#!/usr/bin/env node
/**
 * xSypher-Stream bootstrapper.
 *
 * One command, no manual setup:
 *
 *   npx xsypher-stream                  run the end-to-end simulation
 *   npx xsypher-stream simulate 5000    same, with an explicit event count
 *   npx xsypher-stream doctor           audit this host
 *   npx xsypher-stream clone [dir]      full source checkout plus a venv
 *   npx xsypher-stream run              production topology
 *
 * Why this file exists: the kernel side of xSypher-Stream needs clang, bpftool
 * and libbpf, and the engine needs a Python environment. None of that belongs
 * in an npm dependency tree, so this script bootstraps the real artifacts on
 * first use and caches them under ~/.xsypher. It downloads the source snapshot
 * for one pinned revision, verifies its SHA-256, creates an isolated virtual
 * environment, and then hands control to the project's own test harness.
 *
 * Rules this file follows:
 *   - Node standard library only. No dependencies, no telemetry, no postinstall
 *     script, nothing executed at install time.
 *   - Every child process is tracked and terminated on SIGINT or SIGTERM, so a
 *     Ctrl-C never leaves an orphan holding the Unix socket.
 *   - Downloads are pinned and hash-checked before anything is executed.
 *   - Failures print what went wrong, why it matters, and what to do next.
 */

import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

// --------------------------------------------------------------------------- //
// Identity                                                                     //
// --------------------------------------------------------------------------- //

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.resolve(HERE, '..');

const REPO_OWNER = 'anwariqbaldawar';
const REPO_NAME = 'xSypher-Stream-Zero-Trust-Kernel-log-Telemetry';
const REPO_SLUG = `${REPO_OWNER}/${REPO_NAME}`;

/**
 * Pinned source snapshot. The revision is immutable and the digest was taken
 * from codeload for exactly that revision, so a compromised mirror or a
 * rewritten tag cannot change what this script executes.
 */
const SOURCE_REV = '756ab2972f01a83ad8d33d7e0d4ba874db887d27';
const SOURCE_SHA256 = '0aa38e2ab6623853ef8098443dcbe1b65dd5b39536a0842f10ae93944580040b';
const SOURCE_TARBALL = `https://codeload.github.com/${REPO_SLUG}/tar.gz/${SOURCE_REV}`;

const MIN_PYTHON = [3, 10];
const DEFAULT_EVENTS = 10_000;
const CACHE_DIR = process.env.XSYPHER_HOME || path.join(os.homedir(), '.xsypher');

function packageVersion() {
  try {
    const raw = fs.readFileSync(path.join(PKG_ROOT, 'package.json'), 'utf8');
    return JSON.parse(raw).version || '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const VERSION = packageVersion();

// --------------------------------------------------------------------------- //
// Terminal output                                                              //
// --------------------------------------------------------------------------- //

const COLOR = Boolean(process.stdout.isTTY) && !process.env.NO_COLOR && process.env.TERM !== 'dumb';

const paint = (code) => (text) => (COLOR ? `\u001b[${code}m${text}\u001b[0m` : `${text}`);
const bold = paint('1');
const dim = paint('2');
const red = paint('31');
const green = paint('32');
const yellow = paint('33');
const blue = paint('34');
const cyan = paint('36');

const out = (line = '') => process.stdout.write(`${line}\n`);
const err = (line = '') => process.stderr.write(`${line}\n`);

const log = {
  step: (message) => out(`${cyan('[..]')} ${message}`),
  ok: (message) => out(`${green('[ok]')} ${message}`),
  warn: (message) => out(`${yellow('[!!]')} ${message}`),
  fail: (message) => err(`${red('[xx]')} ${message}`),
  info: (message) => out(`${blue('[--]')} ${message}`),
  detail: (message) => out(`     ${dim(message)}`),
  blank: () => out(),
};

/** An error with a message and an optional remediation hint. */
class CliError extends Error {
  constructor(message, hint, code = 1) {
    super(message);
    this.hint = hint;
    this.exitCode = code;
  }
}

function reportError(error) {
  if (error instanceof CliError) {
    log.fail(error.message);
    if (error.hint) {
      for (const line of String(error.hint).split('\n')) log.detail(line);
    }
    return error.exitCode;
  }
  log.fail(error && error.message ? error.message : String(error));
  if (process.env.XSYPHER_DEBUG && error && error.stack) {
    err(dim(error.stack));
  } else {
    log.detail('Re-run with XSYPHER_DEBUG=1 for a stack trace.');
  }
  return 1;
}

// --------------------------------------------------------------------------- //
// Child processes and signals                                                  //
// --------------------------------------------------------------------------- //

/** Live children, so a signal can take the whole tree down with it. */
const children = new Set();
let shuttingDown = false;

function register(child) {
  children.add(child);
  child.on('exit', () => children.delete(child));
  return child;
}

async function terminateChildren(signal = 'SIGTERM') {
  const live = [...children];
  if (live.length === 0) return;
  for (const child of live) {
    if (child.exitCode !== null || child.killed) continue;
    try {
      if (process.platform === 'win32') child.kill(signal);
      else process.kill(-child.pid, signal); // negative pid: the whole group
    } catch {
      try {
        child.kill(signal);
      } catch {
        /* already gone */
      }
    }
  }
  await new Promise((resolve) => setTimeout(resolve, 2000));
  for (const child of live) {
    if (child.exitCode !== null) continue;
    try {
      if (process.platform === 'win32') child.kill('SIGKILL');
      else process.kill(-child.pid, 'SIGKILL');
    } catch {
      /* already gone */
    }
  }
}

for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, async () => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.blank();
    log.warn(`${signal} received, stopping child processes`);
    await terminateChildren(signal === 'SIGHUP' ? 'SIGHUP' : 'SIGTERM');
    process.exit(signal === 'SIGINT' ? 130 : 143);
  });
}

/** Locate an executable on PATH without a dependency. */
function which(command) {
  if (!command) return null;
  if (command.includes(path.sep)) {
    return fs.existsSync(command) ? command : null;
  }
  const dirs = (process.env.PATH || '').split(path.delimiter).filter(Boolean);
  const exts = process.platform === 'win32'
    ? (process.env.PATHEXT || '.EXE;.CMD;.BAT').split(';')
    : [''];
  for (const dir of dirs) {
    for (const ext of exts) {
      const candidate = path.join(dir, command + ext);
      try {
        if (fs.statSync(candidate).isFile()) {
          fs.accessSync(candidate, fs.constants.X_OK);
          return candidate;
        }
      } catch {
        /* keep looking */
      }
    }
  }
  return null;
}

/** Run a command and capture its output. Never throws on a non-zero exit. */
function capture(command, args = [], options = {}) {
  const result = spawnSync(command, args, {
    encoding: 'utf8',
    timeout: options.timeout || 15_000,
    env: { ...process.env, ...(options.env || {}) },
    cwd: options.cwd,
  });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: (result.stdout || '').trim(),
    stderr: (result.stderr || '').trim(),
    error: result.error || null,
  };
}

/** Run a command with inherited stdio, tracked for signal cleanup. */
function runForeground(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = register(
      spawn(command, args, {
        cwd: options.cwd,
        env: { ...process.env, ...(options.env || {}) },
        stdio: 'inherit',
        detached: process.platform !== 'win32',
      }),
    );
    child.on('error', (error) => {
      reject(new CliError(`could not start ${command}: ${error.message}`,
        `Check that ${command} is installed and on PATH.`));
    });
    child.on('exit', (code, signal) => resolve({ code: code === null ? 1 : code, signal }));
  });
}

/**
 * Run a command and stream its output live while collecting it for a summary.
 * Both stdout and stderr are mirrored to the caller's terminal.
 */
function runStreaming(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = register(
      spawn(command, args, {
        cwd: options.cwd,
        env: { ...process.env, ...(options.env || {}) },
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
      }),
    );
    const collected = [];
    const feed = (stream, sink) => {
      let pending = '';
      stream.setEncoding('utf8');
      stream.on('data', (chunk) => {
        sink.write(chunk);
        collected.push(chunk);
        pending += chunk;
        const lines = pending.split('\n');
        pending = lines.pop();
        for (const line of lines) options.onLine?.(line);
      });
      stream.on('end', () => {
        if (pending) options.onLine?.(pending);
      });
    };
    feed(child.stdout, process.stdout);
    feed(child.stderr, process.stderr);
    child.on('error', (error) => {
      reject(new CliError(`could not start ${command}: ${error.message}`,
        `Check that ${command} is installed and on PATH.`));
    });
    child.on('exit', (code, signal) => {
      resolve({ code: code === null ? 1 : code, signal, output: collected.join('') });
    });
  });
}

// --------------------------------------------------------------------------- //
// Downloads and archive extraction                                             //
// --------------------------------------------------------------------------- //

function sha256(buffer) {
  return createHash('sha256').update(buffer).digest('hex');
}

/** HTTPS GET with redirect following and a size sanity check. */
function download(url, expectedBytes = 0, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      reject(new CliError(`too many redirects fetching ${url}`, 'Check network egress rules.'));
      return;
    }
    const request = https.get(url, { headers: { 'user-agent': `xsypher-stream/${VERSION}` } }, (response) => {
      const { statusCode, headers } = response;
      if (statusCode >= 300 && statusCode < 400 && headers.location) {
        response.resume();
        const next = new URL(headers.location, url).toString();
        resolve(download(next, expectedBytes, redirects + 1));
        return;
      }
      if (statusCode !== 200) {
        response.resume();
        reject(new CliError(`download failed: HTTP ${statusCode} for ${url}`,
          'If this host is offline, use the git checkout path: xsypher clone <dir>'));
        return;
      }
      const total = Number(headers['content-length'] || expectedBytes || 0);
      const chunks = [];
      let received = 0;
      let lastRender = 0;
      response.on('data', (chunk) => {
        chunks.push(chunk);
        received += chunk.length;
        const now = Date.now();
        if (process.stdout.isTTY && now - lastRender > 250) {
          lastRender = now;
          const percent = total ? ((received / total) * 100).toFixed(0) : '?';
          process.stdout.write(`\r     ${dim(`downloading ${(received / 1024).toFixed(0)} KiB (${percent}%)`)}`);
        }
      });
      response.on('end', () => {
        if (process.stdout.isTTY) process.stdout.write('\r' + ' '.repeat(48) + '\r');
        resolve(Buffer.concat(chunks));
      });
      response.on('error', reject);
    });
    request.setTimeout(60_000, () => {
      request.destroy(new CliError(`download timed out: ${url}`, 'Retry, or use xsypher clone.'));
    });
    request.on('error', (error) => {
      const tls = /certificate|CERT_|self.signed|unable to verify/i.test(error.message);
      const failure = new CliError(`network error: ${error.message}`,
        tls
          ? 'Node could not verify the TLS chain. Behind a TLS-inspecting proxy, point Node at the\n' +
            'corporate root: export NODE_EXTRA_CA_CERTS=/path/to/ca-bundle.crt'
          : 'Check connectivity to codeload.github.com, or use xsypher clone <dir>.');
      failure.tls = tls;
      reject(failure);
    });
  });
}

/**
 * Fetch with a transport fallback.
 *
 * Node ships its own CA bundle, which a TLS-inspecting proxy invalidates. curl
 * uses the system store, so it is tried once when the failure is a certificate
 * problem. Either way the bytes are hash-checked against the pinned digest
 * before anything is extracted or executed, so the transport does not carry any
 * trust of its own.
 */
async function fetchPinned(url) {
  try {
    return await download(url);
  } catch (error) {
    if (!(error instanceof CliError) || !error.tls) throw error;
    const curl = which('curl');
    if (!curl) throw error;
    log.warn('node could not verify the TLS chain, retrying with the system CA store');
    const temp = path.join(os.tmpdir(), `xsypher-${process.pid}.tar.gz`);
    const result = spawnSync(curl, [
      '-fsSL', '--retry', '2', '--connect-timeout', '20', '-o', temp, url,
    ], { encoding: 'utf8', timeout: 120_000 });
    try {
      if (result.status !== 0) {
        throw new CliError(`curl could not fetch the snapshot: ${(result.stderr || '').trim()}`,
          'Set NODE_EXTRA_CA_CERTS to the corporate root and retry.');
      }
      return await fsp.readFile(temp);
    } finally {
      await fsp.rm(temp, { force: true });
    }
  }
}

/**
 * Minimal tar reader for the gzip archives codeload serves.
 *
 * Handles regular files, directories, GNU long names and pax path overrides.
 * Refuses absolute paths and parent traversal, so an archive cannot write
 * outside the destination directory.
 */
function extractTarGz(buffer, destination, stripRoot = true) {
  const tar = zlib.gunzipSync(buffer);
  let offset = 0;
  let paxPath = null;
  let longName = null;
  const written = [];

  const readString = (start, length) => {
    const slice = tar.subarray(start, start + length);
    const end = slice.indexOf(0);
    return slice.subarray(0, end === -1 ? slice.length : end).toString('utf8');
  };

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break; // end-of-archive marker

    const rawName = readString(offset, 100);
    const sizeField = readString(offset + 124, 12).trim();
    const type = String.fromCharCode(header[156] || 48);
    const prefix = readString(offset + 345, 155);
    const size = parseInt(sizeField || '0', 8) || 0;

    let name = prefix ? `${prefix}/${rawName}` : rawName;
    if (longName) {
      name = longName;
      longName = null;
    }
    if (paxPath) {
      name = paxPath;
      paxPath = null;
    }

    const bodyStart = offset + 512;
    const bodyEnd = bodyStart + size;
    const body = tar.subarray(bodyStart, bodyEnd);
    offset = bodyStart + Math.ceil(size / 512) * 512;

    if (type === 'x' || type === 'X') {
      const text = body.toString('utf8');
      const match = /(?:^|\n)\d+ path=([^\n]+)\n/.exec(text);
      if (match) paxPath = match[1];
      continue;
    }
    if (type === 'L') {
      longName = body.subarray(0, body.indexOf(0) === -1 ? body.length : body.indexOf(0)).toString('utf8');
      continue;
    }
    if (type !== '0' && type !== '\0' && type !== '5') continue; // links, devices, metadata

    let relative = name;
    if (stripRoot) {
      const slash = relative.indexOf('/');
      if (slash === -1) continue; // top level entry itself
      relative = relative.slice(slash + 1);
    }
    relative = relative.replace(/\/+$/, '');
    if (!relative) continue;
    if (path.isAbsolute(relative) || relative.split('/').includes('..')) {
      throw new CliError(`refusing unsafe path in archive: ${name}`,
        'The archive is corrupt or has been tampered with.');
    }
    const target = path.join(destination, relative);
    if (type === '5') {
      fs.mkdirSync(target, { recursive: true });
      continue;
    }
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, body, { mode: 0o644 });
    written.push(relative);
  }
  return written;
}

// --------------------------------------------------------------------------- //
// Source tree resolution                                                       //
// --------------------------------------------------------------------------- //

/** True when this script runs from a full git checkout rather than the package. */
function checkoutRoot() {
  const candidate = PKG_ROOT;
  const anchors = [
    path.join(candidate, 'src', 'engine', 'main.py'),
    path.join(candidate, 'tests', 'simulate_mcp_attack.py'),
    path.join(candidate, 'requirements.txt'),
  ];
  return anchors.every((file) => fs.existsSync(file)) ? candidate : null;
}

const REQUIRED_SOURCE_FILES = [
  path.join('src', 'engine', 'main.py'),
  path.join('src', 'engine', 'abi.py'),
  path.join('tests', 'simulate_mcp_attack.py'),
  path.join('config', 'rules.yaml'),
  'requirements.txt',
  path.join('include', 'xsypher_abi.h'),
];

function sourceDir() {
  return path.join(CACHE_DIR, 'src', SOURCE_REV);
}

/**
 * Return a directory that contains the full project source.
 *
 * A git checkout is used as-is. An installed npm package carries neither `src/`
 * nor `tests/` (see the `files` list), so the pinned snapshot is fetched once
 * and cached under ~/.xsypher.
 */
async function resolveSource({ quiet = false } = {}) {
  const local = checkoutRoot();
  if (local) return { root: local, mode: 'checkout' };

  const cached = sourceDir();
  const missing = REQUIRED_SOURCE_FILES.filter((file) => !fs.existsSync(path.join(cached, file)));
  if (missing.length === 0) {
    if (!quiet) log.ok(`using cached source ${SOURCE_REV.slice(0, 12)} in ${cached}`);
    return { root: cached, mode: 'cache' };
  }

  if (!quiet) {
    log.step(`fetching source ${SOURCE_REV.slice(0, 12)} from ${REPO_SLUG}`);
    log.detail(SOURCE_TARBALL);
  }
  const payload = await fetchPinned(SOURCE_TARBALL);
  const digest = sha256(payload);
  if (SOURCE_SHA256 && digest !== SOURCE_SHA256) {
    throw new CliError('source snapshot failed its integrity check',
      `expected sha256 ${SOURCE_SHA256}\n  actual   sha256 ${digest}\n` +
      'Nothing was extracted and nothing was executed. Re-run to retry, or use xsypher clone.');
  }
  if (!SOURCE_SHA256) {
    log.warn('source snapshot is unpinned for this build; integrity check skipped');
  } else if (!quiet) {
    log.ok(`sha256 verified ${digest.slice(0, 16)}...`);
  }

  const staging = `${cached}.partial-${process.pid}`;
  await fsp.rm(staging, { recursive: true, force: true });
  await fsp.mkdir(staging, { recursive: true });
  try {
    extractTarGz(payload, staging, true);
    const stillMissing = REQUIRED_SOURCE_FILES.filter((file) => !fs.existsSync(path.join(staging, file)));
    if (stillMissing.length > 0) {
      throw new CliError('source snapshot is incomplete',
        `missing after extraction: ${stillMissing.join(', ')}`);
    }
    await fsp.rm(cached, { recursive: true, force: true });
    await fsp.mkdir(path.dirname(cached), { recursive: true });
    await fsp.rename(staging, cached);
  } finally {
    await fsp.rm(staging, { recursive: true, force: true });
  }
  if (!quiet) log.ok(`source ready in ${cached}`);
  return { root: cached, mode: 'cache' };
}

// --------------------------------------------------------------------------- //
// Python and the cached virtual environment                                    //
// --------------------------------------------------------------------------- //

function pythonCandidates() {
  const explicit = process.env.XSYPHER_PYTHON;
  return [explicit, 'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3', 'python']
    .filter(Boolean);
}

function pythonVersion(command) {
  const probe = capture(command, ['-c', 'import sys; print("%d.%d.%d" % sys.version_info[:3])']);
  if (!probe.ok) return null;
  const [major, minor, patch] = probe.stdout.split('.').map(Number);
  if (Number.isNaN(major) || Number.isNaN(minor)) return null;
  return { major, minor, patch, text: probe.stdout };
}

function supported(version) {
  if (!version) return false;
  if (version.major > MIN_PYTHON[0]) return true;
  return version.major === MIN_PYTHON[0] && version.minor >= MIN_PYTHON[1];
}

/** Pick an interpreter that can host the engine. */
function findPython() {
  const seen = new Set();
  for (const command of pythonCandidates()) {
    const resolved = which(command);
    if (!resolved || seen.has(resolved)) continue;
    seen.add(resolved);
    const version = pythonVersion(resolved);
    if (supported(version)) return { command: resolved, version };
  }
  return null;
}

function venvPython(venvDir) {
  return process.platform === 'win32'
    ? path.join(venvDir, 'Scripts', 'python.exe')
    : path.join(venvDir, 'bin', 'python');
}

async function pathExists(target) {
  try {
    await fsp.access(target);
    return true;
  } catch {
    return false;
  }
}

/**
 * Create or reuse an isolated environment for one source tree.
 *
 * A marker records the requirements digest and the interpreter version, so a
 * changed requirements.txt rebuilds the environment instead of silently running
 * a stale one.
 */
async function ensureVenv(root, python, { quiet = false } = {}) {
  const venvDir = path.join(root, '.venv');
  const interpreter = venvPython(venvDir);
  const requirementsPath = path.join(root, 'requirements.txt');
  const requirements = await fsp.readFile(requirementsPath, 'utf8').catch(() => '');
  const fingerprint = sha256(`${requirements}\n${python.version.text}\n${process.platform}`);
  const markerPath = path.join(venvDir, '.xsypher-venv.json');

  const existing = await pathExists(interpreter);
  if (existing) {
    let marker = null;
    try {
      marker = JSON.parse(await fsp.readFile(markerPath, 'utf8'));
    } catch {
      marker = null;
    }
    if (marker && marker.fingerprint === fingerprint) {
      const probe = capture(interpreter, ['-c', 'import yaml; print(yaml.__version__)']);
      if (probe.ok) {
        if (!quiet) log.ok(`reusing cached environment ${venvDir} (PyYAML ${probe.stdout})`);
        return { dir: venvDir, python: interpreter };
      }
      if (!quiet) log.warn('cached environment is missing PyYAML, repairing in place');
    }
  } else if (!quiet) {
    log.step(`creating isolated environment in ${venvDir}`);
    log.detail(`interpreter ${python.command} (${python.version.text})`);
    const created = await runForeground(python.command, ['-m', 'venv', venvDir]);
    if (created.code !== 0) {
      throw new CliError('could not create a virtual environment',
        'On Debian or Ubuntu install the venv module: sudo apt install python3-venv\n' +
        'Or point at an interpreter directly: XSYPHER_PYTHON=/usr/bin/python3.12');
    }
  }

  // Install in place rather than rebuilding: a developer environment may hold
  // extra packages (pytest, coverage) that this script has no business deleting.

  if (!quiet) log.step('installing engine dependencies (PyYAML)');
  const installed = await runStreaming(interpreter, [
    '-m', 'pip', 'install', '--disable-pip-version-check', '--no-input', '--quiet',
    '-r', requirementsPath,
  ], { cwd: root });
  if (installed.code !== 0) {
    throw new CliError('dependency installation failed', 'See the pip output above.');
  }

  const check = capture(interpreter, ['-c', 'import yaml; print(yaml.__version__)']);
  if (!check.ok) {
    throw new CliError('PyYAML is not importable after installation',
      'Check pip output above, then delete the environment and retry: rm -rf ' + venvDir);
  }
  await fsp.writeFile(markerPath, JSON.stringify({
    fingerprint,
    requirements: sha256(requirements),
    python: python.version.text,
    createdAt: new Date().toISOString(),
  }, null, 2) + '\n');
  if (!quiet) log.ok(`environment ready, PyYAML ${check.stdout}`);
  return { dir: venvDir, python: interpreter };
}

// --------------------------------------------------------------------------- //
// Docker                                                                       //
// --------------------------------------------------------------------------- //

function dockerInfo() {
  const docker = which('docker');
  if (!docker) return { available: false, version: null };
  const version = capture(docker, ['--version']);
  if (!version.ok) return { available: false, version: null };
  const daemon = capture(docker, ['info', '--format', '{{.ServerVersion}}'], { timeout: 8000 });
  const compose = capture(docker, ['compose', 'version', '--short'], { timeout: 8000 });
  return {
    available: true,
    binary: docker,
    version: version.stdout.replace(/^Docker version\s*/, ''),
    daemon: daemon.ok ? daemon.stdout : null,
    compose: compose.ok ? compose.stdout : null,
  };
}

function dockerImagePresent(image, docker) {
  if (!docker.available) return false;
  const found = capture(docker.binary, ['image', 'inspect', '--format', '{{.Id}}', image], { timeout: 8000 });
  return found.ok && found.stdout.length > 0;
}

// --------------------------------------------------------------------------- //
// Commands                                                                     //
// --------------------------------------------------------------------------- //

const summaryPatterns = {
  streamed: /streamed\s+([\d,]+)\s+benign events in\s+([\d.]+)s\s+\(([\d,]+) events\/s\)/,
  packets: /enforcement pkts\s*:\s*(\d+)\s*\(expected (\d+)\)/,
  audit: /audit chain\s*:\s*verified \((\d+) record\(s\)\)/,
  latency: /mitigation latency:\s*(.+)$/,
  throughput: /throughput\s*:\s*([\d,]+) events\/s/,
  chains: /^\s*ok\s+chain ([A-Z]):\s*(.+?)\s*\(([\d.]+)\s*ms\)\s*$/,
};

function formatCount(value) {
  const number = Number(String(value).replace(/,/g, ''));
  return Number.isFinite(number) ? number.toLocaleString('en-US') : String(value);
}

async function commandSimulate(rest) {
  const flags = parseFlags(rest, { count: 'number', docker: 'bool', quiet: 'bool' });
  const positional = flags._[0] !== undefined ? Number(flags._[0]) : null;
  if (positional !== null && !Number.isInteger(positional)) {
    throw new CliError(`invalid event count: ${flags._[0]}`, 'Use a positive integer, for example simulate 5000.');
  }
  const events = flags.count ?? positional ?? DEFAULT_EVENTS;
  if (!Number.isInteger(events) || events <= 0) {
    throw new CliError(`invalid event count: ${events}`, 'Use a positive integer, for example simulate 5000.');
  }

  const docker = dockerInfo();
  const image = `xsypher-stream:${VERSION}`;
  if (!flags.quiet && docker.available && dockerImagePresent(image, docker)) {
    log.step(`running the simulation in the local image ${image}`);
    const result = await runForeground(docker.binary, [
      'run', '--rm', image,
      'python3', 'tests/simulate_mcp_attack.py', '--events', String(events),
    ]);
    return result.code;
  }
  if (!flags.quiet && docker.available && !flags.docker) {
    log.detail(`docker is present but ${image} is not built and no registry image is published; using local Python`);
  }

  const source = await resolveSource({ quiet: flags.quiet });
  const python = findPython();
  if (!python) {
    throw new CliError('no suitable Python interpreter found',
      `xSypher-Stream needs Python ${MIN_PYTHON.join('.')} or newer.\n` +
      'Debian or Ubuntu: sudo apt install python3 python3-venv\n' +
      'Or set XSYPHER_PYTHON=/path/to/python3.12');
  }
  const venv = await ensureVenv(source.root, python, { quiet: flags.quiet });

  log.step(`simulating ${events.toLocaleString('en-US')} kernel events with 5 attack chains`);
  log.detail(`source ${source.root}`);
  log.blank();

  const summary = { chains: [], packets: null, audit: null, latency: null, streamed: null, throughput: null };
  const result = await runStreaming(venv.python, [
    path.join('tests', 'simulate_mcp_attack.py'), '--events', String(events),
  ], {
    cwd: source.root,
    env: { PYTHONPATH: 'src', PYTHONUNBUFFERED: '1' },
    onLine: (line) => {
      const chain = summaryPatterns.chains.exec(line);
      if (chain) summary.chains.push({ id: chain[1], title: chain[2], ms: Number(chain[3]) });
      const packets = summaryPatterns.packets.exec(line);
      if (packets) summary.packets = { got: Number(packets[1]), expected: Number(packets[2]) };
      const audit = summaryPatterns.audit.exec(line);
      if (audit) summary.audit = Number(audit[1]);
      const latency = summaryPatterns.latency.exec(line);
      if (latency) summary.latency = latency[1].trim();
      const streamed = summaryPatterns.streamed.exec(line);
      if (streamed) {
        summary.streamed = { events: formatCount(streamed[1]), seconds: streamed[2], rate: streamed[3] };
      }
      const throughput = summaryPatterns.throughput.exec(line);
      if (throughput) summary.throughput = throughput[1];
    },
  });

  if (shuttingDown) return result.code || 130;
  log.blank();
  const contained = summary.chains.length;
  const passed = result.code === 0;
  const fastest = contained ? Math.min(...summary.chains.map((chain) => chain.ms)) : null;
  const slowest = contained ? Math.max(...summary.chains.map((chain) => chain.ms)) : null;

  log.info(passed ? bold('result: all chains contained') : bold('result: see the output above'));
  if (contained) {
    log.detail(`chains contained  ${contained} of 5, each ${fastest} to ${slowest} ms from event to policy command`);
  }
  if (summary.packets) {
    log.detail(`policy commands   ${summary.packets.got} of ${summary.packets.expected} expected wire_policy_cmd_t packets`);
  }
  if (summary.audit !== null) {
    log.detail(`audit chain       verified, ${summary.audit} SHA-256 chained records`);
  }
  if (summary.streamed) {
    log.detail(`benign stream     ${summary.streamed.events} events in ${summary.streamed.seconds} s (${formatCount(summary.streamed.rate)} events/s)`);
  }
  if (summary.throughput) {
    log.detail(`in-process replay ${formatCount(summary.throughput)} events/s`);
  }
  log.blank();
  if (!passed) {
    log.fail('the simulation reported a failure');
    return result.code;
  }
  log.ok('nothing was left running; the harness removes its socket and temp tree');
  return 0;
}

async function commandClone(rest) {
  const flags = parseFlags(rest, { force: 'bool', quiet: 'bool' }, { positional: 1 });
  const target = path.resolve(flags._[0] || 'xsypher-stream');

  if (await pathExists(target)) {
    const entries = await fsp.readdir(target).catch(() => []);
    if (entries.length > 0 && !flags.force) {
      throw new CliError(`target directory is not empty: ${target}`,
        'Choose another path, or pass --force to clone into it anyway.');
    }
  }

  log.step(`cloning ${REPO_SLUG}`);
  log.detail(`target ${target}`);

  const git = which('git');
  let cloned = false;
  if (git) {
    const result = await runForeground(git, ['clone', '--depth', '1', `https://github.com/${REPO_SLUG}.git`, target]);
    cloned = result.code === 0;
    if (!cloned) log.warn('git clone failed, falling back to the pinned snapshot');
  } else {
    log.detail('git is not installed, using the pinned source snapshot');
  }

  if (!cloned) {
    const payload = await fetchPinned(SOURCE_TARBALL);
    const digest = sha256(payload);
    if (SOURCE_SHA256 && digest !== SOURCE_SHA256) {
      throw new CliError('source snapshot failed its integrity check',
        `expected sha256 ${SOURCE_SHA256}\n  actual   sha256 ${digest}`);
    }
    await fsp.mkdir(target, { recursive: true });
    extractTarGz(payload, target, true);
    log.ok(`extracted pinned snapshot ${SOURCE_REV.slice(0, 12)}`);
  }

  const python = findPython();
  if (!python) {
    log.warn('no Python 3.10+ interpreter found, skipping environment setup');
    log.detail('install python3 and python3-venv, then run: make test');
  } else {
    await ensureVenv(target, python, { quiet: flags.quiet });
  }

  log.blank();
  log.info(bold(`next steps in ${target}`));
  log.detail('PYTHONPATH=src .venv/bin/python tests/simulate_mcp_attack.py');
  log.detail('make test                     unit tests');
  log.detail('make all                      BPF object and C++20 collector (needs clang, bpftool, libbpf)');
  log.detail('make verify                   full verification with per-step PASS and SKIP');
  log.blank();
  log.ok('clone complete');
  return 0;
}

function kernelInfo() {
  const release = os.release();
  const match = /^(\d+)\.(\d+)/.exec(release);
  const major = match ? Number(match[1]) : 0;
  const minor = match ? Number(match[2]) : 0;
  const supportedKernel = major > 5 || (major === 5 && minor >= 10);
  return { release, major, minor, supported: supportedKernel };
}

function readTrimmed(file) {
  try {
    return fs.readFileSync(file, 'utf8').trim();
  } catch {
    return null;
  }
}

async function commandDoctor(rest) {
  const flags = parseFlags(rest, { json: 'bool' });
  const kernel = kernelInfo();
  const python = findPython();
  const docker = dockerInfo();
  const git = which('git');
  const clang = which('clang');
  const bpftool = which('bpftool');
  const compiler = which('g++') || which('c++');
  const btf = await pathExists('/sys/kernel/btf/vmlinux');
  const lsmRaw = readTrimmed('/sys/kernel/security/lsm');
  const lsmList = lsmRaw ? lsmRaw.split(',').map((item) => item.trim()) : [];
  const bpfLsm = lsmList.includes('bpf');
  const cgroupV2 = fs.existsSync('/sys/fs/cgroup/cgroup.controllers');
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const source = checkoutRoot();

  const rows = [];
  const add = (area, status, detail, hint) => rows.push({ area, status, detail, hint });

  add('platform', process.platform === 'linux' ? 'ok' : 'warn',
    `${process.platform} ${process.arch}`,
    process.platform === 'linux' ? null : 'Only the simulation runs here; kernel telemetry needs Linux.');

  add('kernel', kernel.supported ? 'ok' : 'fail',
    `${kernel.release}${kernel.supported ? '' : ' (needs 5.10 or newer)'}`,
    kernel.supported ? null : 'Upgrade the kernel: BPF CO-RE and ring buffers need 5.10 or newer.');

  add('BTF', btf ? 'ok' : 'fail', btf ? '/sys/kernel/btf/vmlinux present' : 'not available',
    btf ? null : 'Rebuild the kernel with CONFIG_DEBUG_INFO_BTF=y; most distribution kernels already have it.');

  add('BPF LSM', bpfLsm ? 'ok' : 'warn',
    lsmRaw ? `lsm=${lsmRaw}` : '/sys/kernel/security/lsm not readable (needs root)',
    bpfLsm ? null : 'Inline denial needs CONFIG_BPF_LSM=y and lsm=bpf on the kernel command line.');

  add('cgroup v2', cgroupV2 ? 'ok' : 'warn', cgroupV2 ? 'unified hierarchy' : 'not detected',
    cgroupV2 ? null : 'cgroup quarantine targets the unified hierarchy.');

  add('python', python ? 'ok' : 'fail',
    python ? `${python.command} (${python.version.text})` : 'no interpreter 3.10+ on PATH',
    python ? null : 'Install Python 3.10+ with venv: sudo apt install python3 python3-venv');

  add('docker', docker.available ? 'ok' : 'warn',
    docker.available ? `${docker.version}${docker.daemon ? `, daemon ${docker.daemon}` : ', daemon not reachable'}` : 'not installed',
    docker.available ? null : 'Optional. Required only for the container and compose paths.');

  add('toolchain', clang && bpftool && compiler ? 'ok' : 'warn',
    [
      `clang ${clang ? 'present' : 'missing'}`,
      `bpftool ${bpftool ? 'present' : 'missing'}`,
      `g++ ${compiler ? 'present' : 'missing'}`,
    ].join(', '),
    clang && bpftool && compiler ? null : 'Needed only to build the kernel object and collector: sudo apt install clang llvm bpftool libbpf-dev libelf-dev zlib1g-dev g++ make');

  add('git', git ? 'ok' : 'warn', git ? git : 'not installed',
    git ? null : 'Optional. xsypher clone falls back to the pinned snapshot.');

  add('privileges', uid === 0 ? 'ok' : 'warn',
    uid === null ? 'unknown' : uid === 0 ? 'running as root' : `uid ${uid}`,
    uid === 0 ? null : 'Loading BPF programs needs CAP_BPF and CAP_PERFMON, or root.');

  add('source', source ? 'ok' : 'ok',
    source ? `checkout ${source}` : `package install, cache ${CACHE_DIR}`,
    null);

  if (flags.json) {
    out(JSON.stringify({
      version: VERSION,
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      kernel,
      btf,
      bpfLsm,
      lsm: lsmList,
      cgroupV2,
      python: python ? { command: python.command, version: python.version.text } : null,
      docker,
      toolchain: { clang, bpftool, compiler, git },
      uid,
      source: source || CACHE_DIR,
      checks: rows,
    }, null, 2));
    return 0;
  }

  out();
  out(`  ${bold('xSypher-Stream doctor')}  ${dim(`v${VERSION}, node ${process.version}`)}`);
  out(`  ${dim('-'.repeat(74))}`);
  const width = Math.max(...rows.map((row) => row.area.length));
  let failures = 0;
  for (const row of rows) {
    const badge = row.status === 'ok' ? green('ok  ') : row.status === 'warn' ? yellow('warn') : red('fail');
    if (row.status === 'fail') failures += 1;
    out(`  ${badge}  ${row.area.padEnd(width)}  ${row.detail}`);
    if (row.hint && row.status !== 'ok') out(`        ${dim(' '.repeat(width))}  ${dim(row.hint)}`);
  }
  out(`  ${dim('-'.repeat(74))}`);
  const telemetry = kernel.supported && btf && python;
  const enforcement = telemetry && bpfLsm;
  out(`  telemetry    ${telemetry ? green('usable') : red('not usable on this host')}`);
  out(`  enforcement  ${
    enforcement ? green('usable')
      : telemetry ? yellow('not usable, telemetry still works') : red('not usable')}`);
  out(`  simulation   ${python ? green('usable, no privileges needed') : red('needs Python 3.10+')}`);
  out(`  cache        ${CACHE_DIR}`);
  out();
  if (failures > 0) {
    log.warn(`${failures} blocking check(s) failed`);
    return 1;
  }
  log.ok('host audit complete');
  return 0;
}

async function commandRun(rest) {
  const flags = parseFlags(rest, {
    direct: 'bool', socket: 'string', 'no-enforce': 'bool', rules: 'string',
  });

  const source = await resolveSource();
  const composeFile = path.join(source.root, 'deploy', 'docker-compose.yml');
  const docker = dockerInfo();

  if (!flags.direct && docker.available && docker.compose && fs.existsSync(composeFile)) {
    const kernel = kernelInfo();
    if (!kernel.supported) {
      throw new CliError(`kernel ${kernel.release} is too old`, 'xSypher-Stream needs Linux 5.10 or newer.');
    }
    log.step('starting the collector and engine containers');
    log.detail(`docker compose -f ${composeFile} up --build`);
    log.detail('the collector needs host BTF and the host PID namespace; the engine runs unprivileged');
    log.blank();
    const result = await runForeground(docker.binary, [
      'compose', '-f', composeFile, 'up', '--build',
    ], { cwd: source.root });
    return result.code;
  }

  if (flags.direct) {
    return runDirect(source.root, flags);
  }

  log.warn('docker compose is not available on this host');
  log.blank();
  log.info('production without containers:');
  log.detail('sudo make all                     build the kernel object and collector');
  log.detail('sudo xsypher run --direct         start both processes under this supervisor');
  log.blank();
  log.info('prerequisites:');
  log.detail('CONFIG_BPF_LSM=y, lsm=bpf on the kernel command line, kernel 5.10 or newer');
  log.detail('CAP_BPF and CAP_PERFMON (or root) for the collector');
  return 1;
}

async function runDirect(root, flags) {
  const uid = typeof process.getuid === 'function' ? process.getuid() : null;
  const collector = path.join(root, 'build', 'xsypher-collector');
  if (!fs.existsSync(collector)) {
    throw new CliError(`collector binary not found: ${collector}`,
      'Build it first: make all\n' +
      'That step needs clang, bpftool, libbpf-dev, libelf-dev and zlib1g-dev.');
  }
  if (uid !== 0) {
    throw new CliError('the collector needs privileges to load BPF programs',
      'Run with sudo, or grant CAP_BPF and CAP_PERFMON to the binary.');
  }

  const python = findPython();
  if (!python) throw new CliError('no Python 3.10+ interpreter found', 'Install python3 and python3-venv.');
  const venv = await ensureVenv(root, python);
  const socketPath = flags.socket || '/run/xsypher/stream.sock';

  log.step('starting the collector');
  const collectorChild = register(spawn(collector, [
    '--socket-path', socketPath,
    ...(flags['no-enforce'] ? [] : ['--enforce']),
    '--block-imds',
  ], { stdio: 'inherit', detached: process.platform !== 'win32' }));

  // Give the collector time to bind the socket before the engine connects.
  await new Promise((resolve) => setTimeout(resolve, 1500));

  log.step('starting the engine');
  const engineArgs = ['-m', 'engine.main', '--socket-path', socketPath];
  if (!flags['no-enforce']) engineArgs.push('--enforce-kernel');
  if (flags.rules) engineArgs.push('--rules', path.resolve(flags.rules));
  const engineChild = register(spawn(venv.python, engineArgs, {
    cwd: root,
    env: { ...process.env, PYTHONPATH: 'src' },
    stdio: 'inherit',
    detached: process.platform !== 'win32',
  }));

  log.ok('both processes are running; Ctrl-C stops them together');
  return new Promise((resolve) => {
    const finish = (code) => {
      for (const child of [collectorChild, engineChild]) {
        if (child.exitCode === null) {
          try {
            if (process.platform === 'win32') child.kill('SIGTERM');
            else process.kill(-child.pid, 'SIGTERM');
          } catch {
            /* already gone */
          }
        }
      }
      resolve(code);
    };
    engineChild.on('exit', (code) => finish(code === null ? 1 : code));
    collectorChild.on('exit', (code) => finish(code === null ? 1 : code));
  });
}

function commandVersion() {
  out(`xsypher-stream ${VERSION}`);
  out(`source ${SOURCE_REV}`);
  out(`node ${process.version} on ${process.platform} ${process.arch}`);
  return 0;
}

// --------------------------------------------------------------------------- //
// Argument parsing and help                                                    //
// --------------------------------------------------------------------------- //

/**
 * Tiny flag parser. Flags are declared per command, so an unknown flag is an
 * error with a hint rather than a silently ignored argument.
 */
function parseFlags(argv, spec, options = {}) {
  const result = { _: [] };
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (token === '--') {
      result._.push(...argv.slice(index + 1));
      break;
    }
    if (token.startsWith('--')) {
      const [name, inlineValue] = token.slice(2).split('=');
      const type = spec[name];
      if (!type) {
        throw new CliError(`unknown option: --${name}`, 'Run xsypher --help for the accepted options.');
      }
      if (type === 'bool') {
        result[name] = inlineValue === undefined ? true : inlineValue !== 'false';
        continue;
      }
      const value = inlineValue !== undefined ? inlineValue : argv[++index];
      if (value === undefined) {
        throw new CliError(`--${name} needs a value`, `Example: --${name} 5000`);
      }
      result[name] = type === 'number' ? Number(value) : value;
      continue;
    }
    result._.push(token);
  }
  if (options.positional !== undefined && result._.length > options.positional) {
    throw new CliError(`unexpected argument: ${result._[options.positional]}`,
      'Run xsypher --help for usage.');
  }
  return result;
}

const HELP = `
  ${bold('xsypher-stream')} ${dim(`v${VERSION}`)}  Kernel-verified runtime defence for AI agent hosts.

  ${bold('USAGE')}
    xsypher <command> [options]

  ${bold('COMMANDS')}
    simulate [count]     Stream synthetic kernel events and contain five attack chains.
                         No root, no kernel toolchain, no Docker required.
                         ${dim('count defaults to 10000')}
    doctor               Audit this host: kernel, BTF, BPF LSM, Python, Docker, toolchain.
                         ${dim('--json for machine readable output')}
    clone [dir]          Full source checkout plus a ready virtual environment.
                         ${dim('dir defaults to ./xsypher-stream, --force to reuse a directory')}
    run                  Production topology: docker compose up when Docker is present,
                         otherwise instructions for the direct supervisor.
                         ${dim('--direct to supervise the local collector and engine')}

  ${bold('OPTIONS')}
    -h, --help           Show this help
    -v, --version        Show version and the pinned source revision
    simulate --quiet     Suppress bootstrap progress, keep the engine output

  ${bold('ENVIRONMENT')}
    XSYPHER_HOME         Cache directory ${dim(`(default ${CACHE_DIR})`)}
    XSYPHER_PYTHON       Interpreter to use ${dim('(default: first python3 on PATH)')}
    NO_COLOR             Disable ANSI colour
    XSYPHER_DEBUG        Print stack traces on failure

  ${bold('WHAT HAPPENS ON FIRST RUN')}
    The package ships only bin/, config/rules.yaml and deploy/. On first run this
    script downloads the source snapshot for revision ${dim(SOURCE_REV.slice(0, 12))},
    checks its SHA-256, extracts it under ${dim(CACHE_DIR + '/src')}, creates an isolated
    virtual environment, installs PyYAML, and runs the project's own harness.

  ${bold('EXAMPLES')}
    npx xsypher-stream                   simulate 10,000 events
    npx xsypher-stream simulate 5000     simulate 5,000 events
    npx xsypher-stream doctor            can this host enforce?
    npx xsypher-stream clone ~/dev/xsypher
`;

async function main(argv) {
  const [command, ...rest] = argv;
  process.on('exit', () => {
    if (children.size > 0) {
      for (const child of children) {
        try {
          child.kill('SIGKILL');
        } catch {
          /* already gone */
        }
      }
    }
  });

  if (!command || command === 'help' || command === '-h' || command === '--help') {
    out(HELP);
    return 0;
  }
  if (command === '-v' || command === '--version' || command === 'version') {
    return commandVersion();
  }
  if (command.startsWith('-') && !/^-\d/.test(command)) {
    throw new CliError(`unknown option: ${command}`, 'Run xsypher --help for usage.');
  }

  switch (command) {
    case 'simulate':
    case 'sim':
      return commandSimulate(rest);
    case 'doctor':
    case 'check':
      return commandDoctor(rest);
    case 'clone':
      return commandClone(rest);
    case 'run':
    case 'start':
      return commandRun(rest);
    default:
      // A bare number is a shorthand for the default command.
      if (/^\d+$/.test(command)) return commandSimulate([command, ...rest]);
      throw new CliError(`unknown command: ${command}`,
        'Available commands: simulate, doctor, clone, run. Run xsypher --help.');
  }
}

main(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch(async (error) => {
    process.exitCode = reportError(error);
    await terminateChildren();
  });
