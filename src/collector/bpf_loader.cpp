// SPDX-License-Identifier: Apache-2.0
//
// bpf_loader.cpp - libbpf lifecycle + policy map handling.
#include "bpf_loader.hpp"

#include <dirent.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cerrno>

#include <bpf/bpf.h>

#include "xsypher.skel.h"

namespace xsypher {
namespace {

/// Names of the BPF-LSM programs in xsypher.bpf.c.  Kept in one place because
/// they are used for both the autoload decision and the fallback retry.
constexpr const char* kLsmPrograms[] = {
    "xsypher_lsm_bprm_check",
    "xsypher_lsm_socket_connect",
    "xsypher_lsm_file_open",
    "xsypher_lsm_task_kill",
    "xsypher_lsm_bpf",
};

bool is_lsm_related(const std::string& error) {
    static const char* needles[] = {
        "lsm/", "bprm_check_security", "socket_connect", "file_open",
        "BPF_LSM", "bpf_lsm", "LSM", "Attach type", "attach_type",
    };
    for (const char* needle : needles) {
        if (error.find(needle) != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string errno_text(int err) {
    char buffer[256];
    buffer[0] = '\0';
    // GNU strerror_r returns char*, POSIX returns int; use the portable-ish
    // trick of copying through strerror_r's return value.
    const char* text = strerror(err);
    std::snprintf(buffer, sizeof(buffer), "%s (%d)", text ? text : "unknown", err);
    return std::string(buffer);
}

/// Read-modify-write helpers for the single-entry config_map (ABI v3).
bool read_config(int fd, xsypher_config_t& out) {
    std::uint32_t key = 0;
    return bpf_map_lookup_elem(fd, &key, &out) == 0;
}

bool write_config(int fd, const xsypher_config_t& config) {
    std::uint32_t key = 0;
    return bpf_map_update_elem(fd, &key, const_cast<xsypher_config_t*>(&config),
                               BPF_ANY) == 0;
}

/// AI/MCP runtime comm names mirroring engine/lineage.py:AI_RUNTIME_BASENAMES.
constexpr const char* kRuntimeComms[] = {
    "mcp-server", "claude-mcp", "mcp", "node", "nodejs", "deno", "bun",
    "python", "python3", "uvicorn", "gunicorn", "hypercorn", "fastapi",
    "npx", "ollama", "llama-server", "vllm",
};

/// Shell / interpreter binaries whose inode+device fingerprint is registered
/// so an AI lineage cannot execute a renamed copy of them.
constexpr const char* kRestrictedShellPaths[] = {
    "/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh",
    "/bin/fish", "/bin/csh", "/bin/tcsh", "/bin/busybox",
    "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/zsh",
    "/usr/bin/ksh", "/usr/bin/fish", "/usr/bin/csh", "/usr/bin/tcsh",
    "/usr/bin/busybox",
};

}  // namespace

// --------------------------------------------------------------------------- //
// libbpf logging
// --------------------------------------------------------------------------- //

namespace {
int libbpf_print_cb(enum libbpf_print_level level, const char* format, va_list args) {
    if (level == LIBBPF_DEBUG) {
        // Debug messages are only surfaced when libbpf logging was installed
        // in verbose mode; install_libbpf_logging() decides by installing a
        // quiet printer instead.
        return 0;
    }
    if (level == LIBBPF_INFO) {
        std::fputs("[libbpf] ", stderr);
        return vfprintf(stderr, format, args);
    }
    std::fputs("[libbpf:error] ", stderr);
    return vfprintf(stderr, format, args);
}

int libbpf_print_cb_verbose(enum libbpf_print_level level, const char* format,
                            va_list args) {
    const char* prefix = "[libbpf:debug] ";
    if (level == LIBBPF_WARN) {
        prefix = "[libbpf:warn] ";
    } else if (level == LIBBPF_INFO) {
        prefix = "[libbpf:info] ";
    } else if (level == LIBBPF_DEBUG) {
        prefix = "[libbpf:debug] ";
    }
    std::fputs(prefix, stderr);
    return vfprintf(stderr, format, args);
}
}  // namespace

void install_libbpf_logging(bool verbose) {
    libbpf_set_print(verbose ? libbpf_print_cb_verbose : libbpf_print_cb);
}

// --------------------------------------------------------------------------- //
// Lifecycle
// --------------------------------------------------------------------------- //

BpfLoader::~BpfLoader() { unload(); }

bool BpfLoader::load_and_attach(const LoaderOptions& options, std::string& error) {
    std::lock_guard<std::mutex> guard(mutex_);

    options_ = options;
    error.clear();
    last_error_.clear();

    // eBPF maps and programs are accounted against RLIMIT_MEMLOCK on older
    // kernels; raise it as far as the environment allows.
    struct rlimit limit {};
    if (getrlimit(RLIMIT_MEMLOCK, &limit) == 0) {
        limit.rlim_cur = limit.rlim_max;
        (void)setrlimit(RLIMIT_MEMLOCK, &limit);
    }

    if (!open_object(error)) {
        last_error_ = error;
        return false;
    }

    // First attempt: full object including the LSM hooks.
    if (load_object(/*with_lsm=*/true, error)) {
        lsm_available_ = true;
        if (attach_programs(error)) {
            apply_runtime_defaults_locked();
            return true;
        }
        last_error_ = error;
    } else {
        last_error_ = error;
    }

    if (!options_.allow_lsm_fallback || !is_lsm_related(last_error_)) {
        if (error.empty()) {
            error = last_error_;
        }
        destroy_skeleton();
        return false;
    }

    // Fallback: some kernels are built without CONFIG_BPF_LSM or booted
    // without `lsm=bpf`.  Reload with only the tracepoint programs.
    std::fprintf(stderr,
                 "[xsypher] WARNING: BPF-LSM unavailable (%s); continuing in "
                 "telemetry-only mode (inline enforcement disabled)\n",
                 last_error_.c_str());
    destroy_skeleton();

    std::string retry_error;
    if (!open_object(retry_error)) {
        error = "reopen without LSM failed: " + retry_error;
        return false;
    }
    if (!set_autoload_for_lsm(false)) {
        error = "failed to disable LSM autoload";
        destroy_skeleton();
        return false;
    }
    if (!load_object(/*with_lsm=*/false, retry_error)) {
        error = "load without LSM failed: " + retry_error;
        destroy_skeleton();
        return false;
    }

    lsm_available_ = false;
    if (!attach_programs(retry_error)) {
        error = "attach without LSM failed: " + retry_error;
        destroy_skeleton();
        return false;
    }

    apply_runtime_defaults_locked();
    return true;
}

bool BpfLoader::open_object(std::string& error) {
    skel_ = xsypher_bpf__open();
    if (!skel_) {
        error = "xsypher_bpf__open failed: " + errno_text(errno);
        return false;
    }
    return true;
}

bool BpfLoader::set_autoload_for_lsm(bool enable) {
    if (!skel_) {
        return false;
    }
    bool all_ok = true;
    for (std::size_t i = 0; i < sizeof(kLsmPrograms) / sizeof(kLsmPrograms[0]); ++i) {
        // libbpf 1.x: a NULL program simply means "not present", not an error.
        struct bpf_program* prog = bpf_object__find_program_by_name(
            skel_->obj, kLsmPrograms[i]);
        if (!prog) {
            continue;
        }
        int rc = bpf_program__set_autoload(prog, enable);
        if (rc != 0) {
            all_ok = false;
        }
    }
    return all_ok;
}

bool BpfLoader::load_object(bool with_lsm, std::string& error) {
    if (!skel_) {
        error = "skeleton not opened";
        return false;
    }
    (void)with_lsm;
    int rc = xsypher_bpf__load(skel_);
    if (rc != 0) {
        error = "xsypher_bpf__load failed: " + errno_text(-rc);
        return false;
    }
    return true;
}

bool BpfLoader::attach_programs(std::string& error) {
    if (!skel_) {
        error = "skeleton not opened";
        return false;
    }

    // Attach link-by-link so a single unsupported LSM hook cannot take the
    // whole telemetry pipeline down.
    struct bpf_program* prog = nullptr;
    int failed = 0;

    bpf_object__for_each_program(prog, skel_->obj) {
        const char* name = bpf_program__name(prog);
        const char* section = bpf_program__section_name(prog);
        const bool is_lsm =
            (section && std::strncmp(section, "lsm/", 4) == 0) ||
            (section && std::strncmp(section, "fmod_ret/", 9) == 0);

        struct bpf_link* link = bpf_program__attach(prog);
        if (!link) {
            const int saved = errno;
            if (is_lsm) {
                // Non-fatal: drop just this hook and keep the rest alive.
                std::fprintf(stderr,
                             "[xsypher] WARNING: cannot attach LSM program %s (%s): %s\n",
                             name ? name : "?", section ? section : "?",
                             errno_text(saved).c_str());
                if (saved == EINVAL || saved == EPERM || saved == ENOTSUP) {
                    lsm_available_ = false;
                }
                ++failed;
                continue;
            }
            error = std::string("attach failed for program ") + (name ? name : "?") +
                    ": " + errno_text(saved);
            for (bpf_link* attached : links_) {
                bpf_link__destroy(attached);
            }
            links_.clear();
            return false;
        }
        links_.push_back(link);
    }

    if (links_.empty()) {
        error = "no BPF programs could be attached";
        return false;
    }

    (void)failed;
    ringbuf_fd_ = bpf_map__fd(skel_->maps.events_ringbuf);
    if (ringbuf_fd_ < 0) {
        error = "events_ringbuf map has no file descriptor";
        for (struct bpf_link* link : links_) {
            bpf_link__destroy(link);
        }
        links_.clear();
        return false;
    }
    return true;
}

// Caller must hold mutex_ (invoked from load_and_attach()).
void BpfLoader::apply_runtime_defaults_locked() {
    if (!skel_) {
        return;
    }

    // 1. Initialise the ABI v3 control block (config_map[0] =
    //    struct xsypher_config_t).  The BPF program reads this on every hook.
    const int config_fd = bpf_map__fd(skel_->maps.config_map);
    if (config_fd >= 0) {
        xsypher_config_t config{};
        config.enforcement_mode = options_.enforce_inline ? ENFORCEMENT_INLINE_BLOCK
                                                          : ENFORCEMENT_AUDIT_ONLY;
        config.fail_closed_enabled = 0;
        config.heartbeat_timeout_ns = 5ull * 1000000000ull;  // 5 s grace
        config.ringbuf_drop_threshold = 4096;
        config.shutdown_token = 0;
        if (!write_config(config_fd, config)) {
            std::fprintf(stderr, "[xsypher] WARNING: cannot initialise config_map: %s\n",
                         errno_text(errno).c_str());
        }
    }

    // 2. Pre-block the IMDS address when requested.
    if (options_.block_imds) {
        const int ip_fd = bpf_map__fd(skel_->maps.blocked_ipv4_map);
        const std::uint32_t key = XSYPHER_IMDS_IPV4_RAW;
        const std::uint8_t reason = 1;
        if (ip_fd >= 0 && bpf_map_update_elem(ip_fd, &key, &reason, BPF_ANY) != 0) {
            std::fprintf(stderr, "[xsypher] WARNING: cannot pre-block IMDS address: %s\n",
                         errno_text(errno).c_str());
        }
    }

    // 3. Register AI/MCP runtime comm names so the kernel can mark the root
    //    of an AI lineage when it execs one of them.
    for (const char* comm : kRuntimeComms) {
        register_runtime_comm_locked(comm);
    }

    // 4. Pre-populate lineage maps with already-running AI/MCP processes
    //    to close the cold-start race before attaching LSM hooks.
    scan_preexisting_processes_locked();

    // 5. Register the composite inode+device fingerprints of the known shell
    //    / interpreter binaries (survives cp / rename / hardlink).
    for (const char* path : kRestrictedShellPaths) {
        struct stat st {};
        if (::stat(path, &st) != 0) {
            continue;
        }
        register_inode_locked(static_cast<std::uint64_t>(st.st_ino),
                              static_cast<std::uint32_t>(st.st_dev));
    }

    // 6. Protect the collector's own thread-group id so lsm/task_kill cannot
    //    terminate it before an authenticated shutdown token is supplied.
    protect_pid_locked(static_cast<std::uint32_t>(::getpid()), 0);
}

void BpfLoader::scan_preexisting_processes_locked() {
    if (!skel_) {
        return;
    }

    const int lineage_fd = bpf_map__fd(skel_->maps.lineage_map);
    const int pinned_fd = bpf_map__fd(skel_->maps.pinned_taint_map);
    if (lineage_fd < 0 && pinned_fd < 0) {
        return;
    }

    DIR* proc = ::opendir("/proc");
    if (!proc) {
        return;
    }

    struct dirent* entry;
    std::size_t seeded = 0;

    while ((entry = ::readdir(proc)) != nullptr) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        char* end = nullptr;
        unsigned long pid = std::strtoul(entry->d_name, &end, 10);
        if (pid == 0 || *end != '\0') {
            continue;
        }

        char comm_path[64];
        std::snprintf(comm_path, sizeof(comm_path), "/proc/%lu/comm", pid);
        char comm[MAX_COMM_LEN] = {};
        int comm_fd = ::open(comm_path, O_RDONLY | O_CLOEXEC);
        if (comm_fd < 0) {
            continue;
        }
        ssize_t n = ::read(comm_fd, comm, sizeof(comm) - 1);
        ::close(comm_fd);
        if (n <= 0) {
            continue;
        }
        while (n > 0 && (comm[n - 1] == '\n' || comm[n - 1] == '\r')) {
            comm[--n] = '\0';
        }

        bool is_runtime = false;
        for (const char* rcomm : kRuntimeComms) {
            if (std::strcmp(comm, rcomm) == 0) {
                is_runtime = true;
                break;
            }
        }
        if (!is_runtime) {
            continue;
        }

        uint32_t ppid = 0;
        char stat_path[64];
        std::snprintf(stat_path, sizeof(stat_path), "/proc/%lu/stat", pid);
        int stat_fd = ::open(stat_path, O_RDONLY | O_CLOEXEC);
        if (stat_fd >= 0) {
            char stat_buf[512] = {};
            ssize_t sn = ::read(stat_fd, stat_buf, sizeof(stat_buf) - 1);
            ::close(stat_fd);
            if (sn > 0) {
                const char* rparen = std::strrchr(stat_buf, ')');
                if (rparen && *(rparen + 1) != '\0') {
                    char state;
                    unsigned long p = 0;
                    if (std::sscanf(rparen + 2, "%c %lu", &state, &p) == 2) {
                        ppid = static_cast<uint32_t>(p);
                    }
                }
            }
        }

        uint64_t cgroup_id = 0;
        char cgroup_path[64];
        std::snprintf(cgroup_path, sizeof(cgroup_path), "/proc/%lu/cgroup", pid);
        int cg_fd = ::open(cgroup_path, O_RDONLY | O_CLOEXEC);
        if (cg_fd >= 0) {
            char cg_buf[512] = {};
            ssize_t cn = ::read(cg_fd, cg_buf, sizeof(cg_buf) - 1);
            ::close(cg_fd);
            if (cn > 0) {
                char* line = std::strstr(cg_buf, "0::");
                if (line) {
                    char* cg_rel = line + 3;
                    char* endline = std::strchr(cg_rel, '\n');
                    if (endline) *endline = '\0';
                    std::string full_path = std::string("/sys/fs/cgroup") + cg_rel;
                    struct stat cst{};
                    if (::stat(full_path.c_str(), &cst) == 0) {
                        cgroup_id = static_cast<uint64_t>(cst.st_ino);
                    }
                }
            }
        }

        lineage_state_t lin{};
        lin.ppid = ppid;
        lin.root_pid = static_cast<uint32_t>(pid);
        lin.cgroup_id = cgroup_id;
        lin.ai_runtime = 1;
        lin.quarantine = 0;

        const uint32_t key = static_cast<uint32_t>(pid);
        if (pinned_fd >= 0) {
            bpf_map_update_elem(pinned_fd, &key, &lin, BPF_ANY);
        }
        if (lineage_fd >= 0) {
            bpf_map_update_elem(lineage_fd, &key, &lin, BPF_ANY);
        }
        seeded++;
    }
    ::closedir(proc);
    if (seeded > 0) {
        std::fprintf(stderr, "[xsypher] pre-populated %zu running AI/MCP processes into lineage maps\n", seeded);
    }
}

void BpfLoader::unload() {
    std::lock_guard<std::mutex> guard(mutex_);
    destroy_skeleton();
}

void BpfLoader::destroy_skeleton() {
    for (struct bpf_link* link : links_) {
        if (link) {
            bpf_link__destroy(link);
        }
    }
    links_.clear();
    ringbuf_fd_ = -1;
    if (skel_) {
        xsypher_bpf__destroy(skel_);
        skel_ = nullptr;
    }
}

std::string BpfLoader::status_line() const {
    std::string line = "bpf: loaded=";
    line += loaded() ? "yes" : "no";
    line += " programs=" + std::to_string(links_.size());
    line += lsm_available_ ? " lsm=active" : " lsm=unavailable";
    return line;
}

// --------------------------------------------------------------------------- //
// Map helpers
// --------------------------------------------------------------------------- //

namespace {
MapResult update_u8_map(int fd, const void* key, std::uint8_t value, bool del,
                        const char* map_name) {
    MapResult result;
    if (fd < 0) {
        result.err = EBADF;
        result.message = std::string(map_name) + ": map not available";
        return result;
    }
    std::uint8_t v = value;
    int rc = del ? bpf_map_delete_elem(fd, key) : bpf_map_update_elem(fd, key, &v, BPF_ANY);
    if (rc != 0) {
        result.err = errno;
        if (del && result.err == ENOENT) {
            result.ok = true;
            result.message = std::string(map_name) + ": entry already absent";
            return result;
        }
        result.message = std::string(map_name) + ": " + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = std::string(map_name) + (del ? ": deleted" : ": updated");
    return result;
}
}  // namespace

MapResult BpfLoader::quarantine_pid(std::uint32_t tgid, std::uint8_t action) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!skel_) {
        return MapResult{false, ENODEV, "skeleton not loaded"};
    }
    const int fd = bpf_map__fd(skel_->maps.quarantined_pids_map);
    return update_u8_map(fd, &tgid, action, false, "quarantined_pids_map");
}

MapResult BpfLoader::unquarantine_pid(std::uint32_t tgid) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!skel_) {
        return MapResult{false, ENODEV, "skeleton not loaded"};
    }
    const int fd = bpf_map__fd(skel_->maps.quarantined_pids_map);
    return update_u8_map(fd, &tgid, 0, true, "quarantined_pids_map");
}

MapResult BpfLoader::quarantine_cgroup(std::uint64_t cgroup_id, std::uint8_t action) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!skel_) {
        return MapResult{false, ENODEV, "skeleton not loaded"};
    }
    const int fd = bpf_map__fd(skel_->maps.quarantined_cgroups_map);
    return update_u8_map(fd, &cgroup_id, action, false, "quarantined_cgroups_map");
}

MapResult BpfLoader::unquarantine_cgroup(std::uint64_t cgroup_id) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!skel_) {
        return MapResult{false, ENODEV, "skeleton not loaded"};
    }
    const int fd = bpf_map__fd(skel_->maps.quarantined_cgroups_map);
    return update_u8_map(fd, &cgroup_id, 0, true, "quarantined_cgroups_map");
}

MapResult BpfLoader::block_ipv4(std::uint32_t ipv4_network_order, std::uint8_t reason) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!skel_) {
        return MapResult{false, ENODEV, "skeleton not loaded"};
    }
    const int fd = bpf_map__fd(skel_->maps.blocked_ipv4_map);
    return update_u8_map(fd, &ipv4_network_order, reason, false, "blocked_ipv4_map");
}

MapResult BpfLoader::unblock_ipv4(std::uint32_t ipv4_network_order) {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!skel_) {
        return MapResult{false, ENODEV, "skeleton not loaded"};
    }
    const int fd = bpf_map__fd(skel_->maps.blocked_ipv4_map);
    return update_u8_map(fd, &ipv4_network_order, 0, true, "blocked_ipv4_map");
}

MapResult BpfLoader::set_enforcement_mode(std::uint32_t mode) {
    std::lock_guard<std::mutex> guard(mutex_);
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.config_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "config_map not available";
        return result;
    }
    if (mode > ENFORCEMENT_INLINE_BLOCK) {
        mode = ENFORCEMENT_INLINE_BLOCK;
    }
    xsypher_config_t config{};
    if (!read_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    config.enforcement_mode = mode;
    if (!write_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "config_map: enforcement_mode=" + std::to_string(mode);
    return result;
}

MapResult BpfLoader::set_heartbeat(std::uint64_t heartbeat_ns) {
    std::lock_guard<std::mutex> guard(mutex_);
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.config_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "config_map not available";
        return result;
    }
    xsypher_config_t config{};
    if (!read_config(fd, config) || !write_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    config.last_heartbeat_ns = heartbeat_ns;
    if (!write_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "config_map: heartbeat updated";
    return result;
}

MapResult BpfLoader::set_fail_closed(bool enabled) {
    std::lock_guard<std::mutex> guard(mutex_);
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.config_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "config_map not available";
        return result;
    }
    xsypher_config_t config{};
    if (!read_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    config.fail_closed_enabled = enabled ? 1u : 0u;
    if (!write_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "config_map: fail_closed=" + std::string(enabled ? "on" : "off");
    return result;
}

MapResult BpfLoader::set_shutdown_token(std::uint32_t token) {
    std::lock_guard<std::mutex> guard(mutex_);
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.config_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "config_map not available";
        return result;
    }
    xsypher_config_t config{};
    if (!read_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    config.shutdown_token = token;
    if (!write_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "config_map: shutdown_token set";
    return result;
}

MapResult BpfLoader::protect_pid(std::uint32_t tgid, std::uint32_t token) {
    std::lock_guard<std::mutex> guard(mutex_);
    return protect_pid_locked(tgid, token);
}

MapResult BpfLoader::protect_pid_locked(std::uint32_t tgid, std::uint32_t token) {
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.protected_pids_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "protected_pids_map not available";
        return result;
    }
    protected_entry_t entry{};
    entry.token = token;
    entry.is_protected = 1;
    if (bpf_map_update_elem(fd, &tgid, &entry, BPF_ANY) != 0) {
        result.err = errno;
        result.message = std::string("protected_pids_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "protected_pids_map: protected pid " + std::to_string(tgid);
    return result;
}

MapResult BpfLoader::unprotect_pid(std::uint32_t tgid) {
    std::lock_guard<std::mutex> guard(mutex_);
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.protected_pids_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "protected_pids_map not available";
        return result;
    }
    if (bpf_map_delete_elem(fd, &tgid) != 0 && errno != ENOENT) {
        result.err = errno;
        result.message = std::string("protected_pids_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "protected_pids_map: unprotected pid " + std::to_string(tgid);
    return result;
}

MapResult BpfLoader::register_runtime_comm(const char* comm) {
    std::lock_guard<std::mutex> guard(mutex_);
    return register_runtime_comm_locked(comm);
}

MapResult BpfLoader::register_runtime_comm_locked(const char* comm) {
    MapResult result;
    if (!skel_ || comm == nullptr) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.runtime_comms_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "runtime_comms_map not available";
        return result;
    }
    char key[MAX_COMM_LEN] = {};
    std::size_t len = std::strlen(comm);
    if (len >= MAX_COMM_LEN) {
        len = MAX_COMM_LEN - 1;
    }
    std::memcpy(key, comm, len);
    const std::uint8_t value = 1;
    if (bpf_map_update_elem(fd, key, &value, BPF_ANY) != 0) {
        result.err = errno;
        result.message = std::string("runtime_comms_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = std::string("runtime_comms_map: registered ") + comm;
    return result;
}

MapResult BpfLoader::register_inode(std::uint64_t ino, std::uint32_t dev) {
    std::lock_guard<std::mutex> guard(mutex_);
    return register_inode_locked(ino, dev);
}

MapResult BpfLoader::register_inode_locked(std::uint64_t ino, std::uint32_t dev) {
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.restricted_inodes_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "restricted_inodes_map not available";
        return result;
    }
    inode_key_t key{};
    key.ino = ino;
    key.dev = dev;
    const std::uint8_t value = 1;
    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) != 0) {
        result.err = errno;
        result.message = std::string("restricted_inodes_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "restricted_inodes_map: registered inode " + std::to_string(ino);
    return result;
}

MapResult BpfLoader::update_ringbuf_drops(std::uint64_t drops) {
    std::lock_guard<std::mutex> guard(mutex_);
    MapResult result;
    if (!skel_) {
        result.err = ENODEV;
        result.message = "skeleton not loaded";
        return result;
    }
    const int fd = bpf_map__fd(skel_->maps.config_map);
    if (fd < 0) {
        result.err = EBADF;
        result.message = "config_map not available";
        return result;
    }
    xsypher_config_t config{};
    if (!read_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    config.ringbuf_drops = drops;
    if (!write_config(fd, config)) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "config_map: ringbuf_drops updated";
    return result;
}

std::vector<std::uint64_t> BpfLoader::read_metrics() const {
    std::lock_guard<std::mutex> guard(mutex_);
    std::vector<std::uint64_t> totals(METRIC_MAX, 0);
    if (!skel_) {
        return {};
    }
    const int fd = bpf_map__fd(skel_->maps.metrics_map);
    if (fd < 0) {
        return {};
    }

    const int nr_cpus = libbpf_num_possible_cpus();
    if (nr_cpus <= 0) {
        return {};
    }
    std::vector<std::uint64_t> per_cpu(static_cast<std::size_t>(nr_cpus), 0);
    for (std::uint32_t idx = 0; idx < METRIC_MAX; ++idx) {
        std::uint32_t key = idx;
        if (bpf_map_lookup_elem(fd, &key, per_cpu.data()) != 0) {
            continue;
        }
        std::uint64_t sum = 0;
        for (std::uint64_t value : per_cpu) {
            sum += value;
        }
        totals[idx] = sum;
    }
    return totals;
}

}  // namespace xsypher
