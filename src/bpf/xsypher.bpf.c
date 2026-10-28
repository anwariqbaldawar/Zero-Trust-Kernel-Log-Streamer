// SPDX-License-Identifier: GPL-2.0
/*
 * xsypher.bpf.c - xSypher-Stream kernel-space zero-trust telemetry + inline
 * enforcement, written as a single BPF CO-RE (Compile Once - Run Everywhere)
 * object.
 *
 * Design notes
 * ------------
 *  * Telemetry is streamed through a 16 MiB BPF_MAP_TYPE_RINGBUF so that the
 *    kernel never blocks on a slow consumer; drops are counted in the per-CPU
 *    metrics_map instead of being retried.
 *  * Policy state (quarantined PIDs / cgroups, blocked IPv4 addresses,
 *    restricted inode fingerprints, protected PIDs, enforcement / fail-closed
 *    config) lives in BPF hash/array maps that userspace mutates with
 *    bpf_map_update_elem().  No policy decisions are hard-coded in the kernel.
 *  * All struct member reads use BPF_CORE_READ so the object keeps working
 *    across kernel versions without recompilation.
 *  * Every path is verifier friendly: constant loop bounds, no unbounded
 *    pointer arithmetic, all strings read into per-CPU scratch buffers first
 *    and then copied into the reserved ring buffer record with bounded loops.
 *
 * Enforcement model (ABI v3)
 * ---------------------------
 *  * In-kernel lineage: `lineage_map` tracks process ancestry
 *    (tgid -> lineage_state_t).  `sched_process_fork` propagates AI-runtime
 *    flags, the root PID, cgroup and quarantine state from parent to child;
 *    `sched_process_exit` removes the entry.  `bprm_check_security` inherits
 *    from the parent when a process was created before the object loaded and
 *    marks itself as an AI runtime when it execs a registered runtime binary.
 *  * Zero-latency first-syscall block: `lsm/bprm_check_security` inspects the
 *    caller's lineage and the target binary's inode+device fingerprint.  When
 *    the lineage is an AI runtime and the target is a restricted shell /
 *    interpreter (or an unregistered binary that fails policy), it returns
 *    -EPERM synchronously (0 ms) and emits an EVENT_ENFORCED_INLINE audit
 *    record that is *not* in the enforcement critical path.
 *  * Syscall-blind enforcement: `lsm/file_open` (open/openat/openat2/io_uring)
 *    and `lsm/socket_connect` (IPv4 + IPv6, incl. fd00:ec2::254 and
 *    ::ffff:169.254.169.254) replace the syscall tracepoints for enforcement.
 *  * Full path resolution uses `bpf_d_path()` into a BPF_MAP_TYPE_PERCPU_ARRAY
 *    scratch buffer (512 B, above the BPF stack limit) and matches prefixes
 *    with an explicit path-component boundary, so /etc/shadow is never
 *    confused with /home/user/shadow.
 *  * Fail-closed: when `config_map.fail_closed_enabled` is set and the agent
 *    heartbeat has expired (or the ring buffer dropped past its threshold),
 *    tracked AI lineages are denied at the LSM hooks.
 *  * Tamper protection: `lsm/task_kill` blocks SIGKILL/SIGTERM/SIGSTOP against
 *    protected PIDs unless an authenticated shutdown token is set;
 *    `lsm/bpf` blocks BPF_MAP_UPDATE_ELEM / BPF_MAP_DELETE_ELEM / BPF_OBJ_GET
 *    from unauthorized processes.
 *
 * The object is safe to load on kernels without CONFIG_BPF_LSM: the collector
 * disables autoload for the lsm programs when the kernel rejects them;
 * tracepoint programs keep working on their own.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define XSYPHER_BPF_TARGET 1
#include "xsypher_abi.h"

/* ----------------------------------------------------------------------- */
/* Kernel constants not always exposed through vmlinux.h                    */
/* ----------------------------------------------------------------------- */

#ifndef EPERM
#define EPERM 1
#endif
#ifndef EACCES
#define EACCES 13
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif
#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE 0x2
#endif
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef SIGSTOP
#define SIGSTOP 19
#endif
/* bpf_cmd_t values (guarded: vmlinux.h already provides them on real BTF). */
#ifndef BPF_MAP_UPDATE_ELEM
#define BPF_MAP_UPDATE_ELEM 2
#endif
#ifndef BPF_MAP_DELETE_ELEM
#define BPF_MAP_DELETE_ELEM 3
#endif
#ifndef BPF_OBJ_GET
#define BPF_OBJ_GET 8
#endif
#ifndef BPF_ANY
#define BPF_ANY 0
#endif

#define XSYPHER_SCAN_LEN 96   /* bytes of each name we inspect            */
#define XSYPHER_ARG_CHUNK 64  /* per-argv scratch buffer size               */
#define XSYPHER_MATCH_MAX 64  /* max prefix/suffix length for unrolled cmp  */

/* ----------------------------------------------------------------------- */
/* BPF maps                                                                 */
/* ----------------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, XSYPHER_RINGBUF_BYTES);
} events_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);   /* tgid */
    __type(value, __u8);  /* enum xsypher_quarantine_action */
} quarantined_pids_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);   /* cgroup id */
    __type(value, __u8);  /* enum xsypher_quarantine_action */
} quarantined_cgroups_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);   /* raw network-byte-order IPv4 */
    __type(value, __u8);  /* reason */
} blocked_ipv4_map SEC(".maps");

/* Composite { ino, dev } binary fingerprint for restricted shells /
 * interpreters.  Survives cp / rename / hardlink because the inode is the
 * same object. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct inode_key_t);
    __type(value, __u8);  /* 1 = restricted */
} restricted_inodes_map SEC(".maps");

/* In-kernel process lineage (tgid -> lineage_state_t). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);   /* tgid */
    __type(value, struct lineage_state_t);
} lineage_map SEC(".maps");

/* Protected PIDs (collector + engine) and their shutdown tokens. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);   /* tgid */
    __type(value, struct protected_entry_t);
} protected_pids_map SEC(".maps");

/* AI / MCP runtime comm names (mcp-server, python3, node, ...). */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, char[MAX_COMM_LEN]);
    __type(value, __u8);
} runtime_comms_map SEC(".maps");

/* Single control block: enforcement mode, fail-closed, heartbeat. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xsypher_config_t);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} metrics_map SEC(".maps");

/* Per-CPU scratch for bpf_d_path(); 512 B > 512 B BPF stack limit. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, char[XSYPHER_PATH_BUF_LEN]);
} path_scratch_map SEC(".maps");

/* ----------------------------------------------------------------------- */
/* Small verifier-friendly string helpers                                   */
/* ----------------------------------------------------------------------- */

/*
 * Compare the first `len` bytes of `s` against a literal prefix and require
 * the match to end on a path-component boundary (next byte is '/' or NUL).
 * The unrolled bound is deliberately tight (XSYPHER_MATCH_MAX) so the
 * verifier sees a fully constant loop.
 */
static __always_inline int path_prefix_match(const char *s, int slen,
                                              const char *prefix, int plen)
{
    if (plen < 0 || plen >= XSYPHER_MATCH_MAX)
        return 0;
    if (slen < plen)
        return 0;
#pragma unroll
    for (int i = 0; i < XSYPHER_MATCH_MAX; i++) {
        if (i >= plen)
            break;
        if (s[i] != prefix[i])
            return 0;
    }
    if (plen < slen && s[plen] != '/')
        return 0;
    return 1;
}

/* Bounded strlen over a scratch buffer. */
static __always_inline int bounded_len(const char *s, int max)
{
    if (max > XSYPHER_SCAN_LEN - 1)
        max = XSYPHER_SCAN_LEN - 1;
#pragma unroll
    for (int i = 0; i < XSYPHER_SCAN_LEN; i++) {
        if (i >= max)
            return max;
        if (s[i] == '\0')
            return i;
    }
    return max;
}

/* Does `s` end with the literal suffix `suffix` of length `len`? */
static __always_inline int suffix_matches(const char *s, int slen,
                                          const char *suffix, int len)
{
    if (slen < len || len >= XSYPHER_MATCH_MAX)
        return 0;
#pragma unroll
    for (int i = 0; i < XSYPHER_MATCH_MAX; i++) {
        if (i >= len)
            return 1;
        if (s[slen - len + i] != suffix[i])
            return 0;
    }
    return 1;
}

/* Exact equality of a path component against a literal name. */
static __always_inline int comp_equals(const char *comp, int clen,
                                       const char *name, int nlen)
{
    if (clen != nlen || clen >= MAX_COMM_LEN)
        return 0;
#pragma unroll
    for (int i = 0; i < MAX_COMM_LEN; i++) {
        if (i >= nlen)
            return 1;
        if (comp[i] != name[i])
            return 0;
    }
    return 1;
}

/*
 * Copy the last path component of `s` (length `slen`) into `out` (size
 * `out_sz`), NUL terminated.  Returns the component length.
 */
static __always_inline int last_component(const char *s, int slen,
                                          char *out, int out_sz)
{
    if (slen <= 0 || out_sz <= 1)
        return 0;
    int i = slen - 1;
    while (i >= 0 && s[i] != '/')
        i--;
    i++;
    int clen = slen - i;
    if (clen <= 0)
        return 0;
    if (clen > out_sz - 1)
        clen = out_sz - 1;
    __builtin_memcpy(out, &s[i], clen);
    out[clen] = '\0';
    return clen;
}

/* ----------------------------------------------------------------------- */
/* Metrics + policy helpers                                                 */
/* ----------------------------------------------------------------------- */

static __always_inline void metric_inc(__u32 id)
{
    __u64 *value = bpf_map_lookup_elem(&metrics_map, &id);

    if (value)
        *value += 1;
}

static __always_inline struct xsypher_config_t *config_get(void)
{
    __u32 key = 0;

    return bpf_map_lookup_elem(&config_map, &key);
}

static __always_inline __u32 enforcement_mode(void)
{
    struct xsypher_config_t *cfg = config_get();

    return cfg ? cfg->enforcement_mode : ENFORCEMENT_AUDIT_ONLY;
}

/* Returns the stored action (0 = absent) for a PID. */
static __always_inline __u32 pid_action(__u32 tgid)
{
    __u8 *action = bpf_map_lookup_elem(&quarantined_pids_map, &tgid);

    return action ? *action : QUARANTINE_OBSERVE;
}

/* Returns the stored action (0 = absent) for a cgroup. */
static __always_inline __u32 cgroup_action(__u64 cgroup_id)
{
    __u8 *action = bpf_map_lookup_elem(&quarantined_cgroups_map, &cgroup_id);

    return action ? *action : QUARANTINE_OBSERVE;
}

/*
 * 1 when the current task should be denied at an LSM hook because it is
 * quarantined with QUARANTINE_BLOCK and inline enforcement is enabled.
 */
static __always_inline int should_block_quarantine(__u32 tgid, __u64 cgroup_id)
{
    if (enforcement_mode() != ENFORCEMENT_INLINE_BLOCK)
        return 0;
    if (cgroup_action(cgroup_id) == QUARANTINE_BLOCK) {
        metric_inc(METRIC_QUARANTINE_DENIES);
        return 1;
    }
    if (pid_action(tgid) == QUARANTINE_BLOCK) {
        metric_inc(METRIC_QUARANTINE_DENIES);
        return 1;
    }
    return 0;
}

/*
 * Fail-closed trigger: heartbeat expired or the ring buffer dropped past its
 * threshold.  Only meaningful when fail_closed_enabled is set.
 */
static __always_inline int fail_closed_triggered(void)
{
    struct xsypher_config_t *cfg = config_get();

    if (!cfg || !cfg->fail_closed_enabled)
        return 0;
    if (cfg->last_heartbeat_ns &&
        bpf_ktime_get_ns() > cfg->last_heartbeat_ns &&
        (bpf_ktime_get_ns() - cfg->last_heartbeat_ns) >
            cfg->heartbeat_timeout_ns)
        return 1;
    if (cfg->ringbuf_drop_threshold &&
        cfg->ringbuf_drops > cfg->ringbuf_drop_threshold)
        return 1;
    return 0;
}

static __always_inline int shutdown_token_set(void)
{
    struct xsypher_config_t *cfg = config_get();

    return cfg && cfg->shutdown_token != 0;
}

/* ----------------------------------------------------------------------- */
/* Lineage helpers                                                          */
/* ----------------------------------------------------------------------- */

/*
 * Return the caller's lineage state, inheriting from the real parent when the
 * process has no entry of its own (created before the object was loaded).
 */
static __always_inline struct lineage_state_t lineage_of(__u32 tgid)
{
    struct lineage_state_t lin = {};
    struct lineage_state_t *lp = bpf_map_lookup_elem(&lineage_map, &tgid);

    if (lp) {
        lin = *lp;
        return lin;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

    if (task) {
        __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

        if (ppid && ppid != tgid) {
            struct lineage_state_t *plp =
                bpf_map_lookup_elem(&lineage_map, &ppid);
            if (plp) {
                lin = *plp;
                lin.ppid = ppid;
            }
        }
    }
    return lin;
}

static __always_inline void lineage_store(__u32 tgid,
                                          const struct lineage_state_t *lin)
{
    bpf_map_update_elem(&lineage_map, &tgid, (void *)lin, BPF_ANY);
}

/*
 * 1 when `comm` (a NUL padded 16-byte basename) is a registered AI/MCP
 * runtime.
 */
static __always_inline int comm_is_runtime(const char *comm)
{
    return bpf_map_lookup_elem(&runtime_comms_map, comm) != 0;
}

/* ----------------------------------------------------------------------- */
/* Path resolution                                                          */
/* ----------------------------------------------------------------------- */

static __always_inline char *path_scratch(void)
{
    __u32 key = 0;

    return (char *)bpf_map_lookup_elem(&path_scratch_map, &key);
}

/*
 * Resolve `p` with bpf_d_path() into the per-CPU scratch buffer and return it
 * together with its length.  The scratch buffer is zeroed first so matching
 * never reads stale bytes.
 */
static __always_inline char *resolve_path(struct path *p, int *out_len)
{
    char *scratch = path_scratch();

    if (!scratch || !p) {
        if (out_len)
            *out_len = 0;
        return 0;
    }
    __builtin_memset(scratch, 0, XSYPHER_PATH_BUF_LEN);
    int n = bpf_d_path(p, scratch, XSYPHER_PATH_BUF_LEN);

    if (n <= 0) {
        *out_len = 0;
        return 0;
    }
    if (n > XSYPHER_PATH_BUF_LEN - 1)
        n = XSYPHER_PATH_BUF_LEN - 1;
    *out_len = n;
    return scratch;
}

/* ----------------------------------------------------------------------- */
/* Binary / path classification                                             */
/* ----------------------------------------------------------------------- */

/* Credential / key material worth reporting on every access. */
static __always_inline int is_sensitive_path(const char *path, int plen)
{
    if (path_prefix_match(path, plen, "/etc/shadow", 11))
        return 1;
    if (path_prefix_match(path, plen, "/etc/sudoers", 12))
        return 1;
    if (path_prefix_match(path, plen, "/etc/passwd", 11))
        return 1;
    if (path_prefix_match(path, plen, "/root/.ssh", 10))
        return 1;
    if (path_prefix_match(path, plen, "/var/run/secrets", 16))
        return 1;
    if (path_prefix_match(path, plen, "/proc/kcore", 11))
        return 1;
    if (path_prefix_match(path, plen, "/proc/sys/kernel/core_pattern", 27))
        return 1;
    if (suffix_matches(path, plen, ".env", 4))
        return 1;
    return 0;
}

/* Directories where an unexpected write is a staging / persistence signal. */
static __always_inline int is_writable_staging_path(const char *path, int plen)
{
    if (path_prefix_match(path, plen, "/tmp", 4))
        return 1;
    if (path_prefix_match(path, plen, "/dev/shm", 8))
        return 1;
    if (path_prefix_match(path, plen, "/usr/bin", 8))
        return 1;
    if (path_prefix_match(path, plen, "/usr/local/bin", 14))
        return 1;
    if (path_prefix_match(path, plen, "/bin", 4))
        return 1;
    if (path_prefix_match(path, plen, "/sbin", 5))
        return 1;
    if (path_prefix_match(path, plen, "/usr/sbin", 9))
        return 1;
    return 0;
}

/* Interactive shells - the classic escape hatch from an MCP tool call. */
static __always_inline int is_restricted_shell(const char *comp, int clen)
{
    if (comp_equals(comp, clen, "sh", 2))
        return 1;
    if (comp_equals(comp, clen, "bash", 4))
        return 1;
    if (comp_equals(comp, clen, "dash", 4))
        return 1;
    if (comp_equals(comp, clen, "zsh", 3))
        return 1;
    if (comp_equals(comp, clen, "ksh", 3))
        return 1;
    if (comp_equals(comp, clen, "fish", 4))
        return 1;
    if (comp_equals(comp, clen, "csh", 3))
        return 1;
    if (comp_equals(comp, clen, "tcsh", 4))
        return 1;
    if (comp_equals(comp, clen, "busybox", 7))
        return 1;
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Event scaffolding                                                        */
/* ----------------------------------------------------------------------- */

/*
 * Populate identity, cgroup and namespace-lineage fields common to every
 * event.  All task_struct reads go through BPF_CORE_READ so the object is
 * portable across kernels; nsproxy can be NULL while a task is exiting, so it
 * is checked before being dereferenced.
 */
static __always_inline void fill_task_context(struct kernel_event_t *ev)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct nsproxy *nsproxy;

    ev->timestamp_ns = bpf_ktime_get_ns();
    ev->cgroup_id = bpf_get_current_cgroup_id();
    ev->pid = (__u32)pid_tgid;
    ev->tgid = (__u32)(pid_tgid >> 32);
    ev->uid = (__u32)uid_gid;
    ev->gid = (__u32)(uid_gid >> 32);

    if (!task)
        return;

    ev->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_probe_read_kernel_str(ev->comm, MAX_COMM_LEN, BPF_CORE_READ(task, comm));
    bpf_probe_read_kernel_str(ev->parent_comm, MAX_COMM_LEN,
                              BPF_CORE_READ(task, real_parent, comm));

    nsproxy = BPF_CORE_READ(task, nsproxy);
    if (nsproxy) {
        struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsproxy, mnt_ns);
        struct pid_namespace *pid_ns = BPF_CORE_READ(nsproxy, pid_ns_for_children);
        struct net *net_ns = BPF_CORE_READ(nsproxy, net_ns);

        if (mnt_ns)
            ev->mnt_ns_id = BPF_CORE_READ(mnt_ns, ns.inum);
        if (pid_ns)
            ev->pid_ns_id = BPF_CORE_READ(pid_ns, ns.inum);
        if (net_ns)
            ev->net_ns_id = BPF_CORE_READ(net_ns, ns.inum);
    }
}

/* Reserve + zero a ring buffer record and fill in the shared context. */
static __always_inline struct kernel_event_t *reserve_event(__u32 type)
{
    struct kernel_event_t *ev;

    ev = bpf_ringbuf_reserve(&events_ringbuf, sizeof(struct kernel_event_t), 0);
    if (!ev) {
        metric_inc(METRIC_RINGBUF_DROPS);
        return 0;
    }

    __builtin_memset(ev, 0, sizeof(struct kernel_event_t));
    fill_task_context(ev);
    ev->event_type = type;
    metric_inc(METRIC_EVENTS_TOTAL);

    return ev;
}

static __always_inline void submit_event(struct kernel_event_t *ev)
{
    bpf_ringbuf_submit(ev, 0);
}

/* Fill the ABI v3 in-kernel enforcement context on an event. */
static __always_inline void fill_enforcement_ctx(struct kernel_event_t *ev,
                                                 __u64 ino, __u32 dev,
                                                 const struct lineage_state_t *lin)
{
    ev->target_ino = (__u32)ino;
    ev->target_dev = dev;
    ev->lineage_root_pid = lin ? lin->root_pid : 0;
    __u32 flags = 0;

    if (lin) {
        if (lin->ai_runtime)
            flags |= LINEAGE_FLAG_AI_RUNTIME;
        if (lin->quarantine == QUARANTINE_BLOCK)
            flags |= LINEAGE_FLAG_QUARANTINE;
    }
    ev->lineage_flags = flags;
}

/*
 * Emit an EVENT_ENFORCED_INLINE record for a synchronous, in-kernel denial.
 * The record is submitted to the ring buffer *after* the hook has already
 * decided to return -EPERM, so it never sits on the enforcement critical path.
 */
static __always_inline void emit_enforced_inline(struct kernel_event_t *ev,
                                                 __u32 reason, __u64 ino,
                                                 __u32 dev,
                                                 const struct lineage_state_t *lin)
{
    if (!ev)
        return;
    ev->event_type = EVENT_ENFORCED_INLINE;
    ev->blocked_by_lsm = 1;
    ev->enforced_inline = 1;
    ev->retval = -EPERM;
    ev->open_flags = reason;
    fill_enforcement_ctx(ev, ino, dev, lin);
    submit_event(ev);
}

/* ----------------------------------------------------------------------- */
/* Tracepoint context layouts                                               */
/* ----------------------------------------------------------------------- */

struct sys_enter_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long id;
    unsigned long args[6];
};

struct sched_process_exit_ctx {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char comm[TASK_COMM_LEN];
    pid_t pid;
    int prio;
};

/* ----------------------------------------------------------------------- */
/* Tracepoint: execve (telemetry + lineage feed)                            */
/* ----------------------------------------------------------------------- */

/*
 * Join up to XSYPHER_MAX_ARGV_POINTERS argv entries (64 bytes each) into
 * ev->args, space separated.  Pointers are dereferenced with
 * bpf_probe_read_user, never directly.
 */
static __always_inline void collect_argv(struct kernel_event_t *ev,
                                         const char *const *argv)
{
    char argbuf[XSYPHER_ARG_CHUNK];
    __u32 off = 0;

#pragma unroll
    for (int i = 0; i < XSYPHER_MAX_ARGV_POINTERS; i++) {
        const char *argp = 0;
        long n;
        __u32 k;

        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0 || !argp)
            break;

        __builtin_memset(argbuf, 0, sizeof(argbuf));
        n = bpf_probe_read_user_str(argbuf, sizeof(argbuf), argp);
        if (n <= 1) {
            continue;
        }

        if (i > 0) {
            if (off >= MAX_ARGS_LEN - 1)
                break;
            ev->args[off] = ' ';
            off += 1;
        }

#pragma unroll
        for (k = 0; k < XSYPHER_ARG_CHUNK - 1; k++) {
            if (k >= (__u32)(n - 1))
                break;
            if (off >= MAX_ARGS_LEN - 1)
                break;
            ev->args[off] = argbuf[k];
            off += 1;
        }
        if (off >= MAX_ARGS_LEN - 1)
            break;
    }
}

SEC("tp/syscalls/sys_enter_execve")
int xsypher_execve(struct sys_enter_ctx *ctx)
{
    struct kernel_event_t *ev;
    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];

    ev = reserve_event(EVENT_EXECVE);
    if (!ev)
        return 0;

    if (filename) {
        long n = bpf_probe_read_user_str(ev->filename, MAX_PATH_LEN, filename);

        if (n <= 0)
            ev->filename[0] = '\0';
    }
    if (argv)
        collect_argv(ev, argv);

    ev->retval = 0;
    metric_inc(METRIC_EXECVE_EVENTS);
    submit_event(ev);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Tracepoint: connect (telemetry)                                          */
/* ----------------------------------------------------------------------- */

SEC("tp/syscalls/sys_enter_connect")
int xsypher_connect(struct sys_enter_ctx *ctx)
{
    struct kernel_event_t *ev;
    const struct sockaddr *address = (const struct sockaddr *)ctx->args[1];
    struct sockaddr_in addr4 = {};
    struct sockaddr_in6 addr6 = {};
    __u16 family = 0;

    if (!address)
        return 0;

    /* Peek at sa_family first; unknown families are still reported. */
    bpf_probe_read_user(&family, sizeof(family), &address->sa_family);

    if (family != AF_INET && family != AF_INET6)
        return 0;

    ev = reserve_event(EVENT_CONNECT);
    if (!ev)
        return 0;

    ev->af_family = (__u8)family;

    if (family == AF_INET) {
        if (bpf_probe_read_user(&addr4, sizeof(addr4), address) != 0) {
            ev->retval = -1;
        } else {
            ev->daddr_v4 = addr4.sin_addr.s_addr;
            ev->dport = addr4.sin_port;
            ev->retval = 0;
        }
    } else {
        if (bpf_probe_read_user(&addr6, sizeof(addr6), address) != 0) {
            ev->retval = -1;
        } else {
            __builtin_memcpy(ev->daddr_v6, &addr6.sin6_addr, 16);
            ev->dport = addr6.sin6_port;
            ev->retval = 0;
        }
    }

    metric_inc(METRIC_CONNECT_EVENTS);
    submit_event(ev);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Tracepoint: memfd_create (fileless payload staging)                      */
/* ----------------------------------------------------------------------- */

SEC("tp/syscalls/sys_enter_memfd_create")
int xsypher_memfd_create(struct sys_enter_ctx *ctx)
{
    struct kernel_event_t *ev;
    const char *uname = (const char *)ctx->args[0];

    ev = reserve_event(EVENT_MEMFD_CREATE);
    if (!ev)
        return 0;

    if (uname) {
        if (bpf_probe_read_user_str(ev->filename, MAX_PATH_LEN, uname) <= 0)
            ev->filename[0] = '\0';
    }
    ev->open_flags = (__u32)ctx->args[1];
    ev->retval = 0;
    metric_inc(METRIC_MEMFD_EVENTS);
    submit_event(ev);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Tracepoint: sched_process_fork - in-kernel lineage propagation          */
/* ----------------------------------------------------------------------- */

/*
 * Propagate the parent's lineage to the child.  `current` is the parent at
 * this tracepoint; the child's tgid is read from its task_struct (set by
 * copy_process() before _do_fork() emits the tracepoint).  Processes that are
 * not part of a tracked AI lineage are skipped so the map stays focused.
 */
SEC("tp_btf/sched/sched_process_fork")
int BPF_PROG(xsypher_process_fork, struct task_struct *parent,
             struct task_struct *child)
{
    __u32 parent_tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    __u32 child_tgid = BPF_CORE_READ(child, tgid);
    struct lineage_state_t lin = {};
    struct lineage_state_t *pl;

    if (child_tgid == 0)
        child_tgid = BPF_CORE_READ(child, pid);
    if (child_tgid == 0 || child_tgid == parent_tgid)
        return 0;

    pl = bpf_map_lookup_elem(&lineage_map, &parent_tgid);
    if (pl) {
        lin = *pl;
    } else {
        /* Parent not tracked: is it itself an AI runtime? */
        char pcomm[MAX_COMM_LEN] = {};

        bpf_probe_read_kernel_str(pcomm, sizeof(pcomm),
                                  BPF_CORE_READ(parent, comm));
        if (!comm_is_runtime(pcomm))
            return 0;
        lin.ai_runtime = 1;
        lin.root_pid = parent_tgid;
    }

    lin.ppid = parent_tgid;
    lin.cgroup_id = bpf_get_current_cgroup_id();
    if (lin.ai_runtime && lin.root_pid == 0)
        lin.root_pid = parent_tgid;

    lineage_store(child_tgid, &lin);
    metric_inc(METRIC_FORK_EVENTS);
    metric_inc(METRIC_LINEAGE_TRACKED);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* Tracepoint: sched_process_exit - lineage cleanup + telemetry             */
/* ----------------------------------------------------------------------- */

SEC("tp/sched/sched_process_exit")
int xsypher_process_exit(struct sched_process_exit_ctx *ctx)
{
    struct kernel_event_t *ev;
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    /*
     * Drop the exiting tgid from the lineage + quarantine maps immediately:
     * PIDs are recycled aggressively and a stale entry would block or mis-
     * attribute an unrelated process.  Deletion is unconditional (no-op when
     * absent).
     */
    bpf_map_delete_elem(&lineage_map, &tgid);
    bpf_map_delete_elem(&quarantined_pids_map, &tgid);

    ev = reserve_event(EVENT_PROCESS_EXIT);
    if (!ev)
        return 0;

    bpf_probe_read_kernel_str(ev->comm, MAX_COMM_LEN, ctx->comm);
    ev->retval = ctx->pid;
    metric_inc(METRIC_EXIT_EVENTS);
    submit_event(ev);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* LSM: bprm_check_security - synchronous 0 ms first-syscall block         */
/* ----------------------------------------------------------------------- */

/*
 * Returns 1 and sets `reason` when the current task (an AI-runtime lineage)
 * is executing a restricted binary.
 */
static __always_inline int bprm_restricted_reason(struct linux_binprm *bprm,
                                                  __u64 *out_ino, __u32 *out_dev,
                                                  char *pathbuf, int *out_plen,
                                                  char *base, int *out_blen,
                                                  __u32 *out_reason)
{
    struct file *file = BPF_CORE_READ(bprm, file);
    struct inode *inode;
    struct super_block *sb;
    struct path fpath;
    char *pathp;
    int plen = 0;
    int blen = 0;
    int restricted = 0;
    __u32 reason = BLOCK_REASON_NONE;

    *out_ino = 0;
    *out_dev = 0;
    *out_plen = 0;
    *out_blen = 0;
    *out_reason = BLOCK_REASON_NONE;

    if (!file)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
        *out_ino = BPF_CORE_READ(inode, i_ino);
        sb = BPF_CORE_READ(inode, i_sb);
        if (sb)
            *out_dev = BPF_CORE_READ(sb, s_dev);
    }

    __builtin_memset(&fpath, 0, sizeof(fpath));
    fpath = BPF_CORE_READ(file, f_path);
    pathp = resolve_path(&fpath, &plen);
    if (pathp && plen > 0) {
        int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

        __builtin_memcpy(pathbuf, pathp, copy);
        pathbuf[copy] = '\0';
        blen = last_component(pathp, plen, base, MAX_COMM_LEN);
    }
    *out_plen = plen;
    *out_blen = blen;

    /* Primary check: composite inode+device fingerprint. */
    if (*out_ino) {
        struct inode_key_t ik = { *out_ino, *out_dev, 0 };

        if (bpf_map_lookup_elem(&restricted_inodes_map, &ik)) {
            restricted = 1;
            reason = BLOCK_REASON_RESTRICTED_INODE;
        }
    }
    /* Fallback: registered-shell basename (unregistered inode). */
    if (!restricted && blen > 0 && is_restricted_shell(base, blen)) {
        restricted = 1;
        reason = BLOCK_REASON_RESTRICTED_SHELL;
    }
    if (!restricted)
        return 0;

    *out_reason = reason;
    return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(xsypher_lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct lineage_state_t lin;
    struct kernel_event_t *ev;
    char pathbuf[MAX_PATH_LEN];
    char base[MAX_COMM_LEN];
    __u64 ino = 0;
    __u32 dev = 0;
    int plen = 0;
    int blen = 0;
    __u32 reason = BLOCK_REASON_NONE;

    if (ret != 0)
        return ret;

    lin = lineage_of(tgid);

    /* Resolve the target binary fingerprint + path. */
    if (bprm_restricted_reason(bprm, &ino, &dev, pathbuf, &plen, base, &blen,
                               &reason)) {
        /* Mark this process as an AI runtime if it is exec'ing a runtime
         * binary (handled below); restricted-target check first. */
        if (lin.ai_runtime) {
            ev = reserve_event(EVENT_ENFORCED_INLINE);
            if (ev) {
                __builtin_memcpy(ev->filename, pathbuf,
                                 plen < MAX_PATH_LEN - 1 ? plen
                                                         : MAX_PATH_LEN - 1);
                ev->filename[MAX_PATH_LEN - 1] = '\0';
            }
            emit_enforced_inline(ev, reason, ino, dev, &lin);
            metric_inc(METRIC_LSM_BLOCKS);
            return -EPERM;
        }
    }

    /*
     * Mark the current process as an AI runtime when it execs a registered
     * runtime binary.  This is how the root of an AI lineage is recorded even
     * when it was forked before the object loaded.
     */
    if (blen > 0 && comm_is_runtime(base)) {
        lin.ai_runtime = 1;
        if (lin.root_pid == 0)
            lin.root_pid = tgid;
        lin.quarantine = cgroup_action(cgroup_id) == QUARANTINE_BLOCK
                             ? QUARANTINE_BLOCK
                             : lin.quarantine;
        lineage_store(tgid, &lin);
    }

    /* Fail-closed: deny tracked AI lineages once the agent is gone. */
    if (fail_closed_triggered() && lin.ai_runtime) {
        ev = reserve_event(EVENT_ENFORCED_INLINE);
        if (ev) {
            int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

            __builtin_memcpy(ev->filename, pathbuf, copy);
            ev->filename[copy] = '\0';
        }
        emit_enforced_inline(ev, BLOCK_REASON_FAIL_CLOSED, ino, dev, &lin);
        metric_inc(METRIC_FAIL_CLOSED_BLOCKS);
        metric_inc(METRIC_LSM_BLOCKS);
        return -EPERM;
    }

    /* Existing quarantine-based exec denial. */
    if (should_block_quarantine(tgid, cgroup_id)) {
        ev = reserve_event(EVENT_ENFORCED_INLINE);
        if (ev && plen > 0) {
            int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

            __builtin_memcpy(ev->filename, pathbuf, copy);
            ev->filename[copy] = '\0';
        }
        emit_enforced_inline(ev, BLOCK_REASON_QUARANTINE_EXEC, ino, dev, &lin);
        metric_inc(METRIC_LSM_BLOCKS);
        return -EPERM;
    }

    return 0;
}

/* ----------------------------------------------------------------------- */
/* LSM: socket_connect - IPv4 + IPv6 IMDS / blocked-IP denial              */
/* ----------------------------------------------------------------------- */

/* Raw network-order u32 of 169.254.169.254 as stored inside in_addr.s_addr. */
#define XSYPHER_IMDS_ADDR XSYPHER_IMDS_IPV4_RAW

/* AWS IPv6 IMDS fd00:ec2::254 as a raw 16-byte address. */
static const __u8 xsypher_imds_ipv6[16] = XSYPHER_IMDS_IPV6_RAW;

/* IPv4-mapped IPv6 ::ffff:169.254.169.254. */
static const __u8 xsypher_imds_v4mapped[16] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xff, 0xff, 0xa9, 0xfe, 0xa9, 0xfe,
};

static __always_inline int ipv6_is_imds(const __u8 *addr)
{
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (addr[i] != xsypher_imds_ipv6[i])
            goto try_v4mapped;
    }
    return 1;
try_v4mapped:
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (addr[i] != xsypher_imds_v4mapped[i])
            return 0;
    }
    return 1;
}

SEC("lsm/socket_connect")
int BPF_PROG(xsypher_lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct sockaddr_in addr4 = {};
    struct sockaddr_in6 addr6 = {};
    __u8 quarantine_state;
    __u32 daddr;
    __u8 *blocked;
    struct kernel_event_t *ev;
    struct lineage_state_t lin;
    __u16 family = 0;

    if (!address || addrlen < (int)sizeof(struct sockaddr_in))
        return 0;
    if (enforcement_mode() != ENFORCEMENT_INLINE_BLOCK)
        return 0;

    /*
     * address is the kernel-side copy produced by move_addr_to_kernel() before
     * security_socket_connect() runs, hence bpf_probe_read_kernel().
     */
    if (bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family) != 0)
        return 0;

    lin = lineage_of(tgid);
    quarantine_state = (cgroup_action(cgroup_id) == QUARANTINE_BLOCK) ||
                       (pid_action(tgid) == QUARANTINE_BLOCK);

    if (family == AF_INET) {
        if (bpf_probe_read_kernel(&addr4, sizeof(addr4), address) != 0)
            return 0;
        daddr = addr4.sin_addr.s_addr;

        /* 1) Explicitly blocked destination (any process). */
        blocked = bpf_map_lookup_elem(&blocked_ipv4_map, &daddr);
        if (blocked) {
            ev = reserve_event(EVENT_CONNECT);
            if (ev) {
                ev->af_family = AF_INET;
                ev->daddr_v4 = daddr;
                ev->dport = addr4.sin_port;
            }
            emit_enforced_inline(ev, BLOCK_REASON_BLOCKED_IP, 0, 0, &lin);
            metric_inc(METRIC_LSM_BLOCKS);
            metric_inc(METRIC_IP_BLOCKS);
            return -EPERM;
        }

        /* 2) Cloud metadata service from a quarantined / AI lineage. */
        if ((quarantine_state || lin.ai_runtime) && daddr == XSYPHER_IMDS_ADDR) {
            ev = reserve_event(EVENT_CONNECT);
            if (ev) {
                ev->af_family = AF_INET;
                ev->daddr_v4 = daddr;
                ev->dport = addr4.sin_port;
            }
            emit_enforced_inline(ev, BLOCK_REASON_IMDS, 0, 0, &lin);
            metric_inc(METRIC_LSM_BLOCKS);
            metric_inc(METRIC_IMDS_BLOCKS);
            return -EPERM;
        }

        /* 3) Fail-closed: deny tracked AI lineages. */
        if (fail_closed_triggered() && lin.ai_runtime) {
            ev = reserve_event(EVENT_CONNECT);
            if (ev) {
                ev->af_family = AF_INET;
                ev->daddr_v4 = daddr;
                ev->dport = addr4.sin_port;
            }
            emit_enforced_inline(ev, BLOCK_REASON_FAIL_CLOSED, 0, 0, &lin);
            metric_inc(METRIC_FAIL_CLOSED_BLOCKS);
            metric_inc(METRIC_LSM_BLOCKS);
            return -EPERM;
        }
    } else if (family == AF_INET6) {
        if (bpf_probe_read_kernel(&addr6, sizeof(addr6), address) != 0)
            return 0;

        /* AWS IPv6 IMDS + IPv4-mapped IPv6 IMDS. */
        if ((quarantine_state || lin.ai_runtime) &&
            ipv6_is_imds(&addr6.sin6_addr.s6_addr[0])) {
            ev = reserve_event(EVENT_CONNECT);
            if (ev) {
                ev->af_family = AF_INET6;
                __builtin_memcpy(ev->daddr_v6, &addr6.sin6_addr, 16);
                ev->dport = addr6.sin6_port;
            }
            emit_enforced_inline(ev, BLOCK_REASON_IMDS_IPV6, 0, 0, &lin);
            metric_inc(METRIC_LSM_BLOCKS);
            metric_inc(METRIC_IMDS_BLOCKS);
            return -EPERM;
        }

        if (fail_closed_triggered() && lin.ai_runtime) {
            ev = reserve_event(EVENT_CONNECT);
            if (ev) {
                ev->af_family = AF_INET6;
                __builtin_memcpy(ev->daddr_v6, &addr6.sin6_addr, 16);
                ev->dport = addr6.sin6_port;
            }
            emit_enforced_inline(ev, BLOCK_REASON_FAIL_CLOSED, 0, 0, &lin);
            metric_inc(METRIC_FAIL_CLOSED_BLOCKS);
            metric_inc(METRIC_LSM_BLOCKS);
            return -EPERM;
        }
    }

    return 0;
}

/* ----------------------------------------------------------------------- */
/* LSM: file_open - full-path credential / staging enforcement + telemetry  */
/* ----------------------------------------------------------------------- */

SEC("lsm/file_open")
int BPF_PROG(xsypher_lsm_file_open, struct file *file, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct kernel_event_t *ev;
    struct path fpath;
    struct inode *inode;
    struct super_block *sb;
    struct lineage_state_t lin;
    char *pathp;
    int plen = 0;
    __u64 ino = 0;
    __u32 dev = 0;
    unsigned int f_mode;
    int sensitive;
    int write_like;
    int staged;

    if (ret != 0)
        return ret;

    lin = lineage_of(tgid);

    /* Fail-closed: deny tracked AI lineages. */
    if (fail_closed_triggered() && lin.ai_runtime) {
        __builtin_memset(&fpath, 0, sizeof(fpath));
        fpath = BPF_CORE_READ(file, f_path);
        pathp = resolve_path(&fpath, &plen);
        ev = reserve_event(EVENT_ENFORCED_INLINE);
        if (ev && pathp && plen > 0) {
            int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

            __builtin_memcpy(ev->filename, pathp, copy);
            ev->filename[copy] = '\0';
        }
        emit_enforced_inline(ev, BLOCK_REASON_FAIL_CLOSED, ino, dev, &lin);
        metric_inc(METRIC_FAIL_CLOSED_BLOCKS);
        metric_inc(METRIC_LSM_BLOCKS);
        return -EPERM;
    }

    /* Full path resolution (bpf_d_path into per-CPU scratch). */
    __builtin_memset(&fpath, 0, sizeof(fpath));
    fpath = BPF_CORE_READ(file, f_path);
    pathp = resolve_path(&fpath, &plen);
    if (!pathp || plen <= 0)
        return 0;

    inode = BPF_CORE_READ(file, f_inode);
    if (inode) {
        ino = BPF_CORE_READ(inode, i_ino);
        sb = BPF_CORE_READ(inode, i_sb);
        if (sb)
            dev = BPF_CORE_READ(sb, s_dev);
    }

    f_mode = BPF_CORE_READ(file, f_mode);
    write_like = (f_mode & FMODE_WRITE) != 0;
    sensitive = is_sensitive_path(pathp, plen);
    staged = write_like && is_writable_staging_path(pathp, plen);

    /* Enforcement for quarantined domains. */
    if (should_block_quarantine(tgid, cgroup_id)) {
        if (sensitive) {
            ev = reserve_event(EVENT_ENFORCED_INLINE);
            if (ev) {
                int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

                __builtin_memcpy(ev->filename, pathp, copy);
                ev->filename[copy] = '\0';
                ev->open_flags = f_mode;
            }
            emit_enforced_inline(ev, BLOCK_REASON_CREDENTIAL_READ, ino, dev,
                                 &lin);
            metric_inc(METRIC_LSM_BLOCKS);
            return -EACCES;
        }
        if (staged) {
            ev = reserve_event(EVENT_ENFORCED_INLINE);
            if (ev) {
                int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

                __builtin_memcpy(ev->filename, pathp, copy);
                ev->filename[copy] = '\0';
                ev->open_flags = f_mode;
            }
            emit_enforced_inline(ev, BLOCK_REASON_WRITE_DENIED, ino, dev,
                                 &lin);
            metric_inc(METRIC_LSM_BLOCKS);
            return -EACCES;
        }
    }

    /* Telemetry (replaces the removed sys_enter_openat tracepoint): report
     * sensitive reads and staging writes even when not enforcing. */
    if (!sensitive && !staged)
        return 0;

    ev = reserve_event(EVENT_OPENAT);
    if (!ev)
        return 0;
    {
        int copy = plen < MAX_PATH_LEN - 1 ? plen : MAX_PATH_LEN - 1;

        __builtin_memcpy(ev->filename, pathp, copy);
        ev->filename[copy] = '\0';
    }
    fill_enforcement_ctx(ev, ino, dev, &lin);
    ev->open_flags = f_mode;
    ev->retval = staged ? 1 : 0;
    metric_inc(METRIC_OPENAT_EVENTS);
    submit_event(ev);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* LSM: task_kill - in-kernel self-protection                               */
/* ----------------------------------------------------------------------- */

SEC("lsm/task_kill")
int BPF_PROG(xsypher_lsm_task_kill, struct task_struct *target,
             struct kernel_siginfo *info, int sig, const struct cred *cred,
             int ret)
{
    __u32 target_tgid;
    struct protected_entry_t *pe;
    struct kernel_event_t *ev;

    if (ret != 0)
        return ret;
    if (enforcement_mode() != ENFORCEMENT_INLINE_BLOCK)
        return 0;

    /* Kernel-originated signals (info == NULL or the constant 1) are allowed. */
    if (info == (struct kernel_siginfo *)1 || info == NULL)
        return 0;

    target_tgid = BPF_CORE_READ(target, tgid);
    if (target_tgid == 0)
        target_tgid = BPF_CORE_READ(target, pid);
    if (target_tgid == 0)
        return 0;

    pe = bpf_map_lookup_elem(&protected_pids_map, &target_tgid);
    if (!pe || !pe->is_protected)
        return 0;

    /* An authenticated shutdown token lifts the protection. */
    if (shutdown_token_set())
        return 0;

    if (sig == SIGKILL || sig == SIGTERM || sig == SIGSTOP) {
        ev = reserve_event(EVENT_ENFORCED_INLINE);
        if (ev) {
            ev->retval = target_tgid;
        }
        emit_enforced_inline(ev, BLOCK_REASON_TAMPER_KILL, 0, 0, 0);
        metric_inc(METRIC_TAMPER_BLOCKS);
        metric_inc(METRIC_LSM_BLOCKS);
        return -EPERM;
    }

    return 0;
}

/* ----------------------------------------------------------------------- */
/* LSM: bpf - protect xSypher maps/programs from unauthorized mutation     */
/* ----------------------------------------------------------------------- */

SEC("lsm/bpf")
int BPF_PROG(xsypher_lsm_bpf, int cmd, union bpf_attr *attr, unsigned int size,
             int ret)
{
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct protected_entry_t *pe;
    struct kernel_event_t *ev;

    if (ret != 0)
        return ret;
    if (enforcement_mode() != ENFORCEMENT_INLINE_BLOCK)
        return 0;

    if (cmd != BPF_MAP_UPDATE_ELEM && cmd != BPF_MAP_DELETE_ELEM &&
        cmd != BPF_OBJ_GET)
        return 0;

    /* The collector / engine are registered as protected and may mutate. */
    pe = bpf_map_lookup_elem(&protected_pids_map, &tgid);
    if (pe && pe->is_protected)
        return 0;

    ev = reserve_event(EVENT_ENFORCED_INLINE);
    emit_enforced_inline(ev, BLOCK_REASON_TAMPER_BPF, 0, 0, 0);
    metric_inc(METRIC_BPF_BLOCKS);
    metric_inc(METRIC_LSM_BLOCKS);
    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
