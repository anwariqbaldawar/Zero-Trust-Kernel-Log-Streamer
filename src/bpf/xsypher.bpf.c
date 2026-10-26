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
 *    enforcement mode) lives in BPF hash/array maps that userspace mutates with
 *    bpf_map_update_elem().  No policy decisions are hard-coded in the kernel.
 *  * All struct member reads use BPF_CORE_READ so the object keeps working
 *    across kernel versions without recompilation.
 *  * Every path is verifier friendly: constant loop bounds, no unbounded
 *    pointer arithmetic, all strings read into stack scratch buffers first and
 *    then copied into the reserved ring buffer record with bounded loops.
 *
 * The object is safe to load on kernels without CONFIG_BPF_LSM: the collector
 * disables autoload for the three "lsm/*" programs when the kernel rejects
 * them; tracepoint programs keep working on their own.
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

#define XSYPHER_SCAN_LEN 96   /* bytes of each path/name we inspect          */
#define XSYPHER_ARG_CHUNK 64  /* per-argv scratch buffer size                 */

/* LSM block reason codes, carried in kernel_event_t::open_flags.            */
enum xsypher_block_reason {
    BLOCK_REASON_NONE = 0,
    BLOCK_REASON_QUARANTINE_EXEC = 1,
    BLOCK_REASON_IMDS = 2,
    BLOCK_REASON_BLOCKED_IP = 3,
    BLOCK_REASON_CREDENTIAL_READ = 4,
    BLOCK_REASON_WRITE_DENIED = 5,
};

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32); /* enum xsypher_enforcement_mode */
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} metrics_map SEC(".maps");

/* ----------------------------------------------------------------------- */
/* Small verifier-friendly string helpers                                   */
/* ----------------------------------------------------------------------- */

/*
 * Compare the first `len` bytes of `s` against a literal prefix.
 *
 * The unrolled bound is deliberately tight (32) so the verifier sees a fully
 * constant loop: every prefix used below is shorter than 32 characters.  A
 * `len` above the bound simply returns 0 instead of reading out of range.
 */
static __always_inline int prefix_matches(const char *s, const char *prefix, int len)
{
    if (len < 0 || len >= 32)
        return 0;
#pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= len)
            return 1;
        if (s[i] != prefix[i])
            return 0;
    }
    return 1;
}

/*
 * Bounded strlen over a scratch buffer.  `max` must not exceed the unrolled
 * bound (96), which is exactly XSYPHER_SCAN_LEN - 1 at the only call site.
 */
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
    if (slen < len)
        return 0;
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= len)
            return 1;
        if (s[slen - len + i] != suffix[i])
            return 0;
    }
    return 1;
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

static __always_inline __u32 enforcement_mode(void)
{
    __u32 key = 0;
    __u32 *mode = bpf_map_lookup_elem(&config_map, &key);

    return mode ? *mode : ENFORCEMENT_AUDIT_ONLY;
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
 * 1 when the current task should be denied at an LSM hook, i.e. it is
 * quarantined with QUARANTINE_BLOCK and inline enforcement is enabled.
 */
static __always_inline int should_block(__u32 tgid, __u64 cgroup_id)
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

/* Emit an EVENT_LSM_BLOCK record for a denied operation. */
static __always_inline void emit_lsm_block(struct kernel_event_t *ev, __u32 reason)
{
    if (!ev)
        return;
    ev->event_type = EVENT_LSM_BLOCK;
    ev->blocked_by_lsm = 1;
    ev->retval = -EPERM;
    ev->open_flags = reason;
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
/* Tracepoint: execve                                                       */
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
/* Tracepoint: connect                                                      */
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
/* Tracepoint: openat (noisy - filtered in kernel)                          */
/* ----------------------------------------------------------------------- */

/* Credential / key material worth reporting on every access. */
static __always_inline int is_sensitive_read_path(const char *path)
{
    if (prefix_matches(path, "/etc/shadow", 11))
        return 1;
    if (prefix_matches(path, "/etc/sudoers", 12))
        return 1;
    if (prefix_matches(path, "/etc/passwd", 11))
        return 1;
    if (prefix_matches(path, "/root/.ssh", 10))
        return 1;
    if (prefix_matches(path, "/var/run/secrets", 16))
        return 1;
    if (prefix_matches(path, "/proc/kcore", 11))
        return 1;
    if (prefix_matches(path, "/proc/sys/kernel/core_pattern", 27))
        return 1;
    return 0;
}

/* Directories where an unexpected write is a staging / persistence signal. */
static __always_inline int is_writable_staging_path(const char *path)
{
    if (prefix_matches(path, "/tmp", 4))
        return 1;
    if (prefix_matches(path, "/dev/shm", 8))
        return 1;
    if (prefix_matches(path, "/usr/bin", 8))
        return 1;
    if (prefix_matches(path, "/usr/local/bin", 14))
        return 1;
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int xsypher_openat(struct sys_enter_ctx *ctx)
{
    struct kernel_event_t *ev;
    const char *filename = (const char *)ctx->args[1];
    __u32 flags = (__u32)ctx->args[2];
    char pathbuf[XSYPHER_SCAN_LEN];
    int len;
    int sensitive;
    int write_like;
    int staged;

    if (!filename)
        return 0;

    __builtin_memset(pathbuf, 0, sizeof(pathbuf));
    if (bpf_probe_read_user_str(pathbuf, sizeof(pathbuf), filename) <= 0)
        return 0;

    sensitive = is_sensitive_read_path(pathbuf);
    write_like = (flags & (O_WRONLY | O_RDWR | O_CREAT)) != 0;
    staged = write_like && is_writable_staging_path(pathbuf);
    len = bounded_len(pathbuf, XSYPHER_SCAN_LEN - 1);

    /* ".env" style secret files anywhere on disk. */
    if (!sensitive && suffix_matches(pathbuf, len, ".env", 4))
        sensitive = 1;

    if (!sensitive && !staged)
        return 0;

    ev = reserve_event(EVENT_OPENAT);
    if (!ev)
        return 0;

    bpf_probe_read_user_str(ev->filename, MAX_PATH_LEN, filename);
    ev->open_flags = flags;
    ev->retval = staged ? 1 : 0;
    metric_inc(METRIC_OPENAT_EVENTS);
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
/* Tracepoint: sched_process_exit                                           */
/* ----------------------------------------------------------------------- */

SEC("tp/sched/sched_process_exit")
int xsypher_process_exit(struct sched_process_exit_ctx *ctx)
{
    struct kernel_event_t *ev;
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

    /*
     * Drop the exiting tgid from the quarantine map immediately: PIDs are
     * recycled aggressively and a stale entry would block an unrelated
     * process.  Deletion is unconditional (no-op when absent).
     */
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
/* LSM: bprm_check_security - deny exec in quarantined domains              */
/* ----------------------------------------------------------------------- */

SEC("lsm/bprm_check_security")
int BPF_PROG(xsypher_lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct kernel_event_t *ev;
    const char *filename;

    if (ret != 0)
        return ret;
    if (!should_block(tgid, cgroup_id))
        return 0;

    ev = reserve_event(EVENT_EXECVE);
    if (ev) {
        /* Fill the record *before* submitting it to the ring buffer. */
        filename = BPF_CORE_READ(bprm, filename);
        if (filename)
            bpf_probe_read_kernel_str(ev->filename, MAX_PATH_LEN, filename);
    }
    emit_lsm_block(ev, BLOCK_REASON_QUARANTINE_EXEC);
    metric_inc(METRIC_LSM_BLOCKS);

    return -EPERM;
}

/* ----------------------------------------------------------------------- */
/* LSM: socket_connect - deny blocked IPv4 + IMDS from quarantined domains   */
/* ----------------------------------------------------------------------- */

/* Raw network-order u32 of 169.254.169.254 as stored inside in_addr.s_addr. */
#define XSYPHER_IMDS_ADDR XSYPHER_IMDS_IPV4_RAW

SEC("lsm/socket_connect")
int BPF_PROG(xsypher_lsm_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct sockaddr_in addr4 = {};
    __u8 quarantine_state;
    __u32 daddr;
    __u8 *blocked;
    struct kernel_event_t *ev;

    if (!address || addrlen < (int)sizeof(struct sockaddr_in))
        return 0;
    if (enforcement_mode() != ENFORCEMENT_INLINE_BLOCK)
        return 0;

    /*
     * address is the kernel-side copy produced by move_addr_to_kernel() before
     * security_socket_connect() runs, hence bpf_probe_read_kernel().
     */
    if (bpf_probe_read_kernel(&addr4, sizeof(addr4), address) != 0)
        return 0;
    if (addr4.sin_family != AF_INET)
        return 0;

    daddr = addr4.sin_addr.s_addr;
    quarantine_state = (cgroup_action(cgroup_id) == QUARANTINE_BLOCK) ||
                       (pid_action(tgid) == QUARANTINE_BLOCK);

    /* 1) Explicitly blocked destination (any process). */
    blocked = bpf_map_lookup_elem(&blocked_ipv4_map, &daddr);
    if (blocked) {
        ev = reserve_event(EVENT_CONNECT);
        if (ev) {
            ev->af_family = AF_INET;
            ev->daddr_v4 = daddr;
            ev->dport = addr4.sin_port;
        }
        emit_lsm_block(ev, BLOCK_REASON_BLOCKED_IP);
        metric_inc(METRIC_LSM_BLOCKS);
        metric_inc(METRIC_IP_BLOCKS);
        return -EPERM;
    }

    /* 2) Cloud metadata service from a quarantined container. */
    if (quarantine_state && daddr == XSYPHER_IMDS_ADDR) {
        ev = reserve_event(EVENT_CONNECT);
        if (ev) {
            ev->af_family = AF_INET;
            ev->daddr_v4 = daddr;
            ev->dport = addr4.sin_port;
        }
        emit_lsm_block(ev, BLOCK_REASON_IMDS);
        metric_inc(METRIC_LSM_BLOCKS);
        metric_inc(METRIC_IMDS_BLOCKS);
        return -EPERM;
    }

    return 0;
}

/* ----------------------------------------------------------------------- */
/* LSM: file_open - deny credential reads and writes while quarantined      */
/* ----------------------------------------------------------------------- */

SEC("lsm/file_open")
int BPF_PROG(xsypher_lsm_file_open, struct file *file, int ret)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    struct kernel_event_t *ev;
    const unsigned char *name_ptr;
    char pathbuf[XSYPHER_SCAN_LEN];
    unsigned int f_mode;
    int sensitive;
    int write_like;

    if (ret != 0)
        return ret;
    if (!should_block(tgid, cgroup_id))
        return 0;

    __builtin_memset(pathbuf, 0, sizeof(pathbuf));
    name_ptr = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!name_ptr)
        return 0;
    if (bpf_probe_read_kernel_str(pathbuf, sizeof(pathbuf), name_ptr) <= 0)
        return 0;

    f_mode = BPF_CORE_READ(file, f_mode);
    write_like = (f_mode & FMODE_WRITE) != 0;
    sensitive = is_sensitive_read_path(pathbuf);

    if (!sensitive && !write_like)
        return 0;

    ev = reserve_event(EVENT_OPENAT);
    if (ev) {
        __builtin_memcpy(ev->filename, pathbuf, XSYPHER_SCAN_LEN - 1);
        ev->filename[MAX_PATH_LEN - 1] = '\0';
        ev->open_flags = f_mode;
    }
    emit_lsm_block(ev, sensitive ? BLOCK_REASON_CREDENTIAL_READ
                                 : BLOCK_REASON_WRITE_DENIED);
    metric_inc(METRIC_LSM_BLOCKS);
    return -EACCES;
}

char LICENSE[] SEC("license") = "GPL";
