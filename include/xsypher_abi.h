/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0 */
/*
 * xsypher_abi.h - Shared binary ABI for xSypher-Stream.
 *
 * This header is the single source of truth for the byte-level contract between:
 *
 *   1. Kernel space   : eBPF CO-RE programs (restricted C, src/bpf/xsypher.bpf.c)
 *   2. User space     : C++20 collector daemon      (src/collector/)
 *   3. User space     : Python 3.12+ threat engine  (src/engine/abi.py)
 *
 * Every structure in this file is fixed-layout, endian-explicit and padded
 * *explicitly* so that the layout can be reproduced byte-for-byte with
 * ctypes (see src/engine/abi.py, which asserts every size and offset).
 *
 * Layout rules
 * ------------
 *   - All integers are little-endian on-disk / on-wire; multi-byte integer
 *     fields are stored in host byte order (x86_64 / aarch64 LE).
 *   - Network addresses and ports are stored in *raw network byte order*,
 *     i.e. exactly as the kernel hands them to us inside struct sockaddr_in.
 *     On a little-endian host that means the integer value looks byte-swapped
 *     (169.254.169.254 -> 0xFEA9FEA9). Helper macros below make this explicit.
 *   - Structures are `packed, aligned(8)`. Fields are ordered and explicitly
 *     padded so that every member is naturally aligned anyway; `packed` is
 *     therefore a no-op that only documents the intent, and the resulting
 *     layout is identical for clang, g++ and ctypes.
 *   - Structures are zero-initialised everywhere (bpf_ringbuf_reserve() memory
 *     is zeroed by the ring buffer, wire frames are memset() to 0 by C++).
 */

#ifndef XSYPHER_ABI_H
#define XSYPHER_ABI_H

#if defined(__KERNEL__) || defined(XSYPHER_BPF_TARGET)
/* Kernel / eBPF restricted-C compilation: vmlinux.h or linux/types.h provides
 * the __u8/__u16/__u32/__u64/__s32 typedefs used below. */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#else
#include <stdint.h>
#include <stddef.h>

#if defined(__linux__)
/*
 * Use the kernel's own user-space type definitions so that this header can be
 * included next to <linux/types.h>, <sys/socket.h> & friends without a
 * conflicting __u64 typedef (linux uses `unsigned long long`, stdint's
 * uint64_t is `unsigned long` on LP64 - same width, different type).
 */
#include <linux/types.h>
#else
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Wire / ABI constants                                                     */
/* ------------------------------------------------------------------------ */

#define XSYPHER_WIRE_MAGIC 0x58535950u /* "XSYP" */
#define XSYPHER_ABI_VERSION 2u

#define MAX_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 256
#define MAX_CONTAINER_ID_LEN 64

/* Ring buffer sizing (kernel + collector). */
#define XSYPHER_RINGBUF_BYTES (16u * 1024u * 1024u)

/* Maximum number of argv pointers joined into kernel_event_t::args. */
#define XSYPHER_MAX_ARGV_POINTERS 4

/* ------------------------------------------------------------------------ */
/* Event types                                                              */
/* ------------------------------------------------------------------------ */

enum xsypher_event_type {
    EVENT_UNKNOWN = 0,
    EVENT_EXECVE = 1,
    EVENT_CONNECT = 2,
    EVENT_OPENAT = 3,
    EVENT_MEMFD_CREATE = 4,
    EVENT_PROCESS_EXIT = 5,
    EVENT_LSM_BLOCK = 6,
    EVENT_TYPE_MAX = 7,
};

/* Wire frame kinds (wire_event_msg_t::msg_type). */
enum xsypher_msg_type {
    MSG_TELEMETRY_EVENT = 1,
    MSG_HEARTBEAT = 2,
};

/* Policy command kinds (wire_policy_cmd_t::cmd_type). */
enum xsypher_cmd_type {
    CMD_QUARANTINE_PID = 10,
    CMD_UNQUARANTINE_PID = 11,
    CMD_QUARANTINE_CGROUP = 12,
    CMD_UNQUARANTINE_CGROUP = 13,
    CMD_BLOCK_IPV4 = 14,
    CMD_UNBLOCK_IPV4 = 15,
    CMD_SET_ENFORCEMENT_MODE = 16,
    CMD_TYPE_MAX = 17,
};

/* Enforcement modes (config_map[0]). */
enum xsypher_enforcement_mode {
    ENFORCEMENT_AUDIT_ONLY = 0,
    ENFORCEMENT_INLINE_BLOCK = 1,
};

/* Quarantine action values stored in the hash maps. */
enum xsypher_quarantine_action {
    QUARANTINE_OBSERVE = 0,  /* emit events, never block  */
    QUARANTINE_BLOCK = 1,    /* block at the LSM hooks     */
};

/* Metric slots in the per-CPU metrics_map. */
enum xsypher_metric_id {
    METRIC_EVENTS_TOTAL = 0,
    METRIC_RINGBUF_DROPS = 1,
    METRIC_LSM_BLOCKS = 2,
    METRIC_EXECVE_EVENTS = 3,
    METRIC_CONNECT_EVENTS = 4,
    METRIC_OPENAT_EVENTS = 5,
    METRIC_MEMFD_EVENTS = 6,
    METRIC_EXIT_EVENTS = 7,
    METRIC_IMDS_BLOCKS = 8,
    METRIC_IP_BLOCKS = 9,
    METRIC_QUARANTINE_DENIES = 10,
    METRIC_MAX = 16,
};

/* ------------------------------------------------------------------------ */
/* Kernel -> collector event                                                */
/* ------------------------------------------------------------------------ */

/*
 * sizeof(struct kernel_event_t) == 640
 *
 * Field offsets (verified by tests/test_wire_protocol.py):
 *   timestamp_ns    0    cgroup_id       8    pid            16
 *   tgid           20    ppid           24    uid            28
 *   gid            32    mnt_ns_id      36    pid_ns_id      40
 *   net_ns_id      44    event_type     48    retval         52
 *   blocked_by_lsm 56    af_family      57    dport          58
 *   sport          60    reserved0      62    daddr_v4       64
 *   saddr_v4       68    daddr_v6       72    open_flags     88
 *   comm           92    parent_comm   108    filename      124
 *   args          380
 */
struct kernel_event_t {
    __u64 timestamp_ns;      /* bpf_ktime_get_ns() (monotonic, CLOCK_MONOTONIC) */
    __u64 cgroup_id;         /* bpf_get_current_cgroup_id()                     */
    __u32 pid;               /* thread id (task pid)                            */
    __u32 tgid;              /* process id                                      */
    __u32 ppid;              /* real_parent->tgid (may be 0 for kernel threads)  */
    __u32 uid;
    __u32 gid;
    __u32 mnt_ns_id;         /* nsproxy->mnt_ns->ns.inum                        */
    __u32 pid_ns_id;         /* nsproxy->pid_ns_for_children->ns.inum           */
    __u32 net_ns_id;         /* nsproxy->net_ns->ns.inum                        */
    __u32 event_type;        /* enum xsypher_event_type                         */
    __s32 retval;            /* syscall / hook return value, if available       */
    __u8 blocked_by_lsm;     /* 1 when an LSM hook denied the operation         */
    __u8 af_family;          /* AF_INET / AF_INET6 (EVENT_CONNECT)              */
    __u16 dport;             /* network byte order                              */
    __u16 sport;             /* network byte order                              */
    __u8 reserved0[2];       /* explicit padding -> keeps daddr_v4 4-byte aligned */
    __u32 daddr_v4;          /* raw network byte order                          */
    __u32 saddr_v4;          /* raw network byte order                          */
    __u8 daddr_v6[16];       /* raw 16-byte address                             */
    __u32 open_flags;        /* openat(2) flags                                 */
    char comm[MAX_COMM_LEN];        /* current->comm, NUL terminated   */
    char parent_comm[MAX_COMM_LEN]; /* real_parent->comm, NUL terminated */
    char filename[MAX_PATH_LEN];    /* execve/openat path, NUL terminated */
    char args[MAX_ARGS_LEN];        /* first argv pointers joined by ' ' */
} __attribute__((packed, aligned(8)));

/* ------------------------------------------------------------------------ */
/* Collector -> Python enriched wire frame                                  */
/* ------------------------------------------------------------------------ */

/*
 * sizeof(struct wire_event_msg_t) == 720
 *   magic 0 | version 4 | msg_type 6 | seq_no 8 | container_id 16 | event 80
 */
struct wire_event_msg_t {
    __u32 magic;   /* XSYPHER_WIRE_MAGIC */
    __u16 version; /* XSYPHER_ABI_VERSION */
    __u16 msg_type; /* enum xsypher_msg_type */
    __u64 seq_no;  /* monotonic frame sequence number */
    /*
     * Container identity resolved from /proc/<pid>/cgroup: either "host" for
     * root-cgroup processes or a 64 hex character Docker/containerd/CRI-O ID.
     * A full-length ID occupies all 64 bytes and is therefore NOT NUL
     * terminated; shorter values are NUL padded.  Decoders must tolerate both.
     */
    char container_id[MAX_CONTAINER_ID_LEN];
    struct kernel_event_t event;
} __attribute__((packed, aligned(8)));

/* ------------------------------------------------------------------------ */
/* Python -> collector control command                                      */
/* ------------------------------------------------------------------------ */

/*
 * sizeof(struct wire_policy_cmd_t) == 32
 *   magic 0 | version 4 | cmd_type 6 | target_cgroup_id 8 | target_pid 16
 *   target_ipv4 20 | enforcement_mode 24 | reserved0 28
 */
struct wire_policy_cmd_t {
    __u32 magic;   /* XSYPHER_WIRE_MAGIC */
    __u16 version; /* XSYPHER_ABI_VERSION */
    __u16 cmd_type; /* enum xsypher_cmd_type */
    __u64 target_cgroup_id;
    __u32 target_pid;
    __u32 target_ipv4; /* raw network byte order */
    __u32 enforcement_mode; /* enum xsypher_enforcement_mode */
    __u32 reserved0; /* explicit tail padding */
} __attribute__((packed, aligned(8)));

/* ------------------------------------------------------------------------ */
/* Compile-time layout assertions (C11 / C++11 onwards)                     */
/* ------------------------------------------------------------------------ */

#if !defined(XSYPHER_BPF_TARGET)
#ifndef XSYPHER_STATIC_ASSERT
#ifdef __cplusplus
#define XSYPHER_STATIC_ASSERT(cond, msg) static_assert(cond, msg)
#else
#define XSYPHER_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#endif
#endif
#endif

#ifdef XSYPHER_STATIC_ASSERT
XSYPHER_STATIC_ASSERT(sizeof(struct kernel_event_t) == 640,
                      "kernel_event_t must be exactly 640 bytes");
XSYPHER_STATIC_ASSERT(sizeof(struct wire_event_msg_t) == 720,
                      "wire_event_msg_t must be exactly 720 bytes");
XSYPHER_STATIC_ASSERT(sizeof(struct wire_policy_cmd_t) == 32,
                      "wire_policy_cmd_t must be exactly 32 bytes");
XSYPHER_STATIC_ASSERT(offsetof(struct kernel_event_t, event_type) == 48,
                      "kernel_event_t::event_type offset changed");
XSYPHER_STATIC_ASSERT(offsetof(struct kernel_event_t, daddr_v4) == 64,
                      "kernel_event_t::daddr_v4 offset changed");
XSYPHER_STATIC_ASSERT(offsetof(struct kernel_event_t, filename) == 124,
                      "kernel_event_t::filename offset changed");
XSYPHER_STATIC_ASSERT(offsetof(struct wire_event_msg_t, event) == 80,
                      "wire_event_msg_t::event offset changed");
#endif

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/*
 * 169.254.169.254 (AWS / GCP / Azure / OCI IMDS) expressed as the raw u32 the
 * kernel stores inside sockaddr_in.sin_addr.s_addr. On little-endian hosts this
 * evaluates to 0xFEA9FEA9, which is the constant documented in the design.
 */
#define XSYPHER_IMDS_IPV4_OCTETS(a, b, c, d) \
    (((__u32)(a) << 24) | ((__u32)(b) << 16) | ((__u32)(c) << 8) | ((__u32)(d)))
#define XSYPHER_IMDS_IPV4_BE XSYPHER_IMDS_IPV4_OCTETS(169, 254, 169, 254) /* 0xA9FEA9FE */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define XSYPHER_IMDS_IPV4_RAW 0xFEA9FEA9u /* raw in-memory u32 on LE hosts */
#else
#define XSYPHER_IMDS_IPV4_RAW 0xA9FEA9FEu
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XSYPHER_ABI_H */
