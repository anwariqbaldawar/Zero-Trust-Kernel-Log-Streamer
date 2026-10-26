// SPDX-License-Identifier: Apache-2.0
//
// cgroup_resolver.hpp - container identity resolution for kernel events.
//
// Every kernel event carries `pid` and `cgroup_id`.  Resolving those to a
// Docker / containerd / CRI-O container ID requires a /proc walk, which is far
// too slow to run inline for every syscall.  This component keeps a bounded
// LRU cache with a TTL so that steady-state traffic costs one hash lookup.
#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>

#include "xsypher_abi.h"

namespace xsypher {

/// Maximum length of a resolved container identity, including the NUL.
constexpr std::size_t kContainerIdCapacity = MAX_CONTAINER_ID_LEN;

class CgroupResolver {
public:
    explicit CgroupResolver(std::size_t capacity = 4096, double ttl_seconds = 5.0);

    /// Resolve `pid` to a container ID.  Returns "host" for processes in the
    /// root cgroup, an empty string when /proc/<pid> has disappeared.  Results
    /// are cached; the cache is LRU-bounded and TTL-expired.
    std::string resolve_pid(std::uint32_t pid);

    /// Resolve using the kernel-provided cgroup ID when it has already been
    /// mapped by an earlier PID resolution; falls back to `resolve_pid()`.
    std::string resolve_cgroup(std::uint64_t cgroup_id, std::uint32_t pid);

    /// Register an explicit cgroup -> container mapping (used when a PID
    /// resolution succeeded and we know the cgroup ID of that event).
    void remember_cgroup(std::uint64_t cgroup_id, const std::string& container_id);

    /// True when the identity is a real container (not the host).
    static bool is_container(const std::string& container_id);

    /// Statistics for the collector's periodic status line.
    struct Stats {
        std::uint64_t hits = 0;
        std::uint64_t misses = 0;
        std::uint64_t lookups = 0;
        std::size_t cached_pids = 0;
        std::size_t cached_cgroups = 0;
    };
    Stats stats() const;

    /// Drop all cached entries (used on SIGHUP / config reload).
    void clear();

    // -- pure helpers, exposed for unit testing ---------------------------- //
    /// Extract a container ID from the raw text of /proc/<pid>/cgroup.
    /// Returns "host" when no container runtime ID is present.
    static std::string parse_cgroup_file(const std::string& contents);

private:
    struct Entry {
        std::string container_id;
        std::uint64_t expires_at_ms = 0;
        std::list<std::uint32_t>::iterator lru_it;
    };

    static std::uint64_t now_ms();
    std::string resolve_pid_locked(std::uint32_t pid);
    void evict_locked();
    void touch_locked(std::unordered_map<std::uint32_t, Entry>::iterator it);

    mutable std::mutex mutex_{};
    std::size_t capacity_;
    std::uint64_t ttl_ms_;
    std::unordered_map<std::uint32_t, Entry> pid_cache_{};
    std::list<std::uint32_t> lru_{};
    std::unordered_map<std::uint64_t, std::string> cgroup_cache_{};
    std::size_t cgroup_capacity_;
    mutable Stats stats_{};
};

}  // namespace xsypher
