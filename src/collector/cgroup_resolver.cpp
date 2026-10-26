// SPDX-License-Identifier: Apache-2.0
//
// cgroup_resolver.cpp - /proc based container identity resolution.
#include "cgroup_resolver.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string_view>

namespace xsypher {
namespace {

/// Docker, containerd and CRI-O all use 64 hex characters for the container ID.
constexpr std::size_t kContainerIdHexLen = 64;
/// Some runtimes expose only the short (12 hex char) identifier.
constexpr std::size_t kShortContainerIdLen = 12;

bool is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

std::string to_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

/// Read at most `limit` bytes from a file.  Returns false on any error.
bool read_small_file(const std::string& path, std::size_t limit, std::string& out) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    std::array<char, 4096> buffer{};
    std::size_t total = 0;
    out.clear();
    while (total < limit) {
        const std::size_t want = std::min(buffer.size(), limit - total);
        const ssize_t n = ::read(fd, buffer.data(), want);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            ::close(fd);
            return false;
        }
        if (n == 0) {
            break;
        }
        out.append(buffer.data(), static_cast<std::size_t>(n));
        total += static_cast<std::size_t>(n);
    }
    ::close(fd);
    return true;
}

}  // namespace

CgroupResolver::CgroupResolver(std::size_t capacity, double ttl_seconds)
    : capacity_(capacity == 0 ? 1 : capacity),
      ttl_ms_(ttl_seconds <= 0.0 ? 0
                                 : static_cast<std::uint64_t>(ttl_seconds * 1000.0)),
      cgroup_capacity_(capacity == 0 ? 1 : capacity * 2) {}

std::uint64_t CgroupResolver::now_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

bool CgroupResolver::is_container(const std::string& container_id) {
    return !container_id.empty() && container_id != "host";
}

std::string CgroupResolver::parse_cgroup_file(const std::string& contents) {
    // Typical lines:
    //   0::/system.slice/docker-<64hex>.scope
    //   0::/kubepods/burstable/pod<uid>/<64hex>
    //   12:devices:/docker/<64hex>
    //   0::/user.slice/user-1000.slice/session-3.scope        -> host
    std::istringstream stream(contents);
    std::string line;
    std::string fallback;
    while (std::getline(stream, line)) {
        std::string_view view(line);
        // Drop the "hierarchy-id:controllers:" prefix if present.
        const std::size_t first_colon = view.find(':');
        if (first_colon != std::string_view::npos) {
            const std::size_t second_colon = view.find(':', first_colon + 1);
            if (second_colon != std::string_view::npos) {
                view.remove_prefix(second_colon + 1);
            }
        }

        // Scan for a maximal run of hex characters.
        std::size_t i = 0;
        while (i < view.size()) {
            if (!is_hex(view[i])) {
                ++i;
                continue;
            }
            const std::size_t start = i;
            while (i < view.size() && is_hex(view[i])) {
                ++i;
            }
            const std::size_t run = i - start;
            if (run == kContainerIdHexLen) {
                return to_lower(std::string(view.substr(start, run)));
            }
            // systemd cgroup driver: "docker-<64hex>.scope" already handled;
            // some runtimes prefix with a short (12 char) ID only.
            if (run == kShortContainerIdLen && fallback.empty()) {
                fallback = to_lower(std::string(view.substr(start, run)));
            }
        }
    }
    if (!fallback.empty()) {
        return fallback;
    }
    return "host";
}

std::string CgroupResolver::resolve_pid(std::uint32_t pid) {
    std::lock_guard<std::mutex> guard(mutex_);
    ++stats_.lookups;

    const std::uint64_t now = now_ms();
    auto it = pid_cache_.find(pid);
    if (it != pid_cache_.end() && it->second.expires_at_ms > now) {
        ++stats_.hits;
        touch_locked(it);
        return it->second.container_id;
    }

    // Expired entry: drop it so the LRU bookkeeping stays consistent.
    if (it != pid_cache_.end()) {
        lru_.erase(it->second.lru_it);
        pid_cache_.erase(it);
    }

    ++stats_.misses;
    return resolve_pid_locked(pid);
}

std::string CgroupResolver::resolve_pid_locked(std::uint32_t pid) {
    std::string contents;
    std::string container_id;
    const std::string path = "/proc/" + std::to_string(pid) + "/cgroup";

    if (read_small_file(path, 8192, contents)) {
        container_id = parse_cgroup_file(contents);
    } else {
        // Process already gone; do not poison the cache with a bogus entry.
        return {};
    }

    Entry entry;
    entry.container_id = container_id;
    entry.expires_at_ms = now_ms() + ttl_ms_;
    lru_.push_back(pid);
    entry.lru_it = std::prev(lru_.end());
    pid_cache_[pid] = std::move(entry);
    evict_locked();

    stats_.cached_pids = pid_cache_.size();
    return container_id;
}

void CgroupResolver::touch_locked(std::unordered_map<std::uint32_t, Entry>::iterator it) {
    lru_.erase(it->second.lru_it);
    lru_.push_back(it->first);
    it->second.lru_it = std::prev(lru_.end());
}

void CgroupResolver::evict_locked() {
    while (pid_cache_.size() > capacity_ && !lru_.empty()) {
        const std::uint32_t victim = lru_.front();
        lru_.pop_front();
        pid_cache_.erase(victim);
    }
    stats_.cached_pids = pid_cache_.size();
}

void CgroupResolver::remember_cgroup(std::uint64_t cgroup_id,
                                     const std::string& container_id) {
    if (cgroup_id == 0 || container_id.empty()) {
        return;
    }
    std::lock_guard<std::mutex> guard(mutex_);
    if (cgroup_cache_.size() >= cgroup_capacity_) {
        // Cheap bounded eviction: drop a chunk of arbitrary entries.
        std::size_t to_drop = cgroup_capacity_ / 4;
        for (auto it = cgroup_cache_.begin(); it != cgroup_cache_.end() && to_drop > 0;
             ++to_drop) {
            it = cgroup_cache_.erase(it);
        }
    }
    cgroup_cache_[cgroup_id] = container_id;
    stats_.cached_cgroups = cgroup_cache_.size();
}

std::string CgroupResolver::resolve_cgroup(std::uint64_t cgroup_id,
                                           std::uint32_t pid) {
    {
        std::lock_guard<std::mutex> guard(mutex_);
        auto it = cgroup_cache_.find(cgroup_id);
        if (it != cgroup_cache_.end()) {
            ++stats_.hits;
            return it->second;
        }
    }

    const std::string container_id = resolve_pid(pid);
    if (!container_id.empty()) {
        remember_cgroup(cgroup_id, container_id);
    }
    return container_id;
}

CgroupResolver::Stats CgroupResolver::stats() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return stats_;
}

void CgroupResolver::clear() {
    std::lock_guard<std::mutex> guard(mutex_);
    pid_cache_.clear();
    lru_.clear();
    cgroup_cache_.clear();
    stats_.cached_pids = 0;
    stats_.cached_cgroups = 0;
}

}  // namespace xsypher
