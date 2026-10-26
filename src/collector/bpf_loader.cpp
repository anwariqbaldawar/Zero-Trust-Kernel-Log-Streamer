// SPDX-License-Identifier: Apache-2.0
//
// bpf_loader.cpp - libbpf lifecycle + policy map handling.
#include "bpf_loader.hpp"

#include <sys/resource.h>

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

    const int config_fd = bpf_map__fd(skel_->maps.config_map);
    if (config_fd >= 0) {
        const std::uint32_t key = 0;
        const std::uint32_t mode = options_.enforce_inline ? ENFORCEMENT_INLINE_BLOCK
                                                           : ENFORCEMENT_AUDIT_ONLY;
        if (bpf_map_update_elem(config_fd, &key, &mode, BPF_ANY) != 0) {
            std::fprintf(stderr, "[xsypher] WARNING: cannot set enforcement mode: %s\n",
                         errno_text(errno).c_str());
        }
    }

    if (options_.block_imds) {
        const int ip_fd = bpf_map__fd(skel_->maps.blocked_ipv4_map);
        const std::uint32_t key = XSYPHER_IMDS_IPV4_RAW;
        const std::uint8_t reason = 1;
        if (ip_fd >= 0 && bpf_map_update_elem(ip_fd, &key, &reason, BPF_ANY) != 0) {
            std::fprintf(stderr, "[xsypher] WARNING: cannot pre-block IMDS address: %s\n",
                         errno_text(errno).c_str());
        }
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
    std::uint32_t key = 0;
    std::uint32_t value = mode;
    if (bpf_map_update_elem(fd, &key, &value, BPF_ANY) != 0) {
        result.err = errno;
        result.message = std::string("config_map: ") + errno_text(result.err);
        return result;
    }
    result.ok = true;
    result.message = "config_map: enforcement_mode=" + std::to_string(mode);
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
