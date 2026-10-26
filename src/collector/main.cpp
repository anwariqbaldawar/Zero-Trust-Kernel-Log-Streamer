// SPDX-License-Identifier: Apache-2.0
//
// main.cpp - xSypher-Stream collector daemon.
//
// Responsibilities
//   * load + attach the CO-RE BPF object (with graceful LSM fallback)
//   * drain the 16 MiB telemetry ring buffer
//   * enrich every event with container identity
//   * fan telemetry out to Python over AF_UNIX/SOCK_SEQPACKET
//   * apply policy commands coming back from the Python threat engine
//
// The main loop is a single-threaded epoll reactor: the ring buffer, the
// client sockets and the signal fd all share one epoll instance, so there are
// no lock contention or wake-up latency problems on the hot path.
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#if __has_include(<bpf/libbpf_version.h>)
#include <bpf/libbpf_version.h>
#endif

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "bpf_loader.hpp"
#include "cgroup_resolver.hpp"
#include "uds_server.hpp"
#include "xsypher_abi.h"

namespace {

constexpr const char* kDefaultSocketPath = "/run/xsypher/stream.sock";
constexpr const char* kFallbackSocketPath = "/tmp/xsypher-stream.sock";
constexpr int kStatusIntervalMs = 10000;

/// Command line options.
struct Config {
    std::string socket_path = kDefaultSocketPath;
    bool socket_path_from_cli = false;
    bool enforce = false;
    bool block_imds = false;
    bool verbose = false;
    bool lsm_fallback = true;
    bool status_report = true;
};

/// Everything the ring buffer callback needs.
struct RuntimeContext {
    xsypher::BpfLoader* loader = nullptr;
    xsypher::CgroupResolver* resolver = nullptr;
    xsypher::UdsServer* server = nullptr;
    std::atomic<std::uint64_t> seq{0};
    std::atomic<std::uint64_t> events_seen{0};
    std::atomic<std::uint64_t> events_sent{0};
    std::atomic<std::uint64_t> malformed{0};
    std::atomic<std::uint64_t> unknown_cgroup{0};
};

void usage(const char* argv0) {
    std::printf(
        "xSypher-Stream collector (ABI v%u)\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  --socket-path <path>   Unix socket to bind (default: %s)\n"
        "  --enforce              Start in INLINE_BLOCK enforcement mode\n"
        "  --block-imds           Pre-block 169.254.169.254 in blocked_ipv4_map\n"
        "  --no-lsm-fallback      Fail instead of degrading to telemetry-only mode\n"
        "  --no-status            Disable the periodic status line\n"
        "  --verbose              Verbose libbpf logging\n"
        "  -h, --help             Show this help\n"
        "  -V, --version          Show version\n",
        XSYPHER_ABI_VERSION, argv0, kDefaultSocketPath);
}

bool parse_args(int argc, char** argv, Config& config) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            usage(argv[0]);
            std::exit(0);
        }
        if (arg == "-V" || arg == "--version") {
            std::printf("xsypher-collector ABI v%u\n", XSYPHER_ABI_VERSION);
            std::exit(0);
        }
        if (arg == "--enforce") {
            config.enforce = true;
        } else if (arg == "--block-imds") {
            config.block_imds = true;
        } else if (arg == "--verbose") {
            config.verbose = true;
        } else if (arg == "--no-lsm-fallback") {
            config.lsm_fallback = false;
        } else if (arg == "--no-status") {
            config.status_report = false;
        } else if (arg == "--socket-path") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "error: --socket-path requires a value\n");
                return false;
            }
            config.socket_path = argv[++i];
            config.socket_path_from_cli = true;
        } else if (arg.rfind("--socket-path=", 0) == 0) {
            config.socket_path = arg.substr(std::strlen("--socket-path="));
            config.socket_path_from_cli = true;
        } else {
            std::fprintf(stderr, "error: unknown option '%s'\n", arg.c_str());
            usage(argv[0]);
            return false;
        }
    }
    return true;
}

/// Copy a container identity into the fixed-width wire field.
void set_container_id(wire_event_msg_t& frame, const std::string& container_id) {
    std::memset(frame.container_id, 0, sizeof(frame.container_id));
    const std::string value = container_id.empty() ? "host" : container_id;
    // The identity field is fixed width: a 64-hex container ID fills it
    // completely and is therefore not NUL terminated (shorter values are NUL
    // padded), exactly like src/engine/abi.py expects.
    const std::size_t copy_len =
        value.size() < sizeof(frame.container_id) ? value.size()
                                                  : sizeof(frame.container_id);
    std::memcpy(frame.container_id, value.data(), copy_len);
}

/// libbpf ring buffer callback: one kernel_event_t record per invocation.
int handle_ringbuf_event(void* ctx_ptr, void* data, std::size_t len) {
    auto* ctx = static_cast<RuntimeContext*>(ctx_ptr);
    if (!ctx || !data) {
        return 0;
    }
    if (len != sizeof(kernel_event_t)) {
        ctx->malformed.fetch_add(1, std::memory_order_relaxed);
        return 0;
    }

    const auto* event = static_cast<const kernel_event_t*>(data);
    ctx->events_seen.fetch_add(1, std::memory_order_relaxed);

    const std::uint32_t lookup_pid = event->tgid != 0 ? event->tgid : event->pid;
    std::string container_id;
    if (ctx->resolver) {
        container_id = ctx->resolver->resolve_cgroup(event->cgroup_id, lookup_pid);
        if (container_id.empty()) {
            ctx->unknown_cgroup.fetch_add(1, std::memory_order_relaxed);
            container_id = "host";
        }
    } else {
        container_id = "host";
    }

    wire_event_msg_t frame{};
    frame.magic = XSYPHER_WIRE_MAGIC;
    frame.version = XSYPHER_ABI_VERSION;
    frame.msg_type = MSG_TELEMETRY_EVENT;
    frame.seq_no = ctx->seq.fetch_add(1, std::memory_order_relaxed);
    frame.event = *event;
    set_container_id(frame, container_id);

    if (ctx->server && ctx->server->broadcast(frame) > 0) {
        ctx->events_sent.fetch_add(1, std::memory_order_relaxed);
    }
    return 0;
}

/// Apply a policy command coming back from the Python engine.
void handle_policy_command(xsypher::BpfLoader& loader, const wire_policy_cmd_t& cmd) {
    xsypher::MapResult result;
    switch (cmd.cmd_type) {
        case CMD_QUARANTINE_PID:
            result = loader.quarantine_pid(cmd.target_pid, QUARANTINE_BLOCK);
            break;
        case CMD_UNQUARANTINE_PID:
            result = loader.unquarantine_pid(cmd.target_pid);
            break;
        case CMD_QUARANTINE_CGROUP:
            result = loader.quarantine_cgroup(cmd.target_cgroup_id, QUARANTINE_BLOCK);
            break;
        case CMD_UNQUARANTINE_CGROUP:
            result = loader.unquarantine_cgroup(cmd.target_cgroup_id);
            break;
        case CMD_BLOCK_IPV4:
            result = loader.block_ipv4(cmd.target_ipv4, 1);
            break;
        case CMD_UNBLOCK_IPV4:
            result = loader.unblock_ipv4(cmd.target_ipv4);
            break;
        case CMD_SET_ENFORCEMENT_MODE:
            result = loader.set_enforcement_mode(cmd.enforcement_mode);
            break;
        default:
            std::fprintf(stderr, "[xsypher] WARNING: unknown policy cmd %u\n",
                         cmd.cmd_type);
            return;
    }

    if (!result.ok) {
        std::fprintf(stderr, "[xsypher] WARNING: policy cmd %u failed: %s\n",
                     cmd.cmd_type, result.message.c_str());
    } else {
        std::fprintf(stderr, "[xsypher] policy cmd %u applied: %s\n", cmd.cmd_type,
                     result.message.c_str());
    }
}

void report_status(RuntimeContext& ctx, const xsypher::BpfLoader& loader,
                   const xsypher::UdsServer& server,
                   const xsypher::CgroupResolver& resolver) {
    const std::vector<std::uint64_t> metrics = loader.read_metrics();
    const auto resolver_stats = resolver.stats();

    std::string counters = "kernel_metrics=unavailable";
    if (metrics.size() >= METRIC_MAX) {
        char buffer[256];
        std::snprintf(buffer, sizeof(buffer),
                      "events=%llu drops=%llu lsm_blocks=%llu imds=%llu ip=%llu denials=%llu",
                      static_cast<unsigned long long>(metrics[METRIC_EVENTS_TOTAL]),
                      static_cast<unsigned long long>(metrics[METRIC_RINGBUF_DROPS]),
                      static_cast<unsigned long long>(metrics[METRIC_LSM_BLOCKS]),
                      static_cast<unsigned long long>(metrics[METRIC_IMDS_BLOCKS]),
                      static_cast<unsigned long long>(metrics[METRIC_IP_BLOCKS]),
                      static_cast<unsigned long long>(metrics[METRIC_QUARANTINE_DENIES]));
        counters = buffer;
    }

    std::fprintf(stderr,
                 "[xsypher] status %s | ringbuf=%llu sent=%llu bad=%llu | clients=%zu | "
                 "cmd=%llu dropped=%llu | resolver hits=%llu misses=%llu | %s\n",
                 loader.status_line().c_str(),
                 static_cast<unsigned long long>(ctx.events_seen.load()),
                 static_cast<unsigned long long>(ctx.events_sent.load()),
                 static_cast<unsigned long long>(ctx.malformed.load()),
                 server.client_count(),
                 static_cast<unsigned long long>(server.received_commands()),
                 static_cast<unsigned long long>(server.dropped_frames()),
                 static_cast<unsigned long long>(resolver_stats.hits),
                 static_cast<unsigned long long>(resolver_stats.misses),
                 counters.c_str());
}

std::uint64_t monotonic_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

}  // namespace

int main(int argc, char** argv) {
    Config config;
    if (!parse_args(argc, argv, config)) {
        return 2;
    }

    std::signal(SIGPIPE, SIG_IGN);

    // Signals are consumed through signalfd so the reactor never needs to
    // interrupt a syscall.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGQUIT);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
        std::fprintf(stderr, "error: sigprocmask: %s\n", std::strerror(errno));
        return 1;
    }
    const int signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (signal_fd < 0) {
        std::fprintf(stderr, "error: signalfd: %s\n", std::strerror(errno));
        return 1;
    }

    xsypher::install_libbpf_logging(config.verbose);

    xsypher::CgroupResolver resolver;
    xsypher::UdsServer server;

    const std::string fallback =
        config.socket_path_from_cli ? std::string() : std::string(kFallbackSocketPath);
    std::string error;
    if (!server.listen_on(config.socket_path, fallback, error)) {
        std::fprintf(stderr, "error: cannot create socket: %s\n", error.c_str());
        ::close(signal_fd);
        return 1;
    }

    xsypher::BpfLoader loader;
    xsypher::LoaderOptions loader_options;
    loader_options.enforce_inline = config.enforce;
    loader_options.block_imds = config.block_imds;
    loader_options.verbose = config.verbose;
    loader_options.allow_lsm_fallback = config.lsm_fallback;

    if (!loader.load_and_attach(loader_options, error)) {
        std::fprintf(stderr, "error: cannot load BPF object: %s\n", error.c_str());
        server.shutdown();
        ::close(signal_fd);
        return 1;
    }

    std::fprintf(stderr,
                 "[xsypher] collector ready: %s | enforce=%s | imds_block=%s | socket=%s\n",
                 loader.status_line().c_str(),
                 config.enforce ? "yes" : "no", config.block_imds ? "yes" : "no",
                 server.socket_path().c_str());
    if (!loader.lsm_available()) {
        std::fprintf(stderr,
                     "[xsypher] NOTICE: inline enforcement is inactive - rebuild the "
                     "kernel with CONFIG_BPF_LSM=y and boot with lsm=bpf\n");
    }

    RuntimeContext ctx;
    ctx.loader = &loader;
    ctx.resolver = &resolver;
    ctx.server = &server;

    server.set_policy_handler(
        [&loader](const wire_policy_cmd_t& cmd) { handle_policy_command(loader, cmd); });

    server.set_client_handler([](bool connected, std::size_t clients) {
        std::fprintf(stderr, "[xsypher] engine %s (%zu client(s) attached)\n",
                     connected ? "connected" : "disconnected", clients);
    });

    struct ring_buffer* ring = ring_buffer__new(loader.ringbuf_fd(), handle_ringbuf_event,
                                                &ctx, nullptr);
    if (!ring) {
        std::fprintf(stderr, "error: ring_buffer__new failed: %s\n",
                     std::strerror(errno));
        loader.unload();
        server.shutdown();
        ::close(signal_fd);
        return 1;
    }

    // Prefer event driven ring buffer polling; fall back to a timed poll on
    // libbpf versions older than 1.1 which do not expose the epoll fd.
    bool ring_epoll_attached = false;
#if defined(LIBBPF_MAJOR_VERSION) && defined(LIBBPF_MINOR_VERSION)
#if LIBBPF_MAJOR_VERSION > 1 || (LIBBPF_MAJOR_VERSION == 1 && LIBBPF_MINOR_VERSION >= 1)
    const int ring_fd = ring_buffer__epoll_fd(ring);
    if (ring_fd >= 0 &&
        server.watch_fd(ring_fd, [ring](int) { (void)ring_buffer__poll(ring, 0); })) {
        ring_epoll_attached = true;
    }
#endif
#endif
    if (!ring_epoll_attached) {
        std::fprintf(stderr,
                     "[xsypher] NOTICE: falling back to timed ring buffer polling\n");
    }

    bool running = true;
    server.watch_fd(signal_fd, [&running, &resolver](int fd) {
        signalfd_siginfo info{};
        while (::read(fd, &info, sizeof(info)) == static_cast<ssize_t>(sizeof(info))) {
            std::fprintf(stderr, "[xsypher] received signal %u\n", info.ssi_signo);
            if (info.ssi_signo == SIGHUP) {
                // Treat SIGHUP as "reload": drop cached container identities.
                resolver.clear();
                continue;
            }
            running = false;
        }
    });

    std::uint64_t last_status = monotonic_ms();

    while (running) {
        const int ready = server.poll_once(250);
        if (ready < 0) {
            std::fprintf(stderr, "error: epoll_wait: %s\n", std::strerror(errno));
            break;
        }
        if (!ring_epoll_attached) {
            const int rc = ring_buffer__poll(ring, 0);
            if (rc < 0 && rc != -EINTR) {
                std::fprintf(stderr, "error: ring_buffer__poll: %s\n", std::strerror(-rc));
                break;
            }
        }

        if (config.status_report) {
            const std::uint64_t now = monotonic_ms();
            if (now - last_status >= static_cast<std::uint64_t>(kStatusIntervalMs)) {
                report_status(ctx, loader, server, resolver);
                last_status = now;
            }
        }
    }

    std::fprintf(stderr, "[xsypher] shutting down\n");
    ring_buffer__free(ring);
    loader.unload();
    server.shutdown();
    ::close(signal_fd);

    std::fprintf(stderr,
                 "[xsypher] final: ringbuf_events=%llu forwarded=%llu malformed=%llu\n",
                 static_cast<unsigned long long>(ctx.events_seen.load()),
                 static_cast<unsigned long long>(ctx.events_sent.load()),
                 static_cast<unsigned long long>(ctx.malformed.load()));
    return 0;
}
