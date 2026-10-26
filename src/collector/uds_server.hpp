// SPDX-License-Identifier: Apache-2.0
//
// uds_server.hpp - AF_UNIX SOCK_SEQPACKET transport between the C++ collector
// (kernel side) and the Python threat engine (policy side).
//
// * upstream   : wire_event_msg_t datagrams, one per datagram, broadcast to
//                every connected engine (non-blocking, best-effort).
// * downstream : wire_policy_cmd_t datagrams, one per datagram, each delivered
//                to a callback which applies it to the BPF maps.
//
// SOCK_SEQPACKET preserves message boundaries and is connection oriented,
// which is exactly what a binary, versioned protocol needs.
#pragma once

#include <sys/epoll.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

#include "xsypher_abi.h"

namespace xsypher {

/// Callbacks invoked from the epoll loop.
using PolicyCommandHandler = std::function<void(const wire_policy_cmd_t&)>;
using ClientEventHandler = std::function<void(bool connected, std::size_t clients)>;

/// Generic readable-fd callback, used to multiplex signalfd alongside clients.
using FdReadyHandler = std::function<void(int fd)>;

class UdsServer {
public:
    UdsServer();
    ~UdsServer();

    UdsServer(const UdsServer&) = delete;
    UdsServer& operator=(const UdsServer&) = delete;

    /// Create, bind and listen on `path`.  Parent directories are created as
    /// needed.  If `path` is not writable and `fallback_path` is non-empty, the
    /// server retries there (mirrors the /run -> /tmp behaviour).
    bool listen_on(const std::string& path, const std::string& fallback_path,
                   std::string& error);

    /// Path the server is actually bound to.
    const std::string& socket_path() const noexcept { return bound_path_; }

    /// Register the handler for policy commands received from Python.
    void set_policy_handler(PolicyCommandHandler handler);

    /// Register an optional client connect/disconnect observer.
    void set_client_handler(ClientEventHandler handler);

    /// Add an extra fd (e.g. signalfd) to the epoll set.  Returns false on
    /// failure and leaves the epoll set untouched.
    bool watch_fd(int fd, FdReadyHandler handler);

    /// Run one epoll iteration with `timeout_ms`.  Returns the number of ready
    /// descriptors, or -1 with errno set.
    int poll_once(int timeout_ms);

    /// Broadcast one wire frame to every connected client.
    /// Returns the number of clients that accepted the frame.
    std::size_t broadcast(const wire_event_msg_t& frame);

    /// Number of currently connected engine clients.
    std::size_t client_count() const noexcept;

    /// Frames dropped because a client socket buffer was full / closed.
    std::uint64_t dropped_frames() const noexcept {
        return dropped_frames_.load(std::memory_order_relaxed);
    }

    /// Commands accepted from clients.
    std::uint64_t received_commands() const noexcept {
        return received_commands_.load(std::memory_order_relaxed);
    }

    /// Close all sockets and unlink the socket file.  Idempotent.
    void shutdown();

private:
    struct Client {
        int fd = -1;
        std::uint64_t frames_sent = 0;
        std::uint64_t frames_dropped = 0;
    };

    bool bind_socket(const std::string& path, std::string& error);
    void accept_clients();
    void close_client(int fd);
    void drain_client(int fd);
    void emit_client_event(bool connected);
    void add_epoll(int fd, std::uint32_t events);
    void del_epoll(int fd);

    int listen_fd_ = -1;
    int epoll_fd_ = -1;
    std::string bound_path_{};
    std::unordered_map<int, Client> clients_{};
    std::unordered_map<int, FdReadyHandler> extra_fds_{};
    mutable std::mutex clients_mutex_{};
    PolicyCommandHandler policy_handler_{};
    ClientEventHandler client_handler_{};
    std::atomic<std::uint64_t> dropped_frames_{0};
    std::atomic<std::uint64_t> received_commands_{0};
    std::atomic<bool> shutting_down_{false};
};

/// Create all missing parent directories of `path`.  Returns false on error.
bool ensure_parent_directories(const std::string& path);

}  // namespace xsypher
