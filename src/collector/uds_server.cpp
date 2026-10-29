// SPDX-License-Identifier: Apache-2.0
//
// uds_server.cpp - epoll driven AF_UNIX SOCK_SEQPACKET server.
#include "uds_server.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

namespace xsypher {
namespace {

constexpr int kMaxClients = 64;
constexpr std::size_t kMaxSocketPath = sizeof(sockaddr_un::sun_path) - 1;
constexpr std::size_t kRecvBufferCount = 16;

std::string errno_text(int err) {
    char buffer[256];
    std::snprintf(buffer, sizeof(buffer), "%s (%d)",
                  strerror(err) ? strerror(err) : "unknown", err);
    return std::string(buffer);
}

/// Fill a sockaddr_un, rejecting over-long paths.
bool make_sockaddr(const std::string& path, sockaddr_un& addr, socklen_t& len,
                   std::string& error) {
    if (path.empty() || path.size() > kMaxSocketPath) {
        error = "socket path length must be 1.." + std::to_string(kMaxSocketPath);
        return false;
    }
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size());
    len = static_cast<socklen_t>(offsetof(sockaddr_un, sun_path) + path.size() + 1);
    return true;
}

}  // namespace

bool ensure_parent_directories(const std::string& path) {
    const std::size_t slash = path.find_last_of('/');
    if (slash == std::string::npos || slash == 0) {
        return true;
    }
    const std::string dir = path.substr(0, slash);

    std::string partial;
    partial.reserve(dir.size());
    std::size_t pos = 0;
    while (pos <= dir.size()) {
        const std::size_t next = dir.find('/', pos);
        const std::size_t end = (next == std::string::npos) ? dir.size() : next;
        partial = dir.substr(0, end);
        if (!partial.empty()) {
            if (::mkdir(partial.c_str(), 0755) != 0 && errno != EEXIST) {
                return false;
            }
        }
        if (next == std::string::npos) {
            break;
        }
        pos = next + 1;
    }
    return true;
}

UdsServer::UdsServer() = default;

UdsServer::~UdsServer() { shutdown(); }

bool UdsServer::listen_on(const std::string& path, const std::string& fallback_path,
                          std::string& error) {
    error.clear();
    if (listen_fd_ >= 0) {
        error = "server already listening on " + bound_path_;
        return false;
    }

    epoll_fd_ = ::epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd_ < 0) {
        error = "epoll_create1: " + errno_text(errno);
        return false;
    }

    std::string first_error;
    if (!bind_socket(path, first_error)) {
        first_error = path + ": " + first_error;
        if (!fallback_path.empty() && fallback_path != path) {
            std::fprintf(stderr, "[xsypher] WARNING: cannot bind %s (%s); trying %s\n",
                         path.c_str(), first_error.c_str(), fallback_path.c_str());
            if (bind_socket(fallback_path, error)) {
                return true;
            }
            error = first_error + "; fallback " + fallback_path + ": " + error;
            ::close(epoll_fd_);
            epoll_fd_ = -1;
            return false;
        }
        error = first_error;
        ::close(epoll_fd_);
        epoll_fd_ = -1;
        return false;
    }
    return true;
}

bool UdsServer::bind_socket(const std::string& path, std::string& error) {
    (void)ensure_parent_directories(path);

    sockaddr_un addr{};
    socklen_t len = 0;
    if (!make_sockaddr(path, addr, len, error)) {
        return false;
    }

    const int fd = ::socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        error = "socket: " + errno_text(errno);
        return false;
    }

    // Remove a stale socket file left behind by an unclean shutdown.
    if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
        error = "unlink: " + errno_text(errno);
        ::close(fd);
        return false;
    }

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), len) != 0) {
        error = "bind: " + errno_text(errno);
        ::close(fd);
        return false;
    }
    if (::listen(fd, kMaxClients) != 0) {
        error = "listen: " + errno_text(errno);
        ::close(fd);
        (void)::unlink(path.c_str());
        return false;
    }

    listen_fd_ = fd;
    bound_path_ = path;
    add_epoll(fd, EPOLLIN);
    std::fprintf(stderr, "[xsypher] listening on %s (SOCK_SEQPACKET)\n", path.c_str());
    return true;
}

void UdsServer::add_epoll(int fd, std::uint32_t events) {
    epoll_event event{};
    event.events = events;
    event.data.fd = fd;
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &event) != 0) {
        std::fprintf(stderr, "[xsypher] WARNING: epoll_ctl(ADD, fd=%d): %s\n", fd,
                     errno_text(errno).c_str());
    }
}

void UdsServer::del_epoll(int fd) {
    (void)::epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr);
}

bool UdsServer::watch_fd(int fd, FdReadyHandler handler) {
    if (epoll_fd_ < 0 || fd < 0) {
        return false;
    }
    std::lock_guard<std::mutex> guard(clients_mutex_);
    extra_fds_[fd] = std::move(handler);
    add_epoll(fd, EPOLLIN);
    return true;
}

void UdsServer::set_policy_handler(PolicyCommandHandler handler) {
    std::lock_guard<std::mutex> guard(clients_mutex_);
    policy_handler_ = std::move(handler);
}

void UdsServer::set_client_handler(ClientEventHandler handler) {
    std::lock_guard<std::mutex> guard(clients_mutex_);
    client_handler_ = std::move(handler);
}

int UdsServer::poll_once(int timeout_ms) {
    std::vector<epoll_event> events(static_cast<std::size_t>(kMaxClients) + 8);
    const int ready = ::epoll_wait(epoll_fd_, events.data(),
                                   static_cast<int>(events.size()), timeout_ms);
    if (ready < 0) {
        if (errno == EINTR) {
            return 0;
        }
        return -1;
    }

    for (int i = 0; i < ready; ++i) {
        const int fd = events[static_cast<std::size_t>(i)].data.fd;
        const std::uint32_t mask = events[static_cast<std::size_t>(i)].events;

        if (fd == listen_fd_) {
            accept_clients();
            continue;
        }

        // Extra descriptors (signalfd, timerfd, ...) are executed outside the
        // registry lock so their handlers can call back into this object.
        FdReadyHandler extra;
        {
            std::lock_guard<std::mutex> guard(clients_mutex_);
            auto it = extra_fds_.find(fd);
            if (it != extra_fds_.end()) {
                extra = it->second;
            }
        }
        if (extra) {
            extra(fd);
            continue;
        }

        if (mask & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            close_client(fd);
            continue;
        }
        if (mask & EPOLLIN) {
            drain_client(fd);
        }
    }
    return ready;
}

void UdsServer::accept_clients() {
    for (;;) {
        const int fd = ::accept4(listen_fd_, nullptr, nullptr,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            std::fprintf(stderr, "[xsypher] WARNING: accept4: %s\n",
                         errno_text(errno).c_str());
            return;
        }

        bool reject = false;
        {
            std::lock_guard<std::mutex> guard(clients_mutex_);
            if (clients_.size() >= static_cast<std::size_t>(kMaxClients)) {
                reject = true;
            } else {
                Client client;
                client.fd = fd;
                clients_.emplace(fd, client);
            }
        }
        if (reject) {
            std::fprintf(stderr, "[xsypher] WARNING: client limit reached, rejecting fd=%d\n",
                         fd);
            ::close(fd);
            continue;
        }

        add_epoll(fd, EPOLLIN | EPOLLRDHUP);
        std::fprintf(stderr, "[xsypher] engine client connected (fd=%d)\n", fd);
        emit_client_event(true);
    }
}

void UdsServer::close_client(int fd) {
    bool existed = false;
    {
        std::lock_guard<std::mutex> guard(clients_mutex_);
        existed = clients_.erase(fd) > 0;
    }
    if (!existed) {
        return;
    }
    del_epoll(fd);
    ::close(fd);
    std::fprintf(stderr, "[xsypher] engine client disconnected (fd=%d)\n", fd);
    emit_client_event(false);
}

void UdsServer::drain_client(int fd) {
    // SOCK_SEQPACKET: recv() returns exactly one datagram, or -1/EMSGSIZE when
    // the peer sent something larger than our buffer (a protocol violation).
    alignas(8) unsigned char buffer[sizeof(wire_policy_cmd_t) * 2];
    PolicyCommandHandler handler;

    for (std::size_t i = 0; i < kRecvBufferCount; ++i) {
        const ssize_t n = ::recv(fd, buffer, sizeof(buffer), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            close_client(fd);
            return;
        }
        if (n == 0) {
            close_client(fd);
            return;
        }
        if (static_cast<std::size_t>(n) != sizeof(wire_policy_cmd_t)) {
            std::fprintf(stderr,
                         "[xsypher] WARNING: bad control frame size %zd (expected %zu)\n",
                         n, sizeof(wire_policy_cmd_t));
            continue;
        }

        wire_policy_cmd_t cmd{};
        std::memcpy(&cmd, buffer, sizeof(cmd));
        if (cmd.magic != XSYPHER_WIRE_MAGIC) {
            std::fprintf(stderr, "[xsypher] WARNING: bad control magic 0x%08x\n",
                         cmd.magic);
            continue;
        }
        if (cmd.version != XSYPHER_ABI_VERSION) {
            std::fprintf(stderr, "[xsypher] WARNING: unsupported control ABI version %u\n",
                         cmd.version);
            continue;
        }

        {
            std::lock_guard<std::mutex> guard(clients_mutex_);
            handler = policy_handler_;
        }
        received_commands_.fetch_add(1, std::memory_order_relaxed);
        if (handler) {
            handler(cmd);
        }
    }
}

void UdsServer::emit_client_event(bool connected) {
    ClientEventHandler handler;
    std::size_t count = 0;
    {
        std::lock_guard<std::mutex> guard(clients_mutex_);
        handler = client_handler_;
        count = clients_.size();
    }
    if (handler) {
        handler(connected, count);
    }
}

std::size_t UdsServer::broadcast(const wire_event_msg_t& frame) {
    // Called only from the epoll reactor; the fixed-capacity queue needs no lock.
    batch_[batch_size_++] = frame;
    if (batch_size_ == batch_.size())
        flush();
    return client_count(); // queued, not an acknowledgement of delivery
}

void UdsServer::flush() {
    if (!batch_size_)
        return;
    std::array<int, kMaxClients> fds{};
    std::size_t count = 0;
    {
        std::lock_guard<std::mutex> guard(clients_mutex_);
        for (const auto& [fd, client] : clients_)
            if (count < fds.size()) fds[count++] = fd;
    }
    std::array<iovec, 32> iov{};
    std::array<mmsghdr, 32> msgs{};
    for (std::size_t i = 0; i < batch_size_; ++i) {
        iov[i] = {&batch_[i], sizeof(wire_event_msg_t)};
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    for (std::size_t c = 0; c < count; ++c) {
        int n;
        do {
            n = ::sendmmsg(fds[c], msgs.data(), static_cast<unsigned>(batch_size_),
                          MSG_DONTWAIT | MSG_NOSIGNAL);
        } while (n < 0 && errno == EINTR);
        const auto sent = n > 0 ? static_cast<std::size_t>(n) : 0;
        // Partial sends are explicit loss, never an unbounded retry queue.
        dropped_frames_.fetch_add(batch_size_ - sent, std::memory_order_relaxed);
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != ENOBUFS)
            close_client(fds[c]);
    }
    batch_size_ = 0;
}

std::size_t UdsServer::client_count() const noexcept {
    std::lock_guard<std::mutex> guard(clients_mutex_);
    return clients_.size();
}

void UdsServer::shutdown() {
    if (shutting_down_.exchange(true)) {
        return;
    }

    std::vector<int> fds;
    {
        std::lock_guard<std::mutex> guard(clients_mutex_);
        fds.reserve(clients_.size());
        for (const auto& entry : clients_) {
            fds.push_back(entry.first);
        }
        clients_.clear();
        extra_fds_.clear();
    }
    for (const int fd : fds) {
        ::close(fd);
    }

    if (listen_fd_ >= 0) {
        del_epoll(listen_fd_);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (epoll_fd_ >= 0) {
        ::close(epoll_fd_);
        epoll_fd_ = -1;
    }
    if (!bound_path_.empty()) {
        (void)::unlink(bound_path_.c_str());
        std::fprintf(stderr, "[xsypher] unlinked %s\n", bound_path_.c_str());
        bound_path_.clear();
    }
}

}  // namespace xsypher
