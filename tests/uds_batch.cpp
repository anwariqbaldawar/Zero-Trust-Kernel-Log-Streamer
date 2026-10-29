#include "uds_server.hpp"
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <string>
int main() {
    xsypher::UdsServer server;
    std::string error;
    std::string path = "/tmp/xsypher-batch-" + std::to_string(getpid()) + ".sock";
    assert(server.listen_on(path, "", error));
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);
    assert(fd >= 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::strcpy(addr.sun_path, path.c_str());
    assert(connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0);
    server.poll_once(100);
    for (unsigned i = 0; i < 35; ++i) {
        wire_event_msg_t frame{};
        frame.magic = XSYPHER_WIRE_MAGIC;
        frame.seq_no = i;
        server.broadcast(frame);
    }
    server.flush();
    for (unsigned i = 0; i < 35; ++i) {
        wire_event_msg_t frame{};
        assert(recv(fd, &frame, sizeof(frame), 0) == sizeof(frame));
        assert(frame.magic == XSYPHER_WIRE_MAGIC && frame.seq_no == i);
    }
    assert(server.dropped_frames() == 0);
    close(fd);
}
