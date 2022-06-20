#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/poll.h>

#define DEFAULT_BUFFER_SIZE 1024

int main(int argc, char** argv) {

    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    int fd = open("/dev/pec", O_RDWR | O_NONBLOCK);
    int ret = ioctl(fd, 4, atoi(argv[argc - 1]));
    if (ret < 0)
        return -1;
    while (1) {
        struct pollfd pfds[2] = {
                {
                        .fd =  STDIN_FILENO,
                        .events = POLLIN,
                },
                {
                        .fd = fd,
                        .events = POLLIN
                }
        };
        poll(pfds, 2, -1);
        char buffer[DEFAULT_BUFFER_SIZE];
        if (pfds[0].revents & POLLIN) {
            size_t bytes_len = 0;
            while ((bytes_len = read(STDIN_FILENO, buffer, DEFAULT_BUFFER_SIZE)) > 0) {
                write(fd, buffer, bytes_len);
            }
        }
        if (pfds[1].revents & POLLIN) {
            size_t bytes_len = 0;
            while ((bytes_len = read(fd, buffer, DEFAULT_BUFFER_SIZE)) > 0) {
                write(STDOUT_FILENO, buffer, bytes_len);
            }
        }
    }
}