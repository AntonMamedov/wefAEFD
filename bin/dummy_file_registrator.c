#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
int main() {
    int fd = open("/dev/pec", O_RDWR | O_NONBLOCK);
    printf("%s\n", strerror(errno));
    int ret = ioctl(fd, 0, "test_file1");
    printf("%s\n", strerror(errno));
    return 0;
}