#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main() {

    int fd = open("/dev/pec", O_RDWR);
     ioctl(fd, 1);
    char a[50] = "test_file1";
    printf("%s\n", strerror(errno));
    ioctl(fd, 3, "test_file1");
    printf("%s\n", strerror(errno));
    size_t test = 0;
    int ret = ioctl(fd, 5, &test);
    printf("%s\n", strerror(errno));
    close(fd);
    return 0;
}