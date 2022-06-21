#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
int main (int argc, char* argv[]) {
    pid_t  pid;

    int fds1[2];
    int fds2[2];
    pipe (fds1);
    pipe (fds2);
    pid = fork();
    if (pid == -1){
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
       close(fds1[1]);
       dup2(fds1[0], STDIN_FILENO);
       close(fds2[0]);
       dup2(fds2[1], STDOUT_FILENO);
       execve("test_file1", argv, argv);
    }

    close(fds1[0]);
    close(fds2[1]);

    int b_read = 0;
    do{
        char buff[1024];
        b_read = read(fds2[0], buff, 1024);
        write(STDOUT_FILENO, buff, b_read);
    } while (b_read > 0);
    return 0;
}
