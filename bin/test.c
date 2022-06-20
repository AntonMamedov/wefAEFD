#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/wait.h>
int main (int argc, char* argv[]) {
    pid_t  pid;
    int ret = 1;
    int status;

    int fds[2];
    pipe (fds);
    pid = fork();

    if (pid == -1){
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        close(fds[1]);
        dup2(fds[0], STDIN_FILENO);
        execve("test_file1", argv, argv);
    }

    close(fds[0]);
    FILE* stream;
    stream = fdopen(fds[1], "w");
    waitpid(pid, NULL, 0);
}
