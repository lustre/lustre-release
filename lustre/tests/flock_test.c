#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>

void chd_lock_unlock(int);
char fname[1024];

int main(int argc, char **argv)
{
    pid_t pid;
    int cfd, fd, rc;

    if (argc != 2) {
        fprintf(stderr, "\nUSAGE: flock_test filepath\n");
        exit(2);
    }
    strncpy(fname, argv[1], 1023);
    fname[1023] ='\0';
    fd = open(fname, O_RDWR|O_CREAT, (mode_t)0666);
    if (fd == -1) {
        fprintf(stderr, "flock_test: failed to open %s : ", fname);
        perror("");
        exit(1);
    }
    if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
        fprintf(stderr, "flock_test: parent attempt to lock %s failed : ", \
            fname);
        perror("");
        exit(1);
    }

    pid = fork();
    if (pid == -1) {
        fprintf(stderr, "flock_test: fork failed : ");
        perror("");
        exit(1);
    }

    if (pid == 0) {
        pid = getpid();
        sleep(2);
        if ((cfd = open(fname, O_RDWR)) == -1) {
            fprintf(stderr, "flock_test child (%d) cannot open %s: ", \
                pid, fname);
            perror("");
            exit(1);
        }
        if(flock(cfd, LOCK_EX | LOCK_NB) != -1) {
            fprintf(stderr, "flock_test child (%d): %s not yet locked  : ", \
                pid, fname);
            exit(1);
        }
        if(flock(fd, LOCK_UN) == -1) {
            fprintf(stderr, "flock_test child (%d): cannot unlock %s: ", \
                pid, fname);
            perror("");
            exit(1);
        }
        if(flock(cfd, LOCK_EX | LOCK_NB) == -1 ) {
            fprintf(stderr, \
                "flock_test: child (%d) cannot re-lock %s after unlocking : ", \
                pid, fname);
            perror("");
            exit(1);
        }
        close(cfd);
        exit(0);
    }

    waitpid(pid, &rc, 0);
    close(fd);
    unlink(fname);
    if (WIFEXITED(rc) && WEXITSTATUS(rc) != 0) {
        fprintf(stderr, "flock_test: child (%d) exit code = %d\n", \
            pid, WEXITSTATUS(rc));
        exit(1);
    }
    exit(0);
}
