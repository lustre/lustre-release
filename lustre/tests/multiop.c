#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>

#define T1 "write data before unlink\n"
#define T2 "write data after unlink\n"
char buf[128];

char usage[] = 
"Usage: %s filename command-sequence\n"
"    command-sequence items:\n"
"        o  open(O_RDONLY)\n"
"        O  open(O_CREAT|O_RDWR)\n"
"        u  unlink\n"
"        m  mknod\n"
"        c  close\n"
"        _  wait for signal\n"
"        s  stat\n"
"        S  fstat\n";

int main(int argc, char **argv)
{
        char *fname, *commands;
        struct stat st;
        int fd;

        if (argc != 3) {
                fprintf(stderr, usage, argv[0]);
                exit(1);
        }

        fname = argv[1];
        commands = argv[2];

        while (*commands) {
                switch (*commands) {
                case 'o':
                        fd = open(fname, O_RDONLY);
                        if (fd == -1) {
                                perror("open(O_RDONLY)");
                                exit(1);
                        }
                        break;
                case 'O':
                        fd = open(fname, O_CREAT|O_RDWR, 0644);
                        if (fd == -1) {
                                perror("open(O_RDWR|O_CREAT");
                                exit(1);
                        }
                        break;
                case 'm':
                        if (mknod(fname, S_IFREG | 0644, 0) == -1) {
                                perror("mknod(S_IFREG|0644, 0)");
                                exit(1);
                        }
                        break;
                case 'u':
                        if (unlink(fname) == -1) {
                                perror("unlink");
                                exit(1);
                        }
                        break;
                case 'c':
                        if (close(fd) == -1) {
                                perror("close");
                                exit(1);
                        }
                        break;
                case '_':
                        pause();
                        break;
                case 's':
                        if (stat(fname, &st) == -1) {
                                perror("stat");
                                exit(1);
                        }
                        break;
                case 'S':
                        if (fstat(fd, &st) == -1) {
                                perror("fstat");
                                exit(1);
                        }
                        break;
                default:
                        fprintf(stderr, "unknown command \"%c\"\n", *commands);
                        fprintf(stderr, usage, argv[0]);
                        exit(1);
                }

                commands++;
        }
        
        return 0;
}
