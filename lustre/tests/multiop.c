#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
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
"        r  read\n"
"        S  fstat\n"
"        t  fchmod\n"
"        w  write\n"
"        z  seek to zero\n";

void null_handler(int unused) { }

int main(int argc, char **argv)
{
        char *fname, *commands;
        struct stat st;
        int fd = -1;

        if (argc != 3) {
                fprintf(stderr, usage, argv[0]);
                exit(1);
        }

        signal(SIGUSR1, null_handler);

        fname = argv[1];

        for (commands = argv[2]; *commands; commands++) {
                switch (*commands) {
                case '_':
                        pause();
                        break;
                case 'c':
                        if (close(fd) == -1) {
                                perror("close");
                                exit(1);
                        }
			fd = -1;
                        break;
                case 'm':
                        if (mknod(fname, S_IFREG | 0644, 0) == -1) {
                                perror("mknod(S_IFREG|0644, 0)");
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
                case 'o':
                        fd = open(fname, O_RDONLY);
                        if (fd == -1) {
                                perror("open(O_RDONLY)");
                                exit(1);
                        }
                        break;
		case 'r': {
			char buf;
			if (read(fd, &buf, 1) == -1) {
				perror("read");
				exit(1);
			}
		}
                case 'S':
                        if (fstat(fd, &st) == -1) {
                                perror("fstat");
                                exit(1);
                        }
                        break;
                case 's':
                        if (stat(fname, &st) == -1) {
                                perror("stat");
                                exit(1);
                        }
                        break;
                case 't': 
                        if (fchmod(fd, 0) == -1) {
                                perror("fchmod");
                                exit(1);
                        }
                        break;
                case 'u':
                        if (unlink(fname) == -1) {
                                perror("unlink");
                                exit(1);
                        }
                        break;
		case 'w':
			if (write(fd, "w", 1) == -1) {
				perror("write");
				exit(1);
			}
			break;
		case 'z':
			if (lseek(fd, 0, SEEK_SET) == -1) {
				perror("lseek");
				exit(1);
			}
			break;
                default:
                        fprintf(stderr, "unknown command \"%c\"\n", *commands);
                        fprintf(stderr, usage, argv[0]);
                        exit(1);
                }
        }
        
        return 0;
}
