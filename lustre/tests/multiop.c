#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
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
"        U  munmap\n"
"        m  mknod\n"
"        M  mmap to EOF (must open and stat prior)\n"
"        c  close\n"
"        _  wait for signal\n"
"        R  reference entire mmap-ed region\n"
"        s  stat\n"
"        S  fstat\n";

void null_handler(int unused) { }

int main(int argc, char **argv)
{
        char *fname, *commands;
        struct stat st;
	size_t mmap_len, i;
	unsigned char *mmap_ptr = NULL, junk = 0;
        int fd;

        if (argc != 3) {
                fprintf(stderr, usage, argv[0]);
                exit(1);
        }

        signal(SIGUSR1, null_handler);

        fname = argv[1];

        for (commands = argv[2]; *commands; commands++) {
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
		case 'M':
			mmap_len = st.st_size;
			mmap_ptr = mmap(NULL, mmap_len, PROT_READ, MAP_SHARED, 
					fd, 0);
			if (mmap_ptr == MAP_FAILED) {
				perror("mmap");
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
		case 'R':
			for (i = 0; i < mmap_len && mmap_ptr; i += 4096)
				junk += mmap_ptr[i];
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
		case 'U':
			if (munmap(mmap_ptr, mmap_len)) {
				perror("munmap");
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
