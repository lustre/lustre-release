#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h> 
#include <stdlib.h>
#include <unistd.h>

#define T1 "write before unlink\n"
#define T2 "write after unlink\n"
char buf[128];

int main(int argc, char **argv)
{
        int fd, rc;

        if (argc != 2) {
                fprintf(stderr, "usage: %s filename\n", argv[1]); 
                exit(1);
        } else { 
                fprintf(stderr, "congratulations - program starting\n"); 
        }

        fprintf(stderr, "opening\n");
        fd = open(argv[1], O_RDWR | O_TRUNC | O_CREAT, 0644);
        if (fd == -1) { 
                fprintf(stderr, "open (before) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "writing\n");
        rc = write(fd, T1, strlen(T1) + 1); 
        if (rc != strlen(T1) + 1) { 
                fprintf(stderr, "write (before) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "closing\n");
        rc = close(fd); 
        if (rc )  { 
                fprintf(stderr, "close (before) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "opening again\n");
        fd = open(argv[1], O_RDWR );
        if (fd == -1) { 
                fprintf(stderr, "open (before) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "unlinking\n");
        rc = unlink(argv[1]); 
        if (rc )  { 
                fprintf(stderr, "open %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "reading\n");
        rc = read(fd, buf, strlen(T1) + 1); 
        if (rc != strlen(T1) + 1) { 
                fprintf(stderr, "read -after %s rc %d\n", strerror(errno), rc); 
                exit(1); 
        }

        fprintf(stderr, "comparing data\n");
        if (memcmp(buf, T1, strlen(T1) + 1) ) { 
                fprintf(stderr, "FAILURE: read wrong data after unlink\n");
                exit(1); 
        }       

        fprintf(stderr, "truncating\n");
        rc = ftruncate(fd, 0); 
        if (rc )  { 
                fprintf(stderr, "truncate -after unl %s\n", strerror(errno)); 
                exit(1); 
        }
        
        fprintf(stderr, "seeking\n");
        rc = lseek(fd, 0, SEEK_SET);
        if (rc != 0 )  { 
                fprintf(stderr, "seek (before write) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "writing again\n");
        rc = write(fd, T2, strlen(T2) + 1); 
        if (rc != strlen(T2) + 1) { 
                fprintf(stderr, "write (before) %s (rc %d)\n", strerror(errno), rc); 
                exit(1); 
        }

        fprintf(stderr, "seeking\n");
        rc = lseek(fd, 0, SEEK_SET);
        if (rc != 0 )  { 
                fprintf(stderr, "seek (before read) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "reading again\n");
        rc = read(fd, buf, strlen(T2) + 1); 
        if (rc != strlen(T2) + 1) { 
                fprintf(stderr, "read (after trunc) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "comparing data again\n");
        if (memcmp(buf, T2, strlen(T2) + 1) ) { 
                fprintf(stderr, "FAILURE: read wrong data after trunc\n");
                exit(1); 
        }       

        fprintf(stderr, "closing again\n");
        rc = close(fd); 
        if (rc )  { 
                fprintf(stderr, "close (before) %s\n", strerror(errno)); 
                exit(1); 
        }

        fprintf(stderr, "SUCCESS - goto beer\n"); 
        return 0; 
}
