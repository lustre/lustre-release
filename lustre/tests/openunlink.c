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

int main(int argc, char **argv)
{
        char *fname, *fname2;
        struct stat st;
        int fd, rc;

        if (argc < 2 || argc > 3) {
                fprintf(stderr, "usage: %s filename [filename2]\n", argv[0]);
                exit(1);
        }

        fname = argv[1];
        if (argc == 3)
                fname2 = argv[2];
        else
                fname2 = argv[1];

        fprintf(stderr, "opening\n");
        fd = open(fname, O_RDWR | O_TRUNC | O_CREAT, 0644);
        if (fd == -1) {
                fprintf(stderr, "open (normal) %s\n", strerror(errno));
                exit(1);
        }

        fprintf(stderr, "writing\n");
        rc = write(fd, T1, strlen(T1) + 1);
        if (rc != strlen(T1) + 1) {
                fprintf(stderr, "write (normal) %s (rc %d)\n",
                        strerror(errno), rc);
                exit(1);
        }

        if (argc == 3) {
                fprintf(stderr, "closing %s\n", fname);
                rc = close(fd);
                if (rc) {
                        fprintf(stderr, "close (normal) %s\n", strerror(errno));
                        exit(1);
                }

                fprintf(stderr, "opening %s\n", fname2);
                fd = open(fname2, O_RDWR);
                if (fd == -1) {
                        fprintf(stderr, "open (unlink) %s\n", strerror(errno));
                        exit(1);
                }

                fprintf (stderr, "unlinking %s\n", fname2);
                rc = unlink(fname2);
                if (rc) {
                        fprintf(stderr, "unlink %s\n", strerror(errno));
                        exit(1);
                }

                if (access(fname2, F_OK) == 0) {
                        fprintf(stderr, "%s still exists\n", fname2);
                        exit(1);
                }
        } else {
                fprintf(stderr, "resetting fd offset\n");
                rc = lseek(fd, 0, SEEK_SET);
                if (rc) {
                        fprintf(stderr, "seek %s\n", strerror(errno));
                        exit(1);
                }

                printf("unlink %s and press enter\n", fname);
                getc(stdin);
        }

        if (access(fname, F_OK) == 0) {
                fprintf(stderr, "%s still exists\n", fname);
                exit(1);
        }

        fprintf(stderr, "fstating\n");
        rc = fstat(fd, &st);
        if (rc) {
                fprintf(stderr, "fstat (unlink) %s\n", strerror(errno));
                exit(1);
        }
        if (st.st_nlink != 0)
                fprintf(stderr, "st_nlink = %d\n", st.st_nlink);

        fprintf(stderr, "reading\n");
        rc = read(fd, buf, strlen(T1) + 1);
        if (rc != strlen(T1) + 1) {
                fprintf(stderr, "read (unlink) %s (rc %d)\n",
                        strerror(errno), rc);
                exit(1);
        }

        fprintf(stderr, "comparing data\n");
        if (memcmp(buf, T1, strlen(T1) + 1) ) {
                fprintf(stderr, "FAILURE: read wrong data after unlink\n");
                exit(1);
        }

        fprintf(stderr, "truncating\n");
        rc = ftruncate(fd, 0);
        if (rc) {
                fprintf(stderr, "truncate (unlink) %s\n", strerror(errno));
                exit(1);
        }

        fprintf(stderr, "seeking\n");
        rc = lseek(fd, 0, SEEK_SET);
        if (rc) {
                fprintf(stderr, "seek (after unlink trunc) %s\n",
                        strerror(errno));
                exit(1);
        }

        fprintf(stderr, "writing again\n");
        rc = write(fd, T2, strlen(T2) + 1);
        if (rc != strlen(T2) + 1) {
                fprintf(stderr, "write (after unlink trunc) %s (rc %d)\n",
                        strerror(errno), rc);
                exit(1);
        }

        fprintf(stderr, "seeking\n");
        rc = lseek(fd, 0, SEEK_SET);
        if (rc) {
                fprintf(stderr, "seek (before unlink read) %s\n",
                        strerror(errno));
                exit(1);
        }

        fprintf(stderr, "reading again\n");
        rc = read(fd, buf, strlen(T2) + 1);
        if (rc != strlen(T2) + 1) {
                fprintf(stderr, "read (after unlink rewrite) %s (rc %d)\n",
                        strerror(errno), rc);
                exit(1);
        }

        fprintf(stderr, "comparing data again\n");
        if (memcmp(buf, T2, strlen(T2) + 1)) {
                fprintf(stderr, "FAILURE: read wrong data after rewrite\n");
                exit(1);
        }

        fprintf(stderr, "closing\n");
        rc = close(fd);
        if (rc) {
                fprintf(stderr, "close (unlink) %s\n", strerror(errno));
                exit(1);
        }

        fprintf(stderr, "SUCCESS - goto beer\n");
        return 0;
}
