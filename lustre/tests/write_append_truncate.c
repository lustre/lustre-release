/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Each loop does 3 things:
 *   - truncate file to zero (not via ftruncate though, to test O_APPEND)
 *   - append a "chunk" of data (should be at file offset 0 after truncate)
 *   - on each of two threads either append or truncate-up the file
 *
 * If the truncate happened first, we should have a hole in the file.
 * If the append happened first, we should have truncated the file down.
 *
 * We pick the CHUNK_SIZE_MAX and APPEND_SIZE_MAX so that we cross a stripe.
 *
 * compile: mpicc -g -Wall -o write_append_truncate write_append_truncate.c
 * run:     mpirun -np 2 -machlist <hostlist file> write_append_truncate <file>
 *  or:     pdsh -w <two hosts> write_append_truncate <file>
 *  or:     prun -n 2 [-N 2] write_append_truncate <file>
 */
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "mpi.h"

#define DEFAULT_ITER     50000

#define CHUNK_SIZE_MAX   123456
#define CHUNK_CHAR   'C'

#define APPEND_SIZE_MAX  123456
#define APPEND_CHAR  'A'

#define TRUNC_SIZE_MAX   (CHUNK_SIZE_MAX+APPEND_SIZE_MAX)

#define HOSTNAME_SIZE 50

void usage(char *prog)
{
        printf("usage: %s <filename> [nloops]\n", prog);
        printf("%s must be run with at least 2 processes\n", prog);

        MPI_Finalize();
        exit(1);
}

/* Print process rank, loop count, message, and exit (i.e. a fatal error) */
void rprintf(int rank, int loop, const char *fmt, ...)
{
        va_list       ap;

        printf("rank %d, loop %d: ", rank, loop);

        va_start(ap, fmt);

        vprintf(fmt, ap);

        MPI_Abort(MPI_COMM_WORLD, 1);
}

int main(int argc, char *argv[])
{
        int n, nloops = 0, fd;
        int rank, size, ret;
        int chunk_size, append_size, trunc_offset;
        char append_buf[APPEND_SIZE_MAX];
        char chunk_buf[CHUNK_SIZE_MAX];
        char read_buf[TRUNC_SIZE_MAX+APPEND_SIZE_MAX];
        char trunc_buf[TRUNC_SIZE_MAX];
        int done;
        int error;
        char hostname[HOSTNAME_SIZE];
        char *fname, *prog;

        error = MPI_Init(&argc, &argv);
        if (error != MPI_SUCCESS)
                rprintf(-1, -1, "MPI_Init failed: %d\n", error);

        prog = strrchr(argv[0], '/');
        if (prog == NULL)
                prog = argv[0];
        else
                prog++;

        if (argc < 2 || argc > 3)
                usage(prog);

        error = MPI_Comm_rank(MPI_COMM_WORLD, &rank);
        if (error != MPI_SUCCESS)
                rprintf(-1, -1, "MPI_Comm_rank failed: %d\n", error);

        error = MPI_Comm_size(MPI_COMM_WORLD, &size);
        if (error != MPI_SUCCESS)
                rprintf(rank, -1, "MPI_Comm_size failed: %d\n", error);

        if (size < 2)
                rprintf(rank, -1, "%s: must run with at least 2 processes\n",
                        prog);

        memset(append_buf, APPEND_CHAR, APPEND_SIZE_MAX);
        memset(chunk_buf, CHUNK_CHAR, CHUNK_SIZE_MAX);
        memset(trunc_buf, 0, TRUNC_SIZE_MAX);

        if (gethostname(hostname, HOSTNAME_SIZE) < 0)
                rprintf(rank, -1, "gethostname failed: %s\n", strerror(errno));

        fname = argv[1];

        if (argc == 3)
                nloops = strtoul(argv[2], NULL, 0);
        if (nloops == 0)
                nloops = DEFAULT_ITER;

        if (rank == 0) {
                fd = open(fname, O_WRONLY|O_CREAT|O_TRUNC, 0666);
                if (fd < 0)
                        rprintf(0, -1, "create %s failed: %s\n", fname,
                                strerror(errno));
                printf("using %s\n", fname);
        }
        error = MPI_Barrier(MPI_COMM_WORLD);
        if (error != MPI_SUCCESS)
                rprintf(rank, -1, "prep MPI_Barrier failed: %d\n", error);

        fd = open(fname, O_RDWR | O_APPEND);
        if (fd < 0)
                rprintf(rank, -1, "open %s failed: %s\n",fname,strerror(errno));

        for (n = 0; n < nloops; n++) {
                /* reset the environment */
                chunk_size = (rand()%(CHUNK_SIZE_MAX-1))+1;
                append_size = (rand()%(APPEND_SIZE_MAX-1))+1;
                trunc_offset = chunk_size + rand()%append_size;
                if (rank == 0) {
                        if (n % 1000 == 0)
                                printf("loop %5d: chunk %6d/%#07x, "
                                       "append %6d/%#07x, trunc @ %6d/%#07x\n",
                                       n, chunk_size, chunk_size, append_size,
                                       append_size, trunc_offset, trunc_offset);

                        ret = truncate(fname, (off_t)0);
                        if (ret < 0)
                                rprintf(0, n, "truncate @ 0: %s\n",
                                        strerror(errno));
                        done = 0;
                        do {
                                ret = write(fd, chunk_buf+done,chunk_size-done);
                                if (ret <= 0) {
                                        rprintf(0, n, "chunk @ %d: %s\n",
                                                done, strerror(errno));
                                        break;
                                }
                                done += ret;
                        } while (done != chunk_size);
                }

                error = MPI_Barrier(MPI_COMM_WORLD);
                if (error != MPI_SUCCESS)
                        rprintf(rank, n, "start MPI_Barrier: %d\n",error);

                /* Do the race */
                if (rank == n % size) {
                        //
                        done = 0;
                        do {
                                ret = write(fd, append_buf + done,
                                            append_size - done);
                                if (ret < 0) {
                                        rprintf(rank, n,
                                                "loop %d: append @ %u: %s\n",
                                                done, strerror(errno));
                                        break;
                                }
                                done += ret;
                        } while (done != append_size);
                } else if (rank == (n + 1) % size) {
                        ret = truncate(fname, (off_t)trunc_offset);
                        if (ret != 0)
                                rprintf(rank, n, "truncate @ %u: %s\n",
                                        trunc_offset, strerror(errno) );
                }

                error = MPI_Barrier(MPI_COMM_WORLD);
                if (error != MPI_SUCCESS)
                        rprintf(rank, n, "end MPI_Barrier: %d\n", error);

                error = 0;

                /* Check the result */
                if (rank == 0) {
                        struct stat st;
                        if (stat(fname, &st) < 0)
                                rprintf(0, n, "loop %d: stat %s: %s\n",
                                        fname, strerror(errno));

                        if (lseek(fd, (off_t)0, SEEK_SET) != 0)
                                rprintf(0, n, "lseek fname 0: %s\n", fname,
                                        strerror(errno));

                        done = 0;
                        do {
                                ret = read(fd, read_buf+done, st.st_size-done);
                                if (ret < 0) {
                                        rprintf(0, n, "read @ %u: %s\n",
                                               done, strerror(errno));
                                }
                                done += ret;
                        } while (done != st.st_size);

                        if (memcmp(read_buf, chunk_buf, chunk_size)) {
                                printf("loop %d: base chunk bad"
                                       " [0-%d]/[0-%#x] != %c\n", n,
                                       chunk_size - 1, chunk_size - 1,
                                       CHUNK_CHAR);
                                error = 1;
                        }

                        if (st.st_size == trunc_offset) {
                                /* Check case 1: first append then truncate */
                                error = memcmp(read_buf+chunk_size, append_buf,
                                               trunc_offset - chunk_size);
                                if (error) {
                                        printf("loop %d: trunc-after-append bad"
                                               " [%d-%d]/[%#x-%#x] != %c\n",
                                               n, chunk_size, trunc_offset - 1,
                                               chunk_size, trunc_offset - 1,
                                               APPEND_CHAR);
                                }
                        } else {
                                /* Check case 2: first truncate then append */
                                if (memcmp(read_buf+chunk_size, trunc_buf,
                                           trunc_offset-chunk_size)) {
                                        printf("loop %d: append-after-TRUNC bad"
                                               " [%d-%d]/[%#x-%#x] != 0\n",
                                               n, chunk_size, trunc_offset - 1,
                                               chunk_size, trunc_offset - 1);
                                        error = 1;
                                } else if (memcmp(read_buf+trunc_offset,
                                                  append_buf, append_size)) {
                                        printf("loop %d: APPEND-after-trunc bad"
                                               " [%d-%d]/[%#x-%#x] != %c\n",
                                               n, trunc_offset, append_size - 1,
                                               trunc_offset, append_size - 1,
                                               APPEND_CHAR);
                                        error = 1;
                                }
                        }
                }
                ret = MPI_Bcast(&error, 1, MPI_INT, 0, MPI_COMM_WORLD);
                if (ret != MPI_SUCCESS)
                        rprintf(rank, n, "MPI_Bcast: %d\n");

                if (error == 1) {
                        if (rank == 0) {
                                char command[4096];

                                printf("loop %5d: chunk %6d/%#07x, "
                                       "append %6d/%#07x, trunc @ %6d/%#07x\n",
                                       n, chunk_size, chunk_size, append_size,
                                       append_size, trunc_offset, trunc_offset);

                                sprintf(command, "od -Ax -a %s", fname);
                                system(command);
                        }
                        rprintf(rank, n, "on machine %s with pid %d\n",
                                hostname, (int)getpid());
                }
        }

        printf("rank %d, loop %d: finished\n", rank, n);
        close(fd);

        if (rank == 0) {
                error = unlink(fname);
                if (error < 0)
                        rprintf(0, n, "unlink %s failed: %s\n",
                                fname, strerror(errno));
        }

        MPI_Finalize();
        return 0;
}
