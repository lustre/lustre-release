/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <sys/time.h>


#define difftime(a, b)                                          \
        ((double)(a)->tv_sec - (b)->tv_sec +                    \
         ((double)((a)->tv_usec - (b)->tv_usec) / 1000000))

char cmdname[512];

int wait_for_threads(int live_threads)
{
        int rc = 0;
        
        while (live_threads > 0) {
                int status;
                pid_t ret;
                
                ret = waitpid(0, &status, 0);
                if (ret == 0) {
                        continue;
                }
                
                if (ret < 0) {
                        fprintf(stderr, "%s: error: wait - %s\n",
                                cmdname, strerror(errno));
                        if (!rc)
                                rc = errno;
                } else {
                        /*
                         * This is a hack.  We _should_ be able to use
                         * WIFEXITED(status) to see if there was an
                         * error, but it appears to be broken and it
                         * always returns 1 (OK).  See wait(2).
                         */
                        int err = WEXITSTATUS(status);
                        if (err || WIFSIGNALED(status))
                                fprintf(stderr,
                                        "%s: error: PID %d had rc=%d\n",
                                        cmdname, ret, err);
                        if (!rc)
                                rc = err;
                        
                        live_threads--;
                }
        }
        printf("%s done, rc = %d\n", cmdname, rc);
        return rc;
}


int run_one_child(char *file, int thread, int seconds)
{
        struct timeval start, cur;
        double diff;
        char filename[1024];
        char buf[1024];
        int fd, rc = 0, rand, maxrand, len;
        long nfiles = 0, nbytes = 0;

        printf("%s: running thread #%d\n", cmdname, thread);
        
        srandom(thread);
        /* Higher thread numbers will produce bigger random files.  
           Thread 1 will produce only 0-len files. */
        maxrand = 1; rand = thread;
        while (--rand)
                maxrand *= 10;

        gettimeofday(&start, NULL);

        while(!rc) {
                gettimeofday(&cur, NULL);
                if (cur.tv_sec > (start.tv_sec + seconds))
                        break;

                sprintf(filename, "%s-%d-%ld", file, thread, nfiles);
                
                fd = open(filename, O_RDWR | O_CREAT, 0666);
                if (fd < 0) {
                        fprintf(stderr, "%s: error: open(%s): %s\n",
                                cmdname, filename, strerror(errno));
                        rc = errno;
                        break;
                }
                
                sprintf(buf, "%s %010ld %.19s.%012d\n", cmdname, 
                        nfiles++, ctime(&cur.tv_sec), (int)cur.tv_usec);
                len = strlen(buf);

                rand = random() % maxrand;
                while (rand-- > 0) {
                        if (write(fd, buf, len) != len) {
                                fprintf(stderr, "%s: error: write(%s): %s\n",
                                        cmdname, filename, strerror(errno));
                                rc = errno;
                                break;
                        }                     
                        nbytes += len;
                }  
                
                if (close(fd) < 0) {
                        fprintf(stderr, "%s: error: close(%s): %s\n",
                                cmdname, filename, strerror(errno));
                        rc = errno;
                        break;
                }
                if (unlink(filename) < 0) {
                        fprintf(stderr, "%s: error: unlink(%s): %s\n",
                                cmdname, filename, strerror(errno));
                        rc = errno;
                        break;
                }
        }
        
        diff = difftime(&cur, &start);
        printf("%s: %7ld files, %4ld MB in %.2fs (%7.2f files/s, %5.2f MB/s): rc = %d\n",
               cmdname, nfiles, nbytes >> 20, diff,
               (double)nfiles / diff, (double)nbytes/1024/1024 / diff, rc);

        return rc;
}



int main(int argc, char *argv[])
{
        unsigned long duration;
        int threads = 0;
        char *end;
        int i, rc = 0;

        if (argc != 4) {
                fprintf(stderr,
                        "usage: %s <filename> <seconds> <threads>\n",
                        argv[0]);
                exit(1);
        }

        sprintf(cmdname, "%s", argv[0]);        

        duration = strtoul(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "%s: error: bad number of seconds '%s'\n",
                        cmdname, argv[1]);
                exit(2);
        }

        threads = strtoul(argv[3], &end, 0);
        if (*end) {
                fprintf(stderr, "%s: error: bad thread count '%s'\n",
                        cmdname, argv[3]);
                exit(2);
        }

        for (i = 1; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "%s: error: #%d - %s\n",
                                cmdname, i, strerror(rc = errno));
                        return (rc);
                }
                if (rc == 0) {
                        /* children */
                        sprintf(cmdname, "%s-%d", argv[0], i);
                        return (run_one_child(argv[1], i, duration));
                }
        }
        /* parent process */
        printf("%s will run for %ld minutes\n", cmdname, duration/60);
        return (wait_for_threads(threads));
}
