#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>

int main(int argc, char *argv[])
{
        char filename[1024];
        unsigned long count, i;
	int thread = 0;
	int threads = 0;
	int rc;

        if (argc < 3 || argc > 4) {
                fprintf(stderr, "usage: %s <filename> <iterations> [threads]\n",
			argv[0]);
                exit(1);
        }

        count = strtoul(argv[2], NULL, 0);
	if (argc == 4)
		threads = strtoul(argv[3], NULL, 0);

        for (i = 1; i <= threads; i++) {
                rc = fork();
                if (rc < 0) {
                        fprintf(stderr, "error: %s: #%ld - %s\n", argv[0], i,
                                strerror(rc = errno));
                        break;
                } else if (rc == 0) {
                        thread = i;
                        argv[2] = "--device";
                        break;
                } else
                        printf("%s: thread #%ld (PID %d) started\n",
                               argv[0], i, rc);
                rc = 0;
        }

        if (threads && thread == 0) {	/* parent process */
                int live_threads = threads;

                while (live_threads > 0) {
                        int status;
                        pid_t ret;

                        ret = waitpid(0, &status, 0);
                        if (ret == 0) {
                                continue;
                        }

                        if (ret < 0) {
                                fprintf(stderr, "error: %s: wait - %s\n",
                                        argv[0], strerror(errno));
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
                                                "%s: PID %d had rc=%d\n",
                                                argv[0], ret, err);
                                if (!rc)
                                        rc = err;

                                live_threads--;
                        }
                }
	} else {
		for (i = 0; i < count; i++) {
			if (threads)
				sprintf(filename, "%s-%d-%ld",
					argv[1], thread, i);
			else
				sprintf(filename, "%s-%ld", argv[1], i);

			rc = mknod(filename, S_IFREG, 0);
			if (rc < 0) {
				fprintf(stderr, "mknod(%s): %s\n",
					filename, strerror(errno));
				rc = errno;
				break;
			}
			if (unlink(filename) < 0) {
				fprintf(stderr, "unlink(%s): %s\n",
					filename, strerror(errno));
				rc = errno;
				break;
			}
		}
		if (threads)
			printf("Thread %d done: rc = %d\n", thread, rc);
		else
			printf("Done: rc = %d\n", rc);
	}
        return rc;
}
