#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>

/*
 * Usage: rw_seq_cst_vs_drop_caches /mnt/lustre/file0 /mnt/lustre2/file0

 * Race reads of the same file on two client mounts vs writes and drop
 * caches to detect sequential consistency violations. Run
 * indefinately.  all abort() if a consistency violation is found in
 * which case the wait status ($?) will be 134.
*/

#define handle_error(msg)	\
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

static int fd[2] = { -1, -1 };
/* u_max is total number of writes, which are time consumg because they are
 * contending with constant reads
 */
static uint64_t u, u_max = UINT64_MAX / 2;
static uint64_t v[2];

static void *access_thread_start(void *unused)
{
	ssize_t rc;
	int i;

	do {
		for (i = 0; i < 2; i++) {
			rc = pread(fd[i], &v[i], sizeof(v[i]), 0);
			if (rc < 0 || rc != sizeof(v[i]))
				handle_error("pread");
		}
	} while (v[0] <= v[1]);

	fprintf(stderr, "error: u = %"PRIu64", v = %"PRIu64", %"PRIu64"\n",
		u, v[0], v[1]);

	abort();
}

static char stderr_buf[4096];

int main(int argc, char *argv[])
{
	int drop_caches_fd = -1;
	pthread_t access_thread;
	struct stat st[2];
	ssize_t rc;
	int i;

	setvbuf(stderr, stderr_buf, _IOLBF, sizeof(stderr_buf));

	if (argc != 3) {
		fprintf(stderr, "Usage: %s /mnt/lustre/file0 /mnt/lustre2/file0\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	drop_caches_fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	assert(!(drop_caches_fd < 0));

	for (i = 0; i < 2; i++) {
		fd[i] = open(argv[i + 1], O_RDWR|O_CREAT|O_TRUNC, 0666);
		if (fd[i] < 0)
			handle_error("open");

		rc = fstat(fd[i], &st[i]);
		if (rc < 0)
			handle_error("fstat");
	}

	/* file0 and file1 should be the same file on two different
	 * client mount points. */
	if (st[0].st_dev != st[1].st_dev ||
	    st[0].st_ino != st[1].st_ino) {
		fprintf(stderr, "file mismatch\n");
		exit(EXIT_FAILURE);
	}

	rc = pwrite(fd[0], &u, sizeof(u), 0);
	if (rc < 0 || rc != sizeof(u))
		handle_error("pwrite");

	rc = pthread_create(&access_thread, NULL, &access_thread_start, NULL);
	if (rc != 0)
		handle_error("pthread_create");

	for (u = 1; u <= u_max; u++) {
		rc = pwrite(fd[0], &u, sizeof(u), 0);
		if (rc < 0 || rc != sizeof(u))
			handle_error("pwrite");

		rc = write(drop_caches_fd, "3\n", 2);
		if (rc < 0 || rc != 2)
			handle_error("drop caches");
	}

	rc = pthread_cancel(access_thread);
	if (rc != 0)
		handle_error("pthread_cancel");

	rc = pthread_join(access_thread, NULL);
	if (rc != 0)
		handle_error("pthread_join");

	return 0;
}
