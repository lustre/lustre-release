#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>


/****************** Custom includes ********************/
#include <linux/lustre_lite.h>


/******************  Functions ******************/
int write_file(char *name, struct lov_user_md *striping, int bufsize,
	       char *buf1, char *buf2);


/************************  Main **********************/

#define STRIPE_SIZE 128 * 1024

int main(int argc, char *argv[])
{
	struct lov_user_md a_striping;
	long bufsize = sizeof(long) * STRIPE_SIZE;
	char *rbuf, *wbuf;
	int data, *dp;
	int result;

	rbuf = malloc(bufsize);
	wbuf = malloc(bufsize);
	if (!rbuf || !wbuf) {
		fprintf(stderr, "%s: unable to allocate buffers\n", argv[0]);
		return 1;
	}

	/* Initialize to an easily-verified pattern */
	for (data = 0, dp = (int *)wbuf; data < STRIPE_SIZE; data++, dp++)
		*dp = data;

	/*  Init defaults on striping info  */
	a_striping.lum_stripe_size = STRIPE_SIZE;
	a_striping.lum_stripe_pattern = 0;

	/*  Write file for OST1 only  */
	/*       Start at OST 0, and use only 1 OST  */
	a_striping.lum_stripe_offset = 0;
	a_striping.lum_stripe_count = 1;

	result = write_file("/mnt/lustre/ost1", &a_striping, bufsize,
			    wbuf, rbuf);

	if (result < 0)
		goto out;

	/*  Write file for OST2 only  */
	/*       Start at OST 1, and use only 1 OST  */
	a_striping.lum_stripe_offset = 1;
	a_striping.lum_stripe_count = 1;

	result = write_file("/mnt/lustre/ost2", &a_striping, bufsize,
			    wbuf, rbuf);

	if (result < 0)
		goto out;

	/*  Write file across both OST1 and OST2  */
	/*       Start at OST 0, and use only 2 OSTs  */
	a_striping.lum_stripe_offset = 0;
	a_striping.lum_stripe_count = 2;

	result = write_file("/mnt/lustre/ost1and2", &a_striping, bufsize,
			    wbuf, rbuf);

	if (result < 0)
		goto out;

out:
	free(rbuf);
	free(wbuf);
	return result;
}


int write_file(char *name, struct lov_user_md *striping, int bufsize,
	       char *wbuf, char *rbuf)
{
	int fd, result;

	printf("opening %s\n", name);
	fd = open(name, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE, 0644);
	if (fd < 0) {
		fprintf(stderr, "\nUnable to open '%s': %s\n",
			 name, strerror(errno));
		return -errno;
	}

	printf("setting stripe data on %s\n", name);
	result = ioctl(fd, LL_IOC_LOV_SETSTRIPE, striping);
	if (result < 0) {
		fprintf(stderr, "\nError on ioctl for '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -errno;
	}

	/*  Write bogus data  */
	printf("writing data to %s\n", name);
	result = write(fd, wbuf, bufsize);
	if (result < 0) {
		fprintf(stderr, "\nerror: writing data to '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -errno;
	}

	if (result != bufsize) {
		fprintf(stderr, "\nerror: short write to '%s' (%d): %d != %d\n",
			name, fd, result, bufsize);
		close(fd);
		return -1;
	}

	/*  Seek to beginning again */
	printf("seeking in %s\n", name);
	result = lseek(fd, 0, SEEK_SET);
	if (result < 0) {
		fprintf(stderr, "\nerror: seeking to beginning '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -errno;
	}

	/*  Read bogus data back  */
	printf("reading data from %s\n", name);
	result = read(fd, rbuf, bufsize);
	if (result < 0) {
		fprintf(stderr, "\nerror: reading data from '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -errno;
	}

	if (result != bufsize) {
		fprintf(stderr,"\nerror: short read from '%s' (%d): %d != %d\n",
			name, fd, result, bufsize);
		close(fd);
		return -1;
	}

	if (memcmp(wbuf, rbuf, bufsize)) {
		fprintf(stderr, "\nerror: comparing data in '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}
