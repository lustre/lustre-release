#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>


/****************** Custom includes ********************/
#include <linux/lustre_lite.h>
#include <linux/lustre_idl.h>


/******************  Functions ******************/

void usage(char *pgm)
{
	fprintf(stderr, "usage: %s <filename> <stripe size> <start stripe> <stripe count>\n", pgm);

	fprintf(stderr, "\tstripe size: number of bytes in each stripe\n");
	fprintf(stderr, "\tstripe start: OST index which holds first stripe\n");
	fprintf(stderr, "\tstripe count: number of OSTs to stripe over\n");
}

int create_file(char *name, long stripe_size, int stripe_offset,
		int stripe_count)
{
	struct lov_mds_md a_striping;
	int fd, result = 0;

	/*  Initialize IOCTL striping pattern structure  */
	a_striping.lmm_magic = LOV_MAGIC;
	a_striping.lmm_stripe_size = stripe_size;
	a_striping.lmm_stripe_offset = stripe_offset;
	a_striping.lmm_stripe_count = stripe_count;

	fd = open(name, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE, 0644);
	if (fd < 0) {
		fprintf(stderr, "\nUnable to open '%s': %s\n",
			name, strerror(errno));
		result = -errno;
	} else if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, &a_striping)) {
		fprintf(stderr, "\nError on ioctl for '%s' (%d): %s\n",
			name, fd, strerror(errno));
		result = -errno;
	} else if (close(fd) < 0) {
		fprintf(stderr, "\nError on close for '%s' (%d): %s\n",
			name, fd, strerror(errno));
		result = -errno;
	}

	return result;
}

int main(int argc, char *argv[])
{
	int result;
	long st_size;
	int  st_offset,
	     st_count;

	/*  Check to make sure we have enough parameters  */
	if (argc != 5) {
		usage(argv[0]);
		return(-1);
	}

	/* Get the stripe size */
	st_size = atol(argv[2]);

	/* Get the stripe offset*/
	st_offset = atoi(argv[3]);

	/* Get the stripe count */
	st_count = atoi(argv[4]);

	/*  Create the file, as specified.  Return and display any errors.  */
	result = create_file(argv[1], st_size, st_offset, st_count);

	return result;
}
