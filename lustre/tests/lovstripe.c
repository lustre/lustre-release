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
int write_file( char *name, struct lov_user_md *striping );


/************************  Main **********************/

int main( void )
{
	int result;
	struct lov_user_md a_striping;

	/*  Init defaults on striping info  */
	a_striping.lum_stripe_size = 128 * 1024;
	a_striping.lum_stripe_pattern = 0;

	/*  Write file for OST1 only  */
	/*       Start at OST 0, and use only 1 OST  */
	a_striping.lum_stripe_offset = 0;
	a_striping.lum_stripe_count = 1;

	result = write_file("/mnt/lustre/ost1", &a_striping);

	if (result < 0)
		exit(-1);

	/*  Write file for OST2 only  */
	/*       Start at OST 1, and use only 1 OST  */
	a_striping.lum_stripe_offset = 1;
	a_striping.lum_stripe_count = 1;

	result = write_file("/mnt/lustre/ost2", &a_striping);

	if (result < 0)
		exit(-1);

	/*  Write file across both OST1 and OST2  */
	/*       Start at OST 0, and use only 2 OSTs  */
	a_striping.lum_stripe_offset = 0;
	a_striping.lum_stripe_count = 2;

	result = write_file("/mnt/lustre/ost1and2", &a_striping);

	if (result < 0)
		exit(-1);

	return 0;
}


int write_file(char *name, struct lov_user_md *striping)
{
	char buf[262144], buf2[262144];
	int fd, result;

	printf("opening %s\n", name);
	fd = open(name, O_CREAT | O_RDWR | O_LOV_DELAY_CREATE, 0644);
	if (fd < 0) {
		fprintf(stderr, "\nUnable to open '%s': %s\n",
			 name, strerror(errno));
		return -1;
	}

	printf("setting stripe data on %s\n", name);
	result = ioctl(fd, LL_IOC_LOV_SETSTRIPE, striping);
	if (result < 0) {
		fprintf(stderr, "\nError on ioctl for '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -1;
	}

	/*  Write bogus data  */
	printf("writing data to %s\n", name);
	result = write(fd, buf, sizeof(buf));
	if (result < 0) {
		fprintf(stderr, "\nerror: writing data to '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -1;
	}

	if (result != sizeof(buf)) {
		fprintf(stderr, "\nerror: short write to '%s' (%d): %d != %d\n",
			name, fd, result, sizeof(buf));
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
		return -1;
	}

	/*  Read bogus data back  */
	printf("reading data from %s\n", name);
	result = read(fd, buf2, sizeof(buf));
	if (result < 0) {
		fprintf(stderr, "\nerror: reading data from '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -1;
	}

	if (result != sizeof(buf)) {
		fprintf(stderr,"\nerror: short read from '%s' (%d): %d != %d\n",
			name, fd, result, sizeof(buf));
		close(fd);
		return -1;
	}

	if (memcmp(buf, buf2, sizeof(buf))) {
		fprintf(stderr, "\nerror: comparing data in '%s' (%d): %s\n",
			name, fd, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
}
