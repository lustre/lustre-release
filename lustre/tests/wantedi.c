#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <linux/lustre_lib.h>
#include <linux/obd.h>

static int usage(char *prog, FILE *out)
{
        fprintf(out,
		"Usage: %s <dir> <desired child ino>\n", prog);
        exit(out == stderr);
}

#define EXTN_IOC_CREATE_INUM            _IOW('f', 5, long)

int main(int argc, char ** argv)
{
        int dirfd, wantedi, rc;

	if (argc < 2 || argc > 3)
		usage(argv[0], stderr);
	
	dirfd = open(argv[1], O_RDONLY);
	if (dirfd < 0) {
	       perror("open");
	       exit(1);
	}
        
	wantedi = atoi(argv[2]);
	printf("Creating %s/%d with ino %d\n", argv[1], wantedi, wantedi);

	rc = ioctl(dirfd, EXTN_IOC_CREATE_INUM, wantedi);
	if (rc < 0) {
	       perror("ioctl(EXTN_IOC_CREATE_INUM)");
	       exit(2);
	}
}
