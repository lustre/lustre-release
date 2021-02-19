#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/file.h>

#include <lustre/lustreapi.h>

int main(int argc, char **argv)
{
	char *dir = "foreign_dir", *end;
	char *xval = "UUID@UUID";
	mode_t mode = 0700;
	__u32 type = LU_FOREIGN_TYPE_SYMLINK, flags = 0xda05;
	int c, rc;

	while ((c = getopt(argc, argv, "hd:f:m:t:x:")) != -1) {
		switch (c) {
		case 'd':
			dir = optarg;
			break;
		case 'x':
			xval = optarg;
			break;
		case 'm':
			mode = strtoul(optarg, &end, 8);
			if (*end != '\0') {
				fprintf(stderr,
					"%s: invalid mode '%s'\n", argv[0],
					optarg);
				exit(1);
			}
			break;
		case 'f':
			errno = 0;
			flags = strtoul(optarg, &end, 0);
			if (errno != 0 || *end != '\0' ||
			    flags >= UINT32_MAX) {
				fprintf(stderr,
					"%s: invalid flags '%s'\n", argv[0],
					optarg);
				exit(1);
			}
			break;
		case 't':
			type = strtoul(optarg, &end, 0);
			if (*end != '\0') {
				fprintf(stderr,
					"%s: invalid type '%s'\n", argv[0],
					optarg);
				exit(1);
			}
			break;
		case 'h':
		default:
			fprintf(stderr,
				"Usage: %s [-d <dirname>] [-m <octalmode>] [-x <LOV EA content>] [-t <type>] [-f <hexflags>]\n",
				argv[0]);
			exit(0);
			break;
		}
	}

	rc = llapi_dir_create_foreign(dir, mode, type, flags, xval);
	if (rc < 0)
		fprintf(stderr, "llapi_dir_create_foreign() error : %d\n", rc);

	return rc;
}
