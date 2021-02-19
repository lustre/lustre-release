#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>
#include <sys/file.h>

#include <lustre/lustreapi.h>

int main(int argc, char **argv)
{
	int c, fd;
	char *fname = "FILE";
	char *xval = "UUID@UUID";
	size_t len;
	struct lov_foreign_md *lfm;
	char *end;
	__u32 type = LU_FOREIGN_TYPE_SYMLINK, flags = 0xda05;

	while ((c = getopt(argc, argv, "f:x:t:F:")) != -1) {
		switch (c) {
		case 'f':
			fname = optarg;
			break;
		case 'x':
			xval = optarg;
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
		case 'F':
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
		case 'h':
			fprintf(stderr,
				"Usage: %s -f <filename> -x <LOV EA content>\n",
				argv[0]);
			break;
		}
	}

	len = strlen(xval);
	if (len > XATTR_SIZE_MAX || len <= 0) {
		fprintf(stderr,
			"invalid LOV EA length %zu > XATTR_SIZE_MAX (%u)\n",
			len, XATTR_SIZE_MAX);
		exit(1);
	}

	fd = open(fname, O_WRONLY|O_CREAT|O_LOV_DELAY_CREATE, 0644);
	if (fd == -1) {
		perror("open()");
		exit(1);
	}

	lfm = malloc(len + offsetof(struct lov_foreign_md, lfm_value));
	if (lfm == NULL) {
		perror("malloc()");
		exit(1);
	}

	lfm->lfm_magic = LOV_USER_MAGIC_FOREIGN;
	lfm->lfm_length = len;
	lfm->lfm_type = type;
	lfm->lfm_flags = flags;
	memcpy(lfm->lfm_value, xval, len);

	if (ioctl(fd, LL_IOC_LOV_SETSTRIPE, lfm) != 0) {
		perror("ioctl(LL_IOC_LOV_SETSTRIPE)");
		exit(1);
	}

	close(fd);
	return 0;
}
