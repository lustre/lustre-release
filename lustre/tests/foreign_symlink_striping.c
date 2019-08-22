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
#include <linux/lustre/lustre_idl.h>

int main(int argc, char **argv)
{
	char *foreign = NULL;
	int c, rc, fd;
	bool f_opt = false, d_opt = false, h_opt = false;
	/* buf must be large enough to receive biggest possible
	 * foreign LOV/LMV
	 */
	char buf[XATTR_SIZE_MAX];
	struct lmv_foreign_md *lfm = (void *)buf;

	while ((c = getopt(argc, argv, "hf:d:")) != -1) {
		switch (c) {
		case 'd':
			foreign = optarg;
			if (f_opt || d_opt) {
				fprintf(stderr,
					"only one foreign symlink file or dir can be specified at a time\n");
				exit(1);
			}
			d_opt = true;
			break;
		case 'f':
			foreign = optarg;
			if (f_opt || d_opt) {
				fprintf(stderr,
					"only one foreign symlink file or dir can be specified at a time\n");
				exit(1);
			}
			f_opt = true;
			break;
		case 'h':
			h_opt = true;
		default:
			fprintf(stderr,
				"Usage: %s [-[f,d] <foreign file/dir pathname>]\n",
				argv[0]);
			exit(h_opt ? 0 : 1);
			break;
		}
	}

	if (foreign == NULL) {
		fprintf(stderr,
			"a foreign file/dir pathname must be provided\n");
		exit(0);
	}

	/* in case foreign fake symlink feature is active, file/dir must be
	 * opened with O_NOFOLLOW to avoid symlink resolution
	 */
	fd = open(foreign, O_RDONLY|O_NONBLOCK|O_NOFOLLOW);
	if (fd < 0) {
		fprintf(stderr, "open() of '%s' error, rc : %d\n", foreign, fd);
		perror("open()");
		exit(1);
	}

	rc = snprintf(buf, PATH_MAX, "%s", foreign);
	if (rc >= PATH_MAX || rc < 0) {
		fprintf(stderr,
			"unexpected return code or size from snprintf() : %d\n",
			rc);
		exit(1);
	}

	if (f_opt) {
		rc = ioctl(fd, LL_IOC_LOV_GETSTRIPE, &buf);
	} else if (d_opt) {
		lfm->lfm_magic = LMV_MAGIC_V1;
		rc = ioctl(fd, LL_IOC_LMV_GETSTRIPE, &buf);
	}

	if (rc) {
		fprintf(stderr, "%s: %s error: %s\n", foreign,
			f_opt ? "getstripe" : "getdirstripe", strerror(errno));
		exit(1);
	}

	if (lfm->lfm_magic != LOV_USER_MAGIC_FOREIGN &&
	    lfm->lfm_magic != LMV_MAGIC_FOREIGN)
		fprintf(stderr, "unexpected magic : 0x%08X, expected 0x%08X\n",
			lfm->lfm_magic, LOV_USER_MAGIC_FOREIGN);
	if (lfm->lfm_type != LU_FOREIGN_TYPE_SYMLINK)
		fprintf(stderr, "unexpected type : 0x%08X, expected 0x%08X\n",
			lfm->lfm_type, LU_FOREIGN_TYPE_SYMLINK);
	printf("lfm_magic: 0x%08X, lfm_length: %u, lfm_type: 0x%08X, lfm_flags: 0x%08X, lfm_value: '%.*s'\n",
	       lfm->lfm_magic, lfm->lfm_length, lfm->lfm_type, lfm->lfm_flags,
	       lfm->lfm_length, lfm->lfm_value);

	return rc;
}
