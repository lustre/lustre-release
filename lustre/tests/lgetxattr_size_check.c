#include <sys/types.h>
#include <sys/xattr.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void usage(char *prog)
{
	printf("Usage: %s <pathname> <xattr name>\n", prog);
}

/* Simple program to test the lgetxattr return value. */
int main(int argc, char *argv[])
{
	char *path, *xattr, *buf;
	ssize_t ret_null;
	int ret = 0;

	if (argc != 3) {
		usage(argv[0]);
		exit(1);
	}

	path = argv[1];
	xattr = argv[2];

	ret_null = lgetxattr(path, xattr, NULL, 0);
	if (ret_null < 0) {
		fprintf(stderr, "lgetxattr(%s, %s, NULL, 0) failed "
				"with %i: %s\n", path, xattr, errno,
				 strerror(errno));
		ret = 1;
		goto out;
	}

	buf = (char *)malloc(ret_null);
	if (buf == NULL) {
		fprintf(stderr, "malloc(%zi) failed with %i: %s\n",
				 ret_null, errno, strerror(errno));
		ret = 1;
		goto out;
	}

	ssize_t ret_buf = lgetxattr(path, xattr, buf, ret_null);
	if (ret_buf < 0) {
		fprintf(stderr, "lgetxattr(%s, %s, %p, %zi) failed "
				"with %i: %s\n", path, xattr, buf,
				 ret_null, errno, strerror(errno));
		ret = 1;
		goto free;
	}

	if (ret_null != ret_buf) {
		fprintf(stderr, "lgetxattr returned inconsistent sizes!\n");
		fprintf(stderr, "lgetxattr(%s, %s, NULL, 0) = %zi\n",
			path, xattr, ret_null);
		fprintf(stderr, "lgetxattr(%s, %s, %p, %zi) = %zi\n",
			path, xattr, buf, ret_null, ret_buf);
		ret = 1;
		goto free;
	}

free:
	free(buf);
out:
	return ret;
}
