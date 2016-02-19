#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
/* For basename() */
#include <libgen.h>
#include <lnet/nidstr.h>
#include "lsupport.h"

int main(int argc, char **argv)
{
	lnet_nid_t nid;
	uid_t uid;
	int rc;

	if (argc < 3) {
		printf("Usage:\n"
		       "%s <princ> <nid>\n",
		       basename(argv[0]));
		return 1;
	}

	nid = libcfs_str2nid(argv[2]);
	if (nid == LNET_NID_ANY) {
		printf("parse nid %s failed\n", argv[2]);
		return 1;
	}
	rc = lookup_mapping(argv[1], nid, &uid);
	if (rc == -1) {
		printf("lookup mapping failed\n");
		return 1;
	}

	printf("principal: %s\n"
	       "nid:       %#llx\n"
	       "uid:       %u\n",
	       argv[1], nid, uid);

	return 0;
}
