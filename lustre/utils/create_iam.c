#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

void usage(char *prog)
{
        printf("usage: %s [-s] filename\n", prog);
}

struct iam_root {
        struct iam_root_info {
                unsigned char indirect_levels;
                unsigned char pad[3]; 
        } info;
        struct {} entries[0];
};

struct iam_entry {
	unsigned long long ie_key;
	unsigned long 	   ie_index;
};

struct leaf_header {
	unsigned short   lh_magic;
	unsigned short   lh_count;
};

struct leaf_entry {
	unsigned long long le_key;
	unsigned long long le_rec;
};

#define LEAF_HEAD_MAGIC 0x1976
int main(int argc, char **argv)
{
	struct iam_root root;
	struct iam_entry ie;
	struct leaf_header header;
	struct leaf_entry le;
	char buf[4096];
	int fd, rc, file_arg = 1;

        memset(buf, 0, 4096);

        if (argc < 2 || argc > 3) {
                usage(argv[0]);
                exit(1);
        }

     	fd = open(argv[file_arg], O_RDWR | O_TRUNC | O_CREAT, 0644);
        if (fd == -1) {
                printf("Error opening %s %s\n", argv[1], strerror(errno));
                exit(1);
        }
	
	/*create the root entry*/
	memset(buf, 0, 4096);
	root.info.indirect_levels = 0;
	memcpy(buf, &root, sizeof(struct iam_root));

	/*insert the dx_limit compatiable structure to make 
	 *iam compatiable with dx code*/ 	
	header.lh_count = 2;
	
	memcpy (buf + sizeof(struct iam_root), &header,
		sizeof(struct iam_entry));
	
	ie.ie_key = 0x0;
	ie.ie_index = 1;

	memcpy (buf + sizeof(struct iam_root) + sizeof(struct iam_entry), &ie,
		sizeof(struct iam_entry));
	rc = write(fd, buf, sizeof(buf));
	if (rc < 0) {
		printf("Error Writing %s %s \n", argv[1], strerror(errno));
		close(fd);
		exit(rc);
	}
	
	/*create the first index entry*/	
	memset(buf, 0, 4096);
	header.lh_magic = LEAF_HEAD_MAGIC;
	header.lh_count = 1; 
	memcpy(buf, &header, sizeof(struct leaf_header));

	/*insert the lowest key of the leaf*/
	le.le_key = 0; /*tmp assume 0 is the lowest key of the leaf*/ 
	le.le_rec = 0;

	memcpy(buf + sizeof(struct leaf_header), &le, 
	       sizeof(struct leaf_entry)); 
	rc = write(fd, buf, sizeof(buf));
	if (rc < 0) {
		printf("Error Writing %s %s \n", argv[1], strerror(errno));
		close(fd);
		exit(rc);
	}
	close(fd);
	exit(0);
}
