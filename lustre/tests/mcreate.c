#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
        int rc;

        if (argc < 2) {
                printf("Usage %s filename\n", argv[0]);
                return 1;
        }

        rc = mknod(argv[1], S_IFREG | 0644, 0);
        if (rc) {
                printf("mknod(%s) error: %s\n", argv[1], strerror(errno));
        }
        return rc;
}
