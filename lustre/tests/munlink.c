/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char ** argv)
{
        int rc, i;

        if (argc < 2) {
                printf("Usage %s filename {filename ...}\n", argv[0]);
                return 1;
        }

        for (i = 1; i < argc; i++) {
                rc = unlink(argv[i]);
                if (rc) {
                        printf("unlink(%s): %s ", argv[i], strerror(errno));
                        rc = access(argv[i], F_OK);
                        if (rc && errno == ENOENT)
                                printf("(unlinked anyways)\n");
                        else if (rc == 0)
                                printf("(still exists)\n");
                        else
                                printf("(%s looking up)\n", strerror(errno));
                }
        }
        return rc;
}
