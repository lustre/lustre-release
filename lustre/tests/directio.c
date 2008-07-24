/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef _GNU_SOURCE
#define  _GNU_SOURCE
#endif
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

int main(int argc, char **argv)
{
#ifdef O_DIRECT
        int fd;
        char *wbuf, *fname;
        int blocks, seek_blocks;
        long len;
        off64_t seek;
        struct stat64 st;
        char pad = 0xba;
        int action;
        int rc;

        if (argc < 5 || argc > 6) {
                printf("Usage: %s <read/write/rdwr/readhole> file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        if (!strcmp(argv[1], "read"))
                action = O_RDONLY;
        else if (!strcmp(argv[1], "write"))
                action = O_WRONLY;
        else if (!strcmp(argv[1], "rdwr"))
                action = O_RDWR;
        else if (!strcmp(argv[1], "readhole")) {
                action = O_RDONLY;
                pad = 0;
        } else {
                printf("Usage: %s <read/write/rdwr> file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        fname = argv[2];
        seek_blocks = strtoul(argv[3], 0, 0);
        blocks = strtoul(argv[4], 0, 0);
        if (!blocks) {
                printf("Usage: %s <read/write/rdwr> file seek nr_blocks [blocksize]\n", argv[0]);
                return 1;
        }

        fd = open(fname, O_LARGEFILE | O_DIRECT | O_RDWR | O_CREAT, 0644);
        if (fd == -1) {
                printf("Cannot open %s:  %s\n", fname, strerror(errno));
                return 1;
        }

        if (argc >= 6)
                st.st_blksize = strtoul(argv[5], 0, 0);
        else if (fstat64(fd, &st) < 0) {
                printf("Cannot stat %s:  %s\n", fname, strerror(errno));
                return 1;
        }

        printf("directio on %s for %dx%lu bytes \n", fname, blocks,
               st.st_blksize);

        seek = (off64_t)seek_blocks * (off64_t)st.st_blksize;
        len = blocks * st.st_blksize;

        wbuf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (wbuf == MAP_FAILED) {
                printf("No memory %s\n", strerror(errno));
                return 1;
        }
        memset(wbuf, pad, len);

        if (action == O_WRONLY || action == O_RDWR) {
                if (lseek64(fd, seek, SEEK_SET) < 0) {
                        printf("lseek64 failed: %s\n", strerror(errno));
                        return 1;
                }

                rc = write(fd, wbuf, len);
                if (rc != len) {
                        printf("Write error %s (rc = %d, len = %ld)\n",
                               strerror(errno), rc, len);
                        return 1;
                }
        }

        if (action == O_RDONLY || action == O_RDWR) {
                char *rbuf;

                if (lseek64(fd, seek, SEEK_SET) < 0) {
                        printf("Cannot seek %s\n", strerror(errno));
                        return 1;
                }

                rbuf =mmap(0,len,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,0,0);
                if (rbuf == MAP_FAILED) {
                        printf("No memory %s\n", strerror(errno));
                        return 1;
                }

                rc = read(fd, rbuf, len);
                if (rc != len) {
                        printf("Read error: %s rc = %d\n",strerror(errno),rc);
                        return 1;
                }

                if (memcmp(wbuf, rbuf, len)) {
                        printf("Data mismatch\n");
                        return 1;
                }
        }

        printf("PASS\n");
        return 0;
#else /* !O_DIRECT */
#warning O_DIRECT not defined, directio test will fail
        printf("O_DIRECT not defined\n");
        return 1;
#endif /* !O_DIRECT */
}
