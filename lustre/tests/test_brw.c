/*
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
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

/* for O_DIRECT */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <libcfs/libcfs.h>

#define READ  1
#define WRITE 2

#define LPDS sizeof(__u64)
int block_debug_setup(void *addr, int len, __u64 off, __u64 id)
{
        off = cpu_to_le64(off);
        id = cpu_to_le64(id);
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        addr += len - LPDS - LPDS;
        memcpy(addr, (char *)&off, LPDS);
        memcpy(addr + LPDS, (char *)&id, LPDS);

        return 0;
}

int block_debug_check(char *who, void *addr, int size, __u64 off, __u64 id)
{
        __u64 ne_off;
        int err = 0;

        ne_off = le64_to_cpu(off);
        id = le64_to_cpu(id);
        if (memcmp(addr, (char *)&ne_off, LPDS)) {
                CERROR("%s: for offset "LPU64" off: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)addr, ne_off);
                err = -EINVAL;
        }
        if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
                CERROR("%s: for offset "LPU64" id: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)(addr + LPDS), id);
                err = -EINVAL;
        }

        addr += size - LPDS - LPDS;
        if (memcmp(addr, (char *)&ne_off, LPDS)) {
                CERROR("%s: for offset "LPU64" end off: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)addr, ne_off);
                err = -EINVAL;
        }
        if (memcmp(addr + LPDS, (char *)&id, LPDS)) {
                CERROR("%s: for offset "LPU64" end id: "LPX64" != "LPX64"\n",
                       who, off, *(__u64 *)(addr + LPDS), id);
                err = -EINVAL;
        }

        return err;
}
#undef LPDS

void usage(char *prog)
{
        fprintf(stderr,
                "usage: %s file count [[d]{r|w|rw} [pages_per_vec [objid]]]\n",
                prog);
        exit(1);
}

int main(int argc, char **argv)
{
        int fd;
        char *buf;
        long long count, last, offset;
        long pg_vec, len;
        __u64 objid;
        struct stat st;
        int flags = 0;
        int cmd = 0;
        char *end;
        int rc;

        if (argc < 3 || argc > 6)
                usage(argv[0]);

        count = strtoull(argv[2], &end, 0);
        if (*end) {
                fprintf(stderr, "%s: invalid count '%s'\n", argv[0], argv[2]);
                usage(argv[0]);
        }
        if (argc >= 4) {
                if (strchr(argv[3], 'r')) {
                        cmd = READ;
                        flags = O_RDONLY;
                }
                if (strchr(argv[3], 'w')) {
                        cmd |= WRITE;
                        flags = O_RDWR | O_CREAT;
                }
                if (strchr(argv[3], 'd')) {
#ifdef O_DIRECT
                        flags |= O_DIRECT;
#else
                        fprintf(stderr,
                                "%s: O_DIRECT not supported in this build\n",
                                argv[0]);
                        exit(1);
#endif
                }
                if (!cmd)
                        usage(argv[0]);
        } else {
                cmd = READ | WRITE;
                flags = O_RDWR | O_CREAT;
#ifdef O_DIRECT
                flags |= O_DIRECT;
#else
                fprintf(stderr, "%s: warning: not setting O_DIRECT\n",
                        argv[0]);
#endif
        }

        if (argc >= 5) {
                pg_vec = strtoul(argv[4], &end, 0);
                if (*end) {
                        fprintf(stderr, "%s: invalid pages_per_vec '%s'\n",
                                argv[0], argv[4]);
                        usage(argv[0]);
                }
        } else {
                pg_vec = 16;
        }

        if (argc >= 6) {
                objid = strtoull(argv[5], &end, 0);
                if (*end) {
                        fprintf(stderr, "%s: invalid objid '%s'\n",
                                argv[0], argv[5]);
                        usage(argv[0]);
                }
        } else {
                objid = 3;
        }

        printf("%s: %s on %s(objid "LPX64") for %llux%ld pages \n",
               argv[0],
#ifdef O_DIRECT
               flags & O_DIRECT ? "directio" : "i/o",
#else
               "i/o",
#endif
               argv[1], objid, count, pg_vec);

        fd = open(argv[1], flags | O_LARGEFILE);
        if (fd == -1) {
                fprintf(stderr, "%s: cannot open %s:  %s\n", argv[0],
                        argv[1], strerror(errno));
                return 3;
        }

        rc = fstat(fd, &st);
        if (rc < 0) {
                fprintf(stderr, "%s: cannot stat %s: %s\n", argv[0],
                        argv[1], strerror(errno));
                return 4;
        }

        len = pg_vec * st.st_blksize;
        last = (long long)count * len;

        buf = mmap(0, len, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0);
        if (buf == MAP_FAILED) {
                fprintf(stderr, "%s: no buffer memory %s\n",
                        argv[0], strerror(errno));
                return 2;
        }

        for (offset = 0; offset < last && cmd & WRITE; offset += len) {
                int i;

                for (i = 0; i < len; i += st.st_blksize)
                        block_debug_setup(buf + i, st.st_blksize, 
                                          offset + i, objid);

                rc = write(fd, buf, len);

                for (i = 0; i < len; i += st.st_blksize) {
                        if (block_debug_check("write", buf + i, st.st_blksize,
                                              offset + i, objid))
                                return 10;
                }

                if (rc != len) {
                        fprintf(stderr, "%s: write error: %s, rc %d != %ld\n",
                                argv[0], strerror(errno), rc, len);
                        return 4;
                }
        }

        if (lseek(fd, 0, SEEK_SET) != 0) {
                fprintf(stderr, "%s: cannot seek %s\n",
                        argv[0], strerror(errno));
                return 5;
        }

        for (offset = 0; offset < last && cmd & READ; offset += len) {
                int i;

                rc = read(fd, buf, len);
                if (rc != len) {
                        fprintf(stderr, "%s: read error: %s, rc %d != %ld\n",
                                argv[0], strerror(errno), rc, len);
                        return 6;
                }

                for (i = 0; i < len; i += st.st_blksize) {
                        if (block_debug_check("read", buf + i, st.st_blksize,
                                              offset + i, objid))
                                return 11;
                }
        }

        return 0;
}
