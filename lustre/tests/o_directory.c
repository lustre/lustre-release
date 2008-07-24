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

/* for O_DIRECTORY */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
        int fd, rc;

        if (argc != 2) {
                printf("Usage: %s <filename>\n", argv[0]);
                exit(1);
        }

        fd = open(argv[1], O_RDONLY | O_CREAT, 0600);
        if (fd == -1) {
                printf("Error opening %s for create: %s\n", argv[1],
                       strerror(errno));
                exit(1);
        }
        rc = close(fd);
        if (rc < 0) {
                printf("Error closing %s: %s\n", argv[1], strerror(errno));
                exit(1);
        }

        fd = open(argv[1], O_DIRECTORY);
        if (fd >= 0) {
                printf("opening %s as directory should have returned an "
                       "error!\n", argv[1]);
                exit(1);
        }
        if (errno != ENOTDIR) {
                printf("opening %s as directory, expected -ENOTDIR and got "
                       "%s\n", argv[1], strerror(errno));
                exit(1);
        }

        return 0;
}
