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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/darwin/lustre_user.h
 *
 * Lustre public user-space interface definitions.
 */

#ifndef _DARWIN_LUSTRE_USER_H
#define _DARWIN_LUSTRE_USER_H

#include <lustre/types.h>

#ifndef __KERNEL__
/* for llmount */
# define _GNU_SOURCE
# include <getopt.h>
# include <sys/utsname.h>
# include <sys/stat.h>
# include <errno.h>
# include <sys/mount.h>
# include <sys/fcntl.h>
# include <sys/ioccom.h>
# include <sys/wait.h>
# include <string.h>
#endif

typedef struct stat     lstat_t;
#define HAVE_LOV_USER_MDS_DATA

#ifndef LPU64
#if (BITS_PER_LONG == 32 || __WORDSIZE == 32)
# define LPU64 "%llu"
# define LPD64 "%lld"
# define LPX64 "%#llx"
#elif (BITS_PER_LONG == 64 || __WORDSIZE == 64)
# define LPU64 "%lu"
# define LPD64 "%ld"
# define LPX64 "%#lx"
#endif
#endif /* !LPU64 */

#endif /* _LUSTRE_USER_H */
