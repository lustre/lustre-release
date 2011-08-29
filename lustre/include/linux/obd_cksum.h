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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __LINUX_OBD_CKSUM
#define __LINUX_OBD_CKSUM

#ifndef __OBD_CKSUM
#error Do not #include this file directly. #include <obd_chsum.h> instead
#endif

#include <libcfs/libcfs.h>

/* Prefer the kernel's version, if it exports it, because it might be
 * optimized for this CPU. */
#if defined(__KERNEL__) && (defined(CONFIG_CRC32) || defined(CONFIG_CRC32_MODULE))
# include <linux/crc32.h>
# define HAVE_ARCH_CRC32
#endif

#ifdef __KERNEL__
# include <linux/zutil.h>
# ifndef HAVE_ADLER
#  define HAVE_ADLER
# endif
# define adler32(a,b,l) zlib_adler32(a,b,l)
#else /*  __KERNEL__ */
# ifdef HAVE_ADLER
#  include <zlib.h>
# endif
#endif /*! __KERNEL__ */

#endif
