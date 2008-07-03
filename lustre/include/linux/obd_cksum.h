/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __LINUX_OBD_CKSUM
#define __LINUX_OBD_CKSUM

#ifndef __OBD_CKSUM
#error Do not #include this file directly. #include <obd_chsum.h> instead
#endif

#ifdef __KERNEL__
#include <linux/autoconf.h>
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
