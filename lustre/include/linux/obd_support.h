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

#ifndef _LINUX_OBD_SUPPORT
#define _LINUX_OBD_SUPPORT

#ifndef _OBD_SUPPORT
#error Do not #include this file directly. #include <obd_support.h> instead
#endif

#ifdef __KERNEL__
#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
#include <linux/autoconf.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#endif
#include <libcfs/kp30.h>
#include <linux/lustre_compat25.h>

/* Prefer the kernel's version, if it exports it, because it might be
 * optimized for this CPU. */
#if defined(__KERNEL__) && (defined(CONFIG_CRC32) || defined(CONFIG_CRC32_MODULE))
# include <linux/crc32.h>
#else
/* crc32_le lifted from the Linux kernel, which had the following to say:
 *
 * This code is in the public domain; copyright abandoned.
 * Liability for non-performance of this code is limited to the amount
 * you paid for it.  Since it is distributed for free, your refund will
 * be very very small.  If it breaks, you get to keep both pieces.
 */
#define CRCPOLY_LE 0xedb88320
/**
 * crc32_le() - Calculate bitwise little-endian Ethernet AUTODIN II CRC32
 * @crc - seed value for computation.  ~0 for Ethernet, sometimes 0 for
 *        other uses, or the previous crc32 value if computing incrementally.
 * @p   - pointer to buffer over which CRC is run
 * @len - length of buffer @p
 */
static inline __u32 crc32_le(__u32 crc, unsigned char const *p, size_t len)
{
        int i;
        while (len--) {
                crc ^= *p++;
                for (i = 0; i < 8; i++)
                        crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_LE : 0);
        }
        return crc;
}
#endif

#ifdef __KERNEL__
# include <linux/zutil.h>
# ifndef HAVE_ADLER
#  define HAVE_ADLER
# endif
#else /* ! __KERNEL__ */
# ifdef HAVE_ADLER
#  include <zlib.h>

static inline __u32 zlib_adler32(__u32 adler, unsigned char const *p,
                                 size_t len)
{
        return adler32(adler, p, len);
}
# endif
#endif /* __KERNEL__ */

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/blkdev.h>
# include <lvfs.h>
# define OBD_SLEEP_ON(wq, state)  wait_event_interruptible(wq, state)
#else /* !__KERNEL__ */
# define LTIME_S(time) (time)
/* for obd_class.h */
# ifndef ERR_PTR
#  define ERR_PTR(a) ((void *)(a))
# endif
#endif  /* __KERNEL__ */

#endif
