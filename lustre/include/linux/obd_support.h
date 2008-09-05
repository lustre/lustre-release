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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
#include <lustre/lustre_idl.h>

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

static inline __u32 init_checksum(cksum_type_t cksum_type)
{
        switch(cksum_type) {
        case OBD_CKSUM_CRC32:
                return ~0U;
#ifdef HAVE_ADLER
        case OBD_CKSUM_ADLER:
                return 1U;
#endif
        default:
                CERROR("Unknown checksum type (%x)!!!\n", cksum_type);
                LBUG();
        }
        return 0;
}

static inline __u32 compute_checksum(__u32 cksum, unsigned char const *p,
                                     size_t len, cksum_type_t cksum_type)
{
        switch(cksum_type) {
        case OBD_CKSUM_CRC32:
                return crc32_le(cksum, p, len);
#ifdef HAVE_ADLER
        case OBD_CKSUM_ADLER:
                return zlib_adler32(cksum, p, len);
#endif
        default:
                CERROR("Unknown checksum type (%x)!!!\n", cksum_type);
                LBUG();
        }
        return 0;
}

static inline obd_flag cksum_type_pack(cksum_type_t cksum_type)
{
        switch(cksum_type) {
        case OBD_CKSUM_CRC32:
                return OBD_FL_CKSUM_CRC32;
#ifdef HAVE_ADLER
        case OBD_CKSUM_ADLER:
                return OBD_FL_CKSUM_ADLER;
#endif
        default:
                CWARN("unknown cksum type %x\n", cksum_type);
        }
        return OBD_FL_CKSUM_CRC32;
}

static inline cksum_type_t cksum_type_unpack(obd_flag o_flags)
{
        o_flags &= OBD_FL_CKSUM_ALL;
        if ((o_flags - 1) & o_flags)
                CWARN("several checksum types are set: %x\n", o_flags);
        if (o_flags & OBD_FL_CKSUM_ADLER)
#ifdef HAVE_ADLER
                return OBD_CKSUM_ADLER;
#else
                CWARN("checksum type is set to adler32, but adler32 is not "
                      "supported (%x)\n", o_flags);
#endif
        return OBD_CKSUM_CRC32;
}

#ifdef __KERNEL__
# include <linux/types.h>
# include <linux/blkdev.h>
# include <lvfs.h>

#define OBD_FAIL_WRITE(obd, id, sb)                                          \
{                                                                            \
        if (OBD_FAIL_CHECK(id)) {                                            \
                BDEVNAME_DECLARE_STORAGE(tmp);                               \
                CERROR("obd_fail_loc=%x, fail write operation on %s\n",      \
                       id, ll_bdevname(sb, tmp));                            \
                lvfs_set_rdonly(obd, sb);                                    \
                /* We set FAIL_ONCE because we never "un-fail" a device */   \
                obd_fail_loc |= OBD_FAILED | OBD_FAIL_ONCE;                  \
        }                                                                    \
}

#define OBD_SLEEP_ON(wq, state)  wait_event_interruptible(wq, state)


#else /* !__KERNEL__ */
# define LTIME_S(time) (time)
/* for obd_class.h */
# ifndef ERR_PTR
#  define ERR_PTR(a) ((void *)(a))
# endif
#endif  /* __KERNEL__ */

#endif
