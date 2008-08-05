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

#ifndef __OBD_CKSUM
#define __OBD_CKSUM

#if defined(__linux__)
#include <linux/obd_cksum.h>
#elif defined(__APPLE__)
#include <darwin/obd_chksum.h>
#elif defined(__WINNT__)
#include <winnt/obd_cksum.h>
#else
#error Unsupported operating system.
#endif

#include <lustre/lustre_idl.h>

/*
 * Checksums
 */

#ifndef HAVE_ARCH_CRC32
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
                return adler32(cksum, p, len);
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

#ifdef HAVE_ADLER
/* Default preferred checksum algorithm to use (if supported by the server) */
#define OSC_DEFAULT_CKSUM OBD_CKSUM_ADLER
/* Adler-32 is supported */
#define CHECKSUM_ADLER OBD_CKSUM_ADLER
#else
#define OSC_DEFAULT_CKSUM OBD_CKSUM_CRC32
#define CHECKSUM_ADLER 0
#endif

#define OBD_CKSUM_ALL (OBD_CKSUM_CRC32 | CHECKSUM_ADLER)

/* Checksum algorithm names. Must be defined in the same order as the
 * OBD_CKSUM_* flags. */
#define DECLARE_CKSUM_NAME char *cksum_name[] = {"crc32", "adler"}

#endif /* __OBD_H */
