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
 * \param crc  seed value for computation.  ~0 for Ethernet, sometimes 0 for
 *             other uses, or the previous crc32 value if computing incrementally.
 * \param p  - pointer to buffer over which CRC is run
 * \param len- length of buffer \a p
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
 
#ifdef HAVE_ADLER
/* Adler-32 is supported */
#define CHECKSUM_ADLER OBD_CKSUM_ADLER
#else
#define CHECKSUM_ADLER 0
#endif

#ifdef X86_FEATURE_XMM4_2
/* Call Nehalem+ CRC32C harware acceleration instruction on individual bytes. */
static inline __u32 crc32c_hw_byte(__u32 crc, unsigned char const *p,
				   size_t bytes)
{
        while (bytes--) {
                __asm__ __volatile__ (
                        ".byte 0xf2, 0xf, 0x38, 0xf0, 0xf1"
                        : "=S"(crc)
                        : "0"(crc), "c"(*p)
                );
                p++;
        }

        return crc;
}

#if BITS_PER_LONG > 32
#define WORD_SHIFT 3
#define WORD_MASK  7
#define REX "0x48, "
#else
#define WORD_SHIFT 2
#define WORD_MASK  3
#define REX ""
#endif

/* Do we need to worry about unaligned input data here? */
static inline __u32 crc32c_hw(__u32 crc, unsigned char const *p, size_t len)
{
        unsigned int words = len >> WORD_SHIFT;
        unsigned int bytes = len &  WORD_MASK;
        long *ptmp = (long *)p;

        while (words--) {
                __asm__ __volatile__(
                        ".byte 0xf2, " REX "0xf, 0x38, 0xf1, 0xf1;"
                        : "=S"(crc)
                        : "0"(crc), "c"(*ptmp)
                );
                ptmp++;
        }

        if (bytes)
                crc = crc32c_hw_byte(crc, (unsigned char *)ptmp, bytes);

        return crc;
}
#else
/* We should never call this unless the CPU has previously been detected to
 * support this instruction in the SSE4.2 feature set. b=23549  */
static inline __u32 crc32c_hw(__u32 crc, unsigned char const *p,size_t len)
{
        LBUG();
}
#endif

static inline __u32 init_checksum(cksum_type_t cksum_type)
{
        switch(cksum_type) {
        case OBD_CKSUM_CRC32C:
                return ~0U;
#ifdef HAVE_ADLER
        case OBD_CKSUM_ADLER:
                return 1U;
#endif
        case OBD_CKSUM_CRC32:
                return ~0U;
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
        case OBD_CKSUM_CRC32C:
                return crc32c_hw(cksum, p, len);
#ifdef HAVE_ADLER
        case OBD_CKSUM_ADLER:
                return adler32(cksum, p, len);
#endif
        case OBD_CKSUM_CRC32:
                return crc32_le(cksum, p, len);
        default:
                CERROR("Unknown checksum type (%x)!!!\n", cksum_type);
                LBUG();
        }
        return 0;
}

/* The OBD_FL_CKSUM_* flags is packed into 5 bits of o_flags, since there can
 * only be a single checksum type per RPC.
 *
 * The OBD_CHECKSUM_* type bits passed in ocd_cksum_types are a 32-bit bitmask
 * since they need to represent the full range of checksum algorithms that
 * both the client and server can understand.
 *
 * In case of an unsupported types/flags we fall back to CRC32 (even though
 * it isn't very fast) because that is supported by all clients
 * checksums, since 1.6.5 (or earlier via patches).
 *
 * These flags should be listed in order of descending performance, so that
 * in case multiple algorithms are supported the best one is used. */
static inline obd_flag cksum_type_pack(cksum_type_t cksum_type)
{
        if (cksum_type & OBD_CKSUM_CRC32C)
                return OBD_FL_CKSUM_CRC32C;
#ifdef HAVE_ADLER
        if (cksum_type & OBD_CKSUM_ADLER)
                return OBD_FL_CKSUM_ADLER;
#endif
        if (unlikely(cksum_type && !(cksum_type & OBD_CKSUM_CRC32)))
                CWARN("unknown cksum type %x\n", cksum_type);

        return OBD_FL_CKSUM_CRC32;
}

static inline cksum_type_t cksum_type_unpack(obd_flag o_flags)
{
        switch (o_flags & OBD_FL_CKSUM_ALL) {
        case OBD_FL_CKSUM_CRC32C:
                return OBD_CKSUM_CRC32C;
        case OBD_FL_CKSUM_ADLER:
#ifdef HAVE_ADLER
                return OBD_CKSUM_ADLER;
#else
                CWARN("checksum type is set to adler32, but adler32 is not "
                      "supported (%x)\n", o_flags);
                break;
#endif
        default:
                break;
        }

        /* 1.6.4- only supported CRC32 and didn't set o_flags */
        return OBD_CKSUM_CRC32;
}

/* Return a bitmask of the checksum types supported on this system.
 *
 * CRC32 is a required for compatibility (starting with 1.6.5),
 * after which we could move to Adler as the base checksum type.
 *
 * If hardware crc32c support is not available, it is slower than Adler,
 * so don't include it, even if it could be emulated in software. b=23549 */
static inline cksum_type_t cksum_types_supported(void)
{
        cksum_type_t ret = OBD_CKSUM_CRC32;

#ifdef X86_FEATURE_XMM4_2
        if (cpu_has_xmm4_2)
                ret |= OBD_CKSUM_CRC32C;
#endif
#ifdef HAVE_ADLER
        ret |= OBD_CKSUM_ADLER;
#endif
        return ret;
}

/* Select the best checksum algorithm among those supplied in the cksum_types
 * input.
 *
 * Currently, calling cksum_type_pack() with a mask will return the fastest
 * checksum type due to its ordering, but in the future we might want to
 * determine this based on benchmarking the different algorithms quickly.
 * Caution is advised, however, since what is fastest on a single client may
 * not be the fastest or most efficient algorithm on the server.  */
static inline cksum_type_t cksum_type_select(cksum_type_t cksum_types)
{
        return cksum_type_unpack(cksum_type_pack(cksum_types));
}

/* Checksum algorithm names. Must be defined in the same order as the
 * OBD_CKSUM_* flags. */
#define DECLARE_CKSUM_NAME char *cksum_name[] = {"crc32", "adler", "crc32c"}

#endif /* __OBD_H */
