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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2014, Intel Corporation.
 * Author: John L. Hammond <john.hammond@intel.com>
 */
#ifndef _LIBCFS_BYTEORDER_H
#define _LIBCFS_BYTERODER_H

#ifdef __KERNEL__
# include <asm/byteorder.h>
#else /* __KERNEL__ */

# ifdef HAVE_ENDIAN_H
#  include <endian.h>
# endif
# include <byteswap.h>

# define __swab16(x) bswap_16(x)
# define __swab32(x) bswap_32(x)
# define __swab64(x) bswap_64(x)
# define __swab16s(x)				\
	do {					\
		*(x) = bswap_16(*(x));		\
	} while (0)
# define __swab32s(x)				\
	do {					\
		*(x) = bswap_32(*(x));		\
	} while (0)
# define __swab64s(x)				\
	do {					\
		*(x) = bswap_64(*(x));		\
	} while (0)
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define le16_to_cpu(x) (x)
#  define cpu_to_le16(x) (x)
#  define le32_to_cpu(x) (x)
#  define cpu_to_le32(x) (x)
#  define le64_to_cpu(x) (x)
#  define cpu_to_le64(x) (x)

#  define be16_to_cpu(x) bswap_16(x)
#  define cpu_to_be16(x) bswap_16(x)
#  define be32_to_cpu(x) bswap_32(x)
#  define cpu_to_be32(x) bswap_32(x)
#  define be64_to_cpu(x) ((__u64)bswap_64(x))
#  define cpu_to_be64(x) ((__u64)bswap_64(x))
# elif __BYTE_ORDER == __BIG_ENDIAN
#  define le16_to_cpu(x) bswap_16(x)
#  define cpu_to_le16(x) bswap_16(x)
#  define le32_to_cpu(x) bswap_32(x)
#  define cpu_to_le32(x) bswap_32(x)
#  define le64_to_cpu(x) ((__u64)bswap_64(x))
#  define cpu_to_le64(x) ((__u64)bswap_64(x))

#  define be16_to_cpu(x) (x)
#  define cpu_to_be16(x) (x)
#  define be32_to_cpu(x) (x)
#  define cpu_to_be32(x) (x)
#  define be64_to_cpu(x) (x)
#  define cpu_to_be64(x) (x)
# else /*  __BYTE_ORDER == __BIG_ENDIAN */
#  error "Unknown byte order"
# endif /* __BYTE_ORDER != __BIG_ENDIAN */

#endif /* !__KERNEL__ */

#endif /* _LIBCFS_BYTEORDER_H */
