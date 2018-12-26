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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef __OBD_CKSUM
#define __OBD_CKSUM
#include <libcfs/libcfs.h>
#include <libcfs/libcfs_crypto.h>
#include <uapi/linux/lustre/lustre_idl.h>

int obd_t10_cksum_speed(const char *obd_name,
			enum cksum_types cksum_type);

static inline unsigned char cksum_obd2cfs(enum cksum_types cksum_type)
{
	switch (cksum_type) {
	case OBD_CKSUM_CRC32:
		return CFS_HASH_ALG_CRC32;
	case OBD_CKSUM_ADLER:
		return CFS_HASH_ALG_ADLER32;
	case OBD_CKSUM_CRC32C:
		return CFS_HASH_ALG_CRC32C;
	default:
		CERROR("Unknown checksum type (%x)!!!\n", cksum_type);
		LBUG();
	}
	return 0;
}

u32 obd_cksum_type_pack(const char *obd_name, enum cksum_types cksum_type);

static inline enum cksum_types obd_cksum_type_unpack(u32 o_flags)
{
	switch (o_flags & OBD_FL_CKSUM_ALL) {
	case OBD_FL_CKSUM_CRC32C:
		return OBD_CKSUM_CRC32C;
	case OBD_FL_CKSUM_CRC32:
		return OBD_CKSUM_CRC32;
	case OBD_FL_CKSUM_T10IP512:
		return OBD_CKSUM_T10IP512;
	case OBD_FL_CKSUM_T10IP4K:
		return OBD_CKSUM_T10IP4K;
	case OBD_FL_CKSUM_T10CRC512:
		return OBD_CKSUM_T10CRC512;
	case OBD_FL_CKSUM_T10CRC4K:
		return OBD_CKSUM_T10CRC4K;
	default:
		break;
	}

	return OBD_CKSUM_ADLER;
}

/* Return a bitmask of the checksum types supported on this system.
 * 1.8 supported ADLER it is base and not depend on hw
 * Client uses all available local algos
 */
static inline enum cksum_types obd_cksum_types_supported_client(void)
{
	enum cksum_types ret = OBD_CKSUM_ADLER;

	CDEBUG(D_INFO, "Crypto hash speed: crc %d, crc32c %d, adler %d\n",
	       cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32)),
	       cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32C)),
	       cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_ADLER)));

	if (cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32C)) > 0)
		ret |= OBD_CKSUM_CRC32C;
	if (cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32)) > 0)
		ret |= OBD_CKSUM_CRC32;

	/* Client support all kinds of T10 checksum */
	ret |= OBD_CKSUM_T10_ALL;

	return ret;
}

enum cksum_types obd_cksum_types_supported_server(const char *obd_name);

/* Select the best checksum algorithm among those supplied in the cksum_types
 * input.
 *
 * Currently, calling cksum_type_pack() with a mask will return the fastest
 * checksum type due to its benchmarking at libcfs module load.
 * Caution is advised, however, since what is fastest on a single client may
 * not be the fastest or most efficient algorithm on the server.  */
static inline enum cksum_types
obd_cksum_type_select(const char *obd_name, enum cksum_types cksum_types)
{
	u32 flag = obd_cksum_type_pack(obd_name, cksum_types);

	return obd_cksum_type_unpack(flag);
}

/* Checksum algorithm names. Must be defined in the same order as the
 * OBD_CKSUM_* flags. */
#define DECLARE_CKSUM_NAME const char *cksum_name[] = {"crc32", "adler", \
	"crc32c", "reserved", "t10ip512", "t10ip4K", "t10crc512", "t10crc4K"}

typedef __u16 (obd_dif_csum_fn) (void *, unsigned int);

__u16 obd_dif_crc_fn(void *data, unsigned int len);
__u16 obd_dif_ip_fn(void *data, unsigned int len);
int obd_page_dif_generate_buffer(const char *obd_name, struct page *page,
				 __u32 offset, __u32 length,
				 __u16 *guard_start, int guard_number,
				 int *used_number, int sector_size,
				 obd_dif_csum_fn *fn);
/*
 * If checksum type is one T10 checksum types, init the csum_fn and sector
 * size. Otherwise, init them to NULL/zero.
 */
static inline void obd_t10_cksum2dif(enum cksum_types cksum_type,
				     obd_dif_csum_fn **fn, int *sector_size)
{
	*fn = NULL;
	*sector_size = 0;

#if IS_ENABLED(CONFIG_CRC_T10DIF)
	switch (cksum_type) {
	case OBD_CKSUM_T10IP512:
		*fn = obd_dif_ip_fn;
		*sector_size = 512;
		break;
	case OBD_CKSUM_T10IP4K:
		*fn = obd_dif_ip_fn;
		*sector_size = 4096;
		break;
	case OBD_CKSUM_T10CRC512:
		*fn = obd_dif_crc_fn;
		*sector_size = 512;
		break;
	case OBD_CKSUM_T10CRC4K:
		*fn = obd_dif_crc_fn;
		*sector_size = 4096;
		break;
	default:
		break;
	}
#endif /* CONFIG_CRC_T10DIF */
}

enum obd_t10_cksum_type {
	OBD_T10_CKSUM_UNKNOWN = 0,
	OBD_T10_CKSUM_IP512,
	OBD_T10_CKSUM_IP4K,
	OBD_T10_CKSUM_CRC512,
	OBD_T10_CKSUM_CRC4K,
	OBD_T10_CKSUM_MAX
};

#endif /* __OBD_H */
