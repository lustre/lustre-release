// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2018, DataDirect Networks Storage.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Checksum functions
 *
 * Author: Li Xi.
 */

#include <obd_class.h>
#include <obd_cksum.h>

/* Server uses algos that perform at 50% or better of the Adler */
enum cksum_types obd_cksum_types_supported_server(const char *obd_name)
{
	enum cksum_types ret = OBD_CKSUM_ADLER;
	int base_speed;

	CDEBUG(D_INFO, "%s: checksum speed: crc %d, crc32c %d, adler %d, "
	       "t10ip512 %d, t10ip4k %d, t10crc512 %d, t10crc4k %d\n",
	       obd_name,
	       cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32)),
	       cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32C)),
	       cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_ADLER)),
	       obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10IP512),
	       obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10IP4K),
	       obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10CRC512),
	       obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10CRC4K));

	base_speed = cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_ADLER)) / 2;

	if (cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32C)) >=
	    base_speed)
		ret |= OBD_CKSUM_CRC32C;

	if (cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32)) >=
	    base_speed)
		ret |= OBD_CKSUM_CRC32;

	if (obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10IP512) >= base_speed)
		ret |= OBD_CKSUM_T10IP512;

	if (obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10IP4K) >= base_speed)
		ret |= OBD_CKSUM_T10IP4K;

	if (obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10CRC512) >= base_speed)
		ret |= OBD_CKSUM_T10CRC512;

	if (obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10CRC4K) >= base_speed)
		ret |= OBD_CKSUM_T10CRC4K;

	return ret;
}
EXPORT_SYMBOL(obd_cksum_types_supported_server);

/* The OBD_FL_CKSUM_* flags is packed into 5 bits of o_flags, since there can
 * only be a single checksum type per RPC.
 *
 * The OBD_CKSUM_* type bits passed in ocd_cksum_types are a 32-bit bitmask
 * since they need to represent the full range of checksum algorithms that
 * both the client and server can understand.
 *
 * In case of an unsupported types/flags we fall back to ADLER
 * because that is supported by all clients since 1.8
 *
 * In case multiple algorithms are supported the best one is used. */
u32 obd_cksum_type_pack(const char *obd_name, enum cksum_types cksum_type)
{
	unsigned int performance = 0, tmp;
	u32 flag = OBD_FL_CKSUM_ADLER;

	if (cksum_type & OBD_CKSUM_CRC32) {
		tmp = cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32));
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_CRC32;
		}
	}
	if (cksum_type & OBD_CKSUM_CRC32C) {
		tmp = cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_CRC32C));
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_CRC32C;
		}
	}
	if (cksum_type & OBD_CKSUM_ADLER) {
		tmp = cfs_crypto_hash_speed(cksum_obd2cfs(OBD_CKSUM_ADLER));
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_ADLER;
		}
	}

	if (cksum_type & OBD_CKSUM_T10IP512) {
		tmp = obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10IP512);
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_T10IP512;
		}
	}

	if (cksum_type & OBD_CKSUM_T10IP4K) {
		tmp = obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10IP4K);
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_T10IP4K;
		}
	}

	if (cksum_type & OBD_CKSUM_T10CRC512) {
		tmp = obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10CRC512);
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_T10CRC512;
		}
	}

	if (cksum_type & OBD_CKSUM_T10CRC4K) {
		tmp = obd_t10_cksum_speed(obd_name, OBD_CKSUM_T10CRC4K);
		if (tmp > performance) {
			performance = tmp;
			flag = OBD_FL_CKSUM_T10CRC4K;
		}
	}

	if (unlikely(cksum_type && !(cksum_type & OBD_CKSUM_ALL)))
		CWARN("%s: unknown cksum type %x\n", obd_name, cksum_type);

	return flag;
}
EXPORT_SYMBOL(obd_cksum_type_pack);
