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
 * Copyright (c) 2018, DataDirect Networks Storage.
 * Author: Li Xi.
 *
 * General data integrity functions
 */
#include <linux/blkdev.h>
#include <linux/crc-t10dif.h>
#include <asm/checksum.h>
#include <obd_class.h>
#include <obd_cksum.h>

#if IS_ENABLED(CONFIG_CRC_T10DIF)
__u16 obd_dif_crc_fn(void *data, unsigned int len)
{
	return cpu_to_be16(crc_t10dif(data, len));
}
EXPORT_SYMBOL(obd_dif_crc_fn);

__u16 obd_dif_ip_fn(void *data, unsigned int len)
{
	return ip_compute_csum(data, len);
}
EXPORT_SYMBOL(obd_dif_ip_fn);

int obd_page_dif_generate_buffer(const char *obd_name, struct page *page,
				 __u32 offset, __u32 length,
				 __u16 *guard_start, int guard_number,
				 int *used_number, int sector_size,
				 obd_dif_csum_fn *fn)
{
	unsigned int i = offset;
	unsigned int end = offset + length;
	char *data_buf;
	__u16 *guard_buf = guard_start;
	unsigned int data_size;
	int used = 0;

	data_buf = kmap(page) + offset;
	while (i < end) {
		if (used >= guard_number) {
			CERROR("%s: unexpected used guard number of DIF %u/%u, "
			       "data length %u, sector size %u: rc = %d\n",
			       obd_name, used, guard_number, length,
			       sector_size, -E2BIG);
			return -E2BIG;
		}
		data_size = min(round_up(i + 1, sector_size), end) - i;
		*guard_buf = fn(data_buf, data_size);
		guard_buf++;
		data_buf += data_size;
		i += data_size;
		used++;
	}
	kunmap(page);
	*used_number = used;

	return 0;
}
EXPORT_SYMBOL(obd_page_dif_generate_buffer);

static int __obd_t10_performance_test(const char *obd_name,
				      enum cksum_types cksum_type,
				      struct page *data_page,
				      int repeat_number)
{
	unsigned char cfs_alg = cksum_obd2cfs(OBD_CKSUM_T10_TOP);
	struct ahash_request *req;
	obd_dif_csum_fn *fn = NULL;
	unsigned int bufsize;
	unsigned char *buffer;
	struct page *__page;
	__u16 *guard_start;
	int guard_number;
	int used_number = 0;
	int sector_size = 0;
	__u32 cksum;
	int rc = 0;
	int rc2;
	int used;
	int i;

	obd_t10_cksum2dif(cksum_type, &fn, &sector_size);
	if (!fn)
		return -EINVAL;

	__page = alloc_page(GFP_KERNEL);
	if (__page == NULL)
		return -ENOMEM;

	req = cfs_crypto_hash_init(cfs_alg, NULL, 0);
	if (IS_ERR(req)) {
		rc = PTR_ERR(req);
		CERROR("%s: unable to initialize checksum hash %s: rc = %d\n",
		       obd_name, cfs_crypto_hash_name(cfs_alg), rc);
		GOTO(out, rc);
	}

	buffer = kmap(__page);
	guard_start = (__u16 *)buffer;
	guard_number = PAGE_SIZE / sizeof(*guard_start);
	for (i = 0; i < repeat_number; i++) {
		/*
		 * The left guard number should be able to hold checksums of a
		 * whole page
		 */
		rc = obd_page_dif_generate_buffer(obd_name, data_page, 0,
						  PAGE_SIZE,
						  guard_start + used_number,
						  guard_number - used_number,
						  &used, sector_size, fn);
		if (rc)
			break;

		used_number += used;
		if (used_number == guard_number) {
			cfs_crypto_hash_update_page(req, __page, 0,
				used_number * sizeof(*guard_start));
			used_number = 0;
		}
	}
	kunmap(__page);
	if (rc)
		GOTO(out_final, rc);

	if (used_number != 0)
		cfs_crypto_hash_update_page(req, __page, 0,
			used_number * sizeof(*guard_start));

	bufsize = sizeof(cksum);
out_final:
	rc2 = cfs_crypto_hash_final(req, (unsigned char *)&cksum, &bufsize);
	rc = rc ? rc : rc2;
out:
	__free_page(__page);

	return rc;
}

/**
 *  Array of T10PI checksum algorithm speed in MByte per second
 */
static int obd_t10_cksum_speeds[OBD_T10_CKSUM_MAX];

static enum obd_t10_cksum_type
obd_t10_cksum2type(enum cksum_types cksum_type)
{
	switch (cksum_type) {
	case OBD_CKSUM_T10IP512:
		return OBD_T10_CKSUM_IP512;
	case OBD_CKSUM_T10IP4K:
		return OBD_T10_CKSUM_IP4K;
	case OBD_CKSUM_T10CRC512:
		return OBD_T10_CKSUM_CRC512;
	case OBD_CKSUM_T10CRC4K:
		return OBD_T10_CKSUM_CRC4K;
	default:
		return OBD_T10_CKSUM_UNKNOWN;
	}
}

static const char *obd_t10_cksum_name(enum obd_t10_cksum_type index)
{
	DECLARE_CKSUM_NAME;

	/* Need to skip "crc32", "adler", "crc32c", "reserved" */
	return cksum_name[3 + index];
}

/**
 * Compute the speed of specified T10PI checksum type
 *
 * Run a speed test on the given T10PI checksum on buffer using a 1MB buffer
 * size. This is a reasonable buffer size for Lustre RPCs, even if the actual
 * RPC size is larger or smaller.
 *
 * The speed is stored internally in the obd_t10_cksum_speeds[] array, and
 * is available through the obd_t10_cksum_speed() function.
 *
 * This function needs to stay the same as cfs_crypto_performance_test() so
 * that the speeds are comparable. And this function should reflect the real
 * cost of the checksum calculation.
 *
 * \param[in] obd_name		name of the OBD device
 * \param[in] cksum_type	checksum type (OBD_CKSUM_T10*)
 */
static void obd_t10_performance_test(const char *obd_name,
				     enum cksum_types cksum_type)
{
	enum obd_t10_cksum_type index = obd_t10_cksum2type(cksum_type);
	const int buf_len = max(PAGE_SIZE, 1048576UL);
	unsigned long bcount;
	unsigned long start;
	unsigned long end;
	struct page *page;
	int rc = 0;
	void *buf;

	page = alloc_page(GFP_KERNEL);
	if (page == NULL) {
		rc = -ENOMEM;
		goto out;
	}

	buf = kmap(page);
	memset(buf, 0xAD, PAGE_SIZE);
	kunmap(page);

	for (start = jiffies, end = start + msecs_to_jiffies(MSEC_PER_SEC / 4),
	     bcount = 0; time_before(jiffies, end) && rc == 0; bcount++) {
		rc = __obd_t10_performance_test(obd_name, cksum_type, page,
						buf_len / PAGE_SIZE);
		if (rc)
			break;
	}
	end = jiffies;
	__free_page(page);
out:
	if (rc) {
		obd_t10_cksum_speeds[index] = rc;
		CDEBUG(D_INFO, "%s: T10 checksum algorithm %s test error: "
		       "rc = %d\n", obd_name, obd_t10_cksum_name(index), rc);
	} else {
		unsigned long tmp;

		tmp = ((bcount * buf_len / jiffies_to_msecs(end - start)) *
		       1000) / (1024 * 1024);
		obd_t10_cksum_speeds[index] = (int)tmp;
		CDEBUG(D_CONFIG, "%s: T10 checksum algorithm %s speed = %d "
		       "MB/s\n", obd_name, obd_t10_cksum_name(index),
		       obd_t10_cksum_speeds[index]);
	}
}
#endif /* CONFIG_CRC_T10DIF */

int obd_t10_cksum_speed(const char *obd_name,
			enum cksum_types cksum_type)
{
#if IS_ENABLED(CONFIG_CRC_T10DIF)
	enum obd_t10_cksum_type index = obd_t10_cksum2type(cksum_type);

	if (unlikely(obd_t10_cksum_speeds[index] == 0)) {
		static DEFINE_MUTEX(obd_t10_cksum_speed_mutex);

		mutex_lock(&obd_t10_cksum_speed_mutex);
		if (obd_t10_cksum_speeds[index] == 0)
			obd_t10_performance_test(obd_name, cksum_type);
		mutex_unlock(&obd_t10_cksum_speed_mutex);
	}

	return obd_t10_cksum_speeds[index];
#else /* !CONFIG_CRC_T10DIF */
	return 0;
#endif /* !CONFIG_CRC_T10DIF */
}
EXPORT_SYMBOL(obd_t10_cksum_speed);
