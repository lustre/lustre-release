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
 * Data integrity functions for OSD
 * Codes copied from kernel 3.10.0-862.el7
 * drivers/scsi/sd_dif.c and block/t10-pi.c
 */
#ifdef HAVE_LINUX_BLK_INTEGRITY_HEADER
 #include <linux/blk-integrity.h>
#else
 #include <linux/blkdev.h>
#endif
#include <linux/blk_types.h>

#include <obd_cksum.h>
#include <lustre_compat.h>

#include "osd_internal.h"

#if IS_ENABLED(CONFIG_CRC_T10DIF)
#ifdef HAVE_BLK_INTEGRITY_ITER
# define blk_status_gen blk_status_t
# define RETURN_GEN(_gen_fn) return _gen_fn
#else
# define blk_status_gen void
# define RETURN_GEN(_gen_fn) _gen_fn
# define blk_integrity_iter blk_integrity_exchg
# define interval sector_size
# define seed sector
# define blk_status_t int
# define BLK_STS_PROTECTION -EIO
# define BLK_STS_OK 0
#endif
/*
 * Data Integrity Field tuple.
 */
struct t10_pi_tuple {
       __be16 guard_tag;        /* Checksum */
       __be16 app_tag;          /* Opaque storage */
       __be32 ref_tag;          /* Target LBA or indirect LBA */
};

#define T10_PI_APP_ESCAPE cpu_to_be16(0xffff)
#define T10_PI_REF_ESCAPE cpu_to_be32(0xffffffff)

static struct niobuf_local *find_lnb(struct blk_integrity_iter *iter)
{
	struct bio *bio = iter->bio;
	struct bio_vec *bv = &bio->bi_io_vec[iter->bi_idx];
	struct osd_bio_private *bio_private = bio->bi_private;
	struct osd_iobuf *iobuf = bio_private->obp_iobuf;
	int index = bio_private->obp_start_page_idx + iter->bi_idx;
	int i;

	/*
	 * blocks are contiguous in bio but pages added to bio
	 * could have a gap comparing to iobuf->dr_pages.
	 * e.g. a page mapped to a hole in the middle.
	 */
	for (i = index; i < iobuf->dr_npages; i++) {
		if (iobuf->dr_pages[i] == bv->bv_page)
			return iobuf->dr_lnbs[i];
	}

	return NULL;
}

/*
 * Type 1 and Type 2 protection use the same format: 16 bit guard tag,
 * 16 bit app tag, 32 bit reference tag (sector number).
 *
 * Type 3 protection has a 16-bit guard tag and 16 + 32 bits of opaque
 * tag space.
 */
static blk_status_gen osd_dif_generate(struct blk_integrity_iter *iter,
				obd_dif_csum_fn *fn, enum osd_t10_type type)
{
	struct niobuf_local *lnb = find_lnb(iter);
	__be16 *guard_buf = lnb ? lnb->lnb_guards : NULL;
	unsigned int i;

	ENTRY;
	for (i = 0 ; i < iter->data_size ; i += iter->interval) {
		struct t10_pi_tuple *pi = iter->prot_buf;

		if (lnb && lnb->lnb_guard_rpc) {
			pi->guard_tag = *guard_buf;
			guard_buf++;
		} else {
			pi->guard_tag = fn(iter->data_buf, iter->interval);
		}
		pi->app_tag = 0;

		if (type == OSD_T10_TYPE1)
			pi->ref_tag = cpu_to_be32(lower_32_bits(iter->seed));
		else /* if (type == OSD_T10_TYPE3) */
			pi->ref_tag = 0;

		iter->data_buf += iter->interval;
		iter->prot_buf += sizeof(struct t10_pi_tuple);
		iter->seed++;
	}

#ifdef HAVE_BLK_INTEGRITY_ITER
	RETURN(BLK_STS_OK);
#else
	RETURN_EXIT;
#endif
}

static blk_status_t osd_dif_verify(struct blk_integrity_iter *iter,
				   obd_dif_csum_fn *fn, enum osd_t10_type type)
{
	struct niobuf_local *lnb = find_lnb(iter);
	__be16 *guard_buf = lnb ? lnb->lnb_guards : NULL;
	unsigned int i;

	ENTRY;
	for (i = 0 ; i < iter->data_size ; i += iter->interval) {
		struct t10_pi_tuple *pi = iter->prot_buf;
		__be16 csum;

		if (type == OSD_T10_TYPE1 ||
		    type == OSD_T10_TYPE2) {
			if (pi->app_tag == T10_PI_APP_ESCAPE) {
				lnb = NULL;
				goto next;
			}

			if (be32_to_cpu(pi->ref_tag) !=
			    lower_32_bits(iter->seed)) {
				CERROR("%s: ref tag error at location %llu (rcvd %u): rc = %d\n",
				       iter->disk_name,
				       (unsigned long long)iter->seed,
				       be32_to_cpu(pi->ref_tag),
				       BLK_STS_PROTECTION);
				RETURN(BLK_STS_PROTECTION);
			}
		} else  if (type == OSD_T10_TYPE3) {
			if (pi->app_tag == T10_PI_APP_ESCAPE &&
			    pi->ref_tag == T10_PI_REF_ESCAPE) {
				lnb = NULL;
				goto next;
			}
		}

		csum = fn(iter->data_buf, iter->interval);

		if (pi->guard_tag != csum) {
			CERROR("%s: guard tag error on sector %llu (rcvd %04x, want %04x): rc = %d\n",
			       iter->disk_name, (unsigned long long)iter->seed,
			       be16_to_cpu(pi->guard_tag), be16_to_cpu(csum),
			       BLK_STS_PROTECTION);
			RETURN(BLK_STS_PROTECTION);
		}

		if (guard_buf) {
			*guard_buf = csum;
			guard_buf++;
		}

next:
		iter->data_buf += iter->interval;
		iter->prot_buf += sizeof(struct t10_pi_tuple);
		iter->seed++;
	}

	if (lnb)
		lnb->lnb_guard_disk = 1;

	RETURN(BLK_STS_OK);
}

static blk_status_gen osd_dif_type1_generate_crc(struct blk_integrity_iter *iter)
{
	RETURN_GEN(osd_dif_generate(iter, obd_dif_crc_fn, OSD_T10_TYPE1));
}

static blk_status_gen osd_dif_type1_generate_ip(struct blk_integrity_iter *iter)
{
	RETURN_GEN(osd_dif_generate(iter, obd_dif_ip_fn, OSD_T10_TYPE1));
}

static blk_status_gen osd_dif_type3_generate_crc(struct blk_integrity_iter *iter)
{
	RETURN_GEN(osd_dif_generate(iter, obd_dif_crc_fn, OSD_T10_TYPE3));
}

static blk_status_gen osd_dif_type3_generate_ip(struct blk_integrity_iter *iter)
{
	RETURN_GEN(osd_dif_generate(iter, obd_dif_ip_fn, OSD_T10_TYPE3));
}
static blk_status_t osd_dif_type1_verify_crc(struct blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_crc_fn, OSD_T10_TYPE1);
}

static blk_status_t osd_dif_type1_verify_ip(struct blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_ip_fn, OSD_T10_TYPE1);
}

static blk_status_t osd_dif_type3_verify_crc(struct blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_crc_fn, OSD_T10_TYPE3);
}

static blk_status_t osd_dif_type3_verify_ip(struct blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_ip_fn, OSD_T10_TYPE3);
}

int osd_get_integrity_profile(struct osd_device *osd,
			      integrity_gen_fn **generate_fn,
			      integrity_vrfy_fn **verify_fn)
{
	switch (osd->od_t10_type) {
	case OSD_T10_TYPE1_CRC:
		*verify_fn = osd_dif_type1_verify_crc;
		*generate_fn = osd_dif_type1_generate_crc;
		break;
	case OSD_T10_TYPE3_CRC:
		*verify_fn = osd_dif_type3_verify_crc;
		*generate_fn = osd_dif_type3_generate_crc;
		break;
	case OSD_T10_TYPE1_IP:
		*verify_fn = osd_dif_type1_verify_ip;
		*generate_fn = osd_dif_type1_generate_ip;
		break;
	case OSD_T10_TYPE3_IP:
		*verify_fn = osd_dif_type3_verify_ip;
		*generate_fn = osd_dif_type3_generate_ip;
		break;
	default:
		return -ENOTSUPP;
	}

	return 0;
}
#endif /* CONFIG_CRC_T10DIF */

#if IS_ENABLED(CONFIG_BLK_DEV_INTEGRITY) && defined(HAVE_BIO_INTEGRITY_PREP_FN)
/*
 * This function will change the data written, thus it should only be
 * used when checking data integrity feature
 */
static void bio_integrity_fault_inject(struct bio *bio)
{
	struct bio_vec *bvec;
	DECLARE_BVEC_ITER_ALL(iter_all);
	void *kaddr;
	char *addr;

	bio_for_each_segment_all(bvec, bio, iter_all) {
		struct page *page = bvec->bv_page;

		kaddr = kmap(page);
		addr = kaddr;
		*addr = ~(*addr);
		kunmap(page);
		break;
	}
}

static int bio_dif_compare(__u16 *expected_guard_buf, void *bio_prot_buf,
			   unsigned int sectors, int tuple_size)
{
	__be16 *expected_guard;
	__be16 *bio_guard;
	int i;

	expected_guard = expected_guard_buf;
	for (i = 0; i < sectors; i++) {
		bio_guard = (__u16 *)bio_prot_buf;
		if (*bio_guard != *expected_guard) {
			CERROR(
			       "unexpected guard tags on sector %d expected guard %u, bio guard %u, sectors %u, tuple size %d\n",
			       i, *expected_guard, *bio_guard, sectors,
			       tuple_size);
			return -EIO;
		}
		expected_guard++;
		bio_prot_buf += tuple_size;
	}
	return 0;
}

static int osd_bio_integrity_compare(struct bio *bio, struct block_device *bdev,
				     struct osd_iobuf *iobuf, int index)
{
	struct blk_integrity *bi = bdev_get_integrity(bdev);
	struct bio_integrity_payload *bip = bio->bi_integrity;
	struct niobuf_local *lnb = NULL;
	unsigned short sector_size = blk_integrity_interval(bi);
	void *bio_prot_buf = page_address(bip->bip_vec->bv_page) +
		bip->bip_vec->bv_offset;
	struct bio_vec *bv;
	sector_t sector = bio_start_sector(bio);
	unsigned int i, sectors, total;
	DECLARE_BVEC_ITER_ALL(iter_all);
	__be16 *expected_guard;
	int rc;

	total = 0;
	bio_for_each_segment_all(bv, bio, iter_all) {
		for (i = index; i < iobuf->dr_npages; i++) {
			if (iobuf->dr_pages[i] == bv->bv_page) {
				lnb = iobuf->dr_lnbs[i];
				break;
			}
		}
		if (!lnb)
			continue;
		expected_guard = lnb->lnb_guards;
		sectors = bv->bv_len / sector_size;
		if (lnb->lnb_guard_rpc) {
			rc = bio_dif_compare(expected_guard, bio_prot_buf,
					     sectors, bi->tuple_size);
			if (rc)
				return rc;
		}

		sector += sectors;
		bio_prot_buf += sectors * bi->tuple_size;
		total += sectors * bi->tuple_size;
		LASSERT(total <= bip_size(bio->bi_integrity));
		index++;
		lnb = NULL;
	}
	return 0;
}

int osd_bio_integrity_handle(struct osd_device *osd, struct bio *bio,
			     struct osd_iobuf *iobuf)
{
	integrity_gen_fn *generate_fn = NULL;
	integrity_vrfy_fn *verify_fn = NULL;
	int rc;

	ENTRY;

	if (!iobuf->dr_integrity)
		RETURN(0);

	rc = osd_get_integrity_profile(osd, &generate_fn, &verify_fn);
	if (rc)
		RETURN(rc);

# ifdef HAVE_BIO_INTEGRITY_PREP_FN_RETURNS_BOOL
	if (!bio_integrity_prep_fn(bio, generate_fn, verify_fn))
		RETURN(blk_status_to_errno(bio->bi_status));
# else
	rc = bio_integrity_prep_fn(bio, generate_fn, verify_fn);
	if (rc)
		RETURN(rc);
# endif

	/* Verify and inject fault only when writing */
	if (iobuf->dr_rw == 1) {
		if (unlikely(CFS_FAIL_CHECK(OBD_FAIL_OST_INTEGRITY_CMP))) {
			struct super_block *sb = osd_sb(osd);
			struct osd_bio_private *b_priv = bio->bi_private;
			int st_page_index = b_priv->obp_start_page_idx;

			rc = osd_bio_integrity_compare(bio, sb->s_bdev, iobuf,
						       st_page_index);
			if (rc)
				RETURN(rc);
		}

		if (unlikely(CFS_FAIL_CHECK(OBD_FAIL_OST_INTEGRITY_FAULT)))
			bio_integrity_fault_inject(bio);
	}
	RETURN(0);
}
#endif /* CONFIG_BLK_DEV_INTEGRITY */
