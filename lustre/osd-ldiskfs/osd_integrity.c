// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2018, DataDirect Networks Storage.
 */

/*
 * Data integrity functions for OSD
 * Codes copied from kernel 3.10.0-862.el7
 * drivers/scsi/sd_dif.c and block/t10-pi.c
 *
 * Author: Li Xi
 */

#include <linux/t10-pi.h>
#include <obd_cksum.h>
#include <lustre_compat.h>

#include "osd_internal.h"

struct osd_blk_integrity_iter {
	void			*prot_buf;
	void			*data_buf;
	sector_t		seed;
	unsigned int		data_size;
	unsigned short		interval;
	unsigned char		tuple_size;
	const char		*disk_name;
	struct bio		*bio;
	unsigned int		bi_idx;
};

typedef blk_status_t (osd_integrity_proc_fn) (struct osd_blk_integrity_iter *);

static struct niobuf_local *find_lnb(struct osd_blk_integrity_iter *iter)
{
	struct bio *bio = iter->bio;
	struct osd_bio_private *bio_private = bio->bi_private;
	struct osd_iobuf *iobuf = bio_private->obp_iobuf;
	struct page *page = virt_to_page(iter->data_buf);
	int index = bio_private->obp_start_page_idx + iter->bi_idx;
	int i;

	/*
	 * blocks are contiguous in bio but pages added to bio
	 * could have a gap comparing to pages.
	 * e.g. a page mapped to a hole in the middle.
	 */
	for (i = index; i < iobuf->dr_npages; i++) {
		if (iobuf->dr_lnbs[i]->lnb_page == page)
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
static blk_status_t osd_dif_generate(struct osd_blk_integrity_iter *iter,
				obd_dif_csum_fn *fn, enum osd_t10_type type)
{
	struct niobuf_local *lnb = find_lnb(iter);
	__be16 *lnb_guard_buf = lnb ? lnb->lnb_guards : NULL;
	unsigned int i;

	ENTRY;
	for (i = 0 ; i < iter->data_size ; i += iter->interval) {
		struct t10_pi_tuple *pi = iter->prot_buf;

		if (lnb && lnb->lnb_guard_rpc) {
			pi->guard_tag = *lnb_guard_buf;
			lnb_guard_buf++;
		} else {
			pi->guard_tag = fn(iter->data_buf, iter->interval);
		}
		pi->app_tag = 0;

		if (type == OSD_T10_TYPE1)
			pi->ref_tag = cpu_to_be32(lower_32_bits(iter->seed));
		else /* if (type == OSD_T10_TYPE3) */
			pi->ref_tag = 0;

		iter->data_buf += iter->interval;
		iter->prot_buf += iter->tuple_size;
		iter->seed++;
	}

	RETURN(BLK_STS_OK);
}

static blk_status_t osd_dif_verify(struct osd_blk_integrity_iter *iter,
				   obd_dif_csum_fn *fn, enum osd_t10_type type)
{
	struct niobuf_local *lnb = find_lnb(iter);
	__be16 *lnb_guard_buf = lnb ? lnb->lnb_guards : NULL;
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

		if (lnb_guard_buf) {
			*lnb_guard_buf = pi->guard_tag;
			lnb_guard_buf++;
		}

next:
		iter->data_buf += iter->interval;
		iter->prot_buf += iter->tuple_size;
		iter->seed++;
	}

	if (lnb)
		lnb->lnb_guard_disk = 1;

	RETURN(BLK_STS_OK);
}

static blk_status_t osd_dif_type1_generate_crc(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_generate(iter, obd_dif_crc_fn, OSD_T10_TYPE1);
}

static blk_status_t osd_dif_type1_generate_ip(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_generate(iter, obd_dif_ip_fn, OSD_T10_TYPE1);
}

static blk_status_t osd_dif_type3_generate_crc(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_generate(iter, obd_dif_crc_fn, OSD_T10_TYPE3);
}

static blk_status_t osd_dif_type3_generate_ip(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_generate(iter, obd_dif_ip_fn, OSD_T10_TYPE3);
}
static blk_status_t osd_dif_type1_verify_crc(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_crc_fn, OSD_T10_TYPE1);
}

static blk_status_t osd_dif_type1_verify_ip(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_ip_fn, OSD_T10_TYPE1);
}

static blk_status_t osd_dif_type3_verify_crc(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_crc_fn, OSD_T10_TYPE3);
}

static blk_status_t osd_dif_type3_verify_ip(struct osd_blk_integrity_iter *iter)
{
	return osd_dif_verify(iter, obd_dif_ip_fn, OSD_T10_TYPE3);
}

static int osd_get_integrity_proc_fn(struct osd_device *osd, int rw,
			      osd_integrity_proc_fn **proc_fn)
{
	*proc_fn = NULL;

	switch (osd->od_t10_type) {
	case OSD_T10_TYPE1_CRC:
		if (rw == 1)
			*proc_fn = osd_dif_type1_generate_crc;
		else if (rw == 0)
			*proc_fn = osd_dif_type1_verify_crc;
		else
			return -EINVAL;
		break;
	case OSD_T10_TYPE3_CRC:
		if (rw == 1)
			*proc_fn = osd_dif_type3_generate_crc;
		else if (rw == 0)
			*proc_fn = osd_dif_type3_verify_crc;
		else
			return -EINVAL;
		break;
	case OSD_T10_TYPE1_IP:
		if (rw == 1)
			*proc_fn = osd_dif_type1_generate_ip;
		else if (rw == 0)
			*proc_fn = osd_dif_type1_verify_ip;
		else
			return -EINVAL;
		break;
	case OSD_T10_TYPE3_IP:
		if (rw == 1)
			*proc_fn = osd_dif_type3_generate_ip;
		else if (rw == 0)
			*proc_fn = osd_dif_type3_verify_ip;
		else
			return -EINVAL;
		break;
	default:
		return -ENOTSUPP;
	}

	return 0;
}

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

		kaddr = kmap_local_page(page);
		addr = kaddr;
		*addr = ~(*addr);
		kunmap_local(kaddr);
		break;
	}
}

#if IS_ENABLED(CONFIG_BLK_DEV_INTEGRITY)
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
	sector_t sector = bio->bi_iter.bi_sector;
	unsigned int i, sectors, total;
	DECLARE_BVEC_ITER_ALL(iter_all);
	__be16 *expected_guard;
	int rc;

	total = 0;
	bio_for_each_segment_all(bv, bio, iter_all) {
		for (i = index; i < iobuf->dr_npages; i++) {
			if (iobuf->dr_lnbs[i]->lnb_page == bv->bv_page) {
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
#else /* !IS_ENABLED(CONFIG_BLK_DEV_INTEGRITY) */
static int osd_bio_integrity_compare(struct bio *bio, struct block_device *bdev,
				     struct osd_iobuf *iobuf, int index)
{
	return 0;
}
#endif

static blk_status_t osd_bio_integrity_process(struct bio *bio,
					      struct bvec_iter *proc_iter,
					      void *prot_buf,
					      osd_integrity_proc_fn *proc_fn)
{
	struct blk_integrity *bi = blk_get_integrity(bio_get_disk(bio));
	struct osd_blk_integrity_iter iter;
	struct bvec_iter bviter;
	struct bio_vec bv;
	blk_status_t ret = BLK_STS_OK;
	unsigned int pg_offset_total = 0;
	unsigned int pg_offset_cur = 0;
	unsigned int last_bi_idx = 0;

	iter.disk_name = bio_get_disk(bio)->disk_name;
	iter.interval = 1 << bi->interval_exp;
	iter.tuple_size = bi->tuple_size;
	iter.seed = proc_iter->bi_sector;
	iter.prot_buf = prot_buf;
	iter.bio = bio;

	__bio_for_each_segment(bv, bio, bviter, *proc_iter) {
		void *kaddr = kmap_local_page(bv.bv_page);

		/*
		 * For kernels with multipage bvec, a single bio_vec could hold
		 * a number of contiguous pages. The bi_idx could be smaller
		 * than the page index, making it slower to find the lnb.
		 * We need to calculate the index into dr_lnbs here.
		 */
		if (bviter.bi_idx != last_bi_idx) {
			pg_offset_total += pg_offset_cur;
			last_bi_idx = bviter.bi_idx;
		}
		pg_offset_cur = bv.bv_page - (__bvec_iter_bvec(bio->bi_io_vec, bviter))->bv_page;

		iter.data_buf = kaddr + bv.bv_offset;
		iter.data_size = bv.bv_len;
		iter.bi_idx = bviter.bi_idx + pg_offset_total + pg_offset_cur;

		ret = proc_fn(&iter);
		kunmap_local(kaddr);

		if (ret)
			break;

	}
	return ret;
}

void osd_bio_integrity_verify_fn(struct work_struct *work)
{
	osd_integrity_proc_fn *verify_fn = NULL;
	struct osd_bio_private *bio_private =
		container_of(work, struct osd_bio_private, obp_work);
	struct osd_iobuf *iobuf = bio_private->obp_iobuf;
	struct bio *bio = bio_private->obp_bio;
	blk_status_t ret;
	int rc;

	rc = osd_get_integrity_proc_fn(iobuf->dr_dev, iobuf->dr_rw,
				       &verify_fn);
	if (rc)
		goto out;

	ret = osd_bio_integrity_process(bio, &bio_private->obp_integrity_iter,
					bio_private->obp_integrity_buf,
					verify_fn);
	iobuf->dr_error = blk_status_to_errno(ret);
	bio->bi_status = ret;
out:
	osd_bio_fini(bio);
}

/*
 * Prepares the bio for integrity I/O, which is essentially what
 * bio_integrity_prep() does. The difference is that we don't set
 * BIP_BLOCK_INTEGRITY flag on the integrity payload, so the
 * integrity metadata buffer is not freed when the I/O is completed,
 * giving us the chance to get/put guard tags from/to ptlrpc.
 *
 * The integrity payload will be freed by kernel at bio_endin() time,
 * the metadata buffer will be freed by us in osd_bio_fini().
 *
 * For a WRITE, we fill the metadata buffer immdiately, for a READ,
 * upon I/O completion it's up to us to verify data intgerity
 * with the metadata buffer containing integrity metadata read
 * from the storage device.
 */
int osd_bio_integrity_handle(struct osd_device *osd, struct bio *bio,
			     struct osd_iobuf *iobuf)
{
	osd_integrity_proc_fn *generate_fn = NULL;
	struct bio_integrity_payload *bip;
	struct blk_integrity *bi = blk_get_integrity(bio_get_disk(bio));
	struct osd_bio_private *bio_private = bio->bi_private;
	void *buf, *buf_ptr;
	unsigned long start, end;
	unsigned int len, nr_pages;
	unsigned int bytes, offset, i;
	gfp_t gfp = GFP_NOIO;
	int rc;

	ENTRY;

	if (!bdev_integrity_enabled(osd_sb(osd)->s_bdev, iobuf->dr_rw))
		RETURN(0);

	if (!bio_sectors(bio))
		RETURN(0);

	if (osd->od_t10_type == OSD_T10_TYPE_UNKNOWN)
		RETURN(0);

	/*
	 * Zero the memory allocated to not leak uninitialized kernel
	 * memory to disk.  For PI this only affects the app tag, but
	 * for non-integrity metadata it affects the entire metadata
	 * buffer.
	 */
	if (iobuf->dr_rw == 1) {
		rc = osd_get_integrity_proc_fn(osd, iobuf->dr_rw, &generate_fn);
		if (rc)
			RETURN(rc);
		gfp |= __GFP_ZERO;
	}

	/* Allocate kernel buffer for protection data */
	len = bio_integrity_bytes(bi, bio_sectors(bio));
	buf = kmalloc(len, gfp);
	if (unlikely(buf == NULL)) {
		CERROR("%s: could not allocate integrity buffer\n",
		       osd_name(osd));
		bio->bi_status = BLK_STS_RESOURCE;
		RETURN(-ENOMEM);
	}

	end = (((unsigned long)buf) + len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	start = ((unsigned long)buf) >> PAGE_SHIFT;
	nr_pages = end - start;

	/* Allocate bio integrity payload and integrity vectors */
	bip = bio_integrity_alloc(bio, GFP_NOIO, nr_pages);
	if (IS_ERR(bip)) {
		CERROR("%s: could not allocate data integrity bioset\n",
		       osd_name(osd));
		kfree(buf);
		bio->bi_status = BLK_STS_RESOURCE;
		RETURN(-ENOMEM);
	}

#  ifdef HAVE_CSUM_TYPE_BLK_INTEGRITY
	if (bi->csum_type == BLK_INTEGRITY_CSUM_IP)
#  else
	if (bi->flags & BLK_INTEGRITY_IP_CHECKSUM)
#  endif
		bip->bip_flags |= BIP_IP_CHECKSUM;

	/* Map it */
	offset = offset_in_page(buf);
	buf_ptr = buf;
	for (i = 0; i < nr_pages && len > 0; i++) {
		bytes = PAGE_SIZE - offset;

		if (bytes > len)
			bytes = len;

		if (bio_integrity_add_page(bio, virt_to_page(buf_ptr), bytes,
					   offset) < bytes) {
			CERROR("%s: could not attach integrity payload\n",
			       osd_name(osd));
			bio->bi_status = BLK_STS_RESOURCE;
			kfree(buf);
			RETURN(-ENOMEM);
		}

		buf_ptr += bytes;
		len -= bytes;
		offset = 0;
	}

	/*
	 * reset bip_iter.bi_size, usually bio_integrity_add_page does that
	 * for us, but some older kernels doesn't have 80814b8e359f7
	 */
	bip->bip_iter.bi_size = bio_integrity_bytes(bi, bio_sectors(bio));
	bip_set_seed(bip, bio->bi_iter.bi_sector);
	bio_private->obp_integrity_buf = buf;

	if (iobuf->dr_rw == 1) {
		osd_bio_integrity_process(bio, &bio->bi_iter, buf, generate_fn);

		/* Verify and inject fault only when writing */
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
	} else {
		bio_private->obp_integrity_iter = bio->bi_iter;
	}

	RETURN(0);
}
