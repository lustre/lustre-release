/* SPDX-License-Identifier: GPL-2.0 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LIBCFS_LINUX_BIO_H__
#define __LIBCFS_LINUX_BIO_H__

#include_next <linux/bio.h>

#ifndef HAVE_BIO_ALLOC_WITH_BDEV
static inline struct bio *compat_bio_alloc(struct block_device *bdev,
					   unsigned short nr_vecs,
					   __u32 op, gfp_t gfp_mask)
{
	struct bio *bio;

	bio = bio_alloc(gfp_mask, nr_vecs);
	if (bio) {
		bio_set_dev(bio, bdev);
		bio->bi_opf = op;
	}
	return bio;
}
#define bio_alloc(bdev, nr_vecs, op, gfp_mask) \
	compat_bio_alloc((bdev), (nr_vecs), (op), (gfp_mask))
#endif

#endif /* __LIBCFS_LINUX_BIO_H__ */
