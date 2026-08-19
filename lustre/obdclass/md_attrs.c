// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2012, 2017, Intel Corporation.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 */

#include <lustre_compat/linux/string.h>
#include <llog_swab.h>
#include <lustre_swab.h>
#include <obd.h>
#include <md_object.h>

/**
 * lustre_lma_init() - Initialize new @lma.
 * @lma: is the new LMA structure to be initialized
 * @fid: is the FID of the object this LMA belongs to
 * @compat: LMAC_* features that can be ignored if not understood
 * @incompat: LMAI_* features that must be understood to access object
 */
void lustre_lma_init(struct lustre_mdt_attrs *lma, const struct lu_fid *fid,
		     __u32 compat, __u32 incompat)
{
	lma->lma_compat   = compat;
	lma->lma_incompat = incompat;
	lma->lma_self_fid = *fid;

	/* If a field is added in struct lustre_mdt_attrs, zero it explicitly
	 * and change the test below. */
	BUILD_BUG_ON(sizeof(*lma) !=
		     (offsetof(struct lustre_mdt_attrs, lma_self_fid) +
		      sizeof(lma->lma_self_fid)));
}
EXPORT_SYMBOL(lustre_lma_init);

/**
 * lustre_lma_swab() - Swab, if needed, LMA structure which is stored on-disk
 *                     in little-endian order.
 * @lma: pointer to the LMA structure to be swabbed.
 */
void lustre_lma_swab(struct lustre_mdt_attrs *lma)
{
#ifdef __BIG_ENDIAN
	__swab32s(&lma->lma_compat);
	__swab32s(&lma->lma_incompat);
	lustre_swab_lu_fid(&lma->lma_self_fid);
#endif
}
EXPORT_SYMBOL(lustre_lma_swab);

/**
 * lustre_loa_init() - Initialize new @loa.
 * @loa: is the new LOA structure to be initialized
 * @fid: is the FID of the object this LOA belongs to
 * @compat: LMAC_* features that can be ignored if not understood
 * @incompat: LMAI_* features that must be understood to access object
 *
 * The embedded LMA is initialized by lustre_lma_init(); the OST-object PFID
 * EA part (parent FID, stripe and layout component information) is zeroed.
 */
void lustre_loa_init(struct lustre_ost_attrs *loa, const struct lu_fid *fid,
		     __u32 compat, __u32 incompat)
{
	BUILD_BUG_ON(sizeof(*loa) != LMA_OLD_SIZE);

	memset_startat(loa, 0, loa_parent_fid);
	lustre_lma_init(&loa->loa_lma, fid, compat, incompat);
}
EXPORT_SYMBOL(lustre_loa_init);

/**
 * lustre_loa_swab() - Swab, if needed, the LOA structure, which combines the
 *                     LMA EA with the OST-object PFID EA and is stored on-disk
 *                     in little-endian order.
 *
 * @loa: the pointer to the LOA structure to be swabbed.
 * @to_cpu: to indicate swab for CPU order or not.
 */
void lustre_loa_swab(struct lustre_ost_attrs *loa, bool to_cpu)
{
	struct lustre_mdt_attrs *lma = &loa->loa_lma;
#ifdef __BIG_ENDIAN
	__u32 compat = lma->lma_compat;
#endif

	lustre_lma_swab(lma);
#ifdef __BIG_ENDIAN
	if (to_cpu)
		compat = lma->lma_compat;

	if (compat & LMAC_STRIPE_INFO) {
		lustre_swab_lu_fid(&loa->loa_parent_fid);
		__swab32s(&loa->loa_stripe_size);
	}
	if (compat & LMAC_COMP_INFO) {
		__swab32s(&loa->loa_comp_id);
		__swab64s(&loa->loa_comp_start);
		__swab64s(&loa->loa_comp_end);
	}
#endif
}
EXPORT_SYMBOL(lustre_loa_swab);

/**
 * lustre_som_swab() - Swab, if needed, SOM structure which is stored on-disk
 *                     in little-endian order.
 * @attrs: is a pointer to the SOM structure to be swabbed.
 */
void lustre_som_swab(struct lustre_som_attrs *attrs)
{
#ifdef __BIG_ENDIAN
	__swab16s(&attrs->lsa_valid);
	__swab64s(&attrs->lsa_size);
	__swab64s(&attrs->lsa_blocks);
#endif
}
EXPORT_SYMBOL(lustre_som_swab);

/**
 * lustre_hsm_swab() - Swab, if needed, HSM structure which is stored on-disk
 *                     in little-endian order.
 * @attrs: is a pointer to the HSM structure to be swabbed.
 */
void lustre_hsm_swab(struct hsm_attrs *attrs)
{
#ifdef __BIG_ENDIAN
	__swab32s(&attrs->hsm_compat);
	__swab32s(&attrs->hsm_flags);
	__swab64s(&attrs->hsm_arch_id);
	__swab64s(&attrs->hsm_arch_ver);
#endif
}

/**
 * lustre_buf2hsm() - Swab and extract HSM attributes from on-disk xattr.
 * @buf: is a buffer containing the on-disk HSM extended attribute.
 * @rc: is the size of the HSM xattr stored in @buf, or the negative errno
 *      from fetching it
 * @mh: the md_hsm structure where to extract HSM attributes; it is only
 *      filled in when %0 is returned
 *
 * Return:
 * * %0 on success
 * * %-ENODATA if the object has no HSM xattr, i.e. @rc is %0 or %-ENODATA.
 *   This is a normal outcome rather than an error, and callers are expected
 *   to handle it as such.
 * * %negative errno propagated from @rc if fetching the xattr failed
 */
int lustre_buf2hsm(void *buf, int rc, struct md_hsm *mh)
{
	struct hsm_attrs *attrs = (struct hsm_attrs *)buf;

	ENTRY;

	if (rc == 0 ||  rc == -ENODATA)
		/* no HSM attributes */
		RETURN(-ENODATA);

	if (rc < 0)
		/* error hit while fetching xattr */
		RETURN(rc);

	/* unpack HSM attributes */
	lustre_hsm_swab(attrs);

	/* fill md_hsm structure */
	mh->mh_compat   = attrs->hsm_compat;
	mh->mh_flags    = attrs->hsm_flags;
	mh->mh_arch_id  = attrs->hsm_arch_id;
	mh->mh_arch_ver = attrs->hsm_arch_ver;

	RETURN(0);
}
EXPORT_SYMBOL(lustre_buf2hsm);

/**
 * lustre_hsm2buf() - Pack HSM attributes.
 * @buf: is the output buffer where to pack the on-disk HSM xattr.
 * @mh: is the md_hsm structure to pack.
 */
void lustre_hsm2buf(void *buf, const struct md_hsm *mh)
{
	struct hsm_attrs *attrs = (struct hsm_attrs *)buf;

	ENTRY;

	/* copy HSM attributes */
	attrs->hsm_compat   = mh->mh_compat;
	attrs->hsm_flags    = mh->mh_flags;
	attrs->hsm_arch_id  = mh->mh_arch_id;
	attrs->hsm_arch_ver = mh->mh_arch_ver;

	/* pack xattr */
	lustre_hsm_swab(attrs);
}
EXPORT_SYMBOL(lustre_hsm2buf);
