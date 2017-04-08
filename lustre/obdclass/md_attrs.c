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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2012, 2016, Intel Corporation.
 * Use is subject to license terms.
 *
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 */

#include <lustre/lustre_idl.h>

#include <llog_swab.h>
#include <lustre_swab.h>
#include <obd.h>
#include <md_object.h>

/**
 * Initialize new \a lma. Only fid is stored.
 *
 * \param lma - is the new LMA structure to be initialized
 * \param fid - is the FID of the object this LMA belongs to
 * \param incompat - features that MDS must understand to access object
 */
void lustre_lma_init(struct lustre_mdt_attrs *lma, const struct lu_fid *fid,
		     __u32 compat, __u32 incompat)
{
	lma->lma_compat   = compat;
	lma->lma_incompat = incompat;
	lma->lma_self_fid = *fid;

	/* If a field is added in struct lustre_mdt_attrs, zero it explicitly
	 * and change the test below. */
	LASSERT(sizeof(*lma) ==
		(offsetof(struct lustre_mdt_attrs, lma_self_fid) +
		 sizeof(lma->lma_self_fid)));
}
EXPORT_SYMBOL(lustre_lma_init);

/**
 * Swab, if needed, LMA structure which is stored on-disk in little-endian order.
 *
 * \param lma - is a pointer to the LMA structure to be swabbed.
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

void lustre_loa_init(struct lustre_ost_attrs *loa, const struct lu_fid *fid,
		     __u32 compat, __u32 incompat)
{
	CLASSERT(sizeof(*loa) == LMA_OLD_SIZE);

	memset(&loa->loa_parent_fid, 0,
	       sizeof(*loa) - offsetof(typeof(*loa), loa_parent_fid));
	lustre_lma_init(&loa->loa_lma, fid, compat, incompat);
}
EXPORT_SYMBOL(lustre_loa_init);

/**
 * Swab, if needed, LOA (for OST-object only) structure with LMA EA and PFID EA
 * combined together are stored on-disk in little-endian order.
 *
 * \param[in] loa	- the pointer to the LOA structure to be swabbed.
 * \param[in] to_cpu	- to indicate swab for CPU order or not.
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
 * Swab, if needed, HSM structure which is stored on-disk in little-endian
 * order.
 *
 * \param attrs - is a pointer to the HSM structure to be swabbed.
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

/*
 * Swab and extract HSM attributes from on-disk xattr.
 *
 * \param buf - is a buffer containing the on-disk HSM extended attribute.
 * \param rc  - is the HSM xattr stored in \a buf
 * \param mh  - is the md_hsm structure where to extract HSM attributes.
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

/*
 * Pack HSM attributes.
 *
 * \param buf - is the output buffer where to pack the on-disk HSM xattr.
 * \param mh  - is the md_hsm structure to pack.
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
