// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/utils/ll_decode_filter_fid.c
 *
 * Tool for printing the OST filter_fid structure on the objects
 * in human readable form.
 *
 * Author: Andreas Dilger <adilger@sun.com>
 */


#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <asm/byteorder.h>
#include <linux/lustre/lustre_user.h>

#if __BYTE_ORDER == __BIG_ENDIAN
static void lustre_swab_lu_fid(struct lu_fid *fid)
{
	__swab64s(&fid->f_seq);
	__swab32s(&fid->f_oid);
	__swab32s(&fid->f_ver);
}

static void lustre_loa_swab(struct lustre_ost_attrs *loa)
{
	struct lustre_mdt_attrs *lma = &loa->loa_lma;

	__swab32s(&lma->lma_compat);
	__swab32s(&lma->lma_incompat);
	lustre_swab_lu_fid(&lma->lma_self_fid);
	if (lma->lma_compat & LMAC_STRIPE_INFO) {
		lustre_swab_lu_fid(&loa->loa_parent_fid);
		__swab32s(&loa->loa_stripe_size);
	}
	if (lma->lma_compat & LMAC_COMP_INFO) {
		__swab32s(&loa->loa_comp_id);
		__swab64s(&loa->loa_comp_start);
		__swab64s(&loa->loa_comp_end);
	}
};
#else
static void lustre_loa_swab(struct lustre_ost_attrs *loa)
{
}
#endif

int main(int argc, char *argv[])
{
	int rc = 0;
	int i;

	for (i = 1; i < argc; i++) {
		char buf[1024]; /* allow xattr that may be larger */
		struct filter_fid *ff = (void *)buf;
		static int printed;
		int size;

		size = getxattr(argv[i], "trusted.fid", buf,
				sizeof(struct filter_fid));
		if (size < 0) {
			if (errno == ENODATA) {
				struct lustre_ost_attrs *loa = (void *)buf;
				int rc1;

				memset(loa, 0, sizeof(*loa));
				rc1 = getxattr(argv[i], "trusted.lma", loa,
					       sizeof(*loa));
				if (rc1 < sizeof(struct lustre_mdt_attrs)) {
					fprintf(stderr,
						"%s: error reading fid: %s\n",
						argv[i], strerror(ENODATA));
					if (!rc)
						rc = size;
					continue;
				}

				lustre_loa_swab(loa);
				if (rc1 > sizeof(struct lustre_mdt_attrs) &&
				    !(loa->loa_lma.lma_compat &
				      LMAC_STRIPE_INFO)) {
					fprintf(stderr,
						"%s: not stripe info: %s\n",
						argv[i], strerror(ENODATA));
					if (!rc)
						rc = size;
					continue;
				}

				printf("%s: fid="DFID" parent="DFID" stripe=%u "
				       "stripe_size=%u stripe_count=%u",
				       argv[i],
				       PFID(&loa->loa_lma.lma_self_fid),
				       (unsigned long long)loa->loa_parent_fid.f_seq,
				       loa->loa_parent_fid.f_oid, 0, /* ver */
				       loa->loa_parent_fid.f_stripe_idx &
							PFID_STRIPE_COUNT_MASK,
				       loa->loa_stripe_size,
				       loa->loa_parent_fid.f_stripe_idx >>
							PFID_STRIPE_IDX_BITS);
				if (loa->loa_comp_id != 0)
					printf(" component_id=%u "
					       "component_start=%llu "
					       "component_end=%llu",
					       loa->loa_comp_id,
					       (unsigned long long)loa->loa_comp_start,
					       (unsigned long long)loa->loa_comp_end);
				printf("\n");
				continue;
			}

			fprintf(stderr, "%s: error reading fid: %s\n",
				argv[i], strerror(errno));
			if (!rc)
				rc = size;
			continue;
		}

		if (size != sizeof(struct filter_fid) &&
		    size != sizeof(struct filter_fid_18_23) &&
		    size != sizeof(struct filter_fid_24_29) &&
		    size != sizeof(struct filter_fid_210) && !printed) {
			fprintf(stderr,
				"%s: warning: ffid size is unexpected (%d bytes), recompile?\n",
				argv[i], size);
			printed = 1;

			if (size < sizeof(struct filter_fid_24_29))
				continue;
		}

		printf("%s: ", argv[i]);
		if (size == sizeof(struct filter_fid_18_23)) {
			struct filter_fid_18_23 *ffo = (void *)buf;

			printf("objid=%llu seq=%llu ",
			       (unsigned long long)__le64_to_cpu(ffo->ff_objid),
			       (unsigned long long)__le64_to_cpu(ffo->ff_seq));
		}

		printf("parent="DFID" stripe=%u",
		       (unsigned long long)__le64_to_cpu(ff->ff_parent.f_seq),
		       __le32_to_cpu(ff->ff_parent.f_oid), 0, /* ver */
		       /* this is stripe_nr actually */
		       __le32_to_cpu(ff->ff_parent.f_stripe_idx));

		if (size >= sizeof(struct filter_fid_210)) {
			struct ost_layout *ol = &ff->ff_layout;

			/* new filter_fid, support PFL */
			printf(" stripe_size=%u stripe_count=%u",
			       __le32_to_cpu(ol->ol_stripe_size),
			       __le32_to_cpu(ol->ol_stripe_count));
			if (ol->ol_comp_id != 0)
				printf(" component_id=%u "
				       "component_start=%llu "
				       "component_end=%llu",
				       __le32_to_cpu(ol->ol_comp_id),
				       (unsigned long long)
				       __le64_to_cpu(ol->ol_comp_start),
				       (unsigned long long)
				       __le64_to_cpu(ol->ol_comp_end));
		}
		if (size >= sizeof(struct filter_fid))
			printf(" layout_version=%u range=%u",
			       __le32_to_cpu(ff->ff_layout_version),
			       __le32_to_cpu(ff->ff_range));

		printf("\n");
	}

	return rc;
}
