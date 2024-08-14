// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#define DEBUG_SUBSYSTEM S_LMV
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/math64.h>
#include <linux/seq_file.h>

#include <obd_support.h>
#include <lustre_fid.h>
#include <lustre_lib.h>
#include <lustre_net.h>
#include <lustre_dlm.h>
#include <obd_class.h>
#include <lprocfs_status.h>
#include "lmv_internal.h"

int lmv_fld_lookup(struct lmv_obd *lmv, const struct lu_fid *fid, u32 *mds)
{
	struct obd_device *obd = lmv2obd_dev(lmv);
	int rc;

	ENTRY;

	/*
	 * FIXME: Currently ZFS still use local seq for ROOT unfortunately, and
	 * this fid_is_local check should be removed once LU-2240 is fixed
	 */
	if (!fid_is_sane(fid) || !(fid_seq_in_fldb(fid_seq(fid)) ||
				   fid_seq_is_local_file(fid_seq(fid)))) {
		rc = -EINVAL;
		CERROR("%s: invalid FID "DFID": rc = %d\n", obd->obd_name,
		       PFID(fid), rc);
		RETURN(rc);
	}

	rc = fld_client_lookup(&lmv->lmv_fld, fid_seq(fid), mds,
			       LU_SEQ_RANGE_MDT, NULL);
	if (rc) {
		CERROR("%s: Error while looking for mds number. Seq %#llx: rc = %d\n",
		       obd->obd_name, fid_seq(fid), rc);
		RETURN(rc);
	}

	CDEBUG(D_INODE, "FLD lookup got mds #%x for fid="DFID"\n",
	       *mds, PFID(fid));

	if (*mds >= lmv->lmv_mdt_descs.ltd_tgts_size) {
		rc = -EINVAL;
		CERROR("%s: FLD lookup got invalid mds #%x (max: %x) for fid="DFID": rc = %d\n",
		       obd->obd_name, *mds, lmv->lmv_mdt_descs.ltd_tgts_size,
		       PFID(fid), rc);
	}
	RETURN(rc);
}
