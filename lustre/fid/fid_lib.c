// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Miscellaneous fid functions.
 *
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_FID

#include <libcfs/libcfs.h>
#include <linux/module.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_fid.h>

#include "fid_internal.h"

/**
 * A cluster-wide range from which fid-sequences are granted to servers and
 * then clients.
 *
 * Fid namespace:
 * <pre>
 * Normal FID:        seq:64 [2^33,2^64-1]      oid:32          ver:32
 * IGIF      :        0:32, ino:32              gen:32          0:32
 * IDIF      :        0:31, 1:1, ost-index:16,  objd:48         0:32
 * </pre>
 *
 * The first 0x400 sequences of normal FID are reserved for special purpose.
 * FID_SEQ_START + 1 is for local file id generation.
 * FID_SEQ_START + 2 is for .lustre directory and its objects
 */
const struct lu_seq_range LUSTRE_SEQ_SPACE_RANGE = {
	.lsr_start	= FID_SEQ_NORMAL,
	.lsr_end	= (__u64)~0ULL,
};

/* Zero range, used for init and other purposes. */
const struct lu_seq_range LUSTRE_SEQ_ZERO_RANGE = {
	.lsr_start = 0,
};

/* Lustre Big Fs Lock fid. */
const struct lu_fid LUSTRE_BFL_FID = { .f_seq = FID_SEQ_SPECIAL,
				       .f_oid = FID_OID_SPECIAL_BFL,
				       .f_ver = 0x0000000000000000 };
EXPORT_SYMBOL(LUSTRE_BFL_FID);

/** Special fid for "lost+found" special object in .lustre */
const struct lu_fid LU_LPF_FID = { .f_seq = FID_SEQ_DOT_LUSTRE,
				   .f_oid = FID_OID_DOT_LUSTRE_LPF,
				   .f_ver = 0x0000000000000000 };
EXPORT_SYMBOL(LU_LPF_FID);

/** "/lost+found" - special FID for ldiskfs backend, invislbe to client. */
const struct lu_fid LU_BACKEND_LPF_FID = { .f_seq = FID_SEQ_LOCAL_FILE,
					   .f_oid = OSD_LPF_OID,
					   .f_ver = 0x0000000000000000 };
EXPORT_SYMBOL(LU_BACKEND_LPF_FID);

int fid_alloc_generic(const struct lu_env *env, struct lu_device *lu,
		      struct lu_fid *fid, struct lu_object *parent,
		      const struct lu_name *name)
{
	struct dt_device *dt = container_of(lu, struct dt_device,
					    dd_lu_dev);

	return seq_client_alloc_fid(env, dt->dd_cl_seq, fid);
}
EXPORT_SYMBOL(fid_alloc_generic);

int seq_target_init(const struct lu_env *env,
		    struct dt_device *dt, char *svname,
		    bool is_ost)
{
	struct seq_server_site *ss = dt->dd_lu_dev.ld_site->ld_seq_site;
	int rc = 0;

	if (is_ost || dt->dd_cl_seq != NULL)
		return 0;

	if (unlikely(!ss))
		return -ENODEV;

	OBD_ALLOC_PTR(dt->dd_cl_seq);
	if (!dt->dd_cl_seq)
		return -ENOMEM;

	seq_client_init(dt->dd_cl_seq, NULL, LUSTRE_SEQ_METADATA,
			svname, ss->ss_server_seq);

	/*
	 * If the OSD on the sequence controller(MDT0), then allocate
	 * sequence here, otherwise allocate sequence after connected
	 * to MDT0 (see mdt_register_lwp_callback()).
	 */
	if (!ss->ss_node_id)
		rc = seq_server_alloc_meta(dt->dd_cl_seq->lcs_srv,
				   &dt->dd_cl_seq->lcs_space, env);

	return rc;
}
EXPORT_SYMBOL(seq_target_init);

void seq_target_fini(const struct lu_env *env,
		     struct dt_device *dt)
{
	if (!dt->dd_cl_seq)
		return;

	seq_client_fini(dt->dd_cl_seq);
	OBD_FREE_PTR(dt->dd_cl_seq);
	dt->dd_cl_seq = NULL;
}
EXPORT_SYMBOL(seq_target_fini);
