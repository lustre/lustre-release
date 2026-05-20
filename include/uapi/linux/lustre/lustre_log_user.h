/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Userspace-usable portion of Generic infrastructure for managing
 * a collection of logs.
 * See lustre_log.h for more details.
 */

#ifndef _LUSTRE_LOG_USER_H
#define _LUSTRE_LOG_USER_H

#include <linux/types.h>
#include <linux/lustre/lustre_fid.h>

/*  Lustre logs use FIDs constructed from oi_id and oi_seq directly,
 *  without attempting to use the IGIF and IDIF ranges as is done
 *  elsewhere, because of compatibility concerns (see lu-2888).
 */

static inline void logid_to_fid(struct llog_logid *id, struct lu_fid *fid)
{
	/* For compatibility purposes we identify pre-OSD (~< 2.3.51 MDS)
	 * logid's by non-zero ogen (inode generation) and convert them
	 * into IGIF
	 */
	if (id->lgl_ogen == 0) {
		fid->f_seq = id->lgl_oi.oi.oi_seq;
		fid->f_oid = id->lgl_oi.oi.oi_id;
		fid->f_ver = 0;
	} else {
		lu_igif_build(fid, id->lgl_oi.oi.oi_id, id->lgl_ogen);
	}
}

static inline void fid_to_logid(struct lu_fid *fid, struct llog_logid *id)
{
	id->lgl_oi.oi.oi_seq = fid->f_seq;
	id->lgl_oi.oi.oi_id = fid->f_oid;
	id->lgl_ogen = 0;
}

static inline void logid_set_id(struct llog_logid *log_id, __u64 id)
{
	log_id->lgl_oi.oi.oi_id = id;
}

static inline __u64 logid_id(struct llog_logid *log_id)
{
	return log_id->lgl_oi.oi.oi_id;
}

#endif /* ifndef _LUSTRE_LOG_USER_H */
