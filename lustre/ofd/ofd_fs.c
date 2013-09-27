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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_fs.c
 *
 * Author: Alexey Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

int ofd_record_write(const struct lu_env *env, struct ofd_device *ofd,
		     struct dt_object *dt, struct lu_buf *buf, loff_t *off)
{
	struct thandle	*th;
	int		 rc;

	ENTRY;

	LASSERT(dt);

	th = dt_trans_create(env, ofd->ofd_osd);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, dt, buf->lb_len, *off, th);
	if (rc == 0) {
		rc = dt_trans_start_local(env, ofd->ofd_osd, th);
		if (rc == 0)
			rc = dt_record_write(env, dt, buf, off, th);
	}
	dt_trans_stop(env, ofd->ofd_osd, th);

	RETURN(rc);
}

int ofd_precreate_batch(struct ofd_device *ofd, int batch)
{
	int count;

	spin_lock(&ofd->ofd_batch_lock);
	count = min(ofd->ofd_precreate_batch, batch);
	spin_unlock(&ofd->ofd_batch_lock);

	return count;
}

struct ofd_seq *ofd_seq_get(struct ofd_device *ofd, obd_seq seq)
{
	struct ofd_seq *oseq;

	read_lock(&ofd->ofd_seq_list_lock);
	cfs_list_for_each_entry(oseq, &ofd->ofd_seq_list, os_list) {
		if (ostid_seq(&oseq->os_oi) == seq) {
			cfs_atomic_inc(&oseq->os_refc);
			read_unlock(&ofd->ofd_seq_list_lock);
			return oseq;
		}
	}
	read_unlock(&ofd->ofd_seq_list_lock);
	return NULL;
}

static void ofd_seq_destroy(const struct lu_env *env,
			    struct ofd_seq *oseq)
{
	LASSERT(cfs_list_empty(&oseq->os_list));
	LASSERT(oseq->os_lastid_obj != NULL);
	lu_object_put(env, &oseq->os_lastid_obj->do_lu);
	OBD_FREE_PTR(oseq);
}

void ofd_seq_put(const struct lu_env *env, struct ofd_seq *oseq)
{
	if (cfs_atomic_dec_and_test(&oseq->os_refc))
		ofd_seq_destroy(env, oseq);
}

static void ofd_seq_delete(const struct lu_env *env, struct ofd_seq *oseq)
{
	cfs_list_del_init(&oseq->os_list);
	ofd_seq_put(env, oseq);
}

/**
 * Add a new sequence to the OFD device.
 *
 * \param ofd OFD device
 * \param new_seq new sequence to be added
 *
 * \retval the seq to be added or the existing seq
 **/
static struct ofd_seq *ofd_seq_add(const struct lu_env *env,
				   struct ofd_device *ofd,
				   struct ofd_seq *new_seq)
{
	struct ofd_seq *os = NULL;

	write_lock(&ofd->ofd_seq_list_lock);
	cfs_list_for_each_entry(os, &ofd->ofd_seq_list, os_list) {
		if (ostid_seq(&os->os_oi) == ostid_seq(&new_seq->os_oi)) {
			cfs_atomic_inc(&os->os_refc);
			write_unlock(&ofd->ofd_seq_list_lock);
			/* The seq has not been added to the list */
			ofd_seq_put(env, new_seq);
			return os;
		}
	}
	cfs_atomic_inc(&new_seq->os_refc);
	cfs_list_add_tail(&new_seq->os_list, &ofd->ofd_seq_list);
	ofd->ofd_seq_count++;
	write_unlock(&ofd->ofd_seq_list_lock);
	return new_seq;
}

obd_id ofd_seq_last_oid(struct ofd_seq *oseq)
{
	obd_id id;

	spin_lock(&oseq->os_last_oid_lock);
	id = ostid_id(&oseq->os_oi);
	spin_unlock(&oseq->os_last_oid_lock);

	return id;
}

void ofd_seq_last_oid_set(struct ofd_seq *oseq, obd_id id)
{
	spin_lock(&oseq->os_last_oid_lock);
	if (likely(ostid_id(&oseq->os_oi) < id))
		ostid_set_id(&oseq->os_oi, id);
	spin_unlock(&oseq->os_last_oid_lock);
}

int ofd_seq_last_oid_write(const struct lu_env *env, struct ofd_device *ofd,
			   struct ofd_seq *oseq)
{
	struct ofd_thread_info	*info = ofd_info(env);
	obd_id			 tmp;
	int			 rc;

	ENTRY;

	tmp = cpu_to_le64(ofd_seq_last_oid(oseq));

	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	rc = ofd_record_write(env, ofd, oseq->os_lastid_obj, &info->fti_buf,
			      &info->fti_off);

	CDEBUG(D_INODE, "%s: write last_objid "DOSTID": rc = %d\n",
	       ofd_name(ofd), POSTID(&oseq->os_oi), rc);

	RETURN(rc);
}

static void ofd_deregister_seq_exp(struct ofd_device *ofd)
{
	struct seq_server_site	*ss = &ofd->ofd_seq_site;

	if (ss->ss_client_seq != NULL) {
		lustre_deregister_lwp_item(&ss->ss_client_seq->lcs_exp);
		ss->ss_client_seq->lcs_exp = NULL;
	}

	if (ss->ss_server_fld != NULL) {
		lustre_deregister_lwp_item(&ss->ss_server_fld->lsf_control_exp);
		ss->ss_server_fld->lsf_control_exp = NULL;
	}
}

static int ofd_fld_fini(const struct lu_env *env,
			struct ofd_device *ofd)
{
	struct seq_server_site *ss = &ofd->ofd_seq_site;
	ENTRY;

	if (ss && ss->ss_server_fld) {
		fld_server_fini(env, ss->ss_server_fld);
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
	}

	RETURN(0);
}

void ofd_seqs_fini(const struct lu_env *env, struct ofd_device *ofd)
{
	struct ofd_seq  *oseq;
	struct ofd_seq  *tmp;
	cfs_list_t       dispose;
	int		rc;

	ofd_deregister_seq_exp(ofd);

	rc = ofd_fid_fini(env, ofd);
	if (rc != 0)
		CERROR("%s: fid fini error: rc = %d\n", ofd_name(ofd), rc);

	rc = ofd_fld_fini(env, ofd);
	if (rc != 0)
		CERROR("%s: fld fini error: rc = %d\n", ofd_name(ofd), rc);

	CFS_INIT_LIST_HEAD(&dispose);
	write_lock(&ofd->ofd_seq_list_lock);
	cfs_list_for_each_entry_safe(oseq, tmp, &ofd->ofd_seq_list, os_list) {
		cfs_list_move(&oseq->os_list, &dispose);
	}
	write_unlock(&ofd->ofd_seq_list_lock);

	while (!cfs_list_empty(&dispose)) {
		oseq = container_of0(dispose.next, struct ofd_seq, os_list);
		ofd_seq_delete(env, oseq);
	}

	LASSERT(cfs_list_empty(&ofd->ofd_seq_list));
	return;
}

/**
 *
 * \retval the seq with seq number or errno (never NULL)
 */
struct ofd_seq *ofd_seq_load(const struct lu_env *env, struct ofd_device *ofd,
			     obd_seq seq)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_seq		*oseq = NULL;
	struct dt_object	*dob;
	obd_id			 lastid;
	int			 rc;

	ENTRY;

	/* if seq is already initialized */
	oseq = ofd_seq_get(ofd, seq);
	if (oseq != NULL)
		RETURN(oseq);

	OBD_ALLOC_PTR(oseq);
	if (oseq == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	lu_last_id_fid(&info->fti_fid, seq);
	memset(&info->fti_attr, 0, sizeof(info->fti_attr));
	info->fti_attr.la_valid = LA_MODE;
	info->fti_attr.la_mode = S_IFREG |  S_IRUGO | S_IWUSR;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	/* create object tracking per-seq last created
	 * id to be used by orphan recovery mechanism */
	dob = dt_find_or_create(env, ofd->ofd_osd, &info->fti_fid,
				&info->fti_dof, &info->fti_attr);
	if (IS_ERR(dob)) {
		OBD_FREE_PTR(oseq);
		RETURN((void *)dob);
	}

	oseq->os_lastid_obj = dob;

	CFS_INIT_LIST_HEAD(&oseq->os_list);
	mutex_init(&oseq->os_create_lock);
	spin_lock_init(&oseq->os_last_oid_lock);
	ostid_set_seq(&oseq->os_oi, seq);

	cfs_atomic_set(&oseq->os_refc, 1);

	rc = dt_attr_get(env, dob, &info->fti_attr, BYPASS_CAPA);
	if (rc)
		GOTO(cleanup, rc);

	if (info->fti_attr.la_size == 0) {
		/* object is just created, initialize last id */
		ofd_seq_last_oid_set(oseq, OFD_INIT_OBJID);
		ofd_seq_last_oid_write(env, ofd, oseq);
	} else if (info->fti_attr.la_size == sizeof(lastid)) {
		info->fti_off = 0;
		info->fti_buf.lb_buf = &lastid;
		info->fti_buf.lb_len = sizeof(lastid);

		rc = dt_record_read(env, dob, &info->fti_buf, &info->fti_off);
		if (rc) {
			CERROR("%s: can't read last_id: rc = %d\n",
				ofd_name(ofd), rc);
			GOTO(cleanup, rc);
		}
		ofd_seq_last_oid_set(oseq, le64_to_cpu(lastid));
	} else {
		CERROR("%s: corrupted size "LPU64" LAST_ID of seq "LPX64"\n",
			ofd_name(ofd), (__u64)info->fti_attr.la_size, seq);
		GOTO(cleanup, rc = -EINVAL);
	}

	oseq = ofd_seq_add(env, ofd, oseq);
	RETURN((oseq != NULL) ? oseq : ERR_PTR(-ENOENT));
cleanup:
	ofd_seq_put(env, oseq);
	return ERR_PTR(rc);
}

static int ofd_fld_init(const struct lu_env *env, const char *uuid,
			struct ofd_device *ofd)
{
	struct seq_server_site *ss = &ofd->ofd_seq_site;
	int rc;
	ENTRY;

	OBD_ALLOC_PTR(ss->ss_server_fld);
	if (ss->ss_server_fld == NULL)
		RETURN(rc = -ENOMEM);

	rc = fld_server_init(env, ss->ss_server_fld, ofd->ofd_osd, uuid,
			     ss->ss_node_id, LU_SEQ_RANGE_OST);
	if (rc) {
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
		RETURN(rc);
	}
	RETURN(0);
}

static int ofd_register_seq_exp(struct ofd_device *ofd)
{
	struct seq_server_site	*ss = &ofd->ofd_seq_site;
	char			*lwp_name = NULL;
	int			rc;

	OBD_ALLOC(lwp_name, MAX_OBD_NAME);
	if (lwp_name == NULL)
		GOTO(out_free, rc = -ENOMEM);

	rc = tgt_name2lwpname(ofd_name(ofd), lwp_name);
	if (rc != 0)
		GOTO(out_free, rc);

	rc = lustre_register_lwp_item(lwp_name, &ss->ss_client_seq->lcs_exp,
				      NULL, NULL);
	if (rc != 0)
		GOTO(out_free, rc);

	rc = lustre_register_lwp_item(lwp_name,
				      &ss->ss_server_fld->lsf_control_exp,
				      NULL, NULL);
	if (rc != 0) {
		lustre_deregister_lwp_item(&ss->ss_client_seq->lcs_exp);
		ss->ss_client_seq->lcs_exp = NULL;
		GOTO(out_free, rc);
	}
out_free:
	if (lwp_name != NULL)
		OBD_FREE(lwp_name, MAX_OBD_NAME);

	return rc;
}

/* object sequence management */
int ofd_seqs_init(const struct lu_env *env, struct ofd_device *ofd)
{
	int rc;

	rc = ofd_fid_init(env, ofd);
	if (rc != 0) {
		CERROR("%s: fid init error: rc = %d\n", ofd_name(ofd), rc);
		return rc;
	}

	rc = ofd_fld_init(env, ofd_name(ofd), ofd);
	if (rc) {
		CERROR("%s: Can't init fld, rc %d\n", ofd_name(ofd), rc);
		return rc;
	}

	rc = ofd_register_seq_exp(ofd);
	if (rc) {
		CERROR("%s: Can't init seq exp, rc %d\n", ofd_name(ofd), rc);
		return rc;
	}

	rwlock_init(&ofd->ofd_seq_list_lock);
	CFS_INIT_LIST_HEAD(&ofd->ofd_seq_list);
	ofd->ofd_seq_count = 0;
	return rc;
}

int ofd_clients_data_init(const struct lu_env *env, struct ofd_device *ofd,
			  unsigned long fsize)
{
	struct obd_device		*obd = ofd_obd(ofd);
	struct lr_server_data	 	*lsd = &ofd->ofd_lut.lut_lsd;
	struct lsd_client_data		*lcd = NULL;
	struct filter_export_data	*fed;
	int				 cl_idx;
	int				 rc = 0;
	loff_t				 off = lsd->lsd_client_start;

	CLASSERT(offsetof(struct lsd_client_data, lcd_padding) +
		 sizeof(lcd->lcd_padding) == LR_CLIENT_SIZE);

	OBD_ALLOC_PTR(lcd);
	if (lcd == NULL)
		RETURN(-ENOMEM);

	for (cl_idx = 0; off < fsize; cl_idx++) {
		struct obd_export	*exp;
		__u64			 last_rcvd;

		/* Don't assume off is incremented properly by
		 * read_record(), in case sizeof(*lcd)
		 * isn't the same as fsd->lsd_client_size.  */
		off = lsd->lsd_client_start + cl_idx * lsd->lsd_client_size;
		rc = tgt_client_data_read(env, &ofd->ofd_lut, lcd, &off, cl_idx);
		if (rc) {
			CERROR("%s: error reading FILT %s idx %d off %llu: "
			       "rc = %d\n", ofd_name(ofd), LAST_RCVD, cl_idx,
			       off, rc);
			rc = 0;
			break; /* read error shouldn't cause startup to fail */
		}

		if (lcd->lcd_uuid[0] == '\0') {
			CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
			       cl_idx);
			continue;
		}

		last_rcvd = lcd->lcd_last_transno;

		/* These exports are cleaned up by ofd_disconnect(), so they
		 * need to be set up like real exports as ofd_connect() does.
		 */
		exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);

		CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
		       " srv lr: "LPU64"\n", lcd->lcd_uuid, cl_idx,
		       last_rcvd, lsd->lsd_last_transno);

		if (IS_ERR(exp)) {
			if (PTR_ERR(exp) == -EALREADY) {
				/* export already exists, zero out this one */
				CERROR("%s: Duplicate export %s!\n",
				       ofd_name(ofd), lcd->lcd_uuid);
				continue;
			}
			GOTO(err_out, rc = PTR_ERR(exp));
		}

		fed = &exp->exp_filter_data;
		*fed->fed_ted.ted_lcd = *lcd;

		rc = tgt_client_add(env, exp, cl_idx);
		LASSERTF(rc == 0, "rc = %d\n", rc); /* can't fail existing */
		/* VBR: set export last committed version */
		exp->exp_last_committed = last_rcvd;
		spin_lock(&exp->exp_lock);
		exp->exp_connecting = 0;
		exp->exp_in_recovery = 0;
		spin_unlock(&exp->exp_lock);
		obd->obd_max_recoverable_clients++;
		class_export_put(exp);

		/* Need to check last_rcvd even for duplicated exports. */
		CDEBUG(D_OTHER, "client at idx %d has last_rcvd = "LPU64"\n",
		       cl_idx, last_rcvd);

		spin_lock(&ofd->ofd_lut.lut_translock);
		if (last_rcvd > lsd->lsd_last_transno)
			lsd->lsd_last_transno = last_rcvd;
		spin_unlock(&ofd->ofd_lut.lut_translock);
	}

err_out:
	OBD_FREE_PTR(lcd);
	RETURN(rc);
}

int ofd_server_data_init(const struct lu_env *env, struct ofd_device *ofd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct lr_server_data	*lsd = &ofd->ofd_lut.lut_lsd;
	struct obd_device	*obd = ofd_obd(ofd);
	unsigned long		last_rcvd_size;
	__u32			index;
	int			rc;

	rc = dt_attr_get(env, ofd->ofd_lut.lut_last_rcvd, &info->fti_attr,
			 BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	last_rcvd_size = (unsigned long)info->fti_attr.la_size;

	/* ensure padding in the struct is the correct size */
	CLASSERT (offsetof(struct lr_server_data, lsd_padding) +
		  sizeof(lsd->lsd_padding) == LR_SERVER_SIZE);

	rc = server_name2index(obd->obd_name, &index, NULL);
	if (rc < 0) {
		CERROR("%s: Can not get index from obd_name: rc = %d\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	if (last_rcvd_size == 0) {
		LCONSOLE_WARN("%s: new disk, initializing\n", obd->obd_name);

		memcpy(lsd->lsd_uuid, obd->obd_uuid.uuid,
		       sizeof(lsd->lsd_uuid));
		lsd->lsd_last_transno = 0;
		lsd->lsd_mount_count = 0;
		lsd->lsd_server_size = LR_SERVER_SIZE;
		lsd->lsd_client_start = LR_CLIENT_START;
		lsd->lsd_client_size = LR_CLIENT_SIZE;
		lsd->lsd_subdir_count = FILTER_SUBDIR_COUNT;
		lsd->lsd_feature_incompat = OBD_INCOMPAT_OST;
		lsd->lsd_osd_index = index;
	} else {
		rc = tgt_server_data_read(env, &ofd->ofd_lut);
		if (rc) {
			CDEBUG(D_INODE,"OBD ofd: error reading %s: rc %d\n",
			       LAST_RCVD, rc);
			GOTO(err_fsd, rc);
		}
		if (strcmp((char *)lsd->lsd_uuid,
			   (char *)obd->obd_uuid.uuid)) {
			LCONSOLE_ERROR("Trying to start OBD %s using the wrong"
				       " disk %s. Were the /dev/ assignments "
				       "rearranged?\n",
				       obd->obd_uuid.uuid, lsd->lsd_uuid);
			GOTO(err_fsd, rc = -EINVAL);
		}

		if (lsd->lsd_osd_index == 0) {
			lsd->lsd_osd_index = index;
		} else if (lsd->lsd_osd_index != index) {
			LCONSOLE_ERROR("%s: index %d in last rcvd is different"
				       " with the index %d in config log."
				       " It might be disk corruption!\n",
				       obd->obd_name, lsd->lsd_osd_index,
				       index);
			GOTO(err_fsd, rc = -EINVAL);
		}
	}

	lsd->lsd_mount_count++;
	obd->u.obt.obt_mount_count = lsd->lsd_mount_count;
	obd->u.obt.obt_instance = (__u32)obd->u.obt.obt_mount_count;
	ofd->ofd_subdir_count = lsd->lsd_subdir_count;

	if (lsd->lsd_feature_incompat & ~OFD_INCOMPAT_SUPP) {
		CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
		       obd->obd_name,
		       lsd->lsd_feature_incompat & ~OFD_INCOMPAT_SUPP);
		GOTO(err_fsd, rc = -EINVAL);
	}
	if (lsd->lsd_feature_rocompat & ~OFD_ROCOMPAT_SUPP) {
		CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
		       obd->obd_name,
		       lsd->lsd_feature_rocompat & ~OFD_ROCOMPAT_SUPP);
		/* Do something like remount filesystem read-only */
		GOTO(err_fsd, rc = -EINVAL);
	}

	CDEBUG(D_INODE, "%s: server last_transno : "LPU64"\n",
	       obd->obd_name, lsd->lsd_last_transno);
	CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
	       obd->obd_name, lsd->lsd_mount_count);
	CDEBUG(D_INODE, "%s: server data size: %u\n",
	       obd->obd_name, lsd->lsd_server_size);
	CDEBUG(D_INODE, "%s: per-client data start: %u\n",
	       obd->obd_name, lsd->lsd_client_start);
	CDEBUG(D_INODE, "%s: per-client data size: %u\n",
	       obd->obd_name, lsd->lsd_client_size);
	CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
	       obd->obd_name, lsd->lsd_subdir_count);
	CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
	       last_rcvd_size <= lsd->lsd_client_start ? 0 :
	       (last_rcvd_size - lsd->lsd_client_start) /
	       lsd->lsd_client_size);

	if (!obd->obd_replayable)
		CWARN("%s: recovery support OFF\n", obd->obd_name);

	rc = ofd_clients_data_init(env, ofd, last_rcvd_size);

	spin_lock(&ofd->ofd_lut.lut_translock);
	obd->obd_last_committed = lsd->lsd_last_transno;
	ofd->ofd_lut.lut_last_transno = lsd->lsd_last_transno;
	spin_unlock(&ofd->ofd_lut.lut_translock);

	/* save it, so mount count and last_transno is current */
	rc = tgt_server_data_update(env, &ofd->ofd_lut, 0);
	if (rc)
		GOTO(err_fsd, rc);

	RETURN(0);

err_fsd:
	class_disconnect_exports(obd);
	RETURN(rc);
}

int ofd_fs_setup(const struct lu_env *env, struct ofd_device *ofd,
		 struct obd_device *obd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct dt_object	*fo;
	int			 rc = 0;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
		RETURN (-ENOENT);

	/* prepare transactions callbacks */
	ofd->ofd_txn_cb.dtc_txn_start = NULL;
	ofd->ofd_txn_cb.dtc_txn_stop = ofd_txn_stop_cb;
	ofd->ofd_txn_cb.dtc_txn_commit = NULL;
	ofd->ofd_txn_cb.dtc_cookie = ofd;
	ofd->ofd_txn_cb.dtc_tag = LCT_DT_THREAD;
	CFS_INIT_LIST_HEAD(&ofd->ofd_txn_cb.dtc_linkage);

	dt_txn_callback_add(ofd->ofd_osd, &ofd->ofd_txn_cb);

	rc = ofd_server_data_init(env, ofd);
	if (rc)
		GOTO(out, rc);

	lu_local_obj_fid(&info->fti_fid, OFD_HEALTH_CHECK_OID);
	memset(&info->fti_attr, 0, sizeof(info->fti_attr));
	info->fti_attr.la_valid = LA_MODE;
	info->fti_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	fo = dt_find_or_create(env, ofd->ofd_osd, &info->fti_fid,
			       &info->fti_dof, &info->fti_attr);
	if (IS_ERR(fo))
		GOTO(out, rc = PTR_ERR(fo));

	ofd->ofd_health_check_file = fo;

	rc = ofd_seqs_init(env, ofd);
	if (rc)
		GOTO(out_hc, rc);

	RETURN(0);
out_hc:
	lu_object_put(env, &ofd->ofd_health_check_file->do_lu);
out:
	dt_txn_callback_del(ofd->ofd_osd, &ofd->ofd_txn_cb);
	return rc;
}

void ofd_fs_cleanup(const struct lu_env *env, struct ofd_device *ofd)
{
	int i;

	ENTRY;

	ofd_info_init(env, NULL);

	ofd_seqs_fini(env, ofd);

	i = dt_sync(env, ofd->ofd_osd);
	if (i)
		CERROR("can't sync: %d\n", i);

	/* Remove transaction callback */
	dt_txn_callback_del(ofd->ofd_osd, &ofd->ofd_txn_cb);

	if (ofd->ofd_health_check_file) {
		lu_object_put(env, &ofd->ofd_health_check_file->do_lu);
		ofd->ofd_health_check_file = NULL;
	}

	EXIT;
}

