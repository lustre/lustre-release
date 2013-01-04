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
 * Copyright (c) 2012, Intel Corporation.
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

	spin_lock(&ofd->ofd_objid_lock);
	count = min(ofd->ofd_precreate_batch, batch);
	spin_unlock(&ofd->ofd_objid_lock);

	return count;
}

obd_id ofd_last_id(struct ofd_device *ofd, obd_seq group)
{
	obd_id id;

	LASSERT(group <= ofd->ofd_max_group);

	spin_lock(&ofd->ofd_objid_lock);
	id = ofd->ofd_last_objids[group];
	spin_unlock(&ofd->ofd_objid_lock);

	return id;
}

void ofd_last_id_set(struct ofd_device *ofd, obd_id id, obd_seq group)
{
	LASSERT(group <= ofd->ofd_max_group);
	spin_lock(&ofd->ofd_objid_lock);
	if (ofd->ofd_last_objids[group] < id)
		ofd->ofd_last_objids[group] = id;
	spin_unlock(&ofd->ofd_objid_lock);
}

int ofd_last_id_write(const struct lu_env *env, struct ofd_device *ofd,
		      obd_seq group)
{
	struct ofd_thread_info	*info = ofd_info(env);
	obd_id			 tmp;
	int			 rc;

	ENTRY;

	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	CDEBUG(D_INODE, "%s: write last_objid for group "LPU64": "LPU64"\n",
	       ofd_obd(ofd)->obd_name, group, ofd_last_id(ofd, group));

	tmp = cpu_to_le64(ofd_last_id(ofd, group));

	rc = ofd_record_write(env, ofd, ofd->ofd_lastid_obj[group],
			      &info->fti_buf, &info->fti_off);
	RETURN(rc);
}

int ofd_last_group_write(const struct lu_env *env, struct ofd_device *ofd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	obd_seq			 tmp;
	int			 rc;

	ENTRY;

	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	tmp = cpu_to_le32(ofd->ofd_max_group);

	rc = ofd_record_write(env, ofd, ofd->ofd_last_group_file,
			      &info->fti_buf, &info->fti_off);

	RETURN(rc);
}

void ofd_group_fini(const struct lu_env *env, struct ofd_device *ofd,
		    int group)
{
	LASSERT(ofd->ofd_lastid_obj[group]);
	lu_object_put(env, &ofd->ofd_lastid_obj[group]->do_lu);
	ofd->ofd_lastid_obj[group] = NULL;
}

int ofd_group_load(const struct lu_env *env, struct ofd_device *ofd, int group)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct dt_object	*dob;
	obd_id			 lastid;
	int			 rc;

	ENTRY;

	/* if group is already initialized */
	if (ofd->ofd_lastid_obj[group])
		RETURN(0);

	lu_local_obj_fid(&info->fti_fid, OFD_GROUP0_LAST_OID + group);
	memset(&info->fti_attr, 0, sizeof(info->fti_attr));
	info->fti_attr.la_valid = LA_MODE;
	info->fti_attr.la_mode = S_IFREG |  S_IRUGO | S_IWUSR;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	/* create object tracking per-group last created
	 * id to be used by orphan recovery mechanism */
	dob = dt_find_or_create(env, ofd->ofd_osd, &info->fti_fid,
				&info->fti_dof, &info->fti_attr);
	if (IS_ERR(dob))
		RETURN(PTR_ERR(dob));

	ofd->ofd_lastid_obj[group] = dob;
	mutex_init(&ofd->ofd_create_locks[group]);

	rc = dt_attr_get(env, dob, &info->fti_attr, BYPASS_CAPA);
	if (rc)
		GOTO(cleanup, rc);

	if (info->fti_attr.la_size == 0) {
		/* object is just created, initialize last id */
		ofd->ofd_last_objids[group] = OFD_INIT_OBJID;
		ofd_last_id_set(ofd, OFD_INIT_OBJID, group);
		ofd_last_id_write(env, ofd, group);
		ofd_last_group_write(env, ofd);
	} else if (info->fti_attr.la_size == sizeof(lastid)) {
		info->fti_off = 0;
		info->fti_buf.lb_buf = &lastid;
		info->fti_buf.lb_len = sizeof(lastid);

		rc = dt_record_read(env, dob, &info->fti_buf, &info->fti_off);
		if (rc) {
			CERROR("can't read last_id: %d\n", rc);
			GOTO(cleanup, rc);
		}
		ofd->ofd_last_objids[group] = le64_to_cpu(lastid);
	} else {
		CERROR("corrupted size %Lu LAST_ID of group %u\n",
		       (unsigned long long)info->fti_attr.la_size, group);
		rc = -EINVAL;
	}

	RETURN(0);
cleanup:
	ofd_group_fini(env, ofd, group);
	RETURN(rc);
}

/* ofd groups managements */
int ofd_groups_init(const struct lu_env *env, struct ofd_device *ofd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	unsigned long		 groups_size;
	obd_seq			 last_group;
	int			 rc = 0;
	int			 i;

	ENTRY;

	spin_lock_init(&ofd->ofd_objid_lock);

	rc = dt_attr_get(env, ofd->ofd_last_group_file,
			 &info->fti_attr, BYPASS_CAPA);
	if (rc)
		GOTO(cleanup, rc);

	groups_size = (unsigned long)info->fti_attr.la_size;

	if (groups_size == sizeof(last_group)) {
		info->fti_off = 0;
		info->fti_buf.lb_buf = &last_group;
		info->fti_buf.lb_len = sizeof(last_group);

		rc = dt_record_read(env, ofd->ofd_last_group_file,
				    &info->fti_buf, &info->fti_off);
		if (rc) {
			CERROR("can't read LAST_GROUP: %d\n", rc);
			GOTO(cleanup, rc);
		}

		ofd->ofd_max_group = le32_to_cpu(last_group);
		LASSERT(ofd->ofd_max_group <= OFD_MAX_GROUPS);
	} else if (groups_size == 0) {
		ofd->ofd_max_group = 0;
	} else {
		CERROR("groups file is corrupted? size = %lu\n", groups_size);
		GOTO(cleanup, rc = -EIO);
	}

	for (i = 0; i <= ofd->ofd_max_group; i++) {
		rc = ofd_group_load(env, ofd, i);
		if (rc) {
			CERROR("can't load group %d: %d\n", i, rc);
			/* Clean all previously set groups */
			while (i > 0)
				ofd_group_fini(env, ofd, --i);
			GOTO(cleanup, rc);
		}
	}

	CDEBUG(D_OTHER, "%s: %u groups initialized\n",
	      ofd_obd(ofd)->obd_name, ofd->ofd_max_group + 1);
cleanup:
	RETURN(rc);
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
		 * fsfilt_read_record(), in case sizeof(*lcd)
		 * isn't the same as fsd->lsd_client_size.  */
		off = lsd->lsd_client_start + cl_idx * lsd->lsd_client_size;
		rc = tgt_client_data_read(env, &ofd->ofd_lut, lcd, &off, cl_idx);
		if (rc) {
			CERROR("error reading FILT %s idx %d off %llu: rc %d\n",
			       LAST_RCVD, cl_idx, off, rc);
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
				CERROR("Duplicate export %s!\n", lcd->lcd_uuid);
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
	unsigned long		 last_rcvd_size;
	int			 rc;

	rc = dt_attr_get(env, ofd->ofd_lut.lut_last_rcvd, &info->fti_attr,
			 BYPASS_CAPA);
	if (rc)
		RETURN(rc);

	last_rcvd_size = (unsigned long)info->fti_attr.la_size;

	/* ensure padding in the struct is the correct size */
	CLASSERT (offsetof(struct lr_server_data, lsd_padding) +
		  sizeof(lsd->lsd_padding) == LR_SERVER_SIZE);

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

	lu_local_obj_fid(&info->fti_fid, OFD_LAST_GROUP_OID);
	memset(&info->fti_attr, 0, sizeof(info->fti_attr));
	info->fti_attr.la_valid = LA_MODE;
	info->fti_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	fo = dt_find_or_create(env, ofd->ofd_osd, &info->fti_fid,
			       &info->fti_dof, &info->fti_attr);
	if (IS_ERR(fo))
		GOTO(out_hc, rc = PTR_ERR(fo));

	ofd->ofd_last_group_file = fo;

	rc = ofd_groups_init(env, ofd);
	if (rc)
		GOTO(out_lg, rc);

	RETURN(0);
out_lg:
	lu_object_put(env, &ofd->ofd_last_group_file->do_lu);
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

	for (i = 0; i <= ofd->ofd_max_group; i++) {
		if (ofd->ofd_lastid_obj[i]) {
			ofd_last_id_write(env, ofd, i);
			ofd_group_fini(env, ofd, i);
		}
	}

	i = dt_sync(env, ofd->ofd_osd);
	if (i)
		CERROR("can't sync: %d\n", i);

	/* Remove transaction callback */
	dt_txn_callback_del(ofd->ofd_osd, &ofd->ofd_txn_cb);

	if (ofd->ofd_last_group_file) {
		lu_object_put(env, &ofd->ofd_last_group_file->do_lu);
		ofd->ofd_last_group_file = NULL;
	}

	if (ofd->ofd_health_check_file) {
		lu_object_put(env, &ofd->ofd_health_check_file->do_lu);
		ofd->ofd_health_check_file = NULL;
	}

	EXIT;
}

