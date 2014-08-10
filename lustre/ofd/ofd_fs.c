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

	rc = dt_declare_record_write(env, dt, buf, *off, th);
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
			atomic_inc(&oseq->os_refc);
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
	if (atomic_dec_and_test(&oseq->os_refc))
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
			atomic_inc(&os->os_refc);
			write_unlock(&ofd->ofd_seq_list_lock);
			/* The seq has not been added to the list */
			ofd_seq_put(env, new_seq);
			return os;
		}
	}
	atomic_inc(&new_seq->os_refc);
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

void ofd_seqs_free(const struct lu_env *env, struct ofd_device *ofd)
{
	struct ofd_seq  *oseq;
	struct ofd_seq  *tmp;
	cfs_list_t       dispose;

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
}

void ofd_seqs_fini(const struct lu_env *env, struct ofd_device *ofd)
{
	int rc;

	ofd_deregister_seq_exp(ofd);

	rc = ofd_fid_fini(env, ofd);
	if (rc != 0)
		CERROR("%s: fid fini error: rc = %d\n", ofd_name(ofd), rc);

	rc = ofd_fld_fini(env, ofd);
	if (rc != 0)
		CERROR("%s: fld fini error: rc = %d\n", ofd_name(ofd), rc);

	ofd_seqs_free(env, ofd);

	LASSERT(cfs_list_empty(&ofd->ofd_seq_list));
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

	lu_last_id_fid(&info->fti_fid, seq, ofd->ofd_lut.lut_lsd.lsd_osd_index);
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

	atomic_set(&oseq->os_refc, 1);

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
			     LU_SEQ_RANGE_OST);
	if (rc) {
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
		RETURN(rc);
	}
	RETURN(0);
}

/**
 * It will retrieve its FLDB entries from MDT0, and it only happens
 * when upgrading existent FS to 2.6.
 **/
static int ofd_register_lwp_callback(void *data)
{
	struct lu_env		env;
	struct ofd_device	*ofd = data;
	struct lu_server_fld	*fld = ofd->ofd_seq_site.ss_server_fld;
	int			rc;
	ENTRY;

	if (!likely(fld->lsf_new))
		RETURN(0);

	rc = lu_env_init(&env, LCT_DT_THREAD);
	if (rc) {
		CERROR("%s: cannot init env: rc = %d\n", ofd_name(ofd), rc);
		RETURN(rc);
	}

	rc = fld_update_from_controller(&env, fld);
	if (rc != 0) {
		CERROR("%s: cannot update controller: rc = %d\n",
		       ofd_name(ofd), rc);
		GOTO(out, rc);
	}
out:
	lu_env_fini(&env);
	RETURN(rc);
}

static int ofd_register_seq_exp(struct ofd_device *ofd)
{
	struct seq_server_site	*ss = &ofd->ofd_seq_site;
	char			*lwp_name = NULL;
	int			rc;

	OBD_ALLOC(lwp_name, MAX_OBD_NAME);
	if (lwp_name == NULL)
		GOTO(out_free, rc = -ENOMEM);

	rc = tgt_name2lwp_name(ofd_name(ofd), lwp_name, MAX_OBD_NAME, 0);
	if (rc != 0)
		GOTO(out_free, rc);

	rc = lustre_register_lwp_item(lwp_name, &ss->ss_client_seq->lcs_exp,
				      NULL, NULL);
	if (rc != 0)
		GOTO(out_free, rc);

	rc = lustre_register_lwp_item(lwp_name,
				      &ss->ss_server_fld->lsf_control_exp,
				      ofd_register_lwp_callback, ofd);
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

int ofd_fs_setup(const struct lu_env *env, struct ofd_device *ofd,
		 struct obd_device *obd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct dt_object	*fo;
	int			 rc = 0;

	ENTRY;

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
		RETURN (-ENOENT);

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

	if (ofd->ofd_health_check_file) {
		lu_object_put(env, &ofd->ofd_health_check_file->do_lu);
		ofd->ofd_health_check_file = NULL;
	}

	EXIT;
}

