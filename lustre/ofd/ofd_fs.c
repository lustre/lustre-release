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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_fs.c
 *
 * This file provides helper functions to handle various data stored on disk.
 * It uses OSD API and works with any OSD.
 *
 * Note: this file contains also functions for sequence handling, they are
 * placed here improperly and will be moved to the ofd_dev.c and ofd_internal.h,
 * this comment is to be removed after that.
 *
 * Author: Alexey Zhuravlev <alexey.zhuravlev@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

/**
 * Restrict precreate batch count by its upper limit.
 *
 * The precreate batch count is a number of precreates to do in
 * single transaction. It has upper limit - ofd_device::ofd_precreate_batch
 * value which shouldn't be exceeded.
 *
 * \param[in] ofd	OFD device
 * \param[in] batch	number of updates in the batch
 *
 * \retval		\a batch limited by ofd_device::ofd_precreate_batch
 */
int ofd_precreate_batch(struct ofd_device *ofd, int batch)
{
	int count;

	spin_lock(&ofd->ofd_batch_lock);
	count = min(ofd->ofd_precreate_batch, batch);
	spin_unlock(&ofd->ofd_batch_lock);

	return count;
}

/**
 * Get ofd_seq for \a seq.
 *
 * Function finds appropriate structure by \a seq number and
 * increases the reference counter of that structure.
 *
 * \param[in] ofd	OFD device
 * \param[in] seq	sequence number, FID sequence number usually
 *
 * \retval		pointer to the requested ofd_seq structure
 * \retval		NULL if ofd_seq is not found
 */
struct ofd_seq *ofd_seq_get(struct ofd_device *ofd, u64 seq)
{
	struct ofd_seq *oseq;

	read_lock(&ofd->ofd_seq_list_lock);
	list_for_each_entry(oseq, &ofd->ofd_seq_list, os_list) {
		if (ostid_seq(&oseq->os_oi) == seq) {
			atomic_inc(&oseq->os_refc);
			read_unlock(&ofd->ofd_seq_list_lock);
			return oseq;
		}
	}
	read_unlock(&ofd->ofd_seq_list_lock);
	return NULL;
}

/**
 * Drop a reference to ofd_seq.
 *
 * The paired function to the ofd_seq_get(). It decrease the reference counter
 * of the ofd_seq structure and free it if that reference was last one.
 *
 * \param[in] env	execution environment
 * \param[in] oseq	ofd_seq structure to put
 */
void ofd_seq_put(const struct lu_env *env, struct ofd_seq *oseq)
{
	if (atomic_dec_and_test(&oseq->os_refc)) {
		LASSERT(list_empty(&oseq->os_list));
		LASSERT(oseq->os_lastid_obj != NULL);
		dt_object_put(env, oseq->os_lastid_obj);
		OBD_FREE_PTR(oseq);
	}
}

/**
 * Add a new ofd_seq to the given OFD device.
 *
 * First it checks if there is already existent ofd_seq with the same
 * sequence number as used by \a new_seq.
 * If such ofd_seq is not found then the \a new_seq is added to the list
 * of all ofd_seq structures else the \a new_seq is dropped and the found
 * ofd_seq is returned back.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] new_seq	new ofd_seq to be added
 *
 * \retval		ofd_seq structure
 */
static struct ofd_seq *ofd_seq_add(const struct lu_env *env,
				   struct ofd_device *ofd,
				   struct ofd_seq *new_seq)
{
	struct ofd_seq *os = NULL;

	write_lock(&ofd->ofd_seq_list_lock);
	list_for_each_entry(os, &ofd->ofd_seq_list, os_list) {
		if (ostid_seq(&os->os_oi) == ostid_seq(&new_seq->os_oi)) {
			atomic_inc(&os->os_refc);
			write_unlock(&ofd->ofd_seq_list_lock);
			/* The seq has not been added to the list */
			ofd_seq_put(env, new_seq);
			return os;
		}
	}
	atomic_inc(&new_seq->os_refc);
	list_add_tail(&new_seq->os_list, &ofd->ofd_seq_list);
	ofd->ofd_seq_count++;
	write_unlock(&ofd->ofd_seq_list_lock);
	return new_seq;
}

/**
 * Get last object ID for the given sequence.
 *
 * \param[in] oseq	OFD sequence structure
 *
 * \retval		the last object ID for this sequence
 */
u64 ofd_seq_last_oid(struct ofd_seq *oseq)
{
	u64 id;

	spin_lock(&oseq->os_last_oid_lock);
	id = ostid_id(&oseq->os_oi);
	spin_unlock(&oseq->os_last_oid_lock);

	return id;
}

/**
 * Set new last object ID for the given sequence.
 *
 * \param[in] oseq	OFD sequence
 * \param[in] id	the new OID to set
 */
void ofd_seq_last_oid_set(struct ofd_seq *oseq, u64 id)
{
	spin_lock(&oseq->os_last_oid_lock);
	if (likely(ostid_id(&oseq->os_oi) < id)) {
		if (ostid_set_id(&oseq->os_oi, id)) {
			CERROR("Bad %llu to set " DOSTID "\n",
			       (unsigned long long)id, POSTID(&oseq->os_oi));
		}
	}
	spin_unlock(&oseq->os_last_oid_lock);
}

/**
 * Update last used OID on disk for the given sequence.
 *
 * The last used object ID is stored persistently on disk and
 * must be written when updated. This function writes the sequence data.
 * The format is just an object ID of the latest used object FID.
 * Each ID is stored in per-sequence file.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] oseq	ofd_seq structure with data to write
 *
 * \retval		0 on successful write of data from \a oseq
 * \retval		negative value on error
 */
int ofd_seq_last_oid_write(const struct lu_env *env, struct ofd_device *ofd,
			   struct ofd_seq *oseq)
{
	struct ofd_thread_info	*info = ofd_info(env);
	u64			 tmp;
	struct dt_object	*obj = oseq->os_lastid_obj;
	struct thandle		*th;
	int			 rc;

	ENTRY;

	if (ofd->ofd_osd->dd_rdonly)
		RETURN(0);

	tmp = cpu_to_le64(ofd_seq_last_oid(oseq));

	info->fti_buf.lb_buf = &tmp;
	info->fti_buf.lb_len = sizeof(tmp);
	info->fti_off = 0;

	LASSERT(obj != NULL);

	th = dt_trans_create(env, ofd->ofd_osd);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, obj, &info->fti_buf,
				     info->fti_off, th);
	if (rc < 0)
		GOTO(out, rc);
	rc = dt_trans_start_local(env, ofd->ofd_osd, th);
	if (rc < 0)
		GOTO(out, rc);
	rc = dt_record_write(env, obj, &info->fti_buf, &info->fti_off,
			     th);
	if (rc < 0)
		GOTO(out, rc);

	CDEBUG(D_INODE, "%s: write last_objid "DOSTID": rc = %d\n",
	       ofd_name(ofd), POSTID(&oseq->os_oi), rc);
	EXIT;
out:
	dt_trans_stop(env, ofd->ofd_osd, th);
	return rc;
}

/**
 * Deregister LWP items for FLDB and SEQ client on OFD.
 *
 * LWP is lightweight proxy - simplified connection between
 * servers. It is used for FID Location Database (FLDB) and
 * sequence (SEQ) client-server interactions.
 *
 * This function is used during server cleanup process to free
 * LWP items that were previously set up upon OFD start.
 *
 * \param[in]     ofd	OFD device
 */
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

/**
 * Stop FLDB server on OFD.
 *
 * This function is part of OFD cleanup process.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 */
static void ofd_fld_fini(const struct lu_env *env, struct ofd_device *ofd)
{
	struct seq_server_site *ss = &ofd->ofd_seq_site;

	if (ss != NULL && ss->ss_server_fld != NULL) {
		fld_server_fini(env, ss->ss_server_fld);
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
	}
}

/**
 * Free sequence structures on OFD.
 *
 * This function is part of OFD cleanup process, it goes through
 * the list of ofd_seq structures stored in ofd_device structure
 * and frees them.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 */
void ofd_seqs_free(const struct lu_env *env, struct ofd_device *ofd)
{
	struct ofd_seq		*oseq;
	struct ofd_seq		*tmp;
	struct list_head	 dispose;

	INIT_LIST_HEAD(&dispose);
	write_lock(&ofd->ofd_seq_list_lock);
	list_for_each_entry_safe(oseq, tmp, &ofd->ofd_seq_list, os_list)
		list_move(&oseq->os_list, &dispose);
	write_unlock(&ofd->ofd_seq_list_lock);

	while (!list_empty(&dispose)) {
		oseq = container_of0(dispose.next, struct ofd_seq, os_list);
		list_del_init(&oseq->os_list);
		ofd_seq_put(env, oseq);
	}
}

/**
 * Stop FLDB and SEQ services on OFD.
 *
 * This function is part of OFD cleanup process.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 */
void ofd_seqs_fini(const struct lu_env *env, struct ofd_device *ofd)
{
	int rc;

	ofd_deregister_seq_exp(ofd);

	rc = ofd_fid_fini(env, ofd);
	if (rc != 0)
		CERROR("%s: fid fini error: rc = %d\n", ofd_name(ofd), rc);

	ofd_fld_fini(env, ofd);

	ofd_seqs_free(env, ofd);

	LASSERT(list_empty(&ofd->ofd_seq_list));
}

/**
 * Return ofd_seq structure filled with valid data.
 *
 * This function gets the ofd_seq by sequence number and read
 * corresponding data from disk.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] seq	sequence number
 *
 * \retval		ofd_seq structure filled with data
 * \retval		ERR_PTR pointer on error
 */
struct ofd_seq *ofd_seq_load(const struct lu_env *env, struct ofd_device *ofd,
			     u64 seq)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct ofd_seq		*oseq = NULL;
	struct dt_object	*dob;
	u64			 lastid;
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

	INIT_LIST_HEAD(&oseq->os_list);
	mutex_init(&oseq->os_create_lock);
	spin_lock_init(&oseq->os_last_oid_lock);
	ostid_set_seq(&oseq->os_oi, seq);

	atomic_set(&oseq->os_refc, 1);

	rc = dt_attr_get(env, dob, &info->fti_attr);
	if (rc)
		GOTO(cleanup, rc);

	if (info->fti_attr.la_size == 0) {
		/* object is just created, initialize last id */
		if (OBD_FAIL_CHECK(OBD_FAIL_OFD_SET_OID))
			ofd_seq_last_oid_set(oseq, 0xffffff00);
		else
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
		CERROR("%s: corrupted size %llu LAST_ID of seq %#llx\n",
			ofd_name(ofd), (__u64)info->fti_attr.la_size, seq);
		GOTO(cleanup, rc = -EINVAL);
	}

	oseq = ofd_seq_add(env, ofd, oseq);
	RETURN((oseq != NULL) ? oseq : ERR_PTR(-ENOENT));
cleanup:
	ofd_seq_put(env, oseq);
	return ERR_PTR(rc);
}

/**
 * initialize local FLDB server.
 *
 * \param[in] env	execution environment
 * \param[in] uuid	unique name for this FLDS server
 * \param[in] ofd	OFD device
 *
 * \retval		0 on successful initialization
 * \retval		negative value on error
 */
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
	if (rc < 0) {
		OBD_FREE_PTR(ss->ss_server_fld);
		ss->ss_server_fld = NULL;
		RETURN(rc);
	}
	RETURN(0);
}

/**
 * Update local FLDB copy from master server.
 *
 * This callback is called when LWP is connected to the server.
 * It retrieves its FLDB entries from MDT0, and it only happens
 * when upgrading the existing file system to 2.6.
 *
 * \param[in] data	OFD device
 *
 * \retval		0 on successful FLDB update
 * \retval		negative value in case if failure
 */
static int ofd_register_lwp_callback(void *data)
{
	struct lu_env		*env;
	struct ofd_device	*ofd = data;
	struct lu_server_fld	*fld = ofd->ofd_seq_site.ss_server_fld;
	int			rc;

	ENTRY;

	if (!likely(fld->lsf_new))
		RETURN(0);

	OBD_ALLOC_PTR(env);
	if (env == NULL)
		RETURN(-ENOMEM);

	rc = lu_env_init(env, LCT_DT_THREAD);
	if (rc < 0)
		GOTO(out, rc);

	rc = fld_update_from_controller(env, fld);
	if (rc < 0) {
		CERROR("%s: cannot update controller: rc = %d\n",
		       ofd_name(ofd), rc);
		GOTO(out, rc);
	}
	EXIT;
out:
	lu_env_fini(env);
	OBD_FREE_PTR(env);
	return rc;
}

/**
 * Get LWP exports from LWP connection for local FLDB server and SEQ client.
 *
 * This function is part of setup process and initialize FLDB server and SEQ
 * client, so they may work with remote servers.
 *
 * \param[in] ofd	OFD device
 *
 * \retval		0 on successful export get
 * \retval		negative value on error
 */
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

/**
 * Initialize SEQ and FLD service on OFD.
 *
 * This is part of OFD setup process.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 *
 * \retval		0 on successful services initialization
 * \retval		negative value on error
 */
int ofd_seqs_init(const struct lu_env *env, struct ofd_device *ofd)
{
	int rc;

	rwlock_init(&ofd->ofd_seq_list_lock);
	INIT_LIST_HEAD(&ofd->ofd_seq_list);
	ofd->ofd_seq_count = 0;

	rc = ofd_fid_init(env, ofd);
	if (rc != 0) {
		CERROR("%s: fid init error: rc = %d\n", ofd_name(ofd), rc);
		GOTO(out, rc);
	}

	rc = ofd_fld_init(env, ofd_name(ofd), ofd);
	if (rc < 0) {
		CERROR("%s: Can't init fld, rc %d\n", ofd_name(ofd), rc);
		GOTO(out_fid, rc);
	}

	rc = ofd_register_seq_exp(ofd);
	if (rc < 0) {
		CERROR("%s: Can't init seq exp, rc %d\n", ofd_name(ofd), rc);
		GOTO(out_fld, rc);
	}

	RETURN(0);

out_fld:
	ofd_fld_fini(env, ofd);
out_fid:
	ofd_fid_fini(env, ofd);
out:
	return rc;
}

/**
 * Initialize storage for the OFD.
 *
 * This function sets up service files for OFD. Currently, the only
 * service file is "health_check".
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 * \param[in] obd	OBD device (unused now)
 *
 * \retval		0 on successful setup
 * \retval		negative value on error
 */
int ofd_fs_setup(const struct lu_env *env, struct ofd_device *ofd,
		 struct obd_device *obd)
{
	struct ofd_thread_info	*info = ofd_info(env);
	struct dt_object	*fo;
	int			 rc = 0;

	ENTRY;

	rc = ofd_seqs_init(env, ofd);
	if (rc)
		GOTO(out, rc);

	if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
		GOTO(out_seqs, rc = -ENOENT);

	lu_local_obj_fid(&info->fti_fid, OFD_HEALTH_CHECK_OID);
	memset(&info->fti_attr, 0, sizeof(info->fti_attr));
	info->fti_attr.la_valid = LA_MODE;
	info->fti_attr.la_mode = S_IFREG | S_IRUGO | S_IWUSR;
	info->fti_dof.dof_type = dt_mode_to_dft(S_IFREG);

	fo = dt_find_or_create(env, ofd->ofd_osd, &info->fti_fid,
			       &info->fti_dof, &info->fti_attr);
	if (IS_ERR(fo))
		GOTO(out_seqs, rc = PTR_ERR(fo));

	ofd->ofd_health_check_file = fo;

	RETURN(0);

out_seqs:
	ofd_seqs_fini(env, ofd);
out:
	return rc;
}

/**
 * Cleanup service files on OFD.
 *
 * This function syncs whole OFD device and close "health check" file.
 *
 * \param[in] env	execution environment
 * \param[in] ofd	OFD device
 */
void ofd_fs_cleanup(const struct lu_env *env, struct ofd_device *ofd)
{
	int rc;

	ENTRY;

	ofd_seqs_fini(env, ofd);

	rc = dt_sync(env, ofd->ofd_osd);
	if (rc < 0)
		CWARN("%s: can't sync OFD upon cleanup: %d\n",
		      ofd_name(ofd), rc);

	if (ofd->ofd_health_check_file) {
		dt_object_put(env, ofd->ofd_health_check_file);
		ofd->ofd_health_check_file = NULL;
	}

	EXIT;
}

