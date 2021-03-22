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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/osp/lproc_osp.c
 *
 * Lustre OST Proxy Device (OSP), procfs functions
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include "osp_internal.h"

/**
 * Show OSP active status
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t active_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);
	struct obd_device *obd = lu->ld_obd;
	struct obd_import *imp;
	int rc;

	with_imp_locked(obd, imp, rc)
		rc = sprintf(buf, "%d\n", !imp->imp_deactive);
	return rc;
}

/**
 * Activate/Deactivate OSP
 *
 * \param[in] file	proc file
 * \param[in] buffer	string, which is "1" or "0" to activate/deactivate OSP
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t active_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);
	struct obd_device *obd = lu->ld_obd;
	struct obd_import *imp, *imp0;
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	with_imp_locked(obd, imp0, rc)
		imp = class_import_get(imp0);
	if (rc)
		return rc;
	/* opposite senses */
	if (imp->imp_deactive == val)
		rc = ptlrpc_set_import_active(imp, val);
	else
		CDEBUG(D_CONFIG, "activate %u: ignoring repeat request\n",
		       (unsigned int)val);

	class_import_put(imp);

	return rc ?: count;
}
LUSTRE_RW_ATTR(active);

/**
 * Show number of RPCs in flight
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t sync_in_flight_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%u\n", atomic_read(&osp->opd_sync_rpcs_in_flight));
}
LUSTRE_RO_ATTR(sync_in_flight);

/**
 * Show number of RPCs in processing (including uncommitted by OST)
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t sync_in_progress_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%u\n", atomic_read(&osp->opd_sync_rpcs_in_progress));
}
LUSTRE_RO_ATTR(sync_in_progress);

/**
 * Show number of changes to sync
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t sync_changes_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%u\n", atomic_read(&osp->opd_sync_changes));
}

/**
 * Sync changes
 *
 * \param[in] file	proc file
 * \param[in] buffer	unused because any input will do
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t sync_changes_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	struct lu_env env;
	int rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		return rc;

	rc = dt_sync(&env, &osp->opd_dt_dev);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LUSTRE_RW_ATTR(sync_changes);

/**
 * Show maximum number of RPCs in flight allowed
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t max_rpcs_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%u\n", osp->opd_sync_max_rpcs_in_flight);
}

/**
 * Change maximum number of RPCs in flight allowed
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t max_rpcs_in_flight_store(struct kobject *kobj,
					struct attribute *attr,
					const char *buffer,
					size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0)
		return -ERANGE;

	osp->opd_sync_max_rpcs_in_flight = val;
	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_flight);

/**
 * Show maximum number of RPCs in processing allowed
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t max_rpcs_in_progress_show(struct kobject *kobj,
					 struct attribute *attr,
					 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%u\n", osp->opd_sync_max_rpcs_in_progress);
}

/**
 * Change maximum number of RPCs in processing allowed
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t max_rpcs_in_progress_store(struct kobject *kobj,
					  struct attribute *attr,
					  const char *buffer,
					  size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0)
		return -ERANGE;

	osp->opd_sync_max_rpcs_in_progress = val;

	return count;
}
LUSTRE_RW_ATTR(max_rpcs_in_progress);

/**
 * Show number of objects to precreate next time
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t create_count_show(struct kobject *kobj,
				 struct attribute *attr,
				 char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	if (!osp->opd_pre)
		return -EINVAL;

	return sprintf(buf, "%d\n", osp->opd_pre_create_count);
}

/**
 * Change number of objects to precreate next time
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents number of objects to precreate
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t create_count_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	unsigned int val;
	int rc, i;

	if (!osp->opd_pre)
		return -EINVAL;


	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	/* The MDT ALWAYS needs to limit the precreate count to
	 * OST_MAX_PRECREATE, and the constant cannot be changed
	 * because it is a value shared between the OSP and OST
	 * that is the maximum possible number of objects that will
	 * ever be handled by MDT->OST recovery processing.
	 *
	 * If the OST ever gets a request to delete more orphans,
	 * this implies that something has gone badly on the MDT
	 * and the OST will refuse to delete so much data from the
	 * filesystem as a safety measure. */
	if (val < OST_MIN_PRECREATE || val > OST_MAX_PRECREATE)
		return -ERANGE;
	if (val > osp->opd_pre_max_create_count)
		return -ERANGE;

	for (i = 1; (i << 1) <= val; i <<= 1)
		;
	osp->opd_pre_create_count = i;

	return count;
}
LUSTRE_RW_ATTR(create_count);

/**
 * Show maximum number of objects to precreate
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t max_create_count_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	if (!osp->opd_pre)
		return -EINVAL;

	return sprintf(buf, "%d\n", osp->opd_pre_max_create_count);
}

/**
 * Change maximum number of objects to precreate
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t max_create_count_store(struct kobject *kobj,
				      struct attribute *attr,
				      const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	unsigned int val;
	int rc;

	if (!osp->opd_pre)
		return -EINVAL;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val && (val < OST_MIN_PRECREATE ||
		    val > OST_MAX_PRECREATE))
		return -ERANGE;

	if (osp->opd_pre_create_count > val)
		osp->opd_pre_create_count = val;

	/* Can be 0 after setting max_create_count to 0 */
	if (osp->opd_pre_create_count == 0 && val != 0)
		osp->opd_pre_create_count = OST_MIN_PRECREATE;

	osp->opd_pre_max_create_count = val;

	return count;
}
LUSTRE_RW_ATTR(max_create_count);

/**
 * Show last id to assign in creation
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t prealloc_next_id_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	struct lu_fid *fid;
	u64 id;

	if (!osp->opd_pre)
		return -EINVAL;

	fid = &osp->opd_pre_used_fid;
	if (fid_is_idif(fid)) {
		id = fid_idif_id(fid_seq(fid), fid_oid(fid), fid_ver(fid));
		id++;
	} else {
		id = unlikely(fid_oid(fid) == LUSTRE_DATA_SEQ_MAX_WIDTH) ?
			1 : fid_oid(fid) + 1;
	}

	return sprintf(buf, "%llu\n", id);
}
LUSTRE_RO_ATTR(prealloc_next_id);

/**
 * Show last created id OST reported
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */

static ssize_t prealloc_last_id_show(struct kobject *kobj,
				     struct attribute *attr,
				     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	struct lu_fid *fid;
	u64 id;

	if (!osp->opd_pre)
		return -EINVAL;

	fid = &osp->opd_pre_last_created_fid;
	id = fid_is_idif(fid) ?
			 fid_idif_id(fid_seq(fid), fid_oid(fid), fid_ver(fid)) :
			 fid_oid(fid);

	return sprintf(buf, "%llu\n", id);
}
LUSTRE_RO_ATTR(prealloc_last_id);

/**
 * Show next FID sequence to precreate
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t prealloc_next_seq_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	struct lu_fid *fid;

	if (!osp->opd_pre)
		return -EINVAL;

	fid = &osp->opd_pre_used_fid;
	return sprintf(buf, "%#llx\n", fid_is_idif(fid) ?
		       fid_seq(fid) & (~0xffff) : fid_seq(fid));
}
LUSTRE_RO_ATTR(prealloc_next_seq);

/**
 * Show last created FID sequence OST reported
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t prealloc_last_seq_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	struct lu_fid *fid;

	if (!osp->opd_pre)
		return -EINVAL;

	fid = &osp->opd_pre_last_created_fid;
	return sprintf(buf, "%#llx\n", fid_is_idif(fid) ?
		       fid_seq(fid) & (~0xffff) : fid_seq(fid));
}
LUSTRE_RO_ATTR(prealloc_last_seq);

/**
 * Show the number of ids reserved by declare
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t prealloc_reserved_show(struct kobject *kobj,
				      struct attribute *attr,
				      char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	if (!osp->opd_pre)
		return -EINVAL;

	return sprintf(buf, "%llu\n", osp->opd_pre_reserved);
}
LUSTRE_RO_ATTR(prealloc_reserved);

/**
 * Show interval (in seconds) to update statfs data
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t maxage_show(struct kobject *kobj,
			   struct attribute *attr,
			   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%lld\n", osp->opd_statfs_maxage);
}

/**
 * Change interval to update statfs data
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents statfs interval (in seconds)
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t maxage_store(struct kobject *kobj, struct attribute *attr,
			    const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val == 0)
		return -ERANGE;

	osp->opd_statfs_maxage = val;

	return count;
}
LUSTRE_RW_ATTR(maxage);

/**
 * Show current precreation status: output 0 means success, otherwise negative
 * number is printed
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t prealloc_status_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	if (!osp->opd_pre)
		return -EINVAL;

	return sprintf(buf, "%d\n", osp->opd_pre_status);
}
LUSTRE_RO_ATTR(prealloc_status);

/**
 * Show the number of RPCs in processing (including uncommitted by OST) plus
 * changes to sync, i.e. this is the total number of changes OST needs to apply
 * and commit.
 *
 * This counter is used to determine if OST has space returned. A zero value
 * indicates that OST storage space consumed by destroyed objects has been freed
 * on disk, the associated llog records have been cleared, and no synchronous
 * RPC are being processed.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t destroys_in_flight_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%u\n",
		       atomic_read(&osp->opd_sync_rpcs_in_progress) +
		       atomic_read(&osp->opd_sync_changes));
}
LUSTRE_RO_ATTR(destroys_in_flight);

/**
 * Show changes synced from previous mount
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t old_sync_processed_show(struct kobject *kobj,
				       struct attribute *attr,
				       char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct osp_device *osp = dt2osp_dev(dt);

	return sprintf(buf, "%d\n", osp->opd_sync_prev_done);
}
LUSTRE_RO_ATTR(old_sync_processed);

/**
 * Show maximum number of RPCs in flight
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static ssize_t lfsck_max_rpcs_in_flight_show(struct kobject *kobj,
					     struct attribute *attr,
					     char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);
	struct obd_device *obd = lu->ld_obd;
	u32 max;

	max = obd_get_max_rpcs_in_flight(&obd->u.cli);
	return sprintf(buf, "%u\n", max);
}

/**
 * Change maximum number of RPCs in flight
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number of RPCs in flight
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t lfsck_max_rpcs_in_flight_store(struct kobject *kobj,
					      struct attribute *attr,
					      const char *buffer,
					      size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);
	struct obd_device *obd = lu->ld_obd;
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	rc = obd_set_max_rpcs_in_flight(&obd->u.cli, val);
	return rc ? rc : count;
}
LUSTRE_RW_ATTR(lfsck_max_rpcs_in_flight);

ssize_t ping_show(struct kobject *kobj, struct attribute *attr,
		  char *buffer)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);
	struct obd_device *obd = lu->ld_obd;
	int rc;

	rc = ptlrpc_obd_ping(obd);

	return rc;
}
LUSTRE_RO_ATTR(ping);

ssize_t osp_conn_uuid_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_device *lu = dt2lu_dev(dt);
	struct obd_device *obd = lu->ld_obd;
	struct obd_import *imp;
	struct ptlrpc_connection *conn;
	ssize_t count;

	with_imp_locked(obd, imp, count) {
		conn = imp->imp_connection;
		if (conn)
			count = sprintf(buf, "%s\n", conn->c_remote_uuid.uuid);
		else
			count = sprintf(buf, "%s\n", "<none>");
	}

	return count;
}

LUSTRE_ATTR(ost_conn_uuid, 0444, osp_conn_uuid_show, NULL);
LUSTRE_ATTR(mdt_conn_uuid, 0444, osp_conn_uuid_show, NULL);

LDEBUGFS_SEQ_FOPS_RO_TYPE(osp, connect_flags);
LDEBUGFS_SEQ_FOPS_RO_TYPE(osp, server_uuid);
LDEBUGFS_SEQ_FOPS_RO_TYPE(osp, timeouts);

LDEBUGFS_SEQ_FOPS_RW_TYPE(osp, import);
LDEBUGFS_SEQ_FOPS_RO_TYPE(osp, state);

/**
 * Show high watermark (in megabytes). If available free space at OST is grater
 * than high watermark and object allocation for OST is disabled, enable it.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_reserved_mb_high_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", osp->opd_reserved_mb_high);
	return 0;
}

/**
 * Change high watermark
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents new value (in megabytes)
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
osp_reserved_mb_high_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);
	char kernbuf[22] = "";
	u64 val;
	int			rc;

	if (osp == NULL || osp->opd_pre == NULL)
		return -EINVAL;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "MiB");
	if (rc < 0)
		return rc;
	val >>= 20;
	if (val < 1)
		return -ERANGE;

	spin_lock(&osp->opd_pre_lock);
	osp->opd_reserved_mb_high = val;
	if (val <= osp->opd_reserved_mb_low)
		osp->opd_reserved_mb_low = val - 1;
	spin_unlock(&osp->opd_pre_lock);

	return count;
}
LDEBUGFS_SEQ_FOPS(osp_reserved_mb_high);

/**
 * Show low watermark (in megabytes). If available free space at OST is less
 * than low watermark, object allocation for OST is disabled.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_reserved_mb_low_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", osp->opd_reserved_mb_low);
	return 0;
}

/**
 * Change low watermark
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents new value (in megabytes)
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
osp_reserved_mb_low_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);
	char kernbuf[22] = "";
	u64 val;
	int			rc;

	if (osp == NULL || osp->opd_pre == NULL)
		return -EINVAL;

	if (count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	rc = sysfs_memparse(kernbuf, count, &val, "MiB");
	if (rc < 0)
		return rc;
	val >>= 20;

	spin_lock(&osp->opd_pre_lock);
	osp->opd_reserved_mb_low = val;
	if (val >= osp->opd_reserved_mb_high)
		osp->opd_reserved_mb_high = val + 1;
	spin_unlock(&osp->opd_pre_lock);

	return count;
}
LDEBUGFS_SEQ_FOPS(osp_reserved_mb_low);

static ssize_t force_sync_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct dt_device *dt = container_of(kobj, struct dt_device,
					    dd_kobj);
	struct lu_env env;
	int rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc)
		return rc;

	rc = dt_sync(&env, dt);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LUSTRE_WO_ATTR(force_sync);

static struct ldebugfs_vars ldebugfs_osp_obd_vars[] = {
	{ .name =	"connect_flags",
	  .fops =	&osp_connect_flags_fops		},
	{ .name =	"ost_server_uuid",
	  .fops =	&osp_server_uuid_fops		},
	{ .name =	"timeouts",
	  .fops =	&osp_timeouts_fops		},
	{ .name =	"import",
	  .fops =	&osp_import_fops		},
	{ .name =	"state",
	  .fops =	&osp_state_fops			},
	{ .name =	"reserved_mb_high",
	  .fops =	&osp_reserved_mb_high_fops	},
	{ .name =	"reserved_mb_low",
	  .fops =	&osp_reserved_mb_low_fops	},
	{ NULL }
};

static struct ldebugfs_vars ldebugfs_osp_md_vars[] = {
	{ .name =	"connect_flags",
	  .fops =	&osp_connect_flags_fops		},
	{ .name =	"mdt_server_uuid",
	  .fops =	&osp_server_uuid_fops		},
	{ .name =	"timeouts",
	  .fops =	&osp_timeouts_fops		},
	{ .name =	"import",
	  .fops =	&osp_import_fops		},
	{ .name =	"state",
	  .fops =	&osp_state_fops			},
	{ NULL }
};

static struct attribute *osp_obd_attrs[] = {
	/* First two for compatiability reasons */
	&lustre_attr_lfsck_max_rpcs_in_flight.attr,
	&lustre_attr_destroys_in_flight.attr,
	&lustre_attr_active.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_max_rpcs_in_progress.attr,
	&lustre_attr_maxage.attr,
	&lustre_attr_ost_conn_uuid.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_prealloc_status.attr,
	&lustre_attr_prealloc_next_id.attr,
	&lustre_attr_prealloc_last_id.attr,
	&lustre_attr_prealloc_next_seq.attr,
	&lustre_attr_prealloc_last_seq.attr,
	&lustre_attr_prealloc_reserved.attr,
	&lustre_attr_sync_in_flight.attr,
	&lustre_attr_sync_in_progress.attr,
	&lustre_attr_sync_changes.attr,
	&lustre_attr_force_sync.attr,
	&lustre_attr_old_sync_processed.attr,
	&lustre_attr_create_count.attr,
	&lustre_attr_max_create_count.attr,
	NULL,
};

static struct attribute *osp_md_attrs[] = {
	/* First two for compatiability reasons */
	&lustre_attr_lfsck_max_rpcs_in_flight.attr,
	&lustre_attr_destroys_in_flight.attr,
	&lustre_attr_active.attr,
	&lustre_attr_max_rpcs_in_flight.attr,
	&lustre_attr_max_rpcs_in_progress.attr,
	&lustre_attr_maxage.attr,
	&lustre_attr_mdt_conn_uuid.attr,
	&lustre_attr_ping.attr,
	&lustre_attr_prealloc_status.attr,
	NULL,
};

void osp_tunables_fini(struct osp_device *osp)
{
	struct obd_device *obd = osp->opd_obd;
	struct kobject *osc;

	osc = kset_find_obj(lustre_kset, "osc");
	if (osc) {
		sysfs_remove_link(osc, obd->obd_name);
		kobject_put(osc);
	}

	debugfs_remove_recursive(osp->opd_debugfs);
	osp->opd_debugfs = NULL;

	ptlrpc_lprocfs_unregister_obd(obd);

	debugfs_remove_recursive(obd->obd_debugfs_entry);
	obd->obd_debugfs_entry = NULL;

	dt_tunables_fini(&osp->opd_dt_dev);
}

/**
 * Initialize OSP sysfs / debugfs
 *
 * param[in] osp	OSP device
 */
void osp_tunables_init(struct osp_device *osp)
{
	struct obd_device *obd = osp->opd_obd;
	struct kobject *osc;
	int rc;

	if (osp->opd_connect_mdt) {
		osp->opd_dt_dev.dd_ktype.default_attrs = osp_md_attrs;
		obd->obd_debugfs_vars = ldebugfs_osp_md_vars;
	} else {
		osp->opd_dt_dev.dd_ktype.default_attrs = osp_obd_attrs;
		obd->obd_debugfs_vars = ldebugfs_osp_obd_vars;
	}

	rc = dt_tunables_init(&osp->opd_dt_dev, obd->obd_type, obd->obd_name,
			      NULL);
	if (rc) {
		CERROR("%s: failed to setup DT tunables: %d\n",
		       obd->obd_name, rc);
		return;
	}

	/* Since we register the obd device with ptlrpc / sptlrpc we
	 * have to register debugfs with obd_device
	 */
	obd->obd_debugfs_entry = debugfs_create_dir(
		obd->obd_name, obd->obd_type->typ_debugfs_entry);
	ldebugfs_add_vars(obd->obd_debugfs_entry, obd->obd_debugfs_vars, obd);

	sptlrpc_lprocfs_cliobd_attach(obd);
	ptlrpc_lprocfs_register_obd(obd);

	if (osp->opd_connect_mdt || !strstr(obd->obd_name, "osc"))
		return;

	/* If the real OSC is present which is the case for setups
	 * with both server and clients on the same node then use
	 * the OSC's proc root
	 */
	osc = kset_find_obj(lustre_kset, "osc");
	if (osc) {
		rc = sysfs_create_link(osc, &osp->opd_dt_dev.dd_kobj,
				       obd->obd_name);
		kobject_put(osc);
	}

	osp->opd_debugfs = ldebugfs_add_symlink(obd->obd_name, "osc",
						"../osp/%s", obd->obd_name);
	if (!osp->opd_debugfs)
		CERROR("%s: failed to create OSC debugfs symlink\n",
		       obd->obd_name);
}
