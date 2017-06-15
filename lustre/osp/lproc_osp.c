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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/osp/lproc_osp.c
 *
 * Lustre OST Proxy Device (OSP), procfs functions
 *
 * Author: Alex Zhuravlev <alexey.zhuravlev@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include "osp_internal.h"

#ifdef CONFIG_PROC_FS
/**
 * Show OSP active status
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_active_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;

	LPROCFS_CLIMP_CHECK(dev);
	seq_printf(m, "%d\n", !dev->u.cli.cl_import->imp_deactive);
	LPROCFS_CLIMP_EXIT(dev);
	return 0;
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
static ssize_t
osp_active_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > 1)
		return -ERANGE;

	LPROCFS_CLIMP_CHECK(dev);
	/* opposite senses */
	if (dev->u.cli.cl_import->imp_deactive == val)
		rc = ptlrpc_set_import_active(dev->u.cli.cl_import, val);
	else
		CDEBUG(D_CONFIG, "activate %lld: ignoring repeat request\n",
		       val);

	LPROCFS_CLIMP_EXIT(dev);
	return count;
}
LPROC_SEQ_FOPS(osp_active);

/**
 * Show number of RPCs in flight
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_sync_rpcs_in_flight_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", atomic_read(&osp->opd_sync_rpcs_in_flight));
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_sync_rpcs_in_flight);

/**
 * Show number of RPCs in processing (including uncommitted by OST)
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_sync_rpcs_in_progress_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", atomic_read(&osp->opd_sync_rpcs_in_progress));
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_sync_rpcs_in_progress);

/**
 * Show number of changes to sync
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_sync_changes_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", atomic_read(&osp->opd_sync_changes));
	return 0;
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
static ssize_t osp_sync_changes_seq_write(struct file *file,
					 const char __user *buffer,
					 size_t count, loff_t *off)
{
	struct seq_file		*m	= file->private_data;
	struct obd_device	*dev	= m->private;
	struct osp_device	*osp	= lu2osp_dev(dev->obd_lu_dev);
	struct lu_env		 env;
	int			 rc;

	rc = lu_env_init(&env, LCT_LOCAL);
	if (rc != 0)
		return rc;

	rc = dt_sync(&env, &osp->opd_dt_dev);
	lu_env_fini(&env);

	return rc == 0 ? count : rc;
}
LPROC_SEQ_FOPS(osp_sync_changes);

/**
 * Show maximum number of RPCs in flight allowed
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_max_rpcs_in_flight_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", osp->opd_sync_max_rpcs_in_flight);
	return 0;
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
static ssize_t
osp_max_rpcs_in_flight_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct osp_device *osp = lu2osp_dev(dev->obd_lu_dev);
	int rc;
	__s64 val;

	if (osp == NULL)
		return -EINVAL;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 1 || val > INT_MAX)
		return -ERANGE;

	osp->opd_sync_max_rpcs_in_flight = val;
	return count;
}
LPROC_SEQ_FOPS(osp_max_rpcs_in_flight);

/**
 * Show maximum number of RPCs in processing allowed
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_max_rpcs_in_progress_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", osp->opd_sync_max_rpcs_in_progress);
	return 0;
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
static ssize_t
osp_max_rpcs_in_progress_seq_write(struct file *file, const char __user *buffer,
				   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct osp_device *osp = lu2osp_dev(dev->obd_lu_dev);
	int rc;
	__s64 val;

	if (osp == NULL)
		return -EINVAL;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 1 || val > INT_MAX)
		return -ERANGE;

	osp->opd_sync_max_rpcs_in_progress = val;

	return count;
}
LPROC_SEQ_FOPS(osp_max_rpcs_in_progress);

/**
 * Show number of objects to precreate next time
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_create_count_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	seq_printf(m, "%d\n", osp->opd_pre_create_count);
	return 0;
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
static ssize_t
osp_create_count_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	int rc, i;
	__s64 val;

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	rc = lprocfs_str_to_s64(buffer, count, &val);
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
LPROC_SEQ_FOPS(osp_create_count);

/**
 * Show maximum number of objects to precreate
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_max_create_count_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	seq_printf(m, "%d\n", osp->opd_pre_max_create_count);
	return 0;
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
static ssize_t
osp_max_create_count_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	int rc;
	__s64 val;

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0 || val > INT_MAX)
		return -ERANGE;
	if (val > OST_MAX_PRECREATE)
		return -ERANGE;

	if (osp->opd_pre_create_count > val)
		osp->opd_pre_create_count = val;

	osp->opd_pre_max_create_count = val;

	return count;
}
LPROC_SEQ_FOPS(osp_max_create_count);

/**
 * Show last id to assign in creation
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_prealloc_next_id_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	struct lu_fid *fid;
	__u64 id;

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	fid = &osp->opd_pre_used_fid;
	if (fid_is_idif(fid)) {
		id = fid_idif_id(fid_seq(fid), fid_oid(fid), fid_ver(fid));
		id++;
	} else {
		id = unlikely(fid_oid(fid) == LUSTRE_DATA_SEQ_MAX_WIDTH) ?
			1 : fid_oid(fid) + 1;
	}

	seq_printf(m, "%llu\n", id);
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_prealloc_next_id);

/**
 * Show last created id OST reported
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_prealloc_last_id_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	struct lu_fid *fid;
	__u64 id;

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;
	fid = &osp->opd_pre_last_created_fid;
	id = fid_is_idif(fid) ?
			 fid_idif_id(fid_seq(fid), fid_oid(fid), fid_ver(fid)) :
			 fid_oid(fid);

	seq_printf(m, "%llu\n", id);
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_prealloc_last_id);

/**
 * Show next FID sequence to precreate
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_prealloc_next_seq_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	struct lu_fid *fid;

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	fid = &osp->opd_pre_used_fid;
	seq_printf(m, "%#llx\n", fid_is_idif(fid) ?
		   fid_seq(fid) & (~0xffff) : fid_seq(fid));

	return 0;
}
LPROC_SEQ_FOPS_RO(osp_prealloc_next_seq);

/**
 * Show last created FID sequence OST reported
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_prealloc_last_seq_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);
	struct lu_fid *fid;

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	fid = &osp->opd_pre_last_created_fid;
	seq_printf(m, "%#llx\n", fid_is_idif(fid) ?
		   fid_seq(fid) & (~0xffff) : fid_seq(fid));

	return 0;
}
LPROC_SEQ_FOPS_RO(osp_prealloc_last_seq);

/**
 * Show the number of ids reserved by declare
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_prealloc_reserved_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct osp_device *osp = lu2osp_dev(obd->obd_lu_dev);

	if (osp == NULL || osp->opd_pre == NULL)
		return 0;

	seq_printf(m, "%llu\n", osp->opd_pre_reserved);
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_prealloc_reserved);

/**
 * Show interval (in seconds) to update statfs data
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_maxage_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n", osp->opd_statfs_maxage);
	return 0;
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
static ssize_t
osp_maxage_seq_write(struct file *file, const char __user *buffer,
			size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *dev = m->private;
	struct osp_device *osp = lu2osp_dev(dev->obd_lu_dev);
	int rc;
	__s64 val;

	if (osp == NULL)
		return -EINVAL;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 1 || val > INT_MAX)
		return -ERANGE;

	osp->opd_statfs_maxage = val;

	return count;
}
LPROC_SEQ_FOPS(osp_maxage);

/**
 * Show current precreation status: output 0 means success, otherwise negative
 * number is printed
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_pre_status_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL || osp->opd_pre == NULL)
		return -EINVAL;

	seq_printf(m, "%d\n", osp->opd_pre_status);
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_pre_status);

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
static int osp_destroys_in_flight_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *dev = m->private;
	struct osp_device *osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%u\n",
		   atomic_read(&osp->opd_sync_rpcs_in_progress) +
		   atomic_read(&osp->opd_sync_changes));
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_destroys_in_flight);

/**
 * Show changes synced from previous mount
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int osp_old_sync_processed_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*dev = m->private;
	struct osp_device	*osp = lu2osp_dev(dev->obd_lu_dev);

	if (osp == NULL)
		return -EINVAL;

	seq_printf(m, "%d\n", osp->opd_sync_prev_done);
	return 0;
}
LPROC_SEQ_FOPS_RO(osp_old_sync_processed);

/**
 * Show maximum number of RPCs in flight
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 * \retval		0 on success
 * \retval		negative number on error
 */
static int
osp_lfsck_max_rpcs_in_flight_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *dev = m->private;
	__u32 max;

	max = obd_get_max_rpcs_in_flight(&dev->u.cli);
	seq_printf(m, "%u\n", max);
	return 0;
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
static ssize_t
osp_lfsck_max_rpcs_in_flight_seq_write(struct file *file,
				       const char __user *buffer,
				       size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *dev = m->private;
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc == 0) {
		if (val < 0)
			return -ERANGE;

		rc = obd_set_max_rpcs_in_flight(&dev->u.cli, val);
	} else {
		count = rc;
	}

	return count;
}
LPROC_SEQ_FOPS(osp_lfsck_max_rpcs_in_flight);

LPROC_SEQ_FOPS_WO_TYPE(osp, ping);
LPROC_SEQ_FOPS_RO_TYPE(osp, uuid);
LPROC_SEQ_FOPS_RO_TYPE(osp, connect_flags);
LPROC_SEQ_FOPS_RO_TYPE(osp, server_uuid);
LPROC_SEQ_FOPS_RO_TYPE(osp, conn_uuid);

LPROC_SEQ_FOPS_RO_TYPE(osp, timeouts);

LPROC_SEQ_FOPS_RW_TYPE(osp, import);
LPROC_SEQ_FOPS_RO_TYPE(osp, state);

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
	__s64			val;
	int			rc;

	if (osp == NULL)
		return -EINVAL;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, 'M');
	if (rc)
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
LPROC_SEQ_FOPS(osp_reserved_mb_high);

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
	__s64			val;
	int			rc;

	if (osp == NULL)
		return -EINVAL;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, 'M');
	if (rc)
		return rc;
	val >>= 20;

	spin_lock(&osp->opd_pre_lock);
	osp->opd_reserved_mb_low = val;
	if (val >= osp->opd_reserved_mb_high)
		osp->opd_reserved_mb_high = val + 1;
	spin_unlock(&osp->opd_pre_lock);

	return count;
}
LPROC_SEQ_FOPS(osp_reserved_mb_low);

static struct lprocfs_vars lprocfs_osp_obd_vars[] = {
	{ .name =	"uuid",
	  .fops =	&osp_uuid_fops			},
	{ .name =	"ping",
	  .fops =	&osp_ping_fops,
	  .proc_mode =	0222				},
	{ .name =	"connect_flags",
	  .fops =	&osp_connect_flags_fops		},
	{ .name =	"ost_server_uuid",
	  .fops =	&osp_server_uuid_fops		},
	{ .name =	"ost_conn_uuid",
	  .fops =	&osp_conn_uuid_fops		},
	{ .name =	"active",
	  .fops =	&osp_active_fops		},
	{ .name =	"max_rpcs_in_flight",
	  .fops =	&osp_max_rpcs_in_flight_fops	},
	{ .name =	"max_rpcs_in_progress",
	  .fops =	&osp_max_rpcs_in_progress_fops	},
	{ .name =	"create_count",
	  .fops =	&osp_create_count_fops		},
	{ .name =	"max_create_count",
	  .fops =	&osp_max_create_count_fops	},
	{ .name =	"prealloc_next_id",
	  .fops =	&osp_prealloc_next_id_fops	},
	{ .name =	"prealloc_next_seq",
	  .fops =	&osp_prealloc_next_seq_fops	},
	{ .name =	"prealloc_last_id",
	  .fops =	&osp_prealloc_last_id_fops	},
	{ .name =	"prealloc_last_seq",
	  .fops =	&osp_prealloc_last_seq_fops	},
	{ .name =	"prealloc_reserved",
	  .fops =	&osp_prealloc_reserved_fops	},
	{ .name =	"timeouts",
	  .fops =	&osp_timeouts_fops		},
	{ .name =	"import",
	  .fops =	&osp_import_fops		},
	{ .name =	"state",
	  .fops =	&osp_state_fops			},
	{ .name =	"maxage",
	  .fops =	&osp_maxage_fops		},
	{ .name =	"prealloc_status",
	  .fops =	&osp_pre_status_fops		},
	{ .name =	"sync_changes",
	  .fops =	&osp_sync_changes_fops		},
	{ .name =	"sync_in_flight",
	  .fops =	&osp_sync_rpcs_in_flight_fops	},
	{ .name =	"sync_in_progress",
	  .fops =	&osp_sync_rpcs_in_progress_fops	},
	{ .name =	"old_sync_processed",
	  .fops =	&osp_old_sync_processed_fops	},
	{ .name =	"reserved_mb_high",
	  .fops =	&osp_reserved_mb_high_fops	},
	{ .name =	"reserved_mb_low",
	  .fops =	&osp_reserved_mb_low_fops	},

	/* for compatibility reasons */
	{ .name =	"destroys_in_flight",
	  .fops =	&osp_destroys_in_flight_fops		},
	{ .name	=	"lfsck_max_rpcs_in_flight",
	  .fops	=	&osp_lfsck_max_rpcs_in_flight_fops	},
	{ NULL }
};

static struct lprocfs_vars lprocfs_osp_md_vars[] = {
	{ .name =	"uuid",
	  .fops =	&osp_uuid_fops			},
	{ .name =	"ping",
	  .fops =	&osp_ping_fops,
	  .proc_mode =	0222				},
	{ .name =	"connect_flags",
	  .fops =	&osp_connect_flags_fops		},
	{ .name =	"mdt_server_uuid",
	  .fops =	&osp_server_uuid_fops		},
	{ .name =	"mdt_conn_uuid",
	  .fops =	&osp_conn_uuid_fops		},
	{ .name =	"active",
	  .fops =	&osp_active_fops		},
	{ .name =	"max_rpcs_in_flight",
	  .fops =	&osp_max_rpcs_in_flight_fops	},
	{ .name =	"max_rpcs_in_progress",
	  .fops =	&osp_max_rpcs_in_progress_fops	},
	{ .name =	"timeouts",
	  .fops =	&osp_timeouts_fops		},
	{ .name =	"import",
	  .fops =	&osp_import_fops		},
	{ .name =	"state",
	  .fops =	&osp_state_fops			},
	{ .name =	"maxage",
	  .fops =	&osp_maxage_fops		},
	{ .name =	"prealloc_status",
	  .fops =	&osp_pre_status_fops		},

	/* for compatibility reasons */
	{ .name =	"destroys_in_flight",
	  .fops =	&osp_destroys_in_flight_fops		},
	{ .name	=	"lfsck_max_rpcs_in_flight",
	  .fops	=	&osp_lfsck_max_rpcs_in_flight_fops	},
	{ NULL }
};

LPROC_SEQ_FOPS_RO_TYPE(osp, dt_blksize);
LPROC_SEQ_FOPS_RO_TYPE(osp, dt_kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(osp, dt_kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(osp, dt_kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(osp, dt_filestotal);
LPROC_SEQ_FOPS_RO_TYPE(osp, dt_filesfree);

static struct lprocfs_vars lprocfs_osp_osd_vars[] = {
	{ .name =	"blocksize",
	  .fops =	&osp_dt_blksize_fops		},
	{ .name =	"kbytestotal",
	  .fops =	&osp_dt_kbytestotal_fops	},
	{ .name =	"kbytesfree",
	  .fops =	&osp_dt_kbytesfree_fops		},
	{ .name =	"kbytesavail",
	  .fops =	&osp_dt_kbytesavail_fops	},
	{ .name =	"filestotal",
	  .fops =	&osp_dt_filestotal_fops		},
	{ .name =	"filesfree",
	  .fops =	&osp_dt_filesfree_fops		},
	{ NULL }
};

/**
 * Initialize OSP lprocfs
 *
 * param[in] osp	OSP device
 */
void osp_lprocfs_init(struct osp_device *osp)
{
	struct obd_device	*obd = osp->opd_obd;
	struct proc_dir_entry	*osc_proc_dir = NULL;
	struct obd_type		*type;
	int			 rc;

	if (osp->opd_connect_mdt)
		obd->obd_vars = lprocfs_osp_md_vars;
	else
		obd->obd_vars = lprocfs_osp_obd_vars;
	if (lprocfs_obd_setup(obd) != 0)
		return;

	rc = lprocfs_add_vars(obd->obd_proc_entry, lprocfs_osp_osd_vars,
			      &osp->opd_dt_dev);
	if (rc) {
		CERROR("%s: can't register in lprocfs, rc %d\n",
		       obd->obd_name, rc);
		return;
	}

	sptlrpc_lprocfs_cliobd_attach(obd);
	ptlrpc_lprocfs_register_obd(obd);

	if (osp->opd_connect_mdt || !strstr(obd->obd_name, "osc"))
		return;

	/* If the real OSC is present which is the case for setups
	 * with both server and clients on the same node then use
	 * the OSC's proc root */
	type = class_search_type(LUSTRE_OSC_NAME);
	if (type != NULL && type->typ_procroot != NULL)
		osc_proc_dir = type->typ_procroot;
	else
		osc_proc_dir = obd->obd_type->typ_procsym;

	if (osc_proc_dir == NULL)
		return;

	/* for compatibility we link old procfs's OSC entries to osp ones */
	osp->opd_symlink = lprocfs_add_symlink(obd->obd_name, osc_proc_dir,
					       "../osp/%s", obd->obd_name);
	if (osp->opd_symlink == NULL)
		CERROR("cannot create OSC symlink for /proc/fs/lustre/osp/%s\n",
		       obd->obd_name);
}

#endif /* CONFIG_PROC_FS */

