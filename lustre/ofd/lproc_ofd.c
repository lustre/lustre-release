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
 * Copyright (c) 2012, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/lproc_ofd.c
 *
 * This file provides functions of procfs interface for OBD Filter Device (OFD).
 *
 * Author: Andreas Dilger <andreas.dilger@intel.com>
 * Author: Mikhail Pershin <mike.pershin@intel.com>
 * Author: Johann Lombardi <johann.lombardi@intel.com>
 * Author: Fan Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <obd.h>
#include <lprocfs_status.h>
#include <linux/seq_file.h>
#include <lustre_lfsck.h>

#include "ofd_internal.h"

#ifdef CONFIG_PROC_FS

/**
 * Show number of FID allocation sequences.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_seqs_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", ofd->ofd_seq_count);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_seqs);

/**
 * Show estimate of total amount of dirty data on clients.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_tot_dirty_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct tg_grants_data *tgd;

	LASSERT(obd != NULL);
	tgd = &obd->u.obt.obt_lut->lut_tgd;
	seq_printf(m, "%llu\n", tgd->tgd_tot_dirty);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_tot_dirty);

/**
 * Show total amount of space granted to clients.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_tot_granted_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct tg_grants_data *tgd;

	LASSERT(obd != NULL);
	tgd = &obd->u.obt.obt_lut->lut_tgd;
	seq_printf(m, "%llu\n", tgd->tgd_tot_granted);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_tot_granted);

/**
 * Show total amount of space used by IO in progress.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_tot_pending_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct tg_grants_data *tgd;

	LASSERT(obd != NULL);
	tgd = &obd->u.obt.obt_lut->lut_tgd;
	seq_printf(m, "%llu\n", tgd->tgd_tot_pending);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_tot_pending);

/**
 * Show total number of grants for precreate.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_grant_precreate_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	seq_printf(m, "%ld\n",
		   obd->obd_self_export->exp_target_data.ted_grant);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_grant_precreate);

/**
 * Show number of precreates allowed in a single transaction.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_precreate_batch_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd;

	LASSERT(obd != NULL);
	ofd = ofd_dev(obd->obd_lu_dev);
	seq_printf(m, "%d\n", ofd->ofd_precreate_batch);
	return 0;
}

/**
 * Change number of precreates allowed in a single transaction.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_precreate_batch_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 1 || val > INT_MAX)
		return -EINVAL;

	spin_lock(&ofd->ofd_batch_lock);
	ofd->ofd_precreate_batch = val;
	spin_unlock(&ofd->ofd_batch_lock);
	return count;
}
LPROC_SEQ_FOPS(ofd_precreate_batch);

/**
 * Show the last used ID for each FID sequence used by OFD.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_last_id_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd;
	struct ofd_seq		*oseq = NULL;

	if (obd == NULL)
		return 0;

	ofd = ofd_dev(obd->obd_lu_dev);

	read_lock(&ofd->ofd_seq_list_lock);
	list_for_each_entry(oseq, &ofd->ofd_seq_list, os_list) {
		__u64 seq;

		seq = ostid_seq(&oseq->os_oi) == 0 ?
		      fid_idif_seq(ostid_id(&oseq->os_oi),
				   ofd->ofd_lut.lut_lsd.lsd_osd_index) :
		      ostid_seq(&oseq->os_oi);
		seq_printf(m, DOSTID"\n", seq, ostid_id(&oseq->os_oi));
	}
	read_unlock(&ofd->ofd_seq_list_lock);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_last_id);

/**
 * Show maximum number of Filter Modification Data (FMD) maintained by OFD.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_fmd_max_num_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", ofd->ofd_fmd_max_num);
	return 0;
}

/**
 * Change number of FMDs maintained by OFD.
 *
 * This defines how large the list of FMDs can be.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_fmd_max_num_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 65536 || val < 1)
		return -EINVAL;

	ofd->ofd_fmd_max_num = val;
	return count;
}
LPROC_SEQ_FOPS(ofd_fmd_max_num);

/**
 * Show the maximum age of FMD data in seconds.
 *
 * Though it is shown in seconds, it is stored internally in units
 * of jiffies for efficiency.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_fmd_max_age_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "%ld\n", jiffies_to_msecs(ofd->ofd_fmd_max_age) /
		   MSEC_PER_SEC);
	return 0;
}

/**
 * Set the maximum age of FMD data in seconds.
 *
 * This defines how long FMD data stays in the FMD list.
 * It is stored internally in units of jiffies for efficiency.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents maximum number
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_fmd_max_age_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file		*m = file->private_data;
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);
	__s64			 val;
	int			 rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val > 65536 || val < 1)
		return -EINVAL;

	ofd->ofd_fmd_max_age = msecs_to_jiffies(val * MSEC_PER_SEC);
	return count;
}
LPROC_SEQ_FOPS(ofd_fmd_max_age);

/**
 * Show if the OFD is in degraded mode.
 *
 * Degraded means OFD has a failed drive or is undergoing RAID rebuild.
 * The MDS will try to avoid using this OST for new object allocations
 * to reduce the impact to global IO performance when clients writing to
 * this OST are slowed down.  It also reduces the contention on the OST
 * RAID device, allowing it to rebuild more quickly.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_degraded_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", ofd->ofd_raid_degraded);
	return 0;
}

/**
 * Set OFD to degraded mode.
 *
 * This is used to interface to userspace administrative tools for
 * the underlying RAID storage, so that they can mark an OST
 * as having degraded performance.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents mode
 *			1: set degraded mode
 *			0: unset degraded mode
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_degraded_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	int rc;
	__s64 val;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_raid_degraded = !!val;
	spin_unlock(&ofd->ofd_flags_lock);
	return count;
}
LPROC_SEQ_FOPS(ofd_degraded);

/**
 * Show OFD filesystem type.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_fstype_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct lu_device  *d;

	LASSERT(ofd->ofd_osd);
	d = &ofd->ofd_osd->dd_lu_dev;
	LASSERT(d->ld_type);
	seq_printf(m, "%s\n", d->ld_type->ldt_name);
	return 0;
}
LPROC_SEQ_FOPS_RO(ofd_fstype);

/**
 * Show journal handling mode: synchronous or asynchronous.
 *
 * When running in asynchronous mode the journal transactions are not
 * committed to disk before the RPC is replied back to the client.
 * This will typically improve client performance when only a small number
 * of clients are writing, since the client(s) can have more write RPCs
 * in flight. However, it also means that the client has to handle recovery
 * on bulk RPCs, and will have to keep more dirty pages in cache before they
 * are committed on the OST.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_syncjournal_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", ofd->ofd_syncjournal);
	return 0;
}

/**
 * Set journal mode to synchronous or asynchronous.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents mode
 *			1: synchronous mode
 *			0: asynchronous mode
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_syncjournal_seq_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *off)
{
	struct seq_file	*m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -EINVAL;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_syncjournal = !!val;
	ofd_slc_set(ofd);
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LPROC_SEQ_FOPS(ofd_syncjournal);

/* This must be longer than the longest string below */
#define SYNC_STATES_MAXLEN 16

static int ofd_brw_size_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "%u\n", ofd->ofd_brw_size / ONE_MB_BRW_SIZE);
	return 0;
}

static ssize_t
ofd_brw_size_seq_write(struct file *file, const char __user *buffer,
		       size_t count, loff_t *off)
{
	struct seq_file	*m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_with_units_to_s64(buffer, count, &val, 'M');
	if (rc)
		return rc;

	if (val <= 0)
		return -EINVAL;

	if (val > DT_MAX_BRW_SIZE ||
	    val < (1 << ofd->ofd_lut.lut_tgd.tgd_blockbits))
		return -ERANGE;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_brw_size = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LPROC_SEQ_FOPS(ofd_brw_size);

static char *sync_on_cancel_states[] = {"never",
					"blocking",
					"always" };

/**
 * Show OFD policy for handling dirty data under a lock being cancelled.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_sync_lock_cancel_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct lu_target	*tgt = obd->u.obt.obt_lut;

	seq_printf(m, "%s\n",
		   sync_on_cancel_states[tgt->lut_sync_lock_cancel]);
	return 0;
}

/**
 * Change OFD policy for handling dirty data under a lock being cancelled.
 *
 * This variable defines what action OFD takes upon lock cancel
 * There are three possible modes:
 * 1) never - never do sync upon lock cancel. This can lead to data
 *    inconsistencies if both the OST and client crash while writing a file
 *    that is also concurrently being read by another client. In these cases,
 *    this may allow the file data to "rewind" to an earlier state.
 * 2) blocking - do sync only if there is blocking lock, e.g. if another
 *    client is trying to access this same object
 * 3) always - do sync always
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents policy
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_sync_lock_cancel_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct lu_target *tgt = obd->u.obt.obt_lut;
	char kernbuf[SYNC_STATES_MAXLEN];
	__s64 val = -1;
	int i;

	if (count == 0 || count >= sizeof(kernbuf))
		return -EINVAL;

	if (copy_from_user(kernbuf, buffer, count))
		return -EFAULT;
	kernbuf[count] = 0;

	if (kernbuf[count - 1] == '\n')
		kernbuf[count - 1] = 0;

	for (i = 0 ; i < NUM_SYNC_ON_CANCEL_STATES; i++) {
		if (strcmp(kernbuf, sync_on_cancel_states[i]) == 0) {
			val = i;
			break;
		}
	}

	/* Legacy numeric codes */
	if (val == -1) {
		int rc = lprocfs_str_to_s64(buffer, count, &val);
		if (rc)
			return rc;
	}

	if (val < 0 || val > 2)
		return -EINVAL;

	spin_lock(&tgt->lut_flags_lock);
	tgt->lut_sync_lock_cancel = val;
	spin_unlock(&tgt->lut_flags_lock);
	return count;
}
LPROC_SEQ_FOPS(ofd_sync_lock_cancel);

/**
 * Show if grants compatibility mode is disabled.
 *
 * When tgd_grant_compat_disable is set, we don't grant any space to clients
 * not supporting OBD_CONNECT_GRANT_PARAM. Otherwise, space granted to such
 * a client is inflated since it consumes PAGE_SIZE of grant space per
 * block, (i.e. typically 4kB units), but underlaying file system might have
 * block size bigger than page size, e.g. ZFS. See LU-2049 for details.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_grant_compat_disable_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct tg_grants_data *tgd = &obd->u.obt.obt_lut->lut_tgd;

	seq_printf(m, "%u\n", tgd->tgd_grant_compat_disable);
	return 0;
}

/**
 * Change grant compatibility mode.
 *
 * Setting tgd_grant_compat_disable prohibit any space granting to clients
 * not supporting OBD_CONNECT_GRANT_PARAM. See details above.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents mode
 *			1: disable compatibility mode
 *			0: enable compatibility mode
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_grant_compat_disable_seq_write(struct file *file,
				   const char __user *buffer,
				   size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct tg_grants_data *tgd = &obd->u.obt.obt_lut->lut_tgd;
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < 0)
		return -EINVAL;

	tgd->tgd_grant_compat_disable = !!val;

	return count;
}
LPROC_SEQ_FOPS(ofd_grant_compat_disable);

/**
 * Show the limit of soft sync RPCs.
 *
 * This value defines how many IO RPCs with OBD_BRW_SOFT_SYNC flag
 * are allowed before sync update will be triggered.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_soft_sync_limit_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	return lprocfs_uint_seq_show(m, &ofd->ofd_soft_sync_limit);
}

/**
 * Change the limit of soft sync RPCs.
 *
 * Define how many IO RPCs with OBD_BRW_SOFT_SYNC flag
 * allowed before sync update will be done.
 *
 * This limit is global across all exports.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents limit
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_soft_sync_limit_seq_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *off)
{
	struct seq_file	  *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return lprocfs_uint_seq_write(file, buffer, count,
				      (loff_t *) &ofd->ofd_soft_sync_limit);
}
LPROC_SEQ_FOPS(ofd_soft_sync_limit);

/**
 * Show the LFSCK speed limit.
 *
 * The maximum number of items scanned per second.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_lfsck_speed_limit_seq_show(struct seq_file *m, void *data)
{
	struct obd_device       *obd = m->private;
	struct ofd_device	*ofd = ofd_dev(obd->obd_lu_dev);

	return lfsck_get_speed(m, ofd->ofd_osd);
}

/**
 * Change the LFSCK speed limit.
 *
 * Limit number of items that may be scanned per second.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents limit
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_lfsck_speed_limit_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc != 0)
		return rc;

	if (val < 0)
		return -ERANGE;

	rc = lfsck_set_speed(ofd->ofd_osd, val);

	return rc != 0 ? rc : count;
}
LPROC_SEQ_FOPS(ofd_lfsck_speed_limit);

/**
 * Show LFSCK layout verification stats from the most recent LFSCK run.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_lfsck_layout_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return lfsck_dump(m, ofd->ofd_osd, LFSCK_TYPE_LAYOUT);
}
LPROC_SEQ_FOPS_RO(ofd_lfsck_layout);

/**
 * Show if LFSCK performed parent FID verification.
 *
 * \param[in] m		seq_file handle
 * \param[in] data	unused for single entry
 *
 * \retval		0 on success
 * \retval		negative value on error
 */
static int ofd_lfsck_verify_pfid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	seq_printf(m, "switch: %s\ndetected: %llu\nrepaired: %llu\n",
		   ofd->ofd_lfsck_verify_pfid ? "on" : "off",
		   ofd->ofd_inconsistency_self_detected,
		   ofd->ofd_inconsistency_self_repaired);
	return 0;
}

/**
 * Set the LFSCK behavior to verify parent FID correctness.
 *
 * If flag ofd_lfsck_verify_pfid is set then LFSCK does parent FID
 * verification during read/write operations.
 *
 * \param[in] file	proc file
 * \param[in] buffer	string which represents behavior
 *			1: verify parent FID
 *			0: don't verify parent FID
 * \param[in] count	\a buffer length
 * \param[in] off	unused for single entry
 *
 * \retval		\a count on success
 * \retval		negative number on error
 */
static ssize_t
ofd_lfsck_verify_pfid_seq_write(struct file *file, const char __user *buffer,
				size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	__s64 val;
	int rc;

	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc != 0)
		return rc;

	ofd->ofd_lfsck_verify_pfid = !!val;
	if (!ofd->ofd_lfsck_verify_pfid) {
		ofd->ofd_inconsistency_self_detected = 0;
		ofd->ofd_inconsistency_self_repaired = 0;
	}

	return count;
}
LPROC_SEQ_FOPS(ofd_lfsck_verify_pfid);

static int ofd_site_stats_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	return lu_site_stats_seq_print(obd->obd_lu_dev->ld_site, m);
}
LPROC_SEQ_FOPS_RO(ofd_site_stats);

LPROC_SEQ_FOPS_RO_TYPE(ofd, uuid);
LPROC_SEQ_FOPS_RO_TYPE(ofd, blksize);
LPROC_SEQ_FOPS_RO_TYPE(ofd, kbytestotal);
LPROC_SEQ_FOPS_RO_TYPE(ofd, kbytesfree);
LPROC_SEQ_FOPS_RO_TYPE(ofd, kbytesavail);
LPROC_SEQ_FOPS_RO_TYPE(ofd, filestotal);
LPROC_SEQ_FOPS_RO_TYPE(ofd, filesfree);

LPROC_SEQ_FOPS_RO_TYPE(ofd, recovery_status);
LPROC_SEQ_FOPS_RW_TYPE(ofd, recovery_time_soft);
LPROC_SEQ_FOPS_RW_TYPE(ofd, recovery_time_hard);
LPROC_SEQ_FOPS_WO_TYPE(ofd, evict_client);
LPROC_SEQ_FOPS_RO_TYPE(ofd, num_exports);
LPROC_SEQ_FOPS_RO_TYPE(ofd, target_instance);
LPROC_SEQ_FOPS_RW_TYPE(ofd, ir_factor);
LPROC_SEQ_FOPS_RW_TYPE(ofd, checksum_dump);
LPROC_SEQ_FOPS_RW_TYPE(ofd, job_interval);

struct lprocfs_vars lprocfs_ofd_obd_vars[] = {
	{ .name =	"uuid",
	  .fops =	&ofd_uuid_fops			},
	{ .name =	"blocksize",
	  .fops =	&ofd_blksize_fops		},
	{ .name =	"kbytestotal",
	  .fops =	&ofd_kbytestotal_fops		},
	{ .name =	"kbytesfree",
	  .fops =	&ofd_kbytesfree_fops		},
	{ .name =	"kbytesavail",
	  .fops =	&ofd_kbytesavail_fops		},
	{ .name =	"filestotal",
	  .fops =	&ofd_filestotal_fops		},
	{ .name =	"filesfree",
	  .fops =	&ofd_filesfree_fops		},
	{ .name =	"seqs_allocated",
	  .fops =	&ofd_seqs_fops			},
	{ .name =	"fstype",
	  .fops =	&ofd_fstype_fops		},
	{ .name =	"last_id",
	  .fops =	&ofd_last_id_fops		},
	{ .name =	"tot_dirty",
	  .fops =	&ofd_tot_dirty_fops		},
	{ .name =	"tot_pending",
	  .fops =	&ofd_tot_pending_fops		},
	{ .name =	"tot_granted",
	  .fops =	&ofd_tot_granted_fops		},
	{ .name =	"grant_precreate",
	  .fops =	&ofd_grant_precreate_fops	},
	{ .name =	"precreate_batch",
	  .fops =	&ofd_precreate_batch_fops	},
	{ .name =	"recovery_status",
	  .fops =	&ofd_recovery_status_fops	},
	{ .name =	"recovery_time_soft",
	  .fops =	&ofd_recovery_time_soft_fops	},
	{ .name =	"recovery_time_hard",
	  .fops =	&ofd_recovery_time_hard_fops	},
	{ .name =	"evict_client",
	  .fops =	&ofd_evict_client_fops		},
	{ .name =	"num_exports",
	  .fops =	&ofd_num_exports_fops		},
	{ .name =	"degraded",
	  .fops =	&ofd_degraded_fops		},
	{ .name =	"sync_journal",
	  .fops =	&ofd_syncjournal_fops		},
	{ .name =	"brw_size",
	  .fops =	&ofd_brw_size_fops		},
	{ .name =	"sync_on_lock_cancel",
	  .fops =	&ofd_sync_lock_cancel_fops	},
	{ .name =	"instance",
	  .fops =	&ofd_target_instance_fops	},
	{ .name =	"ir_factor",
	  .fops =	&ofd_ir_factor_fops		},
	{ .name =	"checksum_dump",
	  .fops =	&ofd_checksum_dump_fops		},
	{ .name =	"grant_compat_disable",
	  .fops =	&ofd_grant_compat_disable_fops	},
	{ .name =	"client_cache_count",
	  .fops =	&ofd_fmd_max_num_fops		},
	{ .name =	"client_cache_seconds",
	  .fops =	&ofd_fmd_max_age_fops		},
	{ .name =	"job_cleanup_interval",
	  .fops =	&ofd_job_interval_fops		},
	{ .name =	"soft_sync_limit",
	  .fops =	&ofd_soft_sync_limit_fops	},
	{ .name =	"lfsck_speed_limit",
	  .fops =	&ofd_lfsck_speed_limit_fops	},
	{ .name =	"lfsck_layout",
	  .fops =	&ofd_lfsck_layout_fops		},
	{ .name	=	"lfsck_verify_pfid",
	  .fops	=	&ofd_lfsck_verify_pfid_fops	},
	{ .name =	"site_stats",
	  .fops =	&ofd_site_stats_fops		},
	{ NULL }
};

/**
 * Initialize OFD statistics counters
 *
 * param[in] stats	statistics counters
 */
void ofd_stats_counter_init(struct lprocfs_stats *stats)
{
	LASSERT(stats && stats->ls_num >= LPROC_OFD_STATS_LAST);

	lprocfs_counter_init(stats, LPROC_OFD_STATS_READ,
			     LPROCFS_CNTR_AVGMINMAX, "read_bytes", "bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_WRITE,
			     LPROCFS_CNTR_AVGMINMAX, "write_bytes", "bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_GETATTR,
			     0, "getattr", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SETATTR,
			     0, "setattr", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_PUNCH,
			     0, "punch", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SYNC,
			     0, "sync", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_DESTROY,
			     0, "destroy", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_CREATE,
			     0, "create", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_STATFS,
			     0, "statfs", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_GET_INFO,
			     0, "get_info", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SET_INFO,
			     0, "set_info", "reqs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_QUOTACTL,
			     0, "quotactl", "reqs");
}

#endif /* CONFIG_PROC_FS */
