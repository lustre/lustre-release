// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <uapi/linux/lustre/lustre_access_log.h>
#include <obd_cksum.h>

#include "ofd_internal.h"

#ifdef CONFIG_PROC_FS

/**
 * seqs_allocated_show() - Show number of FID allocation sequences.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t seqs_allocated_show(struct kobject *kobj, struct attribute *attr,
				   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return sprintf(buf, "%u\n", ofd->ofd_seq_count);
}
LUSTRE_RO_ATTR(seqs_allocated);

/**
 * grant_precreate_show() - Show total number of grants for precreate.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t grant_precreate_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);

	return sprintf(buf, "%ld\n",
		       obd->obd_self_export->exp_target_data.ted_grant);
}
LUSTRE_RO_ATTR(grant_precreate);

/**
 * precreate_batch_show() - Show number of precreates allowed in a single
 *                          transaction.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t precreate_batch_show(struct kobject *kobj,
				    struct attribute *attr,
				    char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return sprintf(buf, "%d\n", ofd->ofd_precreate_batch);
}

/**
 * precreate_batch_store() - Change number of precreates allowed in a single
 *                           transaction.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents precreate
 * @count: @buffer length
 *
 * Return:
 * * %count on success
 * * %negative number on error
 */
static ssize_t precreate_batch_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val < 1 || val > 65536)
		return -EINVAL;

	spin_lock(&ofd->ofd_batch_lock);
	ofd->ofd_precreate_batch = val;
	spin_unlock(&ofd->ofd_batch_lock);
	return count;
}
LUSTRE_RW_ATTR(precreate_batch);

/**
 * atime_diff_show() - Show number of seconds to delay atime
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t atime_diff_show(struct kobject *kobj, struct attribute *attr,
			       char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%lld\n", ofd->ofd_atime_diff);
}

/**
 * atime_diff_store() - Change number of seconds to delay atime
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents dealy in seconds
 * @count: @buffer length
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t atime_diff_store(struct kobject *kobj, struct attribute *attr,
				const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc)
		return rc;

	if (val > 86400)
		return -EINVAL;

	ofd->ofd_atime_diff = val;
	return count;
}
LUSTRE_RW_ATTR(atime_diff);

/**
 * last_id_seq_show() - Show the last used ID for each FID sequence used by OFD.
 * @m: seq_file handle
 * @data: unused for single entry
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static int last_id_seq_show(struct seq_file *m, void *data)
{
	struct obd_device	*obd = m->private;
	struct ofd_device	*ofd;
	struct ofd_seq		*oseq = NULL;

	if (obd == NULL)
		return 0;

	ofd = ofd_dev(obd->obd_lu_dev);
	if (IS_ERR_OR_NULL(ofd))
		return -ENODEV;

	read_lock(&ofd->ofd_seq_list_lock);
	list_for_each_entry(oseq, &ofd->ofd_seq_list, os_list) {
		__u64 seq;

		seq = ostid_seq(&oseq->os_oi) == 0 ?
		      fid_idif_seq(ostid_id(&oseq->os_oi),
				ofd->ofd_lut.lut_lsd.lsd_osd_index) & ~0xFFFF :
				ostid_seq(&oseq->os_oi);
		seq_printf(m, DOSTID"\n", seq, ostid_id(&oseq->os_oi));
	}
	read_unlock(&ofd->ofd_seq_list_lock);
	return 0;
}

LDEBUGFS_SEQ_FOPS_RO(last_id);

/**
 * degraded_show() - Show if the OFD is in degraded mode.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Degraded means OFD has a failed drive or is undergoing RAID rebuild.
 * The MDS will try to avoid using this OST for new object allocations
 * to reduce the impact to global IO performance when clients writing to
 * this OST are slowed down.  It also reduces the contention on the OST
 * RAID device, allowing it to rebuild more quickly.
 *
 * Returns count of bytes written
 */
static ssize_t degraded_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return sprintf(buf, "%u\n", ofd->ofd_raid_degraded);
}

/**
 * degraded_store() - Set OFD to degraded mode.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents degraded
 * @count: @buffer length
 *
 * This is used to interface to userspace administrative tools for
 * the underlying RAID storage, so that they can mark an OST
 * as having degraded performance.
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t degraded_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_raid_degraded = val;
	spin_unlock(&ofd->ofd_flags_lock);
	return count;
}
LUSTRE_RW_ATTR(degraded);

/**
 * enable_resource_id_check_show() - Show if resource ID checking is enabled
 * on the OST.
 *
 * @kobj: kobject for the OFD device
 * @attr: attribute for the OFD device
 * @buf: buffer to write the value to
 *
 * When enabled, an OST object's UID and GID are checked against
 * the nodemap mapping rules.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static ssize_t enable_resource_id_check_show(struct kobject *kobj,
					     struct attribute *attr, char *buf)
{
	struct obd_device *obd =
		container_of(kobj, struct obd_device, obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 ofd->ofd_lut.lut_enable_resource_id_check);
}

/**
 * enable_resource_id_check_store() - Enable or disable resource ID checking
 * on the OST.
 * @kobj: kobject for the OFD device
 * @attr: attribute for the OFD device
 * @buffer: buffer containing the value to set
 * @count: length of the buffer
 *
 * This is used to interface to userspace administrative tools to enable
 * or disable resource ID checking on the OST.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static ssize_t enable_resource_id_check_store(struct kobject *kobj,
					      struct attribute *attr,
					      const char *buffer, size_t count)
{
	struct obd_device *obd =
		container_of(kobj, struct obd_device, obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_lut.lut_enable_resource_id_check = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(enable_resource_id_check);

/**
 * enable_resource_id_repair_show() - Show if resource ID repair is enabled
 * on the OST.
 *
 * @kobj: kobject for the OFD device
 * @attr: attribute for the OFD device
 * @buf: buffer to write the value to
 *
 * When enabled, an OST object's UID/GID/PROJID are repaired if they are unset.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static ssize_t enable_resource_id_repair_show(struct kobject *kobj,
					      struct attribute *attr, char *buf)
{
	struct obd_device *obd =
		container_of(kobj, struct obd_device, obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 ofd->ofd_enable_resource_id_repair);
}

/**
 * enable_resource_id_repair_store() - Enable or disable resource ID repair
 * on the OST.
 *
 * @kobj: kobject for the OFD device
 * @attr: attribute for the OFD device
 * @buffer: buffer containing the value to set
 * @count: length of the buffer
 *
 * This is used to interface to userspace administrative tools to enable
 * or disable resource ID repair on the OST.
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static ssize_t enable_resource_id_repair_store(struct kobject *kobj,
					       struct attribute *attr,
					       const char *buffer, size_t count)
{
	struct obd_device *obd =
		container_of(kobj, struct obd_device, obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_enable_resource_id_repair = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(enable_resource_id_repair);

/**
 * resource_id_repair_queue_count_show() - Show the resource ID repair queue size
 *
 * @kobj: kobject for the OFD device
 * @attr: attribute for the OFD device
 * @buf: buffer to write the value to
 *
 * Return:
 * * %0 on success
 * * %negative on failure
 */
static ssize_t resource_id_repair_queue_count_show(struct kobject *kobj,
						   struct attribute *attr,
						   char *buf)
{
	struct obd_device *obd =
		container_of(kobj, struct obd_device, obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n",
			 ofd->ofd_id_repair_queue_count);
}

/**
 * resource_id_repair_queue_count_store() - Set resource ID repair queue size
 * @kobj: kobject for the OFD device
 * @attr: attribute for the OFD device
 * @buffer: buffer containing the value to set
 * @count: length of the buffer
 *
 * This is used to interface to userspace administrative tools to set the number
 * of queued repair requests.
 *
 * Return:
 * * %0 on success
 * * %-ERANGE if the value is out of range must be in
 *   [1, OFD_ID_REPAIR_QUEUE_COUNT_LIMIT]
 * * %negative on failure
 */
static ssize_t resource_id_repair_queue_count_store(struct kobject *kobj,
						    struct attribute *attr,
						    const char *buffer,
						    size_t count)
{
	struct obd_device *obd =
		container_of(kobj, struct obd_device, obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 10, &val);
	if (rc)
		return rc;

	if (val < 1 || val > OFD_ID_REPAIR_QUEUE_COUNT_LIMIT)
		return -ERANGE;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_id_repair_queue_count = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(resource_id_repair_queue_count);

/**
 * no_create_show() - Show if the OFD is in no precreate mode.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * This means OFD has been adminstratively disabled at the OST to prevent
 * the MDS from creating any new files on the OST, though existing files
 * can still be read, written, and unlinked.
 *
 * Returns number of bytes written
 */
static ssize_t no_create_show(struct kobject *kobj, struct attribute *attr,
				 char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", ofd->ofd_lut.lut_no_create);
}

/**
 * no_create_store() - Set OFD to no create mode.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents dealy in seconds
 * @count: @buffer length
 *
 * This is used to interface to userspace administrative tools to
 * disable new object creation on the OST.
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t no_create_store(struct kobject *kobj, struct attribute *attr,
				  const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_lut.lut_no_create = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(no_create);

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 20, 53, 0)
/* compatibility entry for a few releases */
#define no_precreate_show no_create_show
#define no_precreate_store no_create_store
LUSTRE_RW_ATTR(no_precreate);
#endif

/**
 * readonly_show() - Show if the OFD is in read-only mode.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * This means OFD has been adminstratively disabled at the OST to prevent
 * writing to the OFD.
 *
 * Returns number of bytes written
 */
static ssize_t readonly_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", ofd->ofd_readonly);
}

/**
 * readonly_store() - Set OFD to readonly mode.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents OST read-only
 * @count: @buffer length
 *
 * This is used to interface to userspace administrative tools to
 * set the OST read-only.
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t readonly_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_readonly = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(readonly);

/**
 * fstype_show() - Show OFD filesystem type.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t fstype_show(struct kobject *kobj, struct attribute *attr,
			   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct lu_device  *d;

	LASSERT(ofd->ofd_osd);
	d = &ofd->ofd_osd->dd_lu_dev;
	LASSERT(d->ld_type);
	return sprintf(buf, "%s\n", d->ld_type->ldt_name);
}
LUSTRE_RO_ATTR(fstype);

/**
 * sync_journal_show() - Show journal handling mode: synchronous or asynchronous
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * When running in asynchronous mode the journal transactions are not
 * committed to disk before the RPC is replied back to the client.
 * This will typically improve client performance when only a small number
 * of clients are writing, since the client(s) can have more write RPCs
 * in flight. However, it also means that the client has to handle recovery
 * on bulk RPCs, and will have to keep more dirty pages in cache before they
 * are committed on the OST.
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t sync_journal_show(struct kobject *kobj, struct attribute *attr,
				char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return sprintf(buf, "%u\n", ofd->ofd_sync_journal);
}

/**
 * sync_journal_store() - Set journal mode to synchronous or asynchronous.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents modes
 *          1: synchronous mode
 *          0: asynchronous mode
 * @count: @buffer length
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t sync_journal_store(struct kobject *kobj, struct attribute *attr,
				 const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	rc = kstrtobool(buffer, &val);
	if (rc)
		return rc;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_sync_journal = val;
	ofd_slc_set(ofd);
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(sync_journal);

static ssize_t brw_size_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	if (IS_ERR_OR_NULL(ofd))
		return -ENODEV;

	return  scnprintf(buf, PAGE_SIZE, "%u\n",
			  ofd->ofd_brw_size / ONE_MB_BRW_SIZE);
}

static ssize_t brw_size_store(struct kobject *kobj, struct attribute *attr,
			      const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	u64 val;
	int rc;

	if (IS_ERR_OR_NULL(ofd))
		return -ENODEV;

	rc = sysfs_memparse(buffer, count, &val, "MiB");
	if (rc < 0)
		return rc;

	if (val == 0)
		return -EINVAL;

	if (val > DT_MAX_BRW_SIZE ||
	    val < (1 << ofd->ofd_lut.lut_tgd.tgd_blockbits))
		return -ERANGE;

	spin_lock(&ofd->ofd_flags_lock);
	ofd->ofd_brw_size = val;
	spin_unlock(&ofd->ofd_flags_lock);

	return count;
}
LUSTRE_RW_ATTR(brw_size);

/**
 * soft_sync_limit_show() - Show the limit of soft sync RPCs.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * This value defines how many IO RPCs with OBD_BRW_SOFT_SYNC flag
 * are allowed before sync update will be triggered.
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t soft_sync_limit_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return sprintf(buf, "%u\n", ofd->ofd_soft_sync_limit);
}

/**
 * soft_sync_limit_store() - Change the limit of soft sync RPCs.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents dealy in seconds
 * @count: @buffer length
 *
 * Define how many IO RPCs with OBD_BRW_SOFT_SYNC flag
 * allowed before sync update will be done.
 *
 * This limit is global across all exports.
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t soft_sync_limit_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc < 0)
		return rc;

	ofd->ofd_soft_sync_limit = val;
	return count;
}
LUSTRE_RW_ATTR(soft_sync_limit);

/**
 * lfsck_speed_limit_show() - Show the LFSCK speed limit.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t lfsck_speed_limit_show(struct kobject *kobj,
				      struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return lfsck_get_speed(buf, ofd->ofd_osd);
}

/**
 * lfsck_speed_limit_store() - Change the LFSCK speed limit.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents speed (e.g., "1000").
 * @count: @buffer length
 *
 * Limit number of items that may be scanned per second.
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t lfsck_speed_limit_store(struct kobject *kobj,
				       struct attribute *attr,
				       const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	unsigned int val;
	int rc;

	rc = kstrtouint(buffer, 0, &val);
	if (rc != 0)
		return rc;

	rc = lfsck_set_speed(ofd->ofd_osd, val);

	return rc != 0 ? rc : count;
}
LUSTRE_RW_ATTR(lfsck_speed_limit);

/**
 * lfsck_layout_seq_show() - Show LFSCK layout verification stats from the most
 *                           recent LFSCK run.
 * @m: seq_file handle
 * @data: unused for single entry
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static int lfsck_layout_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	if (IS_ERR_OR_NULL(ofd))
		return -ENODEV;

	return lfsck_dump(m, ofd->ofd_osd, LFSCK_TYPE_LAYOUT);
}

LDEBUGFS_SEQ_FOPS_RO(lfsck_layout);

/**
 * lfsck_verify_pfid_seq_show() - Show if LFSCK performed parent FID
 *                                verification.
 * @m: seq_file handle
 * @data: unused for single entry
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static int lfsck_verify_pfid_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	if (IS_ERR_OR_NULL(ofd))
		return -ENODEV;

	seq_printf(m, "switch: %s\ndetected: %llu\nrepaired: %llu\n",
		   ofd->ofd_lfsck_verify_pfid ? "on" : "off",
		   ofd->ofd_inconsistency_self_detected,
		   ofd->ofd_inconsistency_self_repaired);
	return 0;
}

/**
 * lfsck_verify_pfid_seq_write() - Set the LFSCK behavior to verify parent FID
 *                                 correctness.
 * @file: proc file
 * @buffer: string which represents behavior
 *          1: verify parent FID
 *          0: don't verify parent FID
 * @count: @buffer length
 * @off: unused for single entry
 *
 * If flag ofd_lfsck_verify_pfid is set then LFSCK does parent FID
 * verification during read/write operations.
 *
 * Return:
 * * %@count on success
 * * %negative number on error
 */
static ssize_t
lfsck_verify_pfid_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	bool val;
	int rc;

	if (IS_ERR_OR_NULL(ofd))
		return -ENODEV;

	rc = kstrtobool_from_user(buffer, count, &val);
	if (rc)
		return rc;

	ofd->ofd_lfsck_verify_pfid = val;
	if (!ofd->ofd_lfsck_verify_pfid) {
		ofd->ofd_inconsistency_self_detected = 0;
		ofd->ofd_inconsistency_self_repaired = 0;
	}

	return count;
}

LDEBUGFS_SEQ_FOPS(lfsck_verify_pfid);

static ssize_t access_log_mask_show(struct kobject *kobj,
			struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%s%s%s\n",
		(ofd->ofd_access_log_mask == 0) ? "0" : "",
		(ofd->ofd_access_log_mask & OFD_ACCESS_READ) ? "r" : "",
		(ofd->ofd_access_log_mask & OFD_ACCESS_WRITE) ? "w" : "");
}

static ssize_t access_log_mask_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	unsigned int mask = 0;
	size_t i;

	for (i = 0; i < count; i++) {
		switch (tolower(buffer[i])) {
		case '0':
			break;
		case 'r':
			mask |= OFD_ACCESS_READ;
			break;
		case 'w':
			mask |= OFD_ACCESS_WRITE;
			break;
		default:
			return -EINVAL;
		}
	}

	ofd->ofd_access_log_mask = mask;

	return count;
}
LUSTRE_RW_ATTR(access_log_mask);

static ssize_t access_log_size_show(struct kobject *kobj,
				    struct attribute *attr, char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", ofd->ofd_access_log_size);
}

static ssize_t access_log_size_store(struct kobject *kobj,
				     struct attribute *attr,
				     const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct ofd_device *ofd = ofd_dev(obd->obd_lu_dev);
	struct ofd_access_log *oal;
	unsigned int size;
	ssize_t rc;

	rc = kstrtouint(buffer, 0, &size);
	if (rc < 0)
		return rc;

	if (!ofd_access_log_size_is_valid(size))
		return -EINVAL;

	/* The size of the ofd_access_log cannot be changed after it
	 * has been created.
	 */
	if (ofd->ofd_access_log_size == size)
		return count;

	oal = ofd_access_log_create(obd->obd_name, size);
	if (IS_ERR(oal))
		return PTR_ERR(oal);

	spin_lock(&ofd->ofd_flags_lock);
	if (ofd->ofd_access_log != NULL) {
		rc = -EBUSY;
	} else {
		ofd->ofd_access_log = oal;
		ofd->ofd_access_log_size = size;
		oal = NULL;
		rc = count;
	}
	spin_unlock(&ofd->ofd_flags_lock);

	ofd_access_log_delete(oal);

	return rc;
}
LUSTRE_RW_ATTR(access_log_size);

static int site_stats_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	return lu_site_stats_seq_print(obd->obd_lu_dev->ld_site, m);
}

LDEBUGFS_SEQ_FOPS_RO(site_stats);

/**
 * checksum_t10pi_enforce_show() - Show if the OFD enforces T10PI checksum.
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buf: buffer where the output string will be written [out]
 *
 * Return:
 * * %0 on success
 * * %negative value on error
 */
static ssize_t checksum_t10pi_enforce_show(struct kobject *kobj,
					   struct attribute *attr,
					   char *buf)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;

	return scnprintf(buf, PAGE_SIZE, "%u\n", lut->lut_cksum_t10pi_enforce);
}

/**
 * checksum_t10pi_enforce_store() - Force specific T10PI checksum modes to be
 *                                  enabled
 * @kobj: Kernel object (OFD device)
 * @attr: Pointer to struct attribute
 * @buffer: string which represents mode
 *          1: set T10PI checksums enforced
 *          0: unset T10PI checksums enforced
 * @count: @buffer length
 *
 * If T10PI *is* supported in hardware, allow only the supported T10PI type
 * to be used. If T10PI is *not* supported by the OSD, setting the enforce
 * parameter forces all T10PI types to be enabled (even if slower) for
 * testing.
 *
 * The final determination of which algorithm to be used depends whether
 * the client supports T10PI or not, and is handled at client connect time.
 *
 * Return:
 * * %count on success
 * * %negative number on error
 */
static ssize_t checksum_t10pi_enforce_store(struct kobject *kobj,
					    struct attribute *attr,
					    const char *buffer, size_t count)
{
	struct obd_device *obd = container_of(kobj, struct obd_device,
					      obd_kset.kobj);
	struct lu_target *lut = obd2obt(obd)->obt_lut;
	bool enforce;
	int rc;

	rc = kstrtobool(buffer, &enforce);
	if (rc)
		return rc;

	spin_lock(&lut->lut_flags_lock);
	lut->lut_cksum_t10pi_enforce = enforce;
	spin_unlock(&lut->lut_flags_lock);
	return count;
}
LUSTRE_RW_ATTR(checksum_t10pi_enforce);

LUSTRE_RW_ATTR(recovery_time_hard);
LUSTRE_RW_ATTR(recovery_time_soft);
LUSTRE_RW_ATTR(ir_factor);

LUSTRE_WO_ATTR(evict_client);
LUSTRE_ATTR(checksum_dump, 0644, dt_checksum_dump_show, dt_checksum_dump_store);
LUSTRE_ATTR(checksum_type, 0444, dt_checksum_type_show, NULL);
LUSTRE_RW_ATTR(job_cleanup_interval);

LUSTRE_RO_ATTR(tot_dirty);
LUSTRE_RO_ATTR(tot_granted);
LUSTRE_RO_ATTR(tot_pending);
LUSTRE_RW_ATTR(grant_compat_disable);
LUSTRE_RO_ATTR(instance);

LUSTRE_RO_ATTR(num_exports);
LUSTRE_RW_ATTR(grant_check_threshold);
LUSTRE_RO_ATTR(eviction_count);

LDEBUGFS_SEQ_FOPS_RO_TYPE(ofd, recovery_status);
LDEBUGFS_SEQ_FOPS_RO_TYPE(ofd, recovery_stale_clients);

static struct ldebugfs_vars ldebugfs_ofd_obd_vars[] = {
	{ .name =	"last_id",
	  .fops =	&last_id_fops			},
	{ .name =	"lfsck_layout",
	  .fops =	&lfsck_layout_fops		},
	{ .name	=	"lfsck_verify_pfid",
	  .fops	=	&lfsck_verify_pfid_fops	},
	{ .name =	"recovery_status",
	  .fops =	&ofd_recovery_status_fops	},
	{ .name =	"recovery_stale_clients",
	  .fops =	&ofd_recovery_stale_clients_fops},
	{ .name =	"site_stats",
	  .fops =	&site_stats_fops		},
	{ NULL }
};

LDEBUGFS_SEQ_FOPS_RO_TYPE(ofd, srpc_serverctx);

static struct ldebugfs_vars ldebugfs_ofd_gss_vars[] = {
	{ .name =	"srpc_serverctx",
	  .fops =	&ofd_srpc_serverctx_fops	},
	{ NULL }
};

/**
 * ofd_stats_counter_init() - Initialize OFD statistics counters
 * @stats: statistics counters
 * @offset:
 * @cntr_umask:
 */
void ofd_stats_counter_init(struct lprocfs_stats *stats, unsigned int offset,
			    enum lprocfs_counter_config cntr_umask)
{
	LASSERT(stats && stats->ls_num >= LPROC_OFD_STATS_LAST);

	lprocfs_counter_init(stats, LPROC_OFD_STATS_READ_BYTES,
			     LPROCFS_TYPE_BYTES_FULL_HISTOGRAM & (~cntr_umask),
			     "read_bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_WRITE_BYTES,
			     LPROCFS_TYPE_BYTES_FULL_HISTOGRAM & (~cntr_umask),
			     "write_bytes");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_READ,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "read");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_WRITE,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "write");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_GETATTR,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "getattr");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SETATTR,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "setattr");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_PUNCH,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "punch");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SYNC,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "sync");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_DESTROY,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "destroy");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_CREATE,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "create");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_STATFS,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "statfs");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_GET_INFO,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "get_info");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_SET_INFO,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "set_info");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_QUOTACTL,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "quotactl");
	lprocfs_counter_init(stats, LPROC_OFD_STATS_PREALLOC,
			     LPROCFS_TYPE_LATENCY & (~cntr_umask), "prealloc");
}

/* belongs to export directory */
LDEBUGFS_SEQ_FOPS_RW_TYPE(ofd, nid_stats_clear);

LUSTRE_OBD_UINT_PARAM_ATTR(at_min);
LUSTRE_OBD_UINT_PARAM_ATTR(at_max);
LUSTRE_OBD_UINT_PARAM_ATTR(at_history);

static struct attribute *ofd_attrs[] = {
	&lustre_attr_access_log_mask.attr,
	&lustre_attr_access_log_size.attr,
	&lustre_attr_atime_diff.attr,
	&lustre_attr_at_history.attr,
	&lustre_attr_at_max.attr,
	&lustre_attr_at_min.attr,
	&lustre_attr_brw_size.attr,
	&lustre_attr_checksum_dump.attr,
	&lustre_attr_checksum_t10pi_enforce.attr,
	&lustre_attr_checksum_type.attr,
	&lustre_attr_degraded.attr,
	&lustre_attr_enable_resource_id_check.attr,
	&lustre_attr_enable_resource_id_repair.attr,
	&lustre_attr_evict_client.attr,
	&lustre_attr_eviction_count.attr,
	&lustre_attr_fstype.attr,
	&lustre_attr_grant_check_threshold.attr,
	&lustre_attr_grant_compat_disable.attr,
	&lustre_attr_grant_precreate.attr,
	&lustre_attr_instance.attr,
	&lustre_attr_ir_factor.attr,
	&lustre_attr_job_cleanup_interval.attr,
	&lustre_attr_lfsck_speed_limit.attr,
	&lustre_attr_no_create.attr,
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 20, 53, 0)
	&lustre_attr_no_precreate.attr,
#endif
	&lustre_attr_num_exports.attr,
	&lustre_attr_precreate_batch.attr,
	&lustre_attr_readonly.attr,
	&lustre_attr_recovery_time_hard.attr,
	&lustre_attr_recovery_time_soft.attr,
	&lustre_attr_resource_id_repair_queue_count.attr,
	&lustre_attr_seqs_allocated.attr,
	&lustre_attr_tot_dirty.attr,
	&lustre_attr_tot_granted.attr,
	&lustre_attr_tot_pending.attr,
	&lustre_attr_soft_sync_limit.attr,
	&lustre_attr_sync_journal.attr,
	NULL,
};

KOBJ_ATTRIBUTE_GROUPS(ofd); /* creates ofd_groups from ofd_attrs */

/**
 * ofd_tunables_init() - Initialize all needed procfs entries for OFD device.
 * @ofd: OFD device
 *
 * Return:
 * * %0 if successful
 * * %negative value on error
 */
int ofd_tunables_init(struct ofd_device *ofd)
{
	struct obd_device *obd = ofd_obd(ofd);
	int rc = 0;

	ENTRY;
	/* lprocfs must be setup before the ofd so state can be safely added
	 * to /proc incrementally as the ofd is setup
	 */
	obd->obd_ktype.default_groups = KOBJ_ATTR_GROUPS(ofd);
	obd->obd_debugfs_vars = ldebugfs_ofd_obd_vars;
	rc = lprocfs_obd_setup(obd, false);
	if (rc) {
		CERROR("%s: lprocfs_obd_setup failed: %d.\n",
		       obd->obd_name, rc);
		RETURN(rc);
	}

	rc = tgt_tunables_init(&ofd->ofd_lut);
	if (rc) {
		CERROR("%s: tgt_tunables_init failed: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(obd_cleanup, rc);
	}

	rc = ldebugfs_alloc_obd_stats(obd, LPROC_OFD_STATS_LAST);
	if (rc) {
		CERROR("%s: lprocfs_alloc_obd_stats failed: %d.\n",
		       obd->obd_name, rc);
		GOTO(tgt_cleanup, rc);
	}

	obd->obd_debugfs_gss_dir = debugfs_create_dir("gss",
						      obd->obd_debugfs_entry);
	if (IS_ERR(obd->obd_debugfs_gss_dir))
		obd->obd_debugfs_gss_dir = NULL;

	ldebugfs_add_vars(obd->obd_debugfs_gss_dir,
			  ldebugfs_ofd_gss_vars, obd);

	obd->obd_debugfs_exports = debugfs_create_dir("exports",
						      obd->obd_debugfs_entry);
	if (IS_ERR(obd->obd_debugfs_exports))
		obd->obd_debugfs_exports = NULL;

	debugfs_create_file("clear", 0644, obd->obd_debugfs_exports,
			    obd, &ofd_nid_stats_clear_fops);

	ofd_stats_counter_init(obd->obd_stats, 0, LPROCFS_CNTR_HISTOGRAM);

	rc = lprocfs_job_stats_init(obd, LPROC_OFD_STATS_LAST,
				    ofd_stats_counter_init);
	if (rc)
		GOTO(obd_free_stats, rc);

	RETURN(0);

obd_free_stats:
	ldebugfs_free_obd_stats(obd);
tgt_cleanup:
	tgt_tunables_fini(&ofd->ofd_lut);
obd_cleanup:
	lprocfs_obd_cleanup(obd);

	return rc;
}
#endif /* CONFIG_PROC_FS */
