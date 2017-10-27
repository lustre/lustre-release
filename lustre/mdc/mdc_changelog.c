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
 * Copyright (c) 2017, Commissariat a l'Energie Atomique et aux Energies
 *                     Alternatives.
 *
 * Author: Henri Doreau <henri.doreau@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/miscdevice.h>

#include <lustre_log.h>

#include "mdc_internal.h"


/*
 * -- Changelog delivery through character device --
 */

/**
 * Mutex to protect chlg_registered_devices below
 */
static DEFINE_MUTEX(chlg_registered_dev_lock);

/**
 * Global linked list of all registered devices (one per MDT).
 */
static LIST_HEAD(chlg_registered_devices);


struct chlg_registered_dev {
	/* Device name of the form "changelog-{MDTNAME}" */
	char			ced_name[32];
	/* Misc device descriptor */
	struct miscdevice	ced_misc;
	/* OBDs referencing this device (multiple mount point) */
	struct list_head	ced_obds;
	/* Reference counter for proper deregistration */
	struct kref		ced_refs;
	/* Link within the global chlg_registered_devices */
	struct list_head	ced_link;
};

struct chlg_reader_state {
	/* Shortcut to the corresponding OBD device */
	struct obd_device	*crs_obd;
	/* Producer thread (if any) */
	struct task_struct	*crs_prod_task;
	/* An error occurred that prevents from reading further */
	bool			 crs_err;
	/* EOF, no more records available */
	bool			 crs_eof;
	/* Desired start position */
	__u64			 crs_start_offset;
	/* Wait queue for the catalog processing thread */
	wait_queue_head_t	 crs_waitq_prod;
	/* Wait queue for the record copy threads */
	wait_queue_head_t	 crs_waitq_cons;
	/* Mutex protecting crs_rec_count and crs_rec_queue */
	struct mutex		 crs_lock;
	/* Number of item in the list */
	__u64			 crs_rec_count;
	/* List of prefetched enqueued_record::enq_linkage_items */
	struct list_head	 crs_rec_queue;
};

struct chlg_rec_entry {
	/* Link within the chlg_reader_state::crs_rec_queue list */
	struct list_head	enq_linkage;
	/* Data (enq_record) field length */
	__u64			enq_length;
	/* Copy of a changelog record (see struct llog_changelog_rec) */
	struct changelog_rec	enq_record[];
};

enum {
	/* Number of records to prefetch locally. */
	CDEV_CHLG_MAX_PREFETCH = 1024,
};

/**
 * ChangeLog catalog processing callback invoked on each record.
 * If the current record is eligible to userland delivery, push
 * it into the crs_rec_queue where the consumer code will fetch it.
 *
 * @param[in]     env  (unused)
 * @param[in]     llh  Client-side handle used to identify the llog
 * @param[in]     hdr  Header of the current llog record
 * @param[in,out] data chlg_reader_state passed from caller
 *
 * @return 0 or LLOG_PROC_* control code on success, negated error on failure.
 */
static int chlg_read_cat_process_cb(const struct lu_env *env,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *hdr, void *data)
{
	struct llog_changelog_rec *rec;
	struct chlg_reader_state *crs = data;
	struct chlg_rec_entry *enq;
	struct l_wait_info lwi = { 0 };
	size_t len;
	int rc;
	ENTRY;

	LASSERT(crs != NULL);
	LASSERT(hdr != NULL);

	rec = container_of(hdr, struct llog_changelog_rec, cr_hdr);

	if (rec->cr_hdr.lrh_type != CHANGELOG_REC) {
		rc = -EINVAL;
		CERROR("%s: not a changelog rec %x/%d in llog "DFID" rc = %d\n",
		       crs->crs_obd->obd_name, rec->cr_hdr.lrh_type,
		       rec->cr.cr_type,
		       PFID(lu_object_fid(&llh->lgh_obj->do_lu)), rc);
		RETURN(rc);
	}

	/* Skip undesired records */
	if (rec->cr.cr_index < crs->crs_start_offset)
		RETURN(0);

	CDEBUG(D_HSM, "%llu %02d%-5s %llu 0x%x t="DFID" p="DFID" %.*s\n",
	       rec->cr.cr_index, rec->cr.cr_type,
	       changelog_type2str(rec->cr.cr_type), rec->cr.cr_time,
	       rec->cr.cr_flags & CLF_FLAGMASK,
	       PFID(&rec->cr.cr_tfid), PFID(&rec->cr.cr_pfid),
	       rec->cr.cr_namelen, changelog_rec_name(&rec->cr));

	l_wait_event(crs->crs_waitq_prod,
		     (crs->crs_rec_count < CDEV_CHLG_MAX_PREFETCH ||
		      kthread_should_stop()), &lwi);

	if (kthread_should_stop())
		RETURN(LLOG_PROC_BREAK);

	len = changelog_rec_size(&rec->cr) + rec->cr.cr_namelen;
	OBD_ALLOC(enq, sizeof(*enq) + len);
	if (enq == NULL)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&enq->enq_linkage);
	enq->enq_length = len;
	memcpy(enq->enq_record, &rec->cr, len);

	mutex_lock(&crs->crs_lock);
	list_add_tail(&enq->enq_linkage, &crs->crs_rec_queue);
	crs->crs_rec_count++;
	mutex_unlock(&crs->crs_lock);

	wake_up_all(&crs->crs_waitq_cons);

	RETURN(0);
}

/**
 * Remove record from the list it is attached to and free it.
 */
static void enq_record_delete(struct chlg_rec_entry *rec)
{
	list_del(&rec->enq_linkage);
	OBD_FREE(rec, sizeof(*rec) + rec->enq_length);
}

/**
 * Record prefetch thread entry point. Opens the changelog catalog and starts
 * reading records.
 *
 * @param[in,out]  args  chlg_reader_state passed from caller.
 * @return 0 on success, negated error code on failure.
 */
static int chlg_load(void *args)
{
	struct chlg_reader_state *crs = args;
	struct obd_device *obd = crs->crs_obd;
	struct llog_ctxt *ctx = NULL;
	struct llog_handle *llh = NULL;
	struct l_wait_info lwi = { 0 };
	int rc;
	ENTRY;

	ctx = llog_get_context(obd, LLOG_CHANGELOG_REPL_CTXT);
	if (ctx == NULL)
		GOTO(err_out, rc = -ENOENT);

	rc = llog_open(NULL, ctx, &llh, NULL, CHANGELOG_CATALOG,
		       LLOG_OPEN_EXISTS);
	if (rc) {
		CERROR("%s: fail to open changelog catalog: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(err_out, rc);
	}

	rc = llog_init_handle(NULL, llh, LLOG_F_IS_CAT|LLOG_F_EXT_JOBID, NULL);
	if (rc) {
		CERROR("%s: fail to init llog handle: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(err_out, rc);
	}

	rc = llog_cat_process(NULL, llh, chlg_read_cat_process_cb, crs, 0, 0);
	if (rc < 0) {
		CERROR("%s: fail to process llog: rc = %d\n", obd->obd_name, rc);
		GOTO(err_out, rc);
	}

	crs->crs_eof = true;

err_out:
	if (rc < 0)
		crs->crs_err = true;

	wake_up_all(&crs->crs_waitq_cons);

	if (llh != NULL)
		llog_cat_close(NULL, llh);

	if (ctx != NULL)
		llog_ctxt_put(ctx);

	l_wait_event(crs->crs_waitq_prod, kthread_should_stop(), &lwi);

	RETURN(rc);
}

/**
 * Read handler, dequeues records from the chlg_reader_state if any.
 * No partial records are copied to userland so this function can return less
 * data than required (short read).
 *
 * @param[in]   file   File pointer to the character device.
 * @param[out]  buff   Userland buffer where to copy the records.
 * @param[in]   count  Userland buffer size.
 * @param[out]  ppos   File position, updated with the index number of the next
 *		       record to read.
 * @return number of copied bytes on success, negated error code on failure.
 */
static ssize_t chlg_read(struct file *file, char __user *buff, size_t count,
			 loff_t *ppos)
{
	struct chlg_reader_state *crs = file->private_data;
	struct chlg_rec_entry *rec;
	struct chlg_rec_entry *tmp;
	struct l_wait_info lwi = { 0 };
	ssize_t  written_total = 0;
	LIST_HEAD(consumed);
	ENTRY;

	if (file->f_flags & O_NONBLOCK && crs->crs_rec_count == 0)
		RETURN(-EAGAIN);

	l_wait_event(crs->crs_waitq_cons,
		     crs->crs_rec_count > 0 || crs->crs_eof || crs->crs_err,
		     &lwi);

	mutex_lock(&crs->crs_lock);
	list_for_each_entry_safe(rec, tmp, &crs->crs_rec_queue, enq_linkage) {
		if (written_total + rec->enq_length > count)
			break;

		if (copy_to_user(buff, rec->enq_record, rec->enq_length)) {
			if (written_total == 0)
				written_total = -EFAULT;
			break;
		}

		buff += rec->enq_length;
		written_total += rec->enq_length;

		crs->crs_rec_count--;
		list_move_tail(&rec->enq_linkage, &consumed);

		crs->crs_start_offset = rec->enq_record->cr_index + 1;
	}
	mutex_unlock(&crs->crs_lock);

	if (written_total > 0)
		wake_up_all(&crs->crs_waitq_prod);

	list_for_each_entry_safe(rec, tmp, &consumed, enq_linkage)
		enq_record_delete(rec);

	*ppos = crs->crs_start_offset;

	RETURN(written_total);
}

/**
 * Jump to a given record index. Helper for chlg_llseek().
 *
 * @param[in,out]  crs     Internal reader state.
 * @param[in]      offset  Desired offset (index record).
 * @return 0 on success, negated error code on failure.
 */
static int chlg_set_start_offset(struct chlg_reader_state *crs, __u64 offset)
{
	struct chlg_rec_entry *rec;
	struct chlg_rec_entry *tmp;

	mutex_lock(&crs->crs_lock);
	if (offset < crs->crs_start_offset) {
		mutex_unlock(&crs->crs_lock);
		return -ERANGE;
	}

	crs->crs_start_offset = offset;
	list_for_each_entry_safe(rec, tmp, &crs->crs_rec_queue, enq_linkage) {
		struct changelog_rec *cr = rec->enq_record;

		if (cr->cr_index >= crs->crs_start_offset)
			break;

		crs->crs_rec_count--;
		enq_record_delete(rec);
	}

	mutex_unlock(&crs->crs_lock);
	wake_up_all(&crs->crs_waitq_prod);
	return 0;
}

/**
 * Move read pointer to a certain record index, encoded as an offset.
 *
 * @param[in,out] file   File pointer to the changelog character device
 * @param[in]	  off    Offset to skip, actually a record index, not byte count
 * @param[in]	  whence Relative/Absolute interpretation of the offset
 * @return the resulting position on success or negated error code on failure.
 */
static loff_t chlg_llseek(struct file *file, loff_t off, int whence)
{
	struct chlg_reader_state *crs = file->private_data;
	loff_t pos;
	int rc;

	switch (whence) {
	case SEEK_SET:
		pos = off;
		break;
	case SEEK_CUR:
		pos = file->f_pos + off;
		break;
	case SEEK_END:
	default:
		return -EINVAL;
	}

	/* We cannot go backward */
	if (pos < file->f_pos)
		return -EINVAL;

	rc = chlg_set_start_offset(crs, pos);
	if (rc != 0)
		return rc;

	file->f_pos = pos;
	return pos;
}

/**
 * Clear record range for a given changelog reader.
 *
 * @param[in]  crs     Current internal state.
 * @param[in]  reader  Changelog reader ID (cl1, cl2...)
 * @param[in]  record  Record index up which to clear
 * @return 0 on success, negated error code on failure.
 */
static int chlg_clear(struct chlg_reader_state *crs, __u32 reader, __u64 record)
{
	struct obd_device *obd = crs->crs_obd;
	struct changelog_setinfo cs  = {
		.cs_recno = record,
		.cs_id    = reader
	};

	return obd_set_info_async(NULL, obd->obd_self_export,
				  strlen(KEY_CHANGELOG_CLEAR),
				  KEY_CHANGELOG_CLEAR, sizeof(cs), &cs, NULL);
}

/** Maximum changelog control command size */
#define CHLG_CONTROL_CMD_MAX	64

/**
 * Handle writes() into the changelog character device. Write() can be used
 * to request special control operations.
 *
 * @param[in]  file  File pointer to the changelog character device
 * @param[in]  buff  User supplied data (written data)
 * @param[in]  count Number of written bytes
 * @param[in]  off   (unused)
 * @return number of written bytes on success, negated error code on failure.
 */
static ssize_t chlg_write(struct file *file, const char __user *buff,
			  size_t count, loff_t *off)
{
	struct chlg_reader_state *crs = file->private_data;
	char *kbuf;
	__u64 record;
	__u32 reader;
	int rc = 0;
	ENTRY;

	if (count > CHLG_CONTROL_CMD_MAX)
		RETURN(-EINVAL);

	OBD_ALLOC(kbuf, CHLG_CONTROL_CMD_MAX);
	if (kbuf == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(kbuf, buff, count))
		GOTO(out_kbuf, rc = -EFAULT);

	kbuf[CHLG_CONTROL_CMD_MAX - 1] = '\0';

	if (sscanf(kbuf, "clear:cl%u:%llu", &reader, &record) == 2)
		rc = chlg_clear(crs, reader, record);
	else
		rc = -EINVAL;

	EXIT;
out_kbuf:
	OBD_FREE(kbuf, CHLG_CONTROL_CMD_MAX);
	return rc < 0 ? rc : count;
}

/**
 * Find the OBD device associated to a changelog character device.
 * @param[in]  cdev  character device instance descriptor
 * @return corresponding OBD device or NULL if none was found.
 */
static struct obd_device *chlg_obd_get(dev_t cdev)
{
	int minor = MINOR(cdev);
	struct obd_device *obd = NULL;
	struct chlg_registered_dev *curr;

	mutex_lock(&chlg_registered_dev_lock);
	list_for_each_entry(curr, &chlg_registered_devices, ced_link) {
		if (curr->ced_misc.minor == minor) {
			/* take the first available OBD device attached */
			obd = list_first_entry(&curr->ced_obds,
					       struct obd_device,
					       u.cli.cl_chg_dev_linkage);
			break;
		}
	}
	mutex_unlock(&chlg_registered_dev_lock);
	return obd;
}

/**
 * Open handler, initialize internal CRS state and spawn prefetch thread if
 * needed.
 * @param[in]  inode  Inode struct for the open character device.
 * @param[in]  file   Corresponding file pointer.
 * @return 0 on success, negated error code on failure.
 */
static int chlg_open(struct inode *inode, struct file *file)
{
	struct chlg_reader_state *crs;
	struct obd_device *obd = chlg_obd_get(inode->i_rdev);
	struct task_struct *task;
	int rc;
	ENTRY;

	if (!obd)
		RETURN(-ENODEV);

	OBD_ALLOC_PTR(crs);
	if (!crs)
		RETURN(-ENOMEM);

	crs->crs_obd = obd;
	crs->crs_err = false;
	crs->crs_eof = false;

	mutex_init(&crs->crs_lock);
	INIT_LIST_HEAD(&crs->crs_rec_queue);
	init_waitqueue_head(&crs->crs_waitq_prod);
	init_waitqueue_head(&crs->crs_waitq_cons);

	if (file->f_mode & FMODE_READ) {
		task = kthread_run(chlg_load, crs, "chlg_load_thread");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			CERROR("%s: cannot start changelog thread: rc = %d\n",
			       obd->obd_name, rc);
			GOTO(err_crs, rc);
		}
		crs->crs_prod_task = task;
	}

	file->private_data = crs;
	RETURN(0);

err_crs:
	OBD_FREE_PTR(crs);
	return rc;
}

/**
 * Close handler, release resources.
 *
 * @param[in]  inode  Inode struct for the open character device.
 * @param[in]  file   Corresponding file pointer.
 * @return 0 on success, negated error code on failure.
 */
static int chlg_release(struct inode *inode, struct file *file)
{
	struct chlg_reader_state *crs = file->private_data;
	struct chlg_rec_entry *rec;
	struct chlg_rec_entry *tmp;

	if (crs->crs_prod_task)
		kthread_stop(crs->crs_prod_task);

	list_for_each_entry_safe(rec, tmp, &crs->crs_rec_queue, enq_linkage)
		enq_record_delete(rec);

	OBD_FREE_PTR(crs);
	return 0;
}

/**
 * Poll handler, indicates whether the device is readable (new records) and
 * writable (always).
 *
 * @param[in]  file   Device file pointer.
 * @param[in]  wait   (opaque)
 * @return combination of the poll status flags.
 */
static unsigned int chlg_poll(struct file *file, poll_table *wait)
{
	struct chlg_reader_state *crs = file->private_data;
	unsigned int mask = 0;

	mutex_lock(&crs->crs_lock);
	poll_wait(file, &crs->crs_waitq_cons, wait);
	if (crs->crs_rec_count > 0)
		mask |= POLLIN | POLLRDNORM;
	if (crs->crs_err)
		mask |= POLLERR;
	if (crs->crs_eof)
		mask |= POLLHUP;
	mutex_unlock(&crs->crs_lock);
	return mask;
}

static const struct file_operations chlg_fops = {
	.owner		= THIS_MODULE,
	.llseek		= chlg_llseek,
	.read		= chlg_read,
	.write		= chlg_write,
	.open		= chlg_open,
	.release	= chlg_release,
	.poll		= chlg_poll,
};

/**
 * This uses obd_name of the form: "testfs-MDT0000-mdc-ffff88006501600"
 * and returns a name of the form: "changelog-testfs-MDT0000".
 */
static void get_chlg_name(char *name, size_t name_len, struct obd_device *obd)
{
	int i;

	snprintf(name, name_len, "changelog-%s", obd->obd_name);

	/* Find the 2nd '-' from the end and truncate on it */
	for (i = 0; i < 2; i++) {
		char *p = strrchr(name, '-');

		if (p == NULL)
			return;
		*p = '\0';
	}
}

/**
 * Find a changelog character device by name.
 * All devices registered during MDC setup are listed in a global list with
 * their names attached.
 */
static struct chlg_registered_dev *
chlg_registered_dev_find_by_name(const char *name)
{
	struct chlg_registered_dev *dit;

	list_for_each_entry(dit, &chlg_registered_devices, ced_link)
		if (strcmp(name, dit->ced_name) == 0)
			return dit;
	return NULL;
}

/**
 * Find chlg_registered_dev structure for a given OBD device.
 * This is bad O(n^2) but for each filesystem:
 *   - N is # of MDTs times # of mount points
 *   - this only runs at shutdown
 */
static struct chlg_registered_dev *
chlg_registered_dev_find_by_obd(const struct obd_device *obd)
{
	struct chlg_registered_dev *dit;
	struct obd_device *oit;

	list_for_each_entry(dit, &chlg_registered_devices, ced_link)
		list_for_each_entry(oit, &dit->ced_obds,
				    u.cli.cl_chg_dev_linkage)
			if (oit == obd)
				return dit;
	return NULL;
}

/**
 * Changelog character device initialization.
 * Register a misc character device with a dynamic minor number, under a name
 * of the form: 'changelog-fsname-MDTxxxx'. Reference this OBD device with it.
 *
 * @param[in] obd  This MDC obd_device.
 * @return 0 on success, negated error code on failure.
 */
int mdc_changelog_cdev_init(struct obd_device *obd)
{
	struct chlg_registered_dev *exist;
	struct chlg_registered_dev *entry;
	int rc;
	ENTRY;

	OBD_ALLOC_PTR(entry);
	if (entry == NULL)
		RETURN(-ENOMEM);

	get_chlg_name(entry->ced_name, sizeof(entry->ced_name), obd);

	entry->ced_misc.minor = MISC_DYNAMIC_MINOR;
	entry->ced_misc.name  = entry->ced_name;
	entry->ced_misc.fops  = &chlg_fops;

	kref_init(&entry->ced_refs);
	INIT_LIST_HEAD(&entry->ced_obds);
	INIT_LIST_HEAD(&entry->ced_link);

	mutex_lock(&chlg_registered_dev_lock);
	exist = chlg_registered_dev_find_by_name(entry->ced_name);
	if (exist != NULL) {
		kref_get(&exist->ced_refs);
		list_add_tail(&obd->u.cli.cl_chg_dev_linkage, &exist->ced_obds);
		GOTO(out_unlock, rc = 0);
	}

	/* Register new character device */
	rc = misc_register(&entry->ced_misc);
	if (rc != 0)
		GOTO(out_unlock, rc);

	list_add_tail(&obd->u.cli.cl_chg_dev_linkage, &entry->ced_obds);
	list_add_tail(&entry->ced_link, &chlg_registered_devices);

	entry = NULL;	/* prevent it from being freed below */

out_unlock:
	mutex_unlock(&chlg_registered_dev_lock);
	if (entry)
		OBD_FREE_PTR(entry);
	RETURN(rc);
}

/**
 * Deregister a changelog character device whose refcount has reached zero.
 */
static void chlg_dev_clear(struct kref *kref)
{
	struct chlg_registered_dev *entry = container_of(kref,
						      struct chlg_registered_dev,
						      ced_refs);
	ENTRY;

	list_del(&entry->ced_link);
	misc_deregister(&entry->ced_misc);
	OBD_FREE_PTR(entry);
	EXIT;
}

/**
 * Release OBD, decrease reference count of the corresponding changelog device.
 */
void mdc_changelog_cdev_finish(struct obd_device *obd)
{
	struct chlg_registered_dev *dev = chlg_registered_dev_find_by_obd(obd);
	ENTRY;

	mutex_lock(&chlg_registered_dev_lock);
	list_del_init(&obd->u.cli.cl_chg_dev_linkage);
	kref_put(&dev->ced_refs, chlg_dev_clear);
	mutex_unlock(&chlg_registered_dev_lock);
	EXIT;
}
