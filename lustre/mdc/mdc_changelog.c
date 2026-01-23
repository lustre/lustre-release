// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2017, Commissariat a l'Energie Atomique et aux Energies
 *                     Alternatives.
 * Copyright (c) 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: Henri Doreau <henri.doreau@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDC

#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/poll.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/idr.h>

#include <lustre_log.h>
#include <uapi/linux/lustre/lustre_ioctl.h>

#include "mdc_internal.h"


/* -- Changelog delivery through character device -- */

/* Mutex to protect chlg_registered_devices below */
static DEFINE_MUTEX(chlg_registered_dev_lock);

/* Global linked list of all registered devices (one per MDT). */
static LIST_HEAD(chlg_registered_devices);

struct chlg_registered_dev {
	/* Device name of the form "changelog-{MDTNAME}" */
	char			 ced_name[32];
	/* changelog char device */
	struct cdev		 ced_cdev;
	struct device		 ced_device;
	/* OBDs referencing this device (multiple mount point) */
	struct list_head	 ced_obds;
	/* Reference counter for proper deregistration */
	struct kref		 ced_refs;
	/* Link within the global chlg_registered_devices */
	struct list_head	 ced_link;
};

struct chlg_reader_state {
	/* Shortcut to the corresponding OBD device */
	struct obd_device	   *crs_obd;
	/* the corresponding chlg_registered_dev */
	struct chlg_registered_dev *crs_ced;
	/* Producer thread (if any) */
	struct task_struct	   *crs_prod_task;
	/* An error occurred that prevents from reading further */
	int			    crs_err;
	/* EOF, no more records available */
	bool			    crs_eof;
	/* Desired start position */
	__u64			    crs_start_offset;
	/* Wait queue for the catalog processing thread */
	wait_queue_head_t	    crs_waitq_prod;
	/* Wait queue for the record copy threads */
	wait_queue_head_t	    crs_waitq_cons;
	/* Mutex protecting crs_rec_count and crs_rec_queue */
	struct mutex		    crs_lock;
	/* Number of item in the list */
	__u64			    crs_rec_count;
	/* List of prefetched enqueued_record::enq_linkage_items */
	struct list_head	    crs_rec_queue;
	unsigned int		    crs_last_catidx;
	unsigned int		    crs_last_idx;
	unsigned int		    crs_flags;
	/* Changelog filter mask (0 = off by default ) */
	__u64			    crs_user_mask;
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

DEFINE_IDR(mdc_changelog_minor_idr);
static DEFINE_SPINLOCK(chlg_minor_lock);

static int chlg_minor_alloc(int *pminor)
{
	void *minor_allocated = (void *)-1;
	int minor;

	idr_preload(GFP_KERNEL);
	spin_lock(&chlg_minor_lock);
	minor = idr_alloc(&mdc_changelog_minor_idr, minor_allocated, 0,
			  MDC_CHANGELOG_DEV_COUNT, GFP_NOWAIT);
	spin_unlock(&chlg_minor_lock);
	idr_preload_end();

	if (minor < 0)
		return minor;

	*pminor = minor;
	return 0;
}

static void chlg_minor_free(int minor)
{
	spin_lock(&chlg_minor_lock);
	idr_remove(&mdc_changelog_minor_idr, minor);
	spin_unlock(&chlg_minor_lock);
}

static void chlg_device_release(struct device *dev)
{
	struct chlg_registered_dev *entry = dev_get_drvdata(dev);

	chlg_minor_free(MINOR(entry->ced_cdev.dev));
	OBD_FREE_PTR(entry);
}

/* Deregister a changelog character device whose refcount has reached zero. */
static void chlg_dev_clear(struct kref *kref)
{
	struct chlg_registered_dev *entry;

	ENTRY;
	entry = container_of(kref, struct chlg_registered_dev,
			     ced_refs);

	list_del(&entry->ced_link);
	cdev_device_del(&entry->ced_cdev, &entry->ced_device);
	put_device(&entry->ced_device);
	EXIT;
}

static inline struct obd_device *chlg_obd_get(struct chlg_registered_dev *dev)
{
	struct obd_device *obd;

	mutex_lock(&chlg_registered_dev_lock);
	if (list_empty(&dev->ced_obds)) {
		mutex_unlock(&chlg_registered_dev_lock);
		return NULL;
	}

	obd = list_first_entry(&dev->ced_obds, struct obd_device,
			       u.cli.cl_chg_dev_linkage);
	class_incref(obd, "changelog", dev);
	mutex_unlock(&chlg_registered_dev_lock);
	return obd;
}

static inline void chlg_obd_put(struct chlg_registered_dev *dev,
			 struct obd_device *obd)
{
	class_decref(obd, "changelog", dev);
}

/**
 * chlg_read_cat_process_cb() - Changelog catalog processing callback
 * @env: (unused)
 * @llh: Client-side handle used to identify the llog
 * @hdr: Header of the current llog record
 * @data: chlg_reader_state passed from caller [in,out]
 *
 * ChangeLog catalog processing callback invoked on each record.
 * If the current record is eligible to userland delivery, push
 * it into the crs_rec_queue where the consumer code will fetch it.
 *
 * Return %0 or LLOG_PROC_* control code on success, %negated error on failure.
 */
static int chlg_read_cat_process_cb(const struct lu_env *env,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *hdr, void *data)
{
	struct llog_changelog_rec *rec;
	struct chlg_reader_state *crs = data;
	struct chlg_rec_entry *enq;
	size_t len;
	int rc;

	ENTRY;

	LASSERT(crs != NULL);
	LASSERT(hdr != NULL);

	rec = container_of(hdr, struct llog_changelog_rec, cr_hdr);

	crs->crs_last_catidx = llh->lgh_hdr->llh_cat_idx;
	crs->crs_last_idx = hdr->lrh_index;

	if (rec->cr_hdr.lrh_type != CHANGELOG_REC) {
		rc = -EINVAL;
		CERROR("%s: not a changelog rec %x/%d in llog : rc = %d\n",
		       crs->crs_obd->obd_name, rec->cr_hdr.lrh_type,
		       rec->cr.cr_type, rc);
		RETURN(rc);
	}

	/* Check if we can skip the entire llog plain */
	if (llog_is_plain_skipable(llh->lgh_hdr, hdr, rec->cr.cr_index,
				   crs->crs_start_offset))
		RETURN(LLOG_SKIP_PLAIN);

	/* Skip undesired records */
	if (rec->cr.cr_index < crs->crs_start_offset)
		RETURN(0);

	/* Check if this record type matches the user's mask */
	if (crs->crs_user_mask &&
	    !(crs->crs_user_mask & BIT(rec->cr.cr_type)))
		RETURN(0);

	CDEBUG(D_HSM, "%llu %02d%-5s %llu 0x%x t="DFID" p="DFID" %.*s\n",
	       rec->cr.cr_index, rec->cr.cr_type,
	       changelog_type2str(rec->cr.cr_type), rec->cr.cr_time,
	       rec->cr.cr_flags & CLF_FLAGMASK,
	       PFID(&rec->cr.cr_tfid), PFID(&rec->cr.cr_pfid),
	       rec->cr.cr_namelen, changelog_rec_name(&rec->cr));

	wait_event_interruptible(crs->crs_waitq_prod,
				 crs->crs_rec_count < CDEV_CHLG_MAX_PREFETCH ||
				 kthread_should_stop());

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

	wake_up(&crs->crs_waitq_cons);

	RETURN(0);
}

/* Remove record from the list it is attached to and free it. */
static void enq_record_delete(struct chlg_rec_entry *rec)
{
	list_del(&rec->enq_linkage);
	OBD_FREE(rec, sizeof(*rec) + rec->enq_length);
}

/**
 * chlg_load() - Record prefetch thread entry point. Opens the changelog catalog
 *               and starts reading records.
 * @args: chlg_reader_state passed from caller. [in,out]
 *
 * Return %0 on success, %negated error code on failure.
 */
static int chlg_load(void *args)
{
	struct chlg_reader_state *crs = args;
	struct chlg_registered_dev *ced = crs->crs_ced;
	struct obd_device *obd = NULL;
	struct llog_ctxt *ctx = NULL;
	struct llog_handle *llh = NULL;
	enum llog_flag nid_be_flag = 0;
	int rc;

	ENTRY;
	crs->crs_last_catidx = 0;
	crs->crs_last_idx = 0;
again:
	obd = chlg_obd_get(ced);
	if (obd == NULL)
		RETURN(-ENODEV);

	crs->crs_obd = obd;

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

	if (crs->crs_flags & CLFE_NID_BE)
		nid_be_flag = LLOG_F_EXT_X_NID_BE;

	rc = llog_init_handle(NULL, llh,
			      LLOG_F_IS_CAT |
			      LLOG_F_EXT_JOBID |
			      LLOG_F_EXT_EXTRA_FLAGS |
			      LLOG_F_EXT_X_UIDGID |
			      LLOG_F_EXT_X_NID | nid_be_flag |
			      LLOG_F_EXT_X_OMODE |
			      LLOG_F_EXT_X_XATTR,
			      NULL);
	if (rc) {
		CERROR("%s: fail to init llog handle: rc = %d\n",
		       obd->obd_name, rc);
		GOTO(err_out, rc);
	}

	rc = llog_cat_process(NULL, llh, chlg_read_cat_process_cb, crs,
				crs->crs_last_catidx, crs->crs_last_idx);
	if (rc < 0) {
		CERROR("%s: fail to process llog: rc = %d\n", obd->obd_name, rc);
		GOTO(err_out, rc);
	}
	if (!kthread_should_stop() &&
	    (crs->crs_flags & CHANGELOG_FLAG_FOLLOW)) {
		llog_cat_close(NULL, llh);
		llog_ctxt_put(ctx);
		class_decref(obd, "changelog", crs);
		schedule_timeout_interruptible(cfs_time_seconds(1));
		goto again;
	}

	crs->crs_eof = true;

err_out:
	if (rc < 0)
		crs->crs_err = rc;

	wake_up(&crs->crs_waitq_cons);

	if (llh != NULL)
		llog_cat_close(NULL, llh);

	if (ctx != NULL)
		llog_ctxt_put(ctx);

	crs->crs_obd = NULL;
	chlg_obd_put(ced, obd);
	wait_event_interruptible(crs->crs_waitq_prod, kthread_should_stop());

	RETURN(rc);
}

static int chlg_start_thread(struct file *file)
{
	struct chlg_reader_state *crs = file->private_data;
	struct task_struct *task;
	int rc = 0;

	if (likely(crs->crs_prod_task))
		return 0;
	if (unlikely(file->f_mode & FMODE_READ) == 0)
		return 0;

	mutex_lock(&crs->crs_lock);
	if (crs->crs_prod_task == NULL) {
		task = kthread_run(chlg_load, crs, "chlg_load_thread");
		if (IS_ERR(task)) {
			rc = PTR_ERR(task);
			CERROR("%s: cannot start changelog thread: rc = %d\n",
			       crs->crs_ced->ced_name, rc);
			GOTO(out, rc);
		}
		crs->crs_prod_task = task;
	}
out:
	mutex_unlock(&crs->crs_lock);
	return rc;
}

/**
 * chlg_read() - Read Handler
 * @file: File pointer to the character device.
 * @buff: Userland buffer where to copy the records. [out]
 * @count: Userland buffer size.
 * @ppos: File position, updated with index number of next record to read. [out]
 *
 * Read handler, dequeues records from the chlg_reader_state if any.
 * No partial records are copied to userland so this function can return less
 * data than required (short read).
 *
 * Return number of copied bytes on success, %negated error code on failure.
 */
static ssize_t chlg_read(struct file *file, char __user *buff, size_t count,
			 loff_t *ppos)
{
	struct chlg_reader_state *crs = file->private_data;
	struct chlg_rec_entry *rec;
	struct chlg_rec_entry *tmp;
	size_t written_total = 0;
	ssize_t rc;
	LIST_HEAD(consumed);

	ENTRY;

	if (file->f_flags & O_NONBLOCK && crs->crs_rec_count == 0) {
		if (crs->crs_err < 0)
			RETURN(crs->crs_err);
		else if (crs->crs_eof)
			RETURN(0);
		else
			RETURN(-EAGAIN);
	}

	rc = chlg_start_thread(file);
	if (rc)
		RETURN(rc);

	rc = wait_event_interruptible(crs->crs_waitq_cons,
			crs->crs_rec_count > 0 || crs->crs_eof || crs->crs_err);

	mutex_lock(&crs->crs_lock);
	list_for_each_entry_safe(rec, tmp, &crs->crs_rec_queue, enq_linkage) {
		if (written_total + rec->enq_length > count)
			break;

		if (copy_to_user(buff, rec->enq_record, rec->enq_length)) {
			rc = -EFAULT;
			break;
		}

		buff += rec->enq_length;
		written_total += rec->enq_length;

		crs->crs_rec_count--;
		list_move_tail(&rec->enq_linkage, &consumed);

		crs->crs_start_offset = rec->enq_record->cr_index + 1;
	}
	mutex_unlock(&crs->crs_lock);

	if (written_total > 0) {
		rc = written_total;
		wake_up(&crs->crs_waitq_prod);
	} else if (rc == 0) {
		rc = crs->crs_err;
	}

	list_for_each_entry_safe(rec, tmp, &consumed, enq_linkage)
		enq_record_delete(rec);

	*ppos = crs->crs_start_offset;

	RETURN(rc);
}

/**
 * chlg_set_start_offset() - Jump to a given record index.
 * @crs: Internal reader state. [in,out]
 * @offset: Desired offset (index record).
 *
 * Jump to a given record index. Helper for chlg_llseek().
 *
 * Return 0 on success, negated error code on failure.
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
	wake_up(&crs->crs_waitq_prod);
	return 0;
}

/**
 * chlg_llseek() - Move read pointer to a certain record index, encoded as an
 *                 offset.
 * @file: File pointer to the changelog character device [in, out]
 * @off: Offset to skip, actually a record index, not byte count
 * @whence: Relative/Absolute interpretation of the offset
 *
 * Return the resulting position on success or %negated error code on failure.
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
 * chlg_clear() - Clear record range for a given changelog reader.
 * @crs: Current internal state.
 * @reader: Changelog reader ID (cl1, cl2...)
 * @record: Record index up which to clear
 *
 * Return %0 on success, %negated error code on failure.
 */
static int chlg_clear(struct chlg_reader_state *crs, __u32 reader, __u64 record)
{
	struct obd_device *obd = NULL;
	struct changelog_setinfo cs  = {
		.cs_recno = record,
		.cs_id    = reader
	};
	int rc;

	obd = chlg_obd_get(crs->crs_ced);
	if (obd == NULL)
		return -ENODEV;

	rc = obd_set_info_async(NULL, obd->obd_self_export,
				strlen(KEY_CHANGELOG_CLEAR),
				KEY_CHANGELOG_CLEAR, sizeof(cs), &cs, NULL);

	chlg_obd_put(crs->crs_ced, obd);
	return rc;
}

/** Maximum changelog control command size */
#define CHLG_CONTROL_CMD_MAX	64

/**
 * chlg_write() - Handle writes into the changelog character device.
 * @file:  File pointer to the changelog character device
 * @buff:  User supplied data (written data)
 * @count: Number of written bytes
 * @off:   (unused)
 *
 * Handle writes() into the changelog character device. Write() can be used
 * to request special control operations.
 *
 * Return number of written bytes on success, negated error code on failure.
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
 * chlg_open() - Open handler
 * @inode: Inode struct for the open character device.
 * @file: Corresponding file pointer.
 *
 * Open handler, initialize internal CRS state and spawn prefetch thread if
 * needed.
 *
 * Return %0 on success, %negated error code on failure.
 */
static int chlg_open(struct inode *inode, struct file *file)
{
	struct chlg_reader_state *crs;
	struct chlg_registered_dev *dev;

	ENTRY;

	dev = container_of(inode->i_cdev, struct chlg_registered_dev, ced_cdev);

	OBD_ALLOC_PTR(crs);
	if (!crs)
		RETURN(-ENOMEM);

	kref_get(&dev->ced_refs);
	crs->crs_ced = dev;
	crs->crs_err = false;
	crs->crs_eof = false;

	mutex_init(&crs->crs_lock);
	INIT_LIST_HEAD(&crs->crs_rec_queue);
	init_waitqueue_head(&crs->crs_waitq_prod);
	init_waitqueue_head(&crs->crs_waitq_cons);
	crs->crs_prod_task = NULL;
	crs->crs_user_mask = 0;

	file->private_data = crs;
	RETURN(0);
}

/**
 * chlg_release() - Close handler, release resources.
 * @inode: Inode struct for the open character device.
 * @file: Corresponding file pointer.
 *
 * Return %0 on success, %negated error code on failure.
 */
static int chlg_release(struct inode *inode, struct file *file)
{
	struct chlg_reader_state *crs = file->private_data;
	struct chlg_rec_entry *rec;
	struct chlg_rec_entry *tmp;
	int rc = 0;

	if (crs->crs_prod_task)
		rc = kthread_stop(crs->crs_prod_task);

	list_for_each_entry_safe(rec, tmp, &crs->crs_rec_queue, enq_linkage)
		enq_record_delete(rec);

	kref_put(&crs->crs_ced->ced_refs, chlg_dev_clear);
	OBD_FREE_PTR(crs);

	return rc;
}

/**
 * chlg_poll() - Poll handler
 * @file: Device file pointer.
 * @wait: (opaque)
 *
 * Poll handler, indicates whether the device is readable (new records) and
 * writable (always).
 *
 * Return combination of the poll status flags.
 */
static unsigned int chlg_poll(struct file *file, poll_table *wait)
{
	struct chlg_reader_state *crs = file->private_data;
	unsigned int mask = 0;
	int rc;

	rc = chlg_start_thread(file);
	if (rc)
		RETURN(rc);

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

/**
 * mdc_changelog_get_user_info() - Send MDS_GET_INFO RPC to fetch changelog
 *                                 user information.
 * @imp: MDC import
 * @in: User-specific changelog filter
 * @out: Returned changelog user information [out]
 *
 * Return %0 on success with @out properly filled, %negated error code on
 * failure.
 */
static int mdc_changelog_get_user_info(struct obd_import *imp,
				       const struct changelog_filter *in,
				       struct changelog_filter *out)
{
	struct ptlrpc_request *req;
	struct changelog_filter *val_in;
	struct changelog_filter *val_out;
	char *key;
	int rc;

	ENTRY;

	req = ptlrpc_request_alloc(imp, &RQF_MDS_GET_INFO);
	if (req == NULL)
		RETURN(-ENOMEM);

	/* Set request fields size and pack request buffers */
	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_KEY, RCL_CLIENT,
			     strlen(KEY_CHANGELOG_USER) + 1);
	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_VAL, RCL_CLIENT,
			     sizeof(struct changelog_filter));
	rc = ptlrpc_request_pack(req, LUSTRE_MDS_VERSION, MDS_GET_INFO);
	if (rc) {
		ptlrpc_request_free(req);
		RETURN(rc);
	}

	/* Fill in KEY */
	key = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_KEY);
	memcpy(key, KEY_CHANGELOG_USER, strlen(KEY_CHANGELOG_USER) + 1);
	/* Fill in VAL*/
	val_in = req_capsule_client_get(&req->rq_pill, &RMF_GETINFO_VAL);
	memcpy(val_in, in, sizeof(struct changelog_filter));

	/* Set reply size */
	req_capsule_set_size(&req->rq_pill, &RMF_GETINFO_VAL, RCL_SERVER,
			     sizeof(struct changelog_filter));

	ptlrpc_request_set_replen(req);
	rc = ptlrpc_queue_wait(req);
	if (rc)
		GOTO(out, rc);

	/* Get reply */
	val_out = req_capsule_server_get(&req->rq_pill, &RMF_GETINFO_VAL);
	if (val_out == NULL)
		GOTO(out, rc = -EPROTO);

	*out = *val_out;
out:
	ptlrpc_req_put(req);
	RETURN(rc);
}

static long chlg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int rc;
	struct chlg_reader_state *crs = file->private_data;

	switch (cmd) {
	case OBD_IOC_CHLG_POLL:
		crs->crs_flags = arg;
		rc = 0;
		break;
	case OBD_IOC_CHANGELOG_FILTER: {
		struct changelog_filter in;	/* filter request */
		struct changelog_filter out;	/* user info reply */
		struct obd_device *obd;

		/* Unpack ioctl data */
		if (copy_from_user(&in, (void __user *)arg, sizeof(in)))
			return -EFAULT;

		/* Get changelog user info */
		obd = chlg_obd_get(crs->crs_ced);
		if (obd == NULL)
			return -ENODEV;
		rc = mdc_changelog_get_user_info(obd->u.cli.cl_import,
						 &in, &out);
		if (rc) {
			CERROR("%s: Failed to get changelog user info for cl%u(%s): rc = %d\n",
			       obd->obd_name, in.cf_user_id, in.cf_username,
			       rc);
			chlg_obd_put(crs->crs_ced, obd);
			break;
		}
		chlg_obd_put(crs->crs_ced, obd);

		mutex_lock(&crs->crs_lock);
		if (in.cf_mask == 0)
			crs->crs_user_mask = out.cf_mask;
		else
			crs->crs_user_mask = in.cf_mask & out.cf_mask;
		mutex_unlock(&crs->crs_lock);

		CDEBUG(D_INFO,
		       "Set changelog filter: username=cl%u(%s), mask=0x%llx\n",
		       out.cf_user_id, out.cf_username, crs->crs_user_mask);
		rc = 0;
		break;
	}
	default:
		rc = -EINVAL;
		break;
	}

	RETURN(rc);
}

static const struct file_operations chlg_fops = {
	.owner		= THIS_MODULE,
	.llseek		= chlg_llseek,
	.read		= chlg_read,
	.write		= chlg_write,
	.open		= chlg_open,
	.release	= chlg_release,
	.poll		= chlg_poll,
	.unlocked_ioctl	= chlg_ioctl,
};

/**
 * get_target_name() - Get changelog defined name from OBD Name
 * @name: changelog define name which was retrived from OBD Name [out]
 * @name_len: size of OBD Name
 * @obd: OBD to get name
 *
 * This uses obd_name of the form: "testfs-MDT0000-mdc-ffff88006501600"
 * and returns a name of the form: "changelog-testfs-MDT0000".
 */
static void get_target_name(char *name, size_t name_len, struct obd_device *obd)
{
	int i;

	snprintf(name, name_len, "%s", obd->obd_name);

	/* Find the 2nd '-' from the end and truncate on it */
	for (i = 0; i < 2; i++) {
		char *p = strrchr(name, '-');

		if (p == NULL)
			return;
		*p = '\0';
	}
}

/**
 * chlg_registered_dev_find_by_name() - Find changelog character device by name.
 * @name: Name of changelog char device to be searched
 *
 * All devices registered during MDC setup are listed in a global list with
 * their names attached.
 *
 * Return struct chlg_registered_dev on Success or %NULL if not found
 */
static struct chlg_registered_dev *
chlg_registered_dev_find_by_name(const char *name)
{
	struct chlg_registered_dev *dit;

	LASSERT(mutex_is_locked(&chlg_registered_dev_lock));
	list_for_each_entry(dit, &chlg_registered_devices, ced_link)
		if (strcmp(name, dit->ced_name) == 0)
			return dit;
	return NULL;
}

/**
 * chlg_registered_dev_find_by_obd() - Find changelog character device by obd
 * @obd: Find changelog device for this OBD device.
 *
 * Find chlg_registered_dev structure for a given OBD device.
 * This is bad O(n^2) but for each filesystem:
 *   - N is # of MDTs times # of mount points
 *   - this only runs at shutdown
 *
 * Return struct chlg_registered_dev on Success or %NULL if not found
 */
static struct chlg_registered_dev *
chlg_registered_dev_find_by_obd(const struct obd_device *obd)
{
	struct chlg_registered_dev *dit;
	struct obd_device *oit;

	LASSERT(mutex_is_locked(&chlg_registered_dev_lock));
	list_for_each_entry(dit, &chlg_registered_devices, ced_link)
		list_for_each_entry(oit, &dit->ced_obds,
				    u.cli.cl_chg_dev_linkage)
			if (oit == obd)
				return dit;
	return NULL;
}

/**
 * mdc_changelog_cdev_init() - Changelog character device initialization.
 * @obd: This MDC obd_device.
 *
 * Register a misc character device with a dynamic minor number, under a name
 * of the form: 'changelog-fsname-MDTxxxx'. Reference this OBD device with it.
 *
 * Return %0 on success, negated error code on failure.
 */
int mdc_changelog_cdev_init(struct obd_device *obd)
{
	struct chlg_registered_dev *exist;
	struct chlg_registered_dev *entry;
	int minor, rc;

	ENTRY;

	OBD_ALLOC_PTR(entry);
	if (entry == NULL)
		RETURN(-ENOMEM);

	get_target_name(entry->ced_name, sizeof(entry->ced_name), obd);

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

	list_add_tail(&obd->u.cli.cl_chg_dev_linkage, &entry->ced_obds);
	list_add_tail(&entry->ced_link, &chlg_registered_devices);

	rc = chlg_minor_alloc(&minor);
	if (rc)
		GOTO(out_listrm, rc);

	device_initialize(&entry->ced_device);
	entry->ced_device.devt = MKDEV(MAJOR(mdc_changelog_dev), minor);
	entry->ced_device.class = mdc_changelog_class;
	entry->ced_device.release = chlg_device_release;
	dev_set_drvdata(&entry->ced_device, entry);
	rc = dev_set_name(&entry->ced_device, "%s-%s", MDC_CHANGELOG_DEV_NAME,
			  entry->ced_name);
	if (rc)
		GOTO(out_minor, rc);

	/* Register new character device */
	cdev_init(&entry->ced_cdev, &chlg_fops);
	entry->ced_cdev.owner = THIS_MODULE;
	rc = cdev_device_add(&entry->ced_cdev, &entry->ced_device);
	if (rc)
		GOTO(out_device_name, rc);

	entry = NULL;	/* prevent it from being freed below */
	GOTO(out_unlock, rc = 0);

out_device_name:
	kfree_const(entry->ced_device.kobj.name);

out_minor:
	chlg_minor_free(minor);

out_listrm:
	list_del_init(&obd->u.cli.cl_chg_dev_linkage);
	list_del(&entry->ced_link);

out_unlock:
	mutex_unlock(&chlg_registered_dev_lock);
	OBD_FREE_PTR(entry);
	RETURN(rc);
}

/**
 * mdc_changelog_cdev_finish() - Release OBD, decrease reference count of the
 *                               corresponding changelog device.
 * @obd: OBD device of changelog
 */
void mdc_changelog_cdev_finish(struct obd_device *obd)
{
	struct chlg_registered_dev *dev;

	ENTRY;
	mutex_lock(&chlg_registered_dev_lock);
	dev = chlg_registered_dev_find_by_obd(obd);
	list_del_init(&obd->u.cli.cl_chg_dev_linkage);
	kref_put(&dev->ced_refs, chlg_dev_clear);
	mutex_unlock(&chlg_registered_dev_lock);
	EXIT;
}
