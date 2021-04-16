#include <linux/cdev.h>
#include <linux/circ_buf.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <uapi/linux/lustre/lustre_access_log.h>
#include "ofd_internal.h"

/* OFD access logs: OST (OFD) RPC handlers log accesses by FID and
 * PFID which are read from userspace through character device files
 * (/dev/lustre-access-log/scratch-OST0000). Accesses are described by
 * struct ofd_access_entry_v1. The char device implements read()
 * (blocking and nonblocking) and poll(), along with an ioctl that
 * returns diagnostic information on an oal device.
 *
 * A control device (/dev/lustre-access-log/control) supports an ioctl()
 * plus poll() method to for oal discovery. See uses of
 * oal_control_event_count and oal_control_wait_queue for details.
 *
 * oal log size and entry size are restricted to powers of 2 to
 * support circ_buf methods. See Documentation/core-api/circular-buffers.rst
 * in the linux tree for more information.
 *
 * The associated struct device (*oal_device) owns the oal. The
 * release() method of oal_device frees the oal and releases its
 * minor. This may seem slightly more complicated than necessary but
 * it allows the OST to be unmounted while the oal still has open file
 * descriptors.
 */

enum {
	OAL_DEV_COUNT = 1 << MINORBITS,
};

struct ofd_access_log {
	char oal_name[128]; /* lustre-OST0000 */
	struct device oal_device;
	struct cdev oal_cdev;
	struct rw_semaphore oal_buf_list_sem;
	struct list_head oal_circ_buf_list;
	unsigned int oal_is_closed;
	unsigned int oal_log_size;
	unsigned int oal_entry_size;
};

struct oal_circ_buf {
	struct list_head ocb_list;
	spinlock_t ocb_write_lock;
	spinlock_t ocb_read_lock;
	struct ofd_access_log *ocb_access_log;
	__u32 ocb_filter;
	wait_queue_head_t ocb_read_wait_queue;
	unsigned int ocb_drop_count;
	struct circ_buf ocb_circ;
};

static atomic_t oal_control_event_count = ATOMIC_INIT(0);
static DECLARE_WAIT_QUEUE_HEAD(oal_control_wait_queue);

static struct class *oal_log_class;
static unsigned int oal_log_major;
static DEFINE_IDR(oal_log_minor_idr); /* TODO Use ida instead. */
static DEFINE_SPINLOCK(oal_log_minor_lock);

bool ofd_access_log_size_is_valid(unsigned int size)
{
	const unsigned int size_min = 2 * sizeof(struct ofd_access_entry_v1);
	const unsigned int size_max = 1U << 30;

	if (size == 0)
		return true;

	return is_power_of_2(size) && size_min <= size && size <= size_max;
}

static void oal_control_event_inc(void)
{
	atomic_inc(&oal_control_event_count);
	wake_up(&oal_control_wait_queue);
}

static int oal_log_minor_alloc(int *pminor)
{
	void *OAL_LOG_MINOR_ALLOCED = (void *)-1;
	int minor;

	idr_preload(GFP_KERNEL);
	spin_lock(&oal_log_minor_lock);
	minor = idr_alloc(&oal_log_minor_idr, OAL_LOG_MINOR_ALLOCED, 0,
			OAL_DEV_COUNT, GFP_NOWAIT);
	spin_unlock(&oal_log_minor_lock);
	idr_preload_end();

	if (minor < 0)
		return minor;

	*pminor = minor;

	return 0;
}

static void oal_log_minor_free(int minor)
{
	spin_lock(&oal_log_minor_lock);
	idr_remove(&oal_log_minor_idr, minor);
	spin_unlock(&oal_log_minor_lock);
}

static bool oal_is_empty(struct oal_circ_buf *ocb)
{
	struct ofd_access_log *oal = ocb->ocb_access_log;

	return CIRC_CNT(ocb->ocb_circ.head,
			ocb->ocb_circ.tail,
			oal->oal_log_size) < oal->oal_entry_size;
}

static ssize_t oal_write_entry(struct oal_circ_buf *ocb,
			const void *entry, size_t entry_size)
{
	struct ofd_access_log *oal = ocb->ocb_access_log;
	struct circ_buf *circ = &ocb->ocb_circ;
	unsigned int head;
	unsigned int tail;
	ssize_t rc;

	if (entry_size != oal->oal_entry_size)
		return -EINVAL;

	spin_lock(&ocb->ocb_write_lock);
	head = circ->head;
	tail = READ_ONCE(circ->tail);

	/* CIRC_SPACE() return space available, 0..oal_log_size -
	 * 1. It always leaves one free char, since a completely full
	 * buffer would have head == tail, which is the same as empty. */
	if (CIRC_SPACE(head, tail, oal->oal_log_size) < oal->oal_entry_size) {
		ocb->ocb_drop_count++;
		rc = -EAGAIN;
		goto out_write_lock;
	}

	memcpy(&circ->buf[head], entry, entry_size);
	rc = entry_size;

	/* Ensure the entry is stored before we update the head. */
	smp_store_release(&circ->head,
			(head + oal->oal_entry_size) & (oal->oal_log_size - 1));

	wake_up(&ocb->ocb_read_wait_queue);
out_write_lock:
	spin_unlock(&ocb->ocb_write_lock);

	return rc;
}

/* Read one entry from the log and return its size. Non-blocking.
 * When the log is empty we return -EAGAIN if the OST is still mounted
 * and 0 otherwise.
 */
static ssize_t oal_read_entry(struct oal_circ_buf *ocb,
			void *entry_buf, size_t entry_buf_size)
{
	struct ofd_access_log *oal = ocb->ocb_access_log;
	struct circ_buf *circ = &ocb->ocb_circ;
	unsigned int head;
	unsigned int tail;
	ssize_t rc;

	/* XXX This method may silently truncate entries when
	 * entry_buf_size is less than oal_entry_size. But that's OK
	 * because you know what you are doing. */
	spin_lock(&ocb->ocb_read_lock);

	/* Memory barrier usage follows circular-buffers.txt. */
	head = smp_load_acquire(&circ->head);
	tail = circ->tail;

	if (!CIRC_CNT(head, tail, oal->oal_log_size)) {
		rc = oal->oal_is_closed ? 0 : -EAGAIN;
		goto out_read_lock;
	}

	BUG_ON(CIRC_CNT(head, tail, oal->oal_log_size) < oal->oal_entry_size);

	/* Extract one entry from the buffer. */
	rc = min_t(size_t, oal->oal_entry_size, entry_buf_size);
	memcpy(entry_buf, &circ->buf[tail], rc);

	/* Memory barrier usage follows circular-buffers.txt. */
	smp_store_release(&circ->tail,
			(tail + oal->oal_entry_size) & (oal->oal_log_size - 1));

out_read_lock:
	spin_unlock(&ocb->ocb_read_lock);

	return rc;
}

static int oal_file_open(struct inode *inode, struct file *filp)
{
	struct ofd_access_log *oal;
	struct oal_circ_buf *ocb;

	oal = container_of(inode->i_cdev, struct ofd_access_log, oal_cdev);

	ocb = kzalloc(sizeof(*ocb), GFP_KERNEL);
	if (!ocb)
		return -ENOMEM;
	ocb->ocb_circ.buf = vmalloc(oal->oal_log_size);
	if (!ocb->ocb_circ.buf) {
		kfree(ocb);
		return -ENOMEM;
	}

	spin_lock_init(&ocb->ocb_write_lock);
	spin_lock_init(&ocb->ocb_read_lock);
	ocb->ocb_access_log = oal;
	init_waitqueue_head(&ocb->ocb_read_wait_queue);

	down_write(&oal->oal_buf_list_sem);
	list_add(&ocb->ocb_list, &oal->oal_circ_buf_list);
	up_write(&oal->oal_buf_list_sem);

	filp->private_data = ocb;

	return nonseekable_open(inode, filp);
}

/* User buffer size must be a multiple of ofd access entry size. */
static ssize_t oal_file_read(struct file *filp, char __user *buf, size_t count,
			loff_t *ppos)
{
	struct oal_circ_buf *ocb = filp->private_data;
	struct ofd_access_log *oal = ocb->ocb_access_log;
	void *entry;
	size_t size = 0;
	int rc = 0;

	if (!count)
		return 0;

	if (count & (oal->oal_entry_size - 1))
		return -EINVAL;

	entry = kzalloc(oal->oal_entry_size, GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	while (size < count) {
		rc = oal_read_entry(ocb, entry, oal->oal_entry_size);
		if (rc == -EAGAIN) {
			if (filp->f_flags & O_NONBLOCK)
				break;

			rc = wait_event_interruptible(ocb->ocb_read_wait_queue,
				!oal_is_empty(ocb) || oal->oal_is_closed);
			if (rc)
				break;
		} else if (rc <= 0) {
			break; /* cloed or error */
		} else {
			if (copy_to_user(buf, entry, oal->oal_entry_size)) {
				rc = -EFAULT;
				break;
			}

			buf += oal->oal_entry_size;
			size += oal->oal_entry_size;
		}
	}

	kfree(entry);

	return size ? size : rc;
}

/* Included for test purposes. User buffer size must be a multiple of
 * ofd access entry size. */
static ssize_t oal_file_write(struct file *filp, const char __user *buf,
			size_t count, loff_t *ppos)
{
	struct oal_circ_buf *ocb = filp->private_data;
	struct ofd_access_log *oal = ocb->ocb_access_log;
	void *entry;
	size_t size = 0;
	ssize_t rc = 0;

	if (!count)
		return 0;

	if (count & (oal->oal_entry_size - 1))
		return -EINVAL;

	entry = kzalloc(oal->oal_entry_size, GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	while (size < count) {
		if (copy_from_user(entry, buf, oal->oal_entry_size)) {
			rc = -EFAULT;
			break;
		}

		rc = oal_write_entry(ocb, entry, oal->oal_entry_size);
		if (rc <= 0)
			break;

		buf += oal->oal_entry_size;
		size += oal->oal_entry_size;
	}

	kfree(entry);

	return size > 0 ? size : rc;
}

unsigned int oal_file_poll(struct file *filp, struct poll_table_struct *wait)
{
	struct oal_circ_buf *ocb = filp->private_data;
	struct ofd_access_log *oal = ocb->ocb_access_log;
	unsigned int mask = 0;

	poll_wait(filp, &ocb->ocb_read_wait_queue, wait);

	spin_lock(&ocb->ocb_read_lock);

	if (!oal_is_empty(ocb) || oal->oal_is_closed)
		mask |= POLLIN;

	spin_unlock(&ocb->ocb_read_lock);

	return mask;
}

static long oal_ioctl_info(struct oal_circ_buf *ocb, unsigned long arg)
{
	struct ofd_access_log *oal = ocb->ocb_access_log;

	struct lustre_access_log_info_v1 __user *lali;
	u32 entry_count = CIRC_CNT(ocb->ocb_circ.head,
				ocb->ocb_circ.tail,
				oal->oal_log_size) / oal->oal_entry_size;
	u32 entry_space = CIRC_SPACE(ocb->ocb_circ.head,
				ocb->ocb_circ.tail,
				oal->oal_log_size) / oal->oal_entry_size;

	lali = (struct lustre_access_log_info_v1 __user *)arg;
	BUILD_BUG_ON(sizeof(lali->lali_name) != sizeof(oal->oal_name));

	if (put_user(LUSTRE_ACCESS_LOG_VERSION_1, &lali->lali_version))
		return -EFAULT;

	if (put_user(LUSTRE_ACCESS_LOG_TYPE_OFD, &lali->lali_type))
		return -EFAULT;

	if (copy_to_user(lali->lali_name, oal->oal_name, sizeof(oal->oal_name)))
		return -EFAULT;

	if (put_user(oal->oal_log_size, &lali->lali_log_size))
		return -EFAULT;

	if (put_user(oal->oal_entry_size, &lali->lali_entry_size))
		return -EFAULT;

	if (put_user(ocb->ocb_circ.head, &lali->_lali_head))
		return -EFAULT;

	if (put_user(ocb->ocb_circ.tail, &lali->_lali_tail))
		return -EFAULT;

	if (put_user(entry_space, &lali->_lali_entry_space))
		return -EFAULT;

	if (put_user(entry_count, &lali->_lali_entry_count))
		return -EFAULT;

	if (put_user(ocb->ocb_drop_count, &lali->_lali_drop_count))
		return -EFAULT;

	if (put_user(oal->oal_is_closed, &lali->_lali_is_closed))
		return -EFAULT;

	return 0;
}

static long oal_file_ioctl(struct file *filp, unsigned int cmd,
			unsigned long arg)
{
	struct oal_circ_buf *ocb = filp->private_data;

	switch (cmd) {
	case LUSTRE_ACCESS_LOG_IOCTL_VERSION:
		return LUSTRE_ACCESS_LOG_VERSION_1;
	case LUSTRE_ACCESS_LOG_IOCTL_INFO:
		return oal_ioctl_info(ocb, arg);
	case LUSTRE_ACCESS_LOG_IOCTL_FILTER:
		ocb->ocb_filter = arg;
		return 0;
	default:
		return -ENOTTY;
	}
}

static int oal_file_release(struct inode *inode, struct file *filp)
{
	struct oal_circ_buf *ocb = filp->private_data;
	struct ofd_access_log *oal = ocb->ocb_access_log;

	down_write(&oal->oal_buf_list_sem);
	list_del(&ocb->ocb_list);
	up_write(&oal->oal_buf_list_sem);

	vfree(ocb->ocb_circ.buf);
	kfree(ocb);

	return 0;
}

static const struct file_operations oal_fops = {
	.owner = THIS_MODULE,
	.open = &oal_file_open,
	.release = &oal_file_release,
	.unlocked_ioctl = &oal_file_ioctl,
	.read = &oal_file_read,
	.write = &oal_file_write,
	.poll = &oal_file_poll,
	.llseek = &no_llseek,
};

static void oal_device_release(struct device *dev)
{
	struct ofd_access_log *oal = dev_get_drvdata(dev);

	oal_log_minor_free(MINOR(oal->oal_device.devt));
	BUG_ON(!list_empty(&oal->oal_circ_buf_list));
	kfree(oal);
}

struct ofd_access_log *ofd_access_log_create(const char *ofd_name, size_t size)
{
	const size_t entry_size = sizeof(struct ofd_access_entry_v1);
	struct ofd_access_log *oal;
	int minor;
	int rc;

	BUILD_BUG_ON(sizeof(oal->oal_name) != MAX_OBD_NAME);
	BUILD_BUG_ON(!is_power_of_2(entry_size));

	if (!size)
		return NULL;

	if (!is_power_of_2(size) || (size & (entry_size - 1)) ||
	    (unsigned int)size != size)
		return ERR_PTR(-EINVAL);

	oal = kzalloc(sizeof(*oal), GFP_KERNEL);
	if (!oal)
		return ERR_PTR(-ENOMEM);

	strlcpy(oal->oal_name, ofd_name, sizeof(oal->oal_name));
	oal->oal_log_size = size;
	oal->oal_entry_size = entry_size;
	INIT_LIST_HEAD(&oal->oal_circ_buf_list);
	init_rwsem(&oal->oal_buf_list_sem);

	rc = oal_log_minor_alloc(&minor);
	if (rc < 0)
		goto out_free;

	device_initialize(&oal->oal_device);
	oal->oal_device.devt = MKDEV(oal_log_major, minor);
	oal->oal_device.class = oal_log_class;
	oal->oal_device.release = &oal_device_release;
	dev_set_drvdata(&oal->oal_device, oal);
	rc = dev_set_name(&oal->oal_device,
			"%s!%s", LUSTRE_ACCESS_LOG_DIR_NAME, oal->oal_name);
	if (rc < 0)
		goto out_minor;

	cdev_init(&oal->oal_cdev, &oal_fops);
	oal->oal_cdev.owner = THIS_MODULE;
	rc = cdev_device_add(&oal->oal_cdev, &oal->oal_device);
	if (rc < 0)
		goto out_device_name;

	oal_control_event_inc();

	return oal;

out_device_name:
	kfree_const(oal->oal_device.kobj.name);
out_minor:
	oal_log_minor_free(minor);
out_free:
	kfree(oal);

	return ERR_PTR(rc);
}

void ofd_access(const struct lu_env *env,
		struct ofd_device *m,
		const struct lu_fid *parent_fid,
		__u64 begin, __u64 end,
		unsigned int size,
		unsigned int segment_count,
		int rw)
{
	unsigned int flags = (rw == READ) ? OFD_ACCESS_READ : OFD_ACCESS_WRITE;
	struct ofd_access_log *oal = m->ofd_access_log;

	/* obdfilter-survey does not set parent FIDs. */
	if (fid_is_zero(parent_fid))
		return;

	if (oal && (flags & m->ofd_access_log_mask)) {
		struct ofd_access_entry_v1 oae = {
			.oae_parent_fid = *parent_fid,
			.oae_begin = begin,
			.oae_end = end,
			.oae_time = ktime_get_real_seconds(),
			.oae_size = size,
			.oae_segment_count = segment_count,
			.oae_flags = flags,
		};
		struct lu_seq_range range = {
			.lsr_flags = LU_SEQ_RANGE_ANY,
		};
		struct oal_circ_buf *ocb;
		int rc;

		/* learn target MDT from FID's sequence */
		rc = fld_server_lookup(env, m->ofd_seq_site.ss_server_fld,
				       fid_seq(parent_fid), &range);
		if (unlikely(rc))
			CERROR("%s: can't resolve "DFID": rc=%d\n",
			       ofd_name(m), PFID(parent_fid), rc);

		down_read(&oal->oal_buf_list_sem);
		list_for_each_entry(ocb, &oal->oal_circ_buf_list, ocb_list) {
			/* filter by MDT index if requested */
			if (ocb->ocb_filter == 0xffffffff ||
			    range.lsr_index == ocb->ocb_filter)
				oal_write_entry(ocb, &oae, sizeof(oae));
		}
		up_read(&oal->oal_buf_list_sem);
	}
}

/* Called on OST umount to:
 * - Close the write end of the oal. The wakes any tasks sleeping in
 *   read or poll and makes all reads return zero once the log
 *   becomes empty.
 * - Delete the associated stuct device and cdev, preventing new
 *   opens. Existing opens retain a reference on the oal through
 *   their reference on oal_device.
 * The oal will be freed when the last open file handle is closed. */
void ofd_access_log_delete(struct ofd_access_log *oal)
{
	struct oal_circ_buf *ocb;

	if (!oal)
		return;

	oal->oal_is_closed = 1;
	down_read(&oal->oal_buf_list_sem);
	list_for_each_entry(ocb, &oal->oal_circ_buf_list, ocb_list)
		wake_up(&ocb->ocb_read_wait_queue);
	up_read(&oal->oal_buf_list_sem);
	cdev_device_del(&oal->oal_cdev, &oal->oal_device);
}

/* private_data for control device file. */
struct oal_control_file {
	int ccf_event_count;
};

/* Control file usage:
 * Open /dev/lustre-access-log/control.
 * while (1)
 *   Poll for readable on control FD.
 *   Call ioctl(FD, LUSTRE_ACCESS_LOG_IOCTL_PRESCAN) to fetch event count.
 *   Scan /dev/ or /sys/class/... for new devices.
 */
static int oal_control_file_open(struct inode *inode, struct file *filp)
{
	struct oal_control_file *ccf;
	int rc;

	rc = nonseekable_open(inode, filp);
	if (rc)
		return rc;

	/* ccf->ccf_event_count = 0 on open */
	ccf = kzalloc(sizeof(*ccf), GFP_KERNEL);
	if (!ccf)
		return -ENOMEM;

	filp->private_data = ccf;

	return 0;
}

static int oal_control_file_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	return 0;
}

static unsigned int oal_control_file_poll(struct file *filp, poll_table *wait)
{
	struct oal_control_file *ccf = filp->private_data;
	unsigned int mask = 0;

	poll_wait(filp, &oal_control_wait_queue, wait);

	if (atomic_read(&oal_control_event_count) != ccf->ccf_event_count)
		mask |= POLLIN;

	return mask;
}

static long oal_control_file_ioctl(struct file *filp, unsigned int cmd,
				unsigned long arg)
{
	struct oal_control_file *ccf = filp->private_data;

	switch (cmd) {
	case LUSTRE_ACCESS_LOG_IOCTL_VERSION:
		return LUSTRE_ACCESS_LOG_VERSION_1;
	case LUSTRE_ACCESS_LOG_IOCTL_MAJOR:
		return oal_log_major;
	case LUSTRE_ACCESS_LOG_IOCTL_PRESCAN:
		ccf->ccf_event_count = atomic_read(&oal_control_event_count);
		return 0;
	default:
		return -ENOTTY;
	}
}

static const struct file_operations oal_control_fops = {
	.owner = THIS_MODULE,
	.open = &oal_control_file_open,
	.release = &oal_control_file_release,
	.poll = &oal_control_file_poll,
	.unlocked_ioctl = &oal_control_file_ioctl,
	.llseek = &noop_llseek,
};

static struct miscdevice oal_control_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = LUSTRE_ACCESS_LOG_DIR_NAME"!control",
	.fops = &oal_control_fops,
};

int ofd_access_log_module_init(void)
{
	dev_t dev;
	int rc;

	BUILD_BUG_ON(!is_power_of_2(sizeof(struct ofd_access_entry_v1)));

	rc = misc_register(&oal_control_misc);
	if (rc)
		return rc;

	rc = alloc_chrdev_region(&dev, 0, OAL_DEV_COUNT,
				LUSTRE_ACCESS_LOG_DIR_NAME);
	if (rc)
		goto out_oal_control_misc;

	oal_log_major = MAJOR(dev);

	oal_log_class = class_create(THIS_MODULE, LUSTRE_ACCESS_LOG_DIR_NAME);
	if (IS_ERR(oal_log_class)) {
		rc = PTR_ERR(oal_log_class);
		goto out_dev;
	}

	return 0;
out_dev:
	unregister_chrdev_region(dev, OAL_DEV_COUNT);
out_oal_control_misc:
	misc_deregister(&oal_control_misc);

	return rc;
}

void ofd_access_log_module_exit(void)
{
	class_destroy(oal_log_class);
	unregister_chrdev_region(MKDEV(oal_log_major, 0), OAL_DEV_COUNT);
	idr_destroy(&oal_log_minor_idr);
	misc_deregister(&oal_control_misc);
}
