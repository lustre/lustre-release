/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 *
 * Object Devices Class Driver
 */

#define EXPORT_SYMTAB
#include <linux/config.h> /* for CONFIG_PROC_FS */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/sched.h>
#include <linux/lp.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/delay.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <asm/ioctls.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/smp_lock.h>
#include <linux/lprocfs_status.h>
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lustre_build_version.h>

struct semaphore obd_conf_sem;   /* serialize configuration commands */
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;
atomic_t obd_memory;
int obd_memmax;

/* The following are visible and mutable through /proc/sys/lustre/. */
unsigned long obd_fail_loc;
unsigned long obd_timeout = 100;
char obd_recovery_upcall[128] = "/usr/lib/lustre/ha_assist";

/*  opening /dev/obd */
static int obd_class_open(struct inode * inode, struct file * file)
{
        ENTRY;

        file->private_data = NULL;
        MOD_INC_USE_COUNT;
        RETURN(0);
}

/*  closing /dev/obd */
static int obd_class_release(struct inode * inode, struct file * file)
{
        ENTRY;

        // XXX drop lsm, connections here
        if (file->private_data)
                file->private_data = NULL;
        MOD_DEC_USE_COUNT;
        RETURN(0);
}

static inline void obd_data2conn(struct lustre_handle *conn,
                                 struct obd_ioctl_data *data)
{
        conn->addr = data->ioc_addr;
        conn->cookie = data->ioc_cookie;
}

static inline void obd_conn2data(struct obd_ioctl_data *data,
                                 struct lustre_handle *conn)
{
        data->ioc_addr = conn->addr;
        data->ioc_cookie = conn->cookie;
}

static void forcibly_detach_exports(struct obd_device *obd)
{
        int rc;
        struct list_head *tmp, *n;
        struct lustre_handle fake_conn;

        CDEBUG(D_IOCTL, "OBD device %d (%p) has exports, "
               "disconnecting them", obd->obd_minor, obd);
        list_for_each_safe(tmp, n, &obd->obd_exports) {
                struct obd_export *exp = list_entry(tmp, struct obd_export,
                                                    exp_obd_chain);
                fake_conn.addr = (__u64)(unsigned long)exp;
                fake_conn.cookie = exp->exp_cookie;
                rc = obd_disconnect(&fake_conn);
                if (rc) {
                        CDEBUG(D_IOCTL, "disconnecting export %p failed: %d\n",
                               exp, rc);
                } else {
                        CDEBUG(D_IOCTL, "export %p disconnected\n", exp);
                }
        }
}

/* to control /dev/obd */
static int obd_class_ioctl (struct inode * inode, struct file * filp,
                            unsigned int cmd, unsigned long arg)
{
        char *buf = NULL;
        struct obd_ioctl_data *data;
        struct obd_device *obd = filp->private_data;
        struct lustre_handle conn;
        int err = 0, len = 0, serialised = 0;
        ENTRY;

        switch (cmd) {
        case OBD_IOC_BRW_WRITE:
        case OBD_IOC_BRW_READ:
        case OBD_IOC_GETATTR:
                break;
        default:
                down(&obd_conf_sem);
                serialised = 1;
                break;
        }

        if (!obd && cmd != OBD_IOC_DEVICE && cmd != TCGETS &&
            cmd != OBD_IOC_LIST && cmd != OBD_GET_VERSION &&
            cmd != OBD_IOC_NAME2DEV && cmd != OBD_IOC_NEWDEV) {
                CERROR("OBD ioctl: No device\n");
                GOTO(out, err = -EINVAL);
        }
        if (obd_ioctl_getdata(&buf, &len, (void *)arg)) {
                CERROR("OBD ioctl: data error\n");
                GOTO(out, err = -EINVAL);
        }
        data = (struct obd_ioctl_data *)buf;

        switch (cmd) {
        case TCGETS:
                GOTO(out, err=-EINVAL);
        case OBD_IOC_DEVICE: {
                CDEBUG(D_IOCTL, "\n");
                if (data->ioc_dev >= MAX_OBD_DEVICES || data->ioc_dev < 0) {
                        CERROR("OBD ioctl: DEVICE insufficient devices\n");
                        GOTO(out, err=-EINVAL);
                }
                CDEBUG(D_IOCTL, "device %d\n", data->ioc_dev);

                filp->private_data = &obd_dev[data->ioc_dev];
                GOTO(out, err=0);
        }

        case OBD_IOC_LIST: {
                int i;
                char *buf2 = data->ioc_bulk;
                int remains = data->ioc_inllen1;

                if (!data->ioc_inlbuf1) {
                        CERROR("No buffer passed!\n");
                        GOTO(out, err=-EINVAL);
                }


                for (i = 0 ; i < MAX_OBD_DEVICES ; i++) {
                        int l;
                        char *status;
                        struct obd_device *obd = &obd_dev[i];
                        if (!obd->obd_type)
                                continue;
                        if (obd->obd_flags & OBD_SET_UP)
                                status = "UP";
                        else if (obd->obd_flags & OBD_ATTACHED)
                                status = "AT";
                        else
                                status = "-";
                        l = snprintf(buf2, remains, "%2d %s %s %s %s %d\n",
                                     i, status, obd->obd_type->typ_name,
                                     obd->obd_name, obd->obd_uuid, obd->obd_type->typ_refcnt);
                        buf2 +=l;
                        remains -=l;
                        if (remains <= 0) {
                                CERROR("not enough space for device listing\n");
                                break;
                        }
                }

                err = copy_to_user((void *)arg, data, len);
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }

        case OBD_GET_VERSION:
                if (!data->ioc_inlbuf1) {
                        CERROR("No buffer passed in ioctl\n");
                        GOTO(out, err = -EINVAL);
                }

                if (strlen(BUILD_VERSION) + 1 > data->ioc_inllen1) {
                        CERROR("ioctl buffer too small to hold version\n");
                        GOTO(out, err = -EINVAL);
                }

                memcpy(data->ioc_bulk, BUILD_VERSION,
                       strlen(BUILD_VERSION) + 1);

                err = copy_to_user((void *)arg, data, len);
                if (err)
                        err = -EFAULT;
                GOTO(out, err);

        case OBD_IOC_NAME2DEV: {
                /* Resolve a device name.  This does not change the
                 * currently selected device.
                 */
                int dev;

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1 ) {
                        CERROR("No name passed,!\n");
                        GOTO(out, err=-EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1-1] !=0) {
                        CERROR("Name not nul terminated!\n");
                        GOTO(out, err=-EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
                dev = class_name2dev(data->ioc_inlbuf1);
                data->ioc_dev = dev;
                if (dev == -1) {
                        CDEBUG(D_IOCTL, "No device for name %s!\n",
                               data->ioc_inlbuf1);
                        GOTO(out, err=-EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s, dev %d\n", data->ioc_inlbuf1,
                       dev);
                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }

        case OBD_IOC_UUID2DEV: {
                /* Resolve a device uuid.  This does not change the
                 * currently selected device.
                 */
                int dev;

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
                        CERROR("No UUID passed!\n");
                        GOTO(out, err=-EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1-1] !=0) {
                        CERROR("Name not nul terminated!\n");
                        GOTO(out, err=-EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
                dev = class_uuid2dev(data->ioc_inlbuf1);
                data->ioc_dev = dev;
                if (dev == -1) {
                        CDEBUG(D_IOCTL, "No device for name %s!\n",
                               data->ioc_inlbuf1);
                        GOTO(out, err=-EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s, dev %d\n", data->ioc_inlbuf1,
                       dev);
                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }

        case OBD_IOC_NEWDEV: {
                int dev = -1;
                int i;

                filp->private_data = NULL;
                for (i = 0 ; i < MAX_OBD_DEVICES ; i++) {
                        struct obd_device *obd = &obd_dev[i];
                        if (!obd->obd_type) {
                                filp->private_data = obd;
                                dev = i;
                                break;
                        }
                }


                data->ioc_dev = dev;
                if (dev == -1)
                        GOTO(out, err=-EINVAL);

                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }

        case OBD_IOC_ATTACH: {
                struct obd_type *type;
                int minor;

                /* have we attached a type to this device */
                if (obd->obd_flags & OBD_ATTACHED || obd->obd_type) {
                        CERROR("OBD: Device %d already typed as %s.\n",
                               obd->obd_minor, MKSTR(obd->obd_type->typ_name));
                        GOTO(out, err = -EBUSY);
                }

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
                        CERROR("No type passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1-1] !=0) {
                        CERROR("Type not nul terminated!\n");
                        GOTO(out, err = -EINVAL);
                }

                CDEBUG(D_IOCTL, "attach type %s name: %s uuid: %s\n",
                       MKSTR(data->ioc_inlbuf1),
                       MKSTR(data->ioc_inlbuf2), MKSTR(data->ioc_inlbuf3));

                /* find the type */
                type = class_get_type(data->ioc_inlbuf1);
                if (!type) {
                        CERROR("OBD: unknown type dev %d\n", obd->obd_minor);
                        GOTO(out, err = -EINVAL);
                }

                minor = obd->obd_minor;
                memset(obd, 0, sizeof(*obd));
                obd->obd_minor = minor;
                obd->obd_type = type;
                INIT_LIST_HEAD(&obd->obd_exports);
                INIT_LIST_HEAD(&obd->obd_imports);
                spin_lock_init(&obd->obd_dev_lock);

                if (data->ioc_inlbuf2) {
                        int len = strlen(data->ioc_inlbuf2) + 1;
                        OBD_ALLOC(obd->obd_name, len);
                        if (!obd->obd_name) {
                                class_put_type(obd->obd_type);
                                GOTO(out, err = -ENOMEM);
                        }
                        memcpy(obd->obd_name, data->ioc_inlbuf2, len);
                } else {
                        CERROR("WARNING: unnamed obd device\n");
                }
                if (data->ioc_inlbuf3) {
                        int len = strlen(data->ioc_inlbuf3);
                        if (len >= sizeof(obd->obd_uuid)) {
                                CERROR("uuid must be < "LPSZ" bytes long\n",
                                       sizeof(obd->obd_uuid));
                                if (obd->obd_name)
                                        OBD_FREE(obd->obd_name,
                                                 strlen(obd->obd_name) + 1);
                                class_put_type(obd->obd_type);
                                GOTO(out, err=-EINVAL);
                        }
                        memcpy(obd->obd_uuid, data->ioc_inlbuf3, len);
                }
                /* do the attach */
                if (OBP(obd, attach))
                        err = OBP(obd,attach)(obd, sizeof(*data), data);
                if (err) {
                        if(data->ioc_inlbuf2)
                                OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                        class_put_type(obd->obd_type);
                        obd->obd_type = NULL;
                } else {
                        obd->obd_flags |= OBD_ATTACHED;

                        type->typ_refcnt++;
                        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
                               obd->obd_minor, data->ioc_inlbuf1);
                }

                GOTO(out, err);
        }

        case OBD_IOC_DETACH: {
                ENTRY;
                if (obd->obd_flags & OBD_SET_UP) {
                        CERROR("OBD device %d still set up\n", obd->obd_minor);
                        GOTO(out, err=-EBUSY);
                }
                if (!(obd->obd_flags & OBD_ATTACHED) ) {
                        CERROR("OBD device %d not attached\n", obd->obd_minor);
                        GOTO(out, err=-ENODEV);
                }
                if (!list_empty(&obd->obd_exports)) {
                        if (!data->ioc_inlbuf1 || data->ioc_inlbuf1[0] != 'F') {
                                CERROR("OBD device %d (%p) has exports\n",
                                       obd->obd_minor, obd);
                                GOTO(out, err=-EBUSY);
                        }
                        forcibly_detach_exports(obd);
                }
                if (OBP(obd, detach))
                        err = OBP(obd,detach)(obd);

                if (obd->obd_name) {
                        OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                        obd->obd_name = NULL;
                }

                obd->obd_flags &= ~OBD_ATTACHED;
                obd->obd_type->typ_refcnt--;
                class_put_type(obd->obd_type);
                obd->obd_type = NULL;
                GOTO(out, err = 0);
        }

        case OBD_IOC_SETUP: {
                /* have we attached a type to this device? */
                if (!(obd->obd_flags & OBD_ATTACHED)) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        GOTO(out, err=-ENODEV);
                }

                /* has this been done already? */
                if ( obd->obd_flags & OBD_SET_UP ) {
                        CERROR("Device %d already setup (type %s)\n",
                               obd->obd_minor, obd->obd_type->typ_name);
                        GOTO(out, err=-EBUSY);
                }

                if ( OBT(obd) && OBP(obd, setup) )
                        err = obd_setup(obd, sizeof(*data), data);

                if (!err) {
                        obd->obd_type->typ_refcnt++;
                        obd->obd_flags |= OBD_SET_UP;
                }

                GOTO(out, err);
        }
        case OBD_IOC_CLEANUP: {
                /* have we attached a type to this device? */
                if (!(obd->obd_flags & OBD_ATTACHED)) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        GOTO(out, err=-ENODEV);
                }

                if ( OBT(obd) && OBP(obd, cleanup) )
                        err = obd_cleanup(obd);

                if (!err) {
                        obd->obd_flags &= ~OBD_SET_UP;
                        obd->obd_type->typ_refcnt--;
                }
                      GOTO(out, err);
        }

        case OBD_IOC_CONNECT: {
                char * cluuid = "OBD_CLASS_UUID";
                obd_data2conn(&conn, data);

                err = obd_connect(&conn, obd, cluuid, NULL, NULL);

                CDEBUG(D_IOCTL, "assigned export "LPX64"\n", conn.addr);
                obd_conn2data(data, &conn);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err)
                        err = -EFAULT;
                // XXX save connection data into file handle
                GOTO(out, err);
        }

        case OBD_IOC_DISCONNECT: {
                obd_data2conn(&conn, data);
                err = obd_disconnect(&conn);
                GOTO(out, err);
        }

        default:
                obd_data2conn(&conn, data);

                err = obd_iocontrol(cmd, &conn, len, data, NULL);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((void *)arg, data, len);
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }

 out:
        if (buf)
                OBD_FREE(buf, len);
        if (serialised)
                up(&obd_conf_sem);
        RETURN(err);
} /* obd_class_ioctl */



/* declare character device */
static struct file_operations obd_psdev_fops = {
        ioctl: obd_class_ioctl,      /* ioctl */
        open: obd_class_open,        /* open */
        release: obd_class_release,  /* release */
};

/* modules setup */
#define OBD_MINOR 241
static struct miscdevice obd_psdev = {
        OBD_MINOR,
        "obd_psdev",
        &obd_psdev_fops
};

void (*class_signal_connection_failure)(struct ptlrpc_connection *);

#ifdef CONFIG_HIGHMEM
/* Allow at most 3/4 of the kmap mappings to be consumed by vector I/O
 * requests.  This avoids deadlocks on servers which have a lot of clients
 * doing vector I/O.  We don't need to do this for non-vector I/O requests
 * because singleton requests will just block on the kmap itself and never
 * deadlock waiting for additional kmaps to complete.
 *
 * If we are a "server" task, we can have at most a single reservation
 * in excess of the maximum.  This avoids a deadlock when multiple client
 * threads are on the same machine as the server threads, and the clients
 * have consumed all of the available mappings.  As long as a single server
 * thread is can make progress, we are guaranteed to avoid deadlock.
 */
#define OBD_KMAP_MAX (LAST_PKMAP * 3 / 4)
static atomic_t obd_kmap_count = ATOMIC_INIT(OBD_KMAP_MAX);
static DECLARE_WAIT_QUEUE_HEAD(obd_kmap_waitq);

void obd_kmap_get(int count, int server)
{
        //CERROR("getting %d kmap counts (%d/%d)\n", count,
        //       atomic_read(&obd_kmap_count), OBD_KMAP_MAX);
        if (count == 1)
                atomic_dec(&obd_kmap_count);
        else while (atomic_add_negative(-count, &obd_kmap_count)) {
                static long next_show = 0;
                static int skipped = 0;

                if (server && atomic_read(&obd_kmap_count) >= -PTL_MD_MAX_IOV)
                        break;

                CDEBUG(D_OTHER, "negative kmap reserved count: %d\n",
                       atomic_read(&obd_kmap_count));
                atomic_add(count, &obd_kmap_count);

                if (time_after(jiffies, next_show)) {
                        CERROR("blocking %s (and %d others) for kmaps\n",
                               current->comm, skipped);
                        next_show = jiffies + 5*HZ;
                        skipped = 0;
                } else
                        skipped++;
                wait_event(obd_kmap_waitq,
                           atomic_read(&obd_kmap_count) >= count);
        }
}

void obd_kmap_put(int count)
{
        atomic_add(count, &obd_kmap_count);
        /* Wake up sleepers.  Sadly, this wakes up all of the tasks at once.
         * We could have something smarter here like:
        while (atomic_read(&obd_kmap_count) > 0)
                wake_up_nr(obd_kmap_waitq, 1);
        although we would need to set somewhere (probably obd_class_init):
        obd_kmap_waitq.flags |= WQ_FLAG_EXCLUSIVE;
        For now the wait_event() condition will handle this OK I believe.
         */
        if (atomic_read(&obd_kmap_count) > 0)
                wake_up(&obd_kmap_waitq);
}

EXPORT_SYMBOL(obd_kmap_get);
EXPORT_SYMBOL(obd_kmap_put);
#endif

EXPORT_SYMBOL(obd_dev);
EXPORT_SYMBOL(obdo_cachep);
EXPORT_SYMBOL(obd_memory);
EXPORT_SYMBOL(obd_memmax);
EXPORT_SYMBOL(obd_fail_loc);
EXPORT_SYMBOL(obd_timeout);
EXPORT_SYMBOL(obd_recovery_upcall);
EXPORT_SYMBOL(ptlrpc_put_connection_superhack);

EXPORT_SYMBOL(class_register_type);
EXPORT_SYMBOL(class_unregister_type);
EXPORT_SYMBOL(class_get_type);
EXPORT_SYMBOL(class_put_type);
EXPORT_SYMBOL(class_name2dev);
EXPORT_SYMBOL(class_uuid2dev);
EXPORT_SYMBOL(class_uuid2obd);
EXPORT_SYMBOL(class_new_export);
EXPORT_SYMBOL(class_destroy_export);
EXPORT_SYMBOL(class_connect);
EXPORT_SYMBOL(class_conn2export);
EXPORT_SYMBOL(class_conn2obd);
EXPORT_SYMBOL(class_conn2cliimp);
EXPORT_SYMBOL(class_conn2ldlmimp);
EXPORT_SYMBOL(class_disconnect);
EXPORT_SYMBOL(class_disconnect_all);
EXPORT_SYMBOL(class_uuid_unparse);

EXPORT_SYMBOL(class_signal_connection_failure);

static int __init init_obdclass(void)
{
        struct obd_device *obd;
        int err;
        int i;

        printk(KERN_INFO "OBD class driver Build Version: " BUILD_VERSION
                      ", info@clusterfs.com\n");

        sema_init(&obd_conf_sem, 1);
        INIT_LIST_HEAD(&obd_types);

        if ((err = misc_register(&obd_psdev))) {
                CERROR("cannot register %d err %d\n", OBD_MINOR, err);
                return err;
        }

        /* This struct is already zerod for us (static global) */
        for (i = 0, obd = obd_dev; i < MAX_OBD_DEVICES; i++, obd++)
                obd->obd_minor = i;

        err = obd_init_caches();
        if (err)
                return err;

        obd_sysctl_init();

        err = lprocfs_reg_main();

        return 0;
}

static void __exit cleanup_obdclass(void)
{
        int i, err;
        ENTRY;

        misc_deregister(&obd_psdev);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_type && (obd->obd_flags & OBD_SET_UP) &&
                    OBT(obd) && OBP(obd, detach)) {
                        /* XXX should this call generic detach otherwise? */
                        OBP(obd, detach)(obd);
                }
        }

        obd_cleanup_caches();
        obd_sysctl_clean();

        err = lprocfs_dereg_main();

        CERROR("obd mem max: %d leaked: %d\n", obd_memmax,
               atomic_read(&obd_memory));
        EXIT;
}

/* Check that we're building against the appropriate version of the Lustre
 * kernel patch */
#include <linux/lustre_version.h>
#if (LUSTRE_KERNEL_VERSION != 5)
# error Cannot continue: Your Lustre kernel patch is out of date
#endif

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Class Driver Build Version: " BUILD_VERSION);
MODULE_LICENSE("GPL");

module_init(init_obdclass);
module_exit(cleanup_obdclass);
