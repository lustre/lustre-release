/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Object Devices Class Driver
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * These are the only exported functions, they provide some generic
 * infrastructure for managing object devices
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#ifdef __KERNEL__
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
#include <linux/smp_lock.h>
#include <linux/seq_file.h>
#else
# include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_build_version.h>
#include <portals/list.h>
#include "llog_internal.h"

struct semaphore obd_conf_sem;   /* serialize configuration commands */
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;
atomic_t obd_memory;
int obd_memmax;

int proc_version;

/* The following are visible and mutable through /proc/sys/lustre/. */
unsigned int obd_fail_loc;
unsigned int obd_timeout = 100;
char obd_lustre_upcall[128] = "/usr/lib/lustre/lustre_upcall";
unsigned int obd_sync_filter; /* = 0, don't sync by default */

#ifdef __KERNEL__
/*  opening /dev/obd */
static int obd_class_open(struct inode * inode, struct file * file)
{
        struct obd_class_user_state *ocus;
        ENTRY;

        OBD_ALLOC(ocus, sizeof(*ocus));
        if (ocus == NULL)
                return (-ENOMEM);

        INIT_LIST_HEAD(&ocus->ocus_conns);
        file->private_data = ocus;

        PORTAL_MODULE_USE;
        RETURN(0);
}

/*  closing /dev/obd */
static int obd_class_release(struct inode * inode, struct file * file)
{
        struct obd_class_user_state *ocus = file->private_data;
        struct obd_class_user_conn  *c;
        ENTRY;

        while (!list_empty (&ocus->ocus_conns)) {
                c = list_entry (ocus->ocus_conns.next,
                                struct obd_class_user_conn, ocuc_chain);
                list_del (&c->ocuc_chain);

                CDEBUG (D_IOCTL, "Auto-disconnect exp %p\n", c->ocuc_exp);

                down (&obd_conf_sem);
                obd_disconnect (c->ocuc_exp, 0);
                up (&obd_conf_sem);

                OBD_FREE (c, sizeof (*c));
        }

        OBD_FREE (ocus, sizeof (*ocus));

        PORTAL_MODULE_UNUSE;
        RETURN(0);
}
#endif

static int obd_class_add_user_exp(struct obd_class_user_state *ocus,
                                  struct obd_export *exp)
{
        struct obd_class_user_conn *c;
        ENTRY;
        /* NB holding obd_conf_sem */

        OBD_ALLOC (c, sizeof (*c));
        if (c == NULL)
                RETURN(-ENOMEM);

        c->ocuc_exp = class_export_get(exp);
        list_add (&c->ocuc_chain, &ocus->ocus_conns);
        RETURN(0);
}

static void obd_class_remove_user_exp(struct obd_class_user_state *ocus,
                                      struct obd_export *exp)
{
        struct obd_class_user_conn *c;
        ENTRY;

        /* NB holding obd_conf_sem or last reference */

        list_for_each_entry(c, &ocus->ocus_conns, ocuc_chain) {
                if (exp == c->ocuc_exp) {
                        list_del (&c->ocuc_chain);
                        OBD_FREE (c, sizeof (*c));
                        class_export_put(exp);
                        EXIT;
                        return;
                }
        }
        EXIT;
}

static inline void obd_data2conn(struct lustre_handle *conn,
                                 struct obd_ioctl_data *data)
{
        memset(conn, 0, sizeof *conn);
        conn->cookie = data->ioc_cookie;
}

static inline void obd_conn2data(struct obd_ioctl_data *data,
                                 struct lustre_handle *conn)
{
        data->ioc_cookie = conn->cookie;
}

int class_resolve_dev_name(uint32_t len, char *name)
{
        int rc;
        int dev;

        if (!len || !name) {
                CERROR("No name passed,!\n");
                GOTO(out, rc = -EINVAL);
        }
        if (name[len - 1] != 0) {
                CERROR("Name not nul terminated!\n");
                GOTO(out, rc = -EINVAL);
        }

        CDEBUG(D_IOCTL, "device name %s\n", name);
        dev = class_name2dev(name);
        if (dev == -1) {
                CDEBUG(D_IOCTL, "No device for name %s!\n", name);
                GOTO(out, rc = -EINVAL);
        }

        CDEBUG(D_IOCTL, "device name %s, dev %d\n", name, dev);
        rc = dev;

out:
        RETURN(rc);
}

int class_handle_ioctl(struct obd_class_user_state *ocus, unsigned int cmd,
                       unsigned long arg)
{
        char *buf = NULL;
        struct obd_ioctl_data *data;
        struct portals_debug_ioctl_data *debug_data;
        struct obd_device *obd = ocus->ocus_current_obd;
        struct lustre_handle conn;
        int err = 0, len = 0, serialised = 0;
        ENTRY;

        if (current->fsuid != 0)
                RETURN(err = -EACCES);

        if ((cmd & 0xffffff00) == ((int)'T') << 8) /* ignore all tty ioctls */
                RETURN(err = -ENOTTY);

        /* only for debugging */
        if (cmd == PTL_IOC_DEBUG_MASK) {
                debug_data = (struct portals_debug_ioctl_data*)arg;
                portal_subsystem_debug = debug_data->subs;
                portal_debug = debug_data->debug;
                return 0;
        }

        switch (cmd) {
        case OBD_IOC_BRW_WRITE:
        case OBD_IOC_BRW_READ:
        case OBD_IOC_GETATTR:
        case ECHO_IOC_ENQUEUE:
        case ECHO_IOC_CANCEL:
        case OBD_IOC_CLIENT_RECOVER:
        case OBD_IOC_CATLOGLIST:
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT:
        case OBD_IOC_LLOG_CANCEL:
        case OBD_IOC_LLOG_CHECK:
        case OBD_IOC_LLOG_REMOVE:
                break;
        default:
                down(&obd_conf_sem);
                serialised = 1;
                break;
        }

        CDEBUG(D_IOCTL, "cmd = %x, obd = %p\n", cmd, obd);
        if (!obd && cmd != OBD_IOC_DEVICE &&
            cmd != OBD_IOC_LIST && cmd != OBD_GET_VERSION &&
            cmd != OBD_IOC_NAME2DEV && cmd != OBD_IOC_UUID2DEV &&
            cmd != OBD_IOC_PROCESS_CFG) {
                CERROR("OBD ioctl: No device\n");
                GOTO(out, err = -EINVAL);
        }
        if (obd_ioctl_getdata(&buf, &len, (void *)arg)) {
                CERROR("OBD ioctl: data error\n");
                GOTO(out, err = -EINVAL);
        }
        data = (struct obd_ioctl_data *)buf;

        switch (cmd) {
        case OBD_IOC_DEVICE: {
                CDEBUG(D_IOCTL, "\n");
                if (data->ioc_dev >= MAX_OBD_DEVICES) {
                        CERROR("OBD ioctl: DEVICE invalid device %d\n",
                               data->ioc_dev);
                        ocus->ocus_current_obd = &obd_dev[data->ioc_dev];
                        GOTO(out, err = -EINVAL);
                }
                CDEBUG(D_IOCTL, "device %d\n", data->ioc_dev);
                ocus->ocus_current_obd = &obd_dev[data->ioc_dev];
                GOTO(out, err = 0);
        }

        case OBD_IOC_PROCESS_CFG: {
                char *buf;
                struct lustre_cfg *lcfg;

                /* FIXME hack to liblustre dump, remove when switch
                   to zeroconf */
#ifndef __KERNEL__
                data->ioc_pbuf1 = data->ioc_inlbuf1;
                data->ioc_plen1 = data->ioc_inllen1;
#endif
                if (!data->ioc_plen1 || !data->ioc_pbuf1) {
                        CERROR("No config buffer passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                err = lustre_cfg_getdata(&buf, data->ioc_plen1,
                                         data->ioc_pbuf1, 0);
                if (err)
                        GOTO(out, err);
                lcfg = (struct lustre_cfg* ) buf;

                err = class_process_config(lcfg);
                lustre_cfg_freedata(buf, data->ioc_plen1);
                GOTO(out, err);
        }

        case OBD_IOC_LIST: {
                int i;
                char *buf2 = data->ioc_bulk;
                int remains = data->ioc_inllen1;

                if (!data->ioc_inlbuf1) {
                        CERROR("No buffer passed!\n");
                        GOTO(out, err = -EINVAL);
                }


                for (i = 0 ; i < MAX_OBD_DEVICES ; i++) {
                        int l;
                        char *status;
                        struct obd_device *obd = &obd_dev[i];

                        if (!obd->obd_type)
                                continue;
                        if (obd->obd_stopping)
                                status = "ST";
                        else if (obd->obd_set_up)
                                status = "UP";
                        else if (obd->obd_attached)
                                status = "AT";
                        else
                                status = "-";
                        l = snprintf(buf2, remains, "%2d %s %s %s %s %d\n",
                                     i, status, obd->obd_type->typ_name,
                                     obd->obd_name, obd->obd_uuid.uuid,
                                     obd->obd_type->typ_refcnt);
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

                dev = class_resolve_dev_name(data->ioc_inllen1,
                                             data->ioc_inlbuf1);
                data->ioc_dev = dev;
                if (dev < 0)
                        GOTO(out, err = -EINVAL);

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
                struct obd_uuid uuid;

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
                        CERROR("No UUID passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1 - 1] != 0) {
                        CERROR("UUID not NUL terminated!\n");
                        GOTO(out, err = -EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
                obd_str2uuid(&uuid, data->ioc_inlbuf1);
                dev = class_uuid2dev(&uuid);
                data->ioc_dev = dev;
                if (dev == -1) {
                        CDEBUG(D_IOCTL, "No device for UUID %s!\n",
                               data->ioc_inlbuf1);
                        GOTO(out, err = -EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s, dev %d\n", data->ioc_inlbuf1,
                       dev);
                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }



        case OBD_IOC_CONNECT: {
                struct obd_export *exp;
                obd_data2conn(&conn, data);

                err = obd_connect(&conn, obd, &obd->obd_uuid);

                CDEBUG(D_IOCTL, "assigned export "LPX64"\n", conn.cookie);
                obd_conn2data(data, &conn);
                if (err)
                        GOTO(out, err);

                exp = class_conn2export(&conn);
                if (exp == NULL)
                        GOTO(out, err = -EINVAL);

                err = obd_class_add_user_exp(ocus, exp);
                if (err != 0) {
                        obd_disconnect(exp, 0);
                        GOTO (out, err);
                }

                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err != 0) {
                        obd_class_remove_user_exp(ocus, exp);
                        obd_disconnect(exp, 0);
                        GOTO (out, err = -EFAULT);
                }
                class_export_put(exp);
                GOTO(out, err);
        }

        case OBD_IOC_DISCONNECT: {
                struct obd_export *exp;
                obd_data2conn(&conn, data);
                exp = class_conn2export(&conn);
                if (exp == NULL)
                        GOTO(out, err = -EINVAL);

                obd_class_remove_user_exp(ocus, exp);
                err = obd_disconnect(exp, 0);
                GOTO(out, err);
        }

        case OBD_IOC_NO_TRANSNO: {
                if (!obd->obd_attached) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        GOTO(out, err = -ENODEV);
                }
                CDEBUG(D_IOCTL,
                       "disabling committed-transno notifications on %d\n",
                       obd->obd_minor);
                obd->obd_no_transno = 1;
                GOTO(out, err = 0);
        }

        case OBD_IOC_CLOSE_UUID: {
                struct lustre_peer peer;
                CDEBUG(D_IOCTL, "closing all connections to uuid %s\n",
                       data->ioc_inlbuf1);
                lustre_uuid_to_peer(data->ioc_inlbuf1, &peer);
                GOTO(out, err = 0);
        }

        default: {
                // obd_data2conn(&conn, data);
                struct obd_class_user_conn *oconn;

                if (list_empty(&ocus->ocus_conns)) 
                        GOTO(out, err = -ENOTCONN);
                        
                oconn = list_entry(ocus->ocus_conns.next, struct obd_class_user_conn, ocuc_chain);
                err = obd_iocontrol(cmd, oconn->ocuc_exp, len, data, NULL);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((void *)arg, data, len);
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }
        }

 out:
        if (buf)
                obd_ioctl_freedata(buf, len);
        if (serialised)
                up(&obd_conf_sem);
        RETURN(err);
} /* class_handle_ioctl */



#define OBD_MINOR 241
#ifdef __KERNEL__
/* to control /dev/obd */
static int obd_class_ioctl(struct inode *inode, struct file *filp,
                           unsigned int cmd, unsigned long arg)
{
        return class_handle_ioctl(filp->private_data, cmd, arg);
}

/* declare character device */
static struct file_operations obd_psdev_fops = {
        ioctl:   obd_class_ioctl,       /* ioctl */
        open:    obd_class_open,        /* open */
        release: obd_class_release,     /* release */
};

/* modules setup */
static struct miscdevice obd_psdev = {
        OBD_MINOR,
        "obd_psdev",
        &obd_psdev_fops
};
#else
void *obd_psdev = NULL;
#endif

EXPORT_SYMBOL(obd_dev);
EXPORT_SYMBOL(obdo_cachep);
EXPORT_SYMBOL(obd_memory);
EXPORT_SYMBOL(obd_memmax);
EXPORT_SYMBOL(obd_fail_loc);
EXPORT_SYMBOL(obd_timeout);
EXPORT_SYMBOL(obd_lustre_upcall);
EXPORT_SYMBOL(obd_sync_filter);
EXPORT_SYMBOL(ptlrpc_put_connection_superhack);
EXPORT_SYMBOL(ptlrpc_abort_inflight_superhack);
EXPORT_SYMBOL(proc_lustre_root);

EXPORT_SYMBOL(class_register_type);
EXPORT_SYMBOL(class_unregister_type);
EXPORT_SYMBOL(class_get_type);
EXPORT_SYMBOL(class_put_type);
EXPORT_SYMBOL(class_name2dev);
EXPORT_SYMBOL(class_name2obd);
EXPORT_SYMBOL(class_uuid2dev);
EXPORT_SYMBOL(class_uuid2obd);
EXPORT_SYMBOL(class_find_client_obd);
EXPORT_SYMBOL(__class_export_put);
EXPORT_SYMBOL(class_new_export);
EXPORT_SYMBOL(class_unlink_export);
EXPORT_SYMBOL(class_import_get);
EXPORT_SYMBOL(class_import_put);
EXPORT_SYMBOL(class_new_import);
EXPORT_SYMBOL(class_destroy_import);
EXPORT_SYMBOL(class_connect);
EXPORT_SYMBOL(class_conn2export);
EXPORT_SYMBOL(class_exp2obd);
EXPORT_SYMBOL(class_conn2obd);
EXPORT_SYMBOL(class_exp2cliimp);
EXPORT_SYMBOL(class_conn2cliimp);
EXPORT_SYMBOL(class_disconnect);
EXPORT_SYMBOL(class_disconnect_exports);

EXPORT_SYMBOL(osic_init);
EXPORT_SYMBOL(osic_add_one);
EXPORT_SYMBOL(osic_wait);
EXPORT_SYMBOL(osic_complete_one);

/* uuid.c */
EXPORT_SYMBOL(class_uuid_unparse);
EXPORT_SYMBOL(lustre_uuid_to_peer);

EXPORT_SYMBOL(class_handle_hash);
EXPORT_SYMBOL(class_handle_unhash);
EXPORT_SYMBOL(class_handle2object);

/* config.c */
EXPORT_SYMBOL(class_get_profile);
EXPORT_SYMBOL(class_process_config);
EXPORT_SYMBOL(class_config_parse_llog);
EXPORT_SYMBOL(class_config_dump_llog);
EXPORT_SYMBOL(class_attach);
EXPORT_SYMBOL(class_setup);
EXPORT_SYMBOL(class_cleanup);
EXPORT_SYMBOL(class_detach);

#ifdef LPROCFS
int obd_proc_read_version(char *page, char **start, off_t off, int count,
                          int *eof, void *data)
{
        *eof = 1;
        return snprintf(page, count, "%s\n", BUILD_VERSION);
}

int obd_proc_read_pinger(char *page, char **start, off_t off, int count,
                         int *eof, void *data)
{
        *eof = 1;
        return snprintf(page, count, "%s\n",
#ifdef ENABLE_PINGER
                        "on"
#else
                        "off"
#endif
                       );
}

/* Root for /proc/fs/lustre */
struct proc_dir_entry *proc_lustre_root = NULL;
struct lprocfs_vars lprocfs_base[] = {
        { "version", obd_proc_read_version, NULL, NULL },
        { "pinger", obd_proc_read_pinger, NULL, NULL },
        { 0 }
};

static void *obd_device_list_seq_start(struct seq_file *p, loff_t*pos)
{
        if (*pos >= MAX_OBD_DEVICES)
                return NULL;
        return &obd_dev[*pos];
}

static void obd_device_list_seq_stop(struct seq_file *p, void *v)
{
}

static void *obd_device_list_seq_next(struct seq_file *p, void *v, loff_t *pos)
{
        ++*pos;
        if (*pos >= MAX_OBD_DEVICES)
                return NULL;
        return &obd_dev[*pos];
}

static int obd_device_list_seq_show(struct seq_file *p, void *v)
{
        struct obd_device *obd = (struct obd_device *)v;
        int index = obd - &obd_dev[0];
        char *status;

        if (!obd->obd_type)
                return 0;
        if (obd->obd_stopping)
                status = "ST";
        else if (obd->obd_set_up)
                status = "UP";
        else if (obd->obd_attached)
                status = "AT";
        else
                status = "--";

        return seq_printf(p, "%3d %s %s %s %s %d\n",
                          (int)index, status, obd->obd_type->typ_name,
                          obd->obd_name, obd->obd_uuid.uuid,
                          atomic_read(&obd->obd_refcount));
}

struct seq_operations obd_device_list_sops = {
        .start = obd_device_list_seq_start,
        .stop = obd_device_list_seq_stop,
        .next = obd_device_list_seq_next,
        .show = obd_device_list_seq_show,
};

static int obd_device_list_open(struct inode *inode, struct file *file)
{
        struct proc_dir_entry *dp = inode->u.generic_ip;
        struct seq_file *seq;
        int rc = seq_open(file, &obd_device_list_sops);

        if (rc)
                return rc;

        seq = file->private_data;
        seq->private = dp->data;

        return 0;
}

struct file_operations obd_device_list_fops = {
        .open = obd_device_list_open,
        .read = seq_read,
        .llseek = seq_lseek,
        .release = seq_release,
};
#endif

#ifdef __KERNEL__
static int __init init_obdclass(void)
#else
int init_obdclass(void)
#endif
{
        struct obd_device *obd;
#ifdef LPROCFS
        struct proc_dir_entry *entry;
#endif
        int err;
        int i;

        printk(KERN_INFO "Lustre: OBD class driver Build Version: "
               BUILD_VERSION", info@clusterfs.com\n");

        class_init_uuidlist();
        err = class_handle_init();
        if (err)
                return err;

        sema_init(&obd_conf_sem, 1);
        INIT_LIST_HEAD(&obd_types);

        err = misc_register(&obd_psdev);
        if (err) {
                CERROR("cannot register %d err %d\n", OBD_MINOR, err);
                return err;
        }

        /* This struct is already zerod for us (static global) */
        for (i = 0, obd = obd_dev; i < MAX_OBD_DEVICES; i++, obd++)
                obd->obd_minor = i;

        err = obd_init_caches();
        if (err)
                return err;

#ifdef __KERNEL__
        obd_sysctl_init();
#endif

#ifdef LPROCFS
        proc_lustre_root = proc_mkdir("lustre", proc_root_fs);
        if (!proc_lustre_root) {
                printk(KERN_ERR
                       "LustreError: error registering /proc/fs/lustre\n");
                RETURN(-ENOMEM);
        }
        proc_version = lprocfs_add_vars(proc_lustre_root, lprocfs_base, NULL);
        entry = create_proc_entry("devices", 0444, proc_lustre_root);
        if (entry == NULL) {
                printk(KERN_ERR "LustreError: error registering "
                       "/proc/fs/lustre/devices\n");
                lprocfs_remove(proc_lustre_root);
                RETURN(-ENOMEM);
        }
        entry->proc_fops = &obd_device_list_fops;
#endif
        return 0;
}

#ifdef __KERNEL__
static void /*__exit*/ cleanup_obdclass(void)
#else
static void cleanup_obdclass(void)
#endif
{
        int i, leaked;
        ENTRY;

        misc_deregister(&obd_psdev);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_type && obd->obd_set_up &&
                    OBT(obd) && OBP(obd, detach)) {
                        /* XXX should this call generic detach otherwise? */
                        OBP(obd, detach)(obd);
                }
        }

        obd_cleanup_caches();
#ifdef __KERNEL__
        obd_sysctl_clean();
#endif
#ifdef LPROCFS
        if (proc_lustre_root) {
                lprocfs_remove(proc_lustre_root);
                proc_lustre_root = NULL;
        }
#endif

        class_handle_cleanup();
        class_exit_uuidlist();

        leaked = atomic_read(&obd_memory);
        CDEBUG(leaked ? D_ERROR : D_INFO,
               "obd mem max: %d leaked: %d\n", obd_memmax, leaked);

        EXIT;
}

/* Check that we're building against the appropriate version of the Lustre
 * kernel patch */
#ifdef __KERNEL__
#include <linux/lustre_version.h>
#define LUSTRE_MIN_VERSION 28
#define LUSTRE_MAX_VERSION 32
#if (LUSTRE_KERNEL_VERSION < LUSTRE_MIN_VERSION)
# error Cannot continue: Your Lustre kernel patch is older than the sources
#elif (LUSTRE_KERNEL_VERSION > LUSTRE_MAX_VERSION)
# error Cannot continue: Your Lustre sources are older than the kernel patch
#endif
 #else
# warning "Lib Lustre - no versioning information"
#endif

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Class Driver Build Version: " BUILD_VERSION);
MODULE_LICENSE("GPL");

module_init(init_obdclass);
module_exit(cleanup_obdclass);
#endif
