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
#define EXPORT_SYMTAB
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
#else

# include <liblustre.h>

#endif

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/lprocfs_status.h>
#include <portals/lib-types.h> /* for PTL_MD_MAX_IOV */
#include <linux/lustre_build_version.h>

struct semaphore obd_conf_sem;   /* serialize configuration commands */
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;
atomic_t obd_memory;
int obd_memmax;

/* Root for /proc/lustre */
struct proc_dir_entry *proc_lustre_root = NULL;

/* The following are visible and mutable through /proc/sys/lustre/. */
unsigned long obd_fail_loc;
unsigned long obd_timeout = 100;
unsigned long obd_bulk_timeout = 1;
char obd_lustre_upcall[128] = "/usr/lib/lustre/lustre_upcall";
unsigned long obd_sync_filter; /* = 0, don't sync by default */

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

                CDEBUG (D_IOCTL, "Auto-disconnect %p\n", &c->ocuc_conn);

                down (&obd_conf_sem);
                obd_disconnect (&c->ocuc_conn, 0);
                up (&obd_conf_sem);

                OBD_FREE (c, sizeof (*c));
        }

        OBD_FREE (ocus, sizeof (*ocus));

        PORTAL_MODULE_UNUSE;
        RETURN(0);
}
#endif

static int
obd_class_add_user_conn (struct obd_class_user_state *ocus,
                         struct lustre_handle *conn)
{
        struct obd_class_user_conn *c;

        /* NB holding obd_conf_sem */

        OBD_ALLOC (c, sizeof (*c));
        if (ocus == NULL)
                return (-ENOMEM);

        c->ocuc_conn = *conn;
        list_add (&c->ocuc_chain, &ocus->ocus_conns);
        return (0);
}

static void
obd_class_remove_user_conn (struct obd_class_user_state *ocus,
                            struct lustre_handle *conn)
{
        struct list_head *e;
        struct obd_class_user_conn *c;

        /* NB holding obd_conf_sem or last reference */

        list_for_each (e, &ocus->ocus_conns) {
                c = list_entry (e, struct obd_class_user_conn, ocuc_chain);
                if (conn->cookie == c->ocuc_conn.cookie) {
                        list_del (&c->ocuc_chain);
                        OBD_FREE (c, sizeof (*c));
                        return;
                }
        }
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

static void dump_exports(struct obd_device *obd)
{
        struct list_head *tmp, *n;

        list_for_each_safe(tmp, n, &obd->obd_exports) {
                struct obd_export *exp = list_entry(tmp, struct obd_export,
                                                    exp_obd_chain);
                CDEBUG(D_ERROR, "%s: %p %s %d %d %p\n",
                       obd->obd_name, exp, exp->exp_client_uuid.uuid,
                       atomic_read(&exp->exp_refcount),
                       exp->exp_failed, exp->exp_outstanding_reply );
        }
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
            cmd != OBD_IOC_NEWDEV && cmd != OBD_IOC_ADD_UUID &&
            cmd != OBD_IOC_DEL_UUID && cmd != OBD_IOC_CLOSE_UUID) {
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
                if (data->ioc_dev >= MAX_OBD_DEVICES || data->ioc_dev < 0) {
                        CERROR("OBD ioctl: DEVICE insufficient devices\n");
                        GOTO(out, err = -EINVAL);
                }
                CDEBUG(D_IOCTL, "device %d\n", data->ioc_dev);

                ocus->ocus_current_obd = &obd_dev[data->ioc_dev];
                GOTO(out, err = 0);
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

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1 ) {
                        CERROR("No name passed,!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1 - 1] != 0) {
                        CERROR("Name not nul terminated!\n");
                        GOTO(out, err = -EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
                dev = class_name2dev(data->ioc_inlbuf1);
                data->ioc_dev = dev;
                if (dev == -1) {
                        CDEBUG(D_IOCTL, "No device for name %s!\n",
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



        case OBD_IOC_NEWDEV: {
                int dev = -1;
                int i;

                ocus->ocus_current_obd = NULL;
                for (i = 0 ; i < MAX_OBD_DEVICES ; i++) {
                        struct obd_device *obd = &obd_dev[i];
                        if (!obd->obd_type) {
                                ocus->ocus_current_obd = obd;
                                dev = i;
                                break;
                        }
                }


                data->ioc_dev = dev;
                if (dev == -1)
                        GOTO(out, err = -EINVAL);

                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err)
                        err = -EFAULT;
                GOTO(out, err);
        }

        case OBD_IOC_ATTACH: {
                struct obd_type *type;
                int minor, len;

                /* have we attached a type to this device */
                if (obd->obd_attached|| obd->obd_type) {
                        CERROR("OBD: Device %d already typed as %s.\n",
                               obd->obd_minor, MKSTR(obd->obd_type->typ_name));
                        GOTO(out, err = -EBUSY);
                }

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
                        CERROR("No type passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1 - 1] != 0) {
                        CERROR("Type not nul terminated!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (!data->ioc_inllen2 || !data->ioc_inlbuf2) {
                        CERROR("No name passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (data->ioc_inlbuf2[data->ioc_inllen2 - 1] != 0) {
                        CERROR("Name not nul terminated!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (!data->ioc_inllen3 || !data->ioc_inlbuf3) {
                        CERROR("No UUID passed!\n");
                        GOTO(out, err = -EINVAL);
                }
                if (data->ioc_inlbuf3[data->ioc_inllen3 - 1] != 0) {
                        CERROR("UUID not nul terminated!\n");
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
                init_waitqueue_head(&obd->obd_refcount_waitq);

                /* XXX belong ins setup not attach  */
                /* recovery data */
                spin_lock_init(&obd->obd_processing_task_lock);
                init_waitqueue_head(&obd->obd_next_transno_waitq);
                INIT_LIST_HEAD(&obd->obd_recovery_queue);
                INIT_LIST_HEAD(&obd->obd_delayed_reply_queue);

                init_waitqueue_head(&obd->obd_commit_waitq);

                len = strlen(data->ioc_inlbuf2) + 1;
                OBD_ALLOC(obd->obd_name, len);
                if (!obd->obd_name) {
                        class_put_type(obd->obd_type);
                        obd->obd_type = NULL;
                        GOTO(out, err = -ENOMEM);
                }
                memcpy(obd->obd_name, data->ioc_inlbuf2, len);

                len = strlen(data->ioc_inlbuf3);
                if (len >= sizeof(obd->obd_uuid)) {
                        CERROR("uuid must be < "LPSZ" bytes long\n",
                               sizeof(obd->obd_uuid));
                        if (obd->obd_name)
                                OBD_FREE(obd->obd_name,
                                         strlen(obd->obd_name) + 1);
                        class_put_type(obd->obd_type);
                        obd->obd_type = NULL;
                        GOTO(out, err = -EINVAL);
                }
                memcpy(obd->obd_uuid.uuid, data->ioc_inlbuf3, len);

                /* do the attach */
                if (OBP(obd, attach))
                        err = OBP(obd,attach)(obd, sizeof(*data), data);
                if (err) {
                        if(data->ioc_inlbuf2)
                                OBD_FREE(obd->obd_name,
                                         strlen(obd->obd_name) + 1);
                        class_put_type(obd->obd_type);
                        obd->obd_type = NULL;
                } else {
                        obd->obd_attached = 1;

                        type->typ_refcnt++;
                        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
                               obd->obd_minor, data->ioc_inlbuf1);
                }

                GOTO(out, err);
        }

        case OBD_IOC_DETACH: {
                ENTRY;
                if (obd->obd_set_up) {
                        CERROR("OBD device %d still set up\n", obd->obd_minor);
                        GOTO(out, err = -EBUSY);
                }
                if (!obd->obd_attached) {
                        CERROR("OBD device %d not attached\n", obd->obd_minor);
                        GOTO(out, err = -ENODEV);
                }
                if (OBP(obd, detach))
                        err = OBP(obd,detach)(obd);

                if (obd->obd_name) {
                        OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                        obd->obd_name = NULL;
                }

                obd->obd_attached = 0;
                obd->obd_type->typ_refcnt--;
                class_put_type(obd->obd_type);
                obd->obd_type = NULL;
                GOTO(out, err = 0);
        }

        case OBD_IOC_SETUP: {
                /* have we attached a type to this device? */
                if (!obd->obd_attached) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        GOTO(out, err = -ENODEV);
                }

                /* has this been done already? */
                if (obd->obd_set_up) {
                        CERROR("Device %d already setup (type %s)\n",
                               obd->obd_minor, obd->obd_type->typ_name);
                        GOTO(out, err = -EBUSY);
                }

                atomic_set(&obd->obd_refcount, 0);

                if ( OBT(obd) && OBP(obd, setup) )
                        err = obd_setup(obd, sizeof(*data), data);

                if (!err) {
                        obd->obd_type->typ_refcnt++;
                        obd->obd_set_up = 1;
                        atomic_inc(&obd->obd_refcount);
                }

                GOTO(out, err);
        }
        case OBD_IOC_CLEANUP: {
                int force = 0, failover = 0;
                char * flag;

                if (!obd->obd_set_up) {
                        CERROR("Device %d not setup\n", obd->obd_minor);
                        GOTO(out, err = -ENODEV);
                }

                if (data->ioc_inlbuf1) {
                        for (flag = data->ioc_inlbuf1; *flag != 0; flag++)
                                switch (*flag) {
                                case 'F':
                                        force = 1;
                                        break;
                                case 'A':
                                        failover = 1;
                                        break;
                                default:
                                        CERROR("unrecognised flag '%c'\n", 
                                               *flag);
                                }
                }
                
                if (atomic_read(&obd->obd_refcount) == 1 || force) {
                        /* this will stop new connections, and need to
                           do it before class_disconnect_exports() */
                        obd->obd_stopping = 1;
                }

                if (atomic_read(&obd->obd_refcount) > 1) {
                        struct l_wait_info lwi = LWI_TIMEOUT_INTR(60 * HZ, NULL,
                                                                  NULL, NULL);
                        int rc;
                        
                        if (!force) {
                                CERROR("OBD device %d (%p) has refcount %d\n",
                                       obd->obd_minor, obd, 
                                       atomic_read(&obd->obd_refcount));
                                dump_exports(obd);
                                GOTO(out, err = -EBUSY);
                        }
                        class_disconnect_exports(obd, failover);
                        CDEBUG(D_IOCTL, 
                               "%s: waiting for obd refs to go away: %d\n", 
                               obd->obd_name, atomic_read(&obd->obd_refcount));
                
                        rc = l_wait_event(obd->obd_refcount_waitq,
                                     atomic_read(&obd->obd_refcount) < 2, &lwi);
                        if (rc == 0) {
                                LASSERT(atomic_read(&obd->obd_refcount) == 1);
                        } else {
                                CERROR("wait cancelled cleaning anyway. "
                                       "refcount: %d\n",
                                       atomic_read(&obd->obd_refcount));
                                dump_exports(obd);
                        }
                        CDEBUG(D_IOCTL, "%s: awake, now finishing cleanup\n", 
                               obd->obd_name);
                }

                if (OBT(obd) && OBP(obd, cleanup))
                        err = obd_cleanup(obd, force, failover);

                if (!err) {
                        obd->obd_set_up = obd->obd_stopping = 0;
                        obd->obd_type->typ_refcnt--;
                        atomic_dec(&obd->obd_refcount);
                        /* XXX this should be an LASSERT */
                        if (atomic_read(&obd->obd_refcount) > 0) 
                                CERROR("%s still has refcount %d after "
                                       "cleanup.\n", obd->obd_name,
                                       atomic_read(&obd->obd_refcount));
                }

                GOTO(out, err);
        }

        case OBD_IOC_CONNECT: {
                struct obd_uuid cluuid = { "OBD_CLASS_UUID" };
                obd_data2conn(&conn, data);

                err = obd_connect(&conn, obd, &cluuid);

                CDEBUG(D_IOCTL, "assigned export "LPX64"\n", conn.cookie);
                obd_conn2data(data, &conn);
                if (err)
                        GOTO(out, err);

                err = obd_class_add_user_conn (ocus, &conn);
                if (err != 0) {
                        obd_disconnect (&conn, 0);
                        GOTO (out, err);
                }

                err = copy_to_user((void *)arg, data, sizeof(*data));
                if (err != 0) {
                        obd_class_remove_user_conn (ocus, &conn);
                        obd_disconnect (&conn, 0);
                        GOTO (out, err = -EFAULT);
                }
                GOTO(out, err);
        }

        case OBD_IOC_DISCONNECT: {
                obd_data2conn(&conn, data);
                obd_class_remove_user_conn (ocus, &conn);
                err = obd_disconnect(&conn, 0);
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
        case OBD_IOC_ADD_UUID: {
                CDEBUG(D_IOCTL, "adding mapping from uuid %s to nid "LPX64
                       ", nal %d\n", data->ioc_inlbuf1, data->ioc_nid,
                       data->ioc_nal);

                err = class_add_uuid(data->ioc_inlbuf1, data->ioc_nid,
                                     data->ioc_nal);
                GOTO(out, err);
        }
        case OBD_IOC_DEL_UUID: {
                CDEBUG(D_IOCTL, "removing mappings for uuid %s\n",
                       data->ioc_inlbuf1 == NULL ? "<all uuids>" :
                       data->ioc_inlbuf1);

                err = class_del_uuid(data->ioc_inlbuf1);
                GOTO(out, err);
        }
        default: { 
                // obd_data2conn(&conn, data);
                struct obd_class_user_conn *oconn = list_entry(ocus->ocus_conns.next, struct obd_class_user_conn, ocuc_chain);
                err = obd_iocontrol(cmd, &oconn->ocuc_conn, len, data, NULL);
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

EXPORT_SYMBOL(lctl_fake_uuid);

EXPORT_SYMBOL(class_register_type);
EXPORT_SYMBOL(class_unregister_type);
EXPORT_SYMBOL(class_get_type);
EXPORT_SYMBOL(class_put_type);
EXPORT_SYMBOL(class_name2dev);
EXPORT_SYMBOL(class_uuid2dev);
EXPORT_SYMBOL(class_uuid2obd);
EXPORT_SYMBOL(class_export_get);
EXPORT_SYMBOL(class_export_put);
EXPORT_SYMBOL(class_new_export);
EXPORT_SYMBOL(class_unlink_export);
EXPORT_SYMBOL(class_import_get);
EXPORT_SYMBOL(class_import_put);
EXPORT_SYMBOL(class_new_import);
EXPORT_SYMBOL(class_destroy_import);
EXPORT_SYMBOL(class_connect);
EXPORT_SYMBOL(class_conn2export);
EXPORT_SYMBOL(class_conn2obd);
EXPORT_SYMBOL(class_conn2cliimp);
EXPORT_SYMBOL(class_conn2ldlmimp);
EXPORT_SYMBOL(class_disconnect);
EXPORT_SYMBOL(class_disconnect_exports);
EXPORT_SYMBOL(lustre_uuid_to_peer);

/* uuid.c */
EXPORT_SYMBOL(class_uuid_unparse);
EXPORT_SYMBOL(client_tgtuuid2obd);

EXPORT_SYMBOL(class_handle_hash);
EXPORT_SYMBOL(class_handle_unhash);
EXPORT_SYMBOL(class_handle2object);

#ifdef __KERNEL__
static int __init init_obdclass(void)
#else
int init_obdclass(void)
#endif
{
        struct obd_device *obd;
        int err;
        int i;

        printk(KERN_INFO "OBD class driver Build Version: " BUILD_VERSION
                      ", info@clusterfs.com\n");

        class_init_uuidlist();
        class_handle_init();

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

#ifdef __KERNEL__
        obd_sysctl_init();
#endif

#ifdef LPROCFS
        proc_lustre_root = proc_mkdir("lustre", proc_root_fs);
        if (!proc_lustre_root)
                printk(KERN_ERR "error registering /proc/fs/lustre\n");
#else
        proc_lustre_root = NULL;
#endif
        return 0;
}

#ifdef __KERNEL__
static void __exit cleanup_obdclass(void)
#else
static void cleanup_obdclass(void)
#endif
{
        int i;
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
        if (proc_lustre_root) {
                lprocfs_remove(proc_lustre_root);
                proc_lustre_root = NULL;
        }

        class_handle_cleanup();
        class_exit_uuidlist();

        CERROR("obd mem max: %d leaked: %d\n", obd_memmax,
               atomic_read(&obd_memory));
        EXIT;
}

/* Check that we're building against the appropriate version of the Lustre
 * kernel patch */
#ifdef __KERNEL__
#include <linux/lustre_version.h>
#define LUSTRE_MIN_VERSION 18
#define LUSTRE_MAX_VERSION 19
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
