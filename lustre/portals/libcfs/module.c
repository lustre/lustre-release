/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2.1 of the GNU Lesser General
 *   Public License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_PORTALS

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/miscdevice.h>

#include <portals/lib-p30.h>
#include <portals/p30.h>
#include <linux/kp30.h>

#define PORTAL_MINOR 240

extern void (kping_client)(struct portal_ioctl_data *);

struct nal_cmd_handler {
        nal_cmd_handler_t nch_handler;
        void * nch_private;
};

static struct nal_cmd_handler nal_cmd[NAL_MAX_NR + 1];
struct semaphore nal_cmd_sem;

#ifdef PORTAL_DEBUG
void
kportal_assertion_failed (char *expr, char *file, char *func, int line)
{
        portals_debug_msg(0, D_EMERG, file, func, line, CDEBUG_STACK(),
                          "ASSERTION(%s) failed\n", expr);
        LBUG();
}
#endif

void
kportal_daemonize (char *str) 
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,63))
        daemonize(str);
#else
        daemonize();
        snprintf (current->comm, sizeof (current->comm), "%s", str);
#endif
}

void
kportal_blockallsigs ()
{
        unsigned long  flags;

        spin_lock_irqsave (&current->sigmask_lock, flags);
        siginitsetinv (&current->blocked, 0);
        recalc_sigpending (current);
        spin_unlock_irqrestore (&current->sigmask_lock, flags);
}

/* called when opening /dev/device */
static int kportal_psdev_open(struct inode * inode, struct file * file)
{
        ENTRY;

        if (!inode)
                RETURN(-EINVAL);
        PORTAL_MODULE_USE;
        RETURN(0);
}

/* called when closing /dev/device */
static int kportal_psdev_release(struct inode * inode, struct file * file)
{
        ENTRY;

        if (!inode)
                RETURN(-EINVAL);

        PORTAL_MODULE_UNUSE;
        RETURN(0);
}

static inline void freedata(void *data, int len)
{
        PORTAL_FREE(data, len);
}

static int
kportal_add_route(int gateway_nalid, ptl_nid_t gateway_nid, ptl_nid_t lo_nid,
                  ptl_nid_t hi_nid)
{
        int rc;
        kpr_control_interface_t *ci;

        ci = (kpr_control_interface_t *) PORTAL_SYMBOL_GET (kpr_control_interface);
        if (ci == NULL)
                return (-ENODEV);

        rc = ci->kprci_add_route (gateway_nalid, gateway_nid, lo_nid, hi_nid);

        PORTAL_SYMBOL_PUT(kpr_control_interface);
        return (rc);
}

static int
kportal_del_route(ptl_nid_t target)
{
        int rc;
        kpr_control_interface_t *ci;

        ci = (kpr_control_interface_t *)PORTAL_SYMBOL_GET(kpr_control_interface);
        if (ci == NULL)
                return (-ENODEV);

        rc = ci->kprci_del_route (target);

        PORTAL_SYMBOL_PUT(kpr_control_interface);
        return (rc);
}

static int
kportal_get_route(int index, __u32 *gateway_nalidp, ptl_nid_t *gateway_nidp,
                  ptl_nid_t *lo_nidp, ptl_nid_t *hi_nidp)
{
        int       gateway_nalid;
        ptl_nid_t gateway_nid;
        ptl_nid_t lo_nid;
        ptl_nid_t hi_nid;
        int       rc;
        kpr_control_interface_t *ci;

        ci = (kpr_control_interface_t *) PORTAL_SYMBOL_GET(kpr_control_interface);
        if (ci == NULL)
                return (-ENODEV);

        rc = ci->kprci_get_route(index, &gateway_nalid, &gateway_nid, &lo_nid,
                                 &hi_nid);

        if (rc == 0) {
                CDEBUG(D_IOCTL, "got route [%d] %d "LPX64":"LPX64" - "LPX64"\n",
                       index, gateway_nalid, gateway_nid, lo_nid, hi_nid);

                *gateway_nalidp = (__u32)gateway_nalid;
                *gateway_nidp   = (__u32)gateway_nid;
                *lo_nidp        = (__u32)lo_nid;
                *hi_nidp        = (__u32)hi_nid;
        }

        PORTAL_SYMBOL_PUT (kpr_control_interface);
        return (rc);
}

static int
kportal_nal_cmd(int nal, struct portal_ioctl_data *data)
{
        int rc = -EINVAL;

        ENTRY;

        down(&nal_cmd_sem);
        if (nal > 0 && nal <= NAL_MAX_NR && nal_cmd[nal].nch_handler) {
                CDEBUG(D_IOCTL, "calling handler nal: %d, cmd: %d\n", nal, data->ioc_nal_cmd);
                rc = nal_cmd[nal].nch_handler(data, nal_cmd[nal].nch_private);
        }
        up(&nal_cmd_sem);
        RETURN(rc);
}

ptl_handle_ni_t *
kportal_get_ni (int nal)
{

        switch (nal)
        {
        case QSWNAL:
                return (PORTAL_SYMBOL_GET(kqswnal_ni));
        case SOCKNAL:
                return (PORTAL_SYMBOL_GET(ksocknal_ni));
        case TOENAL:
                return  (PORTAL_SYMBOL_GET(ktoenal_ni));
        case GMNAL:
                return  (PORTAL_SYMBOL_GET(kgmnal_ni));
        case TCPNAL:
                /* userspace NAL */
                return (NULL);
        case SCIMACNAL:
                return  (PORTAL_SYMBOL_GET(kscimacnal_ni));
        default:
                /* A warning to a naive caller */
                CERROR ("unknown nal: %d\n", nal);
                return (NULL);
        }
}

void
kportal_put_ni (int nal)
{

        switch (nal)
        {
        case QSWNAL:
                PORTAL_SYMBOL_PUT(kqswnal_ni);
                break;
        case SOCKNAL:
                PORTAL_SYMBOL_PUT(ksocknal_ni);
                break;
        case TOENAL:
                PORTAL_SYMBOL_PUT(ktoenal_ni);
                break;
        case GMNAL:
                PORTAL_SYMBOL_PUT(kgmnal_ni);
                break;
        case TCPNAL:
                /* A lesson to a malicious caller */
                LBUG ();
        case SCIMACNAL:
                PORTAL_SYMBOL_PUT(kscimacnal_ni);
                break;
        default:
                CERROR ("unknown nal: %d\n", nal);
        }
}

int
kportal_nal_register(int nal, nal_cmd_handler_t handler, void * private)
{
        int rc = 0;

        CDEBUG(D_IOCTL, "Register NAL %d, handler: %p\n", nal, handler);

        if (nal > 0  && nal <= NAL_MAX_NR) {
                down(&nal_cmd_sem);
                if (nal_cmd[nal].nch_handler != NULL)
                        rc = -EBUSY;
                else {
                        nal_cmd[nal].nch_handler = handler;
                        nal_cmd[nal].nch_private = private;
                }
                up(&nal_cmd_sem);
        }
        return rc;
}

int
kportal_nal_unregister(int nal)
{
        int rc = 0;

        CDEBUG(D_IOCTL, "Unregister NAL %d\n", nal);

        if (nal > 0  && nal <= NAL_MAX_NR) {
                down(&nal_cmd_sem);
                nal_cmd[nal].nch_handler = NULL;
                nal_cmd[nal].nch_private = NULL;
                up(&nal_cmd_sem);
        }
        return rc;
}


static int kportal_ioctl(struct inode *inode, struct file *file,
                         unsigned int cmd, unsigned long arg)
{
        int err = 0;
        char buf[1024];
        struct portal_ioctl_data *data;

        ENTRY;

        if ( _IOC_TYPE(cmd) != IOC_PORTAL_TYPE ||
             _IOC_NR(cmd) < IOC_PORTAL_MIN_NR  ||
             _IOC_NR(cmd) > IOC_PORTAL_MAX_NR ) {
                CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
                                _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
                RETURN(-EINVAL);
        }

        if (portal_ioctl_getdata(buf, buf + 800, (void *)arg)) {
                CERROR("PORTALS ioctl: data error\n");
                RETURN(-EINVAL);
        }

        data = (struct portal_ioctl_data *)buf;

        switch (cmd) {
        case IOC_PORTAL_SET_DAEMON: 
                RETURN (portals_debug_set_daemon ( 
                                        (unsigned int) data->ioc_count,
                                        (unsigned int) data->ioc_inllen1,
                                        (char *) data->ioc_inlbuf1,
                                        (unsigned int) data->ioc_misc)); 
        case IOC_PORTAL_GET_DEBUG: {
                __s32 size = portals_debug_copy_to_user(data->ioc_pbuf1,
                                                        data->ioc_plen1);

                if (size < 0)
                        RETURN(size);

                data->ioc_size = size;
                err = copy_to_user((char *)arg, data, sizeof(*data));
                RETURN(err);
        }
        case IOC_PORTAL_CLEAR_DEBUG:
                portals_debug_clear_buffer();
                RETURN(0);
        case IOC_PORTAL_PANIC:
                if (!capable (CAP_SYS_BOOT))
                        RETURN (-EPERM);
                panic("debugctl-invoked panic");
                RETURN(0);
        case IOC_PORTAL_MARK_DEBUG:
                if (data->ioc_inlbuf1 == NULL ||
                    data->ioc_inlbuf1[data->ioc_inllen1 - 1] != '\0')
                        RETURN(-EINVAL);
                portals_debug_mark_buffer(data->ioc_inlbuf1);
                RETURN(0);
        case IOC_PORTAL_PING: {
                void (*ping)(struct portal_ioctl_data *);

                CDEBUG(D_IOCTL, "doing %d pings to nid "LPU64"\n",
                       data->ioc_count, data->ioc_nid);
                ping = PORTAL_SYMBOL_GET(kping_client);
                if (!ping)
                        CERROR("PORTAL_SYMBOL_GET failed\n");
                else {
                        ping(data);
                        PORTAL_SYMBOL_PUT(kping_client);
                }
                RETURN(0);
        }

        case IOC_PORTAL_ADD_ROUTE:
                CDEBUG(D_IOCTL, "Adding route: [%d] "LPU64" : "LPU64" - "LPU64"\n",
                       data->ioc_nal, data->ioc_nid, data->ioc_nid2,
                       data->ioc_nid3);
                err = kportal_add_route(data->ioc_nal, data->ioc_nid,
                                        MIN (data->ioc_nid2, data->ioc_nid3),
                                        MAX (data->ioc_nid2, data->ioc_nid3));
                break;

        case IOC_PORTAL_DEL_ROUTE:
                CDEBUG (D_IOCTL, "Removing route to "LPU64"\n", data->ioc_nid);
                err = kportal_del_route (data->ioc_nid);
                break;

        case IOC_PORTAL_GET_ROUTE:
                CDEBUG (D_IOCTL, "Getting route [%d]\n", data->ioc_count);
                err = kportal_get_route(data->ioc_count, &data->ioc_nal,
                                        &data->ioc_nid, &data->ioc_nid2,
                                        &data->ioc_nid3);
                if (err == 0)
                        if (copy_to_user((char *)arg, data, sizeof (*data)))
                                err = -EFAULT;
                break;

        case IOC_PORTAL_GET_NID: {
                const ptl_handle_ni_t *nip;
                ptl_process_id_t       pid;

                CDEBUG (D_IOCTL, "Getting nid [%d]\n", data->ioc_nal);

                nip = kportal_get_ni (data->ioc_nal);
                if (nip == NULL)
                        RETURN (-EINVAL);

                err = PtlGetId (*nip, &pid);
                LASSERT (err == PTL_OK);
                kportal_put_ni (data->ioc_nal);

                data->ioc_nid = pid.nid;
                if (copy_to_user ((char *)arg, data, sizeof (*data)))
                        err = -EFAULT;
                break;
        }

        case IOC_PORTAL_NAL_CMD:
                CDEBUG (D_IOCTL, "nal command nal %d cmd %d\n", data->ioc_nal,
                        data->ioc_nal_cmd);
                err = kportal_nal_cmd(data->ioc_nal, data);
                if (err == 0)
                        if (copy_to_user((char *)arg, data, sizeof (*data)))
                                err = -EFAULT;
                break;

        case IOC_PORTAL_FAIL_NID: {
                const ptl_handle_ni_t *nip;

                CDEBUG (D_IOCTL, "fail nid: [%d] "LPU64" count %d\n",
                        data->ioc_nal, data->ioc_nid, data->ioc_count);

                nip = kportal_get_ni (data->ioc_nal);
                if (nip == NULL)
                        return (-EINVAL);

                err = PtlFailNid (*nip, data->ioc_nid, data->ioc_count);
                break;
        }

        default:
                err = -EINVAL;
                break;
        }

        RETURN(err);
}


static struct file_operations portalsdev_fops = {
        ioctl:   kportal_ioctl,
        open:    kportal_psdev_open,
        release: kportal_psdev_release
};


static struct miscdevice portal_dev = {
        PORTAL_MINOR,
        "portals",
        &portalsdev_fops
};

extern int insert_proc(void);
extern void remove_proc(void);
MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

static int init_kportals_module(void)
{
        int rc;

        rc = portals_debug_init(5 * 1024 * 1024);
        if (rc < 0) {
                printk(KERN_ERR "portals_debug_init: %d\n", rc);
                return (rc);
        }

        sema_init(&nal_cmd_sem, 1);

        rc = misc_register(&portal_dev);
        if (rc) {
                CERROR("misc_register: error %d\n", rc);
                goto cleanup_debug;
        }

        rc = PtlInit();
        if (rc) {
                CERROR("PtlInit: error %d\n", rc);
                goto cleanup_deregister;
        }

        rc = insert_proc();
        if (rc) {
                CERROR("insert_proc: error %d\n", rc);
                goto cleanup_fini;
        }

        CDEBUG (D_OTHER, "portals setup OK\n");
        return (0);

 cleanup_fini:
        PtlFini();
 cleanup_deregister:
        misc_deregister(&portal_dev);
 cleanup_debug:
        portals_debug_cleanup();
        return rc;
}

static void exit_kportals_module(void)
{
        int rc;

        remove_proc();
        PtlFini();

        CDEBUG(D_MALLOC, "before Portals cleanup: kmem %d\n",
               atomic_read(&portal_kmemory));


        rc = misc_deregister(&portal_dev);
        if (rc)
                CERROR("misc_deregister error %d\n", rc);

        if (atomic_read(&portal_kmemory) != 0)
                CERROR("Portals memory leaked: %d bytes\n",
                       atomic_read(&portal_kmemory));

        rc = portals_debug_cleanup();
        if (rc)
                printk(KERN_ERR "portals_debug_cleanup: %d\n", rc);
}

EXPORT_SYMBOL(lib_dispatch);
EXPORT_SYMBOL(PtlMEAttach);
EXPORT_SYMBOL(PtlMEInsert);
EXPORT_SYMBOL(PtlMEUnlink);
EXPORT_SYMBOL(PtlEQAlloc);
EXPORT_SYMBOL(PtlMDAttach);
EXPORT_SYMBOL(PtlMDUnlink);
EXPORT_SYMBOL(PtlNIInit);
EXPORT_SYMBOL(PtlNIFini);
EXPORT_SYMBOL(PtlNIDebug);
EXPORT_SYMBOL(PtlInit);
EXPORT_SYMBOL(PtlFini);
EXPORT_SYMBOL(PtlPut);
EXPORT_SYMBOL(PtlGet);
EXPORT_SYMBOL(ptl_err_str);
EXPORT_SYMBOL(portal_subsystem_debug);
EXPORT_SYMBOL(portal_debug);
EXPORT_SYMBOL(portal_stack);
EXPORT_SYMBOL(portal_printk);
EXPORT_SYMBOL(PtlEQWait);
EXPORT_SYMBOL(PtlEQFree);
EXPORT_SYMBOL(PtlEQGet);
EXPORT_SYMBOL(PtlGetId);
EXPORT_SYMBOL(PtlMDBind);
EXPORT_SYMBOL(lib_iov_nob);
EXPORT_SYMBOL(lib_copy_iov2buf);
EXPORT_SYMBOL(lib_copy_buf2iov);
EXPORT_SYMBOL(lib_kiov_nob);
EXPORT_SYMBOL(lib_copy_kiov2buf);
EXPORT_SYMBOL(lib_copy_buf2kiov);
EXPORT_SYMBOL(lib_finalize);
EXPORT_SYMBOL(lib_parse);
EXPORT_SYMBOL(lib_init);
EXPORT_SYMBOL(lib_fini);
EXPORT_SYMBOL(portal_kmemory);
EXPORT_SYMBOL(kportal_daemonize);
EXPORT_SYMBOL(kportal_blockallsigs);
EXPORT_SYMBOL(kportal_nal_register);
EXPORT_SYMBOL(kportal_nal_unregister);
EXPORT_SYMBOL(kportal_assertion_failed);
EXPORT_SYMBOL(dispatch_name);
EXPORT_SYMBOL(kportal_get_ni);
EXPORT_SYMBOL(kportal_put_ni);

module_init(init_kportals_module);
module_exit (exit_kportals_module);
