/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *              An implementation of a loadable kernel mode driver providing
 *              multiple kernel/user space bidirectional communications links.
 *
 *              Author:         Alan Cox <alan@cymru.net>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              version 2 as published by the Free Software Foundation.
 * 
 *              Adapted to become the Linux 2.0 Coda pseudo device
 *              Peter  Braam  <braam@maths.ox.ac.uk> 
 *              Michael Callahan <mjc@emmy.smith.edu>           
 *
 *              Changes for Linux 2.1
 *              Copyright (c) 1997 Carnegie-Mellon University
 *
 *              Redone again for Intermezzo
 *              Copyright (c) 1998 Peter J. Braam
 *
 *              Hacked up again for simulated OBD
 *              Copyright (c) 1999 Stelias Computing, Inc.
 *                (authors {pschwan,braam}@stelias.com)
 *              Copyright (C) 1999 Seagate Technology, Inc.
 *              Copyright (C) 2001 Cluster File Systems, Inc.
 *
 * 
 */

#define EXPORT_SYMTAB
#include <linux/config.h> /* for CONFIG_PROC_FS */
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/major.h>
#include <linux/kmod.h>   /* for request_module() */
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
#include <asm/io.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/obd_class.h>

static int obd_init_magic;
unsigned long obd_memory = 0;
unsigned long obd_fail_loc = 0;
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;

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

        if (file->private_data)
                file->private_data = NULL;

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

static int obd_class_name2dev(char *name)
{
        int res = -1;
        int i;

        for (i=0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if (obd->obd_name && strcmp(name, obd->obd_name) == 0) {
                        res = i;
                        return res;
                }
        }

        return res;
}

/* 
 * support functions: we could use inter-module communication, but this 
 * is more portable to other OS's
 */
static struct obd_type *obd_search_type(char *nm)
{
        struct list_head *tmp;
        struct obd_type *type;
        CDEBUG(D_INFO, "SEARCH %s\n", nm);
        
        tmp = &obd_types;
        while ( (tmp = tmp->next) != &obd_types ) {
                type = list_entry(tmp, struct obd_type, typ_chain);
                CDEBUG(D_INFO, "TYP %s\n", type->typ_name);
                if (strlen(type->typ_name) == strlen(nm) &&
                    strcmp(type->typ_name, nm) == 0 ) {
                        return type;
                }
        }
        return NULL;
}

static struct obd_type *obd_nm_to_type(char *nm) 
{
        struct obd_type *type = obd_search_type(nm);

#ifdef CONFIG_KMOD
        if ( !type ) {
                if ( !request_module(nm) ) {
                        CDEBUG(D_INFO, "Loaded module '%s'\n", nm);
                        type = obd_search_type(nm);
                } else {
                        CDEBUG(D_INFO, "Can't load module '%s'\n", nm);
                }
        }
#endif
        return type;
}

/* to control /dev/obd */
static int obd_class_ioctl (struct inode * inode, struct file * filp, 
                            unsigned int cmd, unsigned long arg)
{
        /* NOTE this must be larger than any of the ioctl data structs */
        char buf[1024];
        struct obd_ioctl_data *data;
        struct obd_device *obd = filp->private_data;
        struct obd_conn conn;
        int rw = OBD_BRW_READ;
        int err = 0;
        ENTRY;

        memset(buf, 0, sizeof(buf));

        if (!obd && cmd != OBD_IOC_DEVICE && cmd != TCGETS
            && cmd != OBD_IOC_NAME2DEV) {
                CERROR("OBD ioctl: No device\n");
                RETURN(-EINVAL);
        }
        if (obd_ioctl_getdata(buf, buf + 800, (void *)arg)) {
                CERROR("OBD ioctl: data error\n");
                RETURN(-EINVAL);
        }
        data = (struct obd_ioctl_data *)buf;

        switch (cmd) {
        case TCGETS:
                RETURN(-EINVAL);
        case OBD_IOC_DEVICE: {
                CDEBUG(D_IOCTL, "\n");
                if (data->ioc_dev >= MAX_OBD_DEVICES || data->ioc_dev < 0) {
                        CERROR("OBD ioctl: DEVICE insufficient devices\n");
                        RETURN(-EINVAL);
                }
                CDEBUG(D_IOCTL, "device %d\n", data->ioc_dev);

                filp->private_data = &obd_dev[data->ioc_dev];
                RETURN(0);
        }

        case OBD_IOC_NAME2DEV: {
                int dev;

                filp->private_data = NULL;

                if (!data->ioc_inlbuf1) {
                        CERROR("No name passed!\n");
                        RETURN(-EINVAL);
                }
                CDEBUG(D_IOCTL, "device name %s\n", data->ioc_inlbuf1);
                dev = obd_class_name2dev(data->ioc_inlbuf1);
                data->ioc_dev = dev;
                if (dev == -1) {
                        CERROR("No device for name %s!\n", data->ioc_inlbuf1);
                        RETURN(-EINVAL);
                }

                CDEBUG(D_IOCTL, "device name %s, dev %d\n", data->ioc_inlbuf1,
                       dev);
                filp->private_data = &obd_dev[data->ioc_dev];
                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }

        case OBD_IOC_ATTACH: {
                struct obd_type *type;

                /* have we attached a type to this device */
                if (obd->obd_flags & OBD_ATTACHED) {
                        CERROR("OBD: Device %d already typed as  %s.\n",
                               obd->obd_minor, MKSTR(obd->obd_type->typ_name));
                        RETURN(-EBUSY);
                }

                CDEBUG(D_IOCTL, "attach %s %s\n", MKSTR(data->ioc_inlbuf1),
                       MKSTR(data->ioc_inlbuf2));

                /* find the type */
                type = obd_nm_to_type(data->ioc_inlbuf1);
                if (!type) {
                        CERROR("OBD: unknown type dev %d\n", obd->obd_minor);
                        RETURN(-EINVAL);
                }

                obd->obd_type = type;
                obd->obd_multi_count = 0;
                INIT_LIST_HEAD(&obd->obd_gen_clients);
                INIT_LIST_HEAD(&obd->obd_req_list);

                /* do the attach */
                if (OBT(obd) && OBP(obd, attach))
                        err = OBP(obd,attach)(obd, sizeof(*data), data);
                if (err) {
                        obd->obd_type = NULL;
                } else {
                        obd->obd_flags |=  OBD_ATTACHED;
                        type->typ_refcnt++;
                        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
                               obd->obd_minor, data->ioc_inlbuf1);
                        obd->obd_proc_entry =
                                proc_lustre_register_obd_device(obd);
                        if (data->ioc_inlbuf2) {
                                int len = strlen(data->ioc_inlbuf2);
                                OBD_ALLOC(obd->obd_name, len + 1);
                                if (!obd->obd_name) {
                                        CERROR("no memory\n");
                                        LBUG();
                                }
                                memcpy(obd->obd_name, data->ioc_inlbuf2, len+1);
                        }

                        MOD_INC_USE_COUNT;
                }

                RETURN(err);
        }

        case OBD_IOC_DETACH: {
                ENTRY;
                if (obd->obd_flags & OBD_SET_UP) {
                        CERROR("OBD device %d still set up\n", obd->obd_minor);
                        RETURN(-EBUSY);
                }
                if (! (obd->obd_flags & OBD_ATTACHED) ) {
                        CERROR("OBD device %d not attached\n", obd->obd_minor);
                        RETURN(-ENODEV);
                }
                if ( !list_empty(&obd->obd_gen_clients) ) {
                        CERROR("OBD device %d has connected clients\n",
                               obd->obd_minor);
                        RETURN(-EBUSY);
                }
                if ( !list_empty(&obd->obd_req_list) ) {
                        CERROR("OBD device %d has hanging requests\n",
                               obd->obd_minor);
                        RETURN(-EBUSY);
                }
                
                if (obd->obd_name) { 
                        OBD_FREE(obd->obd_name, strlen(obd->obd_name)+ 1);
                        obd->obd_name = NULL;
                }

                if (obd->obd_proc_entry)
                        proc_lustre_release_obd_device(obd);

                obd->obd_flags &= ~OBD_ATTACHED;
                obd->obd_type->typ_refcnt--;
                obd->obd_type = NULL;
                MOD_DEC_USE_COUNT;
                RETURN(0);
        }

        case OBD_IOC_SETUP: {
                /* have we attached a type to this device? */
                if (!(obd->obd_flags & OBD_ATTACHED)) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        RETURN(-ENODEV);
                }

                /* has this been done already? */
                if ( obd->obd_flags & OBD_SET_UP ) {
                        CERROR("Device %d already setup (type %s)\n",
                               obd->obd_minor, obd->obd_type->typ_name);
                        RETURN(-EBUSY);
                }

                if ( OBT(obd) && OBP(obd, setup) )
                        err = obd_setup(obd, sizeof(*data), data);

                if (!err) { 
                        obd->obd_type->typ_refcnt++;
                        obd->obd_flags |= OBD_SET_UP;
                }

                RETURN(err);
        }
        case OBD_IOC_CLEANUP: {
                /* have we attached a type to this device? */
                if (!(obd->obd_flags & OBD_ATTACHED)) {
                        CERROR("Device %d not attached\n", obd->obd_minor);
                        RETURN(-ENODEV);
                }

                if ( OBT(obd) && OBP(obd, cleanup) )
                        err = obd_cleanup(obd);

                if (!err) {
                        obd->obd_flags &= ~OBD_SET_UP;
                        obd->obd_type->typ_refcnt--;
                }
                RETURN(err);
        }

        case OBD_IOC_CONNECT: {
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd; 

                err = obd_connect(&conn);

                CDEBUG(D_IOCTL, "assigned connection %d\n", conn.oc_id);
                data->ioc_conn1 = conn.oc_id;
                if (err)
                        RETURN(err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }

        case OBD_IOC_DISCONNECT: { 
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd;

                err = obd_disconnect(&conn);
                RETURN(err);
        }               

        case OBD_IOC_DEC_USE_COUNT: { 
                MOD_DEC_USE_COUNT;
                RETURN(0);
        }

        case OBD_IOC_CREATE: {
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd;

                err = obd_create(&conn, &data->ioc_obdo1);
                if (err)
                        RETURN(err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }

        case OBD_IOC_GETATTR: {
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd;

                err = obd_getattr(&conn, &data->ioc_obdo1);
                if (err)
                        RETURN(err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }

        case OBD_IOC_SETATTR: {
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd;

                err = obd_setattr(&conn, &data->ioc_obdo1);
                if (err)
                        RETURN(err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }

        case OBD_IOC_DESTROY: {
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd;

                err = obd_destroy(&conn, &data->ioc_obdo1);
                if (err)
                        RETURN(err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }

        case OBD_IOC_BRW_WRITE:
                rw = OBD_BRW_WRITE;
        case OBD_IOC_BRW_READ: {
                /* FIXME: use a better ioctl data struct than obd_ioctl_data.
                 *        We don't really support multiple-obdo I/Os here,
                 *        for example offset and count are not per-obdo.
                 */
                struct obd_conn conns[2];
                struct obdo     *obdos[2] = { NULL, NULL };
                obd_count       oa_bufs[2] = { 0, 0 };
                struct page     **bufs = NULL;
                obd_size        *counts = NULL;
                obd_off         *offsets = NULL;
                obd_flag        *flags = NULL;
                int             num = 1;
                int             pages;
                int             i, j;

                pages = oa_bufs[0] = data->ioc_plen1 / PAGE_SIZE;
                if (data->ioc_obdo2.o_id) {
                        num = 2;
                        oa_bufs[1] = data->ioc_plen2 / PAGE_SIZE;
                        pages += oa_bufs[1];
                }

                CDEBUG(D_INODE, "BRW %s with %dx%d pages\n",
                       rw == OBD_BRW_READ ? "read" : "write",
                       num, oa_bufs[0]);
                bufs = kmalloc(pages * sizeof(*bufs), GFP_KERNEL);
                counts = kmalloc(pages * sizeof(*counts), GFP_KERNEL);
                offsets = kmalloc(pages * sizeof(*offsets), GFP_KERNEL);
                flags = kmalloc(pages * sizeof(*flags), GFP_KERNEL);
                if (!bufs || !counts || !offsets || !flags) {
                        CERROR("no memory for %d BRW per-page data\n", pages);
                        err = -ENOMEM;
                        GOTO(brw_free, err);
                }

                obdos[0] = &data->ioc_obdo1;
                if (num > 1)
                        obdos[1] = &data->ioc_obdo2;

                for (i = 0, pages = 0; i < num; i++) {
                        unsigned long off;
                        void *from;

                        conns[i].oc_id = (&data->ioc_conn1)[i];
                        conns[i].oc_dev = obd;

                        from = (&data->ioc_pbuf1)[i];
                        off = data->ioc_offset;

                        for (j = 0; j < oa_bufs[i];
                             j++, pages++, off += PAGE_SIZE, from += PAGE_SIZE){
                                unsigned long to;

                                to = __get_free_pages(GFP_KERNEL, 0);
                                if (!to) {
                                /*      ||
                                    copy_from_user((void *)to,from,PAGE_SIZE))
                                        free_pages(to, 0);
                                 */
                                        CERROR("no memory for brw pages\n");
                                        err = -ENOMEM;
                                        GOTO(brw_cleanup, err);
                                }
                                bufs[pages] = virt_to_page(to);
                                counts[pages] = PAGE_SIZE;
                                offsets[pages] = off;
                                flags[pages] = 0;
                        }
                }

                err = obd_brw(rw, conns, num, obdos, oa_bufs, bufs,
                              counts, offsets, flags);

                EXIT;
        brw_cleanup:
                while (pages-- > 0)
                        free_pages((unsigned long)page_address(bufs[pages]), 0);
        brw_free:
                kfree(flags);
                kfree(offsets);
                kfree(counts);
                kfree(bufs);
                return err;
        }
        default: {
                conn.oc_id = data->ioc_conn1;
                conn.oc_dev = obd;

                err = obd_iocontrol(cmd, &conn, sizeof(*data), data, NULL);
                if (err)
                        RETURN(err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                RETURN(err);
        }
        }
} /* obd_class_ioctl */


/* Driver interface done, utility functions follow */
int obd_register_type(struct obd_ops *ops, char *nm)
{
        struct obd_type *type;

        ENTRY;

        if (obd_init_magic != 0x11223344) {
                CERROR("bad magic for type\n");
                RETURN(-EINVAL);
        }

        if  ( obd_nm_to_type(nm) ) {
                CDEBUG(D_IOCTL, "Type %s already registered\n", nm);
                RETURN(-EEXIST);
        }
        
        OBD_ALLOC(type, sizeof(*type));
        if (!type)
                RETURN(-ENOMEM);
        INIT_LIST_HEAD(&type->typ_chain);
        MOD_INC_USE_COUNT;
        list_add(&type->typ_chain, obd_types.next);
        type->typ_ops = ops;
        type->typ_name = nm;
        RETURN(0);
}
        
int obd_unregister_type(char *nm)
{
        struct obd_type *type = obd_nm_to_type(nm);

        ENTRY;

        if ( !type ) {
                MOD_DEC_USE_COUNT;
                CERROR("unknown obd type\n");
                RETURN(-EINVAL);
        }

        if ( type->typ_refcnt ) {
                MOD_DEC_USE_COUNT;
                CERROR("type %s has refcount (%d)\n", nm, type->typ_refcnt);
                RETURN(-EBUSY);
        }

        list_del(&type->typ_chain);
        OBD_FREE(type, sizeof(*type));
        MOD_DEC_USE_COUNT;
        RETURN(0);
} /* obd_unregister_type */

/* declare character device */
static struct file_operations obd_psdev_fops = {
        ioctl: obd_class_ioctl,       /* ioctl */
        open: obd_class_open,        /* open */
        release: obd_class_release,     /* release */
};

/* modules setup */
#define OBD_MINOR 241
static struct miscdevice obd_psdev = {
        OBD_MINOR,
        "obd_psdev",
        &obd_psdev_fops
};

EXPORT_SYMBOL(obd_register_type);
EXPORT_SYMBOL(obd_unregister_type);

EXPORT_SYMBOL(obd_dev);

EXPORT_SYMBOL(gen_connect);
EXPORT_SYMBOL(gen_client);
EXPORT_SYMBOL(gen_cleanup);
EXPORT_SYMBOL(gen_disconnect);
EXPORT_SYMBOL(gen_copy_data); 
EXPORT_SYMBOL(obdo_cachep);

/* EXPORT_SYMBOL(gen_multi_attach); */
EXPORT_SYMBOL(gen_multi_setup);
EXPORT_SYMBOL(gen_multi_cleanup);
EXPORT_SYMBOL(obd_memory);
EXPORT_SYMBOL(obd_fail_loc);

static int __init init_obdclass(void)
{
        int err;
        int i;

        printk(KERN_INFO "OBD class driver  v0.01, braam@stelias.com\n");

        INIT_LIST_HEAD(&obd_types);

        if ((err = misc_register(&obd_psdev))) {
                CERROR("cannot register %d err %d\n", OBD_MINOR, err);
                return err;
        }

        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                memset(&(obd_dev[i]), 0, sizeof(obd_dev[i]));
                obd_dev[i].obd_minor = i;
                INIT_LIST_HEAD(&obd_dev[i].obd_gen_clients);
                INIT_LIST_HEAD(&obd_dev[i].obd_req_list);
                init_waitqueue_head(&obd_dev[i].obd_req_waitq);
        }

        err = obd_init_obdo_cache();
        if (err)
                return err;
        obd_sysctl_init();
        obd_init_magic = 0x11223344;
        return 0;
}

static void __exit cleanup_obdclass(void)
{
        int i;
        ENTRY;

        misc_deregister(&obd_psdev);
        for (i = 0; i < MAX_OBD_DEVICES; i++) {
                struct obd_device *obd = &obd_dev[i];
                if ( obd->obd_type && 
                     (obd->obd_flags & OBD_SET_UP) &&
                     OBT(obd) && OBP(obd, detach) ) {
                        /* XXX should this call generic detach otherwise? */
                        OBP(obd, detach)(obd);
                }
        }

        obd_cleanup_obdo_cache();
        obd_sysctl_clean();
        CERROR("obd memory leaked: %ld bytes\n", obd_memory);
        obd_init_magic = 0;
        EXIT;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Class Driver v1.0");
MODULE_LICENSE("GPL"); 

module_init(init_obdclass);
module_exit(cleanup_obdclass);
