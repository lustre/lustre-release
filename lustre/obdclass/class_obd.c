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
#include <asm/io.h>
#include <asm/system.h>
#include <asm/poll.h>
#include <asm/uaccess.h>
#include <linux/miscdevice.h>

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/smp_lock.h>
#include <linux/lprocfs.h>

struct semaphore obd_conf_sem;   /* serialize configuration commands */
struct obd_device obd_dev[MAX_OBD_DEVICES];
struct list_head obd_types;
unsigned long obd_memory;

/* The following are visible and mutable through /proc/sys/lustre/. */
unsigned long obd_fail_loc;
unsigned long obd_timeout = 100;
char obd_recovery_upcall[128] = "/usr/lib/lustre/ha_assist";

extern struct obd_type *class_nm_to_type(char *nm);
/*
 * LProcFS specific data structures. These define the namespace for
 * the various device classes. We will need to distribute these
 * later, to individual modules (e.g. MDS, MDC etc)
 */

#ifdef LPROCFS_EXISTS

/*
 * Common OBD namespace for lprocFS (these are used very often)
 */

char* obd_dir_nm_1[]= {
        "mgmt%",
        "mgmt/setup",
        "mgmt/cleanup",
        "mgmt/connect",
        "mgmt/disconnect",
        0
};

lprocfs_vars_t obd_var_nm_1[]= {
        {"num_ops", lprocfs_ll_rd, lprocfs_ll_wr},
        {"min_time", lprocfs_ll_rd, lprocfs_ll_wr},
        {"max_time", lprocfs_ll_rd, lprocfs_ll_wr},
        {"sum_time", lprocfs_ll_rd, lprocfs_ll_wr},
        {"0", 0, 0}
};


/*
 *  MDC Spcific namespace for lprocFS
 */

char *mdc_dir_nm_1[]= {
        "reint",
        "getstatus",
        "getattr",
        "setattr",
        "open",
        "readpage",
        "create",
        "unlink",
        "link",
        "rename",
        0
};

/*
 * Create the MDC groupings
 */
lprocfs_group_t lprocfs_mdc_nm[]= {

        {obd_dir_nm_1, obd_var_nm_1, e_generic},
        {mdc_dir_nm_1, obd_var_nm_1, e_generic},
        {0, 0, 0}
};

/*
 * MDS Device Groupings
 */
char *mds_dir_nm_1[]={
        "getstatus",
        "connect",
        "disconnect_callback",
        "getattr",
        "readpage",
        "open",
        "close",
        "create",
        "unlink",
        "link",
        "rename",
        "reint%",
        "reint/summary",
        "reint/setattr",
        "reint/create",
        "reint/unlink",
        "reint/link",
        "reint/rename",
        "reint/recreate",
        0
};

char *mds_dir_nm_2[]={
        "mstatfs",
        0
};


lprocfs_vars_t mds_var_nm_2[]={
        {"f_type", rd_other, wr_other},
        {"f_bsize",rd_other, wr_other},
        {"f_blocks",rd_other, wr_other},
        {"f_bfree",rd_other, wr_other},
        {"f_bavail",rd_other, wr_other},
        {"uuid",rd_string, wr_string},
        {"0", 0, 0}
};


lprocfs_group_t lprocfs_mds_nm[]={
         {obd_dir_nm_1, obd_var_nm_1, e_generic},
         {mds_dir_nm_1, obd_var_nm_1, e_generic},
         {mds_dir_nm_2, mds_var_nm_2, e_specific},
         {0, 0, 0}
};

/*
 * OSC Namespace
 */

char* osc_dir_nm_1[]={
        "create",
        "destroy",
        "getattr",
        "setattr",
        "open",
        "close",
        "brw",
        "punch",
        "summary",
        "cancel",
        0
};

lprocfs_group_t lprocfs_osc_nm[]={
         {obd_dir_nm_1, obd_var_nm_1, e_generic},
         {osc_dir_nm_1, obd_var_nm_1, e_generic},
         {0, 0, 0}
};


/*
 * OST, LOV, OBD_FILTER namespace
 * Note: These namespaces are exactly similar to the osc_dir_namespace
 * Hence, I use the osc namespace as the base class and add only
 * those attributes that are missing in osc_dir_namespace.
 */

char *ost_lov_obdfilter_dir_nm_1[]={
        "getinfo",
        0

};

char *ost_lov_obdfilter_dir_nm_2[]={
        "ostatfs",
        0
};

lprocfs_vars_t ost_lov_obdfilter_var_nm_2[]={
        {"f_type", rd_other, wr_other},
        {"f_bsize",rd_other, wr_other},
        {"f_blocks",rd_other, wr_other},
        {"f_bfree",rd_other, wr_other},
        {"f_bavail",rd_other, wr_other},
        {"f_objects", rd_other, wr_other},
        {"f_ofree", rd_other, wr_other},
        {"f_objectgroups", rd_other, wr_other},
        {"f_uuid", rd_string, wr_string},
        {"0", 0, 0}
};


lprocfs_group_t lprocfs_ost_lov_obdf_nm[]={
         {obd_dir_nm_1, obd_var_nm_1, e_generic},
         {osc_dir_nm_1, obd_var_nm_1, e_generic},
         {ost_lov_obdfilter_dir_nm_1, obd_var_nm_1, e_generic},
         {ost_lov_obdfilter_dir_nm_2, ost_lov_obdfilter_var_nm_2, e_specific},
         {0, 0, 0}
};

/*
 * LDLM Device namespace
 */


char* ldlm_dir_nm_1[]={
        "locks%",
        "locks/enqueus",
        "locks/cancels",
        "locks/converts",
        "locks/matches",
        0
};

lprocfs_vars_t ldlm_var_nm_1[]= {
        {"num_total", lprocfs_ll_rd, lprocfs_ll_wr},
        {"num_zerolatency", lprocfs_ll_rd, lprocfs_ll_wr},
        {"num_zerolatency_inflight", lprocfs_ll_rd, lprocfs_ll_wr},
        {"num_zerolatency_done", lprocfs_ll_rd, lprocfs_ll_wr},
        {"nonzero_mintime", lprocfs_ll_rd, lprocfs_ll_wr},
        {"nonzero_maxtime", lprocfs_ll_rd, lprocfs_ll_wr},
        {"nonzero_sumtime", lprocfs_ll_rd, lprocfs_ll_wr},
        {"0", 0, 0}

};

lprocfs_group_t lprocfs_ldlm_nm[]={
         {obd_dir_nm_1, obd_var_nm_1, e_generic},
         {ldlm_dir_nm_1, ldlm_var_nm_1, e_generic},
         {0, 0, 0}
};

/*
 * Note: Need to add namespace for breaking out locks by device class
 */

/*
 * PTLRPC Namespace
 */
char* ptlrpc_dir_nm_1[]={
        "counters",
        0
};

lprocfs_vars_t ptlrpc_var_nm_1[]={
        {"msgs_alloc", lprocfs_ll_rd, lprocfs_ll_wr},
        {"msgs_max", lprocfs_ll_rd, lprocfs_ll_wr},
        {"recv_count", lprocfs_ll_rd, lprocfs_ll_wr},
        {"recv_length", lprocfs_ll_rd, lprocfs_ll_wr},
        {"send_count", lprocfs_ll_rd, lprocfs_ll_wr},
        {"send_length", lprocfs_ll_rd, lprocfs_ll_wr},
        {"portal_kmemory", lprocfs_ll_rd, lprocfs_ll_wr},
        {"0", 0, 0}
};

char* ptlrpc_dir_nm_2[] = {
        "network",
        0
};

lprocfs_vars_t ptlrpc_var_nm_2[] = {
        {"type", rd_string, wr_string},
        {"mtu", lprocfs_ll_rd, lprocfs_ll_wr},
        {"rxpackets", lprocfs_ll_rd, lprocfs_ll_wr},
        {"txpackets", lprocfs_ll_rd, lprocfs_ll_wr},
        {"txbytes", lprocfs_ll_rd, lprocfs_ll_wr},
        {"0", 0, 0}
};

lprocfs_group_t lprocfs_ptlrpc_nm[]={
         {obd_dir_nm_1, obd_var_nm_1, e_generic},
         {ptlrpc_dir_nm_1, ptlrpc_var_nm_1, e_generic},
         {ptlrpc_dir_nm_2, ptlrpc_var_nm_2, e_specific},
         {0, 0, 0}
};


/*
 * Building the entire device namespace. This will be used during attach and
 * detach to associate the namespace with the class of the device
 */

lprocfs_obd_nm_t obd_nm[]={
        {"mdc", lprocfs_mdc_nm, sizeof(struct lprofiler_gen)},
        {"mds", lprocfs_mds_nm, sizeof(struct lprofiler_gen)},
        {"osc", lprocfs_osc_nm, sizeof(struct lprofiler_gen)},
        {"ost", lprocfs_ost_lov_obdf_nm, sizeof(struct lprofiler_gen)},
        {"lov", lprocfs_ost_lov_obdf_nm, sizeof(struct lprofiler_gen)},
        {"obdfilter", lprocfs_ost_lov_obdf_nm, sizeof(struct lprofiler_gen)},
        {"obdecho", lprocfs_ost_lov_obdf_nm, sizeof(struct lprofiler_gen)},
        {"ldlm", lprocfs_ldlm_nm, sizeof(struct lprofiler_ldlm)},
        {"ptlrpc", lprocfs_ptlrpc_nm, sizeof(struct lprofiler_ptlrpc)},
        {"0", 0, 0}
};

#else

lprocfs_obd_nm_t* obd_nm=0;

#endif

/*  opening /dev/obd */
static int obd_class_open(struct inode * inode, struct file * file)
{
        ENTRY;

        file->private_data = NULL;
        CDEBUG(D_IOCTL, "MOD_INC_USE for open: count = %d\n",
               atomic_read(&(THIS_MODULE)->uc.usecount));
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

        CDEBUG(D_IOCTL, "MOD_DEC_USE for close: count = %d\n",
               atomic_read(&(THIS_MODULE)->uc.usecount) - 1);
        MOD_DEC_USE_COUNT;
        RETURN(0);
}


inline void obd_data2conn(struct lustre_handle *conn, struct obd_ioctl_data *data)
{
        conn->addr = data->ioc_addr;
        conn->cookie = data->ioc_cookie;
}


inline void obd_conn2data(struct obd_ioctl_data *data, struct lustre_handle *conn)
{
        data->ioc_addr = conn->addr;
        data->ioc_cookie = conn->cookie;
}


/* to control /dev/obd */
static int obd_class_ioctl (struct inode * inode, struct file * filp,
                            unsigned int cmd, unsigned long arg)
{
        char *buf = NULL;
        int len = 0;
        struct obd_ioctl_data *data;
        struct obd_device *obd = filp->private_data;

        struct lustre_handle conn;
        int rw = OBD_BRW_READ;
        int err = 0;
        int serialised = 0;
        int l_idx = 0;
        ENTRY;

        switch (cmd)
        {
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
            cmd != OBD_IOC_LIST &&
            cmd != OBD_IOC_NAME2DEV && cmd != OBD_IOC_NEWDEV) {
                CERROR("OBD ioctl: No device\n");
                GOTO(out, err=-EINVAL);
        }
        if (obd_ioctl_getdata(&buf, &len, (void *)arg)) {
                CERROR("OBD ioctl: data error\n");
                GOTO(out, err=-EINVAL);
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

                err = copy_to_user((int *)arg, data, len);
                GOTO(out, err);
        }


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
                err = copy_to_user((int *)arg, data, sizeof(*data));
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
                err = copy_to_user((int *)arg, data, sizeof(*data));
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

                err = copy_to_user((int *)arg, data, sizeof(*data));
                GOTO(out, err);
        }

        case OBD_IOC_ATTACH: {
                struct obd_type *type;
                int minor;

                /* have we attached a type to this device */
                if (obd->obd_flags & OBD_ATTACHED || obd->obd_type) {
                        CERROR("OBD: Device %d already typed as %s.\n",
                               obd->obd_minor, MKSTR(obd->obd_type->typ_name));
                        GOTO(out, err=-EBUSY);
                }

                if (!data->ioc_inllen1 || !data->ioc_inlbuf1) {
                        CERROR("No type passed!\n");
                        GOTO(out, err=-EINVAL);
                }
                if (data->ioc_inlbuf1[data->ioc_inllen1-1] !=0) {
                        CERROR("Type not nul terminated!\n");
                        GOTO(out, err=-EINVAL);
                }

                CDEBUG(D_IOCTL, "attach type %s name: %s uuid: %s\n",
                       MKSTR(data->ioc_inlbuf1),
                       MKSTR(data->ioc_inlbuf2), MKSTR(data->ioc_inlbuf3));

                /* find the type */
                type = class_nm_to_type(data->ioc_inlbuf1);
                if (!type) {
                        CERROR("OBD: unknown type dev %d\n", obd->obd_minor);
                        GOTO(out, err=-EINVAL);
                }

                minor = obd->obd_minor;
                memset(obd, 0, sizeof(*obd));
                obd->obd_minor = minor;
                obd->obd_type = type;
                INIT_LIST_HEAD(&obd->obd_exports);
                INIT_LIST_HEAD(&obd->obd_imports);
                spin_lock_init(&obd->obd_dev_lock);

                /* do the attach */
                if (OBP(obd, attach))
                        err = OBP(obd,attach)(obd, sizeof(*data), data);
                if (err) {
                        obd->obd_type = NULL;
                } else {
                        obd->obd_flags |= OBD_ATTACHED;

                        type->typ_refcnt++;
                        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
                               obd->obd_minor, data->ioc_inlbuf1);
                        if (data->ioc_inlbuf2) {
                                int len = strlen(data->ioc_inlbuf2) + 1;
                                OBD_ALLOC(obd->obd_name, len);
                                if (!obd->obd_name) {
                                        CERROR("no memory\n");
                                        LBUG();
                                }
                                memcpy(obd->obd_name, data->ioc_inlbuf2, len);
                                /* obd->obd_proc_entry =
                                        proc_lustre_register_obd_device(obd);
                                */
                        } else {
                                CERROR("WARNING: unnamed obd device\n");
                                obd->obd_proc_entry = NULL;
                        }

                        if (data->ioc_inlbuf3) {
                                int len = strlen(data->ioc_inlbuf3);
                                if (len >= sizeof(obd->obd_uuid)) {
                                        CERROR("uuid must be < %d bytes long\n",
                                               sizeof(obd->obd_uuid));
                                        if (obd->obd_name)
                                                OBD_FREE(obd->obd_name,
                                                         strlen(obd->obd_name) + 1);
                                        GOTO(out, err=-EINVAL);
                                }
                                memcpy(obd->obd_uuid, data->ioc_inlbuf3, len);
                        }
                        /* Get the LprocFS namespace for this device class */
                        /*
                        l_idx = lprocfs_get_nm(data->ioc_inlbuf1, obd_nm);
                        if (l_idx < 0) {
                                CERROR("Non-existent device class"
                                       "or proc/lustre not compiled \n");
                        } else {
                                lprocfs_reg_dev(obd, obd_nm[l_idx].obd_names,
                                                obd_nm[l_idx].cntr_blk_sz);
                        }
                        */
                        CDEBUG(D_IOCTL, "MOD_INC_USE for attach: count = %d\n",
                               atomic_read(&(THIS_MODULE)->uc.usecount));
                        MOD_INC_USE_COUNT;
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
#warning FIXME: Mike, we probably need some sort of "force detach" here
                if (!list_empty(&obd->obd_exports) ) {
                        CERROR("OBD device %d (%p) has exports\n",
                               obd->obd_minor, obd);
                        GOTO(out, err=-EBUSY);
                }

                /*
                if (lprocfs_dereg_dev(obd) != LPROCFS_SUCCESS) {
                        CERROR("Could not remove /proc entry\n");
                }
                */
                if (obd->obd_name) {
                        OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                        obd->obd_name = NULL;
                }
                /*
                if (obd->obd_proc_entry)
                        proc_lustre_release_obd_device(obd);
                */

                obd->obd_flags &= ~OBD_ATTACHED;
                obd->obd_type->typ_refcnt--;
                obd->obd_type = NULL;
                CDEBUG(D_IOCTL, "MOD_DEC_USE for detach: count = %d\n",
                       atomic_read(&(THIS_MODULE)->uc.usecount) - 1);
                MOD_DEC_USE_COUNT;
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

                err = obd_connect(&conn, obd, cluuid);

                CDEBUG(D_IOCTL, "assigned export "LPX64"\n", conn.addr);
                obd_conn2data(data, &conn);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                // XXX save connection data into file handle
                GOTO(out, err);
        }

        case OBD_IOC_DISCONNECT: {
                obd_data2conn(&conn, data);
                err = obd_disconnect(&conn);
                GOTO(out, err);
        }

        case OBD_IOC_DEC_USE_COUNT: {
                CDEBUG(D_IOCTL, "MOD_DEC_USE for force dec: count = %d\n",
                       atomic_read(&(THIS_MODULE)->uc.usecount) - 1);
                MOD_DEC_USE_COUNT;
                GOTO(out, err=0);
        }

        case OBD_IOC_CREATE: {
                struct lov_stripe_md *lsm = NULL;
                obd_data2conn(&conn, data);

#warning FIXME: save lsm into file handle for other ops, release on close
                err = obd_create(&conn, &data->ioc_obdo1, &lsm);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                GOTO(out, err);
        }

        case OBD_IOC_GETATTR: {

                obd_data2conn(&conn, data);
                err = obd_getattr(&conn, &data->ioc_obdo1, NULL);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                GOTO(out, err);
        }

        case OBD_IOC_SETATTR: {
                obd_data2conn(&conn, data);
                err = obd_setattr(&conn, &data->ioc_obdo1, NULL);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                GOTO(out, err);
        }

        case OBD_IOC_DESTROY: {
                //void *ea;
                obd_data2conn(&conn, data);

                err = obd_destroy(&conn, &data->ioc_obdo1, NULL);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((int *)arg, data, sizeof(*data));
                GOTO(out, err);
        }

        case OBD_IOC_OPEN: {
                struct lov_stripe_md *lsm = NULL; // XXX fill in from create

                obd_data2conn(&conn, data);
                err = obd_open(&conn, &data->ioc_obdo1, lsm);
                GOTO(out, err);
        }

        case OBD_IOC_CLOSE: {
                struct lov_stripe_md *lsm = NULL; // XXX fill in from create

                obd_data2conn(&conn, data);
                obd_data2conn(&conn, data);
                err = obd_close(&conn, &data->ioc_obdo1, lsm);
                GOTO(out, err);
        }

        case OBD_IOC_BRW_WRITE:
                rw = OBD_BRW_WRITE;
        case OBD_IOC_BRW_READ: {
                struct lov_stripe_md tmp_lsm; // XXX fill in from create
                struct lov_stripe_md *lsm = &tmp_lsm; // XXX fill in from create
                struct io_cb_data *cbd = ll_init_cb();
                obd_count       pages = 0;
                struct brw_page *pga, *pgp;
                __u64 id = data->ioc_obdo1.o_id;
                int gfp_mask = (id & 1) ? GFP_HIGHUSER : GFP_KERNEL;
                int verify = (id != 0);
                __u64 off;
                int j;

                if (!cbd)
                        GOTO(out, err = -ENOMEM);

                obd_data2conn(&conn, data);

                pages = data->ioc_count / PAGE_SIZE;
                off = data->ioc_offset;

                CDEBUG(D_INODE, "BRW %s with %d pages @ "LPX64"\n",
                       rw == OBD_BRW_READ ? "read" : "write", pages, off);
                OBD_ALLOC(pga, pages * sizeof(*pga));
                if (!pga) {
                        CERROR("no memory for %d BRW per-page data\n", pages);
                        GOTO(brw_free, err = -ENOMEM);
                }

                memset(lsm, 0, sizeof(*lsm)); // XXX don't do this later
                lsm->lsm_object_id = id; // ensure id == lsm->lsm_object_id

                for (j = 0, pgp = pga; j < pages; j++, off += PAGE_SIZE, pgp++){
                        pgp->pg = alloc_pages(gfp_mask, 0);
                        if (!pgp->pg) {
                                CERROR("no memory for brw pages\n");
                                GOTO(brw_cleanup, err = -ENOMEM);
                        }
                        pgp->count = PAGE_SIZE;
                        pgp->off = off;
                        pgp->flag = 0;

                        if (verify) {
                                void *addr = kmap(pgp->pg);

                                if (rw == OBD_BRW_WRITE)
                                        page_debug_setup(addr, pgp->count,
                                                         pgp->off, id);
                                else
                                        page_debug_setup(addr, pgp->count,
                                                         0xdeadbeef00c0ffee,
                                                         0xdeadbeef00c0ffee);
                                kunmap(pgp->pg);
                        }
                }

                err = obd_brw(rw, &conn, lsm, j, pga, ll_sync_io_cb, cbd);
                if (err)
                        CERROR("test_brw: error from obd_brw: err = %d\n", err);
                EXIT;
        brw_cleanup:
                for (j = 0, pgp = pga; j < pages; j++, pgp++) {
                        if (pgp->pg != NULL) {
                                if (verify && !err) {
                                        void *addr = kmap(pgp->pg);

                                        err = page_debug_check("test_brw",
                                                               addr,
                                                               PAGE_SIZE,
                                                               pgp->off,id);
                                        kunmap(pgp->pg);
                                }
                                __free_pages(pgp->pg, 0);
                        }
                }
        brw_free:
                OBD_FREE(pga, pages * sizeof(*pga));
                GOTO(out, err);
        }
        default:
                obd_data2conn(&conn, data);

                err = obd_iocontrol(cmd, &conn, len, data, NULL);
                if (err)
                        GOTO(out, err);

                err = copy_to_user((int *)arg, data, len);
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

void (*class_signal_connection_failure)(struct ptlrpc_connection *);
int (*mds_destroy_export)(struct obd_export *exp);
int (*ldlm_destroy_export)(struct obd_export *exp);

EXPORT_SYMBOL(obd_dev);
EXPORT_SYMBOL(obdo_cachep);
EXPORT_SYMBOL(obd_memory);
EXPORT_SYMBOL(obd_fail_loc);
EXPORT_SYMBOL(obd_timeout);
EXPORT_SYMBOL(obd_recovery_upcall);

EXPORT_SYMBOL(class_register_type);
EXPORT_SYMBOL(class_unregister_type);
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
//EXPORT_SYMBOL(class_uuid_parse);
EXPORT_SYMBOL(class_uuid_unparse);
//EXPORT_SYMBOL(class_multi_setup);
//EXPORT_SYMBOL(class_multi_cleanup);

EXPORT_SYMBOL(class_signal_connection_failure);
EXPORT_SYMBOL(mds_destroy_export);
EXPORT_SYMBOL(ldlm_destroy_export);
EXPORT_SYMBOL(ll_sync_io_cb);
EXPORT_SYMBOL(ll_init_cb);

static int __init init_obdclass(void)
{
        struct obd_device *obd;
        int err;
        int i;

        printk(KERN_INFO "OBD class driver  v0.9, info@clusterfs.com\n");

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
        return 0;
}

static void __exit cleanup_obdclass(void)
{
        int i;
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
        CERROR("obd memory leaked: %ld bytes\n", obd_memory);
        EXIT;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Class Driver v1.0");
MODULE_LICENSE("GPL");

module_init(init_obdclass);
module_exit(cleanup_obdclass);
