/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lov/lov.c
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@off.net>
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_LOV

#include <linux/module.h>
#include <linux/obd_class.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];

/* obd methods */
static int lov_connect(struct obd_conn *conn)
{
        int rc;

        MOD_INC_USE_COUNT;
        rc = gen_connect(conn);

        if (rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int lov_disconnect(struct obd_conn *conn)
{
        int rc;

        rc = gen_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        /* XXX cleanup preallocated inodes */
        return rc;
}

static int lov_getattr(struct obd_conn *conn, struct obdo *oa)
{
        int rc;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        rc = obd_getattr(&conn->oc_dev->obd_multi_conn[0], oa);
        RETURN(rc);
}

static int lov_setattr(struct obd_conn *conn, struct obdo *oa)
{
        int rc, retval, i;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        for (i = 0; i < conn->oc_dev->obd_multi_count; i++) {
                rc = obd_setattr(&conn->oc_dev->obd_multi_conn[i], oa);
                if (i == 0)
                        retval = rc;
                else if (retval != rc)
                        CERROR("different results on multiple OBDs!\n");
        }

        RETURN(rc);
}

static int lov_open(struct obd_conn *conn, struct obdo *oa)
{
        int rc, retval, i;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        for (i = 0; i < conn->oc_dev->obd_multi_count; i++) {
                rc = obd_open(&conn->oc_dev->obd_multi_conn[i], oa);
                if (i == 0)
                        retval = rc;
                else if (retval != rc)
                        CERROR("different results on multiple OBDs!\n");
        }

        RETURN(rc);
}

static int lov_close(struct obd_conn *conn, struct obdo *oa)
{
        int rc, retval, i;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        for (i = 0; i < conn->oc_dev->obd_multi_count; i++) {
                rc = obd_close(&conn->oc_dev->obd_multi_conn[i], oa);
                if (i == 0)
                        retval = rc;
                else if (retval != rc)
                        CERROR("different results on multiple OBDs!\n");
        }

        RETURN(rc);
}

static int lov_create(struct obd_conn *conn, struct obdo *oa)
{
        int rc, i;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        for (i = 0; i < conn->oc_dev->obd_multi_count; i++)
                rc = obd_create(&conn->oc_dev->obd_multi_conn[i], oa);

        return rc;
}

static int filter_destroy(struct obd_conn *conn, struct obdo *oa)
{
#if 0
        struct obd_device * obddev;
        struct obd_client * cli;
        struct inode * inode;
        struct file *dir;
        struct file *object;
        int rc;
        struct obd_run_ctxt saved;

        if (!(cli = gen_client(conn))) {
                CERROR("invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        obddev = conn->oc_dev;
        object = filter_obj_open(obddev, oa->o_id, oa->o_mode);
        if (!object || IS_ERR(object)) {
                EXIT;
                return -ENOENT;
        }

        inode = object->f_dentry->d_inode;
        inode->i_nlink = 1;
        inode->i_mode = 010000;

        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        dir = filter_parent(oa->o_id, oa->o_mode);
        if (IS_ERR(dir)) {
                rc = PTR_ERR(dir);
                EXIT;
                goto out;
        }
        dget(dir->f_dentry);
        dget(object->f_dentry);
        rc = vfs_unlink(dir->f_dentry->d_inode, object->f_dentry);

        filp_close(dir, 0);
        filp_close(object, 0);
out:
        pop_ctxt(&saved);
        EXIT;
        return rc;
#endif
        return 0;
}

/* FIXME: maybe we'll just make one node the authoritative attribute node, then
 * we can send this 'punch' to just the authoritative node and the nodes
 * that the punch will affect. */
static int lov_punch(struct obd_conn *conn, struct obdo *oa,
                     obd_size count, obd_off offset)
{
        int rc, retval, i;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        for (i = 0; i < conn->oc_dev->obd_multi_count; i++) {
                rc = obd_punch(&conn->oc_dev->obd_multi_conn[i], oa, count,
                               offset);
                if (i == 0)
                        retval = rc;
                else if (retval != rc)
                        CERROR("different results on multiple OBDs!\n");
        }

        RETURN(rc);
}

/* buffer must lie in user memory here */
static int lov_read(struct obd_conn *conn, struct obdo *oa, char *buf,
                    obd_size *count, obd_off offset)
{
        int rc, i;
        obd_off off = offset;
        obd_size retval = 0;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        while (off < offset + count) {
                int stripe, conn;
                obd_size size, tmp;

                stripe = off / conn->oc_dev->u.lov.lov_stripe_size;
                size = (stripe + 1) * conn->oc_dev->u.lov.lov_strip_size - off;
                if (size > *count)
                        size = *count;


                conn = stripe % conn->oc_dev->obd_multi_count;

                tmp = size;
                rc = obd_read(&conn->oc_dev->obd_multi_conn[conn], oa, buf,
                              &size, off);
                if (rc == 0)
                        retval += size;
                else {
                        CERROR("read(off=%Lu, count=%Lu): %d\n",
                               (unsigned long long)off,
                               (unsigned long long)size, rc);
                        break;
                }

                buf += size;
        }

        *count = retval;
        RETURN(rc);
}


/* buffer must lie in user memory here */
static int filter_write(struct obd_conn *conn, struct obdo *oa, char *buf,
                         obd_size *count, obd_off offset)
{
        int err;
        struct file * file;
        unsigned long retval;

        ENTRY;
        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        file = filter_obj_open(conn->oc_dev, oa->o_id, oa->o_mode);
        if (!file || IS_ERR(file)) {
                EXIT;
                return -PTR_ERR(file);
        }

        /* count doubles as retval */
        retval = file->f_op->write(file, buf, *count, (loff_t *)&offset);
        filp_close(file, 0);

        if ( retval >= 0 ) {
                err = 0;
                *count = retval;
                EXIT;
        } else {
                err = retval;
                *count = 0;
                EXIT;
        }

        return err;
}

static int lov_enqueue(struct obd_conn *conn, struct ldlm_namespace *ns,
                       struct ldlm_handle *parent_lock, __u64 *res_id,
                       __u32 type, struct ldlm_extent *extent, __u32 mode,
                       int *flags, void *data, int datalen,
                       struct ldlm_handle *lockh)
{
        int rc;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        rc = obd_enqueue(&conn->oc_dev->obd_multi_conn[0], ns, parent_lock,
                         res_id, type, extent, mode, flags, data, datalen,
                         lockh);
        RETURN(rc);
}

static int lov_cancel(struct obd_conn *conn, __u32 mode,
                      struct ldlm_handle *lockh)
{
        int rc;
        ENTRY;

        if (!gen_client(conn))
                RETURN(-EINVAL);

        rc = obd_cancel(&conn->oc_dev->obd_multi_conn[0], oa);
        RETURN(rc);
}

struct obd_ops lov_obd_ops = {
        o_setup:       gen_multi_setup,
        o_cleanup:     gen_multi_cleanup,
        o_create:      lov_create,
        o_destroy:     lov_destroy,
        o_getattr:     lov_getattr,
        o_setattr:     lov_setattr,
        o_open:        lov_open,
        o_close:       lov_close,
        o_connect:     lov_connect,
        o_disconnect:  lov_disconnect,
        o_brw:         lov_pgcache_brw,
        o_punch:       lov_punch,
        o_enqueue:     lov_enqueue,
        o_cancel:      lov_cancel
};


#define LOV_VERSION "v0.1"

static int __init lov_init(void)
{
        printk(KERN_INFO "Lustre Logical Object Volume driver " LOV_VERSION
               ", phil@clusterfs.com\n");
        return obd_register_type(&lov_obd_ops, OBD_LOV_DEVICENAME);
}

static void __exit lov_exit(void)
{
        obd_unregister_type(OBD_LOV_DEVICENAME);
}

MODULE_AUTHOR("Phil Schwan <phil@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver v0.1");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
