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
#include <linux/obd_lov.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];

/* obd methods */
static int lov_connect(struct lustre_handle *conn)
{
        int rc;

        MOD_INC_USE_COUNT;
        rc = class_connect(conn);

        if (rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int lov_disconnect(struct lustre_handle *conn)
{
        int rc;

        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        /* XXX cleanup preallocated inodes */
        return rc;
}

static int lov_getattr(struct lustre_handle *conn, struct obdo *oa)
{
        int rc;
        ENTRY;

        if (!class_conn2export(conn))
                RETURN(-EINVAL);

        rc = obd_getattr(&conn->oc_dev->obd_multi_conn[0], oa);
        RETURN(rc);
}

static int lov_setattr(struct lustre_handle *conn, struct obdo *oa)
{
        int rc, retval, i;
        ENTRY;

        if (!class_conn2export(conn))
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

static int lov_open(struct lustre_handle *conn, struct obdo *oa)
{
        int rc, retval, i;
        ENTRY;

        if (!class_conn2export(conn))
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

static int lov_close(struct lustre_handle *conn, struct obdo *oa)
{
        int rc, retval, i;
        ENTRY;

        if (!class_conn2export(conn))
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

static int lov_create(struct lustre_handle *conn, struct obdo *oa)
{
        int rc, retval, i, offset;
        struct obdo tmp;
        struct lov_md md;
        ENTRY;

        if (!class_conn2export(conn))
                RETURN(-EINVAL);

        md.lmd_object_id = oa->o_id;
        md.lmd_stripe_count = conn->oc_dev->obd_multi_count;

        memset(oa->o_inline, 0, sizeof(oa->o_inline));
        offset = sizeof(md);
        for (i = 0; i < md.lmd_stripe_count; i++) {
                struct lov_object_id lov_id;
                rc = obd_create(&conn->oc_dev->obd_multi_conn[i], &tmp);
                if (i == 0) {
                        memcpy(oa, &tmp, sizeof(tmp));
                        retval = rc;
                } else if (retval != rc)
                        CERROR("return codes didn't match (%d, %d)\n",
                               retval, rc);
                lov_id = (struct lov_object_id *)(oa->o_inline + offset);
                lov_id->l_device_id = i;
                lov_id->l_object_id = tmp.o_id;
                offset += sizeof(*lov_id);
        }
        memcpy(oa->o_inline, &md, sizeof(md));

        return rc;
}

static int lov_destroy(struct lustre_handle *conn, struct obdo *oa)
{
        int rc, retval, i, offset;
        struct obdo tmp;
        struct lov_md *md;
        struct lov_object_id lov_id;
        ENTRY;

        if (!class_conn2export(conn))
                RETURN(-EINVAL);

        md = (struct lov_md *)oa->o_inline;

        memcpy(&tmp, oa, sizeof(tmp));

        offset = sizeof(md);
        for (i = 0; i < md->lmd_stripe_count; i++) {
                struct lov_object_id *lov_id;
                lov_id = (struct lov_object_id *)(oa->o_inline + offset);

                tmp.o_id = lov_id->l_object_id;

                rc = obd_destroy(&conn->oc_dev->obd_multi_conn[i], &tmp);
                if (i == 0)
                        retval = rc;
                else if (retval != rc)
                        CERROR("return codes didn't match (%d, %d)\n",
                               retval, rc);
                offset += sizeof(*lov_id);
        }

        return rc;
}

/* FIXME: maybe we'll just make one node the authoritative attribute node, then
 * we can send this 'punch' to just the authoritative node and the nodes
 * that the punch will affect. */
static int lov_punch(struct lustre_handle *conn, struct obdo *oa,
                     obd_size count, obd_off offset)
{
        int rc, retval, i;
        ENTRY;

        if (!class_conn2export(conn))
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

struct lov_callback_data {
        atomic_t count;
        wait_queue_head waitq;
};

static void lov_read_callback(struct ptlrpc_bulk_desc *desc, void *data)
{
        struct lov_callback_data *cb_data = data;

        if (atomic_dec_and_test(&cb_data->count))
                wake_up(&cb_data->waitq);
}

static int lov_read_check_status(struct lov_callback_data *cb_data)
{
        ENTRY;
        if (sigismember(&(current->pending.signal), SIGKILL) ||
            sigismember(&(current->pending.signal), SIGTERM) ||
            sigismember(&(current->pending.signal), SIGINT)) {
                cb_data->flags |= PTL_RPC_FL_INTR;
                RETURN(1);
        }
        if (atomic_read(&cb_data->count) == 0)
                RETURN(1);
        RETURN(0);
}

/* buffer must lie in user memory here */
static int lov_brw(int cmd, struct lustre_handle *conn, obd_count num_oa,
                   struct obdo **oa,
                   obd_count *oa_bufs, struct page **buf,
                   obd_size *count, obd_off *offset, obd_flag *flags,
                   bulk_callback_t callback, void *data)
{
        int rc, i, page_array_offset = 0;
        obd_off off = offset;
        obd_size retval = 0;
        struct lov_callback_data *cb_data;
        ENTRY;

        if (num_oa != 1)
                LBUG();

        if (!class_conn2export(conn))
                RETURN(-EINVAL);

        OBD_ALLOC(cb_data, sizeof(*cb_data));
        if (cb_data == NULL) {
                LBUG();
                RETURN(-ENOMEM);
        }
        INIT_WAITQUEUE_HEAD(&cb_data->waitq);
        atomic_set(&cb_data->count, 0);

        for (i = 0; i < oa_bufs[0]; i++) {
                struct page *current_page = buf[i];

                struct lov_md *md = (struct lov_md *)oa[i]->inline;
                int bufcount = oa_bufs[i];
                // md->lmd_stripe_count

                for (k = page_array_offset; k < bufcount + page_array_offset;
                     k++) {
                        
                }
                page_array_offset += bufcount;


        while (off < offset + count) {
                int stripe, conn;
                obd_size size, tmp;

                stripe = off / conn->oc_dev->u.lov.lov_stripe_size;
                size = (stripe + 1) * conn->oc_dev->u.lov.lov_strip_size - off;
                if (size > *count)
                        size = *count;

                conn = stripe % conn->oc_dev->obd_multi_count;

                tmp = size;
                atomic_inc(&cb_data->count);
                rc = obd_brw(cmd, &conn->oc_dev->obd_multi_conn[conn],
                             num_oa, oa, buf,
                              &size, off, lov_read_callback, cb_data);
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

        wait_event_interruptible(&cb_data->waitq,
                                 lov_read_check_status(cb_data));
        if (cb_data->flags & PTL_RPC_FL_INTR)
                rc = -EINTR;

        /* FIXME: The error handling here sucks */
        *count = retval;
        OBD_FREE(cb_data, sizeof(*cb_data));
        RETURN(rc);
}

static void lov_write_finished(struct ptlrpc_bulk_desc *desc, void *data)
{
        
}

/* buffer must lie in user memory here */
static int filter_write(struct lustre_handle *conn, struct obdo *oa, char *buf,
                         obd_size *count, obd_off offset)
{
        int err;
        struct file *file;
        unsigned long retval;

        ENTRY;
        if (!class_conn2export(conn)) {
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

static int lov_enqueue(struct lustre_handle *conn, struct ldlm_namespace *ns,
                       struct ldlm_handle *parent_lock, __u64 *res_id,
                       __u32 type, struct ldlm_extent *extent, __u32 mode,
                       int *flags, void *data, int datalen,
                       struct ldlm_handle *lockh)
{
        int rc;
        ENTRY;

        if (!class_conn2export(conn))
                RETURN(-EINVAL);

        rc = obd_enqueue(&conn->oc_dev->obd_multi_conn[0], ns, parent_lock,
                         res_id, type, extent, mode, flags, data, datalen,
                         lockh);
        RETURN(rc);
}

static int lov_cancel(struct lustre_handle *conn, __u32 mode,
                      struct ldlm_handle *lockh)
{
        int rc;
        ENTRY;

        if (!class_conn2export(conn))
                RETURN(-EINVAL);

        rc = obd_cancel(&conn->oc_dev->obd_multi_conn[0], oa);
        RETURN(rc);
}
#endif

struct obd_ops lov_obd_ops = {
        o_setup:       class_multi_setup,
        o_cleanup:     class_multi_cleanup,
        o_create:      lov_create,
        o_connect:     lov_connect,
        o_disconnect:  lov_disconnect,
        o_getattr:     lov_getattr,
        o_setattr:     lov_setattr,
        o_open:        lov_open,
        o_close:       lov_close,
#if 0
        o_destroy:     lov_destroy,
        o_brw:         lov_pgcache_brw,
        o_punch:       lov_punch,
        o_enqueue:     lov_enqueue,
        o_cancel:      lov_cancel
#endif
};


#define LOV_VERSION "v0.1"

static int __init lov_init(void)
{
        printk(KERN_INFO "Lustre Logical Object Volume driver " LOV_VERSION
               ", phil@clusterfs.com\n");
        return class_register_type(&lov_obd_ops, OBD_LOV_DEVICENAME);
}

static void __exit lov_exit(void)
{
        class_unregister_type(OBD_LOV_DEVICENAME);
}

MODULE_AUTHOR("Phil Schwan <phil@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver v0.1");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
