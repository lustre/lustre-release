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

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];

/* obd methods */

static int lov_getinfo(struct obd_device *obd, 
                       struct lov_desc *desc, 
                       uuid_t **uuids, 
                       struct ptlrpc_request **request)
{
        struct ptlrpc_request *req;
        struct mds_status_req *streq;
        struct lov_obd *lov = &obd->u.lov; 
        struct mdc_obd *mdc = &lov->mdcobd->u.mdc;
        int rc, size[2] = {sizeof(*streq)};
        ENTRY;

        req = ptlrpc_prep_req2(mdc->mdc_client, mdc->mdc_conn, &mdc->mdc_connh,
                               MDS_LOVINFO, 1, size, NULL);
        if (!req)
                GOTO(out, rc = -ENOMEM);
        
        *request = req;
        streq = lustre_msg_buf(req->rq_reqmsg, 0);
        streq->flags = HTON__u32(MDS_STATUS_LOV);
        streq->repbuf = HTON__u32(8000);
        
        /* prepare for reply */ 
        req->rq_level = LUSTRE_CONN_CON;
        size[0] = sizeof(*desc); 
        size[1] = 8000; 
        req->rq_replen = lustre_msg_size(2, size);
        
        rc = ptlrpc_queue_wait(req);
        rc = ptlrpc_check_status(req, rc);

        if (!rc) {
                memcpy(desc, lustre_msg_buf(req->rq_repmsg, 0), sizeof(*desc));
                *uuids = lustre_msg_buf(req->rq_repmsg, 1);
                lov_unpackdesc(desc); 
        }
        mdc->mdc_max_mdsize = sizeof(*desc) + 
                desc->ld_tgt_count * sizeof(uuid_t);

        EXIT;
 out:
        return rc;
}

static int lov_connect(struct lustre_handle *conn, struct obd_device *obd)
{
        int rc;
        int i;
        struct ptlrpc_request *req;
        struct lov_obd *lov = &obd->u.lov;
        uuid_t *uuidarray; 

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd);
        if (rc) { 
                MOD_DEC_USE_COUNT;
                RETURN(rc); 
        }
        
        rc = lov_getinfo(obd, &lov->desc, &uuidarray, &req);
        if (rc) { 
                CERROR("cannot get lov info %d\n", rc);
                GOTO(out, rc); 
        }
        
        if (lov->desc.ld_tgt_count > 1000) { 
                CERROR("configuration error: target count > 1000 (%d)\n",
                       lov->desc.ld_tgt_count);
                GOTO(out, rc = -EINVAL); 
        }
        
        if (strcmp(obd->obd_uuid, lov->desc.ld_uuid)) { 
                CERROR("lov uuid %s not on mds device (%s)\n", 
                       obd->obd_uuid, lov->desc.ld_uuid);
                GOTO(out, rc = -EINVAL); 
        }                
            
        if (req->rq_repmsg->bufcount < 2 || req->rq_repmsg->buflens[1] < 
            sizeof(uuid_t) * lov->desc.ld_tgt_count) { 
                CERROR("invalid uuid array returned\n");
                GOTO(out, rc = -EINVAL); 
        }

        lov->bufsize = sizeof(struct lov_tgt_desc) *  lov->desc.ld_tgt_count; 
        OBD_ALLOC(lov->tgts, lov->bufsize); 
        if (!lov->tgts) { 
                CERROR("Out of memory\n"); 
                GOTO(out, rc = -ENOMEM); 
        }

        uuidarray = lustre_msg_buf(req->rq_repmsg, 1); 
        for (i = 0 ; i < lov->desc.ld_tgt_count; i++) { 
                memcpy(lov->tgts[i].uuid, uuidarray[i], sizeof(uuid_t)); 
        }

        for (i = 0 ; i < lov->desc.ld_tgt_count; i++) { 
                struct obd_device *tgt = class_uuid2obd(uuidarray[i]);
                if (!tgt) { 
                        CERROR("Target %s not configured\n", uuidarray[i]); 
                        GOTO(out_mem, rc = -EINVAL); 
                }
                rc = obd_connect(&lov->tgts[i].conn, tgt); 
                if (rc) { 
                        CERROR("Target %s connect error %d\n", 
                               uuidarray[i], rc); 
                        GOTO(out_mem, rc);
                }
        }

 out_mem:
        if (rc) { 
                for (i = 0 ; i < lov->desc.ld_tgt_count; i++) { 
                        int rc2;
                        rc2 = obd_disconnect(&lov->tgts[i].conn);
                        if (rc2)
                                CERROR("BAD: Target %s disconnect error %d\n", 
                                       uuidarray[i], rc2); 
                }
                OBD_FREE(lov->tgts, lov->bufsize);
        }
 out:
        if (rc) { 
                class_disconnect(conn);
        }
        if (req)
                ptlrpc_free_req(req); 
        return rc;
        
}

static int lov_disconnect(struct lustre_handle *conn)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        int rc;
        int i; 

        if (!lov->tgts)
                goto out_local;

        for (i = 0 ; i < lov->desc.ld_tgt_count; i++) { 
                rc = obd_disconnect(&lov->tgts[i].conn);
                if (rc) { 
                        CERROR("Target %s disconnect error %d\n", 
                               lov->tgts[i].uuid, rc); 
                        RETURN(rc);
                }
        }
        OBD_FREE(lov->tgts, lov->bufsize);
        lov->bufsize = 0;
        lov->tgts = NULL; 

 out_local:

        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int lov_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct lov_obd *lov = &obd->u.lov;
        int rc = 0;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("osc setup requires an MDC UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("mdc UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        /* FIXME: we should make a connection instead perhaps to avoid
           the mdc from walking away? The fs guarantees this. */ 
        lov->mdcobd = class_uuid2obd(data->ioc_inlbuf1); 
        if (!lov->mdcobd) { 
                CERROR("LOV %s cannot locate MDC %s\n", obd->obd_uuid, 
                       data->ioc_inlbuf1); 
                rc = -EINVAL;
        }
        RETURN(rc); 
} 


static inline int lov_stripe_md_size(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;
        int size;

        size = sizeof(struct lov_stripe_md) + 
                lov->desc.ld_tgt_count * sizeof(struct lov_object_id); 
        return size;
}

static int lov_create(struct lustre_handle *conn, struct obdo *oa, struct lov_stripe_md **ea)
{
        int rc, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_stripe_md *md;
        ENTRY;

        if (!ea) { 
                CERROR("lov_create needs EA for striping information\n"); 
                RETURN(-EINVAL); 
        }

        if (!export)
                RETURN(-EINVAL);
        lov = &export->export_obd->u.lov;

        oa->o_easize =  lov_stripe_md_size(export->export_obd); 
        if (! *ea) { 
                OBD_ALLOC(*ea, oa->o_easize); 
                if (! *ea) 
                        RETURN(-ENOMEM); 
        }

        md = *ea; 
        md->lmd_size = oa->o_easize;
        md->lmd_object_id = oa->o_id;
        if (!md->lmd_stripe_count) { 
                md->lmd_stripe_count = lov->desc.ld_default_stripecount;
        }

        for (i = 0; i < md->lmd_stripe_count; i++) {
                struct lov_stripe_md obj_md; 
                struct lov_stripe_md *obj_mdp = &obj_md; 
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_easize = sizeof(struct lov_stripe_md);
                rc = obd_create(&lov->tgts[i].conn, &tmp, &obj_mdp);
                if (rc) 
                        GOTO(out_cleanup, rc); 
                md->lmd_objects[i].l_object_id = tmp.o_id;
        }

 out_cleanup: 
        if (rc) { 
                int i2, rc2;
                for (i2 = 0 ; i2 < i ; i2++) { 
                        /* destroy already created objects here */ 
                        tmp.o_id = md->lmd_objects[i].l_object_id;
                        rc2 = obd_destroy(&lov->tgts[i].conn, &tmp, NULL);
                        if (rc2) { 
                                CERROR("Failed to remove object from target %d\n", 
                                       i2); 
                        }
                }
        }
        return rc;
}

static int lov_destroy(struct lustre_handle *conn, struct obdo *oa, 
struct lov_stripe_md *ea)
{
        int rc, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_stripe_md *md;
        ENTRY;

        if (!ea) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->export_obd) 
                RETURN(-ENODEV); 

        lov = &export->export_obd->u.lov;
        md = ea;

        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                oa->o_id = md->lmd_objects[i].l_object_id; 
                rc = obd_destroy(&lov->tgts[i].conn, &tmp, NULL);
                if (!rc) { 
                        CERROR("Error destroying object %Ld on %d\n",
                               oa->o_id, i); 
                }
        }
        RETURN(rc);
}

#if 0
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

        wait_event(&cb_data->waitq, lov_read_check_status(cb_data));
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
        o_setup:       lov_setup,
        o_connect:     lov_connect,
        o_disconnect:  lov_disconnect,
        o_create:      lov_create,
        o_destroy:     lov_destroy,
#if 0
        o_getattr:     lov_getattr,
        o_setattr:     lov_setattr,
        o_open:        lov_open,
        o_close:       lov_close,
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
               ", info@clusterfs.com\n");
        return class_register_type(&lov_obd_ops, OBD_LOV_DEVICENAME);
}

static void __exit lov_exit(void)
{
        class_unregister_type(OBD_LOV_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver v0.1");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
