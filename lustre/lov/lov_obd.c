/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lov/lov.c
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@off.net>
 *         Peter Braam <braam@clusterfs.com>
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
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/init.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];

/* obd methods */
static int lov_connect(struct lustre_handle *conn, struct obd_device *obd,
                       char *cluuid)
{
        struct ptlrpc_request *req;
        struct lov_obd *lov = &obd->u.lov;
        struct lustre_handle mdc_conn;
        uuid_t *uuidarray;
        int rc, rc2;
        int i;

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd, cluuid);
        if (rc) {
                MOD_DEC_USE_COUNT;
                RETURN(rc);
        }

        /* retrieve LOV metadata from MDS */
        rc = obd_connect(&mdc_conn, lov->mdcobd, NULL);
        if (rc) {
                CERROR("cannot connect to mdc: rc = %d\n", rc);
                GOTO(out, rc = -EINVAL);
        }

        rc = mdc_getlovinfo(obd, &mdc_conn, &uuidarray, &req);
        rc2 = obd_disconnect(&mdc_conn);
        if (rc || rc2) {
                CERROR("cannot get lov info or disconnect %d/%d\n", rc, rc2);
                GOTO(out, (rc) ? rc : rc2 );
        }

        /* sanity... */
        if (strcmp(obd->obd_uuid, lov->desc.ld_uuid)) {
                CERROR("lov uuid %s not on mds device (%s)\n",
                       obd->obd_uuid, lov->desc.ld_uuid);
                GOTO(out, rc = -EINVAL);
        }
        if (lov->desc.ld_tgt_count > 1000) {
                CERROR("configuration error: target count > 1000 (%d)\n",
                       lov->desc.ld_tgt_count);
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
        for (i = 0 ; i < lov->desc.ld_tgt_count; i++)
                memcpy(lov->tgts[i].uuid, uuidarray[i], sizeof(uuid_t));

        for (i = 0 ; i < lov->desc.ld_tgt_count; i++) {
                struct obd_device *tgt = class_uuid2obd(uuidarray[i]);
                if (!tgt) {
                        CERROR("Target %s not attached\n", uuidarray[i]);
                        GOTO(out_mem, rc = -EINVAL);
                }
                if (!(tgt->obd_flags & OBD_SET_UP)) {
                        CERROR("Target %s not set up\n", uuidarray[i]);
                        GOTO(out_mem, rc = -EINVAL);
                }            
                rc = obd_connect(&lov->tgts[i].conn, tgt, NULL);
                if (rc) {
                        CERROR("Target %s connect error %d\n",
                               uuidarray[i], rc);
                        GOTO(out_mem, rc);
                }
        }

 out_mem:
        if (rc) {
                for (i = 0 ; i < lov->desc.ld_tgt_count; i++) {
                        rc2 = obd_disconnect(&lov->tgts[i].conn);
                        if (rc2)
                                CERROR("BAD: Target %s disconnect error %d\n",
                                       uuidarray[i], rc2);
                }
                OBD_FREE(lov->tgts, lov->bufsize);
        }
 out:
        if (rc)
                class_disconnect(conn);
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

/* the LOV counts on oa->o_id to be set as the LOV object id */
static int lov_create(struct lustre_handle *conn, struct obdo *oa, struct lov_stripe_md **ea)
{
        int rc = 0, i;
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
        lov = &export->exp_obd->u.lov;

        oa->o_easize =  lov_stripe_md_size(export->exp_obd);
        if (!*ea) {
                OBD_ALLOC(*ea, oa->o_easize);
                if (! *ea)
                        RETURN(-ENOMEM);
        }

        md = *ea;
        md->lmd_easize = oa->o_easize;
        md->lmd_object_id = oa->o_id;
        if (!md->lmd_stripe_count) { 
                md->lmd_stripe_count = lov->desc.ld_default_stripe_count;
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
                       struct lov_stripe_md *md)
{
        int rc = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->exp_obd) 
                RETURN(-ENODEV); 

        lov = &export->exp_obd->u.lov;
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

static int lov_getattr(struct lustre_handle *conn, struct obdo *oa, 
                       struct lov_stripe_md *md)
{
        int rc = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->exp_obd) 
                RETURN(-ENODEV); 

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                oa->o_id = md->lmd_objects[i].l_object_id; 

                rc = obd_getattr(&lov->tgts[i].conn, &tmp, NULL);
                if (!rc) { 
                        CERROR("Error getattr object %Ld on %d\n",
                               oa->o_id, i); 
                }
                /* XXX can do something more sophisticated here... */
                if (i == 0 ) {
                        obd_id id = oa->o_id;
                        memcpy(oa, &tmp, sizeof(tmp));
                        oa->o_id = id;
                }
        }
        RETURN(rc);
}

static int lov_setattr(struct lustre_handle *conn, struct obdo *oa, 
                       struct lov_stripe_md *md)
{
        int rc = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->exp_obd) 
                RETURN(-ENODEV); 

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                oa->o_id = md->lmd_objects[i].l_object_id; 

                rc = obd_setattr(&lov->tgts[i].conn, &tmp, NULL);
                if (!rc) { 
                        CERROR("Error setattr object %Ld on %d\n",
                               oa->o_id, i); 
                }
        }
        RETURN(rc);
}

static int lov_open(struct lustre_handle *conn, struct obdo *oa, 
                    struct lov_stripe_md *md)
{
        int rc = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->exp_obd) 
                RETURN(-ENODEV); 

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                oa->o_id = md->lmd_objects[i].l_object_id; 

                rc = obd_open(&lov->tgts[i].conn, &tmp, NULL);
                if (!rc) { 
                        CERROR("Error getattr object %Ld on %d\n",
                               oa->o_id, i); 
                }
        }
        RETURN(rc);
}


static int lov_close(struct lustre_handle *conn, struct obdo *oa, 
                     struct lov_stripe_md *md)
{
        int rc = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->exp_obd) 
                RETURN(-ENODEV); 

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                oa->o_id = md->lmd_objects[i].l_object_id; 

                rc = obd_close(&lov->tgts[i].conn, &tmp, NULL);
                if (!rc) { 
                        CERROR("Error getattr object %Ld on %d\n",
                               oa->o_id, i); 
                }
        }
        RETURN(rc);
}

/* compute offset in stripe i corresponds to offset "in" */
__u64 lov_offset(struct lov_stripe_md *md, __u64 in, int i)
{
        __u32 ssz = md->lmd_stripe_size;
        /* full stripes across all * stripe size */
        __u32 out = ( ((__u32)in) / (md->lmd_stripe_count * ssz)) * ssz;
        __u32 off = (__u32)in % (md->lmd_stripe_count * ssz);

        if ( in == 0xffffffffffffffff ) {
                return 0xffffffffffffffff;
        }

        if ( (i+1) * ssz < off ) 
                out += ssz;
        else if ( i * ssz > off ) 
                out += 0;
        else 
                out += (off - (i * ssz)) % ssz;
        
        return (__u64) out;
}


struct lov_callback_data {
        atomic_t count;
        wait_queue_head_t waitq;
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
                // FIXME XXX what here 
                // cb_data->flags |= PTL_RPC_FL_INTR;
                RETURN(1);
        }
        if (atomic_read(&cb_data->count) == 0)
                RETURN(1);
        RETURN(0);
}


/* FIXME: maybe we'll just make one node the authoritative attribute node, then
 * we can send this 'punch' to just the authoritative node and the nodes
 * that the punch will affect. */
static int lov_punch(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *md, 
                     obd_off start, obd_off end)
{
        int rc = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) { 
                CERROR("LOV requires striping ea for desctruction\n"); 
                RETURN(-EINVAL); 
        }

        if (!export || !export->exp_obd) 
                RETURN(-ENODEV); 

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                __u64 starti = lov_offset(md, start, i); 
                __u64 endi = lov_offset(md, end, i); 
                        
                /* create data objects with "parent" OA */ 
                memcpy(&tmp, oa, sizeof(tmp));
                oa->o_id = md->lmd_objects[i].l_object_id; 

                rc = obd_punch(&lov->tgts[i].conn, &tmp, NULL,
                               starti, endi);
                if (!rc) { 
                        CERROR("Error punch object %Ld on %d\n",
                               oa->o_id, i); 
                }
        }
        RETURN(rc);
}


#if 0
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
        o_getattr:     lov_getattr,
        o_setattr:     lov_setattr,
        o_open:        lov_open,
        o_close:       lov_close,
#if 0
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
