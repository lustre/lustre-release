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
                lov->desc.ld_tgt_count * sizeof(struct lov_oinfo);
        return size;
}

static inline int lov_mds_md_size(struct obd_device *obd)
{
        struct lov_obd *lov = &obd->u.lov;
        int size;

        size = sizeof(struct lov_mds_md) +
                lov->desc.ld_tgt_count * sizeof(struct lov_object_id);
        return size;
}

/* the LOV counts on oa->o_id to be set as the LOV object id */
static int lov_create(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md **ea)
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

        oa->o_easize = lov_stripe_md_size(export->exp_obd);
        if (!*ea) {
                OBD_ALLOC(*ea, oa->o_easize);
                if (! *ea)
                        RETURN(-ENOMEM);
        }

        md = *ea;
        md->lmd_easize = lov_mds_md_size(export->exp_obd);
        md->lmd_object_id = oa->o_id;
        if (!md->lmd_stripe_count)
                md->lmd_stripe_count = lov->desc.ld_default_stripe_count;

        if (!md->lmd_stripe_size)
                md->lmd_stripe_size = lov->desc.ld_default_stripe_size;



        for (i = 0; i < md->lmd_stripe_count; i++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_easize = sizeof(struct lov_stripe_md);
                rc = obd_create(&lov->tgts[i].conn, &tmp, &obj_mdp);
                if (rc)
                        GOTO(out_cleanup, rc);
                md->lmd_oinfo[i].loi_id = tmp.o_id;
                md->lmd_oinfo[i].loi_size = tmp.o_size;
        }

 out_cleanup:
        if (rc) {
                int i2, rc2;
                for (i2 = 0; i2 < i; i2++) {
                        /* destroy already created objects here */
                        tmp.o_id = md->lmd_oinfo[i].loi_id;
                        rc2 = obd_destroy(&lov->tgts[i].conn, &tmp, NULL);
                        if (rc2)
                                CERROR("Failed to remove object from target "
                                       "%d\n", i2);
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
                CERROR("LOV requires striping ea for destruction\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = md->lmd_oinfo[i].loi_id;
                rc = obd_destroy(&lov->tgts[i].conn, &tmp, NULL);
                if (rc)
                        CERROR("Error destroying object %Ld on %d\n",
                               md->lmd_oinfo[i].loi_id, i);
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
        int set = 0;
        ENTRY;

        if (!md) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        oa->o_size = 0;
        oa->o_blocks = 0;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                int err;

                if (md->lmd_oinfo[i].loi_id == 0)
                        continue;

                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = md->lmd_oinfo[i].loi_id;

                err = obd_getattr(&lov->tgts[i].conn, &tmp, NULL);
                if (err) {
                        CERROR("Error getattr object %Ld on %d: err = %d\n",
                               md->lmd_oinfo[i].loi_id, i, err);
                        if (!rc)
                                rc = err;
                        continue; /* XXX or break? */
                }
                if (!set) {
                        obdo_cpy_md(oa, &tmp, tmp.o_valid);
                        set = 1;
                } else {
                        if (tmp.o_valid & OBD_MD_FLSIZE)
                                oa->o_size += tmp.o_size;
                        if (tmp.o_valid & OBD_MD_FLBLOCKS)
                                oa->o_blocks += tmp.o_blocks;
                        if (tmp.o_valid & OBD_MD_FLCTIME &&
                            oa->o_ctime < tmp.o_ctime)
                                oa->o_ctime = tmp.o_ctime;
                        if (tmp.o_valid & OBD_MD_FLMTIME &&
                            oa->o_mtime < tmp.o_mtime)
                                oa->o_mtime = tmp.o_mtime;
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
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = md->lmd_oinfo[i].loi_id;

                rc = obd_setattr(&lov->tgts[i].conn, &tmp, NULL);
                if (rc)
                        CERROR("Error setattr object %Ld on %d\n",
                               tmp.o_id, i);
        }
        RETURN(rc);
}

static int lov_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *md)
{
        int rc = 0, rc2 = 0, i;
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) {
                CERROR("LOV requires striping ea for opening\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = md->lmd_oinfo[i].loi_id;

                rc = obd_open(&lov->tgts[i].conn, &tmp, NULL);
                if (rc) {
                        rc2 = rc;
                        CERROR("Error open object %Ld on %d\n",
                               md->lmd_oinfo[i].loi_id, i);
                }
        }
        RETURN(rc2);
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
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = md->lmd_oinfo[i].loi_id;

                rc = obd_close(&lov->tgts[i].conn, &tmp, NULL);
                if (rc)
                        CERROR("Error close object %Ld on %d\n",
                               md->lmd_oinfo[i].loi_id, i);
        }
        RETURN(rc);
}

#ifndef log2
#define log2(n) ffz(~(n))
#endif

/* compute offset in stripe i corresponding to offset "in" */
__u64 lov_offset(struct lov_stripe_md *md, __u64 in, int i)
{
        __u32 ssz = md->lmd_stripe_size;
        /* full stripes across all * stripe size */
        __u32 out = ( ((__u32)in) / (md->lmd_stripe_count * ssz)) * ssz;
        __u32 off = (__u32)in % (md->lmd_stripe_count * ssz);

        if ( in == 0xffffffffffffffff ) {
                return 0xffffffffffffffff;
        }

        if ( (i+1) * ssz <= off )
                out += (i+1) * ssz;
        else if ( i * ssz > off )
                out += 0;
        else
                out += (off - (i * ssz)) % ssz;

        return (__u64) out;
}

/* compute offset in stripe i corresponding to offset "in" */
__u64 lov_stripe(struct lov_stripe_md *md, __u64 in, int *j)
{
        __u32 ssz = md->lmd_stripe_size;
        __u32 off, out;
        /* full stripes across all * stripe size */
        *j = (((__u32) in)/ssz) % md->lmd_stripe_count;
        off =  (__u32)in % (md->lmd_stripe_count * ssz);
        out = ( ((__u32)in) / (md->lmd_stripe_count * ssz)) * ssz +
                (off - ((*j) * ssz)) % ssz;;

        return (__u64) out;
}

int lov_stripe_which(struct lov_stripe_md *md, __u64 in)
{
        __u32 ssz = md->lmd_stripe_size;
        int j;
        j = (((__u32) in) / ssz) % md->lmd_stripe_count;
        return j;
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

                if (starti == endi)
                        continue;
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = md->lmd_oinfo[i].loi_id;

                rc = obd_punch(&lov->tgts[i].conn, &tmp, NULL,
                               starti, endi);
                if (rc)
                        CERROR("Error punch object %Ld on %d\n",
                               md->lmd_oinfo[i].loi_id, i);
        }
        RETURN(rc);
}

static int lov_osc_brw_callback(struct io_cb_data *cbd, int err, int phase)
{
        int ret = 0;
        ENTRY;

        if (phase == CB_PHASE_START)
                RETURN(0);

        if (phase == CB_PHASE_FINISH) {
                if (err)
                        cbd->err = err;
                if (atomic_dec_and_test(&cbd->refcount))
                        ret = cbd->cb(cbd->data, cbd->err, phase);
                RETURN(ret);
        }

        LBUG();
        return 0;
}

static inline int lov_brw(int cmd, struct lustre_handle *conn,
                          struct lov_stripe_md *md,
                          obd_count oa_bufs,
                          struct brw_page *pga,
                          brw_callback_t callback, struct io_cb_data *cbd)
{
        int stripe_count = md->lmd_stripe_count;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct {
                int bufct;
                int index;
                int subcount;
                struct lov_stripe_md md;
        } *stripeinfo;
        struct brw_page *ioarr;
        int rc, i;
        struct io_cb_data *our_cb;
        ENTRY;

        lov = &export->exp_obd->u.lov;

        our_cb = ll_init_cb();
        if (!our_cb)
                RETURN(-ENOMEM);

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                GOTO(out_cbdata, rc = -ENOMEM);

        OBD_ALLOC(ioarr, sizeof(*ioarr) * oa_bufs);
        if (!ioarr)
                GOTO(out_sinfo, rc = -ENOMEM);

        for (i = 0; i < oa_bufs; i++) {
                int which;
                which = lov_stripe_which(md, pga[i].off);
                stripeinfo[which].bufct++;
        }

        for (i = 0; i < stripe_count; i++) {
                if (i > 0)
                        stripeinfo[i].index = stripeinfo[i - 1].index +
                                stripeinfo[i - 1].bufct;
                stripeinfo[i].md.lmd_object_id = md->lmd_oinfo[i].loi_id;
        }

        for (i = 0; i < oa_bufs; i++) {
                int which, shift;
                which = lov_stripe_which(md, pga[i].off);

                shift = stripeinfo[which].index;
                LASSERT(shift + stripeinfo[which].subcount < oa_bufs);
                ioarr[shift + stripeinfo[which].subcount] = pga[i];
                ioarr[shift + stripeinfo[which].subcount].off =
                        lov_offset(md, pga[i].off, which);
                stripeinfo[which].subcount++;
        }

        our_cb->cb = callback;
        our_cb->data = cbd;

        /* This is the only race-free way I can think of to get the refcount
         * correct. -phil */
        atomic_set(&our_cb->refcount, 0);
        for (i = 0; i < stripe_count; i++)
                if (stripeinfo[i].bufct)
                        atomic_inc(&our_cb->refcount);

        for (i = 0; i < stripe_count; i++) {
                int shift = stripeinfo[i].index;
                if (stripeinfo[i].bufct) {
                        LASSERT(shift < oa_bufs);
                        obd_brw(cmd, &lov->tgts[i].conn, &stripeinfo[i].md,
                                stripeinfo[i].bufct, &ioarr[shift],
                                lov_osc_brw_callback, our_cb);
                }
        }

        rc = callback(cbd, 0, CB_PHASE_START);

        OBD_FREE(ioarr, sizeof(*ioarr) * oa_bufs);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
 out_cbdata:
        OBD_FREE(our_cb, sizeof(*our_cb));
        RETURN(rc);
}

static int lov_enqueue(struct lustre_handle *conn, struct lov_stripe_md *md,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *cookie, int cookielen, __u32 mode,
                       int *flags, void *cb, void *data, int datalen,
                       struct lustre_handle *lockhs)
{
        int rc = 0, i;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_stripe_md submd;
        ENTRY;

        if (!md) {
                CERROR("LOV requires striping ea for desctruction\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                struct ldlm_extent *extent = (struct ldlm_extent *)cookie;
                struct ldlm_extent sub_ext;

                sub_ext.start = lov_offset(md, extent->start, i);
                sub_ext.end = lov_offset(md, extent->end, i);
                if ( sub_ext.start == sub_ext.end )
                        continue;

                submd.lmd_object_id = md->lmd_oinfo[i].loi_id;
                submd.lmd_easize = sizeof(struct lov_mds_md);
                submd.lmd_stripe_count = md->lmd_stripe_count;
                /* XXX submd is not fully initialized here */
                rc = obd_enqueue(&(lov->tgts[i].conn), &submd, parent_lock,
                                 type, &sub_ext, sizeof(sub_ext), mode,
                                 flags, cb, data, datalen, &(lockhs[i]));
                // XXX add a lock debug statement here
                if (rc)
                        CERROR("Error obd_enqueue object %Ld subobj %Ld\n",
                               md->lmd_object_id, md->lmd_oinfo[i].loi_id);
        }
        RETURN(rc);
}

static int lov_cancel(struct lustre_handle *conn, struct lov_stripe_md *md,
                      __u32 mode, struct lustre_handle *lockhs)
{
        int rc = 0, i;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        ENTRY;

        if (!md) {
                CERROR("LOV requires striping ea for lock cancellation\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0; i < md->lmd_stripe_count; i++) {
                struct lov_stripe_md submd;

                if ( lockhs[i].addr == 0 )
                        continue;

                submd.lmd_object_id = md->lmd_oinfo[i].loi_id;
                submd.lmd_easize = sizeof(struct lov_mds_md);
                rc = obd_cancel(&lov->tgts[i].conn, &submd, mode, &lockhs[i]);
                if (rc)
                        CERROR("Error cancel object %Ld subobj %Ld\n",
                               md->lmd_object_id, md->lmd_oinfo[i].loi_id);
        }
        RETURN(rc);
}

static int lov_statfs(struct lustre_handle *conn, struct statfs *sfs)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct statfs lov_sfs;
        int set = 0;
        int rc = 0;
        int i;
        ENTRY;

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;

        /* We only get block data from the OBD */
        for (i = 0 ; i < lov->desc.ld_tgt_count; i++) {
                int err;

                err = obd_statfs(&lov->tgts[i].conn, &lov_sfs);
                if (err) {
                        CERROR("Error statfs OSC %s on %d: err = %d\n",
                               lov->tgts[i].uuid, i, err);
                        if (!rc)
                                rc = err;
                        continue; /* XXX or break? - probably OK to continue */
                }
                if (!set) {
                        memcpy(sfs, &lov_sfs, sizeof(lov_sfs));
                        set = 1;
                } else {
                        sfs->f_bfree += lov_sfs.f_bfree;
                        sfs->f_bavail += lov_sfs.f_bavail;
                        sfs->f_blocks += lov_sfs.f_blocks;
                        /* XXX not sure about this one - depends on policy.
                         *   - could be minimum if we always stripe on all OBDs
                         *     (but that would be wrong for any other policy,
                         *     if one of the OBDs has no more objects left)
                         *   - could be sum if we stripe whole objects
                         *   - could be average, just to give a nice number
                         *   - we just pick first OST and hope it is enough
                        sfs->f_ffree += lov_sfs.f_ffree;
                         */
                }
        }
        RETURN(rc);
}


struct obd_ops lov_obd_ops = {
        o_setup:       lov_setup,
        o_connect:     lov_connect,
        o_disconnect:  lov_disconnect,
        o_create:      lov_create,
        o_destroy:     lov_destroy,
        o_getattr:     lov_getattr,
        o_setattr:     lov_setattr,
        o_statfs:      lov_statfs,
        o_open:        lov_open,
        o_close:       lov_close,
        o_brw:         lov_brw,
        o_punch:       lov_punch,
        o_enqueue:     lov_enqueue,
        o_cancel:      lov_cancel
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
