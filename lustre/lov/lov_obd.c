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
#include <asm/div64.h>

/* obd methods */
static int lov_connect(struct lustre_handle *conn, struct obd_device *obd,
                       obd_uuid_t cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct ptlrpc_request *req = NULL;
        struct lov_obd *lov = &obd->u.lov;
        struct client_obd *mdc = &lov->mdcobd->u.cli;
        struct lov_desc *desc = &lov->desc;
        struct lustre_handle mdc_conn;
        obd_uuid_t *uuidarray;
        int rc, rc2, i;

        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd, cluuid);
        if (rc) {
                MOD_DEC_USE_COUNT;
                RETURN(rc);
        }

        /* We don't want to actually do the underlying connections more than
         * once, so keep track. */
        lov->refcount++;
        if (lov->refcount > 1)
                RETURN(0);

        /* retrieve LOV metadata from MDS */
        rc = obd_connect(&mdc_conn, lov->mdcobd, NULL, recovd, recover);
        if (rc) {
                CERROR("cannot connect to mdc: rc = %d\n", rc);
                GOTO(out_conn, rc);
        }

        rc = mdc_getlovinfo(obd, &mdc_conn, &req);
        rc2 = obd_disconnect(&mdc_conn);
        if (rc) {
                CERROR("cannot get lov info %d\n", rc);
                GOTO(out_conn, rc);
        }

        if (rc2) {
                CERROR("error disconnecting from MDS %d\n", rc2);
                GOTO(out_conn, rc = rc2);
        }

        /* sanity... */
        if (req->rq_repmsg->bufcount < 2 ||
            req->rq_repmsg->buflens[0] < sizeof(*desc)) {
                CERROR("LOV desc: invalid descriptor returned\n");
                GOTO(out_conn, rc = -EINVAL);
        }

        memcpy(desc, lustre_msg_buf(req->rq_repmsg, 0), sizeof(*desc));
        lov_unpackdesc(desc);

        if (req->rq_repmsg->buflens[1] < sizeof(*uuidarray)*desc->ld_tgt_count){
                CERROR("LOV desc: invalid uuid array returned\n");
                GOTO(out_conn, rc = -EINVAL);
        }

        mdc->cl_max_mds_easize = lov_mds_md_size(desc->ld_tgt_count);
        mdc->cl_max_ost_easize = lov_stripe_md_size(desc->ld_tgt_count);

        if (memcmp(obd->obd_uuid, desc->ld_uuid, sizeof(desc->ld_uuid))) {
                CERROR("LOV desc: uuid %s not on mds device (%s)\n",
                       obd->obd_uuid, desc->ld_uuid);
                GOTO(out_conn, rc = -EINVAL);
        }

        if (desc->ld_tgt_count > 1000) {
                CERROR("LOV desc: target count > 1000 (%d)\n",
                       desc->ld_tgt_count);
                GOTO(out_conn, rc = -EINVAL);
        }

        /* Because of 64-bit divide/mod operations only work with a 32-bit
         * divisor in a 32-bit kernel, we cannot support a stripe width
         * of 4GB or larger on 32-bit CPUs.
         */
        if ((desc->ld_default_stripe_count ?
             desc->ld_default_stripe_count : desc->ld_tgt_count) *
             desc->ld_default_stripe_size > ~0UL) {
                CERROR("LOV: stripe width "LPU64"x%u > %lu on 32-bit system\n",
                       desc->ld_default_stripe_size,
                       desc->ld_default_stripe_count ?
                       desc->ld_default_stripe_count : desc->ld_tgt_count,~0UL);
                GOTO(out_conn, rc = -EINVAL);
        }

        lov->bufsize = sizeof(struct lov_tgt_desc) * desc->ld_tgt_count;
        OBD_ALLOC(lov->tgts, lov->bufsize);
        if (!lov->tgts) {
                CERROR("Out of memory\n");
                GOTO(out_conn, rc = -ENOMEM);
        }

        uuidarray = lustre_msg_buf(req->rq_repmsg, 1);
        for (i = 0; i < desc->ld_tgt_count; i++)
                memcpy(lov->tgts[i].uuid, uuidarray[i], sizeof(*uuidarray));

        for (i = 0; i < desc->ld_tgt_count; i++) {
                struct obd_device *tgt = class_uuid2obd(uuidarray[i]);
                if (!tgt) {
                        CERROR("Target %s not attached\n", uuidarray[i]);
                        GOTO(out_disc, rc = -EINVAL);
                }
                if (!(tgt->obd_flags & OBD_SET_UP)) {
                        CERROR("Target %s not set up\n", uuidarray[i]);
                        GOTO(out_disc, rc = -EINVAL);
                }
                rc = obd_connect(&lov->tgts[i].conn, tgt, NULL, recovd,
                                 recover);
                if (rc) {
                        CERROR("Target %s connect error %d\n",
                               uuidarray[i], rc);
                        GOTO(out_disc, rc);
                }
                rc = obd_iocontrol(IOC_OSC_REGISTER_LOV, &lov->tgts[i].conn,
                                   sizeof(struct obd_device *), obd, NULL); 
                if (rc) {
                        CERROR("Target %s REGISTER_LOV error %d\n",
                               uuidarray[i], rc);
                        GOTO(out_disc, rc);
                }
                desc->ld_active_tgt_count++;
                lov->tgts[i].active = 1;
        }

 out:
        ptlrpc_req_finished(req);
        return rc;

 out_disc:
        while (i-- > 0) {
                desc->ld_active_tgt_count--;
                lov->tgts[i].active = 0;
                rc2 = obd_disconnect(&lov->tgts[i].conn);
                if (rc2)
                        CERROR("LOV Target %s disconnect error: rc = %d\n",
                                uuidarray[i], rc2);
        }
        OBD_FREE(lov->tgts, lov->bufsize);
 out_conn:
        class_disconnect(conn);
        goto out;
}

static int lov_disconnect(struct lustre_handle *conn)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        int rc, i;

        if (!lov->tgts)
                goto out_local;

        /* Only disconnect the underlying laters on the final disconnect. */
        lov->refcount--;
        if (lov->refcount != 0)
                goto out_local;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (!lov->tgts[i].active) {
                        CERROR("Skipping disconnect for inactive OSC %s\n",
                               lov->tgts[i].uuid);
                        continue;
                }

                lov->desc.ld_active_tgt_count--;
                lov->tgts[i].active = 0;
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

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LOV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD is the wrong type (!)
 *  -EALREADY: The OSC is already marked (in)active
 */
static int lov_set_osc_active(struct lov_obd *lov, obd_uuid_t uuid,
                              int activate)
{
        struct obd_device *obd;
        int i, rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "Searching in lov %p for uuid %s (activate=%d)\n",
               lov, uuid, activate);

        spin_lock(&lov->lov_lock);
        for (i = 0; i < lov->desc.ld_tgt_count; i++)
                if (strncmp(uuid, lov->tgts[i].uuid,
                            sizeof(lov->tgts[i].uuid)) == 0)
                        break;

        if (i == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        obd = class_conn2obd(&lov->tgts[i].conn);
        if (obd == NULL) {
                LBUG();
                GOTO(out, rc = -ENOTCONN);
        }

        CDEBUG(D_INFO, "Found OBD %p type %s\n", obd, obd->obd_type->typ_name);
        if (strcmp(obd->obd_type->typ_name, "osc") != 0) {
                LBUG();
                GOTO(out, rc = -EBADF);
        }

        if (lov->tgts[i].active == activate) {
                CDEBUG(D_INFO, "OBD %p already %sactive!\n", obd,
                       activate ? "" : "in");
                GOTO(out, rc = -EALREADY);
        }

        CDEBUG(D_INFO, "Marking OBD %p %sactive\n", obd, activate ? "" : "in");

        lov->tgts[i].active = activate;
        if (activate)
                lov->desc.ld_active_tgt_count++;
        else
                lov->desc.ld_active_tgt_count--;

        EXIT;
 out:
        spin_unlock(&lov->lov_lock);
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
                CERROR("mdc UUID must be 36 characters or less\n");
                RETURN(-EINVAL);
        }

        spin_lock_init(&lov->lov_lock);
        lov->mdcobd = class_uuid2obd(data->ioc_inlbuf1);
        if (!lov->mdcobd) {
                CERROR("LOV %s cannot locate MDC %s\n", obd->obd_uuid,
                       data->ioc_inlbuf1);
                rc = -EINVAL;
        }
        RETURN(rc);
}


/* the LOV expects oa->o_id to be set to the LOV object id */
static int lov_create(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md **ea)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi;
        struct obdo *tmp;
        int ost_count, ost_idx = 1, i, rc = 0;
        ENTRY;

        LASSERT(ea);

        if (!export)
                RETURN(-EINVAL);

        tmp = obdo_alloc();
        if (!tmp)
                RETURN(-ENOMEM);

        lov = &export->exp_obd->u.lov;

        spin_lock(&lov->lov_lock);
        ost_count = lov->desc.ld_tgt_count;
        oa->o_easize = lov_stripe_md_size(ost_count);

        lsm = *ea;
        if (!lsm) {
                OBD_ALLOC(lsm, oa->o_easize);
                if (!lsm) {
                        spin_unlock(&lov->lov_lock);
                        GOTO(out_tmp, rc = -ENOMEM);
                }
                lsm->lsm_magic = LOV_MAGIC;
                lsm->lsm_mds_easize = lov_mds_md_size(ost_count);
                ost_idx = 0; /* if lsm->lsm_stripe_offset is set yet */
        }

        LASSERT(oa->o_valid & OBD_MD_FLID);
        lsm->lsm_object_id = oa->o_id;
        if (!lsm->lsm_stripe_count)
                lsm->lsm_stripe_count = lov->desc.ld_default_stripe_count;
        if (!lsm->lsm_stripe_count)
                lsm->lsm_stripe_count = lov->desc.ld_active_tgt_count;
        else if (lsm->lsm_stripe_count > lov->desc.ld_active_tgt_count)
                lsm->lsm_stripe_count = lov->desc.ld_active_tgt_count;

        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;

        /* Because of 64-bit divide/mod operations only work with a 32-bit
         * divisor in a 32-bit kernel, we cannot support a stripe width
         * of 4GB or larger on 32-bit CPUs.
         */
        if (lsm->lsm_stripe_size * lsm->lsm_stripe_count > ~0UL) {
                CERROR("LOV: stripe width "LPU64"x%u > %lu on 32-bit system\n",
                       lsm->lsm_stripe_size, lsm->lsm_stripe_count, ~0UL);
                spin_unlock(&lov->lov_lock);
                GOTO(out_free, rc = -EINVAL);
        }

        lsm->lsm_ost_count = ost_count;
        if (!ost_idx || lsm->lsm_stripe_offset >= ost_count) {
                int mult = lsm->lsm_object_id * lsm->lsm_stripe_count;
                int stripe_offset = mult % ost_count;
                int sub_offset = (mult / ost_count) % lsm->lsm_stripe_count;

                lsm->lsm_stripe_offset = stripe_offset + sub_offset;
        }

        while (!lov->tgts[lsm->lsm_stripe_offset].active)
                lsm->lsm_stripe_offset = (lsm->lsm_stripe_offset+1) % ost_count;

        /* Pick the OSTs before we release the lock */
        ost_idx = lsm->lsm_stripe_offset;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                CDEBUG(D_INODE, "objid "LPX64"[%d] is ost_idx %d (uuid %s)\n",
                       lsm->lsm_object_id, i, ost_idx, lov->tgts[ost_idx].uuid);
                loi->loi_ost_idx = ost_idx;
                do {
                        ost_idx = (ost_idx + 1) % ost_count;
                } while (!lov->tgts[ost_idx].active);
        }

        spin_unlock(&lov->lov_lock);

        CDEBUG(D_INODE, "allocating %d subobjs for objid "LPX64" at idx %d\n",
               lsm->lsm_stripe_count,lsm->lsm_object_id,lsm->lsm_stripe_offset);

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;

                ost_idx = loi->loi_ost_idx;

                /* create data objects with "parent" OA */
                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_easize = sizeof(struct lov_stripe_md);
                rc = obd_create(&lov->tgts[ost_idx].conn, tmp, &obj_mdp);
                if (rc) {
                        CERROR("error creating objid "LPX64" sub-object on "
                               "OST idx %d: rc = %d\n", oa->o_id, ost_idx, rc);
                        GOTO(out_cleanup, rc);
                }
                loi->loi_id = tmp->o_id;
                loi->loi_size = tmp->o_size;
                CDEBUG(D_INODE, "objid "LPX64" has subobj "LPX64" at idx %d\n",
                       lsm->lsm_object_id, loi->loi_id, ost_idx);
        }

        *ea = lsm;

 out_tmp:
        obdo_free(tmp);
        return rc;

 out_cleanup:
        while (i-- > 0) {
                int err;

                --loi;
                /* destroy already created objects here */
                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_id = loi->loi_id;
                err = obd_destroy(&lov->tgts[loi->loi_ost_idx].conn, tmp, NULL);
                if (err)
                        CERROR("Failed to uncreate objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx,
                               err);
        }
 out_free:
        OBD_FREE(lsm, oa->o_easize);
        goto out_tmp;
}

static int lov_destroy(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea for destruction\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;
                rc = obd_destroy(&lov->tgts[loi->loi_ost_idx].conn, &tmp, NULL);
                if (rc)
                        CERROR("Error destroying objid "LPX64" subobj "LPX64
                               " on OST idx %d\n: rc = %d",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, rc);
        }
        RETURN(rc);
}

/* compute object size given "stripeno" and the ost size */
static obd_size lov_stripe_size(struct lov_stripe_md *lsm, obd_size ost_size,
                                int stripeno)
{
        unsigned long ssize  = lsm->lsm_stripe_size;
        unsigned long swidth = ssize * lsm->lsm_stripe_count;
        unsigned long stripe_size;
        obd_size lov_size;

        if (ost_size == 0)
                return 0;

        /* do_div(a, b) returns a % b, and a = a / b */
        stripe_size = do_div(ost_size, ssize);

        if (stripe_size)
                lov_size = ost_size * swidth + stripeno * ssize + stripe_size;
        else
                lov_size = (ost_size - 1) * swidth + (stripeno + 1) * ssize;

        return lov_size;
}

static void lov_merge_attrs(struct obdo *tgt, struct obdo *src, obd_flag valid,
                            struct lov_stripe_md *lsm, int stripeno, int *new)
{
        if (*new) {
                obdo_cpy_md(tgt, src, valid);
                if (valid & OBD_MD_FLSIZE)
                        tgt->o_size = lov_stripe_size(lsm,src->o_size,stripeno);
                *new = 0;
        } else {
                if (valid & OBD_MD_FLSIZE) {
                        /* this handles sparse files properly */
                        obd_size lov_size;

                        lov_size = lov_stripe_size(lsm, src->o_size, stripeno);
                        if (lov_size > tgt->o_size)
                                tgt->o_size = lov_size;
                }
                if (valid & OBD_MD_FLBLOCKS)
                        tgt->o_blocks += src->o_blocks;
                if (valid & OBD_MD_FLCTIME && tgt->o_ctime < src->o_ctime)
                        tgt->o_ctime = src->o_ctime;
                if (valid & OBD_MD_FLMTIME && tgt->o_mtime < src->o_mtime)
                        tgt->o_mtime = src->o_mtime;
        }
}

static int lov_getattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        int new = 1;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        oa->o_size = 0;
        oa->o_blocks = 0;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (loi->loi_id == 0)
                        continue;

                CERROR("objid "LPX64"[%d] has subobj "LPX64" at idx %u\n",
                       oa->o_id, i, loi->loi_id, loi->loi_ost_idx);
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;

                err = obd_getattr(&lov->tgts[loi->loi_ost_idx].conn, &tmp,NULL);
                if (err) {
                        CERROR("Error getattr objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                        continue; /* XXX or break? */
                }
                lov_merge_attrs(oa, &tmp, tmp.o_valid, lsm, i, &new);
        }
        RETURN(rc);
}

static int lov_setattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        /* Note that this code is currently unused, hence LBUG(), just
         * to know when/if it is ever revived that it needs cleanups.
         */
        LBUG();

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        /* size changes should go through punch and not setattr */
        LASSERT(!(oa->o_valid & OBD_MD_FLSIZE));

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;

                err = obd_setattr(&lov->tgts[loi->loi_ost_idx].conn, &tmp,NULL);
                if (err) {
                        CERROR("Error setattr objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        RETURN(rc);
}

static int lov_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *lsm)
{
        struct obdo *tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int new = 1;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea for opening\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        tmp = obdo_alloc();
        if (!tmp)
                RETURN(-ENOMEM);

        lov = &export->exp_obd->u.lov;
        oa->o_size = 0;
        oa->o_blocks = 0;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                /* create data objects with "parent" OA */
                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_id = loi->loi_id;

                err = obd_open(&lov->tgts[loi->loi_ost_idx].conn, tmp, NULL);
                if (err) {
                        CERROR("Error open objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               oa->o_id, lsm->lsm_oinfo[i].loi_id,
                               loi->loi_ost_idx, rc);
                        if (!rc)
                                rc = err;
                }

                lov_merge_attrs(oa, tmp, tmp->o_valid, lsm, i, &new);
        }
        /* FIXME: returning an error, but having opened some objects is a bad
         *        idea, since they will likely never be closed.  We either
         *        need to not return an error if _some_ objects could be
         *        opened, and leave it to read/write to return -EIO (with
         *        hopefully partial error status) or close all opened objects
         *        and return an error.  I think the former is preferred.
         */
        obdo_free(tmp);
        RETURN(rc);
}

static int lov_close(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;

                err = obd_close(&lov->tgts[loi->loi_ost_idx].conn, &tmp, NULL);
                if (err) {
                        CERROR("Error close objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        RETURN(rc);
}

#ifndef log2
#define log2(n) ffz(~(n))
#endif

#warning FIXME: merge these two functions now that they are nearly the same

/* compute ost offset in stripe "stripeno" corresponding to offset "lov_off" */
static obd_off lov_stripe_offset(struct lov_stripe_md *lsm, obd_off lov_off,
                                 int stripeno)
{
        unsigned long ssize  = lsm->lsm_stripe_size;
        unsigned long swidth = ssize * lsm->lsm_stripe_count;
        unsigned long stripe_off, this_stripe;

        if (lov_off == OBD_OBJECT_EOF || lov_off == 0)
                return lov_off;

        /* do_div(a, b) returns a % b, and a = a / b */
        stripe_off = do_div(lov_off, swidth);

        this_stripe = stripeno * ssize;
        if (stripe_off <= this_stripe)
                stripe_off = 0;
        else {
                stripe_off -= this_stripe;

                if (stripe_off > ssize)
                        stripe_off = ssize;
        }


        return lov_off * ssize + stripe_off;
}

/* compute which stripe number "lov_off" will be written into */
static int lov_stripe_number(struct lov_stripe_md *lsm, obd_off lov_off)
{
        unsigned long ssize  = lsm->lsm_stripe_size;
        unsigned long swidth = ssize * lsm->lsm_stripe_count;
        unsigned long stripe_off;

        stripe_off = do_div(lov_off, swidth);

        return stripe_off / ssize;
}


/* FIXME: maybe we'll just make one node the authoritative attribute node, then
 * we can send this 'punch' to just the authoritative node and the nodes
 * that the punch will affect. */
static int lov_punch(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *lsm,
                     obd_off start, obd_off end)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                obd_off starti = lov_stripe_offset(lsm, start, i);
                obd_off endi = lov_stripe_offset(lsm, end, i);
                int err;

                if (starti == endi)
                        continue;
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;

                err = obd_punch(&lov->tgts[loi->loi_ost_idx].conn, &tmp, NULL,
                                starti, endi);
                if (err) {
                        CERROR("Error punch objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
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
                          struct lov_stripe_md *lsm, obd_count oa_bufs,
                          struct brw_page *pga,
                          brw_callback_t callback, struct io_cb_data *cbd)
{
        int stripe_count = lsm->lsm_stripe_count;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct {
                int bufct;
                int index;
                int subcount;
                struct lov_stripe_md lsm;
                int ost_idx;
        } *stripeinfo, *si, *si_last;
        struct brw_page *ioarr;
        int rc, i;
        struct io_cb_data *our_cb;
        struct lov_oinfo *loi;
        int *where;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        lov = &export->exp_obd->u.lov;

        our_cb = ll_init_cb();
        if (!our_cb)
                RETURN(-ENOMEM);

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                GOTO(out_cbdata, rc = -ENOMEM);

        OBD_ALLOC(where, sizeof(*where) * oa_bufs);
        if (!where)
                GOTO(out_sinfo, rc = -ENOMEM);

        OBD_ALLOC(ioarr, sizeof(*ioarr) * oa_bufs);
        if (!ioarr)
                GOTO(out_where, rc = -ENOMEM);

        /* This is the only race-free way I can think of to get the refcount
         * correct. -phil */
        atomic_set(&our_cb->refcount, 0);
        our_cb->cb = callback;
        our_cb->data = cbd;

        for (i = 0; i < oa_bufs; i++) {
                where[i] = lov_stripe_number(lsm, pga[i].off);
                if (stripeinfo[where[i]].bufct++ == 0)
                        atomic_inc(&our_cb->refcount);
        }

        for (i = 0, loi = lsm->lsm_oinfo, si_last = si = stripeinfo;
             i < stripe_count; i++, loi++, si_last = si, si++) {
                if (i > 0)
                        si->index = si_last->index + si_last->bufct;
                si->lsm.lsm_object_id = loi->loi_id;
                si->ost_idx = loi->loi_ost_idx;
        }

        for (i = 0; i < oa_bufs; i++) {
                int which = where[i];
                int shift;

                shift = stripeinfo[which].index + stripeinfo[which].subcount;
                LASSERT(shift < oa_bufs);
                ioarr[shift] = pga[i];
                ioarr[shift].off = lov_stripe_offset(lsm, pga[i].off, which);
                stripeinfo[which].subcount++;
        }

        for (i = 0, si = stripeinfo; i < stripe_count; i++, si++) {
                int shift = si->index;

                if (si->bufct) {
                        LASSERT(shift < oa_bufs);
                        /* XXX handle error returns here */
                        obd_brw(cmd, &lov->tgts[si->ost_idx].conn,
                                &si->lsm, si->bufct, &ioarr[shift],
                                lov_osc_brw_callback, our_cb);
                }
        }

        rc = callback(cbd, 0, CB_PHASE_START);

        OBD_FREE(ioarr, sizeof(*ioarr) * oa_bufs);
 out_where:
        OBD_FREE(where, sizeof(*where) * oa_bufs);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
 out_cbdata:
        OBD_FREE(our_cb, sizeof(*our_cb));
        RETURN(rc);
}

static int lov_enqueue(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *cookie, int cookielen, __u32 mode,
                       int *flags, void *cb, void *data, int datalen,
                       struct lustre_handle *lockhs)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct ldlm_extent *extent = (struct ldlm_extent *)cookie;
                struct ldlm_extent sub_ext;
                struct lov_stripe_md submd;

                sub_ext.start = lov_stripe_offset(lsm, extent->start, i);
                sub_ext.end = lov_stripe_offset(lsm, extent->end, i);
                if (sub_ext.start == sub_ext.end)
                        continue;

                submd.lsm_object_id = loi->loi_id;
                /* XXX submd lsm_mds_easize should be that from the subobj,
                 *     and the subobj should get it opaquely from the LOV.
                 */
                submd.lsm_mds_easize = lov_mds_md_size(lsm->lsm_ost_count);
                submd.lsm_stripe_count = 0;
                /* XXX submd is not fully initialized here */
                rc = obd_enqueue(&(lov->tgts[loi->loi_ost_idx].conn), &submd,
                                 parent_lock, type, &sub_ext, sizeof(sub_ext),
                                 mode, flags, cb, data, datalen, &(lockhs[i]));
                // XXX add a lock debug statement here
                if (rc)
                        CERROR("Error enqueue objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, rc);
        }
        RETURN(rc);
}

static int lov_cancel(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                      __u32 mode, struct lustre_handle *lockhs)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#lx != %#lx\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;

                if (lockhs[i].addr == 0)
                        continue;

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_mds_easize = lov_mds_md_size(lsm->lsm_ost_count);
                submd.lsm_stripe_count = 0;
                rc = obd_cancel(&lov->tgts[loi->loi_ost_idx].conn, &submd,
                                mode, &lockhs[i]);
                if (rc)
                        CERROR("Error cancel objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, rc);
        }
        RETURN(rc);
}

static int lov_cancel_unused(struct lustre_handle *conn,
                             struct lov_stripe_md *lsm, int local_only)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea for lock cancellation\n");
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_mds_easize = lov_mds_md_size(lsm->lsm_ost_count);
                submd.lsm_stripe_count = 0;
                rc = obd_cancel_unused(&lov->tgts[loi->loi_ost_idx].conn,
                                       &submd, local_only);
                if (rc)
                        CERROR("Error cancel unused objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, rc);
        }
        RETURN(rc);
}

static int lov_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct obd_statfs lov_sfs;
        int set = 0;
        int rc = 0;
        int i;
        ENTRY;

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;

        /* We only get block data from the OBD */
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int err;

                err = obd_statfs(&lov->tgts[i].conn, &lov_sfs);
                if (err) {
                        CERROR("Error statfs OSC %s idx %d: err = %d\n",
                               lov->tgts[i].uuid, i, err);
                        if (!rc)
                                rc = err;
                        continue; /* XXX or break? - probably OK to continue */
                }
                if (!set) {
                        memcpy(osfs, &lov_sfs, sizeof(lov_sfs));
                        set = 1;
                } else {
                        osfs->os_bfree += lov_sfs.os_bfree;
                        osfs->os_bavail += lov_sfs.os_bavail;
                        osfs->os_blocks += lov_sfs.os_blocks;
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

static int lov_iocontrol(long cmd, struct lustre_handle *conn, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct obd_ioctl_data *data = karg;
        struct lov_obd *lov = &obddev->u.lov;
        int rc, i;
        ENTRY;

        switch (cmd) {
        case IOC_LOV_SET_OSC_ACTIVE:
                rc = lov_set_osc_active(lov,data->ioc_inlbuf1,data->ioc_offset);
                break;
        default:
                if (lov->desc.ld_tgt_count == 0)
                        RETURN(-ENOTTY);
                rc = 0;
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        int err = obd_iocontrol(cmd, &lov->tgts[i].conn,
                                                len, data, NULL);
                        if (err && !rc)
                                rc = err;
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
        o_cancel:      lov_cancel,
        o_cancel_unused: lov_cancel_unused,
        o_iocontrol:   lov_iocontrol
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
