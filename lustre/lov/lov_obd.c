 /* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
 * Author: Phil Schwan <phil@clusterfs.com>
 *         Peter Braam <braam@clusterfs.com>
 *         Mike Shaver <shaver@clusterfs.com>
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
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_LOV

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lite.h> /* for LL_IOC_LOV_[GS]ETSTRIPE */
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <asm/div64.h>
#include <linux/lprocfs_status.h>


static kmem_cache_t *lov_file_cache;

struct lov_file_handles {
        struct list_head lfh_list;
        __u64 lfh_cookie;
        int lfh_count;
        struct lustre_handle *lfh_handles;
};

struct lov_lock_handles {
        __u64 llh_cookie;
        struct lustre_handle llh_handles[0];
};

extern int lov_packmd(struct lustre_handle *conn, struct lov_mds_md **lmm,
                       struct lov_stripe_md *lsm);
extern int lov_unpackmd(struct lustre_handle *conn, struct lov_stripe_md **lsm,
                         struct lov_mds_md *lmm);
extern int lov_setstripe(struct lustre_handle *conn,
                         struct lov_stripe_md **lsmp, struct lov_mds_md *lmmu);
extern int lov_getstripe(struct lustre_handle *conn, struct lov_mds_md *lmmu,
                         struct lov_stripe_md *lsm);

/* obd methods */
int lov_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(&lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int lov_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static int lov_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct recovd_obd *recovd,
                       ptlrpc_recovery_cb_t recover)
{
        struct ptlrpc_request *req = NULL;
        struct lov_obd *lov = &obd->u.lov;
        struct client_obd *mdc = &lov->mdcobd->u.cli;
        struct lov_desc *desc = &lov->desc;
        struct obd_export *exp;
        struct lustre_handle mdc_conn;
        struct obd_uuid lov_mds_uuid = {"LOV_MDS_UUID"};
        struct obd_uuid uuid;
        char *tmp;
        int rc, rc2, i;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        /* We don't want to actually do the underlying connections more than
         * once, so keep track. */
        lov->refcount++;
        if (lov->refcount > 1)
                RETURN(0);

        exp = class_conn2export(conn);
        spin_lock_init(&exp->exp_lov_data.led_lock);
        INIT_LIST_HEAD(&exp->exp_lov_data.led_open_head);

        /* retrieve LOV metadata from MDS */
        rc = obd_connect(&mdc_conn, lov->mdcobd, &lov_mds_uuid, recovd,recover);
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

        if (req->rq_repmsg->buflens[1] < sizeof(uuid.uuid)*desc->ld_tgt_count){
                CERROR("LOV desc: invalid uuid array returned\n");
                GOTO(out_conn, rc = -EINVAL);
        }

        if (memcmp(obd->obd_uuid.uuid, desc->ld_uuid.uuid,
                   sizeof(desc->ld_uuid.uuid))) {
                CERROR("LOV desc: uuid %s not on mds device (%s)\n",
                       obd->obd_uuid.uuid, desc->ld_uuid.uuid);
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

        tmp = lustre_msg_buf(req->rq_repmsg, 1);
        for (i = 0; i < desc->ld_tgt_count; i++) {
                struct obd_device *tgt;
                struct obd_uuid lov_osc_uuid = { "LOV_OSC_UUID" };

                strncpy(uuid.uuid, tmp, sizeof(uuid.uuid));
                memcpy(&lov->tgts[i].uuid, &uuid, sizeof(uuid));
                tgt = client_tgtuuid2obd(&uuid);
                tmp += sizeof(uuid.uuid);

                if (!tgt) {
                        CERROR("Target %s not attached\n", uuid.uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                if (!(tgt->obd_flags & OBD_SET_UP)) {
                        CERROR("Target %s not set up\n", uuid.uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                rc = obd_connect(&lov->tgts[i].conn, tgt, &lov_osc_uuid, recovd,
                                 recover);

                if (rc) {
                        CERROR("Target %s connect error %d\n", uuid.uuid,
                               rc);
                        GOTO(out_disc, rc);
                }

                rc = obd_iocontrol(IOC_OSC_REGISTER_LOV, &lov->tgts[i].conn,
                                    sizeof(struct obd_device *), obd, NULL);
                if (rc) {
                        CERROR("Target %s REGISTER_LOV error %d\n",
                               uuid.uuid, rc);
                        GOTO(out_disc, rc);
                }

                desc->ld_active_tgt_count++;
                lov->tgts[i].active = 1;
        }

        mdc->cl_max_mds_easize = obd_size_wiremd(conn, NULL);

 out:
        ptlrpc_req_finished(req);
        RETURN(rc);

 out_disc:
        i--; /* skip failed-connect OSC */
        while (i-- > 0) {
                desc->ld_active_tgt_count--;
                lov->tgts[i].active = 0;
                memcpy(&uuid, &lov->tgts[i].uuid, sizeof(uuid));
                rc2 = obd_disconnect(&lov->tgts[i].conn);
                if (rc2)
                        CERROR("error: LOV target %s disconnect on OST idx %d: "
                               "rc = %d\n", uuid.uuid, i, rc2);
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
        struct obd_export *exp;
        struct list_head *p, *n;
        int rc, i;

        if (!lov->tgts)
                goto out_local;

        /* Only disconnect the underlying layers on the final disconnect. */
        lov->refcount--;
        if (lov->refcount != 0)
                goto out_local;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                rc = obd_disconnect(&lov->tgts[i].conn);
                if (rc) {
                        if (lov->tgts[i].active) {
                                CERROR("Target %s disconnect error %d\n",
                                       lov->tgts[i].uuid.uuid, rc);
                        }
                        rc = 0;
                }
                if (lov->tgts[i].active) {
                        lov->desc.ld_active_tgt_count--;
                        lov->tgts[i].active = 0;
                }
        }
        OBD_FREE(lov->tgts, lov->bufsize);
        lov->bufsize = 0;
        lov->tgts = NULL;

        exp = class_conn2export(conn);
        spin_lock(&exp->exp_lov_data.led_lock);
        list_for_each_safe(p, n, &exp->exp_lov_data.led_open_head) {
                /* XXX close these, instead of just discarding them? */
                struct lov_file_handles *lfh;
                lfh = list_entry(p, typeof(*lfh), lfh_list);
                CERROR("discarding open LOV handle %p:"LPX64"\n",
                       lfh, lfh->lfh_cookie);
                list_del(&lfh->lfh_list);
                OBD_FREE(lfh->lfh_handles,
                         lfh->lfh_count * sizeof(*lfh->lfh_handles));
                kmem_cache_free(lov_file_cache, lfh);
        }
        spin_unlock(&exp->exp_lov_data.led_lock);

 out_local:
        rc = class_disconnect(conn);
        return rc;
}

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LOV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD is the wrong type (!)
 *  -EALREADY: The OSC is already marked (in)active
 */
static int lov_set_osc_active(struct lov_obd *lov, struct obd_uuid *uuid,
                              int activate)
{
        struct obd_device *obd;
        struct lov_tgt_desc *tgt;
        int i, rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "Searching in lov %p for uuid %s (activate=%d)\n",
               lov, uuid->uuid, activate);

        spin_lock(&lov->lov_lock);
        for (i = 0, tgt = lov->tgts; i < lov->desc.ld_tgt_count; i++, tgt++) {
                CDEBUG(D_INFO, "lov idx %d is %s conn "LPX64"\n",
                       i, tgt->uuid.uuid, tgt->conn.addr);
                if (strncmp(uuid->uuid, tgt->uuid.uuid, sizeof(uuid->uuid)) == 0)
                        break;
        }

        if (i == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        obd = class_conn2obd(&tgt->conn);
        if (obd == NULL) {
                LBUG();
                GOTO(out, rc = -ENOTCONN);
        }

        CDEBUG(D_INFO, "Found OBD %s=%s device %d (%p) type %s at LOV idx %d\n",
               obd->obd_name, obd->obd_uuid.uuid, obd->obd_minor, obd,
               obd->obd_type->typ_name, i);
        if (strcmp(obd->obd_type->typ_name, "osc") != 0) {
                LBUG();
                GOTO(out, rc = -EBADF);
        }

        if (tgt->active == activate) {
                CDEBUG(D_INFO, "OBD %p already %sactive!\n", obd,
                       activate ? "" : "in");
                GOTO(out, rc = -EALREADY);
        }

        CDEBUG(D_INFO, "Marking OBD %p %sactive\n", obd, activate ? "" : "in");

        tgt->active = activate;
        if (activate) {
                /*
                 * foreach(export)
                 *     foreach(open_file)
                 *         if (file_handle uses this_osc)
                 *             if (has_no_filehandle)
                 *                 open(file_handle, this_osc);
                 */
                /* XXX reconnect? */
                lov->desc.ld_active_tgt_count++;
        } else {
                /*
                 * Should I invalidate filehandles that refer to this OSC, so
                 * that I reopen them during reactivation?
                 */
                /* XXX disconnect from OSC? */
                lov->desc.ld_active_tgt_count--;
        }

#warning "FIXME: walk open files list for objects that need opening"
        EXIT;
 out:
        spin_unlock(&lov->lov_lock);
        return rc;
}

static int lov_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data *data = buf;
        struct lov_obd *lov = &obd->u.lov;
        struct obd_uuid uuid;
        int rc = 0;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("LOV setup requires an MDC UUID\n");
                RETURN(-EINVAL);
        }

        if (data->ioc_inllen1 > 37) {
                CERROR("mdc UUID must be 36 characters or less\n");
                RETURN(-EINVAL);
        }

        spin_lock_init(&lov->lov_lock);
        obd_str2uuid(&uuid, data->ioc_inlbuf1);
        lov->mdcobd = class_uuid2obd(&uuid);
        if (!lov->mdcobd) {
                CERROR("LOV %s cannot locate MDC %s\n", obd->obd_uuid.uuid,
                       data->ioc_inlbuf1);
                rc = -EINVAL;
        }
        RETURN(rc);
}

static struct lov_file_handles *lov_handle2lfh(struct lustre_handle *handle)
{
        struct lov_file_handles *lfh = NULL;

        if (!handle || !handle->addr)
                RETURN(NULL);

        lfh = (struct lov_file_handles *)(unsigned long)(handle->addr);
        if (!kmem_cache_validate(lov_file_cache, lfh))
                RETURN(NULL);

        if (lfh->lfh_cookie != handle->cookie)
                RETURN(NULL);

        return lfh;
}

/* the LOV expects oa->o_id to be set to the LOV object id */
static int lov_create(struct lustre_handle *conn, struct obdo *oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi;
        struct obdo *tmp;
        int ost_count, ost_idx;
        int first = 1, obj_alloc = 0;
        int rc = 0, i;
        ENTRY;

        LASSERT(ea);

        if (!export)
                RETURN(-EINVAL);

        lov = &export->exp_obd->u.lov;

        if (!lov->desc.ld_active_tgt_count)
                RETURN(-EIO);

        tmp = obdo_alloc();
        if (!tmp)
                RETURN(-ENOMEM);

        lsm = *ea;

        if (!lsm) {
                rc = obd_alloc_memmd(conn, &lsm);
                if (rc < 0)
                        GOTO(out_tmp, rc);

                rc = 0;
                lsm->lsm_magic = LOV_MAGIC;
        }

        ost_count = lov->desc.ld_tgt_count;

        LASSERT(oa->o_valid & OBD_MD_FLID);
        lsm->lsm_object_id = oa->o_id;
        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;

        if (!*ea || lsm->lsm_stripe_offset >= ost_count) {
                int mult = lsm->lsm_object_id * lsm->lsm_stripe_count;
                int stripe_offset = mult % ost_count;
                int sub_offset = (mult / ost_count);

                ost_idx = (stripe_offset + sub_offset) % ost_count;
        } else
                ost_idx = lsm->lsm_stripe_offset;

        CDEBUG(D_INODE, "allocating %d subobjs for objid "LPX64" at idx %d\n",
               lsm->lsm_stripe_count, lsm->lsm_object_id, ost_idx);

        loi = lsm->lsm_oinfo;
        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
                int err;

                if (lov->tgts[ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost_idx);
                        continue;
                }

                /* create data objects with "parent" OA */
                memcpy(tmp, oa, sizeof(*tmp));
                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                err = obd_create(&lov->tgts[ost_idx].conn, tmp, &obj_mdp, oti);
                if (err) {
                        if (lov->tgts[ost_idx].active) {
                                CERROR("error creating objid "LPX64" sub-object"
                                       " on OST idx %d/%d: rc = %d\n", oa->o_id,
                                       ost_idx, lsm->lsm_stripe_count, err);
                                if (err > 0) {
                                        CERROR("obd_create returned invalid "
                                               "err %d\n", err);
                                        err = -EIO;
                                }
                                if (!rc)
                                        rc = err;
                        }
                        continue;
                }
                loi->loi_id = tmp->o_id;
                loi->loi_ost_idx = ost_idx;
                CDEBUG(D_INODE, "objid "LPX64" has subobj "LPX64" at idx %d\n",
                       lsm->lsm_object_id, loi->loi_id, ost_idx);

                if (first) {
                        lsm->lsm_stripe_offset = ost_idx;
                        first = 0;
                }

                ++obj_alloc;
                ++loi;

                /* If we have allocated enough objects, we are OK */
                if (obj_alloc == lsm->lsm_stripe_count) {
                        rc = 0;
                        GOTO(out_done, rc);
                }
        }

        if (*ea)
                GOTO(out_cleanup, rc);
        else {
                struct lov_stripe_md *lsm_new;
                /* XXX LOV STACKING call into osc for sizes */
                int size = lov_stripe_md_size(obj_alloc);

                OBD_ALLOC(lsm_new, size);
                if (!lsm_new)
                        GOTO(out_cleanup, rc = -ENOMEM);
                memcpy(lsm_new, lsm, size);
                /* XXX LOV STACKING call into osc for sizes */
                OBD_FREE(lsm, lov_stripe_md_size(lsm->lsm_stripe_count));
                lsm = lsm_new;
        }
 out_done:
        *ea = lsm;

 out_tmp:
        obdo_free(tmp);
        return rc;

 out_cleanup:
        while (obj_alloc-- > 0) {
                int err;

                --loi;
                /* destroy already created objects here */
                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_id = loi->loi_id;
                err = obd_destroy(&lov->tgts[loi->loi_ost_idx].conn, tmp, NULL, NULL);
                if (err)
                        CERROR("Failed to uncreate objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx,
                               err);
        }
        if (!*ea)
                obd_free_memmd(conn, &lsm);
        goto out_tmp;
}

static int lov_destroy(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea for destruction\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        /* Orphan clean up will (someday) fix this up. */
                        continue;
                }

                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;
                if (lfh)
                        memcpy(obdo_handle(&tmp), &lfh->lfh_handles[i],
                               sizeof(lfh->lfh_handles[i]));
                else
                        tmp.o_valid &= ~OBD_MD_FLHANDLE;
                err = obd_destroy(&lov->tgts[loi->loi_ost_idx].conn, &tmp,
                                  NULL, NULL);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: destroying objid "LPX64" subobj "
                               LPX64" on OST idx %d\n: rc = %d",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
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
                            struct lov_stripe_md *lsm, int stripeno, int *set)
{
        if (*set) {
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
        } else {
                obdo_cpy_md(tgt, src, valid);
                if (valid & OBD_MD_FLSIZE)
                        tgt->o_size = lov_stripe_size(lsm,src->o_size,stripeno);
                *set = 1;
        }
}

static int lov_getattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int i;
        int set = 0;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        lov = &export->exp_obd->u.lov;

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

        CDEBUG(D_INFO, "objid "LPX64": %ux%u byte stripes\n",
               lsm->lsm_object_id, lsm->lsm_stripe_count, lsm->lsm_stripe_size);
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oa->o_id, i, loi->loi_id, loi->loi_ost_idx);
                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;
                if (lfh)
                        memcpy(obdo_handle(&tmp), &lfh->lfh_handles[i],
                               sizeof(lfh->lfh_handles[i]));
                else
                        tmp.o_valid &= ~OBD_MD_FLHANDLE;

                err = obd_getattr(&lov->tgts[loi->loi_ost_idx].conn, &tmp,NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: getattr objid "LPX64" subobj "
                                       LPX64" on OST idx %d: rc = %d\n",
                                       oa->o_id, loi->loi_id, loi->loi_ost_idx,
                                       err);
                                RETURN(err);
                        }
                } else {
                        lov_merge_attrs(oa, &tmp, tmp.o_valid, lsm, i, &set);
                }
        }

        RETURN(set ? 0 : -EIO);
}

static int lov_setattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo *tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int rc = 0, i, set = 0;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        /* size changes should go through punch and not setattr */
        LASSERT(!(oa->o_valid & OBD_MD_FLSIZE));

        /* for now, we only expect mtime updates here */
        LASSERT(!(oa->o_valid & ~(OBD_MD_FLID |OBD_MD_FLTYPE |OBD_MD_FLMTIME)));

        tmp = obdo_alloc();
        if (!tmp)
                RETURN(-ENOMEM);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                obdo_cpy_md(tmp, oa, oa->o_valid);

                if (lfh)
                        memcpy(obdo_handle(tmp), &lfh->lfh_handles[i],
                               sizeof(lfh->lfh_handles[i]));
                else
                        tmp->o_valid &= ~OBD_MD_FLHANDLE;

                tmp->o_id = loi->loi_id;

                err = obd_setattr(&lov->tgts[loi->loi_ost_idx].conn, tmp,
                                  NULL, NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: setattr objid "LPX64" subobj "
                                       LPX64" on OST idx %d: rc = %d\n",
                                       oa->o_id, loi->loi_id, loi->loi_ost_idx,
                                       err);
                                if (!rc)
                                        rc = err;
                        }
                } else
                        set = 1;
        }
        obdo_free(tmp);
        if (!set && !rc)
                rc = -EIO;
        RETURN(rc);
}

static int lov_open(struct lustre_handle *conn, struct obdo *oa,
                    struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo *tmp; /* on the heap here, on the stack in lov_close? */
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        struct lustre_handle *handle;
        int set = 0;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea for opening\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        tmp = obdo_alloc();
        if (!tmp)
                RETURN(-ENOMEM);

        lfh = kmem_cache_alloc(lov_file_cache, GFP_KERNEL);
        if (!lfh)
                GOTO(out_tmp, rc = -ENOMEM);
        OBD_ALLOC(lfh->lfh_handles,
                  lsm->lsm_stripe_count * sizeof(*lfh->lfh_handles));
        if (!lfh->lfh_handles)
                GOTO(out_lfh, rc = -ENOMEM);

        lov = &export->exp_obd->u.lov;
        oa->o_size = 0;
        oa->o_blocks = 0;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                /* create data objects with "parent" OA */
                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_id = loi->loi_id;

                rc = obd_open(&lov->tgts[loi->loi_ost_idx].conn, tmp,
                              NULL, NULL);
                if (rc) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: open objid "LPX64" subobj "LPX64
                                       " on OST idx %d: rc = %d\n",
                                       oa->o_id, lsm->lsm_oinfo[i].loi_id,
                                       loi->loi_ost_idx, rc);
                                goto out_handles;
                        }
                        continue;
                }

                lov_merge_attrs(oa, tmp, tmp->o_valid, lsm, i, &set);

                if (tmp->o_valid & OBD_MD_FLHANDLE)
                        memcpy(&lfh->lfh_handles[i], obdo_handle(tmp),
                               sizeof(lfh->lfh_handles[i]));
        }

        handle = obdo_handle(oa);

        lfh->lfh_count = lsm->lsm_stripe_count;
        get_random_bytes(&lfh->lfh_cookie, sizeof(lfh->lfh_cookie));

        handle->addr = (__u64)(unsigned long)lfh;
        handle->cookie = lfh->lfh_cookie;
        oa->o_valid |= OBD_MD_FLHANDLE;
        spin_lock(&export->exp_lov_data.led_lock);
        list_add(&lfh->lfh_list, &export->exp_lov_data.led_open_head);
        spin_unlock(&export->exp_lov_data.led_lock);

        if (!set && !rc)
                rc = -EIO;
out_tmp:
        obdo_free(tmp);
        RETURN(rc);

out_handles:
        for (i--, loi = &lsm->lsm_oinfo[i]; i >= 0; i--, loi--) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        continue;

                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_id = loi->loi_id;
                memcpy(obdo_handle(tmp), &lfh->lfh_handles[i],
                       sizeof(lfh->lfh_handles[i]));

                err = obd_close(&lov->tgts[loi->loi_ost_idx].conn, tmp,
                                NULL, NULL);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: closing objid "LPX64" subobj "LPX64
                               " on OST idx %d after open error: rc=%d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                }
        }

        OBD_FREE(lfh->lfh_handles,
                 lsm->lsm_stripe_count * sizeof(*lfh->lfh_handles));
out_lfh:
        lfh->lfh_cookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(lov_file_cache, lfh);
        goto out_tmp;
}

static int lov_close(struct lustre_handle *conn, struct obdo *oa,
                     struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;
                if (lfh)
                        memcpy(obdo_handle(&tmp), &lfh->lfh_handles[i],
                               sizeof(lfh->lfh_handles[i]));
                else
                        tmp.o_valid &= ~OBD_MD_FLHANDLE;

                err = obd_close(&lov->tgts[loi->loi_ost_idx].conn, &tmp,
                                NULL, NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: close objid "LPX64" subobj "LPX64
                                       " on OST idx %d: rc = %d\n", oa->o_id,
                                       loi->loi_id, loi->loi_ost_idx, err);
                        }
                        if (!rc)
                                rc = err;
                }
        }
        if (lfh) {
                list_del(&lfh->lfh_list);
                OBD_FREE(lfh->lfh_handles,
                         lsm->lsm_stripe_count * sizeof(*lfh->lfh_handles));
                lfh->lfh_cookie = DEAD_HANDLE_MAGIC;
                kmem_cache_free(lov_file_cache, lfh);
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
                     obd_off start, obd_off end, struct obd_trans_info *oti)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

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
                if (lfh)
                        memcpy(obdo_handle(&tmp), &lfh->lfh_handles[i],
                               sizeof(lfh->lfh_handles[i]));
                else
                        tmp.o_valid &= ~OBD_MD_FLHANDLE;

                err = obd_punch(&lov->tgts[loi->loi_ost_idx].conn, &tmp, NULL,
                                starti, endi, NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: punch objid "LPX64" subobj "LPX64
                                       " on OST idx %d: rc = %d\n", oa->o_id,
                                       loi->loi_id, loi->loi_ost_idx, err);
                        }
                        if (!rc)
                                rc = err;
                }
        }
        RETURN(rc);
}

static inline int lov_brw(int cmd, struct lustre_handle *conn,
                          struct lov_stripe_md *lsm, obd_count oa_bufs,
                          struct brw_page *pga, struct obd_brw_set *set,
                          struct obd_trans_info *oti)
{
        struct {
                int bufct;
                int index;
                int subcount;
                struct lov_stripe_md lsm;
                int ost_idx;
        } *stripeinfo, *si, *si_last;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct brw_page *ioarr;
        struct lov_oinfo *loi;
        int rc = 0, i, *where, stripe_count = lsm->lsm_stripe_count;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        lov = &export->exp_obd->u.lov;

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                GOTO(out_cbdata, rc = -ENOMEM);

        OBD_ALLOC(where, sizeof(*where) * oa_bufs);
        if (!where)
                GOTO(out_sinfo, rc = -ENOMEM);

        OBD_ALLOC(ioarr, sizeof(*ioarr) * oa_bufs);
        if (!ioarr)
                GOTO(out_where, rc = -ENOMEM);

        for (i = 0; i < oa_bufs; i++) {
                where[i] = lov_stripe_number(lsm, pga[i].off);
                stripeinfo[where[i]].bufct++;
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
                        rc = obd_brw(cmd, &lov->tgts[si->ost_idx].conn,
                                     &si->lsm, si->bufct, &ioarr[shift],
                                     set, oti);
                        if (rc)
                                GOTO(out_ioarr, rc);
                }
        }

 out_ioarr:
        OBD_FREE(ioarr, sizeof(*ioarr) * oa_bufs);
 out_where:
        OBD_FREE(where, sizeof(*where) * oa_bufs);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
 out_cbdata:
        RETURN(rc);
}

static struct lov_lock_handles *lov_newlockh(struct lov_stripe_md *lsm)
{
        struct lov_lock_handles *lov_lockh;

        OBD_ALLOC(lov_lockh, sizeof(*lov_lockh) +
                  sizeof(*lov_lockh->llh_handles) * lsm->lsm_stripe_count);
        if (!lov_lockh)
                return NULL;

        get_random_bytes(&lov_lockh->llh_cookie, sizeof(lov_lockh->llh_cookie));

        return lov_lockh;
}

/* We are only ever passed local lock handles here, so we do not need to
 * validate (and we can't really because these structs are variable sized
 * and therefore alloced, and not from a private slab).
 *
 * We just check because we can...
 */
static struct lov_lock_handles *lov_h2lovlockh(struct lustre_handle *handle)
{
        struct lov_lock_handles *lov_lockh = NULL;

        if (!handle || !handle->addr)
                RETURN(NULL);

        lov_lockh = (struct lov_lock_handles *)(unsigned long)(handle->addr);
        if (lov_lockh->llh_cookie != handle->cookie)
                RETURN(NULL);

        return lov_lockh;
}

static int lov_enqueue(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *cookie, int cookielen, __u32 mode,
                       int *flags, void *cb, void *data, int datalen,
                       struct lustre_handle *lockh)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_stripe_md submd;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        /* we should never be asked to replay a lock. */

        LASSERT((*flags & LDLM_FL_REPLAY) == 0);

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_newlockh(lsm);
                if (!lov_lockh)
                        RETURN(-ENOMEM);

                lockh->addr = (__u64)(unsigned long)lov_lockh;
                lockh->cookie = lov_lockh->llh_cookie;
                lov_lockhp = lov_lockh->llh_handles;
        } else
                lov_lockhp = lockh;

        lov = &export->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                struct ldlm_extent *extent = (struct ldlm_extent *)cookie;
                struct ldlm_extent sub_ext;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                *flags = 0;
                sub_ext.start = lov_stripe_offset(lsm, extent->start, i);
                sub_ext.end = lov_stripe_offset(lsm, extent->end, i);
                if (sub_ext.start == sub_ext.end /* || !active */)
                        continue;

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                /* XXX submd is not fully initialized here */
                *flags = 0;
                rc = obd_enqueue(&(lov->tgts[loi->loi_ost_idx].conn), &submd,
                                 parent_lock, type, &sub_ext, sizeof(sub_ext),
                                 mode, flags, cb, data, datalen, lov_lockhp);
                // XXX add a lock debug statement here
                if (rc)
                        memset(lov_lockhp, 0, sizeof(*lov_lockhp));
                if (rc && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: enqueue objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, rc);
                        goto out_locks;
                }
        }
        RETURN(0);

out_locks:
        while (loi--, lov_lockhp--, i-- > 0) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->addr == 0 ||
                    lov->tgts[loi->loi_ost_idx].active == 0)
                        continue;

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel(&lov->tgts[loi->loi_ost_idx].conn, &submd,
                                 mode, lov_lockhp);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: cancelling objid "LPX64" on OST "
                               "idx %d after enqueue error: rc = %d\n",
                               loi->loi_id, loi->loi_ost_idx, err);
                }
        }

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh->llh_cookie = DEAD_HANDLE_MAGIC;
                OBD_FREE(lov_lockh, sizeof(*lov_lockh) +
                          sizeof(*lov_lockh->llh_handles) *
                          lsm->lsm_stripe_count);
        }
        lockh->addr = 0;
        lockh->cookie = DEAD_HANDLE_MAGIC;

        RETURN(rc);
}

static int lov_cancel(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                      __u32 mode, struct lustre_handle *lockh)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                RETURN(-EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                RETURN(-EINVAL);
        }

        if (!export || !export->exp_obd)
                RETURN(-ENODEV);

        LASSERT(lockh);
        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_h2lovlockh(lockh);
                if (!lov_lockh) {
                        CERROR("LOV: invalid lov lock handle %p\n", lockh);
                        RETURN(-EINVAL);
                }

                lov_lockhp = lov_lockh->llh_handles;
        } else
                lov_lockhp = lockh;

        lov = &export->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++ ) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->addr == 0) {
                        CDEBUG(D_HA, "lov idx %d no lock?\n", loi->loi_ost_idx);
                        continue;
                }

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel(&lov->tgts[loi->loi_ost_idx].conn, &submd,
                                 mode, lov_lockhp);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: cancel objid "LPX64" subobj "
                                       LPX64" on OST idx %d: rc = %d\n",
                                       lsm->lsm_object_id,
                                       loi->loi_id, loi->loi_ost_idx, err);
                                if (!rc)
                                        rc = err;
                        }
                }
        }

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh->llh_cookie = DEAD_HANDLE_MAGIC;
                OBD_FREE(lov_lockh, sizeof(*lov_lockh) +
                          sizeof(*lov_lockh->llh_handles) *
                          lsm->lsm_stripe_count);
        }
        lockh->addr = 0;
        lockh->cookie = DEAD_HANDLE_MAGIC;

        RETURN(rc);
}

static int lov_cancel_unused(struct lustre_handle *conn,
                             struct lov_stripe_md *lsm, int flags)
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
                int err;

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel_unused(&lov->tgts[loi->loi_ost_idx].conn,
                                       &submd, flags);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: cancel unused objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
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

                if (!lov->tgts[i].active) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", i);
                        continue;
                }

                err = obd_statfs(&lov->tgts[i].conn, &lov_sfs);
                if (err) {
                        if (lov->tgts[i].active) {
                                CERROR("error: statfs OSC %s on OST idx %d: "
                                       "err = %d\n",
                                       lov->tgts[i].uuid.uuid, i, err);
                                if (!rc)
                                        rc = err;
                        }
                        continue;
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
        if (!set && !rc)
                rc = -EIO;
        RETURN(rc);
}

static int lov_iocontrol(unsigned int cmd, struct lustre_handle *conn, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct lov_obd *lov = &obddev->u.lov;
        int i, count = lov->desc.ld_tgt_count;
        struct obd_uuid *uuidp;
        int rc;

        ENTRY;

        switch (cmd) {
        case IOC_LOV_SET_OSC_ACTIVE: {
                struct obd_ioctl_data *data = karg;
                uuidp = (struct obd_uuid *)data->ioc_inlbuf1;
                rc = lov_set_osc_active(lov, uuidp, data->ioc_offset);
                break;
        }
        case OBD_IOC_LOV_GET_CONFIG: {
                struct obd_ioctl_data *data = karg;
                struct lov_tgt_desc *tgtdesc;
                struct lov_desc *desc;
                char *buf = NULL;

                buf = NULL;
                len = 0;
                if (obd_ioctl_getdata(&buf, &len, (void *)uarg))
                        RETURN(-EINVAL);

                data = (struct obd_ioctl_data *)buf;

                if (sizeof(*desc) > data->ioc_inllen1) {
                        OBD_FREE(buf, len);
                        RETURN(-EINVAL);
                }

                if (sizeof(uuidp->uuid) * count > data->ioc_inllen2) {
                        OBD_FREE(buf, len);
                        RETURN(-EINVAL);
                }

                desc = (struct lov_desc *)data->ioc_inlbuf1;
                memcpy(desc, &(lov->desc), sizeof(*desc));

                uuidp = (struct obd_uuid *)data->ioc_inlbuf2;
                tgtdesc = lov->tgts;
                for (i = 0; i < count; i++, uuidp++, tgtdesc++)
                        obd_str2uuid(uuidp, tgtdesc->uuid.uuid);

                rc = copy_to_user((void *)uarg, buf, len);
                if (rc)
                        rc = -EFAULT;
                OBD_FREE(buf, len);
                break;
        }
        case LL_IOC_LOV_SETSTRIPE:
                rc = lov_setstripe(conn, karg, uarg);
                break;
        case LL_IOC_LOV_GETSTRIPE:
                rc = lov_getstripe(conn, karg, uarg);
                break;
        default: {
                int set = 0;
                if (count == 0)
                        RETURN(-ENOTTY);
                rc = 0;
                for (i = 0; i < count; i++) {
                        int err;

                        err = obd_iocontrol(cmd, &lov->tgts[i].conn,
                                            len, karg, uarg);
                        if (err) {
                                if (lov->tgts[i].active) {
                                        CERROR("error: iocontrol OSC %s on OST"
                                               "idx %d: err = %d\n",
                                               lov->tgts[i].uuid.uuid, i, err);
                                        if (!rc)
                                                rc = err;
                                }
                        } else
                                set = 1;
                }
                if (!set && !rc)
                        rc = -EIO;
        }
        }

        RETURN(rc);
}

struct obd_ops lov_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      lov_attach,
        o_detach:      lov_detach,
        o_setup:       lov_setup,
        o_connect:     lov_connect,
        o_disconnect:  lov_disconnect,
        o_statfs:      lov_statfs,
        o_packmd:      lov_packmd,
        o_unpackmd:    lov_unpackmd,
        o_create:      lov_create,
        o_destroy:     lov_destroy,
        o_getattr:     lov_getattr,
        o_setattr:     lov_setattr,
        o_open:        lov_open,
        o_close:       lov_close,
        o_brw:         lov_brw,
        o_punch:       lov_punch,
        o_enqueue:     lov_enqueue,
        o_cancel:      lov_cancel,
        o_cancel_unused: lov_cancel_unused,
        o_iocontrol:   lov_iocontrol
};

static int __init lov_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        printk(KERN_INFO "Lustre Logical Object Volume driver; "
               "info@clusterfs.com\n");
        lov_file_cache = kmem_cache_create("ll_lov_file_data",
                                           sizeof(struct lov_file_handles),
                                           0, 0, NULL, NULL);
        if (!lov_file_cache)
                RETURN(-ENOMEM);

        lprocfs_init_vars(&lvars);
        rc = class_register_type(&lov_obd_ops, lvars.module_vars,
                                 OBD_LOV_DEVICENAME);
        RETURN(rc);
}

static void __exit lov_exit(void)
{
        if (kmem_cache_destroy(lov_file_cache))
                CERROR("couldn't free LOV open cache\n");
        class_unregister_type(OBD_LOV_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
