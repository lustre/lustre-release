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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LOV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/seq_file.h>
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/obd_ost.h>
#include <linux/lprocfs_status.h>

#include "lov_internal.h"

static int lov_stripe_offset(struct lov_stripe_md *lsm, obd_off lov_off,
                             int stripeno, obd_off *obd_off);

struct lov_lock_handles {
        struct portals_handle llh_handle;
        atomic_t llh_refcount;
        int llh_stripe_count;
        struct lustre_handle llh_handles[0];
};

static void lov_llh_addref(void *llhp)
{
        struct lov_lock_handles *llh = llhp;

        atomic_inc(&llh->llh_refcount);
        CDEBUG(D_INFO, "GETting llh %p : new refcount %d\n", llh,
               atomic_read(&llh->llh_refcount));
}

static struct lov_lock_handles *lov_llh_new(struct lov_stripe_md *lsm)
{
        struct lov_lock_handles *llh;

        OBD_ALLOC(llh, sizeof *llh +
                  sizeof(*llh->llh_handles) * lsm->lsm_stripe_count);
        if (llh == NULL) {
                CERROR("out of memory\n");
                return NULL;
        }
        atomic_set(&llh->llh_refcount, 2);
        llh->llh_stripe_count = lsm->lsm_stripe_count;
        INIT_LIST_HEAD(&llh->llh_handle.h_link);
        class_handle_hash(&llh->llh_handle, lov_llh_addref);
        return llh;
}

static struct lov_lock_handles *lov_handle2llh(struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

static void lov_llh_put(struct lov_lock_handles *llh)
{
        CDEBUG(D_INFO, "PUTting llh %p : new refcount %d\n", llh,
               atomic_read(&llh->llh_refcount) - 1);
        LASSERT(atomic_read(&llh->llh_refcount) > 0 &&
                atomic_read(&llh->llh_refcount) < 0x5a5a);
        if (atomic_dec_and_test(&llh->llh_refcount)) {
                LASSERT(list_empty(&llh->llh_handle.h_link));
                OBD_FREE(llh, sizeof *llh +
                         sizeof(*llh->llh_handles) * llh->llh_stripe_count);
        }
}

static void lov_llh_destroy(struct lov_lock_handles *llh)
{
        class_handle_unhash(&llh->llh_handle);
        lov_llh_put(llh);
}

/* obd methods */
int lov_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc;

        lprocfs_init_vars(lov, &lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc == 0) {
#ifdef __KERNEL__
                struct proc_dir_entry *entry;

                entry = create_proc_entry("target_obd", 0444, 
                                          dev->obd_proc_entry);
                if (entry == NULL) {
                        rc = -ENOMEM;
                } else {
                        entry->proc_fops = &lov_proc_target_fops;
                        entry->data = dev;
                }
#endif
        }
        return rc;
}

int lov_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static int lov_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid)
{
        struct ptlrpc_request *req = NULL;
        struct lov_obd *lov = &obd->u.lov;
        struct lov_desc *desc = &lov->desc;
        struct lov_tgt_desc *tgts;
        struct obd_export *exp;
        int rc, rc2, i;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        exp = class_conn2export(conn);

        /* We don't want to actually do the underlying connections more than
         * once, so keep track. */
        lov->refcount++;
        if (lov->refcount > 1) {
                class_export_put(exp);
                RETURN(0);
        }

        for (i = 0, tgts = lov->tgts; i < desc->ld_tgt_count; i++, tgts++) {
                struct obd_uuid *tgt_uuid = &tgts->uuid;
                struct obd_device *tgt_obd;
                struct obd_uuid lov_osc_uuid = { "LOV_OSC_UUID" };
                struct lustre_handle conn = {0, };

                LASSERT( tgt_uuid != NULL);

                tgt_obd = class_find_client_obd(tgt_uuid, LUSTRE_OSC_NAME, 
                                                &obd->obd_uuid);

                if (!tgt_obd) {
                        CERROR("Target %s not attached\n", tgt_uuid->uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                if (!tgt_obd->obd_set_up) {
                        CERROR("Target %s not set up\n", tgt_uuid->uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                if (tgt_obd->u.cli.cl_import->imp_invalid) {
                        CERROR("not connecting OSC %s; administratively "
                               "disabled\n", tgt_uuid->uuid);
                        rc = obd_register_observer(tgt_obd, obd);
                        if (rc) {
                                CERROR("Target %s register_observer error %d; "
                                       "will not be able to reactivate\n",
                                       tgt_uuid->uuid, rc);
                        }
                        continue;
                }

                rc = obd_connect(&conn, tgt_obd, &lov_osc_uuid);
                if (rc) {
                        CERROR("Target %s connect error %d\n", tgt_uuid->uuid,
                               rc);
                        GOTO(out_disc, rc);
                }
                tgts->ltd_exp = class_conn2export(&conn);

                rc = obd_register_observer(tgt_obd, obd);
                if (rc) {
                        CERROR("Target %s register_observer error %d\n",
                               tgt_uuid->uuid, rc);
                        obd_disconnect(tgts->ltd_exp, 0);
                        GOTO(out_disc, rc);
                }

                desc->ld_active_tgt_count++;
                tgts->active = 1;
        }

        ptlrpc_req_finished(req);
        class_export_put(exp);
        RETURN (0);

 out_disc:
        while (i-- > 0) {
                struct obd_uuid uuid;
                --tgts;
                --desc->ld_active_tgt_count;
                tgts->active = 0;
                /* save for CERROR below; (we know it's terminated) */
                uuid = tgts->uuid;
                rc2 = obd_disconnect(tgts->ltd_exp, 0);
                if (rc2)
                        CERROR("error: LOV target %s disconnect on OST idx %d: "
                               "rc = %d\n", uuid.uuid, i, rc2);
        }
        class_disconnect(exp, 0);
        RETURN (rc);
}

static int lov_disconnect(struct obd_export *exp, int flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lov_obd *lov = &obd->u.lov;
        int rc, i;
        ENTRY;

        if (!lov->tgts)
                goto out_local;

        /* Only disconnect the underlying layers on the final disconnect. */
        lov->refcount--;
        if (lov->refcount != 0)
                goto out_local;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (lov->tgts[i].ltd_exp == NULL)
                        continue;

                if (obd->obd_no_recov) {
                        /* Pass it on to our clients.
                         * XXX This should be an argument to disconnect,
                         * XXX not a back-door flag on the OBD.  Ah well.
                         */
                        struct obd_device *osc_obd;
                        osc_obd = class_exp2obd(lov->tgts[i].ltd_exp);
                        if (osc_obd)
                                osc_obd->obd_no_recov = 1;
                }

                obd_register_observer(lov->tgts[i].ltd_exp->exp_obd, NULL);

                rc = obd_disconnect(lov->tgts[i].ltd_exp, flags);
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
                lov->tgts[i].ltd_exp = NULL;
        }

 out_local:
        rc = class_disconnect(exp, 0);
        RETURN(rc);
}

/* Error codes:
 *
 *  -EINVAL  : UUID can't be found in the LOV's target list
 *  -ENOTCONN: The UUID is found, but the target connection is bad (!)
 *  -EBADF   : The UUID is found, but the OBD is the wrong type (!)
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
                       i, tgt->uuid.uuid, tgt->ltd_exp->exp_handle.h_cookie);
                if (strncmp(uuid->uuid, tgt->uuid.uuid, sizeof uuid->uuid) == 0)
                        break;
        }

        if (i == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        obd = class_exp2obd(tgt->ltd_exp);
        if (obd == NULL) {
                /* This can happen if OST failure races with node shutdown */
                GOTO(out, rc = -ENOTCONN);
        }

        CDEBUG(D_INFO, "Found OBD %s=%s device %d (%p) type %s at LOV idx %d\n",
               obd->obd_name, obd->obd_uuid.uuid, obd->obd_minor, obd,
               obd->obd_type->typ_name, i);
        LASSERT(strcmp(obd->obd_type->typ_name, "osc") == 0);

        if (tgt->active == activate) {
                CDEBUG(D_INFO, "OBD %p already %sactive!\n", obd,
                       activate ? "" : "in");
                GOTO(out, rc);
        }

        CDEBUG(D_INFO, "Marking OBD %p %sactive\n", obd, activate ? "" : "in");

        tgt->active = activate;
        if (activate)
                lov->desc.ld_active_tgt_count++;
        else
                lov->desc.ld_active_tgt_count--;

        EXIT;
 out:
        spin_unlock(&lov->lov_lock);
        return rc;
}

static int lov_notify(struct obd_device *obd, struct obd_device *watched,
                       int active)
{
        int rc;
        struct obd_uuid *uuid;

        if (strcmp(watched->obd_type->typ_name, "osc")) {
                CERROR("unexpected notification of %s %s!\n",
                       watched->obd_type->typ_name,
                       watched->obd_name);
                return -EINVAL;
        }
        uuid = &watched->u.cli.cl_import->imp_target_uuid;

        /*
         * Must notify (MDS) before we mark the OSC as active, so that
         * the orphan deletion happens without interference from racing
         * creates.
         */
        if (obd->obd_observer) {
                /* Pass the notification up the chain. */
                rc = obd_notify(obd->obd_observer, watched, active);
                if (rc)
                        RETURN(rc);
        }

        rc = lov_set_osc_active(&obd->u.lov, uuid, active);

        if (rc) {
                CERROR("%sactivation of %s failed: %d\n",
                       active ? "" : "de", uuid->uuid, rc);
        }
        RETURN(rc);
}

static int lov_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lov_desc *desc;
        struct lov_obd *lov = &obd->u.lov;
        struct obd_uuid *uuids;
        struct lov_tgt_desc *tgts;
        int i;
        int count;
        int rc = 0;
        ENTRY;

        if (lcfg->lcfg_inllen1 < 1) {
                CERROR("LOV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen2 < 1) {
                CERROR("LOV setup requires an OST UUID list\n");
                RETURN(-EINVAL);
        }

        desc = (struct lov_desc *)lcfg->lcfg_inlbuf1;
        if (sizeof(*desc) > lcfg->lcfg_inllen1) {
                CERROR("descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), lcfg->lcfg_inllen1);
                RETURN(-EINVAL);
        }

        count = desc->ld_tgt_count;
        uuids = (struct obd_uuid *)lcfg->lcfg_inlbuf2;
        if (sizeof(*uuids) * count != lcfg->lcfg_inllen2) {
                CERROR("UUID array size wrong: %u * %u != %u\n",
                       (int)sizeof(*uuids), count, lcfg->lcfg_inllen2);
                RETURN(-EINVAL);
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
                RETURN(-EINVAL);
        }

        lov->bufsize = sizeof(struct lov_tgt_desc) * count;
        OBD_ALLOC(lov->tgts, lov->bufsize);
        if (lov->tgts == NULL) {
                CERROR("Out of memory\n");
                RETURN(-EINVAL);
        }

        lov->desc = *desc;
        spin_lock_init(&lov->lov_lock);

        for (i = 0, tgts = lov->tgts; i < desc->ld_tgt_count; i++, tgts++) {
                struct obd_uuid *uuid = &tgts->uuid;

                /* NULL termination already checked */
                *uuid = uuids[i];
        }


        RETURN(rc);
}

static int lov_cleanup(struct obd_device *obd, int flags) 
{
        struct lov_obd *lov = &obd->u.lov;

        OBD_FREE(lov->tgts, lov->bufsize);
        RETURN(0);
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
        valid &= src->o_valid;

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
                if (valid & OBD_MD_FLBLKSZ)
                        tgt->o_blksize += src->o_blksize;
                if (valid & OBD_MD_FLCTIME && tgt->o_ctime < src->o_ctime)
                        tgt->o_ctime = src->o_ctime;
                if (valid & OBD_MD_FLMTIME && tgt->o_mtime < src->o_mtime)
                        tgt->o_mtime = src->o_mtime;
        } else {
                memcpy(tgt, src, sizeof(*tgt));
                tgt->o_id = lsm->lsm_object_id;
                if (valid & OBD_MD_FLSIZE)
                        tgt->o_size = lov_stripe_size(lsm,src->o_size,stripeno);
                *set = 1;
        }
}

#ifndef log2
#define log2(n) ffz(~(n))
#endif

static int lov_clear_orphans(struct obd_export *export, struct obdo *src_oa,
                             struct lov_stripe_md **ea,
                             struct obd_trans_info *oti)
{
        struct lov_obd *lov;
        struct obdo *tmp_oa;
        struct obd_uuid *ost_uuid = NULL;
        int rc = 0, i;
        ENTRY;

        LASSERT(src_oa->o_valid & OBD_MD_FLFLAGS &&
                src_oa->o_flags == OBD_FL_DELORPHAN);

        lov = &export->exp_obd->u.lov;

        tmp_oa = obdo_alloc();
        if (tmp_oa == NULL)
                RETURN(-ENOMEM);

        if (src_oa->o_valid & OBD_MD_FLINLINE) {
                ost_uuid = (struct obd_uuid *)src_oa->o_inline;
                CDEBUG(D_HA, "clearing orphans only for %s\n",
                       ost_uuid->uuid);
        }

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
                int err;

                /* if called for a specific target, we don't 
                   care if it is not active. */
                if (lov->tgts[i].active == 0 && ost_uuid == NULL) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", i);
                        continue;
                }

                if (ost_uuid && !obd_uuid_equals(ost_uuid, &lov->tgts[i].uuid))
                        continue;

                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                
                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                err = obd_create(lov->tgts[i].ltd_exp, tmp_oa, &obj_mdp, oti);
                if (err)
                        /* This export will be disabled until it is recovered,
                           and then orphan recovery will be completed. */
                        CERROR("error in orphan recovery on OST idx %d/%d: "
                               "rc = %d\n", i, lov->desc.ld_tgt_count, err);

                if (ost_uuid)
                        break;
        }
        obdo_free(tmp_oa);
        RETURN(rc);
}

#define LOV_CREATE_RESEED_INTERVAL 1000

/* the LOV expects oa->o_id to be set to the LOV object id */
static int lov_create(struct obd_export *exp, struct obdo *src_oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        static int ost_start_idx, ost_start_count;
        struct lov_obd *lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi = NULL;
        struct obdo *tmp_oa, *ret_oa;
        struct llog_cookie *cookies = NULL;
        unsigned ost_count, ost_idx;
        int set = 0, obj_alloc = 0, cookie_sent = 0, rc = 0, i;
        ENTRY;

        LASSERT(ea != NULL);

        if ((src_oa->o_valid & OBD_MD_FLFLAGS) &&
            src_oa->o_flags == OBD_FL_DELORPHAN) {
                rc = lov_clear_orphans(exp, src_oa, ea, oti);
                RETURN(rc);
        }

        if (exp == NULL)
                RETURN(-EINVAL);

        lov = &exp->exp_obd->u.lov;

        if (!lov->desc.ld_active_tgt_count)
                RETURN(-EIO);

        /* Recreate a specific object id at the given OST index */
        if (src_oa->o_valid & OBD_MD_FLFLAGS && src_oa->o_flags &
                                                OBD_FL_RECREATE_OBJS) {
                 struct lov_stripe_md obj_md;
                 struct lov_stripe_md *obj_mdp = &obj_md;

                 ost_idx = src_oa->o_nlink;
                 lsm = *ea;
                 if (lsm == NULL)
                        RETURN(-EINVAL);
                 if (ost_idx >= lov->desc.ld_tgt_count)
                         RETURN(-EINVAL);
                 for (i = 0; i < lsm->lsm_stripe_count; i++) {
                         if (lsm->lsm_oinfo[i].loi_ost_idx == ost_idx) {
                                 if (lsm->lsm_oinfo[i].loi_id != src_oa->o_id)
                                         RETURN(-EINVAL);
                                 break;
                         }
                 }
                 if (i == lsm->lsm_stripe_count)
                         RETURN(-EINVAL);

                 rc = obd_create(lov->tgts[ost_idx].ltd_exp, src_oa,
                                 &obj_mdp, oti);
                 RETURN(rc);
        }

        ret_oa = obdo_alloc();
        if (!ret_oa)
                RETURN(-ENOMEM);

        tmp_oa = obdo_alloc();
        if (!tmp_oa)
                GOTO(out_oa, rc = -ENOMEM);

        lsm = *ea;
        if (lsm == NULL) {
                int stripes;
                ost_count = lov_get_stripecnt(lov, 0);

                /* If the MDS file was truncated up to some size, stripe over
                 * enough OSTs to allow the file to be created at that size. */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        stripes=((src_oa->o_size+LUSTRE_STRIPE_MAXBYTES)>>12)-1;
                        do_div(stripes, (__u32)(LUSTRE_STRIPE_MAXBYTES >> 12));

                        if (stripes > lov->desc.ld_active_tgt_count)
                                RETURN(-EFBIG);
                        if (stripes > ost_count)
                                stripes = ost_count;
                } else {
                        stripes = ost_count;
                }

                rc = lov_alloc_memmd(&lsm, stripes, lov->desc.ld_pattern ?
                                     lov->desc.ld_pattern : LOV_PATTERN_RAID0);
                if (rc < 0)
                        GOTO(out_tmp, rc);

                rc = 0;
        }

        ost_count = lov->desc.ld_tgt_count;

        LASSERT(src_oa->o_valid & OBD_MD_FLID);
        lsm->lsm_object_id = src_oa->o_id;
        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;
        if (!lsm->lsm_pattern) {
                lsm->lsm_pattern = lov->desc.ld_pattern ?
                        lov->desc.ld_pattern : LOV_PATTERN_RAID0;
        }

        if (*ea == NULL || lsm->lsm_oinfo[0].loi_ost_idx >= ost_count) {
                if (--ost_start_count <= 0) {
                        ost_start_idx = ll_insecure_random_int();
                        ost_start_count = LOV_CREATE_RESEED_INTERVAL;
                } else if (lsm->lsm_stripe_count >=
                           lov->desc.ld_active_tgt_count) {
                        /* If we allocate from all of the stripes, make the
                         * next file start on the next OST. */
                        ++ost_start_idx;
                }
                ost_idx = ost_start_idx % ost_count;
        } else {
                ost_idx = lsm->lsm_oinfo[0].loi_ost_idx;
        }

        CDEBUG(D_INODE, "allocating %d subobjs for objid "LPX64" at idx %d\n",
               lsm->lsm_stripe_count, lsm->lsm_object_id, ost_idx);

        /* XXX LOV STACKING: need to figure out how many real OSCs */
        if (oti && (src_oa->o_valid & OBD_MD_FLCOOKIE)) {
                oti_alloc_cookies(oti, lsm->lsm_stripe_count);
                if (!oti->oti_logcookies)
                        GOTO(out_cleanup, rc = -ENOMEM);
                cookies = oti->oti_logcookies;
        }

        loi = lsm->lsm_oinfo;
        for (i = 0; i < ost_count; i++, ost_idx = (ost_idx + 1) % ost_count) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
                int err;

                ++ost_start_idx;
                if (lov->tgts[ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost_idx);
                        continue;
                }

                /* create data objects with "parent" OA */
                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));

                /* XXX When we start creating objects on demand, we need to
                 *     make sure that we always create the object on the
                 *     stripe which holds the existing file size.
                 */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        if (lov_stripe_offset(lsm, src_oa->o_size, i,
                                              &tmp_oa->o_size) < 0 &&
                            tmp_oa->o_size)
                                tmp_oa->o_size--;

                        CDEBUG(D_INODE, "stripe %d has size "LPU64"/"LPU64"\n",
                               i, tmp_oa->o_size, src_oa->o_size);
                }


                /* XXX: LOV STACKING: use real "obj_mdp" sub-data */
                err = obd_create(lov->tgts[ost_idx].ltd_exp, tmp_oa, &obj_mdp,
                                 oti);
                if (err) {
                        if (lov->tgts[ost_idx].active) {
                                CERROR("error creating objid "LPX64" sub-object"
                                       " on OST idx %d/%d: rc = %d\n",
                                       src_oa->o_id, ost_idx,
                                       lsm->lsm_stripe_count, err);
                                if (err > 0) {
                                        CERROR("obd_create returned invalid "
                                               "err %d\n", err);
                                        err = -EIO;
                                }
                        }
                        if (!rc)
                                rc = err;
                        continue;
                }
                if (oti->oti_objid)
                        oti->oti_objid[ost_idx] = tmp_oa->o_id;
                loi->loi_id = tmp_oa->o_id;
                loi->loi_ost_idx = ost_idx;
                CDEBUG(D_INODE, "objid "LPX64" has subobj "LPX64" at idx %d\n",
                       lsm->lsm_object_id, loi->loi_id, ost_idx);

                lov_merge_attrs(ret_oa, tmp_oa, tmp_oa->o_valid, lsm,
                                obj_alloc, &set);
                loi_init(loi);

                if (cookies)
                        ++oti->oti_logcookies;
                if (tmp_oa->o_valid & OBD_MD_FLCOOKIE)
                        ++cookie_sent;
                ++obj_alloc;
                ++loi;

                /* If we have allocated enough objects, we are OK */
                if (obj_alloc == lsm->lsm_stripe_count)
                        GOTO(out_done, rc = 0);
        }

        if (obj_alloc == 0) {
                if (rc == 0)
                        rc = -EIO;
                GOTO(out_cleanup, rc);
        }

        /* If we were passed specific striping params, then a failure to
         * meet those requirements is an error, since we can't reallocate
         * that memory (it might be part of a larger array or something).
         *
         * We can only get here if lsm_stripe_count was originally > 1.
         */
        if (*ea != NULL) {
                CERROR("can't lstripe objid "LPX64": have %u want %u, rc %d\n",
                       lsm->lsm_object_id, obj_alloc, lsm->lsm_stripe_count,rc);
                if (rc == 0)
                        rc = -EFBIG;
                GOTO(out_cleanup, rc);
        } else {
                struct lov_stripe_md *lsm_new;
                /* XXX LOV STACKING call into osc for sizes */
                unsigned oldsize, newsize;

                if (oti && cookies && cookie_sent) {
                        oldsize = lsm->lsm_stripe_count * sizeof(*cookies);
                        newsize = obj_alloc * sizeof(*cookies);

                        oti_alloc_cookies(oti, obj_alloc);
                        if (oti->oti_logcookies) {
                                memcpy(oti->oti_logcookies, cookies, newsize);
                                OBD_FREE(cookies, oldsize);
                                cookies = oti->oti_logcookies;
                        } else {
                                CWARN("'leaking' %d bytes\n", oldsize-newsize);
                        }
                }

                CWARN("using fewer stripes for object "LPX64": old %u new %u\n",
                      lsm->lsm_object_id, lsm->lsm_stripe_count, obj_alloc);
                oldsize = lov_stripe_md_size(lsm->lsm_stripe_count);
                newsize = lov_stripe_md_size(obj_alloc);
                OBD_ALLOC(lsm_new, newsize);
                if (lsm_new != NULL) {
                        memcpy(lsm_new, lsm, newsize);
                        lsm_new->lsm_stripe_count = obj_alloc;
                        OBD_FREE(lsm, oldsize);
                        lsm = lsm_new;
                } else {
                        CWARN("'leaking' %d bytes\n", oldsize - newsize);
                }
                rc = 0;
        }
        EXIT;
 out_done:
        *ea = lsm;
        if (src_oa->o_valid & OBD_MD_FLSIZE &&
            ret_oa->o_size != src_oa->o_size) {
                CERROR("original size "LPU64" isn't new object size "LPU64"\n",
                       src_oa->o_size, ret_oa->o_size);
                LBUG();
        }
        ret_oa->o_id = src_oa->o_id;
        memcpy(src_oa, ret_oa, sizeof(*src_oa));

 out_tmp:
        obdo_free(tmp_oa);
 out_oa:
        obdo_free(ret_oa);
        if (oti && cookies) {
                oti->oti_logcookies = cookies;
                if (!cookie_sent) {
                        oti_free_cookies(oti);
                        src_oa->o_valid &= ~OBD_MD_FLCOOKIE;
                } else {
                        src_oa->o_valid |= OBD_MD_FLCOOKIE;
                }
        }
        RETURN(rc);

 out_cleanup:
        while (obj_alloc-- > 0) {
                struct obd_export *sub_exp;
                int err;

                --loi;
                sub_exp = lov->tgts[loi->loi_ost_idx].ltd_exp;
                /* destroy already created objects here */
                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                tmp_oa->o_id = loi->loi_id;

                err = obd_destroy(sub_exp, tmp_oa, NULL, oti);
                if (err)
                        CERROR("Failed to uncreate objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", src_oa->o_id,
                               loi->loi_id, loi->loi_ost_idx, err);
        }
        if (*ea == NULL)
                obd_free_memmd(exp, &lsm);
        goto out_tmp;
}

#define lsm_bad_magic(LSMP)                                     \
({                                                              \
        struct lov_stripe_md *_lsm__ = (LSMP);                  \
        int _ret__ = 0;                                         \
        if (!_lsm__) {                                          \
                CERROR("LOV requires striping ea\n");           \
                _ret__ = 1;                                     \
        } else if (_lsm__->lsm_magic != LOV_MAGIC) {            \
                CERROR("LOV striping magic bad %#x != %#x\n",   \
                       _lsm__->lsm_magic, LOV_MAGIC);           \
                _ret__ = 1;                                     \
        }                                                       \
        _ret__;                                                 \
})

static int lov_destroy(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo tmp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        /* Orphan clean up will (someday) fix this up. */
                        if (oti != NULL && oa->o_valid & OBD_MD_FLCOOKIE)
                                oti->oti_logcookies++;
                        continue;
                }

                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;
                err = obd_destroy(lov->tgts[loi->loi_ost_idx].ltd_exp, &tmp,
                                  NULL, oti);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: destroying objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        RETURN(rc);
}

static int lov_getattr(struct obd_export *exp, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int i, rc = 0, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;

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

                err = obd_getattr(lov->tgts[loi->loi_ost_idx].ltd_exp, &tmp,
                                  NULL);
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
        if (!set)
                rc = -EIO;
        RETURN(rc);
}

static int lov_getattr_interpret(struct ptlrpc_request_set *rqset, void *data, 
                                 int rc)
{
        struct lov_getattr_async_args *aa = data;
        struct lov_stripe_md *lsm = aa->aa_lsm;
        struct obdo          *oa = aa->aa_oa;
        struct obdo          *obdos = aa->aa_obdos;
        struct lov_oinfo     *loi;
        int                   i;
        int                   set = 0;
        ENTRY;

        if (rc == 0) {
                /* NB all stripe requests succeeded to get here */

                for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
                     i++, loi++) {
                        if (obdos[i].o_valid == 0)      /* inactive stripe */
                                continue;

                        lov_merge_attrs(oa, &obdos[i], obdos[i].o_valid, lsm,
                                        i, &set);
                }

                if (!set) {
                        CERROR ("No stripes had valid attrs\n");
                        rc = -EIO;
                }
        }

        OBD_FREE (obdos, lsm->lsm_stripe_count * sizeof (*obdos));
        RETURN (rc);
}

static int lov_getattr_async(struct obd_export *exp, struct obdo *oa,
                              struct lov_stripe_md *lsm,
                              struct ptlrpc_request_set *rqset)
{
        struct obdo *obdos;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_getattr_async_args *aa;
        int i, rc = 0, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;

        OBD_ALLOC (obdos, lsm->lsm_stripe_count * sizeof (*obdos));
        if (obdos == NULL)
                RETURN(-ENOMEM);

        CDEBUG(D_INFO, "objid "LPX64": %ux%u byte stripes\n",
               lsm->lsm_object_id, lsm->lsm_stripe_count, lsm->lsm_stripe_size);
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        /* leaves obdos[i].obd_valid unset */
                        continue;
                }

                CDEBUG(D_INFO, "objid "LPX64"[%d] has subobj "LPX64" at idx "
                       "%u\n", oa->o_id, i, loi->loi_id, loi->loi_ost_idx);
                /* create data objects with "parent" OA */
                memcpy(&obdos[i], oa, sizeof(obdos[i]));
                obdos[i].o_id = loi->loi_id;

                err = obd_getattr_async(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                         &obdos[i], NULL, rqset);
                if (err) {
                        CERROR("error: getattr objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx,
                               err);
                        GOTO(out_obdos, rc = err);
                }
                set = 1;
        }
        if (!set)
                GOTO (out_obdos, rc = -EIO);

        LASSERT (rqset->set_interpret == NULL);
        rqset->set_interpret = lov_getattr_interpret;
        LASSERT (sizeof (rqset->set_args) >= sizeof (*aa));
        aa = (struct lov_getattr_async_args *)&rqset->set_args;
        aa->aa_lsm = lsm;
        aa->aa_oa = oa;
        aa->aa_obdos = obdos;
        aa->aa_lov = lov;
        GOTO(out, rc = 0);

out_obdos:
        OBD_FREE (obdos, lsm->lsm_stripe_count * sizeof (*obdos));
out:
        RETURN(rc);
}


static int lov_setattr(struct obd_export *exp, struct obdo *src_oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo *tmp_oa, *ret_oa;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        /* for now, we only expect time updates here */
        LASSERT(!(src_oa->o_valid & ~(OBD_MD_FLID|OBD_MD_FLTYPE | OBD_MD_FLMODE|
                                      OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                      OBD_MD_FLCTIME | OBD_MD_FLFLAGS |
                                      OBD_MD_FLSIZE)));
        ret_oa = obdo_alloc();
        if (!ret_oa)
                RETURN(-ENOMEM);

        tmp_oa = obdo_alloc();
        if (!tmp_oa)
                GOTO(out_oa, rc = -ENOMEM);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                tmp_oa->o_id = loi->loi_id;

                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        if (lov_stripe_offset(lsm, src_oa->o_size, i,
                                              &tmp_oa->o_size) < 0 &&
                            tmp_oa->o_size)
                                tmp_oa->o_size--;

                        CDEBUG(D_INODE, "stripe %d has size "LPU64"/"LPU64"\n",
                               i, tmp_oa->o_size, src_oa->o_size);
                }

                err = obd_setattr(lov->tgts[loi->loi_ost_idx].ltd_exp, tmp_oa,
                                  NULL, NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: setattr objid "LPX64" subobj "
                                       LPX64" on OST idx %d: rc = %d\n",
                                       src_oa->o_id, loi->loi_id,
                                       loi->loi_ost_idx, err);
                                if (!rc)
                                        rc = err;
                        }
                        continue;
                }
                lov_merge_attrs(ret_oa, tmp_oa, tmp_oa->o_valid, lsm, i, &set);
        }
        if (!set && !rc)
                rc = -EIO;

        ret_oa->o_id = src_oa->o_id;
        memcpy(src_oa, ret_oa, sizeof(*src_oa));
        GOTO(out_tmp, rc);
out_tmp:
        obdo_free(tmp_oa);
out_oa:
        obdo_free(ret_oa);
        return rc;
}

/* we have an offset in file backed by an lov and want to find out where
 * that offset lands in our given stripe of the file.  for the easy
 * case where the offset is within the stripe, we just have to scale the
 * offset down to make it relative to the stripe instead of the lov.
 *
 * the harder case is what to do when the offset doesn't intersect the
 * stripe.  callers will want start offsets clamped ahead to the start
 * of the nearest stripe in the file.  end offsets similarly clamped to the
 * nearest ending byte of a stripe in the file:
 *
 * all this function does is move offsets to the nearest region of the
 * stripe, and it does its work "mod" the full length of all the stripes.
 * consider a file with 3 stripes:
 *
 *             S                                              E
 * ---------------------------------------------------------------------
 * |    0    |     1     |     2     |    0    |     1     |     2     |
 * ---------------------------------------------------------------------
 *
 * to find stripe 1's offsets for S and E, it divides by the full stripe
 * width and does its math in the context of a single set of stripes:
 *
 *             S         E
 * -----------------------------------
 * |    0    |     1     |     2     |
 * -----------------------------------
 *
 * it'll notice that E is outside stripe 1 and clamp it to the end of the
 * stripe, then multiply it back out by lov_off to give the real offsets in
 * the stripe:
 *
 *   S                   E
 * ---------------------------------------------------------------------
 * |    1    |     1     |     1     |    1    |     1     |     1     |
 * ---------------------------------------------------------------------
 *
 * it would have done similarly and pulled S forward to the start of a 1
 * stripe if, say, S had landed in a 0 stripe.
 *
 * this rounding isn't always correct.  consider an E lov offset that lands
 * on a 0 stripe, the "mod stripe width" math will pull it forward to the
 * start of a 1 stripe, when in fact it wanted to be rounded back to the end
 * of a previous 1 stripe.  this logic is handled by callers and this is why:
 *
 * this function returns < 0 when the offset was "before" the stripe and
 * was moved forward to the start of the stripe in question;  0 when it
 * falls in the stripe and no shifting was done; > 0 when the offset
 * was outside the stripe and was pulled back to its final byte. */
static int lov_stripe_offset(struct lov_stripe_md *lsm, obd_off lov_off,
                             int stripeno, obd_off *obd_off)
{
        unsigned long ssize  = lsm->lsm_stripe_size;
        unsigned long swidth = ssize * lsm->lsm_stripe_count;
        unsigned long stripe_off, this_stripe;
        int ret = 0;

        if (lov_off == OBD_OBJECT_EOF) {
                *obd_off = OBD_OBJECT_EOF;
                return 0;
        }

        /* do_div(a, b) returns a % b, and a = a / b */
        stripe_off = do_div(lov_off, swidth);

        this_stripe = stripeno * ssize;
        if (stripe_off < this_stripe) {
                stripe_off = 0;
                ret = -1;
        } else {
                stripe_off -= this_stripe;

                if (stripe_off >= ssize) {
                        stripe_off = ssize;
                        ret = 1;
                }
        }

        *obd_off = lov_off * ssize + stripe_off;
        return ret;
}

/* Given a whole-file size and a stripe number, give the file size which
 * corresponds to the individual object of that stripe.
 *
 * This behaves basically in the same was as lov_stripe_offset, except that
 * file sizes falling before the beginning of a stripe are clamped to the end
 * of the previous stripe, not the beginning of the next:
 *
 *                                               S
 * ---------------------------------------------------------------------
 * |    0    |     1     |     2     |    0    |     1     |     2     |
 * ---------------------------------------------------------------------
 *
 * if clamped to stripe 2 becomes:
 *
 *                                   S
 * ---------------------------------------------------------------------
 * |    0    |     1     |     2     |    0    |     1     |     2     |
 * ---------------------------------------------------------------------
 */
static obd_off lov_size_to_stripe(struct lov_stripe_md *lsm, obd_off file_size,
                                  int stripeno)
{
        unsigned long ssize  = lsm->lsm_stripe_size;
        unsigned long swidth = ssize * lsm->lsm_stripe_count;
        unsigned long stripe_off, this_stripe;

        if (file_size == OBD_OBJECT_EOF)
                return OBD_OBJECT_EOF;

        /* do_div(a, b) returns a % b, and a = a / b */
        stripe_off = do_div(file_size, swidth);

        this_stripe = stripeno * ssize;
        if (stripe_off < this_stripe) {
                /* Move to end of previous stripe, or zero */
                if (file_size > 0) {
                        file_size--;
                        stripe_off = ssize;
                } else {
                        stripe_off = 0;
                }
        } else {
                stripe_off -= this_stripe;

                if (stripe_off >= ssize) {
                        /* Clamp to end of this stripe */
                        stripe_off = ssize;
                }
        }

        return (file_size * ssize + stripe_off);
}

/* given an extent in an lov and a stripe, calculate the extent of the stripe
 * that is contained within the lov extent.  this returns true if the given
 * stripe does intersect with the lov extent. */
static int lov_stripe_intersects(struct lov_stripe_md *lsm, int stripeno,
                                 obd_off start, obd_off end,
                                 obd_off *obd_start, obd_off *obd_end)
{
        int start_side, end_side;

        start_side = lov_stripe_offset(lsm, start, stripeno, obd_start);
        end_side = lov_stripe_offset(lsm, end, stripeno, obd_end);

        CDEBUG(D_INODE, "["LPU64"->"LPU64"] -> [(%d) "LPU64"->"LPU64" (%d)]\n",
               start, end, start_side, *obd_start, *obd_end, end_side);

        /* this stripe doesn't intersect the file extent when neither
         * start or the end intersected the stripe and obd_start and
         * obd_end got rounded up to the save value. */
        if (start_side != 0 && end_side != 0 && *obd_start == *obd_end)
                return 0;

        /* as mentioned in the lov_stripe_offset commentary, end
         * might have been shifted in the wrong direction.  This
         * happens when an end offset is before the stripe when viewed
         * through the "mod stripe size" math. we detect it being shifted
         * in the wrong direction and touch it up.
         * interestingly, this can't underflow since end must be > start
         * if we passed through the previous check.
         * (should we assert for that somewhere?) */
        if (end_side != 0)
                (*obd_end)--;

        return 1;
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
static int lov_punch(struct obd_export *exp, struct obdo *oa,
                     struct lov_stripe_md *lsm,
                     obd_off start, obd_off end, struct obd_trans_info *oti)
{
        struct obdo tmp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                obd_off starti, endi;
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                if (!lov_stripe_intersects(lsm, i, start, end, &starti, &endi))
                        continue;

                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;

                err = obd_punch(lov->tgts[loi->loi_ost_idx].ltd_exp, &tmp, NULL,
                                starti, endi, NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: punch objid "LPX64" subobj "LPX64
                                       " on OST idx %d: rc = %d\n", oa->o_id,
                                       loi->loi_id, loi->loi_ost_idx, err);
                        }
                        if (!rc)
                                rc = err;
                } else {
                        loi->loi_kms = loi->loi_rss = starti;
                }
        }
        RETURN(rc);
}

static int lov_sync(struct obd_export *exp, struct obdo *oa,
                    struct lov_stripe_md *lsm, obd_off start, obd_off end)
{
        struct obdo *tmp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp->exp_obd)
                RETURN(-ENODEV);

        tmp = obdo_alloc();
        if (!tmp)
                RETURN(-ENOMEM);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                obd_off starti, endi;
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                if (!lov_stripe_intersects(lsm, i, start, end, &starti, &endi))
                        continue;

                memcpy(tmp, oa, sizeof(*tmp));
                tmp->o_id = loi->loi_id;

                err = obd_sync(lov->tgts[loi->loi_ost_idx].ltd_exp, tmp, NULL,
                               starti, endi);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: fsync objid "LPX64" subobj "LPX64
                                       " on OST idx %d: rc = %d\n", oa->o_id,
                                       loi->loi_id, loi->loi_ost_idx, err);
                        }
                        if (!rc)
                                rc = err;
                }
        }

        obdo_free(tmp);
        RETURN(rc);
}

static int lov_brw_check(struct lov_obd *lov, struct obdo *oa,
                         struct lov_stripe_md *lsm,
                         obd_count oa_bufs, struct brw_page *pga)
{
        int i, rc = 0;

        /* The caller just wants to know if there's a chance that this
         * I/O can succeed */
        for (i = 0; i < oa_bufs; i++) {
                int stripe = lov_stripe_number(lsm, pga[i].off);
                int ost = lsm->lsm_oinfo[stripe].loi_ost_idx;
                struct ldlm_extent ext, subext;
                ext.start = pga[i].off;
                ext.end = pga[i].off + pga[i].count;

                if (!lov_stripe_intersects(lsm, i, ext.start, ext.end,
                                           &subext.start, &subext.end))
                        continue;

                if (lov->tgts[ost].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost);
                        return -EIO;
                }
                rc = obd_brw(OBD_BRW_CHECK, lov->tgts[stripe].ltd_exp, oa,
                             NULL, 1, &pga[i], NULL);
                if (rc)
                        break;
        }
        return rc;
}

static int lov_brw(int cmd, struct obd_export *exp, struct obdo *src_oa,
                   struct lov_stripe_md *lsm, obd_count oa_bufs,
                   struct brw_page *pga, struct obd_trans_info *oti)
{
        struct {
                int bufct;
                int index;
                int subcount;
                struct lov_stripe_md lsm;
                int ost_idx;
        } *stripeinfo, *si, *si_last;
        struct obdo *ret_oa = NULL, *tmp_oa = NULL;
        struct lov_obd *lov;
        struct brw_page *ioarr;
        struct lov_oinfo *loi;
        int rc = 0, i, *where, stripe_count = lsm->lsm_stripe_count, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        lov = &exp->exp_obd->u.lov;

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, src_oa, lsm, oa_bufs, pga);
                RETURN(rc);
        }

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                RETURN(-ENOMEM);

        OBD_ALLOC(where, sizeof(*where) * oa_bufs);
        if (!where)
                GOTO(out_sinfo, rc = -ENOMEM);

        OBD_ALLOC(ioarr, sizeof(*ioarr) * oa_bufs);
        if (!ioarr)
                GOTO(out_where, rc = -ENOMEM);

        if (src_oa) {
                ret_oa = obdo_alloc();
                if (!ret_oa)
                        GOTO(out_ioarr, rc = -ENOMEM);

                tmp_oa = obdo_alloc();
                if (!tmp_oa)
                        GOTO(out_oa, rc = -ENOMEM);
        }

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
                lov_stripe_offset(lsm, pga[i].off, which, &ioarr[shift].off);
                stripeinfo[which].subcount++;
        }

        for (i = 0, si = stripeinfo; i < stripe_count; i++, si++) {
                int shift = si->index;

                if (lov->tgts[si->ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", si->ost_idx);
                        GOTO(out_oa, rc = -EIO);
                }

                if (si->bufct) {
                        LASSERT(shift < oa_bufs);
                        if (src_oa)
                                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));

                        tmp_oa->o_id = si->lsm.lsm_object_id;
                        rc = obd_brw(cmd, lov->tgts[si->ost_idx].ltd_exp, 
                                     tmp_oa, &si->lsm, si->bufct, 
                                     &ioarr[shift], oti);
                        if (rc)
                                GOTO(out_ioarr, rc);

                        lov_merge_attrs(ret_oa, tmp_oa, tmp_oa->o_valid, lsm,
                                        i, &set);
                }
        }

        ret_oa->o_id = src_oa->o_id;
        memcpy(src_oa, ret_oa, sizeof(*src_oa));

        GOTO(out_oa, rc);
 out_oa:
        if (tmp_oa)
                obdo_free(tmp_oa);
        if (ret_oa)
                obdo_free(ret_oa);
 out_ioarr:
        OBD_FREE(ioarr, sizeof(*ioarr) * oa_bufs);
 out_where:
        OBD_FREE(where, sizeof(*where) * oa_bufs);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
        return rc;
}

static int lov_brw_interpret(struct ptlrpc_request_set *reqset, void *data,
                             int rc)
{
        struct lov_brw_async_args *aa = data;
        struct lov_stripe_md *lsm = aa->aa_lsm;
        obd_count             oa_bufs = aa->aa_oa_bufs;
        struct obdo          *oa = aa->aa_oa;
        struct obdo          *obdos = aa->aa_obdos;
        struct brw_page      *ioarr = aa->aa_ioarr;
        struct lov_oinfo     *loi;
        int i, set = 0;
        ENTRY;

        if (rc == 0) {
                /* NB all stripe requests succeeded to get here */

                for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
                     i++, loi++) {
                        if (obdos[i].o_valid == 0)      /* inactive stripe */
                                continue;

                        lov_merge_attrs(oa, &obdos[i], obdos[i].o_valid, lsm,
                                        i, &set);
                }

                if (!set) {
                        CERROR("No stripes had valid attrs\n");
                        rc = -EIO;
                }
        }
        oa->o_id = lsm->lsm_object_id;

        OBD_FREE(obdos, lsm->lsm_stripe_count * sizeof(*obdos));
        OBD_FREE(ioarr, sizeof(*ioarr) * oa_bufs);
        RETURN(rc);
}

static int lov_brw_async(int cmd, struct obd_export *exp, struct obdo *oa,
                         struct lov_stripe_md *lsm, obd_count oa_bufs,
                         struct brw_page *pga, struct ptlrpc_request_set *set,
                         struct obd_trans_info *oti)
{
        struct {
                int bufct;
                int index;
                int subcount;
                struct lov_stripe_md lsm;
                int ost_idx;
        } *stripeinfo, *si, *si_last;
        struct lov_obd *lov;
        struct brw_page *ioarr;
        struct obdo *obdos = NULL;
        struct lov_oinfo *loi;
        struct lov_brw_async_args *aa;
        int rc = 0, i, *where, stripe_count = lsm->lsm_stripe_count;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        lov = &exp->exp_obd->u.lov;

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, oa, lsm, oa_bufs, pga);
                RETURN(rc);
        }

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                RETURN(-ENOMEM);

        OBD_ALLOC(where, sizeof(*where) * oa_bufs);
        if (!where)
                GOTO(out_sinfo, rc = -ENOMEM);

        if (oa) {
                OBD_ALLOC(obdos, sizeof(*obdos) * stripe_count);
                if (!obdos)
                        GOTO(out_where, rc = -ENOMEM);
        }

        OBD_ALLOC(ioarr, sizeof(*ioarr) * oa_bufs);
        if (!ioarr)
                GOTO(out_obdos, rc = -ENOMEM);

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

                if (oa) {
                        memcpy(&obdos[i], oa, sizeof(*obdos));
                        obdos[i].o_id = si->lsm.lsm_object_id;
                }
        }

        for (i = 0; i < oa_bufs; i++) {
                int which = where[i];
                int shift;

                shift = stripeinfo[which].index + stripeinfo[which].subcount;
                LASSERT(shift < oa_bufs);
                ioarr[shift] = pga[i];
                lov_stripe_offset(lsm, pga[i].off, which, &ioarr[shift].off);
                stripeinfo[which].subcount++;
        }

        for (i = 0, si = stripeinfo; i < stripe_count; i++, si++) {
                int shift = si->index;

                if (si->bufct == 0)
                        continue;

                if (lov->tgts[si->ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", si->ost_idx);
                        GOTO(out_ioarr, rc = -EIO);
                }

                LASSERT(shift < oa_bufs);

                rc = obd_brw_async(cmd, lov->tgts[si->ost_idx].ltd_exp,
                                   &obdos[i], &si->lsm, si->bufct,
                                   &ioarr[shift], set, oti);
                if (rc)
                        GOTO(out_ioarr, rc);
        }
        LASSERT(rc == 0);
        LASSERT(set->set_interpret == NULL);
        set->set_interpret = (set_interpreter_func)lov_brw_interpret;
        LASSERT(sizeof(set->set_args) >= sizeof(struct lov_brw_async_args));
        aa = (struct lov_brw_async_args *)&set->set_args;
        aa->aa_lsm = lsm;
        aa->aa_obdos = obdos;
        aa->aa_oa = oa;
        aa->aa_ioarr = ioarr;
        aa->aa_oa_bufs = oa_bufs;

        /* Don't free ioarr or obdos - that's done in lov_brw_interpret */
        GOTO(out_where, rc);

 out_ioarr:
        OBD_FREE(ioarr, sizeof(*ioarr) * oa_bufs);
 out_obdos:
        OBD_FREE(obdos, stripe_count * sizeof(*obdos));
 out_where:
        OBD_FREE(where, sizeof(*where) * oa_bufs);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
        return rc;
}

struct lov_async_page *lap_from_cookie(void *cookie)
{
        struct lov_async_page *lap = cookie;
        if (lap->lap_magic != LAP_MAGIC)
                return ERR_PTR(-EINVAL);
        return lap;
};

static int lov_ap_make_ready(void *data, int cmd)
{
        struct lov_async_page *lap = lap_from_cookie(data);
        /* XXX should these assert? */
        if (IS_ERR(lap))
                return -EINVAL;

        return lap->lap_caller_ops->ap_make_ready(lap->lap_caller_data, cmd);
}
static int lov_ap_refresh_count(void *data, int cmd)
{
        struct lov_async_page *lap = lap_from_cookie(data);
        if (IS_ERR(lap))
                return -EINVAL;

        return lap->lap_caller_ops->ap_refresh_count(lap->lap_caller_data, 
                                                     cmd);
}
static void lov_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct lov_async_page *lap = lap_from_cookie(data);
        /* XXX should these assert? */
        if (IS_ERR(lap))
                return;

        lap->lap_caller_ops->ap_fill_obdo(lap->lap_caller_data, cmd, oa);
        /* XXX woah, shouldn't we be altering more here?  size? */
        oa->o_id = lap->lap_loi_id;
}
static void lov_ap_completion(void *data, int cmd, int rc)
{
        struct lov_async_page *lap = lap_from_cookie(data);
        if (IS_ERR(lap))
                return;

        /* in a raid1 regime this would down a count of many ios
         * in flight, onl calling the caller_ops completion when all
         * the raid1 ios are complete */
        lap->lap_caller_ops->ap_completion(lap->lap_caller_data, cmd, rc);
}

static struct obd_async_page_ops lov_async_page_ops = {
        .ap_make_ready =        lov_ap_make_ready,
        .ap_refresh_count =     lov_ap_refresh_count,
        .ap_fill_obdo =         lov_ap_fill_obdo,
        .ap_completion =        lov_ap_completion,
};

int lov_prep_async_page(struct obd_export *exp, struct lov_stripe_md *lsm,
                           struct lov_oinfo *loi, struct page *page,
                           obd_off offset, struct obd_async_page_ops *ops, 
                           void *data, void **res)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);
        LASSERT(loi == NULL);

        OBD_ALLOC(lap, sizeof(*lap));
        if (lap == NULL)
                RETURN(-ENOMEM);

        lap->lap_magic = LAP_MAGIC;
        lap->lap_caller_ops = ops;
        lap->lap_caller_data = data;

        /* for now only raid 0 which passes through */
        lap->lap_stripe = lov_stripe_number(lsm, offset);
        lov_stripe_offset(lsm, offset, lap->lap_stripe, &lap->lap_sub_offset);
        loi = &lsm->lsm_oinfo[lap->lap_stripe];

        /* so the callback doesn't need the lsm */ 
        lap->lap_loi_id = loi->loi_id;

        rc = obd_prep_async_page(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                 lsm, loi, page, lap->lap_sub_offset,
                                 &lov_async_page_ops, lap,
                                 &lap->lap_sub_cookie);
        if (rc) {
                OBD_FREE(lap, sizeof(*lap));
                RETURN(rc);
        }
        CDEBUG(D_CACHE, "lap %p page %p cookie %p off "LPU64"\n", lap, page,
               lap->lap_sub_cookie, offset);
        *res = lap;
        RETURN(0);
}

static int lov_queue_async_io(struct obd_export *exp,
                              struct lov_stripe_md *lsm,
                              struct lov_oinfo *loi, void *cookie,
                              int cmd, obd_off off, int count,
                              obd_flag brw_flags, obd_flag async_flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        lap = lap_from_cookie(cookie);
        if (IS_ERR(lap))
                RETURN(PTR_ERR(lap));

        loi = &lsm->lsm_oinfo[lap->lap_stripe];
        rc = obd_queue_async_io(lov->tgts[loi->loi_ost_idx].ltd_exp, lsm,
                                loi, lap->lap_sub_cookie, cmd, off, count,
                                brw_flags, async_flags);
        RETURN(rc);
}

static int lov_set_async_flags(struct obd_export *exp,
                               struct lov_stripe_md *lsm,
                               struct lov_oinfo *loi, void *cookie,
                               obd_flag async_flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        lap = lap_from_cookie(cookie);
        if (IS_ERR(lap))
                RETURN(PTR_ERR(lap));

        loi = &lsm->lsm_oinfo[lap->lap_stripe];
        rc = obd_set_async_flags(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                 lsm, loi, lap->lap_sub_cookie, async_flags);
        RETURN(rc);
}

static int lov_queue_group_io(struct obd_export *exp,
                              struct lov_stripe_md *lsm,
                              struct lov_oinfo *loi,
                              struct obd_io_group *oig, void *cookie,
                              int cmd, obd_off off, int count,
                              obd_flag brw_flags, obd_flag async_flags)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        lap = lap_from_cookie(cookie);
        if (IS_ERR(lap))
                RETURN(PTR_ERR(lap));

        loi = &lsm->lsm_oinfo[lap->lap_stripe];
        rc = obd_queue_group_io(lov->tgts[loi->loi_ost_idx].ltd_exp, lsm, loi,
                                oig, lap->lap_sub_cookie, cmd, off, count,
                                brw_flags, async_flags);
        RETURN(rc);
}

/* this isn't exactly optimal.  we may have queued sync io in oscs on
 * all stripes, but we don't record that fact at queue time.  so we
 * trigger sync io on all stripes. */
static int lov_trigger_group_io(struct obd_export *exp,
                                struct lov_stripe_md *lsm,
                                struct lov_oinfo *loi,
                                struct obd_io_group *oig)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        int rc = 0, i, err;

        LASSERT(loi == NULL);

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++) {
                err = obd_trigger_group_io(lov->tgts[loi->loi_ost_idx].ltd_exp, 
                                           lsm, loi, oig);
                if (rc == 0 && err != 0)
                        rc = err;
        };
        RETURN(rc);
}

static int lov_teardown_async_page(struct obd_export *exp,
                                   struct lov_stripe_md *lsm,
                                   struct lov_oinfo *loi, void *cookie)
{
        struct lov_obd *lov = &exp->exp_obd->u.lov;
        struct lov_async_page *lap;
        int rc;

        LASSERT(loi == NULL);

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        lap = lap_from_cookie(cookie);
        if (IS_ERR(lap))
                RETURN(PTR_ERR(lap));

        loi = &lsm->lsm_oinfo[lap->lap_stripe];
        rc = obd_teardown_async_page(lov->tgts[loi->loi_ost_idx].ltd_exp, 
                                     lsm, loi, lap->lap_sub_cookie);
        if (rc) {
                CERROR("unable to teardown sub cookie %p: %d\n", 
                       lap->lap_sub_cookie, rc);
                RETURN(rc);
        }
        OBD_FREE(lap, sizeof(*lap));
        RETURN(rc);
}

static int lov_enqueue(struct obd_export *exp, struct lov_stripe_md *lsm,
                       __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                       int *flags, void *bl_cb, void *cp_cb, void *gl_cb,
                       void *data,__u32 lvb_len, void *lvb_swabber,
                       struct lustre_handle *lockh)
{
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        char submd_buf[sizeof(struct lov_stripe_md) + sizeof(struct lov_oinfo)];
        struct lov_stripe_md *submd = (void *)submd_buf;
        ldlm_error_t rc;
        int i, save_flags = *flags;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        /* we should never be asked to replay a lock this way. */
        LASSERT((*flags & LDLM_FL_REPLAY) == 0);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_llh_new(lsm);
                if (lov_lockh == NULL)
                        RETURN(-ENOMEM);

                lockh->cookie = lov_lockh->llh_handle.h_cookie;
                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        lov = &exp->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                ldlm_policy_data_t sub_ext;

                if (!lov_stripe_intersects(lsm, i, policy->l_extent.start,
                                           policy->l_extent.end,
                                           &sub_ext.l_extent.start,
                                           &sub_ext.l_extent.end))
                        continue;

                sub_ext.l_extent.gid = policy->l_extent.gid;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                /* XXX LOV STACKING: submd should be from the subobj */
                submd->lsm_object_id = loi->loi_id;
                submd->lsm_stripe_count = 0;
                submd->lsm_oinfo->loi_kms_valid = loi->loi_kms_valid;
                submd->lsm_oinfo->loi_rss = loi->loi_rss;
                submd->lsm_oinfo->loi_kms = loi->loi_kms;
                loi->loi_mtime = submd->lsm_oinfo->loi_mtime;
                /* XXX submd is not fully initialized here */
                *flags = save_flags;
                rc = obd_enqueue(lov->tgts[loi->loi_ost_idx].ltd_exp, submd,
                                 type, &sub_ext, mode, flags, bl_cb, cp_cb,
                                 gl_cb, data, lvb_len, lvb_swabber, lov_lockhp);

                /* XXX FIXME: This unpleasantness doesn't belong here at *all*.
                 * It belongs in the OSC, except that the OSC doesn't have
                 * access to the real LOI -- it gets a copy, that we created
                 * above, and that copy can be arbitrarily out of date.
                 *
                 * The LOV API is due for a serious rewriting anyways, and this
                 * can be addressed then. */
                if (rc == ELDLM_OK) {
                        struct ldlm_lock *lock = ldlm_handle2lock(lov_lockhp);
                        __u64 tmp = submd->lsm_oinfo->loi_rss;

                        LASSERT(lock != NULL);
                        loi->loi_rss = tmp;
                        /* Extend KMS up to the end of this lock and no further
                         * A lock on [x,y] means a KMS of up to y + 1 bytes! */
                        if (tmp > lock->l_policy_data.l_extent.end)
                                tmp = lock->l_policy_data.l_extent.end + 1;
                        if (tmp >= loi->loi_kms) {
                                CDEBUG(D_INODE, "lock acquired, setting rss="
                                       LPU64", kms="LPU64"\n", loi->loi_rss,
                                       tmp);
                                loi->loi_kms = tmp;
                                loi->loi_kms_valid = 1;
                        } else {
                                CDEBUG(D_INODE, "lock acquired, setting rss="
                                       LPU64"; leaving kms="LPU64", end="LPU64
                                       "\n", loi->loi_rss, loi->loi_kms,
                                       lock->l_policy_data.l_extent.end);
                        }
                        ldlm_lock_allow_match(lock);
                        LDLM_LOCK_PUT(lock);
                } else if (rc == ELDLM_LOCK_ABORTED &&
                           save_flags & LDLM_FL_HAS_INTENT) {
                        memset(lov_lockhp, 0, sizeof(*lov_lockhp));
                        loi->loi_rss = submd->lsm_oinfo->loi_rss;
                        CDEBUG(D_INODE, "glimpsed, setting rss="LPU64"; leaving"
                               " kms="LPU64"\n", loi->loi_rss, loi->loi_kms);
                } else {
                        memset(lov_lockhp, 0, sizeof(*lov_lockhp));
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: enqueue objid "LPX64" subobj "
                                       LPX64" on OST idx %d: rc = %d\n",
                                       lsm->lsm_object_id, loi->loi_id,
                                       loi->loi_ost_idx, rc);
                                GOTO(out_locks, rc);
                        }
                }
        }
        if (lsm->lsm_stripe_count > 1)
                lov_llh_put(lov_lockh);
        RETURN(ELDLM_OK);

 out_locks:
        while (loi--, lov_lockhp--, i-- > 0) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->cookie == 0)
                        continue;

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel(lov->tgts[loi->loi_ost_idx].ltd_exp, &submd,
                                 mode, lov_lockhp);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: cancelling objid "LPX64" on OST "
                               "idx %d after enqueue error: rc = %d\n",
                               loi->loi_id, loi->loi_ost_idx, err);
                }
        }

        if (lsm->lsm_stripe_count > 1) {
                lov_llh_destroy(lov_lockh);
                lov_llh_put(lov_lockh);
        }
        return rc;
}

static int lov_match(struct obd_export *exp, struct lov_stripe_md *lsm,
                     __u32 type, ldlm_policy_data_t *policy, __u32 mode,
                     int *flags, void *data, struct lustre_handle *lockh)
{
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_stripe_md submd;
        ldlm_error_t rc = 0;
        int i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_llh_new(lsm);
                if (lov_lockh == NULL)
                        RETURN(-ENOMEM);

                lockh->cookie = lov_lockh->llh_handle.h_cookie;
                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        lov = &exp->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                ldlm_policy_data_t sub_ext;
                int lov_flags;

                if (!lov_stripe_intersects(lsm, i, policy->l_extent.start,
                                           policy->l_extent.end,
                                           &sub_ext.l_extent.start,
                                           &sub_ext.l_extent.end))
                        continue;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        rc = -EIO;
                        break;
                }

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                lov_flags = *flags;
                /* XXX submd is not fully initialized here */
                rc = obd_match(lov->tgts[loi->loi_ost_idx].ltd_exp, &submd,
                               type, &sub_ext, mode, &lov_flags, data,
                               lov_lockhp);
                if (rc != 1)
                        break;
        }
        if (rc == 1) {
                if (lsm->lsm_stripe_count > 1) {
                        if (*flags & LDLM_FL_TEST_LOCK)
                                lov_llh_destroy(lov_lockh);
                        lov_llh_put(lov_lockh);
                }
                RETURN(1);
        }

        while (loi--, lov_lockhp--, i-- > 0) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->cookie == 0)
                        continue;

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel(lov->tgts[loi->loi_ost_idx].ltd_exp, &submd,
                                 mode, lov_lockhp);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: cancelling objid "LPX64" on OST "
                               "idx %d after match failure: rc = %d\n",
                               loi->loi_id, loi->loi_ost_idx, err);
                }
        }

        if (lsm->lsm_stripe_count > 1) {
                lov_llh_destroy(lov_lockh);
                lov_llh_put(lov_lockh);
        }
        RETURN(rc);
}

static int lov_change_cbdata(struct obd_export *exp,
                             struct lov_stripe_md *lsm, ldlm_iterator_t it,
                             void *data)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;
                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                rc = obd_change_cbdata(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                       &submd, it, data);
        }
        RETURN(rc);
}

static int lov_cancel(struct obd_export *exp, struct lov_stripe_md *lsm,
                      __u32 mode, struct lustre_handle *lockh)
{
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        LASSERT(lockh);
        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_handle2llh(lockh);
                if (!lov_lockh) {
                        CERROR("LOV: invalid lov lock handle %p\n", lockh);
                        RETURN(-EINVAL);
                }

                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        lov = &exp->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->cookie == 0) {
                        CDEBUG(D_HA, "lov idx %d subobj "LPX64" no lock?\n",
                               loi->loi_ost_idx, loi->loi_id);
                        continue;
                }

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel(lov->tgts[loi->loi_ost_idx].ltd_exp, &submd,
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

        if (lsm->lsm_stripe_count > 1)
                lov_llh_destroy(lov_lockh);
        if (lov_lockh != NULL)
                lov_llh_put(lov_lockh);
        RETURN(rc);
}

static int lov_cancel_unused(struct obd_export *exp,
                             struct lov_stripe_md *lsm, int flags, void *opaque)
{
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        lov = &exp->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel_unused(lov->tgts[loi->loi_ost_idx].ltd_exp,
                                        &submd, flags, opaque);
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

#define LOV_U64_MAX ((__u64)~0ULL)
#define LOV_SUM_MAX(tot, add)                                           \
        do {                                                            \
                if ((tot) + (add) < (tot))                              \
                        (tot) = LOV_U64_MAX;                            \
                else                                                    \
                        (tot) += (add);                                 \
        } while(0)

static int lov_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      unsigned long max_age)
{
        struct lov_obd *lov = &obd->u.lov;
        struct obd_statfs lov_sfs;
        int set = 0;
        int rc = 0;
        int i;
        ENTRY;


        /* We only get block data from the OBD */
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int err;

                if (!lov->tgts[i].active) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", i);
                        continue;
                }

                err = obd_statfs(class_exp2obd(lov->tgts[i].ltd_exp), &lov_sfs,
                                 max_age);
                if (err) {
                        if (lov->tgts[i].active && !rc)
                                rc = err;
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
                         *
                         * To give a "reasonable" (if not wholly accurate)
                         * number, we divide the total number of free objects
                         * by expected stripe count (watch out for overflow).
                         */
                        LOV_SUM_MAX(osfs->os_files, lov_sfs.os_files);
                        LOV_SUM_MAX(osfs->os_ffree, lov_sfs.os_ffree);
                }
        }

        if (set) {
                __u32 expected_stripes = lov->desc.ld_default_stripe_count ?
                                         lov->desc.ld_default_stripe_count :
                                         lov->desc.ld_active_tgt_count;

                if (osfs->os_files != LOV_U64_MAX)
                        do_div(osfs->os_files, expected_stripes);
                if (osfs->os_ffree != LOV_U64_MAX)
                        do_div(osfs->os_ffree, expected_stripes);
        } else if (!rc)
                rc = -EIO;

        RETURN(rc);
}

static int lov_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i, count = lov->desc.ld_tgt_count;
        struct obd_uuid *uuidp;
        int rc;

        ENTRY;

        switch (cmd) {
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
                obd_ioctl_freedata(buf, len);
                break;
        }
        case LL_IOC_LOV_SETSTRIPE:
                rc = lov_setstripe(exp, karg, uarg);
                break;
        case LL_IOC_LOV_GETSTRIPE:
                rc = lov_getstripe(exp, karg, uarg);
                break;
        case LL_IOC_LOV_SETEA:
                rc = lov_setea(exp, karg, uarg);
                break;
        default: {
                int set = 0;
                if (count == 0)
                        RETURN(-ENOTTY);
                rc = 0;
                for (i = 0; i < count; i++) {
                        int err;

                        err = obd_iocontrol(cmd, lov->tgts[i].ltd_exp,
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

static int lov_get_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 *vallen, void *val)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i;
        ENTRY;

        if (!vallen || !val)
                RETURN(-EFAULT);

        if (keylen > strlen("lock_to_stripe") &&
            strcmp(key, "lock_to_stripe") == 0) {
                struct {
                        char name[16];
                        struct ldlm_lock *lock;
                        struct lov_stripe_md *lsm;
                } *data = key;
                struct lov_oinfo *loi;
                __u32 *stripe = val;

                if (*vallen < sizeof(*stripe))
                        RETURN(-EFAULT);
                *vallen = sizeof(*stripe);

                /* XXX This is another one of those bits that will need to
                 * change if we ever actually support nested LOVs.  It uses
                 * the lock's export to find out which stripe it is. */
                for (i = 0, loi = data->lsm->lsm_oinfo;
                     i < data->lsm->lsm_stripe_count;
                     i++, loi++) {
                        if (lov->tgts[loi->loi_ost_idx].ltd_exp == 
                            data->lock->l_conn_export) {
                                *stripe = i;
                                RETURN(0);
                        }
                }
                RETURN(-ENXIO);
        } else if (keylen >= strlen("size_to_stripe") &&
                   strcmp(key, "size_to_stripe") == 0) {
                struct {
                        int stripe_number;
                        __u64 size;
                        struct lov_stripe_md *lsm;
                } *data = val;

                if (*vallen < sizeof(*data))
                        RETURN(-EFAULT);

                data->size = lov_size_to_stripe(data->lsm, data->size,
                                                data->stripe_number);
                RETURN(0);
        } else if (keylen >= strlen("last_id") && strcmp(key, "last_id") == 0) {
                obd_id *ids = val;
                int rc, size = sizeof(obd_id);
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        if (!lov->tgts[i].active)
                                continue;
                        rc = obd_get_info(lov->tgts[i].ltd_exp, keylen, key,
                                          &size, &(ids[i]));
                        if (rc != 0)
                                RETURN(rc);
                }
                RETURN(0);
        } else if (keylen >= strlen("lovdesc") && strcmp(key, "lovdesc") == 0) {
                struct lov_desc *desc_ret = val;
                *desc_ret = lov->desc;
                
                RETURN(0);
        }

        RETURN(-EINVAL);
}

static int lov_set_info(struct obd_export *exp, obd_count keylen,
                        void *key, obd_count vallen, void *val)
{
        struct obd_device *obddev = class_exp2obd(exp);
        struct lov_obd *lov = &obddev->u.lov;
        int i, rc = 0;
        ENTRY;

#define KEY_IS(str) \
        (keylen == strlen(str) && memcmp(key, str, keylen) == 0)

        if (KEY_IS("next_id")) {
                if (vallen != lov->desc.ld_tgt_count)
                        RETURN(-EINVAL);
                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                        int er;

                        /* initialize all OSCs, even inactive ones */

                        er = obd_set_info(lov->tgts[i].ltd_exp, keylen, key,
                                          sizeof(obd_id), ((obd_id*)val) + i);
                        if (!rc)
                                rc = er;
                }
                RETURN(rc);
        }

        if (KEY_IS("growth_count")) {
                if (vallen != sizeof(int))
                        RETURN(-EINVAL);
        } else if (KEY_IS("mds_conn") || KEY_IS("unlinked")) {
                if (vallen != 0)
                        RETURN(-EINVAL);
        } else {
                RETURN(-EINVAL);
        }

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int er;

                if (val && !obd_uuid_equals(val, &lov->tgts[i].uuid)) 
                        continue;

                if (!val && !lov->tgts[i].active)
                        continue;

                er = obd_set_info(lov->tgts[i].ltd_exp, keylen, key, vallen,
                                   val);
                if (!rc)
                        rc = er;
        }
        RETURN(rc);
#undef KEY_IS

}

/* Merge rss if kms == 0
 *
 * Even when merging RSS, we will take the KMS value if it's larger.
 * This prevents getattr from stomping on dirty cached pages which
 * extend the file size. */
__u64 lov_merge_size(struct lov_stripe_md *lsm, int kms)
{
        struct lov_oinfo *loi;
        __u64 size = 0;
        int i;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++) {
                obd_size lov_size, tmpsize;

                tmpsize = loi->loi_kms;
                if (kms == 0 && loi->loi_rss > tmpsize)
                        tmpsize = loi->loi_rss;

                lov_size = lov_stripe_size(lsm, tmpsize, i);
                if (lov_size > size)
                        size = lov_size;
        }
        return size;
}
EXPORT_SYMBOL(lov_merge_size);

__u64 lov_merge_mtime(struct lov_stripe_md *lsm, __u64 current_time)
{
        struct lov_oinfo *loi;
        int i;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++) {
                if (loi->loi_mtime > current_time)
                        current_time = loi->loi_mtime;
        }
        return current_time;
}
EXPORT_SYMBOL(lov_merge_mtime);

#if 0
struct lov_multi_wait {
        struct ldlm_lock *lock;
        wait_queue_t      wait;
        int               completed;
        int               generation;
};

int lov_complete_many(struct obd_export *exp, struct lov_stripe_md *lsm,
                      struct lustre_handle *lockh)
{
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_multi_wait *queues;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        if (!exp || !exp->exp_obd)
                RETURN(-ENODEV);

        LASSERT(lockh != NULL);
        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_handle2llh(lockh);
                if (lov_lockh == NULL) {
                        CERROR("LOV: invalid lov lock handle %p\n", lockh);
                        RETURN(-EINVAL);
                }

                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        OBD_ALLOC(queues, lsm->lsm_stripe_count * sizeof(*queues));
        if (queues == NULL)
                GOTO(out, rc = -ENOMEM);

        lov = &exp->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                struct ldlm_lock *lock;
                struct obd_device *obd;
                unsigned long irqflags;

                lock = ldlm_handle2lock(lov_lockhp);
                if (lock == NULL) {
                        CDEBUG(D_HA, "lov idx %d subobj "LPX64" no lock?\n",
                               loi->loi_ost_idx, loi->loi_id);
                        queues[i].completed = 1;
                        continue;
                }

                queues[i].lock = lock;
                init_waitqueue_entry(&(queues[i].wait), current);
                add_wait_queue(lock->l_waitq, &(queues[i].wait));

                obd = class_exp2obd(lock->l_conn_export);
                if (obd != NULL)
                        imp = obd->u.cli.cl_import;
                if (imp != NULL) {
                        spin_lock_irqsave(&imp->imp_lock, irqflags);
                        queues[i].generation = imp->imp_generation;
                        spin_unlock_irqrestore(&imp->imp_lock, irqflags);
                }
        }

        lwi = LWI_TIMEOUT_INTR(obd_timeout * HZ, ldlm_expired_completion_wait,
                               interrupted_completion_wait, &lwd);
        rc = l_wait_event_added(check_multi_complete(queues, lsm), &lwi);

        for (i = 0; i < lsm->lsm_stripe_count; i++)
                remove_wait_queue(lock->l_waitq, &(queues[i].wait));

        if (rc == -EINTR || rc == -ETIMEDOUT) {


        }

 out:
        if (lov_lockh != NULL)
                lov_llh_put(lov_lockh);
        RETURN(rc);
}
#endif

void lov_increase_kms(struct obd_export *exp, struct lov_stripe_md *lsm,
                      obd_off size)
{
        struct lov_oinfo *loi;
        int stripe = 0;
        __u64 kms;
        ENTRY;

        if (size > 0)
                stripe = lov_stripe_number(lsm, size - 1);
        kms = lov_size_to_stripe(lsm, size, stripe);
        loi = &(lsm->lsm_oinfo[stripe]);

        CDEBUG(D_INODE, "stripe %d KMS %sincreasing "LPU64"->"LPU64"\n",
               stripe, kms > loi->loi_kms ? "" : "not ", loi->loi_kms, kms);
        if (kms > loi->loi_kms)
                loi->loi_kms = kms;
        EXIT;
}
EXPORT_SYMBOL(lov_increase_kms);

struct obd_ops lov_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      lov_attach,
        o_detach:      lov_detach,
        o_setup:       lov_setup,
        o_cleanup:     lov_cleanup,
        o_connect:     lov_connect,
        o_disconnect:  lov_disconnect,
        o_statfs:      lov_statfs,
        o_packmd:      lov_packmd,
        o_unpackmd:    lov_unpackmd,
        o_create:      lov_create,
        o_destroy:     lov_destroy,
        o_getattr:     lov_getattr,
        o_getattr_async: lov_getattr_async,
        o_setattr:     lov_setattr,
        o_brw:         lov_brw,
        o_brw_async:   lov_brw_async,
        .o_prep_async_page =    lov_prep_async_page,
        .o_queue_async_io =     lov_queue_async_io,
        .o_set_async_flags =    lov_set_async_flags,
        .o_queue_group_io =     lov_queue_group_io,
        .o_trigger_group_io =   lov_trigger_group_io,
        .o_teardown_async_page  lov_teardown_async_page,
        o_punch:       lov_punch,
        o_sync:        lov_sync,
        o_enqueue:     lov_enqueue,
        o_match:       lov_match,
        o_change_cbdata: lov_change_cbdata,
        o_cancel:      lov_cancel,
        o_cancel_unused: lov_cancel_unused,
        o_iocontrol:   lov_iocontrol,
        o_get_info:    lov_get_info,
        o_set_info:    lov_set_info,
        o_llog_init:   lov_llog_init,
        o_llog_finish: lov_llog_finish,
        o_notify: lov_notify,
};

int __init lov_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        lprocfs_init_vars(lov, &lvars);
        rc = class_register_type(&lov_obd_ops, lvars.module_vars,
                                 OBD_LOV_DEVICENAME);
        RETURN(rc);
}

#ifdef __KERNEL__
static void /*__exit*/ lov_exit(void)
{
        class_unregister_type(OBD_LOV_DEVICENAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
#endif
