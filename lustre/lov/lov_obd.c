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
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_lite.h> /* for LL_IOC_LOV_[GS]ETSTRIPE */
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/seq_file.h>
#include <linux/lprocfs_status.h>

#include "lov_internal.h"

static int lov_stripe_offset(struct lov_stripe_md *lsm, obd_off lov_off,
                             int stripeno, obd_off *obd_off);

struct lov_file_handles {
        struct portals_handle lfh_handle;
        atomic_t lfh_refcount;
        struct list_head lfh_list;
        int lfh_count;
        struct obd_client_handle *lfh_och;
};

struct lov_lock_handles {
        struct portals_handle llh_handle;
        atomic_t llh_refcount;
        int llh_stripe_count;
        struct lustre_handle llh_handles[0];
};

/* lov_file_handles helpers */
static void lov_lfh_addref(void *lfhp)
{
        struct lov_file_handles *lfh = lfhp;

        atomic_inc(&lfh->lfh_refcount);
        CDEBUG(D_MALLOC, "GETting lfh %p : new refcount %d\n", lfh,
               atomic_read(&lfh->lfh_refcount));
}

static struct lov_file_handles *lov_lfh_new(void)
{
        struct lov_file_handles *lfh;

        OBD_ALLOC(lfh, sizeof *lfh);
        if (lfh == NULL) {
                CERROR("out of memory\n");
                return NULL;
        }

        atomic_set(&lfh->lfh_refcount, 2);

        INIT_LIST_HEAD(&lfh->lfh_handle.h_link);
        class_handle_hash(&lfh->lfh_handle, lov_lfh_addref);

        return lfh;
}

static struct lov_file_handles *lov_handle2lfh(struct lustre_handle *handle)
{
        ENTRY;
        LASSERT(handle != NULL);
        RETURN(class_handle2object(handle->cookie));
}

static void lov_lfh_put(struct lov_file_handles *lfh)
{
        CDEBUG(D_MALLOC, "PUTting lfh %p : new refcount %d\n", lfh,
               atomic_read(&lfh->lfh_refcount) - 1);
        LASSERT(atomic_read(&lfh->lfh_refcount) > 0 &&
                atomic_read(&lfh->lfh_refcount) < 0x5a5a);
        if (atomic_dec_and_test(&lfh->lfh_refcount)) {
                LASSERT(list_empty(&lfh->lfh_handle.h_link));
                OBD_FREE(lfh, sizeof *lfh);
        }
}

static void lov_lfh_destroy(struct lov_file_handles *lfh)
{
        class_handle_unhash(&lfh->lfh_handle);
        lov_lfh_put(lfh);
}

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
        struct proc_dir_entry *entry;
        int rc;

        lprocfs_init_vars(lov, &lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc)
                return rc;

        entry = create_proc_entry("target_obd", 0444, dev->obd_proc_entry);
        if (entry == NULL)
                RETURN(-ENOMEM);
        entry->proc_fops = &lov_proc_target_fops;
        entry->data = dev;

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
        struct client_obd *mdc = &lov->mdcobd->u.cli;
        struct lov_desc *desc = &lov->desc;
        struct lov_desc *mdesc;
        struct lov_tgt_desc *tgts;
        struct obd_export *exp;
        struct lustre_handle mdc_conn;
        struct obd_uuid lov_mds_uuid = {"LOV_MDS_UUID"};
        struct obd_uuid *uuids;
        int rc, rc2, i;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        exp = class_conn2export(conn);
        spin_lock_init(&exp->exp_lov_data.led_lock);
        INIT_LIST_HEAD(&exp->exp_lov_data.led_open_head);

        /* We don't want to actually do the underlying connections more than
         * once, so keep track. */
        lov->refcount++;
        if (lov->refcount > 1) {
                class_export_put(exp);
                RETURN(0);
        }

        /* retrieve LOV metadata from MDS */
        rc = obd_connect(&mdc_conn, lov->mdcobd, &lov_mds_uuid);
        if (rc) {
                CERROR("cannot connect to mdc: rc = %d\n", rc);
                GOTO(out_conn, rc);
        }

        rc = mdc_getlovinfo(obd, &mdc_conn, &req);
        rc2 = obd_disconnect(&mdc_conn, 0);
        if (rc) {
                CERROR("cannot get lov info %d\n", rc);
                GOTO(out_conn, rc);
        }

        if (rc2) {
                CERROR("error disconnecting from MDS %d\n", rc2);
                GOTO(out_req, rc = rc2);
        }

        /* mdc_getlovinfo() has checked and swabbed the reply.  It has also
         * done some simple checks (e.g. #uuids consistent with desc, uuid
         * array fits in LOV_MAX_UUID_BUFFER_SIZE and all uuids are
         * terminated), but I still need to verify it makes overall
         * sense */
        mdesc = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*mdesc));
        LASSERT(mdesc != NULL);
        LASSERT_REPSWABBED(req, 0);

        *desc = *mdesc;

        /* XXX We need a separate LOV 'service' UUID from the client device
         *     UUID so that we can mount more than once on a client */
        if (!obd_uuid_equals(&obd->obd_uuid, &desc->ld_uuid)) {
                CERROR("LOV desc: uuid %s not on mds device (%s)\n",
                       obd->obd_uuid.uuid, desc->ld_uuid.uuid);
                GOTO(out_req, rc = -EINVAL);
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
                GOTO(out_req, rc = -EINVAL);
        }

        /* We know ld_tgt_count is reasonable (the array of UUIDS fits in
         * the maximum buffer size, so we won't be making outrageous
         * demands on memory here. */
        lov->bufsize = sizeof(struct lov_tgt_desc) * desc->ld_tgt_count;
        OBD_ALLOC(lov->tgts, lov->bufsize);
        if (lov->tgts == NULL) {
                CERROR("Out of memory\n");
                GOTO(out_req, rc = -ENOMEM);
        }

        uuids = lustre_msg_buf(req->rq_repmsg, 1,
                               sizeof(*uuids) * desc->ld_tgt_count);
        LASSERT(uuids != NULL);
        LASSERT_REPSWABBED(req, 1);

        for (i = 0, tgts = lov->tgts; i < desc->ld_tgt_count; i++, tgts++) {
                struct obd_uuid *uuid = &tgts->uuid;
                struct obd_device *tgt_obd;
                struct obd_uuid lov_osc_uuid = { "LOV_OSC_UUID" };

                /* NULL termination already checked */
                *uuid = uuids[i];

                tgt_obd = client_tgtuuid2obd(uuid);

                if (!tgt_obd) {
                        CERROR("Target %s not attached\n", uuid->uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                if (!tgt_obd->obd_set_up) {
                        CERROR("Target %s not set up\n", uuid->uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                rc = obd_connect(&tgts->conn, tgt_obd, &lov_osc_uuid);

                if (rc) {
                        CERROR("Target %s connect error %d\n", uuid->uuid, rc);
                        GOTO(out_disc, rc);
                }

                rc = obd_iocontrol(IOC_OSC_REGISTER_LOV, &tgts->conn,
                                   sizeof(struct obd_device *), obd, NULL);
                if (rc) {
                        CERROR("Target %s REGISTER_LOV error %d\n",
                               uuid->uuid, rc);
                        obd_disconnect(&tgts->conn, 0);
                        GOTO(out_disc, rc);
                }

                desc->ld_active_tgt_count++;
                tgts->active = 1;
        }

        mdc->cl_max_mds_easize = obd_size_diskmd(conn, NULL);
        mdc->cl_max_mds_cookiesize = desc->ld_tgt_count *
                sizeof(struct llog_cookie);
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
                rc2 = obd_disconnect(&tgts->conn, 0);
                if (rc2)
                        CERROR("error: LOV target %s disconnect on OST idx %d: "
                               "rc = %d\n", uuid.uuid, i, rc2);
        }
        OBD_FREE(lov->tgts, lov->bufsize);
 out_req:
        ptlrpc_req_finished (req);
 out_conn:
        class_export_put(exp);
        class_disconnect(conn, 0);
        RETURN (rc);
}

static int lov_disconnect(struct lustre_handle *conn, int flags)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct obd_export *exp;
        struct list_head *p, *n;
        int rc, i;
        ENTRY;

        if (!lov->tgts)
                goto out_local;

        /* Only disconnect the underlying layers on the final disconnect. */
        lov->refcount--;
        if (lov->refcount != 0)
                goto out_local;

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                if (obd->obd_no_recov) {
                        /* Pass it on to our clients.
                         * XXX This should be an argument to disconnect,
                         * XXX not a back-door flag on the OBD.  Ah well.
                         */
                        struct obd_device *osc_obd =
                                class_conn2obd(&lov->tgts[i].conn);
                        osc_obd->obd_no_recov = 1;
                }
                rc = obd_disconnect(&lov->tgts[i].conn, flags);
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

 out_local:
        exp = class_conn2export(conn);
        if (exp == NULL) {
                CERROR("export handle "LPU64" invalid!  If you can reproduce, "
                       "please send a full debug log to phik\n", conn->cookie);
                RETURN(0);
        }
        spin_lock(&exp->exp_lov_data.led_lock);
        list_for_each_safe(p, n, &exp->exp_lov_data.led_open_head) {
                /* XXX close these, instead of just discarding them? */
                struct lov_file_handles *lfh;
                lfh = list_entry(p, typeof(*lfh), lfh_list);
                CERROR("discarding open LOV handle %p:"LPX64"\n",
                       lfh, lfh->lfh_handle.h_cookie);
                list_del(&lfh->lfh_list);
                OBD_FREE(lfh->lfh_och, lfh->lfh_count * FD_OSTDATA_SIZE);
                lov_lfh_destroy(lfh);
                lov_lfh_put(lfh);
        }
        spin_unlock(&exp->exp_lov_data.led_lock);
        class_export_put(exp);

        rc = class_disconnect(conn, 0);
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
                       i, tgt->uuid.uuid, tgt->conn.cookie);
                if (strncmp(uuid->uuid, tgt->uuid.uuid, sizeof uuid->uuid) == 0)
                        break;
        }

        if (i == lov->desc.ld_tgt_count)
                GOTO(out, rc = -EINVAL);

        obd = class_conn2obd(&tgt->conn);
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
        int rc = 0;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("LOV setup requires an MDC name\n");
                RETURN(-EINVAL);
        }

        spin_lock_init(&lov->lov_lock);
        lov->mdcobd = class_name2obd(data->ioc_inlbuf1);
        if (!lov->mdcobd) {
                CERROR("LOV %s cannot locate MDC %s\n", obd->obd_uuid.uuid,
                       data->ioc_inlbuf1);
                rc = -EINVAL;
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

/* the LOV expects oa->o_id to be set to the LOV object id */
static int lov_create(struct lustre_handle *conn, struct obdo *src_oa,
                      struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_stripe_md *lsm;
        struct lov_oinfo *loi = NULL;
        struct obdo *tmp_oa, *ret_oa;
        struct llog_cookie *cookies = NULL;
        unsigned ost_count, ost_idx;
        int set = 0, obj_alloc = 0, cookie_sent = 0, rc = 0, i;
        ENTRY;

        LASSERT(ea);

        if (!export)
                RETURN(-EINVAL);

        lov = &export->exp_obd->u.lov;

        if (!lov->desc.ld_active_tgt_count)
                GOTO(out_exp, rc = -EIO);

        ret_oa = obdo_alloc();
        if (!ret_oa)
                GOTO(out_exp, rc = -ENOMEM);

        tmp_oa = obdo_alloc();
        if (!tmp_oa)
                GOTO(out_oa, rc = -ENOMEM);

        lsm = *ea;

        if (!lsm) {
                int stripes;
                ost_count = lov_get_stripecnt(lov, 0);

                /* If the MDS file was truncated up to some size, stripe over
                 * enough OSTs to allow the file to be created at that size.
                 */
                if (src_oa->o_valid & OBD_MD_FLSIZE) {
                        stripes=((src_oa->o_size+LUSTRE_STRIPE_MAXBYTES)>>12)-1;
                        do_div(stripes, (__u32)(LUSTRE_STRIPE_MAXBYTES >> 12));

                        if (stripes > lov->desc.ld_active_tgt_count)
                                GOTO(out_exp, rc = -EFBIG);
                        if (stripes < ost_count)
                                stripes = ost_count;
                } else
                        stripes = ost_count;

                rc = lov_alloc_memmd(&lsm, stripes);
                if (rc < 0)
                        GOTO(out_tmp, rc);

                rc = 0;
        }

        ost_count = lov->desc.ld_tgt_count;

        LASSERT(src_oa->o_valid & OBD_MD_FLID);
        lsm->lsm_object_id = src_oa->o_id;
        if (!lsm->lsm_stripe_size)
                lsm->lsm_stripe_size = lov->desc.ld_default_stripe_size;

        if (!*ea || lsm->lsm_stripe_offset >= ost_count) {
                get_random_bytes(&ost_idx, 2);
                ost_idx %= ost_count;
        } else {
                ost_idx = lsm->lsm_stripe_offset;
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
                err = obd_create(&lov->tgts[ost_idx].conn, tmp_oa,&obj_mdp,oti);
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
                loi->loi_id = tmp_oa->o_id;
                loi->loi_ost_idx = ost_idx;
                CDEBUG(D_INODE, "objid "LPX64" has subobj "LPX64" at idx %d\n",
                       lsm->lsm_object_id, loi->loi_id, ost_idx);

                if (set == 0)
                        lsm->lsm_stripe_offset = ost_idx;
                lov_merge_attrs(ret_oa, tmp_oa, tmp_oa->o_valid, lsm,
                                obj_alloc, &set);
                loi->loi_dirty_ot = &loi->loi_dirty_ot_inline;
                ot_init(loi->loi_dirty_ot);

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

                CERROR("reallocating LSM for objid "LPX64": old %u new %u\n",
                       lsm->lsm_object_id, lsm->lsm_stripe_count, obj_alloc);
                oldsize = lov_stripe_md_size(lsm->lsm_stripe_count);
                newsize = lov_stripe_md_size(obj_alloc);
                OBD_ALLOC(lsm_new, newsize);
                if (lsm_new != NULL) {
                        memcpy(lsm_new, lsm, newsize);
                        lsm_new->lsm_stripe_count = obj_alloc;
                        OBD_FREE(lsm, newsize);
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
 out_exp:
        class_export_put(export);
        return rc;

 out_cleanup:
        while (obj_alloc-- > 0) {
                int err;

                --loi;
                /* destroy already created objects here */
                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                tmp_oa->o_id = loi->loi_id;

                if (oti && cookie_sent) {
                        err = obd_log_cancel(&lov->tgts[loi->loi_ost_idx].conn,
                                             NULL, 1, --oti->oti_logcookies,
                                             OBD_LLOG_FL_SENDNOW);
                        if (err)
                                CERROR("Failed to cancel objid "LPX64" subobj "
                                       LPX64" cookie on OST idx %d: rc = %d\n",
                                       src_oa->o_id, loi->loi_id,
                                       loi->loi_ost_idx, err);
                }

                err = obd_destroy(&lov->tgts[loi->loi_ost_idx].conn, tmp_oa,
                                  NULL, oti);
                if (err)
                        CERROR("Failed to uncreate objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", src_oa->o_id,
                               loi->loi_id, loi->loi_ost_idx, err);
        }
        if (*ea == NULL)
                obd_free_memmd(conn, &lsm);
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

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

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
                        memcpy(obdo_handle(&tmp), &lfh->lfh_och[i].och_fh,
                               sizeof(lfh->lfh_och[i].och_fh));
                else
                        tmp.o_valid &= ~OBD_MD_FLHANDLE;
                err = obd_destroy(&lov->tgts[loi->loi_ost_idx].conn, &tmp,
                                  NULL, oti);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: destroying objid "LPX64" subobj "
                               LPX64" on OST idx %d: rc = %d\n",
                               oa->o_id, loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        if (lfh != NULL)
                lov_lfh_put(lfh);
        EXIT;
 out:
        class_export_put(export);
        return rc;
}

static int lov_getattr(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *lsm)
{
        struct obdo tmp;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int i, rc = 0, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

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
                        memcpy(obdo_handle(&tmp), &lfh->lfh_och[i].och_fh,
                               sizeof(lfh->lfh_och[i].och_fh));
                else
                        tmp.o_valid &= ~OBD_MD_FLHANDLE;

                err = obd_getattr(&lov->tgts[loi->loi_ost_idx].conn, &tmp,NULL);
                if (err) {
                        if (lov->tgts[loi->loi_ost_idx].active) {
                                CERROR("error: getattr objid "LPX64" subobj "
                                       LPX64" on OST idx %d: rc = %d\n",
                                       oa->o_id, loi->loi_id, loi->loi_ost_idx,
                                       err);
                                GOTO(out, rc = err);
                        }
                } else {
                        lov_merge_attrs(oa, &tmp, tmp.o_valid, lsm, i, &set);
                }
        }
        if (!set)
                rc = -EIO;
        GOTO(out, rc);
 out:
        if (lfh != NULL)
                lov_lfh_put(lfh);
        class_export_put(export);
        return rc;
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

static int lov_getattr_async (struct lustre_handle *conn, struct obdo *oa,
                              struct lov_stripe_md *lsm,
                              struct ptlrpc_request_set *rqset)
{
        struct obdo *obdos;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        struct lov_getattr_async_args *aa;
        int i;
        int set = 0;
        int rc = 0;
        ENTRY;

        if (!lsm) {
                CERROR("LOV requires striping ea\n");
                GOTO(out, rc = -EINVAL);
        }

        if (lsm->lsm_magic != LOV_MAGIC) {
                CERROR("LOV striping magic bad %#x != %#x\n",
                       lsm->lsm_magic, LOV_MAGIC);
                GOTO(out, rc = -EINVAL);
        }

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

        lov = &export->exp_obd->u.lov;

        OBD_ALLOC (obdos, lsm->lsm_stripe_count * sizeof (*obdos));
        if (obdos == NULL)
                GOTO (out, rc = -ENOMEM);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

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
                if (lfh)
                        memcpy(obdo_handle(&obdos[i]), &lfh->lfh_och[i].och_fh,
                               sizeof(lfh->lfh_och[i].och_fh));
                else
                        obdos[i].o_valid &= ~OBD_MD_FLHANDLE;

                err = obd_getattr_async (&lov->tgts[loi->loi_ost_idx].conn,
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
        GOTO (out, rc = 0);

 out_obdos:
        OBD_FREE (obdos, lsm->lsm_stripe_count * sizeof (*obdos));
 out:
        if (lfh != NULL)
                lov_lfh_put(lfh);
        class_export_put(export);
        RETURN (rc);
}

static int lov_setattr(struct lustre_handle *conn, struct obdo *src_oa,
                       struct lov_stripe_md *lsm, struct obd_trans_info *oti)
{
        struct obdo *tmp_oa, *ret_oa;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int rc = 0, i, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

        /* for now, we only expect time updates here */
        LASSERT(!(src_oa->o_valid & ~(OBD_MD_FLID|OBD_MD_FLTYPE|OBD_MD_FLMODE|
                                      OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                      OBD_MD_FLCTIME)));
        ret_oa = obdo_alloc();
        if (!ret_oa)
                GOTO(out, rc = -ENOMEM);

        tmp_oa = obdo_alloc();
        if (!tmp_oa)
                GOTO(out_oa, rc = -ENOMEM);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));

                if (lfh)
                        memcpy(obdo_handle(tmp_oa), &lfh->lfh_och[i].och_fh,
                               sizeof(lfh->lfh_och[i].och_fh));
                else
                        tmp_oa->o_valid &= ~OBD_MD_FLHANDLE;

                tmp_oa->o_id = loi->loi_id;

                err = obd_setattr(&lov->tgts[loi->loi_ost_idx].conn, tmp_oa,
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
        if (lfh != NULL)
                lov_lfh_put(lfh);

        ret_oa->o_id = src_oa->o_id;
        memcpy(src_oa, ret_oa, sizeof(*src_oa));
        GOTO(out_tmp, rc);
out_tmp:
        obdo_free(tmp_oa);
out_oa:
        obdo_free(ret_oa);
out:
        class_export_put(export);
        return rc;
}

static int lov_open(struct lustre_handle *conn, struct obdo *src_oa,
                    struct lov_stripe_md *lsm, struct obd_trans_info *oti,
                    struct obd_client_handle *och)
{
        struct obdo *tmp_oa, *ret_oa;
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_file_handles *lfh = NULL;
        int set = 0, rc = 0, i;
        ENTRY;
        LASSERT(och != NULL);

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out_exp, rc = -ENODEV);

        ret_oa = obdo_alloc();
        if (!ret_oa)
                GOTO(out_exp, rc = -ENOMEM);

        tmp_oa = obdo_alloc();
        if (!tmp_oa)
                GOTO(out_oa, rc = -ENOMEM);

        lfh = lov_lfh_new();
        if (lfh == NULL)
                GOTO(out_tmp, rc = -ENOMEM);
        OBD_ALLOC(lfh->lfh_och, lsm->lsm_stripe_count * sizeof(*och));
        if (!lfh->lfh_och)
                GOTO(out_lfh, rc = -ENOMEM);

        lov = &export->exp_obd->u.lov;
        src_oa->o_size = 0;
        src_oa->o_blocks = 0;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                /* create data objects with "parent" OA */
                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                tmp_oa->o_id = loi->loi_id;

                rc = obd_open(&lov->tgts[loi->loi_ost_idx].conn, tmp_oa,
                              NULL, NULL, &lfh->lfh_och[i]);
                if (rc) {
                        if (!lov->tgts[loi->loi_ost_idx].active) {
                                rc = 0;
                                continue;
                        }
                        CERROR("error: open objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n",
                               src_oa->o_id, lsm->lsm_oinfo[i].loi_id,
                               loi->loi_ost_idx, rc);
                        goto out_handles;
                }

                lov_merge_attrs(ret_oa, tmp_oa, tmp_oa->o_valid, lsm, i, &set);
        }

        lfh->lfh_count = lsm->lsm_stripe_count;
        och->och_fh.cookie = lfh->lfh_handle.h_cookie;
        obdo_handle(ret_oa)->cookie = lfh->lfh_handle.h_cookie;
        ret_oa->o_valid |= OBD_MD_FLHANDLE;
        ret_oa->o_id = src_oa->o_id;
        memcpy(src_oa, ret_oa, sizeof(*src_oa));

        /* lfh refcount transfers to list */
        spin_lock(&export->exp_lov_data.led_lock);
        list_add(&lfh->lfh_list, &export->exp_lov_data.led_open_head);
        spin_unlock(&export->exp_lov_data.led_lock);

        GOTO(out_tmp, rc);
 out_tmp:
        obdo_free(tmp_oa);
 out_oa:
        obdo_free(ret_oa);
 out_exp:
        class_export_put(export);
        return rc;

 out_handles:
        for (i--, loi = &lsm->lsm_oinfo[i]; i >= 0; i--, loi--) {
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        continue;

                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                tmp_oa->o_id = loi->loi_id;
                memcpy(obdo_handle(tmp_oa), &lfh->lfh_och[i], FD_OSTDATA_SIZE);

                err = obd_close(&lov->tgts[loi->loi_ost_idx].conn, tmp_oa,
                                NULL, NULL);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: closing objid "LPX64" subobj "LPX64
                               " on OST idx %d after open error: rc=%d\n",
                               src_oa->o_id, loi->loi_id, loi->loi_ost_idx,err);
                }
        }

        OBD_FREE(lfh->lfh_och, lsm->lsm_stripe_count * FD_OSTDATA_SIZE);
 out_lfh:
        lov_lfh_destroy(lfh);
        lov_lfh_put(lfh);
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

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));
        if (!lfh)
                LBUG();

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                int err;

                /* create data objects with "parent" OA */
                memcpy(&tmp, oa, sizeof(tmp));
                tmp.o_id = loi->loi_id;
                if (lfh)
                        memcpy(obdo_handle(&tmp), &lfh->lfh_och[i],
                               FD_OSTDATA_SIZE);
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
        if (lfh != NULL) {
                spin_lock(&export->exp_lov_data.led_lock);
                list_del(&lfh->lfh_list);
                spin_unlock(&export->exp_lov_data.led_lock);
                lov_lfh_put(lfh); /* drop the reference owned by the list */

                OBD_FREE(lfh->lfh_och, lsm->lsm_stripe_count * FD_OSTDATA_SIZE);
                lov_lfh_destroy(lfh);
                LASSERT(atomic_read(&lfh->lfh_refcount) == 1);
                lov_lfh_put(lfh); /* balance handle2lfh above */
        } else
                LBUG();
        GOTO(out, rc);
 out:
        class_export_put(export);
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

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

        if (oa->o_valid & OBD_MD_FLHANDLE)
                lfh = lov_handle2lfh(obdo_handle(oa));

        lov = &export->exp_obd->u.lov;
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
                if (lfh)
                        memcpy(obdo_handle(&tmp), &lfh->lfh_och[i].och_fh,
                               sizeof(lfh->lfh_och[i].och_fh));
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
        if (lfh != NULL)
                lov_lfh_put(lfh);
        GOTO(out, rc);
 out:
        class_export_put(export);
        return rc;
}

static int lov_brw_check(struct lov_obd *lov, struct lov_stripe_md *lsm,
                         obd_count oa_bufs, struct brw_page *pga)
{
        int i;

        /* The caller just wants to know if there's a chance that this
         * I/O can succeed */
        for (i = 0; i < oa_bufs; i++) {
                int stripe = lov_stripe_number(lsm, pga[i].off);
                int ost = lsm->lsm_oinfo[stripe].loi_ost_idx;
                struct ldlm_extent ext, subext;
                ext.start = pga[i].off;
                ext.start = pga[i].off + pga[i].count;

                if (!lov_stripe_intersects(lsm, i, ext.start, ext.end,
                                           &subext.start, &subext.end))
                        continue;

                if (lov->tgts[ost].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", ost);
                        return -EIO;
                }
        }
        return 0;
}

static int lov_brw(int cmd, struct lustre_handle *conn, struct obdo *src_oa,
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
        struct obd_export *export = class_conn2export(conn);
        struct obdo *ret_oa = NULL, *tmp_oa = NULL;
        struct lov_file_handles *lfh = NULL;
        struct lov_obd *lov;
        struct brw_page *ioarr;
        struct lov_oinfo *loi;
        int rc = 0, i, *where, stripe_count = lsm->lsm_stripe_count, set = 0;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        lov = &export->exp_obd->u.lov;

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, lsm, oa_bufs, pga);
                GOTO(out_exp, rc);
        }

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                GOTO(out_exp, rc = -ENOMEM);

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

                if (src_oa->o_valid & OBD_MD_FLHANDLE)
                        lfh = lov_handle2lfh(obdo_handle(src_oa));
                else
                        src_oa->o_valid &= ~OBD_MD_FLHANDLE;
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
                        if (src_oa) {
                                memcpy(tmp_oa, src_oa, sizeof(*tmp_oa));
                                if (lfh)
                                        memcpy(obdo_handle(tmp_oa),
                                               &lfh->lfh_och[i].och_fh,
                                               sizeof(lfh->lfh_och[i].och_fh));
                        }

                        tmp_oa->o_id = si->lsm.lsm_object_id;
                        rc = obd_brw(cmd, &lov->tgts[si->ost_idx].conn, tmp_oa,
                                     &si->lsm, si->bufct, &ioarr[shift],
                                     oti);
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
        if (lfh)
                lov_lfh_put(lfh);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
 out_exp:
        class_export_put(export);
        return rc;
}

static int lov_brw_interpret(struct ptlrpc_request_set *rqset,
                             struct lov_brw_async_args *aa, int rc)
{
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

static int lov_brw_async(int cmd, struct lustre_handle *conn, struct obdo *oa,
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
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_file_handles *lfh = NULL;
        struct brw_page *ioarr;
        struct obdo *obdos = NULL;
        struct lov_oinfo *loi;
        struct lov_brw_async_args *aa;
        int rc = 0, i, *where, stripe_count = lsm->lsm_stripe_count;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        lov = &export->exp_obd->u.lov;

        if (cmd == OBD_BRW_CHECK) {
                rc = lov_brw_check(lov, lsm, oa_bufs, pga);
                GOTO(out_exp, rc);
        }

        OBD_ALLOC(stripeinfo, stripe_count * sizeof(*stripeinfo));
        if (!stripeinfo)
                GOTO(out_exp, rc = -ENOMEM);

        OBD_ALLOC(where, sizeof(*where) * oa_bufs);
        if (!where)
                GOTO(out_sinfo, rc = -ENOMEM);

        if (oa) {
                OBD_ALLOC(obdos, sizeof(*obdos) * stripe_count);
                if (!obdos)
                        GOTO(out_where, rc = -ENOMEM);

                if (oa->o_valid & OBD_MD_FLHANDLE)
                        lfh = lov_handle2lfh(obdo_handle(oa));
                else
                        oa->o_valid &= ~OBD_MD_FLHANDLE;
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
                        if (lfh)
                                memcpy(obdo_handle(&obdos[i]),
                                       &lfh->lfh_och[i].och_fh,
                                       sizeof(lfh->lfh_och[i].och_fh));
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

                rc = obd_brw_async(cmd, &lov->tgts[si->ost_idx].conn,
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
        if (lfh)
                lov_lfh_put(lfh);
 out_sinfo:
        OBD_FREE(stripeinfo, stripe_count * sizeof(*stripeinfo));
 out_exp:
        class_export_put(export);
        return rc;
}

static int lov_enqueue(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                       struct lustre_handle *parent_lock,
                       __u32 type, void *cookie, int cookielen, __u32 mode,
                       int *flags, void *cb, void *data,
                       struct lustre_handle *lockh)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_stripe_md submd;
        ldlm_error_t rc;
        int i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        /* we should never be asked to replay a lock this way. */
        LASSERT((*flags & LDLM_FL_REPLAY) == 0);

        if (!export || !export->exp_obd)
                GOTO(out_exp, rc = -ENODEV);

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_llh_new(lsm);
                if (lov_lockh == NULL)
                        GOTO(out_exp, rc = -ENOMEM);

                lockh->cookie = lov_lockh->llh_handle.h_cookie;
                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        lov = &export->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                struct ldlm_extent *extent = (struct ldlm_extent *)cookie;
                struct ldlm_extent sub_ext;

                *flags = 0;
                if (!lov_stripe_intersects(lsm, i, extent->start, extent->end,
                                           &sub_ext.start, &sub_ext.end))
                        continue;

                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                /* XXX submd is not fully initialized here */
                *flags = 0;
                rc = obd_enqueue(&(lov->tgts[loi->loi_ost_idx].conn), &submd,
                                  parent_lock, type, &sub_ext, sizeof(sub_ext),
                                  mode, flags, cb, data, lov_lockhp);

                // XXX add a lock debug statement here
                if (rc != ELDLM_OK) {
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
        GOTO(out_exp, rc = ELDLM_OK);

 out_locks:
        while (loi--, lov_lockhp--, i-- > 0) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->cookie == 0)
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
                lov_llh_destroy(lov_lockh);
                lov_llh_put(lov_lockh);
        }
 out_exp:
        class_export_put(export);
        return(rc);
}

static int lov_match(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                     __u32 type, void *cookie, int cookielen, __u32 mode,
                     int *flags, void *data, struct lustre_handle *lockh)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_lock_handles *lov_lockh = NULL;
        struct lustre_handle *lov_lockhp;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        struct lov_stripe_md submd;
        ldlm_error_t rc = 0;
        int i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out_exp, rc = -ENODEV);

        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_llh_new(lsm);
                if (lov_lockh == NULL)
                        GOTO(out_exp, rc = -ENOMEM);

                lockh->cookie = lov_lockh->llh_handle.h_cookie;
                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        lov = &export->exp_obd->u.lov;
        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count;
             i++, loi++, lov_lockhp++) {
                struct ldlm_extent *extent = (struct ldlm_extent *)cookie;
                struct ldlm_extent sub_ext;
                int lov_flags;

                if (!lov_stripe_intersects(lsm, i, extent->start, extent->end,
                                           &sub_ext.start, &sub_ext.end))
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
                rc = obd_match(&(lov->tgts[loi->loi_ost_idx].conn), &submd,
                               type, &sub_ext, sizeof(sub_ext), mode,
                               &lov_flags, data, lov_lockhp);
                if (rc != 1)
                        break;
        }
        if (rc == 1) {
                if (lsm->lsm_stripe_count > 1)
                        lov_llh_put(lov_lockh);
                GOTO(out_exp, 1);
        }

        while (loi--, lov_lockhp--, i-- > 0) {
                struct lov_stripe_md submd;
                int err;

                if (lov_lockhp->cookie == 0)
                        continue;

                /* XXX LOV STACKING: submd should be from the subobj */
                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel(&lov->tgts[loi->loi_ost_idx].conn, &submd,
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
 out_exp:
        class_export_put(export);
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

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

        LASSERT(lockh);
        if (lsm->lsm_stripe_count > 1) {
                lov_lockh = lov_handle2llh(lockh);
                if (!lov_lockh) {
                        CERROR("LOV: invalid lov lock handle %p\n", lockh);
                        GOTO(out, rc = -EINVAL);
                }

                lov_lockhp = lov_lockh->llh_handles;
        } else {
                lov_lockhp = lockh;
        }

        lov = &export->exp_obd->u.lov;
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

        if (lsm->lsm_stripe_count > 1)
                lov_llh_destroy(lov_lockh);
        if (lov_lockh != NULL)
                lov_llh_put(lov_lockh);
        GOTO(out, rc);
 out:
        class_export_put(export);
        return rc;
}

static int lov_cancel_unused(struct lustre_handle *conn,
                             struct lov_stripe_md *lsm, int flags, void *opaque)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out, rc = -ENODEV);

        lov = &export->exp_obd->u.lov;
        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                struct lov_stripe_md submd;
                int err;

                if (lov->tgts[loi->loi_ost_idx].active == 0)
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);

                submd.lsm_object_id = loi->loi_id;
                submd.lsm_stripe_count = 0;
                err = obd_cancel_unused(&lov->tgts[loi->loi_ost_idx].conn,
                                        &submd, flags, opaque);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: cancel unused objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        GOTO(out, rc);
 out:
        class_export_put(export);
        return rc;
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

                err = obd_statfs(class_conn2obd(&lov->tgts[i].conn), &lov_sfs,
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
                obd_ioctl_freedata(buf, len);
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

static int lov_get_info(struct lustre_handle *conn, __u32 keylen,
                        void *key, __u32 *vallen, void *val)
{
        struct obd_device *obddev = class_conn2obd(conn);
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
                __u32 *stripe = val;
                struct lov_oinfo *loi;

                if (*vallen < sizeof(*stripe))
                        RETURN(-EFAULT);
                *vallen = sizeof(*stripe);

                /* XXX This is another one of those bits that will need to
                 * change if we ever actually support nested LOVs.  It uses
                 * the lock's connection to find out which stripe it is. */
                for (i = 0, loi = data->lsm->lsm_oinfo;
                     i < data->lsm->lsm_stripe_count;
                     i++, loi++) {
                        if (lov->tgts[loi->loi_ost_idx].conn.cookie ==
                            data->lock->l_connh->cookie) {
                                *stripe = i;
                                RETURN(0);
                        }
                }
                RETURN(-ENXIO);
        }

        RETURN(-EINVAL);
}

static int lov_set_info(struct lustre_handle *conn, obd_count keylen,
                        void *key, obd_count vallen, void *val)
{
        struct obd_device *obddev = class_conn2obd(conn);
        struct lov_obd *lov = &obddev->u.lov;
        int i, rc = 0;
        ENTRY;

        if (keylen < strlen("mds_conn") ||
            memcmp(key, "mds_conn", strlen("mds_conn")) != 0)
                RETURN(-EINVAL);

        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                int er;
                er = obd_set_info(&lov->tgts[i].conn, keylen, key, vallen, val);
                if (!rc)
                        rc = er;
        }
        RETURN(rc);
}

static int lov_mark_page_dirty(struct lustre_handle *conn,
                               struct lov_stripe_md *lsm, unsigned long offset)
{
        struct lov_obd *lov = &class_conn2obd(conn)->u.lov;
        struct lov_oinfo *loi;
        struct lov_stripe_md *submd;
        int stripe, rc;
        obd_off off;
        ENTRY;

        if (lsm_bad_magic(lsm))
                RETURN(-EINVAL);

        OBD_ALLOC(submd, lov_stripe_md_size(1));
        if (submd == NULL)
                RETURN(-ENOMEM);

        stripe = lov_stripe_number(lsm, (obd_off)offset << PAGE_CACHE_SHIFT);
        lov_stripe_offset(lsm, (obd_off)offset << PAGE_CACHE_SHIFT, stripe,
                          &off);
        off >>= PAGE_CACHE_SHIFT;

        loi = &lsm->lsm_oinfo[stripe];
        CDEBUG(D_INODE, "off %lu => off %lu on stripe %d\n", offset,
               (unsigned long)off, stripe);
        submd->lsm_oinfo[0].loi_dirty_ot = &loi->loi_dirty_ot_inline;

        rc = obd_mark_page_dirty(&lov->tgts[loi->loi_ost_idx].conn, submd, off);
        OBD_FREE(submd, lov_stripe_md_size(1));
        RETURN(rc);
}

static int lov_clear_dirty_pages(struct lustre_handle *conn,
                                 struct lov_stripe_md *lsm, unsigned long start,
                                 unsigned long end, unsigned long *cleared)

{
        struct obd_export *export = class_conn2export(conn);
        __u64 start_off = (__u64)start << PAGE_CACHE_SHIFT;
        __u64 end_off = (__u64)end << PAGE_CACHE_SHIFT;
        __u64 obd_start, obd_end;
        struct lov_stripe_md *submd = NULL;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int i, rc;
        unsigned long osc_cleared;
        ENTRY;

        *cleared = 0;

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out_exp, rc = -ENODEV);

        OBD_ALLOC(submd, lov_stripe_md_size(1));
        if (submd == NULL)
                GOTO(out_exp, rc = -ENOMEM);

        lov = &export->exp_obd->u.lov;
        rc = 0;
        for (i = 0, loi = lsm->lsm_oinfo;
             i < lsm->lsm_stripe_count;
             i++, loi++) {
                if (lov->tgts[loi->loi_ost_idx].active == 0) {
                        CDEBUG(D_HA, "lov idx %d inactive\n", loi->loi_ost_idx);
                        continue;
                }

                if(!lov_stripe_intersects(lsm, i, start_off, end_off,
                                          &obd_start, &obd_end))
                        continue;
                obd_start >>= PAGE_CACHE_SHIFT;
                obd_end >>= PAGE_CACHE_SHIFT;

                CDEBUG(D_INODE, "offs [%lu,%lu] => offs [%lu,%lu] stripe %d\n",
                       start, end, (unsigned long)obd_start,
                       (unsigned long)obd_end, loi->loi_ost_idx);
                submd->lsm_oinfo[0].loi_dirty_ot = &loi->loi_dirty_ot_inline;
                rc = obd_clear_dirty_pages(&lov->tgts[loi->loi_ost_idx].conn,
                                           submd, obd_start, obd_end,
                                           &osc_cleared);
                if (rc)
                        break;
                *cleared += osc_cleared;
        }
out_exp:
        if (submd)
                OBD_FREE(submd, lov_stripe_md_size(1));
        class_export_put(export);
        RETURN(rc);
}

static int lov_last_dirty_offset(struct lustre_handle *conn,
                                 struct lov_stripe_md *lsm,
                                 unsigned long *offset)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_stripe_md *submd = NULL;
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        unsigned long tmp, count, skip;
        int err, i, rc;
        ENTRY;

        if (lsm_bad_magic(lsm))
                GOTO(out_exp, rc = -EINVAL);

        if (!export || !export->exp_obd)
                GOTO(out_exp, rc = -ENODEV);

        OBD_ALLOC(submd, lov_stripe_md_size(1));
        if (submd == NULL)
                GOTO(out_exp, rc = -ENOMEM);

        *offset = 0;
        lov = &export->exp_obd->u.lov;
        rc = -ENOENT;

        for (i = 0, loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++){
                count = lsm->lsm_stripe_size >> PAGE_CACHE_SHIFT;
                skip = (lsm->lsm_stripe_count - 1) * count;

                submd->lsm_oinfo[0].loi_dirty_ot = &loi->loi_dirty_ot_inline;

                err = obd_last_dirty_offset(&lov->tgts[loi->loi_ost_idx].conn,
                                            submd, &tmp);
                if (err == -ENOENT)
                        continue;
                if (err)
                        GOTO(out_exp, rc = err);

                rc = 0;
                if (tmp != ~0)
                        tmp += (tmp/count * skip) + (i * count);
                if (tmp > *offset)
                        *offset = tmp;
        }
out_exp:
        if (submd)
                OBD_FREE(submd, lov_stripe_md_size(1));
        class_export_put(export);
        RETURN(rc);
}

/* For LOV catalogs, we "nest" catalogs from the parent catalog.  What this
 * means is that the parent catalog has a bunch of log cookies that are
 * pointing at one catalog for each OSC.  The OSC catalogs in turn hold
 * cookies for actual log files. */
static int lov_get_catalogs(struct lov_obd *lov, struct llog_handle *cathandle)
{
        int i, rc;

        ENTRY;
        for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                lov->tgts[i].ltd_cathandle = llog_new_log(cathandle,
                                                          &lov->tgts[i].uuid);
                if (IS_ERR(lov->tgts[i].ltd_cathandle))
                        continue;
                rc = llog_init_catalog(cathandle, &lov->tgts[i].uuid);
                if (rc)
                        GOTO(err_logs, rc);
        }
        lov->lo_catalog_loaded = 1;
        RETURN(0);
err_logs:
        while (i-- > 0) {
                llog_delete_log(cathandle, lov->tgts[i].ltd_cathandle);
                llog_close_log(cathandle, lov->tgts[i].ltd_cathandle);
        }
        return rc;
}

/* Add log records for each OSC that this object is striped over, and return
 * cookies for each one.  We _would_ have nice abstraction here, except that
 * we need to keep cookies in stripe order, even if some are NULL, so that
 * the right cookies are passed back to the right OSTs at the client side.
 * Unset cookies should be all-zero (which will never occur naturally). */
static int lov_log_add(struct lustre_handle *conn,
                       struct llog_handle *cathandle,
                       struct llog_trans_hdr *rec, struct lov_stripe_md *lsm,
                       struct llog_cookie *logcookies, int numcookies)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct lov_obd *lov = &obd->u.lov;
        struct lov_oinfo *loi;
        int i, rc = 0;
        ENTRY;

        LASSERT(logcookies && numcookies >= lsm->lsm_stripe_count);

        if (unlikely(!lov->lo_catalog_loaded))
                lov_get_catalogs(lov, cathandle);

        for (i = 0,loi = lsm->lsm_oinfo; i < lsm->lsm_stripe_count; i++,loi++) {
                rc += obd_log_add(&lov->tgts[loi->loi_ost_idx].conn,
                                  lov->tgts[loi->loi_ost_idx].ltd_cathandle,
                                  rec, NULL, logcookies + rc, numcookies - rc);
        }

        RETURN(rc);
}

static int lov_log_cancel(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                          int count, struct llog_cookie *cookies, int flags)
{
        struct obd_export *export = class_conn2export(conn);
        struct lov_obd *lov;
        struct lov_oinfo *loi;
        int rc = 0, i;
        ENTRY;

        LASSERT(lsm != NULL);
        if (export == NULL || export->exp_obd == NULL)
                GOTO(out, rc = -ENODEV);

        LASSERT(count == lsm->lsm_stripe_count);

        loi = lsm->lsm_oinfo;
        lov = &export->exp_obd->u.lov;
        for (i = 0; i < count; i++, cookies++, loi++) {
                int err;

                err = obd_log_cancel(&lov->tgts[loi->loi_ost_idx].conn,
                                     NULL, 1, cookies, flags);
                if (err && lov->tgts[loi->loi_ost_idx].active) {
                        CERROR("error: objid "LPX64" subobj "LPX64
                               " on OST idx %d: rc = %d\n", lsm->lsm_object_id,
                               loi->loi_id, loi->loi_ost_idx, err);
                        if (!rc)
                                rc = err;
                }
        }
        GOTO(out, rc);
 out:
        class_export_put(export);
        return rc;
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
        o_getattr_async: lov_getattr_async,
        o_setattr:     lov_setattr,
        o_open:        lov_open,
        o_close:       lov_close,
        o_brw:         lov_brw,
        o_brw_async:   lov_brw_async,
        o_punch:       lov_punch,
        o_enqueue:     lov_enqueue,
        o_match:       lov_match,
        o_cancel:      lov_cancel,
        o_cancel_unused: lov_cancel_unused,
        o_iocontrol:   lov_iocontrol,
        o_get_info:    lov_get_info,
        o_set_info:    lov_set_info,
        o_log_add:     lov_log_add,
        o_log_cancel:  lov_log_cancel,
        o_mark_page_dirty:   lov_mark_page_dirty,
        o_clear_dirty_pages: lov_clear_dirty_pages,
        o_last_dirty_offset: lov_last_dirty_offset,
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

static void /*__exit*/ lov_exit(void)
{
        class_unregister_type(OBD_LOV_DEVICENAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Object Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lov_init);
module_exit(lov_exit);
#endif
