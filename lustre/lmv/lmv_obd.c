/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_LMV
#ifdef __KERNEL__
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/div64.h>
#else
#include <liblustre.h>
#endif
#include <linux/ext2_fs.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_mds.h>
#include <linux/obd_class.h>
#include <linux/obd_ost.h>
#include <linux/seq_file.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_fsfilt.h>
#include <linux/obd_lmv.h>
#include "lmv_internal.h"

int lmv_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        struct proc_dir_entry *entry;
        int rc;
        ENTRY;

        lprocfs_init_vars(lmv, &lvars);
        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc)
        	RETURN (rc);

        entry = create_proc_entry("target_obd", 0444, dev->obd_proc_entry);
        if (entry == NULL)
                RETURN(-ENOMEM);
        /* entry->proc_fops = &lmv_proc_target_fops; */
        entry->data = dev;

        RETURN (rc);
}

int lmv_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static int lmv_connect_fake(struct lustre_handle *conn,
                            struct obd_device *obd,
                            struct obd_uuid *cluuid)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;

        rc = class_connect(conn, obd, cluuid);
        if (rc) {
                CERROR("class_connection() returned %d\n", rc);
                RETURN(rc);
        }

        lmv->exp = class_conn2export(conn);
        LASSERT(lmv->exp != NULL);

        lmv->cluuid = *cluuid;
        lmv->connected = 0;

        RETURN(0);
}

int lmv_connect(struct obd_device *obd)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        struct obd_uuid *cluuid;
        struct lmv_tgt_desc *tgts;
        struct obd_export *exp;
        int rc, i;
        ENTRY;

        if (lmv->connected)
                RETURN(0);
      
        lmv->connected = 1;
        cluuid = &lmv->cluuid;
        exp = lmv->exp;
        CDEBUG(D_OTHER, "time to connect %s to %s\n",
                        cluuid->uuid, obd->obd_name);

        /* We don't want to actually do the underlying connections more than
         * once, so keep track. */
        lmv->refcount++;
        if (lmv->refcount > 1) {
                class_export_put(exp);
                RETURN(0);
        }

        for (i = 0, tgts = lmv->tgts; i < lmv->count; i++, tgts++) {
                struct obd_device *tgt_obd;
                struct obd_uuid lmv_osc_uuid = { "LMV_OSC_UUID" };
                struct lustre_handle conn = {0, };

                LASSERT(tgts != NULL);

                tgt_obd = class_find_client_obd(&tgts->uuid, LUSTRE_MDC_NAME, 
                                                &obd->obd_uuid);
                if (!tgt_obd) {
                        CERROR("Target %s not attached\n", tgts->uuid.uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }

                /* for MDS: don't connect to yourself */
                if (obd_uuid_equals(&tgts->uuid, cluuid)) {
                        CDEBUG(D_OTHER, "don't connect back to %s\n",
                               cluuid->uuid);
                        tgts->exp = NULL;
                        continue;
                }

                CDEBUG(D_OTHER, "connect to %s(%s) - %s, %s FOR %s\n",
                        tgt_obd->obd_name, tgt_obd->obd_uuid.uuid,
                        tgts->uuid.uuid, obd->obd_uuid.uuid,
                        cluuid->uuid);

                if (!tgt_obd->obd_set_up) {
                        CERROR("Target %s not set up\n", tgts->uuid.uuid);
                        GOTO(out_disc, rc = -EINVAL);
                }
                
                rc = obd_connect(&conn, tgt_obd, &lmv_osc_uuid);
                if (rc) {
                        CERROR("Target %s connect error %d\n",
                                tgts->uuid.uuid, rc);
                        GOTO(out_disc, rc);
                }
                tgts->exp = class_conn2export(&conn);

                obd_init_ea_size(tgts->exp, lmv->max_easize,
                                        lmv->max_cookiesize);
                
                rc = obd_register_observer(tgt_obd, obd);
                if (rc) {
                        CERROR("Target %s register_observer error %d\n",
                               tgts->uuid.uuid, rc);
                        obd_disconnect(tgts->exp, 0);
                        GOTO(out_disc, rc);
                }

                CDEBUG(D_OTHER, "connected to %s(%s) successfully (%d)\n",
                        tgt_obd->obd_name, tgt_obd->obd_uuid.uuid,
                        atomic_read(&obd->obd_refcount));
        }

        class_export_put(exp);
        RETURN (0);

 out_disc:
        /* FIXME: cleanup here */
        class_disconnect(exp, 0);
        RETURN (rc);
}

static int lmv_disconnect(struct obd_export *exp, int flags)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i;
        ENTRY;

        if (!lmv->tgts)
                goto out_local;

        /* Only disconnect the underlying layers on the final disconnect. */
        lmv->refcount--;
        if (lmv->refcount != 0)
                goto out_local;

        for (i = 0; i < lmv->count; i++) {
                if (lmv->tgts[i].exp == NULL)
                        continue;

                if (obd->obd_no_recov) {
                        /* Pass it on to our clients.
                         * XXX This should be an argument to disconnect,
                         * XXX not a back-door flag on the OBD.  Ah well.
                         */
                        struct obd_device *mdc_obd;
                        mdc_obd = class_exp2obd(lmv->tgts[i].exp);
                        if (mdc_obd)
                                mdc_obd->obd_no_recov = 1;
                }

                CDEBUG(D_OTHER, "disconnected from %s(%s) successfully\n",
                        lmv->tgts[i].exp->exp_obd->obd_name,
                        lmv->tgts[i].exp->exp_obd->obd_uuid.uuid);

                obd_register_observer(lmv->tgts[i].exp->exp_obd, NULL);

                rc = obd_disconnect(lmv->tgts[i].exp, flags);
                lmv->tgts[i].exp = NULL;
        }

 out_local:
        /* FIXME: cleanup here */
        if (!lmv->connected)
                class_export_put(exp);
        rc = class_disconnect(exp, 0);
        RETURN(rc);
}

static int lmv_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct lmv_desc *desc;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct obd_uuid *uuids;
        struct lmv_tgt_desc *tgts;
        int i;
        int count;
        int rc = 0;
        ENTRY;

        if (lcfg->lcfg_inllen1 < 1) {
                CERROR("LMV setup requires a descriptor\n");
                RETURN(-EINVAL);
        }

        if (lcfg->lcfg_inllen2 < 1) {
                CERROR("LMV setup requires an OST UUID list\n");
                RETURN(-EINVAL);
        }

        desc = (struct lmv_desc *)lcfg->lcfg_inlbuf1;
        if (sizeof(*desc) > lcfg->lcfg_inllen1) {
                CERROR("descriptor size wrong: %d > %d\n",
                       (int)sizeof(*desc), lcfg->lcfg_inllen1);
                RETURN(-EINVAL);
        }

        count = desc->ld_count;
        uuids = (struct obd_uuid *)lcfg->lcfg_inlbuf2;
        if (sizeof(*uuids) * count != lcfg->lcfg_inllen2) {
                CERROR("UUID array size wrong: %u * %u != %u\n",
                       sizeof(*uuids), count, lcfg->lcfg_inllen2);
                RETURN(-EINVAL);
        }

        lmv->bufsize = sizeof(struct lmv_tgt_desc) * count;
        OBD_ALLOC(lmv->tgts, lmv->bufsize);
        if (lmv->tgts == NULL) {
                CERROR("Out of memory\n");
                RETURN(-EINVAL);
        }

        for (i = 0, tgts = lmv->tgts; i < count; i++, tgts++) {
                tgts->uuid = uuids[i];
                lmv->count++;
        }

        lmv->max_easize = sizeof(struct ll_fid) * lmv->count
                                        + sizeof(struct mea);
        lmv->max_cookiesize = 0;

        RETURN(rc);
}

static int lmv_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                      unsigned long max_age)
{
        struct lmv_obd *lmv = &obd->u.lmv;
        struct obd_statfs temp;
        int rc = 0, i;
        ENTRY;
        lmv_connect(obd);
        for (i = 0; i < lmv->count; i++) {
                rc = obd_statfs(lmv->tgts[i].exp->exp_obd, &temp, max_age);
                if (rc) {
                        CERROR("can't stat MDS #%d (%s)\n", i,
                               lmv->tgts[i].exp->exp_obd->obd_name);
                        RETURN(rc);
                }
                if (i == 0) {
                        memcpy(osfs, &temp, sizeof(temp));
                } else {
                        osfs->os_bavail += temp.os_bavail;
                        osfs->os_blocks += temp.os_blocks;
                        osfs->os_ffree += temp.os_ffree;
                        osfs->os_files += temp.os_files;
                }
        }
        RETURN(rc);
}

static int lmv_cleanup(struct obd_device *obd, int flags) 
{
        struct lmv_obd *lmv = &obd->u.lmv;
        ENTRY;
        lmv_cleanup_objs(obd);
        OBD_FREE(lmv->tgts, lmv->bufsize);
        RETURN(0);
}

static int lmv_getstatus(struct obd_export *exp, struct ll_fid *fid)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;
        lmv_connect(obd);
        rc = md_getstatus(lmv->tgts[0].exp, fid);
        fid->mds = 0;
        RETURN(rc);
}

static int lmv_getattr(struct obd_export *exp, struct ll_fid *fid,
                unsigned long valid, unsigned int ea_size,
                struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i = fid->mds;
        struct lmv_obj *obj;
        ENTRY;
        lmv_connect(obd);
        obj = lmv_grab_obj(obd, fid, 0);
        CDEBUG(D_OTHER, "GETATTR for %lu/%lu/%lu %s\n",
               (unsigned long) fid->mds,
               (unsigned long) fid->id,
               (unsigned long) fid->generation,
               obj ? "(splitted)" : "");

        LASSERT(fid->mds < lmv->count);
        rc = md_getattr(lmv->tgts[i].exp, fid,
                             valid, ea_size, request);
        if (rc == 0 && obj) {
                /* we have to loop over dirobjs here and gather attrs
                 * for all the slaves */
#warning "attrs gathering here"
        }
        lmv_put_obj(obj);
        RETURN(rc);
}

static int lmv_change_cbdata(struct obd_export *exp,
                                 struct ll_fid *fid, 
                                 ldlm_iterator_t it, void *data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc = 0;
        ENTRY;
        lmv_connect(obd);
        CDEBUG(D_OTHER, "CBDATA for %lu/%lu/%lu\n",
               (unsigned long) fid->mds,
               (unsigned long) fid->id,
               (unsigned long) fid->generation);
        LASSERT(fid->mds < lmv->count);
        rc = md_change_cbdata(lmv->tgts[fid->mds].exp, fid, it, data);
        RETURN(rc);
}

static int lmv_change_cbdata_name(struct obd_export *exp, struct ll_fid *pfid,
                                  char *name, int len, struct ll_fid *cfid,
                                  ldlm_iterator_t it, void *data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc = 0, mds;
        ENTRY;
        lmv_connect(obd);
        LASSERT(pfid->mds < lmv->count);
        LASSERT(cfid->mds < lmv->count);
        CDEBUG(D_OTHER, "CBDATA for %lu/%lu/%lu:%*s -> %lu/%lu/%lu\n",
               (unsigned long) pfid->mds, (unsigned long) pfid->id,
               (unsigned long) pfid->generation, len, name,
               (unsigned long) cfid->mds, (unsigned long) cfid->id,
               (unsigned long) cfid->generation);

        /* this is default mds for directory name belongs to */
        mds = pfid->mds;
        obj = lmv_grab_obj(obd, pfid, 0);
        if (obj) {
                /* directory is splitted. look for right mds for this name */
                mds = raw_name2idx(obj->objcount, name, len);
                lmv_put_obj(obj);
        }
        rc = md_change_cbdata(lmv->tgts[mds].exp, cfid, it, data);
        RETURN(rc);
}

static int lmv_valid_attrs(struct obd_export *exp, struct ll_fid *fid) 
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc = 0;
        ENTRY;
        lmv_connect(obd);
        CDEBUG(D_OTHER, "validate %lu/%lu/%lu\n",
               (unsigned long) fid->mds,
               (unsigned long) fid->id,
               (unsigned long) fid->generation);
        LASSERT(fid->mds < lmv->count);
        rc = md_valid_attrs(lmv->tgts[fid->mds].exp, fid);
        RETURN(rc);
}

int lmv_close(struct obd_export *exp, struct obdo *obdo,
                  struct obd_client_handle *och,
                  struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i = obdo->o_mds;
        ENTRY;
        lmv_connect(obd);
        LASSERT(i < lmv->count);
        CDEBUG(D_OTHER, "CLOSE %lu/%lu/%lu\n", (unsigned long) obdo->o_mds,
               (unsigned long) obdo->o_id, (unsigned long) obdo->o_generation);
        rc = md_close(lmv->tgts[i].exp, obdo, och, request);
        RETURN(rc);
}

int lmv_get_mea_and_update_object(struct obd_export *exp, struct ll_fid *fid)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ptlrpc_request *req = NULL;
        struct lustre_md md;
        int mealen, rc;

        md.mea = NULL;
        mealen = MEA_SIZE_LMV(lmv);

        /* time to update mea of parent fid */
        rc = md_getattr(lmv->tgts[fid->mds].exp, fid,
                        OBD_MD_FLEASIZE, mealen, &req);
        if (rc)
                GOTO(cleanup, rc);
        rc = mdc_req2lustre_md(req, 0, NULL, exp, &md);
        if (rc)
                GOTO(cleanup, rc);
        if (md.mea == NULL)
                GOTO(cleanup, rc = -ENODATA);
        rc = lmv_create_obj_from_attrs(exp, fid, md.mea);
        obd_free_memmd(exp, (struct lov_stripe_md **) &md.mea);

cleanup:
        if (req)
                ptlrpc_req_finished(req);
        RETURN(rc);
}

int lmv_create(struct obd_export *exp, struct mdc_op_data *op_data,
                   const void *data, int datalen, int mode, __u32 uid,
                   __u32 gid, __u64 rdev, struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mds_body *mds_body;
        struct lmv_obj *obj;
        int rc, mds;
        ENTRY;

        lmv_connect(obd);
repeat:
        obj = lmv_grab_obj(obd, &op_data->fid1, 0);
        if (obj) {
                mds = raw_name2idx(obj->objcount, op_data->name,
                                        op_data->namelen);
                op_data->fid1 = obj->objs[mds].fid;
                lmv_put_obj(obj);
        }

        CDEBUG(D_OTHER, "CREATE '%*s' on %lu/%lu/%lu\n",
                        op_data->namelen, op_data->name,
                        (unsigned long) op_data->fid1.mds,
                        (unsigned long) op_data->fid1.id,
                        (unsigned long) op_data->fid1.generation);
        rc = md_create(lmv->tgts[op_data->fid1.mds].exp, op_data, data,
                       datalen, mode, uid, gid, rdev, request);
        if (rc == 0) {
                if (*request == NULL)
                     RETURN(rc);
                mds_body = lustre_msg_buf((*request)->rq_repmsg, 0,
                                          sizeof(*mds_body));
                LASSERT(mds_body != NULL);
                CDEBUG(D_OTHER, "created. id = %lu, generation = %lu, mds = %d\n",
                       (unsigned long) mds_body->fid1.id,
                       (unsigned long) mds_body->fid1.generation,
                       op_data->fid1.mds);
                LASSERT(mds_body->valid & OBD_MD_MDS ||
                                mds_body->mds == op_data->fid1.mds);
        } else if (rc == -ERESTART) {
                /* directory got splitted. time to update local object
                 * and repeat the request with proper MDS */
                rc = lmv_get_mea_and_update_object(exp, &op_data->fid1);
                if (rc == 0) {
                        ptlrpc_req_finished(*request);
                        goto repeat;
                }
        }
        RETURN(rc);
}

int lmv_done_writing(struct obd_export *exp, struct obdo *obdo)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;
        lmv_connect(obd);
        /* FIXME: choose right MDC here */
        rc = md_done_writing(lmv->tgts[0].exp, obdo);
        RETURN(rc);
}

int lmv_enqueue(struct obd_export *exp, int lock_type,
                    struct lookup_intent *it, int lock_mode,
                    struct mdc_op_data *data, struct lustre_handle *lockh,
                    void *lmm, int lmmsize,
                    ldlm_completion_callback cb_completion,
                    ldlm_blocking_callback cb_blocking, void *cb_data)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc, mds;
        ENTRY;
        lmv_connect(obd);
        if (data->namelen) {
                obj = lmv_grab_obj(obd, &data->fid1, 0);
                if (obj) {
                        /* directory is splitted. look for
                         * right mds for this name */
                        mds = raw_name2idx(obj->objcount, data->name,
                                                data->namelen);
                        data->fid1 = obj->objs[mds].fid;
                        lmv_put_obj(obj);
                }
        }
        CDEBUG(D_OTHER, "ENQUEUE '%s' on %lu/%lu\n",
               LL_IT2STR(it), (unsigned long) data->fid1.id,
               (unsigned long) data->fid1.generation);
        rc = md_enqueue(lmv->tgts[data->fid1.mds].exp, lock_type, it,
                        lock_mode, data, lockh, lmm, lmmsize, cb_completion,
                        cb_blocking, cb_data);

        RETURN(rc);
}

int lmv_getattr_name(struct obd_export *exp, struct ll_fid *fid,
                         char *filename, int namelen, unsigned long valid,
                         unsigned int ea_size, struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ll_fid rfid = *fid;
        int rc, mds = fid->mds;
        struct lmv_obj *obj;
        ENTRY;
        lmv_connect(obd);
        CDEBUG(D_OTHER, "getattr_name for %*s on %lu/%lu/%lu\n",
               namelen, filename, (unsigned long) fid->mds,
               (unsigned long) fid->id, (unsigned long) fid->generation);
        obj = lmv_grab_obj(obd, fid, 0);
        if (obj) {
                /* directory is splitted. look for right mds for this name */
                mds = raw_name2idx(obj->objcount, filename, namelen);
                rfid = obj->objs[mds].fid;
                lmv_put_obj(obj);
        }
        rc = md_getattr_name(lmv->tgts[mds].exp, &rfid, filename, namelen,
                                  valid, ea_size, request);
        RETURN(rc);
}


/*
 * llite passes fid of an target inode in data->fid1 and
 * fid of directory in data->fid2
 */
int lmv_link(struct obd_export *exp, struct mdc_op_data *data,
             struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc;
        ENTRY;
        lmv_connect(obd);
        if (data->namelen != 0) {
                /* usual link request */
                obj = lmv_grab_obj(obd, &data->fid1, 0);
                if (obj) {
                        rc = raw_name2idx(obj->objcount, data->name,
                                         data->namelen);
                        data->fid1 = obj->objs[rc].fid;
                        lmv_put_obj(obj);
                }
                CDEBUG(D_OTHER,"link %u/%u/%u:%*s to %u/%u/%u mds %d\n",
                       (unsigned) data->fid2.mds, (unsigned) data->fid2.id,
                       (unsigned) data->fid2.generation, data->namelen,
                       data->name, (unsigned) data->fid1.mds,
                       (unsigned) data->fid1.id,
                       (unsigned) data->fid1.generation, data->fid1.mds);
        } else {
                /* request from MDS to acquire i_links for inode by fid1 */
                CDEBUG(D_OTHER, "inc i_nlinks for %u/%u/%u\n",
                       (unsigned) data->fid1.mds, (unsigned) data->fid1.id,
                       (unsigned) data->fid1.generation);
        }
                        
        rc = md_link(lmv->tgts[data->fid1.mds].exp, data, request);
        RETURN(rc);
}

int lmv_rename(struct obd_export *exp, struct mdc_op_data *data,
               const char *old, int oldlen, const char *new, int newlen,
               struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lmv_obj *obj;
        int rc, mds;
        ENTRY;

        CDEBUG(D_OTHER, "rename %*s in %lu/%lu/%lu to %*s in %lu/%lu/%lu\n",
               oldlen, old, (unsigned long) data->fid1.mds,
               (unsigned long) data->fid1.id,
               (unsigned long) data->fid1.generation,
               newlen, new, (unsigned long) data->fid2.mds,
               (unsigned long) data->fid2.id,
               (unsigned long) data->fid2.generation);

        lmv_connect(obd);

        if (oldlen == 0) {
                /* MDS with old dir entry is asking another MDS
                 * to create name there */
                CDEBUG(D_OTHER,
                       "create %*s(%d/%d) in %lu/%lu/%lu pointing to %lu/%lu/%lu\n",
                       newlen, new, oldlen, newlen,
                       (unsigned long) data->fid2.mds,
                       (unsigned long) data->fid2.id,
                       (unsigned long) data->fid2.generation,
                       (unsigned long) data->fid1.mds,
                       (unsigned long) data->fid1.id,
                       (unsigned long) data->fid1.generation);
                mds = data->fid2.mds;
                goto request;
        }

        obj = lmv_grab_obj(obd, &data->fid1, 0);
        if (obj) {
                /* directory is already splitted, so we have to forward
                 * request to the right MDS */
                mds = raw_name2idx(obj->objcount, old, oldlen);
                data->fid1 = obj->objs[mds].fid;
                CDEBUG(D_OTHER, "forward to MDS #%u (%lu/%lu/%lu)\n", mds,
                       (unsigned long) obj->objs[mds].fid.mds,
                       (unsigned long) obj->objs[mds].fid.id,
                       (unsigned long) obj->objs[mds].fid.generation);
        }
        lmv_put_obj(obj);

        obj = lmv_grab_obj(obd, &data->fid2, 0);
        if (obj) {
                /* directory is already splitted, so we have to forward
                 * request to the right MDS */
                mds = raw_name2idx(obj->objcount, new, newlen);
                data->fid2 = obj->objs[mds].fid;
                CDEBUG(D_OTHER, "forward to MDS #%u (%lu/%lu/%lu)\n", mds,
                       (unsigned long) obj->objs[mds].fid.mds,
                       (unsigned long) obj->objs[mds].fid.id,
                       (unsigned long) obj->objs[mds].fid.generation);
        }
        lmv_put_obj(obj);
        
        mds = data->fid1.mds;

request:
        rc = md_rename(lmv->tgts[mds].exp, data, old, oldlen,
                            new, newlen, request); 
        RETURN(rc);
}

int lmv_setattr(struct obd_export *exp, struct mdc_op_data *data,
                struct iattr *iattr, void *ea, int ealen, void *ea2, int ea2len,
                struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc = 0, i = data->fid1.mds;
        struct ptlrpc_request *req;
        struct mds_body *mds_body;
        struct lmv_obj *obj;
        ENTRY;
        lmv_connect(obd);
        obj = lmv_grab_obj(obd, &data->fid1, 0);
        CDEBUG(D_OTHER, "SETATTR for %lu/%lu/%lu, valid 0x%x%s\n",
               (unsigned long) data->fid1.mds,
               (unsigned long) data->fid1.id,
               (unsigned long) data->fid1.generation, iattr->ia_valid,
               obj ? ", splitted" : "");
        if (obj) {
                for (i = 0; i < obj->objcount; i++) {
                        data->fid1 = obj->objs[i].fid;
                        rc = md_setattr(lmv->tgts[i].exp, data, iattr, ea,
                                        ealen, ea2, ea2len, &req);
                        LASSERT(rc == 0);
                        if (fid_equal(&obj->fid, &obj->objs[i].fid)) {
                                /* this is master object and this request
                                 * should be returned back to llite */
                                *request = req;
                        } else {
                                ptlrpc_req_finished(req);
                        }
                }
                lmv_put_obj(obj);
        } else {
                LASSERT(data->fid1.mds < lmv->count);
                rc = md_setattr(lmv->tgts[i].exp, data, iattr, ea, ealen,
                                ea2, ea2len, request); 
                if (rc == 0) {
                        mds_body = lustre_msg_buf((*request)->rq_repmsg, 0,
                                        sizeof(*mds_body));
                        LASSERT(mds_body != NULL);
                        LASSERT(mds_body->mds == i);
                }
        }
        RETURN(rc);
}

int lmv_sync(struct obd_export *exp, struct ll_fid *fid,
             struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc;
        ENTRY;
        lmv_connect(obd);
        rc = md_sync(lmv->tgts[0].exp, fid, request); 
        RETURN(rc);
}

int lmv_dirobj_blocking_ast(struct ldlm_lock *lock,
                            struct ldlm_lock_desc *desc, void *data, int flag)
{
        struct lustre_handle lockh;
        struct lmv_obj *obj;
        int rc;
        ENTRY;

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING:
                /* time to drop cached attrs for dirobj */
                obj = lock->l_ast_data;
                if (!obj)
                        break;

                CDEBUG(D_OTHER, "cancel %s on %lu/%lu, master %lu/%lu/%lu\n",
                       lock->l_resource->lr_name.name[3] == 1 ?
                                "LOOKUP" : "UPDATE",
                       (unsigned long) lock->l_resource->lr_name.name[0],
                       (unsigned long) lock->l_resource->lr_name.name[1],
                       (unsigned long) obj->fid.mds,
                       (unsigned long) obj->fid.id,
                       (unsigned long) obj->fid.generation);
                break;
        default:
                LBUG();
        }
        RETURN(0);
}

void lmv_remove_dots(struct page *page)
{
        char *kaddr = page_address(page);
        unsigned limit = PAGE_CACHE_SIZE;
        unsigned offs, rec_len;
        struct ext2_dir_entry_2 *p;

        for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {
                p = (struct ext2_dir_entry_2 *)(kaddr + offs);
                rec_len = le16_to_cpu(p->rec_len);

                if ((p->name_len == 1 && p->name[0] == '.') ||
                    (p->name_len == 2 && p->name[0] == '.' && p->name[1] == '.'))
                        p->inode = 0;
        }
}

int lmv_readpage(struct obd_export *exp, struct ll_fid *mdc_fid,
                 __u64 offset, struct page *page,
                 struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct ll_fid rfid = *mdc_fid;
        struct lmv_obj *obj;
        int rc, i;
        ENTRY;
        lmv_connect(obd);
       
        LASSERT(mdc_fid->mds < lmv->count);
        CDEBUG(D_OTHER, "READPAGE at %llu from %lu/%lu/%lu\n",
               offset, (unsigned long) rfid.mds,
               (unsigned long) rfid.id,
               (unsigned long) rfid.generation);

        obj = lmv_grab_obj(obd, mdc_fid, 0);
        if (obj) {
                /* find dirobj containing page with requested offset */
                /* FIXME: what about protecting cached attrs here? */
                for (i = 0; i < obj->objcount; i++) {
                        if (offset < obj->objs[i].size)
                                break;
                        offset -= obj->objs[i].size;
                }
                rfid = obj->objs[i].fid;
                CDEBUG(D_OTHER, "forward to %lu/%lu/%lu with offset %lu\n",
                       (unsigned long) rfid.mds,
                       (unsigned long) rfid.id,
                       (unsigned long) rfid.generation,
                       (unsigned long) offset);
        }
        rc = md_readpage(lmv->tgts[rfid.mds].exp, &rfid, offset, page, request);
        if (rc == 0 && !fid_equal(&rfid, mdc_fid)) {
                /* this page isn't from master object. to avoid
                 * ./.. duplication in directory, we have to remove them
                 * from all slave objects */
                lmv_remove_dots(page);
        }
      
        lmv_put_obj(obj);

        RETURN(rc);
}

int lmv_unlink(struct obd_export *exp, struct mdc_op_data *data,
               struct ptlrpc_request **request)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int rc, i = 0;
        ENTRY;
        lmv_connect(obd);
        if (data->namelen != 0) {
                struct lmv_obj *obj;
                obj = lmv_grab_obj(obd, &data->fid1, 0);
                if (obj) {
                        i = raw_name2idx(obj->objcount, data->name,
                                         data->namelen);
                        data->fid1 = obj->objs[i].fid;
                        lmv_put_obj(obj);
                }
                CDEBUG(D_OTHER, "unlink '%*s' in %lu/%lu/%lu -> %u\n",
                       data->namelen, data->name,
                       (unsigned long) data->fid1.mds,
                       (unsigned long) data->fid1.id,
                       (unsigned long) data->fid1.generation, i);
        } else {
                CDEBUG(D_OTHER, "drop i_nlink on %lu/%lu/%lu\n",
                       (unsigned long) data->fid1.mds,
                       (unsigned long) data->fid1.id,
                       (unsigned long) data->fid1.generation);
        }
        rc = md_unlink(lmv->tgts[data->fid1.mds].exp, data, request); 
        RETURN(rc);
}

struct obd_device *lmv_get_real_obd(struct obd_export *exp,
                                        char *name, int len)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        ENTRY;
        lmv_connect(obd);
        obd = lmv->tgts[0].exp->exp_obd;
        EXIT;
        return obd;
}

int lmv_init_ea_size(struct obd_export *exp, int easize, int cookiesize)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        int i, rc = 0, change = 0;
        ENTRY;

        if (lmv->max_easize < easize) {
                lmv->max_easize = easize;
                change = 1;
        }
        if (lmv->max_cookiesize < cookiesize) {
                lmv->max_cookiesize = cookiesize;
                change = 1;
        }
        if (change == 0)
                RETURN(0);
        
        if (lmv->connected == 0)
                RETURN(0);

        /* FIXME: error handling? */
        for (i = 0; i < lmv->count; i++)
                rc = obd_init_ea_size(lmv->tgts[i].exp, easize, cookiesize);
        RETURN(rc);
}

int lmv_obd_create_single(struct obd_export *exp, struct obdo *oa,
                          struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct lov_stripe_md obj_md;
        struct lov_stripe_md *obj_mdp = &obj_md;
        int rc = 0;
        ENTRY;
        lmv_connect(obd);

        LASSERT(ea == NULL);
        LASSERT(oa->o_mds < lmv->count);

        rc = obd_create(lmv->tgts[oa->o_mds].exp, oa, &obj_mdp, oti);
        LASSERT(rc == 0);

        RETURN(rc);
}

/*
 * to be called from MDS only
 */
int lmv_obd_create(struct obd_export *exp, struct obdo *oa,
               struct lov_stripe_md **ea, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea *mea;
        int i, c, rc = 0;
        struct ll_fid mfid;
        ENTRY;
        lmv_connect(obd);

        LASSERT(oa != NULL);
        
        if (ea == NULL) {
                rc = lmv_obd_create_single(exp, oa, NULL, oti);
                RETURN(rc);
        }

        if (*ea == NULL) {
                rc = obd_alloc_diskmd(exp, (struct lov_mds_md **) ea);
                LASSERT(*ea != NULL);
        }

        mea = (struct mea *) *ea;
        mfid.id = oa->o_id;
        mfid.generation = oa->o_generation;
        rc = 0;
        if (!mea->mea_count || mea->mea_count > lmv->count)
                mea->mea_count = lmv->count;

        mea->mea_master = -1;
        
        /* FIXME: error handling? */
        for (i = 0, c = 0; c < mea->mea_count && i < lmv->count; i++) {
                struct lov_stripe_md obj_md;
                struct lov_stripe_md *obj_mdp = &obj_md;
               
                if (lmv->tgts[i].exp == NULL) {
                        /* this is master MDS */
                        mea->mea_fids[c].id = mfid.id;
                        mea->mea_fids[c].generation = mfid.generation;
                        mea->mea_fids[c].mds = i;
                        mea->mea_master = i;
                        c++;
                        continue;
                }

                /* "Master" MDS should always be part of stripped dir, so
                   scan for it */
                if (mea->mea_master == -1 && c == mea->mea_count - 1)
                        continue;

                oa->o_valid = OBD_MD_FLGENER | OBD_MD_FLTYPE | OBD_MD_FLMODE
                                | OBD_MD_FLUID | OBD_MD_FLGID | OBD_MD_FLID;

                rc = obd_create(lmv->tgts[c].exp, oa, &obj_mdp, oti);
                /* FIXME: error handling here */
                LASSERT(rc == 0);

                mea->mea_fids[c].id = oa->o_id;
                mea->mea_fids[c].generation = oa->o_generation;
                mea->mea_fids[c].mds = i;
                c++;
                CDEBUG(D_OTHER, "dirobj at mds %d: "LPU64"/%u\n",
                       i, oa->o_id, oa->o_generation);
        }
        LASSERT(c == mea->mea_count);
        CDEBUG(D_OTHER, "%d dirobjects created\n", (int) mea->mea_count);

        RETURN(rc);
}

static int lmv_get_info(struct obd_export *exp, __u32 keylen,
                           void *key, __u32 *vallen, void *val)
{
        struct obd_device *obd;
        struct lmv_obd *lmv;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        lmv = &obd->u.lmv;
        if (keylen == 6 && memcmp(key, "mdsize", 6) == 0) {
                __u32 *mdsize = val;
                *vallen = sizeof(__u32);
                *mdsize = sizeof(struct ll_fid) * lmv->count
                                + sizeof(struct mea);
                RETURN(0);
        } else if (keylen == 6 && memcmp(key, "mdsnum", 6) == 0) {
                struct obd_uuid *cluuid = &lmv->cluuid;
                struct lmv_tgt_desc *tgts;
                __u32 *mdsnum = val;
                int i;

                for (i = 0, tgts = lmv->tgts; i < lmv->count; i++, tgts++) {
                        if (obd_uuid_equals(&tgts->uuid, cluuid)) {
                                *vallen = sizeof(__u32);
                                *mdsnum = i;
                                RETURN(0);
                        }
                }
                LASSERT(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

int lmv_set_info(struct obd_export *exp, obd_count keylen,
                 void *key, obd_count vallen, void *val)
{
        struct obd_device *obd;
        struct lmv_obd *lmv;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }
        lmv = &obd->u.lmv;
        lmv_connect(obd);

        if (keylen >= strlen("client") && strcmp(key, "client") == 0) {
                struct lmv_tgt_desc *tgts;
                int i, rc;

                for (i = 0, tgts = lmv->tgts; i < lmv->count; i++, tgts++) {
                        rc = obd_set_info(tgts->exp, keylen, key, vallen, val);
                        if (rc)
                                RETURN(rc);
                }
                RETURN(0);
        }
        
        RETURN(-EINVAL);
}

int lmv_packmd(struct obd_export *exp, struct lov_mds_md **lmmp,
               struct lov_stripe_md *lsm)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lmv_obd *lmv = &obd->u.lmv;
        int mea_size;
        ENTRY;

	mea_size = sizeof(struct ll_fid) * lmv->count + sizeof(struct mea);
        if (!lmmp)
                RETURN(mea_size);

        if (*lmmp && !lsm) {
                OBD_FREE(*lmmp, mea_size);
                *lmmp = NULL;
                RETURN(0);
        }

        if (!*lmmp) {
                OBD_ALLOC(*lmmp, mea_size);
                if (!*lmmp)
                        RETURN(-ENOMEM);
        }

        if (!lsm)
                RETURN(mea_size);

#warning "MEA packing/convertation must be here! -bzzz"
        memcpy(*lmmp, lsm, mea_size);
        RETURN(mea_size);
}

int lmv_unpackmd(struct obd_export *exp, struct lov_stripe_md **mem_tgt,
                        struct lov_mds_md *disk_src, int mdsize)
{
        struct obd_device *obd = class_exp2obd(exp);
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea **tmea = (struct mea **) mem_tgt;
        struct mea *mea = (void *) disk_src;
        int mea_size;
        ENTRY;

	mea_size = sizeof(struct ll_fid) * lmv->count + sizeof(struct mea);
        if (mem_tgt == NULL)
                return mea_size;

        if (*mem_tgt != NULL && disk_src == NULL) {
                OBD_FREE(*tmea, mea_size);
                RETURN(0);
        }

        LASSERT(mea_size == mdsize);

        OBD_ALLOC(*tmea, mea_size);
        /* FIXME: error handling here */
        LASSERT(*tmea != NULL);

        if (!disk_src)
                RETURN(mea_size);

#warning "MEA unpacking/convertation must be here! -bzzz"
        memcpy(*tmea, mea, mdsize);
        RETURN(mea_size);
}

int lmv_brw(int rw, struct obd_export *exp, struct obdo *oa,
                struct lov_stripe_md *ea, obd_count oa_bufs,
                struct brw_page *pgarr, struct obd_trans_info *oti)
{
        struct obd_device *obd = exp->exp_obd;
        struct lmv_obd *lmv = &obd->u.lmv;
        struct mea *mea = (struct mea *) ea;
        int err;
      
        LASSERT(oa != NULL);
        LASSERT(ea != NULL);
        LASSERT(pgarr != NULL);
        LASSERT(oa->o_mds < lmv->count);

        oa->o_gr = mea->mea_fids[oa->o_mds].generation;
        oa->o_id = mea->mea_fids[oa->o_mds].id;
        oa->o_valid =  OBD_MD_FLID | OBD_MD_FLGROUP;
        err = obd_brw(rw, lmv->tgts[oa->o_mds].exp, oa,
                        NULL, oa_bufs, pgarr, oti);
        RETURN(err);
}

struct obd_ops lmv_obd_ops = {
        o_owner:                THIS_MODULE,
        o_attach:               lmv_attach,
        o_detach:               lmv_detach,
        o_setup:                lmv_setup,
        o_cleanup:              lmv_cleanup,
        o_connect:              lmv_connect_fake,
        o_disconnect:           lmv_disconnect,
        o_statfs:               lmv_statfs,
        o_get_info:             lmv_get_info,
        o_set_info:             lmv_set_info,
        o_create:               lmv_obd_create,
        o_packmd:               lmv_packmd,
        o_unpackmd:             lmv_unpackmd,
        o_brw:                  lmv_brw,
        o_init_ea_size:         lmv_init_ea_size,
};

struct md_ops lmv_md_ops = {
        m_getstatus:            lmv_getstatus,
        m_getattr:              lmv_getattr,
        m_change_cbdata:        lmv_change_cbdata,
        m_change_cbdata_name:   lmv_change_cbdata_name,
        m_close:                lmv_close,
        m_create:               lmv_create,
        m_done_writing:         lmv_done_writing,
        m_enqueue:              lmv_enqueue,
        m_getattr_name:         lmv_getattr_name,
        m_intent_lock:          lmv_intent_lock,
        m_link:                 lmv_link,
        m_rename:               lmv_rename,
        m_setattr:              lmv_setattr,
        m_sync:                 lmv_sync,
        m_readpage:             lmv_readpage,
        m_unlink:               lmv_unlink,
        m_get_real_obd:         lmv_get_real_obd,
        m_valid_attrs:          lmv_valid_attrs,
};

//#ifndef LPROCFS
static struct lprocfs_vars lprocfs_module_vars[] = { {0} };
static struct lprocfs_vars lprocfs_obd_vars[] = { {0} };
//#else
LPROCFS_INIT_VARS(lmv, lprocfs_module_vars, lprocfs_obd_vars)

int __init lmv_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        lprocfs_init_vars(lmv, &lvars);
        rc = class_register_type(&lmv_obd_ops, &lmv_md_ops,
                                 lvars.module_vars, OBD_LMV_DEVICENAME);
        RETURN(rc);
}

static void lmv_exit(void)
{
        class_unregister_type(OBD_LMV_DEVICENAME);
}

#ifdef __KERNEL__
MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Logical Metadata Volume OBD driver");
MODULE_LICENSE("GPL");

module_init(lmv_init);
module_exit(lmv_exit);
#endif

