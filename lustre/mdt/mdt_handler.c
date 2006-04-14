/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
 *  Lustre Metadata Target (mdt) request handler
 *
 *  Copyright (c) 2006 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>

/* LUSTRE_VERSION_CODE */
#include <linux/lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <linux/obd_support.h>
/* struct ptlrpc_request */
#include <linux/lustre_net.h>
/* struct obd_export */
#include <linux/lustre_export.h>
/* struct obd_device */
#include <linux/obd.h>

/* struct mds_client_data */
#include "../mds/mds_internal.h"
#include "mdt_internal.h"

/*
 * Initialized in mdt_mod_init().
 */
unsigned long mdt_num_threads;

static int mdt_handle(struct ptlrpc_request *req);
static struct ptlrpc_thread_key mdt_thread_key;

/* object operations */
#if 0
static int mdt_md_mkdir(struct mdt_thread_info *info, struct mdt_device *d,
                        struct lu_fid *pfid, const char *name, struct lu_fid *cfid)
{
        struct mdt_object      *o;
        struct mdt_object      *child;
        struct mdt_lock_handle *lh;

        int result;

        lh = &info->mti_lh[MDT_LH_PARENT];
        lh->mlh_mode = LCK_PW;

        o = mdt_object_find_lock(d, pfid, lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(o))
                return PTR_ERR(o);

        child = mdt_object_find(d, cfid);
        if (!IS_ERR(child)) {
                struct md_object *next = mdt_object_child(o);

                result = next->mo_ops->moo_mkdir(&info->mti_ctxt, next, name,
                                                 mdt_object_child(child));
                mdt_object_put(child);
        } else
                result = PTR_ERR(child);
        mdt_object_unlock(d->mdt_namespace, o, lh);
        mdt_object_put(o);
        return result;
}
#endif
static int mdt_md_getattr(struct mdt_thread_info *info, struct lu_fid *fid)
{
        struct mdt_device *d = info->mti_mdt;
        struct mdt_object *o;
        int               result;

        ENTRY;

        o = mdt_object_find(&info->mti_ctxt, d, fid);
        if (IS_ERR(o))
                return PTR_ERR(o);
        /* attr are in mti_ctxt */
        result = 0;
        mdt_object_put(&info->mti_ctxt, o);

        RETURN(result);
}

static int mdt_getstatus(struct mdt_thread_info *info,
                         struct ptlrpc_request *req, int offset)
{
        struct md_device *next  = info->mti_mdt->mdt_child;
        struct mdt_body  *body;
        int               size = sizeof *body;
        int               result;

        ENTRY;

        result = lustre_pack_reply(req, 1, &size, NULL);
        if (result)
                CERROR(LUSTRE_MDT0_NAME" out of memory for message: size=%d\n",
                       size);
        else if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                result = -ENOMEM;
        else {
                body = lustre_msg_buf(req->rq_repmsg, 0, sizeof *body);
                result = next->md_ops->mdo_root_get(&info->mti_ctxt,
                                                    next, &body->fid1);
        }

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
        RETURN(result);
}

static int mdt_statfs(struct mdt_thread_info *info,
                      struct ptlrpc_request *req, int offset)
{
        struct md_device  *next  = info->mti_mdt->mdt_child;
        struct obd_statfs *osfs;
        struct kstatfs    sfs;
        int               result;
        int               size = sizeof(struct obd_statfs);

        ENTRY;

        result = lustre_pack_reply(req, 1, &size, NULL);
        if (result)
                CERROR(LUSTRE_MDT0_NAME" out of memory for statfs: size=%d\n",
                       size);
        else if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR(LUSTRE_MDT0_NAME": statfs lustre_pack_reply failed\n");
                result = -ENOMEM;
        } else {
                osfs = lustre_msg_buf(req->rq_repmsg, 0, size);
                /* XXX max_age optimisation is needed here. See mds_statfs */
                result = next->md_ops->mdo_statfs(&info->mti_ctxt, next, &sfs);
                statfs_pack(osfs, &sfs);
        }

        RETURN(result);
}

static void mdt_pack_attr2body(struct mdt_body *b, struct lu_attr *attr)
{
        b->valid |= OBD_MD_FLID | OBD_MD_FLCTIME | OBD_MD_FLUID |
                    OBD_MD_FLGID | OBD_MD_FLFLAGS | OBD_MD_FLTYPE |
                    OBD_MD_FLMODE | OBD_MD_FLNLINK | OBD_MD_FLGENER;

        if (!S_ISREG(attr->la_mode))
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLATIME |
                            OBD_MD_FLMTIME;

        b->atime      = attr->la_atime;
        b->mtime      = attr->la_mtime;
        b->ctime      = attr->la_ctime;
        b->mode       = attr->la_mode;
        b->size       = attr->la_size;
        b->blocks     = attr->la_blocks;
        b->uid        = attr->la_uid;
        b->gid        = attr->la_gid;
        b->flags      = attr->la_flags;
        b->nlink      = attr->la_nlink;
}

static int mdt_getattr(struct mdt_thread_info *info,
                       struct ptlrpc_request *req, int offset)
{
        struct mdt_body        *body;
        int                    size = sizeof (*body);
        struct lu_attr  *attr;
        int result;

        ENTRY;

        OBD_ALLOC_PTR(attr);
        if (attr == NULL)
                return -ENOMEM;

        result = lustre_pack_reply(req, 1, &size, NULL);
        if (result)
                CERROR(LUSTRE_MDT0_NAME" out of memory for statfs: size=%d\n",
                       size);
        else if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR(LUSTRE_MDT0_NAME": statfs lustre_pack_reply failed\n");
                result = -ENOMEM;
        } else {
                body = lustre_msg_buf(req->rq_repmsg, 0, size);
                result = mdt_md_getattr(info, &body->fid1);
                if (result == 0)
                        mdt_pack_attr2body(body, &info->mti_ctxt.lc_attr);
        }
        OBD_FREE_PTR(attr);
        RETURN(result);
}

static int mdt_set_info(struct mdt_thread_info *info,
                        struct ptlrpc_request *req, int offset)
{
        struct md_device *next  = info->mti_mdt->mdt_child;
        char *key;
        int keylen, rc = 0;
        ENTRY;
        
        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];
       
        if (((keylen >= strlen("fld_create") &&
            memcmp(key, "fld_create", keylen) == 0)) || 
            ((keylen >= strlen("fld_delete") &&
            memcmp(key, "fld_delete", keylen) == 0))) {
                struct md_fld mf, *p;
                __u32 size = sizeof(struct md_fld);

                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc)
                        RETURN(rc);
                
                p = lustre_swab_reqbuf(req, 1, sizeof(mf), lustre_swab_md_fld);
                mf = *p;
                rc = next->md_ops->mdo_get_info(&info->mti_ctxt, next, keylen, 
                                                key, &size, &mf);
                RETURN(rc); 
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);

}

static int mdt_get_info(struct mdt_thread_info *info,
                        struct ptlrpc_request *req, int offset)
{
        struct md_device *next  = info->mti_mdt->mdt_child;
        char *key;
        int keylen, rc = 0;
        ENTRY;
        
        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];
       
        if (((keylen >= strlen("fld_get") &&
            memcmp(key, "fld_get", keylen) == 0))) {
                struct md_fld mf, *p, *reply;
                int size = sizeof(*reply);
               
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc)
                        RETURN(rc);
                p = lustre_swab_reqbuf(req, 1, sizeof(mf), lustre_swab_md_fld);
                mf = *p;
                rc = next->md_ops->mdo_get_info(&info->mti_ctxt, next, keylen, 
                                                key, &size, &mf);
                reply = lustre_msg_buf(req->rq_repmsg, 0, size);
                *reply = mf;
                RETURN(rc); 
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

static struct lu_device_operations mdt_lu_ops;

static int lu_device_is_mdt(struct lu_device *d)
{
        /*
         * XXX for now. Tags in lu_device_type->ldt_something are needed.
         */
        return ergo(d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static struct mdt_device *mdt_dev(struct lu_device *d)
{
        LASSERT(lu_device_is_mdt(d));
        return container_of(d, struct mdt_device, mdt_md_dev.md_lu_dev);
}

static int mdt_connect(struct mdt_thread_info *info,
                       struct ptlrpc_request *req, int offset)
{
        int result;

        result = target_handle_connect(req, mdt_handle);
        if (result == 0) {
                struct mdt_device *mdt = info->mti_mdt;
                struct obd_connect_data *data;

                data = lustre_msg_buf(req->rq_repmsg, 0, sizeof *data);
                result = seq_mgr_alloc(&info->mti_ctxt,
                                       mdt->mdt_seq_mgr, &data->ocd_seq);
        }
        return result;
}

static int mdt_disconnect(struct mdt_thread_info *info,
                          struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_getattr_name(struct mdt_thread_info *info,
                            struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_setxattr(struct mdt_thread_info *info,
                        struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_getxattr(struct mdt_thread_info *info,
                        struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_readpage(struct mdt_thread_info *info,
                        struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_reint(struct mdt_thread_info *info,
                     struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_close(struct mdt_thread_info *info,
                     struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_done_writing(struct mdt_thread_info *info,
                            struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_pin(struct mdt_thread_info *info,
                   struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_sync(struct mdt_thread_info *info,
                    struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_handle_quotacheck(struct mdt_thread_info *info,
                                 struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

static int mdt_handle_quotactl(struct mdt_thread_info *info,
                               struct ptlrpc_request *req, int offset)
{
        return -EOPNOTSUPP;
}

/*
 * DLM handlers.
 */

static struct ldlm_callback_suite cbs = {
        .lcs_completion = ldlm_server_completion_ast,
        .lcs_blocking   = ldlm_server_blocking_ast,
        .lcs_glimpse    = NULL
};

static int mdt_enqueue(struct mdt_thread_info *info,
                       struct ptlrpc_request *req, int offset)
{
        /*
         * info->mti_dlm_req already contains swapped and (if necessary)
         * converted dlm request.
         */
        LASSERT(info->mti_dlm_req);

        info->mti_fail_id = OBD_FAIL_LDLM_REPLY;
        return ldlm_handle_enqueue0(req, info->mti_dlm_req, &cbs);
}

static int mdt_convert(struct mdt_thread_info *info,
                       struct ptlrpc_request *req, int offset)
{
        LASSERT(info->mti_dlm_req);
        return ldlm_handle_convert0(req, info->mti_dlm_req);
}

static int mdt_bl_callback(struct mdt_thread_info *info,
                           struct ptlrpc_request *req, int offset)
{
        CERROR("bl callbacks should not happen on MDS\n");
        LBUG();
        return -EOPNOTSUPP;
}

static int mdt_cp_callback(struct mdt_thread_info *info,
                           struct ptlrpc_request *req, int offset)
{
        CERROR("cp callbacks should not happen on MDS\n");
        LBUG();
        return -EOPNOTSUPP;
}

/*
 * Build (DLM) resource name from fid.
 */
struct ldlm_res_id *fid_build_res_name(const struct lu_fid *f,
                                       struct ldlm_res_id *name)
{
        memset(name, 0, sizeof *name);
        /* we use fid_num() whoch includes also object version instread of raw
         * fid_oid(). */
        name->name[0] = fid_seq(f);
        name->name[1] = fid_num(f);
        return name;
}

/*
 * Return true if resource is for object identified by fid.
 */
int fid_res_name_eq(const struct lu_fid *f, const struct ldlm_res_id *name)
{
        return name->name[0] == fid_seq(f) && name->name[1] == fid_num(f);
}

/* issues dlm lock on passed @ns, @f stores it lock handle into @lh. */
int fid_lock(struct ldlm_namespace *ns, const struct lu_fid *f,
             struct lustre_handle *lh, ldlm_mode_t mode,
             ldlm_policy_data_t *policy)
{
        struct ldlm_res_id res_id;
        int flags = 0, rc;
        ENTRY;

        LASSERT(ns != NULL);
        LASSERT(lh != NULL);
        LASSERT(f != NULL);

        /* FIXME: is that correct to have @flags=0 here? */
        rc = ldlm_cli_enqueue(NULL, NULL, ns, *fid_build_res_name(f, &res_id),
                              LDLM_IBITS, policy, mode, &flags,
                              ldlm_blocking_ast, ldlm_completion_ast, NULL,
                              NULL, NULL, 0, NULL, lh);
        RETURN (rc == ELDLM_OK ? 0 : -EIO);
}

void fid_unlock(struct ldlm_namespace *ns, const struct lu_fid *f,
                struct lustre_handle *lh, ldlm_mode_t mode)
{
        struct ldlm_lock *lock;
        ENTRY;

        /* FIXME: this is debug stuff, remove it later. */
        lock = ldlm_handle2lock(lh);
        if (!lock) {
                CERROR("invalid lock handle "LPX64, lh->cookie);
                LBUG();
        }

        LASSERT(fid_res_name_eq(f, &lock->l_resource->lr_name));

        ldlm_lock_decref(lh, mode);
        EXIT;
}

static struct mdt_object *mdt_obj(struct lu_object *o)
{
        LASSERT(lu_device_is_mdt(o->lo_dev));
        return container_of(o, struct mdt_object, mot_obj.mo_lu);
}

struct mdt_object *mdt_object_find(struct lu_context *ctxt,
                                   struct mdt_device *d,
                                   struct lu_fid *f)
{
        struct lu_object *o;

        o = lu_object_find(ctxt, d->mdt_md_dev.md_lu_dev.ld_site, f);
        if (IS_ERR(o))
                return (struct mdt_object *)o;
        else
                return mdt_obj(o);
}

void mdt_object_put(struct lu_context *ctxt, struct mdt_object *o)
{
        lu_object_put(ctxt, &o->mot_obj.mo_lu);
}

struct lu_fid *mdt_object_fid(struct mdt_object *o)
{
        return lu_object_fid(&o->mot_obj.mo_lu);
}

int mdt_object_lock(struct ldlm_namespace *ns, struct mdt_object *o,
                    struct mdt_lock_handle *lh, __u64 ibits)
{
        ldlm_policy_data_t p = {
                .l_inodebits = {
                        .bits = ibits
                }
        };
        LASSERT(!lustre_handle_is_used(&lh->mlh_lh));
        LASSERT(lh->mlh_mode != LCK_MINMODE);

        return fid_lock(ns, mdt_object_fid(o), &lh->mlh_lh, lh->mlh_mode, &p);
}

void mdt_object_unlock(struct ldlm_namespace *ns, struct mdt_object *o,
                              struct mdt_lock_handle *lh)
{
        if (lustre_handle_is_used(&lh->mlh_lh)) {
                fid_unlock(ns, mdt_object_fid(o), &lh->mlh_lh, lh->mlh_mode);
                lh->mlh_lh.cookie = 0;
        }
}

struct mdt_object *mdt_object_find_lock(struct lu_context *ctxt,
                                        struct mdt_device *d,
                                        struct lu_fid *f,
                                        struct mdt_lock_handle *lh,
                                        __u64 ibits)
{
        struct mdt_object *o;

        o = mdt_object_find(ctxt, d, f);
        if (!IS_ERR(o)) {
                int result;

                result = mdt_object_lock(d->mdt_namespace, o, lh, ibits);
                if (result != 0) {
                        mdt_object_put(ctxt, o);
                        o = ERR_PTR(result);
                }
        }
        return o;
}

struct mdt_handler {
        const char *mh_name;
        int         mh_fail_id;
        __u32       mh_opc;
        __u32       mh_flags;
        int (*mh_act)(struct mdt_thread_info *info,
                      struct ptlrpc_request *req, int offset);
};

enum mdt_handler_flags {
        /*
         * struct mdt_body is passed in the 0-th incoming buffer.
         */
        HABEO_CORPUS = (1 << 0),
        /*
         * struct ldlm_request is passed in MDS_REQ_INTENT_LOCKREQ_OFF-th
         * incoming buffer.
         */
        HABEO_CLAVIS   = (1 << 1)
};

struct mdt_opc_slice {
        __u32               mos_opc_start;
        int                 mos_opc_end;
        struct mdt_handler *mos_hs;
};

static struct mdt_opc_slice mdt_handlers[];

static struct mdt_handler *mdt_handler_find(__u32 opc)
{
        struct mdt_opc_slice *s;
        struct mdt_handler   *h;

        h = NULL;
        for (s = mdt_handlers; s->mos_hs != NULL; s++) {
                if (s->mos_opc_start <= opc && opc < s->mos_opc_end) {
                        h = s->mos_hs + (opc - s->mos_opc_start);
                        if (h->mh_opc != 0)
                                LASSERT(h->mh_opc == opc);
                        else
                                h = NULL; /* unsupported opc */
                        break;
                }
        }
        return h;
}

static inline __u64 req_exp_last_xid(struct ptlrpc_request *req)
{
        return req->rq_export->exp_mds_data.med_mcd->mcd_last_xid;
}

static int mdt_lock_resname_compat(struct mdt_device *m,
                                   struct ldlm_request *req)
{
        /* XXX something... later. */
        return 0;
}

static int mdt_lock_reply_compat(struct mdt_device *m, struct ldlm_reply *rep)
{
        /* XXX something... later. */
        return 0;
}

/*
 * Invoke handler for this request opc. Also do necessary preprocessing
 * (according to handler ->mh_flags), and post-processing (setting of
 * ->last_{xid,committed}).
 */
static int mdt_req_handle(struct mdt_thread_info *info,
                          struct mdt_handler *h, struct ptlrpc_request *req,
                          int shift)
{
        int result;
        int off;
        int lock_conv;

        ENTRY;

        LASSERT(h->mh_act != NULL);
        LASSERT(h->mh_opc == req->rq_reqmsg->opc);
        LASSERT(current->journal_info == NULL);

        DEBUG_REQ(D_INODE, req, "%s", h->mh_name);

        if (h->mh_fail_id != 0)
                OBD_FAIL_RETURN(h->mh_fail_id, 0);

        off = MDS_REQ_REC_OFF + shift;
        lock_conv =
                h->mh_flags & HABEO_CLAVIS &&
                info->mti_mdt->mdt_flags & MDT_CL_COMPAT_RESNAME;

        result = 0;
        if (h->mh_flags & HABEO_CORPUS) {
                struct mdt_body *body;

                body = info->mti_body =
                        lustre_swab_reqbuf(req, off, sizeof *info->mti_body,
                                           lustre_swab_mdt_body);
                if (body != NULL) {
                        info->mti_object = mdt_object_find(&info->mti_ctxt,
                                                           info->mti_mdt,
                                                           &body->fid1);
                        if (IS_ERR(info->mti_object))
                                result = PTR_ERR(info->mti_object);
                } else {
                        CERROR("Can't unpack body\n");
                        result = -EFAULT;
                }
        } else if (lock_conv) {
                struct ldlm_request *dlm;

                LASSERT(shift == 0);
                dlm = info->mti_dlm_req =
                        lustre_swab_reqbuf(req, MDS_REQ_INTENT_LOCKREQ_OFF,
                                           sizeof *dlm,
                                           lustre_swab_ldlm_request);
                if (dlm != NULL)
                        result = mdt_lock_resname_compat(info->mti_mdt, dlm);
                else {
                        CERROR("Can't unpack dlm request\n");
                        result = -EFAULT;
                }
        }
        if (result == 0)
                /*
                 * Process request.
                 */
                result = h->mh_act(info, req, off);
        /*
         * XXX result value is unconditionally shoved into ->rq_status
         * (original code sometimes placed error code into ->rq_status, and
         * sometimes returned it to the
         * caller). ptlrpc_server_handle_request() doesn't check return value
         * anyway.
         */
        req->rq_status = result;

        LASSERT(current->journal_info == NULL);

        if (lock_conv) {
                struct ldlm_reply *rep;

                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof *rep);
                if (rep != NULL)
                        result = mdt_lock_reply_compat(info->mti_mdt, rep);
        }

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (result == 0 && h->mh_opc != MDS_DISCONNECT) {
                req->rq_reqmsg->last_xid = le64_to_cpu(req_exp_last_xid(req));
                target_committed_to_req(req);
        }
        RETURN(result);
}

void mdt_lock_handle_init(struct mdt_lock_handle *lh)
{
        lh->mlh_lh.cookie = 0ull;
        lh->mlh_mode = LCK_MINMODE;
}

void mdt_lock_handle_fini(struct mdt_lock_handle *lh)
{
        LASSERT(!lustre_handle_is_used(&lh->mlh_lh));
}

static void mdt_thread_info_init(struct mdt_thread_info *info)
{
        int i;

        info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
        /*
         * Poison size array.
         */
        for (i = 0; i < ARRAY_SIZE(info->mti_rep_buf_size); i++)
                info->mti_rep_buf_size[i] = ~0;
        info->mti_rep_buf_nr = i;
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_init(&info->mti_lh[i]);
        lu_context_enter(&info->mti_ctxt);
}

static void mdt_thread_info_fini(struct mdt_thread_info *info)
{
        int i;

        lu_context_exit(&info->mti_ctxt);
        if (info->mti_object != NULL) {
                mdt_object_put(&info->mti_ctxt, info->mti_object);
                info->mti_object = NULL;
        }
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_fini(&info->mti_lh[i]);
}

static int mds_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        /* TODO: enable the below check while really introducing msg version.
         * it's disabled because it will break compatibility with b1_4.
         */
        return (0);

        switch (msg->opc) {
        case MDS_CONNECT:
        case MDS_DISCONNECT:
        case OBD_PING:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_OBD_VERSION);
                break;
        case MDS_GETSTATUS:
        case MDS_GETATTR:
        case MDS_GETATTR_NAME:
        case MDS_STATFS:
        case MDS_READPAGE:
        case MDS_REINT:
        case MDS_CLOSE:
        case MDS_DONE_WRITING:
        case MDS_PIN:
        case MDS_SYNC:
        case MDS_GETXATTR:
        case MDS_SETXATTR:
        case MDS_SET_INFO:
        case MDS_QUOTACHECK:
        case MDS_QUOTACTL:
        case QUOTA_DQACQ:
        case QUOTA_DQREL:
                rc = lustre_msg_check_version(msg, LUSTRE_MDS_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_MDS_VERSION);
                break;
        case LDLM_ENQUEUE:
        case LDLM_CONVERT:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                rc = lustre_msg_check_version(msg, LUSTRE_DLM_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_DLM_VERSION);
                break;
        case OBD_LOG_CANCEL:
        case LLOG_ORIGIN_HANDLE_CREATE:
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
        case LLOG_ORIGIN_HANDLE_PREV_BLOCK:
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
        case LLOG_ORIGIN_HANDLE_CLOSE:
        case LLOG_CATINFO:
                rc = lustre_msg_check_version(msg, LUSTRE_LOG_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_LOG_VERSION);
                break;
        default:
                CERROR("MDS unknown opcode %d\n", msg->opc);
                rc = -ENOTSUPP;
        }
        return rc;
}

static int mdt_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process)
{
        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT: /* This will never get here, but for completeness. */
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case MDS_DISCONNECT:
        case OST_DISCONNECT:
               *process = 1;
               RETURN(0);

        case MDS_CLOSE:
        case MDS_SYNC: /* used in unmounting */
        case OBD_PING:
        case MDS_REINT:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = 0;
                /* XXX what should we set rq_status to here? */
                req->rq_status = -EAGAIN;
                RETURN(ptlrpc_error(req));
        }
}

/*
 * Handle recovery. Return:
 *        +1: continue request processing;
 *       -ve: abort immediately with the given error code;
 *         0: send reply with error code in req->rq_status;
 */
static int mdt_recovery(struct ptlrpc_request *req)
{
        int recovering;
        int abort_recovery;
        struct obd_device *obd;

        ENTRY;

        if (req->rq_reqmsg->opc == MDS_CONNECT)
                RETURN(+1);

        if (req->rq_export == NULL) {
                CERROR("operation %d on unconnected MDS from %s\n",
                       req->rq_reqmsg->opc,
                       libcfs_id2str(req->rq_peer));
                req->rq_status = -ENOTCONN;
                RETURN(0);
        }

        /* sanity check: if the xid matches, the request must be marked as a
         * resent or replayed */
        LASSERTF(ergo(req->rq_xid == req_exp_last_xid(req),
                      lustre_msg_get_flags(req->rq_reqmsg) &
                      (MSG_RESENT | MSG_REPLAY)),
                 "rq_xid "LPU64" matches last_xid, "
                 "expected RESENT flag\n", req->rq_xid);

        /* else: note the opposite is not always true; a RESENT req after a
         * failover will usually not match the last_xid, since it was likely
         * never committed. A REPLAYed request will almost never match the
         * last xid, however it could for a committed, but still retained,
         * open. */

        obd = req->rq_export->exp_obd;

        /* Check for aborted recovery... */
        spin_lock_bh(&obd->obd_processing_task_lock);
        abort_recovery = obd->obd_abort_recovery;
        recovering = obd->obd_recovering;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (abort_recovery) {
                target_abort_recovery(obd);
        } else if (recovering) {
                int rc;
                int should_process;

                rc = mdt_filter_recovery_request(req, obd, &should_process);
                if (rc != 0 || !should_process) {
                        LASSERT(rc < 0);
                        RETURN(rc);
                }
        }
        RETURN(+1);
}

static int mdt_reply(struct ptlrpc_request *req, struct mdt_thread_info *info)
{
        struct obd_device *obd;

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (req->rq_reqmsg->opc != OBD_PING)
                        DEBUG_REQ(D_ERROR, req, "Unexpected MSG_LAST_REPLAY");

                obd = req->rq_export != NULL ? req->rq_export->exp_obd : NULL;
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        RETURN(target_queue_final_reply(req, req->rq_status));
                } else {
                        /* Lost a race with recovery; let the error path
                         * DTRT. */
                        req->rq_status = -ENOTCONN;
                }
        }
        target_send_reply(req, req->rq_status, info->mti_fail_id);
        RETURN(req->rq_status);
}

static int mdt_handle0(struct ptlrpc_request *req, struct mdt_thread_info *info)
{
        struct mdt_handler *h;
        struct lustre_msg  *msg;
        int                 result;

        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);

        msg = req->rq_reqmsg;
        result = mds_msg_check_version(msg);
        if (result == 0) {
                result = mdt_recovery(req);
                switch (result) {
                case +1:
                        h = mdt_handler_find(msg->opc);
                        if (h != NULL)
                                result = mdt_req_handle(info, h, req, 0);
                        else {
                                req->rq_status = -ENOTSUPP;
                                result = ptlrpc_error(req);
                                break;
                        }
                        /* fall through */
                case 0:
                        result = mdt_reply(req, info);
                }
        } else
                CERROR(LUSTRE_MDT0_NAME" drops mal-formed request\n");
        RETURN(result);
}

static int mdt_handle(struct ptlrpc_request *req)
{
        int result;

        struct mdt_thread_info *info = ptlrpc_thread_key_get(req->rq_svc_thread,
                                                             &mdt_thread_key);
        ENTRY;

        mdt_thread_info_init(info);
        /* it can be NULL while CONNECT */
        if (req->rq_export)
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
        info->mti_ctxt.lc_thread = req->rq_svc_thread;

        result = mdt_handle0(req, info);
        mdt_thread_info_fini(info);
        return result;
}

static int mdt_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
        ENTRY;
        RETURN(ELDLM_LOCK_ABORTED);
}

struct ptlrpc_service *ptlrpc_init_svc_conf(struct ptlrpc_service_conf *c,
                                            svc_handler_t h, char *name,
                                            struct proc_dir_entry *proc_entry,
                                            svcreq_printfn_t prntfn)
{
        return ptlrpc_init_svc(c->psc_nbufs, c->psc_bufsize,
                               c->psc_max_req_size, c->psc_max_reply_size,
                               c->psc_req_portal, c->psc_rep_portal,
                               c->psc_watchdog_timeout,
                               h, name, proc_entry,
                               prntfn, c->psc_num_threads);
}

static int mdt_config(struct lu_context *ctx, struct mdt_device *m,
                      const char *name, void *buf, int size, int mode)
{
        struct md_device *child = m->mdt_child;
        ENTRY;
        RETURN(child->md_ops->mdo_config(ctx, child, name, buf, size, mode));
}

static int mdt_seq_mgr_hpr(struct lu_context *ctx, void *opaque, __u64 *seq,
                           int mode)
{
        struct mdt_device *m = opaque;
        int rc;
        ENTRY;

        rc = mdt_config(ctx, m, LUSTRE_CONFIG_METASEQ,
                        seq, sizeof(*seq),
                        mode);
        RETURN(rc);
}

static int mdt_seq_mgr_read(struct lu_context *ctx, void *opaque, __u64 *seq)
{
        ENTRY;
        RETURN(mdt_seq_mgr_hpr(ctx, opaque, seq, LUSTRE_CONFIG_GET));
}

static int mdt_seq_mgr_write(struct lu_context *ctx, void *opaque, __u64 *seq)
{
        ENTRY;
        RETURN(mdt_seq_mgr_hpr(ctx, opaque, seq, LUSTRE_CONFIG_SET));
}

struct lu_seq_mgr_ops seq_mgr_ops = {
        .smo_read  = mdt_seq_mgr_read,
        .smo_write = mdt_seq_mgr_write
};

static void mdt_fini(struct mdt_device *m)
{
        struct lu_device *d = &m->mdt_md_dev.md_lu_dev;

        if (d->ld_site != NULL) {
                lu_site_fini(d->ld_site);
                OBD_FREE_PTR(d->ld_site);
                d->ld_site = NULL;
        }
        if (m->mdt_service != NULL) {
                ptlrpc_unregister_service(m->mdt_service);
                m->mdt_service = NULL;
        }
        if (m->mdt_namespace != NULL) {
                ldlm_namespace_free(m->mdt_namespace, 0);
                m->mdt_namespace = NULL;
        }
        /* finish the stack */
        if (m->mdt_child) {
                struct lu_device *child = md2lu_dev(m->mdt_child);
                child->ld_type->ldt_ops->ldto_device_fini(child);
        }

        if (m->mdt_seq_mgr) {
                seq_mgr_fini(m->mdt_seq_mgr);
                m->mdt_seq_mgr = NULL;
        }

        LASSERT(atomic_read(&d->ld_ref) == 0);
        md_device_fini(&m->mdt_md_dev);
}

static int mdt_init0(struct mdt_device *m,
                     struct lu_device_type *t, struct lustre_cfg *cfg)
{
        int rc;
        struct lu_site *s;
        char   ns_name[48];
        struct obd_device *obd;
        struct lu_device  *mdt_child;
        const char *top   = lustre_cfg_string(cfg, 0);
        const char *child = lustre_cfg_string(cfg, 1);
        struct lu_context ctx;

        ENTRY;

        /* get next layer */
        obd = class_name2obd((char *)child);
        if (obd && obd->obd_lu_dev) {
                CDEBUG(D_INFO, "Child device is %s\n", child);
                m->mdt_child = lu2md_dev(obd->obd_lu_dev);
                mdt_child = md2lu_dev(m->mdt_child);
        } else {
                CDEBUG(D_INFO, "Child device %s is not found\n", child);
                RETURN(-EINVAL);
        }

        OBD_ALLOC_PTR(s);
        if (s == NULL)
                RETURN(-ENOMEM);

        md_device_init(&m->mdt_md_dev, t);
        m->mdt_md_dev.md_lu_dev.ld_ops = &mdt_lu_ops;
        lu_site_init(s, &m->mdt_md_dev.md_lu_dev);

        m->mdt_service_conf.psc_nbufs            = MDS_NBUFS;
        m->mdt_service_conf.psc_bufsize          = MDS_BUFSIZE;
        m->mdt_service_conf.psc_max_req_size     = MDS_MAXREQSIZE;
        m->mdt_service_conf.psc_max_reply_size   = MDS_MAXREPSIZE;
        m->mdt_service_conf.psc_req_portal       = MDS_REQUEST_PORTAL;
        m->mdt_service_conf.psc_rep_portal       = MDC_REPLY_PORTAL;
        m->mdt_service_conf.psc_watchdog_timeout = MDS_SERVICE_WATCHDOG_TIMEOUT;
        /*
         * We'd like to have a mechanism to set this on a per-device basis,
         * but alas...
         */
        m->mdt_service_conf.psc_num_threads = min(max(mdt_num_threads,
                                                      MDT_MIN_THREADS),
                                                  MDT_MAX_THREADS);
        snprintf(ns_name, sizeof ns_name, LUSTRE_MDT0_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);
        if (m->mdt_namespace == NULL)
                GOTO(err_fini_site, rc = -ENOMEM);

        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mdt_ldlm_client", &m->mdt_ldlm_client);

        m->mdt_service =
                ptlrpc_init_svc_conf(&m->mdt_service_conf, mdt_handle,
                                     LUSTRE_MDT0_NAME,
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (m->mdt_service == NULL)
                GOTO(err_free_ns, rc = -ENOMEM);

        /* init the stack */
        LASSERT(mdt_child->ld_type->ldt_ops->ldto_device_init != NULL);
        rc = mdt_child->ld_type->ldt_ops->ldto_device_init(mdt_child, top);
        if (rc) {
                CERROR("can't init device stack, rc %d\n", rc);
                GOTO(err_free_svc, rc);
        }

        m->mdt_seq_mgr = seq_mgr_init(&seq_mgr_ops, m);
        if (!m->mdt_seq_mgr) {
                CERROR("can't initialize sequence manager\n");
                GOTO(err_fini_child, rc);
        }

        rc = lu_context_init(&ctx);
        if (rc != 0)
                GOTO(err_fini_mgr, rc);

        lu_context_enter(&ctx);
        /* init sequence info after device stack is initialized. */
        rc = seq_mgr_setup(&ctx, m->mdt_seq_mgr);
        lu_context_exit(&ctx);
        if (rc)
                GOTO(err_fini_ctx, rc);

        rc = ptlrpc_start_threads(NULL, m->mdt_service, LUSTRE_MDT0_NAME);
        if (rc)
                GOTO(err_fini_ctx, rc);

        lu_context_fini(&ctx);
        RETURN(0);

err_fini_ctx:
        lu_context_fini(&ctx);
err_fini_mgr:
        seq_mgr_fini(m->mdt_seq_mgr);
        m->mdt_seq_mgr = NULL;
err_fini_child:
        mdt_child->ld_type->ldt_ops->ldto_device_fini(mdt_child);
err_free_svc:
        ptlrpc_unregister_service(m->mdt_service);
        m->mdt_service = NULL;
err_free_ns:
        ldlm_namespace_free(m->mdt_namespace, 0);
        m->mdt_namespace = NULL;
err_fini_site:
        lu_site_fini(s);
        OBD_FREE_PTR(s);
        RETURN(rc);
}

static struct lu_object *mdt_object_alloc(struct lu_context *ctxt,
                                          struct lu_device *d)
{
        struct mdt_object *mo;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *o;
                struct lu_object_header *h;

                o = &mo->mot_obj.mo_lu;
                h = &mo->mot_header;
                lu_object_header_init(h);
                lu_object_init(o, h, d);
                lu_object_add_top(h, o);
                return o;
        } else
                return NULL;
}

static int mdt_object_init(struct lu_context *ctxt, struct lu_object *o)
{
        struct mdt_device *d = mdt_dev(o->lo_dev);
        struct lu_device  *under;
        struct lu_object  *below;

        under = &d->mdt_child->md_lu_dev;
        below = under->ld_ops->ldo_object_alloc(ctxt, under);
        if (below != NULL) {
                lu_object_add(o, below);
                return 0;
        } else
                return -ENOMEM;
}

static void mdt_object_free(struct lu_context *ctxt, struct lu_object *o)
{
        struct lu_object_header *h;

        h = o->lo_header;
        lu_object_fini(o);
        lu_object_header_fini(h);
}

static void mdt_object_release(struct lu_context *ctxt, struct lu_object *o)
{
}

static int mdt_object_print(struct lu_context *ctxt,
                            struct seq_file *f, const struct lu_object *o)
{
        return seq_printf(f, LUSTRE_MDT0_NAME"-object@%p", o);
}

static struct lu_device_operations mdt_lu_ops = {
        .ldo_object_alloc   = mdt_object_alloc,
        .ldo_object_init    = mdt_object_init,
        .ldo_object_free    = mdt_object_free,
        .ldo_object_release = mdt_object_release,
        .ldo_object_print   = mdt_object_print
};

/* mds_connect copy */
static int mdt_obd_connect(struct lustre_handle *conn, struct obd_device *obd,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *data)
{
        struct obd_export *exp;
        int rc, abort_recovery;
        struct mdt_device *mdt;
        struct mds_export_data *med;
        struct mds_client_data *mcd = NULL;

        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        mdt = mdt_dev(obd->obd_lu_dev);

        /* Check for aborted recovery. */
        spin_lock_bh(&obd->obd_processing_task_lock);
        abort_recovery = obd->obd_abort_recovery;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (abort_recovery)
                target_abort_recovery(obd);

        /* XXX There is a small race between checking the list and adding a
         * new connection for the same UUID, but the real threat (list
         * corruption when multiple different clients connect) is solved.
         *
         * There is a second race between adding the export to the list,
         * and filling in the client data below.  Hence skipping the case
         * of NULL mcd above.  We should already be controlling multiple
         * connects at the client, and we can't hold the spinlock over
         * memory allocations without risk of deadlocking.
         */
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        LASSERT(exp);
        med = &exp->exp_mds_data;

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd)
                GOTO(out, rc = -ENOMEM);

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

out:
        if (rc) {
                if (mcd) {
                        OBD_FREE(mcd, sizeof(*mcd));
                        med->med_mcd = NULL;
                }
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }

        RETURN(rc);
}

static struct obd_ops mdt_obd_device_ops = {
        .o_owner = THIS_MODULE,
        .o_connect = mdt_obd_connect
};

static struct lu_device *mdt_device_alloc(struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct mdt_device *m;

        OBD_ALLOC_PTR(m);
        if (m != NULL) {
                int result;

                l = &m->mdt_md_dev.md_lu_dev;
                result = mdt_init0(m, t, cfg);
                if (result != 0) {
                        mdt_fini(m);
                        return ERR_PTR(result);
                }

        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

static void mdt_device_free(struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);

        mdt_fini(m);
        OBD_FREE_PTR(m);
}

static void *mdt_thread_init(struct ptlrpc_thread *t)
{
        struct mdt_thread_info *info;
        int result;

        OBD_ALLOC_PTR(info);
        if (info != NULL)
                result = lu_context_init(&info->mti_ctxt);
        else
                result = -ENOMEM;
        if (result != 0)
                info = ERR_PTR(result);
        return info;
}

static void mdt_thread_fini(struct ptlrpc_thread *t, void *data)
{
        struct mdt_thread_info *info = data;
        lu_context_fini(&info->mti_ctxt);
        OBD_FREE_PTR(info);
}

static struct ptlrpc_thread_key mdt_thread_key = {
        .ptk_init = mdt_thread_init,
        .ptk_fini = mdt_thread_fini
};

static int mdt_type_init(struct lu_device_type *t)
{
        return ptlrpc_thread_key_register(&mdt_thread_key);
}

static void mdt_type_fini(struct lu_device_type *t)
{
}

static struct lu_device_type_operations mdt_device_type_ops = {
        .ldto_init = mdt_type_init,
        .ldto_fini = mdt_type_fini,

        .ldto_device_alloc = mdt_device_alloc,
        .ldto_device_free  = mdt_device_free
};

static struct lu_device_type mdt_device_type = {
        .ldt_tags = LU_DEVICE_MD,
        .ldt_name = LUSTRE_MDT0_NAME,
        .ldt_ops  = &mdt_device_type_ops
};

static struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
        { 0 }
};

static struct lprocfs_vars lprocfs_mdt_module_vars[] = {
        { 0 }
};

LPROCFS_INIT_VARS(mdt, lprocfs_mdt_module_vars, lprocfs_mdt_obd_vars);

static int __init mdt_mod_init(void)
{
        struct lprocfs_static_vars lvars;

        mdt_num_threads = MDT_NUM_THREADS;
        lprocfs_init_vars(mdt, &lvars);
        return class_register_type(&mdt_obd_device_ops, lvars.module_vars,
                                   LUSTRE_MDT0_NAME, &mdt_device_type);
}

static void __exit mdt_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDT0_NAME);
}


#define DEF_HNDL(prefix, base, suffix, flags, opc, fn)                  \
[prefix ## _ ## opc - prefix ## _ ## base] = {                          \
        .mh_name    = #opc,                                             \
        .mh_fail_id = OBD_FAIL_ ## prefix ## _  ## opc ## suffix,       \
        .mh_opc     = prefix ## _  ## opc,                              \
        .mh_flags   = flags,                                            \
        .mh_act     = fn                                                \
}

#define DEF_MDT_HNDL(flags, name, fn)                   \
        DEF_HNDL(MDS, GETATTR, _NET, flags, name, fn)

static struct mdt_handler mdt_mds_ops[] = {
        DEF_MDT_HNDL(0,            CONNECT,        mdt_connect),
        DEF_MDT_HNDL(0,            DISCONNECT,     mdt_disconnect),
        DEF_MDT_HNDL(0,            GETSTATUS,      mdt_getstatus),
        DEF_MDT_HNDL(HABEO_CORPUS, GETATTR,        mdt_getattr),
        DEF_MDT_HNDL(HABEO_CORPUS, GETATTR_NAME,   mdt_getattr_name),
        DEF_MDT_HNDL(HABEO_CORPUS, SETXATTR,       mdt_setxattr),
        DEF_MDT_HNDL(HABEO_CORPUS, GETXATTR,       mdt_getxattr),
        DEF_MDT_HNDL(0,            STATFS,         mdt_statfs),
        DEF_MDT_HNDL(HABEO_CORPUS, READPAGE,       mdt_readpage),
        DEF_MDT_HNDL(0,            REINT,          mdt_reint),
        DEF_MDT_HNDL(HABEO_CORPUS, CLOSE,          mdt_close),
        DEF_MDT_HNDL(HABEO_CORPUS, DONE_WRITING,   mdt_done_writing),
        DEF_MDT_HNDL(0,            PIN,            mdt_pin),
        DEF_MDT_HNDL(HABEO_CORPUS, SYNC,           mdt_sync),
        DEF_MDT_HNDL(0,            SET_INFO,       mdt_set_info),
        DEF_MDT_HNDL(0,            GET_INFO,       mdt_get_info),
        DEF_MDT_HNDL(0,            QUOTACHECK,     mdt_handle_quotacheck),
        DEF_MDT_HNDL(0,            QUOTACTL,       mdt_handle_quotactl)
};

static struct mdt_handler mdt_obd_ops[] = {
};

#define DEF_DLM_HNDL(flags, name, fn)                   \
        DEF_HNDL(LDLM, ENQUEUE, , flags, name, fn)

static struct mdt_handler mdt_dlm_ops[] = {
        DEF_DLM_HNDL(HABEO_CLAVIS, ENQUEUE,        mdt_enqueue),
        DEF_DLM_HNDL(HABEO_CLAVIS, CONVERT,        mdt_convert),
        DEF_DLM_HNDL(0,            BL_CALLBACK,    mdt_bl_callback),
        DEF_DLM_HNDL(0,            CP_CALLBACK,    mdt_cp_callback)
};

static struct mdt_handler mdt_llog_ops[] = {
};

static struct mdt_opc_slice mdt_handlers[] = {
        {
                .mos_opc_start = MDS_GETATTR,
                .mos_opc_end   = MDS_LAST_OPC,
                .mos_hs        = mdt_mds_ops
        },
        {
                .mos_opc_start = OBD_PING,
                .mos_opc_end   = OBD_LAST_OPC,
                .mos_hs        = mdt_obd_ops
        },
        {
                .mos_opc_start = LDLM_ENQUEUE,
                .mos_opc_end   = LDLM_LAST_OPC,
                .mos_hs        = mdt_dlm_ops
        },
        {
                .mos_opc_start = LLOG_ORIGIN_HANDLE_CREATE,
                .mos_opc_end   = LLOG_LAST_OPC,
                .mos_hs        = mdt_llog_ops
        },
        {
                .mos_hs        = NULL
        }
};

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Target Prototype ("LUSTRE_MDT0_NAME")");
MODULE_LICENSE("GPL");

CFS_MODULE_PARM(mdt_num_threads, "ul", ulong, 0444,
                "number of mdt service threads to start");

cfs_module(mdt, "0.0.4", mdt_mod_init, mdt_mod_exit);
