/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mdt/mdt_handler.c
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
#include <lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <obd_support.h>
/* struct ptlrpc_request */
#include <lustre_net.h>
/* struct obd_export */
#include <lustre_export.h>
/* struct obd_device */
#include <obd.h>
/* lu2dt_dev() */
#include <dt_object.h>
#include "mdt_internal.h"

/*
 * Initialized in mdt_mod_init().
 */
unsigned long mdt_num_threads;

struct mdt_handler {
        const char *mh_name;
        int         mh_fail_id;
        __u32       mh_opc;
        __u32       mh_flags;
        int (*mh_act)(struct mdt_thread_info *info);

        const struct req_format *mh_fmt;
};

enum mdt_handler_flags {
        /*
         * struct mdt_body is passed in the incoming message, and object
         * identified by this fid exists on disk.
         */
        HABEO_CORPUS = (1 << 0),
        /*
         * struct ldlm_request is passed in the incoming message.
         */
        HABEO_CLAVIS = (1 << 1),
        /*
         * this request has fixed reply format, so that reply message can be
         * packed by generic code.
         */
        HABEO_REFERO = (1 << 2)
};

struct mdt_opc_slice {
        __u32               mos_opc_start;
        int                 mos_opc_end;
        struct mdt_handler *mos_hs;
};

static struct mdt_opc_slice mdt_handlers[];

static int                    mdt_handle    (struct ptlrpc_request *req);
static struct mdt_device     *mdt_dev       (struct lu_device *d);
static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags);

static struct lu_context_key       mdt_thread_key;
static struct lu_object_operations mdt_obj_ops;


static int mdt_getstatus(struct mdt_thread_info *info)
{
        struct md_device *next  = info->mti_mdt->mdt_child;
        int               result;
        struct mdt_body  *body;

        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                result = -ENOMEM;
        else {
                body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
                result = next->md_ops->mdo_root_get(info->mti_ctxt,
                                                    next, &body->fid1);
                if (result == 0)
                        body->valid |= OBD_MD_FLID;
        }

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
        RETURN(result);
}

static int mdt_statfs(struct mdt_thread_info *info)
{
        struct md_device  *next  = info->mti_mdt->mdt_child;
        struct obd_statfs *osfs;
        int                result;

        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR(LUSTRE_MDT0_NAME": statfs lustre_pack_reply failed\n");
                result = -ENOMEM;
        } else {
                osfs = req_capsule_server_get(&info->mti_pill, &RMF_OBD_STATFS);
                /* XXX max_age optimisation is needed here. See mds_statfs */
                result = next->md_ops->mdo_statfs(info->mti_ctxt,
                                                  next, &info->mti_sfs);
                statfs_pack(osfs, &info->mti_sfs);
        }

        RETURN(result);
}

void mdt_pack_attr2body(struct mdt_body *b, struct lu_attr *attr)
{
        b->valid |= OBD_MD_FLCTIME | OBD_MD_FLUID |
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

static int mdt_getattr_pack_msg(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        const struct mdt_body *body = info->mti_body;
        struct req_capsule *pill = &info->mti_pill;
#endif
        struct md_object *next = mdt_object_child(info->mti_object);
        struct lu_attr *la = &info->mti_attr;
        int rc;
        ENTRY;

        rc = mo_attr_get(info->mti_ctxt, next, la);
        if (rc){
                RETURN(rc);
        }
#ifdef MDT_CODE
        if ((S_ISREG(la->la_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(la->la_mode) && (body->valid & OBD_MD_FLDIREA))) {
                rc = mo_xattr_get(info->mti_ctxt, next, NULL, 0, "lov");

                CDEBUG(D_INODE, "got %d bytes MD data for object "DFID3"\n",
                       rc, PFID3(mdt_object_fid(info->mti_object)));
                if (rc < 0) {
                        if (rc != -ENODATA) {
                                CERROR("error getting MD "DFID3": rc = %d\n",
                                       PFID3(mdt_object_fid(info->mti_object)),
                                       rc);
                                RETURN(rc);
                        }
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, 0);
                } else if (rc > MAX_MD_SIZE) {
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, 0);
                        CERROR("MD size %d larger than maximum possible %u\n",
                               rc, MAX_MD_SIZE);
                } else {
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, rc);
                }
        } else if (S_ISLNK(la->la_mode) && (body->valid & OBD_MD_LINKNAME)) {
                /* It also uese the mdt_md to hold symname */
                int len = min_t(int, la->la_size + 1, body->eadatasize);
                req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, len);
        }

#ifdef CONFIG_FS_POSIX_ACL
        if ((mdt_info_req(info)->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (body->valid & OBD_MD_FLACL)) {

                rc = mo_xattr_get(info->mti_ctxt, next,
                                  NULL, 0, XATTR_NAME_ACL_ACCESS);
                if (rc < 0) {
                        if (rc != -ENODATA) {
                                CERROR("got acl size: %d\n", rc);
                                RETURN(rc);
                        }
                        req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER, 0);
                } else
                        req_capsule_set_size(pill, &RMF_EADATA, RCL_SERVER, rc);
        }
#endif
#endif
        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDT_GETATTR_PACK test\n");
                RETURN(-ENOMEM);
        }
        rc = req_capsule_pack(&info->mti_pill);
        if (rc) {
                CERROR("lustre_pack_reply failed: rc %d\n", rc);
                RETURN(rc);
        }

        RETURN(0);
}

static int mdt_getattr_internal(struct mdt_thread_info *info)
{
        struct md_object *next = mdt_object_child(info->mti_object);
        const struct mdt_body  *reqbody = info->mti_body;
        struct mdt_body  *repbody;
        struct lu_attr *la = &info->mti_attr;
        int rc;
#ifdef MDT_CODE
        void *buffer;
        int length;
#endif
        ENTRY;

        rc = mo_attr_get(info->mti_ctxt, next, la);
        if (rc){
                CERROR("getattr error for "DFID3": %d\n",
                        PFID3(&reqbody->fid1), rc);
                RETURN(rc);
        }

        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        mdt_pack_attr2body(repbody, la);
        repbody->fid1 = *mdt_object_fid(info->mti_object);
        repbody->valid |= OBD_MD_FLID;

#ifdef MDT_CODE
        buffer = req_capsule_server_get(&info->mti_pill, &RMF_MDT_MD);
        length = req_capsule_get_size(&info->mti_pill, &RMF_MDT_MD,
                                      RCL_SERVER);

        if ((S_ISREG(la->la_mode) && (reqbody->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(la->la_mode) && (reqbody->valid & OBD_MD_FLDIREA))) {
                rc = mo_xattr_get(info->mti_ctxt, next,
                                  buffer, length, "lov");
                if (rc < 0)
                        RETURN(rc);

                if (S_ISDIR(la->la_mode))
                        repbody->valid |= OBD_MD_FLDIREA;
                else
                        repbody->valid |= OBD_MD_FLEASIZE;
                repbody->eadatasize = rc;
        } else if (S_ISLNK(la->la_mode) &&
                          (reqbody->valid & OBD_MD_LINKNAME) != 0) {
                /* FIXME How to readlink??
                rc = mo_xattr_get(info->mti_ctxt, next,
                                  buffer, length, "readlink");
                */ rc = 10;
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                        RETURN(rc);
                } else {
                        repbody->valid |= OBD_MD_LINKNAME;
                        repbody->eadatasize = rc + 1;
                        ((char*)buffer)[rc] = 0;        /* NULL terminate */
                        CDEBUG(D_INODE, "read symlink dest %s\n", (char*)buffer);
                }
        }

        if (reqbody->valid & OBD_MD_FLMODEASIZE) {
                repbody->max_cookiesize = MAX_MD_SIZE; /*FIXME*/
                repbody->max_mdsize = MAX_MD_SIZE;
                repbody->valid |= OBD_MD_FLMODEASIZE;
        }


#ifdef CONFIG_FS_POSIX_ACL
        if ((mdt_info_req(info)->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (reqbody->valid & OBD_MD_FLACL)) {
                buffer = req_capsule_server_get(&info->mti_pill,
                                                &RMF_EADATA);
                length = req_capsule_get_size(&info->mti_pill,
                                              &RMF_EADATA,
                                              RCL_SERVER);
                rc = mo_xattr_get(info->mti_ctxt, next,
                                  buffer, length, XATTR_NAME_ACL_ACCESS);

                if (rc < 0) {
                        if (rc != -ENODATA) {
                                CERROR("got acl size: %d\n", rc);
                                RETURN(rc);
                        }
                        rc = 0;
                }
                repbody->aclsize = rc;
                repbody->valid |= OBD_MD_FLACL;
        }
#endif
#endif
        RETURN(0);
}

static int mdt_getattr(struct mdt_thread_info *info)
{
        int result;

        LASSERT(info->mti_object != NULL);
        LASSERT(lu_object_assert_exists(info->mti_ctxt,
                                        &info->mti_object->mot_obj.mo_lu));
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR(LUSTRE_MDT0_NAME": getattr lustre_pack_reply failed\n");
                result = -ENOMEM;
        } else {
                result = mdt_getattr_pack_msg(info);
                if (result == 0)
                        result = mdt_getattr_internal(info);
        }
        RETURN(result);
}

/* @ Huang Hua
 * UPDATE lock should be taken against parent, and be release before exit;
 * child_bits lock should be taken against child, and be returned back:
 *            (1)normal request should release the child lock;
 *            (2)intent request will grant the lock to client.
 */
static int mdt_getattr_name_lock(struct mdt_thread_info *info,
                                 struct mdt_lock_handle *lhc,
                                 __u64 child_bits)
{
        struct mdt_object *parent = info->mti_object;
        struct mdt_object *child;
        struct md_object  *next = mdt_object_child(info->mti_object);
        const char *name;
        int result;
        struct mdt_lock_handle *lhp;
        struct lu_fid child_fid;
        struct ldlm_namespace *ns;
        ENTRY;

        LASSERT(info->mti_object != NULL);

        name = req_capsule_client_get(&info->mti_pill, &RMF_NAME);
        if (name == NULL)
                RETURN(-EFAULT);

        ns = info->mti_mdt->mdt_namespace;
        /*step 1: lock parent */
        lhp = &info->mti_lh[MDT_LH_PARENT];
        lhp->mlh_mode = LCK_CR;
        result = mdt_object_lock(ns, parent, lhp, MDS_INODELOCK_UPDATE);
        if (result != 0)
                RETURN(result);

        /*step 2: lookup child's fid by name */
        result = mdo_lookup(info->mti_ctxt, next, name, &child_fid);
        if (result != 0)
                GOTO(out_parent, result);

        /*step 3: find the child object by fid */
        child = mdt_object_find(info->mti_ctxt, info->mti_mdt, &child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, result = PTR_ERR(child));

        /*step 4: lock child: this lock is returned back to caller
         *                    if successfully get attr.
         */
        lhc->mlh_mode = LCK_CR;
        result = mdt_object_lock(ns, child, lhc, child_bits);
        if (result != 0)
                GOTO(out_child, result);

        /* finally, we can get attr for child. */
        result = mdt_getattr_pack_msg(info);
        if (result == 0) {
                struct ldlm_reply *ldlm_rep;
                ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
                LASSERT(ldlm_rep);
                intent_set_disposition(ldlm_rep, DISP_IT_EXECD);
                result = mdt_getattr_internal(info);
                if (result)
                        intent_set_disposition(ldlm_rep, DISP_LOOKUP_NEG);
                else
                        intent_set_disposition(ldlm_rep, DISP_LOOKUP_POS);
        }
        if (result != 0)
                mdt_object_unlock(ns, child, lhc);
        EXIT;

out_child:
        mdt_object_put(info->mti_ctxt, child);
out_parent:
        mdt_object_unlock(ns, parent, lhp);
        return result;
}

/* normal handler: should release the child lock */
static int mdt_getattr_name(struct mdt_thread_info *info)
{
        struct mdt_lock_handle lhc = {{0}};
        int rc;

        ENTRY;

        rc = mdt_getattr_name_lock(info, &lhc, MDS_INODELOCK_UPDATE);
        if (rc == 0 && lustre_handle_is_used(&lhc.mlh_lh))
                ldlm_lock_decref(&lhc.mlh_lh, lhc.mlh_mode);
        RETURN(rc);
}

static struct lu_device_operations mdt_lu_ops;

static int lu_device_is_mdt(struct lu_device *d)
{
        /*
         * XXX for now. Tags in lu_device_type->ldt_something are needed.
         */
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static struct mdt_device *mdt_dev(struct lu_device *d)
{
        LASSERT(lu_device_is_mdt(d));
        return container_of0(d, struct mdt_device, mdt_md_dev.md_lu_dev);
}

static int mdt_connect(struct mdt_thread_info *info)
{
        int result;
        struct ptlrpc_request *req;

        req = mdt_info_req(info);
        result = target_handle_connect(req, mdt_handle);
        if (result == 0) {
                LASSERT(req->rq_export != NULL);
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
        }
        return result;
}

static int mdt_disconnect(struct mdt_thread_info *info)
{
        return target_handle_disconnect(mdt_info_req(info));
}

static int mdt_readpage(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

static int mdt_reint_internal(struct mdt_thread_info *info, __u32 op)
{
        int rc;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_UNPACK, -EFAULT);

        rc = mdt_reint_unpack(info, op);
        if (rc == 0) {
                struct mdt_reint_reply *rep;

                rep = &info->mti_reint_rep;
                rep->mrr_body = req_capsule_server_get(&info->mti_pill,
                                                       &RMF_MDT_BODY);
                if (rep->mrr_body != NULL)
                        /*
                         * XXX fill other fields in @rep with pointers to
                         * reply buffers.
                         */
                        rc = mdt_reint_rec(info);
                else
                        rc = -EFAULT;
        }

        RETURN(rc);
}

static long mdt_reint_opcode(struct mdt_thread_info *info,
                             const struct req_format **fmt)
{
        __u32 *ptr;
        long opc;

        opc = -EINVAL;
        ptr = req_capsule_client_get(&info->mti_pill, &RMF_REINT_OPC);
        if (ptr != NULL) {
                opc = *ptr;
                DEBUG_REQ(D_INODE, mdt_info_req(info), "reint opt = %ld", opc);
                if (opc < REINT_MAX && fmt[opc] != NULL)
                        req_capsule_extend(&info->mti_pill, fmt[opc]);
                else
                        CERROR("Unsupported opc: %ld\n", opc);
        }
        return opc;
}

static int mdt_reint(struct mdt_thread_info *info)
{
        long opc;
        int  rc;

        static const struct req_format *reint_fmts[REINT_MAX] = {
                [REINT_SETATTR] = &RQF_MDS_REINT_SETATTR,
                [REINT_CREATE]  = &RQF_MDS_REINT_CREATE,
                [REINT_LINK]    = &RQF_MDS_REINT_LINK,
                [REINT_UNLINK]  = &RQF_MDS_REINT_UNLINK,
                [REINT_RENAME]  = &RQF_MDS_REINT_RENAME,
                [REINT_OPEN]    = &RQF_MDS_REINT_OPEN
        };

        ENTRY;

        opc = mdt_reint_opcode(info, reint_fmts);
        if (opc >= 0) {
                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                rc = req_capsule_pack(&info->mti_pill);
                if (rc == 0)
                        rc = mdt_reint_internal(info, opc);
        } else
                rc = opc;
        RETURN(rc);
}

static int mdt_close(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        /* TODO: dual to open handling, orphan handling */
        struct mdt_body * reqbody;
        struct mdt_body * repbody;

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);

#endif
        return -EOPNOTSUPP;
}

static int mdt_done_writing(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

static int mdt_pin(struct mdt_thread_info *info)
{
#ifdef MDT_CODE
        /* TODO: This is open handling. */
#endif
        return -EOPNOTSUPP;
}

#ifdef MDT_CODE
/* TODO these two methods not available now. */

/* this should sync the whole device */
static int mdt_device_sync(struct mdt_thread_info *info)
{
        return 0;
}

/* this should sync this object */
static int mdt_object_sync(struct mdt_thread_info *info)
{
        return 0;
}

static int mdt_sync(struct mdt_thread_info *info)
{
        struct mdt_body *body;
        struct req_capsule *pill = &info->mti_pill;
        int rc;
        ENTRY;

        /* The fid may be zero, so we req_capsule_set manually */
        req_capsule_set(pill, &RQF_MDS_SYNC);

        body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(-EINVAL);

        if (fid_seq(&body->fid1) == 0) {
                /* sync the whole device */
                rc = req_capsule_pack(pill);
                if (rc == 0)
                        rc = mdt_device_sync(info);
        } else {
                /* sync an object */
                rc = mdt_unpack_req_pack_rep(info, HABEO_CORPUS | HABEO_REFERO);
                if (rc != 0)
                        RETURN(rc);

                rc = mdt_object_sync(info);
                if (rc != 0)
                        RETURN(rc);

                rc = mo_attr_get(info->mti_ctxt,
                                 mdt_object_child(info->mti_object),
                                 &info->mti_attr);
                if (rc != 0)
                        RETURN(rc);

                body = req_capsule_server_get(pill, &RMF_MDT_BODY);
                mdt_pack_attr2body(body, &info->mti_attr);
                body->fid1 = *mdt_object_fid(info->mti_object);
                body->valid |= OBD_MD_FLID;
        }
        RETURN(rc);
}
#else
static int mdt_sync(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}
#endif


static int mdt_handle_quotacheck(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

static int mdt_handle_quotactl(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

/*
 * OBD PING and other handlers.
 */

static int mdt_obd_ping(struct mdt_thread_info *info)
{
        int result;
        ENTRY;
        result = target_handle_ping(mdt_info_req(info));
        RETURN(result);
}

static int mdt_obd_log_cancel(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

static int mdt_obd_qc_callback(struct mdt_thread_info *info)
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

static int mdt_enqueue(struct mdt_thread_info *info)
{
        /*
         * info->mti_dlm_req already contains swapped and (if necessary)
         * converted dlm request.
         */
        LASSERT(info->mti_dlm_req != NULL);

        info->mti_fail_id = OBD_FAIL_LDLM_REPLY;
        return ldlm_handle_enqueue0(info->mti_mdt->mdt_namespace,
                                    mdt_info_req(info),
                                    info->mti_dlm_req, &cbs);
}

static int mdt_convert(struct mdt_thread_info *info)
{
        LASSERT(info->mti_dlm_req);
        return ldlm_handle_convert0(mdt_info_req(info), info->mti_dlm_req);
}

static int mdt_bl_callback(struct mdt_thread_info *info)
{
        CERROR("bl callbacks should not happen on MDS\n");
        LBUG();
        return -EOPNOTSUPP;
}

static int mdt_cp_callback(struct mdt_thread_info *info)
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
        name->name[0] = fid_seq(f);
        name->name[1] = fid_oid(f);
        name->name[2] = fid_ver(f);
        return name;
}

/*
 * Return true if resource is for object identified by fid.
 */
int fid_res_name_eq(const struct lu_fid *f, const struct ldlm_res_id *name)
{
        return name->name[0] == fid_seq(f) &&
                name->name[1] == fid_oid(f) &&
                name->name[2] == fid_ver(f);
}

/* issues dlm lock on passed @ns, @f stores it lock handle into @lh. */
int fid_lock(struct ldlm_namespace *ns, const struct lu_fid *f,
             struct lustre_handle *lh, ldlm_mode_t mode,
             ldlm_policy_data_t *policy)
{
        struct ldlm_res_id res_id;
        int flags = 0;
        int rc;
        ENTRY;

        LASSERT(ns != NULL);
        LASSERT(lh != NULL);
        LASSERT(f != NULL);

        /* FIXME: is that correct to have @flags=0 here? */
        rc = ldlm_cli_enqueue(NULL, NULL, ns, *fid_build_res_name(f, &res_id),
                              LDLM_IBITS, policy, mode, &flags,
                              ldlm_blocking_ast, ldlm_completion_ast, NULL,
                              NULL, NULL, 0, NULL, lh);
        RETURN(rc == ELDLM_OK ? 0 : -EIO);
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
        return container_of0(o, struct mdt_object, mot_obj.mo_lu);
}

struct mdt_object *mdt_object_find(const struct lu_context *ctxt,
                                   struct mdt_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o;

        o = lu_object_find(ctxt, d->mdt_md_dev.md_lu_dev.ld_site, f);
        if (IS_ERR(o))
                return (struct mdt_object *)o;
        else
                return mdt_obj(o);
}

void mdt_object_put(const struct lu_context *ctxt, struct mdt_object *o)
{
        lu_object_put(ctxt, &o->mot_obj.mo_lu);
}

const struct lu_fid *mdt_object_fid(struct mdt_object *o)
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

struct mdt_object *mdt_object_find_lock(const struct lu_context *ctxt,
                                        struct mdt_device *d,
                                        const struct lu_fid *f,
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
        return req->rq_export->exp_mdt_data.med_mcd->mcd_last_xid;
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
 * Generic code handling requests that have struct mdt_body passed in:
 *
 *  - extract mdt_body from request and save it in @info, if present;
 *
 *  - create lu_object, corresponding to the fid in mdt_body, and save it in
 *  @info;
 *
 *  - if HABEO_CORPUS flag is set for this request type check whether object
 *  actually exists on storage (lu_object_exists()).
 *
 */
static int mdt_body_unpack(struct mdt_thread_info *info, __u32 flags)
{
        int result;
        const struct mdt_body    *body;
        struct mdt_object        *obj;
        const struct lu_context  *ctx;
        struct req_capsule *pill;

        ctx = info->mti_ctxt;
        pill = &info->mti_pill;

        body = info->mti_body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body != NULL) {
                if (fid_is_sane(&body->fid1)) {
                        obj = mdt_object_find(ctx, info->mti_mdt, &body->fid1);
                        if (!IS_ERR(obj)) {
                                if ((flags & HABEO_CORPUS) &&
                                    !lu_object_exists(ctx,
                                                      &obj->mot_obj.mo_lu)) {
                                        mdt_object_put(ctx, obj);
                                        result = -ENOENT;
                                } else {
                                        info->mti_object = obj;
                                        result = 0;
                                }
                        } else
                                result = PTR_ERR(obj);
                } else {
                        CERROR("Invalid fid: "DFID3"\n", PFID3(&body->fid1));
                        result = -EINVAL;
                }
        } else
                result = -EFAULT;
        return result;
}

static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags)
{
        struct req_capsule *pill;
        int result;

        ENTRY;
        pill = &info->mti_pill;

        if (req_capsule_has_field(pill, &RMF_MDT_BODY))
                result = mdt_body_unpack(info, flags);
        else
                result = 0;

        if (result == 0 && (flags & HABEO_REFERO))
                result = req_capsule_pack(pill);

        RETURN(result);
}

/*
 * Invoke handler for this request opc. Also do necessary preprocessing
 * (according to handler ->mh_flags), and post-processing (setting of
 * ->last_{xid,committed}).
 */
static int mdt_req_handle(struct mdt_thread_info *info,
                          struct mdt_handler *h, struct ptlrpc_request *req)
{
        int   result;
        __u32 flags;

        ENTRY;

        LASSERT(h->mh_act != NULL);
        LASSERT(h->mh_opc == req->rq_reqmsg->opc);
        LASSERT(current->journal_info == NULL);

        DEBUG_REQ(D_INODE, req, "%s", h->mh_name);

        if (h->mh_fail_id != 0)
                OBD_FAIL_RETURN(h->mh_fail_id, 0);

        result = 0;
        flags = h->mh_flags;
        LASSERT(ergo(flags & (HABEO_CORPUS | HABEO_REFERO), h->mh_fmt != NULL));

        req_capsule_init(&info->mti_pill,
                         req, RCL_SERVER, info->mti_rep_buf_size);

        if (h->mh_fmt != NULL) {
                req_capsule_set(&info->mti_pill, h->mh_fmt);
                result = mdt_unpack_req_pack_rep(info, flags);
        }

        if (result == 0 && flags & HABEO_CLAVIS) {
                struct ldlm_request *dlm_req;

                LASSERT(h->mh_fmt != NULL);

                dlm_req = req_capsule_client_get(&info->mti_pill, &RMF_DLM_REQ);
                if (dlm_req != NULL) {
                        if (info->mti_mdt->mdt_flags & MDT_CL_COMPAT_RESNAME)
                                result = mdt_lock_resname_compat(info->mti_mdt,
                                                                 dlm_req);
                        info->mti_dlm_req = dlm_req;
                } else {
                        CERROR("Can't unpack dlm request\n");
                        result = -EFAULT;
                }
        }

        if (result == 0)
                /*
                 * Process request.
                 */
                result = h->mh_act(info);
        /*
         * XXX result value is unconditionally shoved into ->rq_status
         * (original code sometimes placed error code into ->rq_status, and
         * sometimes returned it to the
         * caller). ptlrpc_server_handle_request() doesn't check return value
         * anyway.
         */
        req->rq_status = result;

        LASSERT(current->journal_info == NULL);

        if (result == 0 && flags & HABEO_CLAVIS &&
            info->mti_mdt->mdt_flags & MDT_CL_COMPAT_RESNAME) {
                struct ldlm_reply *dlm_rep;

                dlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
                if (dlm_rep != NULL)
                        result = mdt_lock_reply_compat(info->mti_mdt, dlm_rep);
        }

        /* If we're DISCONNECTing, the mdt_export_data is already freed */
        if (result == 0 && h->mh_opc != MDS_DISCONNECT) {
#ifdef MDT_CODE
                /* FIXME: fake untill journal callback & open handling is OK.*/ 
                __u64 last_transno;
                __u64 last_committed;
                struct mdt_device *mdt = info->mti_mdt;

                LASSERT(mdt != NULL);
                spin_lock(&mdt->mdt_transno_lock);
                last_transno = ++ (mdt->mdt_last_transno);
                last_committed = ++ (mdt->mdt_last_committed);
                spin_unlock(&mdt->mdt_transno_lock);
                
                req->rq_repmsg->transno = req->rq_transno = last_transno;
                req->rq_repmsg->last_xid = req->rq_xid;
                req->rq_repmsg->last_committed = last_committed;
                req->rq_export->exp_obd->obd_last_committed = last_committed;
#else
                req->rq_repmsg->last_xid = le64_to_cpu(req_exp_last_xid(req));
                target_committed_to_req(req);
#endif
        }
        req_capsule_fini(&info->mti_pill);
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
        for (i = 0; i < ARRAY_SIZE(info->mti_rep_buf_size); i++)
                info->mti_rep_buf_size[i] = 0;
        info->mti_rep_buf_nr = i;
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_init(&info->mti_lh[i]);
}

static void mdt_thread_info_fini(struct mdt_thread_info *info)
{
        int i;

        if (info->mti_object != NULL) {
                mdt_object_put(info->mti_ctxt, info->mti_object);
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
                                result = mdt_req_handle(info, h, req);
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

/*
 * MDT handler function called by ptlrpc service thread when request comes.
 *
 * XXX common "target" functionality should be factored into separate module
 * shared by mdt, ost and stand-alone services like fld.
 */
static int mdt_handle(struct ptlrpc_request *req)
{
        int result;
        struct lu_context      *ctx;
        struct mdt_thread_info *info;
        ENTRY;

        ctx = req->rq_svc_thread->t_ctx;
        LASSERT(ctx != NULL);
        LASSERT(ctx->lc_thread == req->rq_svc_thread);

        info = lu_context_key_get(ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        mdt_thread_info_init(info);
        /* it can be NULL while CONNECT */
        if (req->rq_export)
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);

        result = mdt_handle0(req, info);
        mdt_thread_info_fini(info);
        RETURN(result);
}

/*Please move these functions from mds to mdt*/
int intent_disposition(struct ldlm_reply *rep, int flag)
{
        if (!rep)
                return 0;
        return (rep->lock_policy_res1 & flag);
}

void intent_set_disposition(struct ldlm_reply *rep, int flag)
{
        if (!rep)
                return;
        rep->lock_policy_res1 |= flag;
}

enum mdt_it_code {
        MDT_IT_OPEN,
        MDT_IT_OCREAT,
        MDT_IT_CREATE,
        MDT_IT_GETATTR,
        MDT_IT_READDIR,
        MDT_IT_LOOKUP,
        MDT_IT_UNLINK,
        MDT_IT_TRUNC,
        MDT_IT_GETXATTR,
        MDT_IT_NR
};

static int mdt_intent_getattr(enum mdt_it_code opcode,
                              struct mdt_thread_info *info,
                              struct ldlm_lock **,
                              int);
static int mdt_intent_reint(enum mdt_it_code opcode,
                            struct mdt_thread_info *info,
                            struct ldlm_lock **,
                            int);

static struct mdt_it_flavor {
        const struct req_format *it_fmt;
        __u32                    it_flags;
        int                    (*it_act)(enum mdt_it_code ,
                                         struct mdt_thread_info *,
                                         struct ldlm_lock **,
                                         int);
        long                     it_reint;
} mdt_it_flavor[] = {
        [MDT_IT_OPEN]     = {
                .it_fmt   = &RQF_LDLM_INTENT,
                /*.it_flags = HABEO_REFERO,*/
                .it_flags = 0,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_OPEN
        },
        [MDT_IT_OCREAT]   = {
                .it_fmt   = &RQF_LDLM_INTENT,
                .it_flags = 0,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_OPEN
        },
        [MDT_IT_CREATE]   = {
                .it_fmt   = &RQF_LDLM_INTENT,
                .it_flags = 0,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_CREATE
        },
        [MDT_IT_GETATTR]  = {
                .it_fmt   = &RQF_LDLM_INTENT_GETATTR,
                .it_flags = 0,
                .it_act   = mdt_intent_getattr
        },
        [MDT_IT_READDIR]  = {
                .it_fmt   = NULL,
                .it_flags = 0,
                .it_act   = NULL
        },
        [MDT_IT_LOOKUP]   = {
                .it_fmt   = &RQF_LDLM_INTENT_GETATTR,
                .it_flags = 0,
                .it_act   = mdt_intent_getattr
        },
        [MDT_IT_UNLINK]   = {
                .it_fmt   = &RQF_LDLM_INTENT_UNLINK,
                .it_flags = 0,
                .it_act   = NULL, /* XXX can be mdt_intent_reint, ? */
                .it_reint = REINT_UNLINK
        },
        [MDT_IT_TRUNC]    = {
                .it_fmt   = NULL,
                .it_flags = 0,
                .it_act   = NULL
        },
        [MDT_IT_GETXATTR] = {
                .it_fmt   = NULL,
                .it_flags = 0,
                .it_act   = NULL
        }
};

static int mdt_intent_getattr(enum mdt_it_code opcode,
                              struct mdt_thread_info *info,
                              struct ldlm_lock **lockp,
                              int flags)
{
        __u64  child_bits;
        struct ldlm_lock *old_lock = *lockp;
        struct ldlm_lock *new_lock = NULL;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct ldlm_reply *ldlm_rep;
        struct mdt_lock_handle lhc = {{0}};
        int    rc;

        ENTRY;

        switch (opcode) {
        case MDT_IT_LOOKUP:
                child_bits = MDS_INODELOCK_LOOKUP;
                break;
        case MDT_IT_GETATTR:
                child_bits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE;
                break;
        default:
                CERROR("Unhandled till now");
                RETURN(-EINVAL);
                break;
        }

        rc = mdt_getattr_name_lock(info, &lhc, child_bits);
        if (rc)
                RETURN(rc);
        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        ldlm_rep->lock_policy_res2 = rc;

        intent_set_disposition(ldlm_rep, DISP_LOOKUP_EXECD);

        if (intent_disposition(ldlm_rep, DISP_LOOKUP_NEG))
                ldlm_rep->lock_policy_res2 = 0;
        if (!intent_disposition(ldlm_rep, DISP_LOOKUP_POS) ||
            ldlm_rep->lock_policy_res2) {
                RETURN(ELDLM_LOCK_ABORTED);
        }

        new_lock = ldlm_handle2lock(&lhc.mlh_lh);
        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY))
                RETURN(0);
        
        LASSERTF(new_lock != NULL, "op %d lockh "LPX64"\n",
                 opcode, lhc.mlh_lh.cookie);

        *lockp = new_lock;

        /* FIXME:This only happen when I can handle RESENT */
        if (new_lock->l_export == req->rq_export) {
                /* Already gave this to the client, which means that we
                 * reconstructed a reply. */
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) &
                        MSG_RESENT);
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /* Fixup the lock to be given to the client */
        l_lock(&new_lock->l_resource->lr_namespace->ns_lock);
        new_lock->l_readers = 0;
        new_lock->l_writers = 0;

        new_lock->l_export = class_export_get(req->rq_export);
        list_add(&new_lock->l_export_chain,
                 &new_lock->l_export->exp_ldlm_data.led_held_locks);

        new_lock->l_blocking_ast = old_lock->l_blocking_ast;
        new_lock->l_completion_ast = old_lock->l_completion_ast;

        new_lock->l_remote_handle = old_lock->l_remote_handle;

        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        LDLM_LOCK_PUT(new_lock);
        l_unlock(&new_lock->l_resource->lr_namespace->ns_lock);

        RETURN(ELDLM_LOCK_REPLACED);
}

static int mdt_intent_reint(enum mdt_it_code opcode,
                            struct mdt_thread_info *info,
                            struct ldlm_lock **lockp,
                            int flags)
{
        long opc;
        int rc;
        struct ldlm_reply *rep;

        static const struct req_format *intent_fmts[REINT_MAX] = {
                [REINT_CREATE]  = &RQF_LDLM_INTENT_CREATE,
                [REINT_OPEN]    = &RQF_LDLM_INTENT_OPEN
        };

        ENTRY;

        opc = mdt_reint_opcode(info, intent_fmts);
        if (opc < 0)
                RETURN(opc);

        if (mdt_it_flavor[opcode].it_reint != opc) {
                CERROR("Reint code %ld doesn't match intent: %d\n",
                       opc, opcode);
                RETURN(-EPROTO);
        }

        rc = req_capsule_pack(&info->mti_pill);
        if (rc)
                RETURN(rc);

        rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        if (rep == NULL)
                RETURN(-EFAULT);
        rep->lock_policy_res2 = mdt_reint_internal(info, opc);
        intent_set_disposition(rep, DISP_IT_EXECD);

        RETURN(ELDLM_LOCK_ABORTED);
}

static int mdt_intent_code(long itcode)
{
        int result;

        switch(itcode) {
        case IT_OPEN:
                result = MDT_IT_OPEN;
                break;
        case IT_OPEN|IT_CREAT:
                result = MDT_IT_OCREAT;
                break;
        case IT_CREAT:
                result = MDT_IT_CREATE;
                break;
        case IT_READDIR:
                result = MDT_IT_READDIR;
                break;
        case IT_GETATTR:
                result = MDT_IT_GETATTR;
                break;
        case IT_LOOKUP:
                result = MDT_IT_LOOKUP;
                break;
        case IT_UNLINK:
                result = MDT_IT_UNLINK;
                break;
        case IT_TRUNC:
                result = MDT_IT_TRUNC;
                break;
        case IT_GETXATTR:
                result = MDT_IT_GETXATTR;
                break;
        default:
                CERROR("Unknown intent opcode: %ld\n", itcode);
                result = -EINVAL;
                break;
        }
        return result;
}

static int mdt_intent_opc(long itopc, struct mdt_thread_info *info,
                          struct ldlm_lock **lockp, int flags)
{
        struct req_capsule   *pill;
        struct mdt_it_flavor *flv;
        int opc;
        int rc;
        ENTRY;

        opc = mdt_intent_code(itopc);
        if (opc < 0)
                RETURN(-EINVAL);

        pill = &info->mti_pill;
        flv  = &mdt_it_flavor[opc];

        if (flv->it_fmt != NULL)
                req_capsule_extend(pill, flv->it_fmt);

        rc = mdt_unpack_req_pack_rep(info, flv->it_flags);
        if (rc == 0) {
                /* execute policy */
                /*XXX LASSERT( flv->it_act) */
                if (flv->it_act) {
                        rc = flv->it_act(opc, info, lockp, flags);
                } else
                        rc = -EOPNOTSUPP;
        }
        RETURN(rc);
}

static int mdt_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
        struct mdt_thread_info *info;
        struct ptlrpc_request  *req  =  req_cookie;
        struct ldlm_intent     *it;
        struct req_capsule     *pill;
        struct ldlm_lock       *lock = *lockp;
        int rc;

        ENTRY;

        LASSERT(req != NULL);

        info = lu_context_key_get(req->rq_svc_thread->t_ctx, &mdt_thread_key);
        LASSERT(info != NULL);
        pill = &info->mti_pill;
        LASSERT(pill->rc_req == req);

        if (req->rq_reqmsg->bufcount > MDS_REQ_INTENT_IT_OFF) {
                req_capsule_extend(pill, &RQF_LDLM_INTENT);
                it = req_capsule_client_get(pill, &RMF_LDLM_INTENT);
                if (it != NULL) {
                        LDLM_DEBUG(lock, "intent policy opc: %s",
                                   ldlm_it2str(it->opc));

                        rc = mdt_intent_opc(it->opc, info, lockp, flags);
                        if (rc == 0)
                                rc = ELDLM_OK;
                } else
                        rc = -EFAULT;
        } else {
                /* No intent was provided */
                LASSERT(pill->rc_fmt == &RQF_LDLM_ENQUEUE);
                rc = req_capsule_pack(pill);
        }
        RETURN(rc);
}

/*
 * Seq wrappers
 */
static int mdt_seq_fini(const struct lu_context *ctx,
                        struct mdt_device *m)
{
        struct lu_site *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        ENTRY;

        if (ls && ls->ls_server_seq) {
                seq_server_fini(ls->ls_server_seq, ctx);
                OBD_FREE_PTR(ls->ls_server_seq);
                ls->ls_server_seq = NULL;
        }
        if (ls && ls->ls_ctlr_seq) {
                seq_server_fini(ls->ls_ctlr_seq, ctx);
                OBD_FREE_PTR(ls->ls_ctlr_seq);
                ls->ls_ctlr_seq = NULL;
        }
        RETURN(0);
}

static int mdt_seq_init(const struct lu_context *ctx,
                        const char *uuid, 
                        struct mdt_device *m)
{
        struct lu_site *ls;
        int rc;
        ENTRY;

        ls = m->mdt_md_dev.md_lu_dev.ld_site;

        /* sequence-controller node */
        if (ls->ls_node_id == 0) {
                LASSERT(ls->ls_ctlr_seq == NULL);
                OBD_ALLOC_PTR(ls->ls_ctlr_seq);

                if (ls->ls_ctlr_seq != NULL) {
                        rc = seq_server_init(ls->ls_ctlr_seq, 
                                             m->mdt_bottom, uuid,
                                             LUSTRE_SEQ_CTLR,
                                             ctx);
                        if (rc)
                                mdt_seq_fini(ctx, m);
                } else
                        rc = -ENOMEM;
        }

        LASSERT(ls->ls_server_seq == NULL);
        OBD_ALLOC_PTR(ls->ls_server_seq);

        if (ls->ls_server_seq != NULL) {
                rc = seq_server_init(ls->ls_server_seq, 
                                     m->mdt_bottom, uuid,
                                     LUSTRE_SEQ_SRV,
                                     ctx);
                if (rc)
                        mdt_seq_fini(ctx, m);
        } else
                rc = -ENOMEM;

        RETURN(rc);
}

/* XXX: this is ugly, should be something else */
static int mdt_seq_init_ctlr(const struct lu_context *ctx,
                             struct mdt_device *m,
                             struct lustre_cfg *cfg)
{
        struct lu_site *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        struct obd_device *mdc;
        struct obd_uuid uuid;
        char *uuid_str;
        int rc, index;
        ENTRY;

        index = simple_strtol(lustre_cfg_string(cfg, 2), NULL, 10);

        /* check if this is first MDC add and controller is not yet
         * initialized. */
        if (index != 0 || ls->ls_ctlr_exp)
                RETURN(0);

        uuid_str = lustre_cfg_string(cfg, 1);
        obd_str2uuid(&uuid, uuid_str);
        mdc = class_find_client_obd(&uuid, LUSTRE_MDC_NAME, NULL);
        if (!mdc) {
                CERROR("can't find controller MDC by uuid %s\n",
                       uuid_str);
                rc = -ENOENT;
        } else if (!mdc->obd_set_up) {
                CERROR("target %s not set up\n", mdc->obd_name);
                rc = -EINVAL;
        } else {
                struct lustre_handle conn = {0, };

                CDEBUG(D_CONFIG, "connect to controller %s(%s)\n",
                       mdc->obd_name, mdc->obd_uuid.uuid);

                rc = obd_connect(&conn, mdc, &mdc->obd_uuid, NULL);

                if (rc) {
                        CERROR("target %s connect error %d\n",
                               mdc->obd_name, rc);
                } else {
                        ls->ls_ctlr_exp = class_conn2export(&conn);

                        OBD_ALLOC_PTR(ls->ls_client_seq);

                        if (ls->ls_client_seq != NULL) {
                                rc = seq_client_init(ls->ls_client_seq,
                                                     mdc->obd_name,
                                                     ls->ls_ctlr_exp);
                        } else
                                rc = -ENOMEM;

                        if (rc)
                                RETURN(rc);

                        LASSERT(ls->ls_server_seq != NULL);

                        rc = seq_server_init_ctlr(ls->ls_server_seq,
                                                  ls->ls_client_seq,
                                                  ctx);
                }
        }

        RETURN(rc);
}

static void mdt_seq_fini_ctlr(struct mdt_device *m)
{
        struct lu_site *ls;

        ENTRY;

        ls = m->mdt_md_dev.md_lu_dev.ld_site;

        if (ls && ls->ls_server_seq)
                seq_server_fini_ctlr(ls->ls_server_seq);
        
        if (ls && ls->ls_client_seq) {
                seq_client_fini(ls->ls_client_seq);
                OBD_FREE_PTR(ls->ls_client_seq);
                ls->ls_client_seq = NULL;
        }
        
        if (ls && ls->ls_ctlr_exp) {
                int rc = obd_disconnect(ls->ls_ctlr_exp);
                ls->ls_ctlr_exp = NULL;
                
                if (rc) {
                        CERROR("failure to disconnect "
                               "obd: %d\n", rc);
                }
        }
        EXIT;
}

/*
 * FLD wrappers
 */
static int mdt_fld_init(const struct lu_context *ctx,
                        const char *uuid, 
                        struct mdt_device *m)
{
        struct lu_site *ls;
        int rc;
        ENTRY;

        ls = m->mdt_md_dev.md_lu_dev.ld_site;

        OBD_ALLOC_PTR(ls->ls_fld);

        if (ls->ls_fld != NULL) {
                rc = fld_server_init(ls->ls_fld, ctx,
                                     uuid, m->mdt_bottom);
                if (rc) {
                        OBD_FREE_PTR(ls->ls_fld);
                        ls->ls_fld = NULL;
                }
        } else
                rc = -ENOMEM;

        RETURN(rc);
}

static int mdt_fld_fini(const struct lu_context *ctx,
                        struct mdt_device *m)
{
        struct lu_site *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        ENTRY;

        if (ls && ls->ls_fld) {
                fld_server_fini(ls->ls_fld, ctx);
                OBD_FREE_PTR(ls->ls_fld);
                ls->ls_fld = NULL;
        }
        RETURN(0);
}

/* device init/fini methods */
static void mdt_stop_ptlrpc_service(struct mdt_device *m)
{
        if (m->mdt_service != NULL) {
                ptlrpc_unregister_service(m->mdt_service);
                m->mdt_service = NULL;
        }
}

static int mdt_start_ptlrpc_service(struct mdt_device *m)
{
        int rc;
        struct ptlrpc_service_conf conf = {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = MDS_MAXREQSIZE,
                .psc_max_reply_size   = MDS_MAXREPSIZE,
                .psc_req_portal       = MDS_REQUEST_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                /*
                 * We'd like to have a mechanism to set this on a per-device
                 * basis, but alas...
                 */
                .psc_num_threads = min(max(mdt_num_threads, MDT_MIN_THREADS),
                                       MDT_MAX_THREADS)
        };

        ENTRY;


        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mdt_ldlm_client", &m->mdt_ldlm_client);

        m->mdt_service =
                ptlrpc_init_svc_conf(&conf, mdt_handle, LUSTRE_MDT0_NAME,
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (m->mdt_service == NULL)
                RETURN(-ENOMEM);

        rc = ptlrpc_start_threads(NULL, m->mdt_service, LUSTRE_MDT0_NAME);
        if (rc)
                GOTO(err_mdt_svc, rc);

        RETURN(rc);
err_mdt_svc:
        ptlrpc_unregister_service(m->mdt_service);
        m->mdt_service = NULL;

        return (rc);
}

static void mdt_stack_fini(const struct lu_context *ctx,
                           struct mdt_device *m, struct lu_device *d)
{
        /* goes through all stack */
        while (d != NULL) {
                struct lu_device *n;
                struct obd_type *type;
                struct lu_device_type *ldt = d->ld_type;

                lu_device_put(d);

                /* each fini() returns next device in stack of layers
                 * * so we can avoid the recursion */
                n = ldt->ldt_ops->ldto_device_fini(ctx, d);
                ldt->ldt_ops->ldto_device_free(ctx, d);

                type = ldt->ldt_obd_type;
                type->typ_refcnt--;
                class_put_type(type);
                /* switch to the next device in the layer */
                d = n;
        }
        m->mdt_child = NULL;
}

static struct lu_device *mdt_layer_setup(const struct lu_context *ctx,
                                         const char *typename,
                                         struct lu_device *child,
                                         struct lustre_cfg *cfg)
{
        struct obd_type       *type;
        struct lu_device_type *ldt;
        struct lu_device      *d;
        int rc;

        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("Unknown type: '%s'\n", typename);
                GOTO(out, rc = -ENODEV);
        }

        ldt = type->typ_lu;
        if (ldt == NULL) {
                CERROR("type: '%s'\n", typename);
                GOTO(out_type, rc = -EINVAL);
        }

        ldt->ldt_obd_type = type;
        d = ldt->ldt_ops->ldto_device_alloc(ctx, ldt, cfg);
        if (IS_ERR(d)) {
                CERROR("Cannot allocate device: '%s'\n", typename);
                GOTO(out_type, rc = -ENODEV);
        }

        LASSERT(child->ld_site);
        d->ld_site = child->ld_site;

        type->typ_refcnt++;
        rc = ldt->ldt_ops->ldto_device_init(ctx, d, child);
        if (rc) {
                CERROR("can't init device '%s', rc %d\n", typename, rc);
                GOTO(out_alloc, rc);
        }
        lu_device_get(d);

        RETURN(d);
out_alloc:
        ldt->ldt_ops->ldto_device_free(ctx, d);
        type->typ_refcnt--;
out_type:
        class_put_type(type);
out:
        return ERR_PTR(rc);
}

static int mdt_stack_init(const struct lu_context *ctx,
                          struct mdt_device *m, struct lustre_cfg *cfg)
{
        struct lu_device  *d = &m->mdt_md_dev.md_lu_dev;
        struct lu_device  *tmp;
        int rc;
        ENTRY;

        /* init the stack */
        tmp = mdt_layer_setup(ctx, LUSTRE_OSD0_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                RETURN(PTR_ERR(tmp));
        }
        m->mdt_bottom = lu2dt_dev(tmp);
        d = tmp;
        tmp = mdt_layer_setup(ctx, LUSTRE_MDD0_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                GOTO(out, rc = PTR_ERR(tmp));
        }
        d = tmp;
        tmp = mdt_layer_setup(ctx, LUSTRE_CMM0_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                GOTO(out, rc = PTR_ERR(tmp));
        }
        d = tmp;
        m->mdt_child = lu2md_dev(d);

        /* process setup config */
        tmp = &m->mdt_md_dev.md_lu_dev;
        rc = tmp->ld_ops->ldo_process_config(ctx, tmp, cfg);

        GOTO(out, rc);
out:
        /* fini from last known good lu_device */
        if (rc)
                mdt_stack_fini(ctx, m, d);

        return rc;
}

static void mdt_fini(const struct lu_context *ctx, struct mdt_device *m)
{
        struct lu_device *d = &m->mdt_md_dev.md_lu_dev;
        struct lu_site   *ls = d->ld_site;

        ENTRY;

        mdt_stop_ptlrpc_service(m);

        /* finish the stack */
        mdt_stack_fini(ctx, m, md2lu_dev(m->mdt_child));

        mdt_fld_fini(ctx, m);
        mdt_seq_fini(ctx, m);
        mdt_seq_fini_ctlr(m);

        LASSERT(atomic_read(&d->ld_ref) == 0);
        md_device_fini(&m->mdt_md_dev);

        if (m->mdt_namespace != NULL) {
                ldlm_namespace_free(m->mdt_namespace, 0);
                m->mdt_namespace = NULL;
        }

        if (ls) {
                lu_site_fini(ls);
                OBD_FREE_PTR(ls);
        }

        EXIT;
}

static int mdt_init0(const struct lu_context *ctx, struct mdt_device *m,
                     struct lu_device_type *t, struct lustre_cfg *cfg)
{
        int rc;
        struct lu_site *s;
        char   ns_name[48];
        const char *dev = lustre_cfg_string(cfg, 0);
        const char *num = lustre_cfg_string(cfg, 2);
        struct obd_device *obd;
        ENTRY;

        obd = class_name2obd(dev);
        m->mdt_md_dev.md_lu_dev.ld_obd = obd;

        spin_lock_init(&m->mdt_transno_lock);
        /* FIXME: We need to load them from disk. But now fake it */
        m->mdt_last_transno = 0;
        m->mdt_last_committed = 0;
        m->mdt_max_mdsize = MAX_MD_SIZE;
        m->mdt_max_cookiesize = sizeof(struct llog_cookie);

        OBD_ALLOC_PTR(s);
        if (s == NULL)
                RETURN(-ENOMEM);

        md_device_init(&m->mdt_md_dev, t);
        m->mdt_md_dev.md_lu_dev.ld_ops = &mdt_lu_ops;

        rc = lu_site_init(s, &m->mdt_md_dev.md_lu_dev);
        if (rc) {
                CERROR("can't init lu_site, rc %d\n", rc);
                GOTO(err_free_site, rc);
        }

        /* init the stack */
        rc = mdt_stack_init(ctx, m, cfg);
        if (rc) {
                CERROR("can't init device stack, rc %d\n", rc);
                GOTO(err_fini_site, rc);
        }

        /* set server index */
        LASSERT(num);
        s->ls_node_id = simple_strtol(num, NULL, 10);

        rc = mdt_fld_init(ctx, obd->obd_name, m);
        if (rc)
                GOTO(err_fini_stack, rc);

        rc = mdt_seq_init(ctx, obd->obd_name, m);
        if (rc)
                GOTO(err_fini_fld, rc);

        snprintf(ns_name, sizeof ns_name, LUSTRE_MDT0_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);
        if (m->mdt_namespace == NULL)
                GOTO(err_fini_seq, rc = -ENOMEM);

        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);

        rc = mdt_start_ptlrpc_service(m);
        if (rc)
                GOTO(err_free_ns, rc);

        RETURN(0);

err_free_ns:
        ldlm_namespace_free(m->mdt_namespace, 0);
        m->mdt_namespace = NULL;
err_fini_seq:
        mdt_seq_fini(ctx, m);
err_fini_fld:
        mdt_fld_fini(ctx, m);
err_fini_stack:
        mdt_stack_fini(ctx, m, md2lu_dev(m->mdt_child));
err_fini_site:
        lu_site_fini(s);
err_free_site:
        OBD_FREE_PTR(s);
        return (rc);
}

/* used by MGS to process specific configurations */
static int mdt_process_config(const struct lu_context *ctx,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct lu_device *next = md2lu_dev(mdt_dev(d)->mdt_child);
        int err;
        ENTRY;

        switch (cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                /* add mdc hook to get first MDT uuid and connect it to
                 * ls->controller to use for seq manager. */
                err = mdt_seq_init_ctlr(ctx, mdt_dev(d), cfg);
                if (err) {
                        CERROR("can't initialize controller export, "
                               "rc %d\n", err);
                }
                /* all MDT specific commands should be here */
        default:
                /* others are passed further */
                err = next->ld_ops->ldo_process_config(ctx, next, cfg);
        }
        RETURN(err);
}

static struct lu_object *mdt_object_alloc(const struct lu_context *ctxt,
                                          const struct lu_object_header *hdr,
                                          struct lu_device *d)
{
        struct mdt_object *mo;

        ENTRY;

        OBD_ALLOC_PTR(mo);
        if (mo != NULL) {
                struct lu_object *o;
                struct lu_object_header *h;

                o = &mo->mot_obj.mo_lu;
                h = &mo->mot_header;
                lu_object_header_init(h);
                lu_object_init(o, h, d);
                lu_object_add_top(h, o);
                o->lo_ops = &mdt_obj_ops;
                RETURN(o);
        } else
                RETURN(NULL);
}

static int mdt_object_init(const struct lu_context *ctxt, struct lu_object *o)
{
        struct mdt_device *d = mdt_dev(o->lo_dev);
        struct lu_device  *under;
        struct lu_object  *below;

        under = &d->mdt_child->md_lu_dev;
        below = under->ld_ops->ldo_object_alloc(ctxt, o->lo_header, under);
        if (below != NULL) {
                lu_object_add(o, below);
                return 0;
        } else
                return -ENOMEM;
}

static void mdt_object_free(const struct lu_context *ctxt, struct lu_object *o)
{
        struct mdt_object *mo = mdt_obj(o);
        struct lu_object_header *h;
        ENTRY;

        h = o->lo_header;
        lu_object_fini(o);
        lu_object_header_fini(h);
        OBD_FREE_PTR(mo);
        EXIT;
}

static int mdt_object_exists(const struct lu_context *ctx,
                             const struct lu_object *o)
{
        return lu_object_exists(ctx, lu_object_next(o));
}

static int mdt_object_print(const struct lu_context *ctxt,
                            struct seq_file *f, const struct lu_object *o)
{
        return seq_printf(f, LUSTRE_MDT0_NAME"-object@%p", o);
}

static struct lu_device_operations mdt_lu_ops = {
        .ldo_object_alloc   = mdt_object_alloc,
        .ldo_process_config = mdt_process_config
};

static struct lu_object_operations mdt_obj_ops = {
        .loo_object_init    = mdt_object_init,
        .loo_object_free    = mdt_object_free,
        .loo_object_print   = mdt_object_print,
        .loo_object_exists  = mdt_object_exists
};

/* mds_connect_internal */
static int mdt_connect0(struct mdt_device *mdt,
                        struct obd_export *exp, struct obd_connect_data *data)
{
        if (data != NULL) {
                data->ocd_connect_flags &= MDT_CONNECT_SUPPORTED;
                data->ocd_ibits_known &= MDS_INODELOCK_FULL;

                /* If no known bits (which should not happen, probably,
                   as everybody should support LOOKUP and UPDATE bits at least)
                   revert to compat mode with plain locks. */
                if (!data->ocd_ibits_known &&
                    data->ocd_connect_flags & OBD_CONNECT_IBITS)
                        data->ocd_connect_flags &= ~OBD_CONNECT_IBITS;

                if (!mdt->mdt_opts.mo_acl)
                        data->ocd_connect_flags &= ~OBD_CONNECT_ACL;

                if (!mdt->mdt_opts.mo_user_xattr)
                        data->ocd_connect_flags &= ~OBD_CONNECT_XATTR;

                exp->exp_connect_flags = data->ocd_connect_flags;
                data->ocd_version = LUSTRE_VERSION_CODE;
                exp->exp_mdt_data.med_ibits_known = data->ocd_ibits_known;
        }

        if (mdt->mdt_opts.mo_acl &&
            ((exp->exp_connect_flags & OBD_CONNECT_ACL) == 0)) {
                CWARN("%s: MDS requires ACL support but client does not\n",
                      mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }
        return 0;
}

/* mds_connect copy */
static int mdt_obd_connect(struct lustre_handle *conn, struct obd_device *obd,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *data)
{
        struct obd_export *exp;
        int rc;
        struct mdt_device *mdt;
        struct mdt_export_data *med;
        struct mdt_client_data *mcd;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        mdt = mdt_dev(obd->obd_lu_dev);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        exp = class_conn2export(conn);
        LASSERT(exp != NULL);
        med = &exp->exp_mdt_data;

        rc = mdt_connect0(mdt, exp, data);
        if (rc == 0) {
                OBD_ALLOC_PTR(mcd);
                if (mcd != NULL) {
                        memcpy(mcd->mcd_uuid, cluuid, sizeof mcd->mcd_uuid);
                        med->med_mcd = mcd;
                } else
                        rc = -ENOMEM;
        }
        if (rc)
                class_disconnect(exp);
        else
                class_export_put(exp);

        RETURN(rc);
}

static int mdt_obd_disconnect(struct obd_export *exp)
{
        struct mdt_export_data *med = &exp->exp_mdt_data;
        unsigned long irqflags;
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        //ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock_irqsave(&exp->exp_lock, irqflags);
        while (!list_empty(&exp->exp_outstanding_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(exp->exp_outstanding_replies.next,
                                   struct ptlrpc_reply_state, rs_exp_list);
                struct ptlrpc_service *svc = rs->rs_service;

                spin_lock(&svc->srv_lock);
                list_del_init(&rs->rs_exp_list);
                ptlrpc_schedule_difficult_reply(rs);
                spin_unlock(&svc->srv_lock);
        }
        spin_unlock_irqrestore(&exp->exp_lock, irqflags);

        OBD_FREE_PTR(med->med_mcd);

        class_export_put(exp);
        RETURN(rc);
}

static int mdt_notify(struct obd_device *obd, struct obd_device *watched,
                      enum obd_notify_event ev, void *data)
{
        struct mdt_device *mdt;
        struct lu_device *next;
        struct lu_context ctxt;
        int rc;
        ENTRY;

        /*FIXME: allocation here may have some problems :( */
        rc = lu_context_init(&ctxt);
        if (rc)
                GOTO(out, rc);

        mdt = mdt_dev(obd->obd_lu_dev);
        next = md2lu_dev(mdt->mdt_child);

        lu_context_enter(&ctxt);
        rc = next->ld_ops->ldo_notify(&ctxt, next, watched, ev, data);
        lu_context_exit(&ctxt);
out:
        lu_context_fini(&ctxt); 
        RETURN(rc); 
}

static struct obd_ops mdt_obd_device_ops = {
        .o_owner = THIS_MODULE,
        .o_connect = mdt_obd_connect,
        .o_disconnect = mdt_obd_disconnect,
        .o_notify = mdt_notify,
};

static void mdt_device_free(const struct lu_context *ctx, struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);

        mdt_fini(ctx, m);
        OBD_FREE_PTR(m);
}

static struct lu_device *mdt_device_alloc(const struct lu_context *ctx,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct mdt_device *m;

        OBD_ALLOC_PTR(m);
        if (m != NULL) {
                int result;

                l = &m->mdt_md_dev.md_lu_dev;
                result = mdt_init0(ctx, m, t, cfg);
                if (result != 0) {
                        OBD_FREE_PTR(m);
                        l = ERR_PTR(result);
                }

        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

/*
 * context key constructor/destructor
 */

static void *mdt_thread_init(const struct lu_context *ctx,
                             struct lu_context_key *key)
{
        struct mdt_thread_info *info;

        /*
         * check that no high order allocations are incurred.
         */
        CLASSERT(CFS_PAGE_SIZE >= sizeof *info);
        OBD_ALLOC_PTR(info);
        if (info != NULL)
                info->mti_ctxt = ctx;
        else
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void mdt_thread_fini(const struct lu_context *ctx,
                            struct lu_context_key *key, void *data)
{
        struct mdt_thread_info *info = data;
        OBD_FREE_PTR(info);
}

static struct lu_context_key mdt_thread_key = {
        .lct_init = mdt_thread_init,
        .lct_fini = mdt_thread_fini
};

static int mdt_type_init(struct lu_device_type *t)
{
        return lu_context_key_register(&mdt_thread_key);
}

static void mdt_type_fini(struct lu_device_type *t)
{
        lu_context_key_degister(&mdt_thread_key);
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
        return class_register_type(&mdt_obd_device_ops, NULL,
                                   lvars.module_vars, LUSTRE_MDT0_NAME,
                                   &mdt_device_type);
}

static void __exit mdt_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDT0_NAME);
}


#define DEF_HNDL(prefix, base, suffix, flags, opc, fn, fmt)             \
[prefix ## _ ## opc - prefix ## _ ## base] = {                          \
        .mh_name    = #opc,                                             \
        .mh_fail_id = OBD_FAIL_ ## prefix ## _  ## opc ## suffix,       \
        .mh_opc     = prefix ## _  ## opc,                              \
        .mh_flags   = flags,                                            \
        .mh_act     = fn,                                               \
        .mh_fmt     = fmt                                               \
}

#define DEF_MDT_HNDL(flags, name, fn, fmt)                                  \
        DEF_HNDL(MDS, GETATTR, _NET, flags, name, fn, fmt)
/*
 * Request with a format known in advance
 */
#define DEF_MDT_HNDL_F(flags, name, fn)                                 \
        DEF_HNDL(MDS, GETATTR, _NET, flags, name, fn, &RQF_MDS_ ## name)
/*
 * Request with a format we do not yet know
 */
#define DEF_MDT_HNDL_0(flags, name, fn)                                 \
        DEF_HNDL(MDS, GETATTR, _NET, flags, name, fn, NULL)

static struct mdt_handler mdt_mds_ops[] = {
DEF_MDT_HNDL_F(0,                         CONNECT,      mdt_connect),
DEF_MDT_HNDL_F(0,                         DISCONNECT,   mdt_disconnect),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, GETSTATUS,    mdt_getstatus),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETATTR,      mdt_getattr),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETATTR_NAME, mdt_getattr_name),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, SETXATTR,     mdt_setxattr),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETXATTR,     mdt_getxattr),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, STATFS,       mdt_statfs),
DEF_MDT_HNDL_0(HABEO_CORPUS,              READPAGE,     mdt_readpage),
DEF_MDT_HNDL_F(0,                         REINT,        mdt_reint),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, CLOSE,        mdt_close),
DEF_MDT_HNDL_0(0,                         DONE_WRITING, mdt_done_writing),
DEF_MDT_HNDL_0(0,                         PIN,          mdt_pin),
DEF_MDT_HNDL_0(0,                         SYNC,         mdt_sync),
DEF_MDT_HNDL_0(0,                         QUOTACHECK,   mdt_handle_quotacheck),
DEF_MDT_HNDL_0(0,                         QUOTACTL,     mdt_handle_quotactl)
};

#define DEF_OBD_HNDL(flags, name, fn)                   \
        DEF_HNDL(OBD, PING, _NET, flags, name, fn, NULL)


static struct mdt_handler mdt_obd_ops[] = {
        DEF_OBD_HNDL(0, PING,           mdt_obd_ping),
        DEF_OBD_HNDL(0, LOG_CANCEL,     mdt_obd_log_cancel),
        DEF_OBD_HNDL(0, QC_CALLBACK,    mdt_obd_qc_callback)
};

#define DEF_DLM_HNDL_0(flags, name, fn)                   \
        DEF_HNDL(LDLM, ENQUEUE, , flags, name, fn, NULL)
#define DEF_DLM_HNDL_F(flags, name, fn)                   \
        DEF_HNDL(LDLM, ENQUEUE, , flags, name, fn, &RQF_LDLM_ ## name)

static struct mdt_handler mdt_dlm_ops[] = {
        DEF_DLM_HNDL_F(HABEO_CLAVIS, ENQUEUE,        mdt_enqueue),
        DEF_DLM_HNDL_0(HABEO_CLAVIS, CONVERT,        mdt_convert),
        DEF_DLM_HNDL_0(0,            BL_CALLBACK,    mdt_bl_callback),
        DEF_DLM_HNDL_0(0,            CP_CALLBACK,    mdt_cp_callback)
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
