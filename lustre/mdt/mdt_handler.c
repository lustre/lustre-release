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
 *   Author: Huang Hua <huanghua@clusterfs.com>
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
 * MDT_FAIL_CHECK
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
#include <lustre_mds.h>
#include <lustre_mdt.h>
#include "mdt_internal.h"
#include <linux/lustre_acl.h>
#include <lustre_param.h>
/*
 * Initialized in mdt_mod_init().
 */
unsigned long mdt_num_threads;

/* ptlrpc request handler for MDT. All handlers are
 * grouped into several slices - struct mdt_opc_slice,
 * and stored in an array - mdt_handlers[].
 */
struct mdt_handler {
        /* The name of this handler. */
        const char *mh_name;
        /* Fail id for this handler, checked at the beginning of this handler*/
        int         mh_fail_id;
        /* Operation code for this handler */
        __u32       mh_opc;
        /* flags are listed in enum mdt_handler_flags below. */
        __u32       mh_flags;
        /* The actual handler function to execute. */
        int (*mh_act)(struct mdt_thread_info *info);
        /* Request format for this request. */
        const struct req_format *mh_fmt;
};

enum mdt_handler_flags {
        /*
         * struct mdt_body is passed in the incoming message, and object
         * identified by this fid exists on disk.
         *
         * "habeo corpus" == "I have a body"
         */
        HABEO_CORPUS = (1 << 0),
        /*
         * struct ldlm_request is passed in the incoming message.
         *
         * "habeo clavis" == "I have a key"
         */
        HABEO_CLAVIS = (1 << 1),
        /*
         * this request has fixed reply format, so that reply message can be
         * packed by generic code.
         *
         * "habeo refero" == "I have a reply"
         */
        HABEO_REFERO = (1 << 2),
        /*
         * this request will modify something, so check whether the filesystem
         * is readonly or not, then return -EROFS to client asap if necessary.
         *
         * "mutabor" == "I shall modify"
         */
        MUTABOR      = (1 << 3)
};

struct mdt_opc_slice {
        __u32               mos_opc_start;
        int                 mos_opc_end;
        struct mdt_handler *mos_hs;
};

static struct mdt_opc_slice mdt_regular_handlers[];
static struct mdt_opc_slice mdt_readpage_handlers[];
static struct mdt_opc_slice mdt_seq_handlers[];
static struct mdt_opc_slice mdt_fld_handlers[];

static struct mdt_device *mdt_dev(struct lu_device *d);
static int mdt_regular_handle(struct ptlrpc_request *req);
static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags);

static struct lu_object_operations mdt_obj_ops;

int mdt_get_disposition(struct ldlm_reply *rep, int flag)
{
        if (!rep)
                return 0;
        return (rep->lock_policy_res1 & flag);
}

void mdt_clear_disposition(struct mdt_thread_info *info,
                           struct ldlm_reply *rep, int flag)
{
        if (info)
                info->mti_opdata &= ~flag;
        if (rep)
                rep->lock_policy_res1 &= ~flag;
}

void mdt_set_disposition(struct mdt_thread_info *info,
                         struct ldlm_reply *rep, int flag)
{
        if (info)
                info->mti_opdata |= flag;
        if (rep)
                rep->lock_policy_res1 |= flag;
}

static int mdt_getstatus(struct mdt_thread_info *info)
{
        struct mdt_device *mdt  = info->mti_mdt;
        struct md_device  *next = mdt->mdt_child;
        struct mdt_body   *body;
        int                rc;

        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                RETURN(err_serious(-ENOMEM));

        body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        rc = next->md_ops->mdo_root_get(info->mti_env, next, &body->fid1);
        if (rc != 0)
                RETURN(rc);

        body->valid |= OBD_MD_FLID;

        if (mdt->mdt_opts.mo_mds_capa) {
                struct mdt_object  *root;
                struct lustre_capa *capa;

                root = mdt_object_find(info->mti_env, mdt, &body->fid1);
                if (IS_ERR(root))
                        RETURN(PTR_ERR(root));

                capa = req_capsule_server_get(&info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;

                rc = mo_capa_get(info->mti_env, mdt_object_child(root), capa,
                                 0);
                mdt_object_put(info->mti_env, root);
                if (rc == 0)
                        body->valid |= OBD_MD_FLMDSCAPA;
        }

        RETURN(rc);
}

static int mdt_statfs(struct mdt_thread_info *info)
{
        struct md_device  *next  = info->mti_mdt->mdt_child;
        struct obd_statfs *osfs;
        int                rc;

        ENTRY;

        /* This will trigger a watchdog timeout */
        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
                         (MDT_SERVICE_WATCHDOG_TIMEOUT / 1000) + 1);


        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                rc = err_serious(-ENOMEM);
        } else {
                osfs = req_capsule_server_get(&info->mti_pill,&RMF_OBD_STATFS);
                /* XXX max_age optimisation is needed here. See mds_statfs */
                rc = next->md_ops->mdo_statfs(info->mti_env, next,
                                              &info->mti_u.ksfs);
                statfs_pack(osfs, &info->mti_u.ksfs);
        }
        RETURN(rc);
}

void mdt_pack_size2body(struct mdt_body *b, const struct lu_attr *attr,
                        struct mdt_object *o)
{
        /* Check if Size-on-MDS is enabled. */
        if (S_ISREG(attr->la_mode) && mdt_sizeonmds_enabled(o)) {
                b->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS);
                b->size = attr->la_size;
                b->blocks = attr->la_blocks;
        }
}

void mdt_pack_attr2body(struct mdt_thread_info *info, struct mdt_body *b,
                        const struct lu_attr *attr, const struct lu_fid *fid)
{
        /*XXX should pack the reply body according to lu_valid*/
        b->valid |= OBD_MD_FLCTIME | OBD_MD_FLUID   |
                    OBD_MD_FLGID   | OBD_MD_FLTYPE  |
                    OBD_MD_FLMODE  | OBD_MD_FLNLINK | OBD_MD_FLFLAGS |
                    OBD_MD_FLATIME | OBD_MD_FLMTIME ;

        if (!S_ISREG(attr->la_mode))
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLRDEV;

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
        b->rdev       = attr->la_rdev;

        if (fid) {
                b->fid1 = *fid;
                b->valid |= OBD_MD_FLID;
                CDEBUG(D_INODE, ""DFID": nlink=%d, mode=%o, size="LPU64"\n",
                                PFID(fid), b->nlink, b->mode, b->size);
        }

        if (info)
                mdt_body_reverse_idmap(info, b);
}

static inline int mdt_body_has_lov(const struct lu_attr *la,
                                   const struct mdt_body *body)
{
        return ((S_ISREG(la->la_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
                (S_ISDIR(la->la_mode) && (body->valid & OBD_MD_FLDIREA )) );
}

static int mdt_getattr_internal(struct mdt_thread_info *info,
                                struct mdt_object *o)
{
        struct md_object        *next = mdt_object_child(o);
        struct mdt_device       *mdt = info->mti_mdt;
        const struct mdt_body   *reqbody = info->mti_body;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_export_data  *med = &req->rq_export->exp_mdt_data;
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *la = &ma->ma_attr;
        struct req_capsule      *pill = &info->mti_pill;
        const struct lu_env     *env = info->mti_env;
        struct mdt_body         *repbody;
        struct lu_buf           *buffer = &info->mti_buf;
        int                     rc;
        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK))
                RETURN(err_serious(-ENOMEM));

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        if (reqbody->valid & OBD_MD_MEA) {
                /* Assumption: MDT_MD size is enough for lmv size FIXME */
                ma->ma_lmv = req_capsule_server_get(pill, &RMF_MDT_MD);
                ma->ma_lmv_size = req_capsule_get_size(pill, &RMF_MDT_MD,
                                                             RCL_SERVER);
                ma->ma_need = MA_INODE | MA_LMV;
        } else {
                ma->ma_need = MA_INODE | MA_LOV ;
                ma->ma_lmm = req_capsule_server_get(pill, &RMF_MDT_MD);
                ma->ma_lmm_size = req_capsule_get_size(pill, &RMF_MDT_MD,
                                                             RCL_SERVER);
        }
        rc = mo_attr_get(env, next, ma);
        if (rc == -EREMOTE) {
                /* This object is located on remote node.*/
                repbody->fid1 = *mdt_object_fid(o);
                repbody->valid = OBD_MD_FLID | OBD_MD_MDS;
                RETURN(0);
        } else if (rc) {
                CERROR("getattr error for "DFID": %d\n",
                        PFID(mdt_object_fid(o)), rc);
                RETURN(rc);
        }

        if (ma->ma_valid & MA_INODE)
                mdt_pack_attr2body(info, repbody, la, mdt_object_fid(o));
        else
                RETURN(-EFAULT);

        if (mdt_body_has_lov(la, reqbody)) {
                if (ma->ma_valid & MA_LOV) {
                        LASSERT(ma->ma_lmm_size);
                        mdt_dump_lmm(D_INFO, ma->ma_lmm);
                        repbody->eadatasize = ma->ma_lmm_size;
                        if (S_ISDIR(la->la_mode))
                                repbody->valid |= OBD_MD_FLDIREA;
                        else
                                repbody->valid |= OBD_MD_FLEASIZE;
                }
                if (ma->ma_valid & MA_LMV) {
                        LASSERT(S_ISDIR(la->la_mode));
                        repbody->eadatasize = ma->ma_lmv_size;
                        repbody->valid |= OBD_MD_FLDIREA;
                        repbody->valid |= OBD_MD_MEA;
                }
        } else if (S_ISLNK(la->la_mode) &&
                          reqbody->valid & OBD_MD_LINKNAME) {
                /* FIXME: Is this buffer long enough? */
                buffer->lb_buf = ma->ma_lmm;
                buffer->lb_len = ma->ma_lmm_size;
                rc = mo_readlink(env, next, buffer);
                if (rc <= 0) {
                        CERROR("readlink failed: %d\n", rc);
                        rc = -EFAULT;
                } else {
                        repbody->valid |= OBD_MD_LINKNAME;
                        repbody->eadatasize = rc + 1;
                        ((char*)ma->ma_lmm)[rc] = 0; /* NULL terminate */
                        CDEBUG(D_INODE, "symlink dest %s, len = %d\n",
                                        (char*)ma->ma_lmm, rc);
                        rc = 0;
                }
        }

        if (reqbody->valid & OBD_MD_FLMODEASIZE) {
                repbody->max_cookiesize = info->mti_mdt->mdt_max_cookiesize;
                repbody->max_mdsize = info->mti_mdt->mdt_max_mdsize;
                repbody->valid |= OBD_MD_FLMODEASIZE;
                CDEBUG(D_INODE, "I am going to change the MAX_MD_SIZE & "
                                "MAX_COOKIE to : %d:%d\n",
                                repbody->max_mdsize,
                                repbody->max_cookiesize);
        }

        if (med->med_rmtclient && (reqbody->valid & OBD_MD_FLRMTPERM)) {
                void *buf = req_capsule_server_get(pill, &RMF_ACL);

                /* mdt_getattr_lock only */
                rc = mdt_pack_remote_perm(info, o, buf);
                if (rc) {
                        repbody->valid &= ~OBD_MD_FLRMTPERM;
                        repbody->aclsize = 0;
                        RETURN(rc);
                } else {
                        repbody->valid |= OBD_MD_FLRMTPERM;
                        repbody->aclsize = sizeof(struct mdt_remote_perm);
                }
        }
#ifdef CONFIG_FS_POSIX_ACL
        else if ((req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
                 (reqbody->valid & OBD_MD_FLACL)) {
                buffer->lb_buf = req_capsule_server_get(pill, &RMF_ACL);
                buffer->lb_len = req_capsule_get_size(pill,
                                                      &RMF_ACL, RCL_SERVER);
                if (buffer->lb_len > 0) {
                        rc = mo_xattr_get(env, next, buffer,
                                          XATTR_NAME_ACL_ACCESS);
                        if (rc < 0) {
                                if (rc == -ENODATA || rc == -EOPNOTSUPP)
                                        rc = 0;
                                else
                                        CERROR("got acl size: %d\n", rc);
                        } else {
                                repbody->aclsize = rc;
                                repbody->valid |= OBD_MD_FLACL;
                                rc = 0;
                        }
                }
        }
#endif

        if ((reqbody->valid & OBD_MD_FLMDSCAPA) && mdt->mdt_opts.mo_mds_capa) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(&info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(env, next, capa, 0);
                if (rc)
                        RETURN(rc);
                repbody->valid |= OBD_MD_FLMDSCAPA;
        }

        RETURN(rc);
}

static int mdt_renew_capa(struct mdt_thread_info *info)
{
        struct mdt_device  *mdt = info->mti_mdt;
        struct mdt_object  *obj = info->mti_object;
        struct mdt_body    *body;
        struct lustre_capa *capa, *c;
        int rc;
        ENTRY;

        /* if object doesn't exist, or server has disabled capability,
         * return directly, client will find body->valid OBD_MD_FLOSSCAPA
         * flag not set.
         */
        if (!obj || !mdt->mdt_opts.mo_mds_capa)
                RETURN(0);

        body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        c = req_capsule_client_get(&info->mti_pill, &RMF_CAPA1);
        LASSERT(c);

        capa = req_capsule_server_get(&info->mti_pill, &RMF_CAPA1);
        LASSERT(capa);

        *capa = *c;
        rc = mo_capa_get(info->mti_env, mdt_object_child(obj), capa, 1);
        if (rc == 0)
                body->valid |= OBD_MD_FLOSSCAPA;

        RETURN(rc);
}

static int mdt_getattr(struct mdt_thread_info *info)
{
        struct mdt_object *obj = info->mti_object;
        struct mdt_body   *reqbody;
        int rc;
        ENTRY;

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                GOTO(out, rc = -EFAULT);

        if (reqbody->valid & OBD_MD_FLOSSCAPA) {
                rc = mdt_renew_capa(info);
                mdt_shrink_reply(info, REPLY_REC_OFF + 1, 0, 0);
                RETURN(rc);
        }

        LASSERT(obj != NULL);
        LASSERT(lu_object_assert_exists(&obj->mot_obj.mo_lu));

        if (reqbody->valid & OBD_MD_FLRMTPERM) {
                rc = mdt_init_ucred(info, reqbody);
                if (rc)
                        GOTO(out, rc);
        }

        rc = mdt_getattr_internal(info, obj);
        if (reqbody->valid & OBD_MD_FLRMTPERM)
                mdt_exit_ucred(info);
        EXIT;
out:
        mdt_shrink_reply(info, REPLY_REC_OFF + 1, 1, 0);
        return rc;
}

static int mdt_is_subdir(struct mdt_thread_info *info)
{
        struct mdt_object   *obj = info->mti_object;
        struct req_capsule  *pill = &info->mti_pill;
        struct mdt_body     *repbody;
        int                  rc;

        obj = info->mti_object;
        LASSERT(obj != NULL);
        LASSERT(lu_object_assert_exists(&obj->mot_obj.mo_lu));
        ENTRY;

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

        /*
         * We save last checked parent fid to @repbody->fid1 for remote
         * directory case.
         */
        LASSERT(fid_is_sane(&info->mti_body->fid2));
        rc = mdo_is_subdir(info->mti_env, mdt_object_child(obj),
                           &info->mti_body->fid2, &repbody->fid1);
        if (rc < 0)
                RETURN(rc);

        /*
         * Save error code to ->mode. Later it it is used for detecting the case
         * of remote subdir.
         */
        repbody->mode = rc;
        repbody->valid = OBD_MD_FLMODE;

        if (rc == -EREMOTE)
                repbody->valid |= OBD_MD_FLID;

        RETURN(0);
}

/*
 * UPDATE lock should be taken against parent, and be release before exit;
 * child_bits lock should be taken against child, and be returned back:
 *            (1)normal request should release the child lock;
 *            (2)intent request will grant the lock to client.
 */
static int mdt_getattr_name_lock(struct mdt_thread_info *info,
                                 struct mdt_lock_handle *lhc,
                                 __u64 child_bits,
                                 struct ldlm_reply *ldlm_rep)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct mdt_object     *parent = info->mti_object;
        struct mdt_object     *child;
        struct md_object      *next = mdt_object_child(info->mti_object);
        struct lu_fid         *child_fid = &info->mti_tmp_fid1;
        int                    is_resent, rc;
        const char            *name;
        struct mdt_lock_handle *lhp;
        struct ldlm_lock      *lock;
        ENTRY;

        is_resent = lustre_handle_is_used(&lhc->mlh_lh);
        if (is_resent)
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);

        LASSERT(info->mti_object != NULL);
        name = req_capsule_client_get(&info->mti_pill, &RMF_NAME);
        if (name == NULL)
                RETURN(err_serious(-EFAULT));

        CDEBUG(D_INODE, "getattr with lock for "DFID"/%s, ldlm_rep = %p\n",
               PFID(mdt_object_fid(parent)), name, ldlm_rep);

        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_EXECD);

        rc = mdt_object_exists(parent);
        if (rc == 0)
                RETURN(-ESTALE);
        else if (rc < 0) {
                CERROR("Object "DFID" locates on remote server\n",
                        PFID(mdt_object_fid(parent)));
                LBUG();
        }

        if (strlen(name) == 0) {
                /* Only getattr on the child. Parent is on another node. */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
                child = parent;
                CDEBUG(D_INODE, "partial getattr_name child_fid = "DFID
                       ", ldlm_rep=%p\n", PFID(mdt_object_fid(child)), ldlm_rep);

                if (is_resent) {
                        /* Do not take lock for resent case. */
                        lock = ldlm_handle2lock(&lhc->mlh_lh);
                        if (!lock) {
                                CERROR("Invalid lock handle "LPX64"\n",
                                       lhc->mlh_lh.cookie);
                                LBUG();
                        }
                        LASSERT(fid_res_name_eq(mdt_object_fid(child),
                                                &lock->l_resource->lr_name));
                        LDLM_LOCK_PUT(lock);
                        rc = 0;
                } else {
                        mdt_lock_handle_init(lhc);
                        lhc->mlh_mode = LCK_CR;

                        /*
                         * Object's name is on another MDS, no lookup lock is
                         * needed here but update is.
                         */
                        child_bits &= ~MDS_INODELOCK_LOOKUP;
                        child_bits |= MDS_INODELOCK_UPDATE;
                        rc = mdt_object_lock(info, child, lhc, child_bits);
                }
                if (rc == 0) {
                        /* Finally, we can get attr for child. */
                        mdt_set_capainfo(info, 0, mdt_object_fid(child),
                                         BYPASS_CAPA);
                        rc = mdt_getattr_internal(info, child);
                        if (rc != 0)
                                mdt_object_unlock(info, child, lhc, 1);
                }
                GOTO(out, rc);
        }

        /*step 1: lock parent */
        lhp = &info->mti_lh[MDT_LH_PARENT];
        lhp->mlh_mode = LCK_CR;
        rc = mdt_object_lock(info, parent, lhp, MDS_INODELOCK_UPDATE);
        if (rc != 0)
                RETURN(rc);

        /*step 2: lookup child's fid by name */
        rc = mdo_lookup(info->mti_env, next, name, child_fid);
        if (rc != 0) {
                if (rc == -ENOENT)
                        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
                GOTO(out_parent, rc);
        } else
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        /*
         *step 3: find the child object by fid & lock it.
         *        regardless if it is local or remote.
         */
        child = mdt_object_find(info->mti_env, info->mti_mdt, child_fid);
        if (IS_ERR(child))
                GOTO(out_parent, rc = PTR_ERR(child));
        if (is_resent) {
                /* Do not take lock for resent case. */
                lock = ldlm_handle2lock(&lhc->mlh_lh);
                if (!lock) {
                        CERROR("Invalid lock handle "LPX64"\n",
                               lhc->mlh_lh.cookie);
                        LBUG();
                }
                LASSERT(fid_res_name_eq(child_fid,
                                        &lock->l_resource->lr_name));
                LDLM_LOCK_PUT(lock);
        } else {
                mdt_lock_handle_init(lhc);
                lhc->mlh_mode = LCK_CR;
                rc = mdt_object_cr_lock(info, child, lhc, child_bits);
                if (rc != 0)
                        GOTO(out_child, rc);
        }

        /* finally, we can get attr for child. */
        mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);
        rc = mdt_getattr_internal(info, child);
        if (rc != 0) {
                mdt_object_unlock(info, child, lhc, 1);
        } else {
                struct ldlm_lock *lock = ldlm_handle2lock(&lhc->mlh_lh);
                if (lock) {
                        struct ldlm_res_id *res_id;
                        struct mdt_body *repbody;
                        struct lu_attr *ma;

                        /* Debugging code. */
                        res_id = &lock->l_resource->lr_name;
                        LDLM_DEBUG(lock, "we will return this lock client\n");
                        LASSERTF(fid_res_name_eq(mdt_object_fid(child),
                                                 &lock->l_resource->lr_name),
                                "Lock res_id: %lu/%lu/%lu, Fid: "DFID".\n",
                                (unsigned long)res_id->name[0],
                                (unsigned long)res_id->name[1],
                                (unsigned long)res_id->name[2],
                                PFID(mdt_object_fid(child)));

                        /* Pack Size-on-MDS inode attributes to the body if
                         * update lock is given. */
                        repbody = req_capsule_server_get(&info->mti_pill,
                                                         &RMF_MDT_BODY);
                        ma = &info->mti_attr.ma_attr;
                        if (lock->l_policy_data.l_inodebits.bits &
                            MDS_INODELOCK_UPDATE)
                                mdt_pack_size2body(repbody, ma, child);
                        LDLM_LOCK_PUT(lock);
                }
        }
        EXIT;
out_child:
        mdt_object_put(info->mti_env, child);
out_parent:
        mdt_object_unlock(info, parent, lhp, 1);
out:
        return rc;
}

/* normal handler: should release the child lock */
static int mdt_getattr_name(struct mdt_thread_info *info)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_CHILD];
        struct mdt_body        *reqbody;
        int rc;
        ENTRY;

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                GOTO(out, rc = err_serious(-EFAULT));

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                GOTO(out, rc);

        rc = mdt_getattr_name_lock(info, lhc, MDS_INODELOCK_UPDATE, NULL);
        if (lustre_handle_is_used(&lhc->mlh_lh)) {
                ldlm_lock_decref(&lhc->mlh_lh, lhc->mlh_mode);
                lhc->mlh_lh.cookie = 0;
        }
        mdt_exit_ucred(info);
        EXIT;
out:
        mdt_shrink_reply(info, REPLY_REC_OFF + 1, 1, 0);
        return rc;
}

static struct lu_device_operations mdt_lu_ops;

static int lu_device_is_mdt(struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static int mdt_connect(struct mdt_thread_info *info)
{
        int rc;
        struct ptlrpc_request *req;

        req = mdt_info_req(info);
        rc = target_handle_connect(req);
        if (rc == 0) {
                LASSERT(req->rq_export != NULL);
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
                rc = mdt_init_idmap(info);
        } else
                rc = err_serious(rc);
        return rc;
}

static int mdt_disconnect(struct mdt_thread_info *info)
{
        int rc;

        rc = target_handle_disconnect(mdt_info_req(info));
        if (rc)
                rc = err_serious(rc);
        return rc;
}

static int mdt_sendpage(struct mdt_thread_info *info,
                        struct lu_rdpg *rdpg)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct ptlrpc_bulk_desc *desc;
        struct l_wait_info      *lwi = &info->mti_u.rdpg.mti_wait_info;
        int                      tmpcount;
        int                      tmpsize;
        int                      i;
        int                      rc;
        ENTRY;

        desc = ptlrpc_prep_bulk_exp(req, rdpg->rp_npages, BULK_PUT_SOURCE,
                                    MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out, rc = -ENOMEM);

        for (i = 0, tmpcount = rdpg->rp_count;
                i < rdpg->rp_npages; i++, tmpcount -= tmpsize) {
                tmpsize = min_t(int, tmpcount, CFS_PAGE_SIZE);
                ptlrpc_prep_bulk_page(desc, rdpg->rp_pages[i], 0, tmpsize);
        }

        LASSERT(desc->bd_nob == rdpg->rp_count);
        rc = ptlrpc_start_bulk_transfer(desc);
        if (rc)
                GOTO(free_desc, rc);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
                GOTO(abort_bulk, rc);

        *lwi = LWI_TIMEOUT(obd_timeout * HZ / 4, NULL, NULL);
        rc = l_wait_event(desc->bd_waitq, !ptlrpc_bulk_active(desc), lwi);
        LASSERT (rc == 0 || rc == -ETIMEDOUT);

        if (rc == 0) {
                if (desc->bd_success &&
                    desc->bd_nob_transferred == rdpg->rp_count)
                        GOTO(free_desc, rc);

                rc = -ETIMEDOUT; /* XXX should this be a different errno? */
        }

        DEBUG_REQ(D_ERROR, req, "bulk failed: %s %d(%d), evicting %s@%s\n",
                  (rc == -ETIMEDOUT) ? "timeout" : "network error",
                  desc->bd_nob_transferred, rdpg->rp_count,
                  req->rq_export->exp_client_uuid.uuid,
                  req->rq_export->exp_connection->c_remote_uuid.uuid);

        class_fail_export(req->rq_export);

        EXIT;
abort_bulk:
        ptlrpc_abort_bulk(desc);
free_desc:
        ptlrpc_free_bulk(desc);
out:
        return rc;
}

#ifdef HAVE_SPLIT_SUPPORT
/*
 * Retrieve dir entry from the page and insert it to the
 * slave object, actually, this should be in osd layer,
 * but since it will not in the final product, so just do
 * it here and do not define more moo api anymore for
 * this.
 */
static int mdt_write_dir_page(struct mdt_thread_info *info, struct page *page,
                              int size)
{
        struct mdt_object *object = info->mti_object;
        struct lu_dirpage *dp;
        struct lu_dirent *ent;
        int rc = 0, offset = 0, is_dir;

        ENTRY;

        /* Disable trans for this name insert, since it will
         * include many trans for this */
        info->mti_no_need_trans = 1;
        kmap(page);
        dp = page_address(page);
        offset = (int)((__u32)lu_dirent_start(dp) - (__u32)dp);

        for (ent = lu_dirent_start(dp); ent != NULL;
                          ent = lu_dirent_next(ent)) {
                struct lu_fid *lf = &ent->lde_fid;
                char *name;

                offset += ent->lde_reclen;
                if (ent->lde_namelen == 0)
                        continue;

                if (offset > size)
                        break;
                is_dir = le32_to_cpu(ent->lde_hash) & MAX_HASH_HIGHEST_BIT;
                OBD_ALLOC(name, ent->lde_namelen + 1);
                memcpy(name, ent->lde_name, ent->lde_namelen);
                rc = mdo_name_insert(info->mti_env,
                                     md_object_next(&object->mot_obj),
                                     name, lf, is_dir);
                OBD_FREE(name, ent->lde_namelen + 1);
                if (rc)
                        GOTO(out, rc);
        }
out:
        kunmap(page);
        RETURN(rc);
}

static int mdt_bulk_timeout(void *data)
{
        ENTRY;

        CERROR("mdt bulk transfer timeout \n");

        RETURN(1);
}

static int mdt_writepage(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct mdt_body         *reqbody;
        struct l_wait_info      *lwi;
        struct ptlrpc_bulk_desc *desc;
        struct page             *page;
        int                rc;
        ENTRY;


        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                RETURN(err_serious(-EFAULT));

        desc = ptlrpc_prep_bulk_exp (req, 1, BULK_GET_SINK, MDS_BULK_PORTAL);
        if (!desc)
                RETURN(err_serious(-ENOMEM));

        /* allocate the page for the desc */
        page = alloc_pages(GFP_KERNEL, 0);
        if (!page)
                GOTO(desc_cleanup, rc = -ENOMEM);

        CDEBUG(D_INFO, "Received page offset %d size %d \n",
                        (int)reqbody->size, (int)reqbody->nlink);

        ptlrpc_prep_bulk_page(desc, page, (int)reqbody->size,
                              (int)reqbody->nlink);

        /* FIXME: following parts are copied from ost_brw_write */

        /* Check if client was evicted while we were doing i/o before touching
           network */
        OBD_ALLOC_PTR(lwi);
        if (!lwi)
                GOTO(cleanup_page, rc = -ENOMEM);

        if (desc->bd_export->exp_failed)
                rc = -ENOTCONN;
        else
                rc = ptlrpc_start_bulk_transfer (desc);
        if (rc == 0) {
                *lwi = LWI_TIMEOUT_INTERVAL(obd_timeout * HZ / 4, HZ,
                                            mdt_bulk_timeout, desc);
                rc = l_wait_event(desc->bd_waitq, !ptlrpc_bulk_active(desc) ||
                                  desc->bd_export->exp_failed, lwi);
                LASSERT(rc == 0 || rc == -ETIMEDOUT);
                if (rc == -ETIMEDOUT) {
                        DEBUG_REQ(D_ERROR, req, "timeout on bulk GET");
                        ptlrpc_abort_bulk(desc);
                } else if (desc->bd_export->exp_failed) {
                        DEBUG_REQ(D_ERROR, req, "Eviction on bulk GET");
                        rc = -ENOTCONN;
                        ptlrpc_abort_bulk(desc);
                } else if (!desc->bd_success ||
                           desc->bd_nob_transferred != desc->bd_nob) {
                        DEBUG_REQ(D_ERROR, req, "%s bulk GET %d(%d)",
                                  desc->bd_success ?
                                  "truncated" : "network error on",
                                  desc->bd_nob_transferred, desc->bd_nob);
                        /* XXX should this be a different errno? */
                        rc = -ETIMEDOUT;
                }
        } else {
                DEBUG_REQ(D_ERROR, req, "ptlrpc_bulk_get failed: rc %d\n", rc);
        }
        if (rc)
                GOTO(cleanup_lwi, rc);
        rc = mdt_write_dir_page(info, page, reqbody->nlink);

cleanup_lwi:
        OBD_FREE_PTR(lwi);
cleanup_page:
        __free_pages(page, 0);
desc_cleanup:
        ptlrpc_free_bulk(desc);
        RETURN(rc);
}
#endif

static int mdt_readpage(struct mdt_thread_info *info)
{
        struct mdt_object *object = info->mti_object;
        struct lu_rdpg    *rdpg = &info->mti_u.rdpg.mti_rdpg;
        struct mdt_body   *reqbody;
        struct mdt_body   *repbody;
        int                rc;
        int                i;
        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK))
                RETURN(err_serious(-ENOMEM));

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL || repbody == NULL)
                RETURN(err_serious(-EFAULT));

        /*
         * prepare @rdpg before calling lower layers and transfer itself. Here
         * reqbody->size contains offset of where to start to read and
         * reqbody->nlink contains number bytes to read.
         */
        rdpg->rp_hash = reqbody->size;
        if ((__u64)rdpg->rp_hash != reqbody->size) {
                CERROR("Invalid hash: %#llx != %#llx\n",
                       (__u64)rdpg->rp_hash, reqbody->size);
                RETURN(-EFAULT);
        }
        rdpg->rp_count  = reqbody->nlink;
        rdpg->rp_npages = (rdpg->rp_count + CFS_PAGE_SIZE - 1)>>CFS_PAGE_SHIFT;
        OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);
        if (rdpg->rp_pages == NULL)
                RETURN(-ENOMEM);

        for (i = 0; i < rdpg->rp_npages; ++i) {
                rdpg->rp_pages[i] = alloc_pages(GFP_KERNEL, 0);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(free_rdpg, rc = -ENOMEM);
        }

        /* call lower layers to fill allocated pages with directory data */
        rc = mo_readpage(info->mti_env, mdt_object_child(object), rdpg);
        if (rc)
                GOTO(free_rdpg, rc);

        /* send pages to client */
        rc = mdt_sendpage(info, rdpg);

        EXIT;
free_rdpg:

        for (i = 0; i < rdpg->rp_npages; i++)
                if (rdpg->rp_pages[i] != NULL)
                        __free_pages(rdpg->rp_pages[i], 0);
        OBD_FREE(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);

        MDT_FAIL_RETURN(OBD_FAIL_MDS_SENDPAGE, 0);

        return rc;
}

static int mdt_reint_internal(struct mdt_thread_info *info,
                              struct mdt_lock_handle *lhc,
                              __u32 op)
{
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_request   *req = mdt_info_req(info);
        int                      rc;
        ENTRY;

        /* pack reply */
        if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
                                     mdt->mdt_max_mdsize);
        if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER,
                                     mdt->mdt_max_cookiesize);
        rc = req_capsule_pack(pill);
        if (rc != 0) {
                CERROR("Can't pack response, rc %d\n", rc);
                RETURN(err_serious(rc));
        }

        /*
         * Check this after packing response, because after we fail here without
         * allocating response, caller anyway may want to get ldlm_reply from it
         * and will get oops.
         */
        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK))
                RETURN(err_serious(-EFAULT));

        rc = mdt_reint_unpack(info, op);
        if (rc != 0) {
                CERROR("Can't unpack reint, rc %d\n", rc);
                RETURN(err_serious(rc));
        }

        rc = mdt_init_ucred_reint(info);
        if (rc)
                RETURN(rc);

        rc = mdt_fix_attr_ucred(info, op);
        if (rc != 0)
                GOTO(out, rc);

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                struct mdt_client_data *mcd;

                mcd = req->rq_export->exp_mdt_data.med_mcd;
                if (mcd->mcd_last_xid == req->rq_xid ||
                    mcd->mcd_last_close_xid == req->rq_xid) {
                        mdt_reconstruct(info, lhc);
                        rc = lustre_msg_get_status(req->rq_repmsg);
                        GOTO(out, rc);
                }
                DEBUG_REQ(D_HA, req, "no reply for RESENT (xid "LPD64")",
                          mcd->mcd_last_xid);
        }
        rc = mdt_reint_rec(info, lhc);

out:
        mdt_exit_ucred(info);
        RETURN(rc);
}

static long mdt_reint_opcode(struct mdt_thread_info *info,
                             const struct req_format **fmt)
{
        __u32 *ptr;
        long opc;

        opc = err_serious(-EFAULT);
        ptr = req_capsule_client_get(&info->mti_pill, &RMF_REINT_OPC);
        if (ptr != NULL) {
                opc = *ptr;
                DEBUG_REQ(D_INODE, mdt_info_req(info), "reint opt = %ld", opc);
                if (opc < REINT_MAX && fmt[opc] != NULL)
                        req_capsule_extend(&info->mti_pill, fmt[opc]);
                else {
                        CERROR("Unsupported opc: %ld\n", opc);
                        opc = err_serious(opc);
                }
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
                /*
                 * No lock possible here from client to pass it to reint code
                 * path.
                 */
                rc = mdt_reint_internal(info, NULL, opc);
        } else {
                rc = opc;
        }

        info->mti_fail_id = OBD_FAIL_MDS_REINT_NET_REP;
        RETURN(rc);
}

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
        struct req_capsule *pill = &info->mti_pill;
        struct mdt_body *body;
        int rc;
        ENTRY;

        /* The fid may be zero, so we req_capsule_set manually */
        req_capsule_set(pill, &RQF_MDS_SYNC);

        body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(err_serious(-EINVAL));

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK))
                RETURN(err_serious(-ENOMEM));

        if (fid_seq(&body->fid1) == 0) {
                /* sync the whole device */
                rc = req_capsule_pack(pill);
                if (rc == 0)
                        rc = mdt_device_sync(info);
                else
                        rc = err_serious(rc);
        } else {
                /* sync an object */
                rc = mdt_unpack_req_pack_rep(info, HABEO_CORPUS|HABEO_REFERO);
                if (rc == 0) {
                        rc = mdt_object_sync(info);
                        if (rc == 0) {
                                struct md_object *next;
                                const struct lu_fid *fid;
                                struct lu_attr *la = &info->mti_attr.ma_attr;

                                next = mdt_object_child(info->mti_object);
                                info->mti_attr.ma_need = MA_INODE;
                                rc = mo_attr_get(info->mti_env, next,
                                                 &info->mti_attr);
                                if (rc == 0) {
                                        body = req_capsule_server_get(pill,
                                                                &RMF_MDT_BODY);
                                        fid = mdt_object_fid(info->mti_object);
                                        mdt_pack_attr2body(info, body, la, fid);
                                }
                        }
                } else
                        rc = err_serious(rc);
        }
        RETURN(rc);
}

static int mdt_quotacheck_handle(struct mdt_thread_info *info)
{
        return err_serious(-EOPNOTSUPP);
}

static int mdt_quotactl_handle(struct mdt_thread_info *info)
{
        return err_serious(-EOPNOTSUPP);
}

/*
 * OBD PING and other handlers.
 */
static int mdt_obd_ping(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;
        rc = target_handle_ping(mdt_info_req(info));
        if (rc < 0)
                rc = err_serious(rc);
        RETURN(rc);
}

static int mdt_obd_log_cancel(struct mdt_thread_info *info)
{
        return err_serious(-EOPNOTSUPP);
}

static int mdt_obd_qc_callback(struct mdt_thread_info *info)
{
        return err_serious(-EOPNOTSUPP);
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
        struct ptlrpc_request *req;
        int rc;

        /*
         * info->mti_dlm_req already contains swapped and (if necessary)
         * converted dlm request.
         */
        LASSERT(info->mti_dlm_req != NULL);

        if (OBD_FAIL_CHECK(OBD_FAIL_LDLM_ENQUEUE)) {
                info->mti_fail_id = OBD_FAIL_LDLM_ENQUEUE;
                return 0;
        }

        req = mdt_info_req(info);
        rc = ldlm_handle_enqueue0(info->mti_mdt->mdt_namespace,
                                  req, info->mti_dlm_req, &cbs);
        info->mti_fail_id = OBD_FAIL_LDLM_REPLY;
        return rc ? err_serious(rc) : req->rq_status;
}

static int mdt_convert(struct mdt_thread_info *info)
{
        int rc;
        struct ptlrpc_request *req;

        LASSERT(info->mti_dlm_req);
        req = mdt_info_req(info);
        rc = ldlm_handle_convert0(req, info->mti_dlm_req);
        return rc ? err_serious(rc) : req->rq_status;
}

static int mdt_bl_callback(struct mdt_thread_info *info)
{
        CERROR("bl callbacks should not happen on MDS\n");
        LBUG();
        return err_serious(-EOPNOTSUPP);
}

static int mdt_cp_callback(struct mdt_thread_info *info)
{
        CERROR("cp callbacks should not happen on MDS\n");
        LBUG();
        return err_serious(-EOPNOTSUPP);
}

/*
 * sec context handlers
 */
static int mdt_sec_ctx_handle(struct mdt_thread_info *info)
{
        return mdt_handle_idmap(info);
}

static struct mdt_object *mdt_obj(struct lu_object *o)
{
        LASSERT(lu_device_is_mdt(o->lo_dev));
        return container_of0(o, struct mdt_object, mot_obj.mo_lu);
}

struct mdt_object *mdt_object_find(const struct lu_env *env,
                                   struct mdt_device *d,
                                   const struct lu_fid *f)
{
        struct lu_object *o;
        struct mdt_object *m;
        ENTRY;

        o = lu_object_find(env, d->mdt_md_dev.md_lu_dev.ld_site, f);
        if (IS_ERR(o))
                m = (struct mdt_object *)o;
        else
                m = mdt_obj(o);
        RETURN(m);
}

int mdt_object_lock(struct mdt_thread_info *info, struct mdt_object *o,
                    struct mdt_lock_handle *lh, __u64 ibits)
{
        ldlm_policy_data_t *policy = &info->mti_policy;
        struct ldlm_res_id *res_id = &info->mti_res_id;
        struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
        int rc;
        ENTRY;

        LASSERT(!lustre_handle_is_used(&lh->mlh_lh));
        LASSERT(lh->mlh_mode != LCK_MINMODE);
        if (mdt_object_exists(o) < 0) {
                LASSERT(!(ibits & MDS_INODELOCK_UPDATE));
                LASSERT(ibits & MDS_INODELOCK_LOOKUP);
        }
        policy->l_inodebits.bits = ibits;

        rc = fid_lock(ns, mdt_object_fid(o), &lh->mlh_lh, lh->mlh_mode,
                      policy, res_id);
        RETURN(rc);
}

/* lock with cross-ref fixes */
int mdt_object_cr_lock(struct mdt_thread_info *info, struct mdt_object *o,
                       struct mdt_lock_handle *lh, __u64 ibits)
{
        if (mdt_object_exists(o) < 0) {
                /* cross-ref object fix */
                ibits &= ~MDS_INODELOCK_UPDATE;
                ibits |= MDS_INODELOCK_LOOKUP;
        }
        return mdt_object_lock(info, o, lh, ibits);
}

/*
 * Just call ldlm_lock_decref() if decref, else we only call ptlrpc_save_lock()
 * to save this lock in req.  when transaction committed, req will be released,
 * and lock will, too.
 */
void mdt_object_unlock(struct mdt_thread_info *info, struct mdt_object *o,
                       struct mdt_lock_handle *lh, int decref)
{
        struct ptlrpc_request *req    = mdt_info_req(info);
        struct lustre_handle  *handle = &lh->mlh_lh;
        ldlm_mode_t            mode   = lh->mlh_mode;
        ENTRY;

        if (lustre_handle_is_used(handle)) {
                if (decref)
                        fid_unlock(mdt_object_fid(o), handle, mode);
                else
                        ptlrpc_save_lock(req, handle, mode);
                handle->cookie = 0;
        }
        EXIT;
}

struct mdt_object *mdt_object_find_lock(struct mdt_thread_info *info,
                                        const struct lu_fid *f,
                                        struct mdt_lock_handle *lh,
                                        __u64 ibits)
{
        struct mdt_object *o;

        o = mdt_object_find(info->mti_env, info->mti_mdt, f);
        if (!IS_ERR(o)) {
                int rc;

                rc = mdt_object_lock(info, o, lh, ibits);
                if (rc != 0) {
                        mdt_object_put(info->mti_env, o);
                        o = ERR_PTR(rc);
                }
        }
        return o;
}

void mdt_object_unlock_put(struct mdt_thread_info * info,
                           struct mdt_object * o,
                           struct mdt_lock_handle *lh,
                           int decref)
{
        mdt_object_unlock(info, o, lh, decref);
        mdt_object_put(info->mti_env, o);
}

static struct mdt_handler *mdt_handler_find(__u32 opc,
                                            struct mdt_opc_slice *supported)
{
        struct mdt_opc_slice *s;
        struct mdt_handler   *h;

        h = NULL;
        for (s = supported; s->mos_hs != NULL; s++) {
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
        return le64_to_cpu(req->rq_export->exp_mdt_data.med_mcd->mcd_last_xid);
}

static inline __u64 req_exp_last_close_xid(struct ptlrpc_request *req)
{
        return le64_to_cpu(req->rq_export->exp_mdt_data.med_mcd->mcd_last_close_xid);
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
        const struct mdt_body    *body;
        struct mdt_object        *obj;
        const struct lu_env      *env;
        struct req_capsule       *pill;
        int                       rc;

        env = info->mti_env;
        pill = &info->mti_pill;

        body = info->mti_body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                return -EFAULT;

        if (!fid_is_sane(&body->fid1)) {
                CERROR("Invalid fid: "DFID"\n", PFID(&body->fid1));
                return -EINVAL;
        }

        /*
         * Do not get size or any capa fields before we check that request
         * contains capa actually. There are some requests which do not, for
         * instance MDS_IS_SUBDIR.
         */
        if (req_capsule_has_field(pill, &RMF_CAPA1, RCL_CLIENT) &&
            req_capsule_get_size(pill, &RMF_CAPA1, RCL_CLIENT))
                mdt_set_capainfo(info, 0, &body->fid1,
                                 req_capsule_client_get(pill, &RMF_CAPA1));

        obj = mdt_object_find(env, info->mti_mdt, &body->fid1);
        if (!IS_ERR(obj)) {
                if ((flags & HABEO_CORPUS) &&
                    !mdt_object_exists(obj)) {
                        mdt_object_put(env, obj);
                        /* for capability renew ENOENT will be handled in 
                         * mdt_renew_capa */
                        if (body->valid & OBD_MD_FLOSSCAPA)
                                rc = 0;
                        else
                                rc = -ENOENT;
                } else {
                        info->mti_object = obj;
                        rc = 0;
                }
        } else
                rc = PTR_ERR(obj);

        return rc;
}

static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags)
{
        struct req_capsule *pill;
        int rc;

        ENTRY;
        pill = &info->mti_pill;

        if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_CLIENT))
                rc = mdt_body_unpack(info, flags);
        else
                rc = 0;

        if (rc == 0 && (flags & HABEO_REFERO)) {
                struct mdt_device       *mdt = info->mti_mdt;
                /*pack reply*/
                if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
                                             mdt->mdt_max_mdsize);
                if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER,
                                             mdt->mdt_max_cookiesize);

                rc = req_capsule_pack(pill);
        }
        RETURN(rc);
}

#if 0
struct lu_context_key mdt_txn_key;
static inline void mdt_finish_reply(struct mdt_thread_info *info, int rc)
{
        struct mdt_device     *mdt = info->mti_mdt;
        struct ptlrpc_request *req = mdt_info_req(info);
        struct obd_export     *exp = req->rq_export;

        /* sometimes the reply message has not been successfully packed */
        if (mdt == NULL || req == NULL || req->rq_repmsg == NULL)
                return;

        if (info->mti_trans_flags & MDT_NONEED_TRANSNO)
                return;

        /*XXX: assert on this when all code will be finished */
        if (rc != 0 && info->mti_transno != 0) {
                info->mti_transno = 0;
                CERROR("Transno is not 0 while rc is %i!\n", rc);
        }

        CDEBUG(D_INODE, "transno = %llu, last_committed = %llu\n",
               info->mti_transno, exp->exp_obd->obd_last_committed);

        spin_lock(&mdt->mdt_transno_lock);
        req->rq_transno = info->mti_transno;
        lustre_msg_set_transno(req->rq_repmsg, info->mti_transno);

        target_committed_to_req(req);

        spin_unlock(&mdt->mdt_transno_lock);
        lustre_msg_set_last_xid(req->rq_repmsg, req_exp_last_xid(req));
        //lustre_msg_set_last_xid(req->rq_repmsg, req->rq_xid);
}
#endif


static int mdt_init_capa_ctxt(const struct lu_env *env, struct mdt_device *m)
{
        struct md_device *next = m->mdt_child;

        return next->md_ops->mdo_init_capa_ctxt(env, next,
                                                m->mdt_opts.mo_mds_capa,
                                                m->mdt_capa_timeout,
                                                m->mdt_capa_alg,
                                                m->mdt_capa_keys);
}

/*
 * Invoke handler for this request opc. Also do necessary preprocessing
 * (according to handler ->mh_flags), and post-processing (setting of
 * ->last_{xid,committed}).
 */
static int mdt_req_handle(struct mdt_thread_info *info,
                          struct mdt_handler *h, struct ptlrpc_request *req)
{
        int   rc, serious = 0;
        __u32 flags;

        ENTRY;

        LASSERT(h->mh_act != NULL);
        LASSERT(h->mh_opc == lustre_msg_get_opc(req->rq_reqmsg));
        LASSERT(current->journal_info == NULL);

        DEBUG_REQ(D_INODE, req, "%s", h->mh_name);

        /*
         * Do not use *_FAIL_CHECK_ONCE() macros, because they will stop
         * correct handling of failed req later in ldlm due to doing
         * obd_fail_loc |= OBD_FAIL_ONCE | OBD_FAILED without actually
         * correct actions like it is done in target_send_reply_msg().
         */
        if (h->mh_fail_id != 0) {
                /*
                 * Set to info->mti_fail_id to handler fail_id, it will be used
                 * later, and better than use default fail_id.
                 */
                if (OBD_FAIL_CHECK(h->mh_fail_id)) {
                        info->mti_fail_id = h->mh_fail_id;
                        RETURN(0);
                }
        }

        rc = 0;
        flags = h->mh_flags;
        LASSERT(ergo(flags & (HABEO_CORPUS|HABEO_REFERO), h->mh_fmt != NULL));

        if (h->mh_fmt != NULL) {
                req_capsule_set(&info->mti_pill, h->mh_fmt);
                rc = mdt_unpack_req_pack_rep(info, flags);
        }

        if (rc == 0 && flags & MUTABOR &&
            req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                /* should it be rq_status? */
                rc = -EROFS;

        if (rc == 0 && flags & HABEO_CLAVIS) {
                struct ldlm_request *dlm_req;

                LASSERT(h->mh_fmt != NULL);

                dlm_req = req_capsule_client_get(&info->mti_pill, &RMF_DLM_REQ);
                if (dlm_req != NULL) {
                        if (info->mti_mdt->mdt_opts.mo_compat_resname)
                                rc = mdt_lock_resname_compat(info->mti_mdt,
                                                             dlm_req);
                        info->mti_dlm_req = dlm_req;
                } else {
                        CERROR("Can't unpack dlm request\n");
                        rc = -EFAULT;
                }
        }

        /* capability setting changed via /proc, needs reinitialize ctxt */
        if (info->mti_mdt && info->mti_mdt->mdt_capa_conf) {
                mdt_init_capa_ctxt(info->mti_env, info->mti_mdt);
                info->mti_mdt->mdt_capa_conf = 0;
        }

        if (rc == 0) {
                /*
                 * Process request, there can be two types of rc:
                 * 1) errors with msg unpack/pack, other failures outside the
                 * operation itself. This is counted as serious errors;
                 * 2) errors during fs operation, should be placed in rq_status
                 * only
                 */
                rc = h->mh_act(info);
                serious = is_serious(rc);
                rc = clear_serious(rc);
        } else
                serious = 1;

        req->rq_status = rc;

        /*
         * ELDLM_* codes which > 0 should be in rq_status only as well as
         * all non-serious errors.
         */
        if (rc > 0 || !serious)
                rc = 0;

        LASSERT(current->journal_info == NULL);

        if (rc == 0 && (flags & HABEO_CLAVIS)
            && info->mti_mdt->mdt_opts.mo_compat_resname) {
                struct ldlm_reply *dlmrep;

                dlmrep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
                if (dlmrep != NULL)
                        rc = mdt_lock_reply_compat(info->mti_mdt, dlmrep);
        }

        /* If we're DISCONNECTing, the mdt_export_data is already freed */
        if (rc == 0 && h->mh_opc != MDS_DISCONNECT)
                target_committed_to_req(req);

        RETURN(rc);
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

static void mdt_thread_info_init(struct ptlrpc_request *req,
                                 struct mdt_thread_info *info)
{
        int i;

        LASSERT(info->mti_env != req->rq_svc_thread->t_env);
        memset(info, 0, sizeof(*info));

        info->mti_rep_buf_nr = ARRAY_SIZE(info->mti_rep_buf_size);
        for (i = 0; i < ARRAY_SIZE(info->mti_rep_buf_size); i++)
                info->mti_rep_buf_size[i] = -1;

        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_init(&info->mti_lh[i]);

        info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
        info->mti_env = req->rq_svc_thread->t_env;
        info->mti_transno = lustre_msg_get_transno(req->rq_reqmsg);

        /* it can be NULL while CONNECT */
        if (req->rq_export)
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
        req_capsule_init(&info->mti_pill, req, RCL_SERVER,
                         info->mti_rep_buf_size);
}

static void mdt_thread_info_fini(struct mdt_thread_info *info)
{
        int i;

        req_capsule_fini(&info->mti_pill);
        if (info->mti_object != NULL) {
                mdt_object_put(info->mti_env, info->mti_object);
                info->mti_object = NULL;
        }
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_fini(&info->mti_lh[i]);
        info->mti_env = NULL;
}

/* mds/handler.c */
extern int mds_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process);
/*
 * Handle recovery. Return:
 *        +1: continue request processing;
 *       -ve: abort immediately with the given error code;
 *         0: send reply with error code in req->rq_status;
 */
static int mdt_recovery(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        int recovering;
        struct obd_device *obd;

        ENTRY;

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                mdt_handle_idmap(info);
                RETURN(+1);
        }

        if (req->rq_export == NULL) {
                CERROR("operation %d on unconnected MDS from %s\n",
                       lustre_msg_get_opc(req->rq_reqmsg),
                       libcfs_id2str(req->rq_peer));
                req->rq_status = -ENOTCONN;
                target_send_reply(req, -ENOTCONN, info->mti_fail_id);
                RETURN(0);
        }

        /* sanity check: if the xid matches, the request must be marked as a
         * resent or replayed */
        if (req->rq_xid == req_exp_last_xid(req) ||
            req->rq_xid == req_exp_last_close_xid(req)) {
                if (!(lustre_msg_get_flags(req->rq_reqmsg) &
                      (MSG_RESENT | MSG_REPLAY))) {
                        CERROR("rq_xid "LPU64" matches last_xid, "
                                "expected RESENT flag\n", req->rq_xid);
                        LBUG();
                        req->rq_status = -ENOTCONN;
                        RETURN(-ENOTCONN);
                }
        }

        /* else: note the opposite is not always true; a RESENT req after a
         * failover will usually not match the last_xid, since it was likely
         * never committed. A REPLAYed request will almost never match the
         * last xid, however it could for a committed, but still retained,
         * open. */

        obd = req->rq_export->exp_obd;

        /* Check for aborted recovery... */
        spin_lock_bh(&obd->obd_processing_task_lock);
        recovering = obd->obd_recovering;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (recovering) {
                int rc;
                int should_process;
                DEBUG_REQ(D_WARNING, req, "Got new replay");
                rc = mds_filter_recovery_request(req, obd, &should_process);
                if (rc != 0 || !should_process)
                        RETURN(rc);
                else if (should_process < 0) {
                        req->rq_status = should_process;
                        rc = ptlrpc_error(req);
                        RETURN(rc);
                }
        }
        RETURN(+1);
}

static int mdt_reply(struct ptlrpc_request *req, int rc,
                     struct mdt_thread_info *info)
{
        ENTRY;

#if 0
        if (req->rq_reply_state == NULL && rc == 0) {
                req->rq_status = rc;
                lustre_pack_reply(req, 1, NULL, NULL);
        }
#endif
        target_send_reply(req, rc, info->mti_fail_id);
        RETURN(0);
}

/* mds/handler.c */
extern int mds_msg_check_version(struct lustre_msg *msg);

static int mdt_handle0(struct ptlrpc_request *req,
                       struct mdt_thread_info *info,
                       struct mdt_opc_slice *supported)
{
        struct mdt_handler *h;
        struct lustre_msg  *msg;
        int                 rc;

        ENTRY;

        MDT_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);

        msg = req->rq_reqmsg;
        rc = mds_msg_check_version(msg);
        if (rc == 0) {
                rc = mdt_recovery(info);
                if (rc == +1) {
                        h = mdt_handler_find(lustre_msg_get_opc(msg),
                                             supported);
                        if (h != NULL) {
                                rc = mdt_req_handle(info, h, req);
                                rc = mdt_reply(req, rc, info);
                        } else {
                                req->rq_status = -ENOTSUPP;
                                rc = ptlrpc_error(req);
                                RETURN(rc);
                        }
                }
        } else
                CERROR(LUSTRE_MDT_NAME" drops mal-formed request\n");
        RETURN(rc);
}

/*
 * MDT handler function called by ptlrpc service thread when request comes.
 *
 * XXX common "target" functionality should be factored into separate module
 * shared by mdt, ost and stand-alone services like fld.
 */
static int mdt_handle_common(struct ptlrpc_request *req,
                             struct mdt_opc_slice *supported)
{
        struct lu_env          *env;
        struct mdt_thread_info *info;
        int                     rc;
        ENTRY;

        env = req->rq_svc_thread->t_env;
        LASSERT(env != NULL);
        LASSERT(env->le_ses != NULL);
        LASSERT(env->le_ctx.lc_thread == req->rq_svc_thread);
        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        mdt_thread_info_init(req, info);

        rc = mdt_handle0(req, info, supported);

        mdt_thread_info_fini(info);
        RETURN(rc);
}

/*
 * This is called from recovery code as handler of _all_ RPC types, FLD and SEQ
 * as well.
 */
int mdt_recovery_handle(struct ptlrpc_request *req)
{
        int rc;
        ENTRY;

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case FLD_QUERY:
                rc = mdt_handle_common(req, mdt_fld_handlers);
                break;
        case SEQ_QUERY:
                rc = mdt_handle_common(req, mdt_seq_handlers);
                break;
        default:
                rc = mdt_handle_common(req, mdt_regular_handlers);
                break;
        }

        RETURN(rc);
}

static int mdt_regular_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_regular_handlers);
}

static int mdt_readpage_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_readpage_handlers);
}

static int mdt_mdsc_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_seq_handlers);
}

static int mdt_mdss_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_seq_handlers);
}

static int mdt_dtss_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_seq_handlers);
}

static int mdt_fld_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_fld_handlers);
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
                .it_flags = MUTABOR,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_OPEN
        },
        [MDT_IT_CREATE]   = {
                .it_fmt   = &RQF_LDLM_INTENT,
                .it_flags = MUTABOR,
                .it_act   = mdt_intent_reint,
                .it_reint = REINT_CREATE
        },
        [MDT_IT_GETATTR]  = {
                .it_fmt   = &RQF_LDLM_INTENT_GETATTR,
                .it_flags = HABEO_REFERO,
                .it_act   = mdt_intent_getattr
        },
        [MDT_IT_READDIR]  = {
                .it_fmt   = NULL,
                .it_flags = 0,
                .it_act   = NULL
        },
        [MDT_IT_LOOKUP]   = {
                .it_fmt   = &RQF_LDLM_INTENT_GETATTR,
                .it_flags = HABEO_REFERO,
                .it_act   = mdt_intent_getattr
        },
        [MDT_IT_UNLINK]   = {
                .it_fmt   = &RQF_LDLM_INTENT_UNLINK,
                .it_flags = MUTABOR,
                .it_act   = NULL, /* XXX can be mdt_intent_reint, ? */
                .it_reint = REINT_UNLINK
        },
        [MDT_IT_TRUNC]    = {
                .it_fmt   = NULL,
                .it_flags = MUTABOR,
                .it_act   = NULL
        },
        [MDT_IT_GETXATTR] = {
                .it_fmt   = NULL,
                .it_flags = 0,
                .it_act   = NULL
        }
};

int mdt_intent_lock_replace(struct mdt_thread_info *info,
                            struct ldlm_lock **lockp,
                            struct ldlm_lock *new_lock,
                            struct mdt_lock_handle *lh,
                            int flags)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct ldlm_lock       *lock = *lockp;

        /*
         * Get new lock only for cases when possible resent did not find any
         * lock.
         */
        if (new_lock == NULL)
                new_lock = ldlm_handle2lock(&lh->mlh_lh);

        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY)) {
                lh->mlh_lh.cookie = 0;
                RETURN(0);
        }

        LASSERTF(new_lock != NULL,
                 "lockh "LPX64"\n", lh->mlh_lh.cookie);

        /*
         * If we've already given this lock to a client once, then we should
         * have no readers or writers.  Otherwise, we should have one reader
         * _or_ writer ref (which will be zeroed below) before returning the
         * lock to a client.
         */
        if (new_lock->l_export == req->rq_export) {
                LASSERT(new_lock->l_readers + new_lock->l_writers == 0);
        } else {
                LASSERT(new_lock->l_export == NULL);
                LASSERT(new_lock->l_readers + new_lock->l_writers == 1);
        }

        *lockp = new_lock;

        if (new_lock->l_export == req->rq_export) {
                /*
                 * Already gave this to the client, which means that we
                 * reconstructed a reply.
                 */
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) &
                        MSG_RESENT);
                lh->mlh_lh.cookie = 0;
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /* Fixup the lock to be given to the client */
        lock_res_and_lock(new_lock);
        new_lock->l_readers = 0;
        new_lock->l_writers = 0;

        new_lock->l_export = class_export_get(req->rq_export);
        list_add(&new_lock->l_export_chain,
                 &new_lock->l_export->exp_ldlm_data.led_held_locks);

        new_lock->l_blocking_ast = lock->l_blocking_ast;
        new_lock->l_completion_ast = lock->l_completion_ast;
        new_lock->l_remote_handle = lock->l_remote_handle;
        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        unlock_res_and_lock(new_lock);
        LDLM_LOCK_PUT(new_lock);
        lh->mlh_lh.cookie = 0;

        RETURN(ELDLM_LOCK_REPLACED);
}

static void mdt_intent_fixup_resent(struct req_capsule *pill,
                                    struct ldlm_lock *new_lock,
                                    struct ldlm_lock **old_lock,
                                    struct mdt_lock_handle *lh)
{
        struct ptlrpc_request  *req = pill->rc_req;
        struct obd_export      *exp = req->rq_export;
        struct lustre_handle    remote_hdl;
        struct ldlm_request    *dlmreq;
        struct list_head       *iter;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
                return;

        dlmreq = req_capsule_client_get(pill, &RMF_DLM_REQ);
        remote_hdl = dlmreq->lock_handle1;

        spin_lock(&exp->exp_ldlm_data.led_lock);
        list_for_each(iter, &exp->exp_ldlm_data.led_held_locks) {
                struct ldlm_lock *lock;
                lock = list_entry(iter, struct ldlm_lock, l_export_chain);
                if (lock == new_lock)
                        continue;
                if (lock->l_remote_handle.cookie == remote_hdl.cookie) {
                        lh->mlh_lh.cookie = lock->l_handle.h_cookie;
                        lh->mlh_mode = lock->l_granted_mode;

                        LDLM_DEBUG(lock, "restoring lock cookie");
                        DEBUG_REQ(D_HA, req, "restoring lock cookie "LPX64,
                                  lh->mlh_lh.cookie);
                        if (old_lock)
                                *old_lock = LDLM_LOCK_GET(lock);
                        spin_unlock(&exp->exp_ldlm_data.led_lock);
                        return;
                }
        }
        spin_unlock(&exp->exp_ldlm_data.led_lock);

        /*
         * If the xid matches, then we know this is a resent request, and allow
         * it. (It's probably an OPEN, for which we don't send a lock.
         */
        if (req->rq_xid == req_exp_last_xid(req))
                return;

        if (req->rq_xid == req_exp_last_close_xid(req))
                return;

        /*
         * This remote handle isn't enqueued, so we never received or processed
         * this request.  Clear MSG_RESENT, because it can be handled like any
         * normal request now.
         */
        lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);

        DEBUG_REQ(D_HA, req, "no existing lock with rhandle "LPX64,
                  remote_hdl.cookie);
}

static int mdt_intent_getattr(enum mdt_it_code opcode,
                              struct mdt_thread_info *info,
                              struct ldlm_lock **lockp,
                              int flags)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_RMT];
        struct ldlm_lock       *new_lock = NULL;
        __u64                   child_bits;
        struct ldlm_reply      *ldlm_rep;
        struct ptlrpc_request  *req;
        struct mdt_body        *reqbody;
        int                     rc;

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
                GOTO(out, rc = -EINVAL);
        }

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                GOTO(out, rc = err_serious(-EFAULT));

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                GOTO(out, rc);

        req = info->mti_pill.rc_req;
        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        mdt_set_disposition(info, ldlm_rep, DISP_IT_EXECD);

        /* Get lock from request for possible resent case. */
        mdt_intent_fixup_resent(&info->mti_pill, *lockp, &new_lock, lhc);

        ldlm_rep->lock_policy_res2 =
                mdt_getattr_name_lock(info, lhc, child_bits, ldlm_rep);

        if (mdt_get_disposition(ldlm_rep, DISP_LOOKUP_NEG))
                ldlm_rep->lock_policy_res2 = 0;
        if (!mdt_get_disposition(ldlm_rep, DISP_LOOKUP_POS) ||
            ldlm_rep->lock_policy_res2) {
                lhc->mlh_lh.cookie = 0ull;
                GOTO(out_ucred, rc = ELDLM_LOCK_ABORTED);
        }

        rc = mdt_intent_lock_replace(info, lockp, new_lock, lhc, flags);
out_ucred:
        mdt_exit_ucred(info);
        GOTO(out, rc);
out:
        mdt_shrink_reply(info, DLM_REPLY_REC_OFF + 1, 1, 0);
        return rc;
}

static int mdt_intent_reint(enum mdt_it_code opcode,
                            struct mdt_thread_info *info,
                            struct ldlm_lock **lockp,
                            int flags)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_RMT];
        struct ldlm_reply      *rep;
        long                    opc;
        int                     rc;

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
                RETURN(err_serious(-EPROTO));
        }

        /* Get lock from request for possible resent case. */
        mdt_intent_fixup_resent(&info->mti_pill, *lockp, NULL, lhc);

        rc = mdt_reint_internal(info, lhc, opc);

        rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        if (rep == NULL)
                RETURN(err_serious(-EFAULT));

        /* MDC expects this in any case */
        if (rc != 0)
                mdt_set_disposition(info, rep, DISP_LOOKUP_EXECD);

        /* cross-ref case, the lock should be returned to the client */
        if (rc == -EREMOTE) {
                LASSERT(lustre_handle_is_used(&lhc->mlh_lh));
                rep->lock_policy_res2 = 0;
                RETURN(mdt_intent_lock_replace(info, lockp, NULL, lhc, flags));
        }
        rep->lock_policy_res2 = clear_serious(rc);

        lhc->mlh_lh.cookie = 0ull;
        RETURN(ELDLM_LOCK_ABORTED);
}

static int mdt_intent_code(long itcode)
{
        int rc;

        switch(itcode) {
        case IT_OPEN:
                rc = MDT_IT_OPEN;
                break;
        case IT_OPEN|IT_CREAT:
                rc = MDT_IT_OCREAT;
                break;
        case IT_CREAT:
                rc = MDT_IT_CREATE;
                break;
        case IT_READDIR:
                rc = MDT_IT_READDIR;
                break;
        case IT_GETATTR:
                rc = MDT_IT_GETATTR;
                break;
        case IT_LOOKUP:
                rc = MDT_IT_LOOKUP;
                break;
        case IT_UNLINK:
                rc = MDT_IT_UNLINK;
                break;
        case IT_TRUNC:
                rc = MDT_IT_TRUNC;
                break;
        case IT_GETXATTR:
                rc = MDT_IT_GETXATTR;
                break;
        default:
                CERROR("Unknown intent opcode: %ld\n", itcode);
                rc = -EINVAL;
                break;
        }
        return rc;
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
                struct ptlrpc_request *req = mdt_info_req(info);
                if (flv->it_flags & MUTABOR &&
                    req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        rc = -EROFS;
        }
        if (rc == 0 && flv->it_act != NULL) {
                /* execute policy */
                rc = flv->it_act(opc, info, lockp, flags);
        } else
                rc = -EOPNOTSUPP;
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

        info = lu_context_key_get(&req->rq_svc_thread->t_env->le_ctx,
                                  &mdt_thread_key);
        LASSERT(info != NULL);
        pill = &info->mti_pill;
        LASSERT(pill->rc_req == req);

        if (req->rq_reqmsg->lm_bufcount > DLM_INTENT_IT_OFF) {
                req_capsule_extend(pill, &RQF_LDLM_INTENT);
                it = req_capsule_client_get(pill, &RMF_LDLM_INTENT);
                if (it != NULL) {
                        LDLM_DEBUG(lock, "intent policy opc: %s\n",
                                   ldlm_it2str(it->opc));

                        rc = mdt_intent_opc(it->opc, info, lockp, flags);
                        if (rc == 0)
                                rc = ELDLM_OK;
                } else
                        rc = err_serious(-EFAULT);
        } else {
                /* No intent was provided */
                LASSERT(pill->rc_fmt == &RQF_LDLM_ENQUEUE);
                rc = req_capsule_pack(pill);
                if (rc)
                        rc = err_serious(rc);
        }
        RETURN(rc);
}

/*
 * Seq wrappers
 */
static int mdt_seq_fini(const struct lu_env *env,
                        struct mdt_device *m)
{
        struct lu_site *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        ENTRY;

        if (ls && ls->ls_server_seq) {
                seq_server_fini(ls->ls_server_seq, env);
                OBD_FREE_PTR(ls->ls_server_seq);
                ls->ls_server_seq = NULL;
        }

        if (ls && ls->ls_control_seq) {
                seq_server_fini(ls->ls_control_seq, env);
                OBD_FREE_PTR(ls->ls_control_seq);
                ls->ls_control_seq = NULL;
        }

        if (ls && ls->ls_client_seq) {
                seq_client_fini(ls->ls_client_seq);
                OBD_FREE_PTR(ls->ls_client_seq);
                ls->ls_client_seq = NULL;
        }

        RETURN(0);
}

static int mdt_seq_init(const struct lu_env *env,
                        const char *uuid,
                        struct mdt_device *m)
{
        struct lu_site *ls;
        char *prefix;
        int rc;
        ENTRY;

        ls = m->mdt_md_dev.md_lu_dev.ld_site;

        /*
         * This is sequence-controller node. Init seq-controller server on local
         * MDT.
         */
        if (ls->ls_node_id == 0) {
                LASSERT(ls->ls_control_seq == NULL);

                OBD_ALLOC_PTR(ls->ls_control_seq);
                if (ls->ls_control_seq == NULL)
                        RETURN(-ENOMEM);

                rc = seq_server_init(ls->ls_control_seq,
                                     m->mdt_bottom, uuid,
                                     LUSTRE_SEQ_CONTROLLER,
                                     env);

                if (rc)
                        GOTO(out_seq_fini, rc);

                OBD_ALLOC_PTR(ls->ls_client_seq);
                if (ls->ls_client_seq == NULL)
                        GOTO(out_seq_fini, rc = -ENOMEM);

                OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
                if (prefix == NULL) {
                        OBD_FREE_PTR(ls->ls_client_seq);
                        GOTO(out_seq_fini, rc = -ENOMEM);
                }

                snprintf(prefix, MAX_OBD_NAME + 5, "ctl-%s",
                         uuid);

                /*
                 * Init seq-controller client after seq-controller server is
                 * ready. Pass ls->ls_control_seq to it for direct talking.
                 */
                rc = seq_client_init(ls->ls_client_seq, NULL,
                                     LUSTRE_SEQ_METADATA, prefix,
                                     ls->ls_control_seq);
                OBD_FREE(prefix, MAX_OBD_NAME + 5);

                if (rc)
                        GOTO(out_seq_fini, rc);
        }

        /* Init seq-server on local MDT */
        LASSERT(ls->ls_server_seq == NULL);

        OBD_ALLOC_PTR(ls->ls_server_seq);
        if (ls->ls_server_seq == NULL)
                GOTO(out_seq_fini, rc = -ENOMEM);

        rc = seq_server_init(ls->ls_server_seq,
                             m->mdt_bottom, uuid,
                             LUSTRE_SEQ_SERVER,
                             env);
        if (rc)
                GOTO(out_seq_fini, rc = -ENOMEM);

        /* Assign seq-controller client to local seq-server. */
        if (ls->ls_node_id == 0) {
                LASSERT(ls->ls_client_seq != NULL);

                rc = seq_server_set_cli(ls->ls_server_seq,
                                        ls->ls_client_seq,
                                        env);
        }

        EXIT;
out_seq_fini:
        if (rc)
                mdt_seq_fini(env, m);

        return rc;
}

static int mdt_md_connect(const struct lu_env *env,
                          struct lustre_handle *conn,
                          struct obd_device *mdc)
{
        struct obd_connect_data *ocd;
        int rc;

        OBD_ALLOC_PTR(ocd);
        if (!ocd)
                RETURN(-ENOMEM);
        /* The connection between MDS must be local */
        ocd->ocd_connect_flags |= OBD_CONNECT_LCL_CLIENT;
        rc = obd_connect(env, conn, mdc, &mdc->obd_uuid, ocd);

        OBD_FREE_PTR(ocd);

        RETURN(rc);
}

/*
 * Init client sequence manager which is used by local MDS to talk to sequence
 * controller on remote node.
 */
static int mdt_seq_init_cli(const struct lu_env *env,
                            struct mdt_device *m,
                            struct lustre_cfg *cfg)
{
        struct lu_site    *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        struct obd_device *mdc;
        struct obd_uuid   *uuidp, *mdcuuidp;
        char              *uuid_str, *mdc_uuid_str;
        int                rc;
        int                index;
        struct mdt_thread_info *info;
        char *p, *index_string = lustre_cfg_string(cfg, 2);
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        uuidp = &info->mti_u.uuid[0];
        mdcuuidp = &info->mti_u.uuid[1];

        LASSERT(index_string);

        index = simple_strtol(index_string, &p, 10);
        if (*p) {
                CERROR("Invalid index in lustre_cgf, offset 2\n");
                RETURN(-EINVAL);
        }

        /* check if this is adding the first MDC and controller is not yet
         * initialized. */
        if (index != 0 || ls->ls_client_seq)
                RETURN(0);

        uuid_str = lustre_cfg_string(cfg, 1);
        mdc_uuid_str = lustre_cfg_string(cfg, 4);
        obd_str2uuid(uuidp, uuid_str);
        obd_str2uuid(mdcuuidp, mdc_uuid_str);

        mdc = class_find_client_obd(uuidp, LUSTRE_MDC_NAME, mdcuuidp);
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

                rc = mdt_md_connect(env, &conn, mdc);
                if (rc) {
                        CERROR("target %s connect error %d\n",
                               mdc->obd_name, rc);
                } else {
                        ls->ls_control_exp = class_conn2export(&conn);

                        OBD_ALLOC_PTR(ls->ls_client_seq);

                        if (ls->ls_client_seq != NULL) {
                                char *prefix;

                                OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
                                if (!prefix)
                                        RETURN(-ENOMEM);

                                snprintf(prefix, MAX_OBD_NAME + 5, "ctl-%s",
                                         mdc->obd_name);

                                rc = seq_client_init(ls->ls_client_seq,
                                                     ls->ls_control_exp,
                                                     LUSTRE_SEQ_METADATA,
                                                     prefix, NULL);
                                OBD_FREE(prefix, MAX_OBD_NAME + 5);
                        } else
                                rc = -ENOMEM;

                        if (rc)
                                RETURN(rc);

                        LASSERT(ls->ls_server_seq != NULL);

                        rc = seq_server_set_cli(ls->ls_server_seq,
                                                ls->ls_client_seq,
                                                env);
                }
        }

        RETURN(rc);
}

static void mdt_seq_fini_cli(struct mdt_device *m)
{
        struct lu_site *ls;
        int rc;

        ENTRY;

        ls = m->mdt_md_dev.md_lu_dev.ld_site;

        if (ls && ls->ls_server_seq)
                seq_server_set_cli(ls->ls_server_seq,
                                   NULL, NULL);

        if (ls && ls->ls_control_exp) {
                rc = obd_disconnect(ls->ls_control_exp);
                if (rc) {
                        CERROR("failure to disconnect "
                               "obd: %d\n", rc);
                }
                ls->ls_control_exp = NULL;
        }
        EXIT;
}

/*
 * FLD wrappers
 */
static int mdt_fld_fini(const struct lu_env *env,
                        struct mdt_device *m)
{
        struct lu_site *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        ENTRY;

        if (ls && ls->ls_server_fld) {
                fld_server_fini(ls->ls_server_fld, env);
                OBD_FREE_PTR(ls->ls_server_fld);
                ls->ls_server_fld = NULL;
        }

        if (ls && ls->ls_client_fld != NULL) {
                fld_client_fini(ls->ls_client_fld);
                OBD_FREE_PTR(ls->ls_client_fld);
                ls->ls_client_fld = NULL;
        }

        RETURN(0);
}

static int mdt_fld_init(const struct lu_env *env,
                        const char *uuid,
                        struct mdt_device *m)
{
        struct lu_fld_target target;
        struct lu_site *ls;
        int rc;
        ENTRY;

        ls = m->mdt_md_dev.md_lu_dev.ld_site;

        OBD_ALLOC_PTR(ls->ls_server_fld);
        if (ls->ls_server_fld == NULL)
                RETURN(rc = -ENOMEM);

        rc = fld_server_init(ls->ls_server_fld,
                             m->mdt_bottom, uuid, env);
        if (rc) {
                OBD_FREE_PTR(ls->ls_server_fld);
                ls->ls_server_fld = NULL;
        }

        OBD_ALLOC_PTR(ls->ls_client_fld);
        if (!ls->ls_client_fld)
                GOTO(out_fld_fini, rc = -ENOMEM);

        rc = fld_client_init(ls->ls_client_fld, uuid,
                             LUSTRE_CLI_FLD_HASH_DHT);
        if (rc) {
                CERROR("can't init FLD, err %d\n",  rc);
                OBD_FREE_PTR(ls->ls_client_fld);
                GOTO(out_fld_fini, rc);
        }

        target.ft_srv = ls->ls_server_fld;
        target.ft_idx = ls->ls_node_id;
        target.ft_exp = NULL;

        fld_client_add_target(ls->ls_client_fld, &target);
        EXIT;
out_fld_fini:
        if (rc)
                mdt_fld_fini(env, m);
        return rc;
}

/* device init/fini methods */
static void mdt_stop_ptlrpc_service(struct mdt_device *m)
{
        if (m->mdt_regular_service != NULL) {
                ptlrpc_unregister_service(m->mdt_regular_service);
                m->mdt_regular_service = NULL;
        }
        if (m->mdt_readpage_service != NULL) {
                ptlrpc_unregister_service(m->mdt_readpage_service);
                m->mdt_readpage_service = NULL;
        }
        if (m->mdt_setattr_service != NULL) {
                ptlrpc_unregister_service(m->mdt_setattr_service);
                m->mdt_setattr_service = NULL;
        }
        if (m->mdt_mdsc_service != NULL) {
                ptlrpc_unregister_service(m->mdt_mdsc_service);
                m->mdt_mdsc_service = NULL;
        }
        if (m->mdt_mdss_service != NULL) {
                ptlrpc_unregister_service(m->mdt_mdss_service);
                m->mdt_mdss_service = NULL;
        }
        if (m->mdt_dtss_service != NULL) {
                ptlrpc_unregister_service(m->mdt_dtss_service);
                m->mdt_dtss_service = NULL;
        }
        if (m->mdt_fld_service != NULL) {
                ptlrpc_unregister_service(m->mdt_fld_service);
                m->mdt_fld_service = NULL;
        }
}

static int mdt_start_ptlrpc_service(struct mdt_device *m)
{
        int rc;
        static struct ptlrpc_service_conf conf;
        ENTRY;

        conf = (typeof(conf)) {
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
                .psc_num_threads   = min(max(mdt_num_threads, MDT_MIN_THREADS),
                                       MDT_MAX_THREADS),
                .psc_ctx_tags      = LCT_MD_THREAD
        };

        m->mdt_ldlm_client = &m->mdt_md_dev.md_lu_dev.ld_obd->obd_ldlm_client;
        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mdt_ldlm_client", m->mdt_ldlm_client);

        m->mdt_regular_service =
                ptlrpc_init_svc_conf(&conf, mdt_regular_handle, LUSTRE_MDT_NAME,
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (m->mdt_regular_service == NULL)
                RETURN(-ENOMEM);

        rc = ptlrpc_start_threads(NULL, m->mdt_regular_service, LUSTRE_MDT_NAME);
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * readpage service configuration. Parameters have to be adjusted,
         * ideally.
         */
        conf = (typeof(conf)) {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = MDS_MAXREQSIZE,
                .psc_max_reply_size   = MDS_MAXREPSIZE,
                .psc_req_portal       = MDS_READPAGE_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads   = min(max(mdt_num_threads, MDT_MIN_THREADS),
                                       MDT_MAX_THREADS),
                .psc_ctx_tags      = LCT_MD_THREAD
        };
        m->mdt_readpage_service =
                ptlrpc_init_svc_conf(&conf, mdt_readpage_handle,
                                     LUSTRE_MDT_NAME "_readpage",
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);

        if (m->mdt_readpage_service == NULL) {
                CERROR("failed to start readpage service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(NULL, m->mdt_readpage_service, "mdt_rdpg");

        /*
         * setattr service configuration.
         */
        conf = (typeof(conf)) {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = MDS_MAXREQSIZE,
                .psc_max_reply_size   = MDS_MAXREPSIZE,
                .psc_req_portal       = MDS_SETATTR_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads   = min(max(mdt_num_threads, MDT_MIN_THREADS),
                                       MDT_MAX_THREADS),
                .psc_ctx_tags      = LCT_MD_THREAD
        };

        m->mdt_setattr_service =
                ptlrpc_init_svc_conf(&conf, mdt_regular_handle,
                                     LUSTRE_MDT_NAME "_setattr",
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);

        if (!m->mdt_setattr_service) {
                CERROR("failed to start setattr service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(NULL, m->mdt_setattr_service, "mdt_attr");
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * sequence controller service configuration
         */
        conf = (typeof(conf)) {
                .psc_nbufs = MDS_NBUFS,
                .psc_bufsize = MDS_BUFSIZE,
                .psc_max_req_size = SEQ_MAXREQSIZE,
                .psc_max_reply_size = SEQ_MAXREPSIZE,
                .psc_req_portal = SEQ_CONTROLLER_PORTAL,
                .psc_rep_portal = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads = SEQ_NUM_THREADS,
                .psc_ctx_tags = LCT_MD_THREAD|LCT_DT_THREAD
        };

        m->mdt_mdsc_service =
                ptlrpc_init_svc_conf(&conf, mdt_mdsc_handle,
                                     LUSTRE_MDT_NAME"_mdsc",
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (!m->mdt_mdsc_service) {
                CERROR("failed to start seq controller service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(NULL, m->mdt_mdsc_service, "mdt_mdsc");
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * metadata sequence server service configuration
         */
        conf = (typeof(conf)) {
                .psc_nbufs = MDS_NBUFS,
                .psc_bufsize = MDS_BUFSIZE,
                .psc_max_req_size = SEQ_MAXREQSIZE,
                .psc_max_reply_size = SEQ_MAXREPSIZE,
                .psc_req_portal = SEQ_METADATA_PORTAL,
                .psc_rep_portal = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads = SEQ_NUM_THREADS,
                .psc_ctx_tags = LCT_MD_THREAD|LCT_DT_THREAD
        };

        m->mdt_mdss_service =
                ptlrpc_init_svc_conf(&conf, mdt_mdss_handle,
                                     LUSTRE_MDT_NAME"_mdss",
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (!m->mdt_mdss_service) {
                CERROR("failed to start metadata seq server service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(NULL, m->mdt_mdss_service, "mdt_mdss");
        if (rc)
                GOTO(err_mdt_svc, rc);


        /*
         * Data sequence server service configuration. We want to have really
         * cluster-wide sequences space. This is why we start only one sequence
         * controller which manages space.
         */
        conf = (typeof(conf)) {
                .psc_nbufs = MDS_NBUFS,
                .psc_bufsize = MDS_BUFSIZE,
                .psc_max_req_size = SEQ_MAXREQSIZE,
                .psc_max_reply_size = SEQ_MAXREPSIZE,
                .psc_req_portal = SEQ_DATA_PORTAL,
                .psc_rep_portal = OSC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads = SEQ_NUM_THREADS,
                .psc_ctx_tags = LCT_MD_THREAD|LCT_DT_THREAD
        };

        m->mdt_dtss_service =
                ptlrpc_init_svc_conf(&conf, mdt_dtss_handle,
                                     LUSTRE_MDT_NAME"_dtss",
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (!m->mdt_dtss_service) {
                CERROR("failed to start data seq server service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(NULL, m->mdt_dtss_service, "mdt_dtss");
        if (rc)
                GOTO(err_mdt_svc, rc);

        /* FLD service start */
        conf = (typeof(conf)) {
                .psc_nbufs            = MDS_NBUFS,
                .psc_bufsize          = MDS_BUFSIZE,
                .psc_max_req_size     = FLD_MAXREQSIZE,
                .psc_max_reply_size   = FLD_MAXREPSIZE,
                .psc_req_portal       = FLD_REQUEST_PORTAL,
                .psc_rep_portal       = MDC_REPLY_PORTAL,
                .psc_watchdog_timeout = MDT_SERVICE_WATCHDOG_TIMEOUT,
                .psc_num_threads      = FLD_NUM_THREADS,
                .psc_ctx_tags         = LCT_DT_THREAD|LCT_MD_THREAD
        };

        m->mdt_fld_service =
                ptlrpc_init_svc_conf(&conf, mdt_fld_handle,
                                     LUSTRE_MDT_NAME"_fld",
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
        if (!m->mdt_fld_service) {
                CERROR("failed to start fld service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(NULL, m->mdt_fld_service, "mdt_fld");
        if (rc)
                GOTO(err_mdt_svc, rc);

        EXIT;
err_mdt_svc:
        if (rc)
                mdt_stop_ptlrpc_service(m);

        return rc;
}

static void mdt_stack_fini(const struct lu_env *env,
                           struct mdt_device *m, struct lu_device *top)
{
        struct lu_device        *d = top, *n;
        struct lustre_cfg_bufs  *bufs;
        struct lustre_cfg       *lcfg;
        struct mdt_thread_info  *info;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        bufs = &info->mti_u.bufs;
        /* process cleanup, pass mdt obd name to get obd umount flags */
        lustre_cfg_bufs_reset(bufs, m->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, bufs);
        if (!lcfg) {
                CERROR("Cannot alloc lcfg!\n");
                return;
        }
        LASSERT(top);
        top->ld_ops->ldo_process_config(env, top, lcfg);
        lustre_cfg_free(lcfg);

        lu_site_purge(env, top->ld_site, ~0);
        while (d != NULL) {
                struct obd_type *type;
                struct lu_device_type *ldt = d->ld_type;

                /* each fini() returns next device in stack of layers
                 * * so we can avoid the recursion */
                n = ldt->ldt_ops->ldto_device_fini(env, d);
                lu_device_put(d);
                ldt->ldt_ops->ldto_device_free(env, d);
                type = ldt->ldt_obd_type;
                type->typ_refcnt--;
                class_put_type(type);

                /* switch to the next device in the layer */
                d = n;
        }
        m->mdt_child = NULL;
}

static struct lu_device *mdt_layer_setup(const struct lu_env *env,
                                         const char *typename,
                                         struct lu_device *child,
                                         struct lustre_cfg *cfg)
{
        struct obd_type       *type;
        struct lu_device_type *ldt;
        struct lu_device      *d;
        int rc;
        ENTRY;

        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("Unknown type: '%s'\n", typename);
                GOTO(out, rc = -ENODEV);
        }

        rc = lu_context_refill(&env->le_ctx);
        if (rc != 0) {
                CERROR("Failure to refill context: '%d'\n", rc);
                GOTO(out_type, rc);
        }

        if (env->le_ses != NULL) {
                rc = lu_context_refill(env->le_ses);
                if (rc != 0) {
                        CERROR("Failure to refill session: '%d'\n", rc);
                        GOTO(out_type, rc);
                }
        }

        ldt = type->typ_lu;
        if (ldt == NULL) {
                CERROR("type: '%s'\n", typename);
                GOTO(out_type, rc = -EINVAL);
        }

        ldt->ldt_obd_type = type;
        d = ldt->ldt_ops->ldto_device_alloc(env, ldt, cfg);
        if (IS_ERR(d)) {
                CERROR("Cannot allocate device: '%s'\n", typename);
                GOTO(out_type, rc = -ENODEV);
        }

        LASSERT(child->ld_site);
        d->ld_site = child->ld_site;

        type->typ_refcnt++;
        rc = ldt->ldt_ops->ldto_device_init(env, d, child);
        if (rc) {
                CERROR("can't init device '%s', rc %d\n", typename, rc);
                GOTO(out_alloc, rc);
        }
        lu_device_get(d);

        RETURN(d);

out_alloc:
        ldt->ldt_ops->ldto_device_free(env, d);
        type->typ_refcnt--;
out_type:
        class_put_type(type);
out:
        return ERR_PTR(rc);
}

static int mdt_stack_init(const struct lu_env *env,
                          struct mdt_device *m, struct lustre_cfg *cfg)
{
        struct lu_device  *d = &m->mdt_md_dev.md_lu_dev;
        struct lu_device  *tmp;
        struct md_device  *md;
        int rc;
        ENTRY;

        /* init the stack */
        tmp = mdt_layer_setup(env, LUSTRE_OSD_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                RETURN(PTR_ERR(tmp));
        }
        m->mdt_bottom = lu2dt_dev(tmp);
        d = tmp;
        tmp = mdt_layer_setup(env, LUSTRE_MDD_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                GOTO(out, rc = PTR_ERR(tmp));
        }
        d = tmp;
        md = lu2md_dev(d);

        tmp = mdt_layer_setup(env, LUSTRE_CMM_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                GOTO(out, rc = PTR_ERR(tmp));
        }
        d = tmp;
        /*set mdd upcall device*/
        md->md_upcall.mu_upcall_dev = lu2md_dev(d);

        md = lu2md_dev(d);
        /*set cmm upcall device*/
        md->md_upcall.mu_upcall_dev = &m->mdt_md_dev;

        m->mdt_child = lu2md_dev(d);

        /* process setup config */
        tmp = &m->mdt_md_dev.md_lu_dev;
        rc = tmp->ld_ops->ldo_process_config(env, tmp, cfg);
        GOTO(out, rc);
out:
        /* fini from last known good lu_device */
        if (rc)
                mdt_stack_fini(env, m, d);

        return rc;
}

static void mdt_fini(const struct lu_env *env, struct mdt_device *m)
{
        struct md_device *next = m->mdt_child;
        struct lu_device  *d = &m->mdt_md_dev.md_lu_dev;
        struct lu_site    *ls = d->ld_site;

        ENTRY;

        mdt_fs_cleanup(env, m);

        ping_evictor_stop();
        mdt_stop_ptlrpc_service(m);

        cleanup_capas(CAPA_SITE_SERVER);
        del_timer(&m->mdt_ck_timer);
        mdt_ck_thread_stop(m);

        upcall_cache_cleanup(m->mdt_rmtacl_cache);
        m->mdt_rmtacl_cache = NULL;

        upcall_cache_cleanup(m->mdt_identity_cache);
        m->mdt_identity_cache = NULL;

        if (m->mdt_namespace != NULL) {
                ldlm_namespace_free(m->mdt_namespace, 0);
                d->ld_obd->obd_namespace = m->mdt_namespace = NULL;
        }

        mdt_seq_fini(env, m);
        mdt_seq_fini_cli(m);
        mdt_fld_fini(env, m);

        if (m->mdt_rootsquash_info) {
                OBD_FREE_PTR(m->mdt_rootsquash_info);
                m->mdt_rootsquash_info = NULL;
        }

        next->md_ops->mdo_init_capa_ctxt(env, next, 0, 0, 0, NULL);
        cleanup_capas(CAPA_SITE_SERVER);
        del_timer(&m->mdt_ck_timer);
        mdt_ck_thread_stop(m);

        /* finish the stack */
        mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));

        if (ls) {
                lu_site_fini(ls);
                OBD_FREE_PTR(ls);
                d->ld_site = NULL;
        }
        LASSERT(atomic_read(&d->ld_ref) == 0);
        md_device_fini(&m->mdt_md_dev);

        EXIT;
}

static void fsoptions_to_mdt_flags(struct mdt_device *m, char *options)
{
        char *p = options;

        if (!options)
                return;

        while (*options) {
                int len;

                while (*p && *p != ',')
                        p++;

                len = p - options;
                if ((len == sizeof("user_xattr") - 1) &&
                    (memcmp(options, "user_xattr", len) == 0)) {
                        m->mdt_opts.mo_user_xattr = 1;
                        LCONSOLE_INFO("Enabling user_xattr\n");
                } else if ((len == sizeof("nouser_xattr") - 1) &&
                           (memcmp(options, "nouser_xattr", len) == 0)) {
                        m->mdt_opts.mo_user_xattr = 0;
                        LCONSOLE_INFO("Disabling user_xattr\n");
                } else if ((len == sizeof("acl") - 1) &&
                           (memcmp(options, "acl", len) == 0)) {
#ifdef CONFIG_FS_POSIX_ACL
                        m->mdt_opts.mo_acl = 1;
                        LCONSOLE_INFO("Enabling ACL\n");
#else
                        m->mdt_opts.mo_acl = 0;
                        CWARN("ignoring unsupported acl mount option\n");
                        LCONSOLE_INFO("Disabling ACL\n");
#endif
                } else if ((len == sizeof("noacl") - 1) &&
                           (memcmp(options, "noacl", len) == 0)) {
#ifdef CONFIG_FS_POSIX_ACL
                        m->mdt_opts.mo_acl = 0;
                        LCONSOLE_INFO("Disabling ACL\n");
#endif
                }

                options = ++p;
        }
}

int mdt_postrecov(const struct lu_env *, struct mdt_device *);

static int mdt_init0(const struct lu_env *env, struct mdt_device *m,
                     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
        struct lprocfs_static_vars lvars;
        struct mdt_thread_info    *info;
        struct obd_device         *obd;
        const char                *dev = lustre_cfg_string(cfg, 0);
        const char                *num = lustre_cfg_string(cfg, 2);
        struct lustre_mount_info  *lmi;
        struct lustre_sb_info     *lsi;
        struct lu_site            *s;
        int                        rc;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        obd = class_name2obd(dev);
        LASSERT(obd);

        spin_lock_init(&m->mdt_transno_lock);

        m->mdt_max_mdsize = MAX_MD_SIZE;
        m->mdt_max_cookiesize = sizeof(struct llog_cookie);

        m->mdt_opts.mo_user_xattr = 0;
        m->mdt_opts.mo_acl = 0;
        lmi = server_get_mount_2(dev);
        if (lmi == NULL) {
                CERROR("Cannot get mount info for %s! "
                       "set mdt_opts by default!\n", dev);
        } else {
                lsi = s2lsi(lmi->lmi_sb);
                fsoptions_to_mdt_flags(m, lsi->lsi_lmd->lmd_opts);
                server_put_mount_2(dev, lmi->lmi_mnt);
        }

        spin_lock_init(&m->mdt_ioepoch_lock);
        m->mdt_opts.mo_compat_resname = 0;
        m->mdt_capa_timeout = CAPA_TIMEOUT;
        m->mdt_capa_alg = CAPA_HMAC_ALG_SHA1;
        m->mdt_ck_timeout = CAPA_KEY_TIMEOUT;
        obd->obd_replayable = 1;
        spin_lock_init(&m->mdt_client_bitmap_lock);

        OBD_ALLOC_PTR(s);
        if (s == NULL)
                RETURN(-ENOMEM);

        md_device_init(&m->mdt_md_dev, ldt);
        m->mdt_md_dev.md_lu_dev.ld_ops = &mdt_lu_ops;
        m->mdt_md_dev.md_lu_dev.ld_obd = obd;
        /* set this lu_device to obd, because error handling need it */
        obd->obd_lu_dev = &m->mdt_md_dev.md_lu_dev;

        rc = lu_site_init(s, &m->mdt_md_dev.md_lu_dev);
        if (rc) {
                CERROR("can't init lu_site, rc %d\n", rc);
                GOTO(err_free_site, rc);
        }

        lprocfs_init_vars(mdt, &lvars);
        rc = lprocfs_obd_setup(obd, lvars.obd_vars);
        if (rc) {
                CERROR("can't init lprocfs, rc %d\n", rc);
                GOTO(err_fini_site, rc);
        }

        /* init the stack */
        rc = mdt_stack_init(env, m, cfg);
        if (rc) {
                CERROR("can't init device stack, rc %d\n", rc);
                GOTO(err_fini_site, rc);
        }

        /* set server index */
        LASSERT(num);
        s->ls_node_id = simple_strtol(num, NULL, 10);

        rc = mdt_fld_init(env, obd->obd_name, m);
        if (rc)
                GOTO(err_fini_stack, rc);

        rc = mdt_seq_init(env, obd->obd_name, m);
        if (rc)
                GOTO(err_fini_fld, rc);

        snprintf(info->mti_u.ns_name, sizeof info->mti_u.ns_name,
                 LUSTRE_MDT_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(info->mti_u.ns_name,
                                              LDLM_NAMESPACE_SERVER);
        if (m->mdt_namespace == NULL)
                GOTO(err_fini_seq, rc = -ENOMEM);

        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);
        /* set obd_namespace for compatibility with old code */
        obd->obd_namespace = m->mdt_namespace;

        m->mdt_identity_cache = upcall_cache_init(obd->obd_name,
                                                  "NONE",
                                                  &mdt_identity_upcall_cache_ops);
        if (IS_ERR(m->mdt_identity_cache)) {
                rc = PTR_ERR(m->mdt_identity_cache);
                m->mdt_identity_cache = NULL;
                GOTO(err_free_ns, rc);
        }

        m->mdt_rmtacl_cache = upcall_cache_init(obd->obd_name,
                                                MDT_RMTACL_UPCALL_PATH,
                                                &mdt_rmtacl_upcall_cache_ops);
        if (IS_ERR(m->mdt_rmtacl_cache)) {
                rc = PTR_ERR(m->mdt_rmtacl_cache);
                m->mdt_rmtacl_cache = NULL;
                GOTO(err_free_ns, rc);
        }

        m->mdt_ck_timer.function = mdt_ck_timer_callback;
        m->mdt_ck_timer.data = (unsigned long)m;
        init_timer(&m->mdt_ck_timer);
        rc = mdt_ck_thread_start(m);
        if (rc)
                GOTO(err_free_ns, rc);

        rc = mdt_start_ptlrpc_service(m);
        if (rc)
                GOTO(err_capa, rc);

        ping_evictor_start();

        rc = mdt_fs_setup(env, m, obd);
        if (rc)
                GOTO(err_stop_service, rc);

        rc = lu_site_init_finish(s);
        if (rc)
                GOTO(err_fs_cleanup, rc);

        if (obd->obd_recovering == 0)
                mdt_postrecov(env, m);

        mdt_init_capa_ctxt(env, m);
        RETURN(0);

err_fs_cleanup:
        mdt_fs_cleanup(env, m);
err_stop_service:
        mdt_stop_ptlrpc_service(m);
err_capa:
        del_timer(&m->mdt_ck_timer);
        mdt_ck_thread_stop(m);
err_free_ns:
        upcall_cache_cleanup(m->mdt_rmtacl_cache);
        m->mdt_rmtacl_cache = NULL;
        upcall_cache_cleanup(m->mdt_identity_cache);
        m->mdt_identity_cache = NULL;
        ldlm_namespace_free(m->mdt_namespace, 0);
        obd->obd_namespace = m->mdt_namespace = NULL;
err_fini_seq:
        mdt_seq_fini(env, m);
err_fini_fld:
        mdt_fld_fini(env, m);
err_fini_stack:
        mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));
err_fini_site:
        lu_site_fini(s);
err_free_site:
        OBD_FREE_PTR(s);

        md_device_fini(&m->mdt_md_dev);
        return (rc);
}

/* used by MGS to process specific configurations */
static int mdt_process_config(const struct lu_env *env,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdt_device *m = mdt_dev(d);
        struct md_device *md_next = m->mdt_child;
        struct lu_device *next = md2lu_dev(md_next);
        int rc = 0;
        ENTRY;

        switch (cfg->lcfg_command) {
        case LCFG_PARAM: {
                struct lprocfs_static_vars lvars;
                struct obd_device *obd = d->ld_obd;

                lprocfs_init_vars(mdt, &lvars);
                rc = class_process_proc_param(PARAM_MDT, lvars.obd_vars, cfg, obd);
                if (rc)
                        /* others are passed further */
                        rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
        case LCFG_ADD_MDC:
                /*
                 * Add mdc hook to get first MDT uuid and connect it to
                 * ls->controller to use for seq manager.
                 */
                rc = mdt_seq_init_cli(env, mdt_dev(d), cfg);
                if (rc) {
                        CERROR("can't initialize controller export, "
                               "rc %d\n", rc);
                }
        default:
                /* others are passed further */
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
        RETURN(rc);
}

static struct lu_object *mdt_object_alloc(const struct lu_env *env,
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

static int mdt_object_init(const struct lu_env *env, struct lu_object *o)
{
        struct mdt_device *d = mdt_dev(o->lo_dev);
        struct lu_device  *under;
        struct lu_object  *below;
        int                rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "object init, fid = "DFID"\n",
               PFID(lu_object_fid(o)));

        under = &d->mdt_child->md_lu_dev;
        below = under->ld_ops->ldo_object_alloc(env, o->lo_header, under);
        if (below != NULL) {
                lu_object_add(o, below);
        } else
                rc = -ENOMEM;

        RETURN(rc);
}

static void mdt_object_free(const struct lu_env *env, struct lu_object *o)
{
        struct mdt_object *mo = mdt_obj(o);
        struct lu_object_header *h;
        ENTRY;

        h = o->lo_header;
        CDEBUG(D_INFO, "object free, fid = "DFID"\n",
               PFID(lu_object_fid(o)));

        lu_object_fini(o);
        lu_object_header_fini(h);
        OBD_FREE_PTR(mo);
        EXIT;
}

static int mdt_object_print(const struct lu_env *env, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return (*p)(env, cookie, LUSTRE_MDT_NAME"-object@%p", o);
}

static struct lu_device_operations mdt_lu_ops = {
        .ldo_object_alloc   = mdt_object_alloc,
        .ldo_process_config = mdt_process_config
};

static struct lu_object_operations mdt_obj_ops = {
        .loo_object_init    = mdt_object_init,
        .loo_object_free    = mdt_object_free,
        .loo_object_print   = mdt_object_print
};

/* mds_connect_internal */
static int mdt_connect_internal(struct obd_export *exp,
                                struct mdt_device *mdt,
                                struct obd_connect_data *data)
{
        __u64 flags;

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

                if (!mdt->mdt_opts.mo_mds_capa)
                        data->ocd_connect_flags &= ~OBD_CONNECT_MDS_CAPA;

                if (!mdt->mdt_opts.mo_oss_capa)
                        data->ocd_connect_flags &= ~OBD_CONNECT_OSS_CAPA;

                exp->exp_connect_flags = data->ocd_connect_flags;
                data->ocd_version = LUSTRE_VERSION_CODE;
                exp->exp_mdt_data.med_ibits_known = data->ocd_ibits_known;
        }

#if 0
        if (mdt->mdt_opts.mo_acl &&
            ((exp->exp_connect_flags & OBD_CONNECT_ACL) == 0)) {
                CWARN("%s: MDS requires ACL support but client does not\n",
                      mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }
#endif

        flags = OBD_CONNECT_LCL_CLIENT | OBD_CONNECT_RMT_CLIENT;
        if ((exp->exp_connect_flags & flags) == flags) {
                CWARN("%s: both local and remote client flags are set\n",
                      mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }

        if (mdt->mdt_opts.mo_mds_capa &&
            ((exp->exp_connect_flags & OBD_CONNECT_MDS_CAPA) == 0)) {
                CWARN("%s: MDS requires capability support, but client not\n",
                      mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }

        if (mdt->mdt_opts.mo_oss_capa &&
            ((exp->exp_connect_flags & OBD_CONNECT_OSS_CAPA) == 0)) {
                CWARN("%s: MDS requires OSS capability support, "
                      "but client not\n",
                      mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }

        return 0;
}

/* mds_connect copy */
static int mdt_obd_connect(const struct lu_env *env,
                           struct lustre_handle *conn, struct obd_device *obd,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *data)
{
        struct mdt_export_data *med;
        struct mdt_client_data *mcd;
        struct obd_export      *exp;
        struct mdt_device      *mdt;
        int                     rc;
        ENTRY;

        LASSERT(env != NULL);
        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        mdt = mdt_dev(obd->obd_lu_dev);

        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        exp = class_conn2export(conn);
        LASSERT(exp != NULL);
        med = &exp->exp_mdt_data;

        rc = mdt_connect_internal(exp, mdt, data);
        if (rc == 0) {
                OBD_ALLOC_PTR(mcd);
                if (mcd != NULL) {
                        memcpy(mcd->mcd_uuid, cluuid, sizeof mcd->mcd_uuid);
                        med->med_mcd = mcd;
                        rc = mdt_client_new(env, mdt, med);
                        if (rc != 0) {
                                OBD_FREE_PTR(mcd);
                                med->med_mcd = NULL;
                        }
                } else
                        rc = -ENOMEM;
        }

        if (rc != 0)
                class_disconnect(exp);
        else
                class_export_put(exp);

        RETURN(rc);
}

static int mdt_obd_reconnect(struct obd_export *exp, struct obd_device *obd,
                             struct obd_uuid *cluuid,
                             struct obd_connect_data *data)
{
        int rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = mdt_connect_internal(exp, mdt_dev(obd->obd_lu_dev), data);

        RETURN(rc);
}

static int mdt_obd_disconnect(struct obd_export *exp)
{
        struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        if (mdt->mdt_namespace != NULL || exp->exp_obd->obd_namespace != NULL)
                ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock(&exp->exp_lock);
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
        spin_unlock(&exp->exp_lock);

        class_export_put(exp);
        RETURN(rc);
}

/* FIXME: Can we avoid using these two interfaces? */
static int mdt_init_export(struct obd_export *exp)
{
        struct mdt_export_data *med = &exp->exp_mdt_data;
        ENTRY;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);
        exp->exp_connecting = 1;
        RETURN(0);
}

static int mdt_destroy_export(struct obd_export *export)
{
        struct mdt_export_data *med;
        struct obd_device      *obd = export->exp_obd;
        struct mdt_device      *mdt;
        struct mdt_thread_info *info;
        struct lu_env           env;
        struct md_attr         *ma;
        int lmm_size;
        int cookie_size;
        int rc = 0;
        ENTRY;

        med = &export->exp_mdt_data;
        if (med->med_rmtclient)
                mdt_cleanup_idmap(med);

        target_destroy_export(export);

        if (obd_uuid_equals(&export->exp_client_uuid, &obd->obd_uuid))
                RETURN(0);

        mdt = mdt_dev(obd->obd_lu_dev);
        LASSERT(mdt != NULL);

        rc = lu_env_init(&env, NULL, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        info = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);
        memset(info, 0, sizeof *info);
        info->mti_env = &env;
        info->mti_mdt = mdt;

        ma = &info->mti_attr;
        lmm_size = ma->ma_lmm_size = mdt->mdt_max_mdsize;
        cookie_size = ma->ma_cookie_size = mdt->mdt_max_cookiesize;
        OBD_ALLOC(ma->ma_lmm, lmm_size);
        OBD_ALLOC(ma->ma_cookie, cookie_size);

        if (ma->ma_lmm == NULL || ma->ma_cookie == NULL)
                GOTO(out, rc = -ENOMEM);
        ma->ma_need = MA_LOV | MA_COOKIE;

        /* Close any open files (which may also cause orphan unlinking). */
        spin_lock(&med->med_open_lock);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mdt_file_data *mfd =
                        list_entry(tmp, struct mdt_file_data, mfd_list);

                /* Remove mfd handle so it can't be found again.
                 * We are consuming the mfd_list reference here. */
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);
                mdt_mfd_close(info, mfd);
                /* TODO: if we close the unlinked file,
                 * we need to remove it's objects from OST */
                memset(&ma->ma_attr, 0, sizeof(ma->ma_attr));
                spin_lock(&med->med_open_lock);
                ma->ma_lmm_size = lmm_size;
                ma->ma_cookie_size = cookie_size;
                ma->ma_need = MA_LOV | MA_COOKIE;
        }
        spin_unlock(&med->med_open_lock);
        info->mti_mdt = NULL;
        mdt_client_del(&env, mdt, med);

out:
        if (lmm_size)
                OBD_FREE(ma->ma_lmm, lmm_size);
        if (cookie_size)
                OBD_FREE(ma->ma_cookie, cookie_size);
        lu_env_fini(&env);

        RETURN(rc);
}

static int mdt_upcall(const struct lu_env *env, struct md_device *md,
                      enum md_upcall_event ev)
{
        struct mdt_device *m = mdt_dev(&md->md_lu_dev);
        struct md_device  *next  = m->mdt_child;
        struct mdt_thread_info *mti;
        int rc = 0;
        ENTRY;

        switch (ev) {
                case MD_LOV_SYNC:
                        rc = next->md_ops->mdo_maxsize_get(env, next,
                                        &m->mdt_max_mdsize,
                                        &m->mdt_max_cookiesize);
                        CDEBUG(D_INFO, "get max mdsize %d max cookiesize %d\n",
                                     m->mdt_max_mdsize, m->mdt_max_cookiesize);
                        break;
                case MD_NO_TRANS:
                        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
                        mti->mti_no_need_trans = 1;
                        CDEBUG(D_INFO, "disable mdt trans for this thread\n");
                        break;
                default:
                        CERROR("invalid event\n");
                        rc = -EINVAL;
                        break;
        }
        RETURN(rc);
}

static int mdt_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct lu_env      env;
        struct obd_device *obd= exp->exp_obd;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct dt_device  *dt = mdt->mdt_bottom;
        int rc;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
        rc = lu_env_init(&env, NULL, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        switch (cmd) {
        case OBD_IOC_SYNC:
                rc = dt->dd_ops->dt_sync(&env, dt);
                break;

        case OBD_IOC_SET_READONLY:
                rc = dt->dd_ops->dt_sync(&env, dt);
                dt->dd_ops->dt_ro(&env, dt);
                break;

        case OBD_IOC_ABORT_RECOVERY:
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_stop_recovery_thread(obd);
                break;

        default:
                CERROR("not supported cmd = %d for device %s\n",
                       cmd, obd->obd_name);
                rc = -EOPNOTSUPP;
        }

        lu_env_fini(&env);
        RETURN(rc);
}

int mdt_postrecov(const struct lu_env *env, struct mdt_device *mdt)
{
        struct lu_device *ld = md2lu_dev(mdt->mdt_child);
        int rc;
        ENTRY;
        rc = ld->ld_ops->ldo_recovery_complete(env, ld);
        RETURN(rc);
}

int mdt_obd_postrecov(struct obd_device *obd)
{
        struct lu_env env;
        int rc;

        rc = lu_env_init(&env, NULL, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);
        rc = mdt_postrecov(&env, mdt_dev(obd->obd_lu_dev));
        lu_env_fini(&env);
        return rc;
}

static struct obd_ops mdt_obd_device_ops = {
        .o_owner          = THIS_MODULE,
        .o_connect        = mdt_obd_connect,
        .o_reconnect      = mdt_obd_reconnect,
        .o_disconnect     = mdt_obd_disconnect,
        .o_init_export    = mdt_init_export,
        .o_destroy_export = mdt_destroy_export,
        .o_iocontrol      = mdt_iocontrol,
        .o_postrecov      = mdt_obd_postrecov

};

static struct lu_device* mdt_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);

        mdt_fini(env, m);
        RETURN(NULL);
}

static void mdt_device_free(const struct lu_env *env, struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);

        OBD_FREE_PTR(m);
}

static struct lu_device *mdt_device_alloc(const struct lu_env *env,
                                          struct lu_device_type *t,
                                          struct lustre_cfg *cfg)
{
        struct lu_device  *l;
        struct mdt_device *m;

        OBD_ALLOC_PTR(m);
        if (m != NULL) {
                int rc;

                l = &m->mdt_md_dev.md_lu_dev;
                rc = mdt_init0(env, m, t, cfg);
                if (rc != 0) {
                        OBD_FREE_PTR(m);
                        l = ERR_PTR(rc);
                        return l;
                }
                m->mdt_md_dev.md_upcall.mu_upcall = mdt_upcall;
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

/*
 * context key constructor/destructor
 */
static void *mdt_key_init(const struct lu_context *ctx,
                          struct lu_context_key *key)
{
        struct mdt_thread_info *info;

        /*
         * check that no high order allocations are incurred.
         */
        CLASSERT(CFS_PAGE_SIZE >= sizeof *info);
        OBD_ALLOC_PTR(info);
        if (info == NULL)
                info = ERR_PTR(-ENOMEM);
        return info;
}

static void mdt_key_fini(const struct lu_context *ctx,
                         struct lu_context_key *key, void *data)
{
        struct mdt_thread_info *info = data;
        OBD_FREE_PTR(info);
}

struct lu_context_key mdt_thread_key = {
        .lct_tags = LCT_MD_THREAD,
        .lct_init = mdt_key_init,
        .lct_fini = mdt_key_fini
};

static void *mdt_txn_key_init(const struct lu_context *ctx,
                              struct lu_context_key *key)
{
        struct mdt_txn_info *txi;

        /*
         * check that no high order allocations are incurred.
         */
        CLASSERT(CFS_PAGE_SIZE >= sizeof *txi);
        OBD_ALLOC_PTR(txi);
        if (txi == NULL)
                txi = ERR_PTR(-ENOMEM);
        return txi;
}

static void mdt_txn_key_fini(const struct lu_context *ctx,
                             struct lu_context_key *key, void *data)
{
        struct mdt_txn_info *txi = data;
        OBD_FREE_PTR(txi);
}

struct lu_context_key mdt_txn_key = {
        .lct_tags = LCT_TX_HANDLE,
        .lct_init = mdt_txn_key_init,
        .lct_fini = mdt_txn_key_fini
};

struct md_ucred *mdt_ucred(const struct mdt_thread_info *info)
{
        return md_ucred(info->mti_env);
}

static int mdt_type_init(struct lu_device_type *t)
{
        int rc;

        rc = lu_context_key_register(&mdt_thread_key);
        if (rc == 0)
                rc = lu_context_key_register(&mdt_txn_key);
        return rc;
}

static void mdt_type_fini(struct lu_device_type *t)
{
        lu_context_key_degister(&mdt_thread_key);
        lu_context_key_degister(&mdt_txn_key);
}

static struct lu_device_type_operations mdt_device_type_ops = {
        .ldto_init = mdt_type_init,
        .ldto_fini = mdt_type_fini,

        .ldto_device_alloc = mdt_device_alloc,
        .ldto_device_free  = mdt_device_free,
        .ldto_device_fini  = mdt_device_fini
};

static struct lu_device_type mdt_device_type = {
        .ldt_tags     = LU_DEVICE_MD,
        .ldt_name     = LUSTRE_MDT_NAME,
        .ldt_ops      = &mdt_device_type_ops,
        .ldt_ctx_tags = LCT_MD_THREAD
};

static int __init mdt_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        printk(KERN_INFO "Lustre: MetaData Target; info@clusterfs.com\n");

        mdt_num_threads = MDT_NUM_THREADS;
        lprocfs_init_vars(mdt, &lvars);
        rc = class_register_type(&mdt_obd_device_ops, NULL,
                                 lvars.module_vars, LUSTRE_MDT_NAME,
                                 &mdt_device_type);

        return rc;
}

static void __exit mdt_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDT_NAME);
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

#define DEF_SEQ_HNDL(flags, name, fn, fmt)                      \
        DEF_HNDL(SEQ, QUERY, _NET, flags, name, fn, fmt)

#define DEF_FLD_HNDL(flags, name, fn, fmt)                      \
        DEF_HNDL(FLD, QUERY, _NET, flags, name, fn, fmt)
/*
 * Request with a format known in advance
 */
#define DEF_MDT_HNDL_F(flags, name, fn)                                 \
        DEF_HNDL(MDS, GETATTR, _NET, flags, name, fn, &RQF_MDS_ ## name)

#define DEF_SEQ_HNDL_F(flags, name, fn)                                 \
        DEF_HNDL(SEQ, QUERY, _NET, flags, name, fn, &RQF_SEQ_ ## name)

#define DEF_FLD_HNDL_F(flags, name, fn)                                 \
        DEF_HNDL(FLD, QUERY, _NET, flags, name, fn, &RQF_FLD_ ## name)
/*
 * Request with a format we do not yet know
 */
#define DEF_MDT_HNDL_0(flags, name, fn)                                 \
        DEF_HNDL(MDS, GETATTR, _NET, flags, name, fn, NULL)

static struct mdt_handler mdt_mds_ops[] = {
DEF_MDT_HNDL_F(0,                         CONNECT,      mdt_connect),
DEF_MDT_HNDL_F(0,                         DISCONNECT,   mdt_disconnect),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, GETSTATUS,    mdt_getstatus),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, GETATTR,      mdt_getattr),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, GETATTR_NAME, mdt_getattr_name),
DEF_MDT_HNDL_F(HABEO_CORPUS|MUTABOR,      SETXATTR,     mdt_setxattr),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETXATTR,     mdt_getxattr),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, STATFS,       mdt_statfs),
DEF_MDT_HNDL_F(0                        |MUTABOR,
                                          REINT,        mdt_reint),
DEF_MDT_HNDL_F(HABEO_CORPUS             , CLOSE,        mdt_close),
DEF_MDT_HNDL_F(HABEO_CORPUS             , DONE_WRITING, mdt_done_writing),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, PIN,          mdt_pin),
DEF_MDT_HNDL_0(0,                         SYNC,         mdt_sync),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, IS_SUBDIR,    mdt_is_subdir),
DEF_MDT_HNDL_0(0,                         QUOTACHECK,   mdt_quotacheck_handle),
DEF_MDT_HNDL_0(0,                         QUOTACTL,     mdt_quotactl_handle)
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

#define DEF_SEC_CTX_HNDL(name, fn)                      \
        DEF_HNDL(SEC_CTX, INIT, _NET, 0, name, fn, NULL)

static struct mdt_handler mdt_sec_ctx_ops[] = {
        DEF_SEC_CTX_HNDL(INIT,          mdt_sec_ctx_handle),
        DEF_SEC_CTX_HNDL(INIT_CONT,     mdt_sec_ctx_handle),
        DEF_SEC_CTX_HNDL(FINI,          mdt_sec_ctx_handle)
};

static struct mdt_opc_slice mdt_regular_handlers[] = {
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
                .mos_opc_start = SEC_CTX_INIT,
                .mos_opc_end   = SEC_LAST_OPC,
                .mos_hs        = mdt_sec_ctx_ops
        },
        {
                .mos_hs        = NULL
        }
};

static struct mdt_handler mdt_readpage_ops[] = {
        DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, READPAGE, mdt_readpage),
#ifdef HAVE_SPLIT_SUPPORT
        DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, WRITEPAGE, mdt_writepage),
#endif

        /*
         * XXX: this is ugly and should be fixed one day, see mdc_close() for
         * detailed comments. --umka
         */
        DEF_MDT_HNDL_F(HABEO_CORPUS,              CLOSE,    mdt_close),
        DEF_MDT_HNDL_F(HABEO_CORPUS,              DONE_WRITING,    mdt_done_writing),
};

static struct mdt_opc_slice mdt_readpage_handlers[] = {
        {
                .mos_opc_start = MDS_GETATTR,
                .mos_opc_end   = MDS_LAST_OPC,
                .mos_hs        = mdt_readpage_ops
        },
        {
                .mos_hs        = NULL
        }
};

static struct mdt_handler mdt_seq_ops[] = {
        DEF_SEQ_HNDL_F(0, QUERY, (int (*)(struct mdt_thread_info *))seq_query)
};

static struct mdt_opc_slice mdt_seq_handlers[] = {
        {
                .mos_opc_start = SEQ_QUERY,
                .mos_opc_end   = SEQ_LAST_OPC,
                .mos_hs        = mdt_seq_ops
        },
        {
                .mos_hs        = NULL
        }
};

static struct mdt_handler mdt_fld_ops[] = {
        DEF_FLD_HNDL_F(0, QUERY, (int (*)(struct mdt_thread_info *))fld_query)
};

static struct mdt_opc_slice mdt_fld_handlers[] = {
        {
                .mos_opc_start = FLD_QUERY,
                .mos_opc_end   = FLD_LAST_OPC,
                .mos_hs        = mdt_fld_ops
        },
        {
                .mos_hs        = NULL
        }
};

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Target ("LUSTRE_MDT_NAME")");
MODULE_LICENSE("GPL");

CFS_MODULE_PARM(mdt_num_threads, "ul", ulong, 0444,
                "number of mdt service threads to start");

cfs_module(mdt, "0.2.0", mdt_mod_init, mdt_mod_exit);
