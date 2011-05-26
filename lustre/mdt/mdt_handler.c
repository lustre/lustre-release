/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2011 Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mdt/mdt_handler.c
 *
 * Lustre Metadata Target (mdt) request handler
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
/*
 * struct OBD_{ALLOC,FREE}*()
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
#ifdef HAVE_QUOTA_SUPPORT
# include <lustre_quota.h>
#endif
#include <lustre_acl.h>
#include <lustre_param.h>
#include <lustre_fsfilt.h>

mdl_mode_t mdt_mdl_lock_modes[] = {
        [LCK_MINMODE] = MDL_MINMODE,
        [LCK_EX]      = MDL_EX,
        [LCK_PW]      = MDL_PW,
        [LCK_PR]      = MDL_PR,
        [LCK_CW]      = MDL_CW,
        [LCK_CR]      = MDL_CR,
        [LCK_NL]      = MDL_NL,
        [LCK_GROUP]   = MDL_GROUP
};

ldlm_mode_t mdt_dlm_lock_modes[] = {
        [MDL_MINMODE] = LCK_MINMODE,
        [MDL_EX]      = LCK_EX,
        [MDL_PW]      = LCK_PW,
        [MDL_PR]      = LCK_PR,
        [MDL_CW]      = LCK_CW,
        [MDL_CR]      = LCK_CR,
        [MDL_NL]      = LCK_NL,
        [MDL_GROUP]   = LCK_GROUP
};

/*
 * Initialized in mdt_mod_init().
 */
static unsigned long mdt_num_threads;
static unsigned long mdt_min_threads;
static unsigned long mdt_max_threads;

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
static struct mdt_opc_slice mdt_xmds_handlers[];
static struct mdt_opc_slice mdt_seq_handlers[];
static struct mdt_opc_slice mdt_fld_handlers[];

static struct mdt_device *mdt_dev(struct lu_device *d);
static int mdt_regular_handle(struct ptlrpc_request *req);
static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags);
static int mdt_fid2path(const struct lu_env *env, struct mdt_device *mdt,
                        struct getinfo_fid2path *fp);

static const struct lu_object_operations mdt_obj_ops;

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

void mdt_lock_reg_init(struct mdt_lock_handle *lh, ldlm_mode_t lm)
{
        lh->mlh_pdo_hash = 0;
        lh->mlh_reg_mode = lm;
        lh->mlh_type = MDT_REG_LOCK;
}

void mdt_lock_pdo_init(struct mdt_lock_handle *lh, ldlm_mode_t lm,
                       const char *name, int namelen)
{
        lh->mlh_reg_mode = lm;
        lh->mlh_type = MDT_PDO_LOCK;

        if (name != NULL) {
                LASSERT(namelen > 0);
                lh->mlh_pdo_hash = full_name_hash(name, namelen);
        } else {
                LASSERT(namelen == 0);
                lh->mlh_pdo_hash = 0ull;
        }
}

static void mdt_lock_pdo_mode(struct mdt_thread_info *info, struct mdt_object *o,
                              struct mdt_lock_handle *lh)
{
        mdl_mode_t mode;
        ENTRY;

        /*
         * Any dir access needs couple of locks:
         *
         * 1) on part of dir we gonna take lookup/modify;
         *
         * 2) on whole dir to protect it from concurrent splitting and/or to
         * flush client's cache for readdir().
         *
         * so, for a given mode and object this routine decides what lock mode
         * to use for lock #2:
         *
         * 1) if caller's gonna lookup in dir then we need to protect dir from
         * being splitted only - LCK_CR
         *
         * 2) if caller's gonna modify dir then we need to protect dir from
         * being splitted and to flush cache - LCK_CW
         *
         * 3) if caller's gonna modify dir and that dir seems ready for
         * splitting then we need to protect it from any type of access
         * (lookup/modify/split) - LCK_EX --bzzz
         */

        LASSERT(lh->mlh_reg_mode != LCK_MINMODE);
        LASSERT(lh->mlh_pdo_mode == LCK_MINMODE);

        /*
         * Ask underlaying level its opinion about preferable PDO lock mode
         * having access type passed as regular lock mode:
         *
         * - MDL_MINMODE means that lower layer does not want to specify lock
         * mode;
         *
         * - MDL_NL means that no PDO lock should be taken. This is used in some
         * cases. Say, for non-splittable directories no need to use PDO locks
         * at all.
         */
        mode = mdo_lock_mode(info->mti_env, mdt_object_child(o),
                             mdt_dlm_mode2mdl_mode(lh->mlh_reg_mode));

        if (mode != MDL_MINMODE) {
                lh->mlh_pdo_mode = mdt_mdl_mode2dlm_mode(mode);
        } else {
                /*
                 * Lower layer does not want to specify locking mode. We do it
                 * our selves. No special protection is needed, just flush
                 * client's cache on modification and allow concurrent
                 * mondification.
                 */
                switch (lh->mlh_reg_mode) {
                case LCK_EX:
                        lh->mlh_pdo_mode = LCK_EX;
                        break;
                case LCK_PR:
                        lh->mlh_pdo_mode = LCK_CR;
                        break;
                case LCK_PW:
                        lh->mlh_pdo_mode = LCK_CW;
                        break;
                default:
                        CERROR("Not expected lock type (0x%x)\n",
                               (int)lh->mlh_reg_mode);
                        LBUG();
                }
        }

        LASSERT(lh->mlh_pdo_mode != LCK_MINMODE);
        EXIT;
}

static int mdt_getstatus(struct mdt_thread_info *info)
{
        struct mdt_device *mdt  = info->mti_mdt;
        struct md_device  *next = mdt->mdt_child;
        struct mdt_body   *repbody;
        int                rc;

        ENTRY;

        rc = mdt_check_ucred(info);
        if (rc)
                RETURN(err_serious(rc));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                RETURN(err_serious(-ENOMEM));

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        rc = next->md_ops->mdo_root_get(info->mti_env, next, &repbody->fid1);
        if (rc != 0)
                RETURN(rc);

        repbody->valid |= OBD_MD_FLID;

        if (mdt->mdt_opts.mo_mds_capa &&
            info->mti_exp->exp_connect_flags & OBD_CONNECT_MDS_CAPA) {
                struct mdt_object  *root;
                struct lustre_capa *capa;

                root = mdt_object_find(info->mti_env, mdt, &repbody->fid1);
                if (IS_ERR(root))
                        RETURN(PTR_ERR(root));

                capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA1);
                LASSERT(capa);
                capa->lc_opc = CAPA_OPC_MDS_DEFAULT;
                rc = mo_capa_get(info->mti_env, mdt_object_child(root), capa,
                                 0);
                mdt_object_put(info->mti_env, root);
                if (rc == 0)
                        repbody->valid |= OBD_MD_FLMDSCAPA;
        }

        RETURN(rc);
}

static int mdt_statfs(struct mdt_thread_info *info)
{
        struct md_device      *next  = info->mti_mdt->mdt_child;
        struct ptlrpc_service *svc;
        struct obd_statfs     *osfs;
        int                    rc;

        ENTRY;

        svc = info->mti_pill->rc_req->rq_rqbd->rqbd_service;

        /* This will trigger a watchdog timeout */
        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
                         (MDT_SERVICE_WATCHDOG_FACTOR *
                          at_get(&svc->srv_at_estimate)) + 1);

        rc = mdt_check_ucred(info);
        if (rc)
                RETURN(err_serious(rc));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                rc = err_serious(-ENOMEM);
        } else {
                osfs = req_capsule_server_get(info->mti_pill, &RMF_OBD_STATFS);
                rc = next->md_ops->mdo_statfs(info->mti_env, next,
                                              &info->mti_u.ksfs);
                statfs_pack(osfs, &info->mti_u.ksfs);
        }
        RETURN(rc);
}

/**
 * Pack SOM attributes into the reply.
 * Call under a DLM UPDATE lock.
 */
static void mdt_pack_size2body(struct mdt_thread_info *info,
                               struct mdt_object *mo)
{
        struct mdt_body *b;
        struct md_attr *ma = &info->mti_attr;

        LASSERT(ma->ma_attr.la_valid & LA_MODE);
        b = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);

        /* Check if Size-on-MDS is supported, if this is a regular file,
         * if SOM is enabled on the object and if SOM cache exists and valid.
         * Otherwise do not pack Size-on-MDS attributes to the reply. */
        if (!(mdt_conn_flags(info) & OBD_CONNECT_SOM) ||
            !S_ISREG(ma->ma_attr.la_mode) ||
            !mdt_object_is_som_enabled(mo) ||
            !(ma->ma_valid & MA_SOM))
                return;

        b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        b->size = ma->ma_som->msd_size;
        b->blocks = ma->ma_som->msd_blocks;
}

void mdt_pack_attr2body(struct mdt_thread_info *info, struct mdt_body *b,
                        const struct lu_attr *attr, const struct lu_fid *fid)
{
        struct md_attr *ma = &info->mti_attr;

        LASSERT(ma->ma_valid & MA_INODE);

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

        /*XXX should pack the reply body according to lu_valid*/
        b->valid |= OBD_MD_FLCTIME | OBD_MD_FLUID   |
                    OBD_MD_FLGID   | OBD_MD_FLTYPE  |
                    OBD_MD_FLMODE  | OBD_MD_FLNLINK | OBD_MD_FLFLAGS |
                    OBD_MD_FLATIME | OBD_MD_FLMTIME ;

        if (!S_ISREG(attr->la_mode)) {
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLRDEV;
        } else if (ma->ma_need & MA_LOV && ma->ma_lmm_size == 0) {
                /* means no objects are allocated on osts. */
                LASSERT(!(ma->ma_valid & MA_LOV));
                /* just ignore blocks occupied by extend attributes on MDS */
                b->blocks = 0;
                /* if no object is allocated on osts, the size on mds is valid. b=22272 */
                b->valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        }

        if (fid) {
                b->fid1 = *fid;
                b->valid |= OBD_MD_FLID;

                /* FIXME: these should be fixed when new igif ready.*/
                b->ino  =  fid_oid(fid);       /* 1.6 compatibility */
                b->generation = fid_ver(fid);  /* 1.6 compatibility */
                b->valid |= OBD_MD_FLGENER;    /* 1.6 compatibility */

                CDEBUG(D_INODE, DFID": nlink=%d, mode=%o, size="LPU64"\n",
                                PFID(fid), b->nlink, b->mode, b->size);
        }

        if (info)
                mdt_body_reverse_idmap(info, b);

        if (b->valid & OBD_MD_FLSIZE)
                CDEBUG(D_VFSTRACE, DFID": returning size %llu\n",
                       PFID(fid), (unsigned long long)b->size);
}

static inline int mdt_body_has_lov(const struct lu_attr *la,
                                   const struct mdt_body *body)
{
        return ((S_ISREG(la->la_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
                (S_ISDIR(la->la_mode) && (body->valid & OBD_MD_FLDIREA )) );
}

static int mdt_getattr_internal(struct mdt_thread_info *info,
                                struct mdt_object *o, int ma_need)
{
        struct md_object        *next = mdt_object_child(o);
        const struct mdt_body   *reqbody = info->mti_body;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *la = &ma->ma_attr;
        struct req_capsule      *pill = info->mti_pill;
        const struct lu_env     *env = info->mti_env;
        struct mdt_body         *repbody;
        struct lu_buf           *buffer = &info->mti_buf;
        int                     rc;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK))
                RETURN(err_serious(-ENOMEM));

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

        ma->ma_valid = 0;

        rc = mdt_object_exists(o);
        if (rc < 0) {
                /* This object is located on remote node.*/
                repbody->fid1 = *mdt_object_fid(o);
                repbody->valid = OBD_MD_FLID | OBD_MD_MDS;
                RETURN(0);
        }

        buffer->lb_buf = req_capsule_server_get(pill, &RMF_MDT_MD);
        buffer->lb_len = req_capsule_get_size(pill, &RMF_MDT_MD, RCL_SERVER);

        /* If it is dir object and client require MEA, then we got MEA */
        if (S_ISDIR(lu_object_attr(&next->mo_lu)) &&
            reqbody->valid & OBD_MD_MEA) {
                /* Assumption: MDT_MD size is enough for lmv size. */
                ma->ma_lmv = buffer->lb_buf;
                ma->ma_lmv_size = buffer->lb_len;
                ma->ma_need = MA_LMV | MA_INODE;
        } else {
                ma->ma_lmm = buffer->lb_buf;
                ma->ma_lmm_size = buffer->lb_len;
                ma->ma_need = MA_LOV | MA_INODE;
        }

        if (S_ISDIR(lu_object_attr(&next->mo_lu)) &&
            reqbody->valid & OBD_MD_FLDIREA  &&
            lustre_msg_get_opc(req->rq_reqmsg) == MDS_GETATTR) {
                /* get default stripe info for this dir. */
                ma->ma_need |= MA_LOV_DEF;
        }
        ma->ma_need |= ma_need;
        if (ma->ma_need & MA_SOM)
                ma->ma_som = &info->mti_u.som.data;

        rc = mo_attr_get(env, next, ma);
        if (unlikely(rc)) {
                CERROR("getattr error for "DFID": %d\n",
                        PFID(mdt_object_fid(o)), rc);
                RETURN(rc);
        }

        if (likely(ma->ma_valid & MA_INODE))
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
                        repbody->valid |= (OBD_MD_FLDIREA|OBD_MD_MEA);
                }
        } else if (S_ISLNK(la->la_mode) &&
                   reqbody->valid & OBD_MD_LINKNAME) {
                buffer->lb_buf = ma->ma_lmm;
                buffer->lb_len = reqbody->eadatasize;
                rc = mo_readlink(env, next, buffer);
                if (unlikely(rc <= 0)) {
                        CERROR("readlink failed: %d\n", rc);
                        rc = -EFAULT;
                } else {
                        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READLINK_EPROTO))
                                 rc -= 2;
                        repbody->valid |= OBD_MD_LINKNAME;
                        repbody->eadatasize = rc;
                        /* NULL terminate */
                        ((char*)ma->ma_lmm)[rc - 1] = 0;
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
                       "MAX_COOKIE to : %d:%d\n", repbody->max_mdsize,
                       repbody->max_cookiesize);
        }

        if (exp_connect_rmtclient(info->mti_exp) &&
            reqbody->valid & OBD_MD_FLRMTPERM) {
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
                                if (rc == -ENODATA) {
                                        repbody->aclsize = 0;
                                        repbody->valid |= OBD_MD_FLACL;
                                        rc = 0;
                                } else if (rc == -EOPNOTSUPP) {
                                        rc = 0;
                                } else {
                                        CERROR("got acl size: %d\n", rc);
                                }
                        } else {
                                repbody->aclsize = rc;
                                repbody->valid |= OBD_MD_FLACL;
                                rc = 0;
                        }
                }
        }
#endif

        if (reqbody->valid & OBD_MD_FLMDSCAPA &&
            info->mti_mdt->mdt_opts.mo_mds_capa &&
            info->mti_exp->exp_connect_flags & OBD_CONNECT_MDS_CAPA) {
                struct lustre_capa *capa;

                capa = req_capsule_server_get(pill, &RMF_CAPA1);
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
        struct mdt_object  *obj = info->mti_object;
        struct mdt_body    *body;
        struct lustre_capa *capa, *c;
        int rc;
        ENTRY;

        /* if object doesn't exist, or server has disabled capability,
         * return directly, client will find body->valid OBD_MD_FLOSSCAPA
         * flag not set.
         */
        if (!obj || !info->mti_mdt->mdt_opts.mo_oss_capa ||
            !(info->mti_exp->exp_connect_flags & OBD_CONNECT_OSS_CAPA))
                RETURN(0);

        body = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL);

        c = req_capsule_client_get(info->mti_pill, &RMF_CAPA1);
        LASSERT(c);

        capa = req_capsule_server_get(info->mti_pill, &RMF_CAPA2);
        LASSERT(capa);

        *capa = *c;
        rc = mo_capa_get(info->mti_env, mdt_object_child(obj), capa, 1);
        if (rc == 0)
                body->valid |= OBD_MD_FLOSSCAPA;
        RETURN(rc);
}

static int mdt_getattr(struct mdt_thread_info *info)
{
        struct mdt_object       *obj = info->mti_object;
        struct req_capsule      *pill = info->mti_pill;
        struct mdt_body         *reqbody;
        struct mdt_body         *repbody;
        mode_t                   mode;
        int                      md_size;
        int rc;
        ENTRY;

        reqbody = req_capsule_client_get(pill, &RMF_MDT_BODY);
        LASSERT(reqbody);

        if (reqbody->valid & OBD_MD_FLOSSCAPA) {
                rc = req_capsule_server_pack(pill);
                if (unlikely(rc))
                        RETURN(err_serious(rc));
                rc = mdt_renew_capa(info);
                GOTO(out_shrink, rc);
        }

        LASSERT(obj != NULL);
        LASSERT(lu_object_assert_exists(&obj->mot_obj.mo_lu));

        mode = lu_object_attr(&obj->mot_obj.mo_lu);
        if (S_ISLNK(mode) && (reqbody->valid & OBD_MD_LINKNAME) &&
            (reqbody->eadatasize > info->mti_mdt->mdt_max_mdsize))
                md_size = reqbody->eadatasize;
        else
                md_size = info->mti_mdt->mdt_max_mdsize;

        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, md_size);

        rc = req_capsule_server_pack(pill);
        if (unlikely(rc != 0))
                RETURN(err_serious(rc));

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        if (reqbody->valid & OBD_MD_FLRMTPERM)
                rc = mdt_init_ucred(info, reqbody);
        else
                rc = mdt_check_ucred(info);
        if (unlikely(rc))
                GOTO(out_shrink, rc);

        info->mti_spec.sp_ck_split = !!(reqbody->valid & OBD_MD_FLCKSPLIT);
        info->mti_cross_ref = !!(reqbody->valid & OBD_MD_FLCROSSREF);

        /*
         * Don't check capability at all, because rename might getattr for
         * remote obj, and at that time no capability is available.
         */
        mdt_set_capainfo(info, 1, &reqbody->fid1, BYPASS_CAPA);
        rc = mdt_getattr_internal(info, obj, 0);
        if (reqbody->valid & OBD_MD_FLRMTPERM)
                mdt_exit_ucred(info);
        EXIT;
out_shrink:
        mdt_shrink_reply(info);
        return rc;
}

static int mdt_is_subdir(struct mdt_thread_info *info)
{
        struct mdt_object     *o = info->mti_object;
        struct req_capsule    *pill = info->mti_pill;
        const struct mdt_body *body = info->mti_body;
        struct mdt_body       *repbody;
        int                    rc;
        ENTRY;

        LASSERT(o != NULL);

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);

        /*
         * We save last checked parent fid to @repbody->fid1 for remote
         * directory case.
         */
        LASSERT(fid_is_sane(&body->fid2));
        LASSERT(mdt_object_exists(o) > 0);
        rc = mdo_is_subdir(info->mti_env, mdt_object_child(o),
                           &body->fid2, &repbody->fid1);
        if (rc == 0 || rc == -EREMOTE)
                repbody->valid |= OBD_MD_FLID;

        RETURN(rc);
}

static int mdt_raw_lookup(struct mdt_thread_info *info,
                          struct mdt_object *parent,
                          const struct lu_name *lname,
                          struct ldlm_reply *ldlm_rep)
{
        struct md_object *next = mdt_object_child(info->mti_object);
        const struct mdt_body *reqbody = info->mti_body;
        struct lu_fid *child_fid = &info->mti_tmp_fid1;
        struct mdt_body *repbody;
        int rc;
        ENTRY;

        if (reqbody->valid != OBD_MD_FLID)
                RETURN(0);

        LASSERT(!info->mti_cross_ref);

        /* Only got the fid of this obj by name */
        rc = mdo_lookup(info->mti_env, next, lname, child_fid,
                        &info->mti_spec);
#if 0
        /* XXX is raw_lookup possible as intent operation? */
        if (rc != 0) {
                if (rc == -ENOENT)
                        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
                RETURN(rc);
        } else
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
#endif
        if (rc == 0) {
                repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
                repbody->fid1 = *child_fid;
                repbody->valid = OBD_MD_FLID;
        }
        RETURN(1);
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
        struct ptlrpc_request  *req       = mdt_info_req(info);
        struct mdt_body        *reqbody   = NULL;
        struct mdt_object      *parent    = info->mti_object;
        struct mdt_object      *child;
        struct md_object       *next      = mdt_object_child(parent);
        struct lu_fid          *child_fid = &info->mti_tmp_fid1;
        struct lu_name         *lname     = NULL;
        const char             *name      = NULL;
        int                     namelen   = 0;
        struct mdt_lock_handle *lhp       = NULL;
        struct ldlm_lock       *lock;
        struct ldlm_res_id     *res_id;
        int                     is_resent;
        int                     ma_need = 0;
        int                     rc;

        ENTRY;

        is_resent = lustre_handle_is_used(&lhc->mlh_reg_lh);
        LASSERT(ergo(is_resent,
                     lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT));

        LASSERT(parent != NULL);
        name = req_capsule_client_get(info->mti_pill, &RMF_NAME);
        if (name == NULL)
                RETURN(err_serious(-EFAULT));

        namelen = req_capsule_get_size(info->mti_pill, &RMF_NAME,
                                       RCL_CLIENT) - 1;
        if (!info->mti_cross_ref) {
                /*
                 * XXX: Check for "namelen == 0" is for getattr by fid
                 * (OBD_CONNECT_ATTRFID), otherwise do not allow empty name,
                 * that is the name must contain at least one character and
                 * the terminating '\0'
                 */
                if (namelen == 0) {
                        reqbody = req_capsule_client_get(info->mti_pill,
                                                         &RMF_MDT_BODY);
                        if (unlikely(reqbody == NULL))
                                RETURN(err_serious(-EFAULT));

                        if (unlikely(!fid_is_sane(&reqbody->fid2)))
                                RETURN(err_serious(-EINVAL));

                        name = NULL;
                        CDEBUG(D_INODE, "getattr with lock for "DFID"/"DFID", "
                               "ldlm_rep = %p\n",
                               PFID(mdt_object_fid(parent)), PFID(&reqbody->fid2),
                               ldlm_rep);
                } else {
                        lname = mdt_name(info->mti_env, (char *)name, namelen);
                        CDEBUG(D_INODE, "getattr with lock for "DFID"/%s, "
                               "ldlm_rep = %p\n", PFID(mdt_object_fid(parent)),
                               name, ldlm_rep);
                }
        }
        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_EXECD);

        rc = mdt_object_exists(parent);
        if (unlikely(rc == 0)) {
                LU_OBJECT_DEBUG(D_WARNING, info->mti_env,
                                &parent->mot_obj.mo_lu,
                                "Parent doesn't exist!\n");
                RETURN(-ESTALE);
        } else if (!info->mti_cross_ref) {
                LASSERTF(rc > 0, "Parent "DFID" is on remote server\n",
                         PFID(mdt_object_fid(parent)));
        }
        if (lname) {
                rc = mdt_raw_lookup(info, parent, lname, ldlm_rep);
                if (rc != 0) {
                        if (rc > 0)
                                rc = 0;
                        RETURN(rc);
                }
        }

        if (info->mti_cross_ref) {
                /* Only getattr on the child. Parent is on another node. */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
                child = parent;
                CDEBUG(D_INODE, "partial getattr_name child_fid = "DFID", "
                       "ldlm_rep=%p\n", PFID(mdt_object_fid(child)), ldlm_rep);

                if (is_resent) {
                        /* Do not take lock for resent case. */
                        lock = ldlm_handle2lock(&lhc->mlh_reg_lh);
                        LASSERTF(lock != NULL, "Invalid lock handle "LPX64"\n",
                                 lhc->mlh_reg_lh.cookie);
                        LASSERT(fid_res_name_eq(mdt_object_fid(child),
                                                &lock->l_resource->lr_name));
                        LDLM_LOCK_PUT(lock);
                        rc = 0;
                } else {
                        mdt_lock_handle_init(lhc);
                        mdt_lock_reg_init(lhc, LCK_PR);

                        /*
                         * Object's name is on another MDS, no lookup lock is
                         * needed here but update is.
                         */
                        child_bits &= ~MDS_INODELOCK_LOOKUP;
                        child_bits |= MDS_INODELOCK_UPDATE;

                        rc = mdt_object_lock(info, child, lhc, child_bits,
                                             MDT_LOCAL_LOCK);
                }
                if (rc == 0) {
                        /* Finally, we can get attr for child. */
                        mdt_set_capainfo(info, 0, mdt_object_fid(child),
                                         BYPASS_CAPA);
                        rc = mdt_getattr_internal(info, child, 0);
                        if (unlikely(rc != 0))
                                mdt_object_unlock(info, child, lhc, 1);
                }
                RETURN(rc);
        }

        if (lname) {
                /* step 1: lock parent */
                lhp = &info->mti_lh[MDT_LH_PARENT];
                mdt_lock_pdo_init(lhp, LCK_PR, name, namelen);
                rc = mdt_object_lock(info, parent, lhp, MDS_INODELOCK_UPDATE,
                                     MDT_LOCAL_LOCK);
                if (unlikely(rc != 0))
                        RETURN(rc);

                /* step 2: lookup child's fid by name */
                rc = mdo_lookup(info->mti_env, next, lname, child_fid,
                                &info->mti_spec);

                if (rc != 0) {
                        if (rc == -ENOENT)
                                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_NEG);
                        GOTO(out_parent, rc);
                } else
                        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        } else {
                *child_fid = reqbody->fid2;
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
        }

        /*
         *step 3: find the child object by fid & lock it.
         *        regardless if it is local or remote.
         */
        child = mdt_object_find(info->mti_env, info->mti_mdt, child_fid);

        if (unlikely(IS_ERR(child)))
                GOTO(out_parent, rc = PTR_ERR(child));
        if (is_resent) {
                /* Do not take lock for resent case. */
                lock = ldlm_handle2lock(&lhc->mlh_reg_lh);
                LASSERTF(lock != NULL, "Invalid lock handle "LPX64"\n",
                         lhc->mlh_reg_lh.cookie);

                res_id = &lock->l_resource->lr_name;
                if (!fid_res_name_eq(mdt_object_fid(child),
                                    &lock->l_resource->lr_name)) {
                         LASSERTF(fid_res_name_eq(mdt_object_fid(parent),
                                                 &lock->l_resource->lr_name),
                                 "Lock res_id: %lu/%lu/%lu, Fid: "DFID".\n",
                                 (unsigned long)res_id->name[0],
                                 (unsigned long)res_id->name[1],
                                 (unsigned long)res_id->name[2],
                                 PFID(mdt_object_fid(parent)));
                          CWARN("Although resent, but still not get child lock"
                                "parent:"DFID" child:"DFID"\n",
                                PFID(mdt_object_fid(parent)),
                                PFID(mdt_object_fid(child)));
                          lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);
                          LDLM_LOCK_PUT(lock);
                          GOTO(relock, 0);
                }
                LDLM_LOCK_PUT(lock);
                rc = 0;
        } else {
relock:
                OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RESEND, obd_timeout*2);
                mdt_lock_handle_init(lhc);
                mdt_lock_reg_init(lhc, LCK_PR);

                if (mdt_object_exists(child) == 0) {
                        LU_OBJECT_DEBUG(D_WARNING, info->mti_env,
                                        &child->mot_obj.mo_lu,
                                        "Object doesn't exist!\n");
                        GOTO(out_child, rc = -ENOENT);
                }

                if (!(child_bits & MDS_INODELOCK_UPDATE)) {
                        struct md_attr *ma = &info->mti_attr;

                        ma->ma_valid = 0;
                        ma->ma_need = MA_INODE;
                        rc = mo_attr_get(info->mti_env,
                                         mdt_object_child(child), ma);
                        if (unlikely(rc != 0))
                                GOTO(out_child, rc);

                        /* If the file has not been changed for some time, we
                         * return not only a LOOKUP lock, but also an UPDATE
                         * lock and this might save us RPC on later STAT. For
                         * directories, it also let negative dentry starts
                         * working for this dir. */
                        if (ma->ma_valid & MA_INODE &&
                            ma->ma_attr.la_valid & LA_CTIME &&
                            info->mti_mdt->mdt_namespace->ns_ctime_age_limit +
                                ma->ma_attr.la_ctime < cfs_time_current_sec())
                                child_bits |= MDS_INODELOCK_UPDATE;
                }

                rc = mdt_object_lock(info, child, lhc, child_bits,
                                     MDT_CROSS_LOCK);

                if (unlikely(rc != 0))
                        GOTO(out_child, rc);
        }

        lock = ldlm_handle2lock(&lhc->mlh_reg_lh);
        /* Get MA_SOM attributes if update lock is given. */
        if (lock &&
            lock->l_policy_data.l_inodebits.bits & MDS_INODELOCK_UPDATE &&
            S_ISREG(lu_object_attr(&mdt_object_child(child)->mo_lu)))
                ma_need = MA_SOM;

        /* finally, we can get attr for child. */
        mdt_set_capainfo(info, 1, child_fid, BYPASS_CAPA);
        rc = mdt_getattr_internal(info, child, ma_need);
        if (unlikely(rc != 0)) {
                mdt_object_unlock(info, child, lhc, 1);
        } else if (lock) {
                /* Debugging code. */
                res_id = &lock->l_resource->lr_name;
                LDLM_DEBUG(lock, "Returning lock to client");
                LASSERTF(fid_res_name_eq(mdt_object_fid(child),
                                         &lock->l_resource->lr_name),
                         "Lock res_id: %lu/%lu/%lu, Fid: "DFID".\n",
                         (unsigned long)res_id->name[0],
                         (unsigned long)res_id->name[1],
                         (unsigned long)res_id->name[2],
                         PFID(mdt_object_fid(child)));
                mdt_pack_size2body(info, child);
        }
        if (lock)
                LDLM_LOCK_PUT(lock);

        EXIT;
out_child:
        mdt_object_put(info->mti_env, child);
out_parent:
        if (lhp)
                mdt_object_unlock(info, parent, lhp, 1);
        return rc;
}

/* normal handler: should release the child lock */
static int mdt_getattr_name(struct mdt_thread_info *info)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_CHILD];
        struct mdt_body        *reqbody;
        struct mdt_body        *repbody;
        int rc;
        ENTRY;

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(reqbody != NULL);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody != NULL);

        info->mti_spec.sp_ck_split = !!(reqbody->valid & OBD_MD_FLCKSPLIT);
        info->mti_cross_ref = !!(reqbody->valid & OBD_MD_FLCROSSREF);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        rc = mdt_init_ucred(info, reqbody);
        if (unlikely(rc))
                GOTO(out_shrink, rc);

        rc = mdt_getattr_name_lock(info, lhc, MDS_INODELOCK_UPDATE, NULL);
        if (lustre_handle_is_used(&lhc->mlh_reg_lh)) {
                ldlm_lock_decref(&lhc->mlh_reg_lh, lhc->mlh_reg_mode);
                lhc->mlh_reg_lh.cookie = 0;
        }
        mdt_exit_ucred(info);
        EXIT;
out_shrink:
        mdt_shrink_reply(info);
        return rc;
}

static const struct lu_device_operations mdt_lu_ops;

static int lu_device_is_mdt(struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static int mdt_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg);

static int mdt_set_info(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        char *key;
        void *val;
        int keylen, vallen, rc = 0;
        ENTRY;

        rc = req_capsule_server_pack(info->mti_pill);
        if (rc)
                RETURN(rc);

        key = req_capsule_client_get(info->mti_pill, &RMF_SETINFO_KEY);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }

        keylen = req_capsule_get_size(info->mti_pill, &RMF_SETINFO_KEY,
                                      RCL_CLIENT);

        val = req_capsule_client_get(info->mti_pill, &RMF_SETINFO_VAL);
        if (val == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info val");
                RETURN(-EFAULT);
        }

        vallen = req_capsule_get_size(info->mti_pill, &RMF_SETINFO_VAL,
                                      RCL_CLIENT);

        /* Swab any part of val you need to here */
        if (KEY_IS(KEY_READ_ONLY)) {
                req->rq_status = 0;
                lustre_msg_set_status(req->rq_repmsg, 0);

                cfs_spin_lock(&req->rq_export->exp_lock);
                if (*(__u32 *)val)
                        req->rq_export->exp_connect_flags |= OBD_CONNECT_RDONLY;
                else
                        req->rq_export->exp_connect_flags &=~OBD_CONNECT_RDONLY;
                cfs_spin_unlock(&req->rq_export->exp_lock);

        } else if (KEY_IS(KEY_CHANGELOG_CLEAR)) {
                struct changelog_setinfo *cs =
                        (struct changelog_setinfo *)val;
                if (vallen != sizeof(*cs)) {
                        CERROR("Bad changelog_clear setinfo size %d\n", vallen);
                        RETURN(-EINVAL);
                }
                if (ptlrpc_req_need_swab(req)) {
                        __swab64s(&cs->cs_recno);
                        __swab32s(&cs->cs_id);
                }

                rc = mdt_iocontrol(OBD_IOC_CHANGELOG_CLEAR, info->mti_exp,
                                   vallen, val, NULL);
                lustre_msg_set_status(req->rq_repmsg, rc);

        } else {
                RETURN(-EINVAL);
        }
        RETURN(0);
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
                rc = mdt_init_sec_level(info);
                if (rc == 0)
                        rc = mdt_init_idmap(info);
                if (rc != 0)
                        obd_disconnect(class_export_get(req->rq_export));
        } else {
                rc = err_serious(rc);
        }
        return rc;
}

static int mdt_disconnect(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        rc = target_handle_disconnect(mdt_info_req(info));
        if (rc)
                rc = err_serious(rc);
        RETURN(rc);
}

static int mdt_sendpage(struct mdt_thread_info *info,
                        struct lu_rdpg *rdpg, int nob)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct obd_export       *exp = req->rq_export;
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
                RETURN(-ENOMEM);

        for (i = 0, tmpcount = nob;
                i < rdpg->rp_npages && tmpcount > 0; i++, tmpcount -= tmpsize) {
                tmpsize = min_t(int, tmpcount, CFS_PAGE_SIZE);
                ptlrpc_prep_bulk_page(desc, rdpg->rp_pages[i], 0, tmpsize);
        }

        LASSERT(desc->bd_nob == nob);
        rc = target_bulk_io(exp, desc, lwi);
        ptlrpc_free_bulk(desc);
        RETURN(rc);
}

#ifdef HAVE_SPLIT_SUPPORT
/*
 * Retrieve dir entry from the page and insert it to the slave object, actually,
 * this should be in osd layer, but since it will not in the final product, so
 * just do it here and do not define more moo api anymore for this.
 */
static int mdt_write_dir_page(struct mdt_thread_info *info, struct page *page,
                              int size)
{
        struct mdt_object *object = info->mti_object;
        struct lu_fid *lf = &info->mti_tmp_fid2;
        struct md_attr *ma = &info->mti_attr;
        struct lu_dirpage *dp;
        struct lu_dirent *ent;
        int rc = 0, offset = 0;
        ENTRY;

        /* Make sure we have at least one entry. */
        if (size == 0)
                RETURN(-EINVAL);

        /*
         * Disable trans for this name insert, since it will include many trans
         * for this.
         */
        info->mti_no_need_trans = 1;
        /*
         * When write_dir_page, no need update parent's ctime,
         * and no permission check for name_insert.
         */
        ma->ma_attr.la_ctime = 0;
        ma->ma_attr.la_valid = LA_MODE;
        ma->ma_valid = MA_INODE;

        cfs_kmap(page);
        dp = page_address(page);
        offset = (int)((__u32)lu_dirent_start(dp) - (__u32)dp);

        for (ent = lu_dirent_start(dp); ent != NULL;
             ent = lu_dirent_next(ent)) {
                struct lu_name *lname;
                char *name;

                if (le16_to_cpu(ent->lde_namelen) == 0)
                        continue;

                fid_le_to_cpu(lf, &ent->lde_fid);
                if (le64_to_cpu(ent->lde_hash) & MAX_HASH_HIGHEST_BIT)
                        ma->ma_attr.la_mode = S_IFDIR;
                else
                        ma->ma_attr.la_mode = 0;
                OBD_ALLOC(name, le16_to_cpu(ent->lde_namelen) + 1);
                if (name == NULL)
                        GOTO(out, rc = -ENOMEM);

                memcpy(name, ent->lde_name, le16_to_cpu(ent->lde_namelen));
                lname = mdt_name(info->mti_env, name,
                                 le16_to_cpu(ent->lde_namelen));
                ma->ma_attr_flags |= (MDS_PERM_BYPASS | MDS_QUOTA_IGNORE);
                rc = mdo_name_insert(info->mti_env,
                                     md_object_next(&object->mot_obj),
                                     lname, lf, ma);
                OBD_FREE(name, le16_to_cpu(ent->lde_namelen) + 1);
                if (rc) {
                        CERROR("Can't insert %*.*s, rc %d\n",
                               le16_to_cpu(ent->lde_namelen),
                               le16_to_cpu(ent->lde_namelen),
                               ent->lde_name, rc);
                        GOTO(out, rc);
                }

                offset += lu_dirent_size(ent);
                if (offset >= size)
                        break;
        }
        EXIT;
out:
        cfs_kunmap(page);
        return rc;
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


        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL)
                RETURN(err_serious(-EFAULT));

        desc = ptlrpc_prep_bulk_exp(req, 1, BULK_GET_SINK, MDS_BULK_PORTAL);
        if (desc == NULL)
                RETURN(err_serious(-ENOMEM));

        /* allocate the page for the desc */
        page = cfs_alloc_page(CFS_ALLOC_STD);
        if (page == NULL)
                GOTO(desc_cleanup, rc = -ENOMEM);

        CDEBUG(D_INFO, "Received page offset %d size %d \n",
               (int)reqbody->size, (int)reqbody->nlink);

        ptlrpc_prep_bulk_page(desc, page, (int)reqbody->size,
                              (int)reqbody->nlink);

        rc = sptlrpc_svc_prep_bulk(req, desc);
        if (rc != 0)
                GOTO(cleanup_page, rc);
        /*
         * Check if client was evicted while we were doing i/o before touching
         * network.
         */
        OBD_ALLOC_PTR(lwi);
        if (!lwi)
                GOTO(cleanup_page, rc = -ENOMEM);

        if (desc->bd_export->exp_failed)
                rc = -ENOTCONN;
        else
                rc = ptlrpc_start_bulk_transfer (desc);
        if (rc == 0) {
                *lwi = LWI_TIMEOUT_INTERVAL(obd_timeout * CFS_HZ / 4, CFS_HZ,
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
                DEBUG_REQ(D_ERROR, req, "ptlrpc_bulk_get failed: rc %d", rc);
        }
        if (rc)
                GOTO(cleanup_lwi, rc);
        rc = mdt_write_dir_page(info, page, reqbody->nlink);

cleanup_lwi:
        OBD_FREE_PTR(lwi);
cleanup_page:
        cfs_free_page(page);
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

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK))
                RETURN(err_serious(-ENOMEM));

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL || repbody == NULL)
                RETURN(err_serious(-EFAULT));

        /*
         * prepare @rdpg before calling lower layers and transfer itself. Here
         * reqbody->size contains offset of where to start to read and
         * reqbody->nlink contains number bytes to read.
         */
        rdpg->rp_hash = reqbody->size;
        if (rdpg->rp_hash != reqbody->size) {
                CERROR("Invalid hash: "LPX64" != "LPX64"\n",
                       rdpg->rp_hash, reqbody->size);
                RETURN(-EFAULT);
        }

        rdpg->rp_attrs = reqbody->mode;
        if (info->mti_exp->exp_connect_flags & OBD_CONNECT_64BITHASH)
                rdpg->rp_attrs |= LUDA_64BITHASH;
        rdpg->rp_count  = min_t(unsigned int, reqbody->nlink,
                                PTLRPC_MAX_BRW_SIZE);
        rdpg->rp_npages = (rdpg->rp_count + CFS_PAGE_SIZE - 1) >>
                          CFS_PAGE_SHIFT;
        OBD_ALLOC(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);
        if (rdpg->rp_pages == NULL)
                RETURN(-ENOMEM);

        for (i = 0; i < rdpg->rp_npages; ++i) {
                rdpg->rp_pages[i] = cfs_alloc_page(CFS_ALLOC_STD);
                if (rdpg->rp_pages[i] == NULL)
                        GOTO(free_rdpg, rc = -ENOMEM);
        }

        /* call lower layers to fill allocated pages with directory data */
        rc = mo_readpage(info->mti_env, mdt_object_child(object), rdpg);
        if (rc < 0)
                GOTO(free_rdpg, rc);

        /* send pages to client */
        rc = mdt_sendpage(info, rdpg, rc);

        EXIT;
free_rdpg:

        for (i = 0; i < rdpg->rp_npages; i++)
                if (rdpg->rp_pages[i] != NULL)
                        cfs_free_page(rdpg->rp_pages[i]);
        OBD_FREE(rdpg->rp_pages, rdpg->rp_npages * sizeof rdpg->rp_pages[0]);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE))
                RETURN(0);

        return rc;
}

static int mdt_reint_internal(struct mdt_thread_info *info,
                              struct mdt_lock_handle *lhc,
                              __u32 op)
{
        struct req_capsule      *pill = info->mti_pill;
        struct mdt_device       *mdt = info->mti_mdt;
        struct md_quota         *mq = md_quota(info->mti_env);
        struct mdt_body         *repbody;
        int                      rc = 0;
        ENTRY;

        /* pack reply */
        if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
                                     mdt->mdt_max_mdsize);
        if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER,
                                     mdt->mdt_max_cookiesize);

        rc = req_capsule_server_pack(pill);
        if (rc != 0) {
                CERROR("Can't pack response, rc %d\n", rc);
                RETURN(err_serious(rc));
        }

        if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_SERVER)) {
                repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
                LASSERT(repbody);
                repbody->eadatasize = 0;
                repbody->aclsize = 0;
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK))
                GOTO(out_shrink, rc = err_serious(-EFAULT));

        rc = mdt_reint_unpack(info, op);
        if (rc != 0) {
                CERROR("Can't unpack reint, rc %d\n", rc);
                GOTO(out_shrink, rc = err_serious(rc));
        }

        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_REINT_DELAY, 10);

        /* for replay no cookkie / lmm need, because client have this already */
        if (info->mti_spec.no_create == 1)  {
                if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER, 0);

                if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER,
                                             0);
        }

        rc = mdt_init_ucred_reint(info);
        if (rc)
                GOTO(out_shrink, rc);

        rc = mdt_fix_attr_ucred(info, op);
        if (rc != 0)
                GOTO(out_ucred, rc = err_serious(rc));

        if (mdt_check_resent(info, mdt_reconstruct, lhc)) {
                rc = lustre_msg_get_status(mdt_info_req(info)->rq_repmsg);
                GOTO(out_ucred, rc);
        }
        mq->mq_exp = info->mti_exp;
        rc = mdt_reint_rec(info, lhc);
        EXIT;
out_ucred:
        mdt_exit_ucred(info);
out_shrink:
        mdt_shrink_reply(info);
        return rc;
}

static long mdt_reint_opcode(struct mdt_thread_info *info,
                             const struct req_format **fmt)
{
        struct mdt_rec_reint *rec;
        long opc;

        opc = err_serious(-EFAULT);
        rec = req_capsule_client_get(info->mti_pill, &RMF_REC_REINT);
        if (rec != NULL) {
                opc = rec->rr_opcode;
                DEBUG_REQ(D_INODE, mdt_info_req(info), "reint opt = %ld", opc);
                if (opc < REINT_MAX && fmt[opc] != NULL)
                        req_capsule_extend(info->mti_pill, fmt[opc]);
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
                [REINT_SETATTR]  = &RQF_MDS_REINT_SETATTR,
                [REINT_CREATE]   = &RQF_MDS_REINT_CREATE,
                [REINT_LINK]     = &RQF_MDS_REINT_LINK,
                [REINT_UNLINK]   = &RQF_MDS_REINT_UNLINK,
                [REINT_RENAME]   = &RQF_MDS_REINT_RENAME,
                [REINT_OPEN]     = &RQF_MDS_REINT_OPEN,
                [REINT_SETXATTR] = &RQF_MDS_REINT_SETXATTR
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

/* this should sync the whole device */
static int mdt_device_sync(const struct lu_env *env, struct mdt_device *mdt)
{
        struct dt_device *dt = mdt->mdt_bottom;
        int rc;
        ENTRY;

        rc = dt->dd_ops->dt_sync(env, dt);
        RETURN(rc);
}

/* this should sync this object */
static int mdt_object_sync(struct mdt_thread_info *info)
{
        struct md_object *next;
        int rc;
        ENTRY;

        if (!mdt_object_exists(info->mti_object)) {
                CWARN("Non existing object  "DFID"!\n",
                      PFID(mdt_object_fid(info->mti_object)));
                RETURN(-ESTALE);
        }
        next = mdt_object_child(info->mti_object);
        rc = mo_object_sync(info->mti_env, next);

        RETURN(rc);
}

static int mdt_sync(struct mdt_thread_info *info)
{
        struct req_capsule *pill = info->mti_pill;
        struct mdt_body *body;
        int rc;
        ENTRY;

        /* The fid may be zero, so we req_capsule_set manually */
        req_capsule_set(pill, &RQF_MDS_SYNC);

        body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(err_serious(-EINVAL));

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK))
                RETURN(err_serious(-ENOMEM));

        if (fid_seq(&body->fid1) == 0) {
                /* sync the whole device */
                rc = req_capsule_server_pack(pill);
                if (rc == 0)
                        rc = mdt_device_sync(info->mti_env, info->mti_mdt);
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
                                info->mti_attr.ma_valid = 0;
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

#ifdef HAVE_QUOTA_SUPPORT
static int mdt_quotacheck_handle(struct mdt_thread_info *info)
{
        struct obd_quotactl *oqctl;
        struct req_capsule *pill = info->mti_pill;
        struct obd_export *exp = info->mti_exp;
        struct md_quota *mq = md_quota(info->mti_env);
        struct md_device *next = info->mti_mdt->mdt_child;
        int rc;
        ENTRY;

        oqctl = req_capsule_client_get(pill, &RMF_OBD_QUOTACTL);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        /* remote client has no permission for quotacheck */
        if (unlikely(exp_connect_rmtclient(exp)))
                RETURN(-EPERM);

        rc = req_capsule_server_pack(pill);
        if (rc)
                RETURN(rc);

        mq->mq_exp = exp;
        rc = next->md_ops->mdo_quota.mqo_check(info->mti_env, next,
                                               oqctl->qc_type);
        RETURN(rc);
}

static int mdt_quotactl_handle(struct mdt_thread_info *info)
{
        struct obd_quotactl *oqctl, *repoqc;
        struct req_capsule *pill = info->mti_pill;
        struct obd_export *exp = info->mti_exp;
        struct md_quota *mq = md_quota(info->mti_env);
        struct md_device *next = info->mti_mdt->mdt_child;
        const struct md_quota_operations *mqo = &next->md_ops->mdo_quota;
        int id, rc;
        ENTRY;

        oqctl = req_capsule_client_get(pill, &RMF_OBD_QUOTACTL);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        id = oqctl->qc_id;
        if (exp_connect_rmtclient(exp)) {
                struct ptlrpc_request *req = mdt_info_req(info);
                struct mdt_export_data *med = mdt_req2med(req);
                struct lustre_idmap_table *idmap = med->med_idmap;

                if (unlikely(oqctl->qc_cmd != Q_GETQUOTA &&
                             oqctl->qc_cmd != Q_GETINFO))
                        RETURN(-EPERM);


                if (oqctl->qc_type == USRQUOTA)
                        id = lustre_idmap_lookup_uid(NULL, idmap, 0,
                                                     oqctl->qc_id);
                else if (oqctl->qc_type == GRPQUOTA)
                        id = lustre_idmap_lookup_gid(NULL, idmap, 0,
                                                     oqctl->qc_id);
                else
                        RETURN(-EINVAL);

                if (id == CFS_IDMAP_NOTFOUND) {
                        CDEBUG(D_QUOTA, "no mapping for id %u\n",
                               oqctl->qc_id);
                        RETURN(-EACCES);
                }
        }

        rc = req_capsule_server_pack(pill);
        if (rc)
                RETURN(rc);

        repoqc = req_capsule_server_get(pill, &RMF_OBD_QUOTACTL);
        LASSERT(repoqc != NULL);

        mq->mq_exp = exp;
        switch (oqctl->qc_cmd) {
        case Q_QUOTAON:
                rc = mqo->mqo_on(info->mti_env, next, oqctl->qc_type);
                break;
        case Q_QUOTAOFF:
                rc = mqo->mqo_off(info->mti_env, next, oqctl->qc_type);
                break;
        case Q_SETINFO:
                rc = mqo->mqo_setinfo(info->mti_env, next, oqctl->qc_type, id,
                                      &oqctl->qc_dqinfo);
                break;
        case Q_GETINFO:
                rc = mqo->mqo_getinfo(info->mti_env, next, oqctl->qc_type, id,
                                      &oqctl->qc_dqinfo);
                break;
        case Q_SETQUOTA:
                rc = mqo->mqo_setquota(info->mti_env, next, oqctl->qc_type, id,
                                       &oqctl->qc_dqblk);
                break;
        case Q_GETQUOTA:
                rc = mqo->mqo_getquota(info->mti_env, next, oqctl->qc_type, id,
                                       &oqctl->qc_dqblk);
                break;
        case Q_GETOINFO:
                rc = mqo->mqo_getoinfo(info->mti_env, next, oqctl->qc_type, id,
                                       &oqctl->qc_dqinfo);
                break;
        case Q_GETOQUOTA:
                rc = mqo->mqo_getoquota(info->mti_env, next, oqctl->qc_type, id,
                                        &oqctl->qc_dqblk);
                break;
        case LUSTRE_Q_INVALIDATE:
                rc = mqo->mqo_invalidate(info->mti_env, next, oqctl->qc_type);
                break;
        case LUSTRE_Q_FINVALIDATE:
                rc = mqo->mqo_finvalidate(info->mti_env, next, oqctl->qc_type);
                break;
        default:
                CERROR("unsupported mdt_quotactl command: %d\n",
                       oqctl->qc_cmd);
                RETURN(-EFAULT);
        }

        *repoqc = *oqctl;
        RETURN(rc);
}
#endif


/*
 * OBD PING and other handlers.
 */
static int mdt_obd_ping(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;

        req_capsule_set(info->mti_pill, &RQF_OBD_PING);

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
 * LLOG handlers.
 */

/** clone llog ctxt from child (mdd)
 * This allows remote llog (replicator) access.
 * We can either pass all llog RPCs (eg mdt_llog_create) on to child where the
 * context was originally set up, or we can handle them directly.
 * I choose the latter, but that means I need any llog
 * contexts set up by child to be accessable by the mdt.  So we clone the
 * context into our context list here.
 */
static int mdt_llog_ctxt_clone(const struct lu_env *env, struct mdt_device *mdt,
                               int idx)
{
        struct md_device  *next = mdt->mdt_child;
        struct llog_ctxt *ctxt;
        int rc;

        if (!llog_ctxt_null(mdt2obd_dev(mdt), idx))
                return 0;

        rc = next->md_ops->mdo_llog_ctxt_get(env, next, idx, (void **)&ctxt);
        if (rc || ctxt == NULL) {
                CERROR("Can't get mdd ctxt %d\n", rc);
                return rc;
        }

        rc = llog_group_set_ctxt(&mdt2obd_dev(mdt)->obd_olg, ctxt, idx);
        if (rc)
                CERROR("Can't set mdt ctxt %d\n", rc);

        return rc;
}

static int mdt_llog_ctxt_unclone(const struct lu_env *env,
                                 struct mdt_device *mdt, int idx)
{
        struct llog_ctxt *ctxt;

        ctxt = llog_get_context(mdt2obd_dev(mdt), idx);
        if (ctxt == NULL)
                return 0;
        /* Put once for the get we just did, and once for the clone */
        llog_ctxt_put(ctxt);
        llog_ctxt_put(ctxt);
        return 0;
}

static int mdt_llog_create(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_CREATE);
        rc = llog_origin_handle_create(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

static int mdt_llog_destroy(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_DESTROY);
        rc = llog_origin_handle_destroy(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

static int mdt_llog_read_header(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_READ_HEADER);
        rc = llog_origin_handle_read_header(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

static int mdt_llog_next_block(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_NEXT_BLOCK);
        rc = llog_origin_handle_next_block(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
}

static int mdt_llog_prev_block(struct mdt_thread_info *info)
{
        int rc;

        req_capsule_set(info->mti_pill, &RQF_LLOG_ORIGIN_HANDLE_PREV_BLOCK);
        rc = llog_origin_handle_prev_block(mdt_info_req(info));
        return (rc < 0 ? err_serious(rc) : rc);
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
        int rc;

        rc = mdt_handle_idmap(info);

        if (unlikely(rc)) {
                struct ptlrpc_request *req = mdt_info_req(info);
                __u32                  opc;

                opc = lustre_msg_get_opc(req->rq_reqmsg);
                if (opc == SEC_CTX_INIT || opc == SEC_CTX_INIT_CONT)
                        sptlrpc_svc_ctx_invalidate(req);
        }

        CFS_FAIL_TIMEOUT(OBD_FAIL_SEC_CTX_HDL_PAUSE, cfs_fail_val);

        return rc;
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

        CDEBUG(D_INFO, "Find object for "DFID"\n", PFID(f));
        o = lu_object_find(env, &d->mdt_md_dev.md_lu_dev, f, NULL);
        if (unlikely(IS_ERR(o)))
                m = (struct mdt_object *)o;
        else
                m = mdt_obj(o);
        RETURN(m);
}

/**
 * Asyncronous commit for mdt device.
 *
 * Pass asynchonous commit call down the MDS stack.
 *
 * \param env environment
 * \param mdt the mdt device
 */
static void mdt_device_commit_async(const struct lu_env *env,
                                    struct mdt_device *mdt)
{
        struct dt_device *dt = mdt->mdt_bottom;
        int rc;

        rc = dt->dd_ops->dt_commit_async(env, dt);
        if (unlikely(rc != 0))
                CWARN("async commit start failed with rc = %d", rc);
}

/**
 * Mark the lock as "synchonous".
 *
 * Mark the lock to deffer transaction commit to the unlock time.
 *
 * \param lock the lock to mark as "synchonous"
 *
 * \see mdt_is_lock_sync
 * \see mdt_save_lock
 */
static inline void mdt_set_lock_sync(struct ldlm_lock *lock)
{
        lock->l_ast_data = (void*)1;
}

/**
 * Check whehter the lock "synchonous" or not.
 *
 * \param lock the lock to check
 * \retval 1 the lock is "synchonous"
 * \retval 0 the lock isn't "synchronous"
 *
 * \see mdt_set_lock_sync
 * \see mdt_save_lock
 */
static inline int mdt_is_lock_sync(struct ldlm_lock *lock)
{
        return lock->l_ast_data != NULL;
}

/**
 * Blocking AST for mdt locks.
 *
 * Starts transaction commit if in case of COS lock conflict or
 * deffers such a commit to the mdt_save_lock.
 *
 * \param lock the lock which blocks a request or cancelling lock
 * \param desc unused
 * \param data unused
 * \param flag indicates whether this cancelling or blocking callback
 * \retval 0
 * \see ldlm_blocking_ast_nocheck
 */
int mdt_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, int flag)
{
        struct obd_device *obd = ldlm_lock_to_ns(lock)->ns_obd;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        int rc;
        ENTRY;

        if (flag == LDLM_CB_CANCELING)
                RETURN(0);
        lock_res_and_lock(lock);
        if (lock->l_blocking_ast != mdt_blocking_ast) {
                unlock_res_and_lock(lock);
                RETURN(0);
        }
        if (mdt_cos_is_enabled(mdt) &&
            lock->l_req_mode & (LCK_PW | LCK_EX) &&
            lock->l_blocking_lock != NULL &&
            lock->l_client_cookie != lock->l_blocking_lock->l_client_cookie) {
                mdt_set_lock_sync(lock);
        }
        rc = ldlm_blocking_ast_nocheck(lock);

        /* There is no lock conflict if l_blocking_lock == NULL,
         * it indicates a blocking ast sent from ldlm_lock_decref_internal
         * when the last reference to a local lock was released */
        if (lock->l_req_mode == LCK_COS && lock->l_blocking_lock != NULL) {
                struct lu_env env;

                rc = lu_env_init(&env, LCT_MD_THREAD);
                if (unlikely(rc != 0))
                        CWARN("lu_env initialization failed with rc = %d,"
                              "cannot start asynchronous commit\n", rc);
                else
                        mdt_device_commit_async(&env, mdt);
                lu_env_fini(&env);
        }
        RETURN(rc);
}

int mdt_object_lock(struct mdt_thread_info *info, struct mdt_object *o,
                    struct mdt_lock_handle *lh, __u64 ibits, int locality)
{
        struct ldlm_namespace *ns = info->mti_mdt->mdt_namespace;
        ldlm_policy_data_t *policy = &info->mti_policy;
        struct ldlm_res_id *res_id = &info->mti_res_id;
        int rc;
        ENTRY;

        LASSERT(!lustre_handle_is_used(&lh->mlh_reg_lh));
        LASSERT(!lustre_handle_is_used(&lh->mlh_pdo_lh));
        LASSERT(lh->mlh_reg_mode != LCK_MINMODE);
        LASSERT(lh->mlh_type != MDT_NUL_LOCK);

        if (mdt_object_exists(o) < 0) {
                if (locality == MDT_CROSS_LOCK) {
                        /* cross-ref object fix */
                        ibits &= ~MDS_INODELOCK_UPDATE;
                        ibits |= MDS_INODELOCK_LOOKUP;
                } else {
                        LASSERT(!(ibits & MDS_INODELOCK_UPDATE));
                        LASSERT(ibits & MDS_INODELOCK_LOOKUP);
                }
                /* No PDO lock on remote object */
                LASSERT(lh->mlh_type != MDT_PDO_LOCK);
        }

        if (lh->mlh_type == MDT_PDO_LOCK) {
                /* check for exists after object is locked */
                if (mdt_object_exists(o) == 0) {
                        /* Non-existent object shouldn't have PDO lock */
                        RETURN(-ESTALE);
                } else {
                        /* Non-dir object shouldn't have PDO lock */
                        if (!S_ISDIR(lu_object_attr(&o->mot_obj.mo_lu)))
                                RETURN(-ENOTDIR);
                }
        }

        memset(policy, 0, sizeof(*policy));
        fid_build_reg_res_name(mdt_object_fid(o), res_id);

        /*
         * Take PDO lock on whole directory and build correct @res_id for lock
         * on part of directory.
         */
        if (lh->mlh_pdo_hash != 0) {
                LASSERT(lh->mlh_type == MDT_PDO_LOCK);
                mdt_lock_pdo_mode(info, o, lh);
                if (lh->mlh_pdo_mode != LCK_NL) {
                        /*
                         * Do not use LDLM_FL_LOCAL_ONLY for parallel lock, it
                         * is never going to be sent to client and we do not
                         * want it slowed down due to possible cancels.
                         */
                        policy->l_inodebits.bits = MDS_INODELOCK_UPDATE;
                        rc = mdt_fid_lock(ns, &lh->mlh_pdo_lh, lh->mlh_pdo_mode,
                                          policy, res_id, LDLM_FL_ATOMIC_CB,
                                          &info->mti_exp->exp_handle.h_cookie);
                        if (unlikely(rc))
                                RETURN(rc);
                }

                /*
                 * Finish res_id initializing by name hash marking part of
                 * directory which is taking modification.
                 */
                res_id->name[LUSTRE_RES_ID_HSH_OFF] = lh->mlh_pdo_hash;
        }

        policy->l_inodebits.bits = ibits;

        /*
         * Use LDLM_FL_LOCAL_ONLY for this lock. We do not know yet if it is
         * going to be sent to client. If it is - mdt_intent_policy() path will
         * fix it up and turn FL_LOCAL flag off.
         */
        rc = mdt_fid_lock(ns, &lh->mlh_reg_lh, lh->mlh_reg_mode, policy,
                          res_id, LDLM_FL_LOCAL_ONLY | LDLM_FL_ATOMIC_CB,
                          &info->mti_exp->exp_handle.h_cookie);
        if (rc)
                mdt_object_unlock(info, o, lh, 1);
        else if (unlikely(OBD_FAIL_PRECHECK(OBD_FAIL_MDS_PDO_LOCK)) &&
                 lh->mlh_pdo_hash != 0 &&
                 (lh->mlh_reg_mode == LCK_PW || lh->mlh_reg_mode == LCK_EX)) {
                OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_PDO_LOCK, 10);
        }

        RETURN(rc);
}

/**
 * Save a lock within request object.
 *
 * Keep the lock referenced until whether client ACK or transaction
 * commit happens or release the lock immediately depending on input
 * parameters. If COS is ON, a write lock is converted to COS lock
 * before saving.
 *
 * \param info thead info object
 * \param h lock handle
 * \param mode lock mode
 * \param decref force immediate lock releasing
 */
static
void mdt_save_lock(struct mdt_thread_info *info, struct lustre_handle *h,
                   ldlm_mode_t mode, int decref)
{
        ENTRY;

        if (lustre_handle_is_used(h)) {
                if (decref || !info->mti_has_trans ||
                    !(mode & (LCK_PW | LCK_EX))){
                        mdt_fid_unlock(h, mode);
                } else {
                        struct mdt_device *mdt = info->mti_mdt;
                        struct ldlm_lock *lock = ldlm_handle2lock(h);
                        struct ptlrpc_request *req = mdt_info_req(info);
                        int no_ack = 0;

                        LASSERTF(lock != NULL, "no lock for cookie "LPX64"\n",
                                 h->cookie);
                        CDEBUG(D_HA, "request = %p reply state = %p"
                               " transno = "LPD64"\n",
                               req, req->rq_reply_state, req->rq_transno);
                        if (mdt_cos_is_enabled(mdt)) {
                                no_ack = 1;
                                ldlm_lock_downgrade(lock, LCK_COS);
                                mode = LCK_COS;
                        }
                        ptlrpc_save_lock(req, h, mode, no_ack);
                        if (mdt_is_lock_sync(lock)) {
                                CDEBUG(D_HA, "found sync-lock,"
                                       " async commit started\n");
                                mdt_device_commit_async(info->mti_env,
                                                        mdt);
                        }
                        LDLM_LOCK_PUT(lock);
                }
                h->cookie = 0ull;
        }

        EXIT;
}

/**
 * Unlock mdt object.
 *
 * Immeditely release the regular lock and the PDO lock or save the
 * lock in reqeuest and keep them referenced until client ACK or
 * transaction commit.
 *
 * \param info thread info object
 * \param o mdt object
 * \param lh mdt lock handle referencing regular and PDO locks
 * \param decref force immediate lock releasing
 */
void mdt_object_unlock(struct mdt_thread_info *info, struct mdt_object *o,
                       struct mdt_lock_handle *lh, int decref)
{
        ENTRY;

        mdt_save_lock(info, &lh->mlh_pdo_lh, lh->mlh_pdo_mode, decref);
        mdt_save_lock(info, &lh->mlh_reg_lh, lh->mlh_reg_mode, decref);

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

                rc = mdt_object_lock(info, o, lh, ibits,
                                     MDT_LOCAL_LOCK);
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
                        if (likely(h->mh_opc != 0))
                                LASSERTF(h->mh_opc == opc,
                                         "opcode mismatch %d != %d\n",
                                         h->mh_opc, opc);
                        else
                                h = NULL; /* unsupported opc */
                        break;
                }
        }
        return h;
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
        ENTRY;

        env = info->mti_env;
        pill = info->mti_pill;

        body = info->mti_body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body == NULL)
                RETURN(-EFAULT);

        if (!(body->valid & OBD_MD_FLID))
                RETURN(0);

        if (!fid_is_sane(&body->fid1)) {
                CERROR("Invalid fid: "DFID"\n", PFID(&body->fid1));
                RETURN(-EINVAL);
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

        RETURN(rc);
}

static int mdt_unpack_req_pack_rep(struct mdt_thread_info *info, __u32 flags)
{
        struct req_capsule *pill = info->mti_pill;
        int rc;
        ENTRY;

        if (req_capsule_has_field(pill, &RMF_MDT_BODY, RCL_CLIENT))
                rc = mdt_body_unpack(info, flags);
        else
                rc = 0;

        if (rc == 0 && (flags & HABEO_REFERO)) {
                struct mdt_device *mdt = info->mti_mdt;

                /* Pack reply. */

                if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
                                             mdt->mdt_max_mdsize);
                if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                        req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER,
                                             mdt->mdt_max_cookiesize);

                rc = req_capsule_server_pack(pill);
        }
        RETURN(rc);
}

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

        /*
         * Checking for various OBD_FAIL_$PREF_$OPC_NET codes. _Do_ not try
         * to put same checks into handlers like mdt_close(), mdt_reint(),
         * etc., without talking to mdt authors first. Checking same thing
         * there again is useless and returning 0 error without packing reply
         * is buggy! Handlers either pack reply or return error.
         *
         * We return 0 here and do not send any reply in order to emulate
         * network failure. Do not send any reply in case any of NET related
         * fail_id has occured.
         */
        if (OBD_FAIL_CHECK_ORSET(h->mh_fail_id, OBD_FAIL_ONCE))
                RETURN(0);

        rc = 0;
        flags = h->mh_flags;
        LASSERT(ergo(flags & (HABEO_CORPUS|HABEO_REFERO), h->mh_fmt != NULL));

        if (h->mh_fmt != NULL) {
                req_capsule_set(info->mti_pill, h->mh_fmt);
                rc = mdt_unpack_req_pack_rep(info, flags);
        }

        if (rc == 0 && flags & MUTABOR &&
            req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                /* should it be rq_status? */
                rc = -EROFS;

        if (rc == 0 && flags & HABEO_CLAVIS) {
                struct ldlm_request *dlm_req;

                LASSERT(h->mh_fmt != NULL);

                dlm_req = req_capsule_client_get(info->mti_pill, &RMF_DLM_REQ);
                if (dlm_req != NULL) {
                        if (unlikely(dlm_req->lock_desc.l_resource.lr_type ==
                                        LDLM_IBITS &&
                                     dlm_req->lock_desc.l_policy_data.\
                                        l_inodebits.bits == 0)) {
                                /*
                                 * Lock without inodebits makes no sense and
                                 * will oops later in ldlm. If client miss to
                                 * set such bits, do not trigger ASSERTION.
                                 *
                                 * For liblustre flock case, it maybe zero.
                                 */
                                rc = -EPROTO;
                        } else {
                                if (info->mti_mdt->mdt_opts.mo_compat_resname)
                                        rc = mdt_lock_resname_compat(
                                                                info->mti_mdt,
                                                                dlm_req);
                                info->mti_dlm_req = dlm_req;
                        }
                } else {
                        rc = -EFAULT;
                }
        }

        /* capability setting changed via /proc, needs reinitialize ctxt */
        if (info->mti_mdt && info->mti_mdt->mdt_capa_conf) {
                mdt_init_capa_ctxt(info->mti_env, info->mti_mdt);
                info->mti_mdt->mdt_capa_conf = 0;
        }

        if (likely(rc == 0)) {
                /*
                 * Process request, there can be two types of rc:
                 * 1) errors with msg unpack/pack, other failures outside the
                 * operation itself. This is counted as serious errors;
                 * 2) errors during fs operation, should be placed in rq_status
                 * only
                 */
                rc = h->mh_act(info);
                if (rc == 0 &&
                    !req->rq_no_reply && req->rq_reply_state == NULL) {
                        DEBUG_REQ(D_ERROR, req, "MDT \"handler\" %s did not "
                                  "pack reply and returned 0 error\n",
                                  h->mh_name);
                        LBUG();
                }
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

        if (rc == 0 && (flags & HABEO_CLAVIS) &&
            info->mti_mdt->mdt_opts.mo_compat_resname) {
                struct ldlm_reply *dlmrep;

                dlmrep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
                if (dlmrep != NULL)
                        rc = mdt_lock_reply_compat(info->mti_mdt, dlmrep);
        }

        /* If we're DISCONNECTing, the mdt_export_data is already freed */
        if (likely(rc == 0 && req->rq_export && h->mh_opc != MDS_DISCONNECT))
                target_committed_to_req(req);

        if (unlikely(req_is_replay(req) &&
                     lustre_msg_get_transno(req->rq_reqmsg) == 0)) {
                DEBUG_REQ(D_ERROR, req, "transno is 0 during REPLAY");
                LBUG();
        }

        target_send_reply(req, rc, info->mti_fail_id);
        RETURN(0);
}

void mdt_lock_handle_init(struct mdt_lock_handle *lh)
{
        lh->mlh_type = MDT_NUL_LOCK;
        lh->mlh_reg_lh.cookie = 0ull;
        lh->mlh_reg_mode = LCK_MINMODE;
        lh->mlh_pdo_lh.cookie = 0ull;
        lh->mlh_pdo_mode = LCK_MINMODE;
}

void mdt_lock_handle_fini(struct mdt_lock_handle *lh)
{
        LASSERT(!lustre_handle_is_used(&lh->mlh_reg_lh));
        LASSERT(!lustre_handle_is_used(&lh->mlh_pdo_lh));
}

/*
 * Initialize fields of struct mdt_thread_info. Other fields are left in
 * uninitialized state, because it's too expensive to zero out whole
 * mdt_thread_info (> 1K) on each request arrival.
 */
static void mdt_thread_info_init(struct ptlrpc_request *req,
                                 struct mdt_thread_info *info)
{
        int i;
        struct md_capainfo *ci;

        req_capsule_init(&req->rq_pill, req, RCL_SERVER);
        info->mti_pill = &req->rq_pill;

        /* lock handle */
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_init(&info->mti_lh[i]);

        /* mdt device: it can be NULL while CONNECT */
        if (req->rq_export) {
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
                info->mti_exp = req->rq_export;
        } else
                info->mti_mdt = NULL;
        info->mti_env = req->rq_svc_thread->t_env;
        ci = md_capainfo(info->mti_env);
        memset(ci, 0, sizeof *ci);
        if (req->rq_export) {
                if (exp_connect_rmtclient(req->rq_export))
                        ci->mc_auth = LC_ID_CONVERT;
                else if (req->rq_export->exp_connect_flags &
                         OBD_CONNECT_MDS_CAPA)
                        ci->mc_auth = LC_ID_PLAIN;
                else
                        ci->mc_auth = LC_ID_NONE;
        }

        info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
        info->mti_transno = lustre_msg_get_transno(req->rq_reqmsg);
        info->mti_mos = NULL;

        memset(&info->mti_attr, 0, sizeof(info->mti_attr));
        info->mti_body = NULL;
        info->mti_object = NULL;
        info->mti_dlm_req = NULL;
        info->mti_has_trans = 0;
        info->mti_no_need_trans = 0;
        info->mti_cross_ref = 0;
        info->mti_opdata = 0;

        /* To not check for split by default. */
        info->mti_spec.sp_ck_split = 0;
        info->mti_spec.no_create = 0;
}

static void mdt_thread_info_fini(struct mdt_thread_info *info)
{
        int i;

        req_capsule_fini(info->mti_pill);
        if (info->mti_object != NULL) {
                /*
                 * freeing an object may lead to OSD level transaction, do not
                 * let it mess with MDT. bz19385.
                 */
                info->mti_no_need_trans = 1;
                mdt_object_put(info->mti_env, info->mti_object);
                info->mti_object = NULL;
        }
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_fini(&info->mti_lh[i]);
        info->mti_env = NULL;
}

static int mdt_filter_recovery_request(struct ptlrpc_request *req,
                                       struct obd_device *obd, int *process)
{
        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT: /* This will never get here, but for completeness. */
        case OST_CONNECT: /* This will never get here, but for completeness. */
        case MDS_DISCONNECT:
        case OST_DISCONNECT:
               *process = 1;
               RETURN(0);

        case MDS_CLOSE:
        case MDS_DONE_WRITING:
        case MDS_SYNC: /* used in unmounting */
        case OBD_PING:
        case MDS_REINT:
        case SEQ_QUERY:
        case FLD_QUERY:
        case LDLM_ENQUEUE:
                *process = target_queue_recovery_request(req, obd);
                RETURN(0);

        default:
                DEBUG_REQ(D_ERROR, req, "not permitted during recovery");
                *process = -EAGAIN;
                RETURN(0);
        }
}

/*
 * Handle recovery. Return:
 *        +1: continue request processing;
 *       -ve: abort immediately with the given error code;
 *         0: send reply with error code in req->rq_status;
 */
static int mdt_recovery(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        struct obd_device *obd;

        ENTRY;

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                {
#if 0
                        int rc;

                        rc = mdt_handle_idmap(info);
                        if (rc)
                                RETURN(rc);
                        else
#endif
                                RETURN(+1);
                }
        }

        if (unlikely(!class_connected_export(req->rq_export))) {
                CERROR("operation %d on unconnected MDS from %s\n",
                       lustre_msg_get_opc(req->rq_reqmsg),
                       libcfs_id2str(req->rq_peer));
                /* FIXME: For CMD cleanup, when mds_B stop, the req from
                 * mds_A will get -ENOTCONN(especially for ping req),
                 * which will cause that mds_A deactive timeout, then when
                 * mds_A cleanup, the cleanup process will be suspended since
                 * deactive timeout is not zero.
                 */
                req->rq_status = -ENOTCONN;
                target_send_reply(req, -ENOTCONN, info->mti_fail_id);
                RETURN(0);
        }

        /* sanity check: if the xid matches, the request must be marked as a
         * resent or replayed */
        if (req_xid_is_last(req)) {
                if (!(lustre_msg_get_flags(req->rq_reqmsg) &
                      (MSG_RESENT | MSG_REPLAY))) {
                        DEBUG_REQ(D_WARNING, req, "rq_xid "LPU64" matches last_xid, "
                                  "expected REPLAY or RESENT flag (%x)", req->rq_xid,
                                  lustre_msg_get_flags(req->rq_reqmsg));
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
        if (unlikely(obd->obd_recovering)) {
                int rc;
                int should_process;
                DEBUG_REQ(D_INFO, req, "Got new replay");
                rc = mdt_filter_recovery_request(req, obd, &should_process);
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

static int mdt_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        switch (lustre_msg_get_opc(msg)) {
        case MDS_CONNECT:
        case MDS_DISCONNECT:
        case OBD_PING:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_OBD_VERSION);
                break;
        case MDS_GETSTATUS:
        case MDS_GETATTR:
        case MDS_GETATTR_NAME:
        case MDS_STATFS:
        case MDS_READPAGE:
        case MDS_WRITEPAGE:
        case MDS_IS_SUBDIR:
        case MDS_REINT:
        case MDS_CLOSE:
        case MDS_DONE_WRITING:
        case MDS_PIN:
        case MDS_SYNC:
        case MDS_GETXATTR:
        case MDS_SETXATTR:
        case MDS_SET_INFO:
        case MDS_GET_INFO:
        case MDS_QUOTACHECK:
        case MDS_QUOTACTL:
        case QUOTA_DQACQ:
        case QUOTA_DQREL:
        case SEQ_QUERY:
        case FLD_QUERY:
                rc = lustre_msg_check_version(msg, LUSTRE_MDS_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_MDS_VERSION);
                break;
        case LDLM_ENQUEUE:
        case LDLM_CONVERT:
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                rc = lustre_msg_check_version(msg, LUSTRE_DLM_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_DLM_VERSION);
                break;
        case OBD_LOG_CANCEL:
        case LLOG_ORIGIN_HANDLE_CREATE:
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
        case LLOG_ORIGIN_HANDLE_CLOSE:
        case LLOG_ORIGIN_HANDLE_DESTROY:
        case LLOG_ORIGIN_HANDLE_PREV_BLOCK:
        case LLOG_CATINFO:
                rc = lustre_msg_check_version(msg, LUSTRE_LOG_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               lustre_msg_get_opc(msg),
                               lustre_msg_get_version(msg),
                               LUSTRE_LOG_VERSION);
                break;
        default:
                CERROR("MDS unknown opcode %d\n", lustre_msg_get_opc(msg));
                rc = -ENOTSUPP;
        }
        return rc;
}

static int mdt_handle0(struct ptlrpc_request *req,
                       struct mdt_thread_info *info,
                       struct mdt_opc_slice *supported)
{
        struct mdt_handler *h;
        struct lustre_msg  *msg;
        int                 rc;

        ENTRY;

        if (OBD_FAIL_CHECK_ORSET(OBD_FAIL_MDS_ALL_REQUEST_NET, OBD_FAIL_ONCE))
                RETURN(0);

        LASSERT(current->journal_info == NULL);

        msg = req->rq_reqmsg;
        rc = mdt_msg_check_version(msg);
        if (likely(rc == 0)) {
                rc = mdt_recovery(info);
                if (likely(rc == +1)) {
                        h = mdt_handler_find(lustre_msg_get_opc(msg),
                                             supported);
                        if (likely(h != NULL)) {
                                rc = mdt_req_handle(info, h, req);
                        } else {
                                CERROR("The unsupported opc: 0x%x\n",
                                       lustre_msg_get_opc(msg) );
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

static int mdt_xmds_handle(struct ptlrpc_request *req)
{
        return mdt_handle_common(req, mdt_xmds_handlers);
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
                .it_act   = NULL,
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
                new_lock = ldlm_handle2lock_long(&lh->mlh_reg_lh, 0);

        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY)) {
                lh->mlh_reg_lh.cookie = 0;
                RETURN(0);
        }

        LASSERTF(new_lock != NULL,
                 "lockh "LPX64"\n", lh->mlh_reg_lh.cookie);

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
                lh->mlh_reg_lh.cookie = 0;
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /*
         * Fixup the lock to be given to the client.
         */
        lock_res_and_lock(new_lock);
        /* Zero new_lock->l_readers and new_lock->l_writers without triggering
         * possible blocking AST. */
        while (new_lock->l_readers > 0) {
                lu_ref_del(&new_lock->l_reference, "reader", new_lock);
                lu_ref_del(&new_lock->l_reference, "user", new_lock);
                new_lock->l_readers--;
        }
        while (new_lock->l_writers > 0) {
                lu_ref_del(&new_lock->l_reference, "writer", new_lock);
                lu_ref_del(&new_lock->l_reference, "user", new_lock);
                new_lock->l_writers--;
        }

        new_lock->l_export = class_export_lock_get(req->rq_export, new_lock);
        new_lock->l_blocking_ast = lock->l_blocking_ast;
        new_lock->l_completion_ast = lock->l_completion_ast;
        new_lock->l_remote_handle = lock->l_remote_handle;
        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        unlock_res_and_lock(new_lock);

        cfs_hash_add(new_lock->l_export->exp_lock_hash,
                     &new_lock->l_remote_handle,
                     &new_lock->l_exp_hash);

        LDLM_LOCK_RELEASE(new_lock);
        lh->mlh_reg_lh.cookie = 0;

        RETURN(ELDLM_LOCK_REPLACED);
}

static void mdt_intent_fixup_resent(struct mdt_thread_info *info,
                                    struct ldlm_lock *new_lock,
                                    struct ldlm_lock **old_lock,
                                    struct mdt_lock_handle *lh)
{
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct obd_export      *exp = req->rq_export;
        struct lustre_handle    remote_hdl;
        struct ldlm_request    *dlmreq;
        struct ldlm_lock       *lock;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
                return;

        dlmreq = req_capsule_client_get(info->mti_pill, &RMF_DLM_REQ);
        remote_hdl = dlmreq->lock_handle[0];

        lock = cfs_hash_lookup(exp->exp_lock_hash, &remote_hdl);
        if (lock) {
                if (lock != new_lock) {
                        lh->mlh_reg_lh.cookie = lock->l_handle.h_cookie;
                        lh->mlh_reg_mode = lock->l_granted_mode;

                        LDLM_DEBUG(lock, "Restoring lock cookie");
                        DEBUG_REQ(D_DLMTRACE, req,
                                  "restoring lock cookie "LPX64,
                                  lh->mlh_reg_lh.cookie);
                        if (old_lock)
                                *old_lock = LDLM_LOCK_GET(lock);
                        cfs_hash_put(exp->exp_lock_hash, &lock->l_exp_hash);
                        return;
                }

                cfs_hash_put(exp->exp_lock_hash, &lock->l_exp_hash);
        }

        /*
         * If the xid matches, then we know this is a resent request, and allow
         * it. (It's probably an OPEN, for which we don't send a lock.
         */
        if (req_xid_is_last(req))
                return;

        /*
         * This remote handle isn't enqueued, so we never received or processed
         * this request.  Clear MSG_RESENT, because it can be handled like any
         * normal request now.
         */
        lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);

        DEBUG_REQ(D_DLMTRACE, req, "no existing lock with rhandle "LPX64,
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
        struct mdt_body        *repbody;
        int                     rc;
        ENTRY;

        reqbody = req_capsule_client_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(reqbody);

        repbody = req_capsule_server_get(info->mti_pill, &RMF_MDT_BODY);
        LASSERT(repbody);

        info->mti_spec.sp_ck_split = !!(reqbody->valid & OBD_MD_FLCKSPLIT);
        info->mti_cross_ref = !!(reqbody->valid & OBD_MD_FLCROSSREF);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        switch (opcode) {
        case MDT_IT_LOOKUP:
                child_bits = MDS_INODELOCK_LOOKUP;
                break;
        case MDT_IT_GETATTR:
                child_bits = MDS_INODELOCK_LOOKUP | MDS_INODELOCK_UPDATE;
                break;
        default:
                CERROR("Unhandled till now");
                GOTO(out_shrink, rc = -EINVAL);
        }

        rc = mdt_init_ucred(info, reqbody);
        if (rc)
                GOTO(out_shrink, rc);

        req = info->mti_pill->rc_req;
        ldlm_rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
        mdt_set_disposition(info, ldlm_rep, DISP_IT_EXECD);

        /* Get lock from request for possible resent case. */
        mdt_intent_fixup_resent(info, *lockp, &new_lock, lhc);

        ldlm_rep->lock_policy_res2 =
                mdt_getattr_name_lock(info, lhc, child_bits, ldlm_rep);

        if (mdt_get_disposition(ldlm_rep, DISP_LOOKUP_NEG))
                ldlm_rep->lock_policy_res2 = 0;
        if (!mdt_get_disposition(ldlm_rep, DISP_LOOKUP_POS) ||
            ldlm_rep->lock_policy_res2) {
                lhc->mlh_reg_lh.cookie = 0ull;
                GOTO(out_ucred, rc = ELDLM_LOCK_ABORTED);
        }

        rc = mdt_intent_lock_replace(info, lockp, new_lock, lhc, flags);
        EXIT;
out_ucred:
        mdt_exit_ucred(info);
out_shrink:
        mdt_shrink_reply(info);
        return rc;
}

static int mdt_intent_reint(enum mdt_it_code opcode,
                            struct mdt_thread_info *info,
                            struct ldlm_lock **lockp,
                            int flags)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_RMT];
        struct ldlm_reply      *rep = NULL;
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
        mdt_intent_fixup_resent(info, *lockp, NULL, lhc);

        rc = mdt_reint_internal(info, lhc, opc);

        /* Check whether the reply has been packed successfully. */
        if (mdt_info_req(info)->rq_repmsg != NULL)
                rep = req_capsule_server_get(info->mti_pill, &RMF_DLM_REP);
        if (rep == NULL)
                RETURN(err_serious(-EFAULT));

        /* MDC expects this in any case */
        if (rc != 0)
                mdt_set_disposition(info, rep, DISP_LOOKUP_EXECD);

        /* Cross-ref case, the lock should be returned to the client */
        if (rc == -EREMOTE) {
                LASSERT(lustre_handle_is_used(&lhc->mlh_reg_lh));
                rep->lock_policy_res2 = 0;
                rc = mdt_intent_lock_replace(info, lockp, NULL, lhc, flags);
                RETURN(rc);
        }
        rep->lock_policy_res2 = clear_serious(rc);

        if (rc == -ENOTCONN || rc == -ENODEV ||
            rc == -EOVERFLOW) { /**< if VBR failure then return error */
                /*
                 * If it is the disconnect error (ENODEV & ENOCONN), the error
                 * will be returned by rq_status, and client at ptlrpc layer
                 * will detect this, then disconnect, reconnect the import
                 * immediately, instead of impacting the following the rpc.
                 */
                lhc->mlh_reg_lh.cookie = 0ull;
                RETURN(rc);
        } else {
                /*
                 * For other cases, the error will be returned by intent.
                 * and client will retrieve the result from intent.
                 */
                 /*
                  * FIXME: when open lock is finished, that should be
                  * checked here.
                  */
                if (lustre_handle_is_used(&lhc->mlh_reg_lh)) {
                        LASSERTF(rc == 0, "Error occurred but lock handle "
                                 "is still in use\n");
                        rep->lock_policy_res2 = 0;
                        rc = mdt_intent_lock_replace(info, lockp, NULL, lhc, flags);
                        RETURN(rc);
                } else {
                        lhc->mlh_reg_lh.cookie = 0ull;
                        RETURN(ELDLM_LOCK_ABORTED);
                }
        }
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

        pill = info->mti_pill;
        flv  = &mdt_it_flavor[opc];

        if (flv->it_fmt != NULL)
                req_capsule_extend(pill, flv->it_fmt);

        rc = mdt_unpack_req_pack_rep(info, flv->it_flags);
        if (rc == 0) {
                struct ptlrpc_request *req = mdt_info_req(info);
                if (flv->it_flags & MUTABOR &&
                    req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                        RETURN(-EROFS);
        }
        if (rc == 0 && flv->it_act != NULL) {
                /* execute policy */
                rc = flv->it_act(opc, info, lockp, flags);
        } else {
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
        int rc;

        ENTRY;

        LASSERT(req != NULL);

        info = lu_context_key_get(&req->rq_svc_thread->t_env->le_ctx,
                                  &mdt_thread_key);
        LASSERT(info != NULL);
        pill = info->mti_pill;
        LASSERT(pill->rc_req == req);

        if (req->rq_reqmsg->lm_bufcount > DLM_INTENT_IT_OFF) {
                req_capsule_extend(pill, &RQF_LDLM_INTENT);
                it = req_capsule_client_get(pill, &RMF_LDLM_INTENT);
                if (it != NULL) {
                        rc = mdt_intent_opc(it->opc, info, lockp, flags);
                        if (rc == 0)
                                rc = ELDLM_OK;

                        /* Lock without inodebits makes no sense and will oops
                         * later in ldlm. Let's check it now to see if we have
                         * ibits corrupted somewhere in mdt_intent_opc().
                         * The case for client miss to set ibits has been
                         * processed by others. */
                        LASSERT(ergo(info->mti_dlm_req->lock_desc.l_resource.\
                                        lr_type == LDLM_IBITS,
                                     info->mti_dlm_req->lock_desc.\
                                        l_policy_data.l_inodebits.bits != 0));
                } else
                        rc = err_serious(-EFAULT);
        } else {
                /* No intent was provided */
                LASSERT(pill->rc_fmt == &RQF_LDLM_ENQUEUE);
                rc = req_capsule_server_pack(pill);
                if (rc)
                        rc = err_serious(rc);
        }
        RETURN(rc);
}

static int mdt_seq_fini(const struct lu_env *env,
                        struct mdt_device *m)
{
        struct md_site *ms = mdt_md_site(m);
        ENTRY;

        if (ms != NULL) {
                if (ms->ms_server_seq) {
                        seq_server_fini(ms->ms_server_seq, env);
                        OBD_FREE_PTR(ms->ms_server_seq);
                        ms->ms_server_seq = NULL;
        }

                if (ms->ms_control_seq) {
                        seq_server_fini(ms->ms_control_seq, env);
                        OBD_FREE_PTR(ms->ms_control_seq);
                        ms->ms_control_seq = NULL;
        }

                if (ms->ms_client_seq) {
                        seq_client_fini(ms->ms_client_seq);
                        OBD_FREE_PTR(ms->ms_client_seq);
                        ms->ms_client_seq = NULL;
                }
        }

        RETURN(0);
}

static int mdt_seq_init(const struct lu_env *env,
                        const char *uuid,
                        struct mdt_device *m)
{
        struct md_site *ms;
        char *prefix;
        int rc;
        ENTRY;

        ms = mdt_md_site(m);

        /*
         * This is sequence-controller node. Init seq-controller server on local
         * MDT.
         */
        if (ms->ms_node_id == 0) {
                LASSERT(ms->ms_control_seq == NULL);

                OBD_ALLOC_PTR(ms->ms_control_seq);
                if (ms->ms_control_seq == NULL)
                        RETURN(-ENOMEM);

                rc = seq_server_init(ms->ms_control_seq,
                                     m->mdt_bottom, uuid,
                                     LUSTRE_SEQ_CONTROLLER,
                                     ms,
                                     env);

                if (rc)
                        GOTO(out_seq_fini, rc);

                OBD_ALLOC_PTR(ms->ms_client_seq);
                if (ms->ms_client_seq == NULL)
                        GOTO(out_seq_fini, rc = -ENOMEM);

                OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
                if (prefix == NULL) {
                        OBD_FREE_PTR(ms->ms_client_seq);
                        GOTO(out_seq_fini, rc = -ENOMEM);
                }

                snprintf(prefix, MAX_OBD_NAME + 5, "ctl-%s",
                         uuid);

                /*
                 * Init seq-controller client after seq-controller server is
                 * ready. Pass ms->ms_control_seq to it for direct talking.
                 */
                rc = seq_client_init(ms->ms_client_seq, NULL,
                                     LUSTRE_SEQ_METADATA, prefix,
                                     ms->ms_control_seq);
                OBD_FREE(prefix, MAX_OBD_NAME + 5);

                if (rc)
                        GOTO(out_seq_fini, rc);
        }

        /* Init seq-server on local MDT */
        LASSERT(ms->ms_server_seq == NULL);

        OBD_ALLOC_PTR(ms->ms_server_seq);
        if (ms->ms_server_seq == NULL)
                GOTO(out_seq_fini, rc = -ENOMEM);

        rc = seq_server_init(ms->ms_server_seq,
                             m->mdt_bottom, uuid,
                             LUSTRE_SEQ_SERVER,
                             ms,
                             env);
        if (rc)
                GOTO(out_seq_fini, rc = -ENOMEM);

        /* Assign seq-controller client to local seq-server. */
        if (ms->ms_node_id == 0) {
                LASSERT(ms->ms_client_seq != NULL);

                rc = seq_server_set_cli(ms->ms_server_seq,
                                        ms->ms_client_seq,
                                        env);
        }

        EXIT;
out_seq_fini:
        if (rc)
                mdt_seq_fini(env, m);

        return rc;
}
/*
 * Init client sequence manager which is used by local MDS to talk to sequence
 * controller on remote node.
 */
static int mdt_seq_init_cli(const struct lu_env *env,
                            struct mdt_device *m,
                            struct lustre_cfg *cfg)
{
        struct md_site    *ms = mdt_md_site(m);
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
        if (index != 0 || ms->ms_client_seq)
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
                LASSERT(ms->ms_control_exp);
                OBD_ALLOC_PTR(ms->ms_client_seq);
                if (ms->ms_client_seq != NULL) {
                        char *prefix;

                        OBD_ALLOC(prefix, MAX_OBD_NAME + 5);
                        if (!prefix)
                                RETURN(-ENOMEM);

                        snprintf(prefix, MAX_OBD_NAME + 5, "ctl-%s",
                                 mdc->obd_name);

                        rc = seq_client_init(ms->ms_client_seq,
                                             ms->ms_control_exp,
                                             LUSTRE_SEQ_METADATA,
                                             prefix, NULL);
                        OBD_FREE(prefix, MAX_OBD_NAME + 5);
                } else
                        rc = -ENOMEM;

                if (rc)
                        RETURN(rc);

                LASSERT(ms->ms_server_seq != NULL);
                rc = seq_server_set_cli(ms->ms_server_seq, ms->ms_client_seq,
                                        env);
        }

        RETURN(rc);
}

static void mdt_seq_fini_cli(struct mdt_device *m)
{
        struct md_site *ms;

        ENTRY;

        ms = mdt_md_site(m);

        if (ms != NULL) {
                if (ms->ms_server_seq)
                        seq_server_set_cli(ms->ms_server_seq,
                                   NULL, NULL);

                if (ms->ms_control_exp) {
                        class_export_put(ms->ms_control_exp);
                        ms->ms_control_exp = NULL;
                }
        }
        EXIT;
}

/*
 * FLD wrappers
 */
static int mdt_fld_fini(const struct lu_env *env,
                        struct mdt_device *m)
{
        struct md_site *ms = mdt_md_site(m);
        ENTRY;

        if (ms && ms->ms_server_fld) {
                fld_server_fini(ms->ms_server_fld, env);
                OBD_FREE_PTR(ms->ms_server_fld);
                ms->ms_server_fld = NULL;
        }

        RETURN(0);
}

static int mdt_fld_init(const struct lu_env *env,
                        const char *uuid,
                        struct mdt_device *m)
{
        struct md_site *ms;
        int rc;
        ENTRY;

        ms = mdt_md_site(m);

        OBD_ALLOC_PTR(ms->ms_server_fld);
        if (ms->ms_server_fld == NULL)
                RETURN(rc = -ENOMEM);

        rc = fld_server_init(ms->ms_server_fld,
                             m->mdt_bottom, uuid,
                             env, ms->ms_node_id);
        if (rc) {
                OBD_FREE_PTR(ms->ms_server_fld);
                ms->ms_server_fld = NULL;
                RETURN(rc);
        }

        RETURN(0);
}

/* device init/fini methods */
static void mdt_stop_ptlrpc_service(struct mdt_device *m)
{
        ENTRY;
        if (m->mdt_regular_service != NULL) {
                ptlrpc_unregister_service(m->mdt_regular_service);
                m->mdt_regular_service = NULL;
        }
        if (m->mdt_readpage_service != NULL) {
                ptlrpc_unregister_service(m->mdt_readpage_service);
                m->mdt_readpage_service = NULL;
        }
        if (m->mdt_xmds_service != NULL) {
                ptlrpc_unregister_service(m->mdt_xmds_service);
                m->mdt_xmds_service = NULL;
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
        EXIT;
}

static int mdt_start_ptlrpc_service(struct mdt_device *m)
{
        int rc;
        static struct ptlrpc_service_conf conf;
        cfs_proc_dir_entry_t *procfs_entry;
        ENTRY;

        procfs_entry = m->mdt_md_dev.md_lu_dev.ld_obd->obd_proc_entry;

        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = MDS_MAXREQSIZE,
                .psc_max_reply_size  = MDS_MAXREPSIZE,
                .psc_req_portal      = MDS_REQUEST_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                /*
                 * We'd like to have a mechanism to set this on a per-device
                 * basis, but alas...
                 */
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD
        };

        m->mdt_ldlm_client = &m->mdt_md_dev.md_lu_dev.ld_obd->obd_ldlm_client;
        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mdt_ldlm_client", m->mdt_ldlm_client);

        m->mdt_regular_service =
                ptlrpc_init_svc_conf(&conf, mdt_regular_handle, LUSTRE_MDT_NAME,
                                     procfs_entry, target_print_req,
                                     LUSTRE_MDT_NAME);
        if (m->mdt_regular_service == NULL)
                RETURN(-ENOMEM);

        rc = ptlrpc_start_threads(m->mdt_regular_service);
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * readpage service configuration. Parameters have to be adjusted,
         * ideally.
         */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = MDS_MAXREQSIZE,
                .psc_max_reply_size  = MDS_MAXREPSIZE,
                .psc_req_portal      = MDS_READPAGE_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD
        };
        m->mdt_readpage_service =
                ptlrpc_init_svc_conf(&conf, mdt_readpage_handle,
                                     LUSTRE_MDT_NAME "_readpage",
                                     procfs_entry, target_print_req,"mdt_rdpg");

        if (m->mdt_readpage_service == NULL) {
                CERROR("failed to start readpage service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_readpage_service);

        /*
         * setattr service configuration.
         */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = MDS_MAXREQSIZE,
                .psc_max_reply_size  = MDS_MAXREPSIZE,
                .psc_req_portal      = MDS_SETATTR_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD
        };

        m->mdt_setattr_service =
                ptlrpc_init_svc_conf(&conf, mdt_regular_handle,
                                     LUSTRE_MDT_NAME "_setattr",
                                     procfs_entry, target_print_req,"mdt_attr");

        if (!m->mdt_setattr_service) {
                CERROR("failed to start setattr service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_setattr_service);
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * sequence controller service configuration
         */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = SEQ_MAXREQSIZE,
                .psc_max_reply_size  = SEQ_MAXREPSIZE,
                .psc_req_portal      = SEQ_CONTROLLER_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD|LCT_DT_THREAD
        };

        m->mdt_mdsc_service =
                ptlrpc_init_svc_conf(&conf, mdt_mdsc_handle,
                                     LUSTRE_MDT_NAME"_mdsc",
                                     procfs_entry, target_print_req,"mdt_mdsc");
        if (!m->mdt_mdsc_service) {
                CERROR("failed to start seq controller service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_mdsc_service);
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * metadata sequence server service configuration
         */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = SEQ_MAXREQSIZE,
                .psc_max_reply_size  = SEQ_MAXREPSIZE,
                .psc_req_portal      = SEQ_METADATA_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD|LCT_DT_THREAD
        };

        m->mdt_mdss_service =
                ptlrpc_init_svc_conf(&conf, mdt_mdss_handle,
                                     LUSTRE_MDT_NAME"_mdss",
                                     procfs_entry, target_print_req,"mdt_mdss");
        if (!m->mdt_mdss_service) {
                CERROR("failed to start metadata seq server service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_mdss_service);
        if (rc)
                GOTO(err_mdt_svc, rc);


        /*
         * Data sequence server service configuration. We want to have really
         * cluster-wide sequences space. This is why we start only one sequence
         * controller which manages space.
         */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = SEQ_MAXREQSIZE,
                .psc_max_reply_size  = SEQ_MAXREPSIZE,
                .psc_req_portal      = SEQ_DATA_PORTAL,
                .psc_rep_portal      = OSC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD|LCT_DT_THREAD
        };

        m->mdt_dtss_service =
                ptlrpc_init_svc_conf(&conf, mdt_dtss_handle,
                                     LUSTRE_MDT_NAME"_dtss",
                                     procfs_entry, target_print_req,"mdt_dtss");
        if (!m->mdt_dtss_service) {
                CERROR("failed to start data seq server service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_dtss_service);
        if (rc)
                GOTO(err_mdt_svc, rc);

        /* FLD service start */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = FLD_MAXREQSIZE,
                .psc_max_reply_size  = FLD_MAXREPSIZE,
                .psc_req_portal      = FLD_REQUEST_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_DT_THREAD|LCT_MD_THREAD
        };

        m->mdt_fld_service =
                ptlrpc_init_svc_conf(&conf, mdt_fld_handle,
                                     LUSTRE_MDT_NAME"_fld",
                                     procfs_entry, target_print_req, "mdt_fld");
        if (!m->mdt_fld_service) {
                CERROR("failed to start fld service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_fld_service);
        if (rc)
                GOTO(err_mdt_svc, rc);

        /*
         * mds-mds service configuration. Separate portal is used to allow
         * mds-mds requests be not blocked during recovery.
         */
        conf = (typeof(conf)) {
                .psc_nbufs           = MDS_NBUFS,
                .psc_bufsize         = MDS_BUFSIZE,
                .psc_max_req_size    = MDS_MAXREQSIZE,
                .psc_max_reply_size  = MDS_MAXREPSIZE,
                .psc_req_portal      = MDS_MDS_PORTAL,
                .psc_rep_portal      = MDC_REPLY_PORTAL,
                .psc_watchdog_factor = MDT_SERVICE_WATCHDOG_FACTOR,
                .psc_min_threads     = mdt_min_threads,
                .psc_max_threads     = mdt_max_threads,
                .psc_ctx_tags        = LCT_MD_THREAD
        };
        m->mdt_xmds_service =
                ptlrpc_init_svc_conf(&conf, mdt_xmds_handle,
                                     LUSTRE_MDT_NAME "_mds",
                                     procfs_entry, target_print_req,"mdt_xmds");

        if (m->mdt_xmds_service == NULL) {
                CERROR("failed to start xmds service\n");
                GOTO(err_mdt_svc, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(m->mdt_xmds_service);
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
        struct obd_device       *obd = mdt2obd_dev(m);
        struct lustre_cfg_bufs  *bufs;
        struct lustre_cfg       *lcfg;
        struct mdt_thread_info  *info;
        char flags[3]="";
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        bufs = &info->mti_u.bufs;
        /* process cleanup, pass mdt obd name to get obd umount flags */
        lustre_cfg_bufs_reset(bufs, obd->obd_name);
        if (obd->obd_force)
                strcat(flags, "F");
        if (obd->obd_fail)
                strcat(flags, "A");
        lustre_cfg_bufs_set_string(bufs, 1, flags);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, bufs);
        if (!lcfg) {
                CERROR("Cannot alloc lcfg!\n");
                return;
        }

        LASSERT(top);
        top->ld_ops->ldo_process_config(env, top, lcfg);
        lustre_cfg_free(lcfg);

        lu_stack_fini(env, top);
        m->mdt_child = NULL;
        m->mdt_bottom = NULL;
}

static struct lu_device *mdt_layer_setup(struct lu_env *env,
                                         const char *typename,
                                         struct lu_device *child,
                                         struct lustre_cfg *cfg)
{
        const char            *dev = lustre_cfg_string(cfg, 0);
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

        rc = lu_env_refill((struct lu_env *)env);
        if (rc != 0) {
                CERROR("Failure to refill session: '%d'\n", rc);
                GOTO(out_type, rc);
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
        rc = ldt->ldt_ops->ldto_device_init(env, d, dev, child);
        if (rc) {
                CERROR("can't init device '%s', rc %d\n", typename, rc);
                GOTO(out_alloc, rc);
        }
        lu_device_get(d);
        lu_ref_add(&d->ld_reference, "lu-stack", &lu_site_init);

        RETURN(d);

out_alloc:
        ldt->ldt_ops->ldto_device_free(env, d);
        type->typ_refcnt--;
out_type:
        class_put_type(type);
out:
        return ERR_PTR(rc);
}

static int mdt_stack_init(struct lu_env *env,
                          struct mdt_device *m,
                          struct lustre_cfg *cfg,
                          struct lustre_mount_info  *lmi)
{
        struct lu_device  *d = &m->mdt_md_dev.md_lu_dev;
        struct lu_device  *tmp;
        struct md_device  *md;
        struct lu_device  *child_lu_dev;
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
        md_upcall_dev_set(md, lu2md_dev(d));

        md = lu2md_dev(d);
        /*set cmm upcall device*/
        md_upcall_dev_set(md, &m->mdt_md_dev);

        m->mdt_child = lu2md_dev(d);

        /* process setup config */
        tmp = &m->mdt_md_dev.md_lu_dev;
        rc = tmp->ld_ops->ldo_process_config(env, tmp, cfg);
        if (rc)
                GOTO(out, rc);

        /* initialize local objects */
        child_lu_dev = &m->mdt_child->md_lu_dev;

        rc = child_lu_dev->ld_ops->ldo_prepare(env,
                                               &m->mdt_md_dev.md_lu_dev,
                                               child_lu_dev);
out:
        /* fini from last known good lu_device */
        if (rc)
                mdt_stack_fini(env, m, d);

        return rc;
}

/**
 * setup CONFIG_ORIG context, used to access local config log.
 * this may need to be rewrite as part of llog rewrite for lu-api.
 */
static int mdt_obd_llog_setup(struct obd_device *obd,
                              struct lustre_sb_info *lsi)
{
        int     rc;

        LASSERT(obd->obd_fsops == NULL);

        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops))
                return PTR_ERR(obd->obd_fsops);

        rc = fsfilt_setup(obd, lsi->lsi_srv_mnt->mnt_sb);
        if (rc) {
                fsfilt_put_ops(obd->obd_fsops);
                return rc;
        }

        OBD_SET_CTXT_MAGIC(&obd->obd_lvfs_ctxt);
        obd->obd_lvfs_ctxt.pwdmnt = lsi->lsi_srv_mnt;
        obd->obd_lvfs_ctxt.pwd = lsi->lsi_srv_mnt->mnt_root;
        obd->obd_lvfs_ctxt.fs = get_ds();

        rc = llog_setup(obd, &obd->obd_olg, LLOG_CONFIG_ORIG_CTXT, obd,
                        0, NULL, &llog_lvfs_ops);
        if (rc) {
                CERROR("llog_setup() failed: %d\n", rc);
                fsfilt_put_ops(obd->obd_fsops);
        }

        return rc;
}

static void mdt_obd_llog_cleanup(struct obd_device *obd)
{
        struct llog_ctxt *ctxt;

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);

        if (obd->obd_fsops) {
                fsfilt_put_ops(obd->obd_fsops);
                obd->obd_fsops = NULL;
        }
}

static void mdt_fini(const struct lu_env *env, struct mdt_device *m)
{
        struct md_device  *next = m->mdt_child;
        struct lu_device  *d    = &m->mdt_md_dev.md_lu_dev;
        struct lu_site    *ls   = d->ld_site;
        struct obd_device *obd = mdt2obd_dev(m);
        ENTRY;

        target_recovery_fini(obd);

        ping_evictor_stop();

        mdt_stop_ptlrpc_service(m);
        mdt_llog_ctxt_unclone(env, m, LLOG_CHANGELOG_ORIG_CTXT);
        mdt_obd_llog_cleanup(obd);
        obd_exports_barrier(obd);
        obd_zombie_barrier();
#ifdef HAVE_QUOTA_SUPPORT
        next->md_ops->mdo_quota.mqo_cleanup(env, next);
#endif
        lut_fini(env, &m->mdt_lut);
        mdt_fs_cleanup(env, m);
        upcall_cache_cleanup(m->mdt_identity_cache);
        m->mdt_identity_cache = NULL;

        if (m->mdt_namespace != NULL) {
                ldlm_namespace_free(m->mdt_namespace, NULL,
                                    d->ld_obd->obd_force);
                d->ld_obd->obd_namespace = m->mdt_namespace = NULL;
        }

        cfs_free_nidlist(&m->mdt_nosquash_nids);
        if (m->mdt_nosquash_str) {
                OBD_FREE(m->mdt_nosquash_str, m->mdt_nosquash_strlen);
                m->mdt_nosquash_str = NULL;
                m->mdt_nosquash_strlen = 0;
        }

        mdt_seq_fini(env, m);
        mdt_seq_fini_cli(m);
        mdt_fld_fini(env, m);
        sptlrpc_rule_set_free(&m->mdt_sptlrpc_rset);

        next->md_ops->mdo_init_capa_ctxt(env, next, 0, 0, 0, NULL);
        cfs_timer_disarm(&m->mdt_ck_timer);
        mdt_ck_thread_stop(m);

        /*
         * Finish the stack
         */
        mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));

        lprocfs_free_per_client_stats(obd);
        lprocfs_free_obd_stats(obd);
        mdt_procfs_fini(m);

        if (ls) {
                struct md_site *mite;

                lu_site_fini(ls);
                mite = lu_site2md(ls);
                OBD_FREE_PTR(mite);
                d->ld_site = NULL;
        }
        LASSERT(cfs_atomic_read(&d->ld_ref) == 0);

        EXIT;
}

static int mdt_adapt_sptlrpc_conf(struct obd_device *obd, int initial)
{
        struct mdt_device       *m = mdt_dev(obd->obd_lu_dev);
        struct sptlrpc_rule_set  tmp_rset;
        int                      rc;

        sptlrpc_rule_set_init(&tmp_rset);
        rc = sptlrpc_conf_target_get_rules(obd, &tmp_rset, initial);
        if (rc) {
                CERROR("mdt %s: failed get sptlrpc rules: %d\n",
                       obd->obd_name, rc);
                return rc;
        }

        sptlrpc_target_update_exp_flavor(obd, &tmp_rset);

        cfs_write_lock(&m->mdt_sptlrpc_lock);
        sptlrpc_rule_set_free(&m->mdt_sptlrpc_rset);
        m->mdt_sptlrpc_rset = tmp_rset;
        cfs_write_unlock(&m->mdt_sptlrpc_lock);

        return 0;
}

static void fsoptions_to_mdt_flags(struct mdt_device *m, char *options)
{
        char *p = options;

        m->mdt_opts.mo_mds_capa = 1;
        m->mdt_opts.mo_oss_capa = 1;
#ifdef CONFIG_FS_POSIX_ACL
        /* ACLs should be enabled by default (b=13829) */
        m->mdt_opts.mo_acl = 1;
        LCONSOLE_INFO("Enabling ACL\n");
#else
        m->mdt_opts.mo_acl = 0;
        LCONSOLE_INFO("Disabling ACL\n");
#endif

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
                } else if ((len == sizeof("noacl") - 1) &&
                           (memcmp(options, "noacl", len) == 0)) {
                        m->mdt_opts.mo_acl = 0;
                        LCONSOLE_INFO("Disabling ACL\n");
                }

                if (!*p)
                        break;

                options = ++p;
        }
}

int mdt_postrecov(const struct lu_env *, struct mdt_device *);

static int mdt_init0(const struct lu_env *env, struct mdt_device *m,
                     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
        struct mdt_thread_info    *info;
        struct obd_device         *obd;
        const char                *dev = lustre_cfg_string(cfg, 0);
        const char                *num = lustre_cfg_string(cfg, 2);
        struct lustre_mount_info  *lmi = NULL;
        struct lustre_sb_info     *lsi;
        struct lustre_disk_data   *ldd;
        struct lu_site            *s;
        struct md_site            *mite;
        const char                *identity_upcall = "NONE";
#ifdef HAVE_QUOTA_SUPPORT
        struct md_device          *next;
#endif
        int                        rc;
        int                        node_id;
        ENTRY;

        md_device_init(&m->mdt_md_dev, ldt);
        /*
         * Environment (env) might be missing mdt_thread_key values at that
         * point, if device is allocated when mdt_thread_key is in QUIESCENT
         * mode.
         *
         * Usually device allocation path doesn't use module key values, but
         * mdt has to do a lot of work here, so allocate key value.
         */
        rc = lu_env_refill((struct lu_env *)env);
        if (rc != 0)
                RETURN(rc);

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        obd = class_name2obd(dev);
        LASSERT(obd != NULL);

        m->mdt_max_mdsize = MAX_MD_SIZE;
        m->mdt_max_cookiesize = sizeof(struct llog_cookie);
        m->mdt_som_conf = 0;

        m->mdt_opts.mo_user_xattr = 0;
        m->mdt_opts.mo_acl = 0;
        m->mdt_opts.mo_cos = MDT_COS_DEFAULT;
        lmi = server_get_mount_2(dev);
        if (lmi == NULL) {
                CERROR("Cannot get mount info for %s!\n", dev);
                RETURN(-EFAULT);
        } else {
                lsi = s2lsi(lmi->lmi_sb);
                fsoptions_to_mdt_flags(m, lsi->lsi_lmd->lmd_opts);
                /* CMD is supported only in IAM mode */
                ldd = lsi->lsi_ldd;
                LASSERT(num);
                node_id = simple_strtol(num, NULL, 10);
                if (!(ldd->ldd_flags & LDD_F_IAM_DIR) && node_id) {
                        CERROR("CMD Operation not allowed in IOP mode\n");
                        GOTO(err_lmi, rc = -EINVAL);
                }
                /* Read recovery timeouts */
                if (lsi->lsi_lmd && lsi->lsi_lmd->lmd_recovery_time_soft)
                        obd->obd_recovery_timeout =
                                lsi->lsi_lmd->lmd_recovery_time_soft;

                if (lsi->lsi_lmd && lsi->lsi_lmd->lmd_recovery_time_hard)
                        obd->obd_recovery_time_hard =
                                lsi->lsi_lmd->lmd_recovery_time_hard;
        }

        cfs_rwlock_init(&m->mdt_sptlrpc_lock);
        sptlrpc_rule_set_init(&m->mdt_sptlrpc_rset);

        cfs_spin_lock_init(&m->mdt_ioepoch_lock);
        m->mdt_opts.mo_compat_resname = 0;
        m->mdt_capa_timeout = CAPA_TIMEOUT;
        m->mdt_capa_alg = CAPA_HMAC_ALG_SHA1;
        m->mdt_ck_timeout = CAPA_KEY_TIMEOUT;
        m->mdt_squash_uid = 0;
        m->mdt_squash_gid = 0;
        CFS_INIT_LIST_HEAD(&m->mdt_nosquash_nids);
        m->mdt_nosquash_str = NULL;
        m->mdt_nosquash_strlen = 0;
        cfs_init_rwsem(&m->mdt_squash_sem);

        OBD_ALLOC_PTR(mite);
        if (mite == NULL)
                GOTO(err_lmi, rc = -ENOMEM);

        s = &mite->ms_lu;

        m->mdt_md_dev.md_lu_dev.ld_ops = &mdt_lu_ops;
        m->mdt_md_dev.md_lu_dev.ld_obd = obd;
        /* set this lu_device to obd, because error handling need it */
        obd->obd_lu_dev = &m->mdt_md_dev.md_lu_dev;

        rc = lu_site_init(s, &m->mdt_md_dev.md_lu_dev);
        if (rc) {
                CERROR("Can't init lu_site, rc %d\n", rc);
                GOTO(err_free_site, rc);
        }

        rc = mdt_procfs_init(m, dev);
        if (rc) {
                CERROR("Can't init MDT lprocfs, rc %d\n", rc);
                GOTO(err_fini_proc, rc);
        }

        /* set server index */
        lu_site2md(s)->ms_node_id = node_id;

        /* failover is the default
         * FIXME: we do not failout mds0/mgs, which may cause some problems.
         * assumed whose ms_node_id == 0 XXX
         * */
        obd->obd_replayable = 1;
        /* No connection accepted until configurations will finish */
        obd->obd_no_conn = 1;

        if (cfg->lcfg_bufcount > 4 && LUSTRE_CFG_BUFLEN(cfg, 4) > 0) {
                char *str = lustre_cfg_string(cfg, 4);
                if (strchr(str, 'n')) {
                        CWARN("%s: recovery disabled\n", obd->obd_name);
                        obd->obd_replayable = 0;
                }
        }

        /* init the stack */
        rc = mdt_stack_init((struct lu_env *)env, m, cfg, lmi);
        if (rc) {
                CERROR("Can't init device stack, rc %d\n", rc);
                GOTO(err_fini_proc, rc);
        }

        rc = lut_init(env, &m->mdt_lut, obd, m->mdt_bottom);
        if (rc)
                GOTO(err_fini_stack, rc);

        rc = mdt_fld_init(env, obd->obd_name, m);
        if (rc)
                GOTO(err_lut, rc);

        rc = mdt_seq_init(env, obd->obd_name, m);
        if (rc)
                GOTO(err_fini_fld, rc);

        snprintf(info->mti_u.ns_name, sizeof info->mti_u.ns_name,
                 LUSTRE_MDT_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(obd, info->mti_u.ns_name,
                                              LDLM_NAMESPACE_SERVER,
                                              LDLM_NAMESPACE_GREEDY,
                                              LDLM_NS_TYPE_MDT);
        if (m->mdt_namespace == NULL)
                GOTO(err_fini_seq, rc = -ENOMEM);

        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);
        /* set obd_namespace for compatibility with old code */
        obd->obd_namespace = m->mdt_namespace;

        /* XXX: to support suppgid for ACL, we enable identity_upcall
         * by default, otherwise, maybe got unexpected -EACCESS. */
        if (m->mdt_opts.mo_acl)
                identity_upcall = MDT_IDENTITY_UPCALL_PATH;

        m->mdt_identity_cache = upcall_cache_init(obd->obd_name, identity_upcall,
                                                  &mdt_identity_upcall_cache_ops);
        if (IS_ERR(m->mdt_identity_cache)) {
                rc = PTR_ERR(m->mdt_identity_cache);
                m->mdt_identity_cache = NULL;
                GOTO(err_free_ns, rc);
        }

        cfs_timer_init(&m->mdt_ck_timer, mdt_ck_timer_callback, m);

        rc = mdt_ck_thread_start(m);
        if (rc)
                GOTO(err_free_ns, rc);

        rc = mdt_fs_setup(env, m, obd, lsi);
        if (rc)
                GOTO(err_capa, rc);

        rc = mdt_obd_llog_setup(obd, lsi);
        if (rc)
                GOTO(err_fs_cleanup, rc);

        rc = mdt_llog_ctxt_clone(env, m, LLOG_CHANGELOG_ORIG_CTXT);
        if (rc)
                GOTO(err_llog_cleanup, rc);

        mdt_adapt_sptlrpc_conf(obd, 1);

#ifdef HAVE_QUOTA_SUPPORT
        next = m->mdt_child;
        rc = next->md_ops->mdo_quota.mqo_setup(env, next, lmi->lmi_mnt);
        if (rc)
                GOTO(err_llog_cleanup, rc);
#endif

        server_put_mount_2(dev, lmi->lmi_mnt);
        lmi = NULL;

        target_recovery_init(&m->mdt_lut, mdt_recovery_handle);

        rc = mdt_start_ptlrpc_service(m);
        if (rc)
                GOTO(err_recovery, rc);

        ping_evictor_start();

        rc = lu_site_init_finish(s);
        if (rc)
                GOTO(err_stop_service, rc);

        if (obd->obd_recovering == 0)
                mdt_postrecov(env, m);

        mdt_init_capa_ctxt(env, m);

        /* Reduce the initial timeout on an MDS because it doesn't need such
         * a long timeout as an OST does. Adaptive timeouts will adjust this
         * value appropriately. */
        if (ldlm_timeout == LDLM_TIMEOUT_DEFAULT)
                ldlm_timeout = MDS_LDLM_TIMEOUT_DEFAULT;

        RETURN(0);

err_stop_service:
        ping_evictor_stop();
        mdt_stop_ptlrpc_service(m);
err_recovery:
        target_recovery_fini(obd);
#ifdef HAVE_QUOTA_SUPPORT
        next->md_ops->mdo_quota.mqo_cleanup(env, next);
#endif
err_llog_cleanup:
        mdt_llog_ctxt_unclone(env, m, LLOG_CHANGELOG_ORIG_CTXT);
        mdt_obd_llog_cleanup(obd);
err_fs_cleanup:
        mdt_fs_cleanup(env, m);
err_capa:
        cfs_timer_disarm(&m->mdt_ck_timer);
        mdt_ck_thread_stop(m);
err_free_ns:
        upcall_cache_cleanup(m->mdt_identity_cache);
        m->mdt_identity_cache = NULL;
        ldlm_namespace_free(m->mdt_namespace, NULL, 0);
        obd->obd_namespace = m->mdt_namespace = NULL;
err_fini_seq:
        mdt_seq_fini(env, m);
err_fini_fld:
        mdt_fld_fini(env, m);
err_lut:
        lut_fini(env, &m->mdt_lut);
err_fini_stack:
        mdt_stack_fini(env, m, md2lu_dev(m->mdt_child));
err_fini_proc:
        mdt_procfs_fini(m);
        lu_site_fini(s);
err_free_site:
        OBD_FREE_PTR(mite);
err_lmi:
        if (lmi)
                server_put_mount_2(dev, lmi->lmi_mnt);
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

                /*
                 * For interoperability between 1.8 and 2.0,
                 * skip old "mdt.group_upcall" param.
                 */
                {
                        char *param = lustre_cfg_string(cfg, 1);
                        if (param && !strncmp("mdt.group_upcall", param, 16)) {
                                CWARN("For 1.8 interoperability, skip this"
                                       " mdt.group_upcall. It is obsolete\n");
                                break;
                        }
                }

                lprocfs_mdt_init_vars(&lvars);
                rc = class_process_proc_param(PARAM_MDT, lvars.obd_vars,
                                              cfg, obd);
                if (rc > 0 || rc == -ENOSYS)
                        /* we don't understand; pass it on */
                        rc = next->ld_ops->ldo_process_config(env, next, cfg);
                break;
        }
        case LCFG_ADD_MDC:
                /*
                 * Add mdc hook to get first MDT uuid and connect it to
                 * ls->controller to use for seq manager.
                 */
                rc = next->ld_ops->ldo_process_config(env, next, cfg);
                if (rc)
                        CERROR("Can't add mdc, rc %d\n", rc);
                else
                        rc = mdt_seq_init_cli(env, mdt_dev(d), cfg);
                break;
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
                cfs_sema_init(&mo->mot_ioepoch_sem, 1);
                cfs_sema_init(&mo->mot_lov_sem, 1);
                RETURN(o);
        } else
                RETURN(NULL);
}

static int mdt_object_init(const struct lu_env *env, struct lu_object *o,
                           const struct lu_object_conf *unused)
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
        struct mdt_object *mdto = mdt_obj((struct lu_object *)o);
        return (*p)(env, cookie, LUSTRE_MDT_NAME"-object@%p(ioepoch="LPU64" "
                    "flags="LPX64", epochcount=%d, writecount=%d)",
                    mdto, mdto->mot_ioepoch, mdto->mot_flags,
                    mdto->mot_ioepoch_count, mdto->mot_writecount);
}

static const struct lu_device_operations mdt_lu_ops = {
        .ldo_object_alloc   = mdt_object_alloc,
        .ldo_process_config = mdt_process_config,
};

static const struct lu_object_operations mdt_obj_ops = {
        .loo_object_init    = mdt_object_init,
        .loo_object_free    = mdt_object_free,
        .loo_object_print   = mdt_object_print
};

static int mdt_obd_set_info_async(struct obd_export *exp,
                                  __u32 keylen, void *key,
                                  __u32 vallen, void *val,
                                  struct ptlrpc_request_set *set)
{
        struct obd_device     *obd = exp->exp_obd;
        int                    rc;
        ENTRY;

        LASSERT(obd);

        if (KEY_IS(KEY_SPTLRPC_CONF)) {
                rc = mdt_adapt_sptlrpc_conf(obd, 0);
                RETURN(rc);
        }

        RETURN(0);
}

/* mds_connect_internal */
static int mdt_connect_internal(struct obd_export *exp,
                                struct mdt_device *mdt,
                                struct obd_connect_data *data)
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

                if (!mdt->mdt_som_conf)
                        data->ocd_connect_flags &= ~OBD_CONNECT_SOM;

                if (data->ocd_connect_flags & OBD_CONNECT_BRW_SIZE) {
                        data->ocd_brw_size = min(data->ocd_brw_size,
                               (__u32)(PTLRPC_MAX_BRW_PAGES << CFS_PAGE_SHIFT));
                        if (data->ocd_brw_size == 0) {
                                CERROR("%s: cli %s/%p ocd_connect_flags: "LPX64
                                       " ocd_version: %x ocd_grant: %d "
                                       "ocd_index: %u ocd_brw_size is "
                                       "unexpectedly zero, network data "
                                       "corruption? Refusing connection of this"
                                       " client\n",
                                       exp->exp_obd->obd_name,
                                       exp->exp_client_uuid.uuid,
                                       exp, data->ocd_connect_flags, data->ocd_version,
                                       data->ocd_grant, data->ocd_index);
                                return -EPROTO;
                        }
                }

                cfs_spin_lock(&exp->exp_lock);
                exp->exp_connect_flags = data->ocd_connect_flags;
                cfs_spin_unlock(&exp->exp_lock);
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

        if ((exp->exp_connect_flags & OBD_CONNECT_FID) == 0) {
                CWARN("%s: MDS requires FID support, but client not\n",
                      mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }

        if (mdt->mdt_som_conf && !exp_connect_som(exp) &&
            !(exp->exp_connect_flags & OBD_CONNECT_MDS_MDS)) {
                CWARN("%s: MDS has SOM enabled, but client does not support "
                      "it\n", mdt->mdt_md_dev.md_lu_dev.ld_obd->obd_name);
                return -EBADE;
        }

        return 0;
}

static int mdt_connect_check_sptlrpc(struct mdt_device *mdt,
                                     struct obd_export *exp,
                                     struct ptlrpc_request *req)
{
        struct sptlrpc_flavor   flvr;
        int                     rc = 0;

        if (exp->exp_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
                cfs_read_lock(&mdt->mdt_sptlrpc_lock);
                sptlrpc_target_choose_flavor(&mdt->mdt_sptlrpc_rset,
                                             req->rq_sp_from,
                                             req->rq_peer.nid,
                                             &flvr);
                cfs_read_unlock(&mdt->mdt_sptlrpc_lock);

                cfs_spin_lock(&exp->exp_lock);

                exp->exp_sp_peer = req->rq_sp_from;
                exp->exp_flvr = flvr;

                if (exp->exp_flvr.sf_rpc != SPTLRPC_FLVR_ANY &&
                    exp->exp_flvr.sf_rpc != req->rq_flvr.sf_rpc) {
                        CERROR("unauthorized rpc flavor %x from %s, "
                               "expect %x\n", req->rq_flvr.sf_rpc,
                               libcfs_nid2str(req->rq_peer.nid),
                               exp->exp_flvr.sf_rpc);
                        rc = -EACCES;
                }

                cfs_spin_unlock(&exp->exp_lock);
        } else {
                if (exp->exp_sp_peer != req->rq_sp_from) {
                        CERROR("RPC source %s doesn't match %s\n",
                               sptlrpc_part2name(req->rq_sp_from),
                               sptlrpc_part2name(exp->exp_sp_peer));
                        rc = -EACCES;
                } else {
                        rc = sptlrpc_target_export_check(exp, req);
                }
        }

        return rc;
}

/* mds_connect copy */
static int mdt_obd_connect(const struct lu_env *env,
                           struct obd_export **exp, struct obd_device *obd,
                           struct obd_uuid *cluuid,
                           struct obd_connect_data *data,
                           void *localdata)
{
        struct mdt_thread_info *info;
        struct obd_export      *lexp;
        struct lustre_handle    conn = { 0 };
        struct mdt_device      *mdt;
        struct ptlrpc_request  *req;
        int                     rc;
        ENTRY;

        LASSERT(env != NULL);
        if (!exp || !obd || !cluuid)
                RETURN(-EINVAL);

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        req = info->mti_pill->rc_req;
        mdt = mdt_dev(obd->obd_lu_dev);

        rc = class_connect(&conn, obd, cluuid);
        if (rc)
                RETURN(rc);

        lexp = class_conn2export(&conn);
        LASSERT(lexp != NULL);

        rc = mdt_connect_check_sptlrpc(mdt, lexp, req);
        if (rc)
                GOTO(out, rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_TGT_RCVG_FLAG))
                lustre_msg_add_op_flags(req->rq_repmsg, MSG_CONNECT_RECOVERING);

        rc = mdt_connect_internal(lexp, mdt, data);
        if (rc == 0) {
                struct mdt_thread_info *mti;
                struct lsd_client_data *lcd = lexp->exp_target_data.ted_lcd;
                LASSERT(lcd);
                mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
                LASSERT(mti != NULL);
                mti->mti_exp = lexp;
                memcpy(lcd->lcd_uuid, cluuid, sizeof lcd->lcd_uuid);
                rc = mdt_client_new(env, mdt);
                if (rc == 0)
                        mdt_export_stats_init(obd, lexp, localdata);
        }

out:
        if (rc != 0) {
                class_disconnect(lexp);
                *exp = NULL;
        } else {
                *exp = lexp;
        }

        RETURN(rc);
}

static int mdt_obd_reconnect(const struct lu_env *env,
                             struct obd_export *exp, struct obd_device *obd,
                             struct obd_uuid *cluuid,
                             struct obd_connect_data *data,
                             void *localdata)
{
        struct mdt_thread_info *info;
        struct mdt_device      *mdt;
        struct ptlrpc_request  *req;
        int                     rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        info = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        req = info->mti_pill->rc_req;
        mdt = mdt_dev(obd->obd_lu_dev);

        rc = mdt_connect_check_sptlrpc(mdt, exp, req);
        if (rc)
                RETURN(rc);

        rc = mdt_connect_internal(exp, mdt_dev(obd->obd_lu_dev), data);
        if (rc == 0)
                mdt_export_stats_init(obd, exp, localdata);

        RETURN(rc);
}
static int mdt_export_cleanup(struct obd_export *exp)
{
        struct mdt_export_data *med = &exp->exp_mdt_data;
        struct obd_device      *obd = exp->exp_obd;
        struct mdt_device      *mdt;
        struct mdt_thread_info *info;
        struct lu_env           env;
        CFS_LIST_HEAD(closing_list);
        struct mdt_file_data *mfd, *n;
        int rc = 0;
        ENTRY;

        cfs_spin_lock(&med->med_open_lock);
        while (!cfs_list_empty(&med->med_open_head)) {
                cfs_list_t *tmp = med->med_open_head.next;
                mfd = cfs_list_entry(tmp, struct mdt_file_data, mfd_list);

                /* Remove mfd handle so it can't be found again.
                 * We are consuming the mfd_list reference here. */
                class_handle_unhash(&mfd->mfd_handle);
                cfs_list_move_tail(&mfd->mfd_list, &closing_list);
        }
        cfs_spin_unlock(&med->med_open_lock);
        mdt = mdt_dev(obd->obd_lu_dev);
        LASSERT(mdt != NULL);

        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        info = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
        LASSERT(info != NULL);
        memset(info, 0, sizeof *info);
        info->mti_env = &env;
        info->mti_mdt = mdt;
        info->mti_exp = exp;

        if (!cfs_list_empty(&closing_list)) {
                struct md_attr *ma = &info->mti_attr;
                int lmm_size;
                int cookie_size;

                lmm_size = mdt->mdt_max_mdsize;
                OBD_ALLOC_LARGE(ma->ma_lmm, lmm_size);
                if (ma->ma_lmm == NULL)
                        GOTO(out_lmm, rc = -ENOMEM);

                cookie_size = mdt->mdt_max_cookiesize;
                OBD_ALLOC_LARGE(ma->ma_cookie, cookie_size);
                if (ma->ma_cookie == NULL)
                        GOTO(out_cookie, rc = -ENOMEM);

                /* Close any open files (which may also cause orphan unlinking). */
                cfs_list_for_each_entry_safe(mfd, n, &closing_list, mfd_list) {
                        cfs_list_del_init(&mfd->mfd_list);
                        memset(&ma->ma_attr, 0, sizeof(ma->ma_attr));
                        ma->ma_lmm_size = lmm_size;
                        ma->ma_cookie_size = cookie_size;
                        ma->ma_need = 0;
                        /* It is not for setattr, just tell MDD to send
                         * DESTROY RPC to OSS if needed */
                        ma->ma_valid = MA_FLAGS;
                        ma->ma_attr_flags = MDS_CLOSE_CLEANUP;
                        /* Don't unlink orphan on failover umount, LU-184 */
                        if (exp->exp_flags & OBD_OPT_FAILOVER)
                                ma->ma_attr_flags |= MDS_KEEP_ORPHAN;
                        mdt_mfd_close(info, mfd);
                }
                OBD_FREE_LARGE(ma->ma_cookie, cookie_size);
                ma->ma_cookie = NULL;
out_cookie:
                OBD_FREE_LARGE(ma->ma_lmm, lmm_size);
                ma->ma_lmm = NULL;
        }
out_lmm:
        info->mti_mdt = NULL;
        /* cleanup client slot early */
        /* Do not erase record for recoverable client. */
        if (!(exp->exp_flags & OBD_OPT_FAILOVER) || exp->exp_failed)
                mdt_client_del(&env, mdt);
        lu_env_fini(&env);

        RETURN(rc);
}

static int mdt_obd_disconnect(struct obd_export *exp)
{
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        rc = server_disconnect_export(exp);
        if (rc != 0)
                CDEBUG(D_IOCTL, "server disconnect error: %d\n", rc);

        rc = mdt_export_cleanup(exp);
        class_export_put(exp);
        RETURN(rc);
}

/* FIXME: Can we avoid using these two interfaces? */
static int mdt_init_export(struct obd_export *exp)
{
        struct mdt_export_data *med = &exp->exp_mdt_data;
        int                     rc;
        ENTRY;

        CFS_INIT_LIST_HEAD(&med->med_open_head);
        cfs_spin_lock_init(&med->med_open_lock);
        cfs_sema_init(&med->med_idmap_sem, 1);
        med->med_idmap = NULL;
        cfs_spin_lock(&exp->exp_lock);
        exp->exp_connecting = 1;
        cfs_spin_unlock(&exp->exp_lock);
        rc = lut_client_alloc(exp);
        if (rc == 0)
                rc = ldlm_init_export(exp);

        if (rc)
                CERROR("Error %d while initializing export\n", rc);
        RETURN(rc);
}

static int mdt_destroy_export(struct obd_export *exp)
{
        struct mdt_export_data *med;
        int rc = 0;
        ENTRY;

        med = &exp->exp_mdt_data;
        if (exp_connect_rmtclient(exp))
                mdt_cleanup_idmap(&exp->exp_mdt_data);

        target_destroy_export(exp);
        ldlm_destroy_export(exp);
        lut_client_free(exp);

        LASSERT(cfs_list_empty(&exp->exp_outstanding_replies));
        LASSERT(cfs_list_empty(&exp->exp_mdt_data.med_open_head));
        if (obd_uuid_equals(&exp->exp_client_uuid, &exp->exp_obd->obd_uuid))
                RETURN(0);

        RETURN(rc);
}

static void mdt_allow_cli(struct mdt_device *m, unsigned int flag)
{
        if (flag & CONFIG_LOG)
                cfs_set_bit(MDT_FL_CFGLOG, &m->mdt_state);

        /* also notify active event */
        if (flag & CONFIG_SYNC)
                cfs_set_bit(MDT_FL_SYNCED, &m->mdt_state);

        if (cfs_test_bit(MDT_FL_CFGLOG, &m->mdt_state) &&
            cfs_test_bit(MDT_FL_SYNCED, &m->mdt_state)) {
                struct obd_device *obd = m->mdt_md_dev.md_lu_dev.ld_obd;

                /* Open for clients */
                if (obd->obd_no_conn) {
                        cfs_spin_lock(&obd->obd_dev_lock);
                        obd->obd_no_conn = 0;
                        cfs_spin_unlock(&obd->obd_dev_lock);
                }
        }
}

static int mdt_upcall(const struct lu_env *env, struct md_device *md,
                      enum md_upcall_event ev, void *data)
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
                        mdt_allow_cli(m, CONFIG_SYNC);
                        if (data)
                                (*(__u64 *)data) =
                                      m->mdt_lut.lut_obd->u.obt.obt_mount_count;
                        break;
                case MD_NO_TRANS:
                        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
                        mti->mti_no_need_trans = 1;
                        CDEBUG(D_INFO, "disable mdt trans for this thread\n");
                        break;
                case MD_LOV_CONFIG:
                        /* Check that MDT is not yet configured */
                        LASSERT(!cfs_test_bit(MDT_FL_CFGLOG, &m->mdt_state));
                        break;
#ifdef HAVE_QUOTA_SUPPORT
                case MD_LOV_QUOTA:
                        if (md->md_lu_dev.ld_obd->obd_recovering == 0 &&
                            likely(md->md_lu_dev.ld_obd->obd_stopping == 0))
                                next->md_ops->mdo_quota.mqo_recovery(env, next);
                        break;
#endif
                default:
                        CERROR("invalid event\n");
                        rc = -EINVAL;
                        break;
        }
        RETURN(rc);
}

static int mdt_obd_notify(struct obd_device *host,
                          struct obd_device *watched,
                          enum obd_notify_event ev, void *data)
{
        struct mdt_device *mdt = mdt_dev(host->obd_lu_dev);
#ifdef HAVE_QUOTA_SUPPORT
        struct md_device *next = mdt->mdt_child;
#endif
        ENTRY;

        switch (ev) {
        case OBD_NOTIFY_CONFIG:
                mdt_allow_cli(mdt, (unsigned long)data);

#ifdef HAVE_QUOTA_SUPPORT
               /* quota_type has been processed, we can now handle
                * incoming quota requests */
                next->md_ops->mdo_quota.mqo_notify(NULL, next);
#endif
                break;
        default:
                CDEBUG(D_INFO, "Unhandled notification %#x\n", ev);
        }
        RETURN(0);
}

static int mdt_rpc_fid2path(struct mdt_thread_info *info, void *key,
                            void *val, int vallen)
{
        struct mdt_device *mdt = mdt_dev(info->mti_exp->exp_obd->obd_lu_dev);
        struct getinfo_fid2path *fpout, *fpin;
        int rc = 0;

        fpin = key + cfs_size_round(sizeof(KEY_FID2PATH));
        fpout = val;

        if (ptlrpc_req_need_swab(info->mti_pill->rc_req))
                lustre_swab_fid2path(fpin);

        memcpy(fpout, fpin, sizeof(*fpin));
        if (fpout->gf_pathlen != vallen - sizeof(*fpin))
                RETURN(-EINVAL);

        rc = mdt_fid2path(info->mti_env, mdt, fpout);
        RETURN(rc);
}

static int mdt_fid2path(const struct lu_env *env, struct mdt_device *mdt,
                        struct getinfo_fid2path *fp)
{
        struct mdt_object *obj;
        int    rc;
        ENTRY;

        CDEBUG(D_IOCTL, "path get "DFID" from "LPU64" #%d\n",
               PFID(&fp->gf_fid), fp->gf_recno, fp->gf_linkno);

        if (!fid_is_sane(&fp->gf_fid))
                RETURN(-EINVAL);

        obj = mdt_object_find(env, mdt, &fp->gf_fid);
        if (obj == NULL || IS_ERR(obj)) {
                CDEBUG(D_IOCTL, "no object "DFID": %ld\n",PFID(&fp->gf_fid),
                       PTR_ERR(obj));
                RETURN(-EINVAL);
        }

        rc = lu_object_exists(&obj->mot_obj.mo_lu);
        if (rc <= 0) {
                if (rc == -1)
                        rc = -EREMOTE;
                else
                        rc = -ENOENT;
                mdt_object_put(env, obj);
                CDEBUG(D_IOCTL, "nonlocal object "DFID": %d\n",
                       PFID(&fp->gf_fid), rc);
                RETURN(rc);
        }

        rc = mo_path(env, md_object_next(&obj->mot_obj), fp->gf_path,
                     fp->gf_pathlen, &fp->gf_recno, &fp->gf_linkno);
        mdt_object_put(env, obj);

        RETURN(rc);
}

static int mdt_get_info(struct mdt_thread_info *info)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        char *key;
        int keylen;
        __u32 *vallen;
        void *valout;
        int rc;
        ENTRY;

        key = req_capsule_client_get(info->mti_pill, &RMF_GETINFO_KEY);
        if (key == NULL) {
                CDEBUG(D_IOCTL, "No GETINFO key");
                RETURN(-EFAULT);
        }
        keylen = req_capsule_get_size(info->mti_pill, &RMF_GETINFO_KEY,
                                      RCL_CLIENT);

        vallen = req_capsule_client_get(info->mti_pill, &RMF_GETINFO_VALLEN);
        if (vallen == NULL) {
                CDEBUG(D_IOCTL, "Unable to get RMF_GETINFO_VALLEN buffer");
                RETURN(-EFAULT);
        }

        req_capsule_set_size(info->mti_pill, &RMF_GETINFO_VAL, RCL_SERVER,
                             *vallen);
        rc = req_capsule_server_pack(info->mti_pill);
        valout = req_capsule_server_get(info->mti_pill, &RMF_GETINFO_VAL);
        if (valout == NULL) {
                CDEBUG(D_IOCTL, "Unable to get get-info RPC out buffer");
                RETURN(-EFAULT);
        }

        if (KEY_IS(KEY_FID2PATH))
                rc = mdt_rpc_fid2path(info, key, valout, *vallen);
        else
                rc = -EINVAL;

        lustre_msg_set_status(req->rq_repmsg, rc);

        RETURN(rc);
}

/* Pass the ioc down */
static int mdt_ioc_child(struct lu_env *env, struct mdt_device *mdt,
                         unsigned int cmd, int len, void *data)
{
        struct lu_context ioctl_session;
        struct md_device *next = mdt->mdt_child;
        int rc;
        ENTRY;

        rc = lu_context_init(&ioctl_session, LCT_SESSION);
        if (rc)
                RETURN(rc);
        ioctl_session.lc_thread = (struct ptlrpc_thread *)cfs_current();
        lu_context_enter(&ioctl_session);
        env->le_ses = &ioctl_session;

        LASSERT(next->md_ops->mdo_iocontrol);
        rc = next->md_ops->mdo_iocontrol(env, next, cmd, len, data);

        lu_context_exit(&ioctl_session);
        lu_context_fini(&ioctl_session);
        RETURN(rc);
}

static int mdt_ioc_version_get(struct mdt_thread_info *mti, void *karg)
{
        struct obd_ioctl_data *data = karg;
        struct lu_fid *fid = (struct lu_fid *)data->ioc_inlbuf1;
        __u64 version;
        struct mdt_object *obj;
        struct mdt_lock_handle  *lh;
        int rc;
        ENTRY;
        CDEBUG(D_IOCTL, "getting version for "DFID"\n", PFID(fid));
        if (!fid_is_sane(fid))
                RETURN(-EINVAL);

        lh = &mti->mti_lh[MDT_LH_PARENT];
        mdt_lock_reg_init(lh, LCK_CR);

        obj = mdt_object_find_lock(mti, fid, lh, MDS_INODELOCK_UPDATE);
        if (IS_ERR(obj))
                RETURN(PTR_ERR(obj));

        rc = mdt_object_exists(obj);
        if (rc < 0) {
                rc = -EREMOTE;
                /**
                 * before calling version get the correct MDS should be
                 * fid, this is error to find remote object here
                 */
                CERROR("nonlocal object "DFID"\n", PFID(fid));
        } else {
                version = mo_version_get(mti->mti_env, mdt_object_child(obj));
               *(__u64 *)data->ioc_inlbuf2 = version;
                rc = 0;
        }
        mdt_object_unlock_put(mti, obj, lh, 1);
        RETURN(rc);
}

/* ioctls on obd dev */
static int mdt_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                         void *karg, void *uarg)
{
        struct lu_env      env;
        struct obd_device *obd = exp->exp_obd;
        struct mdt_device *mdt = mdt_dev(obd->obd_lu_dev);
        struct dt_device  *dt = mdt->mdt_bottom;
        int rc;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        switch (cmd) {
        case OBD_IOC_SYNC:
                rc = mdt_device_sync(&env, mdt);
                break;
        case OBD_IOC_SET_READONLY:
                dt->dd_ops->dt_ro(&env, dt);
                break;
        case OBD_IOC_ABORT_RECOVERY:
                CERROR("Aborting recovery for device %s\n", obd->obd_name);
                target_stop_recovery_thread(obd);
                rc = 0;
                break;
        case OBD_IOC_CHANGELOG_REG:
        case OBD_IOC_CHANGELOG_DEREG:
        case OBD_IOC_CHANGELOG_CLEAR:
                rc = mdt_ioc_child(&env, mdt, cmd, len, karg);
                break;
        case OBD_IOC_GET_OBJ_VERSION: {
                struct mdt_thread_info *mti;
                mti = lu_context_key_get(&env.le_ctx, &mdt_thread_key);
                memset(mti, 0, sizeof *mti);
                mti->mti_env = &env;
                mti->mti_mdt = mdt;
                mti->mti_exp = exp;

                rc = mdt_ioc_version_get(mti, karg);
                break;
        }
        default:
                CERROR("Not supported cmd = %d for device %s\n",
                       cmd, obd->obd_name);
                rc = -EOPNOTSUPP;
        }

        lu_env_fini(&env);
        RETURN(rc);
}

int mdt_postrecov(const struct lu_env *env, struct mdt_device *mdt)
{
        struct lu_device *ld = md2lu_dev(mdt->mdt_child);
#ifdef HAVE_QUOTA_SUPPORT
        struct obd_device *obd = mdt2obd_dev(mdt);
        struct md_device *next = mdt->mdt_child;
#endif
        int rc;
        ENTRY;

        rc = ld->ld_ops->ldo_recovery_complete(env, ld);
#ifdef HAVE_QUOTA_SUPPORT
        if (likely(obd->obd_stopping == 0))
                next->md_ops->mdo_quota.mqo_recovery(env, next);
#endif
        RETURN(rc);
}

int mdt_obd_postrecov(struct obd_device *obd)
{
        struct lu_env env;
        int rc;

        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);
        rc = mdt_postrecov(&env, mdt_dev(obd->obd_lu_dev));
        lu_env_fini(&env);
        return rc;
}

/**
 * Send a copytool req to a client
 * Note this sends a request RPC from a server (MDT) to a client (MDC),
 * backwards of normal comms.
 */
int mdt_hsm_copytool_send(struct obd_export *exp)
{
        struct kuc_hdr *lh;
        struct hsm_action_list *hal;
        struct hsm_action_item *hai;
        int rc, len;
        ENTRY;

        CWARN("%s: writing to mdc at %s\n", exp->exp_obd->obd_name,
              libcfs_nid2str(exp->exp_connection->c_peer.nid));

        len = sizeof(*lh) + sizeof(*hal) + MTI_NAME_MAXLEN +
                /* for mockup below */ 2 * cfs_size_round(sizeof(*hai));
        OBD_ALLOC(lh, len);
        if (lh == NULL)
                RETURN(-ENOMEM);

        lh->kuc_magic = KUC_MAGIC;
        lh->kuc_transport = KUC_TRANSPORT_HSM;
        lh->kuc_msgtype = HMT_ACTION_LIST;
        lh->kuc_msglen = len;

        hal = (struct hsm_action_list *)(lh + 1);
        hal->hal_version = HAL_VERSION;
        hal->hal_archive_num = 1;
        obd_uuid2fsname(hal->hal_fsname, exp->exp_obd->obd_name,
                        MTI_NAME_MAXLEN);

        /* mock up an action list */
        hal->hal_count = 2;
        hai = hai_zero(hal);
        hai->hai_action = HSMA_ARCHIVE;
        hai->hai_fid.f_oid = 0xA00A;
        hai->hai_len = sizeof(*hai);
        hai = hai_next(hai);
        hai->hai_action = HSMA_RESTORE;
        hai->hai_fid.f_oid = 0xB00B;
        hai->hai_len = sizeof(*hai);

        /* Uses the ldlm reverse import; this rpc will be seen by
          the ldlm_callback_handler */
        rc = do_set_info_async(exp->exp_imp_reverse,
                               LDLM_SET_INFO, LUSTRE_OBD_VERSION,
                               sizeof(KEY_HSM_COPYTOOL_SEND),
                               KEY_HSM_COPYTOOL_SEND,
                               len, lh, NULL);

        OBD_FREE(lh, len);

        RETURN(rc);
}

static struct obd_ops mdt_obd_device_ops = {
        .o_owner          = THIS_MODULE,
        .o_set_info_async = mdt_obd_set_info_async,
        .o_connect        = mdt_obd_connect,
        .o_reconnect      = mdt_obd_reconnect,
        .o_disconnect     = mdt_obd_disconnect,
        .o_init_export    = mdt_init_export,
        .o_destroy_export = mdt_destroy_export,
        .o_iocontrol      = mdt_iocontrol,
        .o_postrecov      = mdt_obd_postrecov,
        .o_notify         = mdt_obd_notify
};

static struct lu_device* mdt_device_fini(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);
        ENTRY;

        mdt_fini(env, m);
        RETURN(NULL);
}

static struct lu_device *mdt_device_free(const struct lu_env *env,
                                         struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);
        ENTRY;

        md_device_fini(&m->mdt_md_dev);
        OBD_FREE_PTR(m);
        RETURN(NULL);
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
                        mdt_device_free(env, l);
                        l = ERR_PTR(rc);
                        return l;
                }
                md_upcall_init(&m->mdt_md_dev, mdt_upcall);
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

/* context key constructor/destructor: mdt_key_init, mdt_key_fini */
LU_KEY_INIT_FINI(mdt, struct mdt_thread_info);

/* context key: mdt_thread_key */
LU_CONTEXT_KEY_DEFINE(mdt, LCT_MD_THREAD);

/* context key constructor/destructor: mdt_txn_key_init, mdt_txn_key_fini */
LU_KEY_INIT_FINI(mdt_txn, struct mdt_txn_info);

struct lu_context_key mdt_txn_key = {
        .lct_tags = LCT_TX_HANDLE,
        .lct_init = mdt_txn_key_init,
        .lct_fini = mdt_txn_key_fini
};

struct md_ucred *mdt_ucred(const struct mdt_thread_info *info)
{
        return md_ucred(info->mti_env);
}

/**
 * Enable/disable COS (Commit On Sharing).
 *
 * Set/Clear the COS flag in mdt options.
 *
 * \param mdt mdt device
 * \param val 0 disables COS, other values enable COS
 */
void mdt_enable_cos(struct mdt_device *mdt, int val)
{
        struct lu_env env;
        int rc;

        mdt->mdt_opts.mo_cos = !!val;
        rc = lu_env_init(&env, LCT_MD_THREAD);
        if (unlikely(rc != 0)) {
                CWARN("lu_env initialization failed with rc = %d,"
                      "cannot sync\n", rc);
                return;
        }
        mdt_device_sync(&env, mdt);
        lu_env_fini(&env);
}

/**
 * Check COS (Commit On Sharing) status.
 *
 * Return COS flag status.
 *
 * \param mdt mdt device
 */
int mdt_cos_is_enabled(struct mdt_device *mdt)
{
        return mdt->mdt_opts.mo_cos != 0;
}

/* type constructor/destructor: mdt_type_init, mdt_type_fini */
LU_TYPE_INIT_FINI(mdt, &mdt_thread_key, &mdt_txn_key);

static struct lu_device_type_operations mdt_device_type_ops = {
        .ldto_init = mdt_type_init,
        .ldto_fini = mdt_type_fini,

        .ldto_start = mdt_type_start,
        .ldto_stop  = mdt_type_stop,

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

static struct lu_local_obj_desc mdt_last_recv = {
        .llod_name      = LAST_RCVD,
        .llod_oid       = MDT_LAST_RECV_OID,
        .llod_is_index  = 0,
};

static int __init mdt_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        int rc;

        llo_local_obj_register(&mdt_last_recv);

        if (mdt_num_threads > 0) {
                if (mdt_num_threads > MDT_MAX_THREADS)
                        mdt_num_threads = MDT_MAX_THREADS;
                if (mdt_num_threads < MDT_MIN_THREADS)
                        mdt_num_threads = MDT_MIN_THREADS;
                mdt_max_threads = mdt_min_threads = mdt_num_threads;
        } else {
                mdt_max_threads = MDT_MAX_THREADS;
                mdt_min_threads = MDT_MIN_THREADS;
        }

        lprocfs_mdt_init_vars(&lvars);
        rc = class_register_type(&mdt_obd_device_ops, NULL,
                                 lvars.module_vars, LUSTRE_MDT_NAME,
                                 &mdt_device_type);

        return rc;
}

static void __exit mdt_mod_exit(void)
{
        llo_local_obj_unregister(&mdt_last_recv);
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
DEF_MDT_HNDL  (0,                         SET_INFO,     mdt_set_info,
                                                             &RQF_OBD_SET_INFO),
DEF_MDT_HNDL_F(0,                         GET_INFO,     mdt_get_info),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, GETSTATUS,    mdt_getstatus),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETATTR,      mdt_getattr),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, GETATTR_NAME, mdt_getattr_name),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETXATTR,     mdt_getxattr),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, STATFS,       mdt_statfs),
DEF_MDT_HNDL_F(0           |MUTABOR,      REINT,        mdt_reint),
DEF_MDT_HNDL_F(HABEO_CORPUS,              CLOSE,        mdt_close),
DEF_MDT_HNDL_F(HABEO_CORPUS,              DONE_WRITING, mdt_done_writing),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, PIN,          mdt_pin),
DEF_MDT_HNDL_0(0,                         SYNC,         mdt_sync),
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, IS_SUBDIR,    mdt_is_subdir),
#ifdef HAVE_QUOTA_SUPPORT
DEF_MDT_HNDL_F(0,                         QUOTACHECK,   mdt_quotacheck_handle),
DEF_MDT_HNDL_F(0,                         QUOTACTL,     mdt_quotactl_handle)
#endif
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

#define DEF_LLOG_HNDL(flags, name, fn)                   \
        DEF_HNDL(LLOG, ORIGIN_HANDLE_CREATE, _NET, flags, name, fn, NULL)

static struct mdt_handler mdt_llog_ops[] = {
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_CREATE,      mdt_llog_create),
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_NEXT_BLOCK,  mdt_llog_next_block),
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_READ_HEADER, mdt_llog_read_header),
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_WRITE_REC,   NULL),
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_CLOSE,       NULL),
        DEF_LLOG_HNDL(0, ORIGIN_CONNECT,            NULL),
        DEF_LLOG_HNDL(0, CATINFO,                   NULL),
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_PREV_BLOCK,  mdt_llog_prev_block),
        DEF_LLOG_HNDL(0, ORIGIN_HANDLE_DESTROY,     mdt_llog_destroy),
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
        DEF_MDT_HNDL_F(0,                         CONNECT,  mdt_connect),
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

static struct mdt_handler mdt_xmds_ops[] = {
        DEF_MDT_HNDL_F(0,                         CONNECT,      mdt_connect),
        DEF_MDT_HNDL_F(HABEO_CORPUS             , GETATTR,      mdt_getattr),
        DEF_MDT_HNDL_F(0 | MUTABOR              , REINT,        mdt_reint),
        DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO, IS_SUBDIR,    mdt_is_subdir),
};

static struct mdt_opc_slice mdt_xmds_handlers[] = {
        {
                .mos_opc_start = MDS_GETATTR,
                .mos_opc_end   = MDS_LAST_OPC,
                .mos_hs        = mdt_xmds_ops
        },
        {
                .mos_opc_start = OBD_PING,
                .mos_opc_end   = OBD_LAST_OPC,
                .mos_hs        = mdt_obd_ops
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

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Meta-data Target ("LUSTRE_MDT_NAME")");
MODULE_LICENSE("GPL");

CFS_MODULE_PARM(mdt_num_threads, "ul", ulong, 0444,
                "number of mdt service threads to start");

cfs_module(mdt, "0.2.0", mdt_mod_init, mdt_mod_exit);
