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
        struct md_device *next  = info->mti_mdt->mdt_child;
        int               rc;
        struct mdt_body  *body;

        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK))
                rc = -ENOMEM;
        else {
                body = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
                rc = next->md_ops->mdo_get_root(info->mti_ctxt,
                                                next, &body->fid1);
                if (rc == 0)
                        body->valid |= OBD_MD_FLID;
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
                rc = -ENOMEM;
        } else {
                osfs = req_capsule_server_get(&info->mti_pill,&RMF_OBD_STATFS);
                /* XXX max_age optimisation is needed here. See mds_statfs */
                rc = next->md_ops->mdo_statfs(info->mti_ctxt,
                                              next, &info->mti_u.ksfs);
                statfs_pack(osfs, &info->mti_u.ksfs);
        }

        RETURN(rc);
}

void mdt_pack_attr2body(struct mdt_body *b, const struct lu_attr *attr,
                        const struct lu_fid *fid)
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
        const struct mdt_body   *reqbody = info->mti_body;
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct md_attr          *ma = &info->mti_attr;
        struct lu_attr          *la = &ma->ma_attr;
        struct req_capsule      *pill = &info->mti_pill;
        const struct lu_context *ctxt = info->mti_ctxt;
        struct mdt_body         *repbody;
        void                    *buffer;
        int                     length;
        int                     rc;
        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK))
                RETURN(-ENOMEM);

        repbody = req_capsule_server_get(pill, &RMF_MDT_BODY);
        repbody->eadatasize = 0;
        repbody->aclsize = 0;

        if(reqbody->valid & OBD_MD_MEA) {
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
        rc = mo_attr_get(ctxt, next, ma);
        if (rc == -EREMOTE) {
                /* This object is located on remote node.*/
                repbody->fid1 = *mdt_object_fid(o);
                repbody->valid = OBD_MD_FLID | OBD_MD_MDS;
                RETURN(0);
        } else if (rc){
                CERROR("getattr error for "DFID": %d\n",
                        PFID(mdt_object_fid(o)), rc);
                RETURN(rc);
        }

        if (ma->ma_valid & MA_INODE)
                mdt_pack_attr2body(repbody, la, mdt_object_fid(o));
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
                rc = mo_readlink(ctxt, next, ma->ma_lmm, ma->ma_lmm_size);
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

#ifdef CONFIG_FS_POSIX_ACL
        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (reqbody->valid & OBD_MD_FLACL)) {
                buffer = req_capsule_server_get(pill, &RMF_ACL);
                length = req_capsule_get_size(pill, &RMF_ACL, RCL_SERVER);
                if (length > 0) {
                        rc = mo_xattr_get(ctxt, next, buffer,
                                          length, XATTR_NAME_ACL_ACCESS);
                        if (rc < 0) {
                                if (rc == -ENODATA || rc == -EOPNOTSUPP)
                                        rc = 0;
                                else
                                        CERROR("got acl size: %d\n", rc);
                        } else {
                                repbody->aclsize = rc;
                                repbody->valid |= OBD_MD_FLACL;
                        }
                }
        }
#endif

        RETURN(rc);
}

static int mdt_getattr(struct mdt_thread_info *info)
{
        int rc;
        struct mdt_object *obj;

        obj = info->mti_object;
        LASSERT(obj != NULL);
        LASSERT(lu_object_assert_exists(&obj->mot_obj.mo_lu));
        ENTRY;

        rc = mdt_getattr_internal(info, obj);
        mdt_shrink_reply(info, REPLY_REC_OFF + 1);
        RETURN(rc);
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
        struct mdt_object *parent = info->mti_object;
        struct mdt_object *child;
        struct md_object  *next = mdt_object_child(info->mti_object);
        struct lu_fid     *child_fid = &info->mti_tmp_fid1;
        const char        *name;
        int               rc;
        struct mdt_lock_handle *lhp;
        ENTRY;

        LASSERT(info->mti_object != NULL);
        name = req_capsule_client_get(&info->mti_pill, &RMF_NAME);
        if (name == NULL)
                RETURN(-EFAULT);

        CDEBUG(D_INODE, "getattr with lock for "DFID"/%s, ldlm_rep = %p\n",
                        PFID(mdt_object_fid(parent)), name, ldlm_rep);

        mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_EXECD);
        if (strlen(name) == 0) {
                /* only getattr on the child. parent is on another node. */
                mdt_set_disposition(info, ldlm_rep, DISP_LOOKUP_POS);
                child = parent;
                CDEBUG(D_INODE, "partial getattr_name child_fid = "DFID
                               ", ldlm_rep=%p\n",
                               PFID(mdt_object_fid(child)), ldlm_rep);

                mdt_lock_handle_init(lhc);
                lhc->mlh_mode = LCK_CR;
                rc = mdt_object_lock(info, child, lhc, child_bits);
                if (rc == 0) {
                        /* finally, we can get attr for child. */
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
        rc = mdo_lookup(info->mti_ctxt, next, name, child_fid);
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
        mdt_lock_handle_init(lhc);
        lhc->mlh_mode = LCK_CR;
        child = mdt_object_find_lock(info, child_fid, lhc, child_bits);
        if (IS_ERR(child))
                GOTO(out_parent, rc = PTR_ERR(child));

        /* finally, we can get attr for child. */
        rc = mdt_getattr_internal(info, child);
        if (rc != 0)
                mdt_object_unlock(info, child, lhc, 1);
        else {
                /* This is pure debugging code. */
                struct ldlm_lock *lock;
                struct ldlm_res_id *res_id;
                lock = ldlm_handle2lock(&lhc->mlh_lh);
                if (lock) {
                        res_id = &lock->l_resource->lr_name;
                        LDLM_DEBUG(lock, "we will return this lock client\n");
                        LASSERTF(fid_res_name_eq(mdt_object_fid(child),
                                                 &lock->l_resource->lr_name),
                                "Lock res_id: %lu/%lu/%lu, Fid: "DFID".\n",
                                (unsigned long)res_id->name[0],
                                (unsigned long)res_id->name[1],
                                (unsigned long)res_id->name[2],
                                PFID(mdt_object_fid(child)));
                        LDLM_LOCK_PUT(lock);
                }
        }
        mdt_object_put(info->mti_ctxt, child);

        EXIT;
out_parent:
        mdt_object_unlock(info, parent, lhp, 1);
out:
        return rc;
}

/* normal handler: should release the child lock */
static int mdt_getattr_name(struct mdt_thread_info *info)
{
        struct mdt_lock_handle *lhc = &info->mti_lh[MDT_LH_CHILD];
        int rc;

        ENTRY;

        rc = mdt_getattr_name_lock(info, lhc, MDS_INODELOCK_UPDATE, NULL);
        if (lustre_handle_is_used(&lhc->mlh_lh)) {
                ldlm_lock_decref(&lhc->mlh_lh, lhc->mlh_mode);
                lhc->mlh_lh.cookie = 0;
        }
        mdt_shrink_reply(info, REPLY_REC_OFF + 1);
        RETURN(rc);
}

static struct lu_device_operations mdt_lu_ops;

static int lu_device_is_mdt(struct lu_device *d)
{
        return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static inline struct mdt_device *mdt_dev(struct lu_device *d)
{
        LASSERT(lu_device_is_mdt(d));
        return container_of0(d, struct mdt_device, mdt_md_dev.md_lu_dev);
}

static int mdt_connect(struct mdt_thread_info *info)
{
        int rc;
        struct ptlrpc_request *req;

        req = mdt_info_req(info);
        rc = target_handle_connect(req, mdt_regular_handle);
        if (rc == 0) {
                LASSERT(req->rq_export != NULL);
                info->mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);
        }
        return rc;
}

static int mdt_disconnect(struct mdt_thread_info *info)
{
        return target_handle_disconnect(mdt_info_req(info));
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
static int mdt_write_dir_page(struct mdt_thread_info *info, struct page *page)
{
        struct mdt_object *object = info->mti_object;
        struct lu_dirpage *dp;
        struct lu_dirent *ent;
        int rc = 0;

        kmap(page);
        dp = page_address(page);
        for (ent = lu_dirent_start(dp); ent != NULL;
                          ent = lu_dirent_next(ent)) {
                struct lu_fid *lf = &ent->lde_fid;

                /* FIXME: check isdir */
                rc = mdo_name_insert(info->mti_ctxt,
                                     md_object_next(&object->mot_obj),
                                     ent->lde_name, lf, 0);
                CDEBUG(D_INFO, "insert name %s rc %d \n", ent->lde_name, rc);
                if (rc) {
                        kunmap(page);
                        RETURN(rc);
                }
        }
        kunmap(page);
        RETURN(rc);
}

static int mdt_bulk_timeout(void *data)
{
        ENTRY;
        /* We don't fail the connection here, because having the export
         * killed makes the (vital) call to commitrw very sad.
         */
        RETURN(1);
}

static int mdt_writepage(struct mdt_thread_info *info)
{
        struct ptlrpc_request   *req = mdt_info_req(info);
        struct l_wait_info      *lwi;
        struct ptlrpc_bulk_desc *desc;
        struct page             *page;
        int                rc;
        ENTRY;

        desc = ptlrpc_prep_bulk_exp (req, 1, BULK_GET_SINK, MDS_BULK_PORTAL);
        if (!desc)
                RETURN(-ENOMEM);

        /* allocate the page for the desc */
        page = alloc_pages(GFP_KERNEL, 0);
        if (!page)
                GOTO(desc_cleanup, rc = -ENOMEM);

        ptlrpc_prep_bulk_page(desc, page, 0, CFS_PAGE_SIZE);

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
        rc = mdt_write_dir_page(info, page);

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
                RETURN(-ENOMEM);

        reqbody = req_capsule_client_get(&info->mti_pill, &RMF_MDT_BODY);
        repbody = req_capsule_server_get(&info->mti_pill, &RMF_MDT_BODY);
        if (reqbody == NULL || repbody == NULL)
                RETURN(-EFAULT);

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
        rc = mo_readpage(info->mti_ctxt, mdt_object_child(object), rdpg);
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

static int mdt_reint_internal(struct mdt_thread_info *info, __u32 op)
{
        struct req_capsule      *pill = &info->mti_pill;
        struct mdt_device       *mdt = info->mti_mdt;
        struct ptlrpc_request   *req = mdt_info_req(info);
        int                      rc;
        ENTRY;

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK))
                RETURN(-EFAULT);

        rc = mdt_reint_unpack(info, op);
        if (rc != 0)
                RETURN(rc);

        /*pack reply*/
        if (req_capsule_has_field(pill, &RMF_MDT_MD, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_MDT_MD, RCL_SERVER,
                                     mdt->mdt_max_mdsize);
        if (req_capsule_has_field(pill, &RMF_LOGCOOKIES, RCL_SERVER))
                req_capsule_set_size(pill, &RMF_LOGCOOKIES, RCL_SERVER,
                                     mdt->mdt_max_cookiesize);
        rc = req_capsule_pack(pill);
        if (rc != 0)
                RETURN(rc);

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                struct mdt_client_data *mcd;

                mcd = req->rq_export->exp_mdt_data.med_mcd;
                if (mcd->mcd_last_xid == req->rq_xid) {
                        mdt_reconstruct(info);
                        RETURN(lustre_msg_get_status(req->rq_repmsg));
                }
                DEBUG_REQ(D_HA, req, "no reply for RESENT (xid "LPD64")",
                                     mcd->mcd_last_xid);
        }
        rc = mdt_reint_rec(info);

        RETURN(rc);
}

static long mdt_reint_opcode(struct mdt_thread_info *info,
                             const struct req_format **fmt)
{
        __u32 *ptr;
        long opc;

        opc = -EFAULT;
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
                rc = mdt_reint_internal(info, opc);
        } else
                rc = opc;

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
                RETURN(-EINVAL);

        if (MDT_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK))
                RETURN(-ENOMEM);

        if (fid_seq(&body->fid1) == 0) {
                /* sync the whole device */
                rc = req_capsule_pack(pill);
                if (rc == 0)
                        rc = mdt_device_sync(info);
        } else {
                /* sync an object */
                rc = mdt_unpack_req_pack_rep(info, HABEO_CORPUS|HABEO_REFERO);
                if (rc == 0) {
                        rc = mdt_object_sync(info);
                        if (rc == 0) {
                                struct md_object    *next;
                                const struct lu_fid *fid;
                                struct lu_attr      *la;

                                next = mdt_object_child(info->mti_object);
                                fid = mdt_object_fid(info->mti_object);
                                info->mti_attr.ma_need = MA_INODE;
                                rc = mo_attr_get(info->mti_ctxt, next,
                                                 &info->mti_attr);
                                la = &info->mti_attr.ma_attr;
                                if (rc == 0) {
                                        body = req_capsule_server_get(pill,
                                                                &RMF_MDT_BODY);
                                        mdt_pack_attr2body(body, la, fid);
                                }
                        }
                }
        }
        RETURN(rc);
}

static int mdt_quotacheck_handle(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

static int mdt_quotactl_handle(struct mdt_thread_info *info)
{
        return -EOPNOTSUPP;
}

/*
 * OBD PING and other handlers.
 */
static int mdt_obd_ping(struct mdt_thread_info *info)
{
        int rc;
        ENTRY;
        rc = target_handle_ping(mdt_info_req(info));
        RETURN(rc);
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
        int rc;
        struct ptlrpc_request *req;

        /*
         * info->mti_dlm_req already contains swapped and (if necessary)
         * converted dlm request.
         */
        LASSERT(info->mti_dlm_req != NULL);

        req = mdt_info_req(info);
        info->mti_fail_id = OBD_FAIL_LDLM_REPLY;
        rc = ldlm_handle_enqueue0(info->mti_mdt->mdt_namespace,
                                      req, info->mti_dlm_req, &cbs);
        return rc ? : req->rq_status;
}

static int mdt_convert(struct mdt_thread_info *info)
{
        int rc;
        struct ptlrpc_request *req;

        LASSERT(info->mti_dlm_req);
        req = mdt_info_req(info);
        rc = ldlm_handle_convert0(req, info->mti_dlm_req);
        return rc ? : req->rq_status;
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
 * sec context handlers
 */
static int mdt_sec_ctx_handle(struct mdt_thread_info *info)
{
        return 0;
}

/* issues dlm lock on passed @ns, @f stores it lock handle into @lh. */
int fid_lock(struct ldlm_namespace *ns, const struct lu_fid *f,
             struct lustre_handle *lh, ldlm_mode_t mode,
             ldlm_policy_data_t *policy,
             struct ldlm_res_id *res_id)
{
        int flags = 0; /*XXX: LDLM_FL_LOCAL_ONLY?*/
        int rc;

        LASSERT(ns != NULL);
        LASSERT(lh != NULL);
        LASSERT(f != NULL);

        rc = ldlm_cli_enqueue_local(ns, *fid_build_res_name(f, res_id),
                                    LDLM_IBITS, policy, mode, &flags,
                                    ldlm_blocking_ast, ldlm_completion_ast,
                                    NULL, NULL, 0, NULL, lh);
        return rc == ELDLM_OK ? 0 : -EIO;
}

/* just call ldlm_lock_decref() if decref,
 * else we only call ptlrpc_save_lock() to save this lock in req.
 * when transaction committed, req will be released, and lock will, too */
void fid_unlock(struct ptlrpc_request *req, const struct lu_fid *f,
                struct lustre_handle *lh, ldlm_mode_t mode, int decref)
{
        {
        /* FIXME: this is debug stuff, remove it later. */
                struct ldlm_lock *lock = ldlm_handle2lock(lh);
                if (!lock) {
                        CERROR("invalid lock handle "LPX64, lh->cookie);
                        LBUG();
                }
                LASSERT(fid_res_name_eq(f, &lock->l_resource->lr_name));
                LDLM_LOCK_PUT(lock);
        }
        if (decref)
                ldlm_lock_decref(lh, mode);
        else
                ptlrpc_save_lock(req, lh, mode);
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
        struct mdt_object *m;
        ENTRY;

        o = lu_object_find(ctxt, d->mdt_md_dev.md_lu_dev.ld_site, f);
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

        policy->l_inodebits.bits = ibits;

        rc = fid_lock(ns, mdt_object_fid(o), &lh->mlh_lh, lh->mlh_mode,
                      policy, res_id);
        RETURN(rc);
}

void mdt_object_unlock(struct mdt_thread_info *info, struct mdt_object *o,
                       struct mdt_lock_handle *lh, int decref)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        ENTRY;

        if (lustre_handle_is_used(&lh->mlh_lh)) {
                fid_unlock(req, mdt_object_fid(o),
                           &lh->mlh_lh, lh->mlh_mode, decref);
                lh->mlh_lh.cookie = 0;
        }
        EXIT;
}

struct mdt_object *mdt_object_find_lock(struct mdt_thread_info *info,
                                        const struct lu_fid *f,
                                        struct mdt_lock_handle *lh,
                                        __u64 ibits)
{
        struct mdt_object *o;

        o = mdt_object_find(info->mti_ctxt, info->mti_mdt, f);
        if (!IS_ERR(o)) {
                int rc;

                rc = mdt_object_lock(info, o, lh, ibits);
                if (rc != 0) {
                        mdt_object_put(info->mti_ctxt, o);
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
        mdt_object_put(info->mti_ctxt, o);
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
        const struct mdt_body   *body;
        struct mdt_object       *obj;
        const struct lu_context *ctx;
        struct req_capsule      *pill;
        int                     rc;

        ctx = info->mti_ctxt;
        pill = &info->mti_pill;

        body = info->mti_body = req_capsule_client_get(pill, &RMF_MDT_BODY);
        if (body != NULL) {
                if (fid_is_sane(&body->fid1)) {
                        obj = mdt_object_find(ctx, info->mti_mdt, &body->fid1);
                        if (!IS_ERR(obj)) {
                                if ((flags & HABEO_CORPUS) &&
                                    !lu_object_exists(&obj->mot_obj.mo_lu)) {
                                        mdt_object_put(ctx, obj);
                                        rc = -ENOENT;
                                } else {
                                        info->mti_object = obj;
                                        rc = 0;
                                }
                        } else
                                rc = PTR_ERR(obj);
                } else {
                        CERROR("Invalid fid: "DFID"\n", PFID(&body->fid1));
                        rc = -EINVAL;
                }
        } else
                rc = -EFAULT;
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

/*
 * Invoke handler for this request opc. Also do necessary preprocessing
 * (according to handler ->mh_flags), and post-processing (setting of
 * ->last_{xid,committed}).
 */
static int mdt_req_handle(struct mdt_thread_info *info,
                          struct mdt_handler *h, struct ptlrpc_request *req)
{
        int   rc;
        __u32 flags;

        ENTRY;

        LASSERT(h->mh_act != NULL);
        LASSERT(h->mh_opc == lustre_msg_get_opc(req->rq_reqmsg));
        LASSERT(current->journal_info == NULL);

        DEBUG_REQ(D_INODE, req, "%s", h->mh_name);

        if (h->mh_fail_id != 0)
                MDT_FAIL_RETURN(h->mh_fail_id, 0);

        rc = 0;
        flags = h->mh_flags;
        LASSERT(ergo(flags & (HABEO_CORPUS|HABEO_REFERO), h->mh_fmt != NULL));

        if (h->mh_fmt != NULL) {
                req_capsule_set(&info->mti_pill, h->mh_fmt);
                rc = mdt_unpack_req_pack_rep(info, flags);
        }

        if (rc == 0 && flags & MUTABOR &&
            req->rq_export->exp_connect_flags & OBD_CONNECT_RDONLY)
                rc = -EROFS;

        if (rc == 0 && flags & HABEO_CLAVIS) {
                struct ldlm_request *dlm_req;

                LASSERT(h->mh_fmt != NULL);

                dlm_req = req_capsule_client_get(&info->mti_pill,&RMF_DLM_REQ);
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

        if (rc == 0)
                /*
                 * Process request.
                 */
                rc = h->mh_act(info);
        /*
         * XXX result value is unconditionally shoved into ->rq_status
         * (original code sometimes placed error code into ->rq_status, and
         * sometimes returned it to the
         * caller). ptlrpc_server_handle_request() doesn't check return value
         * anyway.
         */
        req->rq_status = rc;
        rc = 0;
        LASSERT(current->journal_info == NULL);

        if (flags & HABEO_CLAVIS && info->mti_mdt->mdt_opts.mo_compat_resname) {
                struct ldlm_reply *dlmrep;

                dlmrep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
                if (dlmrep != NULL)
                        rc = mdt_lock_reply_compat(info->mti_mdt, dlmrep);
        }

        /* If we're DISCONNECTing, the mdt_export_data is already freed */

#if 0
        if (h->mh_opc != MDS_DISCONNECT &&
            h->mh_opc != MDS_READPAGE &&
            h->mh_opc != LDLM_ENQUEUE) {
                mdt_finish_reply(info, req->rq_status);
        }
#endif
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

        memset(info, 0, sizeof(*info));

        info->mti_rep_buf_nr = ARRAY_SIZE(info->mti_rep_buf_size);
        for (i = 0; i < ARRAY_SIZE(info->mti_rep_buf_size); i++)
                info->mti_rep_buf_size[i] = -1;

        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_init(&info->mti_lh[i]);

        info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
        info->mti_ctxt = req->rq_svc_thread->t_ctx;
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
                mdt_object_put(info->mti_ctxt, info->mti_object);
                info->mti_object = NULL;
        }
        for (i = 0; i < ARRAY_SIZE(info->mti_lh); i++)
                mdt_lock_handle_fini(&info->mti_lh[i]);
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
static int mdt_recovery(struct ptlrpc_request *req)
{
        int recovering;
        int abort_recovery;
        struct obd_device *obd;

        ENTRY;

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT:
        case SEC_CTX_INIT:
        case SEC_CTX_INIT_CONT:
        case SEC_CTX_FINI:
                RETURN(+1);
        }

        if (req->rq_export == NULL) {
                CERROR("operation %d on unconnected MDS from %s\n",
                       lustre_msg_get_opc(req->rq_reqmsg),
                       libcfs_id2str(req->rq_peer));
                req->rq_status = -ENOTCONN;
                RETURN(-ENOTCONN);
        }

        /* sanity check: if the xid matches, the request must be marked as a
         * resent or replayed */
        if (req->rq_xid == req_exp_last_xid(req) ||
            req->rq_xid == req_exp_last_close_xid(req)) {
                if (!(lustre_msg_get_flags(req->rq_reqmsg) &
                      (MSG_RESENT | MSG_REPLAY))) {
                        CERROR("rq_xid "LPU64" matches last_xid, "
                                "expected RESENT flag\n", req->rq_xid);
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
        abort_recovery = obd->obd_abort_recovery;
        recovering = obd->obd_recovering;
        spin_unlock_bh(&obd->obd_processing_task_lock);
        if (abort_recovery) {
                target_abort_recovery(obd);
        } else if (recovering) {
                int rc;
                int should_process;

                rc = mds_filter_recovery_request(req, obd, &should_process);
                if (rc != 0 || !should_process) {
                        RETURN(rc);
                }
        }
        RETURN(+1);
}

static int mdt_reply(struct ptlrpc_request *req, int rc,
                     struct mdt_thread_info *info)
{
        struct obd_device *obd;
        ENTRY;

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (lustre_msg_get_opc(req->rq_reqmsg) != OBD_PING)
                        DEBUG_REQ(D_ERROR, req, "Unexpected MSG_LAST_REPLAY");

                obd = req->rq_export != NULL ? req->rq_export->exp_obd : NULL;
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        RETURN(target_queue_final_reply(req, rc));
                } else {
                        /* Lost a race with recovery; let the error path
                         * DTRT. */
                        rc = req->rq_status = -ENOTCONN;
                }
        }
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
                rc = mdt_recovery(req);
                switch (rc) {
                case +1:
                        h = mdt_handler_find(lustre_msg_get_opc(msg),
                                             supported);
                        if (h != NULL)
                                rc = mdt_req_handle(info, h, req);
                        else {
                                req->rq_status = -ENOTSUPP;
                                rc = ptlrpc_error(req);
                                break;
                        }
                        /* fall through */
                case 0:
                        rc = mdt_reply(req, rc, info);
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
        struct lu_context      *ctx;
        struct mdt_thread_info *info;
        int                     rc;
        ENTRY;

        ctx = req->rq_svc_thread->t_ctx;
        LASSERT(ctx != NULL);
        LASSERT(ctx->lc_thread == req->rq_svc_thread);
        info = lu_context_key_get(ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        mdt_thread_info_init(req, info);

        rc = mdt_handle0(req, info, supported);

        mdt_thread_info_fini(info);
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

static int mdt_intent_getattr(enum mdt_it_code opcode,
                              struct mdt_thread_info *info,
                              struct ldlm_lock **lockp,
                              int flags)
{
        struct ldlm_lock       *old_lock = *lockp;
        struct ldlm_lock       *new_lock = NULL;
        struct ptlrpc_request  *req = mdt_info_req(info);
        struct ldlm_reply      *ldlm_rep;
        struct mdt_lock_handle  tmp_lock;
        struct mdt_lock_handle *lhc = &tmp_lock;
        __u64                   child_bits;

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
        }

        ldlm_rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        mdt_set_disposition(info, ldlm_rep, DISP_IT_EXECD);

        ldlm_rep->lock_policy_res2 =
                mdt_getattr_name_lock(info, lhc, child_bits, ldlm_rep);
        mdt_shrink_reply(info, DLM_REPLY_REC_OFF + 1);

        if (mdt_get_disposition(ldlm_rep, DISP_LOOKUP_NEG))
                ldlm_rep->lock_policy_res2 = 0;
        if (!mdt_get_disposition(ldlm_rep, DISP_LOOKUP_POS) ||
                    ldlm_rep->lock_policy_res2) {
                RETURN(ELDLM_LOCK_ABORTED);
        }

        new_lock = ldlm_handle2lock(&lhc->mlh_lh);
        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY))
                RETURN(0);

        LASSERTF(new_lock != NULL, "op %d lockh "LPX64"\n",
                 opcode, lhc->mlh_lh.cookie);

        *lockp = new_lock;

        /* FIXME:This only happens when MDT can handle RESENT */
        if (new_lock->l_export == req->rq_export) {
                /* Already gave this to the client, which means that we
                 * reconstructed a reply. */
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) &
                        MSG_RESENT);
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /* TODO:
         * These are copied from mds/hander.c, and should be factored into
         * ldlm module in order to share these code, and be easy for merge.
         */

        /* Fixup the lock to be given to the client */
        lock_res_and_lock(new_lock);
        new_lock->l_readers = 0;
        new_lock->l_writers = 0;

        new_lock->l_export = class_export_get(req->rq_export);
        list_add(&new_lock->l_export_chain,
                 &new_lock->l_export->exp_ldlm_data.led_held_locks);

        new_lock->l_blocking_ast = old_lock->l_blocking_ast;
        new_lock->l_completion_ast = old_lock->l_completion_ast;

        new_lock->l_remote_handle = old_lock->l_remote_handle;

        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        unlock_res_and_lock(new_lock);
        LDLM_LOCK_PUT(new_lock);

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

        rc = mdt_reint_internal(info, opc);

        rep = req_capsule_server_get(&info->mti_pill, &RMF_DLM_REP);
        if (rep == NULL)
                RETURN(-EFAULT);
        rep->lock_policy_res2 = rc;

        mdt_set_disposition(info, rep, DISP_IT_EXECD);
#if 0
        mdt_finish_reply(info, rc);
#endif
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

        info = lu_context_key_get(req->rq_svc_thread->t_ctx, &mdt_thread_key);
        LASSERT(info != NULL);
        pill = &info->mti_pill;
        LASSERT(pill->rc_req == req);

        if (req->rq_reqmsg->lm_bufcount > DLM_INTENT_IT_OFF) {
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
        
        if (ls && ls->ls_control_seq) {
                seq_server_fini(ls->ls_control_seq, ctx);
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

static int mdt_seq_init(const struct lu_context *ctx,
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
                                     ctx);

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
                                     ls->ls_control_seq, ctx);
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
                             ctx);
        if (rc)
                GOTO(out_seq_fini, rc = -ENOMEM);

        /* Assign seq-controller client to local seq-server. */
        if (ls->ls_node_id == 0) {
                LASSERT(ls->ls_client_seq != NULL);
                
                rc = seq_server_set_cli(ls->ls_server_seq,
                                        ls->ls_client_seq,
                                        ctx);
        }
        
        EXIT;
out_seq_fini:
        if (rc)
                mdt_seq_fini(ctx, m);

        return rc;
}

/*
 * Init client sequence manager which is used by local MDS to talk to sequence
 * controller on remote node.
 */
static int mdt_seq_init_cli(const struct lu_context *ctx,
                            struct mdt_device *m,
                            struct lustre_cfg *cfg)
{
        struct lu_site    *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        struct obd_device *mdc;
        struct obd_uuid   *uuidp, *mdcuuidp;
        char              *uuid_str, *mdc_uuid_str;
        int               rc;
        int               index;
        struct mdt_thread_info *info;
        char *p, *index_string = lustre_cfg_string(cfg, 2);
        ENTRY;

        info = lu_context_key_get(ctx, &mdt_thread_key);
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

                rc = obd_connect(ctx, &conn, mdc, &mdc->obd_uuid, NULL);

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
                                                     prefix, NULL, NULL);
                                OBD_FREE(prefix, MAX_OBD_NAME + 5);
                        } else
                                rc = -ENOMEM;

                        if (rc)
                                RETURN(rc);

                        LASSERT(ls->ls_server_seq != NULL);

                        rc = seq_server_set_cli(ls->ls_server_seq,
                                                ls->ls_client_seq,
                                                ctx);
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
static int mdt_fld_fini(const struct lu_context *ctx,
                        struct mdt_device *m)
{
        struct lu_site *ls = m->mdt_md_dev.md_lu_dev.ld_site;
        ENTRY;

        if (ls && ls->ls_server_fld) {
                fld_server_fini(ls->ls_server_fld, ctx);
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

static int mdt_fld_init(const struct lu_context *ctx,
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
                             m->mdt_bottom, uuid, ctx);
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
                mdt_fld_fini(ctx, m);
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

static void mdt_stack_fini(const struct lu_context *ctx,
                           struct mdt_device *m, struct lu_device *top)
{
        struct lu_device        *d = top, *n;
        struct lustre_cfg_bufs  *bufs;
        struct lustre_cfg       *lcfg;
        struct mdt_thread_info  *info;
        ENTRY;

        info = lu_context_key_get(ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        bufs = &info->mti_u.bufs;
        /* process cleanup */
        lustre_cfg_bufs_reset(bufs, NULL);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, bufs);
        if (!lcfg) {
                CERROR("Cannot alloc lcfg!\n");
                return;
        }
        LASSERT(top);
        top->ld_ops->ldo_process_config(ctx, top, lcfg);
        lustre_cfg_free(lcfg);

        lu_site_purge(ctx, top->ld_site, ~0);
        while (d != NULL) {
                struct obd_type *type;
                struct lu_device_type *ldt = d->ld_type;

                /* each fini() returns next device in stack of layers
                 * * so we can avoid the recursion */
                n = ldt->ldt_ops->ldto_device_fini(ctx, d);
                lu_device_put(d);
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
        ENTRY;
        
        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("Unknown type: '%s'\n", typename);
                GOTO(out, rc = -ENODEV);
        }

        rc = lu_context_refill(ctx);
        if (rc != 0) {
                CERROR("Failure to refill context: '%d'\n", rc);
                GOTO(out_type, rc);
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
        struct md_device  *md;
        int rc;
        ENTRY;

        /* init the stack */
        tmp = mdt_layer_setup(ctx, LUSTRE_OSD_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                RETURN(PTR_ERR(tmp));
        }
        m->mdt_bottom = lu2dt_dev(tmp);
        d = tmp;
        tmp = mdt_layer_setup(ctx, LUSTRE_MDD_NAME, d, cfg);
        if (IS_ERR(tmp)) {
                GOTO(out, rc = PTR_ERR(tmp));
        }
        d = tmp;
        md = lu2md_dev(d);

        tmp = mdt_layer_setup(ctx, LUSTRE_CMM_NAME, d, cfg);
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
        target_cleanup_recovery(m->mdt_md_dev.md_lu_dev.ld_obd);
        ping_evictor_stop();
        mdt_stop_ptlrpc_service(m);

        if (m->mdt_namespace != NULL) {
                ldlm_namespace_free(m->mdt_namespace, 0);
                m->mdt_namespace = NULL;
        }

        mdt_seq_fini(ctx, m);
        mdt_seq_fini_cli(m);

        mdt_fld_fini(ctx, m);

        mdt_fs_cleanup(ctx, m);
        /* finish the stack */
        mdt_stack_fini(ctx, m, md2lu_dev(m->mdt_child));

        if (ls) {
                lu_site_fini(ls);
                OBD_FREE_PTR(ls);
                d->ld_site = NULL;
        }
        LASSERT(atomic_read(&d->ld_ref) == 0);
        md_device_fini(&m->mdt_md_dev);

        EXIT;
}

int mdt_postrecov(const struct lu_context *, struct mdt_device *);

static int mdt_init0(const struct lu_context *ctx, struct mdt_device *m,
                     struct lu_device_type *ldt, struct lustre_cfg *cfg)
{
        struct mdt_thread_info *info;
        struct obd_device      *obd;
        const char             *dev = lustre_cfg_string(cfg, 0);
        const char             *num = lustre_cfg_string(cfg, 2);
        struct lu_site         *s;
        int                     rc;
        ENTRY;

        info = lu_context_key_get(ctx, &mdt_thread_key);
        LASSERT(info != NULL);

        obd = class_name2obd(dev);
        LASSERT(obd);

        spin_lock_init(&m->mdt_transno_lock);
        
        m->mdt_max_mdsize = MAX_MD_SIZE;
        m->mdt_max_cookiesize = sizeof(struct llog_cookie);

        spin_lock_init(&m->mdt_epoch_lock);
        /* Temporary. should parse mount option. */
        m->mdt_opts.mo_user_xattr = 0;
        m->mdt_opts.mo_acl = 0;
        m->mdt_opts.mo_compat_resname = 0;
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

        snprintf(info->mti_u.ns_name, sizeof info->mti_u.ns_name,
                 LUSTRE_MDT_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(info->mti_u.ns_name,
                                              LDLM_NAMESPACE_SERVER);
        if (m->mdt_namespace == NULL)
                GOTO(err_fini_seq, rc = -ENOMEM);

        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);

        rc = mdt_start_ptlrpc_service(m);
        if (rc)
                GOTO(err_free_ns, rc);

        ping_evictor_start();
        rc = mdt_fs_setup(ctx, m);
        if (rc)
                GOTO(err_stop_service, rc);
        if(obd->obd_recovering == 0)
                mdt_postrecov(ctx, m);
        RETURN(0);

err_stop_service:
        mdt_stop_ptlrpc_service(m);
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

        md_device_fini(&m->mdt_md_dev);
        return (rc);
}

/* used by MGS to process specific configurations */
static int mdt_process_config(const struct lu_context *ctx,
                              struct lu_device *d, struct lustre_cfg *cfg)
{
        struct mdt_device *m = mdt_dev(d);
        struct md_device *md_next  = m->mdt_child;
        struct lu_device *next = md2lu_dev(md_next);
        int err;
        ENTRY;

        switch (cfg->lcfg_command) {
        case LCFG_ADD_MDC:
                /*
                 * Add mdc hook to get first MDT uuid and connect it to
                 * ls->controller to use for seq manager.
                 */
                err = mdt_seq_init_cli(ctx, mdt_dev(d), cfg);
                if (err) {
                        CERROR("can't initialize controller export, "
                               "rc %d\n", err);
                }
        default:
                /* others are passed further */
                err = next->ld_ops->ldo_process_config(ctx, next, cfg);
                break;
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
        int                rc = 0;
        ENTRY;

        CDEBUG(D_INFO, "object init, fid = "DFID"\n",
               PFID(lu_object_fid(o)));

        under = &d->mdt_child->md_lu_dev;
        below = under->ld_ops->ldo_object_alloc(ctxt, o->lo_header, under);
        if (below != NULL) {
                lu_object_add(o, below);
        } else
                rc = -ENOMEM;
        RETURN(rc);
}

static void mdt_object_free(const struct lu_context *ctxt, struct lu_object *o)
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

static int mdt_object_print(const struct lu_context *ctxt, void *cookie,
                            lu_printer_t p, const struct lu_object *o)
{
        return (*p)(ctxt, cookie, LUSTRE_MDT_NAME"-object@%p", o);
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
static int mdt_obd_connect(const struct lu_context *ctx,
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

        LASSERT(ctx != NULL);
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
                        rc = mdt_client_new(ctx, mdt, med);
                        if (rc != 0)
                                OBD_FREE_PTR(mcd);
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
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        //ldlm_cancel_locks_for_export(exp);

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
        struct lu_context       ctxt;
        struct md_attr         *ma;
        int rc = 0;
        ENTRY;

        med = &export->exp_mdt_data;

        target_destroy_export(export);

        if (obd_uuid_equals(&export->exp_client_uuid, &obd->obd_uuid))
                RETURN(0);

        mdt = mdt_dev(obd->obd_lu_dev);
        LASSERT(mdt != NULL);

        rc = lu_context_init(&ctxt, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);

        lu_context_enter(&ctxt);

        info = lu_context_key_get(&ctxt, &mdt_thread_key);
        LASSERT(info != NULL);
        memset(info, 0, sizeof *info);

        ma = &info->mti_attr;
        ma->ma_lmm_size = mdt->mdt_max_mdsize;
        ma->ma_cookie_size = mdt->mdt_max_cookiesize;
        OBD_ALLOC(ma->ma_lmm, ma->ma_lmm_size);
        OBD_ALLOC(ma->ma_cookie, ma->ma_cookie_size);

        if (ma->ma_lmm == NULL || ma->ma_cookie == NULL)
                GOTO(out, rc = -ENOMEM);
        ma->ma_need = MA_LOV | MA_COOKIE;

        /* Close any open files (which may also cause orphan unlinking). */
        spin_lock(&med->med_open_lock);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mdt_file_data *mfd =
                        list_entry(tmp, struct mdt_file_data, mfd_list);
                struct mdt_object *o = mfd->mfd_object;

                /* Remove mfd handle so it can't be found again.
                 * We are consuming the mfd_list reference here. */
                class_handle_unhash(&mfd->mfd_handle);
                list_del_init(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);
                mdt_mfd_close(&ctxt, mdt, mfd, ma);
                /* TODO: if we close the unlinked file,
                 * we need to remove it's objects from OST */
                mdt_object_put(&ctxt, o);
                spin_lock(&med->med_open_lock);
        }
        spin_unlock(&med->med_open_lock);
        mdt_client_del(&ctxt, mdt, med);

out:
        if (ma->ma_lmm)
                OBD_FREE(ma->ma_lmm, ma->ma_lmm_size);
        if (ma->ma_cookie)
                OBD_FREE(ma->ma_cookie, ma->ma_cookie_size);
        lu_context_exit(&ctxt);
        lu_context_fini(&ctxt);

        RETURN(rc);
}

static int mdt_upcall(const struct lu_context *ctx, struct md_device *md,
                      enum md_upcall_event ev)
{
        struct mdt_device *m = mdt_dev(&md->md_lu_dev);
        struct md_device  *next  = m->mdt_child;
        int rc = 0;
        ENTRY;

        switch (ev) {
                case MD_LOV_SYNC:
                        rc = next->md_ops->mdo_get_maxsize(ctx, next,
                                        &m->mdt_max_mdsize,
                                        &m->mdt_max_cookiesize);
                        CDEBUG(D_INFO, "get max mdsize %d max cookiesize %d\n",
                                     m->mdt_max_mdsize, m->mdt_max_cookiesize);
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
        struct lu_context ctxt;
        struct mdt_device *mdt = mdt_dev(exp->exp_obd->obd_lu_dev);
        struct dt_device *dt = mdt->mdt_bottom;
        int rc;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);
        rc = lu_context_init(&ctxt, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);
        lu_context_enter(&ctxt);
        if (cmd == OBD_IOC_SYNC || cmd == OBD_IOC_SET_READONLY) {
                rc = dt->dd_ops->dt_sync(&ctxt, dt);
                if (cmd == OBD_IOC_SET_READONLY)
                        dt->dd_ops->dt_ro(&ctxt, dt);
        } else
                rc = -EOPNOTSUPP;
        lu_context_exit(&ctxt);
        lu_context_fini(&ctxt);
        RETURN(rc);
}

int mdt_postrecov(const struct lu_context *ctx, struct mdt_device *mdt)
{
        struct lu_device *ld = md2lu_dev(mdt->mdt_child);
        int rc;
        ENTRY;
        rc = ld->ld_ops->ldo_recovery_complete(ctx, ld);
        RETURN(rc);
}

int mdt_obd_postrecov(struct obd_device *obd)
{
        struct lu_context ctxt;
        int rc;

        rc = lu_context_init(&ctxt, LCT_MD_THREAD);
        if (rc)
                RETURN(rc);
        lu_context_enter(&ctxt);
        rc = mdt_postrecov(&ctxt, mdt_dev(obd->obd_lu_dev));
        lu_context_exit(&ctxt);
        lu_context_fini(&ctxt);
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

static struct lu_device* mdt_device_fini(const struct lu_context *ctx,
                                         struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);

        mdt_fini(ctx, m);
        RETURN(NULL);
}

static void mdt_device_free(const struct lu_context *ctx, struct lu_device *d)
{
        struct mdt_device *m = mdt_dev(d);

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
                int rc;

                l = &m->mdt_md_dev.md_lu_dev;
                rc = mdt_init0(ctx, m, t, cfg);
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
static void *mdt_thread_init(const struct lu_context *ctx,
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

static void mdt_thread_fini(const struct lu_context *ctx,
                            struct lu_context_key *key, void *data)
{
        struct mdt_thread_info *info = data;
        OBD_FREE_PTR(info);
}

struct lu_context_key mdt_thread_key = {
        .lct_tags = LCT_MD_THREAD,
        .lct_init = mdt_thread_init,
        .lct_fini = mdt_thread_fini
};

static void *mdt_txn_init(const struct lu_context *ctx,
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

static void mdt_txn_fini(const struct lu_context *ctx,
                            struct lu_context_key *key, void *data)
{
        struct mdt_txn_info *txi = data;
        OBD_FREE_PTR(txi);
}

struct lu_context_key mdt_txn_key = {
        .lct_tags = LCT_TX_HANDLE,
        .lct_init = mdt_txn_init,
        .lct_fini = mdt_txn_fini
};


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

static struct lprocfs_vars lprocfs_mdt_obd_vars[] = {
        { 0 }
};

static struct lprocfs_vars lprocfs_mdt_module_vars[] = {
        { 0 }
};

LPROCFS_INIT_VARS(mdt, lprocfs_mdt_module_vars, lprocfs_mdt_obd_vars);

static int __init mdt_mod_init(void)
{
        int rc;
        struct lprocfs_static_vars lvars;

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
        DEF_HNDL(FLD, QUERY, _NET, flags, name, fn, &RQF_SEQ_ ## name)
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
DEF_MDT_HNDL_F(HABEO_CORPUS|HABEO_REFERO|MUTABOR,
                                          SETXATTR,     mdt_setxattr),
DEF_MDT_HNDL_F(HABEO_CORPUS,              GETXATTR,     mdt_getxattr),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, STATFS,       mdt_statfs),
DEF_MDT_HNDL_F(0                        |MUTABOR,
                                          REINT,        mdt_reint),
DEF_MDT_HNDL_F(HABEO_CORPUS             , CLOSE,        mdt_close),
DEF_MDT_HNDL_0(0,                         DONE_WRITING, mdt_done_writing),
DEF_MDT_HNDL_F(0           |HABEO_REFERO, PIN,          mdt_pin),
DEF_MDT_HNDL_0(0,                         SYNC,         mdt_sync),
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
