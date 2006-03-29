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

/*
 * LUSTRE_VERSION_CODE
 */
#include <linux/lustre_ver.h>
/*
 * struct OBD_{ALLOC,FREE}*()
 * OBD_FAIL_CHECK
 */
#include <linux/obd_support.h>

#include <linux/lu_object.h>

#include "mdt.h"

/*
 * Initialized in mdt_mod_init().
 */
unsigned long mdt_num_threads;

static int mdt_getstatus(struct mdt_thread_info *info,
			 struct ptlrpc_request *req, int offset)
{
        struct md_device *mdd  = info->mti_mdt->mdt_child;
	struct mds_body  *body;
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
		result = mdd->md_ops->mdo_root_get(mdd, &body->fid1);
	}

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
        RETURN(result);
}

/*
 * struct obd_device
 */
#include <linux/obd.h>
/*
 * struct class_connect()
 */
#include <linux/obd_class.h>
/*
 * struct obd_export
 */
#include <linux/lustre_export.h>
/*
 * struct mds_client_data
 */
#include <../mds/mds_internal.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_commit_confd.h>
#include <linux/lustre_quota.h>
#include <linux/lustre_disk.h>
#include <linux/lustre_ver.h>

static int mds_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data);
static int mds_postsetup(struct obd_device *obd);
static int mds_cleanup(struct obd_device *obd);

/* Assumes caller has already pushed into the kernel filesystem context */
static int mds_sendpage(struct ptlrpc_request *req, struct file *file,
                        loff_t offset, int count)
{
        struct ptlrpc_bulk_desc *desc;
        struct l_wait_info lwi;
        struct page **pages;
        int rc = 0, npages, i, tmpcount, tmpsize = 0;
        ENTRY;

        LASSERT((offset & (PAGE_SIZE - 1)) == 0); /* I'm dubious about this */

        npages = (count + PAGE_SIZE - 1) >> PAGE_SHIFT;
        OBD_ALLOC(pages, sizeof(*pages) * npages);
        if (!pages)
                GOTO(out, rc = -ENOMEM);

        desc = ptlrpc_prep_bulk_exp(req, npages, BULK_PUT_SOURCE,
                                    MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out_free, rc = -ENOMEM);

        for (i = 0, tmpcount = count; i < npages; i++, tmpcount -= tmpsize) {
                tmpsize = tmpcount > PAGE_SIZE ? PAGE_SIZE : tmpcount;

                pages[i] = alloc_pages(GFP_KERNEL, 0);
                if (pages[i] == NULL)
                        GOTO(cleanup_buf, rc = -ENOMEM);

                ptlrpc_prep_bulk_page(desc, pages[i], 0, tmpsize);
        }

        for (i = 0, tmpcount = count; i < npages; i++, tmpcount -= tmpsize) {
                tmpsize = tmpcount > PAGE_SIZE ? PAGE_SIZE : tmpcount;
                CDEBUG(D_EXT2, "reading %u@%llu from dir %lu (size %llu)\n",
                       tmpsize, offset, file->f_dentry->d_inode->i_ino,
                       file->f_dentry->d_inode->i_size);

                rc = fsfilt_readpage(req->rq_export->exp_obd, file,
                                     kmap(pages[i]), tmpsize, &offset);
                kunmap(pages[i]);

                if (rc != tmpsize)
                        GOTO(cleanup_buf, rc = -EIO);
        }

        LASSERT(desc->bd_nob == count);

        rc = ptlrpc_start_bulk_transfer(desc);
        if (rc)
                GOTO(cleanup_buf, rc);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                CERROR("obd_fail_loc=%x, fail operation rc=%d\n",
                       OBD_FAIL_MDS_SENDPAGE, rc);
                GOTO(abort_bulk, rc);
        }

        lwi = LWI_TIMEOUT(obd_timeout * HZ / 4, NULL, NULL);
        rc = l_wait_event(desc->bd_waitq, !ptlrpc_bulk_active(desc), &lwi);
        LASSERT (rc == 0 || rc == -ETIMEDOUT);

        if (rc == 0) {
                if (desc->bd_success &&
                    desc->bd_nob_transferred == count)
                        GOTO(cleanup_buf, rc);

                rc = -ETIMEDOUT; /* XXX should this be a different errno? */
        }

        DEBUG_REQ(D_ERROR, req, "bulk failed: %s %d(%d), evicting %s@%s\n",
                  (rc == -ETIMEDOUT) ? "timeout" : "network error",
                  desc->bd_nob_transferred, count,
                  req->rq_export->exp_client_uuid.uuid,
                  req->rq_export->exp_connection->c_remote_uuid.uuid);

        class_fail_export(req->rq_export);

        EXIT;
 abort_bulk:
        ptlrpc_abort_bulk (desc);
 cleanup_buf:
        for (i = 0; i < npages; i++)
                if (pages[i])
                        __free_pages(pages[i], 0);

        ptlrpc_free_bulk(desc);
 out_free:
        OBD_FREE(pages, sizeof(*pages) * npages);
 out:
        return rc;
}

/* only valid locked dentries or errors should be returned */
struct dentry *mds_fid2locked_dentry(struct obd_device *obd, struct ll_fid *fid,
                                     struct vfsmount **mnt, int lock_mode,
                                     struct lustre_handle *lockh,
                                     char *name, int namelen, __u64 lockpart)
{
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *de = mds_fid2dentry(mds, fid, mnt), *retval = de;
        struct ldlm_res_id res_id = { .name = {0} };
        int flags = 0, rc;
        ldlm_policy_data_t policy = { .l_inodebits = { lockpart} };
        ENTRY;

        if (IS_ERR(de))
                RETURN(de);

        res_id.name[0] = de->d_inode->i_ino;
        res_id.name[1] = de->d_inode->i_generation;
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, res_id,
                              LDLM_IBITS, &policy, lock_mode, &flags,
                              ldlm_blocking_ast, ldlm_completion_ast,
                              NULL, NULL, NULL, 0, NULL, lockh);
        if (rc != ELDLM_OK) {
                l_dput(de);
                retval = ERR_PTR(-EIO); /* XXX translate ldlm code */
        }

        RETURN(retval);
}

/* Look up an entry by inode number. */
/* this function ONLY returns valid dget'd dentries with an initialized inode
   or errors */
struct dentry *mds_fid2dentry(struct mds_obd *mds, struct ll_fid *fid,
                              struct vfsmount **mnt)
{
        char fid_name[32];
        unsigned long ino = fid->id;
        __u32 generation = fid->generation;
        struct inode *inode;
        struct dentry *result;

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        snprintf(fid_name, sizeof(fid_name), "0x%lx", ino);

        CDEBUG(D_DENTRY, "--> mds_fid2dentry: ino/gen %lu/%u, sb %p\n",
               ino, generation, mds->mds_obt.obt_sb);

        /* under ext3 this is neither supposed to return bad inodes
           nor NULL inodes. */
        result = ll_lookup_one_len(fid_name, mds->mds_fid_de, strlen(fid_name));
        if (IS_ERR(result))
                RETURN(result);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

        if (inode->i_generation == 0 || inode->i_nlink == 0) {
                LCONSOLE_WARN("Found inode with zero generation or link -- this"
                              " may indicate disk corruption (inode: %lu, link:"
                              " %lu, count: %d)\n", inode->i_ino,
                              (unsigned long)inode->i_nlink,
                              atomic_read(&inode->i_count));
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (generation && inode->i_generation != generation) {
                /* we didn't find the right inode.. */
                CDEBUG(D_INODE, "found wrong generation: inode %lu, link: %lu, "
                       "count: %d, generation %u/%u\n", inode->i_ino,
                       (unsigned long)inode->i_nlink,
                       atomic_read(&inode->i_count), inode->i_generation,
                       generation);
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (mnt) {
                *mnt = mds->mds_vfsmnt;
                mntget(*mnt);
        }

        RETURN(result);
}

static int mds_connect_internal(struct obd_export *exp,
                                struct obd_connect_data *data)
{
        struct obd_device *obd = exp->exp_obd;
        if (data != NULL) {
                data->ocd_connect_flags &= MDS_CONNECT_SUPPORTED;
                data->ocd_ibits_known &= MDS_INODELOCK_FULL;

                /* If no known bits (which should not happen, probably,
                   as everybody should support LOOKUP and UPDATE bits at least)
                   revert to compat mode with plain locks. */
                if (!data->ocd_ibits_known &&
                    data->ocd_connect_flags & OBD_CONNECT_IBITS)
                        data->ocd_connect_flags &= ~OBD_CONNECT_IBITS;

                if (!obd->u.mds.mds_fl_acl)
                        data->ocd_connect_flags &= ~OBD_CONNECT_ACL;

                if (!obd->u.mds.mds_fl_user_xattr)
                        data->ocd_connect_flags &= ~OBD_CONNECT_XATTR;

                exp->exp_connect_flags = data->ocd_connect_flags;
                data->ocd_version = LUSTRE_VERSION_CODE;
                exp->exp_mds_data.med_ibits_known = data->ocd_ibits_known;
        }

        if (obd->u.mds.mds_fl_acl &&
            ((exp->exp_connect_flags & OBD_CONNECT_ACL) == 0)) {
                CWARN("%s: MDS requires ACL support but client does not\n",
                      obd->obd_name);
                return -EBADE;
        }
        return 0;
}

static int mds_reconnect(struct obd_export *exp, struct obd_device *obd,
                         struct obd_uuid *cluuid,
                         struct obd_connect_data *data)
{
        int rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = mds_connect_internal(exp, data);

        RETURN(rc);
}

/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data
 * about that client, like open files, the last operation number it did
 * on the server, etc.
 */
static int mds_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data)
{
        struct obd_export *exp;
        struct mds_export_data *med;
        struct mds_client_data *mcd = NULL;
        int rc, abort_recovery;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

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

        rc = mds_connect_internal(exp, data);
        if (rc)
                GOTO(out, rc);

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd)
                GOTO(out, rc = -ENOMEM);

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

        rc = mds_client_add(obd, &obd->u.mds, med, -1);
        GOTO(out, rc);

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

static int mds_init_export(struct obd_export *exp)
{
        struct mds_export_data *med = &exp->exp_mds_data;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);
        RETURN(0);
}

static int mds_destroy_export(struct obd_export *export)
{
        struct mds_export_data *med;
        struct obd_device *obd = export->exp_obd;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        med = &export->exp_mds_data;
        target_destroy_export(export);

        if (obd_uuid_equals(&export->exp_client_uuid, &obd->obd_uuid))
                GOTO(out, 0);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* Close any open files (which may also cause orphan unlinking). */
        spin_lock(&med->med_open_lock);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mds_file_data *mfd =
                        list_entry(tmp, struct mds_file_data, mfd_list);
                struct dentry *dentry = mfd->mfd_dentry;

                /* Remove mfd handle so it can't be found again.
                 * We are consuming the mfd_list reference here. */
                mds_mfd_unlink(mfd, 0);
                spin_unlock(&med->med_open_lock);

                /* If you change this message, be sure to update
                 * replay_single:test_46 */
                CDEBUG(D_INODE|D_IOCTL, "%s: force closing file handle for "
                       "%.*s (ino %lu)\n", obd->obd_name, dentry->d_name.len,
                       dentry->d_name.name, dentry->d_inode->i_ino);
                /* child orphan sem protects orphan_dec_test and
                 * is_orphan race, mds_mfd_close drops it */
                MDS_DOWN_WRITE_ORPHAN_SEM(dentry->d_inode);
                rc = mds_mfd_close(NULL, MDS_REQ_REC_OFF, obd, mfd,
                                   !(export->exp_flags & OBD_OPT_FAILOVER));

                if (rc)
                        CDEBUG(D_INODE|D_IOCTL, "Error closing file: %d\n", rc);
                spin_lock(&med->med_open_lock);
        }
        spin_unlock(&med->med_open_lock);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
out:
        mds_client_free(export);

        RETURN(rc);
}

static int mds_disconnect(struct obd_export *exp)
{
        unsigned long irqflags;
        int rc;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        /* Disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp);
        ldlm_cancel_locks_for_export(exp);

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

        class_export_put(exp);
        RETURN(rc);
}

int mds_get_md(struct obd_device *obd, struct inode *inode, void *md,
               int *size, int lock)
{
        int rc = 0;
        int lmm_size;

        if (lock)
                down(&inode->i_sem);
        rc = fsfilt_get_md(obd, inode, md, *size, "lov");

        if (rc < 0) {
                CERROR("Error %d reading eadata for ino %lu\n",
                       rc, inode->i_ino);
        } else if (rc > 0) {
                lmm_size = rc;
                rc = mds_convert_lov_ea(obd, inode, md, lmm_size);

                if (rc == 0) {
                        *size = lmm_size;
                        rc = lmm_size;
                } else if (rc > 0) {
                        *size = rc;
                }
        } else {
                *size = 0;
        }
        if (lock)
                up(&inode->i_sem);

        RETURN (rc);
}


/* Call with lock=1 if you want mds_pack_md to take the i_sem.
 * Call with lock=0 if the caller has already taken the i_sem. */
int mds_pack_md(struct obd_device *obd, struct lustre_msg *msg, int offset,
                struct mds_body *body, struct inode *inode, int lock)
{
        struct mds_obd *mds = &obd->u.mds;
        void *lmm;
        int lmm_size;
        int rc;
        ENTRY;

        lmm = lustre_msg_buf(msg, offset, 0);
        if (lmm == NULL) {
                /* Some problem with getting eadata when I sized the reply
                 * buffer... */
                CDEBUG(D_INFO, "no space reserved for inode %lu MD\n",
                       inode->i_ino);
                RETURN(0);
        }
        lmm_size = msg->buflens[offset];

        /* I don't really like this, but it is a sanity check on the client
         * MD request.  However, if the client doesn't know how much space
         * to reserve for the MD, it shouldn't be bad to have too much space.
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CWARN("Reading MD for inode %lu of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                // RETURN(-EINVAL);
        }

        rc = mds_get_md(obd, inode, lmm, &lmm_size, lock);
        if (rc > 0) {
                if (S_ISDIR(inode->i_mode))
                        body->valid |= OBD_MD_FLDIREA;
                else
                        body->valid |= OBD_MD_FLEASIZE;
                body->eadatasize = lmm_size;
                rc = 0;
        }

        RETURN(rc);
}

#ifdef CONFIG_FS_POSIX_ACL
static
int mds_pack_posix_acl(struct inode *inode, struct lustre_msg *repmsg,
                       struct mds_body *repbody, int repoff)
{
        struct dentry de = { .d_inode = inode };
        int buflen, rc;
        ENTRY;

        LASSERT(repbody->aclsize == 0);
        LASSERT(repmsg->bufcount > repoff);

        buflen = lustre_msg_buflen(repmsg, repoff);
        if (!buflen)
                GOTO(out, 0);

        if (!inode->i_op || !inode->i_op->getxattr)
                GOTO(out, 0);

        lock_24kernel();
        rc = inode->i_op->getxattr(&de, XATTR_NAME_ACL_ACCESS,
                                   lustre_msg_buf(repmsg, repoff, buflen),
                                   buflen);
        unlock_24kernel();

        if (rc >= 0)
                repbody->aclsize = rc;
        else if (rc != -ENODATA) {
                CERROR("buflen %d, get acl: %d\n", buflen, rc);
                RETURN(rc);
        }
        EXIT;
out:
        repbody->valid |= OBD_MD_FLACL;
        return 0;
}
#else
#define mds_pack_posix_acl(inode, repmsg, repbody, repoff) 0
#endif

int mds_pack_acl(struct mds_export_data *med, struct inode *inode,
                 struct lustre_msg *repmsg, struct mds_body *repbody,
                 int repoff)
{
        return mds_pack_posix_acl(inode, repmsg, repbody, repoff);
}

static int mds_getattr_internal(struct obd_device *obd, struct dentry *dentry,
                                struct ptlrpc_request *req,
                                struct mds_body *reqbody, int reply_off)
{
        struct mds_body *body;
        struct inode *inode = dentry->d_inode;
        int rc = 0;
        ENTRY;

        if (inode == NULL)
                RETURN(-ENOENT);

        body = lustre_msg_buf(req->rq_repmsg, reply_off, sizeof(*body));
        LASSERT(body != NULL);                 /* caller prepped reply */

        mds_pack_inode2fid(&body->fid1, inode);
        mds_pack_inode2body(body, inode);
        reply_off++;

        if ((S_ISREG(inode->i_mode) && (reqbody->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (reqbody->valid & OBD_MD_FLDIREA))) {
                rc = mds_pack_md(obd, req->rq_repmsg, reply_off, body,
                                 inode, 1);

                /* If we have LOV EA data, the OST holds size, atime, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE) &&
                    !(body->valid & OBD_MD_FLDIREA))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);

                lustre_shrink_reply(req, reply_off, body->eadatasize, 0);
                if (body->eadatasize)
                        reply_off++;
        } else if (S_ISLNK(inode->i_mode) &&
                   (reqbody->valid & OBD_MD_LINKNAME) != 0) {
                char *symname = lustre_msg_buf(req->rq_repmsg, reply_off, 0);
                int len;

                LASSERT (symname != NULL);       /* caller prepped reply */
                len = req->rq_repmsg->buflens[reply_off];

                rc = inode->i_op->readlink(dentry, symname, len);
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                } else if (rc != len - 1) {
                        CERROR ("Unexpected readlink rc %d: expecting %d\n",
                                rc, len - 1);
                        rc = -EINVAL;
                } else {
                        CDEBUG(D_INODE, "read symlink dest %s\n", symname);
                        body->valid |= OBD_MD_LINKNAME;
                        body->eadatasize = rc + 1;
                        symname[rc] = 0;        /* NULL terminate */
                        rc = 0;
                }
                reply_off++;
        }

        if (reqbody->valid & OBD_MD_FLMODEASIZE) {
                struct mds_obd *mds = mds_req2mds(req);
                body->max_cookiesize = mds->mds_max_cookiesize;
                body->max_mdsize = mds->mds_max_mdsize;
                body->valid |= OBD_MD_FLMODEASIZE;
        }

        if (rc)
                RETURN(rc);

#ifdef CONFIG_FS_POSIX_ACL
        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (reqbody->valid & OBD_MD_FLACL)) {
                rc = mds_pack_acl(&req->rq_export->exp_mds_data,
                                  inode, req->rq_repmsg,
                                  body, reply_off);

                lustre_shrink_reply(req, reply_off, body->aclsize, 0);
                if (body->aclsize)
                        reply_off++;
        }
#endif

        RETURN(rc);
}

static int mds_getattr_pack_msg(struct ptlrpc_request *req, struct inode *inode,
                                int offset)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc, size[2] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*body));
        LASSERT(body != NULL);                 /* checked by caller */
        LASSERT_REQSWABBED(req, offset);       /* swabbed by caller */

        if ((S_ISREG(inode->i_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (body->valid & OBD_MD_FLDIREA))) {
                down(&inode->i_sem);
                rc = fsfilt_get_md(req->rq_export->exp_obd, inode, NULL, 0,
                                   "lov");
                up(&inode->i_sem);
                CDEBUG(D_INODE, "got %d bytes MD data for inode %lu\n",
                       rc, inode->i_ino);
                if (rc < 0) {
                        if (rc != -ENODATA) {
                                CERROR("error getting inode %lu MD: rc = %d\n",
                                       inode->i_ino, rc);
                                RETURN(rc);
                        }
                        size[bufcount] = 0;
                } else if (rc > mds->mds_max_mdsize) {
                        size[bufcount] = 0;
                        CERROR("MD size %d larger than maximum possible %u\n",
                               rc, mds->mds_max_mdsize);
                } else {
                        size[bufcount] = rc;
                }
                bufcount++;
        } else if (S_ISLNK(inode->i_mode) && (body->valid & OBD_MD_LINKNAME)) {
                if (inode->i_size + 1 != body->eadatasize)
                        CERROR("symlink size: %Lu, reply space: %d\n",
                               inode->i_size + 1, body->eadatasize);
                size[bufcount] = min_t(int, inode->i_size+1, body->eadatasize);
                bufcount++;
                CDEBUG(D_INODE, "symlink size: %Lu, reply space: %d\n",
                       inode->i_size + 1, body->eadatasize);
        }

#ifdef CONFIG_FS_POSIX_ACL
        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (body->valid & OBD_MD_FLACL)) {
                struct dentry de = { .d_inode = inode };

                size[bufcount] = 0;
                if (inode->i_op && inode->i_op->getxattr) {
                        lock_24kernel();
                        rc = inode->i_op->getxattr(&de, XATTR_NAME_ACL_ACCESS,
                                                   NULL, 0);
                        unlock_24kernel();

                        if (rc < 0) {
                                if (rc != -ENODATA) {
                                        CERROR("got acl size: %d\n", rc);
                                        RETURN(rc);
                                }
                        } else
                                size[bufcount] = rc;
                }
                bufcount++;
        }
#endif

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDS_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        rc = lustre_pack_reply(req, bufcount, size, NULL);
        if (rc) {
                CERROR("lustre_pack_reply failed: rc %d\n", rc);
                req->rq_status = rc;
                RETURN(rc);
        }

        RETURN(0);
}

static int mds_getattr_name(int offset, struct ptlrpc_request *req,
                            int child_part, struct lustre_handle *child_lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct ldlm_reply *rep = NULL;
        struct lvfs_run_ctxt saved;
        struct mds_body *body;
        struct dentry *dparent = NULL, *dchild = NULL;
        struct lvfs_ucred uc = {NULL,};
        struct lustre_handle parent_lockh;
        int namesize;
        int rc = 0, cleanup_phase = 0, resent_req = 0;
        char *name;
        ENTRY;

        LASSERT(!strcmp(obd->obd_type->typ_name, LUSTRE_MDS_NAME));

        /* Swab now, before anyone looks inside the request */

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't swab mds_body\n");
                RETURN(-EFAULT);
        }

        LASSERT_REQSWAB(req, offset + 1);
        name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (name == NULL) {
                CERROR("Can't unpack name\n");
                RETURN(-EFAULT);
        }
        namesize = lustre_msg_buflen(req->rq_reqmsg, offset + 1);

        rc = mds_init_ucred(&uc, req, offset);
        if (rc)
                GOTO(cleanup, rc);

        LASSERT (offset == MDS_REQ_REC_OFF || offset == MDS_REQ_INTENT_REC_OFF);
        /* if requests were at offset 2, the getattr reply goes back at 1 */
        if (offset == MDS_REQ_INTENT_REC_OFF) {
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                offset = 1;
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        cleanup_phase = 1; /* kernel context */
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);

        /* FIXME: handle raw lookup */
#if 0
        if (body->valid == OBD_MD_FLID) {
                struct mds_body *mds_reply;
                int size = sizeof(*mds_reply);
                ino_t inum;
                // The user requested ONLY the inode number, so do a raw lookup
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc) {
                        CERROR("out of memory\n");
                        GOTO(cleanup, rc);
                }

                rc = dir->i_op->lookup_raw(dir, name, namesize - 1, &inum);

                mds_reply = lustre_msg_buf(req->rq_repmsg, offset,
                                           sizeof(*mds_reply));
                mds_reply->fid1.id = inum;
                mds_reply->valid = OBD_MD_FLID;
                GOTO(cleanup, rc);
        }
#endif

        if (lustre_handle_is_used(child_lockh)) {
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
                resent_req = 1;
        }

        if (resent_req == 0) {
            if (name) {
                rc = mds_get_parent_child_locked(obd, &obd->u.mds, &body->fid1,
                                                 &parent_lockh, &dparent,
                                                 LCK_CR,
                                                 MDS_INODELOCK_UPDATE,
                                                 name, namesize,
                                                 child_lockh, &dchild, LCK_CR,
                                                 child_part);
            } else {
                        /* For revalidate by fid we always take UPDATE lock */
                        dchild = mds_fid2locked_dentry(obd, &body->fid2, NULL,
                                                       LCK_CR, child_lockh,
                                                       NULL, 0,
                                                       MDS_INODELOCK_UPDATE);
                        LASSERT(dchild);
                        if (IS_ERR(dchild))
                                rc = PTR_ERR(dchild);
            }
            if (rc)
                    GOTO(cleanup, rc);
        } else {
                struct ldlm_lock *granted_lock;
                struct ll_fid child_fid;
                struct ldlm_resource *res;
                DEBUG_REQ(D_DLMTRACE, req, "resent, not enqueuing new locks");
                granted_lock = ldlm_handle2lock(child_lockh);
                LASSERTF(granted_lock != NULL, LPU64"/%u lockh "LPX64"\n",
                         body->fid1.id, body->fid1.generation,
                         child_lockh->cookie);


                res = granted_lock->l_resource;
                child_fid.id = res->lr_name.name[0];
                child_fid.generation = res->lr_name.name[1];
                dchild = mds_fid2dentry(&obd->u.mds, &child_fid, NULL);
                LASSERT(!IS_ERR(dchild));
                LDLM_LOCK_PUT(granted_lock);
        }

        cleanup_phase = 2; /* dchild, dparent, locks */

        if (dchild->d_inode == NULL) {
                intent_set_disposition(rep, DISP_LOOKUP_NEG);
                /* in the intent case, the policy clears this error:
                   the disposition is enough */
                GOTO(cleanup, rc = -ENOENT);
        } else {
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        }

        if (req->rq_repmsg == NULL) {
                rc = mds_getattr_pack_msg(req, dchild->d_inode, offset);
                if (rc != 0) {
                        CERROR ("mds_getattr_pack_msg: %d\n", rc);
                        GOTO (cleanup, rc);
                }
        }

        rc = mds_getattr_internal(obd, dchild, req, body, offset);
        GOTO(cleanup, rc); /* returns the lock to the client */

 cleanup:
        switch (cleanup_phase) {
        case 2:
                if (resent_req == 0) {
                        if (rc && dchild->d_inode)
                                ldlm_lock_decref(child_lockh, LCK_CR);
                        ldlm_lock_decref(&parent_lockh, LCK_CR);
                        l_dput(dparent);
                }
                l_dput(dchild);
        case 1:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        default:
                mds_exit_ucred(&uc, mds);
                if (req->rq_reply_state == NULL) {
                        req->rq_status = rc;
                        lustre_pack_reply(req, 0, NULL, NULL);
                }
        }
        return rc;
}

static int mds_getattr(struct ptlrpc_request *req, int offset)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lvfs_run_ctxt saved;
        struct dentry *de;
        struct mds_body *body;
        struct lvfs_ucred uc = {NULL,};
        int rc = 0;
        ENTRY;

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                RETURN(-EFAULT);

        rc = mds_init_ucred(&uc, req, offset);
        if (rc)
                GOTO(out_ucred, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                rc = req->rq_status = PTR_ERR(de);
                GOTO(out_pop, rc);
        }

        rc = mds_getattr_pack_msg(req, de->d_inode, offset);
        if (rc != 0) {
                CERROR("mds_getattr_pack_msg: %d\n", rc);
                GOTO(out_pop, rc);
        }

        req->rq_status = mds_getattr_internal(obd, de, req, body, 0);

        l_dput(de);
        GOTO(out_pop, rc);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out_ucred:
        if (req->rq_reply_state == NULL) {
                req->rq_status = rc;
                lustre_pack_reply(req, 0, NULL, NULL);
        }
        mds_exit_ucred(&uc, mds);
        return rc;
}

static int mds_obd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                          unsigned long max_age)
{
        int rc;

        spin_lock(&obd->obd_osfs_lock);
        rc = fsfilt_statfs(obd, obd->u.obt.obt_sb, max_age);
        if (rc == 0)
                memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
        spin_unlock(&obd->obd_osfs_lock);

        return rc;
}

static int mds_statfs(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        int rc, size = sizeof(struct obd_statfs);
        ENTRY;

        /* This will trigger a watchdog timeout */
        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
                         (MDS_SERVICE_WATCHDOG_TIMEOUT / 1000) + 1);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK)) {
                CERROR("mds: statfs lustre_pack_reply failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        /* We call this so that we can cache a bit - 1 jiffie worth */
        rc = mds_obd_statfs(obd, lustre_msg_buf(req->rq_repmsg, 0, size),
                            jiffies - HZ);
        if (rc) {
                CERROR("mds_obd_statfs failed: rc %d\n", rc);
                GOTO(out, rc);
        }

        EXIT;
out:
        req->rq_status = rc;
        return 0;
}

static int mds_sync(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body), lustre_swab_mds_body);
        if (body == NULL)
                GOTO(out, rc = -EFAULT);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK)) {
                CERROR("fsync lustre_pack_reply failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        if (body->fid1.id == 0) {
                /* a fid of zero is taken to mean "sync whole filesystem" */
                rc = fsfilt_sync(obd, obd->u.obt.obt_sb);
                GOTO(out, rc);
        } else {
                struct dentry *de;

                de = mds_fid2dentry(mds, &body->fid1, NULL);
                if (IS_ERR(de))
                        GOTO(out, rc = PTR_ERR(de));

                /* The file parameter isn't used for anything */
                if (de->d_inode->i_fop && de->d_inode->i_fop->fsync)
                        rc = de->d_inode->i_fop->fsync(NULL, de, 1);
                if (rc == 0) {
                        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
                        mds_pack_inode2fid(&body->fid1, de->d_inode);
                        mds_pack_inode2body(body, de->d_inode);
                }

                l_dput(de);
                GOTO(out, rc);
        }
out:
        req->rq_status = rc;
        return 0;
}

/* mds_readpage does not take a DLM lock on the inode, because the client must
 * already have a PR lock.
 *
 * If we were to take another one here, a deadlock will result, if another
 * thread is already waiting for a PW lock. */
static int mds_readpage(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct vfsmount *mnt;
        struct dentry *de;
        struct file *file;
        struct mds_body *body, *repbody;
        struct lvfs_run_ctxt saved;
        int rc, size = sizeof(*repbody);
        struct lvfs_ucred uc = {NULL,};
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK))
                RETURN(-ENOMEM);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc) {
                CERROR("error packing readpage reply: rc %d\n", rc);
                GOTO(out, rc);
        }

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                GOTO (out, rc = -EFAULT);

        rc = mds_init_ucred(&uc, req, 0);
        if (rc)
                GOTO(out, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_fid2dentry(&obd->u.mds, &body->fid1, &mnt);
        if (IS_ERR(de))
                GOTO(out_pop, rc = PTR_ERR(de));

        CDEBUG(D_INODE, "ino %lu\n", de->d_inode->i_ino);

        file = dentry_open(de, mnt, O_RDONLY | O_LARGEFILE);
        /* note: in case of an error, dentry_open puts dentry */
        if (IS_ERR(file))
                GOTO(out_pop, rc = PTR_ERR(file));

        /* body->size is actually the offset -eeb */
        if ((body->size & (de->d_inode->i_blksize - 1)) != 0) {
                CERROR("offset "LPU64" not on a block boundary of %lu\n",
                       body->size, de->d_inode->i_blksize);
                GOTO(out_file, rc = -EFAULT);
        }

        /* body->nlink is actually the #bytes to read -eeb */
        if (body->nlink & (de->d_inode->i_blksize - 1)) {
                CERROR("size %u is not multiple of blocksize %lu\n",
                       body->nlink, de->d_inode->i_blksize);
                GOTO(out_file, rc = -EFAULT);
        }

        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*repbody));
        repbody->size = file->f_dentry->d_inode->i_size;
        repbody->valid = OBD_MD_FLSIZE;

        /* to make this asynchronous make sure that the handling function
           doesn't send a reply when this function completes. Instead a
           callback function would send the reply */
        /* body->size is actually the offset -eeb */
        rc = mds_sendpage(req, file, body->size, body->nlink);

out_file:
        filp_close(file, 0);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out:
        mds_exit_ucred(&uc, mds);
        req->rq_status = rc;
        RETURN(0);
}

int mds_reint(struct ptlrpc_request *req, int offset,
              struct lustre_handle *lockh)
{
        struct mds_update_record *rec; /* 116 bytes on the stack?  no sir! */
        int rc;

        OBD_ALLOC(rec, sizeof(*rec));
        if (rec == NULL)
                RETURN(-ENOMEM);

        rc = mds_update_unpack(req, offset, rec);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK)) {
                CERROR("invalid record\n");
                GOTO(out, req->rq_status = -EINVAL);
        }

        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(rec, offset, req, lockh);
 out:
        OBD_FREE(rec, sizeof(*rec));
        return rc;
}

static int mds_filter_recovery_request(struct ptlrpc_request *req,
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

static char *reint_names[] = {
        [REINT_SETATTR] "setattr",
        [REINT_CREATE]  "create",
        [REINT_LINK]    "link",
        [REINT_UNLINK]  "unlink",
        [REINT_RENAME]  "rename",
        [REINT_OPEN]    "open",
};

static int mds_set_info(struct obd_export *exp, struct ptlrpc_request *req)
{
        char *key;
        __u32 *val;
        int keylen, rc = 0;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];

        val = lustre_msg_buf(req->rq_reqmsg, 1, sizeof(*val));
        if (val == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info val");
                RETURN(-EFAULT);
        }

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc)
                RETURN(rc);
        req->rq_repmsg->status = 0;

        if (keylen < strlen("read-only") ||
            memcmp(key, "read-only", keylen) != 0)
                RETURN(-EINVAL);

        if (*val)
                exp->exp_connect_flags |= OBD_CONNECT_RDONLY;
        else
                exp->exp_connect_flags &= ~OBD_CONNECT_RDONLY;

        RETURN(0);
}

static int mds_handle_quotacheck(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl;
        int rc;
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, 0, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 0, NULL, NULL);
        if (rc) {
                CERROR("mds: out of memory while packing quotacheck reply\n");
                RETURN(rc);
        }

        req->rq_status = obd_quotacheck(req->rq_export, oqctl);
        RETURN(0);
}

static int mds_handle_quotactl(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl, *repoqc;
        int rc, size = sizeof(*repoqc);
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, 0, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        repoqc = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repoqc));

        req->rq_status = obd_quotactl(req->rq_export, oqctl);
        *repoqc = *oqctl;
        RETURN(0);
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


enum mdt_handler_flags {
	/*
	 * struct mds_body is passed in the 0-th incoming buffer.
	 */
	HABEO_CORPUS = (1 << 0)
};

struct mdt_handler {
	const char *mh_name;
	int         mh_fail_id;
	__u32       mh_opc;
	__u32       mh_flags;
	int (*mh_act)(struct mdt_thread_info *info,
                      struct ptlrpc_request *req, int offset);
};

#define DEF_HNDL(prefix, base, flags, opc, fn)			\
[prefix ## _ ## opc - prefix ## _ ## base] = {			\
	.mh_name    = #opc,					\
	.mh_fail_id = OBD_FAIL_ ## prefix ## _  ## opc ## _NET,	\
	.mh_opc     = prefix ## _  ## opc,			\
	.mh_flags   = flags,					\
	.mh_act     = fn					\
}

#define DEF_MDT_HNDL(flags, name, fn) DEF_HNDL(MDS, GETATTR, flags, name, fn)

static struct mdt_handler mdt_mds_ops[] = {
	DEF_MDT_HNDL(0,            GETSTATUS,      mdt_getstatus),

	DEF_MDT_HNDL(0,            CONNECT,        mds_connect),
	DEF_MDT_HNDL(0,            DISCONNECT,     mds_disconnect),
	DEF_MDT_HNDL(HABEO_CORPUS, GETATTR,        mds_getattr),
	DEF_MDT_HNDL(HABEO_CORPUS, GETATTR_NAME,   mds_getattr_name),
	DEF_MDT_HNDL(HABEO_CORPUS, SETXATTR,       mds_setxattr),
	DEF_MDT_HNDL(HABEO_CORPUS, GETXATTR,       mds_getxattr),
	DEF_MDT_HNDL(0,            STATFS,         mds_statfs),
	DEF_MDT_HNDL(HABEO_CORPUS, READPAGE,       mds_readpage),
	DEF_MDT_HNDL(0,            REINT,          mds_reint),
	DEF_MDT_HNDL(HABEO_CORPUS, CLOSE,          mds_close),
	DEF_MDT_HNDL(HABEO_CORPUS, DONE_WRITING,   mds_done_writing),
	DEF_MDT_HNDL(0,            PIN,            mds_pin),
	DEF_MDT_HNDL(HABEO_CORPUS, SYNC,           mds_sync),
	DEF_MDT_HNDL(0,            SET_INFO,       mds_set_info),
	DEF_MDT_HNDL(0,            QUOTACHECK,     mds_handle_quotacheck),
	DEF_MDT_HNDL(0,            QUOTACTL,       mds_handle_quotactl)
};

static struct mdt_handler mdt_obd_ops[] = {
};

static struct mdt_handler mdt_dlm_ops[] = {
};

static struct mdt_handler mdt_llog_ops[] = {
};

static struct mdt_opc_slice {
	__u32               mos_opc_start;
	int                 mos_opc_end;
	struct mdt_handler *mos_hs;
} mdt_handlers[] = {
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
	}
};

struct mdt_handler *mdt_handler_find(__u32 opc)
{
	int i;
	struct mdt_opc_slice *s;
	struct mdt_handler *h;

	h = NULL;
	for (i = 0, s = mdt_handlers; i < ARRAY_SIZE(mdt_handlers); i++, s++) {
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

struct mdt_object *mdt_object_find(struct mdt_device *d, struct ll_fid *f)
{
	struct lu_object *o;

	o = lu_object_find(d->mdt_md_dev.md_lu_dev.ld_site, f);
	if (IS_ERR(o))
		return (struct mdt_object *)o;
	else
		return container_of(o, struct mdt_object, mot_obj.mo_lu);
}

void mdt_object_put(struct mdt_object *o)
{
	lu_object_put(&o->mot_obj.mo_lu);
}

static int mdt_req_handle(struct mdt_thread_info *info,
			  struct mdt_handler *h, struct ptlrpc_request *req,
			  int shift)
{
	int result;
        int off;

	ENTRY;

	LASSERT(h->mh_act != NULL);
	LASSERT(h->mh_opc == req->rq_reqmsg->opc);

	DEBUG_REQ(D_INODE, req, "%s", h->mh_name);

	if (h->mh_fail_id != 0)
		OBD_FAIL_RETURN(h->mh_fail_id, 0);

	off = MDS_REQ_REC_OFF + shift;
        result = 0;
	if (h->mh_flags & HABEO_CORPUS) {
		info->mti_body = lustre_swab_reqbuf(req, off,
                                                    sizeof *info->mti_body,
						    lustre_swab_mds_body);
		if (info->mti_body == NULL) {
			CERROR("Can't unpack body\n");
			result = req->rq_status = -EFAULT;
		}
		info->mti_object = mdt_object_find(info->mti_mdt,
						   &info->mti_body->fid1);
		if (IS_ERR(info->mti_object))
			result = PTR_ERR(info->mti_object);
	}
	if (result == 0)
		result = h->mh_act(info, req, off);
	/*
	 * XXX result value is unconditionally shoved into ->rq_status
	 * (original code sometimes placed error code into ->rq_status, and
	 * sometimes returned it to the
	 * caller). ptlrpc_server_handle_request() doesn't check return value
	 * anyway.
	 */
	req->rq_status = result;
	RETURN(result);
}

static void mdt_thread_info_init(struct mdt_thread_info *info)
{
	memset(info, 0, sizeof *info);
	info->mti_fail_id = OBD_FAIL_MDS_ALL_REPLY_NET;
	/*
	 * Poison size array.
	 */
	for (info->mti_rep_buf_nr = 0;
	     info->mti_rep_buf_nr < MDT_REP_BUF_NR_MAX; info->mti_rep_buf_nr++)
		info->mti_rep_buf_size[info->mti_rep_buf_nr] = ~0;
}

static void mdt_thread_info_fini(struct mdt_thread_info *info)
{
	if (info->mti_object != NULL) {
		mdt_object_put(info->mti_object);
		info->mti_object = NULL;
	}
}

static int mdt_handle0(struct ptlrpc_request *req, struct mdt_thread_info *info)
{
        int rc;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
	struct mdt_handler *h;

        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);

        rc = mds_msg_check_version(req->rq_reqmsg);
        if (rc) {
                CERROR(LUSTRE_MDT0_NAME" drops mal-formed request\n");
                RETURN(rc);
        }

        /* XXX identical to OST */
        if (req->rq_reqmsg->opc != MDS_CONNECT) {
                struct mds_export_data *med;
                int recovering, abort_recovery;

                if (req->rq_export == NULL) {
                        CERROR("operation %d on unconnected MDS from %s\n",
                               req->rq_reqmsg->opc,
                               libcfs_id2str(req->rq_peer));
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mds_data;
                obd = req->rq_export->exp_obd;
                mds = &obd->u.mds;

                /* sanity check: if the xid matches, the request must
                 * be marked as a resent or replayed */
                if (req->rq_xid == med->med_mcd->mcd_last_xid)
                        LASSERTF(lustre_msg_get_flags(req->rq_reqmsg) &
                                 (MSG_RESENT | MSG_REPLAY),
                                 "rq_xid "LPU64" matches last_xid, "
                                 "expected RESENT flag\n",
                                 req->rq_xid);
                /* else: note the opposite is not always true; a
                 * RESENT req after a failover will usually not match
                 * the last_xid, since it was likely never
                 * committed. A REPLAYed request will almost never
                 * match the last xid, however it could for a
                 * committed, but still retained, open. */

                /* Check for aborted recovery. */
                spin_lock_bh(&obd->obd_processing_task_lock);
                abort_recovery = obd->obd_abort_recovery;
                recovering = obd->obd_recovering;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                if (abort_recovery) {
                        target_abort_recovery(obd);
                } else if (recovering) {
                        int should_process;

                        rc = mds_filter_recovery_request(req, obd,
                                                         &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                }
        }

	h = mdt_handler_find(req->rq_reqmsg->opc);
	if (h != NULL) {
		rc = mdt_req_handle(info, h, req, 0);
	} else {
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
	}

        LASSERT(current->journal_info == NULL);

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != MDS_DISCONNECT) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;
                req->rq_repmsg->last_xid =
                        le64_to_cpu(med->med_mcd->mcd_last_xid);

                target_committed_to_req(req);
        }

        EXIT;
 out:

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_LAST_REPLAY) {
                if (obd && obd->obd_recovering) {
                        DEBUG_REQ(D_HA, req, "LAST_REPLAY, queuing reply");
                        RETURN(target_queue_final_reply(req, rc));
                }
                /* Lost a race with recovery; let the error path DTRT. */
                rc = req->rq_status = -ENOTCONN;
        }

        target_send_reply(req, rc, info->mti_fail_id);
	RETURN(0);
}

static struct lu_device_operations mdt_lu_ops;

static int lu_device_is_mdt(struct lu_device *d)
{
	/*
	 * XXX for now. Tags in lu_device_type->ldt_something are needed.
	 */
	return ergo(d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static struct mdt_object *mdt_obj(struct lu_object *o)
{
	LASSERT(lu_device_is_mdt(o->lo_dev));
	return container_of(o, struct mdt_object, mot_obj.mo_lu);
}

static struct mdt_device *mdt_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mdt(d));
	return container_of(d, struct mdt_device, mdt_md_dev.md_lu_dev);
}

int mdt_handle(struct ptlrpc_request *req)
{
	int result;

	struct mdt_thread_info info; /* XXX on stack for now */
	mdt_thread_info_init(&info);
	info.mti_mdt = mdt_dev(req->rq_export->exp_obd->obd_lu_dev);

	result = mdt_handle0(req, &info);

	mdt_thread_info_fini(&info);
        return result;
}

static int mdt_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
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

int md_device_init(struct md_device *md, struct lu_device_type *t)
{
	return lu_device_init(&md->md_lu_dev, t);
}

void md_device_fini(struct md_device *md)
{
	lu_device_fini(&md->md_lu_dev);
}

static void mdt_fini(struct lu_device *d)
{
	struct mdt_device *m = mdt_dev(d);

	if (d->ld_site != NULL) {
		lu_site_fini(d->ld_site);
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
	
	LASSERT(atomic_read(&d->ld_ref) == 0);
	md_device_fini(&m->mdt_md_dev);
}

static int mdt_init0(struct mdt_device *m,
                     struct lu_device_type *t, struct lustre_cfg *cfg)
{
	struct lu_site *s;
        char   ns_name[48];

        ENTRY;

	OBD_ALLOC_PTR(s);
	if (s == NULL)
		return -ENOMEM;

	md_device_init(&m->mdt_md_dev, t);

	m->mdt_md_dev.md_lu_dev.ld_ops = &mdt_lu_ops;

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
	lu_site_init(s, &m->mdt_md_dev.md_lu_dev);

        snprintf(ns_name, sizeof ns_name, LUSTRE_MDT0_NAME"-%p", m);
        m->mdt_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);
        if (m->mdt_namespace == NULL)
		return -ENOMEM;
        ldlm_register_intent(m->mdt_namespace, mdt_intent_policy);

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mdt_ldlm_client", &m->mdt_ldlm_client);

        m->mdt_service =
                ptlrpc_init_svc_conf(&m->mdt_service_conf, mdt_handle,
                                     LUSTRE_MDT0_NAME,
                                     m->mdt_md_dev.md_lu_dev.ld_proc_entry,
                                     NULL);
	if (m->mdt_service == NULL)
		return -ENOMEM;

	return ptlrpc_start_threads(NULL, m->mdt_service, LUSTRE_MDT0_NAME);
}

struct lu_object *mdt_object_alloc(struct lu_device *d)
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
		/* ->lo_depth and ->lo_flags are automatically 0 */
		lu_object_add_top(h, o);
		return o;
	} else
		return NULL;
}

int mdt_object_init(struct lu_object *o)
{
	struct mdt_device *d = mdt_dev(o->lo_dev);
	struct lu_device  *under;
	struct lu_object  *below;

	under = &d->mdt_child->md_lu_dev;
	below = under->ld_ops->ldo_object_alloc(under);
	if (below != NULL) {
		lu_object_add(o, below);
		return 0;
	} else
		return -ENOMEM;
}

void mdt_object_free(struct lu_object *o)
{
	struct lu_object_header *h;

	h = o->lo_header;
	lu_object_fini(o);
	lu_object_header_fini(h);
}

void mdt_object_release(struct lu_object *o)
{
}

int mdt_object_print(struct seq_file *f, const struct lu_object *o)
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

static struct ll_fid *mdt_object_fid(struct mdt_object *o)
{
        return lu_object_fid(&o->mot_obj.mo_lu);
}

static int mdt_object_lock(struct mdt_object *o, ldlm_mode_t mode)
{
        return fid_lock(mdt_object_fid(o), &o->mot_lh, mode);
}

static void mdt_object_unlock(struct mdt_object *o, ldlm_mode_t mode)
{
        fid_unlock(mdt_object_fid(o), &o->mot_lh, mode);
}

int mdt_mkdir(struct mdt_device *d, struct ll_fid *pfid, const char *name)
{
	struct mdt_object *o;
	int result;

	o = mdt_object_find(d, pfid);
	if (IS_ERR(o))
		return PTR_ERR(o);
	result = mdt_object_lock(o, LCK_PW);
	if (result == 0) {
		result = d->mdt_child->md_ops->mdo_mkdir(&o->mot_obj, name);
		mdt_object_unlock(o, LCK_PW);
	}
	mdt_object_put(o);
	return result;
}

static struct obd_ops mdt_obd_device_ops = {
        .o_owner           = THIS_MODULE
};

struct lu_device *mdt_device_alloc(struct lu_device_type *t,
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
                        mdt_fini(l);
                        m = ERR_PTR(result);
                }
        } else
                l = ERR_PTR(-ENOMEM);
        return l;
}

void mdt_device_free(struct lu_device *m)
{
        mdt_fini(m);
        OBD_FREE_PTR(m);
}

int mdt_type_init(struct lu_device_type *t)
{
        return 0;
}

void mdt_type_fini(struct lu_device_type *t)
{
}

static struct lu_device_type_operations mdt_device_type_ops = {
        .ldto_init = mdt_type_init,
        .ldto_fini = mdt_type_fini,

        .ldto_device_alloc = mdt_device_alloc,
        .ldto_device_free  = mdt_device_free
};

static struct lu_device_type mdt_device_type = {
        .ldt_name = LUSTRE_MDT0_NAME,
        .ldt_ops  = &mdt_device_type_ops
};

static int __init mdt_mod_init(void)
{
        struct lprocfs_static_vars lvars;
        struct obd_type *type;
        int result;

        mdt_num_threads = MDT_NUM_THREADS;
        lprocfs_init_vars(mdt, &lvars);
        result = class_register_type(&mdt_obd_device_ops,
                                     lvars.module_vars, LUSTRE_MDT0_NAME);
        if (result == 0) {
                type = class_get_type(LUSTRE_MDT0_NAME);
                LASSERT(type != NULL);
                type->typ_lu = &mdt_device_type;
                result = type->typ_lu->ldt_ops->ldto_init(type->typ_lu);
                if (result != 0)
                        class_unregister_type(LUSTRE_MDT0_NAME);
        }
	return result;
}

static void __exit mdt_mod_exit(void)
{
        class_unregister_type(LUSTRE_MDT0_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Meta-data Target Prototype ("LUSTRE_MDT0_NAME")");
MODULE_LICENSE("GPL");

CFS_MODULE_PARM(mdt_num_threads, "ul", ulong, 0444,
                "number of mdt service threads to start");

cfs_module(mdt, "0.0.2", mdt_mod_init, mdt_mod_exit);
