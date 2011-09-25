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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mds/handler.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include <lustre_mds.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <linux/jbd.h>
# include <linux/smp_lock.h>
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
# include <linux/mount.h>

#include <obd_class.h>
#include <lustre_dlm.h>
#include <obd_lov.h>
#include <lustre_fsfilt.h>
#include <lprocfs_status.h>
#include <lustre_quota.h>
#include <lustre_disk.h>
#include <lustre_param.h>

#include "mds_internal.h"

int mds_num_threads;
CFS_MODULE_PARM(mds_num_threads, "i", int, 0444,
                "number of MDS service threads to start");

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
        struct obd_export *exp = req->rq_export;
        struct l_wait_info lwi;
        struct page **pages;
        int timeout;
        int rc = 0, npages, i, tmpcount, tmpsize = 0;
        ENTRY;

        LASSERT((offset & ~CFS_PAGE_MASK) == 0); /* I'm dubious about this */

        npages = (count + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
        OBD_ALLOC(pages, sizeof(*pages) * npages);
        if (!pages)
                GOTO(out, rc = -ENOMEM);

        desc = ptlrpc_prep_bulk_exp(req, npages, BULK_PUT_SOURCE,
                                    MDS_BULK_PORTAL);
        if (desc == NULL)
                GOTO(out_free, rc = -ENOMEM);

        for (i = 0, tmpcount = count; i < npages; i++, tmpcount -= tmpsize) {
                tmpsize = tmpcount > CFS_PAGE_SIZE ? CFS_PAGE_SIZE : tmpcount;

                OBD_PAGE_ALLOC(pages[i], CFS_ALLOC_STD);
                if (pages[i] == NULL)
                        GOTO(cleanup_buf, rc = -ENOMEM);

                ptlrpc_prep_bulk_page(desc, pages[i], 0, tmpsize);
        }

        for (i = 0, tmpcount = count; i < npages; i++, tmpcount -= tmpsize) {
                tmpsize = tmpcount > CFS_PAGE_SIZE ? CFS_PAGE_SIZE : tmpcount;
                CDEBUG(D_EXT2, "reading %u@%llu from dir %lu (size %llu)\n",
                       tmpsize, offset, file->f_dentry->d_inode->i_ino,
                       i_size_read(file->f_dentry->d_inode));

                rc = fsfilt_readpage(exp->exp_obd, file,
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

        timeout = (int)req->rq_deadline - (int)cfs_time_current_sec();
        if (timeout < 0) {
                CERROR("Req deadline already passed %lu (now: %lu)\n",
                       req->rq_deadline, cfs_time_current_sec());
        }
        lwi = LWI_TIMEOUT_INTERVAL(cfs_time_seconds(max(timeout, 1)),
                                   cfs_time_seconds(1), NULL, NULL);
        rc = l_wait_event(desc->bd_waitq, !ptlrpc_server_bulk_active(desc) ||
                          exp->exp_failed || exp->exp_abort_active_req, &lwi);
        LASSERT (rc == 0 || rc == -ETIMEDOUT);

        if (rc == 0) {
                if (desc->bd_success &&
                    desc->bd_nob_transferred == count)
                        GOTO(cleanup_buf, rc);
                rc = -ETIMEDOUT;
                if (exp->exp_abort_active_req || exp->exp_failed)
                        GOTO(abort_bulk, rc);
        }

        DEBUG_REQ(D_ERROR, req, "bulk failed: %s %d(%d), evicting %s@%s\n",
                  (rc == -ETIMEDOUT) ? "timeout" : "network error",
                  desc->bd_nob_transferred, count,
                  req->rq_export->exp_client_uuid.uuid,
                  req->rq_export->exp_connection->c_remote_uuid.uuid);

        class_fail_export(req->rq_export);

        EXIT;
 abort_bulk:
        ptlrpc_abort_bulk(desc);
 cleanup_buf:
        for (i = 0; i < npages; i++)
                if (pages[i])
                        OBD_PAGE_FREE(pages[i]);

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
        int flags = LDLM_FL_ATOMIC_CB, rc;
        ldlm_policy_data_t policy = { .l_inodebits = { lockpart} };
        ENTRY;

        if (IS_ERR(de))
                RETURN(de);

        res_id.name[0] = de->d_inode->i_ino;
        res_id.name[1] = de->d_inode->i_generation;
        rc = ldlm_cli_enqueue_local(obd->obd_namespace, &res_id,
                                    LDLM_IBITS, &policy, lock_mode, &flags,
                                    ldlm_blocking_ast, ldlm_completion_ast,
                                    NULL, NULL, 0, NULL, lockh);
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
        struct obd_device *obd = container_of(mds, struct obd_device, u.mds);
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
        result = mds_lookup(obd, fid_name, mds->mds_fid_de, strlen(fid_name));
        if (IS_ERR(result))
                RETURN(result);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

       if (inode->i_nlink == 0) {
                if (inode->i_mode == 0 &&
                    LTIME_S(inode->i_ctime) == 0 ) {
                        LCONSOLE_WARN("Found inode with zero nlink, mode and "
                                      "ctime -- this may indicate disk"
                                      "corruption (device %s, inode %lu, link:"
                                      " %lu, count: %d)\n", obd->obd_name, inode->i_ino,
                                      (unsigned long)inode->i_nlink,
                                      atomic_read(&inode->i_count));
                }
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
                         struct obd_connect_data *data,
                         void *localdata)
{
        int rc;
        ENTRY;

        if (exp == NULL || obd == NULL || cluuid == NULL)
                RETURN(-EINVAL);

        rc = mds_connect_internal(exp, data);
        if (rc == 0)
                mds_export_stats_init(obd, exp, localdata);

        RETURN(rc);
}

/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data
 * about that client, like open files, the last operation number it did
 * on the server, etc.
 */
static int mds_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data,
                       void *localdata)
{
        struct obd_export *exp;
        struct mds_export_data *med;
        struct lsd_client_data *lcd = NULL;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        /* Check for aborted recovery. */
        target_recovery_check_and_stop(obd);

        /* XXX There is a small race between checking the list and adding a
         * new connection for the same UUID, but the real threat (list
         * corruption when multiple different clients connect) is solved.
         *
         * There is a second race between adding the export to the list,
         * and filling in the client data below.  Hence skipping the case
         * of NULL lcd above.  We should already be controlling multiple
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

        OBD_ALLOC_PTR(lcd);
        if (!lcd)
                GOTO(out, rc = -ENOMEM);

        memcpy(lcd->lcd_uuid, cluuid, sizeof(lcd->lcd_uuid));
        med->med_lcd = lcd;

        rc = mds_client_add(obd, exp, -1, localdata);
        GOTO(out, rc);

out:
        if (rc) {
                if (lcd) {
                        OBD_FREE_PTR(lcd);
                        med->med_lcd = NULL;
                }
                class_disconnect(exp);
        } else {
                class_export_put(exp);
        }

        RETURN(rc);
}

int mds_init_export(struct obd_export *exp)
{
        struct mds_export_data *med = &exp->exp_mds_data;
        ENTRY;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);

        spin_lock(&exp->exp_lock);
        exp->exp_connecting = 1;
        spin_unlock(&exp->exp_lock);

        RETURN(ldlm_init_export(exp));
}

static int mds_destroy_export(struct obd_export *exp)
{
        ENTRY;

        target_destroy_export(exp);
        ldlm_destroy_export(exp);

        LASSERT(list_empty(&exp->exp_mds_data.med_open_head));
        mds_client_free(exp);

        RETURN(0);
}

static int mds_cleanup_mfd(struct obd_export *exp)
{
        struct mds_export_data *med;
        struct obd_device *obd = exp->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_run_ctxt saved;
        struct lov_mds_md *lmm;
        __u32 lmm_sz, cookie_sz;
        struct llog_cookie *logcookies;
        struct list_head closing_list;
        struct mds_file_data *mfd, *n;
        int rc = 0;
        ENTRY;

        med = &exp->exp_mds_data;

        spin_lock(&med->med_open_lock);
        if (list_empty(&med->med_open_head)) {
                spin_unlock(&med->med_open_lock);
                RETURN(0);
        }

        CFS_INIT_LIST_HEAD(&closing_list);
        while (!list_empty(&med->med_open_head)) {
                struct list_head *tmp = med->med_open_head.next;
                struct mds_file_data *mfd =
                        list_entry(tmp, struct mds_file_data, mfd_list);

                /* Remove mfd handle so it can't be found again.
                 * We are consuming the mfd_list reference here. */
                mds_mfd_unlink(mfd, 0);
                list_add_tail(&mfd->mfd_list, &closing_list);
        }
        spin_unlock(&med->med_open_lock);

        lmm_sz = mds->mds_max_mdsize;
        OBD_ALLOC(lmm, lmm_sz);
        if (lmm == NULL) {
                CWARN("%s: allocation failure during cleanup; can not force "
                      "close file handles on this service.\n", obd->obd_name);
                GOTO(out, rc = -ENOMEM);
        }

        cookie_sz = mds->mds_max_cookiesize;
        OBD_ALLOC(logcookies, cookie_sz);
        if (logcookies == NULL) {
                CWARN("%s: allocation failure during cleanup; can not force "
                      "close file handles on this service.\n", obd->obd_name);
                OBD_FREE(lmm, lmm_sz);
                GOTO(out, rc = -ENOMEM);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* Close any open files (which may also cause orphan unlinking). */
        list_for_each_entry_safe(mfd, n, &closing_list, mfd_list) {
                int lmm_size = lmm_sz;
                umode_t mode = mfd->mfd_dentry->d_inode->i_mode;
                __u64 valid = 0;

                /* If you change this message, be sure to update
                 * replay_single:test_46 */
                CDEBUG(D_INODE|D_IOCTL, "%s: force closing file handle for "
                       "%.*s (ino %lu)\n", obd->obd_name,
                       mfd->mfd_dentry->d_name.len,mfd->mfd_dentry->d_name.name,
                       mfd->mfd_dentry->d_inode->i_ino);

                rc = mds_get_md(obd, mfd->mfd_dentry->d_inode, lmm,
                                &lmm_size, 1, 0, 0);
                if (rc < 0)
                        CWARN("mds_get_md failure, rc=%d\n", rc);
                else
                        valid |= OBD_MD_FLEASIZE;

                /* child orphan sem protects orphan_dec_test and
                 * is_orphan race, mds_mfd_close drops it */
                MDS_DOWN_WRITE_ORPHAN_SEM(mfd->mfd_dentry->d_inode);

                list_del_init(&mfd->mfd_list);
                rc = mds_mfd_close(NULL, REQ_REC_OFF, obd, mfd,
                                   !(exp->exp_flags & OBD_OPT_FAILOVER),
                                   lmm, lmm_size, logcookies,
                                   mds->mds_max_cookiesize,
                                   &valid);

                if (rc)
                        CDEBUG(D_INODE|D_IOCTL, "Error closing file: %d\n", rc);

                if (valid & OBD_MD_FLCOOKIE) {
                        rc = mds_osc_destroy_orphan(obd, mode, lmm,
                                                    lmm_size, logcookies, 1);
                        if (rc < 0) {
                                CDEBUG(D_INODE, "%s: destroy of orphan failed,"
                                       " rc = %d\n", obd->obd_name, rc);
                                rc = 0;
                        }
                        valid &= ~OBD_MD_FLCOOKIE;
                }

        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        OBD_FREE(logcookies, cookie_sz);
        OBD_FREE(lmm, lmm_sz);
out:
        RETURN(rc);
}

static int mds_disconnect(struct obd_export *exp)
{
        int rc = 0;
        ENTRY;

        LASSERT(exp);
        class_export_get(exp);

        rc = server_disconnect_export(exp);

        rc = mds_cleanup_mfd(exp);

        class_export_put(exp);
        RETURN(rc);
}

static int mds_getstatus(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_GETSTATUS_PACK, req->rq_status = -ENOMEM);
        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(req->rq_status = rc);

        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*body));
        memcpy(&body->fid1, &mds->mds_rootfid, sizeof(body->fid1));

        /* the last_committed and last_xid fields are filled in for all
         * replies already - no need to do so here also.
         */
        RETURN(0);
}

/* get the LOV EA from @inode and store it into @md.  It can be at most
 * @size bytes, and @size is updated with the actual EA size.
 * The EA size is also returned on success, and -ve errno on failure.
 * If there is no EA then 0 is returned. */
int mds_get_md(struct obd_device *obd, struct inode *inode, void *md,
               int *size, int lock, int flags,
               __u64 connect_flags)
{
        int rc = 0;
        int lmm_size = 0;

        if (lock)
                LOCK_INODE_MUTEX(inode);
        rc = fsfilt_get_md(obd, inode, md, *size, "lov");

        if (rc == 0 && flags == MDS_GETATTR)
                rc = mds_get_default_md(obd, md);

        if (rc < 0) {
                CERROR("Error %d reading eadata for ino %lu\n",
                       rc, inode->i_ino);
        } else if (rc > 0) {
                lmm_size = rc;
                rc = mds_convert_lov_ea(obd, inode, md, lmm_size,
                                        connect_flags);

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
                UNLOCK_INODE_MUTEX(inode);

        RETURN (rc);
}


/* Call with lock=1 if you want mds_pack_md to take the i_mutex.
 * Call with lock=0 if the caller has already taken the i_mutex. */
int mds_pack_md(struct obd_device *obd, struct lustre_msg *msg, int offset,
                struct mds_body *body, struct inode *inode, int lock, int flags,
                __u64 connect_flags)
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
        /* if this replay request we should be silencely exist without fill md*/
        lmm_size = lustre_msg_buflen(msg, offset);
        if (lmm_size == 0)
                RETURN(0);

        /* I don't really like this, but it is a sanity check on the client
         * MD request.  However, if the client doesn't know how much space
         * to reserve for the MD, it shouldn't be bad to have too much space.
         */
        if (lmm_size > mds->mds_max_mdsize) {
                CWARN("Reading MD for inode %lu of %d bytes > max %d\n",
                       inode->i_ino, lmm_size, mds->mds_max_mdsize);
                // RETURN(-EINVAL);
        }

        rc = mds_get_md(obd, inode, lmm, &lmm_size, lock, flags,
                        connect_flags);
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
        LASSERT(lustre_msg_bufcount(repmsg) > repoff);

        buflen = lustre_msg_buflen(repmsg, repoff);
        if (!buflen)
                GOTO(out, 0);

        if (!inode->i_op || !inode->i_op->getxattr)
                GOTO(out, 0);

        rc = inode->i_op->getxattr(&de, MDS_XATTR_NAME_ACL_ACCESS,
                                   lustre_msg_buf(repmsg, repoff, buflen),
                                   buflen);
        if (rc >= 0) {
                repbody->aclsize = rc;
        } else if (rc != -ENODATA) {
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
        int flags = 0;
        ENTRY;

        if (inode == NULL)
                RETURN(-ENOENT);

        body = lustre_msg_buf(req->rq_repmsg, reply_off, sizeof(*body));
        LASSERT(body != NULL);                 /* caller prepped reply */

        body->flags = reqbody->flags; /* copy MDS_BFLAG_EXT_FLAGS if present */
        mds_pack_inode2body(body, inode);
        reply_off++;

        if ((S_ISREG(inode->i_mode) && (reqbody->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (reqbody->valid & OBD_MD_FLDIREA))) {
                if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_GETATTR &&
                   ((S_ISDIR(inode->i_mode) && (reqbody->valid & OBD_MD_FLDIREA))))
                        flags = MDS_GETATTR;

                rc = mds_pack_md(obd, req->rq_repmsg, reply_off, body,
                                 inode, 1, flags,
                                 req->rq_export->exp_connect_flags);

                /* If we have LOV EA data, the OST holds size, atime, mtime */
                if (!(body->valid & OBD_MD_FLEASIZE) &&
                    !(body->valid & OBD_MD_FLDIREA))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);

                reply_off++;
        } else if (S_ISLNK(inode->i_mode) &&
                   (reqbody->valid & OBD_MD_LINKNAME) != 0) {
                char *symname = lustre_msg_buf(req->rq_repmsg, reply_off, 0);
                int len;

                LASSERT (symname != NULL);       /* caller prepped reply */
                len = lustre_msg_buflen(req->rq_repmsg, reply_off);

                rc = inode->i_op->readlink(dentry, symname, len);
                if (rc < 0) {
                        CERROR("readlink failed: %d\n", rc);
                } else if (rc != len - 1) {
                        CERROR ("Unexpected readlink rc %d: expecting %d\n",
                                rc, len - 1);
                        rc = -EINVAL;
                } else {
                        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_READLINK_EPROTO))
                                rc -= 2;

                        CDEBUG(D_INODE, "read symlink dest %s\n", symname);
                        body->valid |= OBD_MD_LINKNAME;
                        body->eadatasize = rc + 1;
                        symname[rc] = 0;        /* NULL terminate */
                        rc = 0;
                }
                reply_off++;
        } else if (reqbody->valid == OBD_MD_FLFLAGS &&
                   reqbody->flags & MDS_BFLAG_EXT_FLAGS) {
                int flags;

                /* We only return the full set of flags on ioctl, otherwise we
                 * get enough flags from the inode in mds_pack_inode2body(). */
                rc = fsfilt_iocontrol(obd, dentry, FSFILT_IOC_GETFLAGS,
                                      (long)&flags);
                if (rc == 0)
                        body->flags = flags | MDS_BFLAG_EXT_FLAGS;
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
        int rc, bufcount = REPLY_REC_OFF + 1;
        int size[4] = { sizeof(struct ptlrpc_body),
                        sizeof(*body) };
        ENTRY;

        LASSERT(offset == REQ_REC_OFF); /* non-intent */

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*body));
        LASSERT(body != NULL);                    /* checked by caller */
        LASSERT(lustre_req_swabbed(req, offset)); /* swabbed by caller */

        if (body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) {
                /* this will be shrinked to actual size before size */
                if (S_ISREG(inode->i_mode) || (S_ISDIR(inode->i_mode)))
                        size[bufcount ++] = mds->mds_max_mdsize;
                else
                        /* we not want LSM for specfial files */
                        body->valid &= ~(OBD_MD_FLEASIZE | OBD_MD_FLDIREA);
        } else if (S_ISLNK(inode->i_mode) && (body->valid & OBD_MD_LINKNAME)) {
                if (i_size_read(inode) > body->eadatasize)
                        CERROR("symlink size: %Lu, reply space: %d\n",
                               i_size_read(inode) + 1, body->eadatasize);
                size[bufcount ++] = min_t(int, i_size_read(inode) + 1,
                                          body->eadatasize);
                CDEBUG(D_INODE, "symlink size: %Lu, reply space: %d\n",
                       i_size_read(inode) + 1, body->eadatasize);
        }
#ifdef CONFIG_FS_POSIX_ACL
        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (body->valid & OBD_MD_FLACL)) {
                size[bufcount ++] = LUSTRE_POSIX_ACL_MAX_SIZE;
        }
#endif

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDS_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        rc = lustre_pack_reply(req, bufcount, size, NULL);
        if (rc) {
                req->rq_status = rc;
                RETURN(rc);
        }

        RETURN(0);
}

static int mds_getattr_lock(struct ptlrpc_request *req, int offset,
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
        int rq_offset = offset;
        char *name;
        ENTRY;

        LASSERT(!strcmp(obd->obd_type->typ_name, LUSTRE_MDS_NAME));
        LASSERT(offset == REQ_REC_OFF || offset == DLM_INTENT_REC_OFF);
        /* if requests were at offset 2, the getattr reply goes back at 1 */
        if (offset == DLM_INTENT_REC_OFF) {
                rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF,
                                     sizeof(*rep));
                offset = DLM_REPLY_REC_OFF;
        }

        /* Swab now, before anyone looks inside the request */
        body = lustre_swab_reqbuf(req, rq_offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't swab mds_body\n");
                GOTO(cleanup_exit, rc = -EFAULT);
        }

        lustre_set_req_swabbed(req, rq_offset + 1);
        name = lustre_msg_string(req->rq_reqmsg, rq_offset + 1, 0);
        if (name == NULL) {
                CERROR("Can't unpack name\n");
                GOTO(cleanup_exit, rc = -EFAULT);
        }
        namesize = lustre_msg_buflen(req->rq_reqmsg, rq_offset + 1);
        /* namesize less than 2 means we have empty name, probably came from
           revalidate by cfid, so no point in having name to be set */
        if (namesize <= 1)
                name = NULL;

        rc = mds_init_ucred(&uc, req, rq_offset);
        if (rc)
                GOTO(cleanup, rc);


        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        cleanup_phase = 1; /* kernel context */
        ldlm_reply_set_disposition(rep, DISP_LOOKUP_EXECD);

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

        /* child_lockh() is only set in fixup_handle_for_resent_req()
         * if MSG_RESENT is set */
        if (lustre_handle_is_used(child_lockh)) {
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
                resent_req = 1;
        }

        if (resent_req == 0) {
                if (name) {
                        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_RESEND, obd_timeout*2);
                        rc = mds_get_parent_child_locked(obd, &obd->u.mds,
                                                         &body->fid1,
                                                         &parent_lockh,
                                                         &dparent, LCK_CR,
                                                         MDS_INODELOCK_UPDATE,
                                                         name, namesize,
                                                         child_lockh, &dchild,
                                                         LCK_CR, child_part,
                                                         IT_GETATTR, 0);
                } else {
                        /* For revalidate by fid we always take UPDATE lock */
                        dchild = mds_fid2locked_dentry(obd, &body->fid2, NULL,
                                                       LCK_CR, child_lockh,
                                                       NULL, 0, child_part);
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
                /* lock was granted in fixup_handle_for_resent_req() if
                 * MSG_RESENT is set */
                LASSERTF(granted_lock != NULL, LPU64"/%u lockh "LPX64"\n",
                         body->fid1.id, body->fid1.generation,
                         child_lockh->cookie);


                res = granted_lock->l_resource;
                child_fid.id = res->lr_name.name[0];
                child_fid.generation = res->lr_name.name[1];
                dchild = mds_fid2dentry(&obd->u.mds, &child_fid, NULL);
                if (IS_ERR(dchild)) {
                        rc = PTR_ERR(dchild);
                        LCONSOLE_WARN("Child "LPU64"/%u lookup error %d.",
                                      child_fid.id, child_fid.generation, rc);
                        GOTO(cleanup, rc);
                }
                LDLM_LOCK_PUT(granted_lock);
        }

        cleanup_phase = 2; /* dchild, dparent, locks */

        if (dchild->d_inode == NULL) {
                ldlm_reply_set_disposition(rep, DISP_LOOKUP_NEG);
                /* in the intent case, the policy clears this error:
                   the disposition is enough */
                GOTO(cleanup, rc = -ENOENT);
        } else {
                ldlm_reply_set_disposition(rep, DISP_LOOKUP_POS);
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
                        if (name) {
                                ldlm_lock_decref(&parent_lockh, LCK_CR);
                                l_dput(dparent);
                        }
                }
                l_dput(dchild);
        case 1:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        default:
                mds_exit_ucred(&uc, mds);
                if (!req->rq_packed_final) {
                        int rc2 = lustre_pack_reply(req, 1, NULL, NULL);
                        if (rc == 0)
                                rc = rc2;
                        req->rq_status = rc;
                }
        }
cleanup_exit:
        return rc;
}

static int mds_getattr(struct ptlrpc_request *req, int offset)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lvfs_run_ctxt saved;
        struct dentry *de;
        struct mds_body *body;
        struct lvfs_ucred uc = { NULL, };
        int rc = 0;
        ENTRY;

        mds_counter_incr(req->rq_export, LPROC_MDS_GETATTR);

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                GOTO(cleanup_exit, rc = -EFAULT);

        rc = mds_init_ucred(&uc, req, offset);
        if (rc)
                GOTO(out_ucred, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_fid2dentry(mds, &body->fid1, NULL);
        if (IS_ERR(de)) {
                req->rq_status = PTR_ERR(de);
                GOTO(out_pop, rc);
        }

        rc = mds_getattr_pack_msg(req, de->d_inode, offset);
        if (rc != 0) {
                CERROR("mds_getattr_pack_msg: %d\n", rc);
                GOTO(out_dput, rc);
        }

        req->rq_status = mds_getattr_internal(obd, de, req, body,REPLY_REC_OFF);
out_dput:
        l_dput(de);
        GOTO(out_pop, rc);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out_ucred:
        if (!req->rq_packed_final) {
                int rc2 = lustre_pack_reply(req, 1, NULL, NULL);
                if (rc == 0)
                        rc = rc2;
                if (rc != 0)
                        req->rq_status = rc;
        } else {
                mds_shrink_body_reply(req, offset, REPLY_REC_OFF);
        }
        mds_exit_ucred(&uc, mds);

cleanup_exit:
        return rc;
}

static int mds_obd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                          __u64 max_age, __u32 flags)
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
        struct ptlrpc_service *svc = req->rq_rqbd->rqbd_service;
        int rc, size[2] = { sizeof(struct ptlrpc_body),
                            sizeof(struct obd_statfs) };
        ENTRY;

        /* This will trigger a watchdog timeout */
        OBD_FAIL_TIMEOUT(OBD_FAIL_MDS_STATFS_LCW_SLEEP,
                         (MDS_SERVICE_WATCHDOG_FACTOR *
                          at_get(&svc->srv_at_estimate)) + 1);
        mds_counter_incr(req->rq_export, LPROC_MDS_STATFS);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_STATFS_PACK))
                GOTO(out, rc = -ENOMEM);
        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);

        /* We call this so that we can cache a bit - 1 jiffie worth */
        rc = mds_obd_statfs(obd, lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                                size[REPLY_REC_OFF]),
                            cfs_time_shift_64(-OBD_STATFS_CACHE_SECONDS), 0);
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
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*body) };
        ENTRY;

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                GOTO(out, rc = -EFAULT);

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK))
                GOTO(out, rc = -ENOMEM);
        mds_counter_incr(req->rq_export, LPROC_MDS_SYNC);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);

        rc = fsfilt_sync(obd, obd->u.obt.obt_sb);
        if (rc == 0 && body->fid1.id != 0) {
                struct dentry *de;

                de = mds_fid2dentry(mds, &body->fid1, NULL);
                if (IS_ERR(de))
                        GOTO(out, rc = PTR_ERR(de));

                body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                mds_pack_inode2body(body, de->d_inode);

                l_dput(de);
        }
        GOTO(out, rc);
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
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*repbody) };
        struct lvfs_ucred uc = {NULL,};
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_READPAGE_PACK, -ENOMEM);
        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                GOTO(out, rc);

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                GOTO (out, rc = -EFAULT);

        rc = mds_init_ucred(&uc, req, offset);
        if (rc)
                GOTO(out, rc);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_fid2dentry(&obd->u.mds, &body->fid1, &mnt);
        if (IS_ERR(de))
                GOTO(out_pop, rc = PTR_ERR(de));

        CDEBUG(D_INODE, "ino %lu\n", de->d_inode->i_ino);

        file = ll_dentry_open(de, mnt, O_RDONLY | O_LARGEFILE, current_cred());
        /* note: in case of an error, dentry_open puts dentry */
        if (IS_ERR(file))
                GOTO(out_pop, rc = PTR_ERR(file));

        /* body->size is actually the offset -eeb */
        if ((body->size & (de->d_inode->i_sb->s_blocksize - 1)) != 0) {
                CERROR("offset "LPU64" not on a block boundary of %lu\n",
                       body->size, de->d_inode->i_sb->s_blocksize);
                GOTO(out_file, rc = -EFAULT);
        }

        /* body->nlink is actually the #bytes to read -eeb */
        if (body->nlink & (de->d_inode->i_sb->s_blocksize - 1)) {
                CERROR("size %u is not multiple of blocksize %lu\n",
                       body->nlink, de->d_inode->i_sb->s_blocksize);
                GOTO(out_file, rc = -EFAULT);
        }

        repbody = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                                 sizeof(*repbody));
        repbody->size = i_size_read(file->f_dentry->d_inode);
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

        mds_root_squash(&req->rq_export->exp_obd->u.mds, &req->rq_peer.nid,
                        &rec->ur_uc.luc_fsuid, &rec->ur_uc.luc_fsgid,
                        &rec->ur_uc.luc_cap, &rec->ur_uc.luc_suppgid1,
                        &rec->ur_uc.luc_suppgid2);

        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(rec, offset, req, lockh);
 out:
        OBD_FREE(rec, sizeof(*rec));
        return rc;
}

static int mds_filter_recovery_request(struct ptlrpc_request *req,
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
        case MDS_SYNC: /* used in unmounting */
        case OBD_PING:
        case MDS_SETXATTR:
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

static int mds_set_info_rpc(struct obd_export *exp, struct ptlrpc_request *req)
{
        void *key, *val;
        int keylen, vallen, rc = 0;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF);

        val = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF + 1, 0);
        vallen = lustre_msg_buflen(req->rq_reqmsg, REQ_REC_OFF + 1);

        rc = lustre_pack_reply(req, 1, NULL, NULL);
        if (rc)
                RETURN(rc);

        lustre_msg_set_status(req->rq_repmsg, 0);

        /* Accept the broken "read-only" key from 1.6.6 clients. b=17493 */
        if (KEY_IS(KEY_READONLY) || KEY_IS(KEY_READONLY_166COMPAT)) {
                if (val == NULL || vallen < sizeof(__u32)) {
                        DEBUG_REQ(D_HA, req, "no set_info val");
                        RETURN(-EFAULT);
                }

                if (*(__u32 *)val)
                        exp->exp_connect_flags |= OBD_CONNECT_RDONLY;
                else
                        exp->exp_connect_flags &= ~OBD_CONNECT_RDONLY;
        } else {
                RETURN(-EINVAL);
        }

        RETURN(0);
}

#ifdef HAVE_QUOTA_SUPPORT
static int mds_handle_quotacheck(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl;
        int rc;
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 1, NULL, NULL);
        if (rc)
                RETURN(rc);

        req->rq_status = obd_quotacheck(req->rq_export, oqctl);
        RETURN(0);
}

static int mds_handle_quotactl(struct ptlrpc_request *req)
{
        struct obd_quotactl *oqctl, *repoqc;
        int rc, size[2] = { sizeof(struct ptlrpc_body), sizeof(*repoqc) };
        ENTRY;

        oqctl = lustre_swab_reqbuf(req, REQ_REC_OFF, sizeof(*oqctl),
                                   lustre_swab_obd_quotactl);
        if (oqctl == NULL)
                RETURN(-EPROTO);

        rc = lustre_pack_reply(req, 2, size, NULL);
        if (rc)
                RETURN(rc);

        repoqc = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*repoqc));

        req->rq_status = obd_quotactl(req->rq_export, oqctl);
        *repoqc = *oqctl;
        RETURN(0);
}
#endif

static int mds_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        switch (lustre_msg_get_opc(msg)) {
        case MDS_CONNECT:
        case MDS_DISCONNECT:
        case OBD_PING:
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

int mds_handle(struct ptlrpc_request *req)
{
        int should_process, fail = OBD_FAIL_MDS_ALL_REPLY_NET;
        int rc = 0;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        struct obd_device *obd = NULL;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        LASSERT(current->journal_info == NULL);

        rc = mds_msg_check_version(req->rq_reqmsg);
        if (rc) {
                CERROR("MDS drop mal-formed request\n");
                RETURN(rc);
        }

        if (lustre_msg_get_opc(req->rq_reqmsg) != MDS_CONNECT) {
                struct mds_export_data *med;
                int recovering;

                if (!class_connected_export(req->rq_export)) {
                        CERROR("operation %d on unconnected MDS from %s\n",
                               lustre_msg_get_opc(req->rq_reqmsg),
                               libcfs_id2str(req->rq_peer));
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mds_data;
                obd = req->rq_export->exp_obd;
                mds = &obd->u.mds;

                /* sanity check: if the xid matches, the request must
                 * be marked as a resent or replayed */
                if (req->rq_xid == le64_to_cpu(med->med_lcd->lcd_last_xid) ||
                    req->rq_xid == le64_to_cpu(med->med_lcd->lcd_last_close_xid))
                        if (!(lustre_msg_get_flags(req->rq_reqmsg) &
                                 (MSG_RESENT | MSG_REPLAY))) {
                                CERROR("rq_xid "LPU64" matches last_xid, "
                                       "expected RESENT flag\n",
                                        req->rq_xid);
                                req->rq_status = -ENOTCONN;
                                GOTO(out, rc = -EFAULT);
                        }
                /* else: note the opposite is not always true; a
                 * RESENT req after a failover will usually not match
                 * the last_xid, since it was likely never
                 * committed. A REPLAYed request will almost never
                 * match the last xid, however it could for a
                 * committed, but still retained, open. */

                /* Check for aborted recovery. */
                spin_lock_bh(&obd->obd_processing_task_lock);
                recovering = obd->obd_recovering;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                if (recovering &&
                    target_recovery_check_and_stop(obd) == 0) {
                        rc = mds_filter_recovery_request(req, obd,
                                                         &should_process);
                        if (rc || !should_process)
                                RETURN(rc);
                }
        }

        switch (lustre_msg_get_opc(req->rq_reqmsg)) {
        case MDS_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = target_handle_connect(req, mds_handle);
                if (!rc) {
                        /* Now that we have an export, set obd. */
                        obd = req->rq_export->exp_obd;
                }
                break;

        case MDS_DISCONNECT:
                DEBUG_REQ(D_INODE, req, "disconnect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DISCONNECT_NET, 0);
                rc = target_handle_disconnect(req);
                req->rq_status = rc;            /* superfluous? */
                break;

        case MDS_GETSTATUS:
                DEBUG_REQ(D_INODE, req, "getstatus");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETSTATUS_NET, 0);
                rc = mds_getstatus(req);
                break;

        case MDS_GETATTR:
                DEBUG_REQ(D_INODE, req, "getattr");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NET, 0);
                rc = mds_getattr(req, REQ_REC_OFF);
                break;

        case MDS_SETXATTR:
                DEBUG_REQ(D_INODE, req, "setxattr");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_SETXATTR_NET, 0);
                rc = mds_setxattr(req);
                break;

        case MDS_GETXATTR:
                DEBUG_REQ(D_INODE, req, "getxattr");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETXATTR_NET, 0);
                rc = mds_getxattr(req);
                break;

        case MDS_GETATTR_NAME: {
                struct lustre_handle lockh = { 0 };
                DEBUG_REQ(D_INODE, req, "getattr_name");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_NAME_NET, 0);

                /* If this request gets a reconstructed reply, we won't be
                 * acquiring any new locks in mds_getattr_lock, so we don't
                 * want to cancel.
                 */
                rc = mds_getattr_lock(req, REQ_REC_OFF, MDS_INODELOCK_UPDATE,
                                      &lockh);
                mds_shrink_body_reply(req, REQ_REC_OFF, REPLY_REC_OFF);
                /* this non-intent call (from an ioctl) is special */
                req->rq_status = rc;
                if (rc == 0 && lustre_handle_is_used(&lockh))
                        ldlm_lock_decref(&lockh, LCK_CR);
                break;
        }
        case MDS_STATFS:
                DEBUG_REQ(D_INODE, req, "statfs");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_STATFS_NET, 0);
                rc = mds_statfs(req);
                break;

        case MDS_READPAGE:
                DEBUG_REQ(D_INODE, req, "readpage");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_READPAGE_NET, 0);
                rc = mds_readpage(req, REQ_REC_OFF);

                if (OBD_FAIL_CHECK(OBD_FAIL_MDS_SENDPAGE)) {
                        RETURN(0);
                }

                break;

        case MDS_REINT: {
                __u32 *opcp = lustre_msg_buf(req->rq_reqmsg, REQ_REC_OFF,
                                             sizeof(*opcp));
                __u32  opc;
                int op = 0;
                int size[4] = { sizeof(struct ptlrpc_body),
                               sizeof(struct mds_body),
                               mds->mds_max_mdsize,
                               mds->mds_max_cookiesize };
                int bufcount;

                /* NB only peek inside req now; mds_reint() will swab it */
                if (opcp == NULL) {
                        CERROR ("Can't inspect opcode\n");
                        rc = -EINVAL;
                        break;
                }
                opc = *opcp;
                if (lustre_req_need_swab(req))
                        __swab32s(&opc);

                DEBUG_REQ(D_INODE, req, "reint %d (%s)", opc,
                          (opc < REINT_MAX) ? reint_names[opc] :
                          "unknown opcode");

                switch (opc) {
                case REINT_CREATE:
                        op = PTLRPC_LAST_CNTR + MDS_REINT_CREATE;
                        break;
                case REINT_LINK:
                        op = PTLRPC_LAST_CNTR + MDS_REINT_LINK;
                        break;
                case REINT_OPEN:
                        op = PTLRPC_LAST_CNTR + MDS_REINT_OPEN;
                        break;
                case REINT_SETATTR:
                        op = PTLRPC_LAST_CNTR + MDS_REINT_SETATTR;
                        break;
                case REINT_RENAME:
                        op = PTLRPC_LAST_CNTR + MDS_REINT_RENAME;
                        break;
                case REINT_UNLINK:
                        op = PTLRPC_LAST_CNTR + MDS_REINT_UNLINK;
                        break;
                default:
                        op = 0;
                        break;
                }

                if (op && req->rq_rqbd->rqbd_service->srv_stats)
                        lprocfs_counter_incr(
                                req->rq_rqbd->rqbd_service->srv_stats, op);

                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                if (opc == REINT_UNLINK || opc == REINT_RENAME)
                        bufcount = 4;
                else if (opc == REINT_OPEN)
                        bufcount = 3;
                else
                        bufcount = 2;

                /* if we do recovery we isn't send reply mds state is restored */
                if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                        size[DLM_REPLY_REC_OFF] = 0;
                        if (opc == REINT_UNLINK || opc == REINT_RENAME)
                                size[DLM_REPLY_REC_OFF + 1] = 0;
                }

                rc = lustre_pack_reply(req, bufcount, size, NULL);
                if (rc)
                        break;

                rc = mds_reint(req, REQ_REC_OFF, NULL);
                mds_shrink_intent_reply(req, opc, REPLY_REC_OFF);
                fail = OBD_FAIL_MDS_REINT_NET_REP;
                break;
        }

        case MDS_CLOSE:
                DEBUG_REQ(D_INODE, req, "close");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CLOSE_NET, 0);
                rc = mds_close(req, REQ_REC_OFF);
                mds_shrink_body_reply(req, REQ_REC_OFF, REPLY_REC_OFF);
                fail = OBD_FAIL_MDS_CLOSE_NET_REP;
                break;

        case MDS_DONE_WRITING:
                DEBUG_REQ(D_INODE, req, "done_writing");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DONE_WRITING_NET, 0);
                rc = mds_done_writing(req, REQ_REC_OFF);
                break;

        case MDS_PIN:
                DEBUG_REQ(D_INODE, req, "pin");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_PIN_NET, 0);
                rc = mds_pin(req, REQ_REC_OFF);
                break;

        case MDS_SYNC:
                DEBUG_REQ(D_INODE, req, "sync");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_SYNC_NET, 0);
                rc = mds_sync(req, REQ_REC_OFF);
                break;

        case MDS_SET_INFO:
                DEBUG_REQ(D_INODE, req, "set_info");
                rc = mds_set_info_rpc(req->rq_export, req);
                break;
#ifdef HAVE_QUOTA_SUPPORT
        case MDS_QUOTACHECK:
                DEBUG_REQ(D_INODE, req, "quotacheck");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_QUOTACHECK_NET, 0);
                rc = mds_handle_quotacheck(req);
                break;

        case MDS_QUOTACTL:
                DEBUG_REQ(D_INODE, req, "quotactl");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_QUOTACTL_NET, 0);
                rc = mds_handle_quotactl(req);
                break;
#endif
        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                rc = target_handle_ping(req);
                if (req->rq_export->exp_delayed)
                        mds_update_client_epoch(req->rq_export);
                break;

        case OBD_LOG_CANCEL:
                CDEBUG(D_INODE, "log cancel\n");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOG_CANCEL_NET, 0);
                rc = -ENOTSUPP; /* la la la */
                break;

        case LDLM_ENQUEUE:
                DEBUG_REQ(D_INODE, req, "enqueue");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_ENQUEUE, 0);
                rc = ldlm_handle_enqueue(req, ldlm_server_completion_ast,
                                         ldlm_server_blocking_ast, NULL);
                fail = OBD_FAIL_LDLM_REPLY;
                break;
        case LDLM_CONVERT:
                DEBUG_REQ(D_INODE, req, "convert");
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_CONVERT, 0);
                rc = ldlm_handle_convert(req);
                break;
        case LDLM_BL_CALLBACK:
        case LDLM_CP_CALLBACK:
                DEBUG_REQ(D_INODE, req, "callback");
                CERROR("callbacks should not happen on MDS\n");
                LBUG();
                OBD_FAIL_RETURN(OBD_FAIL_LDLM_BL_CALLBACK, 0);
                break;
        case LLOG_ORIGIN_HANDLE_CREATE:
                DEBUG_REQ(D_INODE, req, "llog_init");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_create(req);
                break;
        case LLOG_ORIGIN_HANDLE_DESTROY:
                DEBUG_REQ(D_INODE, req, "llog_init");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_destroy(req);
                break;
        case LLOG_ORIGIN_HANDLE_NEXT_BLOCK:
                DEBUG_REQ(D_INODE, req, "llog next block");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_next_block(req);
                break;
        case LLOG_ORIGIN_HANDLE_PREV_BLOCK:
                DEBUG_REQ(D_INODE, req, "llog prev block");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_prev_block(req);
                break;
        case LLOG_ORIGIN_HANDLE_READ_HEADER:
                DEBUG_REQ(D_INODE, req, "llog read header");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_read_header(req);
                break;
        case LLOG_ORIGIN_HANDLE_CLOSE:
                DEBUG_REQ(D_INODE, req, "llog close");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_close(req);
                break;
        case LLOG_CATINFO:
                DEBUG_REQ(D_INODE, req, "llog catinfo");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_catinfo(req);
                break;
        default:
                req->rq_status = -ENOTSUPP;
                rc = ptlrpc_error(req);
                RETURN(rc);
        }

        LASSERT(current->journal_info == NULL);

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (!rc && lustre_msg_get_opc(req->rq_reqmsg) != MDS_DISCONNECT) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;

                /* I don't think last_xid is used for anyway, so I'm not sure
                   if we need to care about last_close_xid here.*/
                lustre_msg_set_last_xid(req->rq_repmsg,
                                        le64_to_cpu(med->med_lcd->lcd_last_xid));
                target_committed_to_req(req);
        }

        EXIT;
out:
        return target_handle_reply(req, rc, fail);
}

/* Update the server data on disk.  This stores the new mount_count and
 * also the last_rcvd value to disk.  If we don't have a clean shutdown,
 * then the server last_rcvd value may be less than that of the clients.
 * This will alert us that we may need to do client recovery.
 *
 * Also assumes for mds_last_transno that we are not modifying it (no locking).
 */
int mds_update_server_data(struct obd_device *obd, int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lr_server_data *lsd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        struct lvfs_run_ctxt saved;
        loff_t off = 0;
        int rc;
        ENTRY;

        CDEBUG(D_SUPER, "MDS mount_count is "LPU64", last_transno is "LPU64"\n",
               mds->mds_mount_count, mds->mds_last_transno);

        spin_lock(&mds->mds_transno_lock);
        lsd->lsd_last_transno = cpu_to_le64(mds->mds_last_transno);
        spin_unlock(&mds->mds_transno_lock);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = fsfilt_write_record(obd, filp, lsd, sizeof(*lsd), &off,force_sync);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc)
                CERROR("error writing MDS server data: rc = %d\n", rc);

        RETURN(rc);
}

static void fsoptions_to_mds_flags(struct mds_obd *mds, char *options)
{
        char *p = options;

        if (!options)
                return;

        while (*options) {
                int len;

                while (*p && *p != ',')
                        p++;

                len = p - options;
                if (len == sizeof("user_xattr") - 1 &&
                    memcmp(options, "user_xattr", len) == 0) {
                        mds->mds_fl_user_xattr = 1;
                        LCONSOLE_INFO("Enabling user_xattr\n");
                } else if (len == sizeof("nouser_xattr") - 1 &&
                           memcmp(options, "nouser_xattr", len) == 0) {
                        mds->mds_fl_user_xattr = 0;
                        LCONSOLE_INFO("Disabling user_xattr\n");
                } else if (len == sizeof("acl") - 1 &&
                           memcmp(options, "acl", len) == 0) {
#ifdef CONFIG_FS_POSIX_ACL
                        mds->mds_fl_acl = 1;
                        LCONSOLE_INFO("Enabling ACL\n");
#else
                        CWARN("ignoring unsupported acl mount option\n");
#endif
                } else if (len == sizeof("noacl") - 1 &&
                           memcmp(options, "noacl", len) == 0) {
#ifdef CONFIG_FS_POSIX_ACL
                        mds->mds_fl_acl = 0;
                        LCONSOLE_INFO("Disabling ACL\n");
#endif
                }

                options = ++p;
        }
}

/* mount the file system (secretly).  lustre_cfg parameters are:
 * 1 = device
 * 2 = fstype
 * 3 = config name
 * 4 = mount options
 */
static int mds_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lprocfs_static_vars lvars;
        struct lustre_cfg* lcfg = buf;
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_sb_info *lsi;
        struct lustre_mount_info *lmi;
        struct vfsmount *mnt;
        struct obd_uuid uuid;
        __u8 *uuid_ptr;
        char *str, *label;
        char ns_name[48];
        int rc = 0;
        ENTRY;

        /* setup 1:/dev/loop/0 2:ext3 3:mdsA 4:errors=remount-ro,iopen_nopriv */

        CLASSERT(offsetof(struct obd_device, u.obt) ==
                 offsetof(struct obd_device, u.mds.mds_obt));

        if (lcfg->lcfg_bufcount < 3)
                RETURN(-EINVAL);

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) == 0 || LUSTRE_CFG_BUFLEN(lcfg, 2) == 0)
                RETURN(-EINVAL);

        lmi = server_get_mount(obd->obd_name);
        if (!lmi) {
                CERROR("Not mounted in lustre_fill_super?\n");
                RETURN(-EINVAL);
        }

        /* We mounted in lustre_fill_super.
           lcfg bufs 1, 2, 4 (device, fstype, mount opts) are ignored.*/
        lsi = s2lsi(lmi->lmi_sb);
        fsoptions_to_mds_flags(mds, lsi->lsi_ldd->ldd_mount_opts);
        fsoptions_to_mds_flags(mds, lsi->lsi_lmd->lmd_opts);
        mnt = lmi->lmi_mnt;
        obd->obd_fsops = fsfilt_get_ops(MT_STR(lsi->lsi_ldd));
        if (IS_ERR(obd->obd_fsops))
                GOTO(err_put, rc = PTR_ERR(obd->obd_fsops));

        CDEBUG(D_SUPER, "%s: mnt = %p\n", lustre_cfg_string(lcfg, 1), mnt);

        if (lvfs_check_rdonly(lvfs_sbdev(mnt->mnt_sb))) {
                CERROR("%s: Underlying device is marked as read-only. "
                       "Setup failed\n", obd->obd_name);
                GOTO(err_ops, rc = -EROFS);
        }

        sema_init(&mds->mds_epoch_sem, 1);
        spin_lock_init(&mds->mds_transno_lock);
        mds->mds_max_mdsize = sizeof(struct lov_mds_md_v3);
        mds->mds_max_cookiesize = sizeof(struct llog_cookie);
        mds->mds_atime_diff = MAX_ATIME_DIFF;
        mds->mds_evict_ost_nids = 1;
        /* sync permission changes */
        mds->mds_sync_permission = 0;

        sprintf(ns_name, "mds-%s", obd->obd_uuid.uuid);
        obd->obd_namespace = ldlm_namespace_new(obd, ns_name, LDLM_NAMESPACE_SERVER,
                                                LDLM_NAMESPACE_GREEDY);
        if (obd->obd_namespace == NULL) {
                mds_cleanup(obd);
                GOTO(err_ops, rc = -ENOMEM);
        }
        ldlm_register_intent(obd->obd_namespace, mds_intent_policy);

        lprocfs_mds_init_vars(&lvars);
        if (lprocfs_obd_setup(obd, lvars.obd_vars) == 0 &&
            lprocfs_alloc_obd_stats(obd, LPROC_MDS_LAST) == 0) {
                /* Init private stats here */
                mds_stats_counter_init(obd->obd_stats);
#ifdef HAVE_DELAYED_RECOVERY
                lprocfs_obd_attach_stale_exports(obd);
#endif
                obd->obd_proc_exports_entry = proc_mkdir("exports",
                                                         obd->obd_proc_entry);
        }

        rc = mds_fs_setup(obd, mnt);
        if (rc) {
                CERROR("%s: MDS filesystem method init failed: rc = %d\n",
                       obd->obd_name, rc);
                GOTO(err_ns, rc);
        }

        if (obd->obd_proc_exports_entry)
                lprocfs_add_simple(obd->obd_proc_exports_entry,
                                   "clear", lprocfs_nid_stats_clear_read,
                                   lprocfs_nid_stats_clear_write, obd, NULL);

        if (lcfg->lcfg_bufcount >= 4 && LUSTRE_CFG_BUFLEN(lcfg, 3) > 0) {
                class_uuid_t uuid;

                ll_generate_random_uuid(uuid);
                class_uuid_unparse(uuid, &mds->mds_lov_uuid);

                OBD_ALLOC(mds->mds_profile, LUSTRE_CFG_BUFLEN(lcfg, 3));
                if (mds->mds_profile == NULL)
                        GOTO(err_fs, rc = -ENOMEM);

                strncpy(mds->mds_profile, lustre_cfg_string(lcfg, 3),
                        LUSTRE_CFG_BUFLEN(lcfg, 3));
        }

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mds_ldlm_client", &obd->obd_ldlm_client);
        obd->obd_replayable = 1;

        rc = lquota_setup(mds_quota_interface_ref, obd);
        if (rc)
                GOTO(err_fs, rc);

        mds->mds_group_hash = upcall_cache_init(obd->obd_name);
        if (IS_ERR(mds->mds_group_hash)) {
                rc = PTR_ERR(mds->mds_group_hash);
                mds->mds_group_hash = NULL;
                GOTO(err_qctxt, rc);
        }

        /* Don't wait for mds_postrecov trying to clear orphans */
        obd->obd_async_recov = 1;
        rc = mds_postsetup(obd);
        /* Bug 11557 - allow async abort_recov start
           FIXME can remove most of this obd_async_recov plumbing
        obd->obd_async_recov = 0;
        */
        if (rc)
                GOTO(err_qctxt, rc);

        uuid_ptr = fsfilt_uuid(obd, obd->u.obt.obt_sb);
        if (uuid_ptr != NULL) {
                class_uuid_unparse(uuid_ptr, &uuid);
                str = uuid.uuid;
        } else {
                str = "no UUID";
        }

        label = fsfilt_get_label(obd, obd->u.obt.obt_sb);
        LCONSOLE_INFO("%s: Now serving %s on %s with recovery %s\n",
                      obd->obd_name, label ?: str, lsi->lsi_lmd->lmd_dev,
                      obd->obd_replayable ? "enabled" : "disabled");

        if (obd->obd_recovering)
                LCONSOLE_WARN("%s: Will be in recovery for at least %d:%.02d, "
                              "or until %d client%s reconnect%s\n",
                              obd->obd_name,
                              obd->obd_recovery_timeout / 60,
                              obd->obd_recovery_timeout % 60,
                              obd->obd_recoverable_clients,
                              obd->obd_recoverable_clients == 1 ? "" : "s",
                              obd->obd_recoverable_clients == 1 ? "s": "");

        /* Reduce the initial timeout on an MDS because it doesn't need such
         * a long timeout as an OST does. Adaptive timeouts will adjust this
         * value appropriately. */
        if (ldlm_timeout == LDLM_TIMEOUT_DEFAULT)
                ldlm_timeout = MDS_LDLM_TIMEOUT_DEFAULT;

        RETURN(0);

err_qctxt:
        lquota_cleanup(mds_quota_interface_ref, obd);
err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mds_fs_cleanup(obd);
        upcall_cache_cleanup(mds->mds_group_hash);
        mds->mds_group_hash = NULL;
        remove_proc_entry("clear", obd->obd_proc_exports_entry);
err_ns:
        lprocfs_free_per_client_stats(obd);
        lprocfs_free_obd_stats(obd);
        lprocfs_obd_cleanup(obd);
        ldlm_namespace_free(obd->obd_namespace, NULL, 0);
        obd->obd_namespace = NULL;
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
err_put:
        server_put_mount(obd->obd_name, mnt);
        obd->u.obt.obt_sb = NULL;
        return rc;
}

static int mds_lov_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device *lov = mds->mds_lov_obd;
        ENTRY;

        if (mds->mds_profile) {
                class_del_profile(mds->mds_profile);
                OBD_FREE(mds->mds_profile, strlen(mds->mds_profile) + 1);
                mds->mds_profile = NULL;
        }

        /* There better be a lov */
        if (!lov)
                RETURN(0);
        if (IS_ERR(lov))
                RETURN(PTR_ERR(lov));

        obd_register_observer(lov, NULL);

        /* Give lov our same shutdown flags */
        lov->obd_force = obd->obd_force;
        lov->obd_fail = obd->obd_fail;

        /* Cleanup the lov */
        obd_disconnect(mds->mds_lov_exp);
        class_manual_cleanup(lov);
        mds->mds_lov_exp = NULL;

        RETURN(0);
}

static int mds_postsetup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct llog_ctxt *ctxt;
        int rc = 0;
        ENTRY;

        rc = llog_setup(obd, LLOG_CONFIG_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        rc = llog_setup(obd, LLOG_LOVEA_ORIG_CTXT, obd, 0, NULL,
                        &llog_lvfs_ops);
        if (rc)
                GOTO(err_llog, rc);

        if (mds->mds_profile) {
                struct lustre_profile *lprof;
                /* The profile defines which osc and mdc to connect to, for a
                   client.  We reuse that here to figure out the name of the
                   lov to use (and ignore lprof->lp_mdc).
                   The profile was set in the config log with
                   LCFG_MOUNTOPT profilenm oscnm mdcnm */
                lprof = class_get_profile(mds->mds_profile);
                if (lprof == NULL) {
                        CERROR("No profile found: %s\n", mds->mds_profile);
                        GOTO(err_cleanup, rc = -ENOENT);
                }
                rc = mds_lov_connect(obd, lprof->lp_osc);
                if (rc)
                        GOTO(err_cleanup, rc);
        }

        RETURN(rc);

err_cleanup:
        mds_lov_clean(obd);
        ctxt = llog_get_context(obd, LLOG_LOVEA_ORIG_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
err_llog:
        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        if (ctxt)
                llog_cleanup(ctxt);
        return rc;
}

int mds_postrecov(struct obd_device *obd)
{
        int rc;
        ENTRY;

        if (obd->obd_fail)
                RETURN(0);

        LASSERT(!obd->obd_recovering);

        /* VBR: update boot epoch after recovery */
        mds_update_last_epoch(obd);

        /* clean PENDING dir */
        rc = mds_cleanup_pending(obd);
        if (rc < 0)
                GOTO(out, rc);
        /* FIXME Does target_finish_recovery really need this to block? */
        /* Notify the LOV, which will in turn call mds_notify for each tgt */
        /* This means that we have to hack obd_notify to think we're obd_set_up
           during mds_lov_connect. */
        obd_notify(obd->u.mds.mds_lov_obd, NULL,
                   obd->obd_async_recov ? OBD_NOTIFY_SYNC_NONBLOCK :
                   OBD_NOTIFY_SYNC, NULL);

        /* quota recovery */
        if (likely(obd->obd_stopping == 0))
                lquota_recovery(mds_quota_interface_ref, obd);

out:
        RETURN(rc);
}

/* We need to be able to stop an mds_lov_synchronize */
static int mds_lov_early_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_device *lov = mds->mds_lov_obd;

        if (!lov || (!obd->obd_force && !obd->obd_fail))
                return(0);

        CDEBUG(D_HA, "abort inflight\n");
        return (obd_precleanup(lov, OBD_CLEANUP_EARLY));
}

static int mds_precleanup(struct obd_device *obd, enum obd_cleanup_stage stage)
{
        int rc = 0;
        ENTRY;

        switch (stage) {
        case OBD_CLEANUP_EARLY:
                break;
        case OBD_CLEANUP_EXPORTS:
                target_cleanup_recovery(obd);
                mds_lov_early_clean(obd);
                break;
        case OBD_CLEANUP_SELF_EXP:
                mds_lov_disconnect(obd);
                mds_lov_clean(obd);
                llog_cleanup(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT));
                llog_cleanup(llog_get_context(obd, LLOG_LOVEA_ORIG_CTXT));
                rc = obd_llog_finish(obd, 0);
                break;
        case OBD_CLEANUP_OBD:
                break;
        }
        RETURN(rc);
}

static int mds_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        lvfs_sbdev_type save_dev;
        ENTRY;

        if (obd->u.obt.obt_sb == NULL)
                RETURN(0);
        save_dev = lvfs_sbdev(obd->u.obt.obt_sb);

        if (mds->mds_lov_exp)
                /* lov export was disconnected by mds_lov_clean;
                   we just need to drop our ref */
                class_export_put(mds->mds_lov_exp);

        remove_proc_entry("clear", obd->obd_proc_exports_entry);
        lprocfs_free_per_client_stats(obd);
        lprocfs_free_obd_stats(obd);
        lprocfs_obd_cleanup(obd);

        lquota_cleanup(mds_quota_interface_ref, obd);

        mds_update_server_data(obd, 1);
        mds_fs_cleanup(obd);

        upcall_cache_cleanup(mds->mds_group_hash);
        mds->mds_group_hash = NULL;

        server_put_mount(obd->obd_name, mds->mds_vfsmnt);
        obd->u.obt.obt_sb = NULL;

        ldlm_namespace_free(obd->obd_namespace, NULL, obd->obd_force);
        obd->obd_namespace = NULL;

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering) {
                target_cancel_recovery_timer(obd);
                obd->obd_recovering = 0;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        fsfilt_put_ops(obd->obd_fsops);

        LCONSOLE_INFO("MDT %s has stopped.\n", obd->obd_name);

        RETURN(0);
}

static void fixup_handle_for_resent_req(struct ptlrpc_request *req, int offset,
                                        struct ldlm_lock *new_lock,
                                        struct ldlm_lock **old_lock,
                                        struct lustre_handle *lockh)
{
        struct obd_export *exp = req->rq_export;
        struct ldlm_request *dlmreq =
                lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*dlmreq));
        struct lustre_handle remote_hdl = dlmreq->lock_handle[0];
        struct ldlm_lock *lock;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
                return;

        lock = lustre_hash_lookup(exp->exp_lock_hash, &remote_hdl);
        if (lock) {
                if (lock != new_lock) {
                        lockh->cookie = lock->l_handle.h_cookie;
                        LDLM_DEBUG(lock, "restoring lock cookie");
                        DEBUG_REQ(D_DLMTRACE, req, "restoring lock cookie "
                                  LPX64, lockh->cookie);
                        if (old_lock)
                                *old_lock = LDLM_LOCK_GET(lock);

                        lh_put(exp->exp_lock_hash, &lock->l_exp_hash);
                        return;
                }
                lh_put(exp->exp_lock_hash, &lock->l_exp_hash);
        }

        /* If the xid matches, then we know this is a resent request,
         * and allow it. (It's probably an OPEN, for which we don't
         * send a lock */
        if (req->rq_xid <=
            le64_to_cpu(exp->exp_mds_data.med_lcd->lcd_last_xid))
                return;

        if (req->rq_xid <=
            le64_to_cpu(exp->exp_mds_data.med_lcd->lcd_last_close_xid))
                return;

        /* This remote handle isn't enqueued, so we never received or
         * processed this request.  Clear MSG_RESENT, because it can
         * be handled like any normal request now. */

        lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);

        DEBUG_REQ(D_DLMTRACE, req, "no existing lock with rhandle "LPX64,
                  remote_hdl.cookie);
}

#define IS_CLIENT_DISCONNECT_ERROR(error) \
                (error == -ENOTCONN || error == -ENODEV)

static int mds_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        struct ldlm_lock *lock = *lockp;
        struct ldlm_intent *it;
        struct mds_obd *mds = &req->rq_export->exp_obd->u.mds;
        struct ldlm_reply *rep;
        struct lustre_handle lockh = { 0 };
        struct ldlm_lock *new_lock = NULL;
        int getattr_part = MDS_INODELOCK_UPDATE;
        int repsize[5] = { [MSG_PTLRPC_BODY_OFF] = sizeof(struct ptlrpc_body),
                           [DLM_LOCKREPLY_OFF]   = sizeof(struct ldlm_reply),
                           [DLM_REPLY_REC_OFF]   = sizeof(struct mds_body),
                           [DLM_REPLY_REC_OFF+1] = mds->mds_max_mdsize };
        int repbufcnt = 4, rc;
        ENTRY;

        LASSERT(req != NULL);

        if (lustre_msg_bufcount(req->rq_reqmsg) <= DLM_INTENT_IT_OFF) {
                /* No intent was provided */
                rc = lustre_pack_reply(req, 2, repsize, NULL);
                if (rc)
                        RETURN(rc);
                RETURN(0);
        }

        it = lustre_swab_reqbuf(req, DLM_INTENT_IT_OFF, sizeof(*it),
                                lustre_swab_ldlm_intent);
        if (it == NULL) {
                CERROR("Intent missing\n");
                RETURN(req->rq_status = -EFAULT);
        }

        LDLM_DEBUG(lock, "intent policy, opc: %s", ldlm_it2str(it->opc));

        if ((req->rq_export->exp_connect_flags & OBD_CONNECT_ACL) &&
            (it->opc & (IT_OPEN | IT_GETATTR | IT_LOOKUP | IT_READDIR)))
                /* we should never allow OBD_CONNECT_ACL if not configured */
                repsize[repbufcnt++] = LUSTRE_POSIX_ACL_MAX_SIZE;
        else if (it->opc & IT_UNLINK)
                repsize[repbufcnt++] = mds->mds_max_cookiesize;

        /* if we do recovery we isn't send reply mds state is restored */
        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                repsize[DLM_REPLY_REC_OFF+1] = 0;
                if (it->opc & IT_UNLINK)
                        repsize[DLM_REPLY_REC_OFF+2] = 0;
        }

        rc = lustre_pack_reply(req, repbufcnt, repsize, NULL);
        if (rc)
                RETURN(req->rq_status = rc);

        rep = lustre_msg_buf(req->rq_repmsg, DLM_LOCKREPLY_OFF, sizeof(*rep));
        ldlm_reply_set_disposition(rep, DISP_IT_EXECD);

        /* execute policy */
        switch ((long)it->opc) {
        case IT_OPEN:
        case IT_CREAT|IT_OPEN:
                mds_counter_incr(req->rq_export, LPROC_MDS_OPEN);
                fixup_handle_for_resent_req(req, DLM_LOCKREQ_OFF, lock, NULL,
                                            &lockh);
                /* XXX swab here to assert that an mds_open reint
                 * packet is following */
                rep->lock_policy_res2 = mds_reint(req, DLM_INTENT_REC_OFF,
                                                  &lockh);
                mds_shrink_intent_reply(req, REINT_OPEN, DLM_REPLY_REC_OFF);
#if 0
                /* We abort the lock if the lookup was negative and
                 * we did not make it to the OPEN portion */
                if (!ldlm_reply_disposition(rep, DISP_LOOKUP_EXECD))
                        RETURN(ELDLM_LOCK_ABORTED);
                if (ldlm_reply_disposition(rep, DISP_LOOKUP_NEG) &&
                    !ldlm_reply_disposition(rep, DISP_OPEN_OPEN))
#endif

                /* If there was an error of some sort or if we are not
                 * returning any locks */
                 if (rep->lock_policy_res2 ||
                     !ldlm_reply_disposition(rep, DISP_OPEN_LOCK)) {
                        /* If it is the disconnect error (ENODEV & ENOCONN)
                         * ptlrpc layer should know this imediately, it should
                         * be replied by rq_stats, otherwise, return it by
                         * intent here
                         */
                         /* if VBR failure then return error in rq_stats too */
                        if (IS_CLIENT_DISCONNECT_ERROR(rep->lock_policy_res2) ||
                            rep->lock_policy_res2 == -EOVERFLOW)
                                RETURN(rep->lock_policy_res2);
                        else
                                RETURN(ELDLM_LOCK_ABORTED);
                 }
                break;
        case IT_LOOKUP:
                        getattr_part = MDS_INODELOCK_LOOKUP;
        case IT_GETATTR:
                        getattr_part |= MDS_INODELOCK_LOOKUP;
                        mds_counter_incr(req->rq_export, LPROC_MDS_GETATTR);
        case IT_READDIR:
                fixup_handle_for_resent_req(req, DLM_LOCKREQ_OFF, lock,
                                            &new_lock, &lockh);

                /* INODEBITS_INTEROP: if this lock was converted from a
                 * plain lock (client does not support inodebits), then
                 * child lock must be taken with both lookup and update
                 * bits set for all operations.
                 */
                if (!(req->rq_export->exp_connect_flags & OBD_CONNECT_IBITS))
                        getattr_part = MDS_INODELOCK_LOOKUP |
                                       MDS_INODELOCK_UPDATE;

                rep->lock_policy_res2 = mds_getattr_lock(req,DLM_INTENT_REC_OFF,
                                                         getattr_part, &lockh);
                mds_shrink_body_reply(req,DLM_INTENT_REC_OFF, DLM_REPLY_REC_OFF);
                /* FIXME: LDLM can set req->rq_status. MDS sets
                   policy_res{1,2} with disposition and status.
                   - replay: returns 0 & req->status is old status
                   - otherwise: returns req->status */
                if (ldlm_reply_disposition(rep, DISP_LOOKUP_NEG))
                        rep->lock_policy_res2 = 0;
                if (!ldlm_reply_disposition(rep, DISP_LOOKUP_POS) ||
                    rep->lock_policy_res2)
                        RETURN(ELDLM_LOCK_ABORTED);
                if (req->rq_status != 0) {
                        LBUG();
                        rep->lock_policy_res2 = req->rq_status;
                        RETURN(ELDLM_LOCK_ABORTED);
                }
                break;
        default:
                CERROR("Unhandled intent "LPD64"\n", it->opc);
                RETURN(-EFAULT);
        }

        /* By this point, whatever function we called above must have either
         * filled in 'lockh', been an intent replay, or returned an error.  We
         * want to allow replayed RPCs to not get a lock, since we would just
         * drop it below anyways because lock replay is done separately by the
         * client afterwards.  For regular RPCs we want to give the new lock to
         * the client instead of whatever lock it was about to get. */
        if (new_lock == NULL)
                new_lock = ldlm_handle2lock(&lockh);
        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY))
                RETURN(0);

        LASSERTF(new_lock != NULL, "op "LPX64" lockh "LPX64"\n",
                 it->opc, lockh.cookie);

        /* If we've already given this lock to a client once, then we should
         * have no readers or writers.  Otherwise, we should have one reader
         * _or_ writer ref (which will be zeroed below) before returning the
         * lock to a client. */
        if (new_lock->l_export == req->rq_export) {
                LASSERT(new_lock->l_readers + new_lock->l_writers == 0);
        } else {
                LASSERT(new_lock->l_export == NULL);
                LASSERT(new_lock->l_readers + new_lock->l_writers == 1);
        }

        *lockp = new_lock;

        if (new_lock->l_export == req->rq_export) {
                /* Already gave this to the client, which means that we
                 * reconstructed a reply. */
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) &
                        MSG_RESENT);
                RETURN(ELDLM_LOCK_REPLACED);
        }

        /* Fixup the lock to be given to the client */
        lock_res_and_lock(new_lock);
        new_lock->l_readers = 0;
        new_lock->l_writers = 0;

        new_lock->l_export = class_export_get(req->rq_export);
        new_lock->l_blocking_ast = lock->l_blocking_ast;
        new_lock->l_completion_ast = lock->l_completion_ast;
        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        memcpy(&new_lock->l_remote_handle, &lock->l_remote_handle,
               sizeof(lock->l_remote_handle));

        unlock_res_and_lock(new_lock);

        lustre_hash_add(new_lock->l_export->exp_lock_hash,
                        &new_lock->l_remote_handle,
                        &new_lock->l_exp_hash);
        LDLM_LOCK_PUT(new_lock);

        RETURN(ELDLM_LOCK_REPLACED);
}

static int mdt_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lprocfs_static_vars lvars;
        int mds_min_threads;
        int mds_max_threads;
        int rc = 0;
        ENTRY;

        lprocfs_mdt_init_vars(&lvars);
        lprocfs_obd_setup(obd, lvars.obd_vars);

        sema_init(&mds->mds_health_sem, 1);

        if (mds_num_threads) {
                /* If mds_num_threads is set, it is the min and the max. */
                if (mds_num_threads > MDS_THREADS_MAX)
                        mds_num_threads = MDS_THREADS_MAX;
                if (mds_num_threads < MDS_THREADS_MIN)
                        mds_num_threads = MDS_THREADS_MIN;
                mds_max_threads = mds_min_threads = mds_num_threads;
        } else {
                /* Base min threads on memory and cpus */
                mds_min_threads = num_possible_cpus() * CFS_NUM_CACHEPAGES >>
                        (27 - CFS_PAGE_SHIFT);
                if (mds_min_threads < MDS_THREADS_MIN)
                        mds_min_threads = MDS_THREADS_MIN;
                /* Largest auto threads start value */
                if (mds_min_threads > 32)
                        mds_min_threads = 32;
                mds_max_threads = min(MDS_THREADS_MAX, mds_min_threads * 4);
        }

        mds->mds_service =
                ptlrpc_init_svc(MDS_NBUFS, MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_MAXREPSIZE, MDS_REQUEST_PORTAL,
                                MDC_REPLY_PORTAL, MDS_SERVICE_WATCHDOG_FACTOR,
                                mds_handle, LUSTRE_MDS_NAME,
                                obd->obd_proc_entry, target_print_req,
                                mds_min_threads, mds_max_threads, "ll_mdt",
                                NULL);

        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                GOTO(err_lprocfs, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, mds->mds_service);
        if (rc)
                GOTO(err_thread, rc);

        mds->mds_setattr_service =
                ptlrpc_init_svc(MDS_NBUFS, MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_MAXREPSIZE, MDS_SETATTR_PORTAL,
                                MDC_REPLY_PORTAL, MDS_SERVICE_WATCHDOG_FACTOR,
                                mds_handle, "mds_setattr",
                                obd->obd_proc_entry, target_print_req,
                                mds_min_threads, mds_max_threads,
                                "ll_mdt_attr", NULL);
        if (!mds->mds_setattr_service) {
                CERROR("failed to start getattr service\n");
                GOTO(err_thread, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, mds->mds_setattr_service);
        if (rc)
                GOTO(err_thread2, rc);

        mds->mds_readpage_service =
                ptlrpc_init_svc(MDS_NBUFS, MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_MAXREPSIZE, MDS_READPAGE_PORTAL,
                                MDC_REPLY_PORTAL, MDS_SERVICE_WATCHDOG_FACTOR,
                                mds_handle, "mds_readpage",
                                obd->obd_proc_entry, target_print_req,
                                MDS_THREADS_MIN_READPAGE, mds_max_threads,
                                "ll_mdt_rdpg", NULL);
        if (!mds->mds_readpage_service) {
                CERROR("failed to start readpage service\n");
                GOTO(err_thread2, rc = -ENOMEM);
        }

        rc = ptlrpc_start_threads(obd, mds->mds_readpage_service);

        if (rc)
                GOTO(err_thread3, rc);

        ping_evictor_start();

        RETURN(0);

err_thread3:
        ptlrpc_unregister_service(mds->mds_readpage_service);
        mds->mds_readpage_service = NULL;
err_thread2:
        ptlrpc_unregister_service(mds->mds_setattr_service);
        mds->mds_setattr_service = NULL;
err_thread:
        ptlrpc_unregister_service(mds->mds_service);
        mds->mds_service = NULL;
err_lprocfs:
        lprocfs_obd_cleanup(obd);
        return rc;
}

static int mdt_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        ping_evictor_stop();

        down(&mds->mds_health_sem);
        ptlrpc_unregister_service(mds->mds_readpage_service);
        ptlrpc_unregister_service(mds->mds_setattr_service);
        ptlrpc_unregister_service(mds->mds_service);
        mds->mds_readpage_service = NULL;
        mds->mds_setattr_service = NULL;
        mds->mds_service = NULL;
        up(&mds->mds_health_sem);

        lprocfs_obd_cleanup(obd);

        RETURN(0);
}

static int mdt_health_check(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;

        down(&mds->mds_health_sem);
        rc |= ptlrpc_service_health_check(mds->mds_readpage_service);
        rc |= ptlrpc_service_health_check(mds->mds_setattr_service);
        rc |= ptlrpc_service_health_check(mds->mds_service);
        up(&mds->mds_health_sem);

        /*
         * health_check to return 0 on healthy
         * and 1 on unhealthy.
         */
        if(rc != 0)
                rc = 1;

        return rc;
}

static struct dentry *mds_lvfs_fid2dentry(__u64 id, __u32 gen, __u64 gr,
                                          void *data)
{
        struct obd_device *obd = data;
        struct ll_fid fid;
        fid.id = id;
        fid.generation = gen;
        return mds_fid2dentry(&obd->u.mds, &fid, NULL);
}

static int mds_health_check(struct obd_device *obd)
{
        struct obd_device_target *odt = &obd->u.obt;
#ifdef USE_HEALTH_CHECK_WRITE
        struct mds_obd *mds = &obd->u.mds;
#endif
        int rc = 0;

        if (odt->obt_sb->s_flags & MS_RDONLY)
                rc = 1;

#ifdef USE_HEALTH_CHECK_WRITE
        LASSERT(mds->mds_obt.obt_health_check_filp != NULL);
        rc |= !!lvfs_check_io_health(obd, mds->mds_obt.obt_health_check_filp);
#endif

        return rc;
}

static int mds_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        int rc = 0;

        switch(lcfg->lcfg_command) {
        case LCFG_PARAM: {
                struct lprocfs_static_vars lvars;
                lprocfs_mds_init_vars(&lvars);

                rc = class_process_proc_param(PARAM_MDT, lvars.obd_vars, lcfg, obd);
                break;
        }
        default:
                break;
        }

        return(rc);
}

struct lvfs_callback_ops mds_lvfs_ops = {
        l_fid2dentry:     mds_lvfs_fid2dentry,
};

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_connect         = mds_connect,
        .o_reconnect       = mds_reconnect,
        .o_init_export     = mds_init_export,
        .o_destroy_export  = mds_destroy_export,
        .o_disconnect      = mds_disconnect,
        .o_setup           = mds_setup,
        .o_precleanup      = mds_precleanup,
        .o_cleanup         = mds_cleanup,
        .o_postrecov       = mds_postrecov,
        .o_statfs          = mds_obd_statfs,
        .o_iocontrol       = mds_iocontrol,
        .o_create          = mds_obd_create,
        .o_destroy         = mds_obd_destroy,
        .o_llog_init       = mds_llog_init,
        .o_llog_finish     = mds_llog_finish,
        .o_notify          = mds_notify,
        .o_health_check    = mds_health_check,
        .o_process_config  = mds_process_config,
};

static struct obd_ops mdt_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_setup           = mdt_setup,
        .o_cleanup         = mdt_cleanup,
        .o_health_check    = mdt_health_check,
};

quota_interface_t *mds_quota_interface_ref;
extern quota_interface_t mds_quota_interface;

static int __init mds_init(void)
{
        int rc;
        struct lprocfs_static_vars lvars;

        request_module("lquota");
        mds_quota_interface_ref = PORTAL_SYMBOL_GET(mds_quota_interface);
        rc = lquota_init(mds_quota_interface_ref);
        if (rc) {
                if (mds_quota_interface_ref)
                        PORTAL_SYMBOL_PUT(mds_quota_interface);
                return rc;
        }
        init_obd_quota_ops(mds_quota_interface_ref, &mds_obd_ops);

        lprocfs_mds_init_vars(&lvars);
        class_register_type(&mds_obd_ops, lvars.module_vars, LUSTRE_MDS_NAME);
        lprocfs_mdt_init_vars(&lvars);
        class_register_type(&mdt_obd_ops, lvars.module_vars, LUSTRE_MDT_NAME);

        return 0;
}

static void /*__exit*/ mds_exit(void)
{
        lquota_exit(mds_quota_interface_ref);
        if (mds_quota_interface_ref)
                PORTAL_SYMBOL_PUT(mds_quota_interface);

        class_unregister_type(LUSTRE_MDS_NAME);
        class_unregister_type(LUSTRE_MDT_NAME);
}

MODULE_AUTHOR("Sun Microsystems, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS)");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
