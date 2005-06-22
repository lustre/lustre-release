/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/handler.c
 *  Lustre Metadata Server (mds) request handler
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Phil Schwan <phil@clusterfs.com>
 *   Author: Mike Shaver <shaver@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/fs.h>
#include <linux/jbd.h>
#include <linux/namei.h>
#include <linux/ext3_fs.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
# include <linux/smp_lock.h>
# include <linux/buffer_head.h>
# include <linux/workqueue.h>
# include <linux/mount.h>
#else
# include <linux/locks.h>
#endif
#include <linux/obd_lov.h>
#include <linux/obd_ost.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lprocfs_status.h>
#include <linux/lustre_commit_confd.h>
#include <linux/lustre_acl.h>
#include "mds_internal.h"
#include <linux/lustre_sec.h>

static int mds_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data);
static int mds_postsetup(struct obd_device *obd);
static int mds_cleanup(struct obd_device *obd, int flags);


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
                       OBD_FAIL_MDS_SENDPAGE, rc = -EIO);
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

        ptlrpc_fail_export(req->rq_export);

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

extern char *ldlm_lockname[];

int mds_lock_mode_for_dir(struct obd_device *obd,
                          struct dentry *dentry, int mode)
{
        int ret_mode = 0, split;

        /* any dir access needs couple locks:
         * 1) on part of dir we gonna lookup/modify in
         * 2) on a whole dir to protect it from concurrent splitting
         *    and to flush client's cache for readdir()
         * so, for a given mode and dentry this routine decides what
         * lock mode to use for lock #2:
         * 1) if caller's gonna lookup in dir then we need to protect
         *    dir from being splitted only - LCK_CR
         * 2) if caller's gonna modify dir then we need to protect
         *    dir from being splitted and to flush cache - LCK_CW
         * 3) if caller's gonna modify dir and that dir seems ready
         *    for splitting then we need to protect it from any
         *    type of access (lookup/modify/split) - LCK_EX -bzzz */

        split = mds_splitting_expected(obd, dentry);
        
        /*
         * it is important to check here only for MDS_NO_SPLITTABLE. The reason
         * is that MDS_NO_SPLITTABLE means dir is not splittable in principle
         * and another thread will not split it on the quiet. But if we have
         * MDS_NO_SPLIT_EXPECTED, this means, that dir may be splitted anytime,
         * but not now (for current thread) and we should consider that it can
         * happen soon and go that branch which can yield LCK_EX to protect from
         * possible splitting.
         */
        if (split == MDS_NO_SPLITTABLE) {
                /*
                 * this inode won't be splitted. so we need not to protect from
                 * just flush client's cache on modification.
                 */
                if (mode == LCK_PW)
                        ret_mode = LCK_CW;
                else
                        ret_mode = 0;
        } else {
                if (mode == LCK_EX) {
                        ret_mode = LCK_EX;
                } else if (mode == LCK_PR) {
                        ret_mode = LCK_CR;
                } else if (mode == LCK_PW) {
                        /*
                         * caller gonna modify directory. We use concurrent
                         * write lock here to retract client's cache for
                         * readdir.
                         */
                        if (split == MDS_EXPECT_SPLIT) {
                                /*
                                 * splitting possible. serialize any access the
                                 * idea is that first one seen dir is splittable
                                 * is given exclusive lock and split
                                 * directory. caller passes lock mode to
                                 * mds_try_to_split_dir() and splitting would be
                                 * done with exclusive lock only -bzzz.
                                 */
                                CDEBUG(D_OTHER, "%s: gonna split %lu/%lu\n",
                                       obd->obd_name,
                                       (unsigned long)dentry->d_inode->i_ino,
                                       (unsigned long)dentry->d_inode->i_generation);
                                ret_mode = LCK_EX;
                        } else {
                                ret_mode = LCK_CW;
                        }
                }
        }

	return ret_mode;        
}

/* only valid locked dentries or errors should be returned */
struct dentry *mds_id2locked_dentry(struct obd_device *obd, struct lustre_id *id,
                                    struct vfsmount **mnt, int lock_mode,
                                    struct lustre_handle *lockh, int *mode,
                                    char *name, int namelen, __u64 lockpart)
{
        struct dentry *de = mds_id2dentry(obd, id, mnt), *retval = de;
        ldlm_policy_data_t policy = { .l_inodebits = { lockpart } };
        struct ldlm_res_id res_id = { .name = {0} };
        int flags = 0, rc;
        ENTRY;

        if (IS_ERR(de))
                RETURN(de);

        lockh[1].cookie = 0;
        res_id.name[0] = id_fid(id);
        res_id.name[1] = id_group(id);
        
#ifdef S_PDIROPS
        if (name && IS_PDIROPS(de->d_inode)) {
                ldlm_policy_data_t cpolicy =
                        { .l_inodebits = { MDS_INODELOCK_UPDATE } };
                LASSERT(mode != NULL);
                *mode = mds_lock_mode_for_dir(obd, de, lock_mode);
                if (*mode) {
                        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace,
                                              res_id, LDLM_IBITS,
                                              &cpolicy, *mode, &flags,
                                              mds_blocking_ast,
                                              ldlm_completion_ast, NULL, NULL,
                                              NULL, 0, NULL, lockh + 1);
                        if (rc != ELDLM_OK) {
                                l_dput(de);
                                RETURN(ERR_PTR(-ENOLCK));
                        }
                }
                flags = 0;

                res_id.name[2] = full_name_hash((unsigned char *)name, namelen);

                CDEBUG(D_INFO, "take lock on "DLID4":"LPX64"\n",
                       OLID4(id), res_id.name[2]);
        }
#else
#warning "No PDIROPS support in the kernel"
#endif
        rc = ldlm_cli_enqueue(NULL, NULL, obd->obd_namespace, res_id,
                              LDLM_IBITS, &policy, lock_mode, &flags,
                              mds_blocking_ast, ldlm_completion_ast,
                              NULL, NULL, NULL, 0, NULL, lockh);
        if (rc != ELDLM_OK) {
                l_dput(de);
                retval = ERR_PTR(-EIO); /* XXX translate ldlm code */
#ifdef S_PDIROPS
                if (lockh[1].cookie)
                        ldlm_lock_decref(lockh + 1, *mode);
#endif
        }

        RETURN(retval);
}

#ifndef DCACHE_DISCONNECTED
#define DCACHE_DISCONNECTED DCACHE_NFSD_DISCONNECTED
#endif

/* Look up an entry by inode number. This function ONLY returns valid dget'd
 * dentries with an initialized inode or errors */
struct dentry *mds_id2dentry(struct obd_device *obd, struct lustre_id *id,
                             struct vfsmount **mnt)
{
        unsigned long ino = (unsigned long)id_ino(id);
        __u32 generation = (__u32)id_gen(id);
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *result;
        struct inode *inode;
        char idname[32];

        if (ino == 0)
                RETURN(ERR_PTR(-ESTALE));

        snprintf(idname, sizeof(idname), "0x%lx", ino);

        CDEBUG(D_DENTRY, "--> mds_id2dentry: ino/gen %lu/%u, sb %p\n",
               ino, generation, mds->mds_sb);

        /* under ext3 this is neither supposed to return bad inodes nor NULL
           inodes. */
        result = ll_lookup_one_len(idname, mds->mds_id_de, 
                                   strlen(idname));
        if (IS_ERR(result))
                RETURN(result);

        inode = result->d_inode;
        if (!inode)
                RETURN(ERR_PTR(-ENOENT));

        if (is_bad_inode(inode)) {
                CERROR("bad inode returned %lu/%u\n",
                       inode->i_ino, inode->i_generation);
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        /* here we disabled generation check, as root inode i_generation
         * of cache mds and real mds are different. */
        if (inode->i_ino != id_ino(&mds->mds_rootid) && generation &&
            inode->i_generation != generation) {
                /* we didn't find the right inode.. */
                if (id_group(id) != mds->mds_num) {
                        CERROR("bad inode %lu found, link: %lu, ct: %d, generation "
                               "%u != %u, mds %u != %u, request to wrong MDS?\n",
                               inode->i_ino, (unsigned long)inode->i_nlink,
                               atomic_read(&inode->i_count), inode->i_generation,
                               generation, mds->mds_num, (unsigned)id_group(id));
                } else {
                        CERROR("bad inode %lu found, link: %lu, ct: %d, generation "
                               "%u != %u, inode is recreated while request handled?\n",
                               inode->i_ino, (unsigned long)inode->i_nlink,
                               atomic_read(&inode->i_count), inode->i_generation,
                               generation);
                }
                dput(result);
                RETURN(ERR_PTR(-ENOENT));
        }

        if (mnt) {
                *mnt = mds->mds_vfsmnt;
                mntget(*mnt);
        }

        RETURN(result);
}

static
int mds_req_add_idmapping(struct ptlrpc_request *req,
                          struct mds_export_data *med)
{
        struct mds_req_sec_desc *rsd;
        struct lustre_sec_desc  *lsd;
        int rc;

        if (!med->med_remote)
                return 0;

        /* maybe we should do it more completely: invalidate the gss ctxt? */
        if (req->rq_mapped_uid == MDS_IDMAP_NOTFOUND) {
                CWARN("didn't find mapped uid\n");
                return -EPERM;
        }

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                return -EPROTO;
        }

        lsd = mds_get_lsd(req->rq_mapped_uid);
        if (!lsd) {
                CERROR("can't get LSD(%u), no mapping added\n",
                       req->rq_mapped_uid);
                return -EPERM;
        }

        rc = mds_idmap_add(med->med_idmap, rsd->rsd_uid, lsd->lsd_uid,
                           rsd->rsd_gid, lsd->lsd_gid);
        mds_put_lsd(lsd);
        return rc;
}

static
int mds_req_del_idmapping(struct ptlrpc_request *req,
                          struct mds_export_data *med)
{
        struct mds_req_sec_desc *rsd;
        struct lustre_sec_desc  *lsd;
        int rc;

        if (!med->med_remote)
                return 0;

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                return -EPROTO;
        }

        LASSERT(req->rq_mapped_uid != -1);
        lsd = mds_get_lsd(req->rq_mapped_uid);
        if (!lsd) {
                CERROR("can't get LSD(%u), no idmapping deleted\n",
                       req->rq_mapped_uid);
                return -EPERM;
        }

        rc = mds_idmap_del(med->med_idmap, rsd->rsd_uid, lsd->lsd_uid,
                           rsd->rsd_gid, lsd->lsd_gid);
        mds_put_lsd(lsd);
        return rc;
}

static int mds_init_export_data(struct ptlrpc_request *req,
                                struct mds_export_data *med)
{
        struct obd_connect_data *data, *reply;
        int ask_remote, ask_local;
        ENTRY;

        data = lustre_msg_buf(req->rq_reqmsg, 5, sizeof(*data));
        reply = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*data));
        LASSERT(data && reply);

        if (med->med_initialized) {
                CDEBUG(D_SEC, "med already initialized, reconnect?\n");
                goto reply;
        }

        ask_remote = data->ocd_connect_flags & OBD_CONNECT_REMOTE;
        ask_local = data->ocd_connect_flags & OBD_CONNECT_LOCAL;

        /* currently the policy is simple: satisfy client as possible
         * as we can.
         */
        if (req->rq_auth_uid == -1) {
                if (ask_remote)
                        CWARN("null sec is used, force to be local\n");
                med->med_remote = 0;
        } else {
                if (ask_remote) {
                        if (!req->rq_remote_realm)
                                CWARN("local realm asked to be remote\n");
                        med->med_remote = 1;
                } else if (ask_local) {
                        if (req->rq_remote_realm)
                                CWARN("remote realm asked to be local\n");
                        med->med_remote = 0;
                } else
                        med->med_remote = (req->rq_remote_realm != 0);
        }

        med->med_nllu = data->ocd_nllu[0];
        med->med_nllg = data->ocd_nllu[1];

        med->med_initialized = 1;
reply:
        reply->ocd_connect_flags &= ~(OBD_CONNECT_REMOTE | OBD_CONNECT_LOCAL);
        if (med->med_remote) {
                if (!med->med_idmap)
                        med->med_idmap = mds_idmap_alloc();

                if (!med->med_idmap)
                        CERROR("Failed to alloc idmap, following request from "
                               "this client will be refused\n");

                reply->ocd_connect_flags |= OBD_CONNECT_REMOTE;
                CDEBUG(D_SEC, "set client as remote\n");
        } else {
                reply->ocd_connect_flags |= OBD_CONNECT_LOCAL;
                CDEBUG(D_SEC, "set client as local\n");
        }

        RETURN(0);
}

static void mds_free_export_data(struct mds_export_data *med)
{
        if (!med->med_idmap)
                return;

        LASSERT(med->med_remote);
        mds_idmap_free(med->med_idmap);
        med->med_idmap = NULL;
}

/* Establish a connection to the MDS.
 *
 * This will set up an export structure for the client to hold state data about
 * that client, like open files, the last operation number it did on the server,
 * etc.
 */
static int mds_connect(struct lustre_handle *conn, struct obd_device *obd,
                       struct obd_uuid *cluuid, struct obd_connect_data *data,
                       unsigned long flags)
{
        struct mds_export_data *med;
        struct mds_client_data *mcd;
        struct obd_export *exp;
        int rc;
        ENTRY;

        if (!conn || !obd || !cluuid)
                RETURN(-EINVAL);

        /* XXX There is a small race between checking the list and adding a new
         * connection for the same UUID, but the real threat (list corruption
         * when multiple different clients connect) is solved.
         *
         * There is a second race between adding the export to the list, and
         * filling in the client data below.  Hence skipping the case of NULL
         * mcd above.  We should already be controlling multiple connects at the
         * client, and we can't hold the spinlock over memory allocations
         * without risk of deadlocking.
         */
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                RETURN(rc);
        exp = class_conn2export(conn);
        
        LASSERT(exp != NULL);
        med = &exp->exp_mds_data;

        OBD_ALLOC(mcd, sizeof(*mcd));
        if (!mcd) {
                CERROR("%s: out of memory for client data.\n",
                        obd->obd_name);
                GOTO(out, rc = -ENOMEM);
        }

        memcpy(mcd->mcd_uuid, cluuid, sizeof(mcd->mcd_uuid));
        med->med_mcd = mcd;

        rc = mds_client_add(obd, &obd->u.mds, med, -1);
        if (rc)
                GOTO(out, rc);
       
        EXIT;
out:
        if (rc) {
                if (mcd)
                        OBD_FREE(mcd, sizeof(*mcd));
                class_disconnect(exp, 0);
        } else {
                class_export_put(exp);
        }
        return rc;
}

static int mds_connect_post(struct obd_export *exp, unsigned initial,
                            unsigned long flags)
{
        struct obd_device *obd = exp->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct mds_export_data *med;
        struct mds_client_data *mcd;
        int rc = 0;
        ENTRY;

        med = &exp->exp_mds_data;
        mcd = med->med_mcd;

        if (initial) {
                /* some one reconnect initially, we have to reset
                 * data existing export can have. bug 6102 */
                if (mcd->mcd_last_xid != 0)
                        CDEBUG(D_HA, "initial reconnect to existing export\n");
                mcd->mcd_last_transno = 0;
                mcd->mcd_last_xid = 0;
                mcd->mcd_last_result = 0;
                mcd->mcd_last_data = 0;
        }

        if (!(flags & OBD_OPT_MDS_CONNECTION)) {
                if (!(exp->exp_flags & OBD_OPT_REAL_CLIENT)) {
                        atomic_inc(&mds->mds_real_clients);
                        CDEBUG(D_OTHER,"%s: peer from %s is real client (%d)\n",
                               obd->obd_name, exp->exp_client_uuid.uuid,
                               atomic_read(&mds->mds_real_clients));
                        exp->exp_flags |= OBD_OPT_REAL_CLIENT;
                }
                if (mds->mds_md_name)
                        rc = mds_md_connect(obd, mds->mds_md_name);
        }
        RETURN(rc);
}

static int mds_init_export(struct obd_export *exp)
{
        struct mds_export_data *med = &exp->exp_mds_data;

        INIT_LIST_HEAD(&med->med_open_head);
        spin_lock_init(&med->med_open_lock);
        return 0;
}

static int mds_destroy_export(struct obd_export *export)
{
        struct obd_device *obd = export->exp_obd;
        struct mds_export_data *med = &export->exp_mds_data;
        struct lvfs_run_ctxt saved;
        int rc = 0;
        ENTRY;

        mds_free_export_data(med);
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
                struct lustre_id sid;
                
                BDEVNAME_DECLARE_STORAGE(btmp);

                /* bug 1579: fix force-closing for 2.5 */
                struct dentry *dentry = mfd->mfd_dentry;

                list_del(&mfd->mfd_list);
                spin_unlock(&med->med_open_lock);

                down(&dentry->d_inode->i_sem);
                rc = mds_read_inode_sid(obd, dentry->d_inode, &sid);
                up(&dentry->d_inode->i_sem);
                if (rc) {
                        CERROR("Can't read inode self id, inode %lu, "
                               "rc %d\n", dentry->d_inode->i_ino, rc);
                        memset(&sid, 0, sizeof(sid));
                }

                /* If you change this message, be sure to update
                 * replay_single:test_46 */
                CERROR("force closing client file handle for %.*s (%s:"
                       DLID4")\n", dentry->d_name.len, dentry->d_name.name,
                       ll_bdevname(dentry->d_inode->i_sb, btmp),
                       OLID4(&sid));
                
                /* child inode->i_alloc_sem protects orphan_dec_test and
                 * is_orphan race, mds_mfd_close drops it */
                DOWN_WRITE_I_ALLOC_SEM(dentry->d_inode);
                rc = mds_mfd_close(NULL, 0, obd, mfd,
                                   !(export->exp_flags & OBD_OPT_FAILOVER));
                if (rc)
                        CDEBUG(D_INODE, "Error closing file: %d\n", rc);
                spin_lock(&med->med_open_lock);
        }
        spin_unlock(&med->med_open_lock);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        EXIT;
out:
        mds_client_free(export, !(export->exp_flags & OBD_OPT_FAILOVER));
        return rc;
}

static int mds_disconnect(struct obd_export *exp, unsigned long flags)
{
        unsigned long irqflags;
        struct obd_device *obd;
        struct mds_obd *mds;
        int rc;
        ENTRY;

        LASSERT(exp != NULL);
        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }
        mds = &obd->u.mds;

        /*
         * suppress any inter-mds requests durring disconnecting lmv if this is
         * detected --force mode. This is needed to avoid endless recovery.
         */
        if (atomic_read(&mds->mds_real_clients) > 0 &&
            !(exp->exp_flags & OBD_OPT_REAL_CLIENT))
                flags |= OBD_OPT_FORCE;
                                                                                              
        if (!(exp->exp_flags & OBD_OPT_REAL_CLIENT)
            && !atomic_read(&mds->mds_real_clients)) {
                /* there was no client at all */
                mds_md_disconnect(obd, flags);
        }

        if ((exp->exp_flags & OBD_OPT_REAL_CLIENT)
            && atomic_dec_and_test(&mds->mds_real_clients)) {
                /* time to drop LMV connections */
                CDEBUG(D_OTHER, "%s: last real client %s disconnected.  "
                       "Disconnnect from LMV now\n",
                       obd->obd_name, exp->exp_client_uuid.uuid);
                mds_md_disconnect(obd, flags);
        }

        spin_lock_irqsave(&exp->exp_lock, irqflags);
        exp->exp_flags = flags;
        spin_unlock_irqrestore(&exp->exp_lock, irqflags);

        /* disconnect early so that clients can't keep using export */
        rc = class_disconnect(exp, flags);
        ldlm_cancel_locks_for_export(exp);

        /* complete all outstanding replies */
        spin_lock_irqsave(&exp->exp_lock, irqflags);
        while (!list_empty(&exp->exp_outstanding_replies)) {
                struct ptlrpc_reply_state *rs =
                        list_entry(exp->exp_outstanding_replies.next,
                                   struct ptlrpc_reply_state, rs_exp_list);
                struct ptlrpc_service *svc = rs->rs_srv_ni->sni_service;

                spin_lock(&svc->srv_lock);
                list_del_init(&rs->rs_exp_list);
                ptlrpc_schedule_difficult_reply(rs);
                spin_unlock(&svc->srv_lock);
        }
        spin_unlock_irqrestore(&exp->exp_lock, irqflags);
        RETURN(rc);
}

static int mds_getstatus(struct ptlrpc_request *req)
{
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc, size;
        ENTRY;

        size = sizeof(*body);
        
        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_GETSTATUS_PACK)) {
                CERROR("mds: out of memory for message: size=%d\n", size);
                req->rq_status = -ENOMEM;       /* superfluous? */
                RETURN(-ENOMEM);
        }

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*body));
        body->valid |= OBD_MD_FID;
        
        memcpy(&body->id1, &mds->mds_rootid, sizeof(body->id1));

        /*
         * the last_committed and last_xid fields are filled in for all replies
         * already - no need to do so here also.
         */
        RETURN(0);
}

int mds_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                     void *data, int flag)
{
        int do_ast;
        ENTRY;

        if (flag == LDLM_CB_CANCELING) {
                /* Don't need to do anything here. */
                RETURN(0);
        }

        /* XXX layering violation!  -phil */
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        
        /*
         * get this: if mds_blocking_ast is racing with mds_intent_policy, such
         * that mds_blocking_ast is called just before l_i_p takes the ns_lock,
         * then by the time we get the lock, we might not be the correct
         * blocking function anymore.  So check, and return early, if so.
         */
        if (lock->l_blocking_ast != mds_blocking_ast) {
                l_unlock(&lock->l_resource->lr_namespace->ns_lock);
                RETURN(0);
        }

        lock->l_flags |= LDLM_FL_CBPENDING;
        do_ast = (!lock->l_readers && !lock->l_writers);
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);

        if (do_ast) {
                struct lustre_handle lockh;
                int rc;

                LDLM_DEBUG(lock, "already unused, calling ldlm_cli_cancel");
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0)
                        CERROR("ldlm_cli_cancel: %d\n", rc);
        } else {
                LDLM_DEBUG(lock, "Lock still has references, will be "
                           "cancelled later");
        }
        RETURN(0);
}

static int mds_convert_md(struct obd_device *obd, struct inode *inode,
                          void *md, int size, int mea)
{
        int rc = size;
        
        if (S_ISREG(inode->i_mode)) {
                rc = mds_convert_lov_ea(obd, inode, md, size);
        } else if (S_ISDIR(inode->i_mode)) {
                if (mea) {
                        rc = mds_convert_mea_ea(obd, inode, md, size);
                } else {
                        rc = mds_convert_lov_ea(obd, inode, md, size);
                }
                if (rc == -EINVAL) {
                        CERROR("Invalid EA format (nor LOV or MEA) "
                               "is detected. Inode %lu/%u\n",
                               inode->i_ino, inode->i_generation);
                }
        }
        return rc;
}

int mds_get_md(struct obd_device *obd, struct inode *inode,
               void *md, int *size, int lock, int mea)
{
        int lmm_size;
        int rc = 0;
        ENTRY;

        if (lock)
                down(&inode->i_sem);

        rc = fsfilt_get_md(obd, inode, md, *size,
                           (mea ? EA_MEA : EA_LOV));
        if (rc < 0) {
                CERROR("Error %d reading eadata for ino %lu\n",
                       rc, inode->i_ino);
        } else if (rc > 0) {
                lmm_size = rc;
                rc = mds_convert_md(obd, inode, md,
                                    lmm_size, mea);
                if (rc == 0) {
                        *size = lmm_size;
                        rc = lmm_size;
                } else if (rc > 0) {
                        *size = rc;
                }
        }
        if (lock)
                up(&inode->i_sem);

        RETURN(rc);
}

/* Call with lock=1 if you want mds_pack_md to take the i_sem.
 * Call with lock=0 if the caller has already taken the i_sem. */
int mds_pack_md(struct obd_device *obd, struct lustre_msg *msg, int offset,
                struct mds_body *body, struct inode *inode, int lock, int mea)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc, lmm_size;
        void *lmm;
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

        rc = mds_get_md(obd, inode, lmm, &lmm_size, lock, mea);
        if (rc > 0) {
                body->valid |= S_ISDIR(inode->i_mode) ?
                        OBD_MD_FLDIREA : OBD_MD_FLEASIZE;
                
                if (mea)
                        body->valid |= OBD_MD_MEA;
                
                body->eadatasize = lmm_size;
                rc = 0;
        }

        RETURN(rc);
}

int mds_pack_link(struct dentry *dentry, struct ptlrpc_request *req,
                  struct mds_body *repbody, int reply_off)
{
        struct inode *inode = dentry->d_inode;
        char *symname;
        int len, rc;
        ENTRY;

        symname = lustre_msg_buf(req->rq_repmsg, reply_off + 1,0);
        LASSERT(symname != NULL);
        len = req->rq_repmsg->buflens[reply_off + 1];
        
        rc = inode->i_op->readlink(dentry, symname, len);
        if (rc < 0) {
                CERROR("readlink failed: %d\n", rc);
        } else if (rc != len - 1) {
                CERROR ("Unexpected readlink rc %d: expecting %d\n",
                        rc, len - 1);
                rc = -EINVAL;
        } else {
                CDEBUG(D_INODE, "read symlink dest %s\n", symname);
                repbody->valid |= OBD_MD_LINKNAME;
                repbody->eadatasize = rc + 1;
                symname[rc] = 0;        /* NULL terminate */
                rc = 0;
        }

        RETURN(rc);
}

int mds_pack_ea(struct dentry *dentry, struct ptlrpc_request *req,
                struct mds_body *repbody, int req_off, int reply_off)
{
        struct inode *inode = dentry->d_inode;
        char *ea_name;
        void *value = NULL;
        int len, rc;
        ENTRY;

        ea_name = lustre_msg_string(req->rq_reqmsg, req_off + 1, 0);
        len = req->rq_repmsg->buflens[reply_off + 1];
        if (len != 0)
                value = lustre_msg_buf(req->rq_repmsg, reply_off + 1, len);

        rc = -EOPNOTSUPP;
        if (inode->i_op && inode->i_op->getxattr) 
                rc = inode->i_op->getxattr(dentry, ea_name, value, len);

        if (rc < 0) {
                if (rc != -ENODATA && rc != -EOPNOTSUPP)
                        CERROR("getxattr failed: %d", rc);
        } else {
                repbody->valid |= OBD_MD_FLEA;
                repbody->eadatasize = rc;
                rc = 0;
        }

        RETURN(rc);        
}

int mds_pack_ealist(struct dentry *dentry, struct ptlrpc_request *req,
                    struct mds_body *repbody, int reply_off)
{
        struct inode *inode = dentry->d_inode;        
        void *value = NULL;
        int len, rc;
        ENTRY;

        len = req->rq_repmsg->buflens[reply_off + 1];
        if (len != 0)
                value = lustre_msg_buf(req->rq_repmsg, reply_off + 1, len);

        rc = -EOPNOTSUPP;
        if (inode->i_op && inode->i_op->getxattr) 
                rc = inode->i_op->listxattr(dentry, value, len);

        if (rc < 0) {
                CERROR("listxattr failed: %d", rc);
        } else {
                repbody->valid |= OBD_MD_FLEALIST;
                repbody->eadatasize = rc;
                rc = 0;
        }
        RETURN(rc);
}

int mds_pack_acl(struct obd_device *obd, struct lustre_msg *repmsg, int offset,
                 struct mds_body *body, struct inode *inode)
{
        struct dentry de = { .d_inode = inode };
        __u32 buflen, *sizep;
        void *buf;
        int size;
        ENTRY;

        if (!inode->i_op->getxattr)
                RETURN(0);

        buflen = repmsg->buflens[offset + 1];
        buf = lustre_msg_buf(repmsg, offset + 1, buflen);

        size = inode->i_op->getxattr(&de, XATTR_NAME_ACL_ACCESS, buf, buflen);
        if (size == -ENODATA || size == -EOPNOTSUPP)
                RETURN(0);
        if (size < 0)
                RETURN(size);
        LASSERT(size);

        sizep = lustre_msg_buf(repmsg, offset, 4);
        if (!sizep) {
                CERROR("can't locate returned acl size buf\n");
                RETURN(-EPROTO);
        }

        *sizep = cpu_to_le32(size);
        body->valid |= OBD_MD_FLACL_ACCESS;

        RETURN(0);
}

/* 
 * here we take simple rule: once uid/fsuid is root, we also squash
 * the gid/fsgid, don't care setuid/setgid attributes.
 */
int mds_squash_root(struct mds_obd *mds, struct mds_req_sec_desc *rsd,
                    ptl_nid_t *peernid)
{
        if (!mds->mds_squash_uid || *peernid == mds->mds_nosquash_nid)
                return 0;

        if (rsd->rsd_uid && rsd->rsd_fsuid)
                return 0;

        CDEBUG(D_SEC, "squash req from "LPX64":"
               "(%u:%u-%u:%u/%x)=>(%u:%u-%u:%u/%x)\n", *peernid,
                rsd->rsd_uid, rsd->rsd_gid,
                rsd->rsd_fsuid, rsd->rsd_fsgid, rsd->rsd_cap,
                rsd->rsd_uid ? rsd->rsd_uid : mds->mds_squash_uid,
                rsd->rsd_uid ? rsd->rsd_gid : mds->mds_squash_gid,
                rsd->rsd_fsuid ? rsd->rsd_fsuid : mds->mds_squash_uid,
                rsd->rsd_fsuid ? rsd->rsd_fsgid : mds->mds_squash_gid,
                rsd->rsd_cap & ~CAP_FS_MASK);

        if (rsd->rsd_uid == 0) {
                rsd->rsd_uid = mds->mds_squash_uid;
                rsd->rsd_gid = mds->mds_squash_gid;
        }
        if (rsd->rsd_fsuid == 0) {
                rsd->rsd_fsuid = mds->mds_squash_uid;
                rsd->rsd_fsgid = mds->mds_squash_gid;
        }
        rsd->rsd_cap &= ~CAP_FS_MASK;

        return 1;
}

static int mds_getattr_internal(struct obd_device *obd, struct dentry *dentry,
                                struct ptlrpc_request *req, int req_off,
                                struct mds_body *reqbody, int reply_off)
{
        struct mds_export_data *med = &req->rq_export->u.eu_mds_data;
        struct inode *inode = dentry->d_inode;
        struct mds_body *body;
        int rc = 0;
        ENTRY;

        if (inode == NULL && !(dentry->d_flags & DCACHE_CROSS_REF))
                RETURN(-ENOENT);

        body = lustre_msg_buf(req->rq_repmsg, reply_off, sizeof(*body));
        LASSERT(body != NULL);                 /* caller prepped reply */

        if (dentry->d_flags & DCACHE_CROSS_REF) {
                mds_pack_dentry2body(obd, body, dentry,
                                     (reqbody->valid & OBD_MD_FID) ? 1 : 0);
                CDEBUG(D_OTHER, "cross reference: "DLID4"\n",
                       OLID4(&body->id1));
                RETURN(0);
        }
        
        mds_pack_inode2body(obd, body, inode,
                            (reqbody->valid & OBD_MD_FID) ? 1 : 0);

        if ((S_ISREG(inode->i_mode) && (reqbody->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (reqbody->valid & OBD_MD_FLDIREA))) {
	    
	        /* guessing what kind og attribute do we need. */
		int is_mea = (S_ISDIR(inode->i_mode) && 
		    (reqbody->valid & OBD_MD_MEA) != 0);
		
                rc = mds_pack_md(obd, req->rq_repmsg, reply_off + 1, 
				 body, inode, 1, is_mea);

                /* if we have LOV EA data, the OST holds size, atime, mtime. */
                if (!(body->valid & OBD_MD_FLEASIZE) &&
                    !(body->valid & OBD_MD_FLDIREA))
                        body->valid |= (OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                                        OBD_MD_FLATIME | OBD_MD_FLMTIME);
        } else if (S_ISLNK(inode->i_mode) &&
                   (reqbody->valid & OBD_MD_LINKNAME) != 0) {
                rc = mds_pack_link(dentry, req, body, reply_off);
        } else if (reqbody->valid & OBD_MD_FLEA) {
                rc = mds_pack_ea(dentry, req, body, req_off, reply_off);
        } else if (reqbody->valid & OBD_MD_FLEALIST) {
                rc = mds_pack_ealist(dentry, req, body, reply_off);
        }
        
        if (reqbody->valid & OBD_MD_FLACL_ACCESS) {
                int inc = (reqbody->valid & OBD_MD_FLEASIZE) ? 2 : 1;
                rc = mds_pack_acl(obd, req->rq_repmsg, reply_off + inc, 
                                  body, inode);
        }                

        if (rc == 0)
                mds_body_do_reverse_map(med, body);

        RETURN(rc);
}

static int mds_getattr_pack_msg_cf(struct ptlrpc_request *req,
                                   struct dentry *dentry,
                                   int offset)
{
        int rc = 0, size[1] = {sizeof(struct mds_body)};
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDS_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                RETURN(-ENOMEM);
        }

        rc = lustre_pack_reply(req, 1, size, NULL);
        if (rc) {
                CERROR("lustre_pack_reply failed: rc %d\n", rc);
                GOTO(out, req->rq_status = rc);
        }

        EXIT;
out:
        return rc;
}

static int mds_getattr_pack_msg(struct ptlrpc_request *req, struct dentry *de,
                                int offset)
{
        struct inode *inode = de->d_inode;
        struct mds_obd *mds = mds_req2mds(req);
        struct mds_body *body;
        int rc = 0, size[4] = {sizeof(*body)}, bufcount = 1;
        ENTRY;

        body = lustre_msg_buf(req->rq_reqmsg, offset, sizeof(*body));
        LASSERT(body != NULL);                 /* checked by caller */
        LASSERT_REQSWABBED(req, offset);       /* swabbed by caller */

        if ((S_ISREG(inode->i_mode) && (body->valid & OBD_MD_FLEASIZE)) ||
            (S_ISDIR(inode->i_mode) && (body->valid & OBD_MD_FLDIREA))) {
                int rc;
                
                down(&inode->i_sem);
                rc = fsfilt_get_md(req->rq_export->exp_obd, inode, NULL, 0,
                                   ((body->valid & OBD_MD_MEA) ? EA_MEA : EA_LOV));
                up(&inode->i_sem);
                if (rc < 0) {
                        if (rc != -ENODATA && rc != -EOPNOTSUPP)
                                CERROR("error getting inode %lu MD: rc = %d\n",
                                       inode->i_ino, rc);
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
        } else if ((body->valid & OBD_MD_FLEA)) {
                char *ea_name = lustre_msg_string(req->rq_reqmsg, 
                                                  offset + 1, 0);
                rc = -EOPNOTSUPP;
                if (inode->i_op && inode->i_op->getxattr) 
                        rc = inode->i_op->getxattr(de, ea_name, NULL, 0);
                
                if (rc < 0) {
                        if (rc != -ENODATA && rc != -EOPNOTSUPP)
                                CERROR("error getting inode %lu EA: rc = %d\n",
                                       inode->i_ino, rc);
                        size[bufcount] = 0;
                } else {
                        size[bufcount] = min_t(int, body->eadatasize, rc);
                }
                bufcount++;
        } else if (body->valid & OBD_MD_FLEALIST) {
                rc = -EOPNOTSUPP;
                if (inode->i_op && inode->i_op->getxattr) 
                        rc = inode->i_op->listxattr(de, NULL, 0);

                if (rc < 0) {
                        if (rc != -ENODATA && rc != -EOPNOTSUPP)
                                CERROR("error getting inode %lu EA: rc = %d\n",
                                       inode->i_ino, rc);
                        size[bufcount] = 0;
                } else {
                        size[bufcount] = min_t(int, body->eadatasize, rc);
                }
                bufcount++;
        }
        
        /* may co-exist with OBD_MD_FLEASIZE */
        if (body->valid & OBD_MD_FLACL_ACCESS) {
                size[bufcount++] = 4;
                size[bufcount++] = xattr_acl_size(LL_ACL_MAX_ENTRIES);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_GETATTR_PACK)) {
                CERROR("failed MDS_GETATTR_PACK test\n");
                req->rq_status = -ENOMEM;
                GOTO(out, rc = -ENOMEM);
        }

        rc = lustre_pack_reply(req, bufcount, size, NULL);
        if (rc) {
                CERROR("out of memory\n");
                GOTO(out, req->rq_status = rc);
        }

        EXIT;
 out:
        return rc;
}

int mds_check_mds_num(struct obd_device *obd, struct inode *inode,
                      char *name, int namelen)
{
        struct mea *mea = NULL;
        int mea_size, rc = 0;
        ENTRY;
        
        rc = mds_md_get_attr(obd, inode, &mea, &mea_size);
        if (rc)
                RETURN(rc);
        if (mea != NULL) {
                /*
                 * dir is already splitted, check if requested filename should
                 * live at this MDS or at another one.
                 */
                int i = mea_name2idx(mea, name, namelen - 1);
                if (mea->mea_master != id_group(&mea->mea_ids[i])) {
                        CDEBUG(D_OTHER,
                               "inapropriate MDS(%d) for %s. should be "
                               "%lu(%d)\n", mea->mea_master, name, 
                               (unsigned long)id_group(&mea->mea_ids[i]), i);
                        rc = -ERESTART;
                }
        }

        if (mea)
                OBD_FREE(mea, mea_size);
        RETURN(rc);
}

static int mds_getattr_lock(struct ptlrpc_request *req, int offset,
                            struct lustre_handle *child_lockh, int child_part)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct ldlm_reply *rep = NULL;
        struct lvfs_run_ctxt saved;
        struct mds_req_sec_desc *rsd;
        struct mds_body *body;
        struct dentry *dparent = NULL, *dchild = NULL;
        struct lvfs_ucred uc = {NULL, NULL,};
        struct lustre_handle parent_lockh[2] = {{0}, {0}};
        unsigned int namesize;
        int rc = 0, cleanup_phase = 0, resent_req = 0, update_mode, reply_offset;
        char *name = NULL;
        ENTRY;

        LASSERT(!strcmp(obd->obd_type->typ_name, LUSTRE_MDS_NAME));
        MD_COUNTER_INCREMENT(obd, getattr_lock);

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                RETURN(-EFAULT);
        }

        /* swab now, before anyone looks inside the request. */
        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't swab mds_body\n");
                GOTO(cleanup, rc = -EFAULT);
        }

        LASSERT_REQSWAB(req, offset + 1);
        name = lustre_msg_string(req->rq_reqmsg, offset + 1, 0);
        if (name == NULL) {
                CERROR("Can't unpack name\n");
                GOTO(cleanup, rc = -EFAULT);
        }
        namesize = req->rq_reqmsg->buflens[offset + 1];

        /* namesize less than 2 means we have empty name, probably came from
           revalidate by cfid, so no point in having name to be set */
        if (namesize <= 1)
                name = NULL;

        LASSERT (offset == 1 || offset == 3);
        if (offset == 3) {
                rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*rep));
                reply_offset = 1;
        } else {
                reply_offset = 0;
        }

        rc = mds_init_ucred(&uc, req, rsd);
        if (rc) {
                GOTO(cleanup, rc);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        cleanup_phase = 1; /* kernel context */
        intent_set_disposition(rep, DISP_LOOKUP_EXECD);

        LASSERT(namesize > 0);
        if (child_lockh->cookie != 0) {
                LASSERT(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT);
                resent_req = 1;
        }
#if HAVE_LOOKUP_RAW
        if (body->valid == OBD_MD_FLID) {
                struct mds_body *mds_reply;
                int size = sizeof(*mds_reply);
                struct inode *dir;
                ino_t inum;

                dparent = mds_id2dentry(obd, &body->id1, NULL);
                if (IS_ERR(dparent)) {
                        rc = PTR_ERR(dparent);
                        GOTO(cleanup, rc);
                }
                /*
                 * the user requested ONLY the inode number, so do a raw lookup.
                 */
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc) {
                        CERROR("out of memory\n");
                        l_dput(dparent);
                        GOTO(cleanup, rc);
                }
                dir  = dparent->d_inode;
                LASSERT(dir->i_op->lookup_raw != NULL);
                rc = dir->i_op->lookup_raw(dir, name, namesize - 1, &inum);
                l_dput(dparent);
                mds_reply = lustre_msg_buf(req->rq_repmsg, 0,
                                           sizeof(*mds_reply));

                id_ino(&mds_reply->id1) = inum;
                mds_reply->valid = OBD_MD_FLID;
                GOTO(cleanup, rc);
        }
#endif
        if (resent_req == 0) {
                LASSERT(id_fid(&body->id1) != 0);
                if (name) {
                        rc = mds_get_parent_child_locked(obd, mds, &body->id1,
                                                         parent_lockh, &dparent,
                                                         LCK_PR, 
                                                         MDS_INODELOCK_UPDATE,
                                                         &update_mode, 
                                                         name, namesize,
                                                         child_lockh, &dchild, 
                                                         LCK_PR, child_part);
                        if (rc)
                                GOTO(cleanup, rc);
                
    			cleanup_phase = 2; /* dchild, dparent, locks */
                        
                        /*
                         * let's make sure this name should leave on this mds
                         * node.
                         */
                        rc = mds_check_mds_num(obd, dparent->d_inode, name, namesize);
                        if (rc)
                                GOTO(cleanup, rc);
                } else {
                        /* we have no dentry here, drop LOOKUP bit */
                        /* FIXME: we need MDS_INODELOCK_LOOKUP or not. */
                        child_part &= ~MDS_INODELOCK_LOOKUP;
                        CDEBUG(D_OTHER, "%s: retrieve attrs for "DLID4"\n",
                               obd->obd_name, OLID4(&body->id1));

                        dchild = mds_id2locked_dentry(obd, &body->id1, NULL,
                                                      LCK_PR, parent_lockh,
                                                      &update_mode,
                                                      NULL, 0, 
                                                      MDS_INODELOCK_UPDATE);
                        if (IS_ERR(dchild)) {
                                CERROR("can't find inode with id "DLID4", err = %d\n", 
                                       OLID4(&body->id1), (int)PTR_ERR(dchild));
                                GOTO(cleanup, rc = PTR_ERR(dchild));
                        }
                        memcpy(child_lockh, parent_lockh, sizeof(parent_lockh[0]));
                }
        } else {
                struct ldlm_lock *granted_lock;

                DEBUG_REQ(D_DLMTRACE, req, "resent, not enqueuing new locks");
                granted_lock = ldlm_handle2lock(child_lockh);

                LASSERTF(granted_lock != NULL, LPU64"/%lu lockh "LPX64"\n",
                         id_fid(&body->id1), (unsigned long)id_group(&body->id1),
                         child_lockh->cookie);

                if (name) {
                        /* usual named request */
                        dparent = mds_id2dentry(obd, &body->id1, NULL);
                        LASSERT(!IS_ERR(dparent));
                        dchild = ll_lookup_one_len(name, dparent, namesize - 1);
                        LASSERT(!IS_ERR(dchild));
                } else {
                        /* client wants to get attr. by id */
                        dchild = mds_id2dentry(obd, &body->id1, NULL);
                        LASSERT(!IS_ERR(dchild));
                }
                LDLM_LOCK_PUT(granted_lock);
        }

        cleanup_phase = 2; /* dchild, dparent, locks */

        if (!DENTRY_VALID(dchild)) {
                intent_set_disposition(rep, DISP_LOOKUP_NEG);
                /*
                 * in the intent case, the policy clears this error: the
                 * disposition is enough.
                 */
                rc = -ENOENT;
                GOTO(cleanup, rc);
        } else {
                intent_set_disposition(rep, DISP_LOOKUP_POS);
        }

        if (req->rq_repmsg == NULL) {
                if (dchild->d_flags & DCACHE_CROSS_REF)
                        rc = mds_getattr_pack_msg_cf(req, dchild, offset);
                else
                        rc = mds_getattr_pack_msg(req, dchild, offset);
                if (rc != 0) {
                        CERROR ("mds_getattr_pack_msg: %d\n", rc);
                        GOTO (cleanup, rc);
                }
        }

        rc = mds_getattr_internal(obd, dchild, req, offset, body, reply_offset);        
        GOTO(cleanup, rc); /* returns the lock to the client */

 cleanup:
        switch (cleanup_phase) {
        case 2:
                if (resent_req == 0) {
                        if (rc && DENTRY_VALID(dchild))
                                ldlm_lock_decref(child_lockh, LCK_PR);
                        if (name)
                                ldlm_lock_decref(parent_lockh, LCK_PR);
#ifdef S_PDIROPS
                        if (parent_lockh[1].cookie != 0)
                                ldlm_lock_decref(parent_lockh + 1, update_mode);
#endif
                        if (dparent)
                                l_dput(dparent);
                }
                l_dput(dchild);
        case 1:
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        default:
                mds_exit_ucred(&uc);
        }
        return rc;
}

static int mds_getattr(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct lvfs_run_ctxt saved;
        struct dentry *de;
        struct mds_req_sec_desc *rsd;
        struct mds_body *body;
        struct lvfs_ucred uc = {NULL, NULL,};
        int rc = 0;
        ENTRY;

        MD_COUNTER_INCREMENT(obd, getattr);

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                RETURN(-EFAULT);
        }

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR ("Can't unpack body\n");
                RETURN (-EFAULT);
        }

        rc = mds_init_ucred(&uc, req, rsd);
        if (rc) {
                mds_exit_ucred(&uc);
                RETURN(rc);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_id2dentry(obd, &body->id1, NULL);
        if (IS_ERR(de)) {
                rc = req->rq_status = PTR_ERR(de);
                GOTO(out_pop, rc);
        }

        rc = mds_getattr_pack_msg(req, de, offset);
        if (rc != 0) {
                CERROR("mds_getattr_pack_msg: %d\n", rc);
                GOTO(out_pop, rc);
        }

        req->rq_status = mds_getattr_internal(obd, de, req, offset, body, 0);
        l_dput(de);

        EXIT;
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        mds_exit_ucred(&uc);
        return rc;
}

static int mds_obd_statfs(struct obd_device *obd, struct obd_statfs *osfs,
                          unsigned long max_age)
{
        int rc;
        ENTRY;

        spin_lock(&obd->obd_osfs_lock);
        rc = fsfilt_statfs(obd, obd->u.mds.mds_sb, max_age);
        if (rc == 0)
                memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
        spin_unlock(&obd->obd_osfs_lock);

        RETURN(rc);
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

        OBD_COUNTER_INCREMENT(obd, statfs);

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
        return rc;
}

static int mds_sync(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct mds_body *body;
        int rc, size = sizeof(*body);
        ENTRY;

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL)
                GOTO(out, rc = -EPROTO);

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_SYNC_PACK)) {
                CERROR("fsync lustre_pack_reply failed: rc = %d\n", rc);
                GOTO(out, rc);
        }

        if (id_ino(&body->id1) == 0) {
                /* an id of zero is taken to mean "sync whole filesystem" */
                rc = fsfilt_sync(obd, mds->mds_sb);
                if (rc)
                        GOTO(out, rc);
        } else {
                /* just any file to grab fsync method - "file" arg unused */
                struct file *file = mds->mds_rcvd_filp;
                struct mds_body *rep_body;
                struct dentry *de;

                de = mds_id2dentry(obd, &body->id1, NULL);
                if (IS_ERR(de))
                        GOTO(out, rc = PTR_ERR(de));

                rc = file->f_op->fsync(NULL, de, 1);
                if (rc)
                        GOTO(out, rc);

                rep_body = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep_body));
                mds_pack_inode2body(obd, rep_body, de->d_inode,
                                    (body->valid & OBD_MD_FID) ? 1 : 0);
                l_dput(de);
        }

        EXIT;
out:
        req->rq_status = rc;
        return rc;
}

/* mds_readpage does not take a DLM lock on the inode, because the client must
 * already have a PR lock.
 *
 * If we were to take another one here, a deadlock will result, if another
 * thread is already waiting for a PW lock. */
static int mds_readpage(struct ptlrpc_request *req, int offset)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct vfsmount *mnt;
        struct dentry *de;
        struct file *file;
        struct mds_req_sec_desc *rsd;
        struct mds_body *body, *repbody;
        struct lvfs_run_ctxt saved;
        int rc, size = sizeof(*repbody);
        struct lvfs_ucred uc = {NULL, NULL,};
        ENTRY;

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_READPAGE_PACK)) {
                CERROR("mds: out of memory\n");
                GOTO(out, rc = -ENOMEM);
        }

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                GOTO (out, rc = -EFAULT);
        }

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't unpack body\n");
                GOTO (out, rc = -EFAULT);
        }

        rc = mds_init_ucred(&uc, req, rsd);
        if (rc) {
                GOTO(out, rc);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        de = mds_id2dentry(obd, &body->id1, &mnt);
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

        EXIT;
out_file:
        filp_close(file, 0);
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
out:
        mds_exit_ucred(&uc);
        req->rq_status = rc;
        return 0;
}

/* update master MDS ID, which is stored in local inode EA. */
int mds_update_mid(struct obd_device *obd, struct lustre_id *id,
                   void *data, int data_len)
{
        struct mds_obd *mds = &obd->u.mds;
        struct dentry *dentry;
        void *handle;
        int rc = 0;
        ENTRY;

        LASSERT(id);
        LASSERT(obd);
        
        dentry = mds_id2dentry(obd, id, NULL);
        if (IS_ERR(dentry))
                GOTO(out, rc = PTR_ERR(dentry));

        if (!dentry->d_inode) {
                CERROR("Can't find object "DLID4".\n",
                       OLID4(id));
                GOTO(out_dentry, rc = -EINVAL);
        }

        handle = fsfilt_start(obd, dentry->d_inode,
                              FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle))
                GOTO(out_dentry, rc = PTR_ERR(handle));

        rc = mds_update_inode_mid(obd, dentry->d_inode, handle,
                                  (struct lustre_id *)data);
        if (rc) {
                CERROR("Can't update inode "DLID4" master id, "
                       "error = %d.\n", OLID4(id), rc);
                GOTO(out_commit, rc);
        }

        EXIT;
out_commit:
        fsfilt_commit(obd, mds->mds_sb, dentry->d_inode,
                      handle, 0);
out_dentry:
        l_dput(dentry);
out:
        return rc;
}
EXPORT_SYMBOL(mds_update_mid);

/* read master MDS ID, which is stored in local inode EA. */
int mds_read_mid(struct obd_device *obd, struct lustre_id *id,
                 void *data, int data_len)
{
        struct dentry *dentry;
        int rc = 0;
        ENTRY;

        LASSERT(id);
        LASSERT(obd);
        
        dentry = mds_id2dentry(obd, id, NULL);
        if (IS_ERR(dentry))
                GOTO(out, rc = PTR_ERR(dentry));

        if (!dentry->d_inode) {
                CERROR("Can't find object "DLID4".\n",
                       OLID4(id));
                GOTO(out_dentry, rc = -EINVAL);
        }

        down(&dentry->d_inode->i_sem);
        rc = mds_read_inode_mid(obd, dentry->d_inode,
                                (struct lustre_id *)data);
        up(&dentry->d_inode->i_sem);
        if (rc) {
                CERROR("Can't read inode "DLID4" master id, "
                       "error = %d.\n", OLID4(id), rc);
                GOTO(out_dentry, rc);
        }

        EXIT;
out_dentry:
        l_dput(dentry);
out:
        return rc;
}
EXPORT_SYMBOL(mds_read_mid);

int mds_read_md(struct obd_device *obd, struct lustre_id *id, 
                char **data, int *datalen)
{
        struct dentry *dentry;
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0, mea = 0;
        char *ea;
        ENTRY;

        LASSERT(id);
        LASSERT(obd);
        
        dentry = mds_id2dentry(obd, id, NULL);
        if (IS_ERR(dentry))
                GOTO(out, rc = PTR_ERR(dentry));

        if (!dentry->d_inode) {
                CERROR("Can't find object "DLID4".\n",
                       OLID4(id));
                GOTO(out_dentry, rc = -EINVAL);
        }
        if (S_ISDIR(dentry->d_inode->i_mode)) {
                *datalen = obd_packmd(mds->mds_md_exp, NULL, NULL);
                mea = 1; 
        } else {
                *datalen = obd_packmd(mds->mds_dt_exp, NULL, NULL); 
                mea = 0;
        }
        OBD_ALLOC(ea, *datalen);
        if (!ea) {
                *datalen = 0;
                GOTO(out_dentry, rc = PTR_ERR(dentry));
        } 
        *data = ea;
        down(&dentry->d_inode->i_sem);
        rc = fsfilt_get_md(obd, dentry->d_inode, *data, *datalen,
                           (mea ? EA_MEA : EA_LOV));
        up(&dentry->d_inode->i_sem);
        
        if (rc < 0) 
                CERROR("Error %d reading eadata for ino %lu\n",
                        rc, dentry->d_inode->i_ino);
out_dentry:
        l_dput(dentry);
out:
        RETURN(rc);
}
EXPORT_SYMBOL(mds_read_md);

int mds_reint(struct ptlrpc_request *req, int offset,
              struct lustre_handle *lockh)
{
        struct mds_update_record *rec;
        struct mds_req_sec_desc *rsd;
        int rc;
        ENTRY;

        OBD_ALLOC(rec, sizeof(*rec));
        if (rec == NULL)
                RETURN(-ENOMEM);

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                GOTO(out, rc = -EFAULT);
        }

        rc = mds_update_unpack(req, offset, rec);
        if (rc || OBD_FAIL_CHECK(OBD_FAIL_MDS_REINT_UNPACK)) {
                CERROR("invalid record\n");
                GOTO(out, req->rq_status = -EINVAL);
        }

        rc = mds_init_ucred(&rec->ur_uc, req, rsd);
        if (rc) {
                GOTO(out, rc);
        }

        /* rc will be used to interrupt a for loop over multiple records */
        rc = mds_reint_rec(rec, offset, req, lockh);

 out:
        mds_exit_ucred(&rec->ur_uc);
        OBD_FREE(rec, sizeof(*rec));
        RETURN(rc);
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
        case OST_CREATE:
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

#define FILTER_VALID_FLAGS (OBD_MD_FLTYPE | OBD_MD_FLMODE | OBD_MD_FLGENER  | \
                            OBD_MD_FLSIZE | OBD_MD_FLBLOCKS | OBD_MD_FLBLKSZ| \
                            OBD_MD_FLATIME | OBD_MD_FLMTIME | OBD_MD_FLCTIME| \
                            OBD_MD_FLID) 

static void reconstruct_create(struct ptlrpc_request *req)
{
        struct mds_export_data *med = &req->rq_export->exp_mds_data;
        struct mds_client_data *mcd = med->med_mcd;
        struct dentry *dentry;
        struct ost_body *body;
        struct lustre_id id;
        int rc;
        ENTRY;

        /* copy rc, transno and disp; steal locks */
        mds_req_from_mcd(req, mcd);
        if (req->rq_status) {
                EXIT;
                return;
        }

        id_gen(&id) = 0;
        id_group(&id) = 0;

        id_ino(&id) = mcd->mcd_last_data;
        LASSERT(id_ino(&id) != 0);

        dentry = mds_id2dentry(req2obd(req), &id, NULL);
        if (IS_ERR(dentry)) {
                CERROR("can't find inode "LPU64"\n", id_ino(&id));
                req->rq_status = PTR_ERR(dentry);
                EXIT;
                return;
        }

        CWARN("reconstruct reply for x"LPU64" (remote ino) "LPU64" -> %lu/%u\n",
              req->rq_xid, id_ino(&id), dentry->d_inode->i_ino,
              dentry->d_inode->i_generation);

        body = lustre_msg_buf(req->rq_repmsg, 0, sizeof (*body));
        obdo_from_inode(&body->oa, dentry->d_inode, FILTER_VALID_FLAGS);
        body->oa.o_id = dentry->d_inode->i_ino;
        body->oa.o_generation = dentry->d_inode->i_generation;
        body->oa.o_valid |= OBD_MD_FLID | OBD_MD_FLGENER;

        down(&dentry->d_inode->i_sem);
        rc = mds_read_inode_sid(req2obd(req), dentry->d_inode, &id);
        up(&dentry->d_inode->i_sem);
        if (rc) {
                CERROR("Can't read inode self id, inode %lu, "
                       "rc %d\n", dentry->d_inode->i_ino, rc);
                id_fid(&id) = 0;
        }

        body->oa.o_fid = id_fid(&id);
        body->oa.o_mds = id_group(&id);
        l_dput(dentry);

        EXIT;
}

static int mds_inode_init_acl(struct obd_device *obd, void *handle,
                              struct dentry *de, void *xattr, int xattr_size)
{
        struct inode *inode = de->d_inode;
        struct posix_acl *acl;
        mode_t mode;
        int rc = 0;

        LASSERT(handle);
        LASSERT(inode);
        LASSERT(xattr);
        LASSERT(xattr_size > 0);

        if (!inode->i_op->getxattr || !inode->i_op->setxattr) {
                CERROR("backend fs dosen't support xattr\n");
                return -EOPNOTSUPP;
        }

        /* set default acl */
        if (S_ISDIR(inode->i_mode)) {
                rc = inode->i_op->setxattr(de, XATTR_NAME_ACL_DEFAULT,
                                           xattr, xattr_size, 0);
                if (rc) {
                        CERROR("set default acl err: %d\n", rc);
                        return rc;
                }
        }

        /* set access acl */
        acl = posix_acl_from_xattr(xattr, xattr_size);
        if (acl == NULL || IS_ERR(acl)) {
                CERROR("insane attr data\n");
                return PTR_ERR(acl);
        }

        if (posix_acl_valid(acl)) {
                CERROR("default acl not valid: %d\n", rc);
                rc = -EFAULT;
                goto out;
        }

        mode = inode->i_mode;
        rc = posix_acl_create_masq(acl, &mode);
        if (rc < 0) {
                CERROR("create masq err %d\n", rc);
                goto out;
        }

        if (inode->i_mode != mode) {
                struct iattr iattr = { .ia_valid = ATTR_MODE,
                                       .ia_mode = mode };
                int rc2;

                rc2 = fsfilt_setattr(obd, de, handle, &iattr, 0);
                if (rc2) {
                        CERROR("setattr mode err: %d\n", rc2);
                        rc = rc2;
                        goto out;
                }
        }

        if (rc > 0) {
                /* we didn't change acl except mode bits of some
                 * entries, so should be fit into original size.
                 */
                rc = posix_acl_to_xattr(acl, xattr, xattr_size);
                LASSERT(rc > 0);

                rc = inode->i_op->setxattr(de, XATTR_NAME_ACL_ACCESS,
                                           xattr, xattr_size, 0);
                if (rc)
                        CERROR("set access acl err: %d\n", rc);
        }
out:
        posix_acl_release(acl);
        return rc;
}

static int mdt_obj_create(struct ptlrpc_request *req)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct mds_obd *mds = &obd->u.mds;
        struct ost_body *body, *repbody;
        void *acl = NULL;
        int acl_size;
        char idname[LL_ID_NAMELEN];
        int size = sizeof(*repbody);
        struct inode *parent_inode;
        struct lvfs_run_ctxt saved;
        int rc, cleanup_phase = 0;
        struct dentry *new = NULL;
        struct dentry_params dp;
        int mealen, flags = 0;
        struct lvfs_ucred uc;
        struct lustre_id id;
        struct mea *mea;
        void *handle = NULL;
        unsigned long cr_inum = 0;
        ENTRY;
       
        DEBUG_REQ(D_HA, req, "create remote object");
        parent_inode = mds->mds_unnamed_dir->d_inode;

        body = lustre_swab_reqbuf(req, 0, sizeof(*body),
                                  lustre_swab_ost_body);
        if (body == NULL)
                RETURN(-EFAULT);

        /* acl data is packed transparently, no swab here */
        LASSERT(req->rq_reqmsg->bufcount >= 2);
        acl_size = req->rq_reqmsg->buflens[1];
        if (acl_size) {
                acl = lustre_msg_buf(req->rq_reqmsg, 1, acl_size);
                if (!acl) {
                        CERROR("No default acl buf?\n");
                        RETURN(-EFAULT);
                }
        }

        rc = lustre_pack_reply(req, 1, &size, NULL);
        if (rc)
                RETURN(rc);

        MDS_CHECK_RESENT(req, reconstruct_create(req));

        uc.luc_lsd = NULL;
        uc.luc_ginfo = NULL;
        uc.luc_uid = body->oa.o_uid;
        uc.luc_gid = body->oa.o_gid;
        uc.luc_fsuid = body->oa.o_uid;
        uc.luc_fsgid = body->oa.o_gid;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        repbody = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*repbody));

        /* in REPLAY case inum should be given (client or other MDS fills it) */
        if (body->oa.o_id && ((body->oa.o_flags & OBD_FL_RECREATE_OBJS) ||
            (lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY))) {
                /*
                 * this is re-create request from MDS holding directory name.
                 * we have to lookup given ino/gen first. if it exists (good
                 * case) then there is nothing to do. if it does not then we
                 * have to recreate it.
                 */
                id_ino(&id) = body->oa.o_id;
                id_gen(&id) = body->oa.o_generation;
 
                new = mds_id2dentry(obd, &id, NULL);
                if (!IS_ERR(new) && new->d_inode) {
                        struct lustre_id sid;
                                
                        CWARN("mkdir() repairing is on its way: %lu/%lu\n",
                              (unsigned long)id_ino(&id), (unsigned long)id_gen(&id));
                        
                        obdo_from_inode(&repbody->oa, new->d_inode,
                                        FILTER_VALID_FLAGS);
                        
                        repbody->oa.o_id = new->d_inode->i_ino;
                        repbody->oa.o_generation = new->d_inode->i_generation;
                        repbody->oa.o_valid |= OBD_MD_FLID | OBD_MD_FLGENER;
                        cleanup_phase = 1;

                        down(&new->d_inode->i_sem);
                        rc = mds_read_inode_sid(obd, new->d_inode, &sid);
                        up(&new->d_inode->i_sem);
                        if (rc) {
                                CERROR("Can't read inode self id "
                                       "inode %lu, rc %d.\n",
                                       new->d_inode->i_ino, rc);
                                GOTO(cleanup, rc);
                        }

                        repbody->oa.o_fid = id_fid(&sid);
                        repbody->oa.o_mds = id_group(&sid);
                        LASSERT(id_fid(&sid) != 0);

                        /* 
                         * here we could use fid passed in body->oa.o_fid and
                         * thus avoid mds_read_inode_sid().
                         */
                        cr_inum = new->d_inode->i_ino;
                        GOTO(cleanup, rc = 0);
                }
        }
        
        down(&parent_inode->i_sem);
        handle = fsfilt_start(obd, parent_inode, FSFILT_OP_MKDIR, NULL);
        if (IS_ERR(handle)) {
                up(&parent_inode->i_sem);
                CERROR("fsfilt_start() failed, rc = %d\n",
                       (int)PTR_ERR(handle));
                GOTO(cleanup, rc = PTR_ERR(handle));
        }
        cleanup_phase = 1; /* transaction */

repeat:
        rc = sprintf(idname, "%u.%u", ll_insecure_random_int(), current->pid);
        new = lookup_one_len(idname, mds->mds_unnamed_dir, rc);
        if (IS_ERR(new)) {
                CERROR("%s: can't lookup new inode (%s) for mkdir: %d\n",
                       obd->obd_name, idname, (int) PTR_ERR(new));
                fsfilt_commit(obd, mds->mds_sb, new->d_inode, handle, 0);
                up(&parent_inode->i_sem);
                RETURN(PTR_ERR(new));
        } else if (new->d_inode) {
                CERROR("%s: name exists. repeat\n", obd->obd_name);
                goto repeat;
        }

        new->d_fsdata = (void *)&dp;
        dp.p_inum = 0;
        dp.p_ptr = req;

        if ((lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) ||
            (body->oa.o_flags & OBD_FL_RECREATE_OBJS)) {
                LASSERT(body->oa.o_id != 0);
                dp.p_inum = body->oa.o_id;
                DEBUG_REQ(D_HA, req, "replay create obj %lu/%lu",
                          (unsigned long)body->oa.o_id,
                          (unsigned long)body->oa.o_generation);
        }

        rc = vfs_mkdir(parent_inode, new, body->oa.o_mode);
        if (rc == 0) {
                if (acl) {
                        rc = mds_inode_init_acl(obd, handle, new,
                                                acl, acl_size);
                        if (rc) {
                                up(&parent_inode->i_sem);
                                GOTO(cleanup, rc);
                        }
                }
                if ((body->oa.o_flags & OBD_FL_RECREATE_OBJS) ||
                    lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                        new->d_inode->i_generation = body->oa.o_generation;
                        mark_inode_dirty(new->d_inode);
                        
                        /*
                         * avoiding asserts in cache flush case, as
                         * @body->oa.o_id should be zero.
                         */
                        if (body->oa.o_id) {
                                LASSERTF(body->oa.o_id == new->d_inode->i_ino, 
                                         "BUG 3550: failed to recreate obj "
                                         LPU64" -> %lu\n", body->oa.o_id,
                                         new->d_inode->i_ino);
                                
                                LASSERTF(body->oa.o_generation == 
                                         new->d_inode->i_generation,
                                         "BUG 3550: failed to recreate obj/gen "
                                         LPU64"/%u -> %lu/%u\n", body->oa.o_id,
                                         body->oa.o_generation,
                                         new->d_inode->i_ino, 
                                         new->d_inode->i_generation);
                        }
                }
                
                obdo_from_inode(&repbody->oa, new->d_inode, FILTER_VALID_FLAGS);
                repbody->oa.o_id = new->d_inode->i_ino;
                repbody->oa.o_generation = new->d_inode->i_generation;
                repbody->oa.o_valid |= OBD_MD_FLID | OBD_MD_FLGENER | OBD_MD_FID;

                if ((body->oa.o_flags & OBD_FL_RECREATE_OBJS) ||
                    lustre_msg_get_flags(req->rq_reqmsg) & MSG_REPLAY) {
                        id_group(&id) = mds->mds_num;
                
                        LASSERT(body->oa.o_fid != 0);
                        id_fid(&id) = body->oa.o_fid;

                        LASSERT(body->oa.o_id != 0);
                        id_ino(&id) = repbody->oa.o_id;
                        id_gen(&id) = repbody->oa.o_generation;
                
                        down(&new->d_inode->i_sem);
                        rc = mds_update_inode_sid(obd, new->d_inode, handle, &id);
                        up(&new->d_inode->i_sem);

                        /* 
                         * make sure, that fid is up-to-date.
                         */
                        mds_set_last_fid(obd, id_fid(&id));
                } else {
                        /*
                         * allocate new sid, as object is created from scratch
                         * and this is not replay.
                         */
                        down(&new->d_inode->i_sem);
                        rc = mds_alloc_inode_sid(obd, new->d_inode, handle, &id);
                        up(&new->d_inode->i_sem);
                }
                if (rc) {
                        CERROR("Can't update lustre ID for inode %lu, "
                               "error = %d\n", new->d_inode->i_ino, rc);
                        GOTO(cleanup, rc);
                }

                /* initializing o_fid after it is allocated. */
                repbody->oa.o_fid = id_fid(&id);
                repbody->oa.o_mds = id_group(&id);

                rc = fsfilt_del_dir_entry(obd, new);
                up(&parent_inode->i_sem);
                if (rc) {
                        CERROR("can't remove name for object: %d\n", rc);
                        GOTO(cleanup, rc);
                }
                
                cleanup_phase = 2; /* created directory object */

                CDEBUG(D_OTHER, "created dirobj: %lu/%lu mode %o\n",
                       (unsigned long)new->d_inode->i_ino,
                       (unsigned long)new->d_inode->i_generation,
                       (unsigned)new->d_inode->i_mode);
                cr_inum = new->d_inode->i_ino;
        } else {
                up(&parent_inode->i_sem);
                CERROR("%s: can't create dirobj: %d\n", obd->obd_name, rc);
                GOTO(cleanup, rc);
        }

        if (body->oa.o_valid & OBD_MD_FLID) {
                /* this is new object for splitted dir. We have to prevent
                 * recursive splitting on it -bzzz */
                mealen = obd_size_diskmd(mds->mds_md_exp, NULL);

                OBD_ALLOC(mea, mealen);
                if (mea == NULL)
                        GOTO(cleanup, rc = -ENOMEM);

                mea->mea_magic = MEA_MAGIC_ALL_CHARS;
                mea->mea_master = 0;
                mea->mea_count = 0;

                down(&new->d_inode->i_sem);
                rc = fsfilt_set_md(obd, new->d_inode, handle,
                                   mea, mealen, EA_MEA);
                up(&new->d_inode->i_sem);
                if (rc)
                        CERROR("fsfilt_set_md() failed, "
                               "rc = %d\n", rc);

                OBD_FREE(mea, mealen);
                
                CDEBUG(D_OTHER, "%s: mark non-splittable %lu/%u - %d\n",
                       obd->obd_name, new->d_inode->i_ino,
                       new->d_inode->i_generation, flags);
        } else if (body->oa.o_easize) {
                /* we pass LCK_EX to split routine to signal that we have
                 * exclusive access to the directory. simple because nobody
                 * knows it already exists -bzzz */
                rc = mds_try_to_split_dir(obd, new, NULL,
                                          body->oa.o_easize, LCK_EX);
                if (rc < 0) {
                        CERROR("Can't split directory %lu, error = %d.\n",
                               new->d_inode->i_ino, rc);
                } else {
                        rc = 0;
                }
        }

        EXIT;
cleanup:
        switch (cleanup_phase) {
        case 2: /* object has been created, but we'll may want to replay it later */
                if (rc == 0)
                        ptlrpc_require_repack(req);
        case 1: /* transaction */
                rc = mds_finish_transno(mds, parent_inode, handle,
                                        req, rc, cr_inum);
        }

        l_dput(new);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
        return rc;
}

static int mdt_get_info(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        int keylen, rc = 0;
        char *key;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no get_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];

        if ((keylen < strlen("mdsize") || strcmp(key, "mdsize") != 0) &&
            (keylen < strlen("mdsnum") || strcmp(key, "mdsnum") != 0) &&
            (keylen < strlen("rootid") || strcmp(key, "rootid") != 0))
                RETURN(-EPROTO);

        if (keylen >= strlen("rootid") && !strcmp(key, "rootid")) {
                struct lustre_id *reply;
                int size = sizeof(*reply);
                
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc)
                        RETURN(rc);

                reply = lustre_msg_buf(req->rq_repmsg, 0, size);
                rc = obd_get_info(exp, keylen, key, (__u32 *)&size, reply);
        } else {
                obd_id *reply;
                int size = sizeof(*reply);
                
                rc = lustre_pack_reply(req, 1, &size, NULL);
                if (rc)
                        RETURN(rc);

                reply = lustre_msg_buf(req->rq_repmsg, 0, size);
                rc = obd_get_info(exp, keylen, key, (__u32 *)&size, reply);
        }

        req->rq_repmsg->status = 0;
        RETURN(rc);
}

static int mds_set_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 vallen, void *val)
{
        struct obd_device *obd;
        struct mds_obd *mds;
        int rc = 0;
        ENTRY;

        obd = class_exp2obd(exp);
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        mds = &obd->u.mds;
        if (keylen >= strlen("mds_type") &&
             memcmp(key, "mds_type", keylen) == 0) {
                int valsize;
                __u32 group;
                
                CDEBUG(D_IOCTL, "set mds type to %x\n", *(int*)val);
                
                mds->mds_obd_type = *(int*)val;
                group = FILTER_GROUP_FIRST_MDS + mds->mds_obd_type;
                valsize = sizeof(group);
                
                /* mds number has been changed, so the corresponding obdfilter
                 * exp need to be changed too. */
                rc = obd_set_info(mds->mds_dt_exp, strlen("mds_conn"),
                                  "mds_conn", valsize, &group);
                RETURN(rc);
        }
        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

static int mdt_set_info(struct ptlrpc_request *req)
{
        char *key, *val;
        struct obd_export *exp = req->rq_export;
        int keylen, rc = 0, vallen;
        ENTRY;

        key = lustre_msg_buf(req->rq_reqmsg, 0, 1);
        if (key == NULL) {
                DEBUG_REQ(D_HA, req, "no set_info key");
                RETURN(-EFAULT);
        }
        keylen = req->rq_reqmsg->buflens[0];

        if (keylen == strlen("mds_type") &&
            memcmp(key, "mds_type", keylen) == 0) {
                rc = lustre_pack_reply(req, 0, NULL, NULL);
                if (rc)
                        RETURN(rc);
                
                val = lustre_msg_buf(req->rq_reqmsg, 1, 0);
                vallen = req->rq_reqmsg->buflens[1];

                rc = obd_set_info(exp, keylen, key, vallen, val);
                req->rq_repmsg->status = 0;
                RETURN(rc);
        }
        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

static void mds_revoke_export_locks(struct obd_export *exp)
{
        struct ldlm_namespace *ns = exp->exp_obd->obd_namespace;
        struct list_head *locklist = &exp->exp_ldlm_data.led_held_locks;
        struct ldlm_lock *lock, *next;
        struct ldlm_lock_desc desc;

        if (!exp->u.eu_mds_data.med_remote)
                return;

        ENTRY;
        l_lock(&ns->ns_lock);
        list_for_each_entry_safe(lock, next, locklist, l_export_chain) {
                if (lock->l_req_mode != lock->l_granted_mode)
                        continue;

                LASSERT(lock->l_resource);
                if (lock->l_resource->lr_type != LDLM_IBITS &&
                    lock->l_resource->lr_type != LDLM_PLAIN)
                        continue;

                if (lock->l_flags & LDLM_FL_AST_SENT)
                        continue;

                lock->l_flags |= LDLM_FL_AST_SENT;

                /* the desc just pretend to exclusive */
                ldlm_lock2desc(lock, &desc);
                desc.l_req_mode = LCK_EX;
                desc.l_granted_mode = 0;

                lock->l_blocking_ast(lock, &desc, NULL, LDLM_CB_BLOCKING);
        }
        l_unlock(&ns->ns_lock);
        EXIT;
}

static int mds_msg_check_version(struct lustre_msg *msg)
{
        int rc;

        switch (msg->opc) {
        case MDS_CONNECT:
        case MDS_DISCONNECT:
        case OBD_PING:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_OBD_VERSION);
                break;
        case MDS_STATFS:
        case MDS_GETSTATUS:
        case MDS_GETATTR:
        case MDS_GETATTR_LOCK:
        case MDS_READPAGE:
        case MDS_REINT:
        case MDS_CLOSE:
        case MDS_DONE_WRITING:
        case MDS_PIN:
        case MDS_SYNC:
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
        case LLOG_ORIGIN_HANDLE_OPEN:
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
        case OST_CREATE:
        case OST_WRITE:
        case OST_GET_INFO:
        case OST_SET_INFO:
                rc = lustre_msg_check_version(msg, LUSTRE_OBD_VERSION);
                if (rc)
                        CERROR("bad opc %u version %08x, expecting %08x\n",
                               msg->opc, msg->version, LUSTRE_OBD_VERSION);
                break;
        case SEC_INIT:
        case SEC_INIT_CONTINUE:
        case SEC_FINI:
                rc = 0;
                break;
        default:
                CERROR("MDS unknown opcode %d\n", msg->opc);
                rc = -ENOTSUPP;
                break;
        }

        return rc;
}

int mds_handle(struct ptlrpc_request *req)
{
        int should_process, fail = OBD_FAIL_MDS_ALL_REPLY_NET;
        struct obd_device *obd = NULL;
        struct mds_obd *mds = NULL; /* quell gcc overwarning */
        int rc = 0;
        ENTRY;

        OBD_FAIL_RETURN(OBD_FAIL_MDS_ALL_REQUEST_NET | OBD_FAIL_ONCE, 0);

        rc = mds_msg_check_version(req->rq_reqmsg);
        if (rc) {
                CERROR("MDS drop mal-formed request\n");
                RETURN(rc);
        }

        /* Security opc should NOT trigger any recovery events */
        if (req->rq_reqmsg->opc == SEC_INIT ||
            req->rq_reqmsg->opc == SEC_INIT_CONTINUE) {
                if (req->rq_export) {
                        mds_req_add_idmapping(req,
                                              &req->rq_export->exp_mds_data);
                        mds_revoke_export_locks(req->rq_export);
                }
                GOTO(out, rc = 0);
        } else if (req->rq_reqmsg->opc == SEC_FINI) {
                if (req->rq_export) {
                        mds_req_del_idmapping(req,
                                              &req->rq_export->exp_mds_data);
                        mds_revoke_export_locks(req->rq_export);
                }
                GOTO(out, rc = 0);
        }

        LASSERT(current->journal_info == NULL);
        /* XXX identical to OST */
        if (req->rq_reqmsg->opc != MDS_CONNECT) {
                struct mds_export_data *med;
                int recovering;

                if (req->rq_export == NULL) {
                        CERROR("operation %d on unconnected MDS from %s\n",
                               req->rq_reqmsg->opc,
                               req->rq_peerstr);
                        req->rq_status = -ENOTCONN;
                        GOTO(out, rc = -ENOTCONN);
                }

                med = &req->rq_export->exp_mds_data;
                obd = req->rq_export->exp_obd;
                mds = &obd->u.mds;

                /* sanity check: if the xid matches, the request must
                 * be marked as a resent or replayed */
                if (req->rq_xid == le64_to_cpu(med->med_mcd->mcd_last_xid) ||
                   req->rq_xid == le64_to_cpu(med->med_mcd->mcd_last_close_xid)) {
                        LASSERTF(lustre_msg_get_flags(req->rq_reqmsg) &
                                 (MSG_RESENT | MSG_REPLAY),
                                 "rq_xid "LPU64" matches last_xid, "
                                 "expected RESENT flag\n",
                                 req->rq_xid);
                }
                /* else: note the opposite is not always true; a
                 * RESENT req after a failover will usually not match
                 * the last_xid, since it was likely never
                 * committed. A REPLAYed request will almost never
                 * match the last xid, however it could for a
                 * committed, but still retained, open. */

                spin_lock_bh(&obd->obd_processing_task_lock);
                recovering = obd->obd_recovering;
                spin_unlock_bh(&obd->obd_processing_task_lock);
                if (recovering) {
                        rc = mds_filter_recovery_request(req, obd,
                                                         &should_process);
                        if (rc || should_process == 0) {
                                RETURN(rc);
                        } else if (should_process < 0) {
                                req->rq_status = should_process;
                                rc = ptlrpc_error(req);
                                RETURN(rc);
                        }
                }
        }

        switch (req->rq_reqmsg->opc) {
        case MDS_CONNECT:
                DEBUG_REQ(D_INODE, req, "connect");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CONNECT_NET, 0);
                rc = target_handle_connect(req);
                if (!rc) {
                        struct mds_export_data *med;

                        LASSERT(req->rq_export);
                        med = &req->rq_export->u.eu_mds_data;
                        mds_init_export_data(req, med);
                        mds_req_add_idmapping(req, med);

                        /* Now that we have an export, set mds. */
                        obd = req->rq_export->exp_obd;
                        mds = mds_req2mds(req);
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
                rc = mds_getattr(req, MDS_REQ_REC_OFF);
                break;

        case MDS_GETATTR_LOCK: {
                struct lustre_handle lockh;
                DEBUG_REQ(D_INODE, req, "getattr_lock");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_GETATTR_LOCK_NET, 0);

                /* If this request gets a reconstructed reply, we won't be
                 * acquiring any new locks in mds_getattr_lock, so we don't
                 * want to cancel.
                 */
                lockh.cookie = 0;
                rc = mds_getattr_lock(req, MDS_REQ_REC_OFF, &lockh,
                                      MDS_INODELOCK_UPDATE);
                /* this non-intent call (from an ioctl) is special */
                req->rq_status = rc;
                if (rc == 0 && lockh.cookie)
                        ldlm_lock_decref(&lockh, LCK_PR);
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
                rc = mds_readpage(req, MDS_REQ_REC_OFF);

                if (OBD_FAIL_CHECK_ONCE(OBD_FAIL_MDS_SENDPAGE)) {
                        if (req->rq_reply_state) {
                                lustre_free_reply_state (req->rq_reply_state);
                                req->rq_reply_state = NULL;
                        }
                        RETURN(0);
                }

                break;
        case MDS_REINT: {
                __u32 *opcp = lustre_msg_buf(req->rq_reqmsg, MDS_REQ_REC_OFF,
                                             sizeof (*opcp));
                __u32  opc;
                int size[3] = {sizeof(struct mds_body), mds->mds_max_mdsize,
                               mds->mds_max_cookiesize};
                int bufcount;

                /* NB only peek inside req now; mds_reint() will swab it */
                if (opcp == NULL) {
                        CERROR ("Can't inspect opcode\n");
                        rc = -EINVAL;
                        break;
                }
                opc = *opcp;
                if (lustre_msg_swabbed (req->rq_reqmsg))
                        __swab32s(&opc);

                DEBUG_REQ(D_INODE, req, "reint %d (%s)", opc,
                          (opc < sizeof(reint_names) / sizeof(reint_names[0]) ||
                           reint_names[opc] == NULL) ? reint_names[opc] :
                                                       "unknown opcode");

                OBD_FAIL_RETURN(OBD_FAIL_MDS_REINT_NET, 0);

                if (opc == REINT_UNLINK || opc == REINT_RENAME)
                        bufcount = 3;
                else if (opc == REINT_OPEN)
                        bufcount = 2;
                else
                        bufcount = 1;

                rc = lustre_pack_reply(req, bufcount, size, NULL);
                if (rc)
                        break;

                rc = mds_reint(req, MDS_REQ_REC_OFF, NULL);
                fail = OBD_FAIL_MDS_REINT_NET_REP;
                break;
        }

        case MDS_CLOSE:
                DEBUG_REQ(D_INODE, req, "close");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_CLOSE_NET, 0);
                rc = mds_close(req, MDS_REQ_REC_OFF);
                break;

        case MDS_DONE_WRITING:
                DEBUG_REQ(D_INODE, req, "done_writing");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_DONE_WRITING_NET, 0);
                rc = mds_done_writing(req, MDS_REQ_REC_OFF);
                break;

        case MDS_PIN:
                DEBUG_REQ(D_INODE, req, "pin");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_PIN_NET, 0);
                rc = mds_pin(req, MDS_REQ_REC_OFF);
                break;

        case MDS_SYNC:
                DEBUG_REQ(D_INODE, req, "sync");
                OBD_FAIL_RETURN(OBD_FAIL_MDS_SYNC_NET, 0);
                rc = mds_sync(req, MDS_REQ_REC_OFF);
                break;

        case OBD_PING:
                DEBUG_REQ(D_INODE, req, "ping");
                rc = target_handle_ping(req);
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
        case LLOG_ORIGIN_HANDLE_OPEN:
                DEBUG_REQ(D_INODE, req, "llog_init");
                OBD_FAIL_RETURN(OBD_FAIL_OBD_LOGD_NET, 0);
                rc = llog_origin_handle_open(req);
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
        case OST_CREATE:
                DEBUG_REQ(D_INODE, req, "ost_create");
                rc = mdt_obj_create(req);
                break;
        case OST_GET_INFO:
                DEBUG_REQ(D_INODE, req, "get_info");
                rc = mdt_get_info(req);
                break;
        case OST_SET_INFO:
                DEBUG_REQ(D_INODE, req, "set_info");
                rc = mdt_set_info(req);
                break;
        case OST_WRITE:
                CDEBUG(D_INODE, "write\n");
                OBD_FAIL_RETURN(OBD_FAIL_OST_BRW_NET, 0);
                rc = ost_brw_write(req, NULL);
                LASSERT(current->journal_info == NULL);
                /* mdt_brw sends its own replies */
                RETURN(rc);
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

        EXIT;

        /* If we're DISCONNECTing, the mds_export_data is already freed */
        if (!rc && req->rq_reqmsg->opc != MDS_DISCONNECT) {
                struct mds_export_data *med = &req->rq_export->exp_mds_data;
                struct obd_device *obd = list_entry(mds, struct obd_device,
                                                    u.mds);
                req->rq_repmsg->last_xid =
                        le64_to_cpu(med->med_mcd->mcd_last_xid);

                if (!obd->obd_no_transno) {
                        req->rq_repmsg->last_committed =
                                obd->obd_last_committed;
                } else {
                        DEBUG_REQ(D_IOCTL, req,
                                  "not sending last_committed update");
                }
                CDEBUG(D_INFO, "last_transno "LPU64", last_committed "LPU64
                       ", xid "LPU64"\n",
                       mds->mds_last_transno, obd->obd_last_committed,
                       req->rq_xid);
        }
 out:


        target_send_reply(req, rc, fail);
        return 0;
}

/* Update the server data on disk.  This stores the new mount_count and also the
 * last_rcvd value to disk.  If we don't have a clean shutdown, then the server
 * last_rcvd value may be less than that of the clients.  This will alert us
 * that we may need to do client recovery.
 *
 * Also assumes for mds_last_transno that we are not modifying it (no locking).
 */
int mds_update_server_data(struct obd_device *obd, int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_server_data *msd = mds->mds_server_data;
        struct file *filp = mds->mds_rcvd_filp;
        struct lvfs_run_ctxt saved;
        loff_t off = 0;
        int rc;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        msd->msd_last_transno = cpu_to_le64(mds->mds_last_transno);

        CDEBUG(D_SUPER, "MDS mount_count is "LPU64", last_transno is "LPU64"\n",
               mds->mds_mount_count, mds->mds_last_transno);
        rc = fsfilt_write_record(obd, filp, msd, sizeof(*msd), &off, force_sync);
        if (rc)
                CERROR("error writing MDS server data: rc = %d\n", rc);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

/* saves last allocated fid counter to file. */
int mds_update_last_fid(struct obd_device *obd, void *handle,
                        int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        struct file *filp = mds->mds_fid_filp;
        struct lvfs_run_ctxt saved;
        loff_t off = 0;
        __u64 last_fid;
        int rc = 0;
        ENTRY;

        spin_lock(&mds->mds_last_fid_lock);
        last_fid = mds->mds_last_fid;
        spin_unlock(&mds->mds_last_fid_lock);

        CDEBUG(D_SUPER, "MDS last_fid is #"LPU64"\n",
               last_fid);

        if (handle) {
                fsfilt_add_journal_cb(obd, mds->mds_sb, last_fid,
                                      handle, mds_commit_last_fid_cb,
                                      NULL);
        }
                
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = fsfilt_write_record(obd, filp, &last_fid, sizeof(last_fid),
                                 &off, force_sync);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if (rc) {
                CERROR("error writing MDS last_fid #"LPU64
                       ", err = %d\n", last_fid, rc);
                RETURN(rc);
        }
                
        CDEBUG(D_SUPER, "wrote fid #"LPU64" at idx "
               "%llu: err = %d\n", last_fid, off, rc);

        RETURN(rc);
}

void mds_set_last_fid(struct obd_device *obd, __u64 fid)
{
        struct mds_obd *mds = &obd->u.mds;

        spin_lock(&mds->mds_last_fid_lock);
        if (fid > mds->mds_last_fid)
                mds->mds_last_fid = fid;
        spin_unlock(&mds->mds_last_fid_lock);
}

void mds_commit_last_transno_cb(struct obd_device *obd,
                                __u64 transno, void *data,
                                int error)
{
        obd_transno_commit_cb(obd, transno, error);
}

void mds_commit_last_fid_cb(struct obd_device *obd,
                            __u64 fid, void *data,
                            int error)
{
        if (error) {
                CERROR("%s: fid "LPD64" commit error: %d\n",
                       obd->obd_name, fid, error);
                return;
        }
        
        CDEBUG(D_HA, "%s: fid "LPD64" committed\n",
               obd->obd_name, fid);
}

__u64 mds_alloc_fid(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        __u64 fid;
        
        spin_lock(&mds->mds_last_fid_lock);
        fid = ++mds->mds_last_fid;
        spin_unlock(&mds->mds_last_fid_lock);

        return fid;
}

/*
 * allocates new lustre_id on passed @inode and saves it to inode EA.
 */
int mds_alloc_inode_sid(struct obd_device *obd, struct inode *inode,
                        void *handle, struct lustre_id *id)
{
        struct mds_obd *mds = &obd->u.mds;
        int alloc = 0, rc = 0;
        ENTRY;

        LASSERT(obd != NULL);
        LASSERT(inode != NULL);

        if (id == NULL) {
                OBD_ALLOC(id, sizeof(*id));
                if (id == NULL)
                        RETURN(-ENOMEM);
                alloc = 1;
        }

        id_group(id) = mds->mds_num;
        id_fid(id) = mds_alloc_fid(obd);
        id_ino(id) = inode->i_ino;
        id_gen(id) = inode->i_generation;
        id_type(id) = (S_IFMT & inode->i_mode);

        rc = mds_update_inode_sid(obd, inode, handle, id);
        if (rc) {
                CERROR("Can't update inode FID EA, "
                       "rc = %d\n", rc);
        }

        if (alloc)
                OBD_FREE(id, sizeof(*id));
        RETURN(rc);
}

/*
 * reads inode self id from inode EA. Probably later this should be replaced by
 * caching inode self id to avoid raeding it every time it is needed.
 */
int mds_read_inode_sid(struct obd_device *obd, struct inode *inode,
                       struct lustre_id *id)
{
        int rc;
        ENTRY;

        LASSERT(id != NULL);
        LASSERT(obd != NULL);
        LASSERT(inode != NULL);

        rc = fsfilt_get_md(obd, inode, &id->li_fid,
                           sizeof(id->li_fid), EA_SID);
        if (rc < 0) {
                CERROR("fsfilt_get_md() failed, "
                       "rc = %d\n", rc);
                RETURN(rc);
        } else if (!rc) {
                rc = -ENODATA;
                RETURN(rc);
        } else {
                rc = 0;
        }

        RETURN(rc);
}

/* updates inode self id in EA. */
int mds_update_inode_sid(struct obd_device *obd, struct inode *inode,
                         void *handle, struct lustre_id *id)
{
        int rc = 0;
        ENTRY;

        LASSERT(id != NULL);
        LASSERT(obd != NULL);
        LASSERT(inode != NULL);
        
        rc = fsfilt_set_md(obd, inode, handle, &id->li_fid,
                           sizeof(id->li_fid), EA_SID);
        if (rc) {
                CERROR("fsfilt_set_md() failed, rc = %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

/* 
 * reads inode id on master MDS. This is usualy done by CMOBD to update requests
 * to master MDS by correct store cookie, needed to find inode on master MDS
 * quickly.
 */
int mds_read_inode_mid(struct obd_device *obd, struct inode *inode,
                       struct lustre_id *id)
{
        int rc;
        ENTRY;

        LASSERT(id != NULL);
        LASSERT(obd != NULL);
        LASSERT(inode != NULL);

        rc = fsfilt_get_md(obd, inode, id, sizeof(*id), EA_MID);
        if (rc < 0) {
                CERROR("fsfilt_get_md() failed, rc = %d\n", rc);
                RETURN(rc);
        } else if (!rc) {
                rc = -ENODATA;
                RETURN(rc);
        } else {
                rc = 0;
        }

        RETURN(rc);
}

/*
 * updates master inode id. Usualy this is done by CMOBD after an inode is
 * created and relationship between cache MDS and master one should be
 * established.
 */
int mds_update_inode_mid(struct obd_device *obd, struct inode *inode,
                         void *handle, struct lustre_id *id)
{
        int rc = 0;
        ENTRY;

        LASSERT(id != NULL);
        LASSERT(obd != NULL);
        LASSERT(inode != NULL);
        
        rc = fsfilt_set_md(obd, inode, handle, id,
                           sizeof(*id), EA_MID);
        if (rc) {
                CERROR("fsfilt_set_md() failed, "
                       "rc = %d\n", rc);
                RETURN(rc);
        }

        RETURN(rc);
}

/* mount the file system (secretly) */
static int mds_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg* lcfg = buf;
        struct mds_obd *mds = &obd->u.mds;
        struct lvfs_obd_ctxt *lvfs_ctxt = NULL;
        char *options = NULL;
        struct vfsmount *mnt;
        char ns_name[48];
        unsigned long page;
        int rc = 0;
        ENTRY;

        if (lcfg->lcfg_bufcount < 3)
                RETURN(rc = -EINVAL);

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) == 0 || LUSTRE_CFG_BUFLEN(lcfg, 2) == 0)
                RETURN(rc = -EINVAL);

        obd->obd_fsops = fsfilt_get_ops(lustre_cfg_string(lcfg, 2));
        if (IS_ERR(obd->obd_fsops))
                RETURN(rc = PTR_ERR(obd->obd_fsops));

        mds->mds_max_mdsize = sizeof(struct lov_mds_md);

        page = __get_free_page(GFP_KERNEL);
        if (!page)
                RETURN(-ENOMEM);

        options = (char *)page;
        memset(options, 0, PAGE_SIZE);

        /*
         * here we use "iopen_nopriv" hardcoded, because it affects MDS utility
         * and the rest of options are passed by mount options. Probably this
         * should be moved to somewhere else like startup scripts or lconf. */
        sprintf(options, "iopen_nopriv");
        
        if (LUSTRE_CFG_BUFLEN(lcfg, 4) > 0 && lustre_cfg_buf(lcfg, 4))
                sprintf(options + strlen(options), ",%s",
                        lustre_cfg_string(lcfg, 4));

        /* we have to know mdsnum before touching underlying fs -bzzz */
        atomic_set(&mds->mds_open_count, 0);
        sema_init(&mds->mds_md_sem, 1);
        sema_init(&mds->mds_create_sem, 1);
        mds->mds_md_connected = 0;
        mds->mds_md_name = NULL;

        if (LUSTRE_CFG_BUFLEN(lcfg, 5) > 0 && lustre_cfg_buf(lcfg, 5) &&
            strncmp(lustre_cfg_string(lcfg, 5), "dumb", LUSTRE_CFG_BUFLEN(lcfg, 5))) {
                class_uuid_t uuid;

                generate_random_uuid(uuid);
                class_uuid_unparse(uuid, &mds->mds_md_uuid);

                OBD_ALLOC(mds->mds_md_name, LUSTRE_CFG_BUFLEN(lcfg, 5));
                if (mds->mds_md_name == NULL) 
                        RETURN(rc = -ENOMEM);

                memcpy(mds->mds_md_name, lustre_cfg_buf(lcfg, 5),
                       LUSTRE_CFG_BUFLEN(lcfg, 5));
                
                CDEBUG(D_OTHER, "MDS: %s is master for %s\n",
                       obd->obd_name, mds->mds_md_name);

                rc = mds_md_connect(obd, mds->mds_md_name);
                if (rc) {
                        OBD_FREE(mds->mds_md_name, LUSTRE_CFG_BUFLEN(lcfg, 5));
                        GOTO(err_ops, rc);
                }
        }

        mds->mds_obd_type = MDS_MASTER_OBD;

        if (LUSTRE_CFG_BUFLEN(lcfg, 6) > 0 && lustre_cfg_buf(lcfg, 6) &&
            strncmp(lustre_cfg_string(lcfg, 6), "dumb", 
                    LUSTRE_CFG_BUFLEN(lcfg, 6))) {
                if (!memcmp(lustre_cfg_string(lcfg, 6), "master", 
                            strlen("master"))) {
                        mds->mds_obd_type = MDS_MASTER_OBD;
                } else if (!memcmp(lustre_cfg_string(lcfg, 6), "cache", 
                                   strlen("cache"))) {
                        mds->mds_obd_type = MDS_CACHE_OBD;
                }     
        }

        rc = lvfs_mount_fs(lustre_cfg_string(lcfg, 1), 
                           lustre_cfg_string(lcfg, 2),
                           options, 0, &lvfs_ctxt);

        free_page(page);

        if (rc || !lvfs_ctxt) {
                CERROR("lvfs_mount_fs failed: rc = %d\n", rc);
                GOTO(err_ops, rc);
        }

        mnt = lvfs_ctxt->loc_mnt;
        mds->mds_lvfs_ctxt = lvfs_ctxt;
        ll_clear_rdonly(ll_sbdev(mnt->mnt_sb));

        CDEBUG(D_SUPER, "%s: mnt = %p\n", lustre_cfg_string(lcfg, 1), mnt);

        sema_init(&mds->mds_epoch_sem, 1);
        atomic_set(&mds->mds_real_clients, 0);
        spin_lock_init(&mds->mds_transno_lock);
        spin_lock_init(&mds->mds_last_fid_lock);
        sema_init(&mds->mds_orphan_recovery_sem, 1);
        mds->mds_max_cookiesize = sizeof(struct llog_cookie);

        sprintf(ns_name, "mds-%s", obd->obd_uuid.uuid);
        obd->obd_namespace = ldlm_namespace_new(ns_name, LDLM_NAMESPACE_SERVER);

        if (obd->obd_namespace == NULL) {
                mds_cleanup(obd, 0);
                GOTO(err_put, rc = -ENOMEM);
        }
        ldlm_register_intent(obd->obd_namespace, mds_intent_policy);

        rc = mds_fs_setup(obd, mnt);
        if (rc) {
                CERROR("%s: MDS filesystem method init failed: rc = %d\n",
                       obd->obd_name, rc);
                GOTO(err_ns, rc);
        }

        rc = llog_start_commit_thread();
        if (rc < 0)

                GOTO(err_fs, rc);


        if (LUSTRE_CFG_BUFLEN(lcfg, 3) > 0 && lustre_cfg_buf(lcfg, 3) &&
            strncmp(lustre_cfg_string(lcfg, 3), "dumb", 
                    LUSTRE_CFG_BUFLEN(lcfg, 3))) {
                class_uuid_t uuid;

                generate_random_uuid(uuid);
                class_uuid_unparse(uuid, &mds->mds_dt_uuid);

                OBD_ALLOC(mds->mds_profile, LUSTRE_CFG_BUFLEN(lcfg, 3));
                if (mds->mds_profile == NULL)
                        GOTO(err_fs, rc = -ENOMEM);

                strncpy(mds->mds_profile, lustre_cfg_string(lcfg, 3),
                        LUSTRE_CFG_BUFLEN(lcfg, 3));
        }

        /* 
         * setup root dir and files ID dir if lmv already connected, or there is
         * not lmv at all.
         */
        if (mds->mds_md_exp || (LUSTRE_CFG_BUFLEN(lcfg, 3) > 0 && 
                                lustre_cfg_buf(lcfg, 3) &&
                                strncmp(lustre_cfg_string(lcfg, 3), "dumb", 
                                        LUSTRE_CFG_BUFLEN(lcfg, 3)))) {
                rc = mds_fs_setup_rootid(obd);
                if (rc)
                        GOTO(err_fs, rc);

                rc = mds_fs_setup_virtid(obd);
                if (rc)
                        GOTO(err_fs, rc);
        }

        ptlrpc_init_client(LDLM_CB_REQUEST_PORTAL, LDLM_CB_REPLY_PORTAL,
                           "mds_ldlm_client", &obd->obd_ldlm_client);
        obd->obd_replayable = 1;

        rc = mds_postsetup(obd);
        if (rc)
                GOTO(err_fs, rc);

        RETURN(0);

err_fs:
        /* No extra cleanup needed for llog_init_commit_thread() */
        mds_fs_cleanup(obd, 0);
err_ns:
        ldlm_namespace_free(obd->obd_namespace, 0);
        obd->obd_namespace = NULL;
err_put:
        unlock_kernel();
        lvfs_umount_fs(mds->mds_lvfs_ctxt);
        mds->mds_sb = 0;
        lock_kernel();
err_ops:
        fsfilt_put_ops(obd->obd_fsops);
        return rc;
}

static int mds_postsetup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        rc = obd_llog_setup(obd, &obd->obd_llogs, LLOG_CONFIG_ORIG_CTXT, 
                            obd, 0, NULL, &llog_lvfs_ops);
        if (rc)
                RETURN(rc);

        if (mds->mds_profile) {
                struct llog_ctxt *lgctxt;
                struct lvfs_run_ctxt saved;
                struct lustre_profile *lprof;
                struct config_llog_instance cfg;

                cfg.cfg_instance = NULL;
                cfg.cfg_uuid = mds->mds_dt_uuid;
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                lgctxt = llog_get_context(&obd->obd_llogs, LLOG_CONFIG_ORIG_CTXT);
                if (!lgctxt) {
                        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                        GOTO(err_llog, rc = -EINVAL);
                }
                
                rc = class_config_process_llog(lgctxt, mds->mds_profile, &cfg);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                if (rc)
                        GOTO(err_llog, rc);

                lprof = class_get_profile(mds->mds_profile);
                if (lprof == NULL) {
                        CERROR("No profile found: %s\n", mds->mds_profile);
                        GOTO(err_cleanup, rc = -ENOENT);
                }
                rc = mds_dt_connect(obd, lprof->lp_lov);
                if (rc)
                        GOTO(err_cleanup, rc);

                rc = mds_md_postsetup(obd);
                if (rc)
                        GOTO(err_cleanup, rc);
        }

        RETURN(rc);
err_cleanup:
        mds_dt_clean(obd);
err_llog:
        obd_llog_cleanup(llog_get_context(&obd->obd_llogs,
                                          LLOG_CONFIG_ORIG_CTXT));
        return rc;
}

int mds_postrecov_common(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct llog_ctxt *ctxt;
        int rc, item = 0, valsize;
         __u32 group;
        ENTRY;

        LASSERT(!obd->obd_recovering);
        ctxt = llog_get_context(&obd->obd_llogs, LLOG_UNLINK_ORIG_CTXT);
        LASSERT(ctxt != NULL);

        /* clean PENDING dir */
        rc = mds_cleanup_orphans(obd);
        if (rc < 0)
                GOTO(out, rc);
        item = rc;

        group = FILTER_GROUP_FIRST_MDS + mds->mds_num;
        valsize = sizeof(group);
        rc = obd_set_info(mds->mds_dt_exp, strlen("mds_conn"),
                          "mds_conn", valsize, &group);
        if (rc)
                GOTO(out, rc);

        rc = llog_connect(ctxt, obd->u.mds.mds_dt_desc.ld_tgt_count,
                          NULL, NULL, NULL);
        if (rc) {
                CERROR("%s: failed at llog_origin_connect: %d\n", 
                       obd->obd_name, rc);
                GOTO(out, rc);
        }

        /* remove the orphaned precreated objects */
        rc = mds_dt_clear_orphans(mds, NULL /* all OSTs */);
        if (rc)
                GOTO(err_llog, rc);

out:
        RETURN(rc < 0 ? rc : item);

err_llog:
        /* cleanup all llogging subsystems */
        rc = obd_llog_finish(obd, &obd->obd_llogs,
                             mds->mds_dt_desc.ld_tgt_count);
        if (rc)
                CERROR("%s: failed to cleanup llogging subsystems\n",
                        obd->obd_name);
        goto out;
}

int mds_postrecov(struct obd_device *obd)
{
        int rc;
        ENTRY;
        rc = mds_postrecov_common(obd);
        if (rc == 0)
                rc = mds_md_reconnect(obd);
        RETURN(rc);
}

int mds_dt_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        if (mds->mds_profile) {
                char * cln_prof;
                struct llog_ctxt *llctx;
                struct lvfs_run_ctxt saved;
                struct config_llog_instance cfg;
                int len = strlen(mds->mds_profile) + sizeof("-clean") + 1;

                OBD_ALLOC(cln_prof, len);
                sprintf(cln_prof, "%s-clean", mds->mds_profile);

                cfg.cfg_instance = NULL;
                cfg.cfg_uuid = mds->mds_dt_uuid;

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                llctx = llog_get_context(&obd->obd_llogs,
                                         LLOG_CONFIG_ORIG_CTXT);
                class_config_process_llog(llctx, cln_prof, &cfg);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                OBD_FREE(cln_prof, len);
                OBD_FREE(mds->mds_profile, strlen(mds->mds_profile) + 1);
                mds->mds_profile = NULL;
        }
        RETURN(0);
}

int mds_md_clean(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        if (mds->mds_md_name) {
                OBD_FREE(mds->mds_md_name, strlen(mds->mds_md_name) + 1);
                mds->mds_md_name = NULL;
        }
        RETURN(0);
}

static int mds_precleanup(struct obd_device *obd, int flags)
{
        int rc = 0;
        ENTRY;

        mds_md_clean(obd);
        mds_dt_disconnect(obd, flags);
        mds_dt_clean(obd);
        obd_llog_cleanup(llog_get_context(&obd->obd_llogs, LLOG_CONFIG_ORIG_CTXT));
        RETURN(rc);
}

extern void lgss_svc_cache_purge_all(void);
static int mds_cleanup(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        if (mds->mds_sb == NULL)
                RETURN(0);

        mds_update_server_data(obd, 1);
        mds_update_last_fid(obd, NULL, 1);
        
        if (mds->mds_dt_objids != NULL) {
                int size = mds->mds_dt_desc.ld_tgt_count *
                        sizeof(obd_id);
                OBD_FREE(mds->mds_dt_objids, size);
        }
        mds_fs_cleanup(obd, flags);

        unlock_kernel();

        /* 2 seems normal on mds, (may_umount() also expects 2
          fwiw), but we only see 1 at this point in obdfilter. */
        lvfs_umount_fs(mds->mds_lvfs_ctxt);

        mds->mds_sb = 0;

        ldlm_namespace_free(obd->obd_namespace, flags & OBD_OPT_FORCE);

        spin_lock_bh(&obd->obd_processing_task_lock);
        if (obd->obd_recovering) {
                target_cancel_recovery_timer(obd);
                obd->obd_recovering = 0;
        }
        spin_unlock_bh(&obd->obd_processing_task_lock);

        lock_kernel();
        fsfilt_put_ops(obd->obd_fsops);

#ifdef ENABLE_GSS
        /* XXX */
        lgss_svc_cache_purge_all();
#endif

        spin_lock(&mds->mds_denylist_lock);
        while (!list_empty( &mds->mds_denylist ) ) {
                deny_sec_t *p_deny_sec = list_entry(mds->mds_denylist.next,
                                                    deny_sec_t, list);
                list_del(&p_deny_sec->list);
                OBD_FREE(p_deny_sec, sizeof(*p_deny_sec));
        }
        spin_unlock(&mds->mds_denylist_lock);
        if(mds->mds_mds_sec)
                OBD_FREE(mds->mds_mds_sec, strlen(mds->mds_mds_sec) + 1);
        if(mds->mds_ost_sec)
                OBD_FREE(mds->mds_ost_sec, strlen(mds->mds_ost_sec) + 1);

        RETURN(0);
}

static int set_security(const char *value, char **sec)
{
        int rc = 0;

        if (!strcmp(value, "null") ||
            !strcmp(value, "krb5i") ||
            !strcmp(value, "krb5p")) {
                OBD_ALLOC(*sec, strlen(value) + 1);
                if(!*sec)
                        RETURN(-ENOMEM);
                memcpy(*sec, value, strlen(value) + 1);
        } else {
                CERROR("Unrecognized value, force use NULL\n");
                rc = -EINVAL;
        }

        return rc;
}

static int mds_process_config(struct obd_device *obd, obd_count len, void *buf)
{
        struct lustre_cfg *lcfg = buf;
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        switch(lcfg->lcfg_command) {
        case LCFG_SET_SECURITY: {
                if ((LUSTRE_CFG_BUFLEN(lcfg, 1) == 0) ||
                    (LUSTRE_CFG_BUFLEN(lcfg, 2) == 0))
                        GOTO(out, rc = -EINVAL);

                if (!strcmp(lustre_cfg_string(lcfg, 1), "mds_sec"))
                        rc = set_security(lustre_cfg_string(lcfg, 2),
                                          &mds->mds_mds_sec);
                else if (!strcmp(lustre_cfg_string(lcfg, 1), "oss_sec"))
                        rc = set_security(lustre_cfg_string(lcfg, 2),
                                          &mds->mds_ost_sec);
                else if (!strcmp(lustre_cfg_string(lcfg, 1), "deny_sec")){
                        spin_lock(&mds->mds_denylist_lock);
                        rc = add_deny_security(lustre_cfg_string(lcfg, 2),
                                               &mds->mds_denylist);
                        spin_unlock(&mds->mds_denylist_lock);
                } else {
                        CERROR("Unrecognized key\n");
                        rc = -EINVAL;
                }
                break;
        }
        default: {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                GOTO(out, rc = -EINVAL);

        }
        }
out:
        RETURN(rc);
}

static void fixup_handle_for_resent_req(struct ptlrpc_request *req,
                                        int offset,
                                        struct ldlm_lock *new_lock,
                                        struct ldlm_lock **old_lock,
                                        struct lustre_handle *lockh)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct ldlm_request *dlmreq =
                lustre_msg_buf(req->rq_reqmsg, offset, sizeof (*dlmreq));
        struct lustre_handle remote_hdl = dlmreq->lock_handle1;
        struct list_head *iter;

        if (!(lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT))
                return;

        l_lock(&obd->obd_namespace->ns_lock);
        list_for_each(iter, &exp->exp_ldlm_data.led_held_locks) {
                struct ldlm_lock *lock;
                lock = list_entry(iter, struct ldlm_lock, l_export_chain);
                if (lock == new_lock)
                        continue;
                if (lock->l_remote_handle.cookie == remote_hdl.cookie) {
                        lockh->cookie = lock->l_handle.h_cookie;
                        LDLM_DEBUG(lock, "restoring lock cookie");
                        DEBUG_REQ(D_HA, req, "restoring lock cookie "LPX64,
                                  lockh->cookie);
                        if (old_lock)
                                *old_lock = LDLM_LOCK_GET(lock);
                        l_unlock(&obd->obd_namespace->ns_lock);
                        return;
                }
        }
        l_unlock(&obd->obd_namespace->ns_lock);

        /* If the xid matches, then we know this is a resent request,
         * and allow it. (It's probably an OPEN, for which we don't
         * send a lock */
        if (req->rq_xid == 
            le64_to_cpu(exp->exp_mds_data.med_mcd->mcd_last_xid))
                return;

        if (req->rq_xid == 
            le64_to_cpu(exp->exp_mds_data.med_mcd->mcd_last_close_xid))
                return;

        /* This remote handle isn't enqueued, so we never received or
         * processed this request.  Clear MSG_RESENT, because it can
         * be handled like any normal request now. */

        lustre_msg_clear_flags(req->rq_reqmsg, MSG_RESENT);

        DEBUG_REQ(D_HA, req, "no existing lock with rhandle "LPX64,
                  remote_hdl.cookie);
}

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

static int mds_intent_policy(struct ldlm_namespace *ns,
                             struct ldlm_lock **lockp, void *req_cookie,
                             ldlm_mode_t mode, int flags, void *data)
{
        struct ptlrpc_request *req = req_cookie;
        struct ldlm_lock *lock = *lockp;
        struct ldlm_intent *it;
        struct mds_obd *mds = &req->rq_export->exp_obd->u.mds;
        struct ldlm_reply *rep;
        struct lustre_handle lockh[2] = {{0}, {0}};
        struct ldlm_lock *new_lock = NULL;
        int getattr_part = MDS_INODELOCK_UPDATE;
        int rc, reply_buffers;
        int repsize[5] = {sizeof(struct ldlm_reply),
                          sizeof(struct mds_body),
                          mds->mds_max_mdsize};

        int offset = MDS_REQ_INTENT_REC_OFF; 
        ENTRY;

        LASSERT(req != NULL);
        MD_COUNTER_INCREMENT(req->rq_export->exp_obd, intent_lock);

        if (req->rq_reqmsg->bufcount <= MDS_REQ_INTENT_IT_OFF) {
                /* No intent was provided */
                int size = sizeof(struct ldlm_reply);
                rc = lustre_pack_reply(req, 1, &size, NULL);
                LASSERT(rc == 0);
                RETURN(0);
        }

        it = lustre_swab_reqbuf(req, MDS_REQ_INTENT_IT_OFF, sizeof(*it),
                                lustre_swab_ldlm_intent);
        if (it == NULL) {
                CERROR("Intent missing\n");
                RETURN(req->rq_status = -EFAULT);
        }

        LDLM_DEBUG(lock, "intent policy, opc: %s", ldlm_it2str(it->opc));

        reply_buffers = 3;
        if (it->opc & ( IT_OPEN | IT_GETATTR | IT_LOOKUP | IT_CHDIR )) {
                reply_buffers = 5;
                repsize[3] = 4;
                repsize[4] = xattr_acl_size(LL_ACL_MAX_ENTRIES);
        }

        rc = lustre_pack_reply(req, reply_buffers, repsize, NULL);
        if (rc)
                RETURN(req->rq_status = rc);

        rep = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep));
        LASSERT(rep != NULL);

        intent_set_disposition(rep, DISP_IT_EXECD);

        /* execute policy */
        switch ((long)it->opc) {
        case IT_OPEN:
        case IT_CREAT|IT_OPEN:
                fixup_handle_for_resent_req(req, MDS_REQ_INTENT_LOCKREQ_OFF,
					    lock, NULL, lockh);
                /* XXX swab here to assert that an mds_open reint
                 * packet is following */
                fixup_handle_for_resent_req(req, MDS_REQ_INTENT_LOCKREQ_OFF, 
                                            lock, NULL, lockh);
                rep->lock_policy_res2 = mds_reint(req, offset, lockh);

                if (rep->lock_policy_res2) {
                        /* 
                         * mds_open() returns ENOLCK where it should return
                         * zero, but it has no lock to return.
                         */
                        if (rep->lock_policy_res2 == ENOLCK)
                                rep->lock_policy_res2 = 0;

                        RETURN(ELDLM_LOCK_ABORTED);
                }
                
                /*
                 * IT_OPEN may return lock on cross-node dentry that we want to
                 * hold during attr retrival -bzzz
                 */
                if (lockh[0].cookie == 0)
                        RETURN(ELDLM_LOCK_ABORTED);
                
                break;
        case IT_LOOKUP:
                getattr_part = MDS_INODELOCK_LOOKUP;
        case IT_CHDIR:
        case IT_GETATTR:
                getattr_part |= MDS_INODELOCK_LOOKUP;
        case IT_READDIR:
                fixup_handle_for_resent_req(req, MDS_REQ_INTENT_LOCKREQ_OFF, 
                                            lock, &new_lock, lockh);
                rep->lock_policy_res2 = mds_getattr_lock(req, offset, lockh,
                                                         getattr_part);
                /* FIXME: LDLM can set req->rq_status. MDS sets
                   policy_res{1,2} with disposition and status.
                   - replay: returns 0 & req->status is old status
                   - otherwise: returns req->status */
                if (intent_disposition(rep, DISP_LOOKUP_NEG))
                        rep->lock_policy_res2 = 0;
                if (!intent_disposition(rep, DISP_LOOKUP_POS) ||
                    rep->lock_policy_res2)
                        RETURN(ELDLM_LOCK_ABORTED);
                if (req->rq_status != 0) {
                        LBUG();
                        rep->lock_policy_res2 = req->rq_status;
                        RETURN(ELDLM_LOCK_ABORTED);
                }
                break;
        case IT_UNLINK:
                rc = mds_lock_and_check_slave(offset, req, lockh);
                if ((rep->lock_policy_res2 = rc)) {
                        if (rc == ENOLCK)
                                rep->lock_policy_res2 = 0;
                        RETURN(ELDLM_LOCK_ABORTED);
                }
                break;
        default:
                CERROR("Unhandled intent "LPD64"\n", it->opc);
                LBUG();
        }

        /* By this point, whatever function we called above must have either
         * filled in 'lockh', been an intent replay, or returned an error.  We
         * want to allow replayed RPCs to not get a lock, since we would just
         * drop it below anyways because lock replay is done separately by the
         * client afterwards.  For regular RPCs we want to give the new lock to
         * the client instead of whatever lock it was about to get. */
        if (new_lock == NULL)
                new_lock = ldlm_handle2lock(&lockh[0]);
        if (new_lock == NULL && (flags & LDLM_FL_INTENT_ONLY))
                RETURN(0);

        LASSERTF(new_lock != NULL, "op "LPX64" lockh "LPX64"\n",
                 it->opc, lockh[0].cookie);

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
        l_lock(&new_lock->l_resource->lr_namespace->ns_lock);
        new_lock->l_readers = 0;
        new_lock->l_writers = 0;

        new_lock->l_export = class_export_get(req->rq_export);
        list_add(&new_lock->l_export_chain,
                 &new_lock->l_export->exp_ldlm_data.led_held_locks);

        new_lock->l_blocking_ast = lock->l_blocking_ast;
        new_lock->l_completion_ast = lock->l_completion_ast;

        memcpy(&new_lock->l_remote_handle, &lock->l_remote_handle,
               sizeof(lock->l_remote_handle));

        new_lock->l_flags &= ~LDLM_FL_LOCAL;

        LDLM_LOCK_PUT(new_lock);
        l_unlock(&new_lock->l_resource->lr_namespace->ns_lock);

        RETURN(ELDLM_LOCK_REPLACED);
}

int mds_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;
        int rc = 0;
        struct mds_obd *mds = &dev->u.mds;

        spin_lock_init(&mds->mds_denylist_lock);
        INIT_LIST_HEAD(&mds->mds_denylist);

        lprocfs_init_multi_vars(0, &lvars);

        rc = lprocfs_obd_attach(dev, lvars.obd_vars);
        if (rc)
                return rc;

        return lprocfs_alloc_md_stats(dev, 0);
}

int mds_detach(struct obd_device *dev)
{
        lprocfs_free_md_stats(dev);
        return lprocfs_obd_detach(dev);
}

int mdt_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_multi_vars(1, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

int mdt_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static int mdt_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        mds->mds_service =
                ptlrpc_init_svc(MDS_NBUFS, MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                                MDS_SERVICE_WATCHDOG_TIMEOUT,
                                mds_handle, "mds", obd->obd_proc_entry);

        if (!mds->mds_service) {
                CERROR("failed to start service\n");
                RETURN(-ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obd, mds->mds_service, MDT_NUM_THREADS,
                                    "ll_mdt");
        if (rc)
                GOTO(err_thread, rc);

        mds->mds_setattr_service =
                ptlrpc_init_svc(MDS_NBUFS, MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_SETATTR_PORTAL, MDC_REPLY_PORTAL,
                                MDS_SERVICE_WATCHDOG_TIMEOUT,
                                mds_handle, "mds_setattr",
                                obd->obd_proc_entry);
        if (!mds->mds_setattr_service) {
                CERROR("failed to start getattr service\n");
                GOTO(err_thread, rc = -ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obd, mds->mds_setattr_service,
                                    MDT_NUM_THREADS, "ll_mdt_attr");
        if (rc)
                GOTO(err_thread2, rc);

        mds->mds_readpage_service =
                ptlrpc_init_svc(MDS_NBUFS, MDS_BUFSIZE, MDS_MAXREQSIZE,
                                MDS_READPAGE_PORTAL, MDC_REPLY_PORTAL,
                                MDS_SERVICE_WATCHDOG_TIMEOUT,
                                mds_handle, "mds_readpage",
                                obd->obd_proc_entry);
        if (!mds->mds_readpage_service) {
                CERROR("failed to start readpage service\n");
                GOTO(err_thread2, rc = -ENOMEM);
        }

        rc = ptlrpc_start_n_threads(obd, mds->mds_readpage_service,
                                    MDT_NUM_THREADS, "ll_mdt_rdpg");

        if (rc)
                GOTO(err_thread3, rc);

        RETURN(0);

err_thread3:
        ptlrpc_unregister_service(mds->mds_readpage_service);
err_thread2:
        ptlrpc_unregister_service(mds->mds_setattr_service);
err_thread:
        ptlrpc_unregister_service(mds->mds_service);
        return rc;
}

static int mdt_cleanup(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        ENTRY;

        ptlrpc_stop_all_threads(mds->mds_readpage_service);
        ptlrpc_unregister_service(mds->mds_readpage_service);

        ptlrpc_stop_all_threads(mds->mds_setattr_service);
        ptlrpc_unregister_service(mds->mds_setattr_service);

        ptlrpc_stop_all_threads(mds->mds_service);
        ptlrpc_unregister_service(mds->mds_service);

        RETURN(0);
}

static struct dentry *mds_lvfs_id2dentry(__u64 ino, __u32 gen,
                                         __u64 gr, void *data)
{
        struct lustre_id id;
        struct obd_device *obd = data;
        
        id_ino(&id) = ino;
        id_gen(&id) = gen;
        return mds_id2dentry(obd, &id, NULL);
}

static int mds_get_info(struct obd_export *exp, __u32 keylen,
                        void *key, __u32 *valsize, void *val)
{
        struct obd_device *obd;
        struct mds_obd *mds;
        ENTRY;

        obd = class_exp2obd(exp);
        mds = &obd->u.mds;
        
        if (obd == NULL) {
                CDEBUG(D_IOCTL, "invalid client cookie "LPX64"\n",
                       exp->exp_handle.h_cookie);
                RETURN(-EINVAL);
        }

        if (keylen >= strlen("reint_log") && memcmp(key, "reint_log", 9) == 0) {
                /* get log_context handle. */
                unsigned long *llh_handle = val;
                *valsize = sizeof(unsigned long);
                *llh_handle = (unsigned long)obd->obd_llog_ctxt[LLOG_REINT_ORIG_CTXT];
                RETURN(0);
        }
        if (keylen >= strlen("cache_sb") && memcmp(key, "cache_sb", 8) == 0) {
                /* get log_context handle. */
                unsigned long *sb = val;
                *valsize = sizeof(unsigned long);
                *sb = (unsigned long)obd->u.mds.mds_sb;
                RETURN(0);
        }

        if (keylen >= strlen("mdsize") && memcmp(key, "mdsize", keylen) == 0) {
                __u32 *mdsize = val;
                *valsize = sizeof(*mdsize);
                *mdsize = mds->mds_max_mdsize;
                RETURN(0);
        }

        if (keylen >= strlen("mdsnum") && strcmp(key, "mdsnum") == 0) {
                __u32 *mdsnum = val;
                *valsize = sizeof(*mdsnum);
                *mdsnum = mds->mds_num;
                RETURN(0);
        }

        if (keylen >= strlen("rootid") && strcmp(key, "rootid") == 0) {
                struct lustre_id *rootid = val;
                *valsize = sizeof(struct lustre_id);
                *rootid = mds->mds_rootid;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);

}
struct lvfs_callback_ops mds_lvfs_ops = {
        l_id2dentry:     mds_lvfs_id2dentry,
};

int mds_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                int objcount, struct obd_ioobj *obj,
                int niocount, struct niobuf_remote *nb,
                struct niobuf_local *res,
                struct obd_trans_info *oti);

int mds_commitrw(int cmd, struct obd_export *exp, struct obdo *oa,
                 int objcount, struct obd_ioobj *obj, int niocount,
                 struct niobuf_local *res, struct obd_trans_info *oti,
                 int rc);

/* use obd ops to offer management infrastructure */
static struct obd_ops mds_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_attach          = mds_attach,
        .o_detach          = mds_detach,
        .o_connect         = mds_connect,
        .o_connect_post    = mds_connect_post,
        .o_init_export     = mds_init_export,
        .o_destroy_export  = mds_destroy_export,
        .o_disconnect      = mds_disconnect,
        .o_setup           = mds_setup,
        .o_precleanup      = mds_precleanup,
        .o_cleanup         = mds_cleanup,
        .o_process_config  = mds_process_config,
        .o_postrecov       = mds_postrecov,
        .o_statfs          = mds_obd_statfs,
        .o_iocontrol       = mds_iocontrol,
        .o_create          = mds_obd_create,
        .o_destroy         = mds_obd_destroy,
        .o_llog_init       = mds_llog_init,
        .o_llog_finish     = mds_llog_finish,
        .o_notify          = mds_notify,
        .o_get_info        = mds_get_info,
        .o_set_info        = mds_set_info,
        .o_preprw          = mds_preprw, 
        .o_commitrw        = mds_commitrw,
};

static struct obd_ops mdt_obd_ops = {
        .o_owner           = THIS_MODULE,
        .o_attach          = mdt_attach,
        .o_detach          = mdt_detach,
        .o_setup           = mdt_setup,
        .o_cleanup         = mdt_cleanup,
};

static int __init mds_init(void)
{
        struct lprocfs_static_vars lvars;

        mds_init_lsd_cache();

        lprocfs_init_multi_vars(0, &lvars);
        class_register_type(&mds_obd_ops, NULL, lvars.module_vars,
                            LUSTRE_MDS_NAME);
        lprocfs_init_multi_vars(1, &lvars);
        class_register_type(&mdt_obd_ops, NULL, lvars.module_vars,
                            LUSTRE_MDT_NAME);

        return 0;
}

static void /*__exit*/ mds_exit(void)
{
        mds_cleanup_lsd_cache();

        class_unregister_type(LUSTRE_MDS_NAME);
        class_unregister_type(LUSTRE_MDT_NAME);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Metadata Server (MDS)");
MODULE_LICENSE("GPL");

module_init(mds_init);
module_exit(mds_exit);
