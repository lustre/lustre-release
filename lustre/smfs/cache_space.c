/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/smfs/cache_space.c
 *  A library of functions to manage cache space based on ARC
 *  (modified LRU) replacement algorithm.
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_SM

#include <linux/lustre_log.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>

#include "smfs_internal.h"

struct cache_purge_param {
        int nfract;             /* percentage of cache dirty to activate
                                 * cpurge */
        int ndirty;             /* maximum number of objects to write out per
                                   wake-cycle */
        int interval;           /* jiffies delay between cache purge */
        int nfract_sync;        /* percentage of cache dirty to activate cpurge
                                   synchronously */
        int nfract_stop_cpurge; /* percentage of cache dirty to stop cpurge */
} cf_prm = {30, 512, 600 * HZ, 60, 20};

static struct cache_purge_queue smfs_cpq;
static struct cache_purge_queue *cpq = &smfs_cpq;

static int cache_leaf_node(struct dentry *dentry, __u64 *active_entry)
{
        struct inode *inode = dentry->d_inode;

        if (!inode)
                return 0;
        
        if (S_ISDIR(inode->i_mode)) {
                if (inode->i_nlink != 2)
                        return 0;
                if (!strncmp((char *)dentry->d_name.name,
                             "lost+found", dentry->d_name.len))
                        return 0;
                LASSERT(active_entry != NULL);
                get_active_entry(inode, active_entry);
                return(*active_entry > 0 ? 0 : 1);
        } else {
                if (inode->i_nlink != 1)
                        return 0;
                if (!strncmp((char *)dentry->d_name.name, KML_LOG_NAME, dentry->d_name.len) ||
                    !strncmp((char *)dentry->d_name.name, CACHE_LRU_LOG, dentry->d_name.len))
                        return 0;
                return 1;
        }
}

static int cache_pre_leaf_node(struct dentry *dentry, __u64 *active_entry, int op)
{
        if (((op == 0 && dentry->d_inode->i_nlink == 0) ||
            (op == 1 && dentry->d_inode->i_nlink == 2)) &&
            strncmp((char *)dentry->d_name.name, KML_LOG_NAME, dentry->d_name.len) &&
            strncmp((char *)dentry->d_name.name, CACHE_LRU_LOG, dentry->d_name.len))
                return 1;
        else if ((op == 2 && dentry->d_inode->i_nlink == 0) ||
                 (op == 3 && dentry->d_inode->i_nlink == 3)) {
                LASSERT(active_entry != NULL);
                get_active_entry(dentry->d_inode, active_entry);
                return(*active_entry > 0 ? 0 : 1);
        }
        return 0;
}

static int set_lru_logcookie(struct inode *inode, void *handle,
                             struct llog_cookie *logcookie)
{
        struct fsfilt_operations *fsops = I2CSB(inode)->sm_fsfilt;
        int rc;
        ENTRY;

        rc = fsops->fs_set_xattr(inode, handle, XATTR_SMFS_CACHE_LOGCOOKIE,
                                 logcookie, sizeof(*logcookie));
        RETURN(rc);
}

static int get_lru_logcookie(struct inode *inode, struct llog_cookie *logcookie)
{
        struct fsfilt_operations *fsops = I2CSB(inode)->sm_fsfilt;
        int rc;
        
        ENTRY;
        rc = fsops->fs_get_xattr(inode, XATTR_SMFS_CACHE_LOGCOOKIE,
                                 logcookie, sizeof(*logcookie));
        RETURN(rc);
}

static int try2purge_from_cache(struct lustre_id cid,
                                struct lustre_id pid)
{
        struct inode *inode, *parent;
        struct super_block *sb = cpq->cpq_sb;
        __u32 hoard_priority = 0;
        int rc = 0;
        ENTRY;

        inode = iget(sb, cid.li_stc.u.e3s.l3s_ino);
        if (IS_ERR(inode)) {
                CERROR("not existent inode: "LPX64"/%u\n",
                       cid.li_stc.u.e3s.l3s_ino,
                       cid.li_stc.u.e3s.l3s_gen);
                RETURN(-ENOENT);
        }
        parent = iget(sb, pid.li_stc.u.e3s.l3s_ino);
        if (IS_ERR(parent)) {
                CERROR("not existent inode: "LPX64"/%u\n",
                       pid.li_stc.u.e3s.l3s_ino,
                       pid.li_stc.u.e3s.l3s_gen);
                iput(inode);
                RETURN(-ENOENT);
        }

        CWARN("inode/parent %lu:%lu on the lru list\n",
              inode->i_ino, parent->i_ino);

        rc = get_hoard_priority(inode, &hoard_priority);
        if (hoard_priority) {
                CWARN("inode %lu set hoard\n", inode->i_ino);
                GOTO(out, rc);
        }
        if (atomic_read(&inode->i_count) > 1 || (inode->i_state & I_DIRTY)) {
                CWARN("inode %lu is busy\n", inode->i_ino);
                GOTO(out, rc = 0);
        }

out:
        iput(inode);
        iput(parent);
        RETURN(rc);
}

static int cache_lru_get_rec_cb(struct llog_handle *llh,
                                struct llog_rec_hdr *rec, void *data)
{
        struct llog_lru_rec *llr;
        int count = *(int *)data, rc = 0;
        ENTRY;

        if (!(le32_to_cpu(llh->lgh_hdr->llh_flags) & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain\n");
                RETURN(-EINVAL);
        }
        if (rec->lrh_type != CACHE_LRU_REC) {
                CERROR("log record type error\n");
                RETURN(-EINVAL);
        }

        llr = (struct llog_lru_rec *)rec;

        if (try2purge_from_cache(llr->llr_cid, llr->llr_pid)==1){
                CDEBUG(D_INODE, "purge ino/gen "LPX64"/%u from cache\n",
                       llr->llr_cid.li_stc.u.e3s.l3s_ino,
                       llr->llr_cid.li_stc.u.e3s.l3s_gen);
                count --;
                if (count == 0)
                        rc = LLOG_PROC_BREAK;
                *(int *)data = count;
        }

        RETURN(rc);
}

static int cpurge_stop(void)
{
        struct fsfilt_operations *fsops = S2SMI(cpq->cpq_sb)->sm_fsfilt;
        struct obd_statfs osfs;
        int rc, free;

        rc = fsops->fs_statfs(cpq->cpq_sb, &osfs);
        LASSERT(rc == 0);

        free = osfs.os_bfree * 100;
        if (free < cf_prm.nfract_stop_cpurge * osfs.os_blocks)
                return 1;
        return 0;
}

static int cache_balance_state(void)
{
        struct fsfilt_operations *fsops = S2SMI(cpq->cpq_sb)->sm_fsfilt;
        struct obd_statfs osfs;
        int rc, free;

        rc = fsops->fs_statfs(cpq->cpq_sb, &osfs);
        LASSERT(rc == 0);

        free = (osfs.os_blocks - osfs.os_bfree) * 100;
        if (free > cf_prm.nfract * osfs.os_blocks) {
                if (free < cf_prm.nfract_sync)
                        return 1;
                return 0;
        }
        return -1;
}

void wakeup_cpurge(void)
{
        wake_up(&cpq->cpq_waitq);
}

/* walk the lru llog to purge count number of objects */
static int purge_some_cache(int *count)
{
        int rc;
        ENTRY;

        rc = llog_cat_process(cpq->cpq_loghandle,
                              (llog_cb_t)cache_lru_get_rec_cb,
                              count);
        if (!rc)
                CDEBUG(D_INODE, "no enough objects available\n");

        RETURN(rc);
}

#define CFLUSH_NR 512

static void check_cache_space(void)
{
        int state = cache_balance_state();
        ENTRY;

        if (state < 0) {
                EXIT;
                return;
        }

        wakeup_cpurge();

        if (state > 0) {
                int count = CFLUSH_NR;
                purge_some_cache(&count);
        }
        EXIT;
}

static int cache_space_hook_lru(struct inode *inode, struct inode *parent,
                                int op, int flags)
{
        struct fsfilt_operations *fsops = S2SMI(cpq->cpq_sb)->sm_fsfilt;
        struct llog_ctxt *ctxt = cpq->cpq_loghandle->lgh_ctxt;
        struct llog_lru_rec *llr = NULL;
        struct llog_cookie *logcookie = NULL;
        void * handle = NULL;
        int cookie_size = sizeof(struct llog_cookie);
        int rc = 0, err;
        ENTRY;

        LASSERT(ctxt != NULL);

        if (op & ~(CACHE_SPACE_DELETE | CACHE_SPACE_INSERT |CACHE_SPACE_COMMIT))
                RETURN(-EINVAL);

        OBD_ALLOC(logcookie, cookie_size);
        if (!logcookie)
                GOTO(out, rc = -ENOMEM);

         if (op & CACHE_SPACE_DELETE) {
                rc = get_lru_logcookie(inode, logcookie);
                if (rc < 0)
                        goto out;

                if (logcookie->lgc_lgl.lgl_oid == 0) {
                        CWARN("inode %lu/%u is not in lru list\n",
                              inode->i_ino, inode->i_generation);
                        rc = -ENOENT;
                }
                else {
                        rc = 0;
                        if (flags && llog_cat_half_bottom(logcookie, ctxt->loc_handle))
                               goto out;

                        rc = llog_cancel(ctxt, 1, logcookie, 0, NULL);
                        if (!rc) {
                                memset(logcookie, 0, cookie_size);
                                rc = set_lru_logcookie(inode, handle, logcookie);
                        }
                        if (rc)
                                        goto out;
                }
        }

         if (op & CACHE_SPACE_INSERT) {
                LASSERT(parent != NULL);
                OBD_ALLOC(llr, sizeof(*llr));
                if (llr == NULL)
                        GOTO(out, rc = -ENOMEM);

                llr->llr_hdr.lrh_len = llr->llr_tail.lrt_len = sizeof(*llr);
                llr->llr_hdr.lrh_type = CACHE_LRU_REC;

                /* FIXME-UMKA: should we setup fid components here? */
                id_ino(&llr->llr_cid) = inode->i_ino;
                id_gen(&llr->llr_cid) = inode->i_generation;
                id_type(&llr->llr_cid) = inode->i_mode & S_IFMT;

                id_ino(&llr->llr_pid) = parent->i_ino;
                id_gen(&llr->llr_pid) = parent->i_generation;
                id_type(&llr->llr_pid) = parent->i_mode & S_IFMT;

                rc = llog_add(ctxt, &llr->llr_hdr, NULL, logcookie, 1,
                              NULL, NULL, NULL);
                if (rc != 1) {
                        CERROR("failed at llog_add: %d\n", rc);
                        GOTO(out, rc);
                }
                rc = set_lru_logcookie(inode, handle, logcookie);
        }

        if (op & CACHE_SPACE_COMMIT) {
                if (handle) {
                        err = fsops->fs_commit(inode->i_sb, inode, handle, 0);
                        if (err) {
                                CERROR("error committing transaction: %d\n", err);
                                if (!rc)
                                        rc = err;
                        }
                }
        }
out:
        if (logcookie)
                OBD_FREE(logcookie, cookie_size);
        if (llr)
                OBD_FREE(llr, sizeof(*llr));
        RETURN(rc);
}

static int cache_purge_thread(void *args)
{
        unsigned long flags;
        struct l_wait_info lwi = LWI_TIMEOUT(cf_prm.interval * HZ, NULL, NULL);
        ENTRY;

        lock_kernel();
        kportal_daemonize("wb_cache_purge");

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        unlock_kernel();
        complete(&cpq->cpq_comp);

        while (1) {
                int ndirty = cf_prm.ndirty;

                purge_some_cache(&ndirty);
                if (ndirty > 0 || cpurge_stop())
                        l_wait_event(cpq->cpq_waitq,
                                     cpq->cpq_flags & SVC_STOPPING,
                                     &lwi);
                if (cpq->cpq_flags & SVC_STOPPING) {
                        cpq->cpq_flags &= ~SVC_STOPPING;
                        EXIT;
                        break;
                }
        }
        cpq->cpq_flags = SVC_STOPPED;
        complete(&cpq->cpq_comp);
        RETURN(0);
}

/* Hooks */
static int cache_space_hook_create (struct inode *dir, struct dentry * dentry)
{
        __u64 active_entry = 0;
        int rc;
        ENTRY;

        LASSERT(cache_leaf_node(dentry, NULL));
        rc = cache_space_hook_lru(dentry->d_inode, dir, CACHE_SPACE_INSERT, 0);
        if (rc)
                RETURN(rc);
        if (cache_leaf_node(dentry->d_parent, &active_entry)) {
                rc = cache_space_hook_lru(dir, NULL, CACHE_SPACE_DELETE, 0);
                if (rc)
                        RETURN(rc);
        }
        if (!active_entry)
                rc = get_active_entry(dir, &active_entry);
        active_entry ++;
        if (!rc)
                rc = set_active_entry(dir, &active_entry, NULL);
        RETURN(rc);
}

static int cache_space_hook_lookup(struct inode *dir, struct dentry *dentry)
{
        __u64 active_entry;
        int rc = 0;
        ENTRY;

        if (cache_leaf_node(dentry, &active_entry))
                rc = cache_space_hook_lru(dentry->d_inode, dir, 
                                          CACHE_SPACE_DELETE | CACHE_SPACE_INSERT, 1);
        RETURN(rc);
}

static int cache_space_hook_link(struct inode *dir, struct dentry *dentry)
{
        __u64 active_entry = 0;
        int rc = 0;
        ENTRY;

        if (cache_pre_leaf_node(dentry, NULL, 1)) {
                rc = cache_space_hook_lru(dentry->d_inode, NULL, 
                                          CACHE_SPACE_DELETE, 0);
                if (rc)
                        RETURN(rc);
        }

        if (cache_leaf_node(dentry->d_parent, &active_entry)) {
                rc = cache_space_hook_lru(dir, NULL, CACHE_SPACE_DELETE, 0);
                if (rc)
                        RETURN(rc);
        }

        if (!active_entry)
                rc = get_active_entry(dir, &active_entry);
        active_entry ++;
        if (!rc)
                rc = set_active_entry(dir, &active_entry, NULL);
        RETURN(rc);
}

static int cache_space_hook_unlink(struct inode *dir, struct dentry *dentry)
{
        __u64 active_entry;
        int rc = 0;
        ENTRY;

        if (cache_pre_leaf_node(dentry, NULL, 0))
                rc = cache_space_hook_lru(dentry->d_inode, NULL,
                                          CACHE_SPACE_DELETE, 0);
        else if (cache_leaf_node(dentry, NULL))
                        rc = cache_space_hook_lru(dentry->d_inode, dir,
                                                  CACHE_SPACE_INSERT,0);
        if (rc)
                RETURN(rc);

        rc = get_active_entry(dir, &active_entry);
        active_entry --;
        if (!rc)
                rc = set_active_entry(dir, &active_entry, NULL);
        if (!rc && cache_leaf_node(dentry->d_parent, &active_entry))
                rc = cache_space_hook_lru(dir,
                                          dentry->d_parent->d_parent->d_inode,
                                          CACHE_SPACE_INSERT, 0);
        RETURN(rc);
}

static int cache_space_hook_mkdir(struct inode *dir, struct dentry *dentry)
{
        __u64 active_entry;
        int rc;
        ENTRY;

        LASSERT(cache_leaf_node(dentry, &active_entry));
        rc = cache_space_hook_lru(dentry->d_inode, dir, CACHE_SPACE_INSERT, 0);

        if (!rc && cache_pre_leaf_node(dentry->d_parent, &active_entry, 3))
                rc = cache_space_hook_lru(dir, NULL, CACHE_SPACE_DELETE, 0);
        RETURN(rc);
}

static int cache_space_hook_rmdir(struct inode *dir, struct dentry *dentry)
{
        __u64 active_entry;
        int rc;
        ENTRY;

        LASSERT(cache_pre_leaf_node(dentry, &active_entry, 2));
        rc = cache_space_hook_lru(dentry->d_inode, NULL, 
                                  CACHE_SPACE_DELETE, 0);

        if (!rc && cache_leaf_node(dentry->d_parent, &active_entry))
                rc = cache_space_hook_lru(dir,
                                          dentry->d_parent->d_parent->d_inode,
                                          CACHE_SPACE_INSERT, 0);
        RETURN(rc);
}

static int cache_space_hook_rename(struct inode *old_dir, struct dentry *old_dentry,
                                   struct inode *new_dir, struct dentry *new_dentry)
{
        __u64 active_entry;
        int rc = 0;
        ENTRY;

        if (new_dentry->d_inode) {
                if (cache_pre_leaf_node(new_dentry, NULL, 0))
                        rc = cache_space_hook_lru(new_dentry->d_inode, NULL,
                                                  CACHE_SPACE_DELETE,0);
                else if (cache_leaf_node(new_dentry, NULL))
                        rc = cache_space_hook_lru(new_dentry->d_inode,
                                                  new_dir,
                                                  CACHE_SPACE_INSERT,0);
        }

        if (rc || old_dir == new_dir)
                RETURN(rc);

        if (!S_ISDIR(old_dentry->d_inode->i_mode)) {
                if (cache_leaf_node(new_dentry->d_parent, &active_entry)) {
                        rc = cache_space_hook_lru(new_dir, NULL,
                                                  CACHE_SPACE_DELETE, 0);
                        if (rc)
                                RETURN(rc);
                }
                if (!active_entry)
                        rc = get_active_entry(new_dir, &active_entry);
                active_entry ++;
                if (!rc)
                        rc = set_active_entry(new_dir, &active_entry, NULL);
                if (rc)
                        RETURN(rc);
                rc = get_active_entry(old_dir, &active_entry);
                active_entry --;
                if (!rc)
                        rc = set_active_entry(old_dir, &active_entry, NULL);
        } else if (cache_pre_leaf_node(new_dentry->d_parent, &active_entry, 3)) {
                rc = cache_space_hook_lru(new_dir, NULL,
                                          CACHE_SPACE_DELETE, 0);
        }

        if (!rc && cache_leaf_node(old_dentry->d_parent, &active_entry)) {
                rc = cache_space_hook_lru(old_dir,
                                          old_dentry->d_parent->d_parent->d_inode,
                                          CACHE_SPACE_INSERT, 0);
        }
        
        RETURN(rc);
}

static int lru_create (struct inode * inode, void * arg)
{
        struct hook_msg * msg = arg;
        return cache_space_hook_create(inode, msg->dentry);
}
static int lru_lookup (struct inode * inode, void * arg)
{
        struct hook_msg * msg = arg;
        return cache_space_hook_lookup(inode, msg->dentry);
}
static int lru_link (struct inode * inode, void * arg)
{
        struct hook_link_msg * msg = arg;
        return cache_space_hook_link(inode, msg->dentry);
}
static int lru_unlink (struct inode * inode, void * arg)
{
        struct hook_unlink_msg * msg = arg;
        return cache_space_hook_unlink(inode, msg->dentry);
}
static int lru_symlink (struct inode * inode, void * arg)
{
        struct hook_symlink_msg * msg = arg;
        return cache_space_hook_create(inode, msg->dentry);
}
static int lru_mkdir (struct inode * inode, void * arg)
{
        struct hook_msg * msg = arg;
        return cache_space_hook_mkdir(inode, msg->dentry);
}
static int lru_rmdir (struct inode * inode, void * arg)
{
        struct hook_unlink_msg * msg = arg;
        return cache_space_hook_rmdir(inode, msg->dentry);
}
static int lru_rename (struct inode * inode, void * arg)
{
        struct hook_rename_msg * msg = arg;
        return cache_space_hook_rename(inode, msg->dentry,
                                       msg->new_dir, msg->new_dentry);
}


typedef int (*post_lru_op)(struct inode *inode, void * msg);
static  post_lru_op smfs_lru_post[HOOK_MAX] = {
        [HOOK_CREATE]     lru_create,
        [HOOK_LOOKUP]     lru_lookup,
        [HOOK_LINK]       lru_link,
        [HOOK_UNLINK]     lru_unlink,
        [HOOK_SYMLINK]    lru_symlink,
        [HOOK_MKDIR]      lru_mkdir,
        [HOOK_RMDIR]      lru_rmdir,
        [HOOK_MKNOD]      lru_create,
        [HOOK_RENAME]     lru_rename,
        [HOOK_SETATTR]    NULL,
        [HOOK_WRITE]      NULL,
        [HOOK_READDIR]    NULL,
};

static int smfs_lru_pre_op(int op, struct inode *inode, void * msg, int ret, 
                           void *priv)
{
        int rc = 0;
        ENTRY;
        
        /* FIXME have not used op */
        check_cache_space();                                       
                                                                               
        RETURN(rc); 
}

static int smfs_lru_post_op(int op, struct inode *inode, void *msg, int ret,
                            void *priv)
{
        int rc = 0;
        
        ENTRY;
        if (ret)
                RETURN(0);
        
        if (smfs_lru_post[op])
                rc = smfs_lru_post[op](inode, msg);
        
        RETURN(rc);                                                             
}

/* Helpers */
static int smfs_exit_lru(struct super_block *sb, void * arg, void * priv)
{
        ENTRY;

        smfs_deregister_plugin(sb, SMFS_PLG_LRU);
                
        EXIT;
        return 0;
}

static int smfs_trans_lru (struct super_block *sb, void *arg, void * priv)
{
        int size;
        
        ENTRY;
        
        size = 20;//LDISKFS_INDEX_EXTRA_TRANS_BLOCKS+LDISKFS_DATA_TRANS_BLOCKS;
        
        RETURN(size);
}

static int smfs_start_lru(struct super_block *sb, void *arg, void * priv)
{
        int rc = 0;
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt *ctxt;
        
        ENTRY;
        
        if (SMFS_IS(smb->plg_flags, SMFS_PLG_LRU))
                RETURN(0);

        /* first to initialize the cache lru catalog on local fs */
        rc = llog_catalog_setup(&ctxt, CACHE_LRU_LOG, smb->smsi_exp,
                                smb->smsi_ctxt, smb->sm_fsfilt,
                                smb->smsi_logs_dir,
                                smb->smsi_objects_dir);
        if (rc) {
                CERROR("failed to initialize cache lru list catalog %d\n", rc);
                RETURN(rc);
        }
        cpq->cpq_sb = sb;
        cpq->cpq_loghandle = ctxt->loc_handle;

        /* start cache purge daemon, only one daemon now */
        init_waitqueue_head(&cpq->cpq_waitq);
        init_completion(&cpq->cpq_comp);
        cpq->cpq_flags = 0;

        rc = kernel_thread(cache_purge_thread, NULL, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                goto err_out;
        }
        wait_for_completion(&cpq->cpq_comp);

        SMFS_SET(smb->plg_flags, SMFS_PLG_LRU);

        RETURN(0);
err_out:
        llog_catalog_cleanup(ctxt);
        OBD_FREE(ctxt, sizeof(*ctxt));
        RETURN(rc);
}

static int smfs_stop_lru(struct super_block *sb, void *arg, void * priv)
{
        struct smfs_super_info * smb = S2SMI(sb);
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;
        
        if (!SMFS_IS(smb->plg_flags, SMFS_PLG_LRU))
                RETURN(0);

        SMFS_CLEAR(smb->plg_flags, SMFS_PLG_LRU);

        init_completion(&cpq->cpq_comp);
        cpq->cpq_flags = SVC_STOPPING;
        wake_up(&cpq->cpq_waitq);
        wait_for_completion(&cpq->cpq_comp);
        
        ctxt = cpq->cpq_loghandle->lgh_ctxt;
        rc = llog_catalog_cleanup(ctxt);
        OBD_FREE(ctxt, sizeof(*ctxt));
        RETURN(0);        
}

typedef int (*lru_helper)(struct super_block * sb, void *msg, void *);
static lru_helper smfs_lru_helpers[PLG_HELPER_MAX] = {
        [PLG_EXIT]       smfs_exit_lru,
        [PLG_START]      smfs_start_lru,
        [PLG_STOP]       smfs_stop_lru,
        [PLG_TRANS_SIZE] smfs_trans_lru,
        [PLG_TEST_INODE] NULL,
        [PLG_SET_INODE]  NULL,
};

static int smfs_lru_help_op(int code, struct super_block * sb,
                            void * arg, void * priv)
{
        ENTRY;
        if (smfs_lru_helpers[code])
                smfs_lru_helpers[code](sb, arg, priv);
        RETURN(0);
}

int smfs_init_lru(struct super_block *sb)
{
        struct smfs_plugin plg = {
                .plg_type = SMFS_PLG_LRU,
                .plg_pre_op = &smfs_lru_pre_op,
                .plg_post_op = &smfs_lru_post_op,
                .plg_helper = &smfs_lru_help_op,
                .plg_private = NULL
        };
        int rc = 0;
        
        ENTRY;

        rc = smfs_register_plugin(sb, &plg); 
        
        RETURN(rc);
}


