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
        int nfract;     /* Percentage of cache dirty to activate cpurge */
        int ndirty;     /* Maximum number of objects to write out per
                           wake-cycle */
        int interval;   /* jiffies delay between cache purge */
        int nfract_sync;/* Percentage of cache dirty to activate
                           cpurge synchronously */
        int nfract_stop_cpurge; /* Percentage of cache dirty to stop cpurge */
} cf_prm = {30, 512, 600 * HZ, 60, 20};

static struct cache_purge_queue smfs_cpq;
static struct cache_purge_queue *cpq = &smfs_cpq;

#define CACHE_HOOK "cache_hook"
int cache_space_pre_hook(struct inode *inode, struct dentry *dentry,
                         void *data1, void *data2, int op, void *handle)
{
        int rc = 0;
        ENTRY;

        if (smfs_cache_hook(inode)) {                                          
               if (!handle) {                                                  
                        handle = smfs_trans_start(inode, KML_CACHE_NOOP, NULL);   
                        if (IS_ERR(handle)) {                                   
                                RETURN(PTR_ERR(handle));
                        }                                                       
                }                                                               
                cache_space_pre(inode, op);                                       
        }                                                                       
        RETURN(rc); 
}

int cache_space_post_hook(struct inode *inode, struct dentry *dentry,
                         void *data1, void *data2, int op, void *handle)
{
        int rc = 0;
        ENTRY;
        if (smfs_cache_hook(inode)) {      
                struct inode *new_inode = (struct inode*)data1;
                struct dentry *new_dentry = (struct dentry*)data2;                    
                LASSERT(handle != NULL);                                
                rc = cache_space_post(op, handle, inode, dentry, new_inode, 
                                      new_dentry);
        }
        RETURN(rc);                                                               
}

int cache_space_hook_init(struct super_block *sb)
{
        struct smfs_super_info  *smfs_info = S2SMI(sb);
        struct smfs_hook_ops    *cache_hops;
        int    rc = 0;
        ENTRY;

        cache_hops = smfs_alloc_hook_ops(CACHE_HOOK, cache_space_pre_hook, 
                                         cache_space_post_hook);
        if (!cache_hops) {
                RETURN(-ENOMEM);
        }
        rc = smfs_register_hook_ops(sb, cache_hops);      
        if (rc) {
                smfs_free_hook_ops(cache_hops);
                RETURN(rc);
        }
        SMFS_SET_CACHE_HOOK(smfs_info);

        RETURN(0);
}

int cache_space_hook_exit(struct super_block *sb)
{
        struct smfs_super_info  *smfs_info = S2SMI(sb);
        struct smfs_hook_ops *cache_hops; 

        cache_hops = smfs_unregister_hook_ops(sb, CACHE_HOOK);
        smfs_free_hook_ops(cache_hops);

        SMFS_CLEAN_CACHE_HOOK(smfs_info);
        return 0;
}

static int cache_leaf_node(struct dentry *dentry, __u64 *active_entry)
{
        struct inode *inode = dentry->d_inode;

        if (S_ISDIR(inode->i_mode)) {
                if (inode->i_nlink != 2)
                        return 0;
                if (!strncmp(dentry->d_name.name, "lost+found", dentry->d_name.len))
                        return 0;
                LASSERT(active_entry != NULL);
                get_active_entry(inode, active_entry);
                return(*active_entry > 0 ? 0 : 1);
        } else {
                if (inode->i_nlink != 1)
                        return 0;
                if (!strncmp(dentry->d_name.name, KML_LOG_NAME, dentry->d_name.len) ||
                    !strncmp(dentry->d_name.name, CACHE_LRU_LOG, dentry->d_name.len))
                        return 0;
                return 1;
        }
}
static int cache_pre_leaf_node(struct dentry *dentry, __u64 *active_entry, int op)
{
        if (((op == 0 && dentry->d_inode->i_nlink == 0) ||
            (op == 1 && dentry->d_inode->i_nlink == 2)) &&
            strncmp(dentry->d_name.name, KML_LOG_NAME, dentry->d_name.len) &&
            strncmp(dentry->d_name.name, CACHE_LRU_LOG, dentry->d_name.len))
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
        rc = fsops->fs_set_xattr(inode, handle, XATTR_SMFS_CACHE_LOGCOOKIE,
                                 logcookie, sizeof(*logcookie));
        RETURN(rc);
}
static int get_lru_logcookie(struct inode *inode, struct llog_cookie *logcookie)
{
        struct fsfilt_operations *fsops = I2CSB(inode)->sm_fsfilt;
        int rc;
        rc = fsops->fs_get_xattr(inode, XATTR_SMFS_CACHE_LOGCOOKIE,
                                 logcookie, sizeof(*logcookie));
        RETURN(rc);
}

static int try2purge_from_cache(struct ll_fid cfid, struct ll_fid pfid)
{
        struct inode *inode, *parent;
        struct super_block *sb = cpq->cpq_sb;
        //struct llog_cookie logcookie;
        __u32 hoard_priority = 0;
        int rc = 0;
        ENTRY;

        inode = iget(sb, cfid.id);
        if (IS_ERR(inode)) {
                CERROR("not existent inode: "LPX64"/%u\n",
                       cfid.id, cfid.generation);
                RETURN(-ENOENT);
        }
        parent = iget(sb, pfid.id);
        if (IS_ERR(parent)) {
                CERROR("not existent inode: "LPX64"/%u\n",
                       pfid.id, pfid.generation);
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

        if (try2purge_from_cache(llr->llr_cfid, llr->llr_pfid)==1){
                CDEBUG(D_INODE, "purge ino/gen "LPX64"/%u from cache\n",
                       llr->llr_cfid.id, llr->llr_cfid.generation);
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

        if (state < 0)
                return;

        wakeup_cpurge();

        if (state > 0) {
                int count = CFLUSH_NR;
                purge_some_cache(&count);
        }
}

void cache_space_pre(struct inode *inode, int op)
{
        ENTRY;

        /* FIXME have not used op */
        check_cache_space();
}

static int cache_space_hook_lru(struct inode *inode, struct inode *parent,
                     void *handle, int op, int flags)
{
        struct fsfilt_operations *fsops = S2SMI(cpq->cpq_sb)->sm_fsfilt;
        struct llog_ctxt *ctxt = cpq->cpq_loghandle->lgh_ctxt;
        struct llog_lru_rec *llr = NULL;
        struct llog_cookie *logcookie = NULL;
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
                        GOTO(out, rc);

                if (logcookie->lgc_lgl.lgl_oid == 0) {
                        CWARN("inode %lu/%u is not in lru list\n",
                              inode->i_ino, inode->i_generation);
                        GOTO(insert, rc = -ENOENT);
                }
                if (flags && llog_cat_half_bottom(logcookie, ctxt->loc_handle))
                        GOTO(out, rc = 0);

                rc = llog_cancel(ctxt, 1, logcookie, 0, NULL);
                if (!rc) {
                        memset(logcookie, 0, cookie_size);
                        rc = set_lru_logcookie(inode, handle, logcookie);
                        if (rc)
                                GOTO(out, rc);
                } else {
                        CERROR("failed at llog_cancel: %d\n", rc);
                        GOTO(out, rc);
                }
        }

insert:
        if (op & CACHE_SPACE_INSERT) {
                LASSERT(parent != NULL);
                OBD_ALLOC(llr, sizeof(*llr));
                if (llr == NULL)
                        GOTO(out, rc = -ENOMEM);

                llr->llr_hdr.lrh_len = llr->llr_tail.lrt_len = sizeof(*llr);
                llr->llr_hdr.lrh_type = CACHE_LRU_REC;
                llr->llr_cfid.id = inode->i_ino;
                llr->llr_cfid.generation = inode->i_generation;
                llr->llr_cfid.f_type = inode->i_mode & S_IFMT;
                llr->llr_pfid.id = parent->i_ino;
                llr->llr_pfid.generation = parent->i_generation;
                llr->llr_pfid.f_type = parent->i_mode & S_IFMT;

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
        return 0;
}

int cache_space_hook_setup(struct super_block *sb)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        /* first to initialize the cache lru catalog on local fs */
        rc = llog_catalog_setup(&ctxt, CACHE_LRU_LOG,
                                S2SMI(sb)->smsi_exp,
                                S2SMI(sb)->smsi_ctxt,
                                S2SMI(sb)->sm_fsfilt,
                                S2SMI(sb)->smsi_logs_dir,
                                S2SMI(sb)->smsi_objects_dir);
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
                GOTO(err_out, rc);
        }
        wait_for_completion(&cpq->cpq_comp);

        RETURN(0);
err_out:
        llog_catalog_cleanup(ctxt);
        OBD_FREE(ctxt, sizeof(*ctxt));
        RETURN(rc);
}

int cache_space_hook_cleanup(void)
{
        struct llog_ctxt *ctxt;
        int rc;
        ENTRY;

        init_completion(&cpq->cpq_comp);
        cpq->cpq_flags = SVC_STOPPING;
        wake_up(&cpq->cpq_waitq);
        wait_for_completion(&cpq->cpq_comp);
        
        ctxt = cpq->cpq_loghandle->lgh_ctxt;
        rc = llog_catalog_cleanup(ctxt);
        OBD_FREE(ctxt, sizeof(*ctxt));
        if (rc)
                CERROR("failed to clean up cache lru list catalog %d\n", rc);

        RETURN(rc);
}

static int cache_space_hook_create(void *handle, struct inode *dir,
                                   struct dentry *dentry, struct inode *new_dir,
                                   struct dentry *new_dentry)
{
        __u64 active_entry = 0;
        int rc;

        LASSERT(cache_leaf_node(dentry, NULL));
        rc = cache_space_hook_lru(dentry->d_inode, dir, handle,
                                  CACHE_SPACE_INSERT, 0);
        if (rc)
                RETURN(rc);
        if (cache_leaf_node(dentry->d_parent, &active_entry)) {
                rc = cache_space_hook_lru(dir,NULL,handle,CACHE_SPACE_DELETE,0);
                if (rc)
                        RETURN(rc);
        }
        if (!active_entry)
                rc = get_active_entry(dir, &active_entry);
        active_entry ++;
        if (!rc)
                rc = set_active_entry(dir, &active_entry, handle);
        RETURN(rc);
}
static int cache_space_hook_lookup(void *handle, struct inode *dir,
                                   struct dentry *dentry, struct inode *new_dir,
                                   struct dentry *new_dentry)
{
        __u64 active_entry;
        int rc = 0;

        if (cache_leaf_node(dentry, &active_entry))
                rc = cache_space_hook_lru(dentry->d_inode, dir, handle,
                                CACHE_SPACE_DELETE | CACHE_SPACE_INSERT,1);
        RETURN(rc);
}
static int cache_space_hook_link(void *handle, struct inode *dir,
                                 struct dentry *dentry, struct inode *new_dir,
                                 struct dentry *new_dentry)
{
        __u64 active_entry = 0;
        int rc = 0;

        if (cache_pre_leaf_node(dentry, NULL, 1)) {
                rc = cache_space_hook_lru(dentry->d_inode, NULL,
                                          handle, CACHE_SPACE_DELETE, 0);
                if (rc)
                        RETURN(rc);
        }

        if (cache_leaf_node(dentry->d_parent, &active_entry)) {
                rc = cache_space_hook_lru(dir,NULL,handle,CACHE_SPACE_DELETE,0);
                if (rc)
                        RETURN(rc);
        }

        if (!active_entry)
                rc = get_active_entry(dir, &active_entry);
        active_entry ++;
        if (!rc)
                rc = set_active_entry(dir, &active_entry, handle);
        RETURN(rc);
}
static int cache_space_hook_unlink(void *handle, struct inode *dir,
                                   struct dentry *dentry, struct inode *new_dir,
                                   struct dentry *new_dentry)
{
        __u64 active_entry;
        int rc = 0;

        if (cache_pre_leaf_node(dentry, NULL, 0))
                rc = cache_space_hook_lru(dentry->d_inode, NULL,
                                          handle, CACHE_SPACE_DELETE, 0);
        else if (cache_leaf_node(dentry, NULL))
                        rc = cache_space_hook_lru(dentry->d_inode, dir,
                                                  handle, CACHE_SPACE_INSERT,0);
        if (rc)
                RETURN(rc);

        rc = get_active_entry(dir, &active_entry);
        active_entry --;
        if (!rc)
                rc = set_active_entry(dir, &active_entry, handle);
        if (!rc && cache_leaf_node(dentry->d_parent, &active_entry))
                rc = cache_space_hook_lru(dir,
                                          dentry->d_parent->d_parent->d_inode,
                                          handle, CACHE_SPACE_INSERT, 0);
        RETURN(rc);
}
static int cache_space_hook_mkdir(void *handle, struct inode *dir,
                                  struct dentry *dentry, struct inode *new_dir,
                                  struct dentry *new_dentry)
{
        __u64 active_entry;
        int rc;

        LASSERT(cache_leaf_node(dentry, &active_entry));
        rc = cache_space_hook_lru(dentry->d_inode, dir, handle,
                                  CACHE_SPACE_INSERT,0);

        if (!rc && cache_pre_leaf_node(dentry->d_parent, &active_entry, 3))
                rc = cache_space_hook_lru(dir,NULL,handle,CACHE_SPACE_DELETE,0);
        RETURN(rc);
}
static int cache_space_hook_rmdir(void *handle, struct inode *dir,
                                  struct dentry *dentry, struct inode *new_dir,
                                  struct dentry *new_dentry)
{
        __u64 active_entry;
        int rc;

        LASSERT(cache_pre_leaf_node(dentry, &active_entry, 2));
        rc = cache_space_hook_lru(dentry->d_inode, NULL, handle,
                                  CACHE_SPACE_DELETE, 0);

        if (!rc && cache_leaf_node(dentry->d_parent, &active_entry))
                rc = cache_space_hook_lru(dir,
                                          dentry->d_parent->d_parent->d_inode,
                                          handle, CACHE_SPACE_INSERT, 0);
        RETURN(rc);
}
static int cache_space_hook_rename(void *handle, struct inode *old_dir,
                        struct dentry *old_dentry, struct inode *new_dir,
                        struct dentry *new_dentry)
{
        __u64 active_entry;
        int rc = 0;

        if (new_dentry->d_inode) {
                if (cache_pre_leaf_node(new_dentry, NULL, 0))
                        rc = cache_space_hook_lru(new_dentry->d_inode, NULL,
                                                  handle, CACHE_SPACE_DELETE,0);
                else if (cache_leaf_node(new_dentry, NULL))
                        rc = cache_space_hook_lru(new_dentry->d_inode,
                                                  new_dir, handle,
                                                  CACHE_SPACE_INSERT,0);
        }

        if (rc || old_dir == new_dir)
                RETURN(rc);

        if (!S_ISDIR(old_dentry->d_inode->i_mode)) {
                if (cache_leaf_node(new_dentry->d_parent, &active_entry)) {
                        rc = cache_space_hook_lru(new_dir, NULL, handle,
                                                  CACHE_SPACE_DELETE, 0);
                        if (rc)
                                RETURN(rc);
                }
                if (!active_entry)
                        rc = get_active_entry(new_dir, &active_entry);
                active_entry ++;
                if (!rc)
                        rc = set_active_entry(new_dir, &active_entry, handle);
                if (rc)
                        RETURN(rc);
                rc = get_active_entry(old_dir, &active_entry);
                active_entry --;
                if (!rc)
                        rc = set_active_entry(old_dir, &active_entry, handle);
        } else if (cache_pre_leaf_node(new_dentry->d_parent, &active_entry, 3))
                rc = cache_space_hook_lru(new_dir, NULL, handle,
                                          CACHE_SPACE_DELETE, 0);

        if (!rc && cache_leaf_node(old_dentry->d_parent, &active_entry))
                rc = cache_space_hook_lru(old_dir,
                                        old_dentry->d_parent->d_parent->d_inode,
                                        handle, CACHE_SPACE_INSERT, 0);
        RETURN(rc);
}

typedef int (*cache_hook_op)(void *handle, struct inode *old_dir,
                             struct dentry *old_dentry, struct inode *new_dir,
                             struct dentry *new_dentry);

static  cache_hook_op cache_space_hook_ops[HOOK_MAX + 1] = {
        [HOOK_CREATE]     cache_space_hook_create,
        [HOOK_LOOKUP]     cache_space_hook_lookup,
        [HOOK_LINK]       cache_space_hook_link,
        [HOOK_UNLINK]     cache_space_hook_unlink,
        [HOOK_SYMLINK]    cache_space_hook_create,
        [HOOK_MKDIR]      cache_space_hook_mkdir,
        [HOOK_RMDIR]      cache_space_hook_rmdir,
        [HOOK_MKNOD]      cache_space_hook_create,
        [HOOK_RENAME]     cache_space_hook_rename,
        [HOOK_SETATTR]    NULL,
        [HOOK_WRITE]      NULL,
};

int cache_space_post(int op, void *handle, struct inode *old_dir,
               struct dentry *old_dentry, struct inode *new_dir,
               struct dentry *new_dentry)
{
        int rc = 0;
        ENTRY;

        LASSERT(op <= HOOK_MAX + 1);

        if (cache_space_hook_ops[op]) 
                rc = cache_space_hook_ops[op](handle, old_dir, old_dentry,
                                              new_dir, new_dentry);
        RETURN(rc);
}
