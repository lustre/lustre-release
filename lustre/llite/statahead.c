/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
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

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include <linux/lustre_version.h>
#include "llite_internal.h"

struct ll_sai_entry {
        struct list_head        se_list;
        unsigned int            se_index;
        int                     se_stat;
};

enum {
        SA_ENTRY_UNSTATED = 0,
        SA_ENTRY_STATED
};

static unsigned int sai_generation = 0;
static spinlock_t sai_generation_lock = SPIN_LOCK_UNLOCKED;

static struct ll_statahead_info *ll_sai_alloc(void)
{
        struct ll_statahead_info *sai;

        OBD_ALLOC_PTR(sai);
        if (!sai)
                return NULL;

        spin_lock(&sai_generation_lock);
        sai->sai_generation = ++sai_generation;
        if (unlikely(sai_generation == 0))
                sai->sai_generation = ++sai_generation;
        spin_unlock(&sai_generation_lock);
        atomic_set(&sai->sai_refcount, 1);
        sai->sai_max = LL_SA_RPC_MIN;
        cfs_waitq_init(&sai->sai_waitq);
        cfs_waitq_init(&sai->sai_thread.t_ctl_waitq);
        CFS_INIT_LIST_HEAD(&sai->sai_entries);
        return sai;
}

static inline 
struct ll_statahead_info *ll_sai_get(struct ll_statahead_info *sai)
{
        LASSERT(sai);
        atomic_inc(&sai->sai_refcount);
        return sai;
}

static void ll_sai_put(struct ll_statahead_info *sai)
{
        struct inode         *inode = sai->sai_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        if (atomic_dec_and_lock(&sai->sai_refcount, &lli->lli_lock)) {
                struct ll_sai_entry *entry, *next;

                lli->lli_sai = NULL;
                spin_unlock(&lli->lli_lock);

                LASSERT(sai->sai_thread.t_flags & SVC_STOPPED);

                if (sai->sai_sent > sai->sai_replied)
                        CDEBUG(D_READA,"statahead for dir %lu/%u does not "
                              "finish: [sent:%u] [replied:%u]\n",
                              inode->i_ino, inode->i_generation,
                              sai->sai_sent, sai->sai_replied);

                list_for_each_entry_safe(entry, next, &sai->sai_entries,
                                         se_list) {
                        list_del(&entry->se_list);
                        OBD_FREE_PTR(entry);
                }
                OBD_FREE_PTR(sai);
                iput(inode);
        }
        EXIT;
}

static struct ll_sai_entry *
ll_sai_entry_get(struct ll_statahead_info *sai, unsigned int index, int stat)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry  *entry;
        ENTRY;

        OBD_ALLOC_PTR(entry);
        if (entry == NULL)
                RETURN(ERR_PTR(-ENOMEM));
        
        CDEBUG(D_READA, "alloc sai entry %p index %u, stat %d\n",
               entry, index, stat);
        entry->se_index = index;
        entry->se_stat  = stat;

        spin_lock(&lli->lli_lock);
        list_add_tail(&entry->se_list, &sai->sai_entries);
        spin_unlock(&lli->lli_lock);

        RETURN(entry);
}

/*
 * inside lli_lock
 * return value:
 *  0: can not find the entry with the index
 *  1: it is the first entry
 *  2: it is not the first entry
 */
static int
ll_sai_entry_set(struct ll_statahead_info *sai, unsigned int index, int stat)
{
        struct ll_sai_entry *entry;
        int                  rc = 0;
        ENTRY;

        if (list_empty(&sai->sai_entries))
                RETURN(0);

        entry = list_entry(sai->sai_entries.next, struct ll_sai_entry, se_list);
        if (entry->se_index == index)
                GOTO(out, rc = 1);

        while (entry->se_list.next != &sai->sai_entries &&
               entry->se_index < index) {
                entry = list_entry(entry->se_list.next, struct ll_sai_entry,
                                   se_list);
                if (entry->se_index == index)
                        GOTO(out, rc = 2);
        }

        EXIT;

out:
        if (rc) {
                LASSERT(entry->se_stat == SA_ENTRY_UNSTATED);
                entry->se_stat = stat;
        }

        return rc;
}

/*
 * Check whether first entry was stated already or not.
 * No need to hold lli_lock, for:
 * (1) it is me that remove entry from the list
 * (2) the statahead thread only add new entry to the list tail
 */
static int ll_sai_entry_stated(struct ll_statahead_info *sai)
{
        struct ll_sai_entry  *entry;
        int                   rc = 0;
        ENTRY;

        if (!list_empty(&sai->sai_entries)) {
                entry = list_entry(sai->sai_entries.next, struct ll_sai_entry,
                                   se_list);
                rc = (entry->se_stat != SA_ENTRY_UNSTATED);
        }

        RETURN(rc);
}

static void ll_sai_entry_put(struct ll_statahead_info *sai)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry  *entry;
        ENTRY;
        
        spin_lock(&lli->lli_lock);
        if (!list_empty(&sai->sai_entries)) {
                entry = list_entry(sai->sai_entries.next,
                                   struct ll_sai_entry, se_list);
                list_del(&entry->se_list);
                OBD_FREE_PTR(entry);
        }
        spin_unlock(&lli->lli_lock);

        EXIT;
}

/* finish lookup/revalidate */
static int ll_statahead_interpret(struct obd_export *exp,
                                  struct ptlrpc_request *req,
                                  struct md_enqueue_info *minfo,
                                  int rc)
{
        struct lookup_intent     *it = &minfo->mi_it;
        struct dentry            *dentry = minfo->mi_dentry;
        struct inode             *dir = dentry->d_parent->d_inode;
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai = NULL;
        ENTRY;

        CDEBUG(D_READA, "interpret statahead %.*s rc %d\n",
               dentry->d_name.len, dentry->d_name.name, rc);

        spin_lock(&lli->lli_lock);
        if (unlikely(lli->lli_sai == NULL ||
            lli->lli_sai->sai_generation != minfo->mi_generation)) {
                spin_unlock(&lli->lli_lock);
                GOTO(out_free, rc = -ESTALE);
        } else {
                sai = ll_sai_get(lli->lli_sai);
                spin_unlock(&lli->lli_lock);
        }

        if (rc || dir == NULL)
                GOTO(out, rc);

        if (dentry->d_inode == NULL) {
                /* lookup */
                struct dentry    *save = dentry;
                struct it_cb_data icbd = {
                        .icbd_parent   = dir,
                        .icbd_childp   = &dentry
                };

                rc = lookup_it_finish(req, DLM_REPLY_REC_OFF, it, &icbd);
                if (!rc)
                        /* 
                         * Here dentry->d_inode might be NULL,
                         * because the entry may have been removed before
                         * we start doing stat ahead.
                         */
                        ll_lookup_finish_locks(it, dentry);

                if (dentry != save)
                        dput(save);
        } else {
                /* revalidate */
                struct mds_body *body;

                body = lustre_msg_buf(req->rq_repmsg, DLM_REPLY_REC_OFF,
                                      sizeof(*body));
                if (memcmp(&minfo->mi_data.fid2, &body->fid1,
                           sizeof(body->fid1))) {
                        ll_unhash_aliases(dentry->d_inode);
                        GOTO(out, rc = -EAGAIN);
                }

                rc = revalidate_it_finish(req, DLM_REPLY_REC_OFF, it, dentry);
                if (rc) {
                        ll_unhash_aliases(dentry->d_inode);
                        GOTO(out, rc);
                }

                spin_lock(&dcache_lock);
                lock_dentry(dentry);
                __d_drop(dentry);
#ifdef DCACHE_LUSTRE_INVALID
                dentry->d_flags &= ~DCACHE_LUSTRE_INVALID;
#endif
                unlock_dentry(dentry);
                d_rehash_cond(dentry, 0);
                spin_unlock(&dcache_lock);

                ll_lookup_finish_locks(it, dentry);
        }
        EXIT;

out:
        if (sai != NULL) {
                int first;

                sai->sai_replied++;
                spin_lock(&lli->lli_lock);
                first = ll_sai_entry_set(sai,
                                         (unsigned int)(long)minfo->mi_cbdata,
                                         SA_ENTRY_STATED);
                /*
                 * wake up the "ls -l" process only when the first entry
                 * returned.
                 */
                spin_unlock(&lli->lli_lock);
                if (first == 1)
                        cfs_waitq_signal(&sai->sai_waitq);
                else if (first == 0)
                        CDEBUG(D_READA, "can't find sai entry for dir "
                               "%lu/%u generation %u index %d\n",
                               dir->i_ino, dir->i_generation,
                               minfo->mi_generation,
                               (unsigned int)(long)minfo->mi_cbdata);

                ll_sai_put(sai);
        }
out_free:
        ll_intent_release(it);
        OBD_FREE_PTR(minfo);

        dput(dentry);
        return rc;
}

static void sa_args_fini(struct md_enqueue_info *minfo,
                         struct ldlm_enqueue_info *einfo)
{
        LASSERT(minfo && einfo);
        OBD_FREE_PTR(minfo);
        OBD_FREE_PTR(einfo);
}

static int sa_args_prep(struct inode *dir, struct dentry *dentry,
                        struct md_enqueue_info **pmi,
                        struct ldlm_enqueue_info **pei)
{
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct md_enqueue_info   *minfo;
        struct ldlm_enqueue_info *einfo;

        OBD_ALLOC_PTR(einfo);
        if (einfo == NULL)
                return -ENOMEM;

        OBD_ALLOC_PTR(minfo);
        if (minfo == NULL) {
                OBD_FREE_PTR(einfo);
                return -ENOMEM;
        }

        minfo->mi_exp = ll_i2mdcexp(dir);
        minfo->mi_it.it_op = IT_GETATTR;
        minfo->mi_dentry = dentry;
        minfo->mi_cb = ll_statahead_interpret;
        minfo->mi_generation = lli->lli_sai->sai_generation;
        minfo->mi_cbdata = (void *)(long)lli->lli_sai->sai_index;

        einfo->ei_type   = LDLM_IBITS;
        einfo->ei_mode   = it_to_lock_mode(&minfo->mi_it);
        einfo->ei_cb_bl  = ll_mdc_blocking_ast;
        einfo->ei_cb_cp  = ldlm_completion_ast;
        einfo->ei_cb_gl  = NULL;
        einfo->ei_cbdata = NULL;

        *pmi = minfo;
        *pei = einfo;

        return 0;
}

/* similar to ll_lookup_it(). */
static int do_sa_lookup(struct inode *dir, struct dentry *dentry)
{
        struct md_enqueue_info   *minfo;
        struct ldlm_enqueue_info *einfo;
        int                       rc;                
        ENTRY;

        rc = sa_args_prep(dir, dentry, &minfo, &einfo);
        if (rc)
                RETURN(rc);

        rc = ll_prepare_mdc_op_data(&minfo->mi_data, dir, NULL,
                                    dentry->d_name.name, dentry->d_name.len, 0,
                                    NULL);
        if (rc == 0)
                rc = mdc_intent_getattr_async(minfo->mi_exp, minfo, einfo);

        if (rc)
                sa_args_fini(minfo, einfo);

        RETURN(rc);
}

/* 
 * similar to ll_revalidate_it().
 * return value:
 *  1      -- dentry valid
 *  0      -- will send stat-ahead request
 *  others -- prepare stat-ahead request failed
 */
static int do_sa_revalidate(struct dentry *dentry)
{
        struct inode             *inode = dentry->d_inode;
        struct ll_fid             fid;
        struct lookup_intent      it = { .it_op = IT_GETATTR };
        struct md_enqueue_info   *minfo;
        struct ldlm_enqueue_info *einfo;
        int rc;
        ENTRY;

        if (inode == NULL)
                RETURN(1);

        if (d_mountpoint(dentry))
                RETURN(1);

        if (dentry == dentry->d_sb->s_root)
                RETURN(1);

        ll_inode2fid(&fid, inode);

        rc = mdc_revalidate_lock(ll_i2mdcexp(inode), &it, &fid);
        if (rc == 1) {
                ll_intent_release(&it);
                RETURN(1);
        }

        rc = sa_args_prep(dentry->d_parent->d_inode, dentry, &minfo, &einfo);
        if (rc)
                RETURN(rc);

        rc = ll_prepare_mdc_op_data(&minfo->mi_data, dentry->d_parent->d_inode,
                                    inode, dentry->d_name.name,
                                    dentry->d_name.len, 0, NULL);
        if (rc == 0)
                rc = mdc_intent_getattr_async(minfo->mi_exp, minfo, einfo);

        if (rc)
                sa_args_fini(minfo, einfo);

        RETURN(rc);
}

static inline void ll_name2qstr(struct qstr *this, const char *name, int namelen)
{
        unsigned long hash = init_name_hash();
        unsigned int  c;

        this->name = name;
        this->len  = namelen;
        for (; namelen > 0; namelen--, name++) {
                c = *(const unsigned char *)name;
                hash = partial_name_hash(c, hash);
        }
        this->hash = end_name_hash(hash);
}

static int ll_statahead_one(struct dentry *parent, struct ll_dir_entry *de)
{
        struct inode           *dir = parent->d_inode;
        struct ll_inode_info   *lli = ll_i2info(dir);
        struct qstr             name;
        struct dentry          *dentry;
        struct ll_sai_entry    *se;
        int                     rc;
        ENTRY;

#ifdef DCACHE_LUSTRE_INVALID
        if (parent->d_flags & DCACHE_LUSTRE_INVALID) {
#else
        if (d_unhashed(parent)) {
#endif
                CDEBUG(D_READA, "parent dentry@%p %.*s is "
                       "invalid, skip statahead\n",
                       parent, parent->d_name.len, parent->d_name.name);
                RETURN(-EINVAL);
        }

        se = ll_sai_entry_get(lli->lli_sai, lli->lli_sai->sai_index,
                              SA_ENTRY_UNSTATED);
        if (IS_ERR(se))
                RETURN(PTR_ERR(se));

        ll_name2qstr(&name, de->lde_name, de->lde_name_len);
        dentry = d_lookup(parent, &name);
        if (!dentry) {
                dentry = d_alloc(parent, &name);
                if (dentry) {
                        rc = do_sa_lookup(dir, dentry);
                        if (rc)
                                dput(dentry);
                } else {
                        GOTO(out, rc = -ENOMEM);
                }
        } else {
                rc = do_sa_revalidate(dentry);
                if (rc)
                        dput(dentry);
        }

        EXIT;

out:
        if (rc) {
                CDEBUG(D_READA, "set sai entry %p index %u stat %d rc %d\n",
                       se, se->se_index, se->se_stat, rc);
                se->se_stat = rc;
                cfs_waitq_signal(&lli->lli_sai->sai_waitq);
        } else {
                lli->lli_sai->sai_sent++;
        }

        lli->lli_sai->sai_index++;
        return rc;
}
                
static inline int sa_check_stop(struct ll_statahead_info *sai)
{
        return !!(sai->sai_thread.t_flags & SVC_STOPPING);
}

static inline int sa_not_full(struct ll_statahead_info *sai)
{
        return sai->sai_index < sai->sai_hit + sai->sai_miss + sai->sai_max;
}

/* (1) hit ratio less than 80%
 * or
 * (2) consecutive miss more than 8
 */
static inline int sa_low_hit(struct ll_statahead_info *sai)
{
        return ((sai->sai_hit < 4 * sai->sai_miss && sai->sai_hit > 7) ||
                (sai->sai_consecutive_miss > 8));
}

struct ll_sa_thread_args {
        struct dentry   *sta_parent;
        pid_t            sta_pid;
};

static int ll_statahead_thread(void *arg)
{
        struct ll_sa_thread_args *sta = arg;
        struct dentry            *parent = dget(sta->sta_parent);
        struct inode             *dir = parent->d_inode;
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_sb_info        *sbi = ll_i2sbi(dir);
        struct ll_statahead_info *sai = ll_sai_get(lli->lli_sai);
        struct ptlrpc_thread     *thread = &sai->sai_thread;
        unsigned long             index = 0;
        int                       first = 0;
        int                       rc = 0;
        char                      name[16] = "";
        ENTRY;

        sbi->ll_sa_total++;
        snprintf(name, 15, "ll_sa_%u", sta->sta_pid);
        cfs_daemonize(name);
        spin_lock(&lli->lli_lock);
        thread->t_flags = SVC_RUNNING;
        spin_unlock(&lli->lli_lock);
        cfs_waitq_signal(&thread->t_ctl_waitq);
        CDEBUG(D_READA, "start doing statahead for %s\n", parent->d_name.name);

        while (1) {
                struct l_wait_info lwi = { 0 };
                unsigned long npages;
                char *kaddr, *limit;
                struct ll_dir_entry *de;
                struct page *page;

                npages = dir_pages(dir);
                /* reach the end of dir */
                if (index >= npages) {
                        CDEBUG(D_READA, "reach end, index/npages %lu/%lu\n",
                               index, npages);
                        break;
                }

                page = ll_get_dir_page(dir, index);
                if (IS_ERR(page)) {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir %lu/%u page %lu/%u: rc %d\n",
                               dir->i_ino, dir->i_generation, index,
                               sai->sai_index, rc);
                        break;
                }

                kaddr = page_address(page);
                limit = kaddr + CFS_PAGE_SIZE - ll_dir_rec_len(1);
                de = (struct ll_dir_entry *)kaddr;
                if (!index) {
                        de = ll_dir_next_entry(de); /* skip "." */
                        de = ll_dir_next_entry(de); /* skip ".." */
                }

                for (; (char*)de <= limit; de = ll_dir_next_entry(de)) {
                        if (!de->lde_inode)
                                continue;

                        if (de->lde_name[0] == '.' && !sai->sai_ls_all) {
                                /* skip hidden files */
                                sai->sai_skip_hidden++;
                                continue;
                        }

                        /* don't stat-ahead first entry */
                        if (unlikely(!first)) {
                                first++;
                                continue;
                        }

                        l_wait_event(thread->t_ctl_waitq,
                                     sa_check_stop(sai) || sa_not_full(sai),
                                     &lwi);

                        if (unlikely(sa_check_stop(sai))) {
                                ll_put_page(page);
                                GOTO(out, rc);
                        }

                        rc = ll_statahead_one(parent, de);
                        if (rc < 0) {
                                ll_put_page(page);
                                GOTO(out, rc);
                        }
                }
                ll_put_page(page);
                index++;
        }
        EXIT;
out:
        spin_lock(&lli->lli_lock);
        thread->t_flags = SVC_STOPPED;
        spin_unlock(&lli->lli_lock);
        cfs_waitq_signal(&sai->sai_waitq);
        cfs_waitq_signal(&thread->t_ctl_waitq);
        ll_sai_put(sai);
        dput(parent);
        CDEBUG(D_READA, "statahead thread stopped, pid %d\n",
               cfs_curproc_pid());
        return rc;
}

/* called in ll_file_release() */
void ll_stop_statahead(struct inode *inode, void *key)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ptlrpc_thread *thread;

        spin_lock(&lli->lli_lock);
        if (lli->lli_opendir_pid == 0 ||
            unlikely(lli->lli_opendir_key != key)) {
                spin_unlock(&lli->lli_lock);
                return;
        }

        lli->lli_opendir_key = NULL;
        lli->lli_opendir_pid = 0;

        if (lli->lli_sai) {
                struct l_wait_info lwi = { 0 };

                thread = &lli->lli_sai->sai_thread;
                if (!(thread->t_flags & SVC_STOPPED)) {
                        thread->t_flags = SVC_STOPPING;
                        spin_unlock(&lli->lli_lock);
                        cfs_waitq_signal(&thread->t_ctl_waitq);

                        CDEBUG(D_READA, "stopping statahead thread, pid %d\n",
                               cfs_curproc_pid());
                        l_wait_event(thread->t_ctl_waitq,
                                     thread->t_flags & SVC_STOPPED,
                                     &lwi);
                } else {
                        spin_unlock(&lli->lli_lock);
                }

                /*
                 * Put the ref which was held when first statahead_enter.
                 * It maybe not the last ref for some statahead requests
                 * maybe inflight.
                 */
                ll_sai_put(lli->lli_sai);
                return;
        }
        spin_unlock(&lli->lli_lock);
}

enum {
        LS_NONE_FIRST_DE = 0,   /* not first dirent, or is "." */
        LS_FIRST_DE,            /* the first non-hidden dirent */
        LS_FIRST_DOT_DE         /* the first hidden dirent, that is ".xxx" */
};

static int is_first_dirent(struct inode *dir, struct dentry *dentry)
{
        struct qstr         *d_name = &dentry->d_name;
        unsigned long        npages, index = 0;
        struct page         *page;
        struct ll_dir_entry *de;
        char                *kaddr, *limit;
        int                  rc = LS_NONE_FIRST_DE, dot_de;
        ENTRY;

        while (1) {
                npages = dir_pages(dir);
                /* reach the end of dir */
                if (index >= npages) {
                        CDEBUG(D_READA, "reach end, index/npages %lu/%lu\n",
                               index, npages);
                        break;
                }

                page = ll_get_dir_page(dir, index);
                if (IS_ERR(page)) {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir %lu/%u page %lu: rc %d\n",
                               dir->i_ino, dir->i_generation, index, rc);
                        break;
                }

                kaddr = page_address(page);
                limit = kaddr + CFS_PAGE_SIZE - ll_dir_rec_len(1);
                de = (struct ll_dir_entry *)kaddr;
                if (!index) {
                        if (unlikely(!(de->lde_name_len == 1 &&
                                       strncmp(de->lde_name, ".", 1) == 0)))
                                CWARN("Maybe got bad on-disk dir: %lu\n",
                                      dir->i_ino);
                        /* skip "." or ingore bad entry */
                        de = ll_dir_next_entry(de);

                        if (unlikely(!(de->lde_name_len == 2 &&
                                       strncmp(de->lde_name, "..", 2) == 0)))
                                CWARN("Maybe got bad on-disk dir: %lu\n",
                                      dir->i_ino);
                        /* skip ".." or ingore bad entry */
                        de = ll_dir_next_entry(de);
                }

                for (; (char*)de <= limit; de = ll_dir_next_entry(de)) {
                        if (!de->lde_inode)
                                continue;

                        if (de->lde_name[0] == '.')
                                dot_de = 1;
                        else
                                dot_de = 0;

                        if (dot_de && d_name->name[0] != '.') {
                                CDEBUG(D_READA, "%.*s skip hidden file %.*s\n",
                                       d_name->len, d_name->name,
                                       de->lde_name_len, de->lde_name);
                                continue;
                        }

                        if (d_name->len == de->lde_name_len &&
                            !strncmp(d_name->name, de->lde_name, d_name->len))
                                rc = LS_FIRST_DE + dot_de;
                        else
                                rc = LS_NONE_FIRST_DE;
                        ll_put_page(page);
                        RETURN(rc);
                }
                ll_put_page(page);
                index++;
        }
        RETURN(rc);
}

/* Start statahead thread if this is the first dir entry.
 * Otherwise if a thread is started already, wait it until it is ahead of me.
 * Return value: 
 *  0       -- miss
 *  1       -- hit
 *  -EEXIST -- stat ahead thread started, and this is the first dentry
 *  -EBADFD -- statahead thread exit and not dentry available
 *  others  -- error
 */
int do_statahead_enter(struct inode *dir, struct dentry **dentryp, int lookup)
{
        struct ll_sb_info        *sbi = ll_i2sbi(dir);
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai = lli->lli_sai;
        struct ll_sa_thread_args  sta;
        struct l_wait_info        lwi = { 0 };
        int                       rc;
        ENTRY;

        LASSERT(lli->lli_opendir_pid == cfs_curproc_pid());

        if (sai) {
                if (unlikely(sai->sai_thread.t_flags & SVC_STOPPED &&
                             list_empty(&sai->sai_entries)))
                        RETURN(-EBADFD);

                if ((*dentryp)->d_name.name[0] == '.') {
                        if (likely(sai->sai_ls_all ||
                            sai->sai_miss_hidden >= sai->sai_skip_hidden)) {
                                /*
                                 * Hidden dentry is the first one, or statahead
                                 * thread does not skip so many hidden dentries
                                 * before "sai_ls_all" enabled as below.
                                 */
                        } else {
                                if (!sai->sai_ls_all)
                                        /*
                                         * It maybe because hidden dentry is not
                                         * the first one, "sai_ls_all" was not
                                         * set, then "ls -al" missed. Enable
                                         * "sai_ls_all" for such case.
                                         */
                                        sai->sai_ls_all = 1;

                                /*
                                 * Such "getattr" has been skipped before
                                 * "sai_ls_all" enabled as above.
                                 */
                                sai->sai_miss_hidden++;
                                RETURN(-ENOENT);
                        }
                }

                if (ll_sai_entry_stated(sai)) {
                        sbi->ll_sa_cached++;
                } else {
                        sbi->ll_sa_blocked++;
                        /* thread started already, avoid double-stat */
                        l_wait_event(sai->sai_waitq,
                                     ll_sai_entry_stated(sai) ||
                                     sai->sai_thread.t_flags & SVC_STOPPED,
                                     &lwi);
                }

                if (lookup) {
                        struct dentry *result;

                        result = d_lookup((*dentryp)->d_parent,
                                          &(*dentryp)->d_name);
                        if (result) {
                                LASSERT(result != *dentryp);
                                dput(*dentryp);
                                *dentryp = result;
                                RETURN(1);
                        }
                }
                /* do nothing for revalidate */
                RETURN(0);
        }

         /* I am the "lli_opendir_pid" owner, only me can set "lli_sai". */ 
        LASSERT(lli->lli_sai == NULL);

        rc = is_first_dirent(dir, *dentryp);
        if (rc == LS_NONE_FIRST_DE) {
                /* It is not "ls -{a}l" operation, no need statahead for it */
                spin_lock(&lli->lli_lock);
                lli->lli_opendir_key = NULL;
                lli->lli_opendir_pid = 0;
                spin_unlock(&lli->lli_lock);
                RETURN(-EBADF);
        }

        sai = ll_sai_alloc();
        if (sai == NULL)
                RETURN(-ENOMEM);
        
        sai->sai_inode  = igrab(dir);
        sai->sai_ls_all = (rc == LS_FIRST_DOT_DE);

        sta.sta_parent = (*dentryp)->d_parent;
        sta.sta_pid    = cfs_curproc_pid();

        lli->lli_sai = sai;
        rc = cfs_kernel_thread(ll_statahead_thread, &sta, 0);
        if (rc < 0) {
                CERROR("can't start ll_sa thread, rc: %d\n", rc);
                sai->sai_thread.t_flags = SVC_STOPPED;
                ll_sai_put(sai);
                LASSERT(lli->lli_sai == NULL);
                RETURN(rc);
        }

        l_wait_event(sai->sai_thread.t_ctl_waitq, 
                     sai->sai_thread.t_flags & (SVC_RUNNING | SVC_STOPPED),
                     &lwi);

        /*
         * We don't stat-ahead for the first dirent since we are already in
         * lookup, and -EEXIST also indicates that this is the first dirent.
         */
        RETURN(-EEXIST);
}

/* update hit/miss count */
void ll_statahead_exit(struct dentry *dentry, int result)
{
        struct dentry         *parent = dentry->d_parent;
        struct ll_inode_info  *lli = ll_i2info(parent->d_inode);
        struct ll_sb_info     *sbi = ll_i2sbi(parent->d_inode);
        struct ll_dentry_data *ldd = ll_d2d(dentry);

        if (lli->lli_opendir_pid != cfs_curproc_pid())
                return;

        if (lli->lli_sai) {
                struct ll_statahead_info *sai = lli->lli_sai;

                if (result == 1) {
                        sbi->ll_sa_hit++;
                        sai->sai_hit++;
                        sai->sai_consecutive_miss = 0;
                        sai->sai_max = min(2 * sai->sai_max, sbi->ll_sa_max);
                } else {
                        sbi->ll_sa_miss++;
                        sai->sai_miss++;
                        sai->sai_consecutive_miss++;
                        if (sa_low_hit(sai) &&
                            sai->sai_thread.t_flags & SVC_RUNNING) {
                                sbi->ll_sa_wrong++;
                                CDEBUG(D_READA, "statahead for dir %.*s hit "
                                       "ratio too low: hit/miss %u/%u, "
                                       "sent/replied %u/%u. stopping statahead "
                                       "thread: pid %d\n",
                                       parent->d_name.len, parent->d_name.name,
                                       sai->sai_hit, sai->sai_miss,
                                       sai->sai_sent, sai->sai_replied,
                                       cfs_curproc_pid());
                                spin_lock(&lli->lli_lock);
                                if (!(sai->sai_thread.t_flags & SVC_STOPPED))
                                        sai->sai_thread.t_flags = SVC_STOPPING;
                                spin_unlock(&lli->lli_lock);
                        }
                }

                cfs_waitq_signal(&sai->sai_thread.t_ctl_waitq);
                ll_sai_entry_put(sai);

                if (likely(ldd != NULL))
                        ldd->lld_sa_generation = sai->sai_generation;
        }
}
