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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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
        struct ptlrpc_request  *se_req;
        struct md_enqueue_info *se_minfo;
};

enum {
        SA_ENTRY_UNSTATED = 0,
        SA_ENTRY_STATED
};

static unsigned int sai_generation = 0;
static spinlock_t sai_generation_lock = SPIN_LOCK_UNLOCKED;

/**
 * Check whether first entry was stated already or not.
 * No need to hold lli_lock, for:
 * (1) it is me that remove entry from the list
 * (2) the statahead thread only add new entry to the list
 */
static int ll_sai_entry_stated(struct ll_statahead_info *sai)
{
        struct ll_sai_entry  *entry;
        int                   rc = 0;

        if (!list_empty(&sai->sai_entries_stated)) {
                entry = list_entry(sai->sai_entries_stated.next,
                                   struct ll_sai_entry, se_list);
                if (entry->se_index == sai->sai_index_next)
                        rc = 1;
        }
        return rc;
}

static inline int sa_received_empty(struct ll_statahead_info *sai)
{
        return list_empty(&sai->sai_entries_received);
}

static inline int sa_not_full(struct ll_statahead_info *sai)
{
        return (sai->sai_index < sai->sai_hit + sai->sai_miss + sai->sai_max);
}

static inline int sa_is_running(struct ll_statahead_info *sai)
{
        return !!(sai->sai_thread.t_flags & SVC_RUNNING);
}

static inline int sa_is_stopping(struct ll_statahead_info *sai)
{
        return !!(sai->sai_thread.t_flags & SVC_STOPPING);
}

static inline int sa_is_stopped(struct ll_statahead_info *sai)
{
        return !!(sai->sai_thread.t_flags & SVC_STOPPED);
}

/**
 * (1) hit ratio less than 80%
 * or
 * (2) consecutive miss more than 8
 */
static inline int sa_low_hit(struct ll_statahead_info *sai)
{
        return ((sai->sai_hit > 7 && sai->sai_hit < 4 * sai->sai_miss) ||
                (sai->sai_consecutive_miss > 8));
}

/**
 * process the deleted entry's member and free the entry.
 * (1) release intent
 * (2) free md_enqueue_info
 * (3) drop dentry's ref count
 * (4) release request's ref count
 */
static void ll_sai_entry_cleanup(struct ll_sai_entry *entry, int free)
{
        struct md_enqueue_info *minfo = entry->se_minfo;
        struct ptlrpc_request  *req = entry->se_req;
        ENTRY;

        if (minfo) {
                entry->se_minfo = NULL;
                ll_intent_release(&minfo->mi_it);
                dput(minfo->mi_dentry);
                iput(minfo->mi_dir);
                OBD_FREE_PTR(minfo);
        }
        if (req) {
                entry->se_req = NULL;
                ptlrpc_req_finished(req);
        }
        if (free) {
                LASSERT(list_empty(&entry->se_list));
                OBD_FREE_PTR(entry);
        }

        EXIT;
}

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
        CFS_INIT_LIST_HEAD(&sai->sai_entries_sent);
        CFS_INIT_LIST_HEAD(&sai->sai_entries_received);
        CFS_INIT_LIST_HEAD(&sai->sai_entries_stated);
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
        struct ll_inode_info *lli;
        ENTRY;

        LASSERT(inode != NULL);
        lli = ll_i2info(inode);
        LASSERT(lli->lli_sai == sai);

        if (atomic_dec_and_test(&sai->sai_refcount)) {
                struct ll_sai_entry *entry, *next;

                spin_lock(&lli->lli_lock);
                if (unlikely(atomic_read(&sai->sai_refcount) > 0)) {
                        /* It is race case, the interpret callback just hold
                         * a reference count */
                        spin_unlock(&lli->lli_lock);
                        EXIT;
                        return;
                }

                LASSERT(lli->lli_opendir_key == NULL);
                lli->lli_sai = NULL;
                lli->lli_opendir_pid = 0;
                spin_unlock(&lli->lli_lock);

                LASSERT(sa_is_stopped(sai));

                if (sai->sai_sent > sai->sai_replied)
                        CDEBUG(D_READA,"statahead for dir %lu/%u does not "
                              "finish: [sent:%u] [replied:%u]\n",
                              inode->i_ino, inode->i_generation,
                              sai->sai_sent, sai->sai_replied);

                list_for_each_entry_safe(entry, next, &sai->sai_entries_sent,
                                         se_list) {
                        list_del_init(&entry->se_list);
                        ll_sai_entry_cleanup(entry, 1);
                }
                list_for_each_entry_safe(entry, next, &sai->sai_entries_received,
                                         se_list) {
                        list_del_init(&entry->se_list);
                        ll_sai_entry_cleanup(entry, 1);
                }
                list_for_each_entry_safe(entry, next, &sai->sai_entries_stated,
                                         se_list) {
                        list_del_init(&entry->se_list);
                        ll_sai_entry_cleanup(entry, 1);
                }
                iput(inode);
                OBD_FREE_PTR(sai);
        }
        EXIT;
}

/**
 * insert it into sai_entries_sent tail when init.
 */
static struct ll_sai_entry *
ll_sai_entry_init(struct ll_statahead_info *sai, unsigned int index)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry  *entry;
        ENTRY;

        OBD_ALLOC_PTR(entry);
        if (entry == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        CDEBUG(D_READA, "alloc sai entry %p index %u\n",
               entry, index);
        entry->se_index = index;
        entry->se_stat  = SA_ENTRY_UNSTATED;

        spin_lock(&lli->lli_lock);
        list_add_tail(&entry->se_list, &sai->sai_entries_sent);
        spin_unlock(&lli->lli_lock);

        RETURN(entry);
}

/**
 * delete it from sai_entries_stated head when fini, it need not
 * to process entry's member.
 */
static void ll_sai_entry_fini(struct ll_statahead_info *sai)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry  *entry;
        ENTRY;

        spin_lock(&lli->lli_lock);
        sai->sai_index_next++;
        if (likely(!list_empty(&sai->sai_entries_stated))) {
                entry = list_entry(sai->sai_entries_stated.next,
                                   struct ll_sai_entry, se_list);
                if (entry->se_index < sai->sai_index_next) {
                        list_del(&entry->se_list);
                        OBD_FREE_PTR(entry);
                }
        } else
                LASSERT(sa_is_stopped(sai));
        spin_unlock(&lli->lli_lock);

        EXIT;
}

/**
 * inside lli_lock.
 * \retval NULL : can not find the entry in sai_entries_sent with the index
 * \retval entry: find the entry in sai_entries_sent with the index
 */
static struct ll_sai_entry *
ll_sai_entry_set(struct ll_statahead_info *sai, unsigned int index, int stat,
                 struct ptlrpc_request *req, struct md_enqueue_info *minfo)
{
        struct ll_sai_entry *entry;
        ENTRY;

        if (!list_empty(&sai->sai_entries_sent)) {
                list_for_each_entry(entry, &sai->sai_entries_sent, se_list) {
                        if (entry->se_index == index) {
                                entry->se_stat = stat;
                                entry->se_req = ptlrpc_request_addref(req);
                                entry->se_minfo = minfo;
                                RETURN(entry);
                        } else if (entry->se_index > index)
                                RETURN(NULL);
                }
        }
        RETURN(NULL);
}

/**
 * inside lli_lock.
 * Move entry to sai_entries_received and
 * insert it into sai_entries_received tail.
 */
static inline void
ll_sai_entry_to_received(struct ll_statahead_info *sai, struct ll_sai_entry *entry)
{
        if (!list_empty(&entry->se_list))
                list_del_init(&entry->se_list);
        list_add_tail(&entry->se_list, &sai->sai_entries_received);
}

/**
 * Move entry to sai_entries_stated and
 * sort with the index.
 */
static int
ll_sai_entry_to_stated(struct ll_statahead_info *sai, struct ll_sai_entry *entry)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry  *se;
        ENTRY;

        ll_sai_entry_cleanup(entry, 0);

        spin_lock(&lli->lli_lock);
        if (!list_empty(&entry->se_list))
                list_del_init(&entry->se_list);

        if (unlikely(entry->se_index < sai->sai_index_next)) {
                spin_unlock(&lli->lli_lock);
                OBD_FREE_PTR(entry);
                RETURN(0);
        }

        list_for_each_entry_reverse(se, &sai->sai_entries_stated, se_list) {
                if (se->se_index < entry->se_index) {
                        list_add(&entry->se_list, &se->se_list);
                        spin_unlock(&lli->lli_lock);
                        RETURN(1);
                }
        }

        /*
         * I am the first entry.
         */
        list_add(&entry->se_list, &sai->sai_entries_stated);
        spin_unlock(&lli->lli_lock);
        RETURN(1);
}

/**
 * finish lookup/revalidate.
 */
static int do_statahead_interpret(struct ll_statahead_info *sai)
{
        struct ll_inode_info   *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry    *entry;
        struct ptlrpc_request  *req;
        struct md_enqueue_info *minfo;
        struct lookup_intent   *it;
        struct dentry          *dentry;
        int                     rc = 0;
        ENTRY;

        spin_lock(&lli->lli_lock);
        LASSERT(!sa_received_empty(sai));
        entry = list_entry(sai->sai_entries_received.next, struct ll_sai_entry,
                           se_list);
        list_del_init(&entry->se_list);
        spin_unlock(&lli->lli_lock);

        if (unlikely(entry->se_index < sai->sai_index_next)) {
                CWARN("Found stale entry: [index %u] [next %u]\n",
                      entry->se_index, sai->sai_index_next);
                ll_sai_entry_cleanup(entry, 1);
                RETURN(0);
        }

        if (entry->se_stat != SA_ENTRY_STATED)
                GOTO(out, rc = entry->se_stat);

        req = entry->se_req;
        minfo = entry->se_minfo;
        it = &minfo->mi_it;
        dentry = minfo->mi_dentry;

        if (dentry->d_inode == NULL) {
                /*
                 * lookup.
                 */
                struct dentry    *save = dentry;
                struct it_cb_data icbd = {
                        .icbd_parent   = minfo->mi_dir,
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

                if (dentry != save) {
                        minfo->mi_dentry = dentry;
                        dput(save);
                }
        } else {
                /*
                 * revalidate.
                 */
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

                spin_lock(&ll_lookup_lock);
                spin_lock(&dcache_lock);
                lock_dentry(dentry);
                dentry->d_flags &= ~DCACHE_LUSTRE_INVALID;
                unlock_dentry(dentry);
                if (d_unhashed(dentry))
                        d_rehash_cond(dentry, 0);
                spin_unlock(&dcache_lock);
                spin_unlock(&ll_lookup_lock);

                ll_lookup_finish_locks(it, dentry);
        }
        EXIT;

out:
        if (likely(ll_sai_entry_to_stated(sai, entry)))
                cfs_waitq_signal(&sai->sai_waitq);
        return rc;
}

static int ll_statahead_interpret(struct obd_export *exp,
                                  struct ptlrpc_request *req,
                                  struct md_enqueue_info *minfo,
                                  int rc)
{
        struct lookup_intent     *it = &minfo->mi_it;
        struct dentry            *dentry = minfo->mi_dentry;
        struct inode             *dir = minfo->mi_dir;
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai;
        struct ll_sai_entry      *entry;
        ENTRY;

        CDEBUG(D_READA, "interpret statahead %.*s rc %d\n",
               dentry->d_name.len, dentry->d_name.name, rc);

        spin_lock(&lli->lli_lock);
        if (unlikely(lli->lli_sai == NULL ||
                     lli->lli_sai->sai_generation != minfo->mi_generation)) {
                spin_unlock(&lli->lli_lock);
                ll_intent_release(it);
                dput(dentry);
                iput(dir);
                OBD_FREE_PTR(minfo);
                RETURN(-ESTALE);
        } else {
                sai = ll_sai_get(lli->lli_sai);
                entry = ll_sai_entry_set(sai,
                                         (unsigned int)(long)minfo->mi_cbdata,
                                         rc ? SA_ENTRY_UNSTATED :
                                         SA_ENTRY_STATED, req, minfo);
                LASSERT(entry != NULL);
                if (likely(sa_is_running(sai))) {
                        ll_sai_entry_to_received(sai, entry);
                        sai->sai_replied++;
                        spin_unlock(&lli->lli_lock);
                        cfs_waitq_signal(&sai->sai_thread.t_ctl_waitq);
                } else {
                        if (!list_empty(&entry->se_list))
                                list_del_init(&entry->se_list);
                        sai->sai_replied++;
                        spin_unlock(&lli->lli_lock);
                        ll_sai_entry_cleanup(entry, 1);
                }
                ll_sai_put(sai);
                RETURN(rc);
        }
}

static void sa_args_fini(struct md_enqueue_info *minfo,
                         struct ldlm_enqueue_info *einfo)
{
        LASSERT(minfo && einfo);
        iput(minfo->mi_dir);
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

        minfo->mi_it.it_op = IT_GETATTR;
        minfo->mi_dentry = dentry;
        minfo->mi_dir = igrab(dir);
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

/**
 * similar to ll_lookup_it().
 */
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
                rc = mdc_intent_getattr_async(ll_i2mdcexp(dir), minfo, einfo);

        if (rc)
                sa_args_fini(minfo, einfo);

        RETURN(rc);
}

/**
 * similar to ll_revalidate_it().
 * \retval      1 -- dentry valid
 * \retval      0 -- will send stat-ahead request
 * \retval others -- prepare stat-ahead request failed
 */
static int do_sa_revalidate(struct inode *dir, struct dentry *dentry)
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

        rc = mdc_revalidate_lock(ll_i2mdcexp(dir), &it, &fid);
        if (rc == 1) {
                ll_intent_release(&it);
                RETURN(1);
        }

        rc = sa_args_prep(dir, dentry, &minfo, &einfo);
        if (rc)
                RETURN(rc);

        rc = ll_prepare_mdc_op_data(&minfo->mi_data, dir,
                                    inode, dentry->d_name.name,
                                    dentry->d_name.len, 0, NULL);
        if (rc == 0)
                rc = mdc_intent_getattr_async(ll_i2mdcexp(dir), minfo, einfo);

        if (rc)
                sa_args_fini(minfo, einfo);

        RETURN(rc);
}

static inline void ll_name2qstr(struct qstr *q, const char *name, int namelen)
{
        q->name = name;
        q->len  = namelen;
        q->hash = full_name_hash(name, namelen);
}

static int ll_statahead_one(struct dentry *parent, struct ll_dir_entry *de)
{
        struct inode             *dir = parent->d_inode;
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai = lli->lli_sai;
        struct qstr               name;
        struct dentry            *dentry;
        struct ll_sai_entry      *se;
        int                       rc;
        ENTRY;

        if (parent->d_flags & DCACHE_LUSTRE_INVALID) {
                CDEBUG(D_READA, "parent dentry@%p %.*s is "
                       "invalid, skip statahead\n",
                       parent, parent->d_name.len, parent->d_name.name);
                RETURN(-EINVAL);
        }

        se = ll_sai_entry_init(sai, sai->sai_index);
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
                rc = do_sa_revalidate(dir, dentry);
                if (rc)
                        dput(dentry);
        }

        EXIT;

out:
        if (rc) {
                CDEBUG(D_READA, "set sai entry %p index %u stat %d rc %d\n",
                       se, se->se_index, se->se_stat, rc);
                se->se_stat = rc;
                if (ll_sai_entry_to_stated(sai, se))
                        cfs_waitq_signal(&sai->sai_waitq);
        } else {
                sai->sai_sent++;
        }

        sai->sai_index++;
        return rc;
}

static int ll_statahead_thread(void *arg)
{
        struct dentry            *parent = (struct dentry *)arg;
        struct inode             *dir = parent->d_inode;
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_sb_info        *sbi = ll_i2sbi(dir);
        struct ll_statahead_info *sai = ll_sai_get(lli->lli_sai);
        struct ptlrpc_thread     *thread = &sai->sai_thread;
        unsigned long             index = 0;
        int                       first = 0;
        int                       rc = 0;
        ENTRY;

        {
                char pname[16];
                snprintf(pname, 15, "ll_sa_%u", lli->lli_opendir_pid);
                cfs_daemonize(pname);
        }

        sbi->ll_sa_total++;
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
                /*
                 * reach the end of dir.
                 */
                if (index >= npages) {
                        CDEBUG(D_READA, "reach end, index/npages %lu/%lu\n",
                               index, npages);

                        while (1) {
                                l_wait_event(thread->t_ctl_waitq,
                                             !sa_is_running(sai) ||
                                             !sa_received_empty(sai) ||
                                             sai->sai_sent == sai->sai_replied,
                                             &lwi);
                                if (!sa_received_empty(sai) &&
                                    sa_is_running(sai))
                                        do_statahead_interpret(sai);
                                else
                                        GOTO(out, rc);
                        }
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
                        /*
                         * skip "."
                         */
                        de = ll_dir_next_entry(de);
                        /*
                         * skip ".."
                         */
                        de = ll_dir_next_entry(de);
                }

                for (; (char*)de <= limit; de = ll_dir_next_entry(de)) {
                        if (de->lde_inode == 0)
                                continue;

                        if (de->lde_name[0] == '.' && !sai->sai_ls_all) {
                                /*
                                 * skip hidden files..
                                 */
                                sai->sai_skip_hidden++;
                                continue;
                        }

                        /*
                         * don't stat-ahead first entry.
                         */
                        if (unlikely(!first)) {
                                first++;
                                continue;
                        }

keep_de:
                        l_wait_event(thread->t_ctl_waitq,
                                     !sa_is_running(sai) || sa_not_full(sai) ||
                                     !sa_received_empty(sai),
                                     &lwi);

                        while (!sa_received_empty(sai) && sa_is_running(sai))
                                do_statahead_interpret(sai);

                        if (unlikely(!sa_is_running(sai))) {
                                ll_put_page(page);
                                GOTO(out, rc);
                        }

                        if (!sa_not_full(sai))
                                /*
                                 * do not skip the current de.
                                 */
                                goto keep_de;

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

/**
 * called in ll_file_release().
 */
void ll_stop_statahead(struct inode *inode, void *key)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        if (unlikely(key == NULL))
                return;

        spin_lock(&lli->lli_lock);
        if (lli->lli_opendir_key != key || lli->lli_opendir_pid == 0) {
                spin_unlock(&lli->lli_lock);
                return;
        }

        lli->lli_opendir_key = NULL;

        if (lli->lli_sai) {
                struct l_wait_info lwi = { 0 };
                struct ptlrpc_thread *thread = &lli->lli_sai->sai_thread;

                if (!sa_is_stopped(lli->lli_sai)) {
                        thread->t_flags = SVC_STOPPING;
                        spin_unlock(&lli->lli_lock);
                        cfs_waitq_signal(&thread->t_ctl_waitq);

                        CDEBUG(D_READA, "stopping statahead thread, pid %d\n",
                               cfs_curproc_pid());
                        l_wait_event(thread->t_ctl_waitq,
                                     sa_is_stopped(lli->lli_sai),
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
        } else {
                lli->lli_opendir_pid = 0;
                spin_unlock(&lli->lli_lock);
        }
}

enum {
        /*
         * not first dirent, or is "."
         */
        LS_NONE_FIRST_DE = 0,
        /*
         * the first non-hidden dirent
         */
        LS_FIRST_DE,
        /*
         * the first hidden dirent, that is ".xxx
         */
        LS_FIRST_DOT_DE
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
                /*
                 * reach the end of dir.
                 */
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
                                CWARN("Maybe got bad on-disk dir: %lu/%u\n",
                                      dir->i_ino, dir->i_generation);
                        /*
                         * skip "." or ingore bad entry.
                         */
                        de = ll_dir_next_entry(de);

                        if (unlikely(!(de->lde_name_len == 2 &&
                                       strncmp(de->lde_name, "..", 2) == 0)))
                                CWARN("Maybe got bad on-disk dir: %lu/%u\n",
                                      dir->i_ino, dir->i_generation);
                        /*
                         * skip ".." or ingore bad entry.
                         */
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

                        if (d_name->len != de->lde_name_len ||
                            strncmp(d_name->name, de->lde_name, d_name->len) != 0)
                                rc = LS_NONE_FIRST_DE;
                        else if (!dot_de)
                                rc = LS_FIRST_DE;
                        else
                                rc = LS_FIRST_DOT_DE;

                        ll_put_page(page);
                        RETURN(rc);
                }
                ll_put_page(page);
                index++;
        }
        RETURN(rc);
}

static int trigger_statahead(struct inode *dir, struct dentry **dentryp)
{
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct l_wait_info        lwi = { 0 };
        struct ll_statahead_info *sai;
        struct dentry            *parent;
        int                       rc;
        ENTRY;

         /* I am the "lli_opendir_pid" owner, only me can set "lli_sai". */
        rc = is_first_dirent(dir, *dentryp);
        if (rc == LS_NONE_FIRST_DE)
                /* It is not "ls -{a}l" operation, no need statahead for it. */
                GOTO(out, rc = -EAGAIN);

        sai = ll_sai_alloc();
        if (sai == NULL)
                GOTO(out, rc = -ENOMEM);

        sai->sai_ls_all = (rc == LS_FIRST_DOT_DE);
        sai->sai_inode = igrab(dir);
        if (unlikely(sai->sai_inode == NULL)) {
                CWARN("Do not start stat ahead on dying inode %lu/%u.\n",
                      dir->i_ino, dir->i_generation);
                OBD_FREE_PTR(sai);
                GOTO(out, rc = -ESTALE);
        }

        /* get parent reference count here, and put it in ll_statahead_thread */
        parent = dget((*dentryp)->d_parent);
        if (unlikely(sai->sai_inode != parent->d_inode)) {
                CWARN("Race condition, someone changed %.*s just now: "
                      "old parent "DFID", new parent "DFID" .\n",
                      (*dentryp)->d_name.len, (*dentryp)->d_name.name,
                      PFID(ll_inode_lu_fid(dir)),
                      PFID(ll_inode_lu_fid(parent->d_inode)));
                dput(parent);
                iput(sai->sai_inode);
                OBD_FREE_PTR(sai);
                RETURN(-EAGAIN);
        }

        lli->lli_sai = sai;
        rc = cfs_kernel_thread(ll_statahead_thread, parent, 0);
        if (rc < 0) {
                CERROR("can't start ll_sa thread, rc: %d\n", rc);
                dput(parent);
                lli->lli_opendir_key = NULL;
                sai->sai_thread.t_flags = SVC_STOPPED;
                ll_sai_put(sai);
                LASSERT(lli->lli_sai == NULL);
                RETURN(-EAGAIN);
        }

        l_wait_event(sai->sai_thread.t_ctl_waitq,
                     sa_is_running(sai) || sa_is_stopped(sai), &lwi);

        /* We don't stat-ahead for the first dirent since we are already in
         * lookup, and -EEXIST also indicates that this is the first dirent. */
        RETURN(-EEXIST);

out:
        spin_lock(&lli->lli_lock);
        lli->lli_opendir_key = NULL;
        lli->lli_opendir_pid = 0;
        spin_unlock(&lli->lli_lock);
        return rc;
}

/**
 * Start statahead thread if this is the first dir entry.
 * Otherwise if a thread is started already, wait it until it is ahead of me.
 * \retval 0       -- stat ahead thread process such dentry, for lookup, it miss
 * \retval 1       -- stat ahead thread process such dentry, for lookup, it hit
 * \retval -EEXIST -- stat ahead thread started, and this is the first dentry
 * \retval -EBADFD -- statahead thread exit and not dentry available
 * \retval -EAGAIN -- try to stat by caller
 * \retval others  -- error
 */
int do_statahead_enter(struct inode *dir, struct dentry **dentryp, int lookup)
{
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai;
        struct ll_sb_info        *sbi;
        int                       rc  = 0;
        ENTRY;

        spin_lock(&lli->lli_lock);
        if (unlikely(lli->lli_opendir_pid != cfs_curproc_pid())) {
                spin_unlock(&lli->lli_lock);
                RETURN(-EAGAIN);
        }

        if (likely(lli->lli_sai)) {
                sai = ll_sai_get(lli->lli_sai);
                spin_unlock(&lli->lli_lock);
        } else {
                spin_unlock(&lli->lli_lock);
                RETURN(trigger_statahead(dir, dentryp));
        }

        if (unlikely(sa_is_stopped(sai) &&
                     list_empty(&sai->sai_entries_stated)))
                GOTO(out, rc = -EBADFD);

        if ((*dentryp)->d_name.name[0] == '.') {
                if (likely(sai->sai_ls_all ||
                           sai->sai_miss_hidden >= sai->sai_skip_hidden)) {
                        /* Hidden dentry is the first one, or statahead thread
                         * does not skip so many hidden dentries before
                         * "sai_ls_all" enabled as below. */
                } else {
                        if (!sai->sai_ls_all)
                                /* It maybe because hidden dentry is not the
                                 * first one, "sai_ls_all" was not set, then
                                 * "ls -al" missed. Enable "sai_ls_all" for
                                 * such case. */
                                sai->sai_ls_all = 1;

                        /* Such "getattr" has been skipped before "sai_ls_all"
                         * enabled as above. */
                        sai->sai_miss_hidden++;
                        GOTO(out, rc = -ENOENT);
                }
        }

        sbi = ll_i2sbi(dir);
        if (ll_sai_entry_stated(sai)) {
                sbi->ll_sa_cached++;
        } else {
                struct l_wait_info lwi =LWI_INTR(LWI_ON_SIGNAL_NOOP, NULL);

                sbi->ll_sa_blocked++;
                /* thread started already, avoid double-stat. */
                rc = l_wait_event(sai->sai_waitq,
                                  ll_sai_entry_stated(sai) || sa_is_stopped(sai),
                                  &lwi);
        }

        if (lookup) {
                struct dentry *result;

                result = d_lookup((*dentryp)->d_parent, &(*dentryp)->d_name);
                if (result) {
                        LASSERT(result != *dentryp);
                        /* BUG 16303: do not drop reference count for "*dentryp",
                         * VFS will do that by itself. */
                        *dentryp = result;
                        GOTO(out, rc = 1);
                }
        }
        /* do nothing for revalidate. */
        EXIT;

out:
        ll_sai_put(sai);
        return rc;
}

/**
 * update hit/miss count.
 */
void ll_statahead_exit(struct inode *dir, struct dentry *dentry, int result)
{
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai;
        struct ll_sb_info        *sbi;
        struct ll_dentry_data    *ldd = ll_d2d(dentry);
        ENTRY;

        spin_lock(&lli->lli_lock);
        if (unlikely(lli->lli_opendir_pid != cfs_curproc_pid())) {
                spin_unlock(&lli->lli_lock);
                EXIT;
                return;
        } else {
                sai = ll_sai_get(lli->lli_sai);
                spin_unlock(&lli->lli_lock);
        }
        sbi = ll_i2sbi(dir);

        if (result >= 1) {
                sbi->ll_sa_hit++;
                sai->sai_hit++;
                sai->sai_consecutive_miss = 0;
                sai->sai_max = min(2 * sai->sai_max, sbi->ll_sa_max);
        } else {
                sbi->ll_sa_miss++;
                sai->sai_miss++;
                sai->sai_consecutive_miss++;
                if (sa_low_hit(sai) && sa_is_running(sai)) {
                        sbi->ll_sa_wrong++;
                        CDEBUG(D_READA, "Statahead for dir "DFID" hit ratio "
                               "too low: hit/miss %u/%u, sent/replied %u/%u, "
                               "stopping statahead thread: pid %d\n",
                               PFID(ll_inode_lu_fid(dir)), sai->sai_hit,
                               sai->sai_miss, sai->sai_sent,
                               sai->sai_replied, cfs_curproc_pid());
                        spin_lock(&lli->lli_lock);
                        if (!sa_is_stopped(sai))
                                sai->sai_thread.t_flags = SVC_STOPPING;
                        spin_unlock(&lli->lli_lock);
                }
        }

        if (!sa_is_stopped(sai))
                cfs_waitq_signal(&sai->sai_thread.t_ctl_waitq);
        ll_sai_entry_fini(sai);
        if (likely(ldd != NULL))
                ldd->lld_sa_generation = sai->sai_generation;

        ll_sai_put(sai);
        EXIT;
}
