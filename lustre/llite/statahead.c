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
        int                     se_index;
        int                     se_stat;
};

enum {
        SA_ENTRY_UNSTATED = 0,
        SA_ENTRY_STATED
};

static struct ll_statahead_info *ll_sai_alloc(void)
{
        struct ll_statahead_info *sai;

        OBD_ALLOC_PTR(sai);
        if (!sai)
                return NULL;

        sai->sai_max = LL_STATAHEAD_MIN;
        cfs_waitq_init(&sai->sai_thread.t_ctl_waitq);
        CFS_INIT_LIST_HEAD(&sai->sai_entries);
        atomic_set(&sai->sai_refc, 1);
        return sai;
}

static inline 
struct ll_statahead_info *ll_sai_get(struct ll_statahead_info *sai)
{
        LASSERT(sai);
        atomic_inc(&sai->sai_refc);
        return sai;
}

static void ll_sai_put(struct ll_statahead_info *sai)
{
        struct inode *inode = sai->sai_inode;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        if (atomic_dec_and_lock(&sai->sai_refc, &lli->lli_lock)) {
                struct ll_sai_entry  *entry, *next;

                LASSERT(sai->sai_thread.t_flags & SVC_STOPPED);
                list_for_each_entry_safe(entry, next, &sai->sai_entries,
                                         se_list) {
                        list_del(&entry->se_list);
                        OBD_FREE_PTR(entry);
                }
                OBD_FREE_PTR(sai);
                lli->lli_sai = NULL;
                spin_unlock(&lli->lli_lock);
                iput(inode);
        }
        EXIT;
}

static struct ll_sai_entry *ll_sai_entry_get(struct ll_statahead_info *sai,
                                             int index, int stat)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sb_info    *sbi = ll_i2sbi(sai->sai_inode);
        struct ll_sai_entry  *entry;
        ENTRY;

        OBD_ALLOC_PTR(entry);
        if (entry == NULL)
                RETURN(NULL);
        
        CDEBUG(D_READA, "alloc sai entry %p index %d, stat %d\n",
               entry, index, stat);
        entry->se_index = index;
        entry->se_stat  = stat;

        spin_lock(&lli->lli_lock);
        list_add_tail(&entry->se_list, &sai->sai_entries);
        sai->sai_entries_nr++;
        sbi->ll_sa_count = sai->sai_entries_nr;
        spin_unlock(&lli->lli_lock);

        LASSERT(sai->sai_entries_nr <= sbi->ll_sa_max);
        RETURN(entry);
}

static void ll_sai_entry_set(struct ll_statahead_info *sai, int index,
                             int stat)
{
        struct ll_sai_entry *entry;
        ENTRY;

        list_for_each_entry(entry, &sai->sai_entries, se_list) {
                if (entry->se_index == index) {
                        LASSERT(entry->se_stat == SA_ENTRY_UNSTATED);
                        entry->se_stat = stat;
                        CDEBUG(D_READA, "set sai entry %p index %d stat %d\n",
                               entry, index, stat);
                        EXIT;
                        return;
                }
        }
        /* Sometimes, this happens when entry has been put and freed */
        CDEBUG(D_READA, "can't find sai entry index %d\n", index);
        EXIT;
}

/* check first entry was stated already */
static int ll_sai_entry_stated(struct ll_statahead_info *sai)
{
        struct ll_inode_info *lli = ll_i2info(sai->sai_inode);
        struct ll_sai_entry  *entry;
        int                   rc = 0;
        ENTRY;

        spin_lock(&lli->lli_lock);
        if (!list_empty(&sai->sai_entries)) {
                entry = list_entry(sai->sai_entries.next, struct ll_sai_entry,
                                   se_list);
                CDEBUG(D_READA, "check sai entry %p index %d stat %d\n",
                       entry, entry->se_index, entry->se_stat);
                rc = (entry->se_stat != SA_ENTRY_UNSTATED);
        }
        spin_unlock(&lli->lli_lock);

        RETURN(rc);
}

/* inside lli_lock */
static void ll_sai_entry_put(struct ll_statahead_info *sai)
{
        struct ll_sai_entry  *entry;
        ENTRY;
        
        if (list_empty(&sai->sai_entries)) {
                EXIT;
                return;
        }
        LASSERT(sai->sai_entries_nr > 0);

        entry = list_entry(sai->sai_entries.next, struct ll_sai_entry, se_list);
        list_del(&entry->se_list);
        sai->sai_entries_nr--;

        CDEBUG(D_READA, "free sa entry %p index %d stat %d\n",
               entry, entry->se_index, entry->se_stat);
        OBD_FREE_PTR(entry);
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
        struct ll_statahead_info *sai;
        ENTRY;

        CDEBUG(D_READA, "interpret statahead %.*s rc %d\n",
               dentry->d_name.len, dentry->d_name.name, rc);
        if (rc || dir == NULL)
                GOTO(out, rc);

        if (dentry->d_inode == NULL) {
                /* lookup */
                struct dentry    *save = dentry;
                struct it_cb_data icbd = {
                        .icbd_parent = dir,
                        .icbd_childp = &dentry
                };

                rc = lookup_it_finish(req, DLM_REPLY_REC_OFF, it, &icbd);
                if (!rc) {
                        /* 
                         * Here dentry->d_inode might be NULL,
                         * because the entry may have been removed before
                         * we start doing stat ahead.
                         */
                        if (dentry != save)
                                dput(save);
                        ll_lookup_finish_locks(it, dentry);
                }
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
                __d_rehash(dentry, 0);
                spin_unlock(&dcache_lock);

                ll_lookup_finish_locks(it, dentry);

        }
        EXIT;
out:
        spin_lock(&lli->lli_lock);
        sai = lli->lli_sai;
        if (sai) {
                lli->lli_sai->sai_replied++;
                ll_sai_entry_set(lli->lli_sai, minfo->mi_cbdata,
                                 SA_ENTRY_STATED);
                cfs_waitq_signal(&lli->lli_sai->sai_thread.t_ctl_waitq);
        }
        spin_unlock(&lli->lli_lock);
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
        minfo->mi_cbdata = lli->lli_sai->sai_sent;

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

/* similar to ll_revalidate_it().
 * return 1: dentry valid.
 *        0: will send stat-ahead request.
 *        -errno: prepare stat-ahead request failed. */
static int do_sa_revalidate(struct dentry *dentry)
{
        struct inode             *inode = dentry->d_inode;
        struct ll_inode_info     *lli = ll_i2info(dentry->d_parent->d_inode);
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

        ll_inode2fid(&fid, inode);

        rc = mdc_revalidate_lock(ll_i2mdcexp(inode), &it, &fid);
        if (rc == 1) {
                ll_intent_release(&it);
                lli->lli_sai->sai_cached++;
                cfs_waitq_signal(&lli->lli_sai->sai_thread.t_ctl_waitq);
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

/* copied from kernel */
static inline void name2qstr(struct qstr *this, const char *name, int namelen)
{
        unsigned long        hash;
        const unsigned char *p = (const unsigned char *)name;
        int                  len;
        unsigned int         c;

        hash = init_name_hash();
        for (len = 0; len < namelen; len++, p++) {
                c = *p;
                hash = partial_name_hash(c, hash);
        }
        this->name = name;
        this->len  = namelen;
        this->hash = end_name_hash(hash);
}

static int ll_statahead_one(struct dentry *parent, ext2_dirent *de)
{
        struct inode           *dir = parent->d_inode;
        struct ll_inode_info   *lli = ll_i2info(dir);
        struct qstr             name;
        struct dentry          *dentry;
        struct ll_sai_entry    *se;
        int                     rc;
        ENTRY;

        name2qstr(&name, de->name, de->name_len);

        se = ll_sai_entry_get(lli->lli_sai, lli->lli_sai->sai_sent,
                              SA_ENTRY_UNSTATED);

#ifdef DCACHE_LUSTRE_INVALID
        if (parent->d_flags & DCACHE_LUSTRE_INVALID) {
#else
        if (d_unhashed(parent)) {
#endif
                CDEBUG(D_READA, "parent dentry@%p %.*s is "
                       "invalid, skip statahead\n",
                       parent, parent->d_name.len, parent->d_name.name);
                GOTO(out, rc = -EINVAL);
        }

        dentry = d_lookup(parent, &name);
        if (!dentry) {
                struct dentry *dentry = d_alloc(parent, &name);

                rc = -ENOMEM;
                if (dentry) {
                        rc = do_sa_lookup(dir, dentry);
                        if (rc)
                                dput(dentry);
                }
                GOTO(out, rc);
        }

        rc = do_sa_revalidate(dentry);
        if (rc)
                dput(dentry);
        GOTO(out, rc);
out:
        if (rc) {
                CDEBUG(D_READA, "set sai entry %p index %d stat %d, rc %d\n",
                       se, se->se_index, se->se_stat, rc);
                se->se_stat = rc;
                cfs_waitq_signal(&lli->lli_sai->sai_thread.t_ctl_waitq);
        }
        lli->lli_sai->sai_sent++;
        return rc;
}
                
static inline int sa_check_stop(struct ll_statahead_info *sai)
{
        return !!(sai->sai_thread.t_flags & SVC_STOPPING);
}

static inline int sa_not_full(struct ll_statahead_info *sai)
{
        return sai->sai_sent - sai->sai_miss - sai->sai_hit < sai->sai_max;
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
        struct l_wait_info        lwi = { 0 };
        unsigned long             index = 0;
        __u64                     offset = 0;
        int                       skip = 0;
        int                       rc = 0;
        char                      name[16] = "";
        ENTRY;

        sbi->ll_sa_total++;

        snprintf(name, 15, "ll_sa_%u", sta->sta_pid);
        cfs_daemonize(name);
        thread->t_flags = SVC_RUNNING;
        cfs_waitq_signal(&thread->t_ctl_waitq);
        CDEBUG(D_READA, "start doing statahead for %s\n", parent->d_name.name);

        if (sai->sai_ls_all)
                CDEBUG(D_READA, "do statahead for hidden files\n");

        while (1) {
                unsigned long npages = dir_pages(dir);

                /* hit ratio < 80% */
                if ((sai->sai_hit < 4 * sai->sai_miss && sai->sai_hit > 7) ||
                     (sai->sai_consecutive_miss > 8)) {
                        sbi->ll_sa_wrong++;
                        CDEBUG(D_READA, "statahead for dir %.*s hit ratio too "
                               "low: hit/miss %u/%u, sent/replied %u/%u, "
                               "cached %u\n",
                               parent->d_name.len, parent->d_name.name,
                               sai->sai_hit, sai->sai_miss, sai->sai_sent,
                               sai->sai_replied, sai->sai_cached);
                        break;
                }

                /* reach the end of dir */
                if (index == npages) {
                        CDEBUG(D_READA, "reach end, index/npages %lu/%lu\n",
                               index, npages);
                        break;
                }

                l_wait_event(thread->t_ctl_waitq,
                             sa_check_stop(sai) || sa_not_full(sai),
                             &lwi);

                if (sa_check_stop(sai))
                        break;

                for (; index < npages; index++, offset = 0) {
                        char *kaddr, *limit;
                        ext2_dirent *de;
                        struct page *page;

                        CDEBUG(D_EXT2,"read %lu of dir %lu/%u page %lu"
                               "/%lu size %llu\n",
                               CFS_PAGE_SIZE, dir->i_ino, dir->i_generation,
                               index, npages, dir->i_size);

                        page = ll_get_dir_page(dir, index);
                        npages = dir_pages(dir);

                        if (IS_ERR(page)) {
                                rc = PTR_ERR(page);
                                CERROR("error reading dir %lu/%u page %lu: "
                                       "rc %d\n",
                                       dir->i_ino, dir->i_generation, index,
                                       rc);
                                GOTO(out, rc);
                        }

                        kaddr = page_address(page);
                        de = (ext2_dirent *)(kaddr + offset);
                        limit = kaddr + CFS_PAGE_SIZE - EXT2_DIR_REC_LEN(1);
                        for (; (char*)de <= limit && sa_not_full(sai);
                             de = ext2_next_entry(de)) {
                                if (!de->inode)
                                        continue;

                                /* don't stat-ahead ".", ".." */
                                if (skip < 2) {
                                        skip++;
                                        continue;
                                }

                                /* don't stat-ahead for hidden files */
                                if (de->name[0] == '.' && !sai->sai_ls_all)
                                        continue;

                                /* don't stat-ahead for the first de */
                                if (skip < 3) {
                                        skip++;
                                        continue;
                                }

                                rc = ll_statahead_one(parent, de);
                                if (rc < 0) {
                                        ext2_put_page(page);
                                        GOTO(out, rc);
                                }
                        }
                        offset = (char *)de - kaddr;
                        ext2_put_page(page);

                        if ((char *)de <= limit)
                                /* !sa_not_full() */
                                break;
                }
        }
        EXIT;
out:
        thread->t_flags = SVC_STOPPED;
        cfs_waitq_signal(&thread->t_ctl_waitq);
        lli->lli_opendir_pid = 0; /* avoid statahead again */
        ll_sai_put(sai);
        dput(parent);
        CDEBUG(D_READA, "stopped statahead thread, pid %d for %s\n",
               current->pid, parent->d_name.name);
        return 0;
}

/* called in ll_file_release */
void ll_stop_statahead(struct inode *inode)
{
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ptlrpc_thread *thread;

        /* don't check pid here. upon fork, if parent closedir before child,
         * child will not have chance to stop this thread. */
        lli->lli_opendir_pid = 0;

        spin_lock(&lli->lli_lock);
        if (lli->lli_sai) {
                struct l_wait_info lwi = { 0 };
                ll_sai_get(lli->lli_sai);
                spin_unlock(&lli->lli_lock);

                CDEBUG(D_READA, "stopping statahead thread, pid %d\n",
                       current->pid);
                thread = &lli->lli_sai->sai_thread;
                thread->t_flags = SVC_STOPPING;
                cfs_waitq_signal(&thread->t_ctl_waitq);
                l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_STOPPED,
                             &lwi);
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
        struct qstr   *d_name = &dentry->d_name;
        unsigned long  npages = dir_pages(dir);
        struct page   *page;
        ext2_dirent   *de;
        unsigned long  index;
        __u64          offset = 0;
        char          *kaddr, *limit;
        int            dot_de = 1; /* dirent is dotfile till now */
        int            rc = LS_NONE_FIRST_DE;
        ENTRY;

        page = ll_get_dir_page(dir, 0);
        if (IS_ERR(page)) {
                CERROR("error reading dir %lu/%u page 0: rc %ld\n",
                       dir->i_ino, dir->i_generation, PTR_ERR(page));
                RETURN(LS_NONE_FIRST_DE);
        }

        kaddr = page_address(page);
        de = (ext2_dirent *)kaddr;
        if (!(de->name_len == 1 && strncmp(de->name, ".", 1) == 0))
                CWARN("Maybe got bad on-disk dir:%lu\n", dir->i_ino);
        de = ext2_next_entry(de); /* skip ".", or ingore bad entry */
        if (!(de->name_len == 2 && strncmp(de->name, "..", 2) == 0))
                CWARN("Maybe got bad on-disk dir:%lu\n", dir->i_ino);
        de = ext2_next_entry(de); /* skip "..", or ingore bad entry */

        offset = (char *)de - kaddr;

        for (index = 0; index < npages; offset = 0) {
                de = (ext2_dirent *)(kaddr + offset);
                limit = kaddr + CFS_PAGE_SIZE - EXT2_DIR_REC_LEN(1);
                for (; (char*)de <= limit; de = ext2_next_entry(de)) {
                        if (!de->inode)
                                continue;

                        if (de->name[0] != '.')
                                dot_de = 0;

                        if (dot_de && d_name->name[0] != '.') {
                                CDEBUG(D_READA, "%.*s skip hidden file %.*s\n",
                                       d_name->len, d_name->name,
                                       de->name_len, de->name);
                                continue;
                        }

                        if (d_name->len == de->name_len &&
                            !strncmp(d_name->name, de->name, d_name->len))
                                rc = LS_FIRST_DE + dot_de;
                        else
                                rc = LS_NONE_FIRST_DE;
                        GOTO(out, rc);
                }

                if (++index >= npages)
                        break;

                ext2_put_page(page);

                page = ll_get_dir_page(dir, index);
                if (IS_ERR(page)) {
                        CERROR("error reading dir %lu/%u page %lu: rc %ld\n",
                               dir->i_ino, dir->i_generation, index,
                               PTR_ERR(page));
                        RETURN(LS_NONE_FIRST_DE);
                }
                kaddr = page_address(page);
        }
        CERROR("%.*s not found in dir %.*s!\n", d_name->len, d_name->name,
               dentry->d_parent->d_name.len, dentry->d_parent->d_name.name);
        EXIT;
out:
        ext2_put_page(page);
        return rc;
}

/* start stat-ahead thread if this is the first dir entry, otherwise if a thread
 * is started already, wait until thread is ahead of me.
 * Return value: 
 *    0 -- miss,
 *    1 -- hit,
 *    -EEXIST -- stat ahead thread started, and this is the first try.
 *    other negative value -- error.
 */
int ll_statahead_enter(struct inode *dir, struct dentry **dentryp, int lookup)
{
        struct ll_sb_info        *sbi = ll_i2sbi(dir);
        struct ll_inode_info     *lli = ll_i2info(dir);
        struct ll_statahead_info *sai;
        struct ll_sa_thread_args  sta;
        struct l_wait_info        lwi = { 0 };
        int                       rc;
        ENTRY;

        if (sbi->ll_sa_max == 0)
                RETURN(-ENOTSUPP);

        /* not the same process, don't statahead */
        if (lli->lli_opendir_pid != current->pid)
                RETURN(-EBADF);

        spin_lock(&lli->lli_lock);
        if (lli->lli_sai) {
                sai = ll_sai_get(lli->lli_sai);
                spin_unlock(&lli->lli_lock);

                if (ll_sai_entry_stated(sai)) {
                        sbi->ll_sa_cached++;
                } else {
                        struct l_wait_info lwi = { 0 };

                        sbi->ll_sa_blocked++;
                        /* thread started already, avoid double-stat */
                        l_wait_event(sai->sai_thread.t_ctl_waitq,
                                     ll_sai_entry_stated(sai) ||
                                     sai->sai_thread.t_flags & SVC_STOPPED,
                                     &lwi);
                }

                ll_sai_put(sai);

                if (lookup) {
                        struct dentry *result;

                        result = d_lookup((*dentryp)->d_parent,
                                          &(*dentryp)->d_name);
                        if (result) {
                                LASSERT(result != *dentryp);
                                dput(*dentryp);
                                *dentryp = result;
                        }
                        RETURN(result != NULL);
                }
                /* do nothing for revalidate */
                RETURN(0);
        }
        spin_unlock(&lli->lli_lock);

        rc = is_first_dirent(dir, *dentryp);
        if (!rc) {
                /* optimization: don't statahead for this pid any longer */
                spin_lock(&lli->lli_lock);
                if (lli->lli_sai == NULL)
                        lli->lli_opendir_pid = 0;
                spin_unlock(&lli->lli_lock);
                RETURN(-EBADF);
        }

        spin_lock(&lli->lli_lock);
        if (lli->lli_sai == NULL) {
                lli->lli_sai = ll_sai_alloc();
                if (lli->lli_sai == NULL) {
                        spin_unlock(&lli->lli_lock);
                        RETURN(-ENOMEM);
                }
        } else {
                /* sai is already there */
                spin_unlock(&lli->lli_lock);
                RETURN(-EBUSY);
        }
        spin_unlock(&lli->lli_lock);
        
        sai = lli->lli_sai;
        sai->sai_inode = igrab(dir);
        sai->sai_ls_all = (rc == LS_FIRST_DOT_DE);

        sta.sta_parent = (*dentryp)->d_parent;
        sta.sta_pid    = current->pid;
        rc = kernel_thread(ll_statahead_thread, &sta, 0);
        if (rc < 0) {
                CERROR("can't start ll_sa thread, rc: %d\n", rc);
                ll_sai_put(sai);
                RETURN(rc);
        }

        l_wait_event(sai->sai_thread.t_ctl_waitq, 
                     sai->sai_thread.t_flags & (SVC_RUNNING | SVC_STOPPED),
                     &lwi);
        ll_sai_put(sai);

        /* we don't stat-ahead for the first dirent since we are already in
         * lookup, and -EEXIST also indicates that this is the first dirent.
         */
        RETURN(-EEXIST);
}

/* update hit/miss count */
void ll_statahead_exit(struct dentry *dentry, int result)
{
        struct ll_inode_info *lli = ll_i2info(dentry->d_parent->d_inode);
        struct ll_sb_info    *sbi = ll_i2sbi(dentry->d_parent->d_inode);

        if (lli->lli_opendir_pid != current->pid)
                return;

        spin_lock(&lli->lli_lock);
        if (lli->lli_sai) {
                struct ll_statahead_info *sai = lli->lli_sai;

                ll_sai_entry_put(sai);
                if (result == 1) {
                        sai->sai_hit++;
                        sai->sai_consecutive_miss = 0;
                        sai->sai_max = min(2 * sai->sai_max, sbi->ll_sa_max);
                        CDEBUG(D_READA, "statahead %.*s hit(hit/miss %u/%u)\n",
                               dentry->d_name.len, dentry->d_name.name,
                               sai->sai_hit, sai->sai_miss);
                } else {
                        sai->sai_miss++;
                        sai->sai_consecutive_miss++;
                        /* upon miss, it's always because some dentry is added
                         * by statahead thread, and at the mean time `ls`
                         * processs finds this dentry, but the d_op for this
                         * dentry is NULL, then revalidate is not done, and
                         * ll_statahead_exit() not called for this dentry,
                         * so statahead thread should be behind of `ls` process,
                         * put one entry to go ahead.
                         */
                        CDEBUG(D_READA, "statahead %.*s miss(hit/miss %u/%u)\n",
                               dentry->d_name.len, dentry->d_name.name,
                               sai->sai_hit, sai->sai_miss);
                        ll_sai_entry_put(sai);
                }
                cfs_waitq_signal(&sai->sai_thread.t_ctl_waitq);
        }
        spin_unlock(&lli->lli_lock);
}
