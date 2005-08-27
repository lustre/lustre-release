/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004, 2005 Cluster File Systems, Inc.
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/kmod.h>
#include <linux/random.h>

#include <linux/obd.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_sec.h>

#include "mds_internal.h"

static struct ptlrpc_thread mds_eck_thread;

static struct thread_ctl {
        struct completion ctl_starting;
        struct completion ctl_finishing;
} mds_eck_ctl;

static LIST_HEAD(mds_capa_key_list);
static spinlock_t mds_capa_lock; /* protect capa and capa key */
struct timer_list mds_eck_timer;

#define CAPA_KEY_JIFFIES(key) \
        expiry_to_jiffies(le64_to_cpu((key)->k_key->lk_expiry))

#define CUR_MDS_CAPA_KEY(mds) (mds)->mds_capa_keys[(mds)->mds_capa_key_idx]
#define CUR_CAPA_KEY(mds) CUR_MDS_CAPA_KEY(mds).k_key
#define CUR_CAPA_KEY_ID(mds) CUR_MDS_CAPA_KEY(mds).k_key->lk_keyid
#define CUR_CAPA_KEY_LIST(mds) CUR_MDS_CAPA_KEY(mds).k_list
#define CUR_CAPA_KEY_EXPIRY(mds) le64_to_cpu(CUR_CAPA_KEY(mds)->lk_expiry)
#define CUR_CAPA_KEY_JIFFIES(mds) CAPA_KEY_JIFFIES(&CUR_MDS_CAPA_KEY(mds))

static int mds_write_capa_key(struct obd_device *obd, int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mds_capa_key *keys = mds->mds_capa_keys;
        struct file *filp = mds->mds_capa_keys_filp;
        struct lvfs_run_ctxt saved;
        loff_t off = 0;
        int i, rc = 0;
        ENTRY;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        for (i = 0; i < 2 && keys[i].k_key; i++) {
                rc = fsfilt_write_record(obd, filp, keys[i].k_key,
                                         sizeof(*keys[i].k_key),
                                         &off, force_sync);
                if (rc) {
                        CERROR("error writing MDS capa key: rc = %d\n", rc);
                        break;
                }
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static inline int
mds_capa_key_cmp(struct mds_obd *mds)
{
        return le32_to_cpu(mds->mds_capa_keys[0].k_key->lk_keyid) -
               le32_to_cpu(mds->mds_capa_keys[1].k_key->lk_keyid);
}

static void
do_update_capa_key(struct mds_obd *mds, struct lustre_capa_key *key)
{
        __u32 keyid = 1;
        __u64 expiry_rounded;

        if (CUR_CAPA_KEY(mds))
                keyid = le32_to_cpu(CUR_CAPA_KEY_ID(mds)) + 1;
        spin_lock(&mds_capa_lock);
        expiry_rounded = round_expiry(mds->mds_capa_key_timeout);
        spin_unlock(&mds_capa_lock);

        key->lk_mdsid = cpu_to_le32(mds->mds_num);
        key->lk_keyid = cpu_to_le32(keyid);
        key->lk_expiry = cpu_to_le64(expiry_rounded);
        get_random_bytes(key->lk_key, sizeof(key->lk_key));
}

static void list_add_capa_key(struct mds_capa_key *key, struct list_head *head)
{
        struct mds_capa_key *tmp;

        list_for_each_entry_reverse(tmp, head, k_list) {
                if (le64_to_cpu(key->k_key->lk_expiry) <
                    le64_to_cpu(tmp->k_key->lk_expiry)) {
                        /* put key before tmp */
                        list_add_tail(&key->k_list, &tmp->k_list);
                        return;
                }
        }

        list_add_tail(&key->k_list, head);
}

int mds_read_capa_key(struct obd_device *obd, struct file *file)
{
        loff_t off = 0;
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_capa_key *key;
        unsigned long capa_keys_size = file->f_dentry->d_inode->i_size;
        unsigned long expiry;
        int i = 0, rc = 0;
        ENTRY;

        if (capa_keys_size == 0) {
                CWARN("%s: initializing new %s\n", obd->obd_name,
                      file->f_dentry->d_name.name);
                 
                OBD_ALLOC(key, sizeof(*key));
                if (!key)
                        RETURN(-ENOMEM);

                do_update_capa_key(mds, key);

                mds->mds_capa_keys[0].k_key = key;
                mds->mds_capa_keys[0].k_obd = obd;
                INIT_LIST_HEAD(&mds->mds_capa_keys[0].k_list);
                mds->mds_capa_key_idx = 0;

                rc = mds_write_capa_key(obd, 1);
                if (rc)
                        GOTO(out, rc);
        } else {
                LASSERT(capa_keys_size == sizeof(*key) ||
                        capa_keys_size == 2 * sizeof(*key));

                while (capa_keys_size > i * sizeof(*key)) {
                        OBD_ALLOC(key, sizeof(*key));
                        if (!key)
                                RETURN(-ENOMEM);

                        rc = fsfilt_read_record(obd, file, key, sizeof(*key),
                                                &off);
                        if (rc) {
                                CERROR("error reading MDS %s capa key: %d\n",
                                       file->f_dentry->d_name.name, rc);
                                OBD_FREE(key, sizeof(*key));
                                GOTO(out, rc);
                        }

                        mds->mds_capa_keys[i].k_key = key;
                        mds->mds_capa_keys[i].k_obd = obd;
                        INIT_LIST_HEAD(&mds->mds_capa_keys[i].k_list);
                        i++;
                }

                mds->mds_capa_key_idx = 0;
                if (mds->mds_capa_keys[1].k_key && mds_capa_key_cmp(mds) < 0)
                        mds->mds_capa_key_idx = 1;
        }

        expiry = CUR_CAPA_KEY_JIFFIES(mds);
        spin_lock(&mds_capa_lock);
        if (time_before(expiry, mds_eck_timer.expires) ||
            !timer_pending(&mds_eck_timer))
                mod_timer(&mds_eck_timer, expiry);
        list_add_capa_key(&CUR_MDS_CAPA_KEY(mds), &mds_capa_key_list);
        spin_unlock(&mds_capa_lock);
out:
        RETURN(rc);
}

void mds_capa_keys_cleanup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int i;

        del_timer(&mds_eck_timer);
        spin_lock(&mds_capa_lock);
        if (CUR_CAPA_KEY(mds))
                list_del_init(&CUR_CAPA_KEY_LIST(mds));
        spin_unlock(&mds_capa_lock);

        for (i = 0; i < 2; i++)
                if (mds->mds_capa_keys[i].k_key)
                        OBD_FREE(mds->mds_capa_keys[i].k_key,
                                 sizeof(struct lustre_capa_key));
}

static int mds_set_capa_key(struct obd_device *obd, struct lustre_capa_key *key)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc;
        ENTRY;

        rc = obd_set_info(mds->mds_dt_exp, strlen("capa_key"), "capa_key",
                          sizeof(*key), key);
        RETURN(rc);
}

static int
mds_update_capa_key(struct obd_device *obd, struct mds_capa_key *mkey,
                    int force_sync)
{
        struct mds_obd *mds = &obd->u.mds;
        int to_update = !mds->mds_capa_key_idx;
        struct lustre_capa_key *key = mds->mds_capa_keys[to_update].k_key;
        __u32 keyid;
        unsigned long expiry;
        int rc, rc2;
        ENTRY;

        LASSERT(mkey != &mds->mds_capa_keys[to_update]);

        if (key == NULL) {
                /* first update */
                OBD_ALLOC(key, sizeof(*key));
                if (!key)
                        RETURN(-ENOMEM);
                mds->mds_capa_keys[to_update].k_key = key;
                mds->mds_capa_keys[to_update].k_obd = obd;
        }

        do_update_capa_key(mds, key);

        keyid = le32_to_cpu(key->lk_keyid);

        rc = mds_set_capa_key(obd, key);
        if (rc)
                /* XXX: anyway, it will be replayed */
                CERROR("error set capa key(id %u), err = %d\n", keyid, rc);

        rc2 = mds_write_capa_key(obd, 1);
        if (rc2)
                GOTO(out, rc2);
        
        CDEBUG(D_INFO, "wrote capa keyid %u\n", keyid);

        spin_lock(&mds_capa_lock);
        list_del_init(&CUR_CAPA_KEY_LIST(mds));
        mds->mds_capa_key_idx = to_update;
        expiry = CUR_CAPA_KEY_JIFFIES(mds);
        list_add_capa_key(&CUR_MDS_CAPA_KEY(mds), &mds_capa_key_list);

        if (time_before(expiry, mds_eck_timer.expires) ||
            !timer_pending(&mds_eck_timer))
                mod_timer(&mds_eck_timer, expiry);
        spin_unlock(&mds_capa_lock);

        DEBUG_MDS_CAPA_KEY(D_INFO, &CUR_MDS_CAPA_KEY(mds),
                           "mds_update_capa_key");
out:
        RETURN(rc2);
}

static inline int have_expired_capa_key(void)
{
        struct mds_capa_key *key;
        int expired = 0;
        ENTRY;

        spin_lock(&mds_capa_lock);
        if (!list_empty(&mds_capa_key_list)) {
                key = list_entry(mds_capa_key_list.next, struct mds_capa_key,
                                 k_list);
                /* expiry is in sec, so in case it misses, the result will
                 * minus HZ and then compare with jiffies. */
                expired = time_before(CAPA_KEY_JIFFIES(key) - HZ, jiffies);
        }
        spin_unlock(&mds_capa_lock);

        RETURN(expired);
}

static int inline mds_capa_key_check_stop(void)
{
        return (mds_eck_thread.t_flags & SVC_STOPPING) ? 1: 0;
}

static int mds_capa_key_thread_main(void *arg)
{
        struct thread_ctl *ctl = arg;
        unsigned long flags;
        int rc;
        ENTRY;

        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);
        THREAD_NAME(current->comm, sizeof(current->comm), "mds_ck");
        unlock_kernel();

        /*
         * letting starting function know, that we are ready and control may be
         * returned.
         */
        mds_eck_thread.t_flags = SVC_RUNNING;
        complete(&ctl->ctl_starting);

        while (!mds_capa_key_check_stop()) {
                struct l_wait_info lwi = { 0 };
                struct mds_capa_key *key, *tmp, *next = NULL;

                l_wait_event(mds_eck_thread.t_ctl_waitq,
                             (have_expired_capa_key() ||
                              mds_capa_key_check_stop()),
                             &lwi);

                spin_lock(&mds_capa_lock);
                list_for_each_entry_safe(key, tmp, &mds_capa_key_list, k_list) {
                        if (time_after(CAPA_KEY_JIFFIES(key), jiffies)) {
                                next = key;
                                break;
                        }

                        spin_unlock(&mds_capa_lock);

                        CDEBUG(D_INFO, "mds capa key expired: "
                               "mds #%u, key #%u\n",
                               le32_to_cpu(key->k_key->lk_mdsid),
                               le32_to_cpu(key->k_key->lk_keyid));

                        rc = mds_update_capa_key(key->k_obd, key, 1);
                        spin_lock(&mds_capa_lock);
                }

                if (next)
                        mod_timer(&mds_eck_timer, CAPA_KEY_JIFFIES(next));
                spin_unlock(&mds_capa_lock);
        }

        mds_eck_thread.t_flags = SVC_STOPPED;

        /* this is SMP-safe way to finish thread. */
        complete_and_exit(&ctl->ctl_finishing, 0);
        EXIT;
}

void mds_capa_key_timer_callback(unsigned long unused)
{
        ENTRY;
        wake_up(&mds_eck_thread.t_ctl_waitq);
        EXIT;
}

int mds_capa_key_start_thread(void)
{
        int rc;
        ENTRY;

        LASSERT(mds_eck_thread.t_flags == 0);
        init_completion(&mds_eck_ctl.ctl_starting);
        init_completion(&mds_eck_ctl.ctl_finishing);
        init_waitqueue_head(&mds_eck_thread.t_ctl_waitq);
        spin_lock_init(&mds_capa_lock);

        rc = kernel_thread(mds_capa_key_thread_main, &mds_eck_ctl,
                           (CLONE_VM | CLONE_FILES));
        if (rc < 0) {
                CERROR("cannot start capa key thread, "
                       "err = %d\n", rc);
                RETURN(rc);
        }

        wait_for_completion(&mds_eck_ctl.ctl_starting);
        LASSERT(mds_eck_thread.t_flags == SVC_RUNNING);
        RETURN(0);
}

void mds_capa_key_stop_thread(void)
{
        ENTRY;
        mds_eck_thread.t_flags = SVC_STOPPING;
        wake_up(&mds_eck_thread.t_ctl_waitq);
        wait_for_completion(&mds_eck_ctl.ctl_finishing);
        LASSERT(mds_eck_thread.t_flags == SVC_STOPPED);
        mds_eck_thread.t_flags = 0;
        EXIT;
}

void mds_update_capa_stat(struct obd_device *obd, int stat)
{
        struct mds_obd *mds = &obd->u.mds;

        spin_lock(&mds_capa_lock);
        mds->mds_capa_stat = stat;
        spin_unlock(&mds_capa_lock);
}

void mds_update_capa_timeout(struct obd_device *obd, unsigned long timeout)
{
        struct mds_obd *mds = &obd->u.mds;

        spin_lock(&mds_capa_lock);
        mds->mds_capa_timeout = timeout;
        /* XXX: update all capabilities in cache if their expiry too long */
        spin_unlock(&mds_capa_lock);
}

int mds_update_capa_key_timeout(struct obd_device *obd, unsigned long timeout)
{
        struct mds_obd *mds = &obd->u.mds;
        struct timeval tv;
        int rc;
        ENTRY;

        do_gettimeofday(&tv);

        spin_lock(&mds_capa_lock);
        mds->mds_capa_key_timeout = timeout;
        if (CUR_CAPA_KEY_EXPIRY(mds) < tv.tv_sec + timeout) {
                spin_unlock(&mds_capa_lock);
                RETURN(0);
        }
        spin_unlock(&mds_capa_lock);

        rc = mds_update_capa_key(obd, &CUR_MDS_CAPA_KEY(mds), 1);

        RETURN(rc);
}

static void mds_capa_reverse_map(struct mds_export_data *med,
                                 struct lustre_capa *capa)
{
        uid_t uid;

        if (!med->med_remote) {
                /* when not remote uid, ruid == uid */
                capa->lc_ruid = capa->lc_uid;
                return;
        }

        ENTRY;
        uid = mds_idmap_lookup_uid(med->med_idmap, 1, capa->lc_uid);
        if (uid == MDS_IDMAP_NOTFOUND)
                uid = med->med_nllu;
        capa->lc_ruid = uid;
        capa->lc_flags |= CAPA_FL_REMUID;
        EXIT;
}


int mds_pack_capa(struct obd_device *obd, struct mds_export_data *med,
                  struct mds_body *req_body, struct lustre_capa *req_capa,
                  struct ptlrpc_request *req, int *offset, struct mds_body *body)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_capa *capa;
        struct lustre_msg *repmsg = req->rq_repmsg;
        struct obd_capa *ocapa;
        __u8 key[CAPA_KEY_LEN];  /* key */
        int stat, expired, rc = 0;
        ENTRY;

        spin_lock(&mds_capa_lock);
        stat = mds->mds_capa_stat;
        spin_unlock(&mds_capa_lock);

        if (stat == 0) {
                (*offset)++;
                RETURN(0); /* capability is disabled */
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_PACK_CAPA))
                RETURN(-EINVAL);

        if (req_body) {
                /* capa renewal, check capa op against open mode */
                struct mds_file_data *mfd;
                int mode;

                mfd = mds_handle2mfd(&req_body->handle);
                if (mfd == NULL) {
                        DEBUG_CAPA(D_ERROR, req_capa, "no handle "LPX64" for",
                                   req_body->handle.cookie);
                        RETURN(-ESTALE);
                }

                mode = accmode(mfd->mfd_mode);
                if (!(req_capa->lc_op & mode)) {
                        DEBUG_CAPA(D_ERROR, req_capa, "accmode %d mismatch",
                                   mode);
                        RETURN(-EACCES);
                }
        }

        LASSERT(repmsg->buflens[*offset] == sizeof(*capa));
        capa = lustre_msg_buf(repmsg, (*offset)++, sizeof(*capa));
        LASSERT(capa != NULL);

        ocapa = capa_get(req_capa->lc_uid, req_capa->lc_op, req_capa->lc_mdsid,
                         req_capa->lc_ino, MDS_CAPA);
        if (ocapa) {
                expired = capa_is_to_expire(ocapa);
                if (!expired) {
                        capa_dup(capa, ocapa);
                        capa_put(ocapa);
                        GOTO(out, rc);
                }
                capa_put(ocapa);
        }

        memcpy(capa, req_capa, sizeof(*capa));
        mds_capa_reverse_map(med, capa);

        spin_lock(&mds_capa_lock);
        capa->lc_keyid = le32_to_cpu(CUR_CAPA_KEY_ID(mds));
        capa->lc_expiry = round_expiry(mds->mds_capa_timeout);
        if (mds->mds_capa_timeout < CAPA_EXPIRY)
                capa->lc_flags |= CAPA_FL_NOROUND;
        memcpy(key, CUR_CAPA_KEY(mds)->lk_key, sizeof(key));
        spin_unlock(&mds_capa_lock);

        capa_hmac(mds->mds_capa_hmac, key, capa);

        ocapa = capa_renew(capa, MDS_CAPA);
        if (!ocapa)
                rc = -ENOMEM;
out:
        if (rc == 0)
                body->valid |= OBD_MD_CAPA;
        RETURN(rc);
}
