/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/quota_master.c
 *  Lustre Quota Master request handler
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
 *   Author: Niu YaWei <niu@clusterfs.com>
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

#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/quotaops.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/quota.h>

#include <linux/obd_class.h>
#include <linux/lustre_quota.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_mds.h>

#include "mds_internal.h"

static struct list_head lustre_dquot_hash[NR_DQHASH];
static spinlock_t dquot_hash_lock = SPIN_LOCK_UNLOCKED;

kmem_cache_t *lustre_dquot_cachep;

int lustre_dquot_init(void)
{
        int i;
        ENTRY;

        LASSERT(lustre_dquot_cachep == NULL);
        lustre_dquot_cachep = kmem_cache_create("lustre_dquot_cache",
                                                sizeof(struct lustre_dquot),
                                                0, 0, NULL, NULL);
        if (!lustre_dquot_cachep)
                return (-ENOMEM);

        for (i = 0; i < NR_DQHASH; i++) {
                INIT_LIST_HEAD(lustre_dquot_hash + i);
        }
        RETURN(0);
}

void lustre_dquot_exit(void)
{
        int i;
        ENTRY;
        /* FIXME cleanup work ?? */

        for (i = 0; i < NR_DQHASH; i++) {
                LASSERT(list_empty(lustre_dquot_hash + i));
        }
        if (lustre_dquot_cachep) {
                LASSERTF(kmem_cache_destroy(lustre_dquot_cachep) == 0,
                         "Cannot destroy lustre_dquot_cache\n");
                lustre_dquot_cachep = NULL;
        }
        EXIT;
}

static inline int const dquot_hashfn(struct lustre_quota_info *info,
                                     unsigned int id, int type)
{
        unsigned long tmp = ((unsigned long)info >> L1_CACHE_SHIFT) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

static struct lustre_dquot *find_dquot(int hashent,
                                       struct lustre_quota_info *lqi, qid_t id,
                                       int type)
{
        struct list_head *head;
        struct lustre_dquot *dquot;
        ENTRY;

        for (head = lustre_dquot_hash[hashent].next;
             head != lustre_dquot_hash + hashent; head = head->next) {
                dquot = list_entry(head, struct lustre_dquot, dq_hash);
                if (dquot->dq_info == lqi &&
                    dquot->dq_id == id && dquot->dq_type == type)
                        RETURN(dquot);
        }
        RETURN(NULL);
}

static struct lustre_dquot *alloc_dquot(struct lustre_quota_info *lqi,
                                        qid_t id, int type)
{
        struct lustre_dquot *dquot = NULL;
        ENTRY;

        OBD_SLAB_ALLOC(dquot, lustre_dquot_cachep, SLAB_NOFS, sizeof(*dquot));
        if (dquot == NULL)
                RETURN(NULL);

        INIT_LIST_HEAD(&dquot->dq_hash);
        INIT_LIST_HEAD(&dquot->dq_unused);
        sema_init(&dquot->dq_sem, 1);
        atomic_set(&dquot->dq_refcnt, 1);
        dquot->dq_info = lqi;
        dquot->dq_id = id;
        dquot->dq_type = type;

        RETURN(dquot);
}

static void free_dquot(struct lustre_dquot *dquot)
{
        OBD_SLAB_FREE(dquot, lustre_dquot_cachep, sizeof(*dquot));
}

static void insert_dquot_nolock(struct lustre_dquot *dquot)
{
        struct list_head *head = lustre_dquot_hash +
            dquot_hashfn(dquot->dq_info, dquot->dq_id, dquot->dq_type);
        list_add(&dquot->dq_hash, head);
}

static void remove_dquot_nolock(struct lustre_dquot *dquot)
{
        LASSERT(!list_empty(&dquot->dq_hash));
        list_del_init(&dquot->dq_hash);
}

static void lustre_dqput(struct lustre_dquot *dquot)
{
        ENTRY;
        spin_lock(&dquot_hash_lock);
        LASSERT(atomic_read(&dquot->dq_refcnt));
        if (atomic_dec_and_test(&dquot->dq_refcnt)) {
                remove_dquot_nolock(dquot);
                free_dquot(dquot);
        }
        spin_unlock(&dquot_hash_lock);
        EXIT;
}

#define DQUOT_DEBUG(dquot, fmt, arg...)                                       \
        CDEBUG(D_QUOTA, "refcnt(%u) id(%u) type(%u) off(%llu) flags(%lu) " \
               "bhardlimit(%u) curspace("LPX64") ihardlimit(%u) "             \
               "curinodes(%u): " fmt, atomic_read(&dquot->dq_refcnt),         \
               dquot->dq_id, dquot->dq_type, dquot->dq_off,  dquot->dq_flags, \
               dquot->dq_dqb.dqb_bhardlimit, dquot->dq_dqb.dqb_curspace,      \
               dquot->dq_dqb.dqb_ihardlimit, dquot->dq_dqb.dqb_curinodes,     \
               ## arg);                                                       \

#define QINFO_DEBUG(qinfo, fmt, arg...)                                       \
        CDEBUG(D_QUOTA, "files (%p/%p) flags(%lu/%lu) blocks(%u/%u) "         \
               "free_blk(/%u/%u) free_entry(%u/%u): " fmt,                    \
               qinfo->qi_files[0], qinfo->qi_files[1],                        \
               qinfo->qi_info[0].dqi_flags, qinfo->qi_info[1].dqi_flags,      \
               qinfo->qi_info[0].dqi_blocks, qinfo->qi_info[1].dqi_blocks,    \
               qinfo->qi_info[0].dqi_free_blk, qinfo->qi_info[1].dqi_free_blk,\
               qinfo->qi_info[0].dqi_free_entry,                              \
               qinfo->qi_info[1].dqi_free_entry, ## arg);

static struct lustre_dquot *lustre_dqget(struct obd_device *obd,
                                         struct lustre_quota_info *lqi,
                                         qid_t id, int type)
{
        unsigned int hashent = dquot_hashfn(lqi, id, type);
        struct lustre_dquot *dquot = NULL;
        int read = 0;
        ENTRY;

        spin_lock(&dquot_hash_lock);
        if ((dquot = find_dquot(hashent, lqi, id, type)) != NULL) {
                atomic_inc(&dquot->dq_refcnt);
        } else {
                dquot = alloc_dquot(lqi, id, type);
                if (dquot) {
                        insert_dquot_nolock(dquot);
                        read = 1;
                }
        }
        spin_unlock(&dquot_hash_lock);

        if (dquot == NULL)
                RETURN(ERR_PTR(-ENOMEM));

        if (read) {
                int rc = 0;

                down(&dquot->dq_info->qi_sem);
                down(&dquot->dq_sem);
                rc = fsfilt_dquot(obd, dquot, QFILE_RD_DQUOT);
                up(&dquot->dq_sem);
                up(&dquot->dq_info->qi_sem);
                if (rc) {
                        CERROR("can't read dquot from admin qutoafile! "
                               "(rc:%d)\n", rc);
                        lustre_dqput(dquot);
                        RETURN(ERR_PTR(rc));
                }
        }
        RETURN(dquot);
}

int dqacq_handler(struct obd_device *obd, struct qunit_data *qdata, int opc)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *info = &mds->mds_quota_info;
        struct lustre_dquot *dquot = NULL;
        __u64 *usage = NULL;
        __u32 *limit = NULL;
        int rc = 0;
        ENTRY;

        dquot = lustre_dqget(obd, info, qdata->qd_id, qdata->qd_type);
        if (IS_ERR(dquot))
                RETURN(PTR_ERR(dquot));

        DQUOT_DEBUG(dquot, "get dquot in dqacq_handler\n");
        QINFO_DEBUG(dquot->dq_info, "get dquot in dqadq_handler\n");

        down(&dquot->dq_info->qi_sem);
        down(&dquot->dq_sem);

        if (qdata->qd_isblk) {
                usage = &dquot->dq_dqb.dqb_curspace;
                limit = &dquot->dq_dqb.dqb_bhardlimit;
        } else {
                usage = (__u64 *) & dquot->dq_dqb.dqb_curinodes;
                limit = &dquot->dq_dqb.dqb_ihardlimit;
        }

        /* if the quota limit in admin quotafile is zero, we just inform
         * slave to clear quota limit with zero qd_count */
        if (*limit == 0) {
                qdata->qd_count = 0;
                GOTO(out, rc);
        }
        if (opc == QUOTA_DQACQ) {
                if (QUSG(*usage + qdata->qd_count, qdata->qd_isblk) > *limit)
                        GOTO(out, rc = -EDQUOT);
                else
                        *usage += qdata->qd_count;
        } else if (opc == QUOTA_DQREL) {
                LASSERT(*usage - qdata->qd_count >= 0);
                *usage -= qdata->qd_count;
        } else {
                LBUG();
        }

        rc = fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);
out:
        up(&dquot->dq_sem);
        up(&dquot->dq_info->qi_sem);
        lustre_dqput(dquot);
        RETURN(rc);
}

void mds_adjust_qunit(struct obd_device *obd, uid_t cuid, gid_t cgid,
                      uid_t puid, gid_t pgid, int rc)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_ctxt *qctxt = &mds->mds_quota_ctxt;
        ENTRY;

        if (rc && rc != -EDQUOT) {
                EXIT;
                return;
        }
        /* dqacq/dqrel file quota on owner of child */
        rc = qctxt_adjust_qunit(obd, qctxt, cuid, cgid, 0);
        if (rc)
                CERROR("error mds adjust child qunit! (rc:%d)\n", rc);
        /* dqacq/dqrel block quota on owner of parent directory */
        rc = qctxt_adjust_qunit(obd, qctxt, puid, pgid, 1);
        if (rc)
                CERROR("error mds adjust parent qunit! (rc:%d)\n", rc);
        EXIT;
}

int init_admin_quotafiles(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        const char *quotafiles[] = LUSTRE_ADMIN_QUOTAFILES;
        struct obd_run_ctxt saved;
        char name[64];
        int i, rc = 0;
        struct dentry *dparent = mds->mds_objects_dir;
        struct inode *iparent = dparent->d_inode;
        ENTRY;

        LASSERT(iparent);
        push_ctxt(&saved, &obd->obd_ctxt, NULL);

        down(&qinfo->qi_sem);
        for (i = 0; i < MAXQUOTAS; i++) {
                struct dentry *de = NULL;
                struct file *fp = NULL;

                if (!Q_TYPESET(oqctl, i))
                        continue;

                /* quota file has been opened ? */
                if (qinfo->qi_files[i]) {
                        CWARN("init %s admin quotafile while quota on.\n",
                              i == USRQUOTA ? "user" : "group");
                        continue;
                }

                /* lookup quota file */
                rc = 0;
                down(&iparent->i_sem);

                de = lookup_one_len(quotafiles[i], dparent,
                                    strlen(quotafiles[i]));
                if (IS_ERR(de) || de->d_inode == NULL)
                        rc = IS_ERR(de) ? PTR_ERR(de) : -ENOENT;
                if (!IS_ERR(de))
                        dput(de);
                up(&iparent->i_sem);

                if (rc && rc != -ENOENT) {
                        CERROR("error lookup quotafile %s! (rc:%d)\n",
                               name, rc);
                        break;
                } else if (!rc) {
                        continue;
                }

                sprintf(name, "OBJECTS/%s", quotafiles[i]);

                LASSERT(rc == -ENOENT);
                /* create quota file */
                fp = filp_open(name, O_CREAT | O_EXCL, 0644);
                if (IS_ERR(fp)) {
                        rc = PTR_ERR(fp);
                        CERROR("error creating admin quotafile %s (rc:%d)\n",
                               name, rc);
                        break;
                }

                qinfo->qi_files[i] = fp;
                rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_INIT_INFO);
                filp_close(fp, 0);
                qinfo->qi_files[i] = NULL;

                if (rc) {
                        CERROR("error init %s admin quotafile! (rc:%d)\n",
                               i == USRQUOTA ? "user" : "group", rc);
                        break;
                }
        }
        up(&qinfo->qi_sem);

        pop_ctxt(&saved, &obd->obd_ctxt, NULL);
        RETURN(rc);
}

int mds_quota_on(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        const char *quotafiles[] = LUSTRE_ADMIN_QUOTAFILES;
        struct obd_run_ctxt saved;
        char name[64];
        int i, rc = 0;
        struct inode *iparent = mds->mds_objects_dir->d_inode;
        ENTRY;

        LASSERT(iparent);
        push_ctxt(&saved, &obd->obd_ctxt, NULL);

        down(&qinfo->qi_sem);
        /* open admin quota files and read quotafile info */
        for (i = 0; i < MAXQUOTAS; i++) {
                struct file *fp = NULL;

                if (!Q_TYPESET(oqctl, i))
                        continue;

                sprintf(name, "OBJECTS/%s", quotafiles[i]);

                if (qinfo->qi_files[i] != NULL) {
                        rc = -EBUSY;
                        break;
                }

                fp = filp_open(name, O_RDWR | O_EXCL, 0644);
                if (IS_ERR(fp)) {
                        rc = PTR_ERR(fp);
                        CERROR("error open %s! (rc:%d)\n", name, rc);
                        break;
                }
                qinfo->qi_files[i] = fp;

                rc = fsfilt_quotainfo(obd, qinfo, i, QFILE_RD_INFO);
                if (rc) {
                        CERROR("error read quotainfo of %s! (rc:%d)\n",
                               name, rc);
                        break;
                }
        }
        up(&qinfo->qi_sem);

        pop_ctxt(&saved, &obd->obd_ctxt, NULL);

        if (rc && rc != -EBUSY) {
                down(&qinfo->qi_sem);
                for (i = 0; i < MAXQUOTAS; i++) {
                        if (!Q_TYPESET(oqctl, i))
                                continue;
                        if (qinfo->qi_files[i])
                                filp_close(qinfo->qi_files[i], 0);
                        qinfo->qi_files[i] = NULL;
                }
                up(&qinfo->qi_sem);
        }
        RETURN(rc);
}

int mds_quota_off(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        int i, rc = 0;
        ENTRY;

        down(&qinfo->qi_sem);
        /* close admin quota files */
        for (i = 0; i < MAXQUOTAS; i++) {
                if (!Q_TYPESET(oqctl, i))
                        continue;

                if (qinfo->qi_files[i] == NULL) {
                        rc = -ESRCH;
                        continue;
                }
                filp_close(qinfo->qi_files[i], 0);
                qinfo->qi_files[i] = NULL;
        }
        up(&qinfo->qi_sem);

        RETURN(rc);
}

int mds_set_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        struct obd_dqinfo *dqinfo = &oqctl->qc_dqinfo;
        int rc = 0;
        ENTRY;

        if (qinfo->qi_files[oqctl->qc_type] == NULL)
                RETURN(-ESRCH);

        down(&qinfo->qi_sem);
        qinfo->qi_info[oqctl->qc_type].dqi_bgrace = dqinfo->dqi_bgrace;
        qinfo->qi_info[oqctl->qc_type].dqi_igrace = dqinfo->dqi_igrace;
        qinfo->qi_info[oqctl->qc_type].dqi_flags = dqinfo->dqi_flags;

        rc = fsfilt_quotainfo(obd, qinfo, oqctl->qc_type, QFILE_WR_INFO);
        up(&qinfo->qi_sem);

        RETURN(rc);
}

int mds_get_dqinfo(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        struct obd_dqinfo *dqinfo = &oqctl->qc_dqinfo;
        ENTRY;

        if (qinfo->qi_files[oqctl->qc_type] == NULL)
                RETURN(-ESRCH);

        down(&qinfo->qi_sem);
        dqinfo->dqi_bgrace = qinfo->qi_info[oqctl->qc_type].dqi_bgrace;
        dqinfo->dqi_igrace = qinfo->qi_info[oqctl->qc_type].dqi_igrace;
        dqinfo->dqi_flags = qinfo->qi_info[oqctl->qc_type].dqi_flags;
        up(&qinfo->qi_sem);

        RETURN(0);
}

static int mds_init_slave_ilimits(struct obd_device *obd,
                                  struct obd_quotactl *oqctl)
{
        /* XXX: for file limits only adjust local now */
        struct mds_obd *mds = &obd->u.mds;
        unsigned int uid = 0, gid = 0;
        struct obd_quotactl *ioqc;
        int rc;
        ENTRY;

        /* if we are going to set zero limit, needn't init slaves */
        if (!oqctl->qc_dqblk.dqb_ihardlimit)
                RETURN(0);

        OBD_ALLOC(ioqc, sizeof(*ioqc));
        if (!ioqc)
                RETURN(-ENOMEM);

        ioqc->qc_cmd = Q_SETQUOTA;
        ioqc->qc_id = oqctl->qc_id;
        ioqc->qc_type = oqctl->qc_type;
        ioqc->qc_dqblk.dqb_valid = QIF_ILIMITS;
        ioqc->qc_dqblk.dqb_ihardlimit = MIN_QLIMIT;

        /* set local limit to MIN_QLIMIT */
        rc = fsfilt_quotactl(obd, mds->mds_sb, ioqc);
        if (rc)
                GOTO(out, rc);

        /* trigger local qunit pre-acquire */
        if (oqctl->qc_type == USRQUOTA)
                uid = oqctl->qc_id;
        else
                gid = oqctl->qc_id;

        rc = qctxt_adjust_qunit(obd, &mds->mds_quota_ctxt, uid, gid, 0);
        if (rc) {
                CERROR("error mds adjust local file quota! (rc:%d)\n", rc);
                GOTO(out, rc);
        }
        /* FIXME initialize all slaves in CMD */
out:
        OBD_FREE(ioqc, sizeof(*ioqc));
        RETURN(rc);
}

static int mds_init_slave_blimits(struct obd_device *obd,
                                  struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_quotactl *ioqc;
        unsigned int uid = 0, gid = 0;
        int rc;
        ENTRY;

        /* if we are going to set zero limit, needn't init slaves */
        if (!oqctl->qc_dqblk.dqb_bhardlimit)
                RETURN(0);

        OBD_ALLOC(ioqc, sizeof(*ioqc));
        if (!ioqc)
                RETURN(-ENOMEM);

        ioqc->qc_cmd = Q_SETQUOTA;
        ioqc->qc_id = oqctl->qc_id;
        ioqc->qc_type = oqctl->qc_type;
        ioqc->qc_dqblk.dqb_valid = QIF_BLIMITS;
        ioqc->qc_dqblk.dqb_bhardlimit = MIN_QLIMIT;

        /* set local limit to MIN_QLIMIT */
        rc = fsfilt_quotactl(obd, mds->mds_sb, ioqc);
        if (rc)
                GOTO(out, rc);

        /* trigger local qunit pre-acquire */
        if (oqctl->qc_type == USRQUOTA)
                uid = oqctl->qc_id;
        else
                gid = oqctl->qc_id;

        rc = qctxt_adjust_qunit(obd, &mds->mds_quota_ctxt, uid, gid, 1);
        if (rc) {
                CERROR("error mds adjust local block quota! (rc:%d)\n", rc);
                GOTO(out, rc);
        }

        /* initialize all slave's limit */
        ioqc->qc_cmd = Q_INITQUOTA;
        rc = obd_quotactl(mds->mds_osc_exp, ioqc);
out:
        OBD_FREE(ioqc, sizeof(*ioqc));
        RETURN(rc);
}

int mds_set_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        __u32 ihardlimit, isoftlimit, bhardlimit, bsoftlimit;
        time_t btime, itime;
        struct lustre_dquot *dquot;
        struct obd_dqblk *dqblk = &oqctl->qc_dqblk;
        int rc = 0;
        ENTRY;

        if (qinfo->qi_files[oqctl->qc_type] == NULL)
                RETURN(-ESRCH);

        dquot = lustre_dqget(obd, qinfo, oqctl->qc_id, oqctl->qc_type);
        if (IS_ERR(dquot))
                RETURN(PTR_ERR(dquot));
        DQUOT_DEBUG(dquot, "get dquot in mds_set_blk\n");
        QINFO_DEBUG(dquot->dq_info, "get dquot in mds_set_blk\n");

        down(&dquot->dq_info->qi_sem);
        down(&dquot->dq_sem);

        ihardlimit = dquot->dq_dqb.dqb_ihardlimit;
        isoftlimit = dquot->dq_dqb.dqb_isoftlimit;
        bhardlimit = dquot->dq_dqb.dqb_bhardlimit;
        bsoftlimit = dquot->dq_dqb.dqb_bsoftlimit;
        btime = dquot->dq_dqb.dqb_btime;
        itime = dquot->dq_dqb.dqb_itime;

        if (dqblk->dqb_valid & QIF_BLIMITS) {
                dquot->dq_dqb.dqb_bhardlimit = dqblk->dqb_bhardlimit;
                dquot->dq_dqb.dqb_bsoftlimit = dqblk->dqb_bsoftlimit;
                /* clear usage (limit pool) */
                if (dquot->dq_dqb.dqb_bhardlimit == 0)
                        dquot->dq_dqb.dqb_curspace = 0;
        }

        if (dqblk->dqb_valid & QIF_ILIMITS) {
                dquot->dq_dqb.dqb_ihardlimit = dqblk->dqb_ihardlimit;
                dquot->dq_dqb.dqb_isoftlimit = dqblk->dqb_isoftlimit;
                /* clear usage (limit pool) */
                if (dquot->dq_dqb.dqb_ihardlimit == 0)
                        dquot->dq_dqb.dqb_curinodes = 0;
        }

        if (dqblk->dqb_valid & QIF_BTIME)
                dquot->dq_dqb.dqb_btime = dqblk->dqb_btime;

        if (dqblk->dqb_valid & QIF_ITIME)
                dquot->dq_dqb.dqb_itime = dqblk->dqb_itime;

        rc = fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);

        up(&dquot->dq_sem);
        up(&dquot->dq_info->qi_sem);

        if (rc)
                GOTO(out, rc);

        if (dqblk->dqb_valid & QIF_ILIMITS && !ihardlimit) {
                rc = mds_init_slave_ilimits(obd, oqctl);
                if (rc) {
                        CERROR("init slave ilimits failed! (rc:%d)\n", rc);
                        GOTO(revoke_out, rc);
                }
        }

        if (dqblk->dqb_valid & QIF_BLIMITS && !bhardlimit) {
                rc = mds_init_slave_blimits(obd, oqctl);
                if (rc) {
                        CERROR("init slave blimits failed! (rc:%d)\n", rc);
                        GOTO(revoke_out, rc);
                }
        }

revoke_out:
        if (rc) {
                /* cancel previous setting */
                down(&dquot->dq_info->qi_sem);
                down(&dquot->dq_sem);
                dquot->dq_dqb.dqb_ihardlimit = ihardlimit;
                dquot->dq_dqb.dqb_isoftlimit = isoftlimit;
                dquot->dq_dqb.dqb_bhardlimit = bhardlimit;
                dquot->dq_dqb.dqb_bsoftlimit = bsoftlimit;
                dquot->dq_dqb.dqb_btime = btime;
                dquot->dq_dqb.dqb_itime = itime;
                fsfilt_dquot(obd, dquot, QFILE_WR_DQUOT);
                up(&dquot->dq_sem);
                up(&dquot->dq_info->qi_sem);
        }
out:
        lustre_dqput(dquot);
        RETURN(rc);
}

static int mds_get_space(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct obd_quotactl *soqc;
        int rc;

        OBD_ALLOC(soqc, sizeof(*soqc));
        if (!soqc)
                RETURN(-ENOMEM);

        soqc->qc_cmd = oqctl->qc_cmd;
        soqc->qc_id = oqctl->qc_id;
        soqc->qc_type = oqctl->qc_type;

        rc = obd_quotactl(obd->u.mds.mds_osc_exp, soqc);

        oqctl->qc_dqblk.dqb_curspace = soqc->qc_dqblk.dqb_curspace;

        OBD_FREE(soqc, sizeof(*soqc));
        return rc;
}

int mds_get_dqblk(struct obd_device *obd, struct obd_quotactl *oqctl)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_quota_info *qinfo = &mds->mds_quota_info;
        struct lustre_dquot *dquot;
        struct obd_dqblk *dqblk = &oqctl->qc_dqblk;
        int rc;
        ENTRY;

        if (qinfo->qi_files[oqctl->qc_type] == NULL)
                RETURN(-ESRCH);

        dquot = lustre_dqget(obd, qinfo, oqctl->qc_id, oqctl->qc_type);
        if (IS_ERR(dquot))
                RETURN(PTR_ERR(dquot));

        down(&dquot->dq_sem);
        dqblk->dqb_ihardlimit = dquot->dq_dqb.dqb_ihardlimit;
        dqblk->dqb_isoftlimit = dquot->dq_dqb.dqb_isoftlimit;
        dqblk->dqb_bhardlimit = dquot->dq_dqb.dqb_bhardlimit;
        dqblk->dqb_bsoftlimit = dquot->dq_dqb.dqb_bsoftlimit;
        dqblk->dqb_btime = dquot->dq_dqb.dqb_btime;
        dqblk->dqb_itime = dquot->dq_dqb.dqb_itime;
        up(&dquot->dq_sem);

        /* the usages in admin quota file is inaccurate */
        dqblk->dqb_curinodes = 0;
        dqblk->dqb_curspace = 0;
        rc = mds_get_space(obd, oqctl);

        lustre_dqput(dquot);
        RETURN(rc);
}
