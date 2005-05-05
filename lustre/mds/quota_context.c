/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mds/quota_context.c
 *  Lustre Quota Context
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

#include <linux/obd_class.h>
#include <linux/lustre_quota.h>
#include <linux/lustre_fsfilt.h>

const unsigned long default_bunit_sz = 100 * 1024 * 1024;       /* 100M bytes */
const unsigned long default_btune_sz = 50 * 1024 * 1024;        /* 50M bytes */
const unsigned long default_iunit_sz = 5000;    /* 5000 inodes */
const unsigned long default_itune_sz = 2500;    /* 2500 inodes */

static inline int const
qunit_hashfn(struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata)
{
        unsigned int id = qdata->qd_id;
        unsigned int type = qdata->qd_type;

        unsigned long tmp = ((unsigned long)qctxt >> L1_CACHE_SHIFT) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

static inline struct lustre_qunit *find_qunit(unsigned int hashent,
                                              struct lustre_quota_ctxt *qctxt,
                                              struct qunit_data *qdata)
{
        struct list_head *pos;
        struct lustre_qunit *qunit = NULL;
        struct qunit_data *tmp;

        list_for_each(pos, qunit_hash + hashent) {
                qunit = list_entry(pos, struct lustre_qunit, lq_hash);
                tmp = &qunit->lq_data;
                if (qunit->lq_ctxt == qctxt &&
                    qdata->qd_id == tmp->qd_id && qdata->qd_type == tmp->qd_type
                    && qdata->qd_isblk == tmp->qd_isblk)
                        return qunit;
        }
        return NULL;
}

/* check_cur_qunit - check the current usage of qunit.
 * @qctxt: quota context
 * @qdata: the type of quota unit to be checked
 *
 * return: 1 - need acquire qunit;
 * 	   2 - need release qunit;
 * 	   0 - need do nothing.
 * 	 < 0 - error.
 */
static int
check_cur_qunit(struct obd_device *obd,
                struct lustre_quota_ctxt *qctxt, struct qunit_data *qdata)
{
        struct super_block *sb = qctxt->lqc_sb;
        unsigned long qunit_sz, tune_sz;
        __u64 usage, limit;
        struct obd_quotactl *qctl = NULL;
        int ret = 0;
        ENTRY;

        if (!sb_any_quota_enabled(sb))
                RETURN(0);

        /* ignore root user */
        if (qdata->qd_id == 0 && qdata->qd_type == USRQUOTA)
                RETURN(0);

        OBD_ALLOC(qctl, sizeof(*qctl));
        if (qctl == NULL)
                RETURN(-ENOMEM);

        /* get fs quota usage & limit */
        qctl->qc_cmd = Q_GETQUOTA;
        qctl->qc_id = qdata->qd_id;
        qctl->qc_type = qdata->qd_type;
        ret = fsfilt_quotactl(obd, sb, qctl);
        if (ret) {
                if (ret == -ESRCH)      /* no limit */
                        ret = 0;
                else
                        CERROR("can't get fs quota usage! (rc:%d)\n", ret);
                GOTO(out, ret);
        }

        if (qdata->qd_isblk) {
                usage = qctl->qc_dqblk.dqb_curspace;
                limit = qctl->qc_dqblk.dqb_bhardlimit;
                qunit_sz = qctxt->lqc_bunit_sz;
                tune_sz = qctxt->lqc_btune_sz;

                LASSERT(!(qunit_sz % QUOTABLOCK_SIZE));
                LASSERT(limit == MIN_QLIMIT
                        || !((__u32) limit % toqb(qunit_sz)));
                limit = limit << QUOTABLOCK_BITS;
        } else {
                usage = qctl->qc_dqblk.dqb_curinodes;
                limit = qctl->qc_dqblk.dqb_ihardlimit;
                qunit_sz = qctxt->lqc_iunit_sz;
                tune_sz = qctxt->lqc_itune_sz;
        }

        /* if it's not first time to set quota, ignore the no quota limit
         * case */
        if (!limit)
                GOTO(out, ret = 0);

        /* we don't count the MIN_QLIMIT */
        if ((limit == MIN_QLIMIT && !qdata->qd_isblk) ||
            (toqb(limit) == MIN_QLIMIT && qdata->qd_isblk))
                limit = 0;

        LASSERT(qdata->qd_count == 0);
        if (limit <= usage + tune_sz) {
                while (qdata->qd_count + limit <= usage + tune_sz)
                        qdata->qd_count += qunit_sz;
                ret = 1;
        } else if (limit > usage + qunit_sz + tune_sz) {
                while (limit - qdata->qd_count > usage + qunit_sz + tune_sz)
                        qdata->qd_count += qunit_sz;
                ret = 2;
        }
        LASSERT(ret == 0 || qdata->qd_count);
out:
        OBD_FREE(qctl, sizeof(*qctl));
        RETURN(ret);
}

/* must hold qctxt->lqc_qunit_lock */
static struct lustre_qunit *dqacq_in_flight(struct lustre_quota_ctxt *qctxt,
                                            struct qunit_data *qdata)
{
        unsigned int hashent = qunit_hashfn(qctxt, qdata);
        struct lustre_qunit *qunit = NULL;
        ENTRY;

        qunit = find_qunit(hashent, qctxt, qdata);
        RETURN(qunit);
}

static struct lustre_qunit *alloc_qunit(struct lustre_quota_ctxt *qctxt,
                                        struct qunit_data *qdata, int opc)
{
        struct lustre_qunit *qunit = NULL;
        ENTRY;

        OBD_SLAB_ALLOC(qunit, qunit_cachep, SLAB_NOFS, sizeof(*qunit));
        if (qunit == NULL)
                RETURN(NULL);

        INIT_LIST_HEAD(&qunit->lq_hash);
        INIT_LIST_HEAD(&qunit->lq_waiters);
        atomic_set(&qunit->lq_refcnt, 1);
        qunit->lq_ctxt = qctxt;
        memcpy(&qunit->lq_data, qdata, sizeof(*qdata));
        qunit->lq_opc = opc;

        RETURN(qunit);
}

static inline void free_qunit(struct lustre_qunit *qunit)
{
        OBD_SLAB_FREE(qunit, qunit_cachep, sizeof(*qunit));
}

static inline void qunit_get(struct lustre_qunit *qunit)
{
        atomic_inc(&qunit->lq_refcnt);
}

static void qunit_put(struct lustre_qunit *qunit)
{
        LASSERT(atomic_read(&qunit->lq_refcnt));
        if (atomic_dec_and_test(&qunit->lq_refcnt))
                free_qunit(qunit);
}

static void
insert_qunit_nolock(struct lustre_quota_ctxt *qctxt, struct lustre_qunit *qunit)
{
        struct list_head *head;

        head = qunit_hash + qunit_hashfn(qctxt, &qunit->lq_data);
        list_add(&qunit->lq_hash, head);
}

static void remove_qunit_nolock(struct lustre_qunit *qunit)
{
        LASSERT(!list_empty(&qunit->lq_hash));
        list_del_init(&qunit->lq_hash);
}

struct qunit_waiter {
        struct list_head qw_entry;
        wait_queue_head_t qw_waitq;
        int qw_rc;
};

#define QDATA_DEBUG(qd, fmt, arg...)                                    \
        CDEBUG(D_QUOTA, "id(%u) type(%u) count(%u) isblk(%u):"          \
               fmt, qd->qd_id, qd->qd_type, qd->qd_count, qd->qd_isblk, \
               ## arg);                                                 \

#define INC_QLIMIT(limit, count) (limit == MIN_QLIMIT) ? \
                                 (limit = count) : (limit += count)

static int
dqacq_completion(struct obd_device *obd,
                 struct lustre_quota_ctxt *qctxt,
                 struct qunit_data *qdata, int rc, int opc)
{
        struct lustre_qunit *qunit = NULL;
        struct super_block *sb = qctxt->lqc_sb;
        unsigned long qunit_sz;
        struct list_head *pos, *tmp;
        int err = 0;
        ENTRY;

        LASSERT(qdata);
        qunit_sz =
            (qdata->qd_isblk) ? qctxt->lqc_bunit_sz : qctxt->lqc_iunit_sz;
        LASSERT(!(qdata->qd_count % qunit_sz));

        /* update local operational quota file */
        if (rc == 0) {
                __u32 count = QUSG(qdata->qd_count, qdata->qd_isblk);
                struct obd_quotactl *qctl = NULL;

                OBD_ALLOC(qctl, sizeof(*qctl));
                if (qctl == NULL)
                        GOTO(out, err = -ENOMEM);

                /* acq/rel qunit for specified uid/gid is serialized,
                 * so there is no race between get fs quota limit and
                 * set fs quota limit */
                qctl->qc_cmd = Q_GETQUOTA;
                qctl->qc_id = qdata->qd_id;
                qctl->qc_type = qdata->qd_type;
                err = fsfilt_quotactl(obd, sb, qctl);
                if (err) {
                        CERROR("error get quota fs limit! (rc:%d)\n", err);
                        GOTO(out_mem, err);
                }

                switch (opc) {
                case QUOTA_DQACQ:
                        if (qdata->qd_isblk) {
                                qctl->qc_dqblk.dqb_valid = QIF_BLIMITS;
                                INC_QLIMIT(qctl->qc_dqblk.dqb_bhardlimit,
                                           count);
                        } else {
                                qctl->qc_dqblk.dqb_valid = QIF_ILIMITS;
                                INC_QLIMIT(qctl->qc_dqblk.dqb_ihardlimit,
                                           count);
                        }
                        break;
                case QUOTA_DQREL:
                        if (qdata->qd_isblk) {
                                LASSERT(count < qctl->qc_dqblk.dqb_bhardlimit);
                                qctl->qc_dqblk.dqb_valid = QIF_BLIMITS;
                                qctl->qc_dqblk.dqb_bhardlimit -= count;
                        } else {
                                LASSERT(count < qctl->qc_dqblk.dqb_ihardlimit);
                                qctl->qc_dqblk.dqb_valid = QIF_ILIMITS;
                                qctl->qc_dqblk.dqb_ihardlimit -= count;
                        }
                        break;
                default:
                        LBUG();
                        break;
                }

                /* clear quota limit */
                if (count == 0) {
                        if (qdata->qd_isblk)
                                qctl->qc_dqblk.dqb_bhardlimit = 0;
                        else
                                qctl->qc_dqblk.dqb_ihardlimit = 0;
                }

                qctl->qc_cmd = Q_SETQUOTA;
                err = fsfilt_quotactl(obd, sb, qctl);
                if (err)
                        CERROR("error set quota fs limit! (rc:%d)\n", err);

                QDATA_DEBUG(qdata, "%s completion\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
out_mem:
                OBD_FREE(qctl, sizeof(*qctl));
        } else if (rc == -EDQUOT) {
                CWARN("acquire qunit got EDQUOT\n");
        } else {
                CERROR("acquire qunit got error! (rc:%d)\n", rc);
        }
out:
        /* remove the qunit from hash */
        spin_lock(&qunit_hash_lock);

        qunit = dqacq_in_flight(qctxt, qdata);

        LASSERT(qunit);
        LASSERT(opc == qunit->lq_opc);
        remove_qunit_nolock(qunit);

        /* wake up all waiters */
        list_for_each_safe(pos, tmp, &qunit->lq_waiters) {
                struct qunit_waiter *qw = list_entry(pos, struct qunit_waiter,
                                                     qw_entry);
                list_del_init(&qw->qw_entry);
                qw->qw_rc = rc;
                wake_up(&qw->qw_waitq);
        }

        spin_unlock(&qunit_hash_lock);

        qunit_put(qunit);
        RETURN(err);
}

struct dqacq_async_args {
        struct lustre_quota_ctxt *aa_ctxt;
        struct lustre_qunit *aa_qunit;
};

static int dqacq_interpret(struct ptlrpc_request *req, void *data, int rc)
{
        struct dqacq_async_args *aa = (struct dqacq_async_args *)data;
        struct lustre_quota_ctxt *qctxt = aa->aa_ctxt;
        struct lustre_qunit *qunit = aa->aa_qunit;
        struct obd_device *obd = req->rq_import->imp_obd;
        struct qunit_data *qdata = NULL;
        ENTRY;

        qdata = lustre_swab_repbuf(req, 0, sizeof(*qdata), lustre_swab_qdata);
        if (rc == 0 && qdata == NULL)
                RETURN(-EPROTO);

        LASSERT(qdata->qd_id == qunit->lq_data.qd_id &&
                qdata->qd_type == qunit->lq_data.qd_type &&
                (qdata->qd_count == qunit->lq_data.qd_count ||
                 qdata->qd_count == 0));

        QDATA_DEBUG(qdata, "%s interpret rc(%d).\n",
                    req->rq_reqmsg->opc == QUOTA_DQACQ ? "DQACQ" : "DQREL", rc);

        rc = dqacq_completion(obd, qctxt, qdata, rc, req->rq_reqmsg->opc);

        RETURN(rc);
}

static int got_qunit(struct qunit_waiter *waiter)
{
        int rc = 0;
        ENTRY;
        spin_lock(&qunit_hash_lock);
        rc = list_empty(&waiter->qw_entry);
        spin_unlock(&qunit_hash_lock);
        RETURN(rc);
}

static int
schedule_dqacq(struct obd_device *obd,
               struct lustre_quota_ctxt *qctxt,
               struct qunit_data *qdata, int opc, int wait)
{
        struct lustre_qunit *qunit = NULL;
        struct qunit_waiter qw;
        struct l_wait_info lwi = { 0 };
        int rc = 0;
        ENTRY;

        INIT_LIST_HEAD(&qw.qw_entry);
        init_waitqueue_head(&qw.qw_waitq);
        qw.qw_rc = 0;

        spin_lock(&qunit_hash_lock);

        qunit = dqacq_in_flight(qctxt, qdata);
        if (qunit && wait) {
                list_add_tail(&qw.qw_entry, &qunit->lq_waiters);
                spin_unlock(&qunit_hash_lock);
                goto wait_completion;
        } else if (qunit && !wait) {
                qunit = NULL;
        } else if (!qunit && (qunit = alloc_qunit(qctxt, qdata, opc)) != NULL)
                insert_qunit_nolock(qctxt, qunit);

        spin_unlock(&qunit_hash_lock);

        if (qunit) {
                struct ptlrpc_request *req;
                struct qunit_data *reqdata;
                struct dqacq_async_args *aa;
                int size = sizeof(*reqdata);

                /* master is going to dqacq/dqrel from itself */
                if (qctxt->lqc_handler) {
                        int rc2;
                        QDATA_DEBUG(qdata, "local %s.\n",
                                    opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
                        rc = qctxt->lqc_handler(obd, qdata, opc);
                        rc2 = dqacq_completion(obd, qctxt, qdata, rc, opc);
                        RETURN((rc && rc != -EDQUOT) ? rc : rc2);
                }

                /* build dqacq/dqrel request */
                LASSERT(qctxt->lqc_import);
                req = ptlrpc_prep_req(qctxt->lqc_import, opc, 1, &size, NULL);
                if (!req)
                        RETURN(-ENOMEM);

                reqdata = lustre_msg_buf(req->rq_reqmsg, 0, sizeof(*reqdata));
                memcpy(reqdata, qdata, sizeof(*reqdata));
                size = sizeof(*reqdata);
                req->rq_replen = lustre_msg_size(1, &size);

                LASSERT(sizeof(*aa) <= sizeof(req->rq_async_args));
                aa = (struct dqacq_async_args *)&req->rq_async_args;
                aa->aa_ctxt = qctxt;
                aa->aa_qunit = qunit;

                req->rq_interpret_reply = dqacq_interpret;
                ptlrpcd_add_req(req);

                QDATA_DEBUG(qdata, "%s scheduled.\n",
                            opc == QUOTA_DQACQ ? "DQACQ" : "DQREL");
        }
wait_completion:
        if (wait && qunit) {
                struct qunit_data *p = &qunit->lq_data;
                QDATA_DEBUG(p, "wait for dqacq.\n");

                l_wait_event(qw.qw_waitq, got_qunit(&qw), &lwi);
                if (qw.qw_rc == 0)
                        rc = -EAGAIN;

                QDATA_DEBUG(p, "wait dqacq done. (rc:%d)\n", qw.qw_rc);
        }
        RETURN(rc);
}

int
qctxt_adjust_qunit(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                   uid_t uid, gid_t gid, __u32 isblk)
{
        int ret, rc = 0, i = USRQUOTA;
        struct qunit_data qdata[MAXQUOTAS];
        ENTRY;

        if (!sb_any_quota_enabled(qctxt->lqc_sb))
                RETURN(0);

        qdata[USRQUOTA].qd_id = uid;
        qdata[USRQUOTA].qd_type = USRQUOTA;
        qdata[USRQUOTA].qd_isblk = isblk;
        qdata[USRQUOTA].qd_count = 0;
        qdata[GRPQUOTA].qd_id = gid;
        qdata[GRPQUOTA].qd_type = GRPQUOTA;
        qdata[GRPQUOTA].qd_isblk = isblk;
        qdata[GRPQUOTA].qd_count = 0;

next:
        ret = check_cur_qunit(obd, qctxt, &qdata[i]);
        if (ret > 0) {
                int opc;
                /* need acquire or release */
                opc = ret == 1 ? QUOTA_DQACQ : QUOTA_DQREL;
                ret = schedule_dqacq(obd, qctxt, &qdata[i], opc, 0);
                if (!rc)
                        rc = ret;
        }
        if (++i < MAXQUOTAS)
                goto next;

        RETURN(rc);
}
EXPORT_SYMBOL(qctxt_adjust_qunit);

int
qctxt_wait_on_dqacq(struct obd_device *obd, struct lustre_quota_ctxt *qctxt,
                    uid_t uid, gid_t gid, __u32 isblk)
{
        struct qunit_data qdata[MAXQUOTAS];
        int i = USRQUOTA, ret, rc = -EAGAIN;
        ENTRY;

        if (!sb_any_quota_enabled(qctxt->lqc_sb))
                RETURN(0);

        qdata[USRQUOTA].qd_id = uid;
        qdata[USRQUOTA].qd_type = USRQUOTA;
        qdata[USRQUOTA].qd_isblk = isblk;
        qdata[USRQUOTA].qd_count = 0;
        qdata[GRPQUOTA].qd_id = gid;
        qdata[GRPQUOTA].qd_type = GRPQUOTA;
        qdata[GRPQUOTA].qd_isblk = isblk;
        qdata[GRPQUOTA].qd_count = 0;

next:
        ret = check_cur_qunit(obd, qctxt, &qdata[i]);
        if (ret > 0)
                rc = schedule_dqacq(obd, qctxt, &qdata[i], QUOTA_DQACQ, 1);

        if (++i < MAXQUOTAS)
                goto next;

        RETURN(rc);
}
EXPORT_SYMBOL(qctxt_wait_on_dqacq);

int
qctxt_init(struct lustre_quota_ctxt *qctxt, struct super_block *sb,
           dqacq_handler_t handler)
{
        int rc = 0;
        ENTRY;

        rc = ptlrpcd_addref();
        if (rc)
                RETURN(rc);

        qctxt->lqc_handler = handler;
        qctxt->lqc_sb = sb;
        qctxt->lqc_import = NULL;
        qctxt->lqc_flags = 0;
        qctxt->lqc_bunit_sz = default_bunit_sz;
        qctxt->lqc_btune_sz = default_btune_sz;
        qctxt->lqc_iunit_sz = default_iunit_sz;
        qctxt->lqc_itune_sz = default_itune_sz;

        RETURN(0);
}
EXPORT_SYMBOL(qctxt_init);

void qctxt_cleanup(struct lustre_quota_ctxt *qctxt, int force)
{
        struct list_head *pos, *tmp;
        struct lustre_qunit *qunit;
        int i;
        ENTRY;

        ptlrpcd_decref();

        spin_lock(&qunit_hash_lock);

        for (i = 0; i < NR_DQHASH; i++) {
                list_for_each_safe(pos, tmp, &qunit_hash[i]) {
                        qunit = list_entry(pos, struct lustre_qunit, lq_hash);
                        LASSERT(qunit->lq_ctxt != qctxt);
                }
        }

        spin_unlock(&qunit_hash_lock);
        EXIT;
}
EXPORT_SYMBOL(qctxt_cleanup);
