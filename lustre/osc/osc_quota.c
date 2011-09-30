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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Whamcloud, Inc.
 *
 * Code originally extracted from quota directory
 */
#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_ost.h>
#include "osc_internal.h"

struct osc_quota_info {
        cfs_list_t         oqi_hash; /* hash list */
        struct client_obd *oqi_cli;  /* osc obd */
        unsigned int       oqi_id;   /* uid/gid of a file */
        short              oqi_type; /* quota type */
};

cfs_spinlock_t qinfo_list_lock = CFS_SPIN_LOCK_UNLOCKED;

static cfs_list_t qinfo_hash[NR_DQHASH];
/* SLAB cache for client quota context */
cfs_mem_cache_t *qinfo_cachep = NULL;

static inline int hashfn(struct client_obd *cli, unsigned long id, int type)
                         __attribute__((__const__));

static inline int hashfn(struct client_obd *cli, unsigned long id, int type)
{
        unsigned long tmp = ((unsigned long)cli>>6) ^ id;
        tmp = (tmp * (MAXQUOTAS - type)) % NR_DQHASH;
        return tmp;
}

/* caller must hold qinfo_list_lock */
static inline void insert_qinfo_hash(struct osc_quota_info *oqi)
{
        cfs_list_t *head = qinfo_hash +
                hashfn(oqi->oqi_cli, oqi->oqi_id, oqi->oqi_type);

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        cfs_list_add(&oqi->oqi_hash, head);
}

/* caller must hold qinfo_list_lock */
static inline void remove_qinfo_hash(struct osc_quota_info *oqi)
{
        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        cfs_list_del_init(&oqi->oqi_hash);
}

/* caller must hold qinfo_list_lock */
static inline struct osc_quota_info *find_qinfo(struct client_obd *cli,
                                                unsigned int id, int type)
{
        struct osc_quota_info *oqi;
        unsigned int           hashent = hashfn(cli, id, type);
        ENTRY;

        LASSERT_SPIN_LOCKED(&qinfo_list_lock);
        cfs_list_for_each_entry(oqi, &qinfo_hash[hashent], oqi_hash) {
                if (oqi->oqi_cli == cli &&
                    oqi->oqi_id == id && oqi->oqi_type == type)
                        RETURN(oqi);
        }
        RETURN(NULL);
}

static struct osc_quota_info *alloc_qinfo(struct client_obd *cli,
                                          unsigned int id, int type)
{
        struct osc_quota_info *oqi;
        ENTRY;

        OBD_SLAB_ALLOC(oqi, qinfo_cachep, CFS_ALLOC_IO, sizeof(*oqi));
        if(!oqi)
                RETURN(NULL);

        CFS_INIT_LIST_HEAD(&oqi->oqi_hash);
        oqi->oqi_cli = cli;
        oqi->oqi_id = id;
        oqi->oqi_type = type;

        RETURN(oqi);
}

static void free_qinfo(struct osc_quota_info *oqi)
{
        OBD_SLAB_FREE(oqi, qinfo_cachep, sizeof(*oqi));
}

int osc_quota_chkdq(struct client_obd *cli, const unsigned int qid[])
{
        unsigned int id;
        int          cnt, rc = QUOTA_OK;
        ENTRY;

        cfs_spin_lock(&qinfo_list_lock);
        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi = NULL;

                id = (cnt == USRQUOTA) ? qid[USRQUOTA] : qid[GRPQUOTA];
                oqi = find_qinfo(cli, id, cnt);
                if (oqi) {
                        rc = NO_QUOTA;
                        break;
                }
        }
        cfs_spin_unlock(&qinfo_list_lock);

        if (rc == NO_QUOTA)
                CDEBUG(D_QUOTA, "chkdq found noquota for %s %d\n",
                       cnt == USRQUOTA ? "user" : "group", id);
        RETURN(rc);
}

int osc_quota_setdq(struct client_obd *cli, const unsigned int qid[],
                    obd_flag valid, obd_flag flags)
{
        unsigned int id;
        obd_flag     noquota;
        int          cnt, rc = 0;
        ENTRY;

        for (cnt = 0; cnt < MAXQUOTAS; cnt++) {
                struct osc_quota_info *oqi = NULL, *old;

                if (!(valid & ((cnt == USRQUOTA) ?
                    OBD_MD_FLUSRQUOTA : OBD_MD_FLGRPQUOTA)))
                        continue;

                id = (cnt == USRQUOTA) ? qid[USRQUOTA] : qid[GRPQUOTA];
                noquota = (cnt == USRQUOTA) ?
                    (flags & OBD_FL_NO_USRQUOTA) : (flags & OBD_FL_NO_GRPQUOTA);

                if (noquota) {
                        oqi = alloc_qinfo(cli, id, cnt);
                        if (!oqi) {
                                rc = -ENOMEM;
                                CDEBUG(D_QUOTA, "setdq for %s %d failed, "
                                       "(rc = %d)\n",
                                       cnt == USRQUOTA ? "user" : "group",
                                       id, rc);
                                break;
                        }
                }

                cfs_spin_lock(&qinfo_list_lock);
                old = find_qinfo(cli, id, cnt);
                if (old && !noquota)
                        remove_qinfo_hash(old);
                else if (!old && noquota)
                        insert_qinfo_hash(oqi);
                cfs_spin_unlock(&qinfo_list_lock);

                if (old && !noquota)
                        CDEBUG(D_QUOTA, "setdq to remove for %s %d\n",
                               cnt == USRQUOTA ? "user" : "group", id);
                else if (!old && noquota)
                        CDEBUG(D_QUOTA, "setdq to insert for %s %d\n",
                               cnt == USRQUOTA ? "user" : "group", id);

                if (old) {
                        if (noquota)
                                free_qinfo(oqi);
                        else
                                free_qinfo(old);
                }
        }
        RETURN(rc);
}

int osc_quota_cleanup(struct obd_device *obd)
{
        struct client_obd     *cli = &obd->u.cli;
        struct osc_quota_info *oqi, *n;
        int i;
        ENTRY;

        cfs_spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                cfs_list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        if (oqi->oqi_cli != cli)
                                continue;
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        cfs_spin_unlock(&qinfo_list_lock);

        RETURN(0);
}

int osc_quota_init()
{
        int i;
        ENTRY;

        LASSERT(qinfo_cachep == NULL);
        qinfo_cachep = cfs_mem_cache_create("osc_quota_info",
                                            sizeof(struct osc_quota_info),
                                            0, 0);
        if (!qinfo_cachep)
                RETURN(-ENOMEM);

        for (i = 0; i < NR_DQHASH; i++)
                CFS_INIT_LIST_HEAD(qinfo_hash + i);

        RETURN(0);
}

int osc_quota_exit()
{
        struct osc_quota_info *oqi, *n;
        int                    i, rc;
        ENTRY;

        cfs_spin_lock(&qinfo_list_lock);
        for (i = 0; i < NR_DQHASH; i++) {
                cfs_list_for_each_entry_safe(oqi, n, &qinfo_hash[i], oqi_hash) {
                        remove_qinfo_hash(oqi);
                        free_qinfo(oqi);
                }
        }
        cfs_spin_unlock(&qinfo_list_lock);

        rc = cfs_mem_cache_destroy(qinfo_cachep);
        LASSERTF(rc == 0, "couldn't destory qinfo_cachep slab\n");
        qinfo_cachep = NULL;

        RETURN(0);
}

int osc_quotactl(struct obd_device *unused, struct obd_export *exp,
                 struct obd_quotactl *oqctl)
{
        struct ptlrpc_request *req;
        struct obd_quotactl   *oqc;
        int                    rc;
        ENTRY;

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_OST_QUOTACTL, LUSTRE_OST_VERSION,
                                        OST_QUOTACTL);
        if (req == NULL)
                RETURN(-ENOMEM);

        oqc = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        *oqc = *oqctl;

        ptlrpc_request_set_replen(req);
        ptlrpc_at_set_req_timeout(req);
        req->rq_no_resend = 1;

        rc = ptlrpc_queue_wait(req);
        if (rc)
                CERROR("ptlrpc_queue_wait failed, rc: %d\n", rc);

        if (req->rq_repmsg &&
            (oqc = req_capsule_server_get(&req->rq_pill, &RMF_OBD_QUOTACTL))) {
                *oqctl = *oqc;
        } else if (!rc) {
                CERROR ("Can't unpack obd_quotactl\n");
                rc = -EPROTO;
        }
        ptlrpc_req_finished(req);

        RETURN(rc);
}

int osc_quotacheck(struct obd_device *unused, struct obd_export *exp,
                   struct obd_quotactl *oqctl)
{
        struct client_obd       *cli = &exp->exp_obd->u.cli;
        struct ptlrpc_request   *req;
        struct obd_quotactl     *body;
        int                      rc;
        ENTRY;

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_OST_QUOTACHECK, LUSTRE_OST_VERSION,
                                        OST_QUOTACHECK);
        if (req == NULL)
                RETURN(-ENOMEM);

        body = req_capsule_client_get(&req->rq_pill, &RMF_OBD_QUOTACTL);
        *body = *oqctl;

        ptlrpc_request_set_replen(req);

        /* the next poll will find -ENODATA, that means quotacheck is
         * going on */
        cli->cl_qchk_stat = -ENODATA;
        rc = ptlrpc_queue_wait(req);
        if (rc)
                cli->cl_qchk_stat = rc;
        ptlrpc_req_finished(req);
        RETURN(rc);
}

int osc_quota_poll_check(struct obd_export *exp, struct if_quotacheck *qchk)
{
        struct client_obd *cli = &exp->exp_obd->u.cli;
        int rc;
        ENTRY;

        qchk->obd_uuid = cli->cl_target_uuid;
        memcpy(qchk->obd_type, LUSTRE_OST_NAME, strlen(LUSTRE_OST_NAME));

        rc = cli->cl_qchk_stat;
        /* the client is not the previous one */
        if (rc == CL_NOT_QUOTACHECKED)
                rc = -EINTR;
        RETURN(rc);
}

int osc_quota_adjust_qunit(struct obd_export *exp,
                           struct quota_adjust_qunit *oqaq,
                           struct lustre_quota_ctxt *qctxt,
                           struct ptlrpc_request_set *rqset)
{
        struct ptlrpc_request     *req;
        struct quota_adjust_qunit *oqa;
        int                        rc = 0;
        ENTRY;

        /* client don't support this kind of operation, abort it */
        if (!(exp->exp_connect_flags & OBD_CONNECT_CHANGE_QS)) {
                CDEBUG(D_QUOTA, "osc: %s don't support change qunit size\n",
                       exp->exp_obd->obd_name);
                RETURN(rc);
        }
        if (strcmp(exp->exp_obd->obd_type->typ_name, LUSTRE_OSC_NAME))
                RETURN(-EINVAL);

        LASSERT(rqset);

        req = ptlrpc_request_alloc_pack(class_exp2cliimp(exp),
                                        &RQF_OST_QUOTA_ADJUST_QUNIT,
                                        LUSTRE_OST_VERSION,
                                        OST_QUOTA_ADJUST_QUNIT);
        if (req == NULL)
                RETURN(-ENOMEM);

        oqa = req_capsule_client_get(&req->rq_pill, &RMF_QUOTA_ADJUST_QUNIT);
        *oqa = *oqaq;

        ptlrpc_request_set_replen(req);

        ptlrpc_set_add_req(rqset, req);
        RETURN(rc);
}
