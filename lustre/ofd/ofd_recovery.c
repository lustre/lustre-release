/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/ofd/ofd_recovery.c
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
 *   Author: Nikita Danilov <nikita@clusterfs.com>
 *   Author: Alex Tomas <alex@clusterfs.com>
 *   Author: Mike Pershin <tappro@sun.com>
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

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

struct thandle *filter_trans_create0(const struct lu_env *env,
                                     struct filter_device *ofd)
{
        struct thandle *th;
        th = dt_trans_create(env, ofd->ofd_osd);
        return th;
}

struct thandle *filter_trans_create(const struct lu_env *env,
                                    struct filter_device *ofd)
{
        struct filter_thread_info *info;
        struct thandle *th;
        struct filter_export_data *fed;
        int rc;

        info = lu_context_key_get(&env->le_ctx, &filter_thread_key);
        LASSERT(info);

#if 0
        /* export can require sync operations */
        if (info->fti_exp != NULL)
                p->tp_sync = info->fti_exp->exp_need_sync;
#endif

        th = filter_trans_create0(env, ofd);
        if (IS_ERR(th))
                return th;

        /* no last_rcvd update needed */
        if (info->fti_exp == NULL)
                return th;

        /* declare last_rcvd update */
        fed = &info->fti_exp->exp_filter_data;
        rc = dt_declare_record_write(env, ofd->ofd_last_rcvd,
                                     sizeof(*fed->fed_lcd),
                                     fed->fed_lr_off, th);
        /* declare last_rcvd header update */
        rc = dt_declare_record_write(env, ofd->ofd_last_rcvd,
                                     sizeof(ofd->ofd_fsd), 0, th);
        LASSERT(rc == 0);

        return th;
}

int filter_trans_start(const struct lu_env *env,
                       struct filter_device *ofd,
                       struct thandle *th)
{
        int rc;
        rc = ofd->ofd_osd->dd_ops->dt_trans_start(env, ofd->ofd_osd, th);
        if (rc)
                CERROR("Cannot start transaction, err =%d\n", rc);
        return rc;
}

void filter_trans_stop(const struct lu_env *env,
                       struct filter_device *ofd,
                       struct thandle *th)
{
        ofd->ofd_osd->dd_ops->dt_trans_stop(env, th);
}

/*
 * last_rcvd & last_committed update callbacks
 */
static int filter_last_rcvd_update(struct filter_thread_info *info,
                                   struct thandle *th)
{
        struct filter_device *ofd = filter_exp(info->fti_exp);
        struct filter_export_data *fed;
        struct lsd_client_data *lcd;
        __s32 rc = th->th_result;
        __u64 *transno_p;
        loff_t off;
        int err;
        ENTRY;

        LASSERT(ofd);
        LASSERT(info->fti_exp);

        fed = &info->fti_exp->exp_filter_data;
        LASSERT(fed);
        lcd = fed->fed_lcd;

        /* if the export has already been failed, we have no last_rcvd slot */
        if (info->fti_exp->exp_failed) {
                CWARN("commit transaction for disconnected client %s: rc %d\n",
                      info->fti_exp->exp_client_uuid.uuid, rc);
                if (rc == 0)
                        rc = -ENOTCONN;
                RETURN(rc);
        }
        LASSERT(lcd);
        off = fed->fed_lr_off;

        mutex_down(&fed->fed_lastrcvd_lock);

        transno_p = &lcd->lcd_last_transno;
        lcd->lcd_last_xid = info->fti_xid;

        /*
         * When we store zero transno in mcd we can lost last transno value
         * because mcd contains 0, but msd is not yet written
         * The server data should be updated also if the latest
         * transno is rewritten by zero. See the bug 11125 for details.
         */
        if (info->fti_transno == 0 &&
            *transno_p == ofd->ofd_last_transno) {
                spin_lock(&ofd->ofd_transno_lock);
                ofd->ofd_fsd.lsd_last_transno = ofd->ofd_last_transno;
                spin_unlock(&ofd->ofd_transno_lock);
                filter_last_rcvd_header_write(info->fti_env, ofd, th);
        }

        *transno_p = info->fti_transno;
        LASSERT(fed->fed_lr_off > 0);
        err = filter_last_rcvd_write(info->fti_env, ofd, lcd, &off, th);

        mutex_up(&fed->fed_lastrcvd_lock);
        RETURN(err);
}

/* add credits for last_rcvd update */
static int filter_txn_start_cb(const struct lu_env *env,
                               struct thandle *handle,
                               void *cookie)
{
        return 0;
}

/* Update last_rcvd records with latests transaction data */
static int filter_txn_stop_cb(const struct lu_env *env,
                              struct thandle *txn, void *cookie)
{
        struct filter_device *ofd = cookie;
        struct filter_txn_info *txi;
        struct filter_thread_info *info;
        ENTRY;

        /* transno in two contexts - for commit_cb and for thread */
        txi = lu_context_key_get(&txn->th_ctx, &filter_txn_thread_key);
        info = lu_context_key_get(&env->le_ctx, &filter_thread_key);

        if (info->fti_exp == NULL || info->fti_no_need_trans ||
            info->fti_exp->exp_filter_data.fed_lcd == NULL) {
                txi->txi_transno = 0;
                info->fti_no_need_trans = 0;
                RETURN(0);
        }

        LASSERT(filter_exp(info->fti_exp) == ofd);
        if (info->fti_has_trans) {
                /* XXX: currently there are allowed cases, but the wrong cases
                 * are also possible, so better check is needed here */
                CDEBUG(D_INFO, "More than one transaction "LPU64"\n",
                       info->fti_transno);
                RETURN(0);
        }

        info->fti_has_trans = 1;
        spin_lock(&ofd->ofd_transno_lock);
        if (txn->th_result != 0) {
                if (info->fti_transno != 0) {
                        CERROR("Replay transno "LPU64" failed: rc %i\n",
                               info->fti_transno, txn->th_result);
                        info->fti_transno = 0;
                }
        } else if (info->fti_transno == 0) {
                info->fti_transno = ++ ofd->ofd_last_transno;
        } else {
                /* should be replay */
                if (info->fti_transno > ofd->ofd_last_transno)
                       ofd->ofd_last_transno = info->fti_transno;
        }

        /* filling reply data */
        CDEBUG(D_INODE, "transno = %llu, last_committed = %llu\n",
               info->fti_transno, filter_obd(ofd)->obd_last_committed);

        /* save transno for the commit callback */
        txi->txi_transno = info->fti_transno;
        spin_unlock(&ofd->ofd_transno_lock);

        return filter_last_rcvd_update(info, txn);
}

/* commit callback, need to update last_commited value */
static int filter_txn_commit_cb(const struct lu_env *env,
                                struct thandle *txn, void *cookie)
{
        struct filter_device *ofd = cookie;
        struct obd_device *obd = filter_obd(ofd);
        struct filter_txn_info *txi;
        int i;

        txi = lu_context_key_get(&txn->th_ctx, &filter_txn_thread_key);

        /* copy of obd_transno_commit_cb() but with locking */
        spin_lock(&ofd->ofd_transno_lock);
        if (txi->txi_transno > obd->obd_last_committed) {
                obd->obd_last_committed = txi->txi_transno;
                spin_unlock(&ofd->ofd_transno_lock);
                ptlrpc_commit_replies(obd);
        } else
                spin_unlock(&ofd->ofd_transno_lock);

        if (txi->txi_transno)
                CDEBUG(D_HA, "%s: transno "LPD64" is committed\n",
                       obd->obd_name, txi->txi_transno);

        /* iterate through all additional callbacks */
        for (i = 0; i < txi->txi_cb_count; i++) {
                txi->txi_cb[i].filter_cb_func(ofd, txi->txi_transno,
                                              txi->txi_cb[i].filter_cb_data,
                                              0);
        }
        return 0;
}

int filter_fs_setup(const struct lu_env *env, struct filter_device *ofd,
                    struct obd_device *obd)
{
        struct lu_fid fid;
        struct filter_object *fo;
        struct lu_attr attr;
        int rc = 0;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
                RETURN (-ENOENT);

        OBD_ALLOC(ofd->ofd_last_rcvd_slots, LR_MAX_CLIENTS / 8);
        if (ofd->ofd_last_rcvd_slots == NULL)
                RETURN(-ENOMEM);

        /* prepare transactions callbacks */
        ofd->ofd_txn_cb.dtc_txn_start = filter_txn_start_cb;
        ofd->ofd_txn_cb.dtc_txn_stop = filter_txn_stop_cb;
        ofd->ofd_txn_cb.dtc_txn_commit = filter_txn_commit_cb;
        ofd->ofd_txn_cb.dtc_cookie = ofd;
        CFS_INIT_LIST_HEAD(&ofd->ofd_txn_cb.dtc_linkage);

        dt_txn_callback_add(ofd->ofd_osd, &ofd->ofd_txn_cb);

        lu_local_obj_fid(&fid, MDT_LAST_RECV_OID);
        memset(&attr, 0, sizeof(attr));
        attr.la_valid = LA_MODE;
        attr.la_mode = S_IFREG | 0666;

        fo = filter_object_find_or_create(env, ofd, &fid, &attr);
        LASSERT(!IS_ERR(fo));
        ofd->ofd_last_rcvd = filter_object_child(fo);
        rc = filter_server_data_init(env, ofd);
        LASSERT(rc == 0);

        lu_local_obj_fid(&fid, MDD_OBJECTS_OID);
        memset(&attr, 0, sizeof(attr));
        attr.la_valid = LA_MODE;
        attr.la_mode = S_IFREG | 0666;

        fo = filter_object_find_or_create(env, ofd, &fid, &attr);
        LASSERT(!IS_ERR(fo));
        ofd->ofd_groups_file = filter_object_child(fo);
        rc = filter_groups_init(env, ofd);
        LASSERT(rc == 0);

        RETURN(0);

//stop_recov:
        target_recovery_fini(obd);
//put_last_rcvd:
        OBD_FREE(ofd->ofd_last_rcvd_slots, LR_MAX_CLIENTS / 8);
        lu_object_put(env, &ofd->ofd_last_rcvd->do_lu);
        ofd->ofd_last_rcvd = NULL;
        return rc;
}

void filter_fs_cleanup(const struct lu_env *env, struct filter_device *ofd)
{
        struct filter_thread_info *info = filter_info_init(env, NULL);
        int i;
        ENTRY;

        info->fti_no_need_trans = 1;

        filter_server_data_update(env, ofd);

        for (i = 0; i < ofd->ofd_max_group; i++)
                filter_last_id_write(env, ofd, i, (i == ofd->ofd_max_group-1));

        /* Remove transaction callback */
        dt_txn_callback_del(ofd->ofd_osd, &ofd->ofd_txn_cb);

        if (ofd->ofd_last_rcvd)
                lu_object_put(env, &ofd->ofd_last_rcvd->do_lu);
        ofd->ofd_last_rcvd = NULL;

        if (ofd->ofd_groups_file)
                lu_object_put(env, &ofd->ofd_groups_file->do_lu);
        ofd->ofd_groups_file = NULL;

        OBD_FREE(ofd->ofd_last_rcvd_slots, LR_MAX_CLIENTS / 8);

        filter_free_capa_keys(ofd);
        cleanup_capa_hash(ofd->ofd_capa_hash);

        EXIT;
}


