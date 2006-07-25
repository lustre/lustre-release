/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_open.c
 *  Lustre Metadata Target (mdt) open/close file handling
 *
 *  Copyright (C) 2002-2006 Cluster File Systems, Inc.
 *   Author: Huang Hua <huanghua@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 */
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MDS

#include "mdt_internal.h"

/* Add client data to the MDS.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_off is -1 (i.e. a new client).
 * Otherwise, we just have to read the data from the last_rcvd file and
 * we know its offset.
 *
 * It should not be possible to fail adding an existing client - otherwise
 * mdt_init_server_data() callsite needs to be fixed.
 */
int mdt_client_add(const struct lu_context *ctxt,
                   struct mdt_device *mdt,
                   struct mdt_export_data *med,
                   int cl_idx)
{
        unsigned long *bitmap = mdt->mdt_client_bitmap;
        struct mdt_client_data *mcd = med->med_mcd;
        struct mdt_server_data *msd = &mdt->mdt_msd;
        int new_client = (cl_idx == -1);
        ENTRY;

        LASSERT(bitmap != NULL);
        LASSERTF(cl_idx > -2, "%d\n", cl_idx);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (new_client) {
                cl_idx = find_first_zero_bit(bitmap, LR_MAX_CLIENTS);
        repeat:
                if (cl_idx >= LR_MAX_CLIENTS ||
                    OBD_FAIL_CHECK_ONCE(OBD_FAIL_MDS_CLIENT_ADD)) {
                        CERROR("no room for clients - fix LR_MAX_CLIENTS\n");
                        return -EOVERFLOW;
                }
                if (test_and_set_bit(cl_idx, bitmap)) {
                        cl_idx = find_next_zero_bit(bitmap, LR_MAX_CLIENTS,
                                                    cl_idx);
                        goto repeat;
                }
        } else {
                if (test_and_set_bit(cl_idx, bitmap)) {
                        CERROR("MDS client %d: bit already set in bitmap!!\n",
                               cl_idx);
                        LBUG();
                }
        }

        CDEBUG(D_INFO, "client at idx %d with UUID '%s' added\n",
               cl_idx, med->med_mcd->mcd_uuid);

        med->med_lr_idx = cl_idx;
        med->med_lr_off = le32_to_cpu(msd->msd_client_start) +
                          (cl_idx * le16_to_cpu(msd->msd_client_size));
        LASSERTF(med->med_lr_off > 0, "med_lr_off = %llu\n", med->med_lr_off);

        if (new_client) {
                loff_t off = med->med_lr_off;
                int rc = 0;
/*
                rc = mdt->mdt_last->do_body_ops->dbo_write(ctxt,
                                                           mdt->mdt_last,
                                                           mcd, sizeof(*mcd),
                                                           &off, NULL);
*/
                if (rc)
                        return rc;
                CDEBUG(D_INFO, "wrote client mcd at idx %u off %llu (len %u)\n",
                       cl_idx, off, sizeof(mcd));
        }
        return 0;
}

int mdt_update_server_data(const struct lu_context *ctxt,
                           struct mdt_device *mdt,
                           int sync)
{
        struct mdt_server_data *msd = &mdt->mdt_msd;
        //loff_t off = 0;
        int rc = 0;
        ENTRY;

        CDEBUG(D_SUPER, "MDS mount_count is "LPU64", last_transno is "LPU64"\n",
                mdt->mdt_mount_count, mdt->mdt_last_transno);

        msd->msd_last_transno = cpu_to_le64(mdt->mdt_last_transno);
/*
        rc = mdt->mdt_last->do_body_ops->dbo_write(ctxt,
                                                   mdt->mdt_last,
                                                   msd,
                                                   sizeof(*msd), &off, NULL);
*/
        RETURN(rc);

}

int mdt_client_free(const struct lu_context *ctxt,
                    struct mdt_device *mdt,
                    struct mdt_export_data *med)
{
        struct mdt_client_data *mcd = med->med_mcd;
        int rc = 0;
        loff_t off;
        ENTRY;

        if (!mcd)
                RETURN(0);

        CDEBUG(D_INFO, "freeing client at idx %u, offset %lld\n",
               med->med_lr_idx, med->med_lr_off);

        off = med->med_lr_off;

        /* Don't clear med_lr_idx here as it is likely also unset.  At worst
         * we leak a client slot that will be cleaned on the next recovery. */
        if (off <= 0) {
                CERROR("client idx %d has offset %lld\n",
                        med->med_lr_idx, off);
                GOTO(free, rc = -EINVAL);
        }

        /* Clear the bit _after_ zeroing out the client so we don't
           race with mdt_client_add and zero out new clients.*/
        if (!test_bit(med->med_lr_idx, mdt->mdt_client_bitmap)) {
                CERROR("MDT client %u: bit already clear in bitmap!!\n",
                       med->med_lr_idx);
                LBUG();
        }

        memset(mcd, 0, sizeof *mcd);
/*
        rc = mdt->mdt_last->do_body_ops->dbo_write(ctxt,
                                                   mdt->mdt_last,
                                                   mcd,
                                                   sizeof(*mcd), &off, NULL);
*/
        CDEBUG_EX(rc == 0 ? D_INFO : D_ERROR,
                  "zeroing out client idx %u in %s rc %d\n",
                  med->med_lr_idx, LAST_RCVD, rc);

        if (!test_and_clear_bit(med->med_lr_idx, mdt->mdt_client_bitmap)) {
                CERROR("MDS client %u: bit already clear in bitmap!!\n",
                       med->med_lr_idx);
                LBUG();
        }

        /* Make sure the server's last_transno is up to date. Do this
         * after the client is freed so we know all the client's
         * transactions have been committed. */
        mdt_update_server_data(ctxt, mdt, 0);

        EXIT;
free:
        OBD_FREE_PTR(mcd);
        med->med_mcd = NULL;
        return 0;
}

static int mdt_init_server_data(const struct lu_context *ctxt,
                                struct mdt_device *mdt)
{
        struct mdt_server_data *msd = &mdt->mdt_msd;
        struct mdt_client_data *mcd = NULL;
        struct obd_device *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        loff_t off = 0;
        unsigned long last_rcvd_size = 0; // = getsize(mdt->mdt_last)
        __u64 mount_count;
        int cl_idx;
        int rc = 0;
        ENTRY;

        /* ensure padding in the struct is the correct size */
        LASSERT(offsetof(struct mdt_server_data, msd_padding) +
                sizeof(msd->msd_padding) == LR_SERVER_SIZE);
        LASSERT(offsetof(struct mdt_client_data, mcd_padding) +
                sizeof(mcd->mcd_padding) == LR_CLIENT_SIZE);

        if (last_rcvd_size == 0) {
                LCONSOLE_WARN("%s: new disk, initializing\n", obd->obd_name);

                memcpy(msd->msd_uuid, obd->obd_uuid.uuid,sizeof(msd->msd_uuid));
                msd->msd_last_transno = 0;
                mount_count = msd->msd_mount_count = 0;
                msd->msd_server_size = cpu_to_le32(LR_SERVER_SIZE);
                msd->msd_client_start = cpu_to_le32(LR_CLIENT_START);
                msd->msd_client_size = cpu_to_le16(LR_CLIENT_SIZE);
                msd->msd_feature_rocompat = cpu_to_le32(OBD_ROCOMPAT_LOVOBJID);
                msd->msd_feature_incompat = cpu_to_le32(OBD_INCOMPAT_MDT |
                                                        OBD_INCOMPAT_COMMON_LR);
        } else {
/*
                rc = mdt->mdt_last->do_body_ops->dbo_read(ctxt,
                                                          mdt->mdt_last,
                                                          msd,
                                                          sizeof(*msd), &off);
*/
                if (rc) {
                        CERROR("error reading MDS %s: rc %d\n", LAST_RCVD, rc);
                        GOTO(out, rc);
                }
                if (strcmp(msd->msd_uuid, obd->obd_uuid.uuid) != 0) {
                        LCONSOLE_ERROR("Trying to start OBD %s using the wrong"
                                       " disk %s. Were the /dev/ assignments "
                                       "rearranged?\n",
                                       obd->obd_uuid.uuid, msd->msd_uuid);
                        GOTO(out, rc = -EINVAL);
                }
                mount_count = le64_to_cpu(msd->msd_mount_count);
        }

        if (msd->msd_feature_incompat & ~cpu_to_le32(MDT_INCOMPAT_SUPP)) {
                CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
                       obd->obd_name, le32_to_cpu(msd->msd_feature_incompat) &
                       ~MDT_INCOMPAT_SUPP);
                GOTO(out, rc = -EINVAL);
        }
        if (msd->msd_feature_rocompat & ~cpu_to_le32(MDT_ROCOMPAT_SUPP)) {
                CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
                       obd->obd_name, le32_to_cpu(msd->msd_feature_rocompat) &
                       ~MDT_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(out, rc = -EINVAL);
        }
        if (!(msd->msd_feature_incompat & cpu_to_le32(OBD_INCOMPAT_COMMON_LR))){
                CDEBUG(D_WARNING, "using old last_rcvd format\n");
                msd->msd_mount_count = msd->msd_last_transno;
                msd->msd_last_transno = msd->msd_unused;
                /* If we update the last_rcvd, we can never go back to
                   an old install, so leave this in the old format for now.
                msd->msd_feature_incompat |= cpu_to_le32(LR_INCOMPAT_COMMON_LR);
                */
        }
        msd->msd_feature_compat = cpu_to_le32(OBD_COMPAT_MDT);

        mdt->mdt_last_transno = le64_to_cpu(msd->msd_last_transno);

        CDEBUG(D_INODE, "%s: server last_transno: "LPU64"\n",
               obd->obd_name, mdt->mdt_last_transno);
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count + 1);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_server_size));
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_client_start));
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, le32_to_cpu(msd->msd_client_size));
        CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
               obd->obd_name, last_rcvd_size);
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= le32_to_cpu(msd->msd_client_start) ? 0 :
               (last_rcvd_size - le32_to_cpu(msd->msd_client_start)) /
                le16_to_cpu(msd->msd_client_size));

        if (!msd->msd_server_size || !msd->msd_client_start ||
            !msd->msd_client_size) {
                CERROR("Bad last_rcvd contents!\n");
                GOTO(out, rc = -EINVAL);
        }

        /* When we do a clean MDS shutdown, we save the last_transno into
         * the header.  If we find clients with higher last_transno values
         * then those clients may need recovery done. */
        for (cl_idx = 0, off = le32_to_cpu(msd->msd_client_start);
             off < last_rcvd_size; cl_idx++) {
                __u64 last_transno;
                struct obd_export *exp;
                struct mdt_export_data *med;

                if (!mcd) {
                        OBD_ALLOC_PTR(mcd);
                        if (!mcd)
                                GOTO(err_client, rc = -ENOMEM);
                }

                off = le32_to_cpu(msd->msd_client_start) +
                        cl_idx * le16_to_cpu(msd->msd_client_size);
/*
                rc = mdt->mdt_last->do_body_ops->dbo_read(ctxt,
                                                          mdt->mdt_last,
                                                          mcd,
                                                          sizeof(*mcd), &off);
*/
                if (rc) {
                        CERROR("error reading MDS %s idx %d, off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        break; /* read error shouldn't cause startup to fail */
                }

                if (mcd->mcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_transno = le64_to_cpu(mcd->mcd_last_transno);

                /* These exports are cleaned up by mdt_obd_disconnect(), so
                 * they need to be set up like real exports as
                 * mdt_obd_connect() does.
                 */
                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64" lx: "LPU64"\n", mcd->mcd_uuid, cl_idx,
                       last_transno, le64_to_cpu(msd->msd_last_transno),
                       le64_to_cpu(mcd->mcd_last_xid));

                exp = class_new_export(obd, (struct obd_uuid *)mcd->mcd_uuid);
                if (IS_ERR(exp))
                        GOTO(err_client, rc = PTR_ERR(exp));

                med = &exp->exp_mdt_data;
                med->med_mcd = mcd;
                rc = mdt_client_add(ctxt, mdt, med, cl_idx);
                LASSERTF(rc == 0, "rc = %d\n", rc); /* can't fail existing */

                mcd = NULL;
                exp->exp_replay_needed = 1;
                exp->exp_connecting = 0;
                obd->obd_recoverable_clients++;
                obd->obd_max_recoverable_clients++;
                class_export_put(exp);

                CDEBUG(D_OTHER, "client at idx %d has last_transno = "LPU64"\n",
                       cl_idx, last_transno);

                if (last_transno > mdt->mdt_last_transno)
                        mdt->mdt_last_transno = last_transno;
        }

        if (mcd)
                OBD_FREE_PTR(mcd);

        obd->obd_last_committed = mdt->mdt_last_transno;

        if (obd->obd_recoverable_clients) {
                CWARN("RECOVERY: service %s, %d recoverable clients, "
                      "last_transno "LPU64"\n", obd->obd_name,
                      obd->obd_recoverable_clients, mdt->mdt_last_transno);
                obd->obd_next_recovery_transno = obd->obd_last_committed + 1;
                obd->obd_recovering = 1;
                obd->obd_recovery_start = CURRENT_SECONDS;
                /* Only used for lprocfs_status */
                obd->obd_recovery_end = obd->obd_recovery_start +
                        OBD_RECOVERY_TIMEOUT;
        }

        mdt->mdt_mount_count = mount_count + 1;
        msd->msd_mount_count = cpu_to_le64(mdt->mdt_mount_count);

        /* save it, so mount count and last_transno is current */
        rc = mdt_update_server_data(ctxt, mdt, 1);
        if (rc)
                GOTO(err_client, rc);

        RETURN(0);

err_client:
        class_disconnect_exports(obd);
out:
        return rc;
}

/*
 * last_rcvd update callbacks
 */
extern struct lu_context_key mdt_txn_key;
extern struct lu_context_key mdt_thread_key;

enum {
        MDT_TXN_LAST_RCVD_CREDITS = 1
};

/* add credits for last_rcvd update */
static int mdt_txn_start_cb(const struct lu_context *ctx,
                            struct dt_device *dev,
                            struct txn_param *param, void *cookie)
{
        param->tp_credits += MDT_TXN_LAST_RCVD_CREDITS;
        return 0;
}

/* Update last_rcvd records with latests transaction data */
static int mdt_txn_stop_cb(const struct lu_context *ctx,
                           struct dt_device *dev,
                           struct thandle *txn, void *cookie)
{
        struct mdt_device *mdt = cookie;
        struct mdt_txn_info *txni;
        struct mdt_thread_info *mti;

        /* transno in two contexts - for commit_cb and for thread */
        txni = lu_context_key_get(&txn->th_ctx, &mdt_txn_key);
        mti = lu_context_key_get(ctx, &mdt_thread_key);
        /*TODO: checks for recovery cases, see mds_finish_transno */
        spin_lock(&mdt->mdt_transno_lock);
        if (mti->mti_transno == 0) {
                mti->mti_transno = ++ mdt->mdt_last_transno;
        } else {
                /* replay */
                if (mti->mti_transno > mdt->mdt_last_transno)
                        mdt->mdt_last_transno = mti->mti_transno;
        }
        spin_unlock(&mdt->mdt_transno_lock);
        /* save transno for the commit callback */
        txni->txi_transno = mti->mti_transno;
/*
        TODO: write last_rcvd
*/
        return 0;
}

/* commit callback, need to update last_commited value */
static int mdt_txn_commit_cb(const struct lu_context *ctx,
                             struct dt_device *dev,
                             struct thandle *txn, void *cookie)
{
        struct mdt_device *mdt = cookie;
        struct obd_device *obd = md2lu_dev(&mdt->mdt_md_dev)->ld_obd;
        struct mdt_txn_info *txi;

        txi = lu_context_key_get(&txn->th_ctx, &mdt_txn_key);
        if (txi->txi_transno > mdt->mdt_last_committed) {
                mdt->mdt_last_committed = txi->txi_transno;
                ptlrpc_commit_replies (obd);
        }
        CDEBUG(D_HA, "%s: transno "LPD64" committed\n",
               obd->obd_name, txi->txi_transno);

        return 0;
}

int mdt_fs_setup(const struct lu_context *ctxt,
                 struct mdt_device *mdt)
{
        //struct lu_fid last_fid;
        //struct dt_object *last;
        int rc = 0;
        ENTRY;

        /* prepare transactions callbacks */
        mdt->mdt_txn_cb.dtc_txn_start = mdt_txn_start_cb;
        mdt->mdt_txn_cb.dtc_txn_stop = mdt_txn_stop_cb;
        mdt->mdt_txn_cb.dtc_txn_commit = mdt_txn_commit_cb;
        mdt->mdt_txn_cb.dtc_cookie = mdt;

        dt_txn_callback_add(mdt->mdt_bottom, &mdt->mdt_txn_cb);
/*
        last = dt_store_open(ctxt, mdt->mdt_bottom, LAST_RCVD, &last_fid);
        if(!IS_ERR(last)) {
                mdt->mdt_last_rcvd = last;
                rc = mdt_init_server_data(ctxt, mdt);
                if (rc) {
                        lu_object_put(ctxt, &last->do_lu);
                        mdt->mdt_last = NULL;
                }
        } else {
                rc = PTR_ERR(last);
                CERROR("cannot open %s: rc = %d\n", LAST_RCVD, rc);
        }
*/
        RETURN (rc);
}


void mdt_fs_cleanup(const struct lu_context *ctxt,
                   struct mdt_device *mdt)
{
        struct obd_device *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;

        /* remove transaction callback */
        dt_txn_callback_del(mdt->mdt_bottom, &mdt->mdt_txn_cb);

        class_disconnect_exports(obd); /* cleans up client info too */

        if (mdt->mdt_last_rcvd)
                lu_object_put(ctxt, &mdt->mdt_last_rcvd->do_lu);
        mdt->mdt_last_rcvd = NULL;
}

