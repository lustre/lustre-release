/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mdt/mdt_recovery.c
 *  Lustre Metadata Target (mdt) recovery-related methods
 *
 *  Copyright (C) 2002-2006 Cluster File Systems, Inc.
 *   Author: Huang Hua <huanghua@clusterfs.com>
 *   Author: Pershin Mike <tappro@clusterfs.com>
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

static int mdt_server_data_update(const struct lu_env *env,
                                  struct mdt_device *mdt);

struct lu_buf *mdt_buf(const struct lu_env *env, void *area, ssize_t len)
{
        struct lu_buf *buf;
        struct mdt_thread_info *mti;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        buf = &mti->mti_buf;
        buf->lb_buf = area;
        buf->lb_len = len;
        return buf;
}

const struct lu_buf *mdt_buf_const(const struct lu_env *env,
                                   const void *area, ssize_t len)
{
        struct lu_buf *buf;
        struct mdt_thread_info *mti;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        buf = &mti->mti_buf;

        buf->lb_buf = (void *)area;
        buf->lb_len = len;
        return buf;
}

int mdt_record_read(const struct lu_env *env,
                    struct dt_object *dt, struct lu_buf *buf, loff_t *pos)
{
        int rc;

        LASSERTF(dt != NULL, "dt is NULL when we want to read record\n");

        rc = dt->do_body_ops->dbo_read(env, dt, buf, pos, BYPASS_CAPA);

        if (rc == buf->lb_len)
                rc = 0;
        else if (rc >= 0)
                rc = -EFAULT;
        return rc;
}

int mdt_record_write(const struct lu_env *env,
                     struct dt_object *dt, const struct lu_buf *buf,
                     loff_t *pos, struct thandle *th)
{
        int rc;

        LASSERTF(dt != NULL, "dt is NULL when we want to write record\n");
        LASSERT(th != NULL);
        rc = dt->do_body_ops->dbo_write(env, dt, buf, pos, th, BYPASS_CAPA);
        if (rc == buf->lb_len)
                rc = 0;
        else if (rc >= 0)
                rc = -EFAULT;
        return rc;
}
/* only one record write */

enum {
        MDT_TXN_LAST_RCVD_WRITE_CREDITS = 3
};

struct thandle* mdt_trans_start(const struct lu_env *env,
                                struct mdt_device *mdt, int credits)
{
        struct mdt_thread_info *mti;
        struct txn_param *p;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        p = &mti->mti_txn_param;
        txn_param_init(p, credits);

        /* export can require sync operations */
        if (mti->mti_exp != NULL)
                p->tp_sync = mti->mti_exp->exp_need_sync;

        return mdt->mdt_bottom->dd_ops->dt_trans_start(env, mdt->mdt_bottom, p);
}

void mdt_trans_stop(const struct lu_env *env,
                    struct mdt_device *mdt, struct thandle *th)
{
        mdt->mdt_bottom->dd_ops->dt_trans_stop(env, th);
}

/* last_rcvd handling */
static inline void msd_le_to_cpu(struct mdt_server_data *buf,
                                 struct mdt_server_data *msd)
{
        memcpy(msd->msd_uuid, buf->msd_uuid, sizeof (msd->msd_uuid));
        msd->msd_last_transno     = le64_to_cpu(buf->msd_last_transno);
        msd->msd_mount_count      = le64_to_cpu(buf->msd_mount_count);
        msd->msd_feature_compat   = le32_to_cpu(buf->msd_feature_compat);
        msd->msd_feature_rocompat = le32_to_cpu(buf->msd_feature_rocompat);
        msd->msd_feature_incompat = le32_to_cpu(buf->msd_feature_incompat);
        msd->msd_server_size      = le32_to_cpu(buf->msd_server_size);
        msd->msd_client_start     = le32_to_cpu(buf->msd_client_start);
        msd->msd_client_size      = le16_to_cpu(buf->msd_client_size);
}

static inline void msd_cpu_to_le(struct mdt_server_data *msd,
                                 struct mdt_server_data *buf)
{
        memcpy(buf->msd_uuid, msd->msd_uuid, sizeof (msd->msd_uuid));
        buf->msd_last_transno     = cpu_to_le64(msd->msd_last_transno);
        buf->msd_mount_count      = cpu_to_le64(msd->msd_mount_count);
        buf->msd_feature_compat   = cpu_to_le32(msd->msd_feature_compat);
        buf->msd_feature_rocompat = cpu_to_le32(msd->msd_feature_rocompat);
        buf->msd_feature_incompat = cpu_to_le32(msd->msd_feature_incompat);
        buf->msd_server_size      = cpu_to_le32(msd->msd_server_size);
        buf->msd_client_start     = cpu_to_le32(msd->msd_client_start);
        buf->msd_client_size      = cpu_to_le16(msd->msd_client_size);
}

static inline void mcd_le_to_cpu(struct mdt_client_data *buf,
                                 struct mdt_client_data *mcd)
{
        memcpy(mcd->mcd_uuid, buf->mcd_uuid, sizeof (mcd->mcd_uuid));
        mcd->mcd_last_transno       = le64_to_cpu(buf->mcd_last_transno);
        mcd->mcd_last_xid           = le64_to_cpu(buf->mcd_last_xid);
        mcd->mcd_last_result        = le32_to_cpu(buf->mcd_last_result);
        mcd->mcd_last_data          = le32_to_cpu(buf->mcd_last_data);
        mcd->mcd_last_close_transno = le64_to_cpu(buf->mcd_last_close_transno);
        mcd->mcd_last_close_xid     = le64_to_cpu(buf->mcd_last_close_xid);
        mcd->mcd_last_close_result  = le32_to_cpu(buf->mcd_last_close_result);
}

static inline void mcd_cpu_to_le(struct mdt_client_data *mcd,
                                 struct mdt_client_data *buf)
{
        memcpy(buf->mcd_uuid, mcd->mcd_uuid, sizeof (mcd->mcd_uuid));
        buf->mcd_last_transno       = cpu_to_le64(mcd->mcd_last_transno);
        buf->mcd_last_xid           = cpu_to_le64(mcd->mcd_last_xid);
        buf->mcd_last_result        = cpu_to_le32(mcd->mcd_last_result);
        buf->mcd_last_data          = cpu_to_le32(mcd->mcd_last_data);
        buf->mcd_last_close_transno = cpu_to_le64(mcd->mcd_last_close_transno);
        buf->mcd_last_close_xid     = cpu_to_le64(mcd->mcd_last_close_xid);
        buf->mcd_last_close_result  = cpu_to_le32(mcd->mcd_last_close_result);
}

static inline int mdt_last_rcvd_header_read(const struct lu_env *env,
                                            struct mdt_device *mdt)
{
        struct mdt_thread_info *mti;
        int rc;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);

        mti->mti_off = 0;
        rc = mdt_record_read(env, mdt->mdt_last_rcvd,
                             mdt_buf(env, &mti->mti_msd, sizeof(mti->mti_msd)),
                             &mti->mti_off);
        if (rc == 0)
                msd_le_to_cpu(&mti->mti_msd, &mdt->mdt_msd);

        CDEBUG(D_INFO, "read last_rcvd header rc = %d:\n"
                       "uuid = %s\n"
                       "last_transno = "LPU64"\n",
                        rc, mdt->mdt_msd.msd_uuid,
                        mdt->mdt_msd.msd_last_transno);
        return rc;
}

static inline int mdt_last_rcvd_header_write(const struct lu_env *env,
                                             struct mdt_device *mdt)
{
        struct mdt_thread_info *mti;
        struct thandle *th;
        int rc;
        ENTRY;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);

        th = mdt_trans_start(env, mdt, MDT_TXN_LAST_RCVD_WRITE_CREDITS);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));

        mti->mti_off = 0;        
        msd_cpu_to_le(&mdt->mdt_msd, &mti->mti_msd);

        rc = mdt_record_write(env, mdt->mdt_last_rcvd,
                              mdt_buf_const(env, &mti->mti_msd, sizeof(mti->mti_msd)),
                              &mti->mti_off, th);

        mdt_trans_stop(env, mdt, th);

        CDEBUG(D_INFO, "write last_rcvd header rc = %d:\n"
               "uuid = %s\nlast_transno = "LPU64"\n",
               rc, mdt->mdt_msd.msd_uuid, mdt->mdt_msd.msd_last_transno);
        
        RETURN(rc);
}

static int mdt_last_rcvd_read(const struct lu_env *env,
                              struct mdt_device *mdt,
                              struct mdt_client_data *mcd, loff_t *off)
{
        struct mdt_thread_info *mti;
        struct mdt_client_data *tmp;
        int rc;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        tmp = &mti->mti_mcd;
        rc = mdt_record_read(env, mdt->mdt_last_rcvd,
                             mdt_buf(env, tmp, sizeof(*tmp)), off);
        if (rc == 0)
                mcd_le_to_cpu(tmp, mcd);

        CDEBUG(D_INFO, "read mcd @%d rc = %d:\n"
                       "uuid = %s\n"
                       "last_transno = "LPU64"\n"
                       "last_xid = "LPU64"\n"
                       "last_result = %d\n"
                       "last_data = %d\n"
                       "last_close_transno = "LPU64"\n"
                       "last_close_xid = "LPU64"\n"
                       "last_close_result = %d\n",
                        (int)*off - sizeof(*tmp),
                        rc,
                        mcd->mcd_uuid,
                        mcd->mcd_last_transno,
                        mcd->mcd_last_xid,
                        mcd->mcd_last_result,
                        mcd->mcd_last_data,
                        mcd->mcd_last_close_transno,
                        mcd->mcd_last_close_xid,
                        mcd->mcd_last_close_result);
        return rc;
}

static int mdt_last_rcvd_write(const struct lu_env *env,
                               struct mdt_device *mdt,
                               struct mdt_client_data *mcd,
                               loff_t *off, struct thandle *th)
{
        struct mdt_thread_info *mti;
        struct mdt_client_data *tmp;
        int rc;

        LASSERT(th != NULL);
        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        tmp = &mti->mti_mcd;

        mcd_cpu_to_le(mcd, tmp);

        rc = mdt_record_write(env, mdt->mdt_last_rcvd,
                              mdt_buf_const(env, tmp, sizeof(*tmp)), off, th);

        CDEBUG(D_INFO, "write mcd @%d rc = %d:\n"
                       "uuid = %s\n"
                       "last_transno = "LPU64"\n"
                       "last_xid = "LPU64"\n"
                       "last_result = %d\n"
                       "last_data = %d\n"
                       "last_close_transno = "LPU64"\n"
                       "last_close_xid = "LPU64"\n"
                       "last_close_result = %d\n",
                        (int)*off - sizeof(*tmp),
                        rc,
                        mcd->mcd_uuid,
                        mcd->mcd_last_transno,
                        mcd->mcd_last_xid,
                        mcd->mcd_last_result,
                        mcd->mcd_last_data,
                        mcd->mcd_last_close_transno,
                        mcd->mcd_last_close_xid,
                        mcd->mcd_last_close_result);
        return rc;
}


static int mdt_clients_data_init(const struct lu_env *env,
                                 struct mdt_device *mdt,
                                 unsigned long last_size)
{
        struct mdt_server_data *msd = &mdt->mdt_msd;
        struct mdt_client_data *mcd = NULL;
        struct obd_device      *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        loff_t off;
        int cl_idx;
        int rc = 0;
        ENTRY;

        /* When we do a clean MDS shutdown, we save the last_transno into
         * the header.  If we find clients with higher last_transno values
         * then those clients may need recovery done. */
        LASSERT(atomic_read(&obd->obd_req_replay_clients) == 0);
        for (cl_idx = 0, off = msd->msd_client_start;
             off < last_size; cl_idx++) {
                __u64 last_transno;
                struct obd_export *exp;

                if (!mcd) {
                        OBD_ALLOC_PTR(mcd);
                        if (!mcd)
                                RETURN(-ENOMEM);
                }

                off = msd->msd_client_start +
                        cl_idx * msd->msd_client_size;

                rc = mdt_last_rcvd_read(env, mdt, mcd, &off);
                if (rc) {
                        CERROR("error reading MDS %s idx %d, off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        rc = 0;
                        break; /* read error shouldn't cause startup to fail */
                }

                if (mcd->mcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_transno = mcd_last_transno(mcd);

                /* These exports are cleaned up by mdt_obd_disconnect(), so
                 * they need to be set up like real exports as
                 * mdt_obd_connect() does.
                 */
                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64" lx: "LPU64"\n", mcd->mcd_uuid, cl_idx,
                       last_transno, msd->msd_last_transno,
                       mcd_last_xid(mcd));

                exp = class_new_export(obd, (struct obd_uuid *)mcd->mcd_uuid);
                if (IS_ERR(exp)) {
                        if (PTR_ERR(exp) == -EALREADY) {
                                /* export already exists, zero out this one */
                                mcd->mcd_uuid[0] = '\0'; 
                        } else
                                GOTO(err_client, rc = PTR_ERR(exp));
                } else {
                        struct mdt_thread_info *mti;                        
                        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
                        LASSERT(mti != NULL);
                        mti->mti_exp = exp;
                        exp->exp_mdt_data.med_mcd = mcd;
                        rc = mdt_client_add(env, mdt, cl_idx);
                        /* can't fail existing */
                        LASSERTF(rc == 0, "rc = %d\n", rc); 
                        mcd = NULL;
                        spin_lock(&exp->exp_lock);
                        exp->exp_connecting = 0;
                        exp->exp_in_recovery = 0;
                        spin_unlock(&exp->exp_lock);
                        obd->obd_max_recoverable_clients++;
                        class_export_put(exp);
                }

                CDEBUG(D_OTHER, "client at idx %d has last_transno="LPU64"\n",
                       cl_idx, last_transno);
                /* protect __u64 value update */
                spin_lock(&mdt->mdt_transno_lock);
                mdt->mdt_last_transno = max(last_transno,
                                            mdt->mdt_last_transno);
                spin_unlock(&mdt->mdt_transno_lock);
        }

err_client:
        if (mcd)
                OBD_FREE_PTR(mcd);
        RETURN(rc);
}

static int mdt_server_data_init(const struct lu_env *env,
                                struct mdt_device *mdt)
{
        struct mdt_server_data *msd = &mdt->mdt_msd;
        struct mdt_client_data *mcd = NULL;
        struct obd_device      *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        struct mdt_thread_info *mti;
        struct dt_object       *obj;
        struct lu_attr         *la;
        unsigned long last_rcvd_size;
        __u64 mount_count;
        int rc;
        ENTRY;

        /* ensure padding in the struct is the correct size */
        CLASSERT(offsetof(struct mdt_server_data, msd_padding) +
                sizeof(msd->msd_padding) == LR_SERVER_SIZE);
        CLASSERT(offsetof(struct mdt_client_data, mcd_padding) +
                sizeof(mcd->mcd_padding) == LR_CLIENT_SIZE);

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(mti != NULL);
        la = &mti->mti_attr.ma_attr;

        obj = mdt->mdt_last_rcvd;
        rc = obj->do_ops->do_attr_get(env, mdt->mdt_last_rcvd, la, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        last_rcvd_size = (unsigned long)la->la_size;

        if (last_rcvd_size == 0) {
                LCONSOLE_WARN("%s: new disk, initializing\n", obd->obd_name);

                memcpy(msd->msd_uuid, obd->obd_uuid.uuid,
                       sizeof(msd->msd_uuid));
                msd->msd_last_transno = 0;
                msd->msd_mount_count = 0;
                msd->msd_server_size = LR_SERVER_SIZE;
                msd->msd_client_start = LR_CLIENT_START;
                msd->msd_client_size = LR_CLIENT_SIZE;
                msd->msd_feature_rocompat = OBD_ROCOMPAT_LOVOBJID;
                msd->msd_feature_incompat = OBD_INCOMPAT_MDT |
                                                       OBD_INCOMPAT_COMMON_LR;
        } else {
                LCONSOLE_WARN("%s: used disk, loading\n", obd->obd_name);
                rc = mdt_last_rcvd_header_read(env, mdt);
                if (rc) {
                        CERROR("error reading MDS %s: rc %d\n", LAST_RCVD, rc);
                        GOTO(out, rc);
                }
                if (strcmp(msd->msd_uuid, obd->obd_uuid.uuid) != 0) {
                        LCONSOLE_ERROR_MSG(0x157, "Trying to start OBD %s using"
                                           "the wrong disk %s. Were the /dev/ "
                                           "assignments rearranged?\n",
                                           obd->obd_uuid.uuid, msd->msd_uuid);
                        GOTO(out, rc = -EINVAL);
                }
        }
        mount_count = msd->msd_mount_count;

        msd->msd_feature_compat = OBD_COMPAT_MDT;

        spin_lock(&mdt->mdt_transno_lock);
        mdt->mdt_last_transno = msd->msd_last_transno;
        spin_unlock(&mdt->mdt_transno_lock);

        CDEBUG(D_INODE, "========BEGIN DUMPING LAST_RCVD========\n");
        CDEBUG(D_INODE, "%s: server last_transno: "LPU64"\n",
               obd->obd_name, mdt->mdt_last_transno);
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, mount_count + 1);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, msd->msd_server_size);
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, msd->msd_client_start);
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, msd->msd_client_size);
        CDEBUG(D_INODE, "%s: last_rcvd size: %lu\n",
               obd->obd_name, last_rcvd_size);
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= msd->msd_client_start ? 0 :
               (last_rcvd_size - msd->msd_client_start) /
                msd->msd_client_size);
        CDEBUG(D_INODE, "========END DUMPING LAST_RCVD========\n");

        if (!msd->msd_server_size || !msd->msd_client_start ||
            !msd->msd_client_size) {
                CERROR("Bad last_rcvd contents!\n");
                GOTO(out, rc = -EINVAL);
        }

        rc = mdt_clients_data_init(env, mdt, last_rcvd_size);
        if (rc)
                GOTO(err_client, rc);

        spin_lock(&mdt->mdt_transno_lock);
        /* obd_last_committed is used for compatibility
         * with other lustre recovery code */
        obd->obd_last_committed = mdt->mdt_last_transno;
        spin_unlock(&mdt->mdt_transno_lock);

        mdt->mdt_mount_count++;
        msd->msd_mount_count = mdt->mdt_mount_count;

        /* save it, so mount count and last_transno is current */
        rc = mdt_server_data_update(env, mdt);
        if (rc)
                GOTO(err_client, rc);

        RETURN(0);

err_client:
        target_recovery_fini(obd);
out:
        return rc;
}

static int mdt_server_data_update(const struct lu_env *env,
                                  struct mdt_device *mdt)
{
        int rc = 0;
        ENTRY;

        CDEBUG(D_SUPER, "MDS mount_count is "LPU64", last_transno is "LPU64"\n",
               mdt->mdt_mount_count, mdt->mdt_last_transno);

        spin_lock(&mdt->mdt_transno_lock);
        mdt->mdt_msd.msd_last_transno = mdt->mdt_last_transno;
        spin_unlock(&mdt->mdt_transno_lock);

        /*
         * This may be called from difficult reply handler and
         * mdt->mdt_last_rcvd may be NULL that time.
         */
        if (mdt->mdt_last_rcvd != NULL)
                rc = mdt_last_rcvd_header_write(env, mdt);
        RETURN(rc);
}

void mdt_cb_new_client(const struct mdt_device *mdt, __u64 transno,
                                  void *data, int err) 
{
        struct obd_device *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        
        target_client_add_cb(obd, transno, data, err);
}

int mdt_client_new(const struct lu_env *env, struct mdt_device *mdt)
{
        unsigned long *bitmap = mdt->mdt_client_bitmap;
        struct mdt_thread_info *mti;
        struct mdt_export_data *med;
        struct mdt_client_data *mcd;
        struct mdt_server_data *msd = &mdt->mdt_msd;
        struct obd_device *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        struct thandle *th;
        loff_t off;
        int rc;
        int cl_idx;
        ENTRY;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(mti != NULL);

        med = &mti->mti_exp->exp_mdt_data;
        mcd = med->med_mcd;

        LASSERT(bitmap != NULL);
        if (!strcmp(med->med_mcd->mcd_uuid, obd->obd_uuid.uuid))
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        spin_lock(&mdt->mdt_client_bitmap_lock);
        cl_idx = find_first_zero_bit(bitmap, LR_MAX_CLIENTS);
        if (cl_idx >= LR_MAX_CLIENTS ||
            OBD_FAIL_CHECK(OBD_FAIL_MDS_CLIENT_ADD)) {
                CERROR("no room for %u clients - fix LR_MAX_CLIENTS\n",
                       cl_idx);
                spin_unlock(&mdt->mdt_client_bitmap_lock);
                RETURN(-EOVERFLOW);
        }
        set_bit(cl_idx, bitmap);
        spin_unlock(&mdt->mdt_client_bitmap_lock);

        CDEBUG(D_INFO, "client at idx %d with UUID '%s' added\n",
               cl_idx, med->med_mcd->mcd_uuid);

        med->med_lr_idx = cl_idx;
        med->med_lr_off = msd->msd_client_start +
                          (cl_idx * msd->msd_client_size);
        init_mutex(&med->med_mcd_lock);

        LASSERTF(med->med_lr_off > 0, "med_lr_off = %llu\n", med->med_lr_off);
        /* write new client data */
        off = med->med_lr_off;
        th = mdt_trans_start(env, mdt, MDT_TXN_LAST_RCVD_WRITE_CREDITS);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));

        /* until this operations will be committed the sync is needed for this
         * export */
        mdt_trans_add_cb(th, mdt_cb_new_client, mti->mti_exp);
        spin_lock(&mti->mti_exp->exp_lock);
        mti->mti_exp->exp_need_sync = 1;
        spin_unlock(&mti->mti_exp->exp_lock);

        rc = mdt_last_rcvd_write(env, mdt, mcd, &off, th);
        CDEBUG(D_INFO, "wrote client mcd at idx %u off %llu (len %u)\n",
               cl_idx, med->med_lr_off, sizeof(*mcd));
        mdt_trans_stop(env, mdt, th);

        RETURN(rc);
}

/* Add client data to the MDS.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_off is -1 (i.e. a new client).
 * Otherwise, we just have to read the data from the last_rcvd file and
 * we know its offset.
 *
 * It should not be possible to fail adding an existing client - otherwise
 * mdt_init_server_data() callsite needs to be fixed.
 */
int mdt_client_add(const struct lu_env *env,
                   struct mdt_device *mdt, int cl_idx)
{
        struct mdt_thread_info *mti;
        struct mdt_export_data *med;
        unsigned long *bitmap = mdt->mdt_client_bitmap;
        struct obd_device *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        struct mdt_server_data *msd = &mdt->mdt_msd;
        int rc = 0;
        ENTRY;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(mti != NULL);

        med = &mti->mti_exp->exp_mdt_data;

        LASSERT(bitmap != NULL);
        LASSERTF(cl_idx >= 0, "%d\n", cl_idx);

        if (!strcmp(med->med_mcd->mcd_uuid, obd->obd_uuid.uuid))
                RETURN(0);

        spin_lock(&mdt->mdt_client_bitmap_lock);
        if (test_and_set_bit(cl_idx, bitmap)) {
                CERROR("MDS client %d: bit already set in bitmap!!\n",
                       cl_idx);
                LBUG();
        }
        spin_unlock(&mdt->mdt_client_bitmap_lock);

        CDEBUG(D_INFO, "client at idx %d with UUID '%s' added\n",
               cl_idx, med->med_mcd->mcd_uuid);

        med->med_lr_idx = cl_idx;
        med->med_lr_off = msd->msd_client_start +
                          (cl_idx * msd->msd_client_size);
        init_mutex(&med->med_mcd_lock);

        LASSERTF(med->med_lr_off > 0, "med_lr_off = %llu\n", med->med_lr_off);

        RETURN(rc);
}

int mdt_client_del(const struct lu_env *env, struct mdt_device *mdt)
{
        struct mdt_thread_info *mti;
        struct mdt_export_data *med;
        struct mdt_client_data *mcd;
        struct obd_device      *obd = mdt->mdt_md_dev.md_lu_dev.ld_obd;
        struct thandle *th;
        loff_t off;
        int rc = 0;
        ENTRY;

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        LASSERT(mti != NULL);

        med = &mti->mti_exp->exp_mdt_data;
        mcd = med->med_mcd;
        if (!mcd)
                RETURN(0);

        /* XXX: If mcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp(med->med_mcd->mcd_uuid, obd->obd_uuid.uuid))
                GOTO(free, 0);

        CDEBUG(D_INFO, "freeing client at idx %u, offset %lld\n",
               med->med_lr_idx, med->med_lr_off);

        off = med->med_lr_off;

        /*
         * Don't clear med_lr_idx here as it is likely also unset.  At worst we
         * leak a client slot that will be cleaned on the next recovery.
         */
        if (off <= 0) {
                CERROR("client idx %d has offset %lld\n",
                        med->med_lr_idx, off);
                GOTO(free, rc = -EINVAL);
        }

        /*
         * Clear the bit _after_ zeroing out the client so we don't race with
         * mdt_client_add and zero out new clients.
         */
        if (!test_bit(med->med_lr_idx, mdt->mdt_client_bitmap)) {
                CERROR("MDT client %u: bit already clear in bitmap!!\n",
                       med->med_lr_idx);
                LBUG();
        }

        /*
         * This may be called from difficult reply handler path and
         * mdt->mdt_last_rcvd may be NULL that time.
         */
        if (mdt->mdt_last_rcvd != NULL) {
                th = mdt_trans_start(env, mdt, MDT_TXN_LAST_RCVD_WRITE_CREDITS);
                if (IS_ERR(th))
                        GOTO(free, rc = PTR_ERR(th));

                mutex_down(&med->med_mcd_lock);
                memset(mcd, 0, sizeof *mcd);

                rc = mdt_last_rcvd_write(env, mdt, mcd, &off, th);
                mutex_up(&med->med_mcd_lock);
                mdt_trans_stop(env, mdt, th);
        }

        CDEBUG(rc == 0 ? D_INFO : D_ERROR, "Zeroing out client idx %u in "
               "%s rc %d\n",  med->med_lr_idx, LAST_RCVD, rc);

        spin_lock(&mdt->mdt_client_bitmap_lock);
        clear_bit(med->med_lr_idx, mdt->mdt_client_bitmap);
        spin_unlock(&mdt->mdt_client_bitmap_lock);
        
        /*
         * Make sure the server's last_transno is up to date. Do this after the
         * client is freed so we know all the client's transactions have been
         * committed.
         */
        mdt_server_data_update(env, mdt);
        EXIT;
free:
        OBD_FREE_PTR(mcd);
        med->med_mcd = NULL;
        return 0;
}

/*
 * last_rcvd & last_committed update callbacks
 */
static int mdt_last_rcvd_update(struct mdt_thread_info *mti,
                                struct thandle *th)
{
        struct mdt_device *mdt = mti->mti_mdt;
        struct ptlrpc_request *req = mdt_info_req(mti);
        struct mdt_export_data *med;
        struct mdt_client_data *mcd;
        loff_t off;
        int err;
        __s32 rc = th->th_result;
        __u64 *transno_p;

        ENTRY;
        LASSERT(req);
        LASSERT(req->rq_export);
        LASSERT(mdt);
        med = &req->rq_export->exp_mdt_data;
        LASSERT(med);
        mcd = med->med_mcd;
        /* if the export has already been failed, we have no last_rcvd slot */
        if (req->rq_export->exp_failed) {
                CWARN("commit transaction for disconnected client %s: rc %d\n",
                      req->rq_export->exp_client_uuid.uuid, rc);
                if (rc == 0)
                        rc = -ENOTCONN;
                RETURN(rc);
        }

        off = med->med_lr_off;
        mutex_down(&med->med_mcd_lock);
        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE ||
            lustre_msg_get_opc(req->rq_reqmsg) == MDS_DONE_WRITING) {
                transno_p = &mcd->mcd_last_close_transno;
                mcd->mcd_last_close_xid = req->rq_xid;
                mcd->mcd_last_close_result = rc;
        } else {
                transno_p = &mcd->mcd_last_transno;
                mcd->mcd_last_xid = req->rq_xid;
                mcd->mcd_last_result = rc;
                /*XXX: save intent_disposition in mdt_thread_info?
                 * also there is bug - intent_dispostion is __u64,
                 * see struct ldlm_reply->lock_policy_res1; */
                 mcd->mcd_last_data = mti->mti_opdata;
        }

        /*
         * When we store zero transno in mcd we can lost last transno value
         * because mcd contains 0, but msd is not yet written
         * The server data should be updated also if the latest 
         * transno is rewritten by zero. See the bug 11125 for details.
         */
        if (mti->mti_transno == 0 && 
            *transno_p == mdt->mdt_last_transno)
                mdt_server_data_update(mti->mti_env, mdt);

        *transno_p = mti->mti_transno;

        if (off <= 0) {
                CERROR("client idx %d has offset %lld\n", med->med_lr_idx, off);
                err = -EINVAL;
        } else {
                err = mdt_last_rcvd_write(mti->mti_env, mdt, mcd, &off, th);
        }
        mutex_up(&med->med_mcd_lock);
        RETURN(err);
}

extern struct lu_context_key mdt_thread_key;

/* add credits for last_rcvd update */
static int mdt_txn_start_cb(const struct lu_env *env,
                            struct txn_param *param, void *cookie)
{
        param->tp_credits += MDT_TXN_LAST_RCVD_WRITE_CREDITS;
        return 0;
}

/* Update last_rcvd records with latests transaction data */
static int mdt_txn_stop_cb(const struct lu_env *env,
                           struct thandle *txn, void *cookie)
{
        struct mdt_device *mdt = cookie;
        struct mdt_txn_info *txi;
        struct mdt_thread_info *mti;
        struct ptlrpc_request *req;

        /* transno in two contexts - for commit_cb and for thread */
        txi = lu_context_key_get(&txn->th_ctx, &mdt_txn_key);
        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        req = mdt_info_req(mti);

        if (mti->mti_mdt == NULL || req == NULL || mti->mti_no_need_trans) {
                txi->txi_transno = 0;
                mti->mti_no_need_trans = 0;
                return 0;
        }

        if (mti->mti_has_trans) {
                /* XXX: currently there are allowed cases, but the wrong cases
                 * are also possible, so better check is needed here */
                CDEBUG(D_INFO, "More than one transaction "LPU64"\n", mti->mti_transno);
                return 0;
        }

        mti->mti_has_trans = 1;
        spin_lock(&mdt->mdt_transno_lock);
        if (txn->th_result != 0) {
                if (mti->mti_transno != 0) {
                        CERROR("Replay transno "LPU64" failed: rc %i\n",
                               mti->mti_transno, txn->th_result);
                        mti->mti_transno = 0;
                }
        } else if (mti->mti_transno == 0) {
                mti->mti_transno = ++ mdt->mdt_last_transno;
        } else {
                /* should be replay */
                if (mti->mti_transno > mdt->mdt_last_transno)
                        mdt->mdt_last_transno = mti->mti_transno;
        }

        /* sometimes the reply message has not been successfully packed */
        LASSERT(req != NULL && req->rq_repmsg != NULL);

        /* filling reply data */
        CDEBUG(D_INODE, "transno = %llu, last_committed = %llu\n",
               mti->mti_transno, req->rq_export->exp_obd->obd_last_committed);

        req->rq_transno = mti->mti_transno;
        lustre_msg_set_transno(req->rq_repmsg, mti->mti_transno);
        lustre_msg_set_last_xid(req->rq_repmsg,
                         mcd_last_xid(req->rq_export->exp_mdt_data.med_mcd));
        /* save transno for the commit callback */
        txi->txi_transno = mti->mti_transno;
        spin_unlock(&mdt->mdt_transno_lock);

        return mdt_last_rcvd_update(mti, txn);
}

/* commit callback, need to update last_commited value */
static int mdt_txn_commit_cb(const struct lu_env *env,
                             struct thandle *txn, void *cookie)
{
        struct mdt_device *mdt = cookie;
        struct obd_device *obd = md2lu_dev(&mdt->mdt_md_dev)->ld_obd;
        struct mdt_txn_info *txi;
        int i;

        txi = lu_context_key_get(&txn->th_ctx, &mdt_txn_key);

        /* copy of obd_transno_commit_cb() but with locking */
        spin_lock(&mdt->mdt_transno_lock);
        if (txi->txi_transno > obd->obd_last_committed) {
                obd->obd_last_committed = txi->txi_transno;
                spin_unlock(&mdt->mdt_transno_lock);
                ptlrpc_commit_replies(obd);
        } else
                spin_unlock(&mdt->mdt_transno_lock);

        if (txi->txi_transno)
                CDEBUG(D_HA, "%s: transno "LPD64" is committed\n",
                       obd->obd_name, txi->txi_transno);

        /* iterate through all additional callbacks */
        for (i = 0; i < txi->txi_cb_count; i++) {
                txi->txi_cb[i].mdt_cb_func(mdt, txi->txi_transno,
                                           txi->txi_cb[i].mdt_cb_data, 0);
        }
        return 0;
}

int mdt_fs_setup(const struct lu_env *env, struct mdt_device *mdt,
                 struct obd_device *obd)
{
        struct lu_fid fid;
        struct dt_object *o;
        int rc = 0;
        ENTRY;

        if (OBD_FAIL_CHECK(OBD_FAIL_MDS_FS_SETUP))
                RETURN(-ENOENT);

        /* prepare transactions callbacks */
        mdt->mdt_txn_cb.dtc_txn_start = mdt_txn_start_cb;
        mdt->mdt_txn_cb.dtc_txn_stop = mdt_txn_stop_cb;
        mdt->mdt_txn_cb.dtc_txn_commit = mdt_txn_commit_cb;
        mdt->mdt_txn_cb.dtc_cookie = mdt;
        CFS_INIT_LIST_HEAD(&mdt->mdt_txn_cb.dtc_linkage);

        dt_txn_callback_add(mdt->mdt_bottom, &mdt->mdt_txn_cb);

        o = dt_store_open(env, mdt->mdt_bottom, LAST_RCVD, &fid);
        if (!IS_ERR(o)) {
                mdt->mdt_last_rcvd = o;
                rc = mdt_server_data_init(env, mdt);
                if (rc)
                        GOTO(put_last_rcvd, rc);
        } else {
                rc = PTR_ERR(o);
                CERROR("cannot open %s: rc = %d\n", LAST_RCVD, rc);
                RETURN(rc);
        }

        o = dt_store_open(env, mdt->mdt_bottom, CAPA_KEYS, &fid);
        if (!IS_ERR(o)) {
                mdt->mdt_ck_obj = o;
                rc = mdt_capa_keys_init(env, mdt);
                if (rc)
                        GOTO(put_ck_object, rc);
        } else {
                rc = PTR_ERR(o);
                CERROR("cannot open %s: rc = %d\n", CAPA_KEYS, rc);
                GOTO(put_last_rcvd, rc);
        }
        RETURN(0);

put_ck_object:
        lu_object_put(env, &o->do_lu);
        mdt->mdt_ck_obj = NULL;
put_last_rcvd:
        lu_object_put(env, &mdt->mdt_last_rcvd->do_lu);
        mdt->mdt_last_rcvd = NULL;
        return rc;
}


void mdt_fs_cleanup(const struct lu_env *env, struct mdt_device *mdt)
{
        ENTRY;

        /* Remove transaction callback */
        dt_txn_callback_del(mdt->mdt_bottom, &mdt->mdt_txn_cb);
        if (mdt->mdt_last_rcvd)
                lu_object_put(env, &mdt->mdt_last_rcvd->do_lu);
        mdt->mdt_last_rcvd = NULL;
        if (mdt->mdt_ck_obj)
                lu_object_put(env, &mdt->mdt_ck_obj->do_lu);
        mdt->mdt_ck_obj = NULL;
        EXIT;
}

/* reconstruction code */
static void mdt_steal_ack_locks(struct ptlrpc_request *req)
{
        struct obd_export         *exp = req->rq_export;
        struct list_head          *tmp;
        struct ptlrpc_reply_state *oldrep;
        struct ptlrpc_service     *svc;
        int                        i;

        /* CAVEAT EMPTOR: spinlock order */
        spin_lock(&exp->exp_lock);
        list_for_each (tmp, &exp->exp_outstanding_replies) {
                oldrep = list_entry(tmp, struct ptlrpc_reply_state,rs_exp_list);

                if (oldrep->rs_xid != req->rq_xid)
                        continue;

                if (lustre_msg_get_opc(oldrep->rs_msg) !=
                    lustre_msg_get_opc(req->rq_reqmsg))
                        CERROR ("Resent req xid "LPX64" has mismatched opc: "
                                "new %d old %d\n", req->rq_xid,
                                lustre_msg_get_opc(req->rq_reqmsg),
                                lustre_msg_get_opc(oldrep->rs_msg));

                svc = oldrep->rs_service;
                spin_lock (&svc->srv_lock);

                list_del_init (&oldrep->rs_exp_list);

                CWARN("Stealing %d locks from rs %p x"LPD64".t"LPD64
                      " o%d NID %s\n",
                      oldrep->rs_nlocks, oldrep,
                      oldrep->rs_xid, oldrep->rs_transno,
                      lustre_msg_get_opc(oldrep->rs_msg),
                      libcfs_nid2str(exp->exp_connection->c_peer.nid));

                for (i = 0; i < oldrep->rs_nlocks; i++)
                        ptlrpc_save_lock(req,
                                         &oldrep->rs_locks[i],
                                         oldrep->rs_modes[i]);
                oldrep->rs_nlocks = 0;

                DEBUG_REQ(D_HA, req, "stole locks for");
                ptlrpc_schedule_difficult_reply (oldrep);

                spin_unlock (&svc->srv_lock);
                break;
        }
        spin_unlock(&exp->exp_lock);
}

void mdt_req_from_mcd(struct ptlrpc_request *req,
                      struct mdt_client_data *mcd)
{
        DEBUG_REQ(D_HA, req, "restoring transno "LPD64"/status %d",
                  mcd->mcd_last_transno, mcd->mcd_last_result);

        if (lustre_msg_get_opc(req->rq_reqmsg) == MDS_CLOSE ||
            lustre_msg_get_opc(req->rq_repmsg) == MDS_DONE_WRITING) {
                req->rq_transno = mcd->mcd_last_close_transno;
                req->rq_status = mcd->mcd_last_close_result;
                lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
                lustre_msg_set_status(req->rq_repmsg, req->rq_status);
        } else {
                req->rq_transno = mcd->mcd_last_transno;
                req->rq_status = mcd->mcd_last_result;
                lustre_msg_set_transno(req->rq_repmsg, req->rq_transno);
                lustre_msg_set_status(req->rq_repmsg, req->rq_status);
        }
        mdt_steal_ack_locks(req);
}

void mdt_reconstruct_generic(struct mdt_thread_info *mti,
                             struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request *req = mdt_info_req(mti);
        struct mdt_export_data *med = &req->rq_export->exp_mdt_data;

        return mdt_req_from_mcd(req, med->med_mcd);
}

static void mdt_reconstruct_create(struct mdt_thread_info *mti,
                                   struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request  *req = mdt_info_req(mti);
        struct mdt_export_data *med = &req->rq_export->exp_mdt_data;
        struct mdt_device *mdt = mti->mti_mdt;
        struct mdt_object *child;
        struct mdt_body *body;
        int rc;

        mdt_req_from_mcd(req, med->med_mcd);
        if (req->rq_status)
                return;

        /* if no error, so child was created with requested fid */
        child = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid2);
        LASSERT(!IS_ERR(child));

        body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
        rc = mo_attr_get(mti->mti_env, mdt_object_child(child), &mti->mti_attr);
        if (rc == -EREMOTE) {
                /* object was created on remote server */
                req->rq_status = rc;
                body->valid |= OBD_MD_MDS;
        }
        mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr, mdt_object_fid(child));
        mdt_object_put(mti->mti_env, child);
}

static void mdt_reconstruct_setattr(struct mdt_thread_info *mti,
                                    struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request  *req = mdt_info_req(mti);
        struct mdt_export_data *med = &req->rq_export->exp_mdt_data;
        struct mdt_device *mdt = mti->mti_mdt;
        struct mdt_object *obj;
        struct mdt_body *body;

        mdt_req_from_mcd(req, med->med_mcd);
        if (req->rq_status)
                return;

        body = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
        obj = mdt_object_find(mti->mti_env, mdt, mti->mti_rr.rr_fid1);
        LASSERT(!IS_ERR(obj));
        mo_attr_get(mti->mti_env, mdt_object_child(obj), &mti->mti_attr);
        mdt_pack_attr2body(mti, body, &mti->mti_attr.ma_attr,
                           mdt_object_fid(obj));
        if (mti->mti_epoch && (mti->mti_epoch->flags & MF_EPOCH_OPEN)) {
                struct mdt_file_data *mfd;
                struct mdt_body *repbody;

                repbody = req_capsule_server_get(mti->mti_pill, &RMF_MDT_BODY);
                repbody->ioepoch = obj->mot_ioepoch;
                spin_lock(&med->med_open_lock);
                list_for_each_entry(mfd, &med->med_open_head, mfd_list) {
                        if (mfd->mfd_xid == req->rq_xid)
                                break;
                }
                LASSERT(&mfd->mfd_list != &med->med_open_head);
                spin_unlock(&med->med_open_lock);
                repbody->handle.cookie = mfd->mfd_handle.h_cookie;
        }

        mdt_object_put(mti->mti_env, obj);
}

static void mdt_reconstruct_setxattr(struct mdt_thread_info *mti,
                                     struct mdt_lock_handle *lhc)
{
        /* reply nothing */
        req_capsule_shrink(mti->mti_pill, &RMF_EADATA, 0, RCL_SERVER);
}

typedef void (*mdt_reconstructor)(struct mdt_thread_info *mti,
                                  struct mdt_lock_handle *lhc);

static mdt_reconstructor reconstructors[REINT_MAX] = {
        [REINT_SETATTR]  = mdt_reconstruct_setattr,
        [REINT_CREATE]   = mdt_reconstruct_create,
        [REINT_LINK]     = mdt_reconstruct_generic,
        [REINT_UNLINK]   = mdt_reconstruct_generic,
        [REINT_RENAME]   = mdt_reconstruct_generic,
        [REINT_OPEN]     = mdt_reconstruct_open,
        [REINT_SETXATTR] = mdt_reconstruct_setxattr
};

void mdt_reconstruct(struct mdt_thread_info *mti,
                     struct mdt_lock_handle *lhc)
{
        ENTRY;
        reconstructors[mti->mti_rr.rr_opcode](mti, lhc);
        EXIT;
}
