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
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/filter_fs.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Alex Tomas <alex@clusterfs.com>
 * Author: Mike Pershin <tappro@sun.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

obd_id filter_last_id(struct filter_device *ofd, obd_gr group)
{
        obd_id id;

        LASSERT(group <= ofd->ofd_max_group);

        spin_lock(&ofd->ofd_objid_lock);
        id = ofd->ofd_last_objids[group];
        spin_unlock(&ofd->ofd_objid_lock);

        return id;
}

void filter_last_id_set(struct filter_device *ofd, obd_id id, obd_gr group)
{
        LASSERT(group <= ofd->ofd_max_group);
        spin_lock(&ofd->ofd_objid_lock);
        if (ofd->ofd_last_objids[group] < id)
                ofd->ofd_last_objids[group] = id;
        spin_unlock(&ofd->ofd_objid_lock);
}

int filter_last_id_read(const struct lu_env *env, struct filter_device *ofd,
                        obd_gr group)
{
        struct filter_thread_info *info = filter_info(env);
        struct lu_buf              buf;
        loff_t                     off;
        obd_id tmp;
        int rc;
        ENTRY;

        LASSERT(ofd->ofd_groups_file != NULL);
        LASSERT(info);

        buf.lb_buf = &tmp;
        buf.lb_len = sizeof(tmp);
        off = group * sizeof(tmp);

        rc = dt_record_read(env, ofd->ofd_groups_file, &buf, &off, NULL);
        if (rc >= 0) {
                filter_last_id_set(ofd, le64_to_cpu(tmp), group);
                CDEBUG(D_INODE, "%s: read last_objid for group "LPU64": "
                       LPU64"\n", filter_obd(ofd)->obd_name, group,
                       filter_last_id(ofd, group));
        } else
                CERROR("read group "LPU64" last objid: rc = %d\n", group, rc);

        RETURN(rc);
}

int filter_last_id_write(const struct lu_env *env, struct filter_device *ofd,
                         obd_gr group, int force_sync)
{
        struct thandle *th;
        struct lu_buf   buf;
        obd_id          tmp;
        loff_t          off;
        int             rc;
        ENTRY;

        CDEBUG(D_INODE, "%s: write last_objid for group "LPU64": "LPU64"\n",
               filter_obd(ofd)->obd_name, group, filter_last_id(ofd, group));

        LASSERT(ofd->ofd_groups_file != NULL);

        tmp = cpu_to_le64(filter_last_id(ofd, group));
        buf.lb_buf = &tmp;
        buf.lb_len = sizeof(tmp);
        off = group * sizeof(tmp);

        th = filter_trans_create(env, ofd);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));
        rc = dt_declare_record_write(env, ofd->ofd_groups_file,
                                     buf.lb_len, off, th);
        LASSERT(rc == 0);
        rc = filter_trans_start(env, ofd, th);
        if (rc)
                RETURN(rc);

        rc = dt_record_write(env, ofd->ofd_groups_file, &buf, &off,
                             th, BYPASS_CAPA, 1);
        if (rc)
                CERROR("write group "LPU64" last objid: rc = %d\n", group, rc);

        filter_trans_stop(env, ofd, th);

        RETURN(rc);
}

/* filter groups managements */
int filter_groups_init(const struct lu_env *env, struct filter_device *ofd)
{
        struct filter_thread_info *info = filter_info(env);
        unsigned long groups_size;
        struct lu_buf buf;
        loff_t        off;
        obd_id lastid;
        int rc, i;

        spin_lock_init(&ofd->ofd_objid_lock);

        rc = dt_attr_get(env, ofd->ofd_groups_file, &info->fti_attr,
                         BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        groups_size = (unsigned long)info->fti_attr.la_size;

        if (groups_size == 0) {
                CWARN("%s: no groups yet\n", filter_obd(ofd)->obd_name);
                RETURN(0);
        }

        if (groups_size % sizeof(lastid) != 0) {
                CERROR("groups file is corrupted? size = %lu\n", groups_size);
                RETURN(-EIO);
        }

        ofd->ofd_max_group = groups_size / sizeof(lastid);
        LASSERT(ofd->ofd_max_group <= FILTER_MAX_GROUPS); /* XXX: dynamic? */

        off = 0;
        buf.lb_buf = &ofd->ofd_last_objids;
        buf.lb_len = sizeof(lastid) * ofd->ofd_max_group;
        rc = dt_record_read(env, ofd->ofd_groups_file, &buf, &off, NULL);
        if (rc) {
                CERROR("can't initialize last_ids: %d\n", rc);
                RETURN(rc);
        }
        /* last objids are stored in le format, convert them to cpu */
        spin_lock(&ofd->ofd_objid_lock);
        for (i = 0; i < groups_size; i++)
                ofd->ofd_last_objids[i] = le64_to_cpu(ofd->ofd_last_objids[i]);
        spin_unlock(&ofd->ofd_objid_lock);

        CWARN("%s: %u groups initialized\n", filter_obd(ofd)->obd_name,
              ofd->ofd_max_group);
        RETURN(0);
}

static inline void fsd_le_to_cpu(struct lr_server_data *buf,
                                 struct lr_server_data *lsd)
{
        memcpy(lsd->lsd_uuid, buf->lsd_uuid, sizeof (lsd->lsd_uuid));
        lsd->lsd_last_transno     = le64_to_cpu(buf->lsd_last_transno);
        lsd->lsd_compat14         = le64_to_cpu(buf->lsd_compat14);
        lsd->lsd_mount_count      = le64_to_cpu(buf->lsd_mount_count);
        lsd->lsd_feature_compat   = le32_to_cpu(buf->lsd_feature_compat);
        lsd->lsd_feature_rocompat = le32_to_cpu(buf->lsd_feature_rocompat);
        lsd->lsd_feature_incompat = le32_to_cpu(buf->lsd_feature_incompat);
        lsd->lsd_server_size      = le32_to_cpu(buf->lsd_server_size);
        lsd->lsd_client_start     = le32_to_cpu(buf->lsd_client_start);
        lsd->lsd_client_size      = le16_to_cpu(buf->lsd_client_size);
        lsd->lsd_subdir_count     = le16_to_cpu(buf->lsd_subdir_count);
        lsd->lsd_catalog_oid      = le64_to_cpu(buf->lsd_catalog_oid);
        lsd->lsd_catalog_ogen     = le32_to_cpu(buf->lsd_catalog_ogen);
        memcpy(lsd->lsd_peeruuid, buf->lsd_peeruuid,
               sizeof (lsd->lsd_peeruuid));
        lsd->lsd_ost_index        = le32_to_cpu(buf->lsd_ost_index);
        lsd->lsd_mdt_index        = le32_to_cpu(buf->lsd_mdt_index);
}

static inline void fsd_cpu_to_le(struct lr_server_data *lsd,
                                 struct lr_server_data *buf)
{
        memcpy(buf->lsd_uuid, lsd->lsd_uuid, sizeof (lsd->lsd_uuid));
        buf->lsd_last_transno     = cpu_to_le64(lsd->lsd_last_transno);
        buf->lsd_compat14         = cpu_to_le64(lsd->lsd_compat14);
        buf->lsd_mount_count      = cpu_to_le64(lsd->lsd_mount_count);
        buf->lsd_feature_compat   = cpu_to_le32(lsd->lsd_feature_compat);
        buf->lsd_feature_rocompat = cpu_to_le32(lsd->lsd_feature_rocompat);
        buf->lsd_feature_incompat = cpu_to_le32(lsd->lsd_feature_incompat);
        buf->lsd_server_size      = cpu_to_le32(lsd->lsd_server_size);
        buf->lsd_client_start     = cpu_to_le32(lsd->lsd_client_start);
        buf->lsd_client_size      = cpu_to_le16(lsd->lsd_client_size);
        buf->lsd_subdir_count     = cpu_to_le16(lsd->lsd_subdir_count);
        buf->lsd_catalog_oid      = cpu_to_le64(lsd->lsd_catalog_oid);
        buf->lsd_catalog_ogen     = cpu_to_le32(lsd->lsd_catalog_ogen);
        memcpy(buf->lsd_peeruuid, lsd->lsd_peeruuid,
               sizeof (lsd->lsd_peeruuid));
        buf->lsd_ost_index        = cpu_to_le32(lsd->lsd_ost_index);
        buf->lsd_mdt_index        = cpu_to_le32(lsd->lsd_mdt_index);
}

static inline void lcd_le_to_cpu(struct lsd_client_data *buf,
                                 struct lsd_client_data *lcd)
{
        memcpy(lcd->lcd_uuid, buf->lcd_uuid, sizeof (lcd->lcd_uuid));
        lcd->lcd_last_transno = le64_to_cpu(buf->lcd_last_transno);
        lcd->lcd_last_xid  = le64_to_cpu(buf->lcd_last_xid);
#if 0
        lcd->lcd_group     = le32_to_cpu(buf->lcd_group);
#endif
}

static inline void lcd_cpu_to_le(struct lsd_client_data *lcd,
                                 struct lsd_client_data *buf)
{
        memcpy(buf->lcd_uuid, lcd->lcd_uuid, sizeof (lcd->lcd_uuid));
        buf->lcd_last_transno = cpu_to_le64(lcd->lcd_last_transno);
        buf->lcd_last_xid  = cpu_to_le64(lcd->lcd_last_xid);
#if 0
        buf->lcd_group     = cpu_to_le32(lcd->lcd_group);
#endif
}

static int filter_last_rcvd_header_read(const struct lu_env *env,
                                        struct filter_device *ofd)
{
        struct filter_thread_info *info = filter_info(env);
        struct lu_buf              buf;
        loff_t                     off;
        int rc;

        off = 0;
        buf.lb_buf = &info->fti_fsd;
        buf.lb_len = sizeof(info->fti_fsd);

        rc = dt_record_read(env, ofd->ofd_last_rcvd, &buf, &off, BYPASS_CAPA);
        if (rc == 0)
                fsd_le_to_cpu(&info->fti_fsd, &ofd->ofd_fsd);
        return rc;
}

int filter_last_rcvd_header_write(const struct lu_env *env,
                                  struct filter_device *ofd,
                                  struct thandle *th)
{
        struct filter_thread_info *info;
        struct lu_buf              buf;
        loff_t                     off;
        int                        rc;
        ENTRY;

        info = lu_context_key_get(&env->le_ctx, &filter_thread_key);
        LASSERT(info);

        buf.lb_buf = &info->fti_fsd;
        buf.lb_len = sizeof(info->fti_fsd);
        off = 0;

        fsd_cpu_to_le(&ofd->ofd_fsd, &info->fti_fsd);

        rc = dt_record_write(env, ofd->ofd_last_rcvd, &buf,
                             &off, th, BYPASS_CAPA, 1);
        CDEBUG(D_INFO, "write last_rcvd header rc = %d:\n"
               "uuid = %s\nlast_transno = "LPU64"\n",
               rc, ofd->ofd_fsd.lsd_uuid, ofd->ofd_fsd.lsd_last_transno);

        RETURN(rc);
}

static int filter_last_rcvd_read(const struct lu_env *env,
                                 struct filter_device *ofd,
                                 struct lsd_client_data *lcd, loff_t *off)
{
        struct filter_thread_info *info = filter_info(env);
        struct lu_buf              buf;
        int rc;

        buf.lb_buf = &info->fti_fsd;
        buf.lb_len = sizeof(info->fti_fsd);

        rc = dt_record_read(env, ofd->ofd_last_rcvd, &buf, off, BYPASS_CAPA);
        if (rc == 0)
                lcd_le_to_cpu((struct lsd_client_data *) &info->fti_fsd, lcd);
        return rc;
}

int filter_last_rcvd_write(const struct lu_env *env,
                           struct filter_device *ofd,
                           struct lsd_client_data *lcd,
                           loff_t *off, struct thandle *th)
{
        struct filter_thread_info *info = filter_info(env);
        struct lu_buf              buf;
        int rc;

        lcd_cpu_to_le(lcd, (struct lsd_client_data *) &info->fti_fsd);

        buf.lb_buf = &info->fti_fsd;
        buf.lb_len = sizeof(info->fti_fsd);

        rc = dt_record_write(env, ofd->ofd_last_rcvd, &buf,
                             off, th, BYPASS_CAPA, 1);
        return rc;
}

static inline int filter_clients_data_init(const struct lu_env *env,
                                           struct filter_device *ofd,
                                           unsigned long fsize)
{
        struct obd_device *obd = filter_obd(ofd);
        struct lr_server_data *fsd = &ofd->ofd_fsd;
        struct lsd_client_data *lcd = NULL;
        struct filter_export_data *fed;
        int cl_idx, rc = 0;
        loff_t off = fsd->lsd_client_start;

        CLASSERT (offsetof(struct lsd_client_data, lcd_padding) +
                 sizeof(lcd->lcd_padding) == LR_CLIENT_SIZE);

        for (cl_idx = 0; off < fsize; cl_idx++) {
                struct obd_export *exp;
                __u64 last_rcvd;

                if (!lcd) {
                        OBD_ALLOC_PTR(lcd);
                        if (!lcd)
                                GOTO(err_out, rc = -ENOMEM);
                }

                /* Don't assume off is incremented properly by
                 * fsfilt_read_record(), in case sizeof(*lcd)
                 * isn't the same as fsd->lsd_client_size.  */
                off = fsd->lsd_client_start + cl_idx * fsd->lsd_client_size;
                rc = filter_last_rcvd_read(env, ofd, lcd, &off);
                if (rc) {
                        CERROR("error reading FILT %s idx %d off %llu: rc %d\n",
                               LAST_RCVD, cl_idx, off, rc);
                        rc = 0;
                        break; /* read error shouldn't cause startup to fail */
                }

                if (lcd->lcd_uuid[0] == '\0') {
                        CDEBUG(D_INFO, "skipping zeroed client at offset %d\n",
                               cl_idx);
                        continue;
                }

                last_rcvd = lcd->lcd_last_transno;

                /* These exports are cleaned up by filter_disconnect(), so they
                 * need to be set up like real exports as filter_connect() does.
                 */
                exp = class_new_export(obd, (struct obd_uuid *)lcd->lcd_uuid);

                CDEBUG(D_HA, "RCVRNG CLIENT uuid: %s idx: %d lr: "LPU64
                       " srv lr: "LPU64"\n", lcd->lcd_uuid, cl_idx,
                       last_rcvd, fsd->lsd_last_transno);

                if (IS_ERR(exp)) {
                        if (PTR_ERR(exp) == -EALREADY) {
                                /* export already exists, zero out this one */
                                CERROR("Zeroing out duplicate export due to "
                                       "bug 10479.\n");
                                lcd->lcd_uuid[0] = '\0';
                        } else {
                                GOTO(err_out, rc = PTR_ERR(exp));
                        }
                } else {
                        fed = &exp->exp_filter_data;
                        fed->fed_lcd = lcd;
#if 0
                        fed->fed_group = lcd->lcd_group;
#endif
                        filter_export_stats_init(ofd, exp, NULL);
                        rc = filter_client_add(env, ofd, fed, cl_idx);
                        LASSERTF(rc == 0, "rc = %d\n", rc); /* can't fail existing */

                        lcd = NULL;
                        spin_lock(&exp->exp_lock);
                        exp->exp_connecting = 0;
                        exp->exp_in_recovery = 0;
                        spin_unlock(&exp->exp_lock);
                        obd->obd_max_recoverable_clients++;
                        class_export_put(exp);
                }

                /* Need to check last_rcvd even for duplicated exports. */
                CDEBUG(D_OTHER, "client at idx %d has last_rcvd = "LPU64"\n",
                       cl_idx, last_rcvd);

                spin_lock(&ofd->ofd_transno_lock);
                if (last_rcvd > fsd->lsd_last_transno)
                        fsd->lsd_last_transno = last_rcvd;
                spin_unlock(&ofd->ofd_transno_lock);
        }

        if (lcd)
                OBD_FREE(lcd, sizeof(*lcd));
err_out:
        RETURN(rc);
}

void filter_free_server_data(void)
{
        LBUG();
}

int filter_server_data_update(const struct lu_env *env,
                              struct filter_device *ofd)
{
        int rc = 0;
        ENTRY;

        CDEBUG(D_SUPER, "OSS mount_count is "LPU64", last_transno is "LPU64"\n",
               ofd->ofd_fsd.lsd_mount_count, ofd->ofd_fsd.lsd_last_transno);

        spin_lock(&ofd->ofd_transno_lock);
        ofd->ofd_fsd.lsd_last_transno = ofd->ofd_last_transno;
        spin_unlock(&ofd->ofd_transno_lock);

        /*
         * This may be called from difficult reply handler and
         * mdt->mdt_last_rcvd may be NULL that time.
         */
        if (ofd->ofd_last_rcvd != NULL) {
                struct thandle *th;

                th = filter_trans_create0(env, ofd);
                if (IS_ERR(th))
                        RETURN(PTR_ERR(th));
                dt_declare_record_write(env, ofd->ofd_last_rcvd,
                                        sizeof(ofd->ofd_fsd), 0, th);
                rc = filter_trans_start(env, ofd, th);
                if (rc)
                        RETURN(rc);
                rc = filter_last_rcvd_header_write(env, ofd, th);
                filter_trans_stop(env, ofd, th);
        }

        RETURN(rc);
}

int filter_server_data_init(const struct lu_env *env,
                            struct filter_device *ofd)
{
        struct filter_thread_info *info = filter_info(env);
        struct lr_server_data *fsd = &ofd->ofd_fsd;
        struct obd_device *obd = filter_obd(ofd);
        unsigned long last_rcvd_size;
#if 0
        __u64 mount_count;
#endif
        int rc;

        rc = dt_attr_get(env, ofd->ofd_last_rcvd, &info->fti_attr, BYPASS_CAPA);
        if (rc)
                RETURN(rc);

        last_rcvd_size = (unsigned long)info->fti_attr.la_size;

        /* ensure padding in the struct is the correct size */
        CLASSERT (offsetof(struct lr_server_data, lsd_padding) +
                  sizeof(fsd->lsd_padding) == LR_SERVER_SIZE);

        if (last_rcvd_size == 0) {
                LCONSOLE_WARN("%s: new disk, initializing\n", obd->obd_name);

                memcpy(fsd->lsd_uuid, obd->obd_uuid.uuid,
                       sizeof(fsd->lsd_uuid));
                fsd->lsd_last_transno = 0;
                fsd->lsd_mount_count = 0;
                fsd->lsd_server_size = LR_SERVER_SIZE;
                fsd->lsd_client_start = LR_CLIENT_START;
                fsd->lsd_client_size = LR_CLIENT_SIZE;
                fsd->lsd_subdir_count = FILTER_SUBDIR_COUNT;
                fsd->lsd_feature_incompat = OBD_INCOMPAT_OST;
        } else {
                rc = filter_last_rcvd_header_read(env, ofd);
                if (rc) {
                        CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                               LAST_RCVD, rc);
                        GOTO(err_fsd, rc);
                }
                if (strcmp((char *) fsd->lsd_uuid, (char *) obd->obd_uuid.uuid)) {
                        LCONSOLE_ERROR("Trying to start OBD %s using the wrong"
                                       " disk %s. Were the /dev/ assignments "
                                       "rearranged?\n",
                                       obd->obd_uuid.uuid, fsd->lsd_uuid);
                        GOTO(err_fsd, rc = -EINVAL);
                }
        }

        fsd->lsd_mount_count++;
        ofd->ofd_subdir_count = fsd->lsd_subdir_count;

        if (fsd->lsd_feature_incompat & ~FILTER_INCOMPAT_SUPP) {
                CERROR("%s: unsupported incompat filesystem feature(s) %x\n",
                       obd->obd_name,
                       fsd->lsd_feature_incompat & ~FILTER_INCOMPAT_SUPP);
                GOTO(err_fsd, rc = -EINVAL);
        }
        if (fsd->lsd_feature_rocompat & ~FILTER_ROCOMPAT_SUPP) {
                CERROR("%s: unsupported read-only filesystem feature(s) %x\n",
                       obd->obd_name, 
                       fsd->lsd_feature_rocompat & ~FILTER_ROCOMPAT_SUPP);
                /* Do something like remount filesystem read-only */
                GOTO(err_fsd, rc = -EINVAL);
        }

        CDEBUG(D_INODE, "%s: server last_transno : "LPU64"\n",
               obd->obd_name, fsd->lsd_last_transno);
        CDEBUG(D_INODE, "%s: server mount_count: "LPU64"\n",
               obd->obd_name, fsd->lsd_mount_count);
        CDEBUG(D_INODE, "%s: server data size: %u\n",
               obd->obd_name, fsd->lsd_server_size);
        CDEBUG(D_INODE, "%s: per-client data start: %u\n",
               obd->obd_name, fsd->lsd_client_start);
        CDEBUG(D_INODE, "%s: per-client data size: %u\n",
               obd->obd_name, fsd->lsd_client_size);
        CDEBUG(D_INODE, "%s: server subdir_count: %u\n",
               obd->obd_name, fsd->lsd_subdir_count);
        CDEBUG(D_INODE, "%s: last_rcvd clients: %lu\n", obd->obd_name,
               last_rcvd_size <= fsd->lsd_client_start ? 0 :
               (last_rcvd_size - fsd->lsd_client_start) /
                fsd->lsd_client_size);

        if (!obd->obd_replayable) {
                CWARN("%s: recovery support OFF\n", obd->obd_name);
        }

        rc = filter_clients_data_init(env, ofd, last_rcvd_size);

        spin_lock(&ofd->ofd_transno_lock);
        obd->obd_last_committed = fsd->lsd_last_transno;
        spin_unlock(&ofd->ofd_transno_lock);

        /* save it, so mount count and last_transno is current */
        rc = filter_server_data_update(env, ofd);
        if (rc)
                GOTO(err_fsd, rc);

        RETURN(0);

err_fsd:
        class_disconnect_exports(obd);
        RETURN(rc);
}

