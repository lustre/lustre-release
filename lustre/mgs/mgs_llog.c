/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mgs/mgs_llog.c
 *  Lustre Management Server (mgs) llog controller
 *
 *  Copyright (C) 2001-2005 Cluster File Systems, Inc.
 *   Author LinSongTao <lincent@clusterfs.com>
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
#define DEBUG_SUBSYSTEM S_MGS

#ifdef __KERNEL__
# include <linux/module.h>
# include <linux/pagemap.h>
#endif

#include <linux/obd_class.h>
#include <linux/lustre_mgs.h>
#include <linux/lustre_fsfilt.h>
#include "mgs_internal.h"

static struct mgs_update_llh* mgs_get_update_handle(struct obd_device *obd,
                                                    char *fsname, char *name)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgs_update_llh *mul, *l;
        struct list_head *update_llh_list = &mgs->mgs_update_llhs;

        list_for_each_entry_safe(mul, l, update_llh_list, mul_list) {
                if (!strcmp(mul->mul_name, name) &&
                    !strcmp(mul->mul_fsname, fsname))
                        return mul;
        }
        return NULL;
}

static int mgs_new_update_handle(struct obd_device *obd,
                                 struct mgs_update_llh *mul,
                                 char  *fsname, char *name)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct list_head *update_llh_list = &mgs->mgs_update_llhs;
        int rc = 0;

        if(mgs_get_update_handle(obd, fsname, name))
                GOTO(out, rc = -EBUSY);

        OBD_ALLOC(mul, sizeof(*mul));
        if (!mul) {
                CERROR("Can not allocate memory for update_llh.\n");
                GOTO(out, rc = -ENOMEM);
        }
        strncpy(mul->mul_name, name, sizeof mul->mul_name);
        strncpy(mul->mul_fsname, fsname, sizeof mul->mul_fsname);

        spin_lock(&mgs->mgs_llh_lock);
        /*seach again, in case of race.*/
        if (mgs_get_update_handle(obd, fsname, name))
                 spin_unlock(&mgs->mgs_llh_lock);
                 GOTO(out_free, rc = -EBUSY);
        }
        list_add(&mul->mul_list, &mgs->mgs_update_llhs);
        spin_unlock(&mgs->mgs_llh_lock);

out:
        return rc;

out_free:
        OBD_FREE(mul, sizeof(*mul));
        goto out;
}

static void mgs_free_update_handle(struct obd_device *obd,
                                   struct mgs_update_llh *mul)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        
        spin_lock(&mgs->mgs_llh_lock);
        list_del(&mul->mul_list);
        spin_unlock(&mgs->mgs_llh_lock);
      
        return;
}

static int mgs_start_record(struct obd_device *obd, 
                            struct obd_ioctl_data *data)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        struct mgs_update_llh *mul;
        struct llog_handle **llh_res;
        char *name = data->ioc_inlbuf1;
        char *fsname = data->ioc_inlbuf2;
        int rc = 0;

        rc = mgs_new_update_handle(obd, mul, fsname, name);
        if (rc)
                RETURN(rc);

        llh_res = &mul->mul_llh;
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         llh_res, NULL, fsname, name);
        if (rc == 0)
                llog_init_handle(mul->mul_llh, LLOG_F_IS_PLAIN, &cfg_uuid);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_end_record(struct obd_device *obd, 
                          struct obd_ioctl_data *data)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        struct mgs_update_llh *mul;
        char *name = data->ioc_inlbuf1;
        char *fsname = data->ioc_inlbuf2;
        int rc = 0;

        mul = mgs_get_update_handle(obd, fsname, name);
        if (!mul) {
                CERROR("Can not get update handle for %s:%s \n",
                       fsname, name);
                return -EINVAL;
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_close(mul->mul_llh);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_clear_record(struct obd_device *obd, 
                            struct obd_ioctl_data *data)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        struct mgs_update_llh *mul;
        struct llog_handel **llh_res;
        char *name = data->ioc_inlbuf1;
        char *fsname = data->ioc_inlbuf2;
        int rc = 0;

        rc = mgs_new_update_handle(obd, mul, fsname, name);
        if (rc)
                RETURN(rc);

        llh_res = &mul->mul_llh;
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         llh_res, NULL, name);
        if (rc == 0) {
                llog_init_handle(mul->mul_llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_destroy(mul->mul_llh);
                llog_free_handle(mul->mul_llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        mgs_free_update_handle(obd, mul);

        RETURN(rc);
}

static int mgs_do_record(struct obd_device *obd,
                         struct obd_ioctl_data *data,
                         int from_user)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgs_update_llh *mul;
        char *name = data->ioc_inlbuf1;
        char *fsname = data->ioc_inlbuf2;
        char *cfg_buf;
        struct llog_rec_hdr rec;
        int rc = 0;
        
        mul = mgs_get_update_handle(obd, fsname, name);
        if (!mul) {
                CERROR("Can not get update handle for %s:%s \n",
                       fsname, name);
                return -EINVAL;
        }

        rec.lrh_len = llog_data_len(data->ioc_plen1);

        if (data->ioc_type == LUSTRE_CFG_TYPE) {
                rec.lrh_type = OBD_CFG_REC;
        } else {
                CERROR("unknown cfg record type:%d \n", data->ioc_type);
                RETURN(-EINVAL);
        }

        if (from_user) {
                OBD_ALLOC(cfg_buf, data->ioc_plen1);
                if (cfg_buf == NULL)
                        RETURN(-ENOMEM);
                rc = copy_from_user(cfg_buf, data->ioc_pbuf1, data->ioc_plen1);
                if (rc) {
                        OBD_FREE(cfg_buf, data->ioc_plen1);
                        RETURN(rc);
                }
        } else
                cfg_buf = data->ioc_bulk;
 
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_write_rec(mul->mul_llh, &rec, NULL, 0, cfg_buf, -1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        OBD_FREE(cfg_buf, data->ioc_plen1);
        RETURN(rc);
}

int mgs_update_llog(struct obd_device *obd,
                    struct obd_ioctl_data *data)
{       
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgs_update_llh *mul;
        char *name = data->ioc_inlbuf1;
        char *fsname = data->ioc_inlbuf2;
        int rc;

        /*First phase: writing mds log  */
        logname  = name;
        data->ioc_inlbuf1 = logname;
        data->ioc_inllen1 = strlen(data->ioc_inlbuf1) + 1;
        data->ioc_inlbuf2 = fsname;
        data->ioc_inllen2 = strlen(data->ioc_inlbuf2) + 1;
        
        rc = mgs_clear_record(obd, data);
        if (rc) {
                CERROR("failed to clear log %s: %d\n", logname, rc);
                RETURN(rc);
        }

        rc = mgs_start_record(obd, data);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                RETURN(rc);
        }
        sprintf(lovuuid, "lov_%s_%s", fsname, name);
        
}

int mgs_iocontrol(unsigned int cmd, struct obd_export *exp, int len,
                  void *karg, void *uarg)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct obd_device *obd = exp->exp_obd;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct obd_ioctl_data *data = karg;
        struct lvfs_run_ctxt saved;
        int rc = 0;

        ENTRY;
        CDEBUG(D_IOCTL, "handling ioctl cmd %#x\n", cmd);

        switch (cmd) {
        case OBD_IOC_RECORD: {
                rc = mgs_start_record(obd, data);
                RETURN(rc);
        }

        case OBD_IOC_ENDRECORD: {
                rc = mgs_end_record(obd, data);
                RETURN(rc);
        }

        case OBD_IOC_CLEAR_LOG: {
                rc = mgs_clear_record(obd, data);
                RETURN(rc);
        }

        case OBD_IOC_DORECORD: {
                rc = mgs_do_record(obd, data, 1);
                RETURN(rc);
        }

        case OBD_IOC_UPDATE_LOG: {
                rc = mgs_update_llog(obd, data);
                RETURN(rc);
        }
        case OBD_IOC_PARSE: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_parse_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }

        case OBD_IOC_DUMP_LOG: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = class_config_dump_llog(ctxt, data->ioc_inlbuf1, NULL);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                if (rc)
                        RETURN(rc);

                RETURN(rc);
        }

        case OBD_IOC_SYNC: {
                CDEBUG(D_HA, "syncing mgs %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.mgs.mgs_sb);
                RETURN(rc);
        }

        case OBD_IOC_SET_READONLY: {
                void *handle;
                struct inode *inode = obd->u.mgs.mgs_sb->s_root->d_inode;
                BDEVNAME_DECLARE_STORAGE(tmp);
                CERROR("*** setting device %s read-only ***\n",
                       ll_bdevname(obd->u.mgs.mgs_sb, tmp));

                handle = fsfilt_start(obd, inode, FSFILT_OP_MKNOD, NULL);
                if (!IS_ERR(handle))
                        rc = fsfilt_commit(obd, inode, handle, 1);

                CDEBUG(D_HA, "syncing mgs %s\n", obd->obd_name);
                rc = fsfilt_sync(obd, obd->u.mgs.mgs_sb);

                lvfs_set_rdonly(lvfs_sbdev(obd->u.mgs.mgs_sb));
                RETURN(0);
        }


        case OBD_IOC_LLOG_CHECK:
        case OBD_IOC_LLOG_CANCEL:
        case OBD_IOC_LLOG_REMOVE: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);

                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
        }
        case OBD_IOC_LLOG_INFO:
        case OBD_IOC_LLOG_PRINT: {
                struct llog_ctxt *ctxt =
                        llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);

                push_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);
                rc = llog_ioctl(ctxt, cmd, data);
                pop_ctxt(&saved, &ctxt->loc_exp->exp_obd->obd_lvfs_ctxt, NULL);

                RETURN(rc);
        }

        case OBD_IOC_ABORT_RECOVERY:
                CERROR("aborting recovery for device %s\n", obd->obd_name);
                target_abort_recovery(obd);
                RETURN(0);

        default:
                CDEBUG(D_INFO, "unknown command %x\n", cmd);
                RETURN(-EINVAL);
        }
        RETURN(0);
}
