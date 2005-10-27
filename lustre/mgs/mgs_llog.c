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
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#endif

#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <linux/obd_ost.h>
#include <libcfs/list.h>
#include <linux/lvfs.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_disk.h>
#include <linux/lustre_mgs.h>
#include "mgs_internal.h"

static struct lustre_cfg_bufs llog_bufs;

static int mgs_do_record(struct obd_device *obd, struct llog_handle *llh,
                         void *cfg_buf);

static int record_attach(struct obd_device *obd, struct llog_handle *llh,
                         char* name, char *type, char *uuid)
{
        struct lustre_cfg *lcfg;
        int rc;

        lustre_cfg_bufs_reset(&llog_bufs, NULL);

        lustre_cfg_bufs_set_string(&llog_bufs, 0, name);
        lustre_cfg_bufs_set_string(&llog_bufs, 1, type);
        if (uuid)
               lustre_cfg_bufs_set_string(&llog_bufs, 2, uuid);

        lcfg = lustre_cfg_new(LCFG_ATTACH, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static int record_add_uuid(struct obd_device *obd, struct llog_handle *llh,
                           uint64_t nid, char *uuid)
{
        struct lustre_cfg *lcfg;
        int rc;

        lustre_cfg_bufs_reset(&llog_bufs, NULL);
        if (uuid)
                lustre_cfg_bufs_set_string(&llog_bufs, 1, uuid);

        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &llog_bufs);
        lcfg->lcfg_nid = nid;

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static int record_lov_setup(struct obd_device *obd, struct llog_handle *llh,
                            char *device_name, struct lov_desc *desc)
{
       struct lustre_cfg *lcfg;
        int rc;

        lustre_cfg_bufs_reset(&llog_bufs, device_name);

        lustre_cfg_bufs_set(&llog_bufs, 1, desc, sizeof(*desc));

        lcfg = lustre_cfg_new(LCFG_SETUP, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static int record_setup(struct obd_device *obd, struct llog_handle *llh,
                        char *device_name, int args, char**argv)
{
        struct lustre_cfg *lcfg;
        int i, rc;

        lustre_cfg_bufs_reset(&llog_bufs, device_name);

        for(i = 1; i < args ; i++)
                lustre_cfg_bufs_set_string(&llog_bufs, i, argv[i-1]);
        
        lcfg = lustre_cfg_new(LCFG_SETUP, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static int record_lov_modify_tgts(struct obd_device *obd, 
                                  struct llog_handle *llh,
                                  char *device_name, char *op, char *uuid,
                                  char *index, char *gen)
{
        struct lustre_cfg *lcfg;
        int cmd, rc; 

        lustre_cfg_bufs_reset(&llog_bufs, device_name);

        if (!strncmp(op, "add", 4)) {
                cmd = LCFG_LOV_ADD_OBD;
        } else if (!strncmp(op, "del", 4)) {
                cmd = LCFG_LOV_DEL_OBD;
        } 

        lustre_cfg_bufs_set_string(&llog_bufs, 1, uuid);
        lustre_cfg_bufs_set_string(&llog_bufs, 2, index);
        lustre_cfg_bufs_set_string(&llog_bufs, 3, gen);

        lcfg = lustre_cfg_new(cmd, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}                                  

static int record_mount_point(struct obd_device *obd, struct llog_handle *llh,
                              char *mds_name, char *lov_name, char *mdc_name)
{
        struct lustre_cfg *lcfg;
        int cmd, rc; 

        lustre_cfg_bufs_reset(&llog_bufs, NULL);

        lustre_cfg_bufs_set_string(&llog_bufs, 1, mds_name);
        lustre_cfg_bufs_set_string(&llog_bufs, 2, lov_name);
        if (mdc_name)
                lustre_cfg_bufs_set_string(&llog_bufs, 2, mdc_name);

        lcfg = lustre_cfg_new(cmd, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}                                  

struct mgs_open_llog* find_mgs_open_llog(struct obd_device *obd, char *name)
{
        struct mgs_obd *mgs= &obd->u.mgs;
        struct list_head *tmp;
        struct mgs_open_llog *mol;
        char fsname[40];
        char *p;

        p = strrchr(name, '/');
        if (p != NULL)
                strncpy(fsname, name, p - name);
        else
                return NULL;

        list_for_each(tmp, &mgs->mgs_open_llogs) {
                mol = list_entry(tmp, struct mgs_open_llog, mol_list);
                if (!strcmp(mol->mol_fsname, fsname))
                        return mol;
        }
        return NULL;
}

static int mgs_start_record(struct obd_device *obd, 
                            struct llog_handle *llh, char *name)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct lvfs_run_ctxt saved;
        struct llog_handle **llh_res;
        int rc = 0;
        
        if (llh)
                RETURN(-EBUSY);

        llh_res = &llh;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         llh_res, NULL, name);
        if (rc == 0)
                llog_init_handle(llh, LLOG_F_IS_PLAIN, &cfg_uuid);

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_end_record(struct obd_device *obd,
                          struct llog_handle *llh, char* name)
{
        struct lvfs_run_ctxt saved;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_close(llh);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_clear_record(struct obd_device *obd, 
                            struct llog_handle *llh, char *name)
{
        struct lvfs_run_ctxt saved;
        struct llog_handle **llh_res;
        int rc = 0;

        if (llh)
                RETURN(-EBUSY);
        llh_res = &llh;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         llh_res, NULL, name);
        if (rc == 0) {
                llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_destroy(llh);
                llog_free_handle(llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_do_record(struct obd_device *obd, struct llog_handle *llh,
                         void *cfg_buf)
{
        
        struct lvfs_run_ctxt saved;
        struct llog_rec_hdr rec;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_write_rec(llh, &rec, NULL, 0, cfg_buf, -1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_write_mds_llog(struct obd_device *obd, char* name)
{
        struct mgs_open_llog *mol;
        struct llog_handle *llh;
        struct system_db *db;
        struct list_head *tmp;
        int i, rc = 0;

        mol = find_mgs_open_llog(obd, name);
        if (!mol)
                RETURN(-EINVAL);

        db = mol->mol_system_db;
        if(!db)
                RETURN(-EINVAL);

        llh = mol->mol_cfg_llh;

        rc = mgs_clear_record(obd, llh, name);
        if (rc) {
                CERROR("failed to clear log %s: %d\n", name, rc);
                RETURN(rc);
        }

        rc = mgs_start_record(obd, llh, name);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
                RETURN(rc);
        }

        rc = record_attach(obd, llh, db->mds_name, "lov", db->mds_uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n", name, rc);
                RETURN(rc);
        }

        rc = record_lov_setup(obd, llh, db->mds_name, &db->lovdesc);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", name, rc);
                RETURN(rc);
        }

        rc = record_add_uuid(obd, llh, db->mds_nid, db->mds_uuid);
        if (rc) {
                CERROR("failed to record log(add uuid) %s: %d\n", name, rc);
                RETURN(rc);
        }

        i = 0;
        list_for_each(tmp, &db->ost_infos) {
                char   ostuuid[64];
                char   nodeuuid[64];
                char   devname[64];
                char   index[16];
                char   *setup_argv[2];
                struct ost_info *oinfo = list_entry(tmp, struct ost_info,
                                                    osi_list);

                sprintf(ostuuid,  "%s_UUID", oinfo->osi_ostname);
                sprintf(nodeuuid, "%s_UUID", oinfo->osi_nodename);

                rc = record_add_uuid(obd, llh, oinfo->osi_nid, nodeuuid);
                if (rc) {
                        CERROR("failed to record log(add_uuid) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                rc = record_attach(obd, llh, oinfo->osi_ostname, 
                                   "osc", db->mds_uuid);
                if (rc) {
                        CERROR("failed to record log(attach_uuid) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(devname,"OSC_%s_%s_%s",
                        db->mds_nodename, oinfo->osi_ostname, db->mds_name);

                setup_argv[0] = ostuuid;
                setup_argv[1] = nodeuuid;
                rc = record_setup(obd, llh, devname, 2, setup_argv);
                if (rc) {
                        CERROR("failed to record log(setup) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(index, "%d", oinfo->osi_stripe_index);
                rc = record_lov_modify_tgts(obd, llh, db->mds_name, "add", ostuuid,
                                            index, "1");
                if (rc) {
                        CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }
        }
        
        rc = record_mount_point(obd, llh, db->mds_name, db->lov_name, NULL);
        if (rc) {
                CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                       name, rc);
                RETURN(rc);
        }

        RETURN(rc);
}

int mgs_update_llog(struct obd_device *obd, char *name)
{       
        char logname[64];
        int rc = 0;

        /* Two phases: 1. writing mds log. 
                       2. writing client log
         */

        /*First phase: writing mds log  */
        sprintf(logname, "%s/mds1", name);
        rc = mgs_write_mds_llog(obd, logname);
        if (rc) {
                CERROR("failed to write log %s: %d\n", logname, rc);
                RETURN(rc);
        }

        /*Second phase: writing client log  */
        sprintf(logname, "%s/client", name);
        rc = mgs_write_client_llog(obd, logname);
        if (rc) {
                CERROR("failed to write log %s: %d\n", logname, rc);
                RETURN(rc);
        }

        return rc;
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
                char *name = data->ioc_inlbuf1;
                if (mgs->mgs_cfg_llh)
                        RETURN(-EBUSY);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                                 &mgs->mgs_cfg_llh, NULL,  name);
                if (rc == 0)
                        llog_init_handle(mgs->mgs_cfg_llh, LLOG_F_IS_PLAIN,
                                         &cfg_uuid);
                else
                        mgs->mgs_cfg_llh = NULL;
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                RETURN(rc);
        }

        case OBD_IOC_ENDRECORD: {
               if (!mgs->mgs_cfg_llh)
                        RETURN(-EBADF);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_close(mgs->mgs_cfg_llh);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                mgs->mgs_cfg_llh = NULL;
                RETURN(rc);
        }

        case OBD_IOC_CLEAR_LOG: {
                char *name = data->ioc_inlbuf1;
                if (mgs->mgs_cfg_llh)
                        RETURN(-EBUSY);

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                                 &mgs->mgs_cfg_llh, NULL, name);
                if (rc == 0) {
                        llog_init_handle(mgs->mgs_cfg_llh, LLOG_F_IS_PLAIN,
                                         NULL);

                        rc = llog_destroy(mgs->mgs_cfg_llh);
                        llog_free_handle(mgs->mgs_cfg_llh);
                }
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                mgs->mgs_cfg_llh = NULL;
                RETURN(rc);
        }

        case OBD_IOC_DORECORD: {
                char *cfg_buf;
                struct llog_rec_hdr rec;
                if (!mgs->mgs_cfg_llh)
                        RETURN(-EBADF);

                rec.lrh_len = llog_data_len(data->ioc_plen1);

                if (data->ioc_type == LUSTRE_CFG_TYPE) {
                        rec.lrh_type = OBD_CFG_REC;
                } else {
                        CERROR("unknown cfg record type:%d \n", data->ioc_type);
                        RETURN(-EINVAL);
                }

                OBD_ALLOC(cfg_buf, data->ioc_plen1);
                if (cfg_buf == NULL)
                        RETURN(-EINVAL);
                rc = copy_from_user(cfg_buf, data->ioc_pbuf1, data->ioc_plen1);
                if (rc) {
                        OBD_FREE(cfg_buf, data->ioc_plen1);
                        RETURN(rc);
                }

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                rc = llog_write_rec(mgs->mgs_cfg_llh, &rec, NULL, 0,
                                    cfg_buf, -1);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

                OBD_FREE(cfg_buf, data->ioc_plen1);
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


#ifdef __KERNEL__

static int mgs_llog_lvfs_pad(struct obd_device *obd, struct l_file *file,
                                int len, int index)
{
        struct llog_rec_hdr rec = { 0 };
        struct llog_rec_tail tail;
        int rc;
        ENTRY;

        LASSERT(len >= LLOG_MIN_REC_SIZE && (len & 0x7) == 0);

        tail.lrt_len = rec.lrh_len = len;
        tail.lrt_index = rec.lrh_index = index;
        rec.lrh_type = LLOG_PAD_MAGIC;

        rc = fsfilt_write_record(obd, file, &rec, sizeof(rec), &file->f_pos, 0);
        if (rc) {
                CERROR("error writing padding record: rc %d\n", rc);
                goto out;
        }

        file->f_pos += len - sizeof(rec) - sizeof(tail);
        rc = fsfilt_write_record(obd, file, &tail, sizeof(tail),&file->f_pos,0);
        if (rc) {
                CERROR("error writing padding record: rc %d\n", rc);
                goto out;
        }

 out:
        RETURN(rc);
}

static int mgs_llog_lvfs_write_blob(struct obd_device *obd, struct l_file *file,
                                struct llog_rec_hdr *rec, void *buf, loff_t off)
{
        int rc;
        struct llog_rec_tail end;
        loff_t saved_off = file->f_pos;
        int buflen = rec->lrh_len;

        ENTRY;
        file->f_pos = off;

        if (!buf) {
                rc = fsfilt_write_record(obd, file, rec, buflen,&file->f_pos,0);
                if (rc) {
                        CERROR("error writing log record: rc %d\n", rc);
                        goto out;
                }
                GOTO(out, rc = 0);
        }

        /* the buf case */
        rec->lrh_len = sizeof(*rec) + buflen + sizeof(end);
        rc = fsfilt_write_record(obd, file, rec, sizeof(*rec), &file->f_pos, 0);
        if (rc) {
                CERROR("error writing log hdr: rc %d\n", rc);
                goto out;
        }

        rc = fsfilt_write_record(obd, file, buf, buflen, &file->f_pos, 0);
        if (rc) {
                CERROR("error writing log buffer: rc %d\n", rc);
                goto out;
        }

        end.lrt_len = rec->lrh_len;
        end.lrt_index = rec->lrh_index;
        rc = fsfilt_write_record(obd, file, &end, sizeof(end), &file->f_pos, 0);
        if (rc) {
                CERROR("error writing log tail: rc %d\n", rc);
                goto out;
        }

        rc = 0;
 out:
        if (saved_off > file->f_pos)
                file->f_pos = saved_off;
        LASSERT(rc <= 0);
        RETURN(rc);
}

static int mgs_llog_lvfs_read_blob(struct obd_device *obd, struct l_file *file,
                                void *buf, int size, loff_t off)
{
        loff_t offset = off;
        int rc;
        ENTRY;

        rc = fsfilt_read_record(obd, file, buf, size, &offset);
        if (rc) {
                CERROR("error reading log record: rc %d\n", rc);
                RETURN(rc);
        }
        RETURN(0);
}

static int mgs_llog_lvfs_read_header(struct llog_handle *handle)
{
        struct obd_device *obd;
        int rc;
        ENTRY;

        LASSERT(sizeof(*handle->lgh_hdr) == LLOG_CHUNK_SIZE);

        obd = handle->lgh_ctxt->loc_exp->exp_obd;

        if (handle->lgh_file->f_dentry->d_inode->i_size == 0) {
                CDEBUG(D_HA, "not reading header from 0-byte log\n");
                RETURN(LLOG_EEMPTY);
        }

        rc = mgs_llog_lvfs_read_blob(obd, handle->lgh_file, handle->lgh_hdr,
                                 LLOG_CHUNK_SIZE, 0);
        if (rc) {
                CERROR("error reading log header from %.*s\n",
                       handle->lgh_file->f_dentry->d_name.len,
                       handle->lgh_file->f_dentry->d_name.name);
        } else {
                struct llog_rec_hdr *llh_hdr = &handle->lgh_hdr->llh_hdr;

                if (LLOG_REC_HDR_NEEDS_SWABBING(llh_hdr))
                        lustre_swab_llog_hdr(handle->lgh_hdr);

                if (llh_hdr->lrh_type != LLOG_HDR_MAGIC) {
                        CERROR("bad log %.*s header magic: %#x (expected %#x)\n",
                               handle->lgh_file->f_dentry->d_name.len,
                               handle->lgh_file->f_dentry->d_name.name,
                               llh_hdr->lrh_type, LLOG_HDR_MAGIC);
                        rc = -EIO;
                } else if (llh_hdr->lrh_len != LLOG_CHUNK_SIZE) {
                        CERROR("incorrectly sized log %.*s header: %#x "
                               "(expected %#x)\n",
                               handle->lgh_file->f_dentry->d_name.len,
                               handle->lgh_file->f_dentry->d_name.name,
                               llh_hdr->lrh_len, LLOG_CHUNK_SIZE);
                        CERROR("you may need to re-run lconf --write_conf.\n");
                        rc = -EIO;
                }
        }

        handle->lgh_last_idx = handle->lgh_hdr->llh_tail.lrt_index;
        handle->lgh_file->f_pos = handle->lgh_file->f_dentry->d_inode->i_size;

        RETURN(rc);
}

/* returns negative in on error; 0 if success && reccookie == 0; 1 otherwise */
/* appends if idx == -1, otherwise overwrites record idx. */
static int mgs_llog_lvfs_write_rec(struct llog_handle *loghandle,
                                   struct llog_rec_hdr *rec,
                                   struct llog_cookie *reccookie, int cookiecount,
                                   void *buf, int idx)
{
        struct llog_log_hdr *llh;
        int reclen = rec->lrh_len, index, rc;
        struct llog_rec_tail *lrt;
        struct obd_device *obd;
        struct file *file;
        size_t left;
        ENTRY;

        llh = loghandle->lgh_hdr;
        file = loghandle->lgh_file;
        obd = loghandle->lgh_ctxt->loc_exp->exp_obd;

        /* record length should not bigger than LLOG_CHUNK_SIZE */
        if (buf)
                rc = (reclen > LLOG_CHUNK_SIZE - sizeof(struct llog_rec_hdr) -
                      sizeof(struct llog_rec_tail)) ? -E2BIG : 0;
        else
                rc = (reclen > LLOG_CHUNK_SIZE) ? -E2BIG : 0;
        if (rc)
                RETURN(rc);

        if (idx != -1) {
                loff_t saved_offset;

                /* no header: only allowed to insert record 1 */
                if (idx != 1 && !file->f_dentry->d_inode->i_size) {
                        CERROR("idx != -1 in empty log\n");
                        LBUG();
                }

                if (idx && llh->llh_size && llh->llh_size != reclen)
                        RETURN(-EINVAL);

                rc = mgs_llog_lvfs_write_blob(obd, file, &llh->llh_hdr, NULL, 0);
                /* we are done if we only write the header or on error */
                if (rc || idx == 0)
                        RETURN(rc);

                saved_offset = sizeof(*llh) + (idx-1)*rec->lrh_len;
                rc = mgs_llog_lvfs_write_blob(obd, file, rec, buf, saved_offset);
                if (rc == 0 && reccookie) {
                        reccookie->lgc_lgl = loghandle->lgh_id;
                        reccookie->lgc_index = idx;
                        rc = 1;
                }
                RETURN(rc);
        }

        /* Make sure that records don't cross a chunk boundary, so we can
         * process them page-at-a-time if needed.  If it will cross a chunk
         * boundary, write in a fake (but referenced) entry to pad the chunk.
         *
         * We know that llog_current_log() will return a loghandle that is
         * big enough to hold reclen, so all we care about is padding here.
         */
        left = LLOG_CHUNK_SIZE - (file->f_pos & (LLOG_CHUNK_SIZE - 1));
        if (buf)
                reclen = sizeof(*rec) + rec->lrh_len + 
                        sizeof(struct llog_rec_tail);

        /* NOTE: padding is a record, but no bit is set */
        if (left != 0 && left != reclen &&
            left < (reclen + LLOG_MIN_REC_SIZE)) {
                loghandle->lgh_last_idx++;
                rc = mgs_llog_lvfs_pad(obd, file, left, loghandle->lgh_last_idx);
                if (rc)
                        RETURN(rc);
                /* if it's the last idx in log file, then return -ENOSPC */
                if (loghandle->lgh_last_idx == LLOG_BITMAP_SIZE(llh) - 1)
                        RETURN(-ENOSPC);
        }

        loghandle->lgh_last_idx++;
        index = loghandle->lgh_last_idx;
        LASSERT(index < LLOG_BITMAP_SIZE(llh));
        rec->lrh_index = index;
        if (buf == NULL) {
                lrt = (struct llog_rec_tail *)
                        ((char *)rec + rec->lrh_len - sizeof(*lrt));
                lrt->lrt_len = rec->lrh_len;
                lrt->lrt_index = rec->lrh_index;
        }
        if (ext2_set_bit(index, llh->llh_bitmap)) {
                CERROR("argh, index %u already set in log bitmap?\n", index);
                LBUG(); /* should never happen */
        }
        llh->llh_count++;
        llh->llh_tail.lrt_index = index;

        rc = mgs_llog_lvfs_write_blob(obd, file, &llh->llh_hdr, NULL, 0);
        if (rc)
                RETURN(rc);

        rc = mgs_llog_lvfs_write_blob(obd, file, rec, buf, file->f_pos);
        if (rc)
                RETURN(rc);

        CDEBUG(D_HA, "added record "LPX64": idx: %u, %u bytes\n",
               loghandle->lgh_id.lgl_oid, index, rec->lrh_len);
        if (rc == 0 && reccookie) {
                reccookie->lgc_lgl = loghandle->lgh_id;
                reccookie->lgc_index = index;
                if ((rec->lrh_type == MDS_UNLINK_REC) || 
                                (rec->lrh_type == MDS_SETATTR_REC))
                        reccookie->lgc_subsys = LLOG_MDS_OST_ORIG_CTXT;
                else if (rec->lrh_type == OST_SZ_REC)
                        reccookie->lgc_subsys = LLOG_SIZE_ORIG_CTXT;
                else if (rec->lrh_type == OST_RAID1_REC)
                        reccookie->lgc_subsys = LLOG_RD1_ORIG_CTXT;
                else
                        reccookie->lgc_subsys = -1;
                rc = 1;
        }
        if (rc == 0 && rec->lrh_type == LLOG_GEN_REC)
                rc = 1;

        RETURN(rc);
}

/* We can skip reading at least as many log blocks as the number of
* minimum sized log records we are skipping.  If it turns out
* that we are not far enough along the log (because the
* actual records are larger than minimum size) we just skip
* some more records. */

static void llog_skip_over(__u64 *off, int curr, int goal)
{
        if (goal <= curr)
                return;
        *off = (*off + (goal-curr-1) * LLOG_MIN_REC_SIZE) &
                ~(LLOG_CHUNK_SIZE - 1);
}


/* sets:
 *  - cur_offset to the furthest point read in the log file
 *  - cur_idx to the log index preceeding cur_offset
 * returns -EIO/-EINVAL on error
 */
static int mgs_llog_lvfs_next_block(struct llog_handle *loghandle, int *cur_idx,
                                int next_idx, __u64 *cur_offset, void *buf,
                                int len)
{
        int rc;
        ENTRY;

        if (len == 0 || len & (LLOG_CHUNK_SIZE - 1))
                RETURN(-EINVAL);

        CDEBUG(D_OTHER, "looking for log index %u (cur idx %u off "LPU64")\n",
               next_idx, *cur_idx, *cur_offset);

        while (*cur_offset < loghandle->lgh_file->f_dentry->d_inode->i_size) {
                struct llog_rec_hdr *rec;
                struct llog_rec_tail *tail;
                loff_t ppos;

                llog_skip_over(cur_offset, *cur_idx, next_idx);

                ppos = *cur_offset;
                rc = fsfilt_read_record(loghandle->lgh_ctxt->loc_exp->exp_obd,
                                        loghandle->lgh_file, buf, len,
                                        &ppos);

                if (rc) {
                        CERROR("Cant read llog block at log id "LPU64
                               "/%u offset "LPU64"\n",
                               loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen,
                               *cur_offset);
                        RETURN(rc);
                }

                /* put number of bytes read into rc to make code simpler */
                rc = ppos - *cur_offset;
                *cur_offset = ppos;

                if (rc == 0) /* end of file, nothing to do */
                        RETURN(0);

                if (rc < sizeof(*tail)) {
                        CERROR("Invalid llog block at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, *cur_offset);
                        RETURN(-EINVAL);
                }

                rec = buf;
                tail = (struct llog_rec_tail *)((char *)buf + rc -
                                                sizeof(struct llog_rec_tail));

                if (LLOG_REC_HDR_NEEDS_SWABBING(rec)) {
                        lustre_swab_llog_rec(rec, tail);
                }

                *cur_idx = tail->lrt_index;

                /* this shouldn't happen */
                if (tail->lrt_index == 0) {
                        CERROR("Invalid llog tail at log id "LPU64"/%u offset "
                               LPU64"\n", loghandle->lgh_id.lgl_oid,
                               loghandle->lgh_id.lgl_ogen, *cur_offset);
                        RETURN(-EINVAL);
                }
                if (tail->lrt_index < next_idx)
                        continue;

                /* sanity check that the start of the new buffer is no farther
                 * than the record that we wanted.  This shouldn't happen. */
                if (rec->lrh_index > next_idx) {
                        CERROR("missed desired record? %u > %u\n",
                               rec->lrh_index, next_idx);
                        RETURN(-ENOENT);
                }
                RETURN(0);
        }
        RETURN(-EIO);
}

static struct file *llog_filp_open(char *name, int flags, int mode)
{
        char *logname;
        struct file *filp;
        int len;

        OBD_ALLOC(logname, PATH_MAX);
        if (logname == NULL)
                return ERR_PTR(-ENOMEM); 

        len = snprintf(logname, PATH_MAX, "%s/%s", 
                       MOUNT_CONFIGS_DIR, name);

        if (len >= PATH_MAX - 1) {
                filp = ERR_PTR(-ENAMETOOLONG);
        } else {
                CERROR("logname = %s\n", logname);
                filp = l_filp_open(logname, flags, mode);
                if (IS_ERR(filp))
                        CERROR("logfile creation %s: %ld\n", logname,
                               PTR_ERR(filp));
        }

        OBD_FREE(logname, PATH_MAX);
        return filp;
}

/* This is a callback from the llog_* functions.
 * Assumes caller has already pushed us into the kernel context. */
static int mgs_llog_lvfs_create(struct llog_ctxt *ctxt, struct llog_handle **res,
                            struct llog_logid *logid, char *name)
{
        struct llog_handle *handle;
        struct obd_device *obd;
        struct l_dentry *dchild = NULL;
        struct obdo *oa = NULL;
        int rc = 0, cleanup_phase = 1;
        int open_flags = O_RDWR | O_CREAT | O_LARGEFILE;
        ENTRY;

        handle = llog_alloc_handle();
        if (handle == NULL)
                RETURN(-ENOMEM);
        *res = handle;

        LASSERT(ctxt);
        LASSERT(ctxt->loc_exp);
        obd = ctxt->loc_exp->exp_obd;

        if (logid != NULL) {
                dchild = obd_lvfs_fid2dentry(ctxt->loc_exp, logid->lgl_oid,
                                             logid->lgl_ogen, logid->lgl_ogr);

                if (IS_ERR(dchild)) {
                        rc = PTR_ERR(dchild);
                        CERROR("error looking up logfile "LPX64":0x%x: rc %d\n",
                               logid->lgl_oid, logid->lgl_ogen, rc);
                        GOTO(cleanup, rc);
                }

                cleanup_phase = 2;
                if (dchild->d_inode == NULL) {
                        rc = -ENOENT;
                        CERROR("nonexistent log file "LPX64":"LPX64": rc %d\n",
                               logid->lgl_oid, logid->lgl_ogr, rc);
                        GOTO(cleanup, rc);
                }

                handle->lgh_file = l_dentry_open(&obd->obd_lvfs_ctxt, dchild,
                                                    O_RDWR | O_LARGEFILE);
                if (IS_ERR(handle->lgh_file)) {
                        rc = PTR_ERR(handle->lgh_file);
                        CERROR("error opening logfile "LPX64"0x%x: rc %d\n",
                               logid->lgl_oid, logid->lgl_ogen, rc);
                        GOTO(cleanup, rc);
                }

                /* assign the value of lgh_id for handle directly */
                handle->lgh_id = *logid;

        } else if (name) {
                handle->lgh_file = llog_filp_open(name, open_flags, 0644);

                if (IS_ERR(handle->lgh_file))
                        GOTO(cleanup, rc = PTR_ERR(handle->lgh_file));

                handle->lgh_id.lgl_ogr = 1;
                handle->lgh_id.lgl_oid =
                        handle->lgh_file->f_dentry->d_inode->i_ino;
                handle->lgh_id.lgl_ogen =
                        handle->lgh_file->f_dentry->d_inode->i_generation;
                
        } else {
                oa = obdo_alloc();
                if (oa == NULL)
                        GOTO(cleanup, rc = -ENOMEM);
                /* XXX get some filter group constants */
                oa->o_gr = 1;
                oa->o_valid = OBD_MD_FLGENER | OBD_MD_FLGROUP;
                rc = obd_create(ctxt->loc_exp, oa, NULL, NULL);
                if (rc)
                        GOTO(cleanup, rc);

                dchild = obd_lvfs_fid2dentry(ctxt->loc_exp, oa->o_id,
                                             oa->o_generation, oa->o_gr);

                if (IS_ERR(dchild))
                        GOTO(cleanup, rc = PTR_ERR(dchild));
                cleanup_phase = 2;
                handle->lgh_file = l_dentry_open(&obd->obd_lvfs_ctxt, dchild,
                                                 open_flags);
                if (IS_ERR(handle->lgh_file))
                        GOTO(cleanup, rc = PTR_ERR(handle->lgh_file));

                handle->lgh_id.lgl_ogr = oa->o_gr;
                handle->lgh_id.lgl_oid = oa->o_id;
                handle->lgh_id.lgl_ogen = oa->o_generation;
        }

        handle->lgh_ctxt = ctxt;
 finish:
        if (oa)
                obdo_free(oa);
        RETURN(rc);
cleanup:
        switch (cleanup_phase) {
        case 2:
                l_dput(dchild);
        case 1:
                llog_free_handle(handle);
        }
        goto finish;
}

static int mgs_llog_lvfs_close(struct llog_handle *handle)
{
        int rc;
        ENTRY;

        rc = filp_close(handle->lgh_file, 0);
        if (rc)
                CERROR("error closing log: rc %d\n", rc);
        RETURN(rc);
}

static int mgs_llog_lvfs_destroy(struct llog_handle *handle)
{
        struct dentry *fdentry;
        struct obdo *oa;
        int rc;
        ENTRY;

        fdentry = handle->lgh_file->f_dentry;
        if (strcmp(fdentry->d_parent->d_name.name, MOUNT_CONFIGS_DIR) == 0) {
                /* CONFIGS files aren't really "lustre" objects - special case*/
                struct obd_device *obd = handle->lgh_ctxt->loc_exp->exp_obd;
                struct inode *inode = fdentry->d_parent->d_inode;
                struct lvfs_run_ctxt saved;

                push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                dget(fdentry);
                rc = mgs_llog_lvfs_close(handle);

                if (rc == 0) {
                        down(&inode->i_sem);
                        rc = vfs_unlink(inode, fdentry);
                        up(&inode->i_sem);
                }

                dput(fdentry);
                pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                RETURN(rc);
        }

        oa = obdo_alloc();
        if (oa == NULL)
                RETURN(-ENOMEM);

        oa->o_id = handle->lgh_id.lgl_oid;
        oa->o_gr = handle->lgh_id.lgl_ogr;
        oa->o_generation = handle->lgh_id.lgl_ogen;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP | OBD_MD_FLGENER;

        rc = mgs_llog_lvfs_close(handle);
        if (rc)
                GOTO(out, rc);

        rc = obd_destroy(handle->lgh_ctxt->loc_exp, oa, NULL, NULL);
 out:
        obdo_free(oa);
        RETURN(rc);
}

/* reads the catalog list */
int llog_get_cat_list(struct obd_device *obd, struct obd_device *disk_obd,
                      char *name, int count, struct llog_catid *idarray)
{
        struct lvfs_run_ctxt saved;
        struct l_file *file;
        int rc;
        int size = sizeof(*idarray) * count;
        loff_t off = 0;

        if (!count) {
                CERROR("Empty catalog?\n");
                RETURN(0);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        file = filp_open(name, O_RDWR | O_CREAT | O_LARGEFILE, 0700);
        if (!file || IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s: rc = %d\n",
                       name, rc);
                GOTO(out, rc);
        }

        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", name,
                       file->f_dentry->d_inode->i_mode);
                GOTO(out, rc = -ENOENT);
        }

        rc = fsfilt_read_record(disk_obd, file, idarray, size, &off);
        if (rc) {
                CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                       name, rc);
                GOTO(out, rc);
        }

 out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (file && !IS_ERR(file))
                rc = filp_close(file, 0);
        RETURN(rc);
}
EXPORT_SYMBOL(llog_get_cat_list);

/* writes the cat list */
int llog_put_cat_list(struct obd_device *obd, struct obd_device *disk_obd,
                      char *name, int count, struct llog_catid *idarray)
{
        struct lvfs_run_ctxt saved;
        struct l_file *file;
        int rc;
        int size = sizeof(*idarray) * count;
        loff_t off = 0;

        if (!count) {
                CERROR("Empty catalog?\n");
                RETURN(0);
        }
        
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        file = filp_open(name, O_RDWR | O_CREAT | O_LARGEFILE, 0700);
        if (!file || IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create %s: rc = %d\n",
                       name, rc);
                GOTO(out, rc);
        }

        if (!S_ISREG(file->f_dentry->d_inode->i_mode)) {
                CERROR("%s is not a regular file!: mode = %o\n", name,
                       file->f_dentry->d_inode->i_mode);
                GOTO(out, rc = -ENOENT);
        }

        rc = fsfilt_write_record(disk_obd, file, idarray, size, &off, 1);
        if (rc) {
                CDEBUG(D_INODE,"OBD filter: error reading %s: rc %d\n",
                       name, rc);
                GOTO(out, rc);
        }

 out:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (file && !IS_ERR(file))
                rc = filp_close(file, 0);
        RETURN(rc);
}

struct llog_operations mgs_llog_lvfs_ops = {
        lop_write_rec:   mgs_llog_lvfs_write_rec,
        lop_next_block:  mgs_llog_lvfs_next_block,
        lop_read_header: mgs_llog_lvfs_read_header,
        lop_create:      mgs_llog_lvfs_create,
        lop_destroy:     mgs_llog_lvfs_destroy,
        lop_close:       mgs_llog_lvfs_close,
        //        lop_cancel: llog_lvfs_cancel,
};

EXPORT_SYMBOL(mgs_llog_lvfs_ops);

#else /* !__KERNEL__ */

static int mgs_llog_lvfs_read_header(struct llog_handle *handle)
{
        LBUG();
        return 0;
}

static int mgs_llog_lvfs_write_rec(struct llog_handle *loghandle,
                               struct llog_rec_hdr *rec,
                               struct llog_cookie *reccookie, int cookiecount,
                               void *buf, int idx)
{
        LBUG();
        return 0;
}

static int mgs_llog_lvfs_next_block(struct llog_handle *loghandle, int *cur_idx,
                                int next_idx, __u64 *cur_offset, void *buf,
                                int len)
{
        LBUG();
        return 0;
}

static int mgs_llog_lvfs_create(struct llog_ctxt *ctxt, struct llog_handle **res,
                            struct llog_logid *logid, char *fsname, char *name)
{
        LBUG();
        return 0;
}

static int mgs_llog_lvfs_close(struct llog_handle *handle)
{
        LBUG();
        return 0;
}

static int mgs_llog_lvfs_destroy(struct llog_handle *handle)
{
        LBUG();
        return 0;
}

int mgs_llog_get_cat_list(struct obd_device *obd, struct obd_device *disk_obd,
                      char *name, int count, struct llog_catid *idarray)
{
        LBUG();
        return 0;
}

int mgs_llog_put_cat_list(struct obd_device *obd, struct obd_device *disk_obd,
                      char *name, int count, struct llog_catid *idarray)
{
        LBUG();
        return 0;
}

struct llog_operations mgs_llog_lvfs_ops = {
        lop_write_rec:   mgs_llog_lvfs_write_rec,
        lop_next_block:  mgs_llog_lvfs_next_block,
        lop_read_header: mgs_llog_lvfs_read_header,
        lop_create:      mgs_llog_lvfs_create,
        lop_destroy:     mgs_llog_lvfs_destroy,
        lop_close:       mgs_llog_lvfs_close,
//        lop_cancel:      mgs_llog_lvfs_cancel,
};
#endif
