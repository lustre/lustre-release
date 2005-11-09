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
#define EXPORT_SYMTAB
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

        lustre_cfg_bufs_reset(&llog_bufs, name);

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
                                  char *lov_name, char *op, char *ost_uuid,
                                  char *index, char *gen)
{
        struct lustre_cfg *lcfg;
        int cmd, rc; 

        lustre_cfg_bufs_reset(&llog_bufs, lov_name);

        if (!strncmp(op, "add", 4)) {
                cmd = LCFG_LOV_ADD_OBD;
        } else if (!strncmp(op, "del", 4)) {
                cmd = LCFG_LOV_DEL_OBD;
        } 

        lustre_cfg_bufs_set_string(&llog_bufs, 1, ost_uuid);
        lustre_cfg_bufs_set_string(&llog_bufs, 2, index);
        lustre_cfg_bufs_set_string(&llog_bufs, 3, gen);

        lcfg = lustre_cfg_new(cmd, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}                                  

static int record_mount_point(struct obd_device *obd, struct llog_handle *llh,
                              char *profile, char *lov_name, char *mdc_name)
{
        struct lustre_cfg *lcfg;
        int rc; 

        lustre_cfg_bufs_reset(&llog_bufs, NULL);

        lustre_cfg_bufs_set_string(&llog_bufs, 1, profile);
        lustre_cfg_bufs_set_string(&llog_bufs, 2, lov_name);
        if (mdc_name)
                lustre_cfg_bufs_set_string(&llog_bufs, 2, mdc_name);

        lcfg = lustre_cfg_new(LCFG_MOUNTOPT, &llog_bufs);

        rc = mgs_do_record(obd, llh, (void *)lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}                                  

struct mgs_open_llog* find_mgs_open_llog(struct obd_device *obd, char *name)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct list_head *tmp;
        struct mgs_open_llog *mol;
        char fsname[64];
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

struct mgs_open_llog* create_mgs_open_llog(struct obd_device *obd, char *name)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgs_open_llog *mol, *tmp;
        char *p;

        OBD_ALLOC(mol, sizeof(*mol));
        if (!mol) {
                CERROR("can not allocate memory for mgs_open_llog.\n");
                return NULL;
        }

        p = strrchr(name, '/');
        if (p != NULL)
                strncpy(mol->mol_fsname, name, p - name);
        else {
                CERROR("logname need to include fsname.\n");
                goto cleanup;
        }
#if 0
        rc = mgs_load_system_db(obd, name, &mol->mol_system_db);
        if (rc) 
                goto cleanup;
#endif
        mol->mol_refs = 1;

        spin_lock_init(&mol->mol_lock);

        spin_lock(&mgs->mgs_open_llogs_lock);

        tmp = find_mgs_open_llog(obd, name);
        if(tmp) {
               OBD_FREE(mol->mol_system_db, sizeof(struct system_db));
               OBD_FREE(mol, sizeof(*mol));
               mol = tmp;
        } else 
               list_add(&mol->mol_list, &mgs->mgs_open_llogs);

        spin_unlock(&mgs->mgs_open_llogs_lock);

        return mol;
        
cleanup:
        OBD_FREE(mol, sizeof(*mol));
        return NULL;
}

struct mgs_open_llog* open_mgs_open_llog(struct obd_device *obd, char *name)
{
        struct mgs_open_llog *mol;

        mol = find_mgs_open_llog(obd, name);
        if (!mol) {
                mol = create_mgs_open_llog(obd, name);
                return mol;
        }

        spin_lock(&mol->mol_lock);
        mol->mol_refs++;
        spin_unlock(&mol->mol_lock);

        return mol;
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
        char lov_name[64];
        char uuid[64];
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

        /* the same uuid for lov and osc */
        sprintf(uuid, "%s_lov_UUID", db->mds_name);
        sprintf(lov_name, "lov_%s", db->mds_name);

        rc = record_attach(obd, llh, lov_name, "lov", uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n", name, rc);
                RETURN(rc);
        }

        rc = record_lov_setup(obd, llh, lov_name, &db->lovdesc);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", name, rc);
                RETURN(rc);
        }

        i = 0;
        list_for_each(tmp, &db->ost_infos) {
                char   ost_node_uuid[64];
                char   osc_name[64];
                char   index[16];
                char   *setup_argv[2];
                struct ost_info *oinfo = list_entry(tmp, struct ost_info,
                                                    osi_list);

                sprintf(ost_node_uuid, "%s_UUID", oinfo->osi_nodename);
                sprintf(osc_name,"OSC_%s_%s_%s",
                        db->mds_nodename, oinfo->osi_ostname, db->mds_name);

                rc = record_add_uuid(obd, llh, oinfo->osi_nid, ost_node_uuid);
                if (rc) {
                        CERROR("failed to record log(add_uuid) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                rc = record_attach(obd, llh, osc_name, "osc", uuid);
                if (rc) {
                        CERROR("failed to record log(attach_uuid) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                setup_argv[0] = oinfo->osi_ostuuid;
                setup_argv[1] = ost_node_uuid;
                rc = record_setup(obd, llh, osc_name, 2, setup_argv);
                if (rc) {
                        CERROR("failed to record log(setup) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(index, "%d", oinfo->osi_stripe_index);
                rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                            oinfo->osi_ostuuid, index, "1");
                if (rc) {
                        CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }
        }
        
        rc = record_mount_point(obd, llh, db->mds_name, lov_name, NULL);
        if (rc) {
                CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                       name, rc);
                RETURN(rc);
        }

        rc = mgs_end_record(obd, llh, name);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
                RETURN(rc);
        }

        RETURN(rc);
}

static int mgs_write_client_llog(struct obd_device *obd, char* name)
{
        struct mgs_open_llog *mol;
        struct llog_handle *llh;
        struct system_db *db;
        struct list_head *tmp;
        char mds_node_uuid[64];
        char lov_name[64];
        char uuid[64];
        char mdc_name[80];
        char mdc_uuid[64];
        char   *setup_argv[2];
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


        /* the same uuid for lov and osc */
        sprintf(uuid, "%s_lov_UUID", db->mds_name);
        sprintf(lov_name, "lov_client");

        rc = record_attach(obd, llh, lov_name, "lov", uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n", name, rc);
                RETURN(rc);
        }

        rc = record_lov_setup(obd, llh, lov_name, &db->lovdesc);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", name, rc);
                RETURN(rc);
        }

        i = 0;
        list_for_each(tmp, &db->ost_infos) {
                char   ost_node_uuid[64];
                char   osc_name[64];
                char   index[16];
                struct ost_info *oinfo = list_entry(tmp, struct ost_info,
                                                    osi_list);

                sprintf(ost_node_uuid, "%s_UUID", oinfo->osi_nodename);
                sprintf(osc_name, "OSC_%s_%s_MNT_client",
                        db->mds_nodename, oinfo->osi_ostname);

                rc = record_add_uuid(obd, llh, oinfo->osi_nid, ost_node_uuid);
                if (rc) {
                        CERROR("failed to record log(add_uuid) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                rc = record_attach(obd, llh, osc_name, "osc", uuid);
                if (rc) {
                        CERROR("failed to record log(attach_uuid) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                setup_argv[0] = oinfo->osi_ostuuid;
                setup_argv[1] = ost_node_uuid;
                rc = record_setup(obd, llh, osc_name, 2, setup_argv);
                if (rc) {
                        CERROR("failed to record log(setup) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(index, "%d", oinfo->osi_stripe_index);
                rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                            oinfo->osi_ostuuid, index, "1");
                if (rc) {
                        CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }
        }
      
        sprintf(mds_node_uuid, "%s_UUID", db->mds_nodename);
        rc = record_add_uuid(obd, llh, db->mds_nid, mds_node_uuid);
        if (rc) {
                CERROR("failed to record log(add uuid) %s: %d\n",
                       name, rc);
                RETURN(rc);
        }
    
        sprintf(mdc_name, "MDC_%s_%s_MNT_client",
                db->mds_nodename, db->mds_name);
        sprintf(mdc_uuid, "MDC_%s_UUID", db->fsname);

        rc = record_attach(obd, llh, mdc_name, "mdc", mdc_uuid);
        if (rc) {
                CERROR("failed to record log(attach) %s: %d\n",
                       name, rc);
                RETURN(rc);
        }

        setup_argv[0] = db->mds_uuid;
        setup_argv[1] = mds_node_uuid;
        rc = record_setup(obd, llh, mdc_name, 2, setup_argv);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n",
                       name, rc);
                RETURN(rc);
        }

        rc = record_mount_point(obd, llh, "client", lov_name, NULL);
        if (rc) {
                CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                       name, rc);
                RETURN(rc);
        }

        rc = mgs_end_record(obd, llh, name);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
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

