/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mgs/mgs_llog.c
 *  Lustre Management Server (mgs) llog controller
 *
 *  Copyright (C) 2001-2005 Cluster File Systems, Inc.
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
static int get_index_map_handler(struct llog_handle *llh,
                                 struct llog_rec_hdr *rec, 
                                 void *data)
{
        void *index_map = data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;
        ENTRY;

        if (rec->lrh_type == OBD_CFG_REC) {
                struct lustre_cfg *lcfg;
                char index_str[16];
                int i, index;

                rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
                if (rc)
                        GOTO(out, rc);

                lcfg = (struct lustre_cfg *)cfg_buf;

                if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD) {
                        memset(index_str, 0, 16);
                        strncpy(index_str, (char *)lustre_cfg_buf(lcfg, 2),
                                lcfg->lcfg_buflens[2]);
                        index = simple_strtol(index_str, NULL, 0);
                        set_bit(i, index_map);
                }
                if (lcfg->lcfg_command == LCFG_LOV_DEL_OBD) {
                        memset(index_str, 0, 16);
                        strncpy(index_str, (char *)lustre_cfg_buf(lcfg, 2),
                                lcfg->lcfg_buflens[2]);
                        index = simple_strtol(index_str, NULL, 0);
                        clear_bit(i, index_map);
                }
        } else {
                CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
                rc = -EINVAL;
        }
out:
        RETURN(rc);
}

static int get_index_map_from_llog(struct obd_device *obd, char *fsname,
                                   void *index_map)
{
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        int rc, rc2;

        OBD_ALLOC(index_map, 4096);
        if (!index_map)
                return -ENOMEM;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_REPL_CTXT),
                         &loghandle, NULL, fsname);
        if (rc)
                GOTO(out_pop, rc);

        llog_init_handle(loghandle, 0, NULL);
        if (rc)
                GOTO(out_close, rc);

        rc = llog_process(loghandle, get_index_map_handler, 
                          index_map, NULL);

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int next_ost_index(void *index_map, int map_len)
{
        int i;
        for (i = 0; i < map_len * 8; i++)
                 if (test_bit(i, index_map))
                        return i;
        CERROR("Index exceed upping.\n");
        return -ERANGE;
}

static int get_ost_number(void *index_map, int map_len)
{
       int i,num;
       for (i = 0, num = 0; i < map_len * 8; i++)
               if (test_bit(i, index_map))
                        num++;
       return num;
}

int mgs_get_index(struct obd_device *obd, char *full_fsname,
                         int disk_type, int *new_index)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct system_db *db;
        struct list_head *tmp;
        int rc = 0;

        list_for_each(tmp, &mgs->mgs_system_db_list) {
                db = list_entry(tmp, struct system_db, db_list);
                if (!strcmp(db->fsname, full_fsname)) {
                        if (disk_type & LDD_F_SV_TYPE_OST)
                                *new_index = next_ost_index(db->index_map, 4096);
                        else
                                *new_index = 1; /*FIXME*/
                        return 0;
                }
        }
 
        OBD_ALLOC(db, sizeof(*db));
        if (!db)
               return -ENOMEM;
        strcpy(db->fsname, full_fsname);
        INIT_LIST_HEAD(&db->db_list);
        INIT_LIST_HEAD(&db->ost_infos);
        rc = get_index_map_from_llog(obd, full_fsname, db->index_map);
        if (rc)
                GOTO(clean, rc);
        spin_lock(&mgs->mgs_system_db_lock);
        list_add(&db->db_list, &mgs->mgs_system_db_list);
        spin_unlock(&mgs->mgs_system_db_lock);

        *new_index = next_ost_index(db->index_map, 4096);

out:
        return rc;
clean:
        OBD_FREE(db, sizeof(*db));
        goto out;
}
EXPORT_SYMBOL(mgs_get_index);                         

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

static int mgs_write_basic_llog(struct obd_device *obd, 
                                struct mgmt_mds_info *mmi)
{
        int rc = 0;
        CERROR("New basic LLOG.\n"); /*FIXME: add soon*/
        return rc;
}
static int mgs_write_mds_llog(struct obd_device *obd, struct mgmt_mds_info *mmi)
{
        struct mgs_open_llog *mol;
        struct llog_handle *llh;
        struct list_head *tmp;
        char *name = mmi->mmi_fullfsname;
        struct lov_desc *lovdesc;
        char lov_name[64];
        char uuid[64];
        int i, rc = 0;

        llh = llog_alloc_handle();
        if (llh == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(lovdesc, sizeof(*lovdesc));
        if (lovdesc == NULL)
                GOTO(cleanup, rc = -ENOMEM);
        lovdesc->ld_pattern = mmi->mmi_pattern;
        lovdesc->ld_default_stripe_size = mmi->mmi_stripe_size;
        lovdesc->ld_default_stripe_offset = mmi->mmi_stripe_offset;

        rc = mgs_clear_record(obd, llh, name);
        if (rc) {
                CERROR("failed to clear log %s: %d\n", name, rc);
                GOTO(cleanup, rc);
        }

        rc = mgs_start_record(obd, llh, name);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
                GOTO(cleanup, rc);
        }

        /* the same uuid for lov and osc */
        sprintf(uuid, "%s_lov_UUID", mmi->mmi_mds_name);
        sprintf(lov_name, "lov_%s", mmi->mmi_mds_name);
        sprintf((char*)lovdesc->ld_uuid.uuid, "%s_UUID", lov_name);

        rc = record_attach(obd, llh, lov_name, "lov", uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n", name, rc);
                GOTO(cleanup, rc);
        }

        rc = record_lov_setup(obd, llh, lov_name, lovdesc);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", name, rc);
                GOTO(cleanup, rc);
        }
#if 0
        i = 0;
        list_for_each(tmp, &db->ost_infos) {
                char   ost_node_uuid[64];
                char   osc_name[64];
                char   index[16];
                char   *setup_argv[2];
                struct mgmt_ost_info *oinfo;

                oinfo = list_entry(tmp, struct mgmt_ost_info, moi_list);

                sprintf(ost_node_uuid, "%s_UUID", oinfo->moi_nodename);
                sprintf(osc_name,"OSC_%s_%s_%s",
                        db->mds_nodename, oinfo->moi_ostname, db->mds_name);

                rc = record_add_uuid(obd, llh, oinfo->moi_nid, ost_node_uuid);
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

                setup_argv[0] = oinfo->moi_ostuuid;
                setup_argv[1] = ost_node_uuid;
                rc = record_setup(obd, llh, osc_name, 2, setup_argv);
                if (rc) {
                        CERROR("failed to record log(setup) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(index, "%d", oinfo->moi_stripe_index);
                rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                            oinfo->moi_ostuuid, index, "1");
                if (rc) {
                        CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }
        }
#endif        
        rc = record_mount_point(obd, llh, mmi->mmi_mds_name, lov_name, NULL);
        if (rc) {
                CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                       name, rc);
                GOTO(cleanup, rc);
        }

        rc = mgs_end_record(obd, llh, name);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
                GOTO(cleanup, rc);
        }
out:
        RETURN(rc);
cleanup:
        llog_free_handle(llh);
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

#if 0
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
                struct mgmt_ost_info *oinfo;

                oinfo = list_entry(tmp, struct mgmt_ost_info, moi_list);

                sprintf(ost_node_uuid, "%s_UUID", oinfo->moi_nodename);
                sprintf(osc_name, "OSC_%s_%s_MNT_client",
                        db->mds_nodename, oinfo->moi_ostname);

                rc = record_add_uuid(obd, llh, oinfo->moi_nid, ost_node_uuid);
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

                setup_argv[0] = oinfo->moi_ostuuid;
                setup_argv[1] = ost_node_uuid;
                rc = record_setup(obd, llh, osc_name, 2, setup_argv);
                if (rc) {
                        CERROR("failed to record log(setup) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(index, "%d", oinfo->moi_stripe_index);
                rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                            oinfo->moi_ostuuid, index, "1");
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
#endif
        RETURN(rc);
}
#if 0
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
#endif

int decompose_fullfsname(char *fullfsname, char *fsname, char *poolname)
{
        char *p = NULL;
        
        OBD_ALLOC(fsname, sizeof(*fullfsname));
        if (!fsname) {
                CERROR("Can't not copy fsname from request.\n");
                return -ENOMEM;
        }

        p = strchr(fsname, '/');
        if (p) {
                p = '\0';
                poolname = p++;
        }
        return 0;       
}

/* Build basic disk directory for llog */
static int build_llog_dir(struct obd_device *obd, char *full_fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct lvfs_run_ctxt saved;
        struct dentry *fs_dentry, *pool_dentry;
        char *fsname = NULL, *poolname = NULL;
        int rc;

        rc = decompose_fullfsname(full_fsname, fsname, poolname);
        if (rc)
                GOTO(out, rc);
        
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        fs_dentry = simple_mkdir(mgs->mgs_configs_dir, fsname, 0777, 1);
        if (IS_ERR(fs_dentry)) {
                rc = PTR_ERR(fs_dentry);
                CERROR("cannot create %s dir : rc = %d\n", fsname, rc);
                GOTO(cleanup_pop, rc);
        }

        pool_dentry = simple_mkdir(fs_dentry, poolname, 0777, 1);
        if (IS_ERR(pool_dentry)) {
                rc = PTR_ERR(pool_dentry);
                CERROR("cannot create %s dir : rc = %d\n", poolname, rc);
                GOTO(cleanup_dput, rc);
        }
        dput(pool_dentry);
cleanup_dput:
        dput(fs_dentry);
cleanup_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        OBD_FREE(fsname, sizeof(full_fsname));
out:
        return rc;
}

int mgmt_handle_first_connect(struct ptlrpc_request *req)
{
        struct obd_export *exp = req->rq_export;
        struct obd_device *obd = exp->exp_obd;
        struct mgs_obd *mgs = &obd->u.mgs;
        __u32  *disk_type;
        char *full_fsname, *node_name;
        int rep_size = sizeof(int);
        int new_index, *rep_index;
        int rc;

        disk_type = lustre_swab_reqbuf(req, 0, sizeof(*disk_type),
                                       __swab32s);
        full_fsname = lustre_swab_reqbuf(req, 1, NAME_MAXLEN, NULL);
        node_name = lustre_swab_reqbuf(req, 2, NAME_MAXLEN, NULL);

        if (*disk_type & LDD_F_SV_TYPE_MDT) {
                CDEBUG(D_INODE,
                       "New MDS Server belong to FILESYSTEM[/POOL]%s\n",
                       full_fsname);
        }
        else if (*disk_type & LDD_F_SV_TYPE_OST) {
                CDEBUG(D_INODE,
                       "New OST Server belong to FILESYSTEM[/POOL]%s\n",
                       full_fsname);
        }
        else {
                CERROR("Wrong disk type register.\n");
                GOTO(out, rc = -EFAULT);
        }

        rc = build_llog_dir(obd, full_fsname);
        if (rc) {
                CERROR("Can not build llog dir.\n");
                GOTO(out, rc);
        }

        rc = mgs_get_index(obd, full_fsname, *disk_type, &new_index);
        if (rc) {
                CERROR("Can not get index for the new server.\n" );
                new_index = rc;
        }

out:
        lustre_pack_reply(req, 1, &rep_size, NULL);
        rep_index = lustre_msg_buf(req->rq_repmsg, 0, sizeof(int));
        *rep_index = new_index;

        return rc;
}

int llog_add_ost(struct obd_device *obd, struct mgmt_ost_info *moi)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct llog_handle *llh;
        struct system_db *db = NULL;
        struct list_head *tmp;
        char logname[64], lov_name[64];
        char ost_node_uuid[64];
        char osc_name[64];
        char uuid[64];
        char setup_argv[2];
        char index[16];
        int rc = 0;

        list_for_each(tmp, &mgs->mgs_system_db_list) {
                struct system_db *tmp_db;
                tmp_db = list_entry(tmp, struct system_db, db_list);
                if (!strcmp(tmp_db->fsname, moi->moi_fullfsname)) {
                        db = tmp_db;
                        break;
                }
        }
        if (!db)
                RETURN(-EINVAL);

        llh = llog_alloc_handle();
        if (llh == NULL)
                RETURN(-ENOMEM);

        /* Two phases: 1. writing mds log. 
                       2. writing client log
         */

        /*First phase: writing mds log  */
        sprintf(logname, "%s/mds1", moi->moi_fullfsname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);
        }
        sprintf(ost_node_uuid, "%s_UUID", moi->moi_nodename);
        sprintf(osc_name, "OSC_%s_%s_MNT_client",
                db->fsname, moi->moi_ostname);

        rc = record_add_uuid(obd, llh, moi->moi_nid, ost_node_uuid);
        if (rc) {
                CERROR("failed to record log(add_uuid) %s: %d\n",
                        logname, rc);
                GOTO(out, rc);
        }
        sprintf(uuid, "%s_lov_UUID", moi->moi_fullfsname);

        rc = record_attach(obd, llh, osc_name, "osc", uuid);
        if (rc) {
                CERROR("failed to record log(attach_uuid) %s: %d\n",
                        logname, rc);
                GOTO(out, rc);
        }

        setup_argv[0] = moi->moi_ostuuid;
        setup_argv[1] = ost_node_uuid;
        rc = record_setup(obd, llh, osc_name, 2, setup_argv);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);
        }

        sprintf(index, "%d", moi->moi_stripe_index);
        rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                    moi->moi_ostuuid, index, "1");
        if (rc) {
                CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);
        }

        rc = mgs_end_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);
        }

        /*Second Phase : writing client llog */
        sprintf(logname, "%s/client", moi->moi_fullfsname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);
        }

        sprintf(ost_node_uuid, "%s_UUID", moi->moi_nodename);
        sprintf(osc_name, "OSC_%s_%s_MNT_client",
                db->fsname, moi->moi_ostname);

        rc = record_add_uuid(obd, llh, moi->moi_nid, ost_node_uuid);
        if (rc) {
                CERROR("failed to record log(add_uuid) %s: %d\n",
                        logname, rc);
                GOTO(out, rc);
        }

        rc = record_attach(obd, llh, osc_name, "osc", uuid);
        if (rc) {
                CERROR("failed to record log(attach_uuid) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);
        }

        setup_argv[0] = moi->moi_ostuuid;
        setup_argv[1] = ost_node_uuid;
        rc = record_setup(obd, llh, osc_name, 2, setup_argv);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);
        }

        sprintf(index, "%d", moi->moi_stripe_index);
        rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                    moi->moi_ostuuid, index, "1");
        if (rc) {
                CERROR("failed to record log(lov_modify_tgts) %s: %d\n",
                        logname, rc);
                GOTO(out, rc);
        }

        rc = mgs_end_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);
        }
out:
        llog_free_handle(llh);
        return rc;
}
EXPORT_SYMBOL(llog_add_ost);

int llog_add_mds(struct obd_device *obd, struct mgmt_mds_info *mmi)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct llog_handle *llh;
        struct system_db *db = NULL;
        struct list_head *tmp;
        char logname[64], lov_name[64];
        char mds_node_uuid[64];
        char uuid[64];
        char mdc_name[80];
        char mdc_uuid[64];
        char *setup_argv[2];
        struct lov_desc *ld;
        int rc = 0;

        list_for_each(tmp, &mgs->mgs_system_db_list) {
                struct system_db *tmp_db;
                tmp_db = list_entry(tmp, struct system_db, db_list);
                if (!strcmp(tmp_db->fsname, mmi->mmi_fullfsname)) {
                        db = tmp_db;
                        break;
                }
        }
        if (!db)
                RETURN(-EINVAL);

        llh = llog_alloc_handle();
        if (llh == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
             GOTO(out, rc = -ENOMEM);

        ld->ld_tgt_count = get_ost_number(db->index_map, 4096);
        ld->ld_default_stripe_count = mmi->mmi_stripe_size;
        ld->ld_pattern = mmi->mmi_pattern;
        ld->ld_default_stripe_offset = mmi->mmi_stripe_offset;
        sprintf((char*)ld->ld_uuid.uuid,  "lov1_UUID");

        /* Two phases: 1. writing mds log. 
                       2. writing client log
         */

        /*First phase: writing mds log  */
        sprintf(logname, "%s/mds1", mmi->mmi_fullfsname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);;
        }

        /* the same uuid for lov and osc */
        sprintf(uuid, "%s_lov_UUID", mmi->mmi_mds_name);
        sprintf(lov_name, "lov_client");

        rc = record_attach(obd, llh, lov_name, "lov", uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n", logname, rc);
                GOTO(out, rc);;
        }

        rc = record_lov_setup(obd, llh, lov_name, ld);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", logname, rc);
                GOTO(out, rc);;
        }

        rc = record_mount_point(obd, llh, mmi->mmi_mds_name, lov_name, NULL);
        if (rc) {
                CERROR("failed to record log(mount_point) %s: %d\n",
                       logname, rc);
                GOTO(cleanup, rc);
        }

        rc = mgs_end_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(cleanup, rc);
        }

        /*Second phase: writing client log  */
        sprintf(logname, "%s/client", logname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);;
        }

        /* the same uuid for lov and osc */
        sprintf(uuid, "%s_lov_UUID", mmi->mmi_mds_name);
        sprintf(lov_name, "lov_client");

        rc = record_attach(obd, llh, lov_name, "lov", uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);;
        }

        rc = record_lov_setup(obd, llh, lov_name, ld);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", logname, rc);
                GOTO(out, rc);;
        }

        sprintf(mds_node_uuid, "%s_UUID", mmi->mmi_mds_nodename);
        rc = record_add_uuid(obd, llh, mmi->mmi_nid, mds_node_uuid);
        if (rc) {
                CERROR("failed to record log(add uuid) %s: %d\n",
                       logname, rc);
                RETURN(rc);
        }
    
        sprintf(mdc_name, "MDC_%s_%s_MNT_client",
                mmi->mmi_mds_nodename, mmi->mmi_mds_name);
        sprintf(mdc_uuid, "MDC_%s_UUID", mmi->mmi_fullfsname);

        rc = record_attach(obd, llh, mdc_name, "mdc", mdc_uuid);
        if (rc) {
                CERROR("failed to record log(attach) %s: %d\n",
                       logname, rc);
                RETURN(rc);
        }

        sprintf(setup_argv[0],"%s_UUID", mmi->mmi_mds_name);
        setup_argv[1] = mds_node_uuid;
        rc = record_setup(obd, llh, mdc_name, 2, setup_argv);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n",
                       logname, rc);
                RETURN(rc);
        }

        rc = record_mount_point(obd, llh, "client", lov_name, NULL);
        if (rc) {
                CERROR("failed to record log(mount_point) %s: %d\n",
                       logname, rc);
                RETURN(rc);
        }

        rc = mgs_end_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                RETURN(rc);
        }

cleanup:
        OBD_FREE(ld, sizeof(*ld));
out:
        llog_free_handle(llh);
        return rc;
}
EXPORT_SYMBOL(llog_add_mds);

int mgmt_handle_mds_add(struct ptlrpc_request *req)
{    
        struct obd_device *obd = &req->rq_export->exp_obd;
        struct mgs_obd *mgs = &obd->u.mgs;
        struct mgmt_mds_info *req_mmi, *mmi, *rep_mmi;
        int rep_size = sizeof(*mmi);
        int index, rc;

        OBD_ALLOC(mmi, sizeof(*mmi));
        if (!mmi)
                GOTO(out, rc = -ENOMEM);
        req_mmi = lustre_swab_reqbuf(req, 0, sizeof(*mmi),
                                     lustre_swab_mgmt_mds_info);
        memcpy(mmi, req_mmi, sizeof(*mmi));
        
        rc = llog_add_mds(obd, mmi);
out:
        lustre_pack_reply(req, 1, &rep_size, NULL); 
        rep_mmi = lustre_msg_buf(req->rq_repmsg, 0, sizeof(*rep_mmi));
        memcpy(rep_mmi, mmi, sizeof(*rep_mmi));
        if (rc)
                rep_mmi->mmi_index = rc;
        return rc;
}
EXPORT_SYMBOL(mgmt_handle_mds_add);


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
