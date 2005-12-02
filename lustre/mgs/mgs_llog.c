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
#define D_MGS D_CONFIG|D_ERROR

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

static int db_handler(struct llog_handle *llh, struct llog_rec_hdr *rec, 
                      void *data)
{
        struct system_db *db = (struct system_db *)data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;
        ENTRY;

        db->sdb_flags &= ~SDB_NO_LLOG;

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
                        set_bit(i, db->index_map);
                }
                if (lcfg->lcfg_command == LCFG_LOV_DEL_OBD) {
                        memset(index_str, 0, 16);
                        strncpy(index_str, (char *)lustre_cfg_buf(lcfg, 2),
                                lcfg->lcfg_buflens[2]);
                        index = simple_strtol(index_str, NULL, 0);
                        clear_bit(i, db->index_map);
                }
        } else {
                CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
                rc = -EINVAL;
        }
out:
        RETURN(rc);
}

static int get_db_from_llog(struct obd_device *obd, char *logname,
                                   struct system_db *db)
{
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        int rc, rc2;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_REPL_CTXT),
                         &loghandle, NULL, logname);
        if (rc)
                GOTO(out_pop, rc);

        llog_init_handle(loghandle, 0, NULL);
        if (rc)
                GOTO(out_close, rc);

        rc = llog_process(loghandle, db_handler, (void *)db, NULL);

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
                 if (!test_bit(i, index_map))
                        return i;
        CERROR("max index exceeded.\n");
        return -ERANGE;
}

static int count_osts(void *index_map, int map_len)
{
       int i,num;
       for (i = 0, num = 0; i < map_len * 8; i++)
               if (test_bit(i, index_map))
                        num++;
       return num;
}

static struct system_db *mgs_find_db(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct system_db *db;
        struct list_head *tmp;

        list_for_each(tmp, &mgs->mgs_system_db_list) {
                db = list_entry(tmp, struct system_db, db_list);
                if (strcmp(db->fsname, fsname) == 0) {
                        return db;
                }
        }
        return NULL;
}

#define INDEX_MAP_SIZE 4096

static struct system_db *mgs_new_db(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct system_db *db;
        
        OBD_ALLOC(db, sizeof(*db));
        if (!db)
               return NULL;
        OBD_ALLOC(db->index_map, INDEX_MAP_SIZE);
        if (!db->index_map) {
                OBD_FREE(db);
                return NULL;
        }
        strncpy(db->fsname, fsname, sizeof(db->fsname));
        INIT_LIST_HEAD(&db->ost_infos);
        db->sdb_flags |= SDB_NO_LLOG;

        spin_lock(&mgs->mgs_system_db_lock);
        list_add(&db->db_list, &mgs->mgs_system_db_list);
        spin_unlock(&mgs->mgs_system_db_lock);

        return db;
}

static void mgs_free_db(struct system_db *db)
{
        list_del(&db->db_list);
        OBD_FREE(db->index_map, INDEX_MAP_SIZE);
        OBD_FREE(db, sizeof(*db);
}

int mgs_init_db_list(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        spin_lock_init(&mgs->mgs_system_db_lock);
        INIT_LIST_HEAD(&mgs->mgs_system_db_list);
        return 0;
}

int mgs_cleanup_db_list(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct system_db *db;
        struct list_head *tmp, *tmp2;
        spin_lock(&mgs->mgs_system_db_lock);
        list_for_each_safe(tmp, tmp2, &mgs->mgs_system_db_list) {
                db = list_entry(tmp, struct system_db, db_list);
                mgs_free_db(db);
        }
        spin_unlock(&mgs->mgs_system_db_lock);
        return 0;
}

static inline int name_create(char *prefix, char *suffix, char **newname){        
        OBD_ALLOC(newname, strlen(prefix) + strlen(suffix) + 1);
        if (!newname) 
                return -ENOMEM;
        sprintf(newname, "%s%s", prefix, suffix);
        return 0;
}

static inline void name_destroy(char *newname){        
        if (newname)
                OBD_FREE(newname, strlen(newname) + 1);
}


static int mgs_find_or_make_db(struct obd_device *obd, char *name, 
                               struct system_db **dbh)
{
        struct system_db *db;
        char *cliname;
        int rc = 0;

        db = mgs_find_db(obd, name);
        if (db) {
                *dbh = db;
                return 0;
        }

        CDEBUG(D_MGS, "Creating new db\n");
        db = mgs_new_db(name);
        if (!db) 
                return -ENOMEM;

        /* extract the db from the client llog */
        name_create(name, "-client", &cliname);
        rc = get_db_from_llog(obd, cliname, db);
        name_destroy(cliname);
        if (rc) {
                CERROR("Can't get db from llog %d\n", rc);
                mgs_free_db(db);
                return rc;
        }

        *dbh = db;
        
        if (LOG_IS_EMPTY(db)) {
                CDEBUG(D_MGS, "llog %s is empty\n", name); 
        }

        return 0;
}

int mgs_set_next_index(struct obd_device *obd, mgmt_target_info *mti)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct system_db *db;
        int rc = 0;

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, db); 

        if (mti->mti_flags & LDD_F_SV_TYPE_OST)
                mti->mti_stripe_index = next_ost_index(db->index_map, 
                                                       INDEX_MAP_SIZE);
        else
                mti->mti_stripe_index = 1; /*FIXME*/

        make_sv_name(mti->mti_flags, mti->mti_stripe_index,
                     mti->mti_fsname, mti->mti_svname);

        CDEBUG(D_MGS, "Set new index for %s\n", mti->mti_svname);

        return rc;
}

static inline int mgs_do_record(struct obd_device *obd, struct llog_handle *llh,
                                struct lustre_cfg *lcfg)
{
        struct lvfs_run_ctxt   saved;
        struct llog_rec_hdr    rec;
        int rc;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_write_rec(llh, &rec, NULL, 0, (void *)lcfg, -1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        return rc;
}

static int do_record(struct obd_device *obd, struct llog_handle *llh,
                     char *cfgname, lnet_nid_t nid, int cmd,
                     char *s1, char *s2, char *s3, char *s4)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg     *lcfg;
        int rc;
               
        CDEBUG(D_TRACE, "lcfg %s %#x %s %s %s %s\n", cfgname,
               cmd, s1, s2, s3, s4); 

        lustre_cfg_bufs_reset(&bufs, cfgname);
        if (s1) 
                lustre_cfg_bufs_set_string(&bufs, 1, s1);
        if (s2) 
                lustre_cfg_bufs_set_string(&bufs, 2, s2);
        if (s3) 
                lustre_cfg_bufs_set_string(&bufs, 3, s3);
        if (s4) 
                lustre_cfg_bufs_set_string(&bufs, 4, s4);

        lcfg = lustre_cfg_new(cmd, &bufs);
        lcfg->lcfg_nid = nid;

        rc = mgs_do_record(obd, llh, lcfg);
        
        lustre_cfg_free(lcfg);
        return(rc);
}

static inline int record_attach(struct obd_device *obd, struct llog_handle *llh,
                                char* name, char *type, char *uuid)
{
        return do_record(obd,llh,name,0,LCFG_ATTACH,type,uuid,0,0);
}

static inline int record_add_uuid(struct obd_device *obd, struct llog_handle *llh,
                           uint64_t nid, char *uuid)
{
        return do_record(obd,llh,NULL,nid,LCFG_ADD_UUID,uuid,0,0,0);
}

static int record_lov_setup(struct obd_device *obd, struct llog_handle *llh,
                            char *device_name, struct lov_desc *desc)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        lustre_cfg_bufs_reset(&bufs, device_name);
        lustre_cfg_bufs_set(&llog_bufs, 1, desc, sizeof(*desc));
        lcfg = lustre_cfg_new(LCFG_SETUP, &llog_bufs);

        rc = mgs_do_record(obd, llh, lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static int record_lov_modify_tgts(struct obd_device *obd,
                                  struct llog_handle *llh,
                                  char *lov_name, char *op, char *ost_uuid,
                                  char *index, char *gen)
{
        int cmd; 
        if (strncmp(op, "add", 3) == 0) 
                cmd = LCFG_LOV_ADD_OBD;
        else 
                cmd = LCFG_LOV_DEL_OBD;
        
        return do_record(obd,llh,lov_name,0,cmd,ost_uuid,index,gen,0);
}                                  

static inline int record_mount_opt(struct obd_device *obd, struct llog_handle *llh,
                                     char *profile, char *lov_name, char *mdc_name)
{
        return do_record(obd,llh,NULL,0,LCFG_MOUNTOPT,profile,lov_name,mdc_name,0);
}                                  

static int mgs_start_log(struct obd_device *obd, 
                            struct llog_handle **llh, char *name)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct lvfs_run_ctxt saved;
        int rc = 0;
        
        if (*llh)
                RETURN(-EBUSY);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         llh, NULL, name);
        if (rc == 0)
                llog_init_handle(*llh, LLOG_F_IS_PLAIN, &cfg_uuid);
        else
                *llh = NULL;

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_end_log(struct obd_device *obd,
                          struct llog_handle *llh, char* name)
{
        struct lvfs_run_ctxt saved;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_close(llh);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        RETURN(rc);
}

static int mgs_clear_log(struct obd_device *obd, char *name)
{
        struct lvfs_run_ctxt saved;
        struct llog_handle *llh;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         &llh, NULL, name);
        if (rc == 0) {
                llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_destroy(llh);
                llog_free_handle(llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        if (rc)
                CERROR("failed to clear log %s: %d\n", name, rc);

        return(rc);
}

/* lov is the first thing in the mdt and client logs */
static int mgs_write_log_lov(struct obd_device *obd, char *fsname,
                             char *logname, char *mdcname)
{
        struct llog_handle *llh;
        struct lov_desc *lovdesc;
        char lov_name[64];
        char uuid[64];
        int rc = 0;
        ENTRY;

        /* FIXME just make lov_setup accept empty desc (put uuid in buf 2) */
        OBD_ALLOC(lovdesc, sizeof(*lovdesc));
        if (lovdesc == NULL)
                GOTO(cleanup, rc = -ENOMEM);
        /* Use defaults here, will fix them later with LCFG_PARAM */
        lovdesc->ld_pattern = 0;
        lovdesc->ld_default_stripe_size = 1024*1024;
        lovdesc->ld_default_stripe_offset = 0;
        sprintf(lov_name, "lov_%s", mti->mti_fsname);
        /* can these be the same? */
        sprintf(uuid, "%s_lov_UUID", mti->mti_fsname);
        sprintf((char*)lovdesc->ld_uuid.uuid, "%s_UUID", lov_name);

        rc = mgs_start_log(obd, &llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
                GOTO(out, rc);
        }

        rc = record_attach(obd, llh, lov_name, "lov", uuid);
        if (rc) {
                CERROR("failed to record log(attach lov) %s: %d\n", name, rc);
                GOTO(out, rc);
        }

        rc = record_lov_setup(obd, llh, lov_name, lovdesc);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n", name, rc);
                GOTO(out, rc);
        }

        /* profile is the same as the logname */
        rc = record_mount_opt(obd, llh, logname, lov_name, mdcname);
        if (rc) {
                CERROR("failed to record log(mount_opt) %s: %d\n",
                       logname, rc);
                GOTO(cleanup, rc);
        }

        rc = mgs_end_log(obd, llh, name);
        if (rc) {
                CERROR("failed to record log %s: %d\n", name, rc);
                GOTO(out, rc);
        }
out:
        RETURN(rc);
}

static int mgs_write_log_mdt(struct obd_device *obd,
                             struct mgmt_target_info *mti)
{
        struct system_db *db;
        struct llog_handle *llh;
        char *cliname, *mdcname, *tmpname;
        int rc;

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, db); 
        if (rc || !db) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                return(-EINVAL);
        }

        name_create(mti->mti_fsname, "-client", &cliname);
        name_create(mti->mti_fsname, "-mdc", &mdcname);
        if (LOG_IS_EMPTY(db)) {
                /* First time for all logs for this fs */
                rc = mgs_clear_log(obd, mti->mti_svname);
                rc = mgs_write_log_lov(obd, mti->mti_fsname, mti->mti_svname,0);
                /* Start client log */
                rc = mgs_clear_log(obd, cliname);
                rc = mgs_write_log_lov(obd, mti->mti_fsname, cliname, mdcname);
        }
        
        /* We added the lov+mount opt, maybe some osc's, now for the mds.
           We might add more ost's after this. Note that during the parsing
           of this log, this is when the mds will start. */ 
        rc = mgs_start_log(obd, &llh, mti->mti_svname);
        name_create(mti->mti_svname, "_UUID", &tmpname);
        rc = record_attach(obd, llh, mti->mti_svname, LUSTRE_MDS_NAME, tmpname);
        name_destroy(tmpname);
        rc = do_record(obd,llh,mti->mti_svname,0,LCFG_SETUP,
                       "somedev"/*ignored*/,"sometype"/*ignored*/,
                       mti->mti_svname, 0/*options*/);
        rc = mgs_end_record(obd, llh, logname);

        /* Add the mdt info to the client */
        /* FIXME add lines to client 
#09 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
#10 L attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_031388313f
#11 L setup    0:MDC_uml1_mdsA_MNT_client  1:mdsA_UUID  2:uml1_UUID
#12 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
#13 L add_conn 0:MDC_uml1_mdsA_MNT_client  1:uml2_UUID
#14 L mount_option 0:  1:client  2:lov1  3:MDC_uml1_mdsA_MNT_client
        */
        name_destroy(mdcname);
        name_destroy(cliname);
        return rc;
}

int mgs_write_log_target(struct obd_device *obd,
                         struct mgmt_target_info *mti)
{
        if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                rc = mgs_write_llog_mdt(mti);
        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                rc = mgs_write_llog_ost(mti);
        } else {
                CERROR("Unknown target type, can't create log\n",
                       mti->mti_svname);
                rc = -EINVAL;
        }
        return rc;
}

int llog_add_mds(struct obd_device *obd, struct mgmt_target_info *mti)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct llog_handle *llh;
        struct system_db *db;
        char logname[64], lov_name[64];
        char mds_node_uuid[64];
        char uuid[64];
        char mdc_name[80];
        char mdc_uuid[64];
        char *setup_argv[2];
        struct lov_desc *ld;
        int rc = 0;

        db = mgs_find_db(obd, mti->mti_fsname);
        if (!db)
                RETURN(-EINVAL);

        llh = llog_alloc_handle();
        if (llh == NULL)
                RETURN(-ENOMEM);

        OBD_ALLOC(ld, sizeof(*ld));
        if (!ld)
             GOTO(out, rc = -ENOMEM);

        ld->ld_tgt_count = count_osts(db->index_map, INDEX_MAP_SIZE);
        ld->ld_default_stripe_count = mti->mti_stripe_size;
        ld->ld_pattern = mti->mti_stripe_pattern;
        ld->ld_default_stripe_offset = mti->mti_stripe_offset;
        sprintf((char*)ld->ld_uuid.uuid,  "lov1_UUID");

        /* Two phases: 1. writing mds log. 
                       2. writing client log
         */

        /*First phase: writing mds log  */
        sprintf(logname, "%s/mds1", mti->mti_fullfsname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);;
        }

        /* the same uuid for lov and osc */
        sprintf(uuid, "%s_lov_UUID", mti->mti_target_name);
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

        rc = record_mount_point(obd, llh, mti->mti_target_name, lov_name, NULL);
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
        sprintf(uuid, "%s_lov_UUID", mti->mti_target_name);
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

        sprintf(mds_node_uuid, "%s_UUID", mti->mti_target_nodename);
        rc = record_add_uuid(obd, llh, mti->mti_nid, mds_node_uuid);
        if (rc) {
                CERROR("failed to record log(add uuid) %s: %d\n",
                       logname, rc);
                RETURN(rc);
        }
    
        sprintf(mdc_name, "MDC_%s_%s_MNT_client",
                mti->mti_target_nodename, mti->mti_target_name);
        sprintf(mdc_uuid, "MDC_%s_UUID", mti->mti_fullfsname);

        rc = record_attach(obd, llh, mdc_name, "mdc", mdc_uuid);
        if (rc) {
                CERROR("failed to record log(attach) %s: %d\n",
                       logname, rc);
                RETURN(rc);
        }

        sprintf(setup_argv[0],"%s_UUID", mti->mti_mds_name);
        rc = do_record(obd,llh,mdc_name,0,LCFG_SETUP,mds_uuid FIXME,mds_node_uuid,0,0);
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

        rc = mgs_clear_log(obd, llh, name);
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
                struct mgmt_target_info *oinfo;

                oinfo = list_entry(tmp, struct mgmt_target_info, mti_list);

                sprintf(ost_node_uuid, "%s_UUID", oinfo->mti_nodename);
                sprintf(osc_name, "OSC_%s_%s_MNT_client",
                        db->mds_nodename, oinfo->mti_ostname);

                rc = record_add_uuid(obd, llh, oinfo->mti_nid, ost_node_uuid);
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

                setup_argv[0] = oinfo->mti_ostuuid;
                setup_argv[1] = ost_node_uuid;
                do_record(obd,llh,osc_name,0,LCFG_SETUP,oinfo->mti_ostuuid,ost_node_uuid,0,0);
                if (rc) {
                        CERROR("failed to record log(setup) %s: %d\n",
                               name, rc);
                        RETURN(rc);
                }

                sprintf(index, "%d", oinfo->mti_stripe_index);
                rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                            oinfo->mti_ostuuid, index, "1");
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

        rc = do_record(obd,llh,mdc_name,0,LCFG_SETUP,db->mds_uuid,mds_node_uuid,0,0);
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

static int mgs_write_log_add(struct obd_device *obd, 
                                struct mgmt_target_info *mti)
{
        int rc = 0;
        CERROR("New basic LLOG.\n"); /*FIXME: add soon*/
        return rc;
}

static int decompose_fullfsname(char *fullfsname, char *fsname, char *poolname)
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

int mgs_write_llog_ost(struct obd_device *obd, struct mgmt_target_info *mti)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct llog_handle *llh;
        struct system_db *db;
        char logname[64], lov_name[64];
        char ost_node_uuid[64];
        char osc_name[64];
        char uuid[64];
        char setup_argv[2];
        char index[16];
        int rc = 0;

        db = mgs_find_db(obd, mti->mti_fsname);
        if (!db)
                RETURN(-EINVAL);

        llh = llog_alloc_handle();
        if (llh == NULL)
                RETURN(-ENOMEM);

        /* Two phases: 1. writing mds log. 
                       2. writing client log
         */

        /*First phase: writing mds log  */
        sprintf(logname, "%s/mds1", mti->mti_fullfsname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);
        }
        sprintf(ost_node_uuid, "%s_UUID", mti->mti_nodename);
        sprintf(osc_name, "OSC_%s_%s_MNT_client",
                db->fsname, mti->mti_ostname);

        rc = record_add_uuid(obd, llh, mti->mti_nid, ost_node_uuid);
        if (rc) {
                CERROR("failed to record log(add_uuid) %s: %d\n",
                        logname, rc);
                GOTO(out, rc);
        }
        sprintf(uuid, "%s_lov_UUID", mti->mti_fullfsname);

        rc = record_attach(obd, llh, osc_name, "osc", uuid);
        if (rc) {
                CERROR("failed to record log(attach_uuid) %s: %d\n",
                        logname, rc);
                GOTO(out, rc);
        }

        rc = do_record(obd,llh,osc_name,0,LCFG_SETUP,mti->mti_ostuuid,ost_node_uuid,0,0);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);
        }

        sprintf(index, "%d", mti->mti_stripe_index);
        rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                    mti->mti_ostuuid, index, "1");
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
        sprintf(logname, "%s/client", mti->mti_fullfsname);

        rc = mgs_start_record(obd, llh, logname);
        if (rc) {
                CERROR("failed to record log %s: %d\n", logname, rc);
                GOTO(out, rc);
        }

        sprintf(ost_node_uuid, "%s_UUID", mti->mti_nodename);
        sprintf(osc_name, "OSC_%s_%s_MNT_client",
                db->fsname, mti->mti_ostname);

        rc = record_add_uuid(obd, llh, mti->mti_nid, ost_node_uuid);
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

        rc = do_record(obd,llh,osc_name,0,LCFG_SETUP,mti->mti_ostuuid,ost_node_uuid,0,0);
        if (rc) {
                CERROR("failed to record log(setup) %s: %d\n",
                       logname, rc);
                GOTO(out, rc);
        }

        sprintf(index, "%d", mti->mti_stripe_index);
        rc = record_lov_modify_tgts(obd, llh, lov_name, "add",
                                    mti->mti_ostuuid, index, "1");
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

        default:
                CDEBUG(D_INFO, "unknown command %x\n", cmd);
                RETURN(-EINVAL);
        }
        RETURN(0);
}
