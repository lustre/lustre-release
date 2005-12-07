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

        CDEBUG(D_MGS, "db_handler\n");

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

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         &loghandle, NULL, logname);
        if (rc)
                GOTO(out_pop, rc);

        llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
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
       int i, num;
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
                if (strcmp(db->fsname, fsname) == 0)
                        return db;
        }
        return NULL;
}

#define INDEX_MAP_SIZE 4096

static struct system_db *mgs_new_db(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct system_db *db;
        
        OBD_ALLOC(db, sizeof(*db));
        if (!db) {
                CERROR("No memory for system_db.\n");
                return NULL;
        }
        OBD_ALLOC(db->index_map, INDEX_MAP_SIZE);
        if (!db->index_map) {
                CERROR("No memory for index_map.\n");
                OBD_FREE(db, sizeof(*db));
                return NULL;
        }
        strncpy(db->fsname, fsname, sizeof(db->fsname));
        //INIT_LIST_HEAD(&db->ost_infos);
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
        OBD_FREE(db, sizeof(*db));
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

static inline int name_create(char *prefix, char *suffix, char **newname)
{
        LASSERT(newname);
        OBD_ALLOC(*newname, strlen(prefix) + strlen(suffix) + 1);
        if (!*newname) 
                return -ENOMEM;
        sprintf(*newname, "%s%s", prefix, suffix);
        return 0;
}

static inline void name_destroy(char *newname)
{        
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
        db = mgs_new_db(obd, name);
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

int mgs_set_next_index(struct obd_device *obd, struct mgmt_target_info *mti)
{
        struct system_db *db;
        int rc = 0;

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db); 
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                return rc;
        }

        if (mti->mti_flags & LDD_F_SV_TYPE_OST)
                mti->mti_stripe_index = 
                        next_ost_index(db->index_map, INDEX_MAP_SIZE);
        else
                mti->mti_stripe_index = 1; /*FIXME*/

        make_sv_name(mti->mti_flags, mti->mti_stripe_index,
                     mti->mti_fsname, mti->mti_svname);

        CDEBUG(D_MGS, "Set new index for %s to %d\n", mti->mti_svname, 
               mti->mti_stripe_index);

        return rc;
}

static int mgs_backup_llog(struct obd_device *obd, char* fsname)
{
        struct file *filp, *bak_filp;
        struct lvfs_run_ctxt saved;
        char *logname, *buf;
        loff_t soff = 0 , doff = 0;
        int count = 4096, len;
        int rc = 0;

        OBD_ALLOC(logname, PATH_MAX);
        if (logname == NULL)
                return -ENOMEM;

        OBD_ALLOC(buf, count);
        if (!buf)
                GOTO(out , rc = -ENOMEM);

        len = snprintf(logname, PATH_MAX, "%s/%s.bak",
                       MOUNT_CONFIGS_DIR, fsname);

        if (len >= PATH_MAX - 1) {
                GOTO(out, -ENAMETOOLONG);
        } 

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
                
        bak_filp = l_filp_open(logname, O_RDWR|O_CREAT|O_TRUNC, 0660);
        if (IS_ERR(bak_filp)) {
                rc = PTR_ERR(bak_filp);
                CERROR("backup logfile open %s: %d\n", logname, rc);
                GOTO(pop, rc);
        }
        sprintf(logname, "%s/%s", MOUNT_CONFIGS_DIR, fsname);
        filp = l_filp_open(logname, O_RDONLY, 0);
        if (IS_ERR(filp)) {
                rc = PTR_ERR(filp);
                CERROR("logfile open %s: %d\n", logname, rc);
                GOTO(close1f, rc);
        }

        while ((rc = lustre_fread(filp, buf, count, &soff)) > 0) {
                rc = lustre_fwrite(bak_filp, buf, count, &doff);
                break;
        }

        filp_close(filp, 0);
close1f:
        filp_close(bak_filp, 0);
pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
out:
        if (buf)
                OBD_FREE(buf, count);
        OBD_FREE(logname, PATH_MAX);
        return rc;
}

static int mgs_do_record(struct obd_device *obd, struct llog_handle *llh,
                         struct lustre_cfg *lcfg)
{
        struct lvfs_run_ctxt   saved;
        struct llog_rec_hdr    rec;
        int buflen, rc;

        LASSERT(llh);
        LASSERT(llh->lgh_ctxt);        

        buflen = lustre_cfg_len(lcfg->lcfg_bufcount,
                                lcfg->lcfg_buflens);
        rec.lrh_len = llog_data_len(buflen);
        rec.lrh_type = OBD_CFG_REC;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* idx = -1 means append */
        rc = llog_write_rec(llh, &rec, NULL, 0, (void *)lcfg, -1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc) {
                CERROR("failed %d\n", rc);
        }
        LASSERT(!rc);
        return rc;
}

static int record_base(struct obd_device *obd, struct llog_handle *llh,
                     char *cfgname, lnet_nid_t nid, int cmd,
                     char *s1, char *s2, char *s3, char *s4)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg     *lcfg;
        int rc;
               
        CDEBUG(D_MGS, "lcfg %s %#x %s %s %s %s\n", cfgname,
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
        
        if (rc) {
                CERROR("error %d: lcfg %s %#x %s %s %s %s\n", rc, cfgname,
                       cmd, s1, s2, s3, s4); 
        }
        return(rc);
}


static inline int record_add_uuid(struct obd_device *obd, 
                                  struct llog_handle *llh, 
                                  uint64_t nid, char *uuid)
{
        return record_base(obd,llh,NULL,nid,LCFG_ADD_UUID,uuid,0,0,0);
}

static inline int record_attach(struct obd_device *obd, struct llog_handle *llh,
                                char *devname, char *type, char *uuid)
{
        return record_base(obd,llh,devname,0,LCFG_ATTACH,type,uuid,0,0);
}

static inline int record_setup(struct obd_device *obd, struct llog_handle *llh,
                               char *devname, 
                               char *s1, char *s2, char *s3, char *s4)
{
        return record_base(obd,llh,devname,0,LCFG_SETUP,s1,s2,s3,s4);
}

static int record_lov_setup(struct obd_device *obd, struct llog_handle *llh,
                            char *device_name, struct lov_desc *desc)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        CDEBUG(D_MGS, "lcfg %s lov_setup\n", device_name);

        lustre_cfg_bufs_reset(&bufs, device_name);
        lustre_cfg_bufs_set(&bufs, 1, desc, sizeof(*desc));
        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);

        rc = mgs_do_record(obd, llh, lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static inline int record_lov_add(struct obd_device *obd,
                                 struct llog_handle *llh,
                                 char *lov_name, char *ost_uuid,
                                 char *index, char *gen)
{
        return record_base(obd,llh,lov_name,0,LCFG_LOV_ADD_OBD,
                           ost_uuid,index,gen,0);
}                                  

static inline int record_mount_opt(struct obd_device *obd, 
                                   struct llog_handle *llh,
                                   char *profile, char *lov_name,
                                   char *mdc_name)
{
        return record_base(obd,llh,NULL,0,LCFG_MOUNTOPT,
                           profile,lov_name,mdc_name,0);
}                                  

static int record_start_log(struct obd_device *obd, 
                            struct llog_handle **llh, char *name)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct lvfs_run_ctxt saved;
        int rc = 0;
        
        if (*llh) {
                GOTO(out, rc = -EBUSY);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         llh, NULL, name);
        if (rc == 0)
                llog_init_handle(*llh, LLOG_F_IS_PLAIN, &cfg_uuid);
        else
                *llh = NULL;

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

out:
        if (rc) {
                CERROR("Can't start log %s: %d\n", name, rc);
        }
        RETURN(rc);
}

static int record_end_log(struct obd_device *obd, struct llog_handle **llh)
{
        struct lvfs_run_ctxt saved;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_close(*llh);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        *llh = NULL;
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
                             char *logname, char *lovname)
{
        struct llog_handle *llh = NULL;
        struct lov_desc *lovdesc;
        char *uuid;
        int rc = 0;
        ENTRY;

        /*
        #01 L attach   0:lov_mdsA  1:lov  2:71ccb_lov_mdsA_19f961a9e1
        #02 L lov_setup 0:lov_mdsA 1:(struct lov_desc)
              uuid=lov1_UUID, stripe count=1, size=1048576, offset=0, pattern=0
        */

        /* FIXME just make lov_setup accept empty desc (put uuid in buf 2) */
        OBD_ALLOC(lovdesc, sizeof(*lovdesc));
        if (lovdesc == NULL)
                RETURN(-ENOMEM);
        /* Use defaults here, will fix them later with LCFG_PARAM */
        lovdesc->ld_pattern = 0;
        lovdesc->ld_default_stripe_size = 1024*1024;
        lovdesc->ld_default_stripe_offset = 0;
        sprintf((char*)lovdesc->ld_uuid.uuid, "%s_UUID", lovname);
        /* can these be the same? */
        uuid = (char *)lovdesc->ld_uuid.uuid;

        rc = record_start_log(obd, &llh, logname);
        rc = record_attach(obd, llh, lovname, "lov", uuid);
        rc = record_lov_setup(obd, llh, lovname, lovdesc);
        
        RETURN(rc);
}

static int mgs_write_log_mdt(struct obd_device *obd,
                             struct mgmt_target_info *mti)
{
        struct system_db *db;
        struct llog_handle *llh = NULL;
        char *cliname, *mdcname, *lovname, *nodeuuid, *mdsuuid, *mdcuuid;
        int rc, first_log = 0;

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db); 
        if (rc || !db) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                return(-EINVAL);
        }

        CDEBUG(D_MGS, "writing new mdt %s\n", mti->mti_svname);

        name_create(mti->mti_fsname, "-mdtlov", &lovname);
        /* Append mdt info to mdt log */
        if (LOG_IS_EMPTY(db)) {
                /* First time for all logs for this fs */
                first_log++;
                rc = mgs_clear_log(obd, mti->mti_svname);
                rc = mgs_write_log_lov(obd, mti->mti_fsname, mti->mti_svname,
                                       lovname);
        } else {
                rc = mgs_backup_llog(obd, mti->mti_fsname);
                if (rc) {
                        CERROR("Can not backup llog, abort updating llog.\n");
                        return rc;
                }
        }
        name_create(mti->mti_svname, "_UUID", &mdsuuid);
        
        /* We added the lov+mount opt, maybe some osc's, now for the mds.
           We might add more ost's after this. Note that during the parsing
           of this log, this is when the mds will start. This was not 
           formerly part of the mds log, it was directly executed by lconf. */ 
        /*
        #09 L mount_option 0:  1:mdsA  2:lov_mdsA
        attach mds mdsA mdsA_UUID
        setup /dev/loop2 ldiskfs mdsA errors=remount-ro,user_xattr
        */
        rc = record_start_log(obd, &llh, mti->mti_svname);
        rc = record_mount_opt(obd, llh, mti->mti_svname, lovname, 0);
        rc = record_attach(obd, llh, mti->mti_svname, LUSTRE_MDS_NAME, mdsuuid);
        rc = record_setup(obd,llh,mti->mti_svname,
                          "dev"/*ignored*/,"type"/*ignored*/,
                          mti->mti_svname, 0/*options*/);
        rc = record_end_log(obd, &llh);

        /* Append mdt info to the client log */
        name_create(mti->mti_fsname, "-client", &cliname);
        name_destroy(lovname);
        name_create(mti->mti_fsname, "-clilov", &lovname);
        if (first_log) {
                /* Start client log */
                rc = mgs_clear_log(obd, cliname);
                rc = mgs_write_log_lov(obd, mti->mti_fsname, cliname, lovname);
        }

        /* Add the mdt info to the client */
        name_create(libcfs_nid2str(mti->mti_nid), "_UUID", &nodeuuid);
        name_create(mti->mti_svname, "-mdc", &mdcname);
        name_create(mdcname, "_UUID", &mdcuuid);
        
        /* 
        #09 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        #10 L attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f
        #11 L setup    0:MDC_uml1_mdsA_MNT_client  1:mdsA_UUID  2:uml1_UUID
        #12 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #13 L add_conn 0:MDC_uml1_mdsA_MNT_client  1:uml2_UUID
        #14 L mount_option 0:  1:client  2:lov1  3:MDC_uml1_mdsA_MNT_client
        */
        rc = record_start_log(obd, &llh, cliname);
        /* FIXME can we just use the nid as the node uuid, or do we really
           need the hostname? */
        rc = record_add_uuid(obd, llh, mti->mti_nid, nodeuuid);
        rc = record_attach(obd, llh, mdcname, LUSTRE_MDC_NAME, mdcuuid);
        rc = record_setup(obd,llh,mdcname,mdsuuid,nodeuuid,0,0);
        /* FIXME add uuid, add_conn for failover mdt's */
        rc = record_mount_opt(obd, llh, cliname, lovname, mdcname);
        rc = record_end_log(obd, &llh);

        name_destroy(mdcuuid);
        name_destroy(mdcname);
        name_destroy(nodeuuid);
        name_destroy(cliname);
        name_destroy(mdsuuid);
        name_destroy(lovname);
        return rc;
}

/* Add the ost info to the client/mdt lov */
static int mgs_write_log_osc(struct obd_device *obd, 
                             struct mgmt_target_info *mti,
                             int first_log,
                             char *logname, char *lovname, char *ostuuid)
{
        struct llog_handle *llh = NULL;
        char *nodeuuid, *oscname, *oscuuid;
        char index[5];
        int rc;

        if (first_log) {
                /* First osc, add the lov */
                rc = mgs_clear_log(obd, logname);
                rc = mgs_write_log_lov(obd, mti->mti_fsname, logname, lovname);
        }

        name_create(libcfs_nid2str(mti->mti_nid), "_UUID", &nodeuuid);
        name_create(mti->mti_svname, "-osc", &oscname);
        name_create(oscname, "_UUID", &oscuuid);

        /*
        #03 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        #04 L attach   0:OSC_uml1_ost1_MNT_client  1:osc  2:89070_lov1_a41dff51a
        #05 L setup    0:OSC_uml1_ost1_MNT_client  1:ost1_UUID  2:uml1_UUID
        #06 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #07 L add_conn 0:OSC_uml1_ost1_MNT_client  1:uml2_UUID
        #08 L lov_modify_tgts add 0:lov1  1:ost1_UUID  2:0  3:1
        */
        rc = record_start_log(obd, &llh, logname);
        rc = record_add_uuid(obd, llh, mti->mti_nid, nodeuuid);
        rc = record_attach(obd, llh, oscname, LUSTRE_OSC_NAME, oscuuid);
        rc = record_setup(obd, llh, oscname, ostuuid, nodeuuid, 0, 0);
        /* FIXME add uuid, add_conn for failover ost's */
        snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);
        rc = record_lov_add(obd,llh, lovname, ostuuid, index,"1"/*generation*/);
        rc = record_end_log(obd, &llh);
        
        name_destroy(oscuuid);
        name_destroy(oscname);
        name_destroy(nodeuuid);
        return rc;
}

static int mgs_write_log_ost(struct obd_device *obd,
                             struct mgmt_target_info *mti)
{
        struct system_db *db;
        struct llog_handle *llh = NULL;
        char *logname, *lovname, *ostuuid;
        int rc, first_log = 0;

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db); 
        if (rc || !db) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                return(-EINVAL);
        }
        if (LOG_IS_EMPTY(db)) 
                /* First time for all logs for this fs */
                first_log++;
        
        CDEBUG(D_MGS, "writing new ost %s\n", mti->mti_svname);

        /* The ost startup log */
        /*
        attach obdfilter ost1 ost1_UUID
        setup /dev/loop2 ldiskfs f|n errors=remount-ro,user_xattr
        */
        rc = record_start_log(obd, &llh, mti->mti_svname);
        name_create(mti->mti_svname, "_UUID", &ostuuid);
        rc = record_attach(obd, llh, mti->mti_svname,
                           "obdfilter"/*LUSTRE_OST_NAME*/, ostuuid);
        rc = record_setup(obd,llh,mti->mti_svname,
                          "dev"/*ignored*/,"type"/*ignored*/,
                          "f", 0/*options*/);
        rc = record_end_log(obd, &llh);
        
        /* We also have to update the other logs where this osc is part of 
           the lov */
        /* Append ost info to mdt log */
        // FIXME need real mdt name
        name_create(mti->mti_fsname, "-mdt0001", &logname);
        name_create(mti->mti_fsname, "-mdtlov", &lovname);
        mgs_write_log_osc(obd, mti, first_log, logname, lovname, ostuuid);
        name_destroy(lovname);
        name_destroy(logname);

        /* Append ost info to the client log */
        name_create(mti->mti_fsname, "-client", &logname);
        name_create(mti->mti_fsname, "-clilov", &lovname);
        mgs_write_log_osc(obd, mti, first_log, logname, lovname, ostuuid);
        name_destroy(lovname);
        name_destroy(logname);
        
        name_destroy(ostuuid);
        return rc;
}

int mgs_write_log_target(struct obd_device *obd,
                         struct mgmt_target_info *mti)
{
        int rc = -EINVAL;
        if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                rc = mgs_write_log_mdt(obd, mti);
        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                rc = mgs_write_log_ost(obd, mti);
        } else {
                CERROR("Unknown target type %#x, can't create log for %s\n",
                       mti->mti_flags, mti->mti_svname);
        }
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
