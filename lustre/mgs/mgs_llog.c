/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/mgs/mgs_llog.c
 *  Lustre Management Server (mgs) config llog creation
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Nathan Rutman <nathan@clusterfs.com>
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
#define D_MGS D_CONFIG|D_WARNING

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


static inline int sv_name2index(char *svname, unsigned long *idx)
{
        char *dash = strchr(svname, '-');
        if (!dash) {
                CERROR("Can't understand server name %s\n", svname);
                return(-EINVAL);
        }
        *idx = simple_strtoul(dash + 4, NULL, 16);
        return 0;
}


/******************** DB functions *********************/

/* from the (client) config log, figure out:
        1. which ost's/mdt's are configured (by index)
        2. what the last config step is
*/
/* FIXME is it better to have a separate db file, instead of parsing the info
   out of the client log? */
static int mgsdb_handler(struct llog_handle *llh, struct llog_rec_hdr *rec, 
                      void *data)
{
        struct fs_db *db = (struct fs_db *)data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        struct lustre_cfg *lcfg;
        unsigned long index;
        int rc = 0;
        ENTRY;

        if (rec->lrh_type != OBD_CFG_REC) {
                CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
                RETURN(-EINVAL);
        }

        rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
        if (rc) {
                CERROR("Insane cfg\n");
                RETURN(rc);
        }

        lcfg = (struct lustre_cfg *)cfg_buf;

        CDEBUG(D_INFO, "cmd %x %s %s\n", lcfg->lcfg_command, 
               lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));

        /* Figure out ost indicies */ 
        /* lov_modify_tgts add 0:lov1  1:ost1_UUID  2(index):0  3(gen):1 */
        if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD ||
            lcfg->lcfg_command == LCFG_LOV_DEL_OBD) {
                index = simple_strtoul(lustre_cfg_string(lcfg, 2),
                                       NULL, 10);
                CDEBUG(D_MGS, "OST index for %s is %lu (%s)\n",
                       lustre_cfg_string(lcfg, 1), index, 
                       lustre_cfg_string(lcfg, 2));
                set_bit(index, db->fd_ost_index_map);
        }
        
        /* Figure out mdt indicies */
        /* attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f */
        if ((lcfg->lcfg_command == LCFG_ATTACH) &&
            (strcmp(lustre_cfg_string(lcfg, 1), LUSTRE_MDC_NAME) == 0)) {
                rc = sv_name2index(lustre_cfg_string(lcfg, 0), &index);
                if (rc) {
                        CWARN("Unparsable MDC name %s, assuming index 0\n",
                              lustre_cfg_string(lcfg, 0));
                        index = 0;
                        rc = 0;
                }
                CDEBUG(D_MGS, "MDT index is %lu\n", index);
                set_bit(index, db->fd_mdt_index_map);
        }

        /* Keep track of the latest marker step */
        if (lcfg->lcfg_command == LCFG_MARKER) {
                struct cfg_marker *marker;
                marker = lustre_cfg_buf(lcfg, 1);
                db->fd_gen = max(db->fd_gen, marker->cm_step);
                CDEBUG(D_MGS, "marker %d %s\n", marker->cm_step, 
                       marker->cm_comment);
        }

        RETURN(rc);
}

static int mgs_get_db_from_llog(struct obd_device *obd, char *logname,
                                struct fs_db *db)
{
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        int rc, rc2;
        ENTRY;

        down(&db->fd_sem);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        
        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         &loghandle, NULL, logname);
        if (rc)
                GOTO(out_pop, rc);

        rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);

        if (llog_get_size(loghandle) <= 1)
                db->fd_flags |= FSDB_EMPTY;

        rc = llog_process(loghandle, mgsdb_handler, (void *)db, NULL);
        CDEBUG(D_MGS, "get_db = %d\n", rc);
out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;

out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        up(&db->fd_sem);

        RETURN(rc);
}

static int next_index(void *index_map, int map_len)
{
        int i;
        for (i = 0; i < map_len * 8; i++)
                 if (!test_bit(i, index_map)) {
                         return i;
                 }
        CERROR("max index %d exceeded.\n", i);
        return -1;
}

#if 0
static int count_osts(void *index_map, int map_len)
{
       int i, num;
       for (i = 0, num = 0; i < map_len * 8; i++)
               if (test_bit(i, index_map))
                        num++;
       return num;
}
#endif

static struct fs_db *mgs_find_db(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *db;
        struct list_head *tmp;

        list_for_each(tmp, &mgs->mgs_fs_db_list) {
                db = list_entry(tmp, struct fs_db, fd_list);
                if (strcmp(db->fd_name, fsname) == 0)
                        return db;
        }
        return NULL;
}

#define INDEX_MAP_SIZE 4096

/* caller must hold the mgs->mgs_fs_db_lock */
static struct fs_db *mgs_new_db(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *db;
        ENTRY;
        
        OBD_ALLOC(db, sizeof(*db));
        if (!db) 
                RETURN(NULL);

        OBD_ALLOC(db->fd_ost_index_map, INDEX_MAP_SIZE);
        OBD_ALLOC(db->fd_mdt_index_map, INDEX_MAP_SIZE);
        if (!db->fd_ost_index_map || !db->fd_mdt_index_map) {
                CERROR("No memory for index maps\n");
                GOTO(err, 0);
        }
        
        strncpy(db->fd_name, fsname, sizeof(db->fd_name));
        sema_init(&db->fd_sem, 1);
        list_add(&db->fd_list, &mgs->mgs_fs_db_list);

        RETURN(db);
err:
        if (db->fd_ost_index_map) 
                OBD_FREE(db->fd_ost_index_map, INDEX_MAP_SIZE);
        if (db->fd_mdt_index_map) 
                OBD_FREE(db->fd_mdt_index_map, INDEX_MAP_SIZE);
        OBD_FREE(db, sizeof(*db));
        RETURN(NULL);
}

static void mgs_free_db(struct fs_db *db)
{
        /* wait for anyone with the sem */
        down(&db->fd_sem);
        list_del(&db->fd_list);
        OBD_FREE(db->fd_ost_index_map, INDEX_MAP_SIZE);
        OBD_FREE(db->fd_mdt_index_map, INDEX_MAP_SIZE);
        OBD_FREE(db, sizeof(*db));
}

int mgs_init_db_list(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        spin_lock_init(&mgs->mgs_fs_db_lock);
        INIT_LIST_HEAD(&mgs->mgs_fs_db_list);
        return 0;
}

int mgs_cleanup_db_list(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *db;
        struct list_head *tmp, *tmp2;
        spin_lock(&mgs->mgs_fs_db_lock);
        list_for_each_safe(tmp, tmp2, &mgs->mgs_fs_db_list) {
                db = list_entry(tmp, struct fs_db, fd_list);
                mgs_free_db(db);
        }
        spin_unlock(&mgs->mgs_fs_db_lock);
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
                               struct fs_db **dbh)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *db;
        char *cliname;
        int rc = 0;

        spin_lock(&mgs->mgs_fs_db_lock);
        db = mgs_find_db(obd, name);
        if (db) {
                spin_unlock(&mgs->mgs_fs_db_lock);
                *dbh = db;
                return 0;
        }

        CDEBUG(D_MGS, "Creating new db\n");
        db = mgs_new_db(obd, name);
        spin_unlock(&mgs->mgs_fs_db_lock);
        if (!db) 
                return -ENOMEM;

        /* populate the db from the client llog */
        name_create(name, "-client", &cliname);
        rc = mgs_get_db_from_llog(obd, cliname, db);
        name_destroy(cliname);
        if (rc) {
                CERROR("Can't get db from llog %d\n", rc);
                mgs_free_db(db);
                return rc;
        }

        *dbh = db;
        
        return 0;
}

/* 1 = index in use
   0 = index unused 
   -1= empty client log */
int mgs_check_index(struct obd_device *obd, struct mgs_target_info *mti)
{
        struct fs_db *db;
        void *imap;
        int rc = 0;
        ENTRY;

        LASSERT(!(mti->mti_flags & LDD_F_NEED_INDEX));

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db); 
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                RETURN(rc);
        }

        if (db->fd_flags & FSDB_EMPTY) 
                RETURN(-1);

        if (mti->mti_flags & LDD_F_SV_TYPE_OST) 
                imap = db->fd_ost_index_map;
        else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) 
                imap = db->fd_mdt_index_map;
        else
                RETURN(-EINVAL);

        if (test_bit(mti->mti_stripe_index, imap)) 
                RETURN(1);
        RETURN(0);
}


int mgs_set_index(struct obd_device *obd, struct mgs_target_info *mti)
{
        struct fs_db *db;
        void *imap;
        int rc = 0;
        ENTRY;

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db); 
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                RETURN(rc);
        }

        if (mti->mti_flags & LDD_F_SV_TYPE_OST) 
                imap = db->fd_ost_index_map;
        else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) 
                imap = db->fd_mdt_index_map;
        else
                RETURN(-EINVAL);

        if (mti->mti_flags & LDD_F_NEED_INDEX) {
                rc = next_index(imap, INDEX_MAP_SIZE);
                if (rc == -1)
                        RETURN(-ERANGE);
                mti->mti_stripe_index = rc;
        }

        /* Remove after CMD */
        if ((mti->mti_flags & LDD_F_SV_TYPE_MDT) && 
            (mti->mti_stripe_index > 0)) {
                LCONSOLE_ERROR("MDT index must = 0 (until Clustered MetaData "
                               "feature is ready.)\n");
                mti->mti_stripe_index = 0;
        }

        if (mti->mti_stripe_index >= INDEX_MAP_SIZE * 8) {
                LCONSOLE_ERROR("Server %s requested index %d, but the"
                               "max index is %d.\n", 
                               mti->mti_svname, mti->mti_stripe_index,
                               INDEX_MAP_SIZE * 8);
                RETURN(-ERANGE);
        }

        if (test_bit(mti->mti_stripe_index, imap)) {
                LCONSOLE_ERROR("Server %s requested index %d, but that "
                               "index is already in use\n",
                               mti->mti_svname, mti->mti_stripe_index);
                RETURN(-EADDRINUSE);
        }
         
        set_bit(mti->mti_stripe_index, imap);
        sv_make_name(mti->mti_flags, mti->mti_stripe_index,
                     mti->mti_fsname, mti->mti_svname);

        CDEBUG(D_MGS, "Set new index for %s to %d\n", mti->mti_svname, 
               mti->mti_stripe_index);

        RETURN(0);
}
                           
/******************** config log recording functions *********************/

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

static inline int record_add_conn(struct obd_device *obd, 
                                  struct llog_handle *llh,
                                  char *devname,
                                  char *uuid)
{
        return record_base(obd,llh,devname,0,LCFG_ADD_CONN,uuid,0,0,0);
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
                            char *devname, struct lov_desc *desc)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        lustre_cfg_bufs_reset(&bufs, devname);
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

static int record_marker(struct obd_device *obd, struct llog_handle *llh,
                         struct fs_db *db, __u32 flags,
                         char *svname, char *comment)
{
        struct cfg_marker marker;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        CDEBUG(D_MGS, "lcfg marker\n");

        if (flags & CM_START) 
                db->fd_gen++;
        marker.cm_step = db->fd_gen;
        marker.cm_flags = flags;
        strncpy(marker.cm_svname, svname, sizeof(marker.cm_svname)); 
        strncpy(marker.cm_comment, comment, sizeof(marker.cm_comment)); 
        lustre_cfg_bufs_reset(&bufs, NULL);
        lustre_cfg_bufs_set(&bufs, 1, &marker, sizeof(marker));
        lcfg = lustre_cfg_new(LCFG_MARKER, &bufs);

        rc = mgs_do_record(obd, llh, lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static inline int record_param(struct obd_device *obd, struct llog_handle *llh,
                               char *devname, 
                               char *s1, char *s2, char *s3, char *s4)
{
        return record_base(obd,llh,devname,0,LCFG_PARAM,s1,s2,s3,s4);
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
        *llh = NULL;
        
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

static int mgs_log_is_empty(struct obd_device *obd, char *name)
{
        struct lvfs_run_ctxt saved;
        struct llog_handle *llh;
        int rc = 0;

        /* FIXME cache the empty state in the db */

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT),
                         &llh, NULL, name);
        if (rc == 0) {
                llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_get_size(llh);
                llog_close(llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* header is record 1 */
        return(rc <= 1);
}

/******************** config "macros" *********************/

/* lov is the first thing in the mdt and client logs */
static int mgs_write_log_lov(struct obd_device *obd, struct fs_db *db, 
                             struct mgs_target_info *mti,
                             char *logname, char *lovname)
{
        struct llog_handle *llh = NULL;
        struct lov_desc *lovdesc;
        char *uuid;
        int rc = 0;
        ENTRY;

        CDEBUG(D_MGS, "Writing log %s\n", logname);

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
        lovdesc->ld_magic = LOV_DESC_MAGIC;
        lovdesc->ld_tgt_count = 0;
        lovdesc->ld_default_stripe_count = mti->mti_stripe_count;
        lovdesc->ld_pattern = mti->mti_stripe_pattern;
        lovdesc->ld_default_stripe_size = mti->mti_stripe_size;
        lovdesc->ld_default_stripe_offset = mti->mti_stripe_offset;
        sprintf((char*)lovdesc->ld_uuid.uuid, "%s_UUID", lovname);
        /* can these be the same? */
        uuid = (char *)lovdesc->ld_uuid.uuid;

        /* This should always be the first entry in a log.
        rc = mgs_clear_log(obd, logname); */
        rc = record_start_log(obd, &llh, logname);
        rc = record_marker(obd, llh, db, CM_START, mti->mti_svname,"lov setup"); 
        rc = record_attach(obd, llh, lovname, "lov", uuid);
        rc = record_lov_setup(obd, llh, lovname, lovdesc);
        rc = record_marker(obd, llh, db, CM_END, mti->mti_svname, "lov setup"); 
        rc = record_end_log(obd, &llh);
        
        OBD_FREE(lovdesc, sizeof(*lovdesc));
        RETURN(rc);
}

static int mgs_write_log_mdt(struct obd_device *obd, struct fs_db *db,
                             struct mgs_target_info *mti)
{
        struct llog_handle *llh = NULL;
        char *cliname, *mdcname, *lovname, *nodeuuid, *mdcuuid;
        char *s1, *s2, *s3, *s4, *s5;
        lnet_nid_t nid;
        int rc, i, first_log = 0;
        ENTRY;

        CDEBUG(D_MGS, "writing new mdt %s\n", mti->mti_svname);

        if (*mti->mti_uuid == 0) {
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
                name_create(mti->mti_fsname, "-mdtlov", &lovname);
        } else {
                /* We're starting with an old uuid.  Assume old name for lov
                   as well. */
                /* FIXME parse mds name out of uuid */
                name_create("lov", "_mdsA", &lovname);
        }

        /* Append mdt info to mdt log */
        if (mgs_log_is_empty(obd, mti->mti_svname)) {
                /* This is the first time for all logs for this fs, 
                   since any ost should have already started the mdt log. */
                first_log++;
                rc = mgs_write_log_lov(obd, db, mti, mti->mti_svname,
                                       lovname);
        } 
        /* else there's already some ost entries in the mdt log. */

        /* We added the lov, maybe some osc's, now for the mdt.
           We might add more ost's after this. Note that during the parsing
           of this log, this is when the mdt will start. (This was not 
           formerly part of the old mds log, it was directly executed by
           lconf.) */ 
        /*
        #09 L mount_option 0:  1:mdsA  2:lov_mdsA
        attach mds mdsA mdsA_UUID
        setup /dev/loop2 ldiskfs mdsA errors=remount-ro,user_xattr
        */
        rc = record_start_log(obd, &llh, mti->mti_svname);
        rc = record_marker(obd, llh, db, CM_START, mti->mti_svname, "add mdt"); 

        /* FIXME this should just be added via a MGS ioctl 
           OBD_IOC_LOV_SETSTRIPE / LL_IOC_LOV_SETSTRIPE */
        if (!first_log) {
                /* Fix lov settings if they were set by something other
                   than the MDT */
                OBD_ALLOC(s1, 256);
                if (s1) {
                        s2 = sprintf(s1, "default_stripe_size="LPU64,
                                     mti->mti_stripe_size) + s1 + 1;
                        s3 = sprintf(s2, "default_stripe_count=%u",
                                     mti->mti_stripe_count) + s2 + 1;
                        s4 = sprintf(s3, "default_stripe_offset="LPU64,
                                     mti->mti_stripe_offset) + s3 + 1;
                        s5 =  sprintf(s4, "default_stripe_pattern=%u",
                                mti->mti_stripe_pattern) + s4 + 1;
                        LASSERT(s5 - s1 < 256);
                        record_param(obd, llh, lovname, s1, s2, s3, s4);
                }
        }
        
        rc = record_mount_opt(obd, llh, mti->mti_svname, lovname, 0);
        rc = record_attach(obd, llh, mti->mti_svname, LUSTRE_MDS_NAME, 
                           mti->mti_uuid);
        rc = record_setup(obd, llh, mti->mti_svname,
                          "dev"/*ignored*/, "type"/*ignored*/,
                          mti->mti_svname, 0/*options*/);
        rc = record_marker(obd, llh, db, CM_END, mti->mti_svname, "add mdt"); 
        rc = record_end_log(obd, &llh);

        if (mti->mti_flags & LDD_F_UPGRADE14) 
                /* If we're upgrading, the client log is done. */
                GOTO(out_nocli, rc);

        /* Append the mdt info to the client log */
        name_create(mti->mti_fsname, "-client", &cliname);
        name_destroy(lovname);
        name_create(mti->mti_fsname, "-clilov", &lovname);
        if (first_log) {
                /* Start client log */
                rc = mgs_write_log_lov(obd, db, mti, cliname, lovname);
        }

        name_create(libcfs_nid2str(mti->mti_nids[0]), /*"_UUID"*/"", &nodeuuid);
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
        rc = record_marker(obd, llh, db, CM_START, mti->mti_svname, "add mdc");
        if (!first_log && s1) {
                /* Record new lov settings */
                record_param(obd, llh, lovname, s1, s2, s3, s4);
                OBD_FREE(s1, 256);
        }
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s\n", libcfs_nid2str(mti->mti_nids[i]));
                rc = record_add_uuid(obd, llh, mti->mti_nids[i], nodeuuid);
        }
        rc = record_attach(obd, llh, mdcname, LUSTRE_MDC_NAME, mdcuuid);
        rc = record_setup(obd, llh, mdcname, mti->mti_uuid,nodeuuid, 0, 0);
        for (i = 0; i < mti->mti_failnid_count; i++) {
                nid = mti->mti_failnids[i];
                CDEBUG(D_MGS, "add failover nid %s\n", libcfs_nid2str(nid));
                rc = record_add_uuid(obd, llh, nid, libcfs_nid2str(nid));
                rc = record_add_conn(obd, llh, mdcname, libcfs_nid2str(nid));
        }
        rc = record_mount_opt(obd, llh, cliname, lovname, mdcname);
        rc = record_marker(obd, llh, db, CM_END, mti->mti_svname, "add mdc"); 
        rc = record_end_log(obd, &llh);

        name_destroy(mdcuuid);
        name_destroy(mdcname);
        name_destroy(nodeuuid);
        name_destroy(cliname);
out_nocli:
        name_destroy(lovname);
        RETURN(rc);
}

/* Add the ost info to the client/mdt lov */
static int mgs_write_log_osc(struct obd_device *obd, struct fs_db *db,
                             struct mgs_target_info *mti,
                             char *logname, char *lovname)
{
        struct llog_handle *llh = NULL;
        char *nodeuuid, *oscname, *oscuuid, *lovuuid;
        char index[5];
        lnet_nid_t nid;
        int i, rc;

        if (mgs_log_is_empty(obd, logname)) {
                /* The first time an osc is added, setup the lov */
                rc = mgs_write_log_lov(obd, db, mti, logname, lovname);
        }
  
        CDEBUG(D_MGS, "adding osc for %s to log %s\n",
               mti->mti_svname, logname);

        name_create(libcfs_nid2str(mti->mti_nids[0]), /*"_UUID"*/"", &nodeuuid);
        name_create(mti->mti_svname, "-osc", &oscname);
        name_create(oscname, "_UUID", &oscuuid);
        name_create(lovname, "_UUID", &lovuuid);

        /*
        #03 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        #04 L attach   0:OSC_uml1_ost1_MNT_client  1:osc  2:89070_lov1_a41dff51a
        #05 L setup    0:OSC_uml1_ost1_MNT_client  1:ost1_UUID  2:uml1_UUID
        #06 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #07 L add_conn 0:OSC_uml1_ost1_MNT_client  1:uml2_UUID
        #08 L lov_modify_tgts add 0:lov1  1:ost1_UUID  2(index):0  3(gen):1
        */
        rc = record_start_log(obd, &llh, logname);
        rc = record_marker(obd, llh, db, CM_START, mti->mti_svname, "add osc"); 
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s\n", libcfs_nid2str(mti->mti_nids[i]));
                rc = record_add_uuid(obd, llh, mti->mti_nids[i], nodeuuid);
        }
        rc = record_attach(obd, llh, oscname, LUSTRE_OSC_NAME, lovuuid);
        rc = record_setup(obd, llh, oscname, mti->mti_uuid, nodeuuid, 0, 0);
        for (i = 0; i < mti->mti_failnid_count; i++) {
                nid = mti->mti_failnids[i];
                CDEBUG(D_MGS, "add failover nid %s\n", libcfs_nid2str(nid));
                rc = record_add_uuid(obd, llh, nid, libcfs_nid2str(nid));
                rc = record_add_conn(obd, llh, oscname, libcfs_nid2str(nid));
        }
        snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);
        rc = record_lov_add(obd, llh, lovname, mti->mti_uuid, index, "1");
        rc = record_marker(obd, llh, db, CM_END, mti->mti_svname, "add osc"); 
        rc = record_end_log(obd, &llh);
        
        name_destroy(lovuuid);
        name_destroy(oscuuid);
        name_destroy(oscname);
        name_destroy(nodeuuid);
        return rc;
}

static int mgs_write_log_ost(struct obd_device *obd, struct fs_db *db,
                             struct mgs_target_info *mti)
{
        struct llog_handle *llh = NULL;
        char *logname, *lovname;
        int rc;
        ENTRY;
        
        CDEBUG(D_MGS, "writing new ost %s\n", mti->mti_svname);

        /* The ost startup log */

        /* If the ost log already exists, that means that someone reformatted
           the ost and it called target_add again.
           FIXME check and warn here, maybe inc config ver #?  Or abort, 
           and claim there's already a server with that name?  Maybe need 
           another flag to say it's okay to rewrite. 
           Heck, what do we do about the client and mds logs? We better
           abort. */
        if (!mgs_log_is_empty(obd, mti->mti_svname)) {
                LCONSOLE_ERROR("The config log for %s already exists, yet the "
                               "server claims it never registered.  It may have"
                               " been reformatted, or the index changed. This "
                               "must be resolved before this server can be "
                               "added.\n", mti->mti_svname);
                return -EALREADY;
        }
        /*
        attach obdfilter ost1 ost1_UUID
        setup /dev/loop2 ldiskfs f|n errors=remount-ro,user_xattr
        */
        rc = record_start_log(obd, &llh, mti->mti_svname);
        rc = record_marker(obd, llh, db, CM_START, mti->mti_svname, "add ost"); 
        if (*mti->mti_uuid == 0) 
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
        rc = record_attach(obd, llh, mti->mti_svname,
                           "obdfilter"/*LUSTRE_OST_NAME*/, mti->mti_uuid);
        rc = record_setup(obd,llh,mti->mti_svname,
                          "dev"/*ignored*/,"type"/*ignored*/,
                          "f", 0/*options*/);
        rc = record_marker(obd, llh, db, CM_END, mti->mti_svname, "add ost"); 
        rc = record_end_log(obd, &llh);
        
        if (mti->mti_flags & LDD_F_UPGRADE14) 
                /* If we're upgrading, the client log is done. */
                RETURN(rc);

        /* We also have to update the other logs where this osc is part of 
           the lov */
        /* Append ost info to mdt log */
        // FIXME need real mdt name -- but MDT may not have registered yet!
        // FIXME add to all mdt logs for CMD
        name_create(mti->mti_fsname, "-MDT0000", &logname);
        name_create(mti->mti_fsname, "-mdtlov", &lovname);
        mgs_write_log_osc(obd, db, mti, logname, lovname);
        name_destroy(lovname);
        name_destroy(logname);

        /* Append ost info to the client log */
        name_create(mti->mti_fsname, "-client", &logname);
        name_create(mti->mti_fsname, "-clilov", &lovname);
        mgs_write_log_osc(obd, db, mti, logname, lovname);
        name_destroy(lovname);
        name_destroy(logname);
        
        RETURN(rc);
}

int mgs_write_log_target(struct obd_device *obd,
                         struct mgs_target_info *mti)
{
        struct fs_db *db;
        int rc = -EINVAL;

        /* set/check the new target index */
        rc = mgs_set_index(obd, mti);
        if (rc) {
                CERROR("Can't get index (%d)\n", rc);
                return rc;
        }

        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db); 
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                return rc;
        }

        down(&db->fd_sem);
        if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                rc = mgs_write_log_mdt(obd, db, mti);
        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                rc = mgs_write_log_ost(obd, db, mti);
        } else {
                CERROR("Unknown target type %#x, can't create log for %s\n",
                       mti->mti_flags, mti->mti_svname);
        }
        up(&db->fd_sem);
        
        if (!rc) 
                db->fd_flags &= ~FSDB_EMPTY;

        return rc;
}


/* COMPAT_146 */
/***************** upgrade pre-mountconf logs to mountconf *****************/

int mgs_upgrade_logs_14(struct obd_device *obd, struct fs_db *db, 
                        struct mgs_target_info *mti)
{
        int rc = 0;
        ENTRY;

        CDEBUG(D_MGS, "Upgrading old logs for %s\n", mti->mti_fsname);

        /* If we get here, we know: 
                the client log fsname-client exists
                the logs have not been updated
           so
        1. parse the old client log (client log name?) to find out UUIDs for
           all servers
        2. regen all ost logs: servers will get new
           name based on index, but will keep their old uuids.
        3. append mdt startup to the end of the mdt log
        4. append marker to old client log signifying we did the upgrade
        ?  translate mds/client logs to new names?
                  2 UP mdt MDS MDS_uuid 3
                  3 UP lov lov_mdsA 47d06_lov_mdsA_61f31f85bc 4
                  4 UP osc OSC_uml1_ost1_mdsA 47d06_lov_mdsA_61f31f85bc 4
                  5 UP osc OSC_uml1_ost2_mdsA 47d06_lov_mdsA_61f31f85bc 4
                  6 UP mds lustre-MDT0000 mdsA_UUID 3
                to
        ?  update server uuids?
        */

        /* FIXME hardcoded for proof-of-concept. Really, we have to parse the
           old logs to find osts, lov & mdc for client mountopt.  */

        if (!(mti->mti_flags & LDD_F_SV_TYPE_MDT)) {
                CERROR("MDT first\n");
                RETURN(-EINVAL);
        }
                
        if (1) 
        {
                CDEBUG(D_MGS, "Upgrade MDT\n");
                /* Need to set the mdsuuid first */
                mti->mti_stripe_index = 0;
                sv_make_name(mti->mti_flags, mti->mti_stripe_index,
                             mti->mti_fsname, mti->mti_svname);
                sprintf(mti->mti_uuid, "mdsA_UUID");
                if (mgs_log_is_empty(obd, mti->mti_svname)) {
                        CERROR("The MDT log %s is missing.\n", mti->mti_svname);
                        RETURN(-ENOENT);
                }
                /* FIXME Old logs already have an old mount opt 
                   which we should drop */
                rc = mgs_write_log_mdt(obd, db, mti);
        }

        {
                /* Write the ost logs */
                struct mgs_target_info omti;
                CDEBUG(D_MGS, "Upgrade OST\n");

                /* these indicies were already marked by mgs_db_handler */
                omti = *mti;
                omti.mti_flags |= LDD_F_SV_TYPE_OST;
                omti.mti_flags &= ~(LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_MGS);
                omti.mti_stripe_index = 0;
                sv_make_name(omti.mti_flags, omti.mti_stripe_index,
                             omti.mti_fsname, omti.mti_svname);
                sprintf(omti.mti_uuid, "ost1_UUID");
                if (!mgs_log_is_empty(obd, omti.mti_svname)) {
                        CERROR("The OST log %s already exists.\n",
                               omti.mti_svname);
                } else {
                        rc = mgs_write_log_ost(obd, db, &omti);
                }

                omti.mti_stripe_index = 1;
                sv_make_name(omti.mti_flags, omti.mti_stripe_index,
                             omti.mti_fsname, omti.mti_svname);
                sprintf(omti.mti_uuid, "ost2_UUID");
                if (!mgs_log_is_empty(obd, omti.mti_svname)) {
                        CERROR("The OST log %s already exists.\n",
                               omti.mti_svname);
                } else {
                        rc = mgs_write_log_ost(obd, db, &omti);
                }
        }

        {
                struct llog_handle *llh = NULL;
                char *cliname;
                CDEBUG(D_MGS, "Upgrade client\n");

                name_create(mti->mti_fsname, "-client", &cliname);

                /* Mark the client log so we know we updated (fd_gen == 1) */
                rc = record_start_log(obd, &llh, cliname);
                rc = record_marker(obd, llh, db, CM_START, "client",
                                   "upgrade from 1.4"); 
                /* FIXME find the old lovname and mdcname */
                /* old: mount_option 0:  1:client  2:lov1  3:MDC_uml1_mdsA_MNT_client */
                /* new: mount_option 0:  1:lustre-client  2:lustre-clilov  3:lustre-MDT0000-mdc */
                rc = record_mount_opt(obd, llh, cliname, "lov1", 
                                      "MDC_uml1_mdsA_MNT_client");
                rc = record_marker(obd, llh, db, CM_END, "client", 
                                   "upgrade to 1.6"); 
                rc = record_end_log(obd, &llh);
                name_destroy(cliname);
        }
        
        RETURN(rc);
}

/* Make newly-connecting upgraded servers happy. */ 
int mgs_upgrade_sv_14(struct obd_device *obd, struct mgs_target_info *mti)
{
        struct fs_db *db;
        int rc = 0;
        ENTRY;
        
        rc = mgs_find_or_make_db(obd, mti->mti_fsname, &db);
        if (rc) {
                LCONSOLE_ERROR("The 1.4 log for fs %s in %s is unreadable, " 
                               "I can't upgrade it.\n",
                               mti->mti_fsname, MOUNT_CONFIGS_DIR);
                RETURN(-ENOENT);
        }

        if (db->fd_gen == 0) {
                /* There were no markers in the client log, meaning we have 
                   not updated the logs for this fs */
                rc = mgs_upgrade_logs_14(obd, db, mti);
                if (rc) 
                        RETURN(rc);
        }

        RETURN(rc);
}
/* end COMPAT_146 */

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

static int dentry_readdir(struct obd_device *obd, struct dentry *dir,
                          struct vfsmount *inmnt, 
                          struct list_head *dentry_list){
        /* see mds_cleanup_pending */
        struct lvfs_run_ctxt saved;
        struct file *file;
        struct dentry *dentry;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;
                                                                                
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        dentry = dget(dir);
        if (IS_ERR(dentry))
                GOTO(out_pop, rc = PTR_ERR(dentry));
        mnt = mntget(inmnt);
        if (IS_ERR(mnt)) {
                l_dput(dentry);
                GOTO(out_pop, rc = PTR_ERR(mnt));
        }

        file = dentry_open(dentry, mnt, O_RDONLY);
        if (IS_ERR(file))
                /* dentry_open_it() drops the dentry, mnt refs */
                GOTO(out_pop, rc = PTR_ERR(file));
                                                                                
        INIT_LIST_HEAD(dentry_list);
        rc = l_readdir(file, dentry_list);
        filp_close(file, 0);
        /*  filp_close->fput() drops the dentry, mnt refs */
                                                                                
out_pop:
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

/* erase all logs for the given fs */
int mgs_erase_logs(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        static struct fs_db *db;
        struct list_head dentry_list;
        struct l_linux_dirent *dirent, *n;
        int rc, len = strlen(fsname);
        ENTRY;
        
        /* Find all the logs in the CONFIGS directory */
        rc = dentry_readdir(obd, mgs->mgs_configs_dir,
                             mgs->mgs_vfsmnt, &dentry_list);
        if (rc) {
                CERROR("Can't read %s dir\n", MOUNT_CONFIGS_DIR);
                RETURN(rc);
        }
                                                                                
        /* Delete the fs db */
        spin_lock(&mgs->mgs_fs_db_lock);
        db = mgs_find_db(obd, fsname);
        if (db) 
                mgs_free_db(db);
        spin_unlock(&mgs->mgs_fs_db_lock);

        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                list_del(&dirent->lld_list);
                if (strncmp(fsname, dirent->lld_name, len) == 0) {
                        CDEBUG(D_MGS, "Removing log %s\n", dirent->lld_name);
                        mgs_clear_log(obd, dirent->lld_name);
                }
                OBD_FREE(dirent, sizeof(*dirent));
        }
        
        RETURN(rc);
}


#if 0
/******************** unused *********************/
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

/* from mdt_iocontrol */
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

#endif
