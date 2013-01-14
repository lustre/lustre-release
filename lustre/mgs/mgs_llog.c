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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/mgs/mgs_llog.c
 *
 * Lustre Management Server (mgs) config llog creation
 *
 * Author: Nathan Rutman <nathan@clusterfs.com>
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_MGS
#define D_MGS D_CONFIG

#ifdef __KERNEL__
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#endif

#include <obd.h>
#include <obd_lov.h>
#include <obd_class.h>
#include <lustre_log.h>
#include <obd_ost.h>
#include <libcfs/list.h>
#include <linux/lvfs.h>
#include <lustre_fsfilt.h>
#include <lustre_disk.h>
#include <lustre_param.h>
#include "mgs_internal.h"

/******************** Class functions *********************/

/* Caller must list_del and OBD_FREE each dentry from the list */
int class_dentry_readdir(struct obd_device *obd, struct dentry *dir,
                         struct vfsmount *inmnt,
                         struct list_head *dentry_list)
{
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

        file = ll_dentry_open(dentry, mnt, O_RDONLY, current_cred());
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

/******************** DB functions *********************/

static inline int name_create(char **newname, char *prefix, char *suffix)
{
        LASSERT(newname);
        OBD_ALLOC(*newname, strlen(prefix) + strlen(suffix) + 1);
        if (!*newname)
                return -ENOMEM;
        sprintf(*newname, "%s%s", prefix, suffix);
        return 0;
}

static inline void name_destroy(char **name)
{
        if (*name)
                OBD_FREE(*name, strlen(*name) + 1);
        *name = NULL;
}

/* from the (client) config log, figure out:
        1. which ost's/mdt's are configured (by index)
        2. what the last config step is
        3. COMPAT_146 lov name
        4. COMPAT_146 mdt lov name
        5. COMPAT_146 mdc name
*/
/* It might be better to have a separate db file, instead of parsing the info
   out of the client log.  This is slow and potentially error-prone. */
static int mgs_fsdb_handler(struct llog_handle *llh, struct llog_rec_hdr *rec,
                            void *data)
{
        struct fs_db *fsdb = (struct fs_db *)data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        struct lustre_cfg *lcfg;
        __u32 index;
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
                CDEBUG(D_MGS, "OST index for %s is %u (%s)\n",
                       lustre_cfg_string(lcfg, 1), index,
                       lustre_cfg_string(lcfg, 2));
                set_bit(index, fsdb->fsdb_ost_index_map);
        }

        /* Figure out mdt indicies */
        /* attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f */
        if ((lcfg->lcfg_command == LCFG_ATTACH) &&
            (strcmp(lustre_cfg_string(lcfg, 1), LUSTRE_MDC_NAME) == 0)) {
                rc = server_name2index(lustre_cfg_string(lcfg, 0),
                                       &index, NULL);
                if (rc != LDD_F_SV_TYPE_MDT) {
                        CWARN("Unparsable MDC name %s, assuming index 0\n",
                              lustre_cfg_string(lcfg, 0));
                        index = 0;
                }
                rc = 0;
                CDEBUG(D_MGS, "MDT index is %u\n", index);
                set_bit(index, fsdb->fsdb_mdt_index_map);
        }

        /* COMPAT_146 */
        /* figure out the old LOV name. fsdb_gen = 0 means old log */
        /* #01 L attach 0:lov_mdsA 1:lov 2:cdbe9_lov_mdsA_dc8cf7f3bb */
        if ((fsdb->fsdb_gen == 0) && (lcfg->lcfg_command == LCFG_ATTACH) &&
            (strcmp(lustre_cfg_string(lcfg, 1), LUSTRE_LOV_NAME) == 0)) {
                fsdb->fsdb_flags |= FSDB_OLDLOG14;
                name_destroy(&fsdb->fsdb_clilov);
                rc = name_create(&fsdb->fsdb_clilov,
                                 lustre_cfg_string(lcfg, 0), "");
                if (rc)
                        RETURN(rc);
                CDEBUG(D_MGS, "client lov name is %s\n", fsdb->fsdb_clilov);
        }

        /* figure out the old MDT lov name from the MDT uuid */
        if ((fsdb->fsdb_gen == 0) && (lcfg->lcfg_command == LCFG_SETUP) &&
            (strncmp(lustre_cfg_string(lcfg, 0), "MDC_", 4) == 0)) {
                char *ptr;
                fsdb->fsdb_flags |= FSDB_OLDLOG14;
                ptr = strstr(lustre_cfg_string(lcfg, 1), "_UUID");
                if (!ptr) {
                        CERROR("Can't parse MDT uuid %s\n",
                               lustre_cfg_string(lcfg, 1));
                        RETURN(-EINVAL);
                }
                *ptr = '\0';
                name_destroy(&fsdb->fsdb_mdtlov);
                rc = name_create(&fsdb->fsdb_mdtlov,
                                 "lov_", lustre_cfg_string(lcfg, 1));
                if (rc)
                        RETURN(rc);
                name_destroy(&fsdb->fsdb_mdc);
                rc = name_create(&fsdb->fsdb_mdc,
                                 lustre_cfg_string(lcfg, 0), "");
                if (rc)
                        RETURN(rc);
                CDEBUG(D_MGS, "MDT lov name is %s\n", fsdb->fsdb_mdtlov);
        }
        /* end COMPAT_146 */

        /* Keep track of the latest marker step */
        if (lcfg->lcfg_command == LCFG_MARKER) {
                struct cfg_marker *marker;
                marker = lustre_cfg_buf(lcfg, 1);
                fsdb->fsdb_gen = max(fsdb->fsdb_gen, marker->cm_step);
        }

        RETURN(rc);
}

static int mgs_get_fsdb_from_llog(struct obd_device *obd, struct fs_db *fsdb)
{
        char *logname;
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        int rc, rc2;
        ENTRY;

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
        name_create(&logname, fsdb->fsdb_name, "-client");
        down(&fsdb->fsdb_sem);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(ctxt, &loghandle, NULL, logname);
        if (rc)
                GOTO(out_pop, rc);

        rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);

        if (llog_get_size(loghandle) <= 1)
                fsdb->fsdb_flags |= FSDB_LOG_EMPTY;

        rc = llog_process(loghandle, mgs_fsdb_handler, (void *)fsdb, NULL);
        CDEBUG(D_INFO, "get_db = %d\n", rc);
out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;
out_pop:
        llog_ctxt_put(ctxt);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        up(&fsdb->fsdb_sem);
        name_destroy(&logname);

        RETURN(rc);
}

static struct fs_db *mgs_find_fsdb(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *fsdb;
        struct list_head *tmp;

        list_for_each(tmp, &mgs->mgs_fs_db_list) {
                fsdb = list_entry(tmp, struct fs_db, fsdb_list);
                if (strcmp(fsdb->fsdb_name, fsname) == 0)
                        return fsdb;
        }
        return NULL;
}

/* caller must hold the mgs->mgs_fs_db_lock */
static struct fs_db *mgs_new_fsdb(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *fsdb;
        int rc;
        ENTRY;

        OBD_ALLOC_PTR(fsdb);
        if (!fsdb)
                RETURN(NULL);

        OBD_ALLOC(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
        OBD_ALLOC(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
        if (!fsdb->fsdb_ost_index_map || !fsdb->fsdb_mdt_index_map) {
                CERROR("No memory for index maps\n");
                GOTO(err, 0);
        }

        strncpy(fsdb->fsdb_name, fsname, sizeof(fsdb->fsdb_name));
        fsdb->fsdb_name[sizeof(fsdb->fsdb_name) - 1] = 0;
        rc = name_create(&fsdb->fsdb_mdtlov, fsname, "-mdtlov");
        if (rc)
                GOTO(err, rc);
        rc = name_create(&fsdb->fsdb_clilov, fsname, "-clilov");
        if (rc)
                GOTO(err, rc);

        sema_init(&fsdb->fsdb_sem, 1);
        list_add(&fsdb->fsdb_list, &mgs->mgs_fs_db_list);
        lproc_mgs_add_live(obd, fsdb);

        RETURN(fsdb);
err:
        if (fsdb->fsdb_ost_index_map)
                OBD_FREE(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
        if (fsdb->fsdb_mdt_index_map)
                OBD_FREE(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
        name_destroy(&fsdb->fsdb_clilov);
        name_destroy(&fsdb->fsdb_mdtlov);
        OBD_FREE_PTR(fsdb);
        RETURN(NULL);
}

static void mgs_free_fsdb(struct obd_device *obd, struct fs_db *fsdb)
{
        /* wait for anyone with the sem */
        down(&fsdb->fsdb_sem);
        lproc_mgs_del_live(obd, fsdb);
        list_del(&fsdb->fsdb_list);
        OBD_FREE(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
        OBD_FREE(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
        name_destroy(&fsdb->fsdb_clilov);
        name_destroy(&fsdb->fsdb_mdtlov);
        name_destroy(&fsdb->fsdb_mdc);
        OBD_FREE_PTR(fsdb);
}

int mgs_init_fsdb_list(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        INIT_LIST_HEAD(&mgs->mgs_fs_db_list);
        return 0;
}

int mgs_cleanup_fsdb_list(struct obd_device *obd)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *fsdb;
        struct list_head *tmp, *tmp2;
        down(&mgs->mgs_sem);
        list_for_each_safe(tmp, tmp2, &mgs->mgs_fs_db_list) {
                fsdb = list_entry(tmp, struct fs_db, fsdb_list);
                mgs_free_fsdb(obd, fsdb);
        }
        up(&mgs->mgs_sem);
        return 0;
}

static int mgs_find_or_make_fsdb(struct obd_device *obd, char *name,
                                 struct fs_db **dbh)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct fs_db *fsdb;
        int rc = 0;

        down(&mgs->mgs_sem);
        fsdb = mgs_find_fsdb(obd, name);
        if (fsdb) {
                up(&mgs->mgs_sem);
                *dbh = fsdb;
                return 0;
        }

        CDEBUG(D_MGS, "Creating new db\n");
        fsdb = mgs_new_fsdb(obd, name);
        up(&mgs->mgs_sem);
        if (!fsdb)
                return -ENOMEM;

        /* populate the db from the client llog */
        rc = mgs_get_fsdb_from_llog(obd, fsdb);
        if (rc) {
                CERROR("Can't get db from client log %d\n", rc);
                mgs_free_fsdb(obd, fsdb);
                return rc;
        }

        *dbh = fsdb;

        return 0;
}

/* 1 = index in use
   0 = index unused
   -1= empty client log */
int mgs_check_index(struct obd_device *obd, struct mgs_target_info *mti)
{
        struct fs_db *fsdb;
        void *imap;
        int rc = 0;
        ENTRY;

        LASSERT(!(mti->mti_flags & LDD_F_NEED_INDEX));

        rc = mgs_find_or_make_fsdb(obd, mti->mti_fsname, &fsdb);
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                RETURN(rc);
        }

        if (fsdb->fsdb_flags & FSDB_LOG_EMPTY)
                RETURN(-1);

        if (mti->mti_flags & LDD_F_SV_TYPE_OST)
                imap = fsdb->fsdb_ost_index_map;
        else if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
                imap = fsdb->fsdb_mdt_index_map;
        else
                RETURN(-EINVAL);

        if (test_bit(mti->mti_stripe_index, imap))
                RETURN(1);
        RETURN(0);
}

static __inline__ int next_index(void *index_map, int map_len)
{
        int i;
        for (i = 0; i < map_len * 8; i++)
                 if (!test_bit(i, index_map)) {
                         return i;
                 }
        CERROR("max index %d exceeded.\n", i);
        return -1;
}

/* Return codes:
        0  newly marked as in use
        <0 err
        +EALREADY for update of an old index */
static int mgs_set_index(struct fs_db *fsdb, struct mgs_target_info *mti)
{
        void *imap;
        int rc = 0;
        ENTRY;

        if (mti->mti_flags & LDD_F_SV_TYPE_OST)
                imap = fsdb->fsdb_ost_index_map;
        else if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
                imap = fsdb->fsdb_mdt_index_map;
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
                LCONSOLE_ERROR_MSG(0x13e, "MDT index must = 0 (until Clustered "
                                   "MetaData feature is ready.)\n");
                mti->mti_stripe_index = 0;
        }

        if (mti->mti_stripe_index >= INDEX_MAP_SIZE * 8) {
                LCONSOLE_ERROR_MSG(0x13f, "Server %s requested index %d, but the"
                                   "max index is %d.\n",
                                   mti->mti_svname, mti->mti_stripe_index,
                                   INDEX_MAP_SIZE * 8);
                RETURN(-ERANGE);
        }

        if (test_bit(mti->mti_stripe_index, imap)) {
                if ((mti->mti_flags & LDD_F_VIRGIN) &&
                    !(mti->mti_flags & LDD_F_WRITECONF)) {
                        LCONSOLE_ERROR_MSG(0x140, "Server %s requested index "
                                           "%d, but that index is already in "
                                           "use. Use --writeconf to force\n",
                                           mti->mti_svname,
                                           mti->mti_stripe_index);
                        RETURN(-EADDRINUSE);
                } else {
                        CDEBUG(D_MGS, "Server %s updating index %d\n",
                               mti->mti_svname, mti->mti_stripe_index);
                        RETURN(EALREADY);
                }
        }

        set_bit(mti->mti_stripe_index, imap);
        fsdb->fsdb_flags &= ~FSDB_LOG_EMPTY;
        server_make_name(mti->mti_flags, mti->mti_stripe_index,
                         mti->mti_fsname, mti->mti_svname);

        CDEBUG(D_MGS, "Set index for %s to %d\n", mti->mti_svname,
               mti->mti_stripe_index);

        RETURN(0);
}

struct mgs_modify_lookup {
        struct cfg_marker mml_marker;
        int               mml_modified;
};

static int mgs_modify_handler(struct llog_handle *llh, struct llog_rec_hdr *rec,
                              void *data)
{
        struct mgs_modify_lookup *mml = (struct mgs_modify_lookup *)data;
        struct cfg_marker *marker;
        struct lustre_cfg *lcfg = (struct lustre_cfg *)(rec + 1);
        int cfg_len = rec->lrh_len - sizeof(struct llog_rec_hdr) -
                sizeof(struct llog_rec_tail);
        int rc;
        ENTRY;

        if (rec->lrh_type != OBD_CFG_REC) {
                CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
                RETURN(-EINVAL);
        }

        rc = lustre_cfg_sanity_check(lcfg, cfg_len);
        if (rc) {
                CERROR("Insane cfg\n");
                RETURN(rc);
        }

        /* We only care about markers */
        if (lcfg->lcfg_command != LCFG_MARKER)
                RETURN(0);

        marker = lustre_cfg_buf(lcfg, 1);
        if ((strcmp(mml->mml_marker.cm_comment, marker->cm_comment) == 0) &&
            (strcmp(mml->mml_marker.cm_tgtname, marker->cm_tgtname) == 0) &&
            !(marker->cm_flags & CM_SKIP)) {
                /* Found a non-skipped marker match */
                CDEBUG(D_MGS, "Changing rec %u marker %d %x->%x: %s %s\n",
                       rec->lrh_index, marker->cm_step,
                       marker->cm_flags, mml->mml_marker.cm_flags,
                       marker->cm_tgtname, marker->cm_comment);
                /* Overwrite the old marker llog entry */
                marker->cm_flags &= ~CM_EXCLUDE; /* in case we're unexcluding */
                marker->cm_flags |= mml->mml_marker.cm_flags;
                marker->cm_canceltime = mml->mml_marker.cm_canceltime;
                /* Header and tail are added back to lrh_len in
                   llog_lvfs_write_rec */
                rec->lrh_len = cfg_len;
                rc = llog_write_rec(llh, rec, NULL, 0, (void *)lcfg,
                                    rec->lrh_index);
                if (!rc)
                         mml->mml_modified++;
        }

        RETURN(rc);
}

/* Modify an existing config log record (for CM_SKIP or CM_EXCLUDE) */
static int mgs_modify(struct obd_device *obd, struct fs_db *fsdb,
                      struct mgs_target_info *mti, char *logname,
                      char *devname, char *comment, int flags)
{
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        struct mgs_modify_lookup *mml;
        int rc, rc2;
        ENTRY;

        CDEBUG(D_MGS, "modify %s/%s/%s fl=%x\n", logname, devname, comment,
               flags);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
        rc = llog_create(ctxt, &loghandle, NULL, logname);
        if (rc)
                GOTO(out_pop, rc);

        rc = llog_init_handle(loghandle, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);

        if (llog_get_size(loghandle) <= 1)
                GOTO(out_close, rc = 0);

        OBD_ALLOC_PTR(mml);
        if (!mml)
                GOTO(out_close, rc = -ENOMEM);
        strcpy(mml->mml_marker.cm_comment, comment);
        strcpy(mml->mml_marker.cm_tgtname, devname);
        /* Modify mostly means cancel */
        mml->mml_marker.cm_flags = flags;
        mml->mml_marker.cm_canceltime = flags ? cfs_time_current_sec() : 0;
        mml->mml_modified = 0;
        rc = llog_process(loghandle, mgs_modify_handler, (void *)mml, NULL);
        if (!rc && !mml->mml_modified)
                rc = -ENODEV;
        OBD_FREE_PTR(mml);

out_close:
        rc2 = llog_close(loghandle);
        if (!rc)
                rc = rc2;
out_pop:
        llog_ctxt_put(ctxt);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc && rc != -ENODEV)
                CERROR("modify %s/%s failed %d\n",
                       mti->mti_svname, comment, rc);

        RETURN(rc);
}


/******************** config log recording functions *********************/

static int record_lcfg(struct obd_device *obd, struct llog_handle *llh,
                         struct lustre_cfg *lcfg)
{
        struct lvfs_run_ctxt   saved;
        struct llog_rec_hdr    rec;
        int buflen, rc;

        if (!lcfg || !llh)
                return -ENOMEM;

        LASSERT(llh->lgh_ctxt);

        buflen = lustre_cfg_len(lcfg->lcfg_bufcount,
                                lcfg->lcfg_buflens);
        rec.lrh_len = llog_data_len(buflen);
        rec.lrh_type = OBD_CFG_REC;
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* idx = -1 means append */
        rc = llog_write_rec(llh, &rec, NULL, 0, (void *)lcfg, -1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc)
                CERROR("failed %d\n", rc);
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
        if (!lcfg)
                return -ENOMEM;
        lcfg->lcfg_nid = nid;

        rc = record_lcfg(obd, llh, lcfg);

        lustre_cfg_free(lcfg);

        if (rc) {
                CERROR("error %d: lcfg %s %#x %s %s %s %s\n", rc, cfgname,
                       cmd, s1, s2, s3, s4);
        }
        return(rc);
}


static inline int record_add_uuid(struct obd_device *obd,
                                  struct llog_handle *llh,
                                  __u64 nid, char *uuid)
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
        if (!lcfg)
                return -ENOMEM;
        rc = record_lcfg(obd, llh, lcfg);

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
                         struct fs_db *fsdb, __u32 flags,
                         char *tgtname, char *comment)
{
        struct cfg_marker marker;
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        int rc;

        if (flags & CM_START)
                fsdb->fsdb_gen++;
        marker.cm_step = fsdb->fsdb_gen;
        marker.cm_flags = flags;
        marker.cm_vers = LUSTRE_VERSION_CODE;
        strncpy(marker.cm_tgtname, tgtname, sizeof(marker.cm_tgtname));
        strncpy(marker.cm_comment, comment, sizeof(marker.cm_comment));
        marker.cm_createtime = cfs_time_current_sec();
        marker.cm_canceltime = 0;
        lustre_cfg_bufs_reset(&bufs, NULL);
        lustre_cfg_bufs_set(&bufs, 1, &marker, sizeof(marker));
        lcfg = lustre_cfg_new(LCFG_MARKER, &bufs);
        if (!lcfg)
                return -ENOMEM;
        rc = record_lcfg(obd, llh, lcfg);

        lustre_cfg_free(lcfg);
        return rc;
}

static int record_start_log(struct obd_device *obd,
                            struct llog_handle **llh, char *name)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        int rc = 0;

        if (*llh)
                GOTO(out, rc = -EBUSY);

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        if (!ctxt)
                GOTO(out, rc = -ENODEV);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(ctxt, llh, NULL, name);
        if (rc == 0)
                llog_init_handle(*llh, LLOG_F_IS_PLAIN, &cfg_uuid);
        else
                *llh = NULL;

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);

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
        struct llog_ctxt *ctxt;
        int rc = 0;

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc == 0) {
                llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_get_size(llh);
                llog_close(llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);
        /* header is record 1 */
        return(rc <= 1);
}

/******************** config "macros" *********************/

/* write an lcfg directly into a log (with markers) */
static int mgs_write_log_direct(struct obd_device *obd, struct fs_db *fsdb,
                                char *logname, struct lustre_cfg *lcfg,
                                char *devname, char *comment)
{
        struct llog_handle *llh = NULL;
        int rc;
        ENTRY;

        if (!lcfg)
                RETURN(-ENOMEM);

        rc = record_start_log(obd, &llh, logname);
        if (rc)
                RETURN(rc);

        /* FIXME These should be a single journal transaction */
        rc = record_marker(obd, llh, fsdb, CM_START, devname, comment);

        rc = record_lcfg(obd, llh, lcfg);

        rc = record_marker(obd, llh, fsdb, CM_END, devname, comment);
        rc = record_end_log(obd, &llh);

        RETURN(rc);
}

/* write the lcfg in all logs for the given fs */
int mgs_write_log_direct_all(struct obd_device *obd, struct fs_db *fsdb,
                             struct mgs_target_info *mti,
                             struct lustre_cfg *lcfg,
                             char *devname, char *comment)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        struct list_head dentry_list;
        struct l_linux_dirent *dirent, *n;
        char *fsname = mti->mti_fsname;
        char *logname;
        int rc = 0, len = strlen(fsname);
        ENTRY;

        /* We need to set params for any future logs
           as well. FIXME Append this file to every new log.
           Actually, we should store as params (text), not llogs.  Or
           in a database. */
        name_create(&logname, fsname, "-params");
        if (mgs_log_is_empty(obd, logname)) {
                struct llog_handle *llh = NULL;
                rc = record_start_log(obd, &llh, logname);
                record_end_log(obd, &llh);
        }
        name_destroy(&logname);
        if (rc)
                RETURN(rc);

        /* Find all the logs in the CONFIGS directory */
        rc = class_dentry_readdir(obd, mgs->mgs_configs_dir,
                                  mgs->mgs_vfsmnt, &dentry_list);
        if (rc) {
                CERROR("Can't read %s dir\n", MOUNT_CONFIGS_DIR);
                RETURN(rc);
        }

        /* Could use fsdb index maps instead of directory listing */
        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                list_del(&dirent->lld_list);
                if (strncmp(fsname, dirent->lld_name, len) == 0) {
                        CDEBUG(D_MGS, "Changing log %s\n", dirent->lld_name);
                        /* Erase any old settings of this same parameter */
                        mgs_modify(obd, fsdb, mti, dirent->lld_name, devname,
                                   comment, CM_SKIP);
                        /* Write the new one */
                        if (lcfg) {
                                rc = mgs_write_log_direct(obd, fsdb,
                                                          dirent->lld_name,
                                                          lcfg, devname,
                                                          comment);
                                if (rc)
                                        CERROR("err %d writing log %s\n", rc,
                                               dirent->lld_name);
                        }
                }
                OBD_FREE(dirent, sizeof(*dirent));
        }

        RETURN(rc);
}

/* lov is the first thing in the mdt and client logs */
static int mgs_write_log_lov(struct obd_device *obd, struct fs_db *fsdb,
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
        lovdesc->ld_magic = LOV_DESC_MAGIC;
        lovdesc->ld_tgt_count = 0;
        /* Defaults.  Can be changed later by lcfg config_param */
        lovdesc->ld_default_stripe_count = 1;
        lovdesc->ld_pattern = LOV_PATTERN_RAID0;
        lovdesc->ld_default_stripe_size = 1024 * 1024;
        lovdesc->ld_default_stripe_offset = -1;
        lovdesc->ld_qos_maxage = QOS_DEFAULT_MAXAGE;
        sprintf((char*)lovdesc->ld_uuid.uuid, "%s_UUID", lovname);
        /* can these be the same? */
        uuid = (char *)lovdesc->ld_uuid.uuid;

        /* This should always be the first entry in a log.
        rc = mgs_clear_log(obd, logname); */
        rc = record_start_log(obd, &llh, logname);
        if (rc)
                GOTO(out, rc);
        /* FIXME these should be a single journal transaction */
        rc = record_marker(obd, llh, fsdb, CM_START, lovname, "lov setup");
        rc = record_attach(obd, llh, lovname, "lov", uuid);
        rc = record_lov_setup(obd, llh, lovname, lovdesc);
        rc = record_marker(obd, llh, fsdb, CM_END, lovname, "lov setup");
        rc = record_end_log(obd, &llh);
out:
        OBD_FREE(lovdesc, sizeof(*lovdesc));
        RETURN(rc);
}

/* add failnids to open log */
static int mgs_write_log_failnids(struct obd_device *obd,
                                  struct mgs_target_info *mti,
                                  struct llog_handle *llh,
                                  char *cliname)
{
        char *failnodeuuid = NULL;
        char *ptr = mti->mti_params;
        lnet_nid_t nid;
        int rc = 0;
        /*
        #03 L add_uuid  nid=uml1@tcp(0x20000c0a80201) nal=90 0:  1:uml1_UUID
        #04 L add_uuid  nid=1@elan(0x1000000000001)   nal=90 0:  1:uml1_UUID
        #05 L setup    0:OSC_uml1_ost1_mdsA  1:ost1_UUID  2:uml1_UUID
        #06 L add_uuid  nid=uml2@tcp(0x20000c0a80202) nal=90 0:  1:uml2_UUID
        #0x L add_uuid  nid=2@elan(0x1000000000002)   nal=90 0:  1:uml2_UUID
        #07 L add_conn 0:OSC_uml1_ost1_mdsA  1:uml2_UUID
        */

        /* Pull failnid info out of params string */
        while (class_find_param(ptr, PARAM_FAILNODE, &ptr) == 0) {
                while (class_parse_nid(ptr, &nid, &ptr) == 0) {
                        if (failnodeuuid == NULL) {
                                /* We don't know the failover node name,
                                   so just use the first nid as the uuid */
                                rc = name_create(&failnodeuuid,
                                                 libcfs_nid2str(nid), "");
                                if (rc)
                                        return rc;
                        }
                        CDEBUG(D_MGS, "add nid %s for failover uuid %s, "
                               "client %s\n", libcfs_nid2str(nid),
                               failnodeuuid, cliname);
                        rc = record_add_uuid(obd, llh, nid, failnodeuuid);
                }
                if (failnodeuuid) {
                        rc = record_add_conn(obd, llh, cliname, failnodeuuid);
                        name_destroy(&failnodeuuid);
                        failnodeuuid = NULL;
                }
        }

        return rc;
}

static int __mgs_write_log_mdt(struct obd_device *obd, struct fs_db *fsdb,
                             struct mgs_target_info *mti)
{
        struct llog_handle *llh = NULL;
        char mdt_uuid[sizeof(struct obd_uuid)];
        char *svname;
        int rc;

        ENTRY;
        name_create(&svname, mti->mti_fsname, "-MDT0000");
        if (!mgs_log_is_empty(obd, svname))
                GOTO(out, rc = 0);

        /* Make up our own uuid */
        snprintf(mdt_uuid, sizeof(struct obd_uuid), "%s_UUID", svname);

        rc = mgs_write_log_lov(obd, fsdb, mti, svname,
                        fsdb->fsdb_mdtlov);
        if (rc)
                GOTO(out, rc);

        rc = record_start_log(obd, &llh, svname);
        if (rc)
                GOTO(out, rc);
        /* FIXME this whole fn should be a single journal transaction */
        record_marker(obd, llh, fsdb, CM_START, svname,"add mdt");
        record_mount_opt(obd, llh, svname, fsdb->fsdb_mdtlov, 0);
        record_attach(obd, llh, svname, LUSTRE_MDS_NAME, mdt_uuid);

        record_setup(obd, llh, svname,
                   mdt_uuid /* Ignored. Compatible with future. */,
                   "0" /* MDT Index, default to zero. */,
                   svname,
                   0 /* options */);
        record_marker(obd, llh, fsdb, CM_END, svname, "add mdt");
        record_end_log(obd, &llh);
        EXIT;
out:
        name_destroy(&svname);
        return rc;
}

static int mgs_write_log_mdt(struct obd_device *obd, struct fs_db *fsdb,
                             struct mgs_target_info *mti)
{
        struct llog_handle *llh = NULL;
        char *cliname, *mdcname, *nodeuuid, *mdcuuid;
        int rc, i, first_log = 0;
        ENTRY;

        CDEBUG(D_MGS, "writing new mdt %s\n", mti->mti_svname);

        if (mti->mti_uuid[0] == '\0') {
                /* Make up our own uuid */
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
        }

        /* Append mdt info to mdt log */
        if (mgs_log_is_empty(obd, mti->mti_svname)) {
                /* This is the first time for all logs for this fs,
                   since any ost should have already started the mdt log. */
                first_log++;
                rc = __mgs_write_log_mdt(obd, fsdb, mti);
        }
        /* else there's already some ost entries in the mdt log. */

        /* We added the lov, maybe some osc's, now for the mdt.
           We might add more ost's after this. Note that during the parsing
           of this log, this is when the mdt will start. (This was not
           formerly part of the old mds log, it was directly executed by
           lconf.) */
        /* Append the mdt info to the client log */
        name_create(&cliname, mti->mti_fsname, "-client");
        if (first_log) {
                /* Start client log */
                rc = mgs_write_log_lov(obd, fsdb, mti, cliname,
                                       fsdb->fsdb_clilov);
        }

        name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]),/*"_UUID"*/"");
        name_create(&mdcname, mti->mti_svname, "-mdc");
        name_create(&mdcuuid, mdcname, "_UUID");
        /*
        #09 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        #10 L attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f
        #11 L setup    0:MDC_uml1_mdsA_MNT_client  1:mdsA_UUID  2:uml1_UUID
        #12 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #13 L add_conn 0:MDC_uml1_mdsA_MNT_client  1:uml2_UUID
        #14 L mount_option 0:  1:client  2:lov1  3:MDC_uml1_mdsA_MNT_client
        */
        rc = record_start_log(obd, &llh, cliname);
        if (rc)
                GOTO(out, rc);
        rc = record_marker(obd, llh, fsdb, CM_START, mti->mti_svname,"add mdc");
        /* COMPAT_146 */
        if (fsdb->fsdb_flags & FSDB_OLDLOG14) {
                /* Old client log already has MDC entry, but needs mount opt
                   for new client name (lustre-client) */
                /* FIXME Old MDT log already has an old mount opt
                   which we should remove (currently handled by
                   class_del_profiles()) */
                rc = record_mount_opt(obd, llh, cliname, fsdb->fsdb_clilov,
                                      fsdb->fsdb_mdc);
                /* Only add failnids with --writeconf
                rc = mgs_write_log_failnids(obd, mti, llh, fsdb->fsdb_mdc);
                */
                /* end COMPAT_146 */
        } else {
                for (i = 0; i < mti->mti_nid_count; i++) {
                        CDEBUG(D_MGS, "add nid %s\n",
                               libcfs_nid2str(mti->mti_nids[i]));
                        rc = record_add_uuid(obd, llh, mti->mti_nids[i],
                                             nodeuuid);
                }
                rc = record_attach(obd, llh, mdcname, LUSTRE_MDC_NAME, mdcuuid);
                rc = record_setup(obd, llh, mdcname, mti->mti_uuid,nodeuuid,
                                  0, 0);
                rc = mgs_write_log_failnids(obd, mti, llh, mdcname);
                rc = record_mount_opt(obd, llh, cliname, fsdb->fsdb_clilov,
                                      mdcname);
        }
        rc = record_marker(obd, llh, fsdb, CM_END, mti->mti_svname, "add mdc");
        rc = record_end_log(obd, &llh);
out:
        name_destroy(&mdcuuid);
        name_destroy(&mdcname);
        name_destroy(&nodeuuid);
        name_destroy(&cliname);
        RETURN(rc);
}

/* Add the ost info to the client/mdt lov */
static int mgs_write_log_osc(struct obd_device *obd, struct fs_db *fsdb,
                             struct mgs_target_info *mti,
                             char *logname, char *lovname, int flags)
{
        struct llog_handle *llh = NULL;
        char *nodeuuid, *oscname, *oscuuid, *lovuuid;
        char index[6];
        int i, rc;

        if (mgs_log_is_empty(obd, logname)) {
                /* The first item in the log must be the lov, so we have
                   somewhere to add our osc. */
                rc = mgs_write_log_lov(obd, fsdb, mti, logname, lovname);
        }

        CDEBUG(D_MGS, "adding osc for %s to log %s\n",
               mti->mti_svname, logname);

        name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
        name_create(&oscname, mti->mti_svname, "-osc");
        name_create(&oscuuid, oscname, "_UUID");
        name_create(&lovuuid, lovname, "_UUID");

        /*
        #03 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        multihomed (#4)
        #04 L add_uuid  nid=1@elan(0x1000000000001)  nal=90 0:  1:uml1_UUID
        #04 L attach   0:OSC_uml1_ost1_MNT_client  1:osc  2:89070_lov1_a41dff51a
        #05 L setup    0:OSC_uml1_ost1_MNT_client  1:ost1_UUID  2:uml1_UUID
        failover (#6,7)
        #06 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #07 L add_conn 0:OSC_uml1_ost1_MNT_client  1:uml2_UUID
        #08 L lov_modify_tgts add 0:lov1  1:ost1_UUID  2(index):0  3(gen):1
        */
        rc = record_start_log(obd, &llh, logname);
        if (rc)
                GOTO(out, rc);
        /* FIXME these should be a single journal transaction */
        rc = record_marker(obd, llh, fsdb, CM_START | flags, mti->mti_svname,
                           "add osc");
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s\n", libcfs_nid2str(mti->mti_nids[i]));
                rc = record_add_uuid(obd, llh, mti->mti_nids[i], nodeuuid);
        }
        rc = record_attach(obd, llh, oscname, LUSTRE_OSC_NAME, lovuuid);
        rc = record_setup(obd, llh, oscname, mti->mti_uuid, nodeuuid, 0, 0);
        rc = mgs_write_log_failnids(obd, mti, llh, oscname);
        snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);
        rc = record_lov_add(obd, llh, lovname, mti->mti_uuid, index, "1");
        rc = record_marker(obd, llh, fsdb, CM_END | flags, mti->mti_svname,
                           "add osc");
        rc = record_end_log(obd, &llh);
out:
        name_destroy(&lovuuid);
        name_destroy(&oscuuid);
        name_destroy(&oscname);
        name_destroy(&nodeuuid);
        return rc;
}

static int mgs_write_log_ost(struct obd_device *obd, struct fs_db *fsdb,
                             struct mgs_target_info *mti)
{
        struct llog_handle *llh = NULL;
        char *logname;
        char *ptr = mti->mti_params;
        int rc, flags = 0, failout = 0;
        ENTRY;

        CDEBUG(D_MGS, "writing new ost %s\n", mti->mti_svname);

        /* The ost startup log */

        /* If the ost log already exists, that means that someone reformatted
           the ost and it called target_add again. */
        if (!mgs_log_is_empty(obd, mti->mti_svname)) {
                LCONSOLE_ERROR_MSG(0x141, "The config log for %s already "
                                   "exists, yet the server claims it never "
                                   "registered. It may have been reformatted, "
                                   "or the index changed. writeconf the MDT to "
                                   "regenerate all logs.\n", mti->mti_svname);
                RETURN(-EALREADY);
        }
        /*
        attach obdfilter ost1 ost1_UUID
        setup /dev/loop2 ldiskfs f|n errors=remount-ro,user_xattr
        */
        if (class_find_param(ptr, PARAM_FAILMODE, &ptr) == 0)
                failout = (strncmp(ptr, "failout", 7) == 0);
        rc = record_start_log(obd, &llh, mti->mti_svname);
        if (rc)
                RETURN(rc);
        /* FIXME these should be a single journal transaction */
        rc = record_marker(obd, llh, fsdb, CM_START, mti->mti_svname,"add ost");
        if (*mti->mti_uuid == '\0')
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
        rc = record_attach(obd, llh, mti->mti_svname,
                           "obdfilter"/*LUSTRE_OST_NAME*/, mti->mti_uuid);
        rc = record_setup(obd, llh, mti->mti_svname,
                          "dev"/*ignored*/, "type"/*ignored*/,
                          failout ? "n" : "f", 0/*options*/);
        rc = record_marker(obd, llh, fsdb, CM_END, mti->mti_svname, "add ost");
        rc = record_end_log(obd, &llh);

        /* We also have to update the other logs where this osc is part of
           the lov */

        if (fsdb->fsdb_flags & FSDB_OLDLOG14) {
                /* If we're upgrading, the old mdt log already has our
                   entry. Let's do a fake one for fun. */
                /* Note that we can't add any new failnids, since we don't
                   know the old osc names. */
                flags = CM_SKIP | CM_UPGRADE146;
        } else if ((mti->mti_flags & LDD_F_UPDATE) != LDD_F_UPDATE) {
                /* If the update flag isn't set, don't really update
                   client/mdt logs. */
                flags |= CM_SKIP;
                LCONSOLE_WARN("Client log for %s was not updated; writeconf "
                              "the MDT first to regenerate it.\n",
                              mti->mti_svname);
        }

        /* Append ost info to mdt log */
        /* FIXME add to all MDT logs for CMD */
        /* FIXME need real MDT name, but MDT may not have registered yet! */

        name_create(&logname, mti->mti_fsname, "-MDT0000");
        rc = __mgs_write_log_mdt(obd, fsdb, mti);
        rc = mgs_write_log_osc(obd, fsdb, mti, logname, fsdb->fsdb_mdtlov,
                               flags);
        name_destroy(&logname);

        /* Append ost info to the client log */
        name_create(&logname, mti->mti_fsname, "-client");
        rc = mgs_write_log_osc(obd, fsdb, mti, logname, fsdb->fsdb_clilov,
                               flags);
        name_destroy(&logname);

        RETURN(rc);
}

static __inline__ int mgs_param_empty(char *ptr)
{
        char *tmp;

        if ((tmp = strchr(ptr, '=')) && (*(++tmp) == '\0'))
                return 1;
        return 0;
}

static int mgs_write_log_failnid_internal(struct obd_device *obd,
                                          struct fs_db *fsdb,
                                          struct mgs_target_info *mti,
                                          char *logname, char *cliname)
{
        int rc;
        struct llog_handle *llh = NULL;

        if (mgs_param_empty(mti->mti_params)) {
                /* Remove _all_ failnids */
                rc = mgs_modify(obd, fsdb, mti, logname,
                                mti->mti_svname, "add failnid", CM_SKIP);
                return rc;
        }

        /* Otherwise failover nids are additive */
        rc = record_start_log(obd, &llh, logname);
        if (!rc) {
                /* FIXME this should be a single journal transaction */
                rc = record_marker(obd, llh, fsdb, CM_START,
                                   mti->mti_svname, "add failnid");
                rc = mgs_write_log_failnids(obd, mti, llh, cliname);
                rc = record_marker(obd, llh, fsdb, CM_END,
                                   mti->mti_svname, "add failnid");
                rc = record_end_log(obd, &llh);
        }

        return rc;
}

/* Add additional failnids to an existing log.
   The mdc/osc must have been added to logs first */
/* tcp nids must be in dotted-quad ascii -
   we can't resolve hostnames from the kernel. */
static int mgs_write_log_add_failnid(struct obd_device *obd, struct fs_db *fsdb,
                                     struct mgs_target_info *mti)
{
        char *logname, *cliname;
        int rc;
        ENTRY;

        /* FIXME we currently can't erase the failnids
         * given when a target first registers, since they aren't part of
         * an "add uuid" stanza */

        /* Verify that we know about this target */
        if (mgs_log_is_empty(obd, mti->mti_svname)) {
                LCONSOLE_ERROR_MSG(0x142, "The target %s has not registered "
                                   "yet. It must be started before failnids can"
                                   " be added.\n", mti->mti_svname);
                RETURN(-ENOENT);
        }

        /* Create mdc/osc client name (e.g. lustre-OST0001-osc) */
        if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                /* COMPAT_146 */
                if (fsdb->fsdb_mdc)
                        name_create(&cliname, fsdb->fsdb_mdc, "");
                else
                        name_create(&cliname, mti->mti_svname, "-mdc");
        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                /* COMPAT_146 */
                if (fsdb->fsdb_flags & FSDB_OLDLOG14) {
                        LCONSOLE_ERROR_MSG(0x143, "Failover NIDs cannot be "
                                           "added to upgraded client logs for "
                                           "%s. Consider updating the "
                                           "configuration with --writeconf.\n",
                                           mti->mti_svname);
                        RETURN(-EINVAL);
                }
                name_create(&cliname, mti->mti_svname, "-osc");
        } else {
                RETURN(-EINVAL);
        }

        /* Add failover nids to the client log */
        name_create(&logname, mti->mti_fsname, "-client");
        rc = mgs_write_log_failnid_internal(obd, fsdb, mti, logname, cliname);
        name_destroy(&logname);

        if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                /* Add OST failover nids to the MDT log as well */
                name_create(&logname, mti->mti_fsname, "-MDT0000");
                rc = mgs_write_log_failnid_internal(obd, fsdb, mti, logname,
                                                    cliname);
                name_destroy(&logname);
        }

        name_destroy(&cliname);
        RETURN(rc);
}

static int mgs_wlp_lcfg(struct obd_device *obd, struct fs_db *fsdb,
                        struct mgs_target_info *mti,
                        char *logname, struct lustre_cfg_bufs *bufs,
                        char *tgtname, char *ptr)
{
        char comment[MTI_NAME_MAXLEN];
        char *tmp;
        struct lustre_cfg *lcfg;
        int rc, del;

        /* Erase any old settings of this same parameter */
        memcpy(comment, ptr, MTI_NAME_MAXLEN);
        comment[MTI_NAME_MAXLEN - 1] = 0;
        /* But don't try to match the value. */
        if ((tmp = strchr(comment, '=')))
            *tmp = 0;
        /* FIXME we should skip settings that are the same as old values */
        rc = mgs_modify(obd, fsdb, mti, logname, tgtname, comment, CM_SKIP);
        del = mgs_param_empty(ptr);

        LCONSOLE_INFO("%sing parameter %s.%s in log %s\n", del ? "Disabl" : rc ?
                      "Sett" : "Modify", tgtname, comment, logname);
        if (del)
                return rc;

        lustre_cfg_bufs_reset(bufs, tgtname);
        lustre_cfg_bufs_set_string(bufs, 1, ptr);
        lcfg = lustre_cfg_new(LCFG_PARAM, bufs);
        if (!lcfg)
                return -ENOMEM;
        rc = mgs_write_log_direct(obd, fsdb, logname, lcfg, tgtname, comment);
        lustre_cfg_free(lcfg);
        return rc;
}

/* write global variable settings into log */
static int mgs_write_log_sys(struct obd_device *obd, struct fs_db *fsdb,
                             struct mgs_target_info *mti, char *sys, char *ptr)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        char *tmp;
        char sep;
        int cmd, val;
        int rc;

        if (class_match_param(ptr, PARAM_TIMEOUT, &tmp) == 0)
                cmd = LCFG_SET_TIMEOUT;
        else if (class_match_param(ptr, PARAM_LDLM_TIMEOUT, &tmp) == 0)
                cmd = LCFG_SET_LDLM_TIMEOUT;
        /* Check for known params here so we can return error to lctl */
        else if ((class_match_param(ptr, PARAM_AT_MIN, &tmp) == 0)
                 || (class_match_param(ptr, PARAM_AT_MAX, &tmp) == 0)
                 || (class_match_param(ptr, PARAM_AT_EXTRA, &tmp) == 0)
                 || (class_match_param(ptr, PARAM_AT_EARLY_MARGIN, &tmp) == 0)
                 || (class_match_param(ptr, PARAM_AT_HISTORY, &tmp) == 0))
                cmd = LCFG_PARAM;
        else
                return -EINVAL;

        /* separate the value */
        val = simple_strtoul(tmp, NULL, 0);
        if (*tmp == '\0')
                CDEBUG(D_MGS, "global '%s' removed\n", sys);
        else
                CDEBUG(D_MGS, "global '%s' val=%d\n", sys, val);

        lustre_cfg_bufs_reset(&bufs, NULL);
        lustre_cfg_bufs_set_string(&bufs, 1, sys);
        lcfg = lustre_cfg_new(cmd, &bufs);
        lcfg->lcfg_num = val;
        /* truncate the comment to the parameter name */
        ptr = tmp - 1;
        sep = *ptr;
        *ptr = '\0';
        /* modify all servers and clients */
        rc = mgs_write_log_direct_all(obd, fsdb, mti,
                                      *tmp == '\0' ? NULL : lcfg,
                                      mti->mti_fsname, sys);
        *ptr = sep;
        lustre_cfg_free(lcfg);
        return rc;
}

static int mgs_write_log_params(struct obd_device *obd, struct fs_db *fsdb,
                                struct mgs_target_info *mti)
{
        struct lustre_cfg_bufs bufs;
        char *logname;
        char *ptr = mti->mti_params;
        char *endptr, *tmp;
        int rc = 0, rc2 = 0;
        ENTRY;

        if (!mti->mti_params)
                RETURN(0);

        /* For various parameter settings, we have to figure out which logs
           care about them (e.g. both mdt and client for lov settings) */
        while (ptr) {
                while (*ptr == ' ')
                        ptr++;
                if (*ptr == '\0')
                        break;
                endptr = strchr(ptr, ' ');
                if (endptr)
                        *endptr = '\0';
                CDEBUG(D_MGS, "next param '%s'\n", ptr);

                /* The params are stored in MOUNT_DATA_FILE and modified
                   via tunefs.lustre */

                /* Processed in lustre_start_mgc */
                if (class_match_param(ptr, PARAM_MGSNODE, NULL) == 0)
                        goto end_while;

                /* Processed in mgs_write_log_ost */
                if (class_match_param(ptr, PARAM_FAILMODE, NULL) == 0) {
                        if (mti->mti_flags & LDD_F_PARAM) {
                                LCONSOLE_ERROR_MSG(0x169, "%s can only be "
                                                   "changed with tunefs.lustre "
                                                   "and --writeconf\n", ptr);
                                rc = -EPERM;
                        }
                        goto end_while;
                }

                if (class_match_param(ptr, PARAM_FAILNODE, NULL) == 0) {
                        /* Add a failover nidlist */
                        rc = 0;
                        /* We already processed failovers params for new
                           targets in mgs_write_log_target */
                        if (mti->mti_flags & LDD_F_PARAM) {
                                CDEBUG(D_MGS, "Adding failnode\n");
                                rc = mgs_write_log_add_failnid(obd, fsdb, mti);
                        }
                        goto end_while;
                }

                if (class_match_param(ptr, PARAM_SYS, &tmp) == 0) {
                        rc = mgs_write_log_sys(obd, fsdb, mti, ptr, tmp);
                        goto end_while;
                }

                if (class_match_param(ptr, PARAM_OSC""PARAM_ACTIVE, &tmp) == 0){
                        /* active=0 means off, anything else means on */
                        int flag = (*tmp == '0') ? CM_EXCLUDE : 0;
                        if (!(mti->mti_flags & LDD_F_SV_TYPE_OST)) {
                                LCONSOLE_ERROR_MSG(0x144, "%s: Only OSCs can be"
                                                   " (de)activated.\n",
                                                   mti->mti_svname);
                                rc = -EINVAL;
                                goto end_while;
                        }
                        LCONSOLE_WARN("Permanently %sactivating %s\n",
                                      flag ? "de": "re", mti->mti_svname);
                        /* Modify clilov */
                        name_create(&logname, mti->mti_fsname, "-client");
                        rc = mgs_modify(obd, fsdb, mti, logname,
                                        mti->mti_svname, "add osc", flag);
                        name_destroy(&logname);
                        if (rc)
                                goto active_err;
                        /* Modify mdtlov */
                        /* FIXME add to all MDT logs for CMD */
                        name_create(&logname, mti->mti_fsname, "-MDT0000");
                        rc = mgs_modify(obd, fsdb, mti, logname,
                                        mti->mti_svname, "add osc", flag);
                        name_destroy(&logname);
active_err:
                        if (rc) {
                                LCONSOLE_ERROR_MSG(0x145, "Couldn't find %s in "
                                                  "log (%d). No permanent "
                                                  "changes were made to the "
                                                  "config log.\n",
                                                  mti->mti_svname, rc);
                                if (fsdb->fsdb_flags & FSDB_OLDLOG14)
                                        LCONSOLE_ERROR_MSG(0x146, "This may be "
                                        "because the log is in the old 1.4 "
                                        "style. Consider --writeconf to "
                                        "update the logs.\n");
                                goto end_while;
                        }
                        /* Fall through to osc proc for deactivating
                           live OSC on running MDT / clients. */
                }

                /* Below here, let obd's XXX_process_config methods handle it */

                /* All lov. in proc */
                if (class_match_param(ptr, PARAM_LOV, NULL) == 0) {
                        CDEBUG(D_MGS, "lov param %s\n", ptr);
                        if (!(mti->mti_flags & LDD_F_SV_TYPE_MDT)) {
                                LCONSOLE_ERROR_MSG(0x147, "LOV params must be "
                                                   "set on the MDT, not %s. "
                                                   "Ignoring.\n",
                                                   mti->mti_svname);
                                rc = 0;
                                goto end_while;
                        }

                        /* Modify mdtlov */
                        if (mgs_log_is_empty(obd, mti->mti_svname)) {
                                rc = -ENODEV;
                                goto end_while;
                        }
                        rc = mgs_wlp_lcfg(obd, fsdb, mti, mti->mti_svname,
                                          &bufs, fsdb->fsdb_mdtlov, ptr);
                        if (rc)
                                goto end_while;

                        /* Modify clilov */
                        name_create(&logname, mti->mti_fsname, "-client");
                        rc = mgs_wlp_lcfg(obd, fsdb, mti, logname, &bufs,
                                          fsdb->fsdb_clilov, ptr);
                        name_destroy(&logname);
                        goto end_while;
                }

                /* All osc., mdc., llite. params in proc */
                if ((class_match_param(ptr, PARAM_OSC, NULL) == 0) ||
                    (class_match_param(ptr, PARAM_MDC, NULL) == 0) ||
                    (class_match_param(ptr, PARAM_LLITE, NULL) == 0)) {
                        char *cname;
                        if (memcmp(ptr, PARAM_LLITE, strlen(PARAM_LLITE)) == 0){
                                name_create(&cname, mti->mti_fsname, "-client");
                        /* Add the client type to match the obdname
                           in class_config_llog_handler */
                        } else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                                /* COMPAT_146 */
                                if (fsdb->fsdb_mdc)
                                        name_create(&cname, fsdb->fsdb_mdc, "");
                                else
                                        name_create(&cname, mti->mti_svname,
                                                    "-mdc");
                        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                                /* COMPAT_146 */
                                if (fsdb->fsdb_flags & FSDB_OLDLOG14) {
                                      LCONSOLE_ERROR_MSG(0x148, "Upgraded client"
                                           " logs for %s cannot be modified. "
                                           "Consider updating the "
                                           "configuration with --writeconf\n",
                                           mti->mti_svname);
                                        /* We don't know the names of all the
                                           old oscs*/
                                        rc = -EINVAL;
                                        goto end_while;
                                }
                                name_create(&cname, mti->mti_svname, "-osc");
                        } else {
                                rc = -EINVAL;
                                goto end_while;
                        }

                        CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);

                        /* Modify client */
                        name_create(&logname, mti->mti_fsname, "-client");
                        rc = mgs_wlp_lcfg(obd, fsdb, mti, logname, &bufs,
                                          cname, ptr);
                        name_destroy(&logname);

                        /* osc params affect the MDT as well */
                        if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                                /* FIXME add to all MDT logs for CMD */
                                name_create(&logname, mti->mti_fsname,
                                            "-MDT0000");
                                if (!mgs_log_is_empty(obd, logname))
                                        rc = mgs_wlp_lcfg(obd, fsdb, mti,
                                                          logname, &bufs,
                                                          cname, ptr);
                                name_destroy(&logname);
                        }
                        name_destroy(&cname);
                        goto end_while;
                }

                /* All mdt., ost. params in proc */
                if ((class_match_param(ptr, PARAM_MDT, NULL) == 0) ||
                    (class_match_param(ptr, PARAM_OST, NULL) == 0)) {
                        CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);
                        if (mgs_log_is_empty(obd, mti->mti_svname)) {
                                rc = -ENODEV;
                                goto end_while;
                        }
                        rc = mgs_wlp_lcfg(obd, fsdb, mti, mti->mti_svname,
                                          &bufs, mti->mti_svname, ptr);
                        goto end_while;
                }

                LCONSOLE_WARN("Ignoring unrecognized param '%s'\n", ptr);
                rc2 = -ENOSYS;

end_while:
                if (rc) {
                        CERROR("err %d on param '%s\n", rc, ptr);
                        break;
                }

                if (!endptr)
                        /* last param */
                        break;

                *endptr = ' ';
                ptr = endptr + 1;
        }

        RETURN(rc ?: rc2);
}

int mgs_check_failnid(struct obd_device *obd, struct mgs_target_info *mti)
{
        /* Not implementing automatic failover nid addition at this time. */
        return 0;
#if 0
        struct fs_db *fsdb;
        int rc;
        ENTRY;

        rc = mgs_find_or_make_fsdb(obd, fsname, &fsdb);
        if (rc)
                RETURN(rc);

        if (mgs_log_is_empty(obd, mti->mti_svname))
                /* should never happen */
                RETURN(-ENOENT);

        CDEBUG(D_MGS, "Checking for new failnids for %s\n", mti->mti_svname);

        /* FIXME We can just check mti->params to see if we're already in
           the failover list.  Modify mti->params for rewriting back at
           server_register_target(). */

        down(&fsdb->fsdb_sem);
        rc = mgs_write_log_add_failnid(obd, fsdb, mti);
        up(&fsdb->fsdb_sem);

        RETURN(rc);
#endif
}

int mgs_write_log_target(struct obd_device *obd,
                         struct mgs_target_info *mti)
{
        struct fs_db *fsdb;
        int rc;
        ENTRY;

        rc = mgs_find_or_make_fsdb(obd, mti->mti_fsname, &fsdb);
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                RETURN(rc);
        }

        down(&fsdb->fsdb_sem);

        /* set/check the new target index */
        rc = mgs_set_index(fsdb, mti);
        if (rc < 0) {
                CERROR("Can't get index (%d)\n", rc);
                GOTO(out_up, rc);
        }

        /* COMPAT_146 */
        if (mti->mti_flags & LDD_F_UPGRADE14) {
                if (rc == EALREADY) {
                        LCONSOLE_INFO("Found index %d for %s 1.4 log, "
                                      "upgrading\n", mti->mti_stripe_index,
                                      mti->mti_svname);
                } else {
                        LCONSOLE_ERROR_MSG(0x149, "Failed to find %s in the old"
                                           " client log. Apparently it is not "
                                           "part of this filesystem, or the old"
                                           " log is wrong.\nUse 'writeconf' on "
                                           "the MDT to force log regeneration."
                                           "\n", mti->mti_svname);
                        /* Not in client log?  Upgrade anyhow...*/
                        /* Argument against upgrading: reformat MDT,
                           upgrade OST, then OST will start but will be SKIPped
                           in client logs.  Maybe error now is better. */
                        /* RETURN(-EINVAL); */
                }
                /* end COMPAT_146 */
        } else {
                if (rc == EALREADY) {
                        /* This might be a params update, or a
                           local writeconf. (For "full" writeconf, the client
                           log won't have an entry for this target, so we
                           won't get here.) */
                        LCONSOLE_WARN("Found index %d for %s, updating log\n",
                                      mti->mti_stripe_index, mti->mti_svname);
                        /* We would like to mark old log sections as invalid
                           and add new log sections in the client and mdt logs.
                           But if we add new sections, then live clients will
                           get repeat setup instructions for already running
                           osc's. So don't update the client/mdt logs. */
                        mti->mti_flags &= ~LDD_F_UPDATE;
                }
        }

        if (mti->mti_flags &
            (LDD_F_VIRGIN | LDD_F_UPGRADE14 | LDD_F_WRITECONF)) {
                /* Generate a log from scratch */
                if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                        rc = mgs_write_log_mdt(obd, fsdb, mti);
                } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                        rc = mgs_write_log_ost(obd, fsdb, mti);
                } else {
                        CERROR("Unknown target type %#x, can't create log for "
                               "%s\n", mti->mti_flags, mti->mti_svname);
                }
                if (rc) {
                        CERROR("Can't write logs for %s (%d)\n",
                               mti->mti_svname, rc);
                        GOTO(out_up, rc);
                }
        } else {
                /* Just update the params from tunefs in mgs_write_log_params */
                CDEBUG(D_MGS, "Update params for %s\n", mti->mti_svname);
                mti->mti_flags |= LDD_F_PARAM;
        }

        rc = mgs_write_log_params(obd, fsdb, mti);

out_up:
        up(&fsdb->fsdb_sem);
        RETURN(rc);
}

/* COMPAT_146 */
/* Permanent settings of all parameters by writing into the appropriate
 * configuration logs.
 * A parameter with null value ("<param>='\0'") means to erase it out of
 * the logs.
 */
/* verify that we can handle the old config logs */
int mgs_upgrade_sv_14(struct obd_device *obd, struct mgs_target_info *mti)
{
        struct fs_db *fsdb;
        int rc = 0;
        ENTRY;

        /* Create ost log normally, as servers register.  Servers
           register with their old uuids (from last_rcvd), so old
           (MDT and client) logs should work.
         - new MDT won't know about old OSTs, only the ones that have
           registered, so we need the old MDT log to get the LOV right
           in order for old clients to work.
         - Old clients connect to the MDT, not the MGS, for their logs, and
           will therefore receive the old client log from the MDT /LOGS dir.
         - Old clients can continue to use and connect to old or new OSTs
         - New clients will contact the MGS for their log
        */

        LCONSOLE_INFO("upgrading server %s from pre-1.6\n", mti->mti_svname);
        server_mti_print("upgrade", mti);

        rc = mgs_find_or_make_fsdb(obd, mti->mti_fsname, &fsdb);
        if (rc)
                RETURN(rc);

        if (fsdb->fsdb_flags & FSDB_LOG_EMPTY) {
                LCONSOLE_ERROR_MSG(0x14a, "The old client log %s-client is "
                                   "missing.  Was tunefs.lustre successful?\n",
                                   mti->mti_fsname);
                RETURN(-ENOENT);
        }

        if (fsdb->fsdb_gen == 0) {
                /* There were no markers in the client log, meaning we have
                   not updated the logs for this fs */
                CDEBUG(D_MGS, "found old, unupdated client log\n");
        }

        if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                if (mgs_log_is_empty(obd, mti->mti_svname)) {
                        LCONSOLE_ERROR_MSG(0x14b, "The old MDT log %s is "
                                           "missing. Was tunefs.lustre "
                                           "successful?\n",
                                           mti->mti_svname);
                        RETURN(-ENOENT);
                }

                /* We're starting with an old uuid.  Assume old name for lov
                   as well since the lov entry already exists in the log. */
                CDEBUG(D_MGS, "old mds uuid %s\n", mti->mti_uuid);
                if (strncmp(mti->mti_uuid, fsdb->fsdb_mdtlov + 4,
                            strlen(fsdb->fsdb_mdtlov) - 4) != 0) {
                        CERROR("old mds uuid %s doesn't match log %s (%s)\n",
                               mti->mti_uuid, fsdb->fsdb_mdtlov,
                               fsdb->fsdb_mdtlov + 4);
                        RETURN(-EINVAL);
                }
        }

        if (!(fsdb->fsdb_flags & FSDB_OLDLOG14)) {
                LCONSOLE_ERROR_MSG(0x14c, "%s-client is supposedly an old log, "
                                   "but no old LOV or MDT was found. Consider "
                                   "updating the configuration with "
                                   "--writeconf.\n", mti->mti_fsname);
        }

        RETURN(rc);
}
/* end COMPAT_146 */

int mgs_erase_log(struct obd_device *obd, char *name)
{
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        struct llog_handle *llh;
        int rc = 0;

        ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc == 0) {
                llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
                rc = llog_destroy(llh);
                llog_free_handle(llh);
        }
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        llog_ctxt_put(ctxt);

        if (rc)
                CERROR("failed to clear log %s: %d\n", name, rc);

        return(rc);
}

/* erase all logs for the given fs */
int mgs_erase_logs(struct obd_device *obd, char *fsname)
{
        struct mgs_obd *mgs = &obd->u.mgs;
        static struct fs_db *fsdb;
        struct list_head dentry_list;
        struct l_linux_dirent *dirent, *n;
        int rc, len = strlen(fsname);
        char *suffix;
        ENTRY;

        /* Find all the logs in the CONFIGS directory */
        rc = class_dentry_readdir(obd, mgs->mgs_configs_dir,
                                  mgs->mgs_vfsmnt, &dentry_list);
        if (rc) {
                CERROR("Can't read %s dir\n", MOUNT_CONFIGS_DIR);
                RETURN(rc);
        }

        down(&mgs->mgs_sem);

        /* Delete the fs db */
        fsdb = mgs_find_fsdb(obd, fsname);
        if (fsdb)
                mgs_free_fsdb(obd, fsdb);

        list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                list_del(&dirent->lld_list);
                suffix = strrchr(dirent->lld_name, '-');
                if (suffix != NULL) {
                        if ((len == suffix - dirent->lld_name) &&
                            (strncmp(fsname, dirent->lld_name, len) == 0)) {
                                CDEBUG(D_MGS, "Removing log %s\n",
                                       dirent->lld_name);
                                mgs_erase_log(obd, dirent->lld_name);
                        }
                }
                OBD_FREE(dirent, sizeof(*dirent));
        }

        up(&mgs->mgs_sem);

        RETURN(rc);
}

/* from llog_swab */
static void print_lustre_cfg(struct lustre_cfg *lcfg)
{
        int i;
        ENTRY;

        CDEBUG(D_MGS, "lustre_cfg: %p\n", lcfg);
        CDEBUG(D_MGS, "\tlcfg->lcfg_version: %#x\n", lcfg->lcfg_version);

        CDEBUG(D_MGS, "\tlcfg->lcfg_command: %#x\n", lcfg->lcfg_command);
        CDEBUG(D_MGS, "\tlcfg->lcfg_num: %#x\n", lcfg->lcfg_num);
        CDEBUG(D_MGS, "\tlcfg->lcfg_flags: %#x\n", lcfg->lcfg_flags);
        CDEBUG(D_MGS, "\tlcfg->lcfg_nid: %s\n", libcfs_nid2str(lcfg->lcfg_nid));

        CDEBUG(D_MGS, "\tlcfg->lcfg_bufcount: %d\n", lcfg->lcfg_bufcount);
        if (lcfg->lcfg_bufcount < LUSTRE_CFG_MAX_BUFCOUNT)
                for (i = 0; i < lcfg->lcfg_bufcount; i++) {
                        CDEBUG(D_MGS, "\tlcfg->lcfg_buflens[%d]: %d %s\n",
                               i, lcfg->lcfg_buflens[i],
                               lustre_cfg_string(lcfg, i));
                }
        EXIT;
}

/* Set a permanent (config log) param for a target or fs
 * \param lcfg buf0 may contain the device (testfs-MDT0000) name
 *             buf1 contains the single parameter
 */
int mgs_setparam(struct obd_device *obd, struct lustre_cfg *lcfg, char *fsname)
{
        struct fs_db *fsdb;
        struct mgs_target_info *mti;
        char *devname, *param;
        char *ptr, *tmp;
        __u32 index;
        int rc = 0;
        ENTRY;

        print_lustre_cfg(lcfg);

        /* lustre, lustre-mdtlov, lustre-client, lustre-MDT0000 */
        devname = lustre_cfg_string(lcfg, 0);
        param = lustre_cfg_string(lcfg, 1);
        if (!devname) {
                /* Assume device name embedded in param:
                   lustre-OST0000.osc.max_dirty_mb=32 */
                ptr = strchr(param, '.');
                if (ptr) {
                        devname = param;
                        *ptr = 0;
                        param = ptr + 1;
                }
        }
        if (!devname) {
                LCONSOLE_ERROR_MSG(0x14d, "No target specified: %s\n", param);
                RETURN(-ENOSYS);
        }

        /* Extract fsname */
        ptr = strrchr(devname, '-');
        memset(fsname, 0, MTI_NAME_MAXLEN);
        if (ptr && (server_name2index(ptr, &index, NULL) >= 0)) {
                /* param related to llite isn't allowed to set by OST or MDT */
                if (strncmp(param, PARAM_LLITE, sizeof(PARAM_LLITE)) == 0)
                        RETURN(-EINVAL);

                strncpy(fsname, devname, ptr - devname);
        } else {
                /* assume devname is the fsname */
                strncpy(fsname, devname, MTI_NAME_MAXLEN);
        }
        fsname[MTI_NAME_MAXLEN - 1] = 0;
        CDEBUG(D_MGS, "setparam fs='%s' device='%s'\n", fsname, devname);

        rc = mgs_find_or_make_fsdb(obd, fsname, &fsdb);
        if (rc)
                RETURN(rc);
        if (fsdb->fsdb_flags & FSDB_LOG_EMPTY) {
                CERROR("No filesystem targets for %s.  cfg_device from lctl "
                       "is '%s'\n", fsname, devname);
                mgs_free_fsdb(obd, fsdb);
                RETURN(-EINVAL);
        }

        /* Create a fake mti to hold everything */
        OBD_ALLOC_PTR(mti);
        if (!mti)
                GOTO(out, rc = -ENOMEM);
        strncpy(mti->mti_fsname, fsname, MTI_NAME_MAXLEN);
        strncpy(mti->mti_svname, devname, MTI_NAME_MAXLEN);
        strncpy(mti->mti_params, param, sizeof(mti->mti_params));
        rc = server_name2index(mti->mti_svname, &mti->mti_stripe_index, &tmp);
        if (rc < 0)
                /* Not a valid server; may be only fsname */
                rc = 0;
        else
                /* Strip -osc or -mdc suffix from svname */
                if (server_make_name(rc, mti->mti_stripe_index, mti->mti_fsname,
                                     mti->mti_svname))
                        GOTO(out, rc = -EINVAL);

        mti->mti_flags = rc | LDD_F_PARAM;

        down(&fsdb->fsdb_sem);
        rc = mgs_write_log_params(obd, fsdb, mti);
        up(&fsdb->fsdb_sem);

out:
        OBD_FREE_PTR(mti);
        RETURN(rc);
}


static int mgs_write_log_pool(struct obd_device *obd, char *logname, struct fs_db *fsdb,
                       char *lovname,
                       enum lcfg_command_type cmd,
                       char *poolname, char *fsname,
                       char *ostname, char *comment)
{
        struct llog_handle *llh = NULL;
        int rc;

        rc = record_start_log(obd, &llh, logname);
        if (rc)
                RETURN(rc);
        rc = record_marker(obd, llh, fsdb, CM_START, lovname, comment);
        record_base(obd, llh, lovname, 0, cmd, poolname, fsname, ostname, 0);
        rc = record_marker(obd, llh, fsdb, CM_END, lovname, comment);
        rc = record_end_log(obd, &llh);

        return(rc);
}

int mgs_pool_cmd(struct obd_device *obd, enum lcfg_command_type cmd,
                 char *fsname, char *poolname, char *ostname)
{
        struct fs_db *fsdb;
        char mdt_index[16];
        char *lovname;
        char *logname;
        char *label, *canceled_label = NULL;
        int label_sz;
        struct mgs_target_info *mti;
        int rc;
        ENTRY;

        rc = mgs_find_or_make_fsdb(obd, fsname, &fsdb);
        if (rc) {
                CERROR("Can't get db for %s\n", fsname);
                RETURN(rc);
        }
        if (fsdb->fsdb_flags & FSDB_LOG_EMPTY) {
                CERROR("%s is not defined\n", fsname);
                mgs_free_fsdb(obd, fsdb);
                RETURN(-EINVAL);
        }

        label_sz = 10 + strlen(fsname) + strlen(poolname);

        /* check if ostname match fsname */
        if (ostname != NULL) {
                char *ptr;

                ptr = strrchr(ostname, '-');
                if ((ptr == NULL) ||
                    (strncmp(fsname, ostname, ptr-ostname) != 0))
                        RETURN(-EINVAL);
                label_sz += strlen(ostname);
        }

        OBD_ALLOC(label, label_sz);
        if (label == NULL)
                RETURN(-ENOMEM);

        switch(cmd) {
        case LCFG_POOL_NEW: {
                sprintf(label,
                        "new %s.%s", fsname, poolname);
                break;
        }
        case LCFG_POOL_ADD: {
                sprintf(label,
                        "add %s.%s.%s", fsname, poolname, ostname);
                break;
        }
        case LCFG_POOL_REM: {
                OBD_ALLOC(canceled_label, label_sz);
                if (canceled_label == NULL)
                         RETURN(-ENOMEM);
                sprintf(label,
                        "rem %s.%s.%s", fsname, poolname, ostname);
                sprintf(canceled_label,
                        "add %s.%s.%s", fsname, poolname, ostname);
                break;
        }
        case LCFG_POOL_DEL: {
                OBD_ALLOC(canceled_label, label_sz);
                if (canceled_label == NULL)
                         RETURN(-ENOMEM);
                sprintf(label,
                        "del %s.%s", fsname, poolname);
                sprintf(canceled_label,
                        "new %s.%s", fsname, poolname);
                break;
        }
        default: {
                break;
        }
        }

        down(&fsdb->fsdb_sem);

        sprintf(mdt_index, "-MDT%04x", 0);
        name_create(&logname, fsname, mdt_index);
        name_create(&lovname, fsdb->fsdb_mdtlov, "");

        mti = NULL;
        if (canceled_label != NULL) {
                OBD_ALLOC(mti, sizeof(*mti));
                if (mti != NULL) {
                        strcpy(mti->mti_svname, "lov pool");
                        mgs_modify(obd, fsdb, mti, logname, lovname,
                                   canceled_label, CM_SKIP);
                }
        }

        mgs_write_log_pool(obd, logname, fsdb, lovname,
                           cmd, fsname, poolname, ostname, label);
        name_destroy(&logname);

        name_create(&logname, fsname, "-client");
        if (canceled_label != NULL) {
                mgs_modify(obd, fsdb, mti, logname, lovname,
                           canceled_label, CM_SKIP);
        }
        mgs_write_log_pool(obd, logname, fsdb, fsdb->fsdb_clilov,
                           cmd, fsname, poolname, ostname, label);
        name_destroy(&logname);
        name_destroy(&lovname);

        up(&fsdb->fsdb_sem);

        OBD_FREE(label, label_sz);
        if (canceled_label != NULL)
                OBD_FREE(canceled_label, label_sz);

        if (mti != NULL)
                OBD_FREE(mti, sizeof(*mti));

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



#endif
