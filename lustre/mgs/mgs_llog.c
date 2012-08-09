/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, Whamcloud, Inc.
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
#include <lustre_sec.h>
#include <lquota.h>
#include "mgs_internal.h"

/********************** Class functions ********************/

/* Caller must list_del and OBD_FREE each dentry from the list */
int class_dentry_readdir(const struct lu_env *env,
			 struct mgs_device *mgs, cfs_list_t *dentry_list)
{
        /* see mds_cleanup_pending */
        struct lvfs_run_ctxt saved;
        struct file *file;
        struct dentry *dentry;
        struct vfsmount *mnt;
        int rc = 0;
        ENTRY;

	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	dentry = dget(mgs->mgs_configs_dir);
        if (IS_ERR(dentry))
                GOTO(out_pop, rc = PTR_ERR(dentry));
	mnt = mntget(mgs->mgs_vfsmnt);
        if (IS_ERR(mnt)) {
                l_dput(dentry);
                GOTO(out_pop, rc = PTR_ERR(mnt));
        }

        file = ll_dentry_open(dentry, mnt, O_RDONLY, current_cred());
        if (IS_ERR(file))
                /* dentry_open_it() drops the dentry, mnt refs */
                GOTO(out_pop, rc = PTR_ERR(file));

        CFS_INIT_LIST_HEAD(dentry_list);
        rc = l_readdir(file, dentry_list);
        filp_close(file, 0);
        /*  filp_close->fput() drops the dentry, mnt refs */

out_pop:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
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

struct mgs_fsdb_handler_data
{
        struct fs_db   *fsdb;
        __u32           ver;
};

/* from the (client) config log, figure out:
        1. which ost's/mdt's are configured (by index)
        2. what the last config step is
        3. COMPAT_146 lov name
        4. COMPAT_146 mdt lov name
        5. COMPAT_146 mdc name
        6. COMPAT_18 osc name
*/
/* It might be better to have a separate db file, instead of parsing the info
   out of the client log.  This is slow and potentially error-prone. */
static int mgs_fsdb_handler(const struct lu_env *env, struct llog_handle *llh,
			    struct llog_rec_hdr *rec, void *data)
{
	struct mgs_fsdb_handler_data *d = data;
        struct fs_db *fsdb = d->fsdb;
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
                cfs_set_bit(index, fsdb->fsdb_ost_index_map);
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
                cfs_set_bit(index, fsdb->fsdb_mdt_index_map);
                fsdb->fsdb_mdt_count ++;
        }

        /* COMPAT_146 */
        /* figure out the old LOV name. fsdb_gen = 0 means old log */
        /* #01 L attach 0:lov_mdsA 1:lov 2:cdbe9_lov_mdsA_dc8cf7f3bb */
        if ((fsdb->fsdb_gen == 0) && (lcfg->lcfg_command == LCFG_ATTACH) &&
            (strcmp(lustre_cfg_string(lcfg, 1), LUSTRE_LOV_NAME) == 0)) {
                cfs_set_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags);
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
                cfs_set_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags);
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

        /*
         * compat to 1.8, check osc name used by MDT0 to OSTs, bz18548.
         */
        if (!cfs_test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags) &&
            lcfg->lcfg_command == LCFG_ATTACH &&
            strcmp(lustre_cfg_string(lcfg, 1), LUSTRE_OSC_NAME) == 0) {
                if (OBD_OCD_VERSION_MAJOR(d->ver) == 1 &&
                    OBD_OCD_VERSION_MINOR(d->ver) <= 8) {
                        CWARN("MDT using 1.8 OSC name scheme\n");
                        cfs_set_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags);
                }
        }

        if (lcfg->lcfg_command == LCFG_MARKER) {
                struct cfg_marker *marker;
                marker = lustre_cfg_buf(lcfg, 1);

                d->ver = marker->cm_vers;

                /* Keep track of the latest marker step */
                fsdb->fsdb_gen = max(fsdb->fsdb_gen, marker->cm_step);
        }

        RETURN(rc);
}

/* fsdb->fsdb_mutex is already held  in mgs_find_or_make_fsdb*/
static int mgs_get_fsdb_from_llog(const struct lu_env *env,
				  struct mgs_device *mgs,
				  struct fs_db *fsdb)
{
        char *logname;
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        struct mgs_fsdb_handler_data d = { fsdb, 0 };
        int rc, rc2;
        ENTRY;

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
        name_create(&logname, fsdb->fsdb_name, "-client");
        cfs_mutex_lock(&fsdb->fsdb_mutex);
	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	rc = llog_open_create(NULL, ctxt, &loghandle, NULL, logname);
	if (rc)
		GOTO(out_pop, rc);

	rc = llog_init_handle(NULL, loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	if (llog_get_size(loghandle) <= 1)
		cfs_set_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags);

	rc = llog_process_or_fork(env, loghandle, mgs_fsdb_handler, (void *)&d,
				  NULL, false);
	CDEBUG(D_INFO, "get_db = %d\n", rc);
out_close:
	rc2 = llog_close(NULL, loghandle);
        if (!rc)
                rc = rc2;
out_pop:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
        cfs_mutex_unlock(&fsdb->fsdb_mutex);
        name_destroy(&logname);
        llog_ctxt_put(ctxt);

        RETURN(rc);
}

static void mgs_free_fsdb_srpc(struct fs_db *fsdb)
{
        struct mgs_tgt_srpc_conf *tgtconf;

        /* free target-specific rules */
        while (fsdb->fsdb_srpc_tgt) {
                tgtconf = fsdb->fsdb_srpc_tgt;
                fsdb->fsdb_srpc_tgt = tgtconf->mtsc_next;

                LASSERT(tgtconf->mtsc_tgt);

                sptlrpc_rule_set_free(&tgtconf->mtsc_rset);
                OBD_FREE(tgtconf->mtsc_tgt, strlen(tgtconf->mtsc_tgt) + 1);
                OBD_FREE_PTR(tgtconf);
        }

        /* free general rules */
        sptlrpc_rule_set_free(&fsdb->fsdb_srpc_gen);
}

struct fs_db *mgs_find_fsdb(struct mgs_device *mgs, char *fsname)
{
        struct fs_db *fsdb;
        cfs_list_t *tmp;

        cfs_list_for_each(tmp, &mgs->mgs_fs_db_list) {
                fsdb = cfs_list_entry(tmp, struct fs_db, fsdb_list);
                if (strcmp(fsdb->fsdb_name, fsname) == 0)
                        return fsdb;
        }
        return NULL;
}

/* caller must hold the mgs->mgs_fs_db_lock */
static struct fs_db *mgs_new_fsdb(const struct lu_env *env,
				  struct mgs_device *mgs, char *fsname)
{
        struct fs_db *fsdb;
        int rc;
        ENTRY;

        if (strlen(fsname) >= sizeof(fsdb->fsdb_name)) {
                CERROR("fsname %s is too long\n", fsname);
                RETURN(NULL);
        }

        OBD_ALLOC_PTR(fsdb);
        if (!fsdb)
                RETURN(NULL);

        strcpy(fsdb->fsdb_name, fsname);
        cfs_mutex_init(&fsdb->fsdb_mutex);
        cfs_set_bit(FSDB_UDESC, &fsdb->fsdb_flags);

        if (strcmp(fsname, MGSSELF_NAME) == 0) {
                cfs_set_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags);
        } else {
                OBD_ALLOC(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
                OBD_ALLOC(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
                if (!fsdb->fsdb_ost_index_map || !fsdb->fsdb_mdt_index_map) {
                        CERROR("No memory for index maps\n");
                        GOTO(err, 0);
                }

                rc = name_create(&fsdb->fsdb_mdtlov, fsname, "-mdtlov");
                if (rc)
                        GOTO(err, rc);
                rc = name_create(&fsdb->fsdb_mdtlmv, fsname, "-mdtlmv");
                if (rc)
                        GOTO(err, rc);
                rc = name_create(&fsdb->fsdb_clilov, fsname, "-clilov");
                if (rc)
                        GOTO(err, rc);
                rc = name_create(&fsdb->fsdb_clilmv, fsname, "-clilmv");
                if (rc)
                        GOTO(err, rc);

                /* initialise data for NID table */
		mgs_ir_init_fs(env, mgs, fsdb);

		lproc_mgs_add_live(mgs, fsdb);
        }

        cfs_list_add(&fsdb->fsdb_list, &mgs->mgs_fs_db_list);

        RETURN(fsdb);
err:
        if (fsdb->fsdb_ost_index_map)
                OBD_FREE(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
        if (fsdb->fsdb_mdt_index_map)
                OBD_FREE(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
        name_destroy(&fsdb->fsdb_clilov);
        name_destroy(&fsdb->fsdb_clilmv);
        name_destroy(&fsdb->fsdb_mdtlov);
        name_destroy(&fsdb->fsdb_mdtlmv);
        OBD_FREE_PTR(fsdb);
        RETURN(NULL);
}

static void mgs_free_fsdb(struct mgs_device *mgs, struct fs_db *fsdb)
{
        /* wait for anyone with the sem */
        cfs_mutex_lock(&fsdb->fsdb_mutex);
	lproc_mgs_del_live(mgs, fsdb);
        cfs_list_del(&fsdb->fsdb_list);

        /* deinitialize fsr */
	mgs_ir_fini_fs(mgs, fsdb);

        if (fsdb->fsdb_ost_index_map)
                OBD_FREE(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
        if (fsdb->fsdb_mdt_index_map)
                OBD_FREE(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
        name_destroy(&fsdb->fsdb_clilov);
        name_destroy(&fsdb->fsdb_clilmv);
        name_destroy(&fsdb->fsdb_mdtlov);
        name_destroy(&fsdb->fsdb_mdtlmv);
        name_destroy(&fsdb->fsdb_mdc);
        mgs_free_fsdb_srpc(fsdb);
        cfs_mutex_unlock(&fsdb->fsdb_mutex);
        OBD_FREE_PTR(fsdb);
}

int mgs_init_fsdb_list(struct mgs_device *mgs)
{
        CFS_INIT_LIST_HEAD(&mgs->mgs_fs_db_list);
        return 0;
}

int mgs_cleanup_fsdb_list(struct mgs_device *mgs)
{
        struct fs_db *fsdb;
        cfs_list_t *tmp, *tmp2;
        cfs_mutex_lock(&mgs->mgs_mutex);
        cfs_list_for_each_safe(tmp, tmp2, &mgs->mgs_fs_db_list) {
                fsdb = cfs_list_entry(tmp, struct fs_db, fsdb_list);
		mgs_free_fsdb(mgs, fsdb);
        }
        cfs_mutex_unlock(&mgs->mgs_mutex);
        return 0;
}

int mgs_find_or_make_fsdb(const struct lu_env *env,
			  struct mgs_device *mgs, char *name,
                          struct fs_db **dbh)
{
        struct fs_db *fsdb;
        int rc = 0;

        cfs_mutex_lock(&mgs->mgs_mutex);
	fsdb = mgs_find_fsdb(mgs, name);
        if (fsdb) {
                cfs_mutex_unlock(&mgs->mgs_mutex);
                *dbh = fsdb;
                return 0;
        }

        CDEBUG(D_MGS, "Creating new db\n");
	fsdb = mgs_new_fsdb(env, mgs, name);
        cfs_mutex_unlock(&mgs->mgs_mutex);
        if (!fsdb)
                return -ENOMEM;

        if (!cfs_test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags)) {
                /* populate the db from the client llog */
		rc = mgs_get_fsdb_from_llog(env, mgs, fsdb);
                if (rc) {
                        CERROR("Can't get db from client log %d\n", rc);
			mgs_free_fsdb(mgs, fsdb);
                        return rc;
                }
        }

        /* populate srpc rules from params llog */
	rc = mgs_get_fsdb_srpc_from_llog(env, mgs, fsdb);
        if (rc) {
                CERROR("Can't get db from params log %d\n", rc);
		mgs_free_fsdb(mgs, fsdb);
                return rc;
        }

        *dbh = fsdb;

        return 0;
}

/* 1 = index in use
   0 = index unused
   -1= empty client log */
int mgs_check_index(const struct lu_env *env,
		    struct mgs_device *mgs,
		    struct mgs_target_info *mti)
{
        struct fs_db *fsdb;
        void *imap;
        int rc = 0;
        ENTRY;

        LASSERT(!(mti->mti_flags & LDD_F_NEED_INDEX));

	rc = mgs_find_or_make_fsdb(env, mgs, mti->mti_fsname, &fsdb);
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                RETURN(rc);
        }

        if (cfs_test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags))
                RETURN(-1);

        if (mti->mti_flags & LDD_F_SV_TYPE_OST)
                imap = fsdb->fsdb_ost_index_map;
        else if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
                imap = fsdb->fsdb_mdt_index_map;
        else
                RETURN(-EINVAL);

        if (cfs_test_bit(mti->mti_stripe_index, imap))
                RETURN(1);
        RETURN(0);
}

static __inline__ int next_index(void *index_map, int map_len)
{
        int i;
        for (i = 0; i < map_len * 8; i++)
                 if (!cfs_test_bit(i, index_map)) {
                         return i;
                 }
        CERROR("max index %d exceeded.\n", i);
        return -1;
}

/* Return codes:
        0  newly marked as in use
        <0 err
        +EALREADY for update of an old index */
static int mgs_set_index(const struct lu_env *env,
			 struct mgs_device *mgs,
			 struct mgs_target_info *mti)
{
        struct fs_db *fsdb;
        void *imap;
        int rc = 0;
        ENTRY;

	rc = mgs_find_or_make_fsdb(env, mgs, mti->mti_fsname, &fsdb);
        if (rc) {
                CERROR("Can't get db for %s\n", mti->mti_fsname);
                RETURN(rc);
        }

        if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                imap = fsdb->fsdb_ost_index_map;
        } else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                imap = fsdb->fsdb_mdt_index_map;
                if (fsdb->fsdb_mdt_count >= MAX_MDT_COUNT) {
                        LCONSOLE_ERROR_MSG(0x13f, "The max mdt count"
                                           "is %d\n", (int)MAX_MDT_COUNT);
                        RETURN(-ERANGE);
                }
        } else {
                RETURN(-EINVAL);
        }

        if (mti->mti_flags & LDD_F_NEED_INDEX) {
                rc = next_index(imap, INDEX_MAP_SIZE);
                if (rc == -1)
                        RETURN(-ERANGE);
                mti->mti_stripe_index = rc;
                if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
                        fsdb->fsdb_mdt_count ++;
        }

        if (mti->mti_stripe_index >= INDEX_MAP_SIZE * 8) {
                LCONSOLE_ERROR_MSG(0x13f, "Server %s requested index %d, "
                                   "but the max index is %d.\n",
                                   mti->mti_svname, mti->mti_stripe_index,
                                   INDEX_MAP_SIZE * 8);
                RETURN(-ERANGE);
        }

        if (cfs_test_bit(mti->mti_stripe_index, imap)) {
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

        cfs_set_bit(mti->mti_stripe_index, imap);
        cfs_clear_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags);
	server_make_name(mti->mti_flags & ~(LDD_F_VIRGIN | LDD_F_WRITECONF),
			 mti->mti_stripe_index, mti->mti_fsname, mti->mti_svname);

        CDEBUG(D_MGS, "Set index for %s to %d\n", mti->mti_svname,
               mti->mti_stripe_index);

        RETURN(0);
}

struct mgs_modify_lookup {
        struct cfg_marker mml_marker;
        int               mml_modified;
};

static int mgs_modify_handler(const struct lu_env *env,
			      struct llog_handle *llh,
			      struct llog_rec_hdr *rec, void *data)
{
	struct mgs_modify_lookup *mml = data;
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
		rc = llog_write_rec(NULL, llh, rec, NULL, 0, (void *)lcfg,
				    rec->lrh_index);
                if (!rc)
                         mml->mml_modified++;
        }

        RETURN(rc);
}

/* Modify an existing config log record (for CM_SKIP or CM_EXCLUDE) */
static int mgs_modify(const struct lu_env *env, struct mgs_device *mgs,
		      struct fs_db *fsdb, struct mgs_target_info *mti,
		      char *logname, char *devname, char *comment, int flags)
{
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        struct mgs_modify_lookup *mml;
        int rc, rc2;
        ENTRY;

        CDEBUG(D_MGS, "modify %s/%s/%s fl=%x\n", logname, devname, comment,
               flags);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	rc = llog_open(NULL, ctxt, &loghandle, NULL, logname,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out_pop, rc);
	}

	rc = llog_init_handle(NULL, loghandle, LLOG_F_IS_PLAIN, NULL);
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
	rc = llog_process_or_fork(env, loghandle, mgs_modify_handler,
				  (void *)mml, NULL, false);
        if (!rc && !mml->mml_modified)
                rc = -ENODEV;
        OBD_FREE_PTR(mml);

out_close:
	rc2 = llog_close(NULL, loghandle);
        if (!rc)
                rc = rc2;
out_pop:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
        if (rc && rc != -ENODEV)
                CERROR("modify %s/%s failed %d\n",
                       mti->mti_svname, comment, rc);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

/******************** config log recording functions *********************/

static int record_lcfg(const struct lu_env *env, struct llog_handle *llh,
                         struct lustre_cfg *lcfg)
{
        struct lvfs_run_ctxt   saved;
        struct llog_rec_hdr    rec;
        int buflen, rc;
	struct obd_device *obd = llh->lgh_ctxt->loc_obd;

        if (!lcfg || !llh)
                return -ENOMEM;

        LASSERT(llh->lgh_ctxt);

        buflen = lustre_cfg_len(lcfg->lcfg_bufcount,
                                lcfg->lcfg_buflens);
        rec.lrh_len = llog_data_len(buflen);
        rec.lrh_type = OBD_CFG_REC;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        /* idx = -1 means append */
	rc = llog_write_rec(NULL, llh, &rec, NULL, 0, (void *)lcfg, -1);
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        if (rc)
                CERROR("failed %d\n", rc);
        return rc;
}

static int record_base(const struct lu_env *env, struct llog_handle *llh,
                     char *cfgname, lnet_nid_t nid, int cmd,
                     char *s1, char *s2, char *s3, char *s4)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	struct lustre_cfg     *lcfg;
	int rc;

	CDEBUG(D_MGS, "lcfg %s %#x %s %s %s %s\n", cfgname,
	       cmd, s1, s2, s3, s4);

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, cfgname);
	if (s1)
		lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 1, s1);
	if (s2)
		lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 2, s2);
	if (s3)
		lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 3, s3);
	if (s4)
		lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 4, s4);

	lcfg = lustre_cfg_new(cmd, &mgi->mgi_bufs);
	if (!lcfg)
		return -ENOMEM;
	lcfg->lcfg_nid = nid;

	rc = record_lcfg(env, llh, lcfg);

	lustre_cfg_free(lcfg);

        if (rc) {
                CERROR("error %d: lcfg %s %#x %s %s %s %s\n", rc, cfgname,
                       cmd, s1, s2, s3, s4);
        }
	return rc;
}


static inline int record_add_uuid(const struct lu_env *env,
				  struct llog_handle *llh,
				  uint64_t nid, char *uuid)
{
	return record_base(env, llh, NULL, nid, LCFG_ADD_UUID, uuid, 0, 0, 0);

}

static inline int record_add_conn(const struct lu_env *env,
				  struct llog_handle *llh,
				  char *devname, char *uuid)
{
	return record_base(env, llh, devname, 0, LCFG_ADD_CONN, uuid, 0, 0, 0);
}

static inline int record_attach(const struct lu_env *env,
				struct llog_handle *llh, char *devname,
				char *type, char *uuid)
{
	return record_base(env, llh,devname, 0, LCFG_ATTACH, type, uuid, 0, 0);
}

static inline int record_setup(const struct lu_env *env,
			       struct llog_handle *llh, char *devname,
			       char *s1, char *s2, char *s3, char *s4)
{
	return record_base(env, llh, devname, 0, LCFG_SETUP, s1, s2, s3, s4);
}

static int record_lov_setup(const struct lu_env *env, struct llog_handle *llh,
			    char *devname, struct lov_desc *desc)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	struct lustre_cfg *lcfg;
	int rc;

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, devname);
	lustre_cfg_bufs_set(&mgi->mgi_bufs, 1, desc, sizeof(*desc));
	lcfg = lustre_cfg_new(LCFG_SETUP, &mgi->mgi_bufs);
	if (!lcfg)
		return -ENOMEM;
	rc = record_lcfg(env, llh, lcfg);

	lustre_cfg_free(lcfg);
	return rc;
}

static int record_lmv_setup(const struct lu_env *env, struct llog_handle *llh,
                            char *devname, struct lmv_desc *desc)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	struct lustre_cfg *lcfg;
	int rc;

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, devname);
	lustre_cfg_bufs_set(&mgi->mgi_bufs, 1, desc, sizeof(*desc));
	lcfg = lustre_cfg_new(LCFG_SETUP, &mgi->mgi_bufs);

	rc = record_lcfg(env, llh, lcfg);

	lustre_cfg_free(lcfg);
	return rc;
}

static inline int record_mdc_add(const struct lu_env *env,
                                 struct llog_handle *llh,
                                 char *logname, char *mdcuuid,
                                 char *mdtuuid, char *index,
                                 char *gen)
{
	return record_base(env,llh,logname,0,LCFG_ADD_MDC,
                           mdtuuid,index,gen,mdcuuid);
}

static inline int record_lov_add(const struct lu_env *env,
                                 struct llog_handle *llh,
                                 char *lov_name, char *ost_uuid,
                                 char *index, char *gen)
{
	return record_base(env,llh,lov_name,0,LCFG_LOV_ADD_OBD,
                           ost_uuid,index,gen,0);
}

static inline int record_mount_opt(const struct lu_env *env,
                                   struct llog_handle *llh,
                                   char *profile, char *lov_name,
                                   char *mdc_name)
{
	return record_base(env,llh,NULL,0,LCFG_MOUNTOPT,
                           profile,lov_name,mdc_name,0);
}

static int record_marker(const struct lu_env *env,
			 struct llog_handle *llh,
                         struct fs_db *fsdb, __u32 flags,
                         char *tgtname, char *comment)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	struct lustre_cfg *lcfg;
	int rc;

	if (flags & CM_START)
		fsdb->fsdb_gen++;
	mgi->mgi_marker.cm_step = fsdb->fsdb_gen;
	mgi->mgi_marker.cm_flags = flags;
	mgi->mgi_marker.cm_vers = LUSTRE_VERSION_CODE;
	strncpy(mgi->mgi_marker.cm_tgtname, tgtname,
		sizeof(mgi->mgi_marker.cm_tgtname));
	strncpy(mgi->mgi_marker.cm_comment, comment,
		sizeof(mgi->mgi_marker.cm_comment));
	mgi->mgi_marker.cm_createtime = cfs_time_current_sec();
	mgi->mgi_marker.cm_canceltime = 0;
	lustre_cfg_bufs_reset(&mgi->mgi_bufs, NULL);
	lustre_cfg_bufs_set(&mgi->mgi_bufs, 1, &mgi->mgi_marker,
			    sizeof(mgi->mgi_marker));
	lcfg = lustre_cfg_new(LCFG_MARKER, &mgi->mgi_bufs);
	if (!lcfg)
		return -ENOMEM;
	rc = record_lcfg(env, llh, lcfg);

	lustre_cfg_free(lcfg);
	return rc;
}

static int record_start_log(const struct lu_env *env,
			    struct mgs_device *mgs,
                            struct llog_handle **llh, char *name)
{
        static struct obd_uuid cfg_uuid = { .uuid = "config_uuid" };
        struct lvfs_run_ctxt saved;
        struct llog_ctxt *ctxt;
        int rc = 0;

        if (*llh)
                GOTO(out, rc = -EBUSY);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        if (!ctxt)
                GOTO(out, rc = -ENODEV);
	LASSERT(ctxt->loc_obd == mgs->mgs_obd);

	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	rc = llog_open_create(NULL, ctxt, llh, NULL, name);
	if (rc)
		GOTO(out_ctxt, rc);
	rc = llog_init_handle(NULL, *llh, LLOG_F_IS_PLAIN, &cfg_uuid);
	if (rc) {
		llog_close(NULL, *llh);
		*llh = NULL;
	}
out_ctxt:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	llog_ctxt_put(ctxt);
out:
	if (rc)
		CERROR("Can't start log %s: %d\n", name, rc);
	RETURN(rc);
}

static int record_end_log(const struct lu_env *env, struct llog_handle **llh)
{
        struct lvfs_run_ctxt saved;
	struct obd_device *obd = (*llh)->lgh_ctxt->loc_obd;
        int rc = 0;

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);

	rc = llog_close(NULL, *llh);
        *llh = NULL;

        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
        RETURN(rc);
}

static int mgs_log_is_empty(const struct lu_env *env,
			    struct mgs_device *mgs, char *name)
{
        struct lvfs_run_ctxt saved;
        struct llog_handle *llh;
        struct llog_ctxt *ctxt;
        int rc = 0;

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	rc = llog_open(NULL, ctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out_ctxt, rc);
	}

	llog_init_handle(NULL, llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);
	rc = llog_get_size(llh);

out_close:
	llog_close(NULL, llh);
out_ctxt:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	llog_ctxt_put(ctxt);
	/* header is record 1 */
	return (rc <= 1);
}

/******************** config "macros" *********************/

/* write an lcfg directly into a log (with markers) */
static int mgs_write_log_direct(const struct lu_env *env,
				struct mgs_device *mgs, struct fs_db *fsdb,
                                char *logname, struct lustre_cfg *lcfg,
                                char *devname, char *comment)
{
        struct llog_handle *llh = NULL;
        int rc;
        ENTRY;

        if (!lcfg)
                RETURN(-ENOMEM);

	rc = record_start_log(env, mgs, &llh, logname);
        if (rc)
                RETURN(rc);

        /* FIXME These should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, devname, comment);

	rc = record_lcfg(env, llh, lcfg);

	rc = record_marker(env, llh, fsdb, CM_END, devname, comment);
	rc = record_end_log(env, &llh);

        RETURN(rc);
}

/* write the lcfg in all logs for the given fs */
int mgs_write_log_direct_all(const struct lu_env *env,
			     struct mgs_device *mgs,
			     struct fs_db *fsdb,
			     struct mgs_target_info *mti,
			     struct lustre_cfg *lcfg,
			     char *devname, char *comment,
			     int server_only)
{
        cfs_list_t dentry_list;
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
	if (mgs_log_is_empty(env, mgs, logname)) {
		struct llog_handle *llh = NULL;
		rc = record_start_log(env, mgs, &llh, logname);
		record_end_log(env, &llh);
        }
        name_destroy(&logname);
        if (rc)
                RETURN(rc);

        /* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &dentry_list);
        if (rc) {
                CERROR("Can't read %s dir\n", MOUNT_CONFIGS_DIR);
                RETURN(rc);
        }

        /* Could use fsdb index maps instead of directory listing */
        cfs_list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                cfs_list_del(&dirent->lld_list);
                /* don't write to sptlrpc rule log */
		if (strstr(dirent->lld_name, "-sptlrpc") != NULL)
			goto next;

		/* caller wants write server logs only */
		if (server_only && strstr(dirent->lld_name, "-client") != NULL)
			goto next;

		if (strncmp(fsname, dirent->lld_name, len) == 0) {
                        CDEBUG(D_MGS, "Changing log %s\n", dirent->lld_name);
                        /* Erase any old settings of this same parameter */
			mgs_modify(env, mgs, fsdb, mti, dirent->lld_name,
				   devname, comment, CM_SKIP);
                        /* Write the new one */
                        if (lcfg) {
				rc = mgs_write_log_direct(env, mgs, fsdb,
                                                          dirent->lld_name,
                                                          lcfg, devname,
                                                          comment);
                                if (rc)
                                        CERROR("err %d writing log %s\n", rc,
                                               dirent->lld_name);
                        }
                }
next:
                OBD_FREE(dirent, sizeof(*dirent));
        }

        RETURN(rc);
}

static int mgs_write_log_mdc_to_mdt(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    struct mgs_target_info *mti,
				    char *logname);
static int mgs_write_log_osc_to_lov(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
                                    struct mgs_target_info *mti,
                                    char *logname, char *suffix, char *lovname,
                                    enum lustre_sec_part sec_part, int flags);
static void name_create_mdt_and_lov(char **logname, char **lovname,
                                    struct fs_db *fsdb, int i);

static int mgs_steal_llog_handler(const struct lu_env *env,
				  struct llog_handle *llh,
				  struct llog_rec_hdr *rec, void *data)
{
	struct mgs_device *mgs;
        struct mgs_target_info *mti, *tmti;
        struct fs_db *fsdb;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        struct lustre_cfg *lcfg;
        int rc = 0;
        struct llog_handle *mdt_llh = NULL;
        static int got_an_osc_or_mdc = 0;
        /* 0: not found any osc/mdc;
           1: found osc;
           2: found mdc;
        */
        static int last_step = -1;

        ENTRY;

        mti = ((struct temp_comp*)data)->comp_mti;
        tmti = ((struct temp_comp*)data)->comp_tmti;
        fsdb = ((struct temp_comp*)data)->comp_fsdb;
	mgs = ((struct temp_comp*)data)->comp_mgs;

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

        if (lcfg->lcfg_command == LCFG_MARKER) {
                struct cfg_marker *marker;
                marker = lustre_cfg_buf(lcfg, 1);
                if (!strncmp(marker->cm_comment,"add osc",7) &&
                    (marker->cm_flags & CM_START)){
                        got_an_osc_or_mdc = 1;
                        strncpy(tmti->mti_svname, marker->cm_tgtname,
                                sizeof(tmti->mti_svname));
			rc = record_start_log(env, mgs, &mdt_llh,
					      mti->mti_svname);
			rc = record_marker(env, mdt_llh, fsdb, CM_START,
                                           mti->mti_svname,"add osc(copied)");
			rc = record_end_log(env, &mdt_llh);
                        last_step = marker->cm_step;
                        RETURN(rc);
                }
                if (!strncmp(marker->cm_comment,"add osc",7) &&
                    (marker->cm_flags & CM_END)){
                        LASSERT(last_step == marker->cm_step);
                        last_step = -1;
                        got_an_osc_or_mdc = 0;
			rc = record_start_log(env, mgs, &mdt_llh,
					      mti->mti_svname);
			rc = record_marker(env, mdt_llh, fsdb, CM_END,
                                           mti->mti_svname,"add osc(copied)");
			rc = record_end_log(env, &mdt_llh);
                        RETURN(rc);
                }
                if (!strncmp(marker->cm_comment,"add mdc",7) &&
                    (marker->cm_flags & CM_START)){
                        got_an_osc_or_mdc = 2;
                        last_step = marker->cm_step;
                        memcpy(tmti->mti_svname, marker->cm_tgtname,
                               strlen(marker->cm_tgtname));

                        RETURN(rc);
                }
                if (!strncmp(marker->cm_comment,"add mdc",7) &&
                    (marker->cm_flags & CM_END)){
                        LASSERT(last_step == marker->cm_step);
                        last_step = -1;
                        got_an_osc_or_mdc = 0;
                        RETURN(rc);
                }
        }

        if (got_an_osc_or_mdc == 0 || last_step < 0)
                RETURN(rc);

        if (lcfg->lcfg_command == LCFG_ADD_UUID) {
                uint64_t nodenid;
                nodenid = lcfg->lcfg_nid;

                tmti->mti_nids[tmti->mti_nid_count] = nodenid;
                tmti->mti_nid_count++;

                RETURN(rc);
        }

        if (lcfg->lcfg_command == LCFG_SETUP) {
                char *target;

                target = lustre_cfg_string(lcfg, 1);
                memcpy(tmti->mti_uuid, target, strlen(target));
                RETURN(rc);
        }

        /* ignore client side sptlrpc_conf_log */
        if (lcfg->lcfg_command == LCFG_SPTLRPC_CONF)
                RETURN(rc);

        if (lcfg->lcfg_command == LCFG_ADD_MDC) {
                int index;

                if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1)
                        RETURN (-EINVAL);

                memcpy(tmti->mti_fsname, mti->mti_fsname,
                       strlen(mti->mti_fsname));
                tmti->mti_stripe_index = index;

		mgs_write_log_mdc_to_mdt(env, mgs, fsdb,
					 tmti, mti->mti_svname);
                memset(tmti, 0, sizeof(*tmti));
                RETURN(rc);
        }

        if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD) {
                int index;
                char mdt_index[9];
                char *logname, *lovname;

                name_create_mdt_and_lov(&logname, &lovname, fsdb,
                                        mti->mti_stripe_index);
                sprintf(mdt_index, "-MDT%04x", mti->mti_stripe_index);

                if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1) {
                        name_destroy(&logname);
                        name_destroy(&lovname);
                        RETURN(-EINVAL);
                }

                tmti->mti_stripe_index = index;
		mgs_write_log_osc_to_lov(env, mgs, fsdb, tmti, logname,
                                         mdt_index, lovname,
                                         LUSTRE_SP_MDT, 0);
                name_destroy(&logname);
                name_destroy(&lovname);
                RETURN(rc);
        }
        RETURN(rc);
}

/* fsdb->fsdb_mutex is already held  in mgs_write_log_target*/
/* stealed from mgs_get_fsdb_from_llog*/
static int mgs_steal_llog_for_mdt_from_client(const struct lu_env *env,
					      struct mgs_device *mgs,
                                              char *client_name,
                                              struct temp_comp* comp)
{
        struct llog_handle *loghandle;
        struct lvfs_run_ctxt saved;
        struct mgs_target_info *tmti;
        struct llog_ctxt *ctxt;
	int rc;

        ENTRY;

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);

        OBD_ALLOC_PTR(tmti);
        if (tmti == NULL)
		GOTO(out_ctxt, rc = -ENOMEM);

	comp->comp_tmti = tmti;
	comp->comp_mgs = mgs;

	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);

	rc = llog_open(NULL, ctxt, &loghandle, NULL, client_name,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out_pop, rc);
	}

	rc = llog_init_handle(NULL, loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	rc = llog_process_or_fork(env, loghandle, mgs_steal_llog_handler,
				  (void *)comp, NULL, false);
	CDEBUG(D_MGS, "steal llog re = %d\n", rc);
out_close:
	llog_close(NULL, loghandle);
out_pop:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
	OBD_FREE_PTR(tmti);
out_ctxt:
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

/* lmv is the second thing for client logs */
/* copied from mgs_write_log_lov. Please refer to that.  */
static int mgs_write_log_lmv(const struct lu_env *env,
			     struct mgs_device *mgs,
			     struct fs_db *fsdb,
                             struct mgs_target_info *mti,
                             char *logname, char *lmvname)
{
        struct llog_handle *llh = NULL;
        struct lmv_desc *lmvdesc;
        char *uuid;
        int rc = 0;
        ENTRY;

        CDEBUG(D_MGS, "Writing lmv(%s) log for %s\n", lmvname,logname);

        OBD_ALLOC_PTR(lmvdesc);
        if (lmvdesc == NULL)
                RETURN(-ENOMEM);
        lmvdesc->ld_active_tgt_count = 0;
        lmvdesc->ld_tgt_count = 0;
        sprintf((char*)lmvdesc->ld_uuid.uuid, "%s_UUID", lmvname);
        uuid = (char *)lmvdesc->ld_uuid.uuid;

	rc = record_start_log(env, mgs, &llh, logname);
	rc = record_marker(env, llh, fsdb, CM_START, lmvname, "lmv setup");
	rc = record_attach(env, llh, lmvname, "lmv", uuid);
	rc = record_lmv_setup(env, llh, lmvname, lmvdesc);
	rc = record_marker(env, llh, fsdb, CM_END, lmvname, "lmv setup");
	rc = record_end_log(env, &llh);

        OBD_FREE_PTR(lmvdesc);
        RETURN(rc);
}

/* lov is the first thing in the mdt and client logs */
static int mgs_write_log_lov(const struct lu_env *env, struct mgs_device *mgs,
			     struct fs_db *fsdb, struct mgs_target_info *mti,
                             char *logname, char *lovname)
{
        struct llog_handle *llh = NULL;
        struct lov_desc *lovdesc;
        char *uuid;
        int rc = 0;
        ENTRY;

        CDEBUG(D_MGS, "Writing lov(%s) log for %s\n", lovname, logname);

        /*
        #01 L attach   0:lov_mdsA  1:lov  2:71ccb_lov_mdsA_19f961a9e1
        #02 L lov_setup 0:lov_mdsA 1:(struct lov_desc)
              uuid=lov1_UUID, stripe count=1, size=1048576, offset=0, pattern=0
        */

        /* FIXME just make lov_setup accept empty desc (put uuid in buf 2) */
        OBD_ALLOC_PTR(lovdesc);
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
	rc = record_start_log(env, mgs, &llh, logname);
        if (rc)
                GOTO(out, rc);
        /* FIXME these should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, lovname, "lov setup");
	rc = record_attach(env, llh, lovname, "lov", uuid);
	rc = record_lov_setup(env, llh, lovname, lovdesc);
	rc = record_marker(env, llh, fsdb, CM_END, lovname, "lov setup");
	rc = record_end_log(env, &llh);

        EXIT;
out:
        OBD_FREE_PTR(lovdesc);
        return rc;
}

/* add failnids to open log */
static int mgs_write_log_failnids(const struct lu_env *env,
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
			rc = record_add_uuid(env, llh, nid, failnodeuuid);
                }
                if (failnodeuuid) {
			rc = record_add_conn(env, llh, cliname, failnodeuuid);
                        name_destroy(&failnodeuuid);
                        failnodeuuid = NULL;
                }
        }

        return rc;
}

static int mgs_write_log_mdc_to_lmv(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
                                    struct mgs_target_info *mti,
                                    char *logname, char *lmvname)
{
        struct llog_handle *llh = NULL;
        char *mdcname, *nodeuuid, *mdcuuid, *lmvuuid;
        char index[6];
        int i, rc;
        ENTRY;

	if (mgs_log_is_empty(env, mgs, logname)) {
                CERROR("log is empty! Logical error\n");
                RETURN(-EINVAL);
        }

        CDEBUG(D_MGS, "adding mdc for %s to log %s:lmv(%s)\n",
               mti->mti_svname, logname, lmvname);

        name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
        name_create(&mdcname, mti->mti_svname, "-mdc");
        name_create(&mdcuuid, mdcname, "_UUID");
        name_create(&lmvuuid, lmvname, "_UUID");

	rc = record_start_log(env, mgs, &llh, logname);
	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,
                           "add mdc");

        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s for mdt\n",
                       libcfs_nid2str(mti->mti_nids[i]));

		rc = record_add_uuid(env, llh, mti->mti_nids[i], nodeuuid);
        }

	rc = record_attach(env, llh, mdcname, LUSTRE_MDC_NAME, lmvuuid);
	rc = record_setup(env, llh, mdcname, mti->mti_uuid, nodeuuid, 0, 0);
	rc = mgs_write_log_failnids(env, mti, llh, mdcname);
        snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);
	rc = record_mdc_add(env, llh, lmvname, mdcuuid, mti->mti_uuid,
                            index, "1");
	rc = record_marker(env, llh, fsdb, CM_END, mti->mti_svname,
                           "add mdc");
	rc = record_end_log(env, &llh);

        name_destroy(&lmvuuid);
        name_destroy(&mdcuuid);
        name_destroy(&mdcname);
        name_destroy(&nodeuuid);
        RETURN(rc);
}

/* add new mdc to already existent MDS */
static int mgs_write_log_mdc_to_mdt(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    struct mgs_target_info *mti,
				    char *logname)
{
        struct llog_handle *llh = NULL;
        char *nodeuuid, *mdcname, *mdcuuid, *mdtuuid;
        int idx = mti->mti_stripe_index;
        char index[9];
        int i, rc;

        ENTRY;
	if (mgs_log_is_empty(env, mgs, logname)) {
                CERROR("log is empty! Logical error\n");
                RETURN (-EINVAL);
        }

        CDEBUG(D_MGS, "adding mdc index %d to %s\n", idx, logname);

        name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
        snprintf(index, sizeof(index), "-mdc%04x", idx);
        name_create(&mdcname, logname, index);
        name_create(&mdcuuid, mdcname, "_UUID");
        name_create(&mdtuuid, logname, "_UUID");

	rc = record_start_log(env, mgs, &llh, logname);
	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname, "add mdc");
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s for mdt\n",
                       libcfs_nid2str(mti->mti_nids[i]));
		rc = record_add_uuid(env, llh, mti->mti_nids[i], nodeuuid);
        }
	rc = record_attach(env, llh, mdcname, LUSTRE_MDC_NAME, mdcuuid);
	rc = record_setup(env, llh, mdcname, mti->mti_uuid, nodeuuid, 0, 0);
	rc = mgs_write_log_failnids(env, mti, llh, mdcname);
        snprintf(index, sizeof(index), "%d", idx);

	rc = record_mdc_add(env, llh, logname, mdcuuid, mti->mti_uuid,
                            index, "1");
	rc = record_marker(env, llh, fsdb, CM_END, mti->mti_svname, "add mdc");
	rc = record_end_log(env, &llh);

        name_destroy(&mdcuuid);
        name_destroy(&mdcname);
        name_destroy(&nodeuuid);
        name_destroy(&mdtuuid);
        RETURN(rc);
}

static int mgs_write_log_mdt0(const struct lu_env *env,
			      struct mgs_device *mgs,
			      struct fs_db *fsdb,
			      struct mgs_target_info *mti)
{
        char *log = mti->mti_svname;
        struct llog_handle *llh = NULL;
        char *uuid, *lovname;
        char mdt_index[6];
        char *ptr = mti->mti_params;
        int rc = 0, failout = 0;
        ENTRY;

        OBD_ALLOC(uuid, sizeof(struct obd_uuid));
        if (uuid == NULL)
                RETURN(-ENOMEM);

        if (class_find_param(ptr, PARAM_FAILMODE, &ptr) == 0)
                failout = (strncmp(ptr, "failout", 7) == 0);

        name_create(&lovname, log, "-mdtlov");
	if (mgs_log_is_empty(env, mgs, log))
		rc = mgs_write_log_lov(env, mgs, fsdb, mti, log, lovname);

        sprintf(uuid, "%s_UUID", log);
        sprintf(mdt_index, "%d", mti->mti_stripe_index);

        /* add MDT itself */
	rc = record_start_log(env, mgs, &llh, log);
        if (rc)
                GOTO(out, rc);

        /* FIXME this whole fn should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, log, "add mdt");
	rc = record_attach(env, llh, log, LUSTRE_MDT_NAME, uuid);
	rc = record_mount_opt(env, llh, log, lovname, NULL);
	rc = record_setup(env, llh, log, uuid, mdt_index, lovname,
                        failout ? "n" : "f");
	rc = record_marker(env, llh, fsdb, CM_END, log, "add mdt");
	rc = record_end_log(env, &llh);
out:
        name_destroy(&lovname);
        OBD_FREE(uuid, sizeof(struct obd_uuid));
        RETURN(rc);
}

static inline void name_create_mdt(char **logname, char *fsname, int i)
{
        char mdt_index[9];

        sprintf(mdt_index, "-MDT%04x", i);
        name_create(logname, fsname, mdt_index);
}

static void name_create_mdt_and_lov(char **logname, char **lovname,
                                    struct fs_db *fsdb, int i)
{
        name_create_mdt(logname, fsdb->fsdb_name, i);
        /* COMPAT_180 */
        if (i == 0 && cfs_test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags))
                name_create(lovname, fsdb->fsdb_name, "-mdtlov");
        else
                name_create(lovname, *logname, "-mdtlov");
}

static inline void name_create_mdt_osc(char **oscname, char *ostname,
                                       struct fs_db *fsdb, int i)
{
        char suffix[16];

        if (i == 0 && cfs_test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags))
                sprintf(suffix, "-osc");
        else
                sprintf(suffix, "-osc-MDT%04x", i);
        name_create(oscname, ostname, suffix);
}

/* envelope method for all layers log */
static int mgs_write_log_mdt(const struct lu_env *env,
			     struct mgs_device *mgs,
			     struct fs_db *fsdb,
			     struct mgs_target_info *mti)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
        struct llog_handle *llh = NULL;
        char *cliname;
        int rc, i = 0;
        ENTRY;

        CDEBUG(D_MGS, "writing new mdt %s\n", mti->mti_svname);

#if 0
        /* COMPAT_146 */
        if (mti->mti_flags & LDD_F_UPGRADE14) {
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
        /* end COMPAT_146 */
#endif
        if (mti->mti_uuid[0] == '\0') {
                /* Make up our own uuid */
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
        }

        /* add mdt */
	rc = mgs_write_log_mdt0(env, mgs, fsdb, mti);

        /* Append the mdt info to the client log */
        name_create(&cliname, mti->mti_fsname, "-client");

	if (mgs_log_is_empty(env, mgs, cliname)) {
                /* Start client log */
		rc = mgs_write_log_lov(env, mgs, fsdb, mti, cliname,
                                       fsdb->fsdb_clilov);
		rc = mgs_write_log_lmv(env, mgs, fsdb, mti, cliname,
                                       fsdb->fsdb_clilmv);
        }

        /*
        #09 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        #10 L attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f
        #11 L setup    0:MDC_uml1_mdsA_MNT_client  1:mdsA_UUID  2:uml1_UUID
        #12 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #13 L add_conn 0:MDC_uml1_mdsA_MNT_client  1:uml2_UUID
        #14 L mount_option 0:  1:client  2:lov1  3:MDC_uml1_mdsA_MNT_client
        */

#if 0
        /* COMPAT_146 */
        if (mti->mti_flags & LDD_F_UPGRADE14) {
                rc = record_start_log(obd, &llh, cliname);
                if (rc)
                        GOTO(out, rc);

                rc = record_marker(obd, llh, fsdb, CM_START,
                                   mti->mti_svname,"add mdc");

                /* Old client log already has MDC entry, but needs mount opt
                   for new client name (lustre-client) */
                /* FIXME Old MDT log already has an old mount opt
                   which we should remove (currently handled by
                   class_del_profiles()) */
                rc = record_mount_opt(obd, llh, cliname, fsdb->fsdb_clilov,
                                      fsdb->fsdb_mdc);
                /* end COMPAT_146 */

                rc = record_marker(obd, llh, fsdb, CM_END,
                                   mti->mti_svname, "add mdc");
        } else
#endif
        {
                /* copy client info about lov/lmv */
		mgi->mgi_comp.comp_mti = mti;
		mgi->mgi_comp.comp_fsdb = fsdb;

		rc = mgs_steal_llog_for_mdt_from_client(env, mgs, cliname,
							&mgi->mgi_comp);

		rc = mgs_write_log_mdc_to_lmv(env, mgs, fsdb, mti, cliname,
                                              fsdb->fsdb_clilmv);
                /* add mountopts */
		rc = record_start_log(env, mgs, &llh, cliname);
                if (rc)
                        GOTO(out, rc);

		rc = record_marker(env, llh, fsdb, CM_START, cliname,
                                   "mount opts");
		rc = record_mount_opt(env, llh, cliname, fsdb->fsdb_clilov,
                                      fsdb->fsdb_clilmv);
		rc = record_marker(env, llh, fsdb, CM_END, cliname,
                                   "mount opts");
        }

	rc = record_end_log(env, &llh);
out:
        name_destroy(&cliname);

        // for_all_existing_mdt except current one
        for (i = 0; i < INDEX_MAP_SIZE * 8; i++){
                char *mdtname;
                if (i !=  mti->mti_stripe_index &&
                    cfs_test_bit(i,  fsdb->fsdb_mdt_index_map)) {
                        name_create_mdt(&mdtname, mti->mti_fsname, i);
			rc = mgs_write_log_mdc_to_mdt(env, mgs, fsdb,
						      mti, mdtname);
                        name_destroy(&mdtname);
                }
        }

        RETURN(rc);
}

/* Add the ost info to the client/mdt lov */
static int mgs_write_log_osc_to_lov(const struct lu_env *env,
				    struct mgs_device *mgs, struct fs_db *fsdb,
                                    struct mgs_target_info *mti,
                                    char *logname, char *suffix, char *lovname,
                                    enum lustre_sec_part sec_part, int flags)
{
        struct llog_handle *llh = NULL;
        char *nodeuuid, *oscname, *oscuuid, *lovuuid, *svname;
        char index[6];
        int i, rc;

        ENTRY;
        CDEBUG(D_INFO, "adding osc for %s to log %s\n",
               mti->mti_svname, logname);

	if (mgs_log_is_empty(env, mgs, logname)) {
                CERROR("log is empty! Logical error\n");
                RETURN (-EINVAL);
        }

        name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
        name_create(&svname, mti->mti_svname, "-osc");
        name_create(&oscname, svname, suffix);
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

	rc = record_start_log(env, mgs, &llh, logname);
        if (rc)
                GOTO(out, rc);
        /* FIXME these should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START | flags, mti->mti_svname,
                           "add osc");
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s\n", libcfs_nid2str(mti->mti_nids[i]));
		rc = record_add_uuid(env, llh, mti->mti_nids[i], nodeuuid);
        }
	rc = record_attach(env, llh, oscname, LUSTRE_OSC_NAME, lovuuid);
	rc = record_setup(env, llh, oscname, mti->mti_uuid, nodeuuid, 0, 0);
	rc = mgs_write_log_failnids(env, mti, llh, oscname);
        snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);
	rc = record_lov_add(env, llh, lovname, mti->mti_uuid, index, "1");
	rc = record_marker(env, llh, fsdb, CM_END | flags, mti->mti_svname,
                           "add osc");
	rc = record_end_log(env, &llh);
out:
        name_destroy(&lovuuid);
        name_destroy(&oscuuid);
        name_destroy(&oscname);
        name_destroy(&svname);
        name_destroy(&nodeuuid);
        RETURN(rc);
}

static int mgs_write_log_ost(const struct lu_env *env,
			     struct mgs_device *mgs, struct fs_db *fsdb,
                             struct mgs_target_info *mti)
{
        struct llog_handle *llh = NULL;
        char *logname, *lovname;
        char *ptr = mti->mti_params;
        int rc, flags = 0, failout = 0, i;
        ENTRY;

        CDEBUG(D_MGS, "writing new ost %s\n", mti->mti_svname);

        /* The ost startup log */

        /* If the ost log already exists, that means that someone reformatted
           the ost and it called target_add again. */
	if (!mgs_log_is_empty(env, mgs, mti->mti_svname)) {
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
	rc = record_start_log(env, mgs, &llh, mti->mti_svname);
        if (rc)
                RETURN(rc);
        /* FIXME these should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,"add ost");
        if (*mti->mti_uuid == '\0')
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
	rc = record_attach(env, llh, mti->mti_svname,
                           "obdfilter"/*LUSTRE_OST_NAME*/, mti->mti_uuid);
	rc = record_setup(env, llh, mti->mti_svname,
                          "dev"/*ignored*/, "type"/*ignored*/,
                          failout ? "n" : "f", 0/*options*/);
	rc = record_marker(env, llh, fsdb, CM_END, mti->mti_svname, "add ost");
	rc = record_end_log(env, &llh);

        /* We also have to update the other logs where this osc is part of
           the lov */

        if (cfs_test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
                /* If we're upgrading, the old mdt log already has our
                   entry. Let's do a fake one for fun. */
                /* Note that we can't add any new failnids, since we don't
                   know the old osc names. */
                flags = CM_SKIP | CM_UPGRADE146;

        } else if ((mti->mti_flags & LDD_F_UPDATE) != LDD_F_UPDATE) {
                /* If the update flag isn't set, don't update client/mdt
                   logs. */
                flags |= CM_SKIP;
                LCONSOLE_WARN("Client log for %s was not updated; writeconf "
                              "the MDT first to regenerate it.\n",
                              mti->mti_svname);
        }

        /* Add ost to all MDT lov defs */
        for (i = 0; i < INDEX_MAP_SIZE * 8; i++){
                if (cfs_test_bit(i, fsdb->fsdb_mdt_index_map)) {
                        char mdt_index[9];

                        name_create_mdt_and_lov(&logname, &lovname, fsdb, i);
                        sprintf(mdt_index, "-MDT%04x", i);
			mgs_write_log_osc_to_lov(env, mgs, fsdb, mti, logname,
                                                 mdt_index, lovname,
                                                 LUSTRE_SP_MDT, flags);
                        name_destroy(&logname);
                        name_destroy(&lovname);
                }
        }

        /* Append ost info to the client log */
        name_create(&logname, mti->mti_fsname, "-client");
	if (mgs_log_is_empty(env, mgs, logname)) {
                /* Start client log */
		rc = mgs_write_log_lov(env, mgs, fsdb, mti, logname,
                                       fsdb->fsdb_clilov);
		rc = mgs_write_log_lmv(env, mgs, fsdb, mti, logname,
                                       fsdb->fsdb_clilmv);
        }
	mgs_write_log_osc_to_lov(env, mgs, fsdb, mti, logname, "",
                                 fsdb->fsdb_clilov, LUSTRE_SP_CLI, flags);
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

static int mgs_write_log_failnid_internal(const struct lu_env *env,
					  struct mgs_device *mgs,
                                          struct fs_db *fsdb,
                                          struct mgs_target_info *mti,
                                          char *logname, char *cliname)
{
        int rc;
        struct llog_handle *llh = NULL;

        if (mgs_param_empty(mti->mti_params)) {
                /* Remove _all_ failnids */
		rc = mgs_modify(env, mgs, fsdb, mti, logname,
                                mti->mti_svname, "add failnid", CM_SKIP);
                return rc;
        }

        /* Otherwise failover nids are additive */
	rc = record_start_log(env, mgs, &llh, logname);
        if (!rc) {
                /* FIXME this should be a single journal transaction */
		rc = record_marker(env, llh, fsdb, CM_START,
                                   mti->mti_svname, "add failnid");
		rc = mgs_write_log_failnids(env, mti, llh, cliname);
		rc = record_marker(env, llh, fsdb, CM_END,
                                   mti->mti_svname, "add failnid");
		rc = record_end_log(env, &llh);
        }

        return rc;
}


/* Add additional failnids to an existing log.
   The mdc/osc must have been added to logs first */
/* tcp nids must be in dotted-quad ascii -
   we can't resolve hostnames from the kernel. */
static int mgs_write_log_add_failnid(const struct lu_env *env,
				     struct mgs_device *mgs,
				     struct fs_db *fsdb,
                                     struct mgs_target_info *mti)
{
        char *logname, *cliname;
        int rc;
        ENTRY;

        /* FIXME we currently can't erase the failnids
         * given when a target first registers, since they aren't part of
         * an "add uuid" stanza */

        /* Verify that we know about this target */
	if (mgs_log_is_empty(env, mgs, mti->mti_svname)) {
                LCONSOLE_ERROR_MSG(0x142, "The target %s has not registered "
                                   "yet. It must be started before failnids "
                                   "can be added.\n", mti->mti_svname);
                RETURN(-ENOENT);
        }

        /* Create mdc/osc client name (e.g. lustre-OST0001-osc) */
        if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                name_create(&cliname, mti->mti_svname, "-mdc");
        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                name_create(&cliname, mti->mti_svname, "-osc");
        } else {
                RETURN(-EINVAL);
        }

        /* Add failover nids to the client log */
        name_create(&logname, mti->mti_fsname, "-client");
	rc = mgs_write_log_failnid_internal(env, mgs, fsdb,mti,logname,cliname);
        name_destroy(&logname);
        name_destroy(&cliname);

        if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                /* Add OST failover nids to the MDT logs as well */
                int i;

                for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
                        if (!cfs_test_bit(i, fsdb->fsdb_mdt_index_map))
                                continue;
                        name_create_mdt(&logname, mti->mti_fsname, i);
                        name_create_mdt_osc(&cliname, mti->mti_svname, fsdb, i);
			rc = mgs_write_log_failnid_internal(env, mgs, fsdb, mti,
                                                            logname, cliname);
                        name_destroy(&cliname);
                        name_destroy(&logname);
                }
        }

        RETURN(rc);
}

static int mgs_wlp_lcfg(const struct lu_env *env,
			struct mgs_device *mgs, struct fs_db *fsdb,
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
	rc = mgs_modify(env, mgs, fsdb, mti, logname, tgtname, comment,CM_SKIP);
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
	rc = mgs_write_log_direct(env, mgs, fsdb, logname,lcfg,tgtname,comment);
        lustre_cfg_free(lcfg);
        return rc;
}

/* write global variable settings into log */
static int mgs_write_log_sys(const struct lu_env *env,
			     struct mgs_device *mgs, struct fs_db *fsdb,
			     struct mgs_target_info *mti, char *sys, char *ptr)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	struct lustre_cfg *lcfg;
	char *tmp, sep;
	int rc, cmd, convert = 1;

	if (class_match_param(ptr, PARAM_TIMEOUT, &tmp) == 0) {
		cmd = LCFG_SET_TIMEOUT;
	} else if (class_match_param(ptr, PARAM_LDLM_TIMEOUT, &tmp) == 0) {
		cmd = LCFG_SET_LDLM_TIMEOUT;
	/* Check for known params here so we can return error to lctl */
	} else if ((class_match_param(ptr, PARAM_AT_MIN, &tmp) == 0) ||
		(class_match_param(ptr, PARAM_AT_MAX, &tmp) == 0) ||
		(class_match_param(ptr, PARAM_AT_EXTRA, &tmp) == 0) ||
		(class_match_param(ptr, PARAM_AT_EARLY_MARGIN, &tmp) == 0) ||
		(class_match_param(ptr, PARAM_AT_HISTORY, &tmp) == 0)) {
		cmd = LCFG_PARAM;
	} else if (class_match_param(ptr, PARAM_JOBID_VAR, &tmp) == 0) {
		convert = 0; /* Don't convert string value to integer */
		cmd = LCFG_PARAM;
	} else {
		return -EINVAL;
	}

	if (mgs_param_empty(ptr))
		CDEBUG(D_MGS, "global '%s' removed\n", sys);
	else
		CDEBUG(D_MGS, "global '%s' val=%s\n", sys, tmp);

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, NULL);
	lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 1, sys);
	if (!convert && *tmp != '\0')
		lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 2, tmp);
	lcfg = lustre_cfg_new(cmd, &mgi->mgi_bufs);
	lcfg->lcfg_num = convert ? simple_strtoul(tmp, NULL, 0) : 0;
	/* truncate the comment to the parameter name */
	ptr = tmp - 1;
	sep = *ptr;
	*ptr = '\0';
	/* modify all servers and clients */
	rc = mgs_write_log_direct_all(env, mgs, fsdb, mti,
				      *tmp == '\0' ? NULL : lcfg,
				      mti->mti_fsname, sys, 0);
	if (rc == 0 && *tmp != '\0') {
		switch (cmd) {
		case LCFG_SET_TIMEOUT:
			if (!obd_timeout_set || lcfg->lcfg_num > obd_timeout)
				class_process_config(lcfg);
			break;
		case LCFG_SET_LDLM_TIMEOUT:
			if (!ldlm_timeout_set || lcfg->lcfg_num > ldlm_timeout)
				class_process_config(lcfg);
			break;
		default:
			break;
		}
	}
	*ptr = sep;
	lustre_cfg_free(lcfg);
	return rc;
}

/* write quota settings into log */
static int mgs_write_log_quota(const struct lu_env *env, struct mgs_device *mgs,
			       struct fs_db *fsdb, struct mgs_target_info *mti,
			       char *quota, char *ptr)
{
	struct lustre_cfg_bufs bufs;
	struct lustre_cfg *lcfg;
	char *tmp;
	char sep;
	int cmd = LCFG_PARAM;
	int rc;

	/* support only 'meta' and 'data' pools so far */
	if (class_match_param(ptr, QUOTA_METAPOOL_NAME, &tmp) != 0 &&
	    class_match_param(ptr, QUOTA_DATAPOOL_NAME, &tmp) != 0) {
		CERROR("parameter quota.%s isn't supported (only quota.mdt "
		       "& quota.ost are)\n", ptr);
		return -EINVAL;
	}

	if (*tmp == '\0') {
		CDEBUG(D_MGS, "global '%s' removed\n", quota);
	} else {
		CDEBUG(D_MGS, "global '%s'\n", quota);

		if (strchr(tmp, 'u') == NULL && strchr(tmp, 'g') == NULL &&
		    strcmp(tmp, "none") != 0) {
			CERROR("enable option(%s) isn't supported\n", tmp);
			return -EINVAL;
		}
	}

	lustre_cfg_bufs_reset(&bufs, NULL);
	lustre_cfg_bufs_set_string(&bufs, 1, quota);
	lcfg = lustre_cfg_new(cmd, &bufs);
	/* truncate the comment to the parameter name */
	ptr = tmp - 1;
	sep = *ptr;
	*ptr = '\0';

	/* XXX we duplicated quota enable information in all server
	 *     config logs, it should be moved to a separate config
	 *     log once we cleanup the config log for global param. */
	/* modify all servers */
	rc = mgs_write_log_direct_all(env, mgs, fsdb, mti,
				      *tmp == '\0' ? NULL : lcfg,
				      mti->mti_fsname, quota, 1);
	*ptr = sep;
	lustre_cfg_free(lcfg);
	return rc;
}

static int mgs_srpc_set_param_disk(const struct lu_env *env,
				   struct mgs_device *mgs,
                                   struct fs_db *fsdb,
                                   struct mgs_target_info *mti,
                                   char *param)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
        struct llog_handle     *llh = NULL;
        char                   *logname;
        char                   *comment, *ptr;
        struct lustre_cfg      *lcfg;
        int                     rc, len;
        ENTRY;

        /* get comment */
        ptr = strchr(param, '=');
        LASSERT(ptr);
        len = ptr - param;

        OBD_ALLOC(comment, len + 1);
        if (comment == NULL)
                RETURN(-ENOMEM);
        strncpy(comment, param, len);
        comment[len] = '\0';

        /* prepare lcfg */
	lustre_cfg_bufs_reset(&mgi->mgi_bufs, mti->mti_svname);
	lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 1, param);
	lcfg = lustre_cfg_new(LCFG_SPTLRPC_CONF, &mgi->mgi_bufs);
        if (lcfg == NULL)
                GOTO(out_comment, rc = -ENOMEM);

        /* construct log name */
        rc = name_create(&logname, mti->mti_fsname, "-sptlrpc");
        if (rc)
                GOTO(out_lcfg, rc);

	if (mgs_log_is_empty(env, mgs, logname)) {
		rc = record_start_log(env, mgs, &llh, logname);
		record_end_log(env, &llh);
                if (rc)
                        GOTO(out, rc);
        }

        /* obsolete old one */
	mgs_modify(env, mgs, fsdb, mti, logname, mti->mti_svname,
		   comment, CM_SKIP);

        /* write the new one */
	rc = mgs_write_log_direct(env, mgs, fsdb, logname, lcfg,
                                  mti->mti_svname, comment);
        if (rc)
                CERROR("err %d writing log %s\n", rc, logname);

out:
        name_destroy(&logname);
out_lcfg:
        lustre_cfg_free(lcfg);
out_comment:
        OBD_FREE(comment, len + 1);
        RETURN(rc);
}

static int mgs_srpc_set_param_udesc_mem(struct fs_db *fsdb,
                                        char *param)
{
        char    *ptr;

        /* disable the adjustable udesc parameter for now, i.e. use default
         * setting that client always ship udesc to MDT if possible. to enable
         * it simply remove the following line */
        goto error_out;

        ptr = strchr(param, '=');
        if (ptr == NULL)
                goto error_out;
        *ptr++ = '\0';

        if (strcmp(param, PARAM_SRPC_UDESC))
                goto error_out;

        if (strcmp(ptr, "yes") == 0) {
                cfs_set_bit(FSDB_UDESC, &fsdb->fsdb_flags);
                CWARN("Enable user descriptor shipping from client to MDT\n");
        } else if (strcmp(ptr, "no") == 0) {
                cfs_clear_bit(FSDB_UDESC, &fsdb->fsdb_flags);
                CWARN("Disable user descriptor shipping from client to MDT\n");
        } else {
                *(ptr - 1) = '=';
                goto error_out;
        }
        return 0;

error_out:
        CERROR("Invalid param: %s\n", param);
        return -EINVAL;
}

static int mgs_srpc_set_param_mem(struct fs_db *fsdb,
                                  const char *svname,
                                  char *param)
{
        struct sptlrpc_rule      rule;
        struct sptlrpc_rule_set *rset;
        int                      rc;
        ENTRY;

        if (strncmp(param, PARAM_SRPC, sizeof(PARAM_SRPC) - 1) != 0) {
                CERROR("Invalid sptlrpc parameter: %s\n", param);
                RETURN(-EINVAL);
        }

        if (strncmp(param, PARAM_SRPC_UDESC,
                    sizeof(PARAM_SRPC_UDESC) - 1) == 0) {
                RETURN(mgs_srpc_set_param_udesc_mem(fsdb, param));
        }

        if (strncmp(param, PARAM_SRPC_FLVR, sizeof(PARAM_SRPC_FLVR) - 1) != 0) {
                CERROR("Invalid sptlrpc flavor parameter: %s\n", param);
                RETURN(-EINVAL);
        }

        param += sizeof(PARAM_SRPC_FLVR) - 1;

        rc = sptlrpc_parse_rule(param, &rule);
        if (rc)
                RETURN(rc);

        /* mgs rules implies must be mgc->mgs */
        if (cfs_test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags)) {
                if ((rule.sr_from != LUSTRE_SP_MGC &&
                     rule.sr_from != LUSTRE_SP_ANY) ||
                    (rule.sr_to != LUSTRE_SP_MGS &&
                     rule.sr_to != LUSTRE_SP_ANY))
                        RETURN(-EINVAL);
        }

        /* preapre room for this coming rule. svcname format should be:
         * - fsname: general rule
         * - fsname-tgtname: target-specific rule
         */
        if (strchr(svname, '-')) {
                struct mgs_tgt_srpc_conf *tgtconf;
                int                       found = 0;

                for (tgtconf = fsdb->fsdb_srpc_tgt; tgtconf != NULL;
                     tgtconf = tgtconf->mtsc_next) {
                        if (!strcmp(tgtconf->mtsc_tgt, svname)) {
                                found = 1;
                                break;
                        }
                }

                if (!found) {
                        int name_len;

                        OBD_ALLOC_PTR(tgtconf);
                        if (tgtconf == NULL)
                                RETURN(-ENOMEM);

                        name_len = strlen(svname);

                        OBD_ALLOC(tgtconf->mtsc_tgt, name_len + 1);
                        if (tgtconf->mtsc_tgt == NULL) {
                                OBD_FREE_PTR(tgtconf);
                                RETURN(-ENOMEM);
                        }
                        memcpy(tgtconf->mtsc_tgt, svname, name_len);

                        tgtconf->mtsc_next = fsdb->fsdb_srpc_tgt;
                        fsdb->fsdb_srpc_tgt = tgtconf;
                }

                rset = &tgtconf->mtsc_rset;
        } else {
                rset = &fsdb->fsdb_srpc_gen;
        }

        rc = sptlrpc_rule_set_merge(rset, &rule);

        RETURN(rc);
}

static int mgs_srpc_set_param(const struct lu_env *env,
			      struct mgs_device *mgs,
                              struct fs_db *fsdb,
                              struct mgs_target_info *mti,
                              char *param)
{
        char                   *copy;
        int                     rc, copy_size;
        ENTRY;

#ifndef HAVE_GSS
        RETURN(-EINVAL);
#endif
        /* keep a copy of original param, which could be destroied
         * during parsing */
        copy_size = strlen(param) + 1;
        OBD_ALLOC(copy, copy_size);
        if (copy == NULL)
                return -ENOMEM;
        memcpy(copy, param, copy_size);

        rc = mgs_srpc_set_param_mem(fsdb, mti->mti_svname, param);
        if (rc)
                goto out_free;

        /* previous steps guaranteed the syntax is correct */
	rc = mgs_srpc_set_param_disk(env, mgs, fsdb, mti, copy);
        if (rc)
                goto out_free;

        if (cfs_test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags)) {
                /*
                 * for mgs rules, make them effective immediately.
                 */
                LASSERT(fsdb->fsdb_srpc_tgt == NULL);
		sptlrpc_target_update_exp_flavor(mgs->mgs_obd,
						 &fsdb->fsdb_srpc_gen);
        }

out_free:
        OBD_FREE(copy, copy_size);
        RETURN(rc);
}

struct mgs_srpc_read_data {
        struct fs_db   *msrd_fsdb;
        int             msrd_skip;
};

static int mgs_srpc_read_handler(const struct lu_env *env,
				 struct llog_handle *llh,
				 struct llog_rec_hdr *rec, void *data)
{
	struct mgs_srpc_read_data *msrd = data;
        struct cfg_marker         *marker;
        struct lustre_cfg         *lcfg = (struct lustre_cfg *)(rec + 1);
        char                      *svname, *param;
        int                        cfg_len, rc;
        ENTRY;

        if (rec->lrh_type != OBD_CFG_REC) {
                CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
                RETURN(-EINVAL);
        }

        cfg_len = rec->lrh_len - sizeof(struct llog_rec_hdr) -
                  sizeof(struct llog_rec_tail);

        rc = lustre_cfg_sanity_check(lcfg, cfg_len);
        if (rc) {
                CERROR("Insane cfg\n");
                RETURN(rc);
        }

        if (lcfg->lcfg_command == LCFG_MARKER) {
                marker = lustre_cfg_buf(lcfg, 1);

                if (marker->cm_flags & CM_START &&
                    marker->cm_flags & CM_SKIP)
                        msrd->msrd_skip = 1;
                if (marker->cm_flags & CM_END)
                        msrd->msrd_skip = 0;

                RETURN(0);
        }

        if (msrd->msrd_skip)
                RETURN(0);

        if (lcfg->lcfg_command != LCFG_SPTLRPC_CONF) {
                CERROR("invalid command (%x)\n", lcfg->lcfg_command);
                RETURN(0);
        }

        svname = lustre_cfg_string(lcfg, 0);
        if (svname == NULL) {
                CERROR("svname is empty\n");
                RETURN(0);
        }

        param = lustre_cfg_string(lcfg, 1);
        if (param == NULL) {
                CERROR("param is empty\n");
                RETURN(0);
        }

        rc = mgs_srpc_set_param_mem(msrd->msrd_fsdb, svname, param);
        if (rc)
                CERROR("read sptlrpc record error (%d): %s\n", rc, param);

        RETURN(0);
}

int mgs_get_fsdb_srpc_from_llog(const struct lu_env *env,
				struct mgs_device *mgs,
                                struct fs_db *fsdb)
{
        struct llog_handle        *llh = NULL;
        struct lvfs_run_ctxt       saved;
        struct llog_ctxt          *ctxt;
        char                      *logname;
        struct mgs_srpc_read_data  msrd;
        int                        rc;
        ENTRY;

        /* construct log name */
        rc = name_create(&logname, fsdb->fsdb_name, "-sptlrpc");
        if (rc)
                RETURN(rc);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);

	if (mgs_log_is_empty(env, mgs, logname))
                GOTO(out, rc = 0);

	push_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);

	rc = llog_open(NULL, ctxt, &llh, NULL, logname,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out_pop, rc);
	}

	rc = llog_init_handle(NULL, llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);

        if (llog_get_size(llh) <= 1)
                GOTO(out_close, rc = 0);

        msrd.msrd_fsdb = fsdb;
        msrd.msrd_skip = 0;

	rc = llog_process_or_fork(env, llh, mgs_srpc_read_handler,
				  (void *)&msrd, NULL, false);

out_close:
	llog_close(NULL, llh);
out_pop:
	pop_ctxt(&saved, &mgs->mgs_obd->obd_lvfs_ctxt, NULL);
out:
        llog_ctxt_put(ctxt);
        name_destroy(&logname);

        if (rc)
                CERROR("failed to read sptlrpc config database: %d\n", rc);
        RETURN(rc);
}

/* Permanent settings of all parameters by writing into the appropriate
 * configuration logs.
 * A parameter with null value ("<param>='\0'") means to erase it out of
 * the logs.
 */
static int mgs_write_log_param(const struct lu_env *env,
			       struct mgs_device *mgs, struct fs_db *fsdb,
                               struct mgs_target_info *mti, char *ptr)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
        char *logname;
        char *tmp;
        int rc = 0, rc2 = 0;
        ENTRY;

        /* For various parameter settings, we have to figure out which logs
           care about them (e.g. both mdt and client for lov settings) */
        CDEBUG(D_MGS, "next param '%s'\n", ptr);

        /* The params are stored in MOUNT_DATA_FILE and modified via
           tunefs.lustre, or set using lctl conf_param */

        /* Processed in lustre_start_mgc */
        if (class_match_param(ptr, PARAM_MGSNODE, NULL) == 0)
                GOTO(end, rc);

	/* Processed in ost/mdt */
	if (class_match_param(ptr, PARAM_NETWORK, NULL) == 0)
		GOTO(end, rc);

        /* Processed in mgs_write_log_ost */
        if (class_match_param(ptr, PARAM_FAILMODE, NULL) == 0) {
                if (mti->mti_flags & LDD_F_PARAM) {
                        LCONSOLE_ERROR_MSG(0x169, "%s can only be "
                                           "changed with tunefs.lustre"
                                           "and --writeconf\n", ptr);
                        rc = -EPERM;
                }
                GOTO(end, rc);
        }

        if (class_match_param(ptr, PARAM_SRPC, NULL) == 0) {
		rc = mgs_srpc_set_param(env, mgs, fsdb, mti, ptr);
                GOTO(end, rc);
        }

        if (class_match_param(ptr, PARAM_FAILNODE, NULL) == 0) {
                /* Add a failover nidlist */
                rc = 0;
                /* We already processed failovers params for new
                   targets in mgs_write_log_target */
                if (mti->mti_flags & LDD_F_PARAM) {
                        CDEBUG(D_MGS, "Adding failnode\n");
			rc = mgs_write_log_add_failnid(env, mgs, fsdb, mti);
                }
                GOTO(end, rc);
        }

        if (class_match_param(ptr, PARAM_SYS, &tmp) == 0) {
		rc = mgs_write_log_sys(env, mgs, fsdb, mti, ptr, tmp);
                GOTO(end, rc);
        }

	if (class_match_param(ptr, PARAM_QUOTA, &tmp) == 0) {
		rc = mgs_write_log_quota(env, mgs, fsdb, mti, ptr, tmp);
		GOTO(end, rc);
	}

        if (class_match_param(ptr, PARAM_OSC""PARAM_ACTIVE, &tmp) == 0) {
                /* active=0 means off, anything else means on */
                int flag = (*tmp == '0') ? CM_EXCLUDE : 0;
                int i;

                if (!(mti->mti_flags & LDD_F_SV_TYPE_OST)) {
                        LCONSOLE_ERROR_MSG(0x144, "%s: Only OSCs can "
                                           "be (de)activated.\n",
                                           mti->mti_svname);
                        GOTO(end, rc = -EINVAL);
                }
                LCONSOLE_WARN("Permanently %sactivating %s\n",
                              flag ? "de": "re", mti->mti_svname);
                /* Modify clilov */
                name_create(&logname, mti->mti_fsname, "-client");
		rc = mgs_modify(env, mgs, fsdb, mti, logname,
                                mti->mti_svname, "add osc", flag);
                name_destroy(&logname);
                if (rc)
                        goto active_err;
                /* Modify mdtlov */
                /* Add to all MDT logs for CMD */
                for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
                        if (!cfs_test_bit(i, fsdb->fsdb_mdt_index_map))
                                continue;
                        name_create_mdt(&logname, mti->mti_fsname, i);
			rc = mgs_modify(env, mgs, fsdb, mti, logname,
                                        mti->mti_svname, "add osc", flag);
                        name_destroy(&logname);
                        if (rc)
                                goto active_err;
                }
        active_err:
                if (rc) {
                        LCONSOLE_ERROR_MSG(0x145, "Couldn't find %s in"
                                           "log (%d). No permanent "
                                           "changes were made to the "
                                           "config log.\n",
                                           mti->mti_svname, rc);
                        if (cfs_test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags))
                                LCONSOLE_ERROR_MSG(0x146, "This may be"
                                                   " because the log"
                                                   "is in the old 1.4"
                                                   "style. Consider "
                                                   " --writeconf to "
                                                   "update the logs.\n");
                        GOTO(end, rc);
                }
                /* Fall through to osc proc for deactivating live OSC
                   on running MDT / clients. */
        }
        /* Below here, let obd's XXX_process_config methods handle it */

        /* All lov. in proc */
        if (class_match_param(ptr, PARAM_LOV, NULL) == 0) {
                char *mdtlovname;

                CDEBUG(D_MGS, "lov param %s\n", ptr);
                if (!(mti->mti_flags & LDD_F_SV_TYPE_MDT)) {
                        LCONSOLE_ERROR_MSG(0x147, "LOV params must be "
                                           "set on the MDT, not %s. "
                                           "Ignoring.\n",
                                           mti->mti_svname);
                        GOTO(end, rc = 0);
                }

                /* Modify mdtlov */
		if (mgs_log_is_empty(env, mgs, mti->mti_svname))
                        GOTO(end, rc = -ENODEV);

                name_create_mdt_and_lov(&logname, &mdtlovname, fsdb,
                                        mti->mti_stripe_index);
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, mti->mti_svname,
				  &mgi->mgi_bufs, mdtlovname, ptr);
                name_destroy(&logname);
                name_destroy(&mdtlovname);
                if (rc)
                        GOTO(end, rc);

                /* Modify clilov */
                name_create(&logname, mti->mti_fsname, "-client");
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname, &mgi->mgi_bufs,
                                  fsdb->fsdb_clilov, ptr);
                name_destroy(&logname);
                GOTO(end, rc);
        }

        /* All osc., mdc., llite. params in proc */
        if ((class_match_param(ptr, PARAM_OSC, NULL) == 0) ||
            (class_match_param(ptr, PARAM_MDC, NULL) == 0) ||
            (class_match_param(ptr, PARAM_LLITE, NULL) == 0)) {
                char *cname;
                if (memcmp(ptr, PARAM_LLITE, strlen(PARAM_LLITE)) == 0) {
                        name_create(&cname, mti->mti_fsname, "-client");
                        /* Add the client type to match the obdname in
                           class_config_llog_handler */
                } else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                        /* COMPAT_146 */
                        if (fsdb->fsdb_mdc)
                                name_create(&cname, fsdb->fsdb_mdc, "");
                        else
                                name_create(&cname, mti->mti_svname,
                                            "-mdc");
                } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                        /* COMPAT_146 */
                        if (cfs_test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
                                LCONSOLE_ERROR_MSG(0x148, "Upgraded "
                                                   "client logs for %s"
                                                   " cannot be "
                                                   "modified. Consider"
                                                   " updating the "
                                                   "configuration with"
                                                   " --writeconf\n",
                                                   mti->mti_svname);
                                /* We don't know the names of all the
                                   old oscs*/
                                GOTO(end, rc = -EINVAL);
                        }
                        name_create(&cname, mti->mti_svname, "-osc");
                } else {
                        GOTO(end, rc = -EINVAL);
                }

                CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);

                /* Modify client */
                name_create(&logname, mti->mti_fsname, "-client");
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname, &mgi->mgi_bufs,
                                  cname, ptr);

                /* osc params affect the MDT as well */
                if (!rc && (mti->mti_flags & LDD_F_SV_TYPE_OST)) {
                        int i;

                        for (i = 0; i < INDEX_MAP_SIZE * 8; i++){
                                if (!cfs_test_bit(i, fsdb->fsdb_mdt_index_map))
                                        continue;
                                name_destroy(&cname);
                                name_create_mdt_osc(&cname, mti->mti_svname,
                                                    fsdb, i);
                                name_destroy(&logname);
                                name_create_mdt(&logname, mti->mti_fsname, i);
				if (!mgs_log_is_empty(env, mgs, logname))
					rc = mgs_wlp_lcfg(env, mgs, fsdb, mti,
							  logname, &mgi->mgi_bufs,
							  cname, ptr);
                                if (rc)
                                        break;
                        }
                }
                name_destroy(&logname);
                name_destroy(&cname);
                GOTO(end, rc);
        }

        /* All mdt. params in proc */
        if (class_match_param(ptr, PARAM_MDT, NULL) == 0) {
                int i;
                __u32 idx;

                CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);
                if (strncmp(mti->mti_svname, mti->mti_fsname,
                            MTI_NAME_MAXLEN) == 0)
                        /* device is unspecified completely? */
                        rc = LDD_F_SV_TYPE_MDT | LDD_F_SV_ALL;
                else
                        rc = server_name2index(mti->mti_svname, &idx, NULL);
                if (rc < 0)
                        goto active_err;
                if ((rc & LDD_F_SV_TYPE_MDT) == 0)
                        goto active_err;
                if (rc & LDD_F_SV_ALL) {
                        for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
                                if (!cfs_test_bit(i,
                                                  fsdb->fsdb_mdt_index_map))
                                        continue;
                                name_create_mdt(&logname, mti->mti_fsname, i);
				rc = mgs_wlp_lcfg(env, mgs, fsdb, mti,
						  logname, &mgi->mgi_bufs,
                                                  logname, ptr);
                                name_destroy(&logname);
                                if (rc)
                                        goto active_err;
                        }
                } else {
			rc = mgs_wlp_lcfg(env, mgs, fsdb, mti,
					  mti->mti_svname, &mgi->mgi_bufs,
                                          mti->mti_svname, ptr);
                        if (rc)
                                goto active_err;
                }
                GOTO(end, rc);
        }

        /* All mdd., ost. params in proc */
        if ((class_match_param(ptr, PARAM_MDD, NULL) == 0) ||
            (class_match_param(ptr, PARAM_OST, NULL) == 0)) {
                CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);
		if (mgs_log_is_empty(env, mgs, mti->mti_svname))
                        GOTO(end, rc = -ENODEV);

		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, mti->mti_svname,
				  &mgi->mgi_bufs, mti->mti_svname, ptr);
                GOTO(end, rc);
        }

        LCONSOLE_WARN("Ignoring unrecognized param '%s'\n", ptr);
        rc2 = -ENOSYS;

end:
        if (rc)
                CERROR("err %d on param '%s'\n", rc, ptr);

        RETURN(rc ?: rc2);
}

/* Not implementing automatic failover nid addition at this time. */
int mgs_check_failnid(const struct lu_env *env, struct mgs_device *mgs,
		      struct mgs_target_info *mti)
{
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

        cfs_mutex_lock(&fsdb->fsdb_mutex);
        rc = mgs_write_log_add_failnid(obd, fsdb, mti);
        cfs_mutex_unlock(&fsdb->fsdb_mutex);

        RETURN(rc);
#endif
        return 0;
}

int mgs_write_log_target(const struct lu_env *env,
			 struct mgs_device *mgs,
                         struct mgs_target_info *mti,
                         struct fs_db *fsdb)
{
        int rc = -EINVAL;
        char *buf, *params;
        ENTRY;

        /* set/check the new target index */
	rc = mgs_set_index(env, mgs, mti);
        if (rc < 0) {
                CERROR("Can't get index (%d)\n", rc);
                RETURN(rc);
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

        cfs_mutex_lock(&fsdb->fsdb_mutex);

        if (mti->mti_flags &
            (LDD_F_VIRGIN | LDD_F_UPGRADE14 | LDD_F_WRITECONF)) {
                /* Generate a log from scratch */
                if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
			rc = mgs_write_log_mdt(env, mgs, fsdb, mti);
                } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
			rc = mgs_write_log_ost(env, mgs, fsdb, mti);
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

        /* allocate temporary buffer, where class_get_next_param will
           make copy of a current  parameter */
        OBD_ALLOC(buf, strlen(mti->mti_params) + 1);
        if (buf == NULL)
                GOTO(out_up, rc = -ENOMEM);
        params = mti->mti_params;
        while (params != NULL) {
                rc = class_get_next_param(&params, buf);
                if (rc) {
                        if (rc == 1)
                                /* there is no next parameter, that is
                                   not an error */
                                rc = 0;
                        break;
                }
                CDEBUG(D_MGS, "remaining string: '%s', param: '%s'\n",
                       params, buf);
		rc = mgs_write_log_param(env, mgs, fsdb, mti, buf);
                if (rc)
                        break;
        }

        OBD_FREE(buf, strlen(mti->mti_params) + 1);

out_up:
        cfs_mutex_unlock(&fsdb->fsdb_mutex);
        RETURN(rc);
}

/* COMPAT_146 */
/* verify that we can handle the old config logs */
int mgs_upgrade_sv_14(const struct lu_env *env, struct mgs_device *mgs,
		      struct mgs_target_info *mti, struct fs_db *fsdb)
{
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

        if (cfs_test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
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
		if (mgs_log_is_empty(env, mgs, mti->mti_svname)) {
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

        if (!cfs_test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
                LCONSOLE_ERROR_MSG(0x14c, "%s-client is supposedly an old "
                                   "log, but no old LOV or MDT was found. "
                                   "Consider updating the configuration with"
                                   " --writeconf.\n", mti->mti_fsname);
        }

        RETURN(rc);
}
/* end COMPAT_146 */

int mgs_erase_log(const struct lu_env *env, struct mgs_device *mgs, char *name)
{
	struct lvfs_run_ctxt	 saved;
	struct llog_ctxt	*ctxt;
	int			 rc = 0;
	struct obd_device *obd = mgs->mgs_obd;

	ctxt = llog_get_context(obd, LLOG_CONFIG_ORIG_CTXT);
	if (ctxt == NULL) {
		CERROR("%s: MGS config context doesn't exist\n",
		       obd->obd_name);
		rc = -ENODEV;
	} else {
		push_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
		rc = llog_erase(NULL, ctxt, NULL, name);
		/* llog may not exist */
		if (rc == -ENOENT)
			rc = 0;
		pop_ctxt(&saved, &obd->obd_lvfs_ctxt, NULL);
		llog_ctxt_put(ctxt);
	}

	if (rc)
		CERROR("%s: failed to clear log %s: %d\n", obd->obd_name,
		       name, rc);

	return rc;
}

/* erase all logs for the given fs */
int mgs_erase_logs(const struct lu_env *env, struct mgs_device *mgs, char *fsname)
{
        struct fs_db *fsdb;
        cfs_list_t dentry_list;
        struct l_linux_dirent *dirent, *n;
        int rc, len = strlen(fsname);
        char *suffix;
        ENTRY;

        /* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &dentry_list);
        if (rc) {
                CERROR("Can't read %s dir\n", MOUNT_CONFIGS_DIR);
                RETURN(rc);
        }

        cfs_mutex_lock(&mgs->mgs_mutex);

        /* Delete the fs db */
	fsdb = mgs_find_fsdb(mgs, fsname);
        if (fsdb)
		mgs_free_fsdb(mgs, fsdb);

        cfs_list_for_each_entry_safe(dirent, n, &dentry_list, lld_list) {
                cfs_list_del(&dirent->lld_list);
                suffix = strrchr(dirent->lld_name, '-');
                if (suffix != NULL) {
                        if ((len == suffix - dirent->lld_name) &&
                            (strncmp(fsname, dirent->lld_name, len) == 0)) {
                                CDEBUG(D_MGS, "Removing log %s\n",
                                       dirent->lld_name);
				mgs_erase_log(env, mgs, dirent->lld_name);
                        }
                }
                OBD_FREE(dirent, sizeof(*dirent));
        }

        cfs_mutex_unlock(&mgs->mgs_mutex);

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
int mgs_setparam(const struct lu_env *env, struct mgs_device *mgs,
		 struct lustre_cfg *lcfg, char *fsname)
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

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
        if (rc)
                RETURN(rc);
        if (!cfs_test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags) &&
            cfs_test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
                CERROR("No filesystem targets for %s.  cfg_device from lctl "
                       "is '%s'\n", fsname, devname);
		mgs_free_fsdb(mgs, fsdb);
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

        cfs_mutex_lock(&fsdb->fsdb_mutex);
	rc = mgs_write_log_param(env, mgs, fsdb, mti, mti->mti_params);
        cfs_mutex_unlock(&fsdb->fsdb_mutex);

        /*
         * Revoke lock so everyone updates.  Should be alright if
         * someone was already reading while we were updating the logs,
         * so we don't really need to hold the lock while we're
         * writing (above).
         */
	mgs_revoke_lock(mgs, fsdb, CONFIG_T_CONFIG);
out:
        OBD_FREE_PTR(mti);
        RETURN(rc);
}

static int mgs_write_log_pool(const struct lu_env *env,
			      struct mgs_device *mgs, char *logname,
                              struct fs_db *fsdb, char *lovname,
                              enum lcfg_command_type cmd,
                              char *poolname, char *fsname,
                              char *ostname, char *comment)
{
        struct llog_handle *llh = NULL;
        int rc;

	rc = record_start_log(env, mgs, &llh, logname);
        if (rc)
                return rc;
	rc = record_marker(env, llh, fsdb, CM_START, lovname, comment);
	record_base(env, llh, lovname, 0, cmd, poolname, fsname, ostname, 0);
	rc = record_marker(env, llh, fsdb, CM_END, lovname, comment);
	rc = record_end_log(env, &llh);

        return rc;
}

int mgs_pool_cmd(const struct lu_env *env, struct mgs_device *mgs,
		 enum lcfg_command_type cmd, char *fsname,
		 char *poolname, char *ostname)
{
        struct fs_db *fsdb;
        char *lovname;
        char *logname;
        char *label = NULL, *canceled_label = NULL;
        int label_sz;
        struct mgs_target_info *mti = NULL;
        int rc, i;
        ENTRY;

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
        if (rc) {
                CERROR("Can't get db for %s\n", fsname);
                RETURN(rc);
        }
        if (cfs_test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
                CERROR("%s is not defined\n", fsname);
		mgs_free_fsdb(mgs, fsdb);
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
                GOTO(out, rc = -ENOMEM);

        switch(cmd) {
	case LCFG_POOL_NEW:
                sprintf(label,
                        "new %s.%s", fsname, poolname);
                break;
	case LCFG_POOL_ADD:
                sprintf(label,
                        "add %s.%s.%s", fsname, poolname, ostname);
                break;
	case LCFG_POOL_REM:
                OBD_ALLOC(canceled_label, label_sz);
                if (canceled_label == NULL)
                         GOTO(out, rc = -ENOMEM);
                sprintf(label,
                        "rem %s.%s.%s", fsname, poolname, ostname);
                sprintf(canceled_label,
                        "add %s.%s.%s", fsname, poolname, ostname);
                break;
	case LCFG_POOL_DEL:
                OBD_ALLOC(canceled_label, label_sz);
                if (canceled_label == NULL)
                         GOTO(out, rc = -ENOMEM);
                sprintf(label,
                        "del %s.%s", fsname, poolname);
                sprintf(canceled_label,
                        "new %s.%s", fsname, poolname);
                break;
	default:
                break;
        }

        cfs_mutex_lock(&fsdb->fsdb_mutex);

        if (canceled_label != NULL) {
                OBD_ALLOC_PTR(mti);
                if (mti == NULL)
                        GOTO(out, rc = -ENOMEM);
        }

        /* write pool def to all MDT logs */
        for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
                 if (cfs_test_bit(i,  fsdb->fsdb_mdt_index_map)) {
                        name_create_mdt_and_lov(&logname, &lovname, fsdb, i);

                        if (canceled_label != NULL) {
                                strcpy(mti->mti_svname, "lov pool");
				mgs_modify(env, mgs, fsdb, mti, logname,
					   lovname, canceled_label,
					   CM_SKIP);
                        }

			mgs_write_log_pool(env, mgs, logname, fsdb, lovname,
                                           cmd, fsname, poolname, ostname,
                                           label);
                        name_destroy(&logname);
                        name_destroy(&lovname);
                }
        }

        name_create(&logname, fsname, "-client");
        if (canceled_label != NULL)
		mgs_modify(env, mgs, fsdb, mti, logname, fsdb->fsdb_clilov,
                           canceled_label, CM_SKIP);

	mgs_write_log_pool(env, mgs, logname, fsdb, fsdb->fsdb_clilov,
                           cmd, fsname, poolname, ostname, label);
        name_destroy(&logname);

        cfs_mutex_unlock(&fsdb->fsdb_mutex);
        /* request for update */
	mgs_revoke_lock(mgs, fsdb, CONFIG_T_CONFIG);

        EXIT;
out:
        if (label != NULL)
                OBD_FREE(label, label_sz);

        if (canceled_label != NULL)
                OBD_FREE(canceled_label, label_sz);

        if (mti != NULL)
                OBD_FREE_PTR(mti);

        return rc;
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
