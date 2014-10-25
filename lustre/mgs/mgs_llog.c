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
 * Copyright (c) 2011, 2013, Intel Corporation.
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
 * Author: Alex Zhuravlev <bzzz@whamcloud.com>
 * Author: Mikhail Pershin <tappro@whamcloud.com>
 */

#define DEBUG_SUBSYSTEM S_MGS
#define D_MGS D_CONFIG

#include <obd.h>
#include <obd_lov.h>
#include <lustre_param.h>
#include <lustre_sec.h>
#include <lustre_quota.h>

#include "mgs_internal.h"

/********************** Class functions ********************/

int class_dentry_readdir(const struct lu_env *env,
			 struct mgs_device *mgs, cfs_list_t *list)
{
	struct dt_object    *dir = mgs->mgs_configs_dir;
	const struct dt_it_ops *iops;
	struct dt_it        *it;
	struct mgs_direntry *de;
	char		    *key;
	int		     rc, key_sz;

	CFS_INIT_LIST_HEAD(list);

	LASSERT(dir);
	LASSERT(dir->do_index_ops);

	iops = &dir->do_index_ops->dio_it;
	it = iops->init(env, dir, LUDA_64BITHASH, BYPASS_CAPA);
	if (IS_ERR(it))
		RETURN(PTR_ERR(it));

	rc = iops->load(env, it, 0);
	if (rc <= 0)
		GOTO(fini, rc = 0);

	/* main cycle */
	do {
		key = (void *)iops->key(env, it);
		if (IS_ERR(key)) {
			CERROR("%s: key failed when listing %s: rc = %d\n",
			       mgs->mgs_obd->obd_name, MOUNT_CONFIGS_DIR,
			       (int) PTR_ERR(key));
			goto next;
		}
		key_sz = iops->key_size(env, it);
		LASSERT(key_sz > 0);

		/* filter out "." and ".." entries */
		if (key[0] == '.') {
			if (key_sz == 1)
				goto next;
			if (key_sz == 2 && key[1] == '.')
				goto next;
		}

		de = mgs_direntry_alloc(key_sz + 1);
		if (de == NULL) {
			rc = -ENOMEM;
			break;
		}

		memcpy(de->name, key, key_sz);
		de->name[key_sz] = 0;

		cfs_list_add(&de->list, list);

next:
		rc = iops->next(env, it);
	} while (rc == 0);
	rc = 0;

	iops->put(env, it);

fini:
	iops->fini(env, it);
	if (rc)
		CERROR("%s: key failed when listing %s: rc = %d\n",
		       mgs->mgs_obd->obd_name, MOUNT_CONFIGS_DIR, rc);
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
	3. COMPAT_18 osc name
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
                fsdb->fsdb_mdt_count ++;
        }

	/**
	 * figure out the old config. fsdb_gen = 0 means old log
	 * It is obsoleted and not supported anymore
	 */
	if (fsdb->fsdb_gen == 0) {
		CERROR("Old config format is not supported\n");
		RETURN(-EINVAL);
	}

        /*
         * compat to 1.8, check osc name used by MDT0 to OSTs, bz18548.
         */
	if (!test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags) &&
            lcfg->lcfg_command == LCFG_ATTACH &&
            strcmp(lustre_cfg_string(lcfg, 1), LUSTRE_OSC_NAME) == 0) {
                if (OBD_OCD_VERSION_MAJOR(d->ver) == 1 &&
                    OBD_OCD_VERSION_MINOR(d->ver) <= 8) {
                        CWARN("MDT using 1.8 OSC name scheme\n");
			set_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags);
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
	char				*logname;
	struct llog_handle		*loghandle;
	struct llog_ctxt		*ctxt;
	struct mgs_fsdb_handler_data	 d = { fsdb, 0 };
	int rc;

	ENTRY;

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
	rc = name_create(&logname, fsdb->fsdb_name, "-client");
	if (rc)
		GOTO(out_put, rc);
	rc = llog_open_create(env, ctxt, &loghandle, NULL, logname);
	if (rc)
		GOTO(out_pop, rc);

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	if (llog_get_size(loghandle) <= 1)
		set_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags);

	rc = llog_process(env, loghandle, mgs_fsdb_handler, (void *)&d, NULL);
	CDEBUG(D_INFO, "get_db = %d\n", rc);
out_close:
	llog_close(env, loghandle);
out_pop:
        name_destroy(&logname);
out_put:
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
	mutex_init(&fsdb->fsdb_mutex);
	set_bit(FSDB_UDESC, &fsdb->fsdb_flags);
	fsdb->fsdb_gen = 1;

        if (strcmp(fsname, MGSSELF_NAME) == 0) {
		set_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags);
        } else {
                OBD_ALLOC(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
                OBD_ALLOC(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
                if (!fsdb->fsdb_ost_index_map || !fsdb->fsdb_mdt_index_map) {
                        CERROR("No memory for index maps\n");
			GOTO(err, rc = -ENOMEM);
                }

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
        OBD_FREE_PTR(fsdb);
        RETURN(NULL);
}

static void mgs_free_fsdb(struct mgs_device *mgs, struct fs_db *fsdb)
{
        /* wait for anyone with the sem */
	mutex_lock(&fsdb->fsdb_mutex);
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
        mgs_free_fsdb_srpc(fsdb);
	mutex_unlock(&fsdb->fsdb_mutex);
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
	mutex_lock(&mgs->mgs_mutex);
        cfs_list_for_each_safe(tmp, tmp2, &mgs->mgs_fs_db_list) {
                fsdb = cfs_list_entry(tmp, struct fs_db, fsdb_list);
		mgs_free_fsdb(mgs, fsdb);
        }
	mutex_unlock(&mgs->mgs_mutex);
        return 0;
}

int mgs_find_or_make_fsdb(const struct lu_env *env,
			  struct mgs_device *mgs, char *name,
                          struct fs_db **dbh)
{
        struct fs_db *fsdb;
        int rc = 0;

	ENTRY;
	mutex_lock(&mgs->mgs_mutex);
	fsdb = mgs_find_fsdb(mgs, name);
        if (fsdb) {
		mutex_unlock(&mgs->mgs_mutex);
                *dbh = fsdb;
		RETURN(0);
        }

        CDEBUG(D_MGS, "Creating new db\n");
	fsdb = mgs_new_fsdb(env, mgs, name);
	/* lock fsdb_mutex until the db is loaded from llogs */
	if (fsdb)
		mutex_lock(&fsdb->fsdb_mutex);
	mutex_unlock(&mgs->mgs_mutex);
        if (!fsdb)
		RETURN(-ENOMEM);

	if (!test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags)) {
                /* populate the db from the client llog */
		rc = mgs_get_fsdb_from_llog(env, mgs, fsdb);
                if (rc) {
                        CERROR("Can't get db from client log %d\n", rc);
			GOTO(out_free, rc);
                }
        }

        /* populate srpc rules from params llog */
	rc = mgs_get_fsdb_srpc_from_llog(env, mgs, fsdb);
        if (rc) {
                CERROR("Can't get db from params log %d\n", rc);
		GOTO(out_free, rc);
        }

	mutex_unlock(&fsdb->fsdb_mutex);
        *dbh = fsdb;

        RETURN(0);

out_free:
	mutex_unlock(&fsdb->fsdb_mutex);
	mgs_free_fsdb(mgs, fsdb);
	return rc;
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

	if (test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags))
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

	mutex_lock(&fsdb->fsdb_mutex);
        if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                imap = fsdb->fsdb_ost_index_map;
        } else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
                imap = fsdb->fsdb_mdt_index_map;
        } else {
		GOTO(out_up, rc = -EINVAL);
        }

        if (mti->mti_flags & LDD_F_NEED_INDEX) {
                rc = next_index(imap, INDEX_MAP_SIZE);
                if (rc == -1)
			GOTO(out_up, rc = -ERANGE);
                mti->mti_stripe_index = rc;
                if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
                        fsdb->fsdb_mdt_count ++;
        }

        if (mti->mti_stripe_index >= INDEX_MAP_SIZE * 8) {
                LCONSOLE_ERROR_MSG(0x13f, "Server %s requested index %d, "
                                   "but the max index is %d.\n",
                                   mti->mti_svname, mti->mti_stripe_index,
                                   INDEX_MAP_SIZE * 8);
		GOTO(out_up, rc = -ERANGE);
        }

	if (test_bit(mti->mti_stripe_index, imap)) {
                if ((mti->mti_flags & LDD_F_VIRGIN) &&
                    !(mti->mti_flags & LDD_F_WRITECONF)) {
                        LCONSOLE_ERROR_MSG(0x140, "Server %s requested index "
                                           "%d, but that index is already in "
                                           "use. Use --writeconf to force\n",
                                           mti->mti_svname,
                                           mti->mti_stripe_index);
			GOTO(out_up, rc = -EADDRINUSE);
                } else {
                        CDEBUG(D_MGS, "Server %s updating index %d\n",
                               mti->mti_svname, mti->mti_stripe_index);
			GOTO(out_up, rc = EALREADY);
                }
        }

	set_bit(mti->mti_stripe_index, imap);
	clear_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags);
	mutex_unlock(&fsdb->fsdb_mutex);
	server_make_name(mti->mti_flags & ~(LDD_F_VIRGIN | LDD_F_WRITECONF),
			 mti->mti_stripe_index, mti->mti_fsname, mti->mti_svname);

        CDEBUG(D_MGS, "Set index for %s to %d\n", mti->mti_svname,
               mti->mti_stripe_index);

        RETURN(0);
out_up:
	mutex_unlock(&fsdb->fsdb_mutex);
	return rc;
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
	struct lustre_cfg *lcfg = REC_DATA(rec);
	int cfg_len = REC_DATA_LEN(rec);
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
		rc = llog_write(env, llh, rec, NULL, 0, (void *)lcfg,
				rec->lrh_index);
                if (!rc)
                         mml->mml_modified++;
        }

        RETURN(rc);
}

/**
 * Modify an existing config log record (for CM_SKIP or CM_EXCLUDE)
 * Return code:
 * 0 - modified successfully,
 * 1 - no modification was done
 * negative - error
 */
static int mgs_modify(const struct lu_env *env, struct mgs_device *mgs,
		      struct fs_db *fsdb, struct mgs_target_info *mti,
		      char *logname, char *devname, char *comment, int flags)
{
        struct llog_handle *loghandle;
        struct llog_ctxt *ctxt;
        struct mgs_modify_lookup *mml;
	int rc;

        ENTRY;

	LASSERT(mutex_is_locked(&fsdb->fsdb_mutex));
	CDEBUG(D_MGS, "modify %s/%s/%s fl=%x\n", logname, devname, comment,
	       flags);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        LASSERT(ctxt != NULL);
	rc = llog_open(env, ctxt, &loghandle, NULL, logname, LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out_pop, rc);
	}

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);

        if (llog_get_size(loghandle) <= 1)
                GOTO(out_close, rc = 0);

        OBD_ALLOC_PTR(mml);
        if (!mml)
                GOTO(out_close, rc = -ENOMEM);
	if (strlcpy(mml->mml_marker.cm_comment, comment,
		    sizeof(mml->mml_marker.cm_comment)) >=
	    sizeof(mml->mml_marker.cm_comment))
		GOTO(out_close, rc = -E2BIG);
	if (strlcpy(mml->mml_marker.cm_tgtname, devname,
		    sizeof(mml->mml_marker.cm_tgtname)) >=
	    sizeof(mml->mml_marker.cm_tgtname))
		GOTO(out_close, rc = -E2BIG);
        /* Modify mostly means cancel */
        mml->mml_marker.cm_flags = flags;
        mml->mml_marker.cm_canceltime = flags ? cfs_time_current_sec() : 0;
        mml->mml_modified = 0;
	rc = llog_process(env, loghandle, mgs_modify_handler, (void *)mml,
			  NULL);
	if (!rc && !mml->mml_modified)
		rc = 1;
        OBD_FREE_PTR(mml);

out_close:
	llog_close(env, loghandle);
out_pop:
	if (rc < 0)
		CERROR("%s: modify %s/%s failed: rc = %d\n",
		       mgs->mgs_obd->obd_name, mti->mti_svname, comment, rc);
        llog_ctxt_put(ctxt);
        RETURN(rc);
}

/** This structure is passed to mgs_replace_handler */
struct mgs_replace_uuid_lookup {
	/* Nids are replaced for this target device */
	struct mgs_target_info target;
	/* Temporary modified llog */
	struct llog_handle *temp_llh;
	/* Flag is set if in target block*/
	int in_target_device;
	/* Nids already added. Just skip (multiple nids) */
	int device_nids_added;
	/* Flag is set if this block should not be copied */
	int skip_it;
};

/**
 * Check: a) if block should be skipped
 * b) is it target block
 *
 * \param[in] lcfg
 * \param[in] mrul
 *
 * \retval 0 should not to be skipped
 * \retval 1 should to be skipped
 */
static int check_markers(struct lustre_cfg *lcfg,
			 struct mgs_replace_uuid_lookup *mrul)
{
	 struct cfg_marker *marker;

	/* Track markers. Find given device */
	if (lcfg->lcfg_command == LCFG_MARKER) {
		marker = lustre_cfg_buf(lcfg, 1);
		/* Clean llog from records marked as CM_EXCLUDE.
		   CM_SKIP records are used for "active" command
		   and can be restored if needed */
		if ((marker->cm_flags & (CM_EXCLUDE | CM_START)) ==
		    (CM_EXCLUDE | CM_START)) {
			mrul->skip_it = 1;
			return 1;
		}

		if ((marker->cm_flags & (CM_EXCLUDE | CM_END)) ==
		    (CM_EXCLUDE | CM_END)) {
			mrul->skip_it = 0;
			return 1;
		}

		if (strcmp(mrul->target.mti_svname, marker->cm_tgtname) == 0) {
			LASSERT(!(marker->cm_flags & CM_START) ||
				!(marker->cm_flags & CM_END));
			if (marker->cm_flags & CM_START) {
				mrul->in_target_device = 1;
				mrul->device_nids_added = 0;
			} else if (marker->cm_flags & CM_END)
				mrul->in_target_device = 0;
		}
	}

	return 0;
}

static int record_lcfg(const struct lu_env *env, struct llog_handle *llh,
		       struct lustre_cfg *lcfg)
{
	struct llog_rec_hdr	 rec;
	int			 buflen, rc;

        if (!lcfg || !llh)
                return -ENOMEM;

        LASSERT(llh->lgh_ctxt);

        buflen = lustre_cfg_len(lcfg->lcfg_bufcount,
                                lcfg->lcfg_buflens);
        rec.lrh_len = llog_data_len(buflen);
        rec.lrh_type = OBD_CFG_REC;

        /* idx = -1 means append */
	rc = llog_write(env, llh, &rec, NULL, 0, (void *)lcfg, -1);
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

/**
 * \retval <0 record processing error
 * \retval n record is processed. No need copy original one.
 * \retval 0 record is not processed.
 */
static int process_command(const struct lu_env *env, struct lustre_cfg *lcfg,
			   struct mgs_replace_uuid_lookup *mrul)
{
	int nids_added = 0;
	lnet_nid_t nid;
	char *ptr;
	int rc;

	if (lcfg->lcfg_command == LCFG_ADD_UUID) {
		/* LCFG_ADD_UUID command found. Let's skip original command
		   and add passed nids */
		ptr = mrul->target.mti_params;
		while (class_parse_nid(ptr, &nid, &ptr) == 0) {
			CDEBUG(D_MGS, "add nid %s with uuid %s, "
			       "device %s\n", libcfs_nid2str(nid),
				mrul->target.mti_params,
				mrul->target.mti_svname);
			rc = record_add_uuid(env,
					     mrul->temp_llh, nid,
					     mrul->target.mti_params);
			if (!rc)
				nids_added++;
		}

		if (nids_added == 0) {
			CERROR("No new nids were added, nid %s with uuid %s, "
			       "device %s\n", libcfs_nid2str(nid),
			       mrul->target.mti_params,
			       mrul->target.mti_svname);
			RETURN(-ENXIO);
		} else {
			mrul->device_nids_added = 1;
		}

		return nids_added;
	}

	if (mrul->device_nids_added && lcfg->lcfg_command == LCFG_SETUP) {
		/* LCFG_SETUP command found. UUID should be changed */
		rc = record_setup(env,
				  mrul->temp_llh,
				  /* devname the same */
				  lustre_cfg_string(lcfg, 0),
				  /* s1 is not changed */
				  lustre_cfg_string(lcfg, 1),
				  /* new uuid should be
				  the full nidlist */
				  mrul->target.mti_params,
				  /* s3 is not changed */
				  lustre_cfg_string(lcfg, 3),
				  /* s4 is not changed */
				  lustre_cfg_string(lcfg, 4));
		return rc ? rc : 1;
	}

	/* Another commands in target device block */
	return 0;
}

/**
 * Handler that called for every record in llog.
 * Records are processed in order they placed in llog.
 *
 * \param[in] llh       log to be processed
 * \param[in] rec       current record
 * \param[in] data      mgs_replace_uuid_lookup structure
 *
 * \retval 0    success
 */
static int mgs_replace_handler(const struct lu_env *env,
			       struct llog_handle *llh,
			       struct llog_rec_hdr *rec,
			       void *data)
{
	struct mgs_replace_uuid_lookup *mrul;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	int cfg_len = REC_DATA_LEN(rec);
	int rc;
	ENTRY;

	mrul = (struct mgs_replace_uuid_lookup *)data;

	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("unhandled lrh_type: %#x, cmd %x %s %s\n",
		       rec->lrh_type, lcfg->lcfg_command,
		       lustre_cfg_string(lcfg, 0),
		       lustre_cfg_string(lcfg, 1));
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, cfg_len);
	if (rc) {
		/* Do not copy any invalidated records */
		GOTO(skip_out, rc = 0);
	}

	rc = check_markers(lcfg, mrul);
	if (rc || mrul->skip_it)
		GOTO(skip_out, rc = 0);

	/* Write to new log all commands outside target device block */
	if (!mrul->in_target_device)
		GOTO(copy_out, rc = 0);

	/* Skip all other LCFG_ADD_UUID and LCFG_ADD_CONN records
	   (failover nids) for this target, assuming that if then
	   primary is changing then so is the failover */
	if (mrul->device_nids_added &&
	    (lcfg->lcfg_command == LCFG_ADD_UUID ||
	     lcfg->lcfg_command == LCFG_ADD_CONN))
		GOTO(skip_out, rc = 0);

	rc = process_command(env, lcfg, mrul);
	if (rc < 0)
		RETURN(rc);

	if (rc)
		RETURN(0);
copy_out:
	/* Record is placed in temporary llog as is */
	rc = llog_write(env, mrul->temp_llh, rec, NULL, 0, NULL, -1);

	CDEBUG(D_MGS, "Copied idx=%d, rc=%d, len=%d, cmd %x %s %s\n",
	       rec->lrh_index, rc, rec->lrh_len, lcfg->lcfg_command,
	       lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));
	RETURN(rc);

skip_out:
	CDEBUG(D_MGS, "Skipped idx=%d, rc=%d, len=%d, cmd %x %s %s\n",
	       rec->lrh_index, rc, rec->lrh_len, lcfg->lcfg_command,
	       lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));
	RETURN(rc);
}

static int mgs_log_is_empty(const struct lu_env *env,
			    struct mgs_device *mgs, char *name)
{
	struct llog_ctxt	*ctxt;
	int			 rc;

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	rc = llog_is_empty(env, ctxt, name);
	llog_ctxt_put(ctxt);
	return rc;
}

static int mgs_replace_nids_log(const struct lu_env *env,
				struct obd_device *mgs, struct fs_db *fsdb,
				char *logname, char *devname, char *nids)
{
	struct llog_handle *orig_llh, *backup_llh;
	struct llog_ctxt *ctxt;
	struct mgs_replace_uuid_lookup *mrul;
	struct mgs_device *mgs_dev = lu2mgs_dev(mgs->obd_lu_dev);
	static struct obd_uuid	 cfg_uuid = { .uuid = "config_uuid" };
	char *backup;
	int rc, rc2;
	ENTRY;

	CDEBUG(D_MGS, "Replace nids for %s in %s\n", devname, logname);

	ctxt = llog_get_context(mgs, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	if (mgs_log_is_empty(env, mgs_dev, logname)) {
		/* Log is empty. Nothing to replace */
		GOTO(out_put, rc = 0);
	}

	OBD_ALLOC(backup, strlen(logname) + strlen(".bak") + 1);
	if (backup == NULL)
		GOTO(out_put, rc = -ENOMEM);

	sprintf(backup, "%s.bak", logname);

	rc = llog_backup(env, mgs, ctxt, ctxt, logname, backup);
	if (rc == 0) {
		/* Now erase original log file. Connections are not allowed.
		   Backup is already saved */
		rc = llog_erase(env, ctxt, NULL, logname);
		if (rc < 0)
			GOTO(out_free, rc);
	} else if (rc != -ENOENT) {
		CERROR("%s: can't make backup for %s: rc = %d\n",
		       mgs->obd_name, logname, rc);
		GOTO(out_free,rc);
	}

	/* open local log */
	rc = llog_open_create(env, ctxt, &orig_llh, NULL, logname);
	if (rc)
		GOTO(out_restore, rc);

	rc = llog_init_handle(env, orig_llh, LLOG_F_IS_PLAIN, &cfg_uuid);
	if (rc)
		GOTO(out_closel, rc);

	/* open backup llog */
	rc = llog_open(env, ctxt, &backup_llh, NULL, backup,
		       LLOG_OPEN_EXISTS);
	if (rc)
		GOTO(out_closel, rc);

	rc = llog_init_handle(env, backup_llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	if (llog_get_size(backup_llh) <= 1)
		GOTO(out_close, rc = 0);

	OBD_ALLOC_PTR(mrul);
	if (!mrul)
		GOTO(out_close, rc = -ENOMEM);
	/* devname is only needed information to replace UUID records */
	strncpy(mrul->target.mti_svname, devname, MTI_NAME_MAXLEN);
	/* parse nids later */
	strncpy(mrul->target.mti_params, nids, MTI_PARAM_MAXLEN);
	/* Copy records to this temporary llog */
	mrul->temp_llh = orig_llh;

	rc = llog_process(env, backup_llh, mgs_replace_handler,
			  (void *)mrul, NULL);
	OBD_FREE_PTR(mrul);
out_close:
	rc2 = llog_close(NULL, backup_llh);
	if (!rc)
		rc = rc2;
out_closel:
	rc2 = llog_close(NULL, orig_llh);
	if (!rc)
		rc = rc2;

out_restore:
	if (rc) {
		CERROR("%s: llog should be restored: rc = %d\n",
		       mgs->obd_name, rc);
		rc2 = llog_backup(env, mgs, ctxt, ctxt, backup,
				  logname);
		if (rc2 < 0)
			CERROR("%s: can't restore backup %s: rc = %d\n",
			       mgs->obd_name, logname, rc2);
	}

out_free:
	OBD_FREE(backup, strlen(backup) + 1);

out_put:
	llog_ctxt_put(ctxt);

	if (rc)
		CERROR("%s: failed to replace nids in log %s: rc = %d\n",
		       mgs->obd_name, logname, rc);

	RETURN(rc);
}

/**
 * Parse device name and get file system name and/or device index
 *
 * \param[in]   devname device name (ex. lustre-MDT0000)
 * \param[out]  fsname  file system name(optional)
 * \param[out]  index   device index(optional)
 *
 * \retval 0    success
 */
static int mgs_parse_devname(char *devname, char *fsname, __u32 *index)
{
	int rc;
	ENTRY;

	/* Extract fsname */
	if (fsname) {
		rc = server_name2fsname(devname, fsname, NULL);
		if (rc < 0) {
			CDEBUG(D_MGS, "Device name %s without fsname\n",
			       devname);
			RETURN(-EINVAL);
		}
	}

	if (index) {
		rc = server_name2index(devname, index, NULL);
		if (rc < 0) {
			CDEBUG(D_MGS, "Device name %s with wrong index\n",
			       devname);
			RETURN(-EINVAL);
		}
	}

	RETURN(0);
}

static int only_mgs_is_running(struct obd_device *mgs_obd)
{
	/* TDB: Is global variable with devices count exists? */
	int num_devices = get_devices_count();
	/* osd, MGS and MGC + self_export
	   (wc -l /proc/fs/lustre/devices <= 2) && (num_exports <= 2) */
	return (num_devices <= 3) && (mgs_obd->obd_num_exports <= 2);
}

static int name_create_mdt(char **logname, char *fsname, int i)
{
	char mdt_index[9];

	sprintf(mdt_index, "-MDT%04x", i);
	return name_create(logname, fsname, mdt_index);
}

/**
 * Replace nids for \a device to \a nids values
 *
 * \param obd           MGS obd device
 * \param devname       nids need to be replaced for this device
 * (ex. lustre-OST0000)
 * \param nids          nids list (ex. nid1,nid2,nid3)
 *
 * \retval 0    success
 */
int mgs_replace_nids(const struct lu_env *env,
		     struct mgs_device *mgs,
		     char *devname, char *nids)
{
	/* Assume fsname is part of device name */
	char fsname[MTI_NAME_MAXLEN];
	int rc;
	__u32 index;
	char *logname;
	struct fs_db *fsdb;
	unsigned int i;
	int conn_state;
	struct obd_device *mgs_obd = mgs->mgs_obd;
	ENTRY;

	/* We can only change NIDs if no other nodes are connected */
	spin_lock(&mgs_obd->obd_dev_lock);
	conn_state = mgs_obd->obd_no_conn;
	mgs_obd->obd_no_conn = 1;
	spin_unlock(&mgs_obd->obd_dev_lock);

	/* We can not change nids if not only MGS is started */
	if (!only_mgs_is_running(mgs_obd)) {
		CERROR("Only MGS is allowed to be started\n");
		GOTO(out, rc = -EINPROGRESS);
	}

	/* Get fsname and index*/
	rc = mgs_parse_devname(devname, fsname, &index);
	if (rc)
		GOTO(out, rc);

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
	if (rc) {
		CERROR("%s: can't find fsdb: rc = %d\n", fsname, rc);
		GOTO(out, rc);
	}

	/* Process client llogs */
	name_create(&logname, fsname, "-client");
	rc = mgs_replace_nids_log(env, mgs_obd, fsdb, logname, devname, nids);
	name_destroy(&logname);
	if (rc) {
		CERROR("%s: error while replacing NIDs for %s: rc = %d\n",
		       fsname, devname, rc);
		GOTO(out, rc);
	}

	/* Process MDT llogs */
	for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
		if (!test_bit(i, fsdb->fsdb_mdt_index_map))
			continue;
		name_create_mdt(&logname, fsname, i);
		rc = mgs_replace_nids_log(env, mgs_obd, fsdb, logname, devname, nids);
		name_destroy(&logname);
		if (rc)
			GOTO(out, rc);
	}

out:
	spin_lock(&mgs_obd->obd_dev_lock);
	mgs_obd->obd_no_conn = conn_state;
	spin_unlock(&mgs_obd->obd_dev_lock);

	RETURN(rc);
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
			   ost_uuid, index, gen, 0);
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
	int cplen = 0;

	if (flags & CM_START)
		fsdb->fsdb_gen++;
	mgi->mgi_marker.cm_step = fsdb->fsdb_gen;
	mgi->mgi_marker.cm_flags = flags;
	mgi->mgi_marker.cm_vers = LUSTRE_VERSION_CODE;
	cplen = strlcpy(mgi->mgi_marker.cm_tgtname, tgtname,
			sizeof(mgi->mgi_marker.cm_tgtname));
	if (cplen >= sizeof(mgi->mgi_marker.cm_tgtname))
		return -E2BIG;
	cplen = strlcpy(mgi->mgi_marker.cm_comment, comment,
			sizeof(mgi->mgi_marker.cm_comment));
	if (cplen >= sizeof(mgi->mgi_marker.cm_comment))
		return -E2BIG;
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

static int record_start_log(const struct lu_env *env, struct mgs_device *mgs,
			    struct llog_handle **llh, char *name)
{
	static struct obd_uuid	 cfg_uuid = { .uuid = "config_uuid" };
	struct llog_ctxt	*ctxt;
	int			 rc = 0;
	ENTRY;

	if (*llh)
		GOTO(out, rc = -EBUSY);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
        if (!ctxt)
                GOTO(out, rc = -ENODEV);
	LASSERT(ctxt->loc_obd == mgs->mgs_obd);

	rc = llog_open_create(env, ctxt, llh, NULL, name);
	if (rc)
		GOTO(out_ctxt, rc);
	rc = llog_init_handle(env, *llh, LLOG_F_IS_PLAIN, &cfg_uuid);
	if (rc)
		llog_close(env, *llh);
out_ctxt:
	llog_ctxt_put(ctxt);
out:
	if (rc) {
		CERROR("%s: can't start log %s: rc = %d\n",
		       mgs->mgs_obd->obd_name, name, rc);
		*llh = NULL;
	}
	RETURN(rc);
}

static int record_end_log(const struct lu_env *env, struct llog_handle **llh)
{
	int rc;

	rc = llog_close(env, *llh);
	*llh = NULL;

	return rc;
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
	if (rc)
		GOTO(out_end, rc);
	rc = record_lcfg(env, llh, lcfg);
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, devname, comment);
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
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
	cfs_list_t list;
	struct mgs_direntry *dirent, *n;
        char *fsname = mti->mti_fsname;
        int rc = 0, len = strlen(fsname);
        ENTRY;

        /* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &list);
	if (rc)
                RETURN(rc);

        /* Could use fsdb index maps instead of directory listing */
	cfs_list_for_each_entry_safe(dirent, n, &list, list) {
		cfs_list_del(&dirent->list);
                /* don't write to sptlrpc rule log */
		if (strstr(dirent->name, "-sptlrpc") != NULL)
			goto next;

		/* caller wants write server logs only */
		if (server_only && strstr(dirent->name, "-client") != NULL)
			goto next;

		if (strncmp(fsname, dirent->name, len) == 0) {
			CDEBUG(D_MGS, "Changing log %s\n", dirent->name);
                        /* Erase any old settings of this same parameter */
			rc = mgs_modify(env, mgs, fsdb, mti, dirent->name,
					devname, comment, CM_SKIP);
			if (rc < 0)
				CERROR("%s: Can't modify llog %s: rc = %d\n",
				       mgs->mgs_obd->obd_name, dirent->name,rc);
                        /* Write the new one */
                        if (lcfg) {
				rc = mgs_write_log_direct(env, mgs, fsdb,
							  dirent->name,
							  lcfg, devname,
							  comment);
                                if (rc)
					CERROR("%s: writing log %s: rc = %d\n",
					       mgs->mgs_obd->obd_name,
					       dirent->name, rc);
                        }
                }
next:
		mgs_direntry_free(dirent);
        }

        RETURN(rc);
}

static int mgs_write_log_osp_to_mdt(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    struct mgs_target_info *mti,
				    int index, char *logname);
static int mgs_write_log_osc_to_lov(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
                                    struct mgs_target_info *mti,
				    char *logname, char *suffix, char *lovname,
                                    enum lustre_sec_part sec_part, int flags);
static int name_create_mdt_and_lov(char **logname, char **lovname,
				   struct fs_db *fsdb, int i);

static int add_param(char *params, char *key, char *val)
{
	char *start = params + strlen(params);
	char *end = params + sizeof(((struct mgs_target_info *)0)->mti_params);
	int keylen = 0;

	if (key != NULL)
		keylen = strlen(key);
	if (start + 1 + keylen + strlen(val) >= end) {
		CERROR("params are too long: %s %s%s\n",
		       params, key != NULL ? key : "", val);
		return -EINVAL;
	}

	sprintf(start, " %s%s", key != NULL ? key : "", val);
	return 0;
}

/**
 * Walk through client config log record and convert the related records
 * into the target.
 **/
static int mgs_steal_client_llog_handler(const struct lu_env *env,
					 struct llog_handle *llh,
					 struct llog_rec_hdr *rec, void *data)
{
	struct mgs_device *mgs;
	struct obd_device *obd;
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
	int cplen = 0;

        ENTRY;

        mti = ((struct temp_comp*)data)->comp_mti;
        tmti = ((struct temp_comp*)data)->comp_tmti;
        fsdb = ((struct temp_comp*)data)->comp_fsdb;
	obd = ((struct temp_comp *)data)->comp_obd;
	mgs = lu2mgs_dev(obd->obd_lu_dev);
	LASSERT(mgs);

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
		if (!strncmp(marker->cm_comment, "add osc", 7) &&
		    (marker->cm_flags & CM_START) &&
		     !(marker->cm_flags & CM_SKIP)) {
			got_an_osc_or_mdc = 1;
			cplen = strlcpy(tmti->mti_svname, marker->cm_tgtname,
					sizeof(tmti->mti_svname));
			if (cplen >= sizeof(tmti->mti_svname))
				RETURN(-E2BIG);
			rc = record_start_log(env, mgs, &mdt_llh,
					      mti->mti_svname);
			if (rc)
				RETURN(rc);
			rc = record_marker(env, mdt_llh, fsdb, CM_START,
					   mti->mti_svname, "add osc(copied)");
			record_end_log(env, &mdt_llh);
			last_step = marker->cm_step;
			RETURN(rc);
		}
		if (!strncmp(marker->cm_comment, "add osc", 7) &&
		    (marker->cm_flags & CM_END) &&
		     !(marker->cm_flags & CM_SKIP)) {
			LASSERT(last_step == marker->cm_step);
			last_step = -1;
			got_an_osc_or_mdc = 0;
			memset(tmti, 0, sizeof(*tmti));
			rc = record_start_log(env, mgs, &mdt_llh,
					      mti->mti_svname);
			if (rc)
				RETURN(rc);
			rc = record_marker(env, mdt_llh, fsdb, CM_END,
					   mti->mti_svname, "add osc(copied)");
			record_end_log(env, &mdt_llh);
			RETURN(rc);
		}
		if (!strncmp(marker->cm_comment, "add mdc", 7) &&
		    (marker->cm_flags & CM_START) &&
		     !(marker->cm_flags & CM_SKIP)) {
			got_an_osc_or_mdc = 2;
			last_step = marker->cm_step;
			memcpy(tmti->mti_svname, marker->cm_tgtname,
			       strlen(marker->cm_tgtname));

			RETURN(rc);
		}
		if (!strncmp(marker->cm_comment, "add mdc", 7) &&
		    (marker->cm_flags & CM_END) &&
		     !(marker->cm_flags & CM_SKIP)) {
			LASSERT(last_step == marker->cm_step);
			last_step = -1;
			got_an_osc_or_mdc = 0;
			memset(tmti, 0, sizeof(*tmti));
			RETURN(rc);
		}
	}

        if (got_an_osc_or_mdc == 0 || last_step < 0)
                RETURN(rc);

	if (lcfg->lcfg_command == LCFG_ADD_UUID) {
		uint64_t nodenid = lcfg->lcfg_nid;

		if (strlen(tmti->mti_uuid) == 0) {
			/* target uuid not set, this config record is before
			 * LCFG_SETUP, this nid is one of target node nid.
			 */
			tmti->mti_nids[tmti->mti_nid_count] = nodenid;
			tmti->mti_nid_count++;
		} else {
			/* failover node nid */
			rc = add_param(tmti->mti_params, PARAM_FAILNODE,
				       libcfs_nid2str(nodenid));
		}

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

		rc = mgs_write_log_osp_to_mdt(env, mgs, fsdb, tmti,
					      mti->mti_stripe_index,
					      mti->mti_svname);
                memset(tmti, 0, sizeof(*tmti));
                RETURN(rc);
        }

        if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD) {
                int index;
                char mdt_index[9];
                char *logname, *lovname;

		rc = name_create_mdt_and_lov(&logname, &lovname, fsdb,
					     mti->mti_stripe_index);
		if (rc)
			RETURN(rc);
                sprintf(mdt_index, "-MDT%04x", mti->mti_stripe_index);

                if (sscanf(lustre_cfg_buf(lcfg, 2), "%d", &index) != 1) {
                        name_destroy(&logname);
                        name_destroy(&lovname);
                        RETURN(-EINVAL);
                }

                tmti->mti_stripe_index = index;
		rc = mgs_write_log_osc_to_lov(env, mgs, fsdb, tmti, logname,
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
	comp->comp_obd = mgs->mgs_obd;

	rc = llog_open(env, ctxt, &loghandle, NULL, client_name,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out_pop, rc);
	}

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	rc = llog_process_or_fork(env, loghandle, mgs_steal_client_llog_handler,
				  (void *)comp, NULL, false);
	CDEBUG(D_MGS, "steal llog re = %d\n", rc);
out_close:
	llog_close(env, loghandle);
out_pop:
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
	if (rc)
		GOTO(out_free, rc);
	rc = record_marker(env, llh, fsdb, CM_START, lmvname, "lmv setup");
	if (rc)
		GOTO(out_end, rc);
	rc = record_attach(env, llh, lmvname, "lmv", uuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_lmv_setup(env, llh, lmvname, lmvdesc);
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, lmvname, "lmv setup");
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
out_free:
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
		GOTO(out_free, rc);
        /* FIXME these should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, lovname, "lov setup");
	if (rc)
		GOTO(out_end, rc);
	rc = record_attach(env, llh, lovname, "lov", uuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_lov_setup(env, llh, lovname, lovdesc);
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, lovname, "lov setup");
	if (rc)
		GOTO(out_end, rc);
        EXIT;
out_end:
	record_end_log(env, &llh);
out_free:
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
	char *mdcname = NULL;
	char *nodeuuid = NULL;
	char *mdcuuid = NULL;
	char *lmvuuid = NULL;
        char index[6];
        int i, rc;
        ENTRY;

	if (mgs_log_is_empty(env, mgs, logname)) {
                CERROR("log is empty! Logical error\n");
                RETURN(-EINVAL);
        }

        CDEBUG(D_MGS, "adding mdc for %s to log %s:lmv(%s)\n",
               mti->mti_svname, logname, lmvname);

	rc = name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
	if (rc)
		RETURN(rc);
	rc = name_create(&mdcname, mti->mti_svname, "-mdc");
	if (rc)
		GOTO(out_free, rc);
	rc = name_create(&mdcuuid, mdcname, "_UUID");
	if (rc)
		GOTO(out_free, rc);
	rc = name_create(&lmvuuid, lmvname, "_UUID");
	if (rc)
		GOTO(out_free, rc);

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		GOTO(out_free, rc);
	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,
                           "add mdc");
	if (rc)
		GOTO(out_end, rc);
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s for mdt\n",
                       libcfs_nid2str(mti->mti_nids[i]));

		rc = record_add_uuid(env, llh, mti->mti_nids[i], nodeuuid);
		if (rc)
			GOTO(out_end, rc);
        }

	rc = record_attach(env, llh, mdcname, LUSTRE_MDC_NAME, lmvuuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, mdcname, mti->mti_uuid, nodeuuid, 0, 0);
	if (rc)
		GOTO(out_end, rc);
	rc = mgs_write_log_failnids(env, mti, llh, mdcname);
	if (rc)
		GOTO(out_end, rc);
        snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);
	rc = record_mdc_add(env, llh, lmvname, mdcuuid, mti->mti_uuid,
                            index, "1");
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, mti->mti_svname,
                           "add mdc");
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
out_free:
        name_destroy(&lmvuuid);
        name_destroy(&mdcuuid);
        name_destroy(&mdcname);
        name_destroy(&nodeuuid);
        RETURN(rc);
}

static inline int name_create_lov(char **lovname, char *mdtname,
				  struct fs_db *fsdb, int index)
{
	/* COMPAT_180 */
	if (index == 0 && test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags))
		return name_create(lovname, fsdb->fsdb_name, "-mdtlov");
	else
		return name_create(lovname, mdtname, "-mdtlov");
}

static int name_create_mdt_and_lov(char **logname, char **lovname,
				   struct fs_db *fsdb, int i)
{
	int rc;

	rc = name_create_mdt(logname, fsdb->fsdb_name, i);
	if (rc)
		return rc;
	/* COMPAT_180 */
	if (i == 0 && test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags))
		rc = name_create(lovname, fsdb->fsdb_name, "-mdtlov");
	else
		rc = name_create(lovname, *logname, "-mdtlov");
	if (rc) {
		name_destroy(logname);
		*logname = NULL;
	}
	return rc;
}

static inline int name_create_mdt_osc(char **oscname, char *ostname,
				      struct fs_db *fsdb, int i)
{
	char suffix[16];

	if (i == 0 && test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags))
		sprintf(suffix, "-osc");
	else
		sprintf(suffix, "-osc-MDT%04x", i);
	return name_create(oscname, ostname, suffix);
}

/* add new mdc to already existent MDS */
static int mgs_write_log_osp_to_mdt(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    struct mgs_target_info *mti,
				    int mdt_index, char *logname)
{
	struct llog_handle	*llh = NULL;
	char	*nodeuuid = NULL;
	char	*ospname = NULL;
	char	*lovuuid = NULL;
	char	*mdtuuid = NULL;
	char	*svname = NULL;
	char	*mdtname = NULL;
	char	*lovname = NULL;
	char	index_str[16];
	int	i, rc;

	ENTRY;
	if (mgs_log_is_empty(env, mgs, mti->mti_svname)) {
                CERROR("log is empty! Logical error\n");
                RETURN (-EINVAL);
        }

	CDEBUG(D_MGS, "adding osp index %d to %s\n", mti->mti_stripe_index,
	       logname);

	rc = name_create_mdt(&mdtname, fsdb->fsdb_name, mti->mti_stripe_index);
	if (rc)
		RETURN(rc);

	rc = name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create(&svname, mdtname, "-osp");
	if (rc)
		GOTO(out_destory, rc);

	sprintf(index_str, "-MDT%04x", mdt_index);
	rc = name_create(&ospname, svname, index_str);
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create_lov(&lovname, logname, fsdb, mdt_index);
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create(&lovuuid, lovname, "_UUID");
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create(&mdtuuid, mdtname, "_UUID");
	if (rc)
		GOTO(out_destory, rc);

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		GOTO(out_destory, rc);

	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,
			   "add osp");
	if (rc)
		GOTO(out_destory, rc);

	for (i = 0; i < mti->mti_nid_count; i++) {
		CDEBUG(D_MGS, "add nid %s for mdt\n",
		       libcfs_nid2str(mti->mti_nids[i]));
		rc = record_add_uuid(env, llh, mti->mti_nids[i], nodeuuid);
		if (rc)
			GOTO(out_end, rc);
        }

	rc = record_attach(env, llh, ospname, LUSTRE_OSP_NAME, lovuuid);
	if (rc)
		GOTO(out_end, rc);

	rc = record_setup(env, llh, ospname, mti->mti_uuid, nodeuuid,
			  NULL, NULL);
	if (rc)
		GOTO(out_end, rc);

	rc = mgs_write_log_failnids(env, mti, llh, ospname);
	if (rc)
		GOTO(out_end, rc);

	/* Add mdc(osp) to lod */
	snprintf(index_str, sizeof(mti->mti_stripe_index), "%d",
		 mti->mti_stripe_index);
	rc = record_base(env, llh, lovname, 0, LCFG_ADD_MDC, mti->mti_uuid,
			 index_str, "1", NULL);
	if (rc)
		GOTO(out_end, rc);

	rc = record_marker(env, llh, fsdb, CM_END, mti->mti_svname, "add osp");
	if (rc)
		GOTO(out_end, rc);

out_end:
	record_end_log(env, &llh);

out_destory:
	name_destroy(&mdtuuid);
	name_destroy(&lovuuid);
	name_destroy(&lovname);
	name_destroy(&ospname);
	name_destroy(&svname);
        name_destroy(&nodeuuid);
	name_destroy(&mdtname);
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

	rc = name_create(&lovname, log, "-mdtlov");
	if (rc)
		GOTO(out_free, rc);
	if (mgs_log_is_empty(env, mgs, log)) {
		rc = mgs_write_log_lov(env, mgs, fsdb, mti, log, lovname);
		if (rc)
			GOTO(out_lod, rc);
	}

        sprintf(mdt_index, "%d", mti->mti_stripe_index);

	rc = record_start_log(env, mgs, &llh, log);
	if (rc)
		GOTO(out_lod, rc);

	/* add MDT itself */

        /* FIXME this whole fn should be a single journal transaction */
	sprintf(uuid, "%s_UUID", log);
	rc = record_marker(env, llh, fsdb, CM_START, log, "add mdt");
	if (rc)
		GOTO(out_lod, rc);
	rc = record_attach(env, llh, log, LUSTRE_MDT_NAME, uuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_mount_opt(env, llh, log, lovname, NULL);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, log, uuid, mdt_index, lovname,
                        failout ? "n" : "f");
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, log, "add mdt");
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
out_lod:
	name_destroy(&lovname);
out_free:
        OBD_FREE(uuid, sizeof(struct obd_uuid));
        RETURN(rc);
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

        if (mti->mti_uuid[0] == '\0') {
                /* Make up our own uuid */
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
        }

        /* add mdt */
	rc = mgs_write_log_mdt0(env, mgs, fsdb, mti);
	if (rc)
		RETURN(rc);
        /* Append the mdt info to the client log */
	rc = name_create(&cliname, mti->mti_fsname, "-client");
	if (rc)
		RETURN(rc);

	if (mgs_log_is_empty(env, mgs, cliname)) {
                /* Start client log */
		rc = mgs_write_log_lov(env, mgs, fsdb, mti, cliname,
                                       fsdb->fsdb_clilov);
		if (rc)
			GOTO(out_free, rc);
		rc = mgs_write_log_lmv(env, mgs, fsdb, mti, cliname,
                                       fsdb->fsdb_clilmv);
		if (rc)
			GOTO(out_free, rc);
        }

        /*
        #09 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
        #10 L attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f
        #11 L setup    0:MDC_uml1_mdsA_MNT_client  1:mdsA_UUID  2:uml1_UUID
        #12 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
        #13 L add_conn 0:MDC_uml1_mdsA_MNT_client  1:uml2_UUID
        #14 L mount_option 0:  1:client  2:lov1  3:MDC_uml1_mdsA_MNT_client
        */

                /* copy client info about lov/lmv */
		mgi->mgi_comp.comp_mti = mti;
		mgi->mgi_comp.comp_fsdb = fsdb;

		rc = mgs_steal_llog_for_mdt_from_client(env, mgs, cliname,
							&mgi->mgi_comp);
		if (rc)
			GOTO(out_free, rc);
		rc = mgs_write_log_mdc_to_lmv(env, mgs, fsdb, mti, cliname,
                                              fsdb->fsdb_clilmv);
		if (rc)
			GOTO(out_free, rc);

                /* add mountopts */
		rc = record_start_log(env, mgs, &llh, cliname);
		if (rc)
			GOTO(out_free, rc);

		rc = record_marker(env, llh, fsdb, CM_START, cliname,
                                   "mount opts");
		if (rc)
			GOTO(out_end, rc);
		rc = record_mount_opt(env, llh, cliname, fsdb->fsdb_clilov,
                                      fsdb->fsdb_clilmv);
		if (rc)
			GOTO(out_end, rc);
		rc = record_marker(env, llh, fsdb, CM_END, cliname,
                                   "mount opts");

	if (rc)
		GOTO(out_end, rc);

	/* for_all_existing_mdt except current one */
	for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
		if (i !=  mti->mti_stripe_index &&
		    test_bit(i, fsdb->fsdb_mdt_index_map)) {
			char *logname;

			rc = name_create_mdt(&logname, fsdb->fsdb_name, i);
			if (rc)
				GOTO(out_end, rc);

			rc = mgs_write_log_osp_to_mdt(env, mgs, fsdb, mti,
						      i, logname);
			name_destroy(&logname);
			if (rc)
				GOTO(out_end, rc);
		}
	}
out_end:
	record_end_log(env, &llh);
out_free:
	name_destroy(&cliname);
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
	char *nodeuuid = NULL;
	char *oscname = NULL;
	char *oscuuid = NULL;
	char *lovuuid = NULL;
	char *svname = NULL;
        char index[6];
        int i, rc;

        ENTRY;
        CDEBUG(D_INFO, "adding osc for %s to log %s\n",
               mti->mti_svname, logname);

	if (mgs_log_is_empty(env, mgs, logname)) {
                CERROR("log is empty! Logical error\n");
                RETURN (-EINVAL);
        }

	rc = name_create(&nodeuuid, libcfs_nid2str(mti->mti_nids[0]), "");
	if (rc)
		RETURN(rc);
	rc = name_create(&svname, mti->mti_svname, "-osc");
	if (rc)
		GOTO(out_free, rc);

	/* for the system upgraded from old 1.8, keep using the old osc naming
	 * style for mdt, see name_create_mdt_osc(). LU-1257 */
	if (test_bit(FSDB_OSCNAME18, &fsdb->fsdb_flags))
		rc = name_create(&oscname, svname, "");
	else
		rc = name_create(&oscname, svname, suffix);
	if (rc)
		GOTO(out_free, rc);

	rc = name_create(&oscuuid, oscname, "_UUID");
	if (rc)
		GOTO(out_free, rc);
	rc = name_create(&lovuuid, lovname, "_UUID");
	if (rc)
		GOTO(out_free, rc);


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
		GOTO(out_free, rc);

        /* FIXME these should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START | flags, mti->mti_svname,
                           "add osc");
	if (rc)
		GOTO(out_end, rc);

	/* NB: don't change record order, because upon MDT steal OSC config
	 * from client, it treats all nids before LCFG_SETUP as target nids
	 * (multiple interfaces), while nids after as failover node nids.
	 * See mgs_steal_client_llog_handler() LCFG_ADD_UUID.
	 */
        for (i = 0; i < mti->mti_nid_count; i++) {
                CDEBUG(D_MGS, "add nid %s\n", libcfs_nid2str(mti->mti_nids[i]));
		rc = record_add_uuid(env, llh, mti->mti_nids[i], nodeuuid);
		if (rc)
			GOTO(out_end, rc);
        }
	rc = record_attach(env, llh, oscname, LUSTRE_OSC_NAME, lovuuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, oscname, mti->mti_uuid, nodeuuid, 0, 0);
	if (rc)
		GOTO(out_end, rc);
	rc = mgs_write_log_failnids(env, mti, llh, oscname);
	if (rc)
		GOTO(out_end, rc);

	snprintf(index, sizeof(index), "%d", mti->mti_stripe_index);

	rc = record_lov_add(env, llh, lovname, mti->mti_uuid, index, "1");
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END | flags, mti->mti_svname,
                           "add osc");
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
out_free:
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
	if (rc)
		GOTO(out_end, rc);
        if (*mti->mti_uuid == '\0')
                snprintf(mti->mti_uuid, sizeof(mti->mti_uuid),
                         "%s_UUID", mti->mti_svname);
	rc = record_attach(env, llh, mti->mti_svname,
                           "obdfilter"/*LUSTRE_OST_NAME*/, mti->mti_uuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, mti->mti_svname,
                          "dev"/*ignored*/, "type"/*ignored*/,
                          failout ? "n" : "f", 0/*options*/);
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, mti->mti_svname, "add ost");
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
	if (rc)
		RETURN(rc);
        /* We also have to update the other logs where this osc is part of
           the lov */

	if (test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
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
		if (test_bit(i, fsdb->fsdb_mdt_index_map)) {
                        char mdt_index[9];

			rc = name_create_mdt_and_lov(&logname, &lovname, fsdb,
						     i);
			if (rc)
				RETURN(rc);
                        sprintf(mdt_index, "-MDT%04x", i);
			rc = mgs_write_log_osc_to_lov(env, mgs, fsdb, mti,
						      logname, mdt_index,
						      lovname, LUSTRE_SP_MDT,
						      flags);
                        name_destroy(&logname);
                        name_destroy(&lovname);
			if (rc)
				RETURN(rc);
                }
        }

        /* Append ost info to the client log */
	rc = name_create(&logname, mti->mti_fsname, "-client");
	if (rc)
		RETURN(rc);
	if (mgs_log_is_empty(env, mgs, logname)) {
                /* Start client log */
		rc = mgs_write_log_lov(env, mgs, fsdb, mti, logname,
                                       fsdb->fsdb_clilov);
		if (rc)
			GOTO(out_free, rc);
		rc = mgs_write_log_lmv(env, mgs, fsdb, mti, logname,
                                       fsdb->fsdb_clilmv);
		if (rc)
			GOTO(out_free, rc);
        }
	rc = mgs_write_log_osc_to_lov(env, mgs, fsdb, mti, logname, "",
				      fsdb->fsdb_clilov, LUSTRE_SP_CLI, 0);
out_free:
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
		return rc < 0 ? rc : 0;
        }

        /* Otherwise failover nids are additive */
	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		return rc;
                /* FIXME this should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,
			   "add failnid");
	if (rc)
		goto out_end;
	rc = mgs_write_log_failnids(env, mti, llh, cliname);
	if (rc)
		goto out_end;
	rc = record_marker(env, llh, fsdb, CM_END,
			   mti->mti_svname, "add failnid");
out_end:
	record_end_log(env, &llh);
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
		rc = name_create(&cliname, mti->mti_svname, "-mdc");
        } else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
		rc = name_create(&cliname, mti->mti_svname, "-osc");
        } else {
                RETURN(-EINVAL);
        }
	if (rc)
		RETURN(rc);
        /* Add failover nids to the client log */
	rc = name_create(&logname, mti->mti_fsname, "-client");
	if (rc) {
		name_destroy(&cliname);
		RETURN(rc);
	}
	rc = mgs_write_log_failnid_internal(env, mgs, fsdb,mti,logname,cliname);
        name_destroy(&logname);
        name_destroy(&cliname);
	if (rc)
		RETURN(rc);

        if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
                /* Add OST failover nids to the MDT logs as well */
                int i;

                for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
			if (!test_bit(i, fsdb->fsdb_mdt_index_map))
                                continue;
			rc = name_create_mdt(&logname, mti->mti_fsname, i);
			if (rc)
				RETURN(rc);
			rc = name_create_mdt_osc(&cliname, mti->mti_svname,
						 fsdb, i);
			if (rc) {
				name_destroy(&logname);
				RETURN(rc);
			}
			rc = mgs_write_log_failnid_internal(env, mgs, fsdb,
							    mti, logname,
							    cliname);
                        name_destroy(&cliname);
                        name_destroy(&logname);
			if (rc)
				RETURN(rc);
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
	if (rc < 0)
		return rc;
        del = mgs_param_empty(ptr);

        LCONSOLE_INFO("%sing parameter %s.%s in log %s\n", del ? "Disabl" : rc ?
                      "Sett" : "Modify", tgtname, comment, logname);
        if (del)
                return rc;

        lustre_cfg_bufs_reset(bufs, tgtname);
	lustre_cfg_bufs_set_string(bufs, 1, ptr);
	if (mti->mti_flags & LDD_F_PARAM2)
		lustre_cfg_bufs_set_string(bufs, 2, LCTL_UPCALL);

	lcfg = lustre_cfg_new((mti->mti_flags & LDD_F_PARAM2) ?
			      LCFG_SET_PARAM : LCFG_PARAM, bufs);

        if (!lcfg)
                return -ENOMEM;
	rc = mgs_write_log_direct(env, mgs, fsdb, logname,lcfg,tgtname,comment);
        lustre_cfg_free(lcfg);
        return rc;
}

static int mgs_write_log_param2(const struct lu_env *env,
				struct mgs_device *mgs,
				struct fs_db *fsdb,
				struct mgs_target_info *mti, char *ptr)
{
	struct lustre_cfg_bufs	bufs;
	int			rc = 0;
	ENTRY;

	CDEBUG(D_MGS, "next param '%s'\n", ptr);
	rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, PARAMS_FILENAME, &bufs,
			  mti->mti_svname, ptr);

	RETURN(rc);
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
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct lustre_cfg	*lcfg;
	char			*tmp;
	char			 sep;
	int			 rc, cmd = LCFG_PARAM;

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

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, mti->mti_fsname);
	lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 1, quota);
	lcfg = lustre_cfg_new(cmd, &mgi->mgi_bufs);
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
	return rc < 0 ? rc : 0;
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
                if (rc)
                        GOTO(out, rc);
		record_end_log(env, &llh);
        }

        /* obsolete old one */
	rc = mgs_modify(env, mgs, fsdb, mti, logname, mti->mti_svname,
			comment, CM_SKIP);
	if (rc < 0)
		GOTO(out, rc);
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
		set_bit(FSDB_UDESC, &fsdb->fsdb_flags);
                CWARN("Enable user descriptor shipping from client to MDT\n");
        } else if (strcmp(ptr, "no") == 0) {
		clear_bit(FSDB_UDESC, &fsdb->fsdb_flags);
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
	if (test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags)) {
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

	if (test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags)) {
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
	struct lustre_cfg         *lcfg = REC_DATA(rec);
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

	rc = llog_open(env, ctxt, &llh, NULL, logname,
		       LLOG_OPEN_EXISTS);
	if (rc < 0) {
		if (rc == -ENOENT)
			rc = 0;
		GOTO(out, rc);
	}

	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(out_close, rc);

        if (llog_get_size(llh) <= 1)
                GOTO(out_close, rc = 0);

        msrd.msrd_fsdb = fsdb;
        msrd.msrd_skip = 0;

	rc = llog_process(env, llh, mgs_srpc_read_handler, (void *)&msrd,
			  NULL);

out_close:
	llog_close(env, llh);
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
		rc = name_create(&logname, mti->mti_fsname, "-client");
		if (rc)
			GOTO(end, rc);
		rc = mgs_modify(env, mgs, fsdb, mti, logname,
                                mti->mti_svname, "add osc", flag);
                name_destroy(&logname);
                if (rc)
                        goto active_err;
                /* Modify mdtlov */
                /* Add to all MDT logs for CMD */
                for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
			if (!test_bit(i, fsdb->fsdb_mdt_index_map))
                                continue;
			rc = name_create_mdt(&logname, mti->mti_fsname, i);
			if (rc)
				GOTO(end, rc);
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
			if (test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags))
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

		rc = name_create_mdt_and_lov(&logname, &mdtlovname, fsdb,
					     mti->mti_stripe_index);
		if (rc)
			GOTO(end, rc);
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, mti->mti_svname,
				  &mgi->mgi_bufs, mdtlovname, ptr);
                name_destroy(&logname);
                name_destroy(&mdtlovname);
                if (rc)
                        GOTO(end, rc);

                /* Modify clilov */
		rc = name_create(&logname, mti->mti_fsname, "-client");
		if (rc)
			GOTO(end, rc);
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

		if (test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
			LCONSOLE_ERROR_MSG(0x148, "Upgraded client logs for %s"
					   " cannot be modified. Consider"
					   " updating the configuration with"
					   " --writeconf\n",
					   mti->mti_svname);
			GOTO(end, rc = -EINVAL);
		}
		if (memcmp(ptr, PARAM_LLITE, strlen(PARAM_LLITE)) == 0) {
			rc = name_create(&cname, mti->mti_fsname, "-client");
			/* Add the client type to match the obdname in
			   class_config_llog_handler */
		} else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
			rc = name_create(&cname, mti->mti_svname, "-mdc");
		} else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
			rc = name_create(&cname, mti->mti_svname, "-osc");
		} else {
			GOTO(end, rc = -EINVAL);
		}
		if (rc)
			GOTO(end, rc);

                CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);

                /* Modify client */
		rc = name_create(&logname, mti->mti_fsname, "-client");
		if (rc) {
			name_destroy(&cname);
			GOTO(end, rc);
		}
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname, &mgi->mgi_bufs,
                                  cname, ptr);

                /* osc params affect the MDT as well */
                if (!rc && (mti->mti_flags & LDD_F_SV_TYPE_OST)) {
                        int i;

                        for (i = 0; i < INDEX_MAP_SIZE * 8; i++){
				if (!test_bit(i, fsdb->fsdb_mdt_index_map))
                                        continue;
                                name_destroy(&cname);
				rc = name_create_mdt_osc(&cname, mti->mti_svname,
							 fsdb, i);
                                name_destroy(&logname);
				if (rc)
					break;
				rc = name_create_mdt(&logname,
						     mti->mti_fsname, i);
				if (rc)
					break;
				if (!mgs_log_is_empty(env, mgs, logname)) {
					rc = mgs_wlp_lcfg(env, mgs, fsdb,
							  mti, logname,
							  &mgi->mgi_bufs,
							  cname, ptr);
					if (rc)
						break;
				}
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
				if (!test_bit(i,
                                                  fsdb->fsdb_mdt_index_map))
                                        continue;
				rc = name_create_mdt(&logname,
						mti->mti_fsname, i);
				if (rc)
					goto active_err;
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

	/* All mdd., ost. and osd. params in proc */
	if ((class_match_param(ptr, PARAM_MDD, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_OST, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_OSD, NULL) == 0)) {
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

	mutex_lock(&fsdb->fsdb_mutex);
        rc = mgs_write_log_add_failnid(obd, fsdb, mti);
	mutex_unlock(&fsdb->fsdb_mutex);

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

	if (rc == EALREADY) {
		LCONSOLE_WARN("Found index %d for %s, updating log\n",
			      mti->mti_stripe_index, mti->mti_svname);
		/* We would like to mark old log sections as invalid
		   and add new log sections in the client and mdt logs.
		   But if we add new sections, then live clients will
		   get repeat setup instructions for already running
		   osc's. So don't update the client/mdt logs. */
		mti->mti_flags &= ~LDD_F_UPDATE;
		rc = 0;
	}

	mutex_lock(&fsdb->fsdb_mutex);

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
	mutex_unlock(&fsdb->fsdb_mutex);
        RETURN(rc);
}

int mgs_erase_log(const struct lu_env *env, struct mgs_device *mgs, char *name)
{
	struct llog_ctxt	*ctxt;
	int			 rc = 0;

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
	if (ctxt == NULL) {
		CERROR("%s: MGS config context doesn't exist\n",
		       mgs->mgs_obd->obd_name);
		rc = -ENODEV;
	} else {
		rc = llog_erase(env, ctxt, NULL, name);
		/* llog may not exist */
		if (rc == -ENOENT)
			rc = 0;
		llog_ctxt_put(ctxt);
	}

	if (rc)
		CERROR("%s: failed to clear log %s: %d\n",
		       mgs->mgs_obd->obd_name, name, rc);

	return rc;
}

/* erase all logs for the given fs */
int mgs_erase_logs(const struct lu_env *env, struct mgs_device *mgs, char *fsname)
{
	struct fs_db *fsdb;
	cfs_list_t list;
	struct mgs_direntry *dirent, *n;
	int rc, len = strlen(fsname);
	char *suffix;
	ENTRY;

	/* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &list);
	if (rc)
		RETURN(rc);

	mutex_lock(&mgs->mgs_mutex);

        /* Delete the fs db */
	fsdb = mgs_find_fsdb(mgs, fsname);
        if (fsdb)
		mgs_free_fsdb(mgs, fsdb);

	mutex_unlock(&mgs->mgs_mutex);

	cfs_list_for_each_entry_safe(dirent, n, &list, list) {
		cfs_list_del(&dirent->list);
		suffix = strrchr(dirent->name, '-');
		if (suffix != NULL) {
			if ((len == suffix - dirent->name) &&
			    (strncmp(fsname, dirent->name, len) == 0)) {
				CDEBUG(D_MGS, "Removing log %s\n",
				       dirent->name);
				mgs_erase_log(env, mgs, dirent->name);
			}
		}
		mgs_direntry_free(dirent);
	}

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

/* Setup params fsdb and log
 */
int mgs_params_fsdb_setup(const struct lu_env *env, struct mgs_device *mgs,
			  struct fs_db *fsdb)
{
	struct llog_handle	*params_llh = NULL;
	int			rc;
	ENTRY;

	rc = mgs_find_or_make_fsdb(env, mgs, PARAMS_FILENAME, &fsdb);
	if (fsdb != NULL) {
		mutex_lock(&fsdb->fsdb_mutex);
		rc = record_start_log(env, mgs, &params_llh, PARAMS_FILENAME);
		if (rc == 0)
			rc = record_end_log(env, &params_llh);
		mutex_unlock(&fsdb->fsdb_mutex);
	}

	RETURN(rc);
}

/* Cleanup params fsdb and log
 */
int mgs_params_fsdb_cleanup(const struct lu_env *env, struct mgs_device *mgs)
{
	return mgs_erase_logs(env, mgs, PARAMS_FILENAME);
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
	char *ptr;
	const char *tmp;
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

	rc = mgs_parse_devname(devname, fsname, NULL);
	if (rc == 0 && !mgs_parse_devname(devname, NULL, &index)) {
                /* param related to llite isn't allowed to set by OST or MDT */
		if (rc == 0 && strncmp(param, PARAM_LLITE,
				   sizeof(PARAM_LLITE)) == 0)
                        RETURN(-EINVAL);
        } else {
                /* assume devname is the fsname */
		memset(fsname, 0, MTI_NAME_MAXLEN);
                strncpy(fsname, devname, MTI_NAME_MAXLEN);
		fsname[MTI_NAME_MAXLEN - 1] = 0;
        }
        CDEBUG(D_MGS, "setparam fs='%s' device='%s'\n", fsname, devname);

	rc = mgs_find_or_make_fsdb(env, mgs,
				   lcfg->lcfg_command == LCFG_SET_PARAM ?
				   PARAMS_FILENAME : fsname, &fsdb);
	if (rc)
		RETURN(rc);

	if (lcfg->lcfg_command != LCFG_SET_PARAM &&
	    !test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags) &&
	    test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
                CERROR("No filesystem targets for %s.  cfg_device from lctl "
                       "is '%s'\n", fsname, devname);
		mgs_free_fsdb(mgs, fsdb);
                RETURN(-EINVAL);
        }

        /* Create a fake mti to hold everything */
        OBD_ALLOC_PTR(mti);
        if (!mti)
                GOTO(out, rc = -ENOMEM);
	if (strlcpy(mti->mti_fsname, fsname, sizeof(mti->mti_fsname))
	    >= sizeof(mti->mti_fsname))
		GOTO(out, rc = -E2BIG);
	if (strlcpy(mti->mti_svname, devname, sizeof(mti->mti_svname))
	    >= sizeof(mti->mti_svname))
		GOTO(out, rc = -E2BIG);
	if (strlcpy(mti->mti_params, param, sizeof(mti->mti_params))
	    >= sizeof(mti->mti_params))
		GOTO(out, rc = -E2BIG);
        rc = server_name2index(mti->mti_svname, &mti->mti_stripe_index, &tmp);
        if (rc < 0)
                /* Not a valid server; may be only fsname */
                rc = 0;
        else
                /* Strip -osc or -mdc suffix from svname */
                if (server_make_name(rc, mti->mti_stripe_index, mti->mti_fsname,
                                     mti->mti_svname))
                        GOTO(out, rc = -EINVAL);
	/*
	 * Revoke lock so everyone updates.  Should be alright if
	 * someone was already reading while we were updating the logs,
	 * so we don't really need to hold the lock while we're
	 * writing (above).
	 */
	if (lcfg->lcfg_command == LCFG_SET_PARAM) {
		mti->mti_flags = rc | LDD_F_PARAM2;
		mutex_lock(&fsdb->fsdb_mutex);
		rc = mgs_write_log_param2(env, mgs, fsdb, mti, mti->mti_params);
		mutex_unlock(&fsdb->fsdb_mutex);
		mgs_revoke_lock(mgs, fsdb, CONFIG_T_PARAMS);
	} else {
		mti->mti_flags = rc | LDD_F_PARAM;
		mutex_lock(&fsdb->fsdb_mutex);
		rc = mgs_write_log_param(env, mgs, fsdb, mti, mti->mti_params);
		mutex_unlock(&fsdb->fsdb_mutex);
		mgs_revoke_lock(mgs, fsdb, CONFIG_T_CONFIG);
	}

out:
        OBD_FREE_PTR(mti);
        RETURN(rc);
}

static int mgs_write_log_pool(const struct lu_env *env,
			      struct mgs_device *mgs, char *logname,
			      struct fs_db *fsdb, char *tgtname,
                              enum lcfg_command_type cmd,
			      char *fsname, char *poolname,
                              char *ostname, char *comment)
{
        struct llog_handle *llh = NULL;
        int rc;

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		return rc;
	rc = record_marker(env, llh, fsdb, CM_START, tgtname, comment);
	if (rc)
		goto out;
	rc = record_base(env, llh, tgtname, 0, cmd,
			 fsname, poolname, ostname, 0);
	if (rc)
		goto out;
	rc = record_marker(env, llh, fsdb, CM_END, tgtname, comment);
out:
	record_end_log(env, &llh);
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
	if (test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
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
		RETURN(-ENOMEM);

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
			GOTO(out_label, rc = -ENOMEM);
                sprintf(label,
                        "rem %s.%s.%s", fsname, poolname, ostname);
                sprintf(canceled_label,
                        "add %s.%s.%s", fsname, poolname, ostname);
                break;
	case LCFG_POOL_DEL:
                OBD_ALLOC(canceled_label, label_sz);
                if (canceled_label == NULL)
			GOTO(out_label, rc = -ENOMEM);
                sprintf(label,
                        "del %s.%s", fsname, poolname);
                sprintf(canceled_label,
                        "new %s.%s", fsname, poolname);
                break;
	default:
                break;
        }

        if (canceled_label != NULL) {
                OBD_ALLOC_PTR(mti);
                if (mti == NULL)
			GOTO(out_cancel, rc = -ENOMEM);
        }

	mutex_lock(&fsdb->fsdb_mutex);
        /* write pool def to all MDT logs */
        for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
		if (test_bit(i,  fsdb->fsdb_mdt_index_map)) {
			rc = name_create_mdt_and_lov(&logname, &lovname,
						     fsdb, i);
			if (rc) {
				mutex_unlock(&fsdb->fsdb_mutex);
				GOTO(out_mti, rc);
			}
                        if (canceled_label != NULL) {
                                strcpy(mti->mti_svname, "lov pool");
				rc = mgs_modify(env, mgs, fsdb, mti, logname,
						lovname, canceled_label,
						CM_SKIP);
                        }

			if (rc >= 0)
				rc = mgs_write_log_pool(env, mgs, logname,
							fsdb, lovname, cmd,
							fsname, poolname,
							ostname, label);
                        name_destroy(&logname);
                        name_destroy(&lovname);
			if (rc) {
				mutex_unlock(&fsdb->fsdb_mutex);
				GOTO(out_mti, rc);
			}
                }
        }

	rc = name_create(&logname, fsname, "-client");
	if (rc) {
		mutex_unlock(&fsdb->fsdb_mutex);
		GOTO(out_mti, rc);
	}
	if (canceled_label != NULL) {
		rc = mgs_modify(env, mgs, fsdb, mti, logname,
				fsdb->fsdb_clilov, canceled_label, CM_SKIP);
		if (rc < 0) {
			mutex_unlock(&fsdb->fsdb_mutex);
			name_destroy(&logname);
			GOTO(out_mti, rc);
		}
	}

	rc = mgs_write_log_pool(env, mgs, logname, fsdb, fsdb->fsdb_clilov,
				cmd, fsname, poolname, ostname, label);
	mutex_unlock(&fsdb->fsdb_mutex);
	name_destroy(&logname);
        /* request for update */
	mgs_revoke_lock(mgs, fsdb, CONFIG_T_CONFIG);

        EXIT;
out_mti:
        if (mti != NULL)
                OBD_FREE_PTR(mti);
out_cancel:
	if (canceled_label != NULL)
		OBD_FREE(canceled_label, label_sz);
out_label:
	OBD_FREE(label, label_sz);
        return rc;
}
