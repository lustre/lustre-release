// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
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
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <lustre_sec.h>
#include <lustre_quota.h>
#include <lustre_sec.h>

#include "mgs_internal.h"

/********************** Class functions ********************/

/**
 * Find all logs in CONFIG directory and link then into list.
 *
 * \param[in] env	pointer to the thread context
 * \param[in] mgs	pointer to the mgs device
 * \param[out] log_list	the list to hold the found llog name entry
 *
 * \retval		0 for success
 * \retval		negative error number on failure
 **/
int class_dentry_readdir(const struct lu_env *env, struct mgs_device *mgs,
			 struct list_head *log_list)
{
	struct dt_object *dir = mgs->mgs_configs_dir;
	const struct dt_it_ops *iops;
	struct dt_it *it;
	struct mgs_direntry *de;
	char *key;
	int rc, key_sz;

	INIT_LIST_HEAD(log_list);

	LASSERT(dir);
	LASSERT(dir->do_index_ops);

	iops = &dir->do_index_ops->dio_it;
	it = iops->init(env, dir, LUDA_64BITHASH);
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

		/* filter out files */
		if (!lu_name_in_white_list(key, key_sz)) {
			CDEBUG(D_MGS, "Not in white list, skipping %.*s\n",
			       key_sz, key);
			goto next;
		}

		de = mgs_direntry_alloc(key_sz + 1);
		if (de == NULL) {
			rc = -ENOMEM;
			break;
		}

		memcpy(de->mde_name, key, key_sz);
		de->mde_name[key_sz] = 0;

		list_add(&de->mde_list, log_list);

next:
		rc = iops->next(env, it);
	} while (rc == 0);
	if (rc > 0)
		rc = 0;

	iops->put(env, it);

fini:
	iops->fini(env, it);
	if (rc) {
		struct mgs_direntry *n;

		CERROR("%s: key failed when listing %s: rc = %d\n",
		       mgs->mgs_obd->obd_name, MOUNT_CONFIGS_DIR, rc);

		list_for_each_entry_safe(de, n, log_list, mde_list) {
			list_del_init(&de->mde_list);
			mgs_direntry_free(de);
		}
	}

	RETURN(rc);
}

/******************** DB functions *********************/

static inline int name_create(char **newname, char *prefix, char *suffix)
{
	size_t newname_len = strlen(prefix) + strlen(suffix) + 1;

	LASSERT(newname);

	OBD_ALLOC(*newname, newname_len);
	if (!*newname)
		return -ENOMEM;

	snprintf(*newname, newname_len, "%s%s", prefix, suffix);
	return 0;
}

static inline void name_destroy(char **name)
{
	OBD_FREE(*name, strlen(*name) + 1);
	*name = NULL;
}

static inline int niduuid_create(char **niduuid, char *nidstr)
{
	size_t niduuid_len = strlen(nidstr) + 1;

	LASSERT(niduuid);

	/* Large NIDs may be longer than UUID_MAX. In this case we skip bytes at
	 * the start of the string because the bytes at the end of the NID
	 * should be more unique
	 */
	if (niduuid_len > UUID_MAX) {
		nidstr += niduuid_len - UUID_MAX;
		niduuid_len = strlen(nidstr) + 1;
	}

	OBD_ALLOC(*niduuid, niduuid_len);
	if (!*niduuid)
		return -ENOMEM;

	snprintf(*niduuid, niduuid_len, "%s", nidstr);
	return 0;
}

static inline void niduuid_destroy(char **niduuid)
{
	name_destroy(niduuid);
}

static inline int name_create_osp(char **ospname, char **devtype, char *tgtname,
				  int index)
{
	size_t sz = strlen(tgtname) + sizeof("-osx-MDTXXXX");
	char *out = NULL;
	char *type = NULL;

	if (strstr(tgtname, "-MDT"))
		type = "osp";
	else if (strstr(tgtname, "-OST"))
		type = "osc";
	else
		return -EINVAL;

	OBD_ALLOC(out, sz);
	if (!out)
		return -ENOMEM;

	if (snprintf(out, sz, "%s-%s-MDT%04x", tgtname, type, index) >= sz) {
		OBD_FREE(out, sz);
		return -EOVERFLOW;
	}

	*ospname = out;
	if (devtype)
		*devtype = type;

	return 0;
}

static inline int name_create_lov(char **lovname, char *mdtname)
{
	return name_create(lovname, mdtname, "-mdtlov");
}


struct mgs_fsdb_handler_data
{
	struct fs_db   *fsdb;
	__u32		ver;
};

/* from the (client) config log, figure out:
 * 1. which ost's/mdt's are configured (by index)
 * 2. what the last config step is
 * 3. COMPAT_18 osc name
*/
/* It might be better to have a separate db file, instead of parsing the info
   out of the client log.  This is slow and potentially error-prone. */
static int mgs_fsdb_handler(const struct lu_env *env, struct llog_handle *llh,
			    struct llog_rec_hdr *rec, void *data)
{
	struct mgs_fsdb_handler_data *d = data;
	struct fs_db *fsdb = d->fsdb;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	u32 index;
	int rc = 0;

	ENTRY;
	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc) {
		CERROR("Insane cfg\n");
		RETURN(rc);
	}

	CDEBUG(D_INFO, "cmd %x %s %s\n", lcfg->lcfg_command,
	       lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));

	/* Figure out ost indicies */
	/* lov_modify_tgts add 0:lov1  1:ost1_UUID  2(index):0  3(gen):1 */
	if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD ||
	    lcfg->lcfg_command == LCFG_LOV_DEL_OBD) {
		rc = kstrtouint(lustre_cfg_string(lcfg, 2), 10, &index);
		if (rc)
			RETURN(rc);

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
		if (!test_bit(index, fsdb->fsdb_mdt_index_map)) {
			set_bit(index, fsdb->fsdb_mdt_index_map);
			fsdb->fsdb_mdt_count++;
		}
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
	char *logname;
	struct llog_handle *loghandle;
	struct llog_ctxt *ctxt;
	struct mgs_fsdb_handler_data d = {
		.fsdb = fsdb,
	};
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

static void mgs_unlink_fsdb(struct mgs_device *mgs, struct fs_db *fsdb)
{
	mutex_lock(&mgs->mgs_mutex);
	if (likely(!list_empty(&fsdb->fsdb_list))) {
		LASSERTF(atomic_read(&fsdb->fsdb_ref) >= 2,
			 "Invalid ref %d on %s\n",
			 atomic_read(&fsdb->fsdb_ref),
			 fsdb->fsdb_name);

		list_del_init(&fsdb->fsdb_list);
		/* Drop the reference on the list.*/
		mgs_put_fsdb(mgs, fsdb);
	}
	mutex_unlock(&mgs->mgs_mutex);
}

/* The caller must hold mgs->mgs_mutex. */
static inline struct fs_db *
mgs_find_fsdb_noref(struct mgs_device *mgs, const char *fsname)
{
	struct fs_db *fsdb;
	struct list_head *tmp;

	list_for_each(tmp, &mgs->mgs_fs_db_list) {
		fsdb = list_entry(tmp, struct fs_db, fsdb_list);
		if (strcmp(fsdb->fsdb_name, fsname) == 0)
			return fsdb;
	}

	return NULL;
}

/* The caller must hold mgs->mgs_mutex. */
static void mgs_remove_fsdb_by_name(struct mgs_device *mgs, const char *name)
{
	struct fs_db *fsdb;

	fsdb = mgs_find_fsdb_noref(mgs, name);
	if (fsdb) {
		list_del_init(&fsdb->fsdb_list);
		/* Drop the reference on the list.*/
		mgs_put_fsdb(mgs, fsdb);
	}
}

/* The caller must hold mgs->mgs_mutex. */
struct fs_db *mgs_find_fsdb(struct mgs_device *mgs, const char *fsname)
{
	struct fs_db *fsdb;

	fsdb = mgs_find_fsdb_noref(mgs, fsname);
	if (fsdb)
		atomic_inc(&fsdb->fsdb_ref);

	return fsdb;
}

/* The caller must hold mgs->mgs_mutex. */
static struct fs_db *mgs_new_fsdb(const struct lu_env *env,
				  struct mgs_device *mgs, char *fsname)
{
	struct fs_db *fsdb;
	int rc;
	ENTRY;

	if (strlen(fsname) >= sizeof(fsdb->fsdb_name)) {
		CERROR("fsname %s is too long\n", fsname);

		RETURN(ERR_PTR(-EINVAL));
	}

	OBD_ALLOC_PTR(fsdb);
	if (!fsdb)
		RETURN(ERR_PTR(-ENOMEM));

	strncpy(fsdb->fsdb_name, fsname, sizeof(fsdb->fsdb_name));
	mutex_init(&fsdb->fsdb_mutex);
	INIT_LIST_HEAD(&fsdb->fsdb_list);
	set_bit(FSDB_UDESC, &fsdb->fsdb_flags);
	fsdb->fsdb_gen = 1;
	INIT_LIST_HEAD(&fsdb->fsdb_clients);
	atomic_set(&fsdb->fsdb_notify_phase, 0);
	init_waitqueue_head(&fsdb->fsdb_notify_waitq);
	init_completion(&fsdb->fsdb_notify_comp);

	if (strcmp(fsname, MGSSELF_NAME) == 0) {
		set_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags);
		fsdb->fsdb_mgs = mgs;
		if (logname_is_barrier(fsname))
			goto add;
	} else {
		OBD_ALLOC(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
		if (!fsdb->fsdb_mdt_index_map) {
			CERROR("No memory for MDT index maps\n");

			GOTO(err, rc = -ENOMEM);
		}

		OBD_ALLOC(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
		if (!fsdb->fsdb_ost_index_map) {
			CERROR("No memory for OST index maps\n");

			GOTO(err, rc = -ENOMEM);
		}

		if (logname_is_barrier(fsname))
			goto add;

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

	if (!test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags) &&
	    strcmp(PARAMS_FILENAME, fsname) != 0) {
		/* populate the db from the client llog */
		rc = mgs_get_fsdb_from_llog(env, mgs, fsdb);
		if (rc) {
			CERROR("Can't get db from client log %d\n", rc);

			GOTO(err, rc);
		}
	}

	/* populate srpc rules from params llog */
	rc = mgs_get_fsdb_srpc_from_llog(env, mgs, fsdb);
	if (rc) {
		CERROR("Can't get db from params log %d\n", rc);

		GOTO(err, rc);
	}

add:
	/* One ref is for the fsdb on the list.
	 * The other ref is for the caller. */
	atomic_set(&fsdb->fsdb_ref, 2);
	list_add(&fsdb->fsdb_list, &mgs->mgs_fs_db_list);

	RETURN(fsdb);

err:
	atomic_set(&fsdb->fsdb_ref, 1);
	mgs_put_fsdb(mgs, fsdb);

	RETURN(ERR_PTR(rc));
}

static void mgs_free_fsdb(struct mgs_device *mgs, struct fs_db *fsdb)
{
	LASSERT(list_empty(&fsdb->fsdb_list));

	lproc_mgs_del_live(mgs, fsdb);

	/* deinitialize fsr */
	if (fsdb->fsdb_mgs)
		mgs_ir_fini_fs(mgs, fsdb);

	OBD_FREE(fsdb->fsdb_ost_index_map, INDEX_MAP_SIZE);
	OBD_FREE(fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE);
	name_destroy(&fsdb->fsdb_clilov);
	name_destroy(&fsdb->fsdb_clilmv);
	mgs_free_fsdb_srpc(fsdb);
	OBD_FREE_PTR(fsdb);
}

void mgs_put_fsdb(struct mgs_device *mgs, struct fs_db *fsdb)
{
	if (atomic_dec_and_test(&fsdb->fsdb_ref))
		mgs_free_fsdb(mgs, fsdb);
}

int mgs_init_fsdb_list(struct mgs_device *mgs)
{
	INIT_LIST_HEAD(&mgs->mgs_fs_db_list);
	return 0;
}

int mgs_cleanup_fsdb_list(struct mgs_device *mgs)
{
	struct fs_db *fsdb;
	struct list_head *tmp, *tmp2;

	mutex_lock(&mgs->mgs_mutex);
	list_for_each_safe(tmp, tmp2, &mgs->mgs_fs_db_list) {
		fsdb = list_entry(tmp, struct fs_db, fsdb_list);
		list_del_init(&fsdb->fsdb_list);
		mgs_put_fsdb(mgs, fsdb);
	}
	mutex_unlock(&mgs->mgs_mutex);
	return 0;
}

/* The caller must hold mgs->mgs_mutex. */
int mgs_find_or_make_fsdb_nolock(const struct lu_env *env,
				struct mgs_device *mgs,
				char *name, struct fs_db **dbh)
{
	struct fs_db *fsdb;
	int rc = 0;
	ENTRY;

	fsdb = mgs_find_fsdb(mgs, name);
	if (!fsdb) {
		fsdb = mgs_new_fsdb(env, mgs, name);
		if (IS_ERR(fsdb))
			rc = PTR_ERR(fsdb);

		CDEBUG(D_MGS, "Created new db: rc = %d\n", rc);
	}

	if (!rc)
		*dbh = fsdb;

	RETURN(rc);
}

int mgs_find_or_make_fsdb(const struct lu_env *env, struct mgs_device *mgs,
			  char *name, struct fs_db **dbh)
{
	int rc;
	ENTRY;

	mutex_lock(&mgs->mgs_mutex);
	rc = mgs_find_or_make_fsdb_nolock(env, mgs, name, dbh);
	mutex_unlock(&mgs->mgs_mutex);

	RETURN(rc);
}

/* 1 = index in use
 * 0 = index unused
 * -1= empty client log
 */
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
		GOTO(out, rc = -1);

	if (mti->mti_flags & LDD_F_SV_TYPE_OST)
		imap = fsdb->fsdb_ost_index_map;
	else if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
		imap = fsdb->fsdb_mdt_index_map;
	else
		GOTO(out, rc = -EINVAL);

	if (test_bit(mti->mti_stripe_index, imap))
		GOTO(out, rc = 1);

	GOTO(out, rc = 0);

out:
	mgs_put_fsdb(mgs, fsdb);
	return rc;
}

static __inline__ int next_index(void *index_map, int map_len)
{
	int i;

	for (i = 0; i < map_len * 8; i++)
		if (!test_bit(i, index_map))
			return i;
	CERROR("max index %d exceeded.\n", i);
	return -1;
}

/* Make the mdt/ost server obd name based on the filesystem name */
static bool server_make_name(u32 flags, u16 index, const char *fs,
			     char *name_buf, size_t name_buf_size)
{
	bool invalid_flag = false;

	if (flags & (LDD_F_SV_TYPE_MDT | LDD_F_SV_TYPE_OST)) {
		char reg_flag = '-';

		if (flags & LDD_F_WRITECONF)
			reg_flag = '=';
		else if (flags & LDD_F_VIRGIN)
			reg_flag = ':';

		if (!(flags & LDD_F_SV_ALL))
			snprintf(name_buf, name_buf_size, "%.8s%c%s%04x", fs,
				reg_flag,
				(flags & LDD_F_SV_TYPE_MDT) ? "MDT" : "OST",
				index);
	} else if (flags & LDD_F_SV_TYPE_MGS) {
		snprintf(name_buf, name_buf_size, "MGS");
	} else {
		CERROR("unknown server type %#x\n", flags);
		invalid_flag = true;
	}
	return invalid_flag;
}

/* Return codes:
 * 0  newly marked as in use
 * <0 err
 * +EALREADY for update of an old index
 */
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
	if (mti->mti_flags & LDD_F_SV_TYPE_OST)
		imap = fsdb->fsdb_ost_index_map;
	else if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
		imap = fsdb->fsdb_mdt_index_map;
	else
		GOTO(out_up, rc = -EINVAL);

	if (mti->mti_flags & LDD_F_NEED_INDEX) {
		rc = next_index(imap, INDEX_MAP_SIZE);
		if (rc == -1)
			GOTO(out_up, rc = -ERANGE);
		mti->mti_stripe_index = rc;
	}

	/* the last index(0xffff) is reserved for default value. */
	if (mti->mti_stripe_index >= INDEX_MAP_SIZE * 8 - 1) {
		LCONSOLE_ERROR("Server %s requested index %u, but index must be less than %u.\n",
			       mti->mti_svname, mti->mti_stripe_index,
			       INDEX_MAP_SIZE * 8 - 1);
		GOTO(out_up, rc = -ERANGE);
	}

	if (test_bit(mti->mti_stripe_index, imap)) {
		if ((mti->mti_flags & LDD_F_VIRGIN) &&
		    !(mti->mti_flags & LDD_F_WRITECONF)) {
			LCONSOLE_ERROR("Server %s requested index %d, but that index is already in use. Use --writeconf to force\n",
				       mti->mti_svname,
				       mti->mti_stripe_index);
			GOTO(out_up, rc = -EADDRINUSE);
		} else {
			CDEBUG(D_MGS, "Server %s updating index %d\n",
			       mti->mti_svname, mti->mti_stripe_index);
			GOTO(out_up, rc = EALREADY);
		}
	} else {
		set_bit(mti->mti_stripe_index, imap);
		if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
			fsdb->fsdb_mdt_count++;
	}

	set_bit(mti->mti_stripe_index, imap);
	clear_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags);
	if (server_make_name(mti->mti_flags & ~(LDD_F_VIRGIN | LDD_F_WRITECONF),
			     mti->mti_stripe_index, mti->mti_fsname,
			     mti->mti_svname, sizeof(mti->mti_svname))) {
		CERROR("unknown server type %#x\n", mti->mti_flags);
		GOTO(out_up, rc = -EINVAL);
	}

	CDEBUG(D_MGS, "Set index for %s to %d\n", mti->mti_svname,
	       mti->mti_stripe_index);

	GOTO(out_up, rc = 0);

out_up:
	mutex_unlock(&fsdb->fsdb_mutex);
	mgs_put_fsdb(mgs, fsdb);
	return rc;
}

struct mgs_modify_lookup {
	struct cfg_marker mml_marker;
	int		mml_modified;
};

enum mgs_search_pool_status {
	POOL_STATUS_NONE = 0,
	POOL_STATUS_EXIST,
	POOL_STATUS_OST_EXIST,
};

struct mgs_search_pool_data {
	char				*msp_tgt;
	char				*msp_fs;
	char				*msp_pool;
	char				*msp_ost;
	enum mgs_search_pool_status	msp_status;
	bool				msp_skip;
};

static int mgs_search_pool_cb(const struct lu_env *env,
			      struct llog_handle *llh,
			      struct llog_rec_hdr *rec, void *data)
{
	struct mgs_search_pool_data *d = data;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	char *fsname;
	char *poolname;
	char *ostname = NULL;
	int rc;
	ENTRY;

	if (rec->lrh_type != OBD_CFG_REC) {
		CDEBUG(D_ERROR, "Unhandled lrh_type: %#x\n", rec->lrh_type);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc) {
		CDEBUG(D_ERROR, "Insane cfg\n");
		RETURN(rc);
	}

	/* check if section is skipped */
	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

		if (!(marker->cm_flags & CM_END))
			RETURN(0);

		d->msp_skip = (marker->cm_flags & CM_SKIP) ||
			strcmp(d->msp_tgt, marker->cm_tgtname) != 0;

		RETURN(0);
	}

	if (d->msp_skip)
		RETURN(0);

	switch (lcfg->lcfg_command) {
	case LCFG_POOL_ADD:
	case LCFG_POOL_REM:
		ostname = lustre_cfg_string(lcfg, 3);
		fallthrough;
	case LCFG_POOL_NEW:
	case LCFG_POOL_DEL:
		fsname = lustre_cfg_string(lcfg, 1);
		poolname = lustre_cfg_string(lcfg, 2);
		break;
	default:
		RETURN(0);
	}

	if (strcmp(d->msp_fs, fsname) != 0)
		RETURN(0);
	if (strcmp(d->msp_pool, poolname) != 0)
		RETURN(0);
	if (ostname && d->msp_ost && (strcmp(d->msp_ost, ostname) != 0))
		RETURN(0);

	/* Found a non-skipped marker match */
	CDEBUG(D_MGS, "Matched pool rec %u cmd:0x%x %s.%s %s\n",
	       rec->lrh_index, lcfg->lcfg_command, fsname, poolname,
	       ostname ? ostname : "");

	switch (lcfg->lcfg_command) {
	case LCFG_POOL_ADD:
		d->msp_status = POOL_STATUS_OST_EXIST;
		RETURN(LLOG_PROC_BREAK);
	case LCFG_POOL_REM:
		d->msp_status = POOL_STATUS_EXIST;
		RETURN(LLOG_PROC_BREAK);
	case LCFG_POOL_NEW:
		d->msp_status = POOL_STATUS_EXIST;
		RETURN(LLOG_PROC_BREAK);
	case LCFG_POOL_DEL:
		d->msp_status = POOL_STATUS_NONE;
		RETURN(LLOG_PROC_BREAK);
	default:
		break;
	}

	RETURN(0);
}

/**
 * Search a pool in a MGS configuration.
 * Return code:
 * positive - return the status of the pool,
 * negative - error
 */
static
int mgs_search_pool(const struct lu_env *env, struct mgs_device *mgs,
		    struct fs_db *fsdb, struct mgs_target_info *mti,
		    char *logname, char *devname, char *fsname, char *poolname,
		    char *ostname)
{
	struct llog_handle *loghandle;
	struct llog_ctxt *ctxt;
	struct mgs_search_pool_data d;
	int status = POOL_STATUS_NONE;
	int rc;

	ENTRY;

	LASSERT(mutex_is_locked(&fsdb->fsdb_mutex));


	d.msp_tgt = devname;
	d.msp_fs = fsname;
	d.msp_pool = poolname;
	d.msp_ost = ostname;
	d.msp_status = POOL_STATUS_NONE;
	d.msp_skip = false;

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

	rc = llog_reverse_process(env, loghandle, mgs_search_pool_cb, &d, NULL);
	if (rc == LLOG_PROC_BREAK)
		status = d.msp_status;

out_close:
	llog_close(env, loghandle);
out_pop:
	llog_ctxt_put(ctxt);

	RETURN(rc < 0 ? rc : status);
}

static int mgs_modify_handler(const struct lu_env *env,
			      struct llog_handle *llh,
			      struct llog_rec_hdr *rec, void *data)
{
	struct mgs_modify_lookup *mml = data;
	struct cfg_marker *marker;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	int rc;

	ENTRY;
	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
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
		rc = llog_write(env, llh, rec, rec->lrh_index);
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
	rc = strscpy(mml->mml_marker.cm_comment, comment,
		     sizeof(mml->mml_marker.cm_comment));
	if (rc < 0)
		GOTO(out_free, rc);
	rc = strscpy(mml->mml_marker.cm_tgtname, devname,
		     sizeof(mml->mml_marker.cm_tgtname));
	if (rc < 0)
		GOTO(out_free, rc);
	/* Modify mostly means cancel */
	mml->mml_marker.cm_flags = flags;
	mml->mml_marker.cm_canceltime = flags ? ktime_get_real_seconds() : 0;
	mml->mml_modified = 0;
	rc = llog_process(env, loghandle, mgs_modify_handler, (void *)mml,
			  NULL);
	if (!rc && !mml->mml_modified)
		rc = 1;

out_free:
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

static int param_value_cmp(const char *val1, const char *val2)
{
	int rc = 0;

	if (!val1 || !val2)
		return val1 != val2;

	do {
		size_t len1, len2;

		val1 += strspn(val1, " ");
		val2 += strspn(val2, " ");
		len1 = strcspn(val1, " ");
		len2 = strcspn(val2, " ");
		if (len1 != len2) {
			rc = 1;
			break;
		} else if (!len1) {
			break;
		}

		rc = (strncmp(val1, val2, len1) != 0);
		val1 += len1;
		val2 += len2;
	} while (!rc);

	return rc;
}

enum mgs_modify_param_mode {
	MPM_REPLACE = 0,
	MPM_DELETE,
	MPM_LOOKUP_VAL,
};

struct mgs_modify_param_data {
	enum mgs_modify_param_mode mpm_mode;
	__s64			mpm_canceltime;
	char			*mpm_tgt;
	char			*mpm_name;
	char			*mpm_value;
	struct llog_rec_hdr	*mpm_start;
	struct llog_cookie	mpm_start_cookie;
	int			mpm_deleted;
};

static int mgs_modify_param_hdl(const struct lu_env *env,
				struct llog_handle *llh,
				struct llog_rec_hdr *rec, void *data)
{
	struct mgs_modify_param_data *mpm = data;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	int cfg_len = REC_DATA_LEN(rec);
	char *name;
	char *value;
	bool value_match;
	int rc;

	ENTRY;
	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("%s: unhandled lrh_type %#x: rc = %d\n",
		       llh->lgh_name, rec->lrh_type, -EINVAL);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, cfg_len);
	if (rc) {
		CERROR("%s: Insane config: rc = %d\n", llh->lgh_name, rc);
		RETURN(rc);
	}

	/* We only care about markers */
	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

		if (!(marker->cm_flags & (CM_START | CM_END)) ||
		    (marker->cm_flags & CM_SKIP))
			RETURN(0);

		if (strcmp(mpm->mpm_name, marker->cm_comment) != 0 ||
		    strcmp(mpm->mpm_tgt, marker->cm_tgtname) != 0)
			RETURN(0);

		marker->cm_flags |= CM_SKIP;
		marker->cm_canceltime = mpm->mpm_canceltime;
		if (marker->cm_flags & CM_START) {
			/* missing end section */
			if (unlikely(mpm->mpm_start))
				GOTO(free_mdp, rc = -EBADMSG);

			/* save the start marker to skip */
			llog_get_cookie(env, &mpm->mpm_start_cookie);

			OBD_ALLOC(mpm->mpm_start, rec->lrh_len);
			if (!mpm->mpm_start)
				RETURN(-ENOMEM);

			memcpy(mpm->mpm_start, rec, rec->lrh_len);

			RETURN(0);
		}

		if (!mpm->mpm_start)
			RETURN(0);
		if (mpm->mpm_mode == MPM_LOOKUP_VAL)
			GOTO(free_mdp, rc = 0);

		/* skip the param section : re-write CM_START marker */
		rc = llog_write_cookie(env, llh, mpm->mpm_start,
				       &mpm->mpm_start_cookie,
				       mpm->mpm_start->lrh_index);
		if (rc < 0)
			GOTO(free_mdp, rc);
		/* re-write CM_END marker */
		rc = llog_write(env, llh, rec, rec->lrh_index);
		if (rc)
			GOTO(free_mdp, rc);

		mpm->mpm_deleted++;
		if (mpm->mpm_mode == MPM_REPLACE)
			rc = LLOG_PROC_BREAK;

		GOTO(free_mdp, rc);
	}

	if (!mpm->mpm_start)
		RETURN(0);
	if (lcfg->lcfg_command != LCFG_PARAM &&
	    lcfg->lcfg_command != LCFG_SET_PARAM)
		RETURN(0);

	/* check old parameter value */
	value = lustre_cfg_string(lcfg, 1);
	name = strsep(&value, "=");

	/* param does not match with marker comment -> ignore */
	if (unlikely(strcmp(mpm->mpm_name, name) != 0))
		GOTO(free_mdp, rc = 0);
	/* no value to check */
	if (!mpm->mpm_value)
		RETURN(0);

	value_match = value && !param_value_cmp(mpm->mpm_value, value);

	switch (mpm->mpm_mode) {
	case MPM_DELETE:
		if (!value_match)
			GOTO(free_mdp, rc = 0);
		break;
	case MPM_REPLACE:
	case MPM_LOOKUP_VAL:
		if (value_match)
			GOTO(free_mdp, rc = -EEXIST);
		break;
	default:
		RETURN(-EINVAL);
	}

	RETURN(0);

free_mdp:
	OBD_FREE(mpm->mpm_start, mpm->mpm_start->lrh_len);
	mpm->mpm_start = NULL;

	return rc;
}

static int param_is_compound(const char *param)
{
	size_t len;
	const char *str = param;

	len = strcspn(str, ".=");
	while (str[len] == '.') {
		str += len + 1;
		len = strcspn(str, ".=");
	}

	if (!len || str[len] != '=')
		return 0;

	len++;
	if (strncmp(str, PARAM_TBFRULES, len) == 0 ||
	    strncmp(str, PARAM_PCC, len) == 0 ||
	    strncmp(str, PARAM_WBC, len) == 0)
		return 1;

	return 0;
}

/**
 * Mark param section with CM_SKIP matching param name and value
 * Return code:
 * 0 - deleted successfully,
 * 1 - no modification was done
 * negative - error
 */
static int mgs_modify_param(const struct lu_env *env, struct mgs_device *mgs,
			    struct fs_db *fsdb, struct mgs_target_info *mti,
			    char *logname, char *devname, char *param, bool del)
{
	struct llog_handle *loghandle;
	struct llog_ctxt *ctxt;
	struct mgs_modify_param_data mpm = { 0 };
	char *dup;
	int rc;

	ENTRY;

	LASSERT(mutex_is_locked(&fsdb->fsdb_mutex));
	CDEBUG(D_MGS, "modify %s/%s/%s del=%d\n", logname, devname, param, del);

	if (!param || !param[0])
		RETURN(-EINVAL);

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

	dup = kstrdup(param, GFP_KERNEL);
	if (!dup)
		GOTO(out_close, rc = -ENOMEM);

	mpm.mpm_value = dup;
	mpm.mpm_name = strsep(&mpm.mpm_value, "=");
	if (mpm.mpm_value && !mpm.mpm_value[0])
		mpm.mpm_value = NULL;

	/* for compound parameter several entries are allowed, only
	 * check for existing entries matching name and value.
	 */
	if (del)
		mpm.mpm_mode = MPM_DELETE;
	else if (mpm.mpm_value)
		mpm.mpm_mode = param_is_compound(param) ?
			MPM_LOOKUP_VAL : MPM_REPLACE;
	else
		GOTO(out_free, rc = EINVAL);

	mpm.mpm_canceltime = ktime_get_real_seconds();
	mpm.mpm_tgt = devname;

	rc = llog_process(env, loghandle, mgs_modify_param_hdl, &mpm, NULL);
	if (unlikely(mpm.mpm_start)) {
		OBD_FREE(mpm.mpm_start, mpm.mpm_start->lrh_len);
		GOTO(out_free, rc = -EBADMSG);
	}

	if (rc == LLOG_PROC_BREAK)
		rc = 0;
	if (rc)
		GOTO(out_free, rc);

	switch (mpm.mpm_mode) {
	case MPM_DELETE:
		rc = mpm.mpm_deleted ? 0 : -ENOENT;
		break;
	default:
		rc = !mpm.mpm_deleted;
	}

out_free:
	kfree(dup);
out_close:
	llog_close(env, loghandle);
out_pop:
	if (rc < 0)
		CWARN("%s: modify %s/%s (mode = %d) failed: rc = %d\n",
		      mgs->mgs_obd->obd_name, mti->mti_svname, param,
		      mpm.mpm_mode, rc);
	llog_ctxt_put(ctxt);
	RETURN(rc);
}

enum replace_state {
	REPLACE_COPY = 0,
	REPLACE_SKIP,
	REPLACE_DONE,
	REPLACE_UUID,
	REPLACE_SETUP
};

/** This structure is passed to mgs_replace_handler */
struct mgs_replace_data {
	/* Nids are replaced for this target device */
	struct mgs_target_info target;
	/* Temporary modified llog */
	struct llog_handle *temp_llh;
	enum replace_state state;
	char *failover;
	char *nodeuuid;
};

/**
 * Check: a) if block should be skipped
 * b) is it target block
 *
 * \param[in] lcfg
 * \param[in] mrd
 *
 * \retval 0 should not to be skipped
 * \retval 1 should to be skipped
 */
static int check_markers(struct lustre_cfg *lcfg,
			 struct mgs_replace_data *mrd)
{
	 struct cfg_marker *marker;

	/* Track markers. Find given device */
	if (lcfg->lcfg_command == LCFG_MARKER) {
		marker = lustre_cfg_buf(lcfg, 1);
		/* Clean llog from records marked as CM_SKIP.
		   CM_EXCLUDE records are used for "active" command
		   and can be restored if needed */
		if ((marker->cm_flags & (CM_SKIP | CM_START)) ==
		    (CM_SKIP | CM_START)) {
			mrd->state = REPLACE_SKIP;
			return 1;
		}

		if ((marker->cm_flags & (CM_SKIP | CM_END)) ==
		    (CM_SKIP | CM_END)) {
			mrd->state = REPLACE_COPY;
			return 1;
		}

		if (strcmp(mrd->target.mti_svname, marker->cm_tgtname) == 0) {
			LASSERT(!(marker->cm_flags & CM_START) ||
				!(marker->cm_flags & CM_END));
			if (marker->cm_flags & CM_START) {
				if (!strncmp(marker->cm_comment,
					     "add failnid", 11)) {
					mrd->state = REPLACE_SKIP;
				} else {
					mrd->state = REPLACE_UUID;
					mrd->failover = NULL;
				}
			} else if (marker->cm_flags & CM_END)
				mrd->state = REPLACE_COPY;

			if (!strncmp(marker->cm_comment,
				"add failnid", 11))
				return 1;
		}
	}

	return 0;
}

static
int record_base_raw(const struct lu_env *env, struct llog_handle *llh,
		    char *cfgname, __u32 num, __u32 flags, lnet_nid_t nid,
		    int cmd, char *s1, char *s2, char *s3, char *s4)
{
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct llog_cfg_rec	*lcr;
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

	lcr = lustre_cfg_rec_new(cmd, &mgi->mgi_bufs);
	if (lcr == NULL)
		return -ENOMEM;

	lcr->lcr_cfg.lcfg_num = num;
	lcr->lcr_cfg.lcfg_flags = flags;
	lcr->lcr_cfg.lcfg_nid = nid;
	rc = llog_write(env, llh, &lcr->lcr_hdr, LLOG_NEXT_IDX);

	lustre_cfg_rec_free(lcr);

	if (rc < 0)
		CDEBUG(D_MGS,
		       "failed to write lcfg %s %#x %s %s %s %s: rc = %d\n",
		       cfgname, cmd, s1, s2, s3, s4, rc);
	return rc;
}

static inline
int record_base(const struct lu_env *env, struct llog_handle *llh,
		char *cfgname, lnet_nid_t nid, int cmd,
		char *s1, char *s2, char *s3, char *s4)
{
	return record_base_raw(env, llh, cfgname, 0, 0, nid, cmd,
			       s1, s2, s3, s4);
}

static inline int record_add_uuid(const struct lu_env *env,
				  struct llog_handle *llh,
				  struct lnet_nid *nid, char *uuid)
{
	lnet_nid_t nid4 = 0;
	char *cfg2 = NULL;

	if (nid_is_nid4(nid))
		nid4 = lnet_nid_to_nid4(nid);
	else
		cfg2 = libcfs_nidstr(nid);
	return record_base(env, llh, NULL, nid4, LCFG_ADD_UUID, uuid,
			   cfg2, NULL, NULL);
}

static inline int record_add_conn(const struct lu_env *env,
				  struct llog_handle *llh,
				  char *devname, char *uuid)
{
	return record_base(env, llh, devname, 0, LCFG_ADD_CONN, uuid,
			   NULL, NULL, NULL);
}

static inline int record_attach(const struct lu_env *env,
				struct llog_handle *llh, char *devname,
				char *type, char *uuid)
{
	return record_base(env, llh, devname, 0, LCFG_ATTACH, type, uuid,
			   NULL, NULL);
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
			   struct mgs_replace_data *mrd)
{
	int nids_added = 0;
	struct lnet_nid nid;
	char *ptr;
	int rc = 0;

	if (mrd->state == REPLACE_UUID &&
	    lcfg->lcfg_command == LCFG_ADD_UUID) {
		/* LCFG_ADD_UUID command found. Let's skip original command
		   and add passed nids */
		ptr = mrd->target.mti_params;
		while (class_parse_nid(ptr, &nid, &ptr) == 0) {
			if (!mrd->nodeuuid) {
				rc = niduuid_create(&mrd->nodeuuid,
						    libcfs_nidstr(&nid));
				if (rc) {
					CERROR("Can't create uuid for "
						"nid  %s, device %s\n",
						libcfs_nidstr(&nid),
						mrd->target.mti_svname);
					return rc;
				}
			}
			CDEBUG(D_MGS, "add nid %s with uuid %s, device %s\n",
			       libcfs_nidstr(&nid),
			       mrd->target.mti_params,
			       mrd->nodeuuid);
			rc = record_add_uuid(env,
					     mrd->temp_llh, &nid,
					     mrd->nodeuuid);
			if (rc)
				CWARN("%s: Can't add nid %s for uuid %s :rc=%d\n",
					mrd->target.mti_svname,
					libcfs_nidstr(&nid),
					mrd->nodeuuid, rc);
			else
				nids_added++;

			if (*ptr == ':') {
				mrd->failover = ptr;
				break;
			}
		}

		if (nids_added == 0) {
			CERROR("No new nids were added, nid %s with uuid %s, device %s\n",
			       libcfs_nidstr(&nid),
			       mrd->nodeuuid ? mrd->nodeuuid : "NULL",
			       mrd->target.mti_svname);
			niduuid_destroy(&mrd->nodeuuid);
			return -ENXIO;
		} else {
			mrd->state = REPLACE_SETUP;
		}

		return nids_added;
	}

	if (mrd->state == REPLACE_SETUP && lcfg->lcfg_command == LCFG_SETUP) {
		/* LCFG_SETUP command found. UUID should be changed */
		rc = record_setup(env,
				  mrd->temp_llh,
				  /* devname the same */
				  lustre_cfg_string(lcfg, 0),
				  /* s1 is not changed */
				  lustre_cfg_string(lcfg, 1),
				  mrd->nodeuuid,
				  /* s3 is not changed */
				  lustre_cfg_string(lcfg, 3),
				  /* s4 is not changed */
				  lustre_cfg_string(lcfg, 4));

		niduuid_destroy(&mrd->nodeuuid);
		if (rc)
			return rc;

		if (mrd->failover) {
			ptr = mrd->failover;
			while (class_parse_nid(ptr, &nid, &ptr) == 0) {
				if (mrd->nodeuuid == NULL) {
					rc = niduuid_create(&mrd->nodeuuid,
							   libcfs_nidstr(&nid));
					if (rc)
						return rc;
				}

				CDEBUG(D_MGS, "add nid %s for failover %s\n",
				       libcfs_nidstr(&nid), mrd->nodeuuid);
				rc = record_add_uuid(env, mrd->temp_llh, &nid,
						     mrd->nodeuuid);
				if (rc) {
					CWARN("%s: Can't add nid %s for failover %s :rc = %d\n",
						mrd->target.mti_svname,
						libcfs_nidstr(&nid),
						mrd->nodeuuid, rc);
					niduuid_destroy(&mrd->nodeuuid);
					return rc;
				}
				if (*ptr == ':') {
					rc = record_add_conn(env,
						mrd->temp_llh,
						lustre_cfg_string(lcfg, 0),
						mrd->nodeuuid);
					niduuid_destroy(&mrd->nodeuuid);
					if (rc)
						return rc;
				}
			}
			if (mrd->nodeuuid) {
				rc = record_add_conn(env, mrd->temp_llh,
						     lustre_cfg_string(lcfg, 0),
						     mrd->nodeuuid);
				niduuid_destroy(&mrd->nodeuuid);
				if (rc)
					return rc;
			}
		}
		mrd->state = REPLACE_DONE;
		return rc ? rc : 1;
	}

	/* All new UUID are added. Skip. */
	if (mrd->state == REPLACE_SETUP &&
		lcfg->lcfg_command == LCFG_ADD_UUID)
		return 1;

	/* Another commands in target device block */
	return 0;
}

/**
 * Handler that called for every record in llog.
 * Records are processed in order they placed in llog.
 *
 * \param[in] llh       log to be processed
 * \param[in] rec       current record
 * \param[in] data      mgs_replace_data structure
 *
 * \retval 0    success
 */
static int mgs_replace_nids_handler(const struct lu_env *env,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *rec,
				    void *data)
{
	struct mgs_replace_data *mrd = data;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	int rc;

	ENTRY;

	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("unhandled lrh_type: %#x, cmd %x %s %s\n",
		       rec->lrh_type, lcfg->lcfg_command,
		       lustre_cfg_string(lcfg, 0),
		       lustre_cfg_string(lcfg, 1));
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc) /* Do not copy any invalidated records */
		GOTO(skip_out, rc = 0);

	rc = check_markers(lcfg, mrd);
	if (rc || mrd->state == REPLACE_SKIP)
		GOTO(skip_out, rc = 0);

	/* Write to new log all commands outside target device block */
	if (mrd->state == REPLACE_COPY)
		GOTO(copy_out, rc = 0);

	if (mrd->state == REPLACE_DONE &&
	    (lcfg->lcfg_command == LCFG_ADD_UUID ||
	     lcfg->lcfg_command == LCFG_ADD_CONN)) {
		if (!mrd->failover)
			CWARN("Previous failover is deleted, but new one is "
			      "not set. This means you configure system "
			      "without failover or passed wrong replace_nids "
			      "command parameters. Device %s, passed nids %s\n",
			      mrd->target.mti_svname, mrd->target.mti_params);
		GOTO(skip_out, rc = 0);
	}

	rc = process_command(env, lcfg, mrd);
	if (rc < 0)
		RETURN(rc);

	if (rc)
		RETURN(0);
copy_out:
	/* Record is placed in temporary llog as is */
	rc = llog_write(env, mrd->temp_llh, rec, LLOG_NEXT_IDX);

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

static int mgs_replace_log(const struct lu_env *env,
			   struct obd_device *mgs,
			   char *logname, char *devname,
			   llog_cb_t replace_handler, void *data)
{
	struct llog_handle *orig_llh, *backup_llh;
	struct llog_ctxt *ctxt;
	struct mgs_replace_data *mrd;
	struct mgs_device *mgs_dev = lu2mgs_dev(mgs->obd_lu_dev);
	static struct obd_uuid	 cfg_uuid = { .uuid = "config_uuid" };
	char *backup;
	int rc, rc2, buf_size;
	time64_t now;
	ENTRY;

	ctxt = llog_get_context(mgs, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	if (mgs_log_is_empty(env, mgs_dev, logname)) {
		/* Log is empty. Nothing to replace */
		GOTO(out_put, rc = 0);
	}

	now = ktime_get_real_seconds();

	/* max time64_t in decimal fits into 20 bytes long string */
	buf_size = strlen(logname) + 1 + 20 + 1 + strlen(".bak") + 1;
	OBD_ALLOC(backup, buf_size);
	if (backup == NULL)
		GOTO(out_put, rc = -ENOMEM);

	snprintf(backup, buf_size, "%s.%llu.bak", logname, now);

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

	OBD_ALLOC_PTR(mrd);
	if (!mrd)
		GOTO(out_close, rc = -ENOMEM);
	/* devname is only needed information to replace UUID records */
	if (devname)
		strscpy(mrd->target.mti_svname, devname,
			sizeof(mrd->target.mti_svname));
	/* data is parsed in llog callback */
	if (data)
		strscpy(mrd->target.mti_params, data,
			sizeof(mrd->target.mti_params));
	/* Copy records to this temporary llog */
	mrd->temp_llh = orig_llh;

	rc = llog_process_or_fork(env, backup_llh, replace_handler,
			  (void *)mrd, NULL, false);
	OBD_FREE_PTR(mrd);
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
	OBD_FREE(backup, buf_size);

out_put:
	llog_ctxt_put(ctxt);

	if (rc)
		CERROR("%s: failed to replace log %s: rc = %d\n",
		       mgs->obd_name, logname, rc);

	RETURN(rc);
}

static int mgs_replace_nids_log(const struct lu_env *env,
				struct obd_device *obd,
				char *logname, char *devname, char *nids)
{
	CDEBUG(D_MGS, "Replace NIDs for %s in %s\n", devname, logname);
	return mgs_replace_log(env, obd, logname, devname,
			       mgs_replace_nids_handler, nids);
}

/**
 * Parse device name and get file system name and/or device index
 *
 * @devname	device name (ex. lustre-MDT0000)
 * @fsname	file system name extracted from @devname and returned
 *		to the caller (optional)
 * @index	device index extracted from @devname and returned to
 *		the caller (optional)
 *
 * RETURN	0			success if we are only interested in
 *					extracting fsname from devname.
 *					i.e index is NULL
 *
 *		LDD_F_SV_TYPE_*		Besides extracting the fsname the
 *					user also wants the index. Report to
 *					the user the type of obd device the
 *					returned index belongs too.
 *
 *		-EINVAL			The obd device name is improper so
 *					fsname could not be extracted.
 *
 *		-ENXIO			Failed to extract the index out of
 *					the obd device name. Most likely an
 *					invalid obd device name
 */
static int mgs_parse_devname(char *devname, char *fsname, u32 *index)
{
	int rc = 0;
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
			RETURN(-ENXIO);
		}
	}

	/* server_name2index can return LDD_F_SV_TYPE_* so always return rc */
	RETURN(rc);
}

/* This is only called during replace_nids */
static int only_mgs_is_running(struct obd_device *mgs_obd)
{
	int num_devices = class_obd_devs_count();
	int num_exports = 0;
	struct obd_export *exp;

	spin_lock(&mgs_obd->obd_dev_lock);
	list_for_each_entry(exp, &mgs_obd->obd_exports, exp_obd_chain) {
		/* skip self export */
		if (exp == mgs_obd->obd_self_export)
			continue;

		++num_exports;

		if (num_exports > 1)
			CERROR("%s: node %s still connected during replace_nids connect_flags:%llx\n",
			       mgs_obd->obd_name,
			       libcfs_nidstr(&exp->exp_nid_stats->nid),
			       exp_connect_flags(exp));
	}
	spin_unlock(&mgs_obd->obd_dev_lock);

	/* osd, MGS and MGC + MGC export (nosvc starts MGC)
	 *  (wc -l /proc/fs/lustre/devices <= 3) && (non self exports == 1)
	 */
	return (num_devices <= 3) && (num_exports <= 1);
}

static int name_create_mdt(char **logname, char *fsname, int mdt_idx)
{
	char postfix[9];

	if (mdt_idx > INDEX_MAP_MAX_VALUE)
		return -E2BIG;

	snprintf(postfix, sizeof(postfix), "-MDT%04x", mdt_idx);
	return name_create(logname, fsname, postfix);
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
	struct fs_db *fsdb = NULL;
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

	/* Get fsname and index */
	rc = mgs_parse_devname(devname, fsname, &index);
	if (rc < 0)
		GOTO(out, rc);

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
	if (rc) {
		CERROR("%s: can't find fsdb: rc = %d\n", fsname, rc);
		GOTO(out, rc);
	}

	/* Process client llogs */
	rc = name_create(&logname, fsname, "-client");
	if (rc)
		GOTO(out, rc);
	rc = mgs_replace_nids_log(env, mgs_obd, logname, devname, nids);
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
		rc = name_create_mdt(&logname, fsname, i);
		if (rc)
			GOTO(out, rc);
		rc = mgs_replace_nids_log(env, mgs_obd, logname, devname, nids);
		name_destroy(&logname);
		if (rc)
			GOTO(out, rc);
	}

out:
	spin_lock(&mgs_obd->obd_dev_lock);
	mgs_obd->obd_no_conn = conn_state;
	spin_unlock(&mgs_obd->obd_dev_lock);

	if (fsdb)
		mgs_put_fsdb(mgs, fsdb);

	RETURN(rc);
}

/**
 * This is called for every record in llog. Some of records are
 * skipped, others are copied to new log as is.
 * Records to be skipped are
 *  marker records marked SKIP
 *  records enclosed between SKIP markers
 *
 * \param[in] llh	log to be processed
 * \param[in] rec	current record
 * \param[in] data	mgs_replace_data structure
 *
 * \retval 0	success
 **/
static int mgs_clear_config_handler(const struct lu_env *env,
				    struct llog_handle *llh,
				    struct llog_rec_hdr *rec, void *data)
{
	struct mgs_replace_data *mrd = data;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	int rc;

	ENTRY;

	if (rec->lrh_type != OBD_CFG_REC) {
		CDEBUG(D_MGS, "Config llog Name=%s, Record Index=%u, "
		       "Unhandled Record Type=%#x\n", llh->lgh_name,
		       rec->lrh_index, rec->lrh_type);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc) {
		CDEBUG(D_MGS, "Config llog Name=%s, Invalid config file.",
		       llh->lgh_name);
		RETURN(-EINVAL);
	}

	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker;

		marker = lustre_cfg_buf(lcfg, 1);
		if (marker->cm_flags & CM_SKIP) {
			if (marker->cm_flags & CM_START)
				mrd->state = REPLACE_SKIP;
			if (marker->cm_flags & CM_END)
				mrd->state = REPLACE_COPY;
			/* SKIP section started or finished */
			CDEBUG(D_MGS, "Skip idx=%d, rc=%d, len=%d, "
			       "cmd %x %s %s\n", rec->lrh_index, rc,
			       rec->lrh_len, lcfg->lcfg_command,
			       lustre_cfg_string(lcfg, 0),
			       lustre_cfg_string(lcfg, 1));
			RETURN(0);
		}
	} else {
		if (mrd->state == REPLACE_SKIP) {
			/* record enclosed between SKIP markers, skip it */
			CDEBUG(D_MGS, "Skip idx=%d, rc=%d, len=%d, "
			       "cmd %x %s %s\n", rec->lrh_index, rc,
			       rec->lrh_len, lcfg->lcfg_command,
			       lustre_cfg_string(lcfg, 0),
			       lustre_cfg_string(lcfg, 1));
			RETURN(0);
		}
	}

	/* Record is placed in temporary llog as is */
	rc = llog_write(env, mrd->temp_llh, rec, LLOG_NEXT_IDX);

	CDEBUG(D_MGS, "Copied idx=%d, rc=%d, len=%d, cmd %x %s %s\n",
	       rec->lrh_index, rc, rec->lrh_len, lcfg->lcfg_command,
	       lustre_cfg_string(lcfg, 0), lustre_cfg_string(lcfg, 1));
	RETURN(rc);
}

/*
 * Directory CONFIGS/ may contain files which are not config logs to
 * be cleared. Skip any llogs with a non-alphanumeric character after
 * the last '-'. For example, fsname-MDT0000.sav, fsname-MDT0000.bak,
 * fsname-MDT0000.orig, fsname-MDT0000~, fsname-MDT0000.20150516, etc.
 */
static bool config_to_clear(const char *logname)
{
	int i;
	char *str;

	str = strrchr(logname, '-');
	if (!str)
		return 0;

	i = 0;
	while (isalnum(str[++i]));
	return str[i] == '\0';
}

/**
 * Clear config logs for \a name
 *
 * \param env
 * \param mgs		MGS device
 * \param name		name of device or of filesystem
 *			(ex. lustre-OST0000 or lustre) in later case all logs
 *			will be cleared
 *
 * \retval 0		success
 */
int mgs_clear_configs(const struct lu_env *env,
		     struct mgs_device *mgs, const char *name)
{
	struct list_head dentry_list;
	struct mgs_direntry *dirent, *n;
	char *namedash;
	int conn_state;
	struct obd_device *mgs_obd = mgs->mgs_obd;
	int rc;

	ENTRY;

	/* Prevent clients and servers from connecting to mgs */
	spin_lock(&mgs_obd->obd_dev_lock);
	conn_state = mgs_obd->obd_no_conn;
	mgs_obd->obd_no_conn = 1;
	spin_unlock(&mgs_obd->obd_dev_lock);

	/*
	 * config logs cannot be cleaned if anything other than
	 * MGS is started
	 */
	if (!only_mgs_is_running(mgs_obd)) {
		CERROR("Only MGS is allowed to be started\n");
		GOTO(out, rc = -EBUSY);
	}

	/* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &dentry_list);
	if (rc) {
		CERROR("%s: cannot read config directory '%s': rc = %d\n",
		       mgs_obd->obd_name, MOUNT_CONFIGS_DIR, rc);
		GOTO(out, rc);
	}

	if (list_empty(&dentry_list)) {
		CERROR("%s: list empty reading config dir '%s': rc = %d\n",
			mgs_obd->obd_name, MOUNT_CONFIGS_DIR, -ENOENT);
		GOTO(out, rc = -ENOENT);
	}

	OBD_ALLOC(namedash, strlen(name) + 2);
	if (namedash == NULL)
		GOTO(out, rc = -ENOMEM);
	snprintf(namedash, strlen(name) + 2, "%s-", name);

	list_for_each_entry(dirent, &dentry_list, mde_list) {
		if (strcmp(name, dirent->mde_name) &&
		    strncmp(namedash, dirent->mde_name, strlen(namedash)))
			continue;
		if (!config_to_clear(dirent->mde_name))
			continue;
		CDEBUG(D_MGS, "%s: Clear config log %s\n",
		       mgs_obd->obd_name, dirent->mde_name);
		rc = mgs_replace_log(env, mgs_obd, dirent->mde_name, NULL,
				     mgs_clear_config_handler, NULL);
		if (rc)
			break;
	}

	list_for_each_entry_safe(dirent, n, &dentry_list, mde_list) {
		list_del_init(&dirent->mde_list);
		mgs_direntry_free(dirent);
	}
	OBD_FREE(namedash, strlen(name) + 2);
out:
	spin_lock(&mgs_obd->obd_dev_lock);
	mgs_obd->obd_no_conn = conn_state;
	spin_unlock(&mgs_obd->obd_dev_lock);

	RETURN(rc);
}

static int record_lov_setup(const struct lu_env *env, struct llog_handle *llh,
			    char *devname, struct lov_desc *desc)
{
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct llog_cfg_rec	*lcr;
	int rc;

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, devname);
	lustre_cfg_bufs_set(&mgi->mgi_bufs, 1, desc, sizeof(*desc));
	lcr = lustre_cfg_rec_new(LCFG_SETUP, &mgi->mgi_bufs);
	if (lcr == NULL)
		return -ENOMEM;

	rc = llog_write(env, llh, &lcr->lcr_hdr, LLOG_NEXT_IDX);
	lustre_cfg_rec_free(lcr);
	return rc;
}

static int record_lmv_setup(const struct lu_env *env, struct llog_handle *llh,
			    char *devname, struct lmv_desc *desc)
{
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct llog_cfg_rec	*lcr;
	int rc;

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, devname);
	lustre_cfg_bufs_set(&mgi->mgi_bufs, 1, desc, sizeof(*desc));
	lcr = lustre_cfg_rec_new(LCFG_SETUP, &mgi->mgi_bufs);
	if (lcr == NULL)
		return -ENOMEM;

	rc = llog_write(env, llh, &lcr->lcr_hdr, LLOG_NEXT_IDX);
	lustre_cfg_rec_free(lcr);
	return rc;
}

static inline int record_mdc_add(const struct lu_env *env,
				 struct llog_handle *llh,
				 char *logname, char *mdcuuid,
				 char *mdtuuid, char *index,
				 char *gen)
{
	return record_base(env,llh,logname,0,LCFG_ADD_MDC,
			   mdtuuid, index, gen, mdcuuid);
}

static inline int record_lov_add(const struct lu_env *env,
				 struct llog_handle *llh,
				 char *lov_name, char *ost_uuid,
				 char *index, char *gen)
{
	return record_base(env, llh, lov_name, 0, LCFG_LOV_ADD_OBD,
			   ost_uuid, index, gen, NULL);
}

static inline int record_mount_opt(const struct lu_env *env,
				   struct llog_handle *llh,
				   char *profile, char *lov_name,
				   char *mdc_name)
{
	return record_base(env, llh, NULL, 0, LCFG_MOUNTOPT,
			   profile, lov_name, mdc_name, NULL);
}

static int record_marker(const struct lu_env *env,
			 struct llog_handle *llh,
			 struct fs_db *fsdb, __u32 flags,
			 char *tgtname, char *comment)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	struct llog_cfg_rec *lcr;
	int rc;
	int cplen = 0;

	if (flags & CM_START)
		fsdb->fsdb_gen++;
	mgi->mgi_marker.cm_step = fsdb->fsdb_gen;
	mgi->mgi_marker.cm_flags = flags;
	mgi->mgi_marker.cm_vers = LUSTRE_VERSION_CODE;
	cplen = strscpy(mgi->mgi_marker.cm_tgtname, tgtname,
			sizeof(mgi->mgi_marker.cm_tgtname));
	if (cplen < 0)
		return cplen;
	cplen = strscpy(mgi->mgi_marker.cm_comment, comment,
			sizeof(mgi->mgi_marker.cm_comment));
	if (cplen < 0)
		return cplen;
	mgi->mgi_marker.cm_createtime = ktime_get_real_seconds();
	mgi->mgi_marker.cm_canceltime = 0;
	lustre_cfg_bufs_reset(&mgi->mgi_bufs, NULL);
	lustre_cfg_bufs_set(&mgi->mgi_bufs, 1, &mgi->mgi_marker,
			    sizeof(mgi->mgi_marker));
	lcr = lustre_cfg_rec_new(LCFG_MARKER, &mgi->mgi_bufs);
	if (lcr == NULL)
		return -ENOMEM;

	rc = llog_write(env, llh, &lcr->lcr_hdr, LLOG_NEXT_IDX);
	lustre_cfg_rec_free(lcr);
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
				char *logname, struct llog_cfg_rec *lcr,
				char *devname, char *comment)
{
	struct llog_handle *llh = NULL;
	int rc;

	ENTRY;

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		RETURN(rc);

        /* FIXME These should be a single journal transaction */
	rc = record_marker(env, llh, fsdb, CM_START, devname, comment);
	if (rc)
		GOTO(out_end, rc);
	rc = llog_write(env, llh, &lcr->lcr_hdr, LLOG_NEXT_IDX);
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
static int mgs_write_log_direct_all(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    struct mgs_target_info *mti,
				    struct llog_cfg_rec *lcr, char *devname,
				    char *comment, int server_only)
{
	struct list_head	 log_list;
	struct mgs_direntry	*dirent, *n;
	char			*fsname = mti->mti_fsname;
	int			 rc = 0, len = strlen(fsname);

	ENTRY;
	/* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &log_list);
	if (rc)
		RETURN(rc);

	/* Could use fsdb index maps instead of directory listing */
	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		list_del_init(&dirent->mde_list);
		/* don't write to sptlrpc rule log */
		if (strstr(dirent->mde_name, "-sptlrpc") != NULL)
			goto next;

		/* caller wants write server logs only */
		if (server_only && strstr(dirent->mde_name, "-client") != NULL)
			goto next;

		if (strlen(dirent->mde_name) <= len ||
		    strncmp(fsname, dirent->mde_name, len) != 0 ||
		    dirent->mde_name[len] != '-')
			goto next;

		CDEBUG(D_MGS, "Changing log %s\n", dirent->mde_name);
		/* Erase any old settings of this same parameter */
		rc = mgs_modify(env, mgs, fsdb, mti, dirent->mde_name,
				devname, comment, CM_SKIP);
		if (rc < 0)
			CERROR("%s: Can't modify llog %s: rc = %d\n",
			       mgs->mgs_obd->obd_name, dirent->mde_name, rc);
		if (lcr == NULL)
			goto next;
		/* Write the new one */
		rc = mgs_write_log_direct(env, mgs, fsdb, dirent->mde_name,
					  lcr, devname, comment);
		if (rc != 0)
			CERROR("%s: writing log %s: rc = %d\n",
			       mgs->mgs_obd->obd_name, dirent->mde_name, rc);
next:
		mgs_direntry_free(dirent);
	}

	RETURN(rc);
}

/**
 * Replace a mdt name in MDT configuration name
 * mdtname should be formated like this: <fsname>-MDT<mdtindex>
 **/
static
int mgs_replace_mdtname(char *name, size_t size, char *mdtsrc, char *mdtnew)
{
	char *ptr, *src, *new;
	size_t n;

	if (!name || !size)
		return 0;

	src = strstr(mdtsrc, "-MDT");
	new = strstr(mdtnew, "-MDT");
	if (!src || !new)
		return -EINVAL;

	n = src - mdtsrc;
	if (strncmp(name, mdtsrc, n) != 0)
		return -ENOENT;
	if (name[n] == '\0')
		return 0;
	if (name[n] != '-')
		return -ENOENT;

	n = strlen(src);
	ptr = strstr(name, src);
	while (ptr) {
		char *end = ptr + n;

		if (*end == '\0' || *end == '-' || *end == '_')
			strncpy(ptr, new, n);
		ptr = end;
		ptr = strstr(ptr, src);
	}

	return 0;
}

static inline
bool mgs_copy_skipped(struct cfg_marker *marker, struct mgs_target_info *mti,
		      char *mdtsrc)
{
	size_t fsname_len = strlen(mti->mti_fsname);
	char *comment = marker->cm_comment;
	char *tgtname = marker->cm_tgtname;

	if (marker->cm_flags & CM_SKIP)
		return true;

	/* fsname does not match? */
	if (strncmp(tgtname, mti->mti_fsname, fsname_len) != 0)
		return true;

	if (tgtname[fsname_len] != '\0' && tgtname[fsname_len] != '-')
		return true;

	/* filter out existing sections */
	if (strncmp(comment, "add mdt", 7) == 0 ||
	    strncmp(comment, "lov setup", 9) == 0 ||
	    strncmp(comment, "add osp", 7) == 0 ||
	    strncmp(comment, "add osc", 7) == 0 ||
	    strncmp(comment, "add failnid", 11) == 0)
		return true;

	/* exclude paramater for invalid osp devices (--writeconf case) */
	if (strncmp(tgtname, mti->mti_svname, strlen(mti->mti_svname)) == 0)
		return true;

	return false;
}

/**
 * Update the marker->cm_tgtname with the new MDT target name:
 *	marker ... lustre-MDT0000  'mdt.identity_upcall'
 * -->	marker ... lustre-MDT0003  'mdt.identity_upcall'
 **/
static inline
void mgs_copy_update_marker(char *fsname, struct cfg_marker *marker,
			    char *mdtsrc, char *mdtnew)
{
	mgs_replace_mdtname(marker->cm_tgtname, sizeof(marker->cm_tgtname),
			    mdtsrc, mdtnew);
}

struct mgs_copy_data {
	struct llog_handle	*mcd_llh;
	struct mgs_target_info	*mcd_mti;
	struct fs_db		*mcd_fsdb;
	bool			mcd_skip;
};

/**
 * Walk through MDT config log records and convert the related records
 * into the target.
 *
 * The osp sections (add osp/add osc) are excluded. Those sections are
 * generated from client configuration by mgs_steal_osp_rec_from_client()
 **/
static int mgs_copy_mdt_llog_handler(const struct lu_env *env,
				      struct llog_handle *llh,
				      struct llog_rec_hdr *rec, void *data)
{
	struct mgs_copy_data *mcd = data;
	struct mgs_target_info *mti = mcd->mcd_mti;
	struct llog_handle *mdt_llh = mcd->mcd_llh;
	struct fs_db *fsdb = mcd->mcd_fsdb;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	char *mdtsrc = llh->lgh_name;
	char *s[5] = { 0 };
	int i;
	int rc = 0;

	ENTRY;

	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc) {
		CERROR("Insane cfg\n");
		RETURN(rc);
	}

	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

		if (marker->cm_flags & CM_START)
			mcd->mcd_skip = mgs_copy_skipped(marker, mti, mdtsrc);

		if (mcd->mcd_skip)
			RETURN(0);

		mgs_copy_update_marker(mti->mti_fsname, marker,
				       mdtsrc, mti->mti_svname);
		rc = record_marker(env, mdt_llh, fsdb, marker->cm_flags,
				   marker->cm_tgtname, marker->cm_comment);
		if (rc)
			RETURN(rc);

		if (marker->cm_flags & CM_END)
			mcd->mcd_skip = true;

		RETURN(0);
	}

	if (mcd->mcd_skip)
		RETURN(0);

	/* init cfg strings with the client record values */
	for (i = 0; i < 5; i++)
		s[i] = lustre_cfg_buf(lcfg, i);

	/* convert records with the new target name */
	switch (lcfg->lcfg_command) {
	case LCFG_ATTACH:
	case LCFG_DETACH:
	case LCFG_ADD_CONN:
	case LCFG_DEL_CONN:
	case LCFG_SETUP:
	case LCFG_CLEANUP:
	case LCFG_ADD_MDC:
	case LCFG_DEL_MDC:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_ADD_OBD:
	case LCFG_LOV_DEL_OBD:
		RETURN(0);
		break;
	default:
		rc = mgs_replace_mdtname(s[0], LUSTRE_CFG_BUFLEN(lcfg, 0),
					 mdtsrc, mti->mti_svname);
		if (rc)
			RETURN(rc);
		break;
	}

	rc = record_base_raw(env, mdt_llh, s[0],
			     lcfg->lcfg_num, lcfg->lcfg_flags, lcfg->lcfg_nid,
			     lcfg->lcfg_command, s[1], s[2], s[3], s[4]);

	RETURN(rc);
}


/* copy an existing MDT configuration records for a new MDT configuration */
static int mgs_copy_llog_from_mdt(const struct lu_env *env,
				   struct mgs_device *mgs,
				   struct mgs_target_info *mti,
				   struct fs_db *fsdb)
{
	char *logname = NULL;
	struct llog_handle *loghandle;
	struct llog_ctxt *ctxt;
	struct mgs_copy_data mcd = { 0 };
	int i;
	int rc;

	ENTRY;

	if (fsdb->fsdb_mdt_count < 2)
		RETURN(0);

	for_each_set_bit(i, fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE) {
		if (mti->mti_stripe_index == i)
			continue;

		rc = name_create_mdt(&logname, fsdb->fsdb_name, i);
		if (rc)
			GOTO(out_free, rc);

		if (mgs_log_is_empty(env, mgs, logname)) {
			name_destroy(&logname);
			continue;
		}

		break;
	}

	/* is there an existing MDT configuration? */
	if (!logname)
		RETURN(0);

	/* check if MDT source name is valid */
	if (strncmp(mti->mti_svname, logname, strlen(mti->mti_fsname) + 1) != 0)
		GOTO(out_free, rc = -EINVAL);
	if (strlen(mti->mti_svname) != strlen(logname))
		GOTO(out_free, rc = -EINVAL);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	rc = llog_open(env, ctxt, &loghandle, NULL, logname,
		       LLOG_OPEN_EXISTS);
	if (rc < 0)
		GOTO(out_put, rc);

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	mcd.mcd_mti = mti;
	mcd.mcd_fsdb = fsdb;
	mcd.mcd_skip = true;

	rc = record_start_log(env, mgs, &mcd.mcd_llh, mti->mti_svname);
	if (rc)
		GOTO(out_close, rc);

	rc = llog_process_or_fork(env, loghandle, mgs_copy_mdt_llog_handler,
				  &mcd, NULL, false);
	if (rc)
		CWARN("%s: Fail to copy records from %s configuration: rc = %d\n",
		      mti->mti_svname, logname, rc);

	record_end_log(env, &mcd.mcd_llh);

	EXIT;
out_close:
	llog_close(env, loghandle);
out_put:
	llog_ctxt_put(ctxt);
out_free:
	name_destroy(&logname);

	return rc;
}

struct mgs_steal_data {
	struct llog_handle	*msd_llh;
	struct fs_db		*msd_fsdb;
	struct mgs_target_info	*msd_mti;
	bool			msd_skip;
	char			*msd_ospname;
	char			*msd_lovname;
	char			*msd_lovuuid;
	char			*msd_devtype;
};

static inline
int mgs_steal_update_names(char *tgtname, struct mgs_steal_data *msd)
{
	struct mgs_target_info	*mti = msd->msd_mti;
	int rc = 0;

	name_destroy(&msd->msd_ospname);
	name_destroy(&msd->msd_lovname);
	name_destroy(&msd->msd_lovuuid);

	rc = name_create_osp(&msd->msd_ospname, &msd->msd_devtype, tgtname,
			     mti->mti_stripe_index);
	if (rc)
		return rc;

	rc = name_create_lov(&msd->msd_lovname, mti->mti_svname);
	if (rc)
		goto err_free_osp;

	rc = name_create(&msd->msd_lovuuid, msd->msd_lovname,  "_UUID");
	if (rc)
		goto err_free_lov;

	return 0;

err_free_lov:
	name_destroy(&msd->msd_lovname);
err_free_osp:
	name_destroy(&msd->msd_ospname);

	return rc;
}

static inline
int mgs_steal_skipped(struct mgs_steal_data *msd,
		      struct cfg_marker *marker)
{
	char *tgtname = marker->cm_tgtname;
	char *comment = marker->cm_comment;
	char *fsname = msd->msd_mti->mti_fsname;
	size_t fsname_len = strlen(fsname);

	if ((marker->cm_flags & CM_SKIP) ||
	    strncmp(tgtname, fsname, fsname_len) != 0 ||
	    tgtname[fsname_len] != '-')
		return true;

	if (strncmp(comment, "add mdc", 7) != 0 &&
	    strncmp(comment, "add osc", 7) != 0 &&
	    strncmp(comment, "add failnid", 11) != 0)
		return true;

	/* check for invalid osp devices (--writeconf case) */
	if (strcmp(tgtname, msd->msd_mti->mti_svname) == 0)
		return true;

	return false;
}

/**
 * Walk through client config log for mdc/osc records and convert the related
 * records in osp records for the new MDT target.
 **/
static int mgs_steal_client_llog_handler(const struct lu_env *env,
					 struct llog_handle *llh,
					 struct llog_rec_hdr *rec, void *data)
{
	struct mgs_steal_data *msd = data;
	struct fs_db *fsdb = msd->msd_fsdb;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	char *s[5] = { 0 };
	int i;
	int rc = 0;

	ENTRY;

	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("%s: unhandled lrh_type %#x: rc = %d\n",
		       llh->lgh_name, rec->lrh_type, -EINVAL);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
	if (rc) {
		CERROR("%s: insane cfg: rc = %d\n", llh->lgh_name, rc);
		RETURN(rc);
	}

	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);
		char *comment = marker->cm_comment;

		if (marker->cm_flags & CM_START) {
			msd->msd_skip = mgs_steal_skipped(msd, marker);
			if (msd->msd_skip)
				RETURN(0);

			rc = mgs_steal_update_names(marker->cm_tgtname, msd);
			if (rc)
				RETURN(rc);
		}

		if (msd->msd_skip)
			RETURN(0);

		if (strncmp(comment, "add mdc", 7) == 0)
			comment = "add osp";

		rc = record_marker(env, msd->msd_llh, fsdb, marker->cm_flags,
				   marker->cm_tgtname, comment);
		if (rc)
			RETURN(rc);

		if (marker->cm_flags & CM_END)
			msd->msd_skip = true;

		RETURN(0);
	}

	if (msd->msd_skip)
		RETURN(0);

	/* init cfg strings with the client record values */
	for (i = 0; i < 5; i++)
		s[i] = lustre_cfg_buf(lcfg, i);

	/* convert the mdc records to osp */
	switch (lcfg->lcfg_command) {
	case LCFG_ADD_UUID:
		break;
	case LCFG_ATTACH:
		s[1] = msd->msd_devtype;
		s[2] = msd->msd_lovuuid;
		fallthrough;
	case LCFG_DETACH:
	case LCFG_ADD_CONN:
	case LCFG_DEL_CONN:
	case LCFG_SETUP:
	case LCFG_CLEANUP:
		s[0] = msd->msd_ospname;
		break;
	case LCFG_ADD_MDC:
	case LCFG_DEL_MDC:
	case LCFG_LOV_ADD_INA:
	case LCFG_LOV_ADD_OBD:
	case LCFG_LOV_DEL_OBD:
		s[0] = msd->msd_lovname;
		break;
	default:
		RETURN(0);
	}

	rc = record_base_raw(env, msd->msd_llh, s[0],
			     lcfg->lcfg_num, lcfg->lcfg_flags, lcfg->lcfg_nid,
			     lcfg->lcfg_command, s[1], s[2], s[3], s[4]);

	RETURN(rc);
}

/*
 * Steal mdc/osc records from the client configuration and convert them to
 * create osp devices (OST and MDT) for a new MDT configuration.
 *
 * fsdb->fsdb_mutex is already held in mgs_write_log_target
 * stealed from mgs_get_fsdb_from_llog
 */
static int mgs_steal_osp_rec_from_client(const struct lu_env *env,
					 struct mgs_device *mgs,
					 char *client_name,
					 struct mgs_target_info *mti,
					 struct fs_db *fsdb)
{
	struct llog_handle *loghandle;
	struct llog_ctxt *ctxt;
	struct mgs_steal_data msd = { 0 };
	int rc;

	ENTRY;

	if (mgs_log_is_empty(env, mgs, client_name))
		RETURN(0);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt != NULL);

	rc = llog_open(env, ctxt, &loghandle, NULL, client_name,
		       LLOG_OPEN_EXISTS);
	if (rc < 0)
		GOTO(out_pop, rc);

	rc = llog_init_handle(env, loghandle, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out_close, rc);

	msd.msd_fsdb = fsdb;
	msd.msd_skip = true;
	msd.msd_mti = mti;

	rc = record_start_log(env, mgs, &msd.msd_llh, mti->mti_svname);
	if (rc)
		GOTO(out_close, rc);

	rc = llog_process_or_fork(env, loghandle, mgs_steal_client_llog_handler,
				  &msd, NULL, false);
	if (rc)
		CWARN("%s: Fail to generate osp devices from %s : rc = %d\n",
		      mti->mti_svname, client_name, rc);

	record_end_log(env, &msd.msd_llh);

	name_destroy(&msd.msd_ospname);
	name_destroy(&msd.msd_lovname);
	name_destroy(&msd.msd_lovuuid);

out_close:
	llog_close(env, loghandle);
out_pop:
	llog_ctxt_put(ctxt);

	RETURN(rc);
}

/* mount opt is the third thing in client logs */
static int mgs_write_log_mount_opt(const struct lu_env *env,
				   struct mgs_device *mgs, struct fs_db *fsdb,
				   char *logname)
{
	struct llog_handle *llh = NULL;
	int rc = 0;

	ENTRY;

	CDEBUG(D_MGS, "Writing mount options log for %s\n", logname);

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		RETURN(rc);

	rc = record_marker(env, llh, fsdb, CM_START, logname, "mount opts");
	if (rc)
		GOTO(out_end, rc);
	rc = record_mount_opt(env, llh, logname, fsdb->fsdb_clilov,
			      fsdb->fsdb_clilmv);
	if (rc)
		GOTO(out_end, rc);
	rc = record_marker(env, llh, fsdb, CM_END, logname, "mount opts");
	if (rc)
		GOTO(out_end, rc);
out_end:
	record_end_log(env, &llh);
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
	CDEBUG(D_MGS, "Writing lmv(%s) log for %s\n", lmvname, logname);

	OBD_ALLOC_PTR(lmvdesc);
	if (lmvdesc == NULL)
		RETURN(-ENOMEM);
	lmvdesc->ld_active_tgt_count = 0;
	lmvdesc->ld_tgt_count = 0;
	sprintf((char *)lmvdesc->ld_uuid.uuid, "%s_UUID", lmvname);
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
	 * #01 L attach   0:lov_mdsA  1:lov  2:71ccb_lov_mdsA_19f961a9e1
	 * #02 L lov_setup 0:lov_mdsA 1:(struct lov_desc)
	 * uuid=lov1_UUID, stripe count=1, size=1048576, offset=0, pattern=0
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
	lovdesc->ld_default_stripe_size = LOV_DESC_STRIPE_SIZE_DEFAULT;
	lovdesc->ld_default_stripe_offset = -1;
	lovdesc->ld_qos_maxage = LOV_DESC_QOS_MAXAGE_DEFAULT;
	sprintf((char *)lovdesc->ld_uuid.uuid, "%s_UUID", lovname);
	/* can these be the same? */
	uuid = (char *)lovdesc->ld_uuid.uuid;

	/* This should always be the first entry in a log.
	 * rc = mgs_clear_log(obd, logname);
	 */
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
	struct lnet_nid nid;
	int rc = 0;

	/*
	 * #03 L add_uuid  nid=uml1@tcp(0x20000c0a80201) nal=90 0:  1:uml1_UUID
	 * #04 L add_uuid  nid=1@elan(0x1000000000001)   nal=90 0:  1:uml1_UUID
	 * #05 L setup    0:OSC_uml1_ost1_mdsA  1:ost1_UUID  2:uml1_UUID
	 * #06 L add_uuid  nid=uml2@tcp(0x20000c0a80202) nal=90 0:  1:uml2_UUID
	 * #0x L add_uuid  nid=2@elan(0x1000000000002)   nal=90 0:  1:uml2_UUID
	 * #07 L add_conn 0:OSC_uml1_ost1_mdsA  1:uml2_UUID
	 */

	/*
	 * Pull failnid info out of params string, which may contain something
	 * like "<nid1>,<nid2>:<nid3>,<nid4>".  class_parse_nid() does not
	 * complain about abnormal inputs like ",:<nid1>", "<nid1>:,<nid2>",
	 * etc.  However, convert_hostnames() should have caught those.
	 */
	while (class_find_param(ptr, PARAM_FAILNODE, &ptr) == 0) {
		while (class_parse_nid(ptr, &nid, &ptr) == 0) {
			char nidstr[LNET_NIDSTR_SIZE];

			if (failnodeuuid == NULL) {
				/* We don't know the failover node name,
				 * so just use the first nid as the uuid */
				libcfs_nidstr_r(&nid, nidstr, sizeof(nidstr));
				rc = niduuid_create(&failnodeuuid, nidstr);
				if (rc != 0)
					return rc;
			}
			CDEBUG(D_MGS,
			       "add nid %s for failover uuid %s, client %s\n",
			       libcfs_nidstr_r(&nid, nidstr, sizeof(nidstr)),
			       failnodeuuid, cliname);
			rc = record_add_uuid(env, llh, &nid, failnodeuuid);
			/*
			 * If *ptr is ':', we have added all NIDs for
			 * failnodeuuid.
			 */
			if (*ptr == ':') {
				rc = record_add_conn(env, llh, cliname,
						     failnodeuuid);
				niduuid_destroy(&failnodeuuid);
				failnodeuuid = NULL;
			}
		}
		if (failnodeuuid) {
			rc = record_add_conn(env, llh, cliname, failnodeuuid);
			niduuid_destroy(&failnodeuuid);
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
	char tmp[LNET_NIDSTR_SIZE], *nidstr;
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

	if (!target_supports_large_nid(mti)) {
		libcfs_nid2str_r(mti->mti_nids[0], tmp, sizeof(tmp));
		nidstr = tmp;
	} else {
		nidstr = mti->mti_nidlist[0];
	}

	rc = niduuid_create(&nodeuuid, nidstr);
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

	rc = mgs_modify(env, mgs, fsdb, mti, logname, mti->mti_svname,
			"add mdc", CM_SKIP);
	if (rc < 0)
		GOTO(out_free, rc);

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		GOTO(out_free, rc);
	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,
			   "add mdc");
	if (rc)
		GOTO(out_end, rc);

	for (i = 0; i < mti->mti_nid_count; i++) {
		struct lnet_nid nid;

		if (target_supports_large_nid(mti)) {
			rc = libcfs_strnid(&nid, mti->mti_nidlist[i]);
			if (rc < 0)
				GOTO(out_end, rc);
		} else {
			lnet_nid4_to_nid(mti->mti_nids[i], &nid);
		}

		CDEBUG(D_MGS, "add nid %s for mdt\n", libcfs_nidstr(&nid));
		rc = record_add_uuid(env, llh, &nid, nodeuuid);
		if (rc)
			GOTO(out_end, rc);
	}

	rc = record_attach(env, llh, mdcname, LUSTRE_MDC_NAME, lmvuuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, mdcname, mti->mti_uuid, nodeuuid,
			  NULL, NULL);
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
	niduuid_destroy(&nodeuuid);
	RETURN(rc);
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

/* add new mdc to already existent MDS */
static int mgs_write_log_osp_to_mdt(const struct lu_env *env,
				    struct mgs_device *mgs,
				    struct fs_db *fsdb,
				    struct mgs_target_info *mti,
				    int mdt_index, char *logname)
{
	char tmp[LNET_NIDSTR_SIZE], *nidstr;
	struct llog_handle	*llh = NULL;
	char	*nodeuuid = NULL;
	char	*ospname = NULL;
	char	*lovuuid = NULL;
	char	*mdtuuid = NULL;
	char	*mdtname = NULL;
	char	*lovname = NULL;
	char    index_str[16];
	int	i, rc;

	ENTRY;
	if (mgs_log_is_empty(env, mgs, mti->mti_svname)) {
		CERROR("log is empty! Logical error\n");
		RETURN(-EINVAL);
	}

	CDEBUG(D_MGS, "adding osp index %d to %s\n", mti->mti_stripe_index,
	       logname);

	rc = name_create_mdt(&mdtname, fsdb->fsdb_name, mti->mti_stripe_index);
	if (rc)
		RETURN(rc);

	if (!target_supports_large_nid(mti)) {
		libcfs_nid2str_r(mti->mti_nids[0], tmp, sizeof(tmp));
		nidstr = tmp;
	} else {
		nidstr = mti->mti_nidlist[0];
	}

	rc = niduuid_create(&nodeuuid, nidstr);
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create_osp(&ospname, NULL, mdtname, mdt_index);
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create_lov(&lovname, logname);
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create(&lovuuid, lovname, "_UUID");
	if (rc)
		GOTO(out_destory, rc);

	rc = name_create(&mdtuuid, mdtname, "_UUID");
	if (rc)
		GOTO(out_destory, rc);

	rc = mgs_modify(env, mgs, fsdb, mti, logname, mti->mti_svname,
			"add osp", CM_SKIP);
	if (rc < 0)
		GOTO(out_destory, rc);

	rc = record_start_log(env, mgs, &llh, logname);
	if (rc)
		GOTO(out_destory, rc);

	rc = record_marker(env, llh, fsdb, CM_START, mti->mti_svname,
			   "add osp");
	if (rc)
		GOTO(out_destory, rc);

	for (i = 0; i < mti->mti_nid_count; i++) {
		struct lnet_nid nid;

		if (target_supports_large_nid(mti)) {
			rc = libcfs_strnid(&nid, mti->mti_nidlist[i]);
			if (rc < 0)
				GOTO(out_end, rc);
		} else {
			lnet_nid4_to_nid(mti->mti_nids[i], &nid);
		}

		CDEBUG(D_MGS, "add nid %s for mdt\n", libcfs_nidstr(&nid));
		rc = record_add_uuid(env, llh, &nid, nodeuuid);
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
	snprintf(index_str, sizeof(index_str), "%d", mti->mti_stripe_index);
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
	niduuid_destroy(&nodeuuid);
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
	struct obd_uuid *uuid;
	char *lovname;
	char mdt_index[6];
	char *ptr = mti->mti_params;
	int rc = 0, failout = 0;

	ENTRY;
	OBD_ALLOC_PTR(uuid);
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
	sprintf(uuid->uuid, "%s_UUID", log);
	rc = record_marker(env, llh, fsdb, CM_START, log, "add mdt");
	if (rc)
		GOTO(out_lod, rc);
	rc = record_attach(env, llh, log, LUSTRE_MDT_NAME, uuid->uuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_mount_opt(env, llh, log, lovname, NULL);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, log, uuid->uuid, mdt_index, lovname,
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
	OBD_FREE_PTR(uuid);
	RETURN(rc);
}

/* envelope method for all layers log */
static int mgs_write_log_mdt(const struct lu_env *env,
			     struct mgs_device *mgs,
			     struct fs_db *fsdb,
			     struct mgs_target_info *mti)
{
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
		rc = mgs_write_log_mount_opt(env, mgs, fsdb, cliname);
		if (rc)
			GOTO(out_free, rc);
	}

	/*
	 * #09 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
	 * #10 L attach   0:MDC_uml1_mdsA_MNT_client  1:mdc  2:1d834_MNT_client_03f
	 * #11 L setup    0:MDC_uml1_mdsA_MNT_client  1:mdsA_UUID  2:uml1_UUID
	 * #12 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
	 * #13 L add_conn 0:MDC_uml1_mdsA_MNT_client  1:uml2_UUID
	 */
	rc = mgs_steal_osp_rec_from_client(env, mgs, cliname, mti, fsdb);
	if (rc)
		GOTO(out_free, rc);

	/* Try to copy remaining configurations from an existing MDT target */
	rc = mgs_copy_llog_from_mdt(env, mgs, mti, fsdb);
	if (rc)
		GOTO(out_free, rc);

	rc = mgs_write_log_mdc_to_lmv(env, mgs, fsdb, mti, cliname,
				      fsdb->fsdb_clilmv);
	if (rc)
		GOTO(out_free, rc);

	rc = record_start_log(env, mgs, &llh, cliname);
	if (rc)
		GOTO(out_free, rc);

	/* for_all_existing_mdt except current one */
	for_each_set_bit(i, fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE) {
		char *logname;

		if (mti->mti_stripe_index == i)
			continue;

		rc = name_create_mdt(&logname, fsdb->fsdb_name, i);
		if (rc)
			GOTO(out_end, rc);

		/*
		 * NB: If the log for the MDT is empty, it means
		 * the MDT is only added to the index
		 * map, and not being process yet, i.e. this
		 * is an unregistered MDT, see mgs_write_log_target().
		 * so we should skip it. Otherwise
		 *
		 * 1. MGS get register request for MDT1 and MDT2.
		 *
		 * 2. Then both MDT1 and MDT2 are added into
		 * fsdb_mdt_index_map. (see mgs_set_index()).
		 *
		 * 3. Then MDT1 get the lock of fsdb_mutex, then
		 * generate the config log, here, it will regard MDT2
		 * as an existent MDT, and generate "add osp" for
		 * lustre-MDT0001-osp-MDT0002. Note: at the moment
		 * MDT0002 config log is still empty, so it will
		 * add "add osp" even before "lov setup", which
		 * will definitly cause trouble.
		 *
		 * 4. MDT1 registeration finished, fsdb_mutex is
		 * released, then MDT2 get in, then in above
		 * mgs_steal_osp_rec_from_client(), it will
		 * add another osp log for lustre-MDT0001-osp-MDT0002,
		 * which will cause another trouble.
		 */
		if (!mgs_log_is_empty(env, mgs, logname))
			rc = mgs_write_log_osp_to_mdt(env, mgs, fsdb, mti, i,
						      logname);
		name_destroy(&logname);
		if (rc)
			GOTO(out_end, rc);
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
	char tmp[LNET_NIDSTR_SIZE], *nidstr;
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
		RETURN(-EINVAL);
	}

	if (!target_supports_large_nid(mti)) {
		libcfs_nid2str_r(mti->mti_nids[0], tmp, sizeof(tmp));
		nidstr = tmp;
	} else {
		nidstr = mti->mti_nidlist[0];
	}

	rc = niduuid_create(&nodeuuid, nidstr);
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
	 * #03 L add_uuid nid=uml1@tcp(0x20000c0a80201) 0:  1:uml1_UUID
	 * multihomed (#4)
	 * #04 L add_uuid  nid=1@elan(0x1000000000001)  nal=90 0:  1:uml1_UUID
	 * #04 L attach   0:OSC_uml1_ost1_MNT_client  1:osc  2:89070_lov1_a41dff51a
	 * #05 L setup    0:OSC_uml1_ost1_MNT_client  1:ost1_UUID  2:uml1_UUID
	 * failover (#6,7)
	 * #06 L add_uuid nid=uml2@tcp(0x20000c0a80202) 0:  1:uml2_UUID
	 * #07 L add_conn 0:OSC_uml1_ost1_MNT_client  1:uml2_UUID
	 * #08 L lov_modify_tgts add 0:lov1  1:ost1_UUID  2(index):0  3(gen):1
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
		struct lnet_nid nid;

		if (target_supports_large_nid(mti)) {
			rc = libcfs_strnid(&nid, mti->mti_nidlist[i]);
			if (rc < 0)
				GOTO(out_end, rc);
		} else {
			lnet_nid4_to_nid(mti->mti_nids[i], &nid);
		}

		CDEBUG(D_MGS, "add nid %s\n", libcfs_nidstr(&nid));
		rc = record_add_uuid(env, llh, &nid, nodeuuid);
		if (rc)
			GOTO(out_end, rc);
	}

	rc = record_attach(env, llh, oscname, LUSTRE_OSC_NAME, lovuuid);
	if (rc)
		GOTO(out_end, rc);
	rc = record_setup(env, llh, oscname, mti->mti_uuid, nodeuuid,
			  NULL, NULL);
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
	niduuid_destroy(&nodeuuid);
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
	 * the ost and it called target_add again.
	 */
	if (!mgs_log_is_empty(env, mgs, mti->mti_svname)) {
		LCONSOLE_ERROR("The config log for %s already exists, yet the server claims it never registered. It may have been reformatted, or the index changed. writeconf the MDT to regenerate all logs.\n",
			       mti->mti_svname);
		RETURN(-EALREADY);
	}

	/*
	 * attach obdfilter ost1 ost1_UUID
	 * setup /dev/loop2 ldiskfs f|n errors=remount-ro,user_xattr
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
			  failout ? "n" : "f", NULL/*options*/);
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
	 * the lov
	 */

	if (test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
		/* If we're upgrading, the old mdt log already has our
		 * entry. Let's do a fake one for fun.
		 */
		/* Note that we can't add any new failnids, since we don't
		 * know the old osc names.
		 */
		flags = CM_SKIP | CM_UPGRADE146;
	} else if ((mti->mti_flags & LDD_F_UPDATE) != LDD_F_UPDATE) {
		/* If the update flag isn't set, don't update client/mdt
		 * logs.
		 */
		flags |= CM_SKIP;
		LCONSOLE_WARN("Client log for %s was not updated; writeconf the MDT first to regenerate it.\n",
			mti->mti_svname);
	}

	/* Add ost to all MDT lov defs */
	for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
		if (test_bit(i, fsdb->fsdb_mdt_index_map)) {
			char mdt_index[13];

			rc = name_create_mdt_and_lov(&logname, &lovname, fsdb,
						     i);
			if (rc)
				RETURN(rc);

			snprintf(mdt_index, sizeof(mdt_index), "-MDT%04x", i);
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
		rc = mgs_write_log_mount_opt(env, mgs, fsdb, logname);
		if (rc)
			GOTO(out_free, rc);
	}
	rc = mgs_write_log_osc_to_lov(env, mgs, fsdb, mti, logname, "",
				      fsdb->fsdb_clilov, LUSTRE_SP_CLI, flags);
out_free:
	name_destroy(&logname);
	RETURN(rc);
}

static inline void mgs_param_del_value(char *ptr)
{
	char *tmp = strchr(ptr, '=');

	if (tmp && tmp[1])
		tmp[1] = '\0';
}

static inline int mgs_param_empty(const char *ptr)
{
	char *tmp = strchr(ptr, '=');

	if (!tmp || tmp[1] == '\0')
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
	int i;
	int rc;

	ENTRY;
	/* FIXME we currently can't erase the failnids
	 * given when a target first registers, since they aren't part of
	 * an "add uuid" stanza
	 */

	/* Verify that we know about this target */
	if (mgs_log_is_empty(env, mgs, mti->mti_svname)) {
		LCONSOLE_ERROR("The target %s has not registered yet. It must be started before failnids can be added.\n",
			       mti->mti_svname);
		RETURN(-ENOENT);
	}

	/* Create mdc/osc client name (e.g. lustre-OST0001-osc) */
	if (mti->mti_flags & LDD_F_SV_TYPE_MDT)
		rc = name_create(&cliname, mti->mti_svname, "-mdc");
	else if (mti->mti_flags & LDD_F_SV_TYPE_OST)
		rc = name_create(&cliname, mti->mti_svname, "-osc");
	else
		RETURN(-EINVAL);

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


	/* Add OST/MDT failover nids to the MDT logs as well */
	for_each_set_bit(i, fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE) {
		/* No osp device fsname-MDTXXXX-osp-MDTXXXX in conf*/
		if (mti->mti_flags & LDD_F_SV_TYPE_MDT
		    && mti->mti_stripe_index == i)
			continue;

		rc = name_create_mdt(&logname, mti->mti_fsname, i);
		if (rc)
			RETURN(rc);

		if (mgs_log_is_empty(env, mgs, logname)) {
			name_destroy(&logname);
			continue;
		}

		rc = name_create_osp(&cliname, NULL, mti->mti_svname, i);
		if (rc) {
			name_destroy(&logname);
			RETURN(rc);
		}
		rc = mgs_write_log_failnid_internal(env, mgs, fsdb, mti,
						    logname, cliname);
		name_destroy(&cliname);
		name_destroy(&logname);
		if (rc)
			RETURN(rc);
	}

	RETURN(rc);
}

static int mgs_wlp_lcfg(const struct lu_env *env,
			struct mgs_device *mgs, struct fs_db *fsdb,
			struct mgs_target_info *mti,
			char *logname, struct lustre_cfg_bufs *bufs,
			char *tgtname, char *ptr, bool del)
{
	struct llog_cfg_rec *lcr;
	char *comment;
	int rc, len;

	/* erase any old settings of this same parameter */
	rc = mgs_modify_param(env, mgs, fsdb, mti, logname, tgtname, ptr, del);
	/* nothing to do */
	if (rc == -EEXIST)
		return 0;
	if (rc < 0)
		return rc;

	LCONSOLE_INFO("%s parameter %s.%s in log %s\n", del ? "Disabling" : rc ?
		      "Setting" : "Modifying", tgtname, ptr, logname);
	if (del)
		return 0;

	lustre_cfg_bufs_reset(bufs, tgtname);
	lustre_cfg_bufs_set_string(bufs, 1, ptr);
	if (mti->mti_flags & LDD_F_PARAM2)
		lustre_cfg_bufs_set_string(bufs, 2, LCTL_UPCALL);

	lcr = lustre_cfg_rec_new((mti->mti_flags & LDD_F_PARAM2) ?
				 LCFG_SET_PARAM : LCFG_PARAM, bufs);
	if (lcr == NULL)
		return -ENOMEM;

	len = strcspn(ptr, "=");
	comment = kstrndup(ptr, len, GFP_KERNEL);
	if (!comment)
		GOTO(out, rc = -ENOMEM);

	rc = mgs_write_log_direct(env, mgs, fsdb, logname, lcr, tgtname,
				  comment);
	kfree(comment);

out:
	lustre_cfg_rec_free(lcr);

	return rc;
}

/* write global variable settings into log */
static int mgs_write_log_sys(const struct lu_env *env,
			     struct mgs_device *mgs, struct fs_db *fsdb,
			     struct mgs_target_info *mti, char *sys, char *ptr)
{
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct lustre_cfg	*lcfg;
	struct llog_cfg_rec	*lcr;
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
	lcr = lustre_cfg_rec_new(cmd, &mgi->mgi_bufs);
	if (lcr == NULL)
		return -ENOMEM;

	lcfg = &lcr->lcr_cfg;
	if (convert) {
		rc = kstrtouint(tmp, 0, &lcfg->lcfg_num);
		if (rc)
			GOTO(out_rec_free, rc);
	} else {
		lcfg->lcfg_num = 0;
	}

	/* truncate the comment to the parameter name */
	ptr = tmp - 1;
	sep = *ptr;
	*ptr = '\0';
	/* modify all servers and clients */
	rc = mgs_write_log_direct_all(env, mgs, fsdb, mti,
				      *tmp == '\0' ? NULL : lcr,
				      mti->mti_fsname, sys, 0);
	if (rc == 0 && *tmp != '\0') {
		switch (cmd) {
		case LCFG_SET_TIMEOUT:
			if (!obd_timeout_set || lcfg->lcfg_num > obd_timeout)
				class_process_config(lcfg, &lustre_kset->kobj);
			break;
		case LCFG_SET_LDLM_TIMEOUT:
			if (!ldlm_timeout_set || lcfg->lcfg_num > ldlm_timeout)
				class_process_config(lcfg, &lustre_kset->kobj);
			break;
		default:
			break;
		}
	}
	*ptr = sep;
out_rec_free:
	lustre_cfg_rec_free(lcr);
	return rc;
}

/* write quota settings into log */
static int mgs_write_log_quota(const struct lu_env *env, struct mgs_device *mgs,
			       struct fs_db *fsdb, struct mgs_target_info *mti,
			       char *quota, char *ptr)
{
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct llog_cfg_rec	*lcr;
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
		    strchr(tmp, 'p') == NULL &&
		    strcmp(tmp, "none") != 0) {
			CERROR("enable option(%s) isn't supported\n", tmp);
			return -EINVAL;
		}
	}

	lustre_cfg_bufs_reset(&mgi->mgi_bufs, mti->mti_fsname);
	lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 1, quota);
	lcr = lustre_cfg_rec_new(cmd, &mgi->mgi_bufs);
	if (lcr == NULL)
		return -ENOMEM;

	/* truncate the comment to the parameter name */
	ptr = tmp - 1;
	sep = *ptr;
	*ptr = '\0';

	/* XXX we duplicated quota enable information in all server
	 *     config logs, it should be moved to a separate config
	 *     log once we cleanup the config log for global param. */
	/* modify all servers */
	rc = mgs_write_log_direct_all(env, mgs, fsdb, mti,
				      *tmp == '\0' ? NULL : lcr,
				      mti->mti_fsname, quota, 1);
	*ptr = sep;
	lustre_cfg_rec_free(lcr);
	return rc < 0 ? rc : 0;
}

static int mgs_srpc_set_param_disk(const struct lu_env *env,
				   struct mgs_device *mgs,
				   struct fs_db *fsdb,
				   struct mgs_target_info *mti,
				   char *param)
{
	struct mgs_thread_info	*mgi = mgs_env_info(env);
	struct llog_cfg_rec	*lcr;
	struct llog_handle	*llh = NULL;
	char			*logname;
	char			*comment, *ptr;
	int			 rc, len;

	ENTRY;

	/* get comment */
	ptr = strchr(param, '=');
	LASSERT(ptr != NULL);
	len = ptr - param;

	OBD_ALLOC(comment, len + 1);
	if (comment == NULL)
		RETURN(-ENOMEM);
	strncpy(comment, param, len);
	comment[len] = '\0';

	/* prepare lcfg */
	lustre_cfg_bufs_reset(&mgi->mgi_bufs, mti->mti_svname);
	lustre_cfg_bufs_set_string(&mgi->mgi_bufs, 1, param);
	lcr = lustre_cfg_rec_new(LCFG_SPTLRPC_CONF, &mgi->mgi_bufs);
	if (lcr == NULL)
		GOTO(out_comment, rc = -ENOMEM);

	/* construct log name */
	rc = name_create(&logname, mti->mti_fsname, "-sptlrpc");
	if (rc < 0)
		GOTO(out_lcfg, rc);

	if (mgs_log_is_empty(env, mgs, logname)) {
		rc = record_start_log(env, mgs, &llh, logname);
		if (rc < 0)
			GOTO(out, rc);
		record_end_log(env, &llh);
	}

	/* obsolete old one */
	rc = mgs_modify(env, mgs, fsdb, mti, logname, mti->mti_svname,
			comment, CM_SKIP);
	if (rc < 0)
		GOTO(out, rc);
	/* write the new one */
	rc = mgs_write_log_direct(env, mgs, fsdb, logname, lcr,
				  mti->mti_svname, comment);
	if (rc)
		CERROR("%s: error writing log %s: rc = %d\n",
		       mgs->mgs_obd->obd_name, logname, rc);
out:
	name_destroy(&logname);
out_lcfg:
	lustre_cfg_rec_free(lcr);
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
	 * it simply remove the following line
	 */
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
	struct sptlrpc_rule rule;
	struct sptlrpc_rule_set *rset;
	int rc;

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

	/* prepare room for this coming rule. svcname format should be:
	 * - fsname: general rule
	 * - fsname-tgtname: target-specific rule
	 */
	if (strchr(svname, '-')) {
		struct mgs_tgt_srpc_conf *tgtconf;
		int found = 0;

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
	} else if (strcmp(svname, MGSSELF_NAME) == 0) {
		/* put _mgs related srpc rule directly in mgs ruleset */
		rset = &fsdb->fsdb_mgs->mgs_lut.lut_sptlrpc_rset;
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
	char *copy;
	int rc, copy_size;

	ENTRY;
#ifndef HAVE_GSS
	RETURN(-EINVAL);
#endif
	/* keep a copy of original param, which could be destroyed
	 * during parsing
	 */
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
	int		msrd_skip;
};

static int mgs_srpc_read_handler(const struct lu_env *env,
				 struct llog_handle *llh,
				 struct llog_rec_hdr *rec, void *data)
{
	struct mgs_srpc_read_data *msrd = data;
	struct cfg_marker *marker;
	struct lustre_cfg *lcfg = REC_DATA(rec);
	char *svname, *param;
	int rc;

	ENTRY;
	if (rec->lrh_type != OBD_CFG_REC) {
		CERROR("unhandled lrh_type: %#x\n", rec->lrh_type);
		RETURN(-EINVAL);
	}

	rc = lustre_cfg_sanity_check(lcfg, REC_DATA_LEN(rec));
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
	struct llog_handle	*llh = NULL;
	struct llog_ctxt	*ctxt;
	char			*logname;
	struct mgs_srpc_read_data  msrd;
	int			rc;

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

static int mgs_write_log_param2(const struct lu_env *env,
				struct mgs_device *mgs,
				struct fs_db *fsdb,
				struct mgs_target_info *mti,
				char *ptr, bool del)
{
	struct lustre_cfg_bufs bufs;
	int rc;

	ENTRY;
	CDEBUG(D_MGS, "next param '%s'\n", ptr);

	/* PARAM_MGSNODE and PARAM_NETWORK are set only when formating
	 * or during the inital mount. It can never change after that.
	 */
	if (!class_match_param(ptr, PARAM_MGSNODE, NULL) ||
	    !class_match_param(ptr, PARAM_NETWORK, NULL)) {
		rc = 0;
		goto end;
	}

	/* Processed in mgs_write_log_ost. Another value that can't
	 * be changed by lctl set_param -P.
	 */
	if (!class_match_param(ptr, PARAM_FAILMODE, NULL)) {
		LCONSOLE_ERROR("%s can only be changed with tunefs.lustre and --writeconf\n",
			       ptr);
		rc = -EPERM;
		goto end;
	}

	/* FIXME !!! Support for sptlrpc is incomplete. Currently the change
	 * doesn't transmit to the client. See LU-7183.
	 */
	if (!class_match_param(ptr, PARAM_SRPC, NULL)) {
		if (del)
			mgs_param_del_value(ptr);

		rc = mgs_srpc_set_param(env, mgs, fsdb, mti, ptr);
		goto end;
	}

	/* Can't use class_match_param since ptr doesn't start with
	 * PARAM_FAILNODE. So we look for PARAM_FAILNODE contained in ptr.
	 */
	if (strstr(ptr, PARAM_FAILNODE)) {
		/* Add a failover nidlist. We already processed failovers
		 * params for new targets in mgs_write_log_target.
		 */
		const char *param;

		if (del)
			mgs_param_del_value(ptr);

		/* can't use wildcards with failover.node */
		if (strchr(ptr, '*')) {
			rc = -ENODEV;
			goto end;
		}

		param = strstr(ptr, PARAM_FAILNODE);
		rc = strscpy(mti->mti_params, param, sizeof(mti->mti_params));
		if (rc < 0)
			goto end;

		CDEBUG(D_MGS, "Adding failnode with param %s\n",
		       mti->mti_params);
		rc = mgs_write_log_add_failnid(env, mgs, fsdb, mti);
		goto end;
	}

	/* root squash parameters must not be set on llite subsystem, this can
	 * lead to inconsistencies between client and server values
	 */
	if ((strstr(ptr, PARAM_NOSQUASHNIDS) ||
	     strstr(ptr, PARAM_ROOTSQUASH)) &&
	    strncmp(ptr, "llite.", strlen("llite.")) == 0) {
		rc = -EINVAL;
		CWARN("%s: cannot add %s param to llite subsystem, use mdt instead: rc=%d\n",
		      mgs->mgs_obd->obd_name,
		      strstr(ptr, PARAM_ROOTSQUASH) ?
			PARAM_ROOTSQUASH : PARAM_NOSQUASHNIDS,
		      rc);
		goto end;
	}

	rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, PARAMS_FILENAME, &bufs,
			  mti->mti_svname, ptr, del);
end:
	RETURN(rc);
}

/* Permanent settings of all parameters by writing into the appropriate
 * configuration logs.
 * A parameter with null value ("<param>='\0'") means to erase it out of
 * the logs.
 */
static int mgs_write_log_param(const struct lu_env *env,
			       struct mgs_device *mgs, struct fs_db *fsdb,
			       struct mgs_target_info *mti, char *ptr, bool del)
{
	struct mgs_thread_info *mgi = mgs_env_info(env);
	char *logname;
	char *tmp;
	int rc = 0;
	ENTRY;

	/* For various parameter settings, we have to figure out which logs
	 * care about them (e.g. both mdt and client for lov settings)
	 */
	CDEBUG(D_MGS, "next param '%s'\n", ptr);

	/* The params are stored in MOUNT_DATA_FILE and modified via
	 * tunefs.lustre, or set using lctl conf_param
	 */

	/* Processed in lustre_start_mgc */
	if (class_match_param(ptr, PARAM_MGSNODE, NULL) == 0)
		GOTO(end, rc);

	/* Processed in ost/mdt */
	if (class_match_param(ptr, PARAM_NETWORK, NULL) == 0)
		GOTO(end, rc);

	/* Processed in mgs_write_log_ost */
	if (class_match_param(ptr, PARAM_FAILMODE, NULL) == 0) {
		if (mti->mti_flags & LDD_F_PARAM) {
			LCONSOLE_ERROR("%s can only be changed with tunefs.lustre and --writeconf\n",
				       ptr);
			rc = -EPERM;
		}
		GOTO(end, rc);
	}

	if (class_match_param(ptr, PARAM_SRPC, NULL) == 0) {
		if (del)
			mgs_param_del_value(ptr);

		rc = mgs_srpc_set_param(env, mgs, fsdb, mti, ptr);
		GOTO(end, rc);
	}

	if (class_match_param(ptr, PARAM_FAILNODE, NULL) == 0) {
		/* Add a failover nidlist */
		rc = 0;
		/* We already processed failovers params for new
		 * targets in mgs_write_log_target
		 */
		if (mti->mti_flags & LDD_F_PARAM) {
			CDEBUG(D_MGS, "Adding failnode\n");
			if (del)
				mgs_param_del_value(ptr);

			rc = mgs_write_log_add_failnid(env, mgs, fsdb, mti);
		}
		GOTO(end, rc);
	}

	if (class_match_param(ptr, PARAM_SYS, &tmp) == 0) {
		if (del)
			mgs_param_del_value(ptr);

		rc = mgs_write_log_sys(env, mgs, fsdb, mti, ptr, tmp);
		GOTO(end, rc);
	}

	if (class_match_param(ptr, PARAM_QUOTA, &tmp) == 0) {
		if (del)
			mgs_param_del_value(ptr);

		rc = mgs_write_log_quota(env, mgs, fsdb, mti, ptr, tmp);
		GOTO(end, rc);
	}

	if (class_match_param(ptr, PARAM_OSC PARAM_ACTIVE, &tmp) == 0 ||
	    class_match_param(ptr, PARAM_MDC PARAM_ACTIVE, &tmp) == 0) {
		/* active=0 means off, anything else means on */
		int flag = (*tmp == '0' || del) ? CM_EXCLUDE : 0;
		bool deactive_osc = memcmp(ptr, PARAM_OSC PARAM_ACTIVE,
					   strlen(PARAM_OSC PARAM_ACTIVE)) == 0;
		int i;

		if (!deactive_osc) {
			__u32	index;

			rc = server_name2index(mti->mti_svname, &index, NULL);
			if (rc < 0)
				GOTO(end, rc);

			if (index == 0) {
				LCONSOLE_ERROR("%s: MDC0 can not be (de)activated.\n",
					       mti->mti_svname);
				GOTO(end, rc = -EPERM);
			}
		}

		LCONSOLE_WARN("Permanently %sactivating %s\n",
			      flag ? "de" : "re", mti->mti_svname);
		/* Modify clilov */
		rc = name_create(&logname, mti->mti_fsname, "-client");
		if (rc < 0)
			GOTO(end, rc);
		rc = mgs_modify(env, mgs, fsdb, mti, logname,
				mti->mti_svname,
				deactive_osc ? "add osc" : "add mdc", flag);
		name_destroy(&logname);
		if (rc < 0)
			goto active_err;

		/* Modify mdtlov */
		/* Add to all MDT logs for DNE */
		for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
			if (!test_bit(i, fsdb->fsdb_mdt_index_map))
				continue;
			rc = name_create_mdt(&logname, mti->mti_fsname, i);
			if (rc < 0)
				GOTO(end, rc);
			rc = mgs_modify(env, mgs, fsdb, mti, logname,
					mti->mti_svname,
					deactive_osc ? "add osc" : "add osp",
					flag);
			name_destroy(&logname);
			if (rc < 0)
				goto active_err;
		}
active_err:
		if (rc < 0) {
			LCONSOLE_ERROR("Couldn't find %s in log (%d). No permanent changes were made to the config log.\n",
				       mti->mti_svname, rc);
			if (test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags))
				LCONSOLE_ERROR("This may be because the log is in the old 1.4 style. Consider --writeconf to update the logs.\n");
			GOTO(end, rc);
		}
		/* Fall through to osc/mdc proc for deactivating live
		 * OSC/OSP on running MDT / clients.
		 */
	}
	/* Below here, let obd's XXX_process_config methods handle it */

	/* All lov. in proc */
	if (class_match_param(ptr, PARAM_LOV, NULL) == 0) {
		char *mdtlovname;

		CDEBUG(D_MGS, "lov param %s\n", ptr);
		if (!(mti->mti_flags & LDD_F_SV_TYPE_MDT)) {
			LCONSOLE_ERROR("LOV params must be set on the MDT, not %s. Ignoring.\n",
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
				  &mgi->mgi_bufs, mdtlovname, ptr, del);
		name_destroy(&logname);
		name_destroy(&mdtlovname);
		if (rc)
			GOTO(end, rc);

		/* Modify clilov */
		rc = name_create(&logname, mti->mti_fsname, "-client");
		if (rc)
			GOTO(end, rc);
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname, &mgi->mgi_bufs,
				  fsdb->fsdb_clilov, ptr, del);
		name_destroy(&logname);
		GOTO(end, rc);
	}

	/* All osc., mdc., llite. params in proc */
	if ((class_match_param(ptr, PARAM_OSC, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_MDC, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_LLITE, NULL) == 0)) {
		char *cname;

		if (test_bit(FSDB_OLDLOG14, &fsdb->fsdb_flags)) {
			LCONSOLE_ERROR("Upgraded client logs for %s cannot be modified. Consider updating the configuration with --writeconf\n",
				       mti->mti_svname);
			GOTO(end, rc = -EINVAL);
		}
		if (memcmp(ptr, PARAM_LLITE, strlen(PARAM_LLITE)) == 0) {
			rc = name_create(&cname, mti->mti_fsname, "-client");
			/* Add the client type to match the obdname in
			 * class_config_llog_handler
			 */
		} else if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
			rc = name_create(&cname, mti->mti_svname, "-mdc");
		} else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
			rc = name_create(&cname, mti->mti_svname, "-osc");
		} else {
			GOTO(end, rc = -EINVAL);
		}
		if (rc)
			GOTO(end, rc);

		/* Forbid direct update of llite root squash parameters.
		 * These parameters are indirectly set via the MDT settings.
		 * See (LU-1778) */
		if ((class_match_param(ptr, PARAM_LLITE, &tmp) == 0) &&
		    ((memcmp(tmp, "root_squash=", 12) == 0) ||
		     (memcmp(tmp, "nosquash_nids=", 14) == 0))) {
			LCONSOLE_ERROR("%s: root squash parameters can only "
				"be updated through MDT component\n",
				mti->mti_fsname);
			name_destroy(&cname);
			GOTO(end, rc = -EINVAL);
		}

		CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);

		/* Modify client */
		rc = name_create(&logname, mti->mti_fsname, "-client");
		if (rc) {
			name_destroy(&cname);
			GOTO(end, rc);
		}
		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname, &mgi->mgi_bufs,
				  cname, ptr, del);

		/* osc params affect the MDT as well */
		if (!rc && (mti->mti_flags & LDD_F_SV_TYPE_OST)) {
			int i;

			for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
				if (!test_bit(i, fsdb->fsdb_mdt_index_map))
					continue;
				name_destroy(&cname);
				rc = name_create_osp(&cname, NULL,
						     mti->mti_svname, i);
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
							  cname, ptr, del);
					if (rc)
						break;
				}
			}
		}

		/* For mdc activate/deactivate, it affects OSP on MDT as well */
		if (class_match_param(ptr, PARAM_MDC PARAM_ACTIVE, &tmp) == 0 &&
		    rc == 0) {
			char suffix[16];
			char *lodname = NULL;
			char *param_str = NULL;
			int i;
			int index;

			/* replace mdc with osp */
			memcpy(ptr, PARAM_OSP, strlen(PARAM_OSP));
			rc = server_name2index(mti->mti_svname, &index, NULL);
			if (rc < 0) {
				memcpy(ptr, PARAM_MDC, strlen(PARAM_MDC));
				GOTO(end, rc);
			}

			for (i = 0; i < INDEX_MAP_SIZE * 8; i++) {
				if (!test_bit(i, fsdb->fsdb_mdt_index_map))
					continue;

				if (i == index)
					continue;

				name_destroy(&logname);
				rc = name_create_mdt(&logname, mti->mti_fsname,
						     i);
				if (rc < 0)
					break;

				if (mgs_log_is_empty(env, mgs, logname))
					continue;

				snprintf(suffix, sizeof(suffix), "-osp-MDT%04x",
					 i);
				name_destroy(&cname);
				rc = name_create(&cname, mti->mti_svname,
						 suffix);
				if (rc < 0)
					break;

				rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname,
						  &mgi->mgi_bufs, cname,
						  ptr, del);
				if (rc < 0)
					break;

				/* Add configuration log for noitfying LOD
				 * to active/deactive the OSP. */
				name_destroy(&param_str);
				rc = name_create(&param_str, cname,
						 (*tmp == '0') ?  ".active=0" :
						 ".active=1");
				if (rc < 0)
					break;

				name_destroy(&lodname);
				rc = name_create(&lodname, logname, "-mdtlov");
				if (rc < 0)
					break;

				rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname,
						  &mgi->mgi_bufs, lodname,
						  param_str, del);
				if (rc < 0)
					break;
			}
			memcpy(ptr, PARAM_MDC, strlen(PARAM_MDC));
			name_destroy(&lodname);
			name_destroy(&param_str);
		}

		name_destroy(&logname);
		name_destroy(&cname);
		GOTO(end, rc);
	}

	/* All mdt. params in proc */
	if (class_match_param(ptr, PARAM_MDT, &tmp) == 0) {
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
						  logname, ptr, del);
				name_destroy(&logname);
				if (rc)
					goto active_err;
			}
		} else {
			if ((memcmp(tmp, "root_squash=", 12) == 0) ||
			    (memcmp(tmp, "nosquash_nids=", 14) == 0)) {
				LCONSOLE_ERROR("%s: root squash parameters "
					"cannot be applied to a single MDT\n",
					mti->mti_fsname);
				GOTO(end, rc = -EINVAL);
			}
			rc = mgs_wlp_lcfg(env, mgs, fsdb, mti,
					  mti->mti_svname, &mgi->mgi_bufs,
					  mti->mti_svname, ptr, del);
			if (rc)
				goto active_err;
		}

		/* root squash settings are also applied to llite
		 * config log (see LU-1778) */
		if (rc == 0 &&
		    ((memcmp(tmp, "root_squash=", 12) == 0) ||
		     (memcmp(tmp, "nosquash_nids=", 14) == 0))) {
			char *cname;
			char *ptr2;

			rc = name_create(&cname, mti->mti_fsname, "-client");
			if (rc)
				GOTO(end, rc);
			rc = name_create(&logname, mti->mti_fsname, "-client");
			if (rc) {
				name_destroy(&cname);
				GOTO(end, rc);
			}
			rc = name_create(&ptr2, PARAM_LLITE, tmp);
			if (rc) {
				name_destroy(&cname);
				name_destroy(&logname);
				GOTO(end, rc);
			}
			rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, logname,
					  &mgi->mgi_bufs, cname, ptr2, del);
			name_destroy(&ptr2);
			name_destroy(&logname);
			name_destroy(&cname);
		}
		GOTO(end, rc);
	}

	/* All mdd., ost. and osd. params in proc */
	if ((class_match_param(ptr, PARAM_MDD, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_LOD, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_OST, NULL) == 0) ||
	    (class_match_param(ptr, PARAM_OSD, NULL) == 0)) {
		CDEBUG(D_MGS, "%.3s param %s\n", ptr, ptr + 4);
		if (mgs_log_is_empty(env, mgs, mti->mti_svname))
			GOTO(end, rc = -ENODEV);

		rc = mgs_wlp_lcfg(env, mgs, fsdb, mti, mti->mti_svname,
				  &mgi->mgi_bufs, mti->mti_svname, ptr, del);
		GOTO(end, rc);
	}

	/* For handling degraded zfs OST */
	if (class_match_param(ptr, PARAM_AUTODEGRADE, NULL) == 0)
		GOTO(end, rc);

	LCONSOLE_WARN("Ignoring unrecognized param '%s'\n", ptr);

end:
	if (rc)
		CERROR("err %d on param '%s'\n", rc, ptr);

	RETURN(rc);
}

int mgs_write_log_target(const struct lu_env *env, struct mgs_device *mgs,
			 struct mgs_target_info *mti, struct fs_db *fsdb)
{
	char	*buf, *params;
	int	 rc = -EINVAL;

	ENTRY;

	/* set/check the new target index */
	rc = mgs_set_index(env, mgs, mti);
	if (rc < 0)
		RETURN(rc);

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

	CFS_FAIL_TIMEOUT(OBD_FAIL_MGS_WRITE_TARGET_DELAY, cfs_fail_val > 0 ?
			 cfs_fail_val : 10);

	mutex_lock(&fsdb->fsdb_mutex);

	if (mti->mti_flags & (LDD_F_VIRGIN | LDD_F_WRITECONF)) {
		/* Generate a log from scratch */
		if (mti->mti_flags & LDD_F_SV_TYPE_MDT) {
			rc = mgs_write_log_mdt(env, mgs, fsdb, mti);
		} else if (mti->mti_flags & LDD_F_SV_TYPE_OST) {
			rc = mgs_write_log_ost(env, mgs, fsdb, mti);
		} else {
			CERROR("Unknown target type %#x, can't create log for %s\n",
			       mti->mti_flags, mti->mti_svname);
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
	 * make copy of a current  parameter
	 */
	OBD_ALLOC(buf, strlen(mti->mti_params) + 1);
	if (buf == NULL)
		GOTO(out_up, rc = -ENOMEM);
	params = mti->mti_params;
	while (params != NULL) {
		rc = class_get_next_param(&params, buf);
		if (rc) {
			if (rc == 1)
				/* there is no next parameter, that is
				 * not an error
				 */
				rc = 0;
			break;
		}
		CDEBUG(D_MGS, "remaining string: '%s', param: '%s'\n",
		       params, buf);
		rc = mgs_write_log_param(env, mgs, fsdb, mti, buf, false);
		if (rc == -EEXIST)
			rc = 0;
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
int mgs_erase_logs(const struct lu_env *env, struct mgs_device *mgs,
		   const char *fsname)
{
	struct list_head log_list;
	struct mgs_direntry *dirent, *n;
	char barrier_name[20] = {};
	char *suffix;
	int count = 0;
	int rc, len = strlen(fsname);
	ENTRY;

	mutex_lock(&mgs->mgs_mutex);

	/* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &log_list);
	if (rc) {
		mutex_unlock(&mgs->mgs_mutex);
		RETURN(rc);
	}

	if (list_empty(&log_list)) {
		mutex_unlock(&mgs->mgs_mutex);
		RETURN(-ENOENT);
	}

	snprintf(barrier_name, sizeof(barrier_name) - 1, "%s-%s",
		 fsname, BARRIER_FILENAME);
	/* Delete the barrier fsdb */
	mgs_remove_fsdb_by_name(mgs, barrier_name);
	/* Delete the fs db */
	mgs_remove_fsdb_by_name(mgs, fsname);
	mutex_unlock(&mgs->mgs_mutex);

	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		list_del_init(&dirent->mde_list);
		suffix = strrchr(dirent->mde_name, '-');
		if (suffix != NULL) {
			if ((len == suffix - dirent->mde_name) &&
			    (strncmp(fsname, dirent->mde_name, len) == 0)) {
				CDEBUG(D_MGS, "Removing log %s\n",
				       dirent->mde_name);
				mgs_erase_log(env, mgs, dirent->mde_name);
				count++;
			}
		}
		mgs_direntry_free(dirent);
	}

	if (count == 0)
		rc = -ENOENT;

	RETURN(rc);
}

/* list all logs for the given fs */
int mgs_list_logs(const struct lu_env *env, struct mgs_device *mgs,
		  struct obd_ioctl_data *data)
{
	struct list_head	 log_list;
	struct mgs_direntry	*dirent, *n;
	char			*out, *suffix, prefix[] = "config_log: ";
	int			 prefix_len = strlen(prefix);
	int			 len, remains, start = 0, rc;

	ENTRY;

	/* Find all the logs in the CONFIGS directory */
	rc = class_dentry_readdir(env, mgs, &log_list);
	if (rc)
		RETURN(rc);

	out = data->ioc_bulk;
	remains = data->ioc_inllen1;
	/* OBD_FAIL: fetch the config_log records from the specified one */
	if (CFS_FAIL_CHECK(OBD_FAIL_CATLIST))
		data->ioc_count = cfs_fail_val;

	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		list_del_init(&dirent->mde_list);
		suffix = strrchr(dirent->mde_name, '-');
		if (suffix != NULL) {
			len = prefix_len + dirent->mde_len + 1;
			if (remains - len < 0) {
				/* No enough space for this record */
				mgs_direntry_free(dirent);
				goto out;
			}
			start++;
			if (start < data->ioc_count) {
				mgs_direntry_free(dirent);
				continue;
			}
			len = scnprintf(out, remains, "%s%s\n", prefix,
					dirent->mde_name);
			out += len;
			remains -= len;
		}
		mgs_direntry_free(dirent);
		if (remains <= 1)
			/* Full */
			goto out;
	}
	/* Finished */
	start = 0;
out:
	data->ioc_count = start;
	RETURN(rc);
}

struct mgs_lcfg_fork_data {
	struct lustre_cfg_bufs	 mlfd_bufs;
	struct mgs_device	*mlfd_mgs;
	struct llog_handle	*mlfd_llh;
	const char		*mlfd_oldname;
	const char		*mlfd_newname;
	char			 mlfd_data[];
};

static bool contain_valid_fsname(char *buf, const char *fsname,
				 size_t buflen, size_t namelen)
{
	if (buflen < namelen)
		return false;

	if (memcmp(buf, fsname, namelen) != 0)
		return false;

	if (buf[namelen] != '\0' && buf[namelen] != '-')
		return false;

	return true;
}

static int mgs_lcfg_fork_handler(const struct lu_env *env,
				 struct llog_handle *o_llh,
				 struct llog_rec_hdr *o_rec, void *data)
{
	struct mgs_lcfg_fork_data *mlfd = data;
	struct lustre_cfg_bufs *n_bufs = &mlfd->mlfd_bufs;
	struct lustre_cfg *o_lcfg = (struct lustre_cfg *)(o_rec + 1);
	struct llog_cfg_rec *lcr;
	char *o_buf;
	char *n_buf = mlfd->mlfd_data;
	int o_buflen;
	int o_namelen = strlen(mlfd->mlfd_oldname);
	int n_namelen = strlen(mlfd->mlfd_newname);
	int diff = n_namelen - o_namelen;
	__u32 cmd = o_lcfg->lcfg_command;
	__u32 cnt = o_lcfg->lcfg_bufcount;
	int rc;
	int i;
	ENTRY;

	/* buf[0] */
	o_buf = lustre_cfg_buf(o_lcfg, 0);
	o_buflen = o_lcfg->lcfg_buflens[0];
	if (contain_valid_fsname(o_buf, mlfd->mlfd_oldname, o_buflen,
				 o_namelen)) {
		memcpy(n_buf, mlfd->mlfd_newname, n_namelen);
		memcpy(n_buf + n_namelen, o_buf + o_namelen,
		       o_buflen - o_namelen);
		lustre_cfg_bufs_reset(n_bufs, n_buf);
		n_buf += round_up(o_buflen + diff, 8);
	} else {
		lustre_cfg_bufs_reset(n_bufs, o_buflen != 0 ? o_buf : NULL);
	}

	switch (cmd) {
	case LCFG_MARKER: {
		struct cfg_marker *o_marker;
		struct cfg_marker *n_marker;
		int tgt_namelen;

		if (cnt != 2) {
			CDEBUG(D_MGS, "Unknown cfg marker entry with %d "
			       "buffers\n", cnt);
			RETURN(-EINVAL);
		}

		/* buf[1] is marker */
		o_buf = lustre_cfg_buf(o_lcfg, 1);
		o_buflen = o_lcfg->lcfg_buflens[1];
		o_marker = (struct cfg_marker *)o_buf;
		if (!contain_valid_fsname(o_marker->cm_tgtname,
					  mlfd->mlfd_oldname,
					  sizeof(o_marker->cm_tgtname),
					  o_namelen)) {
			lustre_cfg_bufs_set(n_bufs, 1, o_marker,
					    sizeof(*o_marker));
			break;
		}

		n_marker = (struct cfg_marker *)n_buf;
		*n_marker = *o_marker;
		memcpy(n_marker->cm_tgtname, mlfd->mlfd_newname, n_namelen);
		tgt_namelen = strlen(o_marker->cm_tgtname);
		if (tgt_namelen > o_namelen)
			memcpy(n_marker->cm_tgtname + n_namelen,
			       o_marker->cm_tgtname + o_namelen,
			       tgt_namelen - o_namelen);
		n_marker->cm_tgtname[tgt_namelen + diff] = '\0';
		lustre_cfg_bufs_set(n_bufs, 1, n_marker, sizeof(*n_marker));
		break;
	}
	case LCFG_PARAM:
	case LCFG_SET_PARAM: {
		for (i = 1; i < cnt; i++)
			/* buf[i] is the param value, reuse it directly */
			lustre_cfg_bufs_set(n_bufs, i,
					    lustre_cfg_buf(o_lcfg, i),
					    o_lcfg->lcfg_buflens[i]);
		break;
	}
	case LCFG_POOL_NEW:
	case LCFG_POOL_ADD:
	case LCFG_POOL_REM:
	case LCFG_POOL_DEL: {
		if (cnt < 3 || cnt > 4) {
			CDEBUG(D_MGS, "Unknown cfg pool (%x) entry with %d "
			       "buffers\n", cmd, cnt);
			RETURN(-EINVAL);
		}

		/* buf[1] is fsname */
		o_buf = lustre_cfg_buf(o_lcfg, 1);
		o_buflen = o_lcfg->lcfg_buflens[1];
		memcpy(n_buf, mlfd->mlfd_newname, n_namelen);
		memcpy(n_buf + n_namelen, o_buf + o_namelen,
		       o_buflen - o_namelen);
		lustre_cfg_bufs_set(n_bufs, 1, n_buf, o_buflen + diff);
		n_buf += round_up(o_buflen + diff, 8);

		/* buf[2] is the pool name, reuse it directly */
		lustre_cfg_bufs_set(n_bufs, 2, lustre_cfg_buf(o_lcfg, 2),
				    o_lcfg->lcfg_buflens[2]);

		if (cnt == 3)
			break;

		/* buf[3] is ostname */
		o_buf = lustre_cfg_buf(o_lcfg, 3);
		o_buflen = o_lcfg->lcfg_buflens[3];
		memcpy(n_buf, mlfd->mlfd_newname, n_namelen);
		memcpy(n_buf + n_namelen, o_buf + o_namelen,
		       o_buflen - o_namelen);
		lustre_cfg_bufs_set(n_bufs, 3, n_buf, o_buflen + diff);
		break;
	}
	case LCFG_SETUP: {
		if (cnt == 2) {
			o_buflen = o_lcfg->lcfg_buflens[1];
			if (o_buflen == sizeof(struct lov_desc) ||
			    o_buflen == sizeof(struct lmv_desc)) {
				char *o_uuid;
				char *n_uuid;
				int uuid_len;

				/* buf[1] */
				o_buf = lustre_cfg_buf(o_lcfg, 1);
				if (o_buflen == sizeof(struct lov_desc)) {
					struct lov_desc *o_desc =
						(struct lov_desc *)o_buf;
					struct lov_desc *n_desc =
						(struct lov_desc *)n_buf;

					*n_desc = *o_desc;
					o_uuid = o_desc->ld_uuid.uuid;
					n_uuid = n_desc->ld_uuid.uuid;
					uuid_len = sizeof(o_desc->ld_uuid.uuid);
				} else {
					struct lmv_desc *o_desc =
						(struct lmv_desc *)o_buf;
					struct lmv_desc *n_desc =
						(struct lmv_desc *)n_buf;

					*n_desc = *o_desc;
					o_uuid = o_desc->ld_uuid.uuid;
					n_uuid = n_desc->ld_uuid.uuid;
					uuid_len = sizeof(o_desc->ld_uuid.uuid);
				}

				if (unlikely(!contain_valid_fsname(o_uuid,
						mlfd->mlfd_oldname, uuid_len,
						o_namelen))) {
					lustre_cfg_bufs_set(n_bufs, 1, o_buf,
							    o_buflen);
					break;
				}

				memcpy(n_uuid, mlfd->mlfd_newname, n_namelen);
				uuid_len = strlen(o_uuid);
				if (uuid_len > o_namelen)
					memcpy(n_uuid + n_namelen,
					       o_uuid + o_namelen,
					       uuid_len - o_namelen);
				n_uuid[uuid_len + diff] = '\0';
				lustre_cfg_bufs_set(n_bufs, 1, n_buf, o_buflen);
				break;
			} /* else case fall through */
		} /* else case fall through */
	}
	fallthrough;
	default: {
		for (i = 1; i < cnt; i++) {
			o_buflen = o_lcfg->lcfg_buflens[i];
			if (o_buflen == 0)
				continue;

			o_buf = lustre_cfg_buf(o_lcfg, i);
			if (!contain_valid_fsname(o_buf, mlfd->mlfd_oldname,
						  o_buflen, o_namelen)) {
				lustre_cfg_bufs_set(n_bufs, i, o_buf, o_buflen);
				continue;
			}

			memcpy(n_buf, mlfd->mlfd_newname, n_namelen);
			if (o_buflen == o_namelen) {
				lustre_cfg_bufs_set(n_bufs, i, n_buf,
						    n_namelen);
				n_buf += round_up(n_namelen, 8);
				continue;
			}

			memcpy(n_buf + n_namelen, o_buf + o_namelen,
			       o_buflen - o_namelen);
			lustre_cfg_bufs_set(n_bufs, i, n_buf, o_buflen + diff);
			n_buf += round_up(o_buflen + diff, 8);
		}
		break;
	}
	}

	lcr = lustre_cfg_rec_new(cmd, n_bufs);
	if (!lcr)
		RETURN(-ENOMEM);

	lcr->lcr_cfg = *o_lcfg;
	rc = llog_write(env, mlfd->mlfd_llh, &lcr->lcr_hdr, LLOG_NEXT_IDX);
	lustre_cfg_rec_free(lcr);

	RETURN(rc);
}

static int mgs_lcfg_fork_one(const struct lu_env *env, struct mgs_device *mgs,
			     struct mgs_direntry *mde, const char *oldname,
			     const char *newname)
{
	struct llog_handle *old_llh = NULL;
	struct llog_handle *new_llh = NULL;
	struct llog_ctxt *ctxt = NULL;
	struct mgs_lcfg_fork_data *mlfd = NULL;
	char *name_buf = NULL;
	int name_buflen;
	int old_namelen = strlen(oldname);
	int new_namelen = strlen(newname);
	int rc;
	ENTRY;

	name_buflen = mde->mde_len + new_namelen - old_namelen;
	OBD_ALLOC(name_buf, name_buflen);
	if (!name_buf)
		RETURN(-ENOMEM);

	memcpy(name_buf, newname, new_namelen);
	memcpy(name_buf + new_namelen, mde->mde_name + old_namelen,
	       mde->mde_len - old_namelen);

	CDEBUG(D_MGS, "Fork the config-log from %s to %s\n",
	       mde->mde_name, name_buf);

	ctxt = llog_get_context(mgs->mgs_obd, LLOG_CONFIG_ORIG_CTXT);
	LASSERT(ctxt);

	rc = llog_open_create(env, ctxt, &new_llh, NULL, name_buf);
	if (rc)
		GOTO(out, rc);

	rc = llog_init_handle(env, new_llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out, rc);

	if (unlikely(mgs_log_is_empty(env, mgs, mde->mde_name)))
		GOTO(out, rc = 0);

	rc = llog_open(env, ctxt, &old_llh, NULL, mde->mde_name,
		       LLOG_OPEN_EXISTS);
	if (rc)
		GOTO(out, rc);

	rc = llog_init_handle(env, old_llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(out, rc);

	new_llh->lgh_hdr->llh_tgtuuid = old_llh->lgh_hdr->llh_tgtuuid;

	OBD_ALLOC(mlfd, LLOG_MIN_CHUNK_SIZE);
	if (!mlfd)
		GOTO(out, rc = -ENOMEM);

	mlfd->mlfd_mgs = mgs;
	mlfd->mlfd_llh = new_llh;
	mlfd->mlfd_oldname = oldname;
	mlfd->mlfd_newname = newname;

	rc = llog_process(env, old_llh, mgs_lcfg_fork_handler, mlfd, NULL);
	OBD_FREE(mlfd, LLOG_MIN_CHUNK_SIZE);

	GOTO(out, rc);

out:
	if (old_llh)
		llog_close(env, old_llh);
	if (new_llh)
		llog_close(env, new_llh);
	OBD_FREE(name_buf, name_buflen);
	if (ctxt)
		llog_ctxt_put(ctxt);

	return rc;
}

int mgs_lcfg_fork(const struct lu_env *env, struct mgs_device *mgs,
		  const char *oldname, const char *newname)
{
	struct list_head log_list;
	struct mgs_direntry *dirent, *n;
	int olen = strlen(oldname);
	int nlen = strlen(newname);
	int count = 0;
	int rc = 0;
	ENTRY;

	if (unlikely(!oldname || oldname[0] == '\0' ||
		     !newname || newname[0] == '\0'))
		RETURN(-EINVAL);

	if (strcmp(oldname, newname) == 0)
		RETURN(-EINVAL);

	/* lock it to prevent fork/erase/register in parallel. */
	mutex_lock(&mgs->mgs_mutex);

	rc = class_dentry_readdir(env, mgs, &log_list);
	if (rc) {
		mutex_unlock(&mgs->mgs_mutex);
		RETURN(rc);
	}

	if (list_empty(&log_list)) {
		mutex_unlock(&mgs->mgs_mutex);
		RETURN(-ENOENT);
	}

	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		char *ptr;

		ptr = strrchr(dirent->mde_name, '-');
		if (ptr) {
			int tlen = ptr - dirent->mde_name;

			if (tlen == nlen &&
			    strncmp(newname, dirent->mde_name, tlen) == 0)
				GOTO(out, rc = -EEXIST);

			if (tlen == olen &&
			    strncmp(oldname, dirent->mde_name, tlen) == 0)
				continue;
		}

		list_del_init(&dirent->mde_list);
		mgs_direntry_free(dirent);
	}

	if (list_empty(&log_list)) {
		mutex_unlock(&mgs->mgs_mutex);
		RETURN(-ENOENT);
	}

	list_for_each_entry(dirent, &log_list, mde_list) {
		rc = mgs_lcfg_fork_one(env, mgs, dirent, oldname, newname);
		if (rc)
			break;

		count++;
	}

out:
	mutex_unlock(&mgs->mgs_mutex);

	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		list_del_init(&dirent->mde_list);
		mgs_direntry_free(dirent);
	}

	if (rc && count > 0)
		mgs_erase_logs(env, mgs, newname);

	RETURN(rc);
}

int mgs_lcfg_erase(const struct lu_env *env, struct mgs_device *mgs,
		   const char *fsname)
{
	int rc;
	ENTRY;

	if (unlikely(!fsname || fsname[0] == '\0'))
		RETURN(-EINVAL);

	rc = mgs_erase_logs(env, mgs, fsname);

	RETURN(rc);
}

static int mgs_xattr_del(const struct lu_env *env, struct dt_object *obj)
{
	struct dt_device *dev;
	struct thandle *th = NULL;
	int rc = 0;

	ENTRY;

	dev = container_of(obj->do_lu.lo_dev, struct dt_device, dd_lu_dev);
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_xattr_del(env, obj, XATTR_TARGET_RENAME, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	dt_write_lock(env, obj, 0);
	rc = dt_xattr_del(env, obj, XATTR_TARGET_RENAME, th);

	GOTO(unlock, rc);

unlock:
	dt_write_unlock(env, obj);

stop:
	dt_trans_stop(env, dev, th);

	return rc;
}

int mgs_lcfg_rename(const struct lu_env *env, struct mgs_device *mgs)
{
	struct list_head log_list;
	struct mgs_direntry *dirent, *n;
	char fsname[16];
	struct lu_buf buf = {
		.lb_buf = fsname,
		.lb_len = sizeof(fsname)
	};
	int rc = 0;

	ENTRY;

	rc = class_dentry_readdir(env, mgs, &log_list);
	if (rc)
		RETURN(rc);

	if (list_empty(&log_list))
		RETURN(0);

	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		struct dt_object *o = NULL;
		char oldname[16];
		char *ptr;
		int len;

		list_del_init(&dirent->mde_list);
		ptr = strrchr(dirent->mde_name, '-');
		if (!ptr)
			goto next;

		len = ptr - dirent->mde_name;
		if (unlikely(len >= sizeof(oldname))) {
			CDEBUG(D_MGS, "Skip invalid configuration file %s\n",
			       dirent->mde_name);
			goto next;
		}

		o = local_file_find(env, mgs->mgs_los, mgs->mgs_configs_dir,
				    dirent->mde_name);
		if (IS_ERR(o)) {
			rc = PTR_ERR(o);
			CDEBUG(D_MGS, "Fail to locate file %s: rc = %d\n",
			       dirent->mde_name, rc);
			goto next;
		}

		rc = dt_xattr_get(env, o, &buf, XATTR_TARGET_RENAME);
		if (rc < 0) {
			if (rc == -ENODATA)
				rc = 0;
			else
				CDEBUG(D_MGS,
				       "Fail to get EA for %s: rc = %d\n",
				       dirent->mde_name, rc);
			goto next;
		}

		if (unlikely(rc == len &&
			     memcmp(fsname, dirent->mde_name, len) == 0)) {
			/* The new fsname is the same as the old one. */
			rc = mgs_xattr_del(env, o);
			goto next;
		}

		memcpy(oldname, dirent->mde_name, len);
		oldname[len] = '\0';
		fsname[rc] = '\0';
		rc = mgs_lcfg_fork_one(env, mgs, dirent, oldname, fsname);
		if (rc && rc != -EEXIST) {
			CDEBUG(D_MGS, "Fail to fork %s: rc = %d\n",
			       dirent->mde_name, rc);
			goto next;
		}

		rc = mgs_erase_log(env, mgs, dirent->mde_name);
		if (rc) {
			CDEBUG(D_MGS, "Fail to erase old %s: rc = %d\n",
			       dirent->mde_name, rc);
			/* keep it there if failed to remove it. */
			rc = 0;
		}

next:
		if (o && !IS_ERR(o))
			lu_object_put(env, &o->do_lu);

		mgs_direntry_free(dirent);
		if (rc)
			break;
	}

	list_for_each_entry_safe(dirent, n, &log_list, mde_list) {
		list_del_init(&dirent->mde_list);
		mgs_direntry_free(dirent);
	}

	RETURN(rc);
}

/* Setup _mgs fsdb and log
 */
int mgs__mgs_fsdb_setup(const struct lu_env *env, struct mgs_device *mgs)
{
	struct fs_db *fsdb = NULL;
	int rc;
	ENTRY;

	rc = mgs_find_or_make_fsdb(env, mgs, MGSSELF_NAME, &fsdb);
	if (!rc)
		mgs_put_fsdb(mgs, fsdb);

	RETURN(rc);
}

/* Setup params fsdb and log
 */
int mgs_params_fsdb_setup(const struct lu_env *env, struct mgs_device *mgs)
{
	struct fs_db *fsdb = NULL;
	struct llog_handle *params_llh = NULL;
	int rc;
	ENTRY;

	rc = mgs_find_or_make_fsdb(env, mgs, PARAMS_FILENAME, &fsdb);
	if (!rc) {
		mutex_lock(&fsdb->fsdb_mutex);
		rc = record_start_log(env, mgs, &params_llh, PARAMS_FILENAME);
		if (!rc)
			rc = record_end_log(env, &params_llh);
		mutex_unlock(&fsdb->fsdb_mutex);
		mgs_put_fsdb(mgs, fsdb);
	}

	RETURN(rc);
}

/* Cleanup params fsdb and log
 */
int mgs_params_fsdb_cleanup(const struct lu_env *env, struct mgs_device *mgs)
{
	int rc;

	rc = mgs_erase_logs(env, mgs, PARAMS_FILENAME);
	return rc == -ENOENT ? 0 : rc;
}

/**
 * Fill in the mgs_target_info based on data devname and param provide.
 *
 * @env		thread context
 * @mgs		mgs device
 * @mti		mgs target info. We want to set this based other paramters
 *		passed to this function. Once setup we write it to the config
 *		logs.
 * @devname	optional OBD device name
 * @param	string that contains both what tunable to set and the value to
 *		set it to.
 *
 * RETURN	0 for success
 *		negative error number on failure
 **/
static int mgs_set_conf_param(const struct lu_env *env, struct mgs_device *mgs,
			      struct mgs_target_info *mti, const char *devname,
			      const char *param, bool del)
{
	struct fs_db *fsdb = NULL;
	int dev_type;
	int rc = 0;

	ENTRY;
	/* lustre, lustre-mdtlov, lustre-client, lustre-MDT0000 */
	if (!devname) {
		size_t len;

		/* We have two possible cases here:
		 *
		 * 1) the device name embedded in the param:
		 *    lustre-OST0000.osc.max_dirty_mb=32
		 *
		 * 2) the file system name is embedded in
		 *    the param: lustre.sys.at.min=0
		 */
		len = strcspn(param, ".=");
		if (!len || param[len] == '=')
			RETURN(-EINVAL);

		if (len >= sizeof(mti->mti_svname))
			RETURN(-E2BIG);

		snprintf(mti->mti_svname, sizeof(mti->mti_svname),
			 "%.*s", (int)len, param);
		param += len + 1;
	} else {
		rc = strscpy(mti->mti_svname, devname, sizeof(mti->mti_svname));
		if (rc < 0)
			RETURN(rc);
	}

	if (!strlen(mti->mti_svname)) {
		LCONSOLE_ERROR("No target specified: %s\n", param);
		RETURN(-ENOSYS);
	}

	dev_type = mgs_parse_devname(mti->mti_svname, mti->mti_fsname,
				     &mti->mti_stripe_index);
	switch (dev_type) {
	/* For this case we have an invalid obd device name */
	case -ENXIO:
		CDEBUG(D_MGS, "%s don't contain an index\n", mti->mti_svname);
		strscpy(mti->mti_fsname, mti->mti_svname, MTI_NAME_MAXLEN);
		dev_type = 0;
		break;
	/* Not an obd device, assume devname is the fsname.
	 * User might of only provided fsname and not obd device
	 */
	case -EINVAL:
		CDEBUG(D_MGS, "%s is seen as a file system name\n", mti->mti_svname);
		strscpy(mti->mti_fsname, mti->mti_svname, MTI_NAME_MAXLEN);
		dev_type = 0;
		break;
	default:
		if (dev_type < 0)
			GOTO(out, rc = dev_type);

		/* param related to llite isn't allowed to set by OST or MDT */
		if (dev_type & LDD_F_SV_TYPE_OST ||
		    dev_type & LDD_F_SV_TYPE_MDT) {
			/* param related to llite isn't allowed to set by OST
			 * or MDT
			 */
			if (!strncmp(param, PARAM_LLITE,
				     sizeof(PARAM_LLITE) - 1))
				GOTO(out, rc = -EINVAL);

			/* Strip -osc or -mdc suffix from svname */
			if (server_make_name(dev_type, mti->mti_stripe_index,
					     mti->mti_fsname, mti->mti_svname,
					     sizeof(mti->mti_svname)))
				GOTO(out, rc = -EINVAL);
		}
		break;
	}
	rc = strscpy(mti->mti_params, param, sizeof(mti->mti_params));
	if (rc < 0)
		GOTO(out, rc);

	CDEBUG(D_MGS, "set_conf_param fs='%s' device='%s' param='%s'\n",
	       mti->mti_fsname, mti->mti_svname, mti->mti_params);

	rc = mgs_find_or_make_fsdb(env, mgs, mti->mti_fsname, &fsdb);
	if (rc)
		GOTO(out, rc);

	if (!test_bit(FSDB_MGS_SELF, &fsdb->fsdb_flags) &&
	    test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
		CERROR("No filesystem targets for %s. cfg_device from lctl "
		       "is '%s'\n", mti->mti_fsname, mti->mti_svname);
		mgs_unlink_fsdb(mgs, fsdb);
		GOTO(out, rc = -EINVAL);
	}

	/*
	 * Revoke lock so everyone updates.  Should be alright if
	 * someone was already reading while we were updating the logs,
	 * so we don't really need to hold the lock while we're
	 * writing (above).
	 */
	mti->mti_flags = dev_type | LDD_F_PARAM;
	mutex_lock(&fsdb->fsdb_mutex);
	rc = mgs_write_log_param(env, mgs, fsdb, mti, mti->mti_params, del);
	mutex_unlock(&fsdb->fsdb_mutex);
	mgs_revoke_lock(mgs, fsdb, MGS_CFG_T_CONFIG);

out:
	if (fsdb)
		mgs_put_fsdb(mgs, fsdb);

	RETURN(rc);
}

static int mgs_set_param2(const struct lu_env *env, struct mgs_device *mgs,
			  struct mgs_target_info *mti,
			  const char *param, bool del)
{
	struct fs_db *fsdb = NULL;
	int dev_type;
	size_t len;
	int rc;

	rc = strscpy(mti->mti_params, param, sizeof(mti->mti_params));
	if (rc < 0)
		GOTO(out, rc);

	len = strcspn(param, ".=");
	if (len && param[len] != '=') {
		struct list_head *tmp;
		char *ptr;

		param += len + 1;
		ptr = strchr(param, '.');

		len = strlen(param);
		if (ptr)
			len -= strlen(ptr);
		if (len >= sizeof(mti->mti_svname))
			GOTO(out, rc = -E2BIG);

		snprintf(mti->mti_svname, sizeof(mti->mti_svname), "%.*s",
			(int)len, param);

		mutex_lock(&mgs->mgs_mutex);
		if (unlikely(list_empty(&mgs->mgs_fs_db_list))) {
			mutex_unlock(&mgs->mgs_mutex);
			GOTO(out, rc = -ENODEV);
		}

		list_for_each(tmp, &mgs->mgs_fs_db_list) {
			fsdb = list_entry(tmp, struct fs_db, fsdb_list);
			if (fsdb->fsdb_has_lproc_entry &&
			    strcmp(fsdb->fsdb_name, "params") != 0 &&
			    strstr(param, fsdb->fsdb_name)) {
				snprintf(mti->mti_svname,
					 sizeof(mti->mti_svname), "%s",
					 fsdb->fsdb_name);
				break;
			}
			fsdb = NULL;
		}

		if (!fsdb) {
			snprintf(mti->mti_svname, sizeof(mti->mti_svname),
				 "general");
		}
		mutex_unlock(&mgs->mgs_mutex);
	} else {
		snprintf(mti->mti_svname, sizeof(mti->mti_svname), "general");
	}

	CDEBUG(D_MGS, "set_param2 fs='%s' device='%s' param='%s'\n",
	       mti->mti_fsname, mti->mti_svname, mti->mti_params);

	/* The return value should be the device type i.e LDD_F_SV_TYPE_XXX.
	 * A returned error tells us we don't have a target obd device.
	 */
	dev_type = server_name2index(mti->mti_svname, &mti->mti_stripe_index,
				     NULL);
	if (dev_type < 0)
		dev_type = 0;

	/* the return value should be the device type i.e LDD_F_SV_TYPE_XXX.
	 * Strip -osc or -mdc suffix from svname
	 */
	if ((dev_type & LDD_F_SV_TYPE_OST || dev_type & LDD_F_SV_TYPE_MDT) &&
	    server_make_name(dev_type, mti->mti_stripe_index,
			     mti->mti_fsname, mti->mti_svname,
			     sizeof(mti->mti_svname)))
		GOTO(out, rc = -EINVAL);

	rc = mgs_find_or_make_fsdb(env, mgs, PARAMS_FILENAME, &fsdb);
	if (rc)
		GOTO(out, rc);
	/*
	 * Revoke lock so everyone updates.  Should be alright if
	 * someone was already reading while we were updating the logs,
	 * so we don't really need to hold the lock while we're
	 * writing (above).
	 */
	mti->mti_flags = dev_type | LDD_F_PARAM2;
	mutex_lock(&fsdb->fsdb_mutex);
	rc = mgs_write_log_param2(env, mgs, fsdb, mti, mti->mti_params, del);
	mutex_unlock(&fsdb->fsdb_mutex);
	mgs_revoke_lock(mgs, fsdb, MGS_CFG_T_PARAMS);
	mgs_put_fsdb(mgs, fsdb);
out:
	RETURN(rc);
}

/* Set a permanent (config log) param for a target or fs
 *
 * @lcfg buf0 may contain the device (testfs-MDT0000) name
 *       buf1 contains the single parameter
 */
int mgs_set_param(const struct lu_env *env, struct mgs_device *mgs,
		  struct lustre_cfg *lcfg)
{
	const char *param = lustre_cfg_string(lcfg, 1);
	char *delstr = lustre_cfg_string(lcfg, 2);
	struct mgs_target_info *mti;
	bool del;
	int rc;

	/* Create a fake mti to hold everything */
	OBD_ALLOC_PTR(mti);
	if (!mti)
		return -ENOMEM;

	print_lustre_cfg(lcfg);

	/* no value means delete the parameter */
	del = mgs_param_empty(param) || (delstr && strcmp(delstr, "del") == 0);
	if (lcfg->lcfg_command == LCFG_PARAM) {
		/* For the case of lctl conf_param devname can be
		 * lustre, lustre-mdtlov, lustre-client, lustre-MDT0000
		 */
		const char *devname = lustre_cfg_string(lcfg, 0);

		rc = mgs_set_conf_param(env, mgs, mti, devname, param, del);
	} else {
		/* In the case of lctl set_param -P lcfg[0] will always
		 * be 'general'. At least for now.
		 */
		rc = mgs_set_param2(env, mgs, mti, param, del);
	}

	OBD_FREE_PTR(mti);

	return rc;
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
			 fsname, poolname, ostname, NULL);
	if (rc)
		goto out;
	rc = record_marker(env, llh, fsdb, CM_END, tgtname, comment);
out:
	record_end_log(env, &llh);
	return rc;
}

static inline
int mgs_pool_check_ostname(struct fs_db *fsdb, char *fsname, char *ostname)
{
	char *ptr;
	unsigned int index;

	/* check if ostname match fsname */
	ptr = strrchr(ostname, '-');
	if (!ptr || (strncmp(fsname, ostname, ptr - ostname) != 0))
		RETURN(-EINVAL);

	ptr++;
	if (sscanf(ptr, "OST%04x_UUID", &index) != 1)
		return -EINVAL;
	if (index > INDEX_MAP_MAX_VALUE)
		return -ERANGE;
	if (!test_bit(index, fsdb->fsdb_ost_index_map))
		return -ENODEV;

	return 0;
}

static
int mgs_pool_sanity(const struct lu_env *env, struct mgs_device *mgs,
		    struct fs_db *fsdb, struct mgs_target_info *mti,
		    char *logname, char *devname, enum lcfg_command_type cmd,
		    char *fsname, char *poolname, char *ostname)
{
	char *lov = fsdb->fsdb_clilov;
	int status;
	int rc = 0;

	status = mgs_search_pool(env, mgs, fsdb, mti, logname, lov,
				 fsname, poolname, ostname);
	if (status < 0)
		return status;

	switch (cmd) {
	case LCFG_POOL_NEW:
		if (status >= POOL_STATUS_EXIST)
			rc = -EEXIST;
		break;
	case LCFG_POOL_ADD:
		if (status == POOL_STATUS_NONE)
			rc = -ENOMEDIUM;
		else if (status == POOL_STATUS_OST_EXIST)
			rc = -EEXIST;
		break;
	case LCFG_POOL_REM:
		if (status == POOL_STATUS_NONE)
			rc = -ENOMEDIUM;
		if (status != POOL_STATUS_OST_EXIST)
			rc = -ENOENT;
		break;
	case LCFG_POOL_DEL:
		if (status == POOL_STATUS_NONE)
			rc = -ENOENT;
		if (status == POOL_STATUS_OST_EXIST)
			rc = -ENOTEMPTY;
		break;
	default:
		rc = -EINVAL;
		break;
	}

	return rc;
}


int mgs_pool_cmd(const struct lu_env *env, struct mgs_device *mgs,
		 enum lcfg_command_type cmd, char *fsname,
		 char *poolname, char *ostname)
{
	struct fs_db *fsdb;
	char *lovname;
	char *logname;
	char *label = NULL;
	char *canceled_label = NULL;
	int label_sz;
	struct mgs_target_info *mti = NULL;
	int rc, i;
	ENTRY;

	if ((cmd == LCFG_POOL_REM || cmd == LCFG_POOL_ADD) && !ostname)
		RETURN(-EINVAL);
	if ((cmd == LCFG_POOL_DEL || cmd == LCFG_POOL_NEW) && ostname)
		ostname = NULL;

	rc = mgs_find_or_make_fsdb(env, mgs, fsname, &fsdb);
	if (rc) {
		CERROR("Can't get db for %s\n", fsname);
		RETURN(rc);
	}
	if (test_bit(FSDB_LOG_EMPTY, &fsdb->fsdb_flags)) {
		CERROR("%s is not defined\n", fsname);
		mgs_unlink_fsdb(mgs, fsdb);
		GOTO(out_fsdb, rc = -EINVAL);
	}

	label_sz = 10 + strlen(fsname) + strlen(poolname);
	if (ostname) {
		rc =  mgs_pool_check_ostname(fsdb, fsname, ostname);
		if (rc)
			GOTO(out_fsdb, rc);
		label_sz += strlen(ostname);
	}

	OBD_ALLOC(label, label_sz);
	if (!label)
		GOTO(out_fsdb, rc = -ENOMEM);

	switch (cmd) {
	case LCFG_POOL_NEW:
		sprintf(label, "new %s.%s", fsname, poolname);
		break;
	case LCFG_POOL_ADD:
		sprintf(label, "add %s.%s.%s", fsname, poolname, ostname);
		break;
	case LCFG_POOL_REM:
		OBD_ALLOC(canceled_label, label_sz);
		if (canceled_label == NULL)
			GOTO(out_label, rc = -ENOMEM);
		sprintf(label, "rem %s.%s.%s", fsname, poolname, ostname);
		sprintf(canceled_label, "add %s.%s.%s",
			fsname, poolname, ostname);
		break;
	case LCFG_POOL_DEL:
		OBD_ALLOC(canceled_label, label_sz);
		if (canceled_label == NULL)
			GOTO(out_label, rc = -ENOMEM);

		sprintf(label, "del %s.%s", fsname, poolname);
		sprintf(canceled_label, "new %s.%s", fsname, poolname);
		break;
	default:
		break;
	}

	OBD_ALLOC_PTR(mti);
	if (!mti)
		GOTO(out_cancel, rc = -ENOMEM);
	strscpy(mti->mti_svname, "lov pool", sizeof(mti->mti_svname));

	mutex_lock(&fsdb->fsdb_mutex);

	rc = name_create(&logname, fsname, "-client");
	if (rc)
		GOTO(out_unlock, rc);

	rc = mgs_pool_sanity(env, mgs, fsdb, mti, logname, fsdb->fsdb_clilov,
			     cmd, fsname, poolname, ostname);
	if (rc < 0)
		GOTO(out_logname, rc);

	if (canceled_label)
		rc = mgs_modify(env, mgs, fsdb, mti, logname,
				fsdb->fsdb_clilov, canceled_label, CM_SKIP);

	if (rc < 0)
		GOTO(out_logname, rc);

	rc = mgs_write_log_pool(env, mgs, logname, fsdb, fsdb->fsdb_clilov,
				cmd, fsname, poolname, ostname, label);
	if (rc < 0)
		GOTO(out_logname, rc);

	name_destroy(&logname);

	/* write pool def to all MDT logs */
	for_each_set_bit(i, fsdb->fsdb_mdt_index_map, INDEX_MAP_SIZE) {
		rc = name_create_mdt_and_lov(&logname, &lovname, fsdb, i);
		if (rc)
			GOTO(out_unlock, rc);

		if (canceled_label)
			rc = mgs_modify(env, mgs, fsdb, mti, logname, lovname,
					canceled_label, CM_SKIP);

		if (rc < 0)
			GOTO(out_names, rc);

		rc = mgs_write_log_pool(env, mgs, logname, fsdb, lovname, cmd,
					fsname, poolname, ostname, label);
		if (rc)
			GOTO(out_names, rc);

		name_destroy(&logname);
		name_destroy(&lovname);
	}
	mutex_unlock(&fsdb->fsdb_mutex);

	/* request for update */
	mgs_revoke_lock(mgs, fsdb, MGS_CFG_T_CONFIG);

	GOTO(out_mti, rc);

out_names:
	name_destroy(&lovname);
out_logname:
	name_destroy(&logname);
out_unlock:
	mutex_unlock(&fsdb->fsdb_mutex);
out_mti:
	OBD_FREE_PTR(mti);
out_cancel:
	OBD_FREE(canceled_label, label_sz);
out_label:
	OBD_FREE(label, label_sz);
out_fsdb:
	mgs_put_fsdb(mgs, fsdb);

	return rc;
}
