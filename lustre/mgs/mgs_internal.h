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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _MGS_INTERNAL_H
#define _MGS_INTERNAL_H

#include <libcfs/libcfs.h>
#include <lustre_log.h>
#include <lustre_export.h>
#include <lustre_nodemap.h>
#include <dt_object.h>

#define MGSSELF_NAME    "_mgs"

#define MGS_SERVICE_WATCHDOG_FACTOR 2

/* -- imperative recovery control data structures -- */
/**
 * restarting targets.
 */
struct mgs_nidtbl;
struct mgs_nidtbl_target {
	struct list_head	mnt_list;
	struct mgs_nidtbl      *mnt_fs;
	u64			mnt_version;
	int			mnt_type;	/* OST or MDT */
	struct mgs_target_info	mnt_mti;
};

enum {
        IR_FULL = 0,
        IR_STARTUP,
        IR_DISABLED,
        IR_PARTIAL
};

#define IR_STRINGS { "full", "startup", "disabled", "partial" }

/**
 */
struct fs_db;

/**
 * maintain fs client nodes of mgs.
 */
struct mgs_fsc {
	struct fs_db		*mfc_fsdb;
        /**
         * Where the fs client comes from.
         */
	struct obd_export	*mfc_export;
        /**
         * list of fs clients from the same export,
         * protected by mgs_export_data->med_lock
         */
	struct list_head	mfc_export_list;
        /**
         * list of fs clients in the same fsdb, protected by fsdb->fsdb_mutex
         */
	struct list_head	mfc_fsdb_list;
	unsigned		mfc_ir_capable:1;
};

struct mgs_nidtbl {
	struct fs_db		*mn_fsdb;
	struct file		*mn_version_file;
	struct mutex		 mn_lock;
	u64			 mn_version;
	int			 mn_nr_targets;
	struct list_head	 mn_targets;
};

struct mgs_tgt_srpc_conf {
        struct mgs_tgt_srpc_conf  *mtsc_next;
        char                      *mtsc_tgt;
        struct sptlrpc_rule_set    mtsc_rset;
};

#define INDEX_MAP_SIZE  8192     /* covers indicies to FFFF */
#define INDEX_MAP_MAX_VALUE	((INDEX_MAP_SIZE * 8) - 1)

#define FSDB_LOG_EMPTY          (0)  /* missing client log */
#define FSDB_OLDLOG14           (1)  /* log starts in old (1.4) style */
#define FSDB_REVOKING_LOCK      (2)  /* DLM lock is being revoked */
#define FSDB_MGS_SELF           (3)  /* for '_mgs', used by sptlrpc */
#define FSDB_OSCNAME18          (4)  /* old 1.8 style OSC naming */
#define FSDB_UDESC              (5)  /* sptlrpc user desc, will be obsolete */
#define FSDB_REVOKING_PARAMS	(6)  /* DLM lock is being revoked */

struct fs_db {
	char		  fsdb_name[20];
	struct list_head  fsdb_list;		/* list of databases */
	struct mutex	  fsdb_mutex;
	union {
		void	 *fsdb_ost_index_map;	/* bitmap of used indicies */
		void	 *fsdb_barrier_map;	/* bitmap of barrier */
	};
	void		 *fsdb_mdt_index_map;	/* bitmap of used indicies */
	atomic_t	  fsdb_ref;
	char		 *fsdb_clilov;	/* COMPAT_146 client lov name */
	char		 *fsdb_clilmv;
	unsigned long	  fsdb_flags;
	__u32		  fsdb_barrier_status;
	int		  fsdb_mdt_count;
	time64_t	  fsdb_barrier_timeout;
	__u32		  fsdb_barrier_expected;
	int		  fsdb_barrier_result;
	time64_t	  fsdb_barrier_latest_create_time;

        /* in-memory copy of the srpc rules, guarded by fsdb_lock */
        struct sptlrpc_rule_set   fsdb_srpc_gen;
        struct mgs_tgt_srpc_conf *fsdb_srpc_tgt;

        /* list of fs clients, mgs_fsc. protected by mgs_mutex */
	struct list_head     fsdb_clients;
        int                  fsdb_nonir_clients;
        int                  fsdb_ir_state;

        /* Target NIDs Table */
        struct mgs_nidtbl    fsdb_nidtbl;

	/* async thread to notify clients */
	struct mgs_device    *fsdb_mgs;
	wait_queue_head_t     fsdb_notify_waitq;
	struct completion     fsdb_notify_comp;
	ktime_t		      fsdb_notify_start;
	atomic_t	      fsdb_notify_phase;
	volatile unsigned int fsdb_notify_async:1,
			      fsdb_notify_stop:1,
			      fsdb_has_lproc_entry:1,
			      fsdb_barrier_disabled:1;
	/* statistic data */
	ktime_t		fsdb_notify_total;
	ktime_t		fsdb_notify_max;
	unsigned int	fsdb_notify_count;
	__u32		fsdb_gen;
};

struct mgs_device {
	struct dt_device		 mgs_dt_dev;
	struct ptlrpc_service		*mgs_service;
	struct dt_device		*mgs_bottom;
	struct obd_export		*mgs_bottom_exp;
	struct dt_object		*mgs_configs_dir;
	struct dt_object		*mgs_nidtbl_dir;
	struct list_head		 mgs_fs_db_list;
	spinlock_t			 mgs_lock; /* covers mgs_fs_db_list */
	struct proc_dir_entry		*mgs_proc_live;
	struct proc_dir_entry           *mgs_proc_osd;
	struct attribute		*mgs_fstype;
	struct attribute		*mgs_mntdev;
	time64_t			 mgs_start_time;
	struct obd_device		*mgs_obd;
	struct local_oid_storage	*mgs_los;
	struct mutex			 mgs_mutex;
	struct mutex			 mgs_health_mutex;
	struct rw_semaphore		 mgs_barrier_rwsem;
	struct lu_target		 mgs_lut;
};

/* this is a top object */
struct mgs_object {
	struct lu_object_header mgo_header;
	struct dt_object        mgo_obj;
	int			mgo_no_attrs;
	int			mgo_reserved;
};

int mgs_init_fsdb_list(struct mgs_device *mgs);
int mgs_cleanup_fsdb_list(struct mgs_device *mgs);
int mgs__mgs_fsdb_setup(const struct lu_env *env, struct mgs_device *mgs);
int mgs_params_fsdb_setup(const struct lu_env *env, struct mgs_device *mgs);
int mgs_params_fsdb_cleanup(const struct lu_env *env, struct mgs_device *mgs);
int mgs_find_or_make_fsdb(const struct lu_env *env, struct mgs_device *mgs,
			  char *name, struct fs_db **dbh);
int mgs_find_or_make_fsdb_nolock(const struct lu_env *env,
				  struct mgs_device *mgs, char *name,
				  struct fs_db **dbh);
struct fs_db *mgs_find_fsdb(struct mgs_device *mgs, const char *fsname);
void mgs_put_fsdb(struct mgs_device *mgs, struct fs_db *fsdb);
int mgs_get_fsdb_srpc_from_llog(const struct lu_env *env,
				struct mgs_device *mgs, struct fs_db *fsdb);
int mgs_check_index(const struct lu_env *env, struct mgs_device *mgs,
		    struct mgs_target_info *mti);
int mgs_write_log_target(const struct lu_env *env, struct mgs_device *mgs,
			 struct mgs_target_info *mti, struct fs_db *fsdb);
int mgs_replace_nids(const struct lu_env *env, struct mgs_device *mgs,
		     char *devname, char *nids);
int mgs_clear_configs(const struct lu_env *env, struct mgs_device *mgs,
		      const char *devname);
int mgs_erase_log(const struct lu_env *env, struct mgs_device *mgs,
		  char *name);
int mgs_erase_logs(const struct lu_env *env, struct mgs_device *mgs,
		   const char *fsname);
int mgs_set_param(const struct lu_env *env, struct mgs_device *mgs,
		  struct lustre_cfg *lcfg);
int mgs_list_logs(const struct lu_env *env, struct mgs_device *mgs,
		  struct obd_ioctl_data *data);
int mgs_pool_cmd(const struct lu_env *env, struct mgs_device *mgs,
		 enum lcfg_command_type cmd, char *poolname, char *fsname,
		 char *ostname);
int mgs_nodemap_cmd(const struct lu_env *env, struct mgs_device *mgs,
		    enum lcfg_command_type cmd, const char *nodemap_name,
		    char *param);

/* mgs_handler.c */
int  mgs_get_lock(struct obd_device *obd, struct ldlm_res_id *res,
                  struct lustre_handle *lockh);
int  mgs_put_lock(struct lustre_handle *lockh);
void mgs_revoke_lock(struct mgs_device *mgs, struct fs_db *fsdb,
		     enum mgs_cfg_type type);

/* mgs_nids.c */
int  mgs_ir_update(const struct lu_env *env, struct mgs_device *mgs,
		   struct mgs_target_info *mti);
int mgs_ir_init_fs(const struct lu_env *env, struct mgs_device *mgs,
		   struct fs_db *fsdb);
void mgs_ir_fini_fs(struct mgs_device *mgs, struct fs_db *fsdb);
void mgs_ir_notify_complete(struct fs_db *fsdb);
int  mgs_get_ir_logs(struct ptlrpc_request *req);
int  lprocfs_wr_ir_state(struct file *file, const char __user *buffer,
			 size_t count, void *data);
int  lprocfs_rd_ir_state(struct seq_file *seq, void *data);
ssize_t
lprocfs_ir_timeout_seq_write(struct file *file, const char __user *buffer,
			     size_t count, loff_t *off);
int  lprocfs_ir_timeout_seq_show(struct seq_file *seq, void *data);
void mgs_fsc_cleanup(struct obd_export *exp);
void mgs_fsc_cleanup_by_fsdb(struct fs_db *fsdb);
int  mgs_fsc_attach(const struct lu_env *env, struct obd_export *exp,
		    char *fsname);

/* mgs_fs.c */
int mgs_export_stats_init(struct obd_device *obd, struct obd_export *exp,
                          void *localdata);
int mgs_client_free(struct obd_export *exp);
int mgs_fs_setup(const struct lu_env *env, struct mgs_device *m);
int mgs_fs_cleanup(const struct lu_env *env, struct mgs_device *m);

/* mgs_barrier.c */
int mgs_iocontrol_barrier(const struct lu_env *env,
			  struct mgs_device *mgs,
			  struct obd_ioctl_data *data);

#ifdef CONFIG_PROC_FS
int lproc_mgs_setup(struct mgs_device *mgs, const char *osd_name);
void lproc_mgs_cleanup(struct mgs_device *mgs);
int lproc_mgs_add_live(struct mgs_device *mgs, struct fs_db *fsdb);
int lproc_mgs_del_live(struct mgs_device *mgs, struct fs_db *fsdb);
#else
static inline int lproc_mgs_setup(struct mgs_device *mgs, const char *osd_name)
{return 0;}
static inline void lproc_mgs_cleanup(struct mgs_device *mgs)
{}
static inline int lproc_mgs_add_live(struct mgs_device *mgs, struct fs_db *fsdb)
{return 0;}
static inline int lproc_mgs_del_live(struct mgs_device *mgs, struct fs_db *fsdb)
{return 0;}
#endif

/* mgs/lproc_mgs.c */
enum {
        LPROC_MGS_CONNECT = 0,
        LPROC_MGS_DISCONNECT,
        LPROC_MGS_EXCEPTION,
        LPROC_MGS_TARGET_REG,
        LPROC_MGS_TARGET_DEL,
        LPROC_MGS_LAST
};
void mgs_counter_incr(struct obd_export *exp, int opcode);
void mgs_stats_counter_init(struct lprocfs_stats *stats);

struct temp_comp {
	struct mgs_target_info	*comp_tmti;
	struct mgs_target_info	*comp_mti;
	struct fs_db		*comp_fsdb;
	struct obd_device	*comp_obd;
};

struct mgs_thread_info {
	struct lustre_cfg_bufs	mgi_bufs;
	char			mgi_fsname[MTI_NAME_MAXLEN];
	struct cfg_marker	mgi_marker;
	struct temp_comp	mgi_comp;
	union ldlm_gl_desc	mgi_gl_desc;
};

extern struct lu_context_key mgs_thread_key;

static inline struct mgs_thread_info *mgs_env_info(const struct lu_env *env)
{
	return lu_env_info(env, &mgs_thread_key);
}

extern const struct lu_device_operations mgs_lu_ops;

static inline int lu_device_is_mgs(struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mgs_lu_ops);
}

static inline struct mgs_device* lu2mgs_dev(struct lu_device *d)
{
	LASSERT(lu_device_is_mgs(d));
	return container_of_safe(d, struct mgs_device, mgs_dt_dev.dd_lu_dev);
}

static inline struct mgs_device *exp2mgs_dev(struct obd_export *exp)
{
	return lu2mgs_dev(exp->exp_obd->obd_lu_dev);
}

static inline struct lu_device *mgs2lu_dev(struct mgs_device *d)
{
	return (&d->mgs_dt_dev.dd_lu_dev);
}

static inline struct mgs_device *dt2mgs_dev(struct dt_device *d)
{
	LASSERT(lu_device_is_mgs(&d->dd_lu_dev));
	return container_of(d, struct mgs_device, mgs_dt_dev);
}

static inline struct mgs_object *lu2mgs_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_mgs(o->lo_dev)));
	return container_of_safe(o, struct mgs_object, mgo_obj.do_lu);
}

static inline struct lu_object *mgs2lu_obj(struct mgs_object *obj)
{
	return &obj->mgo_obj.do_lu;
}

static inline struct mgs_object *mgs_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_mgs(o->lo_dev));
	return container_of(o, struct mgs_object, mgo_obj.do_lu);
}

static inline struct mgs_object *dt2mgs_obj(const struct dt_object *d)
{
	return mgs_obj(&d->do_lu);
}

static inline struct dt_object* mgs_object_child(struct mgs_object *o)
{
	return container_of(lu_object_next(mgs2lu_obj(o)),
			    struct dt_object, do_lu);
}

struct mgs_direntry {
	struct list_head	 mde_list;
	char			*mde_name;
	int			 mde_len;
};

static inline void mgs_direntry_free(struct mgs_direntry *de)
{
	LASSERT(list_empty(&de->mde_list));
	if (de) {
		LASSERT(de->mde_len);
		OBD_FREE(de->mde_name, de->mde_len);
		OBD_FREE_PTR(de);
	}
}

static inline struct mgs_direntry *mgs_direntry_alloc(int len)
{
	struct mgs_direntry *de;

	OBD_ALLOC_PTR(de);
	if (de == NULL)
		return NULL;

	OBD_ALLOC(de->mde_name, len);
	if (de->mde_name == NULL) {
		OBD_FREE_PTR(de);
		return NULL;
	}

	de->mde_len = len;
	INIT_LIST_HEAD(&de->mde_list);

	return de;
}

/* mgs_llog.c */
int class_dentry_readdir(const struct lu_env *env, struct mgs_device *mgs,
			 struct list_head *list);
int mgs_lcfg_fork(const struct lu_env *env, struct mgs_device *mgs,
		  const char *oldname, const char *newname);
int mgs_lcfg_erase(const struct lu_env *env, struct mgs_device *mgs,
		   const char *fsname);
int mgs_lcfg_rename(const struct lu_env *env, struct mgs_device *mgs);

#endif /* _MGS_INTERNAL_H */
