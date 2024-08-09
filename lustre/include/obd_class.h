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
 * lustre/include/obd_class.h
 *
 * Header defining common operations on OBD devices.
 *
 */

#ifndef __CLASS_OBD_H
#define __CLASS_OBD_H

#include <linux/kobject.h>
#include <obd_support.h>
#include <lustre_import.h>
#include <lustre_net.h>
#include <obd.h>
#include <lustre_lib.h>
#include <uapi/linux/lustre/lustre_idl.h>
#include <lprocfs_status.h>
#ifdef HAVE_SERVER_SUPPORT
#include <lu_target.h>
#include <obd_target.h>
#include <dt_object.h>
#endif

#ifdef HAVE_SERVER_SUPPORT
#define SERVER_ONLY_EXPORT_SYMBOL(symbol)	EXPORT_SYMBOL(symbol)
#define SERVER_ONLY
#else
#define SERVER_ONLY static
#define SERVER_ONLY_EXPORT_SYMBOL(symbol)
#endif

#define OBD_STATFS_NODELAY	0x0001	/* requests should be send without delay
					 * and resends for avoid deadlocks */
#define OBD_STATFS_FROM_CACHE	0x0002	/* the statfs callback should not update
					 * obd_osfs_age */
#define OBD_STATFS_FOR_MDT0	0x0004	/* The statfs is only for retrieving
					 * information from MDT0. */
#define OBD_STATFS_SUM		0x0008	/* get aggregated statfs from MDT */
#define OBD_STATFS_NESTED	0x0010	/* Call while already holding
					 * obd_dev_mutex of a difference
					 * device.
					 */

#define OBD_MAX_INDEX xa_limit_31b.max

#define obd_device_find(devno)						\
	xa_find(&obd_devs, &devno, OBD_MAX_INDEX, XA_PRESENT)

#define obd_device_find_after(devno)					\
	xa_find_after(&obd_devs, &devno, OBD_MAX_INDEX, XA_PRESENT)

#define obd_device_for_each(devno, obd)			\
	xa_for_each(&obd_devs, devno, obd)

#define obd_device_for_each_start(devno, obd, start)	\
	xa_for_each_start(&obd_devs, devno, obd, start)

#define obd_device_for_each_cond(devno, obd, cond)	 \
	obd_device_for_each(devno, obd)			 \
	if (cond)

#define obd_device_for_each_uuid(devno, obd, uuid)	 \
	obd_device_for_each_cond(devno, obd,		 \
				 obd_uuid_equals(uuid, &obd->obd_uuid))

#define obd_device_lock() xa_lock(&obd_devs)
#define obd_device_unlock() xa_unlock(&obd_devs)

/* OBD Operations Declarations */
extern struct obd_device *class_exp2obd(struct obd_export *);
extern int class_handle_ioctl(unsigned int cmd, void __user *uarg);
int lustre_get_jobid(char *jobid, size_t len);
void lustre_jobid_clear(const char *jobid);
void jobid_cache_fini(void);
int jobid_cache_init(void);
char *jobid_current(void);
int jobid_set_current(char *jobid);

struct lu_device_type;

/* genops.c */
extern struct xarray obd_devs;
struct obd_export *class_conn2export(struct lustre_handle *);
#ifdef HAVE_SERVER_SUPPORT
struct obd_type *class_add_symlinks(const char *name, bool enable_proc);
#endif
int class_register_type(const struct obd_ops *dt_ops,
			const struct md_ops *md_ops, bool enable_proc,
			const char *nm, struct lu_device_type *ldt);
int class_unregister_type(const char *nm);

struct obd_device *class_newdev(const char *type_name, const char *name,
				const char *uuid);
int class_register_device(struct obd_device *obd);
void class_unregister_device(struct obd_device *obd);
void class_free_dev(struct obd_device *obd);

struct obd_device *class_str2obd(const char *str);
int class_name2dev(const char *name);
struct obd_device *class_name2obd(const char *name);
int class_uuid2dev(struct obd_uuid *uuid);
struct obd_device *class_uuid2obd(struct obd_uuid *uuid);
struct obd_device *class_find_client_obd(struct obd_uuid *tgt_uuid,
					 const char *type_name,
					 struct obd_uuid *grp_uuid);
struct obd_device *class_num2obd(int num);
int class_obd_devs_count(void);

int class_notify_sptlrpc_conf(const char *fsname, int namelen);

static inline char *obd_export_nid2str(struct obd_export *exp)
{
	return exp->exp_connection == NULL ?
	       "<unknown>" : libcfs_nidstr(&exp->exp_connection->c_peer.nid);
}

static inline char *obd_import_nid2str(struct obd_import *imp)
{
	return imp->imp_connection == NULL ?
	       "<unknown>" : libcfs_nidstr(&imp->imp_connection->c_peer.nid);
}

int obd_export_evict_by_nid(struct obd_device *obd, const char *nid);
int obd_export_evict_by_uuid(struct obd_device *obd, const char *uuid);
int obd_connect_flags2str(char *page, int count, __u64 flags, __u64 flags2,
			  const char *sep);

int obd_zombie_impexp_init(void);
void obd_zombie_impexp_stop(void);
void obd_zombie_impexp_cull(void);
void obd_zombie_barrier(void);
void obd_exports_barrier(struct obd_device *obd);
int kuc_len(int payload_len);
struct kuc_hdr * kuc_ptr(void *p);
void *kuc_alloc(int payload_len, int transport, int type);
void kuc_free(void *p, int payload_len);
int obd_get_request_slot(struct client_obd *cli);
void obd_put_request_slot(struct client_obd *cli);
__u32 obd_get_max_rpcs_in_flight(struct client_obd *cli);
int obd_set_max_rpcs_in_flight(struct client_obd *cli, __u32 max);
__u16 obd_get_max_mod_rpcs_in_flight(struct client_obd *cli);
int obd_set_max_mod_rpcs_in_flight(struct client_obd *cli, __u16 max);
int obd_mod_rpc_stats_seq_show(struct client_obd *cli, struct seq_file *seq);

/* page_pools.c */
int  obd_pool_init(void);
void obd_pool_fini(void);
void obd_pool_add_user(void);
int obd_pool_get_desc_pages(struct ptlrpc_bulk_desc *desc);
int obd_pool_get_pages_array(struct page **pa, unsigned int count);
int obd_pool_get_objects(void **buf, unsigned int order);
void obd_pool_put_desc_pages(struct ptlrpc_bulk_desc *desc);
void obd_pool_put_pages_array(struct page **pa, unsigned int count);
void obd_pool_put_objects(void *buf, unsigned int order);
int obd_pool_get_free_objects(unsigned int order);
int pool_is_at_full_capacity(int order);

int encrypt_page_pools_seq_show(struct seq_file *m, void *v);
int page_pools_seq_show(struct seq_file *m, void *v);

__u16 obd_get_mod_rpc_slot(struct client_obd *cli, __u32 opc);
void obd_put_mod_rpc_slot(struct client_obd *cli, __u32 opc, __u16 tag);

struct llog_handle;
struct llog_rec_hdr;
typedef int (*llog_cb_t)(const struct lu_env *, struct llog_handle *,
			 struct llog_rec_hdr *, void *);

struct obd_export *obd_stale_export_get(void);
void obd_stale_export_put(struct obd_export *exp);
void obd_stale_export_adjust(struct obd_export *exp);

/* obd_config.c */
/* For interoperability */
struct cfg_interop_param {
	char *old_param;
	char *new_param;
};

#ifdef HAVE_SERVER_SUPPORT
void lustre_register_quota_process_config(int (*qpc)(struct lustre_cfg *lcfg));
#endif

char *lustre_cfg_string(struct lustre_cfg *lcfg, u32 index);
struct lustre_cfg *lustre_cfg_rename(struct lustre_cfg *cfg,
				     const char *new_name);
void print_lustre_cfg(struct lustre_cfg *lcfg);
int class_process_config(struct lustre_cfg *lcfg);
ssize_t class_set_global(const char *param);
ssize_t class_modify_config(struct lustre_cfg *lcfg, const char *prefix,
			    struct kobject *kobj);
int class_attach(struct lustre_cfg *lcfg);
int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg);
int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg);
int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg);

int class_find_param(char *buf, char *key, char **valp);
struct cfg_interop_param *class_find_old_param(const char *param,
					       struct cfg_interop_param *ptr);
int class_get_next_param(char **params, char *copy);
int class_match_param(char *buf, const char *key, char **valp);
int class_parse_nid(char *buf, struct lnet_nid *nid, char **endh);
int class_parse_nid_quiet(char *buf, struct lnet_nid *nid, char **endh);
int class_parse_net(char *buf, u32 *net, char **endh);
int class_match_nid(char *buf, char *key, struct lnet_nid *nid);
int class_match_net(char *buf, char *key, u32 net);

struct obd_device *class_incref(struct obd_device *obd,
				const char *scope, const void *source);
void class_decref(struct obd_device *obd,
		  const char *scope, const void *source);
void dump_exports(struct obd_device *obd, int locks, int debug_level);
int class_config_llog_handler(const struct lu_env *env,
			      struct llog_handle *handle,
			      struct llog_rec_hdr *rec, void *data);
int class_add_conn(struct obd_device *obd, struct lustre_cfg *lcfg);

#define CFG_F_START	0x01   /* Set when we start updating from a log */
#define CFG_F_MARKER	0x02   /* We are within a maker */
#define CFG_F_SKIP	0x04   /* We should ignore this cfg command */
#define CFG_F_EXCLUDE	0x10   /* OST exclusion list */

/* Passed as data param to class_config_parse_llog */
struct config_llog_instance {
	unsigned long		 cfg_instance;
	struct super_block	*cfg_sb;
	struct obd_uuid		 cfg_uuid;
	llog_cb_t		 cfg_callback;
	int			 cfg_last_idx; /* for partial llog processing */
	int			 cfg_flags;
	__u32			 cfg_lwp_idx;
	__u32			 cfg_sub_clds;
};
int class_config_parse_llog(const struct lu_env *env, struct llog_ctxt *ctxt,
			    char *name, struct config_llog_instance *cfg);

/**
 * Generate a unique configuration instance for this mount
 *
 * Temporary hack to bypass ASLR in 4.15+ kernels, a better fix soon.
 * For now, use the same value as before - the superblock pointer value.
 *
 * Using the client UUID would be an option, but it needs more testing.
 */
static inline unsigned long ll_get_cfg_instance(struct super_block *sb)
{
	return (unsigned long)sb;
}

#define CONFIG_SUB_SPTLRPC	0x01
#define CONFIG_SUB_RECOVER	0x02
#define CONFIG_SUB_PARAMS	0x04
#define CONFIG_SUB_NODEMAP	0x08
#define CONFIG_SUB_BARRIER	0x10

/* Sub clds should be attached to the config_llog_data when processing
 * config log for client or server target. */
#define CONFIG_SUB_CLIENT	(CONFIG_SUB_SPTLRPC | CONFIG_SUB_RECOVER | \
				 CONFIG_SUB_PARAMS)
#define CONFIG_SUB_SERVER	(CONFIG_SUB_CLIENT | CONFIG_SUB_NODEMAP | \
				 CONFIG_SUB_BARRIER)

#define PARAMS_FILENAME		"params"
#define BARRIER_FILENAME	"barrier"
#define LCTL_UPCALL		"lctl"

static inline bool logname_is_barrier(const char *logname)
{
	char *ptr;

	/* logname for barrier is "fsname-barrier" */
	ptr = strstr(logname, BARRIER_FILENAME);
	if (ptr && (ptr - logname) >= 2 &&
	    *(ptr - 1) == '-' && *(ptr + 7) == '\0')
		return true;

	return false;
}

/* list of active configuration logs  */
struct config_llog_data {
	struct ldlm_res_id	    cld_resid;
	struct lustre_handle	    cld_lockh;
	struct config_llog_instance cld_cfg;
	struct list_head	    cld_list_chain;/* on config_llog_list */
	refcount_t		    cld_refcount;
	struct config_llog_data	   *cld_sptlrpc;/* depended sptlrpc log */
	struct config_llog_data	   *cld_params;	/* common parameters log */
	struct config_llog_data	   *cld_recover;/* imperative recover log */
	struct config_llog_data	   *cld_nodemap;/* nodemap log */
	struct config_llog_data	   *cld_barrier;/* barrier log (for MDT only) */
	struct obd_export	   *cld_mgcexp;
	struct mutex		    cld_lock;
	enum mgs_cfg_type	    cld_type;
	unsigned int		    cld_stopping:1, /* we were told to stop
						     * watching */
				    cld_lostlock:1, /* lock not requeued */
				    cld_processed:1;  /* successfully fetched */
	char			    cld_logname[];
};

struct lustre_profile {
	struct list_head	 lp_list;
	char			*lp_profile;
	char			*lp_dt;
	char			*lp_md;
	int			 lp_refs;
	bool			 lp_list_deleted;
};

struct lustre_profile *class_get_profile(const char * prof);
void class_del_profile(const char *prof);
void class_put_profile(struct lustre_profile *lprof);
void class_del_profiles(void);


#if LUSTRE_TRACKS_LOCK_EXP_REFS

void __class_export_add_lock_ref(struct obd_export *, struct ldlm_lock *);
void __class_export_del_lock_ref(struct obd_export *, struct ldlm_lock *);
extern void (*class_export_dump_hook)(struct obd_export *);

#else

#define __class_export_add_lock_ref(exp, lock)		   do {} while (0)
#define __class_export_del_lock_ref(exp, lock)		   do {} while (0)

#endif

#define class_export_rpc_inc(exp)					\
({									\
	atomic_inc(&(exp)->exp_rpc_count);				\
	CDEBUG(D_INFO, "RPC GETting export %p : new rpc_count %d\n",	\
	       (exp), atomic_read(&(exp)->exp_rpc_count));		\
})

#define class_export_rpc_dec(exp)					\
({									\
	LASSERT(atomic_read(&(exp)->exp_rpc_count) > 0);		\
	atomic_dec(&(exp)->exp_rpc_count);				\
	CDEBUG(D_INFO, "RPC PUTting export %p : new rpc_count %d\n",	\
	       (exp), atomic_read(&(exp)->exp_rpc_count));		\
})

#define class_export_lock_get(exp, lock)				\
({									\
	atomic_inc(&(exp)->exp_locks_count);				\
	__class_export_add_lock_ref(exp, lock);				\
	CDEBUG(D_INFO, "lock GETting export %p : new locks_count %d\n", \
	       (exp), atomic_read(&(exp)->exp_locks_count));		\
	class_export_get(exp);						\
})

#define class_export_lock_put(exp, lock)				\
({									\
	LASSERT(atomic_read(&(exp)->exp_locks_count) > 0);		\
	atomic_dec(&(exp)->exp_locks_count);				\
	__class_export_del_lock_ref(exp, lock);				\
	CDEBUG(D_INFO, "lock PUTting export %p : new locks_count %d\n", \
	       (exp), atomic_read(&(exp)->exp_locks_count));		\
	class_export_put(exp);						\
})

#define class_export_cb_get(exp)					\
({									\
	atomic_inc(&(exp)->exp_cb_count);				\
	CDEBUG(D_INFO, "callback GETting export %p : new cb_count %d\n",\
	       (exp), atomic_read(&(exp)->exp_cb_count));		\
	class_export_get(exp);						\
})

#define class_export_cb_put(exp)					\
({									\
	LASSERT(atomic_read(&(exp)->exp_cb_count) > 0);			\
	atomic_dec(&(exp)->exp_cb_count);				\
	CDEBUG(D_INFO, "callback PUTting export %p : new cb_count %d\n",\
	       (exp), atomic_read(&(exp)->exp_cb_count));		\
	class_export_put(exp);						\
})

/* genops.c */
struct obd_export *class_export_get(struct obd_export *exp);
void class_export_put(struct obd_export *exp);
struct obd_export *class_new_export(struct obd_device *obd,
				    struct obd_uuid *cluuid);
struct obd_export *class_new_export_self(struct obd_device *obd,
					 struct obd_uuid *uuid);
void class_unlink_export(struct obd_export *exp);

struct obd_import *class_import_get(struct obd_import *);
void class_import_put(struct obd_import *);
struct obd_import *class_new_import(struct obd_device *obd);
void class_destroy_import(struct obd_import *exp);

#ifdef HAVE_SERVER_SUPPORT
struct obd_type *class_search_type(const char *name);
struct obd_type *class_get_type(const char *name);
#endif
void class_put_type(struct obd_type *type);
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
		  struct obd_uuid *cluuid);
int class_disconnect(struct obd_export *exp);
void class_fail_export(struct obd_export *exp);
int class_connected_export(struct obd_export *exp);
void class_disconnect_exports(struct obd_device *obd);
int class_manual_cleanup(struct obd_device *obd);
void class_disconnect_stale_exports(struct obd_device *,
				    int (*test_export)(struct obd_export *));

static inline enum obd_option exp_flags_from_obd(struct obd_device *obd)
{
	return ((obd->obd_fail ? OBD_OPT_FAILOVER : 0) |
		(obd->obd_force ? OBD_OPT_FORCE : 0) |
		(obd->obd_abort_recovery ? OBD_OPT_ABORT_RECOV : 0) |
		0);
}

#ifdef HAVE_SERVER_SUPPORT
static inline struct lu_target *class_exp2tgt(struct obd_export *exp)
{
	struct obd_device_target *obt;

	LASSERT(exp->exp_obd);
	obt = (void *)&exp->exp_obd->u;
	if (obt->obt_magic != OBT_MAGIC)
		return NULL;
	return obt->obt_lut;
}

static inline struct lr_server_data *class_server_data(struct obd_device *obd)
{
	struct obd_device_target *obt = obd2obt(obd);

	LASSERT(obt);
	return &obt->obt_lut->lut_lsd;
}
#endif

/* obdo.c */
struct lu_attr;
struct inode;

void obdo_from_la(struct obdo *dst, const struct lu_attr *la, u64 valid);
void la_from_obdo(struct lu_attr *la, const struct obdo *dst, u64 valid);

void obdo_cpy_md(struct obdo *dst, const struct obdo *src, u64 valid);
void obdo_to_ioobj(const struct obdo *oa, struct obd_ioobj *ioobj);

static inline int obd_check_dev(struct obd_device *obd)
{
	if (!obd) {
		CERROR("NULL device\n");
		return -ENODEV;
	}
	return 0;
}

/* ensure obd_setup and !obd_stopping */
#define OBD_CHECK_DEV_ACTIVE(obd)				\
do {								\
	rc = obd_check_dev(obd);				\
	if (rc)							\
		return rc;					\
								\
	if (!(obd)->obd_set_up || (obd)->obd_stopping) {	\
		CERROR("Device %d not setup\n",			\
		       (obd)->obd_minor);			\
		RETURN(-ENODEV);				\
	}							\
} while (0)


static inline int lprocfs_nid_ldlm_stats_init(struct nid_stat* tmp)
{
	/* Always add in ldlm_stats */
	tmp->nid_ldlm_stats =
		lprocfs_stats_alloc(LDLM_LAST_OPC - LDLM_FIRST_OPC,
				    LPROCFS_STATS_FLAG_NOPERCPU);
	if (tmp->nid_ldlm_stats == NULL)
		return -ENOMEM;

	lprocfs_init_ldlm_stats(tmp->nid_ldlm_stats);

	return lprocfs_stats_register(tmp->nid_proc, "ldlm_stats",
				      tmp->nid_ldlm_stats);
}

static inline int exp_check_ops(struct obd_export *exp)
{
	if (exp == NULL) {
		RETURN(-ENODEV);
	}
	if (exp->exp_obd == NULL || !exp->exp_obd->obd_type) {
		RETURN(-EOPNOTSUPP);
	}
	RETURN(0);
}

static inline int obd_get_info(const struct lu_env *env, struct obd_export *exp,
			       __u32 keylen, void *key,
			       __u32 *vallen, void *val)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_get_info) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_get_info(env, exp, keylen,
							    key, vallen, val);
	RETURN(rc);
}

static inline int obd_set_info_async(const struct lu_env *env,
				     struct obd_export *exp,
				     __u32 keylen, void *key,
				     __u32 vallen, void *val,
				     struct ptlrpc_request_set *set)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_set_info_async) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_set_info_async(env, exp,
								  keylen,
								  key,
								  vallen,
								  val, set);
	RETURN(rc);
}

/*
 * obd-lu integration.
 *
 * Functionality is being moved into new lu_device-based layering, but some
 * pieces of configuration process are still based on obd devices.
 *
 * Specifically, lu_device_type_operations::ldto_device_alloc() methods fully
 * subsume ->o_setup() methods of obd devices they replace. The same for
 * lu_device_operations::ldo_process_config() and ->o_process_config(). As a
 * result, obd_setup() and obd_process_config() branch and call one XOR
 * another.
 *
 * Yet neither lu_device_type_operations::ldto_device_fini() nor
 * lu_device_type_operations::ldto_device_free() fully implement the
 * functionality of ->o_precleanup() and ->o_cleanup() they override. Hence,
 * obd_precleanup() and obd_cleanup() call both lu_device and obd operations.
 */
static inline int obd_setup(struct obd_device *obd, struct lustre_cfg *cfg)
{
	int rc;
	struct obd_type *type = obd->obd_type;
	struct lu_device_type *ldt;

	ENTRY;

	wait_var_event(&type->typ_lu,
		       smp_load_acquire(&type->typ_lu) != OBD_LU_TYPE_SETUP);
	ldt = type->typ_lu;
	if (ldt != NULL) {
		struct lu_context session_ctx;
		struct lu_env env;

		lu_context_init(&session_ctx, LCT_SESSION | LCT_SERVER_SESSION);
		session_ctx.lc_thread = NULL;
		lu_context_enter(&session_ctx);

		rc = lu_env_init(&env, ldt->ldt_ctx_tags);
		if (rc == 0) {
			struct lu_device *dev;
			env.le_ses = &session_ctx;
			dev = ldt->ldt_ops->ldto_device_alloc(&env, ldt, cfg);
			lu_env_fini(&env);
			if (!IS_ERR(dev)) {
				obd->obd_lu_dev = dev;
				dev->ld_obd = obd;
#ifdef HAVE_SERVER_SUPPORT
				if (lu_device_is_dt(dev) &&
				    lu2dt_dev(dev)->dd_rdonly)
					obd->obd_read_only = 1;
#endif
				rc = 0;
			} else
				rc = PTR_ERR(dev);
		}
		lu_context_exit(&session_ctx);
		lu_context_fini(&session_ctx);
	} else {
		if (!obd->obd_type->typ_dt_ops->o_setup) {
			CERROR("%s: no %s operation\n", obd->obd_name,
			       __func__);
			RETURN(-EOPNOTSUPP);
		}
		rc = obd->obd_type->typ_dt_ops->o_setup(obd, cfg);
	}
	RETURN(rc);
}

static inline int obd_precleanup(struct obd_device *obd)
{
	int rc;
	struct lu_device_type *ldt = obd->obd_type->typ_lu;
	struct lu_device *d = obd->obd_lu_dev;

	ENTRY;

	if (ldt != NULL && d != NULL) {
		struct lu_env *env = lu_env_find();
		struct lu_env _env;

		if (!env) {
			env = &_env;
			rc = lu_env_init(env, ldt->ldt_ctx_tags);
			LASSERT(rc == 0);
			lu_env_add(env);
		}
		ldt->ldt_ops->ldto_device_fini(env, d);
		if (env == &_env) {
			lu_env_remove(env);
			lu_env_fini(env);
		}
	}

	if (!obd->obd_type->typ_dt_ops->o_precleanup)
		RETURN(0);

	rc = obd->obd_type->typ_dt_ops->o_precleanup(obd);
	RETURN(rc);
}

static inline int obd_cleanup(struct obd_device *obd)
{
	int rc;
	struct lu_device_type *ldt = obd->obd_type->typ_lu;
	struct lu_device *d = obd->obd_lu_dev;

	ENTRY;
	if (ldt != NULL && d != NULL) {
		struct lu_env env;

		rc = lu_env_init(&env, ldt->ldt_ctx_tags);
		if (rc == 0) {
			ldt->ldt_ops->ldto_device_free(&env, d);
			lu_env_fini(&env);
			obd->obd_lu_dev = NULL;
		}
	}
	if (!obd->obd_type->typ_dt_ops->o_cleanup)
		RETURN(0);

	rc = obd->obd_type->typ_dt_ops->o_cleanup(obd);
	RETURN(rc);
}

static inline void obd_cleanup_client_import(struct obd_device *obd)
{
	ENTRY;

	/* If we set up but never connected, the client import will not
	 * have been cleaned.
	 */
	down_write(&obd->u.cli.cl_sem);
	if (obd->u.cli.cl_import) {
		struct obd_import *imp;

		imp = obd->u.cli.cl_import;
		CDEBUG(D_CONFIG, "%s: client import never connected\n",
		       obd->obd_name);
		ptlrpc_invalidate_import(imp);
		client_destroy_import(imp);
		obd->u.cli.cl_import = NULL;
	}
	up_write(&obd->u.cli.cl_sem);

	EXIT;
}

static inline int obd_process_config(struct obd_device *obd, int datalen,
				     void *data)
{
	int rc;
	struct lu_device_type *ldt = obd->obd_type->typ_lu;
	struct lu_device *d = obd->obd_lu_dev;

	ENTRY;

	obd->obd_process_conf = 1;
	if (ldt != NULL && d != NULL) {
		struct lu_env env;

		rc = lu_env_init(&env, ldt->ldt_ctx_tags);
		if (rc == 0) {
			rc = d->ld_ops->ldo_process_config(&env, d, data);
			lu_env_fini(&env);
		}
	} else {
		if (!obd->obd_type->typ_dt_ops->o_process_config) {
			CERROR("%s: no %s operation\n",
			       obd->obd_name, __func__);
			RETURN(-EOPNOTSUPP);
		}
		rc = obd->obd_type->typ_dt_ops->o_process_config(obd, datalen,
								 data);
	}

	obd->obd_process_conf = 0;

	RETURN(rc);
}

static inline int obd_create(const struct lu_env *env, struct obd_export *exp,
			     struct obdo *obdo)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_create) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_create(env, exp, obdo);
	RETURN(rc);
}

static inline int obd_destroy(const struct lu_env *env, struct obd_export *exp,
			      struct obdo *obdo)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_destroy) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_destroy(env, exp, obdo);
	RETURN(rc);
}

static inline int obd_getattr(const struct lu_env *env, struct obd_export *exp,
			      struct obdo *oa)
{
	int rc;

	ENTRY;
	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_getattr) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_getattr(env, exp, oa);

	RETURN(rc);
}

static inline int obd_setattr(const struct lu_env *env, struct obd_export *exp,
			      struct obdo *oa)
{
	int rc;

	ENTRY;
	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_setattr) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_setattr(env, exp, oa);

	RETURN(rc);
}

static inline int obd_add_conn(struct obd_import *imp, struct obd_uuid *uuid,
			       int priority)
{
	struct obd_device *obd = imp->imp_obd;
	int rc;

	ENTRY;

	OBD_CHECK_DEV_ACTIVE(obd);
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_add_conn) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	rc = obd->obd_type->typ_dt_ops->o_add_conn(imp, uuid, priority);
	RETURN(rc);
}

static inline int obd_del_conn(struct obd_import *imp, struct obd_uuid *uuid)
{
	struct obd_device *obd = imp->imp_obd;
	int rc;

	ENTRY;

	OBD_CHECK_DEV_ACTIVE(obd);
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_del_conn) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	rc = obd->obd_type->typ_dt_ops->o_del_conn(imp, uuid);
	RETURN(rc);
}

static inline struct obd_uuid *obd_get_uuid(struct obd_export *exp)
{
	struct obd_uuid *uuid;

	ENTRY;

	if (!exp->exp_obd->obd_type ||
	    !exp->exp_obd->obd_type->typ_dt_ops->o_get_uuid)
		RETURN(NULL);

	uuid = exp->exp_obd->obd_type->typ_dt_ops->o_get_uuid(exp);
	RETURN(uuid);
}

/** Create a new /a exp on device /a obd for the uuid /a cluuid
 * @param exp New export handle
 * @param d Connect data, supported flags are set, flags also understood
 *    by obd are returned.
 */
static inline int obd_connect(const struct lu_env *env,
			      struct obd_export **exp, struct obd_device *obd,
			      struct obd_uuid *cluuid,
			      struct obd_connect_data *data,
			      void *localdata)
{
	int rc;
	__u64 ocf = data ? data->ocd_connect_flags : 0;

	ENTRY;

	OBD_CHECK_DEV_ACTIVE(obd);
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_connect) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	rc = obd->obd_type->typ_dt_ops->o_connect(env, exp, obd, cluuid, data,
						  localdata);
	/* check that only subset is granted */
	LASSERT(ergo(data != NULL, (data->ocd_connect_flags & ocf) ==
				    data->ocd_connect_flags));
	RETURN(rc);
}

static inline int obd_reconnect(const struct lu_env *env,
				struct obd_export *exp,
				struct obd_device *obd,
				struct obd_uuid *cluuid,
				struct obd_connect_data *d,
				void *localdata)
{
	int rc;
	__u64 ocf = d ? d->ocd_connect_flags : 0;

	ENTRY;

	OBD_CHECK_DEV_ACTIVE(obd);
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_reconnect)
		RETURN(0);

	rc = obd->obd_type->typ_dt_ops->o_reconnect(env, exp, obd, cluuid, d,
						    localdata);
	/* check that only subset is granted */
	LASSERT(ergo(d != NULL,
		     (d->ocd_connect_flags & ocf) == d->ocd_connect_flags));
	RETURN(rc);
}

static inline int obd_disconnect(struct obd_export *exp)
{
	int rc;

	ENTRY;
	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_disconnect) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_disconnect(exp);
	RETURN(rc);
}

static inline int obd_fid_alloc(const struct lu_env *env,
				struct obd_export *exp,
				struct lu_fid *fid,
				struct md_op_data *op_data)
{
	int rc;

	ENTRY;
	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_fid_alloc) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_fid_alloc(env, exp, fid,
							     op_data);
	RETURN(rc);
}

static inline int obd_pool_new(struct obd_device *obd, char *poolname)
{
	int rc;

	ENTRY;

	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_pool_new) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	/* Check poolname validity */
	if (!poolname || poolname[0] == '\0' || lov_pool_is_reserved(poolname))
		RETURN(-EINVAL);

	rc = obd->obd_type->typ_dt_ops->o_pool_new(obd, poolname);
	RETURN(rc);
}

static inline int obd_pool_del(struct obd_device *obd, char *poolname)
{
	int rc;

	ENTRY;
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_pool_del) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	rc = obd->obd_type->typ_dt_ops->o_pool_del(obd, poolname);
	RETURN(rc);
}

static inline int obd_pool_add(struct obd_device *obd, char *poolname,
			       char *ostname)
{
	int rc;

	ENTRY;

	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_pool_add) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	rc = obd->obd_type->typ_dt_ops->o_pool_add(obd, poolname, ostname);
	RETURN(rc);
}

static inline int obd_pool_rem(struct obd_device *obd, char *poolname,
			       char *ostname)
{
	int rc;

	ENTRY;
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_pool_rem) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	rc = obd->obd_type->typ_dt_ops->o_pool_rem(obd, poolname, ostname);
	RETURN(rc);
}

static inline int obd_init_export(struct obd_export *exp)
{
	int rc = 0;

	ENTRY;
	if (exp->exp_obd != NULL && exp->exp_obd->obd_type &&
	    exp->exp_obd->obd_type->typ_dt_ops->o_init_export)
		rc = exp->exp_obd->obd_type->typ_dt_ops->o_init_export(exp);
	RETURN(rc);
}

static inline int obd_destroy_export(struct obd_export *exp)
{
	ENTRY;
	if (exp->exp_obd != NULL && exp->exp_obd->obd_type &&
	    exp->exp_obd->obd_type->typ_dt_ops->o_destroy_export)
		exp->exp_obd->obd_type->typ_dt_ops->o_destroy_export(exp);
	RETURN(0);
}

/* @max_age is the oldest time in seconds that we accept using a cached data.
 * If the cache is older than @max_age we will get a new value from the
 * target. Use a value of 'ktime_get_seconds() + X' to guarantee freshness.
 */
static inline int obd_statfs_async(struct obd_export *exp,
				   struct obd_info *oinfo,
				   time64_t max_age,
				   struct ptlrpc_request_set *rqset)
{
	struct obd_device *obd;
	int rc = 0;

	ENTRY;

	if (exp == NULL || exp->exp_obd == NULL)
		RETURN(-EINVAL);

	obd = exp->exp_obd;
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_statfs) {
		rc = -EOPNOTSUPP;
		CERROR("%s: no statfs operation: rc = %d\n", obd->obd_name, rc);
		RETURN(rc);
	}

	CDEBUG(D_SUPER, "%s: age %lld, max_age %lld\n",
	       obd->obd_name, obd->obd_osfs_age, max_age);
	rc = obd->obd_type->typ_dt_ops->o_statfs_async(exp, oinfo, max_age,
						       rqset);

	RETURN(rc);
}

/* @max_age is the oldest time in seconds that we accept using a cached data.
 * If the cache is older than @max_age we will get a new value from the
 * target. Use a value of 'ktime_get_seconds() + X' to guarantee freshness.
 */
static inline int obd_statfs(const struct lu_env *env, struct obd_export *exp,
			     struct obd_statfs *osfs, time64_t max_age,
			     __u32 flags)
{
	struct obd_device *obd;
	int rc = 0;

	ENTRY;
	if (unlikely(exp == NULL || exp->exp_obd == NULL))
		RETURN(-EINVAL);

	obd = exp->exp_obd;
	OBD_CHECK_DEV_ACTIVE(obd);

	if (unlikely(!obd->obd_type || !obd->obd_type->typ_dt_ops->o_statfs)) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	CDEBUG(D_SUPER, "%s: age %lld, max_age %lld\n",
	       obd->obd_name, obd->obd_osfs_age, max_age);
	/* ignore cache if aggregated isn't expected */
	if (obd->obd_osfs_age < max_age ||
	    ((obd->obd_osfs.os_state & OS_STATFS_SUM) &&
	     !(flags & OBD_STATFS_SUM))) {
		/* the RPC will block anyway, so avoid sending many at once */
		rc = mutex_lock_interruptible_nested(&obd->obd_dev_mutex,
						     (flags & OBD_STATFS_NESTED)
						     ? SINGLE_DEPTH_NESTING : 0);
		if (rc)
			RETURN(rc);
		if (obd->obd_osfs_age < max_age ||
		    ((obd->obd_osfs.os_state & OS_STATFS_SUM) &&
		     !(flags & OBD_STATFS_SUM))) {
			rc = obd->obd_type->typ_dt_ops->o_statfs(env, exp, osfs,
								 max_age,
								 flags);
		} else {
			mutex_unlock(&obd->obd_dev_mutex);
			GOTO(cached, rc = 0);
		}
		if (rc == 0) {
			CDEBUG(D_SUPER,
			       "%s: update %p cache blocks %llu/%llu objects %llu/%llu\n",
			       obd->obd_name, &obd->obd_osfs,
			       osfs->os_bavail, osfs->os_blocks,
			       osfs->os_ffree, osfs->os_files);

			spin_lock(&obd->obd_osfs_lock);
			memcpy(&obd->obd_osfs, osfs, sizeof(obd->obd_osfs));
			obd->obd_osfs_age = ktime_get_seconds();
			spin_unlock(&obd->obd_osfs_lock);
		}
		mutex_unlock(&obd->obd_dev_mutex);
	} else {
cached:
		CDEBUG(D_SUPER,
		       "%s: use %p cache blocks %llu/%llu objects %llu/%llu\n",
		       obd->obd_name, &obd->obd_osfs,
		       obd->obd_osfs.os_bavail, obd->obd_osfs.os_blocks,
		       obd->obd_osfs.os_ffree, obd->obd_osfs.os_files);
		spin_lock(&obd->obd_osfs_lock);
		memcpy(osfs, &obd->obd_osfs, sizeof(*osfs));
		spin_unlock(&obd->obd_osfs_lock);
	}
	RETURN(rc);
}

static inline int obd_preprw(const struct lu_env *env, int cmd,
			     struct obd_export *exp, struct obdo *oa,
			     int objcount, struct obd_ioobj *obj,
			     struct niobuf_remote *remote, int *pages,
			     struct niobuf_local *local)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_preprw) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_preprw(env, cmd, exp,
							  oa, objcount, obj,
							  remote, pages, local);

	RETURN(rc);
}

static inline int obd_commitrw(const struct lu_env *env, int cmd,
			       struct obd_export *exp, struct obdo *oa,
			       int objcount, struct obd_ioobj *obj,
			       struct niobuf_remote *rnb, int pages,
			       struct niobuf_local *local, const int orig_rc,
			       int nob, ktime_t kstart)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_commitrw) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_commitrw(env, cmd, exp, oa,
							    objcount, obj,
							    rnb, pages, local,
							    orig_rc, nob,
							    kstart);

	RETURN(rc);
}

static inline int obd_iocontrol(unsigned int cmd, struct obd_export *exp,
				int len, void *karg, void __user *uarg)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_iocontrol) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_iocontrol(cmd, exp,
							     len, karg,
							     uarg);
	RETURN(rc);
}

static inline void obd_import_event(struct obd_device *obd,
				    struct obd_import *imp,
				    enum obd_import_event event)
{
	ENTRY;
	if (!obd) {
		CERROR("NULL device\n");
		EXIT;
		return;
	}

	if (obd->obd_set_up && obd->obd_type->typ_dt_ops->o_import_event)
		obd->obd_type->typ_dt_ops->o_import_event(obd, imp, event);

	EXIT;
}

static inline int obd_notify(struct obd_device *obd,
			     struct obd_device *watched,
			     enum obd_notify_event ev)
{
	int rc;

	ENTRY;

	rc = obd_check_dev(obd);
	if (rc)
		return rc;

	if (!obd->obd_set_up) {
		CDEBUG(D_HA, "obd %s not set up\n", obd->obd_name);
		RETURN(-EINVAL);
	}

	if (!obd->obd_type->typ_dt_ops->o_notify) {
		CDEBUG(D_HA, "obd %s has no notify handler\n", obd->obd_name);
		RETURN(-ENOSYS);
	}

	rc = obd->obd_type->typ_dt_ops->o_notify(obd, watched, ev);

	RETURN(rc);
}

static inline int obd_notify_observer(struct obd_device *observer,
				      struct obd_device *observed,
				      enum obd_notify_event ev)
{
	int rc = 0;
	int rc2 = 0;
	struct obd_notify_upcall *onu;

	if (WARN_ON_ONCE(!observer))
		return -ENODEV;

	if (observer->obd_observer)
		rc = obd_notify(observer->obd_observer, observed, ev);

	/*
	 * Also, call non-obd listener, if any
	 */
	onu = &observer->obd_upcall;
	if (onu->onu_upcall != NULL)
		rc2 = onu->onu_upcall(observer, observed, ev, onu->onu_owner);

	return rc ? rc : rc2;
}

static inline int obd_quotactl(struct obd_export *exp,
			       struct obd_quotactl *oqctl)
{
	int rc;

	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_quotactl) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = exp->exp_obd->obd_type->typ_dt_ops->o_quotactl(exp->exp_obd,
							    exp, oqctl);
	RETURN(rc);
}

static inline int obd_quota_iter(struct obd_export *exp,
				 struct obd_quotactl *oqctl,
				 struct list_head *list)
{
	int rc = 0;

	do {
		oqctl->qc_iter_list = (__u64)list;
		rc = obd_quotactl(exp, oqctl);
		if (rc)
			break;

	} while (oqctl->qc_iter_md_offset || oqctl->qc_iter_dt_offset);

	return rc;
}

static inline int obd_health_check(const struct lu_env *env,
				   struct obd_device *obd)
{
	/* returns: 0 on healthy
	 *	   >0 on unhealthy + reason code/flag
	 *	      however the only suppored reason == 1 right now
	 *	      We'll need to define some better reasons
	 *	      or flags in the future.
	 *	   <0 on error
	 */
	int rc;

	ENTRY;

	/* NULL method is normal here */
	if (obd == NULL || !obd->obd_type) {
		CERROR("cleaned up obd\n");
		RETURN(-EOPNOTSUPP);
	}
	if (!obd->obd_set_up || obd->obd_stopping)
		RETURN(0);
	if (!obd->obd_type->typ_dt_ops->o_health_check)
		RETURN(0);

	rc = obd->obd_type->typ_dt_ops->o_health_check(env, obd);
	RETURN(rc);
}

static inline int obd_register_observer(struct obd_device *obd,
					struct obd_device *observer)
{
	int rc;

	ENTRY;

	rc = obd_check_dev(obd);
	if (rc)
		return rc;

	down_write(&obd->obd_observer_link_sem);
	if (obd->obd_observer && observer) {
		up_write(&obd->obd_observer_link_sem);
		RETURN(-EALREADY);
	}
	obd->obd_observer = observer;
	up_write(&obd->obd_observer_link_sem);
	RETURN(0);
}

/* metadata helpers */
enum mps_stat_idx {
	LPROC_MD_CLOSE,
	LPROC_MD_CREATE,
	LPROC_MD_ENQUEUE,
	LPROC_MD_GETATTR,
	LPROC_MD_INTENT_LOCK,
	LPROC_MD_LINK,
	LPROC_MD_RENAME,
	LPROC_MD_SETATTR,
	LPROC_MD_FSYNC,
	LPROC_MD_READ_PAGE,
	LPROC_MD_UNLINK,
	LPROC_MD_SETXATTR,
	LPROC_MD_GETXATTR,
	LPROC_MD_INTENT_GETATTR_ASYNC,
	LPROC_MD_REVALIDATE_LOCK,
	LPROC_MD_LAST_OPC,
};

static inline int md_get_root(struct obd_export *exp, const char *fileset,
			      struct lu_fid *fid)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_get_root(exp, fileset,
							      fid);
}

static inline int md_getattr(struct obd_export *exp,
			     struct md_op_data *op_data,
			     struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_GETATTR);

	return exp->exp_obd->obd_type->typ_md_ops->m_getattr(exp, op_data,
							     request);
}

static inline int md_null_inode(struct obd_export *exp,
				   const struct lu_fid *fid)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_null_inode(exp, fid);
}

static inline int md_close(struct obd_export *exp, struct md_op_data *op_data,
			   struct md_open_data *mod,
			   struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_CLOSE);

	return exp->exp_obd->obd_type->typ_md_ops->m_close(exp, op_data, mod,
							   request);
}

static inline int md_create(struct obd_export *exp, struct md_op_data *op_data,
			    const void *data, size_t datalen, umode_t mode,
			    uid_t uid, gid_t gid, kernel_cap_t cap_effective,
			    __u64 rdev, struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_CREATE);

	return exp->exp_obd->obd_type->typ_md_ops->m_create(exp, op_data, data,
							    datalen, mode, uid,
							    gid, cap_effective,
							    rdev, request);
}

static inline int md_enqueue(struct obd_export *exp,
			     struct ldlm_enqueue_info *einfo,
			     const union ldlm_policy_data *policy,
			     struct md_op_data *op_data,
			     struct lustre_handle *lockh,
			     __u64 extra_lock_flags)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_ENQUEUE);

	return exp->exp_obd->obd_type->typ_md_ops->m_enqueue(exp, einfo, policy,
							     op_data, lockh,
							     extra_lock_flags);
}

static inline int md_getattr_name(struct obd_export *exp,
				  struct md_op_data *op_data,
				  struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_getattr_name(exp, op_data,
								  request);
}

static inline int md_intent_lock(struct obd_export *exp,
				 struct md_op_data *op_data,
				 struct lookup_intent *it,
				 struct ptlrpc_request **reqp,
				 ldlm_blocking_callback cb_blocking,
				 __u64 extra_lock_flags)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_INTENT_LOCK);

	return exp->exp_obd->obd_type->typ_md_ops->m_intent_lock(exp, op_data,
								 it, reqp,
								 cb_blocking,
								 extra_lock_flags);
}

static inline int md_link(struct obd_export *exp, struct md_op_data *op_data,
			  struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_LINK);

	return exp->exp_obd->obd_type->typ_md_ops->m_link(exp, op_data,
							  request);
}

static inline int md_rename(struct obd_export *exp, struct md_op_data *op_data,
			    const char *old_name, size_t oldlen,
			    const char *new_name, size_t newlen,
			    struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_RENAME);

	return exp->exp_obd->obd_type->typ_md_ops->m_rename(exp, op_data,
							    old_name,
							    oldlen, new_name,
							    newlen, request);
}

static inline int md_setattr(struct obd_export *exp, struct md_op_data *op_data,
			     void *ea, size_t ealen,
			     struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_SETATTR);

	return exp->exp_obd->obd_type->typ_md_ops->m_setattr(exp, op_data, ea,
							     ealen, request);
}

static inline int md_fsync(struct obd_export *exp, const struct lu_fid *fid,
			   struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_FSYNC);

	return exp->exp_obd->obd_type->typ_md_ops->m_fsync(exp, fid, request);
}

/* FLR: resync mirrored files. */
static inline int md_file_resync(struct obd_export *exp,
				 struct md_op_data *data)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_file_resync(exp, data);
}

static inline int md_read_page(struct obd_export *exp,
			       struct md_op_data *op_data,
			       struct md_readdir_info *mrinfo,
			       __u64  hash_offset, struct page **ppage)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_READ_PAGE);

	return exp->exp_obd->obd_type->typ_md_ops->m_read_page(exp, op_data,
							       mrinfo,
							       hash_offset,
							       ppage);
}

static inline int md_unlink(struct obd_export *exp, struct md_op_data *op_data,
			    struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_UNLINK);

	return exp->exp_obd->obd_type->typ_md_ops->m_unlink(exp, op_data,
							    request);
}

static inline int md_get_lustre_md(struct obd_export *exp,
				   struct req_capsule *pill,
				   struct obd_export *dt_exp,
				   struct obd_export *md_exp,
				   struct lustre_md *md)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_get_lustre_md(exp, pill,
								   dt_exp,
								   md_exp, md);
}

static inline int md_put_lustre_md(struct obd_export *exp,
				    struct lustre_md *md)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_put_lustre_md(exp, md);
}

static inline int md_merge_attr(struct obd_export *exp,
				const struct lmv_stripe_object *lso,
				struct cl_attr *attr,
				ldlm_blocking_callback cb)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_merge_attr(exp, lso, attr,
								cb);
}

static inline int md_setxattr(struct obd_export *exp, const struct lu_fid *fid,
			      u64 obd_md_valid, const char *name,
			      const void *value, size_t value_size,
			      unsigned int xattr_flags, u32 suppgid,
			      struct ptlrpc_request **req)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_SETXATTR);

	return exp->exp_obd->obd_type->typ_md_ops->m_setxattr(exp, fid,
							      obd_md_valid,
							      name, value,
							      value_size,
							      xattr_flags,
							      suppgid,
							      req);
}

static inline int md_getxattr(struct obd_export *exp, const struct lu_fid *fid,
			      u64 obd_md_valid, const char *name,
			      size_t buf_size, struct ptlrpc_request **req)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_GETXATTR);

	return exp->exp_obd->obd_type->typ_md_ops->m_getxattr(exp, fid,
							      obd_md_valid,
							      name, buf_size,
							      req);
}

static inline int md_set_open_replay_data(struct obd_export *exp,
					  struct obd_client_handle *och,
					  struct lookup_intent *it)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_set_open_replay_data(exp,
									  och,
									  it);
}

static inline int md_clear_open_replay_data(struct obd_export *exp,
					    struct obd_client_handle *och)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_clear_open_replay_data(exp, och);
}

static inline int md_set_lock_data(struct obd_export *exp,
				   const struct lustre_handle *lockh,
				   void *data, __u64 *bits)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_set_lock_data(exp, lockh,
								   data,
								   bits);
}

static inline
int md_cancel_unused(struct obd_export *exp, const struct lu_fid *fid,
		     union ldlm_policy_data *policy, enum ldlm_mode mode,
		     enum ldlm_cancel_flags cancel_flags, void *opaque)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_cancel_unused(exp,
								   fid, policy,
								   mode,
								   cancel_flags,
								   opaque);
}

static inline enum ldlm_mode md_lock_match(struct obd_export *exp, __u64 flags,
					   const struct lu_fid *fid,
					   enum ldlm_type type,
					   union ldlm_policy_data *policy,
					   enum ldlm_mode mode,
					   struct lustre_handle *lockh)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_lock_match(exp, flags,
								fid, type,
								policy, mode,
								lockh);
}

static inline int md_init_ea_size(struct obd_export *exp, __u32 ea_size,
				  __u32 def_ea_size)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_init_ea_size(exp, ea_size,
								  def_ea_size);
}

static inline int md_intent_getattr_async(struct obd_export *exp,
					  struct md_op_item *item)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_INTENT_GETATTR_ASYNC);

	return exp->exp_obd->obd_type->typ_md_ops->m_intent_getattr_async(exp,
									  item);
}

static inline int md_revalidate_lock(struct obd_export *exp,
				     struct lookup_intent *it,
				     struct lu_fid *fid, __u64 *bits)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_REVALIDATE_LOCK);

	return exp->exp_obd->obd_type->typ_md_ops->m_revalidate_lock(exp,
								     it, fid,
								     bits);
}

static inline int md_get_fid_from_lsm(struct obd_export *exp,
				      const struct lmv_stripe_object *lso,
				      const char *name, int namelen,
				      struct lu_fid *fid)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_get_fid_from_lsm(exp,
								      lso, name,
								      namelen,
								      fid);
}

/* Unpack an MD struct from disk to in-memory format.
 * Returns +ve size of unpacked MD (0 for free), or -ve error.
 *
 * If *plsm != NULL and lmm == NULL then *lsm will be freed.
 * If *plsm == NULL then it will be allocated.
 */
static inline int md_stripe_object_create(struct obd_export *exp,
					  struct lmv_stripe_object **lsop,
					  const union lmv_mds_md *lmm,
					  size_t lmm_size)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_stripe_object_create(exp,
									  lsop,
									  lmm,
									  lmm_size);
}

static inline int md_rmfid(struct obd_export *exp, struct fid_array *fa,
			   int *rcs, struct ptlrpc_request_set *set)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_rmfid(exp, fa, rcs, set);
}

static inline struct lu_batch *
md_batch_create(struct obd_export *exp, enum lu_batch_flags flags,
		__u32 max_count)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return ERR_PTR(rc);

	return exp->exp_obd->obd_type->typ_md_ops->m_batch_create(exp, flags,
								  max_count);
}

static inline int md_batch_stop(struct obd_export *exp, struct lu_batch *bh)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_batch_stop(exp, bh);
}

static inline int md_batch_flush(struct obd_export *exp, struct lu_batch *bh,
				 bool wait)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_batch_flush(exp, bh, wait);
}

static inline int md_batch_add(struct obd_export *exp, struct lu_batch *bh,
			       struct md_op_item *item)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return exp->exp_obd->obd_type->typ_md_ops->m_batch_add(exp, bh, item);
}

/* OBD Metadata Support */

extern int obd_init_caches(void);
extern void obd_cleanup_caches(void);

typedef int (*register_lwp_cb)(void *data);

struct lwp_register_item {
	struct obd_export **lri_exp;
	register_lwp_cb	    lri_cb_func;
	void		   *lri_cb_data;
	struct list_head    lri_list;
	atomic_t	    lri_ref;
	char		    lri_name[MTI_NAME_MAXLEN];
};

/* obd_mount.c */
#ifdef HAVE_SERVER_SUPPORT
int lustre_register_lwp_item(const char *lwpname, struct obd_export **exp,
			     register_lwp_cb cb_func, void *cb_data);
void lustre_deregister_lwp_item(struct obd_export **exp);
struct obd_export *lustre_find_lwp_by_index(const char *dev, __u32 idx);
void lustre_notify_lwp_list(struct obd_export *exp);
int tgt_name2lwp_name(const char *tgt_name, char *lwp_name, int len, __u32 idx);
#endif /* HAVE_SERVER_SUPPORT */
int lustre_check_exclusion(struct super_block *sb, char *svname);

/* lustre_peer.c    */
int lustre_uuid_to_peer(const char *uuid, struct lnet_nid *peer_nid,
			int index);
int class_add_uuid(const char *uuid, struct lnet_nid *nid);
int class_del_uuid (const char *uuid);
int class_add_nids_to_uuid(struct obd_uuid *uuid, struct lnet_nid *nidlist,
			   int nid_count, int nid_size);
int class_check_uuid(struct obd_uuid *uuid, struct lnet_nid *nid);

/* class_obd.c */
extern char obd_jobid_name[];

extern unsigned int obd_lbug_on_eviction;
extern unsigned int obd_dump_on_eviction;

static inline bool do_dump_on_eviction(struct obd_device *exp_obd)
{
	if (obd_lbug_on_eviction &&
	    strncmp(exp_obd->obd_type->typ_name, LUSTRE_MGC_NAME,
		    strlen(LUSTRE_MGC_NAME))) {
		CERROR("LBUG upon eviction\n");
		LBUG();
	}

	return obd_dump_on_eviction;
}

/* statfs_pack.c */
struct kstatfs;
void statfs_pack(struct obd_statfs *osfs, struct kstatfs *sfs);
void statfs_unpack(struct kstatfs *sfs, struct obd_statfs *osfs);

/* root squash info */
struct root_squash_info {
	uid_t			rsi_uid;
	gid_t			rsi_gid;
	struct list_head	rsi_nosquash_nids;
	spinlock_t		rsi_lock;
};

int server_name2index(const char *svname, __u32 *idx, const char **endptr);

/* linux-module.c */
struct obd_ioctl_data;
int obd_ioctl_getdata(struct obd_ioctl_data **data, int *len, void __user *arg);
int class_procfs_init(void);
int class_procfs_clean(void);

extern void obd_heat_add(struct obd_heat_instance *instance,
			 unsigned int time_second, __u64 count,
			 unsigned int weight, unsigned int period_second);
extern void obd_heat_decay(struct obd_heat_instance *instance,
			   __u64 time_second, unsigned int weight,
			   unsigned int period_second);
extern __u64 obd_heat_get(struct obd_heat_instance *instance,
			  unsigned int time_second, unsigned int weight,
			  unsigned int period_second);
extern void obd_heat_clear(struct obd_heat_instance *instance, int count);

/* struct kobj_type */
static inline
struct attribute *_get_attr_matches(const struct kobj_type *typ,
				    const char *key, size_t keylen,
				    int (*is_match)(const char *, const char *,
						    size_t))
{
	int i;

#ifdef HAVE_KOBJ_TYPE_DEFAULT_GROUPS
	for (i = 0; typ->default_groups[i]; i++) {
		int k;
		struct attribute **attrs;

		attrs = (struct attribute **)typ->default_groups[i]->attrs;
		for (k = 0; attrs[k]; k++) {
			if (is_match(attrs[k]->name, key, keylen))
				return (struct attribute *)attrs[k];
		}
	}
#else
	for (i = 0; typ->default_attrs[i]; i++) {
		if (is_match(typ->default_attrs[i]->name, key, keylen))
			return typ->default_attrs[i];
	}
#endif
	return NULL;
}

static inline
int _attr_name_exact(const char *attr_name, const char *key, size_t len)
{
	return !strcmp(attr_name, key);
}

static inline
struct attribute *get_attr_by_name(const struct kobj_type *typ,
				   const char *name)
{
	return _get_attr_matches(typ, name, 0, _attr_name_exact);
}

static inline
int _attr_name_starts_with(const char *attr_name, const char *name, size_t len)
{
	return !strncmp(attr_name, name, len);
}

static inline
struct attribute *get_attr_starts_with(const struct kobj_type *typ,
				       const char *name,
				       size_t len)
{
	return _get_attr_matches(typ, name, len, _attr_name_starts_with);
}

int obd_ioctl_msg(const char *file, const char *func, int line, int level,
		  const char *name, unsigned int cmd, const char *msg, int rc);
#define OBD_IOC_DEBUG(level, dev, cmd, msg, rc)	\
	obd_ioctl_msg(__FILE__, __func__, __LINE__, level, dev, cmd, msg, rc)
#define OBD_IOC_ERROR(dev, cmd, msg, rc)	\
	obd_ioctl_msg(__FILE__, __func__, __LINE__, D_ERROR, dev, cmd, msg, rc)

/* ldlm/ldlm_lib.c */
void target_recovery_fini(struct obd_device *obd);
void target_recovery_init(struct lu_target *lut, svc_handler_t handler);


#endif /* __LINUX_OBD_CLASS_H */
