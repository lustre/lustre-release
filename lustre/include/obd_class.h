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
 * Lustre is a trademark of Sun Microsystems, Inc.
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

#define OBD_STATFS_NODELAY      0x0001  /* requests should be send without delay
                                         * and resends for avoid deadlocks */
#define OBD_STATFS_FROM_CACHE   0x0002  /* the statfs callback should not update
                                         * obd_osfs_age */
#define OBD_STATFS_FOR_MDT0	0x0004	/* The statfs is only for retrieving
					 * information from MDT0. */
#define OBD_STATFS_SUM		0x0008	/* get aggregated statfs from MDT */

extern rwlock_t obd_dev_lock;

/* OBD Operations Declarations */
extern struct obd_device *class_conn2obd(struct lustre_handle *);
extern struct obd_device *class_exp2obd(struct obd_export *);
extern int class_handle_ioctl(unsigned int cmd, unsigned long arg);
int lustre_get_jobid(char *jobid, size_t len);
void lustre_jobid_clear(const char *jobid);
void jobid_cache_fini(void);
int jobid_cache_init(void);

struct lu_device_type;

/* genops.c */
struct obd_export *class_conn2export(struct lustre_handle *);
struct kobject *class_setup_tunables(const char *name);
int class_register_type(struct obd_ops *, struct md_ops *, bool enable_proc,
			struct lprocfs_vars *module_vars,
			const char *nm, struct lu_device_type *ldt);
int class_unregister_type(const char *nm);

struct obd_device *class_newdev(const char *type_name, const char *name,
				const char *uuid);
int class_register_device(struct obd_device *obd);
void class_unregister_device(struct obd_device *obd);
void class_free_dev(struct obd_device *obd);

struct obd_device *class_dev_by_str(const char *str);
int class_name2dev(const char *name);
struct obd_device *class_name2obd(const char *name);
int class_uuid2dev(struct obd_uuid *uuid);
struct obd_device *class_uuid2obd(struct obd_uuid *uuid);
void class_obd_list(void);
struct obd_device * class_find_client_obd(struct obd_uuid *tgt_uuid,
                                          const char * typ_name,
                                          struct obd_uuid *grp_uuid);
struct obd_device * class_devices_in_group(struct obd_uuid *grp_uuid,
                                           int *next);
struct obd_device * class_num2obd(int num);
int get_devices_count(void);

int class_notify_sptlrpc_conf(const char *fsname, int namelen);

static inline char *obd_export_nid2str(struct obd_export *exp)
{
	return exp->exp_connection == NULL ?
	       "<unknown>" : libcfs_nid2str(exp->exp_connection->c_peer.nid);
}

static inline char *obd_import_nid2str(struct obd_import *imp)
{
	return imp->imp_connection == NULL ?
	       "<unknown>" : libcfs_nid2str(imp->imp_connection->c_peer.nid);
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

__u16 obd_get_mod_rpc_slot(struct client_obd *cli, __u32 opc,
			   struct lookup_intent *it);
void obd_put_mod_rpc_slot(struct client_obd *cli, __u32 opc,
			  struct lookup_intent *it, __u16 tag);

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

char *lustre_cfg_string(struct lustre_cfg *lcfg, u32 index);
struct lustre_cfg *lustre_cfg_rename(struct lustre_cfg *cfg,
				     const char *new_name);
void print_lustre_cfg(struct lustre_cfg *lcfg);
int class_process_config(struct lustre_cfg *lcfg);
ssize_t class_set_global(const char *param);
ssize_t class_modify_config(struct lustre_cfg *lcfg, const char *prefix,
			    struct kobject *kobj);
int class_process_proc_param(char *prefix, struct lprocfs_vars *lvars,
			     struct lustre_cfg *lcfg, void *data);
int class_attach(struct lustre_cfg *lcfg);
int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg);
int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg);
int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg);

int class_find_param(char *buf, char *key, char **valp);
struct cfg_interop_param *class_find_old_param(const char *param,
					       struct cfg_interop_param *ptr);
int class_get_next_param(char **params, char *copy);
int class_match_param(char *buf, const char *key, char **valp);
int class_parse_nid(char *buf, lnet_nid_t *nid, char **endh);
int class_parse_nid_quiet(char *buf, lnet_nid_t *nid, char **endh);
int class_parse_net(char *buf, u32 *net, char **endh);
int class_match_nid(char *buf, char *key, lnet_nid_t nid);
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

#define CFG_F_START     0x01   /* Set when we start updating from a log */
#define CFG_F_MARKER    0x02   /* We are within a maker */
#define CFG_F_SKIP      0x04   /* We should ignore this cfg command */
#define CFG_F_EXCLUDE   0x10   /* OST exclusion list */

/* Passed as data param to class_config_parse_llog */
struct config_llog_instance {
	char			*cfg_obdname;
	void			*cfg_instance;
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
	struct config_llog_instance cld_cfg;
	struct list_head	    cld_list_chain;/* on config_llog_list */
	atomic_t		    cld_refcount;
	struct config_llog_data    *cld_sptlrpc;/* depended sptlrpc log */
	struct config_llog_data    *cld_params;	/* common parameters log */
	struct config_llog_data    *cld_recover;/* imperative recover log */
	struct config_llog_data    *cld_nodemap;/* nodemap log */
	struct config_llog_data    *cld_barrier;/* barrier log (for MDT only) */
	struct obd_export	   *cld_mgcexp;
	struct mutex		    cld_lock;
	int			    cld_type;
	unsigned int		    cld_stopping:1, /* we were told to stop
						     * watching */
				    cld_lostlock:1; /* lock not requeued */
	char			    cld_logname[0];
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

#define __class_export_add_lock_ref(exp, lock)             do {} while(0)
#define __class_export_del_lock_ref(exp, lock)             do {} while(0)

#endif

#define class_export_rpc_inc(exp)                                       \
({                                                                      \
	atomic_inc(&(exp)->exp_rpc_count);                          	\
	CDEBUG(D_INFO, "RPC GETting export %p : new rpc_count %d\n",    \
	       (exp), atomic_read(&(exp)->exp_rpc_count));          	\
})

#define class_export_rpc_dec(exp)                                       \
({                                                                      \
	LASSERT_ATOMIC_POS(&exp->exp_rpc_count);                        \
	atomic_dec(&(exp)->exp_rpc_count);                          	\
	CDEBUG(D_INFO, "RPC PUTting export %p : new rpc_count %d\n",    \
	       (exp), atomic_read(&(exp)->exp_rpc_count));          	\
})

#define class_export_lock_get(exp, lock)                                \
({                                                                      \
	atomic_inc(&(exp)->exp_locks_count);                        	\
	__class_export_add_lock_ref(exp, lock);                         \
	CDEBUG(D_INFO, "lock GETting export %p : new locks_count %d\n", \
	       (exp), atomic_read(&(exp)->exp_locks_count));        	\
	class_export_get(exp);                                          \
})

#define class_export_lock_put(exp, lock)                                \
({                                                                      \
	LASSERT_ATOMIC_POS(&exp->exp_locks_count);                      \
	atomic_dec(&(exp)->exp_locks_count);                        	\
	__class_export_del_lock_ref(exp, lock);                         \
	CDEBUG(D_INFO, "lock PUTting export %p : new locks_count %d\n", \
	       (exp), atomic_read(&(exp)->exp_locks_count));        	\
	class_export_put(exp);                                          \
})

#define class_export_cb_get(exp)                                        \
({                                                                      \
	atomic_inc(&(exp)->exp_cb_count);                           	\
	CDEBUG(D_INFO, "callback GETting export %p : new cb_count %d\n",\
	       (exp), atomic_read(&(exp)->exp_cb_count));           	\
	class_export_get(exp);                                          \
})

#define class_export_cb_put(exp)                                        \
({                                                                      \
	LASSERT_ATOMIC_POS(&exp->exp_cb_count);                         \
	atomic_dec(&(exp)->exp_cb_count);                           	\
	CDEBUG(D_INFO, "callback PUTting export %p : new cb_count %d\n",\
	       (exp), atomic_read(&(exp)->exp_cb_count));           	\
	class_export_put(exp);                                          \
})

/* genops.c */
struct obd_export *class_export_get(struct obd_export *exp);
void class_export_put(struct obd_export *exp);
struct obd_export *class_new_export(struct obd_device *obddev,
                                    struct obd_uuid *cluuid);
struct obd_export *class_new_export_self(struct obd_device *obd,
					 struct obd_uuid *uuid);
void class_unlink_export(struct obd_export *exp);

struct obd_import *class_import_get(struct obd_import *);
void class_import_put(struct obd_import *);
struct obd_import *class_new_import(struct obd_device *obd);
void class_destroy_import(struct obd_import *exp);

struct obd_type *class_search_type(const char *name);
struct obd_type *class_get_type(const char *name);
void class_put_type(struct obd_type *type);
int class_connect(struct lustre_handle *conn, struct obd_device *obd,
                  struct obd_uuid *cluuid);
int class_disconnect(struct obd_export *exp);
void class_fail_export(struct obd_export *exp);
int class_connected_export(struct obd_export *exp);
void class_disconnect_exports(struct obd_device *obddev);
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
        LASSERT(exp->exp_obd);
	if (exp->exp_obd->u.obt.obt_magic != OBT_MAGIC)
		return NULL;
        return exp->exp_obd->u.obt.obt_lut;
}

static inline struct lr_server_data *class_server_data(struct obd_device *obd)
{
        LASSERT(obd->u.obt.obt_lut);
        return &obd->u.obt.obt_lut->lut_lsd;
}
#endif

/* obdo.c */
struct lu_attr;
struct inode;

void obdo_from_la(struct obdo *dst, const struct lu_attr *la, u64 valid);
void la_from_obdo(struct lu_attr *la, const struct obdo *dst, u64 valid);

void obdo_cpy_md(struct obdo *dst, const struct obdo *src, u64 valid);
void obdo_to_ioobj(const struct obdo *oa, struct obd_ioobj *ioobj);

#define OBP(dev, op)    (dev)->obd_type->typ_dt_ops->o_ ## op
#define MDP(dev, op)    (dev)->obd_type->typ_md_ops->m_ ## op

/* Ensure obd_setup: used for cleanup which must be called
   while obd is stopping */
#define OBD_CHECK_DEV(obd)                                      \
do {                                                            \
        if (!(obd)) {                                           \
                CERROR("NULL device\n");                        \
                RETURN(-ENODEV);                                \
        }                                                       \
} while (0)

/* ensure obd_setup and !obd_stopping */
#define OBD_CHECK_DEV_ACTIVE(obd)                               \
do {                                                            \
        OBD_CHECK_DEV(obd);                                     \
        if (!(obd)->obd_set_up || (obd)->obd_stopping) {        \
                CERROR("Device %d not setup\n",                 \
                       (obd)->obd_minor);                       \
                RETURN(-ENODEV);                                \
        }                                                       \
} while (0)


static inline int lprocfs_nid_ldlm_stats_init(struct nid_stat* tmp)
{
	/* Always add in ldlm_stats */
	tmp->nid_ldlm_stats =
		lprocfs_alloc_stats(LDLM_LAST_OPC - LDLM_FIRST_OPC,
				    LPROCFS_STATS_FLAG_NOPERCPU);
	if (tmp->nid_ldlm_stats == NULL)
		return -ENOMEM;

	lprocfs_init_ldlm_stats(tmp->nid_ldlm_stats);

	return lprocfs_register_stats(tmp->nid_proc, "ldlm_stats",
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

static inline int class_devno_max(void)
{
	return MAX_OBD_DEVICES;
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

	rc = OBP(exp->exp_obd, get_info)(env, exp, keylen, key, vallen, val);
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

        rc = OBP(exp->exp_obd, set_info_async)(env, exp, keylen, key, vallen,
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
	struct lu_device_type *ldt = obd->obd_type->typ_lu;
	struct lu_device *d;

        ENTRY;

        if (ldt != NULL) {
                struct lu_context  session_ctx;
                struct lu_env env;
                lu_context_init(&session_ctx, LCT_SESSION | LCT_SERVER_SESSION);
                session_ctx.lc_thread = NULL;
                lu_context_enter(&session_ctx);

                rc = lu_env_init(&env, ldt->ldt_ctx_tags);
                if (rc == 0) {
                        env.le_ses = &session_ctx;
                        d = ldt->ldt_ops->ldto_device_alloc(&env, ldt, cfg);
                        lu_env_fini(&env);
                        if (!IS_ERR(d)) {
                                obd->obd_lu_dev = d;
                                d->ld_obd = obd;
                                rc = 0;
                        } else
                                rc = PTR_ERR(d);
                }
                lu_context_exit(&session_ctx);
                lu_context_fini(&session_ctx);

        } else {
		if (!obd->obd_type->typ_dt_ops->o_setup) {
			CERROR("%s: no %s operation\n", obd->obd_name,
			       __func__);
			RETURN(-EOPNOTSUPP);
		}
                rc = OBP(obd, setup)(obd, cfg);
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
		struct lu_env env;

		rc = lu_env_init(&env, ldt->ldt_ctx_tags);
		if (rc == 0) {
			ldt->ldt_ops->ldto_device_fini(&env, d);
			lu_env_fini(&env);
		}
	}

	if (!obd->obd_type->typ_dt_ops->o_precleanup)
		RETURN(0);

	rc = OBP(obd, precleanup)(obd);
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

        rc = OBP(obd, cleanup)(obd);
        RETURN(rc);
}

static inline void obd_cleanup_client_import(struct obd_device *obd)
{
        ENTRY;

        /* If we set up but never connected, the
           client import will not have been cleaned. */
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
                rc = OBP(obd, process_config)(obd, datalen, data);
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

	rc = OBP(exp->exp_obd, create)(env, exp, obdo);
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

	rc = OBP(exp->exp_obd, destroy)(env, exp, obdo);
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

	rc = OBP(exp->exp_obd, getattr)(env, exp, oa);

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

	rc = OBP(exp->exp_obd, setattr)(env, exp, oa);

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

        rc = OBP(obd, add_conn)(imp, uuid, priority);
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

        rc = OBP(obd, del_conn)(imp, uuid);
        RETURN(rc);
}

static inline struct obd_uuid *obd_get_uuid(struct obd_export *exp)
{
        struct obd_uuid *uuid;
        ENTRY;

	if (!exp->exp_obd->obd_type ||
	    !exp->exp_obd->obd_type->typ_dt_ops->o_get_uuid)
		RETURN(NULL);

        uuid = OBP(exp->exp_obd, get_uuid)(exp);
        RETURN(uuid);
}

/** Create a new /a exp on device /a obd for the uuid /a cluuid
 * @param exp New export handle
 * @param d Connect data, supported flags are set, flags also understood
 *    by obd are returned.
 */
static inline int obd_connect(const struct lu_env *env,
                              struct obd_export **exp,struct obd_device *obd,
                              struct obd_uuid *cluuid,
                              struct obd_connect_data *data,
                              void *localdata)
{
        int rc;
        __u64 ocf = data ? data->ocd_connect_flags : 0; /* for post-condition
                                                   * check */
        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_connect) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

        rc = OBP(obd, connect)(env, exp, obd, cluuid, data, localdata);
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
        __u64 ocf = d ? d->ocd_connect_flags : 0; /* for post-condition
                                                   * check */

        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_reconnect)
		RETURN(0);

        rc = OBP(obd, reconnect)(env, exp, obd, cluuid, d, localdata);
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

        rc = OBP(exp->exp_obd, disconnect)(exp);
        RETURN(rc);
}

static inline int obd_fid_init(struct obd_device *obd, struct obd_export *exp,
			       enum lu_cli_type type)
{
	int rc;
	ENTRY;

	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_fid_init)
		RETURN(0);

	rc = OBP(obd, fid_init)(obd, exp, type);
	RETURN(rc);
}

static inline int obd_fid_fini(struct obd_device *obd)
{
	int rc;
	ENTRY;
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_fid_fini)
		RETURN(0);

	rc = OBP(obd, fid_fini)(obd);
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

	rc = OBP(exp->exp_obd, fid_alloc)(env, exp, fid, op_data);
	RETURN(rc);
}

static inline int obd_ping(const struct lu_env *env, struct obd_export *exp)
{
        int rc;
        ENTRY;

	if (!exp->exp_obd->obd_type ||
	    !exp->exp_obd->obd_type->typ_dt_ops->o_ping)
		RETURN(0);

        rc = OBP(exp->exp_obd, ping)(env, exp);
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

        rc = OBP(obd, pool_new)(obd, poolname);
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

        rc = OBP(obd, pool_del)(obd, poolname);
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

        rc = OBP(obd, pool_add)(obd, poolname, ostname);
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

	rc = OBP(obd, pool_rem)(obd, poolname, ostname);
	RETURN(rc);
}

static inline int obd_init_export(struct obd_export *exp)
{
	int rc = 0;

	ENTRY;
	if (exp->exp_obd != NULL && exp->exp_obd->obd_type &&
	    OBP((exp)->exp_obd, init_export))
		rc = OBP(exp->exp_obd, init_export)(exp);
	RETURN(rc);
}

static inline int obd_destroy_export(struct obd_export *exp)
{
	ENTRY;
	if (exp->exp_obd != NULL && exp->exp_obd->obd_type &&
	    OBP(exp->exp_obd, destroy_export))
		OBP(exp->exp_obd, destroy_export)(exp);
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
	int rc = 0;
	struct obd_device *obd;

	ENTRY;

	if (exp == NULL || exp->exp_obd == NULL)
		RETURN(-EINVAL);

	obd = exp->exp_obd;
	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_statfs) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	CDEBUG(D_SUPER, "%s: osfs %p age %lld, max_age %lld\n",
	       obd->obd_name, &obd->obd_osfs, obd->obd_osfs_age, max_age);
	if (obd->obd_osfs_age < max_age) {
		rc = OBP(obd, statfs_async)(exp, oinfo, max_age, rqset);
	} else {
		CDEBUG(D_SUPER,
		       "%s: use %p cache blocks %llu/%llu objects %llu/%llu\n",
		       obd->obd_name, &obd->obd_osfs,
		       obd->obd_osfs.os_bavail, obd->obd_osfs.os_blocks,
		       obd->obd_osfs.os_ffree, obd->obd_osfs.os_files);
		spin_lock(&obd->obd_osfs_lock);
		memcpy(oinfo->oi_osfs, &obd->obd_osfs,
		       sizeof(*oinfo->oi_osfs));
		spin_unlock(&obd->obd_osfs_lock);
		oinfo->oi_flags |= OBD_STATFS_FROM_CACHE;
		if (oinfo->oi_cb_up)
			oinfo->oi_cb_up(oinfo, 0);
	}
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
        int rc = 0;
        struct obd_device *obd = exp->exp_obd;
        ENTRY;

        if (obd == NULL)
                RETURN(-EINVAL);

	OBD_CHECK_DEV_ACTIVE(obd);

	if (!obd->obd_type || !obd->obd_type->typ_dt_ops->o_statfs) {
		CERROR("%s: no %s operation\n", obd->obd_name, __func__);
		RETURN(-EOPNOTSUPP);
	}

	CDEBUG(D_SUPER, "osfs %lld, max_age %lld\n",
               obd->obd_osfs_age, max_age);
	/* ignore cache if aggregated isn't expected */
	if (obd->obd_osfs_age < max_age ||
	    ((obd->obd_osfs.os_state & OS_STATE_SUM) &&
	     !(flags & OBD_STATFS_SUM))) {
                rc = OBP(obd, statfs)(env, exp, osfs, max_age, flags);
                if (rc == 0) {
			spin_lock(&obd->obd_osfs_lock);
			memcpy(&obd->obd_osfs, osfs, sizeof(obd->obd_osfs));
			obd->obd_osfs_age = ktime_get_seconds();
			spin_unlock(&obd->obd_osfs_lock);
		}
	} else {
		CDEBUG(D_SUPER, "%s: use %p cache blocks %llu/%llu"
		       " objects %llu/%llu\n",
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

	rc = OBP(exp->exp_obd, preprw)(env, cmd, exp, oa, objcount, obj, remote,
				       pages, local);

	RETURN(rc);
}

static inline int obd_commitrw(const struct lu_env *env, int cmd,
			       struct obd_export *exp, struct obdo *oa,
			       int objcount, struct obd_ioobj *obj,
			       struct niobuf_remote *rnb, int pages,
			       struct niobuf_local *local, int rc)
{
	ENTRY;

	rc = exp_check_ops(exp);
	if (rc)
		RETURN(rc);

	if (!exp->exp_obd->obd_type->typ_dt_ops->o_commitrw) {
		CERROR("%s: no %s operation\n",
		       (exp)->exp_obd->obd_name, __func__);
		RETURN(-ENOTSUPP);
	}

	rc = OBP(exp->exp_obd, commitrw)(env, cmd, exp, oa, objcount, obj,
					 rnb, pages, local, rc);

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

        rc = OBP(exp->exp_obd, iocontrol)(cmd, exp, len, karg, uarg);
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

        if (obd->obd_set_up && OBP(obd, import_event))
                OBP(obd, import_event)(obd, imp, event);

        EXIT;
}

static inline int obd_notify(struct obd_device *obd,
			     struct obd_device *watched,
			     enum obd_notify_event ev)
{
	int rc;
	ENTRY;
	OBD_CHECK_DEV(obd);

	if (!obd->obd_set_up) {
		CDEBUG(D_HA, "obd %s not set up\n", obd->obd_name);
		RETURN(-EINVAL);
	}

	if (!OBP(obd, notify)) {
		CDEBUG(D_HA, "obd %s has no notify handler\n", obd->obd_name);
		RETURN(-ENOSYS);
	}

	rc = OBP(obd, notify)(obd, watched, ev);

	RETURN(rc);
}

static inline int obd_notify_observer(struct obd_device *observer,
				      struct obd_device *observed,
				      enum obd_notify_event ev)
{
	int rc = 0;
	int rc2 = 0;
	struct obd_notify_upcall *onu;

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

        rc = OBP(exp->exp_obd, quotactl)(exp->exp_obd, exp, oqctl);
        RETURN(rc);
}

static inline int obd_health_check(const struct lu_env *env,
				   struct obd_device *obd)
{
	/* returns: 0 on healthy
	 *         >0 on unhealthy + reason code/flag
	 *            however the only suppored reason == 1 right now
	 *            We'll need to define some better reasons
	 *            or flags in the future.
	 *         <0 on error
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
	if (!OBP(obd, health_check))
		RETURN(0);

	rc = OBP(obd, health_check)(env, obd);
	RETURN(rc);
}

static inline int obd_register_observer(struct obd_device *obd,
                                        struct obd_device *observer)
{
        ENTRY;
        OBD_CHECK_DEV(obd);
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

	return MDP(exp->exp_obd, get_root)(exp, fileset, fid);
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

	return MDP(exp->exp_obd, getattr)(exp, op_data, request);
}

static inline int md_null_inode(struct obd_export *exp,
                                   const struct lu_fid *fid)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, null_inode)(exp, fid);
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

	return MDP(exp->exp_obd, close)(exp, op_data, mod, request);
}

static inline int md_create(struct obd_export *exp, struct md_op_data *op_data,
			    const void *data, size_t datalen, umode_t mode,
			    uid_t uid, gid_t gid, cfs_cap_t cap_effective,
			    __u64 rdev, struct ptlrpc_request **request)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_CREATE);

	return MDP(exp->exp_obd, create)(exp, op_data, data, datalen, mode,
					 uid, gid, cap_effective, rdev,
					 request);
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

	return MDP(exp->exp_obd, enqueue)(exp, einfo, policy, op_data, lockh,
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

	return MDP(exp->exp_obd, getattr_name)(exp, op_data, request);
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

	return MDP(exp->exp_obd, intent_lock)(exp, op_data, it, reqp,
					      cb_blocking, extra_lock_flags);
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

	return MDP(exp->exp_obd, link)(exp, op_data, request);
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

	return MDP(exp->exp_obd, rename)(exp, op_data, old_name, oldlen,
					 new_name, newlen, request);
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

	return MDP(exp->exp_obd, setattr)(exp, op_data, ea, ealen, request);
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

	return MDP(exp->exp_obd, fsync)(exp, fid, request);
}

/* FLR: resync mirrored files. */
static inline int md_file_resync(struct obd_export *exp,
				 struct md_op_data *data)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, file_resync)(exp, data);
}

static inline int md_read_page(struct obd_export *exp,
			       struct md_op_data *op_data,
			       struct md_callback *cb_op,
			       __u64  hash_offset,
			       struct page **ppage)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_READ_PAGE);

	return MDP(exp->exp_obd, read_page)(exp, op_data, cb_op, hash_offset,
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

	return MDP(exp->exp_obd, unlink)(exp, op_data, request);
}

static inline int md_get_lustre_md(struct obd_export *exp,
                                   struct ptlrpc_request *req,
                                   struct obd_export *dt_exp,
                                   struct obd_export *md_exp,
                                   struct lustre_md *md)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, get_lustre_md)(exp, req, dt_exp, md_exp, md);
}

static inline int md_free_lustre_md(struct obd_export *exp,
                                    struct lustre_md *md)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, free_lustre_md)(exp, md);
}

static inline int md_merge_attr(struct obd_export *exp,
				const struct lmv_stripe_md *lsm,
				struct cl_attr *attr,
				ldlm_blocking_callback cb)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, merge_attr)(exp, lsm, attr, cb);
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

	return MDP(exp->exp_obd, setxattr)(exp, fid, obd_md_valid, name,
					   value, value_size, xattr_flags,
					   suppgid, req);
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

	return MDP(exp->exp_obd, getxattr)(exp, fid, obd_md_valid, name,
					   buf_size, req);
}

static inline int md_set_open_replay_data(struct obd_export *exp,
					  struct obd_client_handle *och,
					  struct lookup_intent *it)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, set_open_replay_data)(exp, och, it);
}

static inline int md_clear_open_replay_data(struct obd_export *exp,
                                            struct obd_client_handle *och)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, clear_open_replay_data)(exp, och);
}

static inline int md_set_lock_data(struct obd_export *exp,
				   const struct lustre_handle *lockh,
				   void *data, __u64 *bits)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, set_lock_data)(exp, lockh, data, bits);
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

	return MDP(exp->exp_obd, cancel_unused)(exp, fid, policy, mode,
						cancel_flags, opaque);
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

	return MDP(exp->exp_obd, lock_match)(exp, flags, fid, type,
					     policy, mode, lockh);
}

static inline int md_init_ea_size(struct obd_export *exp, __u32 ea_size,
				  __u32 def_ea_size)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, init_ea_size)(exp, ea_size, def_ea_size);
}

static inline int md_intent_getattr_async(struct obd_export *exp,
					  struct md_enqueue_info *minfo)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	lprocfs_counter_incr(exp->exp_obd->obd_md_stats,
			     LPROC_MD_INTENT_GETATTR_ASYNC);

	return MDP(exp->exp_obd, intent_getattr_async)(exp, minfo);
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

	return MDP(exp->exp_obd, revalidate_lock)(exp, it, fid, bits);
}

static inline int md_get_fid_from_lsm(struct obd_export *exp,
				      const struct lmv_stripe_md *lsm,
				      const char *name, int namelen,
				      struct lu_fid *fid)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, get_fid_from_lsm)(exp, lsm, name, namelen,
						   fid);
}

/* Unpack an MD struct from disk to in-memory format.
 * Returns +ve size of unpacked MD (0 for free), or -ve error.
 *
 * If *plsm != NULL and lmm == NULL then *lsm will be freed.
 * If *plsm == NULL then it will be allocated.
 */
static inline int md_unpackmd(struct obd_export *exp,
			      struct lmv_stripe_md **plsm,
			      const union lmv_mds_md *lmm, size_t lmm_size)
{
	int rc;

	rc = exp_check_ops(exp);
	if (rc)
		return rc;

	return MDP(exp->exp_obd, unpackmd)(exp, plsm, lmm, lmm_size);
}

/* OBD Metadata Support */

extern int obd_init_caches(void);
extern void obd_cleanup_caches(void);

/* support routines */
extern struct kmem_cache *obdo_cachep;

#define OBDO_ALLOC(ptr)                                                       \
do {                                                                          \
	OBD_SLAB_ALLOC_PTR_GFP((ptr), obdo_cachep, GFP_NOFS);             \
} while(0)

#define OBDO_FREE(ptr)                                                        \
do {                                                                          \
        OBD_SLAB_FREE_PTR((ptr), obdo_cachep);                                \
} while(0)


typedef int (*register_lwp_cb)(void *data);

struct lwp_register_item {
	struct obd_export **lri_exp;
	register_lwp_cb	    lri_cb_func;
	void		   *lri_cb_data;
	struct list_head    lri_list;
	atomic_t	    lri_ref;
	char		    lri_name[MTI_NAME_MAXLEN];
};

/* I'm as embarrassed about this as you are.
 *
 * <shaver> // XXX do not look into _superhack with remaining eye
 * <shaver> // XXX if this were any uglier, I'd get my own show on MTV */
extern int (*ptlrpc_put_connection_superhack)(struct ptlrpc_connection *c);

/* obd_mount.c */
#ifdef HAVE_SERVER_SUPPORT
int lustre_register_lwp_item(const char *lwpname, struct obd_export **exp,
			     register_lwp_cb cb_func, void *cb_data);
void lustre_deregister_lwp_item(struct obd_export **exp);
struct obd_export *lustre_find_lwp_by_index(const char *dev, __u32 idx);
void lustre_notify_lwp_list(struct obd_export *exp);
int tgt_name2lwp_name(const char *tgt_name, char *lwp_name, int len, __u32 idx);
#endif /* HAVE_SERVER_SUPPORT */
int lustre_register_fs(void);
int lustre_unregister_fs(void);
int lustre_check_exclusion(struct super_block *sb, char *svname);

typedef __u8 class_uuid_t[16];
static inline void class_uuid_unparse(class_uuid_t uu, struct obd_uuid *out)
{
	snprintf(out->uuid, sizeof(out->uuid), "%02x%02x%02x%02x-%02x%02x-"
		 "%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 uu[14], uu[15], uu[12], uu[13], uu[10], uu[11], uu[8], uu[9],
		 uu[6], uu[7], uu[4], uu[5], uu[2], uu[3], uu[0], uu[1]);
}

/* lustre_peer.c    */
int lustre_uuid_to_peer(const char *uuid, lnet_nid_t *peer_nid, int index);
int class_add_uuid(const char *uuid, __u64 nid);
int class_del_uuid (const char *uuid);
int class_check_uuid(struct obd_uuid *uuid, __u64 nid);

/* class_obd.c */
extern char obd_jobid_name[];

/* prng.c */
#define ll_generate_random_uuid(uuid_out) cfs_get_random_bytes(uuid_out, sizeof(class_uuid_t))

/* statfs_pack.c */
struct kstatfs;
void statfs_pack(struct obd_statfs *osfs, struct kstatfs *sfs);
void statfs_unpack(struct kstatfs *sfs, struct obd_statfs *osfs);

/* root squash info */
struct rw_semaphore;
struct root_squash_info {
	uid_t			rsi_uid;
	gid_t			rsi_gid;
	struct list_head	rsi_nosquash_nids;
	struct rw_semaphore	rsi_sem;
};

int server_name2index(const char *svname, __u32 *idx, const char **endptr);

/* linux-module.c */
extern struct miscdevice obd_psdev;
int obd_ioctl_getdata(char **buf, int *len, void __user *arg);
int class_procfs_init(void);
int class_procfs_clean(void);
#endif /* __LINUX_OBD_CLASS_H */
