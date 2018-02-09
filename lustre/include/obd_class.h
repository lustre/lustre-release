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
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#ifndef __CLASS_OBD_H
#define __CLASS_OBD_H


#include <obd_support.h>
#include <lustre_import.h>
#include <lustre_net.h>
#include <obd.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lprocfs_status.h>

#define OBD_STATFS_NODELAY      0x0001  /* requests should be send without delay
                                         * and resends for avoid deadlocks */
#define OBD_STATFS_FROM_CACHE   0x0002  /* the statfs callback should not update
                                         * obd_osfs_age */
#define OBD_STATFS_FOR_MDT0	0x0004	/* The statfs is only for retrieving
					 * information from MDT0. */

extern rwlock_t obd_dev_lock;

/* OBD Operations Declarations */
extern struct obd_device *class_conn2obd(struct lustre_handle *);
extern struct obd_device *class_exp2obd(struct obd_export *);
extern int class_handle_ioctl(unsigned int cmd, unsigned long arg);
extern int lustre_get_jobid(char *jobid);

struct lu_device_type;

/* genops.c */
struct obd_export *class_conn2export(struct lustre_handle *);
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

char *obd_export_nid2str(struct obd_export *exp);

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
#define CFG_F_COMPAT146 0x08   /* Allow old-style logs */
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
	struct list_head	    cld_list_chain;
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

#define OBT(dev)        (dev)->obd_type
#define OBP(dev, op)    (dev)->obd_type->typ_dt_ops->o_ ## op
#define MDP(dev, op)    (dev)->obd_type->typ_md_ops->m_ ## op
#define CTXTP(ctxt, op) (ctxt)->loc_logops->lop_##op

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


#ifdef CONFIG_PROC_FS
#define OBD_COUNTER_OFFSET(op)						       \
	((offsetof(struct obd_ops, o_ ## op) -				       \
	  offsetof(struct obd_ops, o_iocontrol))			       \
	 / sizeof(((struct obd_ops *)NULL)->o_iocontrol))

/* The '- 1' below is for o_owner. */
#define NUM_OBD_STATS							       \
	(sizeof(struct obd_ops) /					       \
	 sizeof(((struct obd_ops *)NULL)->o_iocontrol) - 1)

#define OBD_COUNTER_INCREMENT(obd, op)					       \
	lprocfs_counter_incr((obd)->obd_stats,				       \
			     (obd)->obd_cntr_base + OBD_COUNTER_OFFSET(op))

#define EXP_COUNTER_INCREMENT(exp, op)					       \
	do {								       \
		unsigned int _off;					       \
		_off = (exp)->exp_obd->obd_cntr_base + OBD_COUNTER_OFFSET(op); \
		lprocfs_counter_incr((exp)->exp_obd->obd_stats, _off);	       \
		if ((exp)->exp_obd->obd_uses_nid_stats &&		       \
		    (exp)->exp_nid_stats != NULL)			       \
			lprocfs_counter_incr((exp)->exp_nid_stats->nid_stats,  \
					     _off);			       \
	} while (0)

#define _MD_COUNTER_OFFSET(m_op)					       \
	((offsetof(struct md_ops, m_op) -				       \
	  offsetof(struct md_ops, MD_STATS_FIRST_OP)) /			       \
	 sizeof(((struct md_ops *)NULL)->MD_STATS_FIRST_OP))

#define MD_COUNTER_OFFSET(op) _MD_COUNTER_OFFSET(m_ ## op)

#define NUM_MD_STATS							       \
	(_MD_COUNTER_OFFSET(MD_STATS_LAST_OP) -				       \
	 _MD_COUNTER_OFFSET(MD_STATS_FIRST_OP) + 1)

/* Note that we only increment md counters for ops whose offset is less
 * than NUM_MD_STATS. This is explained in a comment in the definition
 * of struct md_ops. */
#define EXP_MD_COUNTER_INCREMENT(exp, op)				       \
	do {								       \
		if (MD_COUNTER_OFFSET(op) < NUM_MD_STATS)		       \
			lprocfs_counter_incr((exp)->exp_obd->obd_md_stats,     \
					(exp)->exp_obd->obd_md_cntr_base +     \
					MD_COUNTER_OFFSET(op));	               \
	} while (0)

#else
#define OBD_COUNTER_OFFSET(op)
#define OBD_COUNTER_INCREMENT(obd, op)
#define EXP_COUNTER_INCREMENT(exp, op)
#define EXP_MD_COUNTER_INCREMENT(exp, op)
#endif

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

#define EXP_CHECK_MD_OP(exp, op)					\
do {									\
	if ((exp) == NULL) {						\
		CERROR("obd_" #op ": NULL export\n");			\
		RETURN(-ENODEV);					\
	}								\
	if ((exp)->exp_obd == NULL || !OBT((exp)->exp_obd)) {		\
		CERROR("obd_" #op ": cleaned up obd\n");		\
		RETURN(-EOPNOTSUPP);					\
	}								\
	if (!OBT((exp)->exp_obd) || !MDP((exp)->exp_obd, op)) {		\
		CERROR("%s: obd_" #op ": dev %d no operation\n",	\
		       (exp)->exp_obd->obd_name,			\
		       (exp)->exp_obd->obd_minor);			\
		RETURN(-EOPNOTSUPP);					\
	}								\
} while (0)


#define OBD_CHECK_DT_OP(obd, op, err)					\
do {									\
	if (!OBT(obd) || !OBP((obd), op)) {				\
		if (err)						\
			CERROR("%s: no obd_" #op " operation\n",	\
			       obd->obd_name);				\
		RETURN(err);						\
	}								\
} while (0)

#define EXP_CHECK_DT_OP(exp, op)					\
do {									\
	if ((exp) == NULL) {						\
		CERROR("obd_" #op ": NULL export\n");			\
		RETURN(-ENODEV);					\
	}								\
	if ((exp)->exp_obd == NULL || !OBT((exp)->exp_obd)) {		\
		CERROR("obd_" #op ": cleaned up obd\n");		\
		RETURN(-EOPNOTSUPP);					\
	}								\
	OBD_CHECK_DT_OP((exp)->exp_obd, op, -EOPNOTSUPP);		\
} while (0)

#define CTXT_CHECK_OP(ctxt, op, err)					\
do {									\
	if (!OBT(ctxt->loc_obd) || !CTXTP((ctxt), op)) {		\
		if (err)						\
			CERROR("%s: no lop_" #op "operation\n",		\
			       ctxt->loc_obd->obd_name);		\
		RETURN(err);						\
	}								\
} while (0)

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

	EXP_CHECK_DT_OP(exp, get_info);
	EXP_COUNTER_INCREMENT(exp, get_info);

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

        EXP_CHECK_DT_OP(exp, set_info_async);
        EXP_COUNTER_INCREMENT(exp, set_info_async);

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

#define DECLARE_LU_VARS(ldt, d)                 \
        struct lu_device_type *ldt;       \
        struct lu_device *d

static inline int obd_setup(struct obd_device *obd, struct lustre_cfg *cfg)
{
        int rc;
        DECLARE_LU_VARS(ldt, d);
        ENTRY;

        ldt = obd->obd_type->typ_lu;
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
                OBD_CHECK_DT_OP(obd, setup, -EOPNOTSUPP);
                OBD_COUNTER_INCREMENT(obd, setup);
                rc = OBP(obd, setup)(obd, cfg);
        }
        RETURN(rc);
}

static inline int obd_precleanup(struct obd_device *obd)
{
	int rc;
	DECLARE_LU_VARS(ldt, d);
	ENTRY;

	OBD_CHECK_DEV(obd);
	ldt = obd->obd_type->typ_lu;
	d = obd->obd_lu_dev;
	if (ldt != NULL && d != NULL) {
		struct lu_env env;

		rc = lu_env_init(&env, ldt->ldt_ctx_tags);
		if (rc == 0) {
			ldt->ldt_ops->ldto_device_fini(&env, d);
			lu_env_fini(&env);
		}
	}
	OBD_CHECK_DT_OP(obd, precleanup, 0);
	OBD_COUNTER_INCREMENT(obd, precleanup);

	rc = OBP(obd, precleanup)(obd);
	RETURN(rc);
}

static inline int obd_cleanup(struct obd_device *obd)
{
        int rc;
        DECLARE_LU_VARS(ldt, d);
        ENTRY;

        OBD_CHECK_DEV(obd);

        ldt = obd->obd_type->typ_lu;
        d = obd->obd_lu_dev;
        if (ldt != NULL && d != NULL) {
                struct lu_env env;

                rc = lu_env_init(&env, ldt->ldt_ctx_tags);
                if (rc == 0) {
                        ldt->ldt_ops->ldto_device_free(&env, d);
                        lu_env_fini(&env);
                        obd->obd_lu_dev = NULL;
                }
        }
        OBD_CHECK_DT_OP(obd, cleanup, 0);
        OBD_COUNTER_INCREMENT(obd, cleanup);

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

static inline int
obd_process_config(struct obd_device *obd, int datalen, void *data)
{
        int rc;
        DECLARE_LU_VARS(ldt, d);
        ENTRY;

        OBD_CHECK_DEV(obd);

        obd->obd_process_conf = 1;
        ldt = obd->obd_type->typ_lu;
        d = obd->obd_lu_dev;
        if (ldt != NULL && d != NULL) {
                struct lu_env env;

                rc = lu_env_init(&env, ldt->ldt_ctx_tags);
                if (rc == 0) {
                        rc = d->ld_ops->ldo_process_config(&env, d, data);
                        lu_env_fini(&env);
                }
        } else {
                OBD_CHECK_DT_OP(obd, process_config, -EOPNOTSUPP);
                rc = OBP(obd, process_config)(obd, datalen, data);
        }
        OBD_COUNTER_INCREMENT(obd, process_config);
        obd->obd_process_conf = 0;

        RETURN(rc);
}

static inline int obd_create(const struct lu_env *env, struct obd_export *exp,
			     struct obdo *obdo)
{
	int rc;
	ENTRY;

	EXP_CHECK_DT_OP(exp, create);
	EXP_COUNTER_INCREMENT(exp, create);

	rc = OBP(exp->exp_obd, create)(env, exp, obdo);
	RETURN(rc);
}

static inline int obd_destroy(const struct lu_env *env, struct obd_export *exp,
			      struct obdo *obdo)
{
	int rc;
	ENTRY;

	EXP_CHECK_DT_OP(exp, destroy);
	EXP_COUNTER_INCREMENT(exp, destroy);

	rc = OBP(exp->exp_obd, destroy)(env, exp, obdo);
	RETURN(rc);
}

static inline int obd_getattr(const struct lu_env *env, struct obd_export *exp,
			      struct obdo *oa)
{
	int rc;

	ENTRY;
	EXP_CHECK_DT_OP(exp, getattr);
	EXP_COUNTER_INCREMENT(exp, getattr);
	rc = OBP(exp->exp_obd, getattr)(env, exp, oa);

	RETURN(rc);
}

static inline int obd_setattr(const struct lu_env *env, struct obd_export *exp,
			      struct obdo *oa)
{
	int rc;

	ENTRY;
	EXP_CHECK_DT_OP(exp, setattr);
	EXP_COUNTER_INCREMENT(exp, setattr);
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
        OBD_CHECK_DT_OP(obd, add_conn, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, add_conn);

        rc = OBP(obd, add_conn)(imp, uuid, priority);
        RETURN(rc);
}

static inline int obd_del_conn(struct obd_import *imp, struct obd_uuid *uuid)
{
        struct obd_device *obd = imp->imp_obd;
        int rc;
        ENTRY;

        OBD_CHECK_DEV_ACTIVE(obd);
        OBD_CHECK_DT_OP(obd, del_conn, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, del_conn);

        rc = OBP(obd, del_conn)(imp, uuid);
        RETURN(rc);
}

static inline struct obd_uuid *obd_get_uuid(struct obd_export *exp)
{
        struct obd_uuid *uuid;
        ENTRY;

        OBD_CHECK_DT_OP(exp->exp_obd, get_uuid, NULL);
        EXP_COUNTER_INCREMENT(exp, get_uuid);

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
        OBD_CHECK_DT_OP(obd, connect, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, connect);

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
        OBD_CHECK_DT_OP(obd, reconnect, 0);
        OBD_COUNTER_INCREMENT(obd, reconnect);

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

        EXP_CHECK_DT_OP(exp, disconnect);
        EXP_COUNTER_INCREMENT(exp, disconnect);

        rc = OBP(exp->exp_obd, disconnect)(exp);
        RETURN(rc);
}

static inline int obd_fid_init(struct obd_device *obd, struct obd_export *exp,
			       enum lu_cli_type type)
{
	int rc;
	ENTRY;

	OBD_CHECK_DT_OP(obd, fid_init, 0);
	OBD_COUNTER_INCREMENT(obd, fid_init);

	rc = OBP(obd, fid_init)(obd, exp, type);
	RETURN(rc);
}

static inline int obd_fid_fini(struct obd_device *obd)
{
	int rc;
	ENTRY;

	OBD_CHECK_DT_OP(obd, fid_fini, 0);
	OBD_COUNTER_INCREMENT(obd, fid_fini);

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

	EXP_CHECK_DT_OP(exp, fid_alloc);
	EXP_COUNTER_INCREMENT(exp, fid_alloc);

	rc = OBP(exp->exp_obd, fid_alloc)(env, exp, fid, op_data);
	RETURN(rc);
}

static inline int obd_ping(const struct lu_env *env, struct obd_export *exp)
{
        int rc;
        ENTRY;

        OBD_CHECK_DT_OP(exp->exp_obd, ping, 0);
        EXP_COUNTER_INCREMENT(exp, ping);

        rc = OBP(exp->exp_obd, ping)(env, exp);
        RETURN(rc);
}

static inline int obd_pool_new(struct obd_device *obd, char *poolname)
{
        int rc;
        ENTRY;

        OBD_CHECK_DT_OP(obd, pool_new, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_new);

        rc = OBP(obd, pool_new)(obd, poolname);
        RETURN(rc);
}

static inline int obd_pool_del(struct obd_device *obd, char *poolname)
{
        int rc;
        ENTRY;

        OBD_CHECK_DT_OP(obd, pool_del, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_del);

        rc = OBP(obd, pool_del)(obd, poolname);
        RETURN(rc);
}

static inline int obd_pool_add(struct obd_device *obd, char *poolname, char *ostname)
{
        int rc;
        ENTRY;

        OBD_CHECK_DT_OP(obd, pool_add, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_add);

        rc = OBP(obd, pool_add)(obd, poolname, ostname);
        RETURN(rc);
}

static inline int obd_pool_rem(struct obd_device *obd, char *poolname, char *ostname)
{
        int rc;
        ENTRY;

        OBD_CHECK_DT_OP(obd, pool_rem, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, pool_rem);

        rc = OBP(obd, pool_rem)(obd, poolname, ostname);
        RETURN(rc);
}

static inline void obd_getref(struct obd_device *obd)
{
        ENTRY;
        if (OBT(obd) && OBP(obd, getref)) {
                OBD_COUNTER_INCREMENT(obd, getref);
                OBP(obd, getref)(obd);
        }
        EXIT;
}

static inline void obd_putref(struct obd_device *obd)
{
        ENTRY;
        if (OBT(obd) && OBP(obd, putref)) {
                OBD_COUNTER_INCREMENT(obd, putref);
                OBP(obd, putref)(obd);
        }
        EXIT;
}

static inline int obd_init_export(struct obd_export *exp)
{
        int rc = 0;

        ENTRY;
        if ((exp)->exp_obd != NULL && OBT((exp)->exp_obd) &&
            OBP((exp)->exp_obd, init_export))
                rc = OBP(exp->exp_obd, init_export)(exp);
        RETURN(rc);
}

static inline int obd_destroy_export(struct obd_export *exp)
{
        ENTRY;
        if ((exp)->exp_obd != NULL && OBT((exp)->exp_obd) &&
            OBP((exp)->exp_obd, destroy_export))
                OBP(exp->exp_obd, destroy_export)(exp);
        RETURN(0);
}

/* @max_age is the oldest time in jiffies that we accept using a cached data.
 * If the cache is older than @max_age we will get a new value from the
 * target.  Use a value of "cfs_time_current() + HZ" to guarantee freshness. */
static inline int obd_statfs_async(struct obd_export *exp,
                                   struct obd_info *oinfo,
                                   __u64 max_age,
                                   struct ptlrpc_request_set *rqset)
{
        int rc = 0;
        struct obd_device *obd;
        ENTRY;

        if (exp == NULL || exp->exp_obd == NULL)
                RETURN(-EINVAL);

        obd = exp->exp_obd;
        OBD_CHECK_DT_OP(obd, statfs, -EOPNOTSUPP);
        OBD_COUNTER_INCREMENT(obd, statfs);

	CDEBUG(D_SUPER, "%s: osfs %p age %llu, max_age %llu\n",
               obd->obd_name, &obd->obd_osfs, obd->obd_osfs_age, max_age);
        if (cfs_time_before_64(obd->obd_osfs_age, max_age)) {
                rc = OBP(obd, statfs_async)(exp, oinfo, max_age, rqset);
        } else {
		CDEBUG(D_SUPER, "%s: use %p cache blocks %llu/%llu objects %llu/%llu\n",
                       obd->obd_name, &obd->obd_osfs,
                       obd->obd_osfs.os_bavail, obd->obd_osfs.os_blocks,
                       obd->obd_osfs.os_ffree, obd->obd_osfs.os_files);
		spin_lock(&obd->obd_osfs_lock);
		memcpy(oinfo->oi_osfs, &obd->obd_osfs, sizeof(*oinfo->oi_osfs));
		spin_unlock(&obd->obd_osfs_lock);
                oinfo->oi_flags |= OBD_STATFS_FROM_CACHE;
                if (oinfo->oi_cb_up)
                        oinfo->oi_cb_up(oinfo, 0);
        }
        RETURN(rc);
}

static inline int obd_statfs_rqset(struct obd_export *exp,
                                   struct obd_statfs *osfs, __u64 max_age,
                                   __u32 flags)
{
	struct ptlrpc_request_set *set = NULL;
	struct obd_info oinfo = {
		.oi_osfs = osfs,
		.oi_flags = flags,
	};
	int rc = 0;

	ENTRY;

	set = ptlrpc_prep_set();
	if (set == NULL)
		RETURN(-ENOMEM);

	rc = obd_statfs_async(exp, &oinfo, max_age, set);
	if (rc == 0)
		rc = ptlrpc_set_wait(set);

	ptlrpc_set_destroy(set);

	RETURN(rc);
}

/* @max_age is the oldest time in jiffies that we accept using a cached data.
 * If the cache is older than @max_age we will get a new value from the
 * target.  Use a value of "cfs_time_current() + HZ" to guarantee freshness. */
static inline int obd_statfs(const struct lu_env *env, struct obd_export *exp,
                             struct obd_statfs *osfs, __u64 max_age,
                             __u32 flags)
{
        int rc = 0;
        struct obd_device *obd = exp->exp_obd;
        ENTRY;

        if (obd == NULL)
                RETURN(-EINVAL);

        OBD_CHECK_DT_OP(obd, statfs, -EOPNOTSUPP);
	OBD_CHECK_DEV_ACTIVE(obd);
        OBD_COUNTER_INCREMENT(obd, statfs);

	CDEBUG(D_SUPER, "osfs %llu, max_age %llu\n",
               obd->obd_osfs_age, max_age);
        if (cfs_time_before_64(obd->obd_osfs_age, max_age)) {
                rc = OBP(obd, statfs)(env, exp, osfs, max_age, flags);
                if (rc == 0) {
			spin_lock(&obd->obd_osfs_lock);
			memcpy(&obd->obd_osfs, osfs, sizeof(obd->obd_osfs));
			obd->obd_osfs_age = cfs_time_current_64();
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
	EXP_CHECK_DT_OP(exp, preprw);
	EXP_COUNTER_INCREMENT(exp, preprw);
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

	EXP_CHECK_DT_OP(exp, commitrw);
	EXP_COUNTER_INCREMENT(exp, commitrw);
	rc = OBP(exp->exp_obd, commitrw)(env, cmd, exp, oa, objcount, obj,
					 rnb, pages, local, rc);

	RETURN(rc);
}

static inline int obd_iocontrol(unsigned int cmd, struct obd_export *exp,
				int len, void *karg, void __user *uarg)
{
        int rc;
        ENTRY;

        EXP_CHECK_DT_OP(exp, iocontrol);
        EXP_COUNTER_INCREMENT(exp, iocontrol);

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
        if (obd->obd_set_up && OBP(obd, import_event)) {
                OBD_COUNTER_INCREMENT(obd, import_event);
                OBP(obd, import_event)(obd, imp, event);
        }
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

	OBD_COUNTER_INCREMENT(obd, notify);
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

        EXP_CHECK_DT_OP(exp, quotactl);
        EXP_COUNTER_INCREMENT(exp, quotactl);

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

        /* don't use EXP_CHECK_DT_OP, because NULL method is normal here */
        if (obd == NULL || !OBT(obd)) {
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
static inline int md_get_root(struct obd_export *exp, const char *fileset,
			      struct lu_fid *fid)
{
	int rc;

	ENTRY;
	EXP_CHECK_MD_OP(exp, get_root);
	EXP_MD_COUNTER_INCREMENT(exp, get_root);
	rc = MDP(exp->exp_obd, get_root)(exp, fileset, fid);

	RETURN(rc);
}

static inline int md_getattr(struct obd_export *exp, struct md_op_data *op_data,
                             struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, getattr);
        EXP_MD_COUNTER_INCREMENT(exp, getattr);
        rc = MDP(exp->exp_obd, getattr)(exp, op_data, request);
        RETURN(rc);
}

static inline int md_null_inode(struct obd_export *exp,
                                   const struct lu_fid *fid)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, null_inode);
        EXP_MD_COUNTER_INCREMENT(exp, null_inode);
        rc = MDP(exp->exp_obd, null_inode)(exp, fid);
        RETURN(rc);
}

static inline int md_close(struct obd_export *exp, struct md_op_data *op_data,
                           struct md_open_data *mod,
                           struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, close);
        EXP_MD_COUNTER_INCREMENT(exp, close);
        rc = MDP(exp->exp_obd, close)(exp, op_data, mod, request);
        RETURN(rc);
}

static inline int md_create(struct obd_export *exp, struct md_op_data *op_data,
			    const void *data, size_t datalen, umode_t mode,
			    uid_t uid, gid_t gid, cfs_cap_t cap_effective,
			    __u64 rdev, struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, create);
        EXP_MD_COUNTER_INCREMENT(exp, create);
        rc = MDP(exp->exp_obd, create)(exp, op_data, data, datalen, mode,
                                       uid, gid, cap_effective, rdev, request);
        RETURN(rc);
}

static inline int md_enqueue(struct obd_export *exp,
			     struct ldlm_enqueue_info *einfo,
			     const union ldlm_policy_data *policy,
			     struct md_op_data *op_data,
			     struct lustre_handle *lockh,
			     __u64 extra_lock_flags)
{
	int rc;
	ENTRY;
	EXP_CHECK_MD_OP(exp, enqueue);
	EXP_MD_COUNTER_INCREMENT(exp, enqueue);
	rc = MDP(exp->exp_obd, enqueue)(exp, einfo, policy, op_data, lockh,
					extra_lock_flags);
        RETURN(rc);
}

static inline int md_getattr_name(struct obd_export *exp,
                                  struct md_op_data *op_data,
                                  struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, getattr_name);
        EXP_MD_COUNTER_INCREMENT(exp, getattr_name);
        rc = MDP(exp->exp_obd, getattr_name)(exp, op_data, request);
        RETURN(rc);
}

static inline int md_intent_lock(struct obd_export *exp,
				 struct md_op_data *op_data,
				 struct lookup_intent *it,
				 struct ptlrpc_request **reqp,
				 ldlm_blocking_callback cb_blocking,
				 __u64 extra_lock_flags)
{
	int rc;
	ENTRY;
	EXP_CHECK_MD_OP(exp, intent_lock);
	EXP_MD_COUNTER_INCREMENT(exp, intent_lock);
	rc = MDP(exp->exp_obd, intent_lock)(exp, op_data, it, reqp, cb_blocking,
					    extra_lock_flags);
	RETURN(rc);
}

static inline int md_link(struct obd_export *exp, struct md_op_data *op_data,
                          struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, link);
        EXP_MD_COUNTER_INCREMENT(exp, link);
        rc = MDP(exp->exp_obd, link)(exp, op_data, request);
        RETURN(rc);
}

static inline int md_rename(struct obd_export *exp, struct md_op_data *op_data,
			    const char *old, size_t oldlen, const char *new,
			    size_t newlen, struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, rename);
        EXP_MD_COUNTER_INCREMENT(exp, rename);
        rc = MDP(exp->exp_obd, rename)(exp, op_data, old, oldlen, new,
                                       newlen, request);
        RETURN(rc);
}

static inline int md_setattr(struct obd_export *exp, struct md_op_data *op_data,
			     void *ea, size_t ealen,
			     struct ptlrpc_request **request)
{
	int rc;
	ENTRY;
	EXP_CHECK_MD_OP(exp, setattr);
	EXP_MD_COUNTER_INCREMENT(exp, setattr);
	rc = MDP(exp->exp_obd, setattr)(exp, op_data, ea, ealen, request);
	RETURN(rc);
}

static inline int md_fsync(struct obd_export *exp, const struct lu_fid *fid,
			   struct ptlrpc_request **request)
{
	int rc;

	ENTRY;
	EXP_CHECK_MD_OP(exp, fsync);
	EXP_MD_COUNTER_INCREMENT(exp, fsync);
	rc = MDP(exp->exp_obd, fsync)(exp, fid, request);

	RETURN(rc);
}

static inline int md_read_page(struct obd_export *exp,
			       struct md_op_data *op_data,
			       struct md_callback *cb_op,
			       __u64  hash_offset,
			       struct page **ppage)
{
	int rc;
	ENTRY;
	EXP_CHECK_MD_OP(exp, read_page);
	EXP_MD_COUNTER_INCREMENT(exp, read_page);
	rc = MDP(exp->exp_obd, read_page)(exp, op_data, cb_op, hash_offset,
					  ppage);
	RETURN(rc);
}

static inline int md_unlink(struct obd_export *exp, struct md_op_data *op_data,
                            struct ptlrpc_request **request)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, unlink);
        EXP_MD_COUNTER_INCREMENT(exp, unlink);
        rc = MDP(exp->exp_obd, unlink)(exp, op_data, request);
        RETURN(rc);
}

static inline int md_get_lustre_md(struct obd_export *exp,
                                   struct ptlrpc_request *req,
                                   struct obd_export *dt_exp,
                                   struct obd_export *md_exp,
                                   struct lustre_md *md)
{
        ENTRY;
        EXP_CHECK_MD_OP(exp, get_lustre_md);
        EXP_MD_COUNTER_INCREMENT(exp, get_lustre_md);
        RETURN(MDP(exp->exp_obd, get_lustre_md)(exp, req, dt_exp, md_exp, md));
}

static inline int md_free_lustre_md(struct obd_export *exp,
                                    struct lustre_md *md)
{
        ENTRY;
        EXP_CHECK_MD_OP(exp, free_lustre_md);
        EXP_MD_COUNTER_INCREMENT(exp, free_lustre_md);
        RETURN(MDP(exp->exp_obd, free_lustre_md)(exp, md));
}

static inline int md_merge_attr(struct obd_export *exp,
				const struct lmv_stripe_md *lsm,
				struct cl_attr *attr,
				ldlm_blocking_callback cb)
{
	ENTRY;
	EXP_CHECK_MD_OP(exp, merge_attr);
	EXP_MD_COUNTER_INCREMENT(exp, merge_attr);
	RETURN(MDP(exp->exp_obd, merge_attr)(exp, lsm, attr, cb));
}

static inline int md_setxattr(struct obd_export *exp, const struct lu_fid *fid,
			      u64 valid, const char *name,
			      const char *input, int input_size,
			      int output_size, int flags, __u32 suppgid,
			      struct ptlrpc_request **request)
{
	ENTRY;
	EXP_CHECK_MD_OP(exp, setxattr);
	EXP_MD_COUNTER_INCREMENT(exp, setxattr);
	RETURN(MDP(exp->exp_obd, setxattr)(exp, fid, valid, name, input,
					   input_size, output_size, flags,
					   suppgid, request));
}

static inline int md_getxattr(struct obd_export *exp, const struct lu_fid *fid,
			      u64 valid, const char *name,
			      const char *input, int input_size,
			      int output_size, int flags,
			      struct ptlrpc_request **request)
{
	ENTRY;
	EXP_CHECK_MD_OP(exp, getxattr);
	EXP_MD_COUNTER_INCREMENT(exp, getxattr);
	RETURN(MDP(exp->exp_obd, getxattr)(exp, fid, valid, name, input,
					   input_size, output_size, flags,
					   request));
}

static inline int md_set_open_replay_data(struct obd_export *exp,
					  struct obd_client_handle *och,
					  struct lookup_intent *it)
{
	ENTRY;
	EXP_CHECK_MD_OP(exp, set_open_replay_data);
	EXP_MD_COUNTER_INCREMENT(exp, set_open_replay_data);
	RETURN(MDP(exp->exp_obd, set_open_replay_data)(exp, och, it));
}

static inline int md_clear_open_replay_data(struct obd_export *exp,
                                            struct obd_client_handle *och)
{
        ENTRY;
        EXP_CHECK_MD_OP(exp, clear_open_replay_data);
        EXP_MD_COUNTER_INCREMENT(exp, clear_open_replay_data);
        RETURN(MDP(exp->exp_obd, clear_open_replay_data)(exp, och));
}

static inline int md_set_lock_data(struct obd_export *exp,
				   const struct lustre_handle *lockh,
				   void *data, __u64 *bits)
{
        ENTRY;
        EXP_CHECK_MD_OP(exp, set_lock_data);
        EXP_MD_COUNTER_INCREMENT(exp, set_lock_data);
        RETURN(MDP(exp->exp_obd, set_lock_data)(exp, lockh, data, bits));
}

static inline
int md_cancel_unused(struct obd_export *exp, const struct lu_fid *fid,
		     union ldlm_policy_data *policy, enum ldlm_mode mode,
		     enum ldlm_cancel_flags cancel_flags, void *opaque)
{
	int rc;
	ENTRY;

	EXP_CHECK_MD_OP(exp, cancel_unused);
	EXP_MD_COUNTER_INCREMENT(exp, cancel_unused);

	rc = MDP(exp->exp_obd, cancel_unused)(exp, fid, policy, mode,
					      cancel_flags, opaque);
	RETURN(rc);
}

static inline enum ldlm_mode md_lock_match(struct obd_export *exp, __u64 flags,
					   const struct lu_fid *fid,
					   enum ldlm_type type,
					   union ldlm_policy_data *policy,
					   enum ldlm_mode mode,
					   struct lustre_handle *lockh)
{
	ENTRY;
	EXP_CHECK_MD_OP(exp, lock_match);
	EXP_MD_COUNTER_INCREMENT(exp, lock_match);
	RETURN(MDP(exp->exp_obd, lock_match)(exp, flags, fid, type,
					     policy, mode, lockh));
}

static inline int md_init_ea_size(struct obd_export *exp, __u32 ea_size,
				  __u32 def_ea_size)
{
	ENTRY;
	EXP_CHECK_MD_OP(exp, init_ea_size);
	EXP_MD_COUNTER_INCREMENT(exp, init_ea_size);
	RETURN(MDP(exp->exp_obd, init_ea_size)(exp, ea_size, def_ea_size));
}

static inline int md_intent_getattr_async(struct obd_export *exp,
					  struct md_enqueue_info *minfo)
{
	int rc;
	ENTRY;
	EXP_CHECK_MD_OP(exp, intent_getattr_async);
	EXP_MD_COUNTER_INCREMENT(exp, intent_getattr_async);
	rc = MDP(exp->exp_obd, intent_getattr_async)(exp, minfo);
	RETURN(rc);
}

static inline int md_revalidate_lock(struct obd_export *exp,
                                     struct lookup_intent *it,
                                     struct lu_fid *fid, __u64 *bits)
{
        int rc;
        ENTRY;
        EXP_CHECK_MD_OP(exp, revalidate_lock);
        EXP_MD_COUNTER_INCREMENT(exp, revalidate_lock);
        rc = MDP(exp->exp_obd, revalidate_lock)(exp, it, fid, bits);
        RETURN(rc);
}

static inline int md_get_fid_from_lsm(struct obd_export *exp,
				      const struct lmv_stripe_md *lsm,
				      const char *name, int namelen,
				      struct lu_fid *fid)
{
	int rc;
	ENTRY;
	EXP_CHECK_MD_OP(exp, get_fid_from_lsm);
	EXP_MD_COUNTER_INCREMENT(exp, get_fid_from_lsm);
	rc = MDP(exp->exp_obd, get_fid_from_lsm)(exp, lsm, name, namelen, fid);
	RETURN(rc);
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
	ENTRY;
	EXP_CHECK_MD_OP(exp, unpackmd);
	EXP_MD_COUNTER_INCREMENT(exp, unpackmd);
	rc = MDP(exp->exp_obd, unpackmd)(exp, plsm, lmm, lmm_size);
	RETURN(rc);
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

/* sysctl.c */
extern int obd_sysctl_init(void);
extern void obd_sysctl_clean(void);

/* uuid.c  */
typedef __u8 class_uuid_t[16];
void class_uuid_unparse(class_uuid_t in, struct obd_uuid *out);

/* lustre_peer.c    */
int lustre_uuid_to_peer(const char *uuid, lnet_nid_t *peer_nid, int index);
int class_add_uuid(const char *uuid, __u64 nid);
int class_del_uuid (const char *uuid);
int class_check_uuid(struct obd_uuid *uuid, __u64 nid);

/* class_obd.c */
extern char obd_jobid_node[];

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
