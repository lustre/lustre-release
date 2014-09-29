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
 * lustre/mdt/mdt_internal.h
 *
 * Lustre Metadata Target (mdt) request handler
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Mike Shaver <shaver@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 * Author: Huang Hua <huanghua@clusterfs.com>
 */

#ifndef _MDT_INTERNAL_H
#define _MDT_INTERNAL_H

#if defined(__KERNEL__)

#include <lustre_net.h>
#include <lustre/lustre_idl.h>
#include <obd_class.h>
#include <lustre_disk.h>
#include <lu_target.h>
#include <md_object.h>
#include <lustre_fid.h>
#include <lustre_fld.h>
#include <lustre_req_layout.h>
#include <lustre_sec.h>
#include <lustre_idmap.h>
#include <lustre_eacl.h>
#include <lustre_quota.h>

/* check if request's xid is equal to last one or not*/
static inline int req_xid_is_last(struct ptlrpc_request *req)
{
        struct lsd_client_data *lcd = req->rq_export->exp_target_data.ted_lcd;
        return (req->rq_xid == lcd->lcd_last_xid ||
                req->rq_xid == lcd->lcd_last_close_xid);
}

struct mdt_object;

/* file data for open files on MDS */
struct mdt_file_data {
	struct portals_handle mfd_handle; /* must be first */
	__u64		      mfd_mode;   /* open mode provided by client */
	cfs_list_t            mfd_list;   /* protected by med_open_lock */
	__u64                 mfd_xid;    /* xid of the open request */
	struct lustre_handle  mfd_old_handle; /* old handle in replay case */
	struct mdt_object    *mfd_object; /* point to opened object */
};

#define CDT_NONBLOCKING_RESTORE		(1ULL << 0)
#define CDT_NORETRY_ACTION		(1ULL << 1)
#define CDT_POLICY_LAST			CDT_NORETRY_ACTION
#define CDT_POLICY_SHIFT_COUNT		2
#define CDT_POLICY_ALL			(CDT_NONBLOCKING_RESTORE | \
					CDT_NORETRY_ACTION)

/* when adding a new policy, do not forget to update
 * lustre/mdt/mdt_coordinator.c::hsm_policy_names[]
 */
#define CDT_DEFAULT_POLICY		CDT_NORETRY_ACTION

enum cdt_states { CDT_STOPPED = 0,
		  CDT_INIT,
		  CDT_RUNNING,
		  CDT_DISABLE,
		  CDT_STOPPING };

/* when multiple lock are needed, the lock order is
 * cdt_llog_lock
 * cdt_agent_lock
 * cdt_counter_lock
 * cdt_restore_lock
 * cdt_request_lock
 */
struct coordinator {
	struct ptlrpc_thread	 cdt_thread;	     /**< coordinator thread */
	struct lu_env		 cdt_env;	     /**< coordinator lustre
						      * env */
	struct lu_context	 cdt_session;	     /** session for lu_ucred */
	struct proc_dir_entry	*cdt_proc_dir;	     /**< cdt /proc directory */
	__u64			 cdt_policy;	     /**< policy flags */
	enum cdt_states		 cdt_state;	      /**< state */
	atomic_t		 cdt_compound_id;     /**< compound id
						       * counter */
	__u64			 cdt_last_cookie;     /**< last cookie
						       * allocated */
	struct mutex		 cdt_llog_lock;       /**< protect llog
						       * access */
	struct rw_semaphore	 cdt_agent_lock;      /**< protect agent list */
	struct rw_semaphore	 cdt_request_lock;    /**< protect request
						       * list */
	struct mutex		 cdt_restore_lock;    /**< protect restore
						       * list */
	cfs_time_t		 cdt_loop_period;     /**< llog scan period */
	cfs_time_t		 cdt_grace_delay;     /**< request grace
						       * delay */
	cfs_time_t		 cdt_active_req_timeout; /**< request timeout */
	__u32			 cdt_default_archive_id; /**< archive id used
						       * when none are
						       * specified */
	__u64			 cdt_max_requests;    /**< max count of started
						       * requests */
	atomic_t		 cdt_request_count;   /**< current count of
						       * started requests */
	struct list_head	 cdt_requests;	      /**< list of started
						       * requests */
	struct list_head	 cdt_agents;	      /**< list of register
						       * agents */
	struct list_head	 cdt_restore_hdl;     /**< list of restore lock
						       * handles */
	/* Bitmasks indexed by the HSMA_XXX constants. */
	__u64			 cdt_user_request_mask;
	__u64			 cdt_group_request_mask;
	__u64			 cdt_other_request_mask;
};

/* mdt state flag bits */
#define MDT_FL_CFGLOG 0
#define MDT_FL_SYNCED 1

struct mdt_device {
	/* super-class */
	struct lu_device	   mdt_lu_dev;
	struct seq_server_site	   mdt_seq_site;
        /* DLM name-space for meta-data locks maintained by this server */
        struct ldlm_namespace     *mdt_namespace;
        /* ptlrpc handle for MDS->client connections (for lock ASTs). */
        struct ptlrpc_client      *mdt_ldlm_client;
        /* underlying device */
	struct obd_export         *mdt_child_exp;
        struct md_device          *mdt_child;
        struct dt_device          *mdt_bottom;
	struct obd_export	  *mdt_bottom_exp;
        /** target device */
        struct lu_target           mdt_lut;
	/*
	 * Options bit-fields.
	 */
	struct {
		unsigned int       mo_user_xattr:1,
				   mo_acl:1,
				   mo_compat_resname:1,
				   mo_mds_capa:1,
				   mo_oss_capa:1,
				   mo_cos:1,
				   mo_coordinator:1;
	} mdt_opts;
        /* mdt state flags */
        unsigned long              mdt_state;
        /* lock to protect IOepoch */
	spinlock_t		   mdt_ioepoch_lock;
        __u64                      mdt_ioepoch;

        /* transaction callbacks */
        struct dt_txn_callback     mdt_txn_cb;

        /* these values should be updated from lov if necessary.
         * or should be placed somewhere else. */
        int                        mdt_max_mdsize;

	int			   mdt_max_ea_size;

        struct upcall_cache        *mdt_identity_cache;

        /* sptlrpc rules */
	rwlock_t		   mdt_sptlrpc_lock;
        struct sptlrpc_rule_set    mdt_sptlrpc_rset;

	/* capability keys */
	unsigned long              mdt_capa_timeout;
	__u32                      mdt_capa_alg;
	struct dt_object          *mdt_ck_obj;
	unsigned long              mdt_ck_timeout;
	unsigned long              mdt_ck_expiry;
	struct timer_list          mdt_ck_timer;
	struct ptlrpc_thread       mdt_ck_thread;
	struct lustre_capa_key     mdt_capa_keys[2];
	unsigned int               mdt_capa_conf:1,
				   mdt_som_conf:1,
				   /* Enable remote dir on non-MDT0 */
				   mdt_enable_remote_dir:1;

	gid_t			   mdt_enable_remote_dir_gid;
	/* statfs optimization: we cache a bit  */
	struct obd_statfs	   mdt_osfs;
	__u64			   mdt_osfs_age;
	spinlock_t		   mdt_osfs_lock;

        /* root squash */
        uid_t                      mdt_squash_uid;
        gid_t                      mdt_squash_gid;
        cfs_list_t                 mdt_nosquash_nids;
        char                      *mdt_nosquash_str;
        int                        mdt_nosquash_strlen;
	struct rw_semaphore	   mdt_squash_sem;

        int                        mdt_sec_level;
        struct rename_stats        mdt_rename_stats;
	struct lu_fid		   mdt_md_root_fid;

	/* connection to quota master */
	struct obd_export	  *mdt_qmt_exp;
	/* quota master device associated with this MDT */
	struct lu_device	  *mdt_qmt_dev;

	struct coordinator	   mdt_coordinator;
};

#define MDT_SERVICE_WATCHDOG_FACTOR	(2)
#define MDT_ROCOMPAT_SUPP	(OBD_ROCOMPAT_LOVOBJID)
#define MDT_INCOMPAT_SUPP	(OBD_INCOMPAT_MDT | OBD_INCOMPAT_COMMON_LR | \
				OBD_INCOMPAT_FID | OBD_INCOMPAT_IAM_DIR | \
				OBD_INCOMPAT_LMM_VER | OBD_INCOMPAT_MULTI_OI)
#define MDT_COS_DEFAULT         (0)

struct mdt_object {
	struct lu_object_header	mot_header;
	struct lu_object	mot_obj;
        __u64                   mot_ioepoch;
        __u64                   mot_flags;
        int                     mot_ioepoch_count;
        int                     mot_writecount;
        /* Lock to protect object's IO epoch. */
	struct mutex		mot_ioepoch_mutex;
        /* Lock to protect create_data */
	struct mutex		mot_lov_mutex;
	/* Lock to protect lease open.
	 * Lease open acquires write lock; normal open acquires read lock */
	struct rw_semaphore	mot_open_sem;
	atomic_t		mot_lease_count;
	atomic_t		mot_open_count;
};

enum mdt_object_flags {
        /** SOM attributes are changed. */
        MOF_SOM_CHANGE  = (1 << 0),
        /**
         * The SOM recovery state for mdt object.
         * This state is an in-memory equivalent of an absent SOM EA, used
         * instead of invalidating SOM EA while IOEpoch is still opened when
         * a client eviction occurs or a client fails to obtain SOM attributes.
         * It indicates that the last IOEpoch holder will need to obtain SOM
         * attributes under [0;EOF] extent lock to flush all the client's
         * cached of evicted from MDS clients (but not necessary evicted from
         * OST) before taking ost attributes.
         */
        MOF_SOM_RECOV   = (1 << 1),
        /** File has been just created. */
        MOF_SOM_CREATED = (1 << 2),
        /** lov object has been created. */
        MOF_LOV_CREATED = (1 << 3),
};

struct mdt_lock_handle {
        /* Lock type, reg for cross-ref use or pdo lock. */
        mdl_type_t              mlh_type;

        /* Regular lock */
        struct lustre_handle    mlh_reg_lh;
        ldlm_mode_t             mlh_reg_mode;

        /* Pdirops lock */
        struct lustre_handle    mlh_pdo_lh;
        ldlm_mode_t             mlh_pdo_mode;
        unsigned int            mlh_pdo_hash;

	/* Remote regular lock */
	struct lustre_handle    mlh_rreg_lh;
	ldlm_mode_t	     mlh_rreg_mode;
};

enum {
	MDT_LH_PARENT,	/* parent lockh */
	MDT_LH_CHILD,	/* child lockh */
	MDT_LH_OLD,	/* old lockh for rename */
	MDT_LH_LAYOUT = MDT_LH_OLD, /* layout lock */
	MDT_LH_NEW,	/* new lockh for rename */
	MDT_LH_RMT,	/* used for return lh to caller */
	MDT_LH_LOCAL,	/* local lock never return to client */
	MDT_LH_NR
};

enum {
        MDT_LOCAL_LOCK,
        MDT_CROSS_LOCK
};

struct mdt_reint_record {
        mdt_reint_t             rr_opcode;
        const struct lustre_handle *rr_handle;
        const struct lu_fid    *rr_fid1;
        const struct lu_fid    *rr_fid2;
        const char             *rr_name;
        int                     rr_namelen;
        const char             *rr_tgt;
        int                     rr_tgtlen;
        const void             *rr_eadata;
        int                     rr_eadatalen;
        int                     rr_logcookielen;
        const struct llog_cookie  *rr_logcookies;
        __u32                   rr_flags;
};

enum mdt_reint_flag {
        MRF_OPEN_TRUNC = 1 << 0,
};

struct mdt_thread_info;
struct tx_arg;
typedef int (*tx_exec_func_t)(const struct lu_env *, struct thandle *,
			      struct tx_arg *);

struct tx_arg {
	tx_exec_func_t		exec_fn;
	tx_exec_func_t		undo_fn;
	struct dt_object	*object;
	char			*file;
	struct update_reply	*reply;
	int			line;
	int			index;
	union {
		struct {
			const struct dt_rec	*rec;
			const struct dt_key	*key;
		} insert;
		struct {
		} ref;
		struct {
			struct lu_attr	attr;
		} attr_set;
		struct {
			struct lu_buf	buf;
			const char	*name;
			int		flags;
			__u32		csum;
		} xattr_set;
		struct {
			struct lu_attr			attr;
			struct dt_allocation_hint	hint;
			struct dt_object_format		dof;
			struct lu_fid			fid;
		} create;
		struct {
			struct lu_buf	buf;
			loff_t		pos;
		} write;
		struct {
			struct ost_body	    *body;
		} destroy;
	} u;
};

#define TX_MAX_OPS	  10
struct thandle_exec_args {
	struct thandle		*ta_handle;
	struct dt_device	*ta_dev;
	int			ta_err;
	struct tx_arg		ta_args[TX_MAX_OPS];
	int			ta_argno;   /* used args */
};

/*
 * Common data shared by mdt-level handlers. This is allocated per-thread to
 * reduce stack consumption.
 */
struct mdt_thread_info {
        /*
         * XXX: Part One:
         * The following members will be filled explicitly
         * with specific data in mdt_thread_info_init().
         */
        /* TODO: move this into mdt_session_key(with LCT_SESSION), because
         * request handling may migrate from one server thread to another.
         */
        struct req_capsule        *mti_pill;

        /* although we have export in req, there are cases when it is not
         * available, e.g. closing files upon export destroy */
        struct obd_export          *mti_exp;
        /*
         * A couple of lock handles.
         */
        struct mdt_lock_handle     mti_lh[MDT_LH_NR];

        struct mdt_device         *mti_mdt;
        const struct lu_env       *mti_env;
	/* XXX: temporary flag to have healthy mti during OUT calls
	 * to be removed upon moving MDT to the unified target code */
	bool			   mti_txn_compat;

        /*
         * Additional fail id that can be set by handler. Passed to
         * target_send_reply().
         */
        int                        mti_fail_id;

        /* transaction number of current request */
        __u64                      mti_transno;


        /*
         * XXX: Part Two:
         * The following members will be filled expilictly
         * with zero in mdt_thread_info_init(). These members may be used
         * by all requests.
         */

        /*
         * Object attributes.
         */
        struct md_attr             mti_attr;
        /*
         * Body for "habeo corpus" operations.
         */
        const struct mdt_body     *mti_body;
        /*
         * Host object. This is released at the end of mdt_handler().
         */
        struct mdt_object         *mti_object;
        /*
         * Lock request for "habeo clavis" operations.
         */
        const struct ldlm_request *mti_dlm_req;

        __u32                      mti_has_trans:1, /* has txn already? */
                                   mti_cross_ref:1;

        /* opdata for mdt_reint_open(), has the same as
         * ldlm_reply:lock_policy_res1.  mdt_update_last_rcvd() stores this
         * value onto disk for recovery when mdt_trans_stop_cb() is called.
         */
        __u64                      mti_opdata;

        /*
         * XXX: Part Three:
         * The following members will be filled explicitly
         * with zero in mdt_reint_unpack(), because they are only used
         * by reint requests (including mdt_reint_open()).
         */

        /*
         * reint record. contains information for reint operations.
         */
        struct mdt_reint_record    mti_rr;

        /** md objects included in operation */
        struct mdt_object         *mti_mos;
        __u64                      mti_ver[PTLRPC_NUM_VERSIONS];
        /*
         * Operation specification (currently create and lookup)
         */
        struct md_op_spec          mti_spec;

        /*
         * XXX: Part Four:
         * The following members will _NOT_ be initialized at all.
         * DO NOT expect them to contain any valid value.
         * They should be initialized explicitly by the user themselves.
         */

         /* XXX: If something is in a union, make sure they do not conflict */

        struct lu_fid              mti_tmp_fid1;
        struct lu_fid              mti_tmp_fid2;
        ldlm_policy_data_t         mti_policy;    /* for mdt_object_lock() and
                                                   * mdt_rename_lock() */
        struct ldlm_res_id         mti_res_id;    /* for mdt_object_lock() and
                                                     mdt_rename_lock()   */
        union {
                struct obd_uuid    uuid[2];       /* for mdt_seq_init_cli()  */
                char               ns_name[48];   /* for mdt_init0()         */
                struct lustre_cfg_bufs bufs;      /* for mdt_stack_fini()    */
		struct obd_statfs  osfs;          /* for mdt_statfs()        */
                struct {
                        /* for mdt_readpage()      */
                        struct lu_rdpg     mti_rdpg;
                        /* for mdt_sendpage()      */
                        struct l_wait_info mti_wait_info;
                } rdpg;
                struct {
                        struct md_attr attr;
                        struct md_som_data data;
                } som;
		struct {
			struct dt_object_format	mti_update_dof;
			struct update_reply	*mti_update_reply;
			struct update		*mti_update;
			int			mti_update_reply_index;
			struct obdo		mti_obdo;
			struct dt_object	*mti_dt_object;
		} update;
        } mti_u;

        /* IO epoch related stuff. */
        struct mdt_ioepoch        *mti_ioepoch;
        __u64                      mti_replayepoch;

	loff_t                     mti_off;
	struct lu_buf              mti_buf;
	struct lu_buf              mti_big_buf;
	struct lustre_capa_key     mti_capa_key;

        /* Ops object filename */
        struct lu_name             mti_name;
	/* per-thread values, can be re-used */
	void			  *mti_big_lmm;
	int			   mti_big_lmmsize;
	/* big_lmm buffer was used and must be used in reply */
	int			   mti_big_lmm_used;
	/* should be enough to fit lustre_mdt_attrs */
	char			   mti_xattr_buf[128];
	struct thandle_exec_args   mti_handle;
	struct ldlm_enqueue_info   mti_einfo;
};

/* ptlrpc request handler for MDT. All handlers are
 * grouped into several slices - struct mdt_opc_slice,
 * and stored in an array - mdt_handlers[].
 */
struct mdt_handler {
	/* The name of this handler. */
	const char *mh_name;
	/* Fail id for this handler, checked at the beginning of this handler*/
	int	 mh_fail_id;
	/* Operation code for this handler */
	__u32       mh_opc;
	/* flags are listed in enum mdt_handler_flags below. */
	__u32       mh_flags;
	/* The actual handler function to execute. */
	int (*mh_act)(struct mdt_thread_info *info);
	/* Request format for this request. */
	const struct req_format *mh_fmt;
};

struct mdt_opc_slice {
	__u32			mos_opc_start;
	int			mos_opc_end;
	struct mdt_handler	*mos_hs;
};

struct cdt_req_progress {
	struct mutex		 crp_lock;	/**< protect tree */
	struct interval_node	*crp_root;	/**< tree to track extent
						 *   moved */
	struct interval_node	**crp_node;	/**< buffer for tree nodes
						 *   vector of fixed size
						 *   vectors */
	int			 crp_cnt;	/**< # of used nodes */
	int			 crp_max;	/**< # of allocated nodes */
};

struct cdt_agent_req {
	cfs_list_t		 car_request_list; /**< to chain all the req. */
	atomic_t		 car_refcount;     /**< reference counter */
	__u64			 car_compound_id;  /**< compound id */
	__u64			 car_flags;        /**< request original flags */
	struct obd_uuid		 car_uuid;         /**< agent doing the req. */
	__u32			 car_archive_id;   /**< archive id */
	int			 car_canceled;     /**< request was canceled */
	cfs_time_t		 car_req_start;    /**< start time */
	cfs_time_t		 car_req_update;   /**< last update time */
	struct hsm_action_item	*car_hai;          /**< req. to the agent */
	struct cdt_req_progress	 car_progress;     /**< track data mvt
						    *   progress */
};
extern struct kmem_cache *mdt_hsm_car_kmem;

struct hsm_agent {
	cfs_list_t	 ha_list;		/**< to chain the agents */
	struct obd_uuid	 ha_uuid;		/**< agent uuid */
	__u32		*ha_archive_id;		/**< archive id */
	int		 ha_archive_cnt;	/**< number of archive entries
						 *   0 means any archive */
	atomic_t	 ha_requests;		/**< current request count */
	atomic_t	 ha_success;		/**< number of successful
						 * actions */
	atomic_t	 ha_failure;		/**< number of failed actions */
};

struct cdt_restore_handle {
	cfs_list_t		 crh_list;	/**< to chain the handle */
	struct lu_fid		 crh_fid;	/**< fid of the object */
	struct ldlm_extent	 crh_extent;	/**< extent of the restore */
	struct mdt_lock_handle	 crh_lh;	/**< lock handle */
};
extern struct kmem_cache *mdt_hsm_cdt_kmem;	/** restore handle slab cache */

static inline const struct md_device_operations *
mdt_child_ops(struct mdt_device * m)
{
        LASSERT(m->mdt_child);
        return m->mdt_child->md_ops;
}

static inline struct md_object *mdt_object_child(struct mdt_object *o)
{
	LASSERT(o);
	return lu2md(lu_object_next(&o->mot_obj));
}

static inline struct ptlrpc_request *mdt_info_req(struct mdt_thread_info *info)
{
         return info->mti_pill ? info->mti_pill->rc_req : NULL;
}

static inline __u64 mdt_conn_flags(struct mdt_thread_info *info)
{
	LASSERT(info->mti_exp);
	return exp_connect_flags(info->mti_exp);
}

static inline void mdt_object_get(const struct lu_env *env,
				  struct mdt_object *o)
{
	ENTRY;
	lu_object_get(&o->mot_obj);
	EXIT;
}

static inline void mdt_object_put(const struct lu_env *env,
				  struct mdt_object *o)
{
	ENTRY;
	lu_object_put(env, &o->mot_obj);
	EXIT;
}

static inline int mdt_object_exists(const struct mdt_object *o)
{
	return lu_object_exists(&o->mot_obj);
}

static inline int mdt_object_remote(const struct mdt_object *o)
{
	return lu_object_remote(&o->mot_obj);
}

static inline const struct lu_fid *mdt_object_fid(const struct mdt_object *o)
{
	return lu_object_fid(&o->mot_obj);
}

static inline struct lu_site *mdt_lu_site(const struct mdt_device *mdt)
{
	return mdt->mdt_lu_dev.ld_site;
}

static inline struct seq_server_site *mdt_seq_site(struct mdt_device *mdt)
{
	return &mdt->mdt_seq_site;
}

static inline void mdt_export_evict(struct obd_export *exp)
{
        class_fail_export(exp);
        class_export_put(exp);
}

/* Here we use LVB_TYPE to check dne client, because it is
 * also landed on 2.4. */
static inline int mdt_is_dne_client(struct obd_export *exp)
{
	return !!(exp_connect_flags(exp) & OBD_CONNECT_LVB_TYPE);
}

int mdt_get_disposition(struct ldlm_reply *rep, int flag);
void mdt_set_disposition(struct mdt_thread_info *info,
                        struct ldlm_reply *rep, int flag);
void mdt_clear_disposition(struct mdt_thread_info *info,
                        struct ldlm_reply *rep, int flag);

void mdt_lock_pdo_init(struct mdt_lock_handle *lh,
                       ldlm_mode_t lm, const char *name,
                       int namelen);

void mdt_lock_reg_init(struct mdt_lock_handle *lh,
                       ldlm_mode_t lm);

int mdt_lock_setup(struct mdt_thread_info *info,
                   struct mdt_object *o,
                   struct mdt_lock_handle *lh);

int mdt_check_resent_lock(struct mdt_thread_info *info,
			  struct mdt_object *mo,
			  struct mdt_lock_handle *lhc);

int mdt_object_lock(struct mdt_thread_info *,
                    struct mdt_object *,
                    struct mdt_lock_handle *,
                    __u64, int);

int mdt_object_lock_try(struct mdt_thread_info *,
			struct mdt_object *,
			struct mdt_lock_handle *,
			__u64, int);

void mdt_object_unlock(struct mdt_thread_info *,
                       struct mdt_object *,
                       struct mdt_lock_handle *,
                       int decref);

struct mdt_object *mdt_object_new(const struct lu_env *,
				  struct mdt_device *,
				  const struct lu_fid *);
struct mdt_object *mdt_object_find(const struct lu_env *,
                                   struct mdt_device *,
                                   const struct lu_fid *);
struct mdt_object *mdt_object_find_lock(struct mdt_thread_info *,
                                        const struct lu_fid *,
                                        struct mdt_lock_handle *,
                                        __u64);
void mdt_object_unlock_put(struct mdt_thread_info *,
                           struct mdt_object *,
                           struct mdt_lock_handle *,
                           int decref);

void mdt_client_compatibility(struct mdt_thread_info *info);

int mdt_remote_object_lock(struct mdt_thread_info *mti,
			   struct mdt_object *o, struct lustre_handle *lh,
			   ldlm_mode_t mode, __u64 ibits);
int mdt_close_unpack(struct mdt_thread_info *info);
int mdt_reint_unpack(struct mdt_thread_info *info, __u32 op);
int mdt_reint_rec(struct mdt_thread_info *, struct mdt_lock_handle *);
void mdt_pack_attr2body(struct mdt_thread_info *info, struct mdt_body *b,
                        const struct lu_attr *attr, const struct lu_fid *fid);

int mdt_getxattr(struct mdt_thread_info *info);
int mdt_reint_setxattr(struct mdt_thread_info *info,
                       struct mdt_lock_handle *lh);

void mdt_lock_handle_init(struct mdt_lock_handle *lh);
void mdt_lock_handle_fini(struct mdt_lock_handle *lh);

void mdt_reconstruct(struct mdt_thread_info *, struct mdt_lock_handle *);
void mdt_reconstruct_generic(struct mdt_thread_info *mti,
                             struct mdt_lock_handle *lhc);

extern void target_recovery_fini(struct obd_device *obd);
extern void target_recovery_init(struct lu_target *lut,
                                 svc_handler_t handler);
int mdt_fs_setup(const struct lu_env *, struct mdt_device *,
                 struct obd_device *, struct lustre_sb_info *lsi);
void mdt_fs_cleanup(const struct lu_env *, struct mdt_device *);

int mdt_export_stats_init(struct obd_device *obd,
                          struct obd_export *exp,
                          void *client_nid);

int mdt_pin(struct mdt_thread_info* info);

int mdt_lock_new_child(struct mdt_thread_info *info,
                       struct mdt_object *o,
                       struct mdt_lock_handle *child_lockh);

void mdt_mfd_set_mode(struct mdt_file_data *mfd,
		      __u64 mode);

int mdt_reint_open(struct mdt_thread_info *info,
                   struct mdt_lock_handle *lhc);

struct mdt_file_data *mdt_handle2mfd(struct mdt_export_data *med,
				     const struct lustre_handle *handle,
				     bool is_replay);

enum {
        MDT_IOEPOCH_CLOSED  = 0,
        MDT_IOEPOCH_OPENED  = 1,
        MDT_IOEPOCH_GETATTR = 2,
};

enum {
        MDT_SOM_DISABLE = 0,
        MDT_SOM_ENABLE  = 1,
};

int mdt_attr_get_complex(struct mdt_thread_info *info,
			 struct mdt_object *o, struct md_attr *ma);
int mdt_ioepoch_open(struct mdt_thread_info *info, struct mdt_object *o,
                     int created);
int mdt_object_is_som_enabled(struct mdt_object *mo);
int mdt_write_get(struct mdt_object *o);
void mdt_write_put(struct mdt_object *o);
int mdt_write_read(struct mdt_object *o);
struct mdt_file_data *mdt_mfd_new(const struct mdt_export_data *med);
int mdt_mfd_close(struct mdt_thread_info *info, struct mdt_file_data *mfd);
void mdt_mfd_free(struct mdt_file_data *mfd);
int mdt_close(struct mdt_thread_info *info);
int mdt_attr_set(struct mdt_thread_info *info, struct mdt_object *mo,
                 struct md_attr *ma, int flags);
int mdt_add_dirty_flag(struct mdt_thread_info *info, struct mdt_object *mo,
			struct md_attr *ma);
int mdt_done_writing(struct mdt_thread_info *info);
int mdt_fix_reply(struct mdt_thread_info *info);
int mdt_handle_last_unlink(struct mdt_thread_info *, struct mdt_object *,
                           const struct md_attr *);
void mdt_reconstruct_open(struct mdt_thread_info *, struct mdt_lock_handle *);

struct lu_buf *mdt_buf(const struct lu_env *env, void *area, ssize_t len);
const struct lu_buf *mdt_buf_const(const struct lu_env *env,
                                   const void *area, ssize_t len);

void mdt_dump_lmm(int level, const struct lov_mds_md *lmm, __u64 valid);

int mdt_check_ucred(struct mdt_thread_info *);
int mdt_init_ucred(struct mdt_thread_info *, struct mdt_body *);
int mdt_init_ucred_reint(struct mdt_thread_info *);
void mdt_exit_ucred(struct mdt_thread_info *);
int mdt_version_get_check(struct mdt_thread_info *, struct mdt_object *, int);
void mdt_version_get_save(struct mdt_thread_info *, struct mdt_object *, int);
int mdt_version_get_check_save(struct mdt_thread_info *, struct mdt_object *,
                               int);
int mdt_handle_common(struct ptlrpc_request *req,
		      struct mdt_opc_slice *supported);
int mdt_connect(struct mdt_thread_info *info);
int mdt_disconnect(struct mdt_thread_info *info);
int mdt_set_info(struct mdt_thread_info *info);
int mdt_get_info(struct mdt_thread_info *info);
int mdt_getstatus(struct mdt_thread_info *info);
int mdt_getattr(struct mdt_thread_info *info);
int mdt_getattr_name(struct mdt_thread_info *info);
int mdt_statfs(struct mdt_thread_info *info);
int mdt_reint(struct mdt_thread_info *info);
int mdt_sync(struct mdt_thread_info *info);
int mdt_is_subdir(struct mdt_thread_info *info);
int mdt_obd_ping(struct mdt_thread_info *info);
int mdt_obd_log_cancel(struct mdt_thread_info *info);
int mdt_obd_qc_callback(struct mdt_thread_info *info);
int mdt_enqueue(struct mdt_thread_info *info);
int mdt_convert(struct mdt_thread_info *info);
int mdt_bl_callback(struct mdt_thread_info *info);
int mdt_cp_callback(struct mdt_thread_info *info);
int mdt_llog_create(struct mdt_thread_info *info);
int mdt_llog_destroy(struct mdt_thread_info *info);
int mdt_llog_read_header(struct mdt_thread_info *info);
int mdt_llog_next_block(struct mdt_thread_info *info);
int mdt_llog_prev_block(struct mdt_thread_info *info);
int mdt_sec_ctx_handle(struct mdt_thread_info *info);
int mdt_readpage(struct mdt_thread_info *info);
int mdt_obd_idx_read(struct mdt_thread_info *info);
int mdt_tgt_connect(struct tgt_session_info *tsi);
void mdt_thread_info_init(struct ptlrpc_request *req,
			  struct mdt_thread_info *mti);
void mdt_thread_info_fini(struct mdt_thread_info *mti);

extern struct mdt_opc_slice mdt_regular_handlers[];
extern struct mdt_opc_slice mdt_seq_handlers[];
extern struct mdt_opc_slice mdt_fld_handlers[];

int mdt_quotacheck(struct mdt_thread_info *info);
int mdt_quotactl(struct mdt_thread_info *info);
int mdt_quota_dqacq(struct mdt_thread_info *info);
int mdt_swap_layouts(struct mdt_thread_info *info);

extern struct lprocfs_vars lprocfs_mds_module_vars[];
extern struct lprocfs_vars lprocfs_mds_obd_vars[];

int mdt_hsm_attr_set(struct mdt_thread_info *info, struct mdt_object *obj,
		     const struct md_hsm *mh);

struct mdt_handler *mdt_handler_find(__u32 opc,
				     struct mdt_opc_slice *supported);
/* mdt_idmap.c */
int mdt_init_sec_level(struct mdt_thread_info *);
int mdt_init_idmap(struct mdt_thread_info *);
void mdt_cleanup_idmap(struct mdt_export_data *);
int mdt_handle_idmap(struct mdt_thread_info *);
int ptlrpc_user_desc_do_idmap(struct ptlrpc_request *,
                              struct ptlrpc_user_desc *);
void mdt_body_reverse_idmap(struct mdt_thread_info *,
                            struct mdt_body *);
int mdt_remote_perm_reverse_idmap(struct ptlrpc_request *,
                                  struct mdt_remote_perm *);
int mdt_fix_attr_ucred(struct mdt_thread_info *, __u32);

static inline struct mdt_device *mdt_dev(struct lu_device *d)
{
	return container_of0(d, struct mdt_device, mdt_lu_dev);
}

static inline struct dt_object *mdt_obj2dt(struct mdt_object *mo)
{
	struct lu_object	*lo;
	struct mdt_device	*mdt = mdt_dev(mo->mot_obj.lo_dev);

	lo = lu_object_locate(mo->mot_obj.lo_header,
			      mdt->mdt_bottom->dd_lu_dev.ld_type);

	return lu2dt(lo);
}

/* mdt/mdt_identity.c */
#define MDT_IDENTITY_UPCALL_PATH        "/usr/sbin/l_getidentity"

extern struct upcall_cache_ops mdt_identity_upcall_cache_ops;

struct md_identity *mdt_identity_get(struct upcall_cache *, __u32);

void mdt_identity_put(struct upcall_cache *, struct md_identity *);

void mdt_flush_identity(struct upcall_cache *, int);

__u32 mdt_identity_get_perm(struct md_identity *, __u32, lnet_nid_t);

int mdt_pack_remote_perm(struct mdt_thread_info *, struct mdt_object *, void *);

/* mdt/mdt_hsm.c */
int mdt_hsm_state_get(struct mdt_thread_info *info);
int mdt_hsm_state_set(struct mdt_thread_info *info);
int mdt_hsm_action(struct mdt_thread_info *info);
int mdt_hsm_progress(struct mdt_thread_info *info);
int mdt_hsm_ct_register(struct mdt_thread_info *info);
int mdt_hsm_ct_unregister(struct mdt_thread_info *info);
int mdt_hsm_request(struct mdt_thread_info *info);
/* mdt/mdt_hsm_cdt_actions.c */
extern const struct file_operations mdt_hsm_actions_fops;
void dump_llog_agent_req_rec(const char *prefix,
			     const struct llog_agent_req_rec *larr);
int cdt_llog_process(const struct lu_env *env, struct mdt_device *mdt,
		     llog_cb_t cb, void *data);
int mdt_agent_record_add(const struct lu_env *env, struct mdt_device *mdt,
			 __u64 compound_id, __u32 archive_id,
			 __u64 flags, struct hsm_action_item *hai);
int mdt_agent_record_update(const struct lu_env *env,
			    struct mdt_device *mdt, __u64 *cookies,
			    int cookies_count, enum agent_req_status status);
int mdt_agent_llog_update_rec(const struct lu_env *env, struct mdt_device *mdt,
			      struct llog_handle *llh,
			      struct llog_agent_req_rec *larr);

/* mdt/mdt_hsm_cdt_agent.c */
extern const struct file_operations mdt_hsm_agent_fops;
int mdt_hsm_agent_register(struct mdt_thread_info *info,
			   const struct obd_uuid *uuid,
			   int nr_archives, __u32 *archive_num);
int mdt_hsm_agent_register_mask(struct mdt_thread_info *info,
				const struct obd_uuid *uuid,
				__u32 archive_mask);
int mdt_hsm_agent_unregister(struct mdt_thread_info *info,
			     const struct obd_uuid *uuid);
int mdt_hsm_agent_update_statistics(struct coordinator *cdt,
				    int succ_rq, int fail_rq, int new_rq,
				    const struct obd_uuid *uuid);
int mdt_hsm_find_best_agent(struct coordinator *cdt, __u32 archive,
			    struct obd_uuid *uuid);
int mdt_hsm_agent_send(struct mdt_thread_info *mti, struct hsm_action_list *hal,
		       bool purge);
int mdt_hsm_coordinator_update(struct mdt_thread_info *mti,
			       struct hsm_progress_kernel *pgs);
/* mdt/mdt_hsm_cdt_client.c */
int mdt_hsm_add_actions(struct mdt_thread_info *info,
			struct hsm_action_list *hal, __u64 *compound_id);
int mdt_hsm_get_actions(struct mdt_thread_info *mti,
			struct hsm_action_list *hal);
int mdt_hsm_get_running(struct mdt_thread_info *mti,
			struct hsm_action_list *hal);
bool mdt_hsm_restore_is_running(struct mdt_thread_info *mti,
				const struct lu_fid *fid);
/* mdt/mdt_hsm_cdt_requests.c */
extern const struct file_operations mdt_hsm_active_requests_fops;
void dump_requests(char *prefix, struct coordinator *cdt);
struct cdt_agent_req *mdt_cdt_alloc_request(__u64 compound_id, __u32 archive_id,
					    __u64 flags, struct obd_uuid *uuid,
					    struct hsm_action_item *hai);
void mdt_cdt_free_request(struct cdt_agent_req *car);
int mdt_cdt_add_request(struct coordinator *cdt, struct cdt_agent_req *new_car);
struct cdt_agent_req *mdt_cdt_find_request(struct coordinator *cdt,
					   const __u64 cookie,
					   const struct lu_fid *fid);
void mdt_cdt_get_work_done(struct cdt_agent_req *car, __u64 *done_sz);
void mdt_cdt_get_request(struct cdt_agent_req *car);
void mdt_cdt_put_request(struct cdt_agent_req *car);
struct cdt_agent_req *mdt_cdt_update_request(struct coordinator *cdt,
					 const struct hsm_progress_kernel *pgs);
int mdt_cdt_remove_request(struct coordinator *cdt, __u64 cookie);
/* mdt/mdt_coordinator.c */
void mdt_hsm_dump_hal(int level, const char *prefix,
		      struct hsm_action_list *hal);
/* coordinator management */
int mdt_hsm_cdt_init(struct mdt_device *mdt);
int mdt_hsm_cdt_start(struct mdt_device *mdt);
int mdt_hsm_cdt_stop(struct mdt_device *mdt);
int mdt_hsm_cdt_fini(struct mdt_device *mdt);
int mdt_hsm_cdt_wakeup(struct mdt_device *mdt);

/* coordinator control /proc interface */
int lprocfs_wr_hsm_cdt_control(struct file *file, const char *buffer,
			       unsigned long count, void *data);
int lprocfs_rd_hsm_cdt_control(char *page, char **start, off_t off,
			       int count, int *eof, void *data);
int hsm_cdt_procfs_init(struct mdt_device *mdt);
void hsm_cdt_procfs_fini(struct mdt_device *mdt);
struct lprocfs_vars *hsm_cdt_get_proc_vars(void);
/* md_hsm helpers */
struct mdt_object *mdt_hsm_get_md_hsm(struct mdt_thread_info *mti,
				      const struct lu_fid *fid,
				      struct md_hsm *hsm);
/* actions/request helpers */
int mdt_hsm_add_hal(struct mdt_thread_info *mti,
		    struct hsm_action_list *hal, struct obd_uuid *uuid);
bool mdt_hsm_is_action_compat(const struct hsm_action_item *hai,
			      const int hal_an, const __u64 rq_flags,
			      const struct md_hsm *hsm);
int mdt_hsm_update_request_state(struct mdt_thread_info *mti,
				 struct hsm_progress_kernel *pgs,
				 const int update_record);

extern struct lu_context_key       mdt_thread_key;
/* debug issues helper starts here*/
static inline int mdt_fail_write(const struct lu_env *env,
                                 struct dt_device *dd, int id)
{
        if (OBD_FAIL_CHECK_ORSET(id, OBD_FAIL_ONCE)) {
                CERROR(LUSTRE_MDT_NAME": cfs_fail_loc=%x, fail write ops\n",
                       id);
                return dd->dd_ops->dt_ro(env, dd);
                /* We set FAIL_ONCE because we never "un-fail" a device */
        }

        return 0;
}

static inline struct mdt_export_data *mdt_req2med(struct ptlrpc_request *req)
{
        return &req->rq_export->exp_mdt_data;
}

typedef void (*mdt_reconstruct_t)(struct mdt_thread_info *mti,
                                  struct mdt_lock_handle *lhc);
static inline int mdt_check_resent(struct mdt_thread_info *info,
                                   mdt_reconstruct_t reconstruct,
                                   struct mdt_lock_handle *lhc)
{
        struct ptlrpc_request *req = mdt_info_req(info);
        ENTRY;

        if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
                if (req_xid_is_last(req)) {
                        reconstruct(info, lhc);
                        RETURN(1);
                }
                DEBUG_REQ(D_HA, req, "no reply for RESENT req (have "LPD64")",
                          req->rq_export->exp_target_data.ted_lcd->lcd_last_xid);
        }
        RETURN(0);
}

struct lu_ucred *mdt_ucred(const struct mdt_thread_info *info);
struct lu_ucred *mdt_ucred_check(const struct mdt_thread_info *info);

static inline int is_identity_get_disabled(struct upcall_cache *cache)
{
        return cache ? (strcmp(cache->uc_upcall, "NONE") == 0) : 1;
}

int mdt_blocking_ast(struct ldlm_lock*, struct ldlm_lock_desc*, void*, int);

/* Issues dlm lock on passed @ns, @f stores it lock handle into @lh. */
static inline int mdt_fid_lock(struct ldlm_namespace *ns,
                               struct lustre_handle *lh,
                               ldlm_mode_t mode,
                               ldlm_policy_data_t *policy,
                               const struct ldlm_res_id *res_id,
			       __u64 flags, const __u64 *client_cookie)
{
        int rc;

        LASSERT(ns != NULL);
        LASSERT(lh != NULL);

        rc = ldlm_cli_enqueue_local(ns, res_id, LDLM_IBITS, policy,
                                    mode, &flags, mdt_blocking_ast,
                                    ldlm_completion_ast, NULL, NULL, 0,
				    LVB_T_NONE, client_cookie, lh);
        return rc == ELDLM_OK ? 0 : -EIO;
}

static inline void mdt_fid_unlock(struct lustre_handle *lh,
                                  ldlm_mode_t mode)
{
        ldlm_lock_decref(lh, mode);
}

extern mdl_mode_t mdt_mdl_lock_modes[];
extern ldlm_mode_t mdt_dlm_lock_modes[];

static inline mdl_mode_t mdt_dlm_mode2mdl_mode(ldlm_mode_t mode)
{
        LASSERT(IS_PO2(mode));
        return mdt_mdl_lock_modes[mode];
}

static inline ldlm_mode_t mdt_mdl_mode2dlm_mode(mdl_mode_t mode)
{
        LASSERT(IS_PO2(mode));
        return mdt_dlm_lock_modes[mode];
}

/* mdt_lvb.c */
extern struct ldlm_valblock_ops mdt_lvbo;

static inline struct lu_name *mdt_name(const struct lu_env *env,
                                       char *name, int namelen)
{
        struct lu_name *lname;
        struct mdt_thread_info *mti;

        LASSERT(namelen > 0);
        /* trailing '\0' in buffer */
        LASSERT(name[namelen] == '\0');

        mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
        lname = &mti->mti_name;
        lname->ln_name = name;
        lname->ln_namelen = namelen;
        return lname;
}

static inline struct lu_name *mdt_name_copy(struct lu_name *tlname,
                                            struct lu_name *slname)
{
        LASSERT(tlname);
        LASSERT(slname);

        tlname->ln_name = slname->ln_name;
        tlname->ln_namelen = slname->ln_namelen;
        return tlname;
}

void mdt_enable_cos(struct mdt_device *, int);
int mdt_cos_is_enabled(struct mdt_device *);

/* lprocfs stuff */
enum {
        LPROC_MDT_OPEN = 0,
        LPROC_MDT_CLOSE,
        LPROC_MDT_MKNOD,
        LPROC_MDT_LINK,
        LPROC_MDT_UNLINK,
        LPROC_MDT_MKDIR,
        LPROC_MDT_RMDIR,
        LPROC_MDT_RENAME,
        LPROC_MDT_GETATTR,
        LPROC_MDT_SETATTR,
        LPROC_MDT_GETXATTR,
        LPROC_MDT_SETXATTR,
        LPROC_MDT_STATFS,
        LPROC_MDT_SYNC,
        LPROC_MDT_SAMEDIR_RENAME,
        LPROC_MDT_CROSSDIR_RENAME,
        LPROC_MDT_LAST,
};
void mdt_counter_incr(struct ptlrpc_request *req, int opcode);
void mdt_stats_counter_init(struct lprocfs_stats *stats);
void lprocfs_mdt_init_vars(struct lprocfs_static_vars *lvars);
void lprocfs_mds_init_vars(struct lprocfs_static_vars *lvars);
int mdt_procfs_init(struct mdt_device *mdt, const char *name);
void mdt_procfs_fini(struct mdt_device *mdt);

/* lustre/mdt_mdt_lproc.c */
int lprocfs_mdt_open_files_seq_open(struct inode *inode,
				    struct file *file);
void mdt_rename_counter_tally(struct mdt_thread_info *info,
			      struct mdt_device *mdt,
			      struct ptlrpc_request *req,
			      struct mdt_object *src, struct mdt_object *tgt);

/* Capability */
int mdt_ck_thread_start(struct mdt_device *mdt);
void mdt_ck_thread_stop(struct mdt_device *mdt);
void mdt_ck_timer_callback(unsigned long castmeharder);
int mdt_capa_keys_init(const struct lu_env *env, struct mdt_device *mdt);
void mdt_set_capainfo(struct mdt_thread_info *info, int offset,
		      const struct lu_fid *fid, struct lustre_capa *capa);
void mdt_dump_capainfo(struct mdt_thread_info *info);

static inline struct obd_device *mdt2obd_dev(const struct mdt_device *mdt)
{
	return mdt->mdt_lu_dev.ld_obd;
}

extern const struct lu_device_operations mdt_lu_ops;

static inline int lu_device_is_mdt(struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &mdt_lu_ops);
}

static inline struct mdt_device *lu2mdt_dev(struct lu_device *d)
{
	LASSERTF(lu_device_is_mdt(d), "It is %s instead of MDT %p %p\n",
		 d->ld_type->ldt_name, d->ld_ops, &mdt_lu_ops);
	return container_of0(d, struct mdt_device, mdt_lu_dev);
}

static inline char *mdt_obd_name(struct mdt_device *mdt)
{
	return mdt->mdt_lu_dev.ld_obd->obd_name;
}

int mds_mod_init(void);
void mds_mod_exit(void);

#endif /* __KERNEL__ */
#endif /* _MDT_H */
