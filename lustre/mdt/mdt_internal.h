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

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_hash.h>
#include <upcall_cache.h>
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
#include <lustre_linkea.h>

struct mdt_object;

/* file data for open files on MDS */
struct mdt_file_data {
	/**  portals handle must be first */
	struct portals_handle	mfd_handle;
	/** open mode provided by client */
	__u64			mfd_mode;
	/** protected by med_open_lock */
	struct list_head	mfd_list;
	/** xid of the open request */
	__u64			mfd_xid;
	/** old handle in replay case */
	struct lustre_handle	mfd_old_handle;
	/** point to opened object */
	struct mdt_object	*mfd_object;
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

/* Coordinator states. Keep the cdt_transition table in sync. */
enum cdt_states { CDT_STOPPED = 0,
		  CDT_INIT,
		  CDT_RUNNING,
		  CDT_DISABLE,
		  CDT_STOPPING,

		  CDT_STATES_COUNT
};

static inline char *cdt_mdt_state2str(int state)
{
	switch (state) {
	case CDT_INIT:
		return "init";
	case CDT_RUNNING:
		return "enabled";
	case CDT_STOPPING:
		return "stopping";
	case CDT_STOPPED:
		return "stopped";
	case CDT_DISABLE:
		return "disabled";
	default:
		return "unknown";
	}
}

/* when multiple lock are needed, the lock order is
 * cdt_llog_lock
 * cdt_agent_lock
 * cdt_counter_lock
 * cdt_restore_lock
 * cdt_request_lock
 */
struct coordinator {
	wait_queue_head_t	 cdt_waitq;	     /**< cdt wait queue */
	bool			 cdt_event;	     /**< coordinator event */
	struct task_struct	*cdt_task;	     /**< cdt thread handle */
	struct lu_env		 cdt_env;	     /**< coordinator lustre
						      * env */
	struct lu_context	 cdt_session;	     /** session for lu_ucred */
	struct proc_dir_entry	*cdt_proc_dir;	     /**< cdt /proc directory */
	__u64			 cdt_policy;	     /**< policy flags */
	enum cdt_states		 cdt_state;	      /**< state */
	spinlock_t		 cdt_state_lock;      /**< cdt_state lock */
	atomic_t		 cdt_compound_id;     /**< compound id
						       * counter */
	__u64			 cdt_last_cookie;     /**< last cookie
						       * allocated */
	struct rw_semaphore	 cdt_llog_lock;       /**< protect llog
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
	/* started requests (struct cdt_agent_req:car_cookie_hash)
	 * indexed by cookie */
	struct cfs_hash		*cdt_request_cookie_hash;
	/* started requests (struct cdt_agent_req:car_request_list) */
	struct list_head	 cdt_request_list;
	struct list_head	 cdt_agents;	      /**< list of register
						       * agents */
	struct list_head	 cdt_restore_hdl;     /**< list of restore lock
						       * handles */

	/* Hash of cookies to locations of record locations in agent
	 * request log. */
	struct cfs_hash		*cdt_agent_record_hash;

	/* Bitmasks indexed by the HSMA_XXX constants. */
	__u64			 cdt_user_request_mask;
	__u64			 cdt_group_request_mask;
	__u64			 cdt_other_request_mask;

	/* Remove archive on last unlink policy */
	bool			 cdt_remove_archive_on_last_unlink;

	bool			 cdt_wakeup_coordinator;
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
				   mo_cos:1,
				   mo_evict_tgt_nids:1;
	} mdt_opts;
        /* mdt state flags */
        unsigned long              mdt_state;

        /* transaction callbacks */
        struct dt_txn_callback     mdt_txn_cb;

        /* these values should be updated from lov if necessary.
         * or should be placed somewhere else. */
        int                        mdt_max_mdsize;

	int			   mdt_max_ea_size;

        struct upcall_cache        *mdt_identity_cache;

	unsigned int               mdt_capa_conf:1,
				   /* Enable remote dir on non-MDT0 */
				   mdt_enable_remote_dir:1,
				   mdt_skip_lfsck:1;

	gid_t			   mdt_enable_remote_dir_gid;

	/* lock for osfs and md_root */
	spinlock_t		   mdt_lock;

	/* statfs optimization: we cache a bit  */
	struct obd_statfs	   mdt_osfs;
	__u64			   mdt_osfs_age;

        /* root squash */
	struct root_squash_info    mdt_squash;

        struct rename_stats        mdt_rename_stats;
	struct lu_fid		   mdt_md_root_fid;

	/* connection to quota master */
	struct obd_export	  *mdt_qmt_exp;
	/* quota master device associated with this MDT */
	struct lu_device	  *mdt_qmt_dev;

	struct coordinator	   mdt_coordinator;

	/* inter-MDT connection count */
	atomic_t		   mdt_mds_mds_conns;

	/* MDT device async commit count, used for debug and sanity test */
	atomic_t		   mdt_async_commit_count;

	struct mdt_object	  *mdt_md_root;
};

#define MDT_SERVICE_WATCHDOG_FACTOR	(2)
#define MDT_COS_DEFAULT         (0)

struct mdt_object {
	struct lu_object_header	mot_header;
	struct lu_object	mot_obj;
	unsigned int		mot_lov_created:1,  /* lov object created */
				mot_cache_attr:1;   /* enable remote object
						     * attribute cache */
	int			mot_write_count;
	spinlock_t		mot_write_lock;
        /* Lock to protect create_data */
	struct mutex		mot_lov_mutex;
	/* Lock to protect lease open.
	 * Lease open acquires write lock; normal open acquires read lock */
	struct rw_semaphore	mot_open_sem;
	atomic_t		mot_lease_count;
	atomic_t		mot_open_count;
};

struct mdt_lock_handle {
	/* Lock type, reg for cross-ref use or pdo lock. */
	mdl_type_t		mlh_type;

	/* Regular lock */
	struct lustre_handle	mlh_reg_lh;
	enum ldlm_mode		mlh_reg_mode;

	/* Pdirops lock */
	struct lustre_handle	mlh_pdo_lh;
	enum ldlm_mode		mlh_pdo_mode;
	unsigned int		mlh_pdo_hash;

	/* Remote regular lock */
	struct lustre_handle	mlh_rreg_lh;
	enum ldlm_mode		mlh_rreg_mode;
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

/* Special magical errno for communicaiton between mdt_reint_open()
 * and mdt_intent_reint() which means return the lock to the client
 * for subsequent cross ref open. Previously we used plain -EREMOTE
 * but other functions called in that path might return it too and
 * confuse us. This is not returned to the client. See LU-5370. */
#define MDT_EREMOTE_OPEN (EREMOTE + 1024)

struct mdt_reint_record {
	mdt_reint_t			 rr_opcode;
	const struct lustre_handle	*rr_handle;
	const struct lu_fid		*rr_fid1;
	const struct lu_fid		*rr_fid2;
	struct lu_name			 rr_name;
	struct lu_name			 rr_tgt_name;
	void				*rr_eadata;
	int				 rr_eadatalen;
	__u32				 rr_flags;
};

enum mdt_reint_flag {
        MRF_OPEN_TRUNC = 1 << 0,
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
				   mti_cross_ref:1,
	/* big_lmm buffer was used and must be used in reply */
				   mti_big_lmm_used:1,
				   mti_big_acl_used:1;

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
	struct lu_fid			mti_tmp_fid1;
	struct lu_fid			mti_tmp_fid2;
	union ldlm_policy_data		mti_policy; /* for mdt_object_lock() */
	struct ldlm_res_id		mti_res_id; /* and mdt_rename_lock() */
	union {
		struct obd_uuid		uuid[2];    /* for mdt_seq_init_cli() */
		char			ns_name[48];/* for mdt_init0()        */
		struct lustre_cfg_bufs	bufs;       /* for mdt_stack_fini()   */
		struct obd_statfs	osfs;       /* for mdt_statfs()       */
                struct {
                        /* for mdt_readpage()      */
                        struct lu_rdpg     mti_rdpg;
                        /* for mdt_sendpage()      */
                        struct l_wait_info mti_wait_info;
                } rdpg;
		struct {
			struct md_attr attr;
		} hsm;
        } mti_u;

	struct lustre_handle	   mti_close_handle;
	loff_t                     mti_off;
	struct lu_buf              mti_buf;
	struct lu_buf              mti_big_buf;

        /* Ops object filename */
        struct lu_name             mti_name;
	/* per-thread values, can be re-used, may be vmalloc'd */
	void			  *mti_big_lmm;
	void			  *mti_big_acl;
	int			   mti_big_lmmsize;
	int			   mti_big_aclsize;
	/* should be enough to fit lustre_mdt_attrs */
	char			   mti_xattr_buf[128];
	struct ldlm_enqueue_info   mti_einfo;
	struct tg_reply_data	  *mti_reply_data;
};

extern struct lu_context_key mdt_thread_key;

static inline struct mdt_thread_info *mdt_th_info(const struct lu_env *env)
{
	struct mdt_thread_info *mti;

	lu_env_refill((void *)env);
	mti = lu_context_key_get(&env->le_ctx, &mdt_thread_key);
	LASSERT(mti);
	return mti;
}

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
	struct hlist_node	 car_cookie_hash;  /**< find req by cookie */
	struct list_head	 car_request_list; /**< to chain all the req. */
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
	struct list_head ha_list;		/**< to chain the agents */
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
	struct list_head	crh_list;	/**< to chain the handle */
	struct lu_fid		crh_fid;	/**< fid of the object */
	struct ldlm_extent	crh_extent;	/**< extent of the restore */
	struct mdt_lock_handle	crh_lh;		/**< lock handle */
};
extern struct kmem_cache *mdt_hsm_cdt_kmem;	/** restore handle slab cache */

struct hsm_record_update {
	__u64 cookie;
	enum agent_req_status status;
};

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
}

/* Here we use LVB_TYPE to check dne client, because it is
 * also landed on 2.4. */
static inline bool mdt_is_dne_client(struct obd_export *exp)
{
	return !!(exp_connect_flags(exp) & OBD_CONNECT_LVB_TYPE);
}

static inline bool mdt_is_striped_client(struct obd_export *exp)
{
	return exp_connect_flags(exp) & OBD_CONNECT_DIR_STRIPE;
}

__u64 mdt_get_disposition(struct ldlm_reply *rep, __u64 op_flag);
void mdt_set_disposition(struct mdt_thread_info *info,
			 struct ldlm_reply *rep, __u64 op_flag);
void mdt_clear_disposition(struct mdt_thread_info *info,
			   struct ldlm_reply *rep, __u64 op_flag);

void mdt_lock_pdo_init(struct mdt_lock_handle *lh, enum ldlm_mode lock_mode,
		       const struct lu_name *lname);

void mdt_lock_reg_init(struct mdt_lock_handle *lh, enum ldlm_mode lm);

int mdt_lock_setup(struct mdt_thread_info *info, struct mdt_object *mo,
		   struct mdt_lock_handle *lh);

int mdt_check_resent_lock(struct mdt_thread_info *info, struct mdt_object *mo,
			  struct mdt_lock_handle *lhc);

int mdt_object_lock(struct mdt_thread_info *info, struct mdt_object *mo,
		    struct mdt_lock_handle *lh, __u64 ibits);

int mdt_reint_object_lock(struct mdt_thread_info *info, struct mdt_object *o,
			  struct mdt_lock_handle *lh, __u64 ibits,
			  bool cos_incompat);

int mdt_object_lock_try(struct mdt_thread_info *info, struct mdt_object *mo,
			struct mdt_lock_handle *lh, __u64 ibits);

int mdt_reint_object_lock_try(struct mdt_thread_info *info,
			      struct mdt_object *o, struct mdt_lock_handle *lh,
			      __u64 ibits, bool cos_incompat);

void mdt_object_unlock(struct mdt_thread_info *info, struct mdt_object *mo,
		       struct mdt_lock_handle *lh, int decref);

struct mdt_object *mdt_object_new(const struct lu_env *env,
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
			   struct mdt_object *o, const struct lu_fid *fid,
			   struct lustre_handle *lh,
			   enum ldlm_mode mode, __u64 ibits, bool nonblock,
			   bool cache);

enum mdt_name_flags {
	MNF_FIX_ANON = 1,
};

int mdt_name_unpack(struct req_capsule *pill,
		    const struct req_msg_field *field,
		    struct lu_name *ln,
		    enum mdt_name_flags flags);
int mdt_close_unpack(struct mdt_thread_info *info);
int mdt_reint_unpack(struct mdt_thread_info *info, __u32 op);
void mdt_fix_lov_magic(struct mdt_thread_info *info, void *eadata);
int mdt_reint_rec(struct mdt_thread_info *, struct mdt_lock_handle *);
#ifdef CONFIG_FS_POSIX_ACL
int mdt_pack_acl2body(struct mdt_thread_info *info, struct mdt_body *repbody,
		      struct mdt_object *o, struct lu_nodemap *nodemap);
#endif
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

int mdt_get_info(struct tgt_session_info *tsi);
int mdt_attr_get_complex(struct mdt_thread_info *info,
			 struct mdt_object *o, struct md_attr *ma);
int mdt_big_xattr_get(struct mdt_thread_info *info, struct mdt_object *o,
		      const char *name);
int mdt_stripe_get(struct mdt_thread_info *info, struct mdt_object *o,
		   struct md_attr *ma, const char *name);
int mdt_write_get(struct mdt_object *o);
void mdt_write_put(struct mdt_object *o);
int mdt_write_read(struct mdt_object *o);
struct mdt_file_data *mdt_mfd_new(const struct mdt_export_data *med);
int mdt_mfd_close(struct mdt_thread_info *info, struct mdt_file_data *mfd);
void mdt_mfd_free(struct mdt_file_data *mfd);
int mdt_close(struct tgt_session_info *tsi);
int mdt_add_dirty_flag(struct mdt_thread_info *info, struct mdt_object *mo,
			struct md_attr *ma);
int mdt_fix_reply(struct mdt_thread_info *info);
int mdt_handle_last_unlink(struct mdt_thread_info *, struct mdt_object *,
			   struct md_attr *);
void mdt_reconstruct_open(struct mdt_thread_info *, struct mdt_lock_handle *);

struct lu_buf *mdt_buf(const struct lu_env *env, void *area, ssize_t len);
const struct lu_buf *mdt_buf_const(const struct lu_env *env,
                                   const void *area, ssize_t len);

void mdt_dump_lmm(int level, const struct lov_mds_md *lmm, __u64 valid);
void mdt_dump_lmv(unsigned int level, const union lmv_mds_md *lmv);

bool allow_client_chgrp(struct mdt_thread_info *info, struct lu_ucred *uc);
int mdt_check_ucred(struct mdt_thread_info *);
int mdt_init_ucred(struct mdt_thread_info *, struct mdt_body *);
int mdt_init_ucred_intent_getattr(struct mdt_thread_info *, struct mdt_body *);
int mdt_init_ucred_reint(struct mdt_thread_info *);
void mdt_exit_ucred(struct mdt_thread_info *);
int mdt_version_get_check(struct mdt_thread_info *, struct mdt_object *, int);
void mdt_version_get_save(struct mdt_thread_info *, struct mdt_object *, int);
int mdt_version_get_check_save(struct mdt_thread_info *, struct mdt_object *,
                               int);
void mdt_thread_info_init(struct ptlrpc_request *req,
			  struct mdt_thread_info *mti);
void mdt_thread_info_fini(struct mdt_thread_info *mti);
struct mdt_thread_info *tsi2mdt_info(struct tgt_session_info *tsi);

int mdt_hsm_attr_set(struct mdt_thread_info *info, struct mdt_object *obj,
		     const struct md_hsm *mh);

int mdt_remote_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
			    void *data, int flag);
int mdt_links_read(struct mdt_thread_info *info,
		   struct mdt_object *mdt_obj,
		   struct linkea_data *ldata);
int mdt_close_internal(struct mdt_thread_info *info, struct ptlrpc_request *req,
		       struct mdt_body *repbody);

static inline struct mdt_device *mdt_dev(struct lu_device *d)
{
	return container_of0(d, struct mdt_device, mdt_lu_dev);
}

static inline struct mdt_object *mdt_obj(struct lu_object *o)
{
	return container_of0(o, struct mdt_object, mot_obj);
}

static inline struct dt_object *mdt_obj2dt(struct mdt_object *mo)
{
	struct lu_object	*lo;
	struct mdt_device	*mdt = mdt_dev(mo->mot_obj.lo_dev);

	lo = lu_object_locate(mo->mot_obj.lo_header,
			      mdt->mdt_bottom->dd_lu_dev.ld_type);

	return lu2dt(lo);
}

static inline bool agent_req_in_final_state(enum agent_req_status ars)
{
	return ((ars == ARS_SUCCEED) || (ars == ARS_FAILED) ||
		(ars == ARS_CANCELED));
}

/* mdt/mdt_identity.c */
#define MDT_IDENTITY_UPCALL_PATH        "/usr/sbin/l_getidentity"

extern struct upcall_cache_ops mdt_identity_upcall_cache_ops;

struct md_identity *mdt_identity_get(struct upcall_cache *, __u32);

void mdt_identity_put(struct upcall_cache *, struct md_identity *);

void mdt_flush_identity(struct upcall_cache *, int);

__u32 mdt_identity_get_perm(struct md_identity *, lnet_nid_t);

/* mdt/mdt_recovery.c */
__u64 mdt_req_from_lrd(struct ptlrpc_request *req, struct tg_reply_data *trd);

/* mdt/mdt_hsm.c */
int mdt_hsm_state_get(struct tgt_session_info *tsi);
int mdt_hsm_state_set(struct tgt_session_info *tsi);
int mdt_hsm_action(struct tgt_session_info *tsi);
int mdt_hsm_progress(struct tgt_session_info *tsi);
int mdt_hsm_ct_register(struct tgt_session_info *tsi);
int mdt_hsm_ct_unregister(struct tgt_session_info *tsi);
int mdt_hsm_request(struct tgt_session_info *tsi);

/* mdt/mdt_hsm_cdt_actions.c */
extern const struct file_operations mdt_hsm_actions_fops;
void dump_llog_agent_req_rec(const char *prefix,
			     const struct llog_agent_req_rec *larr);
int cdt_llog_process(const struct lu_env *env, struct mdt_device *mdt,
		     llog_cb_t cb, void *data, u32 start_cat_idx,
		     u32 start_rec_idx, int rw);
int mdt_agent_record_add(const struct lu_env *env, struct mdt_device *mdt,
			 __u64 compound_id, __u32 archive_id,
			 __u64 flags, struct hsm_action_item *hai);
int mdt_agent_record_update(const struct lu_env *env, struct mdt_device *mdt,
			    struct hsm_record_update *updates,
			    unsigned int updates_count);
void cdt_agent_record_hash_add(struct coordinator *cdt, u64 cookie, u32 cat_idt,
			       u32 rec_idx);
void cdt_agent_record_hash_lookup(struct coordinator *cdt, u64 cookie,
				  u32 *cat_idt, u32 *rec_idx);
void cdt_agent_record_hash_del(struct coordinator *cdt, u64 cookie);

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
			struct hsm_action_list *hal);
int mdt_hsm_get_actions(struct mdt_thread_info *mti,
			struct hsm_action_list *hal);
bool mdt_hsm_restore_is_running(struct mdt_thread_info *mti,
				const struct lu_fid *fid);
/* mdt/mdt_hsm_cdt_requests.c */
extern struct cfs_hash_ops cdt_request_cookie_hash_ops;
extern struct cfs_hash_ops cdt_agent_record_hash_ops;
extern const struct file_operations mdt_hsm_active_requests_fops;
void dump_requests(char *prefix, struct coordinator *cdt);
struct cdt_agent_req *mdt_cdt_alloc_request(__u64 compound_id, __u32 archive_id,
					    __u64 flags, struct obd_uuid *uuid,
					    struct hsm_action_item *hai);
void mdt_cdt_free_request(struct cdt_agent_req *car);
int mdt_cdt_add_request(struct coordinator *cdt, struct cdt_agent_req *new_car);
struct cdt_agent_req *mdt_cdt_find_request(struct coordinator *cdt, u64 cookie);
void mdt_cdt_get_work_done(struct cdt_agent_req *car, __u64 *done_sz);
void mdt_cdt_get_request(struct cdt_agent_req *car);
void mdt_cdt_put_request(struct cdt_agent_req *car);
struct cdt_agent_req *mdt_cdt_update_request(struct coordinator *cdt,
					 const struct hsm_progress_kernel *pgs);
int mdt_cdt_remove_request(struct coordinator *cdt, __u64 cookie);
/* mdt/mdt_coordinator.c */
void mdt_hsm_dump_hal(int level, const char *prefix,
		      struct hsm_action_list *hal);
struct cdt_restore_handle *mdt_hsm_restore_hdl_find(struct coordinator *cdt,
						const struct lu_fid *fid);
/* coordinator management */
int mdt_hsm_cdt_init(struct mdt_device *mdt);
int mdt_hsm_cdt_stop(struct mdt_device *mdt);
int mdt_hsm_cdt_fini(struct mdt_device *mdt);

/*
 * Signal the coordinator has work to do
 * \param cdt [IN] coordinator
 */
static inline void mdt_hsm_cdt_event(struct coordinator *cdt)
{
	cdt->cdt_event = true;
}

/* coordinator control /proc interface */
ssize_t mdt_hsm_cdt_control_seq_write(struct file *file,
				      const char __user *buffer,
				      size_t count, loff_t *off);
int mdt_hsm_cdt_control_seq_show(struct seq_file *m, void *data);
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
			      u32 archive_id, u64 rq_flags,
			      const struct md_hsm *hsm);
int mdt_hsm_update_request_state(struct mdt_thread_info *mti,
				 struct hsm_progress_kernel *pgs,
				 const int update_record);

int mdt_close_swap_layouts(struct mdt_thread_info *info,
			   struct mdt_object *o, struct md_attr *ma);

extern struct lu_context_key       mdt_thread_key;

/* debug issues helper starts here*/
static inline int mdt_fail_write(const struct lu_env *env,
                                 struct dt_device *dd, int id)
{
	if (OBD_FAIL_CHECK_ORSET(id, OBD_FAIL_ONCE)) {
		CERROR(LUSTRE_MDT_NAME": cfs_fail_loc=%x, fail write ops\n",
		       id);
		return dt_ro(env, dd);
		/* We set FAIL_ONCE because we never "un-fail" a device */
	}

	return 0;
}

static inline struct mdt_export_data *mdt_req2med(struct ptlrpc_request *req)
{
	return &req->rq_export->exp_mdt_data;
}

static inline struct mdt_device *mdt_exp2dev(struct obd_export *exp)
{
	return mdt_dev(exp->exp_obd->obd_lu_dev);
}

static inline bool mdt_rdonly(struct obd_export *exp)
{
	if (exp_connect_flags(exp) & OBD_CONNECT_RDONLY ||
	    mdt_exp2dev(exp)->mdt_bottom->dd_rdonly)
		return true;
	return false;
}

typedef void (*mdt_reconstruct_t)(struct mdt_thread_info *mti,
                                  struct mdt_lock_handle *lhc);
static inline int mdt_check_resent(struct mdt_thread_info *info,
                                   mdt_reconstruct_t reconstruct,
                                   struct mdt_lock_handle *lhc)
{
	struct ptlrpc_request *req = mdt_info_req(info);
	int rc = 0;
	ENTRY;

	if (lustre_msg_get_flags(req->rq_reqmsg) & MSG_RESENT) {
		OBD_ALLOC_PTR(info->mti_reply_data);
		if (info->mti_reply_data == NULL)
			RETURN(-ENOMEM);

		if (req_can_reconstruct(req, info->mti_reply_data)) {
			reconstruct(info, lhc);
			rc = 1;
		} else {
			DEBUG_REQ(D_HA, req,
				  "no reply data found for RESENT req");
			rc = 0;
		}
		OBD_FREE_PTR(info->mti_reply_data);
		info->mti_reply_data = NULL;
	}
	RETURN(rc);
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
			       struct lustre_handle *lh, enum ldlm_mode mode,
			       union ldlm_policy_data *policy,
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

static inline void mdt_fid_unlock(struct lustre_handle *lh, enum ldlm_mode mode)
{
	ldlm_lock_decref(lh, mode);
}

static inline bool mdt_slc_is_enabled(struct mdt_device *mdt)
{
	return mdt->mdt_lut.lut_sync_lock_cancel == BLOCKING_SYNC_ON_CANCEL;
}

extern mdl_mode_t mdt_mdl_lock_modes[];
extern enum ldlm_mode mdt_dlm_lock_modes[];

/* LCK_MINMODE which is zero returns false for is_power_of_2 */

static inline mdl_mode_t mdt_dlm_mode2mdl_mode(enum ldlm_mode mode)
{
	LASSERT(mode == LCK_MINMODE || is_power_of_2(mode));
	return mdt_mdl_lock_modes[mode];
}

static inline enum ldlm_mode mdt_mdl_mode2dlm_mode(mdl_mode_t mode)
{
	LASSERT(mode == MDL_MINMODE || is_power_of_2(mode));
	return mdt_dlm_lock_modes[mode];
}

/* mdt_lvb.c */
extern struct ldlm_valblock_ops mdt_lvbo;

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
int mdt_procfs_init(struct mdt_device *mdt, const char *name);
void mdt_procfs_fini(struct mdt_device *mdt);

/* lustre/mdt_mdt_lproc.c */
int lprocfs_mdt_open_files_seq_open(struct inode *inode,
				    struct file *file);
void mdt_rename_counter_tally(struct mdt_thread_info *info,
			      struct mdt_device *mdt,
			      struct ptlrpc_request *req,
			      struct mdt_object *src, struct mdt_object *tgt);

static inline struct obd_device *mdt2obd_dev(const struct mdt_device *mdt)
{
	return mdt->mdt_lu_dev.ld_obd;
}

extern const struct lu_device_operations mdt_lu_ops;

static inline char *mdt_obd_name(struct mdt_device *mdt)
{
	return mdt->mdt_lu_dev.ld_obd->obd_name;
}

int mds_mod_init(void);
void mds_mod_exit(void);

static inline char *mdt_req_get_jobid(struct ptlrpc_request *req)
{
	struct obd_export	*exp = req->rq_export;
	char			*jobid = NULL;

	if (exp_connect_flags(exp) & OBD_CONNECT_JOBSTATS)
		jobid = lustre_msg_get_jobid(req->rq_reqmsg);

	return jobid;
}

#endif /* _MDT_INTERNAL_H */
