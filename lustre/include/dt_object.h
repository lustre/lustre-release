/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef __LUSTRE_DT_OBJECT_H
#define __LUSTRE_DT_OBJECT_H

/*
 * Sub-class of lu_object with methods common for "data" objects in OST stack.
 *
 * Data objects behave like regular files: you can read/write them, get and
 * set their attributes. Implementation of dt interface is supposed to
 * implement some form of garbage collection, normally reference counting
 * (nlink) based one.
 *
 * Examples: osd (lustre/osd) is an implementation of dt interface.
 */

#include <obd_support.h>
#include <lu_object.h>
#include <lustre_quota.h>
#include <libcfs/libcfs.h>

struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;

struct thandle;
struct dt_device;
struct dt_object;
struct dt_index_features;
struct niobuf_local;
struct niobuf_remote;
struct ldlm_enqueue_info;

typedef enum {
	MNTOPT_USERXATTR        = 0x00000001,
	MNTOPT_ACL              = 0x00000002,
} mntopt_t;

struct dt_device_param {
	unsigned int	 ddp_max_name_len;
	unsigned int	 ddp_max_nlink;
	unsigned int	 ddp_symlink_max;
	mntopt_t	 ddp_mntopts;
	unsigned int	 ddp_max_ea_size;
	unsigned int	 ddp_mount_type;
	unsigned long long ddp_maxbytes;
	/* per-inode space consumption */
	short		 ddp_inodespace;
	/* maximum number of blocks in an extent */
	unsigned int	 ddp_max_extent_blks;
	/* per-extent insertion overhead used by client for grant calculation */
	unsigned int	 ddp_extent_tax;
	unsigned int	 ddp_brw_size; /* optimal RPC size */
	/* T10PI checksum type, zero if not supported */
	enum cksum_types ddp_t10_cksum_type;
	bool		 ddp_has_lseek_data_hole;
};

/*
 * Per-transaction commit callback function
 */
struct dt_txn_commit_cb;
typedef void (*dt_cb_t)(struct lu_env *env, struct thandle *th,
			struct dt_txn_commit_cb *cb, int err);

/*
 * Special per-transaction callback for cases when just commit callback
 * is needed and per-device callback are not convenient to use
 */
#define TRANS_COMMIT_CB_MAGIC	0xa0a00a0a
#define MAX_COMMIT_CB_STR_LEN	32

#define DCB_TRANS_STOP		0x1
struct dt_txn_commit_cb {
	struct list_head	dcb_linkage;
	dt_cb_t			dcb_func;
	void			*dcb_data;
	__u32			dcb_magic;
	__u32			dcb_flags;
	char			dcb_name[MAX_COMMIT_CB_STR_LEN];
};

/*
 * Operations on dt device.
 */
struct dt_device_operations {
	/**
	 * dt_statfs() - Return device-wide statistics.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 * @osfs: stats information
	 * @info: stats information
	 *
	 * Return device-wide stats including block size, total and
	 * free blocks, total and free objects, etc. See struct obd_statfs
	 * for the details.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_statfs)(const struct lu_env *env,
			   struct dt_device *dev,
			   struct obd_statfs *osfs,
			   struct obd_statfs_info *info);

	/**
	 * dt_trans_create() - Create transaction.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 *
	 * Create in-memory structure representing the transaction for the
	 * caller. The structure returned will be used by the calling thread
	 * to specify the transaction the updates belong to. Once created
	 * successfully ->dt_trans_stop() must be called in any case (with
	 * ->dt_trans_start() and updates or not) so that the transaction
	 * handle and other resources can be released by the layers below.
	 *
	 * Return: pointer to handle or ERR_PTR()
	 */
	struct thandle *(*dt_trans_create)(const struct lu_env *env,
					   struct dt_device *dev);

	/**
	 * dt_trans_start() - Start transaction.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 * @th:	transaction handle
	 *
	 * Start the transaction. The transaction described by \a th can be
	 * started only once. Another start is considered as an error.
	 * A thread is not supposed to start a transaction while another
	 * transaction isn't closed by the thread (though multiple handles
	 * can be created). The caller should start the transaction once
	 * all possible updates are declared (see the ->do_declare_* methods
	 * below) and all the needed resources are reserved.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_trans_start)(const struct lu_env *env,
				struct dt_device *dev,
				struct thandle *th);

	/**
	 * dt_trans_stop() - Stop transaction.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 * @th:	transaction handle
	 *
	 * Once stopped the transaction described by \a th is complete (all
	 * the needed updates are applied) and further processing such as
	 * flushing to disk, sending to another target, etc, is handled by
	 * lower layers. The caller can't access this transaction by the
	 * handle anymore (except from the commit callbacks, see below).
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_trans_stop)(const struct lu_env *env,
			       struct dt_device *dev,
			       struct thandle *th);

	/**
	 * dt_trans_cb_add() - Add commit callback to the transaction.
	 *
	 * @th:	transaction handle
	 * @dcb: commit callback description
	 *
	 * Add a commit callback to the given transaction handle. The callback
	 * will be called when the associated transaction is stored. I.e. the
	 * transaction will survive an event like power off if the callback did
	 * run. The number of callbacks isn't limited, but you should note that
	 * some disk filesystems do handle the commit callbacks in the thread
	 * handling commit/flush of all the transactions, meaning that new
	 * transactions are blocked from commit and flush until all the
	 * callbacks are done. Also, note multiple callbacks can be running
	 * concurrently using multiple CPU cores. The callbacks will be running
	 * in a special environment which can not be used to pass data around.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_trans_cb_add)(struct thandle *th,
				 struct dt_txn_commit_cb *dcb);

	/**
	 * dt_root_get() - Return FID of root index object.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 * @fid: FID of the root object
	 *
	 * Return the FID of the root object in the filesystem. This object
	 * is usually provided as a bootstrap point by a disk filesystem.
	 * This is up to the implementation which FID to use, though
	 * [FID_SEQ_ROOT:1:0] is reserved for this purpose.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_root_get)(const struct lu_env *env,
			     struct dt_device *dev,
			     struct lu_fid *f);

	/**
	 * dt_conf_get() - Return device configuration data.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 * @param: configuration parameters
	 *
	 * Return device (disk fs, actually) specific configuration.
	 * The configuration isn't subject to change at runtime.
	 * See struct dt_device_param for the details.
	 */
	void  (*dt_conf_get)(const struct lu_env *env,
			     const struct dt_device *dev,
			     struct dt_device_param *param);

	/**
	 * dt_mnt_get() - Return device's vfsmount.
	 *
	 * @dev: dt device
	 *
	 * Return: a pointer to the device's vfsmount
	 */
	struct vfsmount *(*dt_mnt_get)(const struct dt_device *dev);

	/**
	 * dt_sync() - Sync the device.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 *
	 * Sync all the cached state (dirty buffers, pages, etc) to the
	 * persistent storage. The method returns control once the sync is
	 * complete. This operation may incur significant I/O to disk and
	 * should be reserved for cases where a global sync is strictly
	 * necessary.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_sync)(const struct lu_env *env,
			 struct dt_device *dev);

	/**
	 * dt_ro() - Make device read-only.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 *
	 * Prevent new modifications to the device. This is a very specific
	 * state where all the changes are accepted successfully and the
	 * commit callbacks are called, but persistent state never changes.
	 * Used only in the tests to simulate power-off scenario.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_ro)(const struct lu_env *env,
		       struct dt_device *dev);

	/**
	 * Start transaction commit asynchronously.
	 *
	 * @env: execution environment for this thread
	 * @dev: dt device
	 *
	 * Provide a hint to the underlying filesystem that it should start
	 * committing soon. The control returns immediately. It's up to the
	 * layer implementing the method how soon to start committing. Usually
	 * this should be throttled to some extent, otherwise the number of
	 * aggregated transaction goes too high causing performance drop.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_commit_async)(const struct lu_env *env,
				 struct dt_device *dev);

	/**
	 * dt_reserve_or_free_quota() - Manage quota reservations
	 *
	 * @env: execution environment for this thread
	 * @dev: the bottom OSD device to reserve quota
	 * @qi: quota id & space required to reserve
	 *
	 * If qi->lqi_space > 0, reserve quota in advance of an operation
	 * that changes the quota assignment, such as chgrp() or rename() into
	 * a directory with a different group ID.
	 *
	 * If qi->lqi_space < 0, free the reserved quota previously.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dt_reserve_or_free_quota)(const struct lu_env *env,
					  struct dt_device *dev,
					  struct lquota_id_info *qi);
};

struct dt_index_features {
	/* required feature flags from enum dt_index_flags */
	__u32 dif_flags;
	/* minimal required key size */
	size_t dif_keysize_min;
	/* maximal required key size, 0 if no limit */
	size_t dif_keysize_max;
	/* minimal required record size */
	size_t dif_recsize_min;
	/* maximal required record size, 0 if no limit */
	size_t dif_recsize_max;
	/* pointer size for record */
	size_t dif_ptrsize;
};

enum dt_index_flags {
	/* index supports variable sized keys */
	DT_IND_VARKEY = BIT(0),
	/* index supports variable sized records */
	DT_IND_VARREC = BIT(1),
	/* index can be modified */
	DT_IND_UPDATE = BIT(2),
	/* index supports records with non-unique (duplicate) keys */
	DT_IND_NONUNQ = BIT(3),
	/*
	 * index support fixed-size keys sorted with natural numerical way
	 * and is able to return left-side value if no exact value found
	 */
	DT_IND_RANGE = BIT(4),
};

/* for dt_read_lock() and dt_write_lock() object lock rule */
enum dt_object_role {
	DT_SRC_PARENT,
	DT_SRC_CHILD,
	DT_TGT_PARENT,
	DT_TGT_CHILD,
	DT_TGT_ORPHAN,
	DT_LASTID,
};

/*
 * Features, required from index to support file system directories (mapping
 * names to fids).
 */
extern const struct dt_index_features dt_directory_features;
extern const struct dt_index_features dt_otable_features;
extern const struct dt_index_features dt_lfsck_layout_orphan_features;
extern const struct dt_index_features dt_lfsck_layout_dangling_features;
extern const struct dt_index_features dt_lfsck_namespace_features;

/* index features supported by the accounting objects */
extern const struct dt_index_features dt_acct_features;

/* index features supported by the quota global indexes */
extern const struct dt_index_features dt_quota_glb_features;

/* index features supported by the quota slave indexes */
extern const struct dt_index_features dt_quota_slv_features;

/* index features supported by the nodemap index */
extern const struct dt_index_features dt_nodemap_features;

/*
 * This is a general purpose dt allocation hint.
 * It now contains the parent object.
 * It can contain any allocation hint in the future.
 */
struct dt_allocation_hint {
	struct dt_object	*dah_parent;
	const void		*dah_eadata;
	const char		*dah_append_pool;
	int			dah_eadata_len;
	int			dah_append_stripe_count;
	int			dah_acl_len;
	unsigned int		dah_can_block:1,
				/* implicit default LMV inherit is enabled? */
				dah_dmv_imp_inherit:1,
				/* eadata is default LMV sent from client  */
				dah_eadata_is_dmv:1;
};

/*
 * object type specifier.
 */
enum dt_format_type {
	DFT_REGULAR,
	DFT_DIR,
	/** for mknod */
	DFT_NODE,
	/** for special index */
	DFT_INDEX,
	/** for symbolic link */
	DFT_SYM,
};

/*
 * object format specifier.
 */
struct dt_object_format {
	/* type for dt object */
	enum dt_format_type dof_type;
	union {
		struct dof_regular {
			int striped;
		} dof_reg;
		struct dof_dir {
		} dof_dir;
		struct dof_node {
		} dof_node;
		/*
		 * special index need feature as parameter to create
		 * special idx
		 */
		struct dof_index {
			const struct dt_index_features *di_feat;
		} dof_idx;
	} u;
};

enum dt_format_type dt_mode_to_dft(__u32 mode);

typedef __u64 dt_obj_version_t;

union ldlm_policy_data;

struct md_layout_change;

/*
 * A dt_object provides common operations to create and destroy
 * objects and to manage regular and extended attributes.
 */
struct dt_object_operations {
	/**
	 * do_read_lock() - Get read lock on object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @role: a hint to debug locks (see kernel's mutexes)
	 *
	 * Read lock is compatible with other read locks, so it's shared.
	 * Read lock is not compatible with write lock which is exclusive.
	 * The lock is blocking and can't be used from an interrupt context.
	 */
	void  (*do_read_lock)(const struct lu_env *env,
			      struct dt_object *dt,
			      unsigned int role);

	/**
	 * do_write_lock() - Get write lock on object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @role: a hint to debug locks (see kernel's mutexes)
	 *
	 * Write lock is exclusive and cannot be shared. The lock is blocking
	 * and can't be used from an interrupt context.
	 */
	void  (*do_write_lock)(const struct lu_env *env,
			       struct dt_object *dt,
			       unsigned int role);

	/**
	 * do_read_unlock() - Release read lock.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 */
	void  (*do_read_unlock)(const struct lu_env *env,
				struct dt_object *dt);

	/**
	 * do_write_unlock() - Release write lock.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 */
	void  (*do_write_unlock)(const struct lu_env *env,
				 struct dt_object *dt);

	/**
	 * do_write_locked() - Check whether write lock is held.
	 *
	 * The caller can learn whether write lock is held on the object
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 *
	 * Return: 0 no write lock, 1 write lock is held
	 */
	int  (*do_write_locked)(const struct lu_env *env,
				struct dt_object *dt);

	/**
	 * do_declare_attr_get() - Declare request for regular attributes.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 *
	 * Notity the underlying filesystem that the caller may request regular
	 * attributes with ->do_attr_get() soon. This allows OSD to implement
	 * prefetching logic in an object-oriented manner. The implementation
	 * can be noop. This method should avoid expensive delays such as
	 * waiting on disk I/O, otherwise the goal of enabling a performance
	 * optimization would be defeated.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_attr_get)(const struct lu_env *env,
				     struct dt_object *dt);

	/**
	 * do_attr_get() - Return regular attributes.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @attr: attributes to fill
	 *
	 * The object must exist. Currently all the attributes should be
	 * returned, but in the future this can be improved so that only
	 * a selected set is returned. This can improve performance as in
	 * some cases attributes are stored in different places and
	 * getting them all can be an iterative and expensive process.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_attr_get)(const struct lu_env *env,
			     struct dt_object *dt,
			     struct lu_attr *attr);

	/**
	 * do_declare_attr_set() - Declare intent to change regular
	 *                         object's attributes.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @attr: attributes to fill
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the regular attributes may
	 * change in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it. Note that
	 * the la_valid field of \a attr specifies which attributes will change.
	 * The object need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_attr_set)(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct lu_attr *attr,
				     struct thandle *th);

	/**
	 * do_attr_set() - Change regular attributes.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @attr: attributes to fill
	 * @th: transaction handle
	 *
	 * Change regular attributes in the given transaction. Note only
	 * attributes flagged by attr.la_valid change. The object must
	 * exist. If the layer implementing this method is responsible for
	 * quota, then the method should maintain object accounting for the
	 * given credentials when la_uid/la_gid changes.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_attr_set)(const struct lu_env *env,
			     struct dt_object *dt,
			     const struct lu_attr *attr,
			     struct thandle *th);

	/**
	 * do_declare_xattr_get() - Declare intention to request
	 *                          extented attribute.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @buf: unused, may be removed in the future
	 * @name: name of the extended attribute
	 *
	 * Notify the underlying filesystem that the caller may request extended
	 * attribute with ->do_xattr_get() soon. This allows OSD to implement
	 * prefetching logic in an object-oriented manner. The implementation
	 * can be noop. This method should avoid expensive delays such as
	 * waiting on disk I/O, otherwise the goal of enabling a performance
	 * optimization would be defeated.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_xattr_get)(const struct lu_env *env,
				      struct dt_object *dt,
				      struct lu_buf *buf,
				      const char *name);

	/**
	 * do_xattr_get() - Return a value of an extended attribute.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @buf: unused, may be removed in the future
	 * @name: name of the extended attribute
	 *
	 * The object must exist. If the buffer is NULL, then the method
	 * must return the size of the value.
	 *
	 * Return:
	 * 0 - on success
	 * -ERANGE - if @buf is too small
	 * negative - negated errno on error
	 * positive - value's size if @buf is NULL or has zero size
	 */
	int   (*do_xattr_get)(const struct lu_env *env,
			      struct dt_object *dt,
			      struct lu_buf *buf,
			      const char *name);

	/**
	 * do_declare_xattr_set() - Declare intention to change an extended
	 *                          attribute.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @buf: unused, may be removed in the future
	 * @name: name of the extended attribute
	 * @fl:	LU_XATTR_CREATE - fail if EA exists
	 *      LU_XATTR_REPLACE - fail if EA doesn't exist
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the extended attribute may
	 * change in this transaction.  This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it. The object
	 * need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_xattr_set)(const struct lu_env *env,
				      struct dt_object *dt,
				      const struct lu_buf *buf,
				      const char *name,
				      int fl,
				      struct thandle *th);

	/**
	 * do_xattr_set() - Set an extended attribute.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @buf: unused, may be removed in the future
	 * @name: name of the extended attribute
	 * @fl:	LU_XATTR_CREATE - fail if EA exists
	 *      LU_XATTR_REPLACE - fail if EA doesn't exist
	 * @th: transaction handle
	 *
	 * Change or replace the specified extended attribute (EA).
	 * The flags passed in \a fl dictate whether the EA is to be
	 * created or replaced, as follows.
	 *   LU_XATTR_CREATE - fail if EA exists
	 *   LU_XATTR_REPLACE - fail if EA doesn't exist
	 * The object must exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_xattr_set)(const struct lu_env *env,
			      struct dt_object *dt,
			      const struct lu_buf *buf,
			      const char *name,
			      int fl,
			      struct thandle *th);

	/**
	 * do_declare_xattr_del() - Declare intention to delete an extended
	 *                          attribute.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @name: name of the extended attribute
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the extended attribute may
	 * be deleted in this transaction. This enables the layer below to
	 * prepare resources (e.g. journal credits in ext4).  This method
	 * should be called between creating the transaction and starting it.
	 * The object need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_xattr_del)(const struct lu_env *env,
				      struct dt_object *dt,
				      const char *name,
				      struct thandle *th);

	/**
	 * do_xattr_del() - Delete an extended attribute.
	 *
	 * @env: execution environment for this thread
	 * @dt: object to lock for reading
	 * @name: name of the extended attribute
	 * @th: transaction handle
	 *
	 * This method deletes the specified extended attribute. The object
	 * must exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_xattr_del)(const struct lu_env *env,
			      struct dt_object *dt,
			      const char *name,
			      struct thandle *th);

	/**
	 * do_xattr_list() - Return a list of the extended attributes.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @buf: buffer to put the list in
	 *
	 * Fills the passed buffer with a list of the extended attributes
	 * found in the object. The names are separated with '\0'.
	 * The object must exist.
	 *
	 * Return:
	 * positive - bytes used/required in the buffer
	 * negative - negated errno on error
	 */
	int   (*do_xattr_list)(const struct lu_env *env,
			       struct dt_object *dt,
			       const struct lu_buf *buf);

	/**
	 * do_ah_init() - Prepare allocation hint for a new object.
	 *
	 * @env: execution environment for this thread
	 * @ah:	allocation hint
	 * @parent: parent object (can be NULL)
	 * @child: child object
	 * @_mode: type of the child object
	 *
	 * This method is used by the caller to inform OSD of the parent-child
	 * relationship between two objects and enable efficient object
	 * allocation. Filled allocation hint will be passed to ->do_create()
	 * later.
	 */
	void  (*do_ah_init)(const struct lu_env *env,
			    struct dt_allocation_hint *ah,
			    struct dt_object *parent,
			    struct dt_object *child,
			    umode_t mode);

	/**
	 * do_declare_create() - Declare intention to create a new object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @attr: attributes of the new object
	 * @hint: allocation hint
	 * @dof: object format
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the object may be created
	 * in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should reserve an object for the given credentials
	 * and return an error if quota is over. If object creation later
	 * fails for some reason, then the reservation should be released
	 * properly (usually in ->dt_trans_stop()).
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_create)(const struct lu_env *env,
				   struct dt_object *dt,
				   struct lu_attr *attr,
				   struct dt_allocation_hint *hint,
				   struct dt_object_format *dof,
				   struct thandle *th);

	/**
	 * do_create() - Create new object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @attr: attributes of the new object
	 * @hint: allocation hint
	 * @dof: object format
	 * @th: transaction handle
	 *
	 * The method creates the object passed with the specified attributes
	 * and object format. Object allocation procedure can use information
	 * stored in the allocation hint. Different object formats are supported
	 * (see enum dt_format_type and struct dt_object_format) depending on
	 * the device. If creation succeeds, then LOHA_EXISTS flag must be set
	 * in the LU-object header attributes.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should maintain object accounting for the given
	 * credentials.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_create)(const struct lu_env *env,
			   struct dt_object *dt,
			   struct lu_attr *attr,
			   struct dt_allocation_hint *hint,
			   struct dt_object_format *dof,
			   struct thandle *th);

	/**
	 * do_declare_destroy() - Declare intention to destroy an object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the object may be destroyed
	 * in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it. The object
	 * need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_destroy)(const struct lu_env *env,
				    struct dt_object *dt,
				    struct thandle *th);

	/**
	 * do_destroy() - Destroy an object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th: transaction handle
	 *
	 * This method destroys the object and all the resources associated
	 * with the object (data, key/value pairs, extended attributes, etc).
	 * The object must exist. If destroy is successful, then flag
	 * LU_OBJECT_HEARD_BANSHEE should be set to forbid access to this
	 * instance of in-core object. Any subsequent access to the same FID
	 * should get another instance with no LOHA_EXIST flag set.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should maintain object accounting for the given
	 * credentials.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_destroy)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct thandle *th);

	/**
	 * do_index_try() - Try object as an index.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @feat: index features
	 *
	 * Announce that this object is going to be used as an index. This
	 * operation checks that object supports indexing operations and
	 * installs appropriate dt_index_operations vector on success.
	 * Also probes for features. Operation is successful if all required
	 * features are supported. It's not possible to access the object
	 * with index methods before ->do_index_try() returns success.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_index_try)(const struct lu_env *env,
			      struct dt_object *dt,
			      const struct dt_index_features *feat);

	/**
	 * do_declare_ref_add() - Declare intention to increment nlink count.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the nlink regular attribute
	 * be changed in this transaction. This enables the layer below to
	 * prepare resources (e.g. journal credits in ext4).  This method
	 * should be called between creating the transaction and starting it.
	 * The object need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_ref_add)(const struct lu_env *env,
				    struct dt_object *dt,
				    struct thandle *th);

	/**
	 * do_ref_add() - Increment nlink.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th: transaction handle
	 *
	 * Increment nlink (from the regular attributes set) in the given
	 * transaction. Note the absolute limit for nlink should be learnt
	 * from struct dt_device_param::ddp_max_nlink. The object must exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_ref_add)(const struct lu_env *env,
			    struct dt_object *dt, struct thandle *th);

	/**
	 * do_declare_ref_del() - Declare intention to decrement nlink count.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that the nlink regular attribute
	 * be changed in this transaction. This enables the layer below to
	 * prepare resources (e.g. journal credits in ext4).  This method
	 * should be called between creating the transaction and starting it.
	 * The object need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_declare_ref_del)(const struct lu_env *env,
				    struct dt_object *dt,
				    struct thandle *th);

	/**
	 * do_ref_del() - Decrement nlink.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th: transaction handle
	 *
	 * Decrement nlink (from the regular attributes set) in the given
	 * transaction. The object must exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_ref_del)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct thandle *th);

	/**
	 * do_object_sync() - Sync obect.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @start: start of the range to sync
	 * @end: end of the range to sync
	 *
	 * The method is called to sync specified range of the object to a
	 * persistent storage. The control is returned once the operation is
	 * complete. The difference from ->do_sync() is that the object can
	 * be in-sync with the persistent storage (nothing to flush), then
	 * the method returns quickly with no I/O overhead. So, this method
	 * should be preferred over ->do_sync() where possible. Also note that
	 * if the object isn't clean, then some disk filesystems will call
	 * ->do_sync() to maintain overall consistency, in which case it's
	 * still very expensive.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*do_object_sync)(const struct lu_env *env, struct dt_object *obj,
			      __u64 start, __u64 end);

	/**
	 * do_object_lock() - Lock object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @lh: lock handle, sometimes used, sometimes not
	 * @einfo: ldlm callbacks, locking type and mode
	 * @policy: inodebits data
	 *
	 * Lock object(s) using Distributed Lock Manager (LDLM).
	 *
	 * Get LDLM locks for the object. Currently used to lock "remote"
	 * objects in DNE configuration - a service running on MDTx needs
	 * to lock an object on MDTy.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*do_object_lock)(const struct lu_env *env, struct dt_object *dt,
			      struct lustre_handle *lh,
			      struct ldlm_enqueue_info *einfo,
			      union ldlm_policy_data *policy);

	/**
	 * do_object_unlock() - Unlock object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @einfo: ldlm callbacks, locking type and mode
	 * @policy: inodebits data
	 *
	 * Release LDLM lock(s) granted with ->do_object_lock().
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*do_object_unlock)(const struct lu_env *env,
				struct dt_object *dt,
				struct ldlm_enqueue_info *einfo,
				union ldlm_policy_data *policy);

	/**
	 * do_invalidate() - Invalidate attribute cache.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 *
	 * This method invalidate attribute cache of the object, which is on OSP
	 * only.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*do_invalidate)(const struct lu_env *env, struct dt_object *dt);

	/**
	 * do_check_stale() - Check object stale state.
	 *
	 * @dt: object
	 *
	 * OSP only.
	 *
	 * Return: true for stale object, false for not stale object
	 */
	bool (*do_check_stale)(struct dt_object *dt);

	/**
	 * do_declare_layout_change() - Declare intention to instantiate
	 *                              extended layout component.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @layout: data structure to describe the changes to
	 *          the DT object's layout
	 * @buf: buffer containing client's lovea or empty
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*do_declare_layout_change)(const struct lu_env *env,
					struct dt_object *dt,
					struct md_layout_change *mlc,
					struct thandle *th);

	/**
	 * do_layout_change() - Client is trying to write to un-instantiated
	 *                      layout component.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @layout: data structure to describe the changes to
	 *          the DT object's layout
	 * @buf: buffer containing client's lovea or empty
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*do_layout_change)(const struct lu_env *env, struct dt_object *dt,
				struct md_layout_change *mlc,
				struct thandle *th);

	/**
	 * Check whether the file is in PCC-RO state.
	 *
	 * \param[in] env	execution environment
	 * \param[in] dt	DT object
	 * \param[in] layout	data structure to describe the changes to
	 *			the DT object's layout
	 *
	 * \retval 0		success
	 * \retval -ne		-EALREADY if the file is already PCC-RO cached;
	 *			Otherwise, return error code
	 */
	int (*do_layout_pccro_check)(const struct lu_env *env,
				     struct dt_object *dt,
				     struct md_layout_change *mlc);
};

enum dt_bufs_type {
	DT_BUFS_TYPE_READ	= 0x0000,
	DT_BUFS_TYPE_WRITE	= 0x0001,
	DT_BUFS_TYPE_READAHEAD	= 0x0002,
	DT_BUFS_TYPE_LOCAL	= 0x0004,
};

/*
 * Per-dt-object operations on "file body" - unstructure raw data.
 */
struct dt_body_operations {
	/**
	 * dbo_read() - Read data.
	 *
	 * Read unstructured data from an existing regular object.
	 * Only data before attr.la_size is returned.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @buf: buffer (including size) to copy data in
	 * @pos: position in the object to start, updated to
	 *       original value of @pos + bytes returned
	 *
	 * Return:
	 * positive - bytes read on success
	 * negative - negated errno on error
	 */
	ssize_t (*dbo_read)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct lu_buf *buf,
			    loff_t *pos);

	/**
	 * dbo_declare_write() - Declare intention to write data to object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @buf: buffer (including size) to copy data from
	 * @pos: position in the object to start
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that data may be written in
	 * this transaction. This enables the layer below to prepare resources
	 * (e.g. journal credits in ext4).  This method should be called
	 * between creating the transaction and starting it. The object need
	 * not exist. If the layer implementing this method is responsible for
	 * quota, then the method should reserve space for the given credentials
	 * and return an error if quota is over. If the write later fails
	 * for some reason, then the reserve should be released properly
	 * (usually in ->dt_trans_stop()).
	 *
	 * Return: 0 on success, negative on error
	 */
	ssize_t (*dbo_declare_write)(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct lu_buf *buf,
				     loff_t pos,
				     struct thandle *th);

	/**
	 * dbo_write() - Write unstructured data to regular existing object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @buf: buffer (including size) to copy data from
	 * @pos: position in the object to start, updated
	 *       to @pos + bytes written
	 * @th: transaction handle
	 *
	 * The method allocates space and puts data in. Also, the method should
	 * maintain attr.la_size properly. Partial writes are possible.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should maintain space accounting for the given
	 * credentials.
	 *
	 * Return:
	 * positive - bytes read on success
	 * negative - negated errno on error
	 */
	ssize_t (*dbo_write)(const struct lu_env *env,
			     struct dt_object *dt,
			     const struct lu_buf *buf,
			     loff_t *pos,
			     struct thandle *th);

	/**
	 * dbo_bufs_get() - Return buffers for data.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @pos: position in the object to start
	 * @len: size of region in bytes
	 * @lb: array of descriptors to fill
	 * @maxlnb: max slots in lnb array
	 * @rw: 0 if used to read, 1 if used for write
	 *
	 * This method is used to access data with no copying. It's so-called
	 * zero-copy I/O. The method returns the descriptors for the internal
	 * buffers where data are managed by the disk filesystem. For example,
	 * pagecache in case of ext4 or ARC with ZFS. Then other components
	 * (e.g. networking) can transfer data from or to the buffers with no
	 * additional copying.
	 *
	 * The method should fill an array of struct niobuf_local, where
	 * each element describes a full or partial page for data at specific
	 * offset. The caller should use page/lnb_page_offset/len to find data
	 * at object's offset lnb_file_offset.
	 *
	 * The memory referenced by the descriptors can't change its purpose
	 * until the complementary ->dbo_bufs_put() is called. The caller should
	 * specify if the buffers are used to read or modify data so that OSD
	 * can decide how to initialize the buffers: bring all the data for
	 * reads or just bring partial buffers for write. Note: the method does
	 * not check whether output array is large enough.
	 *
	 * Return:
	 * positive - number of descriptors on success
	 * negative - negated errno on error
	 */
	int (*dbo_bufs_get)(const struct lu_env *env,
			    struct dt_object *dt,
			    loff_t pos,
			    ssize_t len,
			    struct niobuf_local *lb,
			    int maxlnb,
			    enum dt_bufs_type rw);

	/**
	 * dbo_bufs_put() - Release reference granted by ->dbo_bufs_get().
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @lb: array of descriptors to fill
	 * @nr: size of the array
	 *
	 * Release the reference granted by the previous ->dbo_bufs_get().
	 * Note the references are counted.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_bufs_put)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct niobuf_local *lb,
			    int nr);

	/**
	 * dbo_read_prep() - Prepare buffers for reading.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @lb: array of descriptors to fill
	 * @nr: size of the array
	 *
	 * The method is called on the given buffers to fill them with data
	 * if that wasn't done in ->dbo_bufs_get(). The idea is that the
	 * caller should be able to get few buffers for discontiguous regions
	 * using few calls to ->dbo_bufs_get() and then request them all for
	 * the preparation with a single call, so that OSD can fire many I/Os
	 * to run concurrently. It's up to the specific OSD whether to implement
	 * this logic in ->dbo_read_prep() or just use ->dbo_bufs_get() to
	 * prepare data for every requested region individually.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_read_prep)(const struct lu_env *env,
			     struct dt_object *dt,
			     struct niobuf_local *lnb,
			     int nr);

	/**
	 * dbo_write_prep() - Prepare buffers for write.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @lb: array of descriptors to fill
	 * @nr: size of the array
	 *
	 * This method is called on the given buffers to ensure the partial
	 * buffers contain correct data. The underlying idea is the same as
	 * in ->db_read_prep().
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_write_prep)(const struct lu_env *env,
			      struct dt_object *dt,
			      struct niobuf_local *lb,
			      int nr);

	/**
	 * dbo_declare_write_commit() - Declare intention to write data stored
	 *                              in the buffers.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @lb: array of descriptors
	 * @nr: size of the array
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that data may be written in
	 * this transaction. This enables the layer below to prepare resources
	 * (e.g. journal credits in ext4).  This method should be called
	 * between creating the transaction and starting it.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should be reserving a space for the given
	 * credentials and return an error if quota is exceeded. If the write
	 * later fails for some reason, then the reserve should be released
	 * properly (usually in ->dt_trans_stop()).
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_declare_write_commit)(const struct lu_env *env,
					struct dt_object *dt,
					struct niobuf_local *lb,
					int nr,
					struct thandle *th);

	/**
	 * dbo_write_commit() - Write to existing object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @lb: array of descriptors
	 * @nr: size of the array
	 * @th: transaction handle
	 * @user_size: apparent size
	 *
	 * This method is used to write data to a persistent storage using
	 * the buffers returned by ->dbo_bufs_get(). The caller puts new
	 * data into the buffers using own mechanisms (e.g. direct transfer
	 * from a NIC). The method should maintain attr.la_size. Also,
	 * attr.la_blocks should be maintained but this can be done in lazy
	 * manner, when actual allocation happens.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should maintain space accounting for the given
	 * credentials.
	 *
	 * user_size parameter is the apparent size of the file, ie the size
	 * of the clear text version of the file. It can differ from the actual
	 * amount of valuable data received when a file is encrypted,
	 * because encrypted pages always contain PAGE_SIZE bytes of data,
	 * even if clear text data is only a few bytes.
	 * In case of encrypted file, apparent size will be stored as the inode
	 * size, so that servers return to clients an object size they can use
	 * to determine clear text size.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_write_commit)(const struct lu_env *env,
				struct dt_object *dt,
				struct niobuf_local *lb,
				int nr,
				struct thandle *th,
				__u64 user_size);

	/**
	 * dbo_fiemap_get() - Return logical to physical block mapping for a
	 *                    given extent
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @fm: describe the region to map and the output buffer
	 *      see the details in include/linux/fiemap.h
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_fiemap_get)(const struct lu_env *env,
			      struct dt_object *dt,
			      struct fiemap *fm);

	/**
	 * dbo_declare_punch() - Declare intention to deallocate space from
	 *                       an object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @start: the start of the region to deallocate
	 * @end: the end of the region to deallocate
	 * @th: transaction handle
	 *
	 * Notify the underlying filesystem that space may be deallocated in
	 * this transactions. This enables the layer below to prepare resources
	 * (e.g. journal credits in ext4).  This method should be called between
	 * creating the transaction and starting it. The object need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dbo_declare_punch)(const struct lu_env *env,
				   struct dt_object *dt,
				   __u64 start,
				   __u64 end,
				   struct thandle *th);

	/**
	 * dbo_punch() - Deallocate specified region in an object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @start: the start of the region to deallocate
	 * @end: the end of the region to deallocate
	 * @th: transaction handle
	 *
	 * This method is used to deallocate (release) space possibly consumed
	 * by the given region of the object. If the layer implementing this
	 * method is responsible for quota, then the method should maintain
	 * space accounting for the given credentials.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dbo_punch)(const struct lu_env *env,
			   struct dt_object *dt,
			   __u64 start,
			   __u64 end,
			   struct thandle *th);

	/**
	 * dbo_ladvice() - Give advices on specified region in an object.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @start: the start of the region affected
	 * @end: the end of the region to affected
	 * @advice: advice type
	 *
	 * This method is used to give advices about access pattern on an
	 * given region of the object. The disk filesystem understands
	 * the advices and tunes cache/read-ahead policies.
	 *
	 * Return: 0 on success, negative on error
	 */
	int   (*dbo_ladvise)(const struct lu_env *env,
			     struct dt_object *dt,
			     __u64 start,
			     __u64 end,
			     enum lu_ladvise_type advice);

	/**
	 * dbo_declare_fallocate() - Declare intention to preallocate space
	 *                           for an object
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @th:	transaction handle
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_declare_fallocate)(const struct lu_env *env,
				    struct dt_object *dt, __u64 start,
				    __u64 end, int mode, struct thandle *th);

	/**
	 * dbo_fallocate() - Allocate specified region for an object
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @start: the start of the region to allocate
	 * @end: the end of the region to allocate
	 * @mode: fallocate mode
	 * @th: transaction handle
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dbo_fallocate)(const struct lu_env *env,
			    struct dt_object *dt,
			    __u64 start,
			    __u64 end,
			    int mode,
			    struct thandle *th);

	/**
	 * dbo_lseek() - Do SEEK_HOLE/SEEK_DATA request on object
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @offset: the offset to start seek from
	 * @whence: seek mode, SEEK_HOLE or SEEK_DATA
	 *
	 * Return:
	 * hole/data offset - on success
	 * negative - negated errno on error
	 */
	loff_t (*dbo_lseek)(const struct lu_env *env, struct dt_object *dt,
			    loff_t offset, int whence);
};

/* Incomplete type of index record. */
struct dt_rec;

/* Incomplete type of index key. */
struct dt_key;

/* Incomplete type of dt iterator. */
struct dt_it;

/*
 * Per-dt-object operations on object as index. Index is a set of key/value
 * pairs abstracted from an on-disk representation. An index supports the
 * number of operations including lookup by key, insert and delete. Also,
 * an index can be iterated to find the pairs one by one, from a beginning
 * or specified point.
 */
struct dt_index_operations {
	/**
	 * dio_lookup() - Lookup in an index by key.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @rec: buffer where value will be stored
	 * @key: key
	 *
	 * The method returns a value for the given key. Key/value format
	 * and size should have been negotiated with ->do_index_try() before.
	 * Thus it's the caller's responsibility to provide the method with
	 * proper key and big enough buffer. No external locking is required,
	 * all the internal consistency should be implemented by the method
	 * or lower layers. The object should have been created with
	 * type DFT_INDEX or DFT_DIR.
	 *
	 * Return:
	 * 0 - on success
	 * -ENOENT - if key isn't found
	 * negative - negated errno on error
	 */
	int (*dio_lookup)(const struct lu_env *env,
			  struct dt_object *dt,
			  struct dt_rec *rec,
			  const struct dt_key *key);

	/**
	 * dio_declare_insert() - Declare intention to insert a key/value into
	 *                        an index.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @rec: buffer storing value
	 * @key: key
	 * @th:	transaction handle
	 *
	 * Notify the underlying filesystem that new key/value may be inserted
	 * in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4). This method should be
	 * called between creating the transaction and starting it. key/value
	 * format and size is subject to ->do_index_try().
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dio_declare_insert)(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_rec *rec,
				  const struct dt_key *key,
				  struct thandle *th);

	/**
	 * dio_insert() - Insert a new key/value pair into an index.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @rec: buffer storing value
	 * @key: key
	 * @th:	transaction handle
	 *
	 * The method inserts specified key/value pair into the given index
	 * object. The internal consistency is maintained by the method or
	 * the functionality below. The format and size of key/value should
	 * have been negotiated before using ->do_index_try(), no additional
	 * information can be specified to the method. The keys are unique
	 * in a given index.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dio_insert)(const struct lu_env *env,
			  struct dt_object *dt,
			  const struct dt_rec *rec,
			  const struct dt_key *key,
			  struct thandle *th);

	/**
	 * dio_declare_delete() - Declare intention to delete a key/value from
	 *                        an index.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @key: key
	 * @th:	transaction handle
	 *
	 * Notify the underlying filesystem that key/value may be deleted in
	 * this transaction. This enables the layer below to prepare resources
	 * (e.g. journal credits in ext4).  This method should be called
	 * between creating the transaction and starting it. Key/value format
	 * and size is subject to ->do_index_try(). The object need not exist.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dio_declare_delete)(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_key *key,
				  struct thandle *th);

	/**
	 * dio_delete() - Delete key/value pair from an index.
	 *
	 * @env: execution environment for this thread
	 * @dt: object
	 * @key: key
	 * @th:	transaction handle
	 *
	 * The method deletes specified key and corresponding value from the
	 * given index object. The internal consistency is maintained by the
	 * method or the functionality below. The format and size of the key
	 * should have been negotiated before using ->do_index_try(), no
	 * additional information can be specified to the method.
	 *
	 * Return: 0 on success, negative on error
	 */
	int (*dio_delete)(const struct lu_env *env,
			  struct dt_object *dt,
			  const struct dt_key *key,
			  struct thandle *th);

	/*
	 * Iterator interface.
	 *
	 * Methods to iterate over an existing index, list the keys stored and
	 * associated values, get key/value size, etc.
	 */
	struct dt_it_ops {
		/**
		 * init() - Allocate and initialize new iterator.
		 *
		 * @env: execution environment for this thread
		 * @dt: object
		 * @attr: ask the iterator to return part of
		 *        the records, see LUDA_* for details
		 *
		 * The iterator is a handler to be used in the subsequent
		 * methods to access index's content. Note the position is
		 * not defined at this point and should be initialized with
		 * ->get() or ->load() method.
		 *
		 * Return: iterator pointer on success or ERR_PTR()
		 */
		struct dt_it *(*init)(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr);

		/**
		 * fini() - Release iterator.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator to release
		 *
		 * Release the specified iterator and all the resources
		 * associated (e.g. the object, index cache, etc).
		 */
		void          (*fini)(const struct lu_env *env,
				      struct dt_it *di);

		/**
		 * get() - Move position of iterator.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 * @key: key to position to
		 *
		 * Move the position of the specified iterator to the specified
		 * key.
		 *
		 * Return:
		 * 0 - if exact key is found
		 * 1 - if at the record with least key
		 *     not larger than the key
		 * negative - negated errno on error
		 */
		int            (*get)(const struct lu_env *env,
				      struct dt_it *di,
				      const struct dt_key *key);

		/**
		 * put() - Release position
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 *
		 * Complimentary method for dt_it_ops::get() above. Some
		 * implementation can increase a reference on the iterator in
		 * dt_it_ops::get(). So the caller should be able to release
		 * with dt_it_ops::put().
		 */
		void           (*put)(const struct lu_env *env,
				      struct dt_it *di);

		/**
		 * next() - Move to next record.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 *
		 * Moves the position of the iterator to a next record
		 *
		 * Return:
		 * 1 - if no more records
		 * 0 - on success, the next record is found
		 * negative - negated errno on error
		 */
		int           (*next)(const struct lu_env *env,
				      struct dt_it *di);

		/**
		 * key() - Return key.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 *
		 * Returns a pointer to a buffer containing the key of the
		 * record at the current position. The pointer is valid and
		 * retains data until ->get(), ->load() and ->fini() methods
		 * are called.
		 *
		 * Return: pointer to key on success or ERR_PTR()
		 */
		struct dt_key *(*key)(const struct lu_env *env,
				      const struct dt_it *di);

		/**
		 * key_size() - Return key size.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 *
		 * Returns size of the key at the current position.
		 *
		 * Return: key's size on success, negative errno otherwise
		 */
		int       (*key_size)(const struct lu_env *env,
				      const struct dt_it *di);

		/**
		 * rec() - Return record.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 * @rec: buffer to store value in
		 * @attr: specify part of the value to copy
		 *
		 * Stores the value of the record at the current position. The
		 * buffer must be big enough (as negotiated with
		 * ->do_index_try() or ->rec_size()). The caller can specify
		 * she is interested only in part of the record, using attr
		 * argument (see LUDA_* definitions for the details).
		 *
		 * Return: 0 on success, negative on error
		 */
		int            (*rec)(const struct lu_env *env,
				      const struct dt_it *di,
				      struct dt_rec *rec,
				      __u32 attr);

		/**
		 * rec_size() - Return record size.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 * @attr: part of the record to return
		 *
		 * Returns size of the record at the current position. The
		 * @attr can be used to specify only the parts of the record
		 * needed to be returned. (see LUDA_* definitions for the
		 * details).
		 *
		 * Return: 0 on success, negative on error
		 */
		int	   (*rec_size)(const struct lu_env *env,
				       const struct dt_it *di,
				      __u32 attr);

		/**
		 * store() - Return a cookie (hash).
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 *
		 * Returns the cookie (usually hash) of the key at the current
		 * position. This allows the caller to resume iteration at this
		 * position later. The exact value is specific to implementation
		 * and should not be interpreted by the caller.
		 *
		 * Return: cookie/hash of the key
		 */
		__u64        (*store)(const struct lu_env *env,
				      const struct dt_it *di);

		/**
		 * load() - Initialize position using cookie/hash.
		 *
		 * @env: execution environment for this thread
		 * @di: iterator
		 * @hash: cookie/hash value
		 *
		 * Initializes the current position of the iterator to one
		 * described by the cookie/hash as returned by ->store()
		 * previously.
		 *
		 * Return:
		 * positive - if current position points to
		 *            record with least cookie not larger
		 *            than cookie
		 * 0 - if current position matches cookie
		 * negative - negated errno on error
		 */
		int           (*load)(const struct lu_env *env,
				      const struct dt_it *di,
				      __u64 hash);
	} dio_it;
};

enum dt_otable_it_valid {
	DOIV_ERROR_HANDLE	= 0x0001,
	DOIV_DRYRUN		= 0x0002,
};

enum dt_otable_it_flags {
	/* Exit when fail. */
	DOIF_FAILOUT	= 0x0001,

	/* Reset iteration position to the device beginning. */
	DOIF_RESET	= 0x0002,

	/* There is up layer component uses the iteration. */
	DOIF_OUTUSED	= 0x0004,

	/* Check only without repairing. */
	DOIF_DRYRUN	= 0x0008,
};

/*
 * otable based iteration needs to use the common DT iteration APIs.
 * To initialize the iteration, it needs call dio_it::init() firstly.
 * Here is how the otable based iteration should prepare arguments to
 * call dt_it_ops::init().
 *
 * For otable based iteration, the 32-bits 'attr' for dt_it_ops::init()
 * is composed of two parts:
 * low 16-bits is for valid bits, high 16-bits is for flags bits.
 */
#define DT_OTABLE_IT_FLAGS_SHIFT	16
#define DT_OTABLE_IT_FLAGS_MASK	0xffff0000

struct dt_device {
	struct lu_device                   dd_lu_dev;
	const struct dt_device_operations *dd_ops;
	struct lu_client_seq		  *dd_cl_seq;

	/*
	 * List of dt_txn_callback (see below). This is not protected in any
	 * way, because callbacks are supposed to be added/deleted only during
	 * single-threaded start-up shut-down procedures.
	 */
	struct list_head		   dd_txn_callbacks;
	unsigned int			   dd_record_fid_accessed:1,
					   dd_rdonly:1;

	/* sysfs and debugfs handling */
	struct dentry			  *dd_debugfs_entry;

	const struct attribute		 **dd_def_attrs;
	struct kobject			   dd_kobj;
	struct kobj_type		   dd_ktype;
	struct completion		   dd_kobj_unregister;
};

int  dt_device_init(struct dt_device *dev, struct lu_device_type *t);
void dt_device_fini(struct dt_device *dev);

static inline int lu_device_is_dt(const struct lu_device *d)
{
	return ergo(d != NULL, d->ld_type->ldt_tags & LU_DEVICE_DT);
}

static inline struct dt_device *lu2dt_dev(struct lu_device *l)
{
	LASSERT(lu_device_is_dt(l));
	return container_of_safe(l, struct dt_device, dd_lu_dev);
}

struct dt_object {
	struct lu_object                   do_lu;
	const struct dt_object_operations *do_ops;
	const struct dt_body_operations   *do_body_ops;
	const struct dt_index_operations  *do_index_ops;
};

/*
 * In-core representation of per-device local object OID storage
 */
struct local_oid_storage {
	/* all initialized llog systems on this node linked by this */
	struct list_head  los_list;

	/* how many handle's reference this los has */
	atomic_t	  los_refcount;
	struct dt_device *los_dev;
	struct dt_object *los_obj;

	/* data used to generate new fids */
	struct mutex	  los_id_lock;
	__u64		  los_seq;
	__u32		  los_last_oid;
};

static inline struct lu_device *dt2lu_dev(struct dt_device *d)
{
	return &d->dd_lu_dev;
}

static inline struct dt_object *lu2dt(struct lu_object *l)
{
	LASSERT(l == NULL || IS_ERR(l) || lu_device_is_dt(l->lo_dev));
	return container_of_safe(l, struct dt_object, do_lu);
}

int  dt_object_init(struct dt_object *obj,
		    struct lu_object_header *h, struct lu_device *d);

void dt_object_fini(struct dt_object *obj);

static inline int dt_object_exists(const struct dt_object *dt)
{
	return lu_object_exists(&dt->do_lu);
}

static inline int dt_object_remote(const struct dt_object *dt)
{
	return lu_object_remote(&dt->do_lu);
}

static inline struct dt_object *lu2dt_obj(struct lu_object *o)
{
	LASSERT(ergo(o != NULL, lu_device_is_dt(o->lo_dev)));
	return container_of_safe(o, struct dt_object, do_lu);
}

static inline struct dt_object *dt_object_child(struct dt_object *o)
{
	return container_of(lu_object_next(&(o)->do_lu),
			    struct dt_object, do_lu);
}

/*
 * This is the general purpose transaction handle.
 * 1. Transaction Life Cycle
 *      This transaction handle is allocated upon starting a new transaction,
 *      and deallocated after this transaction is committed.
 * 2. Transaction Nesting
 *      We do _NOT_ support nested transaction. So, every thread should only
 *      have one active transaction, and a transaction only belongs to one
 *      thread. Due to this, transaction handle need no reference count.
 * 3. Transaction & dt_object locking
 *      dt_object locks should be taken inside transaction.
 * 4. Transaction & RPC
 *      No RPC request should be issued inside transaction.
 */
struct thandle {
	/** the dt device on which the transactions are executed */
	struct dt_device *th_dev;

	/* point to the top thandle, XXX this is a bit hacky right now,
	 * but normal device trans callback triggered by the bottom
	 * device (OSP/OSD == sub thandle layer) needs to get the
	 * top_thandle (see dt_txn_hook_start/stop()), so we put the
	 * top thandle here for now, will fix it when we have better
	 * callback mechanism
	 */
	struct thandle	*th_top;

	/* reserved quota for this handle */
	struct lquota_id_info	th_reserved_quota;

	/* last operation result in this transaction. value used in recovery */
	__s32             th_result;

	/** whether we need sync commit */
	unsigned int		th_sync:1,
	/* local transation, no need to inform other layers */
				th_local:1,
	/* Do we wait the transaction to be submitted (send to remote target) */
				th_wait_submit:1,
	/* complex transaction to track updates on all targets including OSTs */
				th_complex:1,
	/* whether ignore quota */
				th_ignore_quota:1,
	/* whether restart transaction */
				th_restart_tran:1;
};

/*
 * Transaction call-backs.
 *
 * These are invoked by osd (or underlying transaction engine) when
 * transaction changes state.
 *
 * Call-backs are used by upper layers to modify transaction parameters and to
 * perform some actions on for each transaction state transition. Typical
 * example is mdt registering call-back to write into last-received file
 * before each transaction commit.
 */
struct dt_txn_callback {
	int (*dtc_txn_start)(const struct lu_env *env,
			     struct thandle *txn, void *cookie);
	int (*dtc_txn_stop)(const struct lu_env *env,
			    struct thandle *txn, void *cookie);
	void			*dtc_cookie;
	__u32			dtc_tag;
	struct list_head	dtc_linkage;
};

void dt_txn_callback_add(struct dt_device *dev, struct dt_txn_callback *cb);
void dt_txn_callback_del(struct dt_device *dev, struct dt_txn_callback *cb);

int dt_txn_hook_start(const struct lu_env *env,
		      struct dt_device *dev, struct thandle *txn);
int dt_txn_hook_stop(const struct lu_env *env, struct thandle *txn);

int dt_try_as_dir(const struct lu_env *env, struct dt_object *obj, bool check);

/*
 * Callback function used for parsing path.
 * see llo_store_resolve
 */
typedef int (*dt_entry_func_t)(const struct lu_env *env,
			    const char *name,
			    void *pvt);

#define DT_MAX_PATH 1024

int dt_path_parser(const struct lu_env *env,
		   char *local, dt_entry_func_t entry_func,
		   void *data);

struct dt_object *
dt_store_resolve(const struct lu_env *env, struct dt_device *dt,
		 const char *path, struct lu_fid *fid);

struct dt_object *dt_store_open(const struct lu_env *env,
				struct dt_device *dt,
				const char *dirname,
				const char *filename,
				struct lu_fid *fid);

struct dt_object *dt_find_or_create(const struct lu_env *env,
				    struct dt_device *dt,
				    const struct lu_fid *fid,
				    struct dt_object_format *dof,
				    struct lu_attr *attr);

struct dt_object *dt_locate_at(const struct lu_env *env,
			       struct dt_device *dev,
			       const struct lu_fid *fid,
			       struct lu_device *top_dev,
			       const struct lu_object_conf *conf);

static inline struct dt_object *
dt_locate(const struct lu_env *env, struct dt_device *dev,
	  const struct lu_fid *fid)
{
	return dt_locate_at(env, dev, fid,
			    dev->dd_lu_dev.ld_site->ls_top_dev, NULL);
}

static inline struct dt_object *
dt_object_locate(struct dt_object *dto, struct dt_device *dt_dev)
{
	struct lu_object *lo;

	list_for_each_entry(lo, &dto->do_lu.lo_header->loh_layers, lo_linkage) {
		if (lo->lo_dev == &dt_dev->dd_lu_dev)
			return container_of(lo, struct dt_object, do_lu);
	}
	return NULL;
}

static inline void dt_object_put(const struct lu_env *env,
				 struct dt_object *dto)
{
	lu_object_put(env, &dto->do_lu);
}

static inline void dt_object_put_nocache(const struct lu_env *env,
					 struct dt_object *dto)
{
	lu_object_put_nocache(env, &dto->do_lu);
}

int local_oid_storage_init(const struct lu_env *env, struct dt_device *dev,
			   const struct lu_fid *first_fid,
			   struct local_oid_storage **los);
void local_oid_storage_fini(const struct lu_env *env,
			    struct local_oid_storage *los);
int local_object_fid_generate(const struct lu_env *env,
			      struct local_oid_storage *los,
			      struct lu_fid *fid);
int local_object_declare_create(const struct lu_env *env,
				struct local_oid_storage *los,
				struct dt_object *o,
				struct lu_attr *attr,
				struct dt_object_format *dof,
				struct thandle *th);
int local_object_create(const struct lu_env *env,
			struct local_oid_storage *los,
			struct dt_object *o,
			struct lu_attr *attr, struct dt_object_format *dof,
			struct thandle *th);
struct dt_object *local_file_find(const struct lu_env *env,
				  struct local_oid_storage *los,
				  struct dt_object *parent,
				  const char *name);
struct dt_object *local_file_find_or_create(const struct lu_env *env,
					    struct local_oid_storage *los,
					    struct dt_object *parent,
					    const char *name, __u32 mode);
struct dt_object *local_file_find_or_create_with_fid(const struct lu_env *env,
						     struct dt_device *dt,
						     const struct lu_fid *fid,
						     struct dt_object *parent,
						     const char *name,
						     __u32 mode);
struct dt_object *
local_index_find_or_create(const struct lu_env *env,
			   struct local_oid_storage *los,
			   struct dt_object *parent,
			   const char *name, __u32 mode,
			   const struct dt_index_features *ft);
struct dt_object *
local_index_find_or_create_with_fid(const struct lu_env *env,
				    struct dt_device *dt,
				    const struct lu_fid *fid,
				    struct dt_object *parent,
				    const char *name, __u32 mode,
				    const struct dt_index_features *ft);
int local_object_unlink(const struct lu_env *env, struct dt_device *dt,
			struct dt_object *parent, const char *name);

static inline int dt_object_lock(const struct lu_env *env,
				 struct dt_object *o, struct lustre_handle *lh,
				 struct ldlm_enqueue_info *einfo,
				 union ldlm_policy_data *policy)
{
	LASSERT(o);
	LASSERT(o->do_ops);
	LASSERT(o->do_ops->do_object_lock);
	return o->do_ops->do_object_lock(env, o, lh, einfo, policy);
}

static inline int dt_object_unlock(const struct lu_env *env,
				   struct dt_object *o,
				   struct ldlm_enqueue_info *einfo,
				   union ldlm_policy_data *policy)
{
	LASSERT(o);
	LASSERT(o->do_ops);
	LASSERT(o->do_ops->do_object_unlock);
	return o->do_ops->do_object_unlock(env, o, einfo, policy);
}

int dt_lookup_dir(const struct lu_env *env, struct dt_object *dir,
		  const char *name, struct lu_fid *fid);

static inline int dt_object_sync(const struct lu_env *env, struct dt_object *o,
				 __u64 start, __u64 end)
{
	LASSERT(o);
	LASSERT(o->do_ops);
	LASSERT(o->do_ops->do_object_sync);
	return o->do_ops->do_object_sync(env, o, start, end);
}

static inline int dt_fid_alloc(const struct lu_env *env,
			       struct dt_device *d,
			       struct lu_fid *fid,
			       struct lu_object *parent,
			       const struct lu_name *name)
{
	struct lu_device *l = dt2lu_dev(d);

	return l->ld_ops->ldo_fid_alloc(env, l, fid, parent, name);
}

int dt_declare_version_set(const struct lu_env *env, struct dt_object *o,
			   struct thandle *th);
void dt_version_set(const struct lu_env *env, struct dt_object *o,
		    dt_obj_version_t version, struct thandle *th);
int dt_declare_data_version_set(const struct lu_env *env, struct dt_object *o,
				struct thandle *th);
void dt_data_version_set(const struct lu_env *env, struct dt_object *o,
			 dt_obj_version_t version, struct thandle *th);
int dt_declare_data_version_del(const struct lu_env *env, struct dt_object *o,
				struct thandle *th);
void dt_data_version_del(const struct lu_env *env, struct dt_object *o,
			 struct thandle *th);
dt_obj_version_t dt_version_get(const struct lu_env *env, struct dt_object *o);
dt_obj_version_t dt_data_version_get(const struct lu_env *env,
				     struct dt_object *o);
dt_obj_version_t dt_data_version_init(const struct lu_env *env,
				      struct dt_object *o);

int dt_read(const struct lu_env *env, struct dt_object *dt,
	    struct lu_buf *buf, loff_t *pos);
int dt_record_read(const struct lu_env *env, struct dt_object *dt,
		   struct lu_buf *buf, loff_t *pos);
int dt_record_write(const struct lu_env *env, struct dt_object *dt,
		    const struct lu_buf *buf, loff_t *pos, struct thandle *th);
typedef int (*dt_index_page_build_t)(const struct lu_env *env,
				     struct dt_object *obj, union lu_page *lp,
				     size_t bytes, const struct dt_it_ops *iops,
				     struct dt_it *it, __u32 attr, void *arg);
int dt_index_walk(const struct lu_env *env, struct dt_object *obj,
		  const struct lu_rdpg *rdpg, dt_index_page_build_t filler,
		  void *arg);
int dt_index_read(const struct lu_env *env, struct dt_device *dev,
		  struct idx_info *ii, const struct lu_rdpg *rdpg);
void dt_index_page_adjust(struct page **pages, const u32 npages,
			  const size_t nlupgs);

static inline struct thandle *dt_trans_create(const struct lu_env *env,
					      struct dt_device *d)
{
	LASSERT(d->dd_ops->dt_trans_create);
	return d->dd_ops->dt_trans_create(env, d);
}

static inline int dt_trans_start(const struct lu_env *env,
				 struct dt_device *d, struct thandle *th)
{
	LASSERT(d->dd_ops->dt_trans_start);
	return d->dd_ops->dt_trans_start(env, d, th);
}

/* for this transaction hooks shouldn't be called */
static inline int dt_trans_start_local(const struct lu_env *env,
				       struct dt_device *d, struct thandle *th)
{
	LASSERT(d->dd_ops->dt_trans_start);
	th->th_local = 1;
	return d->dd_ops->dt_trans_start(env, d, th);
}

static inline int dt_trans_stop(const struct lu_env *env,
				struct dt_device *d, struct thandle *th)
{
	LASSERT(d->dd_ops->dt_trans_stop);
	return d->dd_ops->dt_trans_stop(env, d, th);
}

static inline int dt_trans_cb_add(struct thandle *th,
				  struct dt_txn_commit_cb *dcb)
{
	LASSERT(th->th_dev->dd_ops->dt_trans_cb_add);
	dcb->dcb_magic = TRANS_COMMIT_CB_MAGIC;
	return th->th_dev->dd_ops->dt_trans_cb_add(th, dcb);
}

static inline int dt_declare_record_write(const struct lu_env *env,
					  struct dt_object *dt,
					  const struct lu_buf *buf,
					  loff_t pos,
					  struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_declare_write);
	LASSERT(th);
	return dt->do_body_ops->dbo_declare_write(env, dt, buf, pos, th);
}

static inline int dt_declare_create(const struct lu_env *env,
				    struct dt_object *dt,
				    struct lu_attr *attr,
				    struct dt_allocation_hint *hint,
				    struct dt_object_format *dof,
				    struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_create);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_CREATE))
		return cfs_fail_err;

	return dt->do_ops->do_declare_create(env, dt, attr, hint, dof, th);
}

static inline int dt_create(const struct lu_env *env,
				    struct dt_object *dt,
				    struct lu_attr *attr,
				    struct dt_allocation_hint *hint,
				    struct dt_object_format *dof,
				    struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_create);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_CREATE))
		return cfs_fail_err;

	return dt->do_ops->do_create(env, dt, attr, hint, dof, th);
}

static inline int dt_declare_destroy(const struct lu_env *env,
				     struct dt_object *dt,
				     struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_destroy);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_DESTROY))
		return cfs_fail_err;

	return dt->do_ops->do_declare_destroy(env, dt, th);
}

static inline int dt_destroy(const struct lu_env *env,
			     struct dt_object *dt,
			     struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_destroy);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DESTROY))
		return cfs_fail_err;

	return dt->do_ops->do_destroy(env, dt, th);
}

static inline void dt_read_lock(const struct lu_env *env,
				struct dt_object *dt,
				unsigned int role)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_read_lock);
	dt->do_ops->do_read_lock(env, dt, role);
}

static inline void dt_write_lock(const struct lu_env *env,
				struct dt_object *dt,
				unsigned int role)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_write_lock);
	dt->do_ops->do_write_lock(env, dt, role);
}

static inline void dt_read_unlock(const struct lu_env *env,
				struct dt_object *dt)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_read_unlock);
	dt->do_ops->do_read_unlock(env, dt);
}

static inline void dt_write_unlock(const struct lu_env *env,
				struct dt_object *dt)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_write_unlock);
	dt->do_ops->do_write_unlock(env, dt);
}

static inline int dt_write_locked(const struct lu_env *env,
				  struct dt_object *dt)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_write_locked);
	return dt->do_ops->do_write_locked(env, dt);
}

static inline bool dt_object_stale(struct dt_object *dt)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);

	if (!dt->do_ops->do_check_stale)
		return false;

	return dt->do_ops->do_check_stale(dt);
}

static inline int dt_declare_attr_get(const struct lu_env *env,
				      struct dt_object *dt)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_attr_get);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_ATTR_GET))
		return cfs_fail_err;

	return dt->do_ops->do_declare_attr_get(env, dt);
}

static inline int dt_attr_get(const struct lu_env *env, struct dt_object *dt,
			      struct lu_attr *la)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_attr_get);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_ATTR_GET))
		return cfs_fail_err;

	return dt->do_ops->do_attr_get(env, dt, la);
}

static inline int dt_declare_attr_set(const struct lu_env *env,
				      struct dt_object *dt,
				      const struct lu_attr *la,
				      struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_attr_set);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_ATTR_SET))
		return cfs_fail_err;

	return dt->do_ops->do_declare_attr_set(env, dt, la, th);
}

static inline int dt_attr_set(const struct lu_env *env, struct dt_object *dt,
			      const struct lu_attr *la, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_attr_set);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_ATTR_SET))
		return cfs_fail_err;

	return dt->do_ops->do_attr_set(env, dt, la, th);
}

static inline int dt_declare_ref_add(const struct lu_env *env,
				     struct dt_object *dt, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_ref_add);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_REF_ADD))
		return cfs_fail_err;

	return dt->do_ops->do_declare_ref_add(env, dt, th);
}

static inline int dt_ref_add(const struct lu_env *env,
			     struct dt_object *dt, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_ref_add);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_REF_ADD))
		return cfs_fail_err;

	return dt->do_ops->do_ref_add(env, dt, th);
}

static inline int dt_declare_ref_del(const struct lu_env *env,
				     struct dt_object *dt, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_ref_del);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_REF_DEL))
		return cfs_fail_err;

	return dt->do_ops->do_declare_ref_del(env, dt, th);
}

static inline int dt_ref_del(const struct lu_env *env,
			     struct dt_object *dt, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_ref_del);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_REF_DEL))
		return cfs_fail_err;

	return dt->do_ops->do_ref_del(env, dt, th);
}

static inline int dt_bufs_get(const struct lu_env *env, struct dt_object *d,
			      struct niobuf_remote *rnb,
			      struct niobuf_local *lnb, int maxlnb,
			      enum dt_bufs_type rw)
{
	LASSERT(d);
	LASSERT(d->do_body_ops);
	LASSERT(d->do_body_ops->dbo_bufs_get);
	return d->do_body_ops->dbo_bufs_get(env, d, rnb->rnb_offset,
					    rnb->rnb_len, lnb, maxlnb, rw);
}

static inline int dt_bufs_put(const struct lu_env *env, struct dt_object *d,
			      struct niobuf_local *lnb, int n)
{
	LASSERT(d);
	LASSERT(d->do_body_ops);
	LASSERT(d->do_body_ops->dbo_bufs_put);
	return d->do_body_ops->dbo_bufs_put(env, d, lnb, n);
}

static inline int dt_write_prep(const struct lu_env *env, struct dt_object *d,
				struct niobuf_local *lnb, int n)
{
	LASSERT(d);
	LASSERT(d->do_body_ops);
	LASSERT(d->do_body_ops->dbo_write_prep);
	return d->do_body_ops->dbo_write_prep(env, d, lnb, n);
}

static inline int dt_declare_write_commit(const struct lu_env *env,
					  struct dt_object *d,
					  struct niobuf_local *lnb,
					  int n, struct thandle *th)
{
	LASSERT(d);
	LASSERT(d->do_body_ops);
	LASSERT(d->do_body_ops->dbo_declare_write_commit);
	LASSERT(th);
	return d->do_body_ops->dbo_declare_write_commit(env, d, lnb, n, th);
}


static inline int dt_write_commit(const struct lu_env *env,
				  struct dt_object *d, struct niobuf_local *lnb,
				  int n, struct thandle *th, __u64 size)
{
	LASSERT(d);
	LASSERT(d->do_body_ops);
	LASSERT(d->do_body_ops->dbo_write_commit);
	return d->do_body_ops->dbo_write_commit(env, d, lnb, n, th, size);
}

static inline int dt_read_prep(const struct lu_env *env, struct dt_object *d,
			       struct niobuf_local *lnb, int n)
{
	LASSERT(d);
	LASSERT(d->do_body_ops);
	LASSERT(d->do_body_ops->dbo_read_prep);
	return d->do_body_ops->dbo_read_prep(env, d, lnb, n);
}

static inline int dt_declare_write(const struct lu_env *env,
				   struct dt_object *dt,
				   const struct lu_buf *buf, loff_t pos,
				   struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_declare_write);
	return dt->do_body_ops->dbo_declare_write(env, dt, buf, pos, th);
}

static inline ssize_t dt_write(const struct lu_env *env, struct dt_object *dt,
			       const struct lu_buf *buf, loff_t *pos,
			       struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_write);
	return dt->do_body_ops->dbo_write(env, dt, buf, pos, th);
}

static inline int dt_declare_punch(const struct lu_env *env,
				   struct dt_object *dt, __u64 start,
				   __u64 end, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_declare_punch);
	return dt->do_body_ops->dbo_declare_punch(env, dt, start, end, th);
}

static inline int dt_punch(const struct lu_env *env, struct dt_object *dt,
			   __u64 start, __u64 end, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_punch);
	return dt->do_body_ops->dbo_punch(env, dt, start, end, th);
}

static inline int dt_ladvise(const struct lu_env *env, struct dt_object *dt,
			     __u64 start, __u64 end, int advice)
{
	LASSERT(dt);
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_ladvise);
	return dt->do_body_ops->dbo_ladvise(env, dt, start, end, advice);
}

static inline int dt_declare_fallocate(const struct lu_env *env,
				       struct dt_object *dt, __u64 start,
				       __u64 end, int mode, struct thandle *th)
{
	LASSERT(dt);
	if (!dt->do_body_ops)
		return -EOPNOTSUPP;
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_declare_fallocate);
	return dt->do_body_ops->dbo_declare_fallocate(env, dt, start, end,
						      mode, th);
}

static inline int dt_falloc(const struct lu_env *env, struct dt_object *dt,
			      __u64 start, __u64 end, int mode,
			      struct thandle *th)
{
	LASSERT(dt);
	if (!dt->do_body_ops)
		return -EOPNOTSUPP;
	LASSERT(dt->do_body_ops);
	LASSERT(dt->do_body_ops->dbo_fallocate);
	return dt->do_body_ops->dbo_fallocate(env, dt, start, end, mode, th);
}

static inline int dt_fiemap_get(const struct lu_env *env, struct dt_object *d,
				struct fiemap *fm)
{
	LASSERT(d);
	if (d->do_body_ops == NULL)
		return -EPROTO;
	if (d->do_body_ops->dbo_fiemap_get == NULL)
		return -EOPNOTSUPP;
	return d->do_body_ops->dbo_fiemap_get(env, d, fm);
}

static inline loff_t dt_lseek(const struct lu_env *env, struct dt_object *d,
			      loff_t offset, int whence)
{
	LASSERT(d);
	if (d->do_body_ops == NULL)
		return -EPROTO;
	if (d->do_body_ops->dbo_lseek == NULL)
		return -EOPNOTSUPP;
	return d->do_body_ops->dbo_lseek(env, d, offset, whence);
}

static inline int dt_statfs_info(const struct lu_env *env,
				 struct dt_device *dev,
				struct obd_statfs *osfs,
				struct obd_statfs_info *info)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_statfs);
	return dev->dd_ops->dt_statfs(env, dev, osfs, info);
}

static inline int dt_statfs(const struct lu_env *env, struct dt_device *dev,
			    struct obd_statfs *osfs)
{
	return dt_statfs_info(env, dev, osfs, NULL);
}

static inline int dt_root_get(const struct lu_env *env, struct dt_device *dev,
			      struct lu_fid *f)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_root_get);
	return dev->dd_ops->dt_root_get(env, dev, f);
}

static inline void dt_conf_get(const struct lu_env *env,
			       const struct dt_device *dev,
			       struct dt_device_param *param)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_conf_get);
	return dev->dd_ops->dt_conf_get(env, dev, param);
}

static inline struct vfsmount *dt_mnt_get(const struct dt_device *dev)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	if (dev->dd_ops->dt_mnt_get)
		return dev->dd_ops->dt_mnt_get(dev);

	return ERR_PTR(-EOPNOTSUPP);
}

static inline int dt_sync(const struct lu_env *env, struct dt_device *dev)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_sync);
	return dev->dd_ops->dt_sync(env, dev);
}

static inline int dt_ro(const struct lu_env *env, struct dt_device *dev)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_ro);
	return dev->dd_ops->dt_ro(env, dev);
}

static inline int dt_declare_insert(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_rec *rec,
				    const struct dt_key *key,
				    struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_index_ops);
	LASSERT(dt->do_index_ops->dio_declare_insert);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_INSERT))
		return cfs_fail_err;

	return dt->do_index_ops->dio_declare_insert(env, dt, rec, key, th);
}

static inline int dt_insert(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_rec *rec,
			    const struct dt_key *key,
			    struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_index_ops);
	LASSERT(dt->do_index_ops->dio_insert);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_INSERT))
		return cfs_fail_err;

	return dt->do_index_ops->dio_insert(env, dt, rec, key, th);
}

static inline int dt_declare_xattr_del(const struct lu_env *env,
				       struct dt_object *dt,
				       const char *name,
				       struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_xattr_del);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_XATTR_DEL))
		return cfs_fail_err;

	return dt->do_ops->do_declare_xattr_del(env, dt, name, th);
}

static inline int dt_xattr_del(const struct lu_env *env,
			       struct dt_object *dt, const char *name,
			       struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_xattr_del);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_XATTR_DEL))
		return cfs_fail_err;

	return dt->do_ops->do_xattr_del(env, dt, name, th);
}

static inline int dt_declare_xattr_set(const struct lu_env *env,
				      struct dt_object *dt,
				      const struct lu_buf *buf,
				      const char *name, int fl,
				      struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_xattr_set);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_XATTR_SET))
		return cfs_fail_err;

	return dt->do_ops->do_declare_xattr_set(env, dt, buf, name, fl, th);
}

static inline int dt_xattr_set(const struct lu_env *env,
			       struct dt_object *dt, const struct lu_buf *buf,
			       const char *name, int fl, struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_xattr_set);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_XATTR_SET))
		return cfs_fail_err;

	return dt->do_ops->do_xattr_set(env, dt, buf, name, fl, th);
}

static inline int dt_declare_xattr_get(const struct lu_env *env,
				       struct dt_object *dt,
				       struct lu_buf *buf,
				       const char *name)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_declare_xattr_get);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_XATTR_GET))
		return cfs_fail_err;

	return dt->do_ops->do_declare_xattr_get(env, dt, buf, name);
}

static inline int dt_xattr_get(const struct lu_env *env,
			       struct dt_object *dt, struct lu_buf *buf,
			       const char *name)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_xattr_get);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_XATTR_GET))
		return cfs_fail_err;

	return dt->do_ops->do_xattr_get(env, dt, buf, name);
}

static inline int dt_xattr_list(const struct lu_env *env, struct dt_object *dt,
				const struct lu_buf *buf)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);
	LASSERT(dt->do_ops->do_xattr_list);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_XATTR_LIST))
		return cfs_fail_err;

	return dt->do_ops->do_xattr_list(env, dt, buf);
}

static inline int dt_invalidate(const struct lu_env *env, struct dt_object *dt)
{
	LASSERT(dt);
	LASSERT(dt->do_ops);

	if (!dt->do_ops->do_invalidate)
		return 0;

	return dt->do_ops->do_invalidate(env, dt);
}

static inline int dt_declare_delete(const struct lu_env *env,
				    struct dt_object *dt,
				    const struct dt_key *key,
				    struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_index_ops);
	LASSERT(dt->do_index_ops->dio_declare_delete);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DECLARE_DELETE))
		return cfs_fail_err;

	return dt->do_index_ops->dio_declare_delete(env, dt, key, th);
}

static inline int dt_delete(const struct lu_env *env,
			    struct dt_object *dt,
			    const struct dt_key *key,
			    struct thandle *th)
{
	LASSERT(dt);
	LASSERT(dt->do_index_ops);
	LASSERT(dt->do_index_ops->dio_delete);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_DELETE))
		return cfs_fail_err;

	return dt->do_index_ops->dio_delete(env, dt, key, th);
}

static inline int dt_commit_async(const struct lu_env *env,
				  struct dt_device *dev)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_commit_async);
	return dev->dd_ops->dt_commit_async(env, dev);
}

static inline int dt_reserve_or_free_quota(const struct lu_env *env,
					   struct dt_device *dev,
					   struct lquota_id_info *qi)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	LASSERT(dev->dd_ops->dt_reserve_or_free_quota);
	return dev->dd_ops->dt_reserve_or_free_quota(env, dev, qi);
}

static inline int dt_lookup(const struct lu_env *env,
			    struct dt_object *dt,
			    struct dt_rec *rec,
			    const struct dt_key *key)
{
	int ret;

	LASSERT(dt);
	LASSERT(dt->do_index_ops);
	LASSERT(dt->do_index_ops->dio_lookup);

	if (CFS_FAULT_CHECK(OBD_FAIL_DT_LOOKUP))
		return cfs_fail_err;

	ret = dt->do_index_ops->dio_lookup(env, dt, rec, key);
	if (ret > 0)
		ret = 0;
	else if (ret == 0)
		ret = -ENOENT;
	return ret;
}

static inline int dt_declare_layout_change(const struct lu_env *env,
					   struct dt_object *o,
					   struct md_layout_change *mlc,
					   struct thandle *th)
{
	LASSERT(o);
	LASSERT(o->do_ops);
	LASSERT(o->do_ops->do_declare_layout_change);
	return o->do_ops->do_declare_layout_change(env, o, mlc, th);
}

static inline int dt_layout_change(const struct lu_env *env,
				   struct dt_object *o,
				   struct md_layout_change *mlc,
				   struct thandle *th)
{
	LASSERT(o);
	LASSERT(o->do_ops);
	LASSERT(o->do_ops->do_layout_change);
	return o->do_ops->do_layout_change(env, o, mlc, th);
}

static inline int dt_layout_pccro_check(const struct lu_env *env,
					struct dt_object *o,
					struct md_layout_change *mlc)
{
	LASSERT(o);
	LASSERT(o->do_ops);
	LASSERT(o->do_ops->do_layout_pccro_check);
	return o->do_ops->do_layout_pccro_check(env, o, mlc);
}

struct dt_find_hint {
	struct lu_fid        *dfh_fid;
	struct dt_device     *dfh_dt;
	struct dt_object     *dfh_o;
};

struct dt_insert_rec {
	union {
		const struct lu_fid	*rec_fid;
		void			*rec_data;
	};
	union {
		struct {
			__u32		 rec_type;
			__u32		 rec_padding;
		};
		__u64			 rec_misc;
	};
};

struct dt_thread_info {
	char                     dti_buf[DT_MAX_PATH];
	struct dt_find_hint      dti_dfh;
	struct lu_attr           dti_attr;
	struct lu_fid            dti_fid;
	struct dt_object_format  dti_dof;
	struct lustre_mdt_attrs  dti_lma;
	struct lu_buf            dti_lb;
	struct lu_object_conf	 dti_conf;
	loff_t                   dti_off;
	struct dt_insert_rec	 dti_dt_rec;
};

extern struct lu_context_key dt_key;

static inline struct dt_thread_info *dt_info(const struct lu_env *env)
{
	struct dt_thread_info *dti;

	dti = lu_context_key_get(&env->le_ctx, &dt_key);
	LASSERT(dti);
	return dti;
}

int dt_global_init(void);
void dt_global_fini(void);
int dt_tunables_init(struct dt_device *dt, struct obd_type *type,
		     const char *name, struct ldebugfs_vars *list);
int dt_tunables_fini(struct dt_device *dt);

#ifdef CONFIG_PROC_FS
int lprocfs_dt_blksize_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_kbytestotal_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_kbytesfree_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_kbytesavail_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_filestotal_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_filesfree_seq_show(struct seq_file *m, void *v);
#endif /* CONFIG_PROC_FS */

#endif /* __LUSTRE_DT_OBJECT_H */
