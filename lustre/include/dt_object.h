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

#ifndef __LUSTRE_DT_OBJECT_H
#define __LUSTRE_DT_OBJECT_H

/** \defgroup dt dt
 * Sub-class of lu_object with methods common for "data" objects in OST stack.
 *
 * Data objects behave like regular files: you can read/write them, get and
 * set their attributes. Implementation of dt interface is supposed to
 * implement some form of garbage collection, normally reference counting
 * (nlink) based one.
 *
 * Examples: osd (lustre/osd) is an implementation of dt interface.
 * @{
 */

#include <obd_support.h>
/*
 * super-class definitions.
 */
#include <lu_object.h>

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
	unsigned	   ddp_max_name_len;
	unsigned	   ddp_max_nlink;
	unsigned	   ddp_symlink_max;
	mntopt_t	   ddp_mntopts;
	unsigned	   ddp_max_ea_size;
	unsigned	   ddp_mount_type;
	unsigned long long ddp_maxbytes;
	/* per-inode space consumption */
	short		   ddp_inodespace;
	/* maximum number of blocks in an extent */
	unsigned	   ddp_max_extent_blks;
	/* per-extent insertion overhead to be used by client for grant
	 * calculation */
	unsigned int	   ddp_extent_tax;
	unsigned int	   ddp_brw_size;	/* optimal RPC size */
	/* T10PI checksum type, zero if not supported */
	enum cksum_types   ddp_t10_cksum_type;
	bool		   ddp_has_lseek_data_hole;
};

/**
 * Per-transaction commit callback function
 */
struct dt_txn_commit_cb;
typedef void (*dt_cb_t)(struct lu_env *env, struct thandle *th,
                        struct dt_txn_commit_cb *cb, int err);
/**
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

/**
 * Operations on dt device.
 */
struct dt_device_operations {
        /**
         * Return device-wide statistics.
	 *
	 * Return device-wide stats including block size, total and
	 * free blocks, total and free objects, etc. See struct obd_statfs
	 * for the details.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 * \param[out] osfs	stats information
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
         */
        int   (*dt_statfs)(const struct lu_env *env,
			   struct dt_device *dev,
			   struct obd_statfs *osfs,
			   struct obd_statfs_info *info);

        /**
	 * Create transaction.
	 *
	 * Create in-memory structure representing the transaction for the
	 * caller. The structure returned will be used by the calling thread
	 * to specify the transaction the updates belong to. Once created
	 * successfully ->dt_trans_stop() must be called in any case (with
	 * ->dt_trans_start() and updates or not) so that the transaction
	 * handle and other resources can be released by the layers below.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 *
	 * \retval pointer to handle	if creation succeeds
	 * \retval ERR_PTR(errno)	if creation fails
         */
        struct thandle *(*dt_trans_create)(const struct lu_env *env,
                                           struct dt_device *dev);

        /**
	 * Start transaction.
	 *
	 * Start the transaction. The transaction described by \a th can be
	 * started only once. Another start is considered as an error.
	 * A thread is not supposed to start a transaction while another
	 * transaction isn't closed by the thread (though multiple handles
	 * can be created). The caller should start the transaction once
	 * all possible updates are declared (see the ->do_declare_* methods
	 * below) and all the needed resources are reserved.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
         */
        int   (*dt_trans_start)(const struct lu_env *env,
				struct dt_device *dev,
				struct thandle *th);

	/**
	 * Stop transaction.
	 *
	 * Once stopped the transaction described by \a th is complete (all
	 * the needed updates are applied) and further processing such as
	 * flushing to disk, sending to another target, etc, is handled by
	 * lower layers. The caller can't access this transaction by the
	 * handle anymore (except from the commit callbacks, see below).
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*dt_trans_stop)(const struct lu_env *env,
			       struct dt_device *dev,
			       struct thandle *th);

        /**
         * Add commit callback to the transaction.
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
	 * \param[in] th	transaction handle
	 * \param[in] dcb	commit callback description
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
         */
        int   (*dt_trans_cb_add)(struct thandle *th,
                                 struct dt_txn_commit_cb *dcb);

        /**
	 * Return FID of root index object.
	 *
	 * Return the FID of the root object in the filesystem. This object
	 * is usually provided as a bootstrap point by a disk filesystem.
	 * This is up to the implementation which FID to use, though
	 * [FID_SEQ_ROOT:1:0] is reserved for this purpose.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 * \param[out] fid	FID of the root object
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
         */
        int   (*dt_root_get)(const struct lu_env *env,
			     struct dt_device *dev,
			     struct lu_fid *f);

        /**
         * Return device configuration data.
	 *
	 * Return device (disk fs, actually) specific configuration.
	 * The configuration isn't subject to change at runtime.
	 * See struct dt_device_param for the details.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 * \param[out] param	configuration parameters
         */
        void  (*dt_conf_get)(const struct lu_env *env,
                             const struct dt_device *dev,
                             struct dt_device_param *param);

	/**
	 * Return device's super block.
	 *
	 * \param[in] dev	dt device
	 */
	struct super_block *(*dt_mnt_sb_get)(const struct dt_device *dev);

	/**
	 * Sync the device.
	 *
	 * Sync all the cached state (dirty buffers, pages, etc) to the
	 * persistent storage. The method returns control once the sync is
	 * complete. This operation may incur significant I/O to disk and
	 * should be reserved for cases where a global sync is strictly
	 * necessary.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*dt_sync)(const struct lu_env *env,
			 struct dt_device *dev);

	/**
	 * Make device read-only.
	 *
	 * Prevent new modifications to the device. This is a very specific
	 * state where all the changes are accepted successfully and the
	 * commit callbacks are called, but persistent state never changes.
	 * Used only in the tests to simulate power-off scenario.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*dt_ro)(const struct lu_env *env,
		       struct dt_device *dev);

	/**
	 * Start transaction commit asynchronously.
	 *

	 * Provide a hint to the underlying filesystem that it should start
	 * committing soon. The control returns immediately. It's up to the
	 * layer implementing the method how soon to start committing. Usually
	 * this should be throttled to some extent, otherwise the number of
	 * aggregated transaction goes too high causing performance drop.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dev	dt device
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
         int   (*dt_commit_async)(const struct lu_env *env,
                                  struct dt_device *dev);
};

struct dt_index_features {
        /** required feature flags from enum dt_index_flags */
        __u32 dif_flags;
        /** minimal required key size */
        size_t dif_keysize_min;
        /** maximal required key size, 0 if no limit */
        size_t dif_keysize_max;
        /** minimal required record size */
        size_t dif_recsize_min;
        /** maximal required record size, 0 if no limit */
        size_t dif_recsize_max;
        /** pointer size for record */
        size_t dif_ptrsize;
};

enum dt_index_flags {
	/** index supports variable sized keys */
	DT_IND_VARKEY = BIT(0),
	/** index supports variable sized records */
	DT_IND_VARREC = BIT(1),
	/** index can be modified */
	DT_IND_UPDATE = BIT(2),
	/** index supports records with non-unique (duplicate) keys */
	DT_IND_NONUNQ = BIT(3),
	/**
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

/**
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

/**
 * This is a general purpose dt allocation hint.
 * It now contains the parent object.
 * It can contain any allocation hint in the future.
 */
struct dt_allocation_hint {
	struct dt_object	*dah_parent;
	const void		*dah_eadata;
	int			dah_eadata_len;
	int			dah_acl_len;
	__u32			dah_mode;
	int			dah_append_stripes;
	bool			dah_can_block;
	char			*dah_append_pool;
};

/**
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

/**
 * object format specifier.
 */
struct dt_object_format {
        /** type for dt object */
        enum dt_format_type dof_type;
        union {
                struct dof_regular {
			int striped;
                } dof_reg;
                struct dof_dir {
                } dof_dir;
                struct dof_node {
                } dof_node;
                /**
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

/**
 * A dt_object provides common operations to create and destroy
 * objects and to manage regular and extended attributes.
 */
struct dt_object_operations {
	/**
	 * Get read lock on object.
	 *
	 * Read lock is compatible with other read locks, so it's shared.
	 * Read lock is not compatible with write lock which is exclusive.
	 * The lock is blocking and can't be used from an interrupt context.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object to lock for reading
	 * \param[in] role	a hint to debug locks (see kernel's mutexes)
	 */
	void  (*do_read_lock)(const struct lu_env *env,
			      struct dt_object *dt,
			      unsigned role);

	/*
	 * Get write lock on object.
	 *
	 * Write lock is exclusive and cannot be shared. The lock is blocking
	 * and can't be used from an interrupt context.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object to lock for writing
	 * \param[in] role	a hint to debug locks (see kernel's mutexes)
	 *
	 */
	void  (*do_write_lock)(const struct lu_env *env,
			       struct dt_object *dt,
			       unsigned role);

	/**
	 * Release read lock.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 */
        void  (*do_read_unlock)(const struct lu_env *env,
                                struct dt_object *dt);

	/**
	 * Release write lock.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 */
        void  (*do_write_unlock)(const struct lu_env *env,
                                 struct dt_object *dt);

	/**
	 * Check whether write lock is held.
	 *
	 * The caller can learn whether write lock is held on the object
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 *
	 * \retval 0		no write lock
	 * \retval 1		write lock is held
	 */
        int  (*do_write_locked)(const struct lu_env *env,
                                struct dt_object *dt);

	/**
	 * Declare intention to request reqular attributes.
	 *
	 * Notity the underlying filesystem that the caller may request regular
	 * attributes with ->do_attr_get() soon. This allows OSD to implement
	 * prefetching logic in an object-oriented manner. The implementation
	 * can be noop. This method should avoid expensive delays such as
	 * waiting on disk I/O, otherwise the goal of enabling a performance
	 * optimization would be defeated.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_declare_attr_get)(const struct lu_env *env,
				     struct dt_object *dt);

	/**
	 * Return regular attributes.
	 *
	 * The object must exist. Currently all the attributes should be
	 * returned, but in the future this can be improved so that only
	 * a selected set is returned. This can improve performance as in
	 * some cases attributes are stored in different places and
	 * getting them all can be an iterative and expensive process.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] attr	attributes to fill
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_attr_get)(const struct lu_env *env,
			     struct dt_object *dt,
			     struct lu_attr *attr);

	/**
	 * Declare intention to change regular object's attributes.
	 *
	 * Notify the underlying filesystem that the regular attributes may
	 * change in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it. Note that
	 * the la_valid field of \a attr specifies which attributes will change.
	 * The object need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] attr	attributes to change specified in attr.la_valid
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
         */
        int   (*do_declare_attr_set)(const struct lu_env *env,
                                     struct dt_object *dt,
                                     const struct lu_attr *attr,
				     struct thandle *th);

	/**
	 * Change regular attributes.
	 *
	 * Change regular attributes in the given transaction. Note only
	 * attributes flagged by attr.la_valid change. The object must
	 * exist. If the layer implementing this method is responsible for
	 * quota, then the method should maintain object accounting for the
	 * given credentials when la_uid/la_gid changes.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] attr	new attributes to apply
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int   (*do_attr_set)(const struct lu_env *env,
                             struct dt_object *dt,
                             const struct lu_attr *attr,
			     struct thandle *th);

	/**
	 * Declare intention to request extented attribute.
	 *
	 * Notify the underlying filesystem that the caller may request extended
	 * attribute with ->do_xattr_get() soon. This allows OSD to implement
	 * prefetching logic in an object-oriented manner. The implementation
	 * can be noop. This method should avoid expensive delays such as
	 * waiting on disk I/O, otherwise the goal of enabling a performance
	 * optimization would be defeated.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] buf	unused, may be removed in the future
	 * \param[in] name	name of the extended attribute
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_declare_xattr_get)(const struct lu_env *env,
				      struct dt_object *dt,
				      struct lu_buf *buf,
				      const char *name);

	/**
	 * Return a value of an extended attribute.
	 *
	 * The object must exist. If the buffer is NULL, then the method
	 * must return the size of the value.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] buf	buffer in which to store the value
	 * \param[in] name	name of the extended attribute
	 *
	 * \retval 0		on success
	 * \retval -ERANGE	if \a buf is too small
	 * \retval negative	negated errno on error
	 * \retval positive	value's size if \a buf is NULL or has zero size
	 */
	int   (*do_xattr_get)(const struct lu_env *env,
			      struct dt_object *dt,
			      struct lu_buf *buf,
			      const char *name);

	/**
	 * Declare intention to change an extended attribute.
	 *
	 * Notify the underlying filesystem that the extended attribute may
	 * change in this transaction.  This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it. The object
	 * need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] buf	buffer storing new value of the attribute
	 * \param[in] name	name of the attribute
	 * \param[in] fl	LU_XATTR_CREATE - fail if EA exists
	 *			LU_XATTR_REPLACE - fail if EA doesn't exist
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
         */
	int   (*do_declare_xattr_set)(const struct lu_env *env,
				      struct dt_object *dt,
				      const struct lu_buf *buf,
				      const char *name,
				      int fl,
				      struct thandle *th);

	/**
	 * Set an extended attribute.
	 *
	 * Change or replace the specified extended attribute (EA).
	 * The flags passed in \a fl dictate whether the EA is to be
	 * created or replaced, as follows.
	 *   LU_XATTR_CREATE - fail if EA exists
	 *   LU_XATTR_REPLACE - fail if EA doesn't exist
	 * The object must exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] buf	buffer storing new value of the attribute
	 * \param[in] name	name of the attribute
	 * \param[in] fl	flags indicating EA creation or replacement
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_xattr_set)(const struct lu_env *env,
			      struct dt_object *dt,
			      const struct lu_buf *buf,
			      const char *name,
			      int fl,
			      struct thandle *th);

	/**
	 * Declare intention to delete an extended attribute.
	 *
	 * Notify the underlying filesystem that the extended attribute may
	 * be deleted in this transaction. This enables the layer below to
	 * prepare resources (e.g. journal credits in ext4).  This method
	 * should be called between creating the transaction and starting it.
	 * The object need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] name	name of the attribute
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_declare_xattr_del)(const struct lu_env *env,
				      struct dt_object *dt,
				      const char *name,
				      struct thandle *th);

	/**
	 * Delete an extended attribute.
	 *
	 * This method deletes the specified extended attribute. The object
	 * must exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] name	name of the attribute
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_xattr_del)(const struct lu_env *env,
			      struct dt_object *dt,
			      const char *name,
			      struct thandle *th);

	/**
	 * Return a list of the extended attributes.
	 *
	 * Fills the passed buffer with a list of the extended attributes
	 * found in the object. The names are separated with '\0'.
	 * The object must exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] buf	buffer to put the list in
	 *
	 * \retval positive	bytes used/required in the buffer
	 * \retval negative	negated errno on error
         */
	int   (*do_xattr_list)(const struct lu_env *env,
			       struct dt_object *dt,
			       const struct lu_buf *buf);

	/**
	 * Prepare allocation hint for a new object.
	 *
	 * This method is used by the caller to inform OSD of the parent-child
	 * relationship between two objects and enable efficient object
	 * allocation. Filled allocation hint will be passed to ->do_create()
	 * later.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[out] ah	allocation hint
	 * \param[in] parent	parent object (can be NULL)
	 * \param[in] child	child object
	 * \param[in] _mode	type of the child object
	 */
	void  (*do_ah_init)(const struct lu_env *env,
			    struct dt_allocation_hint *ah,
			    struct dt_object *parent,
			    struct dt_object *child,
			    umode_t mode);

	/**
	 * Declare intention to create a new object.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] attr	attributes of the new object
	 * \param[in] hint	allocation hint
	 * \param[in] dof	object format
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int   (*do_declare_create)(const struct lu_env *env,
                                   struct dt_object *dt,
                                   struct lu_attr *attr,
                                   struct dt_allocation_hint *hint,
                                   struct dt_object_format *dof,
                                   struct thandle *th);

	/**
	 * Create new object.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] attr	attributes of the new object
	 * \param[in] hint	allocation hint
	 * \param[in] dof	object format
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_create)(const struct lu_env *env,
			   struct dt_object *dt,
                           struct lu_attr *attr,
                           struct dt_allocation_hint *hint,
                           struct dt_object_format *dof,
                           struct thandle *th);

	/**
	 * Declare intention to destroy an object.
	 *
	 * Notify the underlying filesystem that the object may be destroyed
	 * in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4).  This method should be
	 * called between creating the transaction and starting it. The object
	 * need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int   (*do_declare_destroy)(const struct lu_env *env,
                                    struct dt_object *dt,
                                    struct thandle *th);

	/**
	 * Destroy an object.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_destroy)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct thandle *th);

	/**
	 * Try object as an index.
	 *
         * Announce that this object is going to be used as an index. This
	 * operation checks that object supports indexing operations and
         * installs appropriate dt_index_operations vector on success.
         * Also probes for features. Operation is successful if all required
	 * features are supported. It's not possible to access the object
	 * with index methods before ->do_index_try() returns success.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] feat	index features
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int   (*do_index_try)(const struct lu_env *env,
                              struct dt_object *dt,
                              const struct dt_index_features *feat);

	/**
	 * Declare intention to increment nlink count.
	 *
	 * Notify the underlying filesystem that the nlink regular attribute
	 * be changed in this transaction. This enables the layer below to
	 * prepare resources (e.g. journal credits in ext4).  This method
	 * should be called between creating the transaction and starting it.
	 * The object need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_declare_ref_add)(const struct lu_env *env,
				    struct dt_object *dt,
				    struct thandle *th);

	/**
	 * Increment nlink.
	 *
	 * Increment nlink (from the regular attributes set) in the given
	 * transaction. Note the absolute limit for nlink should be learnt
	 * from struct dt_device_param::ddp_max_nlink. The object must exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int   (*do_ref_add)(const struct lu_env *env,
                            struct dt_object *dt, struct thandle *th);

	/**
	 * Declare intention to decrement nlink count.
	 *
	 * Notify the underlying filesystem that the nlink regular attribute
	 * be changed in this transaction. This enables the layer below to
	 * prepare resources (e.g. journal credits in ext4).  This method
	 * should be called between creating the transaction and starting it.
	 * The object need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_declare_ref_del)(const struct lu_env *env,
				    struct dt_object *dt,
				    struct thandle *th);

	/**
	 * Decrement nlink.
	 *
	 * Decrement nlink (from the regular attributes set) in the given
	 * transaction. The object must exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_ref_del)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct thandle *th);

	/**
	 * Sync obect.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] start	start of the range to sync
	 * \param[in] end	end of the range to sync
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*do_object_sync)(const struct lu_env *env, struct dt_object *obj,
			      __u64 start, __u64 end);

	/**
	 * Lock object.
	 *
	 * Lock object(s) using Distributed Lock Manager (LDLM).
	 *
	 * Get LDLM locks for the object. Currently used to lock "remote"
	 * objects in DNE configuration - a service running on MDTx needs
	 * to lock an object on MDTy.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] lh	lock handle, sometimes used, sometimes not
	 * \param[in] einfo	ldlm callbacks, locking type and mode
	 * \param[out] einfo	private data to be passed to unlock later
	 * \param[in] policy	inodebits data
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*do_object_lock)(const struct lu_env *env, struct dt_object *dt,
			      struct lustre_handle *lh,
			      struct ldlm_enqueue_info *einfo,
			      union ldlm_policy_data *policy);

	/**
	 * Unlock object.
	 *
	 * Release LDLM lock(s) granted with ->do_object_lock().
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] einfo	lock handles, from ->do_object_lock()
	 * \param[in] policy	inodebits data
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*do_object_unlock)(const struct lu_env *env,
				struct dt_object *dt,
				struct ldlm_enqueue_info *einfo,
				union ldlm_policy_data *policy);

	/**
	 * Invalidate attribute cache.
	 *
	 * This method invalidate attribute cache of the object, which is on OSP
	 * only.
	 *
	 * \param[in] env	execution envionment for this thread
	 * \param[in] dt	object
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*do_invalidate)(const struct lu_env *env, struct dt_object *dt);

	/**
	 * Check object stale state.
	 *
	 * OSP only.
	 *
	 * \param[in] dt	object
	 *
	 * \retval true		for stale object
	 * \retval false	for not stale object
	 */
	bool (*do_check_stale)(struct dt_object *dt);

	/**
	 * Declare intention to instaintiate extended layout component.
	 *
	 * \param[in] env	execution environment
	 * \param[in] dt	DT object
	 * \param[in] layout	data structure to describe the changes to
	 *			the DT object's layout
	 * \param[in] buf	buffer containing client's lovea or empty
	 *
	 * \retval 0		success
	 * \retval -ne		error code
	 */
	int (*do_declare_layout_change)(const struct lu_env *env,
					struct dt_object *dt,
					struct md_layout_change *mlc,
					struct thandle *th);

	/**
	 * Client is trying to write to un-instantiated layout component.
	 *
	 * \param[in] env	execution environment
	 * \param[in] dt	DT object
	 * \param[in] layout	data structure to describe the changes to
	 *			the DT object's layout
	 * \param[in] buf	buffer containing client's lovea or empty
	 *
	 * \retval 0		success
	 * \retval -ne		error code
	 */
	int (*do_layout_change)(const struct lu_env *env, struct dt_object *dt,
				struct md_layout_change *mlc,
				struct thandle *th);
};

enum dt_bufs_type {
	DT_BUFS_TYPE_READ	= 0x0000,
	DT_BUFS_TYPE_WRITE	= 0x0001,
	DT_BUFS_TYPE_READAHEAD	= 0x0002,
	DT_BUFS_TYPE_LOCAL	= 0x0004,
};

/**
 * Per-dt-object operations on "file body" - unstructure raw data.
 */
struct dt_body_operations {
	/**
	 * Read data.
	 *
	 * Read unstructured data from an existing regular object.
	 * Only data before attr.la_size is returned.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] buf	buffer (including size) to copy data in
	 * \param[in] pos	position in the object to start
	 * \param[out] pos	original value of \a pos + bytes returned
	 *
	 * \retval positive	bytes read on success
	 * \retval negative	negated errno on error
	 */
	ssize_t (*dbo_read)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct lu_buf *buf,
			    loff_t *pos);

	/**
	 * Declare intention to write data to object.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] buf	buffer (including size) to copy data from
	 * \param[in] pos	position in the object to start
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	ssize_t (*dbo_declare_write)(const struct lu_env *env,
				     struct dt_object *dt,
				     const struct lu_buf *buf,
				     loff_t pos,
				     struct thandle *th);

	/**
	 * Write unstructured data to regular existing object.
	 *
	 * The method allocates space and puts data in. Also, the method should
	 * maintain attr.la_size properly. Partial writes are possible.
	 *
	 * If the layer implementing this method is responsible for quota,
	 * then the method should maintain space accounting for the given
	 * credentials.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] buf	buffer (including size) to copy data from
	 * \param[in] pos	position in the object to start
	 * \param[out] pos	\a pos + bytes written
	 * \param[in] th	transaction handle
	 *
	 * \retval positive	bytes written on success
	 * \retval negative	negated errno on error
	 */
	ssize_t (*dbo_write)(const struct lu_env *env,
			     struct dt_object *dt,
			     const struct lu_buf *buf,
			     loff_t *pos,
			     struct thandle *th);

	/**
	 * Return buffers for data.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] pos	position in the object to start
	 * \param[in] len	size of region in bytes
	 * \param[out] lb	array of descriptors to fill
	 * \param[in] maxlnb	max slots in @lnb array
	 * \param[in] rw	0 if used to read, 1 if used for write
	 *
	 * \retval positive	number of descriptors on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_bufs_get)(const struct lu_env *env,
			    struct dt_object *dt,
			    loff_t pos,
			    ssize_t len,
			    struct niobuf_local *lb,
			    int maxlnb,
			    enum dt_bufs_type rw);

	/**
	 * Release reference granted by ->dbo_bufs_get().
	 *
	 * Release the reference granted by the previous ->dbo_bufs_get().
	 * Note the references are counted.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] lb	array of descriptors to fill
	 * \param[in] nr	size of the array
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_bufs_put)(const struct lu_env *env,
			    struct dt_object *dt,
			    struct niobuf_local *lb,
			    int nr);

	/**
	 * Prepare buffers for reading.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] lnb	array of buffer descriptors
	 * \param[in] nr	size of the array
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_read_prep)(const struct lu_env *env,
			     struct dt_object *dt,
			     struct niobuf_local *lnb,
			     int nr);

	/**
	 * Prepare buffers for write.
	 *
	 * This method is called on the given buffers to ensure the partial
	 * buffers contain correct data. The underlying idea is the same as
	 * in ->db_read_prep().
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] lb	array of buffer descriptors
	 * \param[in] nr	size of the array
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_write_prep)(const struct lu_env *env,
			      struct dt_object *dt,
			      struct niobuf_local *lb,
			      int nr);

	/**
	 * Declare intention to write data stored in the buffers.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] lb	array of descriptors
	 * \param[in] nr	size of the array
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_declare_write_commit)(const struct lu_env *env,
					struct dt_object *dt,
					struct niobuf_local *lb,
					int nr,
					struct thandle *th);

	/**
	 * Write to existing object.
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
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] lb	array of descriptors for the buffers
	 * \param[in] nr	size of the array
	 * \param[in] th	transaction handle
	 * \param[in] user_size	apparent size
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_write_commit)(const struct lu_env *env,
				struct dt_object *dt,
				struct niobuf_local *lb,
				int nr,
				struct thandle *th,
				__u64 user_size);

	/**
	 * Return logical to physical block mapping for a given extent
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] fm	describe the region to map and the output buffer
	 *			see the details in include/linux/fiemap.h
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_fiemap_get)(const struct lu_env *env,
			      struct dt_object *dt,
			      struct fiemap *fm);

	/**
	 * Declare intention to deallocate space from an object.
	 *
	 * Notify the underlying filesystem that space may be deallocated in
	 * this transactions. This enables the layer below to prepare resources
	 * (e.g. journal credits in ext4).  This method should be called between
	 * creating the transaction and starting it. The object need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] start	the start of the region to deallocate
	 * \param[in] end	the end of the region to deallocate
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*dbo_declare_punch)(const struct lu_env *env,
				   struct dt_object *dt,
				   __u64 start,
				   __u64 end,
				   struct thandle *th);

	/**
	 * Deallocate specified region in an object.
	 *
	 * This method is used to deallocate (release) space possibly consumed
	 * by the given region of the object. If the layer implementing this
	 * method is responsible for quota, then the method should maintain
	 * space accounting for the given credentials.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] start	the start of the region to deallocate
	 * \param[in] end	the end of the region to deallocate
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*dbo_punch)(const struct lu_env *env,
			   struct dt_object *dt,
			   __u64 start,
			   __u64 end,
			   struct thandle *th);
	/**
	 * Give advices on specified region in an object.
	 *
	 * This method is used to give advices about access pattern on an
	 * given region of the object. The disk filesystem understands
	 * the advices and tunes cache/read-ahead policies.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] start	the start of the region affected
	 * \param[in] end	the end of the region affected
	 * \param[in] advice	advice type
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int   (*dbo_ladvise)(const struct lu_env *env,
			     struct dt_object *dt,
			     __u64 start,
			     __u64 end,
			     enum lu_ladvise_type advice);

	/**
	 * Declare intention to preallocate space for an object
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_declare_fallocate)(const struct lu_env *env,
				    struct dt_object *dt, __u64 start,
				    __u64 end, int mode, struct thandle *th);
	/**
	 * Allocate specified region for an object
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] start	the start of the region to allocate
	 * \param[in] end	the end of the region to allocate
	 * \param[in] mode	fallocate mode
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dbo_fallocate)(const struct lu_env *env,
			    struct dt_object *dt,
			    __u64 start,
			    __u64 end,
			    int mode,
			    struct thandle *th);
	/**
	 * Do SEEK_HOLE/SEEK_DATA request on object
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] offset	the offset to start seek from
	 * \param[in] whence	seek mode, SEEK_HOLE or SEEK_DATA
	 *
	 * \retval hole/data offset	on success
	 * \retval negative		negated errno on error
	 */
	loff_t (*dbo_lseek)(const struct lu_env *env, struct dt_object *dt,
			    loff_t offset, int whence);
};

/**
 * Incomplete type of index record.
 */
struct dt_rec;

/**
 * Incomplete type of index key.
 */
struct dt_key;

/**
 * Incomplete type of dt iterator.
 */
struct dt_it;

/**
 * Per-dt-object operations on object as index. Index is a set of key/value
 * pairs abstracted from an on-disk representation. An index supports the
 * number of operations including lookup by key, insert and delete. Also,
 * an index can be iterated to find the pairs one by one, from a beginning
 * or specified point.
 */
struct dt_index_operations {
	/**
	 * Lookup in an index by key.
	 *
	 * The method returns a value for the given key. Key/value format
	 * and size should have been negotiated with ->do_index_try() before.
	 * Thus it's the caller's responsibility to provide the method with
	 * proper key and big enough buffer. No external locking is required,
	 * all the internal consistency should be implemented by the method
	 * or lower layers. The object should should have been created with
	 * type DFT_INDEX or DFT_DIR.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[out] rec	buffer where value will be stored
	 * \param[in] key	key
	 *
	 * \retval 0		on success
	 * \retval -ENOENT	if key isn't found
	 * \retval negative	negated errno on error
	 */
	int (*dio_lookup)(const struct lu_env *env,
			  struct dt_object *dt,
			  struct dt_rec *rec,
			  const struct dt_key *key);

	/**
	 * Declare intention to insert a key/value into an index.
	 *
	 * Notify the underlying filesystem that new key/value may be inserted
	 * in this transaction. This enables the layer below to prepare
	 * resources (e.g. journal credits in ext4). This method should be
	 * called between creating the transaction and starting it. key/value
	 * format and size is subject to ->do_index_try().
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] rec	buffer storing value
	 * \param[in] key	key
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int (*dio_declare_insert)(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_rec *rec,
				  const struct dt_key *key,
				  struct thandle *th);

	/**
	 * Insert a new key/value pair into an index.
	 *
	 * The method inserts specified key/value pair into the given index
	 * object. The internal consistency is maintained by the method or
	 * the functionality below. The format and size of key/value should
	 * have been negotiated before using ->do_index_try(), no additional
	 * information can be specified to the method. The keys are unique
	 * in a given index.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] rec	buffer storing value
	 * \param[in] key	key
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dio_insert)(const struct lu_env *env,
			  struct dt_object *dt,
			  const struct dt_rec *rec,
			  const struct dt_key *key,
			  struct thandle *th);

	/**
	 * Declare intention to delete a key/value from an index.
	 *
	 * Notify the underlying filesystem that key/value may be deleted in
	 * this transaction. This enables the layer below to prepare resources
	 * (e.g. journal credits in ext4).  This method should be called
	 * between creating the transaction and starting it. Key/value format
	 * and size is subject to ->do_index_try(). The object need not exist.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] key	key
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
        int (*dio_declare_delete)(const struct lu_env *env,
				  struct dt_object *dt,
				  const struct dt_key *key,
				  struct thandle *th);

	/**
	 * Delete key/value pair from an index.
	 *
	 * The method deletes specified key and corresponding value from the
	 * given index object. The internal consistency is maintained by the
	 * method or the functionality below. The format and size of the key
	 * should have been negotiated before using ->do_index_try(), no
	 * additional information can be specified to the method.
	 *
	 * \param[in] env	execution environment for this thread
	 * \param[in] dt	object
	 * \param[in] key	key
	 * \param[in] th	transaction handle
	 *
	 * \retval 0		on success
	 * \retval negative	negated errno on error
	 */
	int (*dio_delete)(const struct lu_env *env,
			  struct dt_object *dt,
			  const struct dt_key *key,
			  struct thandle *th);

        /**
	 * Iterator interface.
	 *
	 * Methods to iterate over an existing index, list the keys stored and
	 * associated values, get key/value size, etc.
         */
        struct dt_it_ops {
		/**
		 * Allocate and initialize new iterator.
		 *
		 * The iterator is a handler to be used in the subsequent
		 * methods to access index's content. Note the position is
		 * not defined at this point and should be initialized with
		 * ->get() or ->load() method.
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] dt	object
		 * \param[in] attr	ask the iterator to return part of
					the records, see LUDA_* for details
		 *
		 * \retval pointer	iterator pointer on success
		 * \retval ERR_PTR(errno)	on error
                 */
                struct dt_it *(*init)(const struct lu_env *env,
				      struct dt_object *dt,
				      __u32 attr);

		/**
		 * Release iterator.
		 *
		 * Release the specified iterator and all the resources
		 * associated (e.g. the object, index cache, etc).
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator to release
		 */
                void          (*fini)(const struct lu_env *env,
                                      struct dt_it *di);

		/**
		 * Move position of iterator.
		 *
		 * Move the position of the specified iterator to the specified
		 * key.
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 * \param[in] key	key to position to
		 *
		 * \retval 0		if exact key is found
		 * \retval 1		if at the record with least key
		 *			not larger than the key
		 * \retval negative	negated errno on error
		 */
                int            (*get)(const struct lu_env *env,
                                      struct dt_it *di,
                                      const struct dt_key *key);

		/**
		 * Release position
		 *
		 * Complimentary method for dt_it_ops::get() above. Some
		 * implementation can increase a reference on the iterator in
		 * dt_it_ops::get(). So the caller should be able to release
		 * with dt_it_ops::put().
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 */
                void           (*put)(const struct lu_env *env,
                                      struct dt_it *di);

		/**
		 * Move to next record.
		 *
		 * Moves the position of the iterator to a next record
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 *
		 * \retval 1		if no more records
		 * \retval 0		on success, the next record is found
		 * \retval negative	negated errno on error
		 */
                int           (*next)(const struct lu_env *env,
                                      struct dt_it *di);

		/**
		 * Return key.
		 *
		 * Returns a pointer to a buffer containing the key of the
		 * record at the current position. The pointer is valid and
		 * retains data until ->get(), ->load() and ->fini() methods
		 * are called.
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 *
		 * \retval pointer to key	on success
		 * \retval ERR_PTR(errno)	on error
		 */
                struct dt_key *(*key)(const struct lu_env *env,
                                      const struct dt_it *di);

		/**
		 * Return key size.
		 *
		 * Returns size of the key at the current position.
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 *
		 * \retval key's size	on success
		 * \retval negative	negated errno on error
		 */
                int       (*key_size)(const struct lu_env *env,
                                      const struct dt_it *di);

		/**
		 * Return record.
		 *
		 * Stores the value of the record at the current position. The
		 * buffer must be big enough (as negotiated with
		 * ->do_index_try() or ->rec_size()). The caller can specify
		 * she is interested only in part of the record, using attr
		 * argument (see LUDA_* definitions for the details).
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 * \param[out] rec	buffer to store value in
		 * \param[in] attr	specify part of the value to copy
		 *
		 * \retval 0		on success
		 * \retval negative	negated errno on error
		 */
                int            (*rec)(const struct lu_env *env,
                                      const struct dt_it *di,
                                      struct dt_rec *rec,
                                      __u32 attr);

		/**
		 * Return record size.
		 *
		 * Returns size of the record at the current position. The
		 * \a attr can be used to specify only the parts of the record
		 * needed to be returned. (see LUDA_* definitions for the
		 * details).
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 * \param[in] attr	part of the record to return
		 *
		 * \retval record's size	on success
		 * \retval negative		negated errno on error
		 */
		int	   (*rec_size)(const struct lu_env *env,
				       const struct dt_it *di,
				      __u32 attr);

		/**
		 * Return a cookie (hash).
		 *
		 * Returns the cookie (usually hash) of the key at the current
		 * position. This allows the caller to resume iteration at this
		 * position later. The exact value is specific to implementation
		 * and should not be interpreted by the caller.
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 *
		 * \retval cookie/hash of the key
		 */
                __u64        (*store)(const struct lu_env *env,
                                      const struct dt_it *di);

		/**
		 * Initialize position using cookie/hash.
		 *
		 * Initializes the current position of the iterator to one
		 * described by the cookie/hash as returned by ->store()
		 * previously.
		 *
		 * \param[in] env	execution environment for this thread
		 * \param[in] di	iterator
		 * \param[in] hash	cookie/hash value
		 *
		 * \retval positive	if current position points to
		 *			record with least cookie not larger
		 *			than cookie
		 * \retval 0		if current position matches cookie
		 * \retval negative	negated errno on error
		 */
                int           (*load)(const struct lu_env *env,
				      const struct dt_it *di,
				      __u64 hash);

		/**
		 * Not used
		 */
                int        (*key_rec)(const struct lu_env *env,
				      const struct dt_it *di,
				      void *key_rec);
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

/* otable based iteration needs to use the common DT iteration APIs.
 * To initialize the iteration, it needs call dio_it::init() firstly.
 * Here is how the otable based iteration should prepare arguments to
 * call dt_it_ops::init().
 *
 * For otable based iteration, the 32-bits 'attr' for dt_it_ops::init()
 * is composed of two parts:
 * low 16-bits is for valid bits, high 16-bits is for flags bits. */
#define DT_OTABLE_IT_FLAGS_SHIFT	16
#define DT_OTABLE_IT_FLAGS_MASK 	0xffff0000

struct dt_device {
        struct lu_device                   dd_lu_dev;
        const struct dt_device_operations *dd_ops;

        /**
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

static inline struct dt_device * lu2dt_dev(struct lu_device *l)
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

/**
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
	 * callback mechanism */
	struct thandle	*th_top;

	/** the last operation result in this transaction.
	 * this value is used in recovery */
	__s32             th_result;

	/** whether we need sync commit */
	unsigned int		th_sync:1,
	/* local transation, no need to inform other layers */
				th_local:1,
	/* Whether we need wait the transaction to be submitted
	 * (send to remote target) */
				th_wait_submit:1,
	/* complex transaction which will track updates on all targets,
	 * including OSTs */
				th_complex:1,
	/* whether ignore quota */
				th_ignore_quota:1,
	/* whether restart transaction */
				th_restart_tran:1;
};

/**
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

int dt_try_as_dir(const struct lu_env *env, struct dt_object *obj);

/**
 * Callback function used for parsing path.
 * \see llo_store_resolve
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
	LASSERT(o != NULL);
	LASSERT(o->do_ops != NULL);
	LASSERT(o->do_ops->do_object_lock != NULL);
	return o->do_ops->do_object_lock(env, o, lh, einfo, policy);
}

static inline int dt_object_unlock(const struct lu_env *env,
				   struct dt_object *o,
				   struct ldlm_enqueue_info *einfo,
				   union ldlm_policy_data *policy)
{
	LASSERT(o != NULL);
	LASSERT(o->do_ops != NULL);
	LASSERT(o->do_ops->do_object_unlock != NULL);
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
dt_obj_version_t dt_version_get(const struct lu_env *env, struct dt_object *o);


int dt_read(const struct lu_env *env, struct dt_object *dt,
            struct lu_buf *buf, loff_t *pos);
int dt_record_read(const struct lu_env *env, struct dt_object *dt,
                   struct lu_buf *buf, loff_t *pos);
int dt_record_write(const struct lu_env *env, struct dt_object *dt,
                    const struct lu_buf *buf, loff_t *pos, struct thandle *th);
typedef int (*dt_index_page_build_t)(const struct lu_env *env,
				     union lu_page *lp, size_t nob,
				     const struct dt_it_ops *iops,
				     struct dt_it *it, __u32 attr, void *arg);
int dt_index_walk(const struct lu_env *env, struct dt_object *obj,
		  const struct lu_rdpg *rdpg, dt_index_page_build_t filler,
		  void *arg);
int dt_index_read(const struct lu_env *env, struct dt_device *dev,
		  struct idx_info *ii, const struct lu_rdpg *rdpg);

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
/** @} dt */


static inline int dt_declare_record_write(const struct lu_env *env,
					  struct dt_object *dt,
					  const struct lu_buf *buf,
					  loff_t pos,
					  struct thandle *th)
{
	int rc;

	LASSERTF(dt != NULL, "dt is NULL when we want to write record\n");
	LASSERT(th != NULL);
	LASSERTF(dt->do_body_ops, DFID" doesn't exit\n",
		 PFID(lu_object_fid(&dt->do_lu)));
	LASSERT(dt->do_body_ops->dbo_declare_write);
	rc = dt->do_body_ops->dbo_declare_write(env, dt, buf, pos, th);
	return rc;
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
                                unsigned role)
{
        LASSERT(dt);
        LASSERT(dt->do_ops);
        LASSERT(dt->do_ops->do_read_lock);
        dt->do_ops->do_read_lock(env, dt, role);
}

static inline void dt_write_lock(const struct lu_env *env,
                                struct dt_object *dt,
                                unsigned role)
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
	LASSERT(dt->do_ops->do_check_stale);

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
        LASSERTF(d != NULL, "dt is NULL when we want to declare write\n");
        LASSERT(th != NULL);
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

static inline struct super_block *dt_mnt_sb_get(const struct dt_device *dev)
{
	LASSERT(dev);
	LASSERT(dev->dd_ops);
	if (dev->dd_ops->dt_mnt_sb_get)
		return dev->dd_ops->dt_mnt_sb_get(dev);

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
	LASSERT(dt->do_ops->do_invalidate);

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

# ifdef CONFIG_PROC_FS
int lprocfs_dt_blksize_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_kbytestotal_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_kbytesfree_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_kbytesavail_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_filestotal_seq_show(struct seq_file *m, void *v);
int lprocfs_dt_filesfree_seq_show(struct seq_file *m, void *v);
# endif /* CONFIG_PROC_FS */

#endif /* __LUSTRE_DT_OBJECT_H */
