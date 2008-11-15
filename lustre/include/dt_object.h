/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
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


/*
 * super-class definitions.
 */
#include <lu_object.h>

#include <libcfs/libcfs.h>

struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;

struct thandle;
struct txn_param;
struct dt_device;
struct dt_object;
struct dt_index_features;
struct dt_quota_ctxt;

struct dt_device_param {
        unsigned           ddp_max_name_len;
        unsigned           ddp_max_nlink;
        unsigned           ddp_block_shift;
};

/**
 * Basic transaction credit op
 */
enum dt_txn_op {
        DTO_INDEX_INSERT,
        DTO_INDEX_DELETE,
        DTO_IDNEX_UPDATE,
        DTO_OBJECT_CREATE,
        DTO_OBJECT_DELETE,
        DTO_ATTR_SET_BASE,
        DTO_XATTR_SET,
        DTO_LOG_REC, /**< XXX temporary: dt layer knows nothing about llog. */
        DTO_WRITE_BASE,
        DTO_WRITE_BLOCK,
        DTO_ATTR_SET_CHOWN,

        DTO_NR
};

/**
 * Operations on dt device.
 */
struct dt_device_operations {
        /**
         * Return device-wide statistics.
         */
        int   (*dt_statfs)(const struct lu_env *env,
                           struct dt_device *dev, struct kstatfs *sfs);
        /**
         * Start transaction, described by \a param.
         */
        struct thandle *(*dt_trans_start)(const struct lu_env *env,
                                          struct dt_device *dev,
                                          struct txn_param *param);
        /**
         * Finish previously started transaction.
         */
        void  (*dt_trans_stop)(const struct lu_env *env,
                               struct thandle *th);
        /**
         * Return fid of root index object.
         */
        int   (*dt_root_get)(const struct lu_env *env,
                             struct dt_device *dev, struct lu_fid *f);
        /**
         * Return device configuration data.
         */
        void  (*dt_conf_get)(const struct lu_env *env,
                             const struct dt_device *dev,
                             struct dt_device_param *param);
        /**
         *  handling device state, mostly for tests
         */
        int   (*dt_sync)(const struct lu_env *env, struct dt_device *dev);
        void  (*dt_ro)(const struct lu_env *env, struct dt_device *dev);
        /**
          * Start a transaction commit asynchronously
          *
          * \param env environment
          * \param dev dt_device to start commit on
          *
          * \return 0 success, negative value if error
          */
         int   (*dt_commit_async)(const struct lu_env *env,
                                  struct dt_device *dev);
        /**
         * Initialize capability context.
         */
        int   (*dt_init_capa_ctxt)(const struct lu_env *env,
                                   struct dt_device *dev,
                                   int mode, unsigned long timeout,
                                   __u32 alg, struct lustre_capa_key *keys);
        /**
         * Initialize quota context.
         */
        void (*dt_init_quota_ctxt)(const struct lu_env *env,
                                   struct dt_device *dev,
                                   struct dt_quota_ctxt *ctxt, void *data);

        /**
         *  get transaction credits for given \a op.
         */
        int (*dt_credit_get)(const struct lu_env *env, struct dt_device *dev,
                             enum dt_txn_op);
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
};

enum dt_index_flags {
        /** index supports variable sized keys */
        DT_IND_VARKEY = 1 << 0,
        /** index supports variable sized records */
        DT_IND_VARREC = 1 << 1,
        /** index can be modified */
        DT_IND_UPDATE = 1 << 2,
        /** index supports records with non-unique (duplicate) keys */
        DT_IND_NONUNQ = 1 << 3
};

/**
 * Features, required from index to support file system directories (mapping
 * names to fids).
 */
extern const struct dt_index_features dt_directory_features;

/**
 * This is a general purpose dt allocation hint.
 * It now contains the parent object.
 * It can contain any allocation hint in the future.
 */
struct dt_allocation_hint {
        struct dt_object *dah_parent;
        __u32             dah_mode;
};

/**
 * Per-dt-object operations.
 */
struct dt_object_operations {
        void  (*do_read_lock)(const struct lu_env *env,
                              struct dt_object *dt, unsigned role);
        void  (*do_write_lock)(const struct lu_env *env,
                               struct dt_object *dt, unsigned role);
        void  (*do_read_unlock)(const struct lu_env *env,
                                struct dt_object *dt);
        void  (*do_write_unlock)(const struct lu_env *env,
                                 struct dt_object *dt);
        /**
         * Note: following ->do_{x,}attr_{set,get}() operations are very
         * similar to ->moo_{x,}attr_{set,get}() operations in struct
         * md_object_operations (see md_object.h). These operations are not in
         * lu_object_operations, because ->do_{x,}attr_set() versions take
         * transaction handle as an argument (this transaction is started by
         * caller). We might factor ->do_{x,}attr_get() into
         * lu_object_operations, but that would break existing symmetry.
         */

        /**
         * Return standard attributes.
         *
         * precondition: lu_object_exists(&dt->do_lu);
         */
        int   (*do_attr_get)(const struct lu_env *env,
                             struct dt_object *dt, struct lu_attr *attr,
                             struct lustre_capa *capa);
        /**
         * Set standard attributes.
         *
         * precondition: dt_object_exists(dt);
         */
        int   (*do_attr_set)(const struct lu_env *env,
                             struct dt_object *dt,
                             const struct lu_attr *attr,
                             struct thandle *handle,
                             struct lustre_capa *capa);
        /**
         * Return a value of an extended attribute.
         *
         * precondition: dt_object_exists(dt);
         */
        int   (*do_xattr_get)(const struct lu_env *env, struct dt_object *dt,
                              struct lu_buf *buf, const char *name,
                              struct lustre_capa *capa);
        /**
         * Set value of an extended attribute.
         *
         * \a fl - flags from enum lu_xattr_flags
         *
         * precondition: dt_object_exists(dt);
         */
        int   (*do_xattr_set)(const struct lu_env *env,
                              struct dt_object *dt, const struct lu_buf *buf,
                              const char *name, int fl, struct thandle *handle,
                              struct lustre_capa *capa);
        /**
         * Delete existing extended attribute.
         *
         * precondition: dt_object_exists(dt);
         */
        int   (*do_xattr_del)(const struct lu_env *env,
                              struct dt_object *dt,
                              const char *name, struct thandle *handle,
                              struct lustre_capa *capa);
        /**
         * Place list of existing extended attributes into \a buf (which has
         * length len).
         *
         * precondition: dt_object_exists(dt);
         */
        int   (*do_xattr_list)(const struct lu_env *env,
                               struct dt_object *dt, struct lu_buf *buf,
                               struct lustre_capa *capa);
        /**
         * Init allocation hint using parent object and child mode.
         * (1) The \a parent might be NULL if this is a partial creation for
         *     remote object.
         * (2) The type of child is in \a child_mode.
         * (3) The result hint is stored in \a ah;
         */
        void  (*do_ah_init)(const struct lu_env *env,
                            struct dt_allocation_hint *ah,
                            struct dt_object *parent,
                            umode_t child_mode);
        /**
         * Create new object on this device.
         *
         * precondition: !dt_object_exists(dt);
         * postcondition: ergo(result == 0, dt_object_exists(dt));
         */
        int   (*do_create)(const struct lu_env *env, struct dt_object *dt,
                           struct lu_attr *attr,
                           struct dt_allocation_hint *hint,
                           struct thandle *th);

        /**
         * Announce that this object is going to be used as an index. This
         * operation check that object supports indexing operations and
         * installs appropriate dt_index_operations vector on success.
         *
         * Also probes for features. Operation is successful if all required
         * features are supported.
         */
        int   (*do_index_try)(const struct lu_env *env,
                              struct dt_object *dt,
                              const struct dt_index_features *feat);
        /**
         * Add nlink of the object
         * precondition: dt_object_exists(dt);
         */
        void  (*do_ref_add)(const struct lu_env *env,
                            struct dt_object *dt, struct thandle *th);
        /**
         * Del nlink of the object
         * precondition: dt_object_exists(dt);
         */
        void  (*do_ref_del)(const struct lu_env *env,
                            struct dt_object *dt, struct thandle *th);

        struct obd_capa *(*do_capa_get)(const struct lu_env *env,
                                        struct dt_object *dt,
                                        struct lustre_capa *old,
                                        __u64 opc);
        int (*do_object_sync)(const struct lu_env *, struct dt_object *);
};

/**
 * Per-dt-object operations on "file body".
 */
struct dt_body_operations {
        /**
         * precondition: dt_object_exists(dt);
         */
        ssize_t (*dbo_read)(const struct lu_env *env, struct dt_object *dt,
                            struct lu_buf *buf, loff_t *pos,
                            struct lustre_capa *capa);
        /**
         * precondition: dt_object_exists(dt);
         */
        ssize_t (*dbo_write)(const struct lu_env *env, struct dt_object *dt,
                             const struct lu_buf *buf, loff_t *pos,
                             struct thandle *handle, struct lustre_capa *capa,
                             int ignore_quota);
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
 * Per-dt-object operations on object as index.
 */
struct dt_index_operations {
        /**
         * precondition: dt_object_exists(dt);
         */
        int (*dio_lookup)(const struct lu_env *env, struct dt_object *dt,
                          struct dt_rec *rec, const struct dt_key *key,
                          struct lustre_capa *capa);
        /**
         * precondition: dt_object_exists(dt);
         */
        int (*dio_insert)(const struct lu_env *env, struct dt_object *dt,
                          const struct dt_rec *rec, const struct dt_key *key,
                          struct thandle *handle, struct lustre_capa *capa,
                          int ignore_quota);
        /**
         * precondition: dt_object_exists(dt);
         */
        int (*dio_delete)(const struct lu_env *env, struct dt_object *dt,
                          const struct dt_key *key, struct thandle *handle,
                          struct lustre_capa *capa);
        /**
         * Iterator interface
         */
        struct dt_it_ops {
                /**
                 * Allocate and initialize new iterator.
                 *
                 * precondition: dt_object_exists(dt);
                 */
                struct dt_it *(*init)(const struct lu_env *env,
                                      struct dt_object *dt, int writable,
                                      struct lustre_capa *capa);
                void          (*fini)(const struct lu_env *env,
                                      struct dt_it *di);
                int            (*get)(const struct lu_env *env,
                                      struct dt_it *di,
                                      const struct dt_key *key);
                void           (*put)(const struct lu_env *env,
                                      struct dt_it *di);
                int            (*del)(const struct lu_env *env,
                                      struct dt_it *di, struct thandle *th);
                int           (*next)(const struct lu_env *env,
                                      struct dt_it *di);
                struct dt_key *(*key)(const struct lu_env *env,
                                      const struct dt_it *di);
                int       (*key_size)(const struct lu_env *env,
                                      const struct dt_it *di);
                struct dt_rec *(*rec)(const struct lu_env *env,
                                      const struct dt_it *di);
                __u64        (*store)(const struct lu_env *env,
                                      const struct dt_it *di);
                int           (*load)(const struct lu_env *env,
                                      const struct dt_it *di, __u64 hash);
        } dio_it;
};

struct dt_device {
        struct lu_device                   dd_lu_dev;
        const struct dt_device_operations *dd_ops;

        /**
         * List of dt_txn_callback (see below). This is not protected in any
         * way, because callbacks are supposed to be added/deleted only during
         * single-threaded start-up shut-down procedures.
         */
        struct list_head                   dd_txn_callbacks;
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
        return container_of0(l, struct dt_device, dd_lu_dev);
}

struct dt_object {
        struct lu_object                   do_lu;
        const struct dt_object_operations *do_ops;
        const struct dt_body_operations   *do_body_ops;
        const struct dt_index_operations  *do_index_ops;
};

int  dt_object_init(struct dt_object *obj,
                    struct lu_object_header *h, struct lu_device *d);

void dt_object_fini(struct dt_object *obj);

static inline int dt_object_exists(const struct dt_object *dt)
{
        return lu_object_exists(&dt->do_lu);
}

struct txn_param {
        /** number of blocks this transaction will modify */
        unsigned int tp_credits;
        /** sync transaction is needed */
        __u32        tp_sync:1;
};

static inline void txn_param_init(struct txn_param *p, unsigned int credits)
{
        memset(p, 0, sizeof(*p));
        p->tp_credits = credits;
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

        /** context for this transaction, tag is LCT_TX_HANDLE */
        struct lu_context th_ctx;

        /** the last operation result in this transaction.
         * this value is used in recovery */
        __s32             th_result;
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
                             struct txn_param *param, void *cookie);
        int (*dtc_txn_stop)(const struct lu_env *env,
                            struct thandle *txn, void *cookie);
        int (*dtc_txn_commit)(const struct lu_env *env,
                              struct thandle *txn, void *cookie);
        void            *dtc_cookie;
        struct list_head dtc_linkage;
};

void dt_txn_callback_add(struct dt_device *dev, struct dt_txn_callback *cb);
void dt_txn_callback_del(struct dt_device *dev, struct dt_txn_callback *cb);

int dt_txn_hook_start(const struct lu_env *env,
                      struct dt_device *dev, struct txn_param *param);
int dt_txn_hook_stop(const struct lu_env *env, struct thandle *txn);
int dt_txn_hook_commit(const struct lu_env *env, struct thandle *txn);

int dt_try_as_dir(const struct lu_env *env, struct dt_object *obj);
struct dt_object *dt_store_open(const struct lu_env *env,
                                struct dt_device *dt, const char *name,
                                struct lu_fid *fid);

/** @} dt */

#endif /* __LUSTRE_DT_OBJECT_H */
