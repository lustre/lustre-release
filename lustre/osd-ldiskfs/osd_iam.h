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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * osd_iam.c
 * Top-level entry points into osd module
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

#ifndef __LINUX_LUSTRE_IAM_H__
#define __LINUX_LUSTRE_IAM_H__

#include <linux/module.h>
#include <asm/unaligned.h>

#include "osd_dynlocks.h"
/*
 *  osd_iam.h
 */

/* implication */
#define ergo(a, b) (!(a) || (b))
/* logical equivalence */
#define equi(a, b) (!!(a) == !!(b))

enum {
        /*
         * Maximal number of non-leaf levels in htree. In the stock ldiskfs this
         * is 2.
         */
        /*
         * XXX reduced back to 2 to make per-node locking work.
         */
        DX_MAX_TREE_HEIGHT = 5,
        /*
         * Scratch keys used by generic code for temporaries.
         *
         * Allocation:
         *
         *         [0] reserved for assertions and as a staging area for
         *         record keys immediately used for key comparisons.
         *
         *         [1] reserved for record key, stored during iteration over
         *         node records (see dx_node_check()).
         *
         *         [2] reserved for leaf node operations.
         *
         *         [3] reserved for index operations.
         *
         *         [4] reserved for path->ip_ikey_target
         *
         */
        DX_SCRATCH_KEYS    = 5,
        /*
         * Maximal format name length.
         */
        DX_FMT_NAME_LEN    = 16,
};


/*
 * Debugging.
 *
 * Various debugging levels.
 */

#if 0
/*
 * Following macros are defined in config.h and are tunable through
 * appropriate configure switches (indicated below).
 */

/*
 * Compile basic assertions in. You want this most of the time.
 *
 * --{enable,disable}-ldiskfs-assert (on by default).
 */
#define LDISKFS_ASSERT (1)

/*
 * Compile heavier correctness checks in. You want this during development
 * cycle.
 *
 * --{enable,disable}-ldiskfs-correctness (off by default).
 */
#define LDISKFS_CORRECTNESS (1)

/*
 * Compile heavy invariant checking in. You want this early during development
 * or when chasing a bug.
 *
 * --{enable,disable}-ldiskfs-invariant (off by default).
 */
#define LDISKFS_INVARIANT (1)
#endif

#if defined(LDISKFS_ASSERT)
#define LDISKFS_ASSERT_ON (1)
#else
#define LDISKFS_ASSERT_ON (0)
#endif

#if defined(LDISKFS_CORRECTNESS)
#define LDISKFS_CORRECTNESS_ON (1)
#else
#define LDISKFS_CORRECTNESS_ON (0)
#endif

#if defined(LDISKFS_INVARIANT)
#define LDISKFS_INVARIANT_ON (1)
#else
#define LDISKFS_INVARIANT_ON (0)
#endif

#ifndef assert
#if LDISKFS_ASSERT_ON
#define assert(test) J_ASSERT(test)
#else
#define assert(test) ((void)(test))
#endif
#endif

#if LDISKFS_CORRECTNESS_ON
#define assert_corr(test) J_ASSERT(test)
#define do_corr(exp) exp
#else
#define assert_corr(test) do {;} while (0)
#define do_corr(exp) do {;} while (0)
#endif

#if LDISKFS_INVARIANT_ON
#define assert_inv(test) J_ASSERT(test)
#else
#define assert_inv(test) do {;} while (0)
#endif

/*
 * Entry within index tree node. Consists of a key immediately followed
 * (without padding) by a pointer to the child node.
 *
 * Both key and pointer are of variable size, hence incomplete type.
 */
struct iam_entry;

struct iam_entry_compat {
        __le32 hash;
        __le32 block;
};

/*
 * Incomplete type used to refer to keys in iam container.
 *
 * As key size can be different from container to container, iam has to use
 * incomplete type. Clients cast pointer to iam_key to real key type and back.
 */
struct iam_key;

/*
 * Incomplete type use to refer to the records stored in iam containers.
 */
struct iam_rec;

/*
 * Key in index node. Possibly compressed. Fixed size.
 */
struct iam_ikey;

/*
 * Scalar type into which certain iam_key's can be uniquely mapped. Used to
 * support interfaces like readdir(), where iteration over index has to be
 * re-startable.
 */
typedef __u32 iam_ptr_t;

/*
 * Index node traversed during tree lookup.
 */
struct iam_frame {
        struct buffer_head *bh;    /* buffer holding node data */
        struct iam_entry *entries; /* array of entries */
        struct iam_entry *at;      /* target entry, found by binary search */
        iam_ptr_t         leaf;    /* (logical) offset of child node found by
                                    * binary search. */
        iam_ptr_t         curidx;  /* (logical) offset of this node. Used to
                                    * per-node locking to detect concurrent
                                    * splits. */
	unsigned int      at_shifted:1; /* The "at" entry has moved to next
					 * because of shrinking index node
					 * for recycling empty leaf node. */
};

/*
 * Opaque entry in the leaf node.
 */
struct iam_lentry;

struct iam_path;
struct iam_container;


/* leaf node reached by tree lookup */
struct iam_leaf {
        struct iam_path    *il_path;
        struct buffer_head *il_bh;
        struct iam_lentry  *il_entries;
        struct iam_lentry  *il_at;
        /*
         * Lock on a leaf node.
         */
        struct dynlock_handle *il_lock;
        iam_ptr_t              il_curidx; /* logical offset of leaf node. */
        void               *il_descr_data;
};

/*
 * Return values of ->lookup() operation from struct iam_leaf_operations.
 */
enum iam_lookup_t {
        /*
         * lookup found a record with the key requested
         */
        IAM_LOOKUP_EXACT  = 0,
        /*
         * lookup positioned leaf on some record
         */
        IAM_LOOKUP_OK     = 1,
        /*
         * leaf was empty
         */
        IAM_LOOKUP_EMPTY  = 2,
        /*
         * lookup positioned leaf before first record
         */
        IAM_LOOKUP_BEFORE = 3,
        /*
         * Found hash may have a continuation in the next leaf.
         */
        IAM_LOOKUP_LAST   = 0x100
};

/*
 * Format-specific container operations. These are called by generic iam code.
 */
struct iam_operations {
        /*
         * Returns pointer (in the same sense as pointer in index entry) to
         * the root node.
         */
        __u32 (*id_root_ptr)(struct iam_container *c);

        /*
         * Check validity and consistency of index node.
         */
        int (*id_node_check)(struct iam_path *path, struct iam_frame *frame);
        /*
         * Copy some data from node header into frame. This is called when
         * new node is loaded into frame.
         */
        int (*id_node_load)(struct iam_path *path, struct iam_frame *frame);
        /*
         * Initialize new node (stored in @bh) that is going to be added into
         * tree.
         */
        int (*id_node_init)(struct iam_container *c,
                            struct buffer_head *bh, int root);
        int (*id_node_read)(struct iam_container *c, iam_ptr_t ptr,
                            handle_t *h, struct buffer_head **bh);
        /*
         * Key comparison functions. Returns -1, 0, +1.
         */
        int (*id_ikeycmp)(const struct iam_container *c,
                          const struct iam_ikey *k1,
                          const struct iam_ikey *k2);
        /*
         * Modify root node when tree height increases.
         */
        struct iam_entry *(*id_root_inc)(struct iam_container *c,
                                         struct iam_path *path,
                                         struct iam_frame *frame);

        struct iam_path_descr *(*id_ipd_alloc)(const struct iam_container *c,
                                               void *area);
        void (*id_ipd_free)(struct iam_path_descr *ipd);
        /*
         * Format name.
         */
        char id_name[DX_FMT_NAME_LEN];
};

/*
 * Another format-specific operation vector, consisting of methods to access
 * leaf nodes. This is separated from struct iam_operations, because it is
 * assumed that there will be many formats with different format of leaf
 * nodes, yes the same struct iam_operations.
 */
struct iam_leaf_operations {
                /*
                 * leaf operations.
                 */

        /*
         * initialize just loaded leaf node.
         */
        int (*init)(struct iam_leaf *p);
        /*
         * Format new node.
         */
        void (*init_new)(struct iam_container *c, struct buffer_head *bh);
        /*
         * Release resources.
         */
        void (*fini)(struct iam_leaf *l);
                /*
                 * returns true iff leaf is positioned at the last entry.
                 */
        int (*at_end)(const struct iam_leaf *l);
                /* position leaf at the first entry */
        void (*start)(struct iam_leaf *l);
                /* more leaf to the next entry. */
        void (*next)(struct iam_leaf *l);
        /*
         * return key of current leaf record. This method may return
         * either pointer to the key stored in node, or copy key into
         * @k buffer supplied by caller and return pointer to this
         * buffer. The latter approach is used when keys in nodes are
         * not stored in plain form (e.g., htree doesn't store keys at
         * all).
         *
         * Caller should assume that returned pointer is only valid
         * while leaf node is pinned and locked.
         */
        struct iam_ikey *(*ikey)(const struct iam_leaf *l, struct iam_ikey *k);
        struct iam_key *(*key)(const struct iam_leaf *l);
        /* return pointer to entry body. Pointer is valid while
           corresponding leaf node is locked and pinned. */
        struct iam_rec *(*rec)(const struct iam_leaf *l);

        void (*key_set)(struct iam_leaf *l, const struct iam_key *k);
        void (*rec_set)(struct iam_leaf *l, const struct iam_rec *r);
        void (*rec_get)(const struct iam_leaf *l, struct iam_rec *r);

        int (*key_cmp)(const struct iam_leaf *l, const struct iam_key *k);
        int (*key_eq)(const struct iam_leaf *l, const struct iam_key *k);

	int (*rec_eq)(const struct iam_leaf *l, const struct iam_rec *r);

        int (*key_size)(const struct iam_leaf *l);
        /*
         * Search leaf @l for a record with key @k or for a place
         * where such record is to be inserted.
         *
         * Scratch keys from @path can be used.
         */
        int (*lookup)(struct iam_leaf *l, const struct iam_key *k);
        int (*ilookup)(struct iam_leaf *l, const struct iam_ikey *ik);

        int (*can_add)(const struct iam_leaf *l,
                       const struct iam_key *k, const struct iam_rec *r);
        /*
         * add rec for a leaf
         */
        void (*rec_add)(struct iam_leaf *l,
                        const struct iam_key *k, const struct iam_rec *r);
        /*
         * remove rec for a leaf
         */
        void (*rec_del)(struct iam_leaf *l, int shift);
        /*
         * split leaf node, moving some entries into @bh (the latter currently
         * is assumed to be empty).
         */
        void (*split)(struct iam_leaf *l, struct buffer_head **bh,
                      iam_ptr_t newblknr);
	/*
	 * the leaf is empty?
	 */
	int (*leaf_empty)(struct iam_leaf *l);
};

/*
 * Parameters, describing a flavor of iam container.
 */
struct iam_descr {
	/*
	 * Size of a key in this container, in bytes.
	 */
	size_t       id_key_size;
	/*
	 * Size of a key in index nodes, in bytes.
	 */
	size_t       id_ikey_size;
	/*
	 * Size of a pointer to the next level (stored in index nodes), in
	 * bytes.
	 */
	size_t       id_ptr_size;
	/*
	 * Size of a record (stored in leaf nodes), in bytes.
	 */
	size_t       id_rec_size;
	/*
	 * Size of unused (by iam) space at the beginning of every non-root
	 * node, in bytes. Used for compatibility with ldiskfs.
	 */
	size_t       id_node_gap;
	/*
	 * Size of unused (by iam) space at the beginning of root node, in
	 * bytes. Used for compatibility with ldiskfs.
	 */
	size_t       id_root_gap;

	const struct iam_operations           *id_ops;
	const struct iam_leaf_operations      *id_leaf_ops;
};

enum {
	IAM_IDLE_HEADER_MAGIC = 0x7903,
};

/*
 * Header structure to record idle blocks.
 */
struct iam_idle_head {
	__le16 iih_magic;
	__le16 iih_count; /* how many idle blocks in this head */
	__le32 iih_next; /* next head for idle blocks */
	__le32 iih_blks[0];
};

/*
 * An instance of iam container.
 */
struct iam_container {
        /*
         * Underlying flat file. IO against this object is issued to
         * read/write nodes.
         */
        struct inode        *ic_object;
        /*
         * BH of root block
         */
        struct buffer_head  *ic_root_bh;
        /*
         * container flavor.
         */
        struct iam_descr    *ic_descr;
        /*
         * read-write lock protecting index consistency.
         */
	struct rw_semaphore	ic_sem;
	struct dynlock       ic_tree_lock;
	/* Protect ic_idle_bh */
	struct mutex	     ic_idle_mutex;
	/*
	 * BH for idle blocks
	 */
	struct buffer_head  *ic_idle_bh;
	unsigned int	     ic_idle_failed:1; /* Idle block mechanism failed */
};

/*
 * description-specific part of iam_path. This is usually embedded into larger
 * structure.
 */
struct iam_path_descr {
        /*
         * Scratch-pad area for temporary keys.
         */
        struct iam_ikey *ipd_key_scratch[DX_SCRATCH_KEYS];
};

/*
 * Structure to keep track of a path drilled through htree.
 */
struct iam_path {
        /*
         * Parent container.
         */
        struct iam_container  *ip_container;
        /*
         * Number of index levels minus one.
         */
        int                    ip_indirect;
        /*
         * Nodes that top-to-bottom traversal passed through.
         */
        struct iam_frame       ip_frames[DX_MAX_TREE_HEIGHT];
        /*
         * Last filled frame in ->ip_frames. Refers to the 'twig' node (one
         * immediately above leaf).
         */
        struct iam_frame      *ip_frame;
        /*
         * Leaf node: a child of ->ip_frame.
         */
        struct iam_leaf        ip_leaf;
        /*
         * Key searched for.
         */
        const struct iam_key  *ip_key_target;
        const struct iam_ikey *ip_ikey_target;
        /*
         * Description-specific data.
         */
        struct iam_path_descr *ip_data;
};

struct ldiskfs_dx_hash_info;

/*
 * Helper structure for legacy htrees.
 */
struct iam_path_compat {
        struct iam_path      ipc_path;
        struct iam_container ipc_container;
        __u32                 ipc_scratch[DX_SCRATCH_KEYS];
        struct ldiskfs_dx_hash_info  *ipc_hinfo;
        struct qstr          *ipc_qstr;
        struct iam_path_descr ipc_descr;
        struct ldiskfs_dx_hash_info   ipc_hinfo_area;
};

#define const_max(p, q) ((p > q) ? p : q)

enum {
        DX_MAX_IKEY_SIZE   = 32, /* be generous */
        /*
         * Hack to avoid dynamic allocation and freeing of ipd.
         */
        DX_IPD_MAX_SIZE    = const_max(sizeof(struct iam_path_compat),
                                       DX_MAX_IKEY_SIZE * DX_SCRATCH_KEYS +
                                       sizeof(struct iam_path_descr))
};

/*
 * iam cursor (iterator) api.
 */

/*
 * States of iterator state machine.
 */
enum iam_it_state {
        /* initial state */
        IAM_IT_DETACHED,
        /* iterator is above particular record in the container */
        IAM_IT_ATTACHED,
        /* iterator is positioned before record  */
        IAM_IT_SKEWED
};

/*
 * Flags controlling iterator functionality.
 */
enum iam_it_flags {
        /*
         * this iterator will move (iam_it_next() will be called on it)
         */
        IAM_IT_MOVE  = BIT(0),
        /*
         * tree can be updated through this iterator.
         */
        IAM_IT_WRITE = BIT(1)
};

/*
 * Iterator.
 *
 * Immediately after call to iam_it_init() iterator is in "detached"
 * (IAM_IT_DETACHED) state: it is associated with given parent container, but
 * doesn't point to any particular record in this container.
 *
 * After successful call to iam_it_get() and until corresponding call to
 * iam_it_put() iterator is in one of "active" states: IAM_IT_ATTACHED or
 * IAM_IT_SKEWED.
 *
 * Active iterator can move through records in a container (provided
 * IAM_IT_MOVE permission) in a key order, can get record and key values as it
 * passes over them, and can modify container (provided IAM_IT_WRITE
 * permission).
 *
 * Iteration may reach the end of container, at which point iterator switches
 * into IAM_IT_DETACHED state.
 *
 * Concurrency: iterators are supposed to be local to thread. Interfaces below
 * do no internal serialization of access to the iterator fields.
 *
 * When in non-detached state, iterator keeps some container nodes pinned in
 * memory and locked (that locking may be implemented at the container
 * granularity though). In particular, clients may assume that pointers to
 * records and keys obtained through iterator interface as valid until
 * iterator is detached (except that they may be invalidated by sub-sequent
 * operations done through the same iterator).
 *
 */
struct iam_iterator {
        /*
         * iterator flags, taken from enum iam_it_flags.
         */
        __u32                 ii_flags;
        enum iam_it_state     ii_state;
        /*
         * path to the record. Valid in IAM_IT_ATTACHED, and IAM_IT_SKEWED
         * states.
         */
        struct iam_path       ii_path;
};

void iam_path_init(struct iam_path *path, struct iam_container *c,
                   struct iam_path_descr *pd);
void iam_path_fini(struct iam_path *path);
void iam_path_release(struct iam_path *path);

void iam_path_compat_init(struct iam_path_compat *path, struct inode *inode);
void iam_path_compat_fini(struct iam_path_compat *path);

struct iam_path_descr *iam_ipd_alloc(void *area, int keysize);
void iam_ipd_free(struct iam_path_descr *ipd);

int  iam_it_init(struct iam_iterator *it, struct iam_container *c, __u32 flags,
                 struct iam_path_descr *pd);
void iam_it_fini(struct iam_iterator *it);
int iam_it_get(struct iam_iterator *it, const struct iam_key *k);
int iam_it_get_at(struct iam_iterator *it, const struct iam_key *k);
void iam_it_dup(struct iam_iterator *dst, const struct iam_iterator *src);
void iam_it_put(struct iam_iterator *it);
int iam_it_next(struct iam_iterator *it);
struct iam_rec *iam_it_rec_get(const struct iam_iterator *it);
int iam_it_rec_set(handle_t *h,
                   struct iam_iterator *it, const struct iam_rec *r);
struct iam_key *iam_it_key_get(const struct iam_iterator *it);
int iam_it_key_size(const struct iam_iterator *it);
int iam_it_rec_insert(handle_t *h, struct iam_iterator *it,
                      const struct iam_key *k, const struct iam_rec *r);
int iam_it_rec_delete(handle_t *h, struct iam_iterator *it);

typedef __u64 iam_pos_t;

iam_pos_t iam_it_store(const struct iam_iterator *it);
int iam_it_load(struct iam_iterator *it, iam_pos_t pos);

int iam_lookup(struct iam_container *c, const struct iam_key *k,
               struct iam_rec *r, struct iam_path_descr *pd);
int iam_delete(handle_t *h, struct iam_container *c, const struct iam_key *k,
               struct iam_path_descr *pd);
int iam_update(handle_t *h, struct iam_container *c, const struct iam_key *k,
               const struct iam_rec *r, struct iam_path_descr *pd);
int iam_insert(handle_t *handle, struct iam_container *c,
               const struct iam_key *k,
               const struct iam_rec *r, struct iam_path_descr *pd);
/*
 * Initialize container @c.
 */
int iam_container_init(struct iam_container *c,
                       struct iam_descr *descr, struct inode *inode);
/*
 * Finalize container @c, release all resources.
 */
void iam_container_fini(struct iam_container *c);

/*
 * Determine container format.
 */
int iam_container_setup(struct iam_container *c);

static inline struct iam_descr *iam_container_descr(struct iam_container *c)
{
        return c->ic_descr;
}

static inline struct iam_descr *iam_path_descr(const struct iam_path *p)
{
        return p->ip_container->ic_descr;
}

static inline struct inode *iam_path_obj(struct iam_path *p)
{
        return p->ip_container->ic_object;
}

static inline void iam_ikeycpy(const struct iam_container *c,
                               struct iam_ikey *k1, const struct iam_ikey *k2)
{
        memcpy(k1, k2, c->ic_descr->id_ikey_size);
}

static inline size_t iam_entry_size(struct iam_path *p)
{
        return iam_path_descr(p)->id_ikey_size + iam_path_descr(p)->id_ptr_size;
}

static inline struct iam_entry *iam_entry_shift(struct iam_path *p,
                                                struct iam_entry *entry,
                                                int shift)
{
        void *e = entry;
        return e + shift * iam_entry_size(p);
}

static inline struct iam_ikey *dx_get_ikey(struct iam_path *p,
                                            struct iam_entry *entry,
                                            struct iam_ikey *key)
{
        return memcpy(key, entry, iam_path_descr(p)->id_ikey_size);
}

static inline struct iam_ikey *iam_ikey_at(struct iam_path *p,
                                           struct iam_entry *entry)
{
        return (struct iam_ikey *)entry;
}

static inline ptrdiff_t iam_entry_diff(struct iam_path *p,
                                       struct iam_entry *e1,
                                       struct iam_entry *e2)
{
        ptrdiff_t diff;

        diff = (void *)e1 - (void *)e2;
        assert_corr(diff / iam_entry_size(p) * iam_entry_size(p) == diff);
        return diff / iam_entry_size(p);
}

/*
 * Helper for the frequent case, where key was already placed into @k1 by
 * callback.
 */
static inline void iam_ikeycpy0(const struct iam_container *c,
                                struct iam_ikey *k1, const struct iam_ikey *k2)
{
        if (k1 != k2)
                iam_ikeycpy(c, k1, k2);
}

static inline int iam_ikeycmp(const struct iam_container *c,
                              const struct iam_ikey *k1,
                              const struct iam_ikey *k2)
{
        return c->ic_descr->id_ops->id_ikeycmp(c, k1, k2);
}

static inline void *iam_entry_off(struct iam_entry *entry, size_t off)
{
        return (void *)((char *)entry + off);
}

/*
 * Leaf helpers.
 */

static inline struct iam_path *iam_leaf_path(const struct iam_leaf *leaf)
{
        return leaf->il_path;
}

static inline struct iam_container *
iam_leaf_container(const struct iam_leaf *leaf)
{
        return iam_leaf_path(leaf)->ip_container;
}

static inline struct iam_descr *iam_leaf_descr(const struct iam_leaf *leaf)
{
        return iam_leaf_container(leaf)->ic_descr;
}

static inline const struct iam_leaf_operations *
iam_leaf_ops(const struct iam_leaf *leaf)
{
	return iam_leaf_descr(leaf)->id_leaf_ops;
}

static inline void iam_reccpy(const struct iam_leaf *leaf,
                              struct iam_rec *rec_dst)
{
        iam_leaf_ops(leaf)->rec_get(leaf, rec_dst);
}

/*XXX These stuff put here, just because they are used by iam.c */
static inline unsigned dx_get_block(struct iam_path *p, struct iam_entry *entry)
{
        u32 *addr;

        addr = iam_entry_off(entry, iam_path_descr(p)->id_ikey_size);
        return le32_to_cpu(get_unaligned(addr));
}

static inline void dx_set_block(struct iam_path *p,
                                struct iam_entry *entry, unsigned value)
{
        u32 *addr;

        addr = iam_entry_off(entry, iam_path_descr(p)->id_ikey_size);
        put_unaligned(cpu_to_le32(value), addr);
}

static inline void dx_set_ikey(struct iam_path *p, struct iam_entry *entry,
                               const struct iam_ikey *key)
{
        iam_ikeycpy(p->ip_container, iam_entry_off(entry, 0), key);
}

struct dx_map_entry
{
        u32 hash;
        u32 offs;
};

struct fake_dirent {
        __le32 inode;
        __le16 rec_len;
        u8 name_len;
        u8 file_type;
};

struct dx_countlimit {
	__le16 limit;
	__le16 count;
};

/*
 * dx_root_info is laid out so that if it should somehow get overlaid by a
 * dirent the two low bits of the hash version will be zero.  Therefore, the
 * hash version mod 4 should never be 0.  Sincerely, the paranoia department.
 */

struct dx_root {
        struct fake_dirent dot;
        char dot_name[4];
        struct fake_dirent dotdot;
        char dotdot_name[4];
        struct dx_root_info
        {
                __le32 reserved_zero;
                u8 hash_version;
                u8 info_length; /* 8 */
                u8 indirect_levels;
                u8 unused_flags;
        }
        info;
        struct {} entries[0];
};

struct dx_node
{
        struct fake_dirent fake;
        struct {} entries[0];
};


static inline unsigned dx_get_count(struct iam_entry *entries)
{
        return le16_to_cpu(((struct dx_countlimit *) entries)->count);
}

static inline unsigned dx_get_limit(struct iam_entry *entries)
{
        return le16_to_cpu(((struct dx_countlimit *) entries)->limit);
}

static inline void dx_set_count(struct iam_entry *entries, unsigned value)
{
        ((struct dx_countlimit *) entries)->count = cpu_to_le16(value);
}

static inline unsigned dx_node_limit(struct iam_path *p)
{
        struct iam_descr *param = iam_path_descr(p);
        unsigned entry_space   = iam_path_obj(p)->i_sb->s_blocksize -
                param->id_node_gap;
        return entry_space / (param->id_ikey_size + param->id_ptr_size);
}

static inline unsigned dx_root_limit(struct iam_path *p)
{
        struct iam_descr *param = iam_path_descr(p);
        unsigned limit = iam_path_obj(p)->i_sb->s_blocksize -
                param->id_root_gap;
        limit /= (param->id_ikey_size + param->id_ptr_size);
        if (limit == dx_node_limit(p))
                limit--;
        return limit;
}


static inline struct iam_entry *dx_get_entries(struct iam_path *path,
                                               void *data, int root)
{
        struct iam_descr *param = iam_path_descr(path);
        return data + (root ? param->id_root_gap : param->id_node_gap);
}


static inline struct iam_entry *dx_node_get_entries(struct iam_path *path,
                                                    struct iam_frame *frame)
{
        return dx_get_entries(path,
                              frame->bh->b_data, frame == path->ip_frames);
}

static inline struct iam_ikey *iam_path_ikey(const struct iam_path *path,
                                             int nr)
{
	LASSERT(0 <= nr && nr < ARRAY_SIZE(path->ip_data->ipd_key_scratch));
        return path->ip_data->ipd_key_scratch[nr];
}

static inline int iam_leaf_is_locked(const struct iam_leaf *leaf)
{
        int result;

	result = dynlock_is_locked(&iam_leaf_container(leaf)->ic_tree_lock,
				   leaf->il_curidx);
        if (!result)
                dump_stack();
        return result;
}

static inline int iam_frame_is_locked(struct iam_path *path,
                                      const struct iam_frame *frame)
{
        int result;

	result = dynlock_is_locked(&path->ip_container->ic_tree_lock,
				   frame->curidx);
        if (!result)
                dump_stack();
        return result;
}

int dx_lookup_lock(struct iam_path *path,
                   struct dynlock_handle **dl, enum dynlock_type lt);

void dx_insert_block(struct iam_path *path, struct iam_frame *frame,
                     u32 hash, u32 block);
int dx_index_is_compat(struct iam_path *path);

int ldiskfs_htree_next_block(struct inode *dir, __u32 hash,
                          struct iam_path *path, __u32 *start_hash);

int split_index_node(handle_t *handle, struct iam_path *path,
                     struct dynlock_handle **lh);
struct ldiskfs_dir_entry_2 *split_entry(struct inode *dir,
                                     struct ldiskfs_dir_entry_2 *de,
                                     unsigned long ino, mode_t mode,
                                     const char *name, int namelen);
struct ldiskfs_dir_entry_2 *find_insertion_point(struct inode *dir,
                                              struct buffer_head *bh,
                                              const char *name, int namelen);
struct ldiskfs_dir_entry_2 *move_entries(struct inode *dir,
                                      struct ldiskfs_dx_hash_info *hinfo,
                                      struct buffer_head **bh1,
                                      struct buffer_head **bh2,
                                      __u32 *delim_hash);

extern struct iam_descr iam_htree_compat_param;

struct dynlock_handle *dx_lock_htree(struct inode *dir, unsigned long value,
                                     enum dynlock_type lt);
void dx_unlock_htree(struct inode *dir, struct dynlock_handle *lh);

/*
 * external
 */
void iam_container_write_lock(struct iam_container *c);
void iam_container_write_unlock(struct iam_container *c);

void iam_container_read_lock(struct iam_container *c);
void iam_container_read_unlock(struct iam_container *c);

int iam_index_next(struct iam_container *c, struct iam_path *p);
int iam_read_leaf(struct iam_path *p);

int iam_node_read(struct iam_container *c, iam_ptr_t ptr,
                  handle_t *handle, struct buffer_head **bh);
int iam_lvar_create(struct inode *obj,
                    int keysize, int ptrsize, int recsize, handle_t *handle);

#ifndef swap
#define swap(x, y) do { typeof(x) z = x; x = y; y = z; } while (0)
#endif

#ifdef DX_DEBUG
#define dxtrace(command) command
#else
#define dxtrace(command) 
#endif

#define BH_DXLock        (BH_BITMAP_UPTODATE + 1)
#define DX_DEBUG (0)
#if DX_DEBUG
static struct iam_lock_stats {
        unsigned dls_bh_lock;
        unsigned dls_bh_busy;
        unsigned dls_bh_again;
        unsigned dls_bh_full_again;
} iam_lock_stats = { 0, };
#define DX_DEVAL(x) x
#else
#define DX_DEVAL(x)
#endif

static inline void iam_lock_bh(struct buffer_head volatile *bh)
{
        DX_DEVAL(iam_lock_stats.dls_bh_lock++);
#ifdef CONFIG_SMP
	while (test_and_set_bit_lock(BH_DXLock, &bh->b_state)) {
		DX_DEVAL(iam_lock_stats.dls_bh_busy++);
		while (test_bit(BH_DXLock, &bh->b_state))
                        cpu_relax();
        }
#endif
}

static inline void iam_unlock_bh(struct buffer_head *bh)
{
#ifdef CONFIG_SMP
	clear_bit_unlock(BH_DXLock, &bh->b_state);
#endif
}


void iam_insert_key(struct iam_path *path, struct iam_frame *frame,
                    const struct iam_ikey *key, iam_ptr_t ptr);

void iam_insert_key_lock(struct iam_path *path, struct iam_frame *frame,
                         const struct iam_ikey *key, iam_ptr_t ptr);


int  iam_leaf_at_end(const struct iam_leaf *l);
void iam_leaf_next(struct iam_leaf *folio);
int iam_leaf_can_add(const struct iam_leaf *l,
                     const struct iam_key *k, const struct iam_rec *r);

struct iam_path *iam_leaf_path(const struct iam_leaf *leaf);
struct iam_container *iam_leaf_container(const struct iam_leaf *leaf);
struct iam_descr *iam_leaf_descr(const struct iam_leaf *leaf);
const struct iam_leaf_operations *iam_leaf_ops(const struct iam_leaf *leaf);


int iam_node_read(struct iam_container *c, iam_ptr_t ptr,
                  handle_t *h, struct buffer_head **bh);

int iam_root_limit(int rootgap, int blocksize, int size);

void iam_lfix_format_init(void);
void iam_lvar_format_init(void);
int iam_lfix_guess(struct iam_container *c);
int iam_lvar_guess(struct iam_container *c);
void iam_htree_format_init(void);

int iam_lfix_create(struct inode *obj,
                    int keysize, int ptrsize, int recsize, handle_t *handle);
struct iam_private_info;

void ldiskfs_iam_release(struct file *filp, struct inode *inode);

int iam_uapi_ioctl(struct inode * inode, struct file * filp, unsigned int cmd,
                   unsigned long arg);

/* dir.c 
#if LDISKFS_INVARIANT_ON
extern int ldiskfs_check_dir_entry(const char *, struct inode *,
                                struct ldiskfs_dir_entry_2 *,
                                struct buffer_head *, unsigned long);
extern int dx_node_check(struct iam_path *p, struct iam_frame *f);
#else
static inline int ldiskfs_check_dir_entry(const char * function,
                                       struct inode * dir,
                                       struct ldiskfs_dir_entry_2 * de,
                                       struct buffer_head * bh,
                                       unsigned long offset)
{
        return 1;
}
#endif
*/

/* __KERNEL__ */

/*
 * User level API. Copy exists in lustre/lustre/tests/iam_ut.c
 */

struct iam_uapi_info {
        __u16 iui_keysize;
        __u16 iui_recsize;
        __u16 iui_ptrsize;
        __u16 iui_height;
        char  iui_fmt_name[DX_FMT_NAME_LEN];
};

struct iam_uapi_op {
        void *iul_key;
        void *iul_rec;
};

struct iam_uapi_it {
        struct iam_uapi_op iui_op;
        __u16              iui_state;
};

enum iam_ioctl_cmd {
        IAM_IOC_INIT     = _IOW('i', 1, struct iam_uapi_info),
        IAM_IOC_GETINFO  = _IOR('i', 2, struct iam_uapi_info),
        IAM_IOC_INSERT   = _IOR('i', 3, struct iam_uapi_op),
        IAM_IOC_LOOKUP   = _IOWR('i', 4, struct iam_uapi_op),
        IAM_IOC_DELETE   = _IOR('i', 5, struct iam_uapi_op),
        IAM_IOC_IT_START = _IOR('i', 6, struct iam_uapi_it),
        IAM_IOC_IT_NEXT  = _IOW('i', 7, struct iam_uapi_it),
        IAM_IOC_IT_STOP  = _IOR('i', 8, struct iam_uapi_it),

        IAM_IOC_POLYMORPH = _IOR('i', 9, unsigned long)
};

/* __LINUX_LUSTRE_IAM_H__ */
#endif
