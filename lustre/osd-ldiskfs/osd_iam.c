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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * iam.c
 * Top-level entry points into iam module
 *
 * Author: Wang Di <wangdi@clusterfs.com>
 * Author: Nikita Danilov <nikita@clusterfs.com>
 */

/*
 * iam: big theory statement.
 *
 * iam (Index Access Module) is a module providing abstraction of persistent
 * transactional container on top of generalized ldiskfs htree.
 *
 * iam supports:
 *
 *     - key, pointer, and record size specifiable per container.
 *
 *     - trees taller than 2 index levels.
 *
 *     - read/write to existing ldiskfs htree directories as iam containers.
 *
 * iam container is a tree, consisting of leaf nodes containing keys and
 * records stored in this container, and index nodes, containing keys and
 * pointers to leaf or index nodes.
 *
 * iam does not work with keys directly, instead it calls user-supplied key
 * comparison function (->dpo_keycmp()).
 *
 * Pointers are (currently) interpreted as logical offsets (measured in
 * blocksful) within underlying flat file on top of which iam tree lives.
 *
 * On-disk format:
 *
 * iam mostly tries to reuse existing htree formats.
 *
 * Format of index node:
 *
 * +-----+-------+-------+-------+------+-------+------------+
 * |     | count |       |       |      |       |            |
 * | gap |   /   | entry | entry | .... | entry | free space |
 * |     | limit |       |       |      |       |            |
 * +-----+-------+-------+-------+------+-------+------------+
 *
 *       gap           this part of node is never accessed by iam code. It
 *                     exists for binary compatibility with ldiskfs htree (that,
 *                     in turn, stores fake struct ext2_dirent for ext2
 *                     compatibility), and to keep some unspecified per-node
 *                     data. Gap can be different for root and non-root index
 *                     nodes. Gap size can be specified for each container
 *                     (gap of 0 is allowed).
 *
 *       count/limit   current number of entries in this node, and the maximal
 *                     number of entries that can fit into node. count/limit
 *                     has the same size as entry, and is itself counted in
 *                     count.
 *
 *       entry         index entry: consists of a key immediately followed by
 *                     a pointer to a child node. Size of a key and size of a
 *                     pointer depends on container. Entry has neither
 *                     alignment nor padding.
 *
 *       free space    portion of node new entries are added to
 *
 * Entries in index node are sorted by their key value.
 *
 * Format of a leaf node is not specified. Generic iam code accesses leaf
 * nodes through ->id_leaf methods in struct iam_descr.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/time.h>
#include <linux/fcntl.h>
#include <linux/stat.h>
#include <linux/string.h>
#include <linux/quotaops.h>
#include <linux/buffer_head.h>
#include <linux/smp_lock.h>
#include "osd_internal.h"

#include "xattr.h"
#include "acl.h"

/*
 * List of all registered formats.
 *
 * No locking. Callers synchronize.
 */
static CFS_LIST_HEAD(iam_formats);

void iam_format_register(struct iam_format *fmt)
{
        cfs_list_add(&fmt->if_linkage, &iam_formats);
}
EXPORT_SYMBOL(iam_format_register);

/*
 * Determine format of given container. This is done by scanning list of
 * registered formats and calling ->if_guess() method of each in turn.
 */
static int iam_format_guess(struct iam_container *c)
{
        int result;
        struct iam_format *fmt;

        /*
         * XXX temporary initialization hook.
         */
        {
                static int initialized = 0;

                if (!initialized) {
                        iam_lvar_format_init();
                        iam_lfix_format_init();
                        initialized = 1;
                }
        }

        result = -ENOENT;
        cfs_list_for_each_entry(fmt, &iam_formats, if_linkage) {
                result = fmt->if_guess(c);
                if (result == 0)
                        break;
        }
        return result;
}

/*
 * Initialize container @c.
 */
int iam_container_init(struct iam_container *c,
                       struct iam_descr *descr, struct inode *inode)
{
        memset(c, 0, sizeof *c);
        c->ic_descr  = descr;
        c->ic_object = inode;
        cfs_init_rwsem(&c->ic_sem);
        return 0;
}
EXPORT_SYMBOL(iam_container_init);

/*
 * Determine container format.
 */
int iam_container_setup(struct iam_container *c)
{
        return iam_format_guess(c);
}
EXPORT_SYMBOL(iam_container_setup);

/*
 * Finalize container @c, release all resources.
 */
void iam_container_fini(struct iam_container *c)
{
}
EXPORT_SYMBOL(iam_container_fini);

void iam_path_init(struct iam_path *path, struct iam_container *c,
                   struct iam_path_descr *pd)
{
        memset(path, 0, sizeof *path);
        path->ip_container = c;
        path->ip_frame = path->ip_frames;
        path->ip_data = pd;
        path->ip_leaf.il_path = path;
}

static void iam_leaf_fini(struct iam_leaf *leaf);

void iam_path_release(struct iam_path *path)
{
        int i;

        for (i = 0; i < ARRAY_SIZE(path->ip_frames); i++) {
                if (path->ip_frames[i].bh != NULL) {
                        brelse(path->ip_frames[i].bh);
                        path->ip_frames[i].bh = NULL;
                }
        }
}

void iam_path_fini(struct iam_path *path)
{
        iam_leaf_fini(&path->ip_leaf);
        iam_path_release(path);
}


void iam_path_compat_init(struct iam_path_compat *path, struct inode *inode)
{
        int i;

        path->ipc_hinfo = &path->ipc_hinfo_area;
        for (i = 0; i < ARRAY_SIZE(path->ipc_scratch); ++i)
                path->ipc_descr.ipd_key_scratch[i] =
                        (struct iam_ikey *)&path->ipc_scratch[i];

        iam_path_init(&path->ipc_path, &path->ipc_container, &path->ipc_descr);
}

void iam_path_compat_fini(struct iam_path_compat *path)
{
        iam_path_fini(&path->ipc_path);
}

/*
 * Helper function initializing iam_path_descr and its key scratch area.
 */
struct iam_path_descr *iam_ipd_alloc(void *area, int keysize)
{
        struct iam_path_descr *ipd;
        void *karea;
        int i;

        ipd = area;
        karea = ipd + 1;
        for (i = 0; i < ARRAY_SIZE(ipd->ipd_key_scratch); ++i, karea += keysize)
                ipd->ipd_key_scratch[i] = karea;
        return ipd;
}
EXPORT_SYMBOL(iam_ipd_alloc);

void iam_ipd_free(struct iam_path_descr *ipd)
{
}
EXPORT_SYMBOL(iam_ipd_free);

int iam_node_read(struct iam_container *c, iam_ptr_t ptr,
                  handle_t *h, struct buffer_head **bh)
{
        int result = 0;

        *bh = ldiskfs_bread(h, c->ic_object, (int)ptr, 0, &result);
        if (*bh == NULL)
                result = -EIO;
        return result;
}

/*
 * Return pointer to current leaf record. Pointer is valid while corresponding
 * leaf node is locked and pinned.
 */
static struct iam_rec *iam_leaf_rec(const struct iam_leaf *leaf)
{
        return iam_leaf_ops(leaf)->rec(leaf);
}

/*
 * Return pointer to the current leaf key. This function returns pointer to
 * the key stored in node.
 *
 * Caller should assume that returned pointer is only valid while leaf node is
 * pinned and locked.
 */
static struct iam_key *iam_leaf_key(const struct iam_leaf *leaf)
{
        return iam_leaf_ops(leaf)->key(leaf);
}

static int iam_leaf_key_size(const struct iam_leaf *leaf)
{
        return iam_leaf_ops(leaf)->key_size(leaf);
}

static struct iam_ikey *iam_leaf_ikey(const struct iam_leaf *leaf,
                                      struct iam_ikey *key)
{
        return iam_leaf_ops(leaf)->ikey(leaf, key);
}

static int iam_leaf_keycmp(const struct iam_leaf *leaf,
                           const struct iam_key *key)
{
        return iam_leaf_ops(leaf)->key_cmp(leaf, key);
}

static int iam_leaf_keyeq(const struct iam_leaf *leaf,
                          const struct iam_key *key)
{
        return iam_leaf_ops(leaf)->key_eq(leaf, key);
}

#if LDISKFS_INVARIANT_ON
static int iam_leaf_check(struct iam_leaf *leaf);
extern int dx_node_check(struct iam_path *p, struct iam_frame *f);

static int iam_path_check(struct iam_path *p)
{
        int i;
        int result;
        struct iam_frame *f;
        struct iam_descr *param;

        result = 1;
        param = iam_path_descr(p);
        for (i = 0; result && i < ARRAY_SIZE(p->ip_frames); ++i) {
                f = &p->ip_frames[i];
                if (f->bh != NULL) {
                        result = dx_node_check(p, f);
                        if (result)
                                result = !param->id_ops->id_node_check(p, f);
                }
        }
        if (result && p->ip_leaf.il_bh != NULL)
                result = iam_leaf_check(&p->ip_leaf);
        if (result == 0) {
                ldiskfs_std_error(iam_path_obj(p)->i_sb, result);
        }
        return result;
}
#endif

static int iam_leaf_load(struct iam_path *path)
{
        iam_ptr_t block;
        int err;
        struct iam_container *c;
        struct buffer_head   *bh;
        struct iam_leaf      *leaf;
        struct iam_descr     *descr;

        c     = path->ip_container;
        leaf  = &path->ip_leaf;
        descr = iam_path_descr(path);
        block = path->ip_frame->leaf;
        if (block == 0) {
                /* XXX bug 11027 */
                printk(CFS_KERN_EMERG "wrong leaf: %lu %d [%p %p %p]\n",
                       (long unsigned)path->ip_frame->leaf,
                       dx_get_count(dx_node_get_entries(path, path->ip_frame)),
                       path->ip_frames[0].bh, path->ip_frames[1].bh,
                       path->ip_frames[2].bh);
        }
        err   = descr->id_ops->id_node_read(c, block, NULL, &bh);
        if (err == 0) {
                leaf->il_bh = bh;
                leaf->il_curidx = block;
                err = iam_leaf_ops(leaf)->init(leaf);
                assert_inv(ergo(err == 0, iam_leaf_check(leaf)));
        }
        return err;
}

static void iam_unlock_htree(struct inode *dir, struct dynlock_handle *lh)
{
        if (lh != NULL)
                dynlock_unlock(&LDISKFS_I(dir)->i_htree_lock, lh);
}


static void iam_leaf_unlock(struct iam_leaf *leaf)
{
        if (leaf->il_lock != NULL) {
                iam_unlock_htree(iam_leaf_container(leaf)->ic_object,
                                leaf->il_lock);
                do_corr(schedule());
                leaf->il_lock = NULL;
        }
}

static void iam_leaf_fini(struct iam_leaf *leaf)
{
        if (leaf->il_path != NULL) {
                iam_leaf_unlock(leaf);
                assert_inv(ergo(leaf->il_bh != NULL, iam_leaf_check(leaf)));
                iam_leaf_ops(leaf)->fini(leaf);
                if (leaf->il_bh) {
                        brelse(leaf->il_bh);
                        leaf->il_bh = NULL;
                        leaf->il_curidx = 0;
                }
        }
}

static void iam_leaf_start(struct iam_leaf *folio)
{
        iam_leaf_ops(folio)->start(folio);
}

void iam_leaf_next(struct iam_leaf *folio)
{
        iam_leaf_ops(folio)->next(folio);
}

static void iam_leaf_rec_add(struct iam_leaf *leaf, const struct iam_key *key,
                             const struct iam_rec *rec)
{
        iam_leaf_ops(leaf)->rec_add(leaf, key, rec);
}

static void iam_rec_del(struct iam_leaf *leaf, int shift)
{
        iam_leaf_ops(leaf)->rec_del(leaf, shift);
}

int iam_leaf_at_end(const struct iam_leaf *leaf)
{
        return iam_leaf_ops(leaf)->at_end(leaf);
}

void iam_leaf_split(struct iam_leaf *l, struct buffer_head **bh, iam_ptr_t nr)
{
        iam_leaf_ops(l)->split(l, bh, nr);
}

int iam_leaf_can_add(const struct iam_leaf *l,
                     const struct iam_key *k, const struct iam_rec *r)
{
        return iam_leaf_ops(l)->can_add(l, k, r);
}

#if LDISKFS_INVARIANT_ON
static int iam_leaf_check(struct iam_leaf *leaf)
{
        return 1;
#if 0
        struct iam_lentry    *orig;
        struct iam_path      *path;
        struct iam_container *bag;
        struct iam_ikey       *k0;
        struct iam_ikey       *k1;
        int result;
        int first;

        orig = leaf->il_at;
        path = iam_leaf_path(leaf);
        bag  = iam_leaf_container(leaf);

        result = iam_leaf_ops(leaf)->init(leaf);
        if (result != 0)
                return result;

        first = 1;
        iam_leaf_start(leaf);
        k0 = iam_path_ikey(path, 0);
        k1 = iam_path_ikey(path, 1);
        while (!iam_leaf_at_end(leaf)) {
                iam_ikeycpy(bag, k0, k1);
                iam_ikeycpy(bag, k1, iam_leaf_ikey(leaf, k1));
                if (!first && iam_ikeycmp(bag, k0, k1) > 0) {
                        return 0;
                }
                first = 0;
                iam_leaf_next(leaf);
        }
        leaf->il_at = orig;
        return 1;
#endif
}
#endif

static int iam_txn_dirty(handle_t *handle,
                         struct iam_path *path, struct buffer_head *bh)
{
        int result;

        result = ldiskfs_journal_dirty_metadata(handle, bh);
        if (result != 0)
                ldiskfs_std_error(iam_path_obj(path)->i_sb, result);
        return result;
}

static int iam_txn_add(handle_t *handle,
                       struct iam_path *path, struct buffer_head *bh)
{
        int result;

        result = ldiskfs_journal_get_write_access(handle, bh);
        if (result != 0)
                ldiskfs_std_error(iam_path_obj(path)->i_sb, result);
        return result;
}

/***********************************************************************/
/* iterator interface                                                  */
/***********************************************************************/

static enum iam_it_state it_state(const struct iam_iterator *it)
{
        return it->ii_state;
}

/*
 * Helper function returning scratch key.
 */
static struct iam_container *iam_it_container(const struct iam_iterator *it)
{
        return it->ii_path.ip_container;
}

static inline int it_keycmp(const struct iam_iterator *it,
                            const struct iam_key *k)
{
        return iam_leaf_keycmp(&it->ii_path.ip_leaf, k);
}

static inline int it_keyeq(const struct iam_iterator *it,
                           const struct iam_key *k)
{
        return iam_leaf_keyeq(&it->ii_path.ip_leaf, k);
}

static int it_ikeycmp(const struct iam_iterator *it, const struct iam_ikey *ik)
{
        return iam_ikeycmp(it->ii_path.ip_container,
                           iam_leaf_ikey(&it->ii_path.ip_leaf,
                                         iam_path_ikey(&it->ii_path, 0)), ik);
}

static inline int it_at_rec(const struct iam_iterator *it)
{
        return !iam_leaf_at_end(&it->ii_path.ip_leaf);
}

static inline int it_before(const struct iam_iterator *it)
{
        return it_state(it) == IAM_IT_SKEWED && it_at_rec(it);
}

/*
 * Helper wrapper around iam_it_get(): returns 0 (success) only when record
 * with exactly the same key as asked is found.
 */
static int iam_it_get_exact(struct iam_iterator *it, const struct iam_key *k)
{
        int result;

        result = iam_it_get(it, k);
        if (result > 0)
                result = 0;
        else if (result == 0)
                /*
                 * Return -ENOENT if cursor is located above record with a key
                 * different from one specified, or in the empty leaf.
                 *
                 * XXX returning -ENOENT only works if iam_it_get() never
                 * returns -ENOENT as a legitimate error.
                 */
                result = -ENOENT;
        return result;
}

void iam_container_write_lock(struct iam_container *ic)
{
        cfs_down_write(&ic->ic_sem);
}

void iam_container_write_unlock(struct iam_container *ic)
{
        cfs_up_write(&ic->ic_sem);
}

void iam_container_read_lock(struct iam_container *ic)
{
        cfs_down_read(&ic->ic_sem);
}

void iam_container_read_unlock(struct iam_container *ic)
{
        cfs_up_read(&ic->ic_sem);
}

/*
 * Initialize iterator to IAM_IT_DETACHED state.
 *
 * postcondition: it_state(it) == IAM_IT_DETACHED
 */
int  iam_it_init(struct iam_iterator *it, struct iam_container *c, __u32 flags,
                 struct iam_path_descr *pd)
{
        memset(it, 0, sizeof *it);
        it->ii_flags  = flags;
        it->ii_state  = IAM_IT_DETACHED;
        iam_path_init(&it->ii_path, c, pd);
        return 0;
}
EXPORT_SYMBOL(iam_it_init);

/*
 * Finalize iterator and release all resources.
 *
 * precondition: it_state(it) == IAM_IT_DETACHED
 */
void iam_it_fini(struct iam_iterator *it)
{
        assert_corr(it_state(it) == IAM_IT_DETACHED);
        iam_path_fini(&it->ii_path);
}
EXPORT_SYMBOL(iam_it_fini);

/*
 * this locking primitives are used to protect parts
 * of dir's htree. protection unit is block: leaf or index
 */
struct dynlock_handle *iam_lock_htree(struct inode *dir, unsigned long value,
                                     enum dynlock_type lt)
{
        return dynlock_lock(&LDISKFS_I(dir)->i_htree_lock, value, lt, GFP_NOFS);
}



int iam_index_lock(struct iam_path *path, struct dynlock_handle **lh)
{
        struct iam_frame *f;

        for (f = path->ip_frame; f >= path->ip_frames; --f, ++lh) {
                do_corr(schedule());
                *lh = iam_lock_htree(iam_path_obj(path), f->curidx, DLT_READ);
                if (*lh == NULL)
                        return -ENOMEM;
        }
        return 0;
}

/*
 * Fast check for frame consistency.
 */
static int iam_check_fast(struct iam_path *path, struct iam_frame *frame)
{
        struct iam_container *bag;
        struct iam_entry *next;
        struct iam_entry *last;
        struct iam_entry *entries;
        struct iam_entry *at;

        bag     = path->ip_container;
        at      = frame->at;
        entries = frame->entries;
        last    = iam_entry_shift(path, entries, dx_get_count(entries) - 1);

        if (unlikely(at > last))
                return -EAGAIN;

        if (unlikely(dx_get_block(path, at) != frame->leaf))
                return -EAGAIN;

        if (unlikely(iam_ikeycmp(bag, iam_ikey_at(path, at),
                                 path->ip_ikey_target) > 0))
                return -EAGAIN;

        next = iam_entry_shift(path, at, +1);
        if (next <= last) {
                if (unlikely(iam_ikeycmp(bag, iam_ikey_at(path, next),
                                         path->ip_ikey_target) <= 0))
                        return -EAGAIN;
        }
        return 0;
}

int dx_index_is_compat(struct iam_path *path)
{
        return iam_path_descr(path) == NULL;
}

/*
 * dx_find_position
 *
 * search position of specified hash in index
 *
 */

struct iam_entry *iam_find_position(struct iam_path *path,
                                   struct iam_frame *frame)
{
        int count;
        struct iam_entry *p;
        struct iam_entry *q;
        struct iam_entry *m;

        count = dx_get_count(frame->entries);
        assert_corr(count && count <= dx_get_limit(frame->entries));
        p = iam_entry_shift(path, frame->entries,
                            dx_index_is_compat(path) ? 1 : 2);
        q = iam_entry_shift(path, frame->entries, count - 1);
        while (p <= q) {
                m = iam_entry_shift(path, p, iam_entry_diff(path, q, p) / 2);
                if (iam_ikeycmp(path->ip_container, iam_ikey_at(path, m),
                                path->ip_ikey_target) > 0)
                        q = iam_entry_shift(path, m, -1);
                else
                        p = iam_entry_shift(path, m, +1);
        }
        return iam_entry_shift(path, p, -1);
}



static iam_ptr_t iam_find_ptr(struct iam_path *path, struct iam_frame *frame)
{
        return dx_get_block(path, iam_find_position(path, frame));
}

void iam_insert_key(struct iam_path *path, struct iam_frame *frame,
                    const struct iam_ikey *key, iam_ptr_t ptr)
{
        struct iam_entry *entries = frame->entries;
        struct iam_entry *new = iam_entry_shift(path, frame->at, +1);
        int count = dx_get_count(entries);

        /*
         * Unfortunately we cannot assert this, as this function is sometimes
         * called by VFS under i_sem and without pdirops lock.
         */
        assert_corr(1 || iam_frame_is_locked(path, frame));
        assert_corr(count < dx_get_limit(entries));
        assert_corr(frame->at < iam_entry_shift(path, entries, count));
        assert_inv(dx_node_check(path, frame));

        memmove(iam_entry_shift(path, new, 1), new,
                (char *)iam_entry_shift(path, entries, count) - (char *)new);
        dx_set_ikey(path, new, key);
        dx_set_block(path, new, ptr);
        dx_set_count(entries, count + 1);
        assert_inv(dx_node_check(path, frame));
}

void iam_insert_key_lock(struct iam_path *path, struct iam_frame *frame,
                         const struct iam_ikey *key, iam_ptr_t ptr)
{
        iam_lock_bh(frame->bh);
        iam_insert_key(path, frame, key, ptr);
        iam_unlock_bh(frame->bh);
}
/*
 * returns 0 if path was unchanged, -EAGAIN otherwise.
 */
static int iam_check_path(struct iam_path *path, struct iam_frame *frame)
{
        int equal;

        iam_lock_bh(frame->bh);
        equal = iam_check_fast(path, frame) == 0 ||
                frame->leaf == iam_find_ptr(path, frame);
        DX_DEVAL(iam_lock_stats.dls_bh_again += !equal);
        iam_unlock_bh(frame->bh);

        return equal ? 0 : -EAGAIN;
}

static int iam_lookup_try(struct iam_path *path)
{
        u32 ptr;
        int err = 0;
        int i;

        struct iam_descr *param;
        struct iam_frame *frame;
        struct iam_container *c;

        param = iam_path_descr(path);
        c = path->ip_container;

        ptr = param->id_ops->id_root_ptr(c);
        for (frame = path->ip_frames, i = 0; i <= path->ip_indirect;
             ++frame, ++i) {
                err = param->id_ops->id_node_read(c, (iam_ptr_t)ptr, NULL,
                                                  &frame->bh);
                do_corr(schedule());

                iam_lock_bh(frame->bh);
                /*
                 * node must be initialized under bh lock because concurrent
                 * creation procedure may change it and iam_lookup_try() will
                 * see obsolete tree height. -bzzz
                 */
                if (err != 0)
                        break;

                if (LDISKFS_INVARIANT_ON) {
                        err = param->id_ops->id_node_check(path, frame);
                        if (err != 0)
                                break;
                }

                err = param->id_ops->id_node_load(path, frame);
                if (err != 0)
                        break;

                assert_inv(dx_node_check(path, frame));
                /*
                 * splitting may change root index block and move hash we're
                 * looking for into another index block so, we have to check
                 * this situation and repeat from begining if path got changed
                 * -bzzz
                 */
                if (i > 0) {
                        err = iam_check_path(path, frame - 1);
                        if (err != 0)
                                break;
                }

                frame->at = iam_find_position(path, frame);
                frame->curidx = ptr;
                frame->leaf = ptr = dx_get_block(path, frame->at);

                iam_unlock_bh(frame->bh);
                do_corr(schedule());
        }
        if (err != 0)
                iam_unlock_bh(frame->bh);
        path->ip_frame = --frame;
        return err;
}

static int __iam_path_lookup(struct iam_path *path)
{
        int err;
        int i;

        for (i = 0; i < DX_MAX_TREE_HEIGHT; ++ i)
                assert(path->ip_frames[i].bh == NULL);

        do {
                err = iam_lookup_try(path);
                do_corr(schedule());
                if (err != 0)
                        iam_path_fini(path);
        } while (err == -EAGAIN);

        return err;
}

/*
 * returns 0 if path was unchanged, -EAGAIN otherwise.
 */
static int iam_check_full_path(struct iam_path *path, int search)
{
        struct iam_frame *bottom;
        struct iam_frame *scan;
        int i;
        int result;

        do_corr(schedule());

        for (bottom = path->ip_frames, i = 0;
             i < DX_MAX_TREE_HEIGHT && bottom->bh != NULL; ++bottom, ++i) {
                ; /* find last filled in frame */
        }

        /*
         * Lock frames, bottom to top.
         */
        for (scan = bottom - 1; scan >= path->ip_frames; --scan)
                iam_lock_bh(scan->bh);
        /*
         * Check them top to bottom.
         */
        result = 0;
        for (scan = path->ip_frames; scan < bottom; ++scan) {
                struct iam_entry *pos;

                if (search) {
                        if (iam_check_fast(path, scan) == 0)
                                continue;

                        pos = iam_find_position(path, scan);
                        if (scan->leaf != dx_get_block(path, pos)) {
                                result = -EAGAIN;
                                break;
                        }
                        scan->at = pos;
                } else {
                        pos = iam_entry_shift(path, scan->entries,
                                              dx_get_count(scan->entries) - 1);
                        if (scan->at > pos ||
                            scan->leaf != dx_get_block(path, scan->at)) {
                                result = -EAGAIN;
                                break;
                        }
                }
        }

        /*
         * Unlock top to bottom.
         */
        for (scan = path->ip_frames; scan < bottom; ++scan)
                iam_unlock_bh(scan->bh);
        DX_DEVAL(iam_lock_stats.dls_bh_full_again += !!result);
        do_corr(schedule());

        return result;
}


/*
 * Performs path lookup and returns with found leaf (if any) locked by htree
 * lock.
 */
int iam_lookup_lock(struct iam_path *path,
                   struct dynlock_handle **dl, enum dynlock_type lt)
{
        int result;
        struct inode *dir;

        dir = iam_path_obj(path);
        while ((result = __iam_path_lookup(path)) == 0) {
                do_corr(schedule());
                *dl = iam_lock_htree(dir, path->ip_frame->leaf, lt);
                if (*dl == NULL) {
                        iam_path_fini(path);
                        result = -ENOMEM;
                        break;
                }
                do_corr(schedule());
                /*
                 * while locking leaf we just found may get split so we need
                 * to check this -bzzz
                 */
                if (iam_check_full_path(path, 1) == 0)
                        break;
                iam_unlock_htree(dir, *dl);
                *dl = NULL;
                iam_path_fini(path);
        }
        return result;
}
/*
 * Performs tree top-to-bottom traversal starting from root, and loads leaf
 * node.
 */
static int iam_path_lookup(struct iam_path *path, int index)
{
        struct iam_container *c;
        struct iam_descr *descr;
        struct iam_leaf  *leaf;
        int result;

        c = path->ip_container;
        leaf = &path->ip_leaf;
        descr = iam_path_descr(path);
        result = iam_lookup_lock(path, &leaf->il_lock, DLT_WRITE);
        assert_inv(iam_path_check(path));
        do_corr(schedule());
        if (result == 0) {
                result = iam_leaf_load(path);
                assert_inv(ergo(result == 0, iam_leaf_check(leaf)));
                if (result == 0) {
                        do_corr(schedule());
                        if (index)
                                result = iam_leaf_ops(leaf)->
                                        ilookup(leaf, path->ip_ikey_target);
                        else
                                result = iam_leaf_ops(leaf)->
                                        lookup(leaf, path->ip_key_target);
                        do_corr(schedule());
                }
                if (result < 0)
                        iam_leaf_unlock(leaf);
        }
        return result;
}

/*
 * Common part of iam_it_{i,}get().
 */
static int __iam_it_get(struct iam_iterator *it, int index)
{
        int result;
        assert_corr(it_state(it) == IAM_IT_DETACHED);

        result = iam_path_lookup(&it->ii_path, index);
        if (result >= 0) {
                int collision;

                collision = result & IAM_LOOKUP_LAST;
                switch (result & ~IAM_LOOKUP_LAST) {
                case IAM_LOOKUP_EXACT:
                        result = +1;
                        it->ii_state = IAM_IT_ATTACHED;
                        break;
                case IAM_LOOKUP_OK:
                        result = 0;
                        it->ii_state = IAM_IT_ATTACHED;
                        break;
                case IAM_LOOKUP_BEFORE:
                case IAM_LOOKUP_EMPTY:
                        result = 0;
                        it->ii_state = IAM_IT_SKEWED;
                        break;
                default:
                        assert(0);
                }
                result |= collision;
        }
        /*
         * See iam_it_get_exact() for explanation.
         */
        assert_corr(result != -ENOENT);
        return result;
}

/*
 * Correct hash, but not the same key was found, iterate through hash
 * collision chain, looking for correct record.
 */
static int iam_it_collision(struct iam_iterator *it)
{
        int result;

        assert(ergo(it_at_rec(it), !it_keyeq(it, it->ii_path.ip_key_target)));

        while ((result = iam_it_next(it)) == 0) {
                do_corr(schedule());
                if (it_ikeycmp(it, it->ii_path.ip_ikey_target) != 0)
                        return -ENOENT;
                if (it_keyeq(it, it->ii_path.ip_key_target))
                        return 0;
        }
        return result;
}

/*
 * Attach iterator. After successful completion, @it points to record with
 * least key not larger than @k.
 *
 * Return value: 0: positioned on existing record,
 *             +ve: exact position found,
 *             -ve: error.
 *
 * precondition:  it_state(it) == IAM_IT_DETACHED
 * postcondition: ergo(result == 0 && it_state(it) == IAM_IT_ATTACHED,
 *                     it_keycmp(it, k) <= 0)
 */
int iam_it_get(struct iam_iterator *it, const struct iam_key *k)
{
        int result;
        assert_corr(it_state(it) == IAM_IT_DETACHED);

        it->ii_path.ip_ikey_target = NULL;
        it->ii_path.ip_key_target  = k;

        result = __iam_it_get(it, 0);

        if (result == IAM_LOOKUP_LAST) {
                result = iam_it_collision(it);
                if (result != 0) {
                        iam_it_put(it);
                        iam_it_fini(it);
                        result = __iam_it_get(it, 0);
                } else
                        result = +1;
        }
        if (result > 0)
                result &= ~IAM_LOOKUP_LAST;

        assert_corr(ergo(result > 0, it_keycmp(it, k) == 0));
        assert_corr(ergo(result == 0 && it_state(it) == IAM_IT_ATTACHED,
                         it_keycmp(it, k) <= 0));
        return result;
}
EXPORT_SYMBOL(iam_it_get);

/*
 * Attach iterator by index key.
 */
static int iam_it_iget(struct iam_iterator *it, const struct iam_ikey *k)
{
        assert_corr(it_state(it) == IAM_IT_DETACHED);

        it->ii_path.ip_ikey_target = k;
        return __iam_it_get(it, 1) & ~IAM_LOOKUP_LAST;
}

/*
 * Attach iterator, and assure it points to the record (not skewed).
 *
 * Return value: 0: positioned on existing record,
 *             +ve: exact position found,
 *             -ve: error.
 *
 * precondition:  it_state(it) == IAM_IT_DETACHED &&
 *                !(it->ii_flags&IAM_IT_WRITE)
 * postcondition: ergo(result == 0, it_state(it) == IAM_IT_ATTACHED)
 */
int iam_it_get_at(struct iam_iterator *it, const struct iam_key *k)
{
        int result;
        assert_corr(it_state(it) == IAM_IT_DETACHED &&
                    !(it->ii_flags&IAM_IT_WRITE));
        result = iam_it_get(it, k);
        if (result == 0) {
                if (it_state(it) != IAM_IT_ATTACHED) {
                        assert_corr(it_state(it) == IAM_IT_SKEWED);
                        result = iam_it_next(it);
                }
        }
        assert_corr(ergo(result >= 0, it_state(it) == IAM_IT_ATTACHED));
        return result;
}
EXPORT_SYMBOL(iam_it_get_at);

/*
 * Duplicates iterator.
 *
 * postcondition: it_state(dst) == it_state(src) &&
 *                iam_it_container(dst) == iam_it_container(src) &&
 *                dst->ii_flags = src->ii_flags &&
 *                ergo(it_state(src) == IAM_IT_ATTACHED,
 *                     iam_it_rec_get(dst) == iam_it_rec_get(src) &&
 *                     iam_it_key_get(dst) == iam_it_key_get(src))
 */
void iam_it_dup(struct iam_iterator *dst, const struct iam_iterator *src)
{
        dst->ii_flags     = src->ii_flags;
        dst->ii_state     = src->ii_state;
        /* XXX not yet. iam_path_dup(&dst->ii_path, &src->ii_path); */
        /*
         * XXX: duplicate lock.
         */
        assert_corr(it_state(dst) == it_state(src));
        assert_corr(iam_it_container(dst) == iam_it_container(src));
        assert_corr(dst->ii_flags = src->ii_flags);
        assert_corr(ergo(it_state(src) == IAM_IT_ATTACHED,
                    iam_it_rec_get(dst) == iam_it_rec_get(src) &&
                    iam_it_key_get(dst) == iam_it_key_get(src)));

}

/*
 * Detach iterator. Does nothing it detached state.
 *
 * postcondition: it_state(it) == IAM_IT_DETACHED
 */
void iam_it_put(struct iam_iterator *it)
{
        if (it->ii_state != IAM_IT_DETACHED) {
                it->ii_state = IAM_IT_DETACHED;
                iam_leaf_fini(&it->ii_path.ip_leaf);
        }
}
EXPORT_SYMBOL(iam_it_put);

static struct iam_ikey *iam_it_ikey_get(const struct iam_iterator *it,
                                        struct iam_ikey *ikey);


/*
 * This function increments the frame pointer to search the next leaf
 * block, and reads in the necessary intervening nodes if the search
 * should be necessary.  Whether or not the search is necessary is
 * controlled by the hash parameter.  If the hash value is even, then
 * the search is only continued if the next block starts with that
 * hash value.  This is used if we are searching for a specific file.
 *
 * If the hash value is HASH_NB_ALWAYS, then always go to the next block.
 *
 * This function returns 1 if the caller should continue to search,
 * or 0 if it should not.  If there is an error reading one of the
 * index blocks, it will a negative error code.
 *
 * If start_hash is non-null, it will be filled in with the starting
 * hash of the next page.
 */
static int iam_htree_advance(struct inode *dir, __u32 hash,
                              struct iam_path *path, __u32 *start_hash,
                              int compat)
{
        struct iam_frame *p;
        struct buffer_head *bh;
        int err, num_frames = 0;
        __u32 bhash;

        p = path->ip_frame;
        /*
         * Find the next leaf page by incrementing the frame pointer.
         * If we run out of entries in the interior node, loop around and
         * increment pointer in the parent node.  When we break out of
         * this loop, num_frames indicates the number of interior
         * nodes need to be read.
         */
        while (1) {
                do_corr(schedule());
                iam_lock_bh(p->bh);
                p->at = iam_entry_shift(path, p->at, +1);
                if (p->at < iam_entry_shift(path, p->entries,
                                            dx_get_count(p->entries))) {
                        p->leaf = dx_get_block(path, p->at);
                        iam_unlock_bh(p->bh);
                        break;
                }
                iam_unlock_bh(p->bh);
                if (p == path->ip_frames)
                        return 0;
                num_frames++;
                --p;
        }

        if (compat) {
                /*
                 * Htree hash magic.
                 */
        /*
         * If the hash is 1, then continue only if the next page has a
         * continuation hash of any value.  This is used for readdir
         * handling.  Otherwise, check to see if the hash matches the
         * desired contiuation hash.  If it doesn't, return since
         * there's no point to read in the successive index pages.
         */
                dx_get_ikey(path, p->at, (struct iam_ikey *)&bhash);
        if (start_hash)
                *start_hash = bhash;
        if ((hash & 1) == 0) {
                if ((bhash & ~1) != hash)
                        return 0;
        }
        }
        /*
         * If the hash is HASH_NB_ALWAYS, we always go to the next
         * block so no check is necessary
         */
        while (num_frames--) {
                iam_ptr_t idx;

                do_corr(schedule());
                iam_lock_bh(p->bh);
                idx = p->leaf = dx_get_block(path, p->at);
                iam_unlock_bh(p->bh);
                err = iam_path_descr(path)->id_ops->
                        id_node_read(path->ip_container, idx, NULL, &bh);
                if (err != 0)
                        return err; /* Failure */
                ++p;
                brelse(p->bh);
                assert_corr(p->bh != bh);
                p->bh = bh;
                p->entries = dx_node_get_entries(path, p);
                p->at = iam_entry_shift(path, p->entries, !compat);
                assert_corr(p->curidx != idx);
                p->curidx = idx;
                iam_lock_bh(p->bh);
                assert_corr(p->leaf != dx_get_block(path, p->at));
                p->leaf = dx_get_block(path, p->at);
                iam_unlock_bh(p->bh);
                assert_inv(dx_node_check(path, p));
        }
        return 1;
}


static inline int iam_index_advance(struct iam_path *path)
{
        return iam_htree_advance(iam_path_obj(path), 0, path, NULL, 0);
}

static void iam_unlock_array(struct inode *dir, struct dynlock_handle **lh)
{
        int i;

        for (i = 0; i < DX_MAX_TREE_HEIGHT; ++i, ++lh) {
                if (*lh != NULL) {
                        iam_unlock_htree(dir, *lh);
                        *lh = NULL;
                }
        }
}
/*
 * Advance index part of @path to point to the next leaf. Returns 1 on
 * success, 0, when end of container was reached. Leaf node is locked.
 */
int iam_index_next(struct iam_container *c, struct iam_path *path)
{
        iam_ptr_t cursor;
        struct dynlock_handle *lh[DX_MAX_TREE_HEIGHT] = { 0, };
        int result;
        struct inode *object;

        /*
         * Locking for iam_index_next()... is to be described.
         */

        object = c->ic_object;
        cursor = path->ip_frame->leaf;

        while (1) {
                result = iam_index_lock(path, lh);
                do_corr(schedule());
                if (result < 0)
                        break;

                result = iam_check_full_path(path, 0);
                if (result == 0 && cursor == path->ip_frame->leaf) {
                        result = iam_index_advance(path);

                        assert_corr(result == 0 ||
                                    cursor != path->ip_frame->leaf);
                        break;
                }
                do {
                        iam_unlock_array(object, lh);

                        iam_path_release(path);
                        do_corr(schedule());

                        result = __iam_path_lookup(path);
                        if (result < 0)
                                break;

                        while (path->ip_frame->leaf != cursor) {
                                do_corr(schedule());

                                result = iam_index_lock(path, lh);
                                do_corr(schedule());
                                if (result < 0)
                                        break;

                                result = iam_check_full_path(path, 0);
                                if (result != 0)
                                        break;

                                result = iam_index_advance(path);
                                if (result == 0) {
                                        CERROR("cannot find cursor : %u\n",
                                                cursor);
                                        result = -EIO;
                                }
                                if (result < 0)
                                        break;
                                result = iam_check_full_path(path, 0);
                                if (result != 0)
                                        break;
                                iam_unlock_array(object, lh);
                        }
                } while (result == -EAGAIN);
                if (result < 0)
                        break;
        }
        iam_unlock_array(object, lh);
        return result;
}

/*
 * Move iterator one record right.
 *
 * Return value: 0: success,
 *              +1: end of container reached
 *             -ve: error
 *
 * precondition:  (it_state(it) == IAM_IT_ATTACHED ||
 *                 it_state(it) == IAM_IT_SKEWED) && it->ii_flags&IAM_IT_MOVE
 * postcondition: ergo(result == 0, it_state(it) == IAM_IT_ATTACHED) &&
 *                ergo(result >  0, it_state(it) == IAM_IT_DETACHED)
 */
int iam_it_next(struct iam_iterator *it)
{
        int result;
        struct iam_path      *path;
        struct iam_leaf      *leaf;
        struct inode         *obj;
        do_corr(struct iam_ikey *ik_orig);

        /* assert_corr(it->ii_flags&IAM_IT_MOVE); */
        assert_corr(it_state(it) == IAM_IT_ATTACHED ||
                    it_state(it) == IAM_IT_SKEWED);

        path = &it->ii_path;
        leaf = &path->ip_leaf;
        obj  = iam_path_obj(path);

        assert_corr(iam_leaf_is_locked(leaf));

        result = 0;
        do_corr(ik_orig = it_at_rec(it) ?
                iam_it_ikey_get(it, iam_path_ikey(path, 2)) : NULL);
        if (it_before(it)) {
                assert_corr(!iam_leaf_at_end(leaf));
                it->ii_state = IAM_IT_ATTACHED;
        } else {
                if (!iam_leaf_at_end(leaf))
                        /* advance within leaf node */
                        iam_leaf_next(leaf);
                /*
                 * multiple iterations may be necessary due to empty leaves.
                 */
                while (result == 0 && iam_leaf_at_end(leaf)) {
                        do_corr(schedule());
                        /* advance index portion of the path */
                        result = iam_index_next(iam_it_container(it), path);
                        assert_corr(iam_leaf_is_locked(leaf));
                        if (result == 1) {
                                struct dynlock_handle *lh;
                                lh = iam_lock_htree(obj, path->ip_frame->leaf,
                                                   DLT_WRITE);
                                if (lh != NULL) {
                                        iam_leaf_fini(leaf);
                                        leaf->il_lock = lh;
                                        result = iam_leaf_load(path);
                                        if (result == 0)
                                                iam_leaf_start(leaf);
                                } else
                                        result = -ENOMEM;
                        } else if (result == 0)
                                /* end of container reached */
                                result = +1;
                        if (result != 0)
                                iam_it_put(it);
                }
                if (result == 0)
                        it->ii_state = IAM_IT_ATTACHED;
        }
        assert_corr(ergo(result == 0, it_state(it) == IAM_IT_ATTACHED));
        assert_corr(ergo(result >  0, it_state(it) == IAM_IT_DETACHED));
        assert_corr(ergo(result == 0 && ik_orig != NULL,
                         it_ikeycmp(it, ik_orig) >= 0));
        return result;
}
EXPORT_SYMBOL(iam_it_next);

/*
 * Return pointer to the record under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED && it_at_rec(it)
 * postcondition: it_state(it) == IAM_IT_ATTACHED
 */
struct iam_rec *iam_it_rec_get(const struct iam_iterator *it)
{
        assert_corr(it_state(it) == IAM_IT_ATTACHED);
        assert_corr(it_at_rec(it));
        return iam_leaf_rec(&it->ii_path.ip_leaf);
}
EXPORT_SYMBOL(iam_it_rec_get);

static void iam_it_reccpy(struct iam_iterator *it, const struct iam_rec *r)
{
        struct iam_leaf *folio;

        folio = &it->ii_path.ip_leaf;
        iam_leaf_ops(folio)->rec_set(folio, r);
}

/*
 * Replace contents of record under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED &&
 *                it->ii_flags&IAM_IT_WRITE
 * postcondition: it_state(it) == IAM_IT_ATTACHED &&
 *                ergo(result == 0, !memcmp(iam_it_rec_get(it), r, ...))
 */
int iam_it_rec_set(handle_t *h,
                   struct iam_iterator *it, const struct iam_rec *r)
{
        int result;
        struct iam_path *path;
        struct buffer_head *bh;

        assert_corr(it_state(it) == IAM_IT_ATTACHED &&
                    it->ii_flags&IAM_IT_WRITE);
        assert_corr(it_at_rec(it));

        path = &it->ii_path;
        bh   = path->ip_leaf.il_bh;
        result = iam_txn_add(h, path, bh);
        if (result == 0) {
                iam_it_reccpy(it, r);
                result = iam_txn_dirty(h, path, bh);
        }
        return result;
}
EXPORT_SYMBOL(iam_it_rec_set);

/*
 * Return pointer to the index key under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED
 */
static struct iam_ikey *iam_it_ikey_get(const struct iam_iterator *it,
                                        struct iam_ikey *ikey)
{
        assert_corr(it_state(it) == IAM_IT_ATTACHED ||
                    it_state(it) == IAM_IT_SKEWED);
        assert_corr(it_at_rec(it));
        return iam_leaf_ikey(&it->ii_path.ip_leaf, ikey);
}

/*
 * Return pointer to the key under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED
 */
struct iam_key *iam_it_key_get(const struct iam_iterator *it)
{
        assert_corr(it_state(it) == IAM_IT_ATTACHED ||
                    it_state(it) == IAM_IT_SKEWED);
        assert_corr(it_at_rec(it));
        return iam_leaf_key(&it->ii_path.ip_leaf);
}
EXPORT_SYMBOL(iam_it_key_get);

/*
 * Return size of key under iterator (in bytes)
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED
 */
int iam_it_key_size(const struct iam_iterator *it)
{
        assert_corr(it_state(it) == IAM_IT_ATTACHED ||
                    it_state(it) == IAM_IT_SKEWED);
        assert_corr(it_at_rec(it));
        return iam_leaf_key_size(&it->ii_path.ip_leaf);
}
EXPORT_SYMBOL(iam_it_key_size);

/*
 * Insertion of new record. Interaction with jbd during non-trivial case (when
 * split happens) is as following:
 *
 *  - new leaf node is involved into transaction by ldiskfs_append();
 *
 *  - old leaf node is involved into transaction by iam_add_rec();
 *
 *  - leaf where insertion point ends in, is marked dirty by iam_add_rec();
 *
 *  - leaf without insertion point is marked dirty (as @new_leaf) by
 *  iam_new_leaf();
 *
 *  - split index nodes are involved into transaction and marked dirty by
 *  split_index_node().
 *
 *  - "safe" index node, which is no split, but where new pointer is inserted
 *  is involved into transaction and marked dirty by split_index_node().
 *
 *  - index node where pointer to new leaf is inserted is involved into
 *  transaction by split_index_node() and marked dirty by iam_add_rec().
 *
 *  - inode is marked dirty by iam_add_rec().
 *
 */

static int iam_new_leaf(handle_t *handle, struct iam_leaf *leaf)
{
        int err;
        iam_ptr_t blknr;
        struct buffer_head   *new_leaf;
        struct buffer_head   *old_leaf;
        struct iam_container *c;
        struct inode         *obj;
        struct iam_path      *path;

        assert_inv(iam_leaf_check(leaf));

        c = iam_leaf_container(leaf);
        path = leaf->il_path;

        obj = c->ic_object;
        new_leaf = ldiskfs_append(handle, obj, (__u32 *)&blknr, &err);
        do_corr(schedule());
        if (new_leaf != NULL) {
                struct dynlock_handle *lh;

                lh = iam_lock_htree(obj, blknr, DLT_WRITE);
                do_corr(schedule());
                if (lh != NULL) {
                        iam_leaf_ops(leaf)->init_new(c, new_leaf);
                        do_corr(schedule());
                        old_leaf = leaf->il_bh;
                        iam_leaf_split(leaf, &new_leaf, blknr);
                        if (old_leaf != leaf->il_bh) {
                                /*
                                 * Switched to the new leaf.
                                 */
                                iam_leaf_unlock(leaf);
                                leaf->il_lock = lh;
                                path->ip_frame->leaf = blknr;
                        } else
                                iam_unlock_htree(obj, lh);
                        do_corr(schedule());
                        err = iam_txn_dirty(handle, path, new_leaf);
                        brelse(new_leaf);
                        if (err == 0)
                                err = ldiskfs_mark_inode_dirty(handle, obj);
                        do_corr(schedule());
                } else
                        err = -ENOMEM;
        }
        assert_inv(iam_leaf_check(leaf));
        assert_inv(iam_leaf_check(&iam_leaf_path(leaf)->ip_leaf));
        assert_inv(iam_path_check(iam_leaf_path(leaf)));
        return err;
}

static inline void dx_set_limit(struct iam_entry *entries, unsigned value)
{
        ((struct dx_countlimit *) entries)->limit = cpu_to_le16(value);
}

static int iam_shift_entries(struct iam_path *path,
                         struct iam_frame *frame, unsigned count,
                         struct iam_entry *entries, struct iam_entry *entries2,
                         u32 newblock)
{
        unsigned count1;
        unsigned count2;
        int delta;

        struct iam_frame *parent = frame - 1;
        struct iam_ikey *pivot = iam_path_ikey(path, 3);

        delta = dx_index_is_compat(path) ? 0 : +1;

        count1 = count/2 + delta;
        count2 = count - count1;
        dx_get_ikey(path, iam_entry_shift(path, entries, count1), pivot);

        dxtrace(printk("Split index %d/%d\n", count1, count2));

        memcpy((char *) iam_entry_shift(path, entries2, delta),
               (char *) iam_entry_shift(path, entries, count1),
               count2 * iam_entry_size(path));

        dx_set_count(entries2, count2 + delta);
        dx_set_limit(entries2, dx_node_limit(path));

        /*
         * NOTE: very subtle piece of code competing dx_probe() may find 2nd
         * level index in root index, then we insert new index here and set
         * new count in that 2nd level index. so, dx_probe() may see 2nd level
         * index w/o hash it looks for. the solution is to check root index
         * after we locked just founded 2nd level index -bzzz
         */
        iam_insert_key_lock(path, parent, pivot, newblock);

        /*
         * now old and new 2nd level index blocks contain all pointers, so
         * dx_probe() may find it in the both.  it's OK -bzzz
         */
        iam_lock_bh(frame->bh);
        dx_set_count(entries, count1);
        iam_unlock_bh(frame->bh);

        /*
         * now old 2nd level index block points to first half of leafs. it's
         * importand that dx_probe() must check root index block for changes
         * under dx_lock_bh(frame->bh) -bzzz
         */

        return count1;
}


int split_index_node(handle_t *handle, struct iam_path *path,
                     struct dynlock_handle **lh)
{

        struct iam_entry *entries;   /* old block contents */
        struct iam_entry *entries2;  /* new block contents */
         struct iam_frame *frame, *safe;
        struct buffer_head *bh_new[DX_MAX_TREE_HEIGHT] = {0};
        u32 newblock[DX_MAX_TREE_HEIGHT] = {0};
        struct dynlock_handle *lock[DX_MAX_TREE_HEIGHT] = {NULL,};
        struct dynlock_handle *new_lock[DX_MAX_TREE_HEIGHT] = {NULL,};
        struct inode *dir = iam_path_obj(path);
        struct iam_descr *descr;
        int nr_splet;
        int i, err;

        descr = iam_path_descr(path);
        /*
         * Algorithm below depends on this.
         */
        assert_corr(dx_root_limit(path) < dx_node_limit(path));

        frame = path->ip_frame;
        entries = frame->entries;

        /*
         * Tall-tree handling: we might have to split multiple index blocks
         * all the way up to tree root. Tricky point here is error handling:
         * to avoid complicated undo/rollback we
         *
         *   - first allocate all necessary blocks
         *
         *   - insert pointers into them atomically.
         */

        /*
         * Locking: leaf is already locked. htree-locks are acquired on all
         * index nodes that require split bottom-to-top, on the "safe" node,
         * and on all new nodes
         */

        dxtrace(printk("using %u of %u node entries\n",
                       dx_get_count(entries), dx_get_limit(entries)));

        /* What levels need split? */
        for (nr_splet = 0; frame >= path->ip_frames &&
             dx_get_count(frame->entries) == dx_get_limit(frame->entries);
             --frame, ++nr_splet) {
                do_corr(schedule());
                if (nr_splet == DX_MAX_TREE_HEIGHT) {
                        /*
                        CWARN(dir->i_sb, __FUNCTION__,
                                     "Directory index full!\n");
                                     */
                        err = -ENOSPC;
                        goto cleanup;
                }
        }

        safe = frame;

        /*
         * Lock all nodes, bottom to top.
         */
        for (frame = path->ip_frame, i = nr_splet; i >= 0; --i, --frame) {
                do_corr(schedule());
                lock[i] = iam_lock_htree(dir, frame->curidx, DLT_WRITE);
                if (lock[i] == NULL) {
                        err = -ENOMEM;
                        goto cleanup;
                }
        }

        /*
         * Check for concurrent index modification.
         */
        err = iam_check_full_path(path, 1);
        if (err)
                goto cleanup;
        /*
         * And check that the same number of nodes is to be split.
         */
        for (i = 0, frame = path->ip_frame; frame >= path->ip_frames &&
             dx_get_count(frame->entries) == dx_get_limit(frame->entries);
             --frame, ++i) {
                ;
        }
        if (i != nr_splet) {
                err = -EAGAIN;
                goto cleanup;
        }

        /* Go back down, allocating blocks, locking them, and adding into
         * transaction... */
        for (frame = safe + 1, i = 0; i < nr_splet; ++i, ++frame) {
                bh_new[i] = ldiskfs_append (handle, dir, &newblock[i], &err);
                do_corr(schedule());
                if (!bh_new[i] ||
                    descr->id_ops->id_node_init(path->ip_container,
                                                bh_new[i], 0) != 0)
                        goto cleanup;
                new_lock[i] = iam_lock_htree(dir, newblock[i], DLT_WRITE);
                if (new_lock[i] == NULL) {
                        err = -ENOMEM;
                        goto cleanup;
                }
                do_corr(schedule());
                BUFFER_TRACE(frame->bh, "get_write_access");
                err = ldiskfs_journal_get_write_access(handle, frame->bh);
                if (err)
                        goto journal_error;
        }
        /* Add "safe" node to transaction too */
        if (safe + 1 != path->ip_frames) {
                do_corr(schedule());
                err = ldiskfs_journal_get_write_access(handle, safe->bh);
                if (err)
                        goto journal_error;
        }

        /* Go through nodes once more, inserting pointers */
        for (frame = safe + 1, i = 0; i < nr_splet; ++i, ++frame) {
                unsigned count;
                int idx;
                struct buffer_head *bh2;
                struct buffer_head *bh;

                entries = frame->entries;
                count = dx_get_count(entries);
                idx = iam_entry_diff(path, frame->at, entries);

                bh2 = bh_new[i];
                entries2 = dx_get_entries(path, bh2->b_data, 0);

                bh = frame->bh;
                if (frame == path->ip_frames) {
                        /* splitting root node. Tricky point:
                         *
                         * In the "normal" B-tree we'd split root *and* add
                         * new root to the tree with pointers to the old root
                         * and its sibling (thus introducing two new nodes).
                         *
                         * In htree it's enough to add one node, because
                         * capacity of the root node is smaller than that of
                         * non-root one.
                         */
                        struct iam_frame *frames;
                        struct iam_entry *next;

                        assert_corr(i == 0);

                        do_corr(schedule());

                        frames = path->ip_frames;
                        memcpy((char *) entries2, (char *) entries,
                               count * iam_entry_size(path));
                        dx_set_limit(entries2, dx_node_limit(path));

                        /* Set up root */
                          iam_lock_bh(frame->bh);
                        next = descr->id_ops->id_root_inc(path->ip_container,
                                                          path, frame);
                        dx_set_block(path, next, newblock[0]);
                          iam_unlock_bh(frame->bh);

                        do_corr(schedule());
                        /* Shift frames in the path */
                        memmove(frames + 2, frames + 1,
                                (sizeof path->ip_frames) - 2 * sizeof frames[0]);
                        /* Add new access path frame */
                        frames[1].at = iam_entry_shift(path, entries2, idx);
                        frames[1].entries = entries = entries2;
                        frames[1].bh = bh2;
                        assert_inv(dx_node_check(path, frame));
                        ++ path->ip_frame;
                        ++ frame;
                        assert_inv(dx_node_check(path, frame));
                        bh_new[0] = NULL; /* buffer head is "consumed" */
                        err = ldiskfs_journal_get_write_access(handle, bh2);
                        if (err)
                                goto journal_error;
                        do_corr(schedule());
                } else {
                        /* splitting non-root index node. */
                        struct iam_frame *parent = frame - 1;

                        do_corr(schedule());
                        count = iam_shift_entries(path, frame, count,
                                              entries, entries2, newblock[i]);
                        /* Which index block gets the new entry? */
                        if (idx >= count) {
                                int d = dx_index_is_compat(path) ? 0 : +1;

                                frame->at = iam_entry_shift(path, entries2,
                                                            idx - count + d);
                                frame->entries = entries = entries2;
                                frame->curidx = newblock[i];
                                swap(frame->bh, bh2);
                                assert_corr(lock[i + 1] != NULL);
                                assert_corr(new_lock[i] != NULL);
                                swap(lock[i + 1], new_lock[i]);
                                bh_new[i] = bh2;
                                parent->at = iam_entry_shift(path,
                                                             parent->at, +1);
                        }
                        assert_inv(dx_node_check(path, frame));
                        assert_inv(dx_node_check(path, parent));
                        dxtrace(dx_show_index ("node", frame->entries));
                        dxtrace(dx_show_index ("node",
                               ((struct dx_node *) bh2->b_data)->entries));
                        err = ldiskfs_journal_dirty_metadata(handle, bh2);
                        if (err)
                                goto journal_error;
                        do_corr(schedule());
                        err = ldiskfs_journal_dirty_metadata(handle, parent->bh);
                        if (err)
                                goto journal_error;
                }
                do_corr(schedule());
                err = ldiskfs_journal_dirty_metadata(handle, bh);
                if (err)
                        goto journal_error;
        }
                /*
                 * This function was called to make insertion of new leaf
                 * possible. Check that it fulfilled its obligations.
                 */
                assert_corr(dx_get_count(path->ip_frame->entries) <
                            dx_get_limit(path->ip_frame->entries));
        assert_corr(lock[nr_splet] != NULL);
        *lh = lock[nr_splet];
        lock[nr_splet] = NULL;
        if (nr_splet > 0) {
                /*
                 * Log ->i_size modification.
                 */
                err = ldiskfs_mark_inode_dirty(handle, dir);
                if (err)
                        goto journal_error;
        }
        goto cleanup;
journal_error:
        ldiskfs_std_error(dir->i_sb, err);

cleanup:
        iam_unlock_array(dir, lock);
        iam_unlock_array(dir, new_lock);

        assert_corr(err || iam_frame_is_locked(path, path->ip_frame));

        do_corr(schedule());
        for (i = 0; i < ARRAY_SIZE(bh_new); ++i) {
                if (bh_new[i] != NULL)
                        brelse(bh_new[i]);
        }
        return err;
}

static int iam_add_rec(handle_t *handle, struct iam_iterator *it,
                       struct iam_path *path,
                       const struct iam_key *k, const struct iam_rec *r)
{
        int err;
        struct iam_leaf *leaf;

        leaf = &path->ip_leaf;
        assert_inv(iam_leaf_check(leaf));
        assert_inv(iam_path_check(path));
        err = iam_txn_add(handle, path, leaf->il_bh);
        if (err == 0) {
                do_corr(schedule());
                if (!iam_leaf_can_add(leaf, k, r)) {
                        struct dynlock_handle *lh = NULL;

                        do {
                                assert_corr(lh == NULL);
                                do_corr(schedule());
                                err = split_index_node(handle, path, &lh);
                                if (err == -EAGAIN) {
                                        assert_corr(lh == NULL);

                                        iam_path_fini(path);
                                        it->ii_state = IAM_IT_DETACHED;

                                        do_corr(schedule());
                                        err = iam_it_get_exact(it, k);
                                        if (err == -ENOENT)
                                                err = +1; /* repeat split */
                                        else if (err == 0)
                                                err = -EEXIST;
                                }
                        } while (err > 0);
                        assert_inv(iam_path_check(path));
                        if (err == 0) {
                                assert_corr(lh != NULL);
                                do_corr(schedule());
                                err = iam_new_leaf(handle, leaf);
                                if (err == 0)
                                        err = iam_txn_dirty(handle, path,
                                                            path->ip_frame->bh);
                        }
                        iam_unlock_htree(iam_path_obj(path), lh);
                        do_corr(schedule());
                }
                if (err == 0) {
                        iam_leaf_rec_add(leaf, k, r);
                        err = iam_txn_dirty(handle, path, leaf->il_bh);
                }
        }
        assert_inv(iam_leaf_check(leaf));
        assert_inv(iam_leaf_check(&path->ip_leaf));
        assert_inv(iam_path_check(path));
        return err;
}

/*
 * Insert new record with key @k and contents from @r, shifting records to the
 * right. On success, iterator is positioned on the newly inserted record.
 *
 * precondition: it->ii_flags&IAM_IT_WRITE &&
 *               (it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_SKEWED) &&
 *               ergo(it_state(it) == IAM_IT_ATTACHED,
 *                    it_keycmp(it, k) <= 0) &&
 *               ergo(it_before(it), it_keycmp(it, k) > 0));
 * postcondition: ergo(result == 0,
 *                     it_state(it) == IAM_IT_ATTACHED &&
 *                     it_keycmp(it, k) == 0 &&
 *                     !memcmp(iam_it_rec_get(it), r, ...))
 */
int iam_it_rec_insert(handle_t *h, struct iam_iterator *it,
                      const struct iam_key *k, const struct iam_rec *r)
{
        int result;
        struct iam_path *path;

        path = &it->ii_path;

        assert_corr(it->ii_flags&IAM_IT_WRITE);
        assert_corr(it_state(it) == IAM_IT_ATTACHED ||
                    it_state(it) == IAM_IT_SKEWED);
        assert_corr(ergo(it_state(it) == IAM_IT_ATTACHED,
                         it_keycmp(it, k) <= 0));
        assert_corr(ergo(it_before(it), it_keycmp(it, k) > 0));
        result = iam_add_rec(h, it, path, k, r);
        if (result == 0)
                it->ii_state = IAM_IT_ATTACHED;
        assert_corr(ergo(result == 0,
                         it_state(it) == IAM_IT_ATTACHED &&
                         it_keycmp(it, k) == 0));
        return result;
}
EXPORT_SYMBOL(iam_it_rec_insert);

/*
 * Delete record under iterator.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED &&
 *                it->ii_flags&IAM_IT_WRITE &&
 *                it_at_rec(it)
 * postcondition: it_state(it) == IAM_IT_ATTACHED ||
 *                it_state(it) == IAM_IT_DETACHED
 */
int iam_it_rec_delete(handle_t *h, struct iam_iterator *it)
{
        int result;
        struct iam_leaf *leaf;
        struct iam_path *path;

        assert_corr(it_state(it) == IAM_IT_ATTACHED &&
                    it->ii_flags&IAM_IT_WRITE);
        assert_corr(it_at_rec(it));

        path = &it->ii_path;
        leaf = &path->ip_leaf;

        assert_inv(iam_leaf_check(leaf));
        assert_inv(iam_path_check(path));

        result = iam_txn_add(h, path, leaf->il_bh);
        /*
         * no compaction for now.
         */
        if (result == 0) {
                iam_rec_del(leaf, it->ii_flags&IAM_IT_MOVE);
                result = iam_txn_dirty(h, path, leaf->il_bh);
                if (result == 0 && iam_leaf_at_end(leaf) &&
                    it->ii_flags&IAM_IT_MOVE) {
                        result = iam_it_next(it);
                        if (result > 0)
                                result = 0;
                }
        }
        assert_inv(iam_leaf_check(leaf));
        assert_inv(iam_path_check(path));
        assert_corr(it_state(it) == IAM_IT_ATTACHED ||
                    it_state(it) == IAM_IT_DETACHED);
        return result;
}
EXPORT_SYMBOL(iam_it_rec_delete);

/*
 * Convert iterator to cookie.
 *
 * precondition:  it_state(it) == IAM_IT_ATTACHED &&
 *                iam_path_descr(it->ii_path)->id_key_size <= sizeof(iam_pos_t)
 * postcondition: it_state(it) == IAM_IT_ATTACHED
 */
iam_pos_t iam_it_store(const struct iam_iterator *it)
{
        iam_pos_t result;

        assert_corr(it_state(it) == IAM_IT_ATTACHED);
        assert_corr(it_at_rec(it));
        assert_corr(iam_it_container(it)->ic_descr->id_ikey_size <=
                    sizeof result);

        result = 0;
        return *(iam_pos_t *)iam_it_ikey_get(it, (void *)&result);
}
EXPORT_SYMBOL(iam_it_store);

/*
 * Restore iterator from cookie.
 *
 * precondition:  it_state(it) == IAM_IT_DETACHED && it->ii_flags&IAM_IT_MOVE &&
 *                iam_path_descr(it->ii_path)->id_key_size <= sizeof(iam_pos_t)
 * postcondition: ergo(result == 0, it_state(it) == IAM_IT_ATTACHED &&
 *                                  iam_it_store(it) == pos)
 */
int iam_it_load(struct iam_iterator *it, iam_pos_t pos)
{
        assert_corr(it_state(it) == IAM_IT_DETACHED &&
                    it->ii_flags&IAM_IT_MOVE);
        assert_corr(iam_it_container(it)->ic_descr->id_ikey_size <= sizeof pos);
        return iam_it_iget(it, (struct iam_ikey *)&pos);
}
EXPORT_SYMBOL(iam_it_load);

/***********************************************************************/
/* invariants                                                          */
/***********************************************************************/

static inline int ptr_inside(void *base, size_t size, void *ptr)
{
        return (base <= ptr) && (ptr < base + size);
}

int iam_frame_invariant(struct iam_frame *f)
{
        return
                (f->bh != NULL &&
                f->bh->b_data != NULL &&
                ptr_inside(f->bh->b_data, f->bh->b_size, f->entries) &&
                ptr_inside(f->bh->b_data, f->bh->b_size, f->at) &&
                f->entries <= f->at);
}
int iam_leaf_invariant(struct iam_leaf *l)
{
        return
                l->il_bh != NULL &&
                l->il_bh->b_data != NULL &&
                ptr_inside(l->il_bh->b_data, l->il_bh->b_size, l->il_entries) &&
                ptr_inside(l->il_bh->b_data, l->il_bh->b_size, l->il_at) &&
                l->il_entries <= l->il_at;
}

int iam_path_invariant(struct iam_path *p)
{
        int i;

        if (p->ip_container == NULL ||
            p->ip_indirect < 0 || p->ip_indirect > DX_MAX_TREE_HEIGHT - 1 ||
            p->ip_frame != p->ip_frames + p->ip_indirect ||
            !iam_leaf_invariant(&p->ip_leaf))
                return 0;
        for (i = 0; i < ARRAY_SIZE(p->ip_frames); ++i) {
                if (i <= p->ip_indirect) {
                        if (!iam_frame_invariant(&p->ip_frames[i]))
                                return 0;
                }
        }
        return 1;
}

int iam_it_invariant(struct iam_iterator *it)
{
        return
                (it->ii_state == IAM_IT_DETACHED ||
                 it->ii_state == IAM_IT_ATTACHED ||
                 it->ii_state == IAM_IT_SKEWED) &&
                !(it->ii_flags & ~(IAM_IT_MOVE | IAM_IT_WRITE)) &&
                ergo(it->ii_state == IAM_IT_ATTACHED ||
                     it->ii_state == IAM_IT_SKEWED,
                     iam_path_invariant(&it->ii_path) &&
                     equi(it_at_rec(it), it->ii_state == IAM_IT_SKEWED));
}

/*
 * Search container @c for record with key @k. If record is found, its data
 * are moved into @r.
 *
 * Return values: 0: found, -ENOENT: not-found, -ve: error
 */
int iam_lookup(struct iam_container *c, const struct iam_key *k,
               struct iam_rec *r, struct iam_path_descr *pd)
{
        struct iam_iterator it;
        int result;

        iam_it_init(&it, c, 0, pd);

        result = iam_it_get_exact(&it, k);
        if (result == 0)
                /*
                 * record with required key found, copy it into user buffer
                 */
                iam_reccpy(&it.ii_path.ip_leaf, r);
        iam_it_put(&it);
        iam_it_fini(&it);
        return result;
}
EXPORT_SYMBOL(iam_lookup);

/*
 * Insert new record @r with key @k into container @c (within context of
 * transaction @h).
 *
 * Return values: 0: success, -ve: error, including -EEXIST when record with
 * given key is already present.
 *
 * postcondition: ergo(result == 0 || result == -EEXIST,
 *                                  iam_lookup(c, k, r2) > 0;
 */
int iam_insert(handle_t *h, struct iam_container *c, const struct iam_key *k,
               const struct iam_rec *r, struct iam_path_descr *pd)
{
        struct iam_iterator it;
        int result;

        iam_it_init(&it, c, IAM_IT_WRITE, pd);

        result = iam_it_get_exact(&it, k);
        if (result == -ENOENT)
                result = iam_it_rec_insert(h, &it, k, r);
        else if (result == 0)
                result = -EEXIST;
        iam_it_put(&it);
        iam_it_fini(&it);
        return result;
}
EXPORT_SYMBOL(iam_insert);

/*
 * Update record with the key @k in container @c (within context of
 * transaction @h), new record is given by @r.
 *
 * Return values: 0: success, -ve: error, including -ENOENT if no record with
 * the given key found.
 */
int iam_update(handle_t *h, struct iam_container *c, const struct iam_key *k,
               const struct iam_rec *r, struct iam_path_descr *pd)
{
        struct iam_iterator it;
        int result;

        iam_it_init(&it, c, IAM_IT_WRITE, pd);

        result = iam_it_get_exact(&it, k);
        if (result == 0)
                iam_it_rec_set(h, &it, r);
        iam_it_put(&it);
        iam_it_fini(&it);
        return result;
}
EXPORT_SYMBOL(iam_update);

/*
 * Delete existing record with key @k.
 *
 * Return values: 0: success, -ENOENT: not-found, -ve: other error.
 *
 * postcondition: ergo(result == 0 || result == -ENOENT,
 *                                 !iam_lookup(c, k, *));
 */
int iam_delete(handle_t *h, struct iam_container *c, const struct iam_key *k,
               struct iam_path_descr *pd)
{
        struct iam_iterator it;
        int result;

        iam_it_init(&it, c, IAM_IT_WRITE, pd);

        result = iam_it_get_exact(&it, k);
        if (result == 0)
                iam_it_rec_delete(h, &it);
        iam_it_put(&it);
        iam_it_fini(&it);
        return result;
}
EXPORT_SYMBOL(iam_delete);

int iam_root_limit(int rootgap, int blocksize, int size)
{
        int limit;
        int nlimit;

        limit = (blocksize - rootgap) / size;
        nlimit = blocksize / size;
        if (limit == nlimit)
                limit--;
        return limit;
}
