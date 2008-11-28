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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * Definitions shared between vvp and liblustre, and other clients in the
 * future.
 *
 *   Author: Oleg Drokin <oleg.drokin@sun.com>
 *   Author: Nikita Danilov <nikita.danilov@sun.com>
 */

#ifndef LCLIENT_H
#define LCLIENT_H

int cl_glimpse_size(struct inode *inode);
int cl_glimpse_lock(const struct lu_env *env, struct cl_io *io,
                    struct inode *inode, struct cl_object *clob);

/**
 * Common IO arguments for various VFS I/O interfaces.
 */
struct ccc_io_args {
        int           cia_is_sendfile;
#ifndef HAVE_FILE_WRITEV
        struct kiocb *cia_iocb;
#endif
        struct iovec *cia_iov;
        unsigned long cia_nrsegs;
        read_actor_t  cia_actor;
        void         *cia_target;
};

/**
 * Locking policy for truncate.
 */
enum ccc_trunc_lock_type {
        /** Locking is done by server */
        TRUNC_NOLOCK,
        /** Extent lock is enqueued */
        TRUNC_EXTENT,
        /** Existing local extent lock is used */
        TRUNC_MATCH
};

/**
 * IO state private to vvp or slp layers.
 */
struct ccc_io {
        /** super class */
        struct cl_io_slice     cui_cl;
        struct cl_io_lock_link cui_link;
        /**
         * I/O vector information to or from which read/write is going.
         */
        struct iovec *cui_iov;
        unsigned long cui_nrsegs;
        /**
         * Total iov count for left IO.
         */
        unsigned long cui_tot_nrsegs;
        /**
         * Old length for iov that was truncated partially.
         */
        size_t cui_iov_olen;
        /**
         * Total size for the left IO.
         */
        size_t cui_tot_count;

        union {
                struct {
                        int                      cui_locks_released;
                        enum ccc_trunc_lock_type cui_local_lock;
                } trunc;
        } u;
        /**
         * True iff io is processing glimpse right now.
         */
        int                  cui_glimpse;
        /**
         * File descriptor against which IO is done.
         */
        struct ll_file_data *cui_fd;
#ifndef HAVE_FILE_WRITEV
        struct kiocb *cui_iocb;
#endif
};

extern struct lu_context_key ccc_key;
extern struct lu_context_key ccc_session_key;

struct ccc_thread_info {
        struct cl_lock_descr cti_descr;
        struct cl_io         cti_io;
        struct cl_sync_io    cti_sync_io;
        struct cl_attr       cti_attr;
};

static inline struct ccc_thread_info *ccc_env_info(const struct lu_env *env)
{
        struct ccc_thread_info      *info;

        info = lu_context_key_get(&env->le_ctx, &ccc_key);
        LASSERT(info != NULL);
        return info;
}

struct ccc_session {
        struct ccc_io cs_ios;
};

static inline struct ccc_session *ccc_env_session(const struct lu_env *env)
{
        struct ccc_session *ses;

        ses = lu_context_key_get(env->le_ses, &ccc_session_key);
        LASSERT(ses != NULL);
        return ses;
}

static inline struct ccc_io *ccc_env_io(const struct lu_env *env)
{
        return &ccc_env_session(env)->cs_ios;
}

/**
 * ccc-private object state.
 */
struct ccc_object {
        struct cl_object_header cob_header;
        struct cl_object        cob_cl;
        struct inode           *cob_inode;

        /**
         * A list of dirty pages pending IO in the cache. Used by
         * SOM. Protected by ll_inode_info::lli_lock.
         *
         * \see ccc_page::cpg_pending_linkage
         */
        struct list_head        cob_pending_list;

        /**
         * Access this counter is protected by inode->i_sem. Now that
         * the lifetime of transient pages must be covered by inode sem,
         * we don't need to hold any lock..
         */
        int                     cob_transient_pages;
        /**
         * Number of outstanding mmaps on this file.
         *
         * \see ll_vm_open(), ll_vm_close().
         */
        atomic_t                cob_mmap_cnt;
};

/**
 * ccc-private page state.
 */
struct ccc_page {
        struct cl_page_slice cpg_cl;
        int                  cpg_defer_uptodate;
        int                  cpg_ra_used;
        int                  cpg_write_queued;
        /**
         * Non-empty iff this page is already counted in
         * ccc_object::cob_pending_list. Protected by
         * ccc_object::cob_pending_guard. This list is only used as a flag,
         * that is, never iterated through, only checked for list_empty(), but
         * having a list is useful for debugging.
         */
        struct list_head     cpg_pending_linkage;
        /** VM page */
        cfs_page_t          *cpg_page;
        struct cl_sync_io   *cpg_sync_io;
        /**
         * checksum for paranoid I/O debugging enabled by
         * ENABLE_LLITE_CHECKSUM configuration option.
         *
         * XXX This cannot be implemented reliably because checksum cannot be
         * updated from ->set_page_dirty() that is called without page VM
         * lock.
         */
        __u32                cpg_checksum;
};

static inline struct ccc_page *cl2ccc_page(const struct cl_page_slice *slice)
{
        return container_of(slice, struct ccc_page, cpg_cl);
}

struct cl_page    *ccc_vmpage_page_transient(cfs_page_t *vmpage);

struct ccc_device {
        struct cl_device    cdv_cl;
        struct super_block *cdv_sb;
        struct cl_device   *cdv_next;
};

struct ccc_lock {
        struct cl_lock_slice clk_cl;
};

struct ccc_req {
        struct cl_req_slice  crq_cl;
};

void *ccc_key_init        (const struct lu_context *ctx,
                           struct lu_context_key *key);
void  ccc_key_fini        (const struct lu_context *ctx,
                           struct lu_context_key *key, void *data);
void *ccc_session_key_init(const struct lu_context *ctx,
                           struct lu_context_key *key);
void  ccc_session_key_fini(const struct lu_context *ctx,
                           struct lu_context_key *key, void *data);

int              ccc_device_init  (const struct lu_env *env,
                                   struct lu_device *d,
                                   const char *name, struct lu_device *next);
struct lu_device *ccc_device_fini (const struct lu_env *env,
                                   struct lu_device *d);
struct lu_device *ccc_device_alloc(const struct lu_env *env,
                                   struct lu_device_type *t,
                                   struct lustre_cfg *cfg,
                                   const struct lu_device_operations *luops,
                                   const struct cl_device_operations *clops);
struct lu_device *ccc_device_free (const struct lu_env *env,
                                   struct lu_device *d);
struct lu_object *ccc_object_alloc(const struct lu_env *env,
                                   const struct lu_object_header *hdr,
                                   struct lu_device *dev,
                                   const struct cl_object_operations *clops,
                                   const struct lu_object_operations *luops);

int ccc_req_init(const struct lu_env *env, struct cl_device *dev,
                 struct cl_req *req);
void ccc_umount(const struct lu_env *env, struct cl_device *dev);
int ccc_global_init(struct lu_device_type *device_type);
void ccc_global_fini(struct lu_device_type *device_type);
int ccc_object_init0(const struct lu_env *env,struct ccc_object *vob,
                     const struct cl_object_conf *conf);
int ccc_object_init(const struct lu_env *env, struct lu_object *obj,
                    const struct lu_object_conf *conf);
void ccc_object_free(const struct lu_env *env, struct lu_object *obj);
int ccc_lock_init(const struct lu_env *env, struct cl_object *obj,
                  struct cl_lock *lock, const struct cl_io *io,
                  const struct cl_lock_operations *lkops);
int ccc_attr_set(const struct lu_env *env, struct cl_object *obj,
                 const struct cl_attr *attr, unsigned valid);
int ccc_object_glimpse(const struct lu_env *env,
                       const struct cl_object *obj, struct ost_lvb *lvb);
int ccc_conf_set(const struct lu_env *env, struct cl_object *obj,
                 const struct cl_object_conf *conf);
cfs_page_t *ccc_page_vmpage(const struct lu_env *env,
                            const struct cl_page_slice *slice);
int ccc_page_is_under_lock(const struct lu_env *env,
                           const struct cl_page_slice *slice, struct cl_io *io);
int ccc_fail(const struct lu_env *env, const struct cl_page_slice *slice);
void ccc_transient_page_verify(const struct cl_page *page);
void ccc_transient_page_own(const struct lu_env *env,
                            const struct cl_page_slice *slice,
                            struct cl_io *io);
void ccc_transient_page_assume(const struct lu_env *env,
                               const struct cl_page_slice *slice,
                               struct cl_io *io);
void ccc_transient_page_unassume(const struct lu_env *env,
                                 const struct cl_page_slice *slice,
                                 struct cl_io *io);
void ccc_transient_page_disown(const struct lu_env *env,
                               const struct cl_page_slice *slice,
                               struct cl_io *io);
void ccc_transient_page_discard(const struct lu_env *env,
                                const struct cl_page_slice *slice,
                                struct cl_io *io);
int ccc_transient_page_prep(const struct lu_env *env,
                            const struct cl_page_slice *slice,
                            struct cl_io *io);
void ccc_lock_fini(const struct lu_env *env,struct cl_lock_slice *slice);
int ccc_lock_enqueue(const struct lu_env *env,const struct cl_lock_slice *slice,
                     struct cl_io *io, __u32 enqflags);
int ccc_lock_unuse(const struct lu_env *env,const struct cl_lock_slice *slice);
int ccc_lock_wait(const struct lu_env *env,const struct cl_lock_slice *slice);
int ccc_lock_fits_into(const struct lu_env *env,
                       const struct cl_lock_slice *slice,
                       const struct cl_lock_descr *need,
                       const struct cl_io *io);
void ccc_lock_state(const struct lu_env *env,
                    const struct cl_lock_slice *slice,
                    enum cl_lock_state state);

void ccc_io_fini(const struct lu_env *env, const struct cl_io_slice *ios);
int ccc_io_one_lock_index(const struct lu_env *env, struct cl_io *io,
                          __u32 enqflags, enum cl_lock_mode mode,
                          pgoff_t start, pgoff_t end);
int ccc_io_one_lock(const struct lu_env *env, struct cl_io *io,
                    __u32 enqflags, enum cl_lock_mode mode,
                    loff_t start, loff_t end);
void ccc_io_end(const struct lu_env *env, const struct cl_io_slice *ios);
int ccc_prep_size(const struct lu_env *env, struct cl_object *obj,
                  struct cl_io *io, loff_t pos, int vfslock);
void ccc_req_completion(const struct lu_env *env,
                        const struct cl_req_slice *slice, int ioret);
void ccc_req_attr_set(const struct lu_env *env,const struct cl_req_slice *slice,
                      const struct cl_object *obj,
                      struct cl_req_attr *oa, obd_valid flags);

struct lu_device   *ccc2lu_dev      (struct ccc_device *vdv);
struct lu_object   *ccc2lu          (struct ccc_object *vob);
struct ccc_device  *lu2ccc_dev      (const struct lu_device *d);
struct ccc_device  *cl2ccc_dev      (const struct cl_device *d);
struct ccc_object  *lu2ccc          (const struct lu_object *obj);
struct ccc_object  *cl2ccc          (const struct cl_object *obj);
struct ccc_lock    *cl2ccc_lock     (const struct cl_lock_slice *slice);
struct ccc_io      *cl2ccc_io       (const struct lu_env *env,
                                     const struct cl_io_slice *slice);
struct ccc_req     *cl2ccc_req      (const struct cl_req_slice *slice);
cfs_page_t         *cl2vm_page      (const struct cl_page_slice *slice);
struct inode       *ccc_object_inode(const struct cl_object *obj);
struct ccc_object  *cl_inode2ccc    (struct inode *inode);

int cl_setattr_do_truncate(struct inode *inode, loff_t size,
                           struct obd_capa *capa);
int cl_setattr_ost(struct inode *inode, struct obd_capa *capa);

struct cl_page *ccc_vmpage_page_transient(cfs_page_t *vmpage);
int ccc_object_invariant(const struct cl_object *obj);
int cl_inode_init(struct inode *inode, struct lustre_md *md);
void cl_inode_fini(struct inode *inode);
int cl_local_size(struct inode *inode);

#ifdef INVARIANT_CHECK
# define CLOBINVRNT(env, clob, expr)                                    \
  do {                                                                  \
          if (unlikely(!(expr))) {                                      \
                  LU_OBJECT_DEBUG(D_ERROR, (env), &(clob)->co_lu, #expr "\n"); \
                  LINVRNT(0);                                           \
          }                                                             \
  } while (0)
#else /* !INVARIANT_CHECK */
# define CLOBINVRNT(env, clob, expr)                                    \
        ((void)sizeof(env), (void)sizeof(clob), (void)sizeof !!(expr))
#endif /* !INVARIANT_CHECK */


#endif /*LCLIENT_H */
