/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __LINUX_FID_H
#define __LINUX_FID_H

/*
 * struct lu_fid
 */
#include <lustre/lustre_idl.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

struct lu_site;
struct lu_context;

/* start seq number */
#define LUSTRE_SEQ_SPACE_START  0x400

/* maximal posible seq number */
#define LUSTRE_SEQ_SPACE_END  ((__u64)~0ULL)

/* this is how may FIDs may be allocated in one sequence. */
#define LUSTRE_SEQ_WIDTH 0x00000000000002800

/* how many sequences may be allocate for meta-sequence (this is 10240
 * sequences). */
#define LUSTRE_SEQ_META_CHUNK 0x00000000000002800

/* how many sequences may be allocate for super-sequence (this is 10240 * 10240
 * sequences), what means that one alloaction for super-sequence allows to
 * allocate 10240 meta-sequences and each of them may have 10240 sequences. */
#define LUSTRE_SEQ_SUPER_CHUNK (LUSTRE_SEQ_META_CHUNK * LUSTRE_SEQ_META_CHUNK)

/* client sequence manager interface */
struct lu_client_seq {
        /* sequence-controller export. */
        struct obd_export      *seq_exp;
        struct semaphore        seq_sem;

        /* different flags. */
        int                     seq_flags;

        /* range of allowed for allocation sequeces. When using lu_client_seq on
         * clients, this contains meta-sequence range. And for servers this
         * contains super-sequence range. */
        struct lu_range         seq_range;

        /* seq related proc */
        struct proc_dir_entry  *seq_proc_entry;

        /* this holds last allocated fid in last obtained seq */
        struct lu_fid           seq_fid;
};

#ifdef __KERNEL__
/* server sequence manager interface */
struct lu_server_seq {
        /* available sequence space */
        struct lu_range         seq_space;

        /* super-sequence range, all super-sequences for other servers are
         * allocated from it. */
        struct lu_range         seq_super;
       
        /* device for server side seq manager needs (saving sequences to backing
         * store). */
        struct dt_device       *seq_dev;

        /* different flags: LUSTRE_SEQ_CONTROLLER, etc. */
        int                     seq_flags;

        /* seq related proc */
        struct proc_dir_entry  *seq_proc_entry;

        /* server side seq service */
        struct ptlrpc_service  *seq_service;

        /* client interafce to request controller */
        struct lu_client_seq   *seq_cli;

        /* semaphore for protecting allocation */
        struct semaphore        seq_sem;
};
#endif

#ifdef __KERNEL__
int seq_server_init(struct lu_server_seq *seq,
                    struct dt_device *dev, int flags,
                    const struct lu_context *ctx);

void seq_server_fini(struct lu_server_seq *seq,
                     const struct lu_context *ctx);

int seq_server_controller(struct lu_server_seq *seq,
                          struct lu_client_seq *cli,
                          const struct lu_context *ctx);
#endif

int seq_client_init(struct lu_client_seq *seq, 
                    struct obd_export *exp,
                    int flags);

void seq_client_fini(struct lu_client_seq *seq);

int seq_client_alloc_super(struct lu_client_seq *seq);
int seq_client_alloc_meta(struct lu_client_seq *seq);

int seq_client_alloc_seq(struct lu_client_seq *seq,
                         __u64 *seqnr);
int seq_client_alloc_fid(struct lu_client_seq *seq,
                         struct lu_fid *fid);

/* Fids common stuff */
static inline int fid_is_local(struct lu_site *site,
                               const struct lu_fid *fid)
{
        /* XXX: fix this when fld is ready. */
        return 1;
}

void fid_to_le(struct lu_fid *dst, const struct lu_fid *src);

#endif /* __LINUX_OBD_CLASS_H */
