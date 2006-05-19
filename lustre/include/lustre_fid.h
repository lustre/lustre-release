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

struct lu_context;
struct lu_seq_mgr_ops {
        int (*smo_read) (struct lu_context *, void *opaque, __u64 *);
        int (*smo_write) (struct lu_context *, void *opaque, __u64 *);
};

struct lu_seq_mgr {
        /* seq management fields */
        struct semaphore       m_seq_sem;
        /* each MDS has own range of seqs ended with this value
         * if it is overflowed the new one should be got from master node */
        __u64                  m_seq_last;
        /* last allocated seq */
        __u64                  m_seq;
        /* ops related stuff */
        void                  *m_opaque;
        struct lu_seq_mgr_ops *m_ops;
};

/* init/fini methods */
struct lu_seq_mgr *seq_mgr_init(struct lu_seq_mgr_ops *, void *);
void seq_mgr_fini(struct lu_seq_mgr *);

/* seq management methods */
int seq_mgr_setup(struct lu_context *, struct lu_seq_mgr *);
int seq_mgr_read(struct lu_context *, struct lu_seq_mgr *);
int seq_mgr_write(struct lu_context *, struct lu_seq_mgr *);
int seq_mgr_alloc(struct lu_context *, struct lu_seq_mgr *, __u64 *);
int seq_mgr_range_alloc(struct lu_context *, struct lu_seq_mgr *, __u64 *);
struct lu_site;
#if 0
int fid_is_local(struct lu_site *site, const struct lu_fid *fid);
#else
static inline int fid_is_local(struct lu_site *site, const struct lu_fid *fid)
{
        return 1;
}
#endif

void fid_to_le(struct lu_fid *dst, const struct lu_fid *src);

/*
 * fld (fid location database) interface.
 */
struct fld_info {
        void *fi_container;
};
struct fld {
        struct proc_dir_entry   *fld_proc_entry;
        struct ptlrpc_service   *fld_service;
        struct dt_device        *fld_dt;
        struct fld_info         *fld_info;
};

int  fld_server_init(struct fld *fld, struct dt_device *dt);
void fld_server_fini(struct fld *fld);


#endif /* __LINUX_OBD_CLASS_H */
