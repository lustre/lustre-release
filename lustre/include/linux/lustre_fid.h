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
#include <linux/lustre_idl.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

struct lu_seq_mgr_ops {
        int (*smo_read) (void *opaque, __u64 *);
        int (*smo_write) (void *opaque, __u64 *);
};

struct lu_seq_mgr {
        /* seq management fields */
        struct semaphore       m_seq_sem;
        __u64                  m_seq;

        /* ops related stuff */
        void                  *m_opaque;
        struct lu_seq_mgr_ops *m_ops;
};

/* init/fini methods */
struct lu_seq_mgr *seq_mgr_init(struct lu_seq_mgr_ops *, void *);
void seq_mgr_fini(struct lu_seq_mgr *);

/* seq management methods */
int seq_mgr_setup(struct lu_seq_mgr *);
int seq_mgr_read(struct lu_seq_mgr *);
int seq_mgr_write(struct lu_seq_mgr *);
int seq_mgr_alloc(struct lu_seq_mgr *, __u64 *);

#endif /* __LINUX_OBD_CLASS_H */
