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

#ifndef __LINUX_FLD_H
#define __LINUX_FLD_H

struct lu_client_fld;
struct lu_server_fld;

/*
 * FLD (Fid Location Database) interface.
 */
enum {
        LUSTRE_CLI_FLD_HASH_DHT = 0,
        LUSTRE_CLI_FLD_HASH_RRB,
        LUSTRE_CLI_FLD_HASH_LAST
};
        
typedef int (*fld_hash_func_t) (struct lu_client_fld *, __u64);

struct lu_fld_hash {
        const char              *fh_name;
        fld_hash_func_t          fh_func;
};

struct lu_server_fld {
        struct proc_dir_entry   *fld_proc_entry;
        struct ptlrpc_service   *fld_service;
        struct dt_device        *fld_dt;
        struct dt_object        *fld_obj;
        struct lu_fid            fld_fid; /* used during initialization */
        struct dt_index_cookie  *fld_cookie;
};

struct lu_client_fld {
        struct proc_dir_entry   *fld_proc_entry;
        struct list_head         fld_exports;
        struct lu_fld_hash      *fld_hash;
        int                      fld_count;
        spinlock_t               fld_lock;
};

/* server methods */
int fld_server_init(struct lu_server_fld *fld,
                    const struct lu_context *ctx, 
                    struct dt_device *dt);

void fld_server_fini(struct lu_server_fld *fld,
                     const struct lu_context *ctx);

/* client methods */
int fld_client_init(struct lu_client_fld *fld,
                    int hash);

void fld_client_fini(struct lu_client_fld *fld);

int fld_client_add_export(struct lu_client_fld *fld,
                          struct obd_export *exp);

int fld_client_del_export(struct lu_client_fld *fld,
                          struct obd_export *exp);

int fld_client_create(struct lu_client_fld *fld,
                      __u64 seq, __u64 mds);

int fld_client_delete(struct lu_client_fld *fld,
                      __u64 seq, __u64 mds);

int fld_client_get(struct lu_client_fld *fld,
                   __u64 seq, __u64 *mds);

int fld_client_lookup(struct lu_client_fld *fld,
                      __u64 seq, __u64 *mds);

#endif
