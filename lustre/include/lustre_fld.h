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
        /* service proc entry */
        cfs_proc_dir_entry_t    *fld_proc_entry;

        /* fld dir proc entry */
        cfs_proc_dir_entry_t    *fld_proc_dir;

        /* pointer to started server service */
        struct ptlrpc_service   *fld_service;

        /* device for access object index methods */
        struct dt_device        *fld_dt;

        /* /fld file object device */
        struct dt_object        *fld_obj;

        /* /fld file fid */
        struct lu_fid            fld_fid;

        /* fld service name in form "fld-MDTXXX" */
        char                     fld_name[80];
};

struct lu_client_fld {
        /* client side proc entry */
        cfs_proc_dir_entry_t    *fld_proc_dir;

        /* list of exports client FLD knows about */
        struct list_head         fld_exports;

        /* current hash to be used to chose an export */
        struct lu_fld_hash      *fld_hash;

        /* exports count */
        int                      fld_count;

        /* lock protecting exports list and fld_hash */
        spinlock_t               fld_lock;

        /* client fld proc entry name */
        char                     fld_name[80];
};

/* server methods */
int fld_server_init(struct lu_server_fld *fld,
                    const struct lu_context *ctx,
                    const char *uuid,
                    struct dt_device *dt);

void fld_server_fini(struct lu_server_fld *fld,
                     const struct lu_context *ctx);

int fld_server_lookup(struct lu_server_fld *fld,
                      const struct lu_context *ctx,
                      __u64 seq, mdsno_t *mds);
        
int fld_server_create(struct lu_server_fld *fld,
                      const struct lu_context *ctx,
                      __u64 seq, mdsno_t mds);

int fld_server_delete(struct lu_server_fld *fld,
                      const struct lu_context *ctx,
                      __u64 seq);

/* client methods */
int fld_client_init(struct lu_client_fld *fld,
                    const char *uuid,
                    int hash);

void fld_client_fini(struct lu_client_fld *fld);

int fld_client_lookup(struct lu_client_fld *fld,
                      __u64 seq, mdsno_t *mds);

int fld_client_create(struct lu_client_fld *fld,
                      __u64 seq, mdsno_t mds);

int fld_client_delete(struct lu_client_fld *fld,
                      __u64 seq);

int fld_client_add_target(struct lu_client_fld *fld,
                          struct obd_export *exp);

int fld_client_del_target(struct lu_client_fld *fld,
                          struct obd_export *exp);

#endif
