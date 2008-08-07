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
 *
 * lustre/include/lustre_fid.h
 *
 * Author: Yury Umanets <umka@clusterfs.com>
 */

#ifndef __LINUX_FID_H
#define __LINUX_FID_H

/*
 * struct lu_fid
 */
#include <lustre/lustre_idl.h>
#include <lustre_req_layout.h>
#include <lustre_mdt.h>

#include <libcfs/libcfs.h>

struct lu_site;
struct lu_context;

/* Whole sequences space range and zero range definitions */
extern const struct lu_range LUSTRE_SEQ_SPACE_RANGE;
extern const struct lu_range LUSTRE_SEQ_ZERO_RANGE;
extern const struct lu_fid LUSTRE_BFL_FID;

enum {
        /*
         * This is how may FIDs may be allocated in one sequence. 16384 for
         * now.
         */
        LUSTRE_SEQ_MAX_WIDTH = 0x0000000000004000ULL,

        /*
         * How many sequences may be allocate for meta-sequence (this is 128
         * sequences).
         */
        /* changed to 16 to avoid overflow in test11 */
        LUSTRE_SEQ_META_WIDTH = 0x0000000000000010ULL,

        /*
         * This is how many sequences may be in one super-sequence allocated to
         * MDTs.
         */
        LUSTRE_SEQ_SUPER_WIDTH = (LUSTRE_SEQ_META_WIDTH * LUSTRE_SEQ_META_WIDTH)
};

enum lu_mgr_type {
        LUSTRE_SEQ_SERVER,
        LUSTRE_SEQ_CONTROLLER
};

enum lu_cli_type {
        LUSTRE_SEQ_METADATA,
        LUSTRE_SEQ_DATA
};

struct lu_server_seq;

/* Client sequence manager interface. */
struct lu_client_seq {
        /* Sequence-controller export. */
        struct obd_export      *lcs_exp;
        struct semaphore        lcs_sem;

        /*
         * Range of allowed for allocation sequeces. When using lu_client_seq on
         * clients, this contains meta-sequence range. And for servers this
         * contains super-sequence range.
         */
        struct lu_range         lcs_space;

        /* Seq related proc */
        cfs_proc_dir_entry_t   *lcs_proc_dir;

        /* This holds last allocated fid in last obtained seq */
        struct lu_fid           lcs_fid;

        /* LUSTRE_SEQ_METADATA or LUSTRE_SEQ_DATA */
        enum lu_cli_type        lcs_type;

        /*
         * Service uuid, passed from MDT + seq name to form unique seq name to
         * use it with procfs.
         */
        char                    lcs_name[80];

        /*
         * Sequence width, that is how many objects may be allocated in one
         * sequence. Default value for it is LUSTRE_SEQ_MAX_WIDTH.
         */
        __u64                   lcs_width;

        /* Seq-server for direct talking */
        struct lu_server_seq   *lcs_srv;
};

/* server sequence manager interface */
struct lu_server_seq {
        /* Available sequences space */
        struct lu_range         lss_space;

        /*
         * Device for server side seq manager needs (saving sequences to backing
         * store).
         */
        struct dt_device       *lss_dev;

        /* /seq file object device */
        struct dt_object       *lss_obj;

        /* Seq related proc */
        cfs_proc_dir_entry_t   *lss_proc_dir;

        /* LUSTRE_SEQ_SERVER or LUSTRE_SEQ_CONTROLLER */
        enum lu_mgr_type       lss_type;

        /* Client interafce to request controller */
        struct lu_client_seq   *lss_cli;

        /* Semaphore for protecting allocation */
        struct semaphore        lss_sem;

        /*
         * Service uuid, passed from MDT + seq name to form unique seq name to
         * use it with procfs.
         */
        char                    lss_name[80];

        /*
         * Allocation chunks for super and meta sequences. Default values are
         * LUSTRE_SEQ_SUPER_WIDTH and LUSTRE_SEQ_META_WIDTH.
         */
        __u64                   lss_width;
};

int seq_query(struct com_thread_info *info);

/* Server methods */
int seq_server_init(struct lu_server_seq *seq,
                    struct dt_device *dev,
                    const char *prefix,
                    enum lu_mgr_type type,
                    const struct lu_env *env);

void seq_server_fini(struct lu_server_seq *seq,
                     const struct lu_env *env);

int seq_server_alloc_super(struct lu_server_seq *seq,
                           struct lu_range *in,
                           struct lu_range *out,
                           const struct lu_env *env);

int seq_server_alloc_meta(struct lu_server_seq *seq,
                          struct lu_range *in,
                          struct lu_range *out,
                          const struct lu_env *env);

int seq_server_set_cli(struct lu_server_seq *seq,
                       struct lu_client_seq *cli,
                       const struct lu_env *env);

/* Client methods */
int seq_client_init(struct lu_client_seq *seq,
                    struct obd_export *exp,
                    enum lu_cli_type type,
                    const char *prefix,
                    struct lu_server_seq *srv);

void seq_client_fini(struct lu_client_seq *seq);

void seq_client_flush(struct lu_client_seq *seq);

int seq_client_alloc_fid(struct lu_client_seq *seq,
                         struct lu_fid *fid);

/* Fids common stuff */
int fid_is_local(struct lu_site *site, const struct lu_fid *fid);

/* fid locking */

struct ldlm_namespace;

enum {
        LUSTRE_RES_ID_SEQ_OFF = 0,
        LUSTRE_RES_ID_OID_OFF = 1,
        LUSTRE_RES_ID_VER_OFF = 2,
        LUSTRE_RES_ID_HSH_OFF = 3
};

/*
 * Build (DLM) resource name from fid.
 */
static inline struct ldlm_res_id *
fid_build_reg_res_name(const struct lu_fid *f,
                       struct ldlm_res_id *name)
{
        memset(name, 0, sizeof *name);
        name->name[LUSTRE_RES_ID_SEQ_OFF] = fid_seq(f);
        name->name[LUSTRE_RES_ID_OID_OFF] = fid_oid(f);
        name->name[LUSTRE_RES_ID_VER_OFF] = fid_ver(f);
        return name;
}

/*
 * Return true if resource is for object identified by fid.
 */
static inline int fid_res_name_eq(const struct lu_fid *f,
                                  const struct ldlm_res_id *name)
{
        return
                name->name[LUSTRE_RES_ID_SEQ_OFF] == fid_seq(f) &&
                name->name[LUSTRE_RES_ID_OID_OFF] == fid_oid(f) &&
                name->name[LUSTRE_RES_ID_VER_OFF] == fid_ver(f);
}


static inline struct ldlm_res_id *
fid_build_pdo_res_name(const struct lu_fid *f,
                       unsigned int hash,
                       struct ldlm_res_id *name)
{
        fid_build_reg_res_name(f, name);
        name->name[LUSTRE_RES_ID_HSH_OFF] = hash;
        return name;
}

static inline __u64 fid_flatten(const struct lu_fid *fid)
{
        return (fid_seq(fid) - 1) * LUSTRE_SEQ_MAX_WIDTH + fid_oid(fid);
}

#define LUSTRE_SEQ_SRV_NAME "seq_srv"
#define LUSTRE_SEQ_CTL_NAME "seq_ctl"

/* Range common stuff */
void range_cpu_to_le(struct lu_range *dst, const struct lu_range *src);
void range_cpu_to_be(struct lu_range *dst, const struct lu_range *src);
void range_le_to_cpu(struct lu_range *dst, const struct lu_range *src);
void range_be_to_cpu(struct lu_range *dst, const struct lu_range *src);

#endif /* __LINUX_FID_H */
