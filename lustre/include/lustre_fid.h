/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *   Author: Yury Umanets <umka@clusterfs.com>
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
#include <lustre_req_layout.h>
#include <lustre_mdt.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

struct lu_site;
struct lu_context;

/* whole sequences space range and zero range definitions */
extern const struct lu_range LUSTRE_SEQ_SPACE_RANGE;
extern const struct lu_range LUSTRE_SEQ_ZERO_RANGE;
extern const struct lu_fid LUSTRE_BFL_FID;

enum {
        /* this is how may FIDs may be allocated in one sequence. 16384 for now */
        LUSTRE_SEQ_MAX_WIDTH = 0x0000000000004000ULL,

        /* how many sequences may be allocate for meta-sequence (this is 128
         * sequences). */
        LUSTRE_SEQ_META_WIDTH = 0x0000000000000080ULL,

        /* this is how many sequences may be in one super-sequence allocated to
         * MDTs. */
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

/* client sequence manager interface */
struct lu_client_seq {
        /* sequence-controller export. */
        struct obd_export      *lcs_exp;
        struct semaphore        lcs_sem;

        /* range of allowed for allocation sequeces. When using lu_client_seq on
         * clients, this contains meta-sequence range. And for servers this
         * contains super-sequence range. */
        struct lu_range         lcs_range;

        /* seq related proc */
        cfs_proc_dir_entry_t   *lcs_proc_dir;

        /* this holds last allocated fid in last obtained seq */
        struct lu_fid           lcs_fid;

        /* LUSTRE_SEQ_METADATA or LUSTRE_SEQ_DATA */
        enum lu_cli_type        lcs_type;

        /* service uuid, passed from MDT + seq name to form unique seq name to
         * use it with procfs. */
        char                    lcs_name[80];

        /* sequence width, that is how many objects may be allocated in one
         * sequence. Default value for it is LUSTRE_SEQ_MAX_WIDTH. */
        __u64                   lcs_width;

        /* seq-server for direct talking */
        struct lu_server_seq   *lcs_srv;
};

/* server sequence manager interface */
struct lu_server_seq {
        /* available sequence space */
        struct lu_range         lss_space;

        /* super-sequence range, all super-sequences for other servers are
         * allocated from it. */
        struct lu_range         lss_super;

        /* device for server side seq manager needs (saving sequences to backing
         * store). */
        struct dt_device       *lss_dev;

        /* /seq file object device */
        struct dt_object       *lss_obj;

        /* seq related proc */
        cfs_proc_dir_entry_t   *lss_proc_dir;

        /* LUSTRE_SEQ_SERVER or LUSTRE_SEQ_CONTROLLER */
        enum lu_mgr_type       lss_type;

        /* client interafce to request controller */
        struct lu_client_seq   *lss_cli;

        /* semaphore for protecting allocation */
        struct semaphore        lss_sem;

        /* service uuid, passed from MDT + seq name to form unique seq name to
         * use it with procfs. */
        char                    lss_name[80];

        /* allocation chunks for super and meta sequences. Default values are
         * LUSTRE_SEQ_SUPER_WIDTH and LUSTRE_SEQ_META_WIDTH. */
        __u64                   lss_super_width;
        __u64                   lss_meta_width;
};

int seq_query(struct com_thread_info *info);

/* Server methods */
int seq_server_init(struct lu_server_seq *seq,
                    struct dt_device *dev,
                    const char *prefix,
                    enum lu_mgr_type type,
                    const struct lu_context *ctx);

void seq_server_fini(struct lu_server_seq *seq,
                     const struct lu_context *ctx);

int seq_server_alloc_super(struct lu_server_seq *seq,
                           struct lu_range *in,
                           struct lu_range *out,
                           const struct lu_context *ctx);

int seq_server_alloc_meta(struct lu_server_seq *seq,
                          struct lu_range *in,
                          struct lu_range *out,
                          const struct lu_context *ctx);

int seq_server_set_cli(struct lu_server_seq *seq,
                       struct lu_client_seq *cli,
                       const struct lu_context *ctx);

/* Client methods */
int seq_client_init(struct lu_client_seq *seq,
                    struct obd_export *exp,
                    enum lu_cli_type type,
                    const char *prefix,
                    struct lu_server_seq *srv);

void seq_client_fini(struct lu_client_seq *seq);

int seq_client_alloc_super(struct lu_client_seq *seq,
                           const struct lu_context *ctx);

int seq_client_alloc_meta(struct lu_client_seq *seq,
                          const struct lu_context *ctx);

int seq_client_alloc_seq(struct lu_client_seq *seq,
                         seqno_t *seqnr);

int seq_client_alloc_fid(struct lu_client_seq *seq,
                         struct lu_fid *fid);

/* Fids common stuff */
int fid_is_local(struct lu_site *site, const struct lu_fid *fid);

void fid_cpu_to_le(struct lu_fid *dst, const struct lu_fid *src);
void fid_cpu_to_be(struct lu_fid *dst, const struct lu_fid *src);
void fid_le_to_cpu(struct lu_fid *dst, const struct lu_fid *src);
void fid_be_to_cpu(struct lu_fid *dst, const struct lu_fid *src);

/* fid locking */

struct ldlm_namespace;

int fid_lock(struct ldlm_namespace *ns, const struct lu_fid *f,
             struct lustre_handle *lh, ldlm_mode_t mode,
             ldlm_policy_data_t *policy,
             struct ldlm_res_id *res_id);
void fid_unlock(const struct lu_fid *f,
                struct lustre_handle *lh, ldlm_mode_t mode);

/*
 * Build (DLM) resource name from fid.
 */
static inline struct ldlm_res_id *
fid_build_res_name(const struct lu_fid *f,
                   struct ldlm_res_id *name)
{
        memset(name, 0, sizeof *name);
        name->name[0] = fid_seq(f);
        name->name[1] = fid_oid(f);
        name->name[2] = fid_ver(f);
        return name;
}

#define LUSTRE_SEQ_SRV_NAME "seq_srv"
#define LUSTRE_SEQ_CTL_NAME "seq_ctl"

/* Range common stuff */
void range_cpu_to_le(struct lu_range *dst, const struct lu_range *src);
void range_cpu_to_be(struct lu_range *dst, const struct lu_range *src);
void range_le_to_cpu(struct lu_range *dst, const struct lu_range *src);
void range_be_to_cpu(struct lu_range *dst, const struct lu_range *src);

#endif /* __LINUX_FID_H */
