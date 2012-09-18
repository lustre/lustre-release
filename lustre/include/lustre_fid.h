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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Whamcloud, Inc.
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

/** \defgroup fid fid
 *
 * @{
 */

/*
 * struct lu_fid
 */
#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <lustre_req_layout.h>
#include <lustre_mdt.h>


struct lu_site;
struct lu_context;

/* Whole sequences space range and zero range definitions */
extern const struct lu_seq_range LUSTRE_SEQ_SPACE_RANGE;
extern const struct lu_seq_range LUSTRE_SEQ_ZERO_RANGE;
extern const struct lu_fid LUSTRE_BFL_FID;
extern const struct lu_fid LU_OBF_FID;
extern const struct lu_fid LU_DOT_LUSTRE_FID;

enum {
        /*
         * This is how may FIDs may be allocated in one sequence(128k)
         */
        LUSTRE_SEQ_MAX_WIDTH = 0x0000000000020000ULL,

        /*
         * How many sequences to allocate to a client at once.
         */
        LUSTRE_SEQ_META_WIDTH = 0x0000000000000001ULL,

         /*
          * seq allocation pool size.
          */
        LUSTRE_SEQ_BATCH_WIDTH = LUSTRE_SEQ_META_WIDTH * 1000,

        /*
         * This is how many sequences may be in one super-sequence allocated to
         * MDTs.
         */
        LUSTRE_SEQ_SUPER_WIDTH = ((1ULL << 30ULL) * LUSTRE_SEQ_META_WIDTH)
};

enum {
        /** 2^6 FIDs for OI containers */
        OSD_OI_FID_OID_BITS     = 6,
        /** reserve enough FIDs in case we want more in the future */
        OSD_OI_FID_OID_BITS_MAX = 10,
};

/** special OID for local objects */
enum local_oid {
        /** \see fld_mod_init */
        FLD_INDEX_OID           = 3UL,
        /** \see fid_mod_init */
        FID_SEQ_CTL_OID         = 4UL,
        FID_SEQ_SRV_OID         = 5UL,
        /** \see mdd_mod_init */
        MDD_ROOT_INDEX_OID      = 6UL,
        MDD_ORPHAN_OID          = 7UL,
        MDD_LOV_OBJ_OID         = 8UL,
        MDD_CAPA_KEYS_OID       = 9UL,
        /** \see mdt_mod_init */
        MDT_LAST_RECV_OID       = 11UL,
        OSD_FS_ROOT_OID         = 13UL,
        ACCT_USER_OID           = 15UL,
        ACCT_GROUP_OID          = 16UL,
	LFSCK_BOOKMARK_OID	= 17UL,
	OTABLE_IT_OID		= 18UL,
        OFD_LAST_RECV_OID       = 19UL,
        OFD_GROUP0_LAST_OID     = 20UL,
        OFD_GROUP4K_LAST_OID    = 20UL+4096,
        OFD_LAST_GROUP_OID      = 4117UL,
        LLOG_CATALOGS_OID       = 4118UL,
        MGS_CONFIGS_OID         = 4119UL,
        OFD_HEALTH_CHECK_OID    = 4120UL,
};

static inline void lu_local_obj_fid(struct lu_fid *fid, __u32 oid)
{
        fid->f_seq = FID_SEQ_LOCAL_FILE;
        fid->f_oid = oid;
        fid->f_ver = 0;
}

static inline void lu_local_name_obj_fid(struct lu_fid *fid, __u32 oid)
{
        fid->f_seq = FID_SEQ_LOCAL_NAME;
        fid->f_oid = oid;
        fid->f_ver = 0;
}

static inline int fid_is_otable_it(const struct lu_fid *fid)
{
	return unlikely(fid_seq(fid) == FID_SEQ_LOCAL_FILE &&
			fid_oid(fid) == OTABLE_IT_OID);
}

static inline int fid_is_acct(const struct lu_fid *fid)
{
        return fid_seq(fid) == FID_SEQ_LOCAL_FILE &&
               (fid_oid(fid) == ACCT_USER_OID ||
                fid_oid(fid) == ACCT_GROUP_OID);
}

static inline int fid_is_quota(const struct lu_fid *fid)
{
	return fid_seq(fid) == FID_SEQ_QUOTA ||
	       fid_seq(fid) == FID_SEQ_QUOTA_GLB;
}

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
        cfs_mutex_t             lcs_mutex;

        /*
         * Range of allowed for allocation sequeces. When using lu_client_seq on
         * clients, this contains meta-sequence range. And for servers this
         * contains super-sequence range.
         */
        struct lu_seq_range         lcs_space;

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

        /* wait queue for fid allocation and update indicator */
        cfs_waitq_t             lcs_waitq;
        int                     lcs_update;
};

/* server sequence manager interface */
struct lu_server_seq {
        /* Available sequences space */
        struct lu_seq_range         lss_space;

        /* keeps highwater in lsr_end for seq allocation algorithm */
        struct lu_seq_range         lss_lowater_set;
        struct lu_seq_range         lss_hiwater_set;

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

        /* Mutex for protecting allocation */
        cfs_mutex_t             lss_mutex;

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

        /*
         * minimum lss_alloc_set size that should be allocated from
         * lss_space
         */
        __u64                   lss_set_width;

        /* sync is needed for update operation */
        __u32                   lss_need_sync;
        /**
         * Pointer to site object, required to access site fld.
         */
        struct md_site         *lss_site;
};

int seq_query(struct com_thread_info *info);

/* Server methods */
int seq_server_init(struct lu_server_seq *seq,
                    struct dt_device *dev,
                    const char *prefix,
                    enum lu_mgr_type type,
                    struct md_site *ls,
                    const struct lu_env *env);

void seq_server_fini(struct lu_server_seq *seq,
                     const struct lu_env *env);

int seq_server_alloc_super(struct lu_server_seq *seq,
                           struct lu_seq_range *out,
                           const struct lu_env *env);

int seq_server_alloc_meta(struct lu_server_seq *seq,
                          struct lu_seq_range *out,
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

int seq_client_alloc_fid(const struct lu_env *env, struct lu_client_seq *seq,
                         struct lu_fid *fid);
int seq_client_get_seq(const struct lu_env *env, struct lu_client_seq *seq,
                       seqno_t *seqnr);

/* Fids common stuff */
int fid_is_local(const struct lu_env *env,
                 struct lu_site *site, const struct lu_fid *fid);

/* fid locking */

struct ldlm_namespace;

/*
 * Build (DLM) resource name from FID.
 *
 * NOTE: until Lustre 1.8.7/2.1.1 the fid_ver() was packed into name[2],
 * but was moved into name[1] along with the OID to avoid consuming the
 * renaming name[2,3] fields that need to be used for the quota identifier.
 */
static inline struct ldlm_res_id *
fid_build_reg_res_name(const struct lu_fid *f,
                       struct ldlm_res_id *name)
{
        memset(name, 0, sizeof *name);
        name->name[LUSTRE_RES_ID_SEQ_OFF] = fid_seq(f);
        name->name[LUSTRE_RES_ID_VER_OID_OFF] = fid_ver_oid(f);
        return name;
}

/*
 * Return true if resource is for object identified by fid.
 */
static inline int fid_res_name_eq(const struct lu_fid *f,
                                  const struct ldlm_res_id *name)
{
        return name->name[LUSTRE_RES_ID_SEQ_OFF] == fid_seq(f) &&
               name->name[LUSTRE_RES_ID_VER_OID_OFF] == fid_ver_oid(f);
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


/**
 * Flatten 128-bit FID values into a 64-bit value for use as an inode number.
 * For non-IGIF FIDs this starts just over 2^32, and continues without
 * conflict until 2^64, at which point we wrap the high 24 bits of the SEQ
 * into the range where there may not be many OID values in use, to minimize
 * the risk of conflict.
 *
 * Suppose LUSTRE_SEQ_MAX_WIDTH less than (1 << 24) which is currently true,
 * the time between re-used inode numbers is very long - 2^40 SEQ numbers,
 * or about 2^40 client mounts, if clients create less than 2^24 files/mount.
 */
static inline __u64 fid_flatten(const struct lu_fid *fid)
{
        __u64 ino;
        __u64 seq;

        if (fid_is_igif(fid)) {
                ino = lu_igif_ino(fid);
                RETURN(ino);
        }

        seq = fid_seq(fid);

        ino = (seq << 24) + ((seq >> 24) & 0xffffff0000ULL) + fid_oid(fid);

        RETURN(ino ? ino : fid_oid(fid));
}

static inline __u32 fid_hash(const struct lu_fid *f, int bits)
{
        /* all objects with same id and different versions will belong to same
         * collisions list. */
        return cfs_hash_long(fid_flatten(f), bits);
}

/**
 * map fid to 32 bit value for ino on 32bit systems. */
static inline __u32 fid_flatten32(const struct lu_fid *fid)
{
        __u32 ino;
        __u64 seq;

        if (fid_is_igif(fid)) {
                ino = lu_igif_ino(fid);
                RETURN(ino);
        }

        seq = fid_seq(fid) - FID_SEQ_START;

        /* Map the high bits of the OID into higher bits of the inode number so
         * that inodes generated at about the same time have a reduced chance
         * of collisions. This will give a period of 2^12 = 1024 unique clients
         * (from SEQ) and up to min(LUSTRE_SEQ_MAX_WIDTH, 2^20) = 128k objects
         * (from OID), or up to 128M inodes without collisions for new files. */
        ino = ((seq & 0x000fffffULL) << 12) + ((seq >> 8) & 0xfffff000) +
               (seq >> (64 - (40-8)) & 0xffffff00) +
               (fid_oid(fid) & 0xff000fff) + ((fid_oid(fid) & 0x00fff000) << 8);

        RETURN(ino ? ino : fid_oid(fid));
}

#define LUSTRE_SEQ_SRV_NAME "seq_srv"
#define LUSTRE_SEQ_CTL_NAME "seq_ctl"

/* Range common stuff */
static inline void range_cpu_to_le(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        dst->lsr_start = cpu_to_le64(src->lsr_start);
        dst->lsr_end = cpu_to_le64(src->lsr_end);
        dst->lsr_index = cpu_to_le32(src->lsr_index);
        dst->lsr_flags = cpu_to_le32(src->lsr_flags);
}

static inline void range_le_to_cpu(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        dst->lsr_start = le64_to_cpu(src->lsr_start);
        dst->lsr_end = le64_to_cpu(src->lsr_end);
        dst->lsr_index = le32_to_cpu(src->lsr_index);
        dst->lsr_flags = le32_to_cpu(src->lsr_flags);
}

static inline void range_cpu_to_be(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        dst->lsr_start = cpu_to_be64(src->lsr_start);
        dst->lsr_end = cpu_to_be64(src->lsr_end);
        dst->lsr_index = cpu_to_be32(src->lsr_index);
        dst->lsr_flags = cpu_to_be32(src->lsr_flags);
}

static inline void range_be_to_cpu(struct lu_seq_range *dst, const struct lu_seq_range *src)
{
        dst->lsr_start = be64_to_cpu(src->lsr_start);
        dst->lsr_end = be64_to_cpu(src->lsr_end);
        dst->lsr_index = be32_to_cpu(src->lsr_index);
        dst->lsr_flags = be32_to_cpu(src->lsr_flags);
}

/** @} fid */

#endif /* __LINUX_FID_H */
