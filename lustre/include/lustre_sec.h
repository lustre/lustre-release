/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2007 Cluster File Systems, Inc.
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
 */

#ifndef _LUSTRE_SEC_H_
#define _LUSTRE_SEC_H_

/*
 * to avoid include
 */
struct key;
struct obd_import;
struct obd_export;
struct ptlrpc_request;
struct ptlrpc_reply_state;
struct ptlrpc_bulk_desc;
struct brw_page;
struct seq_file;

/*
 * forward declaration
 */
struct ptlrpc_sec_policy;
struct ptlrpc_sec_cops;
struct ptlrpc_sec_sops;
struct ptlrpc_sec;
struct ptlrpc_svc_ctx;
struct ptlrpc_cli_ctx;
struct ptlrpc_ctx_ops;

/*
 * flavor constants
 */
enum sptlrpc_policy {
        SPTLRPC_POLICY_NULL             = 0,
        SPTLRPC_POLICY_PLAIN            = 1,
        SPTLRPC_POLICY_GSS              = 2,
        SPTLRPC_POLICY_MAX,
};

enum sptlrpc_mech_null {
        SPTLRPC_MECH_NULL               = 0,
        SPTLRPC_MECH_NULL_MAX,
};

enum sptlrpc_mech_plain {
        SPTLRPC_MECH_PLAIN              = 0,
        SPTLRPC_MECH_PLAIN_MAX,
};

enum sptlrpc_mech_gss {
        SPTLRPC_MECH_GSS_NULL           = 0,
        SPTLRPC_MECH_GSS_KRB5           = 1,
        SPTLRPC_MECH_GSS_MAX,
};

enum sptlrpc_service_type {
        SPTLRPC_SVC_NULL                = 0,    /* no security */
        SPTLRPC_SVC_AUTH                = 1,    /* auth only */
        SPTLRPC_SVC_INTG                = 2,    /* integrity */
        SPTLRPC_SVC_PRIV                = 3,    /* privacy */
        SPTLRPC_SVC_MAX,
};

/*
 * rpc flavor compose/extract, represented as 16 bits
 *
 * 4b (reserved) | 4b (svc) | 4b (mech)  | 4b (policy)
 */
#define RPC_FLVR_POLICY_OFFSET        (0)
#define RPC_FLVR_MECH_OFFSET          (4)
#define RPC_FLVR_SVC_OFFSET           (8)

#define MAKE_RPC_FLVR(policy, mech, svc)                                \
        (((__u16)(policy) << RPC_FLVR_POLICY_OFFSET) |                  \
         ((__u16)(mech) << RPC_FLVR_MECH_OFFSET) |                      \
         ((__u16)(svc) << RPC_FLVR_SVC_OFFSET))

#define MAKE_RPC_SUBFLVR(mech, svc)                                     \
        ((__u16)(mech) |                                                \
         ((__u16)(svc) << (RPC_FLVR_SVC_OFFSET - RPC_FLVR_MECH_OFFSET)))

#define RPC_FLVR_SUB(flavor)                                            \
        ((((__u16)(flavor)) >> RPC_FLVR_MECH_OFFSET) & 0xFF)

#define RPC_FLVR_POLICY(flavor)                                         \
        ((((__u16)(flavor)) >> RPC_FLVR_POLICY_OFFSET) & 0xF)
#define RPC_FLVR_MECH(flavor)                                           \
        ((((__u16)(flavor)) >> RPC_FLVR_MECH_OFFSET) & 0xF)
#define RPC_FLVR_SVC(flavor)                                            \
        ((((__u16)(flavor)) >> RPC_FLVR_SVC_OFFSET) & 0xF)

/*
 * gss subflavors
 */
#define SPTLRPC_SUBFLVR_KRB5N                                           \
        MAKE_RPC_SUBFLVR(SPTLRPC_MECH_GSS_KRB5, SPTLRPC_SVC_NULL)
#define SPTLRPC_SUBFLVR_KRB5A                                           \
        MAKE_RPC_SUBFLVR(SPTLRPC_MECH_GSS_KRB5, SPTLRPC_SVC_AUTH)
#define SPTLRPC_SUBFLVR_KRB5I                                           \
        MAKE_RPC_SUBFLVR(SPTLRPC_MECH_GSS_KRB5, SPTLRPC_SVC_INTG)
#define SPTLRPC_SUBFLVR_KRB5P                                           \
        MAKE_RPC_SUBFLVR(SPTLRPC_MECH_GSS_KRB5, SPTLRPC_SVC_PRIV)

/*
 * "end user" flavors
 */
#define SPTLRPC_FLVR_NULL                               \
        MAKE_RPC_FLVR(SPTLRPC_POLICY_NULL,              \
                      SPTLRPC_MECH_NULL,                \
                      SPTLRPC_SVC_NULL)
#define SPTLRPC_FLVR_PLAIN                              \
        MAKE_RPC_FLVR(SPTLRPC_POLICY_PLAIN,             \
                      SPTLRPC_MECH_PLAIN,               \
                      SPTLRPC_SVC_NULL)
#define SPTLRPC_FLVR_KRB5N                              \
        MAKE_RPC_FLVR(SPTLRPC_POLICY_GSS,               \
                      SPTLRPC_MECH_GSS_KRB5,            \
                      SPTLRPC_SVC_NULL)
#define SPTLRPC_FLVR_KRB5A                              \
        MAKE_RPC_FLVR(SPTLRPC_POLICY_GSS,               \
                      SPTLRPC_MECH_GSS_KRB5,            \
                      SPTLRPC_SVC_AUTH)
#define SPTLRPC_FLVR_KRB5I                              \
        MAKE_RPC_FLVR(SPTLRPC_POLICY_GSS,               \
                      SPTLRPC_MECH_GSS_KRB5,            \
                      SPTLRPC_SVC_INTG)
#define SPTLRPC_FLVR_KRB5P                              \
        MAKE_RPC_FLVR(SPTLRPC_POLICY_GSS,               \
                      SPTLRPC_MECH_GSS_KRB5,            \
                      SPTLRPC_SVC_PRIV)

#define SPTLRPC_FLVR_INVALID            ((__u16) -1)

#define SPTLRPC_FLVR_DEFAULT            SPTLRPC_FLVR_NULL

/*
 * 32 bits wire flavor (msg->lm_secflvr), lower 12 bits is the rpc flavor,
 * higher 20 bits is not defined right now.
 */
#define WIRE_FLVR_RPC(wflvr)            (((__u16) (wflvr)) & 0x0FFF)

static inline void rpc_flvr_set_svc(__u16 *flvr, __u16 svc)
{
        LASSERT(svc < SPTLRPC_SVC_MAX);
        *flvr = MAKE_RPC_FLVR(RPC_FLVR_POLICY(*flvr),
                              RPC_FLVR_MECH(*flvr),
                              svc);
}


struct sptlrpc_flavor {
        __u16   sf_rpc;         /* rpc flavor */
        __u8    sf_bulk_ciph;   /* bulk cipher alg */
        __u8    sf_bulk_hash;   /* bulk hash alg */
        __u32   sf_flags;       /* general flags */
};

enum lustre_sec_part {
        LUSTRE_SP_CLI           = 0,
        LUSTRE_SP_MDT,
        LUSTRE_SP_OST,
        LUSTRE_SP_MGS,
        LUSTRE_SP_ANY           = 0xFF
};

struct sptlrpc_rule {
        __u32                   sr_netid;   /* LNET network ID */
        __u8                    sr_from;    /* sec_part */
        __u8                    sr_to;      /* sec_part */
        __u16                   sr_padding;
        struct sptlrpc_flavor   sr_flvr;
};

struct sptlrpc_rule_set {
        int                     srs_nslot;
        int                     srs_nrule;
        struct sptlrpc_rule    *srs_rules;
};

#define SPTLRPC_CONF_LOG_MAX    (64)

struct sptlrpc_conf_log {
        __u32               scl_max;            /* maximum rules # */
        __u32               scl_nrule;          /* rules # */
        __u8                scl_part;           /* which part am i */
        __u8                scl_pad0;
        __u16               scl_pad1;
        __u32               scl_pad2;
        struct sptlrpc_rule scl_rules[SPTLRPC_CONF_LOG_MAX];
};

static inline void sptlrpc_rule_set_init(struct sptlrpc_rule_set *set)
{
        memset(set, 0, sizeof(*set));
}

void sptlrpc_rule_set_free(struct sptlrpc_rule_set *set);
int  sptlrpc_rule_set_expand(struct sptlrpc_rule_set *set, int expand);
int  sptlrpc_rule_set_merge(struct sptlrpc_rule_set *set,
                            struct sptlrpc_rule *rule,
                            int expand);
int sptlrpc_rule_set_from_log(struct sptlrpc_rule_set *rset,
                              struct sptlrpc_conf_log *log);
void sptlrpc_rule_set_choose(struct sptlrpc_rule_set *rset,
                             enum lustre_sec_part from,
                             lnet_nid_t nid,
                             struct sptlrpc_flavor *flavor);
void sptlrpc_rule_set_dump(struct sptlrpc_rule_set *set);

struct sptlrpc_conf_log *sptlrpc_conf_log_alloc(void);
void sptlrpc_conf_log_free(struct sptlrpc_conf_log *log);
int sptlrpc_conf_log_populate(struct sptlrpc_rule_set *gen,
                              struct sptlrpc_rule_set *tgt,
                              enum lustre_sec_part from,
                              enum lustre_sec_part to,
                              unsigned int fl_udesc,
                              struct sptlrpc_conf_log *log);
struct sptlrpc_conf_log *sptlrpc_conf_log_extract(struct lustre_cfg *lcfg);
void sptlrpc_conf_log_cleanup(struct sptlrpc_conf_log *log);
void sptlrpc_conf_log_dump(struct sptlrpc_conf_log *log);

const char *sptlrpc_part2name(enum lustre_sec_part part);
enum lustre_sec_part sptlrpc_target_sec_part(struct obd_device *obd);

int sptlrpc_cliobd_process_config(struct obd_device *obd,
                                  struct lustre_cfg *lcfg);

/* The maximum length of security payload. 1024 is enough for Kerberos 5,
 * and should be enough for other future mechanisms but not sure.
 * Only used by pre-allocated request/reply pool.
 */
#define SPTLRPC_MAX_PAYLOAD     (1024)


struct vfs_cred {
        uint32_t        vc_uid;
        uint32_t        vc_gid;
};

struct ptlrpc_ctx_ops {
        int     (*match)       (struct ptlrpc_cli_ctx *ctx,
                                struct vfs_cred *vcred);
        int     (*refresh)     (struct ptlrpc_cli_ctx *ctx);
        int     (*validate)    (struct ptlrpc_cli_ctx *ctx);
        void    (*die)         (struct ptlrpc_cli_ctx *ctx,
                                int grace);
        int     (*display)     (struct ptlrpc_cli_ctx *ctx,
                                char *buf, int bufsize);
        /*
         * rpc data transform
         */
        int     (*sign)        (struct ptlrpc_cli_ctx *ctx,
                                struct ptlrpc_request *req);
        int     (*verify)      (struct ptlrpc_cli_ctx *ctx,
                                struct ptlrpc_request *req);
        int     (*seal)        (struct ptlrpc_cli_ctx *ctx,
                                struct ptlrpc_request *req);
        int     (*unseal)      (struct ptlrpc_cli_ctx *ctx,
                                struct ptlrpc_request *req);
        /*
         * bulk transform
         */
        int     (*wrap_bulk)   (struct ptlrpc_cli_ctx *ctx,
                                struct ptlrpc_request *req,
                                struct ptlrpc_bulk_desc *desc);
        int     (*unwrap_bulk) (struct ptlrpc_cli_ctx *ctx,
                                struct ptlrpc_request *req,
                                struct ptlrpc_bulk_desc *desc);
};

#define PTLRPC_CTX_NEW_BIT             (0)  /* newly created */
#define PTLRPC_CTX_UPTODATE_BIT        (1)  /* uptodate */
#define PTLRPC_CTX_DEAD_BIT            (2)  /* mark expired gracefully */
#define PTLRPC_CTX_ERROR_BIT           (3)  /* fatal error (refresh, etc.) */
#define PTLRPC_CTX_CACHED_BIT          (8)  /* in ctx cache (hash etc.) */
#define PTLRPC_CTX_ETERNAL_BIT         (9)  /* always valid */

#define PTLRPC_CTX_NEW                 (1 << PTLRPC_CTX_NEW_BIT)
#define PTLRPC_CTX_UPTODATE            (1 << PTLRPC_CTX_UPTODATE_BIT)
#define PTLRPC_CTX_DEAD                (1 << PTLRPC_CTX_DEAD_BIT)
#define PTLRPC_CTX_ERROR               (1 << PTLRPC_CTX_ERROR_BIT)
#define PTLRPC_CTX_CACHED              (1 << PTLRPC_CTX_CACHED_BIT)
#define PTLRPC_CTX_ETERNAL             (1 << PTLRPC_CTX_ETERNAL_BIT)

#define PTLRPC_CTX_STATUS_MASK         (PTLRPC_CTX_NEW_BIT    |       \
                                        PTLRPC_CTX_UPTODATE   |       \
                                        PTLRPC_CTX_DEAD       |       \
                                        PTLRPC_CTX_ERROR)

struct ptlrpc_cli_ctx {
        struct hlist_node       cc_cache;      /* linked into ctx cache */
        atomic_t                cc_refcount;
        struct ptlrpc_sec      *cc_sec;
        struct ptlrpc_ctx_ops  *cc_ops;
        cfs_time_t              cc_expire;     /* in seconds */
        unsigned int            cc_early_expire:1;
        unsigned long           cc_flags;
        struct vfs_cred         cc_vcred;
        spinlock_t              cc_lock;
        struct list_head        cc_req_list;   /* waiting reqs linked here */
        struct list_head        cc_gc_chain;   /* linked to gc chain */
};

struct ptlrpc_sec_cops {
        /*
         * ptlrpc_sec constructor/destructor
         */
        struct ptlrpc_sec *     (*create_sec)  (struct obd_import *imp,
                                                struct ptlrpc_svc_ctx *ctx,
                                                struct sptlrpc_flavor *flavor);
        void                    (*destroy_sec) (struct ptlrpc_sec *sec);

        /*
         * notify to-be-dead
         */
        void                    (*kill_sec)    (struct ptlrpc_sec *sec);

        /*
         * context
         */
        struct ptlrpc_cli_ctx * (*lookup_ctx)  (struct ptlrpc_sec *sec,
                                                struct vfs_cred *vcred,
                                                int create,
                                                int remove_dead);
        void                    (*release_ctx) (struct ptlrpc_sec *sec,
                                                struct ptlrpc_cli_ctx *ctx,
                                                int sync);
        int                     (*flush_ctx_cache)
                                               (struct ptlrpc_sec *sec,
                                                uid_t uid,
                                                int grace,
                                                int force);
        void                    (*gc_ctx)      (struct ptlrpc_sec *sec);

        /*
         * reverse context
         */
        int                     (*install_rctx)(struct obd_import *imp,
                                                struct ptlrpc_sec *sec,
                                                struct ptlrpc_cli_ctx *ctx);

        /*
         * request/reply buffer manipulation
         */
        int                     (*alloc_reqbuf)(struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req,
                                                int lustre_msg_size);
        void                    (*free_reqbuf) (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req);
        int                     (*alloc_repbuf)(struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req,
                                                int lustre_msg_size);
        void                    (*free_repbuf) (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req);
        int                     (*enlarge_reqbuf)
                                               (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req,
                                                int segment, int newsize);
        /*
         * misc
         */
        int                     (*display)     (struct ptlrpc_sec *sec,
                                                struct seq_file *seq);
};

struct ptlrpc_sec_sops {
        int                     (*accept)      (struct ptlrpc_request *req);
        int                     (*authorize)   (struct ptlrpc_request *req);
        void                    (*invalidate_ctx)
                                               (struct ptlrpc_svc_ctx *ctx);
        /* buffer manipulation */
        int                     (*alloc_rs)    (struct ptlrpc_request *req,
                                                int msgsize);
        void                    (*free_rs)     (struct ptlrpc_reply_state *rs);
        void                    (*free_ctx)    (struct ptlrpc_svc_ctx *ctx);
        /* reverse credential */
        int                     (*install_rctx)(struct obd_import *imp,
                                                struct ptlrpc_svc_ctx *ctx);
        /* bulk transform */
        int                     (*unwrap_bulk) (struct ptlrpc_request *req,
                                                struct ptlrpc_bulk_desc *desc);
        int                     (*wrap_bulk)   (struct ptlrpc_request *req,
                                                struct ptlrpc_bulk_desc *desc);
};

struct ptlrpc_sec_policy {
        struct module                  *sp_owner;
        char                           *sp_name;
        __u16                           sp_policy; /* policy number */
        struct ptlrpc_sec_cops         *sp_cops;   /* client ops */
        struct ptlrpc_sec_sops         *sp_sops;   /* server ops */
};

#define PTLRPC_SEC_FL_REVERSE           0x0001 /* reverse sec */
#define PTLRPC_SEC_FL_ROOTONLY          0x0002 /* treat everyone as root */
#define PTLRPC_SEC_FL_UDESC             0x0004 /* ship udesc */
#define PTLRPC_SEC_FL_BULK              0x0008 /* intensive bulk i/o expected */
#define PTLRPC_SEC_FL_PAG               0x0010 /* PAG mode */

struct ptlrpc_sec {
        struct ptlrpc_sec_policy       *ps_policy;
        atomic_t                        ps_refcount;
        atomic_t                        ps_nctx;        /* statistic only */
        int                             ps_id;          /* unique identifier */
        struct sptlrpc_flavor           ps_flvr;        /* flavor */
        enum lustre_sec_part            ps_part;
        unsigned int                    ps_dying:1;
        struct obd_import              *ps_import;      /* owning import */
        spinlock_t                      ps_lock;        /* protect ccache */
        /*
         * garbage collection
         */
        struct list_head                ps_gc_list;
        cfs_time_t                      ps_gc_interval; /* in seconds */
        cfs_time_t                      ps_gc_next;     /* in seconds */
};

static inline int sec_is_reverse(struct ptlrpc_sec *sec)
{
        return (sec->ps_flvr.sf_flags & PTLRPC_SEC_FL_REVERSE);
}

static inline int sec_is_rootonly(struct ptlrpc_sec *sec)
{
        return (sec->ps_flvr.sf_flags & PTLRPC_SEC_FL_ROOTONLY);
}


struct ptlrpc_svc_ctx {
        atomic_t                        sc_refcount;
        struct ptlrpc_sec_policy       *sc_policy;
};

/*
 * user identity descriptor
 */
#define LUSTRE_MAX_GROUPS               (128)

struct ptlrpc_user_desc {
        __u32           pud_uid;
        __u32           pud_gid;
        __u32           pud_fsuid;
        __u32           pud_fsgid;
        __u32           pud_cap;
        __u32           pud_ngroups;
        __u32           pud_groups[0];
};

/*
 * bulk flavors
 */
enum sptlrpc_bulk_hash_alg {
        BULK_HASH_ALG_NULL      = 0,
        BULK_HASH_ALG_ADLER32,
        BULK_HASH_ALG_CRC32,
        BULK_HASH_ALG_MD5,
        BULK_HASH_ALG_SHA1,
        BULK_HASH_ALG_SHA256,
        BULK_HASH_ALG_SHA384,
        BULK_HASH_ALG_SHA512,
        BULK_HASH_ALG_WP256,
        BULK_HASH_ALG_WP384,
        BULK_HASH_ALG_WP512,
        BULK_HASH_ALG_MAX
};

enum sptlrpc_bulk_cipher_alg {
        BULK_CIPH_ALG_NULL      = 0,
        BULK_CIPH_ALG_ARC4,
        BULK_CIPH_ALG_AES128,
        BULK_CIPH_ALG_AES192,
        BULK_CIPH_ALG_AES256,
        BULK_CIPH_ALG_CAST128,
        BULK_CIPH_ALG_CAST256,
        BULK_CIPH_ALG_TWOFISH128,
        BULK_CIPH_ALG_TWOFISH256,
        BULK_CIPH_ALG_MAX
};

struct sptlrpc_hash_type {
        char           *sht_name;
        char           *sht_tfm_name;
        unsigned int    sht_size;
};

struct sptlrpc_ciph_type {
        char           *sct_name;
        char           *sct_tfm_name;
        __u32           sct_tfm_flags;
        unsigned int    sct_ivsize;
        unsigned int    sct_keysize;
};

const struct sptlrpc_hash_type *sptlrpc_get_hash_type(__u8 hash_alg);
const char * sptlrpc_get_hash_name(__u8 hash_alg);
const struct sptlrpc_ciph_type *sptlrpc_get_ciph_type(__u8 ciph_alg);
const char *sptlrpc_get_ciph_name(__u8 ciph_alg);

#define CIPHER_MAX_BLKSIZE      (16)
#define CIPHER_MAX_KEYSIZE      (64)

struct ptlrpc_bulk_sec_desc {
        __u8            bsd_version;
        __u8            bsd_flags;
        __u8            bsd_pad[4];
        __u8            bsd_hash_alg;                /* hash algorithm */
        __u8            bsd_ciph_alg;                /* cipher algorithm */
        __u8            bsd_key[CIPHER_MAX_KEYSIZE]; /* encrypt key seed */
        __u8            bsd_csum[0];
};


/*
 * lprocfs
 */
struct proc_dir_entry;
extern struct proc_dir_entry *sptlrpc_proc_root;

/*
 * round size up to next power of 2, for slab allocation.
 * @size must be sane (can't overflow after round up)
 */
static inline int size_roundup_power2(int size)
{
        size--;
        size |= size >> 1;
        size |= size >> 2;
        size |= size >> 4;
        size |= size >> 8;
        size |= size >> 16;
        size++;
        return size;
}

/*
 * internal support libraries
 */
void _sptlrpc_enlarge_msg_inplace(struct lustre_msg *msg,
                                  int segment, int newsize);

/*
 * security type
 */
int sptlrpc_register_policy(struct ptlrpc_sec_policy *policy);
int sptlrpc_unregister_policy(struct ptlrpc_sec_policy *policy);

__u16 sptlrpc_name2rpcflavor(const char *name);
const char *sptlrpc_rpcflavor2name(__u16 flavor);
int sptlrpc_flavor2name(struct sptlrpc_flavor *sf, char *buf, int bufsize);

static inline
struct ptlrpc_sec_policy *sptlrpc_policy_get(struct ptlrpc_sec_policy *policy)
{
        __module_get(policy->sp_owner);
        return policy;
}

static inline
void sptlrpc_policy_put(struct ptlrpc_sec_policy *policy)
{
        module_put(policy->sp_owner);
}

/*
 * client credential
 */
static inline
unsigned long cli_ctx_status(struct ptlrpc_cli_ctx *ctx)
{
        return (ctx->cc_flags & PTLRPC_CTX_STATUS_MASK);
}

static inline
int cli_ctx_is_ready(struct ptlrpc_cli_ctx *ctx)
{
        return (cli_ctx_status(ctx) == PTLRPC_CTX_UPTODATE);
}

static inline
int cli_ctx_is_refreshed(struct ptlrpc_cli_ctx *ctx)
{
        return (cli_ctx_status(ctx) != 0);
}

static inline
int cli_ctx_is_uptodate(struct ptlrpc_cli_ctx *ctx)
{
        return ((ctx->cc_flags & PTLRPC_CTX_UPTODATE) != 0);
}

static inline
int cli_ctx_is_error(struct ptlrpc_cli_ctx *ctx)
{
        return ((ctx->cc_flags & PTLRPC_CTX_ERROR) != 0);
}

static inline
int cli_ctx_is_dead(struct ptlrpc_cli_ctx *ctx)
{
        return ((ctx->cc_flags & (PTLRPC_CTX_DEAD | PTLRPC_CTX_ERROR)) != 0);
}

static inline
int cli_ctx_is_eternal(struct ptlrpc_cli_ctx *ctx)
{
        return ((ctx->cc_flags & PTLRPC_CTX_ETERNAL) != 0);
}

/*
 * sec get/put
 */
struct ptlrpc_sec *sptlrpc_sec_get(struct ptlrpc_sec *sec);
void sptlrpc_sec_put(struct ptlrpc_sec *sec);

/*
 * internal apis which only used by policy impelentation
 */
int  sptlrpc_get_next_secid(void);
void sptlrpc_sec_destroy(struct ptlrpc_sec *sec);

/*
 * exported client context api
 */
struct ptlrpc_cli_ctx *sptlrpc_cli_ctx_get(struct ptlrpc_cli_ctx *ctx);
void sptlrpc_cli_ctx_put(struct ptlrpc_cli_ctx *ctx, int sync);
void sptlrpc_cli_ctx_expire(struct ptlrpc_cli_ctx *ctx);
void sptlrpc_cli_ctx_wakeup(struct ptlrpc_cli_ctx *ctx);
int sptlrpc_cli_ctx_display(struct ptlrpc_cli_ctx *ctx, char *buf, int bufsize);

/*
 * exported client context wrap/buffers
 */
int sptlrpc_cli_wrap_request(struct ptlrpc_request *req);
int sptlrpc_cli_unwrap_reply(struct ptlrpc_request *req);
int sptlrpc_cli_alloc_reqbuf(struct ptlrpc_request *req, int msgsize);
void sptlrpc_cli_free_reqbuf(struct ptlrpc_request *req);
int sptlrpc_cli_alloc_repbuf(struct ptlrpc_request *req, int msgsize);
void sptlrpc_cli_free_repbuf(struct ptlrpc_request *req);
int sptlrpc_cli_enlarge_reqbuf(struct ptlrpc_request *req,
                               int segment, int newsize);
int sptlrpc_cli_unwrap_early_reply(struct ptlrpc_request *req);
int sptlrpc_cli_finish_early_reply(struct ptlrpc_request *req);

void sptlrpc_request_out_callback(struct ptlrpc_request *req);

/*
 * exported higher interface of import & request
 */
int sptlrpc_import_sec_adapt(struct obd_import *imp,
                             struct ptlrpc_svc_ctx *ctx,
                             __u16 rpc_flavor);
struct ptlrpc_sec *sptlrpc_import_sec_ref(struct obd_import *imp);
void sptlrpc_import_sec_put(struct obd_import *imp);

int  sptlrpc_import_check_ctx(struct obd_import *imp);
void sptlrpc_import_inval_all_ctx(struct obd_import *imp);
void sptlrpc_import_flush_root_ctx(struct obd_import *imp);
void sptlrpc_import_flush_my_ctx(struct obd_import *imp);
void sptlrpc_import_flush_all_ctx(struct obd_import *imp);
int  sptlrpc_req_get_ctx(struct ptlrpc_request *req);
void sptlrpc_req_put_ctx(struct ptlrpc_request *req, int sync);
int  sptlrpc_req_refresh_ctx(struct ptlrpc_request *req, long timeout);
int  sptlrpc_req_replace_dead_ctx(struct ptlrpc_request *req);
void sptlrpc_req_set_flavor(struct ptlrpc_request *req, int opcode);

int sptlrpc_parse_rule(char *param, struct sptlrpc_rule *rule);

/* gc */
void sptlrpc_gc_add_sec(struct ptlrpc_sec *sec);
void sptlrpc_gc_del_sec(struct ptlrpc_sec *sec);
void sptlrpc_gc_add_ctx(struct ptlrpc_cli_ctx *ctx);

/* misc */
const char * sec2target_str(struct ptlrpc_sec *sec);
int sptlrpc_lprocfs_cliobd_attach(struct obd_device *dev);

/*
 * server side
 */
enum secsvc_accept_res {
        SECSVC_OK       = 0,
        SECSVC_COMPLETE,
        SECSVC_DROP,
};

int  sptlrpc_svc_unwrap_request(struct ptlrpc_request *req);
int  sptlrpc_svc_alloc_rs(struct ptlrpc_request *req, int msglen);
int  sptlrpc_svc_wrap_reply(struct ptlrpc_request *req);
void sptlrpc_svc_free_rs(struct ptlrpc_reply_state *rs);
void sptlrpc_svc_ctx_addref(struct ptlrpc_request *req);
void sptlrpc_svc_ctx_decref(struct ptlrpc_request *req);
void sptlrpc_svc_ctx_invalidate(struct ptlrpc_request *req);

int  sptlrpc_target_export_check(struct obd_export *exp,
                                 struct ptlrpc_request *req);
void sptlrpc_target_update_exp_flavor(struct obd_device *obd,
                                      struct sptlrpc_rule_set *rset);

/*
 * reverse context
 */
int sptlrpc_svc_install_rvs_ctx(struct obd_import *imp,
                                struct ptlrpc_svc_ctx *ctx);
int sptlrpc_cli_install_rvs_ctx(struct obd_import *imp,
                                struct ptlrpc_cli_ctx *ctx);

/* bulk security api */
int sptlrpc_enc_pool_add_user(void);
int sptlrpc_enc_pool_del_user(void);
int  sptlrpc_enc_pool_get_pages(struct ptlrpc_bulk_desc *desc);
void sptlrpc_enc_pool_put_pages(struct ptlrpc_bulk_desc *desc);

int sptlrpc_cli_wrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc);
int sptlrpc_cli_unwrap_bulk_read(struct ptlrpc_request *req,
                                 int nob, obd_count pg_count,
                                 struct brw_page **pga);
int sptlrpc_cli_unwrap_bulk_write(struct ptlrpc_request *req,
                                  struct ptlrpc_bulk_desc *desc);
int sptlrpc_svc_wrap_bulk(struct ptlrpc_request *req,
                          struct ptlrpc_bulk_desc *desc);
int sptlrpc_svc_unwrap_bulk(struct ptlrpc_request *req,
                            struct ptlrpc_bulk_desc *desc);

/* user descriptor helpers */
static inline int sptlrpc_user_desc_size(int ngroups)
{
        return sizeof(struct ptlrpc_user_desc) + ngroups * sizeof(__u32);
}

int sptlrpc_current_user_desc_size(void);
int sptlrpc_pack_user_desc(struct lustre_msg *msg, int offset);
int sptlrpc_unpack_user_desc(struct lustre_msg *msg, int offset);

/* bulk helpers (internal use only by policies) */
int bulk_sec_desc_size(__u8 hash_alg, int request, int read);
int bulk_sec_desc_unpack(struct lustre_msg *msg, int offset);

int bulk_csum_cli_request(struct ptlrpc_bulk_desc *desc, int read,
                          __u32 alg, struct lustre_msg *rmsg, int roff);
int bulk_csum_cli_reply(struct ptlrpc_bulk_desc *desc, int read,
                        struct lustre_msg *rmsg, int roff,
                        struct lustre_msg *vmsg, int voff);
int bulk_csum_svc(struct ptlrpc_bulk_desc *desc, int read,
                  struct ptlrpc_bulk_sec_desc *bsdv, int vsize,
                  struct ptlrpc_bulk_sec_desc *bsdr, int rsize);


#endif /* _LUSTRE_SEC_H_ */
