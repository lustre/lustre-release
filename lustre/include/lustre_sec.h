/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004-2006 Cluster File Systems, Inc.
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
struct obd_import;
struct ptlrpc_request;
struct ptlrpc_reply_state;
struct ptlrpc_bulk_desc;
struct brw_page;

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
enum sptlrpc_policies {
        SPTLRPC_POLICY_NULL             = 0,
        SPTLRPC_POLICY_PLAIN            = 1,
        SPTLRPC_POLICY_GSS              = 2,
        SPTLRPC_POLICY_MAX,
};

enum sptlrpc_subpolicy_null {
        SPTLRPC_SUBPOLICY_NULL          = 0,
        SPTLRPC_SUBPOLICY_NULL_MAX,
};

enum sptlrpc_subpolicy_plain {
        SPTLRPC_SUBPOLICY_PLAIN         = 0,
        SPTLRPC_SUBPOLICY_PLAIN_MAX,
};

enum sptlrpc_subpolicy_gss {
        SPTLRPC_SUBPOLICY_GSS_NONE      = 0,
        SPTLRPC_SUBPOLICY_GSS_KRB5      = 1,
        SPTLRPC_SUBPOLICY_GSS_MAX,
};

enum sptlrpc_service_type {
        SPTLRPC_SVC_NONE                = 0,    /* no security */
        SPTLRPC_SVC_AUTH                = 1,    /* authentication */
        SPTLRPC_SVC_PRIV                = 2,    /* privacy */
        SPTLRPC_SVC_MAX,
};

/*
 * flavor compose/extract
 */

typedef __u32 ptlrpc_sec_flavor_t;

/*
 *  8b (reserved) | 8b (flags) | 6b (policy) | 6b (subpolicy) | 4b (svc)
 */
#define SEC_FLAVOR_FLAGS_OFFSET         (16)
#define SEC_FLAVOR_POLICY_OFFSET        (10)
#define SEC_FLAVOR_SUBPOLICY_OFFSET     (4)
#define SEC_FLAVOR_SVC_OFFSET           (0)

#define SEC_MAKE_RPC_FLAVOR(policy, subpolicy, svc)                     \
        (((__u32)(policy) << SEC_FLAVOR_POLICY_OFFSET) |                \
         ((__u32)(subpolicy) << SEC_FLAVOR_SUBPOLICY_OFFSET) |          \
         ((__u32)(svc) << SEC_FLAVOR_SVC_OFFSET))

#define SEC_MAKE_RPC_SUBFLAVOR(subpolicy, svc)                          \
        (((__u32)(subpolicy) << SEC_FLAVOR_SUBPOLICY_OFFSET) |          \
         ((__u32)(svc) << SEC_FLAVOR_SVC_OFFSET))

#define SEC_FLAVOR_POLICY(flavor)                                       \
        ((((__u32)(flavor)) >> SEC_FLAVOR_POLICY_OFFSET) & 0x3F)
#define SEC_FLAVOR_SUBPOLICY(flavor)                                    \
        ((((__u32)(flavor)) >> SEC_FLAVOR_SUBPOLICY_OFFSET) & 0x3F)
#define SEC_FLAVOR_SVC(flavor)                                          \
        ((((__u32)(flavor)) >> SEC_FLAVOR_SVC_OFFSET) & 0xF)
#define SEC_FLAVOR_SUB(flavor)                                          \
        ((((__u32)(flavor)) >> SEC_FLAVOR_SVC_OFFSET) & 0x3FF)

#define SEC_FLAVOR_RPC(f)                                               \
        (((__u32) f) & ((1 << SEC_FLAVOR_FLAGS_OFFSET) - 1))

/*
 * general gss flavors
 */
#define SPTLRPC_FLVR_GSS_NONE                                   \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_GSS,                 \
                            SPTLRPC_SUBPOLICY_GSS_NONE,         \
                            SPTLRPC_SVC_NONE)
#define SPTLRPC_FLVR_GSS_AUTH                                   \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_GSS,                 \
                            SPTLRPC_SUBPOLICY_GSS_NONE,         \
                            SPTLRPC_SVC_AUTH)
#define SPTLRPC_FLVR_GSS_PRIV                                   \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_GSS,                 \
                            SPTLRPC_SUBPOLICY_GSS_NONE,         \
                            SPTLRPC_SVC_PRIV)

/*
 * gss subflavors
 */
#define SPTLRPC_SUBFLVR_KRB5                                    \
        SEC_MAKE_RPC_SUBFLAVOR(SPTLRPC_SUBPOLICY_GSS_KRB5,      \
                               SPTLRPC_SVC_NONE)
#define SPTLRPC_SUBFLVR_KRB5I                                   \
        SEC_MAKE_RPC_SUBFLAVOR(SPTLRPC_SUBPOLICY_GSS_KRB5,      \
                               SPTLRPC_SVC_AUTH)
#define SPTLRPC_SUBFLVR_KRB5P                                   \
        SEC_MAKE_RPC_SUBFLAVOR(SPTLRPC_SUBPOLICY_GSS_KRB5,      \
                               SPTLRPC_SVC_PRIV)

/*
 * "end user" flavors
 */
#define SPTLRPC_FLVR_NULL                                       \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_NULL,                \
                            SPTLRPC_SUBPOLICY_NULL,             \
                            SPTLRPC_SVC_NONE)
#define SPTLRPC_FLVR_PLAIN                                      \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_PLAIN,               \
                            SPTLRPC_SUBPOLICY_PLAIN,            \
                            SPTLRPC_SVC_NONE)
#define SPTLRPC_FLVR_KRB5                                       \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_GSS,                 \
                            SPTLRPC_SUBPOLICY_GSS_KRB5,         \
                            SPTLRPC_SVC_NONE)
#define SPTLRPC_FLVR_KRB5I                                      \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_GSS,                 \
                            SPTLRPC_SUBPOLICY_GSS_KRB5,         \
                            SPTLRPC_SVC_AUTH)
#define SPTLRPC_FLVR_KRB5P                                      \
        SEC_MAKE_RPC_FLAVOR(SPTLRPC_POLICY_GSS,                 \
                            SPTLRPC_SUBPOLICY_GSS_KRB5,         \
                            SPTLRPC_SVC_PRIV)

#define SPTLRPC_FLVR_INVALID            (-1)

#define SPTLRPC_FLVR_DEFAULT            SPTLRPC_FLVR_NULL

/*
 * flavor flags (maximum 8 flags)
 */
#define SEC_FLAVOR_FL_BULK              (1 << (0 + SEC_FLAVOR_FLAGS_OFFSET))
#define SEC_FLAVOR_FL_USER              (1 << (1 + SEC_FLAVOR_FLAGS_OFFSET))

#define SEC_FLAVOR_HAS_BULK(flavor)             \
        (((flavor) & SEC_FLAVOR_FL_BULK) != 0)
#define SEC_FLAVOR_HAS_USER(flavor)             \
        (((flavor) & SEC_FLAVOR_FL_USER) != 0)


struct sec_flavor_config {
        __u32   sfc_rpc_flavor; /* main rpc flavor */
        __u32   sfc_bulk_priv;  /* bulk encryption algorithm */
        __u32   sfc_bulk_csum;  /* bulk checksum algorithm */
        __u32   sfc_flags;      /* extra flags */
};

enum lustre_part {
        LUSTRE_CLI      = 0,
        LUSTRE_MDT,
        LUSTRE_OST,
        LUSTRE_MGC,
        LUSTRE_MGS,
};

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

#define PTLRPC_CTX_UPTODATE_BIT        (0)  /* uptodate */
#define PTLRPC_CTX_DEAD_BIT            (1)  /* mark expired gracefully */
#define PTLRPC_CTX_ERROR_BIT           (2)  /* fatal error (refresh, etc.) */
#define PTLRPC_CTX_HASHED_BIT          (8)  /* in hash table */
#define PTLRPC_CTX_ETERNAL_BIT         (9)  /* always valid */

#define PTLRPC_CTX_UPTODATE            (1 << PTLRPC_CTX_UPTODATE_BIT)
#define PTLRPC_CTX_DEAD                (1 << PTLRPC_CTX_DEAD_BIT)
#define PTLRPC_CTX_ERROR               (1 << PTLRPC_CTX_ERROR_BIT)
#define PTLRPC_CTX_HASHED              (1 << PTLRPC_CTX_HASHED_BIT)
#define PTLRPC_CTX_ETERNAL             (1 << PTLRPC_CTX_ETERNAL_BIT)

#define PTLRPC_CTX_STATUS_MASK         (PTLRPC_CTX_UPTODATE   |       \
                                        PTLRPC_CTX_DEAD       |       \
                                        PTLRPC_CTX_ERROR)

struct ptlrpc_cli_ctx {
        struct hlist_node       cc_hash;       /* linked into hash table */
        atomic_t                cc_refcount;
        struct ptlrpc_sec      *cc_sec;
        struct ptlrpc_ctx_ops  *cc_ops;
        cfs_time_t              cc_expire;     /* in seconds */
        unsigned long           cc_flags;
        struct vfs_cred         cc_vcred;
        spinlock_t              cc_lock;
        struct list_head        cc_req_list;   /* waiting reqs linked here */
};

struct ptlrpc_sec_cops {
        /*
         * ptlrpc_sec constructor/destructor
         */
        struct ptlrpc_sec *     (*create_sec)  (struct obd_import *imp,
                                                struct ptlrpc_svc_ctx *ctx,
                                                __u32 flavor,
                                                unsigned long flags);
        void                    (*destroy_sec) (struct ptlrpc_sec *sec);
        /*
         * search ctx for a certain user, if this function is missing,
         * a generic function will be invoked by caller. implement this
         * for any special need.
         */
        struct ptlrpc_cli_ctx * (*lookup_ctx)  (struct ptlrpc_sec *sec,
                                                struct vfs_cred *vcred);
        /*
         * ptlrpc_cli_ctx constructor/destructor
         */
        struct ptlrpc_cli_ctx * (*create_ctx)  (struct ptlrpc_sec *sec,
                                                struct vfs_cred *vcred);
        void                    (*destroy_ctx) (struct ptlrpc_sec *sec,
                                                struct ptlrpc_cli_ctx *ctx);
        /* reverse service */
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
};

struct ptlrpc_sec_sops {
        int                     (*accept)      (struct ptlrpc_request *req);
        int                     (*authorize)   (struct ptlrpc_request *req);
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
        __u32                           sp_policy; /* policy number */
        struct ptlrpc_sec_cops         *sp_cops;   /* client ops */
        struct ptlrpc_sec_sops         *sp_sops;   /* server ops */
};

#define PTLRPC_SEC_FL_REVERSE           0x0001 /* reverse sec */
#define PTLRPC_SEC_FL_ROOTONLY          0x0002 /* treat everyone as root */
#define PTLRPC_SEC_FL_BULK              0x0004 /* intensive bulk i/o expected */

struct ptlrpc_sec {
        struct ptlrpc_sec_policy       *ps_policy;
        atomic_t                        ps_refcount;
        __u32                           ps_flavor;      /* rpc flavor */
        unsigned long                   ps_flags;       /* PTLRPC_SEC_FL_XX */
        struct obd_import              *ps_import;      /* owning import */
        spinlock_t                      ps_lock;        /* protect ccache */
        int                             ps_ccache_size; /* must be 2^n */
        struct hlist_head              *ps_ccache;      /* ctx cache hash */
        atomic_t                        ps_busy;        /* busy count */
        cfs_time_t                      ps_gc_interval; /* in seconds */
        cfs_time_t                      ps_gc_next;     /* in seconds */
};

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
enum bulk_checksum_alg {
        BULK_CSUM_ALG_NULL      = 0,
        BULK_CSUM_ALG_CRC32,
        BULK_CSUM_ALG_MD5,
        BULK_CSUM_ALG_SHA1,
        BULK_CSUM_ALG_SHA256,
        BULK_CSUM_ALG_SHA384,
        BULK_CSUM_ALG_SHA512,
        BULK_CSUM_ALG_MAX
};

enum bulk_encrypt_alg {
        BULK_PRIV_ALG_NULL      = 0,
        BULK_PRIV_ALG_ARC4,
        BULK_PRIV_ALG_MAX
};

struct ptlrpc_bulk_sec_desc {
        __u32           bsd_version;
        __u32           bsd_pad;
        __u32           bsd_csum_alg;   /* checksum algorithm */
        __u32           bsd_priv_alg;   /* encrypt algorithm */
        __u8            bsd_iv[16];     /* encrypt iv */
        __u8            bsd_csum[0];
};

const char * sptlrpc_bulk_csum_alg2name(__u32 csum_alg);
const char * sptlrpc_bulk_priv_alg2name(__u32 priv_alg);

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
        int rc;

        LASSERT(size > 0);
        rc = 1 << (fls(size) - 1);
        if ((rc - 1) & size)
                rc <<= 1;
        LASSERT(rc > 0);
        return rc;
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

__u32 sptlrpc_name2flavor(const char *name);
char *sptlrpc_flavor2name(__u32 flavor);

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
struct ptlrpc_cli_ctx *sptlrpc_ctx_get(struct ptlrpc_cli_ctx *ctx);
void sptlrpc_ctx_put(struct ptlrpc_cli_ctx *ctx, int sync);
void sptlrpc_ctx_expire(struct ptlrpc_cli_ctx *ctx);
void sptlrpc_ctx_replace(struct ptlrpc_sec *sec, struct ptlrpc_cli_ctx *new);
void sptlrpc_ctx_wakeup(struct ptlrpc_cli_ctx *ctx);
int sptlrpc_ctx_display(struct ptlrpc_cli_ctx *ctx, char *buf, int bufsize);

/*
 * client wrap/buffers
 */
int sptlrpc_cli_wrap_request(struct ptlrpc_request *req);
int sptlrpc_cli_unwrap_reply(struct ptlrpc_request *req);
int sptlrpc_cli_alloc_reqbuf(struct ptlrpc_request *req, int msgsize);
void sptlrpc_cli_free_reqbuf(struct ptlrpc_request *req);
int sptlrpc_cli_alloc_repbuf(struct ptlrpc_request *req, int msgsize);
void sptlrpc_cli_free_repbuf(struct ptlrpc_request *req);
int sptlrpc_cli_enlarge_reqbuf(struct ptlrpc_request *req,
                               int segment, int newsize);
void sptlrpc_request_out_callback(struct ptlrpc_request *req);

/*
 * higher interface of import & request
 */
int sptlrpc_import_get_sec(struct obd_import *imp, struct ptlrpc_svc_ctx *svc_ctx,
                           __u32 flavor, unsigned long flags);
void sptlrpc_import_put_sec(struct obd_import *imp);
int sptlrpc_import_check_ctx(struct obd_import *imp);
void sptlrpc_import_flush_root_ctx(struct obd_import *imp);
void sptlrpc_import_flush_my_ctx(struct obd_import *imp);
void sptlrpc_import_flush_all_ctx(struct obd_import *imp);
int  sptlrpc_req_get_ctx(struct ptlrpc_request *req);
void sptlrpc_req_put_ctx(struct ptlrpc_request *req);
int  sptlrpc_req_refresh_ctx(struct ptlrpc_request *req, long timeout);
void sptlrpc_req_set_flavor(struct ptlrpc_request *req, int opcode);

int sptlrpc_parse_flavor(enum lustre_part from, enum lustre_part to,
                         char *str, struct sec_flavor_config *conf);
/* misc */
const char * sec2target_str(struct ptlrpc_sec *sec);
int sptlrpc_lprocfs_rd(char *page, char **start, off_t off, int count,
                       int *eof, void *data);

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
int sptlrpc_user_desc_size(void);
int sptlrpc_pack_user_desc(struct lustre_msg *msg, int offset);
int sptlrpc_unpack_user_desc(struct lustre_msg *msg, int offset);

/* bulk helpers (internal use only by policies) */
int bulk_sec_desc_size(__u32 csum_alg, int request, int read);
int bulk_sec_desc_unpack(struct lustre_msg *msg, int offset);

int bulk_csum_cli_request(struct ptlrpc_bulk_desc *desc, int read,
                          __u32 alg, struct lustre_msg *rmsg, int roff);
int bulk_csum_cli_reply(struct ptlrpc_bulk_desc *desc, int read,
                        struct lustre_msg *rmsg, int roff,
                        struct lustre_msg *vmsg, int voff);
int bulk_csum_svc(struct ptlrpc_bulk_desc *desc, int read,
                  struct lustre_msg *vmsg, int voff,
                  struct lustre_msg *rmsg, int roff);


#endif /* _LUSTRE_SEC_H_ */
