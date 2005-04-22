/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Modified from NFSv4 project for Lustre
 * Copyright 2004, Cluster File Systems, Inc.
 * All rights reserved
 * Author: Eric Mei <ericm@clusterfs.com>
 */

#ifndef __SEC_GSS_GSS_INTERNAL_H_
#define __SEC_GSS_GSS_INTERNAL_H_

/* remove this mess when libkcrypt is ready --umka */
#ifndef __KERNEL__
/*
 * Algorithm masks and types.
 */
#define CRYPTO_ALG_TYPE_MASK		0x000000ff
#define CRYPTO_ALG_TYPE_CIPHER		0x00000001
#define CRYPTO_ALG_TYPE_DIGEST		0x00000002
#define CRYPTO_ALG_TYPE_COMPRESS	0x00000004

/*
 * Transform masks and values (for crt_flags).
 */
#define CRYPTO_TFM_MODE_MASK		0x000000ff
#define CRYPTO_TFM_REQ_MASK		0x000fff00
#define CRYPTO_TFM_RES_MASK		0xfff00000

#define CRYPTO_TFM_MODE_ECB		0x00000001
#define CRYPTO_TFM_MODE_CBC		0x00000002
#define CRYPTO_TFM_MODE_CFB		0x00000004
#define CRYPTO_TFM_MODE_CTR		0x00000008

#define CRYPTO_TFM_REQ_WEAK_KEY		0x00000100
#define CRYPTO_TFM_RES_WEAK_KEY		0x00100000
#define CRYPTO_TFM_RES_BAD_KEY_LEN   	0x00200000
#define CRYPTO_TFM_RES_BAD_KEY_SCHED 	0x00400000
#define CRYPTO_TFM_RES_BAD_BLOCK_LEN 	0x00800000
#define CRYPTO_TFM_RES_BAD_FLAGS 	0x01000000

/*
 * Miscellaneous stuff.
 */
#define CRYPTO_UNSPEC			0
#define CRYPTO_MAX_ALG_NAME		64

struct scatterlist {
    struct page		*page;
    unsigned int	offset;
    __u32		dma_address;
    unsigned int	length;
};

static inline struct crypto_tfm *
crypto_alloc_tfm(const char *name, __u32 flags)
{
	return NULL;
}

static inline void 
crypto_free_tfm(struct crypto_tfm *tfm)
{
	return;
}

static inline int 
crypto_digest_setkey(struct crypto_tfm *tfm,
                     const __u8 *key, unsigned int keylen)
{
	return -ENOSYS;
}

static inline unsigned int 
crypto_tfm_alg_blocksize(struct crypto_tfm *tfm)
{
	return 0;
}

static inline unsigned int 
crypto_tfm_alg_ivsize(struct crypto_tfm *tfm)
{
	return 0;
}

#endif /* __KERNEL__ */

struct ptlrpc_sec;
struct ptlrpc_cred;

typedef struct rawobj_s {
        __u32           len;
        __u8           *data;
} rawobj_t;

int rawobj_alloc(rawobj_t *obj, char *buf, int len);
void rawobj_free(rawobj_t *obj);
int rawobj_equal(rawobj_t *a, rawobj_t *b);
int rawobj_dup(rawobj_t *dest, rawobj_t *src);
int rawobj_serialize(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_extract(rawobj_t *obj, __u32 **buf, __u32 *buflen);
int rawobj_extract_local(rawobj_t *obj, __u32 **buf, __u32 *buflen);

typedef struct rawobj_buf_s {
        __u32           dataoff;
        __u32           datalen;
        __u32           buflen;
        __u8           *buf;
} rawobj_buf_t;

/*
 * mark of the interface between kernel and lgssd/lsvcgssd
 */
#define GSSD_INTERFACE_VERSION  (1)

#define MAXSEQ 0x80000000 /* maximum legal sequence number, from rfc 2203 */

enum rpc_gss_proc {
        RPC_GSS_PROC_DATA =             0,
        RPC_GSS_PROC_INIT =             1,
        RPC_GSS_PROC_CONTINUE_INIT =    2,
        RPC_GSS_PROC_DESTROY =          3,
};

enum rpc_gss_svc {
        RPC_GSS_SVC_NONE =              1,
        RPC_GSS_SVC_INTEGRITY =         2,
        RPC_GSS_SVC_PRIVACY =           3,
};

/* on-the-wire gss cred: */
struct rpc_gss_wire_cred {
        __u32                   gc_v;           /* version */
        __u32                   gc_proc;        /* control procedure */
        __u32                   gc_seq;         /* sequence number */
        __u32                   gc_svc;         /* service */
        rawobj_t                gc_ctx;         /* context handle */
};

/* on-the-wire gss verifier: */
struct rpc_gss_wire_verf {
        __u32                   gv_flavor;
        rawobj_t                gv_verf;
};

struct gss_cl_ctx {
        atomic_t                gc_refcount;
        __u32                   gc_proc;
        __u32                   gc_seq;
        spinlock_t              gc_seq_lock;
        struct gss_ctx         *gc_gss_ctx;
        rawobj_t                gc_wire_ctx;
        __u32                   gc_win;
};

struct gss_cred {
        struct ptlrpc_cred      gc_base;
        ptlrpcs_flavor_t        gc_flavor;
        struct gss_cl_ctx      *gc_ctx;
};

/*
 * This only guaranteed be enough for current krb5 des-cbc-crc . We might
 * adjust this when new enc type or mech added in.
 */
#define GSS_PRIVBUF_PREFIX_LEN         (32)
#define GSS_PRIVBUF_SUFFIX_LEN         (32)

/* This is too coarse. We'll let mech determine it */
#define GSS_MAX_AUTH_PAYLOAD    (128)

/* gss_mech_switch.c */
int init_kerberos_module(void);
void cleanup_kerberos_module(void);

/* gss_generic_token.c */
int g_token_size(rawobj_t *mech, unsigned int body_size);
void g_make_token_header(rawobj_t *mech, int body_size, unsigned char **buf);
__u32 g_verify_token_header(rawobj_t *mech, int *body_size,
                            unsigned char **buf_in, int toksize);

/* svcsec_gss.c */
int gss_svc_init(void);
void gss_svc_exit(void);

#endif /* __SEC_GSS_GSS_INTERNAL_H_ */
