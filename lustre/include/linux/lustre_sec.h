/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004 Cluster File Systems, Inc.
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

#ifndef __LINUX_SEC_H_
#define __LINUX_SEC_H_

enum ptlrpcs_major_flavors {
        PTLRPCS_FLVR_MAJOR_NULL         = 0,
        PTLRPCS_FLVR_MAJOR_GSS          = 1,
        PTLRPCS_FLVR_MAJOR_MAX,
};

enum ptlrpcs_null_minor_flavors {
        PTLRPCS_FLVR_MINOR_NULL         = 0,
        PTLRPCS_FLVR_MINOR_NULL_MAX,
};
enum ptlrpcs_gss_minor_flavors {
        PTLRPCS_FLVR_MINOR_GSS_NONE     = 0,
        PTLRPCS_FLVR_MINOR_GSS_KRB5     = 1,
        PTLRPCS_FLVR_MINOR_GSS_MAX,
};

enum ptlrpcs_security_type {
        PTLRPCS_SVC_NONE                = 0,    /* no security */
        PTLRPCS_SVC_AUTH                = 1,    /* authentication */
        PTLRPCS_SVC_PRIV                = 2,    /* privacy */
        PTLRPCS_SVC_MAX,
};

/*
 * flavor compose/extract
 */
#define SEC_FLAVOR_MAJOR_OFFSET         (24)
#define SEC_FLAVOR_RESERVE_OFFSET       (16)
#define SEC_FLAVOR_SVC_OFFSET           (8)
#define SEC_FLAVOR_MINOR_OFFSET         (0)

#define SEC_MAKE_FLAVOR(major, minor, svc)                      \
        (((__u32)(major) << SEC_FLAVOR_MAJOR_OFFSET) |          \
         ((__u32)(svc) << SEC_FLAVOR_SVC_OFFSET) |              \
         ((__u32)(minor) << SEC_FLAVOR_MINOR_OFFSET))

#define SEC_MAKE_SUBFLAVOR(minor, svc)                          \
        (((__u32)(svc) << SEC_FLAVOR_SVC_OFFSET) |              \
         ((__u32)(minor) << SEC_FLAVOR_MINOR_OFFSET))

#define SEC_FLAVOR_MAJOR(flavor)                                        \
        ((((__u32)(flavor)) >> SEC_FLAVOR_MAJOR_OFFSET) & 0xFF)
#define SEC_FLAVOR_MINOR(flavor)                                        \
        ((((__u32)(flavor)) >> SEC_FLAVOR_MINOR_OFFSET) & 0xFF)
#define SEC_FLAVOR_SVC(flavor)                                          \
        ((((__u32)(flavor)) >> SEC_FLAVOR_SVC_OFFSET) & 0xFF)
#define SEC_FLAVOR_SUB(flavor)                                          \
        ((((__u32)(flavor)) >> SEC_FLAVOR_MINOR_OFFSET) & 0xFFFF)

/*
 * general gss flavors
 */
#define PTLRPCS_FLVR_GSS_NONE                           \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_GSS,         \
                        PTLRPCS_FLVR_MINOR_GSS_NONE,    \
                        PTLRPCS_SVC_NONE)
#define PTLRPCS_FLVR_GSS_AUTH                           \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_GSS,         \
                        PTLRPCS_FLVR_MINOR_GSS_NONE,    \
                        PTLRPCS_SVC_AUTH)
#define PTLRPCS_FLVR_GSS_PRIV                           \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_GSS,         \
                        PTLRPCS_FLVR_MINOR_GSS_NONE,    \
                        PTLRPCS_SVC_PRIV)

/*
 * gss subflavors
 */
#define PTLRPCS_SUBFLVR_KRB5                            \
        SEC_MAKE_SUBFLAVOR(PTLRPCS_FLVR_MINOR_GSS_KRB5, \
                           PTLRPCS_SVC_NONE)
#define PTLRPCS_SUBFLVR_KRB5I                           \
        SEC_MAKE_SUBFLAVOR(PTLRPCS_FLVR_MINOR_GSS_KRB5, \
                           PTLRPCS_SVC_AUTH)
#define PTLRPCS_SUBFLVR_KRB5P                           \
        SEC_MAKE_SUBFLAVOR(PTLRPCS_FLVR_MINOR_GSS_KRB5, \
                           PTLRPCS_SVC_PRIV)

/*
 * "end user" flavors
 */
#define PTLRPCS_FLVR_NULL                               \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_NULL,        \
                        PTLRPCS_FLVR_MINOR_NULL,        \
                        PTLRPCS_SVC_NONE)
#define PTLRPCS_FLVR_KRB5                               \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_GSS,         \
                        PTLRPCS_FLVR_MINOR_GSS_KRB5,    \
                        PTLRPCS_SVC_NONE)
#define PTLRPCS_FLVR_KRB5I                              \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_GSS,         \
                        PTLRPCS_FLVR_MINOR_GSS_KRB5,    \
                        PTLRPCS_SVC_AUTH)
#define PTLRPCS_FLVR_KRB5P                              \
        SEC_MAKE_FLAVOR(PTLRPCS_FLVR_MAJOR_GSS,         \
                        PTLRPCS_FLVR_MINOR_GSS_KRB5,    \
                        PTLRPCS_SVC_PRIV)

#define PTLRPCS_FLVR_INVALID    (-1)

__u32 ptlrpcs_name2flavor(const char *name);
char *ptlrpcs_flavor2name(__u32 flavor);


#ifdef __KERNEL__

/* forward declaration */
struct obd_import;
struct ptlrpc_request;
struct ptlrpc_cred;
struct ptlrpc_credops;
struct ptlrpc_sec;
struct ptlrpc_secops;


typedef struct {
        struct list_head        list;
        __u32                   flavor;
} deny_sec_t;

/*
 * This header is prepended at any on-wire ptlrpc packets
 */
struct ptlrpcs_wire_hdr {
        __u32   flavor;
        __u32   unused;
        __u32   msg_len;
        __u32   sec_len;
};

static inline
struct ptlrpcs_wire_hdr *buf_to_sec_hdr(void *buf)
{
        return (struct ptlrpcs_wire_hdr *) buf;
}

static inline
struct lustre_msg *buf_to_lustre_msg(void *buf)
{
        return (struct lustre_msg *)
               ((char *) buf + sizeof(struct ptlrpcs_wire_hdr));
}

static inline
__u8 *buf_to_sec_data(void *buf)
{
        struct ptlrpcs_wire_hdr *hdr = buf_to_sec_hdr(buf);
        return (__u8 *) (buf + sizeof(*hdr) + hdr->msg_len);
}

#define PTLRPC_SEC_GSS_VERSION (1)

enum ptlrpcs_gss_proc {
        PTLRPCS_GSS_PROC_DATA           = 0,
        PTLRPCS_GSS_PROC_INIT           = 1,
        PTLRPCS_GSS_PROC_CONTINUE_INIT  = 2,
        PTLRPCS_GSS_PROC_DESTROY        = 3,
        PTLRPCS_GSS_PROC_ERR            = 4,
};
                                                                                                                        
enum ptlrpcs_gss_svc {
        PTLRPCS_GSS_SVC_NONE            = 1,
        PTLRPCS_GSS_SVC_INTEGRITY       = 2,
        PTLRPCS_GSS_SVC_PRIVACY         = 3,
};

enum ptlrpcs_error {
        PTLRPCS_OK                      = 0,
        PTLRPCS_BADCRED                 = 1,
        PTLRPCS_REJECTEDCRED            = 2,
        PTLRPCS_BADVERF                 = 3,
        PTLRPCS_REJECTEDVERF            = 4,
        PTLRPCS_TOOWEAK                 = 5,
        /* GSS errors */
        PTLRPCS_GSS_CREDPROBLEM         = 13,
        PTLRPCS_GSS_CTXPROBLEM          = 14,
};

struct vfs_cred {
        __u64                   vc_pag;
        uid_t                   vc_uid;
        gid_t                   vc_gid;
        struct group_info      *vc_ginfo;
};

struct ptlrpc_credops {
        int     (*match)  (struct ptlrpc_cred *cred, struct vfs_cred *vcred);
        int     (*refresh)(struct ptlrpc_cred *cred);
        void    (*destroy)(struct ptlrpc_cred *cred);
        int     (*sign)   (struct ptlrpc_cred *cred,
                           struct ptlrpc_request *req);
        int     (*verify) (struct ptlrpc_cred *cred,
                           struct ptlrpc_request *req);
        int     (*seal)   (struct ptlrpc_cred *cred,
                           struct ptlrpc_request *req);
        int     (*unseal) (struct ptlrpc_cred *cred,
                           struct ptlrpc_request *req);
};

#define PTLRPC_CRED_UPTODATE_BIT        0 /* uptodate */
#define PTLRPC_CRED_DEAD_BIT            1 /* mark expired gracefully */
#define PTLRPC_CRED_ERROR_BIT           2 /* fatal error (refresh, etc.) */

#define PTLRPC_CRED_UPTODATE            (1 << PTLRPC_CRED_UPTODATE_BIT)
#define PTLRPC_CRED_DEAD                (1 << PTLRPC_CRED_DEAD_BIT)
#define PTLRPC_CRED_ERROR               (1 << PTLRPC_CRED_ERROR_BIT)

#define PTLRPC_CRED_FLAGS_MASK          (PTLRPC_CRED_UPTODATE |         \
                                         PTLRPC_CRED_DEAD |             \
                                         PTLRPC_CRED_ERROR)

struct ptlrpc_cred {
        struct list_head        pc_hash;   /* linked into hash table */
        atomic_t                pc_refcount;
        struct ptlrpc_sec      *pc_sec;
        struct ptlrpc_credops  *pc_ops;
        unsigned long           pc_expire;
        unsigned long           pc_flags;
        /* XXX maybe should not be here */
        __u64                   pc_pag;
        uid_t                   pc_uid;
};

struct ptlrpc_secops {
        struct ptlrpc_sec *   (*create_sec)    (__u32 flavor,
                                                const char *pipe_dir,
                                                void *pipe_data);
        void                  (*destroy_sec)   (struct ptlrpc_sec *sec);
        struct ptlrpc_cred *  (*create_cred)   (struct ptlrpc_sec *sec,
                                                struct vfs_cred *vcred);
        /* buffer manipulation */
        int                   (*alloc_reqbuf)  (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req,
                                                int lustre_msg_size);
        int                   (*alloc_repbuf)  (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req,
                                                int lustre_msg_size);
        void                  (*free_reqbuf)   (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req);
        void                  (*free_repbuf)   (struct ptlrpc_sec *sec,
                                                struct ptlrpc_request *req);
        /* security payload size estimation */
        int                   (*est_req_payload)(struct ptlrpc_sec *sec,
                                                 struct ptlrpc_request *req,
                                                 int msgsize);
        int                   (*est_rep_payload)(struct ptlrpc_sec *sec,
                                                 struct ptlrpc_request *req,
                                                 int msgsize);
};

struct ptlrpc_sec_type {
        struct module          *pst_owner;
        char                   *pst_name;
        atomic_t                pst_inst;       /* instance, debug only */
        __u32                   pst_flavor;     /* major flavor */
        struct ptlrpc_secops   *pst_ops;
};

#define PTLRPC_SEC_FL_MDS               0x0001 /* outgoing from MDS */
#define PTLRPC_SEC_FL_REVERSE           0x0002 /* reverse sec */
#define PTLRPC_SEC_FL_PAG               0x0004 /* enable PAG */

#define PTLRPC_CREDCACHE_NR     8
#define PTLRPC_CREDCACHE_MASK   (PTLRPC_CREDCACHE_NR - 1)

struct ptlrpc_sec {
        struct ptlrpc_sec_type *ps_type;
        struct list_head        ps_credcache[PTLRPC_CREDCACHE_NR];
        spinlock_t              ps_lock;        /* protect cred cache */
        __u32                   ps_flavor;
        atomic_t                ps_refcount;
        atomic_t                ps_credcount;
        struct obd_import      *ps_import;
        /* actual security model need initialize following fields */
        unsigned long           ps_expire;      /* cache expire interval */
        unsigned long           ps_nextgc;      /* next gc time */
        unsigned long           ps_flags;
};

/* sec.c */
int  ptlrpcs_register(struct ptlrpc_sec_type *type);
int  ptlrpcs_unregister(struct ptlrpc_sec_type *type);

struct ptlrpc_sec * ptlrpcs_sec_create(__u32 flavor,
                                       unsigned long flags,
                                       struct obd_import *import,
                                       const char *pipe_dir,
                                       void *pipe_data);
void ptlrpcs_sec_put(struct ptlrpc_sec *sec);
void ptlrpcs_sec_invalidate_cache(struct ptlrpc_sec *sec);

struct ptlrpc_cred * ptlrpcs_cred_lookup(struct ptlrpc_sec *sec,
                                         struct vfs_cred *vcred);
void ptlrpcs_cred_put(struct ptlrpc_cred *cred, int sync);

static inline void ptlrpcs_cred_get(struct ptlrpc_cred *cred)
{
        LASSERT(atomic_read(&cred->pc_refcount));
        atomic_inc(&cred->pc_refcount);
}

static inline int ptlrpcs_cred_refresh(struct ptlrpc_cred *cred)
{
        LASSERT(cred);
        LASSERT(atomic_read(&cred->pc_refcount));
        LASSERT(cred->pc_ops);
        LASSERT(cred->pc_ops->refresh);
        return cred->pc_ops->refresh(cred);
}

static inline int ptlrpcs_cred_is_uptodate(struct ptlrpc_cred *cred)
{
        smp_mb();
        return ((cred->pc_flags & PTLRPC_CRED_FLAGS_MASK) ==
                PTLRPC_CRED_UPTODATE);
}

static inline int ptlrpcs_cred_is_dead(struct ptlrpc_cred *cred)
{
        smp_mb();
        return ((cred->pc_flags & (PTLRPC_CRED_DEAD | PTLRPC_CRED_ERROR)) != 0);
}

#define ptlrpcs_cred_expire(cred)                                       \
        if (!test_and_set_bit(PTLRPC_CRED_DEAD_BIT, &cred->pc_flags)) { \
                CWARN("cred %p: get expired\n", cred);                  \
                clear_bit(PTLRPC_CRED_UPTODATE_BIT, &cred->pc_flags);   \
        }

static inline int ptlrpcs_cred_check_uptodate(struct ptlrpc_cred *cred)
{
        LASSERT(atomic_read(&cred->pc_refcount));

        if (!ptlrpcs_cred_is_uptodate(cred))
                return 1;

        if (cred->pc_expire == 0)
                return 0;
        if (time_after(cred->pc_expire, get_seconds()))
                return 0;
        ptlrpcs_cred_expire(cred);
        return 1;
}

static inline int ptlrpcs_est_req_payload(struct ptlrpc_request *req,
                                          int datasize)
{
        struct ptlrpc_sec *sec = req->rq_cred->pc_sec;
        struct ptlrpc_secops *ops;

        LASSERT(sec);
        LASSERT(sec->ps_type);
        LASSERT(sec->ps_type->pst_ops);

        ops = sec->ps_type->pst_ops;
        if (ops->est_req_payload)
                return ops->est_req_payload(sec, req, datasize);
        else
                return 0;
}

static inline int ptlrpcs_est_rep_payload(struct ptlrpc_request *req,
                                          int datasize)
{
        struct ptlrpc_sec *sec = req->rq_cred->pc_sec;
        struct ptlrpc_secops *ops;

        LASSERT(sec);
        LASSERT(sec->ps_type);
        LASSERT(sec->ps_type->pst_ops);

        ops = sec->ps_type->pst_ops;
        if (ops->est_rep_payload)
                return ops->est_rep_payload(sec, req, datasize);
        else
                return 0;
}

static inline int add_deny_security(char *sec, struct list_head *head)
{
        deny_sec_t     *p_deny_sec = NULL;
        int             rc = 0;

        LASSERT(sec != NULL);

        OBD_ALLOC(p_deny_sec, sizeof(*p_deny_sec));
        if (p_deny_sec == NULL)
                return -ENOMEM;

        p_deny_sec->flavor = ptlrpcs_name2flavor(sec);
        if (p_deny_sec->flavor == PTLRPCS_FLVR_INVALID) {
                CERROR("unrecognized security type %s\n", (char*) sec);
                rc = -EINVAL;
                goto out;
        }

        list_add_tail(&p_deny_sec->list, head);
out:
        if (rc) {
                if (p_deny_sec)
                        OBD_FREE(p_deny_sec, sizeof(*p_deny_sec));
        }
        return rc;
}

int ptlrpcs_cli_wrap_request(struct ptlrpc_request *req);
int ptlrpcs_cli_unwrap_reply(struct ptlrpc_request *req);
int ptlrpcs_cli_alloc_reqbuf(struct ptlrpc_request *req, int msgsize);
int ptlrpcs_cli_alloc_repbuf(struct ptlrpc_request *req, int msgsize);
void ptlrpcs_cli_free_reqbuf(struct ptlrpc_request *req);
void ptlrpcs_cli_free_repbuf(struct ptlrpc_request *req);

/* higher interface */
int  ptlrpcs_import_get_sec(struct obd_import *imp);
void ptlrpcs_import_drop_sec(struct obd_import *imp);
void ptlrpcs_import_flush_current_creds(struct obd_import *imp);
int  ptlrpcs_req_get_cred(struct ptlrpc_request *req);
void ptlrpcs_req_drop_cred(struct ptlrpc_request *req);
int  ptlrpcs_req_replace_dead_cred(struct ptlrpc_request *req);
int  ptlrpcs_req_refresh_cred(struct ptlrpc_request *req);
int ptlrpcs_check_cred(struct obd_import *imp);

/* internal helpers */
int sec_alloc_reqbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req,
                     int msgsize, int secsize);
void sec_free_reqbuf(struct ptlrpc_sec *sec, struct ptlrpc_request *req);

/* sec_null.c */
int ptlrpcs_null_init(void);
int ptlrpcs_null_exit(void);

/**********************************************************
 * Server side stuff
 **********************************************************/

struct ptlrpc_reply_state;

struct ptlrpc_svcsec {
        struct module           *pss_owner;
        char                    *pss_name;
        __u32                    pss_flavor;    /* major flavor */
        int                      pss_sec_size;

        int                    (*accept)      (struct ptlrpc_request *req,
                                               enum ptlrpcs_error *res);
        int                    (*authorize)   (struct ptlrpc_request *req);
        int                    (*alloc_repbuf)(struct ptlrpc_svcsec *svcsec,
                                               struct ptlrpc_request *req,
                                               int msgsize);
        void                   (*free_repbuf) (struct ptlrpc_svcsec *svcsec,
                                               struct ptlrpc_reply_state *rs);
        void                   (*cleanup_req) (struct ptlrpc_svcsec *svcsec,
                                               struct ptlrpc_request *req);
};

#define SVC_OK          1
#define SVC_COMPLETE    2
#define SVC_DROP        3
#define SVC_LOGIN       4
#define SVC_LOGOUT      5

int svcsec_register(struct ptlrpc_svcsec *ss);
int svcsec_unregister(struct ptlrpc_svcsec *ss);
int svcsec_accept(struct ptlrpc_request *req, enum ptlrpcs_error *res);
int svcsec_authorize(struct ptlrpc_request *req);
int svcsec_alloc_repbuf(struct ptlrpc_svcsec *svcsec,
                        struct ptlrpc_request *req, int msgsize);
void svcsec_cleanup_req(struct ptlrpc_request *req);

struct ptlrpc_svcsec * svcsec_get(struct ptlrpc_svcsec *sec);
void svcsec_put(struct ptlrpc_svcsec *sec);

/* internal helpers */
int svcsec_alloc_reply_state(struct ptlrpc_request *req,
                             int msgsize, int secsize);
void svcsec_free_reply_state(struct ptlrpc_reply_state *rs);

/* svcsec_null.c */
int svcsec_null_init(void);
int svcsec_null_exit(void);

#endif /* __KERNEL__ */

#endif /* __LINUX_SEC_H_ */
