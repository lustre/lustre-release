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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC
#ifdef __KERNEL__
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#else
#include <liblustre.h>
#endif

#include <libcfs/kp30.h>
#include <linux/obd.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_net.h>
#include <linux/lustre_import.h>
#include <linux/lustre_dlm.h>
#include <linux/lustre_sec.h>

static spinlock_t sectypes_lock = SPIN_LOCK_UNLOCKED;
static struct ptlrpc_sec_type *sectypes[PTLRPC_SEC_MAX_FLAVORS] = {
        NULL,
};

int ptlrpcs_register(struct ptlrpc_sec_type *type)
{
        __u32 flavor = type->pst_flavor.flavor;

        LASSERT(type->pst_name);
        LASSERT(type->pst_ops);

        if (flavor >= PTLRPC_SEC_MAX_FLAVORS)
                return -EINVAL;

        spin_lock(&sectypes_lock);
        if (sectypes[flavor]) {
                spin_unlock(&sectypes_lock);
                return -EALREADY;
        }
        sectypes[flavor] = type;
        atomic_set(&type->pst_inst, 0);
        spin_unlock(&sectypes_lock);

        CWARN("Security module %s registered\n", type->pst_name);
        return 0;
}

int ptlrpcs_unregister(struct ptlrpc_sec_type *type)
{
        __u32 flavor = type->pst_flavor.flavor;

        if (flavor >= PTLRPC_SEC_MAX_FLAVORS)
                return -EINVAL;

        spin_lock(&sectypes_lock);
        if (!sectypes[flavor]) {
                spin_unlock(&sectypes_lock);
                return -EINVAL;
        }

        if (sectypes[flavor] != type) {
                CERROR("invalid unregister\n");
                return -EINVAL;
        }

        if (atomic_read(&type->pst_inst)) {
                CERROR("sec module %s still have instance %d\n",
                       type->pst_name, atomic_read(&type->pst_inst));
                spin_unlock(&sectypes_lock);
                return -EINVAL;
        }

        CDEBUG(D_SEC, "Security module %s unregistered\n", type->pst_name);
        sectypes[flavor] = NULL;
        spin_unlock(&sectypes_lock);

        return 0;
}

static
struct ptlrpc_sec_type * ptlrpcs_flavor2type(ptlrpcs_flavor_t *flavor)
{
        struct ptlrpc_sec_type *type;
        __u32 major = flavor->flavor;

        if (major >= PTLRPC_SEC_MAX_FLAVORS)
                return NULL;

        spin_lock(&sectypes_lock);
        type = sectypes[major];
        if (type && !try_module_get(type->pst_owner))
                type = NULL;
        spin_unlock(&sectypes_lock);
        return type;
}

static inline
void ptlrpcs_type_put(struct ptlrpc_sec_type *type)
{
        module_put(type->pst_owner);
}

/***********************************************
 * credential cache helpers                    *
 ***********************************************/

void ptlrpcs_init_credcache(struct ptlrpc_sec *sec)
{
        int i;
        for (i = 0; i < PTLRPC_CREDCACHE_NR; i++)
                INIT_LIST_HEAD(&sec->ps_credcache[i]);
        sec->ps_nextgc = get_seconds() + (sec->ps_expire >> 1);
}

static void ptlrpcs_cred_destroy(struct ptlrpc_cred *cred)
{
        struct ptlrpc_sec *sec = cred->pc_sec;

        LASSERT(cred->pc_sec);
        LASSERT(atomic_read(&cred->pc_refcount) == 0);
        LASSERT(list_empty(&cred->pc_hash));

        cred->pc_ops->destroy(cred);
        atomic_dec(&sec->ps_credcount);
}

static void ptlrpcs_destroy_credlist(struct list_head *head)
{
        struct ptlrpc_cred *cred;

        while (!list_empty(head)) {
                cred = list_entry(head->next, struct ptlrpc_cred, pc_hash);
                list_del_init(&cred->pc_hash);
                ptlrpcs_cred_destroy(cred);
        }
}

static
int ptlrpcs_cred_unlink_expired(struct ptlrpc_cred *cred,
                                struct list_head *freelist)
{
        LASSERT(cred->pc_sec);

        /* only unlink non-busy entries */
        if (atomic_read(&cred->pc_refcount) != 0)
                return 0;
        /* expire is 0 means never expire. a newly created gss cred
         * which during upcall also has 0 expiration
         */
        if (cred->pc_expire == 0)
                return 0;
        /* check real expiration */
        if (time_after(cred->pc_expire, get_seconds()))
                return 0;

        LASSERT((cred->pc_flags & PTLRPC_CRED_FLAGS_MASK) ==
                PTLRPC_CRED_UPTODATE);
        CWARN("cred %p: get expired, unlink\n", cred);

        list_del(&cred->pc_hash);
        list_add(&cred->pc_hash, freelist);
        return 1;
}

static
void ptlrpcs_credcache_gc(struct ptlrpc_sec *sec,
                          struct list_head *freelist)
{
        struct ptlrpc_cred *cred, *n;
        int i;
        ENTRY;

        CDEBUG(D_SEC, "do gc on sec %s\n", sec->ps_type->pst_name);
        for (i = 0; i < PTLRPC_CREDCACHE_NR; i++) {
                list_for_each_entry_safe(cred, n, &sec->ps_credcache[i],
                                         pc_hash) {
                        if (cred->pc_flags & (PTLRPC_CRED_DEAD |
                                              PTLRPC_CRED_ERROR)) {
                                LASSERT(atomic_read(&cred->pc_refcount));
                                continue;
                        }
                        ptlrpcs_cred_unlink_expired(cred, freelist);
                }
        }
        sec->ps_nextgc = get_seconds() + sec->ps_expire;
        EXIT;
}

static
int ptlrpcs_flush_credcache(struct ptlrpc_sec *sec, int force)
{
        struct ptlrpc_cred *cred, *n;
        LIST_HEAD(freelist);
        int i, busy = 0;
        ENTRY;

        spin_lock(&sec->ps_lock);
        for (i = 0; i < PTLRPC_CREDCACHE_NR; i++) {
                list_for_each_entry_safe(cred, n, &sec->ps_credcache[i],
                                         pc_hash) {
                        LASSERT(atomic_read(&cred->pc_refcount) >= 0);
                        if (atomic_read(&cred->pc_refcount)) {
                                busy = 1;
                                if (!force)
                                        continue;
                                list_del_init(&cred->pc_hash);
                        } else
                                list_move(&cred->pc_hash, &freelist);

                        /* don't remove CRED_UPTODATE flag here */
                        cred->pc_flags |= PTLRPC_CRED_DEAD;
                }
        }
        spin_unlock(&sec->ps_lock);
        ptlrpcs_destroy_credlist(&freelist);
        RETURN(busy);
}

/**************************************************
 * credential APIs                                *
 **************************************************/

static inline
int ptlrpcs_cred_get_hash(__u64 pag)
{
        LASSERT((pag & PTLRPC_CREDCACHE_MASK) < PTLRPC_CREDCACHE_NR);
        return (pag & PTLRPC_CREDCACHE_MASK);
}

static
struct ptlrpc_cred * cred_cache_lookup(struct ptlrpc_sec *sec,
                                       struct vfs_cred *vcred,
                                       int create)
{
        struct ptlrpc_cred *cred, *new = NULL, *n;
        LIST_HEAD(freelist);
        int hash, found = 0;
        ENTRY;

        hash = ptlrpcs_cred_get_hash(vcred->vc_pag);

retry:
        spin_lock(&sec->ps_lock);
        /* do gc if expired */
        if (time_after(get_seconds(), sec->ps_nextgc))
                ptlrpcs_credcache_gc(sec, &freelist);

        list_for_each_entry_safe(cred, n, &sec->ps_credcache[hash], pc_hash) {
                /* for DEAD and ERROR entries, its final put will
                 * release them, so we simply skip here.
                 */
                if (cred->pc_flags & (PTLRPC_CRED_DEAD | PTLRPC_CRED_ERROR)) {
                        LASSERT(atomic_read(&cred->pc_refcount));
                        continue;
                }
                if (ptlrpcs_cred_unlink_expired(cred, &freelist))
                        continue;
                if (cred->pc_ops->match(cred, vcred)) {
                        found = 1;
                        break;
                }
        }

        if (found) {
                if (new && new != cred) {
                        /* lost the race, just free it */
                        list_add(&new->pc_hash, &freelist);
                }
                list_move(&cred->pc_hash, &sec->ps_credcache[hash]);
        } else {
                if (new) {
                        list_add(&new->pc_hash, &sec->ps_credcache[hash]);
                        cred = new;
                } else if (create) {
                        spin_unlock(&sec->ps_lock);
                        new = sec->ps_type->pst_ops->create_cred(sec, vcred);
                        if (new) {
                                atomic_inc(&sec->ps_credcount);
                                goto retry;
                        }
                } else
                        cred = NULL;
        }

        /* hold a ref */
        if (cred)
                atomic_inc(&cred->pc_refcount);

        spin_unlock(&sec->ps_lock);

        ptlrpcs_destroy_credlist(&freelist);
        RETURN(cred);
}

struct ptlrpc_cred * ptlrpcs_cred_lookup(struct ptlrpc_sec *sec,
                                         struct vfs_cred *vcred)
{
        struct ptlrpc_cred *cred;
        ENTRY;

        cred = cred_cache_lookup(sec, vcred, 0);
        RETURN(cred);
}

static struct ptlrpc_cred *get_cred(struct ptlrpc_sec *sec)
{
        struct vfs_cred vcred;

        LASSERT(sec);
        /* XXX
         * for now we simply let PAG == real uid
         */
        vcred.vc_pag = (__u64) current->uid;
        vcred.vc_uid = current->uid;

        return cred_cache_lookup(sec, &vcred, 1);
}

int ptlrpcs_req_get_cred(struct ptlrpc_request *req)
{
        struct obd_import *imp = req->rq_import;
        ENTRY;

        LASSERT(!req->rq_cred);
        LASSERT(imp);

        req->rq_cred = get_cred(imp->imp_sec);

        if (!req->rq_cred) {
                CERROR("req %p: fail to get cred from cache\n", req);
                RETURN(-ENOMEM);
        }

        RETURN(0);
}

/*
 * check whether current user have valid credential for an import or not.
 * might repeatedly try in case of non-fatal errors.
 * return 0 on success, 1 on failure
 */
int ptlrpcs_check_cred(struct obd_import *imp)
{
        struct ptlrpc_cred *cred;
        ENTRY;

again:
        cred = get_cred(imp->imp_sec);
        if (!cred)
                RETURN(0);

        if (ptlrpcs_cred_is_uptodate(cred)) {
                if (!ptlrpcs_cred_check_expire(cred)) {
                        ptlrpcs_cred_put(cred, 1);
                        RETURN(0);
                } else {
                        ptlrpcs_cred_put(cred, 1);
                        goto again;
                }
        }

        ptlrpcs_cred_refresh(cred);
        if (ptlrpcs_cred_is_uptodate(cred)) {
                ptlrpcs_cred_put(cred, 1);
                RETURN(0);
        }

        if (cred->pc_flags & PTLRPC_CRED_ERROR ||
            !imp->imp_replayable) {
                ptlrpcs_cred_put(cred, 1);
                RETURN(1);
        }

        ptlrpcs_cred_put(cred, 1);

        if (signal_pending(current)) {
                CWARN("%s: interrupted\n", current->comm);
                RETURN(1);
        }
        goto again;
}

static void ptlrpcs_sec_destroy(struct ptlrpc_sec *sec);

void ptlrpcs_cred_put(struct ptlrpc_cred *cred, int sync)
{
        struct ptlrpc_sec *sec = cred->pc_sec;

        LASSERT(cred);
        LASSERT(sec);
        LASSERT(atomic_read(&cred->pc_refcount));

        spin_lock(&sec->ps_lock);
        if (atomic_dec_and_test(&cred->pc_refcount) && sync &&
            cred->pc_flags & (PTLRPC_CRED_DEAD | PTLRPC_CRED_ERROR)) {
                list_del_init(&cred->pc_hash);
                ptlrpcs_cred_destroy(cred);
                if (!atomic_read(&sec->ps_credcount) &&
                    !atomic_read(&sec->ps_refcount)) {
                        CWARN("put last cred on a dead sec %p(%s), "
                              "also destroy the sec\n", sec,
                               sec->ps_type->pst_name);
                        spin_unlock(&sec->ps_lock);

                        ptlrpcs_sec_destroy(sec);
                        return;
                }
        }
        spin_unlock(&sec->ps_lock);
}

void ptlrpcs_req_drop_cred(struct ptlrpc_request *req)
{
        ENTRY;

        LASSERT(req);
        LASSERT(req->rq_cred);

        if (req->rq_cred) {
                /* We'd like to not use 'sync' mode, but might cause
                 * some cred leak. Need more thinking here. FIXME
                 */
                ptlrpcs_cred_put(req->rq_cred, 1);
                req->rq_cred = NULL;
        } else
                CDEBUG(D_SEC, "req %p have no cred\n", req);
        EXIT;
}

/* 
 * request must have a cred. if failed to get new cred,
 * just restore the old one
 */
int ptlrpcs_req_replace_dead_cred(struct ptlrpc_request *req)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        int rc;
        ENTRY;

        LASSERT(cred);
        LASSERT(cred->pc_flags & PTLRPC_CRED_DEAD);

        ptlrpcs_cred_get(cred);
        ptlrpcs_req_drop_cred(req);
        LASSERT(!req->rq_cred);
        rc = ptlrpcs_req_get_cred(req);
        if (!rc) {
                LASSERT(req->rq_cred);
                LASSERT(req->rq_cred != cred);
                ptlrpcs_cred_put(cred, 1);
        } else {
                LASSERT(!req->rq_cred);
                req->rq_cred = cred;
        }
        RETURN(rc);
}

/*
 * since there's no lock on the cred, its status could be changed
 * by other threads at any time, we allow this race.
 */
int ptlrpcs_req_refresh_cred(struct ptlrpc_request *req)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        ENTRY;

        LASSERT(cred);

        if (ptlrpcs_cred_is_uptodate(cred)) {
                if (!ptlrpcs_cred_check_expire(cred))
                        RETURN(0);
        }

        if (cred->pc_flags & PTLRPC_CRED_ERROR) {
                req->rq_ptlrpcs_err = 1;
                RETURN(-EPERM);
        }

        if (cred->pc_flags & PTLRPC_CRED_DEAD) {
                if (ptlrpcs_req_replace_dead_cred(req) == 0) {
                        LASSERT(cred != req->rq_cred);
                        CDEBUG(D_SEC, "req %p: replace cred %p => %p\n",
                               req, cred, req->rq_cred);
                        cred = req->rq_cred;
                } else {
                        LASSERT(cred == req->rq_cred);
                        CERROR("req %p: failed to replace dead cred %p\n",
                                req, cred);
                        req->rq_ptlrpcs_err = 1;
                        RETURN(-ENOMEM);
                }
        }

        ptlrpcs_cred_refresh(cred);
        if (!ptlrpcs_cred_is_uptodate(cred)) {
                if (cred->pc_flags & PTLRPC_CRED_ERROR)
                        req->rq_ptlrpcs_err = 1;

                CERROR("req %p: failed to refresh cred %p, fatal %d\n",
                        req, cred, req->rq_ptlrpcs_err);
                RETURN(-EPERM);
        } else
                RETURN(0);
}

int ptlrpcs_cli_wrap_request(struct ptlrpc_request *req)
{
        struct ptlrpc_cred     *cred;
        int rc;
        ENTRY;

        LASSERT(req->rq_cred);
        LASSERT(req->rq_cred->pc_sec);
        LASSERT(req->rq_cred->pc_ops);
        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf_len);

        rc = ptlrpcs_req_refresh_cred(req);
        if (rc)
                RETURN(rc);

        CDEBUG(D_SEC, "wrap req %p\n", req);
        cred = req->rq_cred;

        switch (cred->pc_sec->ps_sectype) {
        case PTLRPC_SEC_TYPE_NONE:
        case PTLRPC_SEC_TYPE_AUTH:
                if (req->rq_req_wrapped) {
                        CDEBUG(D_SEC, "req %p(o%u,x"LPU64",t"LPU64") "
                               "already signed, resend?\n", req,
                               req->rq_reqmsg ? req->rq_reqmsg->opc : -1,
                               req->rq_xid, req->rq_transno);
                        req->rq_req_wrapped = 0;
                        req->rq_reqdata_len = sizeof(struct ptlrpcs_wire_hdr) +
                                              req->rq_reqlen;
                        LASSERT(req->rq_reqdata_len % 8 == 0);
                }

                LASSERT(cred->pc_ops->sign);
                rc = cred->pc_ops->sign(cred, req);
                if (!rc)
                        req->rq_req_wrapped = 1;
                break;
        case PTLRPC_SEC_TYPE_PRIV:
                if (req->rq_req_wrapped) {
                        CDEBUG(D_SEC, "req %p(o%u,x"LPU64",t"LPU64") "
                               "already encrypted, resend?\n", req,
                               req->rq_reqmsg ? req->rq_reqmsg->opc : -1,
                               req->rq_xid, req->rq_transno);
                        req->rq_req_wrapped = 0;
                        req->rq_reqdata_len = sizeof(struct ptlrpcs_wire_hdr);
                        LASSERT(req->rq_reqdata_len % 8 == 0);
                }

                LASSERT(cred->pc_ops->seal);
                rc = cred->pc_ops->seal(cred, req);
                if (!rc)
                        req->rq_req_wrapped = 1;
                break;
        default:
                LBUG();
        }
        LASSERT(req->rq_reqdata_len);
        LASSERT(req->rq_reqdata_len % 8 == 0);
        LASSERT(req->rq_reqdata_len >= sizeof(struct ptlrpcs_wire_hdr));
        LASSERT(req->rq_reqdata_len <= req->rq_reqbuf_len);

        RETURN(rc);
}

/* rq_nob_received is the actual received data length */
int ptlrpcs_cli_unwrap_reply(struct ptlrpc_request *req)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        struct ptlrpc_sec *sec;
        struct ptlrpcs_wire_hdr *sec_hdr;
        int rc;
        ENTRY;

        LASSERT(cred);
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_ops);
        LASSERT(req->rq_repbuf);
        
        if (req->rq_nob_received < sizeof(*sec_hdr)) {
                CERROR("req %p: reply size only %d\n",
                        req, req->rq_nob_received);
                RETURN(-EPROTO);
        }

        sec_hdr = (struct ptlrpcs_wire_hdr *) req->rq_repbuf;
        sec_hdr->flavor = le32_to_cpu(sec_hdr->flavor);
        sec_hdr->sectype = le32_to_cpu(sec_hdr->sectype);
        sec_hdr->msg_len = le32_to_cpu(sec_hdr->msg_len);
        sec_hdr->sec_len = le32_to_cpu(sec_hdr->sec_len);

        CDEBUG(D_SEC, "req %p, cred %p, flavor %u, sectype %u\n",
               req, cred, sec_hdr->flavor, sec_hdr->sectype);

        sec = cred->pc_sec;
        if (sec_hdr->flavor != sec->ps_flavor.flavor) {
                CERROR("unmatched flavor %u while expect %u\n",
                       sec_hdr->flavor, sec->ps_flavor.flavor);
                RETURN(-EPROTO);
        }

        if (sizeof(*sec_hdr) + sec_hdr->msg_len + sec_hdr->sec_len >
            req->rq_nob_received) {
                CERROR("msg %u, sec %u, while only get %d\n",
                        sec_hdr->msg_len, sec_hdr->sec_len,
                        req->rq_nob_received);
                RETURN(-EPROTO);
        }

        switch (sec_hdr->sectype) {
        case PTLRPC_SEC_TYPE_NONE:
        case PTLRPC_SEC_TYPE_AUTH: {
                LASSERT(cred->pc_ops->verify);
                rc = cred->pc_ops->verify(cred, req);
                LASSERT(rc || req->rq_repmsg || req->rq_ptlrpcs_restart);
                break;
        case PTLRPC_SEC_TYPE_PRIV:
                LASSERT(cred->pc_ops->unseal);
                rc = cred->pc_ops->unseal(cred, req);
                LASSERT(rc || req->rq_repmsg || req->rq_ptlrpcs_restart);
                break;
        }
        default:
                rc = -1;
                LBUG();
        }
        RETURN(rc);
}

/**************************************************
 * security APIs                                  *
 **************************************************/

struct ptlrpc_sec * ptlrpcs_sec_create(ptlrpcs_flavor_t *flavor,
                                       struct obd_import *import,
                                       const char *pipe_dir,
                                       void *pipe_data)
{
        struct ptlrpc_sec_type *type;
        struct ptlrpc_sec *sec;
        ENTRY;

        type = ptlrpcs_flavor2type(flavor);
        if (!type) {
                CDEBUG(D_SEC, "invalid major flavor %u\n", flavor->flavor);
                RETURN(NULL);
        }

        sec = type->pst_ops->create_sec(flavor, pipe_dir, pipe_data);
        if (sec) {
                spin_lock_init(&sec->ps_lock);
                ptlrpcs_init_credcache(sec);
                sec->ps_type = type;
                sec->ps_flavor = *flavor;
                sec->ps_import = class_import_get(import);
                atomic_set(&sec->ps_refcount, 1);
                atomic_set(&sec->ps_credcount, 0);
                atomic_inc(&type->pst_inst);
        } else
                ptlrpcs_type_put(type);

        return sec;
}

static void ptlrpcs_sec_destroy(struct ptlrpc_sec *sec)
{
        struct ptlrpc_sec_type *type = sec->ps_type;
        struct obd_import *imp = sec->ps_import;

        LASSERT(type && type->pst_ops);
        LASSERT(type->pst_ops->destroy_sec);

        type->pst_ops->destroy_sec(sec);
        atomic_dec(&type->pst_inst);
        ptlrpcs_type_put(type);
        class_import_put(imp);
}

void ptlrpcs_sec_put(struct ptlrpc_sec *sec)
{
        if (atomic_dec_and_test(&sec->ps_refcount)) {
                ptlrpcs_flush_credcache(sec, 1);

                if (atomic_read(&sec->ps_credcount) == 0) {
                        ptlrpcs_sec_destroy(sec);
                } else {
                        CWARN("sec %p(%s) is no usage while %d cred still "
                              "holded, destroy delayed\n",
                               sec, sec->ps_type->pst_name,
                               atomic_read(&sec->ps_credcount));
                }
        }
}

void ptlrpcs_sec_invalidate_cache(struct ptlrpc_sec *sec)
{
        ptlrpcs_flush_credcache(sec, 1);
}

int sec_alloc_reqbuf(struct ptlrpc_sec *sec,
                     struct ptlrpc_request *req,
                     int msgsize, int secsize)
{
        struct ptlrpcs_wire_hdr *hdr;
        ENTRY;

        LASSERT(msgsize % 8 == 0);
        LASSERT(secsize % 8 == 0);

        req->rq_reqbuf_len = sizeof(*hdr) + msgsize + secsize;
        OBD_ALLOC(req->rq_reqbuf, req->rq_reqbuf_len);
        if (!req->rq_reqbuf) {
                CERROR("can't alloc %d\n", req->rq_reqbuf_len);
                RETURN(-ENOMEM);
        }

        hdr = buf_to_sec_hdr(req->rq_reqbuf);
        hdr->flavor = cpu_to_le32(sec->ps_flavor.flavor);
        hdr->sectype = cpu_to_le32(sec->ps_sectype);
        hdr->msg_len = msgsize;
        /* security length will be filled later */

        /* later reqdata_len will be added on actual security payload */
        req->rq_reqdata_len = sizeof(*hdr) + msgsize;
        req->rq_reqmsg = buf_to_lustre_msg(req->rq_reqbuf);

        CDEBUG(D_SEC, "req %p: rqbuf at %p, len %d, msg %d, sec %d\n",
               req, req->rq_reqbuf, req->rq_reqbuf_len,
               msgsize, secsize);

        RETURN(0);
}

/* when complete successfully, req->rq_reqmsg should point to the
 * right place.
 */
int ptlrpcs_cli_alloc_reqbuf(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        struct ptlrpc_sec *sec;
        struct ptlrpc_secops *ops;

        LASSERT(msgsize % 8 == 0);
        LASSERT(sizeof(struct ptlrpcs_wire_hdr) % 8 == 0);
        LASSERT(cred);
        LASSERT(atomic_read(&cred->pc_refcount));
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_type);
        LASSERT(cred->pc_sec->ps_type->pst_ops);
        LASSERT(req->rq_reqbuf == NULL);
        LASSERT(req->rq_reqmsg == NULL);

        sec = cred->pc_sec;
        ops = sec->ps_type->pst_ops;
        if (ops->alloc_reqbuf)
                return ops->alloc_reqbuf(sec, req, msgsize);
        else
                return sec_alloc_reqbuf(sec, req, msgsize, 0);
}

void sec_free_reqbuf(struct ptlrpc_sec *sec,
                     struct ptlrpc_request *req)
{
        LASSERT(req->rq_reqbuf);
        LASSERT(req->rq_reqbuf_len);

        /* sanity check */
        if (req->rq_reqmsg) {
                LASSERT((char *) req->rq_reqmsg >= req->rq_reqbuf &&
                        (char *) req->rq_reqmsg < req->rq_reqbuf +
                                                  req->rq_reqbuf_len);
        }

        OBD_FREE(req->rq_reqbuf, req->rq_reqbuf_len);
        req->rq_reqbuf = NULL;
        req->rq_reqmsg = NULL;
}

void ptlrpcs_cli_free_reqbuf(struct ptlrpc_request *req)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        struct ptlrpc_sec *sec;
        struct ptlrpc_secops *ops;

        LASSERT(cred);
        LASSERT(atomic_read(&cred->pc_refcount));
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_type);
        LASSERT(cred->pc_sec->ps_type->pst_ops);
        LASSERT(req->rq_reqbuf);

        sec = cred->pc_sec;
        ops = sec->ps_type->pst_ops;
        if (ops->free_reqbuf)
                ops->free_reqbuf(sec, req);
        else
                sec_free_reqbuf(sec, req);
}

int ptlrpcs_cli_alloc_repbuf(struct ptlrpc_request *req, int msgsize)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        struct ptlrpc_sec *sec;
        struct ptlrpc_secops *ops;
        int msg_payload, sec_payload;
        ENTRY;

        LASSERT(msgsize % 8 == 0);
        LASSERT(sizeof(struct ptlrpcs_wire_hdr) % 8 == 0);
        LASSERT(cred);
        LASSERT(atomic_read(&cred->pc_refcount));
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_type);
        LASSERT(cred->pc_sec->ps_type->pst_ops);
        LASSERT(req->rq_repbuf == NULL);

        sec = cred->pc_sec;
        ops = sec->ps_type->pst_ops;
        if (ops->alloc_repbuf)
                RETURN(ops->alloc_repbuf(sec, req, msgsize));

        /* default allocation scheme */
        msg_payload = sec->ps_sectype == PTLRPC_SEC_TYPE_PRIV ? 0 : msgsize;
        sec_payload = size_round(ptlrpcs_est_rep_payload(sec, msgsize));

        req->rq_repbuf_len = sizeof(struct ptlrpcs_wire_hdr) +
                             msg_payload + sec_payload;
        OBD_ALLOC(req->rq_repbuf, req->rq_repbuf_len);
        if (!req->rq_repbuf)
                RETURN(-ENOMEM);

        CDEBUG(D_SEC, "req %p: repbuf at %p, len %d, msg %d, sec %d\n",
               req, req->rq_repbuf, req->rq_repbuf_len,
               msg_payload, sec_payload);

        RETURN(0);
}

void ptlrpcs_cli_free_repbuf(struct ptlrpc_request *req)
{
        struct ptlrpc_cred *cred = req->rq_cred;
        struct ptlrpc_sec *sec;
        struct ptlrpc_secops *ops;
        ENTRY;

        LASSERT(cred);
        LASSERT(atomic_read(&cred->pc_refcount));
        LASSERT(cred->pc_sec);
        LASSERT(cred->pc_sec->ps_type);
        LASSERT(cred->pc_sec->ps_type->pst_ops);
        LASSERT(req->rq_repbuf);

        sec = cred->pc_sec;
        ops = sec->ps_type->pst_ops;
        if (ops->free_repbuf)
                ops->free_repbuf(sec, req);
        else {
                OBD_FREE(req->rq_repbuf, req->rq_repbuf_len);
                req->rq_repbuf = NULL;
                req->rq_repmsg = NULL;
        }
        EXIT;
}

int ptlrpcs_import_get_sec(struct obd_import *imp)
{
        ptlrpcs_flavor_t flavor = {PTLRPC_SEC_NULL, 0};
        char *pipedir = NULL;
        ENTRY;

        LASSERT(imp->imp_obd);
        LASSERT(imp->imp_obd->obd_type);

        /* old sec might be still there in reconnecting */
        if (imp->imp_sec)
                RETURN(0);

        /* find actual flavor for client obd. right now server side
         * obd (reverse imp, etc) will simply use NULL.
         */
        if (!strcmp(imp->imp_obd->obd_type->typ_name, "mdc") ||
            !strcmp(imp->imp_obd->obd_type->typ_name, "osc")) {
                struct client_obd *cli = &imp->imp_obd->u.cli;

                if (cli->cl_sec_flavor == PTLRPC_SEC_GSS) {
                        CWARN("select security gss/%s for %s(%s)\n",
                               cli->cl_sec_subflavor == PTLRPC_SEC_GSS_KRB5I ?
                               "krb5i" : "krb5p",
                               imp->imp_obd->obd_type->typ_name,
                               imp->imp_obd->obd_name);
                        flavor.flavor = cli->cl_sec_flavor;
                        flavor.subflavor = cli->cl_sec_subflavor;
                        pipedir = imp->imp_obd->obd_name;
                } else if (cli->cl_sec_flavor == PTLRPC_SEC_NULL) {
                        CWARN("select security null for %s(%s)\n",
                               imp->imp_obd->obd_type->typ_name,
                               imp->imp_obd->obd_name);
                } else {
                        CWARN("unknown security flavor for mdc(%s), "
                              "use 'null'\n", imp->imp_obd->obd_name);
                }
        }

        imp->imp_sec = ptlrpcs_sec_create(&flavor, imp, pipedir, imp);
        if (!imp->imp_sec)
                RETURN(-EINVAL);
        else
                RETURN(0);
}

void ptlrpcs_import_drop_sec(struct obd_import *imp)
{
        ENTRY;
        if (imp->imp_sec) {
                ptlrpcs_sec_put(imp->imp_sec);
                imp->imp_sec = NULL;
        }
        EXIT;
}

int __init ptlrpc_sec_init(void)
{
        int rc;

        if ((rc = ptlrpcs_null_init()))
                return rc;

        if ((rc = svcsec_null_init())) {
                ptlrpcs_null_exit();
                return rc;
        }

#if 0
#if !defined __KERNEL__ && defined ENABLE_GSS
        ptlrpcs_gss_init();
#endif
#endif
        return 0;
}

static void __exit ptlrpc_sec_exit(void)
{
        svcsec_null_exit();
        ptlrpcs_null_exit();
}


EXPORT_SYMBOL(ptlrpcs_register);
EXPORT_SYMBOL(ptlrpcs_unregister);
EXPORT_SYMBOL(ptlrpcs_sec_create);
EXPORT_SYMBOL(ptlrpcs_sec_put);
EXPORT_SYMBOL(ptlrpcs_sec_invalidate_cache);
EXPORT_SYMBOL(ptlrpcs_import_get_sec);
EXPORT_SYMBOL(ptlrpcs_import_drop_sec);
EXPORT_SYMBOL(ptlrpcs_cred_lookup);
EXPORT_SYMBOL(ptlrpcs_cred_put);
EXPORT_SYMBOL(ptlrpcs_req_get_cred);
EXPORT_SYMBOL(ptlrpcs_req_drop_cred);
EXPORT_SYMBOL(ptlrpcs_req_replace_dead_cred);
EXPORT_SYMBOL(ptlrpcs_req_refresh_cred);
EXPORT_SYMBOL(ptlrpcs_check_cred);
EXPORT_SYMBOL(ptlrpcs_cli_alloc_reqbuf);
EXPORT_SYMBOL(ptlrpcs_cli_free_reqbuf);
EXPORT_SYMBOL(ptlrpcs_cli_alloc_repbuf);
EXPORT_SYMBOL(ptlrpcs_cli_free_repbuf);
EXPORT_SYMBOL(ptlrpcs_cli_wrap_request);
EXPORT_SYMBOL(ptlrpcs_cli_unwrap_reply);
EXPORT_SYMBOL(sec_alloc_reqbuf);
EXPORT_SYMBOL(sec_free_reqbuf);

EXPORT_SYMBOL(svcsec_register);
EXPORT_SYMBOL(svcsec_unregister);
EXPORT_SYMBOL(svcsec_accept);
EXPORT_SYMBOL(svcsec_authorize);
EXPORT_SYMBOL(svcsec_alloc_repbuf);
EXPORT_SYMBOL(svcsec_cleanup_req);
EXPORT_SYMBOL(svcsec_get);
EXPORT_SYMBOL(svcsec_put);
EXPORT_SYMBOL(svcsec_alloc_reply_state);
EXPORT_SYMBOL(svcsec_free_reply_state);

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Security Support");
MODULE_LICENSE("GPL");

module_init(ptlrpc_sec_init);
module_exit(ptlrpc_sec_exit);
