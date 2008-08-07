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
 * lustre/include/lustre_capa.h
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
 */

#ifndef __LINUX_CAPA_H_
#define __LINUX_CAPA_H_

/*
 * capability
 */
#ifdef __KERNEL__
#include <linux/crypto.h>
#endif
#include <lustre/lustre_idl.h>

#define CAPA_TIMEOUT 1800                /* sec, == 30 min */
#define CAPA_KEY_TIMEOUT (24 * 60 * 60)  /* sec, == 1 days */

struct capa_hmac_alg {
        const char     *ha_name;
        int             ha_len;
        int             ha_keylen;
};

#define DEF_CAPA_HMAC_ALG(name, type, len, keylen)      \
[CAPA_HMAC_ALG_ ## type] = {                            \
        .ha_name         = name,                        \
        .ha_len          = len,                         \
        .ha_keylen       = keylen,                      \
}

struct client_capa {
        struct inode             *inode;      
        struct list_head          lli_list;     /* link to lli_oss_capas */
};

struct target_capa {
        struct hlist_node         c_hash;       /* link to capa hash */
};

struct obd_capa {
        struct list_head          c_list;       /* link to capa_list */

        struct lustre_capa        c_capa;       /* capa */
        atomic_t                  c_refc;       /* ref count */
        cfs_time_t                c_expiry;     /* jiffies */
        spinlock_t                c_lock;       /* protect capa content */
        int                       c_site;

        union {
                struct client_capa      cli;
                struct target_capa      tgt;
        } u;
};

enum {
        CAPA_SITE_CLIENT = 0,
        CAPA_SITE_SERVER,
        CAPA_SITE_MAX
};

static inline __u64 capa_opc(struct lustre_capa *capa)
{
        return capa->lc_opc;
}

static inline __u32 capa_uid(struct lustre_capa *capa)
{
        return capa->lc_uid;
}

static inline struct lu_fid *capa_fid(struct lustre_capa *capa)
{
        return &capa->lc_fid;
}

static inline __u32 capa_keyid(struct lustre_capa *capa)
{
        return capa->lc_keyid;
}

static inline __u64 capa_expiry(struct lustre_capa *capa)
{
        return capa->lc_expiry;
}

static inline __u32 capa_flags(struct lustre_capa *capa)
{
        return capa->lc_flags & 0xffffff;
}

static inline __u32 capa_alg(struct lustre_capa *capa)
{
        __u32 alg = capa->lc_flags;

        return alg >> 24;
}

static inline __u64 capa_key_mdsid(struct lustre_capa_key *key)
{
        return key->lk_mdsid;
}

static inline __u32 capa_key_keyid(struct lustre_capa_key *key)
{
        return key->lk_keyid;
}

#define DEBUG_CAPA(level, c, fmt, args...)                                     \
do {                                                                           \
CDEBUG(level, fmt " capability@%p uid %u opc "LPX64" fid "DFID" keyid %u "     \
       "expiry "LPU64" flags %u alg %d\n",                                     \
       ##args, c, capa_uid(c), capa_opc(c), PFID(capa_fid(c)), capa_keyid(c),  \
       capa_expiry(c), capa_flags(c), capa_alg(c));                            \
} while (0)

#define DEBUG_CAPA_KEY(level, k, fmt, args...)                                 \
do {                                                                           \
CDEBUG(level, fmt " capability key@%p mdsid "LPU64" keyid %u\n",               \
       ##args, k, capa_key_mdsid(k), capa_key_keyid(k));                       \
} while (0)

typedef int (* renew_capa_cb_t)(struct obd_capa *, struct lustre_capa *);

/* obdclass/capa.c */
extern struct list_head capa_list[];
extern spinlock_t capa_lock;
extern int capa_count[];
extern cfs_mem_cache_t *capa_cachep;

struct hlist_head *init_capa_hash(void);
void cleanup_capa_hash(struct hlist_head *hash);

struct obd_capa *capa_add(struct hlist_head *hash, struct lustre_capa *capa);
struct obd_capa *capa_lookup(struct hlist_head *hash, struct lustre_capa *capa,
                             int alive);

int capa_hmac(__u8 *hmac, struct lustre_capa *capa, __u8 *key);
void capa_cpy(void *dst, struct obd_capa *ocapa);

char *dump_capa_content(char *buf, char *key, int len);

static inline struct obd_capa *alloc_capa(int site)
{
#ifdef __KERNEL__
        struct obd_capa *ocapa;

        OBD_SLAB_ALLOC(ocapa, capa_cachep, GFP_KERNEL, sizeof(*ocapa));
        if (ocapa) {
                atomic_set(&ocapa->c_refc, 0);
                spin_lock_init(&ocapa->c_lock);
                CFS_INIT_LIST_HEAD(&ocapa->c_list);
                ocapa->c_site = site;
        }
        return ocapa;
#else
        return NULL;
#endif
}

static inline void free_capa(struct obd_capa *ocapa)
{
#ifdef __KERNEL__
        if (atomic_read(&ocapa->c_refc)) {
                DEBUG_CAPA(D_ERROR, &ocapa->c_capa, "refc %d for",
                           atomic_read(&ocapa->c_refc));
                LBUG();
        }
        OBD_SLAB_FREE(ocapa, capa_cachep, sizeof(*ocapa));
#else
#endif
}

static inline struct obd_capa *capa_get(struct obd_capa *ocapa)
{
        if (!ocapa)
                return NULL;

        atomic_inc(&ocapa->c_refc);
        return ocapa;
}

static inline void capa_put(struct obd_capa *ocapa)
{
        if (!ocapa)
                return;

        if (atomic_read(&ocapa->c_refc) == 0) {
                DEBUG_CAPA(D_ERROR, &ocapa->c_capa, "refc is 0 for");
                LBUG();
        }
        atomic_dec(&ocapa->c_refc);
}

static inline int open_flags_to_accmode(int flags)
{
        int mode = flags;

        if ((mode + 1) & O_ACCMODE)
                mode++;
        if (mode & O_TRUNC)
                mode |= 2;

        return mode;
}

static inline __u64 capa_open_opc(int mode)
{
        return mode & FMODE_WRITE ? CAPA_OPC_OSS_WRITE : CAPA_OPC_OSS_READ;
}

static inline void set_capa_expiry(struct obd_capa *ocapa)
{
        cfs_time_t expiry = cfs_time_sub((cfs_time_t)ocapa->c_capa.lc_expiry,
                                         cfs_time_current_sec());
        ocapa->c_expiry = cfs_time_add(cfs_time_current(),
                                       cfs_time_seconds(expiry));
}

static inline int capa_is_expired(struct obd_capa *ocapa)
{
        return cfs_time_beforeq(ocapa->c_expiry, cfs_time_current());
}

static inline int capa_opc_supported(struct lustre_capa *capa, __u64 opc)
{
        return (capa_opc(capa) & opc) == opc;
}

static inline struct lustre_capa *
lustre_unpack_capa(struct lustre_msg *msg, unsigned int offset)
{
        struct lustre_capa *capa;

        capa = lustre_swab_buf(msg, offset, sizeof(*capa),
                               lustre_swab_lustre_capa);
        if (capa == NULL)
                CERROR("bufcount %u, bufsize %u\n",
                       lustre_msg_bufcount(msg),
                       (lustre_msg_bufcount(msg) <= offset) ?
                                -1 : lustre_msg_buflen(msg, offset));

        return capa;
}

struct filter_capa_key {
        struct list_head        k_list;
        struct lustre_capa_key  k_key;
};

#define BYPASS_CAPA (struct lustre_capa *)ERR_PTR(-ENOENT)
#endif /* __LINUX_CAPA_H_ */
