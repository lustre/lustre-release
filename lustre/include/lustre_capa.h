/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: Lai Siyao <lsy@clusterfs.com>
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
 *   Lustre capability support.
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

#define NR_CAPAHASH 32
#define CAPA_HASH_SIZE 3000              /* for MDS & OSS */

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
        int                       c_flags;

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

enum {
        OBD_CAPA_FL_NEW     = 1,
        OBD_CAPA_FL_EXPIRED = 1<<1,
        OBD_CAPA_FL_ROOT    = 1<<2,
};

static inline __u64 capa_opc(struct lustre_capa *capa)
{
        return capa->lc_opc;
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
CDEBUG(level, fmt " capability@%p opc "LPX64" fid "DFID" keyid %u expiry "LPU64\
       " flags %u alg %d\n",                                                   \
       ##args, c, capa_opc(c), PFID(capa_fid(c)), capa_keyid(c),               \
       capa_expiry(c), capa_flags(c), capa_alg(c));                            \
} while (0)

#define DEBUG_CAPA_KEY(level, k, fmt, args...)                                 \
do {                                                                           \
CDEBUG(level, fmt " capability key@%p mdsid "LPU64" keyid %u\n",               \
       ##args, k, capa_key_mdsid(k), capa_key_keyid(k));                       \
} while (0)

/* obdclass/capa.c */
extern struct list_head capa_list[];
extern spinlock_t capa_lock;
extern int capa_count[];
extern cfs_mem_cache_t *capa_cachep;

struct obd_capa *capa_add(struct lustre_capa *capa);
struct obd_capa *capa_lookup(struct lustre_capa *capa);

int capa_hmac(__u8 *hmac, struct lustre_capa *capa, __u8 *key);
void capa_cpy(void *dst, struct obd_capa *ocapa);

void cleanup_capas(int site);
void dump_capa_hmac(char *buf, char *key);

static inline int obd_capa_is_new(struct obd_capa *oc)
{
        return !!((oc)->c_flags & OBD_CAPA_FL_NEW);
}

static inline int obd_capa_is_expired(struct obd_capa *oc)
{
        return !!((oc)->c_flags & OBD_CAPA_FL_EXPIRED);
}

static inline int obd_capa_is_valid(struct obd_capa *oc)
{
        return !((oc)->c_flags & (OBD_CAPA_FL_NEW | OBD_CAPA_FL_EXPIRED));
}

static inline void obd_capa_set_new(struct obd_capa *oc)
{
        oc->c_flags |= OBD_CAPA_FL_NEW;
}

static inline void obd_capa_set_expired(struct obd_capa *oc)
{
        oc->c_flags |= OBD_CAPA_FL_EXPIRED;
}

static inline void obd_capa_set_valid(struct obd_capa *oc)
{
        oc->c_flags &= ~(OBD_CAPA_FL_NEW | OBD_CAPA_FL_EXPIRED);
}

static inline void obd_capa_clear_new(struct obd_capa *oc)
{
        oc->c_flags &= ~OBD_CAPA_FL_NEW;
}

static inline void obd_capa_clear_expired(struct obd_capa *oc)
{
        oc->c_flags &= ~OBD_CAPA_FL_EXPIRED;
}

static inline int obd_capa_is_root(struct obd_capa *oc)
{
        return !!((oc)->c_flags & OBD_CAPA_FL_ROOT);
}

static inline void obd_capa_set_root(struct obd_capa *oc)
{
        oc->c_flags |= OBD_CAPA_FL_ROOT;
}

static inline struct obd_capa *alloc_capa(int site)
{
#ifdef __KERNEL__
        struct obd_capa *ocapa;

        OBD_SLAB_ALLOC(ocapa, capa_cachep, SLAB_KERNEL, sizeof(*ocapa));
        if (ocapa) {
                atomic_set(&ocapa->c_refc, 0);
                spin_lock_init(&ocapa->c_lock);
                INIT_LIST_HEAD(&ocapa->c_list);
                ocapa->c_site = site;
                obd_capa_set_new(ocapa);
                capa_count[site]++;
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

        capa_count[ocapa->c_site]--;
        if (capa_count[ocapa->c_site] < 0) {
                DEBUG_CAPA(D_ERROR, &ocapa->c_capa, "total count %d",
                           capa_count[ocapa->c_site]);
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
        time_t expiry = (time_t)ocapa->c_capa.lc_expiry;

        expiry = (jiffies + (expiry - CURRENT_SECONDS) * HZ) / HZ;
        ocapa->c_expiry = expiry * HZ;
}

static inline unsigned long capa_renewal_time(struct obd_capa *ocapa)
{
        /* NB, by default dirty_expire_centisecs is 30*100, that is 30 sec,
         * the following values guarantee that client cache will be flushed
         * to OSS before capability expires.
         */
        return ocapa->c_expiry -
               ((ocapa->c_capa.lc_flags & CAPA_FL_SHORT_EXPIRY) ? 40:1200) * HZ;
}

#ifdef __KERNEL__
static inline int capa_is_to_expire(struct obd_capa *ocapa)
{
        return time_before_eq(capa_renewal_time(ocapa), jiffies);
}

static inline int capa_is_expired(struct obd_capa *ocapa)
{
        return time_before_eq(ocapa->c_expiry, jiffies);
}
#endif

static inline int capa_opc_supported(struct lustre_capa *capa, __u64 opc)
{
        return (capa->lc_opc & opc) == opc;
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
