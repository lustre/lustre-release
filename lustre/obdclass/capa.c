/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/obdclass/capa.c
 *  Lustre Capability Hash Management
 *
 *  Copyright (c) 2005 Cluster File Systems, Inc.
 *   Author: Lai Siyao<lsy@clusterfs.com>
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
#include <linux/version.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>

#include <obd_class.h>
#include <lustre_debug.h>
#include <lustre/lustre_idl.h>
#else
#include <liblustre.h>
#endif

#include <libcfs/list.h>
#include <lustre_capa.h>

cfs_mem_cache_t *capa_cachep = NULL;

#ifdef __KERNEL__
struct list_head capa_list[CAPA_SITE_MAX];
spinlock_t capa_lock = SPIN_LOCK_UNLOCKED; /* lock for capa_hash/capa_list */

static struct hlist_head *capa_hash;
#endif
/* capa count */
int capa_count[CAPA_SITE_MAX] = { 0, };

static struct capa_hmac_alg capa_hmac_algs[] = {
        DEF_CAPA_HMAC_ALG("sha1", SHA1, 20, 20),
};

static const char *capa_site_name[] = {
        [CAPA_SITE_CLIENT] = "client",
        [CAPA_SITE_SERVER] = "server",
        [CAPA_SITE_MAX]    = "error"
};

EXPORT_SYMBOL(capa_cachep);
EXPORT_SYMBOL(capa_list);
EXPORT_SYMBOL(capa_lock);
EXPORT_SYMBOL(capa_count);

int init_capa_hash(void)
{
#ifdef __KERNEL__
        int nr_hash, i;

        OBD_ALLOC(capa_hash, PAGE_SIZE);
        if (!capa_hash)
                return -ENOMEM;

        nr_hash = PAGE_SIZE / sizeof(struct hlist_head);
        LASSERT(nr_hash > NR_CAPAHASH);

        for (i = 0; i < NR_CAPAHASH; i++)
                INIT_HLIST_HEAD(capa_hash + i);
        for (i = CAPA_SITE_CLIENT; i < CAPA_SITE_MAX; i++)
                INIT_LIST_HEAD(&capa_list[i]);
#endif
        return 0;
}

#ifdef __KERNEL__
void cleanup_capa_hash(void)
{
        int i;
        struct hlist_node *pos;
        struct obd_capa *oc;

        for (i = 0; i < NR_CAPAHASH; i++) {
                if (hlist_empty(capa_hash + i))
                        continue;
                hlist_for_each_entry(oc, pos, capa_hash + i, u.tgt.c_hash)
                        DEBUG_CAPA(D_ERROR, &oc->c_capa, "remaining cached");
                LBUG();
        }
        for (i = CAPA_SITE_MAX; i < CAPA_SITE_MAX; i++) {
                if (list_empty(&capa_list[i]))
                        continue;
                list_for_each_entry(oc, &capa_list[i], c_list)
                        DEBUG_CAPA(D_ERROR, &oc->c_capa, "remaining %s",
                                   capa_site_name[oc->c_site]);
                LBUG();
        }
        OBD_FREE(capa_hash, PAGE_SIZE);
}

static inline int const capa_hashfn(struct lu_fid *fid)
{
        return (fid_oid(fid) ^ fid_ver(fid)) *
               (unsigned long)(fid_seq(fid) + 1) % NR_CAPAHASH;
}

static inline int capa_on_server(struct obd_capa *ocapa)
{
        return ocapa->c_site == CAPA_SITE_SERVER;
}

static struct obd_capa *find_capa(struct lustre_capa *capa,
                                  struct hlist_head *head)
{
        struct hlist_node *pos;
        struct obd_capa *ocapa;
        int len = capa->lc_expiry ? sizeof(*capa) :
                                    offsetof(struct lustre_capa, lc_keyid);

        hlist_for_each_entry(ocapa, pos, head, u.tgt.c_hash) {
                if (memcmp(&ocapa->c_capa, capa, len))
                        continue;
                /* don't return an expired one in this case */
                if (capa->lc_expiry == 0 && capa_is_to_expire(ocapa))
                        continue;

                LASSERT(capa_on_server(ocapa));

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "found");
                return ocapa;
        }

        return NULL;
}

static inline void capa_delete(struct obd_capa *ocapa)
{
        LASSERT(capa_on_server(ocapa));
        hlist_del(&ocapa->u.tgt.c_hash);
        list_del(&ocapa->c_list);
        free_capa(ocapa);
}

static inline void free_capa_lru(struct list_head *head)
{
        struct list_head *node = head->next;
        struct obd_capa *ocapa;
        int count = 0;

        /* free 12 unused capa from head */
        while (node != head && count < 12) {
                ocapa = list_entry(node, struct obd_capa, c_list);
                node = node->next;

                LASSERT(capa_on_server(ocapa));
                if (atomic_read(&ocapa->c_refc))
                        continue;

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "free unused");
                capa_delete(ocapa);
                count++;
        }
}

/* add or update */
struct obd_capa *capa_add(struct lustre_capa *capa)
{
        struct hlist_head *head = capa_hash + capa_hashfn(&capa->lc_fid);
        struct obd_capa *ocapa, *old = NULL;

        ocapa = alloc_capa(CAPA_SITE_SERVER);
        if (!ocapa)
                return NULL;

        spin_lock(&capa_lock);

        old = find_capa(capa, head);
        if (!old) {
                ocapa->c_capa = *capa;
                set_capa_expiry(ocapa);
                hlist_add_head(&ocapa->u.tgt.c_hash, head);
                list_add_tail(&ocapa->c_list, &capa_list[CAPA_SITE_SERVER]);
                capa_get(ocapa);

                if (capa_count[CAPA_SITE_SERVER] > CAPA_HASH_SIZE)
                        free_capa_lru(&capa_list[CAPA_SITE_SERVER]);

                DEBUG_CAPA(D_SEC, &ocapa->c_capa, "new");
                                        
                spin_unlock(&capa_lock);
                return ocapa;
        }

        list_move_tail(&old->c_list, &capa_list[CAPA_SITE_SERVER]);
        capa_get(old);

        spin_unlock(&capa_lock);

        DEBUG_CAPA(D_SEC, &old->c_capa, "update");

        free_capa(ocapa);
        return old;
}

struct obd_capa *capa_lookup(struct lustre_capa *capa)
{
        struct hlist_head *head;
        struct obd_capa *ocapa;

        head = capa_hash + capa_hashfn(&capa->lc_fid);

        spin_lock(&capa_lock);
        ocapa = find_capa(capa, head);
        if (ocapa)
                capa_get(ocapa);
        spin_unlock(&capa_lock);

        return ocapa;
}

int capa_hmac(__u8 *hmac, struct lustre_capa *capa, __u8 *key)
{
        struct crypto_tfm *tfm;
        struct capa_hmac_alg *alg;
        int keylen;
        struct scatterlist sl = {
                .page   = virt_to_page(capa),
                .offset = (unsigned long)(capa) % PAGE_SIZE,
                .length = offsetof(struct lustre_capa, lc_hmac),
        };

        if (capa_alg(capa) != CAPA_HMAC_ALG_SHA1) {
                CERROR("unknown capability hmac algorithm!\n");
                return -EFAULT;
        }

        alg = &capa_hmac_algs[capa_alg(capa)];

        tfm = crypto_alloc_tfm(alg->ha_name, 0);
        if (!tfm) {
                CERROR("crypto_alloc_tfm failed, check whether your kernel"
                       "has crypto support!\n");
                return -ENOMEM;
        }
        keylen = alg->ha_keylen;

        crypto_hmac(tfm, key, &keylen, &sl, 1, hmac);
        crypto_free_tfm(tfm);

        return 0;
}

void cleanup_capas(int site)
{
        struct obd_capa *ocapa, *tmp;

        spin_lock(&capa_lock);
        list_for_each_entry_safe(ocapa, tmp, &capa_list[site], c_list)
                if (site == ocapa->c_site)
                        capa_delete(ocapa);
        spin_unlock(&capa_lock);
        LASSERTF(capa_count[site] == 0, "%s capability count is %d\n",
                 capa_site_name[site], capa_count[site]);
}
#endif

void capa_cpy(void *capa, struct obd_capa *ocapa)
{
        spin_lock(&ocapa->c_lock);
        *(struct lustre_capa *)capa = ocapa->c_capa;
        spin_unlock(&ocapa->c_lock);
}

void dump_capa_hmac(char *buf, char *key)
{
        int i, n = 0;

        for (i = 0; i < CAPA_HMAC_MAX_LEN; i++)
                n += sprintf(buf + n, "%02x", (unsigned char) key[i]);
}

EXPORT_SYMBOL(capa_add);
EXPORT_SYMBOL(capa_lookup);

EXPORT_SYMBOL(capa_hmac);
EXPORT_SYMBOL(capa_cpy);

EXPORT_SYMBOL(cleanup_capas);
EXPORT_SYMBOL(dump_capa_hmac);
