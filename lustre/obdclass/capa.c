/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/obdclass/capa.c
 *  Lustre Capability Cache Management
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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

#include <linux/obd_class.h>
#include <linux/lustre_debug.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_sec.h>
#else
#include <liblustre.h>
#endif

#include <libcfs/list.h>
#include <linux/lustre_sec.h>

kmem_cache_t *capa_cachep = NULL;

/* capa_lock protect capa hash, list and content. */
spinlock_t capa_lock = SPIN_LOCK_UNLOCKED;
struct hlist_head *capa_hash;
struct list_head capa_list[3];
static int capa_count[3] = { 0 };

static char *capa_type_name[] = { "client", "mds", "filter" };

/* TODO: mdc and llite all need this, so define it here.
 * in the future it will be moved to ll_sb_info to support multi-
 * mount point */
struct timer_list ll_capa_timer;

EXPORT_SYMBOL(capa_lock);
EXPORT_SYMBOL(capa_hash);
EXPORT_SYMBOL(capa_list);
EXPORT_SYMBOL(ll_capa_timer);

static inline int const
capa_hashfn(unsigned int uid, __u64 mdsid, unsigned long ino)
{
        return (ino ^ uid) * (unsigned long)(mdsid + 1) % NR_CAPAHASH;
}

int capa_op(int flags)
{
        if (flags & (FMODE_WRITE|MDS_OPEN_TRUNC))
                return CAPA_WRITE;
        else if (flags & FMODE_READ)
                return CAPA_READ;

        LBUG(); /* should be either MAY_READ or MAY_WRITE */
        return 0;
}

static struct obd_capa *
find_capa(struct hlist_head *head, uid_t uid, int capa_op, __u64 mdsid,
          unsigned long ino, __u32 igen, int type)
{
        struct hlist_node *pos;
        struct obd_capa *ocapa;
        uid_t ouid;

        CDEBUG(D_INODE, "find capa for (uid %u, op %d, mdsid "LPU64", ino %lu"
               " igen %u, type %d\n", (unsigned) uid, capa_op, mdsid, ino, igen, type);
        hlist_for_each_entry(ocapa, pos, head, c_hash) {
                if (ocapa->c_capa.lc_ino != ino)
                        continue;
                if (ocapa->c_capa.lc_igen != igen)
                        continue;
                if (ocapa->c_capa.lc_mdsid != mdsid)
                        continue;
                if ((ocapa->c_capa.lc_op & capa_op) != ocapa->c_capa.lc_op)
                        continue;
                if (ocapa->c_type != type)
                        continue;

                if (ocapa->c_type == CLIENT_CAPA)
                        ouid = ocapa->c_capa.lc_ruid;
                else
                        ouid = ocapa->c_capa.lc_uid;

                if (ouid != uid)
                        continue;

                DEBUG_CAPA(D_INODE, &ocapa->c_capa, "found %s",
                           capa_type_name[ocapa->c_type]);

                return ocapa;
        }

        return NULL;
}

inline void __capa_get(struct obd_capa *ocapa)
{
        if (ocapa->c_type != CLIENT_CAPA)
                atomic_inc(&ocapa->c_refc);
}

static struct obd_capa *
find_capa_locked(struct hlist_head *head, uid_t uid, int capa_op, __u64 mdsid,
                 unsigned long ino, __u32 igen, int type)
{
        struct obd_capa *ocapa;

        spin_lock(&capa_lock);
        ocapa = find_capa(head, uid, capa_op, mdsid, ino, igen, type);
        if (ocapa)
                __capa_get(ocapa);
        spin_unlock(&capa_lock);

        return ocapa;
}

static struct obd_capa *alloc_capa(void)
{
        struct obd_capa *ocapa;

        OBD_SLAB_ALLOC(ocapa, capa_cachep, SLAB_NOFS, sizeof(*ocapa));
        if (ocapa) {
                INIT_HLIST_NODE(&ocapa->c_hash);
                INIT_LIST_HEAD(&ocapa->c_list);
        }

        return ocapa;
}

static void __capa_put(struct obd_capa *ocapa)
{
        hlist_del_init(&ocapa->c_hash);
        list_del_init(&ocapa->c_list);
        capa_count[ocapa->c_type]--;
}

static void destroy_capa(struct obd_capa *ocapa)
{
        OBD_SLAB_FREE(ocapa, capa_cachep, sizeof(*ocapa));
}

int capa_cache_init(void)
{
        int nr_hash, i;

        OBD_ALLOC(capa_hash, PAGE_SIZE);
        if (!capa_hash)
                return -ENOMEM;

        nr_hash = PAGE_SIZE / sizeof(struct hlist_head);
        LASSERT(nr_hash > NR_CAPAHASH);

        for (i = 0; i < NR_CAPAHASH; i++)
                INIT_HLIST_HEAD(capa_hash + i);

        for (i = 0; i < 3; i++)
                INIT_LIST_HEAD(&capa_list[i]);

        return 0;
}

void capa_cache_cleanup(void)
{
        struct obd_capa *ocapa, *tmp;
        int i;

        for (i = MDS_CAPA; i <= FILTER_CAPA; i++) {
                list_for_each_entry_safe(ocapa, tmp, &capa_list[i], c_list) {
                        __capa_put(ocapa);
                        destroy_capa(ocapa);
                }
        }

        OBD_FREE(capa_hash, PAGE_SIZE);
}


static inline void list_add_capa(struct obd_capa *ocapa, struct list_head *head)
{
        struct obd_capa *tmp;

        /* XXX: capa is sorted in client, this could be optimized */
        if (ocapa->c_type == CLIENT_CAPA) {
                list_for_each_entry_reverse(tmp, head, c_list) {
                        if (ocapa->c_capa.lc_expiry > tmp->c_capa.lc_expiry) {
                                list_add(&ocapa->c_list, &tmp->c_list);
                                return;
                        }
                }
        }

        list_add(&ocapa->c_list, head);
}

static inline void do_update_capa(struct obd_capa *ocapa, struct lustre_capa *capa)
{
        memcpy(&ocapa->c_capa, capa, sizeof(*capa));
}

static struct obd_capa *
get_new_capa_locked(struct hlist_head *head, int type, struct lustre_capa *capa)
{
        uid_t uid = capa->lc_uid;
        int capa_op = capa->lc_op;
        __u64 mdsid = capa->lc_mdsid;
        unsigned long ino = capa->lc_ino;
        struct obd_capa *ocapa, *old;

        ocapa = alloc_capa();
        if (!ocapa)
                return NULL;

        spin_lock(&capa_lock);
        old = find_capa(head, uid, capa_op, mdsid, ino, capa->lc_igen, type);
        if (!old) {
                do_update_capa(ocapa, capa);
                ocapa->c_type = type;
                list_add_capa(ocapa, &capa_list[type]);
                hlist_add_head(&ocapa->c_hash, head);
                if (type == CLIENT_CAPA)
                        INIT_LIST_HEAD(&ocapa->c_lli_list);
                __capa_get(ocapa);

                capa_count[type]++;

                DEBUG_CAPA(D_INODE, &ocapa->c_capa, "new %s",
                           capa_type_name[type]);

                if (type != CLIENT_CAPA && capa_count[type] > CAPA_CACHE_SIZE) {
                        struct list_head *node = capa_list[type].next;
                        struct obd_capa *tcapa;
                        int count = 0;

                        /* free 12 unused capa from head */
                        while (node->next != &capa_list[type] && count < 12) {
                                tcapa = list_entry(node, struct obd_capa,
                                                   c_list);
                                node = node->next;
                                if (atomic_read(&tcapa->c_refc) > 0)
                                        continue;
                                DEBUG_CAPA(D_INODE, &tcapa->c_capa,
                                           "free unused %s",
                                           capa_type_name[type]);
                                __capa_put(tcapa);
                                destroy_capa(tcapa);
                                count++;
                        }
                }
                                        
                spin_unlock(&capa_lock);
                return ocapa;
        }
        spin_unlock(&capa_lock);

        destroy_capa(ocapa);
        return old;
}

struct obd_capa *
capa_get(uid_t uid, int capa_op,__u64 mdsid, unsigned long ino,
         __u32 igen, int type)
{
        struct hlist_head *head = capa_hash + capa_hashfn(uid, mdsid, ino);
        struct obd_capa *ocapa;

        ocapa = find_capa_locked(head, uid, capa_op, mdsid, ino, igen, type);
        
        return ocapa;
}

void capa_put(struct obd_capa *ocapa)
{
        if (!ocapa)
                return;

        DEBUG_CAPA(D_INODE, &ocapa->c_capa, "put %s",
                   capa_type_name[ocapa->c_type]);
        spin_lock(&capa_lock);
        if (ocapa->c_type == CLIENT_CAPA) {
                list_del_init(&ocapa->c_lli_list);
                __capa_put(ocapa);
                destroy_capa(ocapa);
        } else {
                atomic_dec(&ocapa->c_refc);
        }
        spin_unlock(&capa_lock);
}

struct obd_capa *capa_renew(struct lustre_capa *capa, int type)
{
        uid_t uid = capa->lc_uid;
        int capa_op = capa->lc_op;
        __u64 mdsid = capa->lc_mdsid;
        unsigned long ino = capa->lc_ino;
        struct hlist_head *head = capa_hash +
                                  capa_hashfn(uid, mdsid, ino);
        struct obd_capa *ocapa;

        spin_lock(&capa_lock);
        ocapa = find_capa(head, uid, capa_op, mdsid, ino, capa->lc_igen, type);
        if (ocapa) {
                DEBUG_CAPA(D_INFO, capa, "renew %s", capa_type_name[type]);
                do_update_capa(ocapa, capa);
        }
        spin_unlock(&capa_lock);

        if (!ocapa)
                ocapa = get_new_capa_locked(head, type, capa);

        return ocapa;
}

static void dump_capa_key(char *buf, char *key)
{
        int i, n = 0;

        for (i = 0; i < CAPA_KEY_LEN; i++)
                n += sprintf(buf + n, "%02x", (unsigned char) key[i]);
}

void capa_hmac(struct crypto_tfm *tfm, __u8 *key, struct lustre_capa *capa)
{
        int keylen = CAPA_KEY_LEN;
        struct scatterlist sl = {
                .page   = virt_to_page(capa),
                .offset = (unsigned long)(capa) % PAGE_SIZE,
                .length = sizeof(struct lustre_capa_data),
        };

        LASSERT(tfm);
        crypto_hmac(tfm, key, &keylen, &sl, 1, capa->lc_hmac);
        {
        char *buf;

        OBD_ALLOC(key, keylen * 2 + 1);
        if (key) {
                dump_capa_key(buf, key);
                DEBUG_CAPA(D_INODE, capa, "hmac with %s", buf);
        }
        }
}

void capa_dup(void *dst, struct obd_capa *ocapa)
{
        spin_lock(&capa_lock);
        memcpy(dst, &ocapa->c_capa, sizeof(ocapa->c_capa));
        spin_unlock(&capa_lock);
}

void capa_dup2(void *dst, struct lustre_capa *capa)
{
        spin_lock(&capa_lock);
        memcpy(dst, capa, sizeof(*capa));
        spin_unlock(&capa_lock);
}

int capa_expired(struct lustre_capa *capa)
{
        struct timeval tv;

        do_gettimeofday(&tv);
        return ((unsigned long )capa->lc_expiry <= tv.tv_sec) ? 1 : 0;
}

int __capa_is_to_expire(struct obd_capa *ocapa, struct timeval *tv)
{
        int pre_expiry = capa_pre_expiry(&ocapa->c_capa);

        /* XXX: in case the clock is inaccurate, minus one more
         * pre_expiry to make sure the expiry won't miss */
        return ((unsigned long)ocapa->c_capa.lc_expiry -
                2 * pre_expiry <= tv->tv_sec)? 1 : 0;
}

int capa_is_to_expire(struct obd_capa *ocapa)
{
        struct timeval tv;
        int rc;

        do_gettimeofday(&tv);
        spin_lock(&capa_lock);
        rc = __capa_is_to_expire(ocapa, &tv);
        spin_unlock(&capa_lock);

        return rc;
}

EXPORT_SYMBOL(capa_op);
EXPORT_SYMBOL(capa_get);
EXPORT_SYMBOL(capa_put);
EXPORT_SYMBOL(capa_renew);
EXPORT_SYMBOL(__capa_get);
EXPORT_SYMBOL(capa_hmac);
EXPORT_SYMBOL(capa_dup);
EXPORT_SYMBOL(capa_dup2);
EXPORT_SYMBOL(capa_expired);
EXPORT_SYMBOL(__capa_is_to_expire);
EXPORT_SYMBOL(capa_is_to_expire);
