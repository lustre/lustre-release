/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2004 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_MDS

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/kmod.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <asm/segment.h>

#include <libcfs/list.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_ucache.h>

#include "mds_internal.h"

/* 
 * We need share hash table among the groups of MDSs (which server as the same
 * lustre file system), maybe MDT? but there's lprocfs problems of putting this
 * in MDT. so we make it global to the module. which brings the limitation that
 * one node couldn't running multiple MDS which server as different Lustre FS.
 * but which maybe not meaningful.
 */


#define MDS_LSD_HASHSIZE        (256)
static struct upcall_cache _lsd_cache;
static struct list_head _lsd_hashtable[MDS_LSD_HASHSIZE];

struct upcall_cache *__mds_get_global_lsd_cache()
{
        return &_lsd_cache;
}

static unsigned int lsd_hash(struct upcall_cache *cache, __u64 key)
{
        LASSERT(cache == &_lsd_cache);
        return ((__u32) key) & (MDS_LSD_HASHSIZE - 1);
}

static struct upcall_cache_entry *
lsd_alloc_entry(struct upcall_cache *cache, __u64 key)
{
        struct lsd_cache_entry *entry;
        ENTRY;

        OBD_ALLOC(entry, sizeof(*entry));
        if (!entry) {
                CERROR("failed to alloc entry\n");
                RETURN(NULL);
        }
        upcall_cache_init_entry(cache, &entry->base, key);

        RETURN(&entry->base);
}

static void lsd_free_entry(struct upcall_cache *cache,
                           struct upcall_cache_entry *entry)
{
        struct lsd_cache_entry *lentry;

        lentry = container_of(entry, struct lsd_cache_entry, base);
        if (lentry->lsd.lsd_ginfo)
                put_group_info(lentry->lsd.lsd_ginfo);
        OBD_FREE(lentry, sizeof(*lentry));
}


static int lsd_make_upcall(struct upcall_cache *cache,
                           struct upcall_cache_entry *entry)
{
        char *argv[4];
        char *envp[3];
        char uidstr[16];
        int rc;
        ENTRY;

        snprintf(uidstr, 16, "%u", (__u32) entry->ue_key);

        argv[0] = cache->uc_upcall;
        argv[1] = uidstr;
        argv[2] = NULL;
                                                                                                                        
        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/usr/sbin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking lsd upcall %s %s: %d; check "
                       "/proc/fs/lustre/mds/lsd_upcall\n",
                       argv[0], argv[1], rc);
        } else {
                CWARN("Invoked upcall %s %s\n",
                        argv[0], argv[1]);
        }
        RETURN(rc);
}

static int lsd_parse_downcall(struct upcall_cache *cache,
                              struct upcall_cache_entry *entry,
                              void *args)
{
        struct lustre_sec_desc *lsd;
        struct lsd_cache_entry *lentry;
        struct lsd_downcall_args *lsd_args;
        struct group_info *ginfo;
        ENTRY;

        LASSERT(args);

        lentry = container_of(entry, struct lsd_cache_entry, base);
        lsd = &lentry->lsd;
        lsd_args = (struct lsd_downcall_args *) args;
        LASSERT(lsd_args->err == 0);
        LASSERT(lsd_args->ngroups <= NGROUPS_MAX);

        ginfo = groups_alloc(lsd_args->ngroups);
        if (!ginfo) {
                CERROR("can't alloc group_info for %d groups\n",
                        lsd_args->ngroups);
                RETURN(-ENOMEM);
        }
        groups_from_buffer(ginfo, lsd_args->groups);
        groups_sort(ginfo);

        lsd->lsd_uid = lsd_args->uid;
        lsd->lsd_gid = lsd_args->gid;
        lsd->lsd_ginfo = ginfo;
        lsd->lsd_allow_setuid = lsd_args->allow_setuid;
        lsd->lsd_allow_setgid = lsd_args->allow_setgid;
        lsd->lsd_allow_setgrp = lsd_args->allow_setgrp;

        CWARN("LSD: uid %u gid %u ngroups %u, perm (%d/%d/%d)\n",
              lsd->lsd_uid, lsd->lsd_gid, ginfo->ngroups,
              lsd->lsd_allow_setuid, lsd->lsd_allow_setgid,
              lsd->lsd_allow_setgrp);
        RETURN(0);
}

struct lustre_sec_desc * mds_get_lsd(__u32 uid)
{
        struct upcall_cache *cache = &_lsd_cache;
        struct upcall_cache_entry *entry;
        struct lsd_cache_entry *lentry;

        entry = upcall_cache_get_entry(cache, (__u64) uid);
        if (!entry)
                return NULL;

        lentry = container_of(entry, struct lsd_cache_entry, base);
        return &lentry->lsd;
}

void mds_put_lsd(struct lustre_sec_desc *lsd)
{
        struct lsd_cache_entry *lentry;

        LASSERT(lsd);

        lentry = container_of(lsd, struct lsd_cache_entry, lsd);
        upcall_cache_put_entry(&lentry->base);
}

int mds_init_lsd_cache()
{
        struct upcall_cache *cache = &_lsd_cache;
        int i;
        ENTRY;

        cache->uc_hashtable = _lsd_hashtable;
        cache->uc_hashsize = MDS_LSD_HASHSIZE;
        cache->uc_hashlock = RW_LOCK_UNLOCKED;
        for (i = 0; i < cache->uc_hashsize; i++)
                INIT_LIST_HEAD(&cache->uc_hashtable[i]);
        cache->uc_name = "LSD_CACHE";

        /* set default value, proc tunable */
        sprintf(cache->uc_upcall, "%s", "/sbin/lsd_upcall");
        cache->uc_entry_expire = 5 * 60;
        cache->uc_acquire_expire = 5;

        cache->hash = lsd_hash;
        cache->alloc_entry = lsd_alloc_entry;
        cache->free_entry = lsd_free_entry;
        cache->make_upcall = lsd_make_upcall;
        cache->parse_downcall = lsd_parse_downcall;

        RETURN(0);
}

void mds_flush_lsd(__u32 id)
{
        struct upcall_cache *cache = &_lsd_cache;

        if (id == -1)
                upcall_cache_flush_idle(cache);
        else
                upcall_cache_flush_one(cache, (__u64) id);
}

void mds_cleanup_lsd_cache()
{
        upcall_cache_flush_all(&_lsd_cache);
}
