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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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
 * lustre/lvfs/upcall_cache.c
 *
 * Supplementary groups cache.
 */

#define DEBUG_SUBSYSTEM S_SEC

#ifndef AUTOCONF_INCLUDED
#include <linux/config.h>
#endif
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

#include <obd_support.h>
#include <lustre_lib.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)
struct group_info *groups_alloc(int ngroups)
{
        struct group_info *ginfo;

        LASSERT(ngroups <= NGROUPS_SMALL);

        OBD_ALLOC(ginfo, sizeof(*ginfo) + 1 * sizeof(gid_t *));
        if (!ginfo)
                return NULL;
        ginfo->ngroups = ngroups;
        ginfo->nblocks = 1;
        ginfo->blocks[0] = ginfo->small_block;
        atomic_set(&ginfo->usage, 1);

        return ginfo;
}

void groups_free(struct group_info *ginfo)
{
        LASSERT(ginfo->ngroups <= NGROUPS_SMALL);
        LASSERT(ginfo->nblocks == 1);
        LASSERT(ginfo->blocks[0] == ginfo->small_block);

        OBD_FREE(ginfo, sizeof(*ginfo) + 1 * sizeof(gid_t *));
}
#endif

static struct upcall_cache_entry *alloc_entry(__u64 key)
{
        struct upcall_cache_entry *entry;

        OBD_ALLOC(entry, sizeof(*entry));
        if (!entry)
                return NULL;

        UC_CACHE_SET_NEW(entry);
        INIT_LIST_HEAD(&entry->ue_hash);
        entry->ue_key = key;
        atomic_set(&entry->ue_refcount, 0);
        init_waitqueue_head(&entry->ue_waitq);
        return entry;
}

/* protected by hash lock */
static void free_entry(struct upcall_cache_entry *entry)
{
        if (entry->ue_group_info)
                groups_free(entry->ue_group_info);
        list_del(&entry->ue_hash);
        CDEBUG(D_OTHER, "destroy cache entry %p for key "LPU64"\n",
               entry, entry->ue_key);
        OBD_FREE(entry, sizeof(*entry));
}

static void get_entry(struct upcall_cache_entry *entry)
{
        atomic_inc(&entry->ue_refcount);
}

static void put_entry(struct upcall_cache_entry *entry)
{
        if (atomic_dec_and_test(&entry->ue_refcount) &&
            (UC_CACHE_IS_INVALID(entry) || UC_CACHE_IS_EXPIRED(entry))) {
                free_entry(entry);
        }
}

static int check_unlink_entry(struct upcall_cache_entry *entry)
{
        if (UC_CACHE_IS_VALID(entry) &&
            time_before(jiffies, entry->ue_expire))
                return 0;

        if (UC_CACHE_IS_ACQUIRING(entry)) {
                if (time_before(jiffies, entry->ue_acquire_expire))
                        return 0;

                UC_CACHE_SET_EXPIRED(entry);
                wake_up_all(&entry->ue_waitq);
        } else if (!UC_CACHE_IS_INVALID(entry)) {
                UC_CACHE_SET_EXPIRED(entry);
        }

        list_del_init(&entry->ue_hash);
        if (!atomic_read(&entry->ue_refcount))
                free_entry(entry);
        return 1;
}

static int refresh_entry(struct upcall_cache *hash,
                         struct upcall_cache_entry *entry)
{
        char *argv[4];
        char *envp[3];
        char keystr[16];
        int rc;
        ENTRY;

        snprintf(keystr, 16, LPU64, entry->ue_key);

        CDEBUG(D_INFO, "The groups upcall is: %s \n", hash->uc_upcall);
        argv[0] = hash->uc_upcall;
        argv[1] = hash->uc_name;
        argv[2] = keystr;
        argv[3] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/usr/sbin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("%s: error invoking getgroups upcall %s %s %s: rc %d; "
                       "check /proc/fs/lustre/mds/%s/group_upcall\n",
                       hash->uc_name, argv[0], argv[1], argv[2], rc, argv[1]);
        } else {
                CDEBUG(D_HA, "%s: invoked upcall %s %s %s\n", hash->uc_name,
                       argv[0], argv[1], argv[2]);
                rc = 0;
        }
        RETURN(rc);
}

static int entry_set_group_info(struct upcall_cache_entry *entry, __u32 primary,
                                __u32 ngroups, __u32 *groups)
{
        struct group_info *ginfo;
        int i, j;
        ENTRY;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)
        if (ngroups > NGROUPS)
                ngroups = NGROUPS;
#endif

        if (ngroups > NGROUPS_MAX) {
                CERROR("using first %d supplementary groups for uid "LPU64"\n",
                       NGROUPS_MAX, entry->ue_key);
                ngroups = NGROUPS_MAX;
        }

        ginfo = groups_alloc(ngroups);
        if (!ginfo) {
                CERROR("uid "LPU64" update can't alloc ginfo for %d groups\n",
                       entry->ue_key, ngroups);
                RETURN(-ENOMEM);
        }
        entry->ue_group_info = ginfo;
        entry->ue_primary = primary;

        for (i = 0; i < ginfo->nblocks; i++) {
                int cp_count = min(NGROUPS_PER_BLOCK, (int)ngroups);
                int off = i * NGROUPS_PER_BLOCK;

                for (j = 0; j < cp_count; j++)
                        ginfo->blocks[i][j] = groups[off + j];

                ngroups -= cp_count;
        }
        RETURN(0);
}

struct upcall_cache_entry *upcall_cache_get_entry(struct upcall_cache *hash,
                                                  __u64 key, __u32 primary,
                                                  __u32 ngroups, __u32 *groups)
{
        struct upcall_cache_entry *entry = NULL, *new = NULL, *next;
        struct list_head *head;
        wait_queue_t wait;
        int rc, found;
        ENTRY;

        LASSERT(hash);

        if (strcmp(hash->uc_upcall, "NONE") == 0) {
                new = alloc_entry(key);
                if (!new) {
                        CERROR("fail to alloc entry\n");
                        RETURN(NULL);
                }
                get_entry(new);

                /* We have to sort the groups for 2.6 kernels */
                LASSERT(ngroups <= 2);
                if (ngroups == 2 && groups[1] == -1)
                        ngroups--;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
                /* 2.6 needs groups array sorted */
                if (ngroups == 2 && groups[0] > groups[1]) {
                        __u32 tmp = groups[1];
                        groups[1] = groups[0];
                        groups[0] = tmp;
                }
#endif
                if (ngroups > 0 && groups[0] == -1) {
                        groups[0] = groups[1];
                        ngroups--;
                }

                rc = entry_set_group_info(new, primary, ngroups, groups);

                /* We can't cache this entry as it only has a subset of
                 * the user's groups, as sent in suppgid1, suppgid2. */
                UC_CACHE_SET_EXPIRED(new);
                RETURN(new);
        }
        head = &hash->uc_hashtable[UC_CACHE_HASH_INDEX(key)];
find_again:
        found = 0;
        spin_lock(&hash->uc_lock);
        list_for_each_entry_safe(entry, next, head, ue_hash) {
                /* check invalid & expired items */
                if (check_unlink_entry(entry))
                        continue;
                if (entry->ue_key == key) {
                        found = 1;
                        break;
                }
        }

        if (!found) { /* didn't find it */
                if (!new) {
                        spin_unlock(&hash->uc_lock);
                        new = alloc_entry(key);
                        if (!new) {
                                CERROR("fail to alloc entry\n");
                                RETURN(ERR_PTR(-ENOMEM));
                        }
                        goto find_again;
                } else {
                        list_add(&new->ue_hash, head);
                        entry = new;
                }
        } else {
                if (new) {
                        free_entry(new);
                        new = NULL;
                }
                list_move(&entry->ue_hash, head);
        }
        get_entry(entry);

        /* acquire for new one */
        if (UC_CACHE_IS_NEW(entry)) {
                UC_CACHE_SET_ACQUIRING(entry);
                UC_CACHE_CLEAR_NEW(entry);
                entry->ue_acquire_expire = jiffies + hash->uc_acquire_expire;
                spin_unlock(&hash->uc_lock);
                rc = refresh_entry(hash, entry);
                spin_lock(&hash->uc_lock);
                if (rc < 0) {
                        UC_CACHE_CLEAR_ACQUIRING(entry);
                        UC_CACHE_SET_INVALID(entry);
                }
                /* fall through */
        }
        /* someone (and only one) is doing upcall upon
         * this item, just wait it complete
         */
        if (UC_CACHE_IS_ACQUIRING(entry)) {
                init_waitqueue_entry(&wait, current);
                add_wait_queue(&entry->ue_waitq, &wait);
                set_current_state(TASK_INTERRUPTIBLE);
                spin_unlock(&hash->uc_lock);

                schedule_timeout(hash->uc_acquire_expire);

                spin_lock(&hash->uc_lock);
                remove_wait_queue(&entry->ue_waitq, &wait);
                if (UC_CACHE_IS_ACQUIRING(entry)) {
                        static unsigned long next;
                        /* we're interrupted or upcall failed in the middle */
                        if (time_after(jiffies, next)) {
                                CERROR("acquire timeout exceeded for key "LPU64
                                       "\n", entry->ue_key);
                                next = jiffies + 1800;
                        }
                        put_entry(entry);
                        GOTO(out, entry = ERR_PTR(-EIDRM));
                }
                /* fall through */
        }

        /* invalid means error, don't need to try again */
        if (UC_CACHE_IS_INVALID(entry)) {
                put_entry(entry);
                GOTO(out, entry = ERR_PTR(-EIDRM));
        }

        /* check expired
         * We can't refresh the existing one because some
         * memory might be shared by multiple processes.
         */
        if (check_unlink_entry(entry)) {
                /* if expired, try again. but if this entry is
                 * created by me but too quickly turn to expired
                 * without any error, should at least give a
                 * chance to use it once.
                 */
                if (entry != new) {
                        put_entry(entry);
                        spin_unlock(&hash->uc_lock);
                        new = NULL;
                        goto find_again;
                }
        }

        /* Now we know it's good */
out:
        spin_unlock(&hash->uc_lock);
        RETURN(entry);
}
EXPORT_SYMBOL(upcall_cache_get_entry);

void upcall_cache_put_entry(struct upcall_cache *hash,
                            struct upcall_cache_entry *entry)
{
        ENTRY;

        if (!entry) {
                EXIT;
                return;
        }

        LASSERT(atomic_read(&entry->ue_refcount) > 0);
        spin_lock(&hash->uc_lock);
        put_entry(entry);
        spin_unlock(&hash->uc_lock);
        EXIT;
}
EXPORT_SYMBOL(upcall_cache_put_entry);

int upcall_cache_downcall(struct upcall_cache *hash, __u32 err, __u64 key,
                          __u32 primary, __u32 ngroups, __u32 *groups)
{
        struct upcall_cache_entry *entry = NULL;
        struct list_head *head;
        int found = 0, rc = 0;
        ENTRY;

        LASSERT(hash);

        head = &hash->uc_hashtable[UC_CACHE_HASH_INDEX(key)];

        spin_lock(&hash->uc_lock);
        list_for_each_entry(entry, head, ue_hash) {
                if (entry->ue_key == key) {
                        found = 1;
                        get_entry(entry);
                        break;
                }
        }

        if (!found) {
                CDEBUG(D_OTHER, "%s: upcall for key "LPU64" not expected\n",
                       hash->uc_name, entry->ue_key);
                /* haven't found, it's possible */
                spin_unlock(&hash->uc_lock);
                RETURN(-EINVAL);
        }

        if (err) {
                CDEBUG(D_OTHER, "%s: upcall for key "LPU64" returned %d\n",
                       hash->uc_name, entry->ue_key, err);
                GOTO(out, rc = -EINVAL);
        }

        if (!UC_CACHE_IS_ACQUIRING(entry)) {
                CDEBUG(D_RPCTRACE,"%s: found uptodate entry %p (key "LPU64")\n",
                       hash->uc_name, entry, entry->ue_key);
                GOTO(out, rc = 0);
        }

        if (UC_CACHE_IS_INVALID(entry) || UC_CACHE_IS_EXPIRED(entry)) {
                CERROR("%s: found a stale entry %p (key "LPU64") in ioctl\n",
                       hash->uc_name, entry, entry->ue_key);
                GOTO(out, rc = -EINVAL);
        }

        spin_unlock(&hash->uc_lock);
        rc = entry_set_group_info(entry, primary, ngroups, groups);
        spin_lock(&hash->uc_lock);
        if (rc)
                GOTO(out, rc);

        entry->ue_expire = jiffies + hash->uc_entry_expire;
        UC_CACHE_SET_VALID(entry);
        CDEBUG(D_OTHER, "%s: created upcall cache entry %p for key "LPU64"\n",
               hash->uc_name, entry, entry->ue_key);
out:
        if (rc) {
                UC_CACHE_SET_INVALID(entry);
                list_del_init(&entry->ue_hash);
        }
        UC_CACHE_CLEAR_ACQUIRING(entry);
        spin_unlock(&hash->uc_lock);
        wake_up_all(&entry->ue_waitq);
        put_entry(entry);

        RETURN(rc);
}
EXPORT_SYMBOL(upcall_cache_downcall);

static void cache_flush(struct upcall_cache *hash, int force)
{
        struct upcall_cache_entry *entry, *next;
        int i;
        ENTRY;

        spin_lock(&hash->uc_lock);
        for (i = 0; i < UC_CACHE_HASH_SIZE; i++) {
                list_for_each_entry_safe(entry, next,
                                         &hash->uc_hashtable[i], ue_hash) {
                        if (!force && atomic_read(&entry->ue_refcount)) {
                                UC_CACHE_SET_EXPIRED(entry);
                                continue;
                        }
                        LASSERT(!atomic_read(&entry->ue_refcount));
                        free_entry(entry);
                }
        }
        spin_unlock(&hash->uc_lock);
        EXIT;
}

void upcall_cache_flush_idle(struct upcall_cache *cache)
{
        cache_flush(cache, 0);
}
EXPORT_SYMBOL(upcall_cache_flush_idle);

void upcall_cache_flush_all(struct upcall_cache *cache)
{
        cache_flush(cache, 1);
}
EXPORT_SYMBOL(upcall_cache_flush_all);

struct upcall_cache *upcall_cache_init(const char *name)
{
        struct upcall_cache *hash;
        int i;
        ENTRY;

        OBD_ALLOC(hash, sizeof(*hash));
        if (!hash)
                RETURN(ERR_PTR(-ENOMEM));

        spin_lock_init(&hash->uc_lock);
        for (i = 0; i < UC_CACHE_HASH_SIZE; i++)
                INIT_LIST_HEAD(&hash->uc_hashtable[i]);
        strncpy(hash->uc_name, name, sizeof(hash->uc_name) - 1);
        /* set default value, proc tunable */
        strcpy(hash->uc_upcall, "NONE");
        hash->uc_entry_expire = 10 * 60 * HZ;
        hash->uc_acquire_expire = 15 * HZ;

        RETURN(hash);
}
EXPORT_SYMBOL(upcall_cache_init);

void upcall_cache_cleanup(struct upcall_cache *hash)
{
        if (!hash)
                return;
        upcall_cache_flush_all(hash);
        OBD_FREE(hash, sizeof(*hash));
}
EXPORT_SYMBOL(upcall_cache_cleanup);
