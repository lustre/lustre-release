/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Supplementary groups and MDS-side group handling.
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

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_mds.h>

#define GRP_HASH_NEW              0x1
#define GRP_HASH_ACQUIRING        0x2
#define GRP_HASH_INVALID          0x4
#define GRP_HASH_EXPIRED          0x8

#define GRP_IS_NEW(i)          ((i)->ge_flags & GRP_HASH_NEW)
#define GRP_IS_INVALID(i)      ((i)->ge_flags & GRP_HASH_INVALID)
#define GRP_IS_ACQUIRING(i)    ((i)->ge_flags & GRP_HASH_ACQUIRING)
#define GRP_IS_EXPIRED(i)      ((i)->ge_flags & GRP_HASH_EXPIRED)
#define GRP_IS_VALID(i)        ((i)->ge_flags == 0)

#define GRP_SET_NEW(i)         (i)->ge_flags |= GRP_HASH_NEW
#define GRP_SET_INVALID(i)     (i)->ge_flags |= GRP_HASH_INVALID
#define GRP_SET_ACQUIRING(i)   (i)->ge_flags |= GRP_HASH_ACQUIRING
#define GRP_SET_EXPIRED(i)     (i)->ge_flags |= GRP_HASH_EXPIRED
#define GRP_SET_VALID(i)       (i)->ge_flags = 0

#define GRP_CLEAR_NEW(i)       (i)->ge_flags &= ~GRP_HASH_NEW
#define GRP_CLEAR_ACQUIRING(i) (i)->ge_flags &= ~GRP_HASH_ACQUIRING
#define GRP_CLEAR_INVALID(i)   (i)->ge_flags &= ~GRP_HASH_INVALID
#define GRP_CLEAR_EXPIRED(i)   (i)->ge_flags &= ~GRP_HASH_EXPIRED

static struct mds_grp_hash_entry *alloc_entry(uid_t uid)
{
        struct mds_grp_hash_entry *entry;

        OBD_ALLOC(entry, sizeof(*entry));
        if (!entry)
                return NULL;

        GRP_SET_NEW(entry);
        INIT_LIST_HEAD(&entry->ge_hash);
        entry->ge_uid = uid;
        atomic_set(&entry->ge_refcount, 0);
        init_waitqueue_head(&entry->ge_waitq);
        return entry;
}

/* protected by hash lock */
static void free_entry(struct mds_grp_hash_entry *entry)
{
        groups_free(entry->ge_group_info);
        list_del(&entry->ge_hash);
        CDEBUG(D_OTHER, "destroy mds_grp_entry %p for uid %d\n",
               entry, entry->ge_uid);
        OBD_FREE(entry, sizeof(*entry));
}

static void get_entry(struct mds_grp_hash_entry *entry)
{
        atomic_inc(&entry->ge_refcount);
}

static void put_entry(struct mds_grp_hash_entry *entry)
{
        if (atomic_dec_and_test(&entry->ge_refcount) &&
            (GRP_IS_INVALID(entry) || GRP_IS_EXPIRED(entry))) {
                free_entry(entry);
        }
}

static int check_unlink_entry(struct mds_grp_hash_entry *entry)
{
        if (GRP_IS_VALID(entry) &&
            time_before(jiffies, entry->ge_expire))
                return 0;

        if (GRP_IS_ACQUIRING(entry)) {
                if (time_before(jiffies, entry->ge_acquire_expire))
                        return 0;

                GRP_SET_EXPIRED(entry);
                wake_up_all(&entry->ge_waitq);
        } else if (!GRP_IS_INVALID(entry)) {
                GRP_SET_EXPIRED(entry);
        }

        list_del_init(&entry->ge_hash);
        if (!atomic_read(&entry->ge_refcount))
                free_entry(entry);
        return 1;
}

static int refresh_entry(struct mds_grp_hash *hash,
                         struct mds_grp_hash_entry *entry)
{
        char *argv[4];
        char *envp[3];
        char uidstr[16];
        int rc;
        ENTRY;

        snprintf(uidstr, 16, "%d", entry->ge_uid);

        CDEBUG(D_INFO, "The groups upcall is: %s \n", hash->gh_upcall);
        argv[0] = hash->gh_upcall;
        argv[1] = hash->gh_mdsname;
        argv[2] = uidstr;
        argv[3] = NULL;

        envp[0] = "HOME=/";
        envp[1] = "PATH=/sbin:/usr/sbin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0)
                CERROR("%s: error invoking getgroups upcall %s %s %s: %d; check"
                       "/proc/fs/lustre/mds/%s/grp_hash_upcall\n",
                       hash->gh_mdsname, argv[0], argv[1], argv[2], rc,argv[1]);
        else
                CDEBUG(D_HA, "%s: invoked upcall %s %s %s\n", hash->gh_mdsname,
                       argv[0], argv[1], argv[2]);
        RETURN(rc);
}

struct mds_grp_hash_entry *mds_get_group_entry(struct mds_obd *mds, uid_t uid,
                                               __u32 ngroups, __u32 *groups)
{
        struct mds_grp_hash *hash = mds->mds_group_hash;
        struct mds_grp_hash_entry *entry = NULL, *new = NULL, *next;
        struct list_head *head;
        wait_queue_t wait;
        int rc, found;
        ENTRY;

        LASSERT(hash);

        if (!strcmp(hash->gh_upcall, "NONE")) {
                __u32 tmp;

                new = alloc_entry(uid);
                if (!new) {
                        CERROR("fail to alloc entry\n");
                        RETURN(NULL);
                }

                LASSERT(ngroups <= 2);
                if (ngroups == 2 && groups[1] == -1)
                        ngroups--;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,4)
                /* 2.6 needs groups array sorted */
                if (ngroups == 2 && groups[0] > groups[1]) {
                        tmp = groups[1];
                        groups[1] = groups[0];
                        groups[0] = tmp;
                }
#endif
                if (ngroups > 0 && groups[0] == -1) {
                        groups[0] = groups[1];
                        ngroups--;
                }

                new->ge_group_info = groups_alloc(ngroups);
                if (!new->ge_group_info) {
                        CERROR("fail to alloc entry\n");
                        free_entry(new);
                        RETURN(NULL);
                }
                for (tmp = 0; tmp < ngroups; tmp++)
                        new->ge_group_info->blocks[0][tmp] = groups[tmp];

                /* We can't cache this entry as it only has a subset of
                 * the user's groups, as sent in suppgid1, suppgid2. */
                GRP_SET_EXPIRED(new);
                get_entry(new);
                RETURN(new);
        }
        head = &hash->gh_table[MDSGRP_HASH_INDEX(uid)];
find_again:
        found = 0;
        spin_lock(&hash->gh_lock);
        list_for_each_entry_safe(entry, next, head, ge_hash) {
                /* check invalid & expired items */
                if (check_unlink_entry(entry))
                        continue;
                if (entry->ge_uid == uid) {
                        found = 1;
                        break;
                }
        }

        if (!found) { /* didn't find it */
                if (!new) {
                        spin_unlock(&hash->gh_lock);
                        new = alloc_entry(uid);
                        if (!new) {
                                CERROR("fail to alloc entry\n");
                                RETURN(NULL);
                        }
                        goto find_again;
                } else {
                        list_add(&new->ge_hash, head);
                        entry = new;
                }
        } else {
                if (new) {
                        free_entry(new);
                        new = NULL;
                }
                list_move(&entry->ge_hash, head);
        }
        get_entry(entry);

        /* acquire for new one */
        if (GRP_IS_NEW(entry)) {
                GRP_SET_ACQUIRING(entry);
                GRP_CLEAR_NEW(entry);
                entry->ge_acquire_expire = jiffies +
                                           hash->gh_acquire_expire;
                spin_unlock(&hash->gh_lock);
                rc = refresh_entry(hash, entry);
                spin_lock(&hash->gh_lock);
                if (rc) {
                        GRP_CLEAR_ACQUIRING(entry);
                        GRP_SET_INVALID(entry);
                }
                /* fall through */
        }
        /* someone (and only one) is doing upcall upon
         * this item, just wait it complete
         */
        if (GRP_IS_ACQUIRING(entry)) {
                init_waitqueue_entry(&wait, current);
                add_wait_queue(&entry->ge_waitq, &wait);
                set_current_state(TASK_INTERRUPTIBLE);
                spin_unlock(&hash->gh_lock);

                schedule_timeout(hash->gh_acquire_expire);

                spin_lock(&hash->gh_lock);
                remove_wait_queue(&entry->ge_waitq, &wait);
                if (GRP_IS_ACQUIRING(entry)) {
                        static unsigned long next;
                        /* we're interrupted or upcall failed
                         * in the middle
                         */
                        if (time_after(jiffies, next)) {
                                CERROR("uid %u group update failed: check %s\n",
                                       entry->ge_uid, hash->gh_upcall);
                                next = jiffies + 1800;
                        }
                        put_entry(entry);
                        GOTO(out, entry = NULL);
                }
                /* fall through */
        }

        /* invalid means error, don't need to try again */
        if (GRP_IS_INVALID(entry)) {
                put_entry(entry);
                GOTO(out, entry = NULL);
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
                        spin_unlock(&hash->gh_lock);
                        new = NULL;
                        goto find_again;
                }
        }

        /* Now we know it's good */
out:
        spin_unlock(&hash->gh_lock);
        RETURN(entry);
}


void mds_put_group_entry(struct mds_obd *mds,
                         struct mds_grp_hash_entry *entry)
{
        struct mds_grp_hash *hash = mds->mds_group_hash;
        ENTRY;

        if (!entry) {
                EXIT;
                return;
        }

        LASSERT(atomic_read(&entry->ge_refcount) > 0);
        spin_lock(&hash->gh_lock);
        put_entry(entry);
        spin_unlock(&hash->gh_lock);
        EXIT;
}

static int entry_set_group_info(struct mds_grp_hash_entry *entry,
                                __u32 ngroups, gid_t *groups)
{
        struct group_info *ginfo;
        int i, j;
        ENTRY;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,4)
        if (ngroups > NGROUPS)
                ngroups = NGROUPS;
#endif

        if (ngroups > NGROUPS_MAX) {
                CERROR("too many (%d) supp groups\n", ngroups);
                RETURN(-EINVAL);
        }

        ginfo = groups_alloc(ngroups);
        if (!ginfo) {
                CERROR("can't alloc group_info for %d groups\n", ngroups);
                RETURN(-ENOMEM);
        }
        entry->ge_group_info = ginfo;

        for (i = 0; i < ginfo->nblocks; i++) {
                int cp_count = min(NGROUPS_PER_BLOCK, (int)ngroups);
                int off = i * NGROUPS_PER_BLOCK;

                for (j = 0; j < cp_count; j++)
                        ginfo->blocks[i][j] = groups[off + j];

                ngroups -= cp_count;
        }
        RETURN(0);
}

int mds_handle_group_downcall(struct mds_obd *mds, __u32 err, __u32 uid,
                              __u32 ngroups, __u32 *groups)
{
        struct mds_grp_hash *hash = mds->mds_group_hash;
        struct mds_grp_hash_entry *entry = NULL;
        struct list_head *head;
        int found = 0, rc = 0;
        ENTRY;

        LASSERT(hash);

        head = &hash->gh_table[MDSGRP_HASH_INDEX(uid)];

        spin_lock(&hash->gh_lock);
        list_for_each_entry(entry, head, ge_hash) {
                if (entry->ge_uid == uid) {
                        found = 1;
                        break;
                }
        }

        if (!found) {
                /* haven't found, it's possible */
                spin_unlock(&hash->gh_lock);
                RETURN(-EINVAL);
        }

        if (err) {
                GRP_SET_INVALID(entry);
                spin_unlock(&hash->gh_lock);
                GOTO(out, rc = -EINVAL);
        }

        if (!GRP_IS_ACQUIRING(entry) ||
            GRP_IS_INVALID(entry) ||
            GRP_IS_EXPIRED(entry)) {
                CERROR("found a stale entry %p(uid %d) in ioctl\n",
                        entry, entry->ge_uid);
                spin_unlock(&hash->gh_lock);
                GOTO(out, rc = -EINVAL);
        }

        atomic_inc(&entry->ge_refcount);
        spin_unlock(&hash->gh_lock);
        rc = entry_set_group_info(entry, ngroups, groups);

        spin_lock(&hash->gh_lock);
        atomic_dec(&entry->ge_refcount);
        if (rc) {
                GRP_SET_INVALID(entry);
                list_del_init(&entry->ge_hash);
                GOTO(out, rc);
        }
        entry->ge_acquisition_time = CURRENT_TIME;
        entry->ge_expire = jiffies + hash->gh_entry_expire;
        GRP_SET_VALID(entry);
        CDEBUG(D_OTHER, "created mds_grp_entry %p for uid %d\n",
               entry, entry->ge_uid);
        spin_unlock(&hash->gh_lock);
out:
        wake_up_all(&entry->ge_waitq);
        RETURN(rc);
}

static void mds_flush_group_hash(struct mds_grp_hash *hash, int force)
{
        struct mds_grp_hash_entry *entry, *next;
        int i;
        ENTRY;

        spin_lock(&hash->gh_lock);
        for (i = 0; i < MDSGRP_HASH_SIZE; i++) {
                list_for_each_entry_safe(entry, next,
                                         &hash->gh_table[i], ge_hash) {
                        if (!force && atomic_read(&entry->ge_refcount)) {
                                GRP_SET_EXPIRED(entry);
                                continue;
                        }
                        LASSERT(!atomic_read(&entry->ge_refcount));
                        free_entry(entry);
                }
        }
        spin_unlock(&hash->gh_lock);
        EXIT;
}

void mds_group_hash_flush_idle(struct mds_obd *mds)
{
        mds_flush_group_hash(mds->mds_group_hash, 0);
}

#define mds2obd(mds)    \
        ((struct obd_device *)((char *)mds - (int)&((struct obd_device *)0)->u.mds))

int mds_group_hash_init(struct mds_obd *mds)
{
        struct mds_grp_hash *hash;
        int i;
        ENTRY;

        OBD_ALLOC(hash, sizeof(*hash));
        if (!hash)
                RETURN(-ENOMEM);

        rwlock_init(&hash->gh_lock);
        for (i = 0; i < MDSGRP_HASH_SIZE; i++)
                INIT_LIST_HEAD(&hash->gh_table[i]);
        hash->gh_mdsname = mds2obd(mds)->obd_name;
        /* set default value, proc tunable */
        strcpy(hash->gh_upcall, "NONE");
        hash->gh_entry_expire = 5 * 60 * HZ;
        hash->gh_acquire_expire = 5 * HZ;
        mds->mds_group_hash = hash;
        RETURN(0);
}

void mds_group_hash_cleanup(struct mds_obd *mds)
{
        struct mds_grp_hash *hash;

        hash = mds->mds_group_hash;
        if (!hash)
                return;
        mds_flush_group_hash(hash, 1);
        OBD_FREE(hash, sizeof(*hash));
        mds->mds_group_hash = NULL;
}
