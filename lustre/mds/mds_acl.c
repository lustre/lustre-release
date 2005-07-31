/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2005 Cluster File Systems, Inc.
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

/****************************************
 * handle remote getfacl/setfacl upcall *
 ****************************************/

#define RMTACL_UPCALL_HASHSIZE        (1)
static struct upcall_cache _rmtacl_upcall_cache;
static struct list_head _rmtacl_upcall_hashtable[RMTACL_UPCALL_HASHSIZE];

#define RMTACL_UPCALL_PATH              "/usr/bin/lacl_upcall"
#define RMTACL_ACQUIRE_EXPIRE           (15)
#define RMTACL_ENTRY_EXPIRE             (0)
#define RMTACL_ERR_ENTRY_EXPIRE         (0)

struct upcall_cache *__mds_get_global_rmtacl_upcall_cache()
{
        return &_rmtacl_upcall_cache;
}

static unsigned int rmtacl_hash(struct upcall_cache *cache, __u64 key)
{
        LASSERT(cache == &_rmtacl_upcall_cache);
        return 0;
}

static struct upcall_cache_entry *
rmtacl_alloc_entry(struct upcall_cache *cache, __u64 key)
{
        struct rmtacl_upcall_entry *entry;

        OBD_ALLOC(entry, sizeof(*entry));
        if (!entry)
                return NULL;

        upcall_cache_init_entry(cache, &entry->base, key);
        entry->desc = (struct rmtacl_upcall_desc *) ((unsigned long) key);

        return &entry->base;
}

static void rmtacl_free_entry(struct upcall_cache *cache,
                              struct upcall_cache_entry *entry)
{
        struct rmtacl_upcall_entry *rentry;

        rentry = container_of(entry, struct rmtacl_upcall_entry, base);
        OBD_FREE(rentry, sizeof(*rentry));
}

static int rmtacl_make_upcall(struct upcall_cache *cache,
                              struct upcall_cache_entry *entry)
{
        struct rmtacl_upcall_entry *rentry;
        struct rmtacl_upcall_desc *desc;
        char *argv[7];
        char *envp[3];
        char keystr[20];
        char uidstr[16];
        int rc;

        rentry = container_of(entry, struct rmtacl_upcall_entry, base);
        desc = rentry->desc;

        snprintf(keystr, 20, LPX64, entry->ue_key);
        snprintf(uidstr, 16, "%u", desc->uid);

        argv[0] = cache->uc_upcall;
        argv[1] = keystr;
        argv[2] = uidstr;
        argv[3] = desc->root;
        argv[4] = desc->get ? "get" : "set";
        argv[5] = desc->cmd;
        argv[6] = NULL;
                                                                                                                        
        envp[0] = "HOME=/";
        envp[1] = "PATH=/bin:/usr/bin:/usr/local/bin";
        envp[2] = NULL;

        rc = USERMODEHELPER(argv[0], argv, envp);
        if (rc < 0) {
                CERROR("Error invoking upcall %s: %d; check "
                       "/proc/fs/lustre/mds/lacl_upcall\n",
                       argv[0], rc);
        } else {
                CDEBUG(D_SEC, "Invoked upcall %s %s %s %s\n",
                       argv[0], argv[1], argv[2], argv[3]);
        }
        return rc;
}

static int rmtacl_parse_downcall(struct upcall_cache *cache,
                                 struct upcall_cache_entry *entry,
                                 void *args)
{
        struct rmtacl_upcall_entry *rentry;
        struct rmtacl_upcall_desc *desc;
        struct rmtacl_downcall_args *rargs;

        LASSERT(args);

        rentry = container_of(entry, struct rmtacl_upcall_entry, base);
        desc = rentry->desc;
        rargs = (struct rmtacl_downcall_args *) args;

        desc->status = rargs->status;

        if (desc->reslen < rargs->reslen) {
                CERROR("bufsize %u, while %u passed down\n",
                       desc->reslen, rargs->reslen);
                desc->upcall_status = -ENOMEM;
                goto out;
        }

        desc->reslen = rargs->reslen;
        if (!rargs->reslen)
                goto out;

        if (copy_from_user(desc->res, rargs->res, rargs->reslen)) {
                desc->upcall_status = -EFAULT;
                goto out;
        }

out:
        return 0;
}

static void mds_rmtacl_upcall(struct rmtacl_upcall_desc *desc)
{
        struct upcall_cache *cache = &_rmtacl_upcall_cache;
        struct upcall_cache_entry *entry;

        desc->upcall_status = 0;

        entry = upcall_cache_get_entry(cache, (__u64) ((unsigned long) desc));
        if (!entry) {
                desc->upcall_status = -EINVAL;
                return;
        }

        UC_CACHE_SET_EXPIRED(entry);
        upcall_cache_put_entry(entry);
}

int mds_init_rmtacl_upcall_cache()
{
        struct upcall_cache *cache = &_rmtacl_upcall_cache;
        int i;
        ENTRY;

        cache->uc_hashtable = _rmtacl_upcall_hashtable;
        cache->uc_hashsize = RMTACL_UPCALL_HASHSIZE;
        cache->uc_hashlock = RW_LOCK_UNLOCKED;
        for (i = 0; i < cache->uc_hashsize; i++)
                INIT_LIST_HEAD(&cache->uc_hashtable[i]);
        cache->uc_name = "RMTACL_UPCALL";

        /* set default value, proc tunable */
        sprintf(cache->uc_upcall, RMTACL_UPCALL_PATH);
        cache->uc_acquire_expire = RMTACL_ACQUIRE_EXPIRE;
        cache->uc_entry_expire = RMTACL_ENTRY_EXPIRE;
        cache->uc_err_entry_expire = RMTACL_ERR_ENTRY_EXPIRE;

        cache->hash = rmtacl_hash;
        cache->alloc_entry = rmtacl_alloc_entry;
        cache->free_entry = rmtacl_free_entry;
        cache->make_upcall = rmtacl_make_upcall;
        cache->parse_downcall = rmtacl_parse_downcall;

        RETURN(0);
}

void mds_cleanup_rmtacl_upcall_cache()
{
        struct upcall_cache *cache = &_rmtacl_upcall_cache;

        LASSERT(list_empty(&cache->uc_hashtable[0]));
}

/****************************************
 * exported helper functions            *
 ****************************************/

/*
 * traverse through the mountpoint to find lustre mountpoint
 */
static struct vfsmount *mds_get_lustre_mnt(void)
{
        struct vfsmount *mnt, *lmnt = NULL;

        LASSERT(current->fs);
        read_lock(&current->fs->lock);
        mnt = mntget(current->fs->rootmnt);
        read_unlock(&current->fs->lock);
        LASSERT(mnt);

        spin_lock(&vfsmount_lock);
check_point:
        if (!strcmp(mnt->mnt_sb->s_type->name, "lustre") ||
            !strcmp(mnt->mnt_sb->s_type->name, "llite")) {
                lmnt = mntget(mnt);
                goto break_out;
        }

        if (!list_empty(&mnt->mnt_mounts)) {
                mnt = list_entry(mnt->mnt_mounts.next,
                                 struct vfsmount, mnt_child);
                goto check_point;
        }

follow_siblings:
        /* check siblings */
        if (list_empty(&mnt->mnt_child) ||
            mnt->mnt_child.next == &mnt->mnt_parent->mnt_mounts) {
                /* we are the last child */
                LASSERT(mnt->mnt_parent != NULL);
                if (list_empty(&mnt->mnt_child) ||
                    mnt->mnt_parent == NULL)
                        goto break_out;
                mnt = mnt->mnt_parent;
                goto follow_siblings;
        }

        mnt = list_entry(mnt->mnt_child.next, struct vfsmount, mnt_child);
        goto check_point;

break_out:
        spin_unlock(&vfsmount_lock);

        return lmnt;
}

void mds_do_remote_acl_upcall(struct rmtacl_upcall_desc *desc)
{
        struct fs_struct *fs = current->fs;
        struct vfsmount *lmnt;
        char *buf = NULL, *mntpnt;

        lmnt = mds_get_lustre_mnt();
        if (!lmnt) {
                desc->upcall_status = -EOPNOTSUPP;
                return;
        }

        OBD_ALLOC(buf, PAGE_SIZE);
        if (!buf) {
                desc->upcall_status = -ENOMEM;
                goto out;
        }

        mntpnt = __d_path(lmnt->mnt_root, lmnt, fs->root, fs->rootmnt,
                          buf, PAGE_SIZE);
        if (IS_ERR(mntpnt)) {
                desc->upcall_status = PTR_ERR(mntpnt);
                goto out;
        }

        desc->root = mntpnt;
        desc->uid = current->uid;

        mds_rmtacl_upcall(desc);

out:
        if (buf)
                OBD_FREE(buf, PAGE_SIZE);
        mntput(lmnt);
}
