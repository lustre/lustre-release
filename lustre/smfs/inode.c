/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2004 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/obd_class.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_smfs.h>
#include "smfs_internal.h"

static void smfs_read_inode(struct inode *inode)
{
        struct super_block *cache_sb;
        struct inode *cache_inode;
        ENTRY;

        if (!inode)
                return;

        CDEBUG(D_INODE, "read_inode ino %lu\n", inode->i_ino);
        cache_sb = S2CSB(inode->i_sb);

        cache_inode = iget(cache_sb, inode->i_ino);

        SMFS_SET_INODE_REC(inode);
        SMFS_SET_INODE_CACHE_HOOK(inode);
        I2CI(inode) = cache_inode;

        pre_smfs_inode(inode, cache_inode);
        if (cache_sb && cache_sb->s_op->read_inode)
                cache_sb->s_op->read_inode(cache_inode);

        post_smfs_inode(inode, cache_inode);
        sm_set_inode_ops(cache_inode, inode);

        CDEBUG(D_INODE, "read_inode ino %lu icount %d \n",
               inode->i_ino, atomic_read(&inode->i_count));
        EXIT;
}

/* Although some filesystem(such as ext3) do not have
 * clear_inode method, but we need it to free the
 * cache inode
 */
static void smfs_clear_inode(struct inode *inode)
{
        struct super_block *cache_sb;
        struct inode *cache_inode;
        ENTRY;

        if (!inode)
                return;

        cache_sb = S2CSB(inode->i_sb);
        cache_inode = I2CI(inode);

        /*FIXME: because i_count of cache_inode may not
         * be 0 or 1 in before smfs_delete inode, So we
         * need to dec it to 1 before we call delete_inode
         * of the bellow cache filesystem Check again latter*/

        if (atomic_read(&cache_inode->i_count) < 1)
                BUG();

        while (atomic_read(&cache_inode->i_count) != 1)
                atomic_dec(&cache_inode->i_count);

        iput(cache_inode);

        SMFS_CLEAN_INODE_REC(inode);
        I2CI(inode) = NULL;
        EXIT;
}

static void smfs_delete_inode(struct inode *inode)
{
        struct inode *cache_inode;
        struct super_block *cache_sb;
        ENTRY;

        cache_inode = I2CI(inode);
        cache_sb = S2CSB(inode->i_sb);

        if (!cache_inode || !cache_sb)
                return;

        /* FIXME-WANGDI: because i_count of cache_inode may not be 0 or 1 in
         * before smfs_delete inode, So we need to dec it to 1 before we call
         * delete_inode of the bellow cache filesystem Check again latter. */

        if (atomic_read(&cache_inode->i_count) < 1)
                BUG();

        while (atomic_read(&cache_inode->i_count) != 1)
                atomic_dec(&cache_inode->i_count);

        pre_smfs_inode(inode, cache_inode);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        list_del(&cache_inode->i_hash);
        INIT_LIST_HEAD(&cache_inode->i_hash);
#else
        hlist_del_init(&cache_inode->i_hash);
#endif
        
        list_del(&cache_inode->i_list);
        INIT_LIST_HEAD(&cache_inode->i_list);

        if (cache_inode->i_data.nrpages)
                truncate_inode_pages(&cache_inode->i_data, 0);

        if (cache_sb->s_op->delete_inode)
                cache_sb->s_op->delete_inode(cache_inode);

        post_smfs_inode(inode, cache_inode);

        I2CI(inode) = NULL;
        EXIT;
}

static void smfs_write_inode(struct inode *inode, int wait)
{
        struct inode *cache_inode;
        struct super_block *cache_sb;
        ENTRY;

        cache_inode = I2CI(inode);
        cache_sb = S2CSB(inode->i_sb);

        if (!cache_inode || !cache_sb)
                return;

        pre_smfs_inode(inode, cache_inode);

        if (cache_sb->s_op->write_inode)
                cache_sb->s_op->write_inode(cache_inode, wait);

        post_smfs_inode(inode, cache_inode);
        EXIT;
}

static void smfs_dirty_inode(struct inode *inode)
{
        struct inode *cache_inode;
        struct super_block *cache_sb;
        ENTRY;

        cache_inode = I2CI(inode);
        cache_sb = S2CSB(inode->i_sb);

        if (!cache_inode || !cache_sb)
                return;

        pre_smfs_inode(inode, cache_inode);
        if (cache_sb->s_op->dirty_inode)
                cache_sb->s_op->dirty_inode(cache_inode);

        post_smfs_inode(inode, cache_inode);
        EXIT;
}

static void smfs_put_inode(struct inode *inode)
{
        struct inode *cache_inode;
        struct super_block *cache_sb;
        ENTRY;

        cache_inode = I2CI(inode);
        cache_sb = S2CSB(inode->i_sb);

        if (!cache_inode || !cache_sb)
                return;
        if (cache_sb->s_op->put_inode)
                cache_sb->s_op->put_inode(cache_inode);
        EXIT;
}

static void smfs_write_super(struct super_block *sb)
{
        struct super_block *cache_sb;
        ENTRY;

        cache_sb = S2CSB(sb);
        if (!cache_sb)
                return;

        if (cache_sb->s_op->write_super)
                cache_sb->s_op->write_super(cache_sb);

        duplicate_sb(sb, cache_sb);
        EXIT;
}

static void smfs_write_super_lockfs(struct super_block *sb)
{
        struct super_block *cache_sb;
        ENTRY;

        cache_sb = S2CSB(sb);
        if (!cache_sb)
                return;

        if (cache_sb->s_op->write_super_lockfs)
                cache_sb->s_op->write_super_lockfs(cache_sb);

        duplicate_sb(sb, cache_sb);
        EXIT;
}

static void smfs_unlockfs(struct super_block *sb)
{
        struct super_block *cache_sb;
        ENTRY;

        cache_sb = S2CSB(sb);
        if (!cache_sb)
                return;

        if (cache_sb->s_op->unlockfs)
                cache_sb->s_op->unlockfs(cache_sb);

        duplicate_sb(sb, cache_sb);
        EXIT;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int smfs_statfs(struct super_block *sb, struct statfs *buf)
#else
static int smfs_statfs(struct super_block *sb, struct kstatfs *buf)
#endif
{
        struct super_block *cache_sb;
        int rc = 0;
        ENTRY;

        cache_sb = S2CSB(sb);
        if (!cache_sb)
                RETURN(-EINVAL);

        if (cache_sb->s_op->statfs)
                rc = cache_sb->s_op->statfs(cache_sb, buf);

        duplicate_sb(sb, cache_sb);

        RETURN(rc);
}

static int smfs_remount(struct super_block *sb, int *flags, char *data)
{
        struct super_block *cache_sb;
        int rc = 0;
        ENTRY;

        cache_sb = S2CSB(sb);

        if (!cache_sb)
                RETURN(-EINVAL);

        if (cache_sb->s_op->remount_fs)
                rc = cache_sb->s_op->remount_fs(cache_sb, flags, data);

        duplicate_sb(sb, cache_sb);
        RETURN(rc);
}

struct super_operations smfs_super_ops = {
        read_inode:     smfs_read_inode,
        clear_inode:    smfs_clear_inode,
        put_super:      smfs_put_super,
        delete_inode:   smfs_delete_inode,
        write_inode:    smfs_write_inode,
        dirty_inode:    smfs_dirty_inode,       /* BKL not held.  We take it */
        put_inode:      smfs_put_inode,         /* BKL not held.  Don't need */

        write_super:    smfs_write_super,       /* BKL held */
        write_super_lockfs: smfs_write_super_lockfs, /* BKL not held. Take it */
        unlockfs:       smfs_unlockfs,          /* BKL not held.  We take it */
        statfs:         smfs_statfs,            /* BKL held */
        remount_fs:     smfs_remount,           /* BKL held */
};
