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
 * lustre/lvfs/lustre_quota_fmt.c
 *
 * Lustre administrative quota format.
 * from linux/fs/quota_v2.c
 */


#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/quotaio_v1.h>

#include <asm/byteorder.h>
#include <asm/uaccess.h>

#include <lustre_quota.h>
#include "lustre_quota_fmt.h"

typedef char *dqbuf_t;

#define GETIDINDEX(id, depth) (((id) >> ((LUSTRE_DQTREEDEPTH-(depth)-1)*8)) & 0xff)
#define GETENTRIES(buf) ((struct lustre_disk_dqblk *)(((char *)buf)+sizeof(struct lustre_disk_dqdbheader)))

static int check_quota_file(struct file *f, struct inode *inode, int type)
{
        struct lustre_disk_dqheader dqhead;
        mm_segment_t fs;
        ssize_t size;
        loff_t offset = 0;
        static const uint quota_magics[] = LUSTRE_INITQMAGICS;
        static const uint quota_versions[] = LUSTRE_INITQVERSIONS;

        if (f) {
                fs = get_fs();
                set_fs(KERNEL_DS);
                size = f->f_op->read(f, (char *)&dqhead,
                                     sizeof(struct lustre_disk_dqheader), 
                                     &offset);
                set_fs(fs);
        } else { 
#ifndef KERNEL_SUPPORTS_QUOTA_READ
                size = 0;
#else
                struct super_block *sb = inode->i_sb;
                size = sb->s_op->quota_read(sb, type, (char *)&dqhead, 
                                            sizeof(struct lustre_disk_dqheader), 0);
#endif
        }
        if (size != sizeof(struct lustre_disk_dqheader))
                return 0;
        if (le32_to_cpu(dqhead.dqh_magic) != quota_magics[type] ||
            le32_to_cpu(dqhead.dqh_version) != quota_versions[type])
                return 0;
        return 1;
}

/* Check whether given file is really lustre admin quotafile */
int lustre_check_quota_file(struct lustre_quota_info *lqi, int type)
{
        struct file *f = lqi->qi_files[type];
        return check_quota_file(f, NULL, type);
}

/* Read information header from quota file */
int lustre_read_quota_info(struct lustre_quota_info *lqi, int type)
{
        mm_segment_t fs;
        struct lustre_disk_dqinfo dinfo;
        struct lustre_mem_dqinfo *info = &lqi->qi_info[type];
        struct file *f = lqi->qi_files[type];
        ssize_t size;
        loff_t offset = LUSTRE_DQINFOOFF;

        fs = get_fs();
        set_fs(KERNEL_DS);
        size = f->f_op->read(f, (char *)&dinfo, 
                             sizeof(struct lustre_disk_dqinfo), &offset);
        set_fs(fs);
        if (size != sizeof(struct lustre_disk_dqinfo)) {
                printk(KERN_WARNING "Can't read info structure on device %s.\n",
                       f->f_vfsmnt->mnt_sb->s_id);
                return -1;
        }
        info->dqi_bgrace = le32_to_cpu(dinfo.dqi_bgrace);
        info->dqi_igrace = le32_to_cpu(dinfo.dqi_igrace);
        info->dqi_flags = le32_to_cpu(dinfo.dqi_flags);
        info->dqi_blocks = le32_to_cpu(dinfo.dqi_blocks);
        info->dqi_free_blk = le32_to_cpu(dinfo.dqi_free_blk);
        info->dqi_free_entry = le32_to_cpu(dinfo.dqi_free_entry);
        return 0;
}

/* Write information header to quota file */
int lustre_write_quota_info(struct lustre_quota_info *lqi, int type)
{
        mm_segment_t fs;
        struct lustre_disk_dqinfo dinfo;
        struct lustre_mem_dqinfo *info = &lqi->qi_info[type];
        struct file *f = lqi->qi_files[type];
        ssize_t size;
        loff_t offset = LUSTRE_DQINFOOFF;

        info->dqi_flags &= ~DQF_INFO_DIRTY;
        dinfo.dqi_bgrace = cpu_to_le32(info->dqi_bgrace);
        dinfo.dqi_igrace = cpu_to_le32(info->dqi_igrace);
        dinfo.dqi_flags = cpu_to_le32(info->dqi_flags & DQF_MASK);
        dinfo.dqi_blocks = cpu_to_le32(info->dqi_blocks);
        dinfo.dqi_free_blk = cpu_to_le32(info->dqi_free_blk);
        dinfo.dqi_free_entry = cpu_to_le32(info->dqi_free_entry);
        fs = get_fs();
        set_fs(KERNEL_DS);
        size = f->f_op->write(f, (char *)&dinfo, 
                              sizeof(struct lustre_disk_dqinfo), &offset);
        set_fs(fs);
        if (size != sizeof(struct lustre_disk_dqinfo)) {
                printk(KERN_WARNING
                       "Can't write info structure on device %s.\n",
                       f->f_vfsmnt->mnt_sb->s_id);
                return -1;
        }
        return 0;
}

static void disk2memdqb(struct mem_dqblk *m, struct lustre_disk_dqblk *d)
{
        m->dqb_ihardlimit = le32_to_cpu(d->dqb_ihardlimit);
        m->dqb_isoftlimit = le32_to_cpu(d->dqb_isoftlimit);
        m->dqb_curinodes = le32_to_cpu(d->dqb_curinodes);
        m->dqb_itime = le64_to_cpu(d->dqb_itime);
        m->dqb_bhardlimit = le32_to_cpu(d->dqb_bhardlimit);
        m->dqb_bsoftlimit = le32_to_cpu(d->dqb_bsoftlimit);
        m->dqb_curspace = le64_to_cpu(d->dqb_curspace);
        m->dqb_btime = le64_to_cpu(d->dqb_btime);
}

static void mem2diskdqb(struct lustre_disk_dqblk *d, struct mem_dqblk *m,
                        qid_t id)
{
        d->dqb_ihardlimit = cpu_to_le32(m->dqb_ihardlimit);
        d->dqb_isoftlimit = cpu_to_le32(m->dqb_isoftlimit);
        d->dqb_curinodes = cpu_to_le32(m->dqb_curinodes);
        d->dqb_itime = cpu_to_le64(m->dqb_itime);
        d->dqb_bhardlimit = cpu_to_le32(m->dqb_bhardlimit);
        d->dqb_bsoftlimit = cpu_to_le32(m->dqb_bsoftlimit);
        d->dqb_curspace = cpu_to_le64(m->dqb_curspace);
        d->dqb_btime = cpu_to_le64(m->dqb_btime);
        d->dqb_id = cpu_to_le32(id);
}

static dqbuf_t getdqbuf(void)
{
        dqbuf_t buf = kmalloc(LUSTRE_DQBLKSIZE, GFP_NOFS);
        if (!buf)
                printk(KERN_WARNING
                       "VFS: Not enough memory for quota buffers.\n");
        return buf;
}

static inline void freedqbuf(dqbuf_t buf)
{
        kfree(buf);
}

static ssize_t read_blk(struct file *filp, uint blk, dqbuf_t buf)
{
        mm_segment_t fs;
        ssize_t ret;
        loff_t offset = blk << LUSTRE_DQBLKSIZE_BITS;

        memset(buf, 0, LUSTRE_DQBLKSIZE);
        fs = get_fs();
        set_fs(KERNEL_DS);
        ret = filp->f_op->read(filp, (char *)buf, LUSTRE_DQBLKSIZE, &offset);
        set_fs(fs);
        return ret;
}

static ssize_t write_blk(struct file *filp, uint blk, dqbuf_t buf)
{
        mm_segment_t fs;
        ssize_t ret;
        loff_t offset = blk << LUSTRE_DQBLKSIZE_BITS;

        fs = get_fs();
        set_fs(KERNEL_DS);
        ret = filp->f_op->write(filp, (char *)buf, LUSTRE_DQBLKSIZE, &offset);
        set_fs(fs);
        return ret;

}

static void lustre_mark_info_dirty(struct lustre_mem_dqinfo *info)
{
        set_bit(DQF_INFO_DIRTY_B, &info->dqi_flags);
}

#define lustre_info_dirty(info) test_bit(DQF_INFO_DIRTY_B, &(info)->dqi_flags)

/* Remove empty block from list and return it */
static int get_free_dqblk(struct file *filp, struct lustre_mem_dqinfo *info)
{
        dqbuf_t buf = getdqbuf();
        struct lustre_disk_dqdbheader *dh =
            (struct lustre_disk_dqdbheader *)buf;
        int ret, blk;

        if (!buf)
                return -ENOMEM;
        if (info->dqi_free_blk) {
                blk = info->dqi_free_blk;
                if ((ret = read_blk(filp, blk, buf)) < 0)
                        goto out_buf;
                info->dqi_free_blk = le32_to_cpu(dh->dqdh_next_free);
        } else {
                memset(buf, 0, LUSTRE_DQBLKSIZE);
                if ((ret = write_blk(filp, info->dqi_blocks, buf)) < 0) /* Assure block allocation... */
                        goto out_buf;
                blk = info->dqi_blocks++;
        }
        lustre_mark_info_dirty(info);
        ret = blk;
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Insert empty block to the list */
static int put_free_dqblk(struct file *filp, struct lustre_mem_dqinfo *info,
                          dqbuf_t buf, uint blk)
{
        struct lustre_disk_dqdbheader *dh =
            (struct lustre_disk_dqdbheader *)buf;
        int err;

        dh->dqdh_next_free = cpu_to_le32(info->dqi_free_blk);
        dh->dqdh_prev_free = cpu_to_le32(0);
        dh->dqdh_entries = cpu_to_le16(0);
        info->dqi_free_blk = blk;
        lustre_mark_info_dirty(info);
        if ((err = write_blk(filp, blk, buf)) < 0)
                /* Some strange block. We had better leave it... */
                return err;
        return 0;
}

/* Remove given block from the list of blocks with free entries */
static int remove_free_dqentry(struct file *filp,
                               struct lustre_mem_dqinfo *info, dqbuf_t buf,
                               uint blk)
{
        dqbuf_t tmpbuf = getdqbuf();
        struct lustre_disk_dqdbheader *dh =
            (struct lustre_disk_dqdbheader *)buf;
        uint nextblk = le32_to_cpu(dh->dqdh_next_free), prevblk =
            le32_to_cpu(dh->dqdh_prev_free);
        int err;

        if (!tmpbuf)
                return -ENOMEM;
        if (nextblk) {
                if ((err = read_blk(filp, nextblk, tmpbuf)) < 0)
                        goto out_buf;
                ((struct lustre_disk_dqdbheader *)tmpbuf)->dqdh_prev_free =
                    dh->dqdh_prev_free;
                if ((err = write_blk(filp, nextblk, tmpbuf)) < 0)
                        goto out_buf;
        }
        if (prevblk) {
                if ((err = read_blk(filp, prevblk, tmpbuf)) < 0)
                        goto out_buf;
                ((struct lustre_disk_dqdbheader *)tmpbuf)->dqdh_next_free =
                    dh->dqdh_next_free;
                if ((err = write_blk(filp, prevblk, tmpbuf)) < 0)
                        goto out_buf;
        } else {
                info->dqi_free_entry = nextblk;
                lustre_mark_info_dirty(info);
        }
        freedqbuf(tmpbuf);
        dh->dqdh_next_free = dh->dqdh_prev_free = cpu_to_le32(0);
        if (write_blk(filp, blk, buf) < 0)      /* No matter whether write succeeds block is out of list */
                printk(KERN_ERR
                       "VFS: Can't write block (%u) with free entries.\n", blk);
        return 0;
out_buf:
        freedqbuf(tmpbuf);
        return err;
}

/* Insert given block to the beginning of list with free entries */
static int insert_free_dqentry(struct file *filp,
                               struct lustre_mem_dqinfo *info, dqbuf_t buf,
                               uint blk)
{
        dqbuf_t tmpbuf = getdqbuf();
        struct lustre_disk_dqdbheader *dh =
            (struct lustre_disk_dqdbheader *)buf;
        int err;

        if (!tmpbuf)
                return -ENOMEM;
        dh->dqdh_next_free = cpu_to_le32(info->dqi_free_entry);
        dh->dqdh_prev_free = cpu_to_le32(0);
        if ((err = write_blk(filp, blk, buf)) < 0)
                goto out_buf;
        if (info->dqi_free_entry) {
                if ((err = read_blk(filp, info->dqi_free_entry, tmpbuf)) < 0)
                        goto out_buf;
                ((struct lustre_disk_dqdbheader *)tmpbuf)->dqdh_prev_free =
                    cpu_to_le32(blk);
                if ((err = write_blk(filp, info->dqi_free_entry, tmpbuf)) < 0)
                        goto out_buf;
        }
        freedqbuf(tmpbuf);
        info->dqi_free_entry = blk;
        lustre_mark_info_dirty(info);
        return 0;
out_buf:
        freedqbuf(tmpbuf);
        return err;
}

/* Find space for dquot */
static uint find_free_dqentry(struct lustre_dquot *dquot, int *err)
{
        struct lustre_quota_info *lqi = dquot->dq_info;
        struct file *filp = lqi->qi_files[dquot->dq_type];
        struct lustre_mem_dqinfo *info = &lqi->qi_info[dquot->dq_type];
        uint blk, i;
        struct lustre_disk_dqdbheader *dh;
        struct lustre_disk_dqblk *ddquot;
        struct lustre_disk_dqblk fakedquot;
        dqbuf_t buf;

        *err = 0;
        if (!(buf = getdqbuf())) {
                *err = -ENOMEM;
                return 0;
        }
        dh = (struct lustre_disk_dqdbheader *)buf;
        ddquot = GETENTRIES(buf);
        if (info->dqi_free_entry) {
                blk = info->dqi_free_entry;
                if ((*err = read_blk(filp, blk, buf)) < 0)
                        goto out_buf;
        } else {
                blk = get_free_dqblk(filp, info);
                if ((int)blk < 0) {
                        *err = blk;
                        freedqbuf(buf);
                        return 0;
                }
                memset(buf, 0, LUSTRE_DQBLKSIZE);
                info->dqi_free_entry = blk;     /* This is enough as block is already zeroed and entry list is empty... */
                lustre_mark_info_dirty(info);
        }
        if (le16_to_cpu(dh->dqdh_entries) + 1 >= LUSTRE_DQSTRINBLK)     /* Block will be full? */
                if ((*err = remove_free_dqentry(filp, info, buf, blk)) < 0) {
                        printk(KERN_ERR
                               "VFS: find_free_dqentry(): Can't remove block (%u) from entry free list.\n",
                               blk);
                        goto out_buf;
                }
        dh->dqdh_entries = cpu_to_le16(le16_to_cpu(dh->dqdh_entries) + 1);
        memset(&fakedquot, 0, sizeof(struct lustre_disk_dqblk));
        /* Find free structure in block */
        for (i = 0; i < LUSTRE_DQSTRINBLK && 
             memcmp(&fakedquot, ddquot + i, sizeof(fakedquot)); i++) ;

        if (i == LUSTRE_DQSTRINBLK) {
                printk(KERN_ERR
                       "VFS: find_free_dqentry(): Data block full but it shouldn't.\n");
                *err = -EIO;
                goto out_buf;
        }

        if ((*err = write_blk(filp, blk, buf)) < 0) {
                printk(KERN_ERR
                       "VFS: find_free_dqentry(): Can't write quota data block %u.\n",
                       blk);
                goto out_buf;
        }
        dquot->dq_off =
            (blk << LUSTRE_DQBLKSIZE_BITS) +
            sizeof(struct lustre_disk_dqdbheader) +
            i * sizeof(struct lustre_disk_dqblk);
        freedqbuf(buf);
        return blk;
out_buf:
        freedqbuf(buf);
        return 0;
}

/* Insert reference to structure into the trie */
static int do_insert_tree(struct lustre_dquot *dquot, uint * treeblk, int depth)
{
        struct lustre_quota_info *lqi = dquot->dq_info;
        struct file *filp = lqi->qi_files[dquot->dq_type];
        struct lustre_mem_dqinfo *info = &lqi->qi_info[dquot->dq_type];
        dqbuf_t buf;
        int ret = 0, newson = 0, newact = 0;
        u32 *ref;
        uint newblk;

        if (!(buf = getdqbuf()))
                return -ENOMEM;
        if (!*treeblk) {
                ret = get_free_dqblk(filp, info);
                if (ret < 0)
                        goto out_buf;
                *treeblk = ret;
                memset(buf, 0, LUSTRE_DQBLKSIZE);
                newact = 1;
        } else {
                if ((ret = read_blk(filp, *treeblk, buf)) < 0) {
                        printk(KERN_ERR
                               "VFS: Can't read tree quota block %u.\n",
                               *treeblk);
                        goto out_buf;
                }
        }
        ref = (u32 *) buf;
        newblk = le32_to_cpu(ref[GETIDINDEX(dquot->dq_id, depth)]);
        if (!newblk)
                newson = 1;
        if (depth == LUSTRE_DQTREEDEPTH - 1) {

                if (newblk) {
                        printk(KERN_ERR
                               "VFS: Inserting already present quota entry (block %u).\n",
                               ref[GETIDINDEX(dquot->dq_id, depth)]);
                        ret = -EIO;
                        goto out_buf;
                }

                newblk = find_free_dqentry(dquot, &ret);
        } else
                ret = do_insert_tree(dquot, &newblk, depth + 1);
        if (newson && ret >= 0) {
                ref[GETIDINDEX(dquot->dq_id, depth)] = cpu_to_le32(newblk);
                ret = write_blk(filp, *treeblk, buf);
        } else if (newact && ret < 0)
                put_free_dqblk(filp, info, buf, *treeblk);
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Wrapper for inserting quota structure into tree */
static inline int dq_insert_tree(struct lustre_dquot *dquot)
{
        int tmp = LUSTRE_DQTREEOFF;
        return do_insert_tree(dquot, &tmp, 0);
}

/*
 *	We don't have to be afraid of deadlocks as we never have quotas on quota files...
 */
static int lustre_write_dquot(struct lustre_dquot *dquot)
{
        int type = dquot->dq_type;
        struct file *filp;
        mm_segment_t fs;
        loff_t offset;
        ssize_t ret;
        struct lustre_disk_dqblk ddquot, empty;

        if (!dquot->dq_off)
                if ((ret = dq_insert_tree(dquot)) < 0) {
                        printk(KERN_ERR
                               "VFS: Error %Zd occurred while creating quota.\n",
                               ret);
                        return ret;
                }
        filp = dquot->dq_info->qi_files[type];
        offset = dquot->dq_off;
        mem2diskdqb(&ddquot, &dquot->dq_dqb, dquot->dq_id);
        /* Argh... We may need to write structure full of zeroes but that would be
         * treated as an empty place by the rest of the code. Format change would
         * be definitely cleaner but the problems probably are not worth it */
        memset(&empty, 0, sizeof(struct lustre_disk_dqblk));
        if (!memcmp(&empty, &ddquot, sizeof(struct lustre_disk_dqblk)))
                ddquot.dqb_itime = cpu_to_le64(1);
        fs = get_fs();
        set_fs(KERNEL_DS);
        ret = filp->f_op->write(filp, (char *)&ddquot,
                                sizeof(struct lustre_disk_dqblk), &offset);
        set_fs(fs);
        if (ret != sizeof(struct lustre_disk_dqblk)) {
                printk(KERN_WARNING "VFS: dquota write failed on dev %s\n",
                       filp->f_dentry->d_sb->s_id);
                if (ret >= 0)
                        ret = -ENOSPC;
        } else
                ret = 0;

        return ret;
}

/* Free dquot entry in data block */
static int free_dqentry(struct lustre_dquot *dquot, uint blk)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        struct lustre_mem_dqinfo *info =
            &dquot->dq_info->qi_info[dquot->dq_type];
        struct lustre_disk_dqdbheader *dh;
        dqbuf_t buf = getdqbuf();
        int ret = 0;

        if (!buf)
                return -ENOMEM;
        if (dquot->dq_off >> LUSTRE_DQBLKSIZE_BITS != blk) {
                printk(KERN_ERR
                       "VFS: Quota structure has offset to other block (%u) than it should (%u).\n",
                       blk, (uint) (dquot->dq_off >> LUSTRE_DQBLKSIZE_BITS));
                goto out_buf;
        }
        if ((ret = read_blk(filp, blk, buf)) < 0) {
                printk(KERN_ERR "VFS: Can't read quota data block %u\n", blk);
                goto out_buf;
        }
        dh = (struct lustre_disk_dqdbheader *)buf;
        dh->dqdh_entries = cpu_to_le16(le16_to_cpu(dh->dqdh_entries) - 1);
        if (!le16_to_cpu(dh->dqdh_entries)) {   /* Block got free? */
                if ((ret = remove_free_dqentry(filp, info, buf, blk)) < 0 ||
                    (ret = put_free_dqblk(filp, info, buf, blk)) < 0) {
                        printk(KERN_ERR
                               "VFS: Can't move quota data block (%u) to free list.\n",
                               blk);
                        goto out_buf;
                }
        } else {
                memset(buf +
                       (dquot->dq_off & ((1 << LUSTRE_DQBLKSIZE_BITS) - 1)), 0,
                       sizeof(struct lustre_disk_dqblk));
                if (le16_to_cpu(dh->dqdh_entries) == LUSTRE_DQSTRINBLK - 1) {
                        /* Insert will write block itself */
                        if ((ret =
                             insert_free_dqentry(filp, info, buf, blk)) < 0) {
                                printk(KERN_ERR
                                       "VFS: Can't insert quota data block (%u) to free entry list.\n",
                                       blk);
                                goto out_buf;
                        }
                } else if ((ret = write_blk(filp, blk, buf)) < 0) {
                        printk(KERN_ERR
                               "VFS: Can't write quota data block %u\n", blk);
                        goto out_buf;
                }
        }
        dquot->dq_off = 0;      /* Quota is now unattached */
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Remove reference to dquot from tree */
static int remove_tree(struct lustre_dquot *dquot, uint * blk, int depth)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        struct lustre_mem_dqinfo *info =
            &dquot->dq_info->qi_info[dquot->dq_type];
        dqbuf_t buf = getdqbuf();
        int ret = 0;
        uint newblk;
        u32 *ref = (u32 *) buf;

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, *blk, buf)) < 0) {
                printk(KERN_ERR "VFS: Can't read quota data block %u\n", *blk);
                goto out_buf;
        }
        newblk = le32_to_cpu(ref[GETIDINDEX(dquot->dq_id, depth)]);
        if (depth == LUSTRE_DQTREEDEPTH - 1) {
                ret = free_dqentry(dquot, newblk);
                newblk = 0;
        } else
                ret = remove_tree(dquot, &newblk, depth + 1);
        if (ret >= 0 && !newblk) {
                int i;
                ref[GETIDINDEX(dquot->dq_id, depth)] = cpu_to_le32(0);
                for (i = 0; i < LUSTRE_DQBLKSIZE && !buf[i]; i++) ;     /* Block got empty? */
                /* don't put the root block into free blk list! */
                if (i == LUSTRE_DQBLKSIZE && *blk != LUSTRE_DQTREEOFF) {
                        put_free_dqblk(filp, info, buf, *blk);
                        *blk = 0;
                } else if ((ret = write_blk(filp, *blk, buf)) < 0)
                        printk(KERN_ERR
                               "VFS: Can't write quota tree block %u.\n", *blk);
        }
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Delete dquot from tree */
static int lustre_delete_dquot(struct lustre_dquot *dquot)
{
        uint tmp = LUSTRE_DQTREEOFF;

        if (!dquot->dq_off)     /* Even not allocated? */
                return 0;
        return remove_tree(dquot, &tmp, 0);
}

/* Find entry in block */
static loff_t find_block_dqentry(struct lustre_dquot *dquot, uint blk)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        int i;
        struct lustre_disk_dqblk *ddquot = GETENTRIES(buf);

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, blk, buf)) < 0) {
                printk(KERN_ERR "VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        if (dquot->dq_id)
                for (i = 0;
                     i < LUSTRE_DQSTRINBLK
                     && le32_to_cpu(ddquot[i].dqb_id) != dquot->dq_id; i++) ;
        else {                  /* ID 0 as a bit more complicated searching... */
                struct lustre_disk_dqblk fakedquot;

                memset(&fakedquot, 0, sizeof(struct lustre_disk_dqblk));
                for (i = 0; i < LUSTRE_DQSTRINBLK; i++)
                        if (!le32_to_cpu(ddquot[i].dqb_id)
                            && memcmp(&fakedquot, ddquot + i,
                                      sizeof(struct lustre_disk_dqblk)))
                                break;
        }
        if (i == LUSTRE_DQSTRINBLK) {
                printk(KERN_ERR
                       "VFS: Quota for id %u referenced but not present.\n",
                       dquot->dq_id);
                ret = -EIO;
                goto out_buf;
        } else
                ret =
                    (blk << LUSTRE_DQBLKSIZE_BITS) +
                    sizeof(struct lustre_disk_dqdbheader) +
                    i * sizeof(struct lustre_disk_dqblk);
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Find entry for given id in the tree */
static loff_t find_tree_dqentry(struct lustre_dquot *dquot, uint blk, int depth)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        u32 *ref = (u32 *) buf;

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, blk, buf)) < 0) {
                printk(KERN_ERR "VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        ret = 0;
        blk = le32_to_cpu(ref[GETIDINDEX(dquot->dq_id, depth)]);
        if (!blk)               /* No reference? */
                goto out_buf;
        if (depth < LUSTRE_DQTREEDEPTH - 1)
                ret = find_tree_dqentry(dquot, blk, depth + 1);
        else
                ret = find_block_dqentry(dquot, blk);
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Find entry for given id in the tree - wrapper function */
static inline loff_t find_dqentry(struct lustre_dquot *dquot)
{
        return find_tree_dqentry(dquot, LUSTRE_DQTREEOFF, 0);
}

int lustre_read_dquot(struct lustre_dquot *dquot)
{
        int type = dquot->dq_type;
        struct file *filp;
        mm_segment_t fs;
        loff_t offset;
        struct lustre_disk_dqblk ddquot, empty;
        int ret = 0;

        /* Invalidated quota? */
        if (!dquot->dq_info || !(filp = dquot->dq_info->qi_files[type])) {
                printk(KERN_ERR "VFS: Quota invalidated while reading!\n");
                return -EIO;
        }

        offset = find_dqentry(dquot);
        if (offset <= 0) {      /* Entry not present? */
                if (offset < 0)
                        printk(KERN_ERR
                               "VFS: Can't read quota structure for id %u.\n",
                               dquot->dq_id);
                dquot->dq_off = 0;
                set_bit(DQ_FAKE_B, &dquot->dq_flags);
                memset(&dquot->dq_dqb, 0, sizeof(struct mem_dqblk));
                ret = offset;
        } else {
                dquot->dq_off = offset;
                fs = get_fs();
                set_fs(KERNEL_DS);
                if ((ret = filp->f_op->read(filp, (char *)&ddquot,
                                            sizeof(struct lustre_disk_dqblk),
                                            &offset)) !=
                    sizeof(struct lustre_disk_dqblk)) {
                        if (ret >= 0)
                                ret = -EIO;
                        printk(KERN_ERR
                               "VFS: Error while reading quota structure for id %u.\n",
                               dquot->dq_id);
                        memset(&ddquot, 0, sizeof(struct lustre_disk_dqblk));
                } else {
                        ret = 0;
                        /* We need to escape back all-zero structure */
                        memset(&empty, 0, sizeof(struct lustre_disk_dqblk));
                        empty.dqb_itime = cpu_to_le64(1);
                        if (!memcmp(&empty, &ddquot,
                                    sizeof(struct lustre_disk_dqblk)))
                                ddquot.dqb_itime = 0;
                }
                set_fs(fs);
                disk2memdqb(&dquot->dq_dqb, &ddquot);
        }

        return ret;
}

/* Commit changes of dquot to disk - it might also mean deleting it when quota became fake */
int lustre_commit_dquot(struct lustre_dquot *dquot)
{
        int rc = 0;
        /* always clear the flag so we don't loop on an IO error... */
        clear_bit(DQ_MOD_B, &dquot->dq_flags);

        /* The block/inode usage in admin quotafile isn't the real usage
         * over all cluster, so keep the fake dquot entry on disk is
         * meaningless, just remove it */
        if (test_bit(DQ_FAKE_B, &dquot->dq_flags))
                rc = lustre_delete_dquot(dquot);
        else
                rc = lustre_write_dquot(dquot);

        if (rc < 0)
                return rc;

        if (lustre_info_dirty(&dquot->dq_info->qi_info[dquot->dq_type]))
                rc = lustre_write_quota_info(dquot->dq_info, dquot->dq_type);

        return rc;
}

/* We need to export this function to initialize quotafile, because we haven't
 * user level check utility */
int lustre_init_quota_info(struct lustre_quota_info *lqi, int type)
{
        struct lustre_mem_dqinfo *dqinfo = &lqi->qi_info[type];
        struct lustre_disk_dqheader dqhead;
        struct file *fp = lqi->qi_files[type];
        ssize_t size;
        loff_t offset = 0;
        int rc = 0;
        static const uint quota_magics[] = LUSTRE_INITQMAGICS;
        static const uint quota_versions[] = LUSTRE_INITQVERSIONS;

        /* write quotafile header */
        dqhead.dqh_magic = cpu_to_le32(quota_magics[type]);
        dqhead.dqh_version = cpu_to_le32(quota_versions[type]);
        size = fp->f_op->write(fp, (char *)&dqhead,
                               sizeof(struct lustre_disk_dqheader), &offset);

        if (size != sizeof(struct lustre_disk_dqheader)) {
                printk(KERN_ERR "error writing quoafile header (rc:%d)\n", rc);
                rc = size;
        }
        if (rc)
                return rc;

        /* write init quota info */
        memset(dqinfo, 0, sizeof(*dqinfo));
        dqinfo->dqi_bgrace = MAX_DQ_TIME;
        dqinfo->dqi_igrace = MAX_IQ_TIME;
        dqinfo->dqi_blocks = LUSTRE_DQTREEOFF + 1;

        return lustre_write_quota_info(lqi, type);
}

struct dqblk {
        struct list_head link;
        uint blk;
};

static ssize_t quota_read(struct file *file, struct inode *inode, int type,
                          uint blk, dqbuf_t buf)
{
        if (file) {
                return read_blk(file, blk, buf);
        } else {
#ifndef KERNEL_SUPPORTS_QUOTA_READ
                return -ENOTSUPP;
#else
                struct super_block *sb = inode->i_sb;
                memset(buf, 0, LUSTRE_DQBLKSIZE);
                return sb->s_op->quota_read(sb, type, (char *)buf,
                                            LUSTRE_DQBLKSIZE, 
                                            blk << LUSTRE_DQBLKSIZE_BITS);
#endif
        }
}

static int walk_block_dqentry(struct file *filp, struct inode *inode, int type,
                              uint blk, struct list_head *list)
{
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        struct lustre_disk_dqdbheader *dqhead =
            (struct lustre_disk_dqdbheader *)buf;
        struct dqblk *blk_item;
        struct dqblk *pos;
        struct list_head *tmp;

        if (!buf)
                return -ENOMEM;
        if ((ret = quota_read(filp, inode, type, blk, buf)) < 0) {
                printk(KERN_ERR "VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        ret = 0;

        if (!le32_to_cpu(dqhead->dqdh_entries))
                goto out_buf;

        if (list_empty(list)) {
                tmp = list;
                goto done;
        }

        list_for_each_entry(pos, list, link) {
                if (blk == pos->blk)    /* we got this blk already */
                        goto out_buf;
                if (blk > pos->blk)
                        continue;
                break;
        }
        tmp = &pos->link;
done:
        blk_item = kmalloc(sizeof(*blk_item), GFP_NOFS);
        if (!blk_item) {
                ret = -ENOMEM;
                goto out_buf;
        }
        blk_item->blk = blk;
        INIT_LIST_HEAD(&blk_item->link);

        list_add_tail(&blk_item->link, tmp);

out_buf:
        freedqbuf(buf);
        return ret;
}

static int walk_tree_dqentry(struct file *filp, struct inode *inode, int type, 
                             uint blk, int depth, struct list_head *list)
{
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        int index;
        u32 *ref = (u32 *) buf;

        if (!buf)
                return -ENOMEM;
        if ((ret = quota_read(filp, inode, type, blk, buf)) < 0) {
                printk(KERN_ERR "VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        ret = 0;

        for (index = 0; index <= 0xff && !ret; index++) {
                blk = le32_to_cpu(ref[index]);
                if (!blk)       /* No reference */
                        continue;

                if (depth < LUSTRE_DQTREEDEPTH - 1)
                        ret = walk_tree_dqentry(filp, inode, type, blk, 
                                                depth + 1, list);
                else
                        ret = walk_block_dqentry(filp, inode, type, blk, list);
        }
out_buf:
        freedqbuf(buf);
        return ret;
}

/* Walk through the quota file (v2 format) to get all ids with quota limit */
int lustre_get_qids(struct file *fp, struct inode *inode, int type,
                    struct list_head *list)
{
        struct list_head blk_list;
        struct dqblk *blk_item, *tmp;
        dqbuf_t buf = NULL;
        struct lustre_disk_dqblk *ddquot;
        int rc;

        if (!check_quota_file(fp, inode, type)) {
                printk(KERN_ERR "unknown quota file format!\n");
                return -EINVAL;
        }
        if (!list_empty(list)) {
                printk(KERN_ERR "not empty list\n");
                return -EINVAL;
        }

        INIT_LIST_HEAD(&blk_list);
        rc = walk_tree_dqentry(fp, inode, type, LUSTRE_DQTREEOFF, 0, &blk_list);
        if (rc) {
                printk(KERN_ERR "walk through quota file failed!(%d)\n", rc);
                goto out_free;
        }
        if (list_empty(&blk_list))
                return 0;

        buf = getdqbuf();
        if (!buf)
                return -ENOMEM;
        ddquot = GETENTRIES(buf);

        list_for_each_entry(blk_item, &blk_list, link) {
                loff_t ret = 0;
                int i;
                struct lustre_disk_dqblk fakedquot;

                memset(buf, 0, LUSTRE_DQBLKSIZE);
                if ((ret = quota_read(fp, inode, type, blk_item->blk, buf))<0) {
                        printk(KERN_ERR
                               "VFS: Can't read quota tree block %u.\n",
                               blk_item->blk);
                        rc = ret;
                        goto out_free;
                }

                memset(&fakedquot, 0, sizeof(struct lustre_disk_dqblk));
                for (i = 0; i < LUSTRE_DQSTRINBLK; i++) {
                        struct dquot_id *dqid;
                        /* skip empty entry */
                        if (!memcmp
                            (&fakedquot, ddquot + i,
                             sizeof(struct lustre_disk_dqblk)))
                                continue;

                        dqid = kmalloc(sizeof(*dqid), GFP_NOFS);
                        if (!dqid) {
                                rc = -ENOMEM;
                                goto out_free;
                        }
                        dqid->di_id = le32_to_cpu(ddquot[i].dqb_id);
                        INIT_LIST_HEAD(&dqid->di_link);
                        list_add(&dqid->di_link, list);
                }
        }

out_free:
        list_for_each_entry_safe(blk_item, tmp, &blk_list, link) {
                list_del_init(&blk_item->link);
                kfree(blk_item);
        }
        if (buf)
                freedqbuf(buf);
        return rc;
}

EXPORT_SYMBOL(lustre_check_quota_file);
EXPORT_SYMBOL(lustre_read_quota_info);
EXPORT_SYMBOL(lustre_write_quota_info);
EXPORT_SYMBOL(lustre_read_dquot);
EXPORT_SYMBOL(lustre_commit_dquot);
EXPORT_SYMBOL(lustre_init_quota_info);
EXPORT_SYMBOL(lustre_get_qids);
