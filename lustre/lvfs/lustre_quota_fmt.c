/*
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#ifdef HAVE_QUOTAIO_V1_H
# include <linux/quotaio_v1.h>
#endif

#include <asm/byteorder.h>
#include <asm/uaccess.h>

#include <lustre_quota.h>
#include <obd_support.h>
#include "lustre_quota_fmt.h"

static const uint lustre_initqversions[][MAXQUOTAS] = {
        [LUSTRE_QUOTA_V2] = LUSTRE_INITQVERSIONS_V2
};

static const int lustre_dqstrinblk[] = {
        [LUSTRE_QUOTA_V2] = LUSTRE_DQSTRINBLK_V2
};

static const int lustre_disk_dqblk_sz[] = {
        [LUSTRE_QUOTA_V2] = sizeof(struct lustre_disk_dqblk_v2)
};

static const union
{
        struct lustre_disk_dqblk_v2 r1;
} fakedquot[] = {
        [LUSTRE_QUOTA_V2] = {.r1 = {.dqb_itime = __constant_cpu_to_le64(1LLU)}}
};

static const union
{
        struct lustre_disk_dqblk_v2 r1;
} emptydquot[] = {
        [LUSTRE_QUOTA_V2] = {.r1 = { 0 }}
};

extern void *lustre_quota_journal_start(struct inode *inode, int delete);
extern void lustre_quota_journal_stop(void *handle);
extern ssize_t lustre_read_quota(struct file *f, struct inode *inode, int type,
                                 char *buf, int count, loff_t pos);
extern ssize_t lustre_write_quota(struct file *f, char *buf, int count, loff_t pos);

int check_quota_file(struct file *f, struct inode *inode, int type,
                     lustre_quota_version_t version)
{
        struct lustre_disk_dqheader dqhead;
        ssize_t size;
        static const uint quota_magics[] = LUSTRE_INITQMAGICS;
        const uint *quota_versions = lustre_initqversions[version];

        size = lustre_read_quota(f, inode, type, (char *)&dqhead,
                                 sizeof(struct lustre_disk_dqheader), 0);
        if (size != sizeof(struct lustre_disk_dqheader))
                return -EINVAL;
        if (le32_to_cpu(dqhead.dqh_magic) != quota_magics[type] ||
            le32_to_cpu(dqhead.dqh_version) != quota_versions[type])
                return -EINVAL;
        return 0;
}

/**
 * Check whether given file is really lustre admin quotafile
 */
int lustre_check_quota_file(struct lustre_quota_info *lqi, int type)
{
        struct file *f = lqi->qi_files[type];
        return check_quota_file(f, NULL, type, lqi->qi_version);
}
EXPORT_SYMBOL(lustre_check_quota_file);

int lustre_read_quota_file_info(struct file* f, struct lustre_mem_dqinfo* info)
{
        struct lustre_disk_dqinfo dinfo;
        ssize_t size;

        size = lustre_read_quota(f, NULL, 0, (char *)&dinfo,
                                 sizeof(struct lustre_disk_dqinfo),
                                 LUSTRE_DQINFOOFF);

        if (size != sizeof(struct lustre_disk_dqinfo)) {
                CDEBUG(D_ERROR, "Can't read info structure on device %s.\n",
                       f->f_vfsmnt->mnt_sb->s_id);
                return -EINVAL;
        }
        info->dqi_bgrace = le32_to_cpu(dinfo.dqi_bgrace);
        info->dqi_igrace = le32_to_cpu(dinfo.dqi_igrace);
        info->dqi_flags = le32_to_cpu(dinfo.dqi_flags);
        info->dqi_blocks = le32_to_cpu(dinfo.dqi_blocks);
        info->dqi_free_blk = le32_to_cpu(dinfo.dqi_free_blk);
        info->dqi_free_entry = le32_to_cpu(dinfo.dqi_free_entry);
        return 0;
}

/**
 * Read information header from quota file
 */
int lustre_read_quota_info(struct lustre_quota_info *lqi, int type)
{
        return lustre_read_quota_file_info(lqi->qi_files[type],
                                           &lqi->qi_info[type]);
}
EXPORT_SYMBOL(lustre_read_quota_info);

/**
 * Write information header to quota file
 */
int lustre_write_quota_info(struct lustre_quota_info *lqi, int type)
{
        struct lustre_disk_dqinfo dinfo;
        struct lustre_mem_dqinfo *info = &lqi->qi_info[type];
        struct file *f = lqi->qi_files[type];
        ssize_t size;

        info->dqi_flags &= ~DQF_INFO_DIRTY;
        dinfo.dqi_bgrace = cpu_to_le32(info->dqi_bgrace);
        dinfo.dqi_igrace = cpu_to_le32(info->dqi_igrace);
        dinfo.dqi_flags = cpu_to_le32(info->dqi_flags & DQF_MASK);
        dinfo.dqi_blocks = cpu_to_le32(info->dqi_blocks);
        dinfo.dqi_free_blk = cpu_to_le32(info->dqi_free_blk);
        dinfo.dqi_free_entry = cpu_to_le32(info->dqi_free_entry);

        size = lustre_write_quota(f, (char *)&dinfo,
                                  sizeof(struct lustre_disk_dqinfo),
                                  LUSTRE_DQINFOOFF);

        if (size != sizeof(struct lustre_disk_dqinfo)) {
                CDEBUG(D_WARNING,
                       "Can't write info structure on device %s.\n",
                       f->f_vfsmnt->mnt_sb->s_id);
                return -1;
        }
        return 0;
}
EXPORT_SYMBOL(lustre_write_quota_info);

void disk2memdqb(struct lustre_mem_dqblk *m, void *d,
                 lustre_quota_version_t version)
{
        struct lustre_disk_dqblk_v2 *dqblk = (struct lustre_disk_dqblk_v2 *)d;

        LASSERT(version == LUSTRE_QUOTA_V2);

        m->dqb_ihardlimit = le64_to_cpu(dqblk->dqb_ihardlimit);
        m->dqb_isoftlimit = le64_to_cpu(dqblk->dqb_isoftlimit);
        m->dqb_curinodes = le64_to_cpu(dqblk->dqb_curinodes);
        m->dqb_itime = le64_to_cpu(dqblk->dqb_itime);
        m->dqb_bhardlimit = le64_to_cpu(dqblk->dqb_bhardlimit);
        m->dqb_bsoftlimit = le64_to_cpu(dqblk->dqb_bsoftlimit);
        m->dqb_curspace = le64_to_cpu(dqblk->dqb_curspace);
        m->dqb_btime = le64_to_cpu(dqblk->dqb_btime);
}

static int mem2diskdqb(void *d, struct lustre_mem_dqblk *m,
                       qid_t id, lustre_quota_version_t version)
{
        struct lustre_disk_dqblk_v2 *dqblk = (struct lustre_disk_dqblk_v2 *)d;

        LASSERT(version == LUSTRE_QUOTA_V2);

        dqblk->dqb_ihardlimit = cpu_to_le64(m->dqb_ihardlimit);
        dqblk->dqb_isoftlimit = cpu_to_le64(m->dqb_isoftlimit);
        dqblk->dqb_curinodes = cpu_to_le64(m->dqb_curinodes);
        dqblk->dqb_itime = cpu_to_le64(m->dqb_itime);
        dqblk->dqb_bhardlimit = cpu_to_le64(m->dqb_bhardlimit);
        dqblk->dqb_bsoftlimit = cpu_to_le64(m->dqb_bsoftlimit);
        dqblk->dqb_curspace = cpu_to_le64(m->dqb_curspace);
        dqblk->dqb_btime = cpu_to_le64(m->dqb_btime);
        dqblk->dqb_id = cpu_to_le32(id);

        return 0;
}

dqbuf_t getdqbuf(void)
{
        dqbuf_t buf = kmalloc(LUSTRE_DQBLKSIZE, GFP_NOFS);
        if (!buf)
                CDEBUG(D_WARNING, 
                       "VFS: Not enough memory for quota buffers.\n");
        return buf;
}

void freedqbuf(dqbuf_t buf)
{
        kfree(buf);
}

ssize_t read_blk(struct file *filp, struct inode *inode, int type,
                 uint blk, dqbuf_t buf)
{
        ssize_t ret;

        memset(buf, 0, LUSTRE_DQBLKSIZE);
        ret = lustre_read_quota(filp, inode, type, (char *)buf, LUSTRE_DQBLKSIZE,
                                blk << LUSTRE_DQBLKSIZE_BITS);

        /* Reading past EOF just returns a block of zeros */
        if (ret == -EBADR)
                ret = 0;

        return ret;
}

ssize_t write_blk(struct file *filp, uint blk, dqbuf_t buf)
{
        ssize_t ret;

        ret = lustre_write_quota(filp, (char *)buf, LUSTRE_DQBLKSIZE,
                                 blk << LUSTRE_DQBLKSIZE_BITS);

        return ret;
}

void lustre_mark_info_dirty(struct lustre_mem_dqinfo *info)
{
        cfs_set_bit(DQF_INFO_DIRTY_B, &info->dqi_flags);
}

/**
 * Remove empty block from list and return it
 */
int get_free_dqblk(struct file *filp, struct lustre_mem_dqinfo *info)
{
        dqbuf_t buf = getdqbuf();
        struct lustre_disk_dqdbheader *dh =
            (struct lustre_disk_dqdbheader *)buf;
        int ret, blk;

        if (!buf)
                return -ENOMEM;
        if (info->dqi_free_blk) {
                blk = info->dqi_free_blk;
                if ((ret = read_blk(filp, NULL, 0, blk, buf)) < 0)
                        goto out_buf;
                info->dqi_free_blk = le32_to_cpu(dh->dqdh_next_free);
        } else {
                memset(buf, 0, LUSTRE_DQBLKSIZE);
                /* Assure block allocation... */
                if ((ret = write_blk(filp, info->dqi_blocks, buf)) < 0)
                        goto out_buf;
                blk = info->dqi_blocks++;
        }
        lustre_mark_info_dirty(info);
        ret = blk;
out_buf:
        freedqbuf(buf);
        return ret;
}

/**
 * Insert empty block to the list
 */
int put_free_dqblk(struct file *filp, struct lustre_mem_dqinfo *info,
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

/**
 * Remove given block from the list of blocks with free entries
 */
int remove_free_dqentry(struct file *filp,
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
                if ((err = read_blk(filp, NULL, 0, nextblk, tmpbuf)) < 0)
                        goto out_buf;
                ((struct lustre_disk_dqdbheader *)tmpbuf)->dqdh_prev_free =
                    dh->dqdh_prev_free;
                if ((err = write_blk(filp, nextblk, tmpbuf)) < 0)
                        goto out_buf;
        }
        if (prevblk) {
                if ((err = read_blk(filp, NULL, 0, prevblk, tmpbuf)) < 0)
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
        if (write_blk(filp, blk, buf) < 0)
                /* No matter whether write succeeds block is out of list */
                CDEBUG(D_ERROR, 
                       "VFS: Can't write block (%u) with free entries.\n", blk);
        return 0;
out_buf:
        freedqbuf(tmpbuf);
        return err;
}

/**
 * Insert given block to the beginning of list with free entries
 */
int insert_free_dqentry(struct file *filp,
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
                if ((err = read_blk(filp, NULL, 0, info->dqi_free_entry, tmpbuf)) < 0)
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



/**
 * Find space for dquot
 */
static uint find_free_dqentry(struct lustre_dquot *dquot, int *err, 
                              lustre_quota_version_t version)
{
        struct lustre_quota_info *lqi = dquot->dq_info;
        struct file *filp = lqi->qi_files[dquot->dq_type];
        struct lustre_mem_dqinfo *info = &lqi->qi_info[dquot->dq_type];
        uint blk, i;
        struct lustre_disk_dqdbheader *dh;
        void *ddquot;
        int dqblk_sz = lustre_disk_dqblk_sz[version];
        int dqstrinblk = lustre_dqstrinblk[version];
        dqbuf_t buf;

        *err = 0;
        if (!(buf = getdqbuf())) {
                *err = -ENOMEM;
                return 0;
        }
        dh = (struct lustre_disk_dqdbheader *)buf;
        ddquot = GETENTRIES(buf, version);
        if (info->dqi_free_entry) {
                blk = info->dqi_free_entry;
                if ((*err = read_blk(filp, NULL, 0, blk, buf)) < 0)
                        goto out_buf;
        } else {
                blk = get_free_dqblk(filp, info);
                if ((int)blk < 0) {
                        *err = blk;
                        freedqbuf(buf);
                        return 0;
                }
                memset(buf, 0, LUSTRE_DQBLKSIZE);
                info->dqi_free_entry = blk; /* This is enough as block is 
                                               already zeroed and entry list
                                               is empty... */
                lustre_mark_info_dirty(info);
        }

        /* Will block be full */
        if (le16_to_cpu(dh->dqdh_entries) + 1 >= dqstrinblk)
                if ((*err = remove_free_dqentry(filp, info, buf, blk)) < 0) {
                        CDEBUG(D_ERROR, 
                               "VFS: find_free_dqentry(): Can't remove block "
                               "(%u) from entry free list.\n", blk);
                        goto out_buf;
                }
        dh->dqdh_entries = cpu_to_le16(le16_to_cpu(dh->dqdh_entries) + 1);
        /* Find free structure in block */
        for (i = 0; i < dqstrinblk &&
             memcmp((char *)&emptydquot[version],
                    (char *)ddquot + i * dqblk_sz, dqblk_sz);
             i++);

        if (i == dqstrinblk) {
                CDEBUG(D_ERROR, 
                       "VFS: find_free_dqentry(): Data block full but it "
                       "shouldn't.\n");
                *err = -EIO;
                goto out_buf;
        }

        if ((*err = write_blk(filp, blk, buf)) < 0) {
                CDEBUG(D_ERROR,
                       "VFS: find_free_dqentry(): Can't write quota data "
                       "block %u.\n", blk);
                goto out_buf;
        }
        dquot->dq_off =
            (blk << LUSTRE_DQBLKSIZE_BITS) +
            sizeof(struct lustre_disk_dqdbheader) +
            i * dqblk_sz;
        freedqbuf(buf);
        return blk;
out_buf:
        freedqbuf(buf);
        return 0;
}

/**
 * Insert reference to structure into the trie
 */
static int do_insert_tree(struct lustre_dquot *dquot, uint * treeblk, int depth,
                          lustre_quota_version_t version)
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
                if ((ret = read_blk(filp, NULL, 0, *treeblk, buf)) < 0) {
                        CERROR("VFS: Can't read tree quota block %u.\n",
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
                        CDEBUG(D_ERROR, 
                               "VFS: Inserting already present quota entry "
                               "(block %u).\n",
                               ref[GETIDINDEX(dquot->dq_id, depth)]);
                        ret = -EIO;
                        goto out_buf;
                }

                newblk = find_free_dqentry(dquot, &ret, version);
        } else
                ret = do_insert_tree(dquot, &newblk, depth + 1, version);
        if (newson && ret >= 0) {
                ref[GETIDINDEX(dquot->dq_id, depth)] = cpu_to_le32(newblk);
                ret = write_blk(filp, *treeblk, buf);
        } else if (newact && ret < 0)
                put_free_dqblk(filp, info, buf, *treeblk);
out_buf:
        freedqbuf(buf);
        return ret;
}

/**
 * Wrapper for inserting quota structure into tree
 */
static inline int dq_insert_tree(struct lustre_dquot *dquot, 
                                 lustre_quota_version_t version)
{
        int tmp = LUSTRE_DQTREEOFF;
        return do_insert_tree(dquot, &tmp, 0, version);
}

/**
 * We don't have to be afraid of deadlocks as we never have quotas on
 * quota files...
 */
static int lustre_write_dquot(struct lustre_dquot *dquot, 
                              lustre_quota_version_t version)
{
        int type = dquot->dq_type;
        struct file *filp;
        loff_t offset;
        ssize_t ret;
        int dqblk_sz = lustre_disk_dqblk_sz[version];
        struct lustre_disk_dqblk_v2 ddquot;

        ret = mem2diskdqb(&ddquot, &dquot->dq_dqb, dquot->dq_id, version);
        if (ret < 0)
                return ret;

        if (!dquot->dq_off)
                if ((ret = dq_insert_tree(dquot, version)) < 0) {
                        CDEBUG(D_ERROR,
                               "VFS: Error %Zd occurred while creating "
                               "quota.\n", ret);
                        return ret;
                }
        filp = dquot->dq_info->qi_files[type];
        offset = dquot->dq_off;
        /* Argh... We may need to write structure full of zeroes but that would
         * be treated as an empty place by the rest of the code. Format change
         * would be definitely cleaner but the problems probably are not worth
         * it */
        if (!memcmp((char *)&emptydquot[version], (char *)&ddquot, dqblk_sz))
                ddquot.dqb_itime = cpu_to_le64(1);

        ret = lustre_write_quota(filp, (char *)&ddquot, dqblk_sz, offset);
        if (ret != dqblk_sz) {
                CDEBUG(D_WARNING, "VFS: dquota write failed on dev %s\n",
                       filp->f_dentry->d_sb->s_id);
                if (ret >= 0)
                        ret = -ENOSPC;
        } else
                ret = 0;

        return ret;
}

/**
 * Free dquot entry in data block
 */
static int free_dqentry(struct lustre_dquot *dquot, uint blk, 
                        lustre_quota_version_t version)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        struct lustre_mem_dqinfo *info =
            &dquot->dq_info->qi_info[dquot->dq_type];
        struct lustre_disk_dqdbheader *dh;
        dqbuf_t buf = getdqbuf();
        int dqstrinblk = lustre_dqstrinblk[version];
        int ret = 0;

        if (!buf)
                return -ENOMEM;
        if (dquot->dq_off >> LUSTRE_DQBLKSIZE_BITS != blk) {
                CDEBUG(D_ERROR,
                       "VFS: Quota structure has offset to other block (%u) "
                       "than it should (%u).\n",
                       blk, (uint) (dquot->dq_off >> LUSTRE_DQBLKSIZE_BITS));
                goto out_buf;
        }
        if ((ret = read_blk(filp, NULL, 0, blk, buf)) < 0) {
                CDEBUG(D_ERROR, "VFS: Can't read quota data block %u\n", blk);
                goto out_buf;
        }
        dh = (struct lustre_disk_dqdbheader *)buf;
        dh->dqdh_entries = cpu_to_le16(le16_to_cpu(dh->dqdh_entries) - 1);
        if (!le16_to_cpu(dh->dqdh_entries)) {   /* Block got free? */
                if ((ret = remove_free_dqentry(filp, info, buf, blk)) < 0 ||
                    (ret = put_free_dqblk(filp, info, buf, blk)) < 0) {
                        CDEBUG(D_ERROR,
                               "VFS: Can't move quota data block (%u) to free "
                               "list.\n", blk);
                        goto out_buf;
                }
        } else {
                memset(buf + (dquot->dq_off & ((1<<LUSTRE_DQBLKSIZE_BITS) - 1)),
                       0, lustre_disk_dqblk_sz[version]);
                if (le16_to_cpu(dh->dqdh_entries) == dqstrinblk - 1) {
                        /* Insert will write block itself */
                        if ((ret =
                             insert_free_dqentry(filp, info, buf, blk)) < 0) {
                                CDEBUG(D_ERROR,
                                       "VFS: Can't insert quota data block "
                                       "(%u) to free entry list.\n", blk);
                                goto out_buf;
                        }
                } else if ((ret = write_blk(filp, blk, buf)) < 0) {
                        CDEBUG(D_ERROR,
                               "VFS: Can't write quota data block %u\n", blk);
                        goto out_buf;
                }
        }
        dquot->dq_off = 0;      /* Quota is now unattached */
out_buf:
        freedqbuf(buf);
        return ret;
}

/**
 * Remove reference to dquot from tree
 */
static int remove_tree(struct lustre_dquot *dquot, uint * blk, int depth, 
                       lustre_quota_version_t version)
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
        if ((ret = read_blk(filp, NULL, 0, *blk, buf)) < 0) {
                CERROR("VFS: Can't read quota data block %u\n", *blk);
                goto out_buf;
        }
        newblk = le32_to_cpu(ref[GETIDINDEX(dquot->dq_id, depth)]);
        if (depth == LUSTRE_DQTREEDEPTH - 1) {
                ret = free_dqentry(dquot, newblk, version);
                newblk = 0;
        } else
                ret = remove_tree(dquot, &newblk, depth + 1, version);
        if (ret >= 0 && !newblk) {
                int i;
                ref[GETIDINDEX(dquot->dq_id, depth)] = cpu_to_le32(0);
                for (i = 0; i < LUSTRE_DQBLKSIZE && !buf[i]; i++)
                        /* Block got empty? */ ;
                /* don't put the root block into free blk list! */
                if (i == LUSTRE_DQBLKSIZE && *blk != LUSTRE_DQTREEOFF) {
                        put_free_dqblk(filp, info, buf, *blk);
                        *blk = 0;
                } else if ((ret = write_blk(filp, *blk, buf)) < 0)
                        CDEBUG(D_ERROR,
                               "VFS: Can't write quota tree block %u.\n", *blk);
        }
out_buf:
        freedqbuf(buf);
        return ret;
}

/**
 * Delete dquot from tree
 */
static int lustre_delete_dquot(struct lustre_dquot *dquot, 
                                lustre_quota_version_t version)
{
        uint tmp = LUSTRE_DQTREEOFF;

        if (!dquot->dq_off)     /* Even not allocated? */
                return 0;
        return remove_tree(dquot, &tmp, 0, version);
}

/**
 * Find entry in block
 */
static loff_t find_block_dqentry(struct lustre_dquot *dquot, uint blk, 
                                 lustre_quota_version_t version)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        int i;
        struct lustre_disk_dqblk_v2 *ddquot =
                (struct lustre_disk_dqblk_v2 *)GETENTRIES(buf, version);
        int dqblk_sz = lustre_disk_dqblk_sz[version];
        int dqstrinblk = lustre_dqstrinblk[version];

        LASSERT(version == LUSTRE_QUOTA_V2);

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, NULL, 0, blk, buf)) < 0) {
                CERROR("VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        if (dquot->dq_id)
                for (i = 0; i < dqstrinblk && 
                     le32_to_cpu(ddquot[i].dqb_id) != dquot->dq_id;
                     i++) ;
        else {                  /* ID 0 as a bit more complicated searching... */
                for (i = 0; i < dqstrinblk; i++)
                        if (!le32_to_cpu(ddquot[i].dqb_id)
                            && memcmp((char *)&emptydquot[version],
                                      (char *)&ddquot[i], dqblk_sz))
                                break;
        }
        if (i == dqstrinblk) {
                CDEBUG(D_ERROR,
                       "VFS: Quota for id %u referenced but not present.\n",
                       dquot->dq_id);
                ret = -EIO;
                goto out_buf;
        } else
                ret =
                    (blk << LUSTRE_DQBLKSIZE_BITS) +
                    sizeof(struct lustre_disk_dqdbheader) +
                    i * dqblk_sz;
out_buf:
        freedqbuf(buf);
        return ret;
}

/**
 * Find entry for given id in the tree
 */
static loff_t find_tree_dqentry(struct lustre_dquot *dquot, uint blk, int depth,
                                lustre_quota_version_t version)
{
        struct file *filp = dquot->dq_info->qi_files[dquot->dq_type];
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        u32 *ref = (u32 *) buf;

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, NULL, 0, blk, buf)) < 0) {
                CERROR("VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        ret = 0;
        blk = le32_to_cpu(ref[GETIDINDEX(dquot->dq_id, depth)]);
        if (!blk)               /* No reference? */
                goto out_buf;
        if (depth < LUSTRE_DQTREEDEPTH - 1)
                ret = find_tree_dqentry(dquot, blk, depth + 1, version);
        else
                ret = find_block_dqentry(dquot, blk, version);
out_buf:
        freedqbuf(buf);
        return ret;
}

/**
 * Find entry for given id in the tree - wrapper function
 */
static inline loff_t find_dqentry(struct lustre_dquot *dquot,
                                  lustre_quota_version_t version)
{
        return find_tree_dqentry(dquot, LUSTRE_DQTREEOFF, 0, version);
}

int lustre_read_dquot(struct lustre_dquot *dquot)
{
        int type = dquot->dq_type;
        struct file *filp;
        loff_t offset;
        int ret = 0, dqblk_sz;
        lustre_quota_version_t version;

        /* Invalidated quota? */
        if (!dquot->dq_info || !(filp = dquot->dq_info->qi_files[type])) {
                CDEBUG(D_ERROR, "VFS: Quota invalidated while reading!\n");
                return -ESRCH;
        }

        version = dquot->dq_info->qi_version;
        LASSERT(version == LUSTRE_QUOTA_V2);
        dqblk_sz = lustre_disk_dqblk_sz[version];

        offset = find_dqentry(dquot, version);
        if (offset <= 0) {      /* Entry not present? */
                if (offset < 0)
                        CDEBUG(D_ERROR,
                               "VFS: Can't read quota structure for id %u.\n",
                               dquot->dq_id);
                dquot->dq_off = 0;
                cfs_set_bit(DQ_FAKE_B, &dquot->dq_flags);
                memset(&dquot->dq_dqb, 0, sizeof(struct lustre_mem_dqblk));
                ret = offset;
        } else {
                struct lustre_disk_dqblk_v2 ddquot;

                dquot->dq_off = offset;
                if ((ret = lustre_read_quota(filp, NULL, type, (char *)&ddquot,
                                             dqblk_sz, offset)) != dqblk_sz) {
                        if (ret >= 0)
                                ret = -EIO;
                        CDEBUG(D_ERROR,
                               "VFS: Error while reading quota structure for id "
                               "%u.\n", dquot->dq_id);
                        memset((char *)&ddquot, 0, dqblk_sz);
                } else {
                        ret = 0;
                        /* We need to escape back all-zero structure */
                        if (!memcmp((char *)&fakedquot[version],
                                    (char *)&ddquot, dqblk_sz))
                                ddquot.dqb_itime = cpu_to_le64(0);
                }
                disk2memdqb(&dquot->dq_dqb, &ddquot, version);
        }

        return ret;
}
EXPORT_SYMBOL(lustre_read_dquot);

/**
 * Commit changes of dquot to disk - it might also mean deleting
 * it when quota became fake.
 */
int lustre_commit_dquot(struct lustre_dquot *dquot)
{
        int rc = 0;
        lustre_quota_version_t version = dquot->dq_info->qi_version;
        void *handle;
        struct inode *inode = dquot->dq_info->qi_files[dquot->dq_type]->f_dentry->d_inode;
        int delete = 0;

        /* always clear the flag so we don't loop on an IO error... */
        cfs_clear_bit(DQ_MOD_B, &dquot->dq_flags);

        /* The block/inode usage in admin quotafile isn't the real usage
         * over all cluster, so keep the fake dquot entry on disk is
         * meaningless, just remove it */
        if (cfs_test_bit(DQ_FAKE_B, &dquot->dq_flags))
                delete = 1;
        handle = lustre_quota_journal_start(inode, delete);
        if (unlikely(IS_ERR(handle))) {
                rc = PTR_ERR(handle);
                CERROR("fail to lustre_quota_journal_start: rc = %d\n", rc);
                return rc;
        }

        if (delete)
                rc = lustre_delete_dquot(dquot, version);
        else
                rc = lustre_write_dquot(dquot, version);
        lustre_quota_journal_stop(handle);

        if (rc < 0)
                return rc;

        if (lustre_info_dirty(&dquot->dq_info->qi_info[dquot->dq_type]))
                rc = lustre_write_quota_info(dquot->dq_info, dquot->dq_type);

        return rc;
}
EXPORT_SYMBOL(lustre_commit_dquot);

int lustre_init_quota_header(struct lustre_quota_info *lqi, int type,
                             int fakemagics)
{
        static const uint quota_magics[] = LUSTRE_INITQMAGICS;
        static const uint fake_magics[] = LUSTRE_BADQMAGICS;
        const uint* quota_versions = lustre_initqversions[lqi->qi_version];
        struct lustre_disk_dqheader dqhead;
        ssize_t size;
        struct file *fp = lqi->qi_files[type];
        int rc = 0;

        /* write quotafile header */
        dqhead.dqh_magic = cpu_to_le32(fakemagics ? 
                                       fake_magics[type] : quota_magics[type]);
        dqhead.dqh_version = cpu_to_le32(quota_versions[type]);
        size = lustre_write_quota(fp, (char *)&dqhead,
                                  sizeof(struct lustre_disk_dqheader), 0);

        if (size != sizeof(struct lustre_disk_dqheader)) {
                CDEBUG(D_ERROR, "error writing quoafile header (rc:%d)\n", rc);
                rc = size;
        }

        return rc;
}

/**
 * We need to export this function to initialize quotafile, because we haven't
 * user level check utility
 */
int lustre_init_quota_info_generic(struct lustre_quota_info *lqi, int type,
                                   int fakemagics)
{
        struct lustre_mem_dqinfo *dqinfo = &lqi->qi_info[type];
        int rc;

        rc = lustre_init_quota_header(lqi, type, fakemagics);
        if (rc)
                return rc;

        /* write init quota info */
        memset(dqinfo, 0, sizeof(*dqinfo));
        dqinfo->dqi_bgrace = MAX_DQ_TIME;
        dqinfo->dqi_igrace = MAX_IQ_TIME;
        dqinfo->dqi_blocks = LUSTRE_DQTREEOFF + 1;

        return lustre_write_quota_info(lqi, type);
}

int lustre_init_quota_info(struct lustre_quota_info *lqi, int type)
{
        return lustre_init_quota_info_generic(lqi, type, 0);
}
EXPORT_SYMBOL(lustre_init_quota_info);

static int walk_block_dqentry(struct file *filp, struct inode *inode, int type,
                              uint blk, cfs_list_t *list)
{
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        struct lustre_disk_dqdbheader *dqhead =
            (struct lustre_disk_dqdbheader *)buf;
        struct dqblk *blk_item;
        struct dqblk *pos;
        cfs_list_t *tmp;

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, inode, type, blk, buf)) < 0) {
                CERROR("VFS: Can't read quota tree block %u.\n", blk);
                goto out_buf;
        }
        ret = 0;

        if (!le32_to_cpu(dqhead->dqdh_entries))
                goto out_buf;

        if (cfs_list_empty(list)) {
                tmp = list;
                goto done;
        }

        cfs_list_for_each_entry(pos, list, link) {
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
        CFS_INIT_LIST_HEAD(&blk_item->link);

        cfs_list_add_tail(&blk_item->link, tmp);

out_buf:
        freedqbuf(buf);
        return ret;
}

int walk_tree_dqentry(struct file *filp, struct inode *inode, int type, 
                      uint blk, int depth, cfs_list_t *list)
{
        dqbuf_t buf = getdqbuf();
        loff_t ret = 0;
        int index;
        u32 *ref = (u32 *) buf;

        if (!buf)
                return -ENOMEM;
        if ((ret = read_blk(filp, inode, type, blk, buf)) < 0) {
                CERROR("VFS: Can't read quota tree block %u.\n", blk);
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

/**
 * Walk through the quota file (v2 format) to get all ids with quota limit
 */
int lustre_get_qids(struct file *fp, struct inode *inode, int type,
                    cfs_list_t *list)
{
        cfs_list_t blk_list;
        struct dqblk *blk_item, *tmp;
        dqbuf_t buf = NULL;
        struct lustre_disk_dqblk_v2 *ddquot;
        int rc;
        lustre_quota_version_t version;

        ENTRY;

        LASSERT(ergo(fp == NULL, inode != NULL));

        if (check_quota_file(fp, inode, type, LUSTRE_QUOTA_V2) == 0)
                version = LUSTRE_QUOTA_V2;
        else {
                CDEBUG(D_ERROR, "unknown quota file format!\n");
                RETURN(-EINVAL);
        }

        if (!cfs_list_empty(list)) {
                CDEBUG(D_ERROR, "not empty list\n");
                RETURN(-EINVAL);
        }

        CFS_INIT_LIST_HEAD(&blk_list);
        rc = walk_tree_dqentry(fp, inode, type, LUSTRE_DQTREEOFF, 0, &blk_list);
        if (rc) {
                CDEBUG(D_ERROR, "walk through quota file failed!(%d)\n", rc);
                GOTO(out_free, rc);
        }
        if (cfs_list_empty(&blk_list))
                RETURN(0);

        buf = getdqbuf();
        if (!buf)
                RETURN(-ENOMEM);
        ddquot = (struct lustre_disk_dqblk_v2 *)GETENTRIES(buf, version);

        cfs_list_for_each_entry(blk_item, &blk_list, link) {
                loff_t ret = 0;
                int i, dqblk_sz = lustre_disk_dqblk_sz[version];

                memset(buf, 0, LUSTRE_DQBLKSIZE);
                if ((ret = read_blk(fp, inode, type, blk_item->blk, buf)) < 0) {
                        CERROR("VFS: Can't read quota tree block %u.\n",
                               blk_item->blk);
                        GOTO(out_free, rc = ret);
                }

                for (i = 0; i < lustre_dqstrinblk[version]; i++) {
                        struct dquot_id *dqid;
                        /* skip empty entry */
                        if (!memcmp((char *)&emptydquot[version],
                                    (char *)&ddquot[i], dqblk_sz))
                                continue;

			OBD_ALLOC_GFP(dqid, sizeof(*dqid), CFS_ALLOC_NOFS);
                        if (!dqid)
                                GOTO(out_free, rc = -ENOMEM);

                        dqid->di_id    = le32_to_cpu(ddquot[i].dqb_id);
                        dqid->di_flag  = le64_to_cpu(ddquot[i].dqb_ihardlimit) ?
                                         QI_SET : 0;
                        dqid->di_flag |= le64_to_cpu(ddquot[i].dqb_bhardlimit) ?
                                         QB_SET : 0;

                        CFS_INIT_LIST_HEAD(&dqid->di_link);
                        cfs_list_add(&dqid->di_link, list);
                }
        }

out_free:
        cfs_list_for_each_entry_safe(blk_item, tmp, &blk_list, link) {
                cfs_list_del_init(&blk_item->link);
                kfree(blk_item);
        }
        if (buf)
                freedqbuf(buf);

        RETURN(rc);
}
EXPORT_SYMBOL(lustre_get_qids);
