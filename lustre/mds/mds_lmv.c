/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/mds/mds_lov.c
 *  Lustre Metadata Server (mds) handling of striped file data
 *
 *  Copyright (C) 2001-2003 Cluster File Systems, Inc.
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
#define DEBUG_SUBSYSTEM S_MDS

#include <linux/module.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/obd_lov.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_lite.h>
#include <asm/div64.h>

#include "mds_internal.h"

/*
 * TODO:
 *   - magic in mea struct
 */
int mds_md_connect(struct obd_device *obd, char *md_name)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lustre_handle conn = {0};
        int rc, value;
        __u32 valsize;
        ENTRY;

        if (IS_ERR(mds->mds_md_obd))
                RETURN(PTR_ERR(mds->mds_md_obd));

        if (mds->mds_md_connected)
                RETURN(0);

        down(&mds->mds_md_sem);
        if (mds->mds_md_connected) {
                up(&mds->mds_md_sem);
                RETURN(0);
        }

        mds->mds_md_obd = class_name2obd(md_name);
        if (!mds->mds_md_obd) {
                CERROR("MDS cannot locate MD(LMV) %s\n",
                       md_name);
                mds->mds_md_obd = ERR_PTR(-ENOTCONN);
                GOTO(err_last, rc = -ENOTCONN);
        }

        rc = obd_connect(&conn, mds->mds_md_obd, &obd->obd_uuid, NULL,
                         OBD_OPT_MDS_CONNECTION);
        if (rc) {
                CERROR("MDS cannot connect to MD(LMV) %s (%d)\n",
                       md_name, rc);
                mds->mds_md_obd = ERR_PTR(rc);
                GOTO(err_last, rc);
        }
        mds->mds_md_exp = class_conn2export(&conn);
        if (mds->mds_md_exp == NULL)
                CERROR("can't get export!\n");

        rc = obd_register_observer(mds->mds_md_obd, obd);
        if (rc) {
                CERROR("MDS cannot register as observer of MD(LMV) %s, "
                       "rc = %d\n", md_name, rc);
                GOTO(err_discon, rc);
        }

        /* retrieve size of EA */
        rc = obd_get_info(mds->mds_md_exp, strlen("mdsize"),
                          "mdsize", &valsize, &value);
        if (rc) 
                GOTO(err_reg, rc);

        if (value > mds->mds_max_mdsize)
                mds->mds_max_mdsize = value;

        /* find our number in LMV cluster */
        rc = obd_get_info(mds->mds_md_exp, strlen("mdsnum"),
                          "mdsnum", &valsize, &value);
        if (rc) 
                GOTO(err_reg, rc);
        
        mds->mds_num = value;

        rc = obd_set_info(mds->mds_md_exp, strlen("inter_mds"),
                          "inter_mds", 0, NULL);
        if (rc)
                GOTO(err_reg, rc);

        if (mds->mds_mds_sec) {
                rc = obd_set_info(mds->mds_md_exp, strlen("sec"), "sec",
                                  strlen(mds->mds_mds_sec), mds->mds_mds_sec);
                if (rc)
                        GOTO(err_reg, rc);
        }

        mds->mds_md_connected = 1;
        up(&mds->mds_md_sem);
	RETURN(0);

err_reg:
        obd_register_observer(mds->mds_md_obd, NULL);
err_discon:
        obd_disconnect(mds->mds_md_exp, 0);
        mds->mds_md_exp = NULL;
        mds->mds_md_obd = ERR_PTR(rc);
err_last:
        up(&mds->mds_md_sem);
        return rc;
}

int mds_md_postsetup(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        if (mds->mds_md_exp) {
                rc = obd_init_ea_size(mds->mds_md_exp,
                                      mds->mds_max_mdsize,
                                      mds->mds_max_cookiesize);
        }
        
        RETURN(rc);
}

int mds_md_disconnect(struct obd_device *obd, int flags)
{
        struct mds_obd *mds = &obd->u.mds;
        int rc = 0;
        ENTRY;

        if (!mds->mds_md_connected)
                RETURN(0);

        down(&mds->mds_md_sem);
        if (!IS_ERR(mds->mds_md_obd) && mds->mds_md_exp != NULL) {
                LASSERT(mds->mds_md_connected);
                
                obd_register_observer(mds->mds_md_obd, NULL);

                if (flags & OBD_OPT_FORCE) {
                        struct obd_device *lmv_obd;
                        struct obd_ioctl_data ioc_data = { 0 };
                        
                        lmv_obd = class_exp2obd(mds->mds_md_exp);
                        if (lmv_obd == NULL)
                                GOTO(out, rc = 0);

                        /* 
                         * making disconnecting lmv stuff do not send anything
                         * to all remote MDSs from LMV. This is needed to
                         * prevent possible hanging with endless recovery, when
                         * MDS sends disconnect to already disconnected
                         * target. Probably this is wrong, but client does the
                         * same in --force mode and I do not see why can't we do
                         * it here. --umka.
                         */
                        lmv_obd->obd_no_recov = 1;
                        obd_iocontrol(IOC_OSC_SET_ACTIVE, mds->mds_md_exp,
                                      sizeof(ioc_data), &ioc_data, NULL);
                }

                /*
                 * if obd_disconnect() fails (probably because the export was
                 * disconnected by class_disconnect_exports()) then we just need
                 * to drop our ref.
                 */
                mds->mds_md_connected = 0;
                rc = obd_disconnect(mds->mds_md_exp, flags);
                if (rc)
                        class_export_put(mds->mds_md_exp);

        out:
                mds->mds_md_exp = NULL;
                mds->mds_md_obd = NULL;
        }
        up(&mds->mds_md_sem);
        RETURN(rc);
}

int mds_md_reconnect(struct obd_device *obd)
{
        struct mds_obd *mds = &obd->u.mds;
        struct obd_statfs osfs;
        int err;
        ENTRY;

        /* We don't know state of connections to another MDSes
         * before the failure. If MDS we were connected to before
         * the failure gets failed, then it will wait for us to
         * reconnect and will timed recovery out. bug 4920 */
        if (mds->mds_md_connected == 0)
                RETURN(0);
        if (mds->mds_md_obd == NULL)
                RETURN(0);

        err = obd_statfs(mds->mds_md_obd, &osfs, jiffies - HZ);
        if (err)
                CERROR("can't reconnect to MDSes after recovery: %d\n", err);
        RETURN(0);
}

int mds_md_get_attr(struct obd_device *obd, struct inode *inode,
                    struct mea **mea, int *mea_size)
{
        struct mds_obd *mds = &obd->u.mds;
	int rc;
        ENTRY;

	if (!mds->mds_md_obd)
		RETURN(0);
        if (!S_ISDIR(inode->i_mode))
                RETURN(0);

	/* first calculate mea size */
        *mea_size = obd_alloc_diskmd(mds->mds_md_exp,
                                     (struct lov_mds_md **)mea);
        if (*mea_size < 0 || *mea == NULL)
                return *mea_size < 0 ? *mea_size : -EINVAL;

        rc = mds_get_md(obd, inode, *mea, mea_size, 1, 1);

	if (rc <= 0) {
		OBD_FREE(*mea, *mea_size);
		*mea = NULL;
	} else
                rc = 0;

	RETURN(rc);
}

struct dir_entry {
        __u16   namelen;
        __u16   mds;
        __u32   ino;
        __u32   generation;
        __u32   fid;
        char    name[0];
};

#define DIR_PAD			4
#define DIR_ROUND		(DIR_PAD - 1)
#define DIR_REC_LEN(name_len)	(((name_len) + 16 + DIR_ROUND) & ~DIR_ROUND)

/* this struct holds dir entries for particular MDS to be flushed */
struct dir_cache {
        struct list_head list;
        void *cur;
        int free;
        int cached;
        struct obdo oa;
        struct brw_page brwc;
};

struct dirsplit_control {
        struct obd_device *obd;
        struct inode *dir;
        struct dentry *dentry;
        struct mea *mea;
        struct dir_cache *cache;
};

static int dc_new_page_to_cache(struct dir_cache * dirc)
{
        struct page *page;

        if (!list_empty(&dirc->list) && dirc->free > sizeof(__u16)) {
                /* current page became full, mark the end */
                struct dir_entry *de = dirc->cur;
                de->namelen = 0;
        }

        page = alloc_page(GFP_KERNEL);
        if (page == NULL)
                return -ENOMEM;
        list_add_tail(&page->lru, &dirc->list);
        dirc->cur = page_address(page);
        dirc->free = PAGE_SIZE;
        return 0;
}

static int retrieve_generation_numbers(struct dirsplit_control *dc, void *buf)
{
        struct mds_obd *mds = &dc->obd->u.mds;
        struct dir_entry *de;
        struct dentry *dentry;
        char *end;
        
        end = buf + PAGE_SIZE;
        de = (struct dir_entry *) buf;
        while ((char *) de < end && de->namelen) {
                /* lookup an inode */
                LASSERT(de->namelen <= 255);
                dentry = ll_lookup_one_len(de->name, dc->dentry, 
                                           de->namelen);
                if (IS_ERR(dentry)) {
                        CERROR("can't lookup %*s: %d\n", de->namelen,
                               de->name, (int) PTR_ERR(dentry));
                        goto next;
                }
                if (dentry->d_inode != NULL) {
                        int rc;
                        struct lustre_id sid;

                        down(&dentry->d_inode->i_sem);
                        rc = mds_read_inode_sid(dc->obd,
                                                dentry->d_inode, &sid);
                        up(&dentry->d_inode->i_sem);
                        if (rc) {
                                CERROR("Can't read inode self id, "
                                       "inode %lu, rc %d\n",
                                       dentry->d_inode->i_ino, rc);
                                goto next;
                        }

                        de->fid = id_fid(&sid);
                        de->mds = mds->mds_num;
                        de->ino = dentry->d_inode->i_ino;
                        de->generation = dentry->d_inode->i_generation;
                } else if (dentry->d_flags & DCACHE_CROSS_REF) {
                        de->fid = dentry->d_fid;
                        de->ino = dentry->d_inum;
                        de->mds = dentry->d_mdsnum;
                        de->generation = dentry->d_generation;
                } else {
                        CERROR("can't lookup %*s\n", de->namelen, de->name);
                        goto next;
                }
                l_dput(dentry);

next:
                de = (struct dir_entry *)
                        ((char *) de + DIR_REC_LEN(de->namelen));
        }
        return 0;
}

static int flush_buffer_onto_mds(struct dirsplit_control *dc, int mdsnum)
{
        struct mds_obd *mds = &dc->obd->u.mds;
        struct list_head *cur, *tmp;
        struct dir_cache *ca;
        int rc;
        ENTRY; 
        ca = dc->cache + mdsnum;

        if (ca->free > sizeof(__u16)) {
                /* current page became full, mark the end */
                struct dir_entry *de = ca->cur;
                de->namelen = 0;
        }

        list_for_each_safe(cur, tmp, &ca->list) {
                struct page *page;

                page = list_entry(cur, struct page, lru);
                LASSERT(page != NULL);

                retrieve_generation_numbers(dc, page_address(page));

                ca->brwc.pg = page;
                ca->brwc.disk_offset = ca->brwc.page_offset = 0;
                ca->brwc.count = PAGE_SIZE;
                ca->brwc.flag = 0;
                ca->oa.o_mds = mdsnum;
                rc = obd_brw(OBD_BRW_WRITE, mds->mds_md_exp, &ca->oa,
                             (struct lov_stripe_md *) dc->mea,
                             1, &ca->brwc, NULL);
                if (rc)
                        RETURN(rc);

        }
        RETURN(0);
}

static int remove_entries_from_orig_dir(struct dirsplit_control *dc, int mdsnum)
{
        struct list_head *cur, *tmp;
        struct dentry *dentry;
        struct dir_cache *ca;
        struct dir_entry *de;
        struct page *page;
        char *buf, *end;
        int rc;
        ENTRY; 

        ca = dc->cache + mdsnum;
        list_for_each_safe(cur, tmp, &ca->list) {
                page = list_entry(cur, struct page, lru);
                buf = page_address(page);
                end = buf + PAGE_SIZE;

                de = (struct dir_entry *) buf;
                while ((char *) de < end && de->namelen) {
                        /* lookup an inode */
                        LASSERT(de->namelen <= 255);

                        dentry = ll_lookup_one_len(de->name, dc->dentry, 
                                                   de->namelen);
                        if (IS_ERR(dentry)) {
                                CERROR("can't lookup %*s: %d\n", de->namelen,
                                       de->name, (int) PTR_ERR(dentry));
                                goto next;
                        }
                        rc = fsfilt_del_dir_entry(dc->obd, dentry);
                        l_dput(dentry);
next:
                        de = (struct dir_entry *)
                                ((char *) de + DIR_REC_LEN(de->namelen));
                }
        }
        RETURN(0);
}

static int filldir(void * __buf, const char * name, int namlen,
                   loff_t offset, ino_t ino, unsigned int d_type)
{
        struct dirsplit_control *dc = __buf;
        struct mds_obd *mds = &dc->obd->u.mds;
        struct dir_cache *ca;
        struct dir_entry *de;
        int newmds;
        char *n;
        ENTRY;

        if (name[0] == '.' &&
            (namlen == 1 || (namlen == 2 && name[1] == '.'))) {
                /* skip special entries */
                RETURN(0);
        }

        LASSERT(dc != NULL);
        newmds = mea_name2idx(dc->mea, (char *) name, namlen);

        if (newmds == mds->mds_num) {
                /* this entry remains on the current MDS, skip moving */
                RETURN(0);
        }
        
        OBD_ALLOC(n, namlen + 1);
        memcpy(n, name, namlen);
        n[namlen] = (char) 0;
        
        OBD_FREE(n, namlen + 1);

        /* check for space in buffer for new entry */
        ca = dc->cache + newmds;
        if (DIR_REC_LEN(namlen) > ca->free) {
                int err = dc_new_page_to_cache(ca);
                LASSERT(err == 0);
        }
        
        /* insert found entry into buffer to be flushed later */
        /* NOTE: we'll fill generations number later, because we
         * it's stored in inode, thus we need to lookup an entry,
         * but directory is locked for readdir(), so we delay this */
        de = ca->cur;
        de->ino = ino;
        de->mds = d_type;
        de->namelen = namlen;
        memcpy(de->name, name, namlen);
        ca->cur += DIR_REC_LEN(namlen);
        ca->free -= DIR_REC_LEN(namlen);
        ca->cached++;

        RETURN(0);
}

int scan_and_distribute(struct obd_device *obd, struct dentry *dentry,
                        struct mea *mea)
{
        struct inode *dir = dentry->d_inode;
        struct dirsplit_control dc;
        struct file * file;
        int err, i, nlen;
        char *file_name;

        nlen = strlen("__iopen__/") + 10 + 1;
        OBD_ALLOC(file_name, nlen);
        if (!file_name)
                RETURN(-ENOMEM);
        
        i = sprintf(file_name, "__iopen__/0x%lx",
                    dentry->d_inode->i_ino);

        file = filp_open(file_name, O_RDONLY, 0);
        if (IS_ERR(file)) {
                CERROR("can't open directory %s: %d\n",
                                file_name, (int) PTR_ERR(file));
                OBD_FREE(file_name, nlen);
                RETURN(PTR_ERR(file));
        }

        memset(&dc, 0, sizeof(dc));
        dc.obd = obd;
        dc.dir = dir;
        dc.dentry = dentry;
        dc.mea = mea;
        OBD_ALLOC(dc.cache, sizeof(struct dir_cache) * mea->mea_count);
        LASSERT(dc.cache != NULL);
        for (i = 0; i < mea->mea_count; i++) {
                INIT_LIST_HEAD(&dc.cache[i].list);
                dc.cache[i].free = 0;
                dc.cache[i].cached = 0;
        }

        err = vfs_readdir(file, filldir, &dc);
        filp_close(file, 0);
        if (err)
                GOTO(cleanup, err);

        for (i = 0; i < mea->mea_count; i++) {
                if (!dc.cache[i].cached)
                        continue;
                err = flush_buffer_onto_mds(&dc, i);
                if (err)
                        GOTO(cleanup, err);
        }

        for (i = 0; i < mea->mea_count; i++) {
                if (!dc.cache[i].cached)
                        continue;
                err = remove_entries_from_orig_dir(&dc, i);
                if (err)
                        GOTO(cleanup, err);
        }

        EXIT;
cleanup:
        for (i = 0; i < mea->mea_count; i++) {
                struct list_head *cur, *tmp;
                if (!dc.cache[i].cached)
                        continue;
                list_for_each_safe(cur, tmp, &dc.cache[i].list) {
                        struct page *page;
                        page = list_entry(cur, struct page, lru);
                        list_del(&page->lru);
                        __free_page(page);
                }
        }
        OBD_FREE(dc.cache, sizeof(struct dir_cache) * mea->mea_count);
        OBD_FREE(file_name, nlen);

        return err;
}

#define MAX_DIR_SIZE      (64 * 1024)
#define I_NON_SPLITTABLE  (256)

int mds_splitting_expected(struct obd_device *obd, struct dentry *dentry)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mea *mea = NULL;
        int rc, size;

	/* clustered MD ? */
	if (!mds->mds_md_obd)
		return MDS_NO_SPLITTABLE;

        /* inode exist? */
        if (dentry->d_inode == NULL)
                return MDS_NO_SPLITTABLE;

        /* a dir can be splitted only */
        if (!S_ISDIR(dentry->d_inode->i_mode))
                return MDS_NO_SPLITTABLE;

        /* already splittied or slave directory (part of splitted dir) */
        if (dentry->d_inode->i_flags & I_NON_SPLITTABLE)
                return MDS_NO_SPLITTABLE;

        /* don't split root directory */
        if (dentry->d_inode->i_ino == id_ino(&mds->mds_rootid))
                return MDS_NO_SPLITTABLE;

        /* large enough to be splitted? */
        if (dentry->d_inode->i_size < MAX_DIR_SIZE)
                return MDS_NO_SPLIT_EXPECTED;

        mds_md_get_attr(obd, dentry->d_inode, &mea, &size);
        if (mea) {
                /* already splitted or slave object: shouldn't be splitted */
                rc = MDS_NO_SPLITTABLE;
                /* mark to skip subsequent checks */
                dentry->d_inode->i_flags |= I_NON_SPLITTABLE;
                OBD_FREE(mea, size);
        } else {
                /* may be splitted */
                rc = MDS_EXPECT_SPLIT;
        }

        return rc;
}

/*
 * must not be called on already splitted directories.
 */
int mds_try_to_split_dir(struct obd_device *obd, struct dentry *dentry,
                         struct mea **mea, int nstripes, int update_mode)
{
        struct inode *dir = dentry->d_inode;
        struct mds_obd *mds = &obd->u.mds;
        struct mea *tmea = NULL;
        struct obdo *oa = NULL;
	int rc, mea_size = 0;
        struct lustre_id id;
	void *handle;
	ENTRY;

        if (update_mode != LCK_EX)
                return 0;
        
        /* TODO: optimization possible - we already may have mea here */
        rc = mds_splitting_expected(obd, dentry);
        if (rc == MDS_NO_SPLITTABLE)
                return 0;
        if (rc == MDS_NO_SPLIT_EXPECTED && nstripes == 0)
                return 0;
        if (nstripes && nstripes == 1)
                return 0;
        
        LASSERT(mea == NULL || *mea == NULL);

        CDEBUG(D_OTHER, "%s: split directory %u/%lu/%lu\n",
               obd->obd_name, mds->mds_num, dir->i_ino,
               (unsigned long) dir->i_generation);

        if (mea == NULL)
                mea = &tmea;
        mea_size = obd_size_diskmd(mds->mds_md_exp, NULL);

        /* FIXME: Actually we may only want to allocate enough space for
         * necessary amount of stripes, but on the other hand with this
         * approach of allocating maximal possible amount of MDS slots,
         * it would be easier to split the dir over more MDSes */
        rc = obd_alloc_diskmd(mds->mds_md_exp, (void *)mea);
        if (rc < 0) {
                CERROR("obd_alloc_diskmd() failed, error %d.\n", rc);
                RETURN(rc);
        }
        if (*mea == NULL)
                RETURN(-ENOMEM);

        (*mea)->mea_count = nstripes;
       
	/* 1) create directory objects on slave MDS'es */
	/* FIXME: should this be OBD method? */
        oa = obdo_alloc();
        if (!oa)
                RETURN(-ENOMEM);

	oa->o_generation = dir->i_generation;

        obdo_from_inode(oa, dir, OBD_MD_FLTYPE | OBD_MD_FLATIME |
			OBD_MD_FLMTIME | OBD_MD_FLCTIME |
                        OBD_MD_FLUID | OBD_MD_FLGID);

        oa->o_gr = FILTER_GROUP_FIRST_MDS + mds->mds_num;
        oa->o_valid |= OBD_MD_FLID | OBD_MD_FLFLAGS | OBD_MD_FLGROUP;
        oa->o_mode = dir->i_mode;

        /* 
         * until lmv_obd_create() properly rewritten, it is important to have
         * here oa->o_id = dir->i_ino, as otherwise master object will have
         * invalid store cookie (zero inode num), what will lead to -ESTALE in
         * mds_open() or somewhere else.
         */
	oa->o_id = dir->i_ino;

        down(&dir->i_sem);
        rc = mds_read_inode_sid(obd, dir, &id);
        up(&dir->i_sem);
        if (rc) {
                CERROR("Can't read inode self id, inode %lu, "
                       "rc %d.\n", dir->i_ino, rc);
                GOTO(err_oa, rc);
        }
        oa->o_fid = id_fid(&id);
        oa->o_mds = mds->mds_num;
        LASSERT(oa->o_fid != 0);

        CDEBUG(D_OTHER, "%s: create subdirs with mode %o, uid %u, gid %u\n",
               obd->obd_name, dir->i_mode, dir->i_uid, dir->i_gid);
                        
        rc = obd_create(mds->mds_md_exp, oa, NULL, 0,
                        (struct lov_stripe_md **)mea, NULL);
        if (rc) {
                CERROR("Can't create remote inode, rc = %d\n", rc);
                GOTO(err_oa, rc);
        }

        LASSERT(id_fid(&(*mea)->mea_ids[0]));
        CDEBUG(D_OTHER, "%d dirobjects created\n", (int)(*mea)->mea_count);

	/* 2) update dir attribute */
        down(&dir->i_sem);
        
        handle = fsfilt_start(obd, dir, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle)) {
                up(&dir->i_sem);
                CERROR("fsfilt_start() failed: %d\n", (int) PTR_ERR(handle));
                GOTO(err_oa, rc = PTR_ERR(handle));
        }

	rc = fsfilt_set_md(obd, dir, handle, *mea, mea_size, EA_MEA);
        if (rc) {
                up(&dir->i_sem);
                CERROR("fsfilt_set_md() failed, error %d.\n", rc);
                GOTO(err_oa, rc);
        }
        
        rc = fsfilt_commit(obd, mds->mds_sb, dir, handle, 0);
        if (rc) {
                up(&dir->i_sem);
                CERROR("fsfilt_commit() failed, error %d.\n", rc);
                GOTO(err_oa, rc);
        }
        
	up(&dir->i_sem);
	obdo_free(oa);

	/* 3) read through the dir and distribute it over objects */
        rc = scan_and_distribute(obd, dentry, *mea);
	if (mea == &tmea)
                obd_free_diskmd(mds->mds_md_exp, (struct lov_mds_md **)mea);
        if (rc) {
                CERROR("scan_and_distribute() failed, error %d.\n", rc);
                RETURN(rc);
        }

	RETURN(1);

err_oa:
	obdo_free(oa);
        return rc;
}

static int filter_start_page_write(struct inode *inode,
                                   struct niobuf_local *lnb)
{
        struct page *page = alloc_pages(GFP_HIGHUSER, 0);
        if (page == NULL) {
                CERROR("no memory for a temp page\n");
                return lnb->rc = -ENOMEM;
        }
        POISON_PAGE(page, 0xf1);
        page->index = lnb->offset >> PAGE_SHIFT;
        lnb->page = page;
        return 0;
}

struct dentry *filter_id2dentry(struct obd_device *obd,
                                struct dentry *dir_dentry,
                                obd_gr group, obd_id id);

int mds_preprw(int cmd, struct obd_export *exp, struct obdo *oa,
                int objcount, struct obd_ioobj *obj,
                int niocount, struct niobuf_remote *nb,
                struct niobuf_local *res,
                struct obd_trans_info *oti)
{
        struct niobuf_remote *rnb;
        struct niobuf_local *lnb = NULL;
        int rc = 0, i, tot_bytes = 0;
        unsigned long now = jiffies;
        struct dentry *dentry;
        struct lustre_id id;
        ENTRY;

        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        memset(res, 0, niocount * sizeof(*res));

        id_fid(&id) = 0;
        id_group(&id) = 0;
        id_ino(&id) = obj->ioo_id;
        id_gen(&id) = obj->ioo_gr;
        
        dentry = mds_id2dentry(exp->exp_obd, &id, NULL);
        if (IS_ERR(dentry)) {
                CERROR("can't get dentry for "LPU64"/%u: %d\n",
                       id.li_stc.u.e3s.l3s_ino, id.li_stc.u.e3s.l3s_gen,
                       (int)PTR_ERR(dentry));
                GOTO(cleanup, rc = (int) PTR_ERR(dentry));
        }

        if (dentry->d_inode == NULL) {
                CERROR("trying to BRW to non-existent file "LPU64"\n",
                       obj->ioo_id);
                l_dput(dentry);
                GOTO(cleanup, rc = -ENOENT);
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow preprw_write setup %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "preprw_write setup: %lu jiffies\n",
                       (jiffies - now));

        for (i = 0, rnb = nb, lnb = res; i < obj->ioo_bufcnt;
             i++, lnb++, rnb++) {
                lnb->dentry = dentry;
                lnb->offset = rnb->offset;
                lnb->len    = rnb->len;
                lnb->flags  = rnb->flags;

                rc = filter_start_page_write(dentry->d_inode, lnb);
                if (rc) {
                        CDEBUG(rc == -ENOSPC ? D_INODE : D_ERROR, "page err %u@"
                               LPU64" %u/%u %p: rc %d\n", lnb->len, lnb->offset,
                               i, obj->ioo_bufcnt, dentry, rc);
                        while (lnb-- > res)
                                __free_pages(lnb->page, 0);
                        l_dput(dentry);
                        GOTO(cleanup, rc);
                }
                tot_bytes += lnb->len;
        }

        if (time_after(jiffies, now + 15 * HZ))
                CERROR("slow start_page_write %lus\n", (jiffies - now) / HZ);
        else
                CDEBUG(D_INFO, "start_page_write: %lu jiffies\n",
                       (jiffies - now));

        EXIT;
cleanup:
        return rc;
}

int mds_commitrw(int cmd, struct obd_export *exp, struct obdo *oa,
                 int objcount, struct obd_ioobj *obj, int niocount,
                 struct niobuf_local *res, struct obd_trans_info *oti,
                 int retcode)
{
        struct obd_device *obd = exp->exp_obd;
        struct niobuf_local *lnb;
        struct inode *inode = NULL;
        int rc = 0, i, cleanup_phase = 0, err, entries = 0;
        ENTRY;

        LASSERT(objcount == 1);
        LASSERT(current->journal_info == NULL);

        cleanup_phase = 1;
        inode = res->dentry->d_inode;

        for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++) {
                char *end, *buf;
                struct dir_entry *de;

                buf = kmap(lnb->page);
                LASSERT(buf != NULL);
                end = buf + lnb->len;
                de = (struct dir_entry *) buf;
                while ((char *) de < end && de->namelen) {
                        err = fsfilt_add_dir_entry(obd, res->dentry, de->name,
                                                   de->namelen, de->ino,
                                                   de->generation, de->mds,
                                                   de->fid);
                        if (err) {
                                CERROR("can't add dir entry %*s->%u/%u/%u"
                                       " to %lu/%u: %d\n", de->namelen,
                                       de->name, de->mds, (unsigned)de->ino,
                                       (unsigned) de->generation,
                                       res->dentry->d_inode->i_ino,
                                       res->dentry->d_inode->i_generation,
                                       err);
                                rc = err;
                                break;
                        }
                        LASSERT(err == 0);
                        de = (struct dir_entry *)
                                ((char *) de + DIR_REC_LEN(de->namelen));
                        entries++;
                }
                kunmap(lnb->page);
        }

        for (i = 0, lnb = res; i < obj->ioo_bufcnt; i++, lnb++)
                __free_page(lnb->page);
        l_dput(res->dentry);

        RETURN(rc);
}

int mds_choose_mdsnum(struct obd_device *obd, const char *name, int len, int flags,
                        struct ptlrpc_peer *peer, struct inode *parent)
{
        struct mds_obd *mds = &obd->u.mds;
        struct lmv_obd *lmv;
        int i = mds->mds_num;
        char peer_str[PTL_NALFMT_SIZE];
        if (flags & REC_REINT_CREATE) { 
                i = mds->mds_num;
        } else if (mds->mds_md_exp != NULL && peer != NULL) {
                LASSERT(parent != NULL);
                /* distribute only at root level */
                lmv = &mds->mds_md_exp->exp_obd->u.lmv;
                if (parent->i_ino != id_ino(&mds->mds_rootid)) {
                        i = mds->mds_num;
                } else {
                        __u64 nid = peer->peer_id.nid;
                        __u64 count = lmv->desc.ld_tgt_count;
                        i = do_div(nid, count);
                        CWARN("client from %s creates top dir %*s on mds #%d\n",
                              ptlrpc_peernid2str(peer,peer_str), len, name, i+1);
                }
        } else if (mds->mds_md_exp) {
                lmv = &mds->mds_md_exp->exp_obd->u.lmv;
                i = raw_name2idx(MEA_MAGIC_LAST_CHAR, lmv->desc.ld_tgt_count, name, len);
        }
        RETURN(i);
}

int mds_lock_slave_objs(struct obd_device *obd, struct dentry *dentry,
                        struct lustre_handle **rlockh)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mdc_op_data *op_data;
        struct lookup_intent it;
        struct mea *mea = NULL;
        int mea_size, rc;
        int handle_size;
        ENTRY;

        LASSERT(rlockh != NULL);
        LASSERT(dentry != NULL);
        LASSERT(dentry->d_inode != NULL);

	/* clustered MD ? */
	if (!mds->mds_md_obd)
	        RETURN(0);

        /* a dir can be splitted only */
        if (!S_ISDIR(dentry->d_inode->i_mode))
                RETURN(0);

        rc = mds_md_get_attr(obd, dentry->d_inode,
                             &mea, &mea_size);
        if (rc)
                RETURN(rc);

        if (mea == NULL)
                RETURN(0);
        
        if (mea->mea_count == 0)
                /* this is slave object */
                GOTO(cleanup, rc = 0);
                
        CDEBUG(D_OTHER, "%s: lock slaves for %lu/%lu\n",
               obd->obd_name, (unsigned long)dentry->d_inode->i_ino,
               (unsigned long)dentry->d_inode->i_generation);

        handle_size = sizeof(struct lustre_handle) *
                mea->mea_count;
        
        OBD_ALLOC(*rlockh, handle_size);
        if (*rlockh == NULL)
                GOTO(cleanup, rc = -ENOMEM);

        memset(*rlockh, 0, handle_size);
        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL) {
                OBD_FREE(*rlockh, handle_size);
                RETURN(-ENOMEM);
        }
        memset(op_data, 0, sizeof(*op_data));

        op_data->mea1 = mea;
        it.it_op = IT_UNLINK;

        OBD_ALLOC(it.d.fs_data, sizeof(struct lustre_intent_data));

        rc = md_enqueue(mds->mds_md_exp, LDLM_IBITS, &it, LCK_EX,
                        op_data, *rlockh, NULL, 0, ldlm_completion_ast,
                        mds_blocking_ast, NULL);
        OBD_FREE(op_data, sizeof(*op_data));
        OBD_FREE(it.d.fs_data, sizeof(struct lustre_intent_data));
        EXIT;
cleanup:
        OBD_FREE(mea, mea_size);
        return rc;
}

void mds_unlock_slave_objs(struct obd_device *obd, struct dentry *dentry,
                           struct lustre_handle *lockh)
{
        struct mds_obd *mds = &obd->u.mds;
        struct mea *mea = NULL;
        int mea_size, rc, i;
        ENTRY;

        if (lockh == NULL) {
                EXIT;
                return;
        }

	LASSERT(mds->mds_md_obd != NULL);
        LASSERT(S_ISDIR(dentry->d_inode->i_mode));

        rc = mds_md_get_attr(obd, dentry->d_inode, &mea, &mea_size);
        if (rc) {
                CERROR("locks are leaked\n");
                EXIT;
                return;
        }
        LASSERT(mea_size != 0);
        LASSERT(mea != NULL);
        LASSERT(mea->mea_count != 0);

        CDEBUG(D_OTHER, "%s: unlock slaves for %lu/%lu\n", obd->obd_name,
               (unsigned long) dentry->d_inode->i_ino,
               (unsigned long) dentry->d_inode->i_generation);

        for (i = 0; i < mea->mea_count; i++) {
                if (lockh[i].cookie != 0)
                        ldlm_lock_decref(lockh + i, LCK_EX);
        }

        OBD_FREE(lockh, sizeof(struct lustre_handle) * mea->mea_count);
        OBD_FREE(mea, mea_size);
        EXIT;
}

int mds_unlink_slave_objs(struct obd_device *obd, struct dentry *dentry)
{
        struct mds_obd *mds = &obd->u.mds;
        struct ptlrpc_request *req = NULL;
        struct mdc_op_data *op_data;
        struct mea *mea = NULL;
        int mea_size, rc;
        ENTRY;

	/* clustered MD ? */
	if (!mds->mds_md_obd)
	        RETURN(0);

        /* a dir can be splitted only */
        if (!S_ISDIR(dentry->d_inode->i_mode))
                RETURN(0);

        rc = mds_md_get_attr(obd, dentry->d_inode, &mea, &mea_size);
        if (rc)
                RETURN(rc);

        if (mea == NULL)
                RETURN(0);
                       
        if (mea->mea_count == 0)
                GOTO(cleanup, rc = 0);

        CDEBUG(D_OTHER, "%s: unlink slaves for %lu/%lu\n", obd->obd_name,
               (unsigned long)dentry->d_inode->i_ino,
               (unsigned long)dentry->d_inode->i_generation);

        OBD_ALLOC(op_data, sizeof(*op_data));
        if (op_data == NULL)
                RETURN(-ENOMEM);
        
        memset(op_data, 0, sizeof(*op_data));
        op_data->mea1 = mea;
        rc = md_unlink(mds->mds_md_exp, op_data, &req);
        OBD_FREE(op_data, sizeof(*op_data));
        LASSERT(req == NULL);
        EXIT;
cleanup:
        OBD_FREE(mea, mea_size);
        return rc;
}

struct ide_tracking {
        int entries;
        int empty;
};

int mds_ide_filldir(void *__buf, const char *name, int namelen,
                    loff_t offset, ino_t ino, unsigned int d_type)
{
        struct ide_tracking *it = __buf;

        if (ino == 0)
                return 0;

        it->entries++;
        if (it->entries > 2)
                goto noempty;
        if (namelen > 2)
                goto noempty;
        if (name[0] == '.' && namelen == 1)
                return 0;
        if (name[0] == '.' && name[1] == '.' && namelen == 2)
                return 0;
noempty:
        it->empty = 0;
        return -ENOTEMPTY;
}

/* checks if passed dentry points to empty dir. */
int mds_is_dir_empty(struct obd_device *obd, struct dentry *dentry)
{
        struct ide_tracking it;
        struct file * file;
        char *file_name;
        int nlen, i, rc;
        
        it.entries = 0;
        it.empty = 1;

        nlen = strlen("__iopen__/") + 10 + 1;
        OBD_ALLOC(file_name, nlen);
        if (!file_name)
                RETURN(-ENOMEM);
        
        LASSERT(dentry->d_inode != NULL);
        i = sprintf(file_name, "__iopen__/0x%lx",
                    dentry->d_inode->i_ino);

        file = filp_open(file_name, O_RDONLY, 0);
        if (IS_ERR(file)) {
                CERROR("can't open directory %s: %d\n",
                       file_name, (int) PTR_ERR(file));
                GOTO(cleanup, rc = PTR_ERR(file));
        }

        rc = vfs_readdir(file, mds_ide_filldir, &it);
        filp_close(file, 0);

        if (it.empty && rc == 0)
                rc = 1;
        else
                rc = 0;

cleanup:
        OBD_FREE(file_name, nlen);
        return rc;
}

int mds_lock_and_check_slave(int offset, struct ptlrpc_request *req,
                             struct lustre_handle *lockh)
{
        struct obd_device *obd = req->rq_export->exp_obd;
        struct dentry *dentry = NULL;
        struct lvfs_run_ctxt saved;
        int cleanup_phase = 0;
        struct mds_req_sec_desc *rsd;
        struct mds_body *body;
        struct lvfs_ucred uc;
        int rc, update_mode;
        ENTRY;

        rsd = lustre_swab_mds_secdesc(req, MDS_REQ_SECDESC_OFF);
        if (!rsd) {
                CERROR("Can't unpack security desc\n");
                GOTO(cleanup, rc = -EFAULT);
        }

        body = lustre_swab_reqbuf(req, offset, sizeof(*body),
                                  lustre_swab_mds_body);
        if (body == NULL) {
                CERROR("Can't swab mds_body\n");
                GOTO(cleanup, rc = -EFAULT);
        }
        CDEBUG(D_OTHER, "%s: check slave "DLID4"\n", obd->obd_name,
               OLID4(&body->id1));
        
        dentry = mds_id2locked_dentry(obd, &body->id1, NULL, LCK_EX,
                                      lockh, &update_mode, NULL, 0,
                                      MDS_INODELOCK_UPDATE);
        if (IS_ERR(dentry)) {
                CERROR("can't find inode: %d\n", (int) PTR_ERR(dentry));
                GOTO(cleanup, rc = PTR_ERR(dentry));
        }
        cleanup_phase = 1;

	/* 
	 * handling the case when remote MDS checks if dir is empty 
	 * before rename. But it also does it for all entries, because
	 * inode is stored here and remote MDS does not know if rename
	 * point to dir or to reg file. So we check it here. 
	 */
	if (!S_ISDIR(dentry->d_inode->i_mode))
		GOTO(cleanup, rc = 0);

        rc = mds_init_ucred(&uc, req, rsd);
        if (rc) {
                GOTO(cleanup, rc);
        }

        push_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);
	rc = mds_is_dir_empty(obd, dentry) ? 0 : -ENOTEMPTY;
        pop_ctxt(&saved, &obd->obd_lvfs_ctxt, &uc);

        mds_exit_ucred(&uc);
        EXIT;
cleanup:
        switch(cleanup_phase) {
        case 1:
                if (rc)
                        ldlm_lock_decref(lockh, LCK_EX);
                l_dput(dentry);
        default:
                break;
        }
        return rc;
}

int mds_convert_mea_ea(struct obd_device *obd, struct inode *inode,
                       struct lov_mds_md *lmm, int lmm_size)
{
        struct lov_stripe_md *lsm = NULL;
        struct mea_old *old;
        struct mea *mea;
        void *handle;
        int rc, err;
        ENTRY;

        mea = (struct mea *)lmm;
        old = (struct mea_old *)lmm;

        if (mea->mea_magic == MEA_MAGIC_LAST_CHAR ||
            mea->mea_magic == MEA_MAGIC_ALL_CHARS)
                RETURN(0);

        /*
         * making MDS try LOV EA converting in the non-LMV configuration
         * cases.
         */
        if (!obd->u.mds.mds_md_exp)
                RETURN(-EINVAL);

        CDEBUG(D_INODE, "converting MEA EA on %lu/%u from V0 to V1 (%u/%u)\n",
               inode->i_ino, inode->i_generation, old->mea_count, 
               old->mea_master);

        rc = obd_unpackmd(obd->u.mds.mds_md_exp, &lsm, lmm, lmm_size);
        if (rc < 0)
                GOTO(conv_end, rc);

        rc = obd_packmd(obd->u.mds.mds_md_exp, &lmm, lsm);
        if (rc < 0)
                GOTO(conv_free, rc);
        lmm_size = rc;

        handle = fsfilt_start(obd, inode, FSFILT_OP_SETATTR, NULL);
        if (IS_ERR(handle)) {
                rc = PTR_ERR(handle);
                GOTO(conv_free, rc);
        }

        rc = fsfilt_set_md(obd, inode, handle, lmm, lmm_size, EA_MEA);
        err = fsfilt_commit(obd, obd->u.mds.mds_sb, inode, handle, 0);
        if (!rc)
                rc = err ? err : lmm_size;
        GOTO(conv_free, rc);
conv_free:
        obd_free_memmd(obd->u.mds.mds_md_exp, &lsm);
conv_end:
        return rc;
}

