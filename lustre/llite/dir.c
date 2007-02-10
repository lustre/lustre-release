/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/dir.c
 *  linux/fs/ext2/dir.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext2 directory handling functions
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *
 *  All code that works with directory layout had been switched to pagecache
 *  and moved here. AV
 *
 *  Adapted for Lustre Light
 *  Copyright (C) 2002-2003, Cluster File Systems, Inc.
 *
 */

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/version.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
# include <linux/locks.h>   // for wait_on_buffer
#else
# include <linux/buffer_head.h>   // for wait_on_buffer
#endif

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include "llite_internal.h"

typedef struct ext2_dir_entry_2 ext2_dirent;

#define PageChecked(page)        test_bit(PG_checked, &(page)->flags)
#define SetPageChecked(page)     set_bit(PG_checked, &(page)->flags)

/* returns the page unlocked, but with a reference */
static int ll_dir_readpage(struct file *file, struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct ll_fid mdc_fid;
        __u64 offset;
        struct ptlrpc_request *request;
        struct mds_body *body;
        int rc = 0;
        ENTRY;

        offset = (__u64)page->index << CFS_PAGE_SHIFT;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) off "LPU64"\n",
               inode->i_ino, inode->i_generation, inode, offset);

        mdc_pack_fid(&mdc_fid, inode->i_ino, inode->i_generation, S_IFDIR);

        rc = mdc_readpage(ll_i2sbi(inode)->ll_mdc_exp, &mdc_fid,
                          offset, page, &request);
        if (!rc) {
                body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                LASSERT(body != NULL); /* checked by mdc_readpage() */
                /* swabbed by mdc_readpage() */
                LASSERT_REPSWABBED(request, REPLY_REC_OFF);

                inode->i_size = body->size;
                SetPageUptodate(page);
        }
        ptlrpc_req_finished(request);

        unlock_page(page);
        EXIT;
        return rc;
}

struct address_space_operations ll_dir_aops = {
        .readpage  = ll_dir_readpage,
};

/*
 * ext2 uses block-sized chunks. Arguably, sector-sized ones would be
 * more robust, but we have what we have
 */
static inline unsigned ext2_chunk_size(struct inode *inode)
{
        return inode->i_sb->s_blocksize;
}

static inline void ext2_put_page(struct page *page)
{
        kunmap(page);
        page_cache_release(page);
}

static inline unsigned long dir_pages(struct inode *inode)
{
        return (inode->i_size+CFS_PAGE_SIZE-1) >> CFS_PAGE_SHIFT;
}


static void ext2_check_page(struct inode *dir, struct page *page)
{
        unsigned chunk_size = ext2_chunk_size(dir);
        char *kaddr = page_address(page);
        //      u32 max_inumber = le32_to_cpu(sb->u.ext2_sb.s_es->s_inodes_count);
        unsigned rec_len;
        __u64 offs, limit = CFS_PAGE_SIZE;
        ext2_dirent *p;
        char *error;

        if ((dir->i_size >> CFS_PAGE_SHIFT) == (__u64)page->index) {
                limit = dir->i_size & ~CFS_PAGE_MASK;
                if (limit & (chunk_size - 1)) {
                        CERROR("limit "LPU64" dir size %lld index "LPU64"\n",
                               limit, dir->i_size, (__u64)page->index);
                        goto Ebadsize;
                }
                for (offs = limit; offs < CFS_PAGE_SIZE; offs += chunk_size) {
                        ext2_dirent *p = (ext2_dirent*)(kaddr + offs);
                        p->rec_len = cpu_to_le16(chunk_size);
                        p->name_len = 0;
                        p->inode = 0;
                }
                if (!limit)
                        goto out;
        }
        for (offs = 0; offs <= limit - EXT2_DIR_REC_LEN(1); offs += rec_len) {
                p = (ext2_dirent *)(kaddr + offs);
                rec_len = le16_to_cpu(p->rec_len);

                if (rec_len < EXT2_DIR_REC_LEN(1))
                        goto Eshort;
                if (rec_len & 3)
                        goto Ealign;
                if (rec_len < EXT2_DIR_REC_LEN(p->name_len))
                        goto Enamelen;
                if (((offs + rec_len - 1) ^ offs) & ~(chunk_size-1))
                        goto Espan;
                //              if (le32_to_cpu(p->inode) > max_inumber)
                //goto Einumber;
        }
        if (offs != limit)
                goto Eend;
out:
        SetPageChecked(page);
        return;

        /* Too bad, we had an error */

Ebadsize:
        CERROR("%s: directory %lu/%u size %llu is not a multiple of %u\n",
               ll_i2mdcexp(dir)->exp_obd->obd_name, dir->i_ino,
               dir->i_generation, dir->i_size, chunk_size);
        goto fail;
Eshort:
        error = "rec_len is smaller than minimal";
        goto bad_entry;
Ealign:
        error = "unaligned directory entry";
        goto bad_entry;
Enamelen:
        error = "rec_len is too small for name_len";
        goto bad_entry;
Espan:
        error = "directory entry across blocks";
        goto bad_entry;
        //Einumber:
        // error = "inode out of bounds";
bad_entry:
        CERROR("%s: bad entry in directory %lu/%u: %s - "
               "offset="LPU64"+"LPU64", inode=%lu, rec_len=%d, name_len=%d\n",
               ll_i2mdcexp(dir)->exp_obd->obd_name, dir->i_ino,
               dir->i_generation, error, (__u64)page->index << CFS_PAGE_SHIFT,
               offs, (unsigned long)le32_to_cpu(p->inode),
               rec_len, p->name_len);
        goto fail;
Eend:
        p = (ext2_dirent *)(kaddr + offs);
        CERROR("%s: entry in directory %lu/%u spans the page boundary "
               "offset="LPU64"+"LPU64", inode=%lu\n",ll_i2mdcexp(dir)->exp_obd->obd_name,
               dir->i_ino, dir->i_generation,
               (__u64)page->index << CFS_PAGE_SHIFT,
               offs, (unsigned long)le32_to_cpu(p->inode));
fail:
        SetPageChecked(page);
        SetPageError(page);
}

static struct page *ll_get_dir_page(struct inode *dir, unsigned long n)
{
        struct ldlm_res_id res_id =
                { .name = { dir->i_ino, (__u64)dir->i_generation} };
        struct lustre_handle lockh;
        struct obd_device *obddev = class_exp2obd(ll_i2sbi(dir)->ll_mdc_exp);
        struct address_space *mapping = dir->i_mapping;
        struct page *page;
        ldlm_policy_data_t policy = {.l_inodebits = {MDS_INODELOCK_UPDATE} };
        int rc;

        rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_BLOCK_GRANTED,
                             &res_id, LDLM_IBITS, &policy, LCK_CR, &lockh);
        if (!rc) {
                struct lookup_intent it = { .it_op = IT_READDIR };
                struct ptlrpc_request *request;
                struct mdc_op_data data;

                ll_prepare_mdc_op_data(&data, dir, NULL, NULL, 0, 0);

                rc = mdc_enqueue(ll_i2sbi(dir)->ll_mdc_exp, LDLM_IBITS, &it,
                                 LCK_CR, &data, &lockh, NULL, 0,
                                 ldlm_completion_ast, ll_mdc_blocking_ast, dir,
                                 0);

                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: rc: %d\n", rc);
                        return ERR_PTR(rc);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        page = read_cache_page(mapping, n,
                               (filler_t*)mapping->a_ops->readpage, NULL);
        if (IS_ERR(page))
                GOTO(out_unlock, page);

        wait_on_page(page);
        (void)kmap(page);
        if (!PageUptodate(page))
                goto fail;
        if (!PageChecked(page))
                ext2_check_page(dir, page);
        if (PageError(page))
                goto fail;

out_unlock:
        ldlm_lock_decref(&lockh, LCK_CR);
        return page;

fail:
        ext2_put_page(page);
        page = ERR_PTR(-EIO);
        goto out_unlock;
}

/*
 * p is at least 6 bytes before the end of page
 */
static inline ext2_dirent *ext2_next_entry(ext2_dirent *p)
{
        return (ext2_dirent *)((char*)p + le16_to_cpu(p->rec_len));
}

static inline unsigned
ext2_validate_entry(char *base, unsigned offset, unsigned mask)
{
        ext2_dirent *de = (ext2_dirent*)(base + offset);
        ext2_dirent *p = (ext2_dirent*)(base + (offset&mask));
        while ((char*)p < (char*)de)
                p = ext2_next_entry(p);
        return (char *)p - base;
}

static unsigned char ext2_filetype_table[EXT2_FT_MAX] = {
        [EXT2_FT_UNKNOWN]       DT_UNKNOWN,
        [EXT2_FT_REG_FILE]      DT_REG,
        [EXT2_FT_DIR]           DT_DIR,
        [EXT2_FT_CHRDEV]        DT_CHR,
        [EXT2_FT_BLKDEV]        DT_BLK,
        [EXT2_FT_FIFO]          DT_FIFO,
        [EXT2_FT_SOCK]          DT_SOCK,
        [EXT2_FT_SYMLINK]       DT_LNK,
};


int ll_readdir(struct file *filp, void *dirent, filldir_t filldir)
{
        struct inode *inode = filp->f_dentry->d_inode;
        loff_t pos = filp->f_pos;
        // XXX struct super_block *sb = inode->i_sb;
        __u64 offset = pos & ~CFS_PAGE_MASK;
        __u64 n = pos >> CFS_PAGE_SHIFT;
        unsigned long npages = dir_pages(inode);
        unsigned chunk_mask = ~(ext2_chunk_size(inode)-1);
        unsigned char *types = ext2_filetype_table;
        int need_revalidate = (filp->f_version != inode->i_version);
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) pos %llu/%llu\n",
               inode->i_ino, inode->i_generation, inode, pos, inode->i_size);

        if (pos > inode->i_size - EXT2_DIR_REC_LEN(1))
                RETURN(0);

        for ( ; n < npages; n++, offset = 0) {
                char *kaddr, *limit;
                ext2_dirent *de;
                struct page *page;

                CDEBUG(D_EXT2,"read %lu of dir %lu/%u page "LPU64"/%lu "
                       "size %llu\n",
                       CFS_PAGE_SIZE, inode->i_ino, inode->i_generation,
                       n, npages, inode->i_size);
                page = ll_get_dir_page(inode, n);

                /* size might have been updated by mdc_readpage */
                npages = dir_pages(inode);

                if (IS_ERR(page)) {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir %lu/%u page "LPU64": rc %d\n",
                               inode->i_ino, inode->i_generation, n, rc);
                        continue;
                }

                kaddr = page_address(page);
                if (need_revalidate) {
                        /* page already checked from ll_get_dir_page() */
                        offset = ext2_validate_entry(kaddr, offset, chunk_mask);
                        need_revalidate = 0;
                }
                de = (ext2_dirent *)(kaddr+offset);
                limit = kaddr + CFS_PAGE_SIZE - EXT2_DIR_REC_LEN(1);
                for ( ;(char*)de <= limit; de = ext2_next_entry(de)) {
                        if (de->inode) {
                                int over;

                                rc = 0; /* no error if we return something */

                                offset = (char *)de - kaddr;
                                over = filldir(dirent, de->name, de->name_len,
                                               (n << CFS_PAGE_SHIFT) | offset,
                                               le32_to_cpu(de->inode),
                                               types[de->file_type &
                                                     (EXT2_FT_MAX - 1)]);
                                if (over) {
                                        ext2_put_page(page);
                                        GOTO(done, rc);
                                }
                        }
                }
                ext2_put_page(page);
        }

done:
        filp->f_pos = (n << CFS_PAGE_SHIFT) | offset;
        filp->f_version = inode->i_version;
        touch_atime(filp->f_vfsmnt, filp->f_dentry);

        RETURN(rc);
}

#define QCTL_COPY(out, in)              \
do {                                    \
        Q_COPY(out, in, qc_cmd);        \
        Q_COPY(out, in, qc_type);       \
        Q_COPY(out, in, qc_id);         \
        Q_COPY(out, in, qc_stat);       \
        Q_COPY(out, in, qc_dqinfo);     \
        Q_COPY(out, in, qc_dqblk);      \
} while (0)

int ll_dir_setstripe(struct inode *inode, struct lov_user_md *lump)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct mdc_op_data data;
        struct ptlrpc_request *req = NULL;

        struct iattr attr = { 0 };
        int rc = 0;

        /*
         * This is coming from userspace, so should be in
         * local endian.  But the MDS would like it in little
         * endian, so we swab it before we send it.
         */
        if (lump->lmm_magic != LOV_USER_MAGIC)
                RETURN(-EINVAL);

        if (lump->lmm_magic != cpu_to_le32(LOV_USER_MAGIC))
                lustre_swab_lov_user_md(lump);

        ll_prepare_mdc_op_data(&data, inode, NULL, NULL, 0, 0);

        /* swabbing is done in lov_setstripe() on server side */
        rc = mdc_setattr(sbi->ll_mdc_exp, &data,
                         &attr, lump, sizeof(*lump), NULL, 0, &req);
        if (rc) {
                ptlrpc_req_finished(req);
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("mdc_setattr fails: rc = %d\n", rc);
                return rc;
        }
        ptlrpc_req_finished(req);

        return rc;

}

int ll_dir_getstripe(struct inode *inode, struct lov_mds_md **lmmp, 
                     int *lmm_size, struct ptlrpc_request **request) 
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_fid     fid;
        struct mds_body   *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        int rc, lmmsize;

        ll_inode2fid(&fid, inode);

        rc = ll_get_max_mdsize(sbi, &lmmsize);
        if (rc)
                RETURN(rc);

        rc = mdc_getattr(sbi->ll_mdc_exp, &fid,
                        OBD_MD_FLEASIZE|OBD_MD_FLDIREA,
                        lmmsize, &req);
        if (rc < 0) {
                CDEBUG(D_INFO, "mdc_getattr failed on inode "
                       "%lu/%u: rc %d\n", inode->i_ino,
                       inode->i_generation, rc);
                GOTO(out, rc);
        }
        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF,
                        sizeof(*body));
        LASSERT(body != NULL); /* checked by mdc_getattr_name */
        /* swabbed by mdc_getattr_name */
        LASSERT_REPSWABBED(req, REPLY_REC_OFF);

        lmmsize = body->eadatasize;

        if (!(body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
            lmmsize == 0) {
                GOTO(out, rc = -ENODATA);
        }

        lmm = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1, lmmsize);
        LASSERT(lmm != NULL);
        LASSERT_REPSWABBED(req, REPLY_REC_OFF + 1);

        /*
         * This is coming from the MDS, so is probably in
         * little endian.  We convert it to host endian before
         * passing it to userspace.
         */
        if (lmm->lmm_magic == __swab32(LOV_MAGIC)) {
                lustre_swab_lov_user_md((struct lov_user_md *)lmm);
                lustre_swab_lov_user_md_objects((struct lov_user_md *)lmm);
        }
out:
        *lmmp = lmm;
        *lmm_size = lmmsize;
        *request = req;
        return rc;
}

static int ll_dir_ioctl(struct inode *inode, struct file *file,
                        unsigned int cmd, unsigned long arg)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct obd_ioctl_data *data;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p), cmd=%#x\n",
               inode->i_ino, inode->i_generation, inode, cmd);

        /* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
        if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
                return -ENOTTY;

        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_IOCTL);
        switch(cmd) {
        case EXT3_IOC_GETFLAGS:
        case EXT3_IOC_SETFLAGS:
                RETURN(ll_iocontrol(inode, file, cmd, arg));
        case EXT3_IOC_GETVERSION_OLD:
        case EXT3_IOC_GETVERSION:
                RETURN(put_user(inode->i_generation, (int *)arg));
        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case EXT3_IOC_SETVERSION_OLD:
        case EXT3_IOC_SETVERSION:
        */
        case IOC_MDC_LOOKUP: {
                struct ptlrpc_request *request = NULL;
                struct ll_fid fid;
                char *buf = NULL;
                char *filename;
                int namelen, rc, len = 0;

                rc = obd_ioctl_getdata(&buf, &len, (void *)arg);
                if (rc)
                        RETURN(rc);
                data = (void *)buf;

                filename = data->ioc_inlbuf1;
                namelen = data->ioc_inllen1;

                if (namelen < 1) {
                        CDEBUG(D_INFO, "IOC_MDC_LOOKUP missing filename\n");
                        GOTO(out, rc = -EINVAL);
                }

                ll_inode2fid(&fid, inode);
                rc = mdc_getattr_name(sbi->ll_mdc_exp, &fid, filename, namelen,
                                      OBD_MD_FLID, 0, &request);
                if (rc < 0) {
                        CDEBUG(D_INFO, "mdc_getattr_name: %d\n", rc);
                        GOTO(out, rc);
                }

                ptlrpc_req_finished(request);

                EXIT;
        out:
                obd_ioctl_freedata(buf, len);
                return rc;
        }
        case LL_IOC_LOV_SETSTRIPE: {
                struct lov_user_md lum, *lump = (struct lov_user_md *)arg;
                int rc = 0;

                LASSERT(sizeof(lum) == sizeof(*lump));
                LASSERT(sizeof(lum.lmm_objects[0]) ==
                        sizeof(lump->lmm_objects[0]));
                rc = copy_from_user(&lum, lump, sizeof(lum));
                if (rc)
                        return(-EFAULT);

                rc = ll_dir_setstripe(inode, &lum);

                return rc;
        }
        case LL_IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));
        case LL_IOC_LOV_GETSTRIPE:
        case LL_IOC_MDC_GETINFO:
        case IOC_MDC_GETFILEINFO:
        case IOC_MDC_GETFILESTRIPE: {
                struct ptlrpc_request *request = NULL;
                struct mds_body *body;
                struct lov_user_md *lump;
                struct lov_mds_md *lmm = NULL;
                char *filename = NULL;
                int rc, lmmsize;

                if (cmd == IOC_MDC_GETFILEINFO ||
                    cmd == IOC_MDC_GETFILESTRIPE) {
                        filename = getname((const char *)arg);
                        if (IS_ERR(filename))
                                RETURN(PTR_ERR(filename));

                        rc = ll_lov_getstripe_ea_info(inode, filename, &lmm, 
                                                      &lmmsize, &request);
                } else {
                        rc = ll_dir_getstripe(inode, &lmm, &lmmsize, &request);
                }

                if (request) {
                        body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                              sizeof(*body));
                        LASSERT(body != NULL); /* checked by mdc_getattr_name */
                        /* swabbed by mdc_getattr_name */
                        LASSERT_REPSWABBED(request, REPLY_REC_OFF);
                } else {
                        GOTO(out_req, rc);
                }

                if (rc < 0) {
                        if (rc == -ENODATA && (cmd == IOC_MDC_GETFILEINFO || 
                                               cmd == LL_IOC_MDC_GETINFO))
                                GOTO(skip_lmm, rc = 0);
                        else
                                GOTO(out_req, rc);
                }

                if (cmd == IOC_MDC_GETFILESTRIPE ||
                    cmd == LL_IOC_LOV_GETSTRIPE) {
                        lump = (struct lov_user_md *)arg;
                } else {
                        struct lov_user_mds_data *lmdp;
                        lmdp = (struct lov_user_mds_data *)arg;
                        lump = &lmdp->lmd_lmm;
                }
                rc = copy_to_user(lump, lmm, lmmsize);
                if (rc)
                        GOTO(out_lmm, rc = -EFAULT);
        skip_lmm:
                if (cmd == IOC_MDC_GETFILEINFO || cmd == LL_IOC_MDC_GETINFO) {
                        struct lov_user_mds_data *lmdp;
                        lstat_t st = { 0 };

                        st.st_dev     = inode->i_sb->s_dev;
                        st.st_mode    = body->mode;
                        st.st_nlink   = body->nlink;
                        st.st_uid     = body->uid;
                        st.st_gid     = body->gid;
                        st.st_rdev    = body->rdev;
                        st.st_size    = body->size;
                        st.st_blksize = CFS_PAGE_SIZE;
                        st.st_blocks  = body->blocks;
                        st.st_atime   = body->atime;
                        st.st_mtime   = body->mtime;
                        st.st_ctime   = body->ctime;
                        st.st_ino     = body->ino;

                        lmdp = (struct lov_user_mds_data *)arg;
                        rc = copy_to_user(&lmdp->lmd_st, &st, sizeof(st));
                        if (rc)
                                GOTO(out_lmm, rc = -EFAULT);
                }

                EXIT;
        out_lmm:
                if (lmm && lmm->lmm_magic == LOV_MAGIC_JOIN)
                        OBD_FREE(lmm, lmmsize);
        out_req:
                ptlrpc_req_finished(request);
                if (filename)
                        putname(filename);
                return rc;
        }
        case IOC_LOV_GETINFO: {
                struct lov_user_mds_data *lumd;
                struct lov_stripe_md *lsm;
                struct lov_user_md *lum;
                struct lov_mds_md *lmm;
                int lmmsize;
                lstat_t st;
                int rc;

                lumd = (struct lov_user_mds_data *)arg;
                lum = &lumd->lmd_lmm;

                rc = ll_get_max_mdsize(sbi, &lmmsize);
                if (rc)
                        RETURN(rc);

                OBD_ALLOC(lmm, lmmsize);
                rc = copy_from_user(lmm, lum, lmmsize);
                if (rc)
                        GOTO(free_lmm, rc = -EFAULT);

                rc = obd_unpackmd(sbi->ll_osc_exp, &lsm, lmm, lmmsize);
                if (rc < 0)
                        GOTO(free_lmm, rc = -ENOMEM);

                rc = obd_checkmd(sbi->ll_osc_exp, sbi->ll_mdc_exp, lsm);
                if (rc)
                        GOTO(free_lsm, rc);

                /* Perform glimpse_size operation. */
                memset(&st, 0, sizeof(st));

                rc = ll_glimpse_ioctl(sbi, lsm, &st);
                if (rc)
                        GOTO(free_lsm, rc);

                rc = copy_to_user(&lumd->lmd_st, &st, sizeof(st));
                if (rc)
                        GOTO(free_lsm, rc = -EFAULT);

                EXIT;
        free_lsm:
                obd_free_memmd(sbi->ll_osc_exp, &lsm);
        free_lmm:
                OBD_FREE(lmm, lmmsize);
                return rc;
        }
        case OBD_IOC_LLOG_CATINFO: {
                struct ptlrpc_request *req = NULL;
                char *buf = NULL;
                int rc, len = 0;
                char *bufs[3] = { NULL }, *str;
                int lens[3] = { sizeof(struct ptlrpc_body) };
                int size[2] = { sizeof(struct ptlrpc_body) };

                rc = obd_ioctl_getdata(&buf, &len, (void *)arg);
                if (rc)
                        RETURN(rc);
                data = (void *)buf;

                if (!data->ioc_inlbuf1) {
                        obd_ioctl_freedata(buf, len);
                        RETURN(-EINVAL);
                }

                lens[REQ_REC_OFF] = data->ioc_inllen1;
                bufs[REQ_REC_OFF] = data->ioc_inlbuf1;
                if (data->ioc_inllen2) {
                        lens[REQ_REC_OFF + 1] = data->ioc_inllen2;
                        bufs[REQ_REC_OFF + 1] = data->ioc_inlbuf2;
                } else {
                        lens[REQ_REC_OFF + 1] = 0;
                        bufs[REQ_REC_OFF + 1] = NULL;
                }

                req = ptlrpc_prep_req(sbi2mdc(sbi)->cl_import,
                                      LUSTRE_LOG_VERSION, LLOG_CATINFO, 3, lens,
                                      bufs);
                if (!req)
                        GOTO(out_catinfo, rc = -ENOMEM);

                size[REPLY_REC_OFF] = data->ioc_plen1;
                ptlrpc_req_set_repsize(req, 2, size);

                rc = ptlrpc_queue_wait(req);
                str = lustre_msg_string(req->rq_repmsg, REPLY_REC_OFF,
                                        data->ioc_plen1);
                if (!rc)
                        rc = copy_to_user(data->ioc_pbuf1, str,data->ioc_plen1);
                ptlrpc_req_finished(req);
        out_catinfo:
                obd_ioctl_freedata(buf, len);
                RETURN(rc);
        }
        case OBD_IOC_QUOTACHECK: {
                struct obd_quotactl *oqctl;
                int rc, error = 0;

                if (!capable(CAP_SYS_ADMIN))
                        RETURN(-EPERM);

                OBD_ALLOC_PTR(oqctl);
                if (!oqctl)
                        RETURN(-ENOMEM);
                oqctl->qc_type = arg;
                rc = obd_quotacheck(sbi->ll_mdc_exp, oqctl);
                if (rc < 0) {
                        CDEBUG(D_INFO, "mdc_quotacheck failed: rc %d\n", rc);
                        error = rc;
                }

                rc = obd_quotacheck(sbi->ll_osc_exp, oqctl);
                if (rc < 0)
                        CDEBUG(D_INFO, "osc_quotacheck failed: rc %d\n", rc);

                OBD_FREE_PTR(oqctl);
                return error ?: rc;
        }
        case OBD_IOC_POLL_QUOTACHECK: {
                struct if_quotacheck *check;
                int rc;

                if (!capable(CAP_SYS_ADMIN))
                        RETURN(-EPERM);

                OBD_ALLOC_PTR(check);
                if (!check)
                        RETURN(-ENOMEM);

                rc = obd_iocontrol(cmd, sbi->ll_mdc_exp, 0, (void *)check,
                                   NULL);
                if (rc) {
                        CDEBUG(D_QUOTA, "mdc ioctl %d failed: %d\n", cmd, rc);
                        if (copy_to_user((void *)arg, check, sizeof(*check)))
                                rc = -EFAULT;
                        GOTO(out_poll, rc);
                }

                rc = obd_iocontrol(cmd, sbi->ll_osc_exp, 0, (void *)check,
                                   NULL);
                if (rc) {
                        CDEBUG(D_QUOTA, "osc ioctl %d failed: %d\n", cmd, rc);
                        if (copy_to_user((void *)arg, check, sizeof(*check)))
                                rc = -EFAULT;
                        GOTO(out_poll, rc);
                }
        out_poll:
                OBD_FREE_PTR(check);
                RETURN(rc);
        }
#if HAVE_QUOTA_SUPPORT
        case OBD_IOC_QUOTACTL: {
                struct if_quotactl *qctl;
                struct obd_quotactl *oqctl;

                int cmd, type, id, rc = 0;

                OBD_ALLOC_PTR(qctl);
                if (!qctl)
                        RETURN(-ENOMEM);

                OBD_ALLOC_PTR(oqctl);
                if (!oqctl) {
                        OBD_FREE_PTR(qctl);
                        RETURN(-ENOMEM);
                }
                if (copy_from_user(qctl, (void *)arg, sizeof(*qctl)))
                        GOTO(out_quotactl, rc = -EFAULT);

                cmd = qctl->qc_cmd;
                type = qctl->qc_type;
                id = qctl->qc_id;
                switch (cmd) {
                case Q_QUOTAON:
                case Q_QUOTAOFF:
                case Q_SETQUOTA:
                case Q_SETINFO:
                        if (!capable(CAP_SYS_ADMIN))
                                GOTO(out_quotactl, rc = -EPERM);
                        break;
                case Q_GETQUOTA:
                        if (((type == USRQUOTA && current->euid != id) ||
                             (type == GRPQUOTA && !in_egroup_p(id))) &&
                            !capable(CAP_SYS_ADMIN))
                                GOTO(out_quotactl, rc = -EPERM);

                        /* XXX: dqb_valid is borrowed as a flag to mark that
                         *      only mds quota is wanted */
                        if (qctl->qc_dqblk.dqb_valid)
                                qctl->obd_uuid = sbi->ll_mdc_exp->exp_obd->
                                                        u.cli.cl_target_uuid;
                        break;
                case Q_GETINFO:
                        break;
                default:
                        CERROR("unsupported quotactl op: %#x\n", cmd);
                        GOTO(out_quotactl, -ENOTTY);
                }

                QCTL_COPY(oqctl, qctl);

                if (qctl->obd_uuid.uuid[0]) {
                        struct obd_device *obd;
                        struct obd_uuid *uuid = &qctl->obd_uuid;

                        obd = class_find_client_notype(uuid,
                                         &sbi->ll_osc_exp->exp_obd->obd_uuid);
                        if (!obd)
                                GOTO(out_quotactl, rc = -ENOENT);

                        if (cmd == Q_GETINFO)
                                oqctl->qc_cmd = Q_GETOINFO;
                        else if (cmd == Q_GETQUOTA)
                                oqctl->qc_cmd = Q_GETOQUOTA;
                        else
                                GOTO(out_quotactl, rc = -EINVAL);

                        if (sbi->ll_mdc_exp->exp_obd == obd) {
                                rc = obd_quotactl(sbi->ll_mdc_exp, oqctl);
                        } else {
                                int i;
                                struct obd_export *exp;
                                struct lov_obd *lov = &sbi->ll_osc_exp->
                                                            exp_obd->u.lov;

                                for (i = 0; i < lov->desc.ld_tgt_count; i++) {
                                        if (!lov->lov_tgts[i] ||
                                            !lov->lov_tgts[i]->ltd_active)
                                                continue;
                                        exp = lov->lov_tgts[i]->ltd_exp;
                                        if (exp->exp_obd == obd) {
                                                rc = obd_quotactl(exp, oqctl);
                                                break;
                                        }
                                }
                        }

                        oqctl->qc_cmd = cmd;
                        QCTL_COPY(qctl, oqctl);

                        if (copy_to_user((void *)arg, qctl, sizeof(*qctl)))
                                rc = -EFAULT;

                        GOTO(out_quotactl, rc);
                }

                rc = obd_quotactl(sbi->ll_mdc_exp, oqctl);
                if (rc && rc != -EBUSY && cmd == Q_QUOTAON) {
                        oqctl->qc_cmd = Q_QUOTAOFF;
                        obd_quotactl(sbi->ll_mdc_exp, oqctl);
                }

                QCTL_COPY(qctl, oqctl);

                if (copy_to_user((void *)arg, qctl, sizeof(*qctl)))
                        rc = -EFAULT;
        out_quotactl:
                OBD_FREE_PTR(qctl);
                OBD_FREE_PTR(oqctl);
                RETURN(rc);
        }
#endif /* HAVE_QUOTA_SUPPORT */
        case OBD_IOC_GETNAME: {
                struct obd_device *obd = class_exp2obd(sbi->ll_osc_exp);
                if (!obd)
                        RETURN(-EFAULT);
                if (copy_to_user((void *)arg, obd->obd_name,
                                strlen(obd->obd_name) + 1))
                        RETURN (-EFAULT);
                RETURN(0);
        }
        default:
                RETURN(obd_iocontrol(cmd, sbi->ll_osc_exp,0,NULL,(void *)arg));
        }
}

int ll_dir_open(struct inode *inode, struct file *file)
{
        ENTRY;
        RETURN(ll_file_open(inode, file));
}

int ll_dir_release(struct inode *inode, struct file *file)
{
        ENTRY;
        RETURN(ll_file_release(inode, file));
}

struct file_operations ll_dir_operations = {
        .open     = ll_dir_open,
        .release  = ll_dir_release,
        .read     = generic_read_dir,
        .readdir  = ll_readdir,
        .ioctl    = ll_dir_ioctl
};

