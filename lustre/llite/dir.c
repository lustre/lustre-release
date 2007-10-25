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
#include <linux/buffer_head.h>   // for wait_on_buffer

#define DEBUG_SUBSYSTEM S_LLITE

#include <obd_support.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_lite.h>
#include <lustre_dlm.h>
#include <lustre_fid.h>
#include "llite_internal.h"

#ifdef HAVE_PG_FS_MISC
#define PageChecked(page)        test_bit(PG_fs_misc, &(page)->flags)
#define SetPageChecked(page)     set_bit(PG_fs_misc, &(page)->flags)
#endif

/*
 * (new) readdir implementation overview.
 *
 * Original lustre readdir implementation cached exact copy of raw directory
 * pages on the client. These pages were indexed in client page cache by
 * logical offset in the directory file. This design, while very simple and
 * intuitive had some inherent problems:
 *
 *     . it implies that byte offset to the directory entry serves as a
 *     telldir(3)/seekdir(3) cookie, but that offset is not stable: in
 *     ext3/htree directory entries may move due to splits, and more
 *     importantly,
 *
 *     . it is incompatible with the design of split directories for cmd3,
 *     that assumes that names are distributed across nodes based on their
 *     hash, and so readdir should be done in hash order.
 *
 * New readdir implementation does readdir in hash order, and uses hash of a
 * file name as a telldir/seekdir cookie. This led to number of complications:
 *
 *     . hash is not unique, so it cannot be used to index cached directory
 *     pages on the client (note, that it requires a whole pageful of hash
 *     collided entries to cause two pages to have identical hashes);
 *
 *     . hash is not unique, so it cannot, strictly speaking, be used as an
 *     entry cookie. ext3/htree has the same problem and lustre implementation
 *     mimics their solution: seekdir(hash) positions directory at the first
 *     entry with the given hash.
 *
 * Client side.
 *
 * 0. caching
 *
 * Client caches directory pages using hash of the first entry as an index. As
 * noted above hash is not unique, so this solution doesn't work as is:
 * special processing is needed for "page hash chains" (i.e., sequences of
 * pages filled with entries all having the same hash value).
 *
 * First, such chains have to be detected. To this end, server returns to the
 * client the hash of the first entry on the page next to one returned. When
 * client detects that this hash is the same as hash of the first entry on the
 * returned page, page hash collision has to be handled. Pages in the
 * hash chain, except first one, are termed "overflow pages".
 *
 * Solution to index uniqueness problem is to not cache overflow
 * pages. Instead, when page hash collision is detected, all overflow pages
 * from emerging chain are immediately requested from the server and placed in
 * a special data structure (struct ll_dir_chain). This data structure is used
 * by ll_readdir() to process entries from overflow pages. When readdir
 * invocation finishes, overflow pages are discarded. If page hash collision
 * chain weren't completely processed, next call to readdir will again detect
 * page hash collision, again read overflow pages in, process next portion of
 * entries and again discard the pages. This is not as wasteful as it looks,
 * because, given reasonable hash, page hash collisions are extremely rare.
 *
 * 1. directory positioning
 *
 * When seekdir(hash) is called, original
 *
 *
 *
 *
 *
 *
 *
 *
 * Server.
 *
 * identification of and access to overflow pages
 *
 * page format
 *
 *
 *
 *
 *
 */

static __u32 hash_x_index(__u32 value)
{
        return ((__u32)~0) - value;
}
#ifdef HAVE_PG_FS_MISC
#define PageChecked(page)        test_bit(PG_fs_misc, &(page)->flags)
#define SetPageChecked(page)     set_bit(PG_fs_misc, &(page)->flags)
#endif

/* returns the page unlocked, but with a reference */
static int ll_dir_readpage(struct file *file, struct page *page)
{
        struct inode *inode = page->mapping->host;
        struct ptlrpc_request *request;
        struct mdt_body *body;
        struct obd_capa *oc;
        __u64 hash;
        int rc;
        ENTRY;

        hash = hash_x_index(page->index);
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) off %lu\n",
               inode->i_ino, inode->i_generation, inode, (unsigned long)hash);

        oc = ll_mdscapa_get(inode);
        rc = md_readpage(ll_i2sbi(inode)->ll_md_exp, ll_inode2fid(inode),
                         oc, hash, page, &request);
        capa_put(oc);
        if (!rc) {
                body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                /* Checked by mdc_readpage() */
                LASSERT(body != NULL);

                /* Swabbed by mdc_readpage() */
                LASSERT(lustre_rep_swabbed(request, REPLY_REC_OFF));

                if (body->valid & OBD_MD_FLSIZE)
                        i_size_write(inode, body->size);
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

static inline unsigned long dir_pages(struct inode *inode)
{
        return (i_size_read(inode) + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
}

static inline unsigned ll_chunk_size(struct inode *inode)
{
        return inode->i_sb->s_blocksize;
}

static void ll_check_page(struct inode *dir, struct page *page)
{
        /* XXX: check page format later */
        SetPageChecked(page);
}

static inline void ll_put_page(struct page *page)
{
        kunmap(page);
        page_cache_release(page);
}

/*
 * Find, kmap and return page that contains given hash.
 */
static struct page *ll_dir_page_locate(struct inode *dir, unsigned long hash,
                                       __u32 *start, __u32 *end)
{
        struct address_space *mapping = dir->i_mapping;
        /*
         * Complement of hash is used as an index so that
         * radix_tree_gang_lookup() can be used to find a page with starting
         * hash _smaller_ than one we are looking for.
         */
        unsigned long offset = hash_x_index(hash);
        struct page *page;
        int found;

	spin_lock_irq(&mapping->tree_lock);
	found = radix_tree_gang_lookup(&mapping->page_tree,
                                       (void **)&page, offset, 1);
	if (found > 0) {
                struct lu_dirpage *dp;

		page_cache_get(page);
                spin_unlock_irq(&mapping->tree_lock);
                /*
                 * In contrast to find_lock_page() we are sure that directory
                 * page cannot be truncated (while DLM lock is held) and,
                 * hence, can avoid restart.
                 *
                 * In fact, page cannot be locked here at all, because
                 * ll_dir_readpage() does synchronous io.
                 */
                wait_on_page(page);
                if (PageUptodate(page)) {
                        dp = kmap(page);
                        *start = le32_to_cpu(dp->ldp_hash_start);
                        *end   = le32_to_cpu(dp->ldp_hash_end);
                        LASSERT(*start <= hash);
                        if (hash > *end || (*end != *start && hash == *end)) {
                                kunmap(page);
                                lock_page(page);
                                ll_truncate_complete_page(page);
                                unlock_page(page);
                                page_cache_release(page);
                                page = NULL;
                        }
                } else {
                        page_cache_release(page);
                        page = ERR_PTR(-EIO);
                }

	} else {
                spin_unlock_irq(&mapping->tree_lock);
                page = NULL;
        }
        return page;
}

/*
 * Chain of hash overflow pages.
 */
struct ll_dir_chain {
        /* XXX something. Later */
};

static void ll_dir_chain_init(struct ll_dir_chain *chain)
{
}

static void ll_dir_chain_fini(struct ll_dir_chain *chain)
{
}

static struct page *ll_get_dir_page(struct inode *dir, __u32 hash, int exact,
                                    struct ll_dir_chain *chain)
{
        ldlm_policy_data_t policy = {.l_inodebits = {MDS_INODELOCK_UPDATE} };
        struct address_space *mapping = dir->i_mapping;
        struct lustre_handle lockh;
        struct lu_dirpage *dp;
        struct page *page;
        ldlm_mode_t mode;
        int rc;
        __u32 start;
        __u32 end;

        mode = LCK_PR;
        rc = md_lock_match(ll_i2sbi(dir)->ll_md_exp, LDLM_FL_BLOCK_GRANTED,
                           ll_inode2fid(dir), LDLM_IBITS, &policy, mode, &lockh);
        if (!rc) {
                struct ldlm_enqueue_info einfo = { LDLM_IBITS, mode,
                       ll_md_blocking_ast, ldlm_completion_ast, NULL, dir };
                struct lookup_intent it = { .it_op = IT_READDIR };
                struct ptlrpc_request *request;
                struct md_op_data *op_data;

                op_data = ll_prep_md_op_data(NULL, dir, NULL, NULL, 0, 0, 
                                             LUSTRE_OPC_ANY, NULL);
                if (IS_ERR(op_data))
                        return (void *)op_data;

                rc = md_enqueue(ll_i2sbi(dir)->ll_md_exp, &einfo, &it,
                                op_data, &lockh, NULL, 0, 0);

                ll_finish_md_op_data(op_data);

                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: rc: %d\n", rc);
                        return ERR_PTR(rc);
                }
        } else {
                /* for cross-ref object, l_ast_data of the lock may not be set,
                 * we reset it here */
                md_set_lock_data(ll_i2sbi(dir)->ll_md_exp, &lockh.cookie, dir);
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        page = ll_dir_page_locate(dir, hash, &start, &end);
        if (IS_ERR(page))
                GOTO(out_unlock, page);

        if (page != NULL) {
                /*
                 * XXX nikita: not entirely correct handling of a corner case:
                 * suppose hash chain of entries with hash value HASH crosses
                 * border between pages P0 and P1. First both P0 and P1 are
                 * cached, seekdir() is called for some entry from the P0 part
                 * of the chain. Later P0 goes out of cache. telldir(HASH)
                 * happens and finds P1, as it starts with matching hash
                 * value. Remaining entries from P0 part of the chain are
                 * skipped. (Is that really a bug?)
                 *
                 * Possible solutions: 0. don't cache P1 is such case, handle
                 * it as an "overflow" page. 1. invalidate all pages at
                 * once. 2. use HASH|1 as an index for P1.
                 */
                if (exact && hash != start) {
                        /*
                         * readdir asked for a page starting _exactly_ from
                         * given hash, but cache contains stale page, with
                         * entries with smaller hash values. Stale page should
                         * be invalidated, and new one fetched.
                         */
                        CWARN("Stale readpage page %p: %#lx != %#lx\n", page,
                              (unsigned long)hash, (unsigned long)start);
                        lock_page(page);
                        ll_truncate_complete_page(page);
                        unlock_page(page);
                        page_cache_release(page);
                } else
                        GOTO(hash_collision, page);
        }

        page = read_cache_page(mapping, hash_x_index(hash),
                               (filler_t*)mapping->a_ops->readpage, NULL);
        if (IS_ERR(page))
                GOTO(out_unlock, page);

        wait_on_page(page);
        (void)kmap(page);
        if (!PageUptodate(page))
                goto fail;
        if (!PageChecked(page))
                ll_check_page(dir, page);
        if (PageError(page))
                goto fail;
hash_collision:
        dp = page_address(page);

        start = le32_to_cpu(dp->ldp_hash_start);
        end   = le32_to_cpu(dp->ldp_hash_end);
        if (end == start) {
                LASSERT(start == hash);
                CWARN("Page-wide hash collision: %#lx\n", (unsigned long)end);
                /*
                 * Fetch whole overflow chain...
                 *
                 * XXX not yet.
                 */
                goto fail;
        }
out_unlock:
        ldlm_lock_decref(&lockh, mode);
        return page;

fail:
        ll_put_page(page);
        page = ERR_PTR(-EIO);
        goto out_unlock;
}

int ll_readdir(struct file *filp, void *cookie, filldir_t filldir)
{
        struct inode         *inode = filp->f_dentry->d_inode;
        struct ll_inode_info *info  = ll_i2info(inode);
        struct ll_sb_info    *sbi   = ll_i2sbi(inode);
        __u32                 pos   = filp->f_pos;
        struct page          *page;
        struct ll_dir_chain   chain;
        int rc;
        int done;
        int shift;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p) pos %lu/%llu\n",
               inode->i_ino, inode->i_generation, inode,
               (unsigned long)pos, i_size_read(inode));

        if (pos == DIR_END_OFF)
                /*
                 * end-of-file.
                 */
                RETURN(0);

        rc    = 0;
        done  = 0;
        shift = 0;
        ll_dir_chain_init(&chain);

        page = ll_get_dir_page(inode, pos, 0, &chain);

        while (rc == 0 && !done) {
                struct lu_dirpage *dp;
                struct lu_dirent  *ent;

                if (!IS_ERR(page)) {
                        /* 
                         * If page is empty (end of directoryis reached),
                         * use this value. 
                         */
                        __u32 hash = DIR_END_OFF;
                        __u32 next;

                        dp = page_address(page);
                        for (ent = lu_dirent_start(dp); ent != NULL && !done;
                             ent = lu_dirent_next(ent)) {
                                char          *name;
                                int            namelen;
                                struct lu_fid  fid;
                                ino_t          ino;

                                /*
                                 * XXX: implement correct swabbing here.
                                 */

                                hash    = le32_to_cpu(ent->lde_hash);
                                namelen = le16_to_cpu(ent->lde_namelen);

                                if (hash < pos)
                                        /*
                                         * Skip until we find target hash
                                         * value.
                                         */
                                        continue;

                                if (namelen == 0)
                                        /*
                                         * Skip dummy record.
                                         */
                                        continue;

                                fid  = ent->lde_fid;
                                name = ent->lde_name;
                                fid_le_to_cpu(&fid, &fid);
                                ino  = ll_fid_build_ino(sbi, &fid);

                                done = filldir(cookie, name, namelen,
                                               (loff_t)hash, ino, DT_UNKNOWN);
                        }
                        next = le32_to_cpu(dp->ldp_hash_end);
                        ll_put_page(page);
                        if (!done) {
                                pos = next;
                                if (pos == DIR_END_OFF)
                                        /*
                                         * End of directory reached.
                                         */
                                        done = 1;
                                else if (1 /* chain is exhausted*/)
                                        /*
                                         * Normal case: continue to the next
                                         * page.
                                         */
                                        page = ll_get_dir_page(inode, pos, 1,
                                                               &chain);
                                else {
                                        /*
                                         * go into overflow page.
                                         */
                                }
                        } else
                                pos = hash;
                } else {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir "DFID" at %lu: rc %d\n",
                               PFID(&info->lli_fid), (unsigned long)pos, rc);
                }
        }

        filp->f_pos = (loff_t)(__s32)pos;
        filp->f_version = inode->i_version;
        touch_atime(filp->f_vfsmnt, filp->f_dentry);

        ll_dir_chain_fini(&chain);

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

int ll_send_mgc_param(struct obd_export *mgc, char *string)
{
        struct mgs_send_param *msp;
        int rc = 0;

        OBD_ALLOC_PTR(msp);
        if (!msp)
                return -ENOMEM;

        strncpy(msp->mgs_param, string, MGS_PARAM_MAXLEN);
        rc = obd_set_info_async(mgc, strlen(KEY_SET_INFO), KEY_SET_INFO,
                                sizeof(struct mgs_send_param), msp, NULL);
        if (rc)
                CERROR("Failed to set parameter: %d\n", rc);
        OBD_FREE_PTR(msp);

        return rc;
}

char *ll_get_fsname(struct inode *inode)
{
        struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
        char *ptr, *fsname;
        int len;

        OBD_ALLOC(fsname, MGS_PARAM_MAXLEN);
        len = strlen(lsi->lsi_lmd->lmd_profile);
        ptr = strrchr(lsi->lsi_lmd->lmd_profile, '-');
        if (ptr && (strcmp(ptr, "-client") == 0))
                len -= 7;
        strncpy(fsname, lsi->lsi_lmd->lmd_profile, len);
        fsname[len] = '\0';

        return fsname;
}

int ll_dir_setstripe(struct inode *inode, struct lov_user_md *lump,
                     int set_default)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct md_op_data *op_data;
        struct ptlrpc_request *req = NULL;
        int rc = 0;
        struct lustre_sb_info *lsi = s2lsi(inode->i_sb);
        struct obd_device *mgc = lsi->lsi_mgc;
        char *fsname = NULL, *param = NULL;

        /*
         * This is coming from userspace, so should be in
         * local endian.  But the MDS would like it in little
         * endian, so we swab it before we send it.
         */
        if (lump->lmm_magic != LOV_USER_MAGIC)
                RETURN(-EINVAL);

        if (lump->lmm_magic != cpu_to_le32(LOV_USER_MAGIC))
                lustre_swab_lov_user_md(lump);

        op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
                                     LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        /* swabbing is done in lov_setstripe() on server side */
        rc = md_setattr(sbi->ll_md_exp, op_data, lump, sizeof(*lump),
                        NULL, 0, &req, NULL);
        ll_finish_md_op_data(op_data);
        ptlrpc_req_finished(req);
        if (rc) {
                if (rc != -EPERM && rc != -EACCES)
                        CERROR("mdc_setattr fails: rc = %d\n", rc);
        }

        if (set_default && mgc->u.cli.cl_mgc_mgsexp) {
                OBD_ALLOC(param, MGS_PARAM_MAXLEN);

                /* Get fsname and assume devname to be -MDT0000. */
                fsname = ll_get_fsname(inode);
                /* Set root stripesize */
                sprintf(param, "%s-MDT0000.lov.stripesize=%u", fsname,
                        lump->lmm_stripe_size);
                rc = ll_send_mgc_param(mgc->u.cli.cl_mgc_mgsexp, param);
                if (rc)
                        goto end;

                /* Set root stripecount */
                sprintf(param, "%s-MDT0000.lov.stripecount=%u", fsname,
                        lump->lmm_stripe_count);
                rc = ll_send_mgc_param(mgc->u.cli.cl_mgc_mgsexp, param);
                if (rc)
                        goto end;

                /* Set root stripeoffset */
                sprintf(param, "%s-MDT0000.lov.stripeoffset=%u", fsname,
                        lump->lmm_stripe_offset);
                rc = ll_send_mgc_param(mgc->u.cli.cl_mgc_mgsexp, param);
                if (rc)
                        goto end;
end:
                if (fsname)
                        OBD_FREE(fsname, MGS_PARAM_MAXLEN);
                if (param)
                        OBD_FREE(param, MGS_PARAM_MAXLEN);
        }
        return rc;
}

int ll_dir_getstripe(struct inode *inode, struct lov_mds_md **lmmp, 
                     int *lmm_size, struct ptlrpc_request **request) 
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct mdt_body   *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        int rc, lmmsize;
        struct obd_capa *oc;
        
        rc = ll_get_max_mdsize(sbi, &lmmsize);
        if (rc)
                RETURN(rc);

        oc = ll_mdscapa_get(inode);
        rc = md_getattr(sbi->ll_md_exp, ll_inode2fid(inode),
                        oc, OBD_MD_FLEASIZE | OBD_MD_FLDIREA,
                        lmmsize, &req);
        capa_put(oc);
        if (rc < 0) {
                CDEBUG(D_INFO, "md_getattr failed on inode "
                       "%lu/%u: rc %d\n", inode->i_ino,
                       inode->i_generation, rc);
                GOTO(out, rc);
        }

        body = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF, sizeof(*body));
        LASSERT(body != NULL); /* checked by md_getattr_name */
        /* swabbed by mdc_getattr_name */
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF));

        lmmsize = body->eadatasize;

        if (!(body->valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
            lmmsize == 0) {
                GOTO(out, rc = -ENODATA);
        }

        lmm = lustre_msg_buf(req->rq_repmsg, REPLY_REC_OFF + 1, lmmsize);
        LASSERT(lmm != NULL);
        LASSERT(lustre_rep_swabbed(req, REPLY_REC_OFF + 1));

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

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_IOCTL, 1);
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
                int namelen, rc, len = 0;
                char *buf = NULL;
                char *filename;
                struct obd_capa *oc;

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

                oc = ll_mdscapa_get(inode);
                rc = md_getattr_name(sbi->ll_md_exp, ll_inode2fid(inode), oc,
                                     filename, namelen, OBD_MD_FLID, 0,
                                     &request);
                capa_put(oc);
                if (rc < 0) {
                        CDEBUG(D_INFO, "md_getattr_name: %d\n", rc);
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
                int set_default = 0;

                LASSERT(sizeof(lum) == sizeof(*lump));
                LASSERT(sizeof(lum.lmm_objects[0]) ==
                        sizeof(lump->lmm_objects[0]));
                rc = copy_from_user(&lum, lump, sizeof(lum));
                if (rc)
                        RETURN(-EFAULT);

                if (inode->i_sb->s_root == file->f_dentry)
                        set_default = 1;

                rc = ll_dir_setstripe(inode, &lum, set_default);

                RETURN(rc);
        }
        case LL_IOC_OBD_STATFS:
                RETURN(ll_obd_statfs(inode, (void *)arg));
        case LL_IOC_LOV_GETSTRIPE:
        case LL_IOC_MDC_GETINFO:
        case IOC_MDC_GETFILEINFO:
        case IOC_MDC_GETFILESTRIPE: {
                struct ptlrpc_request *request = NULL;
                struct lov_user_md *lump;
                struct lov_mds_md *lmm = NULL;
                struct mdt_body *body;
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
                        body = lustre_msg_buf(request->rq_repmsg,
                                              REPLY_REC_OFF, sizeof(*body));
                        LASSERT(body != NULL); /* checked by md_getattr_name */
                        /* swabbed by md_getattr_name */
                        LASSERT(lustre_rep_swabbed(request, REPLY_REC_OFF));
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
                        st.st_ino     = inode->i_ino;

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

                rc = obd_unpackmd(sbi->ll_dt_exp, &lsm, lmm, lmmsize);
                if (rc < 0)
                        GOTO(free_lmm, rc = -ENOMEM);

                rc = obd_checkmd(sbi->ll_dt_exp, sbi->ll_md_exp, lsm);
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
                obd_free_memmd(sbi->ll_dt_exp, &lsm);
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
                if (!rc) {
                        str = lustre_msg_string(req->rq_repmsg, REPLY_REC_OFF,
                                                data->ioc_plen1);
                        rc = copy_to_user(data->ioc_pbuf1, str, data->ioc_plen1);
                }
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
                rc = obd_quotacheck(sbi->ll_md_exp, oqctl);
                if (rc < 0) {
                        CDEBUG(D_INFO, "md_quotacheck failed: rc %d\n", rc);
                        error = rc;
                }

                rc = obd_quotacheck(sbi->ll_dt_exp, oqctl);
                if (rc < 0)
                        CDEBUG(D_INFO, "obd_quotacheck failed: rc %d\n", rc);

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

                rc = obd_iocontrol(cmd, sbi->ll_md_exp, 0, (void *)check,
                                   NULL);
                if (rc) {
                        CDEBUG(D_QUOTA, "mdc ioctl %d failed: %d\n", cmd, rc);
                        if (copy_to_user((void *)arg, check, sizeof(*check)))
                                rc = -EFAULT;
                        GOTO(out_poll, rc);
                }

                rc = obd_iocontrol(cmd, sbi->ll_dt_exp, 0, (void *)check,
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
#ifdef HAVE_QUOTA_SUPPORT
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
                                qctl->obd_uuid = sbi->ll_md_exp->exp_obd->
                                                        u.cli.cl_target_uuid;
                        break;
                case Q_GETINFO:
                        break;
                default:
                        CERROR("unsupported quotactl op: %#x\n", cmd);
                        GOTO(out_quotactl, rc = -ENOTTY);
                }

                QCTL_COPY(oqctl, qctl);

                if (qctl->obd_uuid.uuid[0]) {
                        struct obd_device *obd;
                        struct obd_uuid *uuid = &qctl->obd_uuid;

                        obd = class_find_client_notype(uuid,
                                         &sbi->ll_dt_exp->exp_obd->obd_uuid);
                        if (!obd)
                                GOTO(out_quotactl, rc = -ENOENT);

                        if (cmd == Q_GETINFO)
                                oqctl->qc_cmd = Q_GETOINFO;
                        else if (cmd == Q_GETQUOTA)
                                oqctl->qc_cmd = Q_GETOQUOTA;
                        else
                                GOTO(out_quotactl, rc = -EINVAL);

                        if (sbi->ll_md_exp->exp_obd == obd) {
                                rc = obd_quotactl(sbi->ll_md_exp, oqctl);
                        } else {
                                int i;
                                struct obd_export *exp;
                                struct lov_obd *lov = &sbi->ll_dt_exp->
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

                rc = obd_quotactl(sbi->ll_md_exp, oqctl);
                if (rc && rc != -EBUSY && cmd == Q_QUOTAON) {
                        oqctl->qc_cmd = Q_QUOTAOFF;
                        obd_quotactl(sbi->ll_md_exp, oqctl);
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
                struct obd_device *obd = class_exp2obd(sbi->ll_dt_exp);
                if (!obd)
                        RETURN(-EFAULT);
                if (copy_to_user((void *)arg, obd->obd_name,
                                strlen(obd->obd_name) + 1))
                        RETURN (-EFAULT);
                RETURN(0);
        }
        case LL_IOC_FLUSHCTX:
                RETURN(ll_flush_ctx(inode));
        case LL_IOC_GETFACL: {
                struct rmtacl_ioctl_data ioc;

                if (copy_from_user(&ioc, (void *)arg, sizeof(ioc)))
                        RETURN(-EFAULT);

                RETURN(ll_ioctl_getfacl(inode, &ioc));
        }
        case LL_IOC_SETFACL: {
                struct rmtacl_ioctl_data ioc;

                if (copy_from_user(&ioc, (void *)arg, sizeof(ioc)))
                        RETURN(-EFAULT);

                RETURN(ll_ioctl_setfacl(inode, &ioc));
        }
        default:
                RETURN(obd_iocontrol(cmd, sbi->ll_dt_exp,0,NULL,(void *)arg));
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

