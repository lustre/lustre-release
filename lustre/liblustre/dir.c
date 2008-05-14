/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light directory handling
 *
 *  Copyright (c) 2002-2004 Cluster File Systems, Inc.
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

#define DEBUG_SUBSYSTEM S_LLITE

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/queue.h>

#include <sysio.h>
#ifdef HAVE_XTIO_H
#include <xtio.h>
#endif
#include <fs.h>
#include <mount.h>
#include <inode.h>
#ifdef HAVE_FILE_H
#include <file.h>
#endif

#undef LIST_HEAD

#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#elif defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#endif

#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#elif defined(HAVE_UNISTD_H)
#include <unistd.h>
#endif

#include <dirent.h>

#include "llite_lib.h"

/* (new) readdir implementation overview can be found in lustre/llite/dir.c */

static int llu_dir_do_readpage(struct inode *inode, struct page *page)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat     *st = llu_i2stat(inode);
        struct llu_sb_info    *sbi = llu_i2sbi(inode);
        struct ptlrpc_request *request;
        struct lustre_handle   lockh;
        struct mdt_body       *body;
        struct lookup_intent   it = { .it_op = IT_READDIR };
        struct md_op_data      op_data = {{ 0 }};
        ldlm_policy_data_t policy = { .l_inodebits = { MDS_INODELOCK_UPDATE } };
        __u64 offset;
        int rc = 0;
        ENTRY;

        rc = md_lock_match(sbi->ll_md_exp, LDLM_FL_BLOCK_GRANTED,
                           &lli->lli_fid, LDLM_IBITS, &policy, LCK_CR, &lockh);
        if (!rc) {
                struct ldlm_enqueue_info einfo = {LDLM_IBITS, LCK_CR,
                        llu_md_blocking_ast, ldlm_completion_ast, NULL, inode};

                llu_prep_md_op_data(&op_data, inode, NULL, NULL, 0, 0,
                                    LUSTRE_OPC_ANY);

                rc = md_enqueue(sbi->ll_md_exp, &einfo, &it,
                                &op_data, &lockh, NULL, 0,
                                LDLM_FL_CANCEL_ON_BLOCK);
                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        RETURN(rc);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        offset = (__u64)hash_x_index(page->index);
        rc = md_readpage(sbi->ll_md_exp, &lli->lli_fid, NULL,
                         offset, page, &request);
        if (!rc) {
                body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
                LASSERT(body != NULL);         /* checked by md_readpage() */

                if (body->valid & OBD_MD_FLSIZE)
                        st->st_size = body->size;
        } else {
                CERROR("read_dir_page(%ld) error %d\n", page->index, rc);
        }
        ptlrpc_req_finished(request);
        EXIT;

        ldlm_lock_decref(&lockh, LCK_CR);
        return rc;
}

static struct page *llu_dir_read_page(struct inode *ino, __u32 hash,
                                      int exact, struct ll_dir_chain *chain)
{
        struct page *page;
        int rc;
        ENTRY;

        OBD_PAGE_ALLOC(page, 0);
        if (!page)
                RETURN(ERR_PTR(-ENOMEM));
        page->index = hash_x_index(hash);

        rc = llu_dir_do_readpage(ino, page);
        if (rc) {
                OBD_PAGE_FREE(page);
                RETURN(ERR_PTR(rc));
        }

        return page;
}

enum {
        EXT2_FT_UNKNOWN,
        EXT2_FT_REG_FILE,
        EXT2_FT_DIR,
        EXT2_FT_CHRDEV,
        EXT2_FT_BLKDEV,
        EXT2_FT_FIFO,
        EXT2_FT_SOCK,
        EXT2_FT_SYMLINK,
        EXT2_FT_MAX
};

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

#define NAME_OFFSET(de) ((int) ((de)->d_name - (char *) (de)))
#define ROUND_UP64(x)   (((x)+sizeof(__u64)-1) & ~(sizeof(__u64)-1))
static int filldir(char *buf, int buflen,
                   const char *name, int namelen, loff_t offset,
                   ino_t ino, unsigned int d_type, int *filled)
{
        cfs_dirent_t *dirent = (cfs_dirent_t *) (buf + *filled);
        int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namelen + 1);

        /* check overflow */
        if ((*filled + reclen) > buflen)
                return 1;

        dirent->d_ino = ino;
#ifdef _DIRENT_HAVE_D_OFF
        dirent->d_off = offset;
#endif
        dirent->d_reclen = reclen;
#ifdef _DIRENT_HAVE_D_TYPE
        dirent->d_type = (unsigned short) d_type;
#endif
        memcpy(dirent->d_name, name, namelen);
        dirent->d_name[namelen] = 0;

        *filled += reclen;

        return 0;
}

/* 
 * TODO: much of the code here is similar/identical to llite ll_readdir().
 * These code can be factored out and shared in a common module.
 */

ssize_t llu_iop_filldirentries(struct inode *dir, _SYSIO_OFF_T *basep, 
			       char *buf, size_t nbytes)
{
        struct llu_inode_info *lli = llu_i2info(dir);
        struct intnl_stat     *st = llu_i2stat(dir);
        loff_t                 pos = *basep;
        struct ll_dir_chain    chain;
        struct page           *page;
        int filled = 0;
        int rc;
        int done;
        int shift;
        ENTRY;

        liblustre_wait_event(0);

        if (st->st_size == 0) {
                CWARN("dir size is 0?\n");
                RETURN(0);
        }

        if (pos == DIR_END_OFF)
                /*
                 * end-of-file.
                 */
                RETURN(0);

        rc    = 0;
        done  = 0;
        shift = 0;
        ll_dir_chain_init(&chain);

        page = llu_dir_read_page(dir, pos, 0, &chain);
        while (rc == 0 && !done) {
                struct lu_dirpage *dp;
                struct lu_dirent  *ent;

                if (!IS_ERR(page)) {
                        /* 
                         * If page is empty (end of directoryis reached),
                         * use this value. 
                         */
                        __u64 hash = DIR_END_OFF;
                        __u64 next;

                        dp = page->addr;
                        for (ent = lu_dirent_start(dp); ent != NULL && !done;
                             ent = lu_dirent_next(ent)) {
                                char          *name;
                                int            namelen;
                                struct lu_fid  fid;
                                ino_t          ino;

                                hash    = le64_to_cpu(ent->lde_hash);
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
                                ino  = llu_fid_build_ino(llu_i2sbi(dir), &fid);

                                done = filldir(buf, nbytes, name, namelen,
                                               (loff_t)hash, ino, DT_UNKNOWN,
                                               &filled);
                        }
                        next = le64_to_cpu(dp->ldp_hash_end);
                        OBD_PAGE_FREE(page);
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
                                        page = llu_dir_read_page(dir, pos, 1,
                                                               &chain);
                                else {
                                        /*
                                         * go into overflow page.
                                         */
                                }
                        } else {
                                pos = hash;
                                if (filled == 0)
                                        GOTO(out, filled = -EINVAL);
                        }
                } else {
                        rc = PTR_ERR(page);
                        CERROR("error reading dir "DFID" at %lu: rc %d\n",
                               PFID(&lli->lli_fid), (unsigned long)pos, rc);
                }
        }
        lli->lli_dir_pos = (loff_t)(__s32)pos;
        *basep = lli->lli_dir_pos;
out:
        ll_dir_chain_fini(&chain);
        liblustre_wait_event(0);
        RETURN(filled);
}
