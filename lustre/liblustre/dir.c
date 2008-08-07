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
 * lustre/liblustre/dir.c
 *
 * Lustre Light directory handling
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

static int llu_dir_do_readpage(struct inode *inode, struct page *page)
{
        struct llu_inode_info *lli = llu_i2info(inode);
        struct intnl_stat *st = llu_i2stat(inode);
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct ll_fid mdc_fid;
        __u64 offset;
        int rc = 0;
        struct ptlrpc_request *request;
        struct lustre_handle lockh;
        struct mds_body *body;
        struct lookup_intent it = { .it_op = IT_READDIR };
        struct mdc_op_data data;
        struct obd_device *obddev = class_exp2obd(sbi->ll_mdc_exp);
        struct ldlm_res_id res_id =
                { .name = {st->st_ino, (__u64)lli->lli_st_generation} };
        ldlm_policy_data_t policy = { .l_inodebits = { MDS_INODELOCK_UPDATE } };
        ENTRY;

        rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_BLOCK_GRANTED,
                             &res_id, LDLM_IBITS, &policy, LCK_CR, &lockh);
        if (!rc) {
                struct ldlm_enqueue_info einfo = {LDLM_IBITS, LCK_CR,
                        llu_mdc_blocking_ast, ldlm_completion_ast, NULL, inode};

                llu_prepare_mdc_op_data(&data, inode, NULL, NULL, 0, 0);

                rc = mdc_enqueue(sbi->ll_mdc_exp, &einfo, &it,
                                 &data, &lockh, NULL, 0,
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

        mdc_pack_fid(&mdc_fid, st->st_ino, lli->lli_st_generation, S_IFDIR);

        offset = (__u64)page->index << CFS_PAGE_SHIFT;
        rc = mdc_readpage(sbi->ll_mdc_exp, &mdc_fid,
                          offset, page, &request);
        if (!rc) {
                body = lustre_msg_buf(request->rq_repmsg, REPLY_REC_OFF,
                                      sizeof(*body));
                LASSERT(body != NULL);         /* checked by mdc_readpage() */
                /* swabbed by mdc_readpage() */
                LASSERT(lustre_rep_swabbed(request, REPLY_REC_OFF));

                st->st_size = body->size;
        } else {
                CERROR("read_dir_page(%ld) error %d\n", page->index, rc);
        }
        ptlrpc_req_finished(request);
        EXIT;

        ldlm_lock_decref(&lockh, LCK_CR);
        return rc;
}

static struct page *llu_dir_read_page(struct inode *ino, unsigned long pgidx)
{
        struct page *page;
        int rc;
        ENTRY;

        OBD_PAGE_ALLOC(page, 0);
        if (!page)
                RETURN(ERR_PTR(-ENOMEM));
        page->index = pgidx;

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
        struct dirent64 *dirent = (struct dirent64 *) (buf + *filled);
        int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namelen + 1);

        /* check overflow */
        if ((*filled + reclen) > buflen)
                return 1;

        dirent->d_ino = ino;
        dirent->d_off = offset;
        dirent->d_reclen = reclen;
#ifndef _AIX
        dirent->d_type = (unsigned short) d_type;
#endif
        memcpy(dirent->d_name, name, namelen);
        dirent->d_name[namelen] = 0;

        *filled += reclen;

        return 0;
}

ssize_t llu_iop_filldirentries(struct inode *ino, _SYSIO_OFF_T *basep, 
			       char *buf, size_t nbytes)
{
        struct llu_inode_info *lli = llu_i2info(ino);
        struct intnl_stat *st = llu_i2stat(ino);
        loff_t pos = *basep, offset;
        int filled = 0;
        unsigned long pgidx, maxpages;
        ENTRY;

        liblustre_wait_event(0);

        if (st->st_size == 0) {
                CWARN("dir size is 0?\n");
                RETURN(0);
        }

        if (pos == -1)
                pos = lli->lli_dir_pos;

        maxpages = (st->st_size + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
        pgidx = pos >> CFS_PAGE_SHIFT;
        offset = pos & ~CFS_PAGE_MASK;

        for ( ; pgidx < maxpages ; pgidx++, offset = 0) {
                struct page *page;
                struct ext2_dirent *de;
                char *addr, *limit;

                page = llu_dir_read_page(ino, pgidx);
                if (IS_ERR(page))
                        continue;

                /* size might have been updated by mdc_readpage */
                maxpages = (st->st_size + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;

                /* fill in buffer */
                addr = page->addr;
                limit = addr + CFS_PAGE_SIZE - EXT2_DIR_REC_LEN(1);
                de = (struct ext2_dirent *) (addr + offset);

                for ( ; (char*) de <= limit; de = ext2_next_entry(de)) {
                        if (de->inode) {
                                int over;
                                unsigned char d_type = DT_UNKNOWN;

                                if (de->file_type < EXT2_FT_MAX)
                                        d_type = ext2_filetype_table[de->file_type];

                                offset = (char*) de - addr;
                                over =  filldir(buf, nbytes, de->name, de->name_len,
                                                (((__u64)pgidx << CFS_PAGE_SHIFT) | offset)
                                                + le16_to_cpu(de->rec_len),
                                                le32_to_cpu(de->inode), d_type, &filled);
                                if (over) {
                                        OBD_PAGE_FREE(page);
                                        /*
                                         * if buffer overflow with no data
                                         * returned yet, then report error
                                         * instead of eof
                                         */
                                        if (filled == 0)
                                                RETURN(-EINVAL);

                                        GOTO(done, 0);
                                }
                        }
                }
                
                OBD_PAGE_FREE(page);
        }
done:
        lli->lli_dir_pos = (__u64)pgidx << CFS_PAGE_SHIFT | offset;
        *basep = lli->lli_dir_pos;
        liblustre_wait_event(0);
        RETURN(filled);
}
