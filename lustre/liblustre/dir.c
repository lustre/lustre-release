/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
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
#include <sys/fcntl.h>
#include <sys/queue.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#undef LIST_HEAD

#include <linux/types.h>
#include <linux/dirent.h>
#include <linux/unistd.h>

#include "llite_lib.h"

static int llu_dir_do_readpage(struct inode *inode, struct page *page)
{
        struct llu_inode_info *lli = llu_i2info(inode);
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
                { .name = {lli->lli_st_ino, (__u64)lli->lli_st_generation} };
        ENTRY;

        if ((lli->lli_st_size + PAGE_CACHE_SIZE - 1) >> PAGE_SHIFT <= page->index) {
                /* XXX why do we need this exactly, and why do we think that
                 *     an all-zero directory page is useful?
                 */
                CERROR("memsetting dir page %lu to zero (size %lld)\n",
                       page->index, lli->lli_st_size);
                memset(page->addr, 0, PAGE_CACHE_SIZE);
                GOTO(readpage_out, rc);
        }

        rc = ldlm_lock_match(obddev->obd_namespace, LDLM_FL_BLOCK_GRANTED,
                             &res_id, LDLM_PLAIN, NULL, LCK_PR, &lockh);
        if (!rc) {
                llu_prepare_mdc_op_data(&data, inode, NULL, NULL, 0, 0);

                rc = mdc_enqueue(sbi->ll_mdc_exp, LDLM_PLAIN, &it, LCK_PR,
                                 &data, &lockh, NULL, 0,
                                 ldlm_completion_ast, llu_mdc_blocking_ast,
                                 inode);
                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        RETURN(rc);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        mdc_pack_fid(&mdc_fid, lli->lli_st_ino, lli->lli_st_generation, S_IFDIR);

        offset = page->index << PAGE_SHIFT;
        rc = mdc_readpage(sbi->ll_mdc_exp, &mdc_fid,
                          offset, page, &request);
        if (!rc) {
                body = lustre_msg_buf(request->rq_repmsg, 0, sizeof (*body));
                LASSERT (body != NULL);         /* checked by mdc_readpage() */
                LASSERT_REPSWABBED (request, 0); /* swabbed by mdc_readpage() */

                lli->lli_st_size = body->size;
        }
        ptlrpc_req_finished(request);
        EXIT;

 readpage_out:
        ldlm_lock_decref(&lockh, LCK_PR);
        return rc;
}

static struct page *llu_dir_read_page(struct inode *ino, int pgidx)
{
        struct page *page;
        int rc;
        ENTRY;

        page = alloc_page(0);
        if (!page) {
                CERROR("alloc page failed\n");
                RETURN(ERR_PTR(-ENOMEM));
        }
        page->index = pgidx;

        rc = llu_dir_do_readpage(ino, page);
        if (rc) {
                free_page(page);
                RETURN(ERR_PTR(rc));
        }

        return page;
}

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
        dirent->d_off = offset,
        dirent->d_reclen = reclen;
        dirent->d_type = (unsigned short) d_type;
        memcpy(dirent->d_name, name, namelen);
        dirent->d_name[namelen] = 0;

        *filled += reclen;

        return 0;
}

ssize_t llu_iop_getdirentries(struct inode *ino, char *buf, size_t nbytes,
                              _SYSIO_OFF_T *basep)
{
        struct llu_inode_info *lli = llu_i2info(ino);
        loff_t pos = *basep, offset;
        int maxpages, pgidx, filled = 0;
        ENTRY;

        if (pos == -1)
                pos = lli->lli_dir_pos;

        maxpages = lli->lli_st_size >> PAGE_CACHE_SHIFT;
        pgidx = pos >> PAGE_CACHE_SHIFT;
        offset = pos & ~PAGE_CACHE_MASK;

        for ( ; pgidx < maxpages ; pgidx++, offset = 0) {
                struct page *page;
                struct ext2_dirent *de;
                char *addr, *limit;

                page = llu_dir_read_page(ino, pgidx);
                if (IS_ERR(page))
                        continue;

                /* size might have been updated by mdc_readpage */
                maxpages = lli->lli_st_size >> PAGE_CACHE_SHIFT;

                /* fill in buffer */
                addr = page->addr;
                limit = addr + PAGE_CACHE_SIZE - EXT2_DIR_REC_LEN(1);
                de = (struct ext2_dirent *) (addr + offset);

                for ( ; (char*) de <= limit; de = ext2_next_entry(de)) {
                        if (de->inode) {
                                int over;
                                unsigned char d_type = 0;

                                /* XXX handle type, etc here */

                                offset = (char*) de - addr;
                                over =  filldir(buf, nbytes, de->name, de->name_len,
                                                (pgidx << PAGE_CACHE_SHIFT) | offset,
                                                le32_to_cpu(de->inode), d_type, &filled);
                                if (over) {
                                        free_page(page);
                                        GOTO(done, 0);
                                }
                        }
                }
                
                free_page(page);
        }
done:
        lli->lli_dir_pos = pgidx << PAGE_CACHE_SHIFT | offset;
        *basep = lli->lli_dir_pos;
        RETURN(filled);
}
