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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
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

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libcfs/libcfs.h>
#include <lustre/lustre_idl.h>
#include <liblustre.h>
#include <lclient.h>
#include <lustre_dlm.h>
#include <lustre_lite.h>
#include <lustre_net.h>
#include <lustre_req_layout.h>
#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include "llite_lib.h"
#include <dirent.h>

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
        int rc = 0;
        ENTRY;

        llu_prep_md_op_data(&op_data, inode, NULL, NULL, 0, 0, LUSTRE_OPC_ANY);
        rc = md_lock_match(sbi->ll_md_exp, LDLM_FL_BLOCK_GRANTED,
                           &lli->lli_fid, LDLM_IBITS, &policy, LCK_CR, &lockh);
        if (!rc) {
		struct ldlm_enqueue_info einfo = {
			.ei_type	= LDLM_IBITS,
			.ei_mode	= LCK_CR,
			.ei_cb_bl	= llu_md_blocking_ast,
			.ei_cb_cp	= ldlm_completion_ast,
			.ei_cbdata	= inode,
		};

		rc = md_enqueue(sbi->ll_md_exp, &einfo, NULL, &it, &op_data,
				&lockh, LDLM_FL_CANCEL_ON_BLOCK);
                request = (struct ptlrpc_request *)it.d.lustre.it_data;
                if (request)
                        ptlrpc_req_finished(request);
                if (rc < 0) {
                        CERROR("lock enqueue: err: %d\n", rc);
                        RETURN(rc);
                }
        }
        ldlm_lock_dump_handle(D_OTHER, &lockh);

        op_data.op_hash_offset = hash_x_index(page->index, 0);
        op_data.op_npages = 1;
        rc = md_readpage(sbi->ll_md_exp, &op_data, &page, &request);
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

static struct page *llu_dir_read_page(struct inode *ino, __u64 hash,
                                     int exact, struct ll_dir_chain *chain)
{
	struct page *page;
        int rc;
        ENTRY;

        OBD_PAGE_ALLOC(page, 0);
        if (!page)
                RETURN(ERR_PTR(-ENOMEM));
        page->index = hash_x_index(hash, 0);

        rc = llu_dir_do_readpage(ino, page);
        if (rc) {
                OBD_PAGE_FREE(page);
                RETURN(ERR_PTR(rc));
        }

        return page;
}

static void *(*memmover)(void *, const void *, size_t) = memmove;

#define NAME_OFFSET(de) ((int) ((de)->d_name - (char *) (de)))
#define ROUND_UP64(x)   (((x)+sizeof(__u64)-1) & ~(sizeof(__u64)-1))
static int filldir(char *buf, int buflen, const char *name, int namelen,
		   loff_t offset, ino_t ino, unsigned int d_type, int *filled)
{
	struct intnl_dirent *dirent = (struct intnl_dirent *)(buf + *filled);
	struct intnl_dirent holder;
	int reclen = ROUND_UP64(NAME_OFFSET(dirent) + namelen + 1);

        /*
         * @buf is not guaranteed to be properly aligned. To work around,
         * first fill stack-allocated @holder, then copy @holder into @buf by
         * memmove().
         */

        /* check overflow */
        if ((*filled + reclen) > buflen)
                return 1;

        holder.d_ino = ino;
#ifdef _DIRENT_HAVE_D_OFF
        holder.d_off = offset;
#endif
        holder.d_reclen = reclen;
#ifdef _DIRENT_HAVE_D_TYPE
        holder.d_type = (unsigned short) d_type;
#endif
        /* gcc unrolls memcpy() of structs into field-wise assignments,
         * assuming proper alignment. Humor it. */
        (*memmover)(dirent, &holder, NAME_OFFSET(dirent));
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
	struct page            *page;
        int filled = 0;
        int rc;
        int done;
        __u16 type;
        ENTRY;

        liblustre_wait_event(0);

        if (st->st_size == 0) {
                CWARN("dir size is 0?\n");
                RETURN(0);
        }

        if (pos == MDS_DIR_END_OFF)
                /*
                 * end-of-file.
                 */
                RETURN(0);

        rc    = 0;
        done  = 0;
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
                        __u64 hash = MDS_DIR_END_OFF;
                        __u64 next;

                        dp = page->addr;
                        for (ent = lu_dirent_start(dp); ent != NULL && !done;
                             ent = lu_dirent_next(ent)) {
                                char          *name;
                                int            namelen;
                                struct lu_fid  fid;
                                __u64          ino;

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
                                ino  = cl_fid_build_ino(&fid, 0);
                                type = ll_dirent_type_get(ent);
                                done = filldir(buf, nbytes, name, namelen,
                                               (loff_t)hash, ino, type,
                                               &filled);
                        }
                        next = le64_to_cpu(dp->ldp_hash_end);
                        OBD_PAGE_FREE(page);
                        if (!done) {
                                pos = next;
                                if (pos == MDS_DIR_END_OFF)
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
        lli->lli_dir_pos = (loff_t)pos;
        *basep = lli->lli_dir_pos;
out:
        ll_dir_chain_fini(&chain);
        liblustre_wait_event(0);
        RETURN(filled);
}
