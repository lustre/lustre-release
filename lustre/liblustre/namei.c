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

#include <stdlib.h>
#include <string.h>
#include <error.h>
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

#include "llite_lib.h"

static void llu_mdc_lock_set_inode(struct lustre_handle *lockh,
                                   struct inode *inode)
{
        struct ldlm_lock *lock = ldlm_handle2lock(lockh);
        ENTRY;

        LASSERT(lock != NULL);
        lock->l_data = inode;
        LDLM_LOCK_PUT(lock);
        EXIT;
}

static int pnode_revalidate_finish(int flag, struct ptlrpc_request *request,
                                   struct inode *parent, struct pnode *pnode,
                                   struct lookup_intent *it, int offset,
                                   obd_id ino)
{
        struct llu_sb_info    *sbi = llu_i2sbi(parent);
        struct pnode_base     *pb = pnode->p_base;
        struct mds_body       *body;
        struct lov_stripe_md  *lsm = NULL;
        struct lov_mds_md     *lmm;
        int                    lmmsize;
        int                    rc = 0;
        ENTRY;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */

        if ((flag & LL_LOOKUP_NEGATIVE) != 0)
                GOTO (out, rc = -ENOENT);

        /* We only get called if the mdc_enqueue() called from
         * ll_intent_lock() was successful.  Therefore the mds_body is
         * present and correct, and the eadata is present (but still
         * opaque, so only obd_unpackmd() can check the size) */
        body = lustre_msg_buf(request->rq_repmsg, offset, sizeof (*body));
        LASSERT (body != NULL);
        LASSERT_REPSWABBED (request, offset);

        if (body->valid & OBD_MD_FLEASIZE) {
                /* Only bother with this if inodes's LSM not set? */

                if (body->eadatasize == 0) {
                        CERROR ("OBD_MD_FLEASIZE set, but eadatasize 0\n");
                        GOTO (out, rc = -EPROTO);
                }
                lmmsize = body->eadatasize;
                lmm = lustre_msg_buf (request->rq_repmsg, offset + 1, lmmsize);
                LASSERT (lmm != NULL);
                LASSERT_REPSWABBED (request, offset + 1);

                rc = obd_unpackmd (&sbi->ll_osc_conn,
                                   &lsm, lmm, lmmsize);
                if (rc < 0) {
                        CERROR ("Error %d unpacking eadata\n", rc);
                        LBUG();
                        /* XXX don't know if I should do this... */
                        GOTO (out, rc);
                        /* or skip the ll_update_inode but still do
                         * mdc_lock_set_inode() */
                }
                LASSERT (rc >= sizeof (*lsm));
                rc = 0;
        }

        llu_update_inode(pb->pb_ino, body, lsm);

        if (lsm != NULL &&
            llu_i2info(pb->pb_ino)->lli_smd != lsm)
                obd_free_memmd (&sbi->ll_osc_conn, &lsm);

        llu_mdc_lock_set_inode((struct lustre_handle *)it->it_lock_handle,
                               pb->pb_ino);
 out:
        RETURN(rc);
}

int llu_pb_revalidate(struct pnode *pnode, int flags, struct lookup_intent *it)
{
        struct pnode_base *pb = pnode->p_base;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,intent=%x\n",
               pb->pb_name.name, it ? it->it_op : 0);

        /* We don't want to cache negative dentries, so return 0 immediately.
         * We believe that this is safe, that negative dentries cannot be
         * pinned by someone else */
        if (pb->pb_ino == NULL) {
                CDEBUG(D_INODE, "negative pb\n");
                RETURN(0);
        }

        if (it == NULL || it->it_op == IT_GETATTR) {
                /* We could just return 1 immediately, but since we should only
                 * be called in revalidate2 if we already have a lock, let's
                 * verify that. */
                struct inode *inode = pb->pb_ino;
                struct llu_inode_info *lli = llu_i2info(inode);
                struct llu_sb_info *sbi = llu_i2sbi(inode);
                struct obd_device *obddev = class_conn2obd(&sbi->ll_mdc_conn);
                struct ldlm_res_id res_id =
                        { .name = {lli->lli_fid.id, (__u64)lli->lli_fid.generation} };
                struct lustre_handle lockh;

                rc = ldlm_lock_match(obddev->obd_namespace,
                                     LDLM_FL_BLOCK_GRANTED, &res_id,
                                     LDLM_PLAIN, NULL, 0, LCK_PR, &lockh);
                if (rc) {
                        /* de->d_flags &= ~DCACHE_LUSTRE_INVALID; */
                        if (it && it->it_op == IT_GETATTR) {
                                memcpy(it->it_lock_handle, &lockh,
                                       sizeof(lockh));
                                it->it_lock_mode = LCK_PR;
                                LL_SAVE_INTENT(inode, it);
                        } else {
                                ldlm_lock_decref(&lockh, LCK_PR);
                        }
                        RETURN(1);
                }
                rc = ldlm_lock_match(obddev->obd_namespace,
                                     LDLM_FL_BLOCK_GRANTED, &res_id,
                                     LDLM_PLAIN, NULL, 0, LCK_PW, &lockh);
                if (rc) {
                        /* de->d_flags &= ~DCACHE_LUSTRE_INVALID; */
                        if (it && it->it_op == IT_GETATTR) {
                                memcpy(it->it_lock_handle, &lockh,
                                       sizeof(lockh));
                                it->it_lock_mode = LCK_PW;
                                LL_SAVE_INTENT(inode, it);
                        } else {
                                ldlm_lock_decref(&lockh, LCK_PW);
                        }
                        RETURN(1);
                }
                /*
                if (S_ISDIR(de->d_inode->i_mode))
                        ll_invalidate_inode_pages(de->d_inode);
                d_unhash_aliases(de->d_inode);
                */
                RETURN(0);
        }

        rc = llu_intent_lock(pb->pb_parent->pb_ino, pnode, it, pnode_revalidate_finish);
        if (rc < 0) {
                CERROR("ll_intent_lock: rc %d : it->it_status %d\n", rc,
                       it->it_status);
                RETURN(0);
        }
        /* unfortunately ll_intent_lock may cause a callback and revoke our
           dentry */
        /*
        spin_lock(&dcache_lock);
        list_del_init(&de->d_hash);
        spin_unlock(&dcache_lock);
        d_rehash(de);
        */
        RETURN(1);
}

struct inode *llu_iget(struct filesys *fs, struct ll_read_inode2_cookie *lic)
{
        struct inode *inode;
        struct mds_body *body = lic->lic_body;

        /* FIXME need to find the if the inode existed or not FIXME */

        inode = llu_new_inode(fs, body->ino, body->mode);
        if (!inode) {
                CERROR("can't allocate new inode\n");
                return NULL;
        }

        llu_update_inode(inode, body, lic->lic_lsm);

        return inode;
}

static int
llu_lookup2_finish(int flag, struct ptlrpc_request *request,
                   struct inode *parent, struct pnode *pnode,
                   struct lookup_intent *it, int offset, obd_id ino)
{
        struct llu_sb_info *sbi = llu_i2sbi(parent);
        struct inode *inode = NULL;
        struct ll_read_inode2_cookie lic = {.lic_body = NULL, .lic_lsm = NULL};

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */

        /* if (!(flag & LL_LOOKUP_NEGATIVE)) { */
        /* XXX libsysio require the inode must be generated here XXX */
        if ((it->it_op & IT_CREAT) || !(flag & LL_LOOKUP_NEGATIVE)) {
                ENTRY;

                /* We only get called if the mdc_enqueue() called from
                 * ll_intent_lock() was successful.  Therefore the mds_body
                 * is present and correct, and the eadata is present if
                 * body->eadatasize != 0 (but still opaque, so only
                 * obd_unpackmd() can check the size) */
                lic.lic_body = lustre_msg_buf(request->rq_repmsg, offset,
                                              sizeof (*lic.lic_body));
                LASSERT (lic.lic_body != NULL);
                LASSERT_REPSWABBED (request, offset);

                if (S_ISREG(lic.lic_body->mode) &&
                    (lic.lic_body->valid & OBD_MD_FLEASIZE)) {
                        struct lov_mds_md    *lmm;
                        int                   lmm_size;
                        int                   rc;

                        lmm_size = lic.lic_body->eadatasize;
                        if (lmm_size == 0) {
                                CERROR("OBD_MD_FLEASIZE set but "
                                       "eadatasize 0\n");
                                RETURN (-EPROTO);
                        }
                        lmm = lustre_msg_buf(request->rq_repmsg, offset + 1,
                                             lmm_size);
                        LASSERT(lmm != NULL);
                        LASSERT_REPSWABBED (request, offset + 1);

                        rc = obd_unpackmd(&sbi->ll_osc_conn,
                                          &lic.lic_lsm, lmm, lmm_size);
                        if (rc < 0) {
                                CERROR ("Error %d unpacking eadata\n", rc);
                                RETURN (rc);
                        }
                        LASSERT (rc >= sizeof (*lic.lic_lsm));
                }

                /* Both ENOMEM and an RPC timeout are possible in ll_iget; which
                 * to pick?  A more generic EIO?  -phik */
                inode = llu_iget(pnode->p_mount->mnt_fs, &lic);
                if (!inode) {
                        /* free the lsm if we allocated one above */
                        if (lic.lic_lsm != NULL)
                                obd_free_memmd(&sbi->ll_osc_conn, &lic.lic_lsm);
                        RETURN(-ENOMEM);
                } else if (lic.lic_lsm != NULL &&
                           llu_i2info(inode)->lli_smd != lic.lic_lsm) {
                        obd_free_memmd(&sbi->ll_osc_conn, &lic.lic_lsm);
                }

                /* If this is a stat, get the authoritative file size */
                if (it->it_op == IT_GETATTR && S_ISREG(inode->i_mode) &&
                    llu_i2info(inode)->lli_smd != NULL) {
                        struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                        struct lustre_handle lockh = {0, 0};
                        struct lov_stripe_md *lsm = llu_i2info(inode)->lli_smd;
                        ldlm_error_t rc;

                        LASSERT(lsm->lsm_object_id != 0);

                        rc = llu_extent_lock(NULL, inode, lsm, LCK_PR, &extent,
                                            &lockh);
                        if (rc != ELDLM_OK)
                                RETURN(-EIO);
                        llu_extent_unlock(NULL, inode, lsm, LCK_PR, &lockh);
                }

                /* dentry = *de = ll_find_alias(inode, dentry); */

                /* We asked for a lock on the directory, and may have been
                 * granted a lock on the inode.  Just in case, fixup the data
                 * pointer. */
                llu_mdc_lock_set_inode((struct lustre_handle*)it->it_lock_handle,
                                       inode);
        } else {
                ENTRY;
        }
#if 0
        dentry->d_op = &ll_d_ops;
        ll_set_dd(dentry);

        if (dentry == saved)
                d_add(dentry, inode);
#endif
        pnode->p_base->pb_ino = inode;

        RETURN(0);
}

static int llu_lookup2(struct inode *parent, struct pnode *pnode,
                       struct lookup_intent *it)
{
        int rc;
        ENTRY;

        /*
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu,intent=%s\n",
               dentry->d_name.name, parent->i_ino, LL_IT2STR(it));
         */

        rc = llu_intent_lock(parent, pnode, it, llu_lookup2_finish);
        if (rc < 0) {
                CDEBUG(D_INFO, "ll_intent_lock: %d\n", rc);
        }

        RETURN(rc);
}

static void translate_lookup_intent(struct intent *intent,
                                    struct lookup_intent *it)
{
        memset(it, 0, sizeof(*it));

        /* FIXME libsysio will assign intent like following:
         * open: INT_OPEN [| INT_CREAT]
         * mkdir: INT_CREAT
         *
         * following logic is adjusted for libsysio
         */

        it->it_flags = intent->int_arg2 ? *((int*)intent->int_arg2) : 0;

        if (intent->int_opmask & INT_OPEN)
                it->it_op |= IT_OPEN;
        else if (intent->int_opmask & INT_CREAT)
                it->it_op |= IT_LOOKUP;

        /* FIXME libsysio has strange code on intent handling,
         * more check later */
        if (it->it_flags & O_CREAT) {
                it->it_op |= IT_CREAT;
                it->it_mode = *((int*)intent->int_arg1);
        }
        if (intent->int_opmask & INT_GETATTR)
                it->it_op |= IT_GETATTR;
        /* libsysio is different to linux vfs when doing unlink/rmdir,
         * INT_UPDPARENT was passed down during name resolution. Here
         * we treat it as normal lookup, later unlink()/rmdir() will
         * do the actual work */
        if (intent->int_opmask & INT_UPDPARENT)
                it->it_op |= IT_LOOKUP;
}

int llu_iop_lookup(struct pnode *pnode,
                   struct inode **inop,
                   struct intent *intnt,
                   const char *path)
{
        struct lookup_intent it_buf, *it;
        int rc;

        *inop = NULL;

        /* the mount root inode have no name, so don't call
         * remote in this case. but probably we need revalidate
         * it here? FIXME */
        if (pnode->p_mount->mnt_root == pnode) {
                struct inode *i = pnode->p_base->pb_ino;
                *inop = i;
                return 0;
        }

        if (!pnode->p_base->pb_name.len)
                return -EINVAL;

        /* libsysio trick */
        if (intnt && path)
                intnt = NULL;

        if (intnt) {
                translate_lookup_intent(intnt, &it_buf);
                it = &it_buf;
        } else
                it = NULL;

        /* param flags is not used, let it be 0 */
        if (llu_pb_revalidate(pnode, 0, it)) {
                LASSERT(pnode->p_base->pb_ino);
                *inop = pnode->p_base->pb_ino;
                return 0;
        }

        rc = llu_lookup2(pnode->p_parent->p_base->pb_ino, pnode, it);
        if (!rc) {
                if (!pnode->p_base->pb_ino)
                        rc = -ENOENT;
                else
                        *inop = pnode->p_base->pb_ino;
        }

        return rc;
}

