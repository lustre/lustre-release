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

#include "llite_lib.h"

static void ll_intent_release(struct lookup_intent *it)
{
        struct lustre_handle *handle;
        ENTRY;

        if (it->d.lustre.it_lock_mode) {
                handle = (struct lustre_handle *)&it->d.lustre.it_lock_handle;
                CDEBUG(D_DLMTRACE, "releasing lock with cookie "LPX64
                       " from it %p\n",
                       handle->cookie, it);
                ldlm_lock_decref(handle, it->d.lustre.it_lock_mode);

                /* intent_release may be called multiple times, from
                   this thread and we don't want to double-decref this
                   lock (see bug 494) */
                it->d.lustre.it_lock_mode = 0;
        }
        it->it_magic = 0;
        it->it_op_release = 0;
        EXIT;
}

/*
 * remove the stale inode from pnode
 */
void unhook_stale_inode(struct pnode *pno)
{
        struct inode *inode = pno->p_base->pb_ino;
        ENTRY;

        LASSERT(inode);
        LASSERT(llu_i2info(inode)->lli_stale_flag);

        pno->p_base->pb_ino = NULL;

        if (!llu_i2info(inode)->lli_open_count) {
                CDEBUG(D_INODE, "unhook inode %p (ino %lu) from pno %p\n",
                                inode, llu_i2info(inode)->lli_st_ino, pno);
                I_RELE(inode);
                if (!inode->i_ref)
                        _sysio_i_gone(inode);
        }

        EXIT;
        return;
}

void llu_lookup_finish_locks(struct lookup_intent *it, struct pnode *pnode)
{
        LASSERT(it);
        LASSERT(pnode);

        if (it && pnode->p_base->pb_ino != NULL) {
                struct inode *inode = pnode->p_base->pb_ino;
                CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%lu)\n",
                       inode, llu_i2info(inode)->lli_st_ino,
                       llu_i2info(inode)->lli_st_generation);
                mdc_set_lock_data(&it->d.lustre.it_lock_handle, inode);
        }

        /* drop IT_LOOKUP locks */
        if (it->it_op == IT_LOOKUP)
                ll_intent_release(it);

}

static inline void llu_invalidate_inode_pages(struct inode * inode)
{
        /* do nothing */
}

static int llu_mdc_blocking_ast(struct ldlm_lock *lock,
                                struct ldlm_lock_desc *desc,
                                void *data, int flag)
{
        int rc;
        struct lustre_handle lockh;
        ENTRY;


        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
                rc = ldlm_cli_cancel(&lockh);
                if (rc < 0) {
                        CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
                        RETURN(rc);
                }
                break;
        case LDLM_CB_CANCELING: {
                struct inode *inode = llu_inode_from_lock(lock);
                struct llu_inode_info *lli;

                /* Invalidate all dentries associated with this inode */
                if (inode == NULL)
                        break;

                lli =  llu_i2info(inode);

                clear_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &lli->lli_flags);

                if (lock->l_resource->lr_name.name[0] != lli->lli_st_ino ||
                    lock->l_resource->lr_name.name[1] != lli->lli_st_generation) {
                        LDLM_ERROR(lock, "data mismatch with ino %lu/%lu",
                                   lli->lli_st_ino, lli->lli_st_generation);
                }
                if (S_ISDIR(lli->lli_st_mode)) {
                        CDEBUG(D_INODE, "invalidating inode %lu\n",
                               lli->lli_st_ino);

                        llu_invalidate_inode_pages(inode);
                }

/*
                if (inode->i_sb->s_root &&
                    inode != inode->i_sb->s_root->d_inode)
                        ll_unhash_aliases(inode);
*/
                I_RELE(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

int llu_pb_revalidate(struct pnode *pnode, int flags, struct lookup_intent *it)
{
        struct pnode_base *pb = pnode->p_base;
        struct ll_fid pfid, cfid;
        struct it_cb_data icbd;
        struct ll_uctxt ctxt;
        struct ptlrpc_request *req = NULL;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct obd_export *exp;
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

        /* check stale inode */
        if (llu_i2info(pb->pb_ino)->lli_stale_flag)
                unhook_stale_inode(pnode);

        /* check again because unhook_stale_inode() might generate
         * negative pnode */
        if (pb->pb_ino == NULL) {
                CDEBUG(D_INODE, "negative pb\n");
                RETURN(0);
        }

        /* This is due to bad interaction with libsysio. remove this when we
         * switched to libbsdio XXX
         */
        {
                struct llu_inode_info *lli = llu_i2info(pb->pb_ino);
                if (lli->lli_it) {
                        CDEBUG(D_INODE, "inode %lu still have intent "
                                        "%p(opc 0x%x), release it\n",
                                        lli->lli_st_ino, lli->lli_it,
                                        lli->lli_it->it_op);
                        ll_intent_release(lli->lli_it);
                        OBD_FREE(lli->lli_it, sizeof(*lli->lli_it));
                        lli->lli_it = NULL;
                }
        }

        exp = llu_i2mdcexp(pb->pb_ino);
        ll_inode2fid(&pfid, pnode->p_parent->p_base->pb_ino);
        ll_inode2fid(&cfid, pb->pb_ino);
        icbd.icbd_parent = pnode->p_parent->p_base->pb_ino;
        icbd.icbd_child = pnode;

        if (!it) {
                it = &lookup_it;
                it->it_op_release = ll_intent_release;
        }

        ll_i2uctxt(&ctxt, pnode->p_parent->p_base->pb_ino, pb->pb_ino);

        rc = mdc_intent_lock(exp, &ctxt, &pfid,
                             pb->pb_name.name, pb->pb_name.len,
                             NULL, 0, &cfid, it, flags, &req,
                             llu_mdc_blocking_ast);
        /* If req is NULL, then mdc_intent_lock only tried to do a lock match;
         * if all was well, it will return 1 if it found locks, 0 otherwise. */
        if (req == NULL && rc >= 0)
                GOTO(out, rc);

        /* Note: ll_intent_lock may cause a callback, check this! */

        if (it->it_op & (IT_OPEN | IT_GETATTR))
                LL_SAVE_INTENT(pb->pb_ino, it);
        RETURN(1);
 out:
        if (req)
                ptlrpc_req_finished(req);
        if (rc == 0) {
                LASSERT(pb->pb_ino);
                if (S_ISDIR(llu_i2info(pb->pb_ino)->lli_st_mode))
                        llu_invalidate_inode_pages(pb->pb_ino);
                llu_i2info(pb->pb_ino)->lli_stale_flag = 1;
                unhook_stale_inode(pnode);
        } else {
                llu_lookup_finish_locks(it, pnode);
                llu_i2info(pb->pb_ino)->lli_stale_flag = 0;
                if (it->it_op & (IT_OPEN | IT_GETATTR))
                        LL_SAVE_INTENT(pb->pb_ino, it);
        }
        RETURN(rc);
}

static int lookup_it_finish(struct ptlrpc_request *request, int offset,
                            struct lookup_intent *it, void *data)
{
        struct it_cb_data *icbd = data;
        struct pnode *child = icbd->icbd_child;
        struct inode *parent = icbd->icbd_parent;
        struct llu_sb_info *sbi = llu_i2sbi(parent);
        struct inode *inode = NULL;
        int rc;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return 
         * Note: libsysio require the inode must be generated here
         */
        if ((it->it_op & IT_CREAT) || !it_disposition(it, DISP_LOOKUP_NEG)) {
                struct lustre_md md;
                struct llu_inode_info *lli;
                ENTRY;

                rc = mdc_req2lustre_md(request, offset, sbi->ll_osc_exp, &md);
                if (rc)
                        RETURN(rc);

                inode = llu_iget(parent->i_fs, &md);
                if (!inode) {
                        /* free the lsm if we allocated one above */
                        if (md.lsm != NULL)
                                obd_free_memmd(sbi->ll_osc_exp, &md.lsm);
                        RETURN(-ENOMEM);
                } else if (md.lsm != NULL &&
                           llu_i2info(inode)->lli_smd != md.lsm) {
                        obd_free_memmd(sbi->ll_osc_exp, &md.lsm);
                }

                lli = llu_i2info(inode);

                /* If this is a stat, get the authoritative file size */
                if (it->it_op == IT_GETATTR && S_ISREG(lli->lli_st_mode) &&
                    lli->lli_smd != NULL) {
                        struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                        struct lustre_handle lockh = {0};
                        struct lov_stripe_md *lsm = lli->lli_smd;
                        ldlm_error_t rc;

                        LASSERT(lsm->lsm_object_id != 0);

                        rc = llu_extent_lock(NULL, inode, lsm, LCK_PR, &extent,
                                            &lockh);
                        if (rc != ELDLM_OK) {
                                I_RELE(inode);
                                RETURN(-EIO);
                        }
                        llu_extent_unlock(NULL, inode, lsm, LCK_PR, &lockh);
                }
        } else {
                ENTRY;
        }

        /* intent will be further used in cases of open()/getattr() */
        if (inode && (it->it_op & (IT_OPEN | IT_GETATTR)))
                LL_SAVE_INTENT(inode, it);

        child->p_base->pb_ino = inode;

        RETURN(0);
}

struct inode *llu_inode_from_lock(struct ldlm_lock *lock)
{
        struct inode *inode;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);

        if (lock->l_ast_data) {
                inode = (struct inode *)lock->l_ast_data;
                I_REF(inode);
        } else
                inode = NULL;

        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return inode;
}

static int llu_lookup_it(struct inode *parent, struct pnode *pnode,
                         struct lookup_intent *it, int flags)
{
        struct ll_fid pfid;
        struct ll_uctxt ctxt;
        struct it_cb_data icbd;
        struct ptlrpc_request *req = NULL;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        int rc;
        ENTRY;

#define EXT2_NAME_LEN (255) /* XXX */

        if (pnode->p_base->pb_name.len > EXT2_NAME_LEN)
                RETURN(-ENAMETOOLONG);

        if (!it) {
                it = &lookup_it;
                it->it_op_release = ll_intent_release;
        }

        icbd.icbd_child = pnode;
        icbd.icbd_parent = parent;
        icbd.icbd_child = pnode;
        ll_inode2fid(&pfid, parent);
        ll_i2uctxt(&ctxt, parent, NULL);

        rc = mdc_intent_lock(llu_i2mdcexp(parent), &ctxt, &pfid,
                             pnode->p_base->pb_name.name,
                             pnode->p_base->pb_name.len,
                             NULL, 0, NULL, it, flags, &req,
                             llu_mdc_blocking_ast);
        if (rc < 0)
                GOTO(out, rc);
        
        rc = lookup_it_finish(req, 1, it, &icbd);
        if (rc != 0) {
                ll_intent_release(it);
                GOTO(out, rc);
        }

        llu_lookup_finish_locks(it, pnode);

 out:
        if (req)
                ptlrpc_req_finished(req);
        return rc;
}

static struct lookup_intent*
translate_lookup_intent(struct intent *intent, const char *path)
{
        struct lookup_intent *it;
        int fmode;

        /* libsysio trick */
        if (!intent || path) {
                CDEBUG(D_VFSTRACE, "not intent needed\n");
                return NULL;
        }

        OBD_ALLOC(it, sizeof(*it));
        LASSERT(it);

        memset(it, 0, sizeof(*it));

        /* libsysio will assign intent like following:
         * NOTE: INT_CREAT has include INT_UPDPARENT
         *
         * open: INT_OPEN [| INT_CREAT]
         * mkdir: INT_CREAT
         * symlink: INT_CREAT
         * unlink: INT_UPDPARENT
         * rmdir: INT_UPDPARENT
         * mknod: INT_CREAT
         * stat: INT_GETATTR
         * setattr: NULL
         *
         * following logic is adjusted for libsysio
         */

        it->it_flags = intent->int_arg2 ? *((int*)intent->int_arg2) : 0;

        if (intent->int_opmask & INT_OPEN) {
                it->it_op |= IT_OPEN;

                /* convert access mode from O_ to FMODE_ */
                if (it->it_flags & O_WRONLY)
                        fmode = FMODE_WRITE;
                else if (it->it_flags & O_RDWR)
                        fmode = FMODE_READ | FMODE_WRITE;
                else
                        fmode = FMODE_READ;
                it->it_flags &= ~O_ACCMODE;
                it->it_flags |= fmode;
        }

        /* XXX libsysio has strange code on intent handling,
         * more check later */
        if (it->it_flags & O_CREAT) {
                it->it_op |= IT_CREAT;
                it->it_create_mode = *((int*)intent->int_arg1);
        }

        if (intent->int_opmask & INT_GETATTR)
                it->it_op |= IT_GETATTR;

        LASSERT(!(intent->int_opmask & INT_SETATTR));

        /* libsysio is different to linux vfs when doing unlink/rmdir,
         * INT_UPDPARENT was passed down during name resolution. Here
         * we treat it as normal lookup, later unlink()/rmdir() will
         * do the actual work */

        /* conform to kernel code, if only IT_LOOKUP was set, don't
         * pass down it */
        if (!it->it_op || it->it_op == IT_LOOKUP) {
                OBD_FREE(it, sizeof(*it));
                it = NULL;
        }
        if (it)
                it->it_op_release = ll_intent_release;

        CDEBUG(D_VFSTRACE, "final intent 0x%x\n", it ? it->it_op : 0);
        return it;
}

int llu_iop_lookup(struct pnode *pnode,
                   struct inode **inop,
                   struct intent *intnt,
                   const char *path)
{
        struct lookup_intent *it;
        int rc;
        ENTRY;

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
                RETURN(-EINVAL);

        it = translate_lookup_intent(intnt, path);

        /* param flags is not used, let it be 0 */
        if (llu_pb_revalidate(pnode, 0, it)) {
                LASSERT(pnode->p_base->pb_ino);
                *inop = pnode->p_base->pb_ino;
                RETURN(0);
        }

        rc = llu_lookup_it(pnode->p_parent->p_base->pb_ino, pnode, it, 0);
        if (!rc) {
                if (!pnode->p_base->pb_ino)
                        rc = -ENOENT;
                else
                        *inop = pnode->p_base->pb_ino;
        }

        RETURN(rc);
}

