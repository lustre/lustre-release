/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
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
 *
 *  derived in small part from linux/fs/ext2/namei.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  Big-endian to little-endian byte-swapping/bitmaps by
 *        David S. Miller (davem@caip.rutgers.edu), 1995
 *  Directory entry file type support and forward compatibility hooks
 *      for B-tree directories by Theodore Ts'o (tytso@mit.edu), 1998
 */

#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp_lock.h>
#include <linux/quotaops.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/obd_support.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_dlm.h>
#include "llite_internal.h"

/* methods */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
static int ll_test_inode(struct inode *inode, unsigned long ino, void *opaque)
#else
static int ll_test_inode(struct inode *inode, void *opaque)
#endif
{
        struct lustre_md *md = opaque;

        if (!(md->body->valid & (OBD_MD_FLGENER | OBD_MD_FLID)))
                CERROR("invalid generation\n");
        CDEBUG(D_VFSTRACE, "comparing inode %p ino %lu/%u to body %u/%u\n",
               inode, inode->i_ino, inode->i_generation, 
               md->body->ino, md->body->generation);

        if (inode->i_generation != md->body->generation)
                return 0;

        /* Apply the attributes in 'opaque' to this inode */
        ll_update_inode(inode, md->body, md->lsm);
        return 1;
}

extern struct dentry_operations ll_d_ops;

int ll_unlock(__u32 mode, struct lustre_handle *lockh)
{
        ENTRY;

        ldlm_lock_decref(lockh, mode);

        RETURN(0);
}

/* Get an inode by inode number (already instantiated by the intent lookup).
 * Returns inode or NULL
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
int ll_set_inode(struct inode *inode, void *opaque)
{
        ll_read_inode2(inode, opaque);
        return 0;
}
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *md)
{
        struct inode *inode;

        LASSERT(hash != 0);
        inode = iget5_locked(sb, hash, ll_test_inode, ll_set_inode, md);

        if (!inode)
                return (NULL);              /* removed ERR_PTR(-ENOMEM) -eeb */

        if (inode->i_state & I_NEW)
                unlock_new_inode(inode);

        // XXX Coda always fills inodes, should Lustre?
        return inode;
}
#else
struct inode *ll_iget(struct super_block *sb, ino_t hash,
                      struct lustre_md *md)
{
        struct inode *inode;
        LASSERT(hash != 0);
        inode = iget4(sb, hash, ll_test_inode, md);
        CDEBUG(D_VFSTRACE, "inode: %lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);
        return inode;
}
#endif

static int ll_intent_to_lock_mode(struct lookup_intent *it)
{
        /* CREAT needs to be tested before open (both could be set) */
        if (it->it_op & IT_CREAT)
                return LCK_PW;
        else if (it->it_op & (IT_READDIR | IT_GETATTR | IT_OPEN | IT_LOOKUP))
                return LCK_PR;

        LBUG();
        RETURN(-EINVAL);
}

int ll_it_open_error(int phase, struct lookup_intent *it)
{
        if (it_disposition(it, DISP_OPEN_OPEN)) {
                if (phase == DISP_OPEN_OPEN)
                        return it->it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_OPEN_CREATE)) {
                if (phase == DISP_OPEN_CREATE)
                        return it->it_status;
                else
                        return 0;
        }

        if (it_disposition(it, DISP_LOOKUP_EXECD)) {
                if (phase == DISP_LOOKUP_EXECD)
                        return it->it_status;
                else
                        return 0;
        }
        CERROR("it disp: %X, status: %d\n", it->it_disposition, it->it_status);
        LBUG();
        return 0;
}

int ll_mdc_blocking_ast(struct ldlm_lock *lock, struct ldlm_lock_desc *desc,
                        void *data, int flag)
{
        int rc;
        struct lustre_handle lockh;
        struct inode *inode = lock->l_data;
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
                /* Invalidate all dentries associated with this inode */
                if (inode == NULL)
                        break;
                if (lock->l_resource->lr_name.name[0] != inode->i_ino ||
                    lock->l_resource->lr_name.name[1] != inode->i_generation) {
                        LDLM_ERROR(lock, "data mismatch with ino %lu/%u",
                                   inode->i_ino, inode->i_generation);
                }
                if (S_ISDIR(inode->i_mode)) {
                        CDEBUG(D_INODE, "invalidating inode %lu\n",
                               inode->i_ino);

                        ll_invalidate_inode_pages(inode);
                }

#warning FIXME: we should probably free this inode if there are no aliases
                if (inode->i_sb->s_root &&
                    inode != inode->i_sb->s_root->d_inode)
                        ll_unhash_aliases(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

int ll_mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                         int flags, void *opaque)
{
        struct ldlm_res_id res_id =
                { .name = {inode->i_ino, inode->i_generation} };
        struct obd_device *obddev = class_conn2obd(conn);
        ENTRY;
        RETURN(ldlm_cli_cancel_unused(obddev->obd_namespace, &res_id, flags,
                                      opaque));
}

void ll_prepare_mdc_op_data(struct mdc_op_data *data,
                            struct inode *i1,
                            struct inode *i2,
                            const char *name,
                            int namelen,
                            int mode)
{
        LASSERT(i1);

        data->ino1 = i1->i_ino;
        data->gen1 = i1->i_generation;
        data->typ1 = i1->i_mode & S_IFMT;
        data->gid1 = i1->i_gid;

        if (i2) {
                data->ino2 = i2->i_ino;
                data->gen2 = i2->i_generation;
                data->typ2 = i2->i_mode & S_IFMT;
                data->gid2 = i2->i_gid;
        } else {
                data->ino2 = 0;
        }

        data->name = name;
        data->namelen = namelen;
        data->mode = mode;
}

/* 
 *This long block is all about fixing up the local state so that it is
 *correct as of the moment _before_ the operation was applied; that
 *way, the VFS will think that everything is normal and call Lustre's
 *regular VFS methods.
 *
 * If we're performing a creation, that means that unless the creation
 * failed with EEXIST, we should fake up a negative dentry.
 *
 * For everything else, we want to lookup to succeed.
 *
 * One additional note: if CREATE or OPEN succeeded, we add an extra
 * reference to the request because we need to keep it around until
 * ll_create/ll_open gets called.
 *
 * The server will return to us, in it_disposition, an indication of
 * exactly what it_status refers to.
 *
 * If DISP_OPEN_OPEN is set, then it_status refers to the open() call,
 * otherwise if DISP_OPEN_CREATE is set, then it status is the
 * creation failure mode.  In either case, one of DISP_LOOKUP_NEG or
 * DISP_LOOKUP_POS will be set, indicating whether the child lookup
 * was successful.
 *
 * Else, if DISP_LOOKUP_EXECD then it_status is the rc of the child
 * lookup.
 */
int ll_intent_lock(struct inode *parent, struct dentry **de,
                   struct lookup_intent *it, int flags, intent_finish_cb intent_finish)
{
        struct dentry *dentry = *de;
        struct inode *inode = dentry->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct lustre_handle lockh;
        struct lookup_intent lookup_it = { .it_op = IT_LOOKUP };
        struct ptlrpc_request *request;
        int rc = 0;
        struct mds_body *mds_body;
        int mode;
        obd_id ino = 0;
        ENTRY;

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        if (it && it->it_magic != INTENT_MAGIC) { 
                CERROR("WARNING: uninitialized intent\n");
                LBUG();
                intent_init(it, IT_LOOKUP, 0);
        }
        if (it->it_op == IT_GETATTR || 
            it->it_op == 0)
                it->it_op = IT_LOOKUP;
        
#endif
        if (!it ||it->it_op == IT_GETXATTR)
                it = &lookup_it;

        it->it_op_release = ll_intent_release;

        CDEBUG(D_DLMTRACE, "name: %*s, intent: %s\n", dentry->d_name.len,
               dentry->d_name.name, ldlm_it2str(it->it_op));
        
        if (dentry->d_name.len > EXT2_NAME_LEN)
                RETURN(-ENAMETOOLONG);

        /* This function may be called twice, we only once want to
           execute the request associated with the intent. If it was
           done already, we skip past this and use the results. */ 
        if (!it_disposition(it, DISP_ENQ_COMPLETE)) {
                struct mdc_op_data op_data;

                ll_prepare_mdc_op_data(&op_data, parent, dentry->d_inode,
                                       dentry->d_name.name, dentry->d_name.len,
                                       0);

                rc = mdc_enqueue(&sbi->ll_mdc_conn, LDLM_PLAIN, it,
                                 ll_intent_to_lock_mode(it), &op_data,
                                 &lockh, NULL, 0, ldlm_completion_ast,
                                 ll_mdc_blocking_ast, NULL);
                if (rc < 0)
                        RETURN(rc);
                memcpy(it->it_lock_handle, &lockh, sizeof(lockh));
        }
        request = it->it_data;
        LASSERT(request != NULL);

        /* non-zero it_disposition indicates that the server performed the
         * intent on our behalf. */
        LASSERT(it_disposition(it, DISP_IT_EXECD));

                
        mds_body = lustre_msg_buf(request->rq_repmsg, 1, sizeof(*mds_body));
        LASSERT(mds_body != NULL);           /* mdc_enqueue checked */
        LASSERT_REPSWABBED(request, 1); /* mdc_enqueue swabbed */

        /* XXX everything with fids please, no ino's inode's etc */
        ino = mds_body->fid1.id;
        mode = mds_body->mode;

        /*We were called from revalidate2: did we find the same inode?*/
        if (inode && 
            (ino != inode->i_ino ||
             mds_body->fid1.generation != inode->i_generation)) {
                it_set_disposition(it, DISP_ENQ_COMPLETE);
                RETURN(-ESTALE);
        }

        /* If we're doing an IT_OPEN which did not result in an actual
         * successful open, then we need to remove the bit which saves
         * this request for unconditional replay. */
        if (it->it_op & IT_OPEN) {
                if (!it_disposition(it, DISP_OPEN_OPEN) ||
                    it->it_status != 0) {
                        unsigned long flags;
                
                        spin_lock_irqsave (&request->rq_lock, flags);
                        request->rq_replay = 0;
                        spin_unlock_irqrestore (&request->rq_lock, flags);
                }
        }

        rc = ll_it_open_error(DISP_LOOKUP_EXECD, it);
        if (rc)
                GOTO(drop_req, rc);
        
        /* keep requests around for the multiple phases of the call
         * this shows the DISP_XX must guarantee we make it into the call 
         */ 
        if (it_disposition(it, DISP_OPEN_CREATE))
                ptlrpc_request_addref(request);
        if (it_disposition(it, DISP_OPEN_OPEN))
                ptlrpc_request_addref(request);
        
        if (it->it_op & IT_CREAT) {
                /* XXX this belongs in ll_create_iit */
        } else if (it->it_op == IT_OPEN) {
                LASSERT(!it_disposition(it, DISP_OPEN_CREATE));
        } else 
                LASSERT(it->it_op & (IT_GETATTR | IT_LOOKUP));

        if (intent_finish != NULL) {
                struct lustre_handle old_lock;
                struct ldlm_lock *lock;

                rc = intent_finish(request, parent, de, it, 1, ino);
                dentry = *de; /* intent_finish may change *de */
                inode = dentry->d_inode;
                if (rc != 0)
                        GOTO(drop_lock, rc);

                /* The intent processing may well have given us a lock different
                 * from the one we requested.  If we already have a matching
                 * lock, then cancel the new one.  (We have to do this here,
                 * instead of in mdc_enqueue, because we need to use the child's
                 * inode as the l_data to match, and that's not available until
                 * intent_finish has performed the iget().) */
                lock = ldlm_handle2lock(&lockh);
                if (lock) {
                        LDLM_DEBUG(lock, "matching against this");
                        LDLM_LOCK_PUT(lock);
                        memcpy(&old_lock, &lockh, sizeof(lockh));
                        if (ldlm_lock_match(NULL,
                                            LDLM_FL_BLOCK_GRANTED |
                                            LDLM_FL_MATCH_DATA,
                                            NULL, LDLM_PLAIN, NULL, 0, LCK_NL,
                                            inode, &old_lock)) {
                                ldlm_lock_decref_and_cancel(&lockh,
                                                            it->it_lock_mode);
                                memcpy(&lockh, &old_lock, sizeof(old_lock));
                                memcpy(it->it_lock_handle, &lockh,
                                       sizeof(lockh));
                        }
                }

        }
        ptlrpc_req_finished(request);

        CDEBUG(D_DENTRY, "D_IT dentry %p intent: %s status %d disp %x\n",
               dentry, ldlm_it2str(it->it_op), it->it_status, it->it_disposition);
        
        /* drop IT_LOOKUP locks */
        if (it->it_op == IT_LOOKUP)
                ll_intent_release(it);
        RETURN(rc);

 drop_lock:
        ll_intent_release(it);
 drop_req:
        ptlrpc_req_finished(request);
        RETURN(rc);
}

/* Search "inode"'s alias list for a dentry that has the same name and parent as
 * de.  If found, return it.  If not found, return de. */
struct dentry *ll_find_alias(struct inode *inode, struct dentry *de)
{
        struct list_head *tmp;

        spin_lock(&dcache_lock);
        list_for_each(tmp, &inode->i_dentry) {
                struct dentry *dentry = list_entry(tmp, struct dentry, d_alias);

                /* We are called here with 'de' already on the aliases list. */
                if (dentry == de) {
                        CERROR("whoops\n");
                        continue;
                }

                if (dentry->d_parent != de->d_parent)
                        continue;

                if (dentry->d_name.len != de->d_name.len)
                        continue;

                if (memcmp(dentry->d_name.name, de->d_name.name,
                           de->d_name.len) != 0)
                        continue;

                if (!list_empty(&dentry->d_lru))
                        list_del_init(&dentry->d_lru);

                hlist_del_init(&dentry->d_hash);
                __d_rehash(dentry, 0); /* avoid taking dcache_lock inside */
                spin_unlock(&dcache_lock);
                atomic_inc(&dentry->d_count);
                iput(inode);
                dentry->d_flags &= ~DCACHE_LUSTRE_INVALID;
                return dentry;
        }

        spin_unlock(&dcache_lock);

        return de;
}

static int
lookup2_finish(struct ptlrpc_request *request,
               struct inode *parent, struct dentry **de,
               struct lookup_intent *it, int offset, obd_id ino)
{
        struct ll_sb_info *sbi = ll_i2sbi(parent);
        struct dentry *dentry = *de, *saved = *de;
        struct inode *inode = NULL;
        int rc;

        /* NB 1 request reference will be taken away by ll_intent_lock()
         * when I return */
        if (!it_disposition(it, DISP_LOOKUP_NEG)) {
                struct lustre_md md;
                ENTRY;

                rc =mdc_req2lustre_md(request, offset, &sbi->ll_osc_conn, &md);
                if (rc) 
                        RETURN(rc);

                inode = ll_iget(dentry->d_sb, ino, &md);
                if (!inode) {
                        /* free the lsm if we allocated one above */
                        if (md.lsm != NULL)
                                obd_free_memmd(&sbi->ll_osc_conn, &md.lsm);
                        RETURN(-ENOMEM);
                } else if (md.lsm != NULL &&
                           ll_i2info(inode)->lli_smd != md.lsm) {
                        obd_free_memmd(&sbi->ll_osc_conn, &md.lsm);
                }

                /* If this is a stat, get the authoritative file size */
                if (it->it_op == IT_GETATTR && S_ISREG(inode->i_mode) &&
                    ll_i2info(inode)->lli_smd != NULL) {
                        struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                        struct lustre_handle lockh = {0};
                        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                        ldlm_error_t rc;

                        LASSERT(lsm->lsm_object_id != 0);

                        rc = ll_extent_lock(NULL, inode, lsm, LCK_PR, &extent,
                                            &lockh);
                        if (rc != ELDLM_OK) {
                                iput(inode);
                                RETURN(-EIO);
                        }
                        ll_extent_unlock(NULL, inode, lsm, LCK_PR, &lockh);
                }

                dentry = *de = ll_find_alias(inode, dentry);

                /* We asked for a lock on the directory, and may have been
                 * granted a lock on the inode.  Just in case, fixup the data
                 * pointer. */
                CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
                       inode, inode->i_ino, inode->i_generation);
                ldlm_lock_set_data((struct lustre_handle*)it->it_lock_handle,
                                   inode);
        } else {
                ENTRY;
        }

        dentry->d_op = &ll_d_ops;
        ll_set_dd(dentry);

        if (dentry == saved)
                d_add(dentry, inode);

        RETURN(0);
}

static struct dentry *ll_lookup_it(struct inode *parent, struct dentry *dentry,
                                   struct lookup_intent *it, int flags)
{
        struct dentry *save = dentry, *retval;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, parent->i_ino, parent->i_generation,
               parent, LL_IT2STR(it));

        if (d_mountpoint(dentry)) { 
                CERROR("Tell Peter, lookup on mtpt, it %s\n", LL_IT2STR(it));
        }

        rc = ll_intent_lock(parent, &dentry, it, flags, lookup2_finish);
        if (rc < 0) {
                CDEBUG(D_INFO, "ll_intent_lock: %d\n", rc);
                GOTO(out, retval = ERR_PTR(rc));
        }

        if (dentry == save)
                GOTO(out, retval = NULL);
        else
                GOTO(out, retval = dentry);
 out:
        return retval;
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static struct dentry *ll_lookup_nd(struct inode *parent, struct dentry *dentry, 
                                   struct nameidata *nd)
{
        struct dentry *de;
        ENTRY;

        if (nd->flags & LOOKUP_LAST && !(nd->flags & LOOKUP_LINK_NOTLAST))
                de = ll_lookup_it(parent, dentry, &nd->it, nd->flags);
        else 
                de = ll_lookup_it(parent, dentry, NULL, 0);

        RETURN(de);
}
#endif

static int ll_mdc_unlink(struct inode *dir, struct inode *child, __u32 mode,
                         const char *name, int len)
{
        struct ptlrpc_request *request = NULL;
        struct mds_body *body;
        struct lov_mds_md *eadata;
        struct lov_stripe_md *lsm = NULL;
        struct obd_trans_info oti = { 0 };
        struct mdc_op_data op_data;
        struct obdo *oa;
        int rc;
        ENTRY;

        ll_prepare_mdc_op_data(&op_data, dir, child, name, len, mode);
        rc = mdc_unlink(&ll_i2sbi(dir)->ll_mdc_conn, &op_data, &request);
        if (rc)
                GOTO(out, rc);
        /* req is swabbed so this is safe */
        body = lustre_msg_buf(request->rq_repmsg, 0, sizeof(*body));

        if (!(body->valid & OBD_MD_FLEASIZE))
                GOTO(out, rc = 0);

        if (body->eadatasize == 0) {
                CERROR("OBD_MD_FLEASIZE set but eadatasize zero\n");
                GOTO(out, rc = -EPROTO);
        }

        /* The MDS sent back the EA because we unlinked the last reference
         * to this file. Use this EA to unlink the objects on the OST.
         * It's opaque so we don't swab here; we leave it to obd_unpackmd() to
         * check it is complete and sensible. */
        eadata = lustre_swab_repbuf(request, 1, body->eadatasize, NULL);
        LASSERT(eadata != NULL);
        if (eadata == NULL) {
                CERROR("Can't unpack MDS EA data\n");
                GOTO(out, rc = -EPROTO);
        }

        rc = obd_unpackmd(ll_i2obdconn(dir), &lsm, eadata, body->eadatasize);
        if (rc < 0) {
                CERROR("obd_unpackmd: %d\n", rc);
                GOTO(out, rc);
        }
        LASSERT(rc >= sizeof(*lsm));

        oa = obdo_alloc();
        if (oa == NULL)
                GOTO(out_free_memmd, rc = -ENOMEM);

        oa->o_id = lsm->lsm_object_id;
        oa->o_mode = body->mode & S_IFMT;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

        if (body->valid & OBD_MD_FLCOOKIE) {
                oa->o_valid |= OBD_MD_FLCOOKIE;
                oti.oti_logcookies = lustre_msg_buf(request->rq_repmsg, 3,
                                                    body->eadatasize);
        }

        rc = obd_destroy(ll_i2obdconn(dir), oa, lsm, &oti);
        obdo_free(oa);
        if (rc)
                CERROR("obd destroy objid 0x"LPX64" error %d\n",
                       lsm->lsm_object_id, rc);
 out_free_memmd:
        obd_free_memmd(ll_i2obdconn(dir), &lsm);
 out:
        ptlrpc_req_finished(request);
        return rc;
}

/* We depend on "mode" being set with the proper file type/umask by now */
static struct inode *ll_create_node(struct inode *dir, const char *name,
                                    int namelen, const void *data, int datalen,
                                    int mode, __u64 extra,
                                    struct lookup_intent *it)
{
        struct inode *inode;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct lustre_md md;
        int rc;
        ENTRY;

        LASSERT(it && it->it_disposition);

        ll_invalidate_inode_pages(dir);

        request = it->it_data;
        rc = mdc_req2lustre_md(request, 1, &sbi->ll_osc_conn, &md);
        if (rc) { 
                GOTO(out, inode = ERR_PTR(rc));
        }

        inode = ll_iget(dir->i_sb, md.body->ino, &md);
        if (!inode || is_bad_inode(inode)) {
                /* XXX might need iput() for bad inode */
                int rc = -EIO;
                CERROR("new_inode -fatal: rc %d\n", rc);
                LBUG();
                GOTO(out, rc);
        }
        LASSERT(list_empty(&inode->i_dentry));

        CDEBUG(D_DLMTRACE, "setting l_data to inode %p (%lu/%u)\n",
               inode, inode->i_ino, inode->i_generation);
        ldlm_lock_set_data((struct lustre_handle*)it->it_lock_handle,
                           inode);

        EXIT;
 out:
        ptlrpc_req_finished(request);
        return inode;
}

/*
 * By the time this is called, we already have created the directory cache
 * entry for the new file, but it is so far negative - it has no inode.
 *
 * We defer creating the OBD object(s) until open, to keep the intent and
 * non-intent code paths similar, and also because we do not have the MDS
 * inode number before calling ll_create_node() (which is needed for LOV),
 * so we would need to do yet another RPC to the MDS to store the LOV EA
 * data on the MDS.  If needed, we would pass the PACKED lmm as data and
 * lmm_size in datalen (the MDS still has code which will handle that).
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int ll_create_it(struct inode *dir, struct dentry *dentry, int mode, struct lookup_intent *it)
{
        struct inode *inode;
        struct ptlrpc_request *request = it->it_data;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),intent=%s\n",
               dentry->d_name.name, dir->i_ino, dir->i_generation, dir,
               LL_IT2STR(it));

        rc = ll_it_open_error(DISP_OPEN_CREATE, it);
        if (rc) {
                ptlrpc_req_finished(request);
                RETURN(rc);
        }

        mdc_store_inode_generation(request, 2, 1);
        inode = ll_create_node(dir, dentry->d_name.name, dentry->d_name.len,
                               NULL, 0, mode, 0, it);
        if (IS_ERR(inode)) {
                RETURN(PTR_ERR(inode));
        }

        d_instantiate(dentry, inode);
        RETURN(0);
}

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
static int ll_create_nd(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
        return ll_create_it(dir, dentry, mode, &nd->it);
}
#endif

static int ll_mknod_raw(struct nameidata *nd, int mode, dev_t rdev)
{
        struct inode *dir = nd->dentry->d_inode;
        const char *name = nd->last.name;
        int len = nd->last.len;
        struct ptlrpc_request *request = NULL;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        mode &= ~current->fs->umask;

        switch (mode & S_IFMT) {
        case 0: 
        case S_IFREG:
                mode |= S_IFREG; /* for mode = 0 case, fallthrough */
        case S_IFCHR: 
        case S_IFBLK:
        case S_IFIFO: 
        case S_IFSOCK:
                ll_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
                err = mdc_create(&sbi->ll_mdc_conn, &op_data, NULL, 0, mode,
                                 current->fsuid, current->fsgid, time,
                                 rdev, &request);
                ptlrpc_req_finished(request);
                break;
        case S_IFDIR:
                err = -EPERM;
                break;
        default:
                err = -EINVAL;
        }
        RETURN(err);
}

static int ll_symlink_raw(struct nameidata *nd, const char *tgt)
{
        struct inode *dir = nd->dentry->d_inode;
        const char *name = nd->last.name;
        int len = nd->last.len;
        struct ptlrpc_request *request = NULL;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p),target=%s\n",
               name, dir->i_ino, dir->i_generation, dir, tgt);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        ll_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(&sbi->ll_mdc_conn, &op_data,
                         tgt, strlen(tgt) + 1, S_IFLNK | S_IRWXUGO,
                         current->fsuid, current->fsgid, time, 0, &request);
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_link_raw(struct nameidata *srcnd, struct nameidata *tgtnd)
{
        struct inode *src = srcnd->dentry->d_inode;
        struct inode *dir = tgtnd->dentry->d_inode;
        const char *name = tgtnd->last.name;
        int len = tgtnd->last.len;
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        int err;
        struct ll_sb_info *sbi = ll_i2sbi(dir);

        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p),dir=%lu/%u(%p),target=%s\n",
               src->i_ino, src->i_generation, src,
               dir->i_ino, dir->i_generation, dir, name);

        ll_prepare_mdc_op_data(&op_data, src, dir, name, len, 0);
        err = mdc_link(&sbi->ll_mdc_conn, &op_data, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}


static int ll_mkdir_raw(struct nameidata *nd, int mode)
{
        struct inode *dir = nd->dentry->d_inode;
        const char *name = nd->last.name;
        int len = nd->last.len;
        struct ptlrpc_request *request = NULL;
        time_t time = LTIME_S(CURRENT_TIME);
        struct ll_sb_info *sbi = ll_i2sbi(dir);
        struct mdc_op_data op_data;
        int err = -EMLINK;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        if (dir->i_nlink >= EXT2_LINK_MAX)
                RETURN(err);

        mode = (mode & (S_IRWXUGO|S_ISVTX) & ~current->fs->umask) | S_IFDIR;
        ll_prepare_mdc_op_data(&op_data, dir, NULL, name, len, 0);
        err = mdc_create(&sbi->ll_mdc_conn, &op_data, NULL, 0, mode,
                         current->fsuid, current->fsgid, time, 0, &request);
        ptlrpc_req_finished(request);
        RETURN(err);
}

static int ll_rmdir_raw(struct nameidata *nd)
{
        struct inode *dir = nd->dentry->d_inode;
        const char *name = nd->last.name;
        int len = nd->last.len;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        rc = ll_mdc_unlink(dir, NULL, S_IFDIR, name, len);
        RETURN(rc);
}

static int ll_unlink_raw(struct nameidata *nd)
{
        struct inode *dir = nd->dentry->d_inode;
        const char *name = nd->last.name;
        int len = nd->last.len;
        int rc;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s,dir=%lu/%u(%p)\n",
               name, dir->i_ino, dir->i_generation, dir);

        rc = ll_mdc_unlink(dir, NULL, S_IFREG, name, len);
        RETURN(rc);
}

static int ll_rename_raw(struct nameidata *oldnd, struct nameidata *newnd)
{
        struct inode *src = oldnd->dentry->d_inode;
        struct inode *tgt = newnd->dentry->d_inode;
        const char *oldname = oldnd->last.name;
        int oldlen  = oldnd->last.len;
        const char *newname = newnd->last.name;
        int newlen  = newnd->last.len;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(src);
        struct mdc_op_data op_data;
        int err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:oldname=%s,src_dir=%lu/%u(%p),newname=%s,"
               "tgt_dir=%lu/%u(%p)\n", oldname, src->i_ino, src->i_generation,
               src, newname, tgt->i_ino, tgt->i_generation, tgt);

        ll_prepare_mdc_op_data(&op_data, src, tgt, NULL, 0, 0);
        err = mdc_rename(&sbi->ll_mdc_conn, &op_data,
                         oldname, oldlen, newname, newlen, &request);
        ptlrpc_req_finished(request);

        RETURN(err);
}

struct inode_operations ll_dir_inode_operations = {
        link_raw:           ll_link_raw,
        unlink_raw:         ll_unlink_raw,
        symlink_raw:        ll_symlink_raw,
        mkdir_raw:          ll_mkdir_raw,
        rmdir_raw:          ll_rmdir_raw,
        mknod_raw:          ll_mknod_raw,
        rename_raw:         ll_rename_raw,
        setattr:         ll_setattr,
        setattr_raw:     ll_setattr_raw,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        create_it:          ll_create_it,
        lookup_it:            ll_lookup_it,
        revalidate_it:      ll_inode_revalidate_it,
#else
        lookup_it:          ll_lookup_nd,
        create_nd:          ll_create_nd,
        getattr_it:         ll_getattr,
#endif
};
