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

#include <linux/module.h>
#include <linux/random.h>
#include <linux/version.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/lprocfs_status.h>
#include "llite_internal.h"

kmem_cache_t *ll_file_data_slab;

extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
extern struct super_operations ll_super_operations;

#ifndef log2
#define log2(n) ffz(~(n))
#endif

char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;
        ENTRY;

        CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
        if (strncmp(opt, data, strlen(opt)))
                RETURN(NULL);
        if ((value = strchr(data, '=')) == NULL)
                RETURN(NULL);

        value++;
        OBD_ALLOC(retval, strlen(value) + 1);
        if (!retval) {
                CERROR("out of memory!\n");
                RETURN(NULL);
        }

        memcpy(retval, value, strlen(value)+1);
        CDEBUG(D_SUPER, "Assigned option: %s, value %s\n", opt, retval);
        RETURN(retval);
}

int ll_set_opt(const char *opt, char *data, int fl)
{
        ENTRY;

        CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
        if (strncmp(opt, data, strlen(opt)))
                RETURN(0);
        else
                RETURN(fl);
}

void ll_options(char *options, char **ost, char **mds, int *flags)
{
        char *this_char;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0))
        char *opt_ptr = options;
#endif
        ENTRY;

        if (!options) {
                EXIT;
                return;
        }

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        for (this_char = strtok (options, ",");
             this_char != NULL;
             this_char = strtok (NULL, ",")) {
#else
        while ((this_char = strsep (&opt_ptr, ",")) != NULL) {
#endif
                CDEBUG(D_SUPER, "this_char %s\n", this_char);
                if (!*ost && (*ost = ll_read_opt("osc", this_char)))
                        continue;
                if (!*mds && (*mds = ll_read_opt("mdc", this_char)))
                        continue;
                if (!(*flags & LL_SBI_NOLCK) &&
                    ((*flags) = (*flags) |
                                ll_set_opt("nolock", this_char,
                                           LL_SBI_NOLCK)))
                        continue;
                if (!(*flags & LL_SBI_READAHEAD) &&
                    ((*flags) = (*flags) |
                                ll_set_opt("readahead", this_char,
                                           LL_SBI_READAHEAD)))
                        continue;
        }
        EXIT;
}

void ll_lli_init(struct ll_inode_info *lli)
{
        sema_init(&lli->lli_open_sem, 1);
        lli->lli_flags = 0;
        lli->lli_maxbytes = PAGE_CACHE_MAXBYTES;
}

int ll_fill_super(struct super_block *sb, void *data, int silent)
{
        struct inode *root = 0;
        struct obd_device *obd;
        struct ll_sb_info *sbi;
        char *osc = NULL;
        char *mdc = NULL;
        int err;
        struct ll_fid rootfid;
        struct obd_statfs osfs;
        struct ptlrpc_request *request = NULL;
        struct lustre_handle osc_conn = {0, };
        struct lustre_handle mdc_conn = {0, };
        struct lustre_md md;
        class_uuid_t uuid;

        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        INIT_HLIST_HEAD(&sbi->ll_orphan_dentry_list);
        ll_s2sbi(sb) = sbi;

        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        ll_options(data, &osc, &mdc, &sbi->ll_flags);

        if (!osc) {
                CERROR("no osc\n");
                GOTO(out_free, err = -EINVAL);
        }

        if (!mdc) {
                CERROR("no mdc\n");
                GOTO(out_free, err = -EINVAL);
        }

        obd = class_name2obd(mdc);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", mdc);
                GOTO(out_free, err = -EINVAL);
        }

        if (proc_lustre_fs_root) {
                err = lprocfs_register_mountpoint(proc_lustre_fs_root, sb,
                                                  osc, mdc);
                if (err < 0)
                        CERROR("could not register mount in /proc/lustre");
        }

        err = obd_connect(&mdc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, err);
        }
        sbi->ll_mdc_exp = class_conn2export(&mdc_conn);

        err = obd_statfs(obd, &osfs, jiffies - HZ);
        if (err)
                GOTO(out_mdc, err);

        LASSERT(osfs.os_bsize);
        sb->s_blocksize = osfs.os_bsize;
        sb->s_blocksize_bits = log2(osfs.os_bsize);
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_maxbytes = PAGE_CACHE_MAXBYTES;

        obd = class_name2obd(osc);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_mdc, err);
        }

        err = obd_connect(&osc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_mdc, err);
        }
        sbi->ll_osc_exp = class_conn2export(&osc_conn);

        err = mdc_getstatus(sbi->ll_mdc_exp, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_osc, err);
        }
        CDEBUG(D_SUPER, "rootfid "LPU64"\n", rootfid.id);
        sbi->ll_rootino = rootfid.id;

        sb->s_op = &ll_super_operations;

        /* make root inode 
         * XXX: move this to after cbd setup? */
        err = mdc_getattr(sbi->ll_mdc_exp, &rootfid,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                GOTO(out_osc, err);
        }

        err = mdc_req2lustre_md(request, 0, sbi->ll_osc_exp, &md);
        if (err) {
                CERROR("failed to understand root inode md: rc = %d\n",err);
                ptlrpc_req_finished (request);
                GOTO(out_osc, err);
        }

        LASSERT(sbi->ll_rootino != 0);
        root = ll_iget(sb, sbi->ll_rootino, &md);

        ptlrpc_req_finished(request);

        if (root == NULL || is_bad_inode(root)) {
                /* XXX might need iput() for bad inode */
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_osc, err = -EBADF);
        }

        sb->s_root = d_alloc_root(root);

out_dev:
        if (mdc)
                OBD_FREE(mdc, strlen(mdc) + 1);
        if (osc)
                OBD_FREE(osc, strlen(osc) + 1);

        RETURN(err);

        iput(root);
out_osc:
        obd_disconnect(sbi->ll_osc_exp, 0);
out_mdc:
        obd_disconnect(sbi->ll_mdc_exp, 0);
out_free:
        lprocfs_unregister_mountpoint(sbi);
        OBD_FREE(sbi, sizeof(*sbi));

        goto out_dev;
} /* ll_read_super */

void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device *obd = class_exp2obd(sbi->ll_mdc_exp);
        struct hlist_node *tmp, *next;
        struct ll_fid rootfid;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        list_del(&sbi->ll_conn_chain);
        obd_disconnect(sbi->ll_osc_exp, 0);

        /* NULL request to force sync on the MDS, and get the last_committed
         * value to flush remaining RPCs from the sending queue on client.
         *
         * XXX This should be an mdc_sync() call to sync the whole MDS fs,
         *     which we can call for other reasons as well.
         */
        if (!obd->obd_no_recov)
                mdc_getstatus(sbi->ll_mdc_exp, &rootfid);

        lprocfs_unregister_mountpoint(sbi);
        if (sbi->ll_proc_root) {
                lprocfs_remove(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
        }

        obd_disconnect(sbi->ll_mdc_exp, 0);

#warning We do this to get rid of orphaned dentries. That is not really trw.
        spin_lock(&dcache_lock);
        hlist_for_each_safe(tmp, next, &sbi->ll_orphan_dentry_list) {
                struct dentry *dentry = hlist_entry(tmp, struct dentry, d_hash);
                shrink_dcache_parent(dentry);
        }
        spin_unlock(&dcache_lock);

        OBD_FREE(sbi, sizeof(*sbi));

        EXIT;
} /* ll_put_super */


struct inode *ll_inode_from_lock(struct ldlm_lock *lock)
{
        struct inode *inode;
        l_lock(&lock->l_resource->lr_namespace->ns_lock);
        if (lock->l_data)
                inode = igrab(lock->l_data);
        else
                inode = NULL;
        l_unlock(&lock->l_resource->lr_namespace->ns_lock);
        return inode;
}

static int null_if_equal(struct ldlm_lock *lock, void *data)
{
        if (data == lock->l_data)
                lock->l_data = NULL;

        if (lock->l_req_mode != lock->l_granted_mode)
                return LDLM_ITER_STOP;

        return LDLM_ITER_CONTINUE;
}

void ll_clear_inode(struct inode *inode)
{
        struct ll_fid fid;
        struct ll_inode_info *lli = ll_i2info(inode);
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        ll_inode2fid(&fid, inode);
        clear_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &(ll_i2info(inode)->lli_flags));
        mdc_change_cbdata(sbi->ll_mdc_exp, &fid, null_if_equal, inode);

        if (lli->lli_smd)
                obd_change_cbdata(sbi->ll_osc_exp, lli->lli_smd,
                                  null_if_equal, inode);

        if (lli->lli_smd) {
                obd_free_memmd(sbi->ll_osc_exp, &lli->lli_smd);
                lli->lli_smd = NULL;
        }

        if (lli->lli_symlink_name) {
                OBD_FREE(lli->lli_symlink_name,
                         strlen(lli->lli_symlink_name) + 1);
                lli->lli_symlink_name = NULL;
        }

        EXIT;
}

/* If this inode has objects allocated to it (lsm != NULL), then the OST
 * object(s) determine the file size and mtime.  Otherwise, the MDS will
 * keep these values until such a time that objects are allocated for it.
 * We do the MDS operations first, as it is checking permissions for us.
 * We don't to the MDS RPC if there is nothing that we want to store there,
 * otherwise there is no harm in updating mtime/atime on the MDS if we are
 * going to do an RPC anyways.
 *
 * If we are doing a truncate, we will send the mtime and ctime updates
 * to the OST with the punch RPC, otherwise we do an explicit setattr RPC.
 * I don't believe it is possible to get e.g. ATTR_MTIME_SET and ATTR_SIZE
 * at the same time.
 */
#define OST_ATTR (ATTR_MTIME | ATTR_MTIME_SET | ATTR_CTIME | \
                  ATTR_ATIME | ATTR_ATIME_SET | ATTR_SIZE)
int ll_setattr_raw(struct inode *inode, struct iattr *attr)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        int ia_valid = attr->ia_valid;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_SETATTR);

        if (ia_valid & ATTR_SIZE) {
                if (attr->ia_size > ll_file_maxbytes(inode)) {
                        CDEBUG(D_INODE, "file too large %llu > "LPU64"\n",
                               attr->ia_size, ll_file_maxbytes(inode));
                        RETURN(-EFBIG);
                }

                attr->ia_valid |= ATTR_MTIME | ATTR_CTIME;
        }

        /* We mark all of the fields "set" so MDS/OST does not re-set them */
        if (attr->ia_valid & ATTR_CTIME) {
                attr->ia_ctime = CURRENT_TIME;
                attr->ia_valid |= ATTR_CTIME_SET;
        }
        if (!(ia_valid & ATTR_ATIME_SET) && (attr->ia_valid & ATTR_ATIME)) {
                attr->ia_atime = CURRENT_TIME;
                attr->ia_valid |= ATTR_ATIME_SET;
        }
        if (!(ia_valid & ATTR_MTIME_SET) && (attr->ia_valid & ATTR_MTIME)) {
                attr->ia_mtime = CURRENT_TIME;
                attr->ia_valid |= ATTR_MTIME_SET;
        }

        if (attr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu, now = %lu\n",
                       LTIME_S(attr->ia_mtime), LTIME_S(attr->ia_ctime),
                       LTIME_S(CURRENT_TIME));
        if (lsm)
                attr->ia_valid &= ~ATTR_SIZE;

        /* If only OST attributes being set on objects, don't do MDS RPC.
         * In that case, we need to check permissions and update the local
         * inode ourselves so we can call obdo_from_inode() always. */
        if (ia_valid & (lsm ? ~(OST_ATTR | ATTR_FROM_OPEN | ATTR_RAW) : ~0)) {
                struct lustre_md md;
                ll_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

                rc = mdc_setattr(sbi->ll_mdc_exp, &op_data,
                                 attr, NULL, 0, NULL, 0, &request);

                if (rc) {
                        ptlrpc_req_finished(request);
                        if (rc != -EPERM && rc != -EACCES)
                                CERROR("mdc_setattr fails: rc = %d\n", rc);
                        RETURN(rc);
                }

                rc = mdc_req2lustre_md(request, 0, sbi->ll_osc_exp, &md);
                if (rc) {
                        ptlrpc_req_finished(request);
                        RETURN(rc);
                }
                ll_update_inode(inode, md.body, md.lsm);
                ptlrpc_req_finished(request);

                if (!md.lsm || !S_ISREG(inode->i_mode)) {
                        CDEBUG(D_INODE, "no lsm: not setting attrs on OST\n");
                        RETURN(0);
                }
        } else {
                /* The OST doesn't check permissions, but the alternative is
                 * a gratuitous RPC to the MDS.  We already rely on the client
                 * to do read/write/truncate permission checks, so is mtime OK?
                 */
                if (ia_valid & (ATTR_MTIME | ATTR_ATIME)) {
                        /* from sys_utime() */
                        if (!(ia_valid & (ATTR_MTIME_SET | ATTR_ATIME_SET))) {
                                if (current->fsuid != inode->i_uid &&
                                    (rc = ll_permission(inode, MAY_WRITE, NULL)) != 0)
                                        RETURN(rc);
                        } else {
				/* from inode_change_ok() */
				if (current->fsuid != inode->i_uid &&
				    !capable(CAP_FOWNER))
					RETURN(-EPERM);
                        }
                }

                /* Won't invoke vmtruncate, as we already cleared ATTR_SIZE */
                inode_setattr(inode, attr);
        }

        if (ia_valid & ATTR_SIZE) {
                struct ldlm_extent extent = { .start = 0,
                                              .end = OBD_OBJECT_EOF };
                struct lustre_handle lockh = { 0 };
                int err, ast_flags = 0;
                /* XXX when we fix the AST intents to pass the discard-range
                 * XXX extent, make ast_flags always LDLM_AST_DISCARD_DATA
                 * XXX here. */

                /* Writeback uses inode->i_size to determine how far out
                 * its cached pages go.  ll_truncate gets a PW lock, canceling
                 * our lock, _after_ it has updated i_size.  this can confuse
                 *
                 * We really need to get our PW lock before we change
                 * inode->i_size.  If we don't we can race with other
                 * i_size updaters on our node, like ll_file_read.  We
                 * can also race with i_size propogation to other
                 * nodes through dirtying and writeback of final cached
                 * pages.  This last one is especially bad for racing
                 * o_append users on other nodes. */
                if (extent.start == 0)
                        ast_flags = LDLM_AST_DISCARD_DATA;
                /* bug 1639: avoid write/truncate i_sem/DLM deadlock */
                LASSERT(atomic_read(&inode->i_sem.count) <= 0);
                up(&inode->i_sem);
                rc = ll_extent_lock_no_validate(NULL, inode, lsm, LCK_PW,
                                                &extent, &lockh, ast_flags);
                down(&inode->i_sem);
                if (rc != ELDLM_OK) {
                        if (rc > 0)
                                RETURN(-ENOLCK);
                        RETURN(rc);
                }

                rc = vmtruncate(inode, attr->ia_size);
                if (rc == 0)
                        set_bit(LLI_F_HAVE_OST_SIZE_LOCK,
                                &ll_i2info(inode)->lli_flags);

                /* unlock now as we don't mind others file lockers racing with
                 * the mds updates below? */
                err = ll_extent_unlock(NULL, inode, lsm, LCK_PW, &lockh);
                if (err) {
                        CERROR("ll_extent_unlock failed: %d\n", err);
                        if (!rc)
                                rc = err;
                }
        } else if (ia_valid & (ATTR_MTIME | ATTR_MTIME_SET)) {
                struct obdo oa;

                CDEBUG(D_INODE, "set mtime on OST inode %lu to %lu\n",
                       inode->i_ino, LTIME_S(attr->ia_mtime));
                oa.o_id = lsm->lsm_object_id;
                oa.o_valid = OBD_MD_FLID;
                obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                            OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                rc = obd_setattr(sbi->ll_osc_exp, &oa, lsm, NULL);
                if (rc)
                        CERROR("obd_setattr fails: rc=%d\n", rc);
        }
        RETURN(rc);
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        LBUG(); /* code is unused, but leave this in case of VFS changes */
        RETURN(-ENOSYS);
}

int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       unsigned long max_age)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_statfs obd_osfs;
        int rc;
        ENTRY;

        rc = obd_statfs(class_exp2obd(sbi->ll_mdc_exp), osfs, max_age);
        if (rc) {
                CERROR("mdc_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "MDC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               osfs->os_bavail, osfs->os_blocks, osfs->os_ffree,osfs->os_files);

        rc = obd_statfs(class_exp2obd(sbi->ll_osc_exp), &obd_osfs, max_age);
        if (rc) {
                CERROR("obd_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "OSC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               obd_osfs.os_bavail, obd_osfs.os_blocks, obd_osfs.os_ffree,
               obd_osfs.os_files);

        osfs->os_blocks = obd_osfs.os_blocks;
        osfs->os_bfree = obd_osfs.os_bfree;
        osfs->os_bavail = obd_osfs.os_bavail;

        /* If we don't have as many objects free on the OST as inodes
         * on the MDS, we reduce the total number of inodes to
         * compensate, so that the "inodes in use" number is correct.
         */
        if (obd_osfs.os_ffree < osfs->os_ffree) {
                osfs->os_files = (osfs->os_files - osfs->os_ffree) +
                        obd_osfs.os_ffree;
                osfs->os_ffree = obd_osfs.os_ffree;
        }

        RETURN(rc);
}

int ll_statfs(struct super_block *sb, struct kstatfs *sfs)
{
        struct obd_statfs osfs;
        int rc;

        CDEBUG(D_VFSTRACE, "VFS Op:\n");
        lprocfs_counter_incr(ll_s2sbi(sb)->ll_stats, LPROC_LL_STAFS);

        /* For now we will always get up-to-date statfs values, but in the
         * future we may allow some amount of caching on the client (e.g.
         * from QOS or lprocfs updates). */
        rc = ll_statfs_internal(sb, &osfs, jiffies - 1);
        if (rc)
                return rc;

        statfs_unpack(sfs, &osfs);

        if (sizeof(sfs->f_blocks) == 4) {
                while (osfs.os_blocks > ~0UL) {
                        sfs->f_bsize <<= 1;

                        osfs.os_blocks >>= 1;
                        osfs.os_bfree >>= 1;
                        osfs.os_bavail >>= 1;
                }
        }

        sfs->f_blocks = osfs.os_blocks;
        sfs->f_bfree = osfs.os_bfree;
        sfs->f_bavail = osfs.os_bavail;

        return 0;
}

void dump_lsm(int level, struct lov_stripe_md *lsm)
{
        CDEBUG(level, "objid "LPX64", maxbytes "LPX64", magic %#08x, "
               "stripe_size %#08x, offset %u, stripe_count %u\n",
               lsm->lsm_object_id, lsm->lsm_maxbytes, lsm->lsm_magic,
               lsm->lsm_stripe_size, lsm->lsm_stripe_offset,
               lsm->lsm_stripe_count);
}

void ll_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_stripe_md *lsm)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        LASSERT ((lsm != NULL) == ((body->valid & OBD_MD_FLEASIZE) != 0));
        if (lsm != NULL) {
                if (lli->lli_smd == NULL) {
                        lli->lli_smd = lsm;
                        lli->lli_maxbytes = lsm->lsm_maxbytes;
                        if (lli->lli_maxbytes > PAGE_CACHE_MAXBYTES)
                                lli->lli_maxbytes = PAGE_CACHE_MAXBYTES;
                } else {
                        if (memcmp(lli->lli_smd, lsm, sizeof(*lsm))) {
                                CERROR("lsm mismatch for inode %ld\n",
                                       inode->i_ino);
                                CERROR("lli_smd:\n");
                                dump_lsm(D_ERROR, lli->lli_smd);
                                CERROR("lsm:\n");
                                dump_lsm(D_ERROR, lsm);
                                LBUG();
                        }
                }
                if (lli->lli_smd != lsm)
                        obd_free_memmd(ll_i2obdexp(inode), &lsm);
        }

        if (body->valid & OBD_MD_FLID)
                inode->i_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                LTIME_S(inode->i_atime) = body->atime;
        if (body->valid & OBD_MD_FLMTIME)
                LTIME_S(inode->i_mtime) = body->mtime;
        if (body->valid & OBD_MD_FLCTIME &&
            body->ctime > LTIME_S(inode->i_ctime))
                LTIME_S(inode->i_ctime) = body->ctime;
        if (body->valid & OBD_MD_FLMODE)
                inode->i_mode = (inode->i_mode & S_IFMT)|(body->mode & ~S_IFMT);
        if (body->valid & OBD_MD_FLTYPE)
                inode->i_mode = (inode->i_mode & ~S_IFMT)|(body->mode & S_IFMT);
        if (body->valid & OBD_MD_FLUID)
                inode->i_uid = body->uid;
        if (body->valid & OBD_MD_FLGID)
                inode->i_gid = body->gid;
        if (body->valid & OBD_MD_FLFLAGS)
                inode->i_flags = body->flags;
        if (body->valid & OBD_MD_FLNLINK)
                inode->i_nlink = body->nlink;
        if (body->valid & OBD_MD_FLGENER)
                inode->i_generation = body->generation;
        if (body->valid & OBD_MD_FLRDEV)
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                inode->i_rdev = body->rdev;
#else
                inode->i_rdev = to_kdev_t(body->rdev);
#endif
        if (body->valid & OBD_MD_FLSIZE)
                inode->i_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                inode->i_blocks = body->blocks;

        if (body->valid & OBD_MD_FLSIZE)
                set_bit(LLI_F_HAVE_MDS_SIZE_LOCK, &lli->lli_flags);
}

void ll_read_inode2(struct inode *inode, void *opaque)
{
        struct lustre_md *md = opaque;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);

        ll_lli_init(lli);

        LASSERT(!lli->lli_smd);

        /* Core attributes from the MDS first.  This is a new inode, and
         * the VFS doesn't zero times in the core inode so we have to do
         * it ourselves.  They will be overwritten by either MDS or OST
         * attributes - we just need to make sure they aren't newer. */
        LTIME_S(inode->i_mtime) = 0;
        LTIME_S(inode->i_atime) = 0;
        LTIME_S(inode->i_ctime) = 0;
        ll_update_inode(inode, md->body, md->lsm);

        /* OIDEBUG(inode); */

        if (S_ISREG(inode->i_mode)) {
                inode->i_op = &ll_file_inode_operations;
                inode->i_fop = &ll_file_operations;
                inode->i_mapping->a_ops = &ll_aops;
                EXIT;
        } else if (S_ISDIR(inode->i_mode)) {
                inode->i_op = &ll_dir_inode_operations;
                inode->i_fop = &ll_dir_operations;
                inode->i_mapping->a_ops = &ll_dir_aops;
                EXIT;
        } else if (S_ISLNK(inode->i_mode)) {
                inode->i_op = &ll_fast_symlink_inode_operations;
                EXIT;
        } else {
                inode->i_op = &ll_special_inode_operations;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
                init_special_inode(inode, inode->i_mode, 
                                   kdev_t_to_nr(inode->i_rdev));
#else
                init_special_inode(inode, inode->i_mode, inode->i_rdev);
#endif
                EXIT;
        }
}

void ll_umount_begin(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device *obd;
        struct obd_ioctl_data ioc_data = { 0 };
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:\n");

        obd = class_exp2obd(sbi->ll_mdc_exp);
        if (obd == NULL) {
                CERROR("Invalid MDC connection handle "LPX64"\n",
                       sbi->ll_mdc_exp->exp_handle.h_cookie);
                EXIT;
                return;
        }
        obd->obd_no_recov = 1;
        obd_iocontrol(IOC_OSC_SET_ACTIVE, sbi->ll_mdc_exp, sizeof ioc_data,
                      &ioc_data, NULL);

        obd = class_exp2obd(sbi->ll_osc_exp);
        if (obd == NULL) {
                CERROR("Invalid LOV connection handle "LPX64"\n",
                       sbi->ll_osc_exp->exp_handle.h_cookie);
                EXIT;
                return;
        }

        obd->obd_no_recov = 1;
        obd_iocontrol(IOC_OSC_SET_ACTIVE, sbi->ll_osc_exp, sizeof ioc_data,
                      &ioc_data, NULL);

        /* Really, we'd like to wait until there are no requests outstanding,
         * and then continue.  For now, we just invalidate the requests,
         * schedule, and hope.
         */
        schedule();

        EXIT;
}
