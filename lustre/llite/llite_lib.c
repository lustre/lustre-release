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
                if ((!*ost && (*ost = ll_read_opt("osc", this_char)))||
                    (!*mds && (*mds = ll_read_opt("mdc", this_char)))||
                    (!(*flags & LL_SBI_NOLCK) &&
                     ((*flags) = (*flags) |
                      ll_set_opt("nolock", this_char, LL_SBI_NOLCK))))
                        continue;
        }
        EXIT;
}

void ll_lli_init(struct ll_inode_info *lli)
{
        sema_init(&lli->lli_open_sem, 1);
        spin_lock_init(&lli->lli_read_extent_lock);
        INIT_LIST_HEAD(&lli->lli_read_extents);
        lli->lli_flags = 0;
        lli->lli_maxbytes = PAGE_CACHE_MAXBYTES;
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        ll_lldo_init(&lli->lli_dirty);
        spin_lock_init(&lli->lli_pg_lock);
        INIT_LIST_HEAD(&lli->lli_lc_item);
        plist_init(&lli->lli_pl_read);
        plist_init(&lli->lli_pl_write);
        atomic_set(&lli->lli_in_writepages, 0);
#endif
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
        struct ptlrpc_connection *mdc_conn;
        struct lustre_md md;
        class_uuid_t uuid;

        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        INIT_LIST_HEAD(&sbi->ll_orphan_dentry_list);
        sb->u.generic_sbp = sbi;
#else
        INIT_HLIST_HEAD(&sbi->ll_orphan_dentry_list);
        spin_lock_init(&sbi->ll_iostats.fis_lock);
        ll_s2sbi(sb) = sbi;
#endif
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

        err = obd_connect(&sbi->ll_mdc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, err);
        }

        err = obd_statfs(obd, &osfs, jiffies - HZ);
        if (err)
                GOTO(out_mdc, err);

        LASSERT(osfs.os_bsize);
        sb->s_blocksize = osfs.os_bsize;
        sb->s_blocksize_bits = log2(osfs.os_bsize);
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_maxbytes = PAGE_CACHE_MAXBYTES;

        mdc_conn = sbi2mdc(sbi)->cl_import->imp_connection;

        obd = class_name2obd(osc);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_mdc, err);
        }

        err = obd_connect(&sbi->ll_osc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_mdc, err);
        }

        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_osc, err);
        }
        CDEBUG(D_SUPER, "rootfid "LPU64"\n", rootfid.id);
        sbi->ll_rootino = rootfid.id;

        sb->s_op = &ll_super_operations;

        /* make root inode 
         * XXX: move this to after cbd setup? */
        err = mdc_getattr(&sbi->ll_mdc_conn, &rootfid,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                GOTO(out_osc, err);
        }

        /* initialize committed transaction callback daemon */
        spin_lock_init(&sbi->ll_commitcbd_lock);
        init_waitqueue_head(&sbi->ll_commitcbd_waitq);
        init_waitqueue_head(&sbi->ll_commitcbd_ctl_waitq);
        sbi->ll_commitcbd_flags = 0;
        err = ll_commitcbd_setup(sbi);
        if (err) {
                CERROR("failed to start commit callback daemon: rc = %d\n",err);
                ptlrpc_req_finished (request);
                GOTO(out_lliod, err);
        }

        err = mdc_req2lustre_md(request, 0, &sbi->ll_osc_conn, &md);
        if (err) {
                CERROR("failed to understand root inode md: rc = %d\n",err);
                ptlrpc_req_finished (request);
                GOTO(out_lliod, err);
        }

        LASSERT(sbi->ll_rootino != 0);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        root = iget4(sb, sbi->ll_rootino, NULL, &md);
#else
        root = ll_iget(sb, sbi->ll_rootino, &md);
#endif

        ptlrpc_req_finished(request);

        if (root == NULL || is_bad_inode(root)) {
                /* XXX might need iput() for bad inode */
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_cbd, err = -EBADF);
        }

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        /* initialize the pagecache writeback thread */
        err = lliod_start(sbi, root);
        if (err) {
                CERROR("failed to start lliod: rc = %d\n",err);
                GOTO(out_root, sb = NULL);
        }
#endif
        sb->s_root = d_alloc_root(root);

        if (proc_lustre_fs_root) {
                err = lprocfs_register_mountpoint(proc_lustre_fs_root, sb,
                                                  osc, mdc);
                if (err < 0)
                        CERROR("could not register mount in /proc/lustre");
        }

out_dev:
        if (mdc)
                OBD_FREE(mdc, strlen(mdc) + 1);
        if (osc)
                OBD_FREE(osc, strlen(osc) + 1);

        RETURN(err);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
out_root:
        iput(root);
#endif
out_cbd:
        ll_commitcbd_cleanup(sbi);
out_lliod:
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        lliod_stop(sbi);
#endif
out_osc:
        obd_disconnect(&sbi->ll_osc_conn, 0);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn, 0);
out_free:
        lprocfs_unregister_mountpoint(sbi);
        OBD_FREE(sbi, sizeof(*sbi));

        goto out_dev;
} /* ll_read_super */

void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        struct obd_device *obd = class_conn2obd(&sbi->ll_mdc_conn);
        struct list_head *tmp, *next;
#else
        struct hlist_node *tmp, *next;
#endif
        struct ll_fid rootfid;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op: sb %p\n", sb);
        list_del(&sbi->ll_conn_chain);
        ll_commitcbd_cleanup(sbi);
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        lliod_stop(sbi);
#endif
        obd_disconnect(&sbi->ll_osc_conn, 0);

        /* NULL request to force sync on the MDS, and get the last_committed
         * value to flush remaining RPCs from the sending queue on client.
         *
         * XXX This should be an mdc_sync() call to sync the whole MDS fs,
         *     which we can call for other reasons as well.
         */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (!obd->obd_no_recov)
#endif
                mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);

        lprocfs_unregister_mountpoint(sbi);
        if (sbi->ll_proc_root) {
                lprocfs_remove(sbi->ll_proc_root);
                sbi->ll_proc_root = NULL;
        }

        obd_disconnect(&sbi->ll_mdc_conn, 0);

        spin_lock(&dcache_lock);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        list_for_each_safe(tmp, next, &sbi->ll_orphan_dentry_list) {
                struct dentry *dentry = list_entry(tmp, struct dentry, d_hash);
                shrink_dcache_parent(dentry);
        }
#else
        hlist_for_each_safe(tmp, next, &sbi->ll_orphan_dentry_list) {
                struct dentry *dentry = hlist_entry(tmp, struct dentry, d_hash);
                shrink_dcache_parent(dentry);
        }
#endif
        spin_unlock(&dcache_lock);

        OBD_FREE(sbi, sizeof(*sbi));

        EXIT;
} /* ll_put_super */

void ll_clear_inode(struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu/%u(%p)\n", inode->i_ino,
               inode->i_generation, inode);
        rc = ll_mdc_cancel_unused(&sbi->ll_mdc_conn, inode,
                                  LDLM_FL_WARN | LDLM_FL_NO_CALLBACK, inode);
        if (rc < 0) {
                CERROR("ll_mdc_cancel_unused: %d\n", rc);
                /* XXX FIXME do something dramatic */
        }

        if (atomic_read(&inode->i_count) != 0)
                CERROR("clearing in-use inode %lu: count = %d\n",
                       inode->i_ino, atomic_read(&inode->i_count));

        if (lli->lli_smd) {
                rc = obd_cancel_unused(&sbi->ll_osc_conn, lli->lli_smd,
                                       LDLM_FL_WARN, inode);
                if (rc < 0) {
                        CERROR("obd_cancel_unused: %d\n", rc);
                        /* XXX FIXME do something dramatic */
                }
                obd_free_memmd(&sbi->ll_osc_conn, &lli->lli_smd);
                lli->lli_smd = NULL;
        }

        if (lli->lli_symlink_name) {
                OBD_FREE(lli->lli_symlink_name,
                         strlen(lli->lli_symlink_name) + 1);
                lli->lli_symlink_name = NULL;
        }

        EXIT;
}

#if 0
static void ll_delete_inode(struct inode *inode)
{
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu(%p)\n", inode->i_ino, inode);
        if (S_ISREG(inode->i_mode)) {
                int err;
                struct obdo *oa;
                struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;

                /* mcreate with no open */
                if (!lsm)
                        GOTO(out, 0);

                if (lsm->lsm_object_id == 0) {
                        CERROR("This really happens\n");
                        /* No obdo was ever created */
                        GOTO(out, 0);
                }

                oa = obdo_alloc();
                if (oa == NULL)
                        GOTO(out, -ENOMEM);

                oa->o_id = lsm->lsm_object_id;
                oa->o_valid = OBD_MD_FLID;
                obdo_from_inode(oa, inode, OBD_MD_FLTYPE);

                err = obd_destroy(ll_i2obdconn(inode), oa, lsm, NULL);
                obdo_free(oa);
                if (err)
                        CDEBUG(D_INODE,
                               "inode %lu obd_destroy objid "LPX64" error %d\n",
                               inode->i_ino, lsm->lsm_object_id, err);
        }
out:
        clear_inode(inode);
        EXIT;
}
#endif

/* like inode_setattr, but doesn't mark the inode dirty */
int ll_attr2inode(struct inode *inode, struct iattr *attr, int trunc)
{
        unsigned int ia_valid = attr->ia_valid;
        int error = 0;

        if ((ia_valid & ATTR_SIZE) && trunc) {
                if (attr->ia_size > ll_file_maxbytes(inode)) {
                        error = -EFBIG;
                        goto out;
                }
                error = vmtruncate(inode, attr->ia_size);
                if (error)
                        goto out;
        } else if (ia_valid & ATTR_SIZE)
                inode->i_size = attr->ia_size;

        if (ia_valid & ATTR_UID)
                inode->i_uid = attr->ia_uid;
        if (ia_valid & ATTR_GID)
                inode->i_gid = attr->ia_gid;
        if (ia_valid & ATTR_ATIME)
                inode->i_atime = attr->ia_atime;
        if (ia_valid & ATTR_MTIME)
                inode->i_mtime = attr->ia_mtime;
        if (ia_valid & ATTR_CTIME)
                inode->i_ctime = attr->ia_ctime;
        if (ia_valid & ATTR_MODE) {
                inode->i_mode = attr->ia_mode;
                if (!in_group_p(inode->i_gid) && !capable(CAP_FSETID))
                        inode->i_mode &= ~S_ISGID;
        }
out:
        return error;
}

int ll_inode_setattr(struct inode *inode, struct iattr *attr, int do_trunc)
{
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int err = 0;
        ENTRY;

        /* change incore inode */
        err = ll_attr2inode(inode, attr, do_trunc);
        if (err)
                RETURN(err);

        /* Don't send size changes to MDS to avoid "fast EA" problems, and
         * also avoid a pointless RPC (we get file size from OST anyways).
         */
        attr->ia_valid &= ~ATTR_SIZE;
        if (attr->ia_valid) {
                struct mdc_op_data op_data;

                ll_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);
                err = mdc_setattr(&sbi->ll_mdc_conn, &op_data,
                                  attr, NULL, 0, NULL, 0, &request);
                if (err)
                        CERROR("mdc_setattr fails: err = %d\n", err);

                ptlrpc_req_finished(request);
                if (S_ISREG(inode->i_mode) && attr->ia_valid & ATTR_MTIME_SET) {
                        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                        struct obdo oa;
                        int err2;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
                        CDEBUG(D_INODE, "set mtime on OST inode %lu to %lu\n",
                               inode->i_ino, attr->ia_mtime);
                        oa.o_mtime = attr->ia_mtime;
#else
                        CDEBUG(D_INODE, "set mtime on OST inode %lu to "
                               LPU64"\n", inode->i_ino, 
                               ll_ts2u64(&attr->ia_mtime));
                        oa.o_mtime = ll_ts2u64(&attr->ia_mtime);
#endif
                        oa.o_id = lsm->lsm_object_id;
                        oa.o_mode = S_IFREG;
                        oa.o_valid = OBD_MD_FLID |OBD_MD_FLTYPE |OBD_MD_FLMTIME;
                        err2 = obd_setattr(&sbi->ll_osc_conn, &oa, lsm, NULL);
                        if (err2) {
                                CERROR("obd_setattr fails: rc=%d\n", err);
                                if (!err)
                                        err = err2;
                        }
                }
        }

        RETURN(err);
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
        time_t now = LTIME_S(CURRENT_TIME);
        int ia_valid = attr->ia_valid;
        int rc = 0;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
        lprocfs_counter_incr(ll_i2sbi(inode)->ll_stats, LPROC_LL_SETATTR);
#endif

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
                attr->ia_ctime = now;
                attr->ia_valid |= ATTR_CTIME_SET;
        }
        if (!(ia_valid & ATTR_ATIME_SET) && (attr->ia_valid & ATTR_ATIME)) {
                attr->ia_atime = now;
                attr->ia_valid |= ATTR_ATIME_SET;
        }
        if (!(ia_valid & ATTR_MTIME_SET) && (attr->ia_valid & ATTR_MTIME)) {
                attr->ia_mtime = now;
                attr->ia_valid |= ATTR_MTIME_SET;
        }

        if (attr->ia_valid & (ATTR_MTIME | ATTR_CTIME))
                CDEBUG(D_INODE, "setting mtime %lu, ctime %lu, now = %lu\n",
                       attr->ia_mtime, attr->ia_ctime, now);
        if (lsm)
                attr->ia_valid &= ~ATTR_SIZE;

        /* If only OST attributes being set on objects, don't do MDS RPC.
         * In that case, we need to check permissions and update the local
         * inode ourselves so we can call obdo_from_inode() always. */
        if (ia_valid & (lsm ? ~(OST_ATTR | ATTR_FROM_OPEN | ATTR_RAW) : ~0)) {
                struct lustre_md md;
                ll_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

                rc = mdc_setattr(&sbi->ll_mdc_conn, &op_data,
                                  attr, NULL, 0, NULL, 0, &request);

                if (rc) {
                        ptlrpc_req_finished(request);
                        if (rc != -EPERM && rc != -EACCES)
                                CERROR("mdc_setattr fails: rc = %d\n", rc);
                        RETURN(rc);
                }

                rc = mdc_req2lustre_md(request, 0, &sbi->ll_osc_conn, &md);
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
                                    (rc = permission(inode, MAY_WRITE)) != 0)
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
                struct ldlm_extent extent = { .start = attr->ia_size,
                                              .end = OBD_OBJECT_EOF };
                struct lustre_handle lockh = { 0 };
                int err;

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
                /* bug 1639: avoid write/truncate i_sem/DLM deadlock */
                LASSERT(atomic_read(&inode->i_sem.count) <= 0);
                up(&inode->i_sem);
                rc = ll_extent_lock_no_validate(NULL, inode, lsm, LCK_PW,
                                                 &extent, &lockh);
                down(&inode->i_sem);
                if (rc != ELDLM_OK) {
                        if (rc > 0)
                                RETURN(-ENOLCK);
                        RETURN(rc);
                }

                rc = vmtruncate(inode, attr->ia_size);
                if (rc == 0)
                        set_bit(LLI_F_HAVE_SIZE_LOCK,
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
                       inode->i_ino, attr->ia_mtime);
                oa.o_id = lsm->lsm_object_id;
                oa.o_valid = OBD_MD_FLID;
                obdo_from_inode(&oa, inode, OBD_MD_FLTYPE | OBD_MD_FLATIME |
                                            OBD_MD_FLMTIME | OBD_MD_FLCTIME);
                rc = obd_setattr(&sbi->ll_osc_conn, &oa, lsm, NULL);
                if (rc)
                        CERROR("obd_setattr fails: rc=%d\n", rc);
        }
        RETURN(rc);
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        int rc = inode_change_ok(de->d_inode, attr);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s\n", de->d_name.name);
        if (rc)
                return rc;

        lprocfs_counter_incr(ll_i2sbi(de->d_inode)->ll_stats, LPROC_LL_SETATTR);
        return ll_inode_setattr(de->d_inode, attr, 1);
}

int ll_statfs_internal(struct super_block *sb, struct obd_statfs *osfs,
                       unsigned long max_age)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_statfs obd_osfs;
        int rc;
        ENTRY;

        rc = obd_statfs(class_conn2obd(&sbi->ll_mdc_conn), osfs, max_age);
        if (rc) {
                CERROR("mdc_statfs fails: rc = %d\n", rc);
                RETURN(rc);
        }

        CDEBUG(D_SUPER, "MDC blocks "LPU64"/"LPU64" objects "LPU64"/"LPU64"\n",
               osfs->os_bavail, osfs->os_blocks, osfs->os_ffree,osfs->os_files);

        rc = obd_statfs(class_conn2obd(&sbi->ll_osc_conn), &obd_osfs, max_age);
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
        }

        if (body->valid & OBD_MD_FLID)
                inode->i_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                LTIME_S(inode->i_atime) = body->atime;
        if (body->valid & OBD_MD_FLMTIME) {
                CDEBUG(D_INODE, "setting ino %lu mtime from %lu to %u\n",
                       inode->i_ino, LTIME_S(inode->i_mtime), body->mtime);
                LTIME_S(inode->i_mtime) = body->mtime;
        }
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

int it_disposition(struct lookup_intent *it, int flag)
{
        return it->it_disposition & flag;
}

void it_set_disposition(struct lookup_intent *it, int flag)
{
        it->it_disposition |= flag;
}

void ll_umount_begin(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_device *obd;
        struct obd_ioctl_data ioc_data = { 0 };
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:\n");

        obd = class_conn2obd(&sbi->ll_mdc_conn);
        if (obd == NULL) {
                CERROR("Invalid MDC connection handle "LPX64"\n",
                       sbi->ll_mdc_conn.cookie);
                EXIT;
                return;
        }
        obd->obd_no_recov = 1;
        obd_iocontrol(IOC_OSC_SET_ACTIVE, &sbi->ll_mdc_conn, sizeof ioc_data,
                      &ioc_data, NULL);

        obd = class_conn2obd(&sbi->ll_osc_conn);
        obd->obd_no_recov = 1;
        obd_iocontrol(IOC_OSC_SET_ACTIVE, &sbi->ll_osc_conn, sizeof ioc_data,
                      &ioc_data, NULL);

        /* Really, we'd like to wait until there are no requests outstanding,
         * and then continue.  For now, we just invalidate the requests,
         * schedule, and hope.
         */
        schedule();

        EXIT;
}
