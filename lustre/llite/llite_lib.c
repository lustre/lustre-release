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



/* whole file is conditional, but we need KERNEL_VERSION and friends */
kmem_cache_t *ll_file_data_slab;
struct super_operations ll_super_operations;

/* /proc/lustre/llite root that tracks llite mount points */
struct proc_dir_entry *proc_lustre_fs_root = NULL;


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
        char *this_char, *opt_ptr;
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

struct super_block *ll_fill_super(struct super_block *sb,
                                  void *data, int silent)
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
        struct ll_read_inode2_cookie lic;
        class_uuid_t uuid;
        struct obd_uuid param_uuid;

        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:\n");
        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(NULL);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        INIT_HLIST_HEAD(&sbi->ll_orphan_dentry_list);
        generate_random_uuid(uuid);
        spin_lock_init(&sbi->ll_iostats.fis_lock);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        ll_s2sbi(sb) = sbi;

        ll_options(data, &osc, &mdc, &sbi->ll_flags);

        if (!osc) {
                CERROR("no osc\n");
                GOTO(out_free, sb = NULL);
        }

        if (!mdc) {
                CERROR("no mdc\n");
                GOTO(out_free, sb = NULL);
        }

        strncpy(param_uuid.uuid, mdc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", mdc);
                GOTO(out_free, sb = NULL);
        }

        err = obd_connect(&sbi->ll_mdc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, sb = NULL);
        }

        mdc_conn = sbi2mdc(sbi)->cl_import->imp_connection;

        strncpy(param_uuid.uuid, osc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_mdc, sb = NULL);
        }

        err = obd_connect(&sbi->ll_osc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_mdc, sb = NULL);
        }

        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_osc, sb = NULL);
        }
        CDEBUG(D_SUPER, "rootfid "LPU64"\n", rootfid.id);
        sbi->ll_rootino = rootfid.id;

        memset(&osfs, 0, sizeof(osfs));
        err = obd_statfs(&sbi->ll_mdc_conn, &osfs);
        sb->s_blocksize = osfs.os_bsize;
        sb->s_blocksize_bits = log2(osfs.os_bsize);
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_maxbytes = (1ULL << (32 + 9)) - osfs.os_bsize;

        sb->s_op = &ll_super_operations;

        /* make root inode 
         * XXX: move this to after cbd setup? */
        err = mdc_getattr(&sbi->ll_mdc_conn, &rootfid,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                GOTO(out_osc, sb = NULL);
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
                GOTO(out_osc, sb = NULL);
        }

        lic.lic_body = lustre_msg_buf(request->rq_repmsg, 0,
                                      sizeof(*lic.lic_body));
        LASSERT (lic.lic_body != NULL);         /* checked by mdc_getattr() */
        LASSERT_REPSWABBED (request, 0);        /* swabbed by mdc_getattr() */

        lic.lic_lsm = NULL;

        LASSERT(sbi->ll_rootino != 0);
        root = ll_iget(sb, sbi->ll_rootino, &lic);

        ptlrpc_req_finished(request);

        if (root == NULL || is_bad_inode(root)) {
                /* XXX might need iput() for bad inode */
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_cbd, sb = NULL);
        }

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

        RETURN(sb);

out_cbd:
        ll_commitcbd_cleanup(sbi);
out_osc:
        obd_disconnect(&sbi->ll_osc_conn, 0);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn, 0);
out_free:
        OBD_FREE(sbi, sizeof(*sbi));

        goto out_dev;
} /* ll_read_super */

int ll_statfs(struct super_block *sb, struct statfs *sfs)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_statfs osfs;
        int rc;
        ENTRY;

        CDEBUG(D_VFSTRACE, "VFS Op:\n");
        memset(sfs, 0, sizeof(*sfs));
        rc = obd_statfs(&sbi->ll_mdc_conn, &osfs);
        statfs_unpack(sfs, &osfs);
        if (rc)
                CERROR("mdc_statfs fails: rc = %d\n", rc);
        else
                CDEBUG(D_SUPER, "mdc_statfs shows blocks "LPU64"/"LPU64
                       " objects "LPU64"/"LPU64"\n",
                       osfs.os_bavail, osfs.os_blocks,
                       osfs.os_ffree, osfs.os_files);

        /* temporary until mds_statfs returns statfs info for all OSTs */
        if (!rc) {
                rc = obd_statfs(&sbi->ll_osc_conn, &osfs);
                if (rc) {
                        CERROR("obd_statfs fails: rc = %d\n", rc);
                        GOTO(out, rc);
                }
                CDEBUG(D_SUPER, "obd_statfs shows blocks "LPU64"/"LPU64
                       " objects "LPU64"/"LPU64"\n",
                       osfs.os_bavail, osfs.os_blocks,
                       osfs.os_ffree, osfs.os_files);

                while (osfs.os_blocks > ~0UL) {
                        sfs->f_bsize <<= 1;

                        osfs.os_blocks >>= 1;
                        osfs.os_bfree >>= 1;
                        osfs.os_bavail >>= 1;
                }
                sfs->f_blocks = osfs.os_blocks;
                sfs->f_bfree = osfs.os_bfree;
                sfs->f_bavail = osfs.os_bavail;
                if (osfs.os_ffree < (__u64)sfs->f_ffree)
                        sfs->f_ffree = osfs.os_ffree;
        }

out:
        RETURN(rc);
}
/* like inode_setattr, but doesn't mark the inode dirty */
static int ll_attr2inode(struct inode *inode, struct iattr *attr, int trunc)
{
        unsigned int ia_valid = attr->ia_valid;
        int error = 0;

        if ((ia_valid & ATTR_SIZE) && trunc) {
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
        ll_attr2inode(inode, attr, do_trunc);

        /* Don't send size changes to MDS to avoid "fast EA" problems, and
         * also avoid a pointless RPC (we get file size from OST anyways).
         */
        attr->ia_valid &= ~ATTR_SIZE;
        if (attr->ia_valid) {
                struct mdc_op_data op_data;

                ll_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);
                err = mdc_setattr(&sbi->ll_mdc_conn, &op_data,
                                  attr, NULL, 0, &request);
                if (err)
                        CERROR("mdc_setattr fails: err = %d\n", err);

                ptlrpc_req_finished(request);
                if (S_ISREG(inode->i_mode) && attr->ia_valid & ATTR_MTIME_SET) {
                        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                        struct obdo oa;
                        int err2;

                        CDEBUG(D_INODE, "set mtime on OST inode %lu to %Lu\n",
                               inode->i_ino, ll_ts2u64(&attr->ia_mtime));
                        oa.o_id = lsm->lsm_object_id;
                        oa.o_mode = S_IFREG;
                        oa.o_valid = OBD_MD_FLID |OBD_MD_FLTYPE |OBD_MD_FLMTIME;
                        oa.o_mtime = ll_ts2u64(&attr->ia_mtime);
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

int ll_setattr_raw(struct inode *inode, struct iattr *attr)
{
        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ptlrpc_request *request = NULL;
        struct mdc_op_data op_data;
        int rc = 0, err;
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);

        if ((attr->ia_valid & ATTR_SIZE)) {
                struct ldlm_extent extent = {attr->ia_size, OBD_OBJECT_EOF};
                struct lustre_handle lockh = { 0, 0 };

                /* If this file doesn't have stripes yet, it is already,
                   by definition, truncated. */
                if (attr->ia_valid & ATTR_FROM_OPEN && lsm == NULL) {
                        LASSERT(attr->ia_size == 0);
                        GOTO(skip_extent_lock, rc = 0);
                }

                /* we really need to get our PW lock before we change
                 * inode->i_size.  if we don't we can race with other
                 * i_size updaters on our node, like ll_file_read.  we
                 * can also race with i_size propogation to other
                 * nodes through dirtying and writeback of final cached
                 * pages.  this last one is especially bad for racing
                 * o_append users on other nodes. */
                rc = ll_extent_lock_no_validate(NULL, inode, lsm, LCK_PW, 
                                                 &extent, &lockh);
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
                if (err)
                        CERROR("ll_extent_unlock failed: %d\n", err);
                if (rc)
                        RETURN(rc);
        }

skip_extent_lock:
        /* Don't send size changes to MDS to avoid "fast EA" problems, and
         * also avoid a pointless RPC (we get file size from OST anyways).
         */
        attr->ia_valid &= ~ATTR_SIZE;
        if (!attr->ia_valid)
                RETURN(0);

        ll_prepare_mdc_op_data(&op_data, inode, NULL, NULL, 0, 0);

        err = mdc_setattr(&sbi->ll_mdc_conn, &op_data,
                          attr, NULL, 0, &request);
        if (err)
                CERROR("mdc_setattr fails: err = %d\n", err);

        ptlrpc_req_finished(request);

        if (S_ISREG(inode->i_mode) && attr->ia_valid & ATTR_MTIME_SET) {
                struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                struct obdo oa;
                int err2;

                CDEBUG(D_INODE, "set mtime on OST inode %lu to %Lu\n",
                       inode->i_ino, ll_ts2u64(&attr->ia_mtime));
                oa.o_id = lsm->lsm_object_id;
                oa.o_mode = S_IFREG;
                oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLMTIME;
                oa.o_mtime = ll_ts2u64(&attr->ia_mtime);
                err2 = obd_setattr(&sbi->ll_osc_conn, &oa, lsm, NULL);
                if (err2) {
                        CERROR("obd_setattr fails: rc=%d\n", err);
                        if (!err)
                                err = err2;
                }
        }
        RETURN(err);
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        int rc = inode_change_ok(de->d_inode, attr);
        CDEBUG(D_VFSTRACE, "VFS Op:name=%s\n", de->d_name.name);
        if (rc)
                return rc;

        return ll_inode_setattr(de->d_inode, attr, 1);
}


void ll_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_stripe_md *lsm)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        LASSERT ((lsm != NULL) == ((body->valid & OBD_MD_FLEASIZE) != 0));
        if (lsm != NULL) {
                if (lli->lli_smd == NULL)
                        lli->lli_smd = lsm;
                else
                        LASSERT(!memcmp(lli->lli_smd, lsm, sizeof(*lsm)));
        }

        if (body->valid & OBD_MD_FLID)
                inode->i_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                LTIME_S(inode->i_atime) = body->atime;
        if (body->valid & OBD_MD_FLMTIME)
                LTIME_S(inode->i_mtime) = body->mtime;
        if (body->valid & OBD_MD_FLCTIME)
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
                inode->i_rdev = to_kdev_t(body->rdev);
        if (body->valid & OBD_MD_FLSIZE)
                inode->i_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                inode->i_blocks = body->blocks;
}

void ll_read_inode2(struct inode *inode, void *opaque)
{
        struct ll_read_inode2_cookie *lic = opaque;
        struct mds_body *body = lic->lic_body;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;
        CDEBUG(D_VFSTRACE, "VFS Op:inode=%lu\n", inode->i_ino);

        sema_init(&lli->lli_open_sem, 1);
        spin_lock_init(&lli->lli_read_extent_lock);
        INIT_LIST_HEAD(&lli->lli_read_extents);
        ll_lldo_init(&lli->lli_dirty);
        lli->lli_flags = 0;

        LASSERT(!lli->lli_smd);

        /* core attributes from the MDS first */
        ll_update_inode(inode, body, lic->lic_lsm);

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
                init_special_inode(inode, inode->i_mode, 
                                   kdev_t_to_nr(inode->i_rdev));
                EXIT;
        }
}
