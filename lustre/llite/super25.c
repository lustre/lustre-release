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

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#include <asm/statfs.h>
kmem_cache_t *ll_file_data_slab;
extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
struct super_operations ll_super_operations;

/* /proc/lustre/llite root that tracks llite mount points */
struct proc_dir_entry *proc_lustre_fs_root = NULL;
/* lproc_llite.c */
extern int lprocfs_register_mountpoint(struct proc_dir_entry *parent,
                                       struct super_block *sb,
                                       char *osc, char *mdc);

extern int ll_init_inodecache(void);
extern void ll_destroy_inodecache(void);
extern int ll_recover(struct recovd_data *, int);
extern int ll_commitcbd_setup(struct ll_sb_info *);
extern int ll_commitcbd_cleanup(struct ll_sb_info *);
int ll_read_inode2(struct inode *inode, void *opaque);

extern int ll_proc_namespace(struct super_block* sb, char* osc, char* mdc);

static char *ll_read_opt(const char *opt, char *data)
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

static int ll_set_opt(const char *opt, char *data, int fl)
{
        ENTRY;

        CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
        if (strncmp(opt, data, strlen(opt)))
                RETURN(0);
        else
                RETURN(fl);
}

static void ll_options(char *options, char **ost, char **mds, int *flags)
{
        char *opt_ptr = options;
        char *this_char;
        ENTRY;

        if (!options) {
                EXIT;
                return;
        }

        while ((this_char = strsep (&opt_ptr, ",")) != NULL) {
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

#ifndef log2
#define log2(n) ffz(~(n))
#endif


static int ll_fill_super(struct super_block *sb, void *data, int silent)
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

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        INIT_LIST_HEAD(&sbi->ll_orphan_dentry_list);
        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        sb->s_fs_info = sbi;

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

        err = obd_connect(&sbi->ll_mdc_conn, obd, &sbi->ll_sb_uuid,
                          ptlrpc_recovd, ll_recover);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, sb = NULL);
        }

        mdc_conn = sbi2mdc(sbi)->cl_import.imp_connection;
        list_add(&mdc_conn->c_sb_chain, &sbi->ll_conn_chain);

        obd = class_uuid2obd(osc);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_mdc, sb = NULL);
        }

        err = obd_connect(&sbi->ll_osc_conn, obd, &sbi->ll_sb_uuid,
                          ptlrpc_recovd, ll_recover);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_mdc, sb = NULL);
        }

        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_mdc, sb = NULL);
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

        /* make root inode */
        err = mdc_getattr(&sbi->ll_mdc_conn, sbi->ll_rootino, S_IFDIR,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                GOTO(out_request, sb = NULL);
        }

        /* initialize committed transaction callback daemon */
        spin_lock_init(&sbi->ll_commitcbd_lock);
        init_waitqueue_head(&sbi->ll_commitcbd_waitq);
        init_waitqueue_head(&sbi->ll_commitcbd_ctl_waitq);
        sbi->ll_commitcbd_flags = 0;
        err = ll_commitcbd_setup(sbi);
        if (err) {
                CERROR("failed to start commit callback daemon: rc = %d\n",err);
                GOTO(out_request, sb = NULL);
        }

        lic.lic_body = lustre_msg_buf(request->rq_repmsg, 0);
        lic.lic_lmm = NULL;
        root = iget5_locked(sb, sbi->ll_rootino, NULL,
                            ll_read_inode2, &lic);

        if (root) {
                sb->s_root = d_alloc_root(root);
                root->i_state &= ~(I_LOCK | I_NEW);
        } else {
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_cdb, sb = NULL);
        }

        ptlrpc_req_finished(request);
        request = NULL;

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

        RETURN(0);

out_cdb:
        ll_commitcbd_cleanup(sbi);
out_request:
        ptlrpc_req_finished(request);
        obd_disconnect(&sbi->ll_osc_conn);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn);
out_free:
        OBD_FREE(sbi, sizeof(*sbi));

        goto out_dev;
} /* ll_fill_super */

struct super_block * ll_get_sb(struct file_system_type *fs_type,
                               int flags, char *devname, void * data)
{
        return get_sb_nodev(fs_type, flags, data, ll_fill_super);
}

static void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct list_head *tmp, *next;
        struct ll_fid rootfid;
        ENTRY;

        list_del(&sbi->ll_conn_chain);
        ll_commitcbd_cleanup(sbi);
        obd_disconnect(&sbi->ll_osc_conn);

        /* NULL request to force sync on the MDS, and get the last_committed
         * value to flush remaining RPCs from the pending queue on client.
         *
         * XXX This should be an mdc_sync() call to sync the whole MDS fs,
         *     which we can call for other reasons as well.
         */
        mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);

        if (sbi->ll_proc_root) {
                lprocfs_remove(sbi->ll_proc_root);
        sbi->ll_proc_root = NULL;
        }

        obd_disconnect(&sbi->ll_mdc_conn);

        spin_lock(&dcache_lock);
        list_for_each_safe(tmp, next, &sbi->ll_orphan_dentry_list){
                struct dentry *dentry = list_entry(tmp, struct dentry, d_hash);
                shrink_dcache_parent(dentry);
        }
        spin_unlock(&dcache_lock);

        OBD_FREE(sbi, sizeof(*sbi));

        EXIT;
} /* ll_put_super */

static void ll_clear_inode(struct inode *inode)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc;
        ENTRY;

#warning "Is there a reason we don't do this in 2.5, but we do in 2.4?"
#if 0
        rc = mdc_cancel_unused(&sbi->ll_mdc_conn, inode, LDLM_FL_NO_CALLBACK);
        if (rc < 0) {
                CERROR("mdc_cancel_unused: %d\n", rc);
                /* XXX FIXME do something dramatic */
        }

        if (lli->lli_smd) {
                rc = obd_cancel_unused(&sbi->ll_osc_conn, lli->lli_smd, 0);
                if (rc < 0) {
                        CERROR("obd_cancel_unused: %d\n", rc);
                        /* XXX FIXME do something dramatic */
                }
        }
#endif

        if (atomic_read(&inode->i_count) != 0)
                CERROR("clearing in-use inode %lu: count = %d\n",
                       inode->i_ino, atomic_read(&inode->i_count));

        if (lli->lli_smd)
                obd_free_memmd(&sbi->ll_osc_conn, &lli->lli_smd);

        if (lli->lli_symlink_name) {
                OBD_FREE(lli->lli_symlink_name,strlen(lli->lli_symlink_name)+1);
                lli->lli_symlink_name = NULL;
        }

        EXIT;
}

#if 0
static void ll_delete_inode(struct inode *inode)
{
        ENTRY;
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
                oa->o_mode = inode->i_mode;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLTYPE;

                err = obd_destroy(ll_i2obdconn(inode), oa, lsm);
                obdo_free(oa);
                if (err)
                        CDEBUG(D_SUPER, "obd destroy objid "LPX64" error %d\n",
                               lsm->lsm_object_id, err);
        }
out:
        clear_inode(inode);
        EXIT;
}
#endif

/* like inode_setattr, but doesn't mark the inode dirty */
static int ll_attr2inode(struct inode * inode, struct iattr * attr, int trunc)
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
                err = mdc_setattr(&sbi->ll_mdc_conn, inode, attr, NULL, 0,
                                  &request);
                if (err)
                        CERROR("mdc_setattr fails: err = %d\n", err);

                ptlrpc_req_finished(request);
                if (S_ISREG(inode->i_mode) && attr->ia_valid & ATTR_MTIME_SET) {
                        struct lov_stripe_md *lsm = ll_i2info(inode)->lli_smd;
                        struct obdo oa;
                        int err2;

                        CDEBUG(D_ERROR, "setting mtime on OST\n");
                        oa.o_id = lsm->lsm_object_id;
                        oa.o_mode = S_IFREG;
                        oa.o_valid = OBD_MD_FLID |OBD_MD_FLTYPE |OBD_MD_FLMTIME;
                        oa.o_mtime = attr->ia_mtime.tv_sec;
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

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        int rc = inode_change_ok(de->d_inode, attr);

        if (rc)
                return rc;

        return ll_inode_setattr(de->d_inode, attr, 1);
}

static int ll_statfs(struct super_block *sb, struct statfs *sfs)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_statfs osfs;
        int rc;
        ENTRY;

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

void ll_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_mds_md *lmm)
{
        struct ll_inode_info *lli = ll_i2info(inode);

        if (lmm != NULL)
                obd_unpackmd(ll_i2obdconn(inode), &lli->lli_smd, lmm);

        if (body->valid & OBD_MD_FLID)
                inode->i_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                inode->i_atime.tv_sec = body->atime;
        if (body->valid & OBD_MD_FLMTIME)
                inode->i_mtime.tv_sec = body->mtime;
        if (body->valid & OBD_MD_FLCTIME)
                inode->i_ctime.tv_sec = body->ctime;
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

int ll_read_inode2(struct inode *inode, void *opaque)
{
        struct ll_read_inode2_cookie *lic = opaque;
        struct mds_body *body = lic->lic_body;
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc = 0;
        ENTRY;

        sema_init(&lli->lli_open_sem, 1);
        lli->flags = 0;
        init_MUTEX(&lli->lli_getattr_sem);
        /* these are 2.4 only, but putting them here for consistency.. */
        spin_lock_init(&lli->lli_read_extent_lock);
        INIT_LIST_HEAD(&lli->lli_read_extents);

        LASSERT(!lli->lli_smd);

        /* core attributes first */
        ll_update_inode(inode, body, lic ? lic->lic_lmm : NULL);

        /* Get the authoritative file size */
        if (lli->lli_smd && S_ISREG(inode->i_mode)) {
                struct ll_file_data *fd = file->private_data;
                struct ldlm_extent extent = {0, OBD_OBJECT_EOF};
                struct lustre_handle lockh = {0, 0};

                LASSERT(lli->lli_smd->lsm_object_id != 0);

                rc = ll_extent_lock(fd, inode, lsm, LCK_PR, &extent, &lockh);
                if (err != ELDLM_OK && err != ELDLM_MATCHED) {
                        ll_clear_inode(inode);
                        make_bad_inode(inode);
                } else {
                        l_extent_unlock(fd, inode, lsm, LCK_PR, &extent,
                                        &lockh);
                }
        }

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
                init_special_inode(inode, inode->i_mode,
                                   kdev_t_to_nr(inode->i_rdev));
                EXIT;
        }

        return rc;
}

static inline void invalidate_request_list(struct list_head *req_list)
{
        struct list_head *tmp, *n;
        list_for_each_safe(tmp, n, req_list) {
                struct ptlrpc_request *req =
                        list_entry(tmp, struct ptlrpc_request, rq_list);
                CERROR("invalidating req xid %d op %d to %s:%d\n",
                       (unsigned long long)req->rq_xid, req->rq_reqmsg->opc,
                       req->rq_connection->c_remote_uuid,
                       req->rq_import->imp_client->cli_request_portal);
                req->rq_flags |= PTL_RPC_FL_ERR;
                wake_up(&req->rq_wait_for_rep);
        }
}

void ll_umount_begin(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct list_head *ctmp;

        ENTRY;

        list_for_each(ctmp, &sbi->ll_conn_chain) {
                struct ptlrpc_connection *conn;
                conn = list_entry(ctmp, struct ptlrpc_connection, c_sb_chain);

                spin_lock(&conn->c_lock);
                conn->c_flags |= CONN_INVALID;
                /*invalidate_request_list(&conn->c_sending_head);*/
                invalidate_request_list(&conn->c_delayed_head);
                spin_unlock(&conn->c_lock);
        }

        EXIT;
}


static kmem_cache_t *ll_inode_cachep;

static struct inode *ll_alloc_inode(struct super_block *sb)
{
        struct ll_inode_info *lli;
        lli = kmem_cache_alloc(ll_inode_cachep, SLAB_KERNEL);
        if (!lli)
                return NULL;

        memset(lli, 0, (char *)&lli->lli_vfs_inode - (char *)lli);
        sema_init(&lli->lli_open_sem, 1);
        init_MUTEX(&lli->lli_size_valid_sem);

        return &lli->lli_vfs_inode;
}

static void ll_destroy_inode(struct inode *inode)
{
        kmem_cache_free(ll_inode_cachep, ll_i2info(inode));
}

static void init_once(void * foo, kmem_cache_t * cachep, unsigned long flags)
{
        struct ll_inode_info *lli = foo;

        if ((flags & (SLAB_CTOR_VERIFY|SLAB_CTOR_CONSTRUCTOR)) ==
            SLAB_CTOR_CONSTRUCTOR)
                inode_init_once(&lli->lli_vfs_inode);
}

int ll_init_inodecache(void)
{
        ll_inode_cachep = kmem_cache_create("lustre_inode_cache",
                                            sizeof(struct ll_inode_info),
                                            0, SLAB_HWCACHE_ALIGN,
                                            init_once, NULL);
        if (ll_inode_cachep == NULL)
                return -ENOMEM;
        return 0;
}

void ll_destroy_inodecache(void)
{
        if (kmem_cache_destroy(ll_inode_cachep))
                CERROR("ll_inode_cache: not all structures were freed\n");
}



/* exported operations */
struct super_operations ll_super_operations =
{
        alloc_inode: ll_alloc_inode,
        destroy_inode: ll_destroy_inode,
        clear_inode: ll_clear_inode,
//        delete_inode: ll_delete_inode,
        put_super: ll_put_super,
        statfs: ll_statfs,
        umount_begin: ll_umount_begin
};


struct file_system_type lustre_lite_fs_type = {
        .owner  = THIS_MODULE,
        .name =   "lustre_lite",
        .get_sb = ll_get_sb,
        .kill_sb = kill_anon_super,
};

static int __init init_lustre_lite(void)
{
        int rc;
        printk(KERN_INFO "Lustre Lite Client File System; "
               "info@clusterfs.com\n");
        rc = ll_init_inodecache();
        if (rc)
                return -ENOMEM;
        ll_file_data_slab = kmem_cache_create("ll_file_data",
                                              sizeof(struct ll_file_data), 0,
                                              SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ll_file_data_slab == NULL) {
                ll_destroy_inodecache();
                return -ENOMEM;
        }

        proc_lustre_fs_root = proc_lustre_root ?
                              proc_mkdir("llite", proc_lustre_root) : NULL;

        return register_filesystem(&lustre_lite_fs_type);
}

static void __exit exit_lustre_lite(void)
{
        unregister_filesystem(&lustre_lite_fs_type);
        ll_destroy_inodecache();
        kmem_cache_destroy(ll_file_data_slab);
        if (proc_lustre_fs_root) {
                lprocfs_remove(proc_lustre_fs_root);
                proc_lustre_fs_root = NULL;
        }
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lite Client File System");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
#endif
