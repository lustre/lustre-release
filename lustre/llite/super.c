/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copryright (C) 2002 Cluster File Systems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/random.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/obd_lov.h>
#include <linux/lustre_dlm.h>
#include <linux/init.h>

kmem_cache_t *ll_file_data_slab;
extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
struct super_operations ll_super_operations;

extern int ll_recover(struct recovd_data *, int);
extern int ll_commitcbd_setup(struct ll_sb_info *);
extern int ll_commitcbd_cleanup(struct ll_sb_info *);

static char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;
        ENTRY;

        CDEBUG(D_SUPER, "option: %s, data %s\n", opt, data);
        if ( strncmp(opt, data, strlen(opt)) )
                RETURN(NULL);
        if ( (value = strchr(data, '=')) == NULL )
                RETURN(NULL);

        value++;
        OBD_ALLOC(retval, strlen(value) + 1);
        if ( !retval ) {
                CERROR("out of memory!\n");
                RETURN(NULL);
        }

        memcpy(retval, value, strlen(value)+1);
        CDEBUG(D_SUPER, "Assigned option: %s, value %s\n", opt, retval);
        RETURN(retval);
}

static void ll_options(char *options, char **ost, char **mds)
{
        char *this_char;
        ENTRY;

        if (!options) {
                EXIT;
                return;
        }

        for (this_char = strtok (options, ",");
             this_char != NULL;
             this_char = strtok (NULL, ",")) {
                CDEBUG(D_SUPER, "this_char %s\n", this_char);
                if ( (!*ost && (*ost = ll_read_opt("osc", this_char)))||
                     (!*mds && (*mds = ll_read_opt("mdc", this_char))) )
                        continue;
        }
        EXIT;
}

#ifndef log2
#define log2(n) ffz(~(n))
#endif

static struct super_block * ll_read_super(struct super_block *sb,
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
        __u64 last_committed;
        __u64 last_xid;
        struct ptlrpc_request *request = NULL;
        struct ll_inode_md md;
        class_uuid_t uuid;

        ENTRY;
        MOD_INC_USE_COUNT;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi) {
                MOD_DEC_USE_COUNT;
                RETURN(NULL);
        }

        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, sbi->ll_sb_uuid);

        sb->u.generic_sbp = sbi;

        ll_options(data, &osc, &mdc);

        if (!osc) {
                CERROR("no osc\n");
                GOTO(out_free, sb = NULL);
        }

        if (!mdc) {
                CERROR("no mdc\n");
                GOTO(out_free, sb = NULL);
        }

        obd = class_uuid2obd(mdc);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", mdc);
                GOTO(out_free, sb = NULL);
        }

        err = obd_connect(&sbi->ll_mdc_conn, obd, sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                GOTO(out_free, sb = NULL);
        }

#warning Peter: is this the right place to raise the connection level?
        sbi2mdc(sbi)->cl_import.imp_connection->c_level = LUSTRE_CONN_FULL;

        obd = class_uuid2obd(osc);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                GOTO(out_mdc, sb = NULL);
        }
        err = obd_connect(&sbi->ll_osc_conn, obd, sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                GOTO(out_mdc, sb = NULL);
        }

        /* XXX: need to store the last_* values somewhere */
        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid, &last_committed,
                            &last_xid, &request);
        ptlrpc_req_finished(request);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_mdc, sb = NULL);
        }
        CDEBUG(D_SUPER, "rootfid %Ld\n", (unsigned long long)rootfid.id);
        sbi->ll_rootino = rootfid.id;

        memset(&osfs, 0, sizeof(osfs));
        request = NULL;
        err = mdc_statfs(&sbi->ll_mdc_conn, &osfs, &request);
        ptlrpc_req_finished(request);
        sb->s_blocksize = osfs.os_bsize;
        sb->s_blocksize_bits = log2(osfs.os_bsize);
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_maxbytes = (1ULL << (32 + 9)) - osfs.os_bsize;

        sb->s_op = &ll_super_operations;

        /* make root inode */
        request = NULL;
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

        md.body = lustre_msg_buf(request->rq_repmsg, 0);
        md.md = NULL;
        root = iget4(sb, sbi->ll_rootino, NULL, &md);

        if (root) {
                sb->s_root = d_alloc_root(root);
        } else {
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_cdb, sb = NULL);
        }

        ptlrpc_req_finished(request);

out_dev:
        if (mdc)
                OBD_FREE(mdc, strlen(mdc) + 1);
        if (osc)
                OBD_FREE(osc, strlen(osc) + 1);

        RETURN(sb);

out_cdb:
        ll_commitcbd_cleanup(sbi);
out_request:
        ptlrpc_req_finished(request);
        obd_disconnect(&sbi->ll_osc_conn);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn);
out_free:
        OBD_FREE(sbi, sizeof(*sbi));

        MOD_DEC_USE_COUNT;
        goto out_dev;
} /* ll_read_super */

static void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        ENTRY;
        ll_commitcbd_cleanup(sbi);
        obd_disconnect(&sbi->ll_osc_conn);
        obd_disconnect(&sbi->ll_mdc_conn);
        OBD_FREE(sbi, sizeof(*sbi));

        MOD_DEC_USE_COUNT;
        EXIT;
} /* ll_put_super */

static void ll_clear_inode(struct inode *inode)
{
        if (atomic_read(&inode->i_count) == 0) {
                struct ll_inode_info *lli = ll_i2info(inode);
                struct lov_stripe_md *md = lli->lli_smd;
                char *symlink_name = lli->lli_symlink_name;

                if (md) {
                        int size = sizeof(*md) +
                                md->lmd_stripe_count * sizeof(struct lov_oinfo);
                        OBD_FREE(md, size);
                        lli->lli_smd = NULL;
                }
                if (symlink_name) {
                        OBD_FREE(symlink_name, strlen(symlink_name) + 1);
                        lli->lli_symlink_name = NULL;
                }
        }
}

static void ll_delete_inode(struct inode *inode)
{
        if (S_ISREG(inode->i_mode)) {
                int err;
                struct obdo *oa;
                struct lov_stripe_md *md = ll_i2info(inode)->lli_smd;

                if (!md)
                        GOTO(out, -EINVAL);

                if (md->lmd_object_id == 0) {
                        CERROR("This really happens\n");
                        /* No obdo was ever created */
                        GOTO(out, 0);
                }

                oa = obdo_alloc();
                if (oa == NULL)
                        GOTO(out, -ENOMEM);

                oa->o_id = md->lmd_object_id;
                oa->o_easize = md->lmd_easize;
                oa->o_mode = inode->i_mode;
                oa->o_valid = OBD_MD_FLID | OBD_MD_FLEASIZE | OBD_MD_FLMODE;

                err = obd_destroy(ll_i2obdconn(inode), oa, md);
                obdo_free(oa);
                CDEBUG(D_SUPER, "obd destroy of %Ld error %d\n",
                       md->lmd_object_id, err);
        }
out:
        clear_inode(inode);
}

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
        int err;

        ENTRY;

        /* change incore inode */
        ll_attr2inode(inode, attr, do_trunc);

        err = mdc_setattr(&sbi->ll_mdc_conn, inode, attr, &request);
        if (err)
                CERROR("mdc_setattr fails (%d)\n", err);

        ptlrpc_req_finished(request);

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
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_s2sbi(sb);
        struct obd_statfs osfs;
        int rc;
        ENTRY;

        memset(sfs, 0, sizeof(*sfs));
        rc = mdc_statfs(&sbi->ll_mdc_conn, &osfs, &request);
        statfs_unpack(sfs, &osfs);
        ptlrpc_req_finished(request);
        if (rc)
                CERROR("mdc_statfs fails: rc = %d\n", rc);
        else
                CDEBUG(D_SUPER, "mdc_statfs shows blocks "LPU64"/"LPU64
                       " objects "LPU64"/"LPU64"\n",
                       osfs.os_bavail, osfs.os_blocks,
                       osfs.os_ffree, osfs.os_files);

        /* temporary until mds_statfs returns statfs info for all OSTs */
        if (!rc) {
                struct statfs obd_sfs;

                rc = obd_statfs(&sbi->ll_osc_conn, &osfs);
                statfs_unpack(&obd_sfs, &osfs);
                if (rc) {
                        CERROR("obd_statfs fails: rc = %d\n", rc);
                        GOTO(out, rc);
                }
                CDEBUG(D_SUPER, "obd_statfs shows blocks "LPU64"/"LPU64
                       " objects "LPU64"/"LPU64"\n",
                       osfs.os_bavail, osfs.os_blocks,
                       osfs.os_ffree, osfs.os_files);

                sfs->f_bfree = obd_sfs.f_bfree;
                sfs->f_bavail = obd_sfs.f_bavail;
                sfs->f_blocks = obd_sfs.f_blocks;
                if (obd_sfs.f_ffree < sfs->f_ffree)
                        sfs->f_ffree = obd_sfs.f_ffree;
        }

out:
        RETURN(rc);
}

inline int ll_stripe_mds_md_size(struct super_block *sb)
{
        struct client_obd *mdc = sbi2mdc(ll_s2sbi(sb));
        return mdc->cl_max_mdsize;
}

static void ll_read_inode2(struct inode *inode, void *opaque)
{
        struct ll_inode_md *md = opaque;
        struct mds_body *body = md->body;
        struct ll_inode_info *lli = ll_i2info(inode);
        ENTRY;

        sema_init(&lli->lli_open_sem, 1);

        /* core attributes first */
        if (body->valid & OBD_MD_FLID)
                inode->i_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                inode->i_atime = body->atime;
        if (body->valid & OBD_MD_FLMTIME)
                inode->i_mtime = body->mtime;
        if (body->valid & OBD_MD_FLCTIME)
                inode->i_ctime = body->ctime;
        if (body->valid & OBD_MD_FLMODE)
                inode->i_mode = body->mode;
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
                inode->i_rdev = body->extra;
        if (body->valid & OBD_MD_FLSIZE)
                inode->i_size = body->size;


        //if (body->valid & OBD_MD_FLEASIZE)
        if (md && md->md && md->md->lmd_stripe_count) {
                struct lov_mds_md *smd = md->md;
                int size;
                if (md->md->lmd_easize != ll_stripe_mds_md_size(inode->i_sb)) {
                        CERROR("Striping metadata size error %ld\n",
                               inode->i_ino);
                        LBUG();
                }
                size = sizeof(*lli->lli_smd) +
                        md->md->lmd_stripe_count * sizeof(struct lov_oinfo);
                OBD_ALLOC(lli->lli_smd, size);
                if (!lli->lli_smd) {
                        CERROR("No memory for %d\n", size);
                        LBUG();
                }
                lov_unpackmd(lli->lli_smd, smd);
        } else {
                lli->lli_smd = NULL;
        }

        /* Get the authoritative file size */
        if (lli->lli_smd && (inode->i_mode & S_IFREG)) {
                int rc;

                rc = ll_file_size(inode, lli->lli_smd);
                if (rc) {
                        CERROR("ll_file_size: %d\n", rc);
                        /* FIXME: need to somehow prevent inode creation */
                        LBUG();
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
                init_special_inode(inode, inode->i_mode, inode->i_rdev);
                EXIT;
        }

        return;
}

/* exported operations */
struct super_operations ll_super_operations =
{
        read_inode2: ll_read_inode2,
        clear_inode: ll_clear_inode,
        delete_inode: ll_delete_inode,
        put_super: ll_put_super,
        statfs: ll_statfs
};

struct file_system_type lustre_lite_fs_type = {
        "lustre_lite", 0, ll_read_super, NULL
};

static int __init init_lustre_lite(void)
{
        printk(KERN_INFO "Lustre Lite 0.0.1, info@clusterfs.com\n");
        ll_file_data_slab = kmem_cache_create("ll_file_data",
                                              sizeof(struct ll_file_data), 0,
                                               SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ll_file_data_slab == NULL)
                return -ENOMEM;
        return register_filesystem(&lustre_lite_fs_type);
}

static void __exit exit_lustre_lite(void)
{
        unregister_filesystem(&lustre_lite_fs_type);
        kmem_cache_destroy(ll_file_data_slab);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lite Client File System v1.0");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
