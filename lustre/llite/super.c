/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copryright (C) 1996 Peter J. Braam <braam@stelias.com>
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 * Copryright (C) 2001 Mountain View Data, Inc.
 * Copryright (C) 2002 Cluster File Systems, Inc.
 *
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/module.h>
#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/lustre_dlm.h>

kmem_cache_t *ll_file_data_slab;
extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
struct super_operations ll_super_operations;

extern int ll_recover(struct ptlrpc_client *);
extern int ll_commitcbd_setup(struct ll_sb_info *);
extern int ll_commitcbd_cleanup(struct ll_sb_info *);

static char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;
        ENTRY;

        CDEBUG(D_INFO, "option: %s, data %s\n", opt, data);
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
                CDEBUG(D_INFO, "this_char %s\n", this_char);
                if ( (!*ost && (*ost = ll_read_opt("ost", this_char)))||
                     (!*mds && (*mds = ll_read_opt("mds", this_char))) )
                        continue;
        }
        EXIT;
}

static struct super_block * ll_read_super(struct super_block *sb,
                                          void *data, int silent)
{
        struct inode *root = 0;
        struct ll_sb_info *sbi;
        char *ost = NULL;
        char *mds = NULL;
        int devno;
        int err;
        struct ll_fid rootfid;
        __u64 last_committed, last_rcvd;
        __u32 last_xid;
        struct ptlrpc_request *request = NULL;
        struct ll_inode_md md;

        ENTRY;
        MOD_INC_USE_COUNT;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi) {
                MOD_DEC_USE_COUNT;
                RETURN(NULL);
        }

        sb->u.generic_sbp = sbi;

        ll_options(data, &ost, &mds);

        if (!ost) {
                CERROR("no ost\n");
                GOTO(out_free, sb = NULL);
        }

        if (!mds) {
                CERROR("no mds\n");
                GOTO(out_free, sb = NULL);
        }

        devno = simple_strtoul(ost, NULL, 0);
        if (devno >= MAX_OBD_DEVICES) {
                CERROR("devno of %s too high\n", ost);
                GOTO(out_free, sb = NULL);
        }

        sbi->ll_osc_conn.oc_dev = &obd_dev[devno];
        err = obd_connect(&sbi->ll_osc_conn);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", ost, err);
                GOTO(out_free, sb = NULL);
        }

        devno = simple_strtoul(mds, NULL, 0);
        if (devno >= MAX_OBD_DEVICES) {
                CERROR("devno of %s too high\n", mds);
                GOTO(out_free, sb = NULL);
        }

        sbi->ll_mdc_conn.oc_dev = &obd_dev[devno];
        err = obd_connect(&sbi->ll_mdc_conn);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mds, err);
                GOTO(out_free, sb = NULL);
        }

#if 0
        err = connmgr_connect(ptlrpc_connmgr, sbi->ll_mds_conn);
        if (err) {
                CERROR("cannot connect to MDS: rc = %d\n", err);
                GOTO(out_rpc, sb = NULL);
        }
#endif 

        sbi2mdc(sbi)->mdc_conn->c_level = LUSTRE_CONN_FULL;

        /* XXX: need to store the last_* values somewhere */
        err = mdc_getstatus(&sbi->ll_mdc_conn,
                            &rootfid, &last_committed, 
                            &last_rcvd, &last_xid,
                            &request);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                GOTO(out_disc, sb = NULL);
        }
        CDEBUG(D_SUPER, "rootfid %ld\n", (unsigned long)rootfid.id);
        sbi->ll_rootino = rootfid.id;

        sb->s_maxbytes = 1ULL << 36;
        /* XXX get this with a get_info call (like we have in OBDFS),
           this info call should return the blocksize of the MDS */
        sb->s_blocksize = 4096;
        sb->s_blocksize_bits = 12;
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_op = &ll_super_operations;

        /* make root inode */
        err = mdc_getattr(&sbi->ll_mdc_conn,
                          sbi->ll_rootino, S_IFDIR,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                GOTO(out_mdc, sb = NULL);
        }

        /* initialize committed transaction callback daemon */
        spin_lock_init(&sbi->ll_commitcbd_lock); 
        init_waitqueue_head(&sbi->ll_commitcbd_waitq);
        init_waitqueue_head(&sbi->ll_commitcbd_ctl_waitq);
        sbi->ll_commitcbd_flags = 0;
        err = ll_commitcbd_setup(sbi);
        if (err) {
                CERROR("failed to start commit callback daemon: rc = %d\n",err);
                GOTO(out_mdc, sb = NULL);
        }

        md.body = lustre_msg_buf(request->rq_repmsg, 0);
        md.obdo = NULL;
        root = iget4(sb, sbi->ll_rootino, NULL, &md);
                     
        if (root) {
                sb->s_root = d_alloc_root(root);
        } else {
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_cdb, sb = NULL);
        }

        ptlrpc_free_req(request);

out_dev:
        if (mds)
                OBD_FREE(mds, strlen(mds) + 1);
        if (ost)
                OBD_FREE(ost, strlen(ost) + 1);

        RETURN(sb);

out_cdb:
        ll_commitcbd_cleanup(sbi);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn);
        obd_disconnect(&sbi->ll_osc_conn);
out_disc:
        ptlrpc_free_req(request);
        obd_disconnect(&sbi->ll_osc_conn);
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
                struct obdo *oa = ll_i2info(inode)->lli_obdo;
                if (oa) {
                        obdo_free(oa);
                        ll_i2info(inode)->lli_obdo = NULL;
                }
                if (ll_i2info(inode)->lli_symlink_name) {
                        OBD_FREE(ll_i2info(inode)->lli_symlink_name,
                                 strlen(ll_i2info(inode)->lli_symlink_name)+ 1);
                        ll_i2info(inode)->lli_symlink_name = NULL;
                }
        }
}

static void ll_delete_inode(struct inode *inode)
{
        if (S_ISREG(inode->i_mode)) { 
                int err;
                struct obdo *oa;
                oa = ll_i2info(inode)->lli_obdo;

                if (!oa)
                        GOTO(out, -EINVAL);

                if (oa->o_id == 0)
                        /* No obdo was ever created */
                        GOTO(out, 0);

                err = obd_destroy(ll_i2obdconn(inode), oa);
                CDEBUG(D_INODE, "obd destroy of %Ld error %d\n",
                       (unsigned long long)oa->o_id, err);
        }
out:
        clear_inode(inode);
}

/* like inode_setattr, but doesn't mark the inode dirty */ 
static int ll_attr2inode(struct inode * inode, struct iattr * attr, int trunc)
{
        unsigned int ia_valid = attr->ia_valid;
        int error = 0;

        if ((ia_valid & ATTR_SIZE) && trunc ) {
                error = vmtruncate(inode, attr->ia_size);
                if (error)
                        goto out;
        } else if (ia_valid & ATTR_SIZE) { 
                inode->i_size = attr->ia_size;
        }               

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

        err = mdc_setattr(&sbi->ll_mdc_conn, inode, attr,
                          &request);
        if (err)
                CERROR("mdc_setattr fails (%d)\n", err);

        ptlrpc_req_finished(request);

        RETURN(err);
}

int ll_setattr(struct dentry *de, struct iattr *attr)
{
        return ll_inode_setattr(de->d_inode, attr, 1);
}

static int ll_statfs(struct super_block *sb, struct statfs *buf)
{
        struct statfs tmp;
        int err;
        ENTRY;

        err = obd_statfs(&ll_s2sbi(sb)->ll_osc_conn, &tmp);
        if (err) {
                CERROR("obd_statfs fails (%d)\n", err);
                RETURN(err);
        }
        memcpy(buf, &tmp, sizeof(*buf));
#if 0
        err = mdc_statfs(&sbi->ll_mds_client, sbi->ll_mds_conn, &tmp,
                          &request);
        if (err) {
                CERROR("obd_statfs fails (%d)\n", err);
                RETURN(err);
        }
	if (tmp.f_files < buf->f_files)
                buf->f_files = tmp.f_files;
	if (tmp.f_ffree < buf->f_ffree)
                buf->f_ffree = tmp.f_ffree;
        buf->f_namelen = tmp.f_namelen;
#endif
        CDEBUG(D_SUPER, "statfs returns avail %ld\n", tmp.f_bavail);

        RETURN(err);
}

static void inline ll_to_inode(struct inode *dst, struct ll_inode_md *md)
{
        struct mds_body *body = md->body;
        struct ll_inode_info *ii = ll_i2info(dst);

        /* core attributes first */
        if ( body->valid & OBD_MD_FLID )
                dst->i_ino = body->ino;
        if ( body->valid & OBD_MD_FLATIME ) 
                dst->i_atime = body->atime;
        if ( body->valid & OBD_MD_FLMTIME ) 
                dst->i_mtime = body->mtime;
        if ( body->valid & OBD_MD_FLCTIME ) 
                dst->i_ctime = body->ctime;
        if ( body->valid & OBD_MD_FLSIZE ) 
                dst->i_size = body->size;
        if ( body->valid & OBD_MD_FLMODE ) 
                dst->i_mode = body->mode;
        if ( body->valid & OBD_MD_FLUID ) 
                dst->i_uid = body->uid;
        if ( body->valid & OBD_MD_FLGID ) 
                dst->i_gid = body->gid;
        if ( body->valid & OBD_MD_FLFLAGS ) 
                dst->i_flags = body->flags;
        if ( body->valid & OBD_MD_FLNLINK )
                dst->i_nlink = body->nlink;
        if ( body->valid & OBD_MD_FLGENER )
                dst->i_generation = body->generation;

        /* this will become more elaborate for striping etc */ 
        if (md->obdo != NULL && md->obdo->o_valid != 0) {
                ii->lli_obdo = obdo_alloc();
                memcpy(ii->lli_obdo, md->obdo, sizeof(*md->obdo));
        }
#if 0

        if (obdo_has_inline(oa)) {
                if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
                    S_ISFIFO(inode->i_mode)) {
                        obd_rdev rdev = *((obd_rdev *)oa->o_inline);
                        CDEBUG(D_INODE,
                               "copying device %x from obdo to inode\n", rdev);
                        init_special_inode(inode, inode->i_mode, rdev);
                } else {
                        CDEBUG(D_INFO, "copying inline from obdo to inode\n");
                        memcpy(oinfo->lli_inline, oa->o_inline, OBD_INLINESZ);
                }
                oinfo->lli_flags |= OBD_FL_INLINEDATA;
        }
#endif 
} /* ll_to_inode */

static inline void ll_read_inode2(struct inode *inode, void *opaque)
{
        struct ll_inode_md *md = opaque;
        
        ENTRY;
        ll_to_inode(inode, md);

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
                                   ((int *)ll_i2info(inode)->lli_inline)[0]);
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
        printk(KERN_INFO "Lustre Lite 0.0.1, braam@clusterfs.com\n");
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

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Lite Client File System v1.0");
MODULE_LICENSE("GPL");

module_init(init_lustre_lite);
module_exit(exit_lustre_lite);
