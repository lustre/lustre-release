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

#include <linux/config.h>
#include <linux/module.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>

kmem_cache_t *ll_file_data_slab;
extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
struct super_operations ll_super_operations;
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

static void ll_options(char *options, char **dev, char **vers)
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
                if ( (!*dev && (*dev = ll_read_opt("device", this_char)))||
                     (!*vers && (*vers = ll_read_opt("version", this_char))) )
                        continue;
        }
        EXIT;
}

static struct super_block * ll_read_super(struct super_block *sb,
                                          void *data, int silent)
{
        struct inode *root = 0;
        struct ll_sb_info *sbi;
        char *device = NULL;
        char *version = NULL;
        int devno;
        int err;
        struct ll_fid rootfid;
        struct ptlrpc_request *request = NULL;

        ENTRY;
        MOD_INC_USE_COUNT;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi) {
                MOD_DEC_USE_COUNT;
                RETURN(NULL);
        }

        sb->u.generic_sbp = sbi;

        ll_options(data, &device, &version);

        if ( !device ) {
                CERROR("no device\n");
                GOTO(out_free, sb = NULL);
        }

        devno = simple_strtoul(device, NULL, 0);
        if ( devno >= MAX_OBD_DEVICES ) {
                CERROR("device of %s too high\n", device);
                GOTO(out_free, sb = NULL);
        }

        sbi->ll_conn.oc_dev = &obd_dev[devno];
        err = obd_connect(&sbi->ll_conn);
        if ( err ) {
                CERROR("cannot connect to %s\n", device);
                GOTO(out_free, sb = NULL);
        }

        ptlrpc_init_client(ptlrpc_connmgr, MDS_REQUEST_PORTAL, MDC_REPLY_PORTAL,
                           &sbi->ll_mds_client);

        sbi->ll_mds_conn = ptlrpc_uuid_to_connection("mds");
        if (!sbi->ll_mds_conn) {
                CERROR("cannot find MDS\n");
                GOTO(out_disc, sb = NULL);
        }

        err = connmgr_connect(ptlrpc_connmgr, sbi->ll_mds_conn);
        if (err) {
                CERROR("cannot connect to MDS\n");
                GOTO(out_disc, sb = NULL);
        }

        sbi->ll_mds_conn->c_level = LUSTRE_CONN_FULL;

        err= mdc_connect(&sbi->ll_mds_client, sbi->ll_mds_conn, 
                    &rootfid, &request); 
        CERROR("rootfid %Ld\n", rootfid.id);
        if (err) { 
                CERROR("cannot mds_connect %d\n", err);
                GOTO(out_disc, sb = NULL);
        }
        sbi->ll_rootino = rootfid.id;

        sb->s_maxbytes = 1ULL << 36;
        sb->s_blocksize = PAGE_SIZE;
        sb->s_blocksize_bits = (unsigned char)PAGE_SHIFT;
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_op = &ll_super_operations;

        /* make root inode */
        err = mdc_getattr(&sbi->ll_mds_client, sbi->ll_mds_conn,
                          sbi->ll_rootino, S_IFDIR,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, &request);
        if (err) {
                CERROR("mdc_getattr failed for root %d\n", err);
                GOTO(out_req, sb = NULL);
        }

        /* initialize committed transaction callback daemon */
        INIT_LIST_HEAD(&sbi->ll_commitcbd_not_committed);
        spin_lock_init(&sbi->ll_commitcbd_lock); 
        init_waitqueue_head(&sbi->ll_commitcbd_waitq);
        init_waitqueue_head(&sbi->ll_commitcbd_ctl_waitq);
        sbi->ll_commitcbd_flags = 0;
        err = ll_commitcbd_setup(sbi);
        if (err) { 
                CERROR("failed to start commit callback daemon\n");
                GOTO(out_req, sb = NULL); 
        }

        root = iget4(sb, sbi->ll_rootino, NULL,
                     lustre_msg_buf(request->rq_repmsg, 0));
        if (root) {
                sb->s_root = d_alloc_root(root);
        } else {
                CERROR("lustre_lite: bad iget4 for root\n");
                GOTO(out_req, sb = NULL);
        }

out_req:
        ptlrpc_free_req(request);
        if (!sb) {
out_disc:
                obd_disconnect(&sbi->ll_conn);
out_free:
                MOD_DEC_USE_COUNT;
                OBD_FREE(sbi, sizeof(*sbi));
        }
        if (device) 
                OBD_FREE(device, strlen(device) + 1);
        if (version)
                OBD_FREE(version, strlen(version) + 1);

        RETURN(sb);
} /* ll_read_super */

static void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = sb->u.generic_sbp;
        ENTRY;
        ll_commitcbd_cleanup(sbi);
        obd_disconnect(&sbi->ll_conn);
        ptlrpc_put_connection(sbi->ll_mds_conn);
        OBD_FREE(sb->u.generic_sbp, sizeof(*sbi));
        MOD_DEC_USE_COUNT;
        EXIT;
} /* ll_put_super */


extern inline struct obdo * ll_oa_from_inode(struct inode *inode, int valid);
static void ll_delete_inode(struct inode *inode)
{
        if (S_ISREG(inode->i_mode)) { 
                int err; 
                struct obdo *oa; 
                oa = ll_oa_from_inode(inode, OBD_MD_FLNOTOBD);
                if (!oa) { 
                        CERROR("no memory\n"); 
                }

                err = obd_destroy(ll_i2obdconn(inode), oa); 
                CDEBUG(D_INODE, "obd destroy of %Ld error %d\n",
                       (unsigned long long)oa->o_id, err);
                obdo_free(oa);
        }

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

        err = mdc_setattr(&sbi->ll_mds_client, sbi->ll_mds_conn, inode, attr,
                          &request);
        if (err)
                CERROR("mdc_setattr fails (%d)\n", err);

        ptlrpc_free_req(request);

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

        err = obd_statfs(ID(sb), &tmp);
        if ( err ) { 
                CERROR("obd_statfs fails (%d)\n", err);
                RETURN(err);
        }
        memcpy(buf, &tmp, sizeof(*buf));
        CDEBUG(D_SUPER, "statfs returns avail %ld\n", tmp.f_bavail);

        RETURN(err);
}

static void inline ll_to_inode(struct inode *dst, struct mds_body *body)
{
        struct ll_inode_info *ii = 
                (struct ll_inode_info *) &dst->u.generic_ip;

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
        if (body->valid & OBD_MD_FLOBJID) 
                ii->lli_objid = body->objid;
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
        struct mds_body *body = opaque; 
        
        ENTRY;
        ll_to_inode(inode, body); 

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
        delete_inode: ll_delete_inode,
        put_super: ll_put_super,
        // statfs: ll_statfs
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
