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
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/segment.h>

#define DEBUG_SUBSYSTEM S_LLIGHT

#include <linux/lustre_light.h>

kmem_cache_t *ll_file_data_slab;
extern struct address_space_operations ll_aops;
extern struct address_space_operations ll_dir_aops;
struct super_operations ll_super_operations;

static char *ll_read_opt(const char *opt, char *data)
{
        char *value;
        char *retval;
        ENTRY;

        CDEBUG(D_INFO, "option: %s, data %s\n", opt, data);
        if ( strncmp(opt, data, strlen(opt)) ) {
                EXIT;
                return NULL;
        }
        if ( (value = strchr(data, '=')) == NULL ) {
                EXIT;
                return NULL;
        }

        value++;
        OBD_ALLOC(retval, strlen(value) + 1);
        if ( !retval ) {
                CERROR("out of memory!\n");
                return NULL;
        }
        
        memcpy(retval, value, strlen(value)+1);
        CDEBUG(D_SUPER, "Assigned option: %s, value %s\n", opt, retval);
        EXIT;
        return retval;
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
        int connected = 0;
        int devno;
        int err;
        struct ptlrpc_request *request = NULL;

        ENTRY;
        MOD_INC_USE_COUNT; 

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi) { 
                EXIT;
                return NULL;
        }
        memset(sbi, 0, sizeof(*sbi));
        sb->u.generic_sbp = sbi;

        ll_options(data, &device, &version);

        if ( !device ) {
                CERROR("no device\n");
                sb = NULL; 
                goto ERR;
        }

        devno = simple_strtoul(device, NULL, 0);
        if ( devno >= MAX_OBD_DEVICES ) {
                CERROR("device of %s too high\n", device);
                sb = NULL; 
                goto ERR;
        } 

        sbi->ll_conn.oc_dev = &obd_dev[devno];
        err = obd_connect(&sbi->ll_conn);
        if ( err ) {
                CERROR("cannot connect to %s\n", device);
                sb = NULL; 
                goto ERR;
        }
        connected = 1;

        /* the first parameter should become an mds device no */
        err = ptlrpc_connect_client(-1, "mds",
                                    MDS_REQUEST_PORTAL,
                                    MDC_REPLY_PORTAL,
                                    mds_pack_req,
                                    mds_unpack_rep,
                                    &sbi->ll_mds_client);
        
        if (err) {
                CERROR("cannot find MDS\n");  
                sb = NULL;
                goto ERR;
        }
        sbi->ll_super = sb;
        sbi->ll_rootino = 2;

        sb->s_maxbytes = 1LL << 36;
        sb->s_blocksize = PAGE_SIZE;
        sb->s_blocksize_bits = (unsigned char)PAGE_SHIFT;
        sb->s_magic = LL_SUPER_MAGIC;
        sb->s_op = &ll_super_operations;

        /* make root inode */
        err = mdc_getattr(&sbi->ll_mds_client, sbi->ll_rootino, S_IFDIR, 
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, &request);
        if (err) {
                CERROR("mdc_getattr failed for root %d\n", err);
                sb = NULL; 
                goto ERR;
        }

        root = iget4(sb, sbi->ll_rootino, NULL, request->rq_rep.mds);
        if (root) {
                sb->s_root = d_alloc_root(root);
        } else {
                CERROR("lustre_light: bad iget4 for root\n");
                sb = NULL; 
                goto ERR;
        } 

ERR:
        ptlrpc_free_req(request);
        if (device)
                OBD_FREE(device, strlen(device) + 1);
        if (version)
                OBD_FREE(version, strlen(version) + 1);
        if (!sb && connected) 
                obd_disconnect(&sbi->ll_conn);

        if (!sb && root) {
                iput(root);
        }
        if (!sb) 
                MOD_DEC_USE_COUNT;

        EXIT;
        return sb;
} /* ll_read_super */

static void ll_put_super(struct super_block *sb)
{
        struct ll_sb_info *sbi = sb->u.generic_sbp;
        ENTRY;
        obd_disconnect(&sbi->ll_conn);
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
                       oa->o_id, err);
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
        struct ptlrpc_request *request;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        int err;

        ENTRY;

        /* change incore inode */
        ll_attr2inode(inode, attr, do_trunc);

        err = mdc_setattr(&sbi->ll_mds_client, inode, attr, &request);
        if (err)
                CERROR("mdc_setattr fails (%d)\n", err);

        ptlrpc_free_req(request);

        EXIT;
        return err;
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
                return err;
        }
        memcpy(buf, &tmp, sizeof(*buf));
        CDEBUG(D_SUPER, "statfs returns avail %ld\n", tmp.f_bavail);
        EXIT;

        return err; 
}

static void inline ll_to_inode(struct inode *dst, struct mds_rep *rep)
{
        struct ll_inode_info *ii = 
                (struct ll_inode_info *) &dst->u.generic_ip;

        /* core attributes first */
        if ( rep->valid & OBD_MD_FLID )
                dst->i_ino = rep->ino;
        if ( rep->valid & OBD_MD_FLATIME ) 
                dst->i_atime = rep->atime;
        if ( rep->valid & OBD_MD_FLMTIME ) 
                dst->i_mtime = rep->mtime;
        if ( rep->valid & OBD_MD_FLCTIME ) 
                dst->i_ctime = rep->ctime;
        if ( rep->valid & OBD_MD_FLSIZE ) 
                dst->i_size = rep->size;
        if ( rep->valid & OBD_MD_FLMODE ) 
                dst->i_mode = rep->mode;
        if ( rep->valid & OBD_MD_FLUID ) 
                dst->i_uid = rep->uid;
        if ( rep->valid & OBD_MD_FLGID ) 
                dst->i_gid = rep->gid;
        if ( rep->valid & OBD_MD_FLFLAGS ) 
                dst->i_flags = rep->flags;
        if ( rep->valid & OBD_MD_FLNLINK )
                dst->i_nlink = rep->nlink;
        if ( rep->valid & OBD_MD_FLGENER )
                dst->i_generation = rep->generation;

        /* this will become more elaborate for striping etc */ 
        if (rep->valid & OBD_MD_FLOBJID) 
                ii->lli_objid = rep->objid;
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
        struct mds_rep *rep = opaque; 
        
        ENTRY;
        ll_to_inode(inode, rep); 

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
        }

        EXIT;
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

struct file_system_type lustre_light_fs_type = {
        "lustre_light", 0, ll_read_super, NULL
};

static int __init init_lustre_light(void)
{
        printk(KERN_INFO "Lustre Light 0.0.1, braam@clusterfs.com\n");
        ll_file_data_slab = kmem_cache_create("ll_file_data",
                                              sizeof(struct ll_file_data), 0,
                                               SLAB_HWCACHE_ALIGN, NULL, NULL);
        if (ll_file_data_slab == NULL)
                return -ENOMEM;

        return register_filesystem(&lustre_light_fs_type);
}

static void __exit exit_lustre_light(void)
{
        unregister_filesystem(&lustre_light_fs_type);
        kmem_cache_destroy(ll_file_data_slab);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Light Client File System v1.0");
MODULE_LICENSE("GPL");

module_init(init_lustre_light);
module_exit(exit_lustre_light);
