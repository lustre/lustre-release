/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/ext2_obd/ext2_obd.c
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 */

#define EXPORT_SYMTAB

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/stat.h>
#include <linux/locks.h>
#include <linux/ext2_fs.h>
#include <linux/quotaops.h>
#include <asm/unistd.h>

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/obd_class.h>
#include <linux/obd_ext2.h>
#include <linux/obd_filter.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];
long filter_memory;

#define FILTER_ROOTINO 2

#define S_SHIFT 12
static char * obd_type_by_mode[S_IFMT >> S_SHIFT] = {
        [0]                     "",
        [S_IFREG >> S_SHIFT]    "R", 
        [S_IFDIR >> S_SHIFT]    "D",
        [S_IFCHR >> S_SHIFT]    "C",
        [S_IFBLK >> S_SHIFT]    "B", 
        [S_IFIFO >> S_SHIFT]    "F", 
        [S_IFSOCK >> S_SHIFT]   "S",
        [S_IFLNK >> S_SHIFT]    "L"
};


/* write the pathname into the string */
static void filter_id(char *buf, obd_id id, obd_mode mode)
{
        sprintf(buf, "O/%s/%Ld", obd_type_by_mode[(mode & S_IFMT) >> S_SHIFT],
                id);
}

/* setup the object store with correct subdirectories */
static int filter_prep(struct obd_device *obddev)
{
        struct obd_run_ctxt saved;
        struct file *file;
        struct inode *inode;
        loff_t off;
        int rc = 0;
        char rootid[128];
        __u64 lastino = 2;

        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        rc = simple_mkdir(current->fs->pwd, "O", 0700);
        rc = simple_mkdir(current->fs->pwd, "P", 0700);
        rc = simple_mkdir(current->fs->pwd, "D", 0700);
        file = filp_open("O", O_RDONLY, 0);
        if (IS_ERR(file)) {
                CERROR("cannot open O\n");
                GOTO(out, rc = PTR_ERR(file));
        }
        rc = simple_mkdir(file->f_dentry, "R", 0700);  /* regular */
        rc = simple_mkdir(file->f_dentry, "D", 0700);  /* directory */
        rc = simple_mkdir(file->f_dentry, "L", 0700);  /* symbolic links */
        rc = simple_mkdir(file->f_dentry, "C", 0700);  /* character devices */
        rc = simple_mkdir(file->f_dentry, "B", 0700);  /* block devices */
        rc = simple_mkdir(file->f_dentry, "F", 0700);  /* fifo's */
        rc = simple_mkdir(file->f_dentry, "S", 0700);  /* sockets */
        filp_close(file, NULL);

        filter_id(rootid, FILTER_ROOTINO, S_IFDIR);
        file = filp_open(rootid, O_RDWR | O_CREAT, 00755);
        if (IS_ERR(file)) {
                CERROR("OBD filter: cannot make root directory"); 
                GOTO(out, rc = PTR_ERR(file));
        }
        filp_close(file, 0);
        /* FIXME: this is the same as the _file_ we just created? */
        rc = simple_mkdir(current->fs->pwd, rootid, 0755);

        file = filp_open("D/status", O_RDWR | O_CREAT, 0700);
        if ( !file || IS_ERR(file) ) {
                CERROR("OBD filter: cannot open/create status file\n");
                GOTO(out, rc = PTR_ERR(file));
        }

        /* steal operations */
        inode = file->f_dentry->d_inode;
        obddev->u.filter.fo_fop = file->f_op;
        obddev->u.filter.fo_iop = inode->i_op;
        obddev->u.filter.fo_aops = inode->i_mapping->a_ops;

        off = 0;
        if (inode->i_size == 0) {
                ssize_t retval = file->f_op->write(file, (char *)&lastino,
                                                   sizeof(lastino), &off);
                if (retval != sizeof(lastino)) {
                        CERROR("OBD filter: error writing lastino\n");
                        GOTO(out, rc = -EIO);
                }
        } else {
                ssize_t retval = file->f_op->read(file, (char *)&lastino,
                                                  sizeof(lastino), &off);
                if (retval != sizeof(lastino)) {
                        CERROR("OBD filter: error reading lastino\n");
                        GOTO(out, rc = -EIO);
                }
        }
        obddev->u.filter.fo_lastino = lastino;
        filp_close(file, 0); 

        rc = 0;
 out:
        pop_ctxt(&saved);

        return(rc);
}

/* cleanup the filter: write last used object id to status file */
static void filter_post(struct obd_device *obddev)
{
        struct obd_run_ctxt saved;
        long rc;
        struct file *file;
        loff_t off = 0; 

        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        file = filp_open("D/status", O_RDWR | O_CREAT, 0700);
        if ( !file || IS_ERR(file)) { 
                CERROR("OBD filter: cannot create status file\n");
                goto out;
        }
        rc = file->f_op->write(file, (char *)&obddev->u.filter.fo_lastino, 
                       sizeof(obddev->u.filter.fo_lastino), &off);
        if (rc != sizeof(obddev->u.filter.fo_lastino) ) { 
                CERROR("OBD filter: error writing lastino\n");
        }

        rc = filp_close(file, NULL); 
        if (rc) { 
                CERROR("OBD filter: cannot close status file\n");
        }
 out:
        pop_ctxt(&saved);
}


static __u64 filter_next_id(struct obd_device *obddev) 
{
        __u64 id;
        spin_lock(&obddev->u.filter.fo_lock);
        obddev->u.filter.fo_lastino++;
        id =    obddev->u.filter.fo_lastino;
        spin_unlock(&obddev->u.filter.fo_lock);
        return id;
}

/* how to get files, dentries, inodes from object id's */
static struct file *filter_obj_open(struct obd_device *obddev, 
                                   __u64 id, __u32 type)
{
        struct obd_run_ctxt saved;
        char name[24];
        struct super_block *sb;
        struct file *file;
        
        sb = obddev->u.filter.fo_sb;
        if (!sb || !sb->s_dev) {
                CDEBUG(D_SUPER, "fatal: device not initialized.\n");
                EXIT;
                return NULL;
        }

        if ( !id ) {
                CDEBUG(D_INODE, "fatal: invalid obdo %Lu\n", id);
                EXIT;
                return NULL;
        }

        if ( ! (type & S_IFMT) ) { 
                CERROR("OBD filter_obj_open, no type (%Ld), mode %o!\n", 
                       id, type);
        }

        filter_id(name, id, type); 
        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        file = filp_open(name, O_RDONLY | O_LARGEFILE, 0);
        pop_ctxt(&saved);

        CDEBUG(D_INODE, "opening obdo %s\n", name);

        return file;
}

static struct file *filter_parent(obd_id id, obd_mode mode)
{
        char path[64];
        struct file *file;

        sprintf(path, "O/%s", obd_type_by_mode[(mode & S_IFMT) >> S_SHIFT]);

        file = filp_open(path, O_RDONLY, 0); 
        return file;
}


static struct inode *filter_inode_from_obj(struct obd_device *obddev, 
                                     __u64 id, __u32 type)
{
        struct file *file;
        struct inode *inode; 

        file = filter_obj_open(obddev, id, type);
        if ( !file ) { 
                CERROR("filter_inode_from_obdo failed\n"); 
                return NULL;
        }

        inode = iget(file->f_dentry->d_inode->i_sb, 
                     file->f_dentry->d_inode->i_ino); 
        filp_close(file, 0);
        return inode;
}

/* obd methods */
static int filter_connect(struct obd_conn *conn)
{
        int rc;

        MOD_INC_USE_COUNT;
        rc = gen_connect(conn);

        if (rc)
                MOD_DEC_USE_COUNT;

        return rc;
}

static int filter_disconnect(struct obd_conn *conn)
{
        int rc;

        rc = gen_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        /* XXX cleanup preallocated inodes */
        return rc;
}

/* mount the file system (secretly) */
static int filter_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct vfsmount *mnt;
        int err = 0;
        ENTRY;

        MOD_INC_USE_COUNT;
        mnt = do_kern_mount(data->ioc_inlbuf2, 0, data->ioc_inlbuf1, NULL);
        err = PTR_ERR(mnt);
        if (IS_ERR(mnt))
                GOTO(err_dec, err);

        /* XXX is this even possible if do_kern_mount succeeded? */
        obddev->u.filter.fo_sb = mnt->mnt_root->d_inode->i_sb;
        if (!obddev->u.filter.fo_sb)
                GOTO(err_put, err = -ENODEV);

        obddev->u.filter.fo_vfsmnt = mnt;
        obddev->u.filter.fo_fstype = strdup(data->ioc_inlbuf2);

        obddev->u.filter.fo_ctxt.pwdmnt = mnt;
        obddev->u.filter.fo_ctxt.pwd = mnt->mnt_root;
        obddev->u.filter.fo_ctxt.fs = KERNEL_DS;

        err = filter_prep(obddev);
        if (err)
                GOTO(err_kfree, err);
        spin_lock_init(&obddev->u.filter.fo_lock);

        RETURN(0);

err_kfree:
        kfree(obddev->u.filter.fo_fstype);
err_put:
        unlock_kernel();
        mntput(obddev->u.filter.fo_vfsmnt);
        obddev->u.filter.fo_sb = 0;
        lock_kernel();

err_dec:
        MOD_DEC_USE_COUNT;
        return err;
}


static int filter_cleanup(struct obd_device * obddev)
{
        struct super_block *sb;

        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) )
                RETURN(0);

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        sb = obddev->u.filter.fo_sb;
        if (!obddev->u.filter.fo_sb)
                RETURN(0);

        filter_post(obddev);

        unlock_kernel();
        mntput(obddev->u.filter.fo_vfsmnt); 
        obddev->u.filter.fo_sb = 0;
        kfree(obddev->u.filter.fo_fstype);

        lock_kernel();

        MOD_DEC_USE_COUNT;
        RETURN(0);
}


static inline void filter_from_inode(struct obdo *oa, struct inode *inode)
{
        int type = oa->o_mode & S_IFMT;
        ENTRY;

        CDEBUG(D_INFO, "src inode %ld, dst obdo %ld valid 0x%08x\n",
               inode->i_ino, (long)oa->o_id, oa->o_valid);
        obdo_from_inode(oa, inode);
        oa->o_mode &= ~S_IFMT;
        oa->o_mode |= type;

        if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
                obd_rdev rdev = kdev_t_to_nr(inode->i_rdev);
                CDEBUG(D_INODE, "copying device %x from inode to obdo\n",
                       rdev);
                *((obd_rdev *)oa->o_inline) = rdev;
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }

#if 0
        else if (filter_has_inline(inode)) {
                CDEBUG(D_INFO, "copying inline from inode to obdo\n");
                memcpy(oa->o_inline, inode->u.ext2_i.i_data,
                       MIN(sizeof(inode->u.ext2_i.i_data),OBD_INLINESZ));
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }

        if (filter_has_obdmd(inode)) {
                /* XXX this will change when we don't store the obdmd in data */
                CDEBUG(D_INFO, "copying obdmd from inode to obdo\n");
                memcpy(oa->o_obdmd, inode->u.ext2_i.i_data,
                       MIN(sizeof(inode->u.ext2_i.i_data),OBD_INLINESZ));
                oa->o_obdflags |= OBD_FL_OBDMDEXISTS;
                oa->o_valid |= OBD_MD_FLOBDMD;
        }
#endif
        EXIT;
}

static int filter_getattr(struct obd_conn *conn, struct obdo *oa)
{
        struct inode *inode;

        ENTRY;
        if ( !gen_client(conn) ) {
                CDEBUG(D_IOCTL, "fatal: invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        if ( !(inode = filter_inode_from_obj(conn->oc_dev, 
                                              oa->o_id, oa->o_mode)) ) { 
                EXIT;
                return -ENOENT;
        }

        oa->o_valid &= ~OBD_MD_FLID;
        filter_from_inode(oa, inode);
        
        iput(inode);
        EXIT;
        return 0;
} 

static int filter_setattr(struct obd_conn *conn, struct obdo *oa)
{
        struct inode *inode;
        struct iattr iattr;
        int rc;
        struct dentry de;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                return -EINVAL;
        }

        inode = filter_inode_from_obj(conn->oc_dev, oa->o_id, oa->o_mode); 
        if ( !inode ) { 
                EXIT;
                return -ENOENT;
        }

        iattr_from_obdo(&iattr, oa);
        iattr.ia_mode &= ~S_IFMT;
        iattr.ia_mode |= S_IFREG;
        de.d_inode = inode;
        if ( inode->i_op->setattr ) {
                rc = inode->i_op->setattr(&de, &iattr);
        } else { 
                rc = inode_setattr(inode, &iattr);
        }

        iput(inode);
        EXIT;
        return rc;
}

static int filter_open(struct obd_conn *conn, struct obdo *oa)
{
        struct inode *inode;
        /* ENTRY; */

        if (!gen_client(conn))
                RETURN(-EINVAL);

        if ( !(inode = filter_inode_from_obj(conn->oc_dev,
                                             oa->o_id, oa->o_mode)) )
                RETURN(-ENOENT);

        return 0;
} /* filter_open */

static int filter_close(struct obd_conn *conn, struct obdo *oa)
{
        struct inode *inode;
        /* ENTRY; */

        if (!gen_client(conn))
                RETURN(-EINVAL);

        if ( !(inode = filter_inode_from_obj(conn->oc_dev,
                                             oa->o_id, oa->o_mode)) )
                RETURN(-ENOENT);

        iput(inode);  /* for the close */
        iput(inode);  /* for this call */
        return 0;
} /* filter_close */

static int filter_create (struct obd_conn* conn, struct obdo *oa)
{
        char name[64];
        struct obd_run_ctxt saved;
        struct file *file;
        int mode;
        struct obd_device *obddev = conn->oc_dev;
        struct iattr;
        ENTRY;

        if (!gen_client(conn)) {
                CERROR("invalid client %u\n", conn->oc_id);
                return -EINVAL;
        }

        oa->o_id = filter_next_id(conn->oc_dev);
        if ( !(oa->o_mode && S_IFMT) ) { 
                CERROR("filter obd: no type!\n");
                return -ENOENT;
        }

        filter_id(name, oa->o_id, oa->o_mode);
        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        mode = oa->o_mode;
        mode &= ~S_IFMT;
        mode |= S_IFREG; 
        file = filp_open(name, O_RDONLY | O_CREAT, mode);
        pop_ctxt(&saved);
        if (IS_ERR(file)) { 
                CERROR("Error mknod obj %s, err %ld\n", name, PTR_ERR(file));
                return -ENOENT;
        }
        filp_close(file, 0);
        
        /* Set flags for fields we have set in ext2_new_inode */
        oa->o_valid |= OBD_MD_FLID | OBD_MD_FLBLKSZ | OBD_MD_FLBLOCKS |
                 OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME |
                 OBD_MD_FLUID | OBD_MD_FLGID;
        return 0;
}

static int filter_destroy(struct obd_conn *conn, struct obdo *oa)
{
        struct obd_device * obddev;
        struct obd_client * cli;
        struct inode * inode;
        struct file *dir;
        struct file *object;
        int rc;
        struct obd_run_ctxt saved;

        if (!(cli = gen_client(conn))) {
                CERROR("invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        obddev = conn->oc_dev;
        object = filter_obj_open(obddev, oa->o_id, oa->o_mode);
        if (!object || IS_ERR(object)) { 
                EXIT;
                return -ENOENT;
        }
        
        inode = object->f_dentry->d_inode;
        inode->i_nlink = 1;
        inode->i_mode = 010000;

        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        dir = filter_parent(oa->o_id, oa->o_mode);
        if (IS_ERR(dir)) {
                rc = PTR_ERR(dir);
                EXIT;
                goto out;
        }
        dget(dir->f_dentry); 
        dget(object->f_dentry);
        rc = vfs_unlink(dir->f_dentry->d_inode, object->f_dentry);

        filp_close(dir, 0);
        filp_close(object, 0);
out:
        pop_ctxt(&saved);
        EXIT;
        return rc;
}

static int filter_truncate(struct obd_conn *conn, struct obdo *oa, obd_size count,
                         obd_off offset)
{
        int error;

        error = filter_setattr(conn, oa);
        oa->o_valid = OBD_MD_FLBLOCKS | OBD_MD_FLCTIME | OBD_MD_FLMTIME;

        EXIT;
        return error;
}

/* buffer must lie in user memory here */
static int filter_read(struct obd_conn *conn, struct obdo *oa, char *buf,
                        obd_size *count, obd_off offset)
{
        struct file * file;
        unsigned long retval;
        int err;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        file = filter_obj_open(conn->oc_dev, oa->o_id, oa->o_mode); 
        if (!file || IS_ERR(file)) { 
                EXIT;
                return -PTR_ERR(file);
        }

        /* count doubles as retval */
        retval = file->f_op->read(file, buf, *count, &offset);
        filp_close(file, 0);

        if ( retval >= 0 ) {
                err = 0;
                *count = retval;
        } else {
                err = retval;
                *count = 0;
        }

        return err;
}


/* buffer must lie in user memory here */
static int filter_write(struct obd_conn *conn, struct obdo *oa, char *buf, 
                         obd_size *count, obd_off offset)
{
        int err;
        struct file * file;
        unsigned long retval;

        ENTRY;
        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        file = filter_obj_open(conn->oc_dev, oa->o_id, oa->o_mode); 
        if (!file || IS_ERR(file)) { 
                EXIT;
                return -PTR_ERR(file);
        }

        /* count doubles as retval */
        retval = file->f_op->write(file, buf, *count, &offset);
        filp_close(file, 0);

        if ( retval >= 0 ) {
                err = 0;
                *count = retval;
                EXIT;
        } else {
                err = retval;
                *count = 0;
                EXIT;
        }

        return err;
} /* filter_write */

static int filter_pgcache_brw(int rw, struct obd_conn *conn, 
                               obd_count num_oa,
                               struct obdo **oa, 
                               obd_count *oa_bufs, 
                               struct page **pages,
                               obd_size *count, 
                               obd_off *offset, 
                               obd_flag *flags)
{
        struct super_block      *sb;
        mm_segment_t oldfs;
        int                      onum;          /* index to oas */
        int                      pnum;          /* index to pages (bufs) */
        unsigned long            retval;
        int                      error;
        struct file *file;

        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        sb = conn->oc_dev->u.filter.fo_sb;
        oldfs = get_fs();
        set_fs(KERNEL_DS); 

        pnum = 0; /* pnum indexes buf 0..num_pages */
        for (onum = 0; onum < num_oa; onum++) {
                int              pg;

                file = filter_obj_open(conn->oc_dev, oa[onum]->o_id, 
                                       oa[onum]->o_mode); 
                if (!file || IS_ERR(file)) { 
                        EXIT;
                        error = -ENOENT;
                        goto ERROR;
                }

                /* count doubles as retval */
                for (pg = 0; pg < oa_bufs[onum]; pg++) {
                        CDEBUG(D_INODE, "OP %d obdo no/pno: (%d,%d) (%ld,%ld) off count (%Ld,%Ld)\n", 
                               rw, onum, pnum, file->f_dentry->d_inode->i_ino,
                               (unsigned long)offset[pnum] >> PAGE_CACHE_SHIFT,
                               offset[pnum], count[pnum]);
                        if (rw == WRITE) { 
                                loff_t off; 
                                char *buffer;
                                off = offset[pnum]; 
                                buffer = kmap(pages[pnum]); 
                                retval = file->f_op->write(file, buffer, count[pnum], &off);
                                kunmap(pages[pnum]);
                                CDEBUG(D_INODE, "retval %ld\n", retval); 
                        } else { 
                                loff_t off = offset[pnum]; 
                                char *buffer = kmap(pages[pnum]);

                                if (off >= file->f_dentry->d_inode->i_size) {
                                        memset(buffer, 0, count[pnum]);
                                        retval = count[pnum];
                                } else {
                                        retval = file->f_op->read(file, buffer, count[pnum], &off);
                                } 
                                kunmap(pages[pnum]);

                                if ( retval != count[pnum] ) {
                                        filp_close(file, 0);
                                        retval = -EIO;
                                        EXIT;
                                        goto ERROR;
                                }
                                CDEBUG(D_INODE, "retval %ld\n", retval); 
                        }
                        pnum++;
                }
                /* sizes and blocks are set by generic_file_write */
                /* ctimes/mtimes will follow with a setattr call */ 
                filp_close(file, 0);
        }
        
        EXIT;
 ERROR:
        set_fs(oldfs);
        error = (retval >= 0) ? 0 : retval;
        return error;
}


struct inode *ioobj_to_inode(struct obd_conn *conn, struct obd_ioobj *o)
{
        struct inode *inode = NULL;
        struct super_block *sb = conn->oc_dev->u.ext2.e2_sb;

        if (!sb || !sb->s_dev) {
                CDEBUG(D_SUPER, "fatal: device not initialized.\n");
                EXIT;
                return NULL;
        }

        if ( !o->ioo_id ) {
                CDEBUG(D_INODE, "fatal: invalid obdo %lu\n", (long)o->ioo_id);
                EXIT;
                return NULL;
        }

        inode = filter_inode_from_obj(conn->oc_dev, o->ioo_id, S_IFREG);
        if (!inode || inode->i_nlink == 0 || is_bad_inode(inode)) {
                CERROR("from obdo - fatal: invalid inode %ld (%s).\n",
                       (long)o->ioo_id, inode ? inode->i_nlink ? "bad inode" :
                       "no links" : "NULL");
                if (inode)
                        iput(inode);
                EXIT;
                return NULL;
        }

        return inode;
}

static int filter_preprw(int cmd, struct obd_conn *conn,
                         int objcount, struct obd_ioobj *obj,
                         int niocount, struct niobuf *nb,
                         struct niobuf *res)
{
        struct obd_ioobj *o = obj;
        struct niobuf *b = nb;
        struct niobuf *r = res;
        int i;
        ENTRY;

        memset(res, 0, sizeof(*res) * niocount);

        for (i = 0; i < objcount; i++, o++) {
                int j;
                for (j = 0; j < o->ioo_bufcnt; j++, b++, r++) {
                        struct inode *inode = ioobj_to_inode(conn, o);
                        struct page *page;

                        /* FIXME: we need to iput all inodes on error */
                        if (!inode)
                                RETURN(-EINVAL);

                        page = lustre_get_page(inode, b->offset >> PAGE_SHIFT);
                        if (IS_ERR(page))
                                RETURN(PTR_ERR(page));

                        if (cmd == OBD_BRW_WRITE) {
                                int rc = lustre_prepare_page(0, PAGE_SIZE,page);
                                if (rc)
                                        CERROR("i %d j %d objcount %d bufcnt %d , rc %d, offset %Ld\n", i, j, objcount, o->ioo_bufcnt, rc, b->offset);
                        }

                        r->addr = (__u64)(unsigned long)page_address(page);
                        r->offset = b->offset;
                        r->page = page;
                        r->len = PAGE_SIZE;
                }
        }
        return 0;
}

static int filter_commitrw(int cmd, struct obd_conn *conn,
                           int objcount, struct obd_ioobj *obj,
                           int niocount, struct niobuf *res)
{
        struct obd_ioobj *o = obj;
        struct niobuf *r = res;
        int i;
        ENTRY;

        for (i = 0; i < objcount; i++, obj++) {
                int j;
                for (j = 0 ; j < o->ioo_bufcnt ; j++, r++) {
                        struct page *page = r->page;

                        if (!r->page)
                                LBUG();

                        if (cmd == OBD_BRW_WRITE) {
                                int rc = lustre_commit_page(page, 0, PAGE_SIZE);

                                /* FIXME: still need to iput the other inodes */
                                if (rc)
                                        RETURN(rc);
                        } else
                                lustre_put_page(page);

                        iput(page->mapping->host);
                }
        }
        RETURN(0);
}

static int filter_statfs (struct obd_conn *conn, struct statfs * statfs)
{
        struct super_block *sb;
        int err;

        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        sb = conn->oc_dev->u.filter.fo_sb;

        err = sb->s_op->statfs(sb, statfs);
        EXIT;
        return err;
} /* filter_statfs */


static int  filter_get_info(struct obd_conn *conn, obd_count keylen,
                             void *key, obd_count *vallen, void **val)
{
        struct obd_device *obddev;
        struct obd_client * cli;
        ENTRY;

        if (!(cli = gen_client(conn))) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                return -EINVAL;
        }

        obddev = conn->oc_dev;
        
        if ( keylen == strlen("blocksize") &&
             memcmp(key, "blocksize", keylen) == 0 ) {
                *vallen = sizeof(int);
                *val = (void *)obddev->u.filter.fo_sb->s_blocksize;
                EXIT;
                return 0;
        }

        if ( keylen == strlen("blocksize_bits") &&
             memcmp(key, "blocksize_bits", keylen) == 0 ){
                *vallen = sizeof(int);
                *val = (void *)(int)obddev->u.filter.fo_sb->s_blocksize_bits;
                EXIT;
                return 0;
        }

        if ( keylen == strlen("root_ino") &&
             memcmp(key, "root_ino", keylen) == 0 ){
                *vallen = sizeof(int);
                *val = (void *)(int) FILTER_ROOTINO;
                EXIT;
                return 0;
        }
        
        CDEBUG(D_IOCTL, "invalid key\n");
        return -EINVAL;
}


struct obd_ops filter_obd_ops = {
        o_iocontrol:   NULL,
        o_get_info:    filter_get_info,
        o_setup:       filter_setup,
        o_cleanup:     filter_cleanup,
        o_connect:     filter_connect,
        o_disconnect:  filter_disconnect,
        o_statfs:      filter_statfs,
        o_getattr:     filter_getattr,
        o_create:      filter_create,
        o_setattr:     filter_setattr,
        o_destroy:     filter_destroy,
        o_open:        filter_open,
        o_close:       filter_close,
        o_read:        filter_read,
        o_write:       filter_write,
        o_brw:         filter_pgcache_brw,
        o_punch:       filter_truncate,
        o_preprw:      filter_preprw,
        o_commitrw:    filter_commitrw
#if 0
        o_preallocate: filter_preallocate_inodes,
        o_migrate:     filter_migrate,
        o_copy:        gen_copy_data,
        o_iterate:     filter_iterate
#endif
};


static int __init obdfilter_init(void)
{
        printk(KERN_INFO "Filtering OBD driver  v0.001, braam@clusterfs.com\n");
        return obd_register_type(&filter_obd_ops, OBD_FILTER_DEVICENAME);
}

static void __exit obdfilter_exit(void)
{
        obd_unregister_type(OBD_FILTER_DEVICENAME);
}

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Filtering OBD driver v1.0");
MODULE_LICENSE("GPL"); 

module_init(obdfilter_init);
module_exit(obdfilter_exit);
