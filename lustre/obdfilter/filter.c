/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/filter/filter.c
 *
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/module.h>
#include <linux/obd_filter.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];
long filter_memory;

#define FILTER_ROOTINO 2

#define S_SHIFT 12
static char *obd_type_by_mode[S_IFMT >> S_SHIFT] = {
        [0]                     NULL,
        [S_IFREG >> S_SHIFT]    "R",
        [S_IFDIR >> S_SHIFT]    "D",
        [S_IFCHR >> S_SHIFT]    "C",
        [S_IFBLK >> S_SHIFT]    "B",
        [S_IFIFO >> S_SHIFT]    "F",
        [S_IFSOCK >> S_SHIFT]   "S",
        [S_IFLNK >> S_SHIFT]    "L"
};

static inline const char *obd_mode_to_type(int mode)
{
        return obd_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

/* write the pathname into the string */
static int filter_id(char *buf, obd_id id, obd_mode mode)
{
        return sprintf(buf, "O/%s/%Ld", obd_mode_to_type(mode),
                       (unsigned long long)id);
}

/* setup the object store with correct subdirectories */
static int filter_prep(struct obd_device *obddev)
{
        struct obd_run_ctxt saved;
        struct filter_obd *filter = &obddev->u.filter;
        struct dentry *dentry;
        struct file *file;
        struct inode *inode;
        loff_t off;
        int rc = 0;
        char rootid[128];
        __u64 lastino = 2;
        int mode = 0;

        push_ctxt(&saved, &filter->fo_ctxt);
        dentry = simple_mkdir(current->fs->pwd, "O", 0700);
        CDEBUG(D_INODE, "got/created O: %p\n", dentry);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot open/create O: rc = %d\n", rc);
                GOTO(out, rc);
        }
        filter->fo_dentry_O = dentry;
        dentry = simple_mkdir(current->fs->pwd, "P", 0700);
        CDEBUG(D_INODE, "got/created P: %p\n", dentry);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot open/create P: rc = %d\n", rc);
                GOTO(out_O, rc);
        }
        CDEBUG(D_INODE, "putting P: %p, count = %d\n", dentry,dentry->d_count.counter-1);
        l_dput(dentry);
        dentry = simple_mkdir(current->fs->pwd, "D", 0700);
        CDEBUG(D_INODE, "got/created D: %p\n", dentry);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot open/create D: rc = %d\n", rc);
                GOTO(out_O, rc);
        }
        CDEBUG(D_INODE, "putting D: %p, count = %d\n", dentry,dentry->d_count.counter-1);
        l_dput(dentry);

        /*
         * Create directories and/or get dentries for each object type.
         * This saves us from having to do multiple lookups for each one.
         */
        for (mode = 0; mode < (S_IFMT >> S_SHIFT); mode++) {
                char *type = obd_type_by_mode[mode];

                if (!type) {
                        filter->fo_dentry_O_mode[mode] = NULL;
                        continue;
                }
                dentry = simple_mkdir(filter->fo_dentry_O, type, 0700);
                CDEBUG(D_INODE, "got/created O/%s: %p\n", type, dentry);
                if (IS_ERR(dentry)) {
                        rc = PTR_ERR(dentry);
                        CERROR("cannot create O/%s: rc = %d\n", type, rc);
                        GOTO(out_O_mode, rc);
                }
                filter->fo_dentry_O_mode[mode] = dentry;
        }

        filter_id(rootid, FILTER_ROOTINO, S_IFDIR);
        file = filp_open(rootid, O_RDWR | O_CREAT, 0755);
        if (IS_ERR(file)) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create root %s: rc = %d\n",
                       rootid, rc);
                GOTO(out_O_mode, rc);
        }
        filp_close(file, 0);

        file = filp_open("D/status", O_RDWR | O_CREAT, 0700);
        if ( !file || IS_ERR(file) ) {
                rc = PTR_ERR(file);
                CERROR("OBD filter: cannot open/create status %s: rc = %d\n",
                       "D/status", rc);
                GOTO(out_O_mode, rc);
        }

        /* steal operations */
        inode = file->f_dentry->d_inode;
        filter->fo_fop = file->f_op;
        filter->fo_iop = inode->i_op;
        filter->fo_aops = inode->i_mapping->a_ops;

        off = 0;
        if (inode->i_size == 0) {
                ssize_t retval = file->f_op->write(file, (char *)&lastino,
                                                   sizeof(lastino), &off);
                if (retval != sizeof(lastino)) {
                        CDEBUG(D_INODE, "OBD filter: error writing lastino\n");
                        filp_close(file, 0);
                        GOTO(out_O_mode, rc = -EIO);
                }
        } else {
                ssize_t retval = file->f_op->read(file, (char *)&lastino,
                                                  sizeof(lastino), &off);
                if (retval != sizeof(lastino)) {
                        CDEBUG(D_INODE, "OBD filter: error reading lastino\n");
                        filp_close(file, 0);
                        GOTO(out_O_mode, rc = -EIO);
                }
        }
        filter->fo_lastino = lastino;
        filp_close(file, 0);

        rc = 0;
 out:
        pop_ctxt(&saved);

        return(rc);

out_O_mode:
        while (--mode >= 0) {
                if (filter->fo_dentry_O_mode[mode]) {
                        CDEBUG(D_INODE, "putting O/%s: %p, count = %d\n",
                               obd_type_by_mode[mode],
                               filter->fo_dentry_O_mode[mode],
                               filter->fo_dentry_O_mode[mode]->d_count.counter-1);
                        l_dput(filter->fo_dentry_O_mode[mode]);
                        filter->fo_dentry_O_mode[mode] = NULL;
                }
        }
out_O:
        CDEBUG(D_INODE, "putting O: %p, count = %d\n", filter->fo_dentry_O,
               filter->fo_dentry_O->d_count.counter);
        l_dput(filter->fo_dentry_O);
        filter->fo_dentry_O = NULL;
        goto out;
}

/* cleanup the filter: write last used object id to status file */
static void filter_post(struct obd_device *obddev)
{
        struct obd_run_ctxt saved;
        struct filter_obd *filter = &obddev->u.filter;
        long rc;
        struct file *file;
        loff_t off = 0;
        int mode;

        push_ctxt(&saved, &filter->fo_ctxt);
        file = filp_open("D/status", O_RDWR | O_CREAT, 0700);
        if (IS_ERR(file)) {
                CERROR("OBD filter: cannot create status file\n");
                goto out;
        }
        rc = file->f_op->write(file, (char *)&filter->fo_lastino,
                       sizeof(filter->fo_lastino), &off);
        if (rc != sizeof(filter->fo_lastino))
                CERROR("OBD filter: error writing lastino: rc = %ld\n", rc);

        rc = filp_close(file, NULL);
        if (rc)
                CERROR("OBD filter: cannot close status file: rc = %ld\n", rc);

        for (mode = 0; mode < (S_IFMT >> S_SHIFT); mode++) {
                if (filter->fo_dentry_O_mode[mode]) {
                        CDEBUG(D_INODE, "putting O/%s: %p, count = %d\n",
                               obd_type_by_mode[mode],
                               filter->fo_dentry_O_mode[mode],
                               filter->fo_dentry_O_mode[mode]->d_count.counter-1);
                        l_dput(filter->fo_dentry_O_mode[mode]);
                        filter->fo_dentry_O_mode[mode] = NULL;
                }
        }
        CDEBUG(D_INODE, "putting O: %p, count = %d\n", filter->fo_dentry_O,
               filter->fo_dentry_O->d_count.counter);
        l_dput(filter->fo_dentry_O);
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
/* parent i_sem is already held if needed for exclusivity */
static struct dentry *filter_fid2dentry(struct obd_device *obddev,
                                        struct dentry *dparent,
                                        __u64 id, __u32 type)
{
        struct super_block *sb = obddev->u.filter.fo_sb;
        struct dentry *dchild;
        char name[32];
        int len;
        ENTRY;

        if (!sb || !sb->s_dev) {
                CERROR("fatal: device not initialized.\n");
                RETURN(ERR_PTR(-ENXIO));
        }

        if (id == 0) {
                CERROR("fatal: invalid object #0\n");
                RETURN(ERR_PTR(-ESTALE));
        }

        if (!(type & S_IFMT)) {
                CERROR("OBD %s, object %Lu has bad type: %o\n", __FUNCTION__,
                       (unsigned long long)id, type);
                RETURN(ERR_PTR(-EINVAL));
        }

        len = sprintf(name, "%Ld", id);
        CDEBUG(D_INODE, "opening object O/%s/%s\n", obd_mode_to_type(type),
               name);
        dchild = lookup_one_len(name, dparent, len);
        CDEBUG(D_INODE, "got child obj O/%s/%s: %p, count = %d\n",
               obd_mode_to_type(type), name, dchild, dchild->d_count.counter);

        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                RETURN(dchild);
        }

        RETURN(dchild);
}

static struct file *filter_obj_open(struct obd_device *obddev,
                                    __u64 id, __u32 type)
{
        struct super_block *sb = obddev->u.filter.fo_sb;
        struct obd_run_ctxt saved;
        char name[24];
        struct file *file;
        ENTRY;

        if (!sb || !sb->s_dev) {
                CERROR("fatal: device not initialized.\n");
                RETURN(ERR_PTR(-ENXIO));
        }

        if (!id) {
                CERROR("fatal: invalid obdo %Lu\n", (unsigned long long)id);
                RETURN(ERR_PTR(-ESTALE));
        }

        if (!(type & S_IFMT)) {
                CERROR("OBD %s, no type (%Ld), mode %o!\n", __FUNCTION__,
                       (unsigned long long)id, type);
                RETURN(ERR_PTR(-EINVAL));
        }

        filter_id(name, id, type);
        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        file = filp_open(name, O_RDONLY | O_LARGEFILE, 0 /* type? */);
        pop_ctxt(&saved);

        CDEBUG(D_INODE, "opening obdo %s: rc = %p\n", name, file);

        if (IS_ERR(file))
                file = NULL;
        RETURN(file);
}

static struct dentry *filter_parent(struct obd_device *obddev, obd_mode mode)
{
        struct filter_obd *filter = &obddev->u.filter;

        return filter->fo_dentry_O_mode[(mode & S_IFMT) >> S_SHIFT];
}


static struct inode *filter_inode_from_obj(struct obd_device *obddev,
                                           __u64 id, __u32 type)
{
        struct dentry *dentry;
        struct inode *inode;

        dentry = filter_fid2dentry(obddev, filter_parent(obddev, type),
                                   id, type);
        if (IS_ERR(dentry)) {
                CERROR("%s: lookup failed: rc = %ld\n", __FUNCTION__,
                       PTR_ERR(dentry));
                RETURN(NULL);
        }

        lock_kernel();
        inode = iget(dentry->d_inode->i_sb, dentry->d_inode->i_ino);
        unlock_kernel();
        CDEBUG(D_INODE, "put child %p, count = %d\n", dentry, dentry->d_count.counter-1);
        l_dput(dentry);
        CDEBUG(D_INODE, "got inode %p (%ld), count = %d\n", inode, inode->i_ino,
               inode->i_count.counter);
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
        struct filter_obd *filter;
        struct vfsmount *mnt;
        int err = 0;
        ENTRY;

        if (!data->ioc_inlbuf1 || !data->ioc_inlbuf2)
                RETURN(-EINVAL);

        MOD_INC_USE_COUNT;
        mnt = do_kern_mount(data->ioc_inlbuf2, 0, data->ioc_inlbuf1, NULL);
        err = PTR_ERR(mnt);
        if (IS_ERR(mnt))
                GOTO(err_dec, err);

        filter = &obddev->u.filter;;
        filter->fo_sb = mnt->mnt_root->d_inode->i_sb;
        /* XXX is this even possible if do_kern_mount succeeded? */
        if (!filter->fo_sb)
                GOTO(err_put, err = -ENODEV);

        filter->fo_vfsmnt = mnt;
        filter->fo_fstype = strdup(data->ioc_inlbuf2);

        filter->fo_ctxt.pwdmnt = mnt;
        filter->fo_ctxt.pwd = mnt->mnt_root;
        filter->fo_ctxt.fs = KERNEL_DS;

        err = filter_prep(obddev);
        if (err)
                GOTO(err_kfree, err);
        spin_lock_init(&filter->fo_lock);

        RETURN(0);

err_kfree:
        kfree(filter->fo_fstype);
err_put:
        unlock_kernel();
        mntput(filter->fo_vfsmnt);
        filter->fo_sb = 0;
        lock_kernel();

err_dec:
        MOD_DEC_USE_COUNT;
        return err;
}


static int filter_cleanup(struct obd_device * obddev)
{
        struct super_block *sb;
        ENTRY;

        if (!(obddev->obd_flags & OBD_SET_UP))
                RETURN(0);

        if (!list_empty(&obddev->obd_gen_clients)) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        sb = obddev->u.filter.fo_sb;
        if (!obddev->u.filter.fo_sb)
                RETURN(0);

        filter_post(obddev);

        shrink_dcache_parent(sb->s_root);
        unlock_kernel();
        CDEBUG(D_INODE, "putting sb->s_root: count = %d\n",
               sb->s_root->d_count.counter-1);
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

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "fatal: invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        inode = filter_inode_from_obj(conn->oc_dev, oa->o_id, oa->o_mode);
        if (!inode)
                RETURN(-ENOENT);

        oa->o_valid &= ~OBD_MD_FLID;
        filter_from_inode(oa, inode);

        CDEBUG(D_INODE, "put inode %p (%ld), count = %d, nlink = %d\n", inode,
               inode->i_ino, inode->i_count.counter - 1, inode->i_nlink);
        iput(inode);
        RETURN(0);
}

static int filter_setattr(struct obd_conn *conn, struct obdo *oa)
{
        struct obd_run_ctxt saved;
        struct inode *inode;
        struct iattr iattr;
        int rc;
        struct dentry de;
        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        inode = filter_inode_from_obj(conn->oc_dev, oa->o_id, oa->o_mode);
        if (!inode)
                RETURN(-ENOENT);

        iattr_from_obdo(&iattr, oa);
        iattr.ia_mode &= ~S_IFMT;
        iattr.ia_mode |= S_IFREG;
        de.d_inode = inode;
        lock_kernel();
        if (iattr.ia_mode & ATTR_SIZE)
                down(&inode->i_sem);
        push_ctxt(&saved, &conn->oc_dev->u.filter.fo_ctxt);
        if (inode->i_op->setattr)
                rc = inode->i_op->setattr(&de, &iattr);
        else
                rc = inode_setattr(inode, &iattr);
        pop_ctxt(&saved);
        if (iattr.ia_mode & ATTR_SIZE)
                up(&inode->i_sem);
        unlock_kernel();

        CDEBUG(D_INODE, "put inode %p (%ld), count = %d, nlink = %d\n", inode,
               inode->i_ino, inode->i_count.counter - 1, inode->i_nlink);
        iput(inode);
        RETURN(rc);
}

static int filter_open(struct obd_conn *conn, struct obdo *oa)
{
        struct inode *inode;
        /* ENTRY; */

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "fatal: invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        inode = filter_inode_from_obj(conn->oc_dev, oa->o_id, oa->o_mode);
        if (!inode)
                RETURN(-ENOENT);

        return 0;
} /* filter_open */

static int filter_close(struct obd_conn *conn, struct obdo *oa)
{
        struct inode *inode;
        /* ENTRY; */

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "fatal: invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        inode = filter_inode_from_obj(conn->oc_dev, oa->o_id, oa->o_mode);
        if (!inode)
                RETURN(-ENOENT);

        CDEBUG(D_INODE, "put inode %p (%ld), count = %d, nlink = %d\n", inode,
               inode->i_ino, inode->i_count.counter - 1, inode->i_nlink);
        iput(inode);  /* for the close */
        CDEBUG(D_INODE, "objid #%ld has %d links, %d count after close\n",
               inode->i_ino, inode->i_nlink, inode->i_count.counter - 1);
        CDEBUG(D_INODE, "put inode %p (%ld), count = %d, nlink = %d\n", inode,
               inode->i_ino, inode->i_count.counter - 1, inode->i_nlink);
        iput(inode);  /* for this call */
        return 0;
} /* filter_close */

static int filter_create(struct obd_conn* conn, struct obdo *oa)
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
        if (!(oa->o_mode && S_IFMT)) {
                CERROR("filter obd: no type!\n");
                return -ENOENT;
        }

        filter_id(name, oa->o_id, oa->o_mode);
        mode = (oa->o_mode & ~S_IFMT) | S_IFREG;
        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        file = filp_open(name, O_RDONLY | O_CREAT, mode);
        pop_ctxt(&saved);
        if (IS_ERR(file)) {
                CERROR("Error mknod obj %s, err %ld\n", name, PTR_ERR(file));
                return -ENOENT;
        }
        filp_close(file, 0);

        /* Set flags for fields we have set in the inode struct */
        oa->o_valid |= OBD_MD_FLID | OBD_MD_FLBLKSZ | OBD_MD_FLBLOCKS |
                 OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME |
                 OBD_MD_FLUID | OBD_MD_FLGID;

        /* XXX Hmm, shouldn't we copy the fields into the obdo here? */
        return 0;
}

static int filter_destroy(struct obd_conn *conn, struct obdo *oa)
{
        struct obd_run_ctxt saved;
        struct obd_device *obddev;
        struct obd_client *cli;
        struct inode *inode;
        struct dentry *dir_dentry, *object_dentry;
        int rc;
        ENTRY;

        if (!(cli = gen_client(conn))) {
                CERROR("invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "destroying object %Ld\n",oa->o_id);
        obddev = conn->oc_dev;

        dir_dentry = filter_parent(obddev, oa->o_mode);
        down(&dir_dentry->d_inode->i_sem);

        object_dentry = filter_fid2dentry(obddev, dir_dentry, oa->o_id,
                                          oa->o_mode);
        if (IS_ERR(object_dentry))
                GOTO(out, rc = -ENOENT);

        inode = object_dentry->d_inode;
        if (inode->i_nlink != 1) {
                CERROR("destroying inode with nlink = %d\n", inode->i_nlink);
                inode->i_nlink = 1;
        }
        inode->i_mode = 010000;

        push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
        rc = vfs_unlink(dir_dentry->d_inode, object_dentry);
        pop_ctxt(&saved);
        CDEBUG(D_INODE, "put child %p, count = %d\n", object_dentry,
               object_dentry->d_count.counter-1);
        l_dput(object_dentry);

        EXIT;
out:
        up(&dir_dentry->d_inode->i_sem);
        return rc;
}

/* NB count and offset are used for punch, but not truncate */
static int filter_truncate(struct obd_conn *conn, struct obdo *oa,
                           obd_size count, obd_off offset)
{
        int error;
        ENTRY;

        CDEBUG(D_INODE, "calling truncate for object #%Ld, valid = %x, "
               "o_size = %Ld\n", oa->o_id, oa->o_valid, oa->o_size);
        error = filter_setattr(conn, oa);
        oa->o_valid = OBD_MD_FLBLOCKS | OBD_MD_FLCTIME | OBD_MD_FLMTIME;

        RETURN(error);
}

/* buffer must lie in user memory here */
static int filter_read(struct obd_conn *conn, struct obdo *oa, char *buf,
                        obd_size *count, obd_off offset)
{
        struct file * file;
        unsigned long retval;
        int err;
        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        file = filter_obj_open(conn->oc_dev, oa->o_id, oa->o_mode);
        if (IS_ERR(file))
                RETURN(PTR_ERR(file));

        /* count doubles as retval */
        retval = file->f_op->read(file, buf, *count, (loff_t *)&offset);
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
        struct obd_run_ctxt saved;
        int err;
        struct file * file;
        unsigned long retval;
        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        file = filter_obj_open(conn->oc_dev, oa->o_id, oa->o_mode);
        if (IS_ERR(file))
                RETURN(PTR_ERR(file));

        /* count doubles as retval */
        push_ctxt(&saved, &conn->oc_dev->u.filter.fo_ctxt);
        retval = file->f_op->write(file, buf, *count, (loff_t *)&offset);
        pop_ctxt(&saved);
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

static int filter_pgcache_brw(int rw, struct obd_conn *conn, obd_count num_oa,
                               struct obdo **oa, obd_count *oa_bufs,
                               struct page **pages, obd_size *count,
                               obd_off *offset, obd_flag *flags)
{
        struct obd_run_ctxt      saved;
        struct super_block      *sb;
        int                      onum;          /* index to oas */
        int                      pnum;          /* index to pages (bufs) */
        unsigned long            retval;
        int                      error;
        struct file             *file;
        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        sb = conn->oc_dev->u.filter.fo_sb;
        // if (rw == WRITE)
        push_ctxt(&saved, &conn->oc_dev->u.filter.fo_ctxt);
        pnum = 0; /* pnum indexes buf 0..num_pages */
        for (onum = 0; onum < num_oa; onum++) {
                int pg;

                file = filter_obj_open(conn->oc_dev, oa[onum]->o_id,
                                       oa[onum]->o_mode);
                if (IS_ERR(file))
                        GOTO(out, retval = PTR_ERR(file));

                /* count doubles as retval */
                for (pg = 0; pg < oa_bufs[onum]; pg++) {
                        CDEBUG(D_INODE, "OP %d obdo no/pno: (%d,%d) (%ld,%ld) "
                               "off count (%Ld,%Ld)\n",
                               rw, onum, pnum, file->f_dentry->d_inode->i_ino,
                               (unsigned long)offset[pnum] >> PAGE_CACHE_SHIFT,
                               (unsigned long long)offset[pnum],
                               (unsigned long long)count[pnum]);
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

                                if (retval != count[pnum]) {
                                        filp_close(file, 0);
                                        GOTO(out, retval = -EIO);
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
out:
        // if (rw == WRITE)
        pop_ctxt(&saved);
        error = (retval >= 0) ? 0 : retval;
        return error;
}


struct inode *ioobj_to_inode(struct obd_conn *conn, struct obd_ioobj *o)
{
        struct super_block *sb = conn->oc_dev->u.filter.fo_sb;
        struct inode *inode = NULL;
        ENTRY;

        if (!sb || !sb->s_dev) {
                CDEBUG(D_SUPER, "fatal: device not initialized.\n");
                RETURN(NULL);
        }

        if ( !o->ioo_id ) {
                CDEBUG(D_INODE, "fatal: invalid obdo %lu\n", (long)o->ioo_id);
                RETURN(NULL);
        }

        inode = filter_inode_from_obj(conn->oc_dev, o->ioo_id, S_IFREG);
        if (!inode || inode->i_nlink == 0 || is_bad_inode(inode)) {
                CERROR("from obdo - fatal: invalid inode %ld (%s).\n",
                       (long)o->ioo_id, inode ? inode->i_nlink ? "bad inode" :
                       "no links" : "NULL");
                iput(inode);
                RETURN(NULL);
        }

        RETURN(inode);
}

static int filter_preprw(int cmd, struct obd_conn *conn,
                         int objcount, struct obd_ioobj *obj,
                         int niocount, struct niobuf_remote *nb,
                         struct niobuf_local *res)
{
        struct obd_run_ctxt saved;
        struct obd_ioobj *o = obj;
        struct niobuf_remote *b = nb;
        struct niobuf_local *r = res;
        int i;
        ENTRY;

        memset(res, 0, sizeof(*res) * niocount);

        // if (cmd == OBD_BRW_WRITE)
        push_ctxt(&saved, &conn->oc_dev->u.filter.fo_ctxt);
        for (i = 0; i < objcount; i++, o++) {
                int j;
                for (j = 0; j < o->ioo_bufcnt; j++, b++, r++) {
                        unsigned long index = b->offset >> PAGE_SHIFT;
                        struct inode *inode = ioobj_to_inode(conn, o);
                        struct page *page;

                        /* FIXME: we need to iput all inodes on error */
                        if (!inode)
                                RETURN(-EINVAL);

                        if (cmd == OBD_BRW_WRITE)
                                page = lustre_get_page_write(inode, index);
                        else
                                page = lustre_get_page_read(inode, index);
                        if (IS_ERR(page))
                                RETURN(PTR_ERR(page));

                        r->addr = (__u64)(unsigned long)page_address(page);
                        r->offset = b->offset;
                        r->page = page;
                        r->len = PAGE_SIZE;
                }
        }
        // if (cmd == OBD_BRW_WRITE)
        pop_ctxt(&saved);
        return(0);
}

static int filter_commitrw(int cmd, struct obd_conn *conn,
                           int objcount, struct obd_ioobj *obj,
                           int niocount, struct niobuf_local *res)
{
        struct obd_run_ctxt saved;
        struct obd_ioobj *o = obj;
        struct niobuf_local *r = res;
        int i;
        ENTRY;

        // if (cmd == OBD_BRW_WRITE)
        push_ctxt(&saved, &conn->oc_dev->u.filter.fo_ctxt);
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

                        CDEBUG(D_INODE, "put inode %p (%ld), count = %d, nlink = %d\n",
                               page->mapping->host,
                               page->mapping->host->i_ino,
                               page->mapping->host->i_count.counter - 1,
                               page->mapping->host->i_nlink);
                        iput(page->mapping->host);
                }
        }
        // if (cmd == OBD_BRW_WRITE)
        pop_ctxt(&saved);
        RETURN(0);
}

static int filter_statfs(struct obd_conn *conn, struct statfs * statfs)
{
        struct super_block *sb;
        int err;
        ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        sb = conn->oc_dev->u.filter.fo_sb;

        err = sb->s_op->statfs(sb, statfs);
        RETURN(err);
} /* filter_statfs */


static int filter_get_info(struct obd_conn *conn, obd_count keylen,
                           void *key, obd_count *vallen, void **val)
{
        struct obd_device *obddev;
        struct obd_client * cli;
        ENTRY;

        if (!(cli = gen_client(conn))) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                RETURN(-EINVAL);
        }

        obddev = conn->oc_dev;

        if ( keylen == strlen("blocksize") &&
             memcmp(key, "blocksize", keylen) == 0 ) {
                *vallen = sizeof(int);
                *val = (void *)obddev->u.filter.fo_sb->s_blocksize;
                RETURN(0);
        }

        if ( keylen == strlen("blocksize_bits") &&
             memcmp(key, "blocksize_bits", keylen) == 0 ){
                *vallen = sizeof(int);
                *val = (void *)(int)obddev->u.filter.fo_sb->s_blocksize_bits;
                RETURN(0);
        }

        if ( keylen == strlen("root_ino") &&
             memcmp(key, "root_ino", keylen) == 0 ){
                *vallen = sizeof(int);
                *val = (void *)(int) FILTER_ROOTINO;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
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
