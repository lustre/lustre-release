/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  linux/fs/obdfilter/filter.c
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * by Peter Braam <braam@clusterfs.com>
 * and Andreas Dilger <adilger@clusterfs.com>
 */

#define EXPORT_SYMTAB
#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/obd_class.h>
#include <linux/lustre_dlm.h>
#include <linux/obd_filter.h>
#include <linux/ext3_jbd.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/extN_jbd.h>
#endif
#include <linux/quotaops.h>
#include <linux/init.h>
#include <linux/random.h>
#include <linux/stringify.h>

static kmem_cache_t *filter_open_cache;
static kmem_cache_t *filter_dentry_cache;

#define FILTER_ROOTINO 2
#define FILTER_ROOTINO_STR __stringify(FILTER_ROOTINO)

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
        return sprintf(buf, "O/%s/"LPU64, obd_mode_to_type(mode), id);
}

static inline void f_dput(struct dentry *dentry)
{
        /* Can't go inside filter_ddelete because it can block */
        CDEBUG(D_INODE, "putting %s: %p, count = %d\n",
               dentry->d_name.name, dentry, atomic_read(&dentry->d_count) - 1);
        LASSERT(atomic_read(&dentry->d_count) > 0);

        dput(dentry);
}

/* Not racy w.r.t. others, because we are the only user of this dentry */
static void filter_drelease(struct dentry *dentry)
{
        if (dentry->d_fsdata)
                kmem_cache_free(filter_dentry_cache, dentry->d_fsdata);
}

struct dentry_operations filter_dops = {
        .d_release = filter_drelease,
};

/* setup the object store with correct subdirectories */
static int filter_prep(struct obd_device *obd)
{
        struct obd_run_ctxt saved;
        struct filter_obd *filter = &obd->u.filter;
        struct dentry *dentry;
        struct dentry *root;
        struct file *file;
        struct inode *inode;
        int rc = 0;
        __u64 lastobjid = 2;
        int mode = 0;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
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
        f_dput(dentry);
        dentry = simple_mkdir(current->fs->pwd, "D", 0700);
        CDEBUG(D_INODE, "got/created D: %p\n", dentry);
        if (IS_ERR(dentry)) {
                rc = PTR_ERR(dentry);
                CERROR("cannot open/create D: rc = %d\n", rc);
                GOTO(out_O, rc);
        }

        root = simple_mknod(dentry, FILTER_ROOTINO_STR, S_IFREG | 0755);
        f_dput(dentry);
        if (IS_ERR(root)) {
                rc = PTR_ERR(root);
                CERROR("OBD filter: cannot open/create root %d: rc = %d\n",
                       FILTER_ROOTINO, rc);
                GOTO(out_O, rc);
        }
        f_dput(root);

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

        if (inode->i_size == 0) {
                __u64 disk_lastobjid = cpu_to_le64(lastobjid);
                ssize_t retval = file->f_op->write(file,(char *)&disk_lastobjid,
                                                   sizeof(disk_lastobjid),
                                                   &file->f_pos);
                if (retval != sizeof(disk_lastobjid)) {
                        CDEBUG(D_INODE,"OBD filter: error writing lastobjid\n");
                        filp_close(file, 0);
                        GOTO(out_O_mode, rc = -EIO);
                }
        } else {
                __u64 disk_lastobjid;
                ssize_t retval = file->f_op->read(file, (char *)&disk_lastobjid,
                                                  sizeof(disk_lastobjid),
                                                  &file->f_pos);
                if (retval != sizeof(disk_lastobjid)) {
                        CDEBUG(D_INODE,"OBD filter: error reading lastobjid\n");
                        filp_close(file, 0);
                        GOTO(out_O_mode, rc = -EIO);
                }
                lastobjid = le64_to_cpu(disk_lastobjid);
        }
        filter->fo_lastobjid = lastobjid;
        filp_close(file, 0);

        rc = 0;
 out:
        pop_ctxt(&saved);

        return(rc);

out_O_mode:
        while (mode-- > 0) {
                struct dentry *dentry = filter->fo_dentry_O_mode[mode];
                if (dentry) {
                        f_dput(dentry);
                        filter->fo_dentry_O_mode[mode] = NULL;
                }
        }
out_O:
        f_dput(filter->fo_dentry_O);
        filter->fo_dentry_O = NULL;
        goto out;
}

/* cleanup the filter: write last used object id to status file */
static void filter_post(struct obd_device *obd)
{
        struct obd_run_ctxt saved;
        struct filter_obd *filter = &obd->u.filter;
        __u64 disk_lastobjid;
        long rc;
        struct file *file;
        int mode;

        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        file = filp_open("D/status", O_RDWR | O_CREAT, 0700);
        if (IS_ERR(file)) {
                CERROR("OBD filter: cannot create status file\n");
                goto out;
        }

        file->f_pos = 0;
        disk_lastobjid = cpu_to_le64(filter->fo_lastobjid);
        rc = file->f_op->write(file, (char *)&disk_lastobjid,
                       sizeof(disk_lastobjid), &file->f_pos);
        if (rc != sizeof(disk_lastobjid))
                CERROR("OBD filter: error writing lastobjid: rc = %ld\n", rc);

        rc = filp_close(file, NULL);
        if (rc)
                CERROR("OBD filter: cannot close status file: rc = %ld\n", rc);

        for (mode = 0; mode < (S_IFMT >> S_SHIFT); mode++) {
                struct dentry *dentry = filter->fo_dentry_O_mode[mode];
                if (dentry) {
                        f_dput(dentry);
                        filter->fo_dentry_O_mode[mode] = NULL;
                }
        }
        f_dput(filter->fo_dentry_O);
out:
        pop_ctxt(&saved);
}


static __u64 filter_next_id(struct obd_device *obd)
{
        obd_id id;

        spin_lock(&obd->u.filter.fo_objidlock);
        id = ++obd->u.filter.fo_lastobjid;
        spin_unlock(&obd->u.filter.fo_objidlock);

        /* FIXME: write the lastobjid to disk here */
        return id;
}

/* how to get files, dentries, inodes from object id's */
/* parent i_sem is already held if needed for exclusivity */
static struct dentry *filter_fid2dentry(struct obd_device *obd,
                                        struct dentry *dparent,
                                        __u64 id, __u32 type)
{
        struct super_block *sb = obd->u.filter.fo_sb;
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
                LBUG();
                RETURN(ERR_PTR(-ESTALE));
        }

        if (!(type & S_IFMT)) {
                CERROR("OBD %s, object "LPU64" has bad type: %o\n",
                       __FUNCTION__, id, type);
                RETURN(ERR_PTR(-EINVAL));
        }

        len = sprintf(name, LPU64, id);
        CDEBUG(D_INODE, "opening object O/%s/%s\n", obd_mode_to_type(type),
               name);
        dchild = lookup_one_len(name, dparent, len);
        if (IS_ERR(dchild)) {
                CERROR("child lookup error %ld\n", PTR_ERR(dchild));
                RETURN(dchild);
        }

        if (!dchild->d_op)
                dchild->d_op = &filter_dops;
        else
                LASSERT(dchild->d_op == &filter_dops);

        CDEBUG(D_INODE, "got child obj O/%s/%s: %p, count = %d\n",
               obd_mode_to_type(type), name, dchild,
               atomic_read(&dchild->d_count));

        LASSERT(atomic_read(&dchild->d_count) > 0);

        RETURN(dchild);
}

static inline struct dentry *filter_parent(struct obd_device *obd,
                                           obd_mode mode)
{
        struct filter_obd *filter = &obd->u.filter;

        return filter->fo_dentry_O_mode[(mode & S_IFMT) >> S_SHIFT];
}

static struct file *filter_obj_open(struct obd_export *export,
                                    __u64 id, __u32 type)
{
        struct filter_obd *filter = &export->exp_obd->u.filter;
        struct super_block *sb = filter->fo_sb;
        struct filter_export_data *fed = &export->exp_filter_data;
        struct filter_dentry_data *fdd;
        struct filter_file_data *ffd;
        struct obd_run_ctxt saved;
        char name[24];
        struct file *file;
        ENTRY;

        if (!sb || !sb->s_dev) {
                CERROR("fatal: device not initialized.\n");
                RETURN(ERR_PTR(-ENXIO));
        }

        if (!id) {
                CERROR("fatal: invalid obdo "LPU64"\n", id);
                RETURN(ERR_PTR(-ESTALE));
        }

        if (!(type & S_IFMT)) {
                CERROR("OBD %s, object "LPU64" has bad type: %o\n",
                       __FUNCTION__, id, type);
                RETURN(ERR_PTR(-EINVAL));
        }

        ffd = kmem_cache_alloc(filter_open_cache, SLAB_KERNEL);
        if (!ffd) {
                CERROR("obdfilter: out of memory\n");
                RETURN(ERR_PTR(-ENOMEM));
        }

        /* We preallocate this to avoid blocking while holding fo_fddlock */
        fdd = kmem_cache_alloc(filter_dentry_cache, SLAB_KERNEL);
        if (!fdd) {
                CERROR("obdfilter: out of memory\n");
                GOTO(out_ffd, file = ERR_PTR(-ENOMEM));
        }

        filter_id(name, id, type);
        push_ctxt(&saved, &filter->fo_ctxt, NULL);
        file = filp_open(name, O_RDONLY | O_LARGEFILE, 0 /* type? */);
        pop_ctxt(&saved);

        if (IS_ERR(file))
                GOTO(out_fdd, file);

        spin_lock(&filter->fo_fddlock);
        if (file->f_dentry->d_fsdata) {
                spin_unlock(&filter->fo_fddlock);
                kmem_cache_free(filter_dentry_cache, fdd);
                fdd = file->f_dentry->d_fsdata;
                LASSERT(kmem_cache_validate(filter_dentry_cache, fdd));
                /* should only happen during client recovery */
                if (fdd->fdd_flags & FILTER_FLAG_DESTROY)
                        CDEBUG(D_INODE,"opening destroyed object "LPX64"\n",id);
                atomic_inc(&fdd->fdd_open_count);
        } else {
                atomic_set(&fdd->fdd_open_count, 1);
                spin_lock_init(&filter->fo_fddlock);
                fdd->fdd_flags = 0;
                /* If this is racy, then we can use {cmp}xchg and atomic_add */
                file->f_dentry->d_fsdata = fdd;
                spin_unlock(&filter->fo_fddlock);
        }

        get_random_bytes(&ffd->ffd_servercookie, sizeof(ffd->ffd_servercookie));
        ffd->ffd_file = file;
        file->private_data = ffd;

        spin_lock(&fed->fed_lock);
        list_add(&ffd->ffd_export_list, &fed->fed_open_head);
        spin_unlock(&fed->fed_lock);

        CDEBUG(D_INODE, "opening objid "LPX64": rc = %p\n", id, file);

out:
        RETURN(file);

out_fdd:
        kmem_cache_free(filter_dentry_cache, fdd);
out_ffd:
        ffd->ffd_servercookie = DEAD_HANDLE_MAGIC;
        kmem_cache_free(filter_open_cache, ffd);
        goto out;
}

/* Caller must hold i_sem on dir_dentry->d_inode */
static int filter_destroy_internal(struct obd_device *obd,
                                   struct dentry *dir_dentry,
                                   struct dentry *object_dentry)
{
        struct obd_run_ctxt saved;
        struct inode *inode = object_dentry->d_inode;
        int rc;

        if (inode->i_nlink != 1 || atomic_read(&inode->i_count) != 1) {
                CERROR("destroying objid %*s nlink = %d, count = %d\n",
                       object_dentry->d_name.len,
                       object_dentry->d_name.name,
                       inode->i_nlink, atomic_read(&inode->i_count));
        }

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        rc = vfs_unlink(dir_dentry->d_inode, object_dentry);
        /* XXX unlink from PENDING directory now too */
        pop_ctxt(&saved);

        if (rc)
                CERROR("error unlinking objid %*s: rc %d\n",
                       object_dentry->d_name.len,
                       object_dentry->d_name.name, rc);

        return rc;
}

static int filter_close_internal(struct obd_device *obd,
                                 struct filter_file_data *ffd)
{
        struct file *filp = ffd->ffd_file;
        struct dentry *object_dentry = dget(filp->f_dentry);
        struct filter_dentry_data *fdd = object_dentry->d_fsdata;
        int rc, rc2 = 0;
        ENTRY;

        LASSERT(filp->private_data == ffd);
        LASSERT(fdd);

        rc = filp_close(filp, 0);

        if (atomic_dec_and_test(&fdd->fdd_open_count) &&
            fdd->fdd_flags & FILTER_FLAG_DESTROY) {
                struct dentry *dir_dentry = filter_parent(obd, S_IFREG);

                down(&dir_dentry->d_inode->i_sem);
                rc2 = filter_destroy_internal(obd, dir_dentry, object_dentry);
                if (rc2 && !rc)
                        rc = rc2;
                up(&dir_dentry->d_inode->i_sem);
        }

        f_dput(object_dentry);
        kmem_cache_free(filter_open_cache, ffd);

        RETURN(rc);
}

/* obd methods */
static int filter_connect(struct lustre_handle *conn, struct obd_device *obd,
                          obd_uuid_t cluuid, struct recovd_obd *recovd,
                          ptlrpc_recovery_cb_t recover)
{
        struct obd_export *exp;
        int rc;

        ENTRY;
        MOD_INC_USE_COUNT;
        rc = class_connect(conn, obd, cluuid);
        if (rc)
                GOTO(out_dec, rc);
        exp = class_conn2export(conn);
        LASSERT(exp);

        INIT_LIST_HEAD(&exp->exp_filter_data.fed_open_head);
        spin_lock_init(&exp->exp_filter_data.fed_lock);
out:
        RETURN(rc);

out_dec:
        MOD_DEC_USE_COUNT;
        goto out;
}

static int filter_disconnect(struct lustre_handle *conn)
{
        struct obd_export *exp = class_conn2export(conn);
        struct filter_export_data *fed;
        int rc;
        ENTRY;

        LASSERT(exp);
        fed = &exp->exp_filter_data;
        spin_lock(&fed->fed_lock);
        while (!list_empty(&fed->fed_open_head)) {
                struct filter_file_data *ffd;

                ffd = list_entry(fed->fed_open_head.next, typeof(*ffd),
                                 ffd_export_list);
                list_del(&ffd->ffd_export_list);
                spin_unlock(&fed->fed_lock);

                CERROR("force closing file %*s on disconnect\n",
                       ffd->ffd_file->f_dentry->d_name.len,
                       ffd->ffd_file->f_dentry->d_name.name);

                filter_close_internal(exp->exp_obd, ffd);
                spin_lock(&fed->fed_lock);
        }
        spin_unlock(&fed->fed_lock);

        ldlm_cancel_locks_for_export(exp);
        rc = class_disconnect(conn);
        if (!rc)
                MOD_DEC_USE_COUNT;

        /* XXX cleanup preallocated inodes */
        RETURN(rc);
}

/* mount the file system (secretly) */
static int filter_setup(struct obd_device *obd, obd_count len, void *buf)
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

        filter = &obd->u.filter;;
        filter->fo_vfsmnt = mnt;
        filter->fo_fstype = strdup(data->ioc_inlbuf2);
        filter->fo_sb = mnt->mnt_root->d_inode->i_sb;
        CERROR("%s: mnt is %p\n", data->ioc_inlbuf1, filter->fo_vfsmnt);
        /* XXX is this even possible if do_kern_mount succeeded? */
        if (!filter->fo_sb)
                GOTO(err_kfree, err = -ENODEV);

        OBD_SET_CTXT_MAGIC(&filter->fo_ctxt);
        filter->fo_ctxt.pwdmnt = mnt;
        filter->fo_ctxt.pwd = mnt->mnt_root;
        filter->fo_ctxt.fs = get_ds();

        err = filter_prep(obd);
        if (err)
                GOTO(err_kfree, err);
        spin_lock_init(&filter->fo_fddlock);
        spin_lock_init(&filter->fo_objidlock);
        INIT_LIST_HEAD(&filter->fo_export_list);

        obd->obd_namespace =
                ldlm_namespace_new("filter-tgt", LDLM_NAMESPACE_SERVER);
        if (obd->obd_namespace == NULL)
                LBUG();

        ptlrpc_init_client(LDLM_REQUEST_PORTAL, LDLM_REPLY_PORTAL,
                           "filter_ldlm_client", &obd->obd_ldlm_client);

        RETURN(0);

err_kfree:
        kfree(filter->fo_fstype);
        unlock_kernel();
        mntput(filter->fo_vfsmnt);
        filter->fo_sb = 0;
        lock_kernel();

err_dec:
        MOD_DEC_USE_COUNT;
        return err;
}


static int filter_cleanup(struct obd_device *obd)
{
        struct super_block *sb;
        ENTRY;

        if (!list_empty(&obd->obd_exports)) {
                CERROR("still has clients!\n");
                class_disconnect_all(obd);
                if (!list_empty(&obd->obd_exports)) {
                        CERROR("still has exports after forced cleanup?\n");
                        RETURN(-EBUSY);
                }
        }

        ldlm_namespace_free(obd->obd_namespace);

        sb = obd->u.filter.fo_sb;
        if (!obd->u.filter.fo_sb)
                RETURN(0);

        filter_post(obd);

        shrink_dcache_parent(sb->s_root);
        unlock_kernel();
        mntput(obd->u.filter.fo_vfsmnt);
        obd->u.filter.fo_sb = 0;
        kfree(obd->u.filter.fo_fstype);

        lock_kernel();

        MOD_DEC_USE_COUNT;
        RETURN(0);
}


static void filter_from_inode(struct obdo *oa, struct inode *inode, int valid)
{
        int type = oa->o_mode & S_IFMT;
        ENTRY;

        CDEBUG(D_INFO, "src inode %ld (%p), dst obdo %ld valid 0x%08x\n",
               inode->i_ino, inode, (long)oa->o_id, valid);
        /* Don't copy the inode number in place of the object ID */
        obdo_from_inode(oa, inode, valid);
        oa->o_mode &= ~S_IFMT;
        oa->o_mode |= type;

        if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode)) {
                obd_rdev rdev = kdev_t_to_nr(inode->i_rdev);
                oa->o_rdev = rdev;
                oa->o_valid |= OBD_MD_FLRDEV;
        }

        EXIT;
}

static struct filter_file_data *filter_handle2ffd(struct lustre_handle *handle)
{
        struct filter_file_data *ffd = NULL;
        ENTRY;

        if (!handle || !handle->addr)
                RETURN(NULL);

        ffd = (struct filter_file_data *)(unsigned long)(handle->addr);
        if (!kmem_cache_validate(filter_open_cache, (void *)ffd))
                RETURN(NULL);

        if (ffd->ffd_servercookie != handle->cookie)
                RETURN(NULL);

        LASSERT(ffd->ffd_file->private_data == ffd);
        RETURN(ffd);
}

static struct dentry *__filter_oa2dentry(struct lustre_handle *conn,
                                         struct obdo *oa, char *what)
{
        struct dentry *dentry = NULL;

        if (oa->o_valid & OBD_MD_FLHANDLE) {
                struct lustre_handle *ost_handle = obdo_handle(oa);
                struct filter_file_data *ffd = filter_handle2ffd(ost_handle);

                if (ffd)
                        dentry = dget(ffd->ffd_file->f_dentry);
        }

        if (!dentry) {
                struct obd_device *obd = class_conn2obd(conn);
                if (!obd) {
                        CERROR("invalid client "LPX64"\n", conn->addr);
                        RETURN(ERR_PTR(-EINVAL));
                }
                dentry = filter_fid2dentry(obd, filter_parent(obd, oa->o_mode),
                                           oa->o_id, oa->o_mode);
        }

        if (!dentry->d_inode) {
                CERROR("%s on non-existent object: "LPU64"\n", what, oa->o_id);
                f_dput(dentry);
                dentry = ERR_PTR(-ENOENT);
        }

        return dentry;
}

#define filter_oa2dentry(conn, oa) __filter_oa2dentry(conn, oa, __FUNCTION__)

static int filter_getattr(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *md)
{
        struct dentry *dentry = NULL;
        int rc = 0;
        ENTRY;

        dentry = filter_oa2dentry(conn, oa);
        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        filter_from_inode(oa, dentry->d_inode, oa->o_valid);

        f_dput(dentry);
        RETURN(rc);
}

static int filter_setattr(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *md)
{
        struct obd_run_ctxt saved;
        struct obd_device *obd = class_conn2obd(conn);
        struct dentry *dentry;
        struct iattr iattr;
        struct inode *inode;
        int rc;
        ENTRY;

        dentry = filter_oa2dentry(conn, oa);

        if (IS_ERR(dentry))
                RETURN(PTR_ERR(dentry));

        iattr_from_obdo(&iattr, oa, oa->o_valid);
        iattr.ia_mode = (iattr.ia_mode & ~S_IFMT) | S_IFREG;
        inode = dentry->d_inode;

        lock_kernel();
        if (iattr.ia_valid & ATTR_SIZE)
                down(&inode->i_sem);
        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        if (inode->i_op->setattr)
                rc = inode->i_op->setattr(dentry, &iattr);
        else
                rc = inode_setattr(inode, &iattr);
        pop_ctxt(&saved);
        if (iattr.ia_valid & ATTR_SIZE) {
                up(&inode->i_sem);
                oa->o_valid = OBD_MD_FLBLOCKS | OBD_MD_FLCTIME | OBD_MD_FLMTIME;
                obdo_from_inode(oa, inode, oa->o_valid);
        }
        unlock_kernel();

        f_dput(dentry);
        RETURN(rc);
}

static int filter_open(struct lustre_handle *conn, struct obdo *oa,
                       struct lov_stripe_md *ea)
{
        struct obd_export *export;
        struct lustre_handle *handle;
        struct filter_file_data *ffd;
        struct file *filp;
        int rc = 0;
        ENTRY;

        export = class_conn2export(conn);
        if (!export) {
                CDEBUG(D_IOCTL, "fatal: invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        filp = filter_obj_open(export, oa->o_id, oa->o_mode);
        if (IS_ERR(filp))
                GOTO(out, rc = PTR_ERR(filp));

        filter_from_inode(oa, filp->f_dentry->d_inode, oa->o_valid);

        ffd = filp->private_data;
        handle = obdo_handle(oa);
        handle->addr = (__u64)(unsigned long)ffd;
        handle->cookie = ffd->ffd_servercookie;
        oa->o_valid |= OBD_MD_FLHANDLE;
out:
        RETURN(rc);
} /* filter_open */

static int filter_close(struct lustre_handle *conn, struct obdo *oa,
                        struct lov_stripe_md *ea)
{
        struct obd_export *exp;
        struct filter_file_data *ffd;
        struct filter_export_data *fed;
        int rc;
        ENTRY;

        exp = class_conn2export(conn);
        if (!exp) {
                CDEBUG(D_IOCTL, "fatal: invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        if (!(oa->o_valid & OBD_MD_FLHANDLE)) {
                CERROR("no handle for close of objid "LPX64"\n", oa->o_id);
                RETURN(-EINVAL);
        }

        ffd = filter_handle2ffd(obdo_handle(oa));
        if (!ffd) {
                struct lustre_handle *handle = obdo_handle(oa);
                CERROR("bad handle ("LPX64") or cookie ("LPX64") for close\n",
                       handle->addr, handle->cookie);
                RETURN(-ESTALE);
        }

        fed = &exp->exp_filter_data;
        spin_lock(&fed->fed_lock);
        list_del(&ffd->ffd_export_list);
        spin_unlock(&fed->fed_lock);

        rc = filter_close_internal(exp->exp_obd, ffd);

        RETURN(rc);
} /* filter_close */

static int filter_create(struct lustre_handle *conn, struct obdo *oa,
                         struct lov_stripe_md **ea)
{
        struct obd_device *obd = class_conn2obd(conn);
        char name[64];
        struct obd_run_ctxt saved;
        struct dentry *new;
        struct iattr;
        ENTRY;

        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                return -EINVAL;
        }

        if (!(oa->o_mode & S_IFMT)) {
                CERROR("OBD %s, object "LPU64" has bad type: %o\n",
                       __FUNCTION__, oa->o_id, oa->o_mode);
                return -ENOENT;
        }

        oa->o_id = filter_next_id(obd);

        //filter_id(name, oa->o_id, oa->o_mode);
        sprintf(name, LPU64, oa->o_id);
        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        new = simple_mknod(filter_parent(obd, oa->o_mode), name, oa->o_mode);
        pop_ctxt(&saved);
        if (IS_ERR(new)) {
                CERROR("Error mknod obj %s, err %ld\n", name, PTR_ERR(new));
                return -ENOENT;
        }

        /* Set flags for fields we have set in the inode struct */
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLBLKSZ | OBD_MD_FLBLOCKS |
                 OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME;
        filter_from_inode(oa, new->d_inode, oa->o_valid);
        f_dput(new);

        return 0;
}

static int filter_destroy(struct lustre_handle *conn, struct obdo *oa,
                          struct lov_stripe_md *ea)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct dentry *dir_dentry, *object_dentry;
        int rc;
        ENTRY;

        if (!obd) {
                CERROR("invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        CDEBUG(D_INODE, "destroying object "LPD64"\n", oa->o_id);

        dir_dentry = filter_parent(obd, oa->o_mode);
        down(&dir_dentry->d_inode->i_sem);

        object_dentry = filter_oa2dentry(conn, oa);
        if (IS_ERR(object_dentry))
                GOTO(out, rc = -ENOENT);

        if (object_dentry->d_fsdata) {
                struct filter_dentry_data *fdd = object_dentry->d_fsdata;

                if (!(fdd->fdd_flags & FILTER_FLAG_DESTROY)) {
                        fdd->fdd_flags |= FILTER_FLAG_DESTROY;
                        /* XXX put into PENDING directory in case of crash */
                }
                GOTO(out_dput, rc = 0);
        }

        rc = filter_destroy_internal(obd, dir_dentry, object_dentry);
out_dput:
        f_dput(object_dentry);

        EXIT;
out:
        up(&dir_dentry->d_inode->i_sem);
        return rc;
}

/* NB count and offset are used for punch, but not truncate */
static int filter_truncate(struct lustre_handle *conn, struct obdo *oa,
                           struct lov_stripe_md *lsm,
                           obd_off start, obd_off end)
{
        int error;
        ENTRY;

        if (end != OBD_OBJECT_EOF)
                CERROR("PUNCH not supported, only truncate works\n");

        CDEBUG(D_INODE, "calling truncate for object "LPX64", valid = %x, "
               "o_size = "LPD64"\n", oa->o_id, oa->o_valid, start);
        oa->o_size = start;
        error = filter_setattr(conn, oa, NULL);
        RETURN(error);
}

static int filter_pgcache_brw(int cmd, struct lustre_handle *conn,
                              struct lov_stripe_md *lsm, obd_count oa_bufs,
                              struct brw_page *pga, brw_callback_t callback,
                              struct io_cb_data *data)
{
        struct obd_export       *export = class_conn2export(conn);
        struct obd_run_ctxt      saved;
        struct super_block      *sb;
        int                      pnum;          /* index to pages (bufs) */
        unsigned long            retval;
        int                      error;
        struct file             *file;
        int pg;
        ENTRY;

        if (!export) {
                CDEBUG(D_IOCTL, "invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        sb = export->exp_obd->u.filter.fo_sb;
        push_ctxt(&saved, &export->exp_obd->u.filter.fo_ctxt, NULL);
        pnum = 0; /* pnum indexes buf 0..num_pages */

        file = filter_obj_open(export, lsm->lsm_object_id, S_IFREG);
        if (IS_ERR(file))
                GOTO(out, retval = PTR_ERR(file));

        /* count doubles as retval */
        for (pg = 0; pg < oa_bufs; pg++) {
                CDEBUG(D_INODE, "OP %d obdo pgno: (%d) (%ld,"LPU64
                       ") off count ("LPU64",%d)\n",
                       cmd, pnum, file->f_dentry->d_inode->i_ino,
                       pga[pnum].off >> PAGE_CACHE_SHIFT, pga[pnum].off,
                       (int)pga[pnum].count);
                if (cmd & OBD_BRW_WRITE) {
                        loff_t off;
                        char *buffer;
                        off = pga[pnum].off;
                        buffer = kmap(pga[pnum].pg);
                        retval = file->f_op->write(file, buffer,
                                                   pga[pnum].count,
                                                   &off);
                        kunmap(pga[pnum].pg);
                        CDEBUG(D_INODE, "retval %ld\n", retval);
                } else {
                        loff_t off = pga[pnum].off;
                        char *buffer = kmap(pga[pnum].pg);

                        if (off >= file->f_dentry->d_inode->i_size) {
                                memset(buffer, 0, pga[pnum].count);
                                retval = pga[pnum].count;
                        } else {
                                retval = file->f_op->read(file, buffer,
                                                          pga[pnum].count, &off);
                        }
                        kunmap(pga[pnum].pg);

                        if (retval != pga[pnum].count) {
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

        /* XXX: do something with callback if it is set? */

        EXIT;
out:
        pop_ctxt(&saved);
        error = (retval >= 0) ? 0 : retval;
        return error;
}

/*
 * Calculate the number of buffer credits needed to write multiple pages in
 * a single ext3/extN transaction.  No, this shouldn't be here, but as yet
 * ext3 doesn't have a nice API for calculating this sort of thing in advance.
 *
 * See comment above ext3_writepage_trans_blocks for details.  We assume
 * no data journaling is being done, but it does allow for all of the pages
 * being non-contiguous.  If we are guaranteed contiguous pages we could
 * reduce the number of (d)indirect blocks a lot.
 *
 * With N blocks per page and P pages, for each inode we have at most:
 * N*P indirect
 * min(N*P, blocksize/4 + 1) dindirect blocks
 * 1 tindirect
 *
 * For the entire filesystem, we have at most:
 * min(sum(nindir + P), ngroups) bitmap blocks (from the above)
 * min(sum(nindir + P), gdblocks) group descriptor blocks (from the above)
 * 1 inode block
 * 1 superblock
 * 2 * EXT3_SINGLEDATA_TRANS_BLOCKS for the quota files
 */
static int ext3_credits_needed(struct super_block *sb, int objcount,
                               struct obd_ioobj *obj)
{
        struct obd_ioobj *o = obj;
        int blockpp = 1 << (PAGE_CACHE_SHIFT - sb->s_blocksize_bits);
        int addrpp = EXT3_ADDR_PER_BLOCK(sb) * blockpp;
        int nbitmaps = 0;
        int ngdblocks = 0;
        int needed = objcount + 1;
        int i;

        for (i = 0; i < objcount; i++, o++) {
                int nblocks = o->ioo_bufcnt * blockpp;
                int ndindirect = min(nblocks, addrpp + 1);
                int nindir = nblocks + ndindirect + 1;

                nbitmaps += nindir + nblocks;
                ngdblocks += nindir + nblocks;

                needed += nindir;
        }

        /* Assumes ext3 and extN have same sb_info layout at the start. */
        if (nbitmaps > EXT3_SB(sb)->s_groups_count)
                nbitmaps = EXT3_SB(sb)->s_groups_count;
        if (ngdblocks > EXT3_SB(sb)->s_gdb_count)
                ngdblocks = EXT3_SB(sb)->s_gdb_count;

        needed += nbitmaps + ngdblocks;

#ifdef CONFIG_QUOTA
        /* We assume that there will be 1 bit set in s_dquot.flags for each
         * quota file that is active.  This is at least true for now.
         */
        needed += hweight32(sb_any_quota_enabled(sb)) *
                EXT3_SINGLEDATA_TRANS_BLOCKS;
#endif

        return needed;
}

/* We have to start a huge journal transaction here to hold all of the
 * metadata for the pages being written here.  This is necessitated by
 * the fact that we do lots of prepare_write operations before we do
 * any of the matching commit_write operations, so even if we split
 * up to use "smaller" transactions none of them could complete until
 * all of them were opened.  By having a single journal transaction,
 * we eliminate duplicate reservations for common blocks like the
 * superblock and group descriptors or bitmaps.
 *
 * We will start the transaction here, but each prepare_write will
 * add a refcount to the transaction, and each commit_write will
 * remove a refcount.  The transaction will be closed when all of
 * the pages have been written.
 */
static void *ext3_filter_journal_start(struct filter_obd *filter,
                                       int objcount, struct obd_ioobj *obj,
                                       int niocount, struct niobuf_remote *nb)
{
        journal_t *journal = NULL;
        handle_t *handle = NULL;
        int needed;

        /* It appears that some kernels have different values for
         * EXT*_MAX_GROUP_LOADED (either 8 or 32), so we cannot
         * assume anything after s_inode_bitmap_number is the same.
         */
        if (!strcmp(filter->fo_fstype, "ext3"))
                journal = EXT3_SB(filter->fo_sb)->s_journal;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        else if (!strcmp(filter->fo_fstype, "extN"))
                journal = EXTN_SB(filter->fo_sb)->s_journal;
#endif
        needed = ext3_credits_needed(filter->fo_sb, objcount, obj);

        /* The number of blocks we could _possibly_ dirty can very large.
         * We reduce our request if it is absurd (and we couldn't get that
         * many credits for a single handle anyways).
         *
         * At some point we have to limit the size of I/Os sent at one time,
         * increase the size of the journal, or we have to calculate the
         * actual journal requirements more carefully by checking all of
         * the blocks instead of being maximally pessimistic.  It remains to
         * be seen if this is a real problem or not.
         */
        if (needed > journal->j_max_transaction_buffers) {
                CERROR("want too many journal credits (%d) using %d instead\n",
                       needed, journal->j_max_transaction_buffers);
                needed = journal->j_max_transaction_buffers;
        }

        lock_kernel();
        handle = journal_start(journal, needed);
        unlock_kernel();
        if (IS_ERR(handle))
                CERROR("can't get handle for %d credits: rc = %ld\n", needed,
                       PTR_ERR(handle));

        return(handle);
}

static void *filter_journal_start(void **journal_save,
                                  struct filter_obd *filter,
                                  int objcount, struct obd_ioobj *obj,
                                  int niocount, struct niobuf_remote *nb)
{
        void *handle = NULL;

        /* This may not be necessary - we probably never have a
         * transaction started when we enter here, so we can
         * remove the saving of the journal state entirely.
         * For now leave it in just to see if it ever happens.
         */
        *journal_save = current->journal_info;
        if (*journal_save) {
                CERROR("Already have handle %p???\n", *journal_save);
                LBUG();
                current->journal_info = NULL;
        }

        if (!strcmp(filter->fo_fstype, "ext3") ||
            !strcmp(filter->fo_fstype, "extN"))
                handle = ext3_filter_journal_start(filter, objcount, obj,
                                                   niocount, nb);
        return handle;
}

static int ext3_filter_journal_stop(void *handle)
{
        int rc;

        /* We got a refcount on the handle for each call to prepare_write,
         * so we can drop the "parent" handle here to avoid the need for
         * osc to call back into filterobd to close the handle.  The
         * remaining references will be dropped in commit_write.
         */
        lock_kernel();
        rc = journal_stop((handle_t *)handle);
        unlock_kernel();

        return rc;
}

static int filter_journal_stop(void *journal_save, struct filter_obd *filter,
                               void *handle)
{
        int rc = 0;

        if (!strcmp(filter->fo_fstype, "ext3") ||
            !strcmp(filter->fo_fstype, "extN"))
                rc = ext3_filter_journal_stop(handle);

        if (rc)
                CERROR("error on journal stop: rc = %d\n", rc);

        current->journal_info = journal_save;

        return rc;
}

static inline void lustre_put_page(struct page *page)
{
        kunmap(page);
        page_cache_release(page);
}


#ifndef PageUptodate
#define PageUptodate(page) Page_Uptodate(page)
#endif
static struct page *
lustre_get_page_read(struct inode *inode,
                     struct niobuf_remote *rnb)
{
        unsigned long index = rnb->offset >> PAGE_SHIFT;
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        int rc;

        page = read_cache_page(mapping, index,
                               (filler_t*)mapping->a_ops->readpage, NULL);
        if (!IS_ERR(page)) {
                wait_on_page(page);
                kmap(page);
                if (!PageUptodate(page)) {
                        CERROR("page index %lu not uptodate\n", index);
                        GOTO(err_page, rc = -EIO);
                }
                if (PageError(page)) {
                        CERROR("page index %lu has error\n", index);
                        GOTO(err_page, rc = -EIO);
                }
        }
        return page;

err_page:
        lustre_put_page(page);
        return ERR_PTR(rc);
}

static struct page *
lustre_get_page_write(struct inode *inode, unsigned long index)
{
        struct address_space *mapping = inode->i_mapping;
        struct page *page;
        int rc;

        page = grab_cache_page(mapping, index); /* locked page */

        if (!IS_ERR(page)) {
                kmap(page);
                /* Note: Called with "O" and "PAGE_SIZE" this is essentially
                 * a no-op for most filesystems, because we write the whole
                 * page.  For partial-page I/O this will read in the page.
                 */
                rc = mapping->a_ops->prepare_write(NULL, page, 0, PAGE_SIZE);
                if (rc) {
                        CERROR("page index %lu, rc = %d\n", index, rc);
                        if (rc != -ENOSPC)
                                LBUG();
                        GOTO(err_unlock, rc);
                }
                /* XXX not sure if we need this if we are overwriting page */
                if (PageError(page)) {
                        CERROR("error on page index %lu, rc = %d\n", index, rc);
                        LBUG();
                        GOTO(err_unlock, rc = -EIO);
                }
        }
        return page;

err_unlock:
        unlock_page(page);
        lustre_put_page(page);
        return ERR_PTR(rc);
}

static int lustre_commit_write(struct page *page, unsigned from, unsigned to)
{
        struct inode *inode = page->mapping->host;
        int err;

        err = page->mapping->a_ops->commit_write(NULL, page, from, to);
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (!err && IS_SYNC(inode))
                err = waitfor_one_page(page);
#else
#warning ADD 2.5 waiting code here?
#endif
        //SetPageUptodate(page); // the client commit_write will do this

        SetPageReferenced(page);
        unlock_page(page);
        lustre_put_page(page);
        return err;
}

struct page *filter_get_page_write(struct inode *inode,
                                   struct niobuf_remote *rnb,
                                   struct niobuf_local *lnb, int *pglocked)
{
        unsigned long index = rnb->offset >> PAGE_SHIFT;
        struct address_space *mapping = inode->i_mapping;

        struct page *page;
        int rc;

        //ASSERT_PAGE_INDEX(index, GOTO(err, rc = -EINVAL));
        if (*pglocked)
                page = grab_cache_page_nowait(mapping, index); /* locked page */
        else
                page = grab_cache_page(mapping, index); /* locked page */


        /* This page is currently locked, so get a temporary page instead. */
        /* XXX I believe this is a very dangerous thing to do - consider if
         *     we had multiple writers for the same file (definitely the case
         *     if we are using this codepath).  If writer A locks the page,
         *     writer B writes to a copy (as here), writer A drops the page
         *     lock, and writer C grabs the lock before B does, then B will
         *     later overwrite the data from C, even if C had LDLM locked
         *     and initiated the write after B did.
         */
        if (!page) {
                unsigned long addr;
                CDEBUG(D_PAGE, "ino %ld page %ld locked\n", inode->i_ino,index);
                addr = __get_free_pages(GFP_KERNEL, 0); /* locked page */
                if (!addr) {
                        CERROR("no memory for a temp page\n");
                        LBUG();
                        GOTO(err, rc = -ENOMEM);
                }
                /* XXX debugging */
                memset((void *)addr, 0xBA, PAGE_SIZE);
                page = virt_to_page(addr);
                kmap(page);
                page->index = index;
                lnb->flags |= N_LOCAL_TEMP_PAGE;
        } else if (!IS_ERR(page)) {
                (*pglocked)++;
                kmap(page);

                rc = mapping->a_ops->prepare_write(NULL, page,
                                                   rnb->offset % PAGE_SIZE,
                                                   rnb->len);
                if (rc) {
                        CERROR("page index %lu, rc = %d\n", index, rc);
                        if (rc != -ENOSPC)
                                LBUG();
                        GOTO(err_unlock, rc);
                }
                /* XXX not sure if we need this if we are overwriting page */
                if (PageError(page)) {
                        CERROR("error on page index %lu, rc = %d\n", index, rc);
                        LBUG();
                        GOTO(err_unlock, rc = -EIO);
                }
        }
        return page;

err_unlock:
        unlock_page(page);
        lustre_put_page(page);
err:
        return ERR_PTR(rc);
}

/*
 * We need to balance prepare_write() calls with commit_write() calls.
 * If the page has been prepared, but we have no data for it, we don't
 * want to overwrite valid data on disk, but we still need to zero out
 * data for space which was newly allocated.  Like part of what happens
 * in __block_prepare_write() for newly allocated blocks.
 *
 * XXX currently __block_prepare_write() creates buffers for all the
 *     pages, and the filesystems mark these buffers as BH_New if they
 *     were newly allocated from disk. We use the BH_New flag similarly.
 */
static int filter_commit_write(struct page *page, unsigned from, unsigned to,
                               int err)
{
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        if (err) {
                unsigned block_start, block_end;
                struct buffer_head *bh, *head = page->buffers;
                unsigned blocksize = head->b_size;
                void *addr = page_address(page);

                /* debugging: just seeing if this ever happens */
                CERROR("called filter_commit_write for obj %ld:%ld on err %d\n",
                       page->index, page->mapping->host->i_ino, err);

                /* Currently one buffer per page, but in the future... */
                for (bh = head, block_start = 0; bh != head || !block_start;
                     block_start = block_end, bh = bh->b_this_page) {
                        block_end = block_start + blocksize;
                        if (buffer_new(bh))
                                memset(addr + block_start, 0, blocksize);
                }
        }
#endif
        return lustre_commit_write(page, from, to);
}

static int filter_preprw(int cmd, struct lustre_handle *conn,
                         int objcount, struct obd_ioobj *obj,
                         int niocount, struct niobuf_remote *nb,
                         struct niobuf_local *res, void **desc_private)
{
        struct obd_run_ctxt saved;
        struct obd_device *obd;
        struct obd_ioobj *o = obj;
        struct niobuf_remote *rnb = nb;
        struct niobuf_local *lnb = res;
        void *journal_save = NULL;
        int pglocked = 0;
        int rc = 0;
        int i;
        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
                CDEBUG(D_IOCTL, "invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }
        memset(res, 0, sizeof(*res) * niocount);

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);

        if (cmd & OBD_BRW_WRITE) {
                *desc_private = filter_journal_start(&journal_save,
                                                     &obd->u.filter,
                                                     objcount, obj, niocount,
                                                     nb);
                if (IS_ERR(*desc_private))
                        GOTO(out_ctxt, rc = PTR_ERR(*desc_private));
        }

        for (i = 0; i < objcount; i++, o++) {
                struct dentry *dentry;
                struct inode *inode;
                int j;

                dentry = filter_fid2dentry(obd, filter_parent(obd, S_IFREG),
                                           o->ioo_id, S_IFREG);
                if (IS_ERR(dentry))
                        GOTO(out_clean, rc = PTR_ERR(dentry));
                inode = dentry->d_inode;
                if (!inode) {
                        CERROR("trying to BRW to non-existent file "LPU64"\n",
                               o->ioo_id);
                        f_dput(dentry);
                        GOTO(out_clean, rc = -ENOENT);
                }

                for (j = 0; j < o->ioo_bufcnt; j++, rnb++, lnb++) {
                        struct page *page;

                        if (j == 0)
                                lnb->dentry = dentry;
                        else
                                lnb->dentry = dget(dentry);

                        if (cmd & OBD_BRW_WRITE)
                                page = filter_get_page_write(inode, rnb, lnb,
                                                             &pglocked);
                        else
                                page = lustre_get_page_read(inode, rnb);

                        if (IS_ERR(page)) {
                                f_dput(dentry);
                                GOTO(out_clean, rc = PTR_ERR(page));
                        }

                        lnb->addr = page_address(page);
                        lnb->offset = rnb->offset;
                        lnb->page = page;
                        lnb->len = rnb->len;
                }
        }

out_stop:
        if (cmd & OBD_BRW_WRITE) {
                int err = filter_journal_stop(journal_save, &obd->u.filter,
                                              *desc_private);
                if (!rc)
                        rc = err;
        }
out_ctxt:
        pop_ctxt(&saved);
        RETURN(rc);
out_clean:
        while (lnb-- > res) {
                CERROR("error cleanup on brw\n");
                f_dput(lnb->dentry);
                if (cmd & OBD_BRW_WRITE)
                        filter_commit_write(lnb->page, 0, PAGE_SIZE, rc);
                else
                        lustre_put_page(lnb->page);
        }
        goto out_stop;
}

static int filter_write_locked_page(struct niobuf_local *lnb)
{
        struct page *lpage;
        int rc;

        lpage = lustre_get_page_write(lnb->dentry->d_inode, lnb->page->index);
        if (IS_ERR(lpage)) {
                /* It is highly unlikely that we would ever get an error here.
                 * The page we want to get was previously locked, so it had to
                 * have already allocated the space, and we were just writing
                 * over the same data, so there would be no hole in the file.
                 *
                 * XXX: possibility of a race with truncate could exist, need
                 *      to check that.  There are no guarantees w.r.t.
                 *      write order even on a local filesystem, although the
                 *      normal response would be to return the number of bytes
                 *      successfully written and leave the rest to the app.
                 */
                rc = PTR_ERR(lpage);
                CERROR("error getting locked page index %ld: rc = %d\n",
                       lnb->page->index, rc);
                GOTO(out, rc);
        }

        /* lpage is kmapped in lustre_get_page_write() above and kunmapped in
         * lustre_commit_write() below, lnb->page was kmapped previously in
         * filter_get_page_write() and kunmapped in lustre_put_page() below.
         */
        memcpy(page_address(lpage), page_address(lnb->page), PAGE_SIZE);
        rc = lustre_commit_write(lpage, 0, PAGE_SIZE);
        if (rc)
                CERROR("error committing locked page %ld: rc = %d\n",
                       lnb->page->index, rc);
out:
        lustre_put_page(lnb->page);

        return rc;
}

static int filter_commitrw(int cmd, struct lustre_handle *conn,
                           int objcount, struct obd_ioobj *obj,
                           int niocount, struct niobuf_local *res,
                           void *private)
{
        struct obd_run_ctxt saved;
        struct obd_ioobj *o;
        struct niobuf_local *r;
        struct obd_device *obd = class_conn2obd(conn);
        void *journal_save;
        int found_locked = 0;
        int rc = 0;
        int i;
        ENTRY;

        push_ctxt(&saved, &obd->u.filter.fo_ctxt, NULL);
        lock_kernel();
        journal_save = current->journal_info;
        LASSERT(!journal_save);

        current->journal_info = private;
        unlock_kernel();
        for (i = 0, o = obj, r = res; i < objcount; i++, o++) {
                int j;
                for (j = 0 ; j < o->ioo_bufcnt ; j++, r++) {
                        struct page *page = r->page;

                        if (!page)
                                LBUG();

                        if (r->flags & N_LOCAL_TEMP_PAGE) {
                                found_locked++;
                                continue;
                        }

                        if (cmd & OBD_BRW_WRITE) {
                                int err = filter_commit_write(page, 0,
                                                              r->len, 0);

                                if (!rc)
                                        rc = err;
                        } else
                                lustre_put_page(page);

                        f_dput(r->dentry);
                }
        }
        lock_kernel();
        current->journal_info = journal_save;
        unlock_kernel();

        if (!found_locked)
                goto out_ctxt;

        for (i = 0, o = obj, r = res; i < objcount; i++, o++) {
                int j;
                for (j = 0 ; j < o->ioo_bufcnt ; j++, r++) {
                        int err;
                        if (!(r->flags & N_LOCAL_TEMP_PAGE))
                                continue;

                        err = filter_write_locked_page(r);
                        if (!rc)
                                rc = err;
                        f_dput(r->dentry);
                }
        }

out_ctxt:
        pop_ctxt(&saved);
        RETURN(rc);
}

static int filter_statfs(struct lustre_handle *conn, struct obd_statfs *osfs)
{
        struct obd_device *obd = class_conn2obd(conn);
        struct statfs sfs;
        int rc;

        ENTRY;
        rc = vfs_statfs(obd->u.filter.fo_sb, &sfs);
        if (!rc)
                statfs_pack(osfs, &sfs);

        return rc;
}

static int filter_get_info(struct lustre_handle *conn, obd_count keylen,
                           void *key, obd_count *vallen, void **val)
{
        struct obd_device *obd;
        ENTRY;

        obd = class_conn2obd(conn);
        if (!obd) {
                CDEBUG(D_IOCTL, "invalid client "LPX64"\n", conn->addr);
                RETURN(-EINVAL);
        }

        if ( keylen == strlen("blocksize") &&
             memcmp(key, "blocksize", keylen) == 0 ) {
                *vallen = sizeof(long);
                *val = (void *)(long)obd->u.filter.fo_sb->s_blocksize;
                RETURN(0);
        }

        if ( keylen == strlen("blocksize_bits") &&
             memcmp(key, "blocksize_bits", keylen) == 0 ){
                *vallen = sizeof(long);
                *val = (void *)(long)obd->u.filter.fo_sb->s_blocksize_bits;
                RETURN(0);
        }

        if ( keylen == strlen("root_ino") &&
             memcmp(key, "root_ino", keylen) == 0 ){
                *vallen = sizeof(obd_id);
                *val = (void *)(obd_id)FILTER_ROOTINO;
                RETURN(0);
        }

        CDEBUG(D_IOCTL, "invalid key\n");
        RETURN(-EINVAL);
}

int filter_copy_data(struct lustre_handle *dst_conn, struct obdo *dst,
                  struct lustre_handle *src_conn, struct obdo *src,
                  obd_size count, obd_off offset)
{
        struct page *page;
        struct lov_stripe_md srcmd, dstmd;
        unsigned long index = 0;
        int err = 0;

        memset(&srcmd, 0, sizeof(srcmd));
        memset(&dstmd, 0, sizeof(dstmd));
        srcmd.lsm_object_id = src->o_id;
        dstmd.lsm_object_id = dst->o_id;

        ENTRY;
        CDEBUG(D_INFO, "src: ino "LPU64" blocks "LPU64", size "LPU64
               ", dst: ino "LPU64"\n",
               src->o_id, src->o_blocks, src->o_size, dst->o_id);
        page = alloc_page(GFP_USER);
        if (page == NULL)
                RETURN(-ENOMEM);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
        while (TryLockPage(page))
                ___wait_on_page(page);
#else
        wait_on_page_locked(page);
#endif

        /* XXX with brw vector I/O, we could batch up reads and writes here,
         *     all we need to do is allocate multiple pages to handle the I/Os
         *     and arrays to handle the request parameters.
         */
        while (index < ((src->o_size + PAGE_SIZE - 1) >> PAGE_SHIFT)) {
                struct brw_page pg;
                struct io_cb_data *cbd = ll_init_cb();

                if (!cbd) {
                        err = -ENOMEM;
                        EXIT;
                        break;
                }

                pg.pg = page;
                pg.count = PAGE_SIZE;
                pg.off = (page->index) << PAGE_SHIFT;
                pg.flag = 0;

                page->index = index;
                err = obd_brw(OBD_BRW_READ, src_conn, &srcmd, 1, &pg,
                              ll_sync_io_cb, cbd);

                if ( err ) {
                        EXIT;
                        break;
                }

                cbd = ll_init_cb();
                if (!cbd) {
                        err = -ENOMEM;
                        EXIT;
                        break;
                }
                pg.flag = OBD_BRW_CREATE;
                CDEBUG(D_INFO, "Read page %ld ...\n", page->index);

                err = obd_brw(OBD_BRW_WRITE, dst_conn, &dstmd, 1, &pg,
                              ll_sync_io_cb, cbd);

                /* XXX should handle dst->o_size, dst->o_blocks here */
                if ( err ) {
                        EXIT;
                        break;
                }

                CDEBUG(D_INFO, "Wrote page %ld ...\n", page->index);

                index++;
        }
        dst->o_size = src->o_size;
        dst->o_blocks = src->o_blocks;
        dst->o_valid |= OBD_MD_FLSIZE | OBD_MD_FLBLOCKS;
        unlock_page(page);
        __free_page(page);

        RETURN(err);
}


static struct obd_ops filter_obd_ops = {
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
        o_brw:         filter_pgcache_brw,
        o_punch:       filter_truncate,
        o_preprw:      filter_preprw,
        o_commitrw:    filter_commitrw
#if 0
        o_preallocate: filter_preallocate_inodes,
        o_migrate:     filter_migrate,
        o_copy:        filter_copy_data,
        o_iterate:     filter_iterate
#endif
};


static int __init obdfilter_init(void)
{
        printk(KERN_INFO "Filtering OBD driver  v0.001, info@clusterfs.com\n");
        filter_open_cache = kmem_cache_create("ll_filter_fdata",
                                              sizeof(struct filter_file_data),
                                              0, 0, NULL, NULL);
        if (!filter_open_cache)
                RETURN(-ENOMEM);

        filter_dentry_cache = kmem_cache_create("ll_filter_dentry",
                                        sizeof(struct filter_dentry_data),
                                        0, 0, NULL, NULL);
        if (!filter_dentry_cache) {
                kmem_cache_destroy(filter_open_cache);
                RETURN(-ENOMEM);
        }

        return class_register_type(&filter_obd_ops, OBD_FILTER_DEVICENAME);
}

static void __exit obdfilter_exit(void)
{
        class_unregister_type(OBD_FILTER_DEVICENAME);
        if (kmem_cache_destroy(filter_dentry_cache))
                CERROR("couldn't free obdfilter dentry cache\n");
        if (kmem_cache_destroy(filter_open_cache))
                CERROR("couldn't free obdfilter open cache\n");
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Lustre Filtering OBD driver v1.0");
MODULE_LICENSE("GPL");

module_init(obdfilter_init);
module_exit(obdfilter_exit);
