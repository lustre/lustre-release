/*
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
#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_ext2.h>

extern struct obd_device obd_dev[MAX_OBD_DEVICES];
long filter_memory;

#define FILTER_ROOTINO 2

#define S_SHIFT 12

static char * obd_type_by_mode[S_IFMT >> S_SHIFT] = {
	[0]                     "",
	[S_IFREG >> S_SHIFT]	"R", 
	[S_IFDIR >> S_SHIFT]	"D",
	[S_IFCHR >> S_SHIFT]	"C",
	[S_IFBLK >> S_SHIFT]	"B", 
	[S_IFIFO >> S_SHIFT]	"F", 
	[S_IFSOCK >> S_SHIFT]	"S",
	[S_IFLNK >> S_SHIFT]	"L"
};

static void filter_id(char *buf, obd_id id, obd_mode mode)
{
	sprintf(buf, "O/%s/%Ld", 
		obd_type_by_mode[(mode & S_IFMT) >> S_SHIFT],
		id);
}

void push_ctxt(struct run_ctxt *save, struct run_ctxt *new)
{ 
	save->fs = get_fs();
	save->pwd = dget(current->fs->pwd);
	save->pwdmnt = mntget(current->fs->pwdmnt);

	set_fs(new->fs);
	set_fs_pwd(current->fs, new->pwdmnt, new->pwd);
}

void pop_ctxt(struct run_ctxt *saved)
{
	set_fs(saved->fs);
	set_fs_pwd(current->fs, saved->pwdmnt, saved->pwd);

	dput(saved->pwd);
	mntput(saved->pwdmnt);
}

static void filter_prep(struct obd_device *obddev)
{
	struct run_ctxt saved;
	struct file *file;
	struct inode *inode;
	long rc;
	int fd;
	char rootid[128];
	struct stat64 buf;
	__u64 lastino = 2;

	push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
	rc = sys_mkdir("O", 0700);
	rc = sys_mkdir("P", 0700);
	rc = sys_mkdir("D", 0700);
	rc = sys_mkdir("O/R", 0700);  /* regular */
	rc = sys_mkdir("O/D", 0700);  /* directory */
	rc = sys_mkdir("O/L", 0700);  /* symbolic links */
	rc = sys_mkdir("O/C", 0700);  /* character devices */
	rc = sys_mkdir("O/B", 0700);  /* block devices */
	rc = sys_mkdir("O/F", 0700);  /* fifo's */
	rc = sys_mkdir("O/S", 0700);  /* sockets */
	
	filter_id(rootid, FILTER_ROOTINO, S_IFDIR);
	file = filp_open(rootid, O_RDWR | O_CREAT, 00755);
	if (IS_ERR(file)) {
		printk("OBD filter: cannot make root directory"); 
		goto out;
	}
	filp_close(file, 0);
	rc = sys_mkdir(rootid, 0755);
	if ( (fd = sys_open("D/status", O_RDWR | O_CREAT, 0700)) == -1 ) {
		printk("OBD filter: cannot create status file\n");
		goto out;
	}
	if ( (rc = sys_fstat64(fd, &buf, 0)) ) { 
		printk("OBD filter: cannot stat status file\n");
		goto out_close;
	}
	if (buf.st_size == 0) { 
		rc = sys_write(fd, (char *)&lastino, sizeof(lastino));
		if (rc != sizeof(lastino)) { 
			printk("OBD filter: error writing lastino\n");
			goto out_close;
		}
	} else { 
		rc = sys_read(fd, (char *)&lastino, sizeof(lastino));
		if (rc != sizeof(lastino)) { 
			printk("OBD filter: error reading lastino\n");
			goto out_close;
		}
	}
	obddev->u.filter.fo_lastino = lastino;

	/* this is also the moment to steal operations */
	file = filp_open("D/status", O_RDONLY | O_LARGEFILE, 0);
	if (!file || IS_ERR(file)) { 
		EXIT;
		goto out_close;
	}
	inode = file->f_dentry->d_inode;
	obddev->u.filter.fo_fop = file->f_op;
	obddev->u.filter.fo_iop = inode->i_op;
	obddev->u.filter.fo_aops = inode->i_mapping->a_ops;
	filp_close(file, 0);
	
 out_close:
	rc = sys_close(fd);
	if (rc) { 
		printk("OBD filter: cannot close status file\n");
	}
 out:
	pop_ctxt(&saved);
}

static void filter_post(struct obd_device *obddev)
{
	struct run_ctxt saved;
	long rc;
	int fd;

	push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
	if ( (fd = sys_open("D/status", O_RDWR | O_CREAT, 0700)) == -1 ) {
		printk("OBD filter: cannot create status file\n");
		goto out;
	}
	rc = sys_write(fd, (char *)&obddev->u.filter.fo_lastino, 
		       sizeof(obddev->u.filter.fo_lastino));
	if (rc != sizeof(sizeof(obddev->u.filter.fo_lastino)) ) { 
		printk("OBD filter: error writing lastino\n");
	}

	rc = sys_close(fd);
	if (rc) { 
		printk("OBD filter: cannot close status file\n");
	}
 out:
	pop_ctxt(&saved);
}


/* release per client resources */
static int filter_disconnect(struct obd_conn *conn)
{
	/* XXX cleanup preallocated inodes */
	return gen_disconnect(conn);
} /* ext2obd_disconnect */

/* mount the file system (secretly) */
static int filter_setup(struct obd_device *obddev, obd_count len,
			void *buf)
			
{
	struct obd_ioctl_data* data = buf;
	struct vfsmount *mnt;
	int err; 
        ENTRY;
        
	
	mnt = do_kern_mount(data->ioc_inlbuf2, 0, 
			    data->ioc_inlbuf1, NULL); 
	err = PTR_ERR(mnt);
	if (IS_ERR(mnt)) { 
		EXIT;
		return err;
	}

	obddev->u.filter.fo_sb = mnt->mnt_root->d_inode->i_sb;
  	if (!obddev->u.filter.fo_sb) {
  		EXIT;
  		return -ENODEV;
  	}

	obddev->u.filter.fo_vfsmnt = mnt;
	obddev->u.filter.fo_fstype = strdup(data->ioc_inlbuf2);

	obddev->u.filter.fo_ctxt.pwdmnt = mnt;
	obddev->u.filter.fo_ctxt.pwd = mnt->mnt_root;
	obddev->u.filter.fo_ctxt.fs = KERNEL_DS;

	filter_prep(obddev);
	spin_lock_init(&obddev->u.filter.fo_lock);

        MOD_INC_USE_COUNT;
        EXIT; 
        return 0;
} 

static __u64 filter_next_id(struct obd_device *obddev) 
{
	__u64 id;
	spin_lock(&obddev->u.filter.fo_lock);
	obddev->u.filter.fo_lastino++;
	id = 	obddev->u.filter.fo_lastino;
	spin_unlock(&obddev->u.filter.fo_lock);
	return id;
}

static int filter_cleanup(struct obd_device * obddev)
{
        struct super_block *sb;

        ENTRY;

        if ( !(obddev->obd_flags & OBD_SET_UP) ) {
                EXIT;
                return 0;
        }

        if ( !list_empty(&obddev->obd_gen_clients) ) {
                printk(KERN_WARNING __FUNCTION__ ": still has clients!\n");
                EXIT;
                return -EBUSY;
        }

        sb = obddev->u.filter.fo_sb;
        if (!obddev->u.filter.fo_sb){
                EXIT;
                return 0;
        }
	filter_post(obddev);

	unlock_kernel();
	mntput(obddev->u.filter.fo_vfsmnt); 
        obddev->u.filter.fo_sb = 0;
	kfree(obddev->u.filter.fo_fstype);

	lock_kernel();

        MOD_DEC_USE_COUNT;
        EXIT;
        return 0;
}


static struct file *filter_obj_open(struct obd_device *obddev, 
				     struct obdo *oa)
{
	struct file *file;
	int error = 0;
	char id[24];
	struct run_ctxt saved;
	struct super_block *sb;

	sb = obddev->u.filter.fo_sb;
        if (!sb || !sb->s_dev) {
                CDEBUG(D_SUPER, "fatal: device not initialized.\n");
                EXIT;
                return NULL;
        }

        if ( !oa->o_id ) {
                CDEBUG(D_INODE, "fatal: invalid obdo %lu\n", (long)oa->o_id);
                EXIT;
                return NULL;
        }

	if ( ! (oa->o_mode & S_IFMT) ) { 
		printk("OBD filter_obj_open, no type (%Ld), mode %o!\n", 
		       oa->o_id, oa->o_mode);
	}
	filter_id(id, oa->o_id, oa->o_mode); 
	push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
	file = filp_open(id , O_RDONLY | O_LARGEFILE, 0);
	pop_ctxt(&saved);

	if (IS_ERR(file)) { 
		error = PTR_ERR(file);
		file = NULL;
	}
	CDEBUG(D_INODE, "opening obdo %s\n", id);

	return file;
}

static struct inode *filter_inode_from_obdo(struct obd_device *obddev, 
				     struct obdo *oa)
{
	struct file *file;
	struct inode *inode; 

	file = filter_obj_open(obddev, oa);
	if ( !file ) { 
		printk("filter_inode_from_obdo failed\n"); 
		return NULL;
	}

        inode = iget(file->f_dentry->d_inode->i_sb, file->f_dentry->d_inode->i_ino); 
	filp_close(file, 0);
	return inode;
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
 else if (ext2obd_has_inline(inode)) {
                CDEBUG(D_INFO, "copying inline from inode to obdo\n");
                memcpy(oa->o_inline, inode->u.ext2_i.i_data,
                       MIN(sizeof(inode->u.ext2_i.i_data),OBD_INLINESZ));
                oa->o_obdflags |= OBD_FL_INLINEDATA;
                oa->o_valid |= OBD_MD_FLINLINE;
        }

        if (ext2obd_has_obdmd(inode)) {
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

	if ( !(inode = filter_inode_from_obdo(conn->oc_dev, oa)) ) { 
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

	inode = filter_inode_from_obdo(conn->oc_dev, oa); 
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

static int filter_create (struct obd_conn* conn, struct obdo *oa)
{
	char name[64];
	struct run_ctxt saved;
	struct file *file;
	int mode;
	struct obd_device *obddev = conn->oc_dev;
	struct iattr;
	ENTRY;

        if (!gen_client(conn)) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                return -EINVAL;
        }
	CDEBUG(D_IOCTL, "\n");

	oa->o_id = filter_next_id(conn->oc_dev);
	if ( !(oa->o_mode && S_IFMT) ) { 
		printk("filter obd: no type!\n");
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
		printk("Error mknod obj %s, err %ld\n", name, PTR_ERR(file));
		return -ENOENT;
	}
	filp_close(file, 0);
	CDEBUG(D_IOCTL, "\n");
	
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
	struct run_ctxt saved;
	char id[128];

        if (!(cli = gen_client(conn))) {
                CDEBUG(D_IOCTL, "invalid client %u\n", conn->oc_id);
                EXIT;
                return -EINVAL;
        }

        obddev = conn->oc_dev;
	inode = filter_inode_from_obdo(obddev, oa);

	if (!inode) { 
		EXIT;
		return -ENOENT;
	}

        inode->i_nlink = 1;
	inode->i_mode = 010000;
	iput(inode);

	filter_id(id, oa->o_id, oa->o_mode);
	push_ctxt(&saved, &obddev->u.filter.fo_ctxt);
	if (sys_unlink(id)) { 
		EXIT;
		pop_ctxt(&saved);
		return -EPERM;
	}
	pop_ctxt(&saved);

	EXIT;
        return 0;
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

	file = filter_obj_open(conn->oc_dev, oa); 
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
} /* ext2obd_read */


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

	file = filter_obj_open(conn->oc_dev, oa); 
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
} /* ext2obd_write */

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

		file = filter_obj_open(conn->oc_dev, oa[onum]); 
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
} /* ext2obd_statfs */


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
        o_connect:     gen_connect,
        o_disconnect:  filter_disconnect,
        o_statfs:      filter_statfs,
        o_getattr:     filter_getattr,
        o_create:      filter_create,
	o_setattr:     filter_setattr,
        o_destroy:     filter_destroy,
        o_read:        filter_read,
        o_write:       filter_write,
	o_brw:         filter_pgcache_brw,
        o_punch:       filter_truncate,
#if 0
        o_preallocate: ext2obd_preallocate_inodes,
        o_migrate:     ext2obd_migrate,
        o_copy:        gen_copy_data,
        o_iterate:     ext2obd_iterate
#endif
};


#ifdef MODULE

void init_module(void)
{
        printk(KERN_INFO "Filtering OBD driver  v0.001, braam@clusterfs.com\n");
        obd_register_type(&filter_obd_ops, OBD_FILTER_DEVICENAME);
}

void cleanup_module(void)
{
        obd_unregister_type(OBD_FILTER_DEVICENAME);
        CDEBUG(D_MALLOC, "FILTER mem used %ld\n", filter_memory);
}

#endif
