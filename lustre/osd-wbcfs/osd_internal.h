/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025-2026, DDN/Whamcloud, Inc.
 */

/*
 * Author: Yingjin Qian <qian@ddn.com>
 */

#ifndef _OSD_INTERNAL_H
#define _OSD_INTERNAL_H

#include <linux/rwsem.h>
#include <linux/dcache.h>
#include <linux/dirent.h>
#include <linux/statfs.h>
#include <linux/file.h>
#include <lustre_compat.h>

#include <obd.h>
#include <obd_class.h>
#include <dt_object.h>

struct osd_object {
	struct dt_object	 oo_dt;
	/*
	 * Inode in the memory FS for file system object represented by this
	 * osd_object. This inode is pinned for the whole duration of the file
	 * life.
	 */
	struct inode		*oo_inode;
	/* Used to implement osd_{read|write}_{lock|unlock}. */
	struct rw_semaphore	 oo_sem;
	/* protects inode attributes. */
	spinlock_t		 oo_guard;
	/* the i_flags in LMA */
	__u32			 oo_lma_flags;
	__u32			 oo_destroyed:1;
	struct lu_object_header	*oo_header;
};

struct osd_device {
	/* Super-class */
	struct dt_device	 od_dt_dev;
	/* Information about underlying memory file system */
	struct vfsmount		*od_mnt;
	/* Service name associated with the OSD device. */
	char			 od_svname[MAX_OBD_NAME];
	char			 od_mntdev[MAX_OBD_NAME];
	int			 od_index;
	atomic_t		 od_connects;
	struct lu_site		 od_site;
	/*
	 * Enable to write back the data in the memory FS into the
	 * persistent storage.
	 */
	unsigned int		 od_writeback_enabled:1;
	unsigned int		 od_is_ost:1;
};

struct osd_thandle {
	struct thandle		ot_super;
	struct list_head	ot_commit_dcb_list;
	struct list_head	ot_stop_dcb_list;
};

struct osd_it_dirent {
	struct lu_fid	oitd_fid;
	__u64           oitd_ino;
	__u64           oitd_off;
	unsigned short  oitd_namelen;
	unsigned int    oitd_type;
	char            oitd_name[];
} __attribute__((packed));

/*
 * As @osd_it_dirent (in memory dirent struct for osd) is greater
 * than lu_dirent struct. osd readdir reads less number of dirent than
 * required for mdd dir page. so buffer size need to be increased so that
 * there would be one MemFS readdir for every mdd readdir page.
 */

#define OSD_IT_BUFSIZE       (PAGE_SIZE + PAGE_SIZE/4)

struct osd_it {
	struct osd_object	*oit_obj;
	struct file		 oit_file;
	/* How many entries have been read-cached from storage */
	int			 oit_rd_dirent;
	/* Current entry is being iterated by caller */
	int			 oit_it_dirent;
	/* Current processing entry */
	struct osd_it_dirent	*oit_dirent;
	/* Buffer to hold entries, size == OSD_IT_BUFSIZE */
	void			*oit_buf;
};

extern atomic_t descriptors_cnt;
extern unsigned int wbcfs_flush_descriptors_cnt;
extern struct work_struct flush_fput;
#define osd_alloc_file_pseudo(inode, mnt, name, flags, fops)		\
({									\
	struct file *__f;						\
	int __descriptors_cnt;						\
	__f = alloc_file_pseudo(inode, mnt, name, flags, fops);		\
	__descriptors_cnt = atomic_inc_return(&descriptors_cnt);	\
	if (unlikely(__descriptors_cnt >= wbcfs_flush_descriptors_cnt)) {\
		/* drop here to skip queue_work */			\
		atomic_set(&descriptors_cnt, 0);			\
		queue_work(system_long_wq, &flush_fput);		\
	}								\
	__f;								\
})

/* Slab to allocate osd_it */
extern struct kmem_cache *osd_it_cachep;

struct osd_hash_it {
	struct list_head	*hit_cursor;
	struct osd_object	*hit_obj;
};

extern struct kmem_cache *osd_hash_it_cachep;

extern const struct dt_body_operations osd_body_ops;
extern const struct dt_object_operations osd_obj_ops;
extern const struct lu_object_operations osd_lu_obj_ops;
extern const struct lu_device_operations osd_lu_ops;
extern const struct dt_index_operations osd_dir_ops;
extern const struct dt_index_operations osd_hash_index_ops;

static inline int lu_device_is_osd(const struct lu_device *d)
{
	return ergo(d != NULL && d->ld_ops != NULL, d->ld_ops == &osd_lu_ops);
}

static inline struct osd_device *osd_dt_dev(const struct dt_device *d)
{
	LASSERT(lu_device_is_osd(&d->dd_lu_dev));
	return container_of(d, struct osd_device, od_dt_dev);
}

static inline struct osd_device *osd_dev(const struct lu_device *d)
{
	LASSERT(lu_device_is_osd(d));
	return osd_dt_dev(container_of(d, struct dt_device, dd_lu_dev));
}

static inline struct osd_device *osd_obj2dev(const struct osd_object *o)
{
	return osd_dev(o->oo_dt.do_lu.lo_dev);
}

static inline struct super_block *osd_sb(const struct osd_device *dev)
{
	if (!dev->od_mnt)
		return NULL;

	return dev->od_mnt->mnt_sb;
}

static inline char *osd_name(struct osd_device *osd)
{
	return osd->od_svname;
}

static inline struct lu_device *osd2lu_dev(struct osd_device *osd)
{
	return &osd->od_dt_dev.dd_lu_dev;
}

static inline struct osd_object *osd_obj(const struct lu_object *o)
{
	LASSERT(lu_device_is_osd(o->lo_dev));
	return container_of(o, struct osd_object, oo_dt.do_lu);
}

/*
 * Put the osd object once done with it.
 *
 * \param obj osd object that needs to be put
 */
static inline void osd_object_put(const struct lu_env *env,
				  struct osd_object *obj)
{
	dt_object_put(env, &obj->oo_dt);
}

static inline struct osd_object *osd_dt_obj(const struct dt_object *d)
{
	return osd_obj(&d->do_lu);
}

#if defined HAVE_INODE_TIMESPEC64 || defined HAVE_INODE_GET_MTIME_SEC
#define osd_timespec			timespec64
#else
#define osd_timespec			timespec
#endif

static inline struct osd_timespec osd_inode_time(struct inode *inode,
						 s64 seconds)
{
	struct osd_timespec ts = { .tv_sec = seconds };

	return ts;
}

#ifdef HAVE_FILLDIR_USE_CTX_RETURN_BOOL
#define WRAP_FILLDIR_FN(prefix, fill_fn) \
static bool fill_fn(struct dir_context *buf, const char *name, int namelen, \
		    loff_t offset, __u64 ino, unsigned int d_type)	    \
{									    \
	return !prefix##fill_fn(buf, name, namelen, offset, ino, d_type);   \
}
#elif defined(HAVE_FILLDIR_USE_CTX)
#define WRAP_FILLDIR_FN(prefix, fill_fn) \
static int fill_fn(struct dir_context *buf, const char *name, int namelen,  \
		   loff_t offset, __u64 ino, unsigned int d_type)	    \
{									    \
	return prefix##fill_fn(buf, name, namelen, offset, ino, d_type);    \
}
#else
#define WRAP_FILLDIR_FN(prefix, fill_fn)
#endif

/*
 * Build inode number from passed @fid.
 *
 * For 32-bit systems or syscalls limit the inode number to a 32-bit value
 * to avoid EOVERFLOW errors.  This will inevitably result in inode number
 * collisions, but fid_flatten32() tries hard to avoid this if possible.
 */
static inline __u64 lu_fid_build_ino(const struct lu_fid *fid, int api32)
{
	if (BITS_PER_LONG == 32 || api32)
		RETURN(fid_flatten32(fid));

	RETURN(fid_flatten64(fid));
}

/*
 * Build inode generation from passed @fid.  If our FID overflows the 32-bit
 * inode number then return a non-zero generation to distinguish them.
 */
static inline __u32 lu_fid_build_gen(const struct lu_fid *fid)
{
	if (fid_is_igif(fid))
		RETURN(lu_igif_gen(fid));

	RETURN(fid_flatten64(fid) >> 32);
}

#endif /* _OSD_INTERNAL_H */
