#ifndef __LINUX_CLASS_OBD_H
#define __LINUX_CLASS_OBD_H
/*
 * Copyright (C) 2001  Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef __KERNEL__
#include <stdint.h>
#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__
#else 
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/time.h>

#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/obd.h>
#endif

/*
 *  ======== OBD Device Declarations ===========
 */
#define MAX_OBD_DEVICES 8
#define MAX_MULTI       16
extern struct obd_device obd_dev[MAX_OBD_DEVICES];

#define OBD_ATTACHED 0x1
#define OBD_SET_UP   0x2

struct obd_conn {
        struct obd_device *oc_dev;
        uint32_t oc_id;
};

typedef struct {
	uint32_t len;
	char *   name;
        struct dentry *dentry;   /* file system obd device names */
        __u8           _uuid[16]; /* uuid obd device names */
} obd_devicename;

#include <linux/obd_ext2.h>
#include <linux/obd_filter.h>
#include <linux/lustre_mds.h>
#include <linux/obd_snap.h>
#include <linux/obd_trace.h>
/* #include <linux/obd_fc.h> */
#include <linux/obd_raid1.h>
#include <linux/obd_ost.h>

#ifdef __KERNEL__
/* corresponds to one of the obdx */
struct obd_device {
        struct obd_type *obd_type;
        int obd_minor;
        int obd_flags;
        int obd_refcnt; 
        obd_devicename obd_fsname; 
	struct proc_dir_entry *obd_proc_entry;
        int obd_multi_count;
        struct obd_conn obd_multi_conn[MAX_MULTI];
        unsigned int obd_gen_last_id;
        unsigned long obd_gen_prealloc_quota;
        struct list_head obd_gen_clients;
        union {
                struct ext2_obd ext2;
                struct filter_obd filter;
                struct mds_obd mds;
                struct raid1_obd raid1;
                struct snap_obd snap;
	        struct trace_obd trace;
                struct ost_obd ost;
                struct osc_obd osc;
        } u;
};

extern struct proc_dir_entry *proc_lustre_register_obd_device(struct obd_device *obd);
extern void proc_lustre_release_obd_device(struct obd_device *obd);
extern void proc_lustre_remove_obd_entry(const char* name, struct obd_device *obd);

/*
 *  ======== OBD Operations Declarations ===========
 */

#define OBD_BRW_READ    (READ)
#define OBD_BRW_WRITE   (WRITE)
#define OBD_BRW_RWMASK  (READ | WRITE)
#define OBD_BRW_CREATE  (0x00000010UL)

struct obd_ops {
        int (*o_iocontrol)(int cmd, struct obd_conn *, int len, void *karg,
                           void *uarg);
        int (*o_get_info)(struct obd_conn *, obd_count keylen, void *key,
                          obd_count *vallen, void **val);
        int (*o_set_info)(struct obd_conn *, obd_count keylen, void *key,
                          obd_count vallen, void *val);
        int (*o_attach)(struct obd_device *dev, obd_count len, void *data);
        int (*o_detach)(struct obd_device *dev);
        int (*o_setup) (struct obd_device *dev, obd_count len, void *data);
        int (*o_cleanup)(struct obd_device *dev);
        int (*o_connect)(struct obd_conn *conn);
        int (*o_disconnect)(struct obd_conn *conn);
        int (*o_statfs)(struct obd_conn *conn, struct statfs *statfs);
        int (*o_preallocate)(struct obd_conn *, obd_count *req, obd_id *ids);
        int (*o_create)(struct obd_conn *conn,  struct obdo *oa);
        int (*o_destroy)(struct obd_conn *conn, struct obdo *oa);
        int (*o_setattr)(struct obd_conn *conn, struct obdo *oa);
        int (*o_getattr)(struct obd_conn *conn, struct obdo *oa);
        int (*o_read)(struct obd_conn *conn, struct obdo *oa, char *buf,
                      obd_size *count, obd_off offset);
        int (*o_write)(struct obd_conn *conn, struct obdo *oa, char *buf,
                       obd_size *count, obd_off offset);
        int (*o_brw)(int rw, struct obd_conn *conn, obd_count num_oa,
                     struct obdo **oa, obd_count *oa_bufs, struct page **buf,
                     obd_size *count, obd_off *offset, obd_flag *flags);
        int (*o_punch)(struct obd_conn *conn, struct obdo *tgt, obd_size count,
                       obd_off offset);
        int (*o_sync)(struct obd_conn *conn, struct obdo *tgt, obd_size count,
                      obd_off offset);
        int (*o_migrate)(struct obd_conn *conn, struct obdo *dst,
                         struct obdo *src, obd_size count, obd_off offset);
        int (*o_copy)(struct obd_conn *dstconn, struct obdo *dst,
                      struct obd_conn *srconn, struct obdo *src,
                      obd_size count, obd_off offset);
        int (*o_iterate)(struct obd_conn *conn, int (*)(obd_id, obd_gr, void *),
                         obd_id *startid, obd_gr group, void *data);
	int (*o_dmaread)(struct obd_conn *conn, int count, struct obd_buf **dest, 
			 struct obd_bufref **source); 
	int (*o_pre_dmawrite)(struct obd_conn *conn, int count, struct obd_buf **dstbufs, 
			 struct obd_bufref **dest); 
	int (*o_dmawrite)(struct obd_conn *conn, int count, struct obd_buf **dstbufs, 
			 struct obd_buf **dest); 
};

struct obd_request {
	struct obdo *oa;
	struct obd_conn *conn;
	__u32 plen1;
	char *pbuf1;
};




#define OBT(dev)        dev->obd_type->typ_ops
#define OBP(dev,op)     dev->obd_type->typ_ops->o_ ## op

#endif 

/* This value is not arbitrarily chosen.  KIO_STATIC_PAGES from linux/iobuf.h */
#define MAX_IOVEC       (KIO_STATIC_PAGES - 1)


/*
 *  ======== OBD Metadata Support  ===========
 */

extern int obd_init_obdo_cache(void);
extern void obd_cleanup_obdo_cache(void);


static inline int obdo_has_inline(struct obdo *obdo)
{
        return (obdo->o_valid & OBD_MD_FLINLINE &&
                obdo->o_obdflags & OBD_FL_INLINEDATA);
};

static inline int obdo_has_obdmd(struct obdo *obdo)
{
        return (obdo->o_valid & OBD_MD_FLOBDMD &&
                obdo->o_obdflags & OBD_FL_OBDMDEXISTS);
};

#ifdef __KERNEL__
/* support routines */
extern kmem_cache_t *obdo_cachep;

static __inline__ struct obdo *obdo_alloc(void)
{
        struct obdo *oa = NULL;

        oa = kmem_cache_alloc(obdo_cachep, SLAB_KERNEL);
        memset(oa, 0, sizeof (*oa));

        return oa;
}

static __inline__ void obdo_free(struct obdo *oa)
{
        if ( !oa ) 
                return;
        kmem_cache_free(obdo_cachep, oa);
}

static __inline__ struct obdo *obdo_fromid(struct obd_conn *conn, obd_id id,
					   obd_mode mode, obd_flag valid)
{
        struct obdo *oa;
        int err;

        ENTRY;
        oa = obdo_alloc();
        if ( !oa ) {
                EXIT;
                return ERR_PTR(-ENOMEM);
        }

        oa->o_id = id;
	oa->o_mode = mode;
        oa->o_valid = valid;
        if ((err = OBP(conn->oc_dev, getattr)(conn, oa))) {
                obdo_free(oa);
                EXIT;
                return ERR_PTR(err);
        }
        EXIT;
        return oa;
}

static inline void obdo_from_iattr(struct obdo *oa, struct iattr *attr)
{
        unsigned int ia_valid = attr->ia_valid;

        if (ia_valid & ATTR_ATIME) {
                oa->o_atime = attr->ia_atime;
                oa->o_valid |= OBD_MD_FLATIME;
        }
        if (ia_valid & ATTR_MTIME) {
                oa->o_mtime = attr->ia_mtime;
                oa->o_valid |= OBD_MD_FLMTIME;
        }
        if (ia_valid & ATTR_CTIME) {
                oa->o_ctime = attr->ia_ctime;
                oa->o_valid |= OBD_MD_FLCTIME;
        }
        if (ia_valid & ATTR_SIZE) {
                oa->o_size = attr->ia_size;
                oa->o_valid |= OBD_MD_FLSIZE;
        }
        if (ia_valid & ATTR_MODE) {
                oa->o_mode = attr->ia_mode;
                oa->o_valid |= OBD_MD_FLMODE;
                if (!in_group_p(oa->o_gid) && !capable(CAP_FSETID))
                        oa->o_mode &= ~S_ISGID;
        }
        if (ia_valid & ATTR_UID)
        {
                oa->o_uid = attr->ia_uid;
                oa->o_valid |= OBD_MD_FLUID;
        }
        if (ia_valid & ATTR_GID) {
                oa->o_gid = attr->ia_gid;
                oa->o_valid |= OBD_MD_FLGID;
        }
}


static inline void iattr_from_obdo(struct iattr *attr, struct obdo *oa)
{
        unsigned int ia_valid = oa->o_valid;
	
	memset(attr, 0, sizeof(*attr));
        if (ia_valid & OBD_MD_FLATIME) {
                attr->ia_atime = oa->o_atime;
                attr->ia_valid |= ATTR_ATIME;
        }
        if (ia_valid & OBD_MD_FLMTIME) {
                attr->ia_mtime = oa->o_mtime;
                attr->ia_valid |= ATTR_MTIME;
        }
        if (ia_valid & OBD_MD_FLCTIME) {
                attr->ia_ctime = oa->o_ctime;
                attr->ia_valid |= ATTR_CTIME;
        }
        if (ia_valid & OBD_MD_FLSIZE) {
                attr->ia_size = oa->o_size;
                attr->ia_valid |= ATTR_SIZE;
        }
        if (ia_valid & OBD_MD_FLMODE) {
                attr->ia_mode = oa->o_mode;
                attr->ia_valid |= ATTR_MODE;
                if (!in_group_p(oa->o_gid) && !capable(CAP_FSETID))
                        attr->ia_mode &= ~S_ISGID;
        }
        if (ia_valid & OBD_MD_FLUID)
        {
                attr->ia_uid = oa->o_uid;
                attr->ia_valid |= ATTR_UID;
        }
        if (ia_valid & OBD_MD_FLGID) {
                attr->ia_gid = oa->o_gid;
                attr->ia_valid |= ATTR_GID;
        }
}


/* WARNING: the file systems must take care not to tinker with
   attributes they don't manage (such as blocks). */

static __inline__ void obdo_from_inode(struct obdo *dst, struct inode *src)
{
        if ( dst->o_valid & OBD_MD_FLID )
                dst->o_id = src->i_ino;
        if ( dst->o_valid & OBD_MD_FLATIME )
                dst->o_atime = src->i_atime;
        if ( dst->o_valid & OBD_MD_FLMTIME )
                dst->o_mtime = src->i_mtime;
        if ( dst->o_valid & OBD_MD_FLCTIME )
                dst->o_ctime = src->i_ctime;
        if ( dst->o_valid & OBD_MD_FLSIZE )
                dst->o_size = src->i_size;
        if ( dst->o_valid & OBD_MD_FLBLOCKS )   /* allocation of space */
                dst->o_blocks = src->i_blocks;
        if ( dst->o_valid & OBD_MD_FLBLKSZ )
                dst->o_blksize = src->i_blksize;
        if ( dst->o_valid & OBD_MD_FLMODE )
                dst->o_mode = src->i_mode;
        if ( dst->o_valid & OBD_MD_FLUID )
                dst->o_uid = src->i_uid;
        if ( dst->o_valid & OBD_MD_FLGID )
                dst->o_gid = src->i_gid;
        if ( dst->o_valid & OBD_MD_FLFLAGS )
                dst->o_flags = src->i_flags;
        if ( dst->o_valid & OBD_MD_FLNLINK )
                dst->o_nlink = src->i_nlink;
        if ( dst->o_valid & OBD_MD_FLGENER ) 
                dst->o_generation = src->i_generation;
}

static __inline__ void obdo_to_inode(struct inode *dst, struct obdo *src)
{

        if ( src->o_valid & OBD_MD_FLID )
                dst->i_ino = src->o_id;
        if ( src->o_valid & OBD_MD_FLATIME ) 
                dst->i_atime = src->o_atime;
        if ( src->o_valid & OBD_MD_FLMTIME ) 
                dst->i_mtime = src->o_mtime;
        if ( src->o_valid & OBD_MD_FLCTIME ) 
                dst->i_ctime = src->o_ctime;
        if ( src->o_valid & OBD_MD_FLSIZE ) 
                dst->i_size = src->o_size;
        if ( src->o_valid & OBD_MD_FLBLOCKS ) /* allocation of space */
                dst->i_blocks = src->o_blocks;
        if ( src->o_valid & OBD_MD_FLBLKSZ )
                dst->i_blksize = src->o_blksize;
        if ( src->o_valid & OBD_MD_FLMODE ) 
                dst->i_mode = src->o_mode;
        if ( src->o_valid & OBD_MD_FLUID ) 
                dst->i_uid = src->o_uid;
        if ( src->o_valid & OBD_MD_FLGID ) 
                dst->i_gid = src->o_gid;
        if ( src->o_valid & OBD_MD_FLFLAGS ) 
                dst->i_flags = src->o_flags;
        if ( src->o_valid & OBD_MD_FLNLINK )
                dst->i_nlink = src->o_nlink;
        if ( src->o_valid & OBD_MD_FLGENER )
                dst->i_generation = src->o_generation;
}

#endif 

static __inline__ void obdo_cpy_md(struct obdo *dst, struct obdo *src)
{
#ifdef __KERNEL__
        CDEBUG(D_INODE, "src obdo %Ld valid 0x%x, dst obdo %Ld\n",
               src->o_id, src->o_valid, dst->o_id);
#endif
        if ( src->o_valid & OBD_MD_FLATIME ) 
                dst->o_atime = src->o_atime;
        if ( src->o_valid & OBD_MD_FLMTIME ) 
                dst->o_mtime = src->o_mtime;
        if ( src->o_valid & OBD_MD_FLCTIME ) 
                dst->o_ctime = src->o_ctime;
        if ( src->o_valid & OBD_MD_FLSIZE ) 
                dst->o_size = src->o_size;
        if ( src->o_valid & OBD_MD_FLBLOCKS ) /* allocation of space */
                dst->o_blocks = src->o_blocks;
        if ( src->o_valid & OBD_MD_FLBLKSZ )
                dst->o_blksize = src->o_blksize;
        if ( src->o_valid & OBD_MD_FLMODE ) 
                dst->o_mode = src->o_mode;
        if ( src->o_valid & OBD_MD_FLUID ) 
                dst->o_uid = src->o_uid;
        if ( src->o_valid & OBD_MD_FLGID ) 
                dst->o_gid = src->o_gid;
        if ( src->o_valid & OBD_MD_FLFLAGS ) 
                dst->o_flags = src->o_flags;
        /*
        if ( src->o_valid & OBD_MD_FLOBDFLG ) 
                dst->o_obdflags = src->o_obdflags;
        */
        if ( src->o_valid & OBD_MD_FLNLINK ) 
                dst->o_nlink = src->o_nlink;
        if ( src->o_valid & OBD_MD_FLGENER ) 
                dst->o_generation = src->o_generation;
        if ( src->o_valid & OBD_MD_FLINLINE &&
             src->o_obdflags & OBD_FL_INLINEDATA) {
                memcpy(dst->o_inline, src->o_inline, sizeof(src->o_inline));
                dst->o_obdflags |= OBD_FL_INLINEDATA;
        }
        if ( src->o_valid & OBD_MD_FLOBDMD &&
             src->o_obdflags & OBD_FL_OBDMDEXISTS) {
                memcpy(dst->o_obdmd, src->o_obdmd, sizeof(src->o_obdmd));
                dst->o_obdflags |= OBD_FL_OBDMDEXISTS;
        }

        dst->o_valid |= src->o_valid;
}


/* returns FALSE if comparison (by flags) is same, TRUE if changed */
static __inline__ int obdo_cmp_md(struct obdo *dst, struct obdo *src,
                                  obd_flag compare)
{
        int res = 0;

        if ( compare & OBD_MD_FLATIME )
                res = (res || (dst->o_atime != src->o_atime));
        if ( compare & OBD_MD_FLMTIME )
                res = (res || (dst->o_mtime != src->o_mtime));
        if ( compare & OBD_MD_FLCTIME )
                res = (res || (dst->o_ctime != src->o_ctime));
        if ( compare & OBD_MD_FLSIZE )
                res = (res || (dst->o_size != src->o_size));
        if ( compare & OBD_MD_FLBLOCKS ) /* allocation of space */
                res = (res || (dst->o_blocks != src->o_blocks));
        if ( compare & OBD_MD_FLBLKSZ )
                res = (res || (dst->o_blksize != src->o_blksize));
        if ( compare & OBD_MD_FLMODE )
                res = (res || (dst->o_mode != src->o_mode));
        if ( compare & OBD_MD_FLUID )
                res = (res || (dst->o_uid != src->o_uid));
        if ( compare & OBD_MD_FLGID )
                res = (res || (dst->o_gid != src->o_gid));
        if ( compare & OBD_MD_FLFLAGS ) 
                res = (res || (dst->o_flags != src->o_flags));
        if ( compare & OBD_MD_FLNLINK )
                res = (res || (dst->o_nlink != src->o_nlink));
        if ( compare & OBD_MD_FLGENER )
                res = (res || (dst->o_generation != src->o_generation));
        /* XXX Don't know if thses should be included here - wasn't previously
        if ( compare & OBD_MD_FLINLINE )
                res = (res || memcmp(dst->o_inline, src->o_inline));
        if ( compare & OBD_MD_FLOBDMD )
                res = (res || memcmp(dst->o_obdmd, src->o_obdmd));
        */
        return res;
}


#ifdef __KERNEL__
int obd_register_type(struct obd_ops *ops, char *nm);
int obd_unregister_type(char *nm);

struct obd_client {
        struct list_head cli_chain;
        struct obd_device *cli_obd;
        unsigned int cli_id;
        unsigned long cli_prealloc_quota;
        struct list_head cli_prealloc_inodes;
};


struct obd_prealloc_inode {
        struct list_head obd_prealloc_chain;
        unsigned long inode;
};

/* generic operations shared by various OBD types */
int gen_multi_setup(struct obd_device *obddev, uint32_t len, void *data);
int gen_multi_cleanup(struct obd_device *obddev);
int gen_multi_attach(struct obd_device *obddev, uint32_t len, void *data);
int gen_multi_detach(struct obd_device *obddev);
int gen_connect (struct obd_conn *conn);
int gen_disconnect(struct obd_conn *conn);
struct obd_client *gen_client(const struct obd_conn *);
int gen_cleanup(struct obd_device *obddev);
int gen_copy_data(struct obd_conn *dst_conn, struct obdo *dst,
                  struct obd_conn *src_conn, struct obdo *src,
                  obd_size count, obd_off offset);

#endif

/* sysctl.c */
extern void obd_sysctl_init (void);
extern void obd_sysctl_clean (void);

#define CHKCONN(conn)   do { if (!gen_client(conn)) {\
                printk("%s %d invalid client %u\n", __FILE__, __LINE__, \
                       conn->oc_id);\
                return -EINVAL; }} while (0) 



#endif /* __LINUX_CLASS_OBD_H */
