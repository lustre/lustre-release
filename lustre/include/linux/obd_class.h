#ifndef __LINUX_CLASS_OBD_H
#define __LINUX_CLASS_OBD_H

#include <linux/fs.h>
#include <linux/ext2_fs.h>
#include <linux/time.h>
#include <linux/obd.h>

#include <linux/obd_ext2.h>
#include <linux/obd_snap.h>
/* #include <linux/obd_fc.h> */
#include <linux/obd_raid1.h>
#include <linux/obd_rpc.h>


#define OBD_PSDEV_MAJOR 120
#define MAX_OBD_DEVICES 8
#define MAX_MULTI 16

typedef unsigned long   objid;
typedef struct inode obdattr;
#if 0
struct obdattr {
	objid                   oa_id;
	umode_t			oa_mode;
	nlink_t			oa_nlink;
	uid_t			oa_uid;
	gid_t			oa_gid;
	off_t			oa_size;
	time_t			oa_atime;
	time_t			oa_mtime;
	time_t			oa_ctime;
	unsigned long		oa_blksize;
	unsigned long		oa_blocks;
	char                    oa_data[116];
	struct obd_ops         *oa_op;
};

#endif

extern struct obd_device obd_dev[MAX_OBD_DEVICES];

	



#define OBD_ATTACHED 0x1
#define OBD_SET_UP   0x2

struct obd_conn {
	struct obd_device *oc_dev;
	unsigned int oc_id;
};

/* corresponds to one of the obdx */
struct obd_device {
	struct obd_type *obd_type;
	int obd_minor;
	int obd_flags;
	int obd_refcnt; 
	int obd_multi_count;
	struct obd_conn obd_multi_conn[MAX_MULTI];
	unsigned int obd_gen_last_id;
	unsigned long obd_gen_prealloc_quota;
	struct list_head obd_gen_clients;
	union {
		struct ext2_obd ext2;
		struct raid1_obd raid1;
		struct snap_obd snap;
		struct rpc_obd rpc;
		/* struct fc_obd fc; */
	} u;
};

struct obd_ops {
	int (*o_attach)(struct obd_device *, int len, void *);
	int (*o_detach)(struct obd_device *);
	int (*o_format)(struct obd_device *, int len, void *);
	int (*o_partition)(struct obd_device *, int len, void *);
	int (*o_connect)(struct obd_conn *conn);
	int (*o_disconnect)(struct obd_conn *);
	int (*o_setup) (struct obd_device *dev, int len, void *data);
	int (*o_cleanup)(struct obd_device *dev);
	int (*o_setattr)(struct obd_conn *, obdattr *oa);
	int (*o_getattr)(struct obd_conn *, obdattr *oa);
	int (*o_statfs)(struct obd_conn *, struct statfs *statfs);
	int (*o_create)(struct obd_conn *, int prealloc_ino, int *er);
	int (*o_destroy)(struct obd_conn *, obdattr *oa);
	int (*o_read)(struct obd_conn *, obdattr *ino, char *buf, unsigned long *count, loff_t offset);
	int (*o_read2)(struct obd_conn *, obdattr *oa, char *buf, unsigned long *count, loff_t offset);
	int (*o_write)(struct obd_conn *, obdattr *oa, char *buf, unsigned long *count, loff_t offset);
	int (*o_brw)(int rw, struct obd_conn * conn, obdattr *obj, struct page *page, int create);
	int (*o_preallocate)(struct obd_conn *, unsigned long *req, long inodes[32]);
	int  (*o_get_info)(struct obd_conn *, int keylen, void *key, int *vallen, void **val);
	int  (*o_set_info)(struct obd_conn *, int keylen, void *key, int vallen, void *val);
	int (*o_migrate)(struct obd_conn *, obdattr *src, obdattr *dst);
	int (*o_copy)(struct obd_conn *dev, obdattr *source, obdattr *target);
	int (*o_iocontrol)(int cmd, struct obd_conn *, int len, void *karg, void *uarg);
	int (*o_iterate)(struct obd_conn *, int (*)(objid, void *), objid, void *);

};

#define OBP(dev,op) dev->obd_type->typ_ops->o_ ## op

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
int gen_connect (struct obd_conn *conn);
int gen_disconnect(struct obd_conn *conn);
int gen_multi_setup(struct obd_device *obddev, int len, void *data);
int gen_multi_cleanup(struct obd_device *obddev);
int gen_multi_attach(struct obd_device *obddev, int len, void *data);
struct obd_client *gen_client(struct obd_conn *);
int gen_multi_detach(struct obd_device *obddev);
int gen_cleanup(struct obd_device *obddev);
int gen_copy_data(struct obd_conn *, obdattr *source, obdattr *target);



/*
 * ioctl commands
 */
struct oic_generic {
	int  att_connid;
	int  att_typelen;
	void *att_type;
	int  att_datalen;
	void *att_data;
};

struct oic_prealloc_s {
	unsigned long cli_id;
	unsigned long alloc; /* user sets it to the number of inodes requesting
		     * to be preallocated.  kernel sets it to the actual number
		     * of succesfully preallocated inodes */
	long inodes[32]; /* actual inode numbers */
};

struct oic_create_s {
	unsigned int conn_id;
	unsigned long prealloc;
};

struct oic_attr_s {
	unsigned int conn_id;
	unsigned long ino;
	struct iattr iattr;
};

struct ioc_mv_s {
	unsigned int conn_id;
	objid  src;
	objid  tgt;
};

struct oic_rw_s {
	unsigned int conn_id;
	unsigned long id;
	char * buf;
	unsigned long count;
	loff_t offset;
};

struct oic_partition {
	int partition;
	unsigned int size;
};


#define OBD_IOC_CREATE                 _IOR ('f',  3, long)
#define OBD_IOC_SETUP                  _IOW ('f',  4, long)
#define OBD_IOC_CLEANUP                _IO  ('f',  5      )
#define OBD_IOC_DESTROY                _IOW ('f',  6, long)
#define OBD_IOC_PREALLOCATE            _IOWR('f',  7, long)
#define OBD_IOC_DEC_USE_COUNT          _IO  ('f',  8      )
#define OBD_IOC_SETATTR                _IOW ('f',  9, long)
#define OBD_IOC_GETATTR                _IOR ('f', 10, long)
#define OBD_IOC_READ                   _IOWR('f', 11, long)
#define OBD_IOC_WRITE                  _IOWR('f', 12, long)
#define OBD_IOC_CONNECT                _IOR ('f', 13, long)
#define OBD_IOC_DISCONNECT             _IOW ('f', 14, long)
#define OBD_IOC_STATFS                 _IOWR('f', 15, long)
#define OBD_IOC_SYNC                   _IOR ('f',  16, long)
#define OBD_IOC_READ2                  _IOWR('f', 17, long)
#define OBD_IOC_FORMAT                 _IOWR('f', 18, long)
#define OBD_IOC_PARTITION              _IOWR('f', 19, long)
#define OBD_IOC_ATTACH                 _IOWR('f', 20, long)
#define OBD_IOC_DETACH                 _IOWR('f', 21, long)
#define OBD_IOC_COPY                   _IOWR('f', 22, long)
#define OBD_IOC_MIGR                   _IOWR('f', 23, long)

#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 32      )


/* sysctl.c */
extern void obd_sysctl_init (void);
extern void obd_sysctl_clean (void);

#define CHKCONN(conn)	do { if (!gen_client(conn)) {\
		printk("%s %d invalid client %u\n", __FILE__, __LINE__, \
		       conn->oc_id);\
		return -EINVAL; }} while (0) 


/* support routines */
static __inline__ obdattr *obd_empty_oa(void)
{
	obdattr *res = NULL;
	OBD_ALLOC(res, obdattr *, sizeof(*res));
	memset(res, 0, sizeof (*res));
	return res;
}

static __inline__ void obd_free_oa(obdattr *oa)
{
	if ( !oa ) 
		return;
	OBD_FREE(oa,sizeof(*oa));
}



static __inline__ obdattr *obd_oa_fromid(struct obd_conn *conn,  objid id)
{
	obdattr *res = NULL;

	OBD_ALLOC(res, obdattr *, sizeof(*res));
	if ( !res ) {
		EXIT;
		return NULL;
	}
	memset(res, 0, sizeof(*res));
	res->i_ino = id;
	if (conn->oc_dev->obd_type->typ_ops->o_getattr(conn, res)) {
		OBD_FREE(res, sizeof(*res));
		EXIT;
		return NULL;
	}
	EXIT;
	return res;
}

#define OBD_MD_NO	(1UL)       /* negates meaning of all flags */
#define OBD_MD_ALL	(OBD_MD_NO) /* passing NO with no other flags == ALL */
#define OBD_MD_FLMODE	(1UL<<1)
#define OBD_MD_FLUID	(1UL<<2)
#define OBD_MD_FLGID	(1UL<<3)
#define OBD_MD_FLSIZE	(1UL<<4)
#define OBD_MD_FLATIME	(1UL<<5)
#define OBD_MD_FLMTIME	(1UL<<6)
#define OBD_MD_FLCTIME	(1UL<<7)
#define OBD_MD_FLFLAGS	(1UL<<8)
#define OBD_MD_FLBLOCKS	(1UL<<9)
#define OBD_MD_FLOBDMD	(1UL<<10)


static __inline__ void obdo_cpy_md(obdattr *dst, obdattr *src, int mask)
{
	/* If the OBD_MD_NO flag is set, then we copy all EXCEPT those
	 * fields given by the flags.  The default is to copy the field
	 * given by the flags.
	 */
	if (mask & OBD_MD_NO)
		mask = ~mask;

	CDEBUG(D_INODE, "flags %x\n", mask);
	if ( mask & OBD_MD_FLMODE ) 
		dst->i_mode = src->i_mode;
	if ( mask & OBD_MD_FLUID ) 
		dst->i_uid = src->i_uid;
	if ( mask & OBD_MD_FLGID ) 
		dst->i_gid = src->i_gid;
	if ( mask & OBD_MD_FLSIZE ) 
		dst->i_size = src->i_size;
	if ( mask & OBD_MD_FLATIME ) 
		dst->i_atime = src->i_atime;
	if ( mask & OBD_MD_FLMTIME ) 
		dst->i_mtime = src->i_mtime;
	if ( mask & OBD_MD_FLCTIME ) 
		dst->i_ctime = src->i_ctime;
	if ( mask & OBD_MD_FLFLAGS ) 
		dst->i_flags = src->i_flags;
	/* allocation of space */
	if ( mask & OBD_MD_FLBLOCKS ) 
		dst->i_blocks = src->i_blocks;
	if ( mask & OBD_MD_FLOBDMD  &&  src->i_blocks == 0 ) {
		CDEBUG(D_IOCTL, "copying inline data: ino %ld\n", dst->i_ino);
		memcpy(&dst->u.ext2_i.i_data, &src->u.ext2_i.i_data, 
		       sizeof(src->u.ext2_i.i_data));
	} else {
		CDEBUG(D_INODE, "XXXX cpy_obdmd: ino %ld iblocks not 0!\n",
		       src->i_ino);
	}
}


static __inline__ int obdo_cmp_md(obdattr *dst, obdattr *src, int mask)
{
	int res = 1;

	/* If the OBD_MD_NO flag is set, then we copy all EXCEPT those
	 * fields given by the flags.  The default is to copy the field
	 * given by the flags.
	 */
	if (mask & OBD_MD_NO)
		mask = ~mask;

	if ( mask & OBD_MD_FLMODE )
		res = (res && (dst->i_mode == src->i_mode));
	if ( mask & OBD_MD_FLUID )
		res = (res && (dst->i_uid == src->i_uid));
	if ( mask & OBD_MD_FLGID )
		res = (res && (dst->i_gid == src->i_gid));
	if ( mask & OBD_MD_FLSIZE )
		res = (res && (dst->i_size == src->i_size));
	if ( mask & OBD_MD_FLATIME )
		res = (res && (dst->i_atime == src->i_atime));
	if ( mask & OBD_MD_FLMTIME )
		res = (res && (dst->i_mtime == src->i_mtime));
	if ( mask & OBD_MD_FLCTIME )
		res = (res && (dst->i_ctime == src->i_ctime));
	if ( mask & OBD_MD_FLFLAGS )
		res = (res && (dst->i_flags == src->i_flags));
	/* allocation of space */
	if ( mask & OBD_MD_FLBLOCKS )
		res = (res && (dst->i_blocks == src->i_blocks));
	return res;
}


static __inline__ void obd_cpy_appmd(obdattr *dst, obdattr *src)
{
	dst->i_mode = src->i_mode;
	dst->i_uid = src->i_uid;
	dst->i_gid = src->i_gid;
	dst->i_size = src->i_size;
	dst->i_atime = src->i_atime;
	dst->i_mtime = src->i_mtime;
	dst->i_ctime = src->i_ctime;
	dst->i_flags = src->i_flags;
	/* allocation of space */
	dst->i_blocks = src->i_blocks;
}

#endif /* __LINUX_CLASS_OBD_H */
