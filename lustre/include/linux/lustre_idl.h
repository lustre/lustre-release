/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * (Un)packing of OST requests
 */

#ifndef __LUSTRE_IDL_H__
#define __LUSTRE_IDL_H__
#ifdef __KERNEL__
#include <linux/ioctl.h>
#include <asm/types.h>

#include <linux/types.h>
#else 
#define __KERNEL__
#include <linux/list.h>
#undef __KERNEL__
#include <stdint.h>
#endif
/* 
 * this file contains all data structures used in Lustre interfaces:
 * - obdo and obd_request records
 * - mds_request records
 * - ioctl's
 */ 


/* 
 *   OST requests: OBDO & OBD request records
 */


/* opcodes */
#define OST_GET_INFO  6
#define OST_CONNECT  7
#define OST_DISCONNECT 8
#define OST_GETATTR  1
#define OST_SETATTR  2
#define OST_BRW      3
#define OST_CREATE   4
#define OST_DESTROY  5

/* packet types */
#define OST_TYPE_REQ 1
#define OST_TYPE_REP 2
#define OST_TYPE_ERR 3

struct ost_req_hdr { 
	__u32 opc;
	__u64 seqno;
	__u32 status;
	__u32 type;
};

struct ost_rep_hdr { 
	__u32 opc;
	__u64 seqno;
	__u32 status;
	__u32 type;
};

typedef uint64_t        obd_id;
typedef uint64_t        obd_gr;
typedef uint64_t        obd_time;
typedef uint64_t        obd_size;
typedef uint64_t        obd_off;
typedef uint64_t        obd_blocks;
typedef uint32_t        obd_blksize;
typedef uint32_t        obd_mode;
typedef uint32_t        obd_uid;
typedef uint32_t        obd_gid;
typedef uint32_t        obd_rdev;
typedef uint32_t        obd_flag;
typedef uint32_t        obd_count;

#define OBD_FL_INLINEDATA       (0x00000001UL)  
#define OBD_FL_OBDMDEXISTS      (0x00000002UL)

#define OBD_INLINESZ    60
#define OBD_OBDMDSZ     60
/* Note: 64-bit types are 64-bit aligned in structure */
struct obdo {
        obd_id                  o_id;
        obd_gr                  o_gr;
        obd_time                o_atime;
        obd_time                o_mtime;
        obd_time                o_ctime;
        obd_size                o_size;
        obd_blocks              o_blocks;
        obd_blksize             o_blksize;
        obd_mode                o_mode;
        obd_uid                 o_uid;
        obd_gid                 o_gid;
        obd_flag                o_flags;
        obd_flag                o_obdflags;
        obd_count               o_nlink;
        obd_count               o_generation;
        obd_flag                o_valid;        /* hot fields in this obdo */
        char                    o_inline[OBD_INLINESZ];
        char                    o_obdmd[OBD_OBDMDSZ];
        struct list_head        o_list;
        struct obd_ops          *o_op;
};

#define OBD_MD_FLALL    (~0UL)
#define OBD_MD_FLID     (0x00000001UL)
#define OBD_MD_FLATIME  (0x00000002UL)
#define OBD_MD_FLMTIME  (0x00000004UL)
#define OBD_MD_FLCTIME  (0x00000008UL)
#define OBD_MD_FLSIZE   (0x00000010UL)
#define OBD_MD_FLBLOCKS (0x00000020UL)
#define OBD_MD_FLBLKSZ  (0x00000040UL)
#define OBD_MD_FLMODE   (0x00000080UL)
#define OBD_MD_FLTYPE   (0x00000100UL)
#define OBD_MD_FLUID    (0x00000200UL)
#define OBD_MD_FLGID    (0x00000400UL)
#define OBD_MD_FLFLAGS  (0x00000800UL)
#define OBD_MD_FLOBDFLG (0x00001000UL)
#define OBD_MD_FLNLINK  (0x00002000UL)
#define OBD_MD_FLGENER  (0x00004000UL)
#define OBD_MD_FLINLINE (0x00008000UL)
#define OBD_MD_FLOBDMD  (0x00010000UL)
#define OBD_MD_FLOBJID  (0x00020000UL)
#define OBD_MD_FLNOTOBD (~(OBD_MD_FLOBDMD | OBD_MD_FLOBDFLG | OBD_MD_FLBLOCKS))

/* request structure for OST's */

#define OST_REQ_HAS_OA1  0x1

struct ost_req_packed { 
	__u32   connid;
	__u32   cmd; 
	struct obdo oa;
	__u32   buflen1;
	__u32   buflen2;
	__u32   bufoffset1;
	__u32   bufoffset2;
};

struct ost_rep_packed {
	__u32   result;
	__u32   connid;
	struct obdo oa;
	__u32   buflen1;
	__u32   buflen2;
	__u32   bufoffset1;
	__u32   bufoffset2;
};

struct obd_buf { 
        __u64 addr;       // address 
        __u64 handle;     // DMA handle
        __u64 matchbits;  // portals match bits
        __u32 offset;     // first bit after addr that is relevant
        __u32 size;       // size from addr + offset that needs moving
};

struct obd_bufref { 
        obd_id    obj_id;
        obd_gr    obj_gr;
        __u64     offset;
        __u32     size; 
        __u32     flags;
}; 

/* reply structure for OST's */





/* 
 *   MDS REQ RECORDS
 */


#define MDS_TYPE_REQ 1
#define MDS_TYPE_REP 2
#define MDS_TYPE_ERR 3

#define MDS_GETATTR   1
#define MDS_REINT     2
#define MDS_READPAGE  3

#define REINT_SETATTR 0
#define REINT_CREATE  1
#define REINT_MAX     1

struct mds_req_hdr { 
	__u32 opc;
	__u64 seqno;
	__u32 status;
	__u32 type;
};

struct ll_fid { 
	__u64 id;
	__u32 generation;
	__u32 f_type;
};

struct niobuf { 
        __u64 addr;
};

struct mds_rep_hdr { 
	__u32 opc;
	__u64 seqno;
	__u32 status;
	__u32 type;
};

struct mds_req_packed {
	struct ll_fid        fid1;
	struct ll_fid        fid2;
        int                        namelen;
        int                        tgtlen;
        __u32                       opcode;
        __u32                       valid;
        __u32 			    mode;
        __u32                       uid;
        __u32                       gid;
        __u64                       size;
        __u32                       mtime;
        __u32                       ctime;
        __u32                       atime;
        __u32                       flags;
        __u32                       major;
        __u32                       minor;
        __u32                       ino;
        __u32                       nlink;
        __u32                       generation;
        __u64                       objid;
};

struct mds_rep_packed {
	struct ll_fid        fid1;
	struct ll_fid        fid2;
        int                        namelen;
        int                        tgtlen;
        __u32                       valid;
        __u32 			    mode;
        __u32                       uid;
        __u32                       gid;
        __u64                       size;
        __u32                       mtime;
        __u32                       ctime;
        __u32                       atime;
        __u32                       flags;
        __u32                       major;
        __u32                       minor;
        __u32                       ino;
        __u32                       nlink;
        __u32                       generation;
        __u64                       objid;
};


/* MDS update records */ 

struct mds_update_record_hdr { 
        __u32 ur_reclen;
        __u32 ur_opcode;
};

struct mds_rec_setattr { 
        __u32           sa_reclen;
        __u32           sa_opcode;
	struct ll_fid   sa_fid;
	__u32	        sa_valid;
	__u32		sa_mode;
	__u32		sa_uid;
	__u32		sa_gid;
	__u64		sa_size;
	__u64		sa_atime;
	__u64		sa_mtime;
	__u64		sa_ctime;
	__u32 	        sa_attr_flags;
};

struct mds_rec_create { 
        __u32           cr_reclen;
        __u32           cr_opcode;
	struct ll_fid   cr_fid;
        __u32           cr_uid;
        __u32           cr_gid;
        __u64           cr_time;
	__u32		cr_mode;
        /* overloaded: id for create, tgtlen for symlink, rdev for mknod */ 
	__u64		cr_id; 
        __u32           cr_namelen;
        /* name here */
};

#ifdef __KERNEL__ 

static inline void ll_ino2fid(struct ll_fid *fid, ino_t ino, __u32 generation, int type)
{
        fid->id = HTON__u64((__u64)ino);
        fid->generation = HTON__u32(generation);
        fid->f_type = HTON__u32(type);
}

static inline void ll_inode2fid(struct ll_fid *fid, struct inode *inode)
{
        fid->id = HTON__u64((__u64)inode->i_ino);
        fid->generation = HTON__u32(inode->i_generation);
        fid->f_type = HTON__u32(inode->i_mode & S_IFMT);
}

#endif 

/* 
 *   OBD IOCTLS
 */


#define OBD_IOCTL_VERSION 0x00010001

struct obd_ioctl_data { 
	uint32_t ioc_len;
	uint32_t ioc_version;
        uint32_t ioc_conn1;
        uint32_t ioc_conn2;
	struct obdo ioc_obdo1;
	struct obdo ioc_obdo2;
        obd_size         ioc_count;
        obd_off          ioc_offset;
	uint32_t         ioc_dev;

	/* buffers the kernel will treat as user pointers */
	uint32_t ioc_plen1;
	char    *ioc_pbuf1;
	uint32_t ioc_plen2;
	char    *ioc_pbuf2;

	/* two inline buffers */
	uint32_t ioc_inllen1;
	char    *ioc_inlbuf1;
	uint32_t ioc_inllen2;
	char    *ioc_inlbuf2;

	char    ioc_bulk[0];
};

struct obd_ioctl_hdr { 
	uint32_t ioc_len;
	uint32_t ioc_version;
};

static inline int obd_ioctl_packlen(struct obd_ioctl_data *data)
{
	int len = sizeof(struct obd_ioctl_data);
	len += size_round(data->ioc_inllen1);
	len += size_round(data->ioc_inllen2);
	return len;
}

static inline int obd_ioctl_is_invalid(struct obd_ioctl_data *data)
{
	if (data->ioc_len > (1<<30)) { 
		printk("OBD ioctl: ioc_len larger than 1<<30\n");
		return 1;
	}
	if (data->ioc_inllen1 > (1<<30)) { 
		printk("OBD ioctl: ioc_inllen1 larger than 1<<30\n");
		return 1;
	}
	if (data->ioc_inllen2 > (1<<30)) { 
		printk("OBD ioctl: ioc_inllen2 larger than 1<<30\n");
		return 1;
	}
	if (data->ioc_inlbuf1 && !data->ioc_inllen1) {
		printk("OBD ioctl: inlbuf1 pointer but 0 length\n");
		return 1;
	}
	if (data->ioc_inlbuf2 && !data->ioc_inllen2) {
		printk("OBD ioctl: inlbuf2 pointer but 0 length\n");
		return 1;
	}
	if (data->ioc_pbuf1 && !data->ioc_plen1) {
		printk("OBD ioctl: pbuf1 pointer but 0 length\n");
		return 1;
	}
	if (data->ioc_pbuf2 && !data->ioc_plen2) {
		printk("OBD ioctl: pbuf2 pointer but 0 length\n");
		return 1;
	}
	if (obd_ioctl_packlen(data) != data->ioc_len ) {
		printk("OBD ioctl: packlen exceeds ioc_len\n");
		return 1;
	}
	if (data->ioc_inllen1 && 
	    data->ioc_bulk[data->ioc_inllen1 - 1] != '\0') { 
		printk("OBD ioctl: inlbuf1 not 0 terminated\n");
		return 1;
	}
	if (data->ioc_inllen2 && 
	    data->ioc_bulk[size_round(data->ioc_inllen1) + data->ioc_inllen2 - 1] != '\0') { 
		printk("OBD ioctl: inlbuf2 not 0 terminated\n");
		return 1;
	}
	return 0;
}

#ifndef __KERNEL__
static inline int obd_ioctl_pack(struct obd_ioctl_data *data, char **pbuf, int max)
{
	char *ptr;
	struct obd_ioctl_data *overlay;
	data->ioc_len = obd_ioctl_packlen(data);
	data->ioc_version = OBD_IOCTL_VERSION;

	if (*pbuf && obd_ioctl_packlen(data) > max) 
		return 1;
	if (*pbuf == NULL) { 
		*pbuf = malloc(data->ioc_len);
	}
	if (!*pbuf)
		return 1;
	overlay = (struct obd_ioctl_data *)*pbuf;
	memcpy(*pbuf, data, sizeof(*data));

	ptr = overlay->ioc_bulk;
	if (data->ioc_inlbuf1)
		LOGL(data->ioc_inlbuf1, data->ioc_inllen1, ptr);
	if (data->ioc_inlbuf2)
		LOGL(data->ioc_inlbuf2, data->ioc_inllen2, ptr);
	if (obd_ioctl_is_invalid(overlay))
		return 1;

	return 0;
}
#else


/* buffer MUST be at least the size of obd_ioctl_hdr */
static inline int obd_ioctl_getdata(char *buf, char *end, void *arg)
{
	struct obd_ioctl_hdr *hdr;
	struct obd_ioctl_data *data;
	int err;
	ENTRY;

	hdr = (struct obd_ioctl_hdr *)buf;
	data = (struct obd_ioctl_data *)buf;

	err = copy_from_user(buf, (void *)arg, sizeof(*hdr));
	if ( err ) {
		EXIT;
		return err;
	}

	if (hdr->ioc_version != OBD_IOCTL_VERSION) { 
		printk("OBD: version mismatch kernel vs application\n");
		return -EINVAL;
	}

	if (hdr->ioc_len + buf >= end) { 
		printk("OBD: user buffer exceeds kernel buffer\n");
		return -EINVAL;
	}


	if (hdr->ioc_len < sizeof(struct obd_ioctl_data)) { 
		printk("OBD: user buffer too small for ioctl\n");
		return -EINVAL;
	}

	err = copy_from_user(buf, (void *)arg, hdr->ioc_len);
	if ( err ) {
		EXIT;
		return err;
	}

	if (obd_ioctl_is_invalid(data)) { 
		printk("OBD: ioctl not correctly formatted\n");
		return -EINVAL;
	}

	if (data->ioc_inllen1) { 
		data->ioc_inlbuf1 = &data->ioc_bulk[0];
	}

	if (data->ioc_inllen2) { 
		data->ioc_inlbuf2 = &data->ioc_bulk[0] + size_round(data->ioc_inllen1);
	}

	EXIT;
	return 0;
}
#endif


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
#define OBD_IOC_SYNC                   _IOR ('f', 16, long)
#define OBD_IOC_READ2                  _IOWR('f', 17, long)
#define OBD_IOC_FORMAT                 _IOWR('f', 18, long)
#define OBD_IOC_PARTITION              _IOWR('f', 19, long)
#define OBD_IOC_ATTACH                 _IOWR('f', 20, long)
#define OBD_IOC_DETACH                 _IOWR('f', 21, long)
#define OBD_IOC_COPY                   _IOWR('f', 22, long)
#define OBD_IOC_MIGR                   _IOWR('f', 23, long)
#define OBD_IOC_PUNCH                  _IOWR('f', 24, long)
#define OBD_IOC_DEVICE                 _IOWR('f', 25, long)

#define OBD_IOC_DEC_FS_USE_COUNT       _IO  ('f', 32      )



#endif
