/*
 * Lustre Light Update Records
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
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
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/segment.h>

#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>
#include <linux/lustre_light.h>

/* packing of MDS records */

void mds_create_pack(struct mds_rec_create *rec, struct inode *inode, const char *name, int namelen, __u32 mode, __u64 id, __u32 uid, __u32 gid, __u64 time)
{
	char *tmp = (char *)rec + sizeof(*rec); 
	/* XXX do something about time, uid, gid */
	rec->cr_reclen = 
		HTON__u32(sizeof(*rec) + size_round(namelen + 1));
	rec->cr_opcode = HTON__u32(REINT_CREATE);

	ll_inode2fid(&rec->cr_fid, inode); 
	rec->cr_mode = HTON__u32(mode);
	rec->cr_id = HTON__u64(id);
	rec->cr_uid = HTON__u32(uid);
	rec->cr_gid = HTON__u32(gid);
	rec->cr_time = HTON__u64(time);
	rec->cr_namelen = namelen;
	LOGL(name, namelen, tmp); 
	*tmp = '\0';
}


void mds_setattr_pack(struct mds_rec_setattr *rec, struct inode *inode, struct iattr *iattr)
{
	rec->sa_reclen = HTON__u32(sizeof(*rec));
	rec->sa_opcode = HTON__u32(REINT_SETATTR);

	ll_inode2fid(&rec->sa_fid, inode); 
	rec->sa_valid = HTON__u32(iattr->ia_valid);
	rec->sa_mode = HTON__u32(iattr->ia_mode);
	rec->sa_uid = HTON__u32(iattr->ia_uid);
	rec->sa_gid = HTON__u32(iattr->ia_gid);
	rec->sa_size = HTON__u64(iattr->ia_size);
	rec->sa_atime = HTON__u64(iattr->ia_atime);
	rec->sa_mtime = HTON__u64(iattr->ia_mtime);
	rec->sa_ctime = HTON__u64(iattr->ia_ctime);
	rec->sa_attr_flags = HTON__u32(iattr->ia_attr_flags);
}

/* unpacking */

static int mds_update_hdr_unpack(char *buf, int len, struct mds_update_record *r)
{
	struct mds_update_record_hdr *hdr = (struct mds_update_record_hdr *)buf;
	
	r->ur_reclen = NTOH__u32(hdr->ur_reclen);
	if (len < sizeof(*hdr) || len != r->ur_reclen) { 
		printk(__FUNCTION__ ": invalid buffer length\n"); 
		return -EFAULT;
	}
	r->ur_opcode = NTOH__u32(hdr->ur_opcode); 
	return 0;
}

static int mds_setattr_unpack(char *buf, int len, struct mds_update_record *r)
{

	struct iattr *attr = &r->ur_iattr;
	struct mds_rec_setattr *rec = (struct mds_rec_setattr *)buf; 

	if (len < sizeof(*rec)) { 
		printk(__FUNCTION__ "invalid buffer length\n"); 
		return -EFAULT;
	}

	r->ur_fid1 = &rec->sa_fid; 
	attr->ia_valid = NTOH__u32(rec->sa_valid);
	attr->ia_mode = NTOH__u32(rec->sa_mode);
	attr->ia_uid = NTOH__u32(rec->sa_uid);
	attr->ia_gid = NTOH__u32(rec->sa_gid);
	attr->ia_size = NTOH__u64(rec->sa_size);
	attr->ia_atime = NTOH__u64(rec->sa_atime);
	attr->ia_mtime = NTOH__u64(rec->sa_mtime);
	attr->ia_ctime = NTOH__u64(rec->sa_ctime);
	attr->ia_attr_flags = NTOH__u32(rec->sa_attr_flags);
	return 0; 
}

static int mds_create_unpack(char *buf, int len, struct mds_update_record *r)
{
	struct mds_rec_create *rec = (struct mds_rec_create *)buf; 
	char *ptr, *end;

	if (len < sizeof(*rec)) { 
		printk(__FUNCTION__ "invalid buffer length\n"); 
		return -EFAULT;
	}
	
	ptr = (char *)rec + sizeof(*rec); 
	end = ptr + len - sizeof(*rec); 
	
	r->ur_fid1 = &rec->cr_fid;
	r->ur_mode = NTOH__u32(rec->cr_mode);
	r->ur_id = NTOH__u64(rec->cr_id);
	r->ur_uid = NTOH__u32(rec->cr_uid);
	r->ur_gid = NTOH__u32(rec->cr_gid);
	r->ur_time = NTOH__u64(rec->cr_time);
	r->ur_namelen = NTOH__u64(rec->cr_namelen);

	UNLOGL(r->ur_name, char, r->ur_namelen, ptr, end); 
	return 0;
}

typedef int (*update_unpacker)(char *, int , struct mds_update_record *); 

static update_unpacker mds_unpackers[REINT_MAX + 1] = {
	[REINT_SETATTR] mds_setattr_unpack, 	
        [REINT_CREATE] mds_create_unpack
};

int mds_update_unpack(char *buf, int len, struct mds_update_record *r)
{
	int rc; 
	ENTRY;

	rc = mds_update_hdr_unpack(buf, len, r);

	if (rc) { 
		EXIT;
		return -EFAULT;
	}

	if ( r->ur_opcode<0 || r->ur_opcode > REINT_MAX) { 
		EXIT;
		return EFAULT; 
	}
	
	rc = mds_unpackers[r->ur_opcode](buf, len, r);
	EXIT;
	return rc;
}
