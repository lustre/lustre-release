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

void mds_create_pack(struct mds_rec_create *rec, struct inode *inode, const char *name, int namelen, __u32 mode, __u64 id, __u32 uid, __u32 gid, __u64 time, const char *tgt, int tgtlen)
{
	char *tmp = (char *)rec + sizeof(*rec); 
	/* XXX do something about time, uid, gid */
	rec->cr_reclen = 
		HTON__u32(sizeof(*rec) + size_round0(namelen) + 
			  size_round0(tgtlen));
	rec->cr_opcode = HTON__u32(REINT_CREATE);

	ll_inode2fid(&rec->cr_fid, inode); 
	rec->cr_mode = HTON__u32(mode);
	rec->cr_id = HTON__u64(id);
	rec->cr_uid = HTON__u32(uid);
	rec->cr_gid = HTON__u32(gid);
	rec->cr_time = HTON__u64(time);
	rec->cr_namelen = HTON__u32(namelen + 1); /* for terminating \0 */ 
	LOGL0(name, namelen, tmp); 
	if (tgt) { 
		rec->cr_tgtlen = HTON__u32(tgtlen + 1); 
		LOGL0(tgt, tgtlen, tmp); 
	}
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

void mds_unlink_pack(struct mds_rec_unlink *rec, 
		     struct inode *inode, const char *name, int namelen)
{
	char *tmp = (char *)rec + sizeof(*rec); 

	rec->ul_reclen = HTON__u32(sizeof(*rec)) + size_round0(namelen);
	rec->ul_opcode = HTON__u32(REINT_UNLINK);

	ll_inode2fid(&rec->ul_fid1, inode); 
	rec->ul_namelen = HTON__u32(namelen + 1); /* for terminating \0 */ 
	LOGL0(name, namelen, tmp); 
}

void mds_link_pack(struct mds_rec_link *rec, 
		     struct inode *inode, struct inode *dir,
		     const char *name, int namelen)
{
	char *tmp = (char *)rec + sizeof(*rec); 
	rec->lk_reclen = HTON__u32(sizeof(*rec)) + size_round0(namelen);
	rec->lk_opcode = HTON__u32(REINT_LINK);

	ll_inode2fid(&rec->lk_fid1, inode); 
	ll_inode2fid(&rec->lk_fid2, dir); 
	rec->lk_namelen = HTON__u32(namelen + 1); /* for terminating \0 */ 
	LOGL0(name, namelen, tmp); 
}

void mds_rename_pack(struct mds_rec_rename *rec, struct inode *srcdir, struct inode *tgtdir, const char *name, int namelen, const char *tgt, int tgtlen)
{
	char *tmp = (char *)rec + sizeof(*rec); 
	/* XXX do something about time, uid, gid */
	rec->rn_reclen = 
		HTON__u32(sizeof(*rec) + size_round0(namelen) + 
			  size_round0(tgtlen));
	rec->rn_opcode = HTON__u32(REINT_RENAME);

	ll_inode2fid(&rec->rn_fid1, srcdir); 
	ll_inode2fid(&rec->rn_fid2, tgtdir); 
	rec->rn_namelen = HTON__u32(namelen + 1); /* for terminating \0 */ 
	LOGL0(name, namelen, tmp); 
	if (tgt) { 
		rec->rn_tgtlen = HTON__u32(tgtlen + 1); 
		LOGL0(tgt, tgtlen, tmp); 
	}
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
	r->ur_namelen = NTOH__u32(rec->cr_namelen);
	r->ur_tgtlen = NTOH__u32(rec->cr_tgtlen);

	UNLOGL0(r->ur_name, char, r->ur_namelen, ptr, end); 
	UNLOGL0(r->ur_tgt, char, r->ur_tgtlen, ptr, end);
	return 0;
}

static int mds_link_unpack(char *buf, int len, struct mds_update_record *r)
{
	struct mds_rec_link *rec = (struct mds_rec_link *)buf; 
	char *ptr, *end;

	if (len < sizeof(*rec)) { 
		printk(__FUNCTION__ "invalid buffer length\n"); 
		return -EFAULT;
	}
	
	ptr = (char *)rec + sizeof(*rec); 
	end = ptr + len - sizeof(*rec); 
	
	r->ur_fid1 = &rec->lk_fid1;
	r->ur_fid2 = &rec->lk_fid2;
	r->ur_namelen = NTOH__u32(rec->lk_namelen);
	UNLOGL0(r->ur_name, char, r->ur_namelen, ptr, end); 
	return 0;
}


static int mds_unlink_unpack(char *buf, int len, struct mds_update_record *r)
{
	struct mds_rec_unlink *rec = (struct mds_rec_unlink *)buf; 
	char *ptr, *end;
	ENTRY;

	if (len < sizeof(*rec)) { 
		printk(__FUNCTION__ "invalid buffer length\n"); 
		return -EFAULT;
	}
	
	ptr = (char *)rec + sizeof(*rec); 
	end = ptr + len - sizeof(*rec); 
	
	r->ur_fid1 = &rec->ul_fid1;
	r->ur_namelen = NTOH__u32(rec->ul_namelen);
	UNLOGL0(r->ur_name, char, r->ur_namelen, ptr, end); 
	EXIT;
	return 0;
}

static int mds_rename_unpack(char *buf, int len, struct mds_update_record *r)
{
	struct mds_rec_rename *rec = (struct mds_rec_rename *)buf; 
	char *ptr, *end;

	if (len < sizeof(*rec)) { 
		printk(__FUNCTION__ "invalid buffer length\n"); 
		return -EFAULT;
	}
	
	ptr = (char *)rec + sizeof(*rec); 
	end = ptr + len - sizeof(*rec); 
	
	r->ur_fid1 = &rec->rn_fid1;
	r->ur_fid2 = &rec->rn_fid2;
	r->ur_namelen = NTOH__u32(rec->rn_namelen);
	r->ur_tgtlen = NTOH__u32(rec->rn_tgtlen);

	UNLOGL0(r->ur_name, char, r->ur_namelen, ptr, end); 
	UNLOGL0(r->ur_tgt, char, r->ur_tgtlen, ptr, end);
	return 0;
}

typedef int (*update_unpacker)(char *, int , struct mds_update_record *); 

static update_unpacker mds_unpackers[REINT_MAX + 1] = {
	[REINT_SETATTR] mds_setattr_unpack, 	
        [REINT_CREATE] mds_create_unpack,
        [REINT_LINK] mds_link_unpack,
        [REINT_UNLINK] mds_unlink_unpack,
        [REINT_RENAME] mds_rename_unpack,
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
