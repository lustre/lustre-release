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


void mds_setattr_pack(struct mds_rec_setattr *rec, struct inode *inode, struct iattr *iattr)
{
	rec->sa_len = HTON__u32(sizeof(*rec));
	rec->sa_opcode = HTON__u32(sizeof(REINT_SETATTR));
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

void mds_setattr_unpack(struct mds_rec_setattr *rec, struct iattr *attr)
{
	attr->ia_valid = NTOH__u32(rec->sa_valid);
	attr->ia_mode = NTOH__u32(rec->sa_mode);
	attr->ia_uid = NTOH__u32(rec->sa_uid);
	attr->ia_gid = NTOH__u32(rec->sa_gid);
	attr->ia_size = NTOH__u64(rec->sa_size);
	attr->ia_atime = NTOH__u64(rec->sa_atime);
	attr->ia_mtime = NTOH__u64(rec->sa_mtime);
	attr->ia_ctime = NTOH__u64(rec->sa_ctime);
	attr->ia_attr_flags = NTOH__u32(rec->sa_attr_flags);
}
