/*
 *  smfs/inode.c
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/lustre_idl.h>
#include "kml_idl.h" 
#include "smfs_internal.h" 
extern struct sm_ops smfs_operations;

#define size_round(x)  (((x)+3) & ~0x3)

void *smfs_trans_start(struct inode *inode, int op)
{

	CDEBUG(D_INODE, "trans start %p\n", 
	       smfs_operations.sm_journal_ops.tr_start);
	if (smfs_operations.sm_journal_ops.tr_start) {
		return smfs_operations.sm_journal_ops.tr_start(inode, op);	
	}
	return NULL;
}

void smfs_trans_commit(void *handle)
{
	if (smfs_operations.sm_journal_ops.tr_commit) {
		smfs_operations.sm_journal_ops.tr_commit(handle);	
	}
	CDEBUG(D_SM, "trans commit %p\n", 
	       smfs_operations.sm_journal_ops.tr_commit);
}
/*The following function are gotten from intermezzo
 * smfs_path
 * logit
 * journal_log_prefix_with_groups_and_ids 
 * journal_log_prefix 
*/
static char* smfs_path(struct dentry *dentry, struct dentry *root,
                        char *buffer, int buflen)
{
        char * end = buffer+buflen;
        char * retval;
                                                                                                                                                                                                     
        *--end = '\0';
        buflen--;
        if (dentry->d_parent != dentry && list_empty(&dentry->d_hash)) {
                buflen -= 10;
                end -= 10;
                memcpy(end, " (deleted)", 10);
        }
                                                                                                                                                                                                     
        /* Get '/' right */
        retval = end-1;
        *retval = '/';
                                                                                                                                                                                                     
        for (;;) {
                struct dentry * parent;
                int namelen;
                                                                                                                                                                                                     
                if (dentry == root)
                        break;
                parent = dentry->d_parent;
                if (dentry == parent)
                        break;
                namelen = dentry->d_name.len;
                buflen -= namelen + 1;
                if (buflen < 0)
                        break;
                end -= namelen;
                memcpy(end, dentry->d_name.name, namelen);
                *--end = '/';
                retval = end;
                dentry = parent;
        }
        return retval;
}
                                                                                                                                                                                                     
static inline char *logit(char *buf, const void *value, int size)
{
        char *ptr = (char *)value;
                                                                                                                                                                                                     
        memcpy(buf, ptr, size);
        buf += size;
        return buf;
}
static inline char *
journal_log_prefix_with_groups_and_ids(char *buf, int opcode,
                                       __u32 ngroups, gid_t *groups,
                                       __u32 fsuid, __u32 fsgid)
{
        struct kml_prefix_hdr p;
        u32 loggroups[NGROUPS_MAX];
                                                                                                                                                                                                     
        int i;
                                                                                                                                                                                                     
        p.version = KML_MAJOR_VERSION | KML_MINOR_VERSION;
        p.pid = cpu_to_le32(current->pid);
        p.auid = cpu_to_le32(current->uid);
        p.fsuid = cpu_to_le32(fsuid);
        p.fsgid = cpu_to_le32(fsgid);
        p.ngroups = cpu_to_le32(ngroups);
        p.opcode = cpu_to_le32(opcode);
        for (i=0 ; i < ngroups ; i++)
                loggroups[i] = cpu_to_le32((__u32) groups[i]);
                                                                                                                                                                                                     
        buf = logit(buf, &p, sizeof(struct kml_prefix_hdr));
        buf = logit(buf, &loggroups, sizeof(__u32) * ngroups);
        return buf;
}
                                                                                                                                                                                                     
static inline char *
journal_log_prefix(char *buf, int opcode)
{
        __u32 groups[NGROUPS_MAX];
        int i;
                                                                                                                                                                                                     
        /* convert 16 bit gid's to 32 bit gid's */
        for (i=0; i<current->ngroups; i++)
                groups[i] = (__u32) current->groups[i];
                                                                                                                                                                                                     
        return journal_log_prefix_with_groups_and_ids(buf, opcode, 
                                                      (__u32)current->ngroups,
                                                      groups,
                                                      (__u32)current->fsuid,
                                                      (__u32)current->fsgid);
}
                                                                                                                                                                                                     
static inline char *
journal_log_prefix_with_groups(char *buf, int opcode, 
                               __u32 ngroups, gid_t *groups)
{
        return journal_log_prefix_with_groups_and_ids(buf, opcode,
                                                      ngroups, groups,
                                                      (__u32)current->fsuid,
                                                      (__u32)current->fsgid);
}

static inline char *log_dentry_version(char *buf, struct dentry *dentry)
{
        struct smfs_version version;
                                                                                                                                                                                                     
        smfs_getversion(&version, dentry->d_inode);
                                                                                                                                                                                                     
        version.sm_mtime = HTON__u64(version.sm_mtime);
        version.sm_ctime = HTON__u64(version.sm_ctime);
        version.sm_size = HTON__u64(version.sm_size);
                                                                                                                                                                                                     
        return logit(buf, &version, sizeof(version));
}
                                                                                                                                                                                                     
static inline char *log_version(char *buf, struct smfs_version *pv)
{
        struct smfs_version version;
                                                                                                                                                                                                     
        memcpy(&version, pv, sizeof(version));
                                                                                                                                                                                                     
        version.sm_mtime = HTON__u64(version.sm_mtime);
        version.sm_ctime = HTON__u64(version.sm_ctime);
        version.sm_size = HTON__u64(version.sm_size);
                                                                                                                                                                                                     
        return logit(buf, &version, sizeof(version));
}
static inline char *journal_log_suffix(char *buf, char *log,
                                       struct dentry *dentry)
{
        struct kml_suffix s;
        struct kml_prefix_hdr *p = (struct kml_prefix_hdr *)log;
                                                                                                                                                                                                     
        s.prevrec = 0;
                                                                                                                                                                                                     
        /* record number needs to be filled in after reservation
           s.recno = cpu_to_le32(rec->recno); */
        s.time = cpu_to_le32(CURRENT_TIME);
        s.len = p->len;
        return logit(buf, &s, sizeof(s));
}

int smfs_kml_log(struct smfs_super_info *smfs_info,
                 const char *buf, size_t size,
                 const char *string1, int len1,
                 const char *string2, int len2,
                 const char *string3, int len3)
{
	int rc = 0;	
	/*should pack the record and dispatch it
	 *create llog handle write to the log*/
	return rc;
}

int smfs_journal_mkdir(struct dentry *dentry,
                       struct smfs_version *tgt_dir_ver,
                       struct smfs_version *new_dir_ver, 
		       int mode)
{
  	int opcode = KML_OPCODE_MKDIR;
        char *buffer, *path, *logrecord, record[292];
        struct dentry *root;
        __u32 uid, gid, lmode, pathlen;
	struct smfs_super_info *smfs_info; 	       
        struct super_block* sb;
        int error, size;
 
	ENTRY;
       
	sb = dentry->d_inode->i_sb;
	root = sb->s_root;
	smfs_info = S2SMI(sb);
	
        uid = cpu_to_le32(dentry->d_inode->i_uid);
        gid = cpu_to_le32(dentry->d_inode->i_gid);
        lmode = cpu_to_le32(mode);
                                                                                                                                                                                                     
        SM_ALLOC(buffer, PAGE_SIZE);
        path = smfs_path(dentry, root, buffer, PAGE_SIZE);
        pathlen = cpu_to_le32(MYPATHLEN(buffer, path));
        size = sizeof(__u32) * current->ngroups +
               sizeof(struct kml_prefix_hdr) + 3 * sizeof(*tgt_dir_ver) +
               sizeof(lmode) + sizeof(uid) + sizeof(gid) + sizeof(pathlen) +
               sizeof(struct kml_suffix);
                                                                                                                                                                                                     
        if ( size > sizeof(record) )
                CERROR("InterMezzo: BUFFER OVERFLOW in %s!\n", __FUNCTION__);
                                                                                                                                                                                                     
        logrecord = journal_log_prefix(record, opcode);
                                                                                                                                                                                                     
        logrecord = log_version(logrecord, tgt_dir_ver);
        logrecord = log_dentry_version(logrecord, dentry->d_parent);
        logrecord = log_version(logrecord, new_dir_ver);
        logrecord = logit(logrecord, &lmode, sizeof(lmode));
        logrecord = logit(logrecord, &uid, sizeof(uid));
        logrecord = logit(logrecord, &gid, sizeof(gid));
        logrecord = logit(logrecord, &pathlen, sizeof(pathlen));
        logrecord = journal_log_suffix(logrecord, record, dentry);
                                                                                                                                                                                                     
        error = smfs_kml_log(smfs_info, record, size,
                         path, size_round(le32_to_cpu(pathlen)),
                         NULL, 0, NULL, 0);
	SM_FREE(buffer, PAGE_SIZE);
	RETURN(error);
}
