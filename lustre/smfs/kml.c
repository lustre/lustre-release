/*
 *  smfs/kml.c
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/lustre_idl.h>
#include "smfs_internal.h" 
#include "kml_idl.h"

/*FIXME there should be more conditions in this check*/
int smfs_do_kml(struct inode *dir)
{
	struct smfs_super_info	*smfs_info = S2SMI(dir->i_sb);	
		
	if (smfs_info->flags & SM_DO_KML) {
		return 1;
	}
	return 0;
}
void smfs_getversion(struct smfs_version * smfs_version,
                           struct inode * inode) 
{
	smfs_version->sm_mtime = (__u64)inode->i_mtime;
        smfs_version->sm_ctime = (__u64)inode->i_ctime;
        smfs_version->sm_size  = (__u64)inode->i_size;
}

int smfs_kml_init(struct super_block *sb)
{
	struct smfs_super_info	*smfs_info = S2SMI(sb);	
	int    rc = 0;
	smfs_info->flags |= SM_DO_KML;

	rc = smfs_llog_setup(&smfs_info->kml_llog);			

	RETURN(rc);
}

int post_kml_mkdir(struct inode *dir, struct dentry *dentry)
{
	struct smfs_version tgt_dir_ver, new_dir_ver;
	int    error;

	smfs_getversion(&tgt_dir_ver, dir); 	

	smfs_getversion(&new_dir_ver, dentry->d_inode); 	
	
	error = smfs_journal_mkdir(dentry, &tgt_dir_ver,
			           &new_dir_ver,
                                   dentry->d_inode->i_mode);
	return error;	                                                                                                                                                                                                     
}

