/*
 *  smfs/journal_ext3.c
 *
 */

#define DEBUG_SUBSYSTEM S_SM

#include <linux/kmod.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/smp_lock.h>
#include <linux/lustre_idl.h>
#if defined(CONFIG_EXT3_FS) || defined (CONFIG_EXT3_FS_MODULE)
#include <linux/jbd.h>
#include <linux/ext3_fs.h>
#include <linux/ext3_jbd.h>
#endif
                                                                                                                                                                                                     
#include "smfs_internal.h" 
#include "kml_idl.h" 
                                                                                                                                                                                                     
#if defined(CONFIG_EXT3_FS) || defined (CONFIG_EXT3_FS_MODULE)

#define MAX_PATH_BLOCKS(inode) (PATH_MAX >> EXT3_BLOCK_SIZE_BITS((inode)->i_sb))
#define MAX_NAME_BLOCKS(inode) (NAME_MAX >> EXT3_BLOCK_SIZE_BITS((inode)->i_sb))

static void *smfs_e3_trans_start(struct inode *inode, 
				int op)
{
        
	int trunc_blks, one_path_blks, extra_path_blks;
        int extra_name_blks, lml_blks, jblocks;
        __u32 avail_kmlblocks;
	handle_t *handle;
	
	avail_kmlblocks = inode->i_sb->u.ext3_sb.s_es->s_free_blocks_count;
                                                                                                                                                                                                     
        if ( avail_kmlblocks < 3 ) {
                return ERR_PTR(-ENOSPC);
        }
                                                                                                                                                                                                     
        if ((op != KML_OPCODE_UNLINK && op != KML_OPCODE_RMDIR)
             && avail_kmlblocks < 6 ) {
                return ERR_PTR(-ENOSPC);
        }
        /* Need journal space for:
             at least three writes to KML (two one block writes, one a path)
             possibly a second name (unlink, rmdir)
             possibly a second path (symlink, rename)
             a one block write to the last rcvd file
        */
                                                                                                                                                                                                     
        trunc_blks = EXT3_DATA_TRANS_BLOCKS + 1;
        one_path_blks = 4*EXT3_DATA_TRANS_BLOCKS + MAX_PATH_BLOCKS(inode) + 3;
        lml_blks = 4*EXT3_DATA_TRANS_BLOCKS + MAX_PATH_BLOCKS(inode) + 2;
        extra_path_blks = EXT3_DATA_TRANS_BLOCKS + MAX_PATH_BLOCKS(inode);
        extra_name_blks = EXT3_DATA_TRANS_BLOCKS + MAX_NAME_BLOCKS(inode);
                                                                                                                                                                                                     
        /* additional blocks appear for "two pathname" operations
           and operations involving the LML records
        */

	switch (op) {
	case KML_OPCODE_MKDIR:
		jblocks = one_path_blks + trunc_blks
                          + EXT3_DATA_TRANS_BLOCKS + 4 + 2;
		break;
	default:
		CDEBUG(D_INODE, "invalid operation %d for journal\n", op);
		return NULL;
	}

	CDEBUG(D_INODE, "creating journal handle (%d blocks)\n", jblocks);
        
	lock_kernel();
        handle = journal_start(EXT3_JOURNAL(inode), jblocks);
        unlock_kernel();

	return handle;
}  

static void smfs_e3_trans_commit(void *handle)
{
        lock_kernel();
        journal_stop(handle);
        unlock_kernel();
}

struct journal_operations smfs_ext3_journal_ops = {
        .tr_start   = smfs_e3_trans_start, 
        .tr_commit  = smfs_e3_trans_commit,
};
#endif

