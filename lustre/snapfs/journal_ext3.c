
/*
 * Snapfs. (C) 2000 Peter J. Braam
 */

#define DEBUG_SUBSYSTEM S_SNAP

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/unistd.h>
#include <linux/jbd.h>
#include <linux/ext3_jbd.h>
#include <linux/ext3_fs.h>
#include <linux/snap.h>

#include "snapfs_internal.h" 


#define EXT3_EA_TRANS_BLOCKS EXT3_DATA_TRANS_BLOCKS

/*
 * must follow the changes of ext3_create_indirect() in fs/ext3/snap.c
 */
#define COW_CREDITS (2 * EXT3_EA_TRANS_BLOCKS + 17 + 2 * EXT3_DATA_TRANS_BLOCKS )

/* start the filesystem journal operations */
static void *snap_e3_trans_start(struct inode *inode, int op)
{
	int jblocks;

	/* XXX needs to be fixed up when we get reiserfs support */
	switch (op) {
	case SNAP_OP_CREATE:
		jblocks = COW_CREDITS + EXT3_DATA_TRANS_BLOCKS + 3;
		break;
	case SNAP_OP_LINK:
		jblocks = COW_CREDITS + EXT3_DATA_TRANS_BLOCKS;
		break;
	case SNAP_OP_UNLINK:
		jblocks = COW_CREDITS + EXT3_DELETE_TRANS_BLOCKS;
		break;
	case SNAP_OP_SYMLINK:
		jblocks = COW_CREDITS + EXT3_DATA_TRANS_BLOCKS + 5;
		break;
	case SNAP_OP_MKDIR:
		jblocks = COW_CREDITS + EXT3_DATA_TRANS_BLOCKS + 4;
		break;
	case SNAP_OP_RMDIR:
		jblocks = 2 * COW_CREDITS + EXT3_DELETE_TRANS_BLOCKS;
		break;
	case SNAP_OP_MKNOD:
		jblocks = COW_CREDITS + EXT3_DATA_TRANS_BLOCKS + 3;
		break;
	case SNAP_OP_RENAME:
		jblocks = 4 * COW_CREDITS + 2 * EXT3_DATA_TRANS_BLOCKS + 2;
		break;
	default:
		CDEBUG(D_INODE, "invalid operation %d for journal\n", op);
		return NULL;
	}

	CDEBUG(D_INODE, "creating journal handle (%d blocks)\n", jblocks);
	return ext3_journal_start(inode, jblocks);
}

static void snap_e3_trans_commit(void *handle)
{
	journal_stop(handle);
}

struct journal_ops snap_ext3_journal_ops = {
	snap_e3_trans_start,
	snap_e3_trans_commit
};

