
/*
 * Snapfs. (C) 2000 Peter J. Braam
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/malloc.h>
#include <linux/vmalloc.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#ifdef CONFIG_SNAPFS_EXT3
#include <linux/ext3_jfs.h>
#endif
#include "linux/filter.h"
#include "linux/snapfs.h"
#include "linux/snapsupport.h"

#ifdef CONFIG_SNAPFS_EXT3

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
		CDEBUG(D_JOURNAL, "invalid operation %d for journal\n", op);
		return NULL;
	}

	CDEBUG(D_JOURNAL, "creating journal handle (%d blocks)\n", jblocks);
	return journal_start(EXT3_JOURNAL(inode), jblocks);
}

static void snap_e3_trans_commit(void *handle)
{
	journal_stop(current->j_handle);
}

struct journal_ops snap_ext3_journal_ops = {
	snap_e3_trans_start,
	snap_e3_trans_commit
};

#endif /* CONFIG_EXT3_FS */
