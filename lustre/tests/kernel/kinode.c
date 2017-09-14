/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */

/*
 * Copyright 2017 Cray Inc. All rights reserved.
 * Author: Frank Zago.
 */

/* Check that the inode number is the same whether the call to
 * vfs_getattr is coming from a system call or from a kthread. When
 * CONFIG_X86_X32 was set, the result used to be different for
 * Lustre. In addition, a user can also check that the same inode
 * number is also seen from the kernel and userspace.  */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/fs.h>
#include <linux/version.h>

/* Random ID passed by userspace, and printed in messages, used to
 * separate different runs of that module. */
static int run_id;
module_param(run_id, int, 0644);
MODULE_PARM_DESC(run_id, "run ID");

/* Name of the file to stat. */
static char fname[4096];
module_param_string(fname, fname, sizeof(fname), 0644);
MODULE_PARM_DESC(fname, "name of file to stat");

struct completion thr_start;

#define PREFIX "lustre_kinode_%u:"

static int stat_file(struct kstat *stbuf)
{
	struct file *fd;
	int rc;

	fd = filp_open(fname, O_RDONLY, 0);
	if (IS_ERR(fd)) {
		pr_err(PREFIX " can't open file %s\n", run_id, fname);
		return -EIO;
	}

#ifdef HAVE_INODEOPS_ENHANCED_GETATTR
	rc = vfs_getattr(&fd->f_path, stbuf, STATX_INO, AT_STATX_SYNC_AS_STAT);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	rc = vfs_getattr(&fd->f_path, stbuf);
#else
	rc = vfs_getattr(fd->f_path.mnt, fd->f_path.dentry, stbuf);
#endif
	if (rc != 0) {
		pr_err(PREFIX " vfs_getattr failed: %d\n", run_id, rc);
		goto out;
	}

	pr_err(PREFIX " inode is %llu\n", run_id, stbuf->ino);
	rc = 0;

out:
	filp_close(fd, NULL);

	return rc;
}

static int stat_thread(void *data)
{
	struct kstat *stbuf = data;
	int rc;

	/* Signal caller that thread has started. */
	complete(&thr_start);

	rc = stat_file(stbuf);

	/* Wait for call to kthread_stop. */
	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		schedule();
		set_current_state(TASK_INTERRUPTIBLE);
	}
	set_current_state(TASK_RUNNING);

	return rc;
}

static int __init kinode_init(void)
{
	struct task_struct *thr;
	struct kstat stbuf1;
	struct kstat stbuf2;
	int rc;

#ifdef CONFIG_X86_X32
	pr_err(PREFIX " CONFIG_X86_X32 is set\n", run_id);
#else
	pr_err(PREFIX " CONFIG_X86_X32 is not set\n", run_id);
#endif

	if (strlen(fname) < 1) {
		pr_err(PREFIX " invalid file name '%s'\n", run_id, fname);
		goto out;
	}

	rc = stat_file(&stbuf1);
	if (rc) {
		pr_err(PREFIX " direct stat failed: %d\n", run_id, rc);
		goto out;
	}

	/* Run the same from a kthread. */
	init_completion(&thr_start);
	thr = kthread_run(stat_thread, &stbuf2, "kinode_%u", run_id);
	if (IS_ERR(thr)) {
		pr_err(PREFIX " Cannot create kthread\n", run_id);
		goto out;
	}

	/* Wait for the thread to start, then wait for it to
	 * terminate. */
	wait_for_completion(&thr_start);
	rc = kthread_stop(thr);
	if (rc) {
		pr_err(PREFIX " indirect stat failed: %d\n", run_id, rc);
		goto out;
	}

	if (stbuf1.ino != stbuf2.ino)
		pr_err(PREFIX " inode numbers are different: %llu %llu\n",
		       run_id, stbuf1.ino, stbuf2.ino);
	else
		pr_err(PREFIX " inode numbers are identical: %llu\n",
		       run_id, stbuf1.ino);

out:
	/* Don't load. */
	return -EINVAL;
}

static void __exit kinode_exit(void)
{
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre inode stat test module");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(kinode_init);
module_exit(kinode_exit);
