/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2003 Cluster File Systems, Inc.
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 */

#ifndef LLITE_INTERNAL_H
#define LLITE_INTERNAL_H

struct ll_sb_info;

extern void lprocfs_unregister_mountpoint(struct ll_sb_info *sbi);
extern struct proc_dir_entry *proc_lustre_fs_root;

struct lustre_handle;
struct lov_stripe_md;


void ll_remove_dirty(struct inode *inode, unsigned long start,
                     unsigned long end);
int ll_mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                         int flags, void *opaque);
int ll_rd_max_dirty_pages(char *page, char **start, off_t off, int count,
                          int *eof, void *data);
int ll_wr_max_dirty_pages(struct file *file, const char *buffer,
                          unsigned long count, void *data);

extern struct super_operations ll_super_operations;

#endif /* LLITE_INTERNAL_H */
