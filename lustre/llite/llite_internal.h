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

struct lustre_handle;
struct lov_stripe_md;

int ll_mdc_cancel_unused(struct lustre_handle *conn, struct inode *inode,
                         int flags, void *opaque);
int ll_rd_dirty_pages(char *page, char **start, off_t off, int count,
                      int *eof, void *data);
int ll_rd_max_dirty_pages(char *page, char **start, off_t off, int count,
                          int *eof, void *data);
int ll_wr_max_dirty_pages(struct file *file, const char *buffer,
                          unsigned long count, void *data);
int ll_clear_dirty_pages(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                         unsigned long start, unsigned long end);
int ll_mark_dirty_page(struct lustre_handle *conn, struct lov_stripe_md *lsm,
                       unsigned long index);

#endif /* LLITE_INTERNAL_H */
