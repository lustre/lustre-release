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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

# define DEBUG_SUBSYSTEM S_LNET

#include <linux/fs.h>
#include <linux/kdev_t.h>
#include <linux/ctype.h>
#include <asm/uaccess.h>

#include <libcfs/libcfs.h>

/* write a userspace buffer to disk.
 * NOTE: this returns 0 on success, not the number of bytes written. */
ssize_t
filp_user_write(struct file *filp, const void *buf, size_t count,
		loff_t *offset)
{
	mm_segment_t fs;
	ssize_t size = 0;

	fs = get_fs();
	set_fs(KERNEL_DS);
	while ((ssize_t)count > 0) {
		size = vfs_write(filp, (const void __user *)buf, count, offset);
		if (size < 0)
			break;
		count -= size;
                buf += size;
		size = 0;
	}
	set_fs(fs);

	return size;
}
EXPORT_SYMBOL(filp_user_write);
