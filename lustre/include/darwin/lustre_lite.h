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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/include/darwin/lustre_lite.h
 *
 * lustre lite cluster file system
 */

#ifndef _DARWIN_LL_H
#define _DARWIN_LL_H

#ifndef _LL_H
#error Do not #include this file directly. #include <lustre_lite.h> instead
#endif

#include <libcfs/libcfs.h>

#ifdef __KERNEL__

struct iattr {
        unsigned int    ia_valid;
        umode_t         ia_mode;
        uid_t           ia_uid;
        gid_t           ia_gid;
        loff_t          ia_size;
        time_t          ia_atime;
        time_t          ia_mtime;
        time_t          ia_ctime;
        unsigned int    ia_attr_flags;
};

#define INTENT_MAGIC 0x19620323 /* Happy birthday! */

struct lustre_intent_data {
        int     it_disposition;
        int     it_status;
        __u64   it_lock_handle;
        void    *it_data;
        int     it_lock_mode;
};

/*
 * Liang: We keep the old lookup_intent struct in XNU 
 * to avoid unnecessary allocate/free. 
 */
#define LUSTRE_IT(it) ((struct lustre_intent_data *)(&(it)->d.lustre))

struct lookup_intent {
	int     it_magic;
	void    (*it_op_release)(struct lookup_intent *);
	int     it_op;
	int     it_create_mode;
	__u64   it_flags;
	union {
                struct lustre_intent_data lustre;
		void *fs_data;
	} d;
};

struct super_operations{
};
#endif

#endif
