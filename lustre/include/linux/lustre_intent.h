/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef LUSTRE_INTENT_H
#define LUSTRE_INTENT_H

#include <linux/lustre_version.h>

#ifndef HAVE_VFS_INTENT_PATCHES
#define IT_OPEN     (1)
#define IT_CREAT    (1<<1)
#define IT_READDIR  (1<<2)
#define IT_GETATTR  (1<<3)
#define IT_LOOKUP   (1<<4)
#define IT_UNLINK   (1<<5)
#define IT_TRUNC    (1<<6)
#define IT_GETXATTR (1<<7)

struct lustre_intent_data {
        int       it_disposition;
        int       it_status;
        __u64     it_lock_handle;
        void     *it_data;
        int       it_lock_mode;
};

struct lookup_intent {
        int     it_op;
        int     it_flags;
	int     it_create_mode;
        union {
                struct lustre_intent_data lustre;
        } d;
};


#endif
#endif
