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

#ifndef _DARWIN_LUSTRE_DLM_H__
#define _DARWIN_LUSTRE_DLM_H__

#ifndef _LUSTRE_DLM_H__
#error Do not #include this file directly. #include <lprocfs_status.h> instead
#endif

#define IT_OPEN     0x0001
#define IT_CREAT    0x0002
#define IT_READDIR  0x0004
#define IT_GETATTR  0x0008
#define IT_LOOKUP   0x0010
#define IT_UNLINK   0x0020
#define IT_GETXATTR 0x0040
#define IT_EXEC     0x0080
#define IT_PIN      0x0100
#define IT_CHDIR    0x0200


#endif
