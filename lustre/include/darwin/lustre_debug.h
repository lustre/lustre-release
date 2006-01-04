/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef _DARWIN_LUSTRE_DEBUG_H
#define _DARWIN_LUSTRE_DEBUG_H

#ifndef _LUSTRE_DEBUG_H
#error Do not #include this file directly. #include <lprocfs_status.h> instead
#endif

#ifdef __KERNEL__
#define LL_CDEBUG_PAGE(mask, page, fmt, arg...)   do {} while (0)
#else
#define LL_CDEBUG_PAGE(mask, page, fmt, arg...)   do {} while (0) 
#endif

#endif
