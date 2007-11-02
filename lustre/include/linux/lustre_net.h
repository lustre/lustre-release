/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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

#ifndef _LINUX_LUSTRE_NET_H
#define _LINUX_LUSTRE_NET_H

#ifndef _LUSTRE_NET_H
#error Do not #include this file directly. #include <lustre_net.h> instead
#endif

#ifdef __KERNEL__
#include <linux/version.h>
#include <linux/workqueue.h>
#endif

/* XXX Liang: should be moved to other header instead of here */
#ifndef WITH_GROUP_INFO
#define WITH_GROUP_INFO
#endif

#endif
