/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001-2004 Cluster File Systems, Inc. <info@clusterfs.com>
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
 * Filesystem interface helper.
 *
 */

#ifndef _LUSTRE_FSFILT_H
#define _LUSTRE_FSFILT_H

#if defined(__linux__)
#include <linux/lustre_fsfilt.h>
#elif defined(__APPLE__)
#include <darwin/lustre_fsfilt.h>
#elif defined(__WINNT__)
#include <winnt/lustre_fsfilt.h>
#else
#error Unsupported operating system.
#endif

#endif
