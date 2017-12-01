/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2017, Intel Corporation.
 *
 * lustre/include/lustre_barrier.h
 *
 * Lustre write barrier (on MDT) exported functions.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LUSTRE_BARRIER_H
# define _LUSTRE_BARRIER_H

#include <dt_object.h>
#include <lustre_export.h>

bool barrier_entry(struct dt_device *key);
void barrier_exit(struct dt_device *key);
int barrier_handler(struct dt_device *key, struct ptlrpc_request *req);
int barrier_register(struct dt_device *key, struct dt_device *next);
void barrier_deregister(struct dt_device *key);

#endif /* _LUSTRE_BARRIER_H */
