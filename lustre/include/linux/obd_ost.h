/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
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
 * Data structures for object storage targets and client: OST & OSC's
 * 
 * See also lustre_idl.h for wire formats of requests.
 *
 */

#ifndef _LUSTRE_OST_H
#define _LUSTRE_OST_H

#include <linux/obd_class.h>

#define LUSTRE_OST_NAME "ost"
#define LUSTRE_OSC_NAME "osc"

/* ost/ost_pack.c */
void ost_pack_niobuf(void **tmp, void *addr, __u64 offset, __u32 len, 
                     __u32 flags, __u32 xid);
void ost_unpack_niobuf(void **tmp, struct niobuf **nbp);
void ost_pack_ioo(void **tmp, struct obdo *oa, int bufcnt);
void ost_unpack_ioo(void **tmp, struct obd_ioobj **ioop);

#endif
