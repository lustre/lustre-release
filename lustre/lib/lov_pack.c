/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2002 Cluster File Systems, Inc. <adilger@clusterfs.com>
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
 * (Un)packing of OST/MDS requests
 *
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_net.h>
#include <linux/obd_support.h>

void lov_packdesc(struct lov_desc *ld)
{
        ld->ld_tgt_count = HTON__u32(ld->ld_tgt_count); 
        ld->ld_default_stripe_count = HTON__u32(ld->ld_default_stripe_count); 
        ld->ld_default_stripe_size = HTON__u32(ld->ld_default_stripe_size); 
        ld->ld_pattern = HTON__u32(ld->ld_pattern); 
}

void lov_unpackdesc(struct lov_desc *ld)
{
        ld->ld_tgt_count = NTOH__u32(ld->ld_tgt_count); 
        ld->ld_default_stripe_count = HTON__u32(ld->ld_default_stripe_count); 
        ld->ld_default_stripe_size = HTON__u32(ld->ld_default_stripe_size); 
        ld->ld_pattern = HTON__u32(ld->ld_pattern); 
}
