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

void lov_packmd(struct lov_mds_md *mdsmd, struct lov_stripe_md *md)
{
        int i;
        mdsmd->lmd_magic = md->lmd_magic;
        mdsmd->lmd_easize = md->lmd_easize;
        mdsmd->lmd_object_id = md->lmd_object_id;
        mdsmd->lmd_stripe_offset = md->lmd_stripe_offset;
        mdsmd->lmd_stripe_count = md->lmd_stripe_count;
        mdsmd->lmd_stripe_size = md->lmd_stripe_size;
        mdsmd->lmd_stripe_pattern = md->lmd_stripe_pattern;
        
        for (i=0; i<md->lmd_stripe_count; i++) 
                mdsmd->lmd_objects[i].l_object_id = md->lmd_oinfo[i].loi_id;
}

void lov_unpackmd(struct lov_stripe_md *md, struct lov_mds_md *mdsmd)
{
        int i;
        md->lmd_magic = mdsmd->lmd_magic;
        md->lmd_easize = mdsmd->lmd_easize;
        md->lmd_object_id = mdsmd->lmd_object_id;
        md->lmd_stripe_offset = mdsmd->lmd_stripe_offset;
        md->lmd_stripe_count = mdsmd->lmd_stripe_count;
        md->lmd_stripe_size = mdsmd->lmd_stripe_size;
        md->lmd_stripe_pattern = mdsmd->lmd_stripe_pattern;
        
        for (i=0; i<md->lmd_stripe_count; i++) 
                md->lmd_oinfo[i].loi_id = mdsmd->lmd_objects[i].l_object_id; 
}
