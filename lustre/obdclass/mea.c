/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002, 2003 Cluster File Systems, Inc.
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
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#else 
#include <liblustre.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#endif
#include <linux/lprocfs_status.h>


int mea_name2idx(struct mea *mea, char *name, int namelen)
{
        unsigned int c;

	/* just to simplify caller code */
       	if (mea == NULL)
		return 0;

        if (mea->mea_count == 0)
                return 0;

        /* FIXME: real hash calculation here */
        c = name[namelen - 1];
        c = c % mea->mea_count;
	
	LASSERT(c < mea->mea_count);
        return c;
}

int raw_name2idx(int count, char *name, int namelen)
{
        unsigned int c;

        LASSERT(namelen > 0);
        if (count <= 1)
                return 0;


        /* FIXME: real hash calculation here */
        c = name[namelen - 1];
        c = c % count;
	
        return c;
}

