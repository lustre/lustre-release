/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc.
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

#include <linux/module.h>
#include <linux/major.h>
#include <linux/smp.h>

#define DEBUG_SUBSYSTEM S_PTLBD

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>
#include <linux/obd_support.h>

#include <linux/obd_ptlbd.h>

static int __init ptlbd_init(void)
{
        int ret;
        ENTRY;

        ret = ptlbd_cl_init();
        if ( ret < 0 ) 
                RETURN(ret);

        ret = ptlbd_sv_init();
        if ( ret < 0 ) 
                GOTO(out_cl, ret);

        ret = ptlbd_blk_init();
        if ( ret < 0 ) 
                GOTO(out_sv, ret);

        RETURN(0);

out_sv:
        ptlbd_sv_exit();
out_cl:
        ptlbd_cl_exit();
        RETURN(ret);
}

static void __exit ptlbd_exit(void)
{
        ENTRY;
        ptlbd_cl_exit();
        ptlbd_sv_exit();
        ptlbd_blk_exit();
        EXIT;
}

module_init(ptlbd_init);
module_exit(ptlbd_exit);
MODULE_LICENSE("GPL");
