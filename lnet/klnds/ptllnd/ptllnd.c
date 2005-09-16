/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
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

#include "ptllnd.h"

lnet_handle_ni_t nih;


void __exit
kptllnd_module_fini (void)
{
        PJK_UT_MSG(">>> %s %s\n",__DATE__,__TIME__);
        PtlNIFini(nih);
        PJK_UT_MSG("<<<\n");
}

int __init
kptllnd_module_init (void)
{
        int    rc = 0;
        lnet_process_id_t portals_id;
        PJK_UT_MSG(">>> %s %s\n",__DATE__,__TIME__);
        
        PJK_UT_MSG("PtlNIInit\n");
        rc = PtlNIInit(PTL_IFACE_DEFAULT, 0, NULL, NULL, &nih);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP){
                /*CERROR ("PtlNIInit: error %d\n", rc);*/
                goto failed;
        }
                
        PJK_UT_MSG("PtlGetId\n");
        if(rc != PtlGetId(nih,&portals_id)){
                /*CERROR ("PtlGetID: error %d\n", rc);*/
        }else{
                PJK_UT_MSG("ptl nid=" LPX64 "\n",portals_id.nid);
        }                
      
failed:                
        PJK_UT_MSG("<<<\n");
        return rc;
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel Portals LND v1.00");
/*MODULE_LICENSE("GPL");*/

module_init(kptllnd_module_init);
module_exit(kptllnd_module_fini);
