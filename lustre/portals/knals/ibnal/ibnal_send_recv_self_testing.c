/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *  *
 *  * Based on ksocknal, qswnal, and gmnal
 *  *
 *  * Copyright (C) 2003 LANL
 *  *   Author: HB Chen <hbchen@lanl.gov>
 *  *   Los Alamos National Lab
 *  *
 *  *   Portals is free software; you can redistribute it and/or
 *  *   modify it under the terms of version 2 of the GNU General Public
 *  *   License as published by the Free Software Foundation.
 *  *
 *  *   Portals is distributed in the hope that it will be useful,
 *  *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  *   GNU General Public License for more details.
 *  *
 *  *   You should have received a copy of the GNU General Public License
 *  *   along with Portals; if not, write to the Free Software
 *  *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *  *
 *  */

#include "ibnal.h"



VAPI_ret_t ibnal_send_recv_self_testing()
{
 VAPI_ret_t           vstat;
 VAPI_sr_desc_t       sr_desc;
 VAPI_sg_lst_entry_t  sr_sg;
 QP_info              *qp;
 VAPI_wr_id_t         send_id;
 int                  buf_id;
 char                 sbuf[KB_32];
 char                 rbuf[KB_32];
 int                  i;
 int                  buf_length = KB_32;
 VAPI_wc_desc_t       comp_desc;
 int                  num_send = 1;
 int                  loop_count = 0;


 printk("ibnal_send_recv_self_testing\n");

 memset(&sbuf, 'a', KB_32);
 memset(&rbuf, ' ', KB_32);
 
 send_id = 2222; 
 buf_id = 0;

 qp = &QP_list[0];

 sr_desc.opcode    = VAPI_SEND;
 sr_desc.comp_type = VAPI_SIGNALED;

 // scatter and gather info
 sr_sg.len  = KB_32;
 sr_sg.lkey = MSbuf_list[buf_id].mr.l_key; // use send MR
 sr_sg.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MSbuf_list[buf_id].buf_addr;

 // copy data to register send buffer
 memcpy(&sr_sg.addr, &buf, buf_length);

 sr_desc.sg_lst_p = &sr_sg;
 sr_desc.sg_lst_len = 1; // only 1 entry is used
 sr_desc.fence = TRUE;
 sr_desc.set_se = FALSE;


 // call VAPI_post_sr to send out this data
 vstat = VAPI_post_sr(qp->hca_hndl, qp->qp_hndl, &sr_desc);

 if (vstat != VAPI_OK) {
   printk("VAPI_post_sr failed (%s).\n",VAPI_strerror(vstat));
 }

 printk("VAPI_post_sr success.\n");

 // poll for completion

 while( loop_count < 100 ){
   vstat = VAPI_poll_cq(qp->hca_hndl, qp->cq_hndl, &comp_desc);
   if( vstat == VAPI_OK ) {
       if(comp_desc.opcode == VAPI_CQE_SQ_SEND_DATA ) {
          /* SEND completion */
         printk("received SQ completion\n");
       }
       else { 
          if(comp_desc.opcode == VAPI_CQE_RQ_SEND_DATA ) {
	    /* RECEIVE completion */
            printk("received RQ completion\n");
            memcpy(&rbuf, (char *) MRbuf_list[buf_id].buf_addar, KB_32);
	    
	    int n;

	    n = memcmp($sbuf, &rbuf, KB_32);
	    printk("compare sbuf and rbuf  n = %d\n", n); 
	    
          }
       	  else  {
            printk("unexpected completion opcode %d \n", comp_desc.opcode);
	  }
       }
   }

   loop_count++; 
   schedule_timeout(500);
 }

 printk("end of ibnal_self_send_recv_testing\n");


}
