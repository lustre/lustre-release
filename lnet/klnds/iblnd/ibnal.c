/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Based on ksocknal, qswnal, and gmnal
 *
 * Copyright (C) 2003 LANL 
 *   Author: HB Chen <hbchen@lanl.gov>
 *   Los Alamos National Lab
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *   
 */

#include "ibnal.h"

// portal handle ID for this IB-NAL
ptl_handle_ni_t kibnal_ni;

// message send buffer mutex
spinlock_t   MSBuf_mutex[NUM_MBUF];

// message recv buffer mutex
spinlock_t   MRBuf_mutex[NUM_MBUF];

// IB-NAL API information 
nal_t  kibnal_api; 

// nal's private data 
kibnal_data_t kibnal_data; 

int ibnal_debug = 0;
VAPI_pd_hndl_t      Pd_hndl;    
unsigned int    Num_posted_recv_buf;

// registered send buffer list
Memory_buffer_info MSbuf_list[NUM_MBUF]; 

// registered recv buffer list 
Memory_buffer_info MRbuf_list[NUM_MBUF];

//
// for router 
// currently there is no need fo IBA  
//
kpr_nal_interface_t kibnal_router_interface = {
        kprni_nalid: IBNAL,
        kprni_arg:   &kibnal_data,
        kprni_fwd:   kibnal_fwd_packet, // forward data to router  
                                        // is router invloving the
                                        // data transmision 
};


// Queue-pair list 
QP_info QP_list[NUM_QPS];

// information associated with a HCA 
HCA_info        Hca_data;

// something about HCA 
VAPI_hca_hndl_t      Hca_hndl; // assume we only use one HCA now 
VAPI_hca_vendor_t    Hca_vendor;
VAPI_hca_cap_t       Hca_cap;
VAPI_hca_port_t      Hca_port_1_props;
VAPI_hca_port_t      Hca_port_2_props;
VAPI_hca_attr_t      Hca_attr;
VAPI_hca_attr_mask_t Hca_attr_mask;
VAPI_cq_hndl_t       Cq_RQ_hndl;    // CQ's handle
VAPI_cq_hndl_t       Cq_SQ_hndl;    // CQ's handle
VAPI_cq_hndl_t       Cq_hndl;    // CQ's handle
Remote_QP_Info       L_QP_data;
Remote_QP_Info       R_QP_data;


//
// forward  API
//
int 
kibnal_forward(nal_t   *nal,
               int     id,
               void    *args,  
               size_t args_len,
               void    *ret,   
               size_t ret_len)
{
        kibnal_data_t *knal_data = nal->nal_data;
        nal_cb_t      *nal_cb = knal_data->kib_cb;

        // ASSERT checking 
        LASSERT (nal == &kibnal_api);
        LASSERT (knal_data == &kibnal_data);
        LASSERT (nal_cb == &kibnal_lib);

        // dispatch forward API function 
        
        CDEBUG(D_NET,"kibnal_forward: function id = %d\n", id);

        lib_dispatch(nal_cb, knal_data, id, args, ret); 

        CDEBUG(D_TRACE,"IBNAL- Done kibnal_forward\n");

        return PTL_OK; // always return PTL_OK
}

//
// lock API  
//
void 
kibnal_lock(nal_t *nal, unsigned long *flags)
{
        kibnal_data_t *knal_data = nal->nal_data;
        nal_cb_t      *nal_cb = knal_data->kib_cb;

        // ASSERT checking 
        LASSERT (nal == &kibnal_api);
        LASSERT (knal_data == &kibnal_data);
        LASSERT (nal_cb == &kibnal_lib);

        // disable logical interrrupt 
        nal_cb->cb_cli(nal_cb,flags);

        CDEBUG(D_TRACE,"IBNAL-Done kibnal_lock\n");

}

//
// unlock API
//
void 
kibnal_unlock(nal_t *nal, unsigned long *flags)
{
        kibnal_data_t *k = nal->nal_data;
        nal_cb_t      *nal_cb = k->kib_cb;

        // ASSERT checking
        LASSERT (nal == &kibnal_api);
        LASSERT (k == &kibnal_data);
        LASSERT (nal_cb == &kibnal_lib);

        // enable logical interrupt 
        nal_cb->cb_sti(nal_cb,flags);

        CDEBUG(D_TRACE,"IBNAL-Done kibnal_unlock");

}

//
// shutdown API 
//     showdown this network interface 
//
int
kibnal_shutdown(nal_t *nal, int ni)
{       
        VAPI_ret_t          vstat;
        kibnal_data_t *k = nal->nal_data;
        nal_cb_t      *nal_cb = k->kib_cb;

        // assert checking
        LASSERT (nal == &kibnal_api);
        LASSERT (k == &kibnal_data);
        LASSERT (nal_cb == &kibnal_lib);

        // take down this IB network interface 
        // there is not corresponding cb function to hande this
        // do we actually need this one 
        // reference to IB network interface shutdown 
        //
        
        vstat = IB_Close_HCA();

        if (vstat != VAPI_OK) {
           CERROR("Failed to close HCA  - %s\n",VAPI_strerror(vstat));
           return (~PTL_OK);
        }

        CDEBUG(D_TRACE,"IBNAL- Done kibnal_shutdown\n");

        return PTL_OK;
}

//
// yield 
// when do we call this yield function 
//
void 
kibnal_yield( nal_t *nal )
{
        kibnal_data_t *k = nal->nal_data;
        nal_cb_t      *nal_cb = k->kib_cb;
        
        // assert checking
        LASSERT (nal == &kibnal_api);
        LASSERT (k    == &kibnal_data);
        LASSERT (nal_cb == &kibnal_lib);

        // check under what condition that we need to 
        // call schedule()
        // who set this need_resched 
        if (current->need_resched)
                schedule();

        CDEBUG(D_TRACE,"IBNAL-Done kibnal_yield");

        return;
}

//
// ibnal init 
//
nal_t *
kibnal_init(int             interface, // no use here 
            ptl_pt_index_t  ptl_size,
            ptl_ac_index_t  ac_size, 
            ptl_pid_t       requested_pid // no use here
           )
{
  nal_t         *nal       = NULL;
  nal_cb_t      *nal_cb    = NULL;
  kibnal_data_t *nal_data  = NULL;
  int            rc;

  unsigned int nnids = 1; // number of nids 
                          // do we know how many nodes are in this
                          // system related to this kib_nid  
                          //

  CDEBUG(D_NET, "kibnal_init:calling lib_init with nid 0x%u\n",
                  kibnal_data.kib_nid);


  CDEBUG(D_NET, "kibnal_init: interface [%d], ptl_size [%d], ac_size[%d]\n", 
                 interface, ptl_size, ac_size);
  CDEBUG(D_NET, "kibnal_init: &kibnal_lib  0x%X\n", &kibnal_lib);
  CDEBUG(D_NET, "kibnal_init: kibnal_data.kib_nid  %d\n", kibnal_data.kib_nid);

  rc = lib_init(&kibnal_lib, 
                kibnal_data.kib_nid, 
                0, // process id is set as 0  
                nnids,
                ptl_size, 
                ac_size);

  if(rc != PTL_OK) {
     CERROR("kibnal_init: Failed lib_init with nid 0x%u, rc=%d\n",
                                  kibnal_data.kib_nid,rc);
  }
  else {
      CDEBUG(D_NET,"kibnal_init: DONE lib_init with nid 0x%x%x\n",
                                  kibnal_data.kib_nid);
  }

  return &kibnal_api;

}


//
// called before remove ibnal kernel module 
//
void __exit 
kibnal_finalize(void) 
{ 
        struct list_head *tmp;

        inter_module_unregister("kibnal_ni");

        // release resources allocated to this Infiniband network interface 
        PtlNIFini(kibnal_ni); 

        lib_fini(&kibnal_lib); 

        IB_Close_HCA();

        // how much do we need to do here?
        list_for_each(tmp, &kibnal_data.kib_list) {
                kibnal_rx_t *conn;
                conn = list_entry(tmp, kibnal_rx_t, krx_item);
                CDEBUG(D_IOCTL, "freeing conn %p\n",conn);
                tmp = tmp->next;
                list_del(&conn->krx_item);
                PORTAL_FREE(conn, sizeof(*conn));
        }

        CDEBUG(D_MALLOC,"done kmem %d\n",atomic_read(&portal_kmemory));
        CDEBUG(D_TRACE,"IBNAL-Done kibnal_finalize\n");

        return;
}


//
// * k_server_thread is a kernel thread 
//   use a shared memory ro exchange HCA's data with a pthread in user 
//   address space
// * will be replaced when CM is used to handle communication management 
//

void k_server_thread(Remote_QP_Info *hca_data)
{
  int              segment_id;
  const int        shared_segment_size = sizeof(Remote_QP_Info); 
  key_t            key = HCA_EXCHANGE_SHM_KEY;
  unsigned long    raddr;
  int exchanged_done = NO;
  int i;

  Remote_QP_Info  *exchange_hca_data;

  long *n;
  long *uaddr;
  long ret = 0;
 
  // create a shared memory with pre-agreement key
  segment_id =  sys_shmget(key,
                           shared_segment_size,
                           IPC_CREAT | 0666);


  // attached to shared memoru 
  // raddr is pointed to an user address space 
  // use this address to update shared menory content 
  ret = sys_shmat(segment_id, 0 , SHM_RND, &raddr);

#ifdef IBNAL_DEBUG 
  if(ret >= 0) {
    CDEBUG(D_NET,"k_server_thread: Shared memory attach success ret = 0X%d,&raddr"
                   " 0X%x (*(&raddr))=0x%x \n", ret, &raddr,  (*(&raddr)));
    printk("k_server_thread: Shared memory attach success ret = 0X%d, &raddr"
                   " 0X%x (*(&raddr))=0x%x \n", ret, &raddr,  (*(&raddr)));
  }
  else {
    CERROR("k_server_thread: Shared memory attach failed ret = 0x%d \n", ret); 
    printk("k_server_thread: Shared memory attach failed ret = 0x%d \n", ret); 
    return;
  }
#endif

  n = &raddr;
  uaddr = *n; // get the U-address 
  /* cast uaddr to exchange_hca_data */
  exchange_hca_data = (Remote_QP_Info  *) uaddr; 
  
  /* copy data from local HCA to shared memory */
  exchange_hca_data->opcode  = hca_data->opcode;
  exchange_hca_data->length  = hca_data->length;

  for(i=0; i < NUM_QPS; i++) {
    exchange_hca_data->dlid[i]    = hca_data->dlid[i];
    exchange_hca_data->rqp_num[i] = hca_data->rqp_num[i];
  }

  // periodically check shared memory until get updated 
  // remote HCA's data from user mode pthread  
  while(exchanged_done == NO) {
    if(exchange_hca_data->opcode == RECV_QP_INFO){
       exchanged_done = YES;
       /* copy data to local buffer from shared memory */
       hca_data->opcode  = exchange_hca_data->opcode;
       hca_data->length  = exchange_hca_data->length;

       for(i=0; i < NUM_QPS; i++) {
         hca_data->dlid[i]    = exchange_hca_data->dlid[i];
         hca_data->rqp_num[i] = exchange_hca_data->rqp_num[i];
       }
       break;
    }
    else { 
       schedule_timeout(1000);
    }
  }
  
  // detached shared memory 
  sys_shmdt(uaddr);

  CDEBUG(D_NET, "Exit from kernel thread: k_server_thread \n");
  printk("Exit from kernel thread: k_server_thread \n");

  return;

}

//
// create QP 
// 
VAPI_ret_t 
create_qp(QP_info *qp, int qp_index)
{

  VAPI_ret_t          vstat;
  VAPI_qp_init_attr_t qp_init_attr;
  VAPI_qp_prop_t      qp_prop;

  qp->hca_hndl = Hca_hndl;
  qp->port     = 1; // default 
  qp->slid     = Hca_port_1_props.lid;
  qp->hca_port = Hca_port_1_props;


  /* Queue Pair Creation Attributes */
  qp_init_attr.cap.max_oust_wr_rq = NUM_WQE;
  qp_init_attr.cap.max_oust_wr_sq = NUM_WQE;
  qp_init_attr.cap.max_sg_size_rq = NUM_SG;
  qp_init_attr.cap.max_sg_size_sq = NUM_SG;
  qp_init_attr.pd_hndl            = qp->pd_hndl;
  qp_init_attr.rdd_hndl           = 0;
  qp_init_attr.rq_cq_hndl         = qp->rq_cq_hndl;
  /* we use here polling */
  //qp_init_attr.rq_sig_type        = VAPI_SIGNAL_REQ_WR;
  qp_init_attr.rq_sig_type        = VAPI_SIGNAL_ALL_WR;
  qp_init_attr.sq_cq_hndl         = qp->sq_cq_hndl;
  /* we use here polling */
  //qp_init_attr.sq_sig_type        = VAPI_SIGNAL_REQ_WR;
  qp_init_attr.sq_sig_type        = VAPI_SIGNAL_ALL_WR;
  // transport servce - reliable connection

  qp_init_attr.ts_type            = VAPI_TS_RC;
          
  vstat = VAPI_create_qp(qp->hca_hndl,   
                         &qp_init_attr,      
                         &qp->qp_hndl, &qp_prop); 

  if (vstat != VAPI_OK) {
     CERROR("Failed creating QP. Return Failed - %s\n",VAPI_strerror(vstat));
     return vstat;
  }
  
  qp->qp_num = qp_prop.qp_num; // the qp number 
  qp->last_posted_send_id  = 0; // user defined work request ID
  qp->last_posted_rcv_id   = 0; // user defined work request ID
  qp->cur_send_outstanding = 0;
  qp->cur_posted_rcv_bufs  = 0;
  qp->snd_rcv_balance      = 0;
  
  CDEBUG(D_OTHER, "create_qp: qp_num = %d, slid = %d, qp_hndl = 0X%X", 
                  qp->qp_num, qp->slid, qp->qp_hndl);

  // initialize spin-lock mutex variables
  spin_lock_init(&(qp->snd_mutex));
  spin_lock_init(&(qp->rcv_mutex));
  spin_lock_init(&(qp->bl_mutex));
  spin_lock_init(&(qp->cln_mutex));
  // number of outstanding requests on the send Q
  qp->cur_send_outstanding = 0; 
  // number of posted receive buffers
  qp->cur_posted_rcv_bufs  = 0;  
  qp->snd_rcv_balance      = 0;

  return(VAPI_OK);

}

//
// initialize a UD qp state to RTR and RTS 
//
VAPI_ret_t 
init_qp_UD(QP_info *qp, int qp_index)
{
  VAPI_qp_attr_t      qp_attr;
  VAPI_qp_init_attr_t qp_init_attr;
  VAPI_qp_attr_mask_t qp_attr_mask;
  VAPI_qp_cap_t       qp_cap;
  VAPI_ret_t       vstat;

  /* Move from RST to INIT */
  /* Change QP to INIT */

  CDEBUG(D_OTHER, "Changing QP state to INIT qp-index = %d\n", qp_index);

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state = VAPI_INIT;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.pkey_ix  = 0;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PKEY_IX);

  CDEBUG(D_OTHER, "pkey_ix qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.port     = qp->port;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PORT);

  CDEBUG(D_OTHER, "port qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.qkey = 0;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QKEY);

  CDEBUG(D_OTHER, "qkey qp_attr_mask = 0X%x\n", qp_attr_mask);

  /* If I do not set this mask, I get an error from HH. QPM should catch it */

  vstat = VAPI_modify_qp(qp->hca_hndl,
                         qp->qp_hndl,
                         &qp_attr,
                         &qp_attr_mask,
                         &qp_cap);

  if (vstat != VAPI_OK) {
     CERROR("Failed modifying QP from RST to INIT. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  CDEBUG(D_OTHER, "Modifying QP from RST to INIT.\n");

  vstat= VAPI_query_qp(qp->hca_hndl,
                       qp->qp_hndl,
                       &qp_attr,
                       &qp_attr_mask,
                       &qp_init_attr);

  if (vstat != VAPI_OK) {
     CERROR("Failed query QP. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  /* Move from INIT to RTR */
  /* Change QP to RTR */
  CDEBUG(D_OTHER, "Changing QP state to RTR\n");

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state         = VAPI_RTR;  
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);

  CDEBUG(D_OTHER, "INIT to RTR- qp_state : qp_attr_mask = 0X%x\n", qp_attr_mask);

  vstat = VAPI_modify_qp(qp->hca_hndl,
                         qp->qp_hndl,
                         &qp_attr,
                         &qp_attr_mask,
                         &qp_cap);

  if (vstat != VAPI_OK) {
     CERROR("Failed modifying QP from INIT to RTR. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }
  
  CDEBUG(D_OTHER, "Modifying QP from INIT to RTR.\n");
  
  vstat= VAPI_query_qp(qp->hca_hndl,
                       qp->qp_hndl,
                       &qp_attr,
                       &qp_attr_mask,
                       &qp_init_attr);

  if (vstat != VAPI_OK) {
     CERROR("Failed query QP. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }
                                      
  /* RTR to RTS - Change QP to RTS */
  CDEBUG(D_OTHER, "Changing QP state to RTS\n");

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state        = VAPI_RTS;   
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);
  
  qp_attr.sq_psn          = START_SQ_PSN;          
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_SQ_PSN);
  
  vstat = VAPI_modify_qp(qp->hca_hndl,
                         qp->qp_hndl,
                         &qp_attr,
                         &qp_attr_mask,
                         &qp_cap);

  if (vstat != VAPI_OK) {
     CERROR("Failed modifying QP from RTR to RTS. %s:%s\n",
                          VAPI_strerror_sym(vstat), 
                          VAPI_strerror(vstat));
     return(vstat);
  }

  CDEBUG(D_OTHER, "Modifying QP from RTR to RTS. \n");
                     
  vstat= VAPI_query_qp(qp->hca_hndl,
                       qp->qp_hndl,
                       &qp_attr,
                       &qp_attr_mask,
                       &qp_init_attr);

  if (vstat != VAPI_OK) {
     CERROR("Failed query QP. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }
                        
  //
  // a QP is at RTS state NOW
  //
 
  CDEBUG(D_OTHER, "IBNAL- UD qp is at RTS NOW\n");
  
  return(vstat);

}



//
// initialize a RC qp state to RTR and RTS 
// RC transport service 
//
VAPI_ret_t 
init_qp_RC(QP_info *qp, int qp_index)
{
  VAPI_qp_attr_t      qp_attr;
  VAPI_qp_init_attr_t qp_init_attr;
  VAPI_qp_attr_mask_t qp_attr_mask;
  VAPI_qp_cap_t       qp_cap;
  VAPI_ret_t       vstat;

  /* Move from RST to INIT */
  /* Change QP to INIT */
  
  CDEBUG(D_OTHER, "Changing QP state to INIT qp-index = %d\n", qp_index);

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state = VAPI_INIT;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);

   CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.pkey_ix  = 0;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PKEY_IX);

  CDEBUG(D_OTHER, "pkey_ix qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.port     = qp->port;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PORT);

  CDEBUG(D_OTHER, "port qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.remote_atomic_flags = VAPI_EN_REM_WRITE | VAPI_EN_REM_READ;
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_REMOTE_ATOMIC_FLAGS);

  CDEBUG(D_OTHER, "remote_atomic_flags qp_attr_mask = 0X%x\n", qp_attr_mask);

  /* If I do not set this mask, I get an error from HH. QPM should catch it */

  vstat = VAPI_modify_qp(qp->hca_hndl,
                         qp->qp_hndl,
                         &qp_attr,
                         &qp_attr_mask,
                         &qp_cap);

  if (vstat != VAPI_OK) {
     CERROR("Failed modifying QP from RST to INIT. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  vstat= VAPI_query_qp(qp->hca_hndl,
                       qp->qp_hndl,
                       &qp_attr,
                       &qp_attr_mask,
                       &qp_init_attr);

  if (vstat != VAPI_OK) {
     CERROR("Failed query QP. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  /* Move from INIT to RTR */
  /* Change QP to RTR */
  CDEBUG(D_OTHER, "Changing QP state to RTR qp_indexi %d\n", qp_index);

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);
  qp_attr.qp_state         = VAPI_RTR;  

  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.av.sl            = 0;/* RESPONDER_SL */
  qp_attr.av.grh_flag      = FALSE;
  qp_attr.av.dlid          = qp->dlid;/*RESPONDER_LID;*/
  qp_attr.av.static_rate   = 0;
  qp_attr.av.src_path_bits = 0;              
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_AV);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.path_mtu         = MTU_2048;// default is MTU_2048             
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PATH_MTU);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.rq_psn           = START_RQ_PSN;              
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_RQ_PSN);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.qp_ous_rd_atom   = NUM_WQE;        
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_OUS_RD_ATOM);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.pkey_ix          = 0;              
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_PKEY_IX);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.min_rnr_timer    = 10;              
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_MIN_RNR_TIMER);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  qp_attr.dest_qp_num = qp->rqp_num;                   

  CDEBUG(D_OTHER, "remore qp num %d\n",  qp->rqp_num);

  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_DEST_QP_NUM);

  CDEBUG(D_OTHER, "qp_state qp_attr_mask = 0X%x\n", qp_attr_mask);

  vstat = VAPI_modify_qp(qp->hca_hndl,
                         qp->qp_hndl,
                         &qp_attr,
                         &qp_attr_mask,
                         &qp_cap);


  if (vstat != VAPI_OK) {
     CERROR("Failed modifying QP from INIT to RTR. qp_index %d - %s\n",
                                                qp_index, VAPI_strerror(vstat));
     return(vstat);
  }
  
  vstat= VAPI_query_qp(qp->hca_hndl,
                       qp->qp_hndl,
                       &qp_attr,
                       &qp_attr_mask,
                       &qp_init_attr);

  if (vstat != VAPI_OK) {
     CERROR("Failed query QP. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }
                                      
  /* RTR to RTS - Change QP to RTS */
  CDEBUG(D_OTHER, "Changing QP state to RTS\n");

  QP_ATTR_MASK_CLR_ALL(qp_attr_mask);

  qp_attr.qp_state        = VAPI_RTS;   
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_QP_STATE);

  qp_attr.sq_psn          = START_SQ_PSN;          
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_SQ_PSN);

  qp_attr.timeout         = 0x18;         
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_TIMEOUT);

  qp_attr.retry_count     = 10;         
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_RETRY_COUNT);

  qp_attr.rnr_retry       = 14;         
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_RNR_RETRY);

  qp_attr.ous_dst_rd_atom = 100;        
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_OUS_DST_RD_ATOM);

  qp_attr.min_rnr_timer   = 5;          
  QP_ATTR_MASK_SET(qp_attr_mask,QP_ATTR_MIN_RNR_TIMER);

  vstat = VAPI_modify_qp(qp->hca_hndl,
                         qp->qp_hndl,
                         &qp_attr,
                         &qp_attr_mask,
                         &qp_cap);

  if (vstat != VAPI_OK) {
     CERROR("Failed modifying QP from RTR to RTS. %s:%s\n",
                   VAPI_strerror_sym(vstat), VAPI_strerror(vstat));
     return(vstat);
  }

  vstat= VAPI_query_qp(qp->hca_hndl,
                       qp->qp_hndl,
                       &qp_attr,
                       &qp_attr_mask,
                       &qp_init_attr);

  if (vstat != VAPI_OK) {
     CERROR("Failed query QP. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }
                        
  //
  // a QP is at RTS state NOW
  //
 
   CDEBUG(D_OTHER, "IBNAL- RC qp is at RTS NOW\n");
  
  return(vstat);
}



VAPI_ret_t 
IB_Open_HCA(kibnal_data_t *kib_data)
{

  VAPI_ret_t     vstat;
  VAPI_cqe_num_t cqe_active_num;
  QP_info        *qp; 
  int            i;
  int            Num_posted_recv_buf;

  /* Open HCA */
  CDEBUG(D_PORTALS, "Opening an HCA\n");

  vstat = VAPI_open_hca(HCA_ID, &Hca_hndl);
  vstat = EVAPI_get_hca_hndl(HCA_ID, &Hca_hndl);
  if (vstat != VAPI_OK) {
     CERROR("Failed opening the HCA: %s. %s...\n",HCA_ID,VAPI_strerror(vstat));
     return(vstat);
  } 

  /* Get HCA CAP */
  vstat = VAPI_query_hca_cap(Hca_hndl, &Hca_vendor, &Hca_cap);
  if (vstat != VAPI_OK) {
     CERROR("Failed query hca cap %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  /* Get port 1 info */
  vstat = VAPI_query_hca_port_prop(Hca_hndl, HCA_PORT_1 , &Hca_port_1_props);
  if (vstat != VAPI_OK) {
     CERROR("Failed query port cap %s\n",VAPI_strerror(vstat));
     return(vstat);
  }      

  /* Get port 2 info */
  vstat = VAPI_query_hca_port_prop(Hca_hndl, HCA_PORT_2, &Hca_port_2_props);
  if (vstat != VAPI_OK) {
     CERROR("Failed query port cap %s\n",VAPI_strerror(vstat));
     return(vstat);
  }      

  // Get a PD 
  CDEBUG(D_PORTALS, "Allocating PD \n");
  vstat = VAPI_alloc_pd(Hca_hndl,&Pd_hndl);
  if (vstat != VAPI_OK) {
     CERROR("Failed allocating a PD. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  vstat = createMemRegion(Hca_hndl, Pd_hndl);
  if (vstat != VAPI_OK) {
     CERROR("Failed registering a memory region.%s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  /* Create CQ for RQ*/
  CDEBUG(D_PORTALS, "Creating a send completion queue\n");

  vstat = VAPI_create_cq(Hca_hndl,    
                         NUM_CQE,    
                         &Cq_hndl, 
                         &cqe_active_num);

  if (vstat != VAPI_OK) {
     CERROR("Failed creating a CQ. %s\n",VAPI_strerror(vstat));
     return(vstat);
  }

  if(NUM_CQE == cqe_active_num) {
    CERROR("VAPI_create_cq: NUM_CQE EQ cqe_active_num \n");
  }
  else {
    CDEBUG(D_NET, "VAPI_create_cq: NUM_CQE %d , actual cqe_active_num %d \n",
                   NUM_CQE, cqe_active_num);
  }

  Cq_SQ_hndl     = Cq_hndl;
  Cq_RQ_hndl     = Cq_hndl;

  //
  // create  QPs 
  //
  for(i=0; i < NUM_QPS; i++) {
      QP_list[i].pd_hndl    = Pd_hndl;
      QP_list[i].hca_hndl   = Hca_hndl;
      // sq rq use the same Cq_hndl 
      QP_list[i].sq_cq_hndl = Cq_hndl; 
      QP_list[i].rq_cq_hndl = Cq_hndl;
      vstat = create_qp(&QP_list[i], i);
      if (vstat != VAPI_OK) {
         CERROR("Failed creating a QP %d %s\n",i, VAPI_strerror(vstat));
         return(vstat);
      }
  }      

  //
  // record HCA data 
  //

  Hca_data.hca_hndl     = Hca_hndl;      // HCA handle
  Hca_data.pd_hndl      = Pd_hndl;       // protection domain
  Hca_data.port         = 1;             // port number
  Hca_data.num_qp       = NUM_QPS;        // number of qp used

  for(i=0; i < NUM_QPS; i++) {
    Hca_data.qp_ptr[i]    = &QP_list[i];   // point to QP_list
  }

  Hca_data.num_cq       = NUM_CQ;        // number of cq used
  Hca_data.cq_hndl      = Cq_hndl;       // 
  Hca_data.sq_cq_hndl   = Cq_SQ_hndl;    // 
  Hca_data.rq_cq_hndl   = Cq_RQ_hndl;    // 
  Hca_data.kib_data     = kib_data;       //
  Hca_data.slid         = QP_list[0].slid;//

  // prepare L_QP_data

#ifdef USE_SHARED_MEMORY_AND_SOCKET

  /*
   *  + use a shared-memory between a user thread and a kernel thread 
   *    for HCA's data exchange on the same node  
   *  + use socket in user mode to exhange HCA's data with a remote node 
   */

  
  R_QP_data.opcode  = SEND_QP_INFO;
  R_QP_data.length  = sizeof(L_QP_data);

  for(i=0; i < NUM_QPS; i++) {
    // my slid  will be used in a remote node as dlid 
    R_QP_data.dlid[i]    = QP_list[i].slid;
    // my qp_num will be used in remode node as remote_qp_number 
    // RC is used here so we need dlid and rqp_num  
    R_QP_data.rqp_num[i] = QP_list[i].qp_num ;
  }

  // create a kernel thread for exchanging HCA's data 
  // R_QP_data will be exchanged with a remoe node

  kernel_thread(k_server_thread, &R_QP_data, 0); // 
  // check if the HCA'data have been updated by kernel_thread 
  // loop until the HCA's data is updated 
  // make sure that uagent is running 
  
  // QP info is exchanged with a remote node   
  while (1) {
    schedule_timeout(1000);
    if(R_QP_data.opcode ==  RECV_QP_INFO) {
       CDEBUG(D_NET, "HCA's data is being updated\n");
       break;
   }
  }
 
#endif

#ifdef USE_SHARED_MEMORY_AND_MULTICAST

  /*
   *  + use a shared-memory between a user thread and a kernel thread 
   *    for HCA's data exchange on the same node  
   *  + use Infinoband UR/multicast in user mode to exhange HCA's data with i
   *    a remote node 
   */

  // use CM, opemSM 
  
#endif

  // 
  for(i=0; i < NUM_QPS; i++) {
     qp = (QP_info *) &QP_list[i];
     QP_list[i].rqp_num = R_QP_data.rqp_num[i]; // remoter qp number 
     QP_list[i].dlid    = R_QP_data.dlid[i];    // remote dlid 
  }

  // already have remote_qp_num adn dlid information
  // initialize QP to RTR/RTS state 
  //
  for(i=0; i < NUM_QPS; i++) {
    vstat = init_qp_RC(&QP_list[i], i);
    if (vstat != VAPI_OK) {
       CERROR("Failed change a QP %d to RTS state%s\n",
                    i,VAPI_strerror(vstat));
       return(vstat);
    }
  }

  // post receiving buffer before any send happened 
  
  Num_posted_recv_buf = post_recv_bufs( (VAPI_wr_id_t ) START_RECV_WRQ_ID); 

  // for irregular completion event or some unexpected failure event 
  vstat = IB_Set_Async_Event_Handler(Hca_data, &kibnal_data);
  if (vstat != VAPI_OK) {
     CERROR("IB_Set_Async_Event_Handler failed: %d\n", vstat);
     return vstat;
  }


  CDEBUG(D_PORTALS, "IBNAL- done with IB_Open_HCA\n");

  for(i=0;  i < NUM_MBUF; i++) {
    spin_lock_init(&MSB_mutex[i]);
  }

  return(VAPI_OK);

}


/* 
  Function:  IB_Set_Event_Handler()
             
             IN   Hca_info hca_data
             IN   kibnal_data_t *kib_data  -- private data      
             OUT  NONE

        return: VAPI_OK - success
                else    - fail 

*/

VAPI_ret_t 
IB_Set_Event_Handler(HCA_info hca_data, kibnal_data_t *kib_data)
{
  VAPI_ret_t vstat;
  EVAPI_compl_handler_hndl_t   comp_handler_hndl;

  // register CQE_Event_Hnadler 
  // VAPI function 
  vstat = VAPI_set_comp_event_handler(hca_data.hca_hndl,
                                      CQE_event_handler,
                                      &hca_data);

  /*
  or use extended VAPI function 
  vstat = EVAPI_set_comp_eventh(hca_data.hca_hndl,
                                hca_data.cq_hndl,
                                CQE_event_handler,
                                &hca_data,
                                &comp_handler_hndl
                                );
  */
                                    
  if (vstat != VAPI_OK) {
      CERROR("IB_Set_Event_Handler: failed EVAPI_set_comp_eventh for"
             " HCA ID = %s (%s).\n", HCA_ID, VAPI_strerror(vstat));
      return vstat;
  }

  // issue a request for completion ievent notification 
  vstat = VAPI_req_comp_notif(hca_data.hca_hndl, 
                              hca_data.cq_hndl,
                              VAPI_NEXT_COMP); 

  if (vstat != VAPI_OK) {
      CERROR("IB_Set_Event_Handler: failed VAPI_req_comp_notif for HCA ID"
             " = %s (%s).\n", HCA_ID, VAPI_strerror(vstat));
  }

  return vstat;
}



/* 
  Function:  IB_Set_Async_Event_Handler()
             
             IN   HCA_info hca_data
             IN   kibnal_data_t *kib_data -- private data      
             OUT  NONE

        return: VAPI_OK - success
                else    - fail 

*/


VAPI_ret_t 
IB_Set_Async_Event_Handler(HCA_info hca_data, kibnal_data_t *kib_data)
{
  VAPI_ret_t    vstat;

  //
  // register an asynchronous event handler for this HCA 
  //

  vstat= VAPI_set_async_event_handler(hca_data.hca_hndl,
                                      async_event_handler, 
                                      kib_data);

  if (vstat != VAPI_OK) {
      CERROR("IB_Set_Async_Event_Handler: failed VAPI_set_async_comp_event_handler"
             " for HCA ID = %s (%s).\n", HCA_ID, VAPI_strerror(vstat));
  }

  return vstat;
}

//
// IB_Close_HCA
// close this Infiniband HCA interface 
// release allocated resources to system 
//
VAPI_ret_t 
IB_Close_HCA(void )
{
        
  VAPI_ret_t  vstat;
  int         ok = 1;
  int         i;
            
  /* Destroy QP */
  CDEBUG(D_PORTALS, "Destroying QP\n");

  for(i=0; i < NUM_QPS; i++) {
     vstat = VAPI_destroy_qp(QP_list[i].hca_hndl, QP_list[i].qp_hndl);
     if (vstat != VAPI_OK) {
        CERROR("Failed destroying QP %d. %s\n", i, VAPI_strerror(vstat));
        ok = 0;
     }
  }

  if (ok) {
     /* Destroy CQ */
     CDEBUG(D_PORTALS, "Destroying CQ\n");
     for(i=0; i < NUM_QPS; i++) {
        // send_cq adn receive_cq are shared the same CQ
        // so only destroy one of them 
        vstat = VAPI_destroy_cq(QP_list[i].hca_hndl, QP_list[i].sq_cq_hndl);
        if (vstat != VAPI_OK) {
           CERROR("Failed destroying CQ %d. %s\n", i, VAPI_strerror(vstat));
           ok = 0;
        }
     }
  }

  if (ok) {
     /* Destroy Memory Region */
     CDEBUG(D_PORTALS, "Deregistering MR\n");
     for(i=0; i < NUM_QPS; i++) {
        vstat = deleteMemRegion(&QP_list[i], i);
        if (vstat != VAPI_OK) {
           CERROR("Failed deregister mem reg %d. %s\n",i, VAPI_strerror(vstat));
           ok = 0;
           break;
        }
     }
  }

  if (ok) {
     // finally 
     /* Close HCA */
     CDEBUG(D_PORTALS, "Closing HCA\n");
     vstat = VAPI_close_hca(Hca_hndl);
     if (vstat != VAPI_OK) {
        CERROR("Failed to close HCA. %s\n", VAPI_strerror(vstat));
        ok = 0;
     }
  }

  CDEBUG(D_PORTALS, "IBNAL- Done with closing HCA \n");
  
  return vstat; 
}


VAPI_ret_t 
createMemRegion(VAPI_hca_hndl_t hca_hndl, 
                   VAPI_pd_hndl_t  pd_hndl) 
{
  VAPI_ret_t  vstat;
  VAPI_mrw_t  mrw;
  VAPI_mrw_t  rep_mr;   
  VAPI_mr_hndl_t   rep_mr_hndl;
  int         buf_size;
  char        *bufptr;
  int         i;

  // send registered memory region 
  for(i=0; i < NUM_ENTRY; i++) {
    MSbuf_list[i].buf_size = KB_32; 
    PORTAL_ALLOC(bufptr, MSbuf_list[i].buf_size);
    if(bufptr == NULL) {
       CDEBUG(D_MALLOC,"Failed to malloc a block of send memory, qix %d size %d\n",
                                          i, MSbuf_list[i].buf_size);
       CERROR("Failed to malloc a block of send memory, qix %d size %d\n",
                                          i, MSbuf_list[i].buf_size);
       return(VAPI_ENOMEM);
    }

    mrw.type   = VAPI_MR; 
    mrw.pd_hndl= pd_hndl;
    mrw.start  = MSbuf_list[i].buf_addr = (VAPI_virt_addr_t)(MT_virt_addr_t) bufptr;
    mrw.size   = MSbuf_list[i].buf_size;
    mrw.acl    = VAPI_EN_LOCAL_WRITE  | 
                 VAPI_EN_REMOTE_WRITE | 
                 VAPI_EN_REMOTE_READ;

    // register send memory region  
    vstat = VAPI_register_mr(hca_hndl, 
                             &mrw, 
                             &rep_mr_hndl, 
                             &rep_mr);

    // this memory region is going to be reused until deregister is called 
    if(vstat != VAPI_OK) {
       CERROR("Failed registering a mem region qix %d Addr=%p, Len=%d. %s\n",
                          i, mrw.start, mrw.size, VAPI_strerror(vstat));
       return(vstat);
    }

    MSbuf_list[i].mr        = rep_mr;
    MSbuf_list[i].mr_hndl   = rep_mr_hndl;
    MSbuf_list[i].bufptr    = bufptr;
    MSbuf_list[i].buf_addr  = rep_mr.start;
    MSbuf_list[i].status    = BUF_REGISTERED;
    MSbuf_list[i].ref_count = 0;
    MSbuf_list[i].buf_type  = REG_BUF;
    MSbuf_list[i].raddr     = 0x0;
    MSbuf_list[i].rkey      = 0x0;
  }

  // RDAM buffer is not reserved for RDAM WRITE/READ
  
  for(i=NUM_ENTRY; i< NUM_MBUF; i++) {
    MSbuf_list[i].status    = BUF_UNREGISTERED;
    MSbuf_list[i].buf_type  = RDMA_BUF;
  }


  // recv registered memory region 
  for(i=0; i < NUM_ENTRY; i++) {
    MRbuf_list[i].buf_size = KB_32; 
    PORTAL_ALLOC(bufptr, MRbuf_list[i].buf_size);

    if(bufptr == NULL) {
       CDEBUG(D_MALLOC, "Failed to malloc a block of send memory, qix %d size %d\n",
                      i, MRbuf_list[i].buf_size);
       return(VAPI_ENOMEM);
    }

    mrw.type   = VAPI_MR; 
    mrw.pd_hndl= pd_hndl;
    mrw.start  = (VAPI_virt_addr_t)(MT_virt_addr_t) bufptr;
    mrw.size   = MRbuf_list[i].buf_size;
    mrw.acl    = VAPI_EN_LOCAL_WRITE  | 
                 VAPI_EN_REMOTE_WRITE | 
                 VAPI_EN_REMOTE_READ;

    // register send memory region  
    vstat = VAPI_register_mr(hca_hndl, 
                             &mrw, 
                             &rep_mr_hndl, 
                             &rep_mr);

    // this memory region is going to be reused until deregister is called 
    if(vstat != VAPI_OK) {
       CERROR("Failed registering a mem region qix %d Addr=%p, Len=%d. %s\n",
                          i, mrw.start, mrw.size, VAPI_strerror(vstat));
       return(vstat);
    }

    MRbuf_list[i].mr        = rep_mr;
    MRbuf_list[i].mr_hndl   = rep_mr_hndl;
    MRbuf_list[i].bufptr    = bufptr;
    MRbuf_list[i].buf_addr  = rep_mr.start;
    MRbuf_list[i].status    = BUF_REGISTERED;
    MRbuf_list[i].ref_count = 0;
    MRbuf_list[i].buf_type  = REG_BUF;
    MRbuf_list[i].raddr     = 0x0;
    MRbuf_list[i].rkey      = rep_mr.r_key;
    MRbuf_list[i].lkey      = rep_mr.l_key;
  
  }
 
  // keep extra information for a qp 
  for(i=0; i < NUM_QPS; i++) {
    QP_list[i].mr_hndl    = MSbuf_list[i].mr_hndl; 
    QP_list[i].mr         = MSbuf_list[i].mr;
    QP_list[i].bufptr     = MSbuf_list[i].bufptr;
    QP_list[i].buf_addr   = MSbuf_list[i].buf_addr;
    QP_list[i].buf_size   = MSbuf_list[i].buf_size;
    QP_list[i].raddr      = MSbuf_list[i].raddr;
    QP_list[i].rkey       = MSbuf_list[i].rkey;
    QP_list[i].lkey       = MSbuf_list[i].lkey;
  }

  CDEBUG(D_PORTALS, "IBNAL- done VAPI_ret_t createMemRegion \n");

  return vstat;

} /* createMemRegion */



VAPI_ret_t  
deleteMemRegion(QP_info *qp, int qix)
{
  VAPI_ret_t  vstat;

  //
  // free send memory assocaited with this memory region  
  //
  PORTAL_FREE(MSbuf_list[qix].bufptr, MSbuf_list[qix].buf_size);

  // de-register it 
  vstat =  VAPI_deregister_mr(qp->hca_hndl, MSbuf_list[qix].mr_hndl);

  if(vstat != VAPI_OK) {
     CERROR("Failed deregistering a send mem region qix %d %s\n",
                         qix, VAPI_strerror(vstat));
     return vstat;
  }

  //
  // free recv memory assocaited with this memory region  
  //
  PORTAL_FREE(MRbuf_list[qix].bufptr, MRbuf_list[qix].buf_size);

  // de-register it 
  vstat =  VAPI_deregister_mr(qp->hca_hndl, MRbuf_list[qix].mr_hndl);

  if(vstat != VAPI_OK) {
     CERROR("Failed deregistering a recv mem region qix %d %s\n",
                         qix, VAPI_strerror(vstat));
     return vstat;
  }

  return vstat;
}


//
// polling based event handling 
// + a daemon process
// + poll the CQ and check what is in the CQ 
// + process incoming CQ event
// + 
//


RDMA_Info_Exchange   Rdma_info;
int                  Cts_Message_arrived = NO;

void k_recv_thread(HCA_info *hca_data)
{
 VAPI_ret_t       vstat; 
 VAPI_wc_desc_t   comp_desc;   
 unsigned long    polling_count = 0;
 u_int32_t        timeout_usec;
 unsigned int     priority = 100;
 unsigned int     length;
 VAPI_wr_id_t     wrq_id;
 u_int32_t        transferred_data_length; /* Num. of bytes transferred */
 void             *bufdata;
 VAPI_virt_addr_t bufaddr;
 unsigned long    buf_size = 0;
 QP_info          *qp;       // point to QP_list

 kportal_daemonize("k_recv_thread"); // make it as a daemon process 

 // tuning variable 
 timeout_usec = 100; // how is the impact on the performance

 // send Q and receive Q are using the same CQ 
 // so only poll one CQ for both operations 
 
 CDEBUG(D_NET, "IBNAL- enter kibnal_recv_thread\n");
 CDEBUG(D_NET, "hca_hndl = 0X%x, cq_hndl=0X%x\n", 
                         hca_data->hca_hndl,hca_data->cq_hndl); 

 qp = hca_data->qp_ptr;
 if(qp == NULL) {
   CDEBUG(D_NET, "in recv_thread qp is NULL\n");
   CDEBUG(D_NET, "Exit from  recv_thread qp is NULL\n");
   return; 
 }
 else {
   CDEBUG(D_NET, "in recv_thread qp is 0X%X\n", qp);
 }

 CDEBUG(D_NET, "kibnal_recv_thread - enter event driver polling loop\n");

 //
 // use event driver 
 //
 


 while(1) {
    polling_count++;

    //
    // send Q and receive Q are using the same CQ 
    // so only poll one CQ for both operations 
    //

    vstat = VAPI_poll_cq(hca_data->hca_hndl,hca_data->cq_hndl, &comp_desc);                      

    if (vstat == VAPI_CQ_EMPTY) { 
      // there is no event in CQE 
      continue;
    } 
    else {
      if (vstat != (VAPI_OK)) {
        CERROR("error while polling completion queuei vstat %d \n", vstat);
        return; 
      }
    }

    // process the complete event 
    switch(comp_desc.opcode) {
      case   VAPI_CQE_SQ_SEND_DATA:
        // about the Send Q ,POST SEND completion 
        // who needs this information
        // get wrq_id
        // mark MSbuf_list[wr_id].status = BUF_REGISTERED 
               
        wrq_id = comp_desc.id;

        if(RDMA_OP_ID < wrq_id) {
          // this RDMA message id, adjust it to the right entry       
          wrq_id = wrq_id - RDMA_OP_ID;
          vstat = VAPI_deregister_mr(qp->hca_hndl, Local_rdma_info.send_rdma_mr_hndl);
        }
        
        if(vstat != VAPI_OK) {
            CERROR("VAPI_CQE_SQ_SEND_DATA: Failed deregistering a RDMAi recv"                   " mem region %s\n", VAPI_strerror(vstat));
        }

        if((RDMA_CTS_ID <= wrq_id) && (RDMA_OP_ID < wrq_id)) {
          // RTS or CTS send complete, release send buffer 
          if(wrq_id >= RDMA_RTS_ID)
            wrq_id = wrq_id - RDMA_RTS_ID;
          else 
            wrq_id = wrq_id - RDMA_CTS_ID;
        }

        spin_lock(&MSB_mutex[(int) wrq_id]);
        MRbuf_list[wrq_id].status = BUF_REGISTERED; 
        spin_unlock(&MSB_mutex[(int) wrq_id]);

        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_SEND_DATA\n");  
        break;

      case   VAPI_CQE_SQ_RDMA_WRITE:
        // about the Send Q,  RDMA write completion 
        // who needs this information
        // data is successfully write from pource to  destionation 
             
        //  get wr_id
        //  mark MSbuf_list[wr_id].status = BUF_REGISTERED 
        //  de-register  rdma buffer 
        //
             
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_RDMA_WRITE\n");  
        break;

      case   VAPI_CQE_SQ_RDMA_READ:
        // about the Send Q
        // RDMA read completion 
        // who needs this information
        // data is successfully read from destionation to source 
        CDEBUG(D_NET, "CQE opcode- VAPI_CQE_SQ_RDMA_READ\n");  
        break;

      case   VAPI_CQE_SQ_COMP_SWAP:
        // about the Send Q
        // RDMA write completion 
        // who needs this information
             
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_COMP_SWAP\n");  
        break;

      case   VAPI_CQE_SQ_FETCH_ADD:
        // about the Send Q
        // RDMA write completion 
        // who needs this information
             
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_FETCH_ADD\n");  
        break;

      case   VAPI_CQE_SQ_BIND_MRW:
        // about the Send Q
        // RDMA write completion 
        // who needs this information
             
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_BIND_MRW\n");  
        break;

      case   VAPI_CQE_RQ_SEND_DATA:
        // about the Receive Q
        // process the incoming data and
        // forward it to .....
        // a completion recevie event is arriving at CQ 
        // issue a recevie to get this arriving data out from CQ 
        // pass the receiving data for further processing 
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_RQ_SEND_DATA\n");  
        wrq_id = comp_desc.id ;
        transferred_data_length = comp_desc.byte_len;
             
        if((wrq_id >= RDMA_CTS_ID) && (wrq_id < RDMA_OP_ID)) {
          // this is RTS/CTS message 
          // process it locally and don't pass it to portals layer 
          // adjust wrq_id to get the right entry in MRbfu_list 
                   
          if(wrq_id >= RDMA_RTS_ID)
            wrq_id = wrq_id - RDMA_RTS_ID;
          else 
            wrq_id = wrq_id - RDMA_CTS_ID;

          bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t) MRbuf_list[wrq_id].buf_addr; 
          MRbuf_list[wrq_id].status = BUF_INUSE; 
          memcpy(&Rdma_info, &bufaddr, sizeof(RDMA_Info_Exchange));    
        
          if(Ready_To_send == Rdma_info.opcode) 
            // an RTS request message from remote node 
            // prepare local RDMA buffer and send local rdma info to
            // remote node 
            CTS_handshaking_protocol(&Rdma_info);
          else 
            if((Clear_To_send == Rdma_info.opcode) && 
                              (RDMA_BUFFER_RESERVED == Rdma_info.flag))
               Cts_Message_arrived = YES;
            else 
              if(RDMA_BUFFER_UNAVAILABLE == Rdma_info.flag) 
                  CERROR("RDMA operation abort-RDMA_BUFFER_UNAVAILABLE\n");
        }
        else {
          //
          // this is an incoming mesage for portals layer 
          // move to PORTALS layer for further processing 
          //
                     
          bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t)
                                       MRbuf_list[wrq_id].buf_addr; 

          MRbuf_list[wrq_id].status = BUF_INUSE; 
          transferred_data_length = comp_desc.byte_len;

          kibnal_rx(hca_data->kib_data, 
                    bufaddr, 
                    transferred_data_length, 
                    MRbuf_list[wrq_id].buf_size, 
                    priority); 
        }

        // repost this receiving buffer and makr it at BUF_REGISTERED 

        vstat = repost_recv_buf(qp, wrq_id);
        if(vstat != (VAPI_OK)) {
          CERROR("error while polling completion queue\n");
        }
        else {
          MRbuf_list[wrq_id].status = BUF_REGISTERED; 
        }

        break;

      case   VAPI_CQE_RQ_RDMA_WITH_IMM:
        // about the Receive Q
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_RQ_RDMA_WITH_IMM\n");  

        wrq_id = comp_desc.id ;
        transferred_data_length = comp_desc.byte_len;
             
        if(wrq_id ==  RDMA_OP_ID) {
          // this is RDAM op , locate the RDAM memory buffer address   
               
          bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t) Local_rdma_info.raddr;

          transferred_data_length = comp_desc.byte_len;

          kibnal_rx(hca_data->kib_data, 
                    bufaddr, 
                    transferred_data_length, 
                    Local_rdma_info.buf_length, 
                    priority); 

          // de-regiser this RDAM receiving memory buffer
          // too early ??    test & check 
          vstat = VAPI_deregister_mr(qp->hca_hndl, Local_rdma_info.recv_rdma_mr_hndl);
          if(vstat != VAPI_OK) {
            CERROR("VAPI_CQE_RQ_RDMA_WITH_IMM: Failed deregistering a RDMA"
                   " recv  mem region %s\n", VAPI_strerror(vstat));
          }
        }

        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_RQ_RDMA_WITH_IMM\n");  
        break;

      case   VAPI_CQE_INVAL_OPCODE:
        //
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_INVAL_OPCODE\n");  
        break;

      default :
        CDEBUG(D_NET, "CQE opcode-unknown opcode\n");  
             break;
    } // switch 
    
    schedule_timeout(RECEIVING_THREAD_TIMEOUT);//how often do we need to poll CQ 

  }// receiving while loop


}


void CQE_event_handler(VAPI_hca_hndl_t hca_hndl, 
                       VAPI_cq_hndl_t  cq_hndl, 
                       void           *private)
{
 VAPI_ret_t       vstat; 
 VAPI_wc_desc_t   comp_desc;   
 unsigned long    polling_count = 0;
 u_int32_t        timeout_usec;
 unsigned int     priority = 100;
 unsigned int     length;
 VAPI_wr_id_t     wrq_id;
 u_int32_t        transferred_data_length; /* Num. of bytes transferred */
 void             *bufdata;
 VAPI_virt_addr_t bufaddr;
 unsigned long    buf_size = 0;
 QP_info          *qp;       // point to QP_list
 HCA_info         *hca_data;

 // send Q and receive Q are using the same CQ 
 // so only poll one CQ for both operations 
 
 CDEBUG(D_NET, "IBNAL- enter CQE_event_handler\n");
 printk("IBNAL- enter CQE_event_handler\n");

 hca_data  = (HCA_info *) private; 

 //
 // use event driven  
 //
 

 vstat = VAPI_poll_cq(hca_data->hca_hndl,hca_data->cq_hndl, &comp_desc);   

 if (vstat == VAPI_CQ_EMPTY) { 
   CDEBUG(D_NET, "CQE_event_handler: there is no event in CQE, how could"
                  " this " "happened \n");
   printk("CQE_event_handler: there is no event in CQE, how could"
                  " this " "happened \n");

 } 
 else {
   if (vstat != (VAPI_OK)) {
     CDEBUG(D_NET, "error while polling completion queue vstat %d - %s\n", 
                vstat, VAPI_strerror(vstat));
     printk("error while polling completion queue vstat %d - %s\n", 
                                               vstat, VAPI_strerror(vstat));
     return; 
   }
 }

 // process the complete event 
 switch(comp_desc.opcode) {
    case   VAPI_CQE_SQ_SEND_DATA:
      // about the Send Q ,POST SEND completion 
      // who needs this information
      // get wrq_id
      // mark MSbuf_list[wr_id].status = BUF_REGISTERED 
               
      wrq_id = comp_desc.id;

#ifdef IBNAL_SELF_TESTING
      if(wrq_id == SEND_RECV_TEST_ID) {
        printk("IBNAL_SELF_TESTING - VAPI_CQE_SQ_SEND_DATA \n"); 
      }
#else  
      if(RDMA_OP_ID < wrq_id) {
        // this RDMA message id, adjust it to the right entry       
        wrq_id = wrq_id - RDMA_OP_ID;
        vstat = VAPI_deregister_mr(qp->hca_hndl, 
                                   Local_rdma_info.send_rdma_mr_hndl);
      }

      if(vstat != VAPI_OK) {
        CERROR(" VAPI_CQE_SQ_SEND_DATA: Failed deregistering a RDMA"
               " recv  mem region %s\n", VAPI_strerror(vstat));
      }

      if((RDMA_CTS_ID <= wrq_id) && (RDMA_OP_ID < wrq_id)) {
        // RTS or CTS send complete, release send buffer 
        if(wrq_id >= RDMA_RTS_ID)
          wrq_id = wrq_id - RDMA_RTS_ID;
        else 
          wrq_id = wrq_id - RDMA_CTS_ID;
      }

      spin_lock(&MSB_mutex[(int) wrq_id]);
      MRbuf_list[wrq_id].status = BUF_REGISTERED; 
      spin_unlock(&MSB_mutex[(int) wrq_id]);
#endif 

      CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_SEND_DATA\n");  

      break;

    case   VAPI_CQE_SQ_RDMA_WRITE:
      // about the Send Q,  RDMA write completion 
      // who needs this information
      // data is successfully write from pource to  destionation 
             
      //  get wr_id
      //  mark MSbuf_list[wr_id].status = BUF_REGISTERED 
      //  de-register  rdma buffer 
      //
             
       CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_RDMA_WRITE\n");  
       break;

      case   VAPI_CQE_SQ_RDMA_READ:
        // about the Send Q
        // RDMA read completion 
        // who needs this information
        // data is successfully read from destionation to source 
         CDEBUG(D_NET, "CQE opcode- VAPI_CQE_SQ_RDMA_READ\n");  
         break;

      case   VAPI_CQE_SQ_COMP_SWAP:
        // about the Send Q
        // RDMA write completion 
        // who needs this information
            
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_COMP_SWAP\n");  
        break;

      case   VAPI_CQE_SQ_FETCH_ADD:
        // about the Send Q
        // RDMA write completion 
        // who needs this information
             
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_FETCH_ADD\n");  
        break;

      case   VAPI_CQE_SQ_BIND_MRW:
        // about the Send Q
        // RDMA write completion 
        // who needs this information
             
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_SQ_BIND_MRW\n");  
        break;

      case   VAPI_CQE_RQ_SEND_DATA:
        // about the Receive Q
        // process the incoming data and
        // forward it to .....
        // a completion recevie event is arriving at CQ 
        // issue a recevie to get this arriving data out from CQ 
        // pass the receiving data for further processing 
         
         CDEBUG(D_NET, "CQE opcode-VAPI_CQE_RQ_SEND_DATA\n");  
          
         wrq_id = comp_desc.id ;

#ifdef IBNAL_SELF_TESTING

      char        rbuf[KB_32];
      int i;

      if(wrq_id == SEND_RECV_TEST_ID) {
        printk("IBNAL_SELF_TESTING - VAPI_CQE_RQ_SEND_DATA\n"); 
      }

      bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t) 
                       MRbuf_list[ SEND_RECV_TEST_BUF_ID].buf_addr; 
      MRbuf_list[SEND_RECV_TEST_BUF_ID].status = BUF_INUSE; 
      memcpy(&rbuf, &bufaddr, KB_32);    
      

      for(i=0; i < 16; i++)
              printk("rbuf[%d]=%c, ", rbuf[i]);
      printk("\n");

      // repost this receiving buffer and makr it at BUF_REGISTERED 
      vstat = repost_recv_buf(qp,SEND_RECV_TEST_BUF_ID);
      if(vstat != (VAPI_OK)) {
        printk("error while polling completion queue\n");
      }
      else {
        MRbuf_list[SEND_RECV_TEST_BUF_ID].status = BUF_REGISTERED; 
      }
#else  
         transferred_data_length = comp_desc.byte_len;
             
         if((wrq_id >= RDMA_CTS_ID) && (wrq_id < RDMA_OP_ID)) {
           // this is RTS/CTS message 
           // process it locally and don't pass it to portals layer 
           // adjust wrq_id to get the right entry in MRbfu_list 
                   
           if(wrq_id >= RDMA_RTS_ID)
             wrq_id = wrq_id - RDMA_RTS_ID;
           else 
             wrq_id = wrq_id - RDMA_CTS_ID;

           bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t) 
                                           MRbuf_list[wrq_id].buf_addr; 
           MRbuf_list[wrq_id].status = BUF_INUSE; 
           memcpy(&Rdma_info, &bufaddr, sizeof(RDMA_Info_Exchange));    
        
           if(Ready_To_send == Rdma_info.opcode) 
             // an RTS request message from remote node 
             // prepare local RDMA buffer and send local rdma info to
             // remote node 
             CTS_handshaking_protocol(&Rdma_info);
           else 
             if((Clear_To_send == Rdma_info.opcode) && 
                                (RDMA_BUFFER_RESERVED == Rdma_info.flag))
               Cts_Message_arrived = YES;
             else 
               if(RDMA_BUFFER_UNAVAILABLE == Rdma_info.flag) 
                 CERROR("RDMA operation abort-RDMA_BUFFER_UNAVAILABLE\n");
         }
         else {
           //
           // this is an incoming mesage for portals layer 
           // move to PORTALS layer for further processing 
           //
                     
           bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t)
                                MRbuf_list[wrq_id].buf_addr; 

           MRbuf_list[wrq_id].status = BUF_INUSE; 
           transferred_data_length = comp_desc.byte_len;

           kibnal_rx(hca_data->kib_data, 
                     bufaddr, 
                     transferred_data_length, 
                     MRbuf_list[wrq_id].buf_size, 
                     priority); 
         }

         // repost this receiving buffer and makr it at BUF_REGISTERED 
         vstat = repost_recv_buf(qp, wrq_id);
         if(vstat != (VAPI_OK)) {
           CERROR("error while polling completion queue\n");
         }
         else {
           MRbuf_list[wrq_id].status = BUF_REGISTERED; 
         }
#endif

         break;

      case   VAPI_CQE_RQ_RDMA_WITH_IMM:
        // about the Receive Q
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_RQ_RDMA_WITH_IMM\n");  

        wrq_id = comp_desc.id ;
        transferred_data_length = comp_desc.byte_len;
             
        if(wrq_id ==  RDMA_OP_ID) {
          // this is RDAM op , locate the RDAM memory buffer address   
              
          bufaddr = (VAPI_virt_addr_t)(MT_virt_addr_t) Local_rdma_info.raddr;

          transferred_data_length = comp_desc.byte_len;

          kibnal_rx(hca_data->kib_data, 
                    bufaddr, 
                    transferred_data_length, 
                    Local_rdma_info.buf_length, 
                    priority); 

          // de-regiser this RDAM receiving memory buffer
          // too early ??    test & check 
          vstat = VAPI_deregister_mr(qp->hca_hndl, Local_rdma_info.recv_rdma_mr_hndl);
          if(vstat != VAPI_OK) {
            CERROR("VAPI_CQE_RQ_RDMA_WITH_IMM: Failed deregistering a RDMA"
               " recv  mem region %s\n", VAPI_strerror(vstat));
          }
        }

        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_RQ_RDMA_WITH_IMM\n");  
        break;

      case   VAPI_CQE_INVAL_OPCODE:
        //
        CDEBUG(D_NET, "CQE opcode-VAPI_CQE_INVAL_OPCODE\n");  
        break;

      default :
        CDEBUG(D_NET, "CQE opcode-unknown opcode\n");  

        break;
    } // switch 
    
  // issue a new request for completion ievent notification 
  vstat = VAPI_req_comp_notif(hca_data->hca_hndl, 
                              hca_data->cq_hndl,
                              VAPI_NEXT_COMP); 


  if(vstat != VAPI_OK) {
    CERROR("PI_req_comp_notif: Failed %s\n", VAPI_strerror(vstat));
  }

  return; // end of event handler 

}



int
kibnal_cmd(struct portal_ioctl_data * data, void * private)
{
  int rc ;

  CDEBUG(D_NET, "kibnal_cmd \n");  

  return YES;
}



void ibnal_send_recv_self_testing(int *my_role)
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

 // make it as a daemon process 
 // kportal_daemonize("ibnal_send_recv_self_testing");  

 printk("My role is 0X%X\n", *my_role);

if(*my_role ==  TEST_SEND_MESSAGE)  {
 printk("Enter ibnal_send_recv_self_testing\n");

 memset(&sbuf, 'a', KB_32);
 memset(&rbuf, ' ', KB_32);
 
 send_id = SEND_RECV_TEST_ID; 
 buf_id = SEND_RECV_TEST_BUF_ID;

 qp = &QP_list[buf_id];

 sr_desc.opcode    = VAPI_SEND;
 sr_desc.comp_type = VAPI_SIGNALED;
 sr_desc.id        =  send_id;

 // scatter and gather info
 sr_sg.len  = KB_32;
 sr_sg.lkey = MSbuf_list[buf_id].mr.l_key; // use send MR
 sr_sg.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MSbuf_list[buf_id].buf_addr;

 // copy data to register send buffer
 memcpy(&sr_sg.addr, &sbuf, buf_length);

 sr_desc.sg_lst_p = &sr_sg;
 sr_desc.sg_lst_len = 1; // only 1 entry is used
 sr_desc.fence = TRUE;
 sr_desc.set_se = FALSE;

 /*
 // call VAPI_post_sr to send out this data
 vstat = VAPI_post_sr(qp->hca_hndl, qp->qp_hndl, &sr_desc);

 if (vstat != VAPI_OK) {
   printk("VAPI_post_sr failed (%s).\n",VAPI_strerror(vstat));
 }

 printk("VAPI_post_sr success.\n");
 */

 }
else {
  printk("I am a receiver and doing nothing here\n"); 
}
         
 printk("ibnal_send_recv_self_testing thread exit \n");

 return;

}


//
// ibnal initialize process  
//
// 1.  Bring up Infiniband network interface 
//     * 
// 2.  Initialize a PORTALS nal interface 
// 
//
int __init 
kibnal_initialize(void)
{
   int           rc;
   int           ntok;
   unsigned long sizemask;
   unsigned int  nid;
   VAPI_ret_t    vstat;


   portals_debug_set_level(IBNAL_DEBUG_LEVEL_1);

   CDEBUG(D_MALLOC, "start kmem %d\n", atomic_read (&portal_kmemory));

   CDEBUG(D_PORTALS, "kibnal_initialize: Enter kibnal_initialize\n");

   // set api functional pointers 
   kibnal_api.forward    = kibnal_forward;
   kibnal_api.shutdown   = kibnal_shutdown;
   kibnal_api.yield      = kibnal_yield;
   kibnal_api.validate   = NULL; /* our api validate is a NOOP */
   kibnal_api.lock       = kibnal_lock;
   kibnal_api.unlock     = kibnal_unlock;
   kibnal_api.nal_data   = &kibnal_data; // this is so called private data 
   kibnal_api.refct      = 1;
   kibnal_api.timeout    = NULL;
   kibnal_lib.nal_data   = &kibnal_data;
  
   memset(&kibnal_data, 0, sizeof(kibnal_data));

   // initialize kib_list list data structure 
   INIT_LIST_HEAD(&kibnal_data.kib_list);

   kibnal_data.kib_cb = &kibnal_lib;

   spin_lock_init(&kibnal_data.kib_dispatch_lock);


   //  
   // bring up the IB inter-connect network interface 
   // setup QP, CQ 
   //
   vstat = IB_Open_HCA(&kibnal_data);

   if(vstat != VAPI_OK) {
     CERROR("kibnal_initialize: IB_Open_HCA failed: %d- %s\n", 
                                                vstat, VAPI_strerror(vstat));

     printk("kibnal_initialize: IB_Open_HCA failed: %d- %s\n", 
                                                vstat, VAPI_strerror(vstat));
     return NO;
   }

   kibnal_data.kib_nid = (__u64 )Hca_hndl;//convert Hca_hndl to 64-bit format
   kibnal_data.kib_init = 1;

   CDEBUG(D_NET, " kibnal_data.kib_nid 0x%x%x\n", kibnal_data.kib_nid);
   printk(" kibnal_data.kib_nid 0x%x%x\n", kibnal_data.kib_nid);

   /* Network interface ready to initialise */
   // get an entery in the PORTALS table for this IB protocol 

   CDEBUG(D_PORTALS,"Call PtlNIInit to register this Infiniband Interface\n");
   printk("Call PtlNIInit to register this Infiniband Interface\n");

   rc = PtlNIInit(kibnal_init, 32, 4, 0, &kibnal_ni);

   if(rc != PTL_OK) {
     CERROR("kibnal_initialize: PtlNIInit failed %d\n", rc);
     printk("kibnal_initialize: PtlNIInit failed %d\n", rc);
     kibnal_finalize();
     return (-ENOMEM);
   }

   CDEBUG(D_PORTALS,"kibnal_initialize: PtlNIInit DONE\n");
   printk("kibnal_initialize: PtlNIInit DONE\n");



#ifdef  POLL_BASED_CQE_HANDLING 
   // create a receiving thread: main loopa
   // this is polling based mail loop   
   kernel_thread(k_recv_thread, &Hca_data, 0);
#endif

#ifdef EVENT_BASED_CQE_HANDLING
  // for completion event handling,  this is event based CQE handling 
  vstat = IB_Set_Event_Handler(Hca_data, &kibnal_data);

  if (vstat != VAPI_OK) {
     CERROR("IB_Set_Event_Handler failed: %d - %s \n", 
                                           vstat, VAPI_strerror(vstat));
     return vstat;
  }

  CDEBUG(D_PORTALS,"IB_Set_Event_Handler Done \n");
  printk("IB_Set_Event_Handler Done \n");
  
#endif

   PORTAL_SYMBOL_REGISTER(kibnal_ni);

#ifdef IBNAL_SELF_TESTING
  //
  // test HCA send recv before normal event handling 
  //
  int  my_role;
  my_role = TEST_SEND_MESSAGE;

  printk("my role is TEST_RECV_MESSAGE\n");

  // kernel_thread(ibnal_send_recv_self_testing, &my_role, 0);
   
  ibnal_send_recv_self_testing(&my_role);

#endif 

  return 0;

}



MODULE_AUTHOR("Hsingbung(HB) Chen <hbchen@lanl.gov>");
MODULE_DESCRIPTION("Kernel Infiniband NAL v0.1");
MODULE_LICENSE("GPL");

module_init (kibnal_initialize);
module_exit (kibnal_finalize);

EXPORT_SYMBOL(kibnal_ni);

