/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Based on ksocknal and qswnal
 *
 *  Author: Hsing-bung Chen <hbchen@lanl.gov>
 *
 *   This file is part of Portals, http://www.sf.net/projects/sandiaportals/
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
 */


#include "ibnal.h"




RDMA_Info_Exchange   Rdma_nfo;
int  Cts_Msg_Arrived = NO;


/*
 *  LIB functions follow
 */

//
// read
// copy a block of data from scr_addr to dst_addr 
// it all happens in kernel space - dst_addr and src_addr 
//
// original definition is to read a block od data from a 
// specified user address  
// 
// cb_read

int kibnal_read (nal_cb_t *nal, 
                 void     *private, 
                 void     *dst_addr, 
                 user_ptr src_addr, 
                 size_t   len)
{
        CDEBUG(D_NET, "kibnal_read: 0x%Lx: reading %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr );

        memcpy( dst_addr, src_addr, len );

        return 0;
}

//
// it seems that read and write are doing the same thing
// because they all happen in kernel space 
// why do we need two functions like read and write 
// to make PORTALS API compatable 
//

//
// write 
// copy a block of data from scr_addr to dst_addr 
// it all happens in kernel space - dst_addr and src_addr 
//
// original definition is to write a block od data to a 
// specified user address  
// 
// cb_write

int kibnal_write(nal_cb_t   *nal, 
                 void       *private, 
                 user_ptr   dst_addr, 
                 void       *src_addr, 
                 size_t     len)
{
        CDEBUG(D_NET, "kibnal_write: 0x%Lx: writing %ld bytes from %p -> %p\n",
               nal->ni.nid, (long)len, src_addr, dst_addr );


        memcpy( dst_addr, src_addr, len );

        return 0;
}

//
// malloc
//
// either vmalloc or kmalloc is used 
// dynamically allocate a block of memory based on the size of buffer  
//
// cb_malloc

void * kibnal_malloc(nal_cb_t *nal, size_t length)
{
        void *buffer;

        // PORTAL_ALLOC will do the job 
        // allocate a buffer with size "length"
        PORTAL_ALLOC(buffer, length);

        return buffer;
}

//
// free
// release a dynamically allocated memory pointed by buffer pointer 
//
// cb_free

void kibnal_free(nal_cb_t *nal, void *buffer, size_t length)
{
        //
        // release allocated buffer to system 
        //
        PORTAL_FREE(buffer, length);
}

//
// invalidate 
// because evernthing is in kernel space (LUSTRE)
// there is no need to mark a piece of user memory as no longer in use by
// the system
//
// cb_invalidate

void kibnal_invalidate(nal_cb_t      *nal, 
                              void          *base, 
                              size_t        extent, 
                              void          *addrkey)
{
  // do nothing 
  CDEBUG(D_NET, "kibnal_invalidate: 0x%Lx: invalidating %p : %d\n", 
                                        nal->ni.nid, base, extent);
  return;
}


//
// validate 
// because everything is in kernel space (LUSTRE)
// there is no need to mark a piece of user memory in use by
// the system
//
// cb_validate

int kibnal_validate(nal_cb_t        *nal,  
                           void            *base, 
                           size_t          extent, 
                           void            **addrkey)
{
  // do nothing 
  CDEBUG(D_NET, "kibnal_validate: 0x%Lx: validating %p : %d\n", 
                                        nal->ni.nid, base, extent);

  return 0;
}


//
// log messages from kernel space 
// printk() is used 
//
// cb_printf

void kibnal_printf(nal_cb_t *nal, const char *fmt, ...)
{
        va_list ap;
        char    msg[256];

        if (portal_debug & D_NET) {
                va_start( ap, fmt );
                vsnprintf( msg, sizeof(msg), fmt, ap );
                va_end( ap );

                printk("CPUId: %d %s",smp_processor_id(), msg);
        }
}

//
// clear interrupt
// use spin_lock to lock protected area such as MD, ME...
// so a process can enter a protected area and do some works
// this won't physicall disable interrup but use a software 
// spin-lock to control some protected areas 
//
// cb_cli 

void kibnal_cli(nal_cb_t *nal, unsigned long *flags) 
{ 
        kibnal_data_t *data= nal->nal_data;

        CDEBUG(D_NET, "kibnal_cli \n");

        spin_lock_irqsave(&data->kib_dispatch_lock,*flags);

}

//
// set interrupt
// use spin_lock to unlock protected area such as MD, ME...
// this won't physicall enable interrup but use a software 
// spin-lock to control some protected areas 
//
// cb_sti

void kibnal_sti(nal_cb_t *nal, unsigned long *flags)
{
        kibnal_data_t *data= nal->nal_data;

        CDEBUG(D_NET, "kibnal_sti \n");

        spin_unlock_irqrestore(&data->kib_dispatch_lock,*flags);
}



//
// nic distance 
// 
// network distance doesn't mean much for this nal 
// here we only indicate 
//      0 - operation is happened on the same node 
//      1 - operation is happened on different nodes 
//          router will handle the data routing 
//
// cb_dist

int kibnal_dist(nal_cb_t *nal, ptl_nid_t nid, unsigned long *dist)
{
        CDEBUG(D_NET, "kibnal_dist \n");

        if ( nal->ni.nid == nid ) {
                *dist = 0;
        } 
        else {
                *dist = 1;
        }

        return 0; // always retrun 0 
}


//
// This is the cb_send() on IB based interconnect system
// prepare a data package and use VAPI_post_sr() to send it
// down-link out-going message 
//


int
kibnal_send(nal_cb_t        *nal,
            void            *private,
            lib_msg_t       *cookie,
            ptl_hdr_t       *hdr,
            int              type,
            ptl_nid_t        nid,
            ptl_pid_t        pid,
            unsigned int     niov,
            ptl_kiov_t      *iov,
            size_t           len)
{
        
        int           rc=0;
        void         *buf = NULL; 
        unsigned long buf_length = sizeof(ptl_hdr_t) + len;
        int           expected_buf_size = 0;
        VAPI_ret_t    vstat;

        PROF_START(kibnal_send); // time stamp send start 

        CDEBUG(D_NET,"kibnal_send: sending %d bytes from %p to nid: 0x%Lx pid %d\n",
               buf_length, iov, nid, HCA_PORT_1);


        // do I need to check the gateway information
        // do I have problem to send direct 
        // do I have to forward a data packet to gateway
        // 
        // The current connection is back-to-back 
        // I always know that data will be send from one-side to
        // the other side
        //
        
        //
        //  check data buffer size 
        //
        //  MSG_SIZE_SMALL 
        //      regular post send 
        //  
        //  MSG_SIZE_LARGE
        //      rdma write
        
        if(buf_length <= SMALL_MSG_SIZE) {  
           expected_buf_size = MSG_SIZE_SMALL;
        } 
        else { 
          if(buf_length > MAX_MSG_SIZE) { 
             CERROR("kibnal_send:request exceeds Transmit data size (%d).\n",
                      MAX_MSG_SIZE);
             rc = -1;
             return rc;
          }
          else {
             expected_buf_size = MSG_SIZE_LARGE; // this is a large data package 
          } 
        }
                
        // prepare data packet for send operation 
        //
        // allocate a data buffer "buf" with size of buf_len(header + payload)
        //                 ---------------
        //  buf            | hdr         |  size = sizeof(ptl_hdr_t)
        //                 --------------
        //                 |payload data |  size = len
        //                 ---------------
        
        // copy header to buf 
        memcpy(buf, hdr, sizeof(ptl_hdr_t));

        // copy payload data from iov to buf
        // use portals library function lib_copy_iov2buf()
        
        if (len != 0)
           lib_copy_iov2buf(((char *)buf) + sizeof (ptl_hdr_t),
                            niov, 
                            iov, 
                            len);

        // buf is ready to do a post send 
        // the send method is base on the buf_size 

        CDEBUG(D_NET,"ib_send %d bytes (size %d) from %p to nid: 0x%Lx "
               " port %d\n", buf_length, expected_buf_size, iov, nid, HCA_PORT_1);

        switch(expected_buf_size) {
          case MSG_SIZE_SMALL:
            // send small message 
            if((vstat = Send_Small_Msg(buf, buf_length)) != VAPI_OK){
                CERROR("Send_Small_Msg() is failed\n");
            } 
            break;

          case MSG_SIZE_LARGE:
            // send small message 
            if((vstat = Send_Large_Msg(buf, buf_length)) != VAPI_OK){
                CERROR("Send_Large_Msg() is failed\n");
            } 
            break;

          default:
            CERROR("Unknown message size %d\n", expected_buf_size);
            break;
        }

        PROF_FINISH(kibnal_send); // time stapm of send operation 

        rc = 1;

        return rc; 
}

//
// kibnal_send_pages
//
// no support 
//
// do you need this 
//
int kibnal_send_pages(nal_cb_t * nal, 
                      void *private, 
                      lib_msg_t * cookie,
                      ptl_hdr_t * hdr, 
                      int type, 
                      ptl_nid_t nid, 
                      ptl_pid_t pid,
                      unsigned int niov, 
                      ptl_kiov_t *iov, 
                      size_t mlen)
{
   int rc = 1;

   CDEBUG(D_NET, "kibnal_send_pages\n");

   // do nothing now for Infiniband 
   
   return rc;
}





//
// kibnal_fwd_packet 
//
// no support 
//
// do you need this 
//
void kibnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd)
{
        CDEBUG(D_NET, "forwarding not implemented\n");
        return;
      
}

//
// kibnal_callback 
//
// no support 
//
// do you need this 
//
int kibnal_callback(nal_cb_t * nal, 
                           void *private, 
                           lib_eq_t *eq,
                           ptl_event_t *ev)
{
        CDEBUG(D_NET,  "callback not implemented\n");
        return PTL_OK;
}


/* Process a received portals packet */
//
//  conver receiving data in to PORTALS header 
//

void kibnal_rx(kibnal_data_t    *kib, 
                      VAPI_virt_addr_t buffer_addr,
                      u_int32_t        buffer_len,
                      u_int32_t        buffer_size,
                      unsigned int     priority) 
{
        ptl_hdr_t  *hdr = (ptl_hdr_t *)  buffer_addr; // case to ptl header format 
        kibnal_rx_t krx;

        CDEBUG(D_NET,"kibnal_rx: buf %p, len %ld\n", buffer_addr, buffer_len);

        if ( buffer_len < sizeof( ptl_hdr_t ) ) {
                /* XXX what's this for? */
                if (kib->kib_shuttingdown)
                        return;
                CERROR("kibnal_rx: did not receive complete portal header, "
                       "len= %ld", buffer_len);

                return;
        }

       // typedef struct {
       //         char             *krx_buffer; // pointer to receiving buffer
       //         unsigned long     krx_len;  // length of buffer
       //         unsigned int      krx_size; //
       //         unsigned int      krx_priority; // do we need this
       //         struct list_head  krx_item;
       // } kibnal_rx_t;
       //
        krx.krx_buffer    = hdr;
        krx.krx_len       = buffer_len;
        krx.krx_size      = buffer_size;
        krx.krx_priority  = priority;

        if ( hdr->dest_nid == kibnal_lib.ni.nid ) {
           // this is my data 
           PROF_START(lib_parse);

           lib_parse(&kibnal_lib, (ptl_hdr_t *)krx.krx_buffer, &krx);

           PROF_FINISH(lib_parse);
        } else {
           /* forward to gateway */
           // Do we expect this happened ?
           //      
           CERROR("kibnal_rx: forwarding not implemented yet");
        }

        return;
}




//
// kibnal_recv_pages 
//
// no support 
//
// do you need this 
//
int
kibnal_recv_pages(nal_cb_t * nal, 
                  void *private, 
                  lib_msg_t * cookie,
                  unsigned int niov, 
                  ptl_kiov_t *iov, 
                  size_t mlen,
                  size_t rlen)
{

  CDEBUG(D_NET, "recv_pages not implemented\n");
  return PTL_OK;
       
}


int 
kibnal_recv(nal_cb_t     *nal,
            void         *private,
            lib_msg_t    *cookie,
            unsigned int  niov,
            struct iovec *iov,
            size_t        mlen,
            size_t        rlen)
{
        kibnal_rx_t *krx = private;

        CDEBUG(D_NET,"kibnal_recv: mlen=%d, rlen=%d\n", mlen, rlen);

        /* What was actually received must be >= what sender claims to
         * have sent.  This is an LASSERT, since lib-move doesn't
         * check cb return code yet. */
        LASSERT (krx->krx_len >= sizeof (ptl_hdr_t) + rlen);
        LASSERT (mlen <= rlen);

        PROF_START(kibnal_recv);

        if(mlen != 0) {
                PROF_START(memcpy);
                lib_copy_buf2iov (niov, iov, krx->krx_buffer +
                                  sizeof (ptl_hdr_t), mlen);
                PROF_FINISH(memcpy);
        }

        PROF_START(lib_finalize);
        
        lib_finalize(nal, private, cookie);
        
        PROF_FINISH(lib_finalize);
        PROF_FINISH(kibnal_recv);

        return rlen;
}

//
// kibnal_map 
// no support 
// do you need this 
//
int kibnal_map(nal_cb_t * nal, 
               unsigned int niov, 
               struct iovec *iov,
               void **addrkey)
{
  CDEBUG(D_NET, "map not implemented\n");
  return PTL_OK; 
}



//
// kibnal_unmap
//
// no support 
//
// do you need this 
//
void kibnal_unmap(nal_cb_t * nal, 
                  unsigned int niov, 
                  struct iovec *iov,
                  void **addrkey)
{
  CDEBUG(D_NET, "unmap not implemented\n");
  return;
}



//
// kibnal_map_pages 
// no support 
// do you need this 
/* as (un)map, but with a set of page fragments */
int kibnal_map_pages(nal_cb_t * nal, 
                     unsigned int niov, 
                     ptl_kiov_t *iov,
                     void **addrkey)
{
  CDEBUG(D_NET, "map_pages not implemented\n");
  return PTL_OK;
}



//
// kibnal_unmap_pages 
//
// no support 
//
// do you need this 
//
void kibnal_unmap_pages(nal_cb_t * nal, 
                               unsigned int niov, 
                               ptl_kiov_t *iov,
                               void **addrkey)
{
  CDEBUG(D_NET, "unmap_pages not implemented\n");
  return ;
}


int kibnal_end(kibnal_data_t *kib)
{

  /* wait for sends to finish ? */
  /* remove receive buffers */
  /* shutdown receive thread */

  CDEBUG(D_NET, "kibnal_end\n");
  IB_Close_HCA();

  return 0;
}


//
//
//  asynchronous event handler: response to some unexpetced operation errors 
//    
//  void async_event_handler(VAPI_hca_hndl_t      hca_hndl,
//                           VAPI_event_record_t *event_record_p,
//                           void*                private_data)
//  the HCA drive will prepare evetn_record_p                        
//
//  this handler is registered with VAPI_set_async_event_handler()
//  VAPI_set_async_event_handler() is issued when an HCA is created 
//
//
void async_event_handler(VAPI_hca_hndl_t      hca_hndl,
                         VAPI_event_record_t *event_record_p,  
                         void*                private_data)
{
  //
  // * event_record_p is prepared by the system when an async
  //   event happened
  // * what to do with private_data 
  // * do we expect more async events happened if so what are they 
  //
  //   only log ERROR message now 

  switch (event_record_p->type) {
    case VAPI_PORT_ERROR:
         printk("Got PORT_ERROR event. port number=%d\n", 
                 event_record_p->modifier.port_num);
         break;
    case VAPI_PORT_ACTIVE:
         printk("Got PORT_ACTIVE event. port number=%d\n", 
                 event_record_p->modifier.port_num);
         break;
    case VAPI_QP_PATH_MIGRATED:    /*QP*/
         printk("Got P_PATH_MIGRATED event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_EEC_PATH_MIGRATED:   /*EEC*/
         printk("Got EEC_PATH_MIGRATED event. eec_hndl=%d\n", 
                 event_record_p->modifier.eec_hndl);
         break;
    case VAPI_QP_COMM_ESTABLISHED: /*QP*/
         printk("Got QP_COMM_ESTABLISHED event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_EEC_COMM_ESTABLISHED: /*EEC*/
         printk("Got EEC_COMM_ESTABLISHED event. eec_hndl=%d\n",
                 event_record_p->modifier.eec_hndl);
         break;
    case VAPI_SEND_QUEUE_DRAINED:  /*QP*/
         printk("Got SEND_QUEUE_DRAINED event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_CQ_ERROR:            /*CQ*/
         printk("Got CQ_ERROR event. cq_hndl=%lu\n", 
                 event_record_p->modifier.cq_hndl);
         break;
    case VAPI_LOCAL_WQ_INV_REQUEST_ERROR: /*QP*/
         printk("Got LOCAL_WQ_INV_REQUEST_ERROR event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_LOCAL_WQ_ACCESS_VIOL_ERROR: /*QP*/
         printk("Got LOCAL_WQ_ACCESS_VIOL_ERROR event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_LOCAL_WQ_CATASTROPHIC_ERROR: /*QP*/
         printk("Got LOCAL_WQ_CATASTROPHIC_ERROR event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_PATH_MIG_REQ_ERROR:  /*QP*/
         printk("Got PATH_MIG_REQ_ERROR event. qp_hndl=%lu\n", 
                 event_record_p->modifier.qp_hndl);
         break;
    case VAPI_LOCAL_CATASTROPHIC_ERROR: /*none*/
         printk("Got LOCAL_CATASTROPHIC_ERROR event. \n");
         break;
    default:
         printk(":got non-valid event type=%d. IGNORING\n",
                    event_record_p->type);
  }

}




VAPI_wr_id_t 
search_send_buf(int buf_length)
{
  VAPI_wr_id_t send_id = -1;
  u_int32_t    i;
  int          flag = NO;
  int          loop_count = 0;  

  CDEBUG(D_NET, "search_send_buf \n");
  
  while((flag == NO) && (loop_count < MAX_LOOP_COUNT)) {
    for(i=0; i < NUM_ENTRY; i++) {
      // problem about using spinlock
      spin_lock(&MSB_mutex[i]);
      if(MSbuf_list[i].status == BUF_REGISTERED)  {
        MSbuf_list[i].status = BUF_INUSE;// make send buf as inuse
        flag =  YES;
        spin_unlock(&MSB_mutex[i]);
        break;
      }
      else
        spin_unlock(&MSB_mutex[i]); 
    }

    loop_count++;
    schedule_timeout(200); // wait for a while 
  }
   
  if(flag == NO)  {
    CDEBUG(D_NET, "search_send_buf: could not locate an entry in MSbuf_list\n");
  }

  send_id = (VAPI_wr_id_t ) i;

  return send_id;
}



VAPI_wr_id_t 
search_RDMA_recv_buf(int buf_length)
{
  VAPI_wr_id_t recv_id = -1;
  u_int32_t    i;
  int          flag = NO;
  int          loop_count = 0;  

  CDEBUG(D_NET, "search_RDMA_recv_buf\n");

  while((flag == NO) && (loop_count < MAX_LOOP_COUNT)) {

    for(i=NUM_ENTRY; i < NUM_MBUF; i++) {

      spin_lock(&MSB_mutex[i]);

      if((MRbuf_list[i].status == BUF_REGISTERED)  &&
         (MRbuf_list[i].buf_size >= buf_length)) {
          MSbuf_list[i].status = BUF_INUSE;// make send buf as inuse
          flag =  YES;
          spin_unlock(&MSB_mutex[i]);
          break;
      }
      else
        spin_unlock(&MSB_mutex[i]);
    }

    loop_count++;

    schedule_timeout(200); // wait for a while 
  }
   
  if(flag == NO)  {
    CERROR("search_RDMA_recv_buf: could not locate an entry in MBbuf_list\n");
  }

  recv_id = (VAPI_wr_id_t ) i;

  return recv_id;

}







VAPI_ret_t Send_Small_Msg(char *buf, int buf_length)
{
 VAPI_ret_t           vstat;
 VAPI_sr_desc_t       sr_desc;
 VAPI_sg_lst_entry_t  sr_sg;
 QP_info              *qp;
 VAPI_wr_id_t         send_id;

 CDEBUG(D_NET, "Send_Small_Msg\n");

 send_id = search_send_buf(buf_length); 

 if(send_id < 0){
   CERROR("Send_Small_Msg: Can not find a QP \n");
   return(~VAPI_OK);
 }

 qp = &QP_list[(int) send_id];

 // find a suitable/registered send_buf from MSbuf_list
 CDEBUG(D_NET, "Send_Small_Msg: current send id  %d \n", send_id);

 sr_desc.opcode    = VAPI_SEND;
 sr_desc.comp_type = VAPI_SIGNALED;
 sr_desc.id        =  send_id;


 // scatter and gather info 
 sr_sg.len  = buf_length;
 sr_sg.lkey = MSbuf_list[send_id].mr.l_key; // use send MR 

 sr_sg.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MSbuf_list[send_id].buf_addr;

 // copy data to register send buffer 
 memcpy(&sr_sg.addr, buf, buf_length);

 sr_desc.sg_lst_p = &sr_sg;
 sr_desc.sg_lst_len = 1; // only 1 entry is used 
 sr_desc.fence = TRUE;
 sr_desc.set_se = FALSE;

 // call VAPI_post_sr to send out this data 
 vstat = VAPI_post_sr(qp->hca_hndl, qp->qp_hndl, &sr_desc);

 if (vstat != VAPI_OK) {
    CERROR("VAPI_post_sr failed (%s).\n",VAPI_strerror(vstat));
 }

 CDEBUG(D_NET, "VAPI_post_sr success.\n");

 return (vstat);

}




VAPI_wr_id_t
RTS_handshaking_protocol(int buf_length) 
{

 VAPI_ret_t           vstat;
 VAPI_sr_desc_t       sr_desc;
 VAPI_sg_lst_entry_t  sr_sg;
 VAPI_wr_id_t         send_id;

 RDMA_Info_Exchange   rdma_info;

 rdma_info.opcode     = Ready_To_send;
 rdma_info.buf_length = buf_length; 
 rdma_info.raddr      = (VAPI_virt_addr_t) 0;
 rdma_info.rkey       = (VAPI_rkey_t) 0 ; 

 QP_info              *qp;

 CDEBUG(D_NET, "RTS_handshaking_protocol\n");

 // find a suitable/registered send_buf from MSbuf_list
 send_id = search_send_buf(sizeof(RDMA_Info_Exchange));   

 qp = &QP_list[(int) send_id];

 CDEBUG(D_NET, "RTS_CTS: current send id  %d \n", send_id);
 sr_desc.opcode    = VAPI_SEND;
 sr_desc.comp_type = VAPI_SIGNALED;
 sr_desc.id        = send_id + RDMA_RTS_ID;// this RTS mesage ID 

 // scatter and gather info 
 sr_sg.len  = sizeof(RDMA_Info_Exchange);
 sr_sg.lkey = MSbuf_list[send_id].mr.l_key; // use send MR 
 sr_sg.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MSbuf_list[send_id].buf_addr;

 // copy data to register send buffer 
 memcpy(&sr_sg.addr, &rdma_info, sizeof(RDMA_Info_Exchange));

 sr_desc.sg_lst_p = &sr_sg;
 sr_desc.sg_lst_len = 1; // only 1 entry is used 
 sr_desc.fence = TRUE;
 sr_desc.set_se = FALSE;

 // call VAPI_post_sr to send out this RTS message data 
 vstat = VAPI_post_sr(qp->hca_hndl, qp->qp_hndl, &sr_desc);

 if (vstat != VAPI_OK) {
    CERROR("RTS: VAPI_post_sr failed (%s).\n",VAPI_strerror_sym(vstat));
 }

 return send_id;

}



// create local receiving Memory Region for a HCA
VAPI_ret_t
createMemRegion_RDMA(VAPI_hca_hndl_t  hca_hndl,
                     VAPI_pd_hndl_t   pd_hndl,
                     char            *bufptr,
                     int              buf_length,
                     VAPI_mr_hndl_t   *rep_mr_hndl,
                     VAPI_mrw_t       *rep_mr)
{
  VAPI_ret_t      vstat;
  VAPI_mrw_t      mrw;
  
  CDEBUG(D_NET, "createMemRegion_RDMA\n");

  // memory region address and size of memory region
  // allocate a block of memory for this HCA 
  // RDMA data buffer
  
  
  if(bufptr == NULL) {
    // need to allcate a local buffer to receive data from a
    // remore VAPI_RDMA_WRITE_IMM
    PORTAL_ALLOC(bufptr, buf_length);
  }

  if(bufptr == NULL) {
    CDEBUG(D_MALLOC, "Failed to malloc a block of RDMA receiving memory, size %d\n",
                                    buf_length);
    return(VAPI_ENOMEM);
  }

  /* Register RDAM data Memory region */
  CDEBUG(D_NET, "Register a RDMA data memory region\n");

  mrw.type   = VAPI_MR;
  mrw.pd_hndl= pd_hndl;
  mrw.start  = (VAPI_virt_addr_t )(MT_virt_addr_t )bufptr;
  mrw.size   = buf_length;
  mrw.acl    = VAPI_EN_LOCAL_WRITE  | 
               VAPI_EN_REMOTE_WRITE | 
               VAPI_EN_REMOTE_READ;

  // register send memory region
  vstat = VAPI_register_mr(hca_hndl,
                           &mrw,
                           rep_mr_hndl,
                           rep_mr);

  // this memory region is going to be reused until deregister is called
  if (vstat != VAPI_OK) {
     CERROR("Failed registering a mem region Addr=%p, Len=%d. %s\n",
             bufptr, buf_length, VAPI_strerror(vstat));
  }

  return(vstat);

}



RDMA_Info_Exchange  Local_rdma_info;

int insert_MRbuf_list(int buf_lenght)
{
  int  recv_id = NUM_ENTRY;      

  CDEBUG(D_NET, "insert_MRbuf_list\n");

  for(recv_id= NUM_ENTRY; recv_id < NUM_MBUF; recv_id++){
       if(BUF_UNREGISTERED == MRbuf_list[recv_id].status)  {
         MRbuf_list[recv_id].status   = BUF_UNREGISTERED;
         MRbuf_list[recv_id].buf_size = buf_lenght;
         break;
       }
  }

  return recv_id;

}  

VAPI_wr_id_t
CTS_handshaking_protocol(RDMA_Info_Exchange *rdma_info) 
{

 VAPI_ret_t           vstat;
 VAPI_sr_desc_t       sr_desc;
 VAPI_sg_lst_entry_t  sr_sg;
 QP_info             *qp;
 VAPI_wr_id_t         send_id;
 VAPI_mr_hndl_t       rep_mr_hndl;
 VAPI_mrw_t           rep_mr;
 int                  recv_id;
 char                *bufptr = NULL;

 // search MRbuf_list for an available entry that
 // has registered data buffer with size equal to rdma_info->buf_lenght

 CDEBUG(D_NET, "CTS_handshaking_protocol\n");

 // register memory buffer for RDAM operation

 vstat = createMemRegion_RDMA(Hca_hndl,
                              Pd_hndl,
                              bufptr, 
                              rdma_info->buf_length,
                              &rep_mr_hndl,
                              &rep_mr);


 Local_rdma_info.opcode            = Clear_To_send;
 Local_rdma_info.recv_rdma_mr      = rep_mr;
 Local_rdma_info.recv_rdma_mr_hndl = rep_mr_hndl;

 if (vstat != VAPI_OK) {
    CERROR("CST_handshaking_protocol: Failed registering a mem region"
           "Len=%d. %s\n", rdma_info->buf_length, VAPI_strerror(vstat));
    Local_rdma_info.flag = RDMA_BUFFER_UNAVAILABLE;
 }
 else {
    // successfully allcate reserved RDAM data buffer 
    recv_id = insert_MRbuf_list(rdma_info->buf_length);   

    if(recv_id >=  NUM_ENTRY) { 
      MRbuf_list[recv_id].buf_addr     = rep_mr.start;
      MRbuf_list[recv_id].mr           = rep_mr;
      MRbuf_list[recv_id].mr_hndl      = rep_mr_hndl;
      MRbuf_list[recv_id].ref_count    = 0;
      Local_rdma_info.flag             = RDMA_BUFFER_RESERVED;
      Local_rdma_info.buf_length       = rdma_info->buf_length; 
      Local_rdma_info.raddr            = rep_mr.start;
      Local_rdma_info.rkey             = rep_mr.r_key; 
    }
    else {
      CERROR("Can not find an entry in MRbuf_list - how could this happen\n");  
    }
 }

 // find a suitable/registered send_buf from MSbuf_list
 send_id = search_send_buf(sizeof(RDMA_Info_Exchange)); 
 CDEBUG(D_NET, "CTS: current send id  %d \n", send_id);
 sr_desc.opcode    = VAPI_SEND;
 sr_desc.comp_type = VAPI_SIGNALED;
 sr_desc.id        = send_id + RDMA_CTS_ID; // this CST message ID 

 // scatter and gather info 
 sr_sg.len  = sizeof(RDMA_Info_Exchange);
 sr_sg.lkey = MSbuf_list[send_id].mr.l_key; // use send MR 
 sr_sg.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MSbuf_list[send_id].buf_addr;

 // copy data to register send buffer 
 memcpy(&sr_sg.addr, &Local_rdma_info, sizeof(RDMA_Info_Exchange));

 sr_desc.sg_lst_p   = &sr_sg;
 sr_desc.sg_lst_len = 1; // only 1 entry is used 
 sr_desc.fence = TRUE;
 sr_desc.set_se = FALSE;

 // call VAPI_post_sr to send out this RTS message data 
 vstat = VAPI_post_sr(qp->hca_hndl, qp->qp_hndl, &sr_desc);

 if (vstat != VAPI_OK) {
    CERROR("CTS: VAPI_post_sr failed (%s).\n",VAPI_strerror(vstat));
 }


}



VAPI_ret_t Send_Large_Msg(char *buf, int buf_length)
{
  VAPI_ret_t           vstat;
  VAPI_sr_desc_t       sr_desc;
  VAPI_sg_lst_entry_t  sr_sg;
  QP_info             *qp;
  VAPI_mrw_t           rep_mr; 
  VAPI_mr_hndl_t       rep_mr_hndl;
  int                  send_id;
  VAPI_imm_data_t      imm_data = 0XAAAA5555;


  CDEBUG(D_NET, "Send_Large_Msg: Enter\n");

  // register this large buf 
  // don't need to copy this buf to send buffer
  vstat = createMemRegion_RDMA(Hca_hndl,
                               Pd_hndl,
                               buf,
                               buf_length,
                               &rep_mr_hndl,
                               &rep_mr);

  if (vstat != VAPI_OK) {
    CERROR("Send_Large_M\sg:  createMemRegion_RDMAi() failed (%s).\n",
                        VAPI_strerror(vstat));
  }
  

  Local_rdma_info.send_rdma_mr      = rep_mr;
  Local_rdma_info.send_rdma_mr_hndl = rep_mr_hndl;

  //
  //     Prepare descriptor for send queue
  //
 
  // ask for a remote rdma buffer with size buf_lenght
  send_id = RTS_handshaking_protocol(buf_length); 

  qp = &QP_list[send_id];

  // wait for CTS message receiving from remote node 
  while(1){
     if(YES == Cts_Message_arrived) {
        // receive CST message from remote node 
        // Rdma_info is available for use
        break;
     }
     schedule_timeout(RTS_CTS_TIMEOUT);
  }
  
  sr_desc.id        = send_id + RDMA_OP_ID;
  sr_desc.opcode    = VAPI_RDMA_WRITE_WITH_IMM;
  sr_desc.comp_type = VAPI_SIGNALED;

  // scatter and gather info 
  sr_sg.len  = buf_length;

  // rdma mr 
  sr_sg.lkey = rep_mr.l_key;  
  sr_sg.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) rep_mr.start;
  sr_desc.sg_lst_p = &sr_sg;
  sr_desc.sg_lst_len = 1; // only 1 entry is used 

  // immediate data - not used here 
  sr_desc.imm_data = imm_data;
  sr_desc.fence = TRUE;
  sr_desc.set_se = FALSE;

  // RDAM operation only
  // raddr and rkey is receiving from remote node  
  sr_desc.remote_addr = Rdma_info.raddr;
  sr_desc.r_key       = Rdma_info.rkey;

  // call VAPI_post_sr to send out this data 
  vstat = VAPI_post_sr(qp->hca_hndl, qp->qp_hndl, &sr_desc);

  if (vstat != VAPI_OK) {
     CERROR("VAPI_post_sr failed (%s).\n",VAPI_strerror_sym(vstat));
  }

}






//
//  repost_recv_buf
//  post a used recv buffer back to recv WQE list 
//  wrq_id is used to indicate the starting position of recv-buffer 
//
VAPI_ret_t 
repost_recv_buf(QP_info      *qp,
                VAPI_wr_id_t  wrq_id) 
{
  VAPI_rr_desc_t       rr;
  VAPI_sg_lst_entry_t  sg_entry;
  VAPI_ret_t           ret;

  CDEBUG(D_NET, "repost_recv_buf\n");

  sg_entry.lkey = MRbuf_list[wrq_id].mr.l_key;
  sg_entry.len  = MRbuf_list[wrq_id].buf_size;
  sg_entry.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MRbuf_list[wrq_id].buf_addr;
  rr.opcode     = VAPI_RECEIVE;
  rr.comp_type  = VAPI_SIGNALED; /* All with CQE (IB compliant) */
  rr.sg_lst_len = 1; /* single buffers */
  rr.sg_lst_p   = &sg_entry;
  rr.id         = wrq_id; /* WQE id used is the index to buffers ptr array */

  ret= VAPI_post_rr(qp->hca_hndl,qp->qp_hndl,&rr);
     
  if (ret != VAPI_OK){
     CERROR("failed reposting RQ WQE (%s) buffer \n",VAPI_strerror_sym(ret));
     return ret;
  }

  CDEBUG(D_NET, "Successfully reposting an RQ WQE %d recv bufer \n", wrq_id);

  return ret ;
}
			
//
// post_recv_bufs
// 	post "num_o_bufs" for receiving data
//      each receiving buf (buffer starting address, size of buffer)
//      each buffer is associated with an id 
//
int 
post_recv_bufs(VAPI_wr_id_t  start_id)
{
  int i;
  VAPI_rr_desc_t       rr;
  VAPI_sg_lst_entry_t  sg_entry;
  VAPI_ret_t           ret;

  CDEBUG(D_NET, "post_recv_bufs\n");

  for(i=0; i< NUM_ENTRY; i++) {
    sg_entry.lkey = MRbuf_list[i].mr.l_key;
    sg_entry.len  = MRbuf_list[i].buf_size;
    sg_entry.addr = (VAPI_virt_addr_t)(MT_virt_addr_t) MRbuf_list[i].buf_addr;
    rr.opcode     = VAPI_RECEIVE;
    rr.comp_type  = VAPI_SIGNALED;  /* All with CQE (IB compliant) */
    rr.sg_lst_len = 1; /* single buffers */
    rr.sg_lst_p   = &sg_entry;
    rr.id         = start_id+i; /* WQE id used is the index to buffers ptr array */

    ret= VAPI_post_rr(QP_list[i].hca_hndl,QP_list[i].qp_hndl, &rr);
    if (ret != VAPI_OK) {
       CERROR("failed posting RQ WQE (%s)\n",VAPI_strerror_sym(ret));
       return i;
    } 
  }

  return i; /* num of buffers posted */
}
			
int 
post_RDMA_bufs(QP_info      *qp, 
               void         *buf_array,
               unsigned int  num_bufs,
               unsigned int  buf_size,
               VAPI_wr_id_t  start_id)
{

  CDEBUG(D_NET, "post_RDMA_bufs \n");
  return YES;
}



//
// LIB NAL
// assign function pointers to theirs corresponding entries
//

nal_cb_t kibnal_lib = {
        nal_data:       &kibnal_data,  /* NAL private data */
        cb_send:        kibnal_send,
        cb_send_pages:  NULL, // not implemented  
        cb_recv:        kibnal_recv,
        cb_recv_pages:  NULL, // not implemented 
        cb_read:        kibnal_read,
        cb_write:       kibnal_write,
        cb_callback:    NULL, // not implemented 
        cb_malloc:      kibnal_malloc,
        cb_free:        kibnal_free,
        cb_map:         NULL, // not implemented 
        cb_unmap:       NULL, // not implemented 
        cb_map_pages:   NULL, // not implemented 
        cb_unmap_pages: NULL, // not implemented 
        cb_printf:      kibnal_printf,
        cb_cli:         kibnal_cli,
        cb_sti:         kibnal_sti,
        cb_dist:        kibnal_dist // no used at this moment 
};
