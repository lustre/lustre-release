#ifndef _IBNAL_H
#define _IBNAL_H

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>

#include <linux/ipc.h>
#include <linux/shm.h>

#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/list.h>
#include <linux/in.h>
#include <unistd.h>

#define DEBUG_SUBSYSTEM S_IBNAL

#include <portals/p30.h>
#include <portals/lib-p30.h>
#include <linux/kp30.h>
#include <linux/kpr.h>

// Infiniband VAPI/EVAPI header files  
// Mellanox MT23108 VAPI
#include <vapi.h>
#include <vapi_types.h>
#include <vapi_common.h>
#include <evapi.h>

// pick a port for this RDMA information exhange between two hosts
#define HOST_PORT           11211 
#define QUEUE_SIZE          1024
#define HCA_PORT_1          1
#define HCA_PORT_2          2 
#define DEBUG_SUBSYSTEM S_IBNAL

#define START_SEND_WRQ_ID        0
#define START_RECV_WRQ_ID        0
#define START_RDMA_WRQ_ID        0  

#define DEFAULT_PRIORITY         100

#define WAIT_FOT_R_RDMA_TIMEOUT 10000
#define MAX_NUM_TRY      3000 

#define MAX_NUM_POLL     300 
#define MAX_LOOP_COUNT   500

#define MAX_GID          32 
#define MCG_BUF_LENGTH   128

#define SHARED_SEGMENT_SIZE   0x10000   
#define HCA_EXCHANGE_SHM_KEY  999 // shared memory key for HCA data exchange 

// some internals opcodes for IB operations used in IBNAL
#define SEND_QP_INFO          0X00000001 
#define RECV_QP_INFO          0X00000010 

// Mellanox InfiniHost MT23108 
// QP/CQ related information
//

#define MTU_256     1 /* 1-256,2-512,3-1024,4-2048 */
#define MTU_512     2 /* 1-256,2-512,3-1024,4-2048 */
#define MTU_1024    3 /* 1-256,2-512,3-1024,4-2048 */
#define MTU_2048    4 /* 1-256,2-512,3-1024,4-2048 */

// number of entries for each CQ and WQ 
// how much do we need ?
#define NUM_CQE        1024
#define NUM_WQE        1024 
#define MAX_OUT_SQ     64 
#define MAX_OUT_RQ     64

#define NUM_MBUF       256 
#define NUM_RDMA_RESERVED_ENTRY 128 
#define NUM_QPS        256 

#define INVALID_WR_ID  ((VAPI_wr_id_t) -1)


// for Vector IO 
// scatter and gather 
// Portals can support upto 64 IO-Vectors 
// how much do we need ? 
#define NUM_SGE        1 
#define NUM_SG         1 
#define NUM_CQ	       1	

#define ONE_KB    1024
#define ONE_MB    1024 * ONE_KB 
#define ONE_GB    1024 * ONE_MB 


#define KB_4      1024 * 4 
#define KB_8      1024 * 8 
#define KB_16     1024 * 16
#define KB_32     1024 * 32
#define KB_64     1024 * 64
#define KB_128    1024 * 128 
#define KB_256    1024 * 256 

// 256 entry in registered buffer list 
// small size message 
#define Num_4_KB       64 
#define Num_8_KB       64 
#define Num_16_KB      40 
#define Num_32_KB      40 
#define Num_64_KB      40 
#define Num_128_KB     4 
#define Num_256_KB     4 

#define SMALL_MSG_SIZE KB_32     

#define MAX_MSG_SIZE   ONE_MB * 512   

//   128's  64KB bufer for send
//   128's  64KB bufer for recv  
//   used in RDAM operation only 

#define NUM_ENTRY      128 

#define End_4_kb        Num_4_KB 
#define End_8_kb        End_4_kb  + Num_8_KB 
#define End_16_kb       End_8_kb  + Num_16_KB
#define End_32_kb       End_16_kb + Num_32_KB
#define End_64_kb       End_32_kb + Num_64_KB
#define End_128_kb      End_64_kb + Num_128_KB
#define End_256_kb      End_128_kb+ Num_256_KB


#define SEND_BUF_SIZE   KB_32
#define RECV_BUF_SIZE   SEND_BUF_SIZE

// #define POLL_BASED_CQE_HANDLING	1
#define EVENT_BASED_CQE_HANDLING        1
#define IBNAL_SELF_TESTING		1

#ifdef  IBNAL_SELF_TESTING
#undef  IBNAL_SELF_TESTING
#endif


#define MSG_SIZE_SMALL 1 
#define MSG_SIZE_LARGE 2 



// some defauly configuration values for early testing 
#define DEFAULT_DLID   1  // default destination link ID
#define DEFAULT_QP_NUM 4  // default QP number 
#define P_KEY          0xFFFF // do we need default value
#define PKEY_IX        0x0 // do we need default value
#define Q_KEY          0x012  // do we need default value 
#define L_KEY          0x12345678 // do we need default value 
#define R_KEY          0x87654321 // do we need default value 
#define HCA_ID         "InfiniHost0" // default 
#define START_PSN      0
#define START_SQ_PSN   0
#define START_RQ_PSN   0


#define __u_long_long   unsigned long long

#define         IBNAL_DEBUG      1

#define         USE_SHARED_MEMORY_AND_SOCKET 1

// operation type
#define TRY_SEND_ONLY    1

#define YES     1  
#define NO      0 

//
// a common data structure for IB QP's operation
// each QP is associated with an QP_info structure 
//
typedef struct QP_info 
{
  VAPI_hca_hndl_t       hca_hndl;      // HCA handle
  IB_port_t             port;          // port number 
  VAPI_qp_hndl_t        qp_hndl;       // QP's handle list 
  VAPI_qp_state_t       qp_state;      // QP's current state 
  VAPI_pd_hndl_t        pd_hndl;       // protection domain
  VAPI_cq_hndl_t        cq_hndl;    // send-queue CQ's handle 
  VAPI_cq_hndl_t        sq_cq_hndl;    // send-queue CQ's handle 
  VAPI_cq_hndl_t        rq_cq_hndl;    // receive-queue CQ's handle
  VAPI_ud_av_hndl_t     av_hndl;    // receive-queue CQ's handle
  VAPI_qp_init_attr_t   qp_init_attr;  // QP's init attribute 
  VAPI_qp_attr_t        qp_attr;       // QP's attribute - dlid 
  VAPI_qp_prop_t        qp_prop;       // QP's propertities
  VAPI_hca_port_t       hca_port;  
  VAPI_qp_num_t         qp_num;    // QP's number 
  VAPI_qp_num_t         rqp_num;       // remote QP's number 
  IB_lid_t              slid;
  IB_lid_t              dlid;
  VAPI_gid_t            src_gid;

  u_int32_t 	        buf_size;
  VAPI_virt_addr_t      buf_addr;
  char		       *bufptr;
  VAPI_mrw_t            mr;       
  VAPI_mr_hndl_t        mr_hndl;
  VAPI_virt_addr_t      raddr;
  VAPI_rkey_t           rkey;
  VAPI_lkey_t           lkey;

  VAPI_wr_id_t          last_posted_send_id; // user defined work request ID 
  VAPI_wr_id_t          last_posted_rcv_id;  // user defined work request ID
  VAPI_mw_hndl_t        mw_hndl;       // memory window handle 
  VAPI_rkey_t           mw_rkey;       // memory window rkey
  VAPI_sg_lst_entry_t   sg_lst[256];       // scatter and gather list 
  int                   sg_list_sz;    // set as NUM_SGE
  VAPI_wr_id_t          wr_id;         //
  spinlock_t            snd_mutex;
  spinlock_t            rcv_mutex;
  spinlock_t            bl_mutex;
  spinlock_t            cln_mutex;
  int                   cur_RDMA_outstanding;
  int                   cur_send_outstanding;
  int                   cur_posted_rcv_bufs;
  int                   snd_rcv_balance;
} QP_info; 


// buffer status 
#define  BUF_REGISTERED   0x10000000 
#define  BUF_INUSE 	  0x01000000  
#define  BUF_UNREGISTERED 0x00100000 

// buffer type 
#define  REG_BUF          0x10000000
#define  RDMA_BUF         0x01000000 

//
// IMM data 
// 
#define   IMM_000         (0 << 32); 
#define   IMM_001         (1 << 32); 
#define   IMM_002         (2 << 32); 
#define   IMM_003         (3 << 32); 
#define   IMM_004         (4 << 32); 
#define   IMM_005         (5 << 32); 
#define   IMM_006         (6 << 32); 
#define   IMM_007         (7 << 32); 
#define   IMM_008         (8 << 32); 
#define   IMM_009         (9 << 32); 
#define   IMM_010         (10 << 32); 
#define   IMM_011         (11 << 32); 
#define   IMM_012         (12 << 32); 
#define   IMM_013         (13 << 32); 
#define   IMM_014         (14 << 32); 
#define   IMM_015         (15 << 32); 
#define   IMM_016         (16 << 32); 
#define   IMM_017         (17 << 32); 
#define   IMM_018         (18 << 32); 
#define   IMM_019         (19 << 32); 
#define   IMM_020         (20 << 32); 
#define   IMM_021         (21 << 32); 
#define   IMM_022         (22 << 32); 
#define   IMM_023         (23 << 32); 
#define   IMM_024         (24 << 32); 
#define   IMM_025         (25 << 32); 
#define   IMM_026         (26 << 32); 
#define   IMM_027         (27 << 32); 
#define   IMM_028         (28 << 32); 
#define   IMM_029         (29 << 32); 
#define   IMM_030         (30 << 32); 
#define   IMM_031         (31 << 32); 
 


typedef struct Memory_buffer_info{
	u_int32_t 	 buf_size;
	VAPI_virt_addr_t buf_addr;
	char		 *bufptr;
	VAPI_mrw_t       mr;       
	VAPI_mr_hndl_t   mr_hndl;
        int              status;
	int              ref_count;  
        int              buf_type;
	VAPI_virt_addr_t raddr;
	VAPI_rkey_t      rkey;
	VAPI_lkey_t      lkey;
} Memory_buffer_info;

typedef struct RDMA_Info_Exchange {
	int               opcode;
	int               buf_length;
	VAPI_mrw_t        recv_rdma_mr;
	VAPI_mr_hndl_t    recv_rdma_mr_hndl;
	VAPI_mrw_t        send_rdma_mr;
	VAPI_mr_hndl_t    send_rdma_mr_hndl;
	VAPI_virt_addr_t  raddr;
	VAPI_rkey_t       rkey;
	int               flag;
}  RDMA_Info_Exchange;

// opcode for Rdma info exchange RTS/CTS 
#define  Ready_To_send     0x10000000
#define  Clear_To_send     0x01000000

#define  RDMA_RTS_ID	   5555 
#define  RDMA_CTS_ID	   7777 
#define  RDMA_OP_ID	   9999 
#define  SEND_RECV_TEST_ID 2222 
#define  SEND_RECV_TEST_BUF_ID 0 

#define  TEST_SEND_MESSAGE 0x00000001 
#define  TEST_RECV_MESSAGE 0x00000002


#define  RTS_CTS_TIMEOUT           50
#define  RECEIVING_THREAD_TIMEOUT  50 
#define  WAIT_FOR_SEND_BUF_TIMEOUT 50

#define  IBNAL_DEBUG_LEVEL_1   0XFFFFFFFF  
#define  IBNAL_DEBUG_LEVEL_2   D_PORTALS | D_NET   | D_WARNING | D_MALLOC | \ 
			       D_ERROR   | D_OTHER | D_TRACE   | D_INFO
			       

// flag for Rdma info exhange 
#define  RDMA_BUFFER_RESERVED       0x10000000
#define  RDMA_BUFFER_UNAVAILABLE    0x01000000


// receiving data structure 
typedef struct {
        ptl_hdr_t         *krx_buffer; // pointer to receiving buffer
        unsigned long     krx_len;  // length of buffer
        unsigned int      krx_size; // 
        unsigned int      krx_priority; // do we need this 
        struct list_head  krx_item;
}  kibnal_rx_t;

// transmitting data structure 
typedef struct {
        nal_cb_t      *ktx_nal;
        void          *ktx_private;
        lib_msg_t     *ktx_cookie;
        char          *ktx_buffer;
        size_t         ktx_len;
        unsigned long  ktx_size;
        int            ktx_ndx;
        unsigned int   ktx_priority;
        unsigned int   ktx_tgt_node;
        unsigned int   ktx_tgt_port_id;
}  kibnal_tx_t;


typedef struct {
        char              kib_init;
        char              kib_shuttingdown;
        IB_port_t         port_num; // IB port information
        struct list_head  kib_list;
        ptl_nid_t         kib_nid;
        nal_t            *kib_nal; 
        nal_cb_t         *kib_cb;
        struct kib_trans *kib_trans; // do I need this 
        struct tq_struct  kib_ready_tq;
        spinlock_t        kib_dispatch_lock;
}  kibnal_data_t;


//
// A data structure for keeping the HCA information in system
// information related to HCA and hca_handle will be kept here 
//
typedef struct HCA_Info 
{
  VAPI_hca_hndl_t       hca_hndl;     // HCA handle
  VAPI_pd_hndl_t        pd_hndl;      // protection domain
  IB_port_t             port;         // port number 
  int                   num_qp;       // number of qp used  
  QP_info               *qp_ptr[NUM_QPS]; // point to QP_list
  int                   num_cq;       // number of cq used 
  VAPI_cq_hndl_t        cq_hndl;   
  VAPI_cq_hndl_t        sq_cq_hndl;   
  VAPI_cq_hndl_t        rq_cq_hndl;   
  IB_lid_t              dlid;
  IB_lid_t              slid;
  kibnal_data_t         *kib_data; // for PORTALS operations
} HCA_info;




// Remote HCA Info information 
typedef struct Remote_HCA_Info {
        unsigned long     opcode;
        unsigned long     length; 
        IB_lid_t          dlid[NUM_QPS];
        VAPI_qp_num_t     rqp_num[NUM_QPS];
} Remote_QP_Info;

typedef struct  Bucket_index{
     int start;
     int end;
} Bucket_index;

// functional prototypes 
// infiniband initialization 
int kib_init(kibnal_data_t *);

// receiving thread 
void kibnal_recv_thread(HCA_info *);
void recv_thread(HCA_info *);

// forward data packet 
void kibnal_fwd_packet (void *, kpr_fwd_desc_t *);

// global data structures 
extern kibnal_data_t        kibnal_data;
extern ptl_handle_ni_t      kibnal_ni;
extern nal_t                kibnal_api;
extern nal_cb_t             kibnal_lib;
extern QP_info              QP_list[];
extern QP_info              CQ_list[];
extern HCA_info             Hca_data;
extern VAPI_hca_hndl_t      Hca_hndl; 
extern VAPI_pd_hndl_t       Pd_hndl;
extern VAPI_hca_vendor_t    Hca_vendor;
extern VAPI_hca_cap_t       Hca_cap;
extern VAPI_hca_port_t      Hca_port_1_props;
extern VAPI_hca_port_t      Hca_port_2_props;
extern VAPI_hca_attr_t      Hca_attr;
extern VAPI_hca_attr_mask_t Hca_attr_mask;
extern VAPI_cq_hndl_t       Cq_SQ_hndl;   
extern VAPI_cq_hndl_t       Cq_RQ_hndl;   
extern VAPI_cq_hndl_t       Cq_hndl;   
extern unsigned long        User_Defined_Small_Msg_Size;
extern Remote_QP_Info      L_HCA_RDMA_Info;  
extern Remote_QP_Info      R_HCA_RDMA_Info; 
extern unsigned int         Num_posted_recv_buf;
extern int                  R_RDMA_DATA_ARRIVED;
extern Memory_buffer_info   MRbuf_list[];
extern Memory_buffer_info   MSbuf_list[];
extern Bucket_index         Bucket[]; 
extern RDMA_Info_Exchange   Rdma_info;
extern int                  Cts_Message_arrived;
extern RDMA_Info_Exchange   Local_rdma_info;
extern spinlock_t	    MSB_mutex[];



// kernel NAL API function prototype 
int  kibnal_forward(nal_t *,int ,void *,size_t ,void *,size_t );
void kibnal_lock(nal_t *, unsigned long *);
void kibnal_unlock(nal_t *, unsigned long *);
int  kibnal_shutdown(nal_t *, int );
void kibnal_yield( nal_t * );
void kibnal_invalidate(nal_cb_t *,void *,size_t ,void *);
int  kibnal_validate(nal_cb_t *,void *,size_t ,void  **);



nal_t *kibnal_init(int , ptl_pt_index_t , ptl_ac_index_t , ptl_pid_t );
void __exit kibnal_finalize(void ); 
VAPI_ret_t create_qp(QP_info *, int );
VAPI_ret_t init_qp(QP_info *, int );
VAPI_ret_t IB_Open_HCA(kibnal_data_t *);
VAPI_ret_t IB_Close_HCA(void );
VAPI_ret_t createMemRegion(VAPI_hca_hndl_t, VAPI_pd_hndl_t); 
VAPI_ret_t  deleteMemRegion(QP_info *, int );

void ibnal_send_recv_self_testing(int *);

int  __init kibnal_initialize(void);



/* CB NAL functions */
int kibnal_send(nal_cb_t *, 
                void *, 
                lib_msg_t *, 
                ptl_hdr_t *,
                int, 
                ptl_nid_t, 
                ptl_pid_t, 
                unsigned int, 
                ptl_kiov_t *, 
                size_t);

int kibnal_send_pages(nal_cb_t *, 
                      void *, 
                      lib_msg_t *, 
                      ptl_hdr_t *,
                      int, 
                      ptl_nid_t, 
                      ptl_pid_t, 
                      unsigned int, 
                      ptl_kiov_t *, 
                      size_t);
int kibnal_recv(nal_cb_t *, void *, lib_msg_t *,
                        unsigned int, struct iovec *, size_t, size_t);
int kibnal_recv_pages(nal_cb_t *, void *, lib_msg_t *,
                        unsigned int, ptl_kiov_t *, size_t, size_t);
int  kibnal_read(nal_cb_t *,void *,void *,user_ptr ,size_t );
int  kibnal_write(nal_cb_t *,void *,user_ptr ,void *,size_t );
int  kibnal_callback(nal_cb_t * , void *, lib_eq_t *, ptl_event_t *);
void *kibnal_malloc(nal_cb_t *,size_t );
void kibnal_free(nal_cb_t *,void *,size_t );
int  kibnal_map(nal_cb_t *, unsigned int , struct iovec *, void **);
void kibnal_unmap(nal_cb_t *, unsigned int , struct iovec *, void **);
int  kibnal_map_pages(nal_cb_t *, unsigned int , ptl_kiov_t *, void **);
void kibnal_unmap_pages(nal_cb_t * , unsigned int , ptl_kiov_t *, void **);
void kibnal_printf(nal_cb_t *, const char *, ...);
void kibnal_cli(nal_cb_t *,unsigned long *); 
void kibnal_sti(nal_cb_t *,unsigned long *);
int  kibnal_dist(nal_cb_t *,ptl_nid_t ,unsigned long *);

void kibnal_fwd_packet (void *, kpr_fwd_desc_t *);
void kibnal_rx(kibnal_data_t *, 
               VAPI_virt_addr_t ,
               u_int32_t,
               u_int32_t,
               unsigned int);
                
int  kibnal_end(kibnal_data_t *);

void async_event_handler(VAPI_hca_hndl_t , VAPI_event_record_t *,void *);

void CQE_event_handler(VAPI_hca_hndl_t ,VAPI_cq_hndl_t , void  *);


VAPI_ret_t Send_Small_Msg(char *, int );
VAPI_ret_t Send_Large_Msg(char *, int );

VAPI_ret_t repost_recv_buf(QP_info *, VAPI_wr_id_t );
int post_recv_bufs(VAPI_wr_id_t );
int  server_listen_thread(void *);
VAPI_wr_id_t RTS_handshaking_protocol(int );
VAPI_wr_id_t CTS_handshaking_protocol(RDMA_Info_Exchange *);

VAPI_ret_t createMemRegion_RDMA(VAPI_hca_hndl_t ,
		                VAPI_pd_hndl_t  ,
				char         *,
				int             , 
	                        VAPI_mr_hndl_t  *,
		                VAPI_mrw_t      *);


VAPI_ret_t IB_Set_Event_Handler(HCA_info , kibnal_data_t *);

VAPI_ret_t IB_Set_Async_Event_Handler(HCA_info ,kibnal_data_t *);

VAPI_wr_id_t find_available_buf(int );
VAPI_wr_id_t search_send_buf(int );
VAPI_wr_id_t find_filler_list(int ,int );
int insert_MRbuf_list(int );


#endif  /* _IBNAL_H */
