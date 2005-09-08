#ifndef _KPING_INCLUDED
#define _KPING_INCLUDED

#include <libcfs/portals_utils.h>
#include <lnet/lnet.h>


#define PTL_PING_IN_SIZE		256	// n packets per buffer
#define PTL_PING_IN_BUFFERS		2	// n fallback buffers

#define PTL_PING_CLIENT			4
#define PTL_PING_SERVER			5

#define PING_HEADER_MAGIC		0xDEADBEEF
#define PING_BULK_MAGIC			0xCAFEBABE

#define PING_HEAD_BITS			0x00000001
#define PING_BULK_BITS			0x00000002
#define PING_IGNORE_BITS		0xFFFFFFFC

#define PTL_PING_ACK			0x01
#define PTL_PING_VERBOSE		0x02
#define PTL_PING_VERIFY			0x04
#define PTL_PING_PREALLOC		0x08


#define NEXT_PRIMARY_BUFFER(index)		\
	(((index + 1) >= PTL_PING_IN_BUFFERS) ? 0 : (index + 1))

#define PDEBUG(str, err)			\
	CERROR ("%s: error=(%d)\n", str, err)


/* Ping data to be passed via the ioctl to kernel space */

#if __KERNEL__

struct pingsrv_data {
	lnet_handle_me_t         me;
        lnet_handle_eq_t         eq;
        void                    *in_buf;
        lnet_process_id_t        my_id;
        lnet_process_id_t        id_local;
        lnet_md_t                mdin;
        lnet_md_t                mdout;
        lnet_handle_md_t         mdin_h;
        lnet_handle_md_t         mdout_h;
        lnet_event_t             evnt;
        cfs_task_t		*tsk;
}; /* struct pingsrv_data */
 
struct pingcli_data {
        
	int                     count;
	int                     size;
	lnet_nid_t              nid;
	int                     timeout;
        lnet_handle_me_t 	me;
        lnet_handle_eq_t	eq;
        char           	       *inbuf;    
        char                   *outbuf;   
        lnet_process_id_t  	myid; 
        lnet_process_id_t  	id_local; 
        lnet_process_id_t  	id_remote;
        lnet_md_t          	md_in_head;
        lnet_md_t          	md_out_head;
        lnet_handle_md_t   	md_in_head_h;
        lnet_handle_md_t   	md_out_head_h;
        lnet_event_t       	ev;
        cfs_task_t		*tsk;
}; /* struct pingcli_data */


#endif /* __KERNEL__ */

#endif /* _KPING_INCLUDED */
