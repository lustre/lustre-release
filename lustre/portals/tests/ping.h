#ifndef _KPING_INCLUDED
#define _KPING_INCLUDED

#include <portals/p30.h>


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
	CERROR ("%s: error=%s (%d)\n", str, ptl_err_str[err], err)


/* Ping data to be passed via the ioctl to kernel space */

#if __KERNEL__


#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,5,0))
#include <linux/workqueue.h>
#else
#include <linux/tqueue.h>
#endif
struct pingsrv_data {
        
        ptl_handle_ni_t         ni;
        ptl_handle_me_t         me;
        ptl_handle_eq_t         eq;
        void                   *in_buf;
        ptl_process_id_t        my_id;
        ptl_process_id_t        id_local;
        ptl_md_t                mdin;
        ptl_md_t                mdout;
        ptl_handle_md_t         mdin_h;
        ptl_handle_md_t         mdout_h;
        ptl_event_t             evnt;
        struct task_struct     *tsk;
}; /* struct pingsrv_data */
 
struct pingcli_data {
        
        struct portal_ioctl_data *args;
        ptl_handle_me_t 	me;
        ptl_handle_eq_t		eq;
        char           	       *inbuf;    
        char                   *outbuf;   
        ptl_process_id_t  	myid; 
        ptl_process_id_t  	id_local; 
        ptl_process_id_t  	id_remote;
        ptl_md_t          	md_in_head;
        ptl_md_t          	md_out_head;
        ptl_handle_md_t   	md_in_head_h;
        ptl_handle_md_t   	md_out_head_h;
        ptl_event_t       	ev;
        struct task_struct     *tsk;
}; /* struct pingcli_data */


#endif /* __KERNEL__ */

#endif /* _KPING_INCLUDED */
