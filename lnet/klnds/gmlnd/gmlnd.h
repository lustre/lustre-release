/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 *
 *   This file is part of Lustre, http://www.lustre.org/
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


/*
 *	Portals GM kernel NAL header file
 *	This file makes all declaration and prototypes 
 *	for the API side and CB side of the NAL
 */
#ifndef __INCLUDE_GMNAL_H__
#define __INCLUDE_GMNAL_H__

/* XXX Lustre as of V1.2.2 drop defines VERSION, which causes problems
 * when including <GM>/include/gm_lanai.h which defines a structure field
 * with the name VERSION XXX */
#ifdef VERSION
# undef VERSION
#endif

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include "linux/config.h"
#include "linux/module.h"
#include "linux/tty.h"
#include "linux/kernel.h"
#include "linux/mm.h"
#include "linux/string.h"
#include "linux/stat.h"
#include "linux/errno.h"
#include "linux/version.h"
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#include "linux/buffer_head.h"
#include "linux/fs.h"
#else
#include "linux/locks.h"
#endif
#include "linux/unistd.h"
#include "linux/init.h"
#include "linux/sem.h"
#include "linux/vmalloc.h"
#include "linux/sysctl.h"

#define DEBUG_SUBSYSTEM S_NAL

#include "portals/nal.h"
#include "portals/api.h"
#include "portals/errno.h"
#include "libcfs/kp30.h"
#include "portals/p30.h"

#include "portals/nal.h"
#include "portals/lib-p30.h"

/* undefine these before including the GM headers which clash */
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#define GM_STRONG_TYPES 1
#ifdef VERSION
#undef VERSION
#endif
#include "gm.h"
#include "gm_internal.h"



/*
 *	Defines for the API NAL
 */

/*
 *	Small message size is configurable
 *	insmod can set small_msg_size
 *	which is used to populate nal_data.small_msg_size
 */
#define GMNAL_MAGIC			0x1234abcd

#define GMNAL_SMALL_MESSAGE		1078

extern  int num_rx_threads;
extern  int num_stxds;
extern  int gm_port_id;

/*
 *	Small Transmit Descriptor
 *	A structre to keep track of a small transmit operation
 *	This structure has a one-to-one relationship with a small
 *	transmit buffer (both create by gmnal_stxd_alloc). 
 *	There are two free list of stxd. One for use by clients of the NAL
 *	and the other by the NAL rxthreads when doing sends. 
 *	This helps prevent deadlock caused by stxd starvation.
 */
typedef struct gmnal_stxd {
	struct gmnal_stxd	*tx_next;
	void 			*tx_buffer;
	int			 tx_buffer_size;
	gm_size_t		 tx_gm_size;
	int			 tx_msg_size;
	int			 tx_gmlid;
	int			 tx_gm_priority;
	int			 tx_type;
        ptl_nid_t                tx_nid;
	struct gmnal_ni 	*tx_gmni;
	lib_msg_t		*tx_cookie;
	int			 tx_niov;
        int                      tx_rxt; 
        int                      tx_kniov;
        struct iovec            *tx_iovec_dup;
	struct iovec		 tx_iov[PTL_MD_MAX_IOV];
} gmnal_stxd_t;

/*
 *	as for gmnal_stxd_t 
 *	a hash table in nal_data find srxds from
 *	the rx buffer address. hash table populated at init time
 */
typedef struct gmnal_srxd {
	void 			*rx_buffer;
	int			 rx_size;
	gm_size_t		 rx_gmsize;
	unsigned int		 rx_sender_gmid;
	__u64		         rx_source_stxd;
	int			 rx_type;
	int			 rx_nsiov;
	int			 rx_nriov;
	struct iovec 		*rx_riov;
	int			 rx_ncallbacks;
	spinlock_t		 rx_callback_lock;
	int			 rx_callback_status;
	lib_msg_t		*rx_cookie;
	struct gmnal_srxd	*rx_next;
	struct gmnal_ni 	*rx_gmni;
} gmnal_srxd_t;

/*
 *	Header which lmgnal puts at the start of each message
 *	watch alignment for ia32/64 interaction
 */
typedef struct gmnal_msghdr {
	__s32		gmm_magic;
	__s32 		gmm_type;
	__s32		gmm_niov;
	__u32	        gmm_sender_gmid;
	__u64           gmm_stxd_remote_ptr;
} WIRE_ATTR gmnal_msghdr_t;

/*
 *	the caretaker thread (ct_thread) gets receive events
 *	(and other events) from the myrinet device via the GM2 API.
 *	caretaker thread populates one work entry for each receive event,
 *	puts it on a Q in nal_data and wakes a receive thread to  
 *	process the receive.  
 *	Processing a portals receive can involve a transmit operation. 
 *	Because of this the caretaker thread cannot process receives 
 *	as it may get deadlocked when supply of transmit descriptors 
 *	is exhausted (as caretaker thread is responsible for replacing 
 *	transmit descriptors on the free list)
 */
typedef struct gmnal_rxtwe {
	void			*buffer;
	unsigned		snode;
	unsigned		sport;
	unsigned		type;
	unsigned		length;
	struct gmnal_rxtwe	*next;
} gmnal_rxtwe_t;

/*
 *	1 receive thread started on each CPU
 */
#define NRXTHREADS 10 /* max number of receiver threads */

typedef struct gmnal_ni {
	spinlock_t	 gmni_stxd_lock;
	struct semaphore gmni_stxd_token;
	gmnal_stxd_t	*gmni_stxd;
	spinlock_t 	 gmni_rxt_stxd_lock;
	struct semaphore gmni_rxt_stxd_token;
	gmnal_stxd_t	*gmni_rxt_stxd;
	gmnal_srxd_t	*gmni_srxd;
	struct gm_hash	*gmni_srxd_hash;
	nal_t		*gmni_nal;	
	lib_nal_t	*gmni_libnal;
	struct gm_port	*gmni_port;
	__u32            gmni_local_gmid;
	__u32            gmni_global_gmid;
	spinlock_t 	 gmni_gm_lock;          /* serialise GM calls */
	long		 gmni_rxthread_pid[NRXTHREADS];
	int		 gmni_rxthread_stop_flag;
	spinlock_t	 gmni_rxthread_flag_lock;
	long		 gmni_rxthread_flag;
	long		 gmni_ctthread_pid;
	int		 gmni_ctthread_flag;
	gm_alarm_t	 gmni_ctthread_alarm;
	int		 gmni_small_msg_size;
	int		 gmni_small_msg_gmsize;
	gmnal_rxtwe_t	*gmni_rxtwe_head;
	gmnal_rxtwe_t	*gmni_rxtwe_tail;
	spinlock_t	 gmni_rxtwe_lock;
	struct semaphore gmni_rxtwe_wait;
} gmnal_ni_t;

/*
 *	Flags to start/stop and check status of threads
 *	each rxthread sets 1 bit (any bit) of the flag on startup
 *	and clears 1 bit when exiting
 */
#define GMNAL_THREAD_RESET	0
#define GMNAL_THREAD_STOP	666
#define GMNAL_CTTHREAD_STARTED	333
#define GMNAL_RXTHREADS_STARTED ( (1<<num_rx_threads)-1)


/*
 * for ioctl get pid
 */
#define GMNAL_IOC_GET_GNID 1	

/*
 *	FUNCTION PROTOTYPES
 */

/*
 *	API NAL
 */
int gmnal_api_startup(nal_t *, ptl_pid_t, 
                      ptl_ni_limits_t *, ptl_ni_limits_t *);

int gmnal_api_forward(nal_t *, int, void *, size_t, void *, size_t);

void gmnal_api_shutdown(nal_t *);

int gmnal_api_validate(nal_t *, void *, size_t);

void gmnal_api_yield(nal_t *, unsigned long *, int);

void gmnal_api_lock(nal_t *, unsigned long *);

void gmnal_api_unlock(nal_t *, unsigned long *);


/*
 *	CB NAL
 */

ptl_err_t gmnal_cb_send(lib_nal_t *, void *, lib_msg_t *, ptl_hdr_t *,
	int, ptl_nid_t, ptl_pid_t, unsigned int, struct iovec *, size_t, size_t);

ptl_err_t gmnal_cb_send_pages(lib_nal_t *, void *, lib_msg_t *, ptl_hdr_t *,
	int, ptl_nid_t, ptl_pid_t, unsigned int, ptl_kiov_t *, size_t, size_t);

ptl_err_t gmnal_cb_recv(lib_nal_t *, void *, lib_msg_t *, 
	unsigned int, struct iovec *, size_t, size_t, size_t);

ptl_err_t gmnal_cb_recv_pages(lib_nal_t *, void *, lib_msg_t *, 
	unsigned int, ptl_kiov_t *, size_t, size_t, size_t);

int gmnal_cb_dist(lib_nal_t *, ptl_nid_t, unsigned long *);

int gmnal_init(void);

void  gmnal_fini(void);


/*
 *	Small and Large Transmit and Receive Descriptor Functions
 */
int  		gmnal_alloc_txd(gmnal_ni_t *);
void 		gmnal_free_txd(gmnal_ni_t *);
gmnal_stxd_t* 	gmnal_get_stxd(gmnal_ni_t *, int);
void 		gmnal_return_stxd(gmnal_ni_t *, gmnal_stxd_t *);

int  		gmnal_alloc_srxd(gmnal_ni_t *);
void 		gmnal_free_srxd(gmnal_ni_t *);

/*
 *	general utility functions
 */
gmnal_srxd_t	*gmnal_rxbuffer_to_srxd(gmnal_ni_t *, void*);
void		gmnal_stop_rxthread(gmnal_ni_t *);
void		gmnal_stop_ctthread(gmnal_ni_t *);
void		gmnal_drop_sends_callback(gm_port_t *, void *, gm_status_t);
void		gmnal_resume_sending_callback(gm_port_t *, void *, gm_status_t);
char		*gmnal_gm_error(gm_status_t);
char		*gmnal_rxevent(gm_recv_event_t*);
void 		gmnal_yield(int);
int		gmnal_start_kernel_threads(gmnal_ni_t *);


/*
 *	Communication functions
 */

/*
 *	Receive threads
 */
int 		gmnal_ct_thread(void *); /* caretaker thread */
int 		gmnal_rx_thread(void *); /* receive thread */
void 		gmnal_pre_receive(gmnal_ni_t*, gmnal_rxtwe_t*, int);
void		gmnal_rx_bad(gmnal_ni_t *, gmnal_rxtwe_t *);
void		gmnal_rx_requeue_buffer(gmnal_ni_t *, gmnal_srxd_t *);
int		gmnal_add_rxtwe(gmnal_ni_t *, gm_recv_t *);
gmnal_rxtwe_t * gmnal_get_rxtwe(gmnal_ni_t *);
void		gmnal_remove_rxtwe(gmnal_ni_t *);


/*
 *	Small messages
 */
ptl_err_t       gmnal_small_tx(lib_nal_t *libnal, void *private, 
                               lib_msg_t *cookie, ptl_hdr_t *hdr, 
                               int type, ptl_nid_t nid, 
                               gmnal_stxd_t *stxd, int size);
void		gmnal_small_tx_callback(gm_port_t *, void *, gm_status_t);

#endif /*__INCLUDE_GMNAL_H__*/
