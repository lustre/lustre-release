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
#include "linux/locks.h"
#include "linux/unistd.h"
#include "linux/init.h"
#include "linux/sem.h"
#include "linux/vmalloc.h"

#define DEBUG_SUBSYSTEM S_GMNAL

#include "portals/nal.h"
#include "portals/api.h"
#include "portals/errno.h"
#include "linux/kp30.h"
#include "portals/p30.h"

#include "portals/lib-nal.h"
#include "portals/lib-p30.h"

#define GM_STRONG_TYPES 1
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
#define GMNAL_SMALL_MESSAGE		1078
#define GMNAL_LARGE_MESSAGE_INIT	1079
#define GMNAL_LARGE_MESSAGE_ACK	1080
#define GMNAL_LARGE_MESSAGE_FINI	1081

extern  int gmnal_small_msg_size;
extern  int num_rx_threads;
extern  int num_stxds;
#define GMNAL_SMALL_MSG_SIZE(a)		a->small_msg_size
#define GMNAL_IS_SMALL_MESSAGE(n,a,b,c)	gmnal_is_small_msg(n, a, b, c)
#define GMNAL_MAGIC				0x1234abcd


/*
 *	Small Transmit Descriptor
 *	A structre to keep track of a small transmit operation
 *	This structure has a one-to-one relationship with a small
 *	transmit buffer (both create by gmnal_stxd_alloc). 
 *	There are two free list of stxd. One for use by clients of the NAL
 *	and the other by the NAL rxthreads when doing sends. 
 *	This helps prevent deadlock caused by stxd starvation.
 */
typedef struct _gmnal_stxd_t {
	void 			*buffer;
	int			buffer_size;
	gm_size_t		gm_size;
	int			msg_size;
	int			gm_target_node;
	int			gm_priority;
	int			type;
	struct _gmnal_data_t 	*nal_data;
	lib_msg_t		*cookie;
	int			niov;
	struct iovec		iov[PTL_MD_MAX_IOV];
	struct _gmnal_stxd_t	*next;
        int                     rxt; 
        int                     kniov;
        struct iovec            *iovec_dup;
} gmnal_stxd_t;

/*
 *	keeps a transmit token for large transmit (gm_get)
 *	and a pointer to rxd that is used as context for large receive
 */
typedef struct _gmnal_ltxd_t {
	struct _gmnal_ltxd_t	*next;
	struct	_gmnal_srxd_t  *srxd;
} gmnal_ltxd_t;


/*
 *	as for gmnal_stxd_t 
 *	a hash table in nal_data find srxds from
 *	the rx buffer address. hash table populated at init time
 */
typedef struct _gmnal_srxd_t {
	void 			*buffer;
	int			size;
	gm_size_t		gmsize;
	unsigned int		gm_source_node;
	gmnal_stxd_t		*source_stxd;
	int			type;
	int			nsiov;
	int			nriov;
	struct iovec 		*riov;
	int			ncallbacks;
	spinlock_t		callback_lock;
	int			callback_status;
	lib_msg_t		*cookie;
	struct _gmnal_srxd_t	*next;
	struct _gmnal_data_t	*nal_data;
} gmnal_srxd_t;

/*
 *	Header which lmgnal puts at the start of each message
 */
typedef struct	_gmnal_msghdr {
	int		magic;
	int 		type;
	unsigned int	sender_node_id;
	gmnal_stxd_t	*stxd;
	int		niov;
	} gmnal_msghdr_t;
#define GMNAL_MSGHDR_SIZE	sizeof(gmnal_msghdr_t)

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
typedef struct _gmnal_rxtwe {
	void			*buffer;
	unsigned		snode;
	unsigned		sport;
	unsigned		type;
	unsigned		length;
	struct _gmnal_rxtwe	*next;
} gmnal_rxtwe_t;

/*
 *	1 receive thread started on each CPU
 */
#define NRXTHREADS 10 /* max number of receiver threads */

typedef struct _gmnal_data_t {
	int		refcnt;
	spinlock_t	cb_lock;
	spinlock_t 	stxd_lock;
	struct semaphore stxd_token;
	gmnal_stxd_t	*stxd;
	spinlock_t 	rxt_stxd_lock;
	struct semaphore rxt_stxd_token;
	gmnal_stxd_t	*rxt_stxd;
	spinlock_t 	ltxd_lock;
	struct semaphore ltxd_token;
	gmnal_ltxd_t	*ltxd;
	spinlock_t 	srxd_lock;
	struct semaphore srxd_token;
	gmnal_srxd_t	*srxd;
	struct gm_hash	*srxd_hash;
	nal_t		*nal;	
	nal_cb_t	*nal_cb;
	struct gm_port	*gm_port;
	unsigned int	gm_local_nid;
	unsigned int	gm_global_nid;
	spinlock_t 	gm_lock;
	long		rxthread_pid[NRXTHREADS];
	int		rxthread_stop_flag;
	spinlock_t	rxthread_flag_lock;
	long		rxthread_flag;
	long		ctthread_pid;
	int		ctthread_flag;
	gm_alarm_t	ctthread_alarm;
	int		small_msg_size;
	int		small_msg_gmsize;
	gmnal_rxtwe_t	*rxtwe_head;
	gmnal_rxtwe_t	*rxtwe_tail;
	spinlock_t	rxtwe_lock;
	struct	semaphore rxtwe_wait;
} gmnal_data_t;

/*
 *	Flags to start/stop and check status of threads
 *	each rxthread sets 1 bit (any bit) of the flag on startup
 *	and clears 1 bit when exiting
 */
#define GMNAL_THREAD_RESET	0
#define GMNAL_THREAD_STOP	666
#define GMNAL_CTTHREAD_STARTED	333
#define GMNAL_RXTHREADS_STARTED ( (1<<num_rx_threads)-1)


extern gmnal_data_t	*global_nal_data;

/*
 *	The gm_port to use for gmnal
 */
#define GMNAL_GM_PORT	4

/*
 * for ioctl get pid
 */
#define GMNAL_IOC_GET_GNID 1	

/*
 *	Return codes
 */
#define GMNAL_STATUS_OK	0
#define GMNAL_STATUS_FAIL	1
#define GMNAL_STATUS_NOMEM	2


/*
 *	FUNCTION PROTOTYPES
 */

/*
 *	Locking macros
 */

/*
 *	For the Small tx and rx descriptor lists
 */
#define GMNAL_TXD_LOCK_INIT(a)		spin_lock_init(&a->stxd_lock);
#define GMNAL_TXD_LOCK(a)		spin_lock(&a->stxd_lock);
#define GMNAL_TXD_UNLOCK(a)		spin_unlock(&a->stxd_lock);
#define GMNAL_TXD_TOKEN_INIT(a, n)	sema_init(&a->stxd_token, n);
#define GMNAL_TXD_GETTOKEN(a)		down(&a->stxd_token);
#define GMNAL_TXD_TRYGETTOKEN(a)	down_trylock(&a->stxd_token)
#define GMNAL_TXD_RETURNTOKEN(a)	up(&a->stxd_token);

#define GMNAL_RXT_TXD_LOCK_INIT(a)	spin_lock_init(&a->rxt_stxd_lock);
#define GMNAL_RXT_TXD_LOCK(a)		spin_lock(&a->rxt_stxd_lock);
#define GMNAL_RXT_TXD_UNLOCK(a)	        spin_unlock(&a->rxt_stxd_lock);
#define GMNAL_RXT_TXD_TOKEN_INIT(a, n)	sema_init(&a->rxt_stxd_token, n);
#define GMNAL_RXT_TXD_GETTOKEN(a)	down(&a->rxt_stxd_token);
#define GMNAL_RXT_TXD_TRYGETTOKEN(a)	down_trylock(&a->rxt_stxd_token)
#define GMNAL_RXT_TXD_RETURNTOKEN(a)	up(&a->rxt_stxd_token);

#define GMNAL_LTXD_LOCK_INIT(a)		spin_lock_init(&a->ltxd_lock);
#define GMNAL_LTXD_LOCK(a)		spin_lock(&a->ltxd_lock);
#define GMNAL_LTXD_UNLOCK(a)		spin_unlock(&a->ltxd_lock);
#define GMNAL_LTXD_TOKEN_INIT(a, n)	sema_init(&a->ltxd_token, n);
#define GMNAL_LTXD_GETTOKEN(a)		down(&a->ltxd_token);
#define GMNAL_LTXD_TRYGETTOKEN(a)	down_trylock(&a->ltxd_token)
#define GMNAL_LTXD_RETURNTOKEN(a)	up(&a->ltxd_token);

#define GMNAL_RXD_LOCK_INIT(a)		spin_lock_init(&a->srxd_lock);
#define GMNAL_RXD_LOCK(a)		spin_lock(&a->srxd_lock);
#define GMNAL_RXD_UNLOCK(a)		spin_unlock(&a->srxd_lock);
#define GMNAL_RXD_TOKEN_INIT(a, n)	sema_init(&a->srxd_token, n);
#define GMNAL_RXD_GETTOKEN(a)		down(&a->srxd_token);
#define GMNAL_RXD_TRYGETTOKEN(a)	down_trylock(&a->srxd_token)
#define GMNAL_RXD_RETURNTOKEN(a)	up(&a->srxd_token);

#define GMNAL_GM_LOCK_INIT(a)		spin_lock_init(&a->gm_lock);
#define GMNAL_GM_LOCK(a)		spin_lock(&a->gm_lock);
#define GMNAL_GM_UNLOCK(a)		spin_unlock(&a->gm_lock);
#define GMNAL_CB_LOCK_INIT(a)		spin_lock_init(&a->cb_lock);


/*
 *	Memory Allocator
 */

/*
 *	API NAL
 */
int gmnal_api_forward(nal_t *, int, void *, size_t, void *, size_t);

int gmnal_api_shutdown(nal_t *, int);

int gmnal_api_validate(nal_t *, void *, size_t);

void gmnal_api_yield(nal_t *);

void gmnal_api_lock(nal_t *, unsigned long *);

void gmnal_api_unlock(nal_t *, unsigned long *);


#define GMNAL_INIT_NAL(a)	do { 	\
				a->forward = gmnal_api_forward; \
				a->shutdown = gmnal_api_shutdown; \
				a->validate = NULL; \
				a->yield = gmnal_api_yield; \
				a->lock = gmnal_api_lock; \
				a->unlock = gmnal_api_unlock; \
				a->timeout = NULL; \
				a->refct = 1; \
				a->nal_data = NULL; \
				} while (0)


/*
 *	CB NAL
 */

int gmnal_cb_send(nal_cb_t *, void *, lib_msg_t *, ptl_hdr_t *,
	int, ptl_nid_t, ptl_pid_t, unsigned int, struct iovec *, size_t);

int gmnal_cb_send_pages(nal_cb_t *, void *, lib_msg_t *, ptl_hdr_t *,
	int, ptl_nid_t, ptl_pid_t, unsigned int, ptl_kiov_t *, size_t);

int gmnal_cb_recv(nal_cb_t *, void *, lib_msg_t *, 
	unsigned int, struct iovec *, size_t, size_t);

int gmnal_cb_recv_pages(nal_cb_t *, void *, lib_msg_t *, 
	unsigned int, ptl_kiov_t *, size_t, size_t);

int gmnal_cb_read(nal_cb_t *, void *private, void *, user_ptr, size_t);

int gmnal_cb_write(nal_cb_t *, void *private, user_ptr, void *, size_t);

int gmnal_cb_callback(nal_cb_t *, void *, lib_eq_t *, ptl_event_t *);

void *gmnal_cb_malloc(nal_cb_t *, size_t);

void gmnal_cb_free(nal_cb_t *, void *, size_t);

void gmnal_cb_unmap(nal_cb_t *, unsigned int, struct iovec*, void **);

int  gmnal_cb_map(nal_cb_t *, unsigned int, struct iovec*, void **); 

void gmnal_cb_printf(nal_cb_t *, const char *fmt, ...);

void gmnal_cb_cli(nal_cb_t *, unsigned long *);

void gmnal_cb_sti(nal_cb_t *, unsigned long *);

int gmnal_cb_dist(nal_cb_t *, ptl_nid_t, unsigned long *);

nal_t *gmnal_init(int, ptl_pt_index_t, ptl_ac_index_t, ptl_pid_t rpid);

void  gmnal_fini(void);



#define GMNAL_INIT_NAL_CB(a)	do {	\
				a->cb_send = gmnal_cb_send; \
				a->cb_send_pages = gmnal_cb_send_pages; \
				a->cb_recv = gmnal_cb_recv; \
				a->cb_recv_pages = gmnal_cb_recv_pages; \
				a->cb_read = gmnal_cb_read; \
				a->cb_write = gmnal_cb_write; \
				a->cb_callback = gmnal_cb_callback; \
				a->cb_malloc = gmnal_cb_malloc; \
				a->cb_free = gmnal_cb_free; \
				a->cb_map = NULL; \
				a->cb_unmap = NULL; \
				a->cb_printf = gmnal_cb_printf; \
				a->cb_cli = gmnal_cb_cli; \
				a->cb_sti = gmnal_cb_sti; \
				a->cb_dist = gmnal_cb_dist; \
				a->nal_data = NULL; \
				} while (0)


/*
 *	Small and Large Transmit and Receive Descriptor Functions
 */
int  		gmnal_alloc_txd(gmnal_data_t *);
void 		gmnal_free_txd(gmnal_data_t *);
gmnal_stxd_t* 	gmnal_get_stxd(gmnal_data_t *, int);
void 		gmnal_return_stxd(gmnal_data_t *, gmnal_stxd_t *);
gmnal_ltxd_t* 	gmnal_get_ltxd(gmnal_data_t *);
void 		gmnal_return_ltxd(gmnal_data_t *, gmnal_ltxd_t *);

int  		gmnal_alloc_srxd(gmnal_data_t *);
void 		gmnal_free_srxd(gmnal_data_t *);
gmnal_srxd_t* 	gmnal_get_srxd(gmnal_data_t *, int);
void 		gmnal_return_srxd(gmnal_data_t *, gmnal_srxd_t *);

/*
 *	general utility functions
 */
gmnal_srxd_t	*gmnal_rxbuffer_to_srxd(gmnal_data_t *, void*);
void		gmnal_stop_rxthread(gmnal_data_t *);
void		gmnal_stop_ctthread(gmnal_data_t *);
void		gmnal_small_tx_callback(gm_port_t *, void *, gm_status_t);
void		gmnal_drop_sends_callback(gm_port_t *, void *, gm_status_t);
char		*gmnal_gm_error(gm_status_t);
char		*gmnal_rxevent(gm_recv_event_t*);
int		gmnal_is_small_msg(gmnal_data_t*, int, struct iovec*, int);
void 		gmnal_yield(int);
int		gmnal_start_kernel_threads(gmnal_data_t *);


/*
 *	Communication functions
 */

/*
 *	Receive threads
 */
int 		gmnal_ct_thread(void *); /* caretaker thread */
int 		gmnal_rx_thread(void *); /* receive thread */
int 		gmnal_pre_receive(gmnal_data_t*, gmnal_rxtwe_t*, int);
int		gmnal_rx_bad(gmnal_data_t *, gmnal_rxtwe_t *, gmnal_srxd_t*);
int		gmnal_rx_requeue_buffer(gmnal_data_t *, gmnal_srxd_t *);
int		gmnal_add_rxtwe(gmnal_data_t *, gm_recv_t *);
gmnal_rxtwe_t * gmnal_get_rxtwe(gmnal_data_t *);
void		gmnal_remove_rxtwe(gmnal_data_t *);


/*
 *	Small messages
 */
int 		gmnal_small_rx(nal_cb_t *, void *, lib_msg_t *, unsigned int, 
			        struct iovec *, size_t, size_t);
int 		gmnal_small_tx(nal_cb_t *, void *, lib_msg_t *, ptl_hdr_t *, 
				int, ptl_nid_t, ptl_pid_t, 
				unsigned int, struct iovec*, int);
void 		gmnal_small_tx_callback(gm_port_t *, void *, gm_status_t);



/*
 *	Large messages
 */
int 		gmnal_large_rx(nal_cb_t *, void *, lib_msg_t *, unsigned int, 
				struct iovec *, size_t, size_t);

int 		gmnal_large_tx(nal_cb_t *, void *, lib_msg_t *, ptl_hdr_t *, 
				int, ptl_nid_t, ptl_pid_t, unsigned int, 
				struct iovec*, int);

void 		gmnal_large_tx_callback(gm_port_t *, void *, gm_status_t);

int 		gmnal_remote_get(gmnal_srxd_t *, int, struct iovec*, int, 
				  struct iovec*);

void		gmnal_remote_get_callback(gm_port_t *, void *, gm_status_t);

int 		gmnal_copyiov(int, gmnal_srxd_t *, int, struct iovec*, int, 
			       struct iovec*);

void 		gmnal_large_tx_ack(gmnal_data_t *, gmnal_srxd_t *);
void 		gmnal_large_tx_ack_callback(gm_port_t *, void *, gm_status_t);
void 		gmnal_large_tx_ack_received(gmnal_data_t *, gmnal_srxd_t *);

#endif /*__INCLUDE_GMNAL_H__*/
