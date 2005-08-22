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
 *      Portals GM kernel NAL header file
 *      This file makes all declaration and prototypes 
 *      for the API side and CB side of the NAL
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
 *      Defines for the API NAL
 */

/* Wire protocol */

typedef struct {
        ptl_hdr_t       gmim_hdr;               /* portals header */
        char            gmim_payload[0];        /* payload */
} gmnal_immediate_msg_t;

typedef struct {
        /* First 2 fields fixed FOR ALL TIME */
        __u32           gmm_magic;              /* I'm a GM message */
        __u16           gmm_version;            /* this is my version number */

        __u16           gmm_type;               /* msg type */
        __u64           gmm_srcnid;             /* sender's NID */
        __u64           gmm_dstnid;             /* destination's NID */
        union {
                gmnal_immediate_msg_t   immediate;
        }               gmm_u;
} WIRE_ATTR gmnal_msg_t;

#define GMNAL_MSG_MAGIC                 0x6d797269 /* 'myri'! */
#define GMNAL_MSG_VERSION               1
#define GMNAL_MSG_IMMEDIATE             1

typedef struct gmnal_tx {
        struct gmnal_tx         *tx_next;
        gmnal_msg_t             *tx_msg;
        int                      tx_buffer_size;
        gm_size_t                tx_gm_size;
        int                      tx_msg_size;
        int                      tx_gmlid;
        int                      tx_gm_priority;
        ptl_nid_t                tx_nid;
        struct gmnal_ni         *tx_gmni;
        lib_msg_t               *tx_libmsg;
        int                      tx_rxt; 
} gmnal_tx_t;

/*
 *      as for gmnal_tx_t 
 *      a hash table in nal_data find rxs from
 *      the rx buffer address. hash table populated at init time
 */
typedef struct gmnal_rx {
        struct list_head         rx_list;
        gmnal_msg_t             *rx_msg;
        int                      rx_size;
        gm_size_t                rx_gmsize;
        unsigned int             rx_recv_nob;
        __u16                    rx_recv_gmid;
        __u8                     rx_recv_port;
        __u8                     rx_recv_type;
        struct gmnal_rx         *rx_next;
} gmnal_rx_t;


/*
 *      1 receive thread started on each CPU
 */
#define NRXTHREADS 10 /* max number of receiver threads */

typedef struct gmnal_ni {
        spinlock_t       gmni_tx_lock;
        struct semaphore gmni_tx_token;
        gmnal_tx_t      *gmni_tx;
        spinlock_t       gmni_rxt_tx_lock;
        struct semaphore gmni_rxt_tx_token;
        gmnal_tx_t      *gmni_rxt_tx;
        gmnal_rx_t      *gmni_rx;
        struct gm_hash  *gmni_rx_hash;
        lib_nal_t       *gmni_libnal;
        struct gm_port  *gmni_port;
        spinlock_t       gmni_gm_lock;          /* serialise GM calls */
        long             gmni_rxthread_pid[NRXTHREADS];
        int              gmni_rxthread_stop_flag;
        spinlock_t       gmni_rxthread_flag_lock;
        long             gmni_rxthread_flag;
        long             gmni_ctthread_pid;
        int              gmni_ctthread_flag;
        gm_alarm_t       gmni_ctthread_alarm;
        int              gmni_msg_size;
        struct list_head gmni_rxq;
        spinlock_t       gmni_rxq_lock;
        struct semaphore gmni_rxq_wait;
} gmnal_ni_t;

/*
 *      Flags to start/stop and check status of threads
 *      each rxthread sets 1 bit (any bit) of the flag on startup
 *      and clears 1 bit when exiting
 */
#define GMNAL_THREAD_RESET      0
#define GMNAL_THREAD_STOP       666
#define GMNAL_CTTHREAD_STARTED  333
#define GMNAL_RXTHREADS_STARTED ( (1<<num_rx_threads)-1)


/*
 * for ioctl get pid
 */
#define GMNAL_IOC_GET_GNID 1    


/* gmnal_api.c */
int gmnal_init(void);
void  gmnal_fini(void);

/* gmnal_cb.c */
ptl_err_t gmnal_cb_recv(lib_nal_t *libnal, void *private, 
                        lib_msg_t *libmsg,
                        unsigned int niov, struct iovec *iov, 
                        size_t offset, size_t mlen, size_t rlen);
ptl_err_t gmnal_cb_recv_pages(lib_nal_t *libnal, void *private, 
                              lib_msg_t *libmsg, 
                              unsigned int nkiov, ptl_kiov_t *kiov, 
                              size_t offset, size_t mlen, size_t rlen);
ptl_err_t gmnal_cb_send(lib_nal_t *libnal, void *private, 
                        lib_msg_t *libmsg, ptl_hdr_t *hdr, int type, 
                        ptl_nid_t nid, ptl_pid_t pid,
                        unsigned int niov, struct iovec *iov, 
                        size_t offset, size_t len);
ptl_err_t gmnal_cb_send_pages(lib_nal_t *libnal, void *private,
                              lib_msg_t *libmsg, ptl_hdr_t *hdr, int type,
                              ptl_nid_t nid, ptl_pid_t pid, 
                              unsigned int nkiov, ptl_kiov_t *kiov, 
                              size_t offset, size_t len);
int gmnal_cb_dist(lib_nal_t *libnal, ptl_nid_t nid, unsigned long *dist);

/* gmnal_util.c */
int gmnal_is_rxthread(gmnal_ni_t *gmnalni);
int gmnal_alloc_txs(gmnal_ni_t *gmnalni);
void gmnal_free_txs(gmnal_ni_t *gmnalni);
gmnal_tx_t *gmnal_get_tx(gmnal_ni_t *gmnalni, int block);
void gmnal_return_tx(gmnal_ni_t *gmnalni, gmnal_tx_t *tx);
int gmnal_alloc_rxs(gmnal_ni_t *gmnalni);
void gmnal_free_rxs(gmnal_ni_t *gmnalni);
void gmnal_stop_rxthread(gmnal_ni_t *gmnalni);
void gmnal_stop_ctthread(gmnal_ni_t *gmnalni);
char *gmnal_gmstatus2str(gm_status_t status);
char *gmnal_rxevent2str(gm_recv_event_t *ev);
void gmnal_yield(int delay);
int gmnal_enqueue_rx(gmnal_ni_t *gmnalni, gm_recv_t *recv);
gmnal_rx_t *gmnal_dequeue_rx(gmnal_ni_t *gmnalni);
int gmnal_start_kernel_threads(gmnal_ni_t *gmnalni);

/* gmnal_comm.c */
void gmnal_pack_msg(gmnal_ni_t *gmnalni, gmnal_tx_t *tx,
                    ptl_nid_t dstnid, int type);
int gmnal_ct_thread(void *arg);
int gmnal_rx_thread(void *arg);
void gmnal_post_rx(gmnal_ni_t *gmnalni, gmnal_rx_t *rx);
ptl_err_t gmnal_post_tx(gmnal_ni_t *gmnalni, gmnal_tx_t *tx, 
                        lib_msg_t *libmsg, ptl_nid_t nid, int nob);

/* Module Parameters */
extern  int num_rx_threads;
extern  int num_txds;
extern  int gm_port_id;

#endif /*__INCLUDE_GMNAL_H__*/
