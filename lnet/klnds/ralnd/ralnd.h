/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/ralnd/ralnd.h
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/uio.h>

#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>

#include <net/sock.h>
#include <linux/in.h>

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <lnet/lnet-sysctl.h>

#include <rapl.h>

/* tunables determined at compile time */
#define RANAL_RESCHED             100           /* # scheduler loops before reschedule */

#define RANAL_PEER_HASH_SIZE      101           /* # peer lists */
#define RANAL_CONN_HASH_SIZE      101           /* # conn lists */

#define RANAL_MIN_TIMEOUT         5             /* minimum timeout interval (seconds) */
#define RANAL_TIMEOUT2KEEPALIVE(t) (((t)+1)/2)  /* timeout -> keepalive interval */

/* fixed constants */
#define RANAL_MAXDEVS             2             /* max # devices RapidArray supports */
#define RANAL_FMA_MAX_PREFIX      232           /* max bytes in FMA "Prefix" we can use */
#define RANAL_FMA_MAX_DATA        ((7<<10)-256) /* Max FMA MSG is 7K including prefix */


typedef struct
{
        int              *kra_n_connd;          /* # connection daemons */
        int              *kra_min_reconnect_interval; /* first failed connection retry... */
        int              *kra_max_reconnect_interval; /* ...exponentially increasing to this */
        int              *kra_ntx;              /* # tx descs */
        int              *kra_credits;          /* # concurrent sends */
        int              *kra_peercredits;      /* # concurrent sends to 1 peer */
        int              *kra_fma_cq_size;      /* # entries in receive CQ */
        int              *kra_timeout;          /* comms timeout (seconds) */
        int              *kra_max_immediate;    /* immediate payload breakpoint */

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
        cfs_sysctl_table_header_t *kra_sysctl;  /* sysctl interface */
#endif
} kra_tunables_t;

typedef struct
{
        RAP_PVOID              rad_handle;    /* device handle */
        RAP_PVOID              rad_fma_cqh;   /* FMA completion queue handle */
        RAP_PVOID              rad_rdma_cqh;  /* rdma completion queue handle */
        int                    rad_id;        /* device id */
        int                    rad_idx;       /* index in kra_devices */
        int                    rad_ready;     /* set by device callback */
        cfs_list_t             rad_ready_conns;/* connections ready to tx/rx */
        cfs_list_t             rad_new_conns; /* new connections to complete */
        cfs_waitq_t            rad_waitq;     /* scheduler waits here */
        cfs_spinlock_t         rad_lock;      /* serialise */
        void                  *rad_scheduler; /* scheduling thread */
        unsigned int           rad_nphysmap;  /* # phys mappings */
        unsigned int           rad_nppphysmap;/* # phys pages mapped */
        unsigned int           rad_nvirtmap;  /* # virt mappings */
        unsigned long          rad_nobvirtmap;/* # virt bytes mapped */
} kra_device_t;

typedef struct
{
        int               kra_init;            /* initialisation state */
        int               kra_shutdown;        /* shut down? */
        cfs_atomic_t      kra_nthreads;        /* # live threads */
        lnet_ni_t        *kra_ni;              /* _the_ nal instance */

        kra_device_t      kra_devices[RANAL_MAXDEVS]; /* device/ptag/cq */
        int               kra_ndevs;           /* # devices */

        cfs_rwlock_t      kra_global_lock;     /* stabilize peer/conn ops */

        cfs_list_t       *kra_peers;           /* hash table of all my known peers */
        int               kra_peer_hash_size;  /* size of kra_peers */
        cfs_atomic_t      kra_npeers;          /* # peers extant */
        int               kra_nonewpeers;      /* prevent new peers */

        cfs_list_t       *kra_conns;           /* conns hashed by cqid */
        int               kra_conn_hash_size;  /* size of kra_conns */
        __u64             kra_peerstamp;       /* when I started up */
        __u64             kra_connstamp;       /* conn stamp generator */
        int               kra_next_cqid;       /* cqid generator */
        cfs_atomic_t      kra_nconns;          /* # connections extant */

        long              kra_new_min_timeout; /* minimum timeout on any new conn */
        cfs_waitq_t       kra_reaper_waitq;    /* reaper sleeps here */
        cfs_spinlock_t    kra_reaper_lock;     /* serialise */

        cfs_list_t        kra_connd_peers;     /* peers waiting for a connection */
        cfs_list_t        kra_connd_acceptq;   /* accepted sockets to handshake */
        cfs_waitq_t       kra_connd_waitq;     /* connection daemons sleep here */
        cfs_spinlock_t    kra_connd_lock;      /* serialise */

        cfs_list_t        kra_idle_txs;        /* idle tx descriptors */
        __u64             kra_next_tx_cookie;  /* RDMA completion cookie */
        cfs_spinlock_t    kra_tx_lock;         /* serialise */
} kra_data_t;

#define RANAL_INIT_NOTHING         0
#define RANAL_INIT_DATA            1
#define RANAL_INIT_ALL             2

typedef struct kra_acceptsock             /* accepted socket queued for connd */
{
        cfs_list_t           ras_list;          /* queue for attention */
        struct socket       *ras_sock;          /* the accepted socket */
} kra_acceptsock_t;

/************************************************************************
 * Wire message structs.  These are sent in sender's byte order
 * (i.e. receiver checks magic and flips if required).
 */

typedef struct kra_connreq                      /* connection request/response */
{                                               /* (sent via socket) */
        __u32             racr_magic;           /* I'm an ranal connreq */
        __u16             racr_version;         /* this is my version number */
        __u16             racr_devid;           /* sender's device ID */
        __u64             racr_srcnid;          /* sender's NID */
        __u64             racr_dstnid;          /* who sender expects to listen */
        __u64             racr_peerstamp;       /* sender's instance stamp */
        __u64             racr_connstamp;       /* sender's connection stamp */
        __u32             racr_timeout;         /* sender's timeout */
        RAP_RI_PARAMETERS racr_riparams;        /* sender's endpoint info */
} kra_connreq_t;

typedef struct
{
        RAP_MEM_KEY       rard_key;
        RAP_PVOID64       rard_addr;
        RAP_UINT32        rard_nob;
} kra_rdma_desc_t;

typedef struct
{
        lnet_hdr_t        raim_hdr;             /* portals header */
        /* Portals payload is in FMA "Message Data" */
} kra_immediate_msg_t;

typedef struct
{
        lnet_hdr_t        raprm_hdr;            /* portals header */
        __u64             raprm_cookie;         /* opaque completion cookie */
} kra_putreq_msg_t;

typedef struct
{
        __u64             rapam_src_cookie;     /* reflected completion cookie */
        __u64             rapam_dst_cookie;     /* opaque completion cookie */
        kra_rdma_desc_t   rapam_desc;           /* sender's sink buffer */
} kra_putack_msg_t;

typedef struct
{
        lnet_hdr_t        ragm_hdr;             /* portals header */
        __u64             ragm_cookie;          /* opaque completion cookie */
        kra_rdma_desc_t   ragm_desc;            /* sender's sink buffer */
} kra_get_msg_t;

typedef struct
{
        __u64             racm_cookie;          /* reflected completion cookie */
} kra_completion_msg_t;

typedef struct                                  /* NB must fit in FMA "Prefix" */
{
        __u32             ram_magic;            /* I'm an ranal message */
        __u16             ram_version;          /* this is my version number */
        __u16             ram_type;             /* msg type */
        __u64             ram_srcnid;           /* sender's NID */
        __u64             ram_connstamp;        /* sender's connection stamp */
        union {
                kra_immediate_msg_t   immediate;
                kra_putreq_msg_t      putreq;
                kra_putack_msg_t      putack;
                kra_get_msg_t         get;
                kra_completion_msg_t  completion;
        }                    ram_u;
        __u32             ram_seq;              /* incrementing sequence number */
} kra_msg_t;

#define RANAL_MSG_MAGIC     LNET_PROTO_RA_MAGIC /* unique magic */
#define RANAL_MSG_VERSION              1        /* current protocol version */

#define RANAL_MSG_FENCE             0x80        /* fence RDMA */

#define RANAL_MSG_NONE              0x00        /* illegal message */
#define RANAL_MSG_NOOP              0x01        /* empty ram_u (keepalive) */
#define RANAL_MSG_IMMEDIATE         0x02        /* ram_u.immediate */
#define RANAL_MSG_PUT_REQ           0x03        /* ram_u.putreq (src->sink) */
#define RANAL_MSG_PUT_NAK           0x04        /* ram_u.completion (no PUT match: sink->src) */
#define RANAL_MSG_PUT_ACK           0x05        /* ram_u.putack (PUT matched: sink->src) */
#define RANAL_MSG_PUT_DONE          0x86        /* ram_u.completion (src->sink) */
#define RANAL_MSG_GET_REQ           0x07        /* ram_u.get (sink->src) */
#define RANAL_MSG_GET_NAK           0x08        /* ram_u.completion (no GET match: src->sink) */
#define RANAL_MSG_GET_DONE          0x89        /* ram_u.completion (src->sink) */
#define RANAL_MSG_CLOSE             0x8a        /* empty ram_u */

/***********************************************************************/

typedef struct kra_tx                           /* message descriptor */
{
        cfs_list_t            tx_list;      /* queue on idle_txs/rac_sendq/rac_waitq */
        struct kra_conn      *tx_conn;      /* owning conn */
        lnet_msg_t           *tx_lntmsg[2]; /* ptl msgs to finalize on completion */
        unsigned long         tx_qtime;     /* when tx started to wait for something (jiffies) */
        int                   tx_nob;       /* # bytes of payload */
        int                   tx_buftype;   /* payload buffer type */
        void                 *tx_buffer;    /* source/sink buffer */
        int                   tx_phys_offset; /* first page offset (if phys) */
        int                   tx_phys_npages; /* # physical pages */
        RAP_PHYS_REGION      *tx_phys;      /* page descriptors */
        RAP_MEM_KEY           tx_map_key;   /* mapping key */
        RAP_RDMA_DESCRIPTOR   tx_rdma_desc; /* rdma descriptor */
        __u64                 tx_cookie;    /* identify this tx to peer */
        kra_msg_t             tx_msg;       /* FMA message buffer */
} kra_tx_t;

#define RANAL_BUF_NONE           0              /* buffer type not set */
#define RANAL_BUF_IMMEDIATE      1              /* immediate data */
#define RANAL_BUF_PHYS_UNMAPPED  2              /* physical: not mapped yet */
#define RANAL_BUF_PHYS_MAPPED    3              /* physical: mapped already */
#define RANAL_BUF_VIRT_UNMAPPED  4              /* virtual: not mapped yet */
#define RANAL_BUF_VIRT_MAPPED    5              /* virtual: mapped already */

typedef struct kra_conn
{
        struct kra_peer    *rac_peer;           /* owning peer */
        cfs_list_t          rac_list;          /* stash on peer's conn list */
        cfs_list_t          rac_hashlist;      /* stash in connection hash table */
        cfs_list_t          rac_schedlist;     /* schedule (on rad_???_conns) for attention */
        cfs_list_t          rac_fmaq;          /* txs queued for FMA */
        cfs_list_t          rac_rdmaq;         /* txs awaiting RDMA completion */
        cfs_list_t          rac_replyq;        /* txs awaiting replies */
        __u64               rac_peerstamp;     /* peer's unique stamp */
        __u64               rac_peer_connstamp;/* peer's unique connection stamp */
        __u64               rac_my_connstamp;  /* my unique connection stamp */
        unsigned long       rac_last_tx;       /* when I last sent an FMA message (jiffies) */
        unsigned long       rac_last_rx;       /* when I last received an FMA messages (jiffies) */
        long                rac_keepalive;     /* keepalive interval (seconds) */
        long                rac_timeout;       /* infer peer death if no rx for this many seconds */
        __u32               rac_cqid;          /* my completion callback id (non-unique) */
        __u32               rac_tx_seq;        /* tx msg sequence number */
        __u32               rac_rx_seq;        /* rx msg sequence number */
        cfs_atomic_t        rac_refcount;      /* # users */
        unsigned int        rac_close_sent;    /* I've sent CLOSE */
        unsigned int        rac_close_recvd;   /* I've received CLOSE */
        unsigned int        rac_state;         /* connection state */
        unsigned int        rac_scheduled;     /* being attented to */
        cfs_spinlock_t      rac_lock;          /* serialise */
        kra_device_t       *rac_device;        /* which device */
        RAP_PVOID           rac_rihandle;      /* RA endpoint */
        kra_msg_t          *rac_rxmsg;         /* incoming message (FMA prefix) */
        kra_msg_t           rac_msg;           /* keepalive/CLOSE message buffer */
} kra_conn_t;

#define RANAL_CONN_ESTABLISHED     0
#define RANAL_CONN_CLOSING         1
#define RANAL_CONN_CLOSED          2

typedef struct kra_peer
{
        cfs_list_t          rap_list;         /* stash on global peer list */
        cfs_list_t          rap_connd_list;   /* schedule on kra_connd_peers */
        cfs_list_t          rap_conns;        /* all active connections */
        cfs_list_t          rap_tx_queue;     /* msgs waiting for a conn */
        lnet_nid_t          rap_nid;          /* who's on the other end(s) */
        __u32               rap_ip;           /* IP address of peer */
        int                 rap_port;         /* port on which peer listens */
        cfs_atomic_t        rap_refcount;     /* # users */
        int                 rap_persistence;  /* "known" peer refs */
        int                 rap_connecting;   /* connection forming */
        unsigned long       rap_reconnect_time; /* CURRENT_SECONDS when reconnect OK */
        unsigned long       rap_reconnect_interval; /* exponential backoff */
} kra_peer_t;

extern kra_data_t      kranal_data;
extern kra_tunables_t  kranal_tunables;

extern void kranal_destroy_peer(kra_peer_t *peer);
extern void kranal_destroy_conn(kra_conn_t *conn);

static inline void
kranal_peer_addref(kra_peer_t *peer)
{
        CDEBUG(D_NET, "%p->%s\n", peer, libcfs_nid2str(peer->rap_nid));
        LASSERT(cfs_atomic_read(&peer->rap_refcount) > 0);
        cfs_atomic_inc(&peer->rap_refcount);
}

static inline void
kranal_peer_decref(kra_peer_t *peer)
{
        CDEBUG(D_NET, "%p->%s\n", peer, libcfs_nid2str(peer->rap_nid));
        LASSERT(cfs_atomic_read(&peer->rap_refcount) > 0);
        if (cfs_atomic_dec_and_test(&peer->rap_refcount))
                kranal_destroy_peer(peer);
}

static inline cfs_list_t *
kranal_nid2peerlist (lnet_nid_t nid)
{
        unsigned int hash = ((unsigned int)nid) % kranal_data.kra_peer_hash_size;

        return (&kranal_data.kra_peers[hash]);
}

static inline int
kranal_peer_active(kra_peer_t *peer)
{
        /* Am I in the peer hash table? */
        return (!cfs_list_empty(&peer->rap_list));
}

static inline void
kranal_conn_addref(kra_conn_t *conn)
{
        CDEBUG(D_NET, "%p->%s\n", conn, 
               libcfs_nid2str(conn->rac_peer->rap_nid));
        LASSERT(cfs_atomic_read(&conn->rac_refcount) > 0);
        cfs_atomic_inc(&conn->rac_refcount);
}

static inline void
kranal_conn_decref(kra_conn_t *conn)
{
        CDEBUG(D_NET, "%p->%s\n", conn,
               libcfs_nid2str(conn->rac_peer->rap_nid));
        LASSERT(cfs_atomic_read(&conn->rac_refcount) > 0);
        if (cfs_atomic_dec_and_test(&conn->rac_refcount))
                kranal_destroy_conn(conn);
}

static inline cfs_list_t *
kranal_cqid2connlist (__u32 cqid)
{
        unsigned int hash = cqid % kranal_data.kra_conn_hash_size;

        return (&kranal_data.kra_conns [hash]);
}

static inline kra_conn_t *
kranal_cqid2conn_locked (__u32 cqid)
{
        cfs_list_t       *conns = kranal_cqid2connlist(cqid);
        cfs_list_t       *tmp;
        kra_conn_t       *conn;

        cfs_list_for_each(tmp, conns) {
                conn = cfs_list_entry(tmp, kra_conn_t, rac_hashlist);

                if (conn->rac_cqid == cqid)
                        return conn;
        }

        return NULL;
}

static inline int
kranal_tx_mapped (kra_tx_t *tx)
{
        return (tx->tx_buftype == RANAL_BUF_VIRT_MAPPED ||
                tx->tx_buftype == RANAL_BUF_PHYS_MAPPED);
}

int kranal_startup (lnet_ni_t *ni);
void kranal_shutdown (lnet_ni_t *ni);
int kranal_ctl(lnet_ni_t *ni, unsigned int cmd, void *arg);
int kranal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int kranal_eager_recv(lnet_ni_t *ni, void *private,
                      lnet_msg_t *lntmsg, void **new_private);
int kranal_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg,
                int delayed, unsigned int niov,
                struct iovec *iov, lnet_kiov_t *kiov,
                unsigned int offset, unsigned int mlen, unsigned int rlen);
int kranal_accept(lnet_ni_t *ni, struct socket *sock);

extern void kranal_free_acceptsock (kra_acceptsock_t *ras);
extern int kranal_listener_procint (cfs_sysctl_table_t *table,
                                    int write, struct file *filp,
                                    void *buffer, size_t *lenp);
extern void kranal_update_reaper_timeout (long timeout);
extern void kranal_tx_done (kra_tx_t *tx, int completion);
extern void kranal_unlink_peer_locked (kra_peer_t *peer);
extern void kranal_schedule_conn (kra_conn_t *conn);
extern int kranal_create_peer (kra_peer_t **peerp, lnet_nid_t nid);
extern int kranal_add_persistent_peer (lnet_nid_t nid, __u32 ip, int port);
extern kra_peer_t *kranal_find_peer_locked (lnet_nid_t nid);
extern void kranal_post_fma (kra_conn_t *conn, kra_tx_t *tx);
extern int kranal_del_peer (lnet_nid_t nid);
extern void kranal_device_callback (RAP_INT32 devid, RAP_PVOID arg);
extern int kranal_thread_start (int(*fn)(void *arg), void *arg);
extern int kranal_connd (void *arg);
extern int kranal_reaper (void *arg);
extern int kranal_scheduler (void *arg);
extern void kranal_close_conn_locked (kra_conn_t *conn, int error);
extern void kranal_close_conn (kra_conn_t *conn, int error);
extern void kranal_terminate_conn_locked (kra_conn_t *conn);
extern void kranal_connect (kra_peer_t *peer);
extern int kranal_conn_handshake (struct socket *sock, kra_peer_t *peer);
extern int kranal_tunables_init(void);
extern void kranal_tunables_fini(void);
extern void kranal_init_msg(kra_msg_t *msg, int type);
