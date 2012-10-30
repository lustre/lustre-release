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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/qswlnd/qswlnd.h
 *
 * Basic library routines.
 */

#ifndef _QSWNAL_H
#define _QSWNAL_H

#include <qsnet/kernel.h>
#undef printf                                   /* nasty QSW #define */
#include <linux/module.h>

#include <elan/epcomms.h>

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/buffer_head.h>  /* wait_on_buffer */
#include <linux/unistd.h>
#include <net/sock.h>
#include <linux/uio.h>

#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/sysctl.h>

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/libcfs.h>
#include <lnet/lnet.h>
#include <lnet/lib-lnet.h>
#include <lnet/lnet-sysctl.h>

/* fixed constants */
#define KQSW_SMALLMSG                  (4<<10)  /* small/large ep receiver breakpoint */
#define KQSW_RESCHED                    100     /* # busy loops that forces scheduler to yield */

#define KQSW_CKSUM                      0       /* enable checksumming (protocol incompatible) */

/*
 * derived constants
 */

#define KQSW_TX_BUFFER_SIZE     (offsetof(kqswnal_msg_t, \
                                          kqm_u.immediate.kqim_payload[*kqswnal_tunables.kqn_tx_maxcontig]))
/* The pre-allocated tx buffer (hdr + small payload) */

#define KQSW_NTXMSGPAGES        (btopr(KQSW_TX_BUFFER_SIZE) + 1 + btopr(LNET_MAX_PAYLOAD) + 1)
/* Reserve elan address space for pre-allocated and pre-mapped transmit
 * buffer and a full payload too.  Extra pages allow for page alignment */

#define KQSW_NRXMSGPAGES_SMALL  (btopr(KQSW_SMALLMSG))
/* receive hdr/payload always contiguous and page aligned */
#define KQSW_NRXMSGBYTES_SMALL  (KQSW_NRXMSGPAGES_SMALL * PAGE_SIZE)

#define KQSW_NRXMSGPAGES_LARGE  (btopr(sizeof(lnet_msg_t) + LNET_MAX_PAYLOAD))
/* receive hdr/payload always contiguous and page aligned */
#define KQSW_NRXMSGBYTES_LARGE  (KQSW_NRXMSGPAGES_LARGE * PAGE_SIZE)
/* biggest complete packet we can receive (or transmit) */

/* Wire messages */
/* Remote memory descriptor */
typedef struct
{
        __u32            kqrmd_nfrag;           /* # frags */
        EP_NMD           kqrmd_frag[0];         /* actual frags */
} kqswnal_remotemd_t;

/* Immediate data */
typedef struct
{
        lnet_hdr_t       kqim_hdr;              /* LNET header */
        char             kqim_payload[0];       /* piggy-backed payload */
} WIRE_ATTR kqswnal_immediate_msg_t;

/* RDMA request */
typedef struct
{
        lnet_hdr_t          kqrm_hdr;           /* LNET header */
        kqswnal_remotemd_t  kqrm_rmd;           /* peer's buffer */
} WIRE_ATTR kqswnal_rdma_msg_t;

typedef struct
{
        __u32            kqm_magic;             /* I'm a qswlnd message */
        __u16            kqm_version;           /* this is my version number */
        __u16            kqm_type;              /* msg type */
#if KQSW_CKSUM
        __u32            kqm_cksum;             /* crc32 checksum */
        __u32            kqm_nob;               /* original msg length */
#endif
        union {
                kqswnal_immediate_msg_t  immediate;
                kqswnal_rdma_msg_t       rdma;
        } WIRE_ATTR kqm_u;
} WIRE_ATTR kqswnal_msg_t;

#if KQSW_CKSUM                                           /* enable checksums ? */
# include <linux/crc32.h>
static inline __u32 kqswnal_csum(__u32 crc, unsigned char const *p, size_t len)
{
#if 1
        return crc32_le(crc, p, len);
#else
        while (len-- > 0)
                crc = ((crc + 0x100) & ~0xff) | ((crc + *p++) & 0xff) ;
        return crc;
#endif
}
# define QSWLND_PROTO_VERSION         0xbeef
#else
# define QSWLND_PROTO_VERSION         1
#endif

#define QSWLND_MSG_IMMEDIATE          0
#define QSWLND_MSG_RDMA               1

typedef union {
        EP_STATUSBLK     ep_statusblk;
        struct {
                __u32       status;
                __u32       magic;
                __u32       version;
                union {
                        struct {
                                __u32    len;
                                __u32    cksum;
                        } WIRE_ATTR get;
                } WIRE_ATTR u;
        } WIRE_ATTR     msg;
} kqswnal_rpc_reply_t;

typedef struct kqswnal_rx
{
        cfs_list_t           krx_list;     /* enqueue -> thread */
        struct kqswnal_rx   *krx_alloclist;/* stack in kqn_rxds */
        EP_RCVR             *krx_eprx;     /* port to post receives to */
        EP_RXD              *krx_rxd;      /* receive descriptor (for repost) */
        EP_NMD               krx_elanbuffer;/* contiguous Elan buffer */
        int                  krx_npages;    /* # pages in receive buffer */
        int                  krx_nob;       /* Number Of Bytes received into buffer */
        int                  krx_rpc_reply_needed:1; /* peer waiting for EKC RPC reply */
        int                  krx_state;     /* what this RX is doing */
        cfs_atomic_t         krx_refcount;  /* how to tell when rpc is done */
#if KQSW_CKSUM
        __u32                krx_cksum;     /* checksum */
#endif
        kqswnal_rpc_reply_t  krx_rpc_reply; /* rpc reply status block */
        lnet_kiov_t          krx_kiov[KQSW_NRXMSGPAGES_LARGE];/* buffer frags */
}  kqswnal_rx_t;

#define KRX_POSTED       1                      /* receiving */
#define KRX_PARSE        2                      /* ready to be parsed */
#define KRX_COMPLETING   3                      /* waiting to be completed */


typedef struct kqswnal_tx
{
        cfs_list_t            ktx_list;         /* enqueue idle/active */
        cfs_list_t            ktx_schedlist;    /* enqueue on scheduler */
        struct kqswnal_tx    *ktx_alloclist;    /* stack in kqn_txds */
        unsigned int          ktx_state:7;      /* What I'm doing */
        unsigned int          ktx_firsttmpfrag:1;  /* ktx_frags[0] is in my ebuffer ? 0 : 1 */
        __u32                 ktx_basepage;     /* page offset in reserved elan tx vaddrs for mapping pages */
        int                   ktx_npages;       /* pages reserved for mapping messages */
        int                   ktx_nmappedpages; /* # pages mapped for current message */
        int                   ktx_port;         /* destination ep port */
        lnet_nid_t            ktx_nid;          /* destination node */
        void                 *ktx_args[3];      /* completion passthru */
        char                 *ktx_buffer;       /* pre-allocated contiguous buffer for hdr + small payloads */
        cfs_time_t            ktx_launchtime;   /* when (in jiffies) the
                                                 * transmit was launched */
        int                   ktx_status;       /* completion status */
#if KQSW_CKSUM
        __u32                 ktx_cksum;        /* optimized GET payload checksum */
#endif
        /* debug/info fields */
        pid_t                 ktx_launcher;     /* pid of launching process */

        int                   ktx_nfrag;        /* # message frags */
        int                   ktx_rail;         /* preferred rail */
        EP_NMD                ktx_ebuffer;      /* elan mapping of ktx_buffer */
        EP_NMD                ktx_frags[EP_MAXFRAG];/* elan mapping of msg frags */
} kqswnal_tx_t;

#define KTX_IDLE        0                       /* on kqn_idletxds */
#define KTX_SENDING     1                       /* normal send */
#define KTX_GETTING     2                       /* sending optimised get */
#define KTX_PUTTING     3                       /* sending optimised put */
#define KTX_RDMA_FETCH  4                       /* handling optimised put */
#define KTX_RDMA_STORE  5                       /* handling optimised get */

typedef struct
{
        int               *kqn_tx_maxcontig;    /* maximum payload to defrag */
        int               *kqn_ntxmsgs;         /* # normal tx msgs */
        int               *kqn_credits;         /* # concurrent sends */
        int               *kqn_peercredits;     /* # concurrent sends to 1 peer */
        int               *kqn_nrxmsgs_large;   /* # 'large' rx msgs */
        int               *kqn_ep_envelopes_large; /* # 'large' rx ep envelopes */
        int               *kqn_nrxmsgs_small;   /* # 'small' rx msgs */
        int               *kqn_ep_envelopes_small; /* # 'small' rx ep envelopes */
        int               *kqn_optimized_puts;  /* optimized PUTs? */
        int               *kqn_optimized_gets;  /* optimized GETs? */
#if KQSW_CKSUM
        int               *kqn_inject_csum_error; /* # csum errors to inject */
#endif

#if defined(CONFIG_SYSCTL) && !CFS_SYSFS_MODULE_PARM
        cfs_sysctl_table_header_t *kqn_sysctl;  /* sysctl interface */
#endif
} kqswnal_tunables_t;

typedef struct
{
        char                 kqn_init;        /* what's been initialised */
        char                 kqn_shuttingdown;/* I'm trying to shut down */
        cfs_atomic_t         kqn_nthreads;    /* # threads running */
        lnet_ni_t           *kqn_ni;          /* _the_ instance of me */

        kqswnal_rx_t        *kqn_rxds;        /* stack of all the receive descriptors */
        kqswnal_tx_t        *kqn_txds;        /* stack of all the transmit descriptors */

        cfs_list_t           kqn_idletxds;    /* transmit descriptors free to use */
        cfs_list_t           kqn_activetxds;  /* transmit descriptors being used */
        cfs_spinlock_t       kqn_idletxd_lock; /* serialise idle txd access */
        cfs_atomic_t         kqn_pending_txs;/* # transmits being prepped */

        cfs_spinlock_t       kqn_sched_lock; /* serialise packet schedulers */
        cfs_waitq_t          kqn_sched_waitq;/* scheduler blocks here */

        cfs_list_t           kqn_readyrxds;  /* rxds full of data */
        cfs_list_t           kqn_donetxds;   /* completed transmits */
        cfs_list_t           kqn_delayedtxds;/* delayed transmits */

        EP_SYS              *kqn_ep;         /* elan system */
        EP_NMH              *kqn_ep_tx_nmh;  /* elan reserved tx vaddrs */
        EP_NMH              *kqn_ep_rx_nmh;  /* elan reserved rx vaddrs */
        EP_XMTR             *kqn_eptx;       /* elan transmitter */
        EP_RCVR             *kqn_eprx_small; /* elan receiver (small messages) */
        EP_RCVR             *kqn_eprx_large; /* elan receiver (large messages) */

        int                  kqn_nnodes;     /* this cluster's size */
        int                  kqn_elanid;     /* this nodes's elan ID */

        EP_STATUSBLK         kqn_rpc_success;/* preset RPC reply status blocks */
        EP_STATUSBLK         kqn_rpc_failed;
        EP_STATUSBLK         kqn_rpc_version;/* reply to future version query */
        EP_STATUSBLK         kqn_rpc_magic;  /* reply to future version query */
}  kqswnal_data_t;

/* kqn_init state */
#define KQN_INIT_NOTHING        0               /* MUST BE ZERO so zeroed state is initialised OK */
#define KQN_INIT_DATA           1
#define KQN_INIT_ALL            2

extern kqswnal_tunables_t  kqswnal_tunables;
extern kqswnal_data_t      kqswnal_data;

extern int kqswnal_thread_start (int (*fn)(void *arg), void *arg);
extern void kqswnal_rxhandler(EP_RXD *rxd);
extern int kqswnal_scheduler (void *);
extern void kqswnal_rx_done (kqswnal_rx_t *krx);

static inline lnet_nid_t
kqswnal_elanid2nid (int elanid)
{
        return LNET_MKNID(LNET_NIDNET(kqswnal_data.kqn_ni->ni_nid), elanid);
}

static inline int
kqswnal_nid2elanid (lnet_nid_t nid)
{
        __u32 elanid = LNET_NIDADDR(nid);

        /* not in this cluster? */
        return (elanid >= kqswnal_data.kqn_nnodes) ? -1 : elanid;
}

static inline lnet_nid_t
kqswnal_rx_nid(kqswnal_rx_t *krx)
{
        return (kqswnal_elanid2nid(ep_rxd_node(krx->krx_rxd)));
}

static inline int
kqswnal_pages_spanned (void *base, int nob)
{
        unsigned long first_page = ((unsigned long)base) >> PAGE_SHIFT;
        unsigned long last_page  = (((unsigned long)base) + (nob - 1)) >> PAGE_SHIFT;

        LASSERT (last_page >= first_page);      /* can't wrap address space */
        return (last_page - first_page + 1);
}

static inline void kqswnal_rx_decref (kqswnal_rx_t *krx)
{
        LASSERT (cfs_atomic_read (&krx->krx_refcount) > 0);
        if (cfs_atomic_dec_and_test (&krx->krx_refcount))
                kqswnal_rx_done(krx);
}

int kqswnal_startup (lnet_ni_t *ni);
void kqswnal_shutdown (lnet_ni_t *ni);
int kqswnal_ctl (lnet_ni_t *ni, unsigned int cmd, void *arg);
int kqswnal_send (lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg);
int kqswnal_recv(lnet_ni_t *ni, void *private, lnet_msg_t *lntmsg, 
                 int delayed, unsigned int niov, 
                 struct iovec *iov, lnet_kiov_t *kiov,
                 unsigned int offset, unsigned int mlen, unsigned int rlen);

int kqswnal_tunables_init(void);
void kqswnal_tunables_fini(void);

#endif /* _QSWNAL_H */
