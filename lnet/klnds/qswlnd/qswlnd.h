/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2001 Cluster File Systems, Inc. <braam@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
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
 *
 * Basic library routines.
 *
 */

#ifndef _QSWNAL_H
#define _QSWNAL_H
#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

#include <qsnet/kernel.h>
#undef printf                                   /* nasty QSW #define */

#include <linux/config.h>
#include <linux/module.h>

#if MULTIRAIL_EKC
# include <elan/epcomms.h>
#else
# include <elan3/elanregs.h>
# include <elan3/elandev.h>
# include <elan3/elanvp.h>
# include <elan3/elan3mmu.h>
# include <elan3/elanctxt.h>
# include <elan3/elandebug.h>
# include <elan3/urom_addrs.h>
# include <elan3/busops.h>
# include <elan3/kcomm.h>
#endif

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0))
#include <linux/locks.h>        /* wait_on_buffer */
#else
#include <linux/buffer_head.h>  /* wait_on_buffer */
#endif
#include <linux/unistd.h>
#include <net/sock.h>
#include <linux/uio.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <asm/segment.h>

#define DEBUG_SUBSYSTEM S_NAL

#include <libcfs/kp30.h>
#include <portals/kpr.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

#define KQSW_CHECKSUM   0
#if KQSW_CHECKSUM
typedef unsigned long kqsw_csum_t;
#define KQSW_CSUM_SIZE  (2 * sizeof (kqsw_csum_t))
#else
#define KQSW_CSUM_SIZE  0
#endif
#define KQSW_HDR_SIZE   (sizeof (ptl_hdr_t) + KQSW_CSUM_SIZE)

/*
 * Performance Tuning defines
 * NB no mention of PAGE_SIZE for interoperability
 */
#define KQSW_TX_MAXCONTIG               (1<<10) /* largest payload that gets made contiguous on transmit */

#define KQSW_NTXMSGS                    8       /* # normal transmit messages */
#define KQSW_NNBLK_TXMSGS               (PAGE_SIZE == 4096 ? 512 : 256)     /* # reserved transmit messages if can't block */ /* avoid qsnet crash b=5291 */

#define KQSW_NRXMSGS_LARGE              64      /* # large receive buffers */
#define KQSW_EP_ENVELOPES_LARGE         256     /* # large ep envelopes */

#define KQSW_NRXMSGS_SMALL              256     /* # small receive buffers */
#define KQSW_EP_ENVELOPES_SMALL         2048    /* # small ep envelopes */

#define KQSW_OPTIMIZED_GETS             1       /* optimize gets >= this size */
#define KQSW_OPTIMIZED_PUTS            (32<<10) /* optimize puts >= this size */

/* fixed constants */
#define KQSW_MAXPAYLOAD                 PTL_MTU
#define KQSW_SMALLPAYLOAD               ((4<<10) - KQSW_HDR_SIZE) /* small/large ep receiver breakpoint */
#define KQSW_RESCHED                    100     /* # busy loops that forces scheduler to yield */

/*
 * derived constants
 */

#define KQSW_TX_BUFFER_SIZE     (KQSW_HDR_SIZE + *kqswnal_tunables.kqn_tx_maxcontig)
/* The pre-allocated tx buffer (hdr + small payload) */

#define KQSW_NTXMSGPAGES        (btopr(KQSW_TX_BUFFER_SIZE) + 1 + btopr(KQSW_MAXPAYLOAD) + 1)
/* Reserve elan address space for pre-allocated and pre-mapped transmit
 * buffer and a full payload too.  Extra pages allow for page alignment */

#define KQSW_NRXMSGPAGES_SMALL  (btopr(KQSW_HDR_SIZE + KQSW_SMALLPAYLOAD))
/* receive hdr/payload always contiguous and page aligned */
#define KQSW_NRXMSGBYTES_SMALL  (KQSW_NRXMSGPAGES_SMALL * PAGE_SIZE)

#define KQSW_NRXMSGPAGES_LARGE  (btopr(KQSW_HDR_SIZE + KQSW_MAXPAYLOAD))
/* receive hdr/payload always contiguous and page aligned */
#define KQSW_NRXMSGBYTES_LARGE  (KQSW_NRXMSGPAGES_LARGE * PAGE_SIZE)
/* biggest complete packet we can receive (or transmit) */

/* Remote memory descriptor */
typedef struct
{
        __u32            kqrmd_nfrag;           /* # frags */
#if MULTIRAIL_EKC
        EP_NMD           kqrmd_frag[0];         /* actual frags */
#else
        EP_IOVEC         kqrmd_frag[0];         /* actual frags */
#endif
} kqswnal_remotemd_t;

typedef struct kqswnal_rx
{
        struct list_head krx_list;              /* enqueue -> thread */
        struct kqswnal_rx *krx_alloclist;       /* stack in kqn_rxds */
        EP_RCVR         *krx_eprx;              /* port to post receives to */
        EP_RXD          *krx_rxd;               /* receive descriptor (for repost) */
#if MULTIRAIL_EKC
        EP_NMD           krx_elanbuffer;        /* contiguous Elan buffer */
#else
        E3_Addr          krx_elanbuffer;        /* contiguous Elan buffer */
#endif
        int              krx_npages;            /* # pages in receive buffer */
        int              krx_nob;               /* Number Of Bytes received into buffer */
        int              krx_rpc_reply_needed;  /* peer waiting for EKC RPC reply */
        int              krx_rpc_reply_status;  /* what status to send */
        int              krx_state;             /* what this RX is doing */
        atomic_t         krx_refcount;          /* how to tell when rpc is done */
        kpr_fwd_desc_t   krx_fwd;               /* embedded forwarding descriptor */
        ptl_kiov_t       krx_kiov[KQSW_NRXMSGPAGES_LARGE]; /* buffer frags */
}  kqswnal_rx_t;

#define KRX_POSTED       1                      /* receiving */
#define KRX_PARSE        2                      /* ready to be parsed */
#define KRX_COMPLETING   3                      /* waiting to be completed */


typedef struct kqswnal_tx
{
        struct list_head  ktx_list;             /* enqueue idle/active */
        struct list_head  ktx_delayed_list;     /* enqueue delayedtxds */
        struct kqswnal_tx *ktx_alloclist;       /* stack in kqn_txds */
        unsigned int      ktx_isnblk:1;         /* reserved descriptor? */
        unsigned int      ktx_state:7;          /* What I'm doing */
        unsigned int      ktx_firsttmpfrag:1;   /* ktx_frags[0] is in my ebuffer ? 0 : 1 */
        uint32_t          ktx_basepage;         /* page offset in reserved elan tx vaddrs for mapping pages */
        int               ktx_npages;           /* pages reserved for mapping messages */
        int               ktx_nmappedpages;     /* # pages mapped for current message */
        int               ktx_port;             /* destination ep port */
        ptl_nid_t         ktx_nid;              /* destination node */
        void             *ktx_args[3];          /* completion passthru */
        char             *ktx_buffer;           /* pre-allocated contiguous buffer for hdr + small payloads */
        unsigned long     ktx_launchtime;       /* when (in jiffies) the transmit was launched */

        /* debug/info fields */
        pid_t             ktx_launcher;         /* pid of launching process */

        int               ktx_nfrag;            /* # message frags */
#if MULTIRAIL_EKC
        int               ktx_rail;             /* preferred rail */
        EP_NMD            ktx_ebuffer;          /* elan mapping of ktx_buffer */
        EP_NMD            ktx_frags[EP_MAXFRAG];/* elan mapping of msg frags */
#else
        E3_Addr           ktx_ebuffer;          /* elan address of ktx_buffer */
        EP_IOVEC          ktx_frags[EP_MAXFRAG];/* msg frags (elan vaddrs) */
#endif
} kqswnal_tx_t;

#define KTX_IDLE        0                       /* on kqn_(nblk_)idletxds */
#define KTX_FORWARDING  1                       /* sending a forwarded packet */
#define KTX_SENDING     2                       /* normal send */
#define KTX_GETTING     3                       /* sending optimised get */
#define KTX_PUTTING     4                       /* sending optimised put */
#define KTX_RDMAING     5                       /* handling optimised put/get */

typedef struct
{
        int               *kqn_tx_maxcontig;    /* maximum payload to defrag */
        int               *kqn_ntxmsgs;         /* # normal tx msgs */
        int               *kqn_nnblk_txmsgs;    /* # reserved tx msgs */
        int               *kqn_nrxmsgs_large;   /* # 'large' rx msgs */
        int               *kqn_ep_envelopes_large; /* # 'large' rx ep envelopes */
        int               *kqn_nrxmsgs_small;   /* # 'small' rx msgs */
        int               *kqn_ep_envelopes_small; /* # 'small' rx ep envelopes */
        int               *kqn_optimized_puts;  /* optimized PUTs? */
        int               *kqn_optimized_gets;  /* optimized GETs? */

#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
        struct ctl_table_header *kqn_sysctl;    /* sysctl interface */
#endif
} kqswnal_tunables_t;

typedef struct
{
        char               kqn_init;            /* what's been initialised */
        char               kqn_shuttingdown;    /* I'm trying to shut down */
        atomic_t           kqn_nthreads;        /* # threads running */
        ptl_ni_t          *kqn_ni;              /* _the_ instance of me */

        kqswnal_rx_t      *kqn_rxds;            /* stack of all the receive descriptors */
        kqswnal_tx_t      *kqn_txds;            /* stack of all the transmit descriptors */

        struct list_head   kqn_idletxds;        /* transmit descriptors free to use */
        struct list_head   kqn_nblk_idletxds;   /* reserved free transmit descriptors */
        struct list_head   kqn_activetxds;      /* transmit descriptors being used */
        spinlock_t         kqn_idletxd_lock;    /* serialise idle txd access */
        wait_queue_head_t  kqn_idletxd_waitq;   /* sender blocks here waiting for idle txd */
        struct list_head   kqn_idletxd_fwdq;    /* forwarded packets block here waiting for idle txd */
        atomic_t           kqn_pending_txs;     /* # transmits being prepped */

        spinlock_t         kqn_sched_lock;      /* serialise packet schedulers */
        wait_queue_head_t  kqn_sched_waitq;     /* scheduler blocks here */

        struct list_head   kqn_readyrxds;       /* rxds full of data */
        struct list_head   kqn_delayedfwds;     /* delayed forwards */
        struct list_head   kqn_delayedtxds;     /* delayed transmits */

#if MULTIRAIL_EKC
        EP_SYS            *kqn_ep;              /* elan system */
        EP_NMH            *kqn_ep_tx_nmh;       /* elan reserved tx vaddrs */
        EP_NMH            *kqn_ep_rx_nmh;       /* elan reserved rx vaddrs */
#else
        EP_DEV            *kqn_ep;              /* elan device */
        ELAN3_DMA_HANDLE  *kqn_eptxdmahandle;   /* elan reserved tx vaddrs */
        ELAN3_DMA_HANDLE  *kqn_eprxdmahandle;   /* elan reserved rx vaddrs */
#endif
        EP_XMTR           *kqn_eptx;            /* elan transmitter */
        EP_RCVR           *kqn_eprx_small;      /* elan receiver (small messages) */
        EP_RCVR           *kqn_eprx_large;      /* elan receiver (large messages) */

        int                kqn_nnodes;          /* this cluster's size */
        int                kqn_elanid;          /* this nodes's elan ID */

        EP_STATUSBLK       kqn_rpc_success;     /* preset RPC reply status blocks */
        EP_STATUSBLK       kqn_rpc_failed;
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
extern void kqswnal_fwd_packet (ptl_ni_t *ni, kpr_fwd_desc_t *fwd);
extern void kqswnal_rx_done (kqswnal_rx_t *krx);

static inline ptl_nid_t
kqswnal_elanid2nid (int elanid)
{
        return PTL_MKNID(PTL_NIDNET(kqswnal_data.kqn_ni->ni_nid), elanid);
}

static inline int
kqswnal_nid2elanid (ptl_nid_t nid)
{
        int elanid = PTL_NIDADDR(nid);

        /* not in this cluster? */
        return (elanid >= kqswnal_data.kqn_nnodes) ? -1 : elanid;
}

static inline ptl_nid_t
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

#if KQSW_CHECKSUM
static inline kqsw_csum_t kqsw_csum (kqsw_csum_t sum, void *base, int nob)
{
        unsigned char *ptr = (unsigned char *)base;

        while (nob-- > 0)
                sum += *ptr++;

        return (sum);
}
#endif

static inline void kqswnal_rx_decref (kqswnal_rx_t *krx)
{
        LASSERT (atomic_read (&krx->krx_refcount) > 0);
        if (atomic_dec_and_test (&krx->krx_refcount))
                kqswnal_rx_done(krx);
}

#if MULTIRAIL_EKC
# ifndef EP_RAILMASK_ALL
#  error "old (unsupported) version of EKC headers"
# endif
#else
/* multirail defines these in <elan/epcomms.h> */
#define EP_MSG_SVC_PORTALS_SMALL      (0x10)  /* Portals over elan port number (large payloads) */
#define EP_MSG_SVC_PORTALS_LARGE      (0x11)  /* Portals over elan port number (small payloads) */
/* NB small/large message sizes are GLOBAL constants */

/* A minimal attempt to minimise inline #ifdeffing */

#define EP_SUCCESS      ESUCCESS
#define EP_ENOMEM	ENOMEM

static inline EP_XMTR *
ep_alloc_xmtr(EP_DEV *e)
{
        return (ep_alloc_large_xmtr(e));
}

static inline EP_RCVR *
ep_alloc_rcvr(EP_DEV *e, int svc, int nenv)
{
        return (ep_install_large_rcvr(e, svc, nenv));
}

static inline void
ep_free_xmtr(EP_XMTR *x)
{
        ep_free_large_xmtr(x);
}

static inline void
ep_free_rcvr(EP_RCVR *r)
{
        ep_remove_large_rcvr(r);
}
#endif

ptl_err_t kqswnal_startup (ptl_ni_t *ni);
void kqswnal_shutdown (ptl_ni_t *ni);
int kqswnal_ctl (ptl_ni_t *ni, unsigned int cmd, void *arg);
ptl_err_t kqswnal_send (ptl_ni_t *ni, void *private,
                        ptl_msg_t *ptlmsg, ptl_hdr_t *hdr,
                        int type, ptl_process_id_t tgt, int routing,
                        unsigned int payload_niov, 
                        struct iovec *payload_iov,
                        size_t payload_offset, size_t payload_nob);
ptl_err_t kqswnal_send_pages (ptl_ni_t *ni, void *private,
                              ptl_msg_t *ptlmsg, ptl_hdr_t *hdr,
                              int type, ptl_process_id_t tgt, int routing,
                              unsigned int payload_niov, 
                              ptl_kiov_t *payload_kiov,
                              size_t payload_offset, size_t payload_nob);
ptl_err_t kqswnal_recv(ptl_ni_t *ni, void *private,
                       ptl_msg_t *ptlmsg, unsigned int niov,
                       struct iovec *iov, size_t offset,
                       size_t mlen, size_t rlen);
ptl_err_t kqswnal_recv_pages(ptl_ni_t *ni, void *private,
                             ptl_msg_t *ptlmsg, unsigned int niov,
                             ptl_kiov_t *kiov, size_t offset,
                             size_t mlen, size_t rlen);

int kqswnal_tunables_init(void);
void kqswnal_tunables_fini(void);

#endif /* _QSWNAL_H */
