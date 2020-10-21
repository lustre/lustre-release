/*
 * Copyright (C) 2004 Cluster File Systems, Inc.
 *
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 * Copyright (c) 2014, 2016, Intel Corporation.
 *
 *   Derived from work by: Eric Barton <eric@bartonsoftware.com>
 *   Author: Nic Henke <nic@cray.com>
 *   Author: James Shimek <jshimek@cray.com>
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
 */
#ifndef _GNILND_GNILND_H_
#define _GNILND_GNILND_H_

#define DEBUG_SUBSYSTEM S_LND

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#ifdef HAVE_LINUX_KERNEL_LOCK
#include <linux/smp_lock.h>
#endif
#include <linux/unistd.h>
#include <linux/uio.h>
#include <linux/time.h>
#include <asm/timex.h>

#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <linux/kmod.h>
#include <linux/sysctl.h>
#include <linux/kthread.h>
#include <linux/nmi.h>

#include <net/sock.h>
#include <linux/in.h>
#include <linux/nmi.h>

#include <lnet/lib-lnet.h>

#include <gni_pub.h>

static inline time_t cfs_duration_sec(long duration_jiffies)
{
	return jiffies_to_msecs(duration_jiffies) / MSEC_PER_SEC;
}

#ifdef CONFIG_SLAB
#define GNILND_MBOX_SIZE	KMALLOC_MAX_SIZE
#else
#define GNILND_SHIFT_HIGH	((MAX_ORDER + PAGE_SHIFT - 1) <= 25 ? \
				(MAX_ORDER + PAGE_SHIFT - 1) : 25)
#define GNILND_SHIFT_MAX	GNILND_SHIFT_HIGH
#define GNILND_MBOX_SIZE	(1UL << GNILND_SHIFT_MAX)
#endif


/* tunables determined at compile time */
#define GNILND_MIN_TIMEOUT	5		/* minimum timeout interval (seconds) */
#define GNILND_TO2KA(t)		(((t)-1)/2)	/* timeout -> keepalive interval */
#define GNILND_MIN_RECONNECT_TO	(GNILND_BASE_TIMEOUT/4)
#define GNILND_MAX_RECONNECT_TO	GNILND_BASE_TIMEOUT
#define GNILND_HARDWARE_TIMEOUT	15		/* maximum time for data to travel between nodes */
#define GNILND_MDD_TIMEOUT	15		/* MDD hold timeout in minutes */
#define GNILND_SCHED_TIMEOUT       1
#define GNILND_DGRAM_TIMEOUT       2
#define GNILND_FAST_MAPPING_TRY   \
	*kgnilnd_tunables.kgn_max_retransmits   /* maximum number to attempt mapping of a tx */
#define GNILND_MAP_RETRY_RATE      1            /* interval between mapping attempts in jiffies */

/* map failure timeout */
#define GNILND_MAP_TIMEOUT         \
	(cfs_time_seconds(*kgnilnd_tunables.kgn_timeout * \
	 *kgnilnd_tunables.kgn_timeout))

/* Should we use the no_retry flag with vzalloc */
#define GNILND_VZALLOC_RETRY 0

/* reaper thread wakup interval */
#define GNILND_REAPER_THREAD_WAKE  1
/* reaper thread checks each conn NCHECKS time every kgnilnd_data.kgn_new_min_timeout */
#define GNILND_REAPER_NCHECKS      4

/* fixed constants */
#define GNILND_MAXDEVS		1		/* max # of GNI devices currently supported */
#define GNILND_MBOX_CREDITS	256		/* number of credits per mailbox */
#define GNILND_CONN_MAGIC         0xa100f       /* magic value for verifying connection validity */
/* checksum values */
#define GNILND_CHECKSUM_OFF		0	/* checksum turned off */
#define GNILND_CHECKSUM_SMSG_HEADER	1	/* Only checksum SMSG header */
#define GNILND_CHECKSUM_SMSG		2	/* checksum entire SMSG packet */
#define GNILND_CHECKSUM_SMSG_BTE	3	/* Full checksum support */

/* tune down some COMPUTE options as they won't see the same number of connections and
 * don't need the throughput of multiple threads by default */
#if defined(CONFIG_CRAY_COMPUTE)
#ifdef CONFIG_MK1OM
#define GNILND_SCHED_THREADS      2             /* default # of kgnilnd_scheduler threads */
#else
#define GNILND_SCHED_THREADS      1             /* default # of kgnilnd_scheduler threads */
#endif
#define GNILND_FMABLK             64            /* default number of mboxes per fmablk */
#define GNILND_SCHED_NICE         0		/* default nice value for scheduler threads */
#define GNILND_COMPUTE            1             /* compute image */
#define GNILND_FAST_RECONNECT     1             /* Fast Reconnect option */
#define GNILND_DEFAULT_CREDITS    64            /* Default number of simultaneous transmits */
#else
#define GNILND_FMABLK             1024          /* default number of mboxes per fmablk */
#define GNILND_SCHED_NICE         -20		/* default nice value for scheduler threads */
#define GNILND_COMPUTE            0             /* service image */
#define GNILND_FAST_RECONNECT     0             /* Fast Reconnect option */
#define GNILND_DEFAULT_CREDITS    256           /* Default number of simultaneous transmits */
#endif

/* EXTRA_BITS are there to allow us to hide NOOP/CLOSE and anything else out of band */
#define GNILND_EXTRA_BITS         1
/* maximum number of conns & bits for cqid in the SMSG event data */
#define GNILND_CQID_NBITS         (21 - GNILND_EXTRA_BITS)
#define GNILND_MSGID_TX_NBITS     (32 - GNILND_CQID_NBITS)
#define GNILND_MAX_CQID           (1 << GNILND_CQID_NBITS)
#define GNILND_MAX_MSG_ID         (1 << GNILND_MSGID_TX_NBITS)
#define GNILND_MAX_MSG_SIZE       (*kgnilnd_tunables.kgn_max_immediate + sizeof(kgn_msg_t))

/* need sane upper bound to limit copy overhead */
#define GNILND_MAX_IMMEDIATE      (64<<10)

/* Max number of connections to keep in purgatory per peer */
#define GNILND_PURGATORY_MAX	  5
/* Closing, don't put in purgatory */
#define GNILND_NOPURG             222

/* payload size to add to the base mailbox size
 * This is subtracting 2 from the concurrent_sends as 4 messages are included in the size
 * gni_smsg_buff_size_needed calculates, the MAX_PAYLOAD is added to
 * the calculation return from that function.*/
#define GNILND_MBOX_PAYLOAD     \
	  (GNILND_MAX_MSG_SIZE * \
	  ((*kgnilnd_tunables.kgn_concurrent_sends - 2) * 2));

/* timeout -> deadman timer for kgni mdd holds */
#define GNILND_TIMEOUT2DEADMAN   ((*kgnilnd_tunables.kgn_mdd_timeout) * 1000 * 60)

/* timeout for failing sends in t is in jiffies*/
#define GNILND_TIMEOUTRX(t)     (t + cfs_time_seconds(*kgnilnd_tunables.kgn_hardware_timeout))

/* time when to release from purgatory in the reaper thread in jiffies */
#define GNILND_PURG_RELEASE(t)   (GNILND_TIMEOUTRX(t) * 3)

/* Macro for finding last_rx 2 datapoints are compared
 * and the most recent one in jiffies is returned.
 */
#define GNILND_LASTRX(conn) (time_after(conn->gnc_last_rx, conn->gnc_last_rx_cq) \
				? conn->gnc_last_rx : conn->gnc_last_rx_cq)

/* fmablk registration failures timeout before failing node */
#define GNILND_REGFAILTO_DISABLE  -1

/************************************************************************
 * Enum, flag and tag data
 */
#define GNILND_INIT_NOTHING         0
#define GNILND_INIT_DATA            1
#define GNILND_INIT_ALL             2

/* If you change the ordering away from MAPPED = UNMAPPED + 1, things break */
#define GNILND_BUF_NONE           0              /* buffer type not set */
#define GNILND_BUF_IMMEDIATE      1              /* immediate data */
#define GNILND_BUF_IMMEDIATE_KIOV 2              /* immediate data */
#define GNILND_BUF_PHYS_UNMAPPED  3              /* physical: not mapped yet */
#define GNILND_BUF_PHYS_MAPPED    4              /* physical: mapped already */

#define GNILND_TX_WAITING_REPLY      (1<<1)     /* expecting to receive reply */
#define GNILND_TX_WAITING_COMPLETION (1<<2)     /* waiting for smsg_send to complete */
#define GNILND_TX_PENDING_RDMA       (1<<3)     /* RDMA transaction pending until we get prev. completion */
#define GNILND_TX_QUIET_ERROR        (1<<4)     /* don't print error on tx_done */
#define GNILND_TX_FAIL_SMSG          (1<<5)     /* pass down error injection for SMSG fail */

/* stash above max CQID to avoid any collision */
#define GNILND_MSGID_NOOP           (GNILND_MAX_CQID + 128)
#define GNILND_MSGID_CLOSE          (GNILND_MSGID_NOOP + 1)

/* kgn_msg_t::gnm_type */
#define GNILND_MSG_NONE              0x00        /* illegal message */
#define GNILND_MSG_NOOP              0x01        /* empty gnm_u (keepalive) */
#define GNILND_MSG_IMMEDIATE         0x02        /* gnm_u.immediate */
#define GNILND_MSG_PUT_REQ           0x03        /* gnm_u.putreq (src->sink) */
#define GNILND_MSG_PUT_NAK           0x04        /* gnm_u.completion (no PUT match: sink->src) */
#define GNILND_MSG_PUT_ACK           0x05        /* gnm_u.putack (PUT matched: sink->src) */
#define GNILND_MSG_PUT_DONE          0x06        /* gnm_u.completion (src->sink) */
#define GNILND_MSG_GET_REQ           0x07        /* gnm_u.get (sink->src) */
#define GNILND_MSG_GET_NAK           0x08        /* gnm_u.completion (no GET match: src->sink) */
#define GNILND_MSG_GET_DONE          0x09        /* gnm_u.completion (src->sink) */
#define GNILND_MSG_CLOSE             0x0a        /* empty gnm_u */
#define GNILND_MSG_PUT_REQ_REV       0x0b	 /* gnm_u.get (src->sink) */
#define GNILND_MSG_PUT_DONE_REV      0x0c	 /* gnm_u.completion (sink->src) */
#define GNILND_MSG_PUT_NAK_REV       0x0d        /* gnm_u.completion (no PUT match: sink->src) */
#define GNILND_MSG_GET_REQ_REV       0x0e        /* gnm_u.get (sink->src ) */
#define GNILND_MSG_GET_ACK_REV       0x0f        /* gnm_u.getack (GET matched: src->sink) */
#define GNILND_MSG_GET_DONE_REV      0x10	 /* gnm_u.completion (sink -> src) */
#define GNILND_MSG_GET_NAK_REV       0x11        /* gnm_u.completeion (no GET match: sink -> src) */

/* defines for gnc_*scheduled states */
#define GNILND_CONN_IDLE             0
#define GNILND_CONN_SCHED            1
#define GNILND_CONN_WANTS_SCHED      2
#define GNILND_CONN_PROCESS          3

#define GNILND_DEV_IDLE              0
#define GNILND_DEV_IRQ               1
#define GNILND_DEV_LOOP              2

#define GNILND_DGRAM_IDLE            0
#define GNILND_DGRAM_SCHED           1
#define GNILND_DGRAM_PROCESS         2

#define GNILND_PEER_IDLE             0
#define GNILND_PEER_CONNECT          1
#define GNILND_PEER_POSTING          2
#define GNILND_PEER_POSTED           3
#define GNILND_PEER_NEEDS_DEATH      4
#define GNILND_PEER_KILL             5

/* for gnc_close_recvd */
#define GNILND_CLOSE_RX              1
#define GNILND_CLOSE_INJECT1         2
#define GNILND_CLOSE_INJECT2         3
#define GNILND_CLOSE_EARLY           4

/* defines for why quiesce trigger set */
#define GNILND_QUIESCE_IDLE          0
#define GNILND_QUIESCE_ADMIN         1
#define GNILND_QUIESCE_RESET         2
#define GNILND_QUIESCE_HW_QUIESCE    3

#define GNILND_PEER_CLEAN            0
#define GNILND_PEER_PERSISTING       1

#define GNILND_DEL_CONN              0
#define GNILND_DEL_PEER              1
#define GNILND_CLEAR_PURGATORY       2

#define GNILND_PEER_UP               0
#define GNILND_PEER_DOWN             1
#define GNILND_PEER_TIMED_OUT        2
#define GNILND_PEER_UNKNOWN          3

/* defines for reverse RDMA states */
#define GNILND_REVERSE_NONE		0
#define GNILND_REVERSE_GET		1
#define GNILND_REVERSE_PUT		2
#define GNILND_REVERSE_BOTH		(GNILND_REVERSE_GET | GNILND_REVERSE_PUT)

typedef enum kgn_fmablk_state {
	GNILND_FMABLK_IDLE = 0, /* is allocated or ready to be freed */
	GNILND_FMABLK_PHYS,     /* allocated out of slab of physical memory */
	GNILND_FMABLK_VIRT,     /* 'standard' vmalloc hunk */
	GNILND_FMABLK_FREED,    /* after free */
} kgn_fmablk_state_t;

typedef enum kgn_tx_list_state {
	GNILND_TX_IDLE = 0,     /* TX is on the idle list, kgn_idle_txs */
	GNILND_TX_ALLOCD,       /* TX has been alloced (off of idle), could be in any state transition */
	GNILND_TX_PEERQ,        /* TX on peer->gnp_tx_queue (no live conn) */
	GNILND_TX_MAPQ,         /* TX on dev:gnd_map_tx for buffer mapping */
	GNILND_TX_FMAQ,         /* TX waiting to be send on conn FMA */
	GNILND_TX_LIVE_FMAQ,    /* TX live on the FMA wire, waiting for completion or reply */
	GNILND_TX_RDMAQ,        /* TX waiting to send FMA confirmation to auth RDMA PUT */
	GNILND_TX_LIVE_RDMAQ,   /* TX live on the RDMA wire, waiting for completion */
	GNILND_TX_DYING,        /* TX got caught on MAPQ or RDMAQ while conn was closing, needs someone to call tx_done */
	GNILND_TX_FREED         /* TX is free! */
} kgn_tx_list_state_t;

typedef enum kgn_conn_state {
	/* don't start @ 0 - prevent memset(0) badness */
	GNILND_CONN_DUMMY = 0,
	GNILND_CONN_LISTEN,
	GNILND_CONN_CONNECTING,
	GNILND_CONN_ESTABLISHED,
	GNILND_CONN_CLOSING,
	GNILND_CONN_CLOSED,
	GNILND_CONN_DONE,
	GNILND_CONN_DESTROY_EP
} kgn_conn_state_t;

/* changing these requires a change to GNILND_CONNREQ_VERSION and
 * will result in dropped packets instead of NAKs. Adding to this is
 * acceptable without changing the CONNREQ_VERSION, but code should
 * be ready to handle NAKs on version mismatch  */
typedef enum kgn_connreq_type {
	GNILND_CONNREQ_REQ = 1,         /* how YOU doin' ? */
	GNILND_CONNREQ_NAK,             /* NO soup for you! */
	GNILND_CONNREQ_CLOSE,           /* we should see other people */
} kgn_connreq_type_t;

typedef enum kgn_dgram_state {
	/* don't use 0 to avoid thinking a memset of zero is valid data */
	GNILND_DGRAM_USED = 1,
	GNILND_DGRAM_POSTING,
	GNILND_DGRAM_POSTED,
	GNILND_DGRAM_PROCESSING,
	GNILND_DGRAM_CANCELED,
	GNILND_DGRAM_DONE,
} kgn_dgram_state_t;

typedef enum kgn_dgram_type {
	GNILND_DGRAM_REQ = 1,         /* how YOU doin' ? */
	GNILND_DGRAM_WC_REQ,          /* you talkin' to ME? */
	GNILND_DGRAM_NAK,             /* NO soup for you! */
	GNILND_DGRAM_CLOSE,           /* we should see other people */
} kgn_dgram_type_t;

/************************************************************************
 * Wire message structs.  These are sent in sender's byte order
 * (i.e. receiver checks magic and flips if required).
 */

#define GNILND_MSG_MAGIC     LNET_PROTO_GNI_MAGIC /* unique magic */
#define GNILND_DGRAM_MAGIC   0x0DDBA11

/*  kgn_msg_t - FMA/SMSG wire struct
  v2:
   * - added checksum to FMA
   * moved seq before paylod
   * __packed added for alignment
  v3:
   * added gnm_payload_len for FMA payload size
  v4:
   * added gncm_retval to completion, allowing return code transmission
     on RDMA NAKs
  v5:
   * changed how CQID and TX ids are assigned
  v6:
   * added retval on CLOSE
  v7:
   * added payload checksumming
  v8:
   * reworked checksumming a bit, changed payload checksums
*/
#define GNILND_MSG_VERSION              8
/* kgn_connreq_t connection request datagram wire struct
  v2:
   * added NAKs
*/

#define GNILND_CONNREQ_VERSION          2

typedef struct kgn_gniparams {
	__u32            gnpr_host_id;          /* ph. host ID of the NIC */
	__u32            gnpr_cqid;             /* cqid I want peer to use when sending events to me */
	gni_smsg_attr_t  gnpr_smsg_attr;        /* my short msg. attributes */
} __packed kgn_gniparams_t;

typedef struct kgn_nak_data {
	__s32            gnnd_errno;            /* errno reason for NAK */

} __packed kgn_nak_data_t;

/* the first bits of the connreq struct CANNOT CHANGE FORM EVER
 * without breaking the ability for us to properly NAK someone */
typedef struct kgn_connreq {                    /* connection request/response */
	__u32             gncr_magic;           /* I'm an gnilnd connreq */
	__u32             gncr_cksum;           /* checksum (0 == disabled) */
	__u16             gncr_type;            /* REQ, NAK, etc */
	__u16             gncr_version;         /* this is my version number */
	__u32             gncr_timeout;         /* sender's timeout */
	__u64             gncr_srcnid;          /* sender's NID */
	__u64             gncr_dstnid;          /* who sender expects to listen */
	__u64             gncr_peerstamp;       /* sender's instance stamp */
	__u64             gncr_connstamp;       /* sender's connection stamp */

	/* everything before this needs to stay static, adding after should
	 * result in a change to GNILND_CONNREQ_VERSION */

	union {
		kgn_gniparams_t   gncr_gnparams;        /* sender's endpoint info */
		kgn_nak_data_t    gncr_nakdata;         /* data (rc, etc) for NAK */
	};
} __packed kgn_connreq_t;

typedef struct {
	gni_mem_handle_t  gnrd_key;
	__u64             gnrd_addr;
	__u32             gnrd_nob;
} __packed kgn_rdma_desc_t;

typedef struct {
	struct lnet_hdr	  gnim_hdr;             /* LNet header */
	/* LNet payload is in FMA "Message Data" */
} __packed kgn_immediate_msg_t;

typedef struct {
	struct lnet_hdr   gnprm_hdr;            /* LNet header */
	__u64             gnprm_cookie;         /* opaque completion cookie */
} __packed kgn_putreq_msg_t;

typedef struct {
	__u64             gnpam_src_cookie;     /* reflected completion cookie */
	__u64             gnpam_dst_cookie;     /* opaque completion cookie */
	__u16		  gnpam_payload_cksum;  /* checksum for get msg */
	kgn_rdma_desc_t   gnpam_desc;           /* sender's sink buffer */
} __packed kgn_putack_msg_t;

typedef struct {
	struct lnet_hdr   gngm_hdr;             /* LNet header */
	__u64             gngm_cookie;          /* opaque completion cookie */
	__u16		  gngm_payload_cksum;   /* checksum for put msg */
	kgn_rdma_desc_t   gngm_desc;            /* sender's sink buffer */
} __packed kgn_get_msg_t;

typedef struct {
	int               gncm_retval;          /* error on NAK, size on REQ */
	__u64             gncm_cookie;          /* reflected completion cookie */
} __packed kgn_completion_msg_t;

typedef struct {                                /* NB must fit in FMA "Prefix" */
	__u32             gnm_magic;            /* I'm an gni message */
	__u16             gnm_version;          /* this is my version number */
	__u16             gnm_type;             /* msg type */
	__u64             gnm_srcnid;           /* sender's NID */
	__u64             gnm_connstamp;        /* sender's connection stamp */
	__u32             gnm_seq;              /* incrementing sequence number */
	__u16             gnm_cksum;            /* checksum (0 == no checksum ) */
	__u16             gnm_payload_cksum;    /* payload checksum (0 == no checksum ) */
	__u32             gnm_payload_len;      /* size of the FMA payload sent */
	union {
		kgn_immediate_msg_t   immediate;
		kgn_putreq_msg_t      putreq;
		kgn_putack_msg_t      putack;
		kgn_get_msg_t         get;
		kgn_completion_msg_t  completion;
	} gnm_u;
} __packed kgn_msg_t;

/************************************************************************
 * runtime tunable data
 */

typedef struct kgn_tunables {
	int              *kgn_min_reconnect_interval; /* connreq starting timeout & retransmit interval */
	int              *kgn_max_reconnect_interval; /* ...exponentially increasing to this */
	int              *kgn_credits;          /* # concurrent sends */
	int              *kgn_fma_cq_size;      /* # entries in receive CQ */
	int              *kgn_peer_credits;     /* # LNet peer credits */
	int              *kgn_concurrent_sends; /* max # of max_immediate in mbox */
	int              *kgn_timeout;          /* comms timeout (seconds) */
	int              *kgn_max_immediate;    /* immediate payload breakpoint */
	int              *kgn_checksum;         /* checksum data */
	int              *kgn_checksum_dump;    /* dump raw data to D_INFO log when checksumming */
	int		 *kgn_bte_put_dlvr_mode; /* BTE Put delivery mode */
	int              *kgn_bte_get_dlvr_mode; /* BTE Get delivery mode */
	int              *kgn_bte_relaxed_ordering; /* relaxed ordering (PASSPW) on BTE transfers */
	int              *kgn_ptag;             /* PTAG for cdm_create */
	int              *kgn_pkey;             /* PKEY for cdm_create */
	int              *kgn_max_retransmits;  /* max number of FMA retransmits before entering delay list */
	int              *kgn_nwildcard;        /* # wildcard per net to post */
	int              *kgn_nice;             /* nice value for kgnilnd threads */
	int              *kgn_rdmaq_intervals;  /* # intervals per second for rdmaq throttle */
	int              *kgn_loops;            /* # of loops sched does before flush/heartbeat tickle */
	int              *kgn_peer_hash_size;   /* size of kgn_peers */
	int              *kgn_peer_health;      /* enable/disable peer health */
	int              *kgn_peer_timeout;     /* Override of the default peer_timeout used by peer_health */
	int              *kgn_vmap_cksum;       /* enable/disable vmap of kiov checksums */
	int              *kgn_mbox_per_block;   /* mailboxes per fmablk */
	int              *kgn_nphys_mbox;       /* # mailboxes to preallocate with physical memory */
	int              *kgn_mbox_credits;     /* max credits per fma */
	int              *kgn_sched_threads;    /* number of kgnilnd_scheduler threads */
	int              *kgn_net_hash_size;    /* size of kgn_net_ht */
	int              *kgn_hardware_timeout; /* max time for a message to get across the network */
	int              *kgn_mdd_timeout;      /* max time for ghal to hold an mdd in minutes */
	int		 *kgn_sched_timeout;    /* max time for scheduler to run before yielding */
	int              *kgn_dgram_timeout;    /* max time for dgram mover to run before scheduling */
	int		 *kgn_sched_nice;	/* nice value for kgnilnd scheduler threads */
	int		 *kgn_reverse_rdma;	/* Reverse RDMA setting */
	int		 *kgn_eager_credits;	/* allocated eager buffers */
	int     *kgn_fast_reconn;      /* fast reconnection on conn timeout */
	int     *kgn_efault_lbug;      /* LBUG on receiving an EFAULT */
	int     *kgn_max_purgatory;    /* # conns/peer to keep in purgatory */
	int     *kgn_reg_fail_timeout; /* registration failure timeout */
	int     *kgn_thread_affinity;  /* bind scheduler threads to cpus */
	int     *kgn_to_reconn_disable;/* disable reconnect after timeout */
	int     *kgn_thread_safe;      /* use thread safe kgni API */
	int     *kgn_vzalloc_noretry;  /* Should we pass the noretry flag */
} kgn_tunables_t;

typedef struct kgn_mbox_info {
	lnet_nid_t mbx_prev_nid;
	lnet_nid_t mbx_prev_purg_nid;
	unsigned long mbx_create_conn_memset;
	unsigned long mbx_add_purgatory;
	unsigned long mbx_detach_of_purgatory;
	unsigned long mbx_release_from_purgatory;
	unsigned long mbx_release_purg_active_dgram;
	int           mbx_nallocs;
	int           mbx_nallocs_total;
} kgn_mbox_info_t;

typedef struct kgn_fma_memblock {
	struct list_head    gnm_bufflist;                          /* memblock is part of device's  gnd_fma_buffs */
	kgn_fmablk_state_t  gnm_state;                             /* how this memory allocated & state of it */
	int                 gnm_hold_timeout;                      /* hold_timeout if used at unmap time */
	int                 gnm_num_mboxs;                         /* total mboxes allocated */
	int                 gnm_avail_mboxs;                       /* number of available mailboxes in the block */
	int                 gnm_held_mboxs;                        /* number of purgatory held  mailboxes */
	int                 gnm_mbox_size;                         /* size of the single mailbox */
	int                 gnm_next_avail_mbox;                   /* next available mailbox */
	long                gnm_max_timeout;                       /* max timeout for possible purgatory hold */
	unsigned int        gnm_blk_size;                          /* how big is our hunk o memory ? */
	void               *gnm_block;                             /* pointer to mem. block */
	gni_mem_handle_t    gnm_hndl;                              /* mem. handle of the block */
	unsigned long      *gnm_bit_array;                         /* bit array tracking allocation of mailboxes */
	kgn_mbox_info_t    *gnm_mbox_info;                         /* array of mbox_information about each mbox */
} kgn_fma_memblock_t;

typedef struct kgn_device {
	gni_nic_handle_t        gnd_handle;       /* device handle */
	gni_cdm_handle_t        gnd_domain;       /* GNI communication domain */
	gni_err_handle_t        gnd_err_handle;   /* device error handle */
	unsigned long           gnd_sched_alive;  /* scheduler thread alive stamp */
	gni_cq_handle_t         gnd_rcv_fma_cqh;  /* FMA rcv. completion queue handle */
	gni_cq_handle_t         gnd_snd_rdma_cqh; /* rdma send completion queue handle */
	gni_cq_handle_t         gnd_snd_fma_cqh;  /* rdma send completion queue handle */
	struct mutex            gnd_cq_mutex;     /* CQ access serialization */
	__u32                   gnd_host_id;      /* ph. host ID of the NIC */
	int                     gnd_id;           /* device id, also index in kgn_devices */
	__u32                   gnd_nid;          /* ph host ID translated to NID */
	struct list_head        gnd_fma_buffs;    /* list of FMA memory blocks */
	struct mutex            gnd_fmablk_mutex; /* mutex for FMA block memory alloc/free */
	spinlock_t              gnd_fmablk_lock;  /* lock for mbox alloc/release */
	atomic_t                gnd_nfmablk;      /* # of fmablk live */
	atomic_t                gnd_fmablk_vers;  /* gnd_fma_bufs stamp */
	atomic_t                gnd_neps;         /* # EP allocated to conns */
	short                   gnd_ready;        /* stuff to do in scheduler thread */
	struct list_head        gnd_ready_conns;  /* connections ready to tx/rx */
	struct list_head        gnd_delay_conns;  /* connections in need of dla/or smsg credits */
	struct list_head        gnd_map_tx;       /* TX: needing buffer mapping */
	wait_queue_head_t       gnd_waitq;        /* scheduler wakeup */
	spinlock_t              gnd_lock;         /* serialise gnd_ready_conns */
	struct list_head        gnd_connd_peers;  /* peers waiting for a connection */
	spinlock_t              gnd_connd_lock;   /* serialise connd_peers */
	wait_queue_head_t       gnd_dgram_waitq;  /* dgram_mover thread wakeup */
	wait_queue_head_t       gnd_dgping_waitq; /* dgram thread ping-pong */
	int                     gnd_dgram_ready;  /* dgrams need movin' */
	struct list_head       *gnd_dgrams;       /* nid hash to dgrams */
	atomic_t                gnd_ndgrams;      /* # dgrams extant */
	atomic_t                gnd_nwcdgrams;    /* # wildcard dgrams to post*/
	spinlock_t              gnd_dgram_lock;   /* serialize gnd_dgrams */
	struct list_head        gnd_map_list;     /* list of all mapped regions */
	int                     gnd_map_version;  /* version flag for map list */
	struct timer_list       gnd_map_timer;    /* wakey-wakey */
	atomic_t                gnd_n_mdd;        /* number of total MDD - fma, tx, etc */
	atomic_t                gnd_n_mdd_held;   /* number of total MDD held - fma, tx, etc */
	atomic_t                gnd_nq_map;       /* # queued waiting for mapping (MDD/GART) */
	atomic64_t              gnd_nbytes_map;   /* bytes of total GART maps - fma, tx, etc */
	__u32                   gnd_map_nphys;    /* # TX phys mappings */
	__u32                   gnd_map_physnop;  /* # TX phys pages mapped */
	spinlock_t              gnd_map_lock;     /* serialize gnd_map_XXX */
	unsigned long           gnd_next_map;     /* next mapping attempt in jiffies */
	int                     gnd_map_attempt;  /* last map attempt # */
	unsigned long           gnd_last_map;     /* map timeout base */
	struct list_head        gnd_rdmaq;        /* RDMA to be sent */
	spinlock_t              gnd_rdmaq_lock;   /* play nice with others */
	atomic64_t              gnd_rdmaq_bytes_out; /* # bytes authorized */
	atomic64_t              gnd_rdmaq_bytes_ok;  /* # bytes allowed until deadline */
	atomic_t                gnd_rdmaq_nstalls;   /* # stalls due to throttle */
	unsigned long           gnd_rdmaq_deadline;  /* when does bucket roll over ? */
	struct timer_list       gnd_rdmaq_timer;     /* wakey-wakey */
	atomic_t                gnd_short_ntx;      /* TX stats: short messages */
	atomic64_t              gnd_short_txbytes;  /* TX stats: short message  payload*/
	atomic_t                gnd_rdma_ntx;       /* TX stats: rdma messages */
	atomic64_t              gnd_rdma_txbytes;   /* TX stats: rdma message payload*/
	atomic_t                gnd_short_nrx;      /* RX stats: short messages */
	atomic64_t              gnd_short_rxbytes;  /* RX stats: short message  payload*/
	atomic_t                gnd_rdma_nrx;       /* RX stats: rdma messages */
	atomic64_t              gnd_rdma_rxbytes;   /* RX stats: rdma message payload*/
	atomic_t                gnd_fast_try;       /* # of times fast send tried */
	atomic_t                gnd_fast_ok;        /* # of times fast send ok */
	atomic_t                gnd_fast_block;     /* # of times fast send blocked */
	unsigned long           gnd_mutex_delay;
	atomic_t                gnd_n_yield;
	atomic_t                gnd_n_schedule;
	atomic_t                gnd_canceled_dgrams; /* # of outstanding cancels */
	struct rw_semaphore     gnd_conn_sem;       /* serialize connection changes/data movement */
	void                   *gnd_smdd_hold_buf;  /* buffer to keep smdd */
	gni_mem_handle_t        gnd_smdd_hold_hndl; /* buffer mem handle */
} kgn_device_t;

typedef struct kgn_net {
	struct list_head    gnn_list;           /* chain on kgni_data::kgn_nets */
	kgn_device_t       *gnn_dev;            /* device for this net */
	struct lnet_ni          *gnn_ni;             /* network interface instance */
	atomic_t            gnn_refcount;       /* # current references */
	int                 gnn_shutdown;       /* lnd_shutdown set */
	__u16               gnn_netnum;         /* stash netnum for quicker lookup */
} kgn_net_t;

static inline lnet_nid_t
kgnilnd_lnd2lnetnid(lnet_nid_t ni_nid, lnet_nid_t kgnilnd_nid)
{
	return LNET_MKNID(LNET_NIDNET(ni_nid), LNET_NIDADDR(kgnilnd_nid));
}

static inline lnet_nid_t
kgnilnd_lnet2lndnid(lnet_nid_t lnet_nid, lnet_nid_t kgnilnd_nid)
{
	return LNET_MKNID(LNET_NIDNET(kgnilnd_nid), LNET_NIDADDR(lnet_nid));
}

/* The code for this is a bit ugly - but really  this just boils down to a __u64
 * that can have various parts accessed separately.
 *
 * The lower 32 bits is the ID
 * we give to SMSG for our completion event - it needs to be globally unique across
 * all TX currently in flight. We separate that out into the CQID so that we can
 * reference the connection (kgnilnd_cqid2conn_locked) and then the msg_id to pull
 * the actual TX out of the per-connection gnc_tx_ref_table.
 *
 * The upper 32 bits are just extra stuff we put into the cookie to ensure this TX
 * has a unique value we can send with RDMA setup messages to ensure the completion for
 * those is unique across the wire. The extra 32 bits are there to ensure that TX id
 * reuse is separated.
 */

typedef struct kgn_tx_ev_id {
	union {
		__u64             txe_cookie;    /* are you my mommy ? */
		struct {
			__u32     txe_chips;     /* extra bits to ensure ID unique across reuse */
			union {
				__u32     txe_smsg_id;      /* ID for SMSG CQ event */
				/* N.B: Never ever ever ever use the bit shifts directly,
				 * you are just asking for a world of pain and are at the
				 * mercy of the compiler layouts */
				struct {
					__u32     txe_cqid :GNILND_CQID_NBITS;
					__u32     txe_idx :GNILND_MSGID_TX_NBITS;
				};
			};
		};
	};
} kgn_tx_ev_id_t;

typedef struct kgn_dgram {
	struct list_head     gndg_list;          /* on hash dev::gnd_dgrams */
	kgn_dgram_state_t    gndg_state;         /* state of this dgram */
	kgn_dgram_type_t     gndg_type;          /* REQ, NAK, etc */
	__u32                gndg_magic;         /* saftey word */
	unsigned long        gndg_post_time;     /* time when we posted */
	struct kgn_conn     *gndg_conn;          /* unbound conn with ep & smsg */
	kgn_connreq_t        gndg_conn_out;      /* connreq from local node */
	kgn_connreq_t        gndg_conn_in;       /* connreq from remote node */
} kgn_dgram_t;

typedef struct kgn_tx {                         /* message descriptor */
	struct list_head          tx_list;      /* TX queues - peer, conn, rdma */
	kgn_tx_list_state_t       tx_list_state;/* where in state machine is this TX ? */
	struct list_head         *tx_list_p;    /* pointer to current list */
	struct kgn_conn          *tx_conn;      /* owning conn */
	struct lnet_msg               *tx_lntmsg[2]; /* ptl msgs to finalize on completion */
	unsigned long             tx_qtime;     /* when tx started to wait for something (jiffies) */
	unsigned long             tx_cred_wait; /* time spend waiting for smsg creds */
	struct list_head          tx_map_list;  /* list entry on device map list */
	unsigned int              tx_nob;       /* # bytes of payload */
	int                       tx_buftype;   /* payload buffer type */
	int                       tx_phys_npages; /* # physical pages */
	gni_mem_handle_t          tx_map_key;   /* mapping key */
	gni_mem_handle_t	  tx_buffer_copy_map_key;  /* mapping key for page aligned copy */
	gni_mem_segment_t        *tx_phys;      /* page descriptors */
	kgn_msg_t                 tx_msg;       /* FMA message buffer */
	kgn_tx_ev_id_t            tx_id;        /* who are you, who ? who ? */
	__u8                      tx_state;     /* state of the descriptor */
	int                       tx_retrans;   /* retrans count of RDMA */
	int                       tx_rc;        /* if we need to stash the ret code until we see completion */
	void                     *tx_buffer;    /* source/sink buffer */
	void			 *tx_buffer_copy;   /* pointer to page aligned buffer */
	unsigned int		  tx_nob_rdma;  /* nob actually rdma */
	unsigned int		  tx_offset;	/* offset of data into copied buffer */
	union {
		gni_post_descriptor_t     tx_rdma_desc; /* rdma descriptor */
		struct page              *tx_imm_pages[GNILND_MAX_IMMEDIATE/PAGE_SIZE];  /* page array to map kiov for immediate send */
	};

	/* we only use one or the other */
	union {
		kgn_putack_msg_t  tx_putinfo;   /* data for differed rdma & re-try */
		kgn_get_msg_t     tx_getinfo;   /* data for rdma re-try*/
	};
} kgn_tx_t;

typedef struct kgn_conn {
	kgn_device_t       *gnc_device;         /* which device */
	struct kgn_peer    *gnc_peer;           /* owning peer */
	int                 gnc_magic;          /* magic value cleared before free */
	struct list_head    gnc_list;           /* stash on peer's conn list - or pending purgatory lists as we clear them */
	struct list_head    gnc_hashlist;       /* stash in connection hash table */
	struct list_head    gnc_schedlist;      /* schedule (on gnd_?_conns) for attention */
	struct list_head    gnc_fmaq;           /* txs queued for FMA */
	struct list_head    gnc_mdd_list;       /* hold list for MDD on hard conn reset */
	struct list_head    gnc_delaylist;      /* If on this list schedule anytime we get interrupted */
	__u64               gnc_peerstamp;      /* peer's unique stamp */
	__u64               gnc_peer_connstamp; /* peer's unique connection stamp */
	__u64               gnc_my_connstamp;   /* my unique connection stamp */
	unsigned long       gnc_first_rx;       /* when I first received an FMA message (jiffies) */
	unsigned long       gnc_last_tx;        /* when I last sent an FMA message (jiffies) */
	unsigned long       gnc_last_rx;        /* when I last sent an FMA message (jiffies) */
	unsigned long       gnc_last_tx_cq;     /* when I last received an FMA CQ (jiffies) */
	unsigned long       gnc_last_rx_cq;     /* when I last received an FMA CQ (jiffies) */
	unsigned long       gnc_last_noop_want; /* time I wanted to send NOOP */
	unsigned long       gnc_last_noop_sent; /* time I did gni_smsg_send on NOOP */
	unsigned long       gnc_last_noop_cq;   /* time when NOOP completed */
	unsigned long       gnc_last_sched_ask; /* time when conn added to ready_conns */
	unsigned long       gnc_last_sched_do;  /* time when conn processed from ready_conns */
	atomic_t            gnc_reaper_noop;    /* # reaper triggered NOOP */
	atomic_t            gnc_sched_noop;     /* # sched triggered NOOP */
	unsigned int        gnc_timeout;        /* infer peer death if no rx for this many seconds */
	__u32               gnc_cqid;           /* my completion callback id (non-unique) */
	atomic_t            gnc_tx_seq;         /* tx msg sequence number */
	atomic_t            gnc_rx_seq;         /* rx msg sequence number */
	struct mutex        gnc_smsg_mutex;     /* tx smsg sequence serialization */
	struct mutex        gnc_rdma_mutex;     /* tx rdma sequence serialization */
	__u64               gnc_tx_retrans;     /* # retrans on SMSG */
	atomic_t            gnc_nlive_fma;      /* # live FMA */
	atomic_t            gnc_nq_rdma;        /* # queued (on device) RDMA */
	atomic_t            gnc_nlive_rdma;     /* # live RDMA */
	short               gnc_close_sent;     /* I've sent CLOSE */
	short               gnc_close_recvd;    /* I've received CLOSE */
	short               gnc_in_purgatory;   /* in the sin bin */
	int                 gnc_error;          /* errno when conn being closed due to error */
	int                 gnc_peer_error;     /* errno peer sent us on CLOSE */
	kgn_conn_state_t    gnc_state;          /* connection state */
	int                 gnc_scheduled;      /* being attented to */
	char		    gnc_sched_caller[30]; /* what function last called schedule */
	int		    gnc_sched_line;	/* what line # last called schedule */
	atomic_t            gnc_refcount;       /* # users */
	spinlock_t          gnc_list_lock;      /* serialise tx lists, max_rx_age */
	gni_ep_handle_t     gnc_ephandle;       /* GNI endpoint */
	kgn_fma_memblock_t *gnc_fma_blk;        /* pointer to fma block for our mailbox */
	gni_smsg_attr_t     gnpr_smsg_attr;     /* my short msg. attributes */
	spinlock_t          gnc_tx_lock;        /* protect tx alloc/free */
	unsigned long       gnc_tx_bits[(GNILND_MAX_MSG_ID/8)/sizeof(unsigned long)]; /* bit table for tx id */
	int                 gnc_next_tx;        /* next tx to use in tx_ref_table */
	kgn_tx_t          **gnc_tx_ref_table;   /* table of TX descriptors for this conn */
	int                 gnc_mbox_id;        /* id of mbox in fma_blk                 */
	short               gnc_needs_detach;   /* flag set in detach_purgatory_all_locked so reaper will clear out purgatory */
	short               gnc_needs_closing;  /* flag set in del_conns when called from kgnilnd_del_peer_or_conn */
	atomic_t	    gnc_tx_in_use;	/* # of tx's currently in use by another thread use kgnilnd_peer_conn_lock */
	kgn_dgram_type_t    gnc_dgram_type;     /* save dgram type used to establish this conn */
	void               *remote_mbox_addr;   /* save remote mbox address */
} kgn_conn_t;

typedef struct kgn_mdd_purgatory {
	gni_mem_handle_t    gmp_map_key;        /* mapping key */
	struct list_head    gmp_list;           /* entry point for purgatory list */
} kgn_mdd_purgatory_t;

typedef struct kgn_peer {
	struct list_head    gnp_list;                   /* stash on global peer list */
	struct list_head    gnp_connd_list;             /* schedule on kgn_connd_peers */
	struct list_head    gnp_conns;                  /* all active connections and all conns in purgatory for the peer */
	struct list_head    gnp_tx_queue;               /* msgs waiting for a conn */
	kgn_net_t          *gnp_net;                    /* net instance for this peer */
	lnet_nid_t          gnp_nid;                    /* who's on the other end(s) */
	atomic_t            gnp_refcount;               /* # users */
	__u32               gnp_host_id;                /* ph. host ID of the peer */
	short               gnp_connecting;             /* connection forming */
	short               gnp_pending_unlink;         /* need last conn close to trigger unlink */
	int                 gnp_last_errno;             /* last error conn saw */
	time64_t	    gnp_last_alive;             /* last time I had valid comms */
	int                 gnp_last_dgram_errno;       /* last error dgrams saw */
	unsigned long       gnp_last_dgram_time;        /* last time I tried to connect */
	unsigned long       gnp_reconnect_time;         /* get_seconds() when reconnect OK */
	unsigned long       gnp_reconnect_interval;     /* exponential backoff */
	atomic_t            gnp_dirty_eps;              /* # of old but yet to be destroyed EPs from conns */
	int                 gnp_state;                  /* up/down/timedout */
	unsigned long       gnp_down_event_time;        /* time peer down */
	unsigned long       gnp_up_event_time;          /* time peer back up */
} kgn_peer_t;

/* the kgn_rx_t is a struct for handing to LNET as the private pointer for things
 * like lnet_parse. It allows a single pointer to let us get enough
 * information in _recv and friends */
typedef struct kgn_rx {
	kgn_conn_t              *grx_conn;      /* connection */
	kgn_msg_t               *grx_msg;       /* message */
	struct lnet_msg              *grx_lntmsg;    /* lnet msg for this rx (eager only) */
	int                      grx_eager;     /* if eager, we copied msg to somewhere */
	struct timespec64        grx_received;  /* time this msg received */
} kgn_rx_t;

typedef struct kgn_data {
	int                     kgn_init;             /* initialisation state */
	int                     kgn_shutdown;         /* shut down? */
	int                     kgn_wc_kill;          /* Should I repost the WC */
	atomic_t                kgn_nthreads;         /* # live threads */
	int                     kgn_nresets;          /* number of stack resets */
	int                     kgn_in_reset;         /* are we in stack reset ? */

	__u64                   kgn_nid_trans_private;/* private data for each of the HW nid2nic arenas */

	kgn_device_t            kgn_devices[GNILND_MAXDEVS]; /* device/ptag/cq etc */
	int                     kgn_ndevs;            /* # devices */

	int                     kgn_ruhroh_running;   /* ruhroh thread is running */
	int                     kgn_ruhroh_shutdown;  /* ruhroh thread should or is shut down */
	wait_queue_head_t       kgn_ruhroh_waitq;     /* ruhroh thread wakeup */
	int                     kgn_quiesce_trigger;  /* should we quiesce ? */
	atomic_t                kgn_nquiesce;         /* how many quiesced ? */
	struct mutex            kgn_quiesce_mutex;    /* serialize ruhroh task, startup and shutdown */
	int                     kgn_needs_reset;      /* we need stack reset */

	/* These next three members implement communication from gnilnd into
	 * the ruhroh task.  To ensure correct operation of the task, code that
	 * writes into them must use memory barriers to ensure that the changes
	 * are visible to other cores in the order the members appear below.  */
	__u32                   kgn_quiesce_secs;     /* seconds to bump timeouts */
	int                     kgn_bump_info_rdy;    /* we have info needed to bump */
	int                     kgn_needs_pause;      /* we need to pause for network quiesce */

	struct list_head       *kgn_nets;             /* hashtable of kgn_net instances */
	struct rw_semaphore     kgn_net_rw_sem;       /* serialise gnn_shutdown, kgn_nets */

	rwlock_t                kgn_peer_conn_lock;   /* stabilize peer/conn ops */
	struct list_head       *kgn_peers;            /* hash table of all my known peers */
	atomic_t                kgn_npeers;           /* # peers extant */
	int                     kgn_peer_version;     /* version flag for peer tables */

	struct list_head       *kgn_conns;            /* conns hashed by cqid */
	atomic_t                kgn_nconns;           /* # connections extant */
	atomic_t                kgn_neager_allocs;    /* # of eager allocations */
	__u64                   kgn_peerstamp;        /* when I started up */
	__u64                   kgn_connstamp;        /* conn stamp generator */
	int                     kgn_conn_version;     /* version flag for conn tables */
	int                     kgn_next_cqid;        /* cqid generator */

	long                    kgn_new_min_timeout;  /* minimum timeout on any new conn */
	wait_queue_head_t       kgn_reaper_waitq;     /* reaper sleeps here */
	spinlock_t              kgn_reaper_lock;      /* serialise */

	struct kmem_cache      *kgn_rx_cache;         /* rx descriptor space */
	struct kmem_cache      *kgn_tx_cache;         /* tx descriptor memory */
	struct kmem_cache      *kgn_tx_phys_cache;    /* tx phys descriptor memory */
	atomic_t                kgn_ntx;              /* # tx in use */
	struct kmem_cache      *kgn_dgram_cache;      /* outgoing datagrams */

	struct page          ***kgn_cksum_map_pages;  /* page arrays for mapping pages on checksum */
	__u64                   kgn_cksum_npages;     /* # pages alloc'd for checksumming */
	atomic_t                kgn_nvmap_cksum;      /* # times we vmapped for checksums */
	atomic_t                kgn_nvmap_short;      /* # times we vmapped for short kiov */

	atomic_t                kgn_nkmap_short;      /* # time we kmapped for a short kiov */
	long                    kgn_rdmaq_override;   /* bytes per second override */

	struct kmem_cache      *kgn_mbox_cache;       /* mailboxes from not-GART */

	atomic_t                kgn_npending_unlink;  /* # of peers pending unlink */
	atomic_t                kgn_npending_conns;   /* # of conns with pending closes */
	atomic_t                kgn_npending_detach;  /* # of conns with a pending detach */
	unsigned long           kgn_last_scheduled;   /* last time schedule was called */
	unsigned long           kgn_last_condresched; /* last time cond_resched was called */
	atomic_t                kgn_rev_offset;       /* # of REV rdma w/misaligned offsets */
	atomic_t                kgn_rev_length;       /* # of REV rdma have misaligned len */
	atomic_t                kgn_rev_copy_buff;    /* # of REV rdma buffer copies */
	unsigned long           free_pages_limit;     /* # of free pages reserve from fma block allocations */
	int                     kgn_enable_gl_mutex;  /* kgni api mtx enable */
} kgn_data_t;

extern kgn_data_t         kgnilnd_data;
extern kgn_tunables_t     kgnilnd_tunables;

extern void kgnilnd_destroy_peer(kgn_peer_t *peer);
extern void kgnilnd_destroy_conn(kgn_conn_t *conn);
extern int _kgnilnd_schedule_conn(kgn_conn_t *conn, const char *caller, int line, int refheld, int lock_held);
extern int _kgnilnd_schedule_delay_conn(kgn_conn_t *conn);

/* Macro wrapper for _kgnilnd_schedule_conn. This will store the function
 * and the line of the calling function to allow us to debug problematic
 * schedule calls in the future without the programmer having to mark
 * the location manually.
 */
#define kgnilnd_schedule_conn(conn)					\
	_kgnilnd_schedule_conn(conn, __func__, __LINE__, 0, 0);

#define kgnilnd_schedule_conn_refheld(conn, refheld)			\
	_kgnilnd_schedule_conn(conn, __func__, __LINE__, refheld, 0);

#define kgnilnd_schedule_conn_nolock(conn)				\
	_kgnilnd_schedule_conn(conn, __func__, __LINE__, 0, 1);


/* Macro wrapper for _kgnilnd_schedule_delay_conn. This will allow us to store
 * extra data if we need to.
 */
#define kgnilnd_schedule_delay_conn(conn) \
	_kgnilnd_schedule_delay_conn(conn);

static inline void
kgnilnd_thread_fini(void)
{
	atomic_dec(&kgnilnd_data.kgn_nthreads);
}

static inline void kgnilnd_gl_mutex_lock(struct mutex *lock)
{
	if (kgnilnd_data.kgn_enable_gl_mutex)
		mutex_lock(lock);
}

static inline void kgnilnd_gl_mutex_unlock(struct mutex *lock)
{
	if (kgnilnd_data.kgn_enable_gl_mutex)
		mutex_unlock(lock);
}

static inline void kgnilnd_conn_mutex_lock(struct mutex *lock)
{
	if (!kgnilnd_data.kgn_enable_gl_mutex)
		mutex_lock(lock);
}

static inline void kgnilnd_conn_mutex_unlock(struct mutex *lock)
{
	if (!kgnilnd_data.kgn_enable_gl_mutex)
		mutex_unlock(lock);
}

/* like mutex_trylock but with a jiffies spinner. This is to allow certain
 * parts of the code to avoid a scheduler trip when the mutex is held
 *
 * Try to acquire the mutex atomically for 1 jiffie. Returns 1 if the mutex
 * has been acquired successfully, and 0 on contention.
 *
 * NOTE: this function follows the spin_trylock() convention, so
 * it is negated to the down_trylock() return values! Be careful
 * about this when converting semaphore users to mutexes.
 *
 * This function must not be used in interrupt context. The
 * mutex must be released by the same task that acquired it.
 */
static inline int __kgnilnd_mutex_trylock(struct mutex *lock)
{
	int             ret;
	unsigned long   timeout;

	LASSERT(!in_interrupt());

	for (timeout = jiffies + 1; time_before(jiffies, timeout);) {

		ret = mutex_trylock(lock);
		if (ret)
			return ret;
	}
	return 0;
}

static inline int kgnilnd_mutex_trylock(struct mutex *lock)
{
	if (!kgnilnd_data.kgn_enable_gl_mutex)
		return 1;

	return __kgnilnd_mutex_trylock(lock);
}

static inline int kgnilnd_trylock(struct mutex *cq_lock,
				  struct mutex *c_lock)
{
	if (kgnilnd_data.kgn_enable_gl_mutex)
		return __kgnilnd_mutex_trylock(cq_lock);
	else
		return __kgnilnd_mutex_trylock(c_lock);
}

static inline void *kgnilnd_vzalloc(int size)
{
	void *ret;
	if (*kgnilnd_tunables.kgn_vzalloc_noretry)
		ret = __ll_vmalloc(size, __GFP_HIGHMEM | GFP_NOIO | __GFP_ZERO |
				   __GFP_NORETRY);
	else
		ret = __ll_vmalloc(size, __GFP_HIGHMEM | GFP_NOIO | __GFP_ZERO);

	LIBCFS_ALLOC_POST(ret, size);
	return ret;
}

static inline void kgnilnd_vfree(void *ptr, int size)
{
	libcfs_kmem_dec(ptr, size);
	vfree(ptr);
}

/* as of kernel version 4.2, set_mb is replaced with smp_store_mb */
#ifndef set_mb
#define set_mb smp_store_mb
#endif

/* Copied from DEBUG_REQ in Lustre - the dance is needed to save stack space */

extern void
_kgnilnd_debug_msg(kgn_msg_t *msg,
		struct libcfs_debug_msg_data *data, const char *fmt, ... );

#define kgnilnd_debug_msg(msgdata, mask, cdls, msg, fmt, a...)                \
do {                                                                          \
	CFS_CHECK_STACK(msgdata, mask, cdls);                                 \
									      \
	if (((mask) & D_CANTMASK) != 0 ||                                     \
	    ((libcfs_debug & (mask)) != 0 &&                                  \
	     (libcfs_subsystem_debug & DEBUG_SUBSYSTEM) != 0))                \
		_kgnilnd_debug_msg((msg), msgdata, fmt, ##a);                 \
} while(0)

/* for most callers (level is a constant) this is resolved at compile time */
#define GNIDBG_MSG(level, msg, fmt, args...)                                  \
do {                                                                          \
	if ((level) & (D_ERROR | D_WARNING | D_NETERROR)) {                   \
	    static struct cfs_debug_limit_state cdls;                         \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, &cdls);                \
	    kgnilnd_debug_msg(&msgdata, level, &cdls, msg,                    \
			      "$$ "fmt" from %s ", ## args,                   \
			      libcfs_nid2str((msg)->gnm_srcnid));             \
	} else {                                                              \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, NULL);                 \
	    kgnilnd_debug_msg(&msgdata, level, NULL, msg,                     \
			      "$$ "fmt" from %s ", ## args,                   \
			      libcfs_nid2str((msg)->gnm_srcnid));             \
	}                                                                     \
} while (0)

/* user puts 'to nid' in msg for us */
#define GNIDBG_TOMSG(level, msg, fmt, args...)                                \
do {                                                                          \
	if ((level) & (D_ERROR | D_WARNING | D_NETERROR)) {                   \
	    static struct cfs_debug_limit_state cdls;                         \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, &cdls);                \
	    kgnilnd_debug_msg(&msgdata, level, &cdls, msg,                    \
			      "$$ "fmt" ", ## args);                          \
	} else {                                                              \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, NULL);                 \
	    kgnilnd_debug_msg(&msgdata, level, NULL, msg,                     \
			      "$$ "fmt" ", ## args);                          \
	}                                                                     \
} while (0)

extern void
_kgnilnd_debug_conn(kgn_conn_t *conn,
		struct libcfs_debug_msg_data *data, const char *fmt, ... );

#define kgnilnd_debug_conn(msgdata, mask, cdls, conn, fmt, a...)               \
do {                                                                           \
	CFS_CHECK_STACK(msgdata, mask, cdls);                                  \
									       \
	if (((mask) & D_CANTMASK) != 0 ||                                      \
	    ((libcfs_debug & (mask)) != 0 &&                                   \
	     (libcfs_subsystem_debug & DEBUG_SUBSYSTEM) != 0))                 \
		_kgnilnd_debug_conn((conn), msgdata, fmt, ##a);                \
} while(0)

/* for most callers (level is a constant) this is resolved at compile time */
#define GNIDBG_CONN(level, conn, fmt, args...)                                  \
do {                                                                            \
	if ((level) & (D_ERROR | D_WARNING | D_NETERROR)) {                     \
	    static struct cfs_debug_limit_state cdls;                           \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, &cdls);                  \
	    kgnilnd_debug_conn(&msgdata, level, &cdls, conn,                    \
			       "$$ "fmt" ", ## args);                           \
	} else {                                                                \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, NULL);                   \
	    kgnilnd_debug_conn(&msgdata, level, NULL, conn,                     \
			       "$$ "fmt" ", ## args);                           \
	}                                                                       \
} while (0)

extern void
_kgnilnd_debug_tx(kgn_tx_t *tx,
		struct libcfs_debug_msg_data *data, const char *fmt, ... );

#define kgnilnd_debug_tx(msgdata, mask, cdls, tx, fmt, a...)                   \
do {                                                                           \
	CFS_CHECK_STACK(msgdata, mask, cdls);                                  \
									       \
	if (((mask) & D_CANTMASK) != 0 ||                                      \
	    ((libcfs_debug & (mask)) != 0 &&                                   \
	     (libcfs_subsystem_debug & DEBUG_SUBSYSTEM) != 0))                 \
		_kgnilnd_debug_tx((tx), msgdata, fmt, ##a);                    \
} while(0)

/* for most callers (level is a constant) this is resolved at compile time */
#define GNIDBG_TX(level, tx, fmt, args...)                                      \
do {                                                                            \
	if ((level) & (D_ERROR | D_WARNING | D_NETERROR)) {                     \
	    static struct cfs_debug_limit_state cdls;                           \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, &cdls);                  \
	    kgnilnd_debug_tx(&msgdata, level, &cdls, tx,                        \
			      "$$ "fmt" ", ## args);                            \
	} else {                                                                \
	    LIBCFS_DEBUG_MSG_DATA_DECL(msgdata, level, NULL);                   \
	    kgnilnd_debug_tx(&msgdata, level, NULL, tx,                         \
			      "$$ "fmt" ", ## args);                            \
	}                                                                       \
} while (0)

#define GNITX_ASSERTF(tx, cond, fmt, a...)                                      \
({                                                                              \
	if (unlikely(!(cond))) {                                                \
		GNIDBG_TX(D_EMERG, tx, "ASSERTION(" #cond ") failed:" fmt, a);  \
		LBUG();                                                         \
	}                                                                       \
})

#define GNILND_IS_QUIESCED                                                      \
	(atomic_read(&kgnilnd_data.kgn_nquiesce) ==                             \
		atomic_read(&kgnilnd_data.kgn_nthreads))

#define KGNILND_SPIN_QUIESCE						\
do {									\
	/* E.T phone home */						\
	atomic_inc(&kgnilnd_data.kgn_nquiesce);				\
	CDEBUG(D_NET, "Waiting for thread pause to be over...\n");	\
	while (kgnilnd_data.kgn_quiesce_trigger) {			\
		msleep_interruptible(MSEC_PER_SEC);			\
	}								\
	/* Mom, my homework is done */					\
	CDEBUG(D_NET, "Waking up from thread pause\n");			\
	atomic_dec(&kgnilnd_data.kgn_nquiesce);				\
} while(0)

/* use macros for addref/decref to get the calling function name in the CDEBUG */
#ifndef LIBCFS_DEBUG
#error "this code uses actions inside LASSERT for ref counting"
#endif

#define kgnilnd_admin_addref(atomic)					\
do {									\
	int val = atomic_inc_return(&atomic);				\
	LASSERTF(val > 0,  #atomic " refcount %d\n", val);		\
	CDEBUG(D_NETTRACE, #atomic " refcount %d\n", val);		\
} while (0)

#define kgnilnd_admin_decref(atomic)					\
do {									\
	int val = atomic_dec_return(&atomic);				\
	LASSERTF(val >= 0,  #atomic " refcount %d\n", val);		\
	CDEBUG(D_NETTRACE, #atomic " refcount %d\n", val);		\
	if (!val)							\
		wake_up_var(&kgnilnd_data);				\
}while (0)

#define kgnilnd_net_addref(net)                                                 \
do {                                                                            \
	int     val = atomic_inc_return(&net->gnn_refcount);                    \
	LASSERTF(val > 1, "net %p refcount %d\n", net, val);                    \
	CDEBUG(D_NETTRACE, "net %p->%s++ (%d)\n", net,                          \
		libcfs_nid2str(net->gnn_ni->ni_nid), val);                      \
} while (0)

#define kgnilnd_net_decref(net)                                                 \
do {                                                                            \
	int     val = atomic_dec_return(&net->gnn_refcount);                    \
	LASSERTF(val >= 0, "net %p refcount %d\n", net, val);                   \
	CDEBUG(D_NETTRACE, "net %p->%s-- (%d)\n", net,                          \
	       libcfs_nid2str(net->gnn_ni->ni_nid), val);                       \
} while (0)

#define kgnilnd_peer_addref(peer)                                               \
do {                                                                            \
	int     val = atomic_inc_return(&peer->gnp_refcount);                   \
	LASSERTF(val > 1, "peer %p refcount %d\n", peer, val);                  \
	CDEBUG(D_NETTRACE, "peer %p->%s++ (%d)\n", peer,                        \
	       libcfs_nid2str(peer->gnp_nid), val);                             \
} while (0)

#define kgnilnd_peer_decref(peer)                                               \
do {                                                                            \
	int     val = atomic_dec_return(&peer->gnp_refcount);                   \
	LASSERTF(val >= 0, "peer %p refcount %d\n", peer, val);                 \
	CDEBUG(D_NETTRACE, "peer %p->%s--(%d)\n", peer,                         \
	       libcfs_nid2str(peer->gnp_nid), val);                             \
	if (val == 0)      				                        \
		kgnilnd_destroy_peer(peer);                                     \
} while(0)

#define kgnilnd_conn_addref(conn)                                       \
do {                                                                    \
	int     val;                                                    \
									\
	smp_wmb();                                                      \
	val = atomic_inc_return(&conn->gnc_refcount);                   \
	LASSERTF(val > 1 && conn->gnc_magic == GNILND_CONN_MAGIC,       \
		"conn %p refc %d to %s\n",                              \
		conn, val,                                              \
		conn->gnc_peer                                          \
			? libcfs_nid2str(conn->gnc_peer->gnp_nid)       \
			: "<?>");                                       \
	CDEBUG(D_NETTRACE, "conn %p->%s++ (%d)\n", conn,                \
		conn->gnc_peer                                          \
			? libcfs_nid2str(conn->gnc_peer->gnp_nid)       \
			: "<?>",                                        \
		val);                                                   \
} while (0)

/* we hijack conn_decref && gnc_refcount = 1 to allow us to push the conn
 * through the scheduler thread to get the EP destroyed. This avoids some
 * messy semaphore business and allows us to reuse the connd_list and existing
 * linkage and avoid creating extra lists just for destroying EPs */

/* Safety Disclaimer:
 * Q: If we decrement the refcount and then check it again, is it possible that
 *    another caller could have passed through this macro concurrently? If so,
 *    then it is possible that both will attempt to call kgnilnd_destroy_conn().
 *
 * A: Yes, entirely possible in most cases, but we can't get concurrent users
 * once we are refcount <= 2. It hinges around gnc_state and membership of
 * gnc_hashlist. There are two ways to find a connection - either ask for
 * it from the peer, kgnilnd_find_conn_locked(peer) or from the CQ id,
 * kgnilnd_cqid2conn_locked(id). While a conn is live, we'll have at least
 * 4 refcounts
 *
 * - #1 from create (kgnilnd_create_conn)
 * - #2 for EP (kgnilnd_create_conn)
 * - #3 - living on peer (gnc_list, kgnilnd_finish_connect)
 * - #4 living in global hash (gnc_hashlist, kgnilnd_finish_connect).
 *
 * Actually, only 3 live, as at the end of kgnilnd_finish_connect, we drop:
 * - #1 - the ref the dgram inherited from kgnilnd_create_conn.
 *
 * There could be more from TX descriptors during the lifetime of a live
 * conn.
 *
 * If we nuke the conn before finish_connect, we won't have parallel paths
 * because nobody besides the dgram handler for the single outstanding
 * dgram can find the connection as it isn't in any searchable tables yet.
 *
 * This leaves connection close, we'll drop 2 refs (#4 and #3) but only
 * after calling kgnilnd_schedule_conn, which would add a new ref (#5). At
 * this point gnc_refcount=2 (#2, #5). We have a 'maybe' send of the CLOSE
 * now on the next scheduler loop, this could be #6 (schedule_conn again)
 * and #7 (TX on gnc_fmaq). Both would be cleared quickly as that TX is
 * sent. Now the gnc_state == CLOSED, so we hit
 * kgnilnd_complete_closed_conn. At this point, nobody can 'find' this conn
 * - we've nuked them from the peer and CQ id tables, so we own them and
 * are guaranteed serial access - hence the complete lack of conn list
 * locking in kgnilnd_complete_closed_conn. We are free then to mark the
 * conn DESTROY_EP (add #6 for schedule_conn), then lose #5 in
 * kgnilnd_process_conns. Then the next scheduler loop would call
 * kgnilnd_destroy_conn_ep (drop #2 for EP) and lose #6 (refcount=0) in
 * kgnilnd_process_conns.
 *
 * Clearly, we are totally safe. Clearly.
 */

#define kgnilnd_conn_decref(conn)                                       \
do {                                                                    \
	int     val;                                                    \
									\
	smp_wmb();                                                      \
	val = atomic_dec_return(&conn->gnc_refcount);                   \
	LASSERTF(val >= 0, "conn %p refc %d to %s\n",                   \
		conn, val,                                              \
		conn->gnc_peer                                          \
			? libcfs_nid2str(conn->gnc_peer->gnp_nid)       \
			: "<?>");                                       \
	CDEBUG(D_NETTRACE, "conn %p->%s-- (%d)\n", conn,                \
		conn->gnc_peer                                          \
			? libcfs_nid2str(conn->gnc_peer->gnp_nid)       \
			: "<?>",                                        \
		val);                                                   \
	smp_rmb();                                                      \
	if ((val == 1) &&                                               \
	    (conn->gnc_ephandle != NULL) &&                             \
	    (conn->gnc_state != GNILND_CONN_DESTROY_EP)) {              \
		set_mb(conn->gnc_state, GNILND_CONN_DESTROY_EP);        \
		kgnilnd_schedule_conn(conn);                            \
	} else if (val == 0) {                                          \
		kgnilnd_destroy_conn(conn);                             \
	}                                                               \
} while (0)

static inline struct list_head *
kgnilnd_nid2peerlist(lnet_nid_t nid)
{
	unsigned int hash = ((unsigned int)LNET_NIDADDR(nid)) % *kgnilnd_tunables.kgn_peer_hash_size;

	RETURN(&kgnilnd_data.kgn_peers[hash]);
}

static inline struct list_head *
kgnilnd_netnum2netlist(__u16 netnum)
{
	unsigned int hash = ((unsigned int) netnum) % *kgnilnd_tunables.kgn_net_hash_size;

	RETURN(&kgnilnd_data.kgn_nets[hash]);
}

static inline int
kgnilnd_peer_active(kgn_peer_t *peer)
{
	/* Am I in the peer hash table? */
	return (!list_empty(&peer->gnp_list));
}

/* need write_lock on kgn_peer_conn_lock */
static inline int
kgnilnd_can_unlink_peer_locked(kgn_peer_t *peer)
{
	CDEBUG(D_NET, "peer 0x%p->%s conns? %d tx? %d\n",
		peer, libcfs_nid2str(peer->gnp_nid),
		!list_empty(&peer->gnp_conns),
		!list_empty(&peer->gnp_tx_queue));

	/* kgn_peer_conn_lock protects us from conflict with
	 * kgnilnd_peer_notify and gnp_persistent */
	RETURN ((list_empty(&peer->gnp_conns)) &&
		(list_empty(&peer->gnp_tx_queue)));
}

/* returns positive if error was for a clean shutdown of conn */
static inline int
kgnilnd_conn_clean_errno(int errno)
{
	/*  - ESHUTDOWN - LND is unloading
	 *  - EUCLEAN - admin requested via "lctl del_peer"
	 *  - ENETRESET - admin requested via "lctl disconnect" or rca event
	 *  - ENOTRECOVERABLE - stack reset
	 *  - EISCONN - cleared via "lctl push"
	 *  not doing ESTALE - that isn't clean */
	RETURN ((errno == 0) ||
		(errno == -ESHUTDOWN) ||
		(errno == -EUCLEAN) ||
		(errno == -ENETRESET) ||
		(errno == -EISCONN) ||
		(errno == -ENOTRECOVERABLE));
}

/* returns positive if error results in purgatory hold */
static inline int
kgnilnd_check_purgatory_errno(int errno)
{
	/* We don't want to save the purgatory lists these cases:
	 *  - EUCLEAN - admin requested via "lctl del_peer"
	 *  - ESHUTDOWN - LND is unloading
	 */
	RETURN ((errno != -ESHUTDOWN) &&
		(errno != -EUCLEAN));

}

/* returns positive if a purgatory hold is needed */
static inline int
kgnilnd_check_purgatory_conn(kgn_conn_t *conn)
{
	int loopback = 0;

	if (conn->gnc_peer) {
		loopback = conn->gnc_peer->gnp_nid ==
		       conn->gnc_peer->gnp_net->gnn_ni->ni_nid;
	} else {
		/* short circuit - a conn that didn't complete
		 * setup never needs a purgatory hold */
		RETURN(0);
	}
	CDEBUG(D_NETTRACE, "conn 0x%p->%s loopback %d close_recvd %d\n",
		conn, conn->gnc_peer ?
				libcfs_nid2str(conn->gnc_peer->gnp_nid) :
				"<?>",
		loopback, conn->gnc_close_recvd);

	/* we only use a purgatory hold if we've not received the CLOSE msg
	 * from our peer - without that message, we can't know the state of
	 * the other end of this connection and must put it into purgatory
	 * to prevent reuse and corruption.
	 * The theory is that a TX error can be communicated in all other cases
	 */
	RETURN(likely(!loopback) && !conn->gnc_close_recvd &&
		kgnilnd_check_purgatory_errno(conn->gnc_error));
}

static inline const char *
kgnilnd_tx_state2str(kgn_tx_list_state_t state);

static inline struct list_head *
kgnilnd_tx_state2list(kgn_peer_t *peer, kgn_conn_t *conn,
			kgn_tx_list_state_t to_state)
{
	switch (to_state) {
	case GNILND_TX_PEERQ:
		return &peer->gnp_tx_queue;
	case GNILND_TX_FMAQ:
		return &conn->gnc_fmaq;
	case GNILND_TX_LIVE_FMAQ:
	case GNILND_TX_LIVE_RDMAQ:
	case GNILND_TX_DYING:
		return NULL;
	case GNILND_TX_MAPQ:
		return &conn->gnc_device->gnd_map_tx;
	case GNILND_TX_RDMAQ:
		return &conn->gnc_device->gnd_rdmaq;
	default:
		/* IDLE, FREED or ALLOCD is not valid "on list" state */
		CERROR("invalid state requested: %s\n",
			kgnilnd_tx_state2str(to_state));
		LBUG();
		break;
	}
}

/* should hold tx, conn or peer lock when calling */
static inline void
kgnilnd_tx_add_state_locked(kgn_tx_t *tx, kgn_peer_t *peer,
			kgn_conn_t *conn, kgn_tx_list_state_t state,
			int add_tail)
{
	struct list_head        *list = NULL;

	/* make sure we have a sane TX state to start */
	GNITX_ASSERTF(tx, (tx->tx_list_p == NULL &&
		  tx->tx_list_state == GNILND_TX_ALLOCD) &&
		list_empty(&tx->tx_list),
		"bad state with tx_list %s",
		list_empty(&tx->tx_list) ? "empty" : "not empty");

	/* WTF - you are already on that state buttmunch */
	GNITX_ASSERTF(tx, state != tx->tx_list_state,
		      "already at %s", kgnilnd_tx_state2str(state));

	/* get proper list from the state requested */
	list = kgnilnd_tx_state2list(peer, conn, state);

	/* add refcount */
	switch (state) {
	case GNILND_TX_PEERQ:
		kgnilnd_peer_addref(peer);
		break;
	case GNILND_TX_ALLOCD:
		/* no refs needed */
		break;
	case GNILND_TX_FMAQ:
		kgnilnd_conn_addref(conn);
		break;
	case GNILND_TX_MAPQ:
		atomic_inc(&conn->gnc_device->gnd_nq_map);
		kgnilnd_conn_addref(conn);
		break;
	case GNILND_TX_LIVE_FMAQ:
		atomic_inc(&conn->gnc_nlive_fma);
		kgnilnd_conn_addref(conn);
		break;
	case GNILND_TX_LIVE_RDMAQ:
		atomic_inc(&conn->gnc_nlive_rdma);
		kgnilnd_conn_addref(conn);
		break;
	case GNILND_TX_RDMAQ:
		atomic_inc(&conn->gnc_nq_rdma);
		kgnilnd_conn_addref(conn);
		break;
	case GNILND_TX_DYING:
		kgnilnd_conn_addref(conn);
		break;
	default:
		CERROR("invalid state requested: %s\n",
			kgnilnd_tx_state2str(state));
		LBUG();
		break;;
	}

	/* if this changes, change kgnilnd_alloc_tx */
	tx->tx_list_state = state;

	/* some states don't have lists - we track them in the per conn
	 * TX table instead. Waste not, want not! */
	if (list != NULL) {
		tx->tx_list_p = list;
		if (add_tail)
			list_add_tail(&tx->tx_list, list);
		else
			list_add(&tx->tx_list, list);
	} else {
		/* set dummy list_p to make book keeping happy and let debugging
		 * be a hair easier */
		tx->tx_list_p = (void *)state;
	}

	GNIDBG_TX(D_NET, tx, "onto %s->0x%p",
		  kgnilnd_tx_state2str(state), list);
}

static inline void
kgnilnd_tx_del_state_locked(kgn_tx_t *tx, kgn_peer_t *peer,
			kgn_conn_t *conn, kgn_tx_list_state_t new_state)
{
	/* These is only 1 "off-list" state */
	GNITX_ASSERTF(tx, new_state == GNILND_TX_ALLOCD,
		      "invalid new_state %s", kgnilnd_tx_state2str(new_state));

	/* new_state == ALLOCD means we are deallocating this tx,
	 * so make sure it was on a valid list to start with */
	GNITX_ASSERTF(tx, (tx->tx_list_p != NULL) &&
		      (((tx->tx_list_state == GNILND_TX_LIVE_FMAQ) ||
			(tx->tx_list_state == GNILND_TX_LIVE_RDMAQ) ||
			(tx->tx_list_state == GNILND_TX_DYING)) == list_empty(&tx->tx_list)),
		      "bad state", NULL);

	GNIDBG_TX(D_NET, tx, "off %p", tx->tx_list_p);

	/* drop refcount */
	switch (tx->tx_list_state) {
	case GNILND_TX_PEERQ:
		kgnilnd_peer_decref(peer);
		break;
	case GNILND_TX_FREED:
	case GNILND_TX_IDLE:
	case GNILND_TX_ALLOCD:
		/* no refs needed */
		break;
	case GNILND_TX_DYING:
		kgnilnd_conn_decref(conn);
		break;
	case GNILND_TX_FMAQ:
		kgnilnd_conn_decref(conn);
		break;
	case GNILND_TX_MAPQ:
		atomic_dec(&conn->gnc_device->gnd_nq_map);
		kgnilnd_conn_decref(conn);
		break;
	case GNILND_TX_LIVE_FMAQ:
		atomic_dec(&conn->gnc_nlive_fma);
		kgnilnd_conn_decref(conn);
		break;
	case GNILND_TX_LIVE_RDMAQ:
		atomic_dec(&conn->gnc_nlive_rdma);
		kgnilnd_conn_decref(conn);
		break;
	case GNILND_TX_RDMAQ:
		atomic_dec(&conn->gnc_nq_rdma);
		kgnilnd_conn_decref(conn);
	/* don't need to assert on default, already did in set */
	}

	/* for ALLOCD, this might already be true, but no harm doing it again */
	list_del_init(&tx->tx_list);
	tx->tx_list_p = NULL;
	tx->tx_list_state = new_state;
}

static inline int
kgnilnd_tx_mapped(kgn_tx_t *tx)
{
	return tx->tx_buftype == GNILND_BUF_PHYS_MAPPED;
}

static inline struct list_head *
kgnilnd_cqid2connlist(__u32 cqid)
{
	unsigned int hash = cqid % *kgnilnd_tunables.kgn_peer_hash_size;

	return (&kgnilnd_data.kgn_conns [hash]);
}

static inline kgn_conn_t *
kgnilnd_cqid2conn_locked(__u32 cqid)
{
	struct list_head *conns = kgnilnd_cqid2connlist(cqid);
	struct list_head *tmp;
	kgn_conn_t       *conn;

	list_for_each(tmp, conns) {
		conn = list_entry(tmp, kgn_conn_t, gnc_hashlist);

		if (conn->gnc_cqid == cqid)
			return conn;
	}

	return NULL;
}

/* returns 1..GNILND_MAX_CQID on success, 0 on failure */
static inline __u32
kgnilnd_get_cqid_locked(void)
{
	int     looped = 0;
	__u32   cqid;

	do {
		cqid = kgnilnd_data.kgn_next_cqid++;
		if (kgnilnd_data.kgn_next_cqid >= GNILND_MAX_CQID) {
			if (looped) {
				return 0;
			}
			kgnilnd_data.kgn_next_cqid = 1;
			looped = 1;
		}
	} while (kgnilnd_cqid2conn_locked(cqid) != NULL);

	return cqid;
}

static inline void
kgnilnd_validate_tx_ev_id(kgn_tx_ev_id_t *ev_id, kgn_tx_t **txp, kgn_conn_t **connp)
{
	kgn_tx_t        *tx = NULL;
	kgn_conn_t      *conn = NULL;

	/* set to NULL so any early return is an error */
	*txp = NULL;
	*connp = NULL;

	LASSERTF((ev_id->txe_idx > 0) &&
		 (ev_id->txe_idx < GNILND_MAX_MSG_ID),
		"bogus txe_idx %d >= %d\n",
		ev_id->txe_idx, GNILND_MAX_MSG_ID);

	LASSERTF((ev_id->txe_cqid > 0) &&
		 (ev_id->txe_cqid < GNILND_MAX_CQID),
		"bogus txe_cqid %d >= %d\n",
		ev_id->txe_cqid, GNILND_MAX_CQID);

	read_lock(&kgnilnd_data.kgn_peer_conn_lock);
	conn = kgnilnd_cqid2conn_locked(ev_id->txe_cqid);

	if (conn == NULL) {
		/* Conn was destroyed? */
		read_unlock(&kgnilnd_data.kgn_peer_conn_lock);
		CDEBUG(D_NET, "CQID %d lookup failed\n", ev_id->txe_cqid);
		return;
	}
	/* just insurance */
	kgnilnd_conn_addref(conn);
	kgnilnd_admin_addref(conn->gnc_tx_in_use);
	read_unlock(&kgnilnd_data.kgn_peer_conn_lock);

	/* we know this is safe - as the TX won't be reused until AFTER
	 * the conn is unlinked from the cqid hash, so we can use the TX
	 * (serializing to avoid any cache oddness) freely from the conn tx ref table */

	spin_lock(&conn->gnc_tx_lock);
	tx = conn->gnc_tx_ref_table[ev_id->txe_idx];
	spin_unlock(&conn->gnc_tx_lock);

	/* We could have a tx that was cleared out by other forces
	 * lctl disconnect or del_peer. */
	if (tx == NULL) {
		CNETERR("txe_idx %d is gone, ignoring event\n", ev_id->txe_idx);
		kgnilnd_admin_decref(conn->gnc_tx_in_use);
		kgnilnd_conn_decref(conn);
		return;
	}

	/* check tx->tx_msg magic to make sure kgni didn't eat it */
	GNITX_ASSERTF(tx, tx->tx_msg.gnm_magic == GNILND_MSG_MAGIC,
		      "came back from kgni with bad magic %x", tx->tx_msg.gnm_magic);

	GNITX_ASSERTF(tx, tx->tx_id.txe_idx == ev_id->txe_idx,
		      "conn 0x%p->%s tx_ref_table hosed: wanted txe_idx %d "
		      "found tx %p txe_idx %d",
		      conn, libcfs_nid2str(conn->gnc_peer->gnp_nid),
		      ev_id->txe_idx, tx, tx->tx_id.txe_idx);

	GNITX_ASSERTF(tx, tx->tx_conn != NULL, "tx with NULL connection", NULL);

	GNITX_ASSERTF(tx, tx->tx_conn == conn, "tx conn does not equal conn", NULL);

	*txp = tx;
	*connp = conn;

	GNIDBG_TX(D_NET, tx, "validated to 0x%p", conn);
}

/* set_normalized_timepsec isn't exported from the kernel, so
 * we need to do the same thing inline */
static inline struct timespec
kgnilnd_ts_sub(struct timespec lhs, struct timespec rhs)
{
	time_t                  sec;
	long                    nsec;
	struct timespec         ts;

	sec = lhs.tv_sec - rhs.tv_sec;
	nsec = lhs.tv_nsec - rhs.tv_nsec;

	while (nsec >= NSEC_PER_SEC) {
		nsec -= NSEC_PER_SEC;
		++sec;
	}
	while (nsec < 0) {
		nsec += NSEC_PER_SEC;
		--sec;
	}
	ts.tv_sec = sec;
	ts.tv_nsec = nsec;
	return ts;
}

static inline int
kgnilnd_count_list(struct list_head *q)
{
	struct list_head *e;
	int               n = 0;

	list_for_each(e, q) {
		n++;
	}

	return n;
}

/* kgnilnd_find_net adds a reference to the net it finds
 * this is so the net will not be removed before the calling function
 * has time to use the data returned. This reference needs to be released
 * by the calling function once it has finished using the returned net
 */

static inline int
kgnilnd_find_net(lnet_nid_t nid, kgn_net_t **netp)
{
	kgn_net_t *net;
	int rc;

	rc = down_read_trylock(&kgnilnd_data.kgn_net_rw_sem);

	if (!rc) {
		return -ESHUTDOWN;
	}

	list_for_each_entry(net, kgnilnd_netnum2netlist(LNET_NETNUM(LNET_NIDNET(nid))), gnn_list) {
		if (!net->gnn_shutdown && LNET_NIDNET(net->gnn_ni->ni_nid) == LNET_NIDNET(nid)) {
			kgnilnd_net_addref(net);
			up_read(&kgnilnd_data.kgn_net_rw_sem);
			*netp = net;
			return 0;
		}
	}

	up_read(&kgnilnd_data.kgn_net_rw_sem);

	return -ENONET;
}

#ifdef CONFIG_DEBUG_SLAB
#define KGNILND_POISON(ptr, c, s) do {} while(0)
#else
#define KGNILND_POISON(ptr, c, s) memset(ptr, c, s)
#endif

int kgnilnd_dev_init(kgn_device_t *dev);
void kgnilnd_dev_fini(kgn_device_t *dev);
int kgnilnd_startup(struct lnet_ni *ni);
void kgnilnd_shutdown(struct lnet_ni *ni);
int kgnilnd_base_startup(void);
void kgnilnd_base_shutdown(void);

int kgnilnd_allocate_phys_fmablk(kgn_device_t *device);
int kgnilnd_map_phys_fmablk(kgn_device_t *device);
void kgnilnd_unmap_fma_blocks(kgn_device_t *device);
void kgnilnd_free_phys_fmablk(kgn_device_t *device);

int kgnilnd_ctl(struct lnet_ni *ni, unsigned int cmd, void *arg);
int kgnilnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg);
int kgnilnd_eager_recv(struct lnet_ni *ni, void *private,
			struct lnet_msg *lntmsg, void **new_private);
int kgnilnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg,
		int delayed, unsigned int niov,
		struct bio_vec *kiov,
		unsigned int offset, unsigned int mlen, unsigned int rlen);

__u16 kgnilnd_cksum_kiov(unsigned int nkiov, struct bio_vec *kiov,
			 unsigned int offset, unsigned int nob, int dump_blob);

/* purgatory functions */
void kgnilnd_add_purgatory_locked(kgn_conn_t *conn, kgn_peer_t *peer);
void kgnilnd_mark_for_detach_purgatory_all_locked(kgn_peer_t *peer);
void kgnilnd_detach_purgatory_locked(kgn_conn_t *conn, struct list_head *conn_list);
void kgnilnd_release_purgatory_list(struct list_head *conn_list);

void kgnilnd_update_reaper_timeout(long timeout);
void kgnilnd_unmap_buffer(kgn_tx_t *tx, int error);
kgn_tx_t *kgnilnd_new_tx_msg(int type, lnet_nid_t source);
void kgnilnd_tx_done(kgn_tx_t *tx, int completion);
void kgnilnd_txlist_done(struct list_head *txlist, int error);
void kgnilnd_unlink_peer_locked(kgn_peer_t *peer);
int _kgnilnd_schedule_conn(kgn_conn_t *conn, const char *caller, int line, int refheld, int lock_held);
int kgnilnd_schedule_process_conn(kgn_conn_t *conn, int sched_intent);

void kgnilnd_schedule_dgram(kgn_device_t *dev);
int kgnilnd_create_peer_safe(kgn_peer_t **peerp, lnet_nid_t nid, kgn_net_t *net, int node_state);
void kgnilnd_add_peer_locked(lnet_nid_t nid, kgn_peer_t *new_stub_peer, kgn_peer_t **peerp);
int kgnilnd_add_peer(kgn_net_t *net, lnet_nid_t nid, kgn_peer_t **peerp);

kgn_peer_t *kgnilnd_find_peer_locked(lnet_nid_t nid);
int kgnilnd_del_conn_or_peer(kgn_net_t *net, lnet_nid_t nid, int command, int error);
void kgnilnd_peer_increase_reconnect_locked(kgn_peer_t *peer);
void kgnilnd_queue_reply(kgn_conn_t *conn, kgn_tx_t *tx);
void kgnilnd_queue_tx(kgn_conn_t *conn, kgn_tx_t *tx);
void kgnilnd_launch_tx(kgn_tx_t *tx, kgn_net_t *net, struct lnet_process_id *target);
int kgnilnd_send_mapped_tx(kgn_tx_t *tx, int try_map_if_full);
void kgnilnd_consume_rx(kgn_rx_t *rx);

void kgnilnd_schedule_device(kgn_device_t *dev);
void kgnilnd_device_callback(__u32 devid, __u64 arg);
void kgnilnd_schedule_device_timer(cfs_timer_cb_arg_t data);
void kgnilnd_schedule_device_timer_rd(cfs_timer_cb_arg_t data);

int kgnilnd_reaper(void *arg);
int kgnilnd_scheduler(void *arg);
int kgnilnd_dgram_mover(void *arg);
int kgnilnd_rca(void *arg);
int kgnilnd_thread_start(int(*fn)(void *arg), void *arg, char *name, int id);

int kgnilnd_create_conn(kgn_conn_t **connp, kgn_device_t *dev);
int kgnilnd_conn_isdup_locked(kgn_peer_t *peer, kgn_conn_t *newconn);
kgn_conn_t *kgnilnd_find_conn_locked(kgn_peer_t *peer);
int kgnilnd_get_conn(kgn_conn_t **connp, kgn_peer_t);
kgn_conn_t *kgnilnd_find_or_create_conn_locked(kgn_peer_t *peer);
void kgnilnd_peer_cancel_tx_queue(kgn_peer_t *peer);
void kgnilnd_cancel_peer_connect_locked(kgn_peer_t *peer, struct list_head *zombies);
int kgnilnd_close_stale_conns_locked(kgn_peer_t *peer, kgn_conn_t *newconn);
void kgnilnd_peer_alive(kgn_peer_t *peer);
void kgnilnd_peer_notify(kgn_peer_t *peer, int error, int alive);
void kgnilnd_close_conn_locked(kgn_conn_t *conn, int error);
void kgnilnd_close_conn(kgn_conn_t *conn, int error);
void kgnilnd_complete_closed_conn(kgn_conn_t *conn);
void kgnilnd_destroy_conn_ep(kgn_conn_t *conn);

int kgnilnd_close_peer_conns_locked(kgn_peer_t *peer, int why);
int kgnilnd_report_node_state(lnet_nid_t nid, int down);
void kgnilnd_wakeup_rca_thread(void);
int kgnilnd_start_rca_thread(void);
int kgnilnd_get_node_state(__u32 nid);

int kgnilnd_tunables_init(void);
void kgnilnd_init_msg(kgn_msg_t *msg, int type, lnet_nid_t source);

void kgnilnd_bump_timeouts(__u32 nap_time, char *reason);
void kgnilnd_pause_threads(void);
int kgnilnd_hw_in_quiesce(void);
int kgnilnd_check_hw_quiesce(void);
void kgnilnd_quiesce_wait(char *reason);
void kgnilnd_quiesce_end_callback(gni_nic_handle_t nic_handle, uint64_t msecs);
int kgnilnd_ruhroh_thread(void *arg);
void kgnilnd_reset_stack(void);
void kgnilnd_critical_error(gni_err_handle_t err_handle);

void kgnilnd_insert_sysctl(void);
void kgnilnd_remove_sysctl(void);
void kgnilnd_proc_init(void);
void kgnilnd_proc_fini(void);

/* gnilnd_conn.c */
void kgnilnd_release_mbox(kgn_conn_t *conn, int purgatory_hold);

int kgnilnd_find_and_cancel_dgram(kgn_device_t *dev, lnet_nid_t dst_nid);
void kgnilnd_cancel_dgram_locked(kgn_dgram_t *dgram);
void kgnilnd_release_dgram(kgn_device_t *dev, kgn_dgram_t *dgram, int shutdown);

int kgnilnd_setup_wildcard_dgram(kgn_device_t *dev);
int kgnilnd_cancel_net_dgrams(kgn_net_t *net);
int kgnilnd_cancel_wc_dgrams(kgn_device_t *dev);
int kgnilnd_cancel_dgrams(kgn_device_t *dev);
void kgnilnd_wait_for_canceled_dgrams(kgn_device_t *dev);

int kgnilnd_dgram_waitq(void *arg);

int kgnilnd_set_conn_params(kgn_dgram_t *dgram);

/* struct2str functions - we don't use a default: case to cause the compile
 * to fail if there is a missing case. This allows us to hide these down here
 * out of the way but ensure we'll catch any updates to the enum/types
 * above */

#define DO_TYPE(x) case x: return #x;
static inline const char *
kgnilnd_fmablk_state2str(kgn_fmablk_state_t state)
{
	/* Only want single char string for this */
	switch (state) {
	case GNILND_FMABLK_IDLE:
		return "I";
	case GNILND_FMABLK_PHYS:
		return "P";
	case GNILND_FMABLK_VIRT:
		return "V";
	case GNILND_FMABLK_FREED:
		return "F";
	}
	return "<unknown state>";
}

static inline const char *
kgnilnd_msgtype2str(int type)
{
	switch (type) {
		DO_TYPE(GNILND_MSG_NONE);
		DO_TYPE(GNILND_MSG_NOOP);
		DO_TYPE(GNILND_MSG_IMMEDIATE);
		DO_TYPE(GNILND_MSG_PUT_REQ);
		DO_TYPE(GNILND_MSG_PUT_NAK);
		DO_TYPE(GNILND_MSG_PUT_ACK);
		DO_TYPE(GNILND_MSG_PUT_DONE);
		DO_TYPE(GNILND_MSG_GET_REQ);
		DO_TYPE(GNILND_MSG_GET_NAK);
		DO_TYPE(GNILND_MSG_GET_DONE);
		DO_TYPE(GNILND_MSG_CLOSE);
		DO_TYPE(GNILND_MSG_PUT_REQ_REV);
		DO_TYPE(GNILND_MSG_PUT_DONE_REV);
		DO_TYPE(GNILND_MSG_PUT_NAK_REV);
		DO_TYPE(GNILND_MSG_GET_REQ_REV);
		DO_TYPE(GNILND_MSG_GET_ACK_REV);
		DO_TYPE(GNILND_MSG_GET_DONE_REV);
		DO_TYPE(GNILND_MSG_GET_NAK_REV);
	}
	return "<unknown msg type>";
}

static inline const char *
kgnilnd_tx_state2str(kgn_tx_list_state_t state)
{
	switch (state) {
		DO_TYPE(GNILND_TX_IDLE);
		DO_TYPE(GNILND_TX_ALLOCD);
		DO_TYPE(GNILND_TX_PEERQ);
		DO_TYPE(GNILND_TX_MAPQ);
		DO_TYPE(GNILND_TX_FMAQ);
		DO_TYPE(GNILND_TX_LIVE_FMAQ);
		DO_TYPE(GNILND_TX_RDMAQ);
		DO_TYPE(GNILND_TX_LIVE_RDMAQ);
		DO_TYPE(GNILND_TX_DYING);
		DO_TYPE(GNILND_TX_FREED);
	}
	return "<unknown state>";
}

static inline const char *
kgnilnd_conn_state2str(kgn_conn_t *conn)
{
	kgn_conn_state_t state = conn->gnc_state;
	switch (state) {
		DO_TYPE(GNILND_CONN_DUMMY);
		DO_TYPE(GNILND_CONN_LISTEN);
		DO_TYPE(GNILND_CONN_CONNECTING);
		DO_TYPE(GNILND_CONN_ESTABLISHED);
		DO_TYPE(GNILND_CONN_CLOSING);
		DO_TYPE(GNILND_CONN_CLOSED);
		DO_TYPE(GNILND_CONN_DONE);
		DO_TYPE(GNILND_CONN_DESTROY_EP);
	}
	return "<?state?>";
}

static inline const char *
kgnilnd_connreq_type2str(kgn_connreq_t *connreq)
{
	kgn_connreq_type_t type = connreq->gncr_type;

	switch (type) {
		DO_TYPE(GNILND_CONNREQ_REQ);
		DO_TYPE(GNILND_CONNREQ_NAK);
		DO_TYPE(GNILND_CONNREQ_CLOSE);
	}
	return "<?type?>";
}

static inline const char *
kgnilnd_dgram_state2str(kgn_dgram_t *dgram)
{
	kgn_dgram_state_t state = dgram->gndg_state;

	switch (state) {
		DO_TYPE(GNILND_DGRAM_USED);
		DO_TYPE(GNILND_DGRAM_POSTING);
		DO_TYPE(GNILND_DGRAM_POSTED);
		DO_TYPE(GNILND_DGRAM_PROCESSING);
		DO_TYPE(GNILND_DGRAM_DONE);
		DO_TYPE(GNILND_DGRAM_CANCELED);
	}
	return "<?state?>";
}

static inline const char *
kgnilnd_dgram_type2str(kgn_dgram_t *dgram)
{
	kgn_dgram_type_t type = dgram->gndg_type;

	switch (type) {
		DO_TYPE(GNILND_DGRAM_REQ);
		DO_TYPE(GNILND_DGRAM_WC_REQ);
		DO_TYPE(GNILND_DGRAM_NAK);
		DO_TYPE(GNILND_DGRAM_CLOSE);
	}
	return "<?type?>";
}

static inline const char *
kgnilnd_conn_dgram_type2str(kgn_dgram_type_t type)
{
	switch (type) {
		DO_TYPE(GNILND_DGRAM_REQ);
		DO_TYPE(GNILND_DGRAM_WC_REQ);
		DO_TYPE(GNILND_DGRAM_NAK);
		DO_TYPE(GNILND_DGRAM_CLOSE);
	}
	return "<?type?>";
}

#undef DO_TYPE

/* pulls in tunables per platform and adds in nid/nic conversion
 * if RCA wasn't available at build time */
#include "gnilnd_hss_ops.h"
/* API wrapper functions - include late to pick up all of the other defines */
#include "gnilnd_api_wrap.h"

#if defined(CONFIG_CRAY_GEMINI)
 #include "gnilnd_gemini.h"
#elif defined(CONFIG_CRAY_ARIES)
 #include "gnilnd_aries.h"
#else
 #error "Undefined Network Hardware Type"
#endif

extern uint32_t kgni_driver_version;

static inline void
kgnilnd_check_kgni_version(void)
{
	uint32_t *kdv;

	kgnilnd_data.kgn_enable_gl_mutex = 1;
	kdv = symbol_get(kgni_driver_version);
	if (!kdv) {
		LCONSOLE_INFO("Not using thread safe locking -"
			" no symbol kgni_driver_version\n");
		return;
	}

	/* Thread-safe kgni implemented in minor ver 0x44/45, code rev 0xb9 */
	if (*kdv < GNI_VERSION_CHECK(0, GNILND_KGNI_TS_MINOR_VER, 0xb9)) {
		symbol_put(kgni_driver_version);
		LCONSOLE_INFO("Not using thread safe locking, gni version 0x%x,"
			" need >= 0x%x\n", *kdv,
			GNI_VERSION_CHECK(0, GNILND_KGNI_TS_MINOR_VER, 0xb9));
		return;
	}

	symbol_put(kgni_driver_version);

	if (!*kgnilnd_tunables.kgn_thread_safe) {
		return;
	}

	/* Use thread-safe locking */
	kgnilnd_data.kgn_enable_gl_mutex = 0;
}

#endif /* _GNILND_GNILND_H_ */
