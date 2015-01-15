/* -*- c-basic-offset: 8; indent-tabs-mode: nil -*- */
/*
	Contains the user interface to the GNI. Kernel and User level.

	Copyright 2007 Cray Inc. All Rights Reserved.
	Written by Igor Gorodetsky <igorodet@cray.com>

	This program is free software; you can redistribute it and/or modify it
	under the terms of the GNU General Public License as published by the
	Free Software Foundation; either version 2 of the License,
	or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
	See the GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software Foundation, Inc.,
	51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
*/

#ifndef _GNI_PUB_H_
#define _GNI_PUB_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef __KERNEL__
#include <stdint.h>
#endif

/* Common definitions for the kernel and the user level */

/**
 * GNI version control macros and values
 * Example: 0x00400080
 */
/* Reflects major releases of GNI SW stack (e.g. support for new HW) */
#define GNI_MAJOR_REV 0x00
/* Reflects any uGNI API changes */
#define GNI_MINOR_REV 0x5c
/* Reflects any uGNI library code changes */
#define GNI_CODE_REV  0x0000

#define GNI_GET_MAJOR(value) ((value >> 24) & 0xFF)
#define GNI_GET_MINOR(value) ((value >> 16) & 0xFF)
#define GNI_GET_REV(value) (value & 0xFFFF)
#define GNI_VERSION ((GNI_MAJOR_REV << 24) | (GNI_MINOR_REV << 16) | GNI_CODE_REV)
#define GNI_VERSION_CHECK(maj,min,code) (((maj) << 24) | ((min) << 16) | code)

/* Definitions of base versions where uGNI features are introduced */
#define GNI_VERSION_FMA_SHARING  0x5b0000

/* Specifies input and output arguments to GNI functions */
#define IN
#define OUT
#define INOUT

/* Reserved PTAGs.
   kernel apps: values  < GNI_PTAG_USER_START,
   user apps: GNI_PTAG_USER_START <= values <= GNI_PTAG_USER_END
   HSN boot: value = GNI_PTAG_MAX

   GNI_PTAG_* values were designed for use on Gemini systems.  User
   applications run on an Aries system should always use a PTAG value of
   'GNI_FIND_ALLOC_PTAG' to allow the driver to automatically allocate a valid
   protection tag.
*/
enum {
	GNI_PTAG_LND = 1,
	GNI_PTAG_OFED,
	GNI_PTAG_USER_START,
	GNI_PTAG_LND_KNC = 128,
	GNI_PTAG_USER_END = 253,
	GNI_PTAG_HSNBOOT = 254,
	GNI_PTAG_MAX = 254,
	GNI_PTAG_LB = 255
};

#define GNI_FIND_ALLOC_PTAG GNI_PTAG_LB

/* Reserved PKEYs.
   kernel apps: values  < GNI_PKEY_USER_START,
   user apps: GNI_PTAG_USER_START <= values <= GNI_PKEY_USER_END
   HSN boot: value = GNI_PKEY_MAX */
enum {
	GNI_PKEY_INVALID = 0,
	GNI_PKEY_LND = 1,
	GNI_PKEY_OFED,
	GNI_PKEY_USER_START = 128,
	GNI_PKEY_USER_END = 65407,
	GNI_PKEY_HSNBOOT = 65408,
	GNI_PKEY_MAX = 65534,
	GNI_PKEY_LB = 65535
};


#define GNI_COOKIE_PKEY_MASK           0xFFFF
#define GNI_COOKIE_PKEY_SHIFT          16
#define GNI_COOKIE_CBPS_MDD_MASK       0x7
#define GNI_COOKIE_CBPS_MDD_SHIFT      3
/* Macro to define COOKIE val (most useful to Aries).
 * cbps_mdd should be set at zero for now */
#define GNI_JOB_CREATE_COOKIE(pkey, cbps_mdd) (((uint32_t)(pkey) << GNI_COOKIE_PKEY_SHIFT) | (((cbps_mdd) & GNI_COOKIE_CBPS_MDD_MASK) << GNI_COOKIE_CBPS_MDD_SHIFT))

/* Registered memory handle */
typedef struct gni_mem_handle {
	uint64_t        qword1;
	uint64_t        qword2;
} gni_mem_handle_t;

typedef enum gni_mem_handle_attr {
	GNI_MEMHNDL_ATTR_READONLY = 1,
	GNI_MEMHNDL_ATTR_VMDH,
	GNI_MEMHNDL_ATTR_MRT,
	GNI_MEMHNDL_ATTR_GART,
	GNI_MEMHNDL_ATTR_IOMMU,
	GNI_MEMHNDL_ATTR_PCI_IOMMU,
	GNI_MEMHNDL_ATTR_CLONE
} gni_mem_handle_attr_t;

/* Opaque handles */
typedef struct gni_nic  *gni_nic_handle_t;
typedef struct gni_cdm  *gni_cdm_handle_t;
typedef struct gni_ep   *gni_ep_handle_t;
typedef struct gni_cq   *gni_cq_handle_t;
typedef struct gni_err  *gni_err_handle_t;
typedef struct gni_msgq *gni_msgq_handle_t;
typedef struct gni_ce   *gni_ce_handle_t;

/* Short messaging types */
typedef enum gni_smsg_type {
	GNI_SMSG_TYPE_INVALID = 0,
	GNI_SMSG_TYPE_MBOX,
	GNI_SMSG_TYPE_MBOX_AUTO_RETRANSMIT
} gni_smsg_type_t;

#define GNI_SMSG_ANY_TAG 0xFF

/* Short messaging attributes */
typedef struct gni_smsg_attr {
	gni_smsg_type_t         msg_type;
	void                    *msg_buffer;
	uint32_t                buff_size;
	gni_mem_handle_t        mem_hndl;
	uint32_t                mbox_offset;
	uint16_t                mbox_maxcredit;
	uint32_t                msg_maxsize;
} gni_smsg_attr_t;

/* Maximum SMSG retransmit count default values */

#define FMA_SMSG_MAX_RETRANS_DEFAULT    10

/* Return codes */
typedef enum gni_return {
	GNI_RC_SUCCESS = 0,
	GNI_RC_NOT_DONE,
	GNI_RC_INVALID_PARAM,
	GNI_RC_ERROR_RESOURCE,
	GNI_RC_TIMEOUT,
	GNI_RC_PERMISSION_ERROR,
	GNI_RC_DESCRIPTOR_ERROR,
	GNI_RC_ALIGNMENT_ERROR,
	GNI_RC_INVALID_STATE,
	GNI_RC_NO_MATCH,
	GNI_RC_SIZE_ERROR,
	GNI_RC_TRANSACTION_ERROR,
	GNI_RC_ILLEGAL_OP,
	GNI_RC_ERROR_NOMEM
} gni_return_t;

/* Communication domain modes */
#define GNI_CDM_MODE_FORK_NOCOPY        0x00000001
#define GNI_CDM_MODE_FORK_FULLCOPY      0x00000002
#define GNI_CDM_MODE_FORK_PARTCOPY      0x00000004 /* default */
/* Do not kill the application for any type of error. For instance, when debugging. */
#define GNI_CDM_MODE_ERR_NO_KILL        0x00000008
/* Kill the application for any TRANSACTION errors. By default only a
 * subset will kill an application. The rest of the errors should be
 * reported through the CQ. Using this mode an application can request
 * being killed for all errors.
 */
#define GNI_CDM_MODE_ERR_ALL_KILL       0x00000010
/* Enable fast polling for GNI_EpPostDataTest,GNI_EpPostDataTestById
 * and GNI_PostDataProbe/GNI_PostDataProbeById.  Using this option may
 * result in loss of intermediate state information for datagram
 * transactions.
 */
#define GNI_CDM_MODE_FAST_DATAGRAM_POLL 0x00000020
/* Enable transmitting RDMA posts through one BTE channel, instead of
 * defaulting to using all three channels. This may be preferred for
 * some applications.
 */
#define GNI_CDM_MODE_BTE_SINGLE_CHANNEL 0x00000040
/* User space may specify PCI_IOMMU to be used for all memory
 * transactions. Setting this will always attempt to use the root
 * complex's address translation in the PCI bridge. If this can not be
 * enabled, but is requested, all memory registrations will error.
 */
#define GNI_CDM_MODE_USE_PCI_IOMMU      0x00000080
/* By default, newly created CDM's will allocate out of a shared MDD
 * pool. This pool is only shared within a protection domain. In an
 * IOMMU environment, there is more address space than MDDs available,
 * so this allows many more MDDs than normal. If the application
 * desires dedicated MDDs by default, then the CDM mode exists for
 * that. The shared mode flag is for convenience when the feature is
 * disabled during initial implementation stages.
 */
#define GNI_CDM_MODE_MDD_DEDICATED      0x00000100
#define GNI_CDM_MODE_MDD_SHARED         0x00000200
/* By default, users may post transactions with either local or global completion
 * notification, not both.  If receipt of both local and global events is requested
 * users must set DUAL_EVENTS.  Performing a post operation with local and global
 * events enabled without DUAL_EVENTS set will yield an error GNI_RC_INVALID_PARAM.
 *
 * In addition, during an EpBind in default mode, transfer requests are allocated
 * equal in size to the number of events in the associated source CQ.  When
 * DUAL_EVENTS is set transfer requests are allocated 1 per 2 CQ event slots.
 * Therefore, a user is limited to posting half as many transactions as CQ events
 * when DUAL_EVENTS is set.  Exceeding this limit will yield an error
 * GNI_RC_ERROR_RESOURCE.
 */
#define GNI_CDM_MODE_DUAL_EVENTS        0x00001000

/* This mode alters the FMA_SHARED behavior wrt. DLA */
#define GNI_CDM_MODE_DLA_ENABLE_FORWARDING   0x00004000
#define GNI_CDM_MODE_DLA_DISABLE_FORWARDING  0x00008000
/* By default, newly created CDM's are assigned a dedicated FMA descriptor.  If
 * no FMA descriptors are available during the creation of a dedicated FMA CDM,
 * the operation will fail.  The FMA_SHARED CDM flag allows applications to
 * share FMA descriptors between (CDM's) within a protection domain.  This
 * enables a user to allocate more CDM's than there are FMA descriptors on a
 * node. */
#define GNI_CDM_MODE_FMA_DEDICATED      0x00010000
#define GNI_CDM_MODE_FMA_SHARED         0x00020000
/* This mode enables the use of cached AMO operations */
#define GNI_CDM_MODE_CACHED_AMO_ENABLED 0x00040000
/* This CDM flag allows applications to request placing the CQs in
 * host memory closest to the NIC. This currently means on die0, but
 * could mean a different die in the future. This increases small
 * message injection rate for some applications.
 */
#define GNI_CDM_MODE_CQ_NIC_LOCAL_PLACEMENT 0x00080000
#define GNI_CDM_MODE_FLBTE_DISABLE          0x00100000
/* Prevent mapping the entire FMA window into a process's address space.
 * Making the FMA window smaller reduces a process's memory footprint and
 * initialization overhead.  FMA throughput will be unnaffected while using
 * this mode with FMA transactions under the size configured in the file:
 * /sys/class/gni/kgni0/fma_sm_win_sz (32k by default, cache-aligned). */
#define GNI_CDM_MODE_FMA_SMALL_WINDOW       0x00200000

#define GNI_CDM_MODE_MASK                   0x0FFFFFFF

/* Upper 4 CDM mode bits are reserved for internal ugni/dmapp usage. */
#define GNI_CDM_MODE_PRIV_RESERVED_1        0x10000000
#define GNI_CDM_MODE_PRIV_RESERVED_2        0x20000000
#define GNI_CDM_MODE_PRIV_RESERVED_3        0x40000000
#define GNI_CDM_MODE_PRIV_RESERVED_4        0x80000000
#define GNI_CDM_MODE_PRIV_MASK              0xF0000000

/* Endpoint machine state */
typedef enum gni_post_state{
	GNI_POST_PENDING,
	GNI_POST_COMPLETED,
	GNI_POST_ERROR,
	GNI_POST_TIMEOUT,
	GNI_POST_TERMINATED,
	GNI_POST_REMOTE_DATA
} gni_post_state_t;

/* The memory attributes associated with the region.*/
#define GNI_MEM_READWRITE               0x00000000
#define GNI_MEM_READ_ONLY               0x00000001
/* Directive to use Virtual MDH while registering this memory region. (user level)*/
#define GNI_MEM_USE_VMDH                0x00000002
/* Directive to use GART while registering the memory region */
#define GNI_MEM_USE_GART                0x00000004
/* Directive not to use GART or MRT as memory is physically contiguous */
#define GNI_MEM_PHYS_CONT               0x00000008
/* Valid only for gni_mem_register_segments(): segments are 4KB each, described by phys. addresses */
#define GNI_MEM_PHYS_SEGMENTS           0x00000010
/* Instruct NIC to enforce strict PI ordering.  On Gemini based platforms, this
   flag disables the HT "Non-Posted Pass Posted Writes" rule.  On Aries based
   platforms, this flag disables routing mode (GNI_DLVMODE_*) based ordering
   for received network requests and responses. */
#define GNI_MEM_STRICT_PI_ORDERING      0x00000020
/* Instruct NIC to issue PI (Processor Interface, e.g. HT) FLUSH command prior
   to sending network responses for the region */
#define GNI_MEM_PI_FLUSH                0x00000040
#define GNI_MEM_MDD_CLONE               0x00000080
/* Instruct NIC to allow relaxed PI ordering.  On Gemini based platforms, this
   flag enables reordering of Non-Posted and Posted write requests into the
   processor by enabling both "Non-Posted Pass Posted Writes" and "Posted Pass
   Posted Writes" rules.  ("Non-Posted Pass Posted Writes" rule is enabled by
   default.)  On Aries based platforms, this flag enables reordering of
   requests not originated in the network.  Note: this flag is overridden by
   the GNI_MEM_STRICT_PI_ORDERING flag. */
#define GNI_MEM_RELAXED_PI_ORDERING     0x00000100
/* Only reserve the PTE range for this block of memory. */
#define GNI_MEM_RESERVE_REGION          0x00000200
/* Update the PTE range for the provided block of memory. The first
 * call with this flag will make MDH live. The application may receive
 * page faults if they don't call update region before sending to an
 * address. This will only fill in new pages, and compare old pages to
 * make sure there aren't any changes. */
#define GNI_MEM_UPDATE_REGION           0x00000400
/* Tell the driver to force this memory to be shared, despite default
 * CDM_MODE flag. If it is shared, then it will go into a pool of MDDs
 * shared with the same PTAGs. */
#define GNI_MEM_MDD_SHARED              0x00000800
/* Tell the driver to force this memory to be dedicated, despite
 * default CDM_MODE flag/kernel flags. If it is dedicated, then it
 * will operate like the old MDDs did, and be subject to the same
 * limits. */
#define GNI_MEM_MDD_DEDICATED           0x00001000
/* Directive that the memory region is GPU-resident memory. */
#define GNI_MEM_CUDA                    0x01000000              /* Cuda device memory */

/* External memory, or resident memory in other PCI devices. These are
 * helper macros, as the different types of external memory have bits
 * assigned to them via the above memory flags */
#define GNI_EXMEM_FLAGS(flag)           ((flag) >> 24)          /* Isolate exmem type */
#define GNI_MEM_IS_EXTERNAL(flag)       (GNI_EXMEM_FLAGS(flag))

typedef struct gni_mem_segment {
	uint64_t        address; /* address of the segment */
	uint64_t        length;  /* size of the segment in bytes */
} gni_mem_segment_t;

/* CQ modes/attributes of operation */
typedef uint32_t gni_cq_mode_t;

/* The CQ will be created with blocking disabled. */
#define GNI_CQ_NOBLOCK          0x00000000
/* The CQ will be created with blocking enabled. */
#define GNI_CQ_BLOCKING         0x00000001
/* the EMULATED mode is reserved for internal uGNI use only. */
#define GNI_CQ_EMULATED         0x00000002
/* EMULATED mode cannot be created with blocking enabled. */
#define GNI_CQ_EMULATED_INVALID (GNI_CQ_EMULATED | GNI_CQ_BLOCKING)
/* use physical pages when creating the CQ, by default memory mapped space is used.  */
#define GNI_CQ_PHYS_PAGES       0x00000004
/* This is a "dummy CQ", as in, the CQ will never be checked for
 * events. It acts like a sink to avoid errors on the sender CQ for
 * instances where a remote event is needed. */
#define GNI_CQ_UNMANAGED        0x00000008

#define GNI_CQ_IS_NON_BLOCKING(modes)     ((modes & GNI_CQ_BLOCKING) == GNI_CQ_NOBLOCK)
#define GNI_CQ_IS_BLOCKING(modes)         ((modes & GNI_CQ_BLOCKING) == GNI_CQ_BLOCKING)
#define GNI_CQ_IS_EMULATED(modes)         ((modes & GNI_CQ_EMULATED) == GNI_CQ_EMULATED)
#define GNI_CQ_IS_NOT_EMULATED(modes)     ((modes & GNI_CQ_EMULATED) == 0)
#define GNI_CQ_IS_INVALID_EMULATED(modes) ((modes & GNI_CQ_EMULATED_INVALID) == GNI_CQ_EMULATED_INVALID)
#define GNI_CQ_USE_PHYS_PAGES(modes)      ((modes & GNI_CQ_PHYS_PAGES) == GNI_CQ_PHYS_PAGES)

/* Macros and enum for processing data component of CQEs associated with
   PostRDMA, PostFma, Short message transactions */

/* Completion queue entry (size of type field is 2 bits) */
#define GNI_CQ_EVENT_TYPE_POST  0x0ULL
#define GNI_CQ_EVENT_TYPE_SMSG  0x1ULL
#define GNI_CQ_EVENT_TYPE_DMAPP 0x2ULL
#define GNI_CQ_EVENT_TYPE_MSGQ  0x3ULL
typedef uint64_t gni_cq_entry_t;

#ifndef GNI_INLINE_CQ_FUNCTIONS
uint64_t gni_cq_get_data(gni_cq_entry_t);
uint64_t gni_cq_get_source(gni_cq_entry_t);
uint64_t gni_cq_get_status(gni_cq_entry_t);
uint64_t gni_cq_get_info(gni_cq_entry_t);
uint64_t gni_cq_overrun(gni_cq_entry_t);
uint64_t gni_cq_rem_overrun(gni_cq_entry_t);
uint64_t gni_cq_get_inst_id(gni_cq_entry_t);
uint64_t gni_cq_get_rem_inst_id(gni_cq_entry_t);
uint64_t gni_cq_get_tid(gni_cq_entry_t);
uint64_t gni_cq_get_msg_id(gni_cq_entry_t);
uint64_t gni_cq_get_type(gni_cq_entry_t);
uint64_t gni_cq_get_block_id(gni_cq_entry_t);
uint64_t gni_cq_get_unsuccessful_cnt(gni_cq_entry_t);
uint64_t gni_cq_get_marker_id(gni_cq_entry_t);
uint64_t gni_cq_get_failed_enqueue_cnt(gni_cq_entry_t);
uint64_t gni_cq_get_ce_id(gni_cq_entry_t);
uint64_t gni_cq_get_reductn_id(gni_cq_entry_t);
uint64_t gni_cq_get_trans_type(gni_cq_entry_t);
void     gni_cq_set_inst_id(gni_cq_entry_t *,uint64_t);
void     gni_cq_set_rem_inst_id(gni_cq_entry_t *,uint64_t);
void     gni_cq_set_tid(gni_cq_entry_t *,uint64_t);
void     gni_cq_set_msg_id(gni_cq_entry_t *,uint64_t);
void     gni_cq_set_type(gni_cq_entry_t *,uint64_t);
void     gni_cq_clr_status(gni_cq_entry_t *);
unsigned gni_cq_status_dla_overflow(gni_cq_entry_t);
unsigned gni_cq_bte_enq_status(gni_cq_entry_t);
#endif /* GNI_INLINE_CQ_FUNCTIONS */

#define GNI_CQ_GET_DATA    gni_cq_get_data
#define GNI_CQ_GET_SOURCE  gni_cq_get_source
#define GNI_CQ_GET_STATUS  gni_cq_get_status
#define GNI_CQ_GET_INFO    gni_cq_get_info
/*
 * GNI_CQ_GET_INST_ID will allow a user to query an event
 * to get the inst_id value associated with it.
 * On a Gemini interconnect, this will be a 32 bit value.
 * On an Aries interconnect, this will be a 24 bit value.
 */
#define GNI_CQ_GET_INST_ID gni_cq_get_inst_id
/*
 * GNI_CQ_GET_REM_INST_ID will allow a user to query a remote event
 * to get the 32 bit remote inst_id value associated with it.
 */
#define GNI_CQ_GET_REM_INST_ID gni_cq_get_rem_inst_id
#define GNI_CQ_GET_TID     gni_cq_get_tid
#define GNI_CQ_GET_MSG_ID  gni_cq_get_msg_id
#define GNI_CQ_GET_TYPE    gni_cq_get_type
#define GNI_CQ_OVERRUN     gni_cq_overrun
#define GNI_CQ_REM_OVERRUN gni_cq_rem_overrun
#define GNI_CQ_GET_BLOCK_ID           gni_cq_get_block_id
#define GNI_CQ_GET_UNSUCCESSFUL_CNT   gni_cq_get_unsuccessful_cnt
#define GNI_CQ_GET_MARKER_ID          gni_cq_get_marker_id
#define GNI_CQ_GET_FAILED_ENQUEUE_CNT gni_cq_get_failed_enqueue_cnt
#define GNI_CQ_GET_CE_ID              gni_cq_get_ce_id
#define GNI_CQ_GET_REDUCTN_ID         gni_cq_get_reductn_id
#define GNI_CQ_GET_TRANS_TYPE         gni_cq_get_trans_type
/*
 * GNI_CQ_SET_INST_ID will allow a user to set the inst_id
 * value for an event.
 * On a Gemini interconnect, this will be a 32 bit value.
 * On an Aries interconnect, this will be truncated to a 24 bit value.
 */
#define GNI_CQ_SET_INST_ID(entry,val) gni_cq_set_inst_id(&(entry),val)
/*
 * GNI_CQ_SET_REM_INST_ID will allow a user to set a 32 bit remote
 * inst_id value for an remote event.
 */
#define GNI_CQ_SET_REM_INST_ID(entry,val) gni_cq_set_rem_inst_id(&(entry),val)
#define GNI_CQ_SET_TID(entry,val)     gni_cq_set_tid(&(entry),val)
#define GNI_CQ_SET_MSG_ID(entry,val)  gni_cq_set_msg_id(&(entry),val)
#define GNI_CQ_SET_TYPE(entry,val)    gni_cq_set_type(&(entry),val)
#define GNI_CQ_CLR_STATUS(entry)      gni_cq_clr_status(&(entry))
#define GNI_CQ_STATUS_OK(entry)      (gni_cq_get_status(entry) == 0)
#define GNI_CQ_STATUS_DLA_OVERFLOW(entry)   (gni_cq_status_dla_overflow(entry))
#define GNI_CQ_BTE_ENQ_STATUS(entry)  gni_cq_bte_enq_status(entry)

/* Transaction types (for type field of post descriptor) */
typedef enum gni_post_type {
	GNI_POST_RDMA_PUT = 1,
	GNI_POST_RDMA_GET,
	GNI_POST_FMA_PUT,
	GNI_POST_FMA_PUT_W_SYNCFLAG,
	GNI_POST_FMA_GET,
	GNI_POST_AMO,
	GNI_POST_CQWRITE,
	GNI_POST_CE,
	GNI_POST_FMA_GET_W_FLAG,
	GNI_POST_AMO_W_FLAG
} gni_post_type_t;

/* FMA Get or Fetching AMO Flagged Response */
#define GNI_FMA_FLAGGED_RESPONSE_SIZE   4     /* size in bytes */

/* FMA command types (for amo_cmd field of post descriptor) */
typedef enum gni_fma_cmd_type {
	/************ AMOs with GET semantics **************/
	GNI_FMA_ATOMIC_FADD    = 0x008,    /* atomic FETCH and ADD */
	GNI_FMA_ATOMIC_FADD_C  = 0x018,    /* cached atomic FETCH and ADD */
	GNI_FMA_ATOMIC_FAND    = 0x009,    /* atomic FETCH and AND */
	GNI_FMA_ATOMIC_FAND_C  = 0x019,    /* cached atomic FETCH and AND */
	GNI_FMA_ATOMIC_FOR     = 0x00A,    /* atomic FETCH and OR */
	GNI_FMA_ATOMIC_FOR_C   = 0x01A,    /* cached atomic FETCH and OR */
	GNI_FMA_ATOMIC_FXOR    = 0x00B,    /* atomic FETCH and XOR */
	GNI_FMA_ATOMIC_FXOR_C  = 0x01B,    /* cached atomic FETCH and XOR */
	GNI_FMA_ATOMIC_FAX     = 0x00C,    /* atomic FETCH AND exclusive OR */
	GNI_FMA_ATOMIC_FAX_C   = 0x01C,    /* cached atomic FETCH AND exclusive OR */
	GNI_FMA_ATOMIC_CSWAP   = 0x00D,    /* atomic COMPARE and SWAP */
	GNI_FMA_ATOMIC_CSWAP_C = 0x01D,    /* cached atomic COMPARE and SWAP */
	/* Second generation commands ( GET sematics ) */
	GNI_FMA_ATOMIC2_FAND_S    = 0x240,    /* atomic fetching logical AND (32-bit operands) */
	GNI_FMA_ATOMIC2_FAND      = 0x041,    /* atomic FETCH and AND */
	GNI_FMA_ATOMIC2_FAND_SC   = 0x260,    /* cached atomic fetching logical AND (32-bit operands) */
	GNI_FMA_ATOMIC2_FAND_C    = 0x061,    /* cached atomic FETCH and AND */
	GNI_FMA_ATOMIC2_FOR_S     = 0x242,    /* atomic fetching logical OR (32-bit operands) */
	GNI_FMA_ATOMIC2_FOR       = 0x043,    /* atomic FETCH and OR */
	GNI_FMA_ATOMIC2_FOR_SC    = 0x262,    /* cached atomic fetching logical OR (32-bit operands) */
	GNI_FMA_ATOMIC2_FOR_C     = 0x063,    /* cached atomic FETCH and OR */
	GNI_FMA_ATOMIC2_FXOR_S    = 0x244,    /* atomic fetching logical Exclusive OR (32-bit operands) */
	GNI_FMA_ATOMIC2_FXOR      = 0x045,    /* atomic FETCH exclusive OR */
	GNI_FMA_ATOMIC2_FXOR_SC   = 0x264,    /* cached atomic fetching logical Exclusive OR (32-bit operands) */
	GNI_FMA_ATOMIC2_FXOR_C    = 0x065,    /* cached atomic FETCH exclusive OR */
	GNI_FMA_ATOMIC2_FSWAP_S   = 0x246,    /* atomic fetching Swap (32-bit operands) */
	GNI_FMA_ATOMIC2_FSWAP     = 0x047,    /* atomic FETCH and SWAP */
	GNI_FMA_ATOMIC2_FSWAP_SC  = 0x266,    /* cached atomic fetching Swap (32-bit operands) */
	GNI_FMA_ATOMIC2_FSWAP_C   = 0x067,    /* cached atomic FETCH and SWAP */
	GNI_FMA_ATOMIC2_FAX_S     = 0x248,    /* atomic fetching logical AND Exclusive OR (32-bit operands) */
	GNI_FMA_ATOMIC2_FAX       = 0x049,    /* atomic FETCH AND exclusive OR */
	GNI_FMA_ATOMIC2_FAX_SC    = 0x268,    /* cached atomic fetching logical AND Exclusive OR (32-bit operands) */
	GNI_FMA_ATOMIC2_FAX_C     = 0x069,    /* cached atomic FETCH AND exclusive OR */
	GNI_FMA_ATOMIC2_FCSWAP_S  = 0x24A,    /* atomic fetching Compare and Swap (32-bit operands) */
	GNI_FMA_ATOMIC2_FCSWAP    = 0x04B,    /* atomic Fetching COMPARE and SWAP */
	GNI_FMA_ATOMIC2_FCSWAP_SC = 0x26A,    /* cached atomic fetching Compare and Swap (32-bit operands) */
	GNI_FMA_ATOMIC2_FCSWAP_C  = 0x06B,    /* cached atomic Fetching COMPARE and SWAP */
	GNI_FMA_ATOMIC2_FIMIN_S   = 0x250,    /* atomic fetching integer signed two’s complement Minimum (32-bit operands) */
	GNI_FMA_ATOMIC2_FIMIN     = 0x051,    /* atomic Fetching integer signed two's complement Minimum */
	GNI_FMA_ATOMIC2_FIMIN_SC  = 0x270,    /* cached atomic fetching int signed two’s complement Minimum (32-bit operands) */
	GNI_FMA_ATOMIC2_FIMIN_C   = 0x071,    /* cached atomic Fetching integer signed two's complement Minimum */
	GNI_FMA_ATOMIC2_FIMAX_S   = 0x252,    /* atomic fetching integer signed two’s complement Maximum (32-bit operands) */
	GNI_FMA_ATOMIC2_FIMAX     = 0x053,    /* atomic Fetching integer signed two's complement Maximum */
	GNI_FMA_ATOMIC2_FIMAX_SC  = 0x272,    /* cached atomic fetching int signed two’s complement Maximum (32-bit operands) */
	GNI_FMA_ATOMIC2_FIMAX_C   = 0x073,    /* cached atomic Fetching integer signed two's complement Maximum */
	GNI_FMA_ATOMIC2_FIADD_S   = 0x254,    /* atomic fetching integer two’s complement Addition (32-bit operands) */
	GNI_FMA_ATOMIC2_FIADD     = 0x055,    /* atomic Fetching integer two's complement Addition */
	GNI_FMA_ATOMIC2_FIADD_SC  = 0x274,    /* cached atomic fetching integer two’s complement Addition (32-bit operands) */
	GNI_FMA_ATOMIC2_FIADD_C   = 0x075,    /* cached atomic Fetching integer two's complement Addition */
	GNI_FMA_ATOMIC2_FFPMIN_S  = 0x258,    /* atomic fetching floating point Minimum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FFPMIN    = 0x059,    /* atomic Fetching floating point Minimum (double precision) */
	GNI_FMA_ATOMIC2_FFPMIN_SC = 0x278,    /* cached atomic fetching floating point Minimum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FFPMIN_C  = 0x079,    /* cached atomic Fetching floating point Minimum (double precision) */
	GNI_FMA_ATOMIC2_FFPMAX_S  = 0x25A,    /* atomic fetching floating point Maximum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FFPMAX    = 0x05B,    /* atomic Fetching floating point Maximum (double precision) */
	GNI_FMA_ATOMIC2_FFPMAX_SC = 0x27A,    /* cached atomic fetching floating point Maximum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FFPMAX_C  = 0x07B,    /* cached atomic Fetching floating point Maximum (double precision) */
	GNI_FMA_ATOMIC2_FFPADD_S  = 0x25C,    /* atomic fetching floating point Addition (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FFPADD    = 0x05D,    /* atomic Fetching floating point Addition (double precision) */
	GNI_FMA_ATOMIC2_FFPADD_SC = 0x27C,    /* cached atomic fetching floating point Addition (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FFPADD_C  = 0x07D,    /* cached atomic Fetching floating point Addition (double precision) */
	/************ AMOs with PUT semantics ***************/
	GNI_FMA_ATOMIC_ADD     = 0x108,    /* atomic ADD */
	GNI_FMA_ATOMIC_ADD_C   = 0x118,    /* cached atomic ADD */
	GNI_FMA_ATOMIC_AND     = 0x109,    /* atomic AND */
	GNI_FMA_ATOMIC_AND_C   = 0x119,    /* cached atomic AND */
	GNI_FMA_ATOMIC_OR      = 0x10A,    /* atomic OR */
	GNI_FMA_ATOMIC_OR_C    = 0x11A,    /* cached atomic OR */
	GNI_FMA_ATOMIC_XOR     = 0x10B,    /* atomic exclusive OR */
	GNI_FMA_ATOMIC_XOR_C   = 0x11B,    /* cached atomic exclusive OR */
	GNI_FMA_ATOMIC_AX      = 0x10C,    /* atomic AND exclusive OR */
	GNI_FMA_ATOMIC_AX_C    = 0x11C,    /* cached atomic AND exclusive OR */
	/* Second generation commands ( PUT sematics ) */
	GNI_FMA_ATOMIC2_AND_S    = 0x340,    /* atomic AND (32-bit operands) */
	GNI_FMA_ATOMIC2_AND      = 0x141,    /* atomic AND */
	GNI_FMA_ATOMIC2_AND_SC   = 0x360,    /* cached atomic AND (32-bit operands) */
	GNI_FMA_ATOMIC2_AND_C    = 0x161,    /* cached atomic AND */
	GNI_FMA_ATOMIC2_OR_S     = 0x342,    /* atomic OR (32-bit operands) */
	GNI_FMA_ATOMIC2_OR       = 0x143,    /* atomic  OR */
	GNI_FMA_ATOMIC2_OR_SC    = 0x362,    /* cached atomic OR (32-bit operands) */
	GNI_FMA_ATOMIC2_OR_C     = 0x163,    /* cached atomic  OR */
	GNI_FMA_ATOMIC2_XOR_S    = 0x344,    /* atomic Exclusive OR (32-bit operands) */
	GNI_FMA_ATOMIC2_XOR      = 0x145,    /* atomic exclusive OR */
	GNI_FMA_ATOMIC2_XOR_SC   = 0x364,    /* cached atomic Exclusive OR (32-bit operands) */
	GNI_FMA_ATOMIC2_XOR_C    = 0x165,    /* cached atomic exclusive OR */
	GNI_FMA_ATOMIC2_SWAP_S   = 0x346,    /* atomic Swap (Store) (32-bit operands) */
	GNI_FMA_ATOMIC2_SWAP     = 0x147,    /* atomic SWAP */
	GNI_FMA_ATOMIC2_SWAP_SC  = 0x366,    /* cached atomic Swap (Store) (32-bit operands) */
	GNI_FMA_ATOMIC2_SWAP_C   = 0x167,    /* cached atomic SWAP */
	GNI_FMA_ATOMIC2_AX_S     = 0x348,    /* atomic AND Exclusive OR (32-bit operands), not valid for FMA_LAUNCH */
	GNI_FMA_ATOMIC2_AX       = 0x149,    /* atomic AND exclusive OR */
	GNI_FMA_ATOMIC2_AX_SC    = 0x368,    /* cached atomic AND Exclusive OR (32-bit operands), not valid for FMA_LAUNCH */
	GNI_FMA_ATOMIC2_AX_C     = 0x169,    /* cached atomic AND exclusive OR */
	GNI_FMA_ATOMIC2_CSWAP_S  = 0x34A,    /* atomic Compare and Swap (Conditional Store) (32-bit operands), not valid for FMA_LAUNCH */
	GNI_FMA_ATOMIC2_CSWAP    = 0x14B,    /* atomic COMPARE and SWAP */
	GNI_FMA_ATOMIC2_CSWAP_SC = 0x36A,    /* cached atomic Compare and Swap (Conditional Store) (32-bit operands), not valid for FMA_LAUNCH */
	GNI_FMA_ATOMIC2_CSWAP_C  = 0x16B,    /* cached atomic COMPARE and SWAP */
	GNI_FMA_ATOMIC2_IMIN_S   = 0x350,    /* atomic integer signed two’s complement Minimum (32-bit operands) */
	GNI_FMA_ATOMIC2_IMIN     = 0x151,    /* atomic integer signed two's complement Minimum */
	GNI_FMA_ATOMIC2_IMIN_SC  = 0x370,    /* cached atomic integer signed two’s complement Minimum (32-bit operands) */
	GNI_FMA_ATOMIC2_IMIN_C   = 0x171,    /* cached atomic integer signed two's complement Minimum */
	GNI_FMA_ATOMIC2_IMAX_S   = 0x352,    /* atomic integer signed two’s complement Maximum (32-bit operands) */
	GNI_FMA_ATOMIC2_IMAX     = 0x153,    /* atomic integer signed two's complement Maximum */
	GNI_FMA_ATOMIC2_IMAX_SC  = 0x372,    /* cached atomic integer signed two’s complement Maximum (32-bit operands) */
	GNI_FMA_ATOMIC2_IMAX_C   = 0x173,    /* cached atomic integer signed two's complement Maximum */
	GNI_FMA_ATOMIC2_IADD_S   = 0x354,    /* atomic integer two’s complement Addition (32-bit operands) */
	GNI_FMA_ATOMIC2_IADD     = 0x155,    /* atomic integer two's complement Addition */
	GNI_FMA_ATOMIC2_IADD_SC  = 0x374,    /* cached atomic integer two’s complement Addition (32-bit operands) */
	GNI_FMA_ATOMIC2_IADD_C   = 0x175,    /* cached atomic integer two's complement Addition */
	GNI_FMA_ATOMIC2_FPMIN_S  = 0x358,    /* atomic floating point Minimum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FPMIN    = 0x159,    /* atomic floating point Minimum (double precision) */
	GNI_FMA_ATOMIC2_FPMIN_SC = 0x378,    /* cached atomic floating point Minimum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FPMIN_C  = 0x179,    /* cached atomic floating point Minimum (double precision) */
	GNI_FMA_ATOMIC2_FPMAX_S  = 0x35A,    /* atomic floating point Maximum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FPMAX    = 0x15B,    /* atomic floating point Maximum (double precision) */
	GNI_FMA_ATOMIC2_FPMAX_SC = 0x37A,    /* cached atomic floating point Maximum (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FPMAX_C  = 0x17B,    /* cached atomic floating point Maximum (double precision) */
	GNI_FMA_ATOMIC2_FPADD_S  = 0x35C,    /* atomic floating point Addition (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FPADD    = 0x15D,    /* atomic floating point Addition (double precision) */
	GNI_FMA_ATOMIC2_FPADD_SC = 0x37C,    /* cached atomic floating point Addition (single precision) (32-bit operands) */
	GNI_FMA_ATOMIC2_FPADD_C  = 0x17D,    /* cached atomic floating point Addition (double precision) */
} gni_fma_cmd_type_t;

/* CE command types */
typedef enum gni_ce_cmd_type {
	GNI_FMA_CE_AND_S        = 0x0ull,   /* Logical AND, short */
	GNI_FMA_CE_AND          = 0x1ull,   /* Logical AND */
	GNI_FMA_CE_OR_S         = 0x2ull,   /* Logical OR, short */
	GNI_FMA_CE_OR           = 0x3ull,   /* Logical OR */
	GNI_FMA_CE_XOR_S        = 0x4ull,   /* Logical XOR, short */
	GNI_FMA_CE_XOR          = 0x5ull,   /* Logical XOR */
	GNI_FMA_CE_IMIN_LIDX_S  = 0x10ull,  /* Integer signed two's complement minimum, short (lowest index returned) */
	GNI_FMA_CE_IMIN_LIDX    = 0x11ull,  /* Integer signed two's complement minimum (lowest index returned) */
	GNI_FMA_CE_IMAX_LIDX_S  = 0x12ull,  /* Integer signed two's complement maximum, short (lowest index returned) */
	GNI_FMA_CE_IMAX_LIDX    = 0x13ull,  /* Integer signed two's complement maximum (lowest index returned) */
	GNI_FMA_CE_IADD_S       = 0x14ull,  /* Integer two's complement ADD, short */
	GNI_FMA_CE_IADD         = 0x15ull,  /* Integer two's complement ADD */
	GNI_FMA_CE_FPMIN_LIDX_S = 0x18ull,  /* Floating point minimum, short (lowest index returned) */
	GNI_FMA_CE_FPMIN_LIDX   = 0x19ull,  /* Floating point minimum (lowest index returned) */
	GNI_FMA_CE_FPMAX_LIDX_S = 0x1aull,  /* Floating point maximum, short (lowest index returned) */
	GNI_FMA_CE_FPMAX_LIDX   = 0x1bull,  /* Floating point maximum (lowest index returned) */
	GNI_FMA_CE_FPADD_S      = 0x1cull,  /* Floating point ADD, short */
	GNI_FMA_CE_FPADD        = 0x1dull,  /* Floating point ADD */
	GNI_FMA_CE_IMIN_GIDX_S  = 0x30ull,  /* Integer signed two's complement minimum, short (greatest index returned) */
	GNI_FMA_CE_IMIN_GIDX    = 0x31ull,  /* Integer signed two's complement minimum (greatest index returned) */
	GNI_FMA_CE_IMAX_GIDX_S  = 0x32ull,  /* Integer signed two's complement maximum, short (greatest index returned) */
	GNI_FMA_CE_IMAX_GIDX    = 0x33ull,  /* Integer signed two's complement maximum (greatest index returned) */
	GNI_FMA_CE_FPMIN_GIDX_S = 0x38ull,  /* Floating point minimum, short (greatest index returned) */
	GNI_FMA_CE_FPMIN_GIDX   = 0x39ull,  /* Floating point minimum (greatest index returned) */
	GNI_FMA_CE_FPMAX_GIDX_S = 0x3aull,  /* Floating point maximum, short (greatest index returned) */
	GNI_FMA_CE_FPMAX_GIDX   = 0x3bull,  /* Floating point maximum (greatest index returned) */
} gni_ce_cmd_type_t;

/* CE result structure */
typedef struct gni_ce_result {
	uint64_t        control;
	uint64_t        result1;
	uint64_t        result2;
} gni_ce_result_t;

/* CE result operations */
uint64_t gni_ce_res_get_status(gni_ce_result_t *);
uint64_t gni_ce_res_status_ok(gni_ce_result_t *);
uint64_t gni_ce_res_get_fpe(gni_ce_result_t *);
uint64_t gni_ce_res_get_red_id(gni_ce_result_t *);

#define GNI_CE_RES_GET_STATUS   gni_ce_res_get_status
#define GNI_CE_RES_STATUS_OK    gni_ce_res_status_ok
#define GNI_CE_RES_GET_FPE      gni_ce_res_get_fpe
#define GNI_CE_RES_GET_RED_ID   gni_ce_res_get_red_id

/* CE floating point exceptions  */
#define GNI_CE_FPE_OP_INVAL     0x1
#define GNI_CE_FPE_OFLOW        0x2
#define GNI_CE_FPE_UFLOW        0x4
#define GNI_CE_FPE_PRECISION    0x8

/* CE child types */
typedef enum {
	GNI_CE_CHILD_UNUSED,
	GNI_CE_CHILD_VCE,
	GNI_CE_CHILD_PE
} gni_ce_child_t;

/* VCE channel modes, used during GNI_CeConfigure(...) */
/* Rounding mode, specify 1 */
#define GNI_CE_MODE_ROUND_UP            0x00000001
#define GNI_CE_MODE_ROUND_DOWN          0x00000002
#define GNI_CE_MODE_ROUND_NEAR          0x00000004
#define GNI_CE_MODE_ROUND_ZERO          0x00000008
/* CQE delivery mode, specify 1 */
#define GNI_CE_MODE_CQE_ONCOMP          0x00000010
#define GNI_CE_MODE_CQE_ONERR           0x00000040
/* Routing mode, specify 1 */
#define GNI_CE_MODE_RC_NMIN_HASH        0x00000080
#define GNI_CE_MODE_RC_MIN_HASH         0x00000100
#define GNI_CE_MODE_RC_MNON_HASH        0x00000200
#define GNI_CE_MODE_RC_ADAPT            0x00000400

#define GNI_CE_MAX_CHILDREN             32

/* CQ event types */
#define GNI_CQMODE_SILENT       0x0000
#define GNI_CQMODE_LOCAL_EVENT  0x0001
#define GNI_CQMODE_GLOBAL_EVENT 0x0002
#define GNI_CQMODE_REMOTE_EVENT 0x0004
#define GNI_CQMODE_DUAL_EVENTS  ( GNI_CQMODE_LOCAL_EVENT | GNI_CQMODE_GLOBAL_EVENT )

/* Delivery modes */
#define GNI_DLVMODE_PERFORMANCE 0x0000
#define GNI_DLVMODE_NO_ADAPT    0x0001
#define GNI_DLVMODE_NO_HASH     0x0002
#define GNI_DLVMODE_NO_RADAPT   0x0004
#define GNI_DLVMODE_IN_ORDER    ( GNI_DLVMODE_NO_ADAPT | GNI_DLVMODE_NO_HASH )

/* Aries delivery modes */
#define GNI_DLVMODE_MNON_HASH   GNI_DLVMODE_IN_ORDER
#define GNI_DLVMODE_NMIN_HASH   0x0008
#define GNI_DLVMODE_MIN_HASH    0x0010
#define GNI_DLVMODE_ADAPTIVE0   GNI_DLVMODE_PERFORMANCE
#define GNI_DLVMODE_ADAPTIVE1   0x0020
#define GNI_DLVMODE_ADAPTIVE2   0x0040
#define GNI_DLVMODE_ADAPTIVE3   0x0080

#define GNI_DLVMODE_ORDERED_TAIL 0x0100

/* Error Event Categories */
/* WARNING: DO NOT CHANGE THESE UNLESS YOU CHANGE ghal_err_cat.h */
#define GNI_ERRMASK_CORRECTABLE_MEMORY   (1 << 0)
#define GNI_ERRMASK_CRITICAL             (1 << 1)
#define GNI_ERRMASK_TRANSACTION          (1 << 2)
#define GNI_ERRMASK_ADDRESS_TRANSLATION  (1 << 3)
#define GNI_ERRMASK_TRANSIENT            (1 << 4)
#define GNI_ERRMASK_INFORMATIONAL        (1 << 5)
#define GNI_ERRMASK_DIAG_ONLY            (1 << 6)
#define GNI_ERRMASK_UNKNOWN_TRANSACTION  (1 << 7)

/* RDMA mode */
/* local_addr is a physical address (kernel only) */
#define GNI_RDMAMODE_PHYS_ADDR  0x0001
/* instruction to Gemini to wait for all responses from this post and all
 * previous posts before processing the next RDMA descriptor */
#define GNI_RDMAMODE_FENCE      0x0002
/* Disable Aries write combining of incoming GET data */
#define GNI_RDMAMODE_GETWC_DIS  0x0004

/* Post CE modes, used during GNI_PostFma(...) */
/* Use two operands (only meaningful for single operand collective operations).
 * Single operand CE operations are all variations of AND, OR, XOR and ADD.  */
#define GNI_CEMODE_TWO_OP               (1 << 0)
/* The provided operands are an intermediate result that has experienced an
 * invalid operation floating point exception. */
#define GNI_CEMODE_FPE_OP_INVAL         (1 << 1)
/* The provided operands are an intermediate result that has experienced an
 * overflow floating point exception */
#define GNI_CEMODE_FPE_OFLOW            (1 << 2)
/* The provided operands are an intermediate result that has experienced an
 * underflow floating point exception. */
#define GNI_CEMODE_FPE_UFLOW            (1 << 3)
/* The provided operands are an intermediate result that has experienced an
 * inexact result floating point exception. */
#define GNI_CEMODE_FPE_PRECISION        (1 << 4)

/* Maximum length in bytes of a datagram transaction */
#define GNI_DATAGRAM_MAXSIZE    128

/*
 * Maximum length in bytes of a short message,
 * this includes the length of the header and data.
 */
#define GNI_SMSG_MAX_SIZE       65535

/* Transaction descriptor */
typedef struct gni_post_descriptor {
	/********************** Control **********************/
	/* points to the next descriptor in the link list */
	void *next_descr;
	/* points to the previous descriptor in the link list */
	void *prev_descr;
	/* holds an ID of the transaction assigned by the user */
	uint64_t post_id;
	/* error status of the transaction */
	uint64_t status;
	/* completion flag of the transaction */
	uint16_t cq_mode_complete;
	/********************** Common ***********************/
	/* type of the transaction */
	gni_post_type_t type;
	/* instruction to generate CQ events of the following types
	   (see GNI_CQMODE_xxx)*/
	uint16_t cq_mode;
	/* delivery mode (see GNI_DLVMODE_xxx) */
	uint16_t dlvr_mode;
	/* address of region on the local node: source for Put, target for Get */
	uint64_t local_addr;
	/* local memory handle */
	gni_mem_handle_t local_mem_hndl;
	/* address of the remote region: target for Put, source for Get */
	uint64_t remote_addr;
	/* remote memory handle */
	gni_mem_handle_t remote_mem_hndl;
	/* number of bytes to move during the transaction */
	uint64_t length;
	/****************** RDMA specific ********************/
	/* see GNI_RDMAMODE_xxx */
	uint16_t rdma_mode;
	/* defines src. CQ for the transaction */
	gni_cq_handle_t src_cq_hndl;
	/************ FMA and AMO specific *******************/
	/* synchronization value */
	uint64_t sync_flag_value;
	/* location to deliver sync. value */
	uint64_t sync_flag_addr;
	/****************** AMO specific *********************/
	/* AMO command for the transaction */
	gni_fma_cmd_type_t amo_cmd;
	/* first operand required by the AMO command */
	uint64_t first_operand;
	/* second operand required by the AMO command */
	uint64_t second_operand;
	/****************** CQWrite specific *****************/
	/* cqwrite value - only 6 least significant bytes available to software */
	uint64_t cqwrite_value;
	/****************** CE specific **********************/
	/* CE command */
	gni_ce_cmd_type_t ce_cmd;
	/* CE modes, see GNI_CEMODE_* */
	uint32_t ce_mode;
	/* CE reduction ID */
	uint64_t ce_red_id;
} gni_post_descriptor_t;

/* NTT configuration table entries */
typedef struct gni_ntt_entry {
	uint32_t        blck_addr;
	uint32_t        rplc_addr;
	uint8_t         rplc_size;
} gni_ntt_entry_t;

/* NTT configuration descriptor */
typedef struct gni_ntt_descriptor {
	/* size of the NTT group to be configured */
	uint32_t        group_size;
	/* NTT granularity */
	uint8_t         granularity;
	/* pointer to the array of new NTT values */
	union {
		uint32_t        *table;
		gni_ntt_entry_t *table_v2;
	} u;
	/* configuration flags ( not used )*/
	uint8_t         flags;
} gni_ntt_descriptor_t;

/* GNI Error Event */
typedef struct gni_error_event {
	uint16_t error_code;
	uint8_t  error_category;
	uint8_t  ptag;
	uint32_t serial_number;
	uint64_t timestamp;
	uint64_t info_mmrs[4];
} gni_error_event_t;

typedef uint8_t gni_error_mask_t;

/* Job parameters and limits */
#define GNI_JOB_INVALID_LIMIT           (-1)
/* Directive for the driver to cleanup NTT at the end of the job */
#define GNI_JOB_CTRL_NTT_CLEANUP        (0x01)
/* Job Control CE Channel Masks */
#define GNI_JOB_CTRL_CE0_MASK           (1<<0)
#define GNI_JOB_CTRL_CE1_MASK           (1<<1)
#define GNI_JOB_CTRL_CE2_MASK           (1<<2)
#define GNI_JOB_CTRL_CE3_MASK           (1<<3)
#define GNI_JOB_CTRL_ALL_CE_MASK        (GNI_JOB_CTRL_CE0_MASK | \
					 GNI_JOB_CTRL_CE1_MASK | \
					 GNI_JOB_CTRL_CE2_MASK | \
					 GNI_JOB_CTRL_CE3_MASK)

typedef struct gni_job_limits {
	int32_t  mdd_limit;      /* IN number of MDDs associated with the given ptag */
	union {
		int32_t  mrt_limit;          /* Gemini: IN number of MRT entries used by MDDs with the given ptag */
		struct {
			uint8_t  ce_limit;    /* Aries: IN number of CE channels available with the given ptag */
			uint8_t  iommu_limit; /* Aries: IN 2 ^ N * 1MB bytes of address space per ptag */
			uint8_t  res_byte2;
			uint8_t  res_byte3;
		} m;
	} a;
	union {
		int32_t  gart_limit;     /* Gemini: IN number of GART entries used by MDDs with the given ptag */
		int32_t  dla_limit;      /* Aries: IN number of DLA entries available with the given ptag */
	} b;
	int32_t  fma_limit;      /* IN number of FMA descriptors associated with the given ptag */
	int32_t  bte_limit;      /* IN number of outstanding BTE descriptors with the given src. ptag */
	int32_t  cq_limit;       /* IN number of CQ descriptors associated with the given ptag */
	int32_t  ntt_ctrl;       /* IN NTT cotrol flag (see GNI_JOB_CTRL_NTT_xxx above)*/
	int32_t  ntt_base;       /* IN Base entry into NTT */
	int32_t  ntt_size;       /* IN size of the NTT */
} gni_job_limits_t;

typedef enum gni_nic_device {
	GNI_DEVICE_GEMINI = 0,
	GNI_DEVICE_ARIES  = 1,
	GNI_DEVICE_PISCES = 2,
	GNI_DEVICE_LAST
} gni_nic_device_t;

/* Resource info types */
typedef enum gni_dev_res {
	GNI_DEV_RES_FIRST = 0,
	GNI_DEV_RES_MDD,
	GNI_DEV_RES_MRT,
	GNI_DEV_RES_CQ,
	GNI_DEV_RES_FMA,
	GNI_DEV_RES_CE,
	GNI_DEV_RES_DLA,
	GNI_DEV_RES_LAST
} gni_dev_res_t;

typedef struct gni_dev_res_desc {
	uint64_t available;
	uint64_t reserved;
	uint64_t held;
	uint64_t total;
} gni_dev_res_desc_t;

typedef enum gni_job_res {
	GNI_JOB_RES_FIRST = 0,
	GNI_JOB_RES_MDD,
	GNI_JOB_RES_MRT,
	GNI_JOB_RES_IOMMU,
	GNI_JOB_RES_GART,
	GNI_JOB_RES_CQ,
	GNI_JOB_RES_FMA,
	GNI_JOB_RES_RMDA,
	GNI_JOB_RES_CE,
	GNI_JOB_RES_DLA,
	GNI_JOB_RES_SFMA,
	GNI_JOB_RES_LAST
} gni_job_res_t;

typedef struct gni_job_res_desc {
	uint64_t used;
	uint64_t limit;
} gni_job_res_desc_t;

typedef enum gni_statistic {
	GNI_STAT_SMSG_BUFF_CREDITS_STALL = 0,
	GNI_STAT_SMSG_DLA_STALL,
	GNI_STAT_SMSG_MBOX_CREDITS_STALL,
	GNI_STAT_SMSG_REQ_STALL,
	GNI_STAT_SMSG_RETRANS_COUNT,
	GNI_STAT_SMSG_RETRANS_DLA_COUNT,
	GNI_STAT_SMSG_RETRANS_STALL,
#if defined CRAY_CONFIG_GHAL_ARIES
	GNI_STAT_DLA_ALLOC_STATUS_STALL,
	GNI_STAT_DLA_ALLOC_STATUS_TIMEOUT,
	GNI_STAT_DLA_BLOCK_ORPHANED,
	GNI_STAT_DLA_BLOCK_RETRANS_COUNT,
	GNI_STAT_DLA_FREE_BLOCKS_STALL,
	GNI_STAT_DLA_FREE_FMAD_BLOCKS_STALL,
	GNI_STAT_DLA_HIGH_RETRANS_COUNT,
	GNI_STAT_DLA_OVERFLOW_RESEND,
	GNI_STAT_DLA_RETRANS_COUNT,
	GNI_STAT_DLA_TOTAL_RETRANS_COUNT,
	GNI_STAT_FLBTE_TXD_CORRUPT,
	GNI_STAT_FLBTE_TXD_NONE,
#endif
	GNI_NUM_STATS
} gni_statistic_t;

extern const char *gni_statistic_str[];

#ifdef __KERNEL__

#define GNI_ERRNO_FUNC_STR_LEN          100

typedef struct gni_errno {
	uint8_t         valid;
	char            func[GNI_ERRNO_FUNC_STR_LEN];
	int             lineno;
	int             errno;
	uint64_t        data1;
	uint64_t        data2;
	uint64_t        data3;
	uint64_t        data4;
} gni_errno_t;

#endif

#ifndef __KERNEL__

/* User level definitions */

/* public MSGQ definitions */

/* shared message queue receive callback function */
typedef int gni_msgq_rcv_cb_func(
		uint32_t snd_id,
		uint32_t snd_pe,
		void     *msg,
		uint8_t  msg_tag,
		void     *cb_data
		);

/* MSGQ limits */
#define GNI_MSGQ_MSG_SZ_MAX             128
#define GNI_MSGQ_NODE_INSTS_MAX         48

/* MSGQ mode flags */
#define GNI_MSGQ_MODE_BLOCKING          (0x01)

/* MSGQ structures */
typedef struct gni_msgq_attr {
	uint32_t         max_msg_sz;
	uint32_t         smsg_q_sz;
	uint32_t         rcv_pool_sz;
	uint32_t         num_msgq_eps;
	uint32_t         nloc_insts;
	uint8_t          modes;
	uint32_t         rcv_cq_sz;
} gni_msgq_attr_t;

typedef struct gni_msgq_rem_inst {
	uint32_t         id;      /* instance ID */
	gni_mem_handle_t mdh;     /* MDH for the shmem region */
	uint64_t         mdh_off; /* offset into the MDH for the smsg mbox */
} gni_msgq_rem_inst_t;

typedef struct gni_msgq_ep_attr {
	uint32_t         pe_addr;
	uint32_t         max_msg_sz;
	uint32_t         smsg_q_sz;
	uint32_t         num_insts;
	gni_msgq_rem_inst_t insts[GNI_MSGQ_NODE_INSTS_MAX];
} gni_msgq_ep_attr_t;

#define MAX_BUILD_STRING_LENGTH 80

typedef struct gni_version_info {
	uint32_t         ugni_version;
	uint32_t         ugni_svn_revision;
	char             ugni_build_string[MAX_BUILD_STRING_LENGTH];
	uint32_t         kgni_version;
	uint32_t         kgni_svn_revision;
	char             kgni_build_string[MAX_BUILD_STRING_LENGTH];
} gni_version_info_t;

/* If return codes are modified, need to modify
   gni_err_str */

extern const char *gni_err_str[];


/**
 * GNI_CdmCreate - Create Communication Domain
 *
 * Parameters:
 * IN
 * inst_id  Instance of the cdm in the job (user level).
 *          Unique address of the instance within the upper layer
 *          protocol domain (kernel level).
 * ptag     Protection Tag.
 * cookie   Unique identifier generated by ALPS. Along with ptag
 *          helps to identify the Communication Domain.
 * modes    bit mask (see GNI_CDM_MODE_xxxxxx definitions)
 *
 * OUT
 * cdm_hndl     Handle returned. The handle is used with the other functions
 *      to specify a particular instance of the Communication Domain.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates an instance of the Communication Domain.
 **/
gni_return_t
	GNI_CdmCreate(
		IN  uint32_t            inst_id,
		IN  uint8_t             ptag,
		IN  uint32_t            cookie,
		IN  uint32_t            modes,
		OUT gni_cdm_handle_t    *cdm_hndl
		);

/**
 * GNI_CdmDestroy - Destroys the instance of a Communication Domain
 *
 * Parameters:
 * IN
 * cdm_hndl   Communication Domain Handle
 *
 * Returns:
 * GNI_RC_SUCCESS - The operation completed successfully
 * GNI_RC_INVALID_PARAM - Caller specified an invalid Communication Domain Handle
 *
 * Description:
 * Destroys the instance of a Communication Domain.  Removes associations
 * between the calling process and the NIC devices that were established via
 * the corresponding Attach function.
 **/
gni_return_t
	GNI_CdmDestroy(
		IN gni_cdm_handle_t     cdm_hndl
		);

/**
 * GNI_CdmGetNicAddress - Get the PE address of a GNI device.
 *
 * Parameters:
 * IN
 * device_id    The ID of the GNI device to query.
 *
 * OUT
 * address      The PE address of the GNI device queried.
 * cpu_id       The ID of the first CPU directly connected to the GNI device.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_NO_MATCH - Specified device_id does not exists.
 *
 * Description:
 *
 * Returns the PE address of the GNI device with ID device_id and the ID of
 * it's most closely connected CPU.
 **/
gni_return_t
	GNI_CdmGetNicAddress(
		IN  uint32_t    device_id,
		OUT uint32_t    *address,
		OUT uint32_t    *cpu_id
		);

/**
 * GNI_CdmAttach - Attach Communication Domain to a NIC device
 *
 * Parameters:
 * IN
 * cdm_hndl     The Communication Domain Handle.
 * device_id    The device identifier , e.g. /dev/kgni1 has
 *              device_id = DEVICE_MINOR_NUMBER - GEMINI_BASE_MINOR_NUMBER = 1
 *              Setting device_id to (-1) will result in attaching to the nearest
 *              Gemini NIC.
 *
 * OUT
 * local_addr   PE address of the Gemini NIC attached
 * nic_hndl     Handle returned. The handle is used with the other functions to specify
 *              a particular instance of a Gemini NIC.
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Caller specified an invalid CDM handle.
 * GNI_RC_NO_MATCH - Specified device_id does not exists
 * GNI_RC_ERROR_RESOURCE - The operation failed due to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_PERMISSION_ERROR - Insufficient permissions to perform operation.
 * GNI_RC_INVALID_STATE - Caller attempts to attach the same CDM instance to
 *                        the same Gemini NIC device more than once.
 *                        If returned while device_id= -1, means that there
 *                        are no more devices left for this CDM to attach to.
 * GNI_RC_NOT_DONE - The process was interrupted.
 *
 * Description:
 * Associates the Communication Domain with a Gemini NIC and provides a
 * NIC handle to the upper layer protocol. A process is not allowed
 * to attach the same CDM instance to the same Gemini NIC more than once,
 * but it is allowed to attach multiple CDMs to the same Gemini NIC.
 **/
gni_return_t
	GNI_CdmAttach(
		IN  gni_cdm_handle_t    cdm_hndl,
		IN  uint32_t            device_id,
		OUT uint32_t            *local_addr,
		OUT gni_nic_handle_t    *nic_hndl
		);

/**
 * GNI_CdmCheckpoint - Sets the checkpoint bit for each GNI nic handle
 *
 * Parameter:
 * IN
 * cdm_handle   Communication Domain Handle
 *
 * Returns:
 * GNI_RC_SUCCESS - The operation completed successfully
 * GNI_RC_INVALID_PARAM - Caller specified an invalid Communication Domain Handle
 *
 * Description:
 * This will set the checkpoint bit in each GNI NIC handle so that subsequent GNI library
 * calls made following a restart will not perform any system calls on the (now closed)
 * GNI device. This is needed so that it's safe to call GNI_CqDestroy and GNI_CdmDestroy
 * after a restart, as these now stale GNI resources have to be freed.
 **/
gni_return_t
	GNI_CdmCheckpoint(
		IN gni_cdm_handle_t     cdm_handle
		);

/**
 * GNI_CdmResume- Unsets the checkpoint bit for each GNI nic handle
 *
 * Parameter:
 * IN
 * cdm_handle   Communication Domain Handle
 *
 * Returns:
 * GNI_RC_SUCCESS - The operation completed successfully
 * GNI_RC_INVALID_PARAM - Caller specified an invalid Communication Domain Handle
 *
 * Description:
 * Reverses the effects of GNI_CdmCheckpoint.
 **/
gni_return_t
	GNI_CdmResume(
		IN gni_cdm_handle_t     cdm_handle
		);

/**
 * GNI_SuspendJob - Suspend GNI resources belonging to a job
 *
 * Parameter:
 * IN
 * device_id    The ID of the GNI device to use
 * job_id       The ID of the job using the communication domain to suspend
 * ptag         The PTAG of the communication domain to suspend
 * cookie       The cookie used by the communication domain to suspend
 * timeout      The Wait timeout in milliseconds
 *
 * Returns:
 * GNI_RC_SUCCESS - The job is suspended
 * GNI_RC_INVALID_PARAM - An invalid parameter was specified
 * GNI_RC_TIMEOUT - Timed out waiting for the operation to complete
 * GNI_RC_PERMISSION_ERROR - Caller is not a privileged user
 * GNI_RC_NOT_DONE - Job cannot be suspended at this point, try again
 * GNI_RC_INVALID_STATE - Job suspend is already pending
 * GNI_RC_ERROR_RESOURCE - Job does not support suspension
 *
 * Description:
 * GNI_SuspendJob notifies the GNI SW stack that the job identified by the
 * device ID and protection tag is going to be suspended.  This function can
 * block until SW stack is ready for the job to be suspended or until the
 * timeout expires.
 */
gni_return_t
	GNI_SuspendJob(
		IN uint32_t     device_id,
		IN uint64_t     job_id,
		IN uint8_t      ptag,
		IN uint32_t     cookie,
		IN uint32_t     timeout
		);

/**
 * GNI_ResumeJob - Un-suspend GNI resources belonging to a job
 *
 * Parameter:
 * IN
 * device_id    The ID of the GNI device to use
 * job_id       The ID of the job using the communication domain to resume
 * ptag         The PTAG of the communication domain to resume
 * cookie       The cookie used by the communicatio domain to resume
 *
 * Returns:
 * GNI_RC_SUCCESS - The job is resumed
 * GNI_RC_INVALID_PARAM - An invalid parameter was specified
 * GNI_RC_PERMISSION_ERROR - Caller is not a privileged user
 * GNI_RC_INVALID_STATE - Job was not suspended
 *
 * Description:
 * GNI_ResumeJob notifies the GNI SW stack that the job identified by the
 * device ID and protection tag is going to resume its execution.
 */
gni_return_t
	GNI_ResumeJob(
		IN uint32_t     device_id,
		IN uint64_t     job_id,
		IN uint8_t      ptag,
		IN uint32_t     cookie
		);

/**
 * GNI_ConfigureNTT - Configure NTT entries for a Gemini device
 *
 * Parameters:
 * IN
 * device_id    The device identifier , e.g. /dev/kgni1 has
 *              device_id = DEVICE_MINOR_NUMBER - GEMINI_BASE_MINOR_NUMBER = 1.
 * ntt_desc     NTT configuration descriptor.
 * OUT
 * ntt_base     On return, is set to the base NTT
 *              entry allocated by the driver.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_PERMISSION_ERROR - Process has insufficient permissions to set up
 *                           NTT resources.
 * GNI_RC_ERROR_RESOURCE - hardware resource limitation prevents NTT setup.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_NO_MATCH - the specified device_id does not exist.
 *
 * Description:
 * This function sets up entries in the NTT associated with a particular
 * Gemini device.
 *
 * Notes:
 * If the table field of the input ntt_desc is set to NULL, the NTT
 * entries starting from ntt_base up to and including
 * ntt_base + ntt_desc->group_size - 1 will be reset to 0.
 *
 * If the ntt_base is -1 and ntt_desc->group_size is -1 and
 * the table field of ntt_desc is NULL all entries of NTT allocations not
 * currently in use will be reset to 0.
 *
 **/
gni_return_t
	GNI_ConfigureNTT(
		IN  int                         device_id,
		IN  gni_ntt_descriptor_t        *ntt_desc,
		OUT uint32_t                    *ntt_base
		);

/**
 * GNI_ConfigureJob - Configure parameters of the job
 *
 * Parameters:
 * IN
 * device_id    The device identifier , e.g. /dev/kgni1 has
 *              device_id = DEVICE_MINOR_NUMBER - GEMINI_BASE_MINOR_NUMBER = 1.
 * job_id       Job container identifier.
 * ptag         Protection tag to be used by all applications in the given job container.
 * cookie       Unique identifier. Assigned to all applications within the
 *              job container along with ptag.
 * limits       Driver takes all the limit values,
 *              that are not set to GNI_JOB_INVALID_LIMIT, and stores them into the
 *              table indexed by the ptag. These limits will get imposed on all
 *              the applications running within the given job container.
 *              Setting limits for the same ptag will overwrite previously set limits.
 *
 * Return:
 *
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_PERMISSION_ERROR - Process has insufficient permissions to configure job
 * GNI_RC_NO_MATCH - the specified device_id does not exist or no NTT entries
 *                   exist for input ntt_base/ntt_size fields in the limits argument.
 * GNI_RC_INVALID_STATE - attempt to use the same ptag with different job_id or
 *                        different cookie.
 * GNI_RC_ILLEGAL_OP - the application is attempting to resize the NTT resources
 * GNI_RC_ERROR_RESOURCE - a resource allocation error was encountered while
 *                         trying to configure the job resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 *
 * The user(ALPS) can call this function multiple times for the same Gemini interface.
 * Driver looks up a triplet (job_id+ptag+cookie) and then adds a new entry into
 * the list it maintains per physical NIC, for every unique triplet.
 * Each entry may have non-unique job_id or ptag or cookie.
 * Using the same ptag with different job_ids's considered to be illegal
 * and such calls will fail.
 * This function must be called before GNI_CdmAttach() for the
 * CDM with the same ptag+cookie.
 * Calling GNI_ConfigureJob for the same triplet will have no effect,
 * unless limit argument is non-NULL.
 *
 * This function may also be used to associated NTT resources with a job.  The
 * NTT resources would have been previously allocated by a call to GNI_ConfigureNTT.
 * In this case, the application shall set the ntt_base and ntt_size fields
 * in the limits input.  If the application expects the driver to cluean up
 * the NTT resources upon termination of the job, the ntt_ctrl field in the
 * limits input must be set to GNI_JOB_CTRL_NTT_CLEANUP.  The application should
 * not attempt to change ntt_base or ntt_size by calling ConfigureJob a subsequent
 * time with different NTT parameters.
 *
 **/
gni_return_t
	GNI_ConfigureJob(
		IN uint32_t             device_id,
		IN uint64_t             job_id,
		IN uint8_t              ptag,
		IN uint32_t             cookie,
		IN gni_job_limits_t     *limits
		);

/**
 * GNI_ConfigureNTTandJob - Configure NTT entries for a Gemini device and parameters of the job
 *
 * Parameters:
 * IN
 * device_id    The device identifier , e.g. /dev/gemini1 has
 *              device_id = DEVICE_MINOR_NUMBER - GEMINI_BASE_MINOR_NUMBER = 1.
 * job_id       Job container identifier.
 * ptag         Protection tag to be used by all applications in the given job container.
 * cookie       Unique identifier. Assigned to all applications within the
 *              job container along with ptag.
 * limits       Driver takes all the limit values,
 *              that are not set to GNI_JOB_INVALID_LIMIT, and stores them into the
 *              table indexed by the ptag. These limits will get imposed on all
 *              the applications running within the given job container.
 *              Setting limits for the same ptag will overwrite previously set limits.
 * ntt_desc     NTT configuration descriptor.
 * OUT
 * ntt_base     On return, is set to the base NTT
 *              entry allocated by the driver.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_PERMISSION_ERROR - Process has insufficient permissions to set up
 *                           NTT resources.
 * GNI_RC_ERROR_RESOURCE - hardware resource limitation prevents NTT setup or
 *                         some other resource allocation error was encountered while
 *                         trying to configure the job resources
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_NO_MATCH - the specified device_id does not exist or no NTT entries
 *                   exist for input ntt_base/ntt_size fields in the limits argument.
 * GNI_RC_INVALID_STATE - attempt to use the same ptag with different job_id or
 *                        different cookie.
 * GNI_RC_ILLEGAL_OP - the application is attempting to resize the NTT resources
 *
 * Description:
 * This function sets up entries in the NTT associated with a particular
 * Gemini device and then configures parameters of the job in a single system call
 *
 * The user(ALPS) can call this function instead of calling GNI_ConfigureNTT and
 * GNI_ConfigureJob one after another. Setting ntt_desc to NULL will make this
 * function equivalent to GNI_ConfigureJob.
 * Driver looks up a triplet (job_id+ptag+cookie) and then adds a new entry into
 * the list it maintains per physical NIC, for every unique triplet.
 * Each entry may have non-unique job_id or ptag or cookie.
 * Using the same ptag with different job_ids's considered to be illegal
 * and such calls will fail.
 * This function or GNI_ConfigureJob must be called before GNI_CdmAttach() for the
 * CDM with the same ptag+cookie.
 *
 * This function can be used to associated NTT resources with a job.
 * If the application expects the driver to clean up the NTT resources
 * upon termination of the job, the ntt_ctrl field in the limits input must be set
 * to GNI_JOB_CTRL_NTT_CLEANUP.
 * The application should not attempt to change ntt_base or ntt_size by calling
 * ConfigureJob a subsequent time with different NTT parameters.
 *
 * Note:
 * This function can't be used to clear NTT table. GNI_ConfigureNTT should be used instead.
 **/
gni_return_t
	GNI_ConfigureNTTandJob(
		IN  int                         device_id,
		IN  uint64_t                    job_id,
		IN  uint8_t                     ptag,
		IN  uint32_t                    cookie,
		IN  gni_job_limits_t            *limits,
		IN  gni_ntt_descriptor_t        *ntt_desc,
		OUT uint32_t                    *ntt_base
		);

/**
 * GNI_EpCreate - Create logical Endpoint
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated Gemini NIC.
 * src_cq_hndl  Handle of the CQ that will be used by default to deliver events
 *              related to the transactions initiated by the local node.
 *
 * OUT
 * ep_hndl      The handle of the newly created Endpoint instance.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates an instance of a Logical Endpoint.
 * A new instance is always created in a non-bound state.
 * A non-bound Endpoint is able to exchange posted data with
 * any bound remote Endpoint within the same Communication Domain.
 * An Endpoint cannot be used to post RDMA, FMA transactions or
 * send short messages while it is in non-bound state.
 **/
gni_return_t
	GNI_EpCreate(
		IN  gni_nic_handle_t    nic_hndl,
		IN  gni_cq_handle_t     src_cq_hndl,
		OUT gni_ep_handle_t     *ep_hndl
		);

/**
 * GNI_EpSetEventData - Set event data for local and remote events
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance.
 * local_event  Value to use when generating LOCAL CQ events
 * remote_event Value to use when generating GLOBAL & REMOTE CQ events
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid EP handle.
 *
 * Description:
 * By default GNI uses local instance_id as an event data for GLOBAL and REMOTE CQ events,
 * and EP remote_id when generating LOCAL CQ events.
 * This function allows to re-assign these events to the user defined values.
 **/
gni_return_t
	GNI_EpSetEventData(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             local_event,
		IN uint32_t             remote_event
		);

/**
 * GNI_EpBind - Bind logical Endpoint to a peer
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to be bound.
 * remote_addr  Physical address of the Gemini NIC at the remote peer or NTT index,
 *              when NTT is enabled for the given Communication Domain.
 * remote_id    User specified ID of the remote instance in the job or unique identifier of
 *              the remote instance within the upper layer protocol domain.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The operation failed due to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function binds a Logical Endpoint to the specific remote address
 * and remote instance in the Communication Domain.
 * Once bound the Endpoint can be used to post RDMA and FMA transactions.
 **/
gni_return_t
	GNI_EpBind(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             remote_addr,
		IN uint32_t             remote_id
		);

/**
 * GNI_EpUnbind - Unbind logical Endpoint
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to be bound.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE - Operation is not permited
 *
 * Description:
 * This function unbinds a Logical Endpoint from the specific remote address
 * and remote instance and releases any internal short message resource.
 * A non-bound Endpoint is able to exchange posted data with
 * any bound remote Endpoint within the same Communication Domain.
 * An Endpoint cannot be used to post RDMA, FMA transactions or
 * send short messages while it is in non-bound state.
 **/
gni_return_t
	GNI_EpUnbind(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * GNI_EpIdle - prepare the GNI endpoint for checkpoint
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to check
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE - Operation is not permited
 *
 * Description:
 * Should be called prior to checkpoint for each GNI endpoint in use until
 * GNI_RC_SUCCESS is received. This will perform a subset of what is done in
 * GNI_EpUnbind to inspect if the GNI endpoint is idle and able to be safely
 * checkpointed. This function will not destroy any resources.
 **/
gni_return_t
	GNI_EpIdle(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * GNI_EpDestroy - Destroy logical Endpoint
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to be destroyed.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 *
 * Description:
 * This function tears down an Endpoint.
 **/
gni_return_t
	GNI_EpDestroy(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * GNI_EpPostData - Exchange datagram with a remote Endpoint
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * in_data      pointer to the data to be sent
 * data_len     size of the data to be sent
 * out_buf      buffer to receive incoming datagram
 * buf_size     size of the buffer for incoming datagram
 *
 * Returns:
 * GNI_RC_SUCCESS - Posted datagram was queued.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 * GNI_RC_ERROR_RESOURCE - Only one outstanding datagram transaction per
 *                         Endpoint is allowed.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_SIZE_ERROR - Size of datagram is too big.
 *
 * Description:
 * This function posts a datagram to be exchanged with a remote Endpoint in the CDM.
 * If the EP is unbound a datagram can be exchanged with any bound Endpoint in the CDM.
 **/
gni_return_t
	GNI_EpPostData(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *in_data,
		IN uint16_t             data_len,
		IN void                 *out_buf,
		IN uint16_t             buf_size
		);

/**
 * GNI_EpPostDataWId - Exchange datagram with a remote Endpoint, assigning an
 *                     id to the datagram.
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * in_data      pointer to the data to be sent
 * data_len     size of the data to be sent
 * out_buf      buffer to receive incoming datagram
 * buf_size     size of the buffer for incoming datagram
 * datagram_id  id associated with the datagram
 *
 * Returns:
 * GNI_RC_SUCCESS - Posted datagram was queued.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified or an invalid
 *                        value (-1) for the datagram_id was specified.
 * GNI_RC_ERROR_RESOURCE - Only one outstanding datagram transaction per
 *                         Endpoint is allowed.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_SIZE_ERROR - Size of datagram is too big.
 *
 * Description:
 * This function posts a datagram to be exchanged with a remote Endpoint in the CDM
 * and associated an Id with the datagram.
 * If the EP is unbound a datagram can be exchanged with any bound Endpoint in the CDM.
 *
 * Notes:
 * It may be useful to associated an Id with a datagram when intermixing usage of
 * bound and unbound EP's with datagrams.
 **/
gni_return_t
	GNI_EpPostDataWId(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *in_data,
		IN uint16_t             data_len,
		IN void                 *out_buf,
		IN uint16_t             buf_size,
		IN uint64_t             datagram_id
		);

/**
 * GNI_EpPostDataTest - Tests for completion of GNI_EpPostData operation
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 *
 * OUT
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 *              (This address is virtual if GNI_CDM_MODE_NTT_ENABLE).
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - Post status is returned through the second function parameter.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received
 *                     datagram.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function returns the state of the PostData transaction.
 **/
gni_return_t
	GNI_EpPostDataTest(
		IN  gni_ep_handle_t     ep_hndl,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * GNI_EpPostDataTestById - Tests for completion of GNI_EpPostData operation for
 *                          a datagram using Id
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * datagram_id  Id of datagram to test for.
 *
 * OUT
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 *              (This address is virtual if GNI_CDM_MODE_NTT_ENABLE).
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - Post status is returned through the second function parameter.
 * GNI_RC_INVALID_PARAM - An invalid EP handle or an invalid datagram_id was specified.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received
 *                     datagram.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function returns the state of the PostData transaction.
 *
 * Notes:
 * The ep handle supplied as input must be the same as that
 * used when posting the datagram using GNI_EpPostDataWId.
 **/
gni_return_t
	GNI_EpPostDataTestById(
		IN  gni_ep_handle_t     ep_hndl,
		IN  uint64_t            datagram_id,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * GNI_EpPostDataWait - Wait for the PostData transaction to complete
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * timeout      The count that this function waits, in milliseconds, for
 *              connection to complete.
 *              Set to (-1) if no timeout is desired. A timeout value of zero
 *              results in a GNI_RC_INVALID_PARAM error returned.
 *
 * OUT
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 *              (This address is virtual if GNI_CDM_MODE_NTT_ENABLE).
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - The transaction completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified or timeout was set to zero.
 * GNI_RC_TIMEOUT - The timeout expired before a datagram completion.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received datagram.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function is used to determine the result of a previously posted EpPostData
 * call on the specified Endpoint, blocking the calling thread until the completion
 * of the posted transaction or until the specified timeout expires.
 **/
gni_return_t
	GNI_EpPostDataWait(
		IN  gni_ep_handle_t     ep_hndl,
		IN  uint32_t            timeout,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * GNI_EpPostDataWaitById - Wait for the PostData transaction with a given ID to complete
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * timeout      The count that this function waits, in milliseconds, for
 *              connection to complete.
 *              Set to (-1) if no timeout is desired. A timeout value of zero
 *              results in a GNI_RC_INVALID_PARAM error returned.
 * datagram_id  Id of datagram to wait for.
 *
 * OUT
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 *              (This address is virtual if GNI_CDM_MODE_NTT_ENABLE).
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - The transaction completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified or timeout was set to zero or
 *                        an invalid datagram id was specified.
 * GNI_RC_TIMEOUT - The timeout expired before a successful completion of the transaction.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received
 *                     datagram.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function is used to determine the result of a previously posted EpPostData
 * call on the specified Endpoint and datagram Id, blocking the calling thread until the completion
 * of the posted transaction or until the specified timeout expires.
 *
 * Notes:
 * The ep handle supplied as input must be the same as that
 * used when posting the datagram using GNI_EpPostDataWId.
 **/
gni_return_t
	GNI_EpPostDataWaitById(
		IN  gni_ep_handle_t     ep_hndl,
		IN  uint64_t            datagram_id,
		IN  uint32_t            timeout,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * GNI_PostDataProbe - Probe for datagrams associated with a cdm/nic which
 *                     are in completed, timed out, or cancelled state.
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a nic associated with the cdm for which datagrams
 *              status is being probed.
 *
 * OUT
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if return value is GNI_RC_SUCCESS.
 *              (This address is virtual if GNI_CDM_MODE_NTT_ENABLE).
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if return value is
 *              GNI_RC_SUCCESS.
 *
 * Returns:
 * GNI_RC_SUCCESS - A datagram in the completed, timed out or cancelled state was found.
 *                  The remote_addr and remote_id of the datagram are
 *                  in the remote_addr and remote_id arguments.
 * GNI_RC_INVALID_PARAM - An invalid NIC handle or invalid address for remote_addr or
 *                        remote_id was specified.
 * GNI_RC_NO_MATCH - No datagram in completed, timed out, or cancelled state was found.
 *
 * Description:
 * This function returns the remote_addr and remote_id of the first datagram found in
 * completed, timed out, or canceled state for the cdm associated with the
 * input nic handle.  This function must be used in conjunction
 * with GNI_EpPostDataTest or GNI_EpPostDataWait to obtain data exchanged
 * in the datagram transaction.
 **/
gni_return_t
	GNI_PostDataProbe(
		IN  gni_nic_handle_t    nic_hndl,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * GNI_PostDataProbeById - Probe by ID for datagrams associated with a cdm/nic which
 *                         are in completed, timed out, or cancelled state.
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a nic associated with the cdm for which datagrams
 *              status is being probed.
 *
 * OUT
 * datagram_id  Id of first datagram found to be in completed, timed out, or
 *              cancelled state.  Valid only if the return value is GNI_RC_SUCCESS.
 *
 * Returns:
 * GNI_RC_SUCCESS - A datagram previously posted with a datagram_id in the completed,
 *                  timed out or cancelled state was found.
 *                  The id of the datagram is returned in the datagram_id argument.
 * GNI_RC_INVALID_PARAM - An invalid NIC handle or an invalid datagram_id address was specified.
 * GNI_RC_NO_MATCH - No datagram in completed, timed out, or cancelled state was found.
 *
 * Description:
 * This function returns the postid of the first datagram posted with a datagram_id found in
 * completed, timed out, or canceled state for the cdm associated with the
 * input nic handle.  This function must be used in conjunction
 * with GNI_EpPostDataTestById or GNI_EpPostDataWaitById to obtain data exchanged
 * in the datagram transaction.
 *
 * Note:
 * This function should be used for probing for completion of datagrams that
 * were previously posted using the GNI_EpPostDataWId function.
 **/
gni_return_t
	GNI_PostDataProbeById(
		IN  gni_nic_handle_t    nic_hndl,
		OUT uint64_t            *datagram_id
		);

/**
 * GNI_PostdataProbeWaitById - Probe by ID for datagrams associated with a cdm/nic until
 *                             a datagram in completed, timed out, or cancelled state
 *                             is found or the timeout expires.
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a nic associated with the cdm for which datagrams
 *              status is being probed.
 * timeout      The number of milliseconds to block before returning
 *              to the caller, (-1) if no time-out is desired.
 *
 * OUT
 * datagram_id  Id of first datagram found to be in completed, timed out, or
 *              cancelled state.  Valid only if the return value is GNI_RC_SUCCESS.
 *
 * Returns:
 * GNI_RC_SUCCESS - A datagram previously posted with a datagram_id in the completed,
 *                  timed out or cancelled state was found.
 *                  The id of the datagram is returned in the datagram_id argument.
 * GNI_RC_INVALID_PARAM - An invalid NIC handle or an invalid datagram_id address was specified.
 * GNI_RC_TIMEOUT - No datagram in completed, timed out, or cancelled state was found before
 *                  the timeout expired.
 *
 * Description:
 * This function returns the postid of the first datagram posted with a datagram_id found in
 * completed, timed out, or canceled state for the cdm associated with the
 * input nic handle.  This function must be used in conjunction
 * with GNI_EpPostdataTestById or GNI_EpPostdataWaitById to obtain data exchanged
 * in the datagram transaction.
 *
 * Note:
 * This function should be used for probing for completion of datagrams that
 * were previously posted using the GNI_EpPostdataWId function.
 **/
gni_return_t
	GNI_PostdataProbeWaitById(
		IN  gni_nic_handle_t    nic_hndl,
		IN  uint32_t            timeout,
		OUT uint64_t            *datagram_id
		);

/**
 * GNI_EpPostDataCancel - Cancels postdata transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 *
 * Returns:
 * GNI_RC_SUCCESS - Canceled successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 * GNI_RC_NO_MATCH      - No active postdata transaction on the ep_hndl.
 *
 * Description:
 * This function is used to cancel a postdata transaction.
 **/
gni_return_t
	GNI_EpPostDataCancel(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * GNI_EpPostDataCancelById - Cancels postdata datagram transaction with
 *                            a given Id
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * datagram_id  Id of datagram to cancel.
 *
 * Returns:
 * GNI_RC_SUCCESS - Canceled successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle or datagram id was specified.
 * GNI_RC_NO_MATCH      - No active postdata transaction on the ep_hndl.
 *
 * Description:
 * This function is used to cancel a postdata transaction.
 **/
gni_return_t
	GNI_EpPostDataCancelById(
		IN gni_ep_handle_t      ep_hndl,
		IN uint64_t             datagram_id
		);

/**
 * GNI_MemRegister - Register memory with the NIC
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a currently open NIC.
 * address      Starting address of the memory region to be registered.
 * length       Length of the memory region to be registered, in bytes.
 * dst_cq_hndl  If not NULL, it will be used to notify the local process
 *              that a remote peer has delivered data from RDMA or FMA PUT
 *              into this memory region.
 * flags        Memory attributes associated with the region
 *              (see GNI_MEM_xxx in gni_puh.h)
 * vmdh_index   Specifies the index within the pre-allocated MDD block that
 *              must be used for the registration, e.g. when set to 0 will
 *              use the first entry of the MDD block. If set to (-1) relies
 *              on GNI library to allocate the next available entry from
 *              the MDD block.
 *
 * INOUT
 * mem_hndl     The new memory handle for the region.
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully registered.
 * GNI_RC_INVALID_PARAM - One on the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The registration operation failed due to
 *                         insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_PERMISSION_ERROR - The user's buffer R/W permissions conflict with
 *                           the flags argument.
 *
 * Description:
 * This function allows a process to register a region of memory with
 * the GNI NIC. The user may specify an arbitrary size region of memory,
 * with arbitrary alignment, but the actual area of memory registered will
 * be registered on MRT block granularity (or physical page granularity if
 * MRT is not enabled for this process).
 * A memory region must consist of a single segment.
 * Using a single segment to register a memory region allows an application
 * to use a virtual address in the future transactions in and out of the
 * registered region. A single segment memory registration should be a common
 * way in which an application registers its memory.
 * A new memory handle is generated for each region of memory that
 * is registered by a process.
 * A length parameter of zero will result in a GNI_RC_INVALID_PARAM error.
 * If GNI_MEM_USE_VMDH flag is set, this function will fail if
 * GNI_SetMddResources has not been called to specify the size of the
 * MDD block to be used. If GNI_MEM_USE_VMDH flag is set, this function
 * will fail with GNI_RC_ERROR_RESOURCE return code if the vMDH entry
 * specified by vmdh_index is already in use.
 * The contents of the memory region being registered are not altered.
 * The memory region must be previously allocated by an application.
 * If failure is returned, the contents of mem_hndl are untouched.
 **/
gni_return_t
	GNI_MemRegister(
		IN    gni_nic_handle_t  nic_hndl,
		IN    uint64_t          address,
		IN    uint64_t          length,
		IN    gni_cq_handle_t   dst_cq_hndl,
		IN    uint32_t          flags,
		IN    uint32_t          vmdh_index,
		INOUT gni_mem_handle_t  *mem_hndl
		);

/**
 * GNI_MemRegisterSegments - Register memory segments with the NIC
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a currently open NIC.
 * mem_segments List of segments to be registered. Each element of the list consists
 *              of the starting address of the memory region and the length, in bytes.
 * segment_cnt  Number of segments in the mem_segments list.
 * dst_cq_hndl  If not NULL, specifies the CQ to receive events related to the
 *              transactions initiated by the remote node into this memory region.
 * flags        Memory attributes associated with the region
 *              (see GNI_MEM_xxx in gni_puh.h)
 * vmdh_index   Specifies the index within the pre-allocated MDD block that
 *              must be used for the registration, e.g. when set to 0 will
 *              use the first entry of the MDD block. If set to (-1) relies
 *              on GNI library to allocate the next available entry from
 *              the MDD block.
 *
 * INOUT
 * mem_hndl     The new memory handle for the region.
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully registered.
 * GNI_RC_INVALID_PARAM - One on the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The registration operation failed due to
 *                         insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_PERMISSION_ERROR - The user's buffer R/W permissions conflict with
 *                           the flags argument.
 *
 * Description:
 * This function allows a process to register a region of memory with
 * the Gemini NIC. The user may specify an arbitrary size region of memory,
 * with arbitrary alignment, but the actual area of memory registered will
 * be registered on MRT block granularity (or physical page granularity if
 * MRT is not enabled for this process).
 * To register a single segment GNI_MemRegister() function must be used.
 * Using multiple segments during the registration
 * imposes the requirement on an application to use an offset within
 * the registered memory region instead of a virtual address in all future
 * transactions where registered region is aligned to MRT block size (or page size
 * for non-MRT registrations).
 * A single segment memory registration should be a common way
 * an application registers its memory. A multiple segments registration
 * should be reserved for special cases.
 * A new memory handle is generated for each region of memory that
 * is registered by a process.
 * A length parameter of zero in any segment will result in a GNI_RC_INVALID_PARAM error.
 * If GNI_MEM_USE_VMDH flag is set, this function will fail if
 * GNI_SetMddResources has not been called to specify the size of the
 * MDD block to be used. If GNI_MEM_USE_VMDH flag is set, this function
 * will fail with GNI_RC_ERROR_RESOURCE return code if the vMDH entry
 * specified by vmdh_index is already in use.
 * The contents of the memory region being registered are not altered.
 * The memory region must be previously allocated by an application.
 * If failure is returned, the contents of mem_hndl are untouched.
 **/
gni_return_t
	GNI_MemRegisterSegments(
		IN    gni_nic_handle_t  nic_hndl,
		IN    gni_mem_segment_t *mem_segments,
		IN    uint32_t          segments_cnt,
		IN    gni_cq_handle_t   dst_cq_hndl,
		IN    uint32_t          flags,
		IN    uint32_t          vmdh_index,
		INOUT gni_mem_handle_t  *mem_hndl
		);


/**
 * GNI_SetMddResources - Set size of MDD block in NIC handle
 *
 * Parameters:
 * IN
 * nic_hndl     The handle for the NIC.
 * num_entries  Number of MDD entries in the block.
 *
 * Returns:
 * GNI_RC_SUCCESS - The block size was successfully specified
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function specifies the size of a contiguous block of MDD entries
 * that can be used for future memory registrations.
 **/
gni_return_t
	GNI_SetMddResources(
		IN gni_nic_handle_t     nic_hndl,
		IN uint32_t             num_entries
		);


/**
 * GNI_MemDeregister - De-register memory
 *
 * Parameters:
 * IN
 * nic_hndl  The handle for the NIC that owns the memory region
 *           being de-registered.
 * mem_hndl  Memory handle for the region.
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully de-registered.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 *
 * Description:
 * This function de-registers memory that was previously registered and unlocks
 * the associated pages from physical memory. The contents and attributes of the
 * region of memory being de-registered are not altered in any way.
 **/
gni_return_t
	GNI_MemDeregister(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_mem_handle_t     *mem_hndl
		);

/**
 * GNI_MemHndlQueryAttr - Query for memory handle attributes
 *
 * Parameters:
 * IN
 * mem_hndl  Memory handle for a registered region.
 * attr      Attribute that is being queried
 *
 * OUT
 * yesno     A pointer to a boolean return val if the attr is set
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully queried.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 *
 * Description:
 * This function returns a yes(1) or no(0) boolean value in the passed in
 * pointer. Only one attribute at a time may be tested, and uGNI will test the
 * memory handle for correctness. See gni_mem_handle_attr_t enum.
 **/
gni_return_t
	GNI_MemHndlQueryAttr(
		IN  gni_mem_handle_t            *mem_hndl,
		IN  gni_mem_handle_attr_t       attr,
		OUT int                         *yesno
		);

/**
 * GNI_RebuildMemHndl - Given one mem_hndl, build a new one with a different VMDH
 *
 * Parameters:
 * IN
 * src_mem_hndl  Memory handle for a registered region.
 * vmdh_index    New VMDH Index to apply
 *
 * OUT
 * dst_mem_hndl  New memory handle for the region on a different node
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully queried.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 * GNI_RC_INVALID_STATE - The mem_hndl wasn't updated at least once.
 *
 * Description:
 * This function returns a new memory handle that contains the same
 * address and length but with a new VMDH index. This way, the memory
 * handle exchange does not need to occur when an instance knows the
 * remote memory layout.
 **/
gni_return_t
	GNI_RebuildMemHndl (
		IN  gni_mem_handle_t    *src_mem_hndl,
		IN  uint32_t            vmdh_index,
		OUT gni_mem_handle_t    *dst_mem_hndl
		);


/**
 * GNI_MemQueryHndls - Get the next memory handle for either the nic handle or
 *                     file descriptor.  Only one of the nic_hndl or fd
 *                     parameters must be specified and valid.
 *
 * Parameters:
 * IN
 * nic_hndl      Handle of a currently open NIC.
 * fd            The file descriptor for a currently open NIC.
 *
 * IN/OUT
 * mem_hndl      If this parameter points to a valid memory handle,
 *               then return the next memory handle found.
 *
 * OUT
 * address       The address of the current memory location.
 * length        The length of the current memory location.
 *
 * Returns:
 * GNI_RC_SUCCESS - A memory handle was successfully found and returned.
 * GNI_RC_INVALID_PARAM - One or more of the parameters were invalid.
 * GNI_RC_NO_MATCH - A memory handle was not found for the supplied NIC or
 *                   a memory handle was not found after the supplied memory
 *                   handle.
 * GNI_RC_INVALID_STATE - The supplied memory handle was invalid or not found.
 *
 * Description:
 * This function returns the next available memory handle with its address
 * and length.  If an error occurs, the address and length will be zero.
 **/
gni_return_t
	GNI_MemQueryHndls(
		IN    gni_nic_handle_t  nic_hndl,
		IN    int               fd,
		INOUT gni_mem_handle_t *mem_hndl,
		OUT   uint64_t         *address,
		OUT   uint64_t         *length
		);


/**
 * GNI_CqCreate - Create Completion Queue
 *
 * Parameters:
 * IN
 * nic_hndl     The handle of the associated NIC.
 * entry_count  The minimum number of completion entries that this CQ will hold.
 * delay_count  The number of events the Gemini will allow to occur before
 *              generating an interrupt.
 *              Setting this to zero results in interrupt delivery with every event.
 *              For the user level this parameter is meaningful only when mode is
 *              set to GNI_CQ_BLOCKING
 * mode         The mode of operation of the new CQ: GNI_CQ_BLOCKING, GNI_CQ_NOBLOCK
 * handler      User supplied callback function to be run for each CQ entry received
 *              in the CQ.
 * context      User supplied pointer to be passed to the handler callback function.
 *
 * OUT
 * cq_hndl      The handle of the newly created Completion Queue.
 *
 * Returns:
 * GNI_RC_SUCCESS - A new Completion Queue was successfully created.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The Completion Queue could not be created due
 *                         to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates a new Completion Queue. The caller must specify
 * the minimum number of completion entries that the queue must contain.
 * To avoid dropped completion notifications, applications should make sure
 * that the number of operations posted on Endpoints attached to
 * a src_cq_hndl does not exceed the completion queue capacity at any time.
 *
 * Notes:
 * The handler, if specified, runs for each CQ entry that is received into
 * the CQ.  The handler is supplied with two arguments, a pointer to the
 * CQ entry, and a pointer to the context provided at CQ creation.
 * The handler is invoked at some time between when the CQ entry is deposited
 * into the CQ and the return of GNI_CqGetEvent or GNI_CqWaitEvent with
 * a status of either GNI_RC_SUCCESS or GNI_RC_TRANSACTION_ERROR.
 * Use of callback functions does not relieve the  user of the need to call
 * GNI_CqGetEvent or GNI_CqWaitEvent for each event deposited into the CQ.
 *
 * Completion Queues may be used for receipt of locally generated events
 * such as those arising from GNI_Post style transactions, etc. or
 * may be used for receipt of remote events, but not both.
 **/
gni_return_t
	GNI_CqCreate(
		IN  gni_nic_handle_t    nic_hndl,
		IN  uint32_t            entry_count,
		IN  uint32_t            delay_count,
		IN  gni_cq_mode_t       mode,
		IN  void                (*handler)(gni_cq_entry_t *,void *),
		IN  void                *context,
		OUT gni_cq_handle_t     *cq_hndl
		);

/**
 * GNI_CqDestroy - Destroy Completion queue
 *
 * Parameters:
 * IN
 * cq_hndl    The handle for the Completion Queue to be destroyed.
 *
 * Returns:
 * GNI_RC_SUCCESS        - The CQ was successfully destroyed.
 * GNI_RC_INVALID_PARAM  - One or more of the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The CQ could not be destroyed because one or
 *                         more Endpoint instances are still associated with it.
 *
 * Description:
 * This function destroys a specified Completion Queue.
 * If any Endpoints are associated with the CQ, the CQ is not destroyed and
 * an error is returned.
 **/
gni_return_t
	GNI_CqDestroy(
		IN gni_cq_handle_t      cq_hndl
		);

/**
 * GNI_PostRdma - Post RDMA transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of a local Endpoint.
 * post_descr   Pointer to a descriptor to be posted.
 *
 * Returns:
 * GNI_RC_SUCCESS - The descriptor was successfully posted.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid.
 * GNI_RC_ALIGNMENT_ERROR - Posted source or destination data pointers or
 *                          data length are not properly aligned.
 * GNI_RC_ERROR_RESOURCE - The transaction request could not be posted due
 *                         to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_PERMISSION_ERROR - The user's buffer R/W permissions conflict with
 *                           the access type.
 *
 * Description:
 * This function adds a descriptor to the tail of the RDMA queue and
 * returns immediately.
 *
 **/
gni_return_t
	GNI_PostRdma(
		IN gni_ep_handle_t              ep_hndl,
		IN gni_post_descriptor_t        *post_descr
		);

/**
 * GNI_PostFma - Post FMA transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of a local Endpoint.
 * post_descr   Pointer to a descriptor to be posted.
 *
 * Returns:
 * GNI_RC_SUCCESS - The descriptor was successfully posted.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid.
 * GNI_RC_ALIGNMENT_ERROR - Posted source or destination data pointers or
 *                          data length are not properly aligned.
 * GNI_RC_ERROR_RESOURCE - The transaction request could not be posted due
 *                         to insufficient resources.
 *
 * Description:
 * This function executes a data transaction (Put, Get or AMO) by
 * storing into the directly mapped FMA Window to initiate a series of
 * FMA requests.
 * It returns before the transaction is confirmed by the remote NIC.
 * Zero-length FMA Put operations are supported. Zero-length FMA Get and
 * zero-length FMA AMO operations are not supported.
 *
 **/

gni_return_t
	GNI_PostFma(
		IN gni_ep_handle_t              ep_hndl,
		IN gni_post_descriptor_t        *post_descr
		);

/**
 * GNI_PostCqWrite - Post a CQ Write transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of a local Endpoint.
 * post_descr   Pointer to a descriptor to be posted.
 *
 * Returns:
 * GNI_RC_SUCCESS - The descriptor was successfully posted.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid; .
 * GNI_RC_RESOUCE_ERROR - Insufficient resources were available to
 *                        initialize the endpoint.
 *
 * Description:
 * This function executes a cqwrite to a remote CQ.
 * It returns before the transaction is confirmed by the remote NIC.
 *
 **/
gni_return_t
	GNI_PostCqWrite(
		IN gni_ep_handle_t              ep_hndl,
		IN gni_post_descriptor_t        *post_descr
		);

/**
 * GNI_GetCompleted - Get next completed descriptor
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 * event_data   The event returned by CqGetEvent function.
 *
 * OUT
 * post_desc    Address of the descriptor that has completed.
 *
 * Returns:
 * GNI_RC_SUCCESS - A completed descriptor was returned with a successful
 *                  completion status.
 * GNI_RC_DESCRIPTOR_ERROR - If the corresponding post queue (FMA, RDMA or AMO)
 *                           is empty, the descriptor pointer is set to NULL,
 *                           otherwise, a completed descriptor is returned with
 *                           an error completion status.
 * GNI_RC_INVALID_PARAM - The CQ handle was invalid.
 * GNI_RC_TRANSACTION_ERROR - A completed descriptor was returned with a
 *                            network error status.
 *
 * Description:
 * This function gets the descriptor from the corresponding post queue.
 * The descriptor is removed from the head of the queue and the address
 * of the descriptor is returned.
 *
 **/
gni_return_t
	GNI_GetCompleted(
		IN  gni_cq_handle_t             cq_hndl,
		IN  gni_cq_entry_t              event_data,
		OUT gni_post_descriptor_t       **post_descr
		);

/**
 * GNI_CqGetEvent - Get next event
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 *
 * OUT
 * event_data   A new event entry data, if the return status indicates success.
 *              Undefined otherwise.
 *
 * Returns:
 * GNI_RC_SUCCESS - A completion entry was found on the Completion Queue.
 * GNI_RC_NOT_DONE - No new completion entries are on the Completion Queue.
 * GNI_RC_INVALID_PARAM - The Completion Queue handle was invalid.
 * GNI_RC_ERROR_RESOURCE - CQ is in an overrun state and CQ events may
 *                         have been lost.
 * GNI_RC_TRANSACTION_ERROR - A network error was encountered in processing a transaction.
 *
 * Description:
 * This function polls the specified Completion Queue for a completion entry.
 * If a completion entry is found, it returns the event data stored in the entry.
 * CqGetEvent is a non-blocking call. It is up to the calling process to
 * subsequently invoke the appropriate function to de-queue the completed descriptor.
 * CqGetEvent only de-queues the completion entry from the Completion Queue.
 *
 **/
gni_return_t
	GNI_CqGetEvent(
		IN  gni_cq_handle_t     cq_hndl,
		OUT gni_cq_entry_t      *event_data
		);

/**
 * GNI_CqWaitEvent - Wait for the next event
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 * timeout      The number of milliseconds to block before returning
 *              to the caller, (-1) if no time-out is desired.
 *
 * OUT
 * event_data   A new event entry data, if the return status indicates success.
 *              Undefined otherwise.
 *
 * Returns:
 * GNI_RC_SUCCESS - A completion entry was found on the Completion Queue.
 * GNI_RC_TIMEOUT - The request timed out and no completion entry was found.
 * GNI_RC_INVALID_PARAM - The Completion Queue handle was invalid.
 * GNI_RC_ERROR_RESOURCE - The Completion Queue was not created in
 *                         the GNI_CQ_BLOCKING mode.
 * GNI_RC_TRANSACTION_ERROR - A network error was encountered in processing a transaction.
 *
 * Description:
 * This function polls the specified Completion Queue for a completion entry.
 * If a completion entry was found, it immediately returns event data.
 * If no completion entry is found, the caller is blocked until a completion
 * entry is generated, or until the timeout value expires.
 * The Completion Queue must be created with the GNI_CQ_BLOCKING mode set
 * in order to be able to block on it.
 *
 **/
gni_return_t
	GNI_CqWaitEvent(
		IN  gni_cq_handle_t     cq_hndl,
		IN  uint64_t            timeout,
		OUT gni_cq_entry_t      *event_data
		);

/**
 * GNI_CqVectorWaitEvent - Wait for the next event on multiple CQs
 *
 * Parameters:
 * IN
 * cq_hndl      Array of Completion Queue handles.
 * num_cqs      Number of Completion Queue handles.
 * timeout      The number of milliseconds to block before returning
 *              to the caller, (-1) if no time-out is desired.
 *
 * OUT
 * event_data   A new event entry data, if the return status indicates success.
 *              Undefined otherwise.
 * which        Array index for the CQ which returned an event (or error).
 *
 * Returns:
 * GNI_RC_SUCCESS - A completion entry was found on the Completion Queue.
 * GNI_RC_TIMEOUT - The request timed out and no completion entry was found.
 * GNI_RC_NOT_DONE - The Completion Queue handle had the interrupt mask set and
 *                   no event was processed.
 * GNI_RC_INVALID_PARAM - One of the Completion Queue handles was invalid.
 * GNI_RC_ERROR_RESOURCE - One of the Completion Queues was not created in
 *                         the GNI_CQ_BLOCKING mode.
 * GNI_RC_TRANSACTION_ERROR - A network error was encountered in processing a transaction.
 * GNI_RC_ERROR_NOMEM - No memory was available for the allocation of the cq
 *                      descriptor or event pointers.
 *
 * Description:
 * This function polls the specified Completion Queues for a completion entry.
 * If a completion entry was found, it immediately returns event data.
 * If no completion entry is found, the caller is blocked until a completion
 * entry is generated, or until the timeout value expires.
 * The Completion Queues must be created with the GNI_CQ_BLOCKING mode set
 * in order to be able to block on it.
 *
 **/
gni_return_t
	GNI_CqVectorWaitEvent(
		IN  gni_cq_handle_t     *cq_hndls,
		IN  uint32_t            num_cqs,
		IN  uint64_t            timeout,
		OUT gni_cq_entry_t      *event_data,
		OUT uint32_t            *which
		);

/**
 * GNI_CqVectorMonitor - Monitor multiple CQs for the next event
 *
 * Parameters:
 * IN
 * cq_hndl      Array of Completion Queue handles.
 * num_cqs      Number of Completion Queue handles.
 * timeout      The number of milliseconds to block before returning
 *              to the caller, (-1) if no time-out is desired.
 *
 * OUT
 * which        Array index for the CQ which returned an event (or error).
 *
 * Returns:
 * GNI_RC_SUCCESS - A completion entry was found on the Completion Queue.
 * GNI_RC_TIMEOUT - The request timed out and no completion entry was found.
 * GNI_RC_NOT_DONE - The Completion Queue handle had the interrupt mask set and
 *                   no event was processed.
 * GNI_RC_INVALID_PARAM - One of the Completion Queue handles was invalid.
 * GNI_RC_ERROR_RESOURCE - One of the Completion Queues was not created in
 *                         the GNI_CQ_BLOCKING mode.
 * GNI_RC_ERROR_NOMEM - No memory was available for the allocation of the cq
 *                      descriptor or event pointers.
 *
 * Description:
 * This function polls the specified Completion Queues for a completion entry.
 * If a completion entry was found, it immediately returns the array index for the CQ.
 * If no completion entry is found, the caller is blocked until a completion
 * entry is generated, or until the timeout value expires.
 * The Completion Queues must be created with the GNI_CQ_BLOCKING mode set
 * in order to be able to block on it.
 *
 **/
gni_return_t
	GNI_CqVectorMonitor(
		IN  gni_cq_handle_t     *cq_hndls,
		IN  uint32_t            num_cqs,
		IN  uint64_t            timeout,
		OUT uint32_t            *which
		);

/**
 * GNI_CqInterruptMask - Increment the interrupt mask for the completion queue handle.
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 *
 * Returns:
 * GNI_RC_SUCCESS - The interrupt mask was incremented successfully.
 * GNI_RC_ERROR_RESOURCE - The interrupt mask was not allocated for
 *                         the Completion Queue.
 * GNI_RC_NOT_DONE - The interrupt mask was not incremented.
 * GNI_RC_INVALID_PARAM - The Completion Queue handle was invalid or the
 *                        Completion Queue was not created in GNI_CQ_BLOCKING
 *                        mode.
 *
 * Description:
 * This function increments the interrupt mask for the specified Completion Queue.
 *
 **/
gni_return_t
	GNI_CqInterruptMask(
		IN gni_cq_handle_t cq_hndl
		);

/**
 * GNI_CqInterruptUnmask - Decrement the interrupt mask for the completion queue handle.
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 *
 * Returns:
 * GNI_RC_SUCCESS - The interrupt mask was decremented successfully.
 * GNI_RC_ERROR_RESOURCE - The interrupt mask was not allocated for
 *                         the Completion Queue.
 * GNI_RC_NOT_DONE - The interrupt mask was not decremented.
 * GNI_RC_INVALID_PARAM - The Completion Queue handle was invalid or the
 *                        Completion Queue was not created in GNI_CQ_BLOCKING
 *                        mode.
 *
 * Description:
 * This function decrements the interrupt mask for the specified Completion Queue.
 *
 **/
gni_return_t
	GNI_CqInterruptUnmask(
		IN gni_cq_handle_t cq_hndl
		);

/**
 * GNI_CqTestEvent - Check if there is an event on a Completion Queue
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 *
 *
 * Returns:
 * GNI_RC_SUCCESS - A completion entry was found on the Completion Queue.
 * GNI_RC_NOT_DONE - No new completion entries are on the Completion Queue.
 * GNI_RC_INVALID_PARAM - The Completion Queue handle was invalid.
 * GNI_RC_ERROR_RESOURCE - CQ is in an overrun state and CQ events may have been lost.
 *
 * Description:
 * This function polls the specified Completion Queue for a completion entry.
 * If a completion entry is found, it return GNI_RC_SUCCESS, unless the
 * CQ is overrun, in which case GNI_RC_ERROR_RESOURCE.  If no completion entry
 * is found GNI_RC_NOT_DONE is returned.
 *
 * No processing of new entries is performed by this function.
 *
 **/
gni_return_t
	GNI_CqTestEvent(
		IN gni_cq_handle_t      cq_hndl
		);

/**
 * GNI_CqErrorStr - Decode error status into a string for a CQ Entry
 *
 * Parameters:
 * IN
 * entry           CQ entry with error status to be decoded
 * len             Length of the buffer in bytes
 *
 * OUT
 * buffer          Pointer to the buffer where the error code will be
 *                 returned.
 *
 * Returns:
 * GNI_RC_SUCCESS - The entry was successfully decoded.
 * GNI_RC_INVALID_PARAM - Invalid input parameter
 * GNI_RC_SIZE_ERROR - Supplied buffer is too small to contain the error
 *                     code
 *
 * Description:
 * This function decodes the error status encoded in a CQ Entry
 * by the hardware.
 *
 **/
gni_return_t
	GNI_CqErrorStr(
		IN  gni_cq_entry_t      entry,
		OUT void                *buffer,
		IN  uint32_t            len
		);

/**
 * GNI_CqErrorRecoverable - Deduce error status as recoverable for a CQ Entry
 *
 * Parameters:
 * IN
 * entry           CQ entry with error status to be decoded
 *
 * OUT
 * recoverable     Pointer to the integer flag that will contain the result.
 *
 * Returns:
 * GNI_RC_SUCCESS - The entry was successfully decoded.
 * GNI_RC_INVALID_PARAM - Invalid input parameter
 * GNI_RC_INVALID_STATE - CQ entry translates to an undefined state
 *
 * Description:
 * This function translates any error status encoded in a CQ Entry by
 * the hardware into a recoverable/unrecoverable flag for application
 * usage.
 *
 **/
gni_return_t
	GNI_CqErrorRecoverable(
		IN  gni_cq_entry_t      entry,
		OUT uint32_t            *recoverable
		);

/**
 * GNI_SmsgBufferSizeNeeded - Return amount of memory required for short message
 *                            resources given parameters in an input short
 *                            message attributes structure
 * IN
 * smsg_attr            pointer to short message attributes structure
 *
 * OUT
 * size                 size in bytes required for the short message buffer
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 * This utility function provides an application with a way to determine the
 * amount of memory needs to be allocated for short messaging resources.  The
 * msg_buffer, buff_size, mem_hndl, and mbox_offset fields in the input
 * smsg_attr structure do not need to be defined.
 **/
gni_return_t
	GNI_SmsgBufferSizeNeeded(
		IN  gni_smsg_attr_t     *smsg_attr,
		OUT unsigned int        *size
		);

/**
 * GNI_SmsgInit - Initialize short messaging resources
 * IN
 * ep_hndl              The handle of the Endpoint.
 * local_smsg_attr      Local parameters for short messaging
 * remote_smsg_attr     Remote parameters for short messaging provided by peer
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_INVALID_STATE - Endpoind is not bound
 * GNI_RC_ERROR_NOMEM - Insufficient memory to allocate short message
 *                      internal structures
 * Description:
 * This function configures the short messaging protocol on the given Endpoint.
 **/
gni_return_t
	GNI_SmsgInit(
		IN gni_ep_handle_t      ep_hndl,
		IN gni_smsg_attr_t      *local_smsg_attr,
		IN gni_smsg_attr_t      *remote_smsg_attr
		);

/**
 * GNI_SmsgSetDeliveryMode - Configures SMSG delivery mode.
 *
 * IN
 * nic_handle           The NIC handle to alter.
 * dlvr_mode            The new SMSG delivery mode.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid NIC handle specified or
 *                        the delivery mode is invalid.
 *
 * Description:
 * This functions sets the SMSG delivery mode for SMSG transactions.
 **/
gni_return_t
	GNI_SmsgSetDeliveryMode(
		IN gni_nic_handle_t        nic_handle,
		IN uint16_t                 dlvr_mode
		);

/**
 * GNI_SmsgSend - Send short message
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 * header       Pointer to the header of a message.
 * header_length Length of the header in bytes.
 * data         Pointer to the payload of the message.
 * data_length  Length of the payload in byte.
 * msg_id       Identifier for application to track transaction.
 *              Only valid for short messaging using MBOX_PERSISTENT type,
 *              otherwise ignored.
 *
 * Returns:
 * GNI_RC_SUCCESS - The message was successfully sent.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or
 *                        the Endpoint is not initialized for short messaging.
 * GNI_RC_NOT_DONE - No credits available to send the message
 * GNI_RC_ERROR_RESOURCE - The total size of the header plus data exceeds
 *                         the maximum short message size given in GNI_SmsgInit.
 *
 * Description:
 * This function sends a message to the remote peer, by copying it into the
 * pre-allocated remote buffer space using the FMA mechanism.  It returns
 * before the delivery is confirmed by the remote NIC.  With MBOX_PERSISTENT
 * type system attempts to re-transmit for certain transaction failures.  This
 * is a non-blocking call.  Completion events are delivered to local and remote
 * completion queues for each send.
 *
 * Note:
 * The SMSG interface uses the FMA mechanism with adaptive routing.  This
 * allows SMSG sends to arrive out of order at the target node.  Due to this,
 * it is possible for completion events to be delivered to the remote
 * completion queue while GNI_SmsgGetNext reports that no new messages are
 * available.  To handle this case when using remote events to detect the
 * arrival of SMSG sends, be sure to clear all messages from an endpoint using
 * GNI_SmsgGetNext after receiving each remote completion event.
 *
 **/
gni_return_t
	GNI_SmsgSend(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *header,
		IN uint32_t             header_length,
		IN void                 *data,
		IN uint32_t             data_length,
		IN uint32_t             msg_id
		);

/**
 * GNI_SmsgSendWTag - Send short message with a tag
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 * header       Pointer to the header of a message.
 * header_length Length of the header in bytes.
 * data         Pointer to the payload of the message.
 * data_length  Length of the payload in byte.
 * msg_id       Identifier for application to track transaction.
 *              Only valid for short messaging using MBOX_PERSISTENT type
 * tag          Tag associated with the short message.
 *
 * Returns:
 * GNI_RC_SUCCESS - The message was successfully sent.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or
 *                        the Endpoint is not initialized for short messaging.
 * GNI_RC_NOT_DONE - No credits available to send the message
 * GNI_RC_ERROR_RESOURCE - The total size of the header plus data exceeds
 *                         the maximum short message size defined by GNI_SMSG_MAX_SIZE.
 *
 * Description:
 * This function sends a tagged message to the remote peer, by copying it into
 * the pre-allocated remote buffer space using the FMA mechanism.
 * It returns before the delivery is confirmed by the remote NIC.
 * With MBOX_PERSISTENT type system attempts to re-transmit
 * for certain transaction failures.
 * This is a non-blocking call.
 *
 **/

gni_return_t
	GNI_SmsgSendWTag(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *header,
		IN uint32_t             header_length,
		IN void                 *data,
		IN uint32_t             data_length,
		IN uint32_t             msg_id,
		IN uint8_t              tag
		);

/**
 * GNI_SmsgGetNext - Get next available short message
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 *
 * OUT
 * header       Pointer to the header of the newly arrived message.
 *
 * Returns:
 * GNI_RC_SUCCESS - The new message is successfully arrived.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or the Endpoint
 *                        is not initialized for short messaging
 * GNI_RC_NOT_DONE - No new messages available.
 * GNI_RC_INVALID_STATE - The SMSG connection has entered an invalid state.
 *
 * Description:
 * This function returns a pointer to the header of the newly arrived message and
 * makes this message current. An application may decide to copy the message out
 * of the mailbox or process it immediately. This is a non-blocking call.
 *
 **/
gni_return_t
	GNI_SmsgGetNext(
		IN  gni_ep_handle_t     ep_hndl,
		OUT void                **header
		);

/**
 * GNI_SmsgGetNextWTag  -   Get next available short message if input tag
 *                          matches that of the short message.
 *
 * Parameters:
 * IN
 * ep_hndl       Instance of an Endpoint.
 *
 * OUT
 * header   Pointer to the header of the newly arrived message.
 *          event value.
 * tag      On input, pointer to value of remote event to be matched.
 *          A wildcard value of GNI_SMSG_ANY_TAG can be used to match any
 *          tag value of the incoming message.
 *          The value is set to that of the matching remote event
 *          on output.
 *
 * Returns:
 * GNI_RC_SUCCESS - The new message is successfully arrived.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or the Endpoint is
 *            not in GNI_EP_STATE_CONNECTED state.
 * GNI_RC_NOT_DONE - No new messages available.
 * GNI_RC_NO_MATCH - Message available, but tag of message doesn't match
 *                   the value supplied in the tag argument.
 * GNI_RC_INVALID_STATE - The SMSG connection has entered an invalid state.
 *
 * Description:
 * This function returns a pointer to the header of the newly arrived message and
 * makes this message current if the input tag matches the tag of the newly
 * arrived message. An application may decide to copy the message header out
 * of the mailbox or process the header immediately. This is a non-blocking call.
 *
 **/
gni_return_t
	GNI_SmsgGetNextWTag(
		IN  gni_ep_handle_t     ep_hndl,
		OUT void                **header,
		OUT uint8_t             *tag
		);


/**
 * GNI_SmsgRelease - Release current message
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 *
 * Returns:
 * GNI_RC_SUCCESS - The current message is successfully released.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or the Endpoint
 *                        is not initialized for short messaging
 * GNI_RC_NOT_DONE - There is no current message.
 *                   The GetNext function must return GNI_RC_SUCCESS before
 *                   calling this function.
 *
 * Description:
 * This function releases the current message buffer. It must be called only
 * after GetNext has returned GNI_RC_SUCCESS. This is a non-blocking call.
 * The message returned by the GetNext function must be copied out or processed
 * prior to making this call.
 *
 **/
gni_return_t
	GNI_SmsgRelease(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * GNI_MsgqInit - Creates the resources required for the shared message queue.
 *
 * Parameters:
 * IN
 * nic_hndl     The handle of the attached NIC device to use in the message
 *              queue system.
 * rcv_cb       A callback function for handling received messages.
 * cb_data      User data to pass to the receive callback function.
 * snd_cq       A send CQ for use with the MSGQ.
 * attrs        The attributes for message queue system initialization.
 *
 * OUT
 * msgq_hndl    A handle for the created message queue resources.
 *
 * Returns:
 * GNI_RC_SUCCESS          Message Queue intialization succeeded.
 * GNI_RC_INVALID_PARAM    An invalid parameter was provided.
 * GNI_RC_ERROR_NOMEM      There was insufficient memory available to attach to
 *                         the shared memory region.
 * GNI_RC_INVALID_STATE    The attributes provided do not match the existing
 *                         message queue attributes or all instances were not
 *                         ready to attach the the shared memory area.
 * GNI_RC_PERMISSION_ERROR The hugetlbfs filesystem was not available.
 *
 * Description:
 *
 * GNI_MsgqInit uses the attributes provided to attach to a shared memory
 * region used for the message queue system.  The shared region is then
 * registered with a private receive completion queue and the provided message
 * queue attributes are stored as control information in the shared area.
 **/
gni_return_t
	GNI_MsgqInit(
		IN  gni_nic_handle_t            nic_hndl,
		IN  gni_msgq_rcv_cb_func        *rcv_cb,
		IN  void                        *cb_data,
		IN  gni_cq_handle_t             snd_cq,
		IN  gni_msgq_attr_t             *attrs,
		OUT gni_msgq_handle_t           *msgq_hndl
		);

/**
 * GNI_MsgqRelease - Frees all resources associated with a message queue handle.
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 *
 * Returns:
 * GNI_RC_SUCCESS       All message queue resources were successfully freed.
 * GNI_RC_INVALID_PARAM An invalid parameter was provided.
 * GNI_RC_NOT_DONE      There are outstanding message queue transactions.
 *
 * Description:
 *
 * GNI_MsgqRelease frees all resources created during GNI_MsgqInit.  All
 * transactions must be completed (or all end-points destroyed) before calling
 * GNI_MsgqRelease.
 **/
gni_return_t
	GNI_MsgqRelease(
		IN gni_msgq_handle_t    msgq_hndl
		);

/**
 * GNI_MsgqIdle - prepare the message queue for checkpoint
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 *
 * Returns:
 * GNI_RC_SUCCESS       All message queue resources are idle.
 * GNI_RC_INVALID_PARAM An invalid parameter was provided.
 * GNI_RC_NOT_DONE      There are outstanding message queue transactions.
 *
 * Description:
 * If program has used GNI_MsgqInit, this function should be called prior to the
 * checkpoint until GNI_RC_SUCCESS is received. This will perform a subset of
 * what is done in GNI_MsgqRelease to inspect if the message queue is idle and
 * able to be safely checkpointed. This function will not destroy any resources.
 * Because the msgq is a shared resource, higher level libaries are expected to
 * prevent further sends by issuing a barrier prior to calling this function.
 **/
gni_return_t
	GNI_MsgqIdle(
		IN gni_msgq_handle_t    msgq_hndl
		);

/**
 * GNI_MsgqGetConnAttrs - Assigns connection resources to a remote end-point
 *              address and returns attributes for completing the connection.
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 * pe_addr      The PE address of the remote end-point to assign connection
 *              resources to (virtual if the NTT is enabled).
 *
 * OUT
 * attrs        The attributes needed to establish a message queue connection
 *              on the remote end-point.
 * attrs_size   (Optional) returns size of attrs that was written
 *
 * Returns:
 * GNI_RC_SUCCESS          Connection resources were assigned to the PE address.
 * GNI_RC_INVALID_PARAM    An invalid parameter was provided.
 * GNI_RC_INVALID_STATE    Connection resources have already been assigned to
 *                         the PE address provided.
 * GNI_RC_ERROR_RESOURCE   All connection resources have already been assigned.
 * GNI_RC_PERMISSION_ERROR Message queue Initialization has not completed
 *                         or teardown has been started.
 *
 * Description:
 *
 * The remote PE address provided is assigned to an SMSG control structure and
 * mailbox for use in an inter-node connection.  An attribute structure
 * describing the assigned resources is then returned.  The attributes must be
 * traded with the remote end-point to establish the connection.
 **/
gni_return_t
	GNI_MsgqGetConnAttrs(
		IN  gni_msgq_handle_t   msgq_hndl,
		IN  uint32_t            pe_addr,
		OUT gni_msgq_ep_attr_t  *attrs,
		OUT uint32_t            *attrs_size
		);

/**
 * GNI_MsgqConnect - Completes an inter-node message queue connection.
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 * pe_addr      The PE address of the remote end-point to assign connection
 *              resources to (virtual if the NTT is enabled).
 * attrs        The connection attributes received from the remote node.
 *
 * Returns:
 * GNI_RC_SUCCESS          The connection was established.
 * GNI_RC_INVALID_PARAM    An invalid parameter was provided.
 * GNI_RC_NO_MATCH         The associated connection resources could not be
 *                         found.
 * GNI_RC_INVALID_STATE    A connection to the PE specfied by the attribute
 *                         structure has already been established.
 * GNI_RC_PERMISSION_ERROR Message queue Initialization has not completed
 *                         or teardown has been started.
 *
 * Description:
 *
 * The remote PE address provided is used to look up the shared connection
 * resources that were assigned during GNI_MsgqGetConnAttrs. The connection is
 * completed by adding the remote end-point attributes provided to the
 * connection resources.
 **/
gni_return_t
	GNI_MsgqConnect(
		IN gni_msgq_handle_t    msgq_hndl,
		IN uint32_t             pe_addr,
		IN gni_msgq_ep_attr_t   *attrs
		);

/**
 * GNI_MsgqConnRelease - De-assign connection resources from a remote PE.
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 * pe_addr      the remote PE address of the message queue connection to free.
 *
 * Returns:
 * GNI_RC_SUCCESS       Connection resources were freed from the PE address.
 * GNI_RC_INVALID_PARAM An invalid parameter was provided.
 * GNI_RC_NO_MATCH      No message queue connection for the PE address was
 *                      found.
 * GNI_RC_NOT_DONE      There are outstanding transactions on the connection.
 *
 * Description:
 *
 * GNI_MsgqConnRelease releases the connection resources assigned to a PE
 * address during GNI_MsgqGetConnAttrs.  All outstanding transactions on the
 * connection must be completed before calling GNI_MsgqConnRelease.  Connection
 * resources freed in this call may be re-assigned with a call to
 * GNI_MsgqGetConnAttrs.
 **/
gni_return_t
	GNI_MsgqConnRelease(
		IN gni_msgq_handle_t    msgq_hndl,
		IN uint32_t             pe_addr
		);

/**
 * GNI_MsgqSend - Sends a message using the message queue system.
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 * ep_hndl      The end-point describing the target for the send.
 * hdr          The message header.
 * hdr_len      The message header length.
 * msg          The message data.
 * msg_len      The message data length.
 * msg_id       The message identifier (returned in a local completion event).
 * msg_tag      The message tag (sent with message data).
 *
 * Returns:
 * GNI_RC_SUCCESS       The send completed successfully.
 * GNI_RC_INVALID_PARAM An invalid parameter was provided.
 * GNI_RC_NO_MATCH      No message queue connection for the end-point was found.
 * GNI_RC_NOT_DONE      No credits are available to send the message.
 * GNI_RC_SIZE_ERROR    The message size exceeds the maximum message size.
 * GNI_RC_INVALID_STATE Connection resources exist but are inactive.
 *
 * Description:
 *
 * The end-point provided is used to look up a message queue connection and
 * target instance information to perform the send.  The completion queue in
 * the provided EP handle is also used for completion notification.
 **/
gni_return_t
	GNI_MsgqSend(
		IN gni_msgq_handle_t    msgq_hndl,
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *hdr,
		IN uint32_t             hdr_len,
		IN void                 *msg,
		IN uint32_t             msg_len,
		IN uint32_t             msg_id,
		IN uint8_t              msg_tag
		);

/**
 * GNI_MsgqProgress - Processes received message queue messages.
 *
 * Parameters:
 * IN
 * msgq_hndl    The handle for the message queue to use for the operation.
 * timeout      The number of milliseconds to block waiting for each message.
 *
 * Returns:
 * GNI_RC_SUCCESS        All messages were processed.
 * GNI_RC_INVALID_PARAM  An invalid parameter was provided.
 * GNI_RC_NOT_DONE       Messages could still be available for processing.
 * GNI_RC_ERROR_RESOURCE The send CQ is full.
 * GNI_RC_INVALID_STATE  An unexpected CQ event was received.
 * GNI_RC_ERROR_NOMEM    Insufficient memory was available to complete the
 *                       operation.
 *
 * Description:
 *
 * The internal receive completion queue is polled for events.  When an event
 * is received the registered receive callback function is called with the
 * message data.  If the user provided callback function returns true,
 * GNI_MsgqProgress will attempt to process another message.  If the callback
 * returns false, GNI_MsgqProgress will return immediately.
 **/
gni_return_t
	GNI_MsgqProgress(
		IN gni_msgq_handle_t    msgq_hndl,
		IN uint32_t             timeout
		);

/**
 * GNI_MsgqSize - Returns the size of the MSGQ allocated shared buffer given a
 *                set of initialization parameters.
 *
 * Parameters:
 * IN
 * attrs        The attributes for message queue system initialization.
 *
 * OUT
 * size         The size, in bytes, required to create the Msgq with the given
 *              set of parameters.
 *
 * Returns:
 * GNI_RC_SUCCESS       The operation completed successfully.
 * GNI_RC_INVALID_PARAM An invalid parameter was provided.
 *
 * Description:
 *
 * Returns the size of the Msgq allocated shared buffer given a set of
 * initialization parameters.  The size is specified in bytes.  The size is
 * always a multiple of the configured hugetlbfs hugepage size.
 **/
gni_return_t
	GNI_MsgqSize(
		IN  gni_msgq_attr_t     *attrs,
		OUT uint32_t            *size
		);

/**
 * GNI_SmsgsSetMaxRetrans - Configures SMSG max retransmit count.
 *
 * IN
 * nic_handle           The NIC handle to alter.
 * max_retrans          The new SMSG max retransmit count.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid NIC handle specified.
 *
 * Description:
 * This functions sets the maximum retransmit counts for SMSG transactions.
 * EPs associated with the NIC handle provided will give up retransmitting SMSG
 * transactions and return GNI_RC_TRANSACTION_ERROR when the retransmit count
 * has been reached.
 **/
gni_return_t
	GNI_SmsgSetMaxRetrans(
		IN gni_nic_handle_t     nic_handle,
		IN uint16_t             max_retrans
		);

/**
 * GNI_SubscribeErrors - Subscribe to error events on associated NIC.
 *
 * Parameters:
 * IN
 * nic_handle           The handle of the associated NIC.
 * device_id            The device identifier, for privileged mode (when NULL is passed in for nic_handle).
 * mask                 The error mask with corresponding bits set for notification.
 * EEQ_size             Size of the EEQ. The queue size will be a default of 64 entries if 0 is passed in.
 *
 * OUT
 * err_handle           The handle of the subscribed error events.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 *                           Or, a non-privileged user is trying to subscribe without a communication domain.
 * GNI_RC_NO_MATCH         - Specified device_id does not exists.
 * GNI_RC_ERROR_RESOURCE   - The event queue could not be created due to insufficient resources.
 * GNI_RC_ERROR_NOMEM      - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates an error event queue. When this function
 * returns, events start reporting immediately. For privileged users,
 * IE: super-users, they can pass in NULL for nic_handle. This
 * signifies to use the passed in device_id instead. This allows
 * privileged users subscribe to errors without a CDM being attached.
 * By default, if no nic_handle is passed in, then errors will be
 * captured for all ptags.
 *
 * Also, the mask value can be a bitwise OR of the error categories as
 * defined by the GNI_ERRMASK_* flags found in gni_pub.h.
 *
 **/
gni_return_t
	GNI_SubscribeErrors(
		IN  gni_nic_handle_t    nic_handle,
		IN  uint32_t            device_id,
		IN  gni_error_mask_t    mask,
		IN  uint32_t            EEQ_size,
		OUT gni_err_handle_t    *err_handle
		);

/**
 * GNI_ReleaseErrors - Release error event notification.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE      - A thread is still waiting on the event queue.
 *
 * Description:
 * This function releases the error event notification and cleans up
 * the memory resources for the event queue.
 *
 **/
gni_return_t
	GNI_ReleaseErrors(
		IN gni_err_handle_t     err_handle
		);

/**
 * GNI_GetErrorMask - Get the currently set error mask.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 *
 * OUT
 * mask                 The pointer to copy the mask value to.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 * The error mask is used to match error events, and decide if the
 * subscriber wants an event delivered. This is a convenience
 * function.
 *
 **/
gni_return_t
	GNI_GetErrorMask(
		IN  gni_err_handle_t    err_handle,
		OUT gni_error_mask_t    *mask
		);

/**
 * GNI_SetErrorMask - Set a new error mask for matching events.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * mask_in              The error mask with corresponding bits set for notification.
 * mask_out             The pointer to copy the pre-set mask value to.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 * Set a new error mask used to match for error event delivery.
 *
 **/
gni_return_t
	GNI_SetErrorMask(
		IN gni_err_handle_t     err_handle,
		IN gni_error_mask_t     mask_in,
		IN gni_error_mask_t     *mask_out
		);

/**
 * GNI_GetErrorEvent - Get an error event, if available.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * event                The pointer to the buffer to copy the event into.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE         - No event was found in the event queue.
 *
 * Description:
 * This function is non-blocking and when it is called it will return
 * any new events in the event pointer.
 *
 **/
gni_return_t
	GNI_GetErrorEvent(
		IN gni_err_handle_t     err_handle,
		IN gni_error_event_t    *event
		);

/**
 * GNI_WaitErrorEvents - Wait until an error event occurs.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * events               The pointer to the buffer to copy the events into.
 * events_size          The number of events in the events pointer.
 * timeout              After first event is triggered, time to wait for subsequent events.
 *
 * OUT
 * num_events           The number of events copied into the events buffer.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE         - No event was found in the event queue.
 * GNI_RC_TIMEOUT          - Timeout was triggered before any more events came.
 * GNI_RC_PERMISSION_ERROR - The events pointer can't be written into.
 *
 * Description:
 * This function will block waiting forever waiting for one event to
 * occur. When that one event is triggered, it will delay returning to
 * try and coalesce error events. The timeout value is specified in
 * number of milliseconds. The number of events copied are stored in
 * the num_events structure.
 *
 **/
gni_return_t
	GNI_WaitErrorEvents(
		IN  gni_err_handle_t    err_handle,
		IN  gni_error_event_t   *events,
		IN  uint32_t            events_size,
		IN  uint32_t            timeout,
		OUT uint32_t            *num_events
		);

/**
 * GNI_SetErrorPtag - Set protection tag for an error handler.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * ptag                 The protect tag to set for matching error events.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 * GNI_RC_PERMISSION_ERROR - Only super-user can set ptag to something other than the communication domain.
 *
 * Description:
 * This is a privileged operation only. This function allows error
 * event capturing on other ptags. It also can be set to 0 to specify
 * capturing all events.
 *
 **/
gni_return_t
	GNI_SetErrorPtag(
		IN gni_err_handle_t     err_handle,
		IN uint8_t              ptag
		);

/**
 * GNI_GetNumLocalDevices - Get the number of local NICs on this node.
 *
 * Parameters:
 * OUT
 * num_devices  Pointer to the number of devices.
 *
 * Returns:
 * GNI_RC_SUCCESS - Number of devices was returned successfully.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - There are no GNI NICs on this node.
 *
 * Description:
 * Returns the number of local device (NIC) IDs.
 **/
gni_return_t
	GNI_GetNumLocalDevices(
		OUT int *num_devices
		);

/**
 * GNI_GetLocalDeviceIds - Get the IDs for each local NIC on this node.
 *
 * Parameters:
 * IN
 * len          The number of entries in the device_ids array.
 *
 * OUT
 * device_ids   Pointer to an array of device IDs.
 *
 * Returns:
 * GNI_RC_SUCCESS - Device IDs were returned successfully.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - There are no GNI NICs on this node.
 *
 * Description:
 * Returns an array of local device (NIC) IDs.
 **/
gni_return_t
	GNI_GetLocalDeviceIds(
		IN  int len,
		OUT int *device_ids
		);

/**
 * GNI_GetVersion - Get the GNI version number.
 *
 * Parameters:
 * OUT
 * version      Pointer to the GNI version number.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid parameter.
 *
 * Description:
 *
 * Returns the GNI version number of the uGNI library.
 **/
gni_return_t
	GNI_GetVersion(
		OUT uint32_t    *version
		);

/**
 * GNI_GetVersionInformation - Get the version information of the uGNI
 *                             and kGNI libraries.
 *
 * Parameters:
 * OUT
 * version_info  Pointer to the structure containing the GNI version
 *               information.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid parameter.
 *
 * Description:
 *
 * Returns the version information of the uGNI and kGNI libraries.
 **/
gni_return_t
	GNI_GetVersionInformation(
		OUT gni_version_info_t  *version_info
		);

/**
 * GNI_GetDeviceType - Get the NIC type of the GNI device on the running system.
 *
 * Parameters:
 * OUT
 * dev_type     The GNI NIC device type of the device on the running system.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_ERROR_RESOURCE - A GNI device does not exist on the running system.
 *
 * Description:
 *
 * Returns the GNI NIC device type of the GNI device on a running system.
 **/
gni_return_t
	GNI_GetDeviceType(
		OUT gni_nic_device_t    *dev_type
		);

/**
 * GNI_GetDevResInfo - Get device resource information.
 *
 * Parameters:
 * IN
 * device_id    The ID of the device to query.
 * res_type     The resource to query.
 *
 * OUT
 * res_desc     A pointer to information about the queried device resource.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid parameter was provided.
 * GNI_RC_ERROR_RESOURCE - The resource queried is not supported by the device
 *                         with ID 'device_id'.
 *
 * Description:
 *
 * Returns information about the device resource 'res_type' for the GNI device
 * with ID 'device_id'.
 **/
gni_return_t
	GNI_GetDevResInfo(
		IN  uint32_t            device_id,
		IN  gni_dev_res_t       res_type,
		OUT gni_dev_res_desc_t  *res_desc
		);

/**
 * GNI_GetJobResInfo - Get job resource information.
 *
 * Parameters:
 * IN
 * device_id    The ID of the device to query.
 * res_type     The resource to query.
 * ptag         The protection tag of the job to query.
 *
 * OUT
 * res_desc     A pointer to information about the queried job resource.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid parameter was provided.
 * GNI_RC_ERROR_RESOURCE - The resource queried is not supported by the device
 *                         with ID 'device_id'
 *
 * Description:
 *
 * Returns information about the job resource 'res_type' for the job with
 * protection tag 'ptag' on the GNI device with ID 'device_id'.
 **/
gni_return_t
	GNI_GetJobResInfo(
		IN  uint32_t            device_id,
		IN  uint8_t             ptag,
		IN  gni_job_res_t       res_type,
		OUT gni_job_res_desc_t  *res_desc
		);

/**
 * GNI_GetNttGran - Get the configured NTT granularity.
 *
 * Parameters:
 * IN
 * device_id    The ID of the GNI device to query.
 *
 * OUT
 * ntt_gran     The NTT granularity configured for the GNI device.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid parameter.
 *
 * Description:
 *
 * Returns the configured NTT granularity for the GNI device with ID
 * 'device_id'.
 **/
gni_return_t
	GNI_GetNttGran(
		IN  uint32_t    device_id,
		OUT uint32_t    *ntt_gran
		);

/**
 * GNI_GetPtag - Get the ptag associated with a cookie.
 *
 * Parameters:
 * IN
 * device_id    The ID of the GNI device to query.
 * cookie       The cookie associated with ptag.
 *
 * OUT
 * ptag         The ptag associated with the cookie.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid parameter.
 * GNI_RC_NO_MATCH - Could not find associated ptag or device_id is
 *                   invalid.
 * GNI_RC_ERROR_RESOURCE - a resource allocation error was encountered while
 *                         trying to configure the job resources.
 *
 * Description:
 *
 * Returns the ptag associated with cookie for the GNI device with ID
 * 'device_id'.
 **/
gni_return_t
	GNI_GetPtag(
		IN  uint32_t    device_id,
		IN  uint32_t    cookie,
		OUT uint8_t     *ptag
		);

/**
 * GNI_CeCreate - Allocate a VCE channel.
 *
 * Parameters:
 * IN
 * nic_hndl     The NIC handle to associate with the VCE channel.
 *
 * OUT
 * ce_hndl      A handle for the new VCE channel.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - A resource allocation error was encountered.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_ILLEGAL_OP - The operation is not supported on this NIC type.
 *
 * Description:
 *
 * The GNI_CeCreate() interface attempts to allocate a hardware VCE channel
 * resource.  On success, a handle to the allocated resource is returned to the
 * user.
 **/
gni_return_t
	GNI_CeCreate(
		IN  gni_nic_handle_t    nic_hndl,
		OUT gni_ce_handle_t     *ce_hndl
		);

/**
 * GNI_CeGetId - Retrieve the ID of a VCE channel.
 *
 * Parameters:
 * IN
 * ce_hndl      The VCE channel to use.
 *
 * OUT
 * ce_id        The ID of the VCE channel.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ILLEGAL_OP - The operation is not supported on this NIC type.
 *
 * Description:
 *
 * The GNI_CeGetId() interface returns the hardware VCE channel identifier from
 * the provided CE handle.  This ID is used to associate an endpoint with the
 * VCE channel.  Endpoints are then used to configure the VCE channel.
 **/
gni_return_t
	GNI_CeGetId(
		IN  gni_ce_handle_t     ce_hndl,
		OUT uint32_t            *ce_id
		);

/**
 * GNI_EpSetCeAttr - Store CE tree attributes into an endpoint.
 *
 * Parameters:
 * IN
 * ep_hndl      The EP handle to use.
 * ce_id        The CE ID to store in the endpoint.
 * child_id     The child ID to store in the endpoint
 * child_type   The child type to store in the endpoint
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ILLEGAL_OP - The operation is not supported on this NIC type.
 *
 * Description:
 *
 * The GNI_EpSetCeAttr() interface sets the CE specific attributes of an
 * endpoint.  A VCE channel is configured using a set of endpoints with CE
 * attributes set.  Each endpoint used for VCE channel configuration represents
 * a node directly connected to the channel.  Additionally, endpoints used to
 * initiate CE operations (leaf nodes in the collective tree) must have CE
 * attributes set.
 *
 * Notes:
 *
 * Endpoints used for CE channel configuration represent either a child PE,
 * child VCE or parent VCE.  Each of these endpoint types is configured using a
 * different set of EP CE attributes.
 *
 * An endpoint representing a child PE is configured with:
 * ce_id - unused.
 * child_id - set to the uniquely assigned index in [0,GNI_CE_MAX_CHILDREN)
 *            that the local VCE channel refers to this child with.
 * child_type - set to GNI_CE_CHILD_PE.
 *
 * An endpoint representing a child VCE is configured with:
 * ce_id - set to the CE ID of the child VCE channel.
 * child_id - set to the uniquely assigned index in [0,GNI_CE_MAX_CHILDREN)
 *            that the local VCE channel refers to this child with.
 * child_type - set to  GNI_CE_CHILD_VCE.
 *
 * An endpoint representing a parent VCE is configured with:
 * ce_id - set to the CE ID of the parent VCE channel.
 * child_id - set to the uniquely assigned index in [0,GNI_CE_MAX_CHILDREN)
 *            that the remote VCE channel refers to this child with.
 * child_type - set to  GNI_CE_CHILD_VCE.
 *
 * Endpoints used to initiate CE operations using GNI_PostFma() must also be
 * configured with CE attributes.  These leaf endpoints are configured with:
 *
 * ce_id - set to the CE ID of the parente VCE channel.
 * child_id - set to the uniquely assigned index in [0,GNI_CE_MAX_CHILDREN)
 *            that the remote VCE channel refers to this child with.
 * child_type - set to GNI_CE_CHILD_PE.
 *
 * Also note that endpoints used for CE operations (either configuration of a
 * VCE channel or as a leaf endpoint) must be bound using remote address and
 * instance ID information.
 **/
gni_return_t
	GNI_EpSetCeAttr(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             ce_id,
		IN uint32_t             child_id,
		IN gni_ce_child_t       child_type
		);

/**
 * GNI_CeConfigure - Configure a VCE channel.
 *
 * Parameters:
 * IN
 * ce_hndl      The VCE channel to configure.
 * child_eps    An array of endpoints representing VCE child connections.
 * num_child_eps The number of child connections.
 * parent_ep    An endpoint representing the VCE parent connection.
 * cq_hndl      The CQ to associate with VCE channel.
 * modes        VCE channel configuration modes.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ILLEGAL_OP - The operation is not supported on this NIC type.
 *
 * Description:
 *
 * The GNI_CeConfigure() interface configures a VCE channel given a set of
 * endpoints representing collective tree conections to the channel.
 **/
gni_return_t
	GNI_CeConfigure(
		IN gni_ce_handle_t      ce_hndl,
		IN gni_ep_handle_t      *child_eps,
		IN uint32_t             num_child_eps,
		IN gni_ep_handle_t      parent_ep,
		IN gni_cq_handle_t      cq_hndl,
		IN uint32_t             modes
		);

/**
 * GNI_CeCheckResult - Check the result of a CE operation.
 *
 * Parameters:
 * IN
 * result       A pointer to the CE result structure used for the operation.
 * length       The size of the result (unused in Aries).
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE - Operation has not completed.
 * GNI_RC_TRANSACTION_ERROR - Operation completed with an error.
 * GNI_RC_ILLEGAL_OP - The operation is not supported on this NIC type.
 *
 * Description:
 *
 * The GNI_CeCheckResult() interface reads control information in the provided
 * CE result structure to determine the status of a pending CE operation.
 *
 * Notes:
 *
 * If GNI_RC_TRANSACTION_ERROR is returned, the result structure must be
 * further analyzed to determine if the result was delivered.  A user should
 * first check the status of the result structure using the
 * GNI_CE_RES_STATUS_OK() macro.  If this macro evaluates to false, the result
 * could not be delivered due to a network error.  Otherwise, the result is
 * available, but the an exception was generated by the operation.  A user
 * should use the GNI_CE_RES_GET_FPE() macro to determine what exception(s)
 * occurred.
 **/
gni_return_t
	GNI_CeCheckResult(
		IN gni_ce_result_t      *result,
		IN uint32_t             length
		);

/**
 * GNI_CeDestroy - Free a VCE channel.
 *
 * Parameters:
 * IN
 * ce_hndl      The VCE channel to free.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ILLEGAL_OP - The operation is not supported on this NIC type.
 *
 * Description:
 *
 * The GNI_CeDestroy() interface frees the VCE channel resources associated
 * with the provided CE handle.
 **/
gni_return_t
	GNI_CeDestroy(
		IN gni_ce_handle_t      ce_hndl
		);

/* Balanced Injection modes */
#define GNI_BI_FLAG_APPLY_NOW                   0x1
#define GNI_BI_FLAG_APPLY_AFTER_THROTTLE        0x2
#define GNI_BI_FLAG_USE_DEFAULT_SETTINGS        0x4
#define GNI_BI_FLAG_VALUE_IS_NUM_ORB_ENTRIES    0x8

/* Balanced Injection limits */
#define GNI_BI_INJECT_BW_MIN                    0
#define GNI_BI_INJECT_BW_MAX                    100
#define GNI_BI_INJECT_BW_ORB_MIN                0
#define GNI_BI_INJECT_BW_ORB_MAX                992

typedef struct gni_bi_desc {
	uint16_t current_bw;
	uint16_t current_aot_bw;
	uint16_t current_norbs;
	uint16_t flags;
	uint16_t sys_def_bw;
	uint16_t sys_def_aot_bw;
	uint16_t cle_seqnum;
	uint16_t hss_seqnum;
} gni_bi_desc_t;

/**
 * GNI_SetBIConfig - Sets the balanced injection configuration.
 *
 * Parameters:
 * IN
 * device_id    The ID of the GNI device to query.
 * bw           The new injection bandwidth value.
 * aot_bw       The new 'apply-on-throttle' injection bandwidth value.
 * modes        modes
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_PERMISSION_ERROR - The operation was attempted by an unpriviledged user.
 *
 * Description:
 *
 * The GNI_SetBIConfig() interface configures a node's balanced injection
 * settings.
 **/
gni_return_t
	GNI_SetBIConfig(
		IN uint32_t     device_id,
		IN uint16_t     bw,
		IN uint16_t     aot_bw,
		IN uint16_t     modes
		);

/**
 * GNI_GetBIConfig - Gets the balanced injection configuration.
 *
 * Parameters:
 * IN
 * device_id    The ID of the GNI device to query.
 *
 * OUT
 * desc         The current balanced injection configuration.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 *
 * The GNI_GetBIConfig() interface returns information about a node's balanced
 * injection configuration.
 **/
gni_return_t
	GNI_GetBIConfig(
		IN uint32_t             device_id,
		OUT gni_bi_desc_t       *desc
		);

/**
 * GNI_BISyncWait - Blocks until the most recent BI configuration update is
 *                  committed.
 *
 * Parameters:
 * IN
 * device_id    The ID of the GNI device to query.
 *
 * OUT
 * timeout      The maximum amount of time in milliseconds to wait.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_TIMEOUT - The timeout expired.
 *
 * Description:
 *
 * The GNI_BISyncWait() interface blocks until the most recent BI configuration
 * update is committed or the timeout expires.
 **/
gni_return_t
	GNI_BISyncWait(
		IN uint32_t     device_id,
		OUT uint32_t    timeout);

/**
 * GNI_GetNicStat - Get a NIC statistic
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated NIC.
 * stat         NIC statistic to get
 *
 * OUT
 * value         Value of the statistic counter
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the arguments is invalid.
 *
 * Description:
 * Read the value of the NIC statistic counter.
 **/
gni_return_t
	GNI_GetNicStat(
		IN gni_nic_handle_t nic_hndl,
		IN gni_statistic_t stat,
		OUT uint32_t *value);

/**
 * GNI_ResetNicStat - Reset a NIC statistic to zero
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated NIC.
 * stat         NIC statistic to clear
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the arguments is invalid.
 *
 * Description:
 * Reset a NIC statistic counter to zero.
 **/
gni_return_t
	GNI_ResetNicStat(
		IN gni_nic_handle_t nic_hndl,
		IN gni_statistic_t stat);

#endif /*not __KERNEL__*/

#ifdef __KERNEL__
/* Kernel level definitions */

/**
 * gni_cdm_create - Create Communication Domain
 *
 * Parameters:
 * IN
 * inst_id      Unique address of the instance within the upper layer
 *              protocol domain.
 * ptag         Protection Tag.
 * cookie       Unique identifier generated by ALPS. Along with ptag
 *              helps to identify the Communication Domain.
 * modes        bit mask (see GNI_CDM_MODE_xxxxxx definitions)
 *
 * OUT
 * cdm_hndl     Handle returned. The handle is used with the other functions
 *              to specify a particular instance of the Communication Domain.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates an instance of the Communication Domain.
 *
 **/
gni_return_t
	gni_cdm_create(
		IN  uint32_t            inst_id,
		IN  uint8_t             ptag,
		IN  uint32_t            cookie,
		IN  uint32_t            modes,
		OUT gni_cdm_handle_t    *cdm_hndl
		);

/**
 * gni_cdm_destroy - Destroy Communication Domain
 *
 * Parameters:
 * IN
 * cdm_hndl     The Communication Domain Handle.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Caller specified an invalid CDM handle.
 *
 * Description:
 * Destroys the instance of the Communication Domain.
 * Removes associations between the calling process and the NIC devices
 * that were established via the corresponding Attach function.
 **/
gni_return_t
	gni_cdm_destroy(
		IN gni_cdm_handle_t     cdm_hndl
		);

/**
 * gni_cdm_attach - Attach Communication Domain to a NIC device
 *
 * Parameters:
 * IN
 * cdm_hndl     The Communication Domain Handle.
 * device_id    The device identifier , e.g. /dev/kgni1 has
 *              device_id = DEVICE_MINOR_NUMBER - GEMINI_BASE_MINOR_NUMBER = 1
 *              Setting device_id to (-1) will result in attaching to
 *              the nearest Gemini NIC.
 *
 * OUT
 * local_addr   PE address of the Gemini NIC attached
 * nic_hndl     Handle returned. The handle is used with the other functions to specify
 *              a particular instance of a Gemini NIC.
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_NOT_DONE - Operation can't succeed right now, try again.
 * GNI_RC_INVALID_PARAM - Caller specified an invalid CDM handle.
 * GNI_RC_NO_MATCH - Specified device_id does not exists
 * GNI_RC_ERROR_RESOURCE - The operation failed due to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * Associates the Communication Domain with a Gemini NIC and provides a NIC handle
 * to the upper layer protocol. A process is not allowed to attach the same CDM
 * instance to the same Gemini NIC more than once, but it is allowed to attach
 * multiple CDMs to the same Gemini NIC.
 **/
gni_return_t
	gni_cdm_attach(
		IN  gni_cdm_handle_t    cdm_hndl,
		IN  uint32_t            device_id,
		OUT uint32_t            *local_addr,
		OUT gni_nic_handle_t    *nic_hndl
		);

/**
 * gni_ep_create - Create logical Endpoint
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated Gemini NIC.
 * src_cq_hndl  Handle of the CQ that will be used by default to deliver events
 *              related to the transactions initiated by the local node.
 *
 * OUT
 * ep_hndl      The handle of the newly created Endpoint instance.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates an instance of a Logical Endpoint.
 * A new instance is always created in a non-bound state.
 * A non-bound Endpoint is able to exchange posted data with
 * any bound remote Endpoint within the same Communication Domain.
 * An Endpoint cannot be used to post RDMA, FMA transactions or
 * send short messages while it is in non-bound state.
 **/
gni_return_t
	gni_ep_create(
		IN  gni_nic_handle_t    nic_hndl,
		IN  gni_cq_handle_t     src_cq_hndl,
		OUT gni_ep_handle_t     *ep_hndl
		);
/**
 * gni_ep_set_eventdata - Set event data  for local and remote events
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance.
 * local_event  Value to use when generating LOCAL CQ events
 * remote_event Value to use when generating GLOBAL & REMOTE CQ events
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid EP handle.
 *
 * Description:
 * By default GNI uses local instance_id as an event data for GLOBAL and REMOTE CQ events,
 * and EP remote_id when generating LOCAL CQ events.
 * This function allows to re-assign these events to the user defined values.
 **/
gni_return_t
	gni_ep_set_eventdata(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             local_event,
		IN uint32_t             remote_event
		);
/**
 * gni_ep_bind - Bind logical Endpoint to a peer
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to be bound.
 * remote_addr  Physical address of the Gemini NIC at the remote peer or NTT index,
 *              when NTT is enabled for the given Communication Domain.
 * remote_id    User specified ID of the remote instance in the job or unique identifier of
 *              the remote instance within the upper layer protocol domain.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function binds a Logical Endpoint to the specific remote address
 * and remote instance in the Communication Domain.
 * Once bound the Endpoint can be used to post RDMA and FMA transactions.
 **/
gni_return_t
	gni_ep_bind(
		IN gni_ep_handle_t      ep_hndl,
		IN uint32_t             remote_addr,
		IN uint32_t             remote_id
		);
/**
 * gni_ep_unbind - Unbind logical Endpoint
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to be bound.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE - Operation is not permited
 *
 * Description:
 * This function unbinds a Logical Endpoint from the specific remote address
 * and remote instance and releases any internal short message resource.
 * A non-bound Endpoint is able to exchange posted data with
 * any bound remote Endpoint within the same Communication Domain.
 * An Endpoint cannot be used to post RDMA, FMA transactions or
 * send short messages while it is in non-bound state.
 **/
gni_return_t
	gni_ep_unbind(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * gni_ep_destroy - Destroy logical Endpoint
 *
 * Parameters:
 * IN
 * ep_hndl      The handle of the Endpoint instance to be destroyed.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 *
 * Description:
 * This function tears down an Endpoint.
 **/
gni_return_t
	gni_ep_destroy(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * gni_ep_postdata - Exchange datagram with a remote Endpoint
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * in_data      pointer to the data to be sent
 * data_len     size of the data to be sent
 * out_buf      buffer to receive incoming datagram
 * buf_size     size of the buffer for incoming datagram
 *
 * Returns:
 * GNI_RC_SUCCESS - Connection request was queued.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 * GNI_RC_ERROR_RESOURCE - Only one outstanding datagram transaction per Endpoint
 *                         is allowed.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_SIZE_ERROR - Size of datagram is too big.
 *
 * Description:
 * This function posts a datagram to be exchanged with a remote Endpoint in the CDM.
 * If the EP is unbound a datagram can be exchanged with any bound Endpoint in the CDM.
 **/
gni_return_t
	gni_ep_postdata(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *in_data,
		IN uint16_t             data_len,
		IN void                 *out_buf,
		IN uint16_t             buf_size
		);

/**
 * gni_ep_postdata_w_id - Exchange datagram with a remote Endpoint, assigning an
 *                        id to the datagram.
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * in_data      pointer to the data to be sent
 * data_len     size of the data to be sent
 * out_buf      buffer to receive incoming datagram
 * buf_size     size of the buffer for incoming datagram
 * datagram_id  id associated with the datagram
 *
 * Returns:
 * GNI_RC_SUCCESS - Posted datagram was queued.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified or an invalid
 *                        value (-1) for the datagram_id was specified.
 * GNI_RC_ERROR_RESOURCE - Only one outstanding datagram transaction per
 *                         Endpoint is allowed.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_SIZE_ERROR - Size of datagram is too big.
 *
 * Description:
 * This function posts a datagram to be exchanged with a remote Endpoint in the CDM
 * and associated an Id with the datagram.
 * If the EP is unbound a datagram can be exchanged with any bound Endpoint in the CDM.
 *
 * Notes:
 * It may be useful to associate an Id with a datagram when intermixing usage of
 * bound and unbound EP's with datagrams.  Unbound endpoints must post datagrams with
 * a datagram id.
 **/
gni_return_t
	gni_ep_postdata_w_id(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *in_data,
		IN uint16_t             data_len,
		IN void                 *out_buf,
		IN uint16_t             buf_size,
		IN uint64_t             datagram_id
		);

/**
 * gni_ep_postdata_test - Tests for completion of a gni_ep_postdata operation.
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 *
 * OUT
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - Connection status is returned through the second function parameter.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received
 *                     datagram.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function returns the state of the PostData transaction.
 **/
gni_return_t
	gni_ep_postdata_test(
		IN  gni_ep_handle_t     ep_hndl,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * gni_ep_postdata_test_by_id - Tests for completion of a gni_ep_postdata_w_id operation
 *                              with a specified post id.
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * datagram_id  Id of the datagram associated with the endpoint.
 *
 * OUT
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - Connection status is returned through the second function parameter.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received
 *                     datagram.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function returns the state of the PostData transaction with an assigned
 * datagram id.
 *
 * Note:
 * Unbound endpoints must test for datagrams with the same datagram id used
 * when calling gni_ep_postdata_w_id.
 **/
gni_return_t
	gni_ep_postdata_test_by_id(
		IN  gni_ep_handle_t     ep_hndl,
		IN  uint64_t            datagram_id,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * gni_ep_postdata_wait - Wait for the Endpoint to connect
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * timeout      The count that this function waits, in milliseconds, for
 *              connection to complete.
 *              Set to (-1) if no timeout is desired. A timeout value of zero results
 *              in a GNI_RC_INVALID_PARAM error returned.
 * post_state   State of the transaction is returned.
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if post_state returned GNI_POST_COMPLETED.
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if post_state returned
 *              GNI_POST_COMPLETED.
 *
 * Returns:
 * GNI_RC_SUCCESS - The connection completed successfully.
 * GNI_RC_INVALID_PARAM - An invalid EP handle was specified or timeout was set to zero.
 * GNI_RC_TIMEOUT - The timeout expired before a successful connection completion.
 * GNI_RC_SIZE_ERROR - Output buffer is too small for the size of the received
 *                     datagram.
 * GNI_RC_NO_MATCH - No matching datagram was found.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function is used to determine the result of a previously posted EpPostData
 * call on the specified Endpoint, blocking the calling thread until the completion
 * of the posted transaction or until the specified timeout expires.
 **/
gni_return_t
	gni_ep_postdata_wait(
		IN  gni_ep_handle_t     ep_hndl,
		IN  uint32_t            timeout,
		OUT gni_post_state_t    *post_state,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * gni_postdata_probe - Probe for datagrams associated with a cdm/nic which
 *                      are in completed, timed out, or cancelled state.
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a nic associated with the cdm for which datagrams
 *              status is being probed.
 *
 * OUT
 * remote_addr  Physical address of the Gemini NIC at the remote peer.
 *              Valid only if return value is GNI_RC_SUCCESS.
 *              (This address is virtual if GNI_CDM_MODE_NTT_ENABLE).
 * remote_id    User specific ID of the remote instance in the job (user)
 *              Unique address of the remote instance within the upper layer
 *              protocol domain (kernel). Valid only if return value is
 *              GNI_RC_SUCCESS.
 *
 * Returns:
 * GNI_RC_SUCCESS - A datagram in the completed, timed out or cancelled state was found.
 *                  The remote_addr and remote_id of the datagram are
 *                  in the remote_addr and remote_id arguments.
 * GNI_RC_INVALID_PARAM - An invalid NIC handle or invalid address for remote_addr or
 *                        remote_id was specified.
 * GNI_RC_NO_MATCH - No datagram in completed, timed out, or cancelled state was found.
 *
 * Description:
 * This function returns the remote_addr and remote_id of the first datagram found in
 * completed, timed out, or canceled state for the cdm associated with the
 * input nic handle.  This function must be used in conjunction
 * with GNI_EpPostDataTest or GNI_EpPostDataWait to obtain data exchanged
 * in the datagram transaction.
 **/
gni_return_t
	gni_postdata_probe(
		IN  gni_nic_handle_t    nic_hndl,
		OUT uint32_t            *remote_addr,
		OUT uint32_t            *remote_id
		);

/**
 * gni_postdata_probe_by_id - Probe by ID for datagrams associated with a cdm/nic which
 *                               are in completed, timed out, or cancelled state.
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a nic associated with the cdm for which datagrams
 *              status is being probed.
 *
 * OUT
 * datagram_id  Id of first datagram found to be in completed, timed out, or
 *              cancelled state.  Valid only if the return value is GNI_RC_SUCCESS.
 *
 * Returns:
 * GNI_RC_SUCCESS - A datagram previously posted with a datagram_id in the completed,
 *                  timed out or cancelled state was found.
 *                  The id of the datagram is returned in the datagram_id argument.
 * GNI_RC_INVALID_PARAM - An invalid NIC handle or an invalid datagram_id address was specified.
 * GNI_RC_NO_MATCH - No datagram in completed, timed out, or cancelled state was found.
 *
 * Description:
 * This function returns the postid of the first datagram posted with a datagram_id found in
 * completed, timed out, or canceled state for the cdm associated with the
 * input nic handle.  This function must be used in conjunction
 * with GNI_EpPostDataTestById or GNI_EpPostDataWaitById to obtain data exchanged
 * in the datagram transaction.
 *
 * Note:
 * This function should be used for probing for completion of datagrams that
 * were previously posted using the GNI_EpPostDataWId function.
 **/
gni_return_t
	gni_postdata_probe_by_id(
		IN  gni_nic_handle_t    nic_hndl,
		OUT uint64_t            *datagram_id
		);

/**
 * gni_postdata_probe_wait_by_id - Probe by ID for datagrams associated with a cdm/nic until
 *                                 a datagram in completed, timed out, or cancelled state is found
 *                                 or the timeout expires.
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a nic associated with the cdm for which datagrams
 *              status is being probed.
 * timeout      The number of milliseconds to block before returning
 *              to the caller, (-1) if no time-out is desired.
 *
 * OUT
 * datagram_id  Id of first datagram found to be in completed, timed out, or
 *              cancelled state.  Valid only if the return value is GNI_RC_SUCCESS.
 *
 * Returns:
 * GNI_RC_SUCCESS - A datagram previously posted with a datagram_id in the completed,
 *                  timed out or cancelled state was found.
 *                  The id of the datagram is returned in the datagram_id argument.
 * GNI_RC_INVALID_PARAM - An invalid NIC handle or an invalid datagram_id address was specified.
 * GNI_RC_TIMEOUT - No datagram in completed, timed out, or cancelled state was found before
 *                  the timeout expired.
 *
 * Description:
 * This function returns the postid of the first datagram posted with a datagram_id found in
 * completed, timed out, or canceled state for the cdm associated with the
 * input nic handle.  This function must be used in conjunction
 * with gni_ep_postdata_test_by_id or gni_ep_postdata_wait_by_id to obtain data exchanged
 * in the datagram transaction.
 *
 * Note:
 * This function should be used for probing for completion of datagrams that
 * were previously posted using the gni_ep_postdata_w_id function.
 **/
gni_return_t
	gni_postdata_probe_wait_by_id(
		IN  gni_nic_handle_t    nic_hndl,
		IN  uint32_t            timeout,
		OUT uint64_t            *datagram_id
		);

/**
 * gni_ep_postdata_cancel - Cancels postdata transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 *
 * Returns:
 * GNI_RC_SUCCESS - Canceled successfully.
 * GNI_RC_INVALID_PARAM - The ep_hndl parameter was invalid
 * GNI_RC_NO_MATCH      - No active postdata transaction on the ep_hndl
 *
 * Description:
 * This function is used to cancel a postdata transaction.
 **/
gni_return_t
	gni_ep_postdata_cancel(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * gni_ep_postdata_cancel_by_id - Cancels postdata transaction with a specified
 *                                post id.
 *
 * Parameters:
 * IN
 * ep_hndl      Handle of the local Endpoint.
 * datagram_id  Id of the datagram to cancel.
 *
 * Returns:
 * GNI_RC_SUCCESS - Canceled successfully.
 * GNI_RC_INVALID_PARAM - The ep_hndl parameter was invalid
 * GNI_RC_NO_MATCH      - No active postdata transaction on the ep_hndl
 *
 * Description:
 * This function is used to cancel a postdata transaction.
 *
 * Note:
 * Unbound endpoints must cancel datagrams with the same datagram id used
 * when calling gni_ep_postdata_w_id.
 **/
gni_return_t
	gni_ep_postdata_cancel_by_id(
		IN gni_ep_handle_t      ep_hndl,
		IN uint64_t             datagram_id
		);

/**
 * gni_mem_register - Register memory with the NIC
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a currently open NIC.
 * address      Starting address of the memory region to be registered.
 * length       Length of the memory region to be registered, in bytes.
 * dst_cq_hndl  If not NULL, specifies the CQ to receive events related to
 *              the transactions initiated by the remote node into this memory region.
 * flags        One of the following flags: GNI_MEM_READWRITE_ONLY, GNI_MEM_READ_ONLY
 *
 * OUT
 * mem_hndl     The new memory handle for the region.
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully registered.
 * GNI_RC_INVALID_PARAM - One on the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The registration operation failed due
 *                         to insufficient resources.
 * GNI_RC_PERMISSION_ERROR - The user's buffer R/W permissions conflict with
 *                           the flags argument.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function allows a process to register a region of memory with the Gemini NIC.
 * The user may specify an arbitrary size region of memory, with arbitrary alignment,
 * but the actual area of memory registered will be registered on MRT block granularity
 * (or physical page granularity if MRT is not enabled for this process).
 * A memory region must consist of a single segment.
 * Using a single segment to register a memory region allows an application to use a virtual
 * address in the future transactions in and out of the registered region.
 * A single segment memory registration should be a common way an application
 * registers its memory, with a multiple segments registration being reserved
 * for special cases. A new memory handle is generated for each region of memory
 * that is registered by a process.
 * A length parameter of zero will result in a GNI_RC_INVALID_PARAM error.
 * The contents of the memory region being registered are not altered.
 * The memory region must be previously allocated by an application.
 * If failure is returned, the contents of mem_hndl are untouched.
 **/
gni_return_t
	gni_mem_register(
		IN  gni_nic_handle_t    nic_hndl,
		IN  uint64_t            address,
		IN  uint64_t            length,
		IN  gni_cq_handle_t     dst_cq_hndl,
		IN  uint32_t            flags,
		OUT gni_mem_handle_t    *mem_hndl
		);

/**
 * gni_mem_register_segments - Register memory with the NIC
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of a currently open NIC.
 * mem_segmets  List of segments to be registered. Each element of the list
 *              consists of the starting address of the memory region and
 *              the length, in bytes.
 * segment_cnt  Number of segments in the mem_segments list.
 * dst_cq_hndl  If not NULL, specifies the CQ to receive events related to
 *              the transactions initiated by the remote node into this memory region.
 * flags        One of the following flags: GNI_MEM_READWRITE_ONLY, GNI_MEM_READ_ONLY
 *
 * OUT
 * mem_hndl     The new memory handle for the region.
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully registered.
 * GNI_RC_INVALID_PARAM - One on the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The registration operation failed due
 *                         to insufficient resources.
 * GNI_RC_PERMISSION_ERROR - The user's buffer R/W permissions conflict with
 *                           the flags argument.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function allows a process to register a region of memory with the Gemini NIC.
 * The user may specify an arbitrary size region of memory, with arbitrary alignment,
 * but the actual area of memory registered will be registered on MRT block granularity
 * (or physical page granularity if MRT is not enabled for this process).
 * This function allows a process to register a region of memory with
 * the Gemini NIC. The user may specify an arbitrary size region of memory,
 * with arbitrary alignment, but the actual area of memory registered will
 * be registered on MRT block granularity (or physical page granularity if
 * MRT is not enabled for this process).
 * To register a single segment GNI_MemRegister() function must be used,
 * with an exception of physical page registration (when GNI_MEM_PHYS_SEGMENTS flag is set).
 * Using this function imposes the requirement on an application to use an offset within
 * the registered memory region instead of a virtual address in all future
 * transactions, where registered region is aligned to MRT block size (or page size
 * for non-MRT registrations).
 * A single segment memory registration should be a common way
 * an application registers its memory. A multiple segments registration
 * should be reserved for special cases.
 * A new memory handle is generated for each region of memory that
 * is registered by a process.
 * A length parameter of zero in any segment will result in a GNI_RC_INVALID_PARAM error.
 * The contents of the memory region being registered are not altered.
 * The memory region must be previously allocated by an application.
 * If failure is returned, the contents of mem_hndl are untouched.
 **/
gni_return_t
	gni_mem_register_segments(
		IN  gni_nic_handle_t    nic_hndl,
		IN  gni_mem_segment_t   *mem_segments,
		IN  uint32_t            segments_cnt,
		IN  gni_cq_handle_t     dst_cq_hndl,
		IN  uint32_t            flags,
		OUT gni_mem_handle_t    *mem_hndl
		);

/**
 * gni_mem_deregister - De-register memory
 *
 * Parameters:
 * IN
 * nic_hndl     The handle for the NIC that owns the memory region being
 *              de-registered.
 * mem_hndl     Memory handle for the region.
 * hold_timeout Specifies a hold period before releasing the MDD for reuse
 *              in milliseconds.
 *
 * Returns:
 * GNI_RC_SUCCESS - The memory region was successfully de-registered.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 *
 * Description:
 * This function de-registers memory that was previously registered
 * and unlocks the associated pages from physical memory. The contents
 * and attributes of the region of memory being de-registered are not
 * altered in any way. When the hold_timeout is used, the MDD is
 * disabled, but not available for reuse until the specified time in
 * milliseconds has elapsed. This is considered a dead-man timer. IE:
 * The timeout is for the driver to maintain the resources, if the
 * upper layers expect to call gni_mem_mdd_release on this mem_hndl,
 * then it must be in less time than this hold_timeout.
 **/
gni_return_t
	gni_mem_deregister(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_mem_handle_t     *mem_hndl,
		IN int                  hold_timeout
		);

/**
 * gni_mem_mdd_release - Release an MDD which was on-hold.
 *
 * Parameters:
 * IN
 * nic_hndl     The handle for the NIC that owns the memory region being
 *              de-registered.
 * mem_hndl     Memory handle for the region.
 *
 * Returns:
 * GNI_RC_SUCCESS - The MDD was successfully released.
 * GNI_RC_NO_MATCH - The MDD was not found on the waiting list.
 *
 * Description:
 * After an MDD is deregistered with a holding period, it can be
 * manually released by upper layers if they know the state is
 * clean. When calling this function it releases the MDD for reuse. It
 * returns two codes. Success means the MDD was found on the timer
 * list and removed. No match means that the MDD wasn't found,
 * although, this could have been on the list and already triggered,
 * or it could be bad parameters. It's hard to say at that point since
 * it is now released and could even be reused. If this funtion
 * returns no match, it would be considered the upper layers fault,
 * since the driver would have released the mem_hndl only after the
 * deadman timer was triggered.
 **/
gni_return_t
	gni_mem_mdd_release(
		IN gni_nic_handle_t     nic_hndl,
		IN gni_mem_handle_t     *mem_hndl
		);

/**
 * gni_cq_create - Create Completion Queue
 *
 * Parameters:
 * IN
 * nic_hndl     The handle of the associated NIC.
 * entry_count  The number of completion entries that this CQ will hold.
 * delay_index  The number of events the Gemini will allow to occur before
 *              generating an interrupt. Setting this to zero results in
 *              interrupt delivery with every event.
 *              For the user level this parameter is meaningful only when
 *              mode is set to GNI_CQ_BLOCKING
 * event_hndl   Address of the user-defined function to be called when
 *              the number of events specified by the delay_count parameter
 *              occurs (kernel level).
 *
 * OUT
 * cq_hndl      The handle of the newly created Completion Queue.
 *
 * Returns:
 * GNI_RC_SUCCESS - A new Completion Queue was successfully created.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The Completion Queue could not be created due
 *                         to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 *
 * Description:
 * This function creates a new Completion Queue. The caller must specify
 * the minimum number of completion entries that the queue must contain.
 * To avoid dropped completion notifications, applications should make sure
 * that the number of operations posted on Endpoints attached to a src_cq_hndl
 * does not exceed the completion queue capacity at any time.
 **/
typedef void (gni_cq_event_hndlr_f)(IN uint32_t device_id, IN uint64_t data);

gni_return_t
	gni_cq_create(
		IN  gni_nic_handle_t            nic_hndl,
		IN  uint32_t                    entry_count,
		IN  uint32_t                    delay_index,
		IN  gni_cq_event_hndlr_f        *event_handler,
		IN  uint64_t                    usr_event_data,
		OUT gni_cq_handle_t             *cq_hndl
		);

/**
 * gni_cq_destroy - Destroy Completion queue
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue to be destroyed.
 *
 * Returns:
 * GNI_RC_SUCCESS - The CQ was successfully destroyed.
 * GNI_RC_INVALID_PARAM - One or more of the parameters was invalid.
 * GNI_RC_ERROR_RESOURCE - The CQ could not be destroyed because one or
 *                         more Endpoint instances are still associated with it.
 *
 * Description:
 * This function destroys a specified Completion Queue.
 * If any Endpoints are associated with the CQ, the CQ is not destroyed and
 * an error is returned.
 **/
gni_return_t
	gni_cq_destroy(
		IN gni_cq_handle_t      cq_hndl
		);

/**
 * gni_post_rdma - Post RDMA transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of a local Endpoint.
 * post_descr   Pointer to a descriptor to be posted.
 *
 * Returns:
 * GNI_RC_SUCCESS - The descriptor was successfully posted.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid.
 * GNI_RC_ALIGNMENT_ERROR - Posted source or destination data pointers or
 *                          data length are not properly aligned.
 * GNI_RC_ERROR_RESOURCE - The transaction request could not be posted due
 *                         to insufficient resources.
 * GNI_RC_ERROR_NOMEM - Insufficient memory to complete the operation.
 * GNI_RC_PERMISSION_ERROR - The user's buffer R/W permissions conflict with
 *                           the access type.
 *
 * Description:
 * This function adds a descriptor to the tail of the RDMA queue
 * and returns immediately.
 *
 **/
gni_return_t
	gni_post_rdma(
		IN gni_ep_handle_t              ep_hndl,
		IN gni_post_descriptor_t        *post_descr
		);

/**
 * gni_post_fma - Post FMA transaction
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of a local Endpoint.
 * post_descr   Pointer to a descriptor to be posted.
 *
 * Returns:
 * GNI_RC_SUCCESS - The descriptor was successfully posted.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid.
 * GNI_RC_ALIGNMENT_ERROR - Posted source or destination data pointers or
 *                          data length are not properly aligned.
 * GNI_RC_ERROR_RESOURCE - The transaction request could not be posted due
 *                         to insufficient resources.
 *
 * Description:
 * This function executes a data transaction (Put, Get, or AMO) by
 * storing into the directly mapped FMA Window to initiate a series
 * of FMA requests.
 * It returns before the transaction is confirmed by the remote NIC.
 * Zero-length FMA Put operations are supported. Zero-length FMA Get and
 * zero-length FMA AMO operations are not supported.
 *
 **/
gni_return_t
	gni_post_fma(
		IN gni_ep_handle_t              ep_hndl,
		IN gni_post_descriptor_t        *post_descr
		);

/**
 * gni_get_completed - Get next completed descriptor
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 * event_data   The event returned by CqGetEvent function.
 *
 * OUT
 * post_desc    Address of the descriptor that has completed.
 *
 * Returns:
 * GNI_RC_SUCCESS - A completed descriptor was returned with a successful
 *                  completion status.
 * GNI_RC_DESCRIPTOR_ERROR - If the corresponding post queue (FMA, RDMA or AMO)
 *                           is empty, the descriptor pointer is set to NULL,
 *                           otherwise, a completed descriptor is returned with
 *                           an error completion status.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid.
 * GNI_RC_TRANSACTION_ERROR - A completed descriptor was returned with a
 *                            network error status.
 *
 * Description:
 * This function gets the descriptor from the corresponding post queue.
 * The post queue is identified by the transaction type the GetCompleted
 * function extracts from the event_data parameter. The descriptor is removed
 * from the head of the queue and the address of the descriptor is returned.
 *
 **/
gni_return_t
	gni_get_completed(
		IN  gni_cq_handle_t             cq_hndl,
		IN  gni_cq_entry_t              event_data,
		OUT gni_post_descriptor_t       **post_descr
		);

/**
 * gni_cq_get_event - Get next event
 *
 * Parameters:
 * IN
 * cq_hndl      The handle for the Completion Queue.
 *
 * OUT
 * event_data   A new event entry data, if the return status indicates success.
 *              Undefined otherwise.
 *
 * Returns:
 * GNI_RC_SUCCESS - A completion entry was found on the Completion Queue.
 * GNI_RC_NOT_DONE - No new completion entries are on the Completion Queue.
 * GNI_RC_INVALID_PARAM - The Completion Queue handle was invalid.
 * GNI_RC_ERROR_RESOURCE - The Completion Queue was in an overrun state and
 *                         events may have been lost.
 * GNI_RC_TRANSACTION_ERROR - A completion entry in an error state was found on
 *                            the Completion Queue in an error state.
 *
 * Description:
 * This function polls the specified Completion Queue for a completion entry.
 * If a completion entry is found, it returns the event data stored in the entry.
 * CqGetEvent is a non-blocking call. It is up to the calling process
 * to subsequently invoke the appropriate function to de-queue the completed descriptor.
 * CqGetEvent only de-queues the completion entry from the Completion Queue.
 *
 **/
gni_return_t
	gni_cq_get_event(
		IN  gni_cq_handle_t     cq_hndl,
		OUT gni_cq_entry_t      *event_data
		);

/**
 * gni_cq_error_str - Decode error status into a string for a CQ Entry
 *
 * Parameters:
 * IN
 * entry           CQ entry with error status to be decoded
 * len             Length of the buffer in bytes
 *
 * OUT
 * buffer          Pointer to the buffer where the error code will be
 *                 returned.
 *
 * Returns:
 * GNI_RC_SUCCESS - The entry was successfully decoded.
 * GNI_RC_INVALID_PARAM - Invalid input parameter
 * GNI_RC_SIZE_ERROR - Supplied buffer is too small to contain the error
 *                     code
 *
 * Description:
 * This function decodes the error status encoded in a CQ Entry
 * by the hardware.
 *
 **/
gni_return_t
	gni_cq_error_str(
		IN  gni_cq_entry_t      entry,
		OUT void                *buffer,
		IN  uint32_t            len
		);

/**
 * gni_cq_error_recoverable - Deduce error status as recoverable for a CQ Entry
 *
 * Parameters:
 * IN
 * entry           CQ entry with error status to be decoded
 *
 * OUT
 * recoverable     Pointer to the integer flag that will contain the result.
 *
 * Returns:
 * GNI_RC_SUCCESS - The entry was successfully decoded.
 * GNI_RC_INVALID_PARAM - Invalid input parameter
 * GNI_RC_INVALID_STATE - CQ entry translates to an undefined state
 *
 * Description:
 * This function translates any error status encoded in a CQ Entry by
 * the hardware into a recoverable/unrecoverable flag for application
 * usage.
 *
 **/
gni_return_t
	gni_cq_error_recoverable(
		IN  gni_cq_entry_t      entry,
		OUT uint32_t            *recoverable
		);

/**
 * gni_smsg_buff_size_needed - Return amount of memory required for short
 *                             message resources given parameters in an input
 *                             short message attributes structure
 * IN
 * local_smsg_attr      parameters for short messaging
 *
 * OUT
 * size                 size in bytes required for the short message buffer
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 * This utility function provides an application with a way to determine the
 * amount of memory needs to be allocated for short messaging resources.  The
 * msg_buffer, buff_size, mem_hndl, and mbox_offset fields in the input
 * smsg_attr structure do not need to be defined.
 **/
gni_return_t
	gni_smsg_buff_size_needed(
		IN  gni_smsg_attr_t     *smsg_attr,
		OUT unsigned int        *size
		);

/**
 * gni_smsg_init - Initialize short messaging resources
 * IN
 * ep_hndl              The handle of the Endpoint.
 * local_smsg_attr      Local parameters for short messaging
 * remote_smsg_attr     Remote parameters for short messaging provided by peer
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_INVALID_STATE - Endpoind is not bound
 * GNI_RC_ERROR_NOMEM - Insufficient memory to allocate short message
 *                      internal structures
 *
 * Description:
 * This function configures the short messaging protocol on the given Endpoint.
 **/
gni_return_t
	gni_smsg_init(
		IN gni_ep_handle_t      ep_hndl,
		IN gni_smsg_attr_t      *local_smsg_attr,
		IN gni_smsg_attr_t      *remote_smsg_attr
		);

/**
 * gni_smsg_set_delivery_mode - Configures SMSG delivery mode.
 *
 * IN
 * nic_handle           The NIC handle to alter.
 * dlvr_mode            The new SMSG delivery mode.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid NIC handle specified or
 *                        the delivery mode is invalid.
 *
 * Description:
 * This functions sets the SMSG delivery mode for SMSG transactions.
 **/
gni_return_t
	gni_smsg_set_delivery_mode(
		IN gni_nic_handle_t        nic_handle,
		IN uint16_t                 dlvr_mode
		);

/**
 * gni_smsg_send - Send short message
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 * header       Pointer to the header of a message.
 * header_length Length of the header in bytes.
 * data         Pointer to the payload of the message.
 * data_length Length of the payload in bytes.
 * msg_id       Identifier for application to track transaction.
 *              Only valid for short messaging using MBOX_PERSISTENT type,
 *              otherwise ignored.
 *
 * Returns:
 * GNI_RC_SUCCESS - The message was successfully sent.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or
 *                        the Endpoint is not initialized for short messaging.
 * GNI_RC_NOT_DONE - No credits available to send the message
 * GNI_RC_ERROR_RESOURCE - The total size of the header plus data exceeds
 *                         the maximum short message size defined by GNI_SMSG_MAX_SIZE.
 *
 * Description:
 * This function sends a message to the remote peer, by copying it into
 * the pre-allocated remote buffer space using the FMA mechanism.
 * It returns before the delivery is confirmed by the remote NIC.
 * With MBOX_PERSISTENT type system attempts to re-transmit
 * for certain transaction failures.
 * This is a non-blocking call.
 *
 **/
gni_return_t
	gni_smsg_send(
		IN gni_ep_handle_t      ep_hndl,
		IN void                 *header,
		IN uint32_t             header_length,
		IN void                 *data,
		IN uint32_t             data_length,
		IN uint32_t             msg_id
		);

/**
 * gni_smsg_getnext - Get next available short message
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 *
 * OUT
 * header       Pointer to the header of the newly arrived message.
 *
 * Returns:
 * GNI_RC_SUCCESS - The new message is successfully arrived.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or the Endpoint is
 *                        not initialized for short messaging.
 * GNI_RC_NOT_DONE - No new messages available.
 * GNI_RC_INVALID_STATE - The SMSG connection has entered an invalid state.
 *
 * Description:
 * This function returns a pointer to the header of the newly arrived message and
 * makes this message current. An application may decide to copy the message out
 * of the mailbox or process it immediately. This is a non-blocking call.
 *
 **/
gni_return_t
	gni_smsg_getnext(
		IN  gni_ep_handle_t     ep_hndl,
		OUT void                **header
		);

/**
 * gni_smsg_release - Release current message
 *
 * Parameters:
 * IN
 * ep_hndl      Instance of an Endpoint.
 *
 * Returns:
 * GNI_RC_SUCCESS - The current message is successfully released.
 * GNI_RC_INVALID_PARAM - The Endpoint handle was invalid or the Endpoint
 *                        is not initialized for short messaging.
 * GNI_RC_NOT_DONE - There is no current message. The GetNext function must
 *                   return GNI_RC_SUCCESS before calling this function.
 *
 * Description:
 * This function releases the current message buffer. It must be called only
 * after GetNext has returned GNI_RC_SUCCESS. This is a non-blocking call.
 * The message returned by the GetNext function must be copied out or processed
 * prior to making this call.
 *
 **/
gni_return_t
	gni_smsg_release(
		IN gni_ep_handle_t      ep_hndl
		);

/**
 * gni_smsg_set_max_retrans - Configures SMSG max retransmit count.
 *
 * IN
 * nic_handle           The NIC handle to alter.
 * max_retrans          The new SMSG max retransmit count.
 *
 * Returns:
 * GNI_RC_SUCCESS - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - Invalid NIC handle specified.
 * Description:
 * This functions sets the maximum retransmit counts for SMSG transactions.
 * EPs associated with the NIC handle provided will give up retransmitting SMSG
 * transactions and return GNI_RC_TRANSACTION_ERROR when the retransmit count
 * has been reached.
 **/
gni_return_t
	gni_smsg_set_max_retrans(
		IN gni_nic_handle_t     nic_handle,
		IN uint16_t             max_retrans
		);

/**
 * gni_subscribe_errors - Subscribe to error events on associated NIC.
 *
 * Parameters:
 * IN
 * nic_handle           The handle of the associated NIC.
 * mask                 The error mask with corresponding bits set for notification.
 * EEQ_size             Size of the EEQ. If 0 is passed in there will be no queue.
 * EQ_new_event         A callback that can be triggered when new events are entered in the EQ.
 * app_crit_err         A critical event which would kill a user app will also trigger this callback.
 *
 * OUT
 * err_handle           The handle of the subscribed error events.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_ERROR_NOMEM   - The event queue could not be created due to insufficient memory.
 *
 * Description:
 * This function creates an error event queue. When this function
 * returns, events start reporting immediately.
 *
 * Also, the mask value can be a bitwise OR of the error categories as
 * defined by the GNI_ERRMASK_* flags found in gni_pub.h.
 *
 **/
gni_return_t
	gni_subscribe_errors(
		IN  gni_nic_handle_t    nic_handle,
		IN  gni_error_mask_t    mask,
		IN  uint32_t            EEQ_size,
		IN  void                (*EQ_new_event)(gni_err_handle_t),
		IN  void                (*app_crit_err)(gni_err_handle_t),
		OUT gni_err_handle_t    *err_handle
		);

/**
 * gni_release_errors - Release error event notification.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE      - A thread is still waiting on the event queue.
 *
 * Description:
 * This function releases the error event notification and cleans up
 * the memory resources for the event queue.
 *
 **/
gni_return_t
	gni_release_errors(
		IN gni_err_handle_t     err_handle
		);

/**
 * gni_get_error_mask - Get the currently set error mask.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 *
 * OUT
 * mask                 The pointer to copy the mask value to.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 * The error mask is used to match error events, and decide if the
 * subscriber wants an event delivered. This is a convenience
 * function.
 *
 **/
gni_return_t
	gni_get_error_mask(
		IN  gni_err_handle_t    err_handle,
		OUT gni_error_mask_t    *mask
		);

/**
 * gni_set_error_mask - Set a new error mask for matching events.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * mask_in              The error mask with corresponding bits set for notification.
 * mask_out             The pointer to copy the pre-set mask value to.
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 *
 * Description:
 * Set a new error mask used to match for error event delivery.
 *
 **/
gni_return_t
	gni_set_error_mask(
		IN gni_err_handle_t     err_handle,
		IN gni_error_mask_t     mask_in,
		IN gni_error_mask_t     *mask_out
		);

/**
 * gni_get_error_event - Get an error event, if available.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * event                The pointer to the buffer to copy the event into.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE         - No event was found in the event queue.
 *
 * Description:
 * This function is non-blocking and when it is called it will return
 * any new events in the event pointer.
 *
 **/
gni_return_t
	gni_get_error_event(
		IN gni_err_handle_t     err_handle,
		IN gni_error_event_t    *event
		);

/**
 * gni_wait_error_events - Wait until an error event occurs.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * events               The pointer to the buffer to copy the events into.
 * events_size          The number of events in the events pointer.
 * timeout              After first event is triggered, time to wait for subsequent events.
 *
 * OUT
 * num_events           The number of events copied into the events buffer.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 * GNI_RC_NOT_DONE         - No event was found in the event queue.
 * GNI_RC_TIMEOUT          - Timeout was triggered before any more events came.
 *
 * Description:
 * This function will block waiting forever waiting for one event to
 * occur. When that one event is triggered, it will delay returning to
 * try and coalesce error events. The timeout value is specified in
 * number of milliseconds. The number of events copied are stored in
 * the num_events structure.
 *
 **/
gni_return_t
	gni_wait_error_events(
		IN  gni_err_handle_t    err_handle,
		IN  gni_error_event_t   *events,
		IN  uint32_t            events_size,
		IN  uint32_t            timeout,
		OUT uint32_t            *num_events
		);

/**
 * gni_set_error_ptag - Set protection tag for error reporting.
 *
 * Parameters:
 * IN
 * err_handle           The handle of the subscribed error events.
 * ptag                 The protect tag to set for matching error events.
 *
 * Returns:
 * GNI_RC_SUCCESS          - Operation completed successfully.
 * GNI_RC_INVALID_PARAM    - One of the input parameters was invalid.
 * GNI_RC_PERMISSION_ERROR - Only super-user can set ptag to something other than the communication domain.
 *
 * Description:
 * This is a privileged operation only. This function allows error
 * event capturing on other ptags. It also can be set to 0 to specify
 * capturing all events.
 *
 **/
gni_return_t
	gni_set_error_ptag(
		IN gni_err_handle_t     err_handle,
		IN uint8_t              ptag
		);

/**
 * gni_set_quiesce_callback - Setup quiesce callback
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated Gemini NIC.
 * qsce_func    A callback func for when quiesce has completed
 *
 * Returns:
 * GNI_RC_SUCCESS       - Operation completed successfully.
 * GNI_RC_INVALID_PARAM - One of the input parameters was invalid.
 * GNI_RC_INVALID_STATE - The nic_hndl was already registered with a quiesce function
 *
 * Description:
 *
 * This is a private function available to Cray specific kernel
 * modules which need to be notified of quiesce state. This function
 * is called when quiesce is completed. Thus, any timers that
 * triggered in the meantime, are aware of why transfers may have
 * stalled. The callback function must not go to sleep. It is called
 * with a lock, for correctness. Finally, the second argument to the
 * callback is the time it took to quiesce in milliseconds.
 **/
gni_return_t
	gni_set_quiesce_callback(
		IN gni_nic_handle_t     nic_hndl,
		IN void                 (*qsce_func)(gni_nic_handle_t, uint64_t)
		);

/**
 * gni_get_quiesce_state - Return quiesce status
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated Gemini NIC.
 *
 * Returns:
 * 0   - Quiesce is not in progress
 * 1   - Quiesce is currently turned on
 *
 * Description:
 *
 * This is a private function available to Cray specific kernel
 * modules which need to query the quiesce state. Thus the unusual
 * return value.
 **/
uint32_t
	gni_get_quiesce_status(
		IN gni_nic_handle_t     nic_hndl
		);


/**
 * gni_get_errno - Return local CPU kgni errno value
 *
 * Parameters:
 * IN
 * nic_hndl     Handle of the associated Gemini NIC.
 *
 * OUT
 * errno_ptr    Pointer to the gni_errno_t structure to copy the local CPU GNI
 *              errno data into.
 *
 * Returns:
 * GNI_RC_SUCCESS       - GNI errno data was copied into the structre at errno_ptr.
 * GNI_RC_INVALID_PARAM - One of the parameters was invalid.
 * GNI_RC_INVALID_STATE - The local CPU GNI errno data has not been updated
 *                        since the last call to gni_get_errno().
 *
 * Description:
 *
 * This function returns extra information after certain kgni interface errors
 * occur on a CPU.  On initialization, each CPU's GNI errno data is invalid.
 * When a kgni public interface call returns an error, the local CPU's
 * gni_errno data could be set if the local CPU's gni_errno data is invalid.
 * When set, a CPU's gni_errno data must be invalidated with a call to
 * gni_get_errno() before new gni_errno data can be saved.  New errno data will
 * not be saved on the local CPU until this call is made.  Due to this, data
 * for the first kgni error (if several may occur in a single interface call)
 * will be saved in the local CPU's gni_errno data.
 **/
gni_return_t
	gni_get_errno(
		IN  gni_nic_handle_t    nic_hndl,
		OUT gni_errno_t         *errno_ptr
		);

#endif /*__KERNEL__*/

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /*_GNI_PUB_H_*/
