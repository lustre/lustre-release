#ifndef _P30_TYPES_H_
#define _P30_TYPES_H_

#include "build_check.h"

#ifdef __linux__
# include <asm/types.h>
# if defined(__powerpc__) && !defined(__KERNEL__)
#  define __KERNEL__
#  include <asm/timex.h>
#  undef __KERNEL__
# else
#  include <asm/timex.h>
# endif
#else
# include <sys/types.h>
typedef u_int32_t __u32;
typedef u_int64_t __u64;
#endif

#ifdef __KERNEL__
# include <linux/time.h>
#else
# include <sys/time.h>
# define do_gettimeofday(tv) gettimeofday(tv, NULL);
#endif

#include <portals/errno.h>

/* This implementation uses the same type for API function return codes and
 * the completion status in an event  */
#define PTL_NI_OK  PTL_OK
typedef ptl_err_t ptl_ni_fail_t;

typedef __u64 ptl_nid_t;
typedef __u32 ptl_pid_t;
typedef __u32 ptl_pt_index_t;
typedef __u32 ptl_ac_index_t;
typedef __u64 ptl_match_bits_t;
typedef __u64 ptl_hdr_data_t;
typedef __u32 ptl_size_t;

#define PTL_TIME_FOREVER    (-1)
#define PTL_EQ_HANDLER_NONE NULL

typedef struct {
        unsigned long nal_idx;			/* which network interface */
        __u64         cookie;			/* which thing on that interface */
} ptl_handle_any_t;

typedef ptl_handle_any_t ptl_handle_ni_t;
typedef ptl_handle_any_t ptl_handle_eq_t;
typedef ptl_handle_any_t ptl_handle_md_t;
typedef ptl_handle_any_t ptl_handle_me_t;

#define PTL_INVALID_HANDLE \
    ((const ptl_handle_any_t){.nal_idx = -1, .cookie = -1})
#define PTL_EQ_NONE PTL_INVALID_HANDLE

static inline int PtlHandleIsEqual (ptl_handle_any_t h1, ptl_handle_any_t h2)
{
	return (h1.nal_idx == h2.nal_idx && h1.cookie == h2.cookie);
}

#define PTL_NID_ANY      ((ptl_nid_t) -1)
#define PTL_PID_ANY      ((ptl_pid_t) -1)

typedef struct {
        ptl_nid_t nid;
        ptl_pid_t pid;   /* node id / process id */
} ptl_process_id_t;

typedef enum {
        PTL_RETAIN = 0,
        PTL_UNLINK
} ptl_unlink_t;

typedef enum {
        PTL_INS_BEFORE,
        PTL_INS_AFTER
} ptl_ins_pos_t;

typedef struct {
	struct page     *kiov_page;
	unsigned int     kiov_len;
	unsigned int     kiov_offset;
} ptl_kiov_t;

typedef struct {
        void            *start;
        ptl_size_t       length;
        int              threshold;
        int              max_size;
        unsigned int     options;
        void            *user_ptr;
        ptl_handle_eq_t  eventq;
	unsigned int     niov;
} ptl_md_t;

/* Options for the MD structure */
#define PTL_MD_OP_PUT               (1 << 0)
#define PTL_MD_OP_GET               (1 << 1)
#define PTL_MD_MANAGE_REMOTE        (1 << 2)
/* unused                           (1 << 3) */
#define PTL_MD_TRUNCATE             (1 << 4)
#define PTL_MD_ACK_DISABLE          (1 << 5)
#define PTL_MD_IOVEC		    (1 << 6)
#define PTL_MD_MAX_SIZE		    (1 << 7)
#define PTL_MD_KIOV                 (1 << 8)
#define PTL_MD_EVENT_START_DISABLE  (1 << 9)
#define PTL_MD_EVENT_END_DISABLE    (1 << 10)

/* For compatibility with Cray Portals */
#define PTL_MD_LUSTRE_COMPLETION_SEMANTICS  0

#define PTL_MD_THRESH_INF       (-1)

typedef enum {
        PTL_EVENT_GET_START,
        PTL_EVENT_GET_END,

        PTL_EVENT_PUT_START,
        PTL_EVENT_PUT_END,

        PTL_EVENT_REPLY_START,
        PTL_EVENT_REPLY_END,

        PTL_EVENT_ACK,

        PTL_EVENT_SEND_START,
	PTL_EVENT_SEND_END,

	PTL_EVENT_UNLINK,
} ptl_event_kind_t;

#define PTL_SEQ_BASETYPE	long
typedef unsigned PTL_SEQ_BASETYPE ptl_seq_t;
#define PTL_SEQ_GT(a,b)	(((signed PTL_SEQ_BASETYPE)((a) - (b))) > 0)

/* XXX
 * cygwin need the pragma line, not clear if it's needed in other places.
 * checking!!!
 */
#ifdef __CYGWIN__
#pragma pack(push, 4)
#endif
typedef struct {
        ptl_event_kind_t   type;
        ptl_process_id_t   initiator;
        ptl_pt_index_t     portal;
        ptl_match_bits_t   match_bits;
        ptl_size_t         rlength;
	ptl_size_t         mlength;
	ptl_size_t         offset;
        ptl_md_t           mem_desc;
        ptl_hdr_data_t     hdr_data;
	int                unlinked;
	ptl_ni_fail_t      ni_fail_type;

        volatile ptl_seq_t sequence;
} ptl_event_t;
#ifdef __CYGWIN__
#pragma pop
#endif

typedef enum {
        PTL_ACK_REQ,
        PTL_NOACK_REQ
} ptl_ack_req_t;

typedef struct {
        volatile ptl_seq_t sequence;
        ptl_size_t size;
        ptl_event_t *base;
        ptl_handle_any_t cb_eq_handle;
} ptl_eq_t;

typedef struct {
        ptl_eq_t *eq;
} ptl_ni_t;

typedef struct {
        int max_match_entries;    /* max number of match entries */
        int max_mem_descriptors;  /* max number of memory descriptors */
        int max_event_queues;     /* max number of event queues */
        int max_atable_index;     /* maximum access control list table index */
        int max_ptable_index;     /* maximum portals table index */
} ptl_ni_limits_t;

/*
 * Status registers
 */
typedef enum {
        PTL_SR_DROP_COUNT,
        PTL_SR_DROP_LENGTH,
        PTL_SR_RECV_COUNT,
        PTL_SR_RECV_LENGTH,
        PTL_SR_SEND_COUNT,
        PTL_SR_SEND_LENGTH,
        PTL_SR_MSGS_MAX,
} ptl_sr_index_t;

typedef int ptl_sr_value_t;

#endif
