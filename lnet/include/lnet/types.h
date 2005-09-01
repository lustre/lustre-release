#ifndef __LNET_TYPES_H__
#define __LNET_TYPES_H__

#include "build_check.h"

#include <libcfs/libcfs.h>

/* This implementation uses the same type for API function return codes and
 * the completion status in an event  */
#define LNET_NI_OK  0
typedef int lnet_ni_fail_t;

typedef __u32 lnet_uid_t;
typedef __u32 lnet_jid_t;
typedef __u64 lnet_nid_t;
typedef __u32 lnet_netid_t;
typedef __u32 lnet_pid_t;
typedef __u32 lnet_pt_index_t;
typedef __u32 lnet_ac_index_t;
typedef __u64 lnet_match_bits_t;
typedef __u64 lnet_hdr_data_t;
typedef __u32 lnet_size_t;

#define LNET_TIME_FOREVER    (-1)

typedef struct {
        __u64         cookie;
} lnet_handle_any_t;

typedef lnet_handle_any_t lnet_handle_ni_t;
typedef lnet_handle_any_t lnet_handle_eq_t;
typedef lnet_handle_any_t lnet_handle_md_t;
typedef lnet_handle_any_t lnet_handle_me_t;

#define LNET_INVALID_HANDLE \
    ((const lnet_handle_any_t){.cookie = -1})
#define LNET_EQ_NONE LNET_INVALID_HANDLE

static inline int LNetHandleIsEqual (lnet_handle_any_t h1, lnet_handle_any_t h2)
{
	return (h1.cookie == h2.cookie);
}

#define LNET_UID_ANY      ((lnet_uid_t) -1)
#define LNET_JID_ANY      ((lnet_jid_t) -1)
#define LNET_NID_ANY      ((lnet_nid_t) -1)
#define LNET_PID_ANY      ((lnet_pid_t) -1)

typedef struct {
        lnet_nid_t nid;
        lnet_pid_t pid;   /* node id / process id */
} lnet_process_id_t;

typedef enum {
        LNET_RETAIN = 0,
        LNET_UNLINK
} lnet_unlink_t;

typedef enum {
        LNET_INS_BEFORE,
        LNET_INS_AFTER
} lnet_ins_pos_t;

typedef struct {
        void            *start;
        lnet_size_t       length;
        int              threshold;
        int              max_size;
        unsigned int     options;
        void            *user_ptr;
        lnet_handle_eq_t  eq_handle;
} lnet_md_t;

/* Options for the MD structure */
#define LNET_MD_OP_PUT               (1 << 0)
#define LNET_MD_OP_GET               (1 << 1)
#define LNET_MD_MANAGE_REMOTE        (1 << 2)
/* unused                           (1 << 3) */
#define LNET_MD_TRUNCATE             (1 << 4)
#define LNET_MD_ACK_DISABLE          (1 << 5)
#define LNET_MD_IOVEC		    (1 << 6)
#define LNET_MD_MAX_SIZE		    (1 << 7)
#define LNET_MD_KIOV                 (1 << 8)

/* For compatibility with Cray Portals */
#define LNET_MD_PHYS                         0

#define LNET_MD_THRESH_INF       (-1)

/* NB lustre portals uses struct iovec internally! */
typedef struct iovec lnet_md_iovec_t;

typedef struct {
	cfs_page_t      *kiov_page;
	unsigned int     kiov_len;
	unsigned int     kiov_offset;
} lnet_kiov_t;

typedef enum {
        LNET_EVENT_GET,
        LNET_EVENT_PUT,
        LNET_EVENT_REPLY,
        LNET_EVENT_ACK,
	LNET_EVENT_SEND,
	LNET_EVENT_UNLINK,
} lnet_event_kind_t;

#define LNET_SEQ_BASETYPE	long
typedef unsigned LNET_SEQ_BASETYPE lnet_seq_t;
#define LNET_SEQ_GT(a,b)	(((signed LNET_SEQ_BASETYPE)((a) - (b))) > 0)

/* XXX
 * cygwin need the pragma line, not clear if it's needed in other places.
 * checking!!!
 */
#ifdef __CYGWIN__
#pragma pack(push, 4)
#endif
typedef struct {
        lnet_event_kind_t   type;
        lnet_process_id_t   initiator;
        lnet_uid_t          uid;
        lnet_jid_t          jid;
        lnet_pt_index_t     pt_index;
        lnet_match_bits_t   match_bits;
        lnet_size_t         rlength;
        lnet_size_t         mlength;
        lnet_size_t         offset;
        lnet_handle_md_t    md_handle;
        lnet_md_t           md;
        lnet_hdr_data_t     hdr_data;
        lnet_seq_t          link;
        lnet_ni_fail_t      ni_fail_type;

        int                unlinked;

        volatile lnet_seq_t sequence;
} lnet_event_t;
#ifdef __CYGWIN__
#pragma pop
#endif

typedef enum {
        LNET_ACK_REQ,
        LNET_NOACK_REQ
} lnet_ack_req_t;

typedef void (*lnet_eq_handler_t)(lnet_event_t *event);
#define LNET_EQ_HANDLER_NONE NULL

typedef struct {
	int max_mes;
	int max_mds;
	int max_eqs;
	int max_ac_index;
	int max_pt_index;
	int max_md_iovecs;
	int max_me_list;
	int max_getput_md;
} lnet_ni_limits_t;

typedef int lnet_sr_value_t;

typedef int lnet_interface_t;
#define LNET_IFACE_DEFAULT    (-1)

#endif
