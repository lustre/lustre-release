/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef __LNET_TYPES_H__
#define __LNET_TYPES_H__

#include <libcfs/libcfs.h>

#define LNET_RESERVED_PORTAL      0  /* portals reserved for lnet's own use */

typedef __u64 lnet_nid_t;
typedef __u32 lnet_pid_t;

#define LNET_NID_ANY      ((lnet_nid_t) -1)
#define LNET_PID_ANY      ((lnet_pid_t) -1)

#ifdef CRAY_XT3
typedef __u32 lnet_uid_t;
#define LNET_UID_ANY      ((lnet_uid_t) -1)
#endif

#define LNET_PID_RESERVED 0xf0000000 /* reserved bits in PID */
#define LNET_PID_USERFLAG 0x80000000 /* set in userspace peers */

#define LNET_TIME_FOREVER    (-1)

typedef struct {
        __u64         cookie;
} lnet_handle_any_t;

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
        unsigned int     length;
        int              threshold;
        int              max_size;
        unsigned int     options;
        void            *user_ptr;
        lnet_handle_eq_t eq_handle;
} lnet_md_t;

/* Max Transfer Unit (minimum supported everywhere) */
#define LNET_MTU_BITS   20
#define LNET_MTU        (1<<LNET_MTU_BITS)

/* limit on the number of entries in discontiguous MDs */
#define LNET_MAX_IOV    256

/* Max payload size */
#ifndef LNET_MAX_PAYLOAD
# error "LNET_MAX_PAYLOAD must be defined in config.h"
#else
# if (LNET_MAX_PAYLOAD < LNET_MTU)
#  error "LNET_MAX_PAYLOAD too small - error in configure --with-max-payload-mb"
# elif defined(__KERNEL__)
#  if (LNET_MAX_PAYLOAD > (PAGE_SIZE * LNET_MAX_IOV))
/*  PAGE_SIZE is a constant: check with cpp! */
#   error "LNET_MAX_PAYLOAD too large - error in configure --with-max-payload-mb"
#  endif
# endif
#endif

/* Options for the MD structure */
#define LNET_MD_OP_PUT               (1 << 0)
#define LNET_MD_OP_GET               (1 << 1)
#define LNET_MD_MANAGE_REMOTE        (1 << 2)
/* unused                            (1 << 3) */
#define LNET_MD_TRUNCATE             (1 << 4)
#define LNET_MD_ACK_DISABLE          (1 << 5)
#define LNET_MD_IOVEC                (1 << 6)
#define LNET_MD_MAX_SIZE             (1 << 7)
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

#define LNET_SEQ_BASETYPE       long
typedef unsigned LNET_SEQ_BASETYPE lnet_seq_t;
#define LNET_SEQ_GT(a,b)        (((signed LNET_SEQ_BASETYPE)((a) - (b))) > 0)

/* XXX
 * cygwin need the pragma line, not clear if it's needed in other places.
 * checking!!!
 */
#ifdef __CYGWIN__
#pragma pack(push, 4)
#endif
typedef struct {
        lnet_process_id_t   target;
        lnet_process_id_t   initiator;
        lnet_nid_t          sender;
        lnet_event_kind_t   type;
        unsigned int        pt_index;
        __u64               match_bits;
        unsigned int        rlength;
        unsigned int        mlength;
        lnet_handle_md_t    md_handle;
        lnet_md_t           md;
        __u64               hdr_data;
        int                 status;
        int                 unlinked;
        unsigned int        offset;
#ifdef CRAY_XT3
        lnet_uid_t          uid;
#endif

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

#endif
