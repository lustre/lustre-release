/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * p30/lib-types.h
 *
 * Types used by the library side routines that do not need to be
 * exposed to the user application
 */

#ifndef _LIB_TYPES_H_
#define _LIB_TYPES_H_

#include "build_check.h"

#include <portals/types.h>
#ifdef __KERNEL__
# include <linux/uio.h>
# include <linux/smp_lock.h>
# include <linux/types.h>
#else
# define PTL_USE_LIB_FREELIST
# include <sys/types.h>
#endif

/* struct nal_cb_t is defined in lib-nal.h */
typedef struct nal_cb_t nal_cb_t;

typedef char *user_ptr;
typedef struct lib_msg_t lib_msg_t;
typedef struct lib_ptl_t lib_ptl_t;
typedef struct lib_ac_t lib_ac_t;
typedef struct lib_me_t lib_me_t;
typedef struct lib_md_t lib_md_t;
typedef struct lib_eq_t lib_eq_t;

#define WIRE_ATTR	__attribute__((packed))

/* The wire handle's interface cookie only matches one network interface in
 * one epoch (i.e. new cookie when the interface restarts or the node
 * reboots).  The object cookie only matches one object on that interface
 * during that object's lifetime (i.e. no cookie re-use). */
typedef struct {
        __u64 wh_interface_cookie;
        __u64 wh_object_cookie;
} WIRE_ATTR ptl_handle_wire_t;

/* byte-flip insensitive! */
#define PTL_WIRE_HANDLE_NONE \
((const ptl_handle_wire_t) {.wh_interface_cookie = -1, .wh_object_cookie = -1})

typedef enum {
        PTL_MSG_ACK = 0,
        PTL_MSG_PUT,
        PTL_MSG_GET,
        PTL_MSG_REPLY,
        PTL_MSG_HELLO,
} ptl_msg_type_t;

/* The variant fields of the portals message header are aligned on an 8
 * byte boundary in the message header.  Note that all types used in these
 * wire structs MUST be fixed size and the smaller types are placed at the
 * end. */
typedef struct ptl_ack {
        ptl_handle_wire_t  dst_wmd;
        ptl_match_bits_t   match_bits;
        ptl_size_t         mlength;
} WIRE_ATTR ptl_ack_t;

typedef struct ptl_put {
        ptl_handle_wire_t  ack_wmd;
        ptl_match_bits_t   match_bits;
        ptl_hdr_data_t     hdr_data;
        ptl_pt_index_t     ptl_index;
        ptl_size_t         offset;
} WIRE_ATTR ptl_put_t;

typedef struct ptl_get {
        ptl_handle_wire_t  return_wmd;
        ptl_match_bits_t   match_bits;
        ptl_pt_index_t     ptl_index;
        ptl_size_t         src_offset;
        ptl_size_t         sink_length;
} WIRE_ATTR ptl_get_t;

typedef struct ptl_reply {
        ptl_handle_wire_t  dst_wmd;
} WIRE_ATTR ptl_reply_t;

typedef struct ptl_hello {
        __u64              incarnation;
        __u32              type;
} WIRE_ATTR ptl_hello_t;

typedef struct {
        ptl_nid_t           dest_nid;
        ptl_nid_t           src_nid;
        ptl_pid_t           dest_pid;
        ptl_pid_t           src_pid;
        __u32               type;               /* ptl_msg_type_t */
        __u32               payload_length;     /* payload data to follow */
        /*<------__u64 aligned------->*/
        union {
                ptl_ack_t   ack;
                ptl_put_t   put;
                ptl_get_t   get;
                ptl_reply_t reply;
                ptl_hello_t hello;
        } msg;
} WIRE_ATTR ptl_hdr_t;

/* A HELLO message contains the portals magic number and protocol version
 * code in the header's dest_nid, the peer's NID in the src_nid, and
 * PTL_MSG_HELLO in the type field.  All other common fields are zero
 * (including payload_size; i.e. no payload).  
 * This is for use by byte-stream NALs (e.g. TCP/IP) to check the peer is
 * running the same protocol and to find out its NID, so that hosts with
 * multiple IP interfaces can have a single NID. These NALs should exchange
 * HELLO messages when a connection is first established. 
 * Individual NALs can put whatever else they fancy in ptl_hdr_t::msg. 
 */
typedef struct {
        __u32	magic;                          /* PORTALS_PROTO_MAGIC */
        __u16   version_major;                  /* increment on incompatible change */
        __u16   version_minor;                  /* increment on compatible change */
} WIRE_ATTR ptl_magicversion_t;

#define PORTALS_PROTO_MAGIC                0xeebc0ded

#define PORTALS_PROTO_VERSION_MAJOR        0
#define PORTALS_PROTO_VERSION_MINOR        3

typedef struct {
        long recv_count, recv_length, send_count, send_length, drop_count,
            drop_length, msgs_alloc, msgs_max;
} lib_counters_t;

/* temporary expedient: limit number of entries in discontiguous MDs */
#define PTL_MTU        (512<<10)
#define PTL_MD_MAX_IOV 128

struct lib_msg_t {
        struct list_head  msg_list;
        lib_md_t         *md;
        ptl_handle_wire_t ack_wmd;
        ptl_event_t       ev;
};

struct lib_ptl_t {
        ptl_pt_index_t size;
        struct list_head *tbl;
};

struct lib_ac_t {
        int next_free;
};

typedef struct {
        struct list_head  lh_hash_chain;
        __u64             lh_cookie;
} lib_handle_t;

#define lh_entry(ptr, type, member) \
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

struct lib_eq_t {
        struct list_head  eq_list;
        lib_handle_t      eq_lh;
        ptl_seq_t         sequence;
        ptl_size_t        size;
        ptl_event_t      *base;
        int               eq_refcount;
        ptl_eq_handler_t  event_callback;
        void             *eq_addrkey;
};

struct lib_me_t {
        struct list_head  me_list;
        lib_handle_t      me_lh;
        ptl_process_id_t  match_id;
        ptl_match_bits_t  match_bits, ignore_bits;
        ptl_unlink_t      unlink;
        lib_md_t         *md;
};

struct lib_md_t {
        struct list_head  md_list;
        lib_handle_t      md_lh;
        lib_me_t         *me;
        user_ptr          start;
        ptl_size_t        offset;
        ptl_size_t        length;
        ptl_size_t        max_size;
        int               threshold;
        int               pending;
        unsigned int      options;
        unsigned int      md_flags;
        void             *user_ptr;
        lib_eq_t         *eq;
        void             *md_addrkey;
        unsigned int      md_niov;                /* # frags */
        union {
                struct iovec  iov[PTL_MD_MAX_IOV];
                ptl_kiov_t    kiov[PTL_MD_MAX_IOV];
        } md_iov;
};

#define PTL_MD_FLAG_ZOMBIE            (1 << 0)
#define PTL_MD_FLAG_AUTO_UNLINK       (1 << 1)

static inline int lib_md_exhausted (lib_md_t *md) 
{
        return (md->threshold == 0 ||
                ((md->options & PTL_MD_MAX_SIZE) != 0 &&
                 md->offset + md->max_size > md->length));
}

#ifdef PTL_USE_LIB_FREELIST
typedef struct
{
        void	          *fl_objs;             /* single contiguous array of objects */
        int                fl_nobjs;            /* the number of them */
        int                fl_objsize;          /* the size (including overhead) of each of them */
        struct list_head   fl_list;             /* where they are enqueued */
} lib_freelist_t;

typedef struct
{
        struct list_head   fo_list;             /* enqueue on fl_list */
        void              *fo_contents;         /* aligned contents */
} lib_freeobj_t;
#endif

typedef struct {
        /* info about peers we are trying to fail */
        struct list_head  tp_list;             /* stash in ni.ni_test_peers */
        ptl_nid_t         tp_nid;              /* matching nid */
        unsigned int      tp_threshold;        /* # failures to simulate */
} lib_test_peer_t;

#define PTL_COOKIE_TYPE_MD    1
#define PTL_COOKIE_TYPE_ME    2
#define PTL_COOKIE_TYPE_EQ    3
#define PTL_COOKIE_TYPES      4
/* PTL_COOKIE_TYPES must be a power of 2, so the cookie type can be
 * extracted by masking with (PTL_COOKIE_TYPES - 1) */

typedef struct {
        ptl_nid_t nid;
        ptl_pid_t pid;
        lib_ptl_t tbl;
        lib_counters_t counters;
        ptl_ni_limits_t actual_limits;

        int               ni_lh_hash_size;      /* size of lib handle hash table */
        struct list_head *ni_lh_hash_table;     /* all extant lib handles, this interface */
        __u64             ni_next_object_cookie; /* cookie generator */
        __u64             ni_interface_cookie;  /* uniquely identifies this ni in this epoch */
        
        struct list_head ni_test_peers;
        
#ifdef PTL_USE_LIB_FREELIST
        lib_freelist_t   ni_free_mes;
        lib_freelist_t   ni_free_msgs;
        lib_freelist_t   ni_free_mds;
        lib_freelist_t   ni_free_eqs;
#endif
        struct list_head ni_active_msgs;
        struct list_head ni_active_mds;
        struct list_head ni_active_eqs;
} lib_ni_t;

#endif
