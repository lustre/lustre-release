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

#include <portals/types.h>
#ifdef __KERNEL__
# define PTL_USE_SLAB_CACHE
# include <linux/uio.h>
# include <linux/smp_lock.h>
# include <linux/types.h>
#else
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

/* Each of these structs should start with an odd number of
 * __u32, or the compiler could add its own padding and confuse
 * everyone.
 *
 * Also, "length" needs to be at offset 28 of each struct.
 */
typedef struct ptl_ack {
        ptl_size_t mlength;
        ptl_handle_wire_t dst_wmd;
        ptl_match_bits_t match_bits;
        ptl_size_t length;                      /* common length (0 for acks) moving out RSN */
} WIRE_ATTR ptl_ack_t;

typedef struct ptl_put {
        ptl_pt_index_t ptl_index;
        ptl_handle_wire_t ack_wmd;
        ptl_match_bits_t match_bits;
        ptl_size_t length;                      /* common length moving out RSN */
        ptl_size_t offset;
        ptl_hdr_data_t hdr_data;
} WIRE_ATTR ptl_put_t;

typedef struct ptl_get {
        ptl_pt_index_t ptl_index;
        ptl_handle_wire_t return_wmd;
        ptl_match_bits_t match_bits;
        ptl_size_t length;                      /* common length (0 for gets) moving out RSN */
        ptl_size_t src_offset;
        ptl_size_t return_offset;               /* unused: going RSN */
        ptl_size_t sink_length;
} WIRE_ATTR ptl_get_t;

typedef struct ptl_reply {
        __u32 unused1;                          /* unused fields going RSN */
        ptl_handle_wire_t dst_wmd;
        ptl_size_t dst_offset;                  /* unused: going RSN */
        __u32 unused2;
        ptl_size_t length;                      /* common length moving out RSN */
} WIRE_ATTR ptl_reply_t;

typedef struct {
        ptl_nid_t dest_nid;
        ptl_nid_t src_nid;
        ptl_pid_t dest_pid;
        ptl_pid_t src_pid;
        __u32 type; /* ptl_msg_type_t */
        union {
                ptl_ack_t ack;
                ptl_put_t put;
                ptl_get_t get;
                ptl_reply_t reply;
        } msg;
} WIRE_ATTR ptl_hdr_t;

/* All length fields in individual unions at same offset */
/* LASSERT for same in lib-move.c */
#define PTL_HDR_LENGTH(h) ((h)->msg.ack.length)

/* A HELLO message contains the portals magic number and protocol version
 * code in the header's dest_nid, the peer's NID in the src_nid, and
 * PTL_MSG_HELLO in the type field.  All other fields are zero (including
 * PTL_HDR_LENGTH; i.e. no payload).
 * This is for use by byte-stream NALs (e.g. TCP/IP) to check the peer is
 * running the same protocol and to find out its NID, so that hosts with
 * multiple IP interfaces can have a single NID. These NALs should exchange
 * HELLO messages when a connection is first established. */
typedef struct {
        __u32	magic;                          /* PORTALS_PROTO_MAGIC */
        __u16   version_major;                  /* increment on incompatible change */
        __u16   version_minor;                  /* increment on compatible change */
} WIRE_ATTR ptl_magicversion_t;

#define PORTALS_PROTO_MAGIC                0xeebc0ded

#define PORTALS_PROTO_VERSION_MAJOR        0
#define PORTALS_PROTO_VERSION_MINOR        1

typedef struct {
        long recv_count, recv_length, send_count, send_length, drop_count,
            drop_length, msgs_alloc, msgs_max;
} lib_counters_t;

/* temporary expedient: limit number of entries in discontiguous MDs */
#if PTL_LARGE_MTU
# define PTL_MD_MAX_IOV	64
#else
# define PTL_MD_MAX_IOV 16
#endif

struct lib_msg_t {
        struct list_head  msg_list;
        int               send_ack;
        lib_md_t         *md;
        ptl_nid_t         nid;
        ptl_pid_t         pid;
        ptl_event_t       ev;
        ptl_handle_wire_t ack_wmd;
        union {
                struct iovec  iov[PTL_MD_MAX_IOV];
                ptl_kiov_t    kiov[PTL_MD_MAX_IOV];
        } msg_iov;
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
        int (*event_callback) (ptl_event_t * event);
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
        ptl_unlink_t      unlink;
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

#define PTL_MD_FLAG_UNLINK            (1 << 0)
#define PTL_MD_FLAG_AUTO_UNLINKED     (1 << 1)

#ifndef PTL_USE_SLAB_CACHE
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
        int up;
        int refcnt;
        ptl_nid_t nid;
        ptl_pid_t pid;
        int num_nodes;
        unsigned int debug;
        lib_ptl_t tbl;
        lib_ac_t ac;
        lib_counters_t counters;

        int               ni_lh_hash_size;      /* size of lib handle hash table */
        struct list_head *ni_lh_hash_table;     /* all extant lib handles, this interface */
        __u64             ni_next_object_cookie; /* cookie generator */
        __u64             ni_interface_cookie;  /* uniquely identifies this ni in this epoch */
        
        struct list_head ni_test_peers;
        
#ifndef PTL_USE_SLAB_CACHE
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
