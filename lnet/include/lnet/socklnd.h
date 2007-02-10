/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * <lnet/socklnd.h>
 *
 * #defines shared between socknal implementation and utilities
 */
#ifndef __LNET_LNET_SOCKLND_H__
#define __LNET_LNET_SOCKLND_H__

#include <lnet/types.h>
#include <lnet/lib-types.h>

#define SOCKLND_CONN_NONE     (-1)
#define SOCKLND_CONN_ANY        0
#define SOCKLND_CONN_CONTROL    1
#define SOCKLND_CONN_BULK_IN    2
#define SOCKLND_CONN_BULK_OUT   3
#define SOCKLND_CONN_NTYPES     4

typedef struct {
        __u32                   kshm_magic;     /* magic number of socklnd message */
        __u32                   kshm_version;   /* version of socklnd message */
        lnet_nid_t              kshm_src_nid;   /* sender's nid */
        lnet_nid_t              kshm_dst_nid;   /* destination nid */
        lnet_pid_t              kshm_src_pid;   /* sender's pid */
        lnet_pid_t              kshm_dst_pid;   /* destination pid */
        __u64                   kshm_src_incarnation; /* sender's incarnation */
        __u64                   kshm_dst_incarnation; /* destination's incarnation */
        __u32                   kshm_ctype;     /* connection type */
        __u32                   kshm_nips;      /* # IP addrs */
        __u32                   kshm_ips[0];    /* IP addrs */
} WIRE_ATTR ksock_hello_msg_t;

typedef struct {
        lnet_hdr_t              ksnm_hdr;       /* lnet hdr */
        char                    ksnm_payload[0];/* lnet payload */
} WIRE_ATTR ksock_lnet_msg_t;

typedef struct {
        __u32                   ksm_type;       /* type of socklnd message */
        __u32                   ksm_csum;       /* checksum if != 0 */
        __u64                   ksm_zc_req_cookie; /* ack required if != 0 */
        __u64                   ksm_zc_ack_cookie; /* ack if != 0 */
        union {
                ksock_lnet_msg_t lnetmsg;       /* lnet message, it's empty if it's NOOP */
        } WIRE_ATTR ksm_u;
} WIRE_ATTR ksock_msg_t;

#define KSOCK_MSG_NOOP          0xc0            /* ksm_u empty */ 
#define KSOCK_MSG_LNET          0xc1            /* lnet msg */

#endif
