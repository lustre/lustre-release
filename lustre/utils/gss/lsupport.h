/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __LIBCFS_H__
#define __LIBCFS_H__

#include <unistd.h>
#include <stdint.h>

#define GSSD_CLI        (0)
#define GSSD_SVC        (1)

void gssd_init_unique(int type);
void gssd_exit_unique(int type);

/*
 * copied from lustre source
 */

typedef uint64_t ptl_nid_t;
typedef uint32_t ptl_netid_t;

#define LUSTRE_GSS_SVC_MDS      0
#define LUSTRE_GSS_SVC_OSS      1

struct lgssd_upcall_data {
        uint32_t        seq;
        uint32_t        uid;
        uint32_t        gid;
        uint32_t        svc;
        uint64_t        nid;
        char            obd[64];
};

#define GSSD_INTERFACE_VERSION        (1)

struct lgssd_ioctl_param {
        int             version;        /* in   */
        char           *uuid;           /* in   */
        int             lustre_svc;     /* in   */
        uid_t           uid;            /* in   */
        gid_t           gid;            /* in   */
        long            send_token_size;/* in   */
        char           *send_token;     /* in   */
        long            reply_buf_size; /* in   */
        char           *reply_buf;      /* in   */
        long            status;         /* out  */
        long            reply_length;   /* out  */
};

#define GSSD_DEFAULT_GETHOSTNAME_EX     "/etc/lustre/nid2hostname"
#define MAPPING_DATABASE_FILE           "/etc/lustre/idmap.conf"

int ptl_nid2hostname(uint64_t nid, char *buf, int buflen);
int lookup_mapping(char *princ, uint32_t nal, ptl_netid_t netid,
                   ptl_nid_t nid, uid_t *uid);

/* how an LNET NID encodes net:address */
#define LNET_NIDADDR(nid)      ((uint32_t)((nid) & 0xffffffff))
#define LNET_NIDNET(nid)       ((uint32_t)(((nid) >> 32)) & 0xffffffff)
#define LNET_MKNID(net,addr)   ((((uint64_t)(net))<<32)|((uint64_t)(addr)))
/* how net encodes type:number */
#define LNET_NETNUM(net)       ((net) & 0xffff)
#define LNET_NETTYP(net)       (((net) >> 16) & 0xffff)
#define LNET_MKNET(typ,num)    ((((uint32_t)(typ))<<16)|((uint32_t)(num)))

#endif /* __LIBCFS_H__ */
