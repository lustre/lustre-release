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

typedef uint64_t lnet_nid_t;
typedef uint32_t lnet_netid_t;

#define LNET_NID_ANY      ((lnet_nid_t) -1)
#define LNET_PID_ANY      ((lnet_pid_t) -1)

enum {
        /* Only add to these values (i.e. don't ever change or redefine them):
         * network addresses depend on them... */
        QSWLND    = 1,
        SOCKLND   = 2,
        GMLND     = 3,
        PTLLND    = 4,
        O2IBLND   = 5,
        CIBLND    = 6,
        OPENIBLND = 7,
        IIBLND    = 8,
        LOLND     = 9,
        RALND     = 10,
        VIBLND    = 11,
        LND_ENUM_END_MARKER
};

int lnet_nid2hostname(lnet_nid_t nid, char *buf, int buflen);
int lookup_mapping(char *princ, uint64_t nid, uid_t *uid);
lnet_nid_t libcfs_str2nid(char *str);

/* how an LNET NID encodes net:address */
#define LNET_NIDADDR(nid)      ((uint32_t)((nid) & 0xffffffff))
#define LNET_NIDNET(nid)       ((uint32_t)(((nid) >> 32)) & 0xffffffff)
#define LNET_MKNID(net,addr)   ((((uint64_t)(net))<<32)|((uint64_t)(addr)))
/* how net encodes type:number */
#define LNET_NETNUM(net)       ((net) & 0xffff)
#define LNET_NETTYP(net)       (((net) >> 16) & 0xffff)
#define LNET_MKNET(typ,num)    ((((uint32_t)(typ))<<16)|((uint32_t)(num)))

#endif /* __LIBCFS_H__ */
