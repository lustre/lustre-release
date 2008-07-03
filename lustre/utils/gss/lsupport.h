/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef __LSUPPORT_H__
#define __LSUPPORT_H__

#include <unistd.h>
#include <stdint.h>

#include <libcfs/libcfs.h>

#define GSSD_CLI        (0)
#define GSSD_SVC        (1)

void gssd_init_unique(int type);
void gssd_exit_unique(int type);

/*
 * copied from lustre source
 */

#define LUSTRE_GSS_SVC_MDS      0
#define LUSTRE_GSS_SVC_OSS      1

extern const char * lustre_svc_name[];

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
        int             secid;          /* in   */
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

int lnet_nid2hostname(lnet_nid_t nid, char *buf, int buflen);
void cleanup_mapping(void);
int lookup_mapping(char *princ, uint64_t nid, uid_t *uid);

#endif /* __LSUPPORT_H__ */
