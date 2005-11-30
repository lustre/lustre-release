/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *   This file is part of Lustre, http://www.lustre.org
 *
 * Lustre disk format definitions.
 */
#ifndef _LUSTRE_DISK_H
#define _LUSTRE_DISK_H_
#define LAST_RCVD "last_rcvd"
#define LOV_OBJID "lov_objid"

#define OBD_COMPAT_OST          0x00000002 /* this is an OST (temporary) */
#define OBD_COMPAT_MDT          0x00000004 /* this is an MDT (temporary) */

#define OBD_ROCOMPAT_LOVOBJID   0x00000001 /* MDS handles LOV_OBJID file */
#define OBD_ROCOMPAT_CROW       0x00000002 /* OST will CROW create objects */

#define OBD_INCOMPAT_GROUPS     0x00000001 /* OST handles group subdirs */
#define OBD_INCOMPAT_OST        0x00000002 /* this is an OST (permanent) */
#define OBD_INCOMPAT_MDT        0x00000004 /* this is an MDT (permanent) */

#define LR_SERVER_SIZE   512
#define LR_CLIENT_START 8192
#define LR_CLIENT_SIZE   128
#if LR_CLIENT_START < LR_SERVER_SIZE
#error "Can't have LR_CLIENT_START < LR_SERVER_SIZE"
#endif
/* This limit is arbitrary (32k clients on x86), but it is convenient to use
 * 2^n * PAGE_SIZE * 8 for the number of bits that fit an order-n allocation. */
#define LR_MAX_CLIENTS (PAGE_SIZE * 8)

/* Data stored per client in the last_rcvd file.  In le32 order. */
struct lsd_client_data {
        __u8 lcd_uuid[40];      /* client UUID */
        __u64 lcd_last_transno; /* last completed transaction ID */
        __u64 lcd_last_xid;     /* xid for the last transaction */
        __u32 lcd_last_result;  /* result from last RPC */
        __u32 lcd_last_data;    /* per-op data (disposition for open &c.) */
        /* for MDS_CLOSE requests */
        __u64 lcd_last_close_transno; /* last completed transaction ID */
        __u64 lcd_last_close_xid;     /* xid for the last transaction */
        __u32 lcd_last_close_result;  /* result from last RPC */
        __u32 lcd_last_close_data;    /* per-op data */
        __u8 lcd_padding[LR_CLIENT_SIZE - 88];
};

#endif /* _LUSTRE_DISK_H_ */
