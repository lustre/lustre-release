/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:cindent:
 *
 * Copyright (C) 2003 High Performance Computing Center North (HPC2N)
 *   Author: Niklas Edmundsson <nikke@hpc2n.umu.se>
 */


#ifndef _SCIMACNAL_H
#define _SCIMACNAL_H

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/locks.h>
#include <linux/unistd.h>
#include <linux/init.h>

#include <asm/system.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <asm/segment.h>
#include <asm/page.h>            /* For PAGE_SIZE */

#define DEBUG_SUBSYSTEM S_UNDEFINED

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

#include <scamac.h>

#ifndef MAC_SAPID_LUSTRE
#define MAC_SAPID_LUSTRE MAC_SAPID_TEST1
#endif /* MAC_SAPID_LUSTRE */

#define SCIMACNAL_MTU 65536
/* FIXME: What is really the MTU of lustre? */
#if PTL_MD_MAX_IOV*PAGE_SIZE > SCIMACNAL_MTU
#error Max MTU of ScaMAC is 64k, PTL_MD_MAX_IOV*PAGE_SIZE is bigger.
#endif

typedef struct {
        mac_handle_t    *handle;
        mac_mblk_t      *msg;
        mac_msg_type_t   type;
        void            *userdata;
}  kscimacnal_rx_t;


typedef struct {
        nal_cb_t        *ktx_nal;
        void            *ktx_private;
        lib_msg_t       *ktx_cookie;
        ptl_hdr_t       ktx_hdr;
}  kscimacnal_tx_t;


typedef struct {
        char              ksci_init;
        char              ksci_shuttingdown;
        ptl_nid_t         ksci_nid;
        nal_cb_t         *ksci_cb;
        spinlock_t        ksci_dispatch_lock;
        mac_handle_t     *ksci_machandle;
}  kscimacnal_data_t;

extern kscimacnal_data_t   kscimacnal_data;
extern nal_t            kscimacnal_api;
extern nal_cb_t         kscimacnal_lib;

void kscimacnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd);
void kscimacnal_rx(mac_handle_t *handle, mac_mblk_t *msg, mac_msg_type_t type, void *userdata);


#endif  /* _SCIMACNAL_H */
