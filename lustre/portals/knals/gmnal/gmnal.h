/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */
#ifndef _GMNAL_H
#define _GMNAL_H

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

#define DEBUG_SUBSYSTEM S_GMNAL

#include <linux/kp30.h>
#include <portals/p30.h>
#include <portals/lib-p30.h>

#include <gm.h>


/*
 *  Myrinet GM NAL
 */
#define NPAGES_LARGE            16
#define NPAGES_SMALL            1
#define MSG_LEN_LARGE            NPAGES_LARGE*PAGE_SIZE
#define MSG_LEN_SMALL            NPAGES_SMALL*PAGE_SIZE
#define MSG_SIZE_LARGE           (gm_min_size_for_length(MSG_LEN_LARGE))
#define MSG_SIZE_SMALL           (gm_min_size_for_length(MSG_LEN_SMALL))

#define TXMSGS                  64 /* Number of Transmit Messages */
#define ENVELOPES               8  /* Number of outstanding receive msgs */

#define KGM_PORT_NUM 3
#define KGM_HOSTNAME "kgmnal"


typedef struct {
        char *krx_buffer;
        unsigned long   krx_len;
        unsigned int   krx_size;
        unsigned int   krx_priority;
        struct list_head krx_item;
}  kgmnal_rx_t;


typedef struct {
        nal_cb_t  *ktx_nal;
        void      *ktx_private;
        lib_msg_t *ktx_cookie;
        char      *ktx_buffer;
        size_t     ktx_len;
        unsigned long ktx_size;
        int        ktx_ndx;
        unsigned int ktx_priority;
        unsigned int ktx_tgt_node;
        unsigned int ktx_tgt_port_id;
}  kgmnal_tx_t;


typedef struct {
        char              kgm_init;
        char              kgm_shuttingdown;
        struct gm_port   *kgm_port;
        struct list_head  kgm_list;
        ptl_nid_t         kgm_nid;
        nal_cb_t         *kgm_cb;
        struct kgm_trans *kgm_trans;
        struct tq_struct  kgm_ready_tq;
        spinlock_t        kgm_dispatch_lock;
        spinlock_t        kgm_update_lock;
        spinlock_t        kgm_send_lock;
}  kgmnal_data_t;

int kgm_init(kgmnal_data_t *kgm_data);
int kgmnal_recv_thread(void *);
int gm_return_mynid(void);
void kgmnal_fwd_packet (void *arg, kpr_fwd_desc_t *fwd);

extern kgmnal_data_t      kgmnal_data;
extern nal_t              kgmnal_api;
extern nal_cb_t           kgmnal_lib;

#endif  /* _GMNAL_H */

