/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 */

#ifndef _OBD_PTLBD_H
#define _OBD_PTLBD_H

#include <linux/obd.h>

#define OBD_PTLBD_SV_DEVICENAME "ptlbd_server"
#define OBD_PTLBD_CL_DEVICENAME "ptlbd_client"

/* XXX maybe this isn't the best header to be dumping all this in.. */

extern int ptlbd_blk_init(void);
extern int ptlbd_cl_init(void);
extern int ptlbd_sv_init(void);

extern void ptlbd_blk_exit(void);
extern void ptlbd_cl_exit(void);
extern void ptlbd_sv_exit(void);

extern int ptlbd_do_connect(struct ptlbd_obd *);
extern int ptlbd_do_disconnect(struct ptlbd_obd *);
extern void ptlbd_blk_register(struct ptlbd_obd *ptlbd);
extern int ptlbd_send_rw_req(struct ptlbd_obd *, ptlbd_cmd_t cmd,
			     struct buffer_head *);
extern int ptlbd_send_flush_req(struct ptlbd_obd *, ptlbd_cmd_t cmd);
extern int ptlbd_handle(struct ptlrpc_request *req);

#endif
