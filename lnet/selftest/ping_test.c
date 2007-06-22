/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 *
 * This file is part of Lustre, http://www.lustre.org
 *
 * Test client & Server
 */
#include <libcfs/kp30.h>
#include "selftest.h"

#define LST_PING_TEST_MAGIC     0xbabeface

typedef struct {
        spinlock_t      pnd_lock;       /* serialize */
        int             pnd_counter;    /* sequence counter */
        int             pnd_err_count;  /* error count */
} lst_ping_data_t;

static lst_ping_data_t  lst_ping_data;

static int
ping_client_init(sfw_test_instance_t *tsi)
{
        spin_lock_init(&lst_ping_data.pnd_lock);
        lst_ping_data.pnd_counter   = 0;
        lst_ping_data.pnd_err_count = 0;

        return 0;
}

static void
ping_client_fini(sfw_test_instance_t *tsi)
{
        CWARN("Total ping %d, failed ping: %d\n",
              lst_ping_data.pnd_counter, lst_ping_data.pnd_err_count);
}

static int
ping_client_prep_rpc(sfw_test_unit_t *tsu,
                     lnet_process_id_t dest, srpc_client_rpc_t **rpc)
{
        srpc_ping_reqst_t *req;
        struct timeval     tv;
        int                rc;

        rc = sfw_create_test_rpc(tsu, dest, 0, 0, rpc);
        if (rc != 0)
                return rc;

        req = &(*rpc)->crpc_reqstmsg.msg_body.ping_reqst;

        req->pnr_magic = LST_PING_TEST_MAGIC;

        spin_lock(&lst_ping_data.pnd_lock);
        req->pnr_seq = lst_ping_data.pnd_counter ++;
        spin_unlock(&lst_ping_data.pnd_lock);

        cfs_fs_timeval(&tv);
        req->pnr_time_sec  = tv.tv_sec;
        req->pnr_time_usec = tv.tv_usec;

        return rc;
}

static void
ping_client_done_rpc(sfw_test_unit_t *tsu, srpc_client_rpc_t *rpc)
{
        srpc_ping_reqst_t *req;
        srpc_ping_reply_t *rep;
        struct timeval     tv;

        req = &rpc->crpc_reqstmsg.msg_body.ping_reqst;
        rep = &rpc->crpc_replymsg.msg_body.ping_reply;

        if (rpc->crpc_status == 0 &&
            rpc->crpc_replymsg.msg_magic != SRPC_MSG_MAGIC) {
                __swab32s(&rep->pnr_seq);
                __swab32s(&rep->pnr_magic);
                __swab32s(&rep->pnr_status);
        }

        if (rpc->crpc_status != 0) {
                CERROR ("Unable to ping %s (%d): %d\n",
                        libcfs_id2str(rpc->crpc_dest),
                        req->pnr_seq, rpc->crpc_status);
        } else if (rep->pnr_magic != LST_PING_TEST_MAGIC) {
                tsu->tsu_error = -EBADMSG;
                CERROR ("Bad magic %u from %s, %u expected.\n",
                        rep->pnr_magic, libcfs_id2str(rpc->crpc_dest),
                        LST_PING_TEST_MAGIC);
        } else if (rep->pnr_seq != req->pnr_seq) {
                tsu->tsu_error = -EBADMSG;
                CERROR ("Bad seq %u from %s, %u expected.\n",
                        rep->pnr_seq, libcfs_id2str(rpc->crpc_dest),
                        req->pnr_seq);
        }

        if (tsu->tsu_error != 0) {
                spin_lock(&lst_ping_data.pnd_lock);
                lst_ping_data.pnd_err_count++;
                spin_unlock(&lst_ping_data.pnd_lock);
                return;
        }

        cfs_fs_timeval(&tv);
        CDEBUG (D_NET, "%d reply in %u usec\n", rep->pnr_seq,
                (unsigned)((tv.tv_sec - (unsigned)req->pnr_time_sec) * 1000000 +
                           (tv.tv_usec - req->pnr_time_usec)));
        return;
}

static int
ping_server_handle (srpc_server_rpc_t *rpc)
{
        srpc_service_t    *sv  = rpc->srpc_service;
        srpc_msg_t        *reqstmsg = &rpc->srpc_reqstbuf->buf_msg;
        srpc_ping_reqst_t *req = &reqstmsg->msg_body.ping_reqst;
        srpc_ping_reply_t *rep = &rpc->srpc_replymsg.msg_body.ping_reply;

        LASSERT (sv->sv_id == SRPC_SERVICE_PING);

        if (reqstmsg->msg_magic != SRPC_MSG_MAGIC) {
                LASSERT (reqstmsg->msg_magic == __swab32(SRPC_MSG_MAGIC));

                __swab32s(&reqstmsg->msg_type);
                __swab32s(&req->pnr_seq);
                __swab32s(&req->pnr_magic);
                __swab64s(&req->pnr_time_sec);
                __swab64s(&req->pnr_time_usec);
        }
        LASSERT (reqstmsg->msg_type == srpc_service2request(sv->sv_id));

        if (req->pnr_magic != LST_PING_TEST_MAGIC) {
                CERROR ("Unexpect magic %08x from %s\n",
                        req->pnr_magic, libcfs_id2str(rpc->srpc_peer));
                return -EINVAL;
        }

        rep->pnr_seq   = req->pnr_seq;
        rep->pnr_magic = LST_PING_TEST_MAGIC;

        CDEBUG (D_NET, "Get ping %d from %s\n",
                req->pnr_seq, libcfs_id2str(rpc->srpc_peer));
        return 0;
}

sfw_test_client_ops_t ping_test_client = 
{
        .tso_init       = ping_client_init,
        .tso_fini       = ping_client_fini,
        .tso_prep_rpc   = ping_client_prep_rpc,
        .tso_done_rpc   = ping_client_done_rpc,
};

srpc_service_t ping_test_service = 
{
        .sv_name        = "ping test",
        .sv_handler     = ping_server_handle,
        .sv_id          = SRPC_SERVICE_PING,
};
