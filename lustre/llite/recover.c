/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 * This code is issued under the GNU General Public License.
 * See the file COPYING in this distribution
 *
 * Copryright (C) 1996 Peter J. Braam <braam@stelias.com>
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 * Copryright (C) 2001 Mountain View Data, Inc.
 * Copryright (C) 2002 Cluster File Systems, Inc.
 *
 */

#include <linux/config.h>
#include <linux/module.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <linux/lustre_lite.h>
#include <linux/lustre_ha.h>

void ll_recover(struct ptlrpc_client *cli)
{
        struct ptlrpc_request *req;
        struct list_head *tmp, *pos;
        ENTRY;

        spin_lock(&cli->cli_lock);
        /* first shot at this: resend the request */ 
        list_for_each_safe(tmp, pos, &cli->cli_sent_head) { 
                req = list_entry(tmp, struct ptlrpc_request, rq_list);
                CDEBUG(D_INODE, "replaying request %p\n", req); 
                list_del(&req->rq_list);
                ptlrpc_resend_req(req); 
        }

        recovd_cli_fixed(cli);
        spin_unlock(&cli->cli_lock);

        EXIT;
}
