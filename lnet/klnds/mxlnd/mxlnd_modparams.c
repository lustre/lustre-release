/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 *
 * Copyright (C) 2006 Myricom, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/klnds/mxlnd/mxlnd.c
 *
 * Author: Eric Barton <eric@bartonsoftware.com>
 * Author: Scott Atchley <atchley at myri.com>
 */

#include "mxlnd.h"

static int n_waitd = MXLND_N_SCHED;
CFS_MODULE_PARM(n_waitd, "i", int, 0444,
                "# of completion daemons");

static int max_peers = MXLND_MAX_PEERS;
CFS_MODULE_PARM(max_peers, "i", int, 0444,
                "maximum number of peers that may connect");

static int cksum = MXLND_CKSUM;
CFS_MODULE_PARM(cksum, "i", int, 0644,
                "set non-zero to enable message (not data payload) checksums");

static int ntx = MXLND_NTX;
CFS_MODULE_PARM(ntx, "i", int, 0444,
                "# of total tx message descriptors");

static int credits = MXLND_MSG_QUEUE_DEPTH;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int board = MXLND_MX_BOARD;
CFS_MODULE_PARM(board, "i", int, 0444,
                "index value of the Myrinet board (NIC)");

static int ep_id = MXLND_MX_EP_ID;
CFS_MODULE_PARM(ep_id, "i", int, 0444, "MX endpoint ID");

static int polling = MXLND_POLLING;
CFS_MODULE_PARM(polling, "i", int, 0444,
                "Use 0 to block (wait). A value > 0 will poll that many times before blocking");

static char *hosts = NULL;
CFS_MODULE_PARM(hosts, "s", charp, 0444,
                "IP-to-hostname resolution file");

kmx_tunables_t kmxlnd_tunables = {
        .kmx_n_waitd            = &n_waitd,
        .kmx_max_peers          = &max_peers,
        .kmx_cksum              = &cksum,
        .kmx_ntx                = &ntx,
        .kmx_credits            = &credits,
        .kmx_board              = &board,
        .kmx_ep_id              = &ep_id,
        .kmx_polling            = &polling,
        .kmx_hosts              = &hosts
};
