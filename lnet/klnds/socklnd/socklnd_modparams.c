/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Portals; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "socklnd.h"

static int timeout = SOCKNAL_TIMEOUT;
CFS_MODULE_PARM(timeout, "i", int, 0644,
                "dead socket timeout (seconds)");

static int credits = SOCKNAL_CREDITS;
CFS_MODULE_PARM(credits, "i", int, 0444,
                "# concurrent sends");

static int peer_credits = SOCKNAL_PEERCREDITS;
CFS_MODULE_PARM(peer_credits, "i", int, 0444,
                "# concurrent sends to 1 peer");

static int nconnds = SOCKNAL_NCONND;
CFS_MODULE_PARM(nconnds, "i", int, 0444,
                "# connection daemons");

static int min_reconnectms = SOCKNAL_MIN_RECONNECTMS;
CFS_MODULE_PARM(min_reconnectms, "i", int, 0644,
                "min connection retry interval (mS)");

static int max_reconnectms = SOCKNAL_MAX_RECONNECTMS;
CFS_MODULE_PARM(max_reconnectms, "i", int, 0644,
                "max connection retry interval (mS)");

static int eager_ack = SOCKNAL_EAGER_ACK;
CFS_MODULE_PARM(eager_ack, "i", int, 0644,
                "send tcp ack packets eagerly");

static int typed_conns = SOCKNAL_TYPED_CONNS;
CFS_MODULE_PARM(typed_conns, "i", int, 0644,
                "use different sockets for bulk");

static int min_bulk = SOCKNAL_MIN_BULK;
CFS_MODULE_PARM(min_bulk, "i", int, 0644,
                "smallest 'large' message");

static int buffer_size = SOCKNAL_BUFFER_SIZE;
CFS_MODULE_PARM(buffer_size, "i", int, 0644,
                "socket buffer size");

static int nagle = SOCKNAL_NAGLE;
CFS_MODULE_PARM(nagle, "i", int, 0644,
                "enable NAGLE?");

static int keepalive_idle = SOCKNAL_KEEPALIVE_IDLE;
CFS_MODULE_PARM(keepalive_idle, "i", int, 0644,
                "# idle seconds before probe");

static int keepalive_count = SOCKNAL_KEEPALIVE_COUNT;
CFS_MODULE_PARM(keepalive_count, "i", int, 0644,
                "# missed probes == dead");

static int keepalive_intvl = SOCKNAL_KEEPALIVE_INTVL;
CFS_MODULE_PARM(keepalive_intvl, "i", int, 0644,
                "seconds between probes");

#if CPU_AFFINITY
static int irq_affinity = SOCKNAL_IRQ_AFFINITY;
CFS_MODULE_PARM(irq_affinity, "i", int, 0644,
                "enable IRQ affinity");
#endif

#if SOCKNAL_ZC
static unsigned int zc_min_frag = SOCKNAL_ZC_MIN_FRAG;
CFS_MODULE_PARM(zc_min_frag, "i", int, 0644,
                "minimum fragment to zero copy");
#endif

ksock_tunables_t ksocknal_tunables = {
        .ksnd_timeout         = &timeout,
	.ksnd_credits         = &credits,
	.ksnd_peercredits     = &peer_credits,
	.ksnd_nconnds         = &nconnds,
	.ksnd_min_reconnectms = &min_reconnectms,
	.ksnd_max_reconnectms = &max_reconnectms,
        .ksnd_eager_ack       = &eager_ack,
        .ksnd_typed_conns     = &typed_conns,
        .ksnd_min_bulk        = &min_bulk,
        .ksnd_buffer_size     = &buffer_size,
        .ksnd_nagle           = &nagle,
        .ksnd_keepalive_idle  = &keepalive_idle,
        .ksnd_keepalive_count = &keepalive_count,
        .ksnd_keepalive_intvl = &keepalive_intvl,
#if SOCKNAL_ZC
        .ksnd_zc_min_frag     = &zc_min_frag,
#endif
#if CPU_AFFINITY
        .ksnd_irq_affinity    = &irq_affinity,
#endif
};

