// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/ */

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>

static int
lolnd_send(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg)
{
	LASSERT(!lntmsg->msg_routing);
	LASSERT(!lntmsg->msg_target_is_router);

	return lnet_parse(ni, &lntmsg->msg_hdr, &ni->ni_nid, lntmsg, 0);
}

static int
lolnd_recv(struct lnet_ni *ni, void *private, struct lnet_msg *lntmsg,
	   int delayed, unsigned int niov,
	   struct bio_vec *kiov,
	   unsigned int offset, unsigned int mlen, unsigned int rlen)
{
	struct lnet_msg *sendmsg = private;

	if (lntmsg) {			/* not discarding */
		lnet_copy_kiov2kiov(niov, kiov, offset,
				    sendmsg->msg_niov,
				    sendmsg->msg_kiov,
				    sendmsg->msg_offset, mlen);

		lnet_finalize(lntmsg, 0);
	}

	lnet_finalize(sendmsg, 0);
	return 0;
}

static int lolnd_instanced;

static void
lolnd_shutdown(struct lnet_ni *ni)
{
	CDEBUG (D_NET, "shutdown\n");
	LASSERT(lolnd_instanced);

	lolnd_instanced = 0;
}

static int
lolnd_startup(struct lnet_ni *ni)
{
	LASSERT (ni->ni_net->net_lnd == &the_lolnd);
	LASSERT (!lolnd_instanced);
	lolnd_instanced = 1;

	return (0);
}

const struct lnet_lnd the_lolnd = {
	.lnd_type	= LOLND,
	.lnd_startup	= lolnd_startup,
	.lnd_shutdown	= lolnd_shutdown,
	.lnd_send	= lolnd_send,
	.lnd_recv	= lolnd_recv
};
