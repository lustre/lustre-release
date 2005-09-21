/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *   Author: Eric Barton <ebarton@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "ptllnd.h"

int pltlnd_send(struct lnet_ni *ni, void *private, lnet_msg_t *msg)
{
	return -EIO;
}

int pltlnd_recv(struct lnet_ni *ni, void *private, lnet_msg_t *msg,
		int delayed, unsigned int niov, 
		struct iovec *iov, lnet_kiov_t *kiov,
		unsigned int offset, unsigned int mlen, unsigned int rlen)
{
	return -EIO;
}

int ptllnd_eager_recv(struct lnet_ni *ni, void *private, lnet_msg_t *msg,
		      void **new_privatep)
{
	return -EIO;
}
