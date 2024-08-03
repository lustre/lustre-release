/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef LUSTRE_INTENT_H
#define LUSTRE_INTENT_H

/* intent IT_XXX are defined in lustre/include/obd.h */

struct lookup_intent {
	int			 it_op;
	int			 it_create_mode;
	enum mds_open_flags	 it_open_flags;
	int			 it_disposition;
	int			 it_status;
	__u64			 it_lock_handle;
	__u64			 it_lock_bits;
	int			 it_lock_mode;
	int			 it_remote_lock_mode;
	__u64			 it_remote_lock_handle;
	struct ptlrpc_request	*it_request;
	unsigned int		 it_lock_set:1;
};

static inline int it_disposition(const struct lookup_intent *it, int flag)
{
	return it->it_disposition & flag;
}

static inline void it_set_disposition(struct lookup_intent *it, int flag)
{
	it->it_disposition |= flag;
}

static inline void it_clear_disposition(struct lookup_intent *it, int flag)
{
	it->it_disposition &= ~flag;
}

#endif
