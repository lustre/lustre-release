/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 *
 * LGPL HEADER END
 *
 */
/* Copyright (c) 2021,  UT-Battelle, LLC
 *
 * Author: James Simmons <jsimmons@infradead.org>
 */

#ifndef __UAPI_LNET_NL_H__
#define __UAPI_LNET_NL_H__

#include <linux/types.h>

enum lnet_nl_key_format {
	/* Is it FLOW or BLOCK */
	LNKF_FLOW		= 1,
	/* Is it SEQUENCE or MAPPING */
	LNKF_MAPPING		= 2,
	LNKF_SEQUENCE		= 4,
};

/**
 * enum lnet_nl_scalar_attrs		- scalar LNet netlink attributes used
 *					  to compose messages for sending or
 *					  receiving.
 *
 * @LN_SCALAR_ATTR_UNSPEC:		unspecified attribute to catch errors
 * @LN_SCALAR_ATTR_PAD:			padding for 64-bit attributes, ignore
 *
 * @LN_SCALAR_ATTR_LIST:		List of scalar attributes (NLA_NESTED)
 * @LN_SCALAR_ATTR_LIST_SIZE:		Number of items in scalar list (NLA_U16)
 * @LN_SCALAR_ATTR_INDEX:		True Netlink attr value (NLA_U16)
 * @LN_SCALAR_ATTR_NLA_TYPE:		Data format for value part of the pair
 *					(NLA_U16)
 * @LN_SCALAR_ATTR_VALUE:		String value of key part of the pair.
 *					(NLA_NUL_STRING)
 * @LN_SCALAR_ATTR_INT_VALUE:		Numeric value of key part of the pair.
 *					(NLA_S64)
 * @LN_SCALAR_ATTR_KEY_FORMAT:		LNKF_* format of the key value pair.
 */
enum lnet_nl_scalar_attrs {
	LN_SCALAR_ATTR_UNSPEC = 0,
	LN_SCALAR_ATTR_PAD = LN_SCALAR_ATTR_UNSPEC,

	LN_SCALAR_ATTR_LIST,
	LN_SCALAR_ATTR_LIST_SIZE,
	LN_SCALAR_ATTR_INDEX,
	LN_SCALAR_ATTR_NLA_TYPE,
	LN_SCALAR_ATTR_VALUE,
	LN_SCALAR_ATTR_INT_VALUE,
	LN_SCALAR_ATTR_KEY_FORMAT,

	__LN_SCALAR_ATTR_MAX_PLUS_ONE,
};

#define LN_SCALAR_MAX (__LN_SCALAR_ATTR_MAX_PLUS_ONE - 1)

struct ln_key_props {
	char			*lkp_value;
	__u16			lkp_key_format;
	__u16			lkp_data_type;
};

struct ln_key_list {
	__u16			lkl_maxattr;
	struct ln_key_props	lkl_list[];
};

#endif /* __UAPI_LNET_NL_H__ */
