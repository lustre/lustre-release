/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (c) 2012, 2013, Intel Corporation.
 */

#include <wireshark/config.h>

#define WIRESHARK_VERSION			\
	((VERSION_MAJOR * 1000 * 1000) +	\
	 (VERSION_MINOR * 1000) +		\
	 (VERSION_MICRO))

/* Wireshark 1.12 brings API change */
#if WIRESHARK_VERSION < 1012000
# define WIRESHARK_COMPAT
#endif
