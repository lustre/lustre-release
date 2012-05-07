/*
 *  Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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

#ifndef __DARWIN_OBD_CKSUM
#define __DARWIN_OBD_CKSUM

#ifndef __OBD_CKSUM
#error Do not #include this file directly. #include <obd_chsum.h> instead
#endif

#include <libcfs/libcfs.h>

#if !defined(__KERNEL__) && defined(HAVE_ADLER)
#  include <zlib.h>
#endif /* !__KERNEL__ */

#endif
