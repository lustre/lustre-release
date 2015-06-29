/*
 * Copyright (C) 2009-2012 Cray, Inc.
 *
 *   Author: Nic Henke <nic@cray.com>
 *   Author: James Shimek <jshimek@cray.com>
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
#ifndef _GNILND_GEMINI_H
#define _GNILND_GEMINI_H

#ifndef _GNILND_HSS_OPS_H
# error "must include gnilnd_hss_ops.h first"
#endif

/* Set HW related values */
#define GNILND_BASE_TIMEOUT        60            /* default sane timeout */
#define GNILND_CHECKSUM_DEFAULT     3            /* all on for Gemini */

#define GNILND_REVERSE_RDMA	    GNILND_REVERSE_NONE
#define GNILND_RDMA_DLVR_OPTION     GNI_DLVMODE_PERFORMANCE

#if !defined(CONFIG_CRAY_COMPUTE)
#define GNILND_SCHED_THREADS        3            /* scheduler threads */
#endif

/* Thread-safe kgni implemented in minor ver 44, code rev 0xb9 */
#define GNILND_KGNI_TS_MINOR_VER 0x44
#define GNILND_TS_ENABLE         0

static inline gni_return_t
kgnilnd_register_smdd_buf(kgn_device_t *dev)
{
	return GNI_RC_SUCCESS;
}

static inline gni_return_t
kgnilnd_deregister_smdd_buf(kgn_device_t *dev)
{
	return GNI_RC_SUCCESS;
}

#endif /* _GNILND_GEMINI_H */
