/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
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
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif

# define DEBUG_SUBSYSTEM S_PORTALS

#include <libcfs/kp30.h>
#include <libcfs/libcfs.h>

/* CAVEAT EMPTOR! Racey temporary buffer allocation!
 * Choose the number of nidstrings to support the MAXIMUM expected number of
 * concurrent users.  If there are more, the returned string will be volatile.
 * NB this number must allow for a process to be descheduled for a timeslice
 * between getting its string and using it.
 */

static char        libcfs_nidstrings[128][PTL_NALFMT_SIZE];
static int         libcfs_nidstring_idx;
static spinlock_t  libcfs_nidstring_lock;

void
libcfs_init_nidstrings (void)
{
        spin_lock_init(&libcfs_nidstring_lock);
}

static char *
libcfs_next_nidstring (void)
{
	unsigned long  flags;
	char          *str;
	
	spin_lock_irqsave(&libcfs_nidstring_lock, flags);
	
	str = libcfs_nidstrings[libcfs_nidstring_idx++];
	if (libcfs_nidstring_idx ==
	    sizeof(libcfs_nidstrings)/sizeof(libcfs_nidstrings[0]))
		libcfs_nidstring_idx = 0;

	spin_unlock_irqrestore(&libcfs_nidstring_lock, flags);

	return str;
}

char *libcfs_nid2str(ptl_nid_t nid)
{
	__u32   hi  = (__u32)(nid>>32);
	__u32   lo  = (__u32)nid;
	char   *str = libcfs_next_nidstring();

        if (nid == PTL_NID_ANY) {
                snprintf(str, PTL_NALFMT_SIZE, "%s", "PTL_NID_ANY");
                return str;
        }

#if !CRAY_PORTALS
	if ((lo & 0xffff) != 0) {
		/* probable IP address */
		if (hi != 0)
                        snprintf(str, PTL_NALFMT_SIZE, "%u:%u.%u.%u.%u",
                                 hi, HIPQUAD(lo));
                else
                        snprintf(str, PTL_NALFMT_SIZE, "%u.%u.%u.%u",
                                 HIPQUAD(lo));
	} else if (hi != 0)
		snprintf(str, PTL_NALFMT_SIZE, "%u:%u", hi, lo);
	else
		snprintf(str, PTL_NALFMT_SIZE, "%u", lo);
#else
	snprintf(str, PTL_NALFMT_SIZE, "%llx", (long long)nid);
#endif
        return str;
}

char *libcfs_id2str(ptl_process_id_t id)
{
        char *str = libcfs_nid2str(id.nid);
	int   len = strlen(str);

        snprintf(str + len, PTL_NALFMT_SIZE - len, "-%u", id.pid);
        return str;
}

EXPORT_SYMBOL(libcfs_nid2str);
EXPORT_SYMBOL(libcfs_id2str);
