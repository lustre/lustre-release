/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *
 *   This file is part of Portals
 *   http://sourceforge.net/projects/sandiaportals/
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
 *
 */

#include "router.h"

#define KPR_PROC_ROUTER "sys/portals/router"

int
kpr_proc_read (char *page, char **start, off_t off, int count, int *eof, void *data)
{
	unsigned long long bytes = kpr_fwd_bytes;
	unsigned long      packets = kpr_fwd_packets;
	unsigned long      errors = kpr_fwd_errors;
        unsigned int       qdepth = atomic_read (&kpr_queue_depth);
	int                len;
	
	*eof = 1;
	if (off != 0)
		return (0);
	
	len = sprintf (page, "%Ld %ld %ld %d\n", bytes, packets, errors, qdepth);
	
	*start = page;
	return (len);
}

int
kpr_proc_write (struct file *file, const char *ubuffer, unsigned long count, void *data)
{
	/* Ignore what we've been asked to write, and just zero the stats counters */
	kpr_fwd_bytes = 0;
	kpr_fwd_packets = 0;
	kpr_fwd_errors = 0;

	return (count);
}

void
kpr_proc_init(void)
{
        struct proc_dir_entry *entry = create_proc_entry (KPR_PROC_ROUTER, S_IFREG | S_IRUGO | S_IWUSR, NULL);

        if (entry == NULL) 
	{
                CERROR("couldn't create proc entry %s\n", KPR_PROC_ROUTER);
                return;
        }

        entry->data = NULL;
        entry->read_proc = kpr_proc_read;
	entry->write_proc = kpr_proc_write;
}

void 
kpr_proc_fini(void)
{
        remove_proc_entry(KPR_PROC_ROUTER, 0);
}
