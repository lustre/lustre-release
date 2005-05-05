/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/unistd.h>
#include <mach/mach_types.h>

#define DEBUG_SUBSYSTEM S_PORTALS
#include <libcfs/libcfs.h>

static cfs_sysctl_table_header_t *portals_table_header = NULL;
extern unsigned int portal_debug;
extern char debug_file_path[1024];
extern unsigned int portal_subsystem_debug;
extern unsigned int portal_printk;
extern atomic_t portal_kmemory;

extern long max_debug_mb;
extern int cfs_trace_daemon SYSCTL_HANDLER_ARGS;
extern int cfs_debug_mb SYSCTL_HANDLER_ARGS;
/*
 * sysctl table for portals
 */
SYSCTL_NODE (,		        OID_AUTO,	portals,	CTLFLAG_RW,
	     0,			"portals sysctl top");

SYSCTL_INT(_portals,		        OID_AUTO,	debug,	
	     CTLTYPE_INT | CTLFLAG_RW ,			&portal_debug,	
	     0,		"debug");
SYSCTL_INT(_portals,		        OID_AUTO,	subsystem_debug,	
	     CTLTYPE_INT | CTLFLAG_RW,			&portal_subsystem_debug,	
	     0,		"subsystem debug");
SYSCTL_INT(_portals,		        OID_AUTO,	printk,	
	     CTLTYPE_INT | CTLFLAG_RW,			&portal_printk,	
	     0,		"printk");
SYSCTL_STRING(_portals,		        OID_AUTO,	debug_path,	
	     CTLTYPE_STRING | CTLFLAG_RW,		debug_file_path,	
	     1024,	"debug path");
SYSCTL_INT(_portals,		        OID_AUTO,	memused,	
	     CTLTYPE_INT | CTLFLAG_RW,			(int *)&portal_kmemory.counter,	
	     0,		"memused");
SYSCTL_PROC(_portals,		        OID_AUTO,	trace_daemon,
	     CTLTYPE_STRING | CTLFLAG_RW,		0,
	     0,		&cfs_trace_daemon,		"A",	"trace daemon");
SYSCTL_PROC(_portals,		        OID_AUTO,	debug_mb,
	     CTLTYPE_INT | CTLFLAG_RW,		        &max_debug_mb,
	     0,		&cfs_debug_mb,		        "L",	"max debug size");


static cfs_sysctl_table_t	top_table[] = {
	&sysctl__portals,
	&sysctl__portals_debug,
	&sysctl__portals_subsystem_debug,
	&sysctl__portals_printk,
	&sysctl__portals_debug_path,
	&sysctl__portals_memused,
	&sysctl__portals_trace_daemon,
	&sysctl__portals_debug_mb,
	NULL
};

/* no proc in osx */
cfs_proc_dir_entry_t *
cfs_create_proc_entry(char *name, int mod, cfs_proc_dir_entry_t *parent)
{
	cfs_proc_dir_entry_t *entry;
	MALLOC(entry, cfs_proc_dir_entry_t *, sizeof(cfs_proc_dir_entry_t), M_TEMP, M_WAITOK|M_ZERO);

	return  entry;
}

void
cfs_free_proc_entry(cfs_proc_dir_entry_t *de){
	FREE(de, M_TEMP);
	return;
};

void
cfs_remove_proc_entry(char *name, cfs_proc_dir_entry_t *entry)
{
	cfs_free_proc_entry(entry);
	return;
}

int
insert_proc(void)
{
#if 1
        if (!portals_table_header) 
                portals_table_header = register_cfs_sysctl_table(top_table, 0);
#endif
	return 0;
}

void
remove_proc(void)
{
#if 1
        if (portals_table_header != NULL) 
                unregister_cfs_sysctl_table(portals_table_header); 
        portals_table_header = NULL;
#endif
	return;
}


