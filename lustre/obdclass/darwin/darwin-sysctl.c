/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/unistd.h>
#include <mach/mach_types.h>
#include <lustre/lustre_build_version.h>

#define DEBUG_SUBSYSTEM S_CLASS
                                                                                                                                                                     
#include <libcfs/libcfs.h>
#ifndef BUILD_VERSION	
#define BUILD_VERSION		"Unknown"
#endif

struct ctl_table_header *obd_table_header = NULL;

int proc_obd_timeout SYSCTL_HANDLER_ARGS;
extern unsigned int obd_dump_on_timeout;
extern unsigned int obd_timeout;
extern unsigned int ldlm_timeout;
extern atomic_t obd_memory;

int read_build_version SYSCTL_HANDLER_ARGS;

SYSCTL_NODE (,                  OID_AUTO,       lustre,	    CTLFLAG_RW,
	     0,                 "lustre sysctl top");
SYSCTL_PROC(_lustre,		OID_AUTO,       timeout, 
	    CTLTYPE_INT | CTLFLAG_RW ,		&obd_timeout,
	    0,		&proc_obd_timeout,	"I",	"obd_timeout");
SYSCTL_PROC(_lustre,		OID_AUTO,       build_version, 
	    CTLTYPE_STRING | CTLFLAG_RD ,	NULL,
	    0,		&read_build_version,	"A",	"lustre_build_version");
SYSCTL_INT(_lustre,		OID_AUTO,	dump_on_timeout, 
	   CTLTYPE_INT | CTLFLAG_RW,		&obd_dump_on_timeout,
	   0,		"lustre_dump_on_timeout");
SYSCTL_INT(_lustre,		OID_AUTO,	debug_peer_on_timeout, 
	   CTLTYPE_INT | CTLFLAG_RW,		&obd_debug_peer_on_timeout,
	   0,		"lustre_debug_peer_on_timeout");
SYSCTL_INT(_lustre,		OID_AUTO,	memused, 
	   CTLTYPE_INT | CTLFLAG_RW,		(int *)&obd_memory.counter,
	   0,		"lustre_memory_used");
SYSCTL_INT(_lustre,		OID_AUTO,	ldlm_timeout, 
	   CTLTYPE_INT | CTLFLAG_RW,		&ldlm_timeout,
	   0,		"ldlm_timeout");

static struct ctl_table      parent_table[] = {
	&sysctl__lustre,
	&sysctl__lustre_timeout,
	&sysctl__lustre_dump_on_timeout,
        &sysctl__lustre_debug_peer_on_timeout,
	&sysctl__lustre_upcall,
	&sysctl__lustre_memused,
	&sysctl__lustre_filter_sync_on_commit,
	&sysctl__lustre_ldlm_timeout,
};

int proc_obd_timeout SYSCTL_HANDLER_ARGS
{ 
	int error = 0;

	error = sysctl_handle_long(oidp, oidp->oid_arg1, oidp->oid_arg2, req); 
	if (!error && req->newptr != USER_ADDR_NULL) {
		if (ldlm_timeout >= obd_timeout)
			ldlm_timeout = max(obd_timeout / 3, 1U);
	} else  if (req->newptr != USER_ADDR_NULL) { 
		printf ("sysctl fail obd_timeout: %d.\n", error);
	} else {
		/* Read request */ 
		error = SYSCTL_OUT(req, &obd_timeout, sizeof obd_timeout);
	}
	return error;
}

int read_build_version SYSCTL_HANDLER_ARGS
{
	int error = 0;

	error = sysctl_handle_long(oidp, oidp->oid_arg1, oidp->oid_arg2, req); 
	if ( req->newptr != USER_ADDR_NULL) {
		printf("sysctl read_build_version is read-only!\n");
	} else {
		error = SYSCTL_OUT(req, BUILD_VERSION, strlen(BUILD_VERSION));
	}
	return error;
}

void obd_sysctl_init (void)
{
#if 1 
	if ( !obd_table_header ) 
		obd_table_header = register_sysctl_table(parent_table);
#endif
}
                                                                                                                                                                     
void obd_sysctl_clean (void)
{
#if 1 
	if ( obd_table_header ) 
		unregister_sysctl_table(obd_table_header);
	obd_table_header = NULL;
#endif
}
