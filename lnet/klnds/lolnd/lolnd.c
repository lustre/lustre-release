/*
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 * Copyright (C) 2002, Lawrence Livermore National Labs (LLNL)
 * W. Marcus Miller - Based on ksocknal
 *
 * This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "lonal.h"

nal_t			klonal_api;
klonal_data_t		klonal_data;
ptl_handle_ni_t        klonal_ni;


int
klonal_cmd (struct portals_cfg *pcfg, void *private)
{
	LASSERT (pcfg != NULL);
	
	switch (pcfg->pcfg_command) {
	case NAL_CMD_REGISTER_MYNID:
		CDEBUG (D_IOCTL, "setting NID to "LPX64" (was "LPX64")\n",
			pcfg->pcfg_nid, klonal_lib.libnal_ni.ni_pid.nid);
		klonal_lib.libnal_ni.ni_pid.nid = pcfg->pcfg_nid;
		return (0);
		
	default:
		return (-EINVAL);
	}
}

static void
klonal_shutdown(nal_t *nal)
{
	unsigned long flags;

	/* NB The first ref was this module! */
	if (nal->nal_refct != 0)
		return;

	CDEBUG (D_NET, "shutdown\n");
	LASSERT (nal == &klonal_api);

	switch (klonal_data.klo_init)
	{
	default:
		LASSERT (0);

	case KLO_INIT_ALL:
                libcfs_nal_cmd_unregister(LONAL);
		/* fall through */

	case KLO_INIT_LIB:
		lib_fini (&klonal_lib);
		break;

	case KLO_INIT_NOTHING:
		return;
	}

	memset(&klonal_data, 0, sizeof (klonal_data));

	CDEBUG (D_MALLOC, "done kmem %d\n", atomic_read(&portal_kmemory));

	printk (KERN_INFO "Lustre: LO NAL unloaded (final mem %d)\n",
                atomic_read(&portal_kmemory));
	PORTAL_MODULE_UNUSE;
}

static int
klonal_startup (nal_t *nal, ptl_pid_t requested_pid,
		ptl_ni_limits_t *requested_limits, 
		ptl_ni_limits_t *actual_limits)
{
	int               rc;
	int               i;
	ptl_process_id_t  my_process_id;
	int               pkmem = atomic_read(&portal_kmemory);

	LASSERT (nal == &klonal_api);

	if (nal->nal_refct != 0) {
		if (actual_limits != NULL)
			*actual_limits = klonal_lib.libnal_ni.ni_actual_limits;
		return (PTL_OK);
	}

	LASSERT (klonal_data.klo_init == KLO_INIT_NOTHING);

	CDEBUG (D_MALLOC, "start kmem %d\n", atomic_read(&portal_kmemory));

	/* ensure all pointers NULL etc */
	memset (&klonal_data, 0, sizeof (klonal_data));

	my_process_id.nid = 0;
	my_process_id.pid = requested_pid;

	rc = lib_init(&klonal_lib, nal, my_process_id,
		      requested_limits, actual_limits);
        if (rc != PTL_OK) {
		CERROR ("lib_init failed %d\n", rc);
		klonal_shutdown (nal);
		return (rc);
	}

	klonal_data.klo_init = KLO_INIT_LIB;

	rc = libcfs_nal_cmd_register (LONAL, &klonal_cmd, NULL);
	if (rc != 0) {
		CERROR ("Can't initialise command interface (rc = %d)\n", rc);
		klonal_shutdown (nal);
		return (PTL_FAIL);
	}

	klonal_data.klo_init = KLO_INIT_ALL;

	printk(KERN_INFO "Lustre: LO NAL (initial mem %d)\n", pkmem);
	PORTAL_MODULE_USE;

	return (PTL_OK);
}

void __exit
klonal_finalise (void)
{
	PtlNIFini(klonal_ni);

	ptl_unregister_nal(LONAL);
}

static int __init
klonal_initialise (void)
{
	int   rc;

	klonal_api.nal_ni_init = klonal_startup;
	klonal_api.nal_ni_fini = klonal_shutdown;

	rc = ptl_register_nal(LONAL, &klonal_api);
	if (rc != PTL_OK) {
		CERROR("Can't register LONAL: %d\n", rc);
		return (-ENOMEM);		/* or something... */
	}

	return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Loopback NAL v0.01");
MODULE_LICENSE("GPL");

module_init (klonal_initialise);
module_exit (klonal_finalise);
