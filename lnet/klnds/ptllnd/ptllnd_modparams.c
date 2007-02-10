/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc. All rights reserved.
 *   Author: PJ Kirner <pjkirner@clusterfs.com>
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   This file is confidential source code owned by Cluster File Systems.
 *   No viewing, modification, compilation, redistribution, or any other
 *   form of use is permitted except through a signed license agreement.
 *
 *   If you have not signed such an agreement, then you have no rights to
 *   this file.  Please destroy it immediately and contact CFS.
 *
 */


#include "ptllnd.h"

static int ntx = 256;
CFS_MODULE_PARM(ntx, "i", int, 0444,
		"# of TX descriptors");

static int max_nodes = 1152;
CFS_MODULE_PARM(max_nodes, "i", int, 0444,
		"maximum number of peer nodes");

static int max_procs_per_node = 2;
CFS_MODULE_PARM(max_procs_per_node, "i", int, 0444,
		"maximum number of processes per peer node to cache");

static int checksum = 0;
CFS_MODULE_PARM(checksum, "i", int, 0644,
		"set non-zero to enable message (not RDMA) checksums");

static int timeout = 50;
CFS_MODULE_PARM(timeout, "i", int, 0644,
		"timeout (seconds)");

static int portal = PTLLND_PORTAL;              /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(portal, "i", int, 0444,
		"portal id");

static int pid = PTLLND_PID;                    /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(pid, "i", int, 0444,
		"portals pid");

static int rxb_npages = 1;
CFS_MODULE_PARM(rxb_npages, "i", int, 0444,
		"# of pages per rx buffer");

static int rxb_nspare = 8;
CFS_MODULE_PARM(rxb_nspare, "i", int, 0444,
                "# of spare rx buffers");

static int credits = 128;
CFS_MODULE_PARM(credits, "i", int, 0444,
		"concurrent sends");

static int peercredits = PTLLND_PEERCREDITS;    /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(peercredits, "i", int, 0444,
		"concurrent sends to 1 peer");

static int max_msg_size = PTLLND_MAX_MSG_SIZE;  /* <lnet/ptllnd_wire.h> */
CFS_MODULE_PARM(max_msg_size, "i", int, 0444,
		"max size of immediate message");

static int peer_hash_table_size = 101;
CFS_MODULE_PARM(peer_hash_table_size, "i", int, 0444,
		"# of slots in the peer hash table");

static int reschedule_loops = 100;
CFS_MODULE_PARM(reschedule_loops, "i", int, 0644,
                "# of loops before scheduler does cond_resched()");

#ifdef CRAY_XT3
static int ptltrace_on_timeout = 0;
CFS_MODULE_PARM(ptltrace_on_timeout, "i", int, 0644,
		"dump ptltrace on timeout");

static char *ptltrace_basename = "/tmp/lnet-ptltrace";
CFS_MODULE_PARM(ptltrace_basename, "s", charp, 0644,
                "ptltrace dump file basename");
#endif
#ifdef PJK_DEBUGGING
static int simulation_bitmap = 0;
CFS_MODULE_PARM(simulation_bitmap, "i", int, 0444,
		"simulation bitmap");
#endif


kptl_tunables_t kptllnd_tunables = {
        .kptl_ntx                    = &ntx,
        .kptl_max_nodes              = &max_nodes,
        .kptl_max_procs_per_node     = &max_procs_per_node,
        .kptl_checksum               = &checksum,
        .kptl_portal                 = &portal,
        .kptl_pid                    = &pid,
        .kptl_timeout                = &timeout,
        .kptl_rxb_npages             = &rxb_npages,
        .kptl_rxb_nspare             = &rxb_nspare,
        .kptl_credits                = &credits,
        .kptl_peercredits            = &peercredits,
        .kptl_max_msg_size           = &max_msg_size,
        .kptl_peer_hash_table_size   = &peer_hash_table_size,
        .kptl_reschedule_loops       = &reschedule_loops,
#ifdef CRAY_XT3
        .kptl_ptltrace_on_timeout    = &ptltrace_on_timeout,
        .kptl_ptltrace_basename      = &ptltrace_basename,
#endif
#ifdef PJK_DEBUGGING
        .kptl_simulation_bitmap      = &simulation_bitmap,
#endif
};


#if CONFIG_SYSCTL && !CFS_SYSFS_MODULE_PARM
#ifdef CRAY_XT3
static char ptltrace_basename_space[1024];

static void
kptllnd_init_strtunable(char **str_param, char *space, int size)
{
        strncpy(space, *str_param, size);
        space[size - 1] = 0;
        *str_param = space;
}
#endif

static ctl_table kptllnd_ctl_table[] = {
	{1, "ntx", &ntx,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{2, "max_nodes", &max_nodes,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{3, "max_procs_per_node", &max_procs_per_node,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{4, "checksum", &checksum,
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{5, "timeout", &timeout,
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{6, "portal", &portal,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{7, "pid", &pid,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{8, "rxb_npages", &rxb_npages,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{9, "credits", &credits,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{10, "peercredits", &peercredits,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{11, "max_msg_size", &max_msg_size,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{12, "peer_hash_table_size", &peer_hash_table_size,
	 sizeof(int), 0444, NULL, &proc_dointvec},
	{13, "reschedule_loops", &reschedule_loops,
	 sizeof(int), 0444, NULL, &proc_dointvec},
#ifdef CRAY_XT3
	{14, "ptltrace_on_timeout", &ptltrace_on_timeout,
	 sizeof(int), 0644, NULL, &proc_dointvec},
	{15, "ptltrace_basename", ptltrace_basename_space,
	 sizeof(ptltrace_basename_space), 0644, NULL, &proc_dostring,
	 &sysctl_string},
#endif
#ifdef PJK_DEBUGGING
	{16, "simulation_bitmap", &simulation_bitmap,
	 sizeof(int), 0444, NULL, &proc_dointvec},
#endif

	{0}
};

static ctl_table kptllnd_top_ctl_table[] = {
	{203, "ptllnd", NULL, 0, 0555, kptllnd_ctl_table},
	{0}
};

int
kptllnd_tunables_init ()
{
#ifdef CRAY_XT3
        kptllnd_init_strtunable(&ptltrace_basename,
                                ptltrace_basename_space,
                                sizeof(ptltrace_basename_space));
#endif
	kptllnd_tunables.kptl_sysctl =
		register_sysctl_table(kptllnd_top_ctl_table, 0);

	if (kptllnd_tunables.kptl_sysctl == NULL)
		CWARN("Can't setup /proc tunables\n");

	return 0;
}

void
kptllnd_tunables_fini ()
{
	if (kptllnd_tunables.kptl_sysctl != NULL)
		unregister_sysctl_table(kptllnd_tunables.kptl_sysctl);
}

#else

int
kptllnd_tunables_init ()
{
	return 0;
}

void
kptllnd_tunables_fini ()
{
}

#endif

