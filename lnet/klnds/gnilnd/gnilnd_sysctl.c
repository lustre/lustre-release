/*
 * Copyright (C) 2012 Cray, Inc.
 *
 * Copyright (c) 2014, Intel Corporation.
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
 */

/* this code liberated and modified from Lustre */

#define DEBUG_SUBSYSTEM S_LND

#include <libcfs/linux/linux-misc.h>

#include "gnilnd.h"

#define GNILND_PEERSTATE_STRLEN 16
typedef struct kgn_sysctl_data {
	int                     ksd_pause_trigger;
	int                     ksd_quiesce_secs;
	int                     ksd_rdmaq_override;
	char                    ksd_peer_state[GNILND_PEERSTATE_STRLEN];
} kgn_sysctl_data_t;

static kgn_sysctl_data_t        kgnilnd_sysctl;

#if defined(CONFIG_SYSCTL)

static struct ctl_table_header *kgnilnd_table_header = NULL;

static int
proc_toggle_thread_pause(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int  old_val = kgnilnd_sysctl.ksd_pause_trigger;
	int  rc = 0;
	ENTRY;

	rc = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!write) {
		/* read */
		RETURN(rc);
	}

	if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
		rc = -EINVAL;
		RETURN(rc);
	}

	if (old_val != kgnilnd_sysctl.ksd_pause_trigger) {
		mutex_lock(&kgnilnd_data.kgn_quiesce_mutex);
		CDEBUG(D_NET, "setting quiesce_trigger %d\n", old_val);
		kgnilnd_data.kgn_quiesce_trigger = kgnilnd_sysctl.ksd_pause_trigger;
		kgnilnd_quiesce_wait("admin sysctl");
		mutex_unlock(&kgnilnd_data.kgn_quiesce_mutex);
	}

	RETURN(rc);
}

static int
proc_hw_quiesce(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int              rc = 0;
	kgn_device_t    *dev;
	ENTRY;

	rc = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!write) {
		/* read */
		RETURN(rc);
	}

	if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
		rc = -EINVAL;
		RETURN(rc);
	}


	/* only device 0 gets the handle, see kgnilnd_dev_init */
	dev = &kgnilnd_data.kgn_devices[0];

	LASSERTF(dev != NULL, "dev 0 is NULL\n");

	kgnilnd_quiesce_end_callback(dev->gnd_handle,
				     kgnilnd_sysctl.ksd_quiesce_secs * MSEC_PER_SEC);

	RETURN(rc);
}

static int
proc_trigger_stack_reset(struct ctl_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int              rc = 0;
	int              i = 1;
	kgn_device_t    *dev;
	ENTRY;

	if (!write) {
		/* read */
		rc = proc_dointvec(table, write, buffer, lenp, ppos);
		RETURN(rc);
	}

	/* only device 0 gets the handle, see kgnilnd_dev_init */
	dev = &kgnilnd_data.kgn_devices[0];

	LASSERTF(dev != NULL, "dev 0 is NULL\n");

	kgnilnd_critical_error(dev->gnd_err_handle);

	/* Wait for the reset to complete.  This prevents any races in testing
	 * where we'd immediately try to send traffic again */
	while (kgnilnd_data.kgn_needs_reset != 0) {
		i++;
		LCONSOLE((((i) & (-i)) == i) ? D_WARNING : D_NET,
				"Waiting for stack reset request to clear\n");
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(cfs_time_seconds(1 * i));
	}

	RETURN(rc);
}

static int
proc_toggle_rdmaq_override(struct ctl_table *table, int write,
			   void __user *buffer, size_t *lenp, loff_t *ppos)
{
	int  old_val = kgnilnd_sysctl.ksd_rdmaq_override;
	int  rc = 0;
	ENTRY;

	rc = proc_dointvec(table, write, buffer, lenp, ppos);
	if (!write) {
		/* read */
		RETURN(rc);
	}

	if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
		rc = -EINVAL;
		RETURN(rc);
	}

	if (old_val != kgnilnd_sysctl.ksd_rdmaq_override) {
		long    new_mb = kgnilnd_sysctl.ksd_rdmaq_override * (long)(1024*1024);
		LCONSOLE_INFO("changing RDMAQ override to %d mbytes/sec\n",
			      kgnilnd_sysctl.ksd_rdmaq_override);
		/* override proc is mbytes, but we calc in bytes */
		kgnilnd_data.kgn_rdmaq_override = new_mb;
		smp_wmb();
	}

	RETURN(rc);
}

/* /proc/sys entry point for injecting up/down nid event
 * <up|down> <nid>
 */
static int
proc_peer_state(struct ctl_table *table, int write, void __user *buffer,
		size_t *lenp, loff_t *ppos)
{
	int             rc;
	int             nid;
	int             node_down;
	char            command[10];
	ENTRY;

	rc = proc_dostring(table, write, buffer, lenp, ppos);

	if (!write) {
		/* read */
		RETURN(rc);
	}

	if (kgnilnd_data.kgn_init != GNILND_INIT_ALL) {
		rc = -EINVAL;
		RETURN(rc);
	}

	/* convert to nid, up/down values */
	rc = sscanf(kgnilnd_sysctl.ksd_peer_state, "%s %d", command, &nid);
	CDEBUG(D_INFO, "command %s, nid %d\n", command, nid);

	if (rc != 2) {
		CDEBUG(D_ERROR, "invalid parameter\n");
		RETURN(rc);
	} else {
		switch (command[0]) {
		case 'd': /* down */
			node_down = 1;
			CDEBUG(D_INFO, "take node %d down\n", nid);
			break;
		case 'u': /* up */
			node_down = 0;
			CDEBUG(D_INFO, "bring node %d up\n", nid);
			break;
		default:
			CDEBUG(D_ERROR, "invalid command %s\n", command);
			RETURN(-EINVAL);
		}
	}

	CDEBUG(D_INFO, "proc_peer_state: reporting node_down %d, nid %d\n",
		      node_down, nid);
	rc = kgnilnd_report_node_state(nid, node_down);

	if (rc) {
		rc = -EINVAL;
	}

	RETURN(rc);
}

static struct ctl_table kgnilnd_table[] = {
	/*
	 * NB No .strategy entries have been provided since sysctl(8) prefers
	 * to go via /proc for portability.
	 */
	{
		INIT_CTL_NAME
		.procname = "version",
		.data     = LUSTRE_VERSION_STRING,
		.maxlen   = sizeof(LUSTRE_VERSION_STRING),
		.mode     = 0444,
		.proc_handler = &proc_dostring
	},
	{
		INIT_CTL_NAME
		.procname = "thread_pause",
		.data     = &kgnilnd_sysctl.ksd_pause_trigger,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_toggle_thread_pause,
	},
	{
		INIT_CTL_NAME
		.procname = "hw_quiesce",
		.data     = &kgnilnd_sysctl.ksd_quiesce_secs,
		.maxlen   = sizeof(__u32),
		.mode     = 0644,
		.proc_handler = &proc_hw_quiesce,
	},
	{
		INIT_CTL_NAME
		.procname = "stack_reset",
		.data     = NULL,
		.maxlen   = sizeof(int),
		.mode     = 0600,
		.proc_handler = &proc_trigger_stack_reset,
	},
	{
		INIT_CTL_NAME
		.procname = "rdmaq_override",
		.data     = &kgnilnd_sysctl.ksd_rdmaq_override,
		.maxlen   = sizeof(int),
		.mode     = 0644,
		.proc_handler = &proc_toggle_rdmaq_override,
	},
	{
		INIT_CTL_NAME
		.procname = "peer_state",
		.data     = kgnilnd_sysctl.ksd_peer_state,
		.maxlen   = GNILND_PEERSTATE_STRLEN,
		.mode     = 0644,
		.proc_handler = &proc_peer_state,
	},
	{ 0 }
};

static struct ctl_table kgnilnd_top_table[2] = {
	{
		INIT_CTL_NAME
		.procname = "kgnilnd",
		.data     = NULL,
		.maxlen   = 0,
		.mode     = 0555,
		.child    = kgnilnd_table
	},
	{ 0 }
};

void kgnilnd_insert_sysctl(void)
{
	if (kgnilnd_table_header == NULL)
		kgnilnd_table_header = register_sysctl_table(kgnilnd_top_table);
}

void kgnilnd_remove_sysctl(void)
{
	if (kgnilnd_table_header != NULL)
		unregister_sysctl_table(kgnilnd_table_header);

	kgnilnd_table_header = NULL;
}

#else
void kgnilnd_insert_sysctl(void) {}
void kgnilnd_remove_sysctl(void) {}
#endif
