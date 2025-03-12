// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2024-2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * DebugFS for EFA Lustre Network Driver
 *
 * Author: Timothy Day <timday@amazon.com>
 */

#define DEBUG_SUBSYSTEM S_LND

#include <linux/debugfs.h>
#include <linux/inet.h>

#include <lprocfs_status.h>

#include "kcompat.h"
#include "efalnd.h"

struct dentry *kefalnd_debug_dir;

static int gidmap_seq_show(struct seq_file *s, void *unused)
{
	struct kefa_peer_ni *peer_ni;
	char ip_str[INET_ADDRSTRLEN];
	struct rhashtable_iter iter;
	u16 *gid_raw;

	rcu_read_lock();
	if (kefalnd.shutdown || kefalnd.init_state == EFALND_INIT_NONE) {
		rcu_read_unlock();
		return 0;
	}

	rhashtable_walk_enter(&kefalnd.peer_ni, &iter);
	rhashtable_walk_start(&iter);

	while ((peer_ni = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(peer_ni))
			continue;

		gid_raw = (u16 *)peer_ni->gid.raw;

		snprintf(ip_str, INET_ADDRSTRLEN, "%d.%d.%d.%d",
			 peer_ni->remote_nid_addr >> 24,
			 peer_ni->remote_nid_addr >> 16 & 0xFF,
			 peer_ni->remote_nid_addr >> 8 & 0xFF,
			 peer_ni->remote_nid_addr & 0xFF);
		seq_printf(s, "%-15s %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x %i %x\n",
			   ip_str, be16_to_cpu(gid_raw[0]),
			   be16_to_cpu(gid_raw[1]),
			   be16_to_cpu(gid_raw[2]),
			   be16_to_cpu(gid_raw[3]),
			   be16_to_cpu(gid_raw[4]),
			   be16_to_cpu(gid_raw[5]),
			   be16_to_cpu(gid_raw[6]),
			   be16_to_cpu(gid_raw[7]),
			   peer_ni->cm_qp.qp_num,
			   peer_ni->cm_qp.qkey);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);
	rcu_read_unlock();

	return 0;
}
LDEBUGFS_SEQ_FOPS_RO(gidmap);

void kefalnd_debugfs_init(void)
{
	kefalnd_debug_dir = debugfs_create_dir("kefalnd", NULL);
	if (IS_ERR_OR_NULL(kefalnd_debug_dir))
		return;

	debugfs_create_atomic_t("peerni_count", 0444, kefalnd_debug_dir,
				&kefalnd.peer_ni_count);
	debugfs_create_file("gidmap", 0444, kefalnd_debug_dir, NULL,
			    &gidmap_fops);
}

void kefalnd_debugfs_exit(void)
{
	debugfs_remove_recursive(kefalnd_debug_dir);
}
