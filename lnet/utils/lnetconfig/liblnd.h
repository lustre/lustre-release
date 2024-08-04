/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (c) 2015, James Simmons <jsimmons@infradead.org>
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef LIB_LND_CONFIG_API_H
#define LIB_LND_CONFIG_API_H

#include <linux/lnet/socklnd.h>
#include <linux/lnet/lnet-dlc.h>
#include <cyaml.h>

int
lustre_net_show_tunables(struct cYAML *tunables,
			 struct lnet_ioctl_config_lnd_cmn_tunables *cmn);

int
lustre_ni_show_tunables(struct cYAML *lnd_tunables,
			__u32 net_type,
			struct lnet_lnd_tunables *lnd, bool backup);

void
lustre_yaml_extract_lnd_tunables(struct cYAML *tree,
				 __u32 net_type,
				 struct lnet_lnd_tunables *tun);

#endif /* LIB_LND_CONFIG_API_H */
