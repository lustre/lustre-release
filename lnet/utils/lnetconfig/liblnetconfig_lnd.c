/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * LGPL HEADER END
 *
 * Copyright (c) 2015, James Simmons
 *
 * Author:
 *   James Simmons <jsimmons@infradead.org>
 */
#include <stdio.h>
#include <string.h>
#include <libcfs/util/ioctl.h>
#include "liblnetconfig.h"
#include "cyaml.h"

static int
lustre_ko2iblnd_show_net(struct cYAML *lndparams,
			 struct lnet_ioctl_config_lnd_tunables *tunables)
{
	struct lnet_ioctl_config_o2iblnd_tunables *lnd_cfg;

	lnd_cfg = &tunables->lt_tun_u.lt_o2ib;

	if (cYAML_create_number(lndparams, "peercredits_hiw",
				lnd_cfg->lnd_peercredits_hiw) == NULL)
		return -1;

	if (cYAML_create_number(lndparams, "map_on_demand",
				lnd_cfg->lnd_map_on_demand) == NULL)
		return -1;

	if (cYAML_create_number(lndparams, "concurrent_sends",
				lnd_cfg->lnd_concurrent_sends) == NULL)
		return -1;

	if (cYAML_create_number(lndparams, "fmr_pool_size",
				lnd_cfg->lnd_fmr_pool_size) == NULL)
		return -1;

	if (cYAML_create_number(lndparams, "fmr_flush_trigger",
				lnd_cfg->lnd_fmr_flush_trigger) == NULL)
		return -1;

	if (cYAML_create_number(lndparams, "fmr_cache",
				lnd_cfg->lnd_fmr_cache) == NULL)
		return -1;
	return 0;
}

int
lustre_interface_show_net(struct cYAML *interfaces, unsigned int index,
			  bool detail, struct lnet_ioctl_config_data *data,
			  struct lnet_ioctl_net_config *net_config)
{
	char ni_index[2]; /* LNET_MAX_INTERFACES is only 16 */

	if (strlen(net_config->ni_interfaces[index]) == 0)
		return 0;

	snprintf(ni_index, sizeof(ni_index), "%d", index);
	if (cYAML_create_string(interfaces, ni_index,
				net_config->ni_interfaces[index]) == NULL)
		return -1;

	if (detail) {
		__u32 net = LNET_NETTYP(LNET_NIDNET(data->cfg_nid));
		struct lnet_ioctl_config_lnd_tunables *lnd_cfg;
		struct cYAML *lndparams;

		if (data->cfg_config_u.cfg_net.net_interface_count == 0 ||
		    net != O2IBLND)
			return 0;

		lndparams = cYAML_create_object(interfaces, "lnd tunables");
		if (lndparams == NULL)
			return -1;

		lnd_cfg = (struct lnet_ioctl_config_lnd_tunables *)net_config->cfg_bulk;
		if (lustre_ko2iblnd_show_net(lndparams, lnd_cfg) < 0)
			return -1;
	}
	return 0;
}

static void
lustre_ko2iblnd_parse_net(struct cYAML *lndparams,
			  struct lnet_ioctl_config_lnd_tunables *lnd_cfg)
{
	struct cYAML *map_on_demand = NULL, *concurrent_sends = NULL;
	struct cYAML *fmr_pool_size = NULL, *fmr_cache = NULL;
	struct cYAML *fmr_flush_trigger = NULL;

	map_on_demand = cYAML_get_object_item(lndparams, "map_on_demand");
	lnd_cfg->lt_tun_u.lt_o2ib.lnd_map_on_demand =
		(map_on_demand) ? map_on_demand->cy_valueint : 0;

	concurrent_sends = cYAML_get_object_item(lndparams, "concurrent_sends");
	lnd_cfg->lt_tun_u.lt_o2ib.lnd_concurrent_sends =
		(concurrent_sends) ? concurrent_sends->cy_valueint : 0;

	fmr_pool_size = cYAML_get_object_item(lndparams, "fmr_pool_size");
	lnd_cfg->lt_tun_u.lt_o2ib.lnd_fmr_pool_size =
		(fmr_pool_size) ? fmr_pool_size->cy_valueint : 0;

	fmr_flush_trigger = cYAML_get_object_item(lndparams,
						  "fmr_flush_trigger");
	lnd_cfg->lt_tun_u.lt_o2ib.lnd_fmr_flush_trigger =
		(fmr_flush_trigger) ? fmr_flush_trigger->cy_valueint : 0;

	fmr_cache = cYAML_get_object_item(lndparams, "fmr_cache");
	lnd_cfg->lt_tun_u.lt_o2ib.lnd_fmr_cache =
		(fmr_cache) ? fmr_cache->cy_valueint : 0;
}

void
lustre_interface_parse(struct cYAML *lndparams, const char *dev_name,
		       struct lnet_ioctl_config_lnd_tunables *lnd_cfg)
{
	if (dev_name != NULL && strstr(dev_name, "ib"))
		lustre_ko2iblnd_parse_net(lndparams, lnd_cfg);
}
