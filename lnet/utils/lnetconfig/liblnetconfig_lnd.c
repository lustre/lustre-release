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
 * Copyright (c) 2016, Intel Corporation.
 *
 * Author:
 *   James Simmons <jsimmons@infradead.org>
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libcfs/util/ioctl.h>
#include "liblnetconfig.h"
#include "cyaml.h"

static int
lustre_o2iblnd_show_tun(struct cYAML *lndparams,
			struct lnet_ioctl_config_o2iblnd_tunables *lnd_cfg)
{
	if (cYAML_create_number(lndparams, "peercredits_hiw",
				lnd_cfg->lnd_peercredits_hiw) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "map_on_demand",
				lnd_cfg->lnd_map_on_demand) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "concurrent_sends",
				lnd_cfg->lnd_concurrent_sends) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "fmr_pool_size",
				lnd_cfg->lnd_fmr_pool_size) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "fmr_flush_trigger",
				lnd_cfg->lnd_fmr_flush_trigger) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "fmr_cache",
				lnd_cfg->lnd_fmr_cache) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "ntx",
				lnd_cfg->lnd_ntx) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "conns_per_peer",
				lnd_cfg->lnd_conns_per_peer) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	return LUSTRE_CFG_RC_NO_ERR;
}

int
lustre_net_show_tunables(struct cYAML *tunables,
			 struct lnet_ioctl_config_lnd_cmn_tunables *cmn)
{


	if (cYAML_create_number(tunables, "peer_timeout",
				cmn->lct_peer_timeout)
					== NULL)
		goto out;

	if (cYAML_create_number(tunables, "peer_credits",
				cmn->lct_peer_tx_credits)
					== NULL)
		goto out;

	if (cYAML_create_number(tunables,
				"peer_buffer_credits",
				cmn->lct_peer_rtr_credits)
					== NULL)
		goto out;

	if (cYAML_create_number(tunables, "credits",
				cmn->lct_max_tx_credits)
					== NULL)
		goto out;

	return LUSTRE_CFG_RC_NO_ERR;

out:
	return LUSTRE_CFG_RC_OUT_OF_MEM;
}

int
lustre_ni_show_tunables(struct cYAML *lnd_tunables,
			__u32 net_type,
			struct lnet_lnd_tunables *lnd)
{
	int rc = LUSTRE_CFG_RC_NO_ERR;

	if (net_type == O2IBLND)
		rc = lustre_o2iblnd_show_tun(lnd_tunables,
					     &lnd->lnd_tun_u.lnd_o2ib);

	return rc;
}

static void
yaml_extract_o2ib_tun(struct cYAML *tree,
		      struct lnet_ioctl_config_o2iblnd_tunables *lnd_cfg)
{
	struct cYAML *map_on_demand = NULL, *concurrent_sends = NULL;
	struct cYAML *fmr_pool_size = NULL, *fmr_cache = NULL;
	struct cYAML *fmr_flush_trigger = NULL, *lndparams = NULL;
	struct cYAML *conns_per_peer = NULL, *ntx = NULL;

	lndparams = cYAML_get_object_item(tree, "lnd tunables");
	if (!lndparams)
		return;

	map_on_demand = cYAML_get_object_item(lndparams, "map_on_demand");
	lnd_cfg->lnd_map_on_demand =
		(map_on_demand) ? map_on_demand->cy_valueint : 0;

	concurrent_sends = cYAML_get_object_item(lndparams, "concurrent_sends");
	lnd_cfg->lnd_concurrent_sends =
		(concurrent_sends) ? concurrent_sends->cy_valueint : 0;

	fmr_pool_size = cYAML_get_object_item(lndparams, "fmr_pool_size");
	lnd_cfg->lnd_fmr_pool_size =
		(fmr_pool_size) ? fmr_pool_size->cy_valueint : 0;

	fmr_flush_trigger = cYAML_get_object_item(lndparams,
						  "fmr_flush_trigger");
	lnd_cfg->lnd_fmr_flush_trigger =
		(fmr_flush_trigger) ? fmr_flush_trigger->cy_valueint : 0;

	fmr_cache = cYAML_get_object_item(lndparams, "fmr_cache");
	lnd_cfg->lnd_fmr_cache =
		(fmr_cache) ? fmr_cache->cy_valueint : 0;

	ntx = cYAML_get_object_item(lndparams, "ntx");
	lnd_cfg->lnd_ntx = (ntx) ? ntx->cy_valueint : 0;

	conns_per_peer = cYAML_get_object_item(lndparams, "conns_per_peer");
	lnd_cfg->lnd_conns_per_peer =
		(conns_per_peer) ? conns_per_peer->cy_valueint : 1;
}


void
lustre_yaml_extract_lnd_tunables(struct cYAML *tree,
				 __u32 net_type,
				 struct lnet_lnd_tunables *tun)
{
	if (net_type == O2IBLND)
		yaml_extract_o2ib_tun(tree,
				      &tun->lnd_tun_u.lnd_o2ib);

}

