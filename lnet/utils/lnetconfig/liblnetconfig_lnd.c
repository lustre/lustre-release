// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (c) 2015, James Simmons
 *
 * Copyright (c) 2016, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Author: James Simmons <jsimmons@infradead.org>
 */

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <libcfs/util/ioctl.h>
#include "liblnd.h"
#include "liblnetconfig.h"

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

	if (cYAML_create_number(lndparams, "timeout",
				lnd_cfg->lnd_timeout) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "tos",
				lnd_cfg->lnd_tos) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	return LUSTRE_CFG_RC_NO_ERR;
}


static int
lustre_socklnd_show_tun(struct cYAML *lndparams,
			struct lnet_ioctl_config_socklnd_tunables *lnd_cfg)
{
	if (cYAML_create_number(lndparams, "conns_per_peer",
				lnd_cfg->lnd_conns_per_peer) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "timeout",
				lnd_cfg->lnd_timeout) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "tos",
				lnd_cfg->lnd_tos) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	return LUSTRE_CFG_RC_NO_ERR;
}

#ifdef HAVE_KFILND
static int
lustre_kfilnd_show_tun(struct cYAML *lndparams,
		       struct lnet_ioctl_config_kfilnd_tunables *lnd_cfg,
		       bool backup)
{
	if (cYAML_create_number(lndparams, "prov_major_version",
				lnd_cfg->lnd_prov_major_version) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "prov_minor_version",
				lnd_cfg->lnd_prov_minor_version) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_number(lndparams, "auth_key",
				lnd_cfg->lnd_auth_key) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (cYAML_create_string(lndparams, "traffic_class",
				lnd_cfg->lnd_traffic_class_str) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	if (!backup &&
	    cYAML_create_number(lndparams, "traffic_class_num",
				lnd_cfg->lnd_traffic_class) == NULL)
		return LUSTRE_CFG_RC_OUT_OF_MEM;

	return LUSTRE_CFG_RC_NO_ERR;
}
#endif

static int
lustre_gnilnd_show_tun(struct cYAML *lndparams,
			struct lnet_ioctl_config_gnilnd_tunables *lnd_cfg)
{
	if (cYAML_create_number(lndparams, "timeout",
				lnd_cfg->lnd_timeout) == NULL)
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
			struct lnet_lnd_tunables *lnd,
			bool backup)
{
	int rc = LUSTRE_CFG_RC_NO_MATCH;

	if (net_type == O2IBLND)
		rc = lustre_o2iblnd_show_tun(lnd_tunables,
					     &lnd->lnd_tun_u.lnd_o2ib);
	else if (net_type == SOCKLND)
		rc = lustre_socklnd_show_tun(lnd_tunables,
					     &lnd->lnd_tun_u.lnd_sock);
#ifdef HAVE_KFILND
	else if (net_type == KFILND)
		rc = lustre_kfilnd_show_tun(lnd_tunables,
					    &lnd->lnd_tun_u.lnd_kfi,
					    backup);
#endif
	else if (net_type == GNILND)
		rc = lustre_gnilnd_show_tun(lnd_tunables,
					    &lnd->lnd_tun_u.lnd_gni);
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
	struct cYAML *tos = NULL;

	lndparams = cYAML_get_object_item(tree, "lnd tunables");
	if (!lndparams)
		return;

	map_on_demand = cYAML_get_object_item(lndparams, "map_on_demand");
	lnd_cfg->lnd_map_on_demand =
		(map_on_demand) ? map_on_demand->cy_valueint : UINT_MAX;

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

	tos = cYAML_get_object_item(lndparams, "tos");
	lnd_cfg->lnd_tos =
		(tos) ? tos->cy_valueint : -1;
}

#ifdef HAVE_KFILND
static void
yaml_extract_kfi_tun(struct cYAML *tree,
		      struct lnet_ioctl_config_kfilnd_tunables *lnd_cfg)
{
	struct cYAML *prov_major_version = NULL;
	struct cYAML *prov_minor_version = NULL;
	struct cYAML *auth_key = NULL;
	struct cYAML *traffic_class = NULL;
	struct cYAML *lndparams = NULL;

	lndparams = cYAML_get_object_item(tree, "lnd tunables");
	if (!lndparams)
		return;

	prov_major_version =
		cYAML_get_object_item(lndparams, "prov_major_version");
	lnd_cfg->lnd_prov_major_version =
		(prov_major_version) ? prov_major_version->cy_valueint : 0;

	prov_minor_version =
		cYAML_get_object_item(lndparams, "prov_minor_version");
	lnd_cfg->lnd_prov_minor_version =
		(prov_minor_version) ? prov_minor_version->cy_valueint : 0;

	auth_key = cYAML_get_object_item(lndparams, "auth_key");
	lnd_cfg->lnd_auth_key =
		(auth_key) ? auth_key->cy_valueint : 0;

	traffic_class = cYAML_get_object_item(lndparams, "traffic_class");
	if (traffic_class && traffic_class->cy_valuestring &&
	    strlen(traffic_class->cy_valuestring) < LNET_MAX_STR_LEN)
		strcpy(&lnd_cfg->lnd_traffic_class_str[0],
		       traffic_class->cy_valuestring);
}
#endif

static void
yaml_extract_sock_tun(struct cYAML *tree,
			 struct lnet_ioctl_config_socklnd_tunables *lnd_cfg)
{
	struct cYAML *conns_per_peer = NULL;
	struct cYAML *tos = NULL;
	struct cYAML *lndparams = NULL;

	lndparams = cYAML_get_object_item(tree, "lnd tunables");
	if (!lndparams)
		return;

	conns_per_peer = cYAML_get_object_item(lndparams, "conns_per_peer");
	lnd_cfg->lnd_conns_per_peer =
		(conns_per_peer) ? conns_per_peer->cy_valueint : 1;

	tos = cYAML_get_object_item(lndparams, "tos");
	lnd_cfg->lnd_tos =
		(tos) ? tos->cy_valueint : -1;
}

void
lustre_yaml_extract_lnd_tunables(struct cYAML *tree,
				 __u32 net_type,
				 struct lnet_lnd_tunables *tun)
{
	if (net_type == O2IBLND)
		yaml_extract_o2ib_tun(tree,
				      &tun->lnd_tun_u.lnd_o2ib);
	else if (net_type == SOCKLND)
		yaml_extract_sock_tun(tree,
				      &tun->lnd_tun_u.lnd_sock);
#ifdef HAVE_KFILND
	else if (net_type == KFILND)
		yaml_extract_kfi_tun(tree,
				     &tun->lnd_tun_u.lnd_kfi);
#endif
}

