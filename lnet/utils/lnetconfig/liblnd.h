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
 * Copyright (c) 2015, James Simmons <jsimmons@infradead.org>
 *
 * Copyright (c) 2016, Intel Corporation.
 */

#ifndef LIB_LND_CONFIG_API_H
#define LIB_LND_CONFIG_API_H

#include <lnet/lib-dlc.h>
#include "cyaml.h"

int
lustre_net_show_tunables(struct cYAML *tunables,
			 struct lnet_ioctl_config_lnd_cmn_tunables *cmn);

int
lustre_ni_show_tunables(struct cYAML *lnd_tunables,
			__u32 net_type,
			struct lnet_lnd_tunables *lnd);

void
lustre_yaml_extract_lnd_tunables(struct cYAML *tree,
				 __u32 net_type,
				 struct lnet_lnd_tunables *tun);

#endif /* LIB_LND_CONFIG_API_H */
