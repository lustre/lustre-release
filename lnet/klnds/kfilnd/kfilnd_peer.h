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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */
/*
 * kfilnd peer interface.
 */

#ifndef _KFILND_PEER_
#define _KFILND_PEER_

#include "kfilnd.h"

void kfilnd_peer_down(struct kfilnd_peer *kp);
void kfilnd_peer_put(struct kfilnd_peer *kp);
struct kfilnd_peer *kfilnd_peer_get(struct kfilnd_dev *dev, lnet_nid_t nid);
void kfilnd_peer_update_rx_contexts(struct kfilnd_peer *kp,
				    unsigned int rx_base,
				    unsigned int rx_count);
void kfilnd_peer_alive(struct kfilnd_peer *kp);
void kfilnd_peer_destroy(struct kfilnd_dev *dev);
void kfilnd_peer_init(struct kfilnd_dev *dev);
kfi_addr_t kfilnd_peer_get_kfi_addr(struct kfilnd_peer *kp);
u16 kfilnd_peer_target_rx_base(struct kfilnd_peer *kp);

#endif /* _KFILND_PEER_ */
