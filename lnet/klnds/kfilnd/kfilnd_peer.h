/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd peer interface.
 */

#ifndef _KFILND_PEER_
#define _KFILND_PEER_

#include "kfilnd.h"

void kfilnd_peer_put(struct kfilnd_peer *kp);
struct kfilnd_peer *kfilnd_peer_get(struct kfilnd_dev *dev, lnet_nid_t nid);
void kfilnd_peer_alive(struct kfilnd_peer *kp);
void kfilnd_peer_destroy(struct kfilnd_dev *dev);
void kfilnd_peer_init(struct kfilnd_dev *dev);
kfi_addr_t kfilnd_peer_get_kfi_addr(struct kfilnd_peer *kp);
u16 kfilnd_peer_target_rx_base(struct kfilnd_peer *kp);
void kfilnd_peer_process_hello(struct kfilnd_peer *kp, struct kfilnd_msg *msg);
void kfilnd_peer_tn_failed(struct kfilnd_peer *kp, int error, bool delete);

#endif /* _KFILND_PEER_ */
