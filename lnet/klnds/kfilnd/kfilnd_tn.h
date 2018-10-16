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
 * kfilnd transaction and state machine processing.
 */
#ifndef _KFILND_TN_
#define _KFILND_TN_

#include "kfilnd.h"

void kfilnd_tn_process_rx_event(struct kfilnd_immediate_buffer *bufdesc,
				struct kfilnd_msg *rx_msg, int msg_size);
void kfilnd_tn_free(struct kfilnd_transaction *tn);
struct kfilnd_transaction *kfilnd_tn_alloc(struct kfilnd_dev *dev, int cpt,
					   lnet_nid_t target_nid,
					   bool alloc_msg, bool is_initiator,
					   bool key);
void kfilnd_tn_event_handler(struct kfilnd_transaction *tn,
			     enum tn_events event, int status);
void kfilnd_tn_cleanup(void);
int kfilnd_tn_init(void);
int kfilnd_tn_set_kiov_buf(struct kfilnd_transaction *tn, struct bio_vec *kiov,
		           size_t num_iov, size_t offset, size_t nob);

#endif /* _KFILND_TN_ */
