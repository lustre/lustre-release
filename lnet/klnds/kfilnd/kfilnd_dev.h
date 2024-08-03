/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd device implementation.
 */

#ifndef _KFILND_DEV_
#define _KFILND_DEV_

#include "kfilnd.h"

/* TODO: Module parameters? */
#define KFILND_CURRENT_HASH_BITS 7
#define KFILND_MAX_HASH_BITS 12

int kfilnd_dev_post_imm_buffers(struct kfilnd_dev *dev);
void kfilnd_dev_free(struct kfilnd_dev *dev);
struct kfilnd_dev *kfilnd_dev_alloc(struct lnet_ni *ni, const char *node);
void kfilnd_dev_reset_stats(struct kfilnd_dev *dev);
u32 kfilnd_dev_get_session_key(struct kfilnd_dev *dev);

#endif /* _KFILND_DEV_ */
