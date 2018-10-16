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
