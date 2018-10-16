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
 * kfilnd completion queue.
 */
#ifndef _KFILND_CQ_
#define _KFILND_CQ_

#include "kfilnd.h"

void kfilnd_cq_process_error(struct kfilnd_ep *ep,
			     struct kfi_cq_err_entry *error);
struct kfilnd_cq *kfilnd_cq_alloc(struct kfilnd_ep *ep,
				  struct kfi_cq_attr *attr);
void kfilnd_cq_free(struct kfilnd_cq *cq);

#endif /*_KFILND_CQ_ */
