/* SPDX-License-Identifier: MIT */

/*
 * Copyright (c) 2024-2025. DDN. All rights reserved.
 * Use of this source code is governed by a MIT-style
 * license that can be found in the LICENSE file.
 */

#include<lustre/lustreapi.h>
#include<linux/lustre/lustre_user.h>


struct hsm_mover_private;

// HSM constants that should be picked up by bindgen
// HSM_REQ_BLOCKING is defined in lustre_user.h as 0x0004
#ifndef HSM_REQ_BLOCKING
#define HSM_REQ_BLOCKING 0x0004
#endif

int llapi_hsm_mover_register(struct hsm_mover_private **priv,
				const char *mnt);
int llapi_hsm_mover_unregister(struct hsm_mover_private **priv);

// int llapi_hsm_mover_action_begin(struct hsm_copyaction_private **phcp,
// 			   const hsm_mover_private *ct,
// 			   const struct hsm_action_item *hai,
// 			   int restore_mdt_index, int restore_open_flags,
// 			   bool is_error);
