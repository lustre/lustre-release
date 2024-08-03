/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2017, Intel Corporation.
 *
 * Lustre write barrier (on MDT) exported functions.
 *
 * Author: Fan, Yong <fan.yong@intel.com>
 */

#ifndef _LUSTRE_BARRIER_H
# define _LUSTRE_BARRIER_H

#include <dt_object.h>
#include <lustre_export.h>

bool barrier_entry(struct dt_device *key);
void barrier_exit(struct dt_device *key);
int barrier_handler(struct dt_device *key, struct ptlrpc_request *req);
int barrier_register(struct dt_device *key, struct dt_device *next);
void barrier_deregister(struct dt_device *key);

#endif /* _LUSTRE_BARRIER_H */
