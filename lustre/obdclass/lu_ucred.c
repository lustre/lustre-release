// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2013, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre user credentials context infrastructure.
 *
 * Author: Nikita Danilov <nikita.danilov@sun.com>
 * Author: Fan Yong <fan.yong@intel.com>
 * Author: Vitaly Fertman <vitaly_fertman@xyratex.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <libcfs/libcfs.h>
#include <obd_support.h>
#include <lu_object.h>
#include <md_object.h>

/* context key constructor/destructor: lu_ucred_key_init, lu_ucred_key_fini */
LU_KEY_INIT_FINI(lu_ucred, struct lu_ucred);

static struct lu_context_key lu_ucred_key = {
	.lct_tags = LCT_SERVER_SESSION,
	.lct_init = lu_ucred_key_init,
	.lct_fini = lu_ucred_key_fini
};

/**
 * Get ucred key if session exists and ucred key is allocated on it.
 * Return NULL otherwise.
 */
struct lu_ucred *lu_ucred(const struct lu_env *env)
{
	if (!env->le_ses)
		return NULL;
	return lu_context_key_get(env->le_ses, &lu_ucred_key);
}
EXPORT_SYMBOL(lu_ucred);

/**
 * Get ucred key and check if it is properly initialized.
 * Return NULL otherwise.
 */
struct lu_ucred *lu_ucred_check(const struct lu_env *env)
{
	struct lu_ucred *uc = lu_ucred(env);
	if (uc && uc->uc_valid != UCRED_OLD && uc->uc_valid != UCRED_NEW)
		return NULL;
	return uc;
}
EXPORT_SYMBOL(lu_ucred_check);

/**
 * Get ucred key, which must exist and must be properly initialized.
 * Assert otherwise.
 */
struct lu_ucred *lu_ucred_assert(const struct lu_env *env)
{
	struct lu_ucred *uc = lu_ucred_check(env);
	LASSERT(uc != NULL);
	return uc;
}
EXPORT_SYMBOL(lu_ucred_assert);

int lu_ucred_global_init(void)
{
	LU_CONTEXT_KEY_INIT(&lu_ucred_key);
	return lu_context_key_register(&lu_ucred_key);
}

void lu_ucred_global_fini(void)
{
	lu_context_key_degister(&lu_ucred_key);
}
