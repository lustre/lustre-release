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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2015, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET
#include <lnet/lib-lnet.h>
#include <lnet/lib-dlc.h>

static int config_on_load = 0;
CFS_MODULE_PARM(config_on_load, "i", int, 0444,
                "configure network at module load");

static struct mutex lnet_config_mutex;

static int
lnet_configure(void *arg)
{
	/* 'arg' only there so I can be passed to cfs_create_thread() */
	int    rc = 0;

	LNET_MUTEX_LOCK(&lnet_config_mutex);

	if (!the_lnet.ln_niinit_self) {
		rc = try_module_get(THIS_MODULE);

		if (rc != 1)
			goto out;

		rc = LNetNIInit(LNET_PID_LUSTRE);
		if (rc >= 0) {
			the_lnet.ln_niinit_self = 1;
			rc = 0;
		} else {
			module_put(THIS_MODULE);
		}
	}

out:
	LNET_MUTEX_UNLOCK(&lnet_config_mutex);
	return rc;
}

static int
lnet_unconfigure (void)
{
	int   refcount;

	LNET_MUTEX_LOCK(&lnet_config_mutex);

	if (the_lnet.ln_niinit_self) {
		the_lnet.ln_niinit_self = 0;
		LNetNIFini();
		module_put(THIS_MODULE);
	}

	LNET_MUTEX_LOCK(&the_lnet.ln_api_mutex);
	refcount = the_lnet.ln_refcount;
	LNET_MUTEX_UNLOCK(&the_lnet.ln_api_mutex);

	LNET_MUTEX_UNLOCK(&lnet_config_mutex);

	return (refcount == 0) ? 0 : -EBUSY;
}

static int
lnet_dyn_configure(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_data *conf =
	  (struct lnet_ioctl_config_data *)hdr;
	int			      rc;

	LNET_MUTEX_LOCK(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_add_ni(LNET_PID_LUSTRE, conf);
	else
		rc = -EINVAL;
	LNET_MUTEX_UNLOCK(&lnet_config_mutex);
	return rc;
}

static int
lnet_dyn_unconfigure(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_data *conf =
	  (struct lnet_ioctl_config_data *) hdr;
	int			      rc;

	LNET_MUTEX_LOCK(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_del_ni(conf->cfg_net);
	else
		rc = -EINVAL;
	LNET_MUTEX_UNLOCK(&lnet_config_mutex);

	return rc;
}

static int
lnet_ioctl(unsigned int cmd, struct libcfs_ioctl_hdr *hdr)
{
	int   rc;

	switch (cmd) {
	case IOC_LIBCFS_CONFIGURE: {
		struct libcfs_ioctl_data *data =
		  (struct libcfs_ioctl_data *)hdr;
		the_lnet.ln_nis_from_mod_params = data->ioc_flags;
		return lnet_configure(NULL);
	}

	case IOC_LIBCFS_UNCONFIGURE:
		return lnet_unconfigure();

	case IOC_LIBCFS_ADD_NET:
		return lnet_dyn_configure(hdr);

	case IOC_LIBCFS_DEL_NET:
		return lnet_dyn_unconfigure(hdr);

	default:
		/* Passing LNET_PID_ANY only gives me a ref if the net is up
		 * already; I'll need it to ensure the net can't go down while
		 * I'm called into it */
		rc = LNetNIInit(LNET_PID_ANY);
		if (rc >= 0) {
			rc = LNetCtl(cmd, hdr);
			LNetNIFini();
		}
		return rc;
	}
}

DECLARE_IOCTL_HANDLER(lnet_ioctl_handler, lnet_ioctl);

static int __init lnet_init(void)
{
	int rc;
	ENTRY;

	mutex_init(&lnet_config_mutex);

	rc = lnet_lib_init();
	if (rc != 0) {
		CERROR("lnet_lib_init: error %d\n", rc);
		RETURN(rc);
	}

	rc = libcfs_register_ioctl(&lnet_ioctl_handler);
	LASSERT(rc == 0);

	if (config_on_load) {
		/* Have to schedule a separate thread to avoid deadlocking
		 * in modload */
		(void)kthread_run(lnet_configure, NULL, "lnet_initd");
	}

	RETURN(0);
}

static void __exit lnet_exit(void)
{
	int rc;

	rc = libcfs_deregister_ioctl(&lnet_ioctl_handler);
	LASSERT(rc == 0);

	lnet_lib_exit();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Networking layer");
MODULE_VERSION(LNET_VERSION);
MODULE_LICENSE("GPL");

module_init(lnet_init);
module_exit(lnet_exit);
