// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2023, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/obd_test.c
 *
 * Simple OBD device for:
 *   1) testing OBD device lifecycle management
 *   2) demonstrating a simple OBD device
 *
 * Author: Timothy Day <timday@amazon.com>
 *
 */

#include <linux/module.h>

#include <obd_class.h>

static int verbose;
module_param(verbose, int, 0644);
MODULE_PARM_DESC(verbose, "Set the logging level for the module");

static int obd_test_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	if (verbose >= 1)
		pr_info("Lustre: OBD: %s", __func__);

	if (verbose >= 2) {
		int obd_minor_found;

		pr_info("Lustre: OBD: obd_name: %s, obd_num: %i, obd_uuid: %s",
		       obd->obd_name, obd->obd_minor, obd->obd_uuid.uuid);

		obd_minor_found = class_name2dev(obd->obd_name);
		pr_info("Lustre: OBD: class_name2dev(): %i, %s",
		       obd_minor_found,
		       obd_minor_found == obd->obd_minor ? "PASS" : "FAIL");

		obd_minor_found = class_uuid2dev(&obd->obd_uuid);
		pr_info("Lustre: OBD: class_uuid2dev(): %i, %s",
		       obd_minor_found,
		       obd_minor_found == obd->obd_minor ? "PASS" : "FAIL");

		obd_minor_found = class_name2obd(obd->obd_name)->obd_minor;
		pr_info("Lustre: OBD: class_name2obd(): %i, %s",
		       obd_minor_found,
		       obd_minor_found == obd->obd_minor ? "PASS" : "FAIL");

		obd_minor_found = class_uuid2obd(&obd->obd_uuid)->obd_minor;
		pr_info("Lustre: OBD: class_uuid2obd(): %i, %s",
		       obd_minor_found,
		       obd_minor_found == obd->obd_minor ? "PASS" : "FAIL");
	}

	return 0;
}

static int obd_test_cleanup(struct obd_device *obd)
{
	if (verbose >= 1)
		pr_info("Lustre: OBD: %s", __func__);

	return 0;
}

static const struct obd_ops obd_test_obd_ops = {
	.o_owner       = THIS_MODULE,
	.o_setup       = obd_test_setup,
	.o_cleanup     = obd_test_cleanup,
};

static int __init obd_test_init(void)
{
	return class_register_type(&obd_test_obd_ops, NULL, false,
				   "obd_test", NULL);
}

static void __exit obd_test_exit(void)
{
	class_unregister_type("obd_test");
}

MODULE_AUTHOR("Amazon, Inc. <timday@amazon.com>");
MODULE_DESCRIPTION("Lustre OBD test module");
MODULE_VERSION(LUSTRE_VERSION_STRING);
MODULE_LICENSE("GPL");

module_init(obd_test_init);
module_exit(obd_test_exit);
