// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025, Amazon and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Simple OBD device mock test for LU-18826.
 *
 * Author: Lijing Chen <lijinc@amazon.com>
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/bitmap.h>

#include <obd_class.h>
#include <lustre_net.h>

struct test_ctx {
	struct client_obd *cli;
	struct obd_import *imp;
	struct obd_device *obd;
	unsigned int old_flags;
	int __user *old_set_child_tid;
};

static void setup_test_context(struct test_ctx *ctx)
{
	int i;

	OBD_ALLOC_PTR(ctx->cli);
	OBD_ALLOC_PTR(ctx->imp);
	OBD_ALLOC_PTR(ctx->obd);

	init_waitqueue_head(&ctx->cli->cl_mod_rpcs_waitq);
	ctx->cli->cl_max_mod_rpcs_in_flight = 0;
	ctx->cli->cl_mod_rpcs_in_flight = 0;

	/* Initialize cl_mod_rpcs_hist */
	spin_lock_init(&ctx->cli->cl_mod_rpcs_hist.oh_lock);
	for (i = 0; i < OBD_HIST_MAX; i++)
		ctx->cli->cl_mod_rpcs_hist.oh_buckets[i] = 0;

	/* Initialize bitmap */
	OBD_ALLOC(ctx->cli->cl_mod_tag_bitmap,
		  BITS_TO_LONGS(OBD_MAX_RIF_MAX) * sizeof(long));

	/* Set up import and obd structures */
	ctx->imp->imp_obd = ctx->obd;
	ctx->cli->cl_import = ctx->imp;
	snprintf(ctx->obd->obd_name, sizeof(ctx->obd->obd_name), "mock_obd");

	/* Save current state */
	ctx->old_flags = current->flags;
	ctx->old_set_child_tid = current->set_child_tid;

	/* Set set_child_tid to NULL for testing */
	current->set_child_tid = NULL;
}

static void cleanup_test_context(struct test_ctx *ctx)
{
	OBD_FREE(ctx->cli->cl_mod_tag_bitmap,
		 BITS_TO_LONGS(OBD_MAX_RIF_MAX) * sizeof(long));
	OBD_FREE_PTR(ctx->obd);
	OBD_FREE_PTR(ctx->imp);
	OBD_FREE_PTR(ctx->cli);

	/* Restore original state */
	current->flags = ctx->old_flags;
	current->set_child_tid = ctx->old_set_child_tid;
}

static void test_kthread_flags(void)
{
	struct test_ctx ctx;
	__u32 opc = MDS_STATFS;
	__u16 ret;

	pr_info("\n=== Starting test case 1: kthread flags ===\n");

	setup_test_context(&ctx);

	/* Set kthread flags */
	current->flags = PF_KTHREAD|PF_MEMALLOC|PF_NOFREEZE|PF_FORKNOEXEC;

	pr_info("Test 1: Current flags: 0x%x\n", current->flags);
	pr_info("Test 1: set_child_tid: %p\n", current->set_child_tid);

	/* Simulate cl_mod_rpcs_in_flight > cl_max_mod_rpcs_in_flight */
	test_and_set_bit(0, ctx.cli->cl_mod_tag_bitmap);
	test_and_set_bit(1, ctx.cli->cl_mod_tag_bitmap);
	ctx.cli->cl_mod_rpcs_in_flight = 1;
	ctx.cli->cl_close_rpcs_in_flight = 1;

	ret = obd_get_mod_rpc_slot(ctx.cli, opc);

	pr_info("Test 1: Return value (slot): %u\n", ret);
	pr_info("Test 1: RPCs in flight: %d\n", ctx.cli->cl_mod_rpcs_in_flight);

	cleanup_test_context(&ctx);

	pr_info("=== Finished test case 1 ===\n");
}

static void test_non_mem_alloc_flags(void)
{
	struct test_ctx ctx;
	__u32 opc = MDS_CLOSE;
	__u16 ret;

	pr_info("\n=== Starting test case 2: non mem_alloc flags ===\n");

	setup_test_context(&ctx);

	/* Set minimal flags */
	current->flags = PF_KTHREAD|PF_NOFREEZE|PF_FORKNOEXEC;

	pr_info("Test 2: Current flags: 0x%x\n", current->flags);
	pr_info("Test 2: set_child_tid: %p\n", current->set_child_tid);

	ret = obd_get_mod_rpc_slot(ctx.cli, opc);

	pr_info("Test 2: Return value (slot): %u\n", ret);
	pr_info("Test 2: RPCs in flight: %d\n", ctx.cli->cl_mod_rpcs_in_flight);

	cleanup_test_context(&ctx);

	pr_info("=== Finished test case 2 ===\n");
}

static int __init obd_mod_rpcs_test_init(void)
{
	/* Run test cases */
	test_kthread_flags();
	test_non_mem_alloc_flags();
	return 0;
}

static void __exit obd_mod_rpcs_test_exit(void)
{
	pr_info("Task Module: Unloading module\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lijing Chen <lijinc@amazon.com>");
MODULE_DESCRIPTION("Lustre OBD test module");
MODULE_VERSION(LUSTRE_VERSION_STRING);

module_init(obd_mod_rpcs_test_init);
module_exit(obd_mod_rpcs_test_exit);
