// SPDX-License-Identifier: GPL-2.0

#include <linux/module.h>
#include <linux/kernel.h>

#include <libcfs/libcfs.h>
#include <lustre_dlm.h>
#include <obd_support.h>
#include <obd.h>
#include <obd_class.h>
#include <lustre_lib.h>
#include "../../ldlm/ldlm_internal.h"

/*
 * Performance tests for ldlm_extent access
 */
static int extent_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	return 0;
}
static int extent_cleanup(struct obd_device *obd)
{
	return 0;
}
static const struct obd_ops extent_ops = {
	.o_owner       = THIS_MODULE,
	.o_setup       = extent_setup,
	.o_cleanup     = extent_cleanup,
};

static struct ldlm_res_id RES_ID = {
	.name = {1, 2, 3, 4},
};

static void test_one(struct ldlm_resource *res,
		     u64 pos, u64 len, enum ldlm_mode mode,
		     int *cnt, int max, struct list_head *list)
{
	__u64 flags = 0;
	enum ldlm_error err;
	ldlm_processing_policy pol;
	struct ldlm_lock *lock = ldlm_lock_new_testing(res);
	//struct ldlm_lock *lock = ldlm_lock_create(ns, &RES_ID,
	//					  LDLM_EXTENT, LCK_EX,
	//					  NULL, NULL, 0, LVB_T_NONE);

	refcount_inc(&res->lr_refcount);

	lock->l_req_mode = mode;

	pol = ldlm_get_processing_policy(res);

	lock->l_policy_data.l_extent.start = pos;
	lock->l_policy_data.l_extent.end = pos + len;
	lock->l_policy_data.l_extent.gid = 0;
	lock->l_req_extent = lock->l_policy_data.l_extent;

	lock_res(res);

	if (pol(lock, &flags, LDLM_PROCESS_ENQUEUE, &err, NULL)
	    == LDLM_ITER_CONTINUE) {
		list_add_tail(&lock->l_lru, list);
		unlock_res(res);
		*cnt += 1;
	} else {
		unlock_res(res);
		ldlm_lock_cancel(lock);
		ldlm_lock_put(lock);
	}

	if (*cnt > max) {
		lock = list_first_entry_or_null(list,
						struct ldlm_lock, l_lru);
		if (lock) {
			list_del_init(&lock->l_lru);
			ldlm_lock_cancel(lock);
			ldlm_lock_put(lock);
			*cnt -= 1;
		}
	}
}

enum tests {
	TEST_NO_OVERLAP,
	TEST_WHOLE_FILE,
	TEST_SAME_RANGE,

	NUM_TESTS,
};

static int ldlm_extent_init(void)
{
	struct lustre_cfg *cfg;
	struct lustre_cfg_bufs bufs;
	char *name, *uuid;
	struct ldlm_resource *res;
	struct obd_device *obd;
	struct ldlm_namespace *ns;
	enum tests tnum;
	struct rnd_state rstate;

	prandom_seed_state(&rstate, 42);

	class_register_type(&extent_ops, NULL, false, "ldlm_test", NULL);

	OBD_ALLOC(name, MAX_OBD_NAME);
	OBD_ALLOC(uuid, MAX_OBD_NAME);
	strscpy(name, "test", MAX_OBD_NAME);
	lustre_cfg_bufs_reset(&bufs, name);
	snprintf(uuid, MAX_OBD_NAME, "%s_UUID", name);

	lustre_cfg_bufs_set_string(&bufs, 1, "ldlm_test"); /* typename */
	lustre_cfg_bufs_set_string(&bufs, 2, uuid);
	OBD_ALLOC(cfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	lustre_cfg_init(cfg, LCFG_ATTACH, &bufs);

	class_attach(cfg);
	obd = class_name2obd("test");
	ns = ldlm_namespace_new(obd, "extent-test", LDLM_NAMESPACE_CLIENT,
				LDLM_NAMESPACE_MODEST,
				LDLM_NS_TYPE_MDT);
	res = ldlm_resource_get(ns, &RES_ID, LDLM_EXTENT, 1);

	pr_info("ldlm_extent: sizeof(struct ldlm_lock)=%lu\n",
	       sizeof(struct ldlm_lock));
	for (tnum = 0; tnum < NUM_TESTS; tnum++) {
		long sum = 0, sumsq = 0, nsec;
		int min_iters = 10, lk_num, it_num;
		int loops;

		pr_info("ldlm_extent: start test %d\n", tnum);
		for (loops = 0; loops < 10 ; loops++) {
			struct ldlm_lock *lock;
			ktime_t start, now;
			LIST_HEAD(list);
			int cnt = 0;
			int max = 1;
			int i;

			start = now = ktime_get();
			for (i = 0; i < 10000000; i++) {
				switch (tnum) {
				case TEST_NO_OVERLAP:
					max = min(8000, min_iters);
					if (i < max * 16 / 15)
						max = i * 15 / 16;
					test_one(res,
						 prandom_u32_state(&rstate), 1,
						 LCK_EX, &cnt, max, &list);
					break;
				case TEST_WHOLE_FILE:
					max = min(1000000, min_iters);
					if (i < max * 16 / 15)
						max = i * 15 / 16;
					test_one(res, 0, OBD_OBJECT_EOF, LCK_PR,
						 &cnt, max, &list);
					test_one(res,
						 prandom_u32_state(&rstate), 1,
						 LCK_PR, &cnt, max, &list);
					break;
				case TEST_SAME_RANGE:
					max = min(1000000, min_iters);
					if (i < max * 16 / 15)
						max = i * 15 / 16;
					test_one(res, 400, 300, LCK_PR,
						 &cnt, max, &list);
					lock = list_first_entry_or_null(&list,
						struct ldlm_lock, l_lru);
					if (lock)
						ldlm_extent_shift_kms(lock, 1000);
					break;
				case NUM_TESTS:
					break;
				}
				now = ktime_get();
				if (ktime_to_ms(ktime_sub(now, start)) > 10000)
					break;
				cond_resched();
			}
			i++;
			if (i < min_iters / 3)
				min_iters = i;
			else if (i > min_iters * 3)
				min_iters *= 10;
			nsec = ktime_to_ns(ktime_sub(now, start)) / i;
			sum += nsec;
			sumsq += nsec * nsec;

			lk_num = it_num = 0;
			while ((lock = list_first_entry_or_null(&list,
						struct ldlm_lock, l_lru))
			       != NULL) {
#ifdef to_ldlm_interval
				struct ldlm_interval *n = lock->l_tree_node;

				if (n && interval_is_intree(&n->li_node) &&
				    lock->l_sl_policy.next == &n->li_group &&
				    lock->l_sl_policy.prev == &n->li_group)
					it_num++;
#else
				if (!RB_EMPTY_NODE(&lock->l_rb) &&
				    list_empty(&lock->l_same_extent))
					it_num++;
#endif
				list_del_init(&lock->l_lru);
				ldlm_lock_cancel(lock);
				ldlm_lock_put(lock);
				lk_num++;
			}
			pr_info("ldlm_extent: test %d loop=%d min_iters=%d iters=%d ns/iter=%lu (%d/%d)\n",
				tnum, loops, min_iters, i, nsec, lk_num, it_num);
		}

		pr_info("ldlm_extent: test %d ended - loops=%d min_iters=%d mean=%ld stddev=%ld\n",
		       tnum, loops, min_iters, sum / loops,
		       int_sqrt((sumsq - sum*sum/loops) / loops-1));
	}
	class_detach(obd, cfg);

	OBD_FREE(name, MAX_OBD_NAME);
	OBD_FREE(uuid, MAX_OBD_NAME);
	OBD_FREE(cfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));

	ldlm_resource_putref(res);
	ldlm_namespace_free_post(ns);
	class_unregister_type("ldlm_test");

	return 0;
}

static void ldlm_extent_exit(void)
{
}

MODULE_DESCRIPTION("Lustre ldlm_extent performance test");
MODULE_LICENSE("GPL");

module_init(ldlm_extent_init);
module_exit(ldlm_extent_exit);
