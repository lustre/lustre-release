// SPDX-License-Identifier: GPL-2.0-only

/*
 * The implementation of the wait_bit*() and related waiting APIs:
 */

#include <linux/sched.h>
#ifdef HAVE_SCHED_HEADERS
#include <linux/sched/signal.h>
#endif
#include <lustre_compat/linux/wait_bit.h>

#ifndef HAVE_WAIT_VAR_EVENT

#define WAIT_TABLE_BITS 8
#define WAIT_TABLE_SIZE (1 << WAIT_TABLE_BITS)

static wait_queue_head_t bit_wait_table[WAIT_TABLE_SIZE] __cacheline_aligned;

wait_queue_head_t *__var_waitqueue(void *p)
{
	return bit_wait_table + hash_ptr(p, WAIT_TABLE_BITS);
}
EXPORT_SYMBOL(__var_waitqueue);

static int
var_wake_function(wait_queue_entry_t *wq_entry, unsigned int mode,
		  int sync, void *arg)
{
	struct wait_bit_key *key = arg;
	struct wait_bit_queue_entry *wbq_entry =
		container_of(wq_entry, struct wait_bit_queue_entry, wq_entry);

	if (wbq_entry->key.flags != key->flags ||
	    wbq_entry->key.bit_nr != key->bit_nr)
		return 0;

	return autoremove_wake_function(wq_entry, mode, sync, key);
}

void init_wait_var_entry(struct wait_bit_queue_entry *wbq_entry, void *var,
			 int flags)
{
	*wbq_entry = (struct wait_bit_queue_entry){
		.key = {
			.flags	= (var),
			.bit_nr = -1,
		},
		.wq_entry = {
			.private = current,
			.func = var_wake_function,
#ifdef HAVE_WAIT_QUEUE_ENTRY_LIST
			.entry = LIST_HEAD_INIT(wbq_entry->wq_entry.entry),
#else
			.task_list = LIST_HEAD_INIT(wbq_entry->wq_entry.task_list),
#endif
		},
	};
}
EXPORT_SYMBOL(init_wait_var_entry);

void wake_up_var(void *var)
{
	__wake_up_bit(__var_waitqueue(var), var, -1);
}
EXPORT_SYMBOL(wake_up_var);

void __init wait_bit_init(void)
{
	int i;

	for (i = 0; i < WAIT_TABLE_SIZE; i++)
		init_waitqueue_head(bit_wait_table + i);
}
#endif /* ! HAVE_WAIT_VAR_EVENT */
