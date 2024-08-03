// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd device implementation.
 */

#include "kfilnd.h"
#include "kfilnd_dev.h"

#define TIME_MAX 0xFFFFFFFFFFFF
static s64 get_ave_duration(struct kfilnd_tn_duration_stat *stat)
{
	s64 duration;

	if (!atomic_read(&stat->accumulated_count))
		return 0;

	duration = atomic64_read(&stat->accumulated_duration) /
		atomic_read(&stat->accumulated_count);

	return min_t(s64, duration, TIME_MAX);
}

static s64 get_min_duration(struct kfilnd_tn_duration_stat *stat)
{
	s64 min;

	min = atomic64_read(&stat->min_duration);
	if (min == MIN_DURATION_RESET)
		return 0;
	return min;
}

static void seq_print_tn_state_stats(struct seq_file *s, struct kfilnd_dev *dev,
				     bool initiator)
{
	struct kfilnd_tn_state_data_size_duration_stats *state_stats;
	unsigned int data_size;

	if (initiator)
		state_stats = &dev->initiator_state_stats;
	else
		state_stats = &dev->target_state_stats;

	seq_printf(s, "%-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s %-20s\n",
		   "MSG_SIZE", "IDLE", "WAIT_TAG_COMP", "IMM_SEND",
		   "TAGGED_RECV_POSTED", "SEND_FAILED", "WAIT_COMP",
		   "WAIT_TOUT_COMP", "SEND_COMP", "WAIT_TOUT_TAG_COMP", "FAIL",
		   "IMM_RECV", "WAIT_TAG_RMA_COMP");

	for (data_size = 0; data_size < KFILND_DATA_SIZE_BUCKETS; data_size++) {
		seq_printf(s, "%-20lu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu %-20llu\n",
			   data_size == 0 ? 0 : BIT(data_size - 1),
			   get_ave_duration(&state_stats->state[TN_STATE_IDLE].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_WAIT_TAG_COMP].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_IMM_SEND].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_TAGGED_RECV_POSTED].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_SEND_FAILED].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_WAIT_COMP].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_WAIT_TIMEOUT_COMP].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_WAIT_SEND_COMP].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_WAIT_TIMEOUT_TAG_COMP].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_FAIL].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_IMM_RECV].data_size[data_size]),
			   get_ave_duration(&state_stats->state[TN_STATE_WAIT_TAG_RMA_COMP].data_size[data_size]));
	}
}

static int kfilnd_initiator_state_stats_file_show(struct seq_file *s,
						  void *unused)
{
	seq_print_tn_state_stats(s, s->private, true);

	return 0;
}

static int kfilnd_initiator_state_stats_file_open(struct inode *inode,
						  struct file *file)
{
	return single_open(file, kfilnd_initiator_state_stats_file_show,
			   inode->i_private);
}

const struct file_operations kfilnd_initiator_state_stats_file_ops = {
	.owner = THIS_MODULE,
	.open = kfilnd_initiator_state_stats_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int kfilnd_target_state_stats_file_show(struct seq_file *s,
					       void *unused)
{
	seq_print_tn_state_stats(s, s->private, false);

	return 0;
}

static int kfilnd_target_state_stats_file_open(struct inode *inode,
					       struct file *file)
{
	return single_open(file, kfilnd_target_state_stats_file_show,
			   inode->i_private);
}

const struct file_operations kfilnd_target_state_stats_file_ops = {
	.owner = THIS_MODULE,
	.open = kfilnd_target_state_stats_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static void seq_print_tn_stats(struct seq_file *s, struct kfilnd_dev *dev,
			       bool initiator)
{
	struct kfilnd_tn_data_size_duration_stats *stats;
	unsigned int data_size;

	if (initiator)
		stats = &dev->initiator_stats;
	else
		stats = &dev->target_stats;

	seq_printf(s, "%16s %16s %16s %16s %16s\n", "MSG_SIZE", "MIN", "MAX",
		   "AVE", "COUNT");

	for (data_size = 0; data_size < KFILND_DATA_SIZE_BUCKETS; data_size++) {
		seq_printf(s, "%16lu %16llu %16llu %16llu %16d\n",
			   data_size == 0 ? 0 : BIT(data_size - 1),
			   get_min_duration(&stats->data_size[data_size]),
			   atomic64_read(&stats->data_size[data_size].max_duration),
			   get_ave_duration(&stats->data_size[data_size]),
			   atomic_read(&stats->data_size[data_size].accumulated_count));
	}
}

static int kfilnd_initiator_stats_file_show(struct seq_file *s, void *unused)
{
	seq_print_tn_stats(s, s->private, true);

	return 0;
}

static int kfilnd_initiator_stats_file_open(struct inode *inode,
					    struct file *file)
{
	return single_open(file, kfilnd_initiator_stats_file_show,
			   inode->i_private);
}

const struct file_operations kfilnd_initiator_stats_file_ops = {
	.owner = THIS_MODULE,
	.open = kfilnd_initiator_stats_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static int kfilnd_target_stats_file_show(struct seq_file *s, void *unused)
{
	seq_print_tn_stats(s, s->private, false);

	return 0;
}

static int kfilnd_target_stats_file_open(struct inode *inode, struct file *file)
{
	return single_open(file, kfilnd_target_stats_file_show,
			   inode->i_private);
}

const struct file_operations kfilnd_target_stats_file_ops = {
	.owner = THIS_MODULE,
	.open = kfilnd_target_stats_file_open,
	.read = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release,
};

static ssize_t kfilnd_reset_stats_file_write(struct file *filp,
					     const char __user *buf,
					     size_t count, loff_t *loff)
{
	kfilnd_dev_reset_stats(filp->f_inode->i_private);

	return count;
}

const struct file_operations kfilnd_reset_stats_file_ops = {
	.owner = THIS_MODULE,
	.write = kfilnd_reset_stats_file_write,
};
