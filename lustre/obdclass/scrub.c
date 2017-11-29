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
 * Copyright (c) 2017, Intel Corporation.
 */
/*
 * lustre/obdclass/scrub.c
 *
 * The OI scrub is used for checking and (re)building Object Index files
 * that are usually backend special. Here are some general scrub related
 * functions that can be shared by different backends for OI scrub.
 *
 * Author: Fan Yong <fan.yong@intel.com>
 */

#define DEBUG_SUBSYSTEM S_LFSCK

#include <linux/kthread.h>
#include <lustre_scrub.h>
#include <lustre_lib.h>

static inline struct dt_device *scrub_obj2dev(struct dt_object *obj)
{
	return container_of0(obj->do_lu.lo_dev, struct dt_device, dd_lu_dev);
}

static void scrub_file_to_cpu(struct scrub_file *des, struct scrub_file *src)
{
	memcpy(des->sf_uuid, src->sf_uuid, 16);
	des->sf_flags	= le64_to_cpu(src->sf_flags);
	des->sf_magic	= le32_to_cpu(src->sf_magic);
	des->sf_status	= le16_to_cpu(src->sf_status);
	des->sf_param	= le16_to_cpu(src->sf_param);
	des->sf_time_last_complete      =
				le64_to_cpu(src->sf_time_last_complete);
	des->sf_time_latest_start       =
				le64_to_cpu(src->sf_time_latest_start);
	des->sf_time_last_checkpoint    =
				le64_to_cpu(src->sf_time_last_checkpoint);
	des->sf_pos_latest_start	=
				le64_to_cpu(src->sf_pos_latest_start);
	des->sf_pos_last_checkpoint     =
				le64_to_cpu(src->sf_pos_last_checkpoint);
	des->sf_pos_first_inconsistent  =
				le64_to_cpu(src->sf_pos_first_inconsistent);
	des->sf_items_checked		=
				le64_to_cpu(src->sf_items_checked);
	des->sf_items_updated		=
				le64_to_cpu(src->sf_items_updated);
	des->sf_items_failed		=
				le64_to_cpu(src->sf_items_failed);
	des->sf_items_updated_prior     =
				le64_to_cpu(src->sf_items_updated_prior);
	des->sf_run_time	= le32_to_cpu(src->sf_run_time);
	des->sf_success_count   = le32_to_cpu(src->sf_success_count);
	des->sf_oi_count	= le16_to_cpu(src->sf_oi_count);
	des->sf_internal_flags	= le16_to_cpu(src->sf_internal_flags);
	memcpy(des->sf_oi_bitmap, src->sf_oi_bitmap, SCRUB_OI_BITMAP_SIZE);
}

static void scrub_file_to_le(struct scrub_file *des, struct scrub_file *src)
{
	memcpy(des->sf_uuid, src->sf_uuid, 16);
	des->sf_flags	= cpu_to_le64(src->sf_flags);
	des->sf_magic	= cpu_to_le32(src->sf_magic);
	des->sf_status	= cpu_to_le16(src->sf_status);
	des->sf_param	= cpu_to_le16(src->sf_param);
	des->sf_time_last_complete      =
				cpu_to_le64(src->sf_time_last_complete);
	des->sf_time_latest_start       =
				cpu_to_le64(src->sf_time_latest_start);
	des->sf_time_last_checkpoint    =
				cpu_to_le64(src->sf_time_last_checkpoint);
	des->sf_pos_latest_start	=
				cpu_to_le64(src->sf_pos_latest_start);
	des->sf_pos_last_checkpoint     =
				cpu_to_le64(src->sf_pos_last_checkpoint);
	des->sf_pos_first_inconsistent  =
				cpu_to_le64(src->sf_pos_first_inconsistent);
	des->sf_items_checked		=
				cpu_to_le64(src->sf_items_checked);
	des->sf_items_updated		=
				cpu_to_le64(src->sf_items_updated);
	des->sf_items_failed		=
				cpu_to_le64(src->sf_items_failed);
	des->sf_items_updated_prior     =
				cpu_to_le64(src->sf_items_updated_prior);
	des->sf_run_time	= cpu_to_le32(src->sf_run_time);
	des->sf_success_count   = cpu_to_le32(src->sf_success_count);
	des->sf_oi_count	= cpu_to_le16(src->sf_oi_count);
	des->sf_internal_flags	= cpu_to_le16(src->sf_internal_flags);
	memcpy(des->sf_oi_bitmap, src->sf_oi_bitmap, SCRUB_OI_BITMAP_SIZE);
}

void scrub_file_init(struct lustre_scrub *scrub, __u8 *uuid)
{
	struct scrub_file *sf = &scrub->os_file;

	memset(sf, 0, sizeof(*sf));
	memcpy(sf->sf_uuid, uuid, 16);
	sf->sf_magic = SCRUB_MAGIC_V1;
	sf->sf_status = SS_INIT;
}
EXPORT_SYMBOL(scrub_file_init);

void scrub_file_reset(struct lustre_scrub *scrub, __u8 *uuid, __u64 flags)
{
	struct scrub_file *sf = &scrub->os_file;

	CDEBUG(D_LFSCK, "%s: reset OI scrub file, old flags = "
	       "%#llx, add flags = %#llx\n",
	       scrub->os_name, sf->sf_flags, flags);

	memcpy(sf->sf_uuid, uuid, 16);
	sf->sf_status = SS_INIT;
	sf->sf_flags |= flags;
	sf->sf_flags &= ~SF_AUTO;
	sf->sf_run_time = 0;
	sf->sf_time_latest_start = 0;
	sf->sf_time_last_checkpoint = 0;
	sf->sf_pos_latest_start = 0;
	sf->sf_pos_last_checkpoint = 0;
	sf->sf_pos_first_inconsistent = 0;
	sf->sf_items_checked = 0;
	sf->sf_items_updated = 0;
	sf->sf_items_failed = 0;
	sf->sf_items_noscrub = 0;
	sf->sf_items_igif = 0;
	if (!scrub->os_in_join)
		sf->sf_items_updated_prior = 0;
}
EXPORT_SYMBOL(scrub_file_reset);

int scrub_file_load(const struct lu_env *env, struct lustre_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file;
	struct lu_buf buf = {
		.lb_buf = &scrub->os_file_disk,
		.lb_len = sizeof(scrub->os_file_disk)
	};
	loff_t pos = 0;
	int rc;

	rc = dt_read(env, scrub->os_obj, &buf, &pos);
	/* failure */
	if (rc < 0) {
		CERROR("%s: fail to load scrub file: rc = %d\n",
		       scrub->os_name, rc);
		return rc;
	}

	/* empty */
	if (!rc)
		return -ENOENT;

	/* corrupted */
	if (rc < buf.lb_len) {
		CDEBUG(D_LFSCK, "%s: fail to load scrub file, "
		       "expected = %d: rc = %d\n",
		       scrub->os_name, (int)buf.lb_len, rc);
		return -EFAULT;
	}

	scrub_file_to_cpu(sf, &scrub->os_file_disk);
	if (sf->sf_magic != SCRUB_MAGIC_V1) {
		CDEBUG(D_LFSCK, "%s: invalid scrub magic 0x%x != 0x%x\n",
		       scrub->os_name, sf->sf_magic, SCRUB_MAGIC_V1);
		return -EFAULT;
	}

	return 0;
}
EXPORT_SYMBOL(scrub_file_load);

int scrub_file_store(const struct lu_env *env, struct lustre_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file_disk;
	struct dt_object *obj = scrub->os_obj;
	struct dt_device *dev = scrub_obj2dev(obj);
	struct lu_buf buf = {
		.lb_buf = sf,
		.lb_len = sizeof(*sf)
	};
	struct thandle *th;
	loff_t pos = 0;
	int rc;
	ENTRY;

	/* Skip store under rdonly mode. */
	if (dev->dd_rdonly)
		RETURN(0);

	scrub_file_to_le(sf, &scrub->os_file);
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(log, rc = PTR_ERR(th));

	rc = dt_declare_record_write(env, obj, &buf, pos, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_record_write(env, obj, &buf, &pos, th);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);

log:
	if (rc)
		CERROR("%s: store scrub file: rc = %d\n",
		       scrub->os_name, rc);
	else
		CDEBUG(D_LFSCK, "%s: store scrub file: rc = %d\n",
		       scrub->os_name, rc);

	scrub->os_time_last_checkpoint = cfs_time_current();
	scrub->os_time_next_checkpoint = scrub->os_time_last_checkpoint +
				cfs_time_seconds(SCRUB_CHECKPOINT_INTERVAL);
	return rc;
}
EXPORT_SYMBOL(scrub_file_store);

int scrub_checkpoint(const struct lu_env *env, struct lustre_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file;
	int rc;

	if (likely(cfs_time_before(cfs_time_current(),
				   scrub->os_time_next_checkpoint) ||
		   scrub->os_new_checked == 0))
		return 0;

	CDEBUG(D_LFSCK, "%s: OI scrub checkpoint at pos %llu\n",
	       scrub->os_name, scrub->os_pos_current);

	down_write(&scrub->os_rwsem);
	sf->sf_items_checked += scrub->os_new_checked;
	scrub->os_new_checked = 0;
	sf->sf_pos_last_checkpoint = scrub->os_pos_current;
	sf->sf_time_last_checkpoint = cfs_time_current_sec();
	sf->sf_run_time += cfs_duration_sec(cfs_time_current() + HALF_SEC -
					    scrub->os_time_last_checkpoint);
	rc = scrub_file_store(env, scrub);
	up_write(&scrub->os_rwsem);

	return rc;
}
EXPORT_SYMBOL(scrub_checkpoint);

int scrub_start(int (*threadfn)(void *data), struct lustre_scrub *scrub,
		void *data, __u32 flags)
{
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct l_wait_info lwi = { 0 };
	struct task_struct *task;
	int rc;
	ENTRY;

again:
	/* os_lock: sync status between stop and scrub thread */
	spin_lock(&scrub->os_lock);
	if (thread_is_running(thread)) {
		spin_unlock(&scrub->os_lock);
		RETURN(-EALREADY);
	}

	if (unlikely(thread_is_stopping(thread))) {
		spin_unlock(&scrub->os_lock);
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_stopped(thread),
			     &lwi);
		goto again;
	}
	spin_unlock(&scrub->os_lock);

	if (scrub->os_file.sf_status == SS_COMPLETED) {
		if (!(flags & SS_SET_FAILOUT))
			flags |= SS_CLEAR_FAILOUT;

		if (!(flags & SS_SET_DRYRUN))
			flags |= SS_CLEAR_DRYRUN;

		flags |= SS_RESET;
	}

	scrub->os_start_flags = flags;
	thread_set_flags(thread, 0);
	task = kthread_run(threadfn, data, "OI_scrub");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start iteration thread: rc = %d\n",
		       scrub->os_name, rc);
		RETURN(rc);
	}

	l_wait_event(thread->t_ctl_waitq,
		     thread_is_running(thread) || thread_is_stopped(thread),
		     &lwi);

	RETURN(0);
}
EXPORT_SYMBOL(scrub_start);

void scrub_stop(struct lustre_scrub *scrub)
{
	struct ptlrpc_thread *thread = &scrub->os_thread;
	struct l_wait_info lwi = { 0 };

	/* os_lock: sync status between stop and scrub thread */
	spin_lock(&scrub->os_lock);
	if (!thread_is_init(thread) && !thread_is_stopped(thread)) {
		thread_set_flags(thread, SVC_STOPPING);
		spin_unlock(&scrub->os_lock);
		wake_up_all(&thread->t_ctl_waitq);
		l_wait_event(thread->t_ctl_waitq,
			     thread_is_stopped(thread),
			     &lwi);
		/* Do not skip the last lock/unlock, which can guarantee that
		 * the caller cannot return until the OI scrub thread exit. */
		spin_lock(&scrub->os_lock);
	}
	spin_unlock(&scrub->os_lock);
}
EXPORT_SYMBOL(scrub_stop);

const char *scrub_status_names[] = {
	"init",
	"scanning",
	"completed",
	"failed",
	"stopped",
	"paused",
	"crashed",
	NULL
};

const char *scrub_flags_names[] = {
	"recreated",
	"inconsistent",
	"auto",
	"upgrade",
	NULL
};

const char *scrub_param_names[] = {
	"failout",
	"dryrun",
	NULL
};

static void scrub_bits_dump(struct seq_file *m, int bits, const char *names[],
			    const char *prefix)
{
	int flag;
	int i;

	seq_printf(m, "%s:%c", prefix, bits != 0 ? ' ' : '\n');

	for (i = 0, flag = 1; bits != 0; i++, flag = 1 << i) {
		if (flag & bits) {
			bits &= ~flag;
			seq_printf(m, "%s%c", names[i],
				   bits != 0 ? ',' : '\n');
		}
	}
}

static void scrub_time_dump(struct seq_file *m, __u64 time, const char *prefix)
{
	if (time != 0)
		seq_printf(m, "%s: %llu seconds\n", prefix,
			   cfs_time_current_sec() - time);
	else
		seq_printf(m, "%s: N/A\n", prefix);
}

static void scrub_pos_dump(struct seq_file *m, __u64 pos, const char *prefix)
{
	if (pos != 0)
		seq_printf(m, "%s: %llu\n", prefix, pos);
	else
		seq_printf(m, "%s: N/A\n", prefix);
}

void scrub_dump(struct seq_file *m, struct lustre_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file;
	__u64 checked;
	__u64 speed;

	down_read(&scrub->os_rwsem);
	seq_printf(m, "name: OI_scrub\n"
		   "magic: 0x%x\n"
		   "oi_files: %d\n"
		   "status: %s\n",
		   sf->sf_magic, (int)sf->sf_oi_count,
		   scrub_status_names[sf->sf_status]);

	scrub_bits_dump(m, sf->sf_flags, scrub_flags_names, "flags");

	scrub_bits_dump(m, sf->sf_param, scrub_param_names, "param");

	scrub_time_dump(m, sf->sf_time_last_complete,
			"time_since_last_completed");

	scrub_time_dump(m, sf->sf_time_latest_start,
			"time_since_latest_start");

	scrub_time_dump(m, sf->sf_time_last_checkpoint,
			"time_since_last_checkpoint");

	scrub_pos_dump(m, sf->sf_pos_latest_start,
			"latest_start_position");

	scrub_pos_dump(m, sf->sf_pos_last_checkpoint,
			"last_checkpoint_position");

	scrub_pos_dump(m, sf->sf_pos_first_inconsistent,
			"first_failure_position");

	checked = sf->sf_items_checked + scrub->os_new_checked;
	seq_printf(m, "checked: %llu\n"
		   "%s: %llu\n"
		   "failed: %llu\n"
		   "prior_%s: %llu\n"
		   "noscrub: %llu\n"
		   "igif: %llu\n"
		   "success_count: %u\n",
		   checked,
		   sf->sf_param & SP_DRYRUN ? "inconsistent" : "updated",
		   sf->sf_items_updated, sf->sf_items_failed,
		   sf->sf_param & SP_DRYRUN ? "inconsistent" : "updated",
		   sf->sf_items_updated_prior, sf->sf_items_noscrub,
		   sf->sf_items_igif, sf->sf_success_count);

	speed = checked;
	if (thread_is_running(&scrub->os_thread)) {
		cfs_duration_t duration = cfs_time_current() -
					  scrub->os_time_last_checkpoint;
		__u64 new_checked = msecs_to_jiffies(scrub->os_new_checked *
						     MSEC_PER_SEC);
		__u32 rtime = sf->sf_run_time +
			      cfs_duration_sec(duration + HALF_SEC);

		if (duration != 0)
			do_div(new_checked, duration);
		if (rtime != 0)
			do_div(speed, rtime);
		seq_printf(m, "run_time: %u seconds\n"
			   "average_speed: %llu objects/sec\n"
			   "real-time_speed: %llu objects/sec\n"
			   "current_position: %llu\n"
			   "scrub_in_prior: %s\n"
			   "scrub_full_speed: %s\n"
			   "partial_scan: %s\n",
			   rtime, speed, new_checked, scrub->os_pos_current,
			   scrub->os_in_prior ? "yes" : "no",
			   scrub->os_full_speed ? "yes" : "no",
			   scrub->os_partial_scan ? "yes" : "no");
	} else {
		if (sf->sf_run_time != 0)
			do_div(speed, sf->sf_run_time);
		seq_printf(m, "run_time: %u seconds\n"
			   "average_speed: %llu objects/sec\n"
			   "real-time_speed: N/A\n"
			   "current_position: N/A\n",
			   sf->sf_run_time, speed);
	}

	up_read(&scrub->os_rwsem);
}
EXPORT_SYMBOL(scrub_dump);
