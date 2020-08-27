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
#include <lustre_fid.h>

static inline struct dt_device *scrub_obj2dev(struct dt_object *obj)
{
	return container_of_safe(obj->do_lu.lo_dev, struct dt_device,
				 dd_lu_dev);
}

static void scrub_file_to_cpu(struct scrub_file *des, struct scrub_file *src)
{
	uuid_copy(&des->sf_uuid, &src->sf_uuid);
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
	uuid_copy(&des->sf_uuid, &src->sf_uuid);
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

void scrub_file_init(struct lustre_scrub *scrub, uuid_t uuid)
{
	struct scrub_file *sf = &scrub->os_file;

	memset(sf, 0, sizeof(*sf));
	uuid_copy(&sf->sf_uuid, &uuid);
	sf->sf_magic = SCRUB_MAGIC_V1;
	sf->sf_status = SS_INIT;
}
EXPORT_SYMBOL(scrub_file_init);

void scrub_file_reset(struct lustre_scrub *scrub, uuid_t uuid, u64 flags)
{
	struct scrub_file *sf = &scrub->os_file;

	CDEBUG(D_LFSCK, "%s: reset OI scrub file, old flags = "
	       "%#llx, add flags = %#llx\n",
	       scrub->os_name, sf->sf_flags, flags);

	uuid_copy(&sf->sf_uuid, &uuid);
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

	scrub->os_time_last_checkpoint = ktime_get_seconds();
	scrub->os_time_next_checkpoint = scrub->os_time_last_checkpoint +
					 SCRUB_CHECKPOINT_INTERVAL;
	return rc;
}
EXPORT_SYMBOL(scrub_file_store);

int scrub_checkpoint(const struct lu_env *env, struct lustre_scrub *scrub)
{
	struct scrub_file *sf = &scrub->os_file;
	time64_t now = ktime_get_seconds();
	int rc;

	if (likely(now < scrub->os_time_next_checkpoint ||
		   scrub->os_new_checked == 0))
		return 0;

	CDEBUG(D_LFSCK, "%s: OI scrub checkpoint at pos %llu\n",
	       scrub->os_name, scrub->os_pos_current);

	down_write(&scrub->os_rwsem);
	sf->sf_items_checked += scrub->os_new_checked;
	scrub->os_new_checked = 0;
	sf->sf_pos_last_checkpoint = scrub->os_pos_current;
	sf->sf_time_last_checkpoint = ktime_get_real_seconds();
	sf->sf_run_time += now - scrub->os_time_last_checkpoint;
	rc = scrub_file_store(env, scrub);
	up_write(&scrub->os_rwsem);

	return rc;
}
EXPORT_SYMBOL(scrub_checkpoint);

int scrub_start(int (*threadfn)(void *data), struct lustre_scrub *scrub,
		void *data, __u32 flags)
{
	struct task_struct *task;
	int rc;
	ENTRY;

	if (scrub->os_task)
		RETURN(-EALREADY);

	if (scrub->os_file.sf_status == SS_COMPLETED) {
		if (!(flags & SS_SET_FAILOUT))
			flags |= SS_CLEAR_FAILOUT;

		if (!(flags & SS_SET_DRYRUN))
			flags |= SS_CLEAR_DRYRUN;

		flags |= SS_RESET;
	}

	task = kthread_create(threadfn, data, "OI_scrub");
	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start iteration thread: rc = %d\n",
		       scrub->os_name, rc);
		RETURN(rc);
	}
	spin_lock(&scrub->os_lock);
	if (scrub->os_task) {
		/* Lost a race */
		spin_unlock(&scrub->os_lock);
		kthread_stop(task);
		RETURN(-EALREADY);
	}
	scrub->os_start_flags = flags;
	scrub->os_task = task;
	wake_up_process(task);
	spin_unlock(&scrub->os_lock);
	wait_var_event(scrub, scrub->os_running || !scrub->os_task);

	RETURN(0);
}
EXPORT_SYMBOL(scrub_start);

void scrub_stop(struct lustre_scrub *scrub)
{
	struct task_struct *task;

	spin_lock(&scrub->os_lock);
	scrub->os_running = 0;
	spin_unlock(&scrub->os_lock);
	task = xchg(&scrub->os_task, NULL);
	if (task)
		kthread_stop(task);
}
EXPORT_SYMBOL(scrub_stop);

const char *const scrub_status_names[] = {
	"init",
	"scanning",
	"completed",
	"failed",
	"stopped",
	"paused",
	"crashed",
	NULL
};

const char *const scrub_flags_names[] = {
	"recreated",
	"inconsistent",
	"auto",
	"upgrade",
	NULL
};

const char *const scrub_param_names[] = {
	"failout",
	"dryrun",
	NULL
};

static void scrub_bits_dump(struct seq_file *m, int bits,
			    const char *const names[],
			    const char *prefix)
{
	int flag;
	int i;

	seq_printf(m, "%s:%c", prefix, bits != 0 ? ' ' : '\n');

	for (i = 0, flag = 1; bits != 0; i++, flag = BIT(i)) {
		if (flag & bits) {
			bits &= ~flag;
			seq_printf(m, "%s%c", names[i],
				   bits != 0 ? ',' : '\n');
		}
	}
}

static void scrub_time_dump(struct seq_file *m, time64_t time,
			    const char *prefix)
{
	if (time != 0)
		seq_printf(m, "%s: %llu seconds\n", prefix,
			   ktime_get_real_seconds() - time);
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
	u64 checked;
	s64 speed;

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
	if (scrub->os_running) {
		s64 new_checked = scrub->os_new_checked;
		time64_t duration;
		time64_t rtime;

		/* Since the time resolution is in seconds for new system
		 * or small devices it ismore likely that duration will be
		 * zero which will lead to inaccurate results.
		 */
		duration = ktime_get_seconds() -
			   scrub->os_time_last_checkpoint;
		if (duration != 0)
			new_checked = div_s64(new_checked, duration);

		rtime = sf->sf_run_time + duration;
		if (rtime != 0)
			speed = div_s64(speed, rtime);

		seq_printf(m, "run_time: %lld seconds\n"
			   "average_speed: %lld objects/sec\n"
			   "real_time_speed: %lld objects/sec\n"
			   "current_position: %llu\n"
			   "scrub_in_prior: %s\n"
			   "scrub_full_speed: %s\n"
			   "partial_scan: %s\n",
			   rtime, speed, new_checked,
			   scrub->os_pos_current,
			   scrub->os_in_prior ? "yes" : "no",
			   scrub->os_full_speed ? "yes" : "no",
			   scrub->os_partial_scan ? "yes" : "no");
	} else {
		if (sf->sf_run_time != 0)
			speed = div_s64(speed, sf->sf_run_time);
		seq_printf(m, "run_time: %d seconds\n"
			   "average_speed: %lld objects/sec\n"
			   "real_time_speed: N/A\n"
			   "current_position: N/A\n",
			   sf->sf_run_time, speed);
	}

	up_read(&scrub->os_rwsem);
}
EXPORT_SYMBOL(scrub_dump);

int lustre_liru_new(struct list_head *head, const struct lu_fid *pfid,
		    const struct lu_fid *cfid, __u64 child,
		    const char *name, int namelen)
{
	struct lustre_index_restore_unit *liru;
	int len = sizeof(*liru) + namelen + 1;

	OBD_ALLOC(liru, len);
	if (!liru)
		return -ENOMEM;

	INIT_LIST_HEAD(&liru->liru_link);
	liru->liru_pfid = *pfid;
	liru->liru_cfid = *cfid;
	liru->liru_clid = child;
	liru->liru_len = len;
	memcpy(liru->liru_name, name, namelen);
	liru->liru_name[namelen] = 0;
	list_add_tail(&liru->liru_link, head);

	return 0;
}
EXPORT_SYMBOL(lustre_liru_new);

int lustre_index_register(struct dt_device *dev, const char *devname,
			  struct list_head *head, spinlock_t *lock, int *guard,
			  const struct lu_fid *fid,
			  __u32 keysize, __u32 recsize)
{
	struct lustre_index_backup_unit *libu, *pos;
	int rc = 0;
	ENTRY;

	if (dev->dd_rdonly || *guard)
		RETURN(1);

	OBD_ALLOC_PTR(libu);
	if (!libu)
		RETURN(-ENOMEM);

	INIT_LIST_HEAD(&libu->libu_link);
	libu->libu_keysize = keysize;
	libu->libu_recsize = recsize;
	libu->libu_fid = *fid;

	spin_lock(lock);
	if (unlikely(*guard)) {
		spin_unlock(lock);
		OBD_FREE_PTR(libu);

		RETURN(1);
	}

	list_for_each_entry_reverse(pos, head, libu_link) {
		rc = lu_fid_cmp(&pos->libu_fid, fid);
		if (rc < 0) {
			list_add(&libu->libu_link, &pos->libu_link);
			spin_unlock(lock);

			RETURN(0);
		}

		if (!rc) {
			/* Registered already. But the former registered one
			 * has different keysize/recsize. It may because that
			 * the former values are from disk and corrupted, then
			 * replace it with new values. */
			if (unlikely(keysize != pos->libu_keysize ||
				     recsize != pos->libu_recsize)) {
				CWARN("%s: the index "DFID" has registered "
				      "with %u/%u, may be invalid, replace "
				      "with %u/%u\n",
				      devname, PFID(fid), pos->libu_keysize,
				      pos->libu_recsize, keysize, recsize);

				pos->libu_keysize = keysize;
				pos->libu_recsize = recsize;
			} else {
				rc = 1;
			}

			spin_unlock(lock);
			OBD_FREE_PTR(libu);

			RETURN(rc);
		}
	}

	list_add(&libu->libu_link, head);
	spin_unlock(lock);

	RETURN(0);
}
EXPORT_SYMBOL(lustre_index_register);

static void lustre_index_degister(struct list_head *head, spinlock_t *lock,
				  const struct lu_fid *fid)
{
	struct lustre_index_backup_unit *libu;
	int rc = -ENOENT;

	spin_lock(lock);
	list_for_each_entry_reverse(libu, head, libu_link) {
		rc = lu_fid_cmp(&libu->libu_fid, fid);
		/* NOT registered. */
		if (rc < 0)
			break;

		if (!rc) {
			list_del(&libu->libu_link);
			break;
		}
	}
	spin_unlock(lock);

	if (!rc)
		OBD_FREE_PTR(libu);
}

static void
lustre_index_backup_make_header(struct lustre_index_backup_header *header,
				__u32 keysize, __u32 recsize,
				const struct lu_fid *fid, __u32 count)
{
	memset(header, 0, sizeof(*header));
	header->libh_magic = cpu_to_le32(INDEX_BACKUP_MAGIC_V1);
	header->libh_count = cpu_to_le32(count);
	header->libh_keysize = cpu_to_le32(keysize);
	header->libh_recsize = cpu_to_le32(recsize);
	fid_cpu_to_le(&header->libh_owner, fid);
}

static int lustre_index_backup_body(const struct lu_env *env,
				    struct dt_object *obj, loff_t *pos,
				    void *buf, int bufsize)
{
	struct dt_device *dev = lu2dt_dev(obj->do_lu.lo_dev);
	struct thandle *th;
	struct lu_buf lbuf = {
		.lb_buf = buf,
		.lb_len = bufsize
	};
	int rc;
	ENTRY;

	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, obj, &lbuf, *pos, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_record_write(env, obj, &lbuf, pos, th);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);
	return rc;
}

static int lustre_index_backup_header(const struct lu_env *env,
				      struct dt_object *obj,
				      const struct lu_fid *tgt_fid,
				      __u32 keysize, __u32 recsize,
				      void *buf, int bufsize, int count)
{
	struct dt_device *dev = lu2dt_dev(obj->do_lu.lo_dev);
	struct lustre_index_backup_header *header = buf;
	struct lu_attr *la = buf;
	struct thandle *th;
	struct lu_buf lbuf = {
		.lb_buf = header,
		.lb_len = sizeof(*header)
	};
	loff_t size = sizeof(*header) + (keysize + recsize) * count;
	loff_t pos = 0;
	int rc;
	bool punch = false;
	ENTRY;

	LASSERT(sizeof(*la) <= bufsize);
	LASSERT(sizeof(*header) <= bufsize);

	rc = dt_attr_get(env, obj, la);
	if (rc)
		RETURN(rc);

	if (la->la_size > size)
		punch = true;

	lustre_index_backup_make_header(header, keysize, recsize,
					tgt_fid, count);
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(PTR_ERR(th));

	rc = dt_declare_record_write(env, obj, &lbuf, pos, th);
	if (rc)
		GOTO(stop, rc);

	if (punch) {
		rc = dt_declare_punch(env, obj, size, OBD_OBJECT_EOF, th);
		if (rc)
			GOTO(stop, rc);
	}

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_record_write(env, obj, &lbuf, &pos, th);
	if (!rc && punch)
		rc = dt_punch(env, obj, size, OBD_OBJECT_EOF, th);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);
	return rc;
}

static int lustre_index_update_lma(const struct lu_env *env,
				   struct dt_object *obj,
				   void *buf, int bufsize)
{
	struct dt_device *dev = lu2dt_dev(obj->do_lu.lo_dev);
	struct lustre_mdt_attrs *lma = buf;
	struct lu_buf lbuf = {
		.lb_buf = lma,
		.lb_len = sizeof(struct lustre_ost_attrs)
	};
	struct thandle *th;
	int fl = LU_XATTR_REPLACE;
	int rc;
	ENTRY;

	LASSERT(bufsize >= lbuf.lb_len);

	rc = dt_xattr_get(env, obj, &lbuf, XATTR_NAME_LMA);
	if (unlikely(rc == -ENODATA)) {
		fl = LU_XATTR_CREATE;
		lustre_lma_init(lma, lu_object_fid(&obj->do_lu),
				LMAC_IDX_BACKUP, 0);
		rc = sizeof(*lma);
	} else if (rc < sizeof(*lma)) {
		RETURN(rc < 0 ? rc : -EFAULT);
	} else {
		lustre_lma_swab(lma);
		if (lma->lma_compat & LMAC_IDX_BACKUP)
			RETURN(0);

		lma->lma_compat |= LMAC_IDX_BACKUP;
	}

	lustre_lma_swab(lma);
	lbuf.lb_len = rc;
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		RETURN(rc);

	rc = dt_declare_xattr_set(env, obj, &lbuf, XATTR_NAME_LMA, fl, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_xattr_set(env, obj, &lbuf, XATTR_NAME_LMA, fl, th);

	GOTO(stop, rc);

stop:
	dt_trans_stop(env, dev, th);
	return rc;
}

static int lustre_index_backup_one(const struct lu_env *env,
				   struct local_oid_storage *los,
				   struct dt_object *parent,
				   struct lustre_index_backup_unit *libu,
				   char *buf, int bufsize)
{
	struct dt_device *dev = scrub_obj2dev(parent);
	struct dt_object *tgt_obj = NULL;
	struct dt_object *bak_obj = NULL;
	const struct dt_it_ops *iops;
	struct dt_it *di;
	loff_t pos = sizeof(struct lustre_index_backup_header);
	int count = 0;
	int size = 0;
	int rc;
	ENTRY;

	tgt_obj = lu2dt(lu_object_find_slice(env, &dev->dd_lu_dev,
					     &libu->libu_fid, NULL));
	if (IS_ERR_OR_NULL(tgt_obj))
		GOTO(out, rc = tgt_obj ? PTR_ERR(tgt_obj) : -ENOENT);

	if (!dt_object_exists(tgt_obj))
		GOTO(out, rc = 0);

	if (!tgt_obj->do_index_ops) {
		struct dt_index_features feat;

		feat.dif_flags = DT_IND_UPDATE;
		feat.dif_keysize_min = libu->libu_keysize;
		feat.dif_keysize_max = libu->libu_keysize;
		feat.dif_recsize_min = libu->libu_recsize;
		feat.dif_recsize_max = libu->libu_recsize;
		feat.dif_ptrsize = 4;
		rc = tgt_obj->do_ops->do_index_try(env, tgt_obj, &feat);
		if (rc)
			GOTO(out, rc);
	}

	lustre_fid2lbx(buf, &libu->libu_fid, bufsize);
	bak_obj = local_file_find_or_create(env, los, parent, buf,
					    S_IFREG | S_IRUGO | S_IWUSR);
	if (IS_ERR_OR_NULL(bak_obj))
		GOTO(out, rc = bak_obj ? PTR_ERR(bak_obj) : -ENOENT);

	iops = &tgt_obj->do_index_ops->dio_it;
	di = iops->init(env, tgt_obj, 0);
	if (IS_ERR(di))
		GOTO(out, rc = PTR_ERR(di));

	rc = iops->load(env, di, 0);
	if (!rc)
		rc = iops->next(env, di);
	else if (rc > 0)
		rc = 0;

	while (!rc) {
		void *key;
		void *rec;

		key = iops->key(env, di);
		memcpy(&buf[size], key, libu->libu_keysize);
		size += libu->libu_keysize;
		rec = &buf[size];
		rc = iops->rec(env, di, rec, 0);
		if (rc)
			GOTO(fini, rc);

		size += libu->libu_recsize;
		count++;
		if (size + libu->libu_keysize + libu->libu_recsize > bufsize) {
			rc = lustre_index_backup_body(env, bak_obj, &pos,
						      buf, size);
			if (rc)
				GOTO(fini, rc);

			size = 0;
		}

		rc = iops->next(env, di);
	}

	if (rc >= 0 && size > 0)
		rc = lustre_index_backup_body(env, bak_obj, &pos, buf, size);

	if (rc < 0)
		GOTO(fini, rc);

	rc = lustre_index_backup_header(env, bak_obj, &libu->libu_fid,
					libu->libu_keysize, libu->libu_recsize,
					buf, bufsize, count);
	if (!rc)
		rc = lustre_index_update_lma(env, tgt_obj, buf, bufsize);

	if (!rc && OBD_FAIL_CHECK(OBD_FAIL_OSD_INDEX_CRASH)) {
		LASSERT(bufsize >= 512);

		pos = 0;
		memset(buf, 0, 512);
		lustre_index_backup_body(env, tgt_obj, &pos, buf, 512);
	}

	GOTO(fini, rc);

fini:
	iops->fini(env, di);
out:
	if (!IS_ERR_OR_NULL(tgt_obj))
		dt_object_put_nocache(env, tgt_obj);
	if (!IS_ERR_OR_NULL(bak_obj))
		dt_object_put_nocache(env, bak_obj);
	return rc;
}

void lustre_index_backup(const struct lu_env *env, struct dt_device *dev,
			 const char *devname, struct list_head *head,
			 spinlock_t *lock, int *guard, bool backup)
{
	struct lustre_index_backup_unit *libu;
	struct local_oid_storage *los = NULL;
	struct dt_object *parent = NULL;
	char *buf = NULL;
	struct lu_fid fid;
	int rc;
	ENTRY;

	if (dev->dd_rdonly || *guard)
		RETURN_EXIT;

	spin_lock(lock);
	*guard = 1;
	spin_unlock(lock);

	if (list_empty(head))
		RETURN_EXIT;

	/* Handle kinds of failures during mount process. */
	if (!dev->dd_lu_dev.ld_site || !dev->dd_lu_dev.ld_site->ls_top_dev)
		backup = false;

	if (backup) {
		OBD_ALLOC_LARGE(buf, INDEX_BACKUP_BUFSIZE);
		if (!buf) {
			backup = false;
			goto scan;
		}

		lu_local_obj_fid(&fid, INDEX_BACKUP_OID);
		parent = lu2dt(lu_object_find_slice(env, &dev->dd_lu_dev,
						    &fid, NULL));
		if (IS_ERR_OR_NULL(parent)) {
			CERROR("%s: failed to locate backup dir: rc = %ld\n",
			       devname, parent ? PTR_ERR(parent) : -ENOENT);
			backup = false;
			goto scan;
		}

		lu_local_name_obj_fid(&fid, 1);
		rc = local_oid_storage_init(env, dev, &fid, &los);
		if (rc) {
			CERROR("%s: failed to init local storage: rc = %d\n",
			       devname, rc);
			backup = false;
		}
	}

scan:
	spin_lock(lock);
	while (!list_empty(head)) {
		libu = list_entry(head->next,
				  struct lustre_index_backup_unit, libu_link);
		list_del_init(&libu->libu_link);
		spin_unlock(lock);

		if (backup) {
			rc = lustre_index_backup_one(env, los, parent, libu,
						     buf, INDEX_BACKUP_BUFSIZE);
			CDEBUG(D_WARNING, "%s: backup index "DFID": rc = %d\n",
			       devname, PFID(&libu->libu_fid), rc);
		}

		OBD_FREE_PTR(libu);
		spin_lock(lock);
	}
	spin_unlock(lock);

	if (los)
		local_oid_storage_fini(env, los);
	if (parent)
		dt_object_put_nocache(env, parent);
	if (buf)
		OBD_FREE_LARGE(buf, INDEX_BACKUP_BUFSIZE);

	EXIT;
}
EXPORT_SYMBOL(lustre_index_backup);

int lustre_index_restore(const struct lu_env *env, struct dt_device *dev,
			 const struct lu_fid *parent_fid,
			 const struct lu_fid *tgt_fid,
			 const struct lu_fid *bak_fid, const char *name,
			 struct list_head *head, spinlock_t *lock,
			 char *buf, int bufsize)
{
	struct dt_object *parent_obj = NULL;
	struct dt_object *tgt_obj = NULL;
	struct dt_object *bak_obj = NULL;
	struct lustre_index_backup_header *header;
	struct dt_index_features *feat;
	struct dt_object_format *dof;
	struct lu_attr *la;
	struct thandle *th;
	struct lu_object_conf conf;
	struct dt_insert_rec ent;
	struct lu_buf lbuf;
	struct lu_fid tfid;
	loff_t pos = 0;
	__u32 keysize;
	__u32 recsize;
	__u32 pairsize;
	int count;
	int rc;
	bool registered = false;
	ENTRY;

	LASSERT(bufsize >= sizeof(*la) + sizeof(*dof) +
		sizeof(*feat) + sizeof(*header));

	memset(buf, 0, bufsize);
	la = (struct lu_attr *)buf;
	dof = (void *)la + sizeof(*la);
	feat = (void *)dof + sizeof(*dof);
	header = (void *)feat + sizeof(*feat);
	lbuf.lb_buf = header;
	lbuf.lb_len = sizeof(*header);

	tgt_obj = lu2dt(lu_object_find_slice(env, &dev->dd_lu_dev,
					     tgt_fid, NULL));
	if (IS_ERR_OR_NULL(tgt_obj))
		GOTO(out, rc = tgt_obj ? PTR_ERR(tgt_obj) : -ENOENT);

	bak_obj = lu2dt(lu_object_find_slice(env, &dev->dd_lu_dev,
					     bak_fid, NULL));
	if (IS_ERR_OR_NULL(bak_obj))
		GOTO(out, rc = bak_obj ? PTR_ERR(bak_obj) : -ENOENT);

	if (!dt_object_exists(bak_obj))
		GOTO(out, rc = -ENOENT);

	parent_obj = lu2dt(lu_object_find_slice(env, &dev->dd_lu_dev,
						parent_fid, NULL));
	if (IS_ERR_OR_NULL(parent_obj))
		GOTO(out, rc = parent_obj ? PTR_ERR(parent_obj) : -ENOENT);

	LASSERT(dt_object_exists(parent_obj));

	if (unlikely(!dt_try_as_dir(env, parent_obj)))
		GOTO(out, rc = -ENOTDIR);

	rc = dt_attr_get(env, tgt_obj, la);
	if (rc)
		GOTO(out, rc);

	rc = dt_record_read(env, bak_obj, &lbuf, &pos);
	if (rc)
		GOTO(out, rc);

	if (le32_to_cpu(header->libh_magic) != INDEX_BACKUP_MAGIC_V1)
		GOTO(out, rc = -EINVAL);

	fid_le_to_cpu(&tfid, &header->libh_owner);
	if (unlikely(!lu_fid_eq(tgt_fid, &tfid)))
		GOTO(out, rc = -EINVAL);

	keysize = le32_to_cpu(header->libh_keysize);
	recsize = le32_to_cpu(header->libh_recsize);
	pairsize = keysize + recsize;

	memset(feat, 0, sizeof(*feat));
	feat->dif_flags = DT_IND_UPDATE;
	feat->dif_keysize_min = feat->dif_keysize_max = keysize;
	feat->dif_recsize_min = feat->dif_recsize_max = recsize;
	feat->dif_ptrsize = 4;

	/* T1: remove old name entry and destroy old index. */
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_delete(env, parent_obj,
			       (const struct dt_key *)name, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_ref_del(env, tgt_obj, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_destroy(env, tgt_obj, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_delete(env, parent_obj, (const struct dt_key *)name, th);
	if (rc)
		GOTO(stop, rc);

	dt_write_lock(env, tgt_obj, 0);
	rc = dt_ref_del(env, tgt_obj, th);
	if (rc == 0) {
		if (S_ISDIR(tgt_obj->do_lu.lo_header->loh_attr))
			dt_ref_del(env, tgt_obj, th);
		rc = dt_destroy(env, tgt_obj, th);
	}
	dt_write_unlock(env, tgt_obj);
	dt_trans_stop(env, dev, th);
	if (rc)
		GOTO(out, rc);

	la->la_valid = LA_MODE | LA_UID | LA_GID;
	conf.loc_flags = LOC_F_NEW;
	dof->u.dof_idx.di_feat = feat;
	dof->dof_type = DFT_INDEX;
	ent.rec_type = S_IFREG;
	ent.rec_fid = tgt_fid;

	/* Drop cache before re-create it. */
	dt_object_put_nocache(env, tgt_obj);
	tgt_obj = lu2dt(lu_object_find_slice(env, &dev->dd_lu_dev,
					     tgt_fid, &conf));
	if (IS_ERR_OR_NULL(tgt_obj))
		GOTO(out, rc = tgt_obj ? PTR_ERR(tgt_obj) : -ENOENT);

	LASSERT(!dt_object_exists(tgt_obj));

	/* T2: create new index and insert new name entry. */
	th = dt_trans_create(env, dev);
	if (IS_ERR(th))
		GOTO(out, rc = PTR_ERR(th));

	rc = dt_declare_create(env, tgt_obj, la, NULL, dof, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_declare_insert(env, parent_obj, (const struct dt_rec *)&ent,
			       (const struct dt_key *)name, th);
	if (rc)
		GOTO(stop, rc);

	rc = dt_trans_start_local(env, dev, th);
	if (rc)
		GOTO(stop, rc);

	dt_write_lock(env, tgt_obj, 0);
	rc = dt_create(env, tgt_obj, la, NULL, dof, th);
	dt_write_unlock(env, tgt_obj);
	if (rc)
		GOTO(stop, rc);

	rc = dt_insert(env, parent_obj, (const struct dt_rec *)&ent,
		       (const struct dt_key *)name, th);
	dt_trans_stop(env, dev, th);
	/* Some index name may has been inserted by OSD
	 * automatically when create the index object. */
	if (unlikely(rc == -EEXIST))
		rc = 0;
	if (rc)
		GOTO(out, rc);

	/* The new index will register via index_try. */
	rc = tgt_obj->do_ops->do_index_try(env, tgt_obj, feat);
	if (rc)
		GOTO(out, rc);

	registered = true;
	count = le32_to_cpu(header->libh_count);
	while (!rc && count > 0) {
		int size = pairsize * count;
		int items = count;
		int i;

		if (size > bufsize) {
			items = bufsize / pairsize;
			size = pairsize * items;
		}

		lbuf.lb_buf = buf;
		lbuf.lb_len = size;
		rc = dt_record_read(env, bak_obj, &lbuf, &pos);
		for (i = 0; i < items && !rc; i++) {
			void *key = &buf[i * pairsize];
			void *rec = &buf[i * pairsize + keysize];

			/* Tn: restore the records. */
			th = dt_trans_create(env, dev);
			if (!th)
				GOTO(out, rc = -ENOMEM);

			rc = dt_declare_insert(env, tgt_obj, rec, key, th);
			if (rc)
				GOTO(stop, rc);

			rc = dt_trans_start_local(env, dev, th);
			if (rc)
				GOTO(stop, rc);

			rc = dt_insert(env, tgt_obj, rec, key, th);
			if (unlikely(rc == -EEXIST))
				rc = 0;

			dt_trans_stop(env, dev, th);
		}

		count -= items;
	}

	GOTO(out, rc);

stop:
	dt_trans_stop(env, dev, th);
	if (rc && registered)
		/* Degister the index to avoid overwriting the backup. */
		lustre_index_degister(head, lock, tgt_fid);

out:
	if (!IS_ERR_OR_NULL(tgt_obj))
		dt_object_put_nocache(env, tgt_obj);
	if (!IS_ERR_OR_NULL(bak_obj))
		dt_object_put_nocache(env, bak_obj);
	if (!IS_ERR_OR_NULL(parent_obj))
		dt_object_put_nocache(env, parent_obj);
	return rc;
}
EXPORT_SYMBOL(lustre_index_restore);
