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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/obdclass/lprocfs_status_server.c
 */

#define DEBUG_SUBSYSTEM S_CLASS


#include <obd_class.h>
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>
#include <lustre_nodemap.h>

#ifdef CONFIG_PROC_FS

int lprocfs_evict_client_open(struct inode *inode, struct file *f)
{
	struct obd_device *obd = PDE_DATA(file_inode(f));

	atomic_inc(&obd->obd_evict_inprogress);
	return 0;
}

int lprocfs_evict_client_release(struct inode *inode, struct file *f)
{
	struct obd_device *obd = PDE_DATA(file_inode(f));

	atomic_dec(&obd->obd_evict_inprogress);
	wake_up(&obd->obd_evict_inprogress_waitq);

	return 0;
}

#define BUFLEN (UUID_MAX + 5)

ssize_t
lprocfs_evict_client_seq_write(struct file *file, const char __user *buffer,
			       size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	char *tmpbuf, *kbuf;

	OBD_ALLOC(kbuf, BUFLEN);
	if (kbuf == NULL)
		return -ENOMEM;

	/*
	 * OBD_ALLOC() will zero kbuf, but we only copy BUFLEN - 1
	 * bytes into kbuf, to ensure that the string is NUL-terminated.
	 * UUID_MAX should include a trailing NUL already.
	 */
	if (copy_from_user(kbuf, buffer,
			   min_t(unsigned long, BUFLEN - 1, count))) {
		count = -EFAULT;
		goto out;
	}
	tmpbuf = cfs_firststr(kbuf, min_t(unsigned long, BUFLEN - 1, count));
	class_incref(obd, __func__, current);

	if (strncmp(tmpbuf, "nid:", 4) == 0)
		obd_export_evict_by_nid(obd, tmpbuf + 4);
	else if (strncmp(tmpbuf, "uuid:", 5) == 0)
		obd_export_evict_by_uuid(obd, tmpbuf + 5);
	else
		obd_export_evict_by_uuid(obd, tmpbuf);

	class_decref(obd, __func__, current);

out:
	OBD_FREE(kbuf, BUFLEN);
	return count;
}
EXPORT_SYMBOL(lprocfs_evict_client_seq_write);

#undef BUFLEN

int lprocfs_num_exports_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = data;

	LASSERT(obd != NULL);
	seq_printf(m, "%u\n", obd->obd_num_exports);
	return 0;
}
EXPORT_SYMBOL(lprocfs_num_exports_seq_show);

static void lprocfs_free_client_stats(struct nid_stat *client_stat)
{
	CDEBUG(D_CONFIG, "stat %p - data %p/%p\n", client_stat,
	       client_stat->nid_proc, client_stat->nid_stats);

	LASSERTF(atomic_read(&client_stat->nid_exp_ref_count) == 0,
		 "nid %s:count %d\n", libcfs_nid2str(client_stat->nid),
		 atomic_read(&client_stat->nid_exp_ref_count));

	if (client_stat->nid_proc)
		lprocfs_remove(&client_stat->nid_proc);

	if (client_stat->nid_stats)
		lprocfs_free_stats(&client_stat->nid_stats);

	if (client_stat->nid_ldlm_stats)
		lprocfs_free_stats(&client_stat->nid_ldlm_stats);

	OBD_FREE_PTR(client_stat);
	return;
}

void lprocfs_free_per_client_stats(struct obd_device *obd)
{
	struct cfs_hash *hash = obd->obd_nid_stats_hash;
	struct nid_stat *stat;
	ENTRY;

	/* we need extra list - because hash_exit called to early */
	/* not need locking because all clients is died */
	while (!list_empty(&obd->obd_nid_stats)) {
		stat = list_entry(obd->obd_nid_stats.next,
				  struct nid_stat, nid_list);
		list_del_init(&stat->nid_list);
		cfs_hash_del(hash, &stat->nid, &stat->nid_hash);
		lprocfs_free_client_stats(stat);
	}
	EXIT;
}
EXPORT_SYMBOL(lprocfs_free_per_client_stats);

static int
lprocfs_exp_print_uuid_seq(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			   struct hlist_node *hnode, void *cb_data)
{
	struct seq_file *m = cb_data;
	struct obd_export *exp = cfs_hash_object(hs, hnode);

	if (exp->exp_nid_stats != NULL)
		seq_printf(m, "%s\n", obd_uuid2str(&exp->exp_client_uuid));
	return 0;
}

static int
lprocfs_exp_print_nodemap_seq(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			      struct hlist_node *hnode, void *cb_data)
{
	struct seq_file *m = cb_data;
	struct obd_export *exp = cfs_hash_object(hs, hnode);
	struct lu_nodemap *nodemap = exp->exp_target_data.ted_nodemap;

	if (nodemap != NULL)
		seq_printf(m, "%s\n", nodemap->nm_name);
	return 0;
}

static int
lprocfs_exp_nodemap_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;
	struct obd_device *obd = stats->nid_obd;

	cfs_hash_for_each_key(obd->obd_nid_hash, &stats->nid,
			      lprocfs_exp_print_nodemap_seq, m);
	return 0;
}
LPROC_SEQ_FOPS_RO(lprocfs_exp_nodemap);

static int lprocfs_exp_uuid_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;
	struct obd_device *obd = stats->nid_obd;

	cfs_hash_for_each_key(obd->obd_nid_hash, &stats->nid,
				lprocfs_exp_print_uuid_seq, m);
	return 0;
}
LPROC_SEQ_FOPS_RO(lprocfs_exp_uuid);

static int
lprocfs_exp_print_hash_seq(struct cfs_hash *hs, struct cfs_hash_bd *bd,
			   struct hlist_node *hnode, void *cb_data)

{
	struct seq_file *m = cb_data;
	struct obd_export *exp = cfs_hash_object(hs, hnode);

	if (exp->exp_lock_hash != NULL) {
		cfs_hash_debug_header(m);
		cfs_hash_debug_str(hs, m);
	}
	return 0;
}

static int lprocfs_exp_hash_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;
	struct obd_device *obd = stats->nid_obd;

	cfs_hash_for_each_key(obd->obd_nid_hash, &stats->nid,
				lprocfs_exp_print_hash_seq, m);
	return 0;
}
LPROC_SEQ_FOPS_RO(lprocfs_exp_hash);

int lprocfs_exp_print_replydata_seq(struct cfs_hash *hs, struct cfs_hash_bd *bd,
				    struct hlist_node *hnode, void *cb_data)

{
	struct obd_export *exp = cfs_hash_object(hs, hnode);
	struct seq_file *m = cb_data;
	struct tg_export_data *ted = &exp->exp_target_data;

	seq_printf(m, "reply_cnt: %d\n"
		   "reply_max: %d\n"
		   "reply_released_by_xid: %d\n"
		   "reply_released_by_tag: %d\n\n",
		   ted->ted_reply_cnt,
		   ted->ted_reply_max,
		   ted->ted_release_xid,
		   ted->ted_release_tag);
	return 0;
}

int lprocfs_exp_replydata_seq_show(struct seq_file *m, void *data)
{
	struct nid_stat *stats = m->private;
	struct obd_device *obd = stats->nid_obd;

	cfs_hash_for_each_key(obd->obd_nid_hash, &stats->nid,
				lprocfs_exp_print_replydata_seq, m);
	return 0;
}
LPROC_SEQ_FOPS_RO(lprocfs_exp_replydata);

int lprocfs_nid_stats_clear_seq_show(struct seq_file *m, void *data)
{
	seq_puts(m, "Write into this file to clear all nid stats and stale nid entries\n");
	return 0;
}
EXPORT_SYMBOL(lprocfs_nid_stats_clear_seq_show);

static int lprocfs_nid_stats_clear_write_cb(void *obj, void *data)
{
	struct nid_stat *stat = obj;
	ENTRY;

	CDEBUG(D_INFO, "refcnt %d\n", atomic_read(&stat->nid_exp_ref_count));
	if (atomic_read(&stat->nid_exp_ref_count) == 1) {
		/* object has only hash references. */
		spin_lock(&stat->nid_obd->obd_nid_lock);
		list_move(&stat->nid_list, data);
		spin_unlock(&stat->nid_obd->obd_nid_lock);
		RETURN(1);
	}
	/* we has reference to object - only clear data*/
	if (stat->nid_stats)
		lprocfs_clear_stats(stat->nid_stats);

	RETURN(0);
}

ssize_t
lprocfs_nid_stats_clear_seq_write(struct file *file, const char __user *buffer,
					size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	struct nid_stat *client_stat;
	struct list_head free_list;

	INIT_LIST_HEAD(&free_list);
	cfs_hash_cond_del(obd->obd_nid_stats_hash,
			  lprocfs_nid_stats_clear_write_cb, &free_list);

	while (!list_empty(&free_list)) {
		client_stat = list_entry(free_list.next, struct nid_stat,
					 nid_list);
		list_del_init(&client_stat->nid_list);
		lprocfs_free_client_stats(client_stat);
	}
	return count;
}
EXPORT_SYMBOL(lprocfs_nid_stats_clear_seq_write);

int lprocfs_exp_setup(struct obd_export *exp, lnet_nid_t *nid)
{
	struct nid_stat *new_stat, *old_stat;
	struct obd_device *obd = NULL;
	struct proc_dir_entry *entry;
	char nidstr[LNET_NIDSTR_SIZE];
	int rc = 0;
	ENTRY;

	if (!exp || !exp->exp_obd || !exp->exp_obd->obd_proc_exports_entry ||
	    !exp->exp_obd->obd_nid_stats_hash)
		RETURN(-EINVAL);

	/* not test against zero because eric say:
	 * You may only test nid against another nid, or LNET_NID_ANY.
	 * Anything else is nonsense.*/
	if (nid == NULL || *nid == LNET_NID_ANY)
		RETURN(-EALREADY);

	libcfs_nid2str_r(*nid, nidstr, sizeof(nidstr));

	spin_lock(&exp->exp_lock);
	if (exp->exp_nid_stats != NULL) {
		spin_unlock(&exp->exp_lock);
		RETURN(-EALREADY);
	}
	spin_unlock(&exp->exp_lock);

	obd = exp->exp_obd;

	CDEBUG(D_CONFIG, "using hash %p\n", obd->obd_nid_stats_hash);

	OBD_ALLOC_PTR(new_stat);
	if (new_stat == NULL)
		RETURN(-ENOMEM);

	new_stat->nid     = *nid;
	new_stat->nid_obd = exp->exp_obd;
	/* we need set default refcount to 1 to balance obd_disconnect */
	atomic_set(&new_stat->nid_exp_ref_count, 1);

	old_stat = cfs_hash_findadd_unique(obd->obd_nid_stats_hash,
					   nid, &new_stat->nid_hash);
	CDEBUG(D_INFO, "Found stats %p for nid %s - ref %d\n",
	       old_stat, nidstr, atomic_read(&old_stat->nid_exp_ref_count));

	/* Return -EALREADY here so that we know that the /proc
	 * entry already has been created */
	if (old_stat != new_stat) {
		spin_lock(&exp->exp_lock);
		if (exp->exp_nid_stats) {
			LASSERT(exp->exp_nid_stats == old_stat);
			nidstat_putref(exp->exp_nid_stats);
		}
		exp->exp_nid_stats = old_stat;
		spin_unlock(&exp->exp_lock);
		GOTO(destroy_new, rc = -EALREADY);
	}
	/* not found - create */
	new_stat->nid_proc = lprocfs_register(nidstr,
					      obd->obd_proc_exports_entry,
					      NULL, NULL);

	if (IS_ERR(new_stat->nid_proc)) {
		rc = PTR_ERR(new_stat->nid_proc);
		new_stat->nid_proc = NULL;
		CERROR("%s: cannot create proc entry for export %s: rc = %d\n",
		       obd->obd_name, nidstr, rc);
		GOTO(destroy_new_ns, rc);
	}

	entry = lprocfs_add_simple(new_stat->nid_proc, "nodemap", new_stat,
				   &lprocfs_exp_nodemap_fops);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CWARN("Error adding the nodemap file: rc = %d\n", rc);
		GOTO(destroy_new_ns, rc);
	}

	entry = lprocfs_add_simple(new_stat->nid_proc, "uuid", new_stat,
				   &lprocfs_exp_uuid_fops);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CWARN("Error adding the NID stats file: rc = %d\n", rc);
		GOTO(destroy_new_ns, rc);
	}

	entry = lprocfs_add_simple(new_stat->nid_proc, "hash", new_stat,
				   &lprocfs_exp_hash_fops);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CWARN("Error adding the hash file: rc = %d\n", rc);
		GOTO(destroy_new_ns, rc);
	}

	entry = lprocfs_add_simple(new_stat->nid_proc, "reply_data", new_stat,
				   &lprocfs_exp_replydata_fops);
	if (IS_ERR(entry)) {
		rc = PTR_ERR(entry);
		CWARN("%s: Error adding the reply_data file: rc = %d\n",
		      obd->obd_name, rc);
		GOTO(destroy_new_ns, rc);
	}

	spin_lock(&exp->exp_lock);
	exp->exp_nid_stats = new_stat;
	spin_unlock(&exp->exp_lock);

	/* protect competitive add to list, not need locking on destroy */
	spin_lock(&obd->obd_nid_lock);
	list_add(&new_stat->nid_list, &obd->obd_nid_stats);
	spin_unlock(&obd->obd_nid_lock);

	RETURN(0);

destroy_new_ns:
	if (new_stat->nid_proc != NULL)
		lprocfs_remove(&new_stat->nid_proc);
	cfs_hash_del(obd->obd_nid_stats_hash, nid, &new_stat->nid_hash);

destroy_new:
	nidstat_putref(new_stat);
	OBD_FREE_PTR(new_stat);
	RETURN(rc);
}
EXPORT_SYMBOL(lprocfs_exp_setup);

int lprocfs_exp_cleanup(struct obd_export *exp)
{
	struct nid_stat *stat = exp->exp_nid_stats;

	if (!stat || !exp->exp_obd)
		RETURN(0);

	nidstat_putref(exp->exp_nid_stats);
	exp->exp_nid_stats = NULL;

	return 0;
}

#define LPROCFS_OBD_OP_INIT(base, stats, op)			\
do {								\
	unsigned int coffset = base + OBD_COUNTER_OFFSET(op);	\
	LASSERT(coffset < stats->ls_num);			\
	lprocfs_counter_init(stats, coffset, 0, #op, "reqs");	\
} while (0)

void lprocfs_init_ops_stats(int num_private_stats, struct lprocfs_stats *stats)
{
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, iocontrol);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, get_info);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, set_info_async);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, setup);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, precleanup);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, cleanup);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, process_config);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, postrecov);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, add_conn);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, del_conn);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, connect);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, reconnect);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, disconnect);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, fid_init);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, fid_fini);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, fid_alloc);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, statfs);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, statfs_async);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, create);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, destroy);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, setattr);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, getattr);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, preprw);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, commitrw);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, init_export);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, destroy_export);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, import_event);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, notify);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, health_check);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, get_uuid);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, quotactl);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, ping);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, pool_new);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, pool_rem);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, pool_add);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, pool_del);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, getref);
	LPROCFS_OBD_OP_INIT(num_private_stats, stats, putref);

	CLASSERT(NUM_OBD_STATS == OBD_COUNTER_OFFSET(putref) + 1);
}
EXPORT_SYMBOL(lprocfs_init_ops_stats);

int lprocfs_alloc_obd_stats(struct obd_device *obd, unsigned num_private_stats)
{
	struct lprocfs_stats *stats;
	unsigned int num_stats;
	int rc, i;

	LASSERT(obd->obd_stats == NULL);
	LASSERT(obd->obd_proc_entry != NULL);
	LASSERT(obd->obd_cntr_base == 0);

	num_stats = NUM_OBD_STATS + num_private_stats;
	stats = lprocfs_alloc_stats(num_stats, 0);
	if (stats == NULL)
		return -ENOMEM;

	lprocfs_init_ops_stats(num_private_stats, stats);

	for (i = num_private_stats; i < num_stats; i++) {
		/* If this LBUGs, it is likely that an obd
		 * operation was added to struct obd_ops in
		 * <obd.h>, and that the corresponding line item
		 * LPROCFS_OBD_OP_INIT(.., .., opname)
		 * is missing from the list above. */
		LASSERTF(stats->ls_cnt_header[i].lc_name != NULL,
			 "Missing obd_stat initializer obd_op "
			 "operation at offset %d.\n", i - num_private_stats);
	}
	rc = lprocfs_register_stats(obd->obd_proc_entry, "stats", stats);
	if (rc < 0) {
		lprocfs_free_stats(&stats);
	} else {
		obd->obd_stats  = stats;
		obd->obd_cntr_base = num_private_stats;
	}
	return rc;
}
EXPORT_SYMBOL(lprocfs_alloc_obd_stats);

void lprocfs_free_obd_stats(struct obd_device *obd)
{
	if (obd->obd_stats)
		lprocfs_free_stats(&obd->obd_stats);
}
EXPORT_SYMBOL(lprocfs_free_obd_stats);

int lprocfs_hash_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	if (obd == NULL)
		return 0;

	cfs_hash_debug_header(m);
	cfs_hash_debug_str(obd->obd_uuid_hash, m);
	cfs_hash_debug_str(obd->obd_nid_hash, m);
	cfs_hash_debug_str(obd->obd_nid_stats_hash, m);
	return 0;
}
EXPORT_SYMBOL(lprocfs_hash_seq_show);

int lprocfs_recovery_status_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct target_distribute_txn_data *tdtd;

	LASSERT(obd != NULL);

	seq_printf(m, "status: ");
	if (obd->obd_max_recoverable_clients == 0) {
		seq_printf(m, "INACTIVE\n");
		goto out;
	}

	/* sampled unlocked, but really... */
	if (obd->obd_recovering == 0) {
		seq_printf(m, "COMPLETE\n");
		seq_printf(m, "recovery_start: %lld\n",
			   (s64)obd->obd_recovery_start);
		seq_printf(m, "recovery_duration: %lld\n",
			   obd->obd_recovery_end ?
			   obd->obd_recovery_end - obd->obd_recovery_start :
			   ktime_get_real_seconds() - obd->obd_recovery_start);
		/* Number of clients that have completed recovery */
		seq_printf(m, "completed_clients: %d/%d\n",
			   obd->obd_max_recoverable_clients -
			   obd->obd_stale_clients,
			   obd->obd_max_recoverable_clients);
		seq_printf(m, "replayed_requests: %d\n",
			   obd->obd_replayed_requests);
		seq_printf(m, "last_transno: %lld\n",
			   obd->obd_next_recovery_transno - 1);
		seq_printf(m, "VBR: %s\n", obd->obd_version_recov ?
			   "ENABLED" : "DISABLED");
		seq_printf(m, "IR: %s\n", obd->obd_no_ir ?
			   "DISABLED" : "ENABLED");
		goto out;
	}

	tdtd = obd->u.obt.obt_lut->lut_tdtd;
	if (tdtd && tdtd->tdtd_show_update_logs_retrievers) {
		char *buf;
		int size = 0;
		int count = 0;

		buf = tdtd->tdtd_show_update_logs_retrievers(
			tdtd->tdtd_show_retrievers_cbdata,
			&size, &count);
		if (count > 0) {
			seq_printf(m, "WAITING\n");
			seq_printf(m, "non-ready MDTs: %s\n",
				   buf ? buf : "unknown (not enough RAM)");
			seq_printf(m, "recovery_start: %lld\n",
				   (s64)obd->obd_recovery_start);
			seq_printf(m, "time_waited: %lld\n",
				   (s64)(ktime_get_real_seconds() -
					 obd->obd_recovery_start));
		}

		if (buf != NULL)
			OBD_FREE(buf, size);

		if (likely(count > 0))
			goto out;
	}

	/* recovery won't start until the clients connect */
	if (obd->obd_recovery_start == 0) {
		seq_printf(m, "WAITING_FOR_CLIENTS\n");
		goto out;
	}

	seq_printf(m, "RECOVERING\n");
	seq_printf(m, "recovery_start: %lld\n", (s64)obd->obd_recovery_start);
	seq_printf(m, "time_remaining: %lld\n",
		   ktime_get_real_seconds() >=
		   obd->obd_recovery_start +
		   obd->obd_recovery_timeout ? 0 :
		   (s64)(obd->obd_recovery_start +
			 obd->obd_recovery_timeout -
			 ktime_get_real_seconds()));
	seq_printf(m, "connected_clients: %d/%d\n",
		   atomic_read(&obd->obd_connected_clients),
		   obd->obd_max_recoverable_clients);
	/* Number of clients that have completed recovery */
	seq_printf(m, "req_replay_clients: %d\n",
		   atomic_read(&obd->obd_req_replay_clients));
	seq_printf(m, "lock_repay_clients: %d\n",
		   atomic_read(&obd->obd_lock_replay_clients));
	seq_printf(m, "completed_clients: %d\n",
		   atomic_read(&obd->obd_connected_clients) -
		   atomic_read(&obd->obd_lock_replay_clients));
	seq_printf(m, "evicted_clients: %d\n", obd->obd_stale_clients);
	seq_printf(m, "replayed_requests: %d\n", obd->obd_replayed_requests);
	seq_printf(m, "queued_requests: %d\n",
		   obd->obd_requests_queued_for_recovery);
	seq_printf(m, "next_transno: %lld\n",
		   obd->obd_next_recovery_transno);
out:
	return 0;
}
EXPORT_SYMBOL(lprocfs_recovery_status_seq_show);

int lprocfs_ir_factor_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	seq_printf(m, "%d\n", obd->obd_recovery_ir_factor);
	return 0;
}
EXPORT_SYMBOL(lprocfs_ir_factor_seq_show);

ssize_t
lprocfs_ir_factor_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	int rc;
	__s64 val;

	LASSERT(obd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	if (val < OBD_IR_FACTOR_MIN || val > OBD_IR_FACTOR_MAX)
		return -EINVAL;

	obd->obd_recovery_ir_factor = val;
	return count;
}
EXPORT_SYMBOL(lprocfs_ir_factor_seq_write);

int lprocfs_checksum_dump_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	seq_printf(m, "%d\n", obd->obd_checksum_dump);
	return 0;
}
EXPORT_SYMBOL(lprocfs_checksum_dump_seq_show);

ssize_t
lprocfs_checksum_dump_seq_write(struct file *file, const char __user *buffer,
			    size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	int rc;
	__s64 val;

	LASSERT(obd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;

	obd->obd_checksum_dump = !!val;
	return count;
}
EXPORT_SYMBOL(lprocfs_checksum_dump_seq_write);

int lprocfs_recovery_time_soft_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	seq_printf(m, "%llu\n", obd->obd_recovery_timeout);
	return 0;
}
EXPORT_SYMBOL(lprocfs_recovery_time_soft_seq_show);

ssize_t
lprocfs_recovery_time_soft_seq_write(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	int rc;
	__s64 val;

	LASSERT(obd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	obd->obd_recovery_timeout = val;
	return count;
}
EXPORT_SYMBOL(lprocfs_recovery_time_soft_seq_write);

int lprocfs_recovery_time_hard_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;

	LASSERT(obd != NULL);
	seq_printf(m, "%lld\n", obd->obd_recovery_time_hard);
	return 0;
}
EXPORT_SYMBOL(lprocfs_recovery_time_hard_seq_show);

ssize_t
lprocfs_recovery_time_hard_seq_write(struct file *file,
				     const char __user *buffer,
				     size_t count, loff_t *off)
{
	struct seq_file *m = file->private_data;
	struct obd_device *obd = m->private;
	int rc;
	__s64 val;

	LASSERT(obd != NULL);
	rc = lprocfs_str_to_s64(buffer, count, &val);
	if (rc)
		return rc;
	if (val < 0 || val > INT_MAX)
		return -ERANGE;

	obd->obd_recovery_time_hard = val;
	return count;
}
EXPORT_SYMBOL(lprocfs_recovery_time_hard_seq_write);

int lprocfs_target_instance_seq_show(struct seq_file *m, void *data)
{
	struct obd_device *obd = m->private;
	struct obd_device_target *target = &obd->u.obt;

	LASSERT(obd != NULL);
	LASSERT(target->obt_magic == OBT_MAGIC);
	seq_printf(m, "%u\n", obd->u.obt.obt_instance);
	return 0;
}
EXPORT_SYMBOL(lprocfs_target_instance_seq_show);

#endif /* CONFIG_PROC_FS*/
