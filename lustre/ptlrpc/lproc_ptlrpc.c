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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */
#define DEBUG_SUBSYSTEM S_CLASS

#ifndef __KERNEL__
# include <liblustre.h>
#endif

#include <obd_support.h>
#include <obd.h>
#include <lprocfs_status.h>
#include <lustre/lustre_idl.h>
#include <lustre_net.h>
#include <obd_class.h>
#include "ptlrpc_internal.h"


struct ll_rpc_opcode {
     __u32       opcode;
     const char *opname;
} ll_rpc_opcode_table[LUSTRE_MAX_OPCODES] = {
        { OST_REPLY,        "ost_reply" },
        { OST_GETATTR,      "ost_getattr" },
        { OST_SETATTR,      "ost_setattr" },
        { OST_READ,         "ost_read" },
        { OST_WRITE,        "ost_write" },
        { OST_CREATE ,      "ost_create" },
        { OST_DESTROY,      "ost_destroy" },
        { OST_GET_INFO,     "ost_get_info" },
        { OST_CONNECT,      "ost_connect" },
        { OST_DISCONNECT,   "ost_disconnect" },
        { OST_PUNCH,        "ost_punch" },
        { OST_OPEN,         "ost_open" },
        { OST_CLOSE,        "ost_close" },
        { OST_STATFS,       "ost_statfs" },
        { 14,                NULL },    /* formerly OST_SAN_READ */
        { 15,                NULL },    /* formerly OST_SAN_WRITE */
        { OST_SYNC,         "ost_sync" },
        { OST_SET_INFO,     "ost_set_info" },
        { OST_QUOTACHECK,   "ost_quotacheck" },
        { OST_QUOTACTL,     "ost_quotactl" },
        { OST_QUOTA_ADJUST_QUNIT, "ost_quota_adjust_qunit" },
        { MDS_GETATTR,      "mds_getattr" },
        { MDS_GETATTR_NAME, "mds_getattr_lock" },
        { MDS_CLOSE,        "mds_close" },
        { MDS_REINT,        "mds_reint" },
        { MDS_READPAGE,     "mds_readpage" },
        { MDS_CONNECT,      "mds_connect" },
        { MDS_DISCONNECT,   "mds_disconnect" },
        { MDS_GETSTATUS,    "mds_getstatus" },
        { MDS_STATFS,       "mds_statfs" },
        { MDS_PIN,          "mds_pin" },
        { MDS_UNPIN,        "mds_unpin" },
        { MDS_SYNC,         "mds_sync" },
        { MDS_DONE_WRITING, "mds_done_writing" },
        { MDS_SET_INFO,     "mds_set_info" },
        { MDS_QUOTACHECK,   "mds_quotacheck" },
        { MDS_QUOTACTL,     "mds_quotactl" },
        { MDS_GETXATTR,     "mds_getxattr" },
        { MDS_SETXATTR,     "mds_setxattr" },
        { MDS_WRITEPAGE,    "mds_writepage" },
        { MDS_IS_SUBDIR,    "mds_is_subdir" },
        { MDS_GET_INFO,     "mds_get_info" },
        { LDLM_ENQUEUE,     "ldlm_enqueue" },
        { LDLM_CONVERT,     "ldlm_convert" },
        { LDLM_CANCEL,      "ldlm_cancel" },
        { LDLM_BL_CALLBACK, "ldlm_bl_callback" },
        { LDLM_CP_CALLBACK, "ldlm_cp_callback" },
        { LDLM_GL_CALLBACK, "ldlm_gl_callback" },
        { LDLM_SET_INFO,    "ldlm_set_info" },
        { MGS_CONNECT,      "mgs_connect" },
        { MGS_DISCONNECT,   "mgs_disconnect" },
        { MGS_EXCEPTION,    "mgs_exception" },
        { MGS_TARGET_REG,   "mgs_target_reg" },
        { MGS_TARGET_DEL,   "mgs_target_del" },
        { MGS_SET_INFO,     "mgs_set_info" },
        { MGS_CONFIG_READ,  "mgs_config_read" },
        { OBD_PING,         "obd_ping" },
        { OBD_LOG_CANCEL,   "llog_origin_handle_cancel" },
        { OBD_QC_CALLBACK,  "obd_quota_callback" },
        { LLOG_ORIGIN_HANDLE_CREATE,     "llog_origin_handle_create" },
        { LLOG_ORIGIN_HANDLE_NEXT_BLOCK, "llog_origin_handle_next_block" },
        { LLOG_ORIGIN_HANDLE_READ_HEADER,"llog_origin_handle_read_header" },
        { LLOG_ORIGIN_HANDLE_WRITE_REC,  "llog_origin_handle_write_rec" },
        { LLOG_ORIGIN_HANDLE_CLOSE,      "llog_origin_handle_close" },
        { LLOG_ORIGIN_CONNECT,           "llog_origin_connect" },
        { LLOG_CATINFO,                  "llog_catinfo" },
        { LLOG_ORIGIN_HANDLE_PREV_BLOCK, "llog_origin_handle_prev_block" },
        { LLOG_ORIGIN_HANDLE_DESTROY,    "llog_origin_handle_destroy" },
        { QUOTA_DQACQ,      "quota_acquire" },
        { QUOTA_DQREL,      "quota_release" },
        { SEQ_QUERY,        "seq_query" },
        { SEC_CTX_INIT,     "sec_ctx_init" },
        { SEC_CTX_INIT_CONT,"sec_ctx_init_cont" },
        { SEC_CTX_FINI,     "sec_ctx_fini" },
        { FLD_QUERY,        "fld_query" }
};

struct ll_eopcode {
     __u32       opcode;
     const char *opname;
} ll_eopcode_table[EXTRA_LAST_OPC] = {
        { LDLM_GLIMPSE_ENQUEUE, "ldlm_glimpse_enqueue" },
        { LDLM_PLAIN_ENQUEUE,   "ldlm_plain_enqueue" },
        { LDLM_EXTENT_ENQUEUE,  "ldlm_extent_enqueue" },
        { LDLM_FLOCK_ENQUEUE,   "ldlm_flock_enqueue" },
        { LDLM_IBITS_ENQUEUE,   "ldlm_ibits_enqueue" },
        { MDS_REINT_SETATTR,    "mds_reint_setattr" },
        { MDS_REINT_CREATE,     "mds_reint_create" },
        { MDS_REINT_LINK,       "mds_reint_link" },
        { MDS_REINT_UNLINK,     "mds_reint_unlink" },
        { MDS_REINT_RENAME,     "mds_reint_rename" },
        { MDS_REINT_OPEN,       "mds_reint_open" },
        { MDS_REINT_SETXATTR,   "mds_reint_setxattr" },
        { BRW_READ_BYTES,       "read_bytes" },
        { BRW_WRITE_BYTES,      "write_bytes" },
};

const char *ll_opcode2str(__u32 opcode)
{
        /* When one of the assertions below fail, chances are that:
         *     1) A new opcode was added in include/lustre/lustre_idl.h,
         *        but is missing from the table above.
         * or  2) The opcode space was renumbered or rearranged,
         *        and the opcode_offset() function in
         *        ptlrpc_internal.h needs to be modified.
         */
        __u32 offset = opcode_offset(opcode);
        LASSERTF(offset < LUSTRE_MAX_OPCODES,
                 "offset %u >= LUSTRE_MAX_OPCODES %u\n",
                 offset, LUSTRE_MAX_OPCODES);
        LASSERTF(ll_rpc_opcode_table[offset].opcode == opcode,
                 "ll_rpc_opcode_table[%u].opcode %u != opcode %u\n",
                 offset, ll_rpc_opcode_table[offset].opcode, opcode);
        return ll_rpc_opcode_table[offset].opname;
}

const char* ll_eopcode2str(__u32 opcode)
{
        LASSERT(ll_eopcode_table[opcode].opcode == opcode);
        return ll_eopcode_table[opcode].opname;
}
#ifdef LPROCFS
void ptlrpc_lprocfs_register(struct proc_dir_entry *root, char *dir,
                             char *name, struct proc_dir_entry **procroot_ret,
                             struct lprocfs_stats **stats_ret)
{
        struct proc_dir_entry *svc_procroot;
        struct lprocfs_stats *svc_stats;
        int i, rc;
        unsigned int svc_counter_config = LPROCFS_CNTR_AVGMINMAX |
                                          LPROCFS_CNTR_STDDEV;

        LASSERT(*procroot_ret == NULL);
        LASSERT(*stats_ret == NULL);

        svc_stats = lprocfs_alloc_stats(EXTRA_MAX_OPCODES+LUSTRE_MAX_OPCODES,0);
        if (svc_stats == NULL)
                return;

        if (dir) {
                svc_procroot = lprocfs_register(dir, root, NULL, NULL);
                if (IS_ERR(svc_procroot)) {
                        lprocfs_free_stats(&svc_stats);
                        return;
                }
        } else {
                svc_procroot = root;
        }

        lprocfs_counter_init(svc_stats, PTLRPC_REQWAIT_CNTR,
                             svc_counter_config, "req_waittime", "usec");
        lprocfs_counter_init(svc_stats, PTLRPC_REQQDEPTH_CNTR,
                             svc_counter_config, "req_qdepth", "reqs");
        lprocfs_counter_init(svc_stats, PTLRPC_REQACTIVE_CNTR,
                             svc_counter_config, "req_active", "reqs");
        lprocfs_counter_init(svc_stats, PTLRPC_TIMEOUT,
                             svc_counter_config, "req_timeout", "sec");
        lprocfs_counter_init(svc_stats, PTLRPC_REQBUF_AVAIL_CNTR,
                             svc_counter_config, "reqbuf_avail", "bufs");
        for (i = 0; i < EXTRA_LAST_OPC; i++) {
                char *units;

                switch(i) {
                case BRW_WRITE_BYTES:
                case BRW_READ_BYTES:
                        units = "bytes";
                        break;
                default:
                        units = "reqs";
                        break;
                }
                lprocfs_counter_init(svc_stats, PTLRPC_LAST_CNTR + i,
                                     svc_counter_config,
                                     ll_eopcode2str(i), units);
        }
        for (i = 0; i < LUSTRE_MAX_OPCODES; i++) {
                __u32 opcode = ll_rpc_opcode_table[i].opcode;
                lprocfs_counter_init(svc_stats,
                                     EXTRA_MAX_OPCODES + i, svc_counter_config,
                                     ll_opcode2str(opcode), "usec");
        }

        rc = lprocfs_register_stats(svc_procroot, name, svc_stats);
        if (rc < 0) {
                if (dir)
                        lprocfs_remove(&svc_procroot);
                lprocfs_free_stats(&svc_stats);
        } else {
                if (dir)
                        *procroot_ret = svc_procroot;
                *stats_ret = svc_stats;
        }
}

static int
ptlrpc_lprocfs_read_req_history_len(char *page, char **start, off_t off,
				    int count, int *eof, void *data)
{
	struct ptlrpc_service *svc = data;
	struct ptlrpc_service_part *svcpt;
	int	total = 0;
	int	i;

	*eof = 1;

	ptlrpc_service_for_each_part(svcpt, i, svc)
		total += svcpt->scp_hist_nrqbds;

	return snprintf(page, count, "%d\n", total);
}

static int
ptlrpc_lprocfs_read_req_history_max(char *page, char **start, off_t off,
                                    int count, int *eof, void *data)
{
	struct ptlrpc_service *svc = data;
	struct ptlrpc_service_part *svcpt;
	int	total = 0;
	int	i;

	*eof = 1;
	ptlrpc_service_for_each_part(svcpt, i, svc)
		total += svc->srv_hist_nrqbds_cpt_max;

	return snprintf(page, count, "%d\n", total);
}

static int
ptlrpc_lprocfs_write_req_history_max(struct file *file, const char *buffer,
                                     unsigned long count, void *data)
{
	struct ptlrpc_service	   *svc = data;
	int			    bufpages;
	int			    val;
	int			    rc;

	rc = lprocfs_write_helper(buffer, count, &val);
        if (rc < 0)
                return rc;

        if (val < 0)
                return -ERANGE;

        /* This sanity check is more of an insanity check; we can still
         * hose a kernel by allowing the request history to grow too
         * far. */
        bufpages = (svc->srv_buf_size + CFS_PAGE_SIZE - 1) >> CFS_PAGE_SHIFT;
        if (val > cfs_num_physpages/(2 * bufpages))
                return -ERANGE;

	cfs_spin_lock(&svc->srv_lock);

	if (val == 0)
		svc->srv_hist_nrqbds_cpt_max = 0;
	else
		svc->srv_hist_nrqbds_cpt_max = max(1, (val / svc->srv_ncpts));

	cfs_spin_unlock(&svc->srv_lock);

	return count;
}

static int
ptlrpc_lprocfs_rd_threads_min(char *page, char **start, off_t off,
			      int count, int *eof, void *data)
{
	struct ptlrpc_service *svc = data;

	return snprintf(page, count, "%d\n",
			svc->srv_nthrs_cpt_init * svc->srv_ncpts);
}

static int
ptlrpc_lprocfs_wr_threads_min(struct file *file, const char *buffer,
                              unsigned long count, void *data)
{
	struct ptlrpc_service	   *svc = data;
	int	val;
	int	rc = lprocfs_write_helper(buffer, count, &val);

	if (rc < 0)
		return rc;

	if (val / svc->srv_ncpts < PTLRPC_NTHRS_INIT)
		return -ERANGE;

	cfs_spin_lock(&svc->srv_lock);
	if (val > svc->srv_nthrs_cpt_limit * svc->srv_ncpts) {
		cfs_spin_unlock(&svc->srv_lock);
		return -ERANGE;
	}

	svc->srv_nthrs_cpt_init = val / svc->srv_ncpts;

	cfs_spin_unlock(&svc->srv_lock);

	return count;
}

static int
ptlrpc_lprocfs_rd_threads_started(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	struct ptlrpc_service *svc = data;
	struct ptlrpc_service_part *svcpt;
	int	total = 0;
	int	i;

	LASSERT(svc->srv_parts != NULL);
	ptlrpc_service_for_each_part(svcpt, i, svc)
		total += svcpt->scp_nthrs_running;

	return snprintf(page, count, "%d\n", total);
}

static int
ptlrpc_lprocfs_rd_threads_max(char *page, char **start, off_t off,
			      int count, int *eof, void *data)
{
	struct ptlrpc_service *svc = data;

	return snprintf(page, count, "%d\n",
			svc->srv_nthrs_cpt_limit * svc->srv_ncpts);
}

static int
ptlrpc_lprocfs_wr_threads_max(struct file *file, const char *buffer,
			      unsigned long count, void *data)
{
	struct ptlrpc_service *svc = data;
	int	val;
	int	rc = lprocfs_write_helper(buffer, count, &val);

	if (rc < 0)
		return rc;

	if (val / svc->srv_ncpts < PTLRPC_NTHRS_INIT)
		return -ERANGE;

	cfs_spin_lock(&svc->srv_lock);
	if (val < svc->srv_nthrs_cpt_init * svc->srv_ncpts) {
		cfs_spin_unlock(&svc->srv_lock);
		return -ERANGE;
	}

	svc->srv_nthrs_cpt_limit = val / svc->srv_ncpts;

	cfs_spin_unlock(&svc->srv_lock);

	return count;
}

struct ptlrpc_srh_iterator {
	int			srhi_idx;
	__u64			srhi_seq;
	struct ptlrpc_request	*srhi_req;
};

int
ptlrpc_lprocfs_svc_req_history_seek(struct ptlrpc_service_part *svcpt,
				    struct ptlrpc_srh_iterator *srhi,
				    __u64 seq)
{
	cfs_list_t		*e;
	struct ptlrpc_request	*req;

	if (srhi->srhi_req != NULL &&
	    srhi->srhi_seq > svcpt->scp_hist_seq_culled &&
            srhi->srhi_seq <= seq) {
                /* If srhi_req was set previously, hasn't been culled and
                 * we're searching for a seq on or after it (i.e. more
                 * recent), search from it onwards.
                 * Since the service history is LRU (i.e. culled reqs will
                 * be near the head), we shouldn't have to do long
                 * re-scans */
                LASSERT (srhi->srhi_seq == srhi->srhi_req->rq_history_seq);
		LASSERT(!cfs_list_empty(&svcpt->scp_hist_reqs));
		e = &srhi->srhi_req->rq_history_list;
	} else {
		/* search from start */
		e = svcpt->scp_hist_reqs.next;
	}

	while (e != &svcpt->scp_hist_reqs) {
                req = cfs_list_entry(e, struct ptlrpc_request, rq_history_list);

                if (req->rq_history_seq >= seq) {
                        srhi->srhi_seq = req->rq_history_seq;
                        srhi->srhi_req = req;
                        return 0;
                }
                e = e->next;
        }

        return -ENOENT;
}

static void *
ptlrpc_lprocfs_svc_req_history_start(struct seq_file *s, loff_t *pos)
{
	struct ptlrpc_service		*svc = s->private;
	struct ptlrpc_service_part	*svcpt;
	struct ptlrpc_srh_iterator	*srhi;
	int				rc;
	int				i;

	OBD_ALLOC(srhi, sizeof(*srhi));
	if (srhi == NULL)
		return NULL;

	srhi->srhi_seq = 0;
	srhi->srhi_req = NULL;

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		srhi->srhi_idx = i;

		cfs_spin_lock(&svcpt->scp_lock);
		rc = ptlrpc_lprocfs_svc_req_history_seek(svcpt, srhi, *pos);
		cfs_spin_unlock(&svcpt->scp_lock);
		if (rc == 0) {
			*pos = srhi->srhi_seq;
			return srhi;
		}
	}

	OBD_FREE(srhi, sizeof(*srhi));
	return NULL;
}

static void
ptlrpc_lprocfs_svc_req_history_stop(struct seq_file *s, void *iter)
{
        struct ptlrpc_srh_iterator *srhi = iter;

        if (srhi != NULL)
                OBD_FREE(srhi, sizeof(*srhi));
}

static void *
ptlrpc_lprocfs_svc_req_history_next(struct seq_file *s,
				    void *iter, loff_t *pos)
{
	struct ptlrpc_service		*svc = s->private;
	struct ptlrpc_srh_iterator	*srhi = iter;
	struct ptlrpc_service_part	*svcpt;
	int				rc = 0;
	int				i;

	for (i = srhi->srhi_idx; i < svc->srv_ncpts; i++) {
		svcpt = svc->srv_parts[i];

		srhi->srhi_idx = i;

		cfs_spin_lock(&svcpt->scp_lock);
		rc = ptlrpc_lprocfs_svc_req_history_seek(svcpt, srhi, *pos + 1);
		cfs_spin_unlock(&svcpt->scp_lock);
		if (rc == 0)
			break;
	}

        if (rc != 0) {
                OBD_FREE(srhi, sizeof(*srhi));
                return NULL;
        }

        *pos = srhi->srhi_seq;
        return srhi;
}

/* common ost/mdt so_req_printer */
void target_print_req(void *seq_file, struct ptlrpc_request *req)
{
        /* Called holding srv_lock with irqs disabled.
         * Print specific req contents and a newline.
         * CAVEAT EMPTOR: check request message length before printing!!!
         * You might have received any old crap so you must be just as
         * careful here as the service's request parser!!! */
        struct seq_file *sf = seq_file;

        switch (req->rq_phase) {
        case RQ_PHASE_NEW:
                /* still awaiting a service thread's attention, or rejected
                 * because the generic request message didn't unpack */
                seq_printf(sf, "<not swabbed>\n");
                break;
        case RQ_PHASE_INTERPRET:
                /* being handled, so basic msg swabbed, and opc is valid
                 * but racing with mds_handle() */
        case RQ_PHASE_COMPLETE:
                /* been handled by mds_handle() reply state possibly still
                 * volatile */
                seq_printf(sf, "opc %d\n", lustre_msg_get_opc(req->rq_reqmsg));
                break;
        default:
                DEBUG_REQ(D_ERROR, req, "bad phase %d", req->rq_phase);
        }
}
EXPORT_SYMBOL(target_print_req);

static int ptlrpc_lprocfs_svc_req_history_show(struct seq_file *s, void *iter)
{
	struct ptlrpc_service		*svc = s->private;
	struct ptlrpc_srh_iterator	*srhi = iter;
	struct ptlrpc_service_part	*svcpt;
	struct ptlrpc_request		*req;
	int				rc;

	LASSERT(srhi->srhi_idx < svc->srv_ncpts);

	svcpt = svc->srv_parts[srhi->srhi_idx];

	cfs_spin_lock(&svcpt->scp_lock);

	rc = ptlrpc_lprocfs_svc_req_history_seek(svcpt, srhi, srhi->srhi_seq);

        if (rc == 0) {
                req = srhi->srhi_req;

                /* Print common req fields.
                 * CAVEAT EMPTOR: we're racing with the service handler
                 * here.  The request could contain any old crap, so you
                 * must be just as careful as the service's request
                 * parser. Currently I only print stuff here I know is OK
                 * to look at coz it was set up in request_in_callback()!!! */
                seq_printf(s, LPD64":%s:%s:x"LPU64":%d:%s:%ld:%lds(%+lds) ",
                           req->rq_history_seq, libcfs_nid2str(req->rq_self),
                           libcfs_id2str(req->rq_peer), req->rq_xid,
                           req->rq_reqlen, ptlrpc_rqphase2str(req),
                           req->rq_arrival_time.tv_sec,
                           req->rq_sent - req->rq_arrival_time.tv_sec,
                           req->rq_sent - req->rq_deadline);
		if (svc->srv_ops.so_req_printer == NULL)
			seq_printf(s, "\n");
		else
			svc->srv_ops.so_req_printer(s, srhi->srhi_req);
        }

	cfs_spin_unlock(&svcpt->scp_lock);
	return rc;
}

static int
ptlrpc_lprocfs_svc_req_history_open(struct inode *inode, struct file *file)
{
        static struct seq_operations sops = {
                .start = ptlrpc_lprocfs_svc_req_history_start,
                .stop  = ptlrpc_lprocfs_svc_req_history_stop,
                .next  = ptlrpc_lprocfs_svc_req_history_next,
                .show  = ptlrpc_lprocfs_svc_req_history_show,
        };
        struct proc_dir_entry *dp = PDE(inode);
        struct seq_file       *seqf;
        int                    rc;

        LPROCFS_ENTRY_AND_CHECK(dp);
        rc = seq_open(file, &sops);
        if (rc) {
                LPROCFS_EXIT();
                return rc;
        }

        seqf = file->private_data;
        seqf->private = dp->data;
        return 0;
}

/* See also lprocfs_rd_timeouts */
static int ptlrpc_lprocfs_rd_timeouts(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct ptlrpc_service		*svc = data;
	struct ptlrpc_service_part	*svcpt;
	struct dhms			ts;
	time_t				worstt;
	unsigned int			cur;
	unsigned int			worst;
	int				nob = 0;
	int				rc = 0;
	int				i;

	LASSERT(svc->srv_parts != NULL);

	if (AT_OFF) {
		rc += snprintf(page + rc, count - rc,
			       "adaptive timeouts off, using obd_timeout %u\n",
			       obd_timeout);
		return rc;
	}

	ptlrpc_service_for_each_part(svcpt, i, svc) {
		cur	= at_get(&svcpt->scp_at_estimate);
		worst	= svcpt->scp_at_estimate.at_worst_ever;
		worstt	= svcpt->scp_at_estimate.at_worst_time;
		s2dhms(&ts, cfs_time_current_sec() - worstt);

		nob = snprintf(page, count,
			       "%10s : cur %3u  worst %3u (at %ld, "
			       DHMS_FMT" ago) ", "service",
			       cur, worst, worstt, DHMS_VARS(&ts));

		nob = lprocfs_at_hist_helper(page, count, nob,
					     &svcpt->scp_at_estimate);
		rc += nob;
		page += nob;
		count -= nob;

		/*
		 * NB: for lustre proc read, the read count must be less
		 * than PAGE_SIZE, please see details in lprocfs_fops_read.
		 * It's unlikely that we exceed PAGE_SIZE at here because
		 * it means the service has more than 50 partitions.
		 */
		if (count <= 0) {
			CWARN("Can't fit AT information of %s in one page, "
			      "please contact with developer to fix this.\n",
			      svc->srv_name);
			break;
		}
	}

	return rc;
}

static int ptlrpc_lprocfs_rd_hp_ratio(char *page, char **start, off_t off,
                                      int count, int *eof, void *data)
{
        struct ptlrpc_service *svc = data;
        int rc = snprintf(page, count, "%d", svc->srv_hpreq_ratio);
        return rc;
}

static int ptlrpc_lprocfs_wr_hp_ratio(struct file *file, const char *buffer,
				      unsigned long count, void *data)
{
	struct ptlrpc_service		*svc = data;
	int	rc;
	int	val;

	rc = lprocfs_write_helper(buffer, count, &val);
	if (rc < 0)
		return rc;

	if (val < 0)
		return -ERANGE;

	cfs_spin_lock(&svc->srv_lock);
	svc->srv_hpreq_ratio = val;
	cfs_spin_unlock(&svc->srv_lock);

	return count;
}

void ptlrpc_lprocfs_register_service(struct proc_dir_entry *entry,
                                     struct ptlrpc_service *svc)
{
        struct lprocfs_vars lproc_vars[] = {
                {.name       = "high_priority_ratio",
                 .read_fptr  = ptlrpc_lprocfs_rd_hp_ratio,
                 .write_fptr = ptlrpc_lprocfs_wr_hp_ratio,
                 .data       = svc},
                {.name       = "req_buffer_history_len",
                 .read_fptr  = ptlrpc_lprocfs_read_req_history_len,
                 .data       = svc},
                {.name       = "req_buffer_history_max",
                 .write_fptr = ptlrpc_lprocfs_write_req_history_max,
                 .read_fptr  = ptlrpc_lprocfs_read_req_history_max,
                 .data       = svc},
                {.name       = "threads_min",
                 .read_fptr  = ptlrpc_lprocfs_rd_threads_min,
                 .write_fptr = ptlrpc_lprocfs_wr_threads_min,
                 .data       = svc},
                {.name       = "threads_max",
                 .read_fptr  = ptlrpc_lprocfs_rd_threads_max,
                 .write_fptr = ptlrpc_lprocfs_wr_threads_max,
                 .data       = svc},
                {.name       = "threads_started",
                 .read_fptr  = ptlrpc_lprocfs_rd_threads_started,
                 .data       = svc},
                {.name       = "timeouts",
                 .read_fptr  = ptlrpc_lprocfs_rd_timeouts,
                 .data       = svc},
                {NULL}
        };
        static struct file_operations req_history_fops = {
                .owner       = THIS_MODULE,
                .open        = ptlrpc_lprocfs_svc_req_history_open,
                .read        = seq_read,
                .llseek      = seq_lseek,
                .release     = lprocfs_seq_release,
        };

        int rc;

        ptlrpc_lprocfs_register(entry, svc->srv_name,
                                "stats", &svc->srv_procroot,
                                &svc->srv_stats);

        if (svc->srv_procroot == NULL)
                return;

        lprocfs_add_vars(svc->srv_procroot, lproc_vars, NULL);

        rc = lprocfs_seq_create(svc->srv_procroot, "req_history",
                                0400, &req_history_fops, svc);
        if (rc)
                CWARN("Error adding the req_history file\n");
}

void ptlrpc_lprocfs_register_obd(struct obd_device *obddev)
{
        ptlrpc_lprocfs_register(obddev->obd_proc_entry, NULL, "stats",
                                &obddev->obd_svc_procroot,
                                &obddev->obd_svc_stats);
}
EXPORT_SYMBOL(ptlrpc_lprocfs_register_obd);

void ptlrpc_lprocfs_rpc_sent(struct ptlrpc_request *req, long amount)
{
        struct lprocfs_stats *svc_stats;
        __u32 op = lustre_msg_get_opc(req->rq_reqmsg);
        int opc = opcode_offset(op);

        svc_stats = req->rq_import->imp_obd->obd_svc_stats;
        if (svc_stats == NULL || opc <= 0)
                return;
        LASSERT(opc < LUSTRE_MAX_OPCODES);
        if (!(op == LDLM_ENQUEUE || op == MDS_REINT))
                lprocfs_counter_add(svc_stats, opc + EXTRA_MAX_OPCODES, amount);
}

void ptlrpc_lprocfs_brw(struct ptlrpc_request *req, int bytes)
{
        struct lprocfs_stats *svc_stats;
        int idx;

        if (!req->rq_import)
                return;
        svc_stats = req->rq_import->imp_obd->obd_svc_stats;
        if (!svc_stats)
                return;
        idx = lustre_msg_get_opc(req->rq_reqmsg);
        switch (idx) {
        case OST_READ:
                idx = BRW_READ_BYTES + PTLRPC_LAST_CNTR;
                break;
        case OST_WRITE:
                idx = BRW_WRITE_BYTES + PTLRPC_LAST_CNTR;
                break;
        default:
                LASSERTF(0, "unsupported opcode %u\n", idx);
                break;
        }

        lprocfs_counter_add(svc_stats, idx, bytes);
}

EXPORT_SYMBOL(ptlrpc_lprocfs_brw);

void ptlrpc_lprocfs_unregister_service(struct ptlrpc_service *svc)
{
        if (svc->srv_procroot != NULL)
                lprocfs_remove(&svc->srv_procroot);

        if (svc->srv_stats)
                lprocfs_free_stats(&svc->srv_stats);
}

void ptlrpc_lprocfs_unregister_obd(struct obd_device *obd)
{
        if (obd->obd_svc_procroot)
                lprocfs_remove(&obd->obd_svc_procroot);

        if (obd->obd_svc_stats)
                lprocfs_free_stats(&obd->obd_svc_stats);
}
EXPORT_SYMBOL(ptlrpc_lprocfs_unregister_obd);


#define BUFLEN (UUID_MAX + 5)

int lprocfs_wr_evict_client(struct file *file, const char *buffer,
                            unsigned long count, void *data)
{
        struct obd_device *obd = data;
        char              *kbuf;
        char              *tmpbuf;

        OBD_ALLOC(kbuf, BUFLEN);
        if (kbuf == NULL)
                return -ENOMEM;

        /*
         * OBD_ALLOC() will zero kbuf, but we only copy BUFLEN - 1
         * bytes into kbuf, to ensure that the string is NUL-terminated.
         * UUID_MAX should include a trailing NUL already.
         */
        if (cfs_copy_from_user(kbuf, buffer,
                               min_t(unsigned long, BUFLEN - 1, count))) {
                count = -EFAULT;
                goto out;
        }
        tmpbuf = cfs_firststr(kbuf, min_t(unsigned long, BUFLEN - 1, count));
        /* Kludge code(deadlock situation): the lprocfs lock has been held
         * since the client is evicted by writting client's
         * uuid/nid to procfs "evict_client" entry. However,
         * obd_export_evict_by_uuid() will call lprocfs_remove() to destroy
         * the proc entries under the being destroyed export{}, so I have
         * to drop the lock at first here.
         * - jay, jxiong@clusterfs.com */
        class_incref(obd, __FUNCTION__, cfs_current());
        LPROCFS_EXIT();

        if (strncmp(tmpbuf, "nid:", 4) == 0)
                obd_export_evict_by_nid(obd, tmpbuf + 4);
        else if (strncmp(tmpbuf, "uuid:", 5) == 0)
                obd_export_evict_by_uuid(obd, tmpbuf + 5);
        else
                obd_export_evict_by_uuid(obd, tmpbuf);

        LPROCFS_ENTRY();
        class_decref(obd, __FUNCTION__, cfs_current());

out:
        OBD_FREE(kbuf, BUFLEN);
        return count;
}
EXPORT_SYMBOL(lprocfs_wr_evict_client);

#undef BUFLEN

int lprocfs_wr_ping(struct file *file, const char *buffer,
                    unsigned long count, void *data)
{
        struct obd_device     *obd = data;
        struct ptlrpc_request *req;
        int                    rc;
        ENTRY;

        LPROCFS_CLIMP_CHECK(obd);
        req = ptlrpc_prep_ping(obd->u.cli.cl_import);
        LPROCFS_CLIMP_EXIT(obd);
        if (req == NULL)
                RETURN(-ENOMEM);

        req->rq_send_state = LUSTRE_IMP_FULL;

        rc = ptlrpc_queue_wait(req);

        ptlrpc_req_finished(req);
        if (rc >= 0)
                RETURN(count);
        RETURN(rc);
}
EXPORT_SYMBOL(lprocfs_wr_ping);

/* Write the connection UUID to this file to attempt to connect to that node.
 * The connection UUID is a node's primary NID. For example,
 * "echo connection=192.168.0.1@tcp0::instance > .../import".
 */
int lprocfs_wr_import(struct file *file, const char *buffer,
                      unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct obd_import *imp = obd->u.cli.cl_import;
        char *kbuf = NULL;
        char *uuid;
        char *ptr;
        int do_reconn = 1;
        const char prefix[] = "connection=";
        const int prefix_len = sizeof(prefix) - 1;

        if (count > CFS_PAGE_SIZE - 1 || count <= prefix_len)
                return -EINVAL;

        OBD_ALLOC(kbuf, count + 1);
        if (kbuf == NULL)
                return -ENOMEM;

        if (cfs_copy_from_user(kbuf, buffer, count))
                GOTO(out, count = -EFAULT);

        kbuf[count] = 0;

        /* only support connection=uuid::instance now */
        if (strncmp(prefix, kbuf, prefix_len) != 0)
                GOTO(out, count = -EINVAL);

        uuid = kbuf + prefix_len;
        ptr = strstr(uuid, "::");
        if (ptr) {
                __u32 inst;
                char *endptr;

                *ptr = 0;
                do_reconn = 0;
                ptr += strlen("::");
                inst = simple_strtol(ptr, &endptr, 10);
                if (*endptr) {
                        CERROR("config: wrong instance # %s\n", ptr);
                } else if (inst != imp->imp_connect_data.ocd_instance) {
                        CDEBUG(D_INFO, "IR: %s is connecting to an obsoleted "
                               "target(%u/%u), reconnecting...\n",
                               imp->imp_obd->obd_name,
                               imp->imp_connect_data.ocd_instance, inst);
                        do_reconn = 1;
                } else {
                        CDEBUG(D_INFO, "IR: %s has already been connecting to "
                               "new target(%u)\n",
                               imp->imp_obd->obd_name, inst);
                }
        }

        if (do_reconn)
                ptlrpc_recover_import(imp, uuid, 1);

out:
        OBD_FREE(kbuf, count + 1);
        return count;
}
EXPORT_SYMBOL(lprocfs_wr_import);

int lprocfs_rd_pinger_recov(char *page, char **start, off_t off,
                            int count, int *eof, void *data)
{
        struct obd_device *obd = data;
        struct obd_import *imp = obd->u.cli.cl_import;
        int rc;

        LPROCFS_CLIMP_CHECK(obd);
        rc = snprintf(page, count, "%d\n", !imp->imp_no_pinger_recover);
        LPROCFS_CLIMP_EXIT(obd);

        return rc;
}
EXPORT_SYMBOL(lprocfs_rd_pinger_recov);

int lprocfs_wr_pinger_recov(struct file *file, const char *buffer,
                      unsigned long count, void *data)
{
        struct obd_device *obd = data;
        struct client_obd *cli = &obd->u.cli;
        struct obd_import *imp = cli->cl_import;
        int rc, val;

        rc = lprocfs_write_helper(buffer, count, &val);
        if (rc < 0)
                return rc;

        if (val != 0 && val != 1)
                return -ERANGE;

        LPROCFS_CLIMP_CHECK(obd);
        cfs_spin_lock(&imp->imp_lock);
        imp->imp_no_pinger_recover = !val;
        cfs_spin_unlock(&imp->imp_lock);
        LPROCFS_CLIMP_EXIT(obd);

        return count;

}
EXPORT_SYMBOL(lprocfs_wr_pinger_recov);

#endif /* LPROCFS */
