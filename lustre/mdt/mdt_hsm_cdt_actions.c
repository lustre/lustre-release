/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.  A copy is
 * included in the COPYING file that accompanied this code.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * GPL HEADER END
 */
/*
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 */
/*
 * lustre/mdt/mdt_hsm_cdt_actions.c
 *
 * Lustre HSM
 *
 * Author: Jacques-Charles Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 */

#define DEBUG_SUBSYSTEM S_MDS

#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_export.h>
#include <obd.h>
#include <lprocfs_status.h>
#include <lustre_log.h>
#include "mdt_internal.h"

void dump_llog_agent_req_rec(const char *prefix,
			     const struct llog_agent_req_rec *larr)
{
	char	buf[12];
	int	sz;

	sz = larr->arr_hai.hai_len - sizeof(larr->arr_hai);
	CDEBUG(D_HSM, "%slrh=[type=%X len=%d idx=%d] fid="DFID
	       " dfid="DFID
	       " compound/cookie="LPX64"/"LPX64
	       " status=%s action=%s archive#=%d flags="LPX64
	       " create="LPU64" change="LPU64
	       " extent="LPX64"-"LPX64" gid="LPX64" datalen=%d"
	       " data=[%s]\n",
	       prefix,
	       larr->arr_hdr.lrh_type,
	       larr->arr_hdr.lrh_len, larr->arr_hdr.lrh_index,
	       PFID(&larr->arr_hai.hai_fid),
	       PFID(&larr->arr_hai.hai_dfid),
	       larr->arr_compound_id, larr->arr_hai.hai_cookie,
	       agent_req_status2name(larr->arr_status),
	       hsm_copytool_action2name(larr->arr_hai.hai_action),
	       larr->arr_archive_id,
	       larr->arr_flags,
	       larr->arr_req_create, larr->arr_req_change,
	       larr->arr_hai.hai_extent.offset,
	       larr->arr_hai.hai_extent.length,
	       larr->arr_hai.hai_gid, sz,
	       hai_dump_data_field(&larr->arr_hai, buf, sizeof(buf)));
}

/*
 * process the actions llog
 * \param env [IN] environment
 * \param mdt [IN] MDT device
 * \param cb [IN] llog callback funtion
 * \param data [IN] llog callback  data
 * \retval 0 success
 * \retval -ve failure
 */
int cdt_llog_process(const struct lu_env *env, struct mdt_device *mdt,
		     llog_cb_t cb, void *data)
{
	struct obd_device	*obd = mdt2obd_dev(mdt);
	struct llog_ctxt	*lctxt = NULL;
	struct coordinator	*cdt = &mdt->mdt_coordinator;
	int			 rc;
	ENTRY;

	lctxt = llog_get_context(obd, LLOG_AGENT_ORIG_CTXT);
	if (lctxt == NULL || lctxt->loc_handle == NULL)
		RETURN(-ENOENT);

	mutex_lock(&cdt->cdt_llog_lock);

	rc = llog_cat_process(env, lctxt->loc_handle, cb, data, 0, 0);
	if (rc < 0)
		CERROR("%s: failed to process HSM_ACTIONS llog (rc=%d)\n",
			mdt_obd_name(mdt), rc);
	else
		rc = 0;

	llog_ctxt_put(lctxt);
	mutex_unlock(&cdt->cdt_llog_lock);
	RETURN(rc);
}

/**
 * add an entry in agent llog
 * \param env [IN] environment
 * \param mdt [IN] PDT device
 * \param compound_id [IN] global id associated with the record
 * \param archive_id [IN] backend archive number
 * \param hai [IN] record to register
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_agent_record_add(const struct lu_env *env,
			 struct mdt_device *mdt,
			 __u64 compound_id, __u32 archive_id,
			 __u64 flags, struct hsm_action_item *hai)
{
	struct obd_device		*obd = mdt2obd_dev(mdt);
	struct coordinator		*cdt = &mdt->mdt_coordinator;
	struct llog_ctxt		*lctxt = NULL;
	struct llog_agent_req_rec	*larr;
	int				 rc;
	int				 sz;
	ENTRY;

	sz = llog_data_len(sizeof(*larr) + hai->hai_len - sizeof(*hai));
	OBD_ALLOC(larr, sz);
	if (!larr)
		RETURN(-ENOMEM);
	larr->arr_hdr.lrh_len = sz;
	larr->arr_hdr.lrh_type = HSM_AGENT_REC;
	larr->arr_status = ARS_WAITING;
	larr->arr_compound_id = compound_id;
	larr->arr_archive_id = archive_id;
	larr->arr_flags = flags;
	larr->arr_req_create = cfs_time_current_sec();
	larr->arr_req_change = larr->arr_req_create;
	memcpy(&larr->arr_hai, hai, hai->hai_len);

	lctxt = llog_get_context(obd, LLOG_AGENT_ORIG_CTXT);
	if (lctxt == NULL || lctxt->loc_handle == NULL)
		GOTO(free, rc = -ENOENT);

	mutex_lock(&cdt->cdt_llog_lock);

	/* in case of cancel request, the cookie is already set to the
	 * value of the request cookie to be cancelled
	 * so we do not change it */
	if (hai->hai_action != HSMA_CANCEL) {
		cdt->cdt_last_cookie++;
		hai->hai_cookie = cdt->cdt_last_cookie;
	}
	larr->arr_hai.hai_cookie = hai->hai_cookie;
	rc = llog_cat_add(env, lctxt->loc_handle, &larr->arr_hdr, NULL);
	if (rc > 0)
		rc = 0;

	mutex_unlock(&cdt->cdt_llog_lock);
	llog_ctxt_put(lctxt);

	EXIT;
free:
	OBD_FREE(larr, sz);
	return rc;
}

/**
 * data passed to llog_cat_process() callback
 * to find requests
 */
struct data_update_cb {
	struct mdt_device	*mdt;
	__u64			*cookies;
	int			 cookies_count;
	int			 cookies_done;
	enum agent_req_status	 status;
	cfs_time_t		 change_time;
};

/**
 *  llog_cat_process() callback, used to update a record
 * \param env [IN] environment
 * \param llh [IN] llog handle
 * \param hdr [IN] llog record
 * \param data [IN] cb data = data_update_cb
 * \retval 0 success
 * \retval -ve failure
 */
static int mdt_agent_record_update_cb(const struct lu_env *env,
				      struct llog_handle *llh,
				      struct llog_rec_hdr *hdr,
				      void *data)
{
	struct llog_agent_req_rec	*larr;
	struct data_update_cb		*ducb;
	int				 rc, i;
	int				 found;
	ENTRY;

	larr = (struct llog_agent_req_rec *)hdr;
	ducb = data;
	found = 0;

	/* check if all done */
	if (ducb->cookies_count == ducb->cookies_done)
		RETURN(LLOG_PROC_BREAK);

	/* if record is in final state, never change */
	/* if record is a cancel request, it cannot be canceled
	 * this is to manage the following case:
	 * when a request is canceled, we have 2 records with the
	 * the same cookie : the one to cancel and the cancel request
	 * the 1st has to be set to ARS_CANCELED and the 2nd to ARS_SUCCEED
	 */
	if (agent_req_in_final_state(larr->arr_status) ||
	    (larr->arr_hai.hai_action == HSMA_CANCEL &&
	     ducb->status == ARS_CANCELED))
		RETURN(0);

	rc = 0;
	for (i = 0 ; i < ducb->cookies_count ; i++) {
		CDEBUG(D_HSM, "%s: search "LPX64", found "LPX64"\n",
		       mdt_obd_name(ducb->mdt), ducb->cookies[i],
		       larr->arr_hai.hai_cookie);
		if (larr->arr_hai.hai_cookie == ducb->cookies[i]) {

			larr->arr_status = ducb->status;
			larr->arr_req_change = ducb->change_time;
			rc = mdt_agent_llog_update_rec(env, ducb->mdt, llh,
						       larr);
			ducb->cookies_done++;
			found = 1;
			break;
		}
	}

	if (rc < 0)
		CERROR("%s: mdt_agent_llog_update_rec() failed, rc = %d\n",
		       mdt_obd_name(ducb->mdt), rc);

	if (found == 1)
		RETURN(LLOG_DEL_RECORD);

	RETURN(rc);
}

/**
 * update an entry in agent llog
 * \param env [IN] environment
 * \param mdt [IN] MDT device
 * \param cookie [IN] entries to update
 *    log cookie are returned by register
 * \param status [IN] new status of the request
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_agent_record_update(const struct lu_env *env, struct mdt_device *mdt,
			    __u64 *cookies, int cookies_count,
			    enum agent_req_status status)
{
	struct data_update_cb	 ducb;
	int			 rc;
	ENTRY;

	ducb.mdt = mdt;
	ducb.cookies = cookies;
	ducb.cookies_count = cookies_count;
	ducb.cookies_done = 0;
	ducb.status = status;
	ducb.change_time = cfs_time_current_sec();

	rc = cdt_llog_process(env, mdt, mdt_agent_record_update_cb, &ducb);
	if (rc < 0)
		CERROR("%s: cdt_llog_process() failed, rc=%d, cannot update "
		       "status to %s for %d cookies, done %d\n",
		       mdt_obd_name(mdt), rc,
		       agent_req_status2name(status),
		       cookies_count, ducb.cookies_done);
	RETURN(rc);
}

/**
 * update a llog record
 *  cdt_llog_lock must be hold
 * \param env [IN] environment
 * \param mdt [IN] mdt device
 * \param llh [IN] llog handle, must be a catalog handle
 * \param larr [IN] record
 * \retval 0 success
 * \retval -ve failure
 */
int mdt_agent_llog_update_rec(const struct lu_env *env,
			      struct mdt_device *mdt, struct llog_handle *llh,
			      struct llog_agent_req_rec *larr)
{
	struct llog_rec_hdr	 saved_hdr;
	int			 rc;
	ENTRY;

	/* saved old record info */
	saved_hdr = larr->arr_hdr;
	/* add new record with updated values */
	larr->arr_hdr.lrh_id = 0;
	larr->arr_hdr.lrh_index = 0;
	rc = llog_cat_add(env, llh->u.phd.phd_cat_handle, &larr->arr_hdr,
			  NULL);
	larr->arr_hdr = saved_hdr;
	RETURN(rc);
}

/*
 * Agent actions /proc seq_file methods
 * As llog processing uses a callback for each entry, we cannot do a sequential
 * read. To limit calls to llog_cat_process (it spawns a thread), we fill
 * multiple record in seq_file buffer in one show call.
 * op->start() sets the iterator up and returns the first element of sequence
 * op->stop() shuts it down.
 * op->show() iterate llog and print element into the buffer.
 * In case of error ->start() and ->next() return ERR_PTR(error)
 * In the end of sequence they return %NULL
 * op->show() returns 0 in case of success and negative number in case of error.
 *
 */
/**
 * seq_file iterator for agent_action entry
 */
#define AGENT_ACTIONS_IT_MAGIC 0x19660426
struct agent_action_iterator {
	int			 aai_magic;	 /**< magic number */
	bool			 aai_eof;	 /**< all done */
	struct lu_env		 aai_env;	 /**< lustre env for llog */
	struct mdt_device	*aai_mdt;	 /**< metadata device */
	struct llog_ctxt	*aai_ctxt;	 /**< llog context */
	int			 aai_cat_index;	 /**< cata idx already shown */
	int			 aai_index;	 /**< idx in cata shown */
};

/**
 * seq_file method called to start access to /proc file
 * get llog context + llog handle
 */
static void *mdt_hsm_actions_proc_start(struct seq_file *s, loff_t *pos)
{
	struct agent_action_iterator	*aai = s->private;
	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X",
		 aai->aai_magic);

	aai->aai_ctxt = llog_get_context(mdt2obd_dev(aai->aai_mdt),
					 LLOG_AGENT_ORIG_CTXT);
	if (aai->aai_ctxt == NULL || aai->aai_ctxt->loc_handle == NULL) {
		CERROR("llog_get_context() failed\n");
		RETURN(ERR_PTR(-ENOENT));
	}

	CDEBUG(D_HSM, "llog succesfully initialized, start from "LPD64"\n",
	       *pos);
	/* first call = rewind */
	if (*pos == 0) {
		aai->aai_cat_index = 0;
		aai->aai_index = -1;
		aai->aai_eof = false;
		*pos = 1;
	}

	if (aai->aai_eof)
		RETURN(NULL);

	RETURN(aai);
}

static void *mdt_hsm_actions_proc_next(struct seq_file *s, void *v,
					 loff_t *pos)
{
	RETURN(NULL);
}

/**
 *  llog_cat_process() callback, used to fill a seq_file buffer
 */
static int hsm_actions_show_cb(const struct lu_env *env,
				 struct llog_handle *llh,
				 struct llog_rec_hdr *hdr,
				 void *data)
{
	struct llog_agent_req_rec    *larr = (struct llog_agent_req_rec *)hdr;
	struct seq_file		     *s = data;
	struct agent_action_iterator *aai;
	int			      rc, sz;
	size_t			      count;
	char			      buf[12];
	ENTRY;

	aai = s->private;
	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X",
		 aai->aai_magic);

	/* if rec already printed => skip */
	if (unlikely(llh->lgh_hdr->llh_cat_idx < aai->aai_cat_index))
		RETURN(0);

	if (unlikely(llh->lgh_hdr->llh_cat_idx == aai->aai_cat_index &&
		     hdr->lrh_index <= aai->aai_index))
		RETURN(0);

	count = s->count;
	sz = larr->arr_hai.hai_len - sizeof(larr->arr_hai);
	rc = seq_printf(s, "lrh=[type=%X len=%d idx=%d/%d] fid="DFID
			" dfid="DFID
			" compound/cookie="LPX64"/"LPX64
			" action=%s archive#=%d flags="LPX64
			" extent="LPX64"-"LPX64
			" gid="LPX64" datalen=%d status=%s"
			" data=[%s]\n",
			hdr->lrh_type, hdr->lrh_len,
			llh->lgh_hdr->llh_cat_idx, hdr->lrh_index,
			PFID(&larr->arr_hai.hai_fid),
			PFID(&larr->arr_hai.hai_dfid),
			larr->arr_compound_id, larr->arr_hai.hai_cookie,
			hsm_copytool_action2name(larr->arr_hai.hai_action),
			larr->arr_archive_id,
			larr->arr_flags,
			larr->arr_hai.hai_extent.offset,
			larr->arr_hai.hai_extent.length,
			larr->arr_hai.hai_gid, sz,
			agent_req_status2name(larr->arr_status),
			hai_dump_data_field(&larr->arr_hai, buf, sizeof(buf)));
	if (rc == 0) {
		aai->aai_cat_index = llh->lgh_hdr->llh_cat_idx;
		aai->aai_index = hdr->lrh_index;
	} else {
		if (s->count == s->size && count > 0) /* rewind the buffer */
			s->count = count;
		rc = LLOG_PROC_BREAK;
	}
	RETURN(rc);
}

/**
 * mdt_hsm_actions_proc_show() is called at for each seq record
 * process the llog, with a cb which fill the file_seq buffer
 * to be faster, one show will fill multiple records
 */
static int mdt_hsm_actions_proc_show(struct seq_file *s, void *v)
{
	struct agent_action_iterator	*aai = s->private;
	struct coordinator		*cdt = &aai->aai_mdt->mdt_coordinator;
	int				 rc;
	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X",
		 aai->aai_magic);

	CDEBUG(D_HSM, "show from cat %d index %d eof=%d\n",
	       aai->aai_cat_index, aai->aai_index, aai->aai_eof);
	if (aai->aai_eof)
		RETURN(0);

	mutex_lock(&cdt->cdt_llog_lock);
	rc = llog_cat_process(&aai->aai_env, aai->aai_ctxt->loc_handle,
			      hsm_actions_show_cb, s,
			      aai->aai_cat_index, aai->aai_index + 1);
	mutex_unlock(&cdt->cdt_llog_lock);
	if (rc == 0) /* all llog parsed */
		aai->aai_eof = true;
	if (rc == LLOG_PROC_BREAK) /* buffer full */
		rc = 0;
	RETURN(rc);
}

/**
 * seq_file method called to stop access to /proc file
 * clean + put llog context
 */
static void mdt_hsm_actions_proc_stop(struct seq_file *s, void *v)
{
	struct agent_action_iterator *aai = s->private;
	ENTRY;

	LASSERTF(aai->aai_magic == AGENT_ACTIONS_IT_MAGIC, "%08X",
		 aai->aai_magic);

	if (aai->aai_ctxt)
		llog_ctxt_put(aai->aai_ctxt);

	EXIT;
	return;
}

static const struct seq_operations mdt_hsm_actions_proc_ops = {
	.start	= mdt_hsm_actions_proc_start,
	.next	= mdt_hsm_actions_proc_next,
	.show	= mdt_hsm_actions_proc_show,
	.stop	= mdt_hsm_actions_proc_stop,
};

static int lprocfs_open_hsm_actions(struct inode *inode, struct file *file)
{
	struct agent_action_iterator	*aai;
	struct seq_file			*s;
	int				 rc;
	struct mdt_device		*mdt;
	ENTRY;

	if (LPROCFS_ENTRY_CHECK(PDE(inode)))
		RETURN(-ENOENT);

	rc = seq_open(file, &mdt_hsm_actions_proc_ops);
	if (rc)
		RETURN(rc);

	OBD_ALLOC_PTR(aai);
	if (aai == NULL)
		GOTO(err, rc = -ENOMEM);

	aai->aai_magic = AGENT_ACTIONS_IT_MAGIC;
	rc = lu_env_init(&aai->aai_env, LCT_LOCAL);
	if (rc)
		GOTO(err, rc);

	/* mdt is saved in proc_dir_entry->data by
	 * mdt_coordinator_procfs_init() calling lprocfs_register()
	 */
	mdt = (struct mdt_device *)PDE(inode)->data;
	aai->aai_mdt = mdt;
	s = file->private_data;
	s->private = aai;

	GOTO(out, rc = 0);

err:
	lprocfs_seq_release(inode, file);
	if (aai && aai->aai_env.le_ses)
		OBD_FREE_PTR(aai->aai_env.le_ses);
	if (aai)
		OBD_FREE_PTR(aai);
out:
	return rc;
}

/**
 * lprocfs_release_hsm_actions() is called at end of /proc access.
 * It frees allocated ressources and calls cleanup lprocfs methods.
 */
static int lprocfs_release_hsm_actions(struct inode *inode, struct file *file)
{
	struct seq_file			*seq = file->private_data;
	struct agent_action_iterator	*aai = seq->private;

	if (aai) {
		lu_env_fini(&aai->aai_env);
		OBD_FREE_PTR(aai);
	}

	return lprocfs_seq_release(inode, file);
}

/* Methods to access HSM action list LLOG through /proc */
const struct file_operations mdt_hsm_actions_fops = {
	.owner		= THIS_MODULE,
	.open		= lprocfs_open_hsm_actions,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= lprocfs_release_hsm_actions,
};

