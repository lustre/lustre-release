// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Lustre Metadata Server (MDD) routines
 */

#define DEBUG_SUBSYSTEM S_MDS

#include "mdd_internal.h"

struct mdd_changelog_user_lookup_data {
	const struct changelog_filter *mcul_req;
	struct changelog_filter *mcul_reply;
	int mcul_found;
};

/*
 * llog_cat_process() callback to lookup a changelog user record by ID or name.
 */
static int mdd_changelog_user_lookup_cb(const struct lu_env *env,
					struct llog_handle *llh,
					struct llog_rec_hdr *hdr, void *data)
{
	struct mdd_changelog_user_lookup_data *mcul = data;
	const struct changelog_filter *req = mcul->mcul_req;
	struct changelog_filter *reply = mcul->mcul_reply;
	struct llog_changelog_user_rec2 *rec;

	ENTRY;

	if ((llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN) == 0)
		RETURN(-ENXIO);

	rec = container_of(hdr, typeof(*rec), cur_hdr);

	if (rec->cur_hdr.lrh_type != CHANGELOG_USER_REC &&
	    rec->cur_hdr.lrh_type != CHANGELOG_USER_REC2)
		RETURN(0);

	/*
	 * Match the requested user ID or name.  cur_name may lie past the end
	 * of an old CHANGELOG_USER_REC -- one written before LU-13055
	 * (v2.14.53), when the record was 40 bytes -- so only an ID can find
	 * one of those.  From that commit on, mdd_changelog_user_register()
	 * writes sizeof(*rec) into lrh_len whichever type it then picks, so
	 * cur_name is inside the record and zeroed.  The name compare is
	 * bounded for the same reason it is in mdd_changelog_name_check_cb():
	 * cur_name comes off disk and nothing guarantees a NUL inside its 16
	 * bytes.
	 */
	if (req->cf_user_id != 0) {
		if (rec->cur_id != req->cf_user_id)
			RETURN(0);
	} else if (rec->cur_hdr.lrh_type != CHANGELOG_USER_REC2 ||
		   strncmp(rec->cur_name, req->cf_username,
			   sizeof(rec->cur_name))) {
		RETURN(0);
	}

	/* Found the user - fill the info structure */
	reply->cf_user_id = rec->cur_id;
	reply->cf_mask = mdd_chlg_usermask(rec);
	/*
	 * Not "if the lookup was by ID": the only caller passes one buffer as
	 * both req and reply, so cf_user_id is this record's by the line
	 * above.  The record's own type is what decides whether it has a name.
	 * Bounded by the source, as the compare above is: cur_name carries no
	 * guaranteed NUL, and cf_username is the larger of the two.
	 */
	if (rec->cur_hdr.lrh_type == CHANGELOG_USER_REC2 &&
	    rec->cur_name[0] != '\0')
		strscpy(reply->cf_username, rec->cur_name,
			sizeof(rec->cur_name));
	CDEBUG(D_INFO, "Found changelog user: user=cl%u(%s), mask=0x%llx\n",
	       reply->cf_user_id, reply->cf_username, reply->cf_mask);

	/* Stop searching */
	mcul->mcul_found = 1;
	RETURN(-EEXIST);
}

/**
 * mdd_changelog_user_lookup() - Lookup a changelog user record by ID or name.
 * @env: Execution environment
 * @mdd: Device to lookup user on
 * @req: Changelog user request
 * @reply: Changelog user reply [out]
 *
 * Return:
 * * %0 on success
 * * %negative on error
 */
int mdd_changelog_user_lookup(const struct lu_env *env,
			      struct mdd_device *mdd,
			      const struct changelog_filter *req,
			      struct changelog_filter *reply)
{
	struct llog_ctxt *ctxt;
	struct mdd_changelog_user_lookup_data mcul = {
		.mcul_req = req,
		.mcul_reply = reply,
		.mcul_found = 0,
	};
	int rc;

	ENTRY;

	ctxt = llog_get_context(mdd2obd_dev(mdd),
				LLOG_CHANGELOG_USER_ORIG_CTXT);
	if (ctxt == NULL)
		RETURN(-ENXIO);
	/* Search through changelog user records */
	rc = llog_cat_process(env, ctxt->loc_handle,
			      mdd_changelog_user_lookup_cb, &mcul, 0, 0);
	llog_ctxt_put(ctxt);

	if (rc == -EEXIST && mcul.mcul_found)
		rc = 0;
	else if (rc == 0 && !mcul.mcul_found)
		rc = -ENOENT;

	RETURN(rc);
}
