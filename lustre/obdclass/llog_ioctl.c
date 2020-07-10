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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LOG

#include <obd_class.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_log.h>
#include "llog_internal.h"

static int str2logid(struct llog_logid *logid, char *str, int len)
{
	unsigned long long id, seq;
	char *start, *end;
	u32 ogen;
	int rc;

	ENTRY;
	start = str;
	if (start[0] == '[') {
		struct lu_fid *fid = &logid->lgl_oi.oi_fid;
		int num;

		fid_zero(fid);
		logid->lgl_ogen = 0;
		num = sscanf(start + 1, SFID, RFID(fid));
		CDEBUG(D_INFO, DFID":%x\n", PFID(fid), logid->lgl_ogen);
		RETURN(num == 3 && fid_is_sane(fid) ? 0 : -EINVAL);
	}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(3, 1, 53, 0)
	/*
	 * logids used to be input in the form "#id#seq:ogen" before they
	 * were changed over to accept the FID [seq:oid:ver] format.
	 * This is accepted for compatibility reasons, though I doubt
	 * anyone is actually using this for anything.
	 */
	if (start[0] != '#')
		RETURN(-EINVAL);

	start++;
	if (start - str >= len - 1)
		RETURN(-EINVAL);
	end = strchr(start, '#');
	if (end == NULL || end == start)
		RETURN(-EINVAL);

	*end = '\0';
	rc = kstrtoull(start, 0, &id);
	if (rc)
		RETURN(rc);

	start = ++end;
	if (start - str >= len - 1)
		RETURN(-EINVAL);

	end = strchr(start, '#');
	if (!end || end == start)
		RETURN(-EINVAL);

	*end = '\0';
	rc = kstrtoull(start, 0, &seq);
	if (rc)
		RETURN(rc);

	ostid_set_seq(&logid->lgl_oi, seq);
	if (ostid_set_id(&logid->lgl_oi, id))
		RETURN(-EINVAL);

	start = ++end;
	if (start - str >= len - 1)
		RETURN(-EINVAL);

	rc = kstrtouint(start, 16, &ogen);
	if (rc)
                RETURN(-EINVAL);
	logid->lgl_ogen = ogen;

	RETURN(0);
#else
	RETURN(-EINVAL);
#endif
}

static int llog_check_cb(const struct lu_env *env, struct llog_handle *handle,
			 struct llog_rec_hdr *rec, void *data)
{
	struct obd_ioctl_data *ioc_data = data;
	static int l, remains;
	static long from, to;
	static char *out;
	int cur_index;
	int rc = 0;

	ENTRY;
	if (ioc_data && ioc_data->ioc_inllen1 > 0) {
		l = 0;
		remains = ioc_data->ioc_inllen4 +
			  round_up(ioc_data->ioc_inllen1, 8) +
			  round_up(ioc_data->ioc_inllen2, 8) +
			  round_up(ioc_data->ioc_inllen3, 8);

		rc = kstrtol(ioc_data->ioc_inlbuf2, 0, &from);
		if (rc)
			RETURN(rc);

		rc = kstrtol(ioc_data->ioc_inlbuf3, 0, &to);
		if (rc)
			RETURN(rc);

		ioc_data->ioc_inllen1 = 0;
		out = ioc_data->ioc_bulk;
	}

	cur_index = rec->lrh_index;
	if (cur_index < from)
		RETURN(0);
	if (to > 0 && cur_index > to)
		RETURN(-LLOG_EEMPTY);

	if (handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT) {
		struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
		struct llog_handle *loghandle;

		if (rec->lrh_type != LLOG_LOGID_MAGIC) {
			l = snprintf(out, remains,
				     "[index]: %05d  [type]: %02x  [len]: %04d failed\n",
				     cur_index, rec->lrh_type,
				     rec->lrh_len);
		}
		if (handle->lgh_ctxt == NULL)
			RETURN(-EOPNOTSUPP);
		rc = llog_cat_id2handle(env, handle, &loghandle, &lir->lid_id);
		if (rc) {
			CDEBUG(D_IOCTL, "cannot find log "DFID":%x\n",
			       PFID(&lir->lid_id.lgl_oi.oi_fid),
			       lir->lid_id.lgl_ogen);
			RETURN(rc);
		}
		rc = llog_process(env, loghandle, llog_check_cb, NULL, NULL);
		llog_handle_put(env, loghandle);
	} else {
		bool ok;

		switch (rec->lrh_type) {
		case OST_SZ_REC:
		case MDS_UNLINK_REC:
		case MDS_UNLINK64_REC:
		case MDS_SETATTR64_REC:
		case OBD_CFG_REC:
		case LLOG_GEN_REC:
		case LLOG_HDR_MAGIC:
			ok = true;
			break;
		default:
			ok = false;
		}

		l = snprintf(out, remains, "[index]: %05d  [type]: "
			     "%02x  [len]: %04d %s\n",
			     cur_index, rec->lrh_type, rec->lrh_len,
			     ok ? "ok" : "failed");
		out += l;
		remains -= l;
		if (remains <= 0) {
			CERROR("%s: no space to print log records\n",
			       handle->lgh_ctxt->loc_obd->obd_name);
			RETURN(-LLOG_EEMPTY);
		}
	}
	RETURN(rc);
}

static int llog_print_cb(const struct lu_env *env, struct llog_handle *handle,
			 struct llog_rec_hdr *rec, void *data)
{
	struct obd_ioctl_data *ioc_data = data;
	static int l, remains;
	static long from, to;
	static char *out;
	int cur_index;
	int rc;

	ENTRY;
	if (ioc_data && ioc_data->ioc_inllen1 > 0) {
		l = 0;
		remains = ioc_data->ioc_inllen4 +
			  round_up(ioc_data->ioc_inllen1, 8) +
			  round_up(ioc_data->ioc_inllen2, 8) +
			  round_up(ioc_data->ioc_inllen3, 8);

		rc = kstrtol(ioc_data->ioc_inlbuf2, 0, &from);
		if (rc)
			RETURN(rc);

		rc = kstrtol(ioc_data->ioc_inlbuf3, 0, &to);
		if (rc)
			RETURN(rc);

		out = ioc_data->ioc_bulk;
		ioc_data->ioc_inllen1 = 0;
	}

	cur_index = rec->lrh_index;
	if (cur_index < from)
		RETURN(0);
	if (to > 0 && cur_index > to)
		RETURN(-LLOG_EEMPTY);

	if (handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT) {
		struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;

		if (rec->lrh_type != LLOG_LOGID_MAGIC) {
			CERROR("invalid record in catalog\n");
			RETURN(-EINVAL);
		}

		l = snprintf(out, remains,
			     "[index]: %05d  [logid]: "DFID":%x\n",
			     cur_index, PFID(&lir->lid_id.lgl_oi.oi_fid),
			     lir->lid_id.lgl_ogen);
	} else if (rec->lrh_type == OBD_CFG_REC) {
		int rc;

		rc = class_config_yaml_output(rec, out, remains);
		if (rc < 0)
			RETURN(rc);
		l = rc;
	} else {
		l = snprintf(out, remains,
			     "[index]: %05d  [type]: %02x  [len]: %04d\n",
			     cur_index, rec->lrh_type, rec->lrh_len);
	}
	out += l;
	remains -= l;
	if (remains <= 0) {
		CERROR("not enough space for print log records\n");
		RETURN(-LLOG_EEMPTY);
	}

	RETURN(0);
}
static int llog_remove_log(const struct lu_env *env, struct llog_handle *cat,
			   struct llog_logid *logid)
{
	struct llog_handle *log;
	int rc;

	ENTRY;

	rc = llog_cat_id2handle(env, cat, &log, logid);
	if (rc) {
		CDEBUG(D_IOCTL, "cannot find log "DFID":%x\n",
		       PFID(&logid->lgl_oi.oi_fid), logid->lgl_ogen);
		RETURN(-ENOENT);
	}

	rc = llog_destroy(env, log);
	if (rc) {
		CDEBUG(D_IOCTL, "cannot destroy log "DFID":%x\n",
		       PFID(&logid->lgl_oi.oi_fid), logid->lgl_ogen);
		GOTO(out, rc);
	}
	llog_cat_cleanup(env, cat, log, log->u.phd.phd_cookie.lgc_index);
out:
	llog_handle_put(env, log);
	RETURN(rc);

}

static int llog_delete_cb(const struct lu_env *env, struct llog_handle *handle,
			  struct llog_rec_hdr *rec, void *data)
{
	struct llog_logid_rec *lir = (struct llog_logid_rec *)rec;
	int rc;

	ENTRY;
	if (rec->lrh_type != LLOG_LOGID_MAGIC)
		RETURN(-EINVAL);
	rc = llog_remove_log(env, handle, &lir->lid_id);

	RETURN(rc);
}


int llog_ioctl(const struct lu_env *env, struct llog_ctxt *ctxt, int cmd,
	       struct obd_ioctl_data *data)
{
	struct llog_logid logid;
	int rc = 0;
	struct llog_handle *handle = NULL;
	char *logname, start;

	ENTRY;

	logname = data->ioc_inlbuf1;
	start = logname[0];
	if (start == '#' || start == '[') {
		rc = str2logid(&logid, logname, data->ioc_inllen1);
		if (rc)
			RETURN(rc);
		rc = llog_open(env, ctxt, &handle, &logid, NULL,
			       LLOG_OPEN_EXISTS);
		if (rc)
			RETURN(rc);
	} else if (start == '$' || isalpha(start) || isdigit(start)) {
		if (start == '$')
			logname++;

		rc = llog_open(env, ctxt, &handle, NULL, logname,
			       LLOG_OPEN_EXISTS);
		if (rc)
			RETURN(rc);
	} else {
		rc = -EINVAL;
		CDEBUG(D_INFO, "%s: invalid log name '%s': rc = %d\n",
		      ctxt->loc_obd->obd_name, logname, rc);
		RETURN(rc);
	}

	rc = llog_init_handle(env, handle, 0, NULL);
	if (rc)
		GOTO(out_close, rc = -ENOENT);

	switch (cmd) {
	case OBD_IOC_LLOG_INFO: {
		int l;
		int remains = data->ioc_inllen2 +
				   cfs_size_round(data->ioc_inllen1);
		char *out = data->ioc_bulk;

		l = snprintf(out, remains,
			     "logid:            "DFID":%x\n"
			     "flags:            %x (%s)\n"
			     "records_count:    %d\n"
			     "last_index:       %d\n",
			     PFID(&handle->lgh_id.lgl_oi.oi_fid),
			     handle->lgh_id.lgl_ogen,
			     handle->lgh_hdr->llh_flags,
			     handle->lgh_hdr->llh_flags &
				LLOG_F_IS_CAT ? "cat" : "plain",
			     handle->lgh_hdr->llh_count,
			     handle->lgh_last_idx);
		out += l;
		remains -= l;
		if (remains <= 0) {
			CERROR("%s: not enough space for log header info\n",
			       ctxt->loc_obd->obd_name);
			rc = -ENOSPC;
		}
		break;
	}
	case OBD_IOC_LLOG_CHECK:
		LASSERT(data->ioc_inllen1 > 0);
		rc = llog_process(env, handle, llog_check_cb, data, NULL);
		if (rc == -LLOG_EEMPTY)
			rc = 0;
		else if (rc)
			GOTO(out_close, rc);
		break;
	case OBD_IOC_LLOG_PRINT:
		LASSERT(data->ioc_inllen1 > 0);
		rc = llog_process(env, handle, llog_print_cb, data, NULL);
		if (rc == -LLOG_EEMPTY)
			rc = 0;
		else if (rc)
			GOTO(out_close, rc);
		break;
	case OBD_IOC_LLOG_CANCEL: {
		struct llog_cookie cookie;
		struct llog_logid plain;
		u32 lgc_index;

		rc = kstrtouint(data->ioc_inlbuf3, 0, &lgc_index);
		if (rc)
			GOTO(out_close, rc);
		cookie.lgc_index = lgc_index;

		if (handle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN) {
			rc = llog_cancel_rec(env, handle, cookie.lgc_index);
			GOTO(out_close, rc);
		} else if (!(handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)) {
			GOTO(out_close, rc = -EINVAL);
		}

		if (data->ioc_inlbuf2 == NULL) /* catalog but no logid */
			GOTO(out_close, rc = -ENOTTY);

		rc = str2logid(&plain, data->ioc_inlbuf2, data->ioc_inllen2);
		if (rc)
			GOTO(out_close, rc);
		cookie.lgc_lgl = plain;
		rc = llog_cat_cancel_records(env, handle, 1, &cookie);
		if (rc)
			GOTO(out_close, rc);
		break;
	}
	case OBD_IOC_LLOG_REMOVE: {
		struct llog_logid plain;

		if (handle->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN) {
			rc = llog_destroy(env, handle);
			GOTO(out_close, rc);
		} else if (!(handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)) {
			GOTO(out_close, rc = -EINVAL);
		}

		if (data->ioc_inlbuf2 > 0) {
			/* remove indicate log from the catalog */
			rc = str2logid(&plain, data->ioc_inlbuf2,
				       data->ioc_inllen2);
			if (rc)
				GOTO(out_close, rc);
			rc = llog_remove_log(env, handle, &plain);
		} else {
			/* remove all the log of the catalog */
			rc = llog_process(env, handle, llog_delete_cb, NULL,
					  NULL);
			if (rc)
				GOTO(out_close, rc);
		}
		break;
	}
	default:
		CERROR("%s: Unknown ioctl cmd %#x\n",
		       ctxt->loc_obd->obd_name, cmd);
		GOTO(out_close, rc = -ENOTTY);
	}

out_close:
	if (handle->lgh_hdr &&
	    handle->lgh_hdr->llh_flags & LLOG_F_IS_CAT)
		llog_cat_close(env, handle);
	else
		llog_close(env, handle);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_ioctl);

int llog_catalog_list(const struct lu_env *env, struct dt_device *d,
		      int count, struct obd_ioctl_data *data,
		      const struct lu_fid *fid)
{
	int size, i;
	struct llog_catid *idarray;
	struct llog_logid *id;
	char *out;
	int l, remains, rc = 0;

	ENTRY;

	if (count == 0) { /* get total number of logs */
		rc = llog_osd_get_cat_list(env, d, 0, 0, NULL, fid);
		if (rc < 0)
			RETURN(rc);
		count = rc;
	}

	size = sizeof(*idarray) * count;

	OBD_ALLOC_LARGE(idarray, size);
	if (!idarray)
		RETURN(-ENOMEM);

	rc = llog_osd_get_cat_list(env, d, 0, count, idarray, fid);
	if (rc)
		GOTO(out, rc);

	out = data->ioc_bulk;
	remains = data->ioc_inllen1;
	/* OBD_FAIL: fetch the catalog records from the specified one */
	if (OBD_FAIL_CHECK(OBD_FAIL_CATLIST))
		data->ioc_count = cfs_fail_val - 1;
	for (i = data->ioc_count; i < count; i++) {
		id = &idarray[i].lci_logid;
		l = snprintf(out, remains, "catalog_log: "DFID":%x\n",
			      PFID(&id->lgl_oi.oi_fid), id->lgl_ogen);
		out += l;
		remains -= l;
		if (remains <= 0) {
			if (remains < 0) {
				/* the print is not complete */
				remains += l;
				data->ioc_bulk[out - data->ioc_bulk - l] = '\0';
				data->ioc_count = i;
			} else {
				data->ioc_count = i++;
			}
			goto out;
		}
	}
	data->ioc_count = 0;
out:
	OBD_FREE_LARGE(idarray, size);
	RETURN(rc);
}
EXPORT_SYMBOL(llog_catalog_list);
