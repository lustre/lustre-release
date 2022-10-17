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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/selftest/conctl.c
 *
 * IOC handle in kernel
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 */

#include <libcfs/linux/linux-net.h>
#include <libcfs/libcfs.h>
#include <lnet/lib-lnet.h>
#include "console.h"

static int
lst_debug_ioctl(struct lstio_debug_args *args)
{
	char *name = NULL;
	int client = 1;
	int rc;

	if (args->lstio_dbg_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_dbg_resultp == NULL)
		return -EINVAL;

	if (args->lstio_dbg_namep != NULL && /* name of batch/group */
	    (args->lstio_dbg_nmlen <= 0 ||
	     args->lstio_dbg_nmlen > LST_NAME_SIZE))
		return -EINVAL;

	if (args->lstio_dbg_namep != NULL) {
		LIBCFS_ALLOC(name, args->lstio_dbg_nmlen + 1);
		if (name == NULL)
			return -ENOMEM;

		if (copy_from_user(name, args->lstio_dbg_namep,
				   args->lstio_dbg_nmlen)) {
			LIBCFS_FREE(name, args->lstio_dbg_nmlen + 1);

			return -EFAULT;
		}

		name[args->lstio_dbg_nmlen] = 0;
	}

	rc = -EINVAL;

	switch (args->lstio_dbg_type) {
	case LST_OPC_SESSION:
		rc = lstcon_session_debug(args->lstio_dbg_timeout,
					  args->lstio_dbg_resultp);
		break;

	case LST_OPC_BATCHSRV:
		client = 0;
		fallthrough;
	case LST_OPC_BATCHCLI:
		if (name == NULL)
			goto out;

		rc = lstcon_batch_debug(args->lstio_dbg_timeout,
					name, client, args->lstio_dbg_resultp);
		break;

	case LST_OPC_GROUP:
		if (name == NULL)
			goto out;

		rc = lstcon_group_debug(args->lstio_dbg_timeout,
					name, args->lstio_dbg_resultp);
		break;

	case LST_OPC_NODES:
		if (args->lstio_dbg_count <= 0 ||
		    args->lstio_dbg_idsp == NULL)
			goto out;

		rc = lstcon_nodes_debug(args->lstio_dbg_timeout,
					args->lstio_dbg_count,
					args->lstio_dbg_idsp,
					args->lstio_dbg_resultp);
		break;

	default:
		break;
	}

out:
	if (name != NULL)
		LIBCFS_FREE(name, args->lstio_dbg_nmlen + 1);

	return rc;
}

static int
lst_group_add_ioctl(struct lstio_group_add_args *args)
{
	char *name;
	int rc;

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_grp_namep == NULL ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_grp_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen)) {
		LIBCFS_FREE(name, args->lstio_grp_nmlen);
		return -EFAULT;
	}

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_group_add(name);

	LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);

	return rc;
}

static int
lst_group_del_ioctl(struct lstio_group_del_args *args)
{
	int rc;
	char *name;

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_grp_namep == NULL ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_grp_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen)) {
		LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_group_del(name);

	LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);

	return rc;
}

static int
lst_group_update_ioctl(struct lstio_group_update_args *args)
{
	int rc;
	char *name;

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_grp_resultp == NULL ||
	    args->lstio_grp_namep == NULL ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_grp_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen)) {
		LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_grp_nmlen] = 0;

	switch (args->lstio_grp_opc) {
	case LST_GROUP_CLEAN:
		rc = lstcon_group_clean(name, args->lstio_grp_args);
		break;

	case LST_GROUP_REFRESH:
		rc = lstcon_group_refresh(name, args->lstio_grp_resultp);
		break;

	case LST_GROUP_RMND:
		if (args->lstio_grp_count <= 0 ||
		    args->lstio_grp_idsp == NULL) {
			rc = -EINVAL;
			break;
		}
		rc = lstcon_nodes_remove(name, args->lstio_grp_count,
					 args->lstio_grp_idsp,
					 args->lstio_grp_resultp);
		break;

	default:
		rc = -EINVAL;
		break;
	}

	LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);

	return rc;
}

static int
lst_nodes_add_ioctl(struct lstio_group_nodes_args *args)
{
	unsigned int feats;
	int rc;
	char *name;

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_grp_idsp == NULL || /* array of ids */
	    args->lstio_grp_count <= 0 ||
	    args->lstio_grp_resultp == NULL ||
	    args->lstio_grp_featp == NULL ||
	    args->lstio_grp_namep == NULL ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_grp_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen)) {
		LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);

		return -EFAULT;
	}

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_nodes_add(name, args->lstio_grp_count,
			      args->lstio_grp_idsp, &feats,
			      args->lstio_grp_resultp);

	LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);
	if (rc == 0 &&
	    copy_to_user(args->lstio_grp_featp, &feats, sizeof(feats))) {
		return -EINVAL;
	}

	return rc;
}

static int
lst_group_list_ioctl(struct lstio_group_list_args *args)
{
	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_grp_idx   < 0 ||
	    args->lstio_grp_namep == NULL ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	return lstcon_group_list(args->lstio_grp_idx,
				 args->lstio_grp_nmlen,
				 args->lstio_grp_namep);
}

static int
lst_group_info_ioctl(struct lstio_group_info_args *args)
{
	char *name;
	int ndent;
	int index;
	int rc;

	if (args->lstio_grp_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_grp_namep == NULL ||
	    args->lstio_grp_nmlen <= 0 ||
	    args->lstio_grp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (args->lstio_grp_entp == NULL && /* output: group entry */
	    args->lstio_grp_dentsp == NULL)  /* output: node entry */
		return -EINVAL;

	if (args->lstio_grp_dentsp != NULL) { /* have node entry */
		if (args->lstio_grp_idxp == NULL || /* node index */
		    args->lstio_grp_ndentp == NULL) /* # of node entry */
			return -EINVAL;

		if (copy_from_user(&ndent, args->lstio_grp_ndentp,
				   sizeof(ndent)) ||
		    copy_from_user(&index, args->lstio_grp_idxp,
				   sizeof(index)))
			return -EFAULT;

		if (ndent <= 0 || index < 0)
			return -EINVAL;
	}

	LIBCFS_ALLOC(name, args->lstio_grp_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_grp_namep,
			   args->lstio_grp_nmlen)) {
		LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_grp_nmlen] = 0;

	rc = lstcon_group_info(name, args->lstio_grp_entp,
			       &index, &ndent, args->lstio_grp_dentsp);

	LIBCFS_FREE(name, args->lstio_grp_nmlen + 1);

	if (rc != 0)
		return rc;

	if (args->lstio_grp_dentsp != NULL &&
	    (copy_to_user(args->lstio_grp_idxp, &index, sizeof(index)) ||
	     copy_to_user(args->lstio_grp_ndentp, &ndent, sizeof(ndent))))
		return -EFAULT;

	return 0;
}

static int
lst_batch_add_ioctl(struct lstio_batch_add_args *args)
{
	int rc;
	char *name;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_namep == NULL ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_bat_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen)) {
		LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_add(name);

	LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);

	return rc;
}

static int
lst_batch_run_ioctl(struct lstio_batch_run_args *args)
{
	int rc;
	char *name;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_namep == NULL ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_bat_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen)) {
		LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_run(name, args->lstio_bat_timeout,
			      args->lstio_bat_resultp);

	LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);

	return rc;
}

static int
lst_batch_stop_ioctl(struct lstio_batch_stop_args *args)
{
	int rc;
	char *name;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_resultp == NULL ||
	    args->lstio_bat_namep == NULL ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_bat_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen)) {
		LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_stop(name, args->lstio_bat_force,
			       args->lstio_bat_resultp);

	LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);

	return rc;
}

static int
lst_batch_query_ioctl(struct lstio_batch_query_args *args)
{
	char *name;
	int rc;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_resultp == NULL ||
	    args->lstio_bat_namep == NULL ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (args->lstio_bat_testidx < 0)
		return -EINVAL;

	LIBCFS_ALLOC(name, args->lstio_bat_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen)) {
		LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_test_batch_query(name,
				     args->lstio_bat_testidx,
				     args->lstio_bat_client,
				     args->lstio_bat_timeout,
				     args->lstio_bat_resultp);

	LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);

	return rc;
}

static int
lst_batch_list_ioctl(struct lstio_batch_list_args *args)
{
	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_idx < 0 ||
	    args->lstio_bat_namep == NULL ||
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	return lstcon_batch_list(args->lstio_bat_idx,
				 args->lstio_bat_nmlen,
				 args->lstio_bat_namep);
}

static int
lst_batch_info_ioctl(struct lstio_batch_info_args *args)
{
	char *name;
	int rc;
	int index;
	int ndent;

	if (args->lstio_bat_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_bat_namep == NULL || /* batch name */
	    args->lstio_bat_nmlen <= 0 ||
	    args->lstio_bat_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (args->lstio_bat_entp == NULL && /* output: batch entry */
	    args->lstio_bat_dentsp == NULL) /* output: node entry */
		return -EINVAL;

	if (args->lstio_bat_dentsp != NULL) { /* have node entry */
		if (args->lstio_bat_idxp == NULL || /* node index */
		    args->lstio_bat_ndentp == NULL) /* # of node entry */
			return -EINVAL;

		if (copy_from_user(&index, args->lstio_bat_idxp,
				   sizeof(index)) ||
		    copy_from_user(&ndent, args->lstio_bat_ndentp,
				   sizeof(ndent)))
			return -EFAULT;

		if (ndent <= 0 || index < 0)
			return -EINVAL;
	}

	LIBCFS_ALLOC(name, args->lstio_bat_nmlen + 1);
	if (name == NULL)
		return -ENOMEM;

	if (copy_from_user(name, args->lstio_bat_namep,
			   args->lstio_bat_nmlen)) {
		LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);
		return -EFAULT;
	}

	name[args->lstio_bat_nmlen] = 0;

	rc = lstcon_batch_info(name,
			       args->lstio_bat_entp, args->lstio_bat_server,
			       args->lstio_bat_testidx, &index, &ndent,
			       args->lstio_bat_dentsp);

	LIBCFS_FREE(name, args->lstio_bat_nmlen + 1);

	if (rc != 0)
		return rc;

	if (args->lstio_bat_dentsp != NULL &&
	    (copy_to_user(args->lstio_bat_idxp, &index, sizeof(index)) ||
	     copy_to_user(args->lstio_bat_ndentp, &ndent, sizeof(ndent))))
		rc = -EFAULT;

	return rc;
}

static int
lst_stat_query_ioctl(struct lstio_stat_args *args)
{
	int rc;
	char *name = NULL;

	/* TODO: not finished */
	if (args->lstio_sta_key != console_session.ses_key)
		return -EACCES;

	if (args->lstio_sta_resultp == NULL)
		return -EINVAL;

	if (args->lstio_sta_idsp != NULL) {
		if (args->lstio_sta_count <= 0)
			return -EINVAL;

		rc = lstcon_nodes_stat(args->lstio_sta_count,
				       args->lstio_sta_idsp,
				       args->lstio_sta_timeout,
				       args->lstio_sta_resultp);
	} else if (args->lstio_sta_namep != NULL) {
		if (args->lstio_sta_nmlen <= 0 ||
		    args->lstio_sta_nmlen > LST_NAME_SIZE)
			return -EINVAL;

		LIBCFS_ALLOC(name, args->lstio_sta_nmlen + 1);
		if (name == NULL)
			return -ENOMEM;

		rc = copy_from_user(name, args->lstio_sta_namep,
				    args->lstio_sta_nmlen);
		if (rc == 0)
			rc = lstcon_group_stat(name, args->lstio_sta_timeout,
					       args->lstio_sta_resultp);
		else
			rc = -EFAULT;

	} else {
		rc = -EINVAL;
	}

	if (name != NULL)
		LIBCFS_FREE(name, args->lstio_sta_nmlen + 1);
	return rc;
}

static int lst_test_add_ioctl(struct lstio_test_args *args)
{
	char *batch_name;
	char *src_name = NULL;
	char *dst_name = NULL;
	void *param = NULL;
	int ret = 0;
	int rc = -ENOMEM;

	if (args->lstio_tes_resultp == NULL ||
	    args->lstio_tes_retp == NULL ||
	    args->lstio_tes_bat_name == NULL || /* no specified batch */
	    args->lstio_tes_bat_nmlen <= 0 ||
	    args->lstio_tes_bat_nmlen > LST_NAME_SIZE ||
	    args->lstio_tes_sgrp_name == NULL || /* no source group */
	    args->lstio_tes_sgrp_nmlen <= 0 ||
	    args->lstio_tes_sgrp_nmlen > LST_NAME_SIZE ||
	    args->lstio_tes_dgrp_name == NULL || /* no target group */
	    args->lstio_tes_dgrp_nmlen <= 0 ||
	    args->lstio_tes_dgrp_nmlen > LST_NAME_SIZE)
		return -EINVAL;

	if (args->lstio_tes_loop == 0 || /* negative is infinite */
	    args->lstio_tes_concur <= 0 ||
	    args->lstio_tes_dist <= 0 ||
	    args->lstio_tes_span <= 0)
		return -EINVAL;

	/* have parameter, check if parameter length is valid */
	if (args->lstio_tes_param != NULL &&
	    (args->lstio_tes_param_len <= 0 ||
	     args->lstio_tes_param_len >
	     PAGE_SIZE - sizeof(struct lstcon_test)))
		return -EINVAL;

	LIBCFS_ALLOC(batch_name, args->lstio_tes_bat_nmlen + 1);
	if (batch_name == NULL)
		return rc;

	LIBCFS_ALLOC(src_name, args->lstio_tes_sgrp_nmlen + 1);
	if (src_name == NULL)
		goto out;

	LIBCFS_ALLOC(dst_name, args->lstio_tes_dgrp_nmlen + 1);
	if (dst_name == NULL)
		goto out;

	if (args->lstio_tes_param != NULL) {
		LIBCFS_ALLOC(param, args->lstio_tes_param_len);
		if (param == NULL)
			goto out;
		if (copy_from_user(param, args->lstio_tes_param,
				   args->lstio_tes_param_len)) {
			rc = -EFAULT;
			goto out;
		}
	}

	rc = -EFAULT;
	if (copy_from_user(batch_name, args->lstio_tes_bat_name,
			   args->lstio_tes_bat_nmlen) ||
	    copy_from_user(src_name, args->lstio_tes_sgrp_name,
			   args->lstio_tes_sgrp_nmlen) ||
	    copy_from_user(dst_name, args->lstio_tes_dgrp_name,
			   args->lstio_tes_dgrp_nmlen))
		goto out;

	rc = lstcon_test_add(batch_name,
			     args->lstio_tes_type,
			     args->lstio_tes_loop,
			     args->lstio_tes_concur,
			     args->lstio_tes_dist, args->lstio_tes_span,
			     src_name, dst_name, param,
			     args->lstio_tes_param_len,
			     &ret, args->lstio_tes_resultp);

	if (ret != 0)
		rc = (copy_to_user(args->lstio_tes_retp, &ret,
				   sizeof(ret))) ? -EFAULT : 0;
out:
	if (batch_name != NULL)
		LIBCFS_FREE(batch_name, args->lstio_tes_bat_nmlen + 1);

	if (src_name != NULL)
		LIBCFS_FREE(src_name, args->lstio_tes_sgrp_nmlen + 1);

	if (dst_name != NULL)
		LIBCFS_FREE(dst_name, args->lstio_tes_dgrp_nmlen + 1);

	if (param != NULL)
		LIBCFS_FREE(param, args->lstio_tes_param_len);

	return rc;
}

int
lstcon_ioctl_entry(struct notifier_block *nb,
		   unsigned long cmd, void *vdata)
{
	struct libcfs_ioctl_hdr *hdr = vdata;
	struct libcfs_ioctl_data *data;
	char *buf = NULL;
	int rc = -EINVAL;
	int opc;

	if (cmd != IOC_LIBCFS_LNETST)
		goto err;

	data = container_of(hdr, struct libcfs_ioctl_data, ioc_hdr);

	opc = data->ioc_u32[0];

	if (data->ioc_plen1 > PAGE_SIZE)
		goto err;

	LIBCFS_ALLOC(buf, data->ioc_plen1);
	if (buf == NULL) {
		rc = -ENOMEM;
		goto err;
	}

	/* copy in parameter */
	if (copy_from_user(buf, data->ioc_pbuf1, data->ioc_plen1)) {
		rc = -EFAULT;
		goto out_free_buf;
	}

	mutex_lock(&console_session.ses_mutex);

	console_session.ses_laststamp = ktime_get_real_seconds();

	if (console_session.ses_shutdown) {
		rc = -ESHUTDOWN;
		goto out;
	}

	if (console_session.ses_expired)
		lstcon_session_end();

	if (opc != LSTIO_SESSION_NEW &&
	    console_session.ses_state == LST_SESSION_NONE) {
		CDEBUG(D_NET, "LST no active session\n");
		rc = -ESRCH;
		goto out;
	}

	memset(&console_session.ses_trans_stat, 0,
	       sizeof(struct lstcon_trans_stat));

	switch (opc) {
	case LSTIO_SESSION_NEW:
		fallthrough;
	case LSTIO_SESSION_END:
		fallthrough;
	case LSTIO_SESSION_INFO:
		rc = -EOPNOTSUPP;
		break;
	case LSTIO_DEBUG:
		rc = lst_debug_ioctl((struct lstio_debug_args *)buf);
		break;
	case LSTIO_GROUP_ADD:
		rc = lst_group_add_ioctl((struct lstio_group_add_args *)buf);
		break;
	case LSTIO_GROUP_DEL:
		rc = lst_group_del_ioctl((struct lstio_group_del_args *)buf);
		break;
	case LSTIO_GROUP_UPDATE:
		rc = lst_group_update_ioctl((struct lstio_group_update_args *)buf);
		break;
	case LSTIO_NODES_ADD:
		rc = lst_nodes_add_ioctl((struct lstio_group_nodes_args *)buf);
		break;
	case LSTIO_GROUP_LIST:
		rc = lst_group_list_ioctl((struct lstio_group_list_args *)buf);
		break;
	case LSTIO_GROUP_INFO:
		rc = lst_group_info_ioctl((struct lstio_group_info_args *)buf);
		break;
	case LSTIO_BATCH_ADD:
		rc = lst_batch_add_ioctl((struct lstio_batch_add_args *)buf);
		break;
	case LSTIO_BATCH_START:
		rc = lst_batch_run_ioctl((struct lstio_batch_run_args *)buf);
		break;
	case LSTIO_BATCH_STOP:
		rc = lst_batch_stop_ioctl((struct lstio_batch_stop_args *)buf);
		break;
	case LSTIO_BATCH_QUERY:
		rc = lst_batch_query_ioctl((struct lstio_batch_query_args *)buf);
		break;
	case LSTIO_BATCH_LIST:
		rc = lst_batch_list_ioctl((struct lstio_batch_list_args *)buf);
		break;
	case LSTIO_BATCH_INFO:
		rc = lst_batch_info_ioctl((struct lstio_batch_info_args *)buf);
		break;
	case LSTIO_TEST_ADD:
		rc = lst_test_add_ioctl((struct lstio_test_args *)buf);
		break;
	case LSTIO_STAT_QUERY:
		rc = lst_stat_query_ioctl((struct lstio_stat_args *)buf);
		break;
	default:
		rc = -EINVAL;
		goto out;
	}

	if (copy_to_user(data->ioc_pbuf2, &console_session.ses_trans_stat,
			 sizeof(struct lstcon_trans_stat)))
		rc = -EFAULT;
out:
	mutex_unlock(&console_session.ses_mutex);
out_free_buf:
	LIBCFS_FREE(buf, data->ioc_plen1);
err:
	return notifier_from_ioctl_errno(rc);
}

static struct genl_family lst_family;

static const struct ln_key_list lst_session_keys = {
	.lkl_maxattr			= LNET_SELFTEST_SESSION_MAX,
	.lkl_list			= {
		[LNET_SELFTEST_SESSION_HDR]	= {
			.lkp_value		= "session",
			.lkp_key_format		= LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LNET_SELFTEST_SESSION_NAME]	= {
			.lkp_value		= "name",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_SELFTEST_SESSION_KEY]	= {
			.lkp_value		= "key",
			.lkp_data_type		= NLA_U32,
		},
		[LNET_SELFTEST_SESSION_TIMESTAMP] = {
			.lkp_value		= "timestamp",
			.lkp_data_type		= NLA_S64,
		},
		[LNET_SELFTEST_SESSION_NID]	= {
			.lkp_value		= "nid",
			.lkp_data_type		= NLA_STRING,
		},
		[LNET_SELFTEST_SESSION_NODE_COUNT] = {
			.lkp_value		= "nodes",
			.lkp_data_type		= NLA_U16,
		},
	},
};

static int lst_sessions_show_dump(struct sk_buff *msg,
				  struct netlink_callback *cb)
{
	const struct ln_key_list *all[] = {
		&lst_session_keys, NULL
	};
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	unsigned int node_count = 0;
	struct lstcon_ndlink *ndl;
	int flag = NLM_F_MULTI;
	int rc = 0;
	void *hdr;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (console_session.ses_state != LST_SESSION_ACTIVE) {
		NL_SET_ERR_MSG(extack, "session is not active");
		GOTO(out_unlock, rc = -ESRCH);
	}

	list_for_each_entry(ndl, &console_session.ses_ndl_list, ndl_link)
		node_count++;

	rc = lnet_genl_send_scalar_list(msg, portid, seq, &lst_family,
					NLM_F_CREATE | NLM_F_MULTI,
					LNET_SELFTEST_CMD_SESSIONS, all);
	if (rc < 0) {
		NL_SET_ERR_MSG(extack, "failed to send key table");
		GOTO(out_unlock, rc);
	}

	if (console_session.ses_force)
		flag |= NLM_F_REPLACE;

	hdr = genlmsg_put(msg, portid, seq, &lst_family, flag,
			  LNET_SELFTEST_CMD_SESSIONS);
	if (!hdr) {
		NL_SET_ERR_MSG(extack, "failed to send values");
		genlmsg_cancel(msg, hdr);
		GOTO(out_unlock, rc = -EMSGSIZE);
	}

	nla_put_string(msg, LNET_SELFTEST_SESSION_NAME,
		       console_session.ses_name);
	nla_put_u32(msg, LNET_SELFTEST_SESSION_KEY,
		    console_session.ses_key);
	nla_put_u64_64bit(msg, LNET_SELFTEST_SESSION_TIMESTAMP,
			  console_session.ses_id.ses_stamp,
			  LNET_SELFTEST_SESSION_PAD);
	nla_put_string(msg, LNET_SELFTEST_SESSION_NID,
		       libcfs_nidstr(&console_session.ses_id.ses_nid));
	nla_put_u16(msg, LNET_SELFTEST_SESSION_NODE_COUNT,
		    node_count);
	genlmsg_end(msg, hdr);
out_unlock:
	return lnet_nl_send_error(cb->skb, portid, seq, rc);
}

static int lst_sessions_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg = NULL;
	int rc = 0;

	mutex_lock(&console_session.ses_mutex);

	console_session.ses_laststamp = ktime_get_real_seconds();

	if (console_session.ses_shutdown) {
		GENL_SET_ERR_MSG(info, "session is shutdown");
		GOTO(out_unlock, rc = -ESHUTDOWN);
	}

	if (console_session.ses_expired)
		lstcon_session_end();

	if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE) &&
	    console_session.ses_state == LST_SESSION_NONE) {
		GENL_SET_ERR_MSG(info, "session is not active");
		GOTO(out_unlock, rc = -ESRCH);
	}

	memset(&console_session.ses_trans_stat, 0,
	       sizeof(struct lstcon_trans_stat));

	if (!(info->nlhdr->nlmsg_flags & NLM_F_CREATE)) {
		lstcon_session_end();
		GOTO(out_unlock, rc);
	}

	if (info->attrs[LN_SCALAR_ATTR_LIST]) {
		struct genlmsghdr *gnlh = nlmsg_data(info->nlhdr);
		const struct ln_key_list *all[] = {
			&lst_session_keys, NULL
		};
		char name[LST_NAME_SIZE];
		struct nlmsghdr *nlh;
		struct nlattr *item;
		bool force = false;
		s64 timeout = 300;
		void *hdr;
		int rem;

		if (info->nlhdr->nlmsg_flags & NLM_F_REPLACE)
			force = true;

		nla_for_each_nested(item, info->attrs[LN_SCALAR_ATTR_LIST],
				    rem) {
			if (nla_type(item) != LN_SCALAR_ATTR_VALUE)
				continue;

			if (nla_strcmp(item, "name") == 0) {
				ssize_t len;

				item = nla_next(item, &rem);
				if (nla_type(item) != LN_SCALAR_ATTR_VALUE)
					GOTO(err_conf, rc = -EINVAL);

				len = nla_strscpy(name, item, sizeof(name));
				if (len < 0)
					rc = len;
			} else if (nla_strcmp(item, "timeout") == 0) {
				item = nla_next(item, &rem);
				if (nla_type(item) !=
				    LN_SCALAR_ATTR_INT_VALUE)
					GOTO(err_conf, rc = -EINVAL);

				timeout = nla_get_s64(item);
				if (timeout < 0)
					rc = -ERANGE;
			}
			if (rc < 0) {
err_conf:
				GENL_SET_ERR_MSG(info,
						 "failed to get config");
				GOTO(out_unlock, rc);
			}
		}

		rc = lstcon_session_new(name, info->nlhdr->nlmsg_pid,
					gnlh->version, timeout,
					force);
		if (rc < 0) {
			GENL_SET_ERR_MSG(info, "new session creation failed");
			lstcon_session_end();
			GOTO(out_unlock, rc);
		}

		msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
		if (!msg) {
			GENL_SET_ERR_MSG(info, "msg allocation failed");
			GOTO(out_unlock, rc = -ENOMEM);
		}

		rc = lnet_genl_send_scalar_list(msg, info->snd_portid,
						info->snd_seq, &lst_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LNET_SELFTEST_CMD_SESSIONS,
						all);
		if (rc < 0) {
			GENL_SET_ERR_MSG(info, "failed to send key table");
			GOTO(out_unlock, rc);
		}

		hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
				  &lst_family, NLM_F_MULTI,
				  LNET_SELFTEST_CMD_SESSIONS);
		if (!hdr) {
			GENL_SET_ERR_MSG(info, "failed to send values");
			genlmsg_cancel(msg, hdr);
			GOTO(out_unlock, rc = -EMSGSIZE);
		}

		nla_put_string(msg, LNET_SELFTEST_SESSION_NAME,
			       console_session.ses_name);
		nla_put_u32(msg, LNET_SELFTEST_SESSION_KEY,
			    console_session.ses_key);
		nla_put_u64_64bit(msg, LNET_SELFTEST_SESSION_TIMESTAMP,
				  console_session.ses_id.ses_stamp,
				  LNET_SELFTEST_SESSION_PAD);
		nla_put_string(msg, LNET_SELFTEST_SESSION_NID,
			       libcfs_nidstr(&console_session.ses_id.ses_nid));
		nla_put_u16(msg, LNET_SELFTEST_SESSION_NODE_COUNT, 0);

		genlmsg_end(msg, hdr);

		nlh = nlmsg_put(msg, info->snd_portid, info->snd_seq,
				NLMSG_DONE, 0, NLM_F_MULTI);
		if (!nlh) {
			GENL_SET_ERR_MSG(info, "failed to complete message");
			genlmsg_cancel(msg, hdr);
			GOTO(out_unlock, rc = -ENOMEM);
		}
		rc = genlmsg_reply(msg, info);
		if (rc)
			GENL_SET_ERR_MSG(info, "failed to send reply");
	}
out_unlock:
	if (rc < 0 && msg)
		nlmsg_free(msg);
	mutex_unlock(&console_session.ses_mutex);
	return rc;
}

static const struct genl_multicast_group lst_mcast_grps[] = {
	{ .name = "sessions",		},
};

static const struct genl_ops lst_genl_ops[] = {
	{
		.cmd		= LNET_SELFTEST_CMD_SESSIONS,
		.dumpit		= lst_sessions_show_dump,
		.doit		= lst_sessions_cmd,
	},
};

static struct genl_family lst_family = {
	.name		= LNET_SELFTEST_GENL_NAME,
	.version	= LNET_SELFTEST_GENL_VERSION,
	.maxattr	= LN_SCALAR_MAX,
	.module		= THIS_MODULE,
	.ops		= lst_genl_ops,
	.n_ops		= ARRAY_SIZE(lst_genl_ops),
	.mcgrps		= lst_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lst_mcast_grps),
};

int lstcon_init_netlink(void)
{
	return genl_register_family(&lst_family);
}

void lstcon_fini_netlink(void)
{
	genl_unregister_family(&lst_family);
}
