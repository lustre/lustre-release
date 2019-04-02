/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 *
 * Copyright (c) 2018-2020 Data Direct Networks.
 *
 *   This file is part of Lustre, https://wiki.whamcloud.com/
 *
 *   Portals is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Portals is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   version 2 along with this program; If not, see
 *   http://www.gnu.org/licenses/gpl-2.0.html
 *
 * Author: Sonia Sharma
 */
/*
 * Copyright (c) 2020, Whamcloud.
 *
 */

#include <errno.h>
#include <limits.h>
#include <byteswap.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <libcfs/util/ioctl.h>
#include <linux/lnet/lnetctl.h>
#include "liblnd.h"
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <linux/lnet/lnet-dlc.h>
#include "liblnetconfig.h"

static inline bool
lnet_udsp_criteria_present(struct lnet_ud_nid_descr *descr)
{
	return descr->ud_net_id.udn_net_type != 0;
}

struct lnet_udsp *lnet_udsp_alloc(void)
{
	struct lnet_udsp *udsp;

	udsp = calloc(1, sizeof(*udsp));

	if (!udsp)
		return NULL;

	INIT_LIST_HEAD(&udsp->udsp_on_list);
	INIT_LIST_HEAD(&udsp->udsp_src.ud_addr_range);
	INIT_LIST_HEAD(&udsp->udsp_src.ud_net_id.udn_net_num_range);
	INIT_LIST_HEAD(&udsp->udsp_dst.ud_addr_range);
	INIT_LIST_HEAD(&udsp->udsp_dst.ud_net_id.udn_net_num_range);
	INIT_LIST_HEAD(&udsp->udsp_rte.ud_addr_range);
	INIT_LIST_HEAD(&udsp->udsp_rte.ud_net_id.udn_net_num_range);

	return udsp;
}

static void
lnet_udsp_nid_descr_free(struct lnet_ud_nid_descr *nid_descr, bool blk)
{
	struct list_head *net_range = &nid_descr->ud_net_id.udn_net_num_range;

	if (!lnet_udsp_criteria_present(nid_descr))
		return;

	/* memory management is a bit tricky here. When we allocate the
	 * memory to store the NID descriptor we allocate a large buffer
	 * for all the data, so we need to free the entire buffer at
	 * once. If the net is present the net_range->next points to that
	 * buffer otherwise if the ud_addr_range is present then it's the
	 * ud_addr_range.next
	 */
	if (blk) {
		if (!list_empty(net_range))
			free(net_range->next);
		else if (!list_empty(&nid_descr->ud_addr_range))
			free(nid_descr->ud_addr_range.next);
	} else {
		cfs_expr_list_free_list(net_range);
		cfs_expr_list_free_list(&nid_descr->ud_addr_range);
	}
}

void
lnet_udsp_free(struct lnet_udsp *udsp, bool blk)
{
	lnet_udsp_nid_descr_free(&udsp->udsp_src, blk);
	lnet_udsp_nid_descr_free(&udsp->udsp_dst, blk);
	lnet_udsp_nid_descr_free(&udsp->udsp_rte, blk);

	free(udsp);
}

static void
copy_range_info(void __user **bulk, void **buf, struct list_head *list,
		int count)
{
	struct lnet_range_expr *range_expr;
	struct cfs_range_expr *range;
	struct cfs_expr_list *exprs;
	int range_count = count;
	int i;

	if (range_count == 0)
		return;

	if (range_count == -1) {
		struct lnet_expressions *e;

		e = *bulk;
		range_count = e->le_count;
		*bulk += sizeof(*e);
	}

	exprs = *buf;
	INIT_LIST_HEAD(&exprs->el_link);
	INIT_LIST_HEAD(&exprs->el_exprs);
	list_add_tail(&exprs->el_link, list);
	*buf += sizeof(*exprs);

	for (i = 0; i < range_count; i++) {
		range_expr = *bulk;
		range = *buf;
		INIT_LIST_HEAD(&range->re_link);
		range->re_lo = range_expr->re_lo;
		range->re_hi = range_expr->re_hi;
		range->re_stride = range_expr->re_stride;
		list_add_tail(&range->re_link, &exprs->el_exprs);
		*bulk += sizeof(*range_expr);
		*buf += sizeof(*range);
	}
}

static int
copy_ioc_udsp_descr(struct lnet_ud_nid_descr *nid_descr, char *type,
		    void **bulk, __u32 *bulk_size)
{
	struct lnet_ioctl_udsp_descr *ioc_nid = *bulk;
	struct lnet_expressions *exprs;
	__u32 descr_type;
	int expr_count = 0;
	int range_count = 0;
	int i;
	__u32 size;
	int remaining_size = *bulk_size;
	void *tmp = *bulk;
	__u32 alloc_size;
	void *buf;
	size_t range_expr_s = sizeof(struct lnet_range_expr);
	size_t lnet_exprs_s = sizeof(struct lnet_expressions);

	/* criteria not present, skip over the static part of the
	 * bulk, which is included for each NID descriptor
	 */
	if (ioc_nid->iud_net.ud_net_type == 0) {
		remaining_size -= sizeof(*ioc_nid);
		if (remaining_size < 0)
			return -EINVAL;
		*bulk += sizeof(*ioc_nid);
		*bulk_size = remaining_size;
		return 0;
	}

	descr_type = ioc_nid->iud_src_hdr.ud_descr_type;
	if (descr_type != *(__u32 *)type)
		return -EINVAL;

	/* calculate the total size to verify we have enough buffer.
	 * Start of by finding how many ranges there are for the net
	 * expression.
	 */
	range_count = ioc_nid->iud_net.ud_net_num_expr.le_count;
	size = sizeof(*ioc_nid) + (range_count * range_expr_s);
	remaining_size -= size;
	if (remaining_size < 0)
		return -EINVAL;

	/* the number of expressions for the NID. IE 4 for IP, 1 for GNI */
	expr_count = ioc_nid->iud_src_hdr.ud_descr_count;
	/* point tmp to the beginning of the NID expressions */
	tmp += size;
	for (i = 0; i < expr_count; i++) {
		/* get the number of ranges per expression */
		exprs = tmp;
		range_count += exprs->le_count;
		size = (range_expr_s * exprs->le_count) + lnet_exprs_s;
		remaining_size -= size;
		if (remaining_size < 0)
			return -EINVAL;
		tmp += size;
	}

	*bulk_size = remaining_size;

	/* copy over the net type */
	nid_descr->ud_net_id.udn_net_type = ioc_nid->iud_net.ud_net_type;

	/* allocate the total memory required to copy this NID descriptor */
	alloc_size = (sizeof(struct cfs_expr_list) * (expr_count + 1)) +
		     (sizeof(struct cfs_range_expr) * (range_count));
	buf = calloc(alloc_size, 1);
	if (!buf)
		return -ENOMEM;

	/* copy over the net number range */
	range_count = ioc_nid->iud_net.ud_net_num_expr.le_count;
	*bulk += sizeof(*ioc_nid);
	copy_range_info(bulk, &buf, &nid_descr->ud_net_id.udn_net_num_range,
			range_count);

	/* copy over the NID descriptor */
	for (i = 0; i < expr_count; i++)
		copy_range_info(bulk, &buf, &nid_descr->ud_addr_range, -1);

	return 0;
}

struct lnet_udsp *
lnet_udsp_demarshal(void *bulk, __u32 bulk_size)
{
	struct lnet_ioctl_udsp *ioc_udsp;
	struct lnet_udsp *udsp;
	int rc = -ENOMEM;

	if (bulk_size < sizeof(*ioc_udsp))
		return NULL;

	udsp = lnet_udsp_alloc();
	if (!udsp)
		return NULL;

	ioc_udsp = bulk;

	udsp->udsp_action_type = ioc_udsp->iou_action_type;
	udsp->udsp_action.udsp_priority = ioc_udsp->iou_action.priority;
	udsp->udsp_idx = ioc_udsp->iou_idx;

	bulk = ioc_udsp->iou_bulk;
	bulk_size -= sizeof(*ioc_udsp);

	if (bulk_size != ioc_udsp->iou_bulk_size)
		goto failed;

	rc = copy_ioc_udsp_descr(&udsp->udsp_src, "SRC", &bulk, &bulk_size);
	if (rc < 0)
		goto failed;

	rc = copy_ioc_udsp_descr(&udsp->udsp_dst, "DST", &bulk, &bulk_size);
	if (rc < 0)
		goto failed;

	rc = copy_ioc_udsp_descr(&udsp->udsp_rte, "RTE", &bulk, &bulk_size);
	if (rc < 0)
		goto failed;

	return udsp;

failed:
	lnet_udsp_free(udsp, true);
	return NULL;
}

static inline int
lnet_get_list_len(struct list_head *list)
{
	struct list_head *l;
	int count = 0;

	list_for_each(l, list)
		count++;

	return count;
}

static size_t
lnet_size_marshaled_nid_descr(struct lnet_ud_nid_descr *descr)
{
	struct cfs_expr_list *expr;
	int expr_count = 0;
	int range_count = 0;
	size_t size = sizeof(struct lnet_ioctl_udsp_descr);

	if (!lnet_udsp_criteria_present(descr))
		return size;

	if (!list_empty(&descr->ud_net_id.udn_net_num_range)) {
		expr = list_entry(descr->ud_net_id.udn_net_num_range.next,
				  struct cfs_expr_list, el_link);
		range_count = lnet_get_list_len(&expr->el_exprs);
	}

	/* count the number of cfs_range_expr in the address expressions */
	list_for_each_entry(expr, &descr->ud_addr_range, el_link) {
		expr_count++;
		range_count += lnet_get_list_len(&expr->el_exprs);
	}

	size += (sizeof(struct lnet_expressions) * expr_count);
	size += (sizeof(struct lnet_range_expr) * range_count);

	return size;
}

size_t
lnet_get_udsp_size(struct lnet_udsp *udsp)
{
	size_t size = sizeof(struct lnet_ioctl_udsp);

	size += lnet_size_marshaled_nid_descr(&udsp->udsp_src);
	size += lnet_size_marshaled_nid_descr(&udsp->udsp_dst);
	size += lnet_size_marshaled_nid_descr(&udsp->udsp_rte);

	return size;
}

static void
copy_exprs(struct cfs_expr_list *expr, void __user **bulk,
	   __s32 *bulk_size)
{
	struct cfs_range_expr *range;
	struct lnet_range_expr range_expr;

	/* copy over the net range expressions to the bulk */
	list_for_each_entry(range, &expr->el_exprs, re_link) {
		range_expr.re_lo = range->re_lo;
		range_expr.re_hi = range->re_hi;
		range_expr.re_stride = range->re_stride;
		memcpy(*bulk, &range_expr, sizeof(range_expr));
		*bulk += sizeof(range_expr);
		*bulk_size -= sizeof(range_expr);
	}
}

static int
copy_nid_range(struct lnet_ud_nid_descr *nid_descr, char *type,
		void __user **bulk, __s32 *bulk_size)
{
	struct lnet_ioctl_udsp_descr ioc_udsp_descr = { { 0 } };
	struct cfs_expr_list *expr;
	struct lnet_expressions ioc_expr;
	int expr_count;
	int net_expr_count = 0;

	ioc_udsp_descr.iud_src_hdr.ud_descr_type = *(__u32 *)type;

	/* if criteria not present, copy over the static part of the NID
	 * descriptor
	 */
	if (!lnet_udsp_criteria_present(nid_descr)) {
		memcpy(*bulk, &ioc_udsp_descr,
			sizeof(ioc_udsp_descr));
		*bulk += sizeof(ioc_udsp_descr);
		*bulk_size -= sizeof(ioc_udsp_descr);
		return 0;
	}

	expr_count = lnet_get_list_len(&nid_descr->ud_addr_range);

	/* copy the net information */
	if (!list_empty(&nid_descr->ud_net_id.udn_net_num_range)) {
		expr = list_entry(nid_descr->ud_net_id.udn_net_num_range.next,
				  struct cfs_expr_list, el_link);
		net_expr_count = lnet_get_list_len(&expr->el_exprs);
	} else {
		net_expr_count = 0;
	}

	/* set the total expression count */
	ioc_udsp_descr.iud_src_hdr.ud_descr_count = expr_count;
	ioc_udsp_descr.iud_net.ud_net_type =
		nid_descr->ud_net_id.udn_net_type;
	ioc_udsp_descr.iud_net.ud_net_num_expr.le_count = net_expr_count;

	/* copy over the header info to the bulk */
	memcpy(*bulk, &ioc_udsp_descr, sizeof(ioc_udsp_descr));
	*bulk += sizeof(ioc_udsp_descr);
	*bulk_size -= sizeof(ioc_udsp_descr);

	/* copy over the net num expression if it exists */
	if (net_expr_count)
		copy_exprs(expr, bulk, bulk_size);

	/* copy the address range */
	list_for_each_entry(expr, &nid_descr->ud_addr_range, el_link) {
		ioc_expr.le_count = lnet_get_list_len(&expr->el_exprs);
		memcpy(*bulk, &ioc_expr, sizeof(ioc_expr));
		*bulk += sizeof(ioc_expr);
		*bulk_size -= sizeof(ioc_expr);

		copy_exprs(expr, bulk, bulk_size);
	}

	return 0;
}

static int
lnet_udsp_marshal(struct lnet_udsp *udsp, void *bulk,
		  __s32 bulk_size)
{
	struct lnet_ioctl_udsp *ioc_udsp;
	int rc = -ENOMEM;

	/* make sure user space allocated enough buffer to marshal the
	 * udsp
	 */
	if (bulk_size < lnet_get_udsp_size(udsp))
		return -EINVAL;

	ioc_udsp = bulk;

	ioc_udsp->iou_idx = udsp->udsp_idx;
	ioc_udsp->iou_action_type = udsp->udsp_action_type;
	ioc_udsp->iou_action.priority = udsp->udsp_action.udsp_priority;

	bulk += sizeof(*ioc_udsp);
	bulk_size -= sizeof(*ioc_udsp);

	rc = copy_nid_range(&udsp->udsp_src, "SRC", &bulk, &bulk_size);
	if (rc != 0)
		return rc;

	rc = copy_nid_range(&udsp->udsp_dst, "DST", &bulk, &bulk_size);
	if (rc != 0)
		return rc;

	rc = copy_nid_range(&udsp->udsp_rte, "RTE", &bulk, &bulk_size);

	return rc;
}

static enum lnet_udsp_action_type
lnet_str2udsp_action(char *type)
{
	if (!type)
		return EN_LNET_UDSP_ACTION_NONE;

	if (!strncmp(type, "priority", strlen("priority")))
		return EN_LNET_UDSP_ACTION_PRIORITY;

	if (!strncmp(type, "pref", strlen("pref")))
		return EN_LNET_UDSP_ACTION_PREFERRED_LIST;

	return EN_LNET_UDSP_ACTION_NONE;
}

int lustre_lnet_add_udsp(char *src, char *dst, char *rte,
			 char *type, union lnet_udsp_action *action,
			 int idx, int seq_no, struct cYAML **err_rc)
{
	struct lnet_udsp *udsp = NULL;
	struct lnet_ioctl_udsp *udsp_bulk;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM;
	void *bulk = NULL;
	__u32 bulk_size;
	char err_str[LNET_MAX_STR_LEN];
	enum lnet_udsp_action_type action_type;

	snprintf(err_str, sizeof(err_str), "\"success\"");

	action_type = lnet_str2udsp_action(type);
	if (action_type == EN_LNET_UDSP_ACTION_NONE) {
		snprintf(err_str, sizeof(err_str),
			 "\"bad action type specified: %s\"", type);
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	/* sanitize parameters:
	 * src-dst can be simultaneously present
	 * dst-rte can be simultaneously present
	 */
	if ((!src && !rte && !dst) ||
	    (src && rte && dst) ||
	    (src && rte && !dst)) {
		snprintf(err_str, sizeof(err_str),
		  "\"The combination of src, dst and rte is not supported\"");
		rc = LUSTRE_CFG_RC_BAD_PARAM;
		goto out;
	}

	udsp = lnet_udsp_alloc();
	if (!udsp) {
		snprintf(err_str, sizeof(err_str), "\"out of memory\"");
		goto out;
	}

	udsp->udsp_idx = idx;
	udsp->udsp_action_type = action_type;

	/* a priority of -1 will result in the lowest possible priority */
	if (action_type == EN_LNET_UDSP_ACTION_PRIORITY)
		udsp->udsp_action.udsp_priority = action->udsp_priority;

	 /* override with the default
	  * if priority is expected, but not specified
	  */
	if (!rte && ((dst && !src) || (src && !dst)) &&
	     action_type != EN_LNET_UDSP_ACTION_PRIORITY) {
		udsp->udsp_action_type = EN_LNET_UDSP_ACTION_PRIORITY;
		udsp->udsp_action.udsp_priority = 0;
	}

	if (src) {
		rc = cfs_parse_nid_parts(src, &udsp->udsp_src.ud_addr_range,
				&udsp->udsp_src.ud_net_id.udn_net_num_range,
				&udsp->udsp_src.ud_net_id.udn_net_type);
		if (rc < 0) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\failed to parse src parameter\"");
			goto out;
		}
	}
	if (dst) {
		rc = cfs_parse_nid_parts(dst, &udsp->udsp_dst.ud_addr_range,
				&udsp->udsp_dst.ud_net_id.udn_net_num_range,
				&udsp->udsp_dst.ud_net_id.udn_net_type);
		if (rc < 0) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\failed to parse dst parameter\"");
			goto out;
		}
	}
	if (rte) {
		rc = cfs_parse_nid_parts(rte, &udsp->udsp_rte.ud_addr_range,
				&udsp->udsp_rte.ud_net_id.udn_net_num_range,
				&udsp->udsp_rte.ud_net_id.udn_net_type);
		if (rc < 0) {
			snprintf(err_str,
				 sizeof(err_str),
				 "\failed to parse rte parameter\"");
			goto out;
		}
	}

	bulk_size = lnet_get_udsp_size(udsp);
	bulk = calloc(1, bulk_size);
	if (!bulk) {
		rc = LUSTRE_CFG_RC_OUT_OF_MEM;
		snprintf(err_str, sizeof(err_str), "\"out of memory\"");
		goto out;
	}

	udsp_bulk = bulk;
	LIBCFS_IOC_INIT_V2(*udsp_bulk, iou_hdr);
	udsp_bulk->iou_hdr.ioc_len = bulk_size;
	udsp_bulk->iou_bulk_size = bulk_size - sizeof(*udsp_bulk);

	rc = lnet_udsp_marshal(udsp, bulk, bulk_size);
	if (rc != LUSTRE_CFG_RC_NO_ERR) {
		rc = LUSTRE_CFG_RC_MARSHAL_FAIL;
		snprintf(err_str,
			 sizeof(err_str),
			 "\"failed to marshal udsp\"");
		goto out;
	}

	udsp_bulk->iou_bulk = bulk + sizeof(*udsp_bulk);

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_ADD_UDSP, bulk);
	if (rc < 0) {
		rc = errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot add udsp: %s\"", strerror(errno));
		goto out;
	}

	rc = LUSTRE_CFG_RC_NO_ERR;

out:
	if (bulk)
		free(bulk);
	if (udsp)
		lnet_udsp_free(udsp, false);
	cYAML_build_error(rc, seq_no, ADD_CMD, "udsp", err_str, err_rc);
	return rc;
}

int lustre_lnet_del_udsp(unsigned int idx, int seq_no, struct cYAML **err_rc)
{
	int rc;
	char err_str[LNET_MAX_STR_LEN];
	struct lnet_ioctl_udsp udsp_bulk;

	snprintf(err_str, sizeof(err_str), "\"success\"");

	LIBCFS_IOC_INIT_V2(udsp_bulk, iou_hdr);
	udsp_bulk.iou_idx = idx;

	rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_DEL_UDSP, &udsp_bulk);
	if (rc < 0) {
		rc = -errno;
		snprintf(err_str, sizeof(err_str),
			 "\"cannot del udsp: %s\"", strerror(rc));
	}

	cYAML_build_error(rc, seq_no, ADD_CMD, "udsp", err_str, err_rc);
	return rc;
}

int lustre_lnet_nid_descr2str(struct lnet_ud_nid_descr *d,
				     char *str, size_t size)
{
	int left = size;
	int len;
	char *net;
	bool addr_found = false;

	/* criteria not defined */
	if (d->ud_net_id.udn_net_type == 0) {
		strncat(str, "NA", left - 1);
		return 0;
	}

	left = cfs_expr2str(&d->ud_addr_range, str, left);
	if (left < 0)
		return left;
	net = libcfs_net2str(LNET_MKNET(d->ud_net_id.udn_net_type, 0));
	if (left < size) {
		len = strlen(net) + 2; /* account for @ and NULL termination */
		addr_found = true;
	} else {
		len = strlen(net) + 1; /* account for NULL termination */
	}

	if (left - len < 0)
		return -ENOBUFS;

	if (addr_found) {
		strncat(str, "@", left);
		left -= 1;
	}

	strncat(str, net, left);

	left -= strlen(net) + 1;

	left = cfs_expr2str(&d->ud_net_id.udn_net_num_range, str, left);
	if (left < 0)
		return left;

	return 0;
}

int yaml_add_udsp_action(struct cYAML *y, struct lnet_udsp *udsp)
{
	struct cYAML *action;

	switch (udsp->udsp_action_type) {
		case EN_LNET_UDSP_ACTION_PRIORITY:
			action = cYAML_create_object(y, "action");
			if (!action)
				return -ENOMEM;
			if (!cYAML_create_number(action, "priority",
				udsp->udsp_action.udsp_priority))
				return -ENOMEM;

		default:
			return 0;
	}

	return 0;
}

int lustre_lnet_show_udsp(int idx, int seq_no, struct cYAML **show_rc,
			  struct cYAML **err_rc)
{
	struct lnet_ioctl_udsp *data = NULL;
	char *ioctl_buf = NULL;
	struct lnet_ioctl_udsp get_size;
	int rc = LUSTRE_CFG_RC_OUT_OF_MEM, i;
	int l_errno = 0;
	int use_idx = 0;
	struct cYAML *root = NULL, *udsp_node = NULL,
		     *first_seq = NULL;
	struct cYAML *item = NULL;
	char err_str[LNET_MAX_STR_LEN];
	char tmp[LNET_MAX_STR_LEN];
	struct lnet_udsp *udsp = NULL;
	bool exist = false;

	snprintf(err_str, sizeof(err_str), "\"out of memory\"");

	root = cYAML_create_object(NULL, NULL);
	if (!root)
		goto out;

	udsp_node = cYAML_create_seq(root, "udsp");
	if (!udsp_node)
		goto out;

	for (i = 0;; i++) {
		data = NULL;
		ioctl_buf = NULL;
		udsp = NULL;

		LIBCFS_IOC_INIT_V2(get_size, iou_hdr);
		if (idx != -1)
			use_idx = idx;
		else
			use_idx = i;

		get_size.iou_idx = use_idx;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_UDSP_SIZE, &get_size);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		ioctl_buf = calloc(get_size.iou_idx, 1);
		if (!ioctl_buf) {
			l_errno = errno;
			break;
		}

		data = (struct lnet_ioctl_udsp *)ioctl_buf;

		LIBCFS_IOC_INIT_V2(*data, iou_hdr);
		data->iou_bulk_size = get_size.iou_idx - sizeof(*data);
		data->iou_bulk = ioctl_buf + sizeof(*data);
		data->iou_idx = use_idx;

		rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_GET_UDSP, ioctl_buf);
		if (rc != 0) {
			l_errno = errno;
			break;
		}

		udsp = lnet_udsp_demarshal(ioctl_buf,
			data->iou_hdr.ioc_len + data->iou_bulk_size);
		if (!udsp) {
			l_errno = -EFAULT;
			break;
		}

		rc = -EINVAL;
		exist = true;

		/* create the tree to be printed. */
		item = cYAML_create_seq_item(udsp_node);
		if (item == NULL)
			goto out;

		if (!first_seq)
			first_seq = item;

		if (cYAML_create_number(item, "idx",
					udsp->udsp_idx) == NULL)
			goto out;

		memset(tmp, 0, LNET_MAX_STR_LEN);
		rc = lustre_lnet_nid_descr2str(&udsp->udsp_src, tmp,
					       LNET_MAX_STR_LEN);

		if (rc)
			goto out;

		if (cYAML_create_string(item, "src", tmp) == NULL)
			goto out;
		memset(tmp, 0, LNET_MAX_STR_LEN);
		rc = lustre_lnet_nid_descr2str(&udsp->udsp_dst, tmp,
					       LNET_MAX_STR_LEN);

		if (rc)
			goto out;

		if (cYAML_create_string(item, "dst", tmp) == NULL)
			goto out;

		memset(tmp, 0, LNET_MAX_STR_LEN);
		rc = lustre_lnet_nid_descr2str(&udsp->udsp_rte, tmp,
					       LNET_MAX_STR_LEN);

		if (rc)
			goto out;

		if (cYAML_create_string(item, "rte", tmp) == NULL)
			goto out;

		if (yaml_add_udsp_action(item, udsp))
			goto out;

		if (ioctl_buf)
			free(ioctl_buf);
		if (udsp)
			lnet_udsp_free(udsp, true);
		/* did we show the given index? */
		if (idx != -1)
			break;
	}

	/* Print out the net information only if show_rc is not provided */
	if (show_rc == NULL)
		cYAML_print_tree(root);

	if (l_errno != ENOENT) {
		snprintf(err_str,
			 sizeof(err_str),
			 "\"cannot get udsp: %s\"",
			 strerror(l_errno));
		rc = -l_errno;
		goto out;
	} else {
		rc = LUSTRE_CFG_RC_NO_ERR;
	}

	snprintf(err_str, sizeof(err_str), "\"success\"");
out:
	if (ioctl_buf)
		free(ioctl_buf);
	if (udsp)
		lnet_udsp_free(udsp, true);

	if (show_rc == NULL || rc != LUSTRE_CFG_RC_NO_ERR || !exist) {
		cYAML_free_tree(root);
	} else if (show_rc != NULL && *show_rc != NULL) {
		struct cYAML *show_node;
		/* find the net node, if one doesn't exist
		 * then insert one.  Otherwise add to the one there
		 */
		show_node = cYAML_get_object_item(*show_rc, "udsp");
		if (show_node != NULL && cYAML_is_sequence(show_node)) {
			cYAML_insert_child(show_node, first_seq);
			free(udsp_node);
			free(root);
		} else if (show_node == NULL) {
			cYAML_insert_sibling((*show_rc)->cy_child,
						udsp_node);
			free(root);
		} else {
			cYAML_free_tree(root);
		}
	} else {
		*show_rc = root;
	}

	cYAML_build_error(rc, seq_no, SHOW_CMD, "udsp", err_str, err_rc);

	return rc;
}

