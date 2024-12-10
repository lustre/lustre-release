// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2015, 2017, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Kernel <-> userspace communication routines.
 * Using pipes for all arches.
 *
 * Author: Nathan Rutman <nathan.rutman@sun.com>
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/file.h>
#include <linux/glob.h>
#include <linux/types.h>

#include <libcfs/linux/linux-net.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_kernelcomm.h>

static struct genl_family lustre_family;

static struct ln_key_list device_list = {
	.lkl_maxattr			= LUSTRE_DEVICE_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_DEVICE_ATTR_HDR]	= {
			.lkp_value		= "devices",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_DEVICE_ATTR_INDEX]	= {
			.lkp_value		= "index",
			.lkp_data_type		= NLA_U16
		},
		[LUSTRE_DEVICE_ATTR_STATUS]	= {
			.lkp_value		= "status",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_CLASS]	= {
			.lkp_value		= "type",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_NAME]	= {
			.lkp_value		= "name",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_UUID]	= {
			.lkp_value		= "uuid",
			.lkp_data_type		= NLA_STRING
		},
		[LUSTRE_DEVICE_ATTR_REFCOUNT]	= {
			.lkp_value		= "refcount",
			.lkp_data_type		= NLA_U32
		},
	},
};

struct genl_dev_list {
	struct obd_device	*gdl_target;
	unsigned int		gdl_start;
};

static inline struct genl_dev_list *
device_dump_ctx(struct netlink_callback *cb)
{
	return (struct genl_dev_list *)cb->args[0];
}

/* generic ->start() handler for GET requests */
static int lustre_device_list_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct genl_dev_list *glist;
	int msg_len, rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	OBD_ALLOC(glist, sizeof(*glist));
	if (!glist)
		return -ENOMEM;

	cb->args[0] = (long)glist;
	glist->gdl_target = NULL;
	glist->gdl_start = 0;

	msg_len = genlmsg_len(gnlh);
	if (msg_len > 0) {
		struct nlattr *params = genlmsg_data(gnlh);
		struct nlattr *dev;
		int rem;

		if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
			NL_SET_ERR_MSG(extack, "no configuration");
			GOTO(report_err, rc);
		}

		nla_for_each_nested(dev, params, rem) {
			struct nlattr *prop;
			int rem2;

			nla_for_each_nested(prop, dev, rem2) {
				char name[MAX_OBD_NAME];
				struct obd_device *obd;

				if (nla_type(prop) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(prop, "name") != 0)
					continue;

				prop = nla_next(prop, &rem2);
				if (nla_type(prop) != LN_SCALAR_ATTR_VALUE)
					GOTO(report_err, rc = -EINVAL);

				rc = nla_strscpy(name, prop, sizeof(name));
				if (rc < 0)
					GOTO(report_err, rc);
				rc = 0;

				obd = class_name2obd(name);
				if (obd)
					glist->gdl_target = obd;
			}
		}
		if (!glist->gdl_target) {
			NL_SET_ERR_MSG(extack, "No devices found");
			rc = -ENOENT;
		}
	}
report_err:
	if (rc < 0) {
		OBD_FREE(glist, sizeof(*glist));
		cb->args[0] = 0;
	}
	return rc;
}

static int lustre_device_list_dump(struct sk_buff *msg,
				   struct netlink_callback *cb)
{
	struct genl_dev_list *glist = device_dump_ctx(cb);
	struct obd_device *filter = glist->gdl_target;
	struct obd_device *obd = NULL;
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	int seq = cb->nlh->nlmsg_seq;
	unsigned long idx = 0;
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	if (glist->gdl_start == 0) {
		const struct ln_key_list *all[] = {
			&device_list, NULL
		};

		rc = lnet_genl_send_scalar_list(msg, portid, seq,
						&lustre_family,
						NLM_F_CREATE | NLM_F_MULTI,
						LUSTRE_CMD_DEVICES, all);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "failed to send key table");
			return rc;
		}
	}

	obd_device_lock();
	obd_device_for_each_start(idx, obd, glist->gdl_start) {
		const char *status;
		void *hdr;

		if (filter && filter != obd)
			continue;

		hdr = genlmsg_put(msg, portid, seq, &lustre_family,
				  NLM_F_MULTI, LUSTRE_CMD_DEVICES);
		if (!hdr) {
			NL_SET_ERR_MSG(extack, "failed to send values");
			genlmsg_cancel(msg, hdr);
			rc = -EMSGSIZE;
			break;
		}

		if (idx == 0)
			nla_put_string(msg, LUSTRE_DEVICE_ATTR_HDR, "");

		nla_put_u16(msg, LUSTRE_DEVICE_ATTR_INDEX, obd->obd_minor);

		/* Collect only the index value for a single obd */
		if (filter) {
			genlmsg_end(msg, hdr);
			idx++;
			break;
		}

		if (obd->obd_stopping)
			status = "ST";
		else if (obd->obd_inactive)
			status = "IN";
		else if (test_bit(OBDF_SET_UP, obd->obd_flags))
			status = "UP";
		else if (test_bit(OBDF_ATTACHED, obd->obd_flags))
			status = "AT";
		else
			status = "--";

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_STATUS, status);

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_CLASS,
			       obd->obd_type->typ_name);

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_NAME,
			       obd->obd_name);

		nla_put_string(msg, LUSTRE_DEVICE_ATTR_UUID,
			       obd->obd_uuid.uuid);

		nla_put_u32(msg, LUSTRE_DEVICE_ATTR_REFCOUNT,
			    kref_read(&obd->obd_refcount));

		genlmsg_end(msg, hdr);
	}
	obd_device_unlock();

	glist->gdl_start = idx + 1;
	rc = lnet_nl_send_error(cb->skb, portid, seq, rc);

	return rc < 0 ? rc : msg->len;
}

#ifndef HAVE_NETLINK_CALLBACK_START
int lustre_old_device_list_dump(struct sk_buff *msg,
				struct netlink_callback *cb)
{
	if (!cb->args[0]) {
		int rc = lustre_device_list_start(cb);

		if (rc < 0)
			return rc;
	}

	return lustre_device_list_dump(msg, cb);
}
#endif

static int lustre_device_done(struct netlink_callback *cb)
{
	struct genl_dev_list *glist;

	glist = device_dump_ctx(cb);
	if (glist) {
		OBD_FREE(glist, sizeof(*glist));
		cb->args[0] = 0;
	}

	return 0;
}

struct ln_key_list stats_params = {
	.lkl_maxattr	= LUSTRE_PARAM_ATTR_MAX,
	.lkl_list	= {
		[LUSTRE_PARAM_ATTR_HDR] = {
			.lkp_value	= "stats",
			.lkp_key_format	= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type	= NLA_NUL_STRING,
		},
		[LUSTRE_PARAM_ATTR_SOURCE] = {
			.lkp_value	= "source",
			.lkp_data_type	= NLA_STRING,
		},
	},
};

static const struct ln_key_list stats_list = {
	.lkl_maxattr			= LUSTRE_STATS_ATTR_MAX,
	.lkl_list			= {
		[LUSTRE_STATS_ATTR_HDR]	= {
			.lkp_value		= "stats",
			.lkp_key_format		= LNKF_SEQUENCE | LNKF_MAPPING,
			.lkp_data_type		= NLA_NUL_STRING,
		},
		[LUSTRE_STATS_ATTR_SOURCE]	= {
			.lkp_value		= "source",
			.lkp_data_type		= NLA_STRING,
		},
		[LUSTRE_STATS_ATTR_TIMESTAMP]	= {
			.lkp_value		= "snapshot_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_STATS_ATTR_START_TIME]	= {
			.lkp_value		= "start_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_STATS_ATTR_ELAPSE_TIME]	= {
			.lkp_value		= "elapsed_time",
			.lkp_data_type		= NLA_S64,
		},
		[LUSTRE_STATS_ATTR_DATASET]	= {
			.lkp_key_format		= LNKF_FLOW | LNKF_MAPPING,
			.lkp_data_type		= NLA_NESTED,
		},
	},
};

static const struct ln_key_list stats_dataset_list = {
	.lkl_maxattr				= LUSTRE_STATS_ATTR_DATASET_MAX,
	.lkl_list				= {
		[LUSTRE_STATS_ATTR_DATASET_NAME]	= {
			.lkp_data_type			= NLA_NUL_STRING,
		},
		[LUSTRE_STATS_ATTR_DATASET_COUNT]	= {
			.lkp_value			= "samples",
			.lkp_data_type			= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_UNITS]	= {
			.lkp_value			= "units",
			.lkp_data_type			= NLA_STRING,
		},
		[LUSTRE_STATS_ATTR_DATASET_MINIMUM]	= {
			.lkp_value			= "min",
			.lkp_data_type			= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_MAXIMUM]	= {
			.lkp_value			= "max",
			.lkp_data_type			= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_SUM]		= {
			.lkp_value			= "sum",
			.lkp_data_type			= NLA_U64,
		},
		[LUSTRE_STATS_ATTR_DATASET_SUMSQUARE]	= {
			.lkp_value			= "stddev",
			.lkp_data_type			= NLA_U64,
		},
	},
};

#ifndef HAVE_GENL_DUMPIT_INFO
static struct cfs_genl_dumpit_info service_info = {
	.family		= &lustre_family,
};
#endif

static inline struct lustre_stats_list *
stats_dump_ctx(struct netlink_callback *cb)
{
	return (struct lustre_stats_list *)cb->args[0];
}

int lustre_stats_done(struct netlink_callback *cb)
{
	struct lustre_stats_list *list = stats_dump_ctx(cb);

	if (list) {
		genradix_free(&list->gfl_list);
		OBD_FREE(list, sizeof(*list));
		cb->args[0] = 0;
	}
	return 0;
}
EXPORT_SYMBOL(lustre_stats_done);

/* Min size for key table and its matching values:
 *	header		strlen("stats")
 *	source		strlen("source") + MAX_OBD_NAME * 2
 *	timestamp	strlen("snapshot_time") + s64
 *	start time	strlen("start time") + s64
 *	elapsed_time	strlen("elapse time") + s64
 */
#define STATS_MSG_MIN_SIZE	(267 + 58)

/* key table + values for each dataset entry:
 *	dataset name	25
 *	dataset count	strlen("samples") + u64
 *	dataset units	strlen("units") + 5
 *	dataset min	strlen("min") + u64
 *	dataset max	strlen("max") + u64
 *	dataset sum	strlen("sum") + u64
 *	dataset stdev	strlen("stddev") + u64
 */
#define STATS_MSG_DATASET_SIZE	(97)

static int lustre_stats_start(struct netlink_callback *cb)
{
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
	unsigned long len = STATS_MSG_MIN_SIZE;
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	struct lustre_stats_list *slist;
	int msg_len = genlmsg_len(gnlh);
	int rc = 0;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
#ifndef HAVE_GENL_DUMPIT_INFO
	cb->args[1] = (unsigned long)&service_info;
#endif
	OBD_ALLOC(slist, sizeof(*slist));
	if (!slist) {
		NL_SET_ERR_MSG(extack, "failed to setup obd list");
		return -ENOMEM;
	}

	genradix_init(&slist->gfl_list);
	slist->gfl_index = 0;
	cb->args[0] = (long)slist;

	if (msg_len > 0) {
		struct nlattr *params = genlmsg_data(gnlh);
		struct nlattr *dev;
		int rem;

		if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
			NL_SET_ERR_MSG(extack, "no configuration");
			GOTO(report_err, rc);
		}

		nla_for_each_nested(dev, params, rem) {
			struct nlattr *item;
			int rem2;

			nla_for_each_nested(item, dev, rem2) {
				char filter[MAX_OBD_NAME * 2];

				if (nla_type(item) != LN_SCALAR_ATTR_VALUE ||
				    nla_strcmp(item, "source") != 0)
					continue;

				item = nla_next(item, &rem2);
				if (nla_type(item) != LN_SCALAR_ATTR_VALUE) {
					NL_SET_ERR_MSG(extack,
						       "source has invalid value");
					GOTO(report_err, rc = -EINVAL);
				}

				memset(filter, 0, sizeof(filter));
				rc = nla_strscpy(filter, item, sizeof(filter));
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "source key string is invalud");
					GOTO(report_err, rc);
				}

				rc = lustre_stats_scan(slist, filter);
				if (rc < 0) {
					NL_SET_ERR_MSG(extack,
						       "stat scan failure");
					GOTO(report_err, rc);
				}

				if (gnlh->version)
					len += STATS_MSG_DATASET_SIZE * rc;
				rc = 0;
			}
		}
	} else {
		rc = lustre_stats_scan(slist, NULL);
		if (rc < 0) {
			NL_SET_ERR_MSG(extack, "stat scan failure");
			GOTO(report_err, rc);
		}

		if (gnlh->version)
			len += STATS_MSG_DATASET_SIZE * rc;
		rc = 0;
	}

	/* Older kernels only support 64K. Our stats can be huge. */
	if (len >= (1UL << (sizeof(cb->min_dump_alloc) << 3))) {
		struct lprocfs_stats **stats;
		struct genradix_iter iter;

		genradix_for_each(&slist->gfl_list, iter, stats)
			lprocfs_stats_free(stats);
		NL_SET_ERR_MSG(extack, "Netlink msg is too large");
		rc = -EMSGSIZE;
	} else {
		cb->min_dump_alloc = len;
	}
report_err:
	if (rc < 0)
		lustre_stats_done(cb);

	return rc;
}

int lustre_stats_dump(struct sk_buff *msg, struct netlink_callback *cb)
{
	const struct cfs_genl_dumpit_info *info = lnet_genl_dumpit_info(cb);
	struct lustre_stats_list *slist = stats_dump_ctx(cb);
	struct genlmsghdr *gnlh = nlmsg_data(cb->nlh);
#ifdef HAVE_NL_PARSE_WITH_EXT_ACK
	struct netlink_ext_ack *extack = NULL;
#endif
	int portid = NETLINK_CB(cb->skb).portid;
	struct lprocfs_stats *prev = NULL;
	int seq = cb->nlh->nlmsg_seq;
	int idx = slist->gfl_index;
	int count, i, rc = 0;
	bool started = true;

#ifdef HAVE_NL_DUMP_WITH_EXT_ACK
	extack = cb->extack;
#endif
	while (idx < slist->gfl_count) {
		struct lprocfs_stats **tmp, *stats;
		struct nlattr *dataset = NULL;
		void *ghdr = NULL;
		char *src;

		tmp = genradix_ptr(&slist->gfl_list, idx);
		stats = tmp[0];
		if (!stats)
			continue;

		if (gnlh->version &&
		   (!idx || (prev && strcmp(stats->ls_cnt_header[2].lc_name,
					    prev->ls_cnt_header[2].lc_name) != 0))) {
			size_t len = sizeof(struct ln_key_list);
			int flags = NLM_F_CREATE | NLM_F_MULTI;
			const struct ln_key_list **all;
			struct ln_key_list *start;

			/* LUSTRE_STATS_ATTR_MAX includes one stat entry
			 * by default since we need to define what a stat
			 * entry is.
			 */
			count = LUSTRE_STATS_ATTR_MAX + stats->ls_num - 1;
			len += sizeof(struct ln_key_props) * count;
			OBD_ALLOC(start, len);
			if (!start) {
				NL_SET_ERR_MSG(extack,
					       "first key list allocation failure");
				GOTO(out_cancel, rc = -ENOMEM);
			}
			*start = stats_list; /* Set initial values */
			start->lkl_maxattr += stats->ls_num;
			for (i = LUSTRE_STATS_ATTR_MAX + 1;
			     i <= start->lkl_maxattr; i++)
				start->lkl_list[i] =
					stats_list.lkl_list[LUSTRE_STATS_ATTR_DATASET];

			OBD_ALLOC_PTR_ARRAY(all, stats->ls_num + 2);
			if (!all) {
				NL_SET_ERR_MSG(extack,
					       "key list allocation failure");
				OBD_FREE(start, len);
				GOTO(out_cancel, rc = -ENOMEM);
			}

			all[0] = start;
			for (i = 1; i <= stats->ls_num; i++)
				all[i] = &stats_dataset_list;
			all[i] = NULL;

			if (idx)
				flags |= NLM_F_REPLACE;
			rc = lnet_genl_send_scalar_list(msg, portid, seq,
							info->family, flags,
							gnlh->cmd, all);
			OBD_FREE_PTR_ARRAY(all, stats->ls_num + 2);
			OBD_FREE(start, len);
			if (rc < 0) {
				NL_SET_ERR_MSG(extack,
					       "failed to send key table");
				GOTO(out_cancel, rc);
			}
		} else if (!gnlh->version && !idx) {
			/* We just want the source of the stats */
			const struct ln_key_list *all[] = {
				&stats_params, NULL
			};

			rc = lnet_genl_send_scalar_list(msg, portid, seq,
							info->family,
							NLM_F_CREATE | NLM_F_MULTI,
							gnlh->cmd, all);
			if (rc < 0) {
				NL_SET_ERR_MSG(extack,
					       "failed to send key table");
				GOTO(out_cancel, rc);
			}
		}
		prev = stats;

		ghdr = genlmsg_put(msg, portid, seq, info->family, NLM_F_MULTI,
				  gnlh->cmd);
		if (!ghdr)
			GOTO(out_cancel, rc = -EMSGSIZE);

		if (started) {
			nla_put_string(msg, LUSTRE_STATS_ATTR_HDR, "");
			started = false;
		}

		src = stats->ls_source;
		if (strstarts(stats->ls_source, ".fs.lustre."))
			src += strlen(".fs.lustre.");
		nla_put_string(msg, LUSTRE_STATS_ATTR_SOURCE, src);

		if (!gnlh->version) { /* We just want the source of the stats */
			idx++;
			GOTO(out_cancel, rc = 0);
		}

		rc = nla_put_s64(msg, LUSTRE_STATS_ATTR_TIMESTAMP,
				 ktime_get_real_ns(), LUSTRE_STATS_ATTR_PAD);
		if (rc < 0)
			GOTO(out_cancel, rc);

		if (gnlh->version > 1) {
			rc = nla_put_s64(msg, LUSTRE_STATS_ATTR_START_TIME,
					 ktime_to_ns(stats->ls_init),
					 LUSTRE_STATS_ATTR_PAD);
			if (rc < 0)
				GOTO(out_cancel, rc);

			rc = nla_put_s64(msg, LUSTRE_STATS_ATTR_ELAPSE_TIME,
					 ktime_to_ns(ktime_sub(stats->ls_init,
							       ktime_get())),
					 LUSTRE_STATS_ATTR_PAD);
			if (rc < 0)
				GOTO(out_cancel, rc);
		}

		i = 0;
		for (count = 0; count < stats->ls_num; count++) {
			struct lprocfs_counter_header *hdr;
			struct lprocfs_counter ctr;
			struct nlattr *stat_attr;

			lprocfs_stats_collect(stats, count, &ctr);

			if (ctr.lc_count == 0)
				continue;

			hdr = &stats->ls_cnt_header[count];
			dataset = nla_nest_start(msg,
						 LUSTRE_STATS_ATTR_DATASET + i++);
			stat_attr = nla_nest_start(msg, 0);

			nla_put_string(msg, LUSTRE_STATS_ATTR_DATASET_NAME,
				       hdr->lc_name);
			nla_put_u64_64bit(msg, LUSTRE_STATS_ATTR_DATASET_COUNT,
					  ctr.lc_count,
					  LUSTRE_STATS_ATTR_DATASET_PAD);

			nla_put_string(msg, LUSTRE_STATS_ATTR_DATASET_UNITS,
				       hdr->lc_units);

			if (hdr->lc_config & LPROCFS_CNTR_AVGMINMAX) {
				nla_put_u64_64bit(msg,
						  LUSTRE_STATS_ATTR_DATASET_MINIMUM,
						  ctr.lc_min,
						  LUSTRE_STATS_ATTR_DATASET_PAD);

				nla_put_u64_64bit(msg,
						  LUSTRE_STATS_ATTR_DATASET_MAXIMUM,
						  ctr.lc_max,
						  LUSTRE_STATS_ATTR_DATASET_PAD);

				nla_put_u64_64bit(msg,
						  LUSTRE_STATS_ATTR_DATASET_SUM,
						  ctr.lc_sum,
						  LUSTRE_STATS_ATTR_DATASET_PAD);

				if (hdr->lc_config & LPROCFS_CNTR_STDDEV) {
					nla_put_u64_64bit(msg,
							  LUSTRE_STATS_ATTR_DATASET_SUMSQUARE,
							  ctr.lc_sumsquare,
							  LUSTRE_STATS_ATTR_DATASET_PAD);
				}
			}
			nla_nest_end(msg, stat_attr);
			nla_nest_end(msg, dataset);
		}
		idx++;
out_cancel:
		lprocfs_stats_free(&stats);
		if (rc < 0) {
			genlmsg_cancel(msg, ghdr);
			return rc;
		}
		genlmsg_end(msg, ghdr);
	}
	slist->gfl_index = idx;

	return rc;
}
EXPORT_SYMBOL(lustre_stats_dump);

#ifndef HAVE_NETLINK_CALLBACK_START
int lustre_old_stats_dump(struct sk_buff *msg, struct netlink_callback *cb)
{
	struct lustre_stats_list *slist = stats_dump_ctx(cb);

	if (!slist) {
		int rc = lustre_stats_start(cb);

		if (rc < 0)
			return lnet_nl_send_error(cb->skb,
						  NETLINK_CB(cb->skb).portid,
						  cb->nlh->nlmsg_seq,
						  rc);
	}

	return lustre_stats_dump(msg, cb);
}
#endif

static int lustre_stats_cmd(struct sk_buff *skb, struct genl_info *info)
{
	struct nlmsghdr *nlh = nlmsg_hdr(skb);
	struct genlmsghdr *gnlh = nlmsg_data(nlh);
	struct nlattr *params = genlmsg_data(gnlh);
	int msg_len, rem, idx = 0, rc = 0;
	struct lustre_stats_list slist;
	struct nlattr *attr;

	msg_len = genlmsg_len(gnlh);
	if (!msg_len) {
		GENL_SET_ERR_MSG(info, "no configuration");
		GOTO(report_err, rc = -ENOMSG);
	}

	if (!(nla_type(params) & LN_SCALAR_ATTR_LIST)) {
		GENL_SET_ERR_MSG(info, "invalid configuration");
		GOTO(report_err, rc = -EINVAL);
	}

	genradix_init(&slist.gfl_list);
	slist.gfl_count = 0;

	nla_for_each_nested(attr, params, rem) {
		struct nlattr *prop;
		int rem2;

		if (nla_type(attr) != LN_SCALAR_ATTR_LIST)
			continue;

		nla_for_each_nested(prop, attr, rem2) {
			char source[MAX_OBD_NAME * 2];

			if (nla_type(prop) != LN_SCALAR_ATTR_VALUE ||
			    nla_strcmp(prop, "source") != 0)
				continue;

			prop = nla_next(prop, &rem2);
			if (nla_type(prop) != LN_SCALAR_ATTR_VALUE)
				GOTO(report_err, rc = -EINVAL);

			memset(source, 0, sizeof(source));
			rc = nla_strscpy(source, prop, sizeof(source));
			if (rc < 0)
				GOTO(report_err, rc);

			rc = lustre_stats_scan(&slist, source);
			if (rc < 0) {
				GENL_SET_ERR_MSG(info,
						 "stat scan failure");
				GOTO(report_err, rc);
			}
			rc = 0;
		}
	}

	while (idx < slist.gfl_count) {
		struct lprocfs_stats **stats;

		stats = genradix_ptr(&slist.gfl_list, idx++);
		if (!stats[0])
			continue;

		lprocfs_stats_clear(stats[0]);
	}
report_err:
	return rc;
}

static const struct genl_multicast_group lustre_mcast_grps[] = {
	{ .name		= "devices",		},
	{ .name		= "stats",		},
};

static const struct genl_ops lustre_genl_ops[] = {
	{
		.cmd		= LUSTRE_CMD_DEVICES,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lustre_device_list_start,
		.dumpit		= lustre_device_list_dump,
#else
		.dumpit		= lustre_old_device_list_dump,
#endif
		.done		= lustre_device_done,
	},
	{
		.cmd		= LUSTRE_CMD_STATS,
#ifdef HAVE_NETLINK_CALLBACK_START
		.start		= lustre_stats_start,
		.dumpit		= lustre_stats_dump,
#else
		.dumpit		= lustre_old_stats_dump,
#endif
		.done		= lustre_stats_done,
		.doit		= lustre_stats_cmd,
	},
};

static struct genl_family lustre_family = {
	.name		= LUSTRE_GENL_NAME,
	.version	= LUSTRE_GENL_VERSION,
	.module		= THIS_MODULE,
	.ops		= lustre_genl_ops,
	.n_ops		= ARRAY_SIZE(lustre_genl_ops),
	.mcgrps		= lustre_mcast_grps,
	.n_mcgrps	= ARRAY_SIZE(lustre_mcast_grps),
#ifdef GENL_FAMILY_HAS_RESV_START_OP
	.resv_start_op	= __LUSTRE_CMD_MAX_PLUS_ONE,
#endif
};

/**
 * libcfs_kkuc_msg_put - send an message from kernel to userspace
 * @param fp to send the message to
 * @param payload Payload data.  First field of payload is always
 *   struct kuc_hdr
 */
int libcfs_kkuc_msg_put(struct file *filp, void *payload)
{
	struct kuc_hdr *kuch = (struct kuc_hdr *)payload;
	ssize_t count = kuch->kuc_msglen;
	loff_t offset = 0;
	int rc = 0;

	if (IS_ERR_OR_NULL(filp))
		return -EBADF;

	if (kuch->kuc_magic != KUC_MAGIC) {
		CERROR("KernelComm: bad magic %x\n", kuch->kuc_magic);
		return -ENOSYS;
	}

	while (count > 0) {
		rc = cfs_kernel_write(filp, payload, count, &offset);
		if (rc < 0)
			break;
		count -= rc;
		payload += rc;
		rc = 0;
	}

	if (rc < 0)
		CWARN("message send failed (%d)\n", rc);
	else
		CDEBUG(D_HSM, "Sent message rc=%d, fp=%p\n", rc, filp);

	return rc;
}
EXPORT_SYMBOL(libcfs_kkuc_msg_put);

/* Broadcast groups are global across all mounted filesystems;
 * i.e. registering for a group on 1 fs will get messages for that
 * group from any fs */
/** A single group registration has a uid and a file pointer */
struct kkuc_reg {
	struct list_head kr_chain;
	struct obd_uuid	 kr_uuid;
	int		 kr_uid;
	struct file	*kr_fp;
	char		 kr_data[];
};

static struct list_head kkuc_groups[KUC_GRP_MAX + 1];
/* Protect message sending against remove and adds */
static DECLARE_RWSEM(kg_sem);

static inline bool libcfs_kkuc_group_is_valid(int group)
{
	return 0 <= group && group < ARRAY_SIZE(kkuc_groups);
}

int libcfs_kkuc_init(void)
{
	int group;

	for (group = 0; group < ARRAY_SIZE(kkuc_groups); group++)
		INIT_LIST_HEAD(&kkuc_groups[group]);

	return genl_register_family(&lustre_family);
}

void libcfs_kkuc_fini(void)
{
	genl_unregister_family(&lustre_family);
}

/** Add a receiver to a broadcast group
 * @param filp pipe to write into
 * @param uid identifier for this receiver
 * @param group group number
 * @param data user data
 */
int libcfs_kkuc_group_add(struct file *filp, const struct obd_uuid *uuid,
			  int uid, int group, void *data, size_t data_len)
{
	struct kkuc_reg *reg;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	/* fput in group_rem */
	if (filp == NULL)
		return -EBADF;

	/* freed in group_rem */
	reg = kzalloc(sizeof(*reg) + data_len, 0);
	if (reg == NULL)
		return -ENOMEM;

	reg->kr_uuid = *uuid;
	reg->kr_fp = filp;
	reg->kr_uid = uid;
	memcpy(reg->kr_data, data, data_len);

	down_write(&kg_sem);
	list_add(&reg->kr_chain, &kkuc_groups[group]);
	up_write(&kg_sem);

	CDEBUG(D_HSM, "Added uid=%d fp=%p to group %d\n", uid, filp, group);

	return 0;
}
EXPORT_SYMBOL(libcfs_kkuc_group_add);

int libcfs_kkuc_group_rem(const struct obd_uuid *uuid, int uid, int group)
{
	struct kkuc_reg *reg, *next;
	ENTRY;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	if (uid == 0) {
		/* Broadcast a shutdown message */
		struct kuc_hdr lh;

		lh.kuc_magic = KUC_MAGIC;
		lh.kuc_transport = KUC_TRANSPORT_GENERIC;
		lh.kuc_msgtype = KUC_MSG_SHUTDOWN;
		lh.kuc_msglen = sizeof(lh);
		libcfs_kkuc_group_put(uuid, group, &lh);
	}

	down_write(&kg_sem);
	list_for_each_entry_safe(reg, next, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) &&
		    (uid == 0 || uid == reg->kr_uid)) {
			list_del(&reg->kr_chain);
			CDEBUG(D_HSM, "Removed uid=%d fp=%p from group %d\n",
				reg->kr_uid, reg->kr_fp, group);
			if (reg->kr_fp != NULL)
				fput(reg->kr_fp);
			kfree(reg);
		}
	}
	up_write(&kg_sem);

	RETURN(0);
}
EXPORT_SYMBOL(libcfs_kkuc_group_rem);

int libcfs_kkuc_group_put(const struct obd_uuid *uuid, int group, void *payload)
{
	struct kkuc_reg	*reg;
	int		 rc = 0;
	int one_success = 0;
	ENTRY;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		return -EINVAL;
	}

	down_write(&kg_sem);

	if (unlikely(list_empty(&kkuc_groups[group])) ||
	    unlikely(CFS_FAIL_CHECK(OBD_FAIL_MDS_HSM_CT_REGISTER_NET))) {
		/* no agent have fully registered, CDT will retry */
		up_write(&kg_sem);
		RETURN(-EAGAIN);
	}

	list_for_each_entry(reg, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) &&
		    reg->kr_fp != NULL) {
			rc = libcfs_kkuc_msg_put(reg->kr_fp, payload);
			if (rc == 0)
				one_success = 1;
			else if (rc == -EPIPE) {
				fput(reg->kr_fp);
				reg->kr_fp = NULL;
			}
		}
	}
	up_write(&kg_sem);

	/* don't return an error if the message has been delivered
	 * at least to one agent */
	if (one_success)
		rc = 0;

	RETURN(rc);
}
EXPORT_SYMBOL(libcfs_kkuc_group_put);

/**
 * Calls a callback function for each link of the given kuc group.
 * @param group the group to call the function on.
 * @param cb_func the function to be called.
 * @param cb_arg extra argument to be passed to the callback function.
 */
int libcfs_kkuc_group_foreach(const struct obd_uuid *uuid, int group,
			      libcfs_kkuc_cb_t cb_func, void *cb_arg)
{
	struct kkuc_reg	*reg;
	int		 rc = 0;
	ENTRY;

	if (!libcfs_kkuc_group_is_valid(group)) {
		CDEBUG(D_WARNING, "Kernelcomm: bad group %d\n", group);
		RETURN(-EINVAL);
	}

	down_read(&kg_sem);
	list_for_each_entry(reg, &kkuc_groups[group], kr_chain) {
		if (obd_uuid_equals(uuid, &reg->kr_uuid) && reg->kr_fp != NULL)
			rc = cb_func(reg->kr_data, cb_arg);
	}
	up_read(&kg_sem);

	RETURN(rc);
}
EXPORT_SYMBOL(libcfs_kkuc_group_foreach);
