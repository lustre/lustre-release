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
 * Copyright (c) 2017, DDN Storage Corporation.
 */
/*
 * Persistent Client Cache
 *
 * PCC is a new framework which provides a group of local cache on Lustre
 * client side. It works in two modes: RW-PCC enables a read-write cache on the
 * local SSDs of a single client; RO-PCC provides a read-only cache on the
 * local SSDs of multiple clients. Less overhead is visible to the applications
 * and network latencies and lock conflicts can be significantly reduced.
 *
 * For RW-PCC, no global namespace will be provided. Each client uses its own
 * local storage as a cache for itself. Local file system is used to manage
 * the data on local caches. Cached I/O is directed to local file system while
 * normal I/O is directed to OSTs. RW-PCC uses HSM for data synchronization.
 * It uses HSM copytool to restore file from local caches to Lustre OSTs. Each
 * PCC has a copytool instance running with unique archive number. Any remote
 * access from another Lustre client would trigger the data synchronization. If
 * a client with RW-PCC goes offline, the cached data becomes inaccessible for
 * other client temporarily. And after the RW-PCC client reboots and the
 * copytool restarts, the data will be accessible again.
 *
 * Following is what will happen in different conditions for RW-PCC:
 *
 * > When file is being created on RW-PCC
 *
 * A normal HSM released file is created on MDT;
 * An empty mirror file is created on local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being prefetched to RW-PCC
 *
 * An file is copied to the local cache;
 * The HSM status of the Lustre file will be set to archived and released;
 * The archive number will be set to the proper value.
 *
 * > When file is being accessed from PCC
 *
 * Data will be read directly from local cache;
 * Metadata will be read from MDT, except file size;
 * File size will be got from local cache.
 *
 * > When PCC cached file is being accessed on another client
 *
 * RW-PCC cached files are automatically restored when a process on another
 * client tries to read or modify them. The corresponding I/O will block
 * waiting for the released file to be restored. This is transparent to the
 * process.
 *
 * For RW-PCC, when a file is being created, a rule-based policy is used to
 * determine whether it will be cached. Rule-based caching of newly created
 * files can determine which file can use a cache on PCC directly without any
 * admission control.
 *
 * RW-PCC design can accelerate I/O intensive applications with one-to-one
 * mappings between files and accessing clients. However, in several use cases,
 * files will never be updated, but need to be read simultaneously from many
 * clients. RO-PCC implements a read-only caching on Lustre clients using
 * SSDs. RO-PCC is based on the same framework as RW-PCC, expect
 * that no HSM mechanism is used.
 *
 * The main advantages to use this SSD cache on the Lustre clients via PCC
 * is that:
 * - The I/O stack becomes much simpler for the cached data, as there is no
 *   interference with I/Os from other clients, which enables easier
 *   performance optimizations;
 * - The requirements on the HW inside the client nodes are small, any kind of
 *   SSDs or even HDDs can be used as cache devices;
 * - Caching reduces the pressure on the object storage targets (OSTs), as
 *   small or random I/Os can be regularized to big sequential I/Os and
 *   temporary files do not even need to be flushed to OSTs.
 *
 * PCC can accelerate applications with certain I/O patterns:
 * - small-sized random writes (< 1MB) from a single client
 * - repeated read of data that is larger than RAM
 * - clients with high network latency
 *
 * Author: Li Xi <lixi@ddn.com>
 * Author: Qian Yingjin <qian@ddn.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include "pcc.h"
#include <linux/namei.h>
#include <linux/file.h>
#include <lustre_compat.h>
#include "llite_internal.h"

#ifdef HAVE_FILEATTR_GET
#include <linux/fileattr.h>
#endif

struct kmem_cache *pcc_inode_slab;

int pcc_super_init(struct pcc_super *super)
{
	struct cred *cred;

	super->pccs_cred = cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	/* Never override disk quota limits or use reserved space */
	cap_lower(cred->cap_effective, CAP_SYS_RESOURCE);
	init_rwsem(&super->pccs_rw_sem);
	INIT_LIST_HEAD(&super->pccs_datasets);
	super->pccs_generation = 1;
	super->pccs_async_threshold = PCC_DEFAULT_ASYNC_THRESHOLD;
	super->pccs_mode = S_IRUSR;

	return 0;
}

/* Rule based auto caching */
static void pcc_id_list_free(struct pcc_expression *expr)
{
	struct pcc_match_id *id, *n;

	if (expr->pe_opc == PCC_FIELD_OP_EQ) {
		list_for_each_entry_safe(id, n, &expr->pe_cond, pmi_linkage) {
			list_del_init(&id->pmi_linkage);
			OBD_FREE_PTR(id);
		}
	}
}

static void pcc_fname_list_free(struct pcc_expression *expr)
{
	struct pcc_match_fname *fname, *n;

	LASSERT(expr->pe_opc == PCC_FIELD_OP_EQ);
	list_for_each_entry_safe(fname, n, &expr->pe_cond, pmf_linkage) {
		OBD_FREE(fname->pmf_name, strlen(fname->pmf_name) + 1);
		list_del_init(&fname->pmf_linkage);
		OBD_FREE_PTR(fname);
	}
}

static void pcc_size_list_free(struct pcc_expression *expr)
{
	struct pcc_match_size *sz, *n;

	if (expr->pe_opc == PCC_FIELD_OP_EQ) {
		list_for_each_entry_safe(sz, n, &expr->pe_cond, pms_linkage) {
			list_del_init(&sz->pms_linkage);
			OBD_FREE_PTR(sz);
		}
	}
}

static void pcc_expression_free(struct pcc_expression *expr)
{
	LASSERT(expr->pe_field >= PCC_FIELD_UID &&
		expr->pe_field < PCC_FIELD_MAX);
	switch (expr->pe_field) {
	case PCC_FIELD_UID:
	case PCC_FIELD_GID:
	case PCC_FIELD_PROJID:
		pcc_id_list_free(expr);
		break;
	case PCC_FIELD_FNAME:
		pcc_fname_list_free(expr);
		break;
	case PCC_FIELD_SIZE:
		pcc_size_list_free(expr);
		break;
	case PCC_FIELD_MTIME:
		break;
	default:
		LBUG();
	}
	OBD_FREE_PTR(expr);
}

static void pcc_conjunction_free(struct pcc_conjunction *conjunction)
{
	struct pcc_expression *expression, *n;

	LASSERT(list_empty(&conjunction->pc_linkage));
	list_for_each_entry_safe(expression, n,
				 &conjunction->pc_expressions,
				 pe_linkage) {
		list_del_init(&expression->pe_linkage);
		pcc_expression_free(expression);
	}
	OBD_FREE_PTR(conjunction);
}

static void pcc_rule_conds_free(struct list_head *cond_list)
{
	struct pcc_conjunction *conjunction, *n;

	list_for_each_entry_safe(conjunction, n, cond_list, pc_linkage) {
		list_del_init(&conjunction->pc_linkage);
		pcc_conjunction_free(conjunction);
	}
}

static void pcc_cmd_fini(struct pcc_cmd *cmd)
{
	if (cmd->pccc_cmd == PCC_ADD_DATASET) {
		if (!list_empty(&cmd->u.pccc_add.pccc_conds))
			pcc_rule_conds_free(&cmd->u.pccc_add.pccc_conds);
		OBD_FREE(cmd->u.pccc_add.pccc_conds_str,
			 strlen(cmd->u.pccc_add.pccc_conds_str) + 1);
	}
}

#define PCC_DISJUNCTION_DELIM	(",")
#define PCC_CONJUNCTION_DELIM	("&")
#define PCC_EXPRESSION_DELIM_EQ	("=")
#define PCC_EXPRESSION_DELIM_LT	("<")
#define PCC_EXPRESSION_DELIM_GT	(">")

static int
pcc_fname_list_add(char *id, struct list_head *fname_list)
{
	struct pcc_match_fname *fname;

	OBD_ALLOC_PTR(fname);
	if (fname == NULL)
		return -ENOMEM;

	OBD_ALLOC(fname->pmf_name, strlen(id) + 1);
	if (fname->pmf_name == NULL) {
		OBD_FREE_PTR(fname);
		return -ENOMEM;
	}

	strcpy(fname->pmf_name, id);
	list_add_tail(&fname->pmf_linkage, fname_list);
	return 0;
}

static int
pcc_fname_list_parse(char *str, struct pcc_expression *expr)
{
	int rc = 0;

	ENTRY;

	while (rc == 0 && str) {
		char *fname = strsep(&str, " ");

		if (*fname)
			rc = pcc_fname_list_add(fname, &expr->pe_cond);
	}
	if (list_empty(&expr->pe_cond))
		rc = -EINVAL;
	if (rc)
		pcc_fname_list_free(expr);
	RETURN(rc);
}

static int
pcc_id_list_parse(char *str, struct pcc_expression *expr)
{
	int rc = 0;

	ENTRY;

	while (str) {
		char *num;
		struct pcc_match_id *id;
		unsigned long id_val;

		num = strsep(&str, " ");
		if (!*num)
			continue;
		rc = kstrtoul(num, 0, &id_val);
		if (rc)
			GOTO(out, rc);

		OBD_ALLOC_PTR(id);
		if (id == NULL)
			GOTO(out, rc = -ENOMEM);

		id->pmi_id = id_val;
		list_add_tail(&id->pmi_linkage, &expr->pe_cond);
	}
	if (list_empty(&expr->pe_cond))
		rc = -EINVAL;
out:
	if (rc)
		pcc_id_list_free(expr);
	RETURN(rc);
}

static int
pcc_expr_id_parse(char *str, struct pcc_expression *expr)
{
	int rc;

	ENTRY;

	if (expr->pe_field != PCC_FIELD_UID &&
	    expr->pe_field != PCC_FIELD_GID &&
	    expr->pe_field != PCC_FIELD_PROJID)
		RETURN(-EINVAL);

	if (expr->pe_opc >= PCC_FIELD_OP_MAX)
		RETURN(-EINVAL);

	if (expr->pe_opc == PCC_FIELD_OP_EQ)
		rc = pcc_id_list_parse(str, expr);
	else {
		unsigned long id;

		rc = kstrtoul(str, 10, &id);
		if (rc != 0)
			RETURN(-EINVAL);

		if (id <= 0 || id >= (u32)~0U)
			RETURN(-EINVAL);

		expr->pe_id = id;
	}

	RETURN(rc);
}

static int
pcc_size_list_parse(char *str, struct pcc_expression *expr)
{
	int rc = 0;

	ENTRY;

	while (rc == 0 && str) {
		char *sz_str;
		struct pcc_match_size *sz;
		__u64 sz_val;

		sz_str = strsep(&str, " ");
		if (!*sz_str)
			continue;

		rc = sysfs_memparse(sz_str, strlen(sz_str), &sz_val, "MiB");
		if (rc < 0)
			GOTO(out, rc);

		OBD_ALLOC_PTR(sz);
		if (sz == NULL)
			GOTO(out, rc = -ENOMEM);

		sz->pms_size = sz_val;
		list_add_tail(&sz->pms_linkage, &expr->pe_cond);
	}
	if (list_empty(&expr->pe_cond))
		rc = -EINVAL;
out:
	if (rc)
		pcc_id_list_free(expr);
	RETURN(rc);
}

static int
pcc_expr_size_parse(char *str, struct pcc_expression *expr)
{
	if (expr->pe_opc == PCC_FIELD_OP_EQ)
		return pcc_size_list_parse(str, expr);
	else
		return sysfs_memparse(str, strlen(str), &expr->pe_size, "MiB");
}

/*
 * Parse relative file age timestamp, allowing suffix for ease of use:
 * s = seconds, m = minutes, h = hours, d = days, w = weeks, y = years
 */
static int pcc_expr_time_parse(char *str, struct pcc_expression *expr)
{
	unsigned long mtime;
	int len = strlen(str);
	unsigned int mult = 1;
	char buf[10];
	int rc;

	if (expr->pe_opc == PCC_FIELD_OP_EQ)
		return -EOPNOTSUPP;

	/* 1B seconds is enough, and avoids the need for overflow checking */
	if (len > 10)
		return -EOVERFLOW;

	strncpy(buf, str, sizeof(buf));
	rc = strspn(buf, "0123456789");
	if (rc < len) {
		switch (str[rc]) {
		case 'y':
			mult *= 52;
			fallthrough;
		case 'w':
			mult *= 7;
			fallthrough;
		case 'd':
			mult *= 24;
			fallthrough;
		case 'h':
			mult *= 60;
			fallthrough;
		case 'm':
			mult *= 60;
			fallthrough;
		case 's':
			break;
		default:
			return -EINVAL;
		}
		buf[rc] = '\0';
	}
	rc = kstrtoul(buf, 10, &mtime);
	if (!rc)
		expr->pe_mtime = mtime * mult;

	return rc;
}

static inline char *
pcc_get_opcode_delim(enum pcc_field_op opc)
{
	switch (opc) {
	case PCC_FIELD_OP_EQ:
		return PCC_EXPRESSION_DELIM_EQ;
	case PCC_FIELD_OP_LT:
		return PCC_EXPRESSION_DELIM_LT;
	case PCC_FIELD_OP_GT:
		return PCC_EXPRESSION_DELIM_GT;
	default:
		LBUG();
		return NULL;
	}
}

static enum pcc_field_op
pcc_get_field_opcode(char **src, char **field)
{
	int i;

	ENTRY;

	for (i = PCC_FIELD_OP_EQ; i < PCC_FIELD_OP_MAX; i++) {
		char *tmp = *src;

		*field = strim(strsep(&tmp, pcc_get_opcode_delim(i)));
		if (**field && tmp) {
			*src = tmp;
			RETURN(i);
		}
	}

	RETURN(PCC_FIELD_OP_INV);
}

static int
pcc_expression_parse(char *str, struct list_head *cond_list)
{
	struct pcc_expression *expr;
	enum pcc_field_op opc;
	char *field;
	int len;
	int rc = 0;

	OBD_ALLOC_PTR(expr);
	if (expr == NULL)
		return -ENOMEM;

	opc = pcc_get_field_opcode(&str, &field);
	if (opc == PCC_FIELD_OP_INV)
		/* No LHS or no '=' */
		GOTO(out, rc = -EINVAL);
	str = skip_spaces(str);
	len = strlen(str);
	if (str[0] != '{' || str[len - 1] != '}')
		GOTO(out, rc = -EINVAL);

	/* Skip '{' and '}' */
	str[len - 1] = '\0';
	str += 1;

	expr->pe_opc = opc;
	INIT_LIST_HEAD(&expr->pe_cond);
	if (strcmp(field, "uid") == 0) {
		expr->pe_field = PCC_FIELD_UID;
		rc = pcc_expr_id_parse(str, expr);
	} else if (strcmp(field, "gid") == 0) {
		expr->pe_field = PCC_FIELD_GID;
		rc = pcc_expr_id_parse(str, expr);
	} else if (strcmp(field, "projid") == 0) {
		expr->pe_field = PCC_FIELD_PROJID;
		rc = pcc_expr_id_parse(str, expr);
	} else if (strcmp(field, "size") == 0) {
		expr->pe_field = PCC_FIELD_SIZE;
		rc = pcc_expr_size_parse(str, expr);
	} else if (strcmp(field, "mtime") == 0) {
		expr->pe_field = PCC_FIELD_MTIME;
		rc = pcc_expr_time_parse(str, expr);
	} else if (strcmp(field, "fname") == 0 ||
		   strcmp(field, "filename") == 0) {
		if (opc != PCC_FIELD_OP_EQ)
			GOTO(out, rc = -EINVAL);
		expr->pe_field = PCC_FIELD_FNAME;
		rc = pcc_fname_list_parse(str, expr);
	} else {
		GOTO(out, rc = -EINVAL);
	}
	if (rc < 0)
		GOTO(out, rc);

	list_add_tail(&expr->pe_linkage, cond_list);
	return 0;
out:
	OBD_FREE_PTR(expr);
	return rc;
}

static int
pcc_conjunction_parse(char *str, struct list_head *cond_list)
{
	struct pcc_conjunction *conjunction;
	int rc = 0;

	OBD_ALLOC_PTR(conjunction);
	if (conjunction == NULL)
		return -ENOMEM;

	INIT_LIST_HEAD(&conjunction->pc_expressions);
	list_add_tail(&conjunction->pc_linkage, cond_list);

	while (rc == 0 && str) {
		char *expr = strsep(&str, PCC_CONJUNCTION_DELIM);

		rc = pcc_expression_parse(expr, &conjunction->pc_expressions);
	}
	return rc;
}

static int pcc_conds_parse(char *orig, struct list_head *cond_list)
{
	char *str;
	int rc = 0;

	orig = kstrdup(orig, GFP_KERNEL);
	if (!orig)
		return -ENOMEM;
	str = orig;

	INIT_LIST_HEAD(cond_list);
	while (rc == 0 && str) {
		char *term = strsep(&str, PCC_DISJUNCTION_DELIM);

		rc = pcc_conjunction_parse(term, cond_list);
	}
	kfree(orig);
	return rc;
}

static int pcc_id_parse(struct pcc_cmd *cmd, const char *id)
{
	int rc;

	OBD_ALLOC(cmd->u.pccc_add.pccc_conds_str, strlen(id) + 1);
	if (cmd->u.pccc_add.pccc_conds_str == NULL)
		return -ENOMEM;

	memcpy(cmd->u.pccc_add.pccc_conds_str, id, strlen(id));

	rc = pcc_conds_parse(cmd->u.pccc_add.pccc_conds_str,
			     &cmd->u.pccc_add.pccc_conds);
	if (rc)
		pcc_cmd_fini(cmd);

	return rc;
}

static int
pcc_parse_value_pair(struct pcc_cmd *cmd, char *buffer)
{
	char *key, *val;
	unsigned long id;
	bool enable;
	int rc;

	val = buffer;
	key = strsep(&val, "=");
	if (val == NULL || strlen(val) == 0)
		return -EINVAL;

	/* Key of the value pair */
	if (strcmp(key, "rwid") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id <= 0)
			return -EINVAL;
		cmd->u.pccc_add.pccc_rwid = id;
	} else if (strcmp(key, "roid") == 0) {
		rc = kstrtoul(val, 10, &id);
		if (rc)
			return rc;
		if (id <= 0)
			return -EINVAL;
		cmd->u.pccc_add.pccc_roid = id;
	} else if (strcmp(key, "auto_attach") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_AUTO_ATTACH;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_AUTO_ATTACH;
	} else if (strcmp(key, "open_attach") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_OPEN_ATTACH;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_OPEN_ATTACH;
	} else if (strcmp(key, "io_attach") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_IO_ATTACH;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_IO_ATTACH;
	} else if (strcmp(key, "stat_attach") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_STAT_ATTACH;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_STAT_ATTACH;
	} else if (strcmp(key, "rwpcc") == 0 || strcmp(key, "pccrw") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_PCCRW;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_PCCRW;
	} else if (strcmp(key, "ropcc") == 0 || strcmp(key, "pccro") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_PCCRO;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_PCCRO;
	} else if (strcmp(key, "mmap_conv") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
#ifdef HAVE_ADD_TO_PAGE_CACHE_LOCKED
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_MMAP_CONV;
#else
			CWARN("mmap convert is not supported, ignored it.\n");
#endif
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_MMAP_CONV;
	} else if (strcmp(key, "proj_quota") == 0) {
		rc = kstrtobool(val, &enable);
		if (rc)
			return rc;
		if (enable)
			cmd->u.pccc_add.pccc_flags |= PCC_DATASET_PROJ_QUOTA;
		else
			cmd->u.pccc_add.pccc_flags &= ~PCC_DATASET_PROJ_QUOTA;
	} else if (strcmp(key, "hsmtool") == 0) {
		cmd->u.pccc_add.pccc_hsmtool_type = hsmtool_string2type(val);
		if (cmd->u.pccc_add.pccc_hsmtool_type != HSMTOOL_POSIX_V1 &&
		    cmd->u.pccc_add.pccc_hsmtool_type != HSMTOOL_POSIX_V2)
			return -EINVAL;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int
pcc_parse_value_pairs(struct pcc_cmd *cmd, char *buffer)
{
	char *val;
	char *token;
	int rc;

	switch (cmd->pccc_cmd) {
	case PCC_ADD_DATASET:
		cmd->u.pccc_add.pccc_hsmtool_type = HSMTOOL_UNKNOWN;
		/* Enable these features by default */
		cmd->u.pccc_add.pccc_flags |= PCC_DATASET_AUTO_ATTACH |
					      PCC_DATASET_PROJ_QUOTA;
		break;
	case PCC_DEL_DATASET:
	case PCC_CLEAR_ALL:
		break;
	default:
		return -EINVAL;
	}

	val = buffer;
	while (val != NULL && strlen(val) != 0) {
		token = strsep(&val, " ");
		rc = pcc_parse_value_pair(cmd, token);
		if (rc)
			return rc;
	}

	return 0;
}

static void
pcc_dataset_rule_fini(struct pcc_match_rule *rule)
{
	if (!list_empty(&rule->pmr_conds))
		pcc_rule_conds_free(&rule->pmr_conds);
	LASSERT(rule->pmr_conds_str != NULL);
	OBD_FREE(rule->pmr_conds_str, strlen(rule->pmr_conds_str) + 1);
}

static int
pcc_dataset_rule_init(struct pcc_match_rule *rule, struct pcc_cmd *cmd)
{
	int rc = 0;

	LASSERT(cmd->u.pccc_add.pccc_conds_str);
	OBD_ALLOC(rule->pmr_conds_str,
		  strlen(cmd->u.pccc_add.pccc_conds_str) + 1);
	if (rule->pmr_conds_str == NULL)
		return -ENOMEM;

	memcpy(rule->pmr_conds_str,
	       cmd->u.pccc_add.pccc_conds_str,
	       strlen(cmd->u.pccc_add.pccc_conds_str));

	INIT_LIST_HEAD(&rule->pmr_conds);
	if (!list_empty(&cmd->u.pccc_add.pccc_conds))
		rc = pcc_conds_parse(rule->pmr_conds_str,
				     &rule->pmr_conds);

	if (rc)
		pcc_dataset_rule_fini(rule);

	return rc;
}

/* Rule Matching */
static int
pcc_id_list_match(struct list_head *id_list, __u32 id_val)
{
	struct pcc_match_id *id;

	list_for_each_entry(id, id_list, pmi_linkage) {
		if (id->pmi_id == id_val)
			return 1;
	}
	return 0;
}

static bool
cfs_match_wildcard(const char *pattern, const char *content)
{
	if (*pattern == '\0' && *content == '\0')
		return true;

	if (*pattern == '*' && *(pattern + 1) != '\0' && *content == '\0')
		return false;

	while (*pattern == *content) {
		pattern++;
		content++;
		if (*pattern == '\0' && *content == '\0')
			return true;

		if (*pattern == '*' && *(pattern + 1) != '\0' &&
		    *content == '\0')
			return false;
	}

	if (*pattern == '*')
		return (cfs_match_wildcard(pattern + 1, content) ||
			cfs_match_wildcard(pattern, content + 1));

	return false;
}

static int
pcc_fname_list_match(struct list_head *fname_list, const char *name)
{
	struct pcc_match_fname *fname;

	list_for_each_entry(fname, fname_list, pmf_linkage) {
		if (cfs_match_wildcard(fname->pmf_name, name))
			return 1;
	}
	return 0;
}

static int
pcc_expr_id_match(struct pcc_expression *expr, __u32 id)
{
	switch (expr->pe_opc) {
	case PCC_FIELD_OP_EQ:
		return pcc_id_list_match(&expr->pe_cond, id);
	case PCC_FIELD_OP_LT:
		return id < expr->pe_id;
	case PCC_FIELD_OP_GT:
		return id > expr->pe_id;
	default:
		return 0;
	}
}

static int
pcc_size_list_match(struct list_head *id_list, __u64 sz_val)
{
	struct pcc_match_size *sz;

	list_for_each_entry(sz, id_list, pms_linkage) {
		if (sz->pms_size == sz_val)
			return 1;
	}
	return 0;
}

static int
pcc_expr_size_match(struct pcc_expression *expr, __u64 sz)
{
	switch (expr->pe_opc) {
	case PCC_FIELD_OP_EQ:
		return pcc_size_list_match(&expr->pe_cond, sz);
	case PCC_FIELD_OP_LT:
		return sz < expr->pe_size;
	case PCC_FIELD_OP_GT:
		return sz > expr->pe_size;
	default:
		return 0;
	}
}

static inline int
pcc_expr_time_match(struct pcc_expression *expr, __u64 time)
{
	/* pe_mtime and pe_size are both __u64 in the same union */
	return pcc_expr_size_match(expr, ktime_get_real_seconds() - time);
}

static int
pcc_expression_match(struct pcc_expression *expr, struct pcc_matcher *matcher)
{
	switch (expr->pe_field) {
	case PCC_FIELD_UID:
		return pcc_expr_id_match(expr, matcher->pm_uid);
	case PCC_FIELD_GID:
		return pcc_expr_id_match(expr, matcher->pm_gid);
	case PCC_FIELD_PROJID:
		return pcc_expr_id_match(expr, matcher->pm_projid);
	case PCC_FIELD_SIZE:
		return pcc_expr_size_match(expr, matcher->pm_size);
	case PCC_FIELD_MTIME:
		return pcc_expr_time_match(expr, matcher->pm_mtime);
	case PCC_FIELD_FNAME:
		return pcc_fname_list_match(&expr->pe_cond,
					    matcher->pm_name->name);
	default:
		return 0;
	}
}

static int
pcc_conjunction_match(struct pcc_conjunction *conjunction,
		      struct pcc_matcher *matcher)
{
	struct pcc_expression *expr;
	int matched;

	list_for_each_entry(expr, &conjunction->pc_expressions, pe_linkage) {
		matched = pcc_expression_match(expr, matcher);
		if (!matched)
			return 0;
	}

	return 1;
}

static int
pcc_cond_match(struct pcc_match_rule *rule, struct pcc_matcher *matcher)
{
	struct pcc_conjunction *conjunction;
	int matched;

	list_for_each_entry(conjunction, &rule->pmr_conds, pc_linkage) {
		matched = pcc_conjunction_match(conjunction, matcher);
		if (matched)
			return 1;
	}

	return 0;
}

static inline bool
pcc_dataset_attach_allowed(struct pcc_dataset *dataset, enum lu_pcc_type type)
{
	if (type == LU_PCC_READWRITE && dataset->pccd_flags & PCC_DATASET_PCCRW)
		return true;

	if (type == LU_PCC_READONLY && dataset->pccd_flags & PCC_DATASET_PCCRO)
		return true;

	return false;
}

struct pcc_dataset*
pcc_dataset_match_get(struct pcc_super *super, enum lu_pcc_type type,
		      struct pcc_matcher *matcher)
{
	struct pcc_dataset *dataset;
	struct pcc_dataset *selected = NULL;

	down_read(&super->pccs_rw_sem);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		if (pcc_dataset_attach_allowed(dataset, type) &&
		    pcc_cond_match(&dataset->pccd_rule, matcher)) {
			kref_get(&dataset->pccd_refcount);
			selected = dataset;
			break;
		}
	}
	up_read(&super->pccs_rw_sem);
	if (selected)
		CDEBUG(D_CACHE, "PCC create, matched %s - %d:%d:%d:%s\n",
		       dataset->pccd_rule.pmr_conds_str,
		       matcher->pm_uid, matcher->pm_gid,
		       matcher->pm_projid, matcher->pm_name->name);

	return selected;
}

static int
pcc_dataset_flags_check(struct pcc_super *super, struct pcc_cmd *cmd)
{
	struct ll_sb_info *sbi;

	sbi = container_of(super, struct ll_sb_info, ll_pcc_super);

	/*
	 * A PCC backend can provide caching service for both PCC-RW and PCC-RO.
	 * It defaults to readonly PCC as long as the server supports it.
	 */
	if (!(exp_connect_flags2(sbi->ll_md_exp) & OBD_CONNECT2_PCCRO)) {
		if (cmd->u.pccc_add.pccc_flags & PCC_DATASET_PCCRO ||
		    !(cmd->u.pccc_add.pccc_flags & PCC_DATASET_PCCRW))
			return -EOPNOTSUPP;
	} else if ((cmd->u.pccc_add.pccc_flags & PCC_DATASET_PCC_ALL) == 0) {
		cmd->u.pccc_add.pccc_flags |= PCC_DATASET_PCC_DEFAULT;
	} /* else RWPCC or ROPCC must have been given */

	if (cmd->u.pccc_add.pccc_rwid == 0 &&
	    cmd->u.pccc_add.pccc_roid == 0)
		return -EINVAL;

	if (cmd->u.pccc_add.pccc_rwid == 0 &&
	    cmd->u.pccc_add.pccc_flags & PCC_DATASET_PCCRW)
		cmd->u.pccc_add.pccc_rwid = cmd->u.pccc_add.pccc_roid;

	if (cmd->u.pccc_add.pccc_roid == 0 &&
	    cmd->u.pccc_add.pccc_flags & PCC_DATASET_PCCRO)
		cmd->u.pccc_add.pccc_roid = cmd->u.pccc_add.pccc_rwid;

	if (cmd->u.pccc_add.pccc_hsmtool_type == HSMTOOL_UNKNOWN)
		cmd->u.pccc_add.pccc_hsmtool_type = HSMTOOL_DEFAULT;

	return 0;
}

/**
 * pcc_dataset_add - Add a Cache policy to control which files need be
 * cached and where it will be cached.
 *
 * @super:	superblock of pcc
 * @cmd:	pcc command
 */
static int
pcc_dataset_add(struct pcc_super *super, struct pcc_cmd *cmd)
{
	char *pathname = cmd->pccc_pathname;
	struct pcc_dataset *dataset;
	struct pcc_dataset *tmp;
	bool found = false;
	int rc;

	rc = pcc_dataset_flags_check(super, cmd);
	if (rc)
		return rc;

	OBD_ALLOC_PTR(dataset);
	if (dataset == NULL)
		return -ENOMEM;

	rc = kern_path(pathname, LOOKUP_DIRECTORY, &dataset->pccd_path);
	if (unlikely(rc)) {
		CDEBUG(D_CACHE, "%s: cache path lookup error: rc = %d\n",
		       pathname, rc);
		OBD_FREE_PTR(dataset);
		return rc;
	}
	strncpy(dataset->pccd_pathname, pathname, PATH_MAX);
	dataset->pccd_rwid = cmd->u.pccc_add.pccc_rwid;
	dataset->pccd_roid = cmd->u.pccc_add.pccc_roid;
	dataset->pccd_flags = cmd->u.pccc_add.pccc_flags;
	dataset->pccd_hsmtool_type = cmd->u.pccc_add.pccc_hsmtool_type;
	kref_init(&dataset->pccd_refcount);

	rc = pcc_dataset_rule_init(&dataset->pccd_rule, cmd);
	if (rc) {
		pcc_dataset_put(dataset);
		return rc;
	}

	down_write(&super->pccs_rw_sem);
	list_for_each_entry(tmp, &super->pccs_datasets, pccd_linkage) {
		if (strcmp(tmp->pccd_pathname, pathname) == 0 ||
		    (dataset->pccd_rwid != 0 &&
		     dataset->pccd_rwid == tmp->pccd_rwid) ||
		    (dataset->pccd_roid != 0 &&
		     dataset->pccd_roid == tmp->pccd_roid)) {
			found = true;
			break;
		}
	}
	if (!found)
		list_add(&dataset->pccd_linkage, &super->pccs_datasets);
	up_write(&super->pccs_rw_sem);

	if (found) {
		pcc_dataset_put(dataset);
		rc = -EEXIST;
	}

	return rc;
}

static struct pcc_dataset *
pcc_dataset_get(struct pcc_super *super, enum lu_pcc_type type, __u32 id)
{
	struct pcc_dataset *dataset;
	struct pcc_dataset *selected = NULL;

	/*
	 * archive ID (read-write ID) or read-only ID is unique in the list,
	 * we just return last added one as first priority.
	 * @id == 0, it will select the first one as candidate dataset.
	 */
	down_read(&super->pccs_rw_sem);
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		if (type == LU_PCC_READWRITE &&
		    (!(dataset->pccd_rwid == id || id == 0) ||
		     !(dataset->pccd_flags & PCC_DATASET_PCCRW)))
			continue;
		if (type == LU_PCC_READONLY &&
		    (!(dataset->pccd_roid == id || id == 0) ||
		     !(dataset->pccd_flags & PCC_DATASET_PCCRO)))
			continue;
		kref_get(&dataset->pccd_refcount);
		selected = dataset;
		break;
	}
	up_read(&super->pccs_rw_sem);
	if (selected)
		CDEBUG(D_CACHE, "matched id %u, PCC mode %d\n", id, type);

	return selected;
}

void pcc_dataset_free(struct kref *kref)
{
	struct pcc_dataset *dataset = container_of(kref, struct pcc_dataset,
						   pccd_refcount);

	pcc_dataset_rule_fini(&dataset->pccd_rule);
	path_put(&dataset->pccd_path);
	OBD_FREE_PTR(dataset);
}

void
pcc_dataset_put(struct pcc_dataset *dataset)
{
	kref_put(&dataset->pccd_refcount, pcc_dataset_free);
}

static int
pcc_dataset_del(struct pcc_super *super, char *pathname)
{
	struct list_head *l, *tmp;
	struct pcc_dataset *dataset;
	int rc = -ENOENT;

	down_write(&super->pccs_rw_sem);
	list_for_each_safe(l, tmp, &super->pccs_datasets) {
		dataset = list_entry(l, struct pcc_dataset, pccd_linkage);
		if (strcmp(dataset->pccd_pathname, pathname) == 0) {
			list_del_init(&dataset->pccd_linkage);
			pcc_dataset_put(dataset);
			super->pccs_generation++;
			rc = 0;
			break;
		}
	}
	up_write(&super->pccs_rw_sem);
	return rc;
}

static void
pcc_dataset_dump(struct pcc_dataset *dataset, struct seq_file *m)
{
	seq_puts(m, "  -\n");
	seq_printf(m, "    " PCC_YAML_PCCPATH ": %s\n",
		   dataset->pccd_pathname);
	seq_printf(m, "    " PCC_YAML_HSMTOOL ": %s\n",
		   hsmtool_type2string(dataset->pccd_hsmtool_type));
	seq_printf(m, "    " PCC_YAML_RWID ": %u\n", dataset->pccd_rwid);
	seq_printf(m, "    " PCC_YAML_ROID ": %u\n", dataset->pccd_roid);
	seq_printf(m, "    " PCC_YAML_FLAGS ": %x\n", dataset->pccd_flags);
	seq_printf(m, "    " PCC_YAML_AUTOCACHE ": %s\n",
		   dataset->pccd_rule.pmr_conds_str);
}

int
pcc_super_dump(struct pcc_super *super, struct seq_file *m)
{
	struct pcc_dataset *dataset;

	down_read(&super->pccs_rw_sem);
	if (!list_empty(&super->pccs_datasets))
		seq_puts(m, "pcc:\n");
	list_for_each_entry(dataset, &super->pccs_datasets, pccd_linkage) {
		pcc_dataset_dump(dataset, m);
	}
	up_read(&super->pccs_rw_sem);
	return 0;
}

static void pcc_remove_datasets(struct pcc_super *super)
{
	struct pcc_dataset *dataset, *tmp;

	down_write(&super->pccs_rw_sem);
	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		list_del(&dataset->pccd_linkage);
		pcc_dataset_put(dataset);
	}
	super->pccs_generation++;
	up_write(&super->pccs_rw_sem);
}

void pcc_super_fini(struct pcc_super *super)
{
	pcc_remove_datasets(super);
	put_cred(super->pccs_cred);
}

static bool pathname_is_valid(const char *pathname)
{
	/* Needs to be absolute path */
	if (pathname == NULL || strlen(pathname) == 0 ||
	    strlen(pathname) >= PATH_MAX || pathname[0] != '/')
		return false;
	return true;
}

static struct pcc_cmd *
pcc_cmd_parse(char *buffer, unsigned long count)
{
	static struct pcc_cmd *cmd;
	char *token;
	char *val;
	int rc = 0;

	OBD_ALLOC_PTR(cmd);
	if (cmd == NULL)
		GOTO(out, rc = -ENOMEM);

	/* clear all setting */
	if (strncmp(buffer, "clear", 5) == 0) {
		cmd->pccc_cmd = PCC_CLEAR_ALL;
		GOTO(out, rc = 0);
	}

	val = buffer;
	token = strsep(&val, " ");
	if (val == NULL || strlen(val) == 0)
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Type of the command */
	if (strcmp(token, "add") == 0)
		cmd->pccc_cmd = PCC_ADD_DATASET;
	else if (strcmp(token, "del") == 0)
		cmd->pccc_cmd = PCC_DEL_DATASET;
	else
		GOTO(out_free_cmd, rc = -EINVAL);

	/* Pathname of the dataset */
	token = strsep(&val, " ");
	if ((val == NULL && cmd->pccc_cmd != PCC_DEL_DATASET) ||
	    !pathname_is_valid(token))
		GOTO(out_free_cmd, rc = -EINVAL);
	cmd->pccc_pathname = token;

	if (cmd->pccc_cmd == PCC_ADD_DATASET) {
		/* List of ID */
		LASSERT(val);
		token = val;
		val = strrchr(token, '}');
		if (!val)
			GOTO(out_free_cmd, rc = -EINVAL);

		/* Skip '}' */
		val++;
		if (*val == '\0') {
			val = NULL;
		} else if (*val == ' ') {
			*val = '\0';
			val++;
		} else {
			GOTO(out_free_cmd, rc = -EINVAL);
		}

		rc = pcc_id_parse(cmd, token);
		if (rc)
			GOTO(out_free_cmd, rc);

		rc = pcc_parse_value_pairs(cmd, val);
		if (rc)
			GOTO(out_cmd_fini, rc = -EINVAL);
	}
	goto out;
out_cmd_fini:
	pcc_cmd_fini(cmd);
out_free_cmd:
	OBD_FREE_PTR(cmd);
out:
	if (rc)
		cmd = ERR_PTR(rc);
	return cmd;
}

int pcc_cmd_handle(char *buffer, unsigned long count,
		   struct pcc_super *super)
{
	int rc = 0;
	struct pcc_cmd *cmd;

	cmd = pcc_cmd_parse(buffer, count);
	if (IS_ERR(cmd))
		return PTR_ERR(cmd);

	switch (cmd->pccc_cmd) {
	case PCC_ADD_DATASET:
		rc = pcc_dataset_add(super, cmd);
		break;
	case PCC_DEL_DATASET:
		rc = pcc_dataset_del(super, cmd->pccc_pathname);
		break;
	case PCC_CLEAR_ALL:
		pcc_remove_datasets(super);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	pcc_cmd_fini(cmd);
	OBD_FREE_PTR(cmd);
	return rc;
}

static inline void pcc_inode_lock(struct inode *inode)
{
	mutex_lock(&ll_i2info(inode)->lli_pcc_lock);
}

static inline void pcc_inode_unlock(struct inode *inode)
{
	mutex_unlock(&ll_i2info(inode)->lli_pcc_lock);
}

static void pcc_inode_init(struct pcc_inode *pcci, struct ll_inode_info *lli)
{
	pcci->pcci_lli = lli;
	lli->lli_pcc_inode = pcci;
	atomic_set(&pcci->pcci_refcount, 0);
	pcci->pcci_type = LU_PCC_NONE;
	pcci->pcci_layout_gen = CL_LAYOUT_GEN_NONE;
	atomic_set(&pcci->pcci_active_ios, 0);
	init_waitqueue_head(&pcci->pcci_waitq);
}

static void pcc_inode_fini(struct pcc_inode *pcci)
{
	struct inode *pcc_inode = pcci->pcci_path.dentry->d_inode;
	struct ll_inode_info *lli = pcci->pcci_lli;

	/* The PCC file was once mmaped? */
	if (pcc_inode && pcc_inode->i_mapping != &pcc_inode->i_data)
		pcc_inode->i_mapping = &pcc_inode->i_data;

	path_put(&pcci->pcci_path);
	pcci->pcci_type = LU_PCC_NONE;
	OBD_SLAB_FREE_PTR(pcci, pcc_inode_slab);
	lli->lli_pcc_inode = NULL;
}

static void pcc_inode_get(struct pcc_inode *pcci)
{
	atomic_inc(&pcci->pcci_refcount);
}

static void pcc_inode_put(struct pcc_inode *pcci)
{
	if (atomic_dec_and_test(&pcci->pcci_refcount))
		pcc_inode_fini(pcci);
}

void pcc_inode_free(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	if (!pcci)
		return;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci) {
		WARN_ON(atomic_read(&pcci->pcci_refcount) > 1);
		pcc_inode_put(pcci);
	}
	pcc_inode_unlock(inode);
}

/*
 * Add HSMTOOL_POSIX_V2 support.
 * As Andreas suggested, we'd better use new layout to
 * reduce overhead:
 * (fid->f_oid >> 16 & oxFFFF)/FID
 */
#define PCC_DATASET_MAX_PATH (6 * 5 + FID_NOBRACE_LEN + 1)
static int pcc_fid2dataset_path(struct pcc_dataset *dataset, char *buf,
				int sz, struct lu_fid *fid)
{
	switch (dataset->pccd_hsmtool_type) {
	case HSMTOOL_POSIX_V1:
		return snprintf(buf, sz, "%04x/%04x/%04x/%04x/%04x/%04x/"
				DFID_NOBRACE,
				(fid)->f_oid       & 0xFFFF,
				(fid)->f_oid >> 16 & 0xFFFF,
				(unsigned int)((fid)->f_seq       & 0xFFFF),
				(unsigned int)((fid)->f_seq >> 16 & 0xFFFF),
				(unsigned int)((fid)->f_seq >> 32 & 0xFFFF),
				(unsigned int)((fid)->f_seq >> 48 & 0xFFFF),
				PFID(fid));
	case HSMTOOL_POSIX_V2:
		return snprintf(buf, sz, "%04x/"DFID_NOBRACE,
				(__u32)((fid)->f_oid ^ (fid)->f_seq) & 0XFFFF,
				PFID(fid));
	default:
		CERROR(DFID ": unknown archive format %u: rc = %d\n",
		       PFID(fid), dataset->pccd_hsmtool_type, -EINVAL);
		return -EINVAL;
	}
}

static inline const struct cred *pcc_super_cred(struct super_block *sb)
{
	return ll_s2sbi(sb)->ll_pcc_super.pccs_cred;
}

void pcc_file_init(struct pcc_file *pccf)
{
	pccf->pccf_file = NULL;
	pccf->pccf_type = LU_PCC_NONE;
}

static inline bool pcc_auto_attach_enabled(struct pcc_dataset *dataset,
					   enum lu_pcc_type type,
					   enum pcc_io_type iot)
{
	if (pcc_dataset_attach_allowed(dataset, type)) {
		if (iot == PIT_OPEN)
			return dataset->pccd_flags & PCC_DATASET_OPEN_ATTACH;
		if (iot == PIT_GETATTR)
			return dataset->pccd_flags & PCC_DATASET_STAT_ATTACH;
		else
			return dataset->pccd_flags & PCC_DATASET_AUTO_ATTACH;
	}

	return false;
}

static const char pcc_xattr_layout[] = XATTR_USER_PREFIX "PCC.layout";

static int pcc_layout_xattr_set(struct pcc_inode *pcci, __u32 gen)
{
	struct dentry *pcc_dentry = pcci->pcci_path.dentry;
	struct ll_inode_info *lli = pcci->pcci_lli;
	int rc;

	ENTRY;

	if (!(lli->lli_pcc_dsflags & PCC_DATASET_AUTO_ATTACH))
		RETURN(0);

	rc = ll_vfs_setxattr(pcc_dentry, pcc_dentry->d_inode, pcc_xattr_layout,
			     &gen, sizeof(gen), 0);

	RETURN(rc);
}

static int pcc_get_layout_info(struct inode *inode, struct cl_layout *clt)
{
	struct lu_env *env;
	struct ll_inode_info *lli = ll_i2info(inode);
	__u16 refcheck;
	int rc;

	ENTRY;

	if (!lli->lli_clob)
		RETURN(-EINVAL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	rc = cl_object_layout_get(env, lli->lli_clob, clt);
	if (rc < 0)
		CDEBUG(D_INODE, "Cannot get layout for "DFID"\n",
		       PFID(ll_inode2fid(inode)));

	cl_env_put(env, &refcheck);
	RETURN(rc < 0 ? rc : 0);
}

/* Must be called with pcci->pcci_lock held */
static void pcc_inode_attach_init(struct pcc_dataset *dataset,
				  struct pcc_inode *pcci,
				  struct dentry *dentry,
				  enum lu_pcc_type type)
{
	pcci->pcci_path.mnt = mntget(dataset->pccd_path.mnt);
	pcci->pcci_path.dentry = dentry;
	LASSERT(atomic_read(&pcci->pcci_refcount) == 0);
	atomic_set(&pcci->pcci_refcount, 1);
	pcci->pcci_type = type;
	pcci->pcci_attr_valid = false;
}

static inline void pcc_inode_dsflags_set(struct ll_inode_info *lli,
					 struct pcc_dataset *dataset)
{
	lli->lli_pcc_generation = ll_info2pccs(lli)->pccs_generation;
	lli->lli_pcc_dsflags = dataset->pccd_flags;
}

static void pcc_inode_attach_set(struct pcc_super *super,
				 struct pcc_dataset *dataset,
				 struct ll_inode_info *lli,
				 struct pcc_inode *pcci,
				 struct dentry *dentry,
				 enum lu_pcc_type type)
{
	pcc_inode_init(pcci, lli);
	pcc_inode_attach_init(dataset, pcci, dentry, type);
	down_read(&super->pccs_rw_sem);
	pcc_inode_dsflags_set(lli, dataset);
	up_read(&super->pccs_rw_sem);
}

static inline void pcc_layout_gen_set(struct pcc_inode *pcci,
				      __u32 gen)
{
	pcci->pcci_layout_gen = gen;
}

static inline bool pcc_inode_has_layout(struct pcc_inode *pcci)
{
	return pcci->pcci_layout_gen != CL_LAYOUT_GEN_NONE;
}

static struct dentry *pcc_lookup(struct dentry *base, char *pathname)
{
	char *ptr = NULL, *component;
	struct dentry *parent;
	struct dentry *child = ERR_PTR(-ENOENT);

	ptr = pathname;

	/* move past any initial '/' to the start of the first path component*/
	while (*ptr == '/')
		ptr++;

	/* store the start of the first path component */
	component = ptr;

	parent = dget(base);
	while (ptr) {
		/* find the start of the next component - if we don't find it,
		 * the current component is the last component
		 */
		ptr = strchr(ptr, '/');
		/* put a NUL char in place of the '/' before the next compnent
		 * so we can treat this component as a string; note the full
		 * path string is NUL terminated to this is not needed for the
		 * last component
		 */
		if (ptr)
			*ptr = '\0';

		/* look up the current component */
		inode_lock(parent->d_inode);
		child = lookup_one_len(component, parent, strlen(component));
		inode_unlock(parent->d_inode);

		/* repair the path string: put '/' back in place of the NUL */
		if (ptr)
			*ptr = '/';

		dput(parent);

		if (IS_ERR_OR_NULL(child))
			break;

		/* we may find a cached negative dentry */
		if (!d_is_positive(child)) {
			dput(child);
			child = NULL;
			break;
		}

		/* descend in to the next level of the path */
		parent = child;

		/* move the pointer past the '/' to the next component */
		if (ptr)
			ptr++;
		component = ptr;
	}

	/* NULL child means we didn't find anything */
	if (!child)
		child = ERR_PTR(-ENOENT);

	return child;
}

static int pcc_try_dataset_attach(struct inode *inode, __u32 gen,
				  enum lu_pcc_type type,
				  struct pcc_dataset *dataset,
				  bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci = lli->lli_pcc_inode;
	const struct cred *old_cred;
	struct dentry *pcc_dentry = NULL;
	char pathname[PCC_DATASET_MAX_PATH];
	__u32 pcc_gen;
	int rc;

	ENTRY;

	if (type == LU_PCC_READWRITE &&
	    !(dataset->pccd_flags & PCC_DATASET_PCCRW))
		RETURN(0);

	if (type == LU_PCC_READONLY &&
	    !(dataset->pccd_flags & PCC_DATASET_PCCRO))
		RETURN(0);

	rc = pcc_fid2dataset_path(dataset, pathname, PCC_DATASET_MAX_PATH,
				  &lli->lli_fid);

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	pcc_dentry = pcc_lookup(dataset->pccd_path.dentry, pathname);
	if (IS_ERR(pcc_dentry)) {
		rc = PTR_ERR(pcc_dentry);
		CDEBUG(D_CACHE, "%s: path lookup error on "DFID":%s: rc = %d\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(&lli->lli_fid),
		       pathname, rc);
		/* ignore this error */
		GOTO(out, rc = 0);
	}

	rc = ll_vfs_getxattr(pcc_dentry, pcc_dentry->d_inode, pcc_xattr_layout,
			     &pcc_gen, sizeof(pcc_gen));
	if (rc < 0)
		/* ignore this error */
		GOTO(out_put_pcc_dentry, rc = 0);

	rc = 0;
	/* The file is still valid cached in PCC, attach it immediately. */
	if (pcc_gen == gen) {
		CDEBUG(D_CACHE, DFID" L.Gen (%d) consistent, auto attached.\n",
		       PFID(&lli->lli_fid), gen);
		if (!pcci) {
			OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
			if (pcci == NULL)
				GOTO(out_put_pcc_dentry, rc = -ENOMEM);

			pcc_inode_init(pcci, lli);
			dget(pcc_dentry);
			pcc_inode_attach_init(dataset, pcci, pcc_dentry, type);
		} else {
			/*
			 * This happened when a file was once attached into
			 * PCC, and some processes keep this file opened
			 * (pcci->refcount > 1) and corresponding PCC file
			 * without any I/O activity, and then this file was
			 * detached by the manual detach command or the
			 * revocation of the layout lock (i.e. cached LRU lock
			 * shrinking).
			 */
			pcc_inode_get(pcci);
			pcci->pcci_type = type;
		}
		pcc_inode_dsflags_set(lli, dataset);
		pcc_layout_gen_set(pcci, gen);
		*cached = true;
	}
out_put_pcc_dentry:
	dput(pcc_dentry);
out:
	revert_creds(old_cred);
	RETURN(rc);
}

static int pcc_try_datasets_attach(struct inode *inode, enum pcc_io_type iot,
				   __u32 gen, enum lu_pcc_type type,
				   bool *cached)
{
	struct pcc_super *super = &ll_i2sbi(inode)->ll_pcc_super;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_dataset *dataset = NULL, *tmp;
	int rc = 0;

	ENTRY;

	down_read(&super->pccs_rw_sem);
	list_for_each_entry_safe(dataset, tmp,
				 &super->pccs_datasets, pccd_linkage) {
		if (!pcc_auto_attach_enabled(dataset, type, iot))
			break;

		rc = pcc_try_dataset_attach(inode, gen, type, dataset, cached);
		if (rc < 0 || (!rc && *cached))
			break;
	}

	/*
	 * Update the saved dataset flags for the inode accordingly if failed.
	 */
	if (!rc && !*cached) {
		/*
		 * Currently auto attach strategy for a PCC backend is
		 * unchangeable once once it was added into the PCC datasets on
		 * a client as the support to change auto attach strategy is
		 * not implemented yet.
		 */
		/*
		 * If tried to attach from one PCC backend:
		 * @lli_pcc_generation > 0:
		 * 1) The file was once attached into PCC, but now the
		 * corresponding PCC backend should be removed from the client;
		 * 2) The layout generation was changed, the data has been
		 * restored;
		 * 3) The corresponding PCC copy is not existed on PCC
		 * @lli_pcc_generation == 0:
		 * The file is never attached into PCC but in a HSM released
		 * state, or once attached into PCC but the inode was evicted
		 * from icache later.
		 * Set the saved dataset flags with PCC_DATASET_NONE. Then this
		 * file will skip from the candidates to try auto attach until
		 * the file is attached into PCC again.
		 *
		 * If the file was never attached into PCC, or once attached but
		 * its inode was evicted from icache (lli_pcc_generation == 0),
		 * or the corresponding dataset was removed from the client,
		 * set the saved dataset flags with PCC_DATASET_NONE.
		 *
		 * TODO: If the file was once attached into PCC but not try to
		 * auto attach due to the change of the configuration parameters
		 * for this dataset (i.e. change from auto attach enabled to
		 * auto attach disabled for this dataset), update the saved
		 * dataset flags with the found one.
		 */
		lli->lli_pcc_dsflags = PCC_DATASET_NONE;
	}
	up_read(&super->pccs_rw_sem);

	RETURN(rc);
}

static struct pcc_attach_context *
pcc_attach_context_alloc(struct file *file, struct inode *inode, __u32 id)
{
	struct pcc_attach_context *pccx;

	OBD_ALLOC_PTR(pccx);
	if (!pccx)
		RETURN(NULL);

	pccx->pccx_file = get_file(file);
	pccx->pccx_inode = inode;
	pccx->pccx_attach_id = id;

	return pccx;
}

static inline void pcc_attach_context_free(struct pcc_attach_context *pccx)
{
	LASSERT(pccx->pccx_file != NULL);
	fput(pccx->pccx_file);
	OBD_FREE_PTR(pccx);
}

static int pcc_attach_check_set(struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;

	pcc_inode_lock(inode);
	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING)
		GOTO(out_unlock, rc = -EINPROGRESS);

	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci))
		GOTO(out_unlock, rc = -EEXIST);

	lli->lli_pcc_state |= PCC_STATE_FL_ATTACHING;
out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

static inline void pcc_readonly_attach_fini(struct inode *inode)
{
	pcc_inode_lock(inode);
	ll_i2info(inode)->lli_pcc_state &= ~PCC_STATE_FL_ATTACHING;
	pcc_inode_unlock(inode);
}

static int pcc_readonly_attach(struct file *file, struct inode *inode,
			       __u32 roid);

static int pcc_readonly_attach_thread(void *arg)
{
	struct pcc_attach_context *pccx = (struct pcc_attach_context *)arg;
	struct file *file = pccx->pccx_file;
	int rc;

	ENTRY;

	/*
	 * For asynchronous open attach, it can not reuse the Lustre file
	 * handle directly when the file is opening for read as the file
	 * position in the file handle can not be shared by both user thread
	 * and asynchronous attach thread in kenerl on the background.
	 * It must reopen the file without O_DIRECT flag and use this new
	 * file hanlde to do data copy from Lustre OSTs to the PCC copy.
	 */
	file = dentry_open(&file->f_path, file->f_flags & ~O_DIRECT,
			   pcc_super_cred(pccx->pccx_inode->i_sb));
	if (IS_ERR_OR_NULL(file))
		GOTO(out, rc = file == NULL ? -EINVAL : PTR_ERR(file));

	rc = pcc_readonly_attach(file, pccx->pccx_inode,
				 pccx->pccx_attach_id);
	fput(file);
out:
	pcc_readonly_attach_fini(pccx->pccx_inode);
	CDEBUG(D_CACHE, "PCC-RO attach in background for %pd "DFID" rc = %d\n",
	       file_dentry(pccx->pccx_file),
	       PFID(ll_inode2fid(pccx->pccx_inode)), rc);
	pcc_attach_context_free(pccx);
	RETURN(rc);
}

static int pcc_readonly_attach_async(struct file *file,
				     struct inode *inode, __u32 roid)
{
	struct pcc_attach_context *pccx = NULL;
	struct task_struct *task;
	int rc;

	ENTRY;

	rc = pcc_attach_check_set(inode);
	if (rc)
		RETURN(rc);

	pccx = pcc_attach_context_alloc(file, inode, roid);
	if (!pccx)
		GOTO(out, rc = -ENOMEM);

	if (ll_i2pccs(inode)->pccs_async_affinity) {
		/* Create a attach kthread on the current node. */
		task = kthread_create(pcc_readonly_attach_thread, pccx,
				      "ll_pcc_%u", current->pid);
	} else {
		int node = cfs_cpt_spread_node(cfs_cpt_tab, CFS_CPT_ANY);

		task = kthread_create_on_node(pcc_readonly_attach_thread, pccx,
					      node, "ll_pcc_%u", current->pid);
	}

	if (IS_ERR(task)) {
		rc = PTR_ERR(task);
		CERROR("%s: cannot start ll_pcc thread for "DFID": rc = %d\n",
		       ll_i2sbi(inode)->ll_fsname, PFID(ll_inode2fid(inode)),
		       rc);
		GOTO(out, rc);
	}

	wake_up_process(task);
	RETURN(0);
out:
	if (pccx)
		pcc_attach_context_free(pccx);

	pcc_readonly_attach_fini(inode);
	RETURN(rc);
}

static int pcc_readonly_attach_sync(struct file *file,
				    struct inode *inode, __u32 roid);

static inline int pcc_do_readonly_attach(struct file *file,
					 struct inode *inode, __u32 roid)
{
	int rc;

	if (max_t(__u64, ll_i2info(inode)->lli_lazysize, i_size_read(inode)) >=
	    ll_i2pccs(inode)->pccs_async_threshold) {
		rc = pcc_readonly_attach_async(file, inode, roid);
		if (!rc || rc == -EINPROGRESS)
			return rc;
	}

	rc = pcc_readonly_attach_sync(file, inode, roid);

	return rc;
}

/* Call with pcci_mutex hold */
static int pcc_try_readonly_open_attach(struct inode *inode, struct file *file,
					bool *cached)
{
	struct dentry *dentry = file->f_path.dentry;
	struct pcc_dataset *dataset;
	struct pcc_matcher item;
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;

	if (!((file->f_flags & O_ACCMODE) == O_RDONLY))
		RETURN(0);

	if (ll_i2info(inode)->lli_pcc_state & PCC_STATE_FL_ATTACHING)
		RETURN(-EINPROGRESS);

	item.pm_uid = from_kuid(&init_user_ns, current_uid());
	item.pm_gid = from_kgid(&init_user_ns, current_gid());
	item.pm_projid = ll_i2info(inode)->lli_projid;
	item.pm_name = &dentry->d_name;
	item.pm_size = ll_i2info(inode)->lli_lazysize;
	item.pm_mtime = inode_get_mtime_sec(inode);
	dataset = pcc_dataset_match_get(&ll_i2sbi(inode)->ll_pcc_super,
					LU_PCC_READONLY, &item);
	if (dataset == NULL)
		RETURN(0);

	if ((dataset->pccd_flags & PCC_DATASET_PCC_ALL) == PCC_DATASET_PCCRO) {
		pcc_inode_unlock(inode);
		rc = pcc_do_readonly_attach(file, inode, dataset->pccd_roid);
		pcc_inode_lock(inode);
		pcci = ll_i2pcci(inode);
		if (pcci && pcc_inode_has_layout(pcci))
			*cached = true;

		if (rc) {
			CDEBUG(D_CACHE,
			       "Failed to try PCC-RO attach "DFID", rc = %d\n",
			       PFID(&ll_i2info(inode)->lli_fid), rc);
			/* ignore the error during auto PCC-RO attach. */
			rc = 0;
		} else {
			CDEBUG(D_CACHE,
			       "PCC-RO attach %pd "DFID" with size %llu\n",
			       dentry, PFID(ll_inode2fid(inode)),
			       i_size_read(inode));
		}
	}

	pcc_dataset_put(dataset);
	RETURN(rc);
}

/*
 * TODO: For RW-PCC, it is desirable to store HSM info as a layout (LU-10606).
 * Thus the client can get archive ID from the layout directly. When try to
 * attach the file automatically which is in HSM released state (according to
 * LOV_PATTERN_F_RELEASED in the layout), it can determine whether the file is
 * valid cached on PCC more precisely according to the @rwid (archive ID) in
 * the PCC dataset and the archive ID in HSM attrs.
 */
static int pcc_try_auto_attach(struct inode *inode, bool *cached,
			       enum pcc_io_type iot)
{
	struct pcc_super *super = &ll_i2sbi(inode)->ll_pcc_super;
	struct cl_layout clt = {
		.cl_layout_gen = 0,
		.cl_is_released = false,
	};
	struct ll_inode_info *lli = ll_i2info(inode);
	__u32 gen;
	int rc;

	ENTRY;

	/*
	 * Quick check whether there is PCC device.
	 */
	if (list_empty(&super->pccs_datasets))
		RETURN(0);

	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING)
		RETURN(0);

	/* Forbid to auto attach the file once mmapped into PCC. */
	if (atomic_read(&lli->lli_pcc_mapcnt) > 0)
		RETURN(0);

	/*
	 * The file layout lock was cancelled. And this open does not
	 * obtain valid layout lock from MDT (i.e. the file is being
	 * HSM restoring).
	 */
	if (iot == PIT_OPEN) {
		if (ll_layout_version_get(lli) == CL_LAYOUT_GEN_NONE)
			RETURN(0);
	} else {
		struct pcc_inode *pcci;

		pcc_inode_unlock(inode);
		rc = ll_layout_refresh(inode, &gen);
		pcc_inode_lock(inode);
		if (rc)
			RETURN(rc);

		pcci = ll_i2pcci(inode);
		if (pcci && pcc_inode_has_layout(pcci)) {
			*cached = true;
			RETURN(0);
		}

		if (atomic_read(&lli->lli_pcc_mapcnt) > 0)
			RETURN(0);
	}

	rc = pcc_get_layout_info(inode, &clt);
	if (rc)
		RETURN(rc);

	if (iot != PIT_OPEN && gen != clt.cl_layout_gen) {
		CDEBUG(D_CACHE, DFID" layout changed from %d to %d.\n",
		       PFID(ll_inode2fid(inode)), gen, clt.cl_layout_gen);
		RETURN(-EINVAL);
	}

	if (clt.cl_is_released) {
		rc = pcc_try_datasets_attach(inode, iot, clt.cl_layout_gen,
					     LU_PCC_READWRITE, cached);
	} else if (clt.cl_is_rdonly) {
		/* Not try read-only attach for data modification operations */
		if (iot == PIT_WRITE || iot == PIT_SETATTR)
			RETURN(0);

		rc = pcc_try_datasets_attach(inode, iot, clt.cl_layout_gen,
					     LU_PCC_READONLY, cached);
	}

	if (*cached)
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_PCC_AUTOAT, 1);

	RETURN(rc);
}

static inline bool pcc_may_auto_attach(struct inode *inode,
				       enum pcc_io_type iot)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_super *super = ll_i2pccs(inode);

	ENTRY;

	/* Known the file was not in any PCC backend. */
	if (lli->lli_pcc_dsflags & PCC_DATASET_NONE)
		RETURN(false);

	/*
	 * lli_pcc_generation == 0 means that the file was never attached into
	 * PCC, or may be once attached into PCC but detached as the inode is
	 * evicted from icache (i.e. "echo 3 > /proc/sys/vm/drop_caches" or
	 * icache shrinking due to the memory pressure), which will cause the
	 * file detach from PCC when releasing the inode from icache.
	 * In either case, we still try to attach.
	 */
	/* lli_pcc_generation == 0, or the PCC setting was changed,
	 * or there is no PCC setup on the client and the try will return
	 * immediately in pcc_try_auto_attach().
	 */
	if (super->pccs_generation != lli->lli_pcc_generation)
		RETURN(true);

	/* The cached setting @lli_pcc_dsflags is valid */
	if (iot == PIT_OPEN)
		RETURN(lli->lli_pcc_dsflags & PCC_DATASET_OPEN_ATTACH);

	if (iot == PIT_GETATTR)
		RETURN(lli->lli_pcc_dsflags & PCC_DATASET_STAT_ATTACH);

	RETURN(lli->lli_pcc_dsflags & PCC_DATASET_IO_ATTACH);
}

static inline void pcc_wait_ios_finish(struct pcc_inode *pcci)
{
	if (atomic_read(&pcci->pcci_active_ios) == 0)
		return;

	CDEBUG(D_CACHE, "Waiting for IO completion: %d\n",
		       atomic_read(&pcci->pcci_active_ios));
	wait_event_idle(pcci->pcci_waitq,
			atomic_read(&pcci->pcci_active_ios) == 0);
}

static inline void pcc_inode_mmap_get(struct inode *inode)
{
	pcc_inode_lock(inode);
	atomic_inc(&ll_i2info(inode)->lli_pcc_mapcnt);
	pcc_inode_unlock(inode);
}

static inline void pcc_inode_mapping_reset(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);
	struct inode *pcc_inode = pcci->pcci_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	int rc;

	pcc_wait_ios_finish(pcci);

	/* Did we mmap this file? */
	if (pcc_inode->i_mapping == &pcc_inode->i_data)
		return;

	LASSERT(mapping == pcc_inode->i_mapping && mapping->host == pcc_inode);

	/*
	 * FIXME: As PCC mmap replaces the inode mapping of the PCC copy on the
	 * PCC backend filesystem with the one of the Lustre file, it may
	 * contain some vmas from the users (i.e. root) directly do mmap on the
	 * file under the PCC backend filesystem. At this time, the mapping may
	 * contain vmas from both Lustre users and users directly performed mmap
	 * on PCC backend filesystem.
	 * Thus, It needs a mechanism to forbid users to access the PCC copy
	 * directly from the user space and the PCC copy can only be accessed
	 * from Lustre PCC hook.
	 * One solution is to use flock() to lock the PCC copy when the file
	 * is once attached into PCC and unlock it when the file is detached
	 * from PCC. By this way, the PCC copy is blocking on access from user
	 * space directly when it is valid cached on PCC.
	 */

	if (pcc_inode_has_layout(pcci))
		return;

	/*
	 * The file is detaching, firstly write out all dirty pages and then
	 * unmap and remove all pagecache associated with the PCC backend.
	 */
	rc = filemap_write_and_wait(mapping);
	if (rc)
		CWARN("%s: Failed to write out data for file fid="DFID"\n",
		      ll_i2sbi(inode)->ll_fsname, PFID(ll_inode2fid(inode)));

	truncate_pagecache_range(inode, 0, LUSTRE_EOF);
	mapping->a_ops = &ll_aops;
	/*
	 * Please note the mapping host (@mapping->host) for the Lustre file is
	 * replaced with the PCC copy in case of mmap() on the PCC cached file.
	 * This may result in the setting of @ra_pages of the Lustre file
	 * handle with the one of the PCC copy wrongly in the kernel:
	 * ->do_dentry_open()->file_ra_state_init()
	 * And this is the last step of the open() call and is not under the
	 * control inside the Lustre file system.
	 * Thus to avoid the setting of @ra_pages wrongly we set @ra_pages with
	 * zero explictly in all read I/O path.
	 */
	mapping->host = inode;
	pcc_inode->i_mapping = &pcc_inode->i_data;

	CDEBUG(D_CACHE, "Reset mapping for inode %p fid="DFID" mapping %p\n",
	       inode, PFID(ll_inode2fid(inode)), inode->i_mapping);
}

static inline void pcc_inode_mmap_put(struct inode *inode)
{
	pcc_inode_lock(inode);
	if (atomic_dec_and_test(&ll_i2info(inode)->lli_pcc_mapcnt))
		pcc_inode_mapping_reset(inode);
	pcc_inode_unlock(inode);
}

/* Call with inode lock held. */
static inline void pcc_inode_detach(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	pcci->pcci_type = LU_PCC_NONE;
	pcc_layout_gen_set(pcci, CL_LAYOUT_GEN_NONE);
	pcc_inode_mapping_reset(inode);
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_PCC_DETACH, 1);
}

static inline void pcc_inode_detach_put(struct inode *inode)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	pcc_inode_detach(inode);
	LASSERT(pcci != NULL);
	pcc_inode_put(pcci);
}

void pcc_layout_invalidate(struct inode *inode)
{
	struct pcc_inode *pcci;

	ENTRY;
	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);

		CDEBUG(D_CACHE, "Invalidate "DFID" layout gen %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), pcci->pcci_layout_gen);

		pcc_inode_detach_put(inode);
	}
	pcc_inode_unlock(inode);
	EXIT;
}

/* Tolerate the IO failure on PCC and fall back to normal Lustre IO path */
static bool pcc_io_tolerate(struct pcc_inode *pcci,
			    enum pcc_io_type iot, int rc)
{
	if (pcci->pcci_type == LU_PCC_READWRITE) {
		if (iot == PIT_WRITE && (rc == -ENOSPC || rc == -EDQUOT))
			return false;
		/* Handle the ->page_mkwrite failure tolerance separately
		 * in pcc_page_mkwrite().
		 */
	} else if (pcci->pcci_type == LU_PCC_READONLY) {
		/*
		 * For async I/O engine such as libaio and io_uring, PCC read
		 * should not tolerate -EAGAIN/-EIOCBQUEUED errors, return
		 * the error code to the caller directly.
		 */
		if ((iot == PIT_READ || iot == PIT_GETATTR ||
		     iot == PIT_SPLICE_READ) && rc < 0 && rc != -ENOMEM &&
		    rc != -EAGAIN && rc != -EIOCBQUEUED)
			return false;
		if (iot == PIT_FAULT && (rc & VM_FAULT_SIGBUS) &&
		    !(rc & VM_FAULT_OOM))
			return false;
	}

	return true;
}

static inline void
pcc_file_fallback_set(struct ll_inode_info *lli, struct pcc_file *pccf)
{
	atomic_inc(&lli->lli_pcc_mapneg);
	pccf->pccf_fallback = 1;
}

static inline void
pcc_file_fallback_reset(struct ll_inode_info *lli, struct pcc_file *pccf)
{
	if (pccf->pccf_fallback) {
		pccf->pccf_fallback = 0;
		atomic_dec(&lli->lli_pcc_mapneg);
	}
}

static inline void
pcc_file_mapping_reset(struct inode *inode, struct file *file, bool cached)
{
	struct file *pcc_file = NULL;

	if (file) {
		struct pcc_file *pccf = ll_file2pccf(file);

		pcc_file = pccf->pccf_file;
		if (!cached && !pccf->pccf_fallback)
			pcc_file_fallback_set(ll_i2info(inode), pccf);
	}

	if (pcc_file) {
		struct inode *pcc_inode = file_inode(pcc_file);

		if (pcc_inode->i_mapping == &pcc_inode->i_data)
			pcc_file->f_mapping = pcc_inode->i_mapping;
	}
}

static void pcc_io_init(struct inode *inode, enum pcc_io_type iot,
			struct file *file, bool *cached)
{
	struct pcc_inode *pcci;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
		if (pcci->pcci_type == LU_PCC_READONLY &&
		    (iot == PIT_WRITE || iot == PIT_SETATTR)) {
			/* Detach from PCC. Fall back to normal I/O path */
			*cached = false;
			pcc_inode_detach_put(inode);
		} else {
			atomic_inc(&pcci->pcci_active_ios);
			*cached = true;
		}
	} else {
		*cached = false;
		/*
		 * Forbid to auto PCC attach if the file has still been
		 * mapped in PCC.
		 */
		if (pcc_may_auto_attach(inode, iot)) {
			(void) pcc_try_auto_attach(inode, cached, iot);
			if (*cached) {
				pcci = ll_i2pcci(inode);
				LASSERT(atomic_read(&pcci->pcci_refcount) > 0);
				atomic_inc(&pcci->pcci_active_ios);
			}
		}
	}
	pcc_file_mapping_reset(inode, file, *cached);
	pcc_inode_unlock(inode);
}

static void pcc_io_fini(struct inode *inode, enum pcc_io_type iot,
			int rc, bool *cached)
{
	struct pcc_inode *pcci = ll_i2pcci(inode);

	LASSERT(pcci && atomic_read(&pcci->pcci_active_ios) > 0 && *cached);

	*cached = pcc_io_tolerate(pcci, iot, rc);
	if (atomic_dec_and_test(&pcci->pcci_active_ios))
		wake_up_all(&pcci->pcci_waitq);
}

bool pcc_inode_permission(struct inode *inode)
{
	umode_t mask = inode->i_mode & ll_i2pccs(inode)->pccs_mode;

	return (mask & (S_IRUSR | S_IXUSR) &&
		inode_owner_or_capable(&nop_mnt_idmap, inode)) ||
	       (mask & (S_IRGRP | S_IXGRP) && in_group_p(inode->i_gid)) ||
	       (mask & (S_IROTH | S_IXOTH));
}

int pcc_file_open(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = file->private_data;
	struct pcc_file *pccf = &fd->fd_pcc_file;
	struct file *pcc_file;
	struct path *path;
	bool cached = false;
	int rc = 0;

	ENTRY;

	if (!S_ISREG(inode->i_mode))
		RETURN(0);

	if (IS_ENCRYPTED(inode))
		RETURN(0);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);

	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING) {
		pcc_file_fallback_set(lli, pccf);
		GOTO(out_unlock, rc = 0);
	}

	if (!pcci || !pcc_inode_has_layout(pcci)) {
		if (pcc_may_auto_attach(inode, PIT_OPEN))
			rc = pcc_try_auto_attach(inode, &cached, PIT_OPEN);

		if (rc == 0 && !cached && pcc_inode_permission(inode))
			rc = pcc_try_readonly_open_attach(inode, file, &cached);

		if (rc < 0)
			GOTO(out_unlock, rc);

		if (!cached) {
			pcc_file_fallback_set(lli, pccf);
			GOTO(out_unlock, rc);
		}

		pcci = ll_i2pcci(inode);
	}

	pcc_inode_get(pcci);
	WARN_ON(pccf->pccf_file);

	path = &pcci->pcci_path;
	CDEBUG(D_CACHE, "opening pcc file '%pd' - %pd\n",
	       path->dentry, file->f_path.dentry);

	pcc_file = dentry_open(path, file->f_flags,
			       pcc_super_cred(inode->i_sb));
	if (IS_ERR_OR_NULL(pcc_file)) {
		rc = pcc_file == NULL ? -EINVAL : PTR_ERR(pcc_file);
		pcc_inode_put(pcci);
	} else {
		pccf->pccf_file = pcc_file;
		pccf->pccf_type = pcci->pcci_type;
	}

out_unlock:
	pcc_inode_unlock(inode);
	RETURN(rc);
}

void pcc_file_release(struct inode *inode, struct file *file)
{
	struct pcc_inode *pcci;
	struct ll_file_data *fd = file->private_data;
	struct pcc_file *pccf;
	struct path *path;

	ENTRY;

	if (!S_ISREG(inode->i_mode) || fd == NULL)
		RETURN_EXIT;

	pccf = &fd->fd_pcc_file;
	pcc_inode_lock(inode);
	pcc_file_fallback_reset(ll_i2info(inode), pccf);

	if (pccf->pccf_file == NULL)
		goto out;

	pcci = ll_i2pcci(inode);
	LASSERT(pcci);
	path = &pcci->pcci_path;
	CDEBUG(D_CACHE, "releasing pcc file \"%pd\"\n", path->dentry);
	pcc_inode_put(pcci);

	LASSERT(file_count(pccf->pccf_file) > 0);
	fput(pccf->pccf_file);
	pccf->pccf_file = NULL;

out:
	pcc_inode_unlock(inode);
	RETURN_EXIT;
}

static ssize_t
__pcc_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
	return file->f_op->read_iter(iocb, iter);
#else
	struct iovec iov;
	struct iov_iter i;
	ssize_t bytes = 0;

	iov_for_each(iov, i, *iter) {
		ssize_t res;

		res = file->f_op->aio_read(iocb, &iov, 1, iocb->ki_pos);
		if (-EIOCBQUEUED == res)
			res = wait_on_sync_kiocb(iocb);
		if (res <= 0) {
			if (bytes == 0)
				bytes = res;
			break;
		}

		bytes += res;
		if (res < iov.iov_len)
			break;
	}

	if (bytes > 0)
		iov_iter_advance(iter, bytes);
	return bytes;
#endif
}

ssize_t pcc_file_read_iter(struct kiocb *iocb,
			   struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct pcc_file *pccf = ll_file2pccf(file);
	ssize_t result;

	ENTRY;
	file->f_ra.ra_pages = 0;
	if (pccf->pccf_file == NULL) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, PIT_READ, file, cached);
	if (!*cached)
		RETURN(0);

	/* Fake I/O error on RO-PCC */
	if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_PCC_FAKE_ERROR))
		GOTO(out, result = -EIO);

	iocb->ki_filp = pccf->pccf_file;
	/* generic_file_aio_read does not support ext4-dax,
	 * __pcc_file_read_iter uses ->aio_read hook directly
	 * to add support for ext4-dax.
	 */
	result = __pcc_file_read_iter(iocb, iter);
	iocb->ki_filp = file;
out:
	pcc_io_fini(inode, PIT_READ, result, cached);
	RETURN(result);
}

static ssize_t
__pcc_file_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;

#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
	return file->f_op->write_iter(iocb, iter);
#else
	struct iovec iov;
	struct iov_iter i;
	ssize_t bytes = 0;

	iov_for_each(iov, i, *iter) {
		ssize_t res;

		res = file->f_op->aio_write(iocb, &iov, 1, iocb->ki_pos);
		if (-EIOCBQUEUED == res)
			res = wait_on_sync_kiocb(iocb);
		if (res <= 0) {
			if (bytes == 0)
				bytes = res;
			break;
		}

		bytes += res;
		if (res < iov.iov_len)
			break;
	}

	if (bytes > 0)
		iov_iter_advance(iter, bytes);
	return bytes;
#endif
}

ssize_t pcc_file_write_iter(struct kiocb *iocb,
			    struct iov_iter *iter, bool *cached)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct pcc_file *pccf = ll_file2pccf(file);
	ssize_t result;

	ENTRY;
	if (pccf->pccf_file == NULL) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, PIT_WRITE, file, cached);
	if (!*cached)
		RETURN(0);

	if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_PCC_FAKE_ERROR))
		GOTO(out, result = -ENOSPC);

	iocb->ki_filp = pccf->pccf_file;

	/* Since __pcc_file_write_iter makes write calls via
	 * the normal vfs interface to the local PCC file system,
	 * the inode lock is not needed.
	 */
	result = __pcc_file_write_iter(iocb, iter);
	iocb->ki_filp = file;
out:
	pcc_io_fini(inode, PIT_WRITE, result, cached);
	RETURN(result);
}

int pcc_inode_setattr(struct inode *inode, struct iattr *attr,
		      bool *cached)
{
	int rc;
	const struct cred *old_cred;
	struct iattr attr2 = *attr;
	struct dentry *pcc_dentry;
	struct pcc_inode *pcci;

	ENTRY;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, PIT_SETATTR, NULL, cached);
	if (!*cached)
		RETURN(0);

	attr2.ia_valid = attr->ia_valid & (ATTR_SIZE | ATTR_ATIME |
			 ATTR_ATIME_SET | ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_CTIME | ATTR_UID | ATTR_GID);
	pcci = ll_i2pcci(inode);
	pcc_dentry = pcci->pcci_path.dentry;
	inode_lock(pcc_dentry->d_inode);
	old_cred = override_creds(pcc_super_cred(inode->i_sb));
#ifdef HAVE_USER_NAMESPACE_ARG
	rc = pcc_dentry->d_inode->i_op->setattr(&nop_mnt_idmap, pcc_dentry,
						&attr2);
#else
	rc = pcc_dentry->d_inode->i_op->setattr(pcc_dentry, &attr2);
#endif
	revert_creds(old_cred);
	inode_unlock(pcc_dentry->d_inode);

	pcc_io_fini(inode, PIT_SETATTR, rc, cached);
	RETURN(rc);
}

int pcc_inode_getattr(struct inode *inode, u32 request_mask,
		      unsigned int flags, bool *cached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
	struct kstat stat;
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc;

	ENTRY;

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, PIT_GETATTR, NULL, cached);
	if (!*cached)
		RETURN(0);

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = ll_vfs_getattr(&ll_i2pcci(inode)->pcci_path, &stat, request_mask,
			    flags);
	revert_creds(old_cred);
	if (rc)
		GOTO(out, rc);

	ll_inode_size_lock(inode);
	if (test_and_clear_bit(LLIF_UPDATE_ATIME, &lli->lli_flags) ||
	    inode_get_atime_sec(inode) < lli->lli_atime)
		inode_set_atime(inode, lli->lli_atime, 0);

	inode_set_mtime(inode, lli->lli_mtime, 0);
	inode_set_ctime(inode, lli->lli_ctime, 0);

	atime = inode_get_atime_sec(inode);
	mtime = inode_get_mtime_sec(inode);
	ctime = inode_get_ctime_sec(inode);

	if (atime < stat.atime.tv_sec)
		atime = stat.atime.tv_sec;

	if (ctime < stat.ctime.tv_sec)
		ctime = stat.ctime.tv_sec;

	if (mtime < stat.mtime.tv_sec)
		mtime = stat.mtime.tv_sec;

	i_size_write(inode, stat.size);
	inode->i_blocks = stat.blocks;

	inode_set_atime(inode, atime, 0);
	inode_set_mtime(inode, mtime, 0);
	inode_set_ctime(inode, ctime, 0);

	ll_inode_size_unlock(inode);
out:
	pcc_io_fini(inode, PIT_GETATTR, rc, cached);
	RETURN(rc);
}

#if defined(HAVE_FILEMAP_SPLICE_READ)
# define do_sys_splice_read	copy_splice_read
#elif defined(HAVE_DEFAULT_FILE_SPLICE_READ_EXPORT)
# define do_sys_splice_read	default_file_splice_read
#else
# define do_sys_splice_read	generic_file_splice_read
#endif

ssize_t pcc_file_splice_read(struct file *in_file, loff_t *ppos,
			     struct pipe_inode_info *pipe,
			     size_t count, unsigned int flags)
{
	struct inode *inode = file_inode(in_file);
	struct file *pcc_file = ll_file2pccf(in_file)->pccf_file;
	bool cached = false;
	ssize_t result;

	ENTRY;
	in_file->f_ra.ra_pages = 0;
	if (!pcc_file)
		RETURN(do_sys_splice_read(in_file, ppos, pipe,
					  count, flags));

	pcc_io_init(inode, PIT_SPLICE_READ, in_file, &cached);
	if (!cached)
		RETURN(do_sys_splice_read(in_file, ppos, pipe,
					  count, flags));

	result = do_sys_splice_read(pcc_file, ppos, pipe, count, flags);

	pcc_io_fini(inode, PIT_SPLICE_READ, result, &cached);
	RETURN(result);
}

int pcc_fsync(struct file *file, loff_t start, loff_t end,
	      int datasync, bool *cached)
{
	struct inode *inode = file_inode(file);
	struct pcc_file *pccf = ll_file2pccf(file);
	struct file *pcc_file = pccf->pccf_file;
	int rc;

	ENTRY;
	if (!pcc_file) {
		*cached = false;
		RETURN(0);
	}

	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	/*
	 * After the file is attached into RO-PCC, its dirty pages on this
	 * client may not be flushed. So fsync() should fall back to normal
	 * Lustre I/O path flushing dirty data to OSTs. And flush on RO-PCC
	 * copy is meaningless.
	 */
	if (pccf->pccf_type == LU_PCC_READONLY) {
		*cached = false;
		RETURN(0);
	}

	pcc_io_init(inode, PIT_FSYNC, file, cached);
	if (!*cached)
		RETURN(0);

	rc = file_inode(pcc_file)->i_fop->fsync(pcc_file,
						start, end, datasync);

	pcc_io_fini(inode, PIT_FSYNC, rc, cached);
	RETURN(rc);
}

static inline void pcc_vma_file_reset(struct inode *inode,
				      struct vm_area_struct *vma)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;

	LASSERT(pccv);
	if (vma->vm_file != pccv->pccv_file) {
		struct pcc_file *pccf = ll_file2pccf(pccv->pccv_file);
		struct file *pcc_file = pccf->pccf_file;
		struct inode *pcc_inode = file_inode(pcc_file);

		LASSERT(vma->vm_file == pcc_file);
		LASSERT(vma->vm_file->f_mapping == inode->i_mapping);
		vma->vm_file = pccv->pccv_file;

		get_file(vma->vm_file);
		if (pcc_file->f_mapping != pcc_inode->i_mapping)
			pcc_file->f_mapping = pcc_inode->i_mapping;
		fput(pcc_file);

		CDEBUG(D_CACHE,
		       DFID" mapcnt %d vm_file %p:%ld lu_file %p:%ld vma %p\n",
		       PFID(ll_inode2fid(inode)),
		       atomic_read(&ll_i2info(inode)->lli_pcc_mapcnt),
		       vma->vm_file, file_count(vma->vm_file), pccv->pccv_file,
		       file_count(pccv->pccv_file), vma);
	}
}

static void pcc_mmap_vma_reset(struct inode *inode, struct vm_area_struct *vma)
{
	pcc_inode_lock(inode);
	pcc_vma_file_reset(inode, vma);
	pcc_inode_unlock(inode);
}

static int pcc_mmap_mapping_set(struct inode *inode, struct inode *pcc_inode);

static void pcc_mmap_io_init(struct inode *inode, enum pcc_io_type iot,
			     struct vm_area_struct *vma, bool *cached)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	struct pcc_file *pccf;

	LASSERT(pccv);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	pccf = ll_file2pccf(pccv->pccv_file);
	if (pcci && pcc_inode_has_layout(pcci)) {
		struct inode *pcc_inode = pcci->pcci_path.dentry->d_inode;

		LASSERT(atomic_read(&pcci->pcci_refcount) > 0);

		if (pcci->pcci_type == LU_PCC_READONLY &&
		    iot == PIT_PAGE_MKWRITE) {
			pcc_inode_detach_put(inode);
			pcc_vma_file_reset(inode, vma);
			*cached = false;
		} else if (pcc_inode->i_mapping == &pcc_inode->i_data) {
			if (atomic_read(&lli->lli_pcc_mapneg) > 0) {
				pcc_inode_detach_put(inode);
				pcc_vma_file_reset(inode, vma);
				*cached = false;
			} else {
				int rc;

				rc = pcc_mmap_mapping_set(inode, pcc_inode);
				if (rc) {
					pcc_inode_detach_put(inode);
					pcc_vma_file_reset(inode, vma);
					*cached = false;
				} else {
					atomic_inc(&pcci->pcci_active_ios);
					*cached = true;
				}
			}
		} else {
			atomic_inc(&pcci->pcci_active_ios);
			*cached = true;
		}
	} else {
		*cached = false;
		pcc_vma_file_reset(inode, vma);
	}

	if (!*cached && !pccf->pccf_fallback)
		pcc_file_fallback_set(lli, pccf);

	pcc_inode_unlock(inode);
}

static int pcc_mmap_pages_convert(struct inode *inode,
				  struct inode *pcc_inode)
{
#ifdef HAVE_ADD_TO_PAGE_CACHE_LOCKED
	struct folio_batch fbatch;
	pgoff_t index = 0;
	unsigned int nr;
	int rc = 0;

	ll_folio_batch_init(&fbatch, 0);
	for ( ; ; ) {
		struct page *page;
		int i;

		nr = ll_filemap_get_folios(pcc_inode->i_mapping,
					   index, ~0UL, &fbatch);
		if (nr == 0)
			break;

		for (i = 0; i < nr; i++) {
#if defined(HAVE_FOLIO_BATCH) && defined(HAVE_FILEMAP_GET_FOLIOS)
			page = &fbatch.folios[i]->page;
#else
			page = fbatch.pages[i];
#endif
			lock_page(page);
			wait_on_page_writeback(page);

			/*
			 * FIXME: Special handling for shadow or DAX entries.
			 * i.e. the PCC backend FS is using DAX access
			 * (ext4-dax) for performance reason on the NVMe
			 * hardware.
			 */
			/* Remove the page from the mapping of the PCC copy. */
			cfs_delete_from_page_cache(page);
			/* Add the page into the mapping of the Lustre file. */
			rc = add_to_page_cache_locked(page, inode->i_mapping,
						      page->index, GFP_KERNEL);
			if (rc) {
				unlock_page(page);
				folio_batch_release(&fbatch);
				return rc;
			}

			unlock_page(page);
		}

		index = page->index + 1;
		folio_batch_release(&fbatch);
		cond_resched();
	}

	return rc;
#else
	return 0;
#endif /* HAVE_ADD_TO_PAGE_CACHE_LOCKED */
}

static int pcc_mmap_mapping_set(struct inode *inode, struct inode *pcc_inode)
{
	struct address_space *mapping = inode->i_mapping;
	struct pcc_inode *pcci = ll_i2pcci(inode);
	int rc;

	ENTRY;

	if (pcc_inode->i_mapping == mapping) {
		LASSERT(mapping->host == pcc_inode);
		LASSERT(mapping->a_ops == pcc_inode->i_mapping->a_ops);
		RETURN(0);
	}

	if (pcc_inode->i_mapping != &pcc_inode->i_data)
		RETURN(-EBUSY);
	/*
	 * Write out all dirty pages and drop all pagecaches before switch the
	 * mapping from the PCC copy to the Lustre file for PCC mmap().
	 */

	rc = filemap_write_and_wait(mapping);
	if (rc)
		return rc;

	truncate_inode_pages(mapping, 0);

	/* Wait all active I/Os on the PCC copy finished. */
	wait_event_idle(pcci->pcci_waitq,
			atomic_read(&pcci->pcci_active_ios) == 0);

	rc = filemap_write_and_wait(pcc_inode->i_mapping);
	if (rc)
		return rc;

	if (ll_i2info(inode)->lli_pcc_dsflags & PCC_DATASET_MMAP_CONV) {
		/*
		 * Move and convert all pagecache on the mapping of the PCC copy
		 * to the Lustre file.
		 */
		rc = pcc_mmap_pages_convert(inode, pcc_inode);
		if (rc)
			return rc;
	} else {
		/* Drop all pagecache on the PCC copy directly. */
		truncate_inode_pages(pcc_inode->i_mapping, 0);
	}

	mapping->a_ops = pcc_inode->i_mapping->a_ops;
	mapping->host = pcc_inode;
	pcc_inode->i_mapping = mapping;

	RETURN(rc);
}

int pcc_file_mmap(struct file *file, struct vm_area_struct *vma,
		  bool *cached)
{
	struct pcc_file *pccf = ll_file2pccf(file);
	struct file *pcc_file = pccf->pccf_file;
	struct inode *inode = file_inode(file);
	struct pcc_inode *pcci;
	int rc = 0;

	ENTRY;
	/* With PCC, the files are cached in an unusual way, then we do some
	 * special magic with mmap to allow Lustre and PCC to share the page
	 * mapping, and the @ra_pages may set with the backing device of PCC
	 * wrongly in this case. So we must manually set the @ra_pages with
	 * zero, otherwise it may result in kernel readahead occurring (which
	 * Lustre does not support).
	 */
	file->f_ra.ra_pages = 0;

	*cached = false;
	if (!pcc_file || !file_inode(pcc_file)->i_fop->mmap)
		RETURN(0);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci && pcc_inode_has_layout(pcci)) {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct inode *pcc_inode = file_inode(pcc_file);
		struct pcc_vma *pccv;

		if (pccf->pccf_fallback) {
			LASSERT(atomic_read(&lli->lli_pcc_mapneg) > 0);
			GOTO(out, rc);
		}

		if (atomic_read(&lli->lli_pcc_mapneg) > 0) {
			pcc_file_fallback_set(lli, pccf);
			GOTO(out, rc);
		}

		LASSERT(atomic_read(&pcci->pcci_refcount) > 1);
		*cached = true;

		rc = pcc_mmap_mapping_set(inode, pcc_inode);
		if (rc)
			GOTO(out, rc);

		OBD_ALLOC_PTR(pccv);
		if (pccv == NULL)
			GOTO(out, rc = -ENOMEM);

		pcc_file->f_mapping = file->f_mapping;
		vma->vm_file = get_file(pcc_file);
		rc = file_inode(pcc_file)->i_fop->mmap(pcc_file, vma);
		if (rc || vma->vm_private_data) {
			/*
			 * Check whether vma->vm_private_data is NULL.
			 * We have used vm_private_data in our PCC mmap design,
			 * it will cause conflict if the underlying PCC backend
			 * filesystem is also using this private data structure.
			 */
			if (vma->vm_private_data)
				rc = -EOPNOTSUPP;
			/*
			 * If call ->mmap() fails, our caller will put Lustre
			 * file so we should drop the reference to the PCC file
			 * copy that we got.
			 */
			fput(pcc_file);
			OBD_FREE_PTR(pccv);
			GOTO(out, rc);
		}

		/* Save the vm ops of backend PCC */
		pccv->pccv_vm_ops = vma->vm_ops;
		pccv->pccv_file = file;
		atomic_set(&pccv->pccv_refcnt, 0);
		vma->vm_private_data = pccv;

		CDEBUG(D_CACHE,
		       DFID" vma %p size %llu len %lu pgoff %lu flags %lx\n",
		       PFID(ll_inode2fid(inode)), vma, i_size_read(inode),
		       vma->vm_end - vma->vm_start, vma->vm_pgoff,
		       vma->vm_flags);
	}
out:
	pcc_inode_unlock(inode);

	RETURN(rc);
}

void pcc_vm_open(struct vm_area_struct *vma)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;
	struct vvp_object *vob;
	struct pcc_file *pccf;
	struct inode *inode;

	ENTRY;
	if (!pccv)
		RETURN_EXIT;

	inode = file_inode(pccv->pccv_file);
	vob = cl_inode2vvp(inode);
	LASSERT(atomic_read(&vob->vob_mmap_cnt) >= 0);
	atomic_inc(&vob->vob_mmap_cnt);

	pccf = ll_file2pccf(pccv->pccv_file);
	atomic_inc(&pccv->pccv_refcnt);
	if (pccv->pccv_vm_ops->open)
		pccv->pccv_vm_ops->open(vma);

	pcc_inode_mmap_get(inode);

	EXIT;
}

void pcc_vm_close(struct vm_area_struct *vma)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;
	struct vvp_object *vob;
	struct pcc_file *pccf;
	struct inode *inode;

	ENTRY;
	if (!pccv)
		RETURN_EXIT;

	inode = file_inode(pccv->pccv_file);
	LASSERT(ll_i2info(inode) != NULL);
	vob = cl_inode2vvp(inode);
	atomic_dec(&vob->vob_mmap_cnt);
	LASSERT(atomic_read(&vob->vob_mmap_cnt) >= 0);

	if (pccv->pccv_vm_ops && pccv->pccv_vm_ops->close)
		pccv->pccv_vm_ops->close(vma);

	pccf = ll_file2pccf(pccv->pccv_file);
	pcc_inode_mmap_put(inode);
	if (atomic_dec_and_test(&pccv->pccv_refcnt)) {
		fput(pccv->pccv_file);
		CDEBUG(D_CACHE,
		      "release pccv "DFID" vm_file %p:%ld lu_file %p:%ld\n",
		       PFID(ll_inode2fid(inode)),
		       vma->vm_file, file_count(vma->vm_file),
		       pccv->pccv_file, file_count(pccv->pccv_file));
		OBD_FREE_PTR(pccv);
	}

	EXIT;
}

int pcc_page_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf,
		     bool *cached)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;
	struct mm_struct *mm = vma->vm_mm;
	struct inode *inode;
	int rc;

	ENTRY;
	if (!pccv || !pccv->pccv_vm_ops) {
		*cached = false;
		RETURN(0);
	}

	inode = file_inode(pccv->pccv_file);
	if (!pccv->pccv_vm_ops->page_mkwrite) {
		__u32 flags = PCC_DETACH_FL_UNCACHE;

		CDEBUG(D_MMAP,
		       "%s: PCC backend fs not support ->page_mkwrite()\n",
		       ll_i2sbi(inode)->ll_fsname);
		(void) pcc_ioctl_detach(inode, &flags);
		pcc_mmap_vma_reset(inode, vma);
		mmap_read_unlock(mm);
		*cached = true;
		RETURN(VM_FAULT_RETRY | VM_FAULT_NOPAGE);
	}
	/* Pause to allow for a race with concurrent detach */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_MKWRITE_PAUSE, cfs_fail_val);

	pcc_mmap_io_init(inode, PIT_PAGE_MKWRITE, vma, cached);
	if (!*cached) {
		/* This happens when the file is detached from PCC after got
		 * the fault page via ->fault() on the inode of the PCC copy.
		 * Here it can not simply fall back to normal Lustre I/O path.
		 * The reason is that the address space of fault page used by
		 * ->page_mkwrite() is still the one of PCC inode. In the
		 * normal Lustre ->page_mkwrite() I/O path, it will be wrongly
		 * handled as the address space of the fault page is not
		 * consistent with the one of the Lustre inode (though the
		 * fault page was truncated).
		 * As the file is detached from PCC, the fault page must
		 * be released frist, and retry the mmap write (->fault() and
		 * ->page_mkwrite).
		 * We use an ugly and tricky method by returning
		 * VM_FAULT_NOPAGE | VM_FAULT_RETRY to the caller
		 * __do_page_fault and retry the memory fault handling.
		 */

		LASSERT(vma->vm_file == pccv->pccv_file);
		if (vmf->page->mapping == &inode->i_data)
			RETURN(0);

		*cached = true;
		mmap_read_unlock(mm);
		RETURN(VM_FAULT_RETRY | VM_FAULT_NOPAGE);
	}

	/*
	 * This fault injection can also be used to simulate -ENOSPC and
	 * -EDQUOT failure of underlying PCC backend fs.
	 */
	if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_PCC_DETACH_MKWRITE))
		GOTO(out, rc = VM_FAULT_SIGBUS);

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
	rc = pccv->pccv_vm_ops->page_mkwrite(vmf);
#else
	rc = pccv->pccv_vm_ops->page_mkwrite(vma, vmf);
#endif

out:
	pcc_io_fini(inode, PIT_PAGE_MKWRITE, rc, cached);

	/* VM_FAULT_SIGBUG usually means that underlying PCC backend fs returns
	 * -EIO, -ENOSPC or -EDQUOT. Thus we can retry this IO from the normal
	 * Lustre I/O path.
	 */
	if (rc & VM_FAULT_SIGBUS) {
		__u32 flags = PCC_DETACH_FL_UNCACHE;

		(void) pcc_ioctl_detach(inode, &flags);
		pcc_mmap_vma_reset(inode, vma);
		mmap_read_unlock(mm);
		RETURN(VM_FAULT_RETRY | VM_FAULT_NOPAGE);
	}
	RETURN(rc);
}

int pcc_fault(struct vm_area_struct *vma, struct vm_fault *vmf,
	      bool *cached)
{
	struct pcc_vma *pccv = (struct pcc_vma *)vma->vm_private_data;
	struct inode *inode;
	int rc;

	ENTRY;
	if (!pccv) {
		*cached = false;
		RETURN(0);
	}

	inode = file_inode(pccv->pccv_file);
	if (!S_ISREG(inode->i_mode)) {
		*cached = false;
		RETURN(0);
	}

	pcc_mmap_io_init(inode, PIT_FAULT, vma, cached);
	if (!*cached)
		RETURN(0);

	/* Tolerate the mmap read failure for RO-PCC */
	if (CFS_FAIL_CHECK(OBD_FAIL_LLITE_PCC_FAKE_ERROR))
		GOTO(out, rc = VM_FAULT_SIGBUS);

#ifdef HAVE_VM_OPS_USE_VM_FAULT_ONLY
	rc = pccv->pccv_vm_ops->fault(vmf);
#else
	rc = pccv->pccv_vm_ops->fault(vma, vmf);
#endif

out:
	pcc_io_fini(inode, PIT_FAULT, rc, cached);

	if ((rc & VM_FAULT_SIGBUS) && !(rc & VM_FAULT_OOM)) {
		__u32 flags = PCC_DETACH_FL_UNCACHE;

		CDEBUG(D_CACHE, "PCC fault failed: fid = "DFID" rc = %d\n",
		       PFID(ll_inode2fid(inode)), rc);
		(void) pcc_ioctl_detach(inode, &flags);
		pcc_mmap_vma_reset(inode, vma);
	}

	RETURN(rc);
}

static int pcc_inode_remove(struct inode *inode, struct dentry *pcc_dentry)
{
	struct dentry *parent = dget_parent(pcc_dentry);
	int rc;

	rc = vfs_unlink(&nop_mnt_idmap, d_inode(parent), pcc_dentry);
	if (rc)
		CWARN("%s: failed to unlink PCC file %pd, rc = %d\n",
		      ll_i2sbi(inode)->ll_fsname, pcc_dentry, rc);

	dput(parent);
	return rc;
}

/* Create directory under base if directory does not exist */
static struct dentry *
pcc_mkdir(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_mkdir(&nop_mnt_idmap, dir, dentry, mode);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

static struct dentry *
pcc_mkdir_p(struct dentry *root, char *path, umode_t mode)
{
	char *ptr, *entry_name;
	struct dentry *parent;
	struct dentry *child = ERR_PTR(-EINVAL);

	ptr = path;
	while (*ptr == '/')
		ptr++;

	entry_name = ptr;
	parent = dget(root);
	while ((ptr = strchr(ptr, '/')) != NULL) {
		*ptr = '\0';
		child = pcc_mkdir(parent, entry_name, mode);
		*ptr = '/';
		dput(parent);
		if (IS_ERR(child))
			break;

		parent = child;
		ptr++;
		entry_name = ptr;
	}

	return child;
}

/* Create file under base. If file already exist, return failure */
static struct dentry *
pcc_create(struct dentry *base, const char *name, umode_t mode)
{
	int rc;
	struct dentry *dentry;
	struct inode *dir = base->d_inode;

	inode_lock(dir);
	dentry = lookup_one_len(name, base, strlen(name));
	if (IS_ERR(dentry))
		goto out;

	if (d_is_positive(dentry))
		goto out;

	rc = vfs_create(&nop_mnt_idmap, dir, dentry, mode, false);
	if (rc) {
		dput(dentry);
		dentry = ERR_PTR(rc);
		goto out;
	}
out:
	inode_unlock(dir);
	return dentry;
}

static int __pcc_inode_create(struct pcc_dataset *dataset,
			      struct lu_fid *fid,
			      struct dentry **dentry)
{
	char *path;
	struct dentry *base;
	struct dentry *child;
	int rc = 0;

	OBD_ALLOC(path, PCC_DATASET_MAX_PATH);
	if (path == NULL)
		return -ENOMEM;

	pcc_fid2dataset_path(dataset, path, PCC_DATASET_MAX_PATH, fid);

	base = pcc_mkdir_p(dataset->pccd_path.dentry, path, 0);
	if (IS_ERR(base)) {
		rc = PTR_ERR(base);
		GOTO(out, rc);
	}

	snprintf(path, PCC_DATASET_MAX_PATH, DFID_NOBRACE, PFID(fid));
	child = pcc_create(base, path, 0);
	if (IS_ERR(child)) {
		rc = PTR_ERR(child);
		GOTO(out_base, rc);
	}
	*dentry = child;

out_base:
	dput(base);
out:
	OBD_FREE(path, PCC_DATASET_MAX_PATH);
	return rc;
}

/*
 * Reset uid, gid or size for the PCC copy masked by @valid.
 */
static int pcc_inode_reset_iattr(struct inode *lustre_inode,
				 struct dentry *dentry, unsigned int valid,
				 kuid_t uid, kgid_t gid, loff_t size)
{
	struct inode *inode = dentry->d_inode;
	struct iattr attr;
	int rc;

	ENTRY;

	attr.ia_valid = valid;
	attr.ia_uid = uid;
	attr.ia_gid = gid;
	attr.ia_size = size;
	attr.ia_mtime = inode_get_mtime(lustre_inode);

	inode_lock(inode);
	rc = notify_change(&nop_mnt_idmap, dentry, &attr, NULL);
	inode_unlock(inode);

	RETURN(rc);
}

static int __pcc_file_reset_projid(struct file *file, __u32 projid)
{
#ifdef HAVE_FILEATTR_GET
	struct fileattr fa = { .fsx_projid = projid };
	struct dentry *dentry = file->f_path.dentry;
	struct inode *inode = d_inode(dentry);
	int rc;

	/* project quota not supported on backing filesystem */
	if (!inode->i_op->fileattr_set)
		return -EOPNOTSUPP;

	rc = inode->i_op->fileattr_set(&nop_mnt_idmap, dentry, &fa);
#else
	struct fsxattr fsx = { .fsx_projid = projid };
	mm_segment_t old_fs;
	int rc;

	/* project quota not supported on backing filesystem */
	if (!file->f_op->unlocked_ioctl)
		return -EOPNOTSUPP;

	old_fs = get_fs();
	set_fs(KERNEL_DS);
	rc = file->f_op->unlocked_ioctl(file, FS_IOC_FSSETXATTR,
					(unsigned long)&fsx);
	set_fs(old_fs);
#endif
	return rc;
}

/* Set the project ID for PCC copy.*/
static int pcc_file_reset_projid(struct pcc_dataset *dataset, struct file *file,
				 __u32 projid)
{
	int rc;

	ENTRY;

	if (!(dataset->pccd_flags & PCC_DATASET_PROJ_QUOTA))
		RETURN(0);

	rc = __pcc_file_reset_projid(file, projid);
	if (rc == -EOPNOTSUPP || rc == -ENOTTY) {
		CWARN("%s: cache fs project quota off, disabling: rc = %d\n",
		      dataset->pccd_pathname, rc);
		dataset->pccd_flags &= ~PCC_DATASET_PROJ_QUOTA;
		RETURN(0);
	}

	RETURN(rc);
}

static int pcc_inode_reset_projid(struct pcc_dataset *dataset,
				  struct dentry *dentry, __u32 projid)
{
	struct path path;
	struct file *file;
	int rc;

	ENTRY;

	if (!(dataset->pccd_flags & PCC_DATASET_PROJ_QUOTA))
		RETURN(0);

	path.mnt = dataset->pccd_path.mnt;
	path.dentry = dentry;
	file = dentry_open(&path, O_WRONLY | O_LARGEFILE, current_cred());
	if (IS_ERR_OR_NULL(file)) {
		rc = file == NULL ? -EINVAL : PTR_ERR(file);
		RETURN(rc);
	}

	rc = pcc_file_reset_projid(dataset, file, projid);
	fput(file);
	RETURN(rc);
}

int pcc_inode_create(struct super_block *sb, struct pcc_dataset *dataset,
		     struct lu_fid *fid, struct dentry **pcc_dentry)
{
	const struct cred *old_cred;
	int rc;

	old_cred = override_creds(pcc_super_cred(sb));
	rc = __pcc_inode_create(dataset, fid, pcc_dentry);
	revert_creds(old_cred);
	return rc;
}

int pcc_inode_create_fini(struct inode *inode, struct pcc_create_attach *pca)
{
	struct dentry *pcc_dentry = pca->pca_dentry;
	const struct cred *old_cred;
	struct pcc_super *super;
	struct pcc_inode *pcci;
	int rc;

	ENTRY;

	if (!pca->pca_dataset)
		RETURN(0);

	if (!inode)
		GOTO(out_dataset_put, rc = 0);

	super = ll_i2pccs(inode);

	LASSERT(pcc_dentry);

	old_cred = override_creds(super->pccs_cred);
	pcc_inode_lock(inode);
	LASSERT(ll_i2pcci(inode) == NULL);
	OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
	if (pcci == NULL)
		GOTO(out_put, rc = -ENOMEM);

	rc = pcc_inode_reset_iattr(inode, pcc_dentry, ATTR_UID | ATTR_GID,
				   old_cred->suid, old_cred->sgid, 0);
	if (rc)
		GOTO(out_put, rc);

	rc = pcc_inode_reset_projid(pca->pca_dataset, pcc_dentry,
				    ll_i2info(inode)->lli_projid);
	if (rc)
		GOTO(out_put, rc);

	pcc_inode_attach_set(super, pca->pca_dataset, ll_i2info(inode),
			     pcci, pcc_dentry, LU_PCC_READWRITE);

	rc = pcc_layout_xattr_set(pcci, 0);
	if (rc) {
		if (!pcci->pcci_unlinked)
			(void) pcc_inode_remove(inode, pcci->pcci_path.dentry);
		pcc_inode_put(pcci);
		GOTO(out_unlock, rc);
	}

	/* Set the layout generation of newly created file with 0 */
	pcc_layout_gen_set(pcci, 0);

out_put:
	if (rc) {
		(void) pcc_inode_remove(inode, pcc_dentry);
		dput(pcc_dentry);

		if (pcci)
			OBD_SLAB_FREE_PTR(pcci, pcc_inode_slab);
	}
out_unlock:
	pcc_inode_unlock(inode);
	revert_creds(old_cred);
out_dataset_put:
	pcc_dataset_put(pca->pca_dataset);
	RETURN(rc);
}

void pcc_create_attach_cleanup(struct super_block *sb,
			       struct pcc_create_attach *pca)
{
	if (!pca->pca_dataset)
		return;

	if (pca->pca_dentry) {
		struct dentry *parent;
		struct inode *i_dir;
		const struct cred *old_cred;
		int rc;

		old_cred = override_creds(pcc_super_cred(sb));
		parent = dget_parent(pca->pca_dentry);
		i_dir = d_inode(parent);
		rc = vfs_unlink(&nop_mnt_idmap, i_dir, pca->pca_dentry);
		dput(parent);
		if (rc)
			CWARN("%s: failed to unlink PCC file %pd: rc = %d\n",
			      ll_s2sbi(sb)->ll_fsname, pca->pca_dentry, rc);
		/* ignore the unlink failure */
		revert_creds(old_cred);
		dput(pca->pca_dentry);
	}

	pcc_dataset_put(pca->pca_dataset);
}

static int pcc_filp_write(struct file *filp, const void *buf, ssize_t count,
			  loff_t *offset)
{
	while (count > 0) {
		ssize_t size;

		size = cfs_kernel_write(filp, buf, count, offset);
		if (size < 0)
			return size;
		count -= size;
		buf += size;
	}
	return 0;
}

static ssize_t pcc_copy_data(struct file *src, struct file *dst)
{
	ssize_t rc = 0;
	ssize_t rc2;
	loff_t pos, offset = 0;
	size_t buf_len = 1048576;
	void *buf;

	ENTRY;

#ifdef FMODE_CAN_READ
	/* Need to add FMODE_CAN_READ flags here, otherwise the check in
	 * kernel_read() during open() for auto PCC-RO attach will fail.
	 */
	if ((src->f_mode & FMODE_READ) &&
	    likely(src->f_op->read || src->f_op->read_iter))
		src->f_mode |= FMODE_CAN_READ;
#endif

	OBD_ALLOC_LARGE(buf, buf_len);
	if (buf == NULL)
		RETURN(-ENOMEM);

	while (1) {
		if (signal_pending(current))
			GOTO(out_free, rc = -EINTR);

		pos = offset;
		rc2 = cfs_kernel_read(src, buf, buf_len, &pos);
		if (rc2 < 0)
			GOTO(out_free, rc = rc2);
		else if (rc2 == 0)
			break;

		pos = offset;
		rc = pcc_filp_write(dst, buf, rc2, &pos);
		if (rc < 0)
			GOTO(out_free, rc);
		offset += rc2;
	}

	rc = offset;
out_free:
	OBD_FREE_LARGE(buf, buf_len);
	RETURN(rc);
}

static int pcc_attach_data_archive(struct file *file, struct inode *inode,
				   struct pcc_dataset *dataset,
				   struct dentry **dentry)
{
	const struct cred *old_cred;
	struct file *pcc_filp;
	bool direct = false;
	struct path path;
	ssize_t ret;
	int rc;

	ENTRY;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	rc = __pcc_inode_create(dataset, &ll_i2info(inode)->lli_fid, dentry);
	if (rc)
		GOTO(out_cred, rc);

	path.mnt = dataset->pccd_path.mnt;
	path.dentry = *dentry;
	pcc_filp = dentry_open(&path, O_WRONLY | O_LARGEFILE, current_cred());
	if (IS_ERR_OR_NULL(pcc_filp)) {
		rc = pcc_filp == NULL ? -EINVAL : PTR_ERR(pcc_filp);
		GOTO(out_dentry, rc);
	}

	rc = pcc_inode_reset_iattr(inode, *dentry, ATTR_UID | ATTR_GID,
				   old_cred->uid, old_cred->gid, 0);
	if (rc)
		GOTO(out_fput, rc);

	rc = pcc_file_reset_projid(dataset, pcc_filp,
				    ll_i2info(inode)->lli_projid);
	if (rc)
		GOTO(out_fput, rc);

	/*
	 * When attach a file at file open() time with direct I/O mode, the
	 * data copy from Lustre OSTs to PCC copy in kernel will report
	 * -EFAULT error as the buffer is allocated in the kernel space, not
	 * from the user space.
	 * Thus it needs to unmask O_DIRECT flag from the file handle during
	 * data copy. After finished data copying, restore the flag in the
	 * file handle.
	 */
	if (file->f_flags & O_DIRECT) {
		file->f_flags &= ~O_DIRECT;
		direct = true;
	}

	ret = pcc_copy_data(file, pcc_filp);
	if (direct)
		file->f_flags |= O_DIRECT;
	if (ret < 0)
		GOTO(out_fput, rc = ret);

	/*
	 * It must to truncate the PCC copy to the same size of the Lustre
	 * copy after copy data. Otherwise, it may get wrong file size after
	 * re-attach a file. See LU-13023 for details.
	 */
	rc = pcc_inode_reset_iattr(inode, *dentry,
				   ATTR_SIZE | ATTR_MTIME | ATTR_MTIME_SET,
				   KUIDT_INIT(0), KGIDT_INIT(0), ret);
out_fput:
	fput(pcc_filp);
out_dentry:
	if (rc) {
		pcc_inode_remove(inode, *dentry);
		dput(*dentry);
	}
out_cred:
	revert_creds(old_cred);
	RETURN(rc);
}

int pcc_readwrite_attach(struct file *file, struct inode *inode,
			 __u32 archive_id)
{
	struct pcc_dataset *dataset;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_super *super = ll_i2pccs(inode);
	struct pcc_inode *pcci;
	struct dentry *dentry;
	int rc;

	ENTRY;

	rc = pcc_attach_check_set(inode);
	if (rc)
		RETURN(rc);

	dataset = pcc_dataset_get(&ll_i2sbi(inode)->ll_pcc_super,
				  LU_PCC_READWRITE, archive_id);
	if (dataset == NULL)
		RETURN(-ENOENT);

	rc = pcc_attach_data_archive(file, inode, dataset, &dentry);
	if (rc)
		GOTO(out_dataset_put, rc);

	/* Pause to allow for a race with concurrent HSM remove */
	CFS_FAIL_TIMEOUT(OBD_FAIL_LLITE_PCC_ATTACH_PAUSE, cfs_fail_val);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	LASSERT(!pcci);
	OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
	if (pcci == NULL)
		GOTO(out_unlock, rc = -ENOMEM);

	pcc_inode_attach_set(super, dataset, lli, pcci,
			     dentry, LU_PCC_READWRITE);
out_unlock:
	pcc_inode_unlock(inode);
	if (rc) {
		const struct cred *old_cred;

		old_cred = override_creds(pcc_super_cred(inode->i_sb));
		(void) pcc_inode_remove(inode, dentry);
		revert_creds(old_cred);
		dput(dentry);
	} else {
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_PCC_ATTACH, 1);
	}
out_dataset_put:
	pcc_dataset_put(dataset);
	RETURN(rc);
}

int pcc_readwrite_attach_fini(struct file *file, struct inode *inode,
			      __u32 gen, bool lease_broken, int rc,
			      bool attached)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
	struct pcc_inode *pcci;
	__u32 gen2;

	ENTRY;

	old_cred = override_creds(pcc_super_cred(inode->i_sb));
	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (rc || lease_broken) {
		if (attached && pcci)
			pcc_inode_put(pcci);

		GOTO(out_unlock, rc);
	}

	/* PCC inode may be released due to layout lock revocatioin */
	if (!pcci)
		GOTO(out_unlock, rc = -ESTALE);

	LASSERT(attached);
	rc = pcc_layout_xattr_set(pcci, gen);
	if (rc)
		GOTO(out_put, rc);

	LASSERT(lli->lli_pcc_state & PCC_STATE_FL_ATTACHING);
	rc = ll_layout_refresh(inode, &gen2);
	if (!rc) {
		if (gen2 == gen) {
			pcc_layout_gen_set(pcci, gen);
		} else {
			CDEBUG(D_CACHE,
			       DFID" layout changed from %d to %d.\n",
			       PFID(ll_inode2fid(inode)), gen, gen2);
			GOTO(out_put, rc = -ESTALE);
		}
	}

out_put:
	if (rc) {
		if (!pcci->pcci_unlinked)
			(void) pcc_inode_remove(inode, pcci->pcci_path.dentry);
		pcc_inode_put(pcci);
	}
out_unlock:
	lli->lli_pcc_state &= ~PCC_STATE_FL_ATTACHING;
	pcc_inode_unlock(inode);
	revert_creds(old_cred);
	RETURN(rc);
}

static int pcc_layout_rdonly_set(struct inode *inode, __u32 *gen, bool *cached)

{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lu_extent ext = {
		.e_start = 0,
		.e_end = OBD_OBJECT_EOF,
	};
	struct cl_layout clt = {
		.cl_layout_gen = 0,
		.cl_is_released = false,
		.cl_is_rdonly = false,
	};
	int retries = 0;
	int rc;

	ENTRY;

repeat:
	rc = pcc_get_layout_info(inode, &clt);
	if (rc)
		RETURN(rc);

	/*
	 * For the HSM released file, restore the data first.
	 */
	if (clt.cl_is_released) {
		retries++;
		if (retries > 2)
			RETURN(-EBUSY);

		if (ll_layout_version_get(lli) != CL_LAYOUT_GEN_NONE) {
			rc = ll_layout_restore(inode, 0, OBD_OBJECT_EOF);
			if (rc) {
				CDEBUG(D_CACHE, DFID" RESTORE failure: %d\n",
				       PFID(&lli->lli_fid), rc);
				RETURN(rc);
			}
		}
		rc = ll_layout_refresh(inode, gen);
		if (rc)
			RETURN(rc);

		goto repeat;
	}


	if (!clt.cl_is_rdonly) {
		rc = ll_layout_write_intent(inode, LAYOUT_INTENT_PCCRO_SET,
					    &ext);
		if (rc)
			RETURN(rc);

		rc = ll_layout_refresh(inode, gen);
	} else { /* Readonly layout */
		struct pcc_inode *pcci;

		*gen = clt.cl_layout_gen;
		/*
		 * The file is already in readonly state, give a chance to
		 * try auto attach.
		 */
		pcc_inode_lock(inode);
		pcci = ll_i2pcci(inode);
		if (pcci && pcc_inode_has_layout(pcci))
			*cached = true;
		else
			rc = pcc_try_datasets_attach(inode, PIT_OPEN, *gen,
						     LU_PCC_READONLY, cached);
		pcc_inode_unlock(inode);
		if (*cached)
			ll_stats_ops_tally(ll_i2sbi(inode),
					   LPROC_LL_PCC_AUTOAT, 1);
	}

	RETURN(rc);
}

static int pcc_readonly_attach(struct file *file,
			       struct inode *inode, __u32 roid)
{
	struct pcc_super *super = ll_i2pccs(inode);
	struct ll_inode_info *lli = ll_i2info(inode);
	const struct cred *old_cred;
	struct pcc_dataset *dataset;
	struct pcc_inode *pcci = NULL;
	struct dentry *dentry;
	bool attached = false;
	bool unlinked = false;
	bool cached = false;
	__u32 gen;
	int rc;

	ENTRY;

	rc = pcc_layout_rdonly_set(inode, &gen, &cached);
	if (cached)
		RETURN(0);
	if (rc)
		RETURN(rc);

	dataset = pcc_dataset_get(&ll_s2sbi(inode->i_sb)->ll_pcc_super,
				  LU_PCC_READONLY, roid);
	if (dataset == NULL)
		RETURN(-ENOENT);

	rc = pcc_attach_data_archive(file, inode, dataset, &dentry);
	if (rc)
		GOTO(out_dataset_put, rc);

	pcc_inode_lock(inode);
	old_cred = override_creds(super->pccs_cred);
	if (gen != ll_layout_version_get(lli)) {
		CDEBUG(D_CACHE, "L.Gen mismatch %u:%u\n",
		       gen, ll_layout_version_get(lli));
		GOTO(out_put_unlock, rc = -ESTALE);
	}

	pcci = ll_i2pcci(inode);
	if (!pcci) {
		OBD_SLAB_ALLOC_PTR_GFP(pcci, pcc_inode_slab, GFP_NOFS);
		if (pcci == NULL)
			GOTO(out_put_unlock, rc = -ENOMEM);

		pcc_inode_attach_set(super, dataset, lli, pcci,
				     dentry, LU_PCC_READONLY);
	} else if (pcc_inode_has_layout(pcci)) {
		/*
		 * There may be a gap between auto attach and auto open cache:
		 * ->pcc_file_open()
		 *  ->pcc_try_auto_attach()
		 *    The file is re-attach into PCC by other thread.
		 *  ->pcc_try_readonly_open_attach()
		 */
		CWARN("%s: The file (fid@"DFID") is already attached.\n",
		      ll_i2sbi(inode)->ll_fsname, PFID(ll_inode2fid(inode)));
		GOTO(out_put_unlock, rc = -EEXIST);
	} else {
		atomic_inc(&pcci->pcci_refcount);
		path_put(&pcci->pcci_path);
		pcci->pcci_path.mnt = mntget(dataset->pccd_path.mnt);
		pcci->pcci_path.dentry = dentry;
		pcci->pcci_type = LU_PCC_READONLY;
	}
	attached = true;
	rc = pcc_layout_xattr_set(pcci, gen);
	if (rc) {
		pcci->pcci_type = LU_PCC_NONE;
		unlinked = pcci->pcci_unlinked;
		GOTO(out_put_unlock, rc);
	}

	pcc_layout_gen_set(pcci, gen);
out_put_unlock:
	if (rc) {
		if (!unlinked)
			(void) pcc_inode_remove(inode, dentry);
		if (attached)
			pcc_inode_put(pcci);
		else
			dput(dentry);
	} else {
		ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_PCC_ATTACH, 1);
	}
	revert_creds(old_cred);
	pcc_inode_unlock(inode);
out_dataset_put:
	pcc_dataset_put(dataset);

	RETURN(rc);
}

static int pcc_readonly_attach_sync(struct file *file,
				    struct inode *inode, __u32 roid)
{
	int rc;

	ENTRY;

	if (!test_bit(LL_SBI_LAYOUT_LOCK, ll_i2sbi(inode)->ll_flags))
		RETURN(-EOPNOTSUPP);

	rc = pcc_attach_check_set(inode);
	if (rc) {
		CDEBUG(D_CACHE,
		       "PCC-RO caching for "DFID" not allowed, rc = %d\n",
		       PFID(ll_inode2fid(inode)), rc);
		/*
		 * Ignore EEXIST error if the file has already attached.
		 * Ignore EINPROGRESS error if the file is being attached,
		 * i.e. copy data from OSTs into PCC.
		 */
		if (rc == -EEXIST || rc == -EINPROGRESS)
			rc = 0;
		RETURN(rc);
	}

	rc = pcc_readonly_attach(file, inode, roid);
	pcc_readonly_attach_fini(inode);
	RETURN(rc);
}

int pcc_ioctl_attach(struct file *file, struct inode *inode,
		     struct lu_pcc_attach *attach)
{
	int rc = 0;

	ENTRY;

	switch (attach->pcca_type) {
	case LU_PCC_READWRITE:
		rc = -EOPNOTSUPP;
		break;
	case LU_PCC_READONLY:
		rc = pcc_readonly_attach_sync(file, inode, attach->pcca_id);
		break;
	default:
		rc = -EINVAL;
		break;
	}

	RETURN(rc);
}

static int pcc_hsm_remove(struct inode *inode)
{
	struct hsm_user_request *hur;
	__u32 gen;
	int len;
	int rc;

	ENTRY;

	rc = ll_layout_restore(inode, 0, OBD_OBJECT_EOF);
	if (rc) {
		CDEBUG(D_CACHE, DFID" RESTORE failure: %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), rc);
		/* ignore the RESTORE failure.
		 * i.e. the file is in exists dirty archived state.
		 */
	} else {
		ll_layout_refresh(inode, &gen);
	}

	len = sizeof(struct hsm_user_request) +
	      sizeof(struct hsm_user_item);
	OBD_ALLOC(hur, len);
	if (hur == NULL)
		RETURN(-ENOMEM);

	hur->hur_request.hr_action = HUA_REMOVE;
	hur->hur_request.hr_archive_id = 0;
	hur->hur_request.hr_flags = 0;
	memcpy(&hur->hur_user_item[0].hui_fid, &ll_i2info(inode)->lli_fid,
	       sizeof(hur->hur_user_item[0].hui_fid));
	hur->hur_user_item[0].hui_extent.offset = 0;
	hur->hur_user_item[0].hui_extent.length = OBD_OBJECT_EOF;
	hur->hur_request.hr_itemcount = 1;
	rc = obd_iocontrol(LL_IOC_HSM_REQUEST, ll_i2sbi(inode)->ll_md_exp,
			   len, hur, NULL);
	if (rc)
		CDEBUG(D_CACHE, DFID" HSM REMOVE failure: %d\n",
		       PFID(&ll_i2info(inode)->lli_fid), rc);

	OBD_FREE(hur, len);
	RETURN(rc);
}

int pcc_ioctl_detach(struct inode *inode, __u32 *flags)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;
	const struct cred *old_cred;
	bool hsm_remove = false;
	int rc = 0;

	ENTRY;

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (lli->lli_pcc_state & PCC_STATE_FL_ATTACHING) {
		*flags |= PCC_DETACH_FL_ATTACHING;
		GOTO(out_unlock, rc = 0);
	}

	if (!pcci || !pcc_inode_has_layout(pcci))
		GOTO(out_unlock, rc = 0);

	LASSERT(atomic_read(&pcci->pcci_refcount) > 0);

	if (pcci->pcci_type == LU_PCC_READWRITE) {
		if (*flags & PCC_DETACH_FL_UNCACHE) {
			hsm_remove = true;
			/*
			 * The file will be removed from PCC, set the flags
			 * with PCC_DATASET_NONE even the later removal of the
			 * PCC copy fails.
			 */
			lli->lli_pcc_dsflags = PCC_DATASET_NONE;
		}

		pcc_inode_detach_put(inode);
	} else if (pcci->pcci_type == LU_PCC_READONLY) {
		pcc_inode_detach(inode);

		if (*flags & PCC_DETACH_FL_UNCACHE && !pcci->pcci_unlinked) {
			old_cred =  override_creds(pcc_super_cred(inode->i_sb));
			rc = pcc_inode_remove(inode, pcci->pcci_path.dentry);
			revert_creds(old_cred);
			if (!rc) {
				pcci->pcci_unlinked = true;
				*flags |= PCC_DETACH_FL_CACHE_REMOVED;
			}
		}

		pcc_inode_put(pcci);
	} else {
		rc = -EOPNOTSUPP;
	}

out_unlock:
	pcc_inode_unlock(inode);

	if (hsm_remove || (*flags & PCC_DETACH_FL_UNCACHE &&
			   *flags & PCC_DETACH_FL_KNOWN_READWRITE)) {
		old_cred = override_creds(pcc_super_cred(inode->i_sb));
		rc = pcc_hsm_remove(inode);
		revert_creds(old_cred);
		if (!rc)
			*flags |= PCC_DETACH_FL_CACHE_REMOVED;
	}

	RETURN(rc);
}

int pcc_ioctl_state(struct file *file, struct inode *inode,
		    struct lu_pcc_state *state)
{
	int rc = 0;
	int count;
	char *buf;
	char *path;
	int buf_len = sizeof(state->pccs_path);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct pcc_inode *pcci;

	ENTRY;
	if (buf_len <= 0)
		RETURN(-EINVAL);

	OBD_ALLOC(buf, buf_len);
	if (buf == NULL)
		RETURN(-ENOMEM);

	pcc_inode_lock(inode);
	pcci = ll_i2pcci(inode);
	if (pcci == NULL) {
		state->pccs_type = LU_PCC_NONE;
		state->pccs_flags = lli->lli_pcc_state;
		GOTO(out_unlock, rc = 0);
	}

	count = atomic_read(&pcci->pcci_refcount);
	if (count == 0) {
		state->pccs_type = LU_PCC_NONE;
		state->pccs_open_count = 0;
		GOTO(out_unlock, rc = 0);
	}

	if (pcc_inode_has_layout(pcci))
		count--;

	if (file) {
		struct ll_file_data *fd = file->private_data;
		struct pcc_file *pccf = &fd->fd_pcc_file;

		if (pccf->pccf_file != NULL)
			count--;
	}

	state->pccs_type = pcci->pcci_type;
	state->pccs_open_count = count;
	state->pccs_flags = lli->lli_pcc_state;
	path = dentry_path_raw(pcci->pcci_path.dentry, buf, buf_len);
	if (IS_ERR(path))
		GOTO(out_unlock, rc = PTR_ERR(path));

	if (strscpy(state->pccs_path, path, buf_len) < 0)
		GOTO(out_unlock, rc = -ENAMETOOLONG);

out_unlock:
	pcc_inode_unlock(inode);
	OBD_FREE(buf, buf_len);
	RETURN(rc);
}
