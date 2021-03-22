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
 * Copyright (c) 2012, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lnet/selftest/conctl.c
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 */
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pwd.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <linux/types.h>

#include <libcfs/util/list.h>
#include <libcfs/util/ioctl.h>
#include <libcfs/util/parser.h>
#include <linux/lnet/lnetctl.h>
#include <linux/lnet/lnetst.h>
#include <linux/lnet/nidstr.h>
#include "lnetconfig/liblnetconfig.h"

struct lst_sid LST_INVALID_SID = { .ses_nid = LNET_NID_ANY, .ses_stamp = -1 };
static struct lst_sid session_id;
static int                 session_key;
static int lst_list_commands(int argc, char **argv);

/* All nodes running 2.6.50 or later understand feature LST_FEAT_BULK_LEN */
static unsigned		session_features = LST_FEATS_MASK;
static struct lstcon_trans_stat	trans_stat;

typedef struct list_string {
	struct list_string *lstr_next;
	int                 lstr_sz;
	char                lstr_str[0];
} lstr_t;

#ifndef offsetof
# define offsetof(typ,memb)     ((unsigned long)((char *)&(((typ *)0)->memb)))
#endif

static int alloc_count = 0;
static int alloc_nob   = 0;

lstr_t *
alloc_lstr(int sz)
{
        lstr_t  *lstr = malloc(offsetof(lstr_t, lstr_str[sz]));

        if (lstr == NULL) {
                fprintf(stderr, "Can't allocate lstr\n");
                abort();
        }

        alloc_nob += sz;
        alloc_count++;

        lstr->lstr_str[0] = 0;
        lstr->lstr_sz = sz;
        return lstr;
}

void
free_lstr(lstr_t *lstr)
{
        alloc_count--;
        alloc_nob -= lstr->lstr_sz;
        free(lstr);
}

void
free_lstrs(lstr_t **list)
{
        lstr_t   *lstr;

        while ((lstr = *list) != NULL) {
                *list = lstr->lstr_next;
                free_lstr(lstr);
        }
}

void
new_lstrs(lstr_t **list, char *prefix, char *postfix,
          int lo, int hi, int stride)
{
        int    n1 = strlen(prefix);
        int    n2 = strlen(postfix);
        int    sz = n1 + 20 + n2 + 1;

        do {
                lstr_t *n = alloc_lstr(sz);

                snprintf(n->lstr_str, sz - 1, "%s%u%s",
                         prefix, lo, postfix);

                n->lstr_next = *list;
                *list = n;

                lo += stride;
        } while (lo <= hi);
}

int
expand_lstr(lstr_t **list, lstr_t *l)
{
        int          nob = strlen(l->lstr_str);
        char        *b1;
        char        *b2;
        char        *expr;
        char        *sep;
        int          x;
        int          y;
        int          z;
        int          n;

        b1 = strchr(l->lstr_str, '[');
        if (b1 == NULL) {
                l->lstr_next = *list;
                *list = l;
                return 0;
        }

        b2 = strchr(b1, ']');
        if (b2 == NULL || b2 == b1 + 1)
                return -1;

        *b1++ = 0;
        *b2++ = 0;
        expr = b1;
        do {

                sep = strchr(expr, ',');
                if (sep != NULL)
                        *sep++ = 0;

                nob = strlen(expr);
                n = nob;
                if (sscanf(expr, "%u%n", &x, &n) >= 1 && n == nob) {
                        /* simple number */
                        new_lstrs(list, l->lstr_str, b2, x, x, 1);
                        continue;
                }

                n = nob;
                if (sscanf(expr, "%u-%u%n", &x, &y, &n) >= 2 && n == nob &&
                    x < y) {
                        /* simple range */
                        new_lstrs(list, l->lstr_str, b2, x, y, 1);
                        continue;
                }

                n = nob;
                if (sscanf(expr, "%u-%u/%u%n", &x, &y, &z, &n) >= 3 && n == nob &&
                    x < y) {
                        /* strided range */
                        new_lstrs(list, l->lstr_str, b2, x, y, z);
                        continue;
                }

                /* syntax error */
                return -1;
        } while ((expr = sep) != NULL);

        free_lstr(l);

        return 1;
}

int
expand_strs(char *str, lstr_t **head)
{
        lstr_t  *list = NULL;
        lstr_t  *nlist;
        lstr_t  *l;
        int      rc = 0;
        int      expanded;

        l = alloc_lstr(strlen(str) + 1);
        memcpy(l->lstr_str, str, strlen(str) + 1);
        l->lstr_next = NULL;
        list = l;

        do {
                expanded = 0;
                nlist = NULL;

                while ((l = list) != NULL) {
                        list = l->lstr_next;

                        rc = expand_lstr(&nlist, l);
                        if (rc < 0) {
                                fprintf(stderr, "Syntax error in \"%s\"\n", str);
                                free_lstr(l);
                                break;
                        }

                        expanded |= rc > 0;
                }

                /* re-order onto 'list' */
                while ((l = nlist) != NULL) {
                        nlist = l->lstr_next;
                        l->lstr_next = list;
                        list = l;
                }

        } while (expanded && rc > 0);

        if (rc >= 0) {
                *head = list;
                return 0;
        }

        while ((l = list) != NULL) {
                list = l->lstr_next;

                free_lstr(l);
        }
        return rc;
}

int
lst_parse_nids(char *str, int *countp, struct lnet_process_id **idspp)
{
        lstr_t  *head = NULL;
        lstr_t  *l;
        int      c = 0;
        int      i;
        int      rc;

        rc = expand_strs(str, &head);
        if (rc != 0)
                goto out;

        l = head;
        while (l != NULL) {
                l = l->lstr_next;
                c++;
        }

	*idspp = malloc(c * sizeof(struct lnet_process_id));
        if (*idspp == NULL) {
                fprintf(stderr, "Out of memory\n");
                rc = -1;
        }

        *countp = c;
out:
        i = 0;
        while ((l = head) != NULL) {
                head = l->lstr_next;

                if (rc == 0) {
                        (*idspp)[i].nid = libcfs_str2nid(l->lstr_str);
                        if ((*idspp)[i].nid == LNET_NID_ANY) {
                                fprintf(stderr, "Invalid nid: %s\n",
                                        l->lstr_str);
                                rc = -1;
                        }

			(*idspp)[i].pid = LNET_PID_LUSTRE;
                        i++;
                }

                free_lstr(l);
        }

        if (rc == 0)
                return 0;

        free(*idspp);
        *idspp = NULL;

        return rc;
}

char *
lst_node_state2str(int state)
{
        if (state == LST_NODE_ACTIVE)
                return "Active";
        if (state == LST_NODE_BUSY)
                return "Busy";
        if (state == LST_NODE_DOWN)
                return "Down";

        return "Unknown";
}

int
lst_node_str2state(char *str)
{
        if (strcasecmp(str, "active") == 0)
                return LST_NODE_ACTIVE;
        if (strcasecmp(str, "busy") == 0)
                return LST_NODE_BUSY;
        if (strcasecmp(str, "down") == 0)
                return LST_NODE_DOWN;
        if (strcasecmp(str, "unknown") == 0)
                return LST_NODE_UNKNOWN;
        if (strcasecmp(str, "invalid") == 0)
                return (LST_NODE_UNKNOWN | LST_NODE_DOWN | LST_NODE_BUSY);

        return -1;
}

char *
lst_test_type2name(int type)
{
        if (type == LST_TEST_PING)
                return "ping";
        if (type == LST_TEST_BULK)
                return "brw";

        return "unknown";
}

int
lst_test_name2type(char *name)
{
        if (strcasecmp(name, "ping") == 0)
                return LST_TEST_PING;
        if (strcasecmp(name, "brw") == 0)
                return LST_TEST_BULK;

        return -1;
}

void
lst_print_usage(char *cmd)
{
        Parser_printhelp(cmd);
}

void
lst_print_error(char *sub, const char *def_format, ...)
{
        va_list ap;

        /* local error returned from kernel */
        switch (errno) {
        case ESRCH:
                fprintf(stderr, "No session exists\n");
                return;
        case ESHUTDOWN:
                fprintf(stderr, "Session is shutting down\n");
                return;
        case EACCES:
                fprintf(stderr, "Unmatched session key or not root\n");
                return;
        case ENOENT:
                fprintf(stderr, "Can't find %s in current session\n", sub);
                return;
        case EINVAL:
                fprintf(stderr, "Invalid parameters list in command line\n");
                return;
        case EFAULT:
                fprintf(stderr, "Bad parameter address\n");
                return;
        case EEXIST:
                fprintf(stderr, "%s already exists\n", sub);
                return;
        default:
                va_start(ap, def_format);
                vfprintf(stderr, def_format, ap);
                va_end(ap);

                return;
        }
}

void
lst_free_rpcent(struct list_head *head)
{
	struct lstcon_rpc_ent *ent;

	while (!list_empty(head)) {
		ent = list_entry(head->next, struct lstcon_rpc_ent, rpe_link);

		list_del(&ent->rpe_link);
		free(ent);
	}
}

void
lst_reset_rpcent(struct list_head *head)
{
	struct lstcon_rpc_ent *ent;

	list_for_each_entry(ent, head, rpe_link) {
		ent->rpe_sid	   = LST_INVALID_SID;
		ent->rpe_peer.nid  = LNET_NID_ANY;
		ent->rpe_peer.pid  = LNET_PID_ANY;
		ent->rpe_rpc_errno = ent->rpe_fwk_errno = 0;
	}
}

int
lst_alloc_rpcent(struct list_head *head, int count, int offset)
{
	struct lstcon_rpc_ent *ent;
        int               i;

        for (i = 0; i < count; i++) {
		ent = malloc(offsetof(struct lstcon_rpc_ent, rpe_payload[offset]));
                if (ent == NULL) {
                        lst_free_rpcent(head);
                        return -1;
                }

		memset(ent, 0, offsetof(struct lstcon_rpc_ent, rpe_payload[offset]));

		ent->rpe_sid	  = LST_INVALID_SID;
		ent->rpe_peer.nid = LNET_NID_ANY;
		ent->rpe_peer.pid = LNET_PID_ANY;
		list_add(&ent->rpe_link, head);
	}

	return 0;
}

void
lst_print_transerr(struct list_head *head, char *optstr)
{
	struct lstcon_rpc_ent *ent;

	list_for_each_entry(ent, head, rpe_link) {
		if (ent->rpe_rpc_errno == 0 && ent->rpe_fwk_errno == 0)
			continue;

                if (ent->rpe_rpc_errno != 0) {
                        fprintf(stderr, "%s RPC failed on %s: %s\n",
                                optstr, libcfs_id2str(ent->rpe_peer),
                                strerror(ent->rpe_rpc_errno));
                        continue;
                }

		fprintf(stderr, "operation %s failed on %s: %s\n",
                        optstr, libcfs_id2str(ent->rpe_peer),
                        strerror(ent->rpe_fwk_errno));
        }
}

int lst_info_batch_ioctl(char *batch, int test, int server,
			struct lstcon_test_batch_ent *entp, int *idxp,
			int *ndentp, struct lstcon_node_ent *dentsp);

int lst_info_group_ioctl(char *name, struct lstcon_ndlist_ent *gent,
			 int *idx, int *count, struct lstcon_node_ent *dents);

int lst_query_batch_ioctl(char *batch, int test, int server,
			  int timeout, struct list_head *head);

int
lst_ioctl(unsigned int opc, void *buf, int len)
{
        struct libcfs_ioctl_data data;
        int    rc;

        LIBCFS_IOC_INIT (data);
        data.ioc_u32[0]  = opc;
        data.ioc_plen1   = len;
        data.ioc_pbuf1   = (char *)buf;
        data.ioc_plen2   = sizeof(trans_stat);
        data.ioc_pbuf2   = (char *)&trans_stat;

        memset(&trans_stat, 0, sizeof(trans_stat));

        rc = l_ioctl(LNET_DEV_ID, IOC_LIBCFS_LNETST, &data);

        /* local error, no valid RPC result */
        if (rc != 0)
                return -1;

        /* RPC error */
        if (trans_stat.trs_rpc_errno != 0)
                return -2;

        /* Framework error */
        if (trans_stat.trs_fwk_errno != 0)
                return -3;

        return 0;
}

int
lst_new_session_ioctl(char *name, int timeout, int force, struct lst_sid *sid)
{
	struct lstio_session_new_args args = { 0 };

        args.lstio_ses_key     = session_key;
        args.lstio_ses_timeout = timeout;
        args.lstio_ses_force   = force;
        args.lstio_ses_idp     = sid;
	args.lstio_ses_feats   = session_features;
        args.lstio_ses_nmlen   = strlen(name);
        args.lstio_ses_namep   = name;

        return lst_ioctl (LSTIO_SESSION_NEW, &args, sizeof(args));
}

int
jt_lst_new_session(int argc, char **argv)
{
	char  buf[LST_NAME_SIZE * 2 + 1];
	char *name;
	int   optidx = 0;
	int   timeout = 300;
	int   force = 0;
	int   c;
	int   rc;

	static const struct option session_opts[] = {
		{ .name = "timeout", .has_arg = required_argument, .val = 't' },
		{ .name = "force",   .has_arg = no_argument,	   .val = 'f' },
		{ .name = NULL } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {

                c = getopt_long(argc, argv, "ft:",
                                session_opts, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 'f':
                        force = 1;
                        break;
                case 't':
                        timeout = atoi(optarg);
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (timeout <= 0) {
                fprintf(stderr, "Invalid timeout value\n");
                return -1;
        }

        if (optind == argc - 1) {
                name = argv[optind ++];
                if (strlen(name) >= LST_NAME_SIZE) {
                        fprintf(stderr, "Name size is limited to %d\n",
                                LST_NAME_SIZE - 1);
                        return -1;
                }

        } else if (optind == argc) {
                char           user[LST_NAME_SIZE];
                char           host[LST_NAME_SIZE];
                struct passwd *pw = getpwuid(getuid());

                if (pw == NULL)
                        snprintf(user, sizeof(user), "%d", (int)getuid());
                else
                        snprintf(user, sizeof(user), "%s", pw->pw_name);

                rc = gethostname(host, sizeof(host));
                if (rc != 0)
                        snprintf(host, sizeof(host), "unknown_host");

		snprintf(buf, sizeof(buf), "%s@%s", user, host);
                name = buf;

        } else {
                lst_print_usage(argv[0]);
                return -1;
        }

        rc = lst_new_session_ioctl(name, timeout, force, &session_id);
        if (rc != 0) {
                lst_print_error("session", "Failed to create session: %s\n",
                                strerror(errno));
                return rc;
        }

	fprintf(stdout, "SESSION: %s FEATURES: %x TIMEOUT: %d FORCE: %s\n",
		name, session_features, timeout, force ? "Yes" : "No");
	return 0;
}

int
lst_session_info_ioctl(char *name, int len, int *key, unsigned *featp,
		       struct lst_sid *sid, struct lstcon_ndlist_ent *ndinfo)
{
	struct lstio_session_info_args args = { 0 };

	args.lstio_ses_idp     = sid;
	args.lstio_ses_keyp    = key;
	args.lstio_ses_featp   = featp;
	args.lstio_ses_ndinfo  = ndinfo;
	args.lstio_ses_nmlen   = len;
	args.lstio_ses_namep   = name;

	return lst_ioctl(LSTIO_SESSION_INFO, &args, sizeof(args));
}

int
jt_lst_show_session(int argc, char **argv)
{
	struct lstcon_ndlist_ent ndinfo;
	struct lst_sid sid;
        char                name[LST_NAME_SIZE];
	unsigned	    feats;
	int		    key;
	int		    rc;

	rc = lst_session_info_ioctl(name, sizeof(name), &key,
				    &feats, &sid, &ndinfo);

        if (rc != 0) {
                lst_print_error("session", "Failed to show session: %s\n",
                                strerror(errno));
                return -1;
        }

	fprintf(stdout, "%s ID: %ju@%s, KEY: %d FEATURES: %x NODES: %d\n",
		name, (uintmax_t)sid.ses_stamp, libcfs_nid2str(sid.ses_nid),
		key, feats, ndinfo.nle_nnode);

        return 0;
}

int
lst_end_session_ioctl(void)
{
	struct lstio_session_end_args args = { 0 };

	args.lstio_ses_key = session_key;
	return lst_ioctl(LSTIO_SESSION_END, &args, sizeof(args));
}

int
jt_lst_end_session(int argc, char **argv)
{
        int             rc;

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        rc = lst_end_session_ioctl();

        if (rc == 0) {
                fprintf(stdout, "session is ended\n");
                return 0;
        }

        if (rc == -1) {
                lst_print_error("session", "Failed to end session: %s\n",
                                strerror(errno));
                return rc;
        }

        if (trans_stat.trs_rpc_errno != 0) {
                fprintf(stderr,
                        "[RPC] Failed to send %d session RPCs: %s\n",
                        lstcon_rpc_stat_failure(&trans_stat, 0),
                        strerror(trans_stat.trs_rpc_errno));
        }

        if (trans_stat.trs_fwk_errno != 0) {
                fprintf(stderr,
                        "[FWK] Failed to end session on %d nodes: %s\n",
                        lstcon_sesop_stat_failure(&trans_stat, 0),
                        strerror(trans_stat.trs_fwk_errno));
        }

        return rc;
}

int
lst_ping_ioctl(char *str, int type, int timeout,
	       int count, struct lnet_process_id *ids, struct list_head *head)
{
	struct lstio_debug_args args = { 0 };

        args.lstio_dbg_key     = session_key;
        args.lstio_dbg_type    = type;
        args.lstio_dbg_flags   = 0;
        args.lstio_dbg_timeout = timeout;
        args.lstio_dbg_nmlen   = (str == NULL) ? 0: strlen(str);
        args.lstio_dbg_namep   = str;
        args.lstio_dbg_count   = count;
        args.lstio_dbg_idsp    = ids;
        args.lstio_dbg_resultp = head;

        return lst_ioctl (LSTIO_DEBUG, &args, sizeof(args));
}

int
lst_get_node_count(int type, char *str, int *countp,
		   struct lnet_process_id **idspp)
{
        char                    buf[LST_NAME_SIZE];
	struct lstcon_test_batch_ent ent;
	struct lstcon_ndlist_ent    *entp = &ent.tbe_cli_nle;
	struct lst_sid sid;
	unsigned		feats;
	int			key;
	int			rc;

	switch (type) {
	case LST_OPC_SESSION:
		rc = lst_session_info_ioctl(buf, LST_NAME_SIZE,
					    &key, &feats, &sid, entp);
		break;

        case LST_OPC_BATCHSRV:
                entp = &ent.tbe_srv_nle;
        case LST_OPC_BATCHCLI:
                rc = lst_info_batch_ioctl(str, 0, 0, &ent, NULL, NULL, NULL);
                break;

        case LST_OPC_GROUP:
                rc = lst_info_group_ioctl(str, entp, NULL, NULL, NULL);
                break;

        case LST_OPC_NODES:
                rc = lst_parse_nids(str, &entp->nle_nnode, idspp) < 0 ? -1 : 0;
                break;

        default:
                rc = -1;
                break;
        }

        if (rc == 0)
                *countp = entp->nle_nnode;

        return rc;
}

int
jt_lst_ping(int argc,  char **argv)
{
	struct list_head   head;
	struct lnet_process_id *ids = NULL;
	struct lstcon_rpc_ent  *ent = NULL;
	char              *str = NULL;
	int                optidx  = 0;
	int                server  = 0;
	int                timeout = 5;
	int                count   = 0;
	int                type    = 0;
	int                rc      = 0;
	int                c;

	static const struct option ping_opts[] = {
		{ .name = "session", .has_arg = no_argument,	   .val = 's' },
		{ .name = "server",  .has_arg = no_argument,	   .val = 'v' },
		{ .name = "batch",   .has_arg = required_argument, .val = 'b' },
		{ .name = "group",   .has_arg = required_argument, .val = 'g' },
		{ .name = "nodes",   .has_arg = required_argument, .val = 'n' },
		{ .name = "timeout", .has_arg = required_argument, .val = 't' },
		{ .name = NULL, } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {

                c = getopt_long(argc, argv, "g:b:n:t:sv",
                                ping_opts, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 's':
                        type = LST_OPC_SESSION;
                        break;

                case 'g':
                        type = LST_OPC_GROUP;
                        str = optarg;
                        break;

                case 'b':
                        type = LST_OPC_BATCHCLI;
                        str = optarg;
                        break;

                case 'n':
                        type = LST_OPC_NODES;
                        str = optarg;
                        break;

                case 't':
                        timeout = atoi(optarg);
                        break;

                case 'v':
                        server = 1;
                        break;

                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (type == 0 || timeout <= 0 || optind != argc) {
                lst_print_usage(argv[0]);
                return -1;
        }

        if (type == LST_OPC_BATCHCLI && server)
                type = LST_OPC_BATCHSRV;

        rc = lst_get_node_count(type, str, &count, &ids);
        if (rc < 0) {
                fprintf(stderr, "Failed to get count of nodes from %s: %s\n",
                        (str == NULL) ? "session" : str, strerror(errno));
                return -1;
        }

	INIT_LIST_HEAD(&head);

        rc = lst_alloc_rpcent(&head, count, LST_NAME_SIZE);
        if (rc != 0) {
                fprintf(stderr, "Out of memory\n");
                goto out;
        }

        if (count == 0) {
                fprintf(stdout, "Target %s is empty\n",
                        (str == NULL) ? "session" : str);
                goto out;
        }

        rc = lst_ping_ioctl(str, type, timeout, count, ids, &head);
        if (rc == -1) { /* local failure */
                lst_print_error("debug", "Failed to ping %s: %s\n",
                                (str == NULL) ? "session" : str,
                                strerror(errno));
                rc = -1;
                goto out;
        }

	/* ignore RPC errors and framwork errors */
	list_for_each_entry(ent, &head, rpe_link) {
		fprintf(stdout, "\t%s: %s [session: %s id: %s]\n",
			libcfs_id2str(ent->rpe_peer),
			lst_node_state2str(ent->rpe_state),
			(ent->rpe_state == LST_NODE_ACTIVE ||
			 ent->rpe_state == LST_NODE_BUSY) ?
				(ent->rpe_rpc_errno == 0 ?
					&ent->rpe_payload[0] : "Unknown") :
				"<NULL>", libcfs_nid2str(ent->rpe_sid.ses_nid));
	}

out:
        lst_free_rpcent(&head);

        if (ids != NULL)
                free(ids);

        return rc;

}

int
lst_add_nodes_ioctl(char *name, int count, struct lnet_process_id *ids,
		    unsigned *featp, struct list_head *resultp)
{
	struct lstio_group_nodes_args args = { 0 };

        args.lstio_grp_key     = session_key;
        args.lstio_grp_nmlen   = strlen(name);
        args.lstio_grp_namep   = name;
        args.lstio_grp_count   = count;
	args.lstio_grp_featp   = featp;
        args.lstio_grp_idsp    = ids;
        args.lstio_grp_resultp = resultp;

        return lst_ioctl(LSTIO_NODES_ADD, &args, sizeof(args));
}

int
lst_del_group_ioctl(char *name)
{
	struct lstio_group_del_args args = { 0 };

	args.lstio_grp_key   = session_key;
	args.lstio_grp_nmlen = strlen(name);
	args.lstio_grp_namep = name;

	return lst_ioctl(LSTIO_GROUP_DEL, &args, sizeof(args));
}

int
lst_del_group(char *grp_name)
{
	int	rc;

	rc = lst_del_group_ioctl(grp_name);
	if (rc == 0) {
		fprintf(stdout, "Group is deleted\n");
		return 0;
	}

	if (rc == -1) {
		lst_print_error("group", "Failed to delete group: %s\n",
				strerror(errno));
		return rc;
	}

	fprintf(stderr, "Group is deleted with some errors\n");

	if (trans_stat.trs_rpc_errno != 0) {
		fprintf(stderr,
			"[RPC] Failed to send %d end session RPCs: %s\n",
			lstcon_rpc_stat_failure(&trans_stat, 0),
			strerror(trans_stat.trs_rpc_errno));
	}

	if (trans_stat.trs_fwk_errno != 0) {
		fprintf(stderr,
			"[FWK] Failed to end session on %d nodes: %s\n",
		lstcon_sesop_stat_failure(&trans_stat, 0),
		strerror(trans_stat.trs_fwk_errno));
	}

	return -1;
}

int
lst_add_group_ioctl(char *name)
{
	struct lstio_group_add_args args = { 0 };

        args.lstio_grp_key     =  session_key;
        args.lstio_grp_nmlen   =  strlen(name);
        args.lstio_grp_namep   =  name;

        return lst_ioctl(LSTIO_GROUP_ADD, &args, sizeof(args));
}

int
jt_lst_add_group(int argc, char **argv)
{
	struct list_head   head;
	struct lnet_process_id *ids;
	char		  *name;
	unsigned	   feats = session_features;
	int		   count;
	int		   rc;
	int		   i;
	bool		   nodes_added = false;

	if (session_key == 0) {
		fprintf(stderr,
			"Can't find env LST_SESSION or value is not valid\n");
		return -1;
	}

	if (argc < 3) {
		lst_print_usage(argv[0]);
		return -1;
	}

	name = argv[1];
	if (strlen(name) >= LST_NAME_SIZE) {
		fprintf(stderr, "Name length is limited to %d\n",
			LST_NAME_SIZE - 1);
		return -1;
	}

	rc = lst_add_group_ioctl(name);
	if (rc != 0) {
		lst_print_error("group", "Failed to add group %s: %s\n",
				name, strerror(errno));
		return -1;
	}

	INIT_LIST_HEAD(&head);

	for (i = 2; i < argc; i++) {
		/* parse address list */
		rc = lst_parse_nids(argv[i], &count, &ids);
		if (rc < 0) {
			fprintf(stderr, "Ignore invalid id list %s\n",
				argv[i]);
			continue;
		}

		if (count == 0)
			continue;

		rc = lst_alloc_rpcent(&head, count, 0);
		if (rc != 0) {
			fprintf(stderr, "Out of memory\n");
			free(ids);
			rc = -1;
			goto failed;
		}

		rc = lst_add_nodes_ioctl(name, count, ids, &feats, &head);

		free(ids);

		if (rc != 0)
			goto failed;

		fprintf(stdout, "%s are added to session\n", argv[i]);

		nodes_added = true;

		if ((feats & session_features) != session_features) {
			fprintf(stdout,
				"Warning, this session will run with "
				"compatible mode because some test nodes "
				"might not understand these features: %x\n",
				(~feats & session_features));
		}

		lst_free_rpcent(&head);
	}

	if (!nodes_added) {
		/*
		 * The selftest kernel module expects that a group should
		 * have at least one node, since it doesn't make sense for
		 * an empty group to be added to a test.
		 */
		fprintf(stderr,
			"No nodes added successfully, deleting group %s\n",
			name);
		rc = lst_del_group(name);
		if (rc != 0) {
			fprintf(stderr,
				"Failed to delete group %s."
				"  Group is empty.\n", name);
		}
	}

	return rc;

failed:
	if (rc == -1) {
		lst_print_error("group", "Failed to add nodes %s: %s\n",
				argv[i], strerror(errno));

	} else {
		if (trans_stat.trs_fwk_errno == EPROTO) {
			fprintf(stderr,
				"test nodes might have different LST "
				"features, please disable some features by "
				"setting LST_FEATURES\n");
		}

		lst_print_transerr(&head, "create session");
	}

	lst_free_rpcent(&head);

	if (!nodes_added) {
		fprintf(stderr,
			"No nodes added successfully, deleting group %s\n",
			name);
		if (lst_del_group(name) != 0) {
			fprintf(stderr,
				"Failed to delete group %s."
				"  Group is empty.\n", name);
		}
	}

	return rc;
}

int
jt_lst_del_group(int argc, char **argv)
{
        int     rc;

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        if (argc != 2) {
                lst_print_usage(argv[0]);
                return -1;
        }

	rc = lst_del_group(argv[1]);

	return rc;
}

int
lst_update_group_ioctl(int opc, char *name, int clean, int count,
		       struct lnet_process_id *ids, struct list_head *resultp)
{
	struct lstio_group_update_args args = { 0 };

        args.lstio_grp_key      = session_key;
        args.lstio_grp_opc      = opc;
        args.lstio_grp_args     = clean;
        args.lstio_grp_nmlen    = strlen(name);
        args.lstio_grp_namep    = name;
        args.lstio_grp_count    = count;
        args.lstio_grp_idsp     = ids;
        args.lstio_grp_resultp  = resultp;

        return lst_ioctl(LSTIO_GROUP_UPDATE, &args, sizeof(args));
}

int
jt_lst_update_group(int argc, char **argv)
{
	struct list_head   head;
	struct lnet_process_id *ids = NULL;
	char              *str = NULL;
	char              *grp = NULL;
	int                optidx = 0;
	int                count = 0;
	int                clean = 0;
	int                opc = 0;
	int                rc;
	int                c;

	static const struct option update_group_opts[] = {
		{ .name = "refresh", .has_arg = no_argument,	   .val = 'f' },
		{ .name = "clean",   .has_arg = required_argument, .val = 'c' },
		{ .name = "remove",  .has_arg = required_argument, .val = 'r' },
		{ .name = NULL } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "fc:r:",
                                update_group_opts, &optidx);

                /* Detect the end of the options. */
                if (c == -1)
                        break;

                switch (c) {
                case 'f':
                        if (opc != 0) {
                                lst_print_usage(argv[0]);
                                return -1;
                        }
                        opc = LST_GROUP_REFRESH;
                        break;

                case 'r':
                        if (opc != 0) {
                                lst_print_usage(argv[0]);
                                return -1;
                        }
                        opc = LST_GROUP_RMND;
                        str = optarg;
                        break;

                case 'c':
                        clean = lst_node_str2state(optarg);
                        if (opc != 0 || clean <= 0) {
                                lst_print_usage(argv[0]);
                                return -1;
                        }
                        opc = LST_GROUP_CLEAN;
                        break;

                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        /* no OPC or group is specified */
        if (opc == 0 || optind != argc - 1) {
                lst_print_usage(argv[0]);
                return -1;
        }

        grp = argv[optind];

	INIT_LIST_HEAD(&head);

        if (opc == LST_GROUP_RMND || opc == LST_GROUP_REFRESH) {
                rc = lst_get_node_count(opc == LST_GROUP_RMND ? LST_OPC_NODES :
                                                                LST_OPC_GROUP,
                                        opc == LST_GROUP_RMND ? str : grp,
                                        &count, &ids);

                if (rc != 0) {
                        fprintf(stderr, "Can't get count of nodes from %s: %s\n",
                                opc == LST_GROUP_RMND ? str : grp,
                                strerror(errno));
                        return -1;
                }

                rc = lst_alloc_rpcent(&head, count, 0);
                if (rc != 0) {
                        fprintf(stderr, "Out of memory\n");
                        free(ids);
                        return -1;
                }

        }

        rc = lst_update_group_ioctl(opc, grp, clean, count, ids, &head);

        if (ids != NULL)
                free(ids);

        if (rc == 0) {
                lst_free_rpcent(&head);
                return 0;
        }

        if (rc == -1) {
                lst_free_rpcent(&head);
                lst_print_error("group", "Failed to update group: %s\n",
                                strerror(errno));
                return rc;
        }

        lst_print_transerr(&head, "Updating group");

        lst_free_rpcent(&head);

        return rc;
}

int
lst_list_group_ioctl(int len, char *name, int idx)
{
	struct lstio_group_list_args args = { 0 };

        args.lstio_grp_key   = session_key;
        args.lstio_grp_idx   = idx;
        args.lstio_grp_nmlen = len;
        args.lstio_grp_namep = name;

        return lst_ioctl(LSTIO_GROUP_LIST, &args, sizeof(args));
}

int
lst_info_group_ioctl(char *name, struct lstcon_ndlist_ent *gent,
		     int *idx, int *count, struct lstcon_node_ent *dents)
{
	struct lstio_group_info_args args = { 0 };

        args.lstio_grp_key    = session_key;
        args.lstio_grp_nmlen  = strlen(name);
        args.lstio_grp_namep  = name;
        args.lstio_grp_entp   = gent;
        args.lstio_grp_idxp   = idx;
        args.lstio_grp_ndentp = count;
        args.lstio_grp_dentsp = dents;

        return lst_ioctl(LSTIO_GROUP_INFO, &args, sizeof(args));
}

int
lst_list_group_all(void)
{
        char  name[LST_NAME_SIZE];
        int   rc;
        int   i;

        /* no group is specified, list name of all groups */
        for (i = 0; ; i++) {
                rc = lst_list_group_ioctl(LST_NAME_SIZE, name, i);
                if (rc == 0) {
                        fprintf(stdout, "%d) %s\n", i + 1, name);
                        continue;
                }

                if (errno == ENOENT)
                        break;

                lst_print_error("group", "Failed to list group: %s\n",
                                strerror(errno));
                return -1;
        }

        fprintf(stdout, "Total %d groups\n", i);

        return 0;
}

#define LST_NODES_TITLE "\tACTIVE\tBUSY\tDOWN\tUNKNOWN\tTOTAL\n"

int
jt_lst_list_group(int argc, char **argv)
{
	struct lstcon_ndlist_ent gent;
	struct lstcon_node_ent   *dents;
	int optidx  = 0;
	int verbose = 0;
	int active  = 0;
	int busy    = 0;
	int down    = 0;
	int unknown = 0;
	int all     = 0;
	int count;
	int index;
	int i;
	int j;
	int c;
	int rc      = 0;

	static const struct option list_group_opts[] = {
		{ .name = "active",  .has_arg = no_argument, .val = 'a' },
		{ .name = "busy",    .has_arg = no_argument, .val = 'b' },
		{ .name = "down",    .has_arg = no_argument, .val = 'd' },
		{ .name = "unknown", .has_arg = no_argument, .val = 'u' },
		{ .name = "all",     .has_arg = no_argument, .val = 'l' },
		{ .name = NULL, } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "abdul",
                                list_group_opts, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 'a':
                        verbose = active = 1;
                        all = 0;
                        break;
                case 'b':
                        verbose = busy = 1;
                        all = 0;
                        break;
                case 'd':
                        verbose = down = 1;
                        all = 0;
                        break;
                case 'u':
                        verbose = unknown = 1;
                        all = 0;
                        break;
                case 'l':
                        verbose = all = 1;
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (optind == argc) {
                /* no group is specified, list name of all groups */
                rc = lst_list_group_all();

                return rc;
        }

        if (!verbose)
                fprintf(stdout, LST_NODES_TITLE);

        /* list nodes in specified groups */
        for (i = optind; i < argc; i++) {
                rc = lst_info_group_ioctl(argv[i], &gent, NULL, NULL, NULL);
                if (rc != 0) {
                        if (errno == ENOENT) {
                                rc = 0;
                                break;
                        }

                        lst_print_error("group", "Failed to list group\n",
                                        strerror(errno));
                        break;
                }

                if (!verbose) {
                        fprintf(stdout, "\t%d\t%d\t%d\t%d\t%d\t%s\n",
                                gent.nle_nactive, gent.nle_nbusy,
                                gent.nle_ndown, gent.nle_nunknown,
                                gent.nle_nnode, argv[i]);
                        continue;
                }

                fprintf(stdout, "Group [ %s ]\n", argv[i]);

                if (gent.nle_nnode == 0) {
                        fprintf(stdout, "No nodes found [ %s ]\n", argv[i]);
                        continue;
                }

                count = gent.nle_nnode;

		dents = malloc(count * sizeof(struct lstcon_node_ent));
                if (dents == NULL) {
                        fprintf(stderr, "Failed to malloc: %s\n",
                                strerror(errno));
                        return -1;
                }

                index = 0;
                rc = lst_info_group_ioctl(argv[i], &gent, &index, &count, dents);
                if (rc != 0) {
                        lst_print_error("group", "Failed to list group: %s\n",
                                        strerror(errno));
                        free(dents);
                        return -1;
                }

                for (j = 0, c = 0; j < count; j++) {
                        if (all ||
                            ((active  &&  dents[j].nde_state == LST_NODE_ACTIVE) ||
                             (busy    &&  dents[j].nde_state == LST_NODE_BUSY)   ||
                             (down    &&  dents[j].nde_state == LST_NODE_DOWN)   ||
                             (unknown &&  dents[j].nde_state == LST_NODE_UNKNOWN))) {

                                fprintf(stdout, "\t%s: %s\n",
                                        libcfs_id2str(dents[j].nde_id),
                                        lst_node_state2str(dents[j].nde_state));
                                c++;
                        }
                }

                fprintf(stdout, "Total %d nodes [ %s ]\n", c, argv[i]);

                free(dents);
        }

        return rc;
}

int
lst_stat_ioctl(char *name, int count, struct lnet_process_id *idsp,
	       int timeout, struct list_head *resultp)
{
	struct lstio_stat_args args = { 0 };

	args.lstio_sta_key     = session_key;
	args.lstio_sta_timeout = timeout;
	args.lstio_sta_nmlen   = strlen(name);
	args.lstio_sta_namep   = name;
	args.lstio_sta_count   = count;
	args.lstio_sta_idsp    = idsp;
	args.lstio_sta_resultp = resultp;

	return lst_ioctl(LSTIO_STAT_QUERY, &args, sizeof(args));
}

typedef struct {
	struct list_head              srp_link;
        int                     srp_count;
        char                   *srp_name;
	struct lnet_process_id      *srp_ids;
	struct list_head              srp_result[2];
} lst_stat_req_param_t;

static void
lst_stat_req_param_free(lst_stat_req_param_t *srp)
{
        int     i;

        for (i = 0; i < 2; i++)
                lst_free_rpcent(&srp->srp_result[i]);

        if (srp->srp_ids != NULL)
                free(srp->srp_ids);

        free(srp);
}

static int
lst_stat_req_param_alloc(char *name, lst_stat_req_param_t **srpp, int save_old)
{
        lst_stat_req_param_t *srp = NULL;
        int                   count = save_old ? 2 : 1;
        int                   rc;
        int                   i;

        srp = malloc(sizeof(*srp));
        if (srp == NULL)
                return -ENOMEM;

        memset(srp, 0, sizeof(*srp));
	INIT_LIST_HEAD(&srp->srp_result[0]);
	INIT_LIST_HEAD(&srp->srp_result[1]);

        rc = lst_get_node_count(LST_OPC_GROUP, name,
                                &srp->srp_count, NULL);
        if (rc != 0 && errno == ENOENT) {
                rc = lst_get_node_count(LST_OPC_NODES, name,
                                        &srp->srp_count, &srp->srp_ids);
        }

        if (rc != 0) {
                fprintf(stderr,
                        "Failed to get count of nodes from %s: %s\n",
                        name, strerror(errno));
                lst_stat_req_param_free(srp);

                return rc;
        }

	srp->srp_name = name;

	for (i = 0; i < count; i++) {
		rc = lst_alloc_rpcent(&srp->srp_result[i], srp->srp_count,
				      sizeof(struct sfw_counters)  +
				      sizeof(struct srpc_counters) +
				      sizeof(struct lnet_counters_common));
		if (rc != 0) {
			fprintf(stderr, "Out of memory\n");
			break;
		}
	}

	if (rc == 0) {
		*srpp = srp;
		return 0;
	}

	lst_stat_req_param_free(srp);

	return rc;
}

typedef struct {
        /* TODO */
        int foo;
} lst_srpc_stat_result;

#define LST_LNET_AVG    0
#define LST_LNET_MIN    1
#define LST_LNET_MAX    2

typedef struct {
        float           lnet_avg_sndrate;
        float           lnet_min_sndrate;
        float           lnet_max_sndrate;
        float           lnet_total_sndrate;

        float           lnet_avg_rcvrate;
        float           lnet_min_rcvrate;
        float           lnet_max_rcvrate;
        float           lnet_total_rcvrate;

        float           lnet_avg_sndperf;
        float           lnet_min_sndperf;
        float           lnet_max_sndperf;
        float           lnet_total_sndperf;

        float           lnet_avg_rcvperf;
        float           lnet_min_rcvperf;
        float           lnet_max_rcvperf;
        float           lnet_total_rcvperf;

        int             lnet_stat_count;
} lst_lnet_stat_result_t;

lst_lnet_stat_result_t lnet_stat_result;

static float
lst_lnet_stat_value(int bw, int send, int off)
{
        float  *p;

        p = bw ? &lnet_stat_result.lnet_avg_sndperf :
                 &lnet_stat_result.lnet_avg_sndrate;

        if (!send)
                p += 4;

        p += off;

        return *p;
}

static void
lst_cal_lnet_stat(float delta, struct lnet_counters_common *lnet_new,
		  struct lnet_counters_common *lnet_old, int mbs)
{
	float perf;
	float rate;
	unsigned int unit_divisor;

	unit_divisor = (mbs) ? (1000 * 1000) : (1024 * 1024);
	perf = (float)(lnet_new->lcc_send_length -
		       lnet_old->lcc_send_length) / unit_divisor / delta;
	lnet_stat_result.lnet_total_sndperf += perf;

	if (lnet_stat_result.lnet_min_sndperf > perf ||
	    lnet_stat_result.lnet_min_sndperf == 0)
		lnet_stat_result.lnet_min_sndperf = perf;

	if (lnet_stat_result.lnet_max_sndperf < perf)
		lnet_stat_result.lnet_max_sndperf = perf;

	perf = (float)(lnet_new->lcc_recv_length -
		       lnet_old->lcc_recv_length) / unit_divisor / delta;
	lnet_stat_result.lnet_total_rcvperf += perf;

	if (lnet_stat_result.lnet_min_rcvperf > perf ||
	    lnet_stat_result.lnet_min_rcvperf == 0)
		lnet_stat_result.lnet_min_rcvperf = perf;

	if (lnet_stat_result.lnet_max_rcvperf < perf)
		lnet_stat_result.lnet_max_rcvperf = perf;

	rate = (lnet_new->lcc_send_count - lnet_old->lcc_send_count) / delta;
	lnet_stat_result.lnet_total_sndrate += rate;

	if (lnet_stat_result.lnet_min_sndrate > rate ||
	    lnet_stat_result.lnet_min_sndrate == 0)
		lnet_stat_result.lnet_min_sndrate = rate;

	if (lnet_stat_result.lnet_max_sndrate < rate)
		lnet_stat_result.lnet_max_sndrate = rate;

	rate = (lnet_new->lcc_recv_count - lnet_old->lcc_recv_count) / delta;
	lnet_stat_result.lnet_total_rcvrate += rate;

	if (lnet_stat_result.lnet_min_rcvrate > rate ||
	    lnet_stat_result.lnet_min_rcvrate == 0)
		lnet_stat_result.lnet_min_rcvrate = rate;

	if (lnet_stat_result.lnet_max_rcvrate < rate)
		lnet_stat_result.lnet_max_rcvrate = rate;

	lnet_stat_result.lnet_stat_count++;

	lnet_stat_result.lnet_avg_sndrate = lnet_stat_result.lnet_total_sndrate /
					    lnet_stat_result.lnet_stat_count;
	lnet_stat_result.lnet_avg_rcvrate = lnet_stat_result.lnet_total_rcvrate /
					    lnet_stat_result.lnet_stat_count;

	lnet_stat_result.lnet_avg_sndperf = lnet_stat_result.lnet_total_sndperf /
					    lnet_stat_result.lnet_stat_count;
	lnet_stat_result.lnet_avg_rcvperf = lnet_stat_result.lnet_total_rcvperf /
					    lnet_stat_result.lnet_stat_count;
}

static void
lst_print_lnet_stat(char *name, int bwrt, int rdwr, int type, int mbs)
{
	int	start1 = 0;
	int	end1   = 1;
	int	start2 = 0;
	int	end2   = 1;
	int	i;
	int	j;
	char   *units;

	if (lnet_stat_result.lnet_stat_count == 0)
		return;

	units = (mbs) ? "MB/s  " : "MiB/s ";

	if (bwrt == 1) /* bw only */
		start1 = 1;

	if (bwrt == 2) /* rates only */
		end1 = 0;

	if (rdwr == 1) /* recv only */
		start2 = 1;

	if (rdwr == 2) /* send only */
		end2 = 0;

	for (i = start1; i <= end1; i++) {
		fprintf(stdout, "[LNet %s of %s]\n",
			i == 0 ? "Rates" : "Bandwidth", name);

		for (j = start2; j <= end2; j++) {
			fprintf(stdout, "[%c] ", j == 0 ? 'R' : 'W');

			if ((type & 1) != 0) {
				fprintf(stdout, i == 0 ? "Avg: %-8.0f RPC/s " :
							 "Avg: %-8.2f %s",
					lst_lnet_stat_value(i, j, 0), units);
			}

			if ((type & 2) != 0) {
				fprintf(stdout, i == 0 ? "Min: %-8.0f RPC/s " :
							 "Min: %-8.2f %s",
					lst_lnet_stat_value(i, j, 1), units);
			}

			if ((type & 4) != 0) {
				fprintf(stdout, i == 0 ? "Max: %-8.0f RPC/s" :
							 "Max: %-8.2f %s",
					lst_lnet_stat_value(i, j, 2), units);
			}

			fprintf(stdout, "\n");
		}
	}
}

static void
lst_print_stat(char *name, struct list_head *resultp,
	       int idx, int lnet, int bwrt, int rdwr, int type,
	       int mbs)
{
	struct list_head tmp[2];
	struct lstcon_rpc_ent *new;
	struct lstcon_rpc_ent *old;
	struct sfw_counters *sfwk_new;
	struct sfw_counters *sfwk_old;
	struct srpc_counters *srpc_new;
	struct srpc_counters *srpc_old;
	struct lnet_counters_common *lnet_new;
	struct lnet_counters_common *lnet_old;
	float delta;
	int errcount = 0;

	INIT_LIST_HEAD(&tmp[0]);
	INIT_LIST_HEAD(&tmp[1]);

        memset(&lnet_stat_result, 0, sizeof(lnet_stat_result));

	while (!list_empty(&resultp[idx])) {
		if (list_empty(&resultp[1 - idx])) {
                        fprintf(stderr, "Group is changed, re-run stat\n");
                        break;
                }

		new = list_entry(resultp[idx].next, struct lstcon_rpc_ent,
                                     rpe_link);
		old = list_entry(resultp[1 - idx].next, struct lstcon_rpc_ent,
                                     rpe_link);

                /* first time get stats result, can't calculate diff */
                if (new->rpe_peer.nid == LNET_NID_ANY)
                        break;

                if (new->rpe_peer.nid != old->rpe_peer.nid ||
                    new->rpe_peer.pid != old->rpe_peer.pid) {
                        /* Something wrong. i.e, somebody change the group */
                        break;
                }

		list_move_tail(&new->rpe_link, &tmp[idx]);

		list_move_tail(&old->rpe_link, &tmp[1 - idx]);

                if (new->rpe_rpc_errno != 0 || new->rpe_fwk_errno != 0 ||
                    old->rpe_rpc_errno != 0 || old->rpe_fwk_errno != 0) {
                        errcount ++;
                        continue;
                }

		sfwk_new = (struct sfw_counters *)&new->rpe_payload[0];
		sfwk_old = (struct sfw_counters *)&old->rpe_payload[0];

		srpc_new = (struct srpc_counters *)((char *)sfwk_new +
						    sizeof(*sfwk_new));
		srpc_old = (struct srpc_counters *)((char *)sfwk_old +
						    sizeof(*sfwk_old));

		lnet_new = (struct lnet_counters_common *)((char *)srpc_new +
							   sizeof(*srpc_new));
		lnet_old = (struct lnet_counters_common *)((char *)srpc_old +
							   sizeof(*srpc_old));

		/* Prior to version 2.3, the running_ms was a counter for
		 * the number of running tests. Since 2.3, running_ms is
		 * changed to hold the millisecond since the start of
		 * the work item. The rpe_stamp field was formerly used,
		 * but is no longer. In 2.12 rpe_stamp was changed to
		 * struct timespec64 and has nanosecond resolution, in
		 * case it is needed in the future.
		 */
		delta = (float)(sfwk_new->running_ms -
				sfwk_old->running_ms) / 1000;

		if (!lnet) /* TODO */
			continue;

		lst_cal_lnet_stat(delta, lnet_new, lnet_old, mbs);
	}

	list_splice(&tmp[idx], &resultp[idx]);
	list_splice(&tmp[1 - idx], &resultp[1 - idx]);

	if (errcount > 0)
		fprintf(stdout, "Failed to stat on %d nodes\n", errcount);

	if (!lnet)  /* TODO */
		return;

	lst_print_lnet_stat(name, bwrt, rdwr, type, mbs);
}

int
jt_lst_stat(int argc, char **argv)
{
	struct list_head	head;
	lst_stat_req_param_t *srp;
	time_t		      last    = 0;
	int		      optidx  = 0;
	int		      timeout = 5; /* default timeout, 5 sec */
	int		      delay   = 5; /* default delay, 5 sec */
	int		      count   = -1; /* run forever */
	int		      lnet    = 1; /* lnet stat by default */
	int		      bwrt    = 0;
	int		      rdwr    = 0;
	int		      type    = -1;
	int		      idx     = 0;
	int		      rc;
	int		      c;
	int		      mbs     = 0; /* report as MB/s */

	static const struct option stat_opts[] = {
		{ .name = "timeout", .has_arg = required_argument, .val = 't' },
		{ .name = "delay",   .has_arg = required_argument, .val = 'd' },
		{ .name = "count",   .has_arg = required_argument, .val = 'o' },
		{ .name = "lnet",    .has_arg = no_argument,	   .val = 'l' },
		{ .name = "rpc",     .has_arg = no_argument,       .val = 'c' },
		{ .name = "bw",      .has_arg = no_argument,       .val = 'b' },
		{ .name = "rate",    .has_arg = no_argument,       .val = 'a' },
		{ .name = "read",    .has_arg = no_argument,       .val = 'r' },
		{ .name = "write",   .has_arg = no_argument,       .val = 'w' },
		{ .name = "avg",     .has_arg = no_argument,       .val = 'g' },
		{ .name = "min",     .has_arg = no_argument,       .val = 'n' },
		{ .name = "max",     .has_arg = no_argument,       .val = 'x' },
		{ .name = "mbs",     .has_arg = no_argument,       .val = 'm' },
		{ .name = NULL } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
		c = getopt_long(argc, argv, "t:d:lcbarwgnxm", stat_opts,
				&optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 't':
                        timeout = atoi(optarg);
                        break;
                case 'd':
                        delay = atoi(optarg);
                        break;
                case 'o':
                        count = atoi(optarg);
                        break;
                case 'l':
                        lnet = 1;
                        break;
                case 'c':
                        lnet = 0;
                        break;
                case 'b':
                        bwrt |= 1;
                        break;
                case 'a':
                        bwrt |= 2;
                        break;
                case 'r':
                        rdwr |= 1;
                        break;
                case 'w':
                        rdwr |= 2;
                        break;
                case 'g':
                        if (type == -1) {
                                type = 1;
                                break;
                        }
                        type |= 1;
                        break;
                case 'n':
                        if (type == -1) {
                                type = 2;
                                break;
                        }
                        type |= 2;
                        break;
		case 'x':
			if (type == -1) {
				type = 4;
				break;
			}
			type |= 4;
			break;
		case 'm':
			mbs = 1;
			break;

		default:
			lst_print_usage(argv[0]);
			return -1;
		}
	}

        if (optind == argc) {
                lst_print_usage(argv[0]);
                return -1;
        }

        if (timeout <= 0 || delay <= 0) {
                fprintf(stderr, "Invalid timeout or delay value\n");
                return -1;
        }

        if (count < -1) {
            fprintf(stderr, "Invalid count value\n");
            return -1;
        }

        /* extra count to get first data point */
        if (count != -1)
            count++;

	INIT_LIST_HEAD(&head);

        while (optind < argc) {
                rc = lst_stat_req_param_alloc(argv[optind++], &srp, 1);
                if (rc != 0)
                        goto out;

		list_add_tail(&srp->srp_link, &head);
        }

        do {
                time_t  now = time(NULL);

                if (now - last < delay) {
                        sleep(delay - now + last);
                        time(&now);
                }
		last = now;

		list_for_each_entry(srp, &head, srp_link) {
                        rc = lst_stat_ioctl(srp->srp_name,
                                            srp->srp_count, srp->srp_ids,
                                            timeout, &srp->srp_result[idx]);
                        if (rc == -1) {
                                lst_print_error("stat", "Failed to stat %s: %s\n",
                                                srp->srp_name, strerror(errno));
                                goto out;
                        }

			lst_print_stat(srp->srp_name, srp->srp_result,
				       idx, lnet, bwrt, rdwr, type, mbs);

			lst_reset_rpcent(&srp->srp_result[1 - idx]);
		}

                idx = 1 - idx;

                if (count > 0)
                        count--;
        } while (count == -1 || count > 0);

out:
	while (!list_empty(&head)) {
		srp = list_entry(head.next, lst_stat_req_param_t, srp_link);

		list_del(&srp->srp_link);
                lst_stat_req_param_free(srp);
        }

        return rc;
}

int
jt_lst_show_error(int argc, char **argv)
{
	struct list_head       head;
	lst_stat_req_param_t  *srp;
	struct lstcon_rpc_ent *ent;
	struct sfw_counters   *sfwk;
	struct srpc_counters  *srpc;
	int		       show_rpc = 1;
	int		       optidx = 0;
	int		       rc = 0;
	int		       ecount;
	int		       c;

	static const struct option show_error_opts[] = {
		{ .name = "session", .has_arg = no_argument, .val = 's' },
		{ .name = NULL, } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "s", show_error_opts, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 's':
                        show_rpc  = 0;
                        break;

                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (optind == argc) {
                lst_print_usage(argv[0]);
                return -1;
        }

	INIT_LIST_HEAD(&head);

        while (optind < argc) {
                rc = lst_stat_req_param_alloc(argv[optind++], &srp, 0);
                if (rc != 0)
                        goto out;

		list_add_tail(&srp->srp_link, &head);
        }

	list_for_each_entry(srp, &head, srp_link) {
                rc = lst_stat_ioctl(srp->srp_name, srp->srp_count,
                                    srp->srp_ids, 10, &srp->srp_result[0]);

                if (rc == -1) {
                        lst_print_error(srp->srp_name, "Failed to show errors of %s: %s\n",
                                        srp->srp_name, strerror(errno));
                        goto out;
                }

                fprintf(stdout, "%s:\n", srp->srp_name);

                ecount = 0;

		list_for_each_entry(ent, &srp->srp_result[0], rpe_link) {
                        if (ent->rpe_rpc_errno != 0) {
                                ecount ++;
                                fprintf(stderr, "RPC failure, can't show error on %s\n",
                                        libcfs_id2str(ent->rpe_peer));
                                continue;
                        }

                        if (ent->rpe_fwk_errno != 0) {
                                ecount ++;
                                fprintf(stderr, "Framework failure, can't show error on %s\n",
                                        libcfs_id2str(ent->rpe_peer));
                                continue;
                        }

			sfwk = (struct sfw_counters *)&ent->rpe_payload[0];
			srpc = (struct srpc_counters *)((char *)sfwk + sizeof(*sfwk));

                        if (srpc->errors == 0 &&
                            sfwk->brw_errors == 0 && sfwk->ping_errors == 0)
                                continue;

                        if (!show_rpc  &&
                            sfwk->brw_errors == 0 && sfwk->ping_errors == 0)
                                continue;

                        ecount ++;

                        fprintf(stderr, "%s: [Session %d brw errors, %d ping errors]%c",
                                libcfs_id2str(ent->rpe_peer),
                                sfwk->brw_errors, sfwk->ping_errors,
                                show_rpc  ? ' ' : '\n');

                        if (!show_rpc)
                                continue;

                        fprintf(stderr, "[RPC: %d errors, %d dropped, %d expired]\n",
                                srpc->errors, srpc->rpcs_dropped, srpc->rpcs_expired);
                }

                fprintf(stdout, "Total %d error nodes in %s\n", ecount, srp->srp_name);
        }
out:
	while (!list_empty(&head)) {
		srp = list_entry(head.next, lst_stat_req_param_t, srp_link);

		list_del(&srp->srp_link);
                lst_stat_req_param_free(srp);
        }

        return rc;
}

int
lst_add_batch_ioctl(char *name)
{
	struct lstio_batch_add_args args = { 0 };

        args.lstio_bat_key   = session_key;
        args.lstio_bat_nmlen = strlen(name);
        args.lstio_bat_namep = name;

        return lst_ioctl (LSTIO_BATCH_ADD, &args, sizeof(args));
}

int
jt_lst_add_batch(int argc, char **argv)
{
        char   *name;
        int     rc;

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        if (argc != 2) {
                lst_print_usage(argv[0]);
                return -1;
        }

        name = argv[1];
        if (strlen(name) >= LST_NAME_SIZE) {
                fprintf(stderr, "Name length is limited to %d\n",
                        LST_NAME_SIZE - 1);
                return -1;
        }

        rc = lst_add_batch_ioctl(name);
        if (rc == 0)
                return 0;

        lst_print_error("batch", "Failed to create batch: %s\n",
                        strerror(errno));

        return -1;
}

int
lst_start_batch_ioctl(char *name, int timeout, struct list_head *resultp)
{
	struct lstio_batch_run_args args = { 0 };

        args.lstio_bat_key     = session_key;
        args.lstio_bat_timeout = timeout;
        args.lstio_bat_nmlen   = strlen(name);
        args.lstio_bat_namep   = name;
        args.lstio_bat_resultp = resultp;

        return lst_ioctl(LSTIO_BATCH_START, &args, sizeof(args));
}

int
jt_lst_start_batch(int argc, char **argv)
{
	struct list_head  head;
	char             *batch;
	int               optidx = 0;
	int               timeout = 0;
	int               count = 0;
	int               rc;
	int               c;

	static const struct option start_batch_opts[] = {
		{ .name = "timeout", .has_arg = required_argument, .val = 't' },
		{ .name = NULL } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "t:",
                                start_batch_opts, &optidx);

                /* Detect the end of the options. */
                if (c == -1)
                        break;

                switch (c) {
                case 't':
                        timeout = atoi(optarg);
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (optind == argc) {
                batch = LST_DEFAULT_BATCH;

        } else if (optind == argc - 1) {
                batch = argv[optind];

        } else {
                lst_print_usage(argv[0]);
                return -1;
        }

        rc = lst_get_node_count(LST_OPC_BATCHCLI, batch, &count, NULL);
        if (rc != 0) {
                fprintf(stderr, "Failed to get count of nodes from %s: %s\n",
                        batch, strerror(errno));
                return -1;
        }

	INIT_LIST_HEAD(&head);

        rc = lst_alloc_rpcent(&head, count, 0);
        if (rc != 0) {
                fprintf(stderr, "Out of memory\n");
                return -1;
        }

        rc = lst_start_batch_ioctl(batch, timeout, &head);

        if (rc == 0) {
                fprintf(stdout, "%s is running now\n", batch);
                lst_free_rpcent(&head);
                return 0;
        }

        if (rc == -1) {
                lst_print_error("batch", "Failed to start batch: %s\n",
                                strerror(errno));
                lst_free_rpcent(&head);
                return rc;
        }

        lst_print_transerr(&head, "Run batch");

        lst_free_rpcent(&head);

        return rc;
}

int
lst_stop_batch_ioctl(char *name, int force, struct list_head *resultp)
{
	struct lstio_batch_stop_args args = { 0 };

        args.lstio_bat_key     = session_key;
        args.lstio_bat_force   = force;
        args.lstio_bat_nmlen   = strlen(name);
        args.lstio_bat_namep   = name;
        args.lstio_bat_resultp = resultp;

        return lst_ioctl(LSTIO_BATCH_STOP, &args, sizeof(args));
}

int
jt_lst_stop_batch(int argc, char **argv)
{
	struct list_head  head;
	char             *batch;
	int               force = 0;
	int               optidx;
	int               count;
	int               rc;
	int               c;

	static const struct option stop_batch_opts[] = {
		{ .name = "force", .has_arg = no_argument, .val = 'f' },
		{ .name = NULL } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "f",
                                stop_batch_opts, &optidx);

                /* Detect the end of the options. */
                if (c == -1)
                        break;

                switch (c) {
                case 'f':
                        force = 1;
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (optind == argc) {
                batch = LST_DEFAULT_BATCH;

        } else if (optind == argc - 1) {
                batch = argv[optind];

        } else {
                lst_print_usage(argv[0]);
                return -1;
        }

        rc = lst_get_node_count(LST_OPC_BATCHCLI, batch, &count, NULL);
        if (rc != 0) {
                fprintf(stderr, "Failed to get count of nodes from %s: %s\n",
                        batch, strerror(errno));
                return -1;
        }

	INIT_LIST_HEAD(&head);

        rc = lst_alloc_rpcent(&head, count, 0);
        if (rc != 0) {
                fprintf(stderr, "Out of memory\n");
                return -1;
        }

        rc = lst_stop_batch_ioctl(batch, force, &head);
        if (rc != 0)
                goto out;

        while (1) {
                lst_reset_rpcent(&head);

                rc = lst_query_batch_ioctl(batch, 0, 0, 30, &head);
                if (rc != 0)
                        goto out;

                if (lstcon_tsbqry_stat_run(&trans_stat, 0)  == 0 &&
                    lstcon_tsbqry_stat_failure(&trans_stat, 0) == 0)
                        break;

                fprintf(stdout, "%d batch in stopping\n",
                        lstcon_tsbqry_stat_run(&trans_stat, 0));
                sleep(1);
        }

        fprintf(stdout, "Batch is stopped\n");
        lst_free_rpcent(&head);

        return 0;
out:
        if (rc == -1) {
                lst_print_error("batch", "Failed to stop batch: %s\n",
                                strerror(errno));
                lst_free_rpcent(&head);
                return -1;
        }

        lst_print_transerr(&head, "stop batch");

        lst_free_rpcent(&head);

        return rc;
}

int
lst_list_batch_ioctl(int len, char *name, int index)
{
	struct lstio_batch_list_args args = { 0 };

        args.lstio_bat_key   = session_key;
        args.lstio_bat_idx   = index;
        args.lstio_bat_nmlen = len;
        args.lstio_bat_namep = name;

        return lst_ioctl(LSTIO_BATCH_LIST, &args, sizeof(args));
}

int
lst_info_batch_ioctl(char *batch, int test, int server,
		     struct lstcon_test_batch_ent *entp, int *idxp,
		     int *ndentp, struct lstcon_node_ent *dentsp)
{
	struct lstio_batch_info_args args = { 0 };

        args.lstio_bat_key     = session_key;
        args.lstio_bat_nmlen   = strlen(batch);
        args.lstio_bat_namep   = batch;
        args.lstio_bat_server  = server;
        args.lstio_bat_testidx = test;
        args.lstio_bat_entp    = entp;
        args.lstio_bat_idxp    = idxp;
        args.lstio_bat_ndentp  = ndentp;
        args.lstio_bat_dentsp  = dentsp;

        return lst_ioctl(LSTIO_BATCH_INFO, &args, sizeof(args));
}

int
lst_list_batch_all(void)
{
        char name[LST_NAME_SIZE];
        int  rc;
        int  i;

        for (i = 0; ; i++) {
                rc = lst_list_batch_ioctl(LST_NAME_SIZE, name, i);
                if (rc == 0) {
                        fprintf(stdout, "%d) %s\n", i + 1, name);
                        continue;
                }

                if (errno == ENOENT)
                        break;

                lst_print_error("batch", "Failed to list batch: %s\n",
                                strerror(errno));
                return rc;
        }

        fprintf(stdout, "Total %d batches\n", i);

        return 0;
}

int
lst_list_tsb_nodes(char *batch, int test, int server,
                   int count, int active, int invalid)
{
	struct lstcon_node_ent *dents;
        int                index = 0;
        int                rc;
        int                c;
        int                i;

        if (count == 0)
                return 0;

        /* verbose list, show nodes in batch or test */
	dents = malloc(count * sizeof(struct lstcon_node_ent));
        if (dents == NULL) {
                fprintf(stdout, "Can't allocate memory\n");
                return -1;
        }

        rc = lst_info_batch_ioctl(batch, test, server,
                                  NULL, &index, &count, dents);
        if (rc != 0) {
                free(dents);
                lst_print_error((test > 0) ? "test" : "batch",
                                (test > 0) ? "Failed to query test: %s\n" :
                                             "Failed to query batch: %s\n",
                                strerror(errno));
                return -1;
        }

        for (i = 0, c = 0; i < count; i++) {
                if ((!active  && dents[i].nde_state == LST_NODE_ACTIVE) ||
                    (!invalid && (dents[i].nde_state == LST_NODE_BUSY  ||
                                  dents[i].nde_state == LST_NODE_DOWN  ||
                                  dents[i].nde_state == LST_NODE_UNKNOWN)))
                        continue;

                fprintf(stdout, "\t%s: %s\n",
                        libcfs_id2str(dents[i].nde_id),
                        lst_node_state2str(dents[i].nde_state));
                c++;
        }

        fprintf(stdout, "Total %d nodes\n", c);
        free(dents);

        return 0;
}

int
jt_lst_list_batch(int argc, char **argv)
{
	struct lstcon_test_batch_ent ent;
	char *batch   = NULL;
	int   optidx  = 0;
	int   verbose = 0; /* list nodes in batch or test */
	int   invalid = 0;
	int   active  = 0;
	int   server  = 0;
	int   ntest   = 0;
	int   test    = 0;
	int   c       = 0;
	int   rc;

	static const struct option list_batch_opts[] = {
		{ .name = "test",    .has_arg = required_argument, .val = 't' },
		{ .name = "invalid", .has_arg = no_argument,	   .val = 'i' },
		{ .name = "active",  .has_arg = no_argument,	   .val = 'a' },
		{ .name = "all",     .has_arg = no_argument,	   .val = 'l' },
		{ .name = "server",  .has_arg = no_argument,	   .val = 's' },
		{ .name = NULL, } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "ailst:",
                                list_batch_opts, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 'a':
                        verbose = active = 1;
                        break;
                case 'i':
                        verbose = invalid = 1;
                        break;
                case 'l':
                        verbose = active = invalid = 1;
                        break;
                case 's':
                        server = 1;
                        break;
                case 't':
                        test = atoi(optarg);
                        ntest = 1;
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (optind == argc) {
                /* list all batches */
                rc = lst_list_batch_all();
                return rc;
        }

        if (ntest == 1 && test <= 0) {
                fprintf(stderr, "Invalid test id, test id starts from 1\n");
                return -1;
        }

        if (optind != argc - 1) {
                lst_print_usage(argv[0]);
                return -1;
        }

        batch = argv[optind];

loop:
        /* show detail of specified batch or test */
        rc = lst_info_batch_ioctl(batch, test, server,
                                  &ent, NULL, NULL, NULL);
        if (rc != 0) {
                lst_print_error((test > 0) ? "test" : "batch",
                                (test > 0) ? "Failed to query test: %s\n" :
                                             "Failed to query batch: %s\n",
                                strerror(errno));
                return -1;
        }

        if (verbose) {
                /* list nodes in test or batch */
                rc = lst_list_tsb_nodes(batch, test, server,
                                        server ? ent.tbe_srv_nle.nle_nnode :
                                                 ent.tbe_cli_nle.nle_nnode,
                                        active, invalid);
                return rc;
        }

        /* only show number of hosts in batch or test */
        if (test == 0) {
                fprintf(stdout, "Batch: %s Tests: %d State: %d\n",
                        batch, ent.u.tbe_batch.bae_ntest,
                        ent.u.tbe_batch.bae_state);
                ntest = ent.u.tbe_batch.bae_ntest;
                test = 1; /* starting from test 1 */

        } else {
                fprintf(stdout,
                        "\tTest %d(%s) (loop: %d, concurrency: %d)\n",
                        test, lst_test_type2name(ent.u.tbe_test.tse_type),
                        ent.u.tbe_test.tse_loop,
                        ent.u.tbe_test.tse_concur);
                ntest --;
                test ++;
        }

        fprintf(stdout, LST_NODES_TITLE);
        fprintf(stdout, "client\t%d\t%d\t%d\t%d\t%d\n"
                        "server\t%d\t%d\t%d\t%d\t%d\n",
                ent.tbe_cli_nle.nle_nactive,
                ent.tbe_cli_nle.nle_nbusy,
                ent.tbe_cli_nle.nle_ndown,
                ent.tbe_cli_nle.nle_nunknown,
                ent.tbe_cli_nle.nle_nnode,
                ent.tbe_srv_nle.nle_nactive,
                ent.tbe_srv_nle.nle_nbusy,
                ent.tbe_srv_nle.nle_ndown,
                ent.tbe_srv_nle.nle_nunknown,
                ent.tbe_srv_nle.nle_nnode);

        if (ntest != 0)
                goto loop;

        return 0;
}

int
lst_query_batch_ioctl(char *batch, int test, int server,
		      int timeout, struct list_head *head)
{
	struct lstio_batch_query_args args = { 0 };

        args.lstio_bat_key     = session_key;
        args.lstio_bat_testidx = test;
        args.lstio_bat_client  = !(server);
        args.lstio_bat_timeout = timeout;
        args.lstio_bat_nmlen   = strlen(batch);
        args.lstio_bat_namep   = batch;
        args.lstio_bat_resultp = head;

        return lst_ioctl(LSTIO_BATCH_QUERY, &args, sizeof(args));
}

void
lst_print_tsb_verbose(struct list_head *head,
                      int active, int idle, int error)
{
	struct lstcon_rpc_ent *ent;

	list_for_each_entry(ent, head, rpe_link) {
                if (ent->rpe_priv[0] == 0 && active)
                        continue;

                if (ent->rpe_priv[0] != 0 && idle)
                        continue;

                if (ent->rpe_fwk_errno == 0 && error)
                        continue;

                fprintf(stdout, "%s [%s]: %s\n",
                        libcfs_id2str(ent->rpe_peer),
                        lst_node_state2str(ent->rpe_state),
                        ent->rpe_rpc_errno != 0 ?
                                strerror(ent->rpe_rpc_errno) :
                                (ent->rpe_priv[0] > 0 ? "Running" : "Idle"));
        }
}

int
jt_lst_query_batch(int argc, char **argv)
{
	struct lstcon_test_batch_ent ent;
	struct list_head head;
	char   *batch   = NULL;
	time_t  last    = 0;
	int     optidx  = 0;
	int     verbose = 0;
	int     server  = 0;
	int     timeout = 5; /* default 5 seconds */
	int     delay   = 5; /* default 5 seconds */
	int     loop    = 1; /* default 1 loop */
	int     active  = 0;
	int     error   = 0;
	int     idle    = 0;
	int     count   = 0;
	int     test    = 0;
	int     rc      = 0;
	int     c       = 0;
	int     i;

	static const struct option query_batch_opts[] = {
		{ .name = "timeout", .has_arg = required_argument, .val = 'o' },
		{ .name = "delay",   .has_arg = required_argument, .val = 'd' },
		{ .name = "loop",    .has_arg = required_argument, .val = 'c' },
		{ .name = "test",    .has_arg = required_argument, .val = 't' },
		{ .name = "server",  .has_arg = no_argument,	   .val = 's' },
		{ .name = "active",  .has_arg = no_argument,	   .val = 'a' },
		{ .name = "idle",    .has_arg = no_argument,	   .val = 'i' },
		{ .name = "error",   .has_arg = no_argument,	   .val = 'e' },
		{ .name = "all",     .has_arg = no_argument,	   .val = 'l' },
		{ .name = NULL, } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "o:d:c:t:saiel",
                                query_batch_opts, &optidx);

                /* Detect the end of the options. */
                if (c == -1)
                        break;

                switch (c) {
                case 'o':
                        timeout = atoi(optarg);
                        break;
                case 'd':
                        delay = atoi(optarg);
                        break;
                case 'c':
                        loop = atoi(optarg);
                        break;
                case 't':
                        test = atoi(optarg);
                        break;
                case 's':
                        server = 1;
                        break;
                case 'a':
                        active = verbose = 1;
                        break;
                case 'i':
                        idle = verbose = 1;
                        break;
                case 'e':
                        error = verbose = 1;
                        break;
                case 'l':
                        verbose = 1;
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (test < 0 || timeout <= 0 || delay <= 0 || loop <= 0) {
                lst_print_usage(argv[0]);
                return -1;
        }

        if (optind == argc) {
                batch = LST_DEFAULT_BATCH;

        } else if (optind == argc - 1) {
                batch = argv[optind];

        } else {
                lst_print_usage(argv[0]);
                return -1;
        }


	INIT_LIST_HEAD(&head);

        if (verbose) {
                rc = lst_info_batch_ioctl(batch, test, server,
                                          &ent, NULL, NULL, NULL);
                if (rc != 0) {
                        fprintf(stderr, "Failed to query %s [%d]: %s\n",
                                batch, test, strerror(errno));
                        return -1;
                }

                count = server ? ent.tbe_srv_nle.nle_nnode :
                                 ent.tbe_cli_nle.nle_nnode;
                if (count == 0) {
                        fprintf(stdout, "Batch or test is empty\n");
                        return 0;
                }
        }

        rc = lst_alloc_rpcent(&head, count, 0);
        if (rc != 0) {
                fprintf(stderr, "Out of memory\n");
                return rc;
        }

        for (i = 0; i < loop; i++) {
                time_t  now = time(NULL);

                if (now - last < delay) {
                        sleep(delay - now + last);
                        time(&now);
                }

                last = now;

                rc = lst_query_batch_ioctl(batch, test,
                                           server, timeout, &head);
                if (rc == -1) {
                        fprintf(stderr, "Failed to query batch: %s\n",
                                strerror(errno));
                        break;
                }

                if (verbose) {
                        /* Verbose mode */
                        lst_print_tsb_verbose(&head, active, idle, error);
                        continue;
                }

                fprintf(stdout, "%s [%d] ", batch, test);

                if (lstcon_rpc_stat_failure(&trans_stat, 0) != 0) {
                        fprintf(stdout, "%d of %d nodes are unknown, ",
                                lstcon_rpc_stat_failure(&trans_stat, 0),
                                lstcon_rpc_stat_total(&trans_stat, 0));
                }

                if (lstcon_rpc_stat_failure(&trans_stat, 0) == 0 &&
                    lstcon_tsbqry_stat_run(&trans_stat, 0)  == 0  &&
                    lstcon_tsbqry_stat_failure(&trans_stat, 0) == 0) {
                        fprintf(stdout, "is stopped\n");
                        continue;
                }

                if (lstcon_rpc_stat_failure(&trans_stat, 0) == 0 &&
                    lstcon_tsbqry_stat_idle(&trans_stat, 0) == 0 &&
                    lstcon_tsbqry_stat_failure(&trans_stat, 0) == 0) {
                        fprintf(stdout, "is running\n");
                        continue;
                }

                fprintf(stdout, "stopped: %d , running: %d, failed: %d\n",
                                lstcon_tsbqry_stat_idle(&trans_stat, 0),
                                lstcon_tsbqry_stat_run(&trans_stat, 0),
                                lstcon_tsbqry_stat_failure(&trans_stat, 0));
        }

        lst_free_rpcent(&head);

        return rc;
}

int
lst_parse_distribute(char *dstr, int *dist, int *span)
{
        *dist = atoi(dstr);
        if (*dist <= 0)
                return -1;

        dstr = strchr(dstr, ':');
        if (dstr == NULL)
                return -1;

        *span = atoi(dstr + 1);
        if (*span <= 0)
                return -1;

        return 0;
}

int
lst_get_bulk_param(int argc, char **argv, struct lst_test_bulk_param *bulk)
{
        char   *tok = NULL;
        char   *end = NULL;
        int     rc  = 0;
        int     i   = 0;

        bulk->blk_size  = 4096;
        bulk->blk_opc   = LST_BRW_READ;
        bulk->blk_flags = LST_BRW_CHECK_NONE;
	bulk->blk_srv_off = bulk->blk_cli_off = 0;

        while (i < argc) {
                if (strcasestr(argv[i], "check=") == argv[i] ||
                    strcasestr(argv[i], "c=") == argv[i]) {
                        tok = strchr(argv[i], '=') + 1;

                        if (strcasecmp(tok, "full") == 0) {
                                bulk->blk_flags = LST_BRW_CHECK_FULL;
                        } else if (strcasecmp(tok, "simple") == 0) {
                                bulk->blk_flags = LST_BRW_CHECK_SIMPLE;
                        } else {
                                fprintf(stderr, "Unknow flag %s\n", tok);
                                return -1;
                        }

		} else if (strcasestr(argv[i], "size=") == argv[i] ||
			   strcasestr(argv[i], "s=") == argv[i]) {
                        tok = strchr(argv[i], '=') + 1;

                        bulk->blk_size = strtol(tok, &end, 0);
                        if (bulk->blk_size <= 0) {
                                fprintf(stderr, "Invalid size %s\n", tok);
                                return -1;
                        }

                        if (end == NULL)
                                return 0;

                        if (*end == 'k' || *end == 'K')
                                bulk->blk_size *= 1024;
                        else if (*end == 'm' || *end == 'M')
                                bulk->blk_size *= 1024 * 1024;

			if (bulk->blk_size > LNET_MTU) {
                                fprintf(stderr, "Size exceed limitation: %d bytes\n",
                                        bulk->blk_size);
                                return -1;
                        }

		} else if (strcasestr(argv[i], "off=") == argv[i]) {
			int	off;

			tok = strchr(argv[i], '=') + 1;

			off = strtol(tok, &end, 0);
			/* NB: align with sizeof(__u64) to simplify page
			 * checking implementation */
			if (off < 0 || off % sizeof(__u64) != 0) {
				fprintf(stderr,
					"Invalid offset %s/%d, it should be "
					"postive value and multiple of %d\n",
					tok, off, (int)sizeof(__u64));
				return -1;
			}

			/* NB: blk_srv_off is reserved so far */
			bulk->blk_cli_off = bulk->blk_srv_off = off;
			if (end == NULL)
				return 0;

                } else if (strcasecmp(argv[i], "read") == 0 ||
                           strcasecmp(argv[i], "r") == 0) {
                        bulk->blk_opc = LST_BRW_READ;

                } else if (strcasecmp(argv[i], "write") == 0 ||
                           strcasecmp(argv[i], "w") == 0) {
                        bulk->blk_opc = LST_BRW_WRITE;

                } else {
                        fprintf(stderr, "Unknow parameter: %s\n", argv[i]);
                        return -1;
                }

                i++;
        }

        return rc;
}

int
lst_get_test_param(char *test, int argc, char **argv, void **param, int *plen)
{
	struct lst_test_bulk_param *bulk = NULL;
        int                    type;

        type = lst_test_name2type(test);
        if (type < 0) {
                fprintf(stderr, "Unknow test name %s\n", test);
                return -1;
        }

        switch (type) {
        case LST_TEST_PING:
                break;

        case LST_TEST_BULK:
                bulk = malloc(sizeof(*bulk));
                if (bulk == NULL) {
                        fprintf(stderr, "Out of memory\n");
                        return -1;
                }

                memset(bulk, 0, sizeof(*bulk));

                if (lst_get_bulk_param(argc, argv, bulk) != 0) {
                        free(bulk);
                        return -1;
                }

                *param = bulk;
                *plen  = sizeof(*bulk);

                break;

        default:
                break;
        }

        /* TODO: parse more parameter */
        return type;
}

int
lst_add_test_ioctl(char *batch, int type, int loop, int concur,
                   int dist, int span, char *sgrp, char *dgrp,
		   void *param, int plen, int *retp, struct list_head *resultp)
{
	struct lstio_test_args args = { 0 };

        args.lstio_tes_key        = session_key;
        args.lstio_tes_bat_nmlen  = strlen(batch);
        args.lstio_tes_bat_name   = batch;
        args.lstio_tes_type       = type;
        args.lstio_tes_oneside    = 0;
        args.lstio_tes_loop       = loop;
        args.lstio_tes_concur     = concur;
        args.lstio_tes_dist       = dist;
        args.lstio_tes_span       = span;
        args.lstio_tes_sgrp_nmlen = strlen(sgrp);
        args.lstio_tes_sgrp_name  = sgrp;
        args.lstio_tes_dgrp_nmlen = strlen(dgrp);
        args.lstio_tes_dgrp_name  = dgrp;
        args.lstio_tes_param_len  = plen;
        args.lstio_tes_param      = param;
        args.lstio_tes_retp       = retp;
        args.lstio_tes_resultp    = resultp;

        return lst_ioctl(LSTIO_TEST_ADD, &args, sizeof(args));
}

int
jt_lst_add_test(int argc, char **argv)
{
	struct list_head head;
	char *batch  = NULL;
	char *test   = NULL;
	char *dstr   = NULL;
	char *from   = NULL;
	char *to     = NULL;
	void *param  = NULL;
	int   optidx = 0;
	int   concur = 1;
	int   loop   = -1;
	int   dist   = 1;
	int   span   = 1;
	int   plen   = 0;
	int   fcount = 0;
	int   tcount = 0;
	int   ret    = 0;
	int   type;
	int   rc;
	int   c;

	static const struct option add_test_opts[] = {
	{ .name = "batch",	 .has_arg = required_argument, .val = 'b' },
	{ .name = "concurrency", .has_arg = required_argument, .val = 'c' },
	{ .name = "distribute",	 .has_arg = required_argument, .val = 'd' },
	{ .name = "from",	 .has_arg = required_argument, .val = 'f' },
	{ .name = "to",		 .has_arg = required_argument, .val = 't' },
	{ .name = "loop",	 .has_arg = required_argument, .val = 'l' },
	{ .name = NULL } };

        if (session_key == 0) {
                fprintf(stderr,
                        "Can't find env LST_SESSION or value is not valid\n");
                return -1;
        }

        while (1) {
                c = getopt_long(argc, argv, "b:c:d:f:l:t:",
                                add_test_opts, &optidx);

                /* Detect the end of the options. */
                if (c == -1)
                        break;

                switch (c) {
                case 'b':
                        batch = optarg;
                        break;
                case 'c':
                        concur = atoi(optarg);
                        break;
                case 'd':
                        dstr = optarg;
                        break;
                case 'f':
                        from = optarg;
                        break;
                case 'l':
                        loop = atoi(optarg);
                        break;
                case 't':
                        to = optarg;
                        break;
                default:
                        lst_print_usage(argv[0]);
                        return -1;
                }
        }

        if (optind == argc || from == NULL || to == NULL) {
                lst_print_usage(argv[0]);
                return -1;
        }

        if (concur <= 0 || concur > LST_MAX_CONCUR) {
                fprintf(stderr, "Invalid concurrency of test: %d\n", concur);
                return -1;
        }

        if (batch == NULL)
                batch = LST_DEFAULT_BATCH;

        if (dstr != NULL) {
                rc = lst_parse_distribute(dstr, &dist, &span);
                if (rc != 0) {
                        fprintf(stderr, "Invalid distribution: %s\n", dstr);
                        return -1;
                }
        }

        test = argv[optind++];

        argc -= optind;
        argv += optind;

        type = lst_get_test_param(test, argc, argv, &param, &plen);
        if (type < 0) {
                fprintf(stderr, "Failed to add test (%s)\n", test);
                return -1;
        }

	INIT_LIST_HEAD(&head);

        rc = lst_get_node_count(LST_OPC_GROUP, from, &fcount, NULL);
        if (rc != 0) {
                fprintf(stderr, "Can't get count of nodes from %s: %s\n",
                        from, strerror(errno));
                goto out;
        }

        rc = lst_get_node_count(LST_OPC_GROUP, to, &tcount, NULL);
        if (rc != 0) {
                fprintf(stderr, "Can't get count of nodes from %s: %s\n",
                        to, strerror(errno));
                goto out;
        }

        rc = lst_alloc_rpcent(&head, fcount > tcount ? fcount : tcount, 0);
        if (rc != 0) {
                fprintf(stderr, "Out of memory\n");
                goto out;
        }

        rc = lst_add_test_ioctl(batch, type, loop, concur,
                                dist, span, from, to, param, plen, &ret, &head);

        if (rc == 0) {
                fprintf(stdout, "Test was added successfully\n");
                if (ret != 0) {
                        fprintf(stdout, "Server group contains userland test "
                                "nodes, old version of tcplnd can't accept "
                                "connection request\n");
                }

                goto out;
        }

        if (rc == -1) {
                lst_print_error("test", "Failed to add test: %s\n",
                                strerror(errno));
                goto out;
        }

        lst_print_transerr(&head, "add test");
out:
        lst_free_rpcent(&head);

        if (param != NULL)
                free(param);

        return rc;
}

static command_t lst_cmdlist[] = {
	{"new_session",		jt_lst_new_session,	NULL,
         "Usage: lst new_session [--timeout TIME] [--force] [NAME]"	                },
	{"end_session",		jt_lst_end_session,	NULL,
         "Usage: lst end_session"	                                                },
        {"show_session",        jt_lst_show_session,    NULL,
         "Usage: lst show_session"                                                      },
        {"ping",                jt_lst_ping ,           NULL,
         "Usage: lst ping  [--group NAME] [--batch NAME] [--session] [--nodes IDS]"     },
	{"add_group",		jt_lst_add_group,	NULL,
         "Usage: lst group NAME IDs [IDs]..."                                           },
        {"del_group",           jt_lst_del_group,       NULL,
         "Usage: lst del_group NAME"                                                    },
        {"update_group",        jt_lst_update_group,    NULL,
         "Usage: lst update_group NAME [--clean] [--refresh] [--remove IDs]"            },
        {"list_group",          jt_lst_list_group,      NULL,
          "Usage: lst list_group [--active] [--busy] [--down] [--unknown] GROUP ..."    },
	{"stat",                jt_lst_stat,            NULL,
	 "Usage: lst stat [--bw] [--rate] [--read] [--write] [--max] [--min] [--avg] "
	 " [--mbs] [--timeout #] [--delay #] [--count #] GROUP [GROUP]"                 },
        {"show_error",          jt_lst_show_error,      NULL,
         "Usage: lst show_error NAME | IDS ..."                                         },
        {"add_batch",           jt_lst_add_batch,       NULL,
         "Usage: lst add_batch NAME"                                                    },
        {"run",                 jt_lst_start_batch,     NULL,
         "Usage: lst run [--timeout TIME] [NAME]"                                       },
        {"stop",                jt_lst_stop_batch,      NULL,
         "Usage: lst stop [--force] BATCH_NAME"                                         },
        {"list_batch",          jt_lst_list_batch,      NULL,
         "Usage: lst list_batch NAME [--test ID] [--server]"                            },
        {"query",               jt_lst_query_batch,     NULL,
         "Usage: lst query [--test ID] [--server] [--timeout TIME] NAME"                },
        {"add_test",            jt_lst_add_test,        NULL,
         "Usage: lst add_test [--batch BATCH] [--loop #] [--concurrency #] "
         " [--distribute #:#] [--from GROUP] [--to GROUP] TEST..."                      },
        {"help",                Parser_help,            0,     "help"                   },
	{"--list-commands",     lst_list_commands,      0,     "list commands"          },
        {0,                     0,                      0,      NULL                    }
};

int
lst_initialize(void)
{
	char   *key;
	char   *feats;

	feats = getenv("LST_FEATURES");
	if (feats != NULL)
		session_features = strtol(feats, NULL, 16);

	if ((session_features & ~LST_FEATS_MASK) != 0) {
		fprintf(stderr,
			"Unsupported session features %x, "
			"only support these features so far: %x\n",
			(session_features & ~LST_FEATS_MASK), LST_FEATS_MASK);
		return -1;
	}

        key = getenv("LST_SESSION");

        if (key == NULL) {
                session_key = 0;
                return 0;
        }

        session_key = atoi(key);

        return 0;
}

static int lst_list_commands(int argc, char **argv)
{
	char buffer[81] = ""; /* 80 printable chars + terminating NUL */

	Parser_list_commands(lst_cmdlist, buffer, sizeof(buffer), NULL, 0, 4);

	return 0;
}

int
main(int argc, char **argv)
{
        int rc = 0;

        setlinebuf(stdout);

        rc = lst_initialize();
        if (rc < 0)
                goto errorout;

	rc = lustre_lnet_config_lib_init();
	if (rc < 0)
		goto errorout;

        Parser_init("lst > ", lst_cmdlist);

        if (argc != 1)  {
                rc = Parser_execarg(argc - 1, argv + 1, lst_cmdlist);
                goto errorout;
        }

        Parser_commands();

errorout:
        return rc;
}
