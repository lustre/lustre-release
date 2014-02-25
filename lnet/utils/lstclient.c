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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lnet/selftest/conctl.c
 *
 * Author: Liang Zhen <liangzhen@clusterfs.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>
#include <lnet/lnetctl.h>
#include <lnet/lnetst.h>
#include "../selftest/rpc.h"
#include "../selftest/selftest.h"

static int lstjn_stopping = 0;
static int lstjn_intialized = 0;


static struct option lstjn_options[] =
{
        {"sesid",       required_argument,  0, 's' },
        {"group",       required_argument,  0, 'g' },
	{"features",	required_argument,  0, 'f' },
        {"server_mode", no_argument,        0, 'm' },
        {0,             0,                  0,  0  }
};

void
lstjn_stop (int sig)
{
        lstjn_stopping = 1;
}

void
lstjn_rpc_done(srpc_client_rpc_t *rpc)
{
        if (!lstjn_intialized)
                lstjn_intialized = 1;
}

int
lstjn_join_session(char *ses, char *grp, unsigned feats)
{
        lnet_process_id_t  sesid;
        srpc_client_rpc_t *rpc;
        srpc_join_reqst_t *req;
        srpc_join_reply_t *rep;
        srpc_mksn_reqst_t *sreq;
        srpc_mksn_reply_t *srep;
        int                rc;

        sesid.pid = LUSTRE_LNET_PID;
        sesid.nid = libcfs_str2nid(ses);
        if (sesid.nid == LNET_NID_ANY) {
                fprintf(stderr, "Invalid session NID: %s\n", ses);
                return -1;
        }

	rpc = sfw_create_rpc(sesid, SRPC_SERVICE_JOIN, feats,
			     0, 0, lstjn_rpc_done, NULL);
        if (rpc == NULL) {
                fprintf(stderr, "Out of memory\n");
                return -1;
        }

        req = &rpc->crpc_reqstmsg.msg_body.join_reqst;

        req->join_sid = LST_INVALID_SID;
	strncpy(req->join_group, grp, sizeof(req->join_group));
	req->join_group[sizeof(req->join_group) - 1] = '\0';

        sfw_post_rpc(rpc);

        for (;;) {
                rc = selftest_wait_events();

                if (lstjn_intialized)
                        break;
        }

        if (rpc->crpc_status != 0) {
                fprintf(stderr, "Failed to send RPC to console: %s\n",
                        strerror(rpc->crpc_status));
                srpc_client_rpc_decref(rpc);
                return -1;
        }

        sfw_unpack_message(&rpc->crpc_replymsg);

        rep = &rpc->crpc_replymsg.msg_body.join_reply;
        if (rep->join_status != 0) {
                fprintf(stderr, "Can't join session %s group %s: %s\n",
                        ses, grp, strerror(rep->join_status));
                srpc_client_rpc_decref(rpc);
                return -1;
        }

	if (rpc->crpc_replymsg.msg_ses_feats != feats) {
		/* this can only happen when connecting to old console
		 * which will ignore features */
		fprintf(stderr, "Can't join session %s group %s because "
			"feature bits can't match: %x/%x, please set "
			"feature bits by -f FEATURES and retry\n",
			ses, grp, feats, rpc->crpc_replymsg.msg_ses_feats);
		srpc_client_rpc_decref(rpc);
		return -1;
	}

        sreq = &rpc->crpc_reqstmsg.msg_body.mksn_reqst;
        sreq->mksn_sid     = rep->join_sid;
        sreq->mksn_force   = 0;
        strcpy(sreq->mksn_name, rep->join_session);

        srep = &rpc->crpc_replymsg.msg_body.mksn_reply;

        rc = sfw_make_session(sreq, srep);
        if (rc != 0 || srep->mksn_status != 0) {
                fprintf(stderr, "Can't create session: %d, %s\n",
                        rc, strerror(srep->mksn_status));
                srpc_client_rpc_decref(rpc);
                return -1;
        }

        fprintf(stdout, "Session %s, ID: %s, "LPU64"\n",
                ses, libcfs_nid2str(rep->join_sid.ses_nid),
                rep->join_sid.ses_stamp);

        srpc_client_rpc_decref(rpc);

        return 0;
}

int
main(int argc, char **argv)
{
	char	*ses = NULL;
	char	*grp = NULL;
	unsigned feats = LST_FEATS_MASK;
	int	 server_mode_flag = 0;
	int	 optidx;
	int	 c;
	int	 rc;

	const char *usage_string =
		   "Usage: lstclient --sesid ID --group GROUP "
		   "--features FEATURES [--server_mode]\n";

	while (1) {
		c = getopt_long(argc, argv, "s:g:f:m",
				lstjn_options, &optidx);

                if (c == -1)
                        break;

                switch (c) {
                case 's':
                        ses = optarg;
                        break;
                case 'g':
                        grp = optarg;
                        break;
		case 'f':
			feats = strtol(optarg, NULL, 16);
			break;

                case 'm':
                        server_mode_flag = 1;
                        break;
                default:
                        fprintf(stderr, "%s", usage_string);
                        return -1;
                }
        }

        if (optind != argc || grp == NULL || ses == NULL) {
                fprintf(stderr, "%s", usage_string);
                return -1;
        }

	if ((feats & ~LST_FEATS_MASK) != 0) {
		fprintf(stderr,
			"lstclient can't understand these feature bits: %x\n",
			(feats & ~LST_FEATS_MASK));
		return -1;
	}

	rc = libcfs_debug_init(5 * 1024 * 1024);
	if (rc != 0) {
		fprintf(stderr, "libcfs_debug_init() failed: %d\n", rc);
		return -1;
	}

	rc = cfs_wi_startup();
	if (rc != 0) {
		fprintf(stderr, "cfs_wi_startup() failed: %d\n", rc);
		libcfs_debug_cleanup();
		return -1;
	}

	rc = LNetInit();
	if (rc != 0) {
		fprintf(stderr, "LNetInit() failed: %d\n", rc);
		cfs_wi_shutdown();
		libcfs_debug_cleanup();
		return -1;
	}

        if (server_mode_flag)
                lnet_server_mode();

        rc = lnet_selftest_init();
        if (rc != 0) {
                fprintf(stderr, "Can't startup selftest\n");
                LNetFini();
                cfs_wi_shutdown();
                libcfs_debug_cleanup();
                return -1;
        }

	rc = lstjn_join_session(ses, grp, feats);
        if (rc != 0)
                goto out;

        signal(SIGINT, lstjn_stop);

        fprintf(stdout, "Start handling selftest requests, Ctl-C to stop\n");

        while (!lstjn_stopping) {
                selftest_wait_events();

                if (!sfw_session_removed())
                        continue;

                fprintf(stdout, "Session ended\n");
                break;
        }

out:
        lnet_selftest_fini();

        LNetFini();

        cfs_wi_shutdown();

        libcfs_debug_cleanup();

        return rc;
}
