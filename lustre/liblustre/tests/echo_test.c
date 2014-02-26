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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/liblustre/tests/echo_test.c
 *
 * Lustre Light user test program
 */

#include <liblustre.h>
#include <obd.h>
#include <obd_class.h>

#define LIBLUSTRE_TEST 1
#include "../utils/lctl.c"

#include "../lutil.h"

extern int class_handle_ioctl(unsigned int cmd, unsigned long arg);

static int liblustre_ioctl(int dev_id, unsigned int opc, void *ptr)
{
	int   rc = -EINVAL;
	
	switch (dev_id) {
	default:
		fprintf(stderr, "Unexpected device id %d\n", dev_id);
		abort();
		break;
		
	case OBD_DEV_ID:
		rc = class_handle_ioctl(opc, (unsigned long)ptr);
		break;
	}

	return rc;
}

static char *echo_server_nid = NULL;
static char *echo_server_ostname = "obd1";
static char *osc_dev_name = "OSC_DEV_NAME";
static char *echo_dev_name = "ECHO_CLIENT_DEV_NAME";

static int connect_echo_client(void)
{
	struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        lnet_nid_t nid;
	char *peer = "ECHO_PEER_NID";
	class_uuid_t osc_uuid, echo_uuid;
	struct obd_uuid osc_uuid_str, echo_uuid_str;
	int err;
	ENTRY;

        ll_generate_random_uuid(osc_uuid);
        class_uuid_unparse(osc_uuid, &osc_uuid_str);
        ll_generate_random_uuid(echo_uuid);
        class_uuid_unparse(echo_uuid, &echo_uuid_str);

        nid = libcfs_str2nid(echo_server_nid);
        if (nid == LNET_NID_ANY) {
                CERROR("Can't parse NID %s\n", echo_server_nid);
                RETURN(-EINVAL);
        }

        /* add uuid */
        lustre_cfg_bufs_reset(&bufs, NULL);
        lustre_cfg_bufs_set_string(&bufs, 1, peer);
        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
        lcfg->lcfg_nid = nid;
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed add_uuid\n");
                RETURN(-EINVAL);
	}

        /* attach osc */
        lustre_cfg_bufs_reset(&bufs, osc_dev_name);
        lustre_cfg_bufs_set_string(&bufs, 1, LUSTRE_OSC_NAME);
        lustre_cfg_bufs_set_string(&bufs, 2, osc_uuid_str.uuid);
        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed attach osc\n");
                RETURN(-EINVAL);
	}

	/* setup osc */
        lustre_cfg_bufs_reset(&bufs, osc_dev_name);
        lustre_cfg_bufs_set_string(&bufs, 1, echo_server_ostname);
        lustre_cfg_bufs_set_string(&bufs, 2, peer);
        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed setup osc\n");
                RETURN(-EINVAL);
	}

	/* attach echo_client */
        lustre_cfg_bufs_reset(&bufs, echo_dev_name);
        lustre_cfg_bufs_set_string(&bufs, 1, "echo_client");
        lustre_cfg_bufs_set_string(&bufs, 2, echo_uuid_str.uuid);
        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed attach echo_client\n");
                RETURN(-EINVAL);
	}

	/* setup echo_client */
        lustre_cfg_bufs_reset(&bufs, echo_dev_name);
        lustre_cfg_bufs_set_string(&bufs, 1, osc_dev_name);
        lustre_cfg_bufs_set_string(&bufs, 2, NULL);
        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed setup echo_client\n");
                RETURN(-EINVAL);
	}

	RETURN(0);
}

static int disconnect_echo_client(void)
{
	struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg = NULL;
	int err;
	ENTRY;

	/* cleanup echo_client */
        lustre_cfg_bufs_reset(&bufs, echo_dev_name);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
        err = class_process_config(lcfg);
        if (err < 0) {
                lustre_cfg_free(lcfg);
		CERROR("failed cleanup echo_client\n");
                RETURN(-EINVAL);
	}

	/* detach echo_client */
        lcfg->lcfg_command = LCFG_DETACH;
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed detach echo_client\n");
                RETURN(-EINVAL);
	}

	/* cleanup osc */
        lustre_cfg_bufs_reset(&bufs, osc_dev_name);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
        err = class_process_config(lcfg);
        if (err < 0) {
                lustre_cfg_free(lcfg);
		CERROR("failed cleanup osc device\n");
                RETURN(-EINVAL);
	}

	/* detach osc */
        lcfg->lcfg_command = LCFG_DETACH;
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err < 0) {
		CERROR("failed detach osc device\n");
                RETURN(-EINVAL);
	}

	RETURN(0);
}

static void usage(const char *s)
{
	printf("Usage: %s -s ost_host_name [-n ost_name] [-x lctl_options ...]\n", s);
	printf("    ost_host_name: the host name of echo server\n");
	printf("    ost_name: ost name, default is \"obd1\"\n");
        printf("    lctl_options: options to pass to lctl.\n");
        printf("            (e.g. -x --device 1 test_getattr 10000 -5)\n");
}

extern int time_ptlwait1;
extern int time_ptlwait2;
extern int time_ptlselect;

int main(int argc, char **argv) 
{
	int c, rc;
	int xindex  = -1;  /* index of -x option */

        /* loop until all options are consumed or we hit
         * a -x option 
         */
	while ((c = getopt(argc, argv, "s:n:x:")) != -1 && 
               xindex == -1) {
		switch (c) {
		case 's':
			echo_server_nid = optarg;
			break;
		case 'n':
			echo_server_ostname = optarg;
			break;
		case 'x':
			xindex = optind-1;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

        /*
         * Only warn with usage() if the -x option isn't specificed
         * because when using -x this check is not valid.
         */
        if (optind != argc && xindex == -1)
                usage(argv[0]);

	if (!echo_server_nid) {
		usage(argv[0]);
		return 1;
	}

        libcfs_debug = 0;
        libcfs_subsystem_debug = 0;

        liblustre_init_random();

	if (liblustre_init_current(argv[0]) ||
	    init_obdclass() || init_lib_portals() ||
	    ptlrpc_init() ||
	    lmv_init() ||
	    mdc_init() ||
	    lov_init() ||
	    osc_init() ||
	    echo_client_init()) {
		printf("error\n");
		return 1;
	}

	rc = connect_echo_client();
	if (rc)
		return rc;

	set_ioc_handler(liblustre_ioctl);


        /*
         * If the -x option is not specified pass no args to lctl
         * otherwise pass all the options after the "-x" to lctl
         *
         * HACK: in the case when the -x option is specified
         * lctl sees argv[0] == "-x" and not the real argv[0] seen
         * in this function.  If that is a problem, a mapping will
         * have to be done to fix that.  However for normal functioning
         * it seems to be irrelavant
         */
	if( xindex == -1 )
		rc = lctl_main(1, &argv[0]);
	else
		rc = lctl_main(argc-xindex+1, &argv[xindex-1]);

	rc |= disconnect_echo_client();

	return rc;
}
