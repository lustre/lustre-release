/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

/* both sys/queue.h (libsysio require it) and portals/lists.h have definition
 * of 'LIST_HEAD'. undef it to suppress warnings
 */
#undef LIST_HEAD

#include <portals/api-support.h> /* needed for ptpctl.h */
#include <portals/ptlctl.h>	/* needed for parse_dump */
#include <procbridge.h>

#include "llite_lib.h"

unsigned int portal_subsystem_debug = ~0 - (S_PORTALS | S_QSWNAL | S_SOCKNAL |
                                            S_GMNAL | S_IBNAL);

ptl_handle_ni_t         tcpnal_ni;
struct task_struct     *current;

/* portals interfaces */
ptl_handle_ni_t *
kportal_get_ni (int nal)
{
        switch (nal)
        {
        case SOCKNAL:
                return &tcpnal_ni;
        default:
                return NULL;
        }
}

inline void
kportal_put_ni (int nal)
{
        return;
}

struct ldlm_namespace;
struct ldlm_res_id;
struct obd_import;

void *inter_module_get(char *arg)
{
        if (!strcmp(arg, "tcpnal_ni"))
                return &tcpnal_ni;
        else if (!strcmp(arg, "ldlm_cli_cancel_unused"))
                return ldlm_cli_cancel_unused;
        else if (!strcmp(arg, "ldlm_namespace_cleanup"))
                return ldlm_namespace_cleanup;
        else if (!strcmp(arg, "ldlm_replay_locks"))
                return ldlm_replay_locks;
        else
                return NULL;
}

/* XXX move to proper place */
char *portals_nid2str(int nal, ptl_nid_t nid, char *str)
{
        switch(nal){
        case TCPNAL:
                /* userspace NAL */
        case SOCKNAL:
                sprintf(str, "%u:%d.%d.%d.%d", (__u32)(nid >> 32),
                        HIPQUAD(nid));
                break;
        case QSWNAL:
        case GMNAL:
        case IBNAL:
        case SCIMACNAL:
                sprintf(str, "%u:%u", (__u32)(nid >> 32), (__u32)nid);
                break;
        default:
                return NULL;
        }
        return str;
}

void init_current(char *comm)
{ 
        current = malloc(sizeof(*current));
        current->fs = malloc(sizeof(*current->fs));
        current->fs->umask = umask(0777);
        umask(current->fs->umask);
        strncpy(current->comm, comm, sizeof(current->comm));
        current->pid = getpid();
        current->fsuid = 0;
        current->fsgid = 0;
        current->cap_effective = -1;
        memset(&current->pending, 0, sizeof(current->pending));
}

/* FIXME */
void generate_random_uuid(unsigned char uuid_out[16])
{
        int *arr = (int*)uuid_out;
        int i;

        for (i = 0; i < sizeof(uuid_out)/sizeof(int); i++)
                arr[i] = rand();
}

ptl_nid_t tcpnal_mynid;

int init_lib_portals()
{
        int max_interfaces;
        int rc;
        ENTRY;

        PtlInit(&max_interfaces);
        rc = PtlNIInit(procbridge_interface, 0, 0, 0, &tcpnal_ni);
        if (rc != 0) {
                CERROR("TCPNAL: PtlNIInit failed: error %d\n", rc);
                PtlFini();
                RETURN (rc);
        }
        PtlNIDebug(tcpnal_ni, ~0);
        RETURN(rc);
}

int
kportal_nal_cmd(struct portals_cfg *pcfg)
{
        /* handle portals command if we want */
        return 0;
}

extern int class_handle_ioctl(unsigned int cmd, unsigned long arg);

int lib_ioctl_nalcmd(int dev_id, int opc, void * ptr)
{
        struct portal_ioctl_data *ptldata;

        if (opc == IOC_PORTAL_NAL_CMD) {
                ptldata = (struct portal_ioctl_data *) ptr;

                if (ptldata->ioc_nal_cmd == NAL_CMD_REGISTER_MYNID) {
                        tcpnal_mynid = ptldata->ioc_nid;
                        printf("mynid: %u.%u.%u.%u\n",
                                (unsigned)(tcpnal_mynid>>24) & 0xFF,
                                (unsigned)(tcpnal_mynid>>16) & 0xFF,
                                (unsigned)(tcpnal_mynid>>8) & 0xFF,
                                (unsigned)(tcpnal_mynid) & 0xFF);
                }
        }

	return (0);
}

int lib_ioctl(int dev_id, int opc, void * ptr)
{
        int rc;

	if (dev_id == OBD_DEV_ID) {
                struct obd_ioctl_data *ioc = ptr;

                //XXX hack!!!
                ioc->ioc_plen1 = ioc->ioc_inllen1;
                ioc->ioc_pbuf1 = ioc->ioc_bulk;
                //XXX

                rc = class_handle_ioctl(opc, (unsigned long)ptr);

                printf ("proccssing ioctl cmd: %x, rc %d\n", opc,  rc);

                if (rc)
                        return rc;
	}
	return (0);
}

int lllib_init(char *dumpfile)
{
        if (!g_zconf) {
                /* this parse only get my nid from config file
                 * before initialize portals
                 */
                if (parse_dump(dumpfile, lib_ioctl_nalcmd))
                        return -1;
        } else {
                /* XXX need setup mynid before tcpnal initialize */
                tcpnal_mynid = ((uint64_t)getpid() << 32) | time(0);
                printf("LibLustre: TCPNAL NID: %016llx\n", tcpnal_mynid);
        }

        init_current("dummy");
        if (init_obdclass() ||
            init_lib_portals() ||
            ptlrpc_init() ||
            ldlm_init() ||
            mdc_init() ||
            lov_init() ||
            osc_init())
                return -1;

        if (!g_zconf && parse_dump(dumpfile, lib_ioctl))
                return -1;

        return _sysio_fssw_register("llite", &llu_fssw_ops);
}
 
#if 0
static void llu_check_request()
{
        liblustre_wait_event(0);
}
#endif

int liblustre_process_log(struct config_llog_instance *cfg, int allow_recov)
{
        struct lustre_cfg lcfg;
        char  *peer = "MDS_PEER_UUID";
        struct obd_device *obd;
        struct lustre_handle mdc_conn = {0, };
        struct obd_export *exp;
        char  *name = "mdc_dev";
        class_uuid_t uuid;
        struct obd_uuid mdc_uuid;
        struct llog_ctxt *ctxt;
        ptl_nid_t nid = 0;
        int nal, err, rc = 0;
        ENTRY;

        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &mdc_uuid);

        if (ptl_parse_nid(&nid, g_zconf_mdsnid)) {
                CERROR("Can't parse NID %s\n", g_zconf_mdsnid);
                RETURN(-EINVAL);
        }
        nal = ptl_name2nal("tcp");
        if (nal <= 0) {
                CERROR("Can't parse NAL tcp\n");
                RETURN(-EINVAL);
        }
        LCFG_INIT(lcfg, LCFG_ADD_UUID, NULL);
        lcfg.lcfg_nid = nid;
        lcfg.lcfg_inllen1 = strlen(peer) + 1;
        lcfg.lcfg_inlbuf1 = peer;
        lcfg.lcfg_nal = nal;
        err = class_process_config(&lcfg);
        if (err < 0)
                GOTO(out, err);

        LCFG_INIT(lcfg, LCFG_ATTACH, name);
        lcfg.lcfg_inlbuf1 = "mdc";
        lcfg.lcfg_inllen1 = strlen(lcfg.lcfg_inlbuf1) + 1;
        lcfg.lcfg_inlbuf2 = mdc_uuid.uuid;
        lcfg.lcfg_inllen2 = strlen(lcfg.lcfg_inlbuf2) + 1;
        err = class_process_config(&lcfg);
        if (err < 0)
                GOTO(out_del_uuid, err);

        LCFG_INIT(lcfg, LCFG_SETUP, name);
        lcfg.lcfg_inlbuf1 = g_zconf_mdsname;
        lcfg.lcfg_inllen1 = strlen(lcfg.lcfg_inlbuf1) + 1;
        lcfg.lcfg_inlbuf2 = peer;
        lcfg.lcfg_inllen2 = strlen(lcfg.lcfg_inlbuf2) + 1;
        err = class_process_config(&lcfg);
        if (err < 0)
                GOTO(out_detach, err);
        
        obd = class_name2obd(name);
        if (obd == NULL)
                GOTO(out_cleanup, err = -EINVAL);

        /* Disable initial recovery on this import */
        err = obd_set_info(obd->obd_self_export,
                           strlen("initial_recov"), "initial_recov",
                           sizeof(allow_recov), &allow_recov);

        err = obd_connect(&mdc_conn, obd, &mdc_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n",
                        g_zconf_mdsname, err);
                GOTO(out_cleanup, err);
        }
        
        exp = class_conn2export(&mdc_conn);
        
        ctxt = exp->exp_obd->obd_llog_ctxt[LLOG_CONFIG_REPL_CTXT];
        rc = class_config_parse_llog(ctxt, g_zconf_profile, cfg);
        if (rc) {
                CERROR("class_config_parse_llog failed: rc = %d\n", rc);
        }

        err = obd_disconnect(exp, 0);

out_cleanup:
        LCFG_INIT(lcfg, LCFG_CLEANUP, name);
        err = class_process_config(&lcfg);
        if (err < 0)
                GOTO(out, err);

out_detach:
        LCFG_INIT(lcfg, LCFG_DETACH, name);
        err = class_process_config(&lcfg);
        if (err < 0)
                GOTO(out, err);

out_del_uuid:
        LCFG_INIT(lcfg, LCFG_DEL_UUID, name);
        lcfg.lcfg_inllen1 = strlen(peer) + 1;
        lcfg.lcfg_inlbuf1 = peer;
        err = class_process_config(&lcfg);

out:
        if (rc == 0)
                rc = err;
        
        RETURN(rc);
}

static void sighandler_USR1(int signum)
{
        /* do nothing */
}

/* parse host:/mdsname/profile string */
int ll_parse_mount_target(const char *target, char **mdsnid,
                          char **mdsname, char **profile)
{
        static char buf[256];
        char *s;

        buf[255] = 0;
        strncpy(buf, target, 255);

        if ((s = strchr(buf, ':'))) {
                *mdsnid = buf;
                *s = '\0';
                                                                                                                        
                while (*++s == '/')
                        ;
                *mdsname = s;
                if ((s = strchr(*mdsname, '/'))) {
                        *s = '\0';
                        *profile = s + 1;
                        return 0;
                }
        }

        return -1;
}

/* env variables */
#define ENV_LUSTRE_MNTPNT               "LIBLUSTRE_MOUNT_POINT"
#define ENV_LUSTRE_MNTTGT               "LIBLUSTRE_MOUNT_TARGET"
#define ENV_LUSTRE_TIMEOUT              "LIBLUSTRE_TIMEOUT"
#define ENV_LUSTRE_DUMPFILE             "LIBLUSTRE_DUMPFILE"

extern int _sysio_native_init();

extern unsigned int obd_timeout;

/* global variables */
int     g_zconf = 0;            /* zeroconf or dumpfile */
char   *g_zconf_mdsname = NULL; /* mdsname, for zeroconf */
char   *g_zconf_mdsnid = NULL;  /* mdsnid, for zeroconf */
char   *g_zconf_profile = NULL; /* profile, for zeroconf */


void __liblustre_setup_(void)
{
        char *lustre_path = NULL;
        char *target = NULL;
        char *timeout = NULL;
        char *dumpfile = NULL;
        char *root_driver = "native";
        char *lustre_driver = "llite";
        char *root_path = "/";
        unsigned mntflgs = 0;

	int err;

        /* consider tha case of starting multiple liblustre instances
         * at a same time on single node.
         */
        srand(time(NULL) + getpid());

        signal(SIGUSR1, sighandler_USR1);

	lustre_path = getenv(ENV_LUSTRE_MNTPNT);
	if (!lustre_path) {
                lustre_path = "/mnt/lustre";
	}

        target = getenv(ENV_LUSTRE_MNTTGT);
        if (!target) {
                dumpfile = getenv(ENV_LUSTRE_DUMPFILE);
                if (!dumpfile) {
                        CERROR("Neither mount target, nor dumpfile\n");
                        exit(1);
                }
                g_zconf = 0;
                printf("LibLustre: mount point %s, dumpfile %s\n",
                        lustre_path, dumpfile);
        } else {
                if (ll_parse_mount_target(target,
                                          &g_zconf_mdsnid,
                                          &g_zconf_mdsname,
                                          &g_zconf_profile)) {
                        CERROR("mal-formed target %s \n", target);
                        exit(1);
                }
                g_zconf = 1;
                printf("LibLustre: mount point %s, target %s\n",
                        lustre_path, target);
        }

        timeout = getenv(ENV_LUSTRE_TIMEOUT);
        if (timeout) {
                obd_timeout = (unsigned int) atoi(timeout);
                printf("LibLustre: set obd timeout as %u seconds\n",
                        obd_timeout);
        }

	if (_sysio_init() != 0) {
		perror("init sysio");
		exit(1);
	}

        /* cygwin don't need native driver */
#ifndef __CYGWIN__
        _sysio_native_init();
#endif

	err = _sysio_mount_root(root_path, root_driver, mntflgs, NULL);
	if (err) {
		perror(root_driver);
		exit(1);
	}

#if 1
	portal_debug = 0;
	portal_subsystem_debug = 0;
#endif
	err = lllib_init(dumpfile);
	if (err) {
		perror("init llite driver");
		exit(1);
	}	

        err = mount("/", lustre_path, lustre_driver, mntflgs, NULL);
	if (err) {
		errno = -err;
		perror(lustre_driver);
		exit(1);
	}

#if 0
        __sysio_hook_sys_enter = llu_check_request;
        __sysio_hook_sys_leave = NULL;
#endif
}

void __liblustre_cleanup_(void)
{
	_sysio_shutdown();
        PtlFini();
}
