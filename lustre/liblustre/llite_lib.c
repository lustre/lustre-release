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

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <portals/api-support.h> /* needed for ptpctl.h */
#include <portals/ptlctl.h>	/* needed for parse_dump */

#include "llite_lib.h"


ptl_handle_ni_t         tcpnal_ni;
struct task_struct *current;
struct obd_class_user_state ocus;

/* portals interfaces */
ptl_handle_ni_t *
kportal_get_ni (int nal)
{
        return &tcpnal_ni;
}

inline void
kportal_put_ni (int nal)
{
        return;
}

struct ldlm_namespace;
struct ldlm_res_id;
struct obd_import;

extern int ldlm_cli_cancel_unused(struct ldlm_namespace *ns, struct ldlm_res_id *res_id, int flags);
extern int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int local_only);
extern int ldlm_replay_locks(struct obd_import *imp);

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
        current->cap_effective = 0;
        memset(&current->pending, 0, sizeof(current->pending));
}

ptl_nid_t tcpnal_mynid;

int init_lib_portals()
{
        int rc;

        PtlInit();
        rc = PtlNIInit(procbridge_interface, 0, 0, 0, &tcpnal_ni);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                PtlFini();
                RETURN (rc);
        }
        PtlNIDebug(tcpnal_ni, ~0);
        return rc;
}

extern int class_handle_ioctl(struct obd_class_user_state *ocus, unsigned int cmd, unsigned long arg);

struct mount_option_s mount_option = {NULL, NULL};

/* FIXME simple arg parser FIXME */
void parse_mount_options(void *arg)
{
        char *buf = NULL;
        struct obd_ioctl_data *data;
        char *ptr, *comma, *eq, **tgt, *v;
        int len;

        if (obd_ioctl_getdata(&buf, &len, arg)) {
                CERROR("OBD ioctl: data error\n");
                return;
        }
        data = (struct obd_ioctl_data *)buf;
        ptr = data->ioc_inlbuf1;
        printf("mount option: %s\n", ptr);

        while (ptr) {
                eq = strchr(ptr, '=');
                if (!eq)
                        return;

                *eq = 0;
                if (!strcmp("osc", ptr))
                        tgt = &mount_option.osc_uuid;
                else if (!strcmp("mdc", ptr))
                        tgt = &mount_option.mdc_uuid;
                else {
                        printf("Unknown mount option %s\n", ptr);
                        return;
                }

                v = eq + 1;
                comma = strchr(v, ',');
                if (comma) {
                        *comma = 0;
                        ptr = comma + 1;
                } else
                        ptr = NULL;

                *tgt = malloc(strlen(v)+1);
                strcpy(*tgt, v);
        }

        if (buf)
                obd_ioctl_freedata(buf, len);
}

int lib_ioctl(int dev_id, int opc, void * ptr)
{
        int rc;

	if (dev_id == OBD_DEV_ID) {
                struct obd_ioctl_data *ioc = ptr;

                if (opc == OBD_IOC_MOUNTOPT) {
                        parse_mount_options(ptr);
                        return 0;
                }

		rc = class_handle_ioctl(&ocus, opc, (unsigned long)ptr);

		/* you _may_ need to call obd_ioctl_unpack or some
		   other verification function if you want to use ioc
		   directly here */
		printf ("processing ioctl cmd: %x buf len: %d, rc %d\n", 
			opc,  ioc->ioc_len, rc);

                if (rc)
                        return rc;
	}
	return (0);
}

int lllib_init(char *arg)
{
	tcpnal_mynid = ntohl(inet_addr(arg));
        INIT_LIST_HEAD(&ocus.ocus_conns);

        init_current("dummy");
        if (init_obdclass() ||
            init_lib_portals() ||
            ptlrpc_init() ||
            ldlm_init() ||
            mdc_init() ||
            lov_init() ||
            osc_init())
                return -1;

	if (parse_dump("/tmp/DUMP_FILE", lib_ioctl))
                return -1;

        return _sysio_fssw_register("llite", &llu_fssw_ops);
}

/* FIXME */
void generate_random_uuid(unsigned char uuid_out[16])
{
        int *arr = (int*)uuid_out;
        int i;

        for (i = 0; i < sizeof(uuid_out)/sizeof(int); i++)
                arr[i] = rand();
}

