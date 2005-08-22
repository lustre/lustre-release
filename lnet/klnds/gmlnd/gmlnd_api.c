/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2003 Los Alamos National Laboratory (LANL)
 *
 *   This file is part of Lustre, http://www.lustre.org/
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

/*
 *	Implements the API NAL functions
 */

#include "gmnal.h"

int
gmnal_cmd(struct portals_cfg *pcfg, void *private)
{
	gmnal_ni_t	*gmnalni = private;
	char		*name;
	int		 nid;
	int		 gmid;
	gm_status_t	 gm_status;

	CDEBUG(D_TRACE, "gmnal_cmd [%d] private [%p]\n",
	       pcfg->pcfg_command, private);
	gmnalni = (gmnal_ni_t*)private;

	switch(pcfg->pcfg_command) {
	case GMNAL_IOC_GET_GNID:

		PORTAL_ALLOC(name, pcfg->pcfg_plen1);
		copy_from_user(name, PCFG_PBUF(pcfg, 1), pcfg->pcfg_plen1);

                gm_status = gm_host_name_to_node_id_ex(gmnalni->gmni_port, 0,
                                                       name, &nid);
                if (gm_status != GM_SUCCESS) {
                        CDEBUG(D_NET, "gm_host_name_to_node_id_ex(...host %s) "
                               "failed[%d]\n", name, gm_status);
                        return -ENOENT;
                }

                CDEBUG(D_NET, "Local node %s id is [%d]\n", name, nid);
		gm_status = gm_node_id_to_global_id(gmnalni->gmni_port,
						    nid, &gmid);
		if (gm_status != GM_SUCCESS) {
			CDEBUG(D_NET, "gm_node_id_to_global_id failed[%d]\n",
			       gm_status);
			return -ENOENT;
		}

		CDEBUG(D_NET, "Global node is is [%u][%x]\n", gmid, gmid);
		copy_to_user(PCFG_PBUF(pcfg, 2), &gmid, pcfg->pcfg_plen2);
                return 0;

	case NAL_CMD_REGISTER_MYNID:
                /* Same NID OK */
                if (pcfg->pcfg_nid == gmnalni->gmni_libnal->libnal_ni.ni_pid.nid)
                        return 0;

                CERROR("Can't change NID from "LPD64" to "LPD64"\n",
                       gmnalni->gmni_libnal->libnal_ni.ni_pid.nid,
                       pcfg->pcfg_nid);
                return -EINVAL;

	default:
		CERROR ("gmnal_cmd UNKNOWN[%d]\n", pcfg->pcfg_command);
		return -EINVAL;
	}
        /* not reached */
}

ptl_nid_t
gmnal_get_local_nid (gmnal_ni_t *gmnalni)
{
	unsigned int	 local_gmid;
        unsigned int     global_gmid;
        ptl_nid_t        nid;
        gm_status_t      gm_status;

        /* Called before anything initialised: no need to lock */
	gm_status = gm_get_node_id(gmnalni->gmni_port, &local_gmid);
	if (gm_status != GM_SUCCESS)
		return PTL_NID_ANY;

	CDEBUG(D_NET, "Local node id is [%u]\n", local_gmid);
        
	gm_status = gm_node_id_to_global_id(gmnalni->gmni_port, 
                                            local_gmid, 
					    &global_gmid);
	if (gm_status != GM_SUCCESS)
		return PTL_NID_ANY;
        
	CDEBUG(D_NET, "Global node id is [%u]\n", global_gmid);

        nid = (__u64)global_gmid;
        LASSERT (nid != PTL_NID_ANY);
        
        return global_gmid;
}


void
gmnal_api_shutdown(nal_t *nal)
{
	lib_nal_t	*libnal = nal->nal_data;
	gmnal_ni_t	*gmnalni = libnal->libnal_data;

        if (nal->nal_refct != 0) {
                /* This module got the first ref */
                PORTAL_MODULE_UNUSE;
                return;
        }

	CDEBUG(D_TRACE, "gmnal_api_shutdown: gmnalni [%p]\n", gmnalni);

        /* Stop portals calling our ioctl handler */
        libcfs_nal_cmd_unregister(GMNAL);

        /* stop processing messages */
	gmnal_stop_ctthread(gmnalni);
	gmnal_stop_rxthread(gmnalni);

	gm_close(gmnalni->gmni_port);
	gm_finalize();

        lib_fini(libnal);

	gmnal_free_txs(gmnalni);
	gmnal_free_rxs(gmnalni);

	PORTAL_FREE(gmnalni, sizeof(*gmnalni));
	PORTAL_FREE(libnal, sizeof(*libnal));
}

int
gmnal_api_startup(nal_t *nal, ptl_pid_t requested_pid,
                  ptl_ni_limits_t *requested_limits,
                  ptl_ni_limits_t *actual_limits)
{

	lib_nal_t	*libnal = NULL;
	gmnal_ni_t	*gmnalni = NULL;
	gmnal_rx_t	*rx = NULL;
	gm_status_t 	 gm_status;
        ptl_process_id_t process_id;
        int              rc;

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL) {
                        libnal = (lib_nal_t *)nal->nal_data;
                        *actual_limits = libnal->libnal_ni.ni_actual_limits;
                }
                PORTAL_MODULE_USE;
                return PTL_OK;
        }

        /* Called on first PtlNIInit() */
	CDEBUG(D_TRACE, "startup\n");

	PORTAL_ALLOC(gmnalni, sizeof(*gmnalni));
	if (gmnalni == NULL) {
		CERROR("can't allocate gmnalni\n");
                return PTL_FAIL;
        }
        
	PORTAL_ALLOC(libnal, sizeof(*libnal));
	if (libnal == NULL) {
		CERROR("can't allocate lib_nal\n");
                goto failed_0;
	}	

	memset(gmnalni, 0, sizeof(*gmnalni));
	gmnalni->gmni_libnal = libnal;
	spin_lock_init(&gmnalni->gmni_gm_lock);

        *libnal = (lib_nal_t) {
                .libnal_send       = gmnal_cb_send,
                .libnal_send_pages = gmnal_cb_send_pages,
                .libnal_recv       = gmnal_cb_recv,
                .libnal_recv_pages = gmnal_cb_recv_pages,
                .libnal_dist       = gmnal_cb_dist,
                .libnal_data       = gmnalni,
        };

	/*
	 *	initialise the interface,
	 */
	CDEBUG(D_NET, "Calling gm_init\n");
	if (gm_init() != GM_SUCCESS) {
		CERROR("call to gm_init failed\n");
                goto failed_1;
	}

	CDEBUG(D_NET, "Calling gm_open with port [%d], "
	       "name [%s], version [%d]\n", gm_port_id,
	       "gmnal", GM_API_VERSION);

	gm_status = gm_open(&gmnalni->gmni_port, 0, gm_port_id, "gmnal",
			    GM_API_VERSION);

        if (gm_status != GM_SUCCESS) {
                CERROR("Can't open GM port %d: %d (%s)\n",
                       gm_port_id, gm_status, gmnal_gmstatus2str(gm_status));
                goto failed_2;
	}

        CDEBUG(D_NET,"gm_open succeeded port[%p]\n",gmnalni->gmni_port);

	gmnalni->gmni_msg_size = offsetof(gmnal_msg_t,
                                          gmm_u.immediate.gmim_payload[PTL_MTU]);
        CWARN("Msg size %08x\n", gmnalni->gmni_msg_size);

	if (gmnal_alloc_rxs(gmnalni) != 0) {
		CERROR("Failed to allocate rx descriptors\n");
                goto failed_3;
	}

	if (gmnal_alloc_txs(gmnalni) != 0) {
		CERROR("Failed to allocate tx descriptors\n");
                goto failed_3;
	}

        process_id.pid = requested_pid;
        process_id.nid = gmnal_get_local_nid(gmnalni);
        if (process_id.nid == PTL_NID_ANY)
                goto failed_3;

	CDEBUG(D_NET, "portals_pid is [%u]\n", process_id.pid);
	CDEBUG(D_NET, "portals_nid is ["LPU64"]\n", process_id.nid);

	/* 	Hang out a bunch of small receive buffers
	 *	In fact hang them all out */
        for (rx = gmnalni->gmni_rx; rx != NULL; rx = rx->rx_next)
                gmnal_post_rx(gmnalni, rx);

	if (lib_init(libnal, nal, process_id,
                     requested_limits, actual_limits) != PTL_OK) {
		CERROR("lib_init failed\n");
                goto failed_3;
	}

	/* Now that we have initialised the portals library, start receive
	 * threads, we do this to avoid processing messages before we can parse
	 * them */
	rc = gmnal_start_kernel_threads(gmnalni);
        if (rc != 0) {
                CERROR("Can't start threads: %d\n", rc);
                goto failed_3;
        }

        rc = libcfs_nal_cmd_register(GMNAL, &gmnal_cmd, libnal->libnal_data);
	if (rc != 0) {
		CDEBUG(D_NET, "libcfs_nal_cmd_register failed: %d\n", rc);
                goto failed_4;
        }

	CDEBUG(D_NET, "gmnal_init finished\n");
	return PTL_OK;

 failed_4:
	gmnal_stop_rxthread(gmnalni);
	gmnal_stop_ctthread(gmnalni);

 failed_3:
        gm_close(gmnalni->gmni_port);

 failed_2:
        gm_finalize();

        /* safe to free buffers after network has been shut down */
        gmnal_free_txs(gmnalni);
        gmnal_free_rxs(gmnalni);

 failed_1:
        PORTAL_FREE(libnal, sizeof(*libnal));

 failed_0:
        PORTAL_FREE(gmnalni, sizeof(*gmnalni));

        return PTL_FAIL;
}

ptl_handle_ni_t kgmnal_ni;
nal_t           the_gm_nal;

/* 
 *        Called when module loaded
 */
int gmnal_init(void)
{
        int    rc;

	CDEBUG(D_NET, "reset nal[%p]\n", &the_gm_nal);

        the_gm_nal = (nal_t) {
                .nal_ni_init = gmnal_api_startup,
                .nal_ni_fini = gmnal_api_shutdown,
                .nal_data = NULL,
        };

        rc = ptl_register_nal(GMNAL, &the_gm_nal);
        if (rc != PTL_OK)
                CERROR("Can't register GMNAL: %d\n", rc);
        rc = PtlNIInit(GMNAL, LUSTRE_SRV_PTL_PID, NULL, NULL, &kgmnal_ni);
        if (rc != PTL_OK && rc != PTL_IFACE_DUP) {
                ptl_unregister_nal(GMNAL);
                return (-ENODEV);
        }

        return (rc);
}


/*
 *	Called when module removed
 */
void gmnal_fini()
{
	CDEBUG(D_TRACE, "gmnal_fini\n");

        PtlNIFini(kgmnal_ni);

        ptl_unregister_nal(GMNAL);
}
