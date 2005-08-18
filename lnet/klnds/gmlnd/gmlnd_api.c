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

ptl_handle_ni_t kgmnal_ni;

extern int gmnal_cmd(struct portals_cfg *pcfg, void *private);

/*
 *	gmnal_api_shutdown
 *      nal_refct == 0 => called on last matching PtlNIFini()
 *	Close down this interface and free any resources associated with it
 *	nal_t	nal	our nal to shutdown
 */
void
gmnal_api_shutdown(nal_t *nal)
{
	gmnal_ni_t	*gmnalni;
	lib_nal_t	*libnal;

        if (nal->nal_refct != 0) {
                /* This module got the first ref */
                PORTAL_MODULE_UNUSE;
                return;
        }

        libnal = (lib_nal_t *)nal->nal_data;
        gmnalni = (gmnal_ni_t *)libnal->libnal_data;
	CDEBUG(D_TRACE, "gmnal_api_shutdown: gmnalni [%p]\n", gmnalni);

        /* Stop portals calling our ioctl handler */
        libcfs_nal_cmd_unregister(GMNAL);

        /* XXX for shutdown "under fire" we probably need to set a shutdown
         * flag so when lib calls us we fail immediately and dont queue any
         * more work but our threads can still call into lib OK.  THEN
         * shutdown our threads, THEN lib_fini() */
        lib_fini(libnal);

	gmnal_stop_rxthread(gmnalni);
	gmnal_stop_ctthread(gmnalni);
	gmnal_free_txd(gmnalni);
	gmnal_free_srxd(gmnalni);
	spin_lock(&gmnalni->gmni_gm_lock);
	gm_close(gmnalni->gmni_port);
	gm_finalize();
	spin_unlock(&gmnalni->gmni_gm_lock);
        /* Don't free 'nal'; it's a static struct */
	PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));
	PORTAL_FREE(libnal, sizeof(lib_nal_t));
}


int
gmnal_api_startup(nal_t *nal, ptl_pid_t requested_pid,
                  ptl_ni_limits_t *requested_limits,
                  ptl_ni_limits_t *actual_limits)
{

	lib_nal_t	*libnal = NULL;
	gmnal_ni_t	*gmnalni = NULL;
	gmnal_srxd_t	*srxd = NULL;
	gm_status_t	gm_status;
	unsigned int	local_gmid = 0, global_gmid = 0;
        ptl_process_id_t process_id;

        if (nal->nal_refct != 0) {
                if (actual_limits != NULL) {
                        libnal = (lib_nal_t *)nal->nal_data;
                        *actual_limits = libnal->libnal_ni.ni_actual_limits;
                }
                PORTAL_MODULE_USE;
                return (PTL_OK);
        }

        /* Called on first PtlNIInit() */

	CDEBUG(D_TRACE, "startup\n");

	PORTAL_ALLOC(gmnalni, sizeof(gmnal_ni_t));
	if (!gmnalni) {
		CERROR("can't get memory\n");
		return(PTL_NO_SPACE);
	}	
	memset(gmnalni, 0, sizeof(gmnal_ni_t));
	/*
 	 *	set the small message buffer size 
	 */

	CDEBUG(D_NET, "Allocd and reset gmnalni[%p]\n", gmnalni);
	CDEBUG(D_NET, "small_msg_size is [%d]\n", gmnalni->gmni_small_msg_size);

	PORTAL_ALLOC(libnal, sizeof(lib_nal_t));
	if (!libnal) {
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));
		return(PTL_NO_SPACE);
	}

	memset(libnal, 0, sizeof(lib_nal_t));
        libnal->libnal_send = gmnal_cb_send;
        libnal->libnal_send_pages = gmnal_cb_send_pages;
        libnal->libnal_recv = gmnal_cb_recv;
        libnal->libnal_recv_pages = gmnal_cb_recv_pages;
        libnal->libnal_map = NULL;
        libnal->libnal_unmap = NULL;
        libnal->libnal_dist = gmnal_cb_dist;
        libnal->libnal_data = gmnalni;

	CDEBUG(D_NET, "Allocd and reset libnal[%p]\n", libnal);

	gmnalni->gmni_nal = nal;
	gmnalni->gmni_libnal = libnal;

	spin_lock_init(&gmnalni->gmni_gm_lock);


	/*
	 *	initialise the interface,
	 */
	CDEBUG(D_NET, "Calling gm_init\n");
	if (gm_init() != GM_SUCCESS) {
		CERROR("call to gm_init failed\n");
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}


	CDEBUG(D_NET, "Calling gm_open with port [%d], "
	       "name [%s], version [%d]\n", gm_port_id,
	       "gmnal", GM_API_VERSION);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_status = gm_open(&gmnalni->gmni_port, 0, gm_port_id, "gmnal",
			    GM_API_VERSION);
	spin_unlock(&gmnalni->gmni_gm_lock);

	CDEBUG(D_NET, "gm_open returned [%d]\n", gm_status);
	if (gm_status == GM_SUCCESS) {
		CDEBUG(D_NET,"gm_open succeeded port[%p]\n",gmnalni->gmni_port);
	} else {
		switch(gm_status) {
		case(GM_INVALID_PARAMETER):
			CERROR("gm_open Failure. Invalid Parameter\n");
			break;
		case(GM_BUSY):
			CERROR("gm_open Failure. GM Busy\n");
			break;
		case(GM_NO_SUCH_DEVICE):
			CERROR("gm_open Failure. No such device\n");
			break;
		case(GM_INCOMPATIBLE_LIB_AND_DRIVER):
			CERROR("gm_open Failure. Incompatile lib and driver\n");
			break;
		case(GM_OUT_OF_MEMORY):
			CERROR("gm_open Failure. Out of Memory\n");
			break;
		default:
			CERROR("gm_open Failure. Unknow error code [%d]\n",
                               gm_status);
			break;
		}	
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	gmnalni->gmni_small_msg_size = sizeof(gmnal_msghdr_t) + 
                                        sizeof(ptl_hdr_t) +
                                        PTL_MTU +
                                        928;    /* !! */
        CWARN("Msg size %08x\n", gmnalni->gmni_small_msg_size);

	gmnalni->gmni_small_msg_gmsize =
                gm_min_size_for_length(gmnalni->gmni_small_msg_size);

	if (gmnal_alloc_srxd(gmnalni) != 0) {
		CERROR("Failed to allocate small rx descriptors\n");
		gmnal_free_txd(gmnalni);
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_close(gmnalni->gmni_port);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}


	/*
 	 *	Hang out a bunch of small receive buffers
	 *	In fact hang them all out
	 */
        for (srxd = gmnalni->gmni_srxd; srxd != NULL; srxd = srxd->rx_next) {
		CDEBUG(D_NET, "giving [%p] to gm_provide_recvive_buffer\n", 
		       srxd->rx_buffer);
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_provide_receive_buffer_with_tag(gmnalni->gmni_port, 
						   srxd->rx_buffer, 
                                                   srxd->rx_gmsize, 
						   GM_LOW_PRIORITY, 0);
		spin_unlock(&gmnalni->gmni_gm_lock);
	}
	
	/*
	 *	Allocate pools of small tx buffers and descriptors
	 */
	if (gmnal_alloc_txd(gmnalni) != 0) {
		CERROR("Failed to allocate small tx descriptors\n");
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_close(gmnalni->gmni_port);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	/*
	 *	Initialise the portals library
	 */
	CDEBUG(D_NET, "Getting node id\n");
	spin_lock(&gmnalni->gmni_gm_lock);
	gm_status = gm_get_node_id(gmnalni->gmni_port, &local_gmid);
	spin_unlock(&gmnalni->gmni_gm_lock);
	if (gm_status != GM_SUCCESS) {
		gmnal_stop_rxthread(gmnalni);
		gmnal_stop_ctthread(gmnalni);
		CERROR("can't determine node id\n");
		gmnal_free_txd(gmnalni);
		gmnal_free_srxd(gmnalni);
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_close(gmnalni->gmni_port);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	gmnalni->gmni_local_gmid = local_gmid;
	CDEBUG(D_NET, "Local node id is [%u]\n", local_gmid);

	spin_lock(&gmnalni->gmni_gm_lock);
	gm_status = gm_node_id_to_global_id(gmnalni->gmni_port, 
                                            local_gmid, 
					    &global_gmid);
	spin_unlock(&gmnalni->gmni_gm_lock);
	if (gm_status != GM_SUCCESS) {
		CERROR("failed to obtain global id\n");
		gmnal_stop_rxthread(gmnalni);
		gmnal_stop_ctthread(gmnalni);
		gmnal_free_txd(gmnalni);
		gmnal_free_srxd(gmnalni);
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_close(gmnalni->gmni_port);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}
	CDEBUG(D_NET, "Global node id is [%u]\n", global_gmid);
	gmnalni->gmni_global_gmid = global_gmid;

/*
	pid = gm_getpid();
*/
        process_id.pid = requested_pid;
        process_id.nid = global_gmid;

	CDEBUG(D_NET, "portals_pid is [%u]\n", process_id.pid);
	CDEBUG(D_NET, "portals_nid is ["LPU64"]\n", process_id.nid);

	CDEBUG(D_PORTALS, "calling lib_init\n");
	if (lib_init(libnal, nal, process_id,
                     requested_limits, actual_limits) != PTL_OK) {
		CERROR("lib_init failed\n");
		gmnal_stop_rxthread(gmnalni);
		gmnal_stop_ctthread(gmnalni);
		gmnal_free_txd(gmnalni);
		gmnal_free_srxd(gmnalni);
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_close(gmnalni->gmni_port);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
	}

	/*
	 * Now that we have initialised the portals library, start receive threads,
	 * we do this to avoid processing messages before we can parse them
	 */
	gmnal_start_kernel_threads(gmnalni);

	while (gmnalni->gmni_rxthread_flag != GMNAL_RXTHREADS_STARTED) {
		gmnal_yield(1);
		CDEBUG(D_NET, "Waiting for receive thread signs of life\n");
	}

	CDEBUG(D_NET, "receive thread seems to have started\n");

	if (libcfs_nal_cmd_register(GMNAL, &gmnal_cmd, libnal->libnal_data) != 0) {
		CDEBUG(D_NET, "libcfs_nal_cmd_register failed\n");

                /* XXX these cleanup cases should be restructured to
                 * minimise duplication... */
                lib_fini(libnal);
                
		gmnal_stop_rxthread(gmnalni);
		gmnal_stop_ctthread(gmnalni);
		gmnal_free_txd(gmnalni);
		gmnal_free_srxd(gmnalni);
		spin_lock(&gmnalni->gmni_gm_lock);
		gm_close(gmnalni->gmni_port);
		gm_finalize();
		spin_unlock(&gmnalni->gmni_gm_lock);
		PORTAL_FREE(gmnalni, sizeof(gmnal_ni_t));	
		PORTAL_FREE(libnal, sizeof(lib_nal_t));
		return(PTL_FAIL);
        }

	CDEBUG(D_NET, "gmnal_init finished\n");

	return(PTL_OK);
}

nal_t the_gm_nal;

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
