/*
 * Copyright (C) 2002 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 * Copyright (C) 2002, Lawrence Livermore National Labs (LLNL)
 * W. Marcus Miller - Based on ksocknal
 *
 * This file is part of Portals, http://www.sf.net/projects/lustre/
 *
 * Portals is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * Portals is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Portals; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "qswnal.h"

ptl_handle_ni_t		kqswnal_ni;
nal_t			kqswnal_api;
kqswnal_data_t		kqswnal_data;

kpr_nal_interface_t kqswnal_router_interface = {
	kprni_nalid:	QSWNAL,
	kprni_arg:	NULL,
	kprni_fwd:	kqswnal_fwd_packet,
};


static int
kqswnal_forward(nal_t   *nal,
		int     id,
		void    *args,  size_t args_len,
		void    *ret,   size_t ret_len)
{
	kqswnal_data_t *k = nal->nal_data;
	nal_cb_t       *nal_cb = k->kqn_cb;

	LASSERT (nal == &kqswnal_api);
	LASSERT (k == &kqswnal_data);
	LASSERT (nal_cb == &kqswnal_lib);

	lib_dispatch(nal_cb, k, id, args, ret); /* nal needs k */
	return (PTL_OK);
}

static void
kqswnal_lock (nal_t *nal, unsigned long *flags)
{
	kqswnal_data_t *k = nal->nal_data;
	nal_cb_t       *nal_cb = k->kqn_cb;

	LASSERT (nal == &kqswnal_api);
	LASSERT (k == &kqswnal_data);
	LASSERT (nal_cb == &kqswnal_lib);

	nal_cb->cb_cli(nal_cb,flags);
}

static void
kqswnal_unlock(nal_t *nal, unsigned long *flags)
{
	kqswnal_data_t *k = nal->nal_data;
	nal_cb_t       *nal_cb = k->kqn_cb;

	LASSERT (nal == &kqswnal_api);
	LASSERT (k == &kqswnal_data);
	LASSERT (nal_cb == &kqswnal_lib);

	nal_cb->cb_sti(nal_cb,flags);
}

static int
kqswnal_shutdown(nal_t *nal, int ni)
{
	CDEBUG (D_NET, "shutdown\n");

	LASSERT (nal == &kqswnal_api);
	return (0);
}

static void
kqswnal_yield( nal_t *nal )
{
	CDEBUG (D_NET, "yield\n");

	if (current->need_resched)
		schedule();
	return;
}

static nal_t *
kqswnal_init(int interface, ptl_pt_index_t ptl_size, ptl_ac_index_t ac_size,
	     ptl_pid_t requested_pid)
{
	ptl_nid_t mynid = ep_nodeid (kqswnal_data.kqn_epdev);
	int       nnids = ep_numnodes (kqswnal_data.kqn_epdev);

        CDEBUG(D_NET, "calling lib_init with nid "LPX64" of %d\n", mynid,nnids);

	lib_init(&kqswnal_lib, mynid, 0, nnids, ptl_size, ac_size);

	return (&kqswnal_api);
}

void __exit
kqswnal_finalise (void)
{
	switch (kqswnal_data.kqn_init)
	{
	default:
		LASSERT (0);

	case KQN_INIT_ALL:
		PORTAL_SYMBOL_UNREGISTER (kqswnal_ni);
		/* fall through */

	case KQN_INIT_PTL:
		PtlNIFini (kqswnal_ni);
		lib_fini (&kqswnal_lib);
		/* fall through */

	case KQN_INIT_DATA:
		break;

	case KQN_INIT_NOTHING:
		return;
	}

	/**********************************************************************/
	/* Make router stop her calling me and fail any more call-ins */
	kpr_shutdown (&kqswnal_data.kqn_router);

	/**********************************************************************/
	/* flag threads to terminate, wake them and wait for them to die */

	kqswnal_data.kqn_shuttingdown = 1;
	wake_up_all (&kqswnal_data.kqn_sched_waitq);

	while (atomic_read (&kqswnal_data.kqn_nthreads) != 0) {
		CDEBUG(D_NET, "waiting for %d threads to terminate\n",
		       atomic_read (&kqswnal_data.kqn_nthreads));
		set_current_state (TASK_UNINTERRUPTIBLE);
		schedule_timeout (HZ);
	}

	/**********************************************************************/
	/* close elan comms */

	if (kqswnal_data.kqn_eprx_small != NULL)
		ep_remove_large_rcvr (kqswnal_data.kqn_eprx_small);

	if (kqswnal_data.kqn_eprx_large != NULL)
		ep_remove_large_rcvr (kqswnal_data.kqn_eprx_large);

	if (kqswnal_data.kqn_eptx != NULL)
		ep_free_large_xmtr (kqswnal_data.kqn_eptx);

	/**********************************************************************/
	/* No more threads.  No more portals, router or comms callbacks!
	 * I control the horizontals and the verticals...
	 */

	/**********************************************************************/
	/* Complete any blocked forwarding packets with error
	 */

	while (!list_empty (&kqswnal_data.kqn_idletxd_fwdq))
	{
		kpr_fwd_desc_t *fwd = list_entry (kqswnal_data.kqn_idletxd_fwdq.next,
						  kpr_fwd_desc_t, kprfd_list);
		list_del (&fwd->kprfd_list);
		kpr_fwd_done (&kqswnal_data.kqn_router, fwd, -EHOSTUNREACH);
	}

	while (!list_empty (&kqswnal_data.kqn_delayedfwds))
	{
		kpr_fwd_desc_t *fwd = list_entry (kqswnal_data.kqn_delayedfwds.next,
						  kpr_fwd_desc_t, kprfd_list);
		list_del (&fwd->kprfd_list);
		kpr_fwd_done (&kqswnal_data.kqn_router, fwd, -EHOSTUNREACH);
	}

	/**********************************************************************/
	/* Wait for router to complete any packets I sent her
	 */

	kpr_deregister (&kqswnal_data.kqn_router);


	/**********************************************************************/
	/* Unmap message buffers and free all descriptors and buffers
	 */

	if (kqswnal_data.kqn_eprxdmahandle != NULL)
	{
		elan3_dvma_unload(kqswnal_data.kqn_epdev->DmaState,
				  kqswnal_data.kqn_eprxdmahandle, 0,
				  KQSW_NRXMSGPAGES_SMALL * KQSW_NRXMSGS_SMALL +
				  KQSW_NRXMSGPAGES_LARGE * KQSW_NRXMSGS_LARGE);

		elan3_dma_release(kqswnal_data.kqn_epdev->DmaState,
				  kqswnal_data.kqn_eprxdmahandle);
	}

	if (kqswnal_data.kqn_eptxdmahandle != NULL)
	{
		elan3_dvma_unload(kqswnal_data.kqn_epdev->DmaState,
				  kqswnal_data.kqn_eptxdmahandle, 0,
				  KQSW_NTXMSGPAGES * (KQSW_NTXMSGS +
						      KQSW_NNBLK_TXMSGS));

		elan3_dma_release(kqswnal_data.kqn_epdev->DmaState,
				  kqswnal_data.kqn_eptxdmahandle);
	}

	if (kqswnal_data.kqn_txds != NULL)
	{
		int   i;

		for (i = 0; i < KQSW_NTXMSGS + KQSW_NNBLK_TXMSGS; i++)
		{
			kqswnal_tx_t *ktx = &kqswnal_data.kqn_txds[i];

			if (ktx->ktx_buffer != NULL)
				PORTAL_FREE(ktx->ktx_buffer,
					    KQSW_TX_BUFFER_SIZE);
		}

		PORTAL_FREE(kqswnal_data.kqn_txds,
			    sizeof (kqswnal_tx_t) * (KQSW_NTXMSGS +
						     KQSW_NNBLK_TXMSGS));
	}

	if (kqswnal_data.kqn_rxds != NULL)
	{
		int   i;
		int   j;

		for (i = 0; i < KQSW_NRXMSGS_SMALL + KQSW_NRXMSGS_LARGE; i++)
		{
			kqswnal_rx_t *krx = &kqswnal_data.kqn_rxds[i];

			for (j = 0; j < krx->krx_npages; j++)
				if (krx->krx_pages[j] != NULL)
					__free_page (krx->krx_pages[j]);
		}

		PORTAL_FREE(kqswnal_data.kqn_rxds,
			    sizeof(kqswnal_rx_t) * (KQSW_NRXMSGS_SMALL +
						    KQSW_NRXMSGS_LARGE));
	}

	/* resets flags, pointers to NULL etc */
	memset(&kqswnal_data, 0, sizeof (kqswnal_data));

	CDEBUG (D_MALLOC, "done kmem %d\n", atomic_read(&portal_kmemory));

	printk (KERN_INFO "Routing QSW NAL unloaded (final mem %d)\n",
                atomic_read(&portal_kmemory));
}

static int __init
kqswnal_initialise (void)
{
	ELAN3_DMA_REQUEST dmareq;
	int               rc;
	int               i;
	int               elan_page_idx;
	int               pkmem = atomic_read(&portal_kmemory);

	LASSERT (kqswnal_data.kqn_init == KQN_INIT_NOTHING);

	CDEBUG (D_MALLOC, "start kmem %d\n", atomic_read(&portal_kmemory));

	kqswnal_api.forward  = kqswnal_forward;
	kqswnal_api.shutdown = kqswnal_shutdown;
	kqswnal_api.yield    = kqswnal_yield;
	kqswnal_api.validate = NULL;		/* our api validate is a NOOP */
	kqswnal_api.lock     = kqswnal_lock;
	kqswnal_api.unlock   = kqswnal_unlock;
	kqswnal_api.nal_data = &kqswnal_data;

	kqswnal_lib.nal_data = &kqswnal_data;

	/* ensure all pointers NULL etc */
	memset (&kqswnal_data, 0, sizeof (kqswnal_data));

	kqswnal_data.kqn_cb = &kqswnal_lib;

	INIT_LIST_HEAD (&kqswnal_data.kqn_idletxds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_nblk_idletxds);
	spin_lock_init (&kqswnal_data.kqn_idletxd_lock);
	init_waitqueue_head (&kqswnal_data.kqn_idletxd_waitq);
	INIT_LIST_HEAD (&kqswnal_data.kqn_idletxd_fwdq);

	INIT_LIST_HEAD (&kqswnal_data.kqn_delayedfwds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_delayedtxds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_readyrxds);

	spin_lock_init (&kqswnal_data.kqn_sched_lock);
	init_waitqueue_head (&kqswnal_data.kqn_sched_waitq);

	spin_lock_init (&kqswnal_data.kqn_statelock);

	/* pointers/lists/locks initialised */
	kqswnal_data.kqn_init = KQN_INIT_DATA;

	/**********************************************************************/
	/* Find the first Elan device */

	kqswnal_data.kqn_epdev = ep_device (0);
	if (kqswnal_data.kqn_epdev == NULL)
	{
		CERROR ("Can't get elan device 0\n");
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Get the transmitter */

	kqswnal_data.kqn_eptx = ep_alloc_large_xmtr (kqswnal_data.kqn_epdev);
	if (kqswnal_data.kqn_eptx == NULL)
	{
		CERROR ("Can't allocate transmitter\n");
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Get the receivers */

	kqswnal_data.kqn_eprx_small = ep_install_large_rcvr (kqswnal_data.kqn_epdev,
							     EP_SVC_LARGE_PORTALS_SMALL,
							     KQSW_EP_ENVELOPES_SMALL);
	if (kqswnal_data.kqn_eprx_small == NULL)
	{
		CERROR ("Can't install small msg receiver\n");
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	kqswnal_data.kqn_eprx_large = ep_install_large_rcvr (kqswnal_data.kqn_epdev,
							     EP_SVC_LARGE_PORTALS_LARGE,
							     KQSW_EP_ENVELOPES_LARGE);
	if (kqswnal_data.kqn_eprx_large == NULL)
	{
		CERROR ("Can't install large msg receiver\n");
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Reserve Elan address space for transmit buffers */

        dmareq.Waitfn   = DDI_DMA_SLEEP;
        dmareq.ElanAddr = (E3_Addr) 0;
        dmareq.Attr     = PTE_LOAD_LITTLE_ENDIAN;
        dmareq.Perm     = ELAN_PERM_REMOTEREAD;

	rc = elan3_dma_reserve(kqswnal_data.kqn_epdev->DmaState,
			      KQSW_NTXMSGPAGES*(KQSW_NTXMSGS+KQSW_NNBLK_TXMSGS),
			      &dmareq, &kqswnal_data.kqn_eptxdmahandle);
	if (rc != DDI_SUCCESS)
	{
		CERROR ("Can't reserve rx dma space\n");
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Reserve Elan address space for receive buffers */

        dmareq.Waitfn   = DDI_DMA_SLEEP;
        dmareq.ElanAddr = (E3_Addr) 0;
        dmareq.Attr     = PTE_LOAD_LITTLE_ENDIAN;
        dmareq.Perm     = ELAN_PERM_REMOTEWRITE;

	rc = elan3_dma_reserve (kqswnal_data.kqn_epdev->DmaState,
				KQSW_NRXMSGPAGES_SMALL * KQSW_NRXMSGS_SMALL +
				KQSW_NRXMSGPAGES_LARGE * KQSW_NRXMSGS_LARGE,
				&dmareq, &kqswnal_data.kqn_eprxdmahandle);
	if (rc != DDI_SUCCESS)
	{
		CERROR ("Can't reserve rx dma space\n");
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Allocate/Initialise transmit descriptors */

	PORTAL_ALLOC(kqswnal_data.kqn_txds,
		     sizeof(kqswnal_tx_t) * (KQSW_NTXMSGS + KQSW_NNBLK_TXMSGS));
	if (kqswnal_data.kqn_txds == NULL)
	{
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	/* clear flags, null pointers etc */
	memset(kqswnal_data.kqn_txds, 0,
	       sizeof(kqswnal_tx_t) * (KQSW_NTXMSGS + KQSW_NNBLK_TXMSGS));
	for (i = 0; i < (KQSW_NTXMSGS + KQSW_NNBLK_TXMSGS); i++)
	{
		int           premapped_pages;
		kqswnal_tx_t *ktx = &kqswnal_data.kqn_txds[i];
		int           basepage = i * KQSW_NTXMSGPAGES;

		PORTAL_ALLOC (ktx->ktx_buffer, KQSW_TX_BUFFER_SIZE);
		if (ktx->ktx_buffer == NULL)
		{
			kqswnal_finalise ();
			return (-ENOMEM);
		}

		/* Map pre-allocated buffer NOW, to save latency on transmit */
		premapped_pages = kqswnal_pages_spanned(ktx->ktx_buffer,
							KQSW_TX_BUFFER_SIZE);

		elan3_dvma_kaddr_load (kqswnal_data.kqn_epdev->DmaState,
				       kqswnal_data.kqn_eptxdmahandle,
				       ktx->ktx_buffer, KQSW_TX_BUFFER_SIZE,
				       basepage, &ktx->ktx_ebuffer);

		ktx->ktx_basepage = basepage + premapped_pages; /* message mapping starts here */
		ktx->ktx_npages = KQSW_NTXMSGPAGES - premapped_pages; /* for this many pages */

		if (i < KQSW_NTXMSGS)
			ktx->ktx_idle = &kqswnal_data.kqn_idletxds;
		else
			ktx->ktx_idle = &kqswnal_data.kqn_nblk_idletxds;

		list_add_tail (&ktx->ktx_list, ktx->ktx_idle);
	}

	/**********************************************************************/
	/* Allocate/Initialise receive descriptors */

	PORTAL_ALLOC (kqswnal_data.kqn_rxds,
		      sizeof (kqswnal_rx_t) * (KQSW_NRXMSGS_SMALL + KQSW_NRXMSGS_LARGE));
	if (kqswnal_data.kqn_rxds == NULL)
	{
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	memset(kqswnal_data.kqn_rxds, 0, /* clear flags, null pointers etc */
	       sizeof(kqswnal_rx_t) * (KQSW_NRXMSGS_SMALL+KQSW_NRXMSGS_LARGE));

	elan_page_idx = 0;
	for (i = 0; i < KQSW_NRXMSGS_SMALL + KQSW_NRXMSGS_LARGE; i++)
	{
		E3_Addr       elanaddr;
		int           j;
		kqswnal_rx_t *krx = &kqswnal_data.kqn_rxds[i];

		if (i < KQSW_NRXMSGS_SMALL)
		{
			krx->krx_npages = KQSW_NRXMSGPAGES_SMALL;
			krx->krx_eprx   = kqswnal_data.kqn_eprx_small;
		}
		else
		{
			krx->krx_npages = KQSW_NRXMSGPAGES_LARGE;
			krx->krx_eprx   = kqswnal_data.kqn_eprx_large;
		}

		LASSERT (krx->krx_npages > 0);
		for (j = 0; j < krx->krx_npages; j++)
		{
			krx->krx_pages[j] = alloc_page (GFP_KERNEL);
			if (krx->krx_pages[j] == NULL)
			{
				kqswnal_finalise ();
				return (-ENOMEM);
			}

			LASSERT(page_address(krx->krx_pages[j]) != NULL);

			elan3_dvma_kaddr_load(kqswnal_data.kqn_epdev->DmaState,
					      kqswnal_data.kqn_eprxdmahandle,
					      page_address(krx->krx_pages[j]),
					      PAGE_SIZE, elan_page_idx,
					      &elanaddr);
			elan_page_idx++;

			if (j == 0)
				krx->krx_elanaddr = elanaddr;

			/* NB we assume a contiguous  */
			LASSERT (elanaddr == krx->krx_elanaddr + j * PAGE_SIZE);
		}
	}
	LASSERT (elan_page_idx ==
		 (KQSW_NRXMSGS_SMALL * KQSW_NRXMSGPAGES_SMALL) +
		 (KQSW_NRXMSGS_LARGE * KQSW_NRXMSGPAGES_LARGE));

	/**********************************************************************/
	/* Network interface ready to initialise */

        rc = PtlNIInit(kqswnal_init, 32, 4, 0, &kqswnal_ni);
        if (rc != 0)
	{
		CERROR ("PtlNIInit failed %d\n", rc);
		kqswnal_finalise ();
		return (-ENOMEM);
	}

	kqswnal_data.kqn_init = KQN_INIT_PTL;

	/**********************************************************************/
	/* Queue receives, now that it's OK to run their completion callbacks */

	for (i = 0; i < KQSW_NRXMSGS_SMALL + KQSW_NRXMSGS_LARGE; i++)
	{
		kqswnal_rx_t *krx = &kqswnal_data.kqn_rxds[i];

		/* NB this enqueue can allocate/sleep (attr == 0) */
		rc = ep_queue_receive(krx->krx_eprx, kqswnal_rxhandler, krx,
				      krx->krx_elanaddr,
				      krx->krx_npages * PAGE_SIZE, 0);
		if (rc != 0)
		{
			CERROR ("failed ep_queue_receive %d\n", rc);
			kqswnal_finalise ();
			return (-ENOMEM);
		}
	}

	/**********************************************************************/
	/* Spawn scheduling threads */
	for (i = 0; i < smp_num_cpus; i++)
	{
		rc = kqswnal_thread_start (kqswnal_scheduler, NULL);
		if (rc != 0)
		{
			CERROR ("failed to spawn scheduling thread: %d\n", rc);
			kqswnal_finalise ();
			return (rc);
		}
	}

	/**********************************************************************/
	/* Connect to the router */
	rc = kpr_register (&kqswnal_data.kqn_router, &kqswnal_router_interface);
	CDEBUG(D_NET, "Can't initialise routing interface (rc = %d): not routing\n",rc);

	PORTAL_SYMBOL_REGISTER(kqswnal_ni);
	kqswnal_data.kqn_init = KQN_INIT_ALL;

	printk(KERN_INFO "Routing QSW NAL loaded on node %d of %d "
	       "(Routing %s, initial mem %d)\n", 
	       ep_nodeid (kqswnal_data.kqn_epdev),
	       ep_numnodes (kqswnal_data.kqn_epdev),
	       kpr_routing (&kqswnal_data.kqn_router) ? "enabled" : "disabled",
	       pkmem);

	return (0);
}


MODULE_AUTHOR("W. Marcus Miller <marcusm@llnl.gov>");
MODULE_DESCRIPTION("Kernel Quadrics Switch NAL v1.00");
MODULE_LICENSE("GPL");

module_init (kqswnal_initialise);
module_exit (kqswnal_finalise);

EXPORT_SYMBOL (kqswnal_ni);
