/*
 * Copyright (C) 2002-2004 Cluster File Systems, Inc.
 *   Author: Eric Barton <eric@bartonsoftware.com>
 *
 * This file is part of Portals, http://www.lustre.org
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

#include "qswlnd.h"


ptl_nal_t kqswnal_nal =
{
	.nal_type       = QSWNAL,
	.nal_startup    = kqswnal_startup,
	.nal_shutdown   = kqswnal_shutdown,
	.nal_ctl        = kqswnal_ctl,
	.nal_send       = kqswnal_send,
        .nal_send_pages = kqswnal_send_pages,
        .nal_recv       = kqswnal_recv,
        .nal_recv_pages = kqswnal_recv_pages,
	.nal_fwd        = kqswnal_fwd_packet,
};

kqswnal_data_t		kqswnal_data;

int
kqswnal_get_tx_desc (struct portal_ioctl_data *data)
{
	unsigned long      flags;
	struct list_head  *tmp;
	kqswnal_tx_t      *ktx;
	ptl_hdr_t         *hdr;
	int                index = data->ioc_count;
	int                rc = -ENOENT;

	spin_lock_irqsave (&kqswnal_data.kqn_idletxd_lock, flags);

	list_for_each (tmp, &kqswnal_data.kqn_activetxds) {
		if (index-- != 0)
			continue;

		ktx = list_entry (tmp, kqswnal_tx_t, ktx_list);
		hdr = (ptl_hdr_t *)ktx->ktx_buffer;

		data->ioc_count  = le32_to_cpu(hdr->payload_length);
		data->ioc_nid    = le64_to_cpu(hdr->dest_nid);
		data->ioc_u64[0] = ktx->ktx_nid;
		data->ioc_u32[0] = le32_to_cpu(hdr->type);
		data->ioc_u32[1] = ktx->ktx_launcher;
		data->ioc_flags  = (list_empty (&ktx->ktx_delayed_list) ? 0 : 1) |
				   (!ktx->ktx_isnblk                    ? 0 : 2) |
				   (ktx->ktx_state << 2);
		rc = 0;
		break;
	}
	
	spin_unlock_irqrestore (&kqswnal_data.kqn_idletxd_lock, flags);
	return (rc);
}

int
kqswnal_ctl (ptl_ni_t *ni, unsigned int cmd, void *arg)
{
	struct portal_ioctl_data *data = arg;

	LASSERT (ni == kqswnal_data.kqn_ni);

	switch (cmd) {
	case IOC_PORTAL_GET_TXDESC:
		return (kqswnal_get_tx_desc (data));

	case IOC_PORTAL_REGISTER_MYNID:
		if (data->ioc_nid == ni->ni_nid)
			return 0;
		
		LASSERT (PTL_NIDNET(data->ioc_nid) == PTL_NIDNET(ni->ni_nid));

		CERROR("obsolete IOC_PORTAL_REGISTER_MYNID for %s(%s)\n",
		       libcfs_nid2str(data->ioc_nid),
		       libcfs_nid2str(ni->ni_nid));
		return 0;
		
	default:
		return (-EINVAL);
	}
}

void
kqswnal_shutdown(ptl_ni_t *ni)
{
	unsigned long flags;
	kqswnal_tx_t *ktx;
	kqswnal_rx_t *krx;
	
	CDEBUG (D_NET, "shutdown\n");
	LASSERT (ni->ni_data == &kqswnal_data);
	LASSERT (ni == kqswnal_data.kqn_ni);

	switch (kqswnal_data.kqn_init)
	{
	default:
		LASSERT (0);

	case KQN_INIT_ALL:
	case KQN_INIT_DATA:
		break;
	}

	/**********************************************************************/
	/* Signal the start of shutdown... */
	spin_lock_irqsave(&kqswnal_data.kqn_idletxd_lock, flags);
	kqswnal_data.kqn_shuttingdown = 1;
	spin_unlock_irqrestore(&kqswnal_data.kqn_idletxd_lock, flags);

	wake_up_all(&kqswnal_data.kqn_idletxd_waitq);

	/**********************************************************************/
	/* wait for sends that have allocated a tx desc to launch or give up */
	while (atomic_read (&kqswnal_data.kqn_pending_txs) != 0) {
		CDEBUG(D_NET, "waiting for %d pending sends\n",
		       atomic_read (&kqswnal_data.kqn_pending_txs));
		cfs_pause(cfs_time_seconds(1));
	}

	/**********************************************************************/
	/* close elan comms */
#if MULTIRAIL_EKC
	/* Shut down receivers first; rx callbacks might try sending... */
	if (kqswnal_data.kqn_eprx_small != NULL)
		ep_free_rcvr (kqswnal_data.kqn_eprx_small);

	if (kqswnal_data.kqn_eprx_large != NULL)
		ep_free_rcvr (kqswnal_data.kqn_eprx_large);

	/* NB ep_free_rcvr() returns only after we've freed off all receive
	 * buffers (see shutdown handling in kqswnal_requeue_rx()).  This
	 * means we must have completed any messages we passed to
	 * ptl_parse() or kpr_fwd_start(). */

	if (kqswnal_data.kqn_eptx != NULL)
		ep_free_xmtr (kqswnal_data.kqn_eptx);

	/* NB ep_free_xmtr() returns only after all outstanding transmits
	 * have called their callback... */
	LASSERT(list_empty(&kqswnal_data.kqn_activetxds));
#else
	/* "Old" EKC just pretends to shutdown cleanly but actually
	 * provides no guarantees */
	if (kqswnal_data.kqn_eprx_small != NULL)
		ep_remove_large_rcvr (kqswnal_data.kqn_eprx_small);

	if (kqswnal_data.kqn_eprx_large != NULL)
		ep_remove_large_rcvr (kqswnal_data.kqn_eprx_large);

	/* wait for transmits to complete */
	while (!list_empty(&kqswnal_data.kqn_activetxds)) {
		CWARN("waiting for active transmits to complete\n");
		cfs_pause(cfs_time_seconds(1));
	}

	if (kqswnal_data.kqn_eptx != NULL)
		ep_free_large_xmtr (kqswnal_data.kqn_eptx);
#endif
	/**********************************************************************/
	/* flag threads to terminate, wake them and wait for them to die */
	kqswnal_data.kqn_shuttingdown = 2;
	wake_up_all (&kqswnal_data.kqn_sched_waitq);

	while (atomic_read (&kqswnal_data.kqn_nthreads) != 0) {
		CDEBUG(D_NET, "waiting for %d threads to terminate\n",
		       atomic_read (&kqswnal_data.kqn_nthreads));
		cfs_pause(cfs_time_seconds(1));
	}

	/**********************************************************************/
	/* No more threads.  No more portals, router or comms callbacks!
	 * I control the horizontals and the verticals...
	 */

#if MULTIRAIL_EKC
	LASSERT (list_empty (&kqswnal_data.kqn_readyrxds));
	LASSERT (list_empty (&kqswnal_data.kqn_delayedtxds));
	LASSERT (list_empty (&kqswnal_data.kqn_delayedfwds));
#endif

	/**********************************************************************/
	/* Complete any blocked forwarding packets, with error
	 */

	while (!list_empty (&kqswnal_data.kqn_idletxd_fwdq))
	{
		kpr_fwd_desc_t *fwd = list_entry (kqswnal_data.kqn_idletxd_fwdq.next,
						  kpr_fwd_desc_t, kprfd_list);
		list_del (&fwd->kprfd_list);
		kpr_fwd_done (ni, fwd, -ESHUTDOWN);
	}

	/**********************************************************************/
	/* Unmap message buffers and free all descriptors and buffers
	 */

#if MULTIRAIL_EKC
	/* FTTB, we need to unmap any remaining mapped memory.  When
	 * ep_dvma_release() get fixed (and releases any mappings in the
	 * region), we can delete all the code from here -------->  */

	for (ktx = kqswnal_data.kqn_txds; ktx != NULL; ktx = ktx->ktx_alloclist) {
		/* If ktx has a buffer, it got mapped; unmap now.  NB only
		 * the pre-mapped stuff is still mapped since all tx descs
		 * must be idle */

		if (ktx->ktx_buffer != NULL)
			ep_dvma_unload(kqswnal_data.kqn_ep,
				       kqswnal_data.kqn_ep_tx_nmh,
				       &ktx->ktx_ebuffer);
	}

	for (krx = kqswnal_data.kqn_rxds; krx != NULL; krx = krx->krx_alloclist) {
		/* If krx_kiov[0].kiov_page got allocated, it got mapped.  
		 * NB subsequent pages get merged */

		if (krx->krx_kiov[0].kiov_page != NULL)
			ep_dvma_unload(kqswnal_data.kqn_ep,
				       kqswnal_data.kqn_ep_rx_nmh,
				       &krx->krx_elanbuffer);
	}
	/* <----------- to here */

	if (kqswnal_data.kqn_ep_rx_nmh != NULL)
		ep_dvma_release(kqswnal_data.kqn_ep, kqswnal_data.kqn_ep_rx_nmh);

	if (kqswnal_data.kqn_ep_tx_nmh != NULL)
		ep_dvma_release(kqswnal_data.kqn_ep, kqswnal_data.kqn_ep_tx_nmh);
#else
	if (kqswnal_data.kqn_eprxdmahandle != NULL)
	{
		elan3_dvma_unload(kqswnal_data.kqn_ep->DmaState,
				  kqswnal_data.kqn_eprxdmahandle, 0,
				  KQSW_NRXMSGPAGES_SMALL * 
				  (*kqswnal_tunables.kqn_nrxmsgs_small) +
				  KQSW_NRXMSGPAGES_LARGE * 
				  (*kqswnal_tunables.kqn_nrxmsgs_large));

		elan3_dma_release(kqswnal_data.kqn_ep->DmaState,
				  kqswnal_data.kqn_eprxdmahandle);
	}

	if (kqswnal_data.kqn_eptxdmahandle != NULL)
	{
		elan3_dvma_unload(kqswnal_data.kqn_ep->DmaState,
				  kqswnal_data.kqn_eptxdmahandle, 0,
				  KQSW_NTXMSGPAGES * (*kqswnal_tunables.kqn_ntxmsgs +
						      *kqswnal_tunables.kqn_nnblk_txmsgs));

		elan3_dma_release(kqswnal_data.kqn_ep->DmaState,
				  kqswnal_data.kqn_eptxdmahandle);
	}
#endif

	while (kqswnal_data.kqn_txds != NULL) {
		ktx = kqswnal_data.kqn_txds;

		if (ktx->ktx_buffer != NULL)
			PORTAL_FREE(ktx->ktx_buffer, KQSW_TX_BUFFER_SIZE);

		kqswnal_data.kqn_txds = ktx->ktx_alloclist;
		PORTAL_FREE(ktx, sizeof(*ktx));
	}

	while (kqswnal_data.kqn_rxds != NULL) {
		int           i;

		krx = kqswnal_data.kqn_rxds;
		for (i = 0; i < krx->krx_npages; i++)
			if (krx->krx_kiov[i].kiov_page != NULL)
				__free_page (krx->krx_kiov[i].kiov_page);

		kqswnal_data.kqn_rxds = krx->krx_alloclist;
		PORTAL_FREE(krx, sizeof (*krx));
	}

	/* resets flags, pointers to NULL etc */
	memset(&kqswnal_data, 0, sizeof (kqswnal_data));

	CDEBUG (D_MALLOC, "done kmem %d\n", atomic_read(&portal_kmemory));

	PORTAL_MODULE_UNUSE;
}

int
kqswnal_startup (ptl_ni_t *ni)
{
#if MULTIRAIL_EKC
	EP_RAILMASK       all_rails = EP_RAILMASK_ALL;
#else
	ELAN3_DMA_REQUEST dmareq;
#endif
	int               rc;
	int               i;
	kqswnal_rx_t     *krx;
	kqswnal_tx_t     *ktx;
	int               elan_page_idx;

	LASSERT (ni->ni_nal == &kqswnal_nal);

	/* Only 1 instance supported */
	if (kqswnal_data.kqn_init != KQN_INIT_NOTHING) {
                CERROR ("Only 1 instance supported\n");
                return -EPERM;
        }

        if (ni->ni_interfaces[0] != NULL) {
                CERROR("Explicit interface config not supported\n");
                return -EPERM;
        }
        
	CDEBUG (D_MALLOC, "start kmem %d\n", atomic_read(&portal_kmemory));
	
	/* ensure all pointers NULL etc */
	memset (&kqswnal_data, 0, sizeof (kqswnal_data));

	kqswnal_data.kqn_ni = ni;
	ni->ni_data = &kqswnal_data;

	INIT_LIST_HEAD (&kqswnal_data.kqn_idletxds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_nblk_idletxds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_activetxds);
	spin_lock_init (&kqswnal_data.kqn_idletxd_lock);
	init_waitqueue_head (&kqswnal_data.kqn_idletxd_waitq);
	INIT_LIST_HEAD (&kqswnal_data.kqn_idletxd_fwdq);

	INIT_LIST_HEAD (&kqswnal_data.kqn_delayedfwds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_delayedtxds);
	INIT_LIST_HEAD (&kqswnal_data.kqn_readyrxds);

	spin_lock_init (&kqswnal_data.kqn_sched_lock);
	init_waitqueue_head (&kqswnal_data.kqn_sched_waitq);

	/* Leave kqn_rpc_success zeroed */
#if MULTIRAIL_EKC
	kqswnal_data.kqn_rpc_failed.Data[0] = -ECONNREFUSED;
#else
	kqswnal_data.kqn_rpc_failed.Status = -ECONNREFUSED;
#endif

	/* pointers/lists/locks initialised */
	kqswnal_data.kqn_init = KQN_INIT_DATA;
	PORTAL_MODULE_USE;
	
#if MULTIRAIL_EKC
	kqswnal_data.kqn_ep = ep_system();
	if (kqswnal_data.kqn_ep == NULL) {
		CERROR("Can't initialise EKC\n");
		kqswnal_shutdown(ni);
		return (-ENODEV);
	}

	if (ep_waitfor_nodeid(kqswnal_data.kqn_ep) == ELAN_INVALID_NODE) {
		CERROR("Can't get elan ID\n");
		kqswnal_shutdown(ni);
		return (-ENODEV);
	}
#else
	/**********************************************************************/
	/* Find the first Elan device */

	kqswnal_data.kqn_ep = ep_device (0);
	if (kqswnal_data.kqn_ep == NULL)
	{
		CERROR ("Can't get elan device 0\n");
		kqswnal_shutdown(ni);
		return (-ENODEV);
	}
#endif

	kqswnal_data.kqn_nnodes = ep_numnodes (kqswnal_data.kqn_ep);
	kqswnal_data.kqn_elanid = ep_nodeid (kqswnal_data.kqn_ep);

	ni->ni_nid = PTL_MKNID(PTL_NIDNET(ni->ni_nid), kqswnal_data.kqn_elanid);
	
	/**********************************************************************/
	/* Get the transmitter */

	kqswnal_data.kqn_eptx = ep_alloc_xmtr (kqswnal_data.kqn_ep);
	if (kqswnal_data.kqn_eptx == NULL)
	{
		CERROR ("Can't allocate transmitter\n");
		kqswnal_shutdown (ni);
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Get the receivers */

	kqswnal_data.kqn_eprx_small = 
		ep_alloc_rcvr (kqswnal_data.kqn_ep,
			       EP_MSG_SVC_PORTALS_SMALL,
			       *kqswnal_tunables.kqn_ep_envelopes_small);
	if (kqswnal_data.kqn_eprx_small == NULL)
	{
		CERROR ("Can't install small msg receiver\n");
		kqswnal_shutdown (ni);
		return (-ENOMEM);
	}

	kqswnal_data.kqn_eprx_large = 
		ep_alloc_rcvr (kqswnal_data.kqn_ep,
			       EP_MSG_SVC_PORTALS_LARGE,
			       *kqswnal_tunables.kqn_ep_envelopes_large);
	if (kqswnal_data.kqn_eprx_large == NULL)
	{
		CERROR ("Can't install large msg receiver\n");
		kqswnal_shutdown (ni);
		return (-ENOMEM);
	}

	/**********************************************************************/
	/* Reserve Elan address space for transmit descriptors NB we may
	 * either send the contents of associated buffers immediately, or
	 * map them for the peer to suck/blow... */
#if MULTIRAIL_EKC
	kqswnal_data.kqn_ep_tx_nmh = 
		ep_dvma_reserve(kqswnal_data.kqn_ep,
				KQSW_NTXMSGPAGES*(*kqswnal_tunables.kqn_ntxmsgs+
						  *kqswnal_tunables.kqn_nnblk_txmsgs),
				EP_PERM_WRITE);
	if (kqswnal_data.kqn_ep_tx_nmh == NULL) {
		CERROR("Can't reserve tx dma space\n");
		kqswnal_shutdown(ni);
		return (-ENOMEM);
	}
#else
        dmareq.Waitfn   = DDI_DMA_SLEEP;
        dmareq.ElanAddr = (E3_Addr) 0;
        dmareq.Attr     = PTE_LOAD_LITTLE_ENDIAN;
        dmareq.Perm     = ELAN_PERM_REMOTEWRITE;

	rc = elan3_dma_reserve(kqswnal_data.kqn_ep->DmaState,
			      KQSW_NTXMSGPAGES*(*kqswnal_tunables.kqn_ntxmsgs+
						*kqswnal_tunables.kqn_nnblk_txmsgs),
			      &dmareq, &kqswnal_data.kqn_eptxdmahandle);
	if (rc != DDI_SUCCESS)
	{
		CERROR ("Can't reserve tx dma space\n");
		kqswnal_shutdown (ni);
		return (-ENOMEM);
	}
#endif
	/**********************************************************************/
	/* Reserve Elan address space for receive buffers */
#if MULTIRAIL_EKC
	kqswnal_data.kqn_ep_rx_nmh =
		ep_dvma_reserve(kqswnal_data.kqn_ep,
				KQSW_NRXMSGPAGES_SMALL * 
				(*kqswnal_tunables.kqn_nrxmsgs_small) +
				KQSW_NRXMSGPAGES_LARGE * 
				(*kqswnal_tunables.kqn_nrxmsgs_large),
				EP_PERM_WRITE);
	if (kqswnal_data.kqn_ep_tx_nmh == NULL) {
		CERROR("Can't reserve rx dma space\n");
		kqswnal_shutdown(ni);
		return (-ENOMEM);
	}
#else
        dmareq.Waitfn   = DDI_DMA_SLEEP;
        dmareq.ElanAddr = (E3_Addr) 0;
        dmareq.Attr     = PTE_LOAD_LITTLE_ENDIAN;
        dmareq.Perm     = ELAN_PERM_REMOTEWRITE;

	rc = elan3_dma_reserve (kqswnal_data.kqn_ep->DmaState,
				KQSW_NRXMSGPAGES_SMALL * 
				(*kqswnal_tunables.kqn_nrxmsgs_small) +
				KQSW_NRXMSGPAGES_LARGE * 
				(*kqswnal_tunables.kqn_nrxmsgs_large),
				&dmareq, &kqswnal_data.kqn_eprxdmahandle);
	if (rc != DDI_SUCCESS)
	{
		CERROR ("Can't reserve rx dma space\n");
		kqswnal_shutdown (ni);
		return (-ENOMEM);
	}
#endif
	/**********************************************************************/
	/* Allocate/Initialise transmit descriptors */

	kqswnal_data.kqn_txds = NULL;
	for (i = 0; i < (*kqswnal_tunables.kqn_ntxmsgs + *kqswnal_tunables.kqn_nnblk_txmsgs); i++)
	{
		int           premapped_pages;
		int           basepage = i * KQSW_NTXMSGPAGES;

		PORTAL_ALLOC (ktx, sizeof(*ktx));
		if (ktx == NULL) {
			kqswnal_shutdown (ni);
			return (-ENOMEM);
		}

		memset(ktx, 0, sizeof(*ktx));	/* NULL pointers; zero flags */
		ktx->ktx_alloclist = kqswnal_data.kqn_txds;
		kqswnal_data.kqn_txds = ktx;

		PORTAL_ALLOC (ktx->ktx_buffer, KQSW_TX_BUFFER_SIZE);
		if (ktx->ktx_buffer == NULL)
		{
			kqswnal_shutdown (ni);
			return (-ENOMEM);
		}

		/* Map pre-allocated buffer NOW, to save latency on transmit */
		premapped_pages = kqswnal_pages_spanned(ktx->ktx_buffer,
							KQSW_TX_BUFFER_SIZE);
#if MULTIRAIL_EKC
		ep_dvma_load(kqswnal_data.kqn_ep, NULL, 
			     ktx->ktx_buffer, KQSW_TX_BUFFER_SIZE, 
			     kqswnal_data.kqn_ep_tx_nmh, basepage,
			     &all_rails, &ktx->ktx_ebuffer);
#else
		elan3_dvma_kaddr_load (kqswnal_data.kqn_ep->DmaState,
				       kqswnal_data.kqn_eptxdmahandle,
				       ktx->ktx_buffer, KQSW_TX_BUFFER_SIZE,
				       basepage, &ktx->ktx_ebuffer);
#endif
		ktx->ktx_basepage = basepage + premapped_pages; /* message mapping starts here */
		ktx->ktx_npages = KQSW_NTXMSGPAGES - premapped_pages; /* for this many pages */

		INIT_LIST_HEAD (&ktx->ktx_delayed_list);

		ktx->ktx_state = KTX_IDLE;
#if MULTIRAIL_EKC
		ktx->ktx_rail = -1;		/* unset rail */
#endif
		ktx->ktx_isnblk = (i >= *kqswnal_tunables.kqn_ntxmsgs);
		list_add_tail (&ktx->ktx_list, 
			       ktx->ktx_isnblk ? &kqswnal_data.kqn_nblk_idletxds :
			                         &kqswnal_data.kqn_idletxds);
	}

	/**********************************************************************/
	/* Allocate/Initialise receive descriptors */
	kqswnal_data.kqn_rxds = NULL;
	elan_page_idx = 0;
	for (i = 0; i < *kqswnal_tunables.kqn_nrxmsgs_small + *kqswnal_tunables.kqn_nrxmsgs_large; i++)
	{
#if MULTIRAIL_EKC
		EP_NMD        elanbuffer;
#else
		E3_Addr       elanbuffer;
#endif
		int           j;

		PORTAL_ALLOC(krx, sizeof(*krx));
		if (krx == NULL) {
			kqswnal_shutdown(ni);
			return (-ENOMEM);
		}

		memset(krx, 0, sizeof(*krx)); /* clear flags, null pointers etc */
		krx->krx_alloclist = kqswnal_data.kqn_rxds;
		kqswnal_data.kqn_rxds = krx;

		if (i < *kqswnal_tunables.kqn_nrxmsgs_small)
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
			struct page *page = alloc_page(GFP_KERNEL);
			
			if (page == NULL) {
				kqswnal_shutdown (ni);
				return (-ENOMEM);
			}

			krx->krx_kiov[j].kiov_page = page;
			LASSERT(page_address(page) != NULL);

#if MULTIRAIL_EKC
			ep_dvma_load(kqswnal_data.kqn_ep, NULL,
				     page_address(page),
				     PAGE_SIZE, kqswnal_data.kqn_ep_rx_nmh,
				     elan_page_idx, &all_rails, &elanbuffer);
			
			if (j == 0) {
				krx->krx_elanbuffer = elanbuffer;
			} else {
				rc = ep_nmd_merge(&krx->krx_elanbuffer,
						  &krx->krx_elanbuffer, 
						  &elanbuffer);
				/* NB contiguous mapping */
				LASSERT(rc);
			}
#else
			elan3_dvma_kaddr_load(kqswnal_data.kqn_ep->DmaState,
					      kqswnal_data.kqn_eprxdmahandle,
					      page_address(page),
					      PAGE_SIZE, elan_page_idx,
					      &elanbuffer);
			if (j == 0)
				krx->krx_elanbuffer = elanbuffer;

			/* NB contiguous mapping */
			LASSERT (elanbuffer == krx->krx_elanbuffer + j * PAGE_SIZE);
#endif
			elan_page_idx++;

		}
	}
	LASSERT (elan_page_idx ==
		 (*kqswnal_tunables.kqn_nrxmsgs_small * KQSW_NRXMSGPAGES_SMALL) +
		 (*kqswnal_tunables.kqn_nrxmsgs_large * KQSW_NRXMSGPAGES_LARGE));

	/**********************************************************************/
	/* Queue receives, now that it's OK to run their completion callbacks */

	for (krx = kqswnal_data.kqn_rxds; krx != NULL; krx = krx->krx_alloclist) {
		/* NB this enqueue can allocate/sleep (attr == 0) */
		krx->krx_state = KRX_POSTED;
#if MULTIRAIL_EKC
		rc = ep_queue_receive(krx->krx_eprx, kqswnal_rxhandler, krx,
				      &krx->krx_elanbuffer, 0);
#else
		rc = ep_queue_receive(krx->krx_eprx, kqswnal_rxhandler, krx,
				      krx->krx_elanbuffer,
				      krx->krx_npages * PAGE_SIZE, 0);
#endif
		if (rc != EP_SUCCESS)
		{
			CERROR ("failed ep_queue_receive %d\n", rc);
			kqswnal_shutdown (ni);
			return (-EIO);
		}
	}

	/**********************************************************************/
	/* Spawn scheduling threads */
	for (i = 0; i < num_online_cpus(); i++) {
		rc = kqswnal_thread_start (kqswnal_scheduler, NULL);
		if (rc != 0)
		{
			CERROR ("failed to spawn scheduling thread: %d\n", rc);
			kqswnal_shutdown (ni);
			return (-ESRCH);
		}
	}

	kqswnal_data.kqn_init = KQN_INIT_ALL;
	return (0);
}

void __exit
kqswnal_finalise (void)
{
	ptl_unregister_nal(&kqswnal_nal);
	kqswnal_tunables_fini();
}

static int __init
kqswnal_initialise (void)
{
	int   rc = kqswnal_tunables_init();
	
	if (rc != 0)
		return rc;

	ptl_register_nal(&kqswnal_nal);
	return (0);
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("Kernel Quadrics/Elan NAL v1.01");
MODULE_LICENSE("GPL");

module_init (kqswnal_initialise);
module_exit (kqswnal_finalise);
