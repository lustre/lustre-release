// SPDX-License-Identifier: GPL-2.0

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * NIC-local bounce pool for ko2iblnd.
 *
 * When the sink buffer of an inbound bulk read sits on a NUMA node remote from
 * the HCA, the device DMAs the write across the inter-socket link, which costs
 * throughput on hardware without PCIe relaxed ordering. We stage such a
 * transfer through a pool of HCA-local pages: the peer RDMA-writes into a local
 * slot and the CPU copies the slot out to the application buffer. The outbound
 * direction is not staged, since an HCA read across the link is barely
 * penalised and the copy would cost more than it saves.
 */

#include "o2iblnd.h"

/* Counters are module-global so a single readout spans every per-HCA pool.
 * Exposed through /sys/kernel/debug/lnet/o2iblnd_bounce_stats; a write resets
 * them.
 */
static atomic64_t kib_bp_hits;		/* slots checked out */
static atomic64_t kib_bp_misses;	/* wanted a slot, none free */
static atomic_t   kib_bp_inflight;	/* slots currently checked out */
static atomic64_t kib_bp_fallback;	/* bounced tx that fell back */
static atomic64_t kib_bp_bytes;		/* bytes staged through slots */

/* FORCE stages every eligible transfer, whatever the sink's NUMA node. It is
 * writable at runtime, so a selftest reaches the same path on a node whose pool
 * was already built.
 */
static inline bool
kiblnd_bounce_forced(void)
{
	return *kiblnd_tunables.kib_bounce_enable == KIBLND_BOUNCE_FORCE;
}

/* NUMA node the HCA's DMA device sits on, or NUMA_NO_NODE when the platform
 * can't say.
 */
static int
kiblnd_hca_numa_node(struct kib_hca_dev *hdev)
{
	struct device *dma = hdev->ibh_ibdev->dma_device;
	int node = dma ? dev_to_node(dma) : NUMA_NO_NODE;

	return node < 0 ? NUMA_NO_NODE : node;
}

/**
 * kiblnd_bounce_alloc_ok() - Whether to allocate a pool on this node.
 *
 * AUTO allocates only on a multi-node NUMA box, where the distance predicate
 * can engage; a single-socket node would pin an arena it could never use.
 * FORCE allocates everywhere so the fail_loc path is exercisable on a
 * single-socket test node. The setter keeps bounce_enable within the
 * tri-state, but match the values explicitly so an out-of-range read can never
 * reach the "allocate" arms.
 *
 * Return: true when the per-HCA pool and copy workqueues should be allocated.
 */
static bool
kiblnd_bounce_alloc_ok(void)
{
	int enable = *kiblnd_tunables.kib_bounce_enable;

	if (enable == KIBLND_BOUNCE_FORCE)
		return true;
	if (enable == KIBLND_BOUNCE_AUTO)
		return IS_ENABLED(CONFIG_NUMA) && num_online_nodes() >= 2;
	return false;
}

/**
 * kiblnd_bounce_slot_zero() - Zero every page of a slot.
 * @slot: slot to scrub.
 *
 * A free slot is kept fully zeroed so a non-conformant peer that writes fewer
 * bytes than it advertised cannot disclose a prior transfer through the
 * untransferred tail. The arena is allocated zeroed, so this only has to
 * re-establish the invariant on release. bounce_scrub gates it, so a trusted
 * fabric can trade the guarantee for the copy it costs and disclose no more
 * than a prior transfer of its own. The caller must own the pages (after
 * kiblnd_unmap_tx on release), since this writes them with the CPU. A
 * non-coherent HCA would need a flush before the next map; the default-on
 * posture targets coherent hardware.
 *
 * With the tunable off the slot keeps its contents and is marked dirty, so a
 * later 0 -> 1 flip is honoured by kiblnd_bounce_get() before the slot is used
 * again.
 */
static void
kiblnd_bounce_slot_zero(struct kib_bounce_slot *slot)
{
	struct kib_bounce_pool *pool = slot->bps_pool;
	struct page **spages = &pool->bp_pages->ibp_pages[slot->bps_index *
							  pool->bp_slot_pages];
	int i;

	if (!*kiblnd_tunables.kib_bounce_scrub) {
		slot->bps_dirty = true;
		return;
	}

	for (i = 0; i < pool->bp_slot_pages; i++) {
		char *p = kmap_local_page(spages[i]);

		memset(p, 0, PAGE_SIZE);
		kunmap_local(p);
	}
	slot->bps_dirty = false;
}

/**
 * kiblnd_bounce_wq_create() - Build the pool's copy-out worker.
 * @pool: pool to attach the worker to.
 *
 * Every slot of a pool is HCA-local, so every copy-out out of it belongs on
 * that pool's own CPT, and one worker there serves the whole HCA. Binding the
 * worker to the pool rather than to an NI keeps the two together: a failover
 * builds a fresh pool on the new HCA's node and this builds its worker there,
 * while the old pool keeps its own worker for as long as a transfer still
 * holds one of its slots.
 *
 * A failure here costs locality, not correctness: the consumer falls back to
 * copying inline. So it warns and leaves the worker NULL rather than failing
 * the pool.
 */
static void
kiblnd_bounce_wq_create(struct kib_bounce_pool *pool)
{
	int max_active = *kiblnd_tunables.kib_bounce_copyout_max_active;
	struct workqueue_struct *wq;
	long rc;

	if (max_active < 1)
		max_active = 1;

	wq = cfs_cpt_bind_workqueue("kib_bnc", lnet_cpt_table(), WQ_MEM_RECLAIM,
				    pool->bp_cpt, max_active);
	if (IS_ERR(wq)) {
		rc = PTR_ERR(wq);
		CWARN("%s: no bounce copy-out worker on cpt %d, copying inline: rc = %ld\n",
		      pool->bp_hdev->ibh_ibdev->name, pool->bp_cpt, rc);
		wq = NULL;
	}

	pool->bp_wq = wq;
}

/**
 * kiblnd_bounce_pool_create() - Build the per-HCA bounce pool.
 * @hdev: HCA to attach the pool to.
 *
 * Allocates the slot array on the HCA-local CPT and the backing pages on the
 * HCA's own NUMA node. A failure here disables the feature for this HCA; it
 * never fails device bringup.
 */
void
kiblnd_bounce_pool_create(struct kib_hca_dev *hdev)
{
	struct kib_bounce_pool *pool;
	s64 pool_bytes;
	s64 slot_bytes;
	s64 max_bytes;
	int slot_size;
	int slot_pages;
	bool node_known;
	int nslots;
	int npages;
	int node;
	int cpt;
	int i;
	int rc;

	hdev->ibh_bounce_pool = NULL;

	if (!kiblnd_bounce_alloc_ok())
		return;

	/* bounce_pool_mb is an unvalidated 0444 int; reject nonsense before it
	 * underflows the slot maths below. The high end is capped once the
	 * slot size is known.
	 */
	pool_bytes = (s64)*kiblnd_tunables.kib_bounce_pool_mb << 20;
	if (pool_bytes < PAGE_SIZE)
		pool_bytes = PAGE_SIZE;

	/* A slot holds the largest bulk MD (LNET_MTU). Its pages are not
	 * physically contiguous, so kiblnd_setup_rd_slot() emits one sg entry
	 * per page; sizing the slot at LNET_MTU keeps that count within
	 * IBLND_MAX_RDMA_FRAGS so tx_frags[] can't overflow.
	 */
	slot_bytes = LNET_MTU;
	if (slot_bytes > pool_bytes)
		slot_bytes = pool_bytes;
	slot_size = round_up((int)slot_bytes, PAGE_SIZE);
	slot_pages = slot_size / PAGE_SIZE;

	/* Cap the arena so the slot and page counts stay within an int. An
	 * arena anywhere near this large fails to allocate below and disables
	 * the feature, which is the honest answer to the request.
	 */
	max_bytes = (s64)(INT_MAX / slot_pages) * slot_size;
	if (pool_bytes > max_bytes)
		pool_bytes = max_bytes;

	nslots = pool_bytes / slot_size;
	if (nslots < 1)
		nslots = 1;
	npages = nslots * slot_pages;

	node = kiblnd_hca_numa_node(hdev);
	node_known = node != NUMA_NO_NODE;
	if (!node_known) {
		/* Without the HCA's node there is nothing to measure the sink
		 * buffer against, and a guessed node can send AUTO the wrong
		 * way (i.e. bounce the buffers that were already local and
		 * leave the remote ones direct.) AUTO declines; FORCE asked for
		 * the arena whatever the topology, so give it one on node 0.
		 */
		if (*kiblnd_tunables.kib_bounce_enable != KIBLND_BOUNCE_FORCE) {
			CWARN("%s: no NUMA node reported for HCA; bounce pool not allocated. Set bounce_enable=2 to bounce anyway\n",
			      hdev->ibh_ibdev->name);
			return;
		}
		CWARN("%s: no NUMA node reported for HCA; forced bounce pool placed on node 0\n",
		      hdev->ibh_ibdev->name);
		node = 0;
	}
	cpt = cfs_cpt_of_node(lnet_cpt_table(), node);
	if (cpt < 0)
		cpt = 0;

	LIBCFS_CPT_ALLOC(pool, lnet_cpt_table(), cpt, sizeof(*pool));
	if (pool == NULL) {
		rc = -ENOMEM;
		CWARN("%s: can't allocate bounce pool, feature disabled: rc = %d\n",
		      hdev->ibh_ibdev->name, rc);
		return;
	}

	pool->bp_hdev = hdev;
	pool->bp_node = node;
	pool->bp_node_known = node_known;
	pool->bp_cpt = cpt;
	pool->bp_slot_size = slot_size;
	pool->bp_slot_pages = slot_pages;
	pool->bp_nslots = nslots;
	spin_lock_init(&pool->bp_lock);
	INIT_LIST_HEAD(&pool->bp_free);
	atomic_set(&pool->bp_inflight, 0);

	rc = kiblnd_alloc_pages_node(&pool->bp_pages, cpt, node, npages);
	if (rc != 0) {
		CWARN("%s: can't allocate %d bounce pool pages on node %d, feature disabled: rc = %d\n",
		      hdev->ibh_ibdev->name, npages, node, rc);
		LIBCFS_FREE(pool, sizeof(*pool));
		return;
	}

	LIBCFS_CPT_ALLOC(pool->bp_slots, lnet_cpt_table(), cpt,
			 nslots * sizeof(struct kib_bounce_slot));
	if (pool->bp_slots == NULL) {
		rc = -ENOMEM;
		CWARN("%s: can't allocate %d bounce slots, feature disabled: rc = %d\n",
		      hdev->ibh_ibdev->name, nslots, rc);
		kiblnd_free_pages(pool->bp_pages);
		LIBCFS_FREE(pool, sizeof(*pool));
		return;
	}

	for (i = 0; i < nslots; i++) {
		struct kib_bounce_slot *slot = &pool->bp_slots[i];

		slot->bps_pool = pool;
		slot->bps_index = i;
		INIT_LIST_HEAD(&slot->bps_list);
		list_add_tail(&slot->bps_list, &pool->bp_free);
	}

	kiblnd_bounce_wq_create(pool);

	hdev->ibh_bounce_pool = pool;
	LCONSOLE_INFO("%s: bounce pool on node %d cpt %d, %d slots x %d bytes\n",
		      hdev->ibh_ibdev->name, node, cpt, nslots, slot_size);
}

/**
 * kiblnd_bounce_pool_destroy() - Tear down a per-HCA bounce pool.
 * @hdev: HCA whose pool is being freed.
 *
 * Reads the pool's own inflight counter rather than the module-global so a
 * leak check on a multi-HCA client binds to the pool being torn down.
 *
 * The HCA holds the last reference on its own pool, and a copy-out holds a
 * reference on the connection it came from, and so on the HCA, for as long as
 * it is queued or running. No copy-out can therefore be outstanding by the
 * time this runs. The worker is drained first regardless, before the slots and
 * pages a queued item would reach.
 *
 * Context: sleeps in destroy_workqueue(). The caller already sleeps in
 *          ib_dealloc_pd().
 */
void
kiblnd_bounce_pool_destroy(struct kib_hca_dev *hdev)
{
	struct kib_bounce_pool *pool = hdev->ibh_bounce_pool;
	int inflight;

	if (pool == NULL)
		return;
	hdev->ibh_bounce_pool = NULL;

	if (pool->bp_wq != NULL) {
		destroy_workqueue(pool->bp_wq);
		pool->bp_wq = NULL;
	}

	inflight = atomic_read(&pool->bp_inflight);
	if (inflight != 0)
		CWARN("%s: %d of %d bounce slot(s) still inflight at destroy\n",
		      hdev->ibh_ibdev->name, inflight, pool->bp_nslots);

	if (pool->bp_slots != NULL)
		LIBCFS_FREE(pool->bp_slots,
			    pool->bp_nslots * sizeof(struct kib_bounce_slot));
	if (pool->bp_pages != NULL)
		kiblnd_free_pages(pool->bp_pages);
	LIBCFS_FREE(pool, sizeof(*pool));
}

/**
 * kiblnd_bounce_get() - Check a free slot out of the pool.
 * @pool: pool to draw from.
 *
 * On exhaustion the caller falls back to a direct transfer, so this warns once
 * per pool rather than failing the I/O.
 *
 * A slot released while bounce_scrub was off holds residue, so scrub it here,
 * once it is ours and before the peer can write a short transfer into it. That
 * keeps "a slot handed out is zeroed" true across a 0 -> 1 flip of the tunable.
 *
 * Context: bp_lock is a plain spin_lock; both callers run in process or
 *          poller-thread context, never in interrupt.
 * Return: a checked-out slot, or NULL when none are free.
 */
struct kib_bounce_slot *
kiblnd_bounce_get(struct kib_bounce_pool *pool)
{
	struct kib_bounce_slot *slot = NULL;

	spin_lock(&pool->bp_lock);
	if (!list_empty(&pool->bp_free)) {
		slot = list_first_entry(&pool->bp_free,
					struct kib_bounce_slot, bps_list);
		list_del_init(&slot->bps_list);
	}
	spin_unlock(&pool->bp_lock);

	if (slot != NULL) {
		if (slot->bps_dirty)
			kiblnd_bounce_slot_zero(slot);
		atomic64_inc(&kib_bp_hits);
		atomic_inc(&kib_bp_inflight);
		atomic_inc(&pool->bp_inflight);
	} else {
		atomic64_inc(&kib_bp_misses);
		if (!pool->bp_warned) {
			pool->bp_warned = true;
			CWARN("%s: all %d bounce slots on node %d in use, I/O falling back to direct. Raise bounce_pool_mb if this recurs.\n",
			      pool->bp_hdev->ibh_ibdev->name, pool->bp_nslots,
			      pool->bp_node);
		}
	}
	return slot;
}

/**
 * kiblnd_bounce_put() - Return a slot to the free list.
 * @slot: slot to release.
 * @already_zeroed: the caller has already zeroed the slot's used bytes. Only
 *                  kiblnd_bounce_copy_out() can report this, since only it
 *                  knows whether it scrubbed what it read.
 *
 * The inbound-success path zeroes each fragment as it copies it out, cache-hot,
 * and passes already_zeroed so the cold full-slot memset is skipped. Every
 * other release scrubs here, re-establishing the all-zero invariant for the
 * next user. The scrub runs before the slot re-enters the free list so a
 * concurrent get() can never hand out unscrubbed pages. With bounce_scrub off
 * the scrub only marks the slot dirty, and kiblnd_bounce_get() completes it if
 * the tunable comes back on.
 */
void
kiblnd_bounce_put(struct kib_bounce_slot *slot, bool already_zeroed)
{
	struct kib_bounce_pool *pool = slot->bps_pool;

	if (!already_zeroed)
		kiblnd_bounce_slot_zero(slot);

	spin_lock(&pool->bp_lock);
	list_add(&slot->bps_list, &pool->bp_free);
	spin_unlock(&pool->bp_lock);
	atomic_dec(&kib_bp_inflight);
	atomic_dec(&pool->bp_inflight);
}

/* A bounced transfer whose slot rd-build or RDMA setup failed and fell back to
 * the direct path. Counted so an operator can tell a fired fallback from a
 * clean bounce.
 */
void
kiblnd_bounce_fallback_inc(void)
{
	atomic64_inc(&kib_bp_fallback);
}

/**
 * kiblnd_bounce_copy_out() - Copy a filled slot out to the application buffer.
 * @slot: slot the peer RDMA-wrote into.
 * @kiov: scattered application sink buffer.
 * @niov: number of @kiov entries.
 * @offset: starting byte offset into @kiov.
 * @nob: bytes to copy.
 *
 * Runs on the HCA-local copy workqueue, off the CQ poller. The slot pages are
 * contiguous from offset 0 while the sink is a scattered kiov, so copy
 * fragment-by-fragment across both page boundaries. When bounce_scrub is on,
 * each slot fragment is zeroed as it is read and the last mapped page's tail
 * past @nob is zeroed too, so every page this transfer could reach leaves
 * zeroed. The caller guarantees nob <= bp_slot_size.
 *
 * bounce_scrub is writable at runtime, so read it once here and report what
 * this copy really did. A caller that instead assumed the scrub from its own
 * later read of the tunable could skip the release scrub of a slot this copy
 * left dirty.
 *
 * Return: true when this copy zeroed what it read, so put() can skip its
 * scrub.
 */
bool
kiblnd_bounce_copy_out(struct kib_bounce_slot *slot, const struct bio_vec *kiov,
		       int niov, int offset, int nob)
{
	struct kib_bounce_pool *pool = slot->bps_pool;
	struct page **spages = &pool->bp_pages->ibp_pages[slot->bps_index *
							  pool->bp_slot_pages];
	bool scrub = *kiblnd_tunables.kib_bounce_scrub;
	int nob_orig = nob;
	int sidx = 0;	/* slot page index */
	int soff = 0;	/* byte offset within the slot page */

	LASSERT(nob > 0);
	LASSERT(niov > 0);

	/* skip whole kiov entries that precede offset, the same walk
	 * kiblnd_setup_rd_kiov() does on the matching direct path
	 */
	kiblnd_kiov_skip(&kiov, &niov, &offset);

	while (nob > 0) {
		char *src;
		char *dst;
		int frag;

		LASSERT(niov > 0);
		frag = min3((int)(kiov->bv_len - offset),
			    (int)PAGE_SIZE - soff, nob);
		src = kmap_local_page(spages[sidx]);
		dst = kmap_local_page(kiov->bv_page);

		memcpy(dst + kiov->bv_offset + offset, src + soff, frag);
		if (scrub)
			memset(src + soff, 0, frag);
		kunmap_local(dst);	/* unmap in reverse map order */
		kunmap_local(src);

		nob -= frag;
		offset += frag;
		soff += frag;
		if (offset >= kiov->bv_len) {	/* spent this app page */
			kiov++;
			niov--;
			offset = 0;
		}
		if (soff >= PAGE_SIZE) {	/* spent this slot page */
			sidx++;
			soff = 0;
		}
	}

	/* The fused zero covers [0,nob). The last mapped page holds only nob
	 * bytes, so zero its tail too rather than depend on byte-granular HCA
	 * length enforcement. Whole pages past ceil(nob/PAGE) are never mapped,
	 * and are zero already whenever the slot was handed out with
	 * bounce_scrub on.
	 */
	if (scrub) {
		int last = (nob_orig - 1) / (int)PAGE_SIZE;
		int used = nob_orig - last * (int)PAGE_SIZE;

		if (used < (int)PAGE_SIZE) {
			char *p = kmap_local_page(spages[last]);

			memset(p + used, 0, (int)PAGE_SIZE - used);
			kunmap_local(p);
		}
	}

	atomic64_add(nob_orig, &kib_bp_bytes);

	return scrub;
}

/**
 * kiblnd_bounce_first_page() - First page an inbound bulk's DMA touches.
 * @kiov: application buffer.
 * @niov: number of @kiov entries.
 * @offset: starting byte offset into @kiov.
 *
 * The placement predicate needs the page the DMA starts on, after skipping
 * whole kiov entries that precede @offset; sampling kiov[0] would read the
 * wrong NUMA node whenever @offset spans entries. Unlike kiblnd_kiov_skip()
 * this stays on the observability path, so it bounds the walk by @niov and
 * returns NULL on an exhausted vector instead of asserting.
 *
 * Return: the first touched page, or NULL when @offset runs past the buffer.
 */
static struct page *
kiblnd_bounce_first_page(const struct bio_vec *kiov, int niov, int offset)
{
	if (kiov == NULL || niov <= 0)
		return NULL;

	while (offset >= kiov->bv_len) {
		offset -= kiov->bv_len;
		if (--niov <= 0)
			return NULL;
		kiov++;
	}
	return kiov->bv_page;
}

/**
 * kiblnd_should_bounce() - Whether to stage an inbound bulk through a slot.
 * @hdev: HCA the bulk will land on.
 * @kiov: application sink buffer, for the NUMA-distance test.
 * @niov: number of @kiov entries.
 * @offset: starting byte offset into @kiov.
 * @nob: transfer length in bytes.
 * @is_p2p: bulk targets peer-to-peer DMA memory, such as GPU pages.
 *
 * The tunable test comes first, so a build with the feature off pays one load
 * and a branch and never walks @kiov. The remaining cheap guards run before
 * page_to_nid() so we never dereference a page the direct path would not have.
 * A transfer larger than one slot cannot be staged even under FORCE, and
 * peer-to-peer buffers are left direct. FORCE then engages unconditionally;
 * AUTO engages when the buffer is a NUMA hop from the HCA, and declines
 * outright when the HCA's own node is unknown.
 *
 * Return: true to route this transfer through a NIC-local slot.
 */
bool
kiblnd_should_bounce(struct kib_hca_dev *hdev, const struct bio_vec *kiov,
		     int niov, int offset, int nob, bool is_p2p)
{
	struct kib_bounce_pool *pool;
	struct page *first;

	if (*kiblnd_tunables.kib_bounce_enable == KIBLND_BOUNCE_OFF)
		return false;
	pool = hdev->ibh_bounce_pool;
	if (pool == NULL)
		return false;
	if (is_p2p)
		return false;
	if (nob < *kiblnd_tunables.kib_bounce_min_nob)
		return false;
	if (nob > pool->bp_slot_size)
		return false;
	if (kiblnd_bounce_forced())
		return true;
	/* bp_node_known can be false here only if the pool was allocated
	 * under FORCE and bounce_enable was then lowered to AUTO.
	 */
	if (!pool->bp_node_known)
		return false;
	if (num_online_nodes() < 2)
		return false;
	first = kiblnd_bounce_first_page(kiov, niov, offset);
	if (first == NULL)
		return false;
	return node_distance(page_to_nid(first), pool->bp_node) >
	       LOCAL_DISTANCE;
}

/* /sys/kernel/debug/lnet/o2iblnd_bounce_stats: a read dumps the counters, any
 * write resets the cumulative ones for a fresh window. kib_bp_inflight is a
 * live gauge (the leak detector) and the bp_warned latches are one-shot per
 * module load, so neither is reset.
 */
static int
kiblnd_bounce_stats_proc(const struct lnet_debugfs_table *table, int write,
			 void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char tmpstr[192];
	size_t nob = *lenp;
	loff_t pos = *ppos;
	int len;

	if (write) {
		atomic64_set(&kib_bp_hits, 0);
		atomic64_set(&kib_bp_misses, 0);
		atomic64_set(&kib_bp_fallback, 0);
		atomic64_set(&kib_bp_bytes, 0);
		return 0;
	}

	len = scnprintf(tmpstr, sizeof(tmpstr),
			"engaged %llu exhausted %llu inflight %d fallback %llu bytes %llu",
			(u64)atomic64_read(&kib_bp_hits),
			(u64)atomic64_read(&kib_bp_misses),
			atomic_read(&kib_bp_inflight),
			(u64)atomic64_read(&kib_bp_fallback),
			(u64)atomic64_read(&kib_bp_bytes));

	if (pos >= len)
		return 0;

	return cfs_trace_copyout_string(buffer, nob, tmpstr + pos, "\n");
}

static struct lnet_debugfs_table kiblnd_bounce_ctl_table[] = {
	{
		.procname	= "o2iblnd_bounce_stats",
		.mode		= 0644,
		.proc_handler	= &kiblnd_bounce_stats_proc,
	},
	{ .procname = NULL }
};

static void *kiblnd_bounce_debugfs_state;

void
kiblnd_bounce_debugfs_init(void)
{
	lnet_insert_debugfs(kiblnd_bounce_ctl_table, THIS_MODULE,
			    &kiblnd_bounce_debugfs_state);
}

void
kiblnd_bounce_debugfs_fini(void)
{
	lnet_remove_debugfs(kiblnd_bounce_ctl_table);
	/* lnet_insert_debugfs() allocated the file_operations this module owns.
	 * Only lnet_debugfs_fini() frees them, so an unload without it leaks.
	 */
	lnet_debugfs_fini(&kiblnd_bounce_debugfs_state);
}
