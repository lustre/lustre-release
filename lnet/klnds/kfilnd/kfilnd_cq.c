// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright 2022 Hewlett Packard Enterprise Development LP
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * kfilnd completion queue.
 */

#include <linux/idr.h>
#include <linux/mutex.h>
#include <linux/byteorder/generic.h>

#include "kfilnd_cq.h"
#include "kfilnd_tn.h"
#include "kfilnd_ep.h"

void kfilnd_cq_process_error(struct kfilnd_ep *ep,
			     struct kfi_cq_err_entry *error)
{
	struct kfilnd_immediate_buffer *buf;
	struct kfilnd_transaction *tn;
	enum tn_events tn_event;
	int status;

	switch (error->flags) {
	case KFI_MSG | KFI_RECV:
		if (error->err != ECANCELED) {
			KFILND_EP_ERROR(ep, "Dropping error receive event %d",
					-error->err);
			return;
		}
		fallthrough;
	case KFI_MSG | KFI_RECV | KFI_MULTI_RECV:
		buf = error->op_context;
		kfilnd_ep_imm_buffer_put(buf);
		return;

	case KFI_TAGGED | KFI_RECV:
	case KFI_TAGGED | KFI_RECV | KFI_REMOTE_CQ_DATA:
	case KFI_TAGGED | KFI_RMA | KFI_READ | KFI_RECV:
	case KFI_TAGGED | KFI_RMA | KFI_WRITE | KFI_RECV:
		tn = error->op_context;
		if (error->err == ECANCELED) {
			tn_event = TN_EVENT_TAG_RX_CANCEL;
			status = 0;
		} else {
			tn_event = TN_EVENT_TAG_RX_FAIL;
			status = -error->err;
		}
		break;

	case KFI_MSG | KFI_SEND:
		tn = error->op_context;
		tn_event = TN_EVENT_TX_FAIL;
		status = -error->err;
		KFILND_EP_ERROR(ep,
				"msg send error %d prov error %d flags %llx",
				status, -error->prov_errno, error->flags);

		break;

	case KFI_TAGGED | KFI_SEND:
	case KFI_TAGGED | KFI_RMA | KFI_READ | KFI_SEND:
	case KFI_TAGGED | KFI_RMA | KFI_WRITE | KFI_SEND:
		tn = error->op_context;
		tn_event = TN_EVENT_TAG_TX_FAIL;
		status = -error->err;
		KFILND_EP_ERROR(ep,
				"tagged error %d prov error %d flags %llx",
				status, -error->prov_errno, error->flags);
		break;

	default:
		LBUG();
	}

	kfilnd_tn_event_handler(tn, tn_event, status);
}

static void kfilnd_cq_process_event(struct kfi_cq_data_entry *event)
{
	struct kfilnd_immediate_buffer *buf;
	struct kfilnd_msg *rx_msg;
	struct kfilnd_transaction *tn;
	enum tn_events tn_event;
	int64_t status = 0;

	switch (event->flags) {
	case KFI_MSG | KFI_RECV:
	case KFI_MSG | KFI_RECV | KFI_MULTI_RECV:
		buf = event->op_context;
		rx_msg = event->buf;

		kfilnd_tn_process_rx_event(buf, rx_msg, event->len);

		/* If the KFI_MULTI_RECV flag is set, the buffer was
		 * unlinked.
		 */
		if (event->flags & KFI_MULTI_RECV)
			kfilnd_ep_imm_buffer_put(buf);
		return;

	case KFI_TAGGED | KFI_RECV | KFI_REMOTE_CQ_DATA:
		status = -1 * (int64_t)be64_to_cpu(event->data);
		fallthrough;
	case KFI_TAGGED | KFI_RMA | KFI_READ | KFI_RECV:
	case KFI_TAGGED | KFI_RMA | KFI_WRITE | KFI_RECV:
		tn_event = TN_EVENT_TAG_RX_OK;
		tn = event->op_context;
		break;

	case KFI_TAGGED | KFI_SEND:
	case KFI_TAGGED | KFI_RMA | KFI_READ | KFI_SEND:
	case KFI_TAGGED | KFI_RMA | KFI_WRITE | KFI_SEND:
		tn = event->op_context;
		tn_event = TN_EVENT_TAG_TX_OK;
		break;

	case KFI_MSG | KFI_SEND:
		tn = event->op_context;
		tn_event = TN_EVENT_TX_OK;
		break;

	default:
		LBUG();
	}

	kfilnd_tn_event_handler(tn, tn_event, status);
}

static void kfilnd_cq_process_completion(struct work_struct *work)
{
	struct kfilnd_cq_work *cq_work =
		container_of(work, struct kfilnd_cq_work, work);
	struct kfilnd_cq *kfilnd_cq = cq_work->cq;
	struct kfid_cq *cq = kfilnd_cq->cq;
	struct kfi_cq_data_entry event;
	struct kfi_cq_err_entry error;
	ssize_t rc;
	bool done = false;

	/* Drain the KFI completion queue of all events and errors. */
	while (!done) {
		rc = kfi_cq_read(cq, &event, 1);
		if (rc == -KFI_EAVAIL) {
			while (kfi_cq_readerr(cq, &error, 0) == 1)
				kfilnd_cq_process_error(kfilnd_cq->ep, &error);
		} else if (rc == 1) {
			kfilnd_cq_process_event(&event);
		} else if (rc == -EAGAIN) {
			done = true;
		} else {
			KFILND_EP_ERROR(kfilnd_cq->ep, "Unexpected rc = %ld",
					rc);
			done = true;
		}
	}

	if (kfilnd_ep_replays_pending(kfilnd_cq->ep))
		kfilnd_ep_flush_replay_queue(kfilnd_cq->ep);
}

static void kfilnd_cq_completion(struct kfid_cq *cq, void *context)
{
	struct kfilnd_cq *kfilnd_cq = context;
	struct kfilnd_cq_work *cq_work;
	unsigned int i;
	unsigned int start_count;

	/* kcxi provider queues on signaling vector (index 0 cpu),
	 * optionally don't queue kfilnd on that cpu
	 */
	start_count = kfilnd_cq->cq_work_count > 1 &&
			prov_cpu_exclusive ? 1 : 0;
	for (i = start_count; i < kfilnd_cq->cq_work_count; i++) {
		cq_work = &kfilnd_cq->cq_works[i];
		queue_work_on(cq_work->work_cpu, kfilnd_wq, &cq_work->work);
	}
}

#define CQ_ALLOC_SIZE(cpu_count) \
	(sizeof(struct kfilnd_cq) + \
	 (sizeof(struct kfilnd_cq_work) * (cpu_count)))

struct kfilnd_cq *kfilnd_cq_alloc(struct kfilnd_ep *ep,
				  struct kfi_cq_attr *attr)
{
	struct kfilnd_cq *cq;
	cpumask_var_t *cpu_mask;
	int rc;
	unsigned int cpu_count = 0;
	unsigned int cpu;
	unsigned int i;
	size_t alloc_size;
	struct kfilnd_cq_work *cq_work;

	cpu_mask = cfs_cpt_cpumask(lnet_cpt_table(), ep->end_cpt);
	for_each_cpu(cpu, *cpu_mask)
		cpu_count++;

	alloc_size = CQ_ALLOC_SIZE(cpu_count);
	LIBCFS_CPT_ALLOC(cq, lnet_cpt_table(), ep->end_cpt, alloc_size);
	if (!cq) {
		rc = -ENOMEM;
		KFILND_EP_ERROR(ep, "Failed to allocate memory: rc=%d", rc);
		goto err;
	}

	memset(cq, 0, alloc_size);

	rc = kfi_cq_open(ep->end_dev->dom->domain, attr, &cq->cq,
			 kfilnd_cq_completion, cq);
	if (rc) {
		KFILND_EP_ERROR(ep, "Failed to open KFI CQ: rc=%d", rc);
		goto err_free_kfilnd_cq;
	}

	i = 0;
	for_each_cpu(cpu, *cpu_mask) {
		cq_work = &cq->cq_works[i];
		cq_work->cq = cq;
		cq_work->work_cpu = cpu;
		INIT_WORK(&cq_work->work, kfilnd_cq_process_completion);
		i++;
	}

	cq->ep = ep;
	cq->cq_work_count = cpu_count;

	return cq;

err_free_kfilnd_cq:
	LIBCFS_FREE(cq, alloc_size);
err:
	return ERR_PTR(rc);
}

void kfilnd_cq_free(struct kfilnd_cq *cq)
{
	flush_workqueue(kfilnd_wq);
	kfi_close(&cq->cq->fid);
	LIBCFS_FREE(cq, CQ_ALLOC_SIZE(cq->cq_work_count));
}
