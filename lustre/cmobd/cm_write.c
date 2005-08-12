/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_CMOBD

#include <linux/version.h>
#include <linux/init.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/lustre_mds.h>
#include <linux/lustre_cmobd.h>

#include <asm/div64.h>
#include <linux/pagemap.h>

#include "cm_internal.h"

extern kmem_cache_t *cmobd_extent_slab;

/* helper function to split an extent */
static obd_count split_extent(struct ldlm_extent *ext, unsigned long interval)
{
        obd_count buf_count, remainder;
        ENTRY;
        
        buf_count = ext->end - ext->start + 1;
        LASSERT(buf_count > 0);
        
        remainder = do_div(buf_count, interval);
        if (remainder)
                buf_count++;

        RETURN(buf_count);
}

static int cmobd_ap_make_ready(void *data, int cmd)
{
        struct cmobd_async_page *cmap = (struct cmobd_async_page *)data;
        struct page *page = cmap->cmap_page;
        ENTRY;
        
        if (cmd == OBD_BRW_READ)
                RETURN(0);
        
        if (TryLockPage(page))
                RETURN(-EAGAIN);

        RETURN(0);
}

static int cmobd_ap_refresh_count(void *data, int cmd)
{
        struct cmobd_async_page *cmap = (struct cmobd_async_page *)data;
        struct page *page = cmap->cmap_page;
        struct inode *inode = page->mapping->host;
        ENTRY;

        LASSERT(cmd != OBD_BRW_READ);

        /* catch race with truncate */
        if (((loff_t)page->index << PAGE_SHIFT) >= inode->i_size)
                RETURN(0);

        /* catch sub-page write at end of file */
        if (((loff_t)page->index << PAGE_SHIFT) + PAGE_SIZE > inode->i_size)
                RETURN(inode->i_size % PAGE_SIZE);

        RETURN(PAGE_SIZE);
}

static void cmobd_ap_fill_obdo(void *data, int cmd, struct obdo *oa)
{
        struct cmobd_async_page *cmap = (struct cmobd_async_page *)data;
        obd_valid valid_flags;
        struct inode *inode;
        ENTRY;

        if (IS_ERR(cmap)) {
                EXIT;
                return;
        }

        inode = cmap->cmap_page->mapping->host;
        oa->o_id = cmap->cmap_es->es_oa.o_id;
        oa->o_gr = cmap->cmap_es->es_oa.o_gr;
        oa->o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
        valid_flags = OBD_MD_FLTYPE | OBD_MD_FLATIME;
        if (cmd == OBD_BRW_WRITE) {
                oa->o_valid |= OBD_MD_FLIFID;
                
                /* FIXME-UMKA: should be here some mds num and mds id? */
                mdc_pack_id(obdo_id(oa), inode->i_ino, 0, 
                            inode->i_mode, 0, 0);
                valid_flags |= OBD_MD_FLMTIME | OBD_MD_FLCTIME;
        }

        obdo_from_inode(oa, inode, valid_flags);

        EXIT;
        return;
}

static void cmobd_ap_completion(void *data, int cmd, struct obdo *oa, int rc)
{
        struct cmobd_async_page *cmap = (struct cmobd_async_page *)data;
        struct cmobd_extent_set *set = cmap->cmap_es;
        unsigned long flags;
        struct page *page;
        int wakeup = 0;
        ENTRY;

        page = cmap->cmap_page;
        LASSERT(PageLocked(page));
        
        /* XXX */
        if (rc)
                SetPageError(page);
        
        spin_lock_irqsave(&set->es_lock, flags);
        LASSERT(!list_empty(&set->es_pages));
        LASSERT(!list_empty(&cmap->cmap_link));
        
        list_del_init(&cmap->cmap_link);
        if (list_empty(&set->es_pages) && !set->es_count)
                wakeup = 1;
        spin_unlock_irqrestore(&set->es_lock, flags);

        obd_teardown_async_page(set->es_exp, set->es_lsm, NULL, 
                                cmap->cmap_cookie);
        OBD_FREE(cmap, sizeof(*cmap));

        unlock_page(page);
        page_cache_release(page);
        
        if (wakeup)
                wake_up(&set->es_waitq);
        EXIT;
        return;
}

static struct obd_async_page_ops cmobd_async_page_ops = {
        .ap_make_ready =        cmobd_ap_make_ready,
        .ap_refresh_count =     cmobd_ap_refresh_count,
        .ap_fill_obdo =         cmobd_ap_fill_obdo,
        .ap_completion =        cmobd_ap_completion,
};

static int cmobd_send_pages(struct obd_device *obd, 
                            struct niobuf_local *lnb,
                            obd_count oa_bufs,
                            struct cmobd_extent_set *set)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct obd_export *exp = cmobd->master_exp;
        struct cmobd_async_page *cmap = NULL;
        obd_count i;
        int rc = 0;
        unsigned long flags;
        ENTRY;
 
        for (i = 0; i < oa_bufs; i++, lnb++) {
                
                OBD_ALLOC(cmap, sizeof(*cmap));
                if (cmap == NULL) {
                        CERROR("Not enought memory\n");
                        rc = -ENOMEM;
                        break;
                }
                INIT_LIST_HEAD(&cmap->cmap_link);
                cmap->cmap_page = lnb->page;
                cmap->cmap_es = set;
                        
                rc = obd_prep_async_page(exp, set->es_lsm, NULL, lnb->page,
                                         lnb->offset, &cmobd_async_page_ops, 
                                         cmap, &cmap->cmap_cookie);
                if (rc) {
                        CERROR("cmobd prep async page failed page(%p) rc(%d)\n", 
                               lnb->page, rc);
                        OBD_FREE(cmap, sizeof(*cmap));
                        break;
                }

                LASSERT(cmap->cmap_page);
                LASSERT(!PageLocked(cmap->cmap_page));
                LASSERT(Page_Uptodate(cmap->cmap_page));
                page_cache_get(cmap->cmap_page);

                spin_lock_irqsave(&set->es_lock, flags);
                list_add_tail(&cmap->cmap_link, &set->es_pages);
                spin_unlock_irqrestore(&set->es_lock, flags);
                
                rc = obd_queue_async_io(exp, set->es_lsm, NULL, cmap->cmap_cookie,
                                        OBD_BRW_WRITE, 0, 0, 0, 0);
                if (rc) {  /* try sync io */
                        struct obd_io_group *oig;
                        
                        spin_lock_irqsave(&set->es_lock, flags);
                        list_del_init(&cmap->cmap_link);
                        spin_unlock_irqrestore(&set->es_lock, flags);

                        lock_page(cmap->cmap_page);
                        
                        rc = oig_init(&oig);
                        if (rc)
                                GOTO(free_page, rc);

                        rc = obd_queue_group_io(exp, set->es_lsm, NULL, oig,
                                                cmap->cmap_cookie,
                                                OBD_BRW_WRITE, 0, lnb->len, 0,
                                                ASYNC_READY | ASYNC_URGENT |
                                                ASYNC_COUNT_STABLE |
                                                ASYNC_GROUP_SYNC);

                        if (rc)
                                GOTO(free_oig, rc);

                        rc = obd_trigger_group_io(exp, set->es_lsm, NULL, oig);
                        if (rc)
                                GOTO(free_oig, rc);

                        rc = oig_wait(oig);
free_oig:
                        oig_release(oig);
free_page:
                        unlock_page(cmap->cmap_page);
                        page_cache_release(cmap->cmap_page);
                        obd_teardown_async_page(exp, set->es_lsm, NULL, 
                                                cmap->cmap_cookie);
                        OBD_FREE(cmap, sizeof(*cmap));
                        if (rc) {
                                CERROR("cmobd sync io failed\n");
                                break;
                        }
                }
        }
        RETURN(rc);
}

static int cmobd_write_extent(struct obd_device *obd, 
                              struct cmobd_extent_info *ei)
{
        struct cmobd_extent_set *set = ei->ei_set;
        struct cm_obd *cmobd = &obd->u.cm;
        unsigned long flags;
        struct obd_ioobj ioo;
        struct niobuf_local *lnb;
        struct niobuf_remote *rnb;
        obd_count i, oa_bufs;
        struct obdo *oa;
        obd_off offset;
        int ret, rc = 0, wakeup = 0;
        ENTRY;

        oa_bufs = split_extent(&ei->ei_extent, PAGE_SIZE);
        LASSERT(oa_bufs > 0);

        OBD_ALLOC(lnb, oa_bufs * sizeof(struct niobuf_local));
        OBD_ALLOC(rnb, oa_bufs * sizeof(struct niobuf_remote));
        oa = obdo_alloc();
        
        if (lnb == NULL || rnb == NULL || oa == NULL)
                GOTO(out, rc = -ENOMEM);

        LASSERT(ei->ei_extent.end >= ei->ei_extent.start);
        LASSERT((ei->ei_extent.start & (PAGE_SIZE -1)) == 0);
        
        for (i = 0, offset = ei->ei_extent.start; i < oa_bufs; 
             i++, offset += PAGE_SIZE) {
                rnb[i].offset = offset;
                rnb[i].len = MIN(PAGE_SIZE, ei->ei_extent.end - offset + 1);
        }

        memcpy(oa, &set->es_oa, sizeof(*oa));
        obdo_to_ioobj(oa, &ioo);
        ioo.ioo_bufcnt = oa_bufs;

        ret = obd_preprw(OBD_BRW_READ, cmobd->cache_exp, oa, 1, &ioo, 
                         oa_bufs, rnb, lnb, NULL, NULL);
        if (ret)
                GOTO(out, rc = ret);

        rc = cmobd_send_pages(obd, lnb, oa_bufs, set);
        if (rc)
                CERROR("cmobd_send_pages failed %d\n", rc);

        rc = obd_commitrw(OBD_BRW_READ, cmobd->cache_exp, oa, 1, &ioo,
                          oa_bufs, lnb, NULL, ret);

        /* countdown and wake up */
        spin_lock_irqsave(&set->es_lock, flags);
        LASSERT(set->es_count);
        set->es_count--;
        if (!set->es_count)
                wakeup = 1;
        spin_unlock_irqrestore(&set->es_lock, flags);

        if (wakeup)
                wake_up(&set->es_waitq);

        EXIT;
out: 
        if (lnb)
                OBD_FREE(lnb, oa_bufs * sizeof(struct niobuf_local));
        if (rnb)
                OBD_FREE(rnb, oa_bufs * sizeof(struct niobuf_remote));
        if (oa)
                obdo_free(oa);

        return rc;
}

static struct cmobd_extent_info* get_next_ei(struct cmobd_write_service *ws)
{
        struct cmobd_extent_info *ei = NULL;
        unsigned long flags;
        int wakeup = 0;

        spin_lock_irqsave(&ws->ws_extent_lock, flags);
        if (!list_empty(&ws->ws_extents)) {
                ei = list_entry(ws->ws_extents.next, 
                                struct cmobd_extent_info, ei_link);
                list_del_init(&ei->ei_link);
                ws->ws_nextents--;
                if (ws->ws_nextents < CMOBD_MAX_EXTENTS)
                        wakeup = 1;
        }
        spin_unlock_irqrestore(&ws->ws_extent_lock, flags);

        if (wakeup)
                wake_up_all(&ws->ws_waitq_provider);

        return ei;
}
       
static int cmobd_write_main(void *arg)
{
        struct ptlrpc_svc_data *data = (struct ptlrpc_svc_data *)arg;
        struct ptlrpc_thread   *thread = data->thread;
        struct obd_device *obd = data->dev;
        struct cm_obd *cmobd = &obd->u.cm;
        struct cmobd_write_service *ws = cmobd->write_srv;
        struct cmobd_extent_info *extent = NULL;
        unsigned long flags;
        int rc;
        ENTRY;

        lock_kernel();
        ptlrpc_daemonize();

        SIGNAL_MASK_LOCK(current, flags);
        sigfillset(&current->blocked);
        RECALC_SIGPENDING;
        SIGNAL_MASK_UNLOCK(current, flags);

        LASSERTF(strlen(data->name) < sizeof(current->comm),
                 "name %d > len %d\n",strlen(data->name),sizeof(current->comm));
        THREAD_NAME(current->comm, sizeof(current->comm) - 1, "%s", data->name);

        unlock_kernel();

        thread->t_flags = SVC_RUNNING;
        wake_up(&thread->t_ctl_waitq);

        /* Record that the thread is running */
        spin_lock_irqsave(&ws->ws_thread_lock, flags);
        ws->ws_nthreads++;
        spin_unlock_irqrestore(&ws->ws_thread_lock, flags);

        while ((thread->t_flags & SVC_STOPPING) == 0) {
                struct l_wait_info lwi = { 0 };
                                  
                l_wait_event_exclusive(ws->ws_waitq_consumer,
                                       ((thread->t_flags & SVC_STOPPING) ||
                                        ((extent = get_next_ei(ws)) != 
                                          NULL)),
                                       &lwi);
                if (extent == NULL)
                        continue;
                rc = cmobd_write_extent(obd, extent);
                if (rc)
                        CERROR("write extent failed rc=%d\n", rc);
                OBD_SLAB_FREE(extent, cmobd_extent_slab, sizeof(*extent));
                extent = NULL;
        }
 
        thread->t_flags = SVC_STOPPED;
        wake_up(&thread->t_ctl_waitq);
       
        spin_lock_irqsave(&ws->ws_thread_lock, flags);
        ws->ws_nthreads--;                    /* must know immediately */
        spin_unlock_irqrestore(&ws->ws_thread_lock, flags);

        RETURN(0);
}

/* functions for manipulating cmobd write replay threads, similar with 
 * ptlrpc threads functions */
static int cmobd_start_thread(struct obd_device *obd, char *name)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct cmobd_write_service *ws = cmobd->write_srv;
        struct l_wait_info lwi = { 0 };
        struct ptlrpc_svc_data d;
        struct ptlrpc_thread *thread;
        unsigned long flags;
        int rc;
        ENTRY;

        OBD_ALLOC(thread, sizeof(*thread));
        if (thread == NULL)
                RETURN(-ENOMEM);
        init_waitqueue_head(&thread->t_ctl_waitq);
        
        d.dev = obd;
        d.svc = NULL;
        d.name = name;
        d.thread = thread;

        spin_lock_irqsave(&ws->ws_thread_lock, flags);
        list_add(&thread->t_link, &ws->ws_threads);
        spin_unlock_irqrestore(&ws->ws_thread_lock, flags);

        /* CLONE_VM and CLONE_FILES just avoid a needless copy, because we
         * just drop the VM and FILES in ptlrpc_daemonize() right away.
         */
        rc = kernel_thread(cmobd_write_main, &d, CLONE_VM | CLONE_FILES);
        if (rc < 0) {
                CERROR("cannot start thread: %d\n", rc);
                spin_lock_irqsave(&ws->ws_thread_lock, flags);
                list_del_init(&thread->t_link);
                spin_unlock_irqrestore(&ws->ws_thread_lock, flags);
                OBD_FREE(thread, sizeof(*thread));
                RETURN(rc);
        }
        l_wait_event(thread->t_ctl_waitq, thread->t_flags & SVC_RUNNING, &lwi);

        RETURN(0);

}

static void cmobd_stop_thread(struct obd_device *obd, 
                              struct ptlrpc_thread *thread)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct cmobd_write_service *ws = cmobd->write_srv;
        struct l_wait_info lwi = { 0 };
        unsigned long flags;
        ENTRY;

        thread->t_flags = SVC_STOPPING;
        wake_up_all(&ws->ws_waitq_consumer);

        l_wait_event(thread->t_ctl_waitq, (thread->t_flags & SVC_STOPPED),
                     &lwi);

        spin_lock_irqsave(&ws->ws_thread_lock, flags);
        list_del(&thread->t_link);
        spin_unlock_irqrestore(&ws->ws_thread_lock, flags);
        
        OBD_FREE(thread, sizeof(*thread));
        EXIT;
}

static void cmobd_stop_all_threads(struct obd_device *obd)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct cmobd_write_service *ws = cmobd->write_srv;
        unsigned long flags;
        struct ptlrpc_thread *thread;
        ENTRY;

        spin_lock_irqsave(&ws->ws_thread_lock, flags);
        while (!list_empty(&ws->ws_threads)) {
                thread = list_entry(ws->ws_threads.next, 
                                    struct ptlrpc_thread, t_link);

                spin_unlock_irqrestore(&ws->ws_thread_lock, flags);
                cmobd_stop_thread(obd, thread);
                spin_lock_irqsave(&ws->ws_thread_lock, flags);
        }

        spin_unlock_irqrestore(&ws->ws_thread_lock, flags);
        EXIT;
}

static int cmobd_start_n_threads(struct obd_device *obd, int num_threads, 
                                 char *base_name)
{
        int i, rc = 0;
        ENTRY;

        for (i = 0; i < num_threads; i++) {
                char name[32];
                snprintf(name, sizeof(name) - 1, "%s_%02d", base_name, i);
                rc = cmobd_start_thread(obd, name);
                if (rc) {
                        CERROR("cannot start %s thread #%d: rc %d\n", base_name,
                               i, rc);
                        cmobd_stop_all_threads(obd);
                }
        }
        RETURN(rc);
}

void cmobd_cleanup_write_srv(struct obd_device *obd)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct list_head *pos, *n;
        struct cmobd_extent_info *ei;
        ENTRY;
        
        cmobd_stop_all_threads(obd);
        
        list_for_each_safe(pos, n, &cmobd->write_srv->ws_extents) {
                ei = list_entry(pos, struct cmobd_extent_info, ei_link);
                list_del_init(&ei->ei_link);
                OBD_FREE(ei, sizeof(*ei));
        }
        OBD_FREE(cmobd->write_srv, sizeof(*cmobd->write_srv));
        EXIT;
}

int cmobd_init_write_srv(struct obd_device *obd)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct cmobd_write_service *ws;
        int rc;
        ENTRY;

        OBD_ALLOC(cmobd->write_srv, sizeof(*cmobd->write_srv));
        if (cmobd->write_srv == NULL)
                RETURN(-ENOMEM);
        ws = cmobd->write_srv;
        
        INIT_LIST_HEAD(&ws->ws_threads);
        spin_lock_init(&ws->ws_thread_lock);
        ws->ws_nthreads = 0;

        INIT_LIST_HEAD(&ws->ws_extents);
        spin_lock_init(&ws->ws_extent_lock);
        ws->ws_nextents = 0;
        init_waitqueue_head(&ws->ws_waitq_provider);
        init_waitqueue_head(&ws->ws_waitq_consumer);

        rc = cmobd_start_n_threads(obd, CMOBD_NUM_THREADS, "cm_write");
        if (rc) 
                cmobd_cleanup_write_srv(obd);
        
        RETURN(rc);
}

static int extent_queue_full(struct cmobd_write_service *ws)
{
        unsigned long flags;
        int full = 0;
        
        spin_lock_irqsave(&ws->ws_extent_lock, flags);
        full = (ws->ws_nextents >= CMOBD_MAX_EXTENTS) ? 1 : 0;
        spin_unlock_irqrestore(&ws->ws_extent_lock, flags);

        return full;
}
        
static void cmobd_queue_extent(struct obd_device *obd, 
                               struct cmobd_extent_info *ex)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct cmobd_write_service *ws = cmobd->write_srv;
        struct cmobd_extent_set *set = ex->ei_set;
        unsigned long flags;
        struct l_wait_info lwi = { 0 };
        ENTRY;

wait:
        l_wait_event(ws->ws_waitq_provider, !extent_queue_full(ws), &lwi);
        
        spin_lock_irqsave(&ws->ws_extent_lock, flags);
        if (ws->ws_nextents >= CMOBD_MAX_EXTENTS) {
                spin_unlock_irqrestore(&ws->ws_extent_lock, flags);
                goto wait;
        }
        list_add_tail(&ex->ei_link, &ws->ws_extents);
        ws->ws_nextents++;
        spin_unlock_irqrestore(&ws->ws_extent_lock, flags);
                
        spin_lock_irqsave(&set->es_lock, flags);
        set->es_count++;
        spin_unlock_irqrestore(&set->es_lock, flags);        

        wake_up_all(&ws->ws_waitq_consumer);

        EXIT;
} 

static obd_size cmobd_id2size(struct obd_export *exp, obd_id id, obd_gr grp)
{
        struct lvfs_run_ctxt saved;
        struct dentry *de = NULL;
        obd_size size;
        ENTRY;
        
        push_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);
        
        de = obd_lvfs_id2dentry(exp, id, 0, grp);
        LASSERT(de);

        size = de->d_inode->i_size;

        dput(de);
        pop_ctxt(&saved, &exp->exp_obd->obd_lvfs_ctxt, NULL);

        RETURN(size);
}

static int extent_set_done(struct cmobd_extent_set *set, int phase)
{
        int done = 0;
        unsigned long flags;

        spin_lock_irqsave(&set->es_lock, flags);
        if (phase == 1)
                done = set->es_count ? 0 : 1;
        else if (phase == 2) 
                done = (!set->es_count && list_empty(&set->es_pages)) ? 1 : 0;
        spin_unlock_irqrestore(&set->es_lock, flags);

        return done;
}

int cmobd_replay_write(struct obd_device *obd, struct obdo *oa, 
                       struct ldlm_extent *ext)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct lov_stripe_md *lsm = NULL;
        struct cmobd_extent_set set;
        struct cmobd_extent_info *ex;
        struct l_wait_info lwi = { 0 };
        struct list_head *pos, *n;
        struct cmobd_async_page *cmap;
        unsigned long flags;
        obd_count i, buf_count;
        obd_off start;
        int rc = 0;
        ENTRY;

        rc = cmobd_dummy_lsm(&lsm, cmobd->master_desc.ld_tgt_count, oa,
                             (__u32)cmobd->master_desc.ld_default_stripe_size);
        if (rc)
                RETURN(-ENOMEM);

        set.es_extent.start = ext->start;
        set.es_extent.end = ext->end;
        set.es_lsm = lsm;
        set.es_exp = cmobd->master_exp;
        set.es_ext_sz = CMOBD_MAX_EXTENT_SZ;
        set.es_count = 0;
        memcpy(&set.es_oa, oa, sizeof(*oa));
        
        INIT_LIST_HEAD(&set.es_pages);
        spin_lock_init(&set.es_lock);
        init_waitqueue_head(&set.es_waitq);
        
        if (set.es_extent.end < set.es_extent.start) {
                CDEBUG(D_HA, "illegal extent in write replay\n");
                GOTO(out, rc = -EINVAL);
        }
        /* start of extent is extended to page boundaries */
        set.es_extent.start -= set.es_extent.start & ~PAGE_MASK;
        /* if the end of extent is EOF, set it as file size */
        if (set.es_extent.end == OBD_OBJECT_EOF) {
                set.es_extent.end = cmobd_id2size(cmobd->cache_exp, 
                                                  oa->o_id, oa->o_gr) - 1;
                if (set.es_extent.end <= 0)
                        GOTO(out, rc = 0);
        }
        
        buf_count = split_extent(&set.es_extent, set.es_ext_sz);
        for (i = 0, start = set.es_extent.start; i < buf_count; 
             i++, start += set.es_ext_sz) {
                OBD_SLAB_ALLOC(ex, cmobd_extent_slab, SLAB_NOFS, sizeof(*ex));
                if (ex == NULL) {
                        CERROR("not enough memory\n");
                        break;
                }

                INIT_LIST_HEAD(&ex->ei_link);
                ex->ei_set = &set;
                ex->ei_extent.start = start;
                ex->ei_extent.end = start + set.es_ext_sz - 1;
                if (ex->ei_extent.end > set.es_extent.end)
                        ex->ei_extent.end = set.es_extent.end;

                cmobd_queue_extent(obd, ex);
        }
        
        l_wait_event(set.es_waitq, extent_set_done(&set, 1), &lwi);
        
        /* fire remaining ios */
        spin_lock_irqsave(&set.es_lock, flags);
        list_for_each_safe (pos, n, &set.es_pages) {
                cmap = list_entry(pos, struct cmobd_async_page, cmap_link);

                /* locked pages are in flight */
                if (PageLocked(cmap->cmap_page))
                        continue;
                
                spin_unlock_irqrestore(&set.es_lock, flags);
                rc = obd_set_async_flags(set.es_exp, set.es_lsm, NULL, 
                                         cmap->cmap_cookie, 
                                         ASYNC_URGENT);
                if (rc)
                        CERROR("cmobd set async flags failed\n");
                spin_lock_irqsave(&set.es_lock, flags);
                break;
        }
        spin_unlock_irqrestore(&set.es_lock, flags);

        l_wait_event(set.es_waitq, extent_set_done(&set, 2), &lwi);
out:
        cmobd_free_lsm(&lsm);
        RETURN(rc);
}
