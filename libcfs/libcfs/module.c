/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2001, 2002 Cluster File Systems, Inc.
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

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_LNET

#include <lnet/lib-lnet.h>
#include <lnet/lnet.h>
#include <libcfs/kp30.h>
#include "tracefile.h"

void
kportal_memhog_free (struct libcfs_device_userstate *ldu)
{
        cfs_page_t **level0p = &ldu->ldu_memhog_root_page;
        cfs_page_t **level1p;
        cfs_page_t **level2p;
        int           count1;
        int           count2;

        if (*level0p != NULL) {

                level1p = (cfs_page_t **)cfs_page_address(*level0p);
                count1 = 0;

                while (count1 < CFS_PAGE_SIZE/sizeof(cfs_page_t *) &&
                       *level1p != NULL) {

                        level2p = (cfs_page_t **)cfs_page_address(*level1p);
                        count2 = 0;

                        while (count2 < CFS_PAGE_SIZE/sizeof(cfs_page_t *) &&
                               *level2p != NULL) {

                                cfs_free_page(*level2p);
                                ldu->ldu_memhog_pages--;
                                level2p++;
                                count2++;
                        }

                        cfs_free_page(*level1p);
                        ldu->ldu_memhog_pages--;
                        level1p++;
                        count1++;
                }

                cfs_free_page(*level0p);
                ldu->ldu_memhog_pages--;

                *level0p = NULL;
        }

        LASSERT (ldu->ldu_memhog_pages == 0);
}

int
kportal_memhog_alloc (struct libcfs_device_userstate *ldu, int npages, int flags)
{
        cfs_page_t **level0p;
        cfs_page_t **level1p;
        cfs_page_t **level2p;
        int           count1;
        int           count2;

        LASSERT (ldu->ldu_memhog_pages == 0);
        LASSERT (ldu->ldu_memhog_root_page == NULL);

        if (npages < 0)
                return -EINVAL;

        if (npages == 0)
                return 0;

        level0p = &ldu->ldu_memhog_root_page;
        *level0p = cfs_alloc_page(flags);
        if (*level0p == NULL)
                return -ENOMEM;
        ldu->ldu_memhog_pages++;

        level1p = (cfs_page_t **)cfs_page_address(*level0p);
        count1 = 0;
        memset(level1p, 0, CFS_PAGE_SIZE);

        while (ldu->ldu_memhog_pages < npages &&
               count1 < CFS_PAGE_SIZE/sizeof(cfs_page_t *)) {

                if (cfs_signal_pending())
                        return (-EINTR);

                *level1p = cfs_alloc_page(flags);
                if (*level1p == NULL)
                        return -ENOMEM;
                ldu->ldu_memhog_pages++;

                level2p = (cfs_page_t **)cfs_page_address(*level1p);
                count2 = 0;
                memset(level2p, 0, CFS_PAGE_SIZE);

                while (ldu->ldu_memhog_pages < npages &&
                       count2 < CFS_PAGE_SIZE/sizeof(cfs_page_t *)) {

                        if (cfs_signal_pending())
                                return (-EINTR);

                        *level2p = cfs_alloc_page(flags);
                        if (*level2p == NULL)
                                return (-ENOMEM);
                        ldu->ldu_memhog_pages++;

                        level2p++;
                        count2++;
                }

                level1p++;
                count1++;
        }

        return 0;
}

/* called when opening /dev/device */
static int libcfs_psdev_open(unsigned long flags, void *args)
{
        struct libcfs_device_userstate *ldu;
        ENTRY;

        PORTAL_MODULE_USE;

        LIBCFS_ALLOC(ldu, sizeof(*ldu));
        if (ldu != NULL) {
                ldu->ldu_memhog_pages = 0;
                ldu->ldu_memhog_root_page = NULL;
        }
        *(struct libcfs_device_userstate **)args = ldu;

        RETURN(0);
}

/* called when closing /dev/device */
static int libcfs_psdev_release(unsigned long flags, void *args)
{
        struct libcfs_device_userstate *ldu;
        ENTRY;

        ldu = (struct libcfs_device_userstate *)args;
        if (ldu != NULL) {
                kportal_memhog_free(ldu);
                LIBCFS_FREE(ldu, sizeof(*ldu));
        }

        PORTAL_MODULE_UNUSE;
        RETURN(0);
}

static struct rw_semaphore ioctl_list_sem;
static struct list_head ioctl_list;

int libcfs_register_ioctl(struct libcfs_ioctl_handler *hand)
{
        int rc = 0;

        down_write(&ioctl_list_sem);
        if (!list_empty(&hand->item))
                rc = -EBUSY;
        else
                list_add_tail(&hand->item, &ioctl_list);
        up_write(&ioctl_list_sem);

        return rc;
}
EXPORT_SYMBOL(libcfs_register_ioctl);

int libcfs_deregister_ioctl(struct libcfs_ioctl_handler *hand)
{
        int rc = 0;

        down_write(&ioctl_list_sem);
        if (list_empty(&hand->item))
                rc = -ENOENT;
        else
                list_del_init(&hand->item);
        up_write(&ioctl_list_sem);

        return rc;
}
EXPORT_SYMBOL(libcfs_deregister_ioctl);

static int libcfs_ioctl(struct cfs_psdev_file *pfile, unsigned long cmd, void *arg)
{
        char    buf[1024];
        int err = -EINVAL;
        struct libcfs_ioctl_data *data;
        ENTRY;

        /* 'cmd' and permissions get checked in our arch-specific caller */

        if (libcfs_ioctl_getdata(buf, buf + 800, (void *)arg)) {
                CERROR("PORTALS ioctl: data error\n");
                RETURN(-EINVAL);
        }
        data = (struct libcfs_ioctl_data *)buf;

        switch (cmd) {
        case IOC_LIBCFS_CLEAR_DEBUG:
                libcfs_debug_clear_buffer();
                RETURN(0);
        /*
         * case IOC_LIBCFS_PANIC:
         * Handled in arch/cfs_module.c
         */
        case IOC_LIBCFS_MARK_DEBUG:
                if (data->ioc_inlbuf1 == NULL ||
                    data->ioc_inlbuf1[data->ioc_inllen1 - 1] != '\0')
                        RETURN(-EINVAL);
                libcfs_debug_mark_buffer(data->ioc_inlbuf1);
                RETURN(0);
#if LWT_SUPPORT
        case IOC_LIBCFS_LWT_CONTROL:
                err = lwt_control ((data->ioc_flags & 1) != 0, 
                                   (data->ioc_flags & 2) != 0);
                break;

        case IOC_LIBCFS_LWT_SNAPSHOT: {
                cycles_t   now;
                int        ncpu;
                int        total_size;

                err = lwt_snapshot (&now, &ncpu, &total_size,
                                    data->ioc_pbuf1, data->ioc_plen1);
                data->ioc_u64[0] = now;
                data->ioc_u32[0] = ncpu;
                data->ioc_u32[1] = total_size;

                /* Hedge against broken user/kernel typedefs (e.g. cycles_t) */
                data->ioc_u32[2] = sizeof(lwt_event_t);
                data->ioc_u32[3] = offsetof(lwt_event_t, lwte_where);

                if (err == 0 &&
                    libcfs_ioctl_popdata(arg, data, sizeof (*data)))
                        err = -EFAULT;
                break;
        }

        case IOC_LIBCFS_LWT_LOOKUP_STRING:
                err = lwt_lookup_string (&data->ioc_count, data->ioc_pbuf1,
                                         data->ioc_pbuf2, data->ioc_plen2);
                if (err == 0 &&
                    libcfs_ioctl_popdata(arg, data, sizeof (*data)))
                        err = -EFAULT;
                break;
#endif
        case IOC_LIBCFS_MEMHOG:
                if (pfile->private_data == NULL) {
                        err = -EINVAL;
                } else {
                        kportal_memhog_free(pfile->private_data);
                        /* XXX The ioc_flags is not GFP flags now, need to be fixed */
                        err = kportal_memhog_alloc(pfile->private_data,
                                                   data->ioc_count,
                                                   data->ioc_flags);
                        if (err != 0)
                                kportal_memhog_free(pfile->private_data);
                }
                break;

        case IOC_LIBCFS_PING_TEST: {
                extern void (kping_client)(struct libcfs_ioctl_data *);
                void (*ping)(struct libcfs_ioctl_data *);

                CDEBUG(D_IOCTL, "doing %d pings to nid %s (%s)\n",
                       data->ioc_count, libcfs_nid2str(data->ioc_nid),
                       libcfs_nid2str(data->ioc_nid));
                ping = PORTAL_SYMBOL_GET(kping_client);
                if (!ping)
                        CERROR("PORTAL_SYMBOL_GET failed\n");
                else {
                        ping(data);
                        PORTAL_SYMBOL_PUT(kping_client);
                }
                RETURN(0);
        }

        default: {
                struct libcfs_ioctl_handler *hand;
                err = -EINVAL;
                down_read(&ioctl_list_sem);
                list_for_each_entry(hand, &ioctl_list, item) {
                        err = hand->handle_ioctl(cmd, data);
                        if (err != -EINVAL) {
                                if (err == 0)
                                        err = libcfs_ioctl_popdata(arg, 
                                                        data, sizeof (*data));
                                break;
                        }
                }
                up_read(&ioctl_list_sem);
                break;
        }
        }

        RETURN(err);
}

struct cfs_psdev_ops libcfs_psdev_ops = {
        libcfs_psdev_open,
        libcfs_psdev_release,
        NULL,
        NULL,
        libcfs_ioctl
};

extern int insert_proc(void);
extern void remove_proc(void);
MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

extern cfs_psdev_t libcfs_dev;
extern struct rw_semaphore tracefile_sem;
extern struct semaphore trace_thread_sem;

extern void libcfs_init_nidstrings(void);
extern int libcfs_arch_init(void);
extern void libcfs_arch_cleanup(void);

static int init_libcfs_module(void)
{
        int rc;

        libcfs_arch_init();
        libcfs_init_nidstrings();
        init_rwsem(&tracefile_sem);
        init_mutex(&trace_thread_sem);
        init_rwsem(&ioctl_list_sem);
        CFS_INIT_LIST_HEAD(&ioctl_list);

        rc = libcfs_debug_init(5 * 1024 * 1024);
        if (rc < 0) {
                printk(KERN_ERR "LustreError: libcfs_debug_init: %d\n", rc);
                return (rc);
        }

#if LWT_SUPPORT
        rc = lwt_init();
        if (rc != 0) {
                CERROR("lwt_init: error %d\n", rc);
                goto cleanup_debug;
        }
#endif
        rc = cfs_psdev_register(&libcfs_dev);
        if (rc) {
                CERROR("misc_register: error %d\n", rc);
                goto cleanup_lwt;
        }

        rc = insert_proc();
        if (rc) {
                CERROR("insert_proc: error %d\n", rc);
                goto cleanup_deregister;
        }

        CDEBUG (D_OTHER, "portals setup OK\n");
        return (0);

 cleanup_deregister:
        cfs_psdev_deregister(&libcfs_dev);
 cleanup_lwt:
#if LWT_SUPPORT
        lwt_fini();
 cleanup_debug:
#endif
        libcfs_debug_cleanup();
        return rc;
}

static void exit_libcfs_module(void)
{
        int rc;

        remove_proc();

        CDEBUG(D_MALLOC, "before Portals cleanup: kmem %d\n",
               atomic_read(&libcfs_kmemory));

        rc = cfs_psdev_deregister(&libcfs_dev);
        if (rc)
                CERROR("misc_deregister error %d\n", rc);

#if LWT_SUPPORT
        lwt_fini();
#endif

        if (atomic_read(&libcfs_kmemory) != 0)
                CERROR("Portals memory leaked: %d bytes\n",
                       atomic_read(&libcfs_kmemory));

        rc = libcfs_debug_cleanup();
        if (rc)
                printk(KERN_ERR "LustreError: libcfs_debug_cleanup: %d\n", rc);
        libcfs_arch_cleanup();
}

cfs_module(libcfs, "1.0.0", init_libcfs_module, exit_libcfs_module);
