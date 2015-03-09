/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#define DEBUG_SUBSYSTEM S_LNET

#include <libcfs/libcfs.h>
#include <libcfs/libcfs_crypto.h>
#include <lnet/lib-lnet.h>
#include <lnet/lib-dlc.h>
#include <lnet/lnet.h>
#include <lnet/nidstr.h>

static void
kportal_memhog_free (struct libcfs_device_userstate *ldu)
{
	struct page **level0p = &ldu->ldu_memhog_root_page;
	struct page **level1p;
	struct page **level2p;
	int           count1;
	int           count2;

	if (*level0p != NULL) {
		level1p = (struct page **)page_address(*level0p);
		count1 = 0;

		while (count1 < PAGE_CACHE_SIZE/sizeof(struct page *) &&
		       *level1p != NULL) {

			level2p = (struct page **)page_address(*level1p);
			count2 = 0;

			while (count2 < PAGE_CACHE_SIZE/sizeof(struct page *) &&
			       *level2p != NULL) {

				__free_page(*level2p);
				ldu->ldu_memhog_pages--;
				level2p++;
				count2++;
			}

			__free_page(*level1p);
			ldu->ldu_memhog_pages--;
			level1p++;
			count1++;
		}

		__free_page(*level0p);
		ldu->ldu_memhog_pages--;

		*level0p = NULL;
	}

	LASSERT(ldu->ldu_memhog_pages == 0);
}

static int
kportal_memhog_alloc(struct libcfs_device_userstate *ldu, int npages,
		     gfp_t flags)
{
	struct page **level0p;
	struct page **level1p;
	struct page **level2p;
	int           count1;
	int           count2;

	LASSERT(ldu->ldu_memhog_pages == 0);
	LASSERT(ldu->ldu_memhog_root_page == NULL);

	if (npages < 0)
		return -EINVAL;

	if (npages == 0)
		return 0;

	level0p = &ldu->ldu_memhog_root_page;
	*level0p = alloc_page(flags);
	if (*level0p == NULL)
		return -ENOMEM;
	ldu->ldu_memhog_pages++;

	level1p = (struct page **)page_address(*level0p);
	count1 = 0;
	memset(level1p, 0, PAGE_CACHE_SIZE);

	while (ldu->ldu_memhog_pages < npages &&
	       count1 < PAGE_CACHE_SIZE/sizeof(struct page *)) {

		if (cfs_signal_pending())
			return -EINTR;

		*level1p = alloc_page(flags);
		if (*level1p == NULL)
			return -ENOMEM;
		ldu->ldu_memhog_pages++;

		level2p = (struct page **)page_address(*level1p);
		count2 = 0;
		memset(level2p, 0, PAGE_CACHE_SIZE);

		while (ldu->ldu_memhog_pages < npages &&
		       count2 < PAGE_CACHE_SIZE/sizeof(struct page *)) {

			if (cfs_signal_pending())
				return -EINTR;

			*level2p = alloc_page(flags);
			if (*level2p == NULL)
				return -ENOMEM;
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

	try_module_get(THIS_MODULE);

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

	module_put(THIS_MODULE);
	RETURN(0);
}

static DECLARE_RWSEM(ioctl_list_sem);
static LIST_HEAD(ioctl_list);

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

static int libcfs_ioctl(struct cfs_psdev_file *pfile,
			unsigned long cmd, void __user *uparam)
{
	struct libcfs_ioctl_data *data = NULL;
	struct libcfs_ioctl_hdr  *hdr;
	int			  err;
	ENTRY;

	/* 'cmd' and permissions get checked in our arch-specific caller */
	err = libcfs_ioctl_getdata(&hdr, uparam);
	if (err != 0) {
		CDEBUG_LIMIT(D_ERROR,
			     "libcfs ioctl: data header error %d\n", err);
		RETURN(err);
	}

	if (hdr->ioc_version == LIBCFS_IOCTL_VERSION) {
		/* The libcfs_ioctl_data_adjust() function performs adjustment
		 * operations on the libcfs_ioctl_data structure to make
		 * it usable by the code.  This doesn't need to be called
		 * for new data structures added. */
		data = container_of(hdr, struct libcfs_ioctl_data, ioc_hdr);
		err = libcfs_ioctl_data_adjust(data);
		if (err != 0)
			GOTO(out, err);
	}

	CDEBUG(D_IOCTL, "libcfs ioctl cmd %lu\n", cmd);
	switch (cmd) {
	case IOC_LIBCFS_CLEAR_DEBUG:
		libcfs_debug_clear_buffer();
		break;
	/*
	 * case IOC_LIBCFS_PANIC:
	 * Handled in arch/cfs_module.c
	 */
	case IOC_LIBCFS_MARK_DEBUG:
		if (data == NULL ||
		    data->ioc_inlbuf1 == NULL ||
		    data->ioc_inlbuf1[data->ioc_inllen1 - 1] != '\0')
			GOTO(out, err = -EINVAL);

		libcfs_debug_mark_buffer(data->ioc_inlbuf1);
		break;

	case IOC_LIBCFS_MEMHOG:
		if (data == NULL)
			GOTO(out, err = -EINVAL);

		if (pfile->private_data == NULL)
			GOTO(out, err = -EINVAL);

		kportal_memhog_free(pfile->private_data);
		err = kportal_memhog_alloc(pfile->private_data,
					   data->ioc_count, data->ioc_flags);
		if (err != 0)
			kportal_memhog_free(pfile->private_data);
		break;

	default: {
		struct libcfs_ioctl_handler *hand;

		err = -EINVAL;
		down_read(&ioctl_list_sem);
		list_for_each_entry(hand, &ioctl_list, item) {
			err = hand->handle_ioctl(cmd, hdr);
			if (err == -EINVAL)
				continue;

			if (err == 0)
				err = libcfs_ioctl_popdata(hdr, uparam);
			break;
		}
		up_read(&ioctl_list_sem);
		break; }
	}
out:
	libcfs_ioctl_freedata(hdr);
	RETURN(err);
}

struct cfs_psdev_ops libcfs_psdev_ops = {
        libcfs_psdev_open,
        libcfs_psdev_release,
        NULL,
        NULL,
        libcfs_ioctl
};

MODULE_AUTHOR("Peter J. Braam <braam@clusterfs.com>");
MODULE_DESCRIPTION("Portals v3.1");
MODULE_LICENSE("GPL");

static int init_libcfs_module(void)
{
	int rc;

	libcfs_arch_init();
	libcfs_init_nidstrings();

	rc = libcfs_debug_init(5 * 1024 * 1024);
	if (rc < 0) {
		printk(KERN_ERR "LustreError: libcfs_debug_init: %d\n", rc);
		return (rc);
	}

	rc = cfs_cpu_init();
	if (rc != 0)
		goto cleanup_debug;

	rc = misc_register(&libcfs_dev);
	if (rc) {
		CERROR("misc_register: error %d\n", rc);
		goto cleanup_cpu;
	}

	rc = cfs_wi_startup();
	if (rc) {
		CERROR("initialize workitem: error %d\n", rc);
		goto cleanup_deregister;
	}

	/* max to 4 threads, should be enough for rehash */
	rc = min(cfs_cpt_weight(cfs_cpt_table, CFS_CPT_ANY), 4);
	rc = cfs_wi_sched_create("cfs_rh", cfs_cpt_table, CFS_CPT_ANY,
				 rc, &cfs_sched_rehash);
	if (rc != 0) {
		CERROR("Startup workitem scheduler: error: %d\n", rc);
		goto cleanup_deregister;
	}

	rc = cfs_crypto_register();
	if (rc) {
		CERROR("cfs_crypto_regster: error %d\n", rc);
		goto cleanup_wi;
	}


	rc = insert_proc();
	if (rc) {
		CERROR("insert_proc: error %d\n", rc);
		goto cleanup_crypto;
	}

	CDEBUG (D_OTHER, "portals setup OK\n");
	return 0;
cleanup_crypto:
	cfs_crypto_unregister();
cleanup_wi:
	cfs_wi_shutdown();
cleanup_deregister:
	misc_deregister(&libcfs_dev);
cleanup_cpu:
	cfs_cpu_fini();
cleanup_debug:
	libcfs_debug_cleanup();
	return rc;
}

static void exit_libcfs_module(void)
{
	int rc;

	remove_proc();

	CDEBUG(D_MALLOC, "before Portals cleanup: kmem %d\n",
	       atomic_read(&libcfs_kmemory));

	if (cfs_sched_rehash != NULL) {
		cfs_wi_sched_destroy(cfs_sched_rehash);
		cfs_sched_rehash = NULL;
	}

	cfs_crypto_unregister();
	cfs_wi_shutdown();

	rc = misc_deregister(&libcfs_dev);
	if (rc)
		CERROR("misc_deregister error %d\n", rc);

	cfs_cpu_fini();

	if (atomic_read(&libcfs_kmemory) != 0)
		CERROR("Portals memory leaked: %d bytes\n",
		       atomic_read(&libcfs_kmemory));

	rc = libcfs_debug_cleanup();
	if (rc)
		printk(KERN_ERR "LustreError: libcfs_debug_cleanup: %d\n",
		       rc);

	libcfs_arch_cleanup();
}

cfs_module(libcfs, "1.0.0", init_libcfs_module, exit_libcfs_module);
