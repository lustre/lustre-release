// SPDX-License-Identifier: GPL-2.0

/* Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2017, Intel Corporation.
 */

/* This file is part of Lustre, http://www.lustre.org/ */

#define DEBUG_SUBSYSTEM S_LNET

#include <linux/miscdevice.h>
#include <lnet/lib-lnet.h>
#include <uapi/linux/lnet/lnet-dlc.h>

static int config_on_load = 0;
module_param(config_on_load, int, 0444);
MODULE_PARM_DESC(config_on_load, "configure network at module load");

static DEFINE_MUTEX(lnet_config_mutex);

int lnet_configure(void *arg)
{
	/* 'arg' only there so I can be passed to cfs_create_thread() */
	int    rc = 0;

	mutex_lock(&lnet_config_mutex);

	if (!the_lnet.ln_niinit_self) {
		rc = try_module_get(THIS_MODULE);

		if (rc != 1)
			goto out;

		rc = LNetNIInit(LNET_PID_LUSTRE);
		if (rc >= 0) {
			the_lnet.ln_niinit_self = 1;
			rc = 0;
		} else {
			module_put(THIS_MODULE);
		}
	}

out:
	mutex_unlock(&lnet_config_mutex);
	return rc;
}

int lnet_unconfigure(void)
{
	int refcount;

	mutex_lock(&lnet_config_mutex);

	if (the_lnet.ln_niinit_self) {
		the_lnet.ln_niinit_self = 0;
		LNetNIFini();
		module_put(THIS_MODULE);
	}

	mutex_lock(&the_lnet.ln_api_mutex);
	refcount = the_lnet.ln_refcount;
	mutex_unlock(&the_lnet.ln_api_mutex);

	mutex_unlock(&lnet_config_mutex);

	return (refcount == 0) ? 0 : -EBUSY;
}

static int
lnet_dyn_configure_net(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_data *conf =
	  (struct lnet_ioctl_config_data *)hdr;
	int			      rc;

	if (conf->cfg_hdr.ioc_len < sizeof(*conf))
		return -EINVAL;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_add_net(conf);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_dyn_unconfigure_net(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_data *conf =
	  (struct lnet_ioctl_config_data *) hdr;
	int			      rc;

	if (conf->cfg_hdr.ioc_len < sizeof(*conf))
		return -EINVAL;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_del_net(conf->cfg_net);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_dyn_configure_ni(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_ni *conf =
	  (struct lnet_ioctl_config_ni *)hdr;
	int rc = -EINVAL;

	if (conf->lic_cfg_hdr.ioc_len < sizeof(*conf))
		return rc;

	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self) {
		struct lnet_ioctl_config_lnd_tunables *tun = NULL;
		struct lnet_nid nid;
		u32 net_id;

		/* get the tunables if they are available */
		if (conf->lic_cfg_hdr.ioc_len >=
		    sizeof(*conf) + sizeof(*tun))
			tun = (struct lnet_ioctl_config_lnd_tunables *) conf->lic_bulk;

		lnet_nid4_to_nid(conf->lic_nid, &nid);
		net_id = LNET_NID_NET(&nid);
		rc = lnet_dyn_add_ni(conf, net_id, &LNET_ANY_NID, tun);
	}
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_dyn_unconfigure_ni(struct libcfs_ioctl_hdr *hdr)
{
	struct lnet_ioctl_config_ni *conf =
	  (struct lnet_ioctl_config_ni *) hdr;
	struct lnet_nid nid;
	int rc = -EINVAL;

	if (conf->lic_cfg_hdr.ioc_len < sizeof(*conf) ||
	    !the_lnet.ln_niinit_self)
		return rc;

	lnet_nid4_to_nid(conf->lic_nid, &nid);
	mutex_lock(&lnet_config_mutex);
	if (the_lnet.ln_niinit_self)
		rc = lnet_dyn_del_ni(&nid);
	else
		rc = -EINVAL;
	mutex_unlock(&lnet_config_mutex);

	return rc;
}

static int
lnet_ioctl(unsigned int cmd, struct libcfs_ioctl_hdr *hdr)
{
	int rc;

	switch (cmd) {
	case IOC_LIBCFS_CONFIGURE: {
		struct libcfs_ioctl_data *data =
		  (struct libcfs_ioctl_data *)hdr;

		if (data->ioc_hdr.ioc_len < sizeof(*data)) {
			rc = -EINVAL;
		} else {
			the_lnet.ln_nis_from_mod_params = data->ioc_flags;
			rc = lnet_configure(NULL);
		}
		break;
	}

	case IOC_LIBCFS_UNCONFIGURE:
		rc = lnet_unconfigure();
		break;

	case IOC_LIBCFS_ADD_NET:
		rc = lnet_dyn_configure_net(hdr);
		break;

	case IOC_LIBCFS_DEL_NET:
		rc = lnet_dyn_unconfigure_net(hdr);
		break;

	case IOC_LIBCFS_ADD_LOCAL_NI:
		rc = lnet_dyn_configure_ni(hdr);
		break;

	case IOC_LIBCFS_DEL_LOCAL_NI:
		rc = lnet_dyn_unconfigure_ni(hdr);
		break;

	default:
		/* Passing LNET_PID_ANY only gives me a ref if the net is up
		 * already; I'll need it to ensure the net can't go down while
		 * I'm called into it */
		rc = LNetNIInit(LNET_PID_ANY);
		if (rc >= 0) {
			rc = LNetCtl(cmd, hdr);
			LNetNIFini();
		}
		break;
	}
	return rc;
}
BLOCKING_NOTIFIER_HEAD(lnet_ioctl_list);
EXPORT_SYMBOL(lnet_ioctl_list);

static inline size_t lnet_ioctl_packlen(struct libcfs_ioctl_data *data)
{
	size_t len = sizeof(*data);

	len += (data->ioc_inllen1 + 7) & ~7;
	len += (data->ioc_inllen2 + 7) & ~7;
	return len;
}

static bool lnet_ioctl_is_invalid(struct libcfs_ioctl_data *data)
{
	const int maxlen = 1 << 30;

	if (data->ioc_hdr.ioc_len > maxlen)
		return true;

	if (data->ioc_inllen1 > maxlen)
		return true;

	if (data->ioc_inllen2 > maxlen)
		return true;

	if (data->ioc_inlbuf1 && !data->ioc_inllen1)
		return true;

	if (data->ioc_inlbuf2 && !data->ioc_inllen2)
		return true;

	if (data->ioc_pbuf1 && !data->ioc_plen1)
		return true;

	if (data->ioc_pbuf2 && !data->ioc_plen2)
		return true;

	if (data->ioc_plen1 && !data->ioc_pbuf1)
		return true;

	if (data->ioc_plen2 && !data->ioc_pbuf2)
		return true;

	if (lnet_ioctl_packlen(data) != data->ioc_hdr.ioc_len)
		return true;

	if (data->ioc_inllen1 &&
		data->ioc_bulk[((data->ioc_inllen1 + 7) & ~7) +
			       data->ioc_inllen2 - 1] != '\0')
		return true;

	return false;
}

static int lnet_ioctl_data_adjust(struct libcfs_ioctl_data *data)
{
	ENTRY;

	if (lnet_ioctl_is_invalid(data)) {
		CERROR("lnet ioctl: parameter not correctly formatted\n");
		RETURN(-EINVAL);
	}

	if (data->ioc_inllen1 != 0)
		data->ioc_inlbuf1 = &data->ioc_bulk[0];

	if (data->ioc_inllen2 != 0)
		data->ioc_inlbuf2 = (&data->ioc_bulk[0] +
				     round_up(data->ioc_inllen1, 8));

	RETURN(0);
}

static int lnet_ioctl_getdata(struct libcfs_ioctl_hdr **hdr_pp,
			      struct libcfs_ioctl_hdr __user *uhdr)
{
	struct libcfs_ioctl_hdr hdr;
	int err;

	ENTRY;
	if (copy_from_user(&hdr, uhdr, sizeof(hdr)))
		RETURN(-EFAULT);

	if (hdr.ioc_version != LNET_IOCTL_VERSION &&
	    hdr.ioc_version != LNET_IOCTL_VERSION2) {
		CERROR("lnet ioctl: version mismatch expected %#x, got %#x\n",
		       LNET_IOCTL_VERSION, hdr.ioc_version);
		RETURN(-EINVAL);
	}

	if (hdr.ioc_len < sizeof(struct libcfs_ioctl_hdr)) {
		CERROR("lnet ioctl: user buffer too small for ioctl\n");
		RETURN(-EINVAL);
	}

	if (hdr.ioc_len > LIBCFS_IOC_DATA_MAX) {
		CERROR("lnet ioctl: user buffer is too large %d/%d\n",
		       hdr.ioc_len, LIBCFS_IOC_DATA_MAX);
		RETURN(-EINVAL);
	}

	LIBCFS_ALLOC(*hdr_pp, hdr.ioc_len);
	if (*hdr_pp == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(*hdr_pp, uhdr, hdr.ioc_len))
		GOTO(free, err = -EFAULT);

	if ((*hdr_pp)->ioc_version != hdr.ioc_version ||
		(*hdr_pp)->ioc_len != hdr.ioc_len) {
		GOTO(free, err = -EINVAL);
	}

	RETURN(0);

free:
	LIBCFS_FREE(*hdr_pp, hdr.ioc_len);
	RETURN(err);
}

static long
lnet_psdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct libcfs_ioctl_data *data = NULL;
	struct libcfs_ioctl_hdr  *hdr;
	int			  err;
	void __user		 *uparam = (void __user *)arg;

	ENTRY;
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	if (_IOC_TYPE(cmd) != IOC_LIBCFS_TYPE ||
	    _IOC_NR(cmd) < IOC_LIBCFS_MIN_NR  ||
	    _IOC_NR(cmd) > IOC_LIBCFS_MAX_NR) {
		CDEBUG(D_IOCTL, "invalid ioctl ( type %d, nr %d, size %d )\n",
		       _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
		return -EINVAL;
	}

	/* 'cmd' and permissions get checked in our arch-specific caller */
	err = lnet_ioctl_getdata(&hdr, uparam);
	if (err != 0) {
		CDEBUG_LIMIT(D_ERROR,
			     "lnet ioctl: data header error %d\n", err);
		RETURN(err);
	}

	if (hdr->ioc_version == LNET_IOCTL_VERSION) {
		/* The lnet_ioctl_data_adjust() function performs adjustment
		 * operations on the libcfs_ioctl_data structure to make
		 * it usable by the code.  This doesn't need to be called
		 * for new data structures added.
		 */
		data = container_of(hdr, struct libcfs_ioctl_data, ioc_hdr);
		err = lnet_ioctl_data_adjust(data);
		if (err != 0)
			GOTO(out, err);
	}

	CDEBUG(D_IOCTL, "lnet ioctl cmd %u\n", cmd);

	err = libcfs_ioctl(cmd, data);
	if (err == -EINVAL)
		err = lnet_ioctl(cmd, hdr);
	if (err == -EINVAL) {
		err = blocking_notifier_call_chain(&lnet_ioctl_list,
						   cmd, hdr);
		if (!(err & NOTIFY_STOP_MASK))
			/* No-one claimed the ioctl */
			err = -EINVAL;
		else
			err = notifier_to_errno(err);
	}
	if (copy_to_user(uparam, hdr, hdr->ioc_len) && !err)
		err = -EFAULT;
out:
	LIBCFS_FREE(hdr, hdr->ioc_len);
	RETURN(err);
}

static const struct file_operations lnet_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= lnet_psdev_ioctl,
};

static struct miscdevice lnet_dev = {
	.minor			= MISC_DYNAMIC_MINOR,
	.name			= "lnet",
	.fops			= &lnet_fops,
};

static int __init lnet_init(void)
{
	int rc;

	ENTRY;
	rc = libcfs_setup();
	if (rc)
		return rc;

	rc = cfs_cpu_init();
	if (rc < 0) {
		CERROR("cfs_cpu_init: rc = %d\n", rc);
		RETURN(rc);
	}

	rc = lnet_lib_init();
	if (rc != 0) {
		CERROR("lnet_lib_init: rc = %d\n", rc);
		cfs_cpu_fini();
		RETURN(rc);
	}

	rc = misc_register(&lnet_dev);
	if (rc) {
		CERROR("misc_register: rc = %d\n", rc);
		cfs_cpu_fini();
		RETURN(rc);
	}

	if (live_router_check_interval != INT_MIN ||
	    dead_router_check_interval != INT_MIN)
		LCONSOLE_WARN("live_router_check_interval and dead_router_check_interval have been deprecated. Use alive_router_check_interval instead. Ignoring these deprecated parameters.\n");

	if (config_on_load) {
		/* Have to schedule a separate thread to avoid deadlocking
		 * in modload */
		(void)kthread_run(lnet_configure, NULL, "lnet_initd");
	}

	RETURN(0);
}

static void __exit lnet_exit(void)
{
	misc_deregister(&lnet_dev);

	lnet_router_exit();
	lnet_lib_exit();
	cfs_cpu_fini();
}

MODULE_AUTHOR("OpenSFS, Inc. <http://www.lustre.org/>");
MODULE_DESCRIPTION("Lustre Networking layer");
MODULE_VERSION(LNET_VERSION);
MODULE_LICENSE("GPL");

module_init(lnet_init);
module_exit(lnet_exit);
