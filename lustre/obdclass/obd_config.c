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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * lustre/obdclass/obd_config.c
 *
 * Config API
 */

#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/kobject.h>
#include <linux/string.h>

#include <llog_swab.h>
#include <lprocfs_status.h>
#include <lustre_disk.h>
#include <uapi/linux/lustre/lustre_ioctl.h>
#include <lustre_log.h>
#include <uapi/linux/lustre/lustre_param.h>
#include <obd_class.h>

#include "llog_internal.h"

#ifdef HAVE_SERVER_SUPPORT
static struct cfs_hash_ops nid_stat_hash_ops;
static struct cfs_hash_ops gen_hash_ops;
#endif /* HAVE_SERVER_SUPPORT */

/*
 * uuid<->export lustre hash operations
 */
/*
 * NOTE: It is impossible to find an export that is in failed
 *      state with this function
 */
static int
uuid_keycmp(struct rhashtable_compare_arg *arg, const void *obj)
{
	const struct obd_uuid *uuid = arg->key;
	const struct obd_export *exp = obj;

	if (obd_uuid_equals(uuid, &exp->exp_client_uuid) &&
	    !exp->exp_failed)
		return 0;
	return -ESRCH;
}

static void
obd_export_exit(void *vexport, void *data)
{
	struct obd_export *exp = vexport;

	class_export_put(exp);
}

static const struct rhashtable_params uuid_hash_params = {
	.key_len	= sizeof(struct obd_uuid),
	.key_offset	= offsetof(struct obd_export, exp_client_uuid),
	.head_offset	= offsetof(struct obd_export, exp_uuid_hash),
	.obj_cmpfn	= uuid_keycmp,
	.max_size	= MAX_OBD_DEVICES,
	.automatic_shrinking = true,
};

int obd_uuid_add(struct obd_device *obd, struct obd_export *export)
{
	int rc;

	class_export_get(export);
	rcu_read_lock();
	rc = rhashtable_lookup_insert_fast(&obd->obd_uuid_hash,
					   &export->exp_uuid_hash,
					   uuid_hash_params);
	if (rc) {
		class_export_put(export);
		if (rc != -EEXIST) {
			/* map obscure error codes to -ENOMEM */
			rc = -ENOMEM;
		} else {
			rc = -EALREADY;
		}
	}
	rcu_read_unlock();

	return rc;
}
EXPORT_SYMBOL(obd_uuid_add);

void obd_uuid_del(struct obd_device *obd, struct obd_export *export)
{
	int rc;

	rcu_read_lock();
	rc = rhashtable_remove_fast(&obd->obd_uuid_hash,
				    &export->exp_uuid_hash,
				    uuid_hash_params);
	if (!rc)
		class_export_put(export);
	rcu_read_unlock();
}
EXPORT_SYMBOL(obd_uuid_del);

#ifdef HAVE_SERVER_SUPPORT
/* obd_uuid_lookup() is used only server side by target_handle_connect(),
 * mdt_hsm_agent_send(), and obd_export_evict_by_uuid().
 */
struct obd_export *obd_uuid_lookup(struct obd_device *obd,
				   struct obd_uuid *uuid)
{
	struct obd_export *export = NULL;

	rcu_read_lock();
	export = rhashtable_lookup_fast(&obd->obd_uuid_hash, uuid,
					uuid_hash_params);
	if (export && !refcount_inc_not_zero(&export->exp_handle.h_ref))
		export = NULL;
	rcu_read_unlock();

	return export;
}
EXPORT_SYMBOL(obd_uuid_lookup);

/*
 * nid<->export hash operations
 */
static u32 nid_keyhash(const void *data, u32 key_len, u32 seed)
{
	const struct obd_export *exp = data;
	void *key;

	if (!exp->exp_connection)
		return 0;

	key = &exp->exp_connection->c_peer.nid;
	return jhash2(key, key_len / sizeof(u32), seed);
}

/*
 * NOTE: It is impossible to find an export that is in failed
 *	 state with this function
 */
static int
nid_keycmp(struct rhashtable_compare_arg *arg, const void *obj)
{
	const lnet_nid_t *nid = arg->key;
	const struct obd_export *exp = obj;

	if (exp->exp_connection->c_peer.nid == *nid)
		return 0;

	return -ESRCH;
}

static void
nid_export_exit(void *vexport, void *data)
{
	struct obd_export *exp = vexport;

	class_export_put(exp);
}

static const struct rhashtable_params nid_hash_params = {
	.key_len		= sizeof(lnet_nid_t),
	.head_offset		= offsetof(struct obd_export, exp_nid_hash),
	.obj_hashfn		= nid_keyhash,
	.obj_cmpfn		= nid_keycmp,
	.automatic_shrinking	= true,
};

int obd_nid_add(struct obd_device *obd, struct obd_export *exp)
{
	int rc;

	if (exp == exp->exp_obd->obd_self_export || exp->exp_hashed)
		return 0;

	class_export_get(exp);
	rc = rhltable_insert_key(&obd->obd_nid_hash,
				 &exp->exp_connection->c_peer.nid,
				 &exp->exp_nid_hash,
				 nid_hash_params);
	if (rc) {
		class_export_put(exp);
		/* map obscure error codes to -ENOMEM */
		rc = -ENOMEM;
	} else {
		exp->exp_hashed = 1;
	}
	return rc;
}
EXPORT_SYMBOL(obd_nid_add);

void obd_nid_del(struct obd_device *obd, struct obd_export *exp)
{
	int rc;

	if (exp == exp->exp_obd->obd_self_export || !exp->exp_hashed)
		return;

	rc = rhltable_remove(&obd->obd_nid_hash, &exp->exp_nid_hash,
			     nid_hash_params);
	if (rc == 0) {
		class_export_put(exp);
		exp->exp_hashed = 0;
	}
}
EXPORT_SYMBOL(obd_nid_del);

int obd_nid_export_for_each(struct obd_device *obd, lnet_nid_t nid,
			    int cb(struct obd_export *exp, void *data),
			    void *data)
{
	struct rhlist_head *exports, *tmp;
	struct obd_export *exp;
	int ret = 0;

	rcu_read_lock();
	exports = rhltable_lookup(&obd->obd_nid_hash, &nid, nid_hash_params);
	if (!exports) {
		ret = -ENODEV;
		goto out_unlock;
	}

	rhl_for_each_entry_rcu(exp, tmp, exports, exp_nid_hash) {
		if (!exp->exp_failed && cb(exp, data))
			ret++;
	}

out_unlock:
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(obd_nid_export_for_each);
#endif /* HAVE_SERVER_SUPPORT */

/*********** string parsing utils *********/

/* returns 0 if we find this key in the buffer, else 1 */
int class_find_param(char *buf, char *key, char **valp)
{
	char *ptr;

	if (!buf)
		return 1;

	ptr = strstr(buf, key);
	if (!ptr)
		return 1;

	if (valp)
		*valp = ptr + strlen(key);

	return 0;
}
EXPORT_SYMBOL(class_find_param);

/**
 * Check whether the proc parameter \a param is an old parameter or not from
 * the array \a ptr which contains the mapping from old parameters to new ones.
 * If it's an old one, then return the pointer to the cfg_interop_param struc-
 * ture which contains both the old and new parameters.
 *
 * \param param			proc parameter
 * \param ptr			an array which contains the mapping from
 *				old parameters to new ones
 *
 * \retval valid-pointer	pointer to the cfg_interop_param structure
 *				which contains the old and new parameters
 * \retval NULL			\a param or \a ptr is NULL,
 *				or \a param is not an old parameter
 */
struct cfg_interop_param *class_find_old_param(const char *param,
					       struct cfg_interop_param *ptr)
{
	char *value = NULL;
	int   name_len = 0;

	if (!param || !ptr)
		RETURN(NULL);

	value = strchr(param, '=');
	if (value)
		name_len = value - param;
	else
		name_len = strlen(param);

	while (ptr->old_param) {
		if (strncmp(param, ptr->old_param, name_len) == 0 &&
		    name_len == strlen(ptr->old_param))
			RETURN(ptr);
		ptr++;
	}

	RETURN(NULL);
}
EXPORT_SYMBOL(class_find_old_param);

/**
 * Finds a parameter in \a params and copies it to \a copy.
 *
 * Leading spaces are skipped. Next space or end of string is the
 * parameter terminator with the exception that spaces inside single or double
 * quotes get included into a parameter. The parameter is copied into \a copy
 * which has to be allocated big enough by a caller, quotes are stripped in
 * the copy and the copy is terminated by 0.
 *
 * On return \a params is set to next parameter or to NULL if last
 * parameter is returned.
 *
 * \retval 0 if parameter is returned in \a copy
 * \retval 1 otherwise
 * \retval -EINVAL if unbalanced quota is found
 */
int class_get_next_param(char **params, char *copy)
{
	char *q1, *q2, *str;
	int len;

	str = *params;
	while (*str == ' ')
		str++;

	if (*str == '\0') {
		*params = NULL;
		return 1;
	}

	while (1) {
		q1 = strpbrk(str, " '\"");
		if (!q1) {
			len = strlen(str);
			memcpy(copy, str, len);
			copy[len] = '\0';
			*params = NULL;
			return 0;
		}
		len = q1 - str;
		if (*q1 == ' ') {
			memcpy(copy, str, len);
			copy[len] = '\0';
			*params = str + len;
			return 0;
		}

		memcpy(copy, str, len);
		copy += len;

		/* search for the matching closing quote */
		str = q1 + 1;
		q2 = strchr(str, *q1);
		if (!q2) {
			CERROR("Unbalanced quota in parameters: \"%s\"\n",
			       *params);
			return -EINVAL;
		}
		len = q2 - str;
		memcpy(copy, str, len);
		copy += len;
		str = q2 + 1;
	}
	return 1;
}
EXPORT_SYMBOL(class_get_next_param);

/*
 * returns 0 if this is the first key in the buffer, else 1.
 * valp points to first char after key.
 */
int class_match_param(char *buf, const char *key, char **valp)
{
	if (!buf)
		return 1;

	if (memcmp(buf, key, strlen(key)) != 0)
		return 1;

	if (valp)
		*valp = buf + strlen(key);

	return 0;
}
EXPORT_SYMBOL(class_match_param);

static int parse_nid(char *buf, void *value, int quiet)
{
	lnet_nid_t *nid = (lnet_nid_t *)value;

	*nid = libcfs_str2nid(buf);
	if (*nid != LNET_NID_ANY)
		return 0;

	if (!quiet)
		LCONSOLE_ERROR_MSG(0x159, "Can't parse NID '%s'\n", buf);
	return -EINVAL;
}

static int parse_net(char *buf, void *value)
{
	__u32 *net = (__u32 *)value;

	*net = libcfs_str2net(buf);
	CDEBUG(D_INFO, "Net %s\n", libcfs_net2str(*net));
	return 0;
}

enum {
	CLASS_PARSE_NID = 1,
	CLASS_PARSE_NET,
};

/*
 * 0 is good NID,
 * 1 not found
 * < 0 error
 * endh is set to next separator
 */
static int class_parse_value(char *buf, int opc, void *value, char **endh,
			     int quiet)
{
	char *endp;
	char  tmp;
	int   rc = 0;

	if (!buf)
		return 1;
	while (*buf == ',' || *buf == ':')
		buf++;
	if (*buf == ' ' || *buf == '/' || *buf == '\0')
		return 1;

	/* NID separators or end of NIDs */
	endp = strpbrk(buf, ",: /");
	if (!endp)
		endp = buf + strlen(buf);

	tmp = *endp;
	*endp = '\0';
	switch (opc) {
	default:
		LBUG();
	case CLASS_PARSE_NID:
		rc = parse_nid(buf, value, quiet);
		break;
	case CLASS_PARSE_NET:
		rc = parse_net(buf, value);
		break;
	}
	*endp = tmp;
	if (rc != 0)
		return rc;
	if (endh)
		*endh = endp;
	return 0;
}

int class_parse_nid(char *buf, lnet_nid_t *nid, char **endh)
{
	return class_parse_value(buf, CLASS_PARSE_NID, (void *)nid, endh, 0);
}
EXPORT_SYMBOL(class_parse_nid);

int class_parse_nid_quiet(char *buf, lnet_nid_t *nid, char **endh)
{
	return class_parse_value(buf, CLASS_PARSE_NID, (void *)nid, endh, 1);
}
EXPORT_SYMBOL(class_parse_nid_quiet);

int class_parse_net(char *buf, __u32 *net, char **endh)
{
	return class_parse_value(buf, CLASS_PARSE_NET, (void *)net, endh, 0);
}

/*
 * 1 param contains key and match
 * 0 param contains key and not match
 * -1 param does not contain key
 */
int class_match_nid(char *buf, char *key, lnet_nid_t nid)
{
	lnet_nid_t tmp;
	int rc = -1;

	while (class_find_param(buf, key, &buf) == 0) {
		/*
		 * please restrict to the NIDs pertaining to
		 * the specified NIDs
		 */
		while (class_parse_nid(buf, &tmp, &buf) == 0) {
			if (tmp == nid)
				return 1;
		}
		rc = 0;
	}
	return rc;
}

int class_match_net(char *buf, char *key, __u32 net)
{
	__u32 tmp;
	int rc = -1;

	while (class_find_param(buf, key, &buf) == 0) {
		/*
		 * please restrict to the NIDs pertaining to
		 * the specified networks
		 */
		while (class_parse_net(buf, &tmp, &buf) == 0) {
			if (tmp == net)
				return 1;
		}
		rc = 0;
	}
	return rc;
}

char *lustre_cfg_string(struct lustre_cfg *lcfg, u32 index)
{
	char *s;

	if (!lcfg->lcfg_buflens[index])
		return NULL;

	s = lustre_cfg_buf(lcfg, index);
	if (!s)
		return NULL;

	/*
	 * make sure it's NULL terminated, even if this kills a char
	 * of data.  Try to use the padding first though.
	 */
	if (s[lcfg->lcfg_buflens[index] - 1] != '\0') {
		size_t last = ALIGN(lcfg->lcfg_buflens[index], 8) - 1;
		char lost;

		/* Use the smaller value */
		if (last > lcfg->lcfg_buflens[index])
			last = lcfg->lcfg_buflens[index];

		lost = s[last];
		s[last] = '\0';
		if (lost != '\0') {
			CWARN("Truncated buf %d to '%s' (lost '%c'...)\n",
			      index, s, lost);
		}
	}
	return s;
}
EXPORT_SYMBOL(lustre_cfg_string);

/********************** class fns **********************/

/**
 * Create a new OBD device and set the type, name and uuid.  If successful,
 * the new device can be accessed by either name or uuid.
 */
int class_attach(struct lustre_cfg *lcfg)
{
	struct obd_export *exp;
	struct obd_device *obd = NULL;
	char *typename, *name, *uuid;
	int rc, len;

	ENTRY;

	if (!LUSTRE_CFG_BUFLEN(lcfg, 1)) {
		CERROR("No type passed!\n");
		RETURN(-EINVAL);
	}
	typename = lustre_cfg_string(lcfg, 1);

	if (!LUSTRE_CFG_BUFLEN(lcfg, 0)) {
		CERROR("No name passed!\n");
		RETURN(-EINVAL);
	}
	name = lustre_cfg_string(lcfg, 0);
	if (!LUSTRE_CFG_BUFLEN(lcfg, 2)) {
		CERROR("No UUID passed!\n");
		RETURN(-EINVAL);
	}

	uuid = lustre_cfg_string(lcfg, 2);
	len = strlen(uuid);
	if (len >= sizeof(obd->obd_uuid)) {
		CERROR("%s: uuid must be < %d bytes long\n",
		       name, (int)sizeof(obd->obd_uuid));
		RETURN(-EINVAL);
	}

	obd = class_newdev(typename, name, uuid);
	if (IS_ERR(obd)) { /* Already exists or out of obds */
		rc = PTR_ERR(obd);
		CERROR("Cannot create device %s of type %s : %d\n",
		       name, typename, rc);
		RETURN(rc);
	}
	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
		 "obd %p obd_magic %08X != %08X\n",
		 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
	LASSERTF(strncmp(obd->obd_name, name, strlen(name)) == 0,
		 "%p obd_name %s != %s\n", obd, obd->obd_name, name);

	exp = class_new_export_self(obd, &obd->obd_uuid);
	if (IS_ERR(exp)) {
		rc = PTR_ERR(exp);
		class_free_dev(obd);
		RETURN(rc);
	}

	obd->obd_self_export = exp;
	list_del_init(&exp->exp_obd_chain_timed);
	class_export_put(exp);

	rc = class_register_device(obd);
	if (rc != 0) {
		class_decref(obd, "newdev", obd);
		RETURN(rc);
	}

	obd->obd_attached = 1;
	CDEBUG(D_IOCTL, "OBD: dev %d attached type %s with refcount %d\n",
	       obd->obd_minor, typename, atomic_read(&obd->obd_refcount));

	RETURN(0);
}
EXPORT_SYMBOL(class_attach);

/**
 * Create hashes, self-export, and call type-specific setup.
 * Setup is effectively the "start this obd" call.
 */
int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	int err = 0;

	ENTRY;

	LASSERT(obd != NULL);
	LASSERTF(obd == class_num2obd(obd->obd_minor),
		 "obd %p != obd_devs[%d] %p\n",
		 obd, obd->obd_minor, class_num2obd(obd->obd_minor));
	LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC,
		 "obd %p obd_magic %08x != %08x\n",
		 obd, obd->obd_magic, OBD_DEVICE_MAGIC);

	/* have we attached a type to this device? */
	if (!obd->obd_attached) {
		CERROR("Device %d not attached\n", obd->obd_minor);
		RETURN(-ENODEV);
	}

	if (obd->obd_set_up) {
		CERROR("Device %d already setup (type %s)\n",
		       obd->obd_minor, obd->obd_type->typ_name);
		RETURN(-EEXIST);
	}

	/* is someone else setting us up right now? (attach inits spinlock) */
	spin_lock(&obd->obd_dev_lock);
	if (obd->obd_starting) {
		spin_unlock(&obd->obd_dev_lock);
		CERROR("Device %d setup in progress (type %s)\n",
		       obd->obd_minor, obd->obd_type->typ_name);
		RETURN(-EEXIST);
	}
	/*
	 * just leave this on forever.  I can't use obd_set_up here because
	 * other fns check that status, and we're not actually set up yet.
	 */
	obd->obd_starting = 1;
	obd->obd_nid_stats_hash = NULL;
	obd->obd_gen_hash = NULL;
	spin_unlock(&obd->obd_dev_lock);

	/* create an uuid-export lustre hash */
	err = rhashtable_init(&obd->obd_uuid_hash, &uuid_hash_params);
	if (err)
		GOTO(err_starting, err);

#ifdef HAVE_SERVER_SUPPORT
	/* create a nid-export lustre hash */
	err = rhltable_init(&obd->obd_nid_hash, &nid_hash_params);
	if (err)
		GOTO(err_uuid_hash, err = -ENOMEM);

	/* create a nid-stats lustre hash */
	obd->obd_nid_stats_hash = cfs_hash_create("NID_STATS",
						  HASH_NID_STATS_CUR_BITS,
						  HASH_NID_STATS_MAX_BITS,
						  HASH_NID_STATS_BKT_BITS, 0,
						  CFS_HASH_MIN_THETA,
						  CFS_HASH_MAX_THETA,
						  &nid_stat_hash_ops,
						  CFS_HASH_DEFAULT);
	if (!obd->obd_nid_stats_hash)
		GOTO(err_nid_hash, err = -ENOMEM);

	/* create a client_generation-export lustre hash */
	obd->obd_gen_hash = cfs_hash_create("UUID_HASH",
					    HASH_GEN_CUR_BITS,
					    HASH_GEN_MAX_BITS,
					    HASH_GEN_BKT_BITS, 0,
					    CFS_HASH_MIN_THETA,
					    CFS_HASH_MAX_THETA,
					    &gen_hash_ops, CFS_HASH_DEFAULT);
	if (!obd->obd_gen_hash)
		GOTO(err_nid_stats_hash, err = -ENOMEM);
#endif /* HAVE_SERVER_SUPPORT */

	err = obd_setup(obd, lcfg);
	if (err)
#ifdef HAVE_SERVER_SUPPORT
		GOTO(err_gen_hash, err);
#else
		GOTO(err_uuid_hash, err);
#endif /* ! HAVE_SERVER_SUPPORT */

	obd->obd_set_up = 1;

	spin_lock(&obd->obd_dev_lock);
	/* cleanup drops this */
	class_incref(obd, "setup", obd);
	spin_unlock(&obd->obd_dev_lock);

	CDEBUG(D_IOCTL, "finished setup of obd %s (uuid %s)\n",
	       obd->obd_name, obd->obd_uuid.uuid);

	RETURN(0);

#ifdef HAVE_SERVER_SUPPORT
err_gen_hash:
	if (obd->obd_gen_hash) {
		cfs_hash_putref(obd->obd_gen_hash);
		obd->obd_gen_hash = NULL;
	}
err_nid_stats_hash:
	if (obd->obd_nid_stats_hash) {
		cfs_hash_putref(obd->obd_nid_stats_hash);
		obd->obd_nid_stats_hash = NULL;
	}
err_nid_hash:
	rhltable_destroy(&obd->obd_nid_hash);
#endif /* HAVE_SERVER_SUPPORT */
err_uuid_hash:
	rhashtable_destroy(&obd->obd_uuid_hash);
err_starting:
	obd->obd_starting = 0;
	CERROR("setup %s failed (%d)\n", obd->obd_name, err);
	return err;
}
EXPORT_SYMBOL(class_setup);

/**
 * We have finished using this OBD and are ready to destroy it.
 * There can be no more references to this obd.
 */
int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	ENTRY;

	if (obd->obd_set_up) {
		CERROR("OBD device %d still set up\n", obd->obd_minor);
		RETURN(-EBUSY);
	}

	spin_lock(&obd->obd_dev_lock);
	if (!obd->obd_attached) {
		spin_unlock(&obd->obd_dev_lock);
		CERROR("OBD device %d not attached\n", obd->obd_minor);
		RETURN(-ENODEV);
	}
	obd->obd_attached = 0;
	spin_unlock(&obd->obd_dev_lock);

	/* cleanup in progress. we don't like to find this device after now */
	class_unregister_device(obd);

	CDEBUG(D_IOCTL, "detach on obd %s (uuid %s)\n",
	       obd->obd_name, obd->obd_uuid.uuid);

	class_decref(obd, "newdev", obd);

	RETURN(0);
}
EXPORT_SYMBOL(class_detach);

/**
 * Start shutting down the OBD.  There may be in-progess ops when
 * this is called.  We tell them to start shutting down with a call
 * to class_disconnect_exports().
 */
int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	int err = 0;
	char *flag;
	ENTRY;

	OBD_RACE(OBD_FAIL_LDLM_RECOV_CLIENTS);

	if (!obd->obd_set_up) {
		CERROR("Device %d not setup\n", obd->obd_minor);
		RETURN(-ENODEV);
	}

	spin_lock(&obd->obd_dev_lock);
	if (obd->obd_stopping) {
		spin_unlock(&obd->obd_dev_lock);
		CERROR("OBD %d already stopping\n", obd->obd_minor);
		RETURN(-ENODEV);
	}
	/* Leave this on forever */
	obd->obd_stopping = 1;
	spin_unlock(&obd->obd_dev_lock);

	/* wait for already-arrived-connections to finish. */
	while (obd->obd_conn_inprogress > 0)
		yield();
	smp_rmb();

	if (lcfg->lcfg_bufcount >= 2 && LUSTRE_CFG_BUFLEN(lcfg, 1) > 0) {
		for (flag = lustre_cfg_string(lcfg, 1); *flag != 0; flag++)
			switch (*flag) {
			case 'F':
				obd->obd_force = 1;
				break;
			case 'A':
				LCONSOLE_WARN("Failing over %s\n",
					      obd->obd_name);
				spin_lock(&obd->obd_dev_lock);
				obd->obd_fail = 1;
#ifdef HAVE_SERVER_SUPPORT
				obd->obd_no_transno = 1;
#endif
				obd->obd_no_recov = 1;
				spin_unlock(&obd->obd_dev_lock);
				if (OBP(obd, iocontrol)) {
					obd_iocontrol(OBD_IOC_SYNC,
						      obd->obd_self_export,
						      0, NULL, NULL);
				}
				break;
			default:
				CERROR("Unrecognised flag '%c'\n", *flag);
			}
	}

	LASSERT(obd->obd_self_export);

	CDEBUG(D_IOCTL, "%s: forcing exports to disconnect: %d/%d\n",
	       obd->obd_name, obd->obd_num_exports,
	       atomic_read(&obd->obd_refcount) - 2);
	dump_exports(obd, 0, D_HA);
	class_disconnect_exports(obd);

	/* Precleanup, we must make sure all exports get destroyed. */
	err = obd_precleanup(obd);
	if (err)
		CERROR("Precleanup %s returned %d\n",
		       obd->obd_name, err);

	/* destroy an uuid-export hash body */
	rhashtable_free_and_destroy(&obd->obd_uuid_hash, obd_export_exit,
				    NULL);
#ifdef HAVE_SERVER_SUPPORT
	/* destroy a nid-export hash body */
	rhltable_free_and_destroy(&obd->obd_nid_hash, nid_export_exit, NULL);

	/* destroy a nid-stats hash body */
	if (obd->obd_nid_stats_hash) {
		cfs_hash_putref(obd->obd_nid_stats_hash);
		obd->obd_nid_stats_hash = NULL;
	}

	/* destroy a client_generation-export hash body */
	if (obd->obd_gen_hash) {
		cfs_hash_putref(obd->obd_gen_hash);
		obd->obd_gen_hash = NULL;
	}
#endif /* HAVE_SERVER_SUPPORT */
	class_decref(obd, "setup", obd);
	obd->obd_set_up = 0;

	RETURN(0);
}

struct obd_device *class_incref(struct obd_device *obd,
				const char *scope,
				const void *source)
{
	lu_ref_add_atomic(&obd->obd_reference, scope, source);
	atomic_inc(&obd->obd_refcount);
	CDEBUG(D_INFO, "incref %s (%p) now %d\n", obd->obd_name, obd,
	       atomic_read(&obd->obd_refcount));

	return obd;
}
EXPORT_SYMBOL(class_incref);

void class_decref(struct obd_device *obd, const char *scope, const void *source)
{
	int last;

	CDEBUG(D_INFO, "Decref %s (%p) now %d - %s\n", obd->obd_name, obd,
	       atomic_read(&obd->obd_refcount), scope);

	LASSERT(obd->obd_num_exports >= 0);
	last = atomic_dec_and_test(&obd->obd_refcount);
	lu_ref_del(&obd->obd_reference, scope, source);

	if (last) {
		struct obd_export *exp;

		LASSERT(!obd->obd_attached);
		/*
		 * All exports have been destroyed; there should
		 * be no more in-progress ops by this point.
		 */
		exp = obd->obd_self_export;

		if (exp) {
			exp->exp_flags |= exp_flags_from_obd(obd);
			class_unlink_export(exp);
		}
	}
}
EXPORT_SYMBOL(class_decref);

/**
 * Add a failover NID location.
 * Client OBD types contact server OBD types using this NID list.
 */
int class_add_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct obd_import *imp;
	struct obd_uuid uuid;
	int rc;

	ENTRY;

	if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
	    LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(struct obd_uuid)) {
		CERROR("invalid conn_uuid\n");
		RETURN(-EINVAL);
	}
	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSP_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_LWP_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_MGC_NAME)) {
		CERROR("can't add connection on non-client dev\n");
		RETURN(-EINVAL);
	}

	imp = obd->u.cli.cl_import;
	if (!imp) {
		CERROR("try to add conn on immature client dev\n");
		RETURN(-EINVAL);
	}

	obd_str2uuid(&uuid, lustre_cfg_string(lcfg, 1));
	rc = obd_add_conn(imp, &uuid, lcfg->lcfg_num);

	RETURN(rc);
}

/** Remove a failover NID location. */
static int class_del_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
{
	struct obd_import *imp;
	struct obd_uuid uuid;
	int rc;

	ENTRY;

	if (LUSTRE_CFG_BUFLEN(lcfg, 1) < 1 ||
	    LUSTRE_CFG_BUFLEN(lcfg, 1) > sizeof(struct obd_uuid)) {
		CERROR("invalid conn_uuid\n");
		RETURN(-EINVAL);
	}
	if (strcmp(obd->obd_type->typ_name, LUSTRE_MDC_NAME) &&
	    strcmp(obd->obd_type->typ_name, LUSTRE_OSC_NAME)) {
		CERROR("can't del connection on non-client dev\n");
		RETURN(-EINVAL);
	}

	imp = obd->u.cli.cl_import;
	if (!imp) {
		CERROR("try to del conn on immature client dev\n");
		RETURN(-EINVAL);
	}

	obd_str2uuid(&uuid, lustre_cfg_string(lcfg, 1));
	rc = obd_del_conn(imp, &uuid);

	RETURN(rc);
}

static LIST_HEAD(lustre_profile_list);
static DEFINE_SPINLOCK(lustre_profile_list_lock);

struct lustre_profile *class_get_profile(const char *prof)
{
	struct lustre_profile *lprof;

	ENTRY;
	spin_lock(&lustre_profile_list_lock);
	list_for_each_entry(lprof, &lustre_profile_list, lp_list) {
		if (!strcmp(lprof->lp_profile, prof)) {
			lprof->lp_refs++;
			spin_unlock(&lustre_profile_list_lock);
			RETURN(lprof);
		}
	}
	spin_unlock(&lustre_profile_list_lock);
	RETURN(NULL);
}
EXPORT_SYMBOL(class_get_profile);

/**
 * Create a named "profile".
 * This defines the MDC and OSC names to use for a client.
 * This also is used to define the LOV to be used by a MDT.
 */
static int class_add_profile(int proflen, char *prof, int osclen, char *osc,
			     int mdclen, char *mdc)
{
	struct lustre_profile *lprof;
	int err = 0;

	ENTRY;

	CDEBUG(D_CONFIG, "Add profile %s\n", prof);

	OBD_ALLOC(lprof, sizeof(*lprof));
	if (!lprof)
		RETURN(-ENOMEM);
	INIT_LIST_HEAD(&lprof->lp_list);

	LASSERT(proflen == (strlen(prof) + 1));
	OBD_ALLOC(lprof->lp_profile, proflen);
	if (!lprof->lp_profile)
		GOTO(out, err = -ENOMEM);
	memcpy(lprof->lp_profile, prof, proflen);

	LASSERT(osclen == (strlen(osc) + 1));
	OBD_ALLOC(lprof->lp_dt, osclen);
	if (!lprof->lp_dt)
		GOTO(out, err = -ENOMEM);
	memcpy(lprof->lp_dt, osc, osclen);

	if (mdclen > 0) {
		LASSERT(mdclen == (strlen(mdc) + 1));
		OBD_ALLOC(lprof->lp_md, mdclen);
		if (!lprof->lp_md)
			GOTO(out, err = -ENOMEM);
		memcpy(lprof->lp_md, mdc, mdclen);
	}

	spin_lock(&lustre_profile_list_lock);
	lprof->lp_refs = 1;
	lprof->lp_list_deleted = false;

	list_add(&lprof->lp_list, &lustre_profile_list);
	spin_unlock(&lustre_profile_list_lock);
	RETURN(err);

out:
	if (lprof->lp_md)
		OBD_FREE(lprof->lp_md, mdclen);
	if (lprof->lp_dt)
		OBD_FREE(lprof->lp_dt, osclen);
	if (lprof->lp_profile)
		OBD_FREE(lprof->lp_profile, proflen);
	OBD_FREE(lprof, sizeof(*lprof));
	RETURN(err);
}

void class_del_profile(const char *prof)
{
	struct lustre_profile *lprof;

	ENTRY;

	CDEBUG(D_CONFIG, "Del profile %s\n", prof);

	lprof = class_get_profile(prof);
	if (lprof) {
		spin_lock(&lustre_profile_list_lock);
		/* because get profile increments the ref counter */
		lprof->lp_refs--;
		list_del(&lprof->lp_list);
		lprof->lp_list_deleted = true;
		spin_unlock(&lustre_profile_list_lock);

		class_put_profile(lprof);
	}
	EXIT;
}
EXPORT_SYMBOL(class_del_profile);

void class_put_profile(struct lustre_profile *lprof)
{
	spin_lock(&lustre_profile_list_lock);
	if ((--lprof->lp_refs) > 0) {
		LASSERT(lprof->lp_refs > 0);
		spin_unlock(&lustre_profile_list_lock);
		return;
	}
	spin_unlock(&lustre_profile_list_lock);

	/* confirm not a negative number */
	LASSERT(lprof->lp_refs == 0);

	/*
	 * At least one class_del_profile/profiles must be called
	 * on the target profile or lustre_profile_list will corrupt
	 */
	LASSERT(lprof->lp_list_deleted);
	OBD_FREE(lprof->lp_profile, strlen(lprof->lp_profile) + 1);
	OBD_FREE(lprof->lp_dt, strlen(lprof->lp_dt) + 1);
	if (lprof->lp_md)
		OBD_FREE(lprof->lp_md, strlen(lprof->lp_md) + 1);
	OBD_FREE(lprof, sizeof(*lprof));
}
EXPORT_SYMBOL(class_put_profile);

/* COMPAT_146 */
void class_del_profiles(void)
{
	struct lustre_profile *lprof, *n;
	ENTRY;

	spin_lock(&lustre_profile_list_lock);
	list_for_each_entry_safe(lprof, n, &lustre_profile_list, lp_list) {
		list_del(&lprof->lp_list);
		lprof->lp_list_deleted = true;
		spin_unlock(&lustre_profile_list_lock);

		class_put_profile(lprof);

		spin_lock(&lustre_profile_list_lock);
	}
	spin_unlock(&lustre_profile_list_lock);
	EXIT;
}
EXPORT_SYMBOL(class_del_profiles);

/*
 * We can't call lquota_process_config directly because
 * it lives in a module that must be loaded after this one.
 */
#ifdef HAVE_SERVER_SUPPORT
static int (*quota_process_config)(struct lustre_cfg *lcfg) = NULL;
#endif /* HAVE_SERVER_SUPPORT */

/**
 * Rename the proc parameter in \a cfg with a new name \a new_name.
 *
 * \param cfg	   config structure which contains the proc parameter
 * \param new_name new name of the proc parameter
 *
 * \retval valid-pointer    pointer to the newly-allocated config structure
 *			    which contains the renamed proc parameter
 * \retval ERR_PTR(-EINVAL) if \a cfg or \a new_name is NULL, or \a cfg does
 *			    not contain a proc parameter
 * \retval ERR_PTR(-ENOMEM) if memory allocation failure occurs
 */
struct lustre_cfg *lustre_cfg_rename(struct lustre_cfg *cfg,
				     const char *new_name)
{
	struct lustre_cfg_bufs *bufs = NULL;
	struct lustre_cfg *new_cfg = NULL;
	char *param = NULL;
	char *new_param = NULL;
	char *value = NULL;
	int name_len = 0;
	int new_len = 0;

	ENTRY;

	if (!cfg || !new_name)
		GOTO(out_nocfg, new_cfg = ERR_PTR(-EINVAL));

	param = lustre_cfg_string(cfg, 1);
	if (!param)
		GOTO(out_nocfg, new_cfg = ERR_PTR(-EINVAL));

	value = strchr(param, '=');
	if (value)
		name_len = value - param;
	else
		name_len = strlen(param);

	new_len = LUSTRE_CFG_BUFLEN(cfg, 1) + strlen(new_name) - name_len;

	OBD_ALLOC(new_param, new_len);
	if (!new_param)
		GOTO(out_nocfg, new_cfg = ERR_PTR(-ENOMEM));

	strlcpy(new_param, new_name, new_len);
	if (value)
		strcat(new_param, value);

	OBD_ALLOC_PTR(bufs);
	if (!bufs)
		GOTO(out_free_param, new_cfg = ERR_PTR(-ENOMEM));

	lustre_cfg_bufs_reset(bufs, NULL);
	lustre_cfg_bufs_init(bufs, cfg);
	lustre_cfg_bufs_set_string(bufs, 1, new_param);

	OBD_ALLOC(new_cfg, lustre_cfg_len(bufs->lcfg_bufcount,
					  bufs->lcfg_buflen));
	if (!new_cfg)
		GOTO(out_free_buf, new_cfg = ERR_PTR(-ENOMEM));

	lustre_cfg_init(new_cfg, cfg->lcfg_command, bufs);

	new_cfg->lcfg_num = cfg->lcfg_num;
	new_cfg->lcfg_flags = cfg->lcfg_flags;
	new_cfg->lcfg_nid = cfg->lcfg_nid;
	new_cfg->lcfg_nal = cfg->lcfg_nal;
out_free_buf:
	OBD_FREE_PTR(bufs);
out_free_param:
	OBD_FREE(new_param, new_len);
out_nocfg:
	RETURN(new_cfg);
}
EXPORT_SYMBOL(lustre_cfg_rename);

static ssize_t process_param2_config(struct lustre_cfg *lcfg)
{
	char *param = lustre_cfg_string(lcfg, 1);
	char *upcall = lustre_cfg_string(lcfg, 2);
	struct kobject *kobj = NULL;
	const char *subsys = param;
	char *argv[] = {
		[0] = "/usr/sbin/lctl",
		[1] = "set_param",
		[2] = param,
		[3] = NULL
	};
	ktime_t start;
	ktime_t end;
	size_t len;
	int rc;

	ENTRY;
	print_lustre_cfg(lcfg);

	len = strcspn(param, ".=");
	if (!len)
		return -EINVAL;

	/* If we find '=' then its the top level sysfs directory */
	if (param[len] == '=')
		return class_set_global(param);

	subsys = kstrndup(param, len, GFP_KERNEL);
	if (!subsys)
		return -ENOMEM;

	kobj = kset_find_obj(lustre_kset, subsys);
	kfree(subsys);
	if (kobj) {
		char *value = param;
		char *envp[4];
		int i;

		param = strsep(&value, "=");
		envp[0] = kasprintf(GFP_KERNEL, "PARAM=%s", param);
		envp[1] = kasprintf(GFP_KERNEL, "SETTING=%s", value);
		envp[2] = kasprintf(GFP_KERNEL, "TIME=%lld",
				    ktime_get_real_seconds());
		envp[3] = NULL;

		rc = kobject_uevent_env(kobj, KOBJ_CHANGE, envp);
		for (i = 0; i < ARRAY_SIZE(envp); i++)
			kfree(envp[i]);

		kobject_put(kobj);

		RETURN(rc);
	}

	/* Add upcall processing here. Now only lctl is supported */
	if (strcmp(upcall, LCTL_UPCALL) != 0) {
		CERROR("Unsupported upcall %s\n", upcall);
		RETURN(-EINVAL);
	}

	start = ktime_get();
	rc = call_usermodehelper(argv[0], argv, NULL, UMH_WAIT_PROC);
	end = ktime_get();

	if (rc < 0) {
		CERROR("lctl: error invoking upcall %s %s %s: rc = %d; "
		       "time %ldus\n", argv[0], argv[1], argv[2], rc,
		       (long)ktime_us_delta(end, start));
	} else {
		CDEBUG(D_HA, "lctl: invoked upcall %s %s %s, time %ldus\n",
		       argv[0], argv[1], argv[2],
		       (long)ktime_us_delta(end, start));
		       rc = 0;
	}

	RETURN(rc);
}

#ifdef HAVE_SERVER_SUPPORT
void lustre_register_quota_process_config(int (*qpc)(struct lustre_cfg *lcfg))
{
	quota_process_config = qpc;
}
EXPORT_SYMBOL(lustre_register_quota_process_config);
#endif /* HAVE_SERVER_SUPPORT */

/**
 * Process configuration commands given in lustre_cfg form.
 * These may come from direct calls (e.g. class_manual_cleanup)
 * or processing the config llog, or ioctl from lctl.
 */
int class_process_config(struct lustre_cfg *lcfg)
{
	struct obd_device *obd;
	int err;

	LASSERT(lcfg && !IS_ERR(lcfg));
	CDEBUG(D_IOCTL, "processing cmd: %x\n", lcfg->lcfg_command);

	/* Commands that don't need a device */
	switch (lcfg->lcfg_command) {
	case LCFG_ATTACH: {
		err = class_attach(lcfg);
		GOTO(out, err);
	}
	case LCFG_ADD_UUID: {
		CDEBUG(D_IOCTL,
		       "adding mapping from uuid %s to nid %#llx (%s)\n",
		       lustre_cfg_string(lcfg, 1), lcfg->lcfg_nid,
		       libcfs_nid2str(lcfg->lcfg_nid));

		err = class_add_uuid(lustre_cfg_string(lcfg, 1),
				     lcfg->lcfg_nid);
		GOTO(out, err);
	}
	case LCFG_DEL_UUID: {
		CDEBUG(D_IOCTL, "removing mappings for uuid %s\n",
		       (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) ==
			0) ? "<all uuids>" : lustre_cfg_string(lcfg, 1));

		err = class_del_uuid(lustre_cfg_string(lcfg, 1));
		GOTO(out, err);
	}
	case LCFG_MOUNTOPT: {
		CDEBUG(D_IOCTL, "mountopt: profile %s osc %s mdc %s\n",
		       lustre_cfg_string(lcfg, 1),
		       lustre_cfg_string(lcfg, 2),
		       lustre_cfg_string(lcfg, 3));
		/*
		 * set these mount options somewhere, so ll_fill_super
		 * can find them.
		 */
		err = class_add_profile(LUSTRE_CFG_BUFLEN(lcfg, 1),
					lustre_cfg_string(lcfg, 1),
					LUSTRE_CFG_BUFLEN(lcfg, 2),
					lustre_cfg_string(lcfg, 2),
					LUSTRE_CFG_BUFLEN(lcfg, 3),
					lustre_cfg_string(lcfg, 3));
		GOTO(out, err);
	}
	case LCFG_DEL_MOUNTOPT: {
		CDEBUG(D_IOCTL, "mountopt: profile %s\n",
		       lustre_cfg_string(lcfg, 1));
		class_del_profile(lustre_cfg_string(lcfg, 1));
		GOTO(out, err = 0);
	}
	case LCFG_SET_TIMEOUT: {
		CDEBUG(D_IOCTL, "changing lustre timeout from %d to %d\n",
		       obd_timeout, lcfg->lcfg_num);
		obd_timeout = max(lcfg->lcfg_num, 1U);
		obd_timeout_set = 1;
		GOTO(out, err = 0);
	}
	case LCFG_SET_LDLM_TIMEOUT: {
		CDEBUG(D_IOCTL, "changing lustre ldlm_timeout from %d to %d\n",
		       ldlm_timeout, lcfg->lcfg_num);
		ldlm_timeout = max(lcfg->lcfg_num, 1U);
		if (ldlm_timeout >= obd_timeout)
			ldlm_timeout = max(obd_timeout / 3, 1U);
		ldlm_timeout_set = 1;
		GOTO(out, err = 0);
	}
	case LCFG_SET_UPCALL: {
		LCONSOLE_ERROR_MSG(0x15a, "recovery upcall is deprecated\n");
		/* COMPAT_146 Don't fail on old configs */
		GOTO(out, err = 0);
	}
	case LCFG_MARKER: {
		struct cfg_marker *marker;

		marker = lustre_cfg_buf(lcfg, 1);
		CDEBUG(D_IOCTL, "marker %d (%#x) %.16s %s\n", marker->cm_step,
		       marker->cm_flags, marker->cm_tgtname,
		       marker->cm_comment);
		GOTO(out, err = 0);
	}
	case LCFG_PARAM: {
		char *tmp;

		/* llite has no OBD */
		if (class_match_param(lustre_cfg_string(lcfg, 1),
				      PARAM_LLITE, NULL) == 0) {
			struct lustre_sb_info *lsi;
			unsigned long addr;
			ssize_t count;

			/*
			 * The instance name contains the sb:
			 * lustre-client-aacfe000
			 */
			tmp = strrchr(lustre_cfg_string(lcfg, 0), '-');
			if (!tmp || !*(++tmp))
				GOTO(out, err = -EINVAL);

			if (sscanf(tmp, "%lx", &addr) != 1)
				GOTO(out, err = -EINVAL);

			lsi = s2lsi((struct super_block *)addr);
			/* This better be a real Lustre superblock! */
			LASSERT(lsi->lsi_lmd->lmd_magic == LMD_MAGIC);

			count = class_modify_config(lcfg, PARAM_LLITE,
						    lsi->lsi_kobj);
			err = count < 0 ? count : 0;
			GOTO(out, err);
		} else if ((class_match_param(lustre_cfg_string(lcfg, 1),
					      PARAM_SYS, &tmp) == 0)) {
			/* Global param settings */
			err = class_set_global(tmp);
			/*
			 * Client or server should not fail to mount if
			 * it hits an unknown configuration parameter.
			 */
			if (err < 0)
				CWARN("Ignoring unknown param %s\n", tmp);

			GOTO(out, err = 0);
#ifdef HAVE_SERVER_SUPPORT
		} else if ((class_match_param(lustre_cfg_string(lcfg, 1),
					      PARAM_QUOTA, &tmp) == 0) &&
			   quota_process_config) {
			err = (*quota_process_config)(lcfg);
			GOTO(out, err);
#endif /* HAVE_SERVER_SUPPORT */
		}

		break;
	}
	case LCFG_SET_PARAM: {
		err = process_param2_config(lcfg);
		GOTO(out, err = 0);
	}
	}
	/* Commands that require a device */
	obd = class_name2obd(lustre_cfg_string(lcfg, 0));
	if (!obd) {
		if (!LUSTRE_CFG_BUFLEN(lcfg, 0))
			CERROR("this lcfg command requires a device name\n");
		else
			CERROR("no device for: %s\n",
			       lustre_cfg_string(lcfg, 0));

		GOTO(out, err = -EINVAL);
	}
	switch(lcfg->lcfg_command) {
	case LCFG_SETUP: {
		err = class_setup(obd, lcfg);
		GOTO(out, err);
	}
	case LCFG_DETACH: {
		err = class_detach(obd, lcfg);
		GOTO(out, err = 0);
	}
	case LCFG_CLEANUP: {
		err = class_cleanup(obd, lcfg);
		GOTO(out, err = 0);
	}
	case LCFG_ADD_CONN: {
		err = class_add_conn(obd, lcfg);
		GOTO(out, err = 0);
	}
	case LCFG_DEL_CONN: {
		err = class_del_conn(obd, lcfg);
		GOTO(out, err = 0);
	}
	case LCFG_POOL_NEW: {
		err = obd_pool_new(obd, lustre_cfg_string(lcfg, 2));
		GOTO(out, err = 0);
	}
	case LCFG_POOL_ADD: {
		err = obd_pool_add(obd, lustre_cfg_string(lcfg, 2),
                                   lustre_cfg_string(lcfg, 3));
		GOTO(out, err = 0);
	}
	case LCFG_POOL_REM: {
		err = obd_pool_rem(obd, lustre_cfg_string(lcfg, 2),
                                   lustre_cfg_string(lcfg, 3));
		GOTO(out, err = 0);
	}
	case LCFG_POOL_DEL: {
		err = obd_pool_del(obd, lustre_cfg_string(lcfg, 2));
		GOTO(out, err = 0);
	}
	/*
	 * Process config log ADD_MDC record twice to add MDC also to LOV
	 * for Data-on-MDT:
	 *
	 * add 0:lustre-clilmv 1:lustre-MDT0000_UUID 2:0 3:1
	 *     4:lustre-MDT0000-mdc_UUID
	 */
	case LCFG_ADD_MDC: {
		struct obd_device *lov_obd;
		char *clilmv;

		err = obd_process_config(obd, sizeof(*lcfg), lcfg);
		if (err)
			GOTO(out, err);

		/* make sure this is client LMV log entry */
		clilmv = strstr(lustre_cfg_string(lcfg, 0), "clilmv");
		if (!clilmv)
			GOTO(out, err);

		/*
		 * replace 'lmv' with 'lov' name to address LOV device and
		 * process llog record to add MDC there.
		 */
		clilmv[4] = 'o';
		lov_obd = class_name2obd(lustre_cfg_string(lcfg, 0));
		if (lov_obd) {
			err = obd_process_config(lov_obd, sizeof(*lcfg), lcfg);
		} else {
			err = -ENOENT;
			CERROR("%s: Cannot find LOV by %s name, rc = %d\n",
			       obd->obd_name, lustre_cfg_string(lcfg, 0), err);
		}
		/* restore 'lmv' name */
		clilmv[4] = 'm';
		GOTO(out, err);
	}
	default: {
		err = obd_process_config(obd, sizeof(*lcfg), lcfg);
		GOTO(out, err);
	}
	}
	EXIT;
out:
	if ((err < 0) && !(lcfg->lcfg_command & LCFG_REQUIRED)) {
		CWARN("Ignoring error %d on optional command %#x\n", err,
		      lcfg->lcfg_command);
		err = 0;
	}
	return err;
}
EXPORT_SYMBOL(class_process_config);

ssize_t class_modify_config(struct lustre_cfg *lcfg, const char *prefix,
			    struct kobject *kobj)
{
	struct kobj_type *typ;
	ssize_t count = 0;
	int i;

	if (lcfg->lcfg_command != LCFG_PARAM) {
		CERROR("Unknown command: %d\n", lcfg->lcfg_command);
		return -EINVAL;
	}

	typ = get_ktype(kobj);
	if (!typ || !typ->default_attrs)
		return -ENODEV;

	print_lustre_cfg(lcfg);

	/*
	 * e.g. tunefs.lustre --param mdt.group_upcall=foo /r/tmp/lustre-mdt
	 * or   lctl conf_param lustre-MDT0000.mdt.group_upcall=bar
	 * or   lctl conf_param lustre-OST0000.osc.max_dirty_mb=36
	 */
	for (i = 1; i < lcfg->lcfg_bufcount; i++) {
		struct attribute *attr;
		size_t keylen;
		char *value;
		char *key;
		int j;

		key = lustre_cfg_buf(lcfg, i);
		/* Strip off prefix */
		if (class_match_param(key, prefix, &key))
			/*
			 * If the prefix doesn't match, return error so we
			 * can pass it down the stack
			 */
			return -EINVAL;

		value = strchr(key, '=');
		if (!value || *(value + 1) == 0) {
			CERROR("%s: can't parse param '%s' (missing '=')\n",
			       lustre_cfg_string(lcfg, 0),
			       lustre_cfg_string(lcfg, i));
			/* continue parsing other params */
			continue;
		}
		keylen = value - key;
		value++;

		attr = NULL;
		for (j = 0; typ->default_attrs[j]; j++) {
			if (!strncmp(typ->default_attrs[j]->name, key,
				     keylen)) {
				attr = typ->default_attrs[j];
				break;
			}
		}

		if (!attr) {
			char *envp[4], *param, *path;

			path = kobject_get_path(kobj, GFP_KERNEL);
			if (!path)
				return -EINVAL;

			/* convert sysfs path to uevent format */
			param = path;
			while ((param = strchr(param, '/')) != NULL)
				*param = '.';

			param = strstr(path, "fs.lustre.") + 10;

			envp[0] = kasprintf(GFP_KERNEL, "PARAM=%s.%.*s",
					    param, (int) keylen, key);
			envp[1] = kasprintf(GFP_KERNEL, "SETTING=%s", value);
			envp[2] = kasprintf(GFP_KERNEL, "TIME=%lld",
					    ktime_get_real_seconds());
			envp[3] = NULL;

			if (kobject_uevent_env(kobj, KOBJ_CHANGE, envp)) {
				CERROR("%s: failed to send uevent %s\n",
				       kobject_name(kobj), key);
			}

			for (i = 0; i < ARRAY_SIZE(envp); i++)
				kfree(envp[i]);
			kfree(path);
		} else {
			count += lustre_attr_store(kobj, attr, value,
						   strlen(value));
		}
	}
	return count;
}
EXPORT_SYMBOL(class_modify_config);

/*
 * Supplemental functions for config logs, it allocates lustre_cfg
 * buffers plus initialized llog record header at the beginning.
 */
struct llog_cfg_rec *lustre_cfg_rec_new(int cmd, struct lustre_cfg_bufs *bufs)
{
	struct llog_cfg_rec *lcr;
	int reclen;

	ENTRY;

	reclen = lustre_cfg_len(bufs->lcfg_bufcount, bufs->lcfg_buflen);
	reclen = llog_data_len(reclen) + sizeof(struct llog_rec_hdr) +
		 sizeof(struct llog_rec_tail);

	OBD_ALLOC(lcr, reclen);
	if (!lcr)
		RETURN(NULL);

	lustre_cfg_init(&lcr->lcr_cfg, cmd, bufs);

	lcr->lcr_hdr.lrh_len = reclen;
	lcr->lcr_hdr.lrh_type = OBD_CFG_REC;

	RETURN(lcr);
}
EXPORT_SYMBOL(lustre_cfg_rec_new);

void lustre_cfg_rec_free(struct llog_cfg_rec *lcr)
{
	ENTRY;
	OBD_FREE(lcr, lcr->lcr_hdr.lrh_len);
	EXIT;
}
EXPORT_SYMBOL(lustre_cfg_rec_free);

/**
 * Parse a configuration llog, doing various manipulations on them
 * for various reasons, (modifications for compatibility, skip obsolete
 * records, change uuids, etc), then class_process_config() resulting
 * net records.
 */
int class_config_llog_handler(const struct lu_env *env,
			      struct llog_handle *handle,
			      struct llog_rec_hdr *rec, void *data)
{
	struct config_llog_instance *cfg = data;
	int cfg_len = rec->lrh_len;
	char *cfg_buf = (char *) (rec + 1);
	int rc = 0;
	ENTRY;

	/* class_config_dump_handler(handle, rec, data); */

	switch (rec->lrh_type) {
	case OBD_CFG_REC: {
		struct lustre_cfg *lcfg, *lcfg_new;
		struct lustre_cfg_bufs bufs;
		char *inst_name = NULL;
		int inst_len = 0;
		int swab = 0;

		lcfg = (struct lustre_cfg *)cfg_buf;
		if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION)) {
			lustre_swab_lustre_cfg(lcfg);
			swab = 1;
		}

		rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
		if (rc)
			GOTO(out, rc);

		/* Figure out config state info */
		if (lcfg->lcfg_command == LCFG_MARKER) {
			struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);
			lustre_swab_cfg_marker(marker, swab,
					       LUSTRE_CFG_BUFLEN(lcfg, 1));
			CDEBUG(D_CONFIG, "Marker, inst_flg=%#x mark_flg=%#x\n",
			       cfg->cfg_flags, marker->cm_flags);
			if (marker->cm_flags & CM_START) {
				/* all previous flags off */
				cfg->cfg_flags = CFG_F_MARKER;
				server_name2index(marker->cm_tgtname,
						  &cfg->cfg_lwp_idx, NULL);
				if (marker->cm_flags & CM_SKIP) {
					cfg->cfg_flags |= CFG_F_SKIP;
					CDEBUG(D_CONFIG, "SKIP #%d\n",
					       marker->cm_step);
				} else if ((marker->cm_flags & CM_EXCLUDE) ||
					   (cfg->cfg_sb &&
					   lustre_check_exclusion(cfg->cfg_sb,
							marker->cm_tgtname))) {
					cfg->cfg_flags |= CFG_F_EXCLUDE;
					CDEBUG(D_CONFIG, "EXCLUDE %d\n",
					       marker->cm_step);
				}
			} else if (marker->cm_flags & CM_END) {
				cfg->cfg_flags = 0;
			}
		}
		/*
		 * A config command without a start marker before it is
		 * illegal
		 */
		if (!(cfg->cfg_flags & CFG_F_MARKER) &&
		    (lcfg->lcfg_command != LCFG_MARKER)) {
			CWARN("Skip config outside markers, (inst: %016lx, uuid: %s, flags: %#x)\n",
				cfg->cfg_instance,
				cfg->cfg_uuid.uuid, cfg->cfg_flags);
			cfg->cfg_flags |= CFG_F_SKIP;
		}
		if (cfg->cfg_flags & CFG_F_SKIP) {
			CDEBUG(D_CONFIG, "skipping %#x\n",
			       cfg->cfg_flags);
			rc = 0;
			/* No processing! */
			break;
		}

		/*
		 * For interoperability between 1.8 and 2.0,
		 * rename "mds" OBD device type to "mdt".
		 */
		{
			char *typename = lustre_cfg_string(lcfg, 1);
			char *index = lustre_cfg_string(lcfg, 2);

			if ((lcfg->lcfg_command == LCFG_ATTACH && typename &&
			    strcmp(typename, "mds") == 0)) {
				CWARN("For 1.8 interoperability, rename obd "
					"type from mds to mdt\n");
				typename[2] = 't';
			}
			if ((lcfg->lcfg_command == LCFG_SETUP && index &&
			    strcmp(index, "type") == 0)) {
				CDEBUG(D_INFO, "For 1.8 interoperability, "
				       "set this index to '0'\n");
				index[0] = '0';
				index[1] = 0;
			}
		}

#ifdef HAVE_SERVER_SUPPORT
		/* newer MDS replaces LOV/OSC with LOD/OSP */
		if ((lcfg->lcfg_command == LCFG_ATTACH ||
		     lcfg->lcfg_command == LCFG_SET_PARAM ||
		     lcfg->lcfg_command == LCFG_PARAM) &&
		    cfg->cfg_sb && IS_MDT(s2lsi(cfg->cfg_sb))) {
			char *typename = lustre_cfg_string(lcfg, 1);

			if (typename &&
			    strcmp(typename, LUSTRE_LOV_NAME) == 0) {
				CDEBUG(D_CONFIG,
				       "For 2.x interoperability, rename obd "
				       "type from lov to lod (%s)\n",
				       s2lsi(cfg->cfg_sb)->lsi_svname);
				strcpy(typename, LUSTRE_LOD_NAME);
			}
			if (typename &&
			    strcmp(typename, LUSTRE_OSC_NAME) == 0) {
				CDEBUG(D_CONFIG,
				       "For 2.x interoperability, rename obd "
				       "type from osc to osp (%s)\n",
				       s2lsi(cfg->cfg_sb)->lsi_svname);
				strcpy(typename, LUSTRE_OSP_NAME);
			}
		}
#endif /* HAVE_SERVER_SUPPORT */

		if (cfg->cfg_flags & CFG_F_EXCLUDE) {
			CDEBUG(D_CONFIG, "cmd: %x marked EXCLUDED\n",
			       lcfg->lcfg_command);
			if (lcfg->lcfg_command == LCFG_LOV_ADD_OBD)
				/* Add inactive instead */
				lcfg->lcfg_command = LCFG_LOV_ADD_INA;
		}

		lustre_cfg_bufs_reset(&bufs, NULL);
		lustre_cfg_bufs_init(&bufs, lcfg);

		if (cfg->cfg_instance &&
		    lcfg->lcfg_command != LCFG_SPTLRPC_CONF &&
		    LUSTRE_CFG_BUFLEN(lcfg, 0) > 0) {
			inst_len = LUSTRE_CFG_BUFLEN(lcfg, 0) +
				LUSTRE_MAXINSTANCE + 4;
			OBD_ALLOC(inst_name, inst_len);
			if (!inst_name)
				GOTO(out, rc = -ENOMEM);
			snprintf(inst_name, inst_len, "%s-%016lx",
				lustre_cfg_string(lcfg, 0),
				cfg->cfg_instance);
			lustre_cfg_bufs_set_string(&bufs, 0, inst_name);
			CDEBUG(D_CONFIG, "cmd %x, instance name: %s\n",
			       lcfg->lcfg_command, inst_name);
		}

		/* override llog UUID for clients, to insure they are unique */
		if (cfg->cfg_instance && lcfg->lcfg_command == LCFG_ATTACH)
			lustre_cfg_bufs_set_string(&bufs, 2,
						   cfg->cfg_uuid.uuid);
		/*
		 * sptlrpc config record, we expect 2 data segments:
		 *  [0]: fs_name/target_name,
		 *  [1]: rule string
		 * moving them to index [1] and [2], and insert MGC's
		 * obdname at index [0].
		 */
		if (cfg->cfg_instance &&
		    lcfg->lcfg_command == LCFG_SPTLRPC_CONF) {
			/* After ASLR changes cfg_instance this needs fixing */
			/* "obd" is set in config_log_find_or_add() */
			struct obd_device *obd = (void *)cfg->cfg_instance;

			lustre_cfg_bufs_set(&bufs, 2, bufs.lcfg_buf[1],
					    bufs.lcfg_buflen[1]);
			lustre_cfg_bufs_set(&bufs, 1, bufs.lcfg_buf[0],
					    bufs.lcfg_buflen[0]);
			lustre_cfg_bufs_set_string(&bufs, 0,
						   obd->obd_name);
		}

		/*
		 * Add net info to setup command
		 * if given on command line.
		 * So config log will be:
		 * [0]: client name
		 * [1]: client UUID
		 * [2]: server UUID
		 * [3]: inactive-on-startup
		 * [4]: restrictive net
		 */
		if (cfg && cfg->cfg_sb && s2lsi(cfg->cfg_sb) &&
		    !IS_SERVER(s2lsi(cfg->cfg_sb))) {
			struct lustre_sb_info *lsi = s2lsi(cfg->cfg_sb);
			char *nidnet = lsi->lsi_lmd->lmd_nidnet;

			if (lcfg->lcfg_command == LCFG_SETUP &&
			    lcfg->lcfg_bufcount != 2 && nidnet) {
				CDEBUG(D_CONFIG, "Adding net %s info to setup "
				       "command for client %s\n", nidnet,
				       lustre_cfg_string(lcfg, 0));
				lustre_cfg_bufs_set_string(&bufs, 4, nidnet);
			}
		}

		/*
		 * Skip add_conn command if uuid is
		 * not on restricted net
		 */
		if (cfg && cfg->cfg_sb && s2lsi(cfg->cfg_sb) &&
		    !IS_SERVER(s2lsi(cfg->cfg_sb))) {
			struct lustre_sb_info *lsi = s2lsi(cfg->cfg_sb);
			char *uuid_str = lustre_cfg_string(lcfg, 1);

			if (lcfg->lcfg_command == LCFG_ADD_CONN &&
			    lsi->lsi_lmd->lmd_nidnet &&
			    LNET_NIDNET(libcfs_str2nid(uuid_str)) !=
			    libcfs_str2net(lsi->lsi_lmd->lmd_nidnet)) {
				CDEBUG(D_CONFIG, "skipping add_conn for %s\n",
				       uuid_str);
				rc = 0;
				/* No processing! */
				break;
			}
		}

		OBD_ALLOC(lcfg_new, lustre_cfg_len(bufs.lcfg_bufcount,
						   bufs.lcfg_buflen));
		if (!lcfg_new)
			GOTO(out, rc = -ENOMEM);

		lustre_cfg_init(lcfg_new, lcfg->lcfg_command, &bufs);
		lcfg_new->lcfg_num   = lcfg->lcfg_num;
		lcfg_new->lcfg_flags = lcfg->lcfg_flags;

		/*
		 * XXX Hack to try to remain binary compatible with
		 * pre-newconfig logs
		 */
		if (lcfg->lcfg_nal != 0 &&      /* pre-newconfig log? */
		    (lcfg->lcfg_nid >> 32) == 0) {
			__u32 addr = (__u32)(lcfg->lcfg_nid & 0xffffffff);

			lcfg_new->lcfg_nid =
				LNET_MKNID(LNET_MKNET(lcfg->lcfg_nal, 0), addr);
			CWARN("Converted pre-newconfig NAL %d NID %x to %s\n",
			      lcfg->lcfg_nal, addr,
			      libcfs_nid2str(lcfg_new->lcfg_nid));
		} else {
			lcfg_new->lcfg_nid = lcfg->lcfg_nid;
		}

		lcfg_new->lcfg_nal = 0; /* illegal value for obsolete field */

		rc = class_process_config(lcfg_new);
		OBD_FREE(lcfg_new, lustre_cfg_len(lcfg_new->lcfg_bufcount,
						  lcfg_new->lcfg_buflens));
		if (inst_name)
			OBD_FREE(inst_name, inst_len);
		break;
	}
	default:
		CERROR("Unknown llog record type %#x encountered\n",
		       rec->lrh_type);
		break;
	}
out:
	if (rc) {
		CERROR("%s: cfg command failed: rc = %d\n",
			handle->lgh_ctxt->loc_obd->obd_name, rc);
		class_config_dump_handler(NULL, handle, rec, data);
	}
	RETURN(rc);
}
EXPORT_SYMBOL(class_config_llog_handler);

int class_config_parse_llog(const struct lu_env *env, struct llog_ctxt *ctxt,
			    char *name, struct config_llog_instance *cfg)
{
	struct llog_process_cat_data cd = {
		.lpcd_first_idx = 0,
	};
	struct llog_handle *llh;
	llog_cb_t callback;
	int rc;
	ENTRY;

	CDEBUG(D_INFO, "looking up llog %s\n", name);
	rc = llog_open(env, ctxt, &llh, NULL, name, LLOG_OPEN_EXISTS);
	if (rc)
		RETURN(rc);

	rc = llog_init_handle(env, llh, LLOG_F_IS_PLAIN, NULL);
	if (rc)
		GOTO(parse_out, rc);

	/* continue processing from where we last stopped to end-of-log */
	if (cfg) {
		cd.lpcd_first_idx = cfg->cfg_last_idx;
		callback = cfg->cfg_callback;
		LASSERT(callback != NULL);
	} else {
		callback = class_config_llog_handler;
	}

	cd.lpcd_last_idx = 0;

	rc = llog_process(env, llh, callback, cfg, &cd);

	CDEBUG(D_CONFIG, "Processed log %s gen %d-%d (rc=%d)\n", name,
	       cd.lpcd_first_idx + 1, cd.lpcd_last_idx, rc);
	if (cfg)
		cfg->cfg_last_idx = cd.lpcd_last_idx;

parse_out:
	llog_close(env, llh);
	RETURN(rc);
}
EXPORT_SYMBOL(class_config_parse_llog);

/**
 * Parse config record and output dump in supplied buffer.
 *
 * This is separated from class_config_dump_handler() to use
 * for ioctl needs as well
 *
 * Sample Output:
 * - { index: 4, event: attach, device: lustrewt-clilov, type: lov,
 *     UUID: lustrewt-clilov_UUID }
 */
int class_config_yaml_output(struct llog_rec_hdr *rec, char *buf, int size)
{
	struct lustre_cfg *lcfg = (struct lustre_cfg *)(rec + 1);
	char *ptr = buf;
	char *end = buf + size;
	int rc = 0, i;
	struct lcfg_type_data *ldata;

	LASSERT(rec->lrh_type == OBD_CFG_REC);
	rc = lustre_cfg_sanity_check(lcfg, rec->lrh_len);
	if (rc < 0)
		return rc;

	ldata = lcfg_cmd2data(lcfg->lcfg_command);
	if (!ldata)
		return -ENOTTY;

	if (lcfg->lcfg_command == LCFG_MARKER)
		return 0;

	/* form YAML entity */
	ptr += snprintf(ptr, end - ptr, "- { index: %u, event: %s",
			rec->lrh_index, ldata->ltd_name);
	if (end - ptr <= 0)
		goto out_overflow;

	if (lcfg->lcfg_flags) {
		ptr += snprintf(ptr, end - ptr, ", flags: %#08x",
				lcfg->lcfg_flags);
		if (end - ptr <= 0)
			goto out_overflow;
	}
	if (lcfg->lcfg_num) {
		ptr += snprintf(ptr, end - ptr, ", num: %#08x",
				lcfg->lcfg_num);
		if (end - ptr <= 0)
			goto out_overflow;
	}
	if (lcfg->lcfg_nid) {
		char nidstr[LNET_NIDSTR_SIZE];

		libcfs_nid2str_r(lcfg->lcfg_nid, nidstr, sizeof(nidstr));
		ptr += snprintf(ptr, end - ptr, ", nid: %s(%#llx)",
				nidstr, lcfg->lcfg_nid);
		if (end - ptr <= 0)
			goto out_overflow;
	}

	if (LUSTRE_CFG_BUFLEN(lcfg, 0) > 0) {
		ptr += snprintf(ptr, end - ptr, ", device: %s",
				lustre_cfg_string(lcfg, 0));
		if (end - ptr <= 0)
			goto out_overflow;
	}

	if (lcfg->lcfg_command == LCFG_SET_PARAM) {
		/*
		 * set_param -P parameters have param=val here, separate
		 * them through pointer magic and print them out in
		 * native yamlese
		 */
		char *cfg_str = lustre_cfg_string(lcfg, 1);
		char *tmp = strchr(cfg_str, '=');
		size_t len;

		if (!tmp)
			goto out_done;

		ptr += snprintf(ptr, end - ptr, ", %s: ", ldata->ltd_bufs[0]);
		len = tmp - cfg_str + 1;
		snprintf(ptr, len, "%s", cfg_str);
		ptr += len - 1;

		ptr += snprintf(ptr, end - ptr, ", %s: ", ldata->ltd_bufs[1]);
		ptr += snprintf(ptr, end - ptr, "%s", tmp + 1);

		goto out_done;
	}

	for (i = 1; i < lcfg->lcfg_bufcount; i++) {
		if (LUSTRE_CFG_BUFLEN(lcfg, i) > 0) {
			ptr += snprintf(ptr, end - ptr, ", %s: %s",
					ldata->ltd_bufs[i - 1],
					lustre_cfg_string(lcfg, i));
			if (end - ptr <= 0)
				goto out_overflow;
		}
	}

out_done:
	ptr += snprintf(ptr, end - ptr, " }\n");
out_overflow:
	/* Return consumed bytes.  If the buffer overflowed, zero last byte */
	rc = ptr - buf;
	if (rc > size) {
		rc = -EOVERFLOW;
		*(end - 1) = '\0';
	}

	return rc;
}

/**
 * parse config record and output dump in supplied buffer.
 * This is separated from class_config_dump_handler() to use
 * for ioctl needs as well
 */
static int class_config_parse_rec(struct llog_rec_hdr *rec, char *buf, int size)
{
	struct lustre_cfg	*lcfg = (struct lustre_cfg *)(rec + 1);
	char			*ptr = buf;
	char			*end = buf + size;
	int			 rc = 0;

	ENTRY;

	LASSERT(rec->lrh_type == OBD_CFG_REC);
	rc = lustre_cfg_sanity_check(lcfg, rec->lrh_len);
	if (rc < 0)
		RETURN(rc);

	ptr += snprintf(ptr, end-ptr, "cmd=%05x ", lcfg->lcfg_command);
	if (lcfg->lcfg_flags)
		ptr += snprintf(ptr, end-ptr, "flags=%#08x ",
				lcfg->lcfg_flags);

	if (lcfg->lcfg_num)
		ptr += snprintf(ptr, end-ptr, "num=%#08x ", lcfg->lcfg_num);

	if (lcfg->lcfg_nid) {
		char nidstr[LNET_NIDSTR_SIZE];

		libcfs_nid2str_r(lcfg->lcfg_nid, nidstr, sizeof(nidstr));
		ptr += snprintf(ptr, end-ptr, "nid=%s(%#llx)    ",
				nidstr, lcfg->lcfg_nid);
	}

	if (lcfg->lcfg_command == LCFG_MARKER) {
		struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);

		ptr += snprintf(ptr, end-ptr, "marker=%d(%#x)%s '%s'",
				marker->cm_step, marker->cm_flags,
				marker->cm_tgtname, marker->cm_comment);
	} else {
		int i;

		for (i = 0; i <  lcfg->lcfg_bufcount; i++) {
			ptr += snprintf(ptr, end-ptr, "%d:%s  ", i,
					lustre_cfg_string(lcfg, i));
		}
	}
	ptr += snprintf(ptr, end - ptr, "\n");
	/* return consumed bytes */
	rc = ptr - buf;
	RETURN(rc);
}

int class_config_dump_handler(const struct lu_env *env,
			      struct llog_handle *handle,
			      struct llog_rec_hdr *rec, void *data)
{
	char *outstr;
	int rc = 0;

	ENTRY;

	OBD_ALLOC(outstr, 256);
	if (!outstr)
		RETURN(-ENOMEM);

	if (rec->lrh_type == OBD_CFG_REC) {
		class_config_parse_rec(rec, outstr, 256);
		LCONSOLE(D_WARNING, "   %s\n", outstr);
	} else {
		LCONSOLE(D_WARNING, "unhandled lrh_type: %#x\n", rec->lrh_type);
		rc = -EINVAL;
	}

	OBD_FREE(outstr, 256);
	RETURN(rc);
}

/**
 * Call class_cleanup and class_detach.
 * "Manual" only in the sense that we're faking lcfg commands.
 */
int class_manual_cleanup(struct obd_device *obd)
{
	char flags[3] = "";
	struct lustre_cfg *lcfg;
	struct lustre_cfg_bufs bufs;
	int rc;

	ENTRY;

	if (!obd) {
		CERROR("empty cleanup\n");
		RETURN(-EALREADY);
	}

	if (obd->obd_force)
		strlcat(flags, "F", sizeof(flags));
	if (obd->obd_fail)
		strlcat(flags, "A", sizeof(flags));

	CDEBUG(D_CONFIG, "Manual cleanup of %s (flags='%s')\n",
	       obd->obd_name, flags);

	lustre_cfg_bufs_reset(&bufs, obd->obd_name);
	lustre_cfg_bufs_set_string(&bufs, 1, flags);
	OBD_ALLOC(lcfg, lustre_cfg_len(bufs.lcfg_bufcount, bufs.lcfg_buflen));
	if (!lcfg)
		RETURN(-ENOMEM);
	lustre_cfg_init(lcfg, LCFG_CLEANUP, &bufs);

	rc = class_process_config(lcfg);
	if (rc) {
		CERROR("cleanup failed %d: %s\n", rc, obd->obd_name);
		GOTO(out, rc);
	}

	/* the lcfg is almost the same for both ops */
	lcfg->lcfg_command = LCFG_DETACH;
	rc = class_process_config(lcfg);
	if (rc)
		CERROR("detach failed %d: %s\n", rc, obd->obd_name);
out:
	OBD_FREE(lcfg, lustre_cfg_len(lcfg->lcfg_bufcount, lcfg->lcfg_buflens));
	RETURN(rc);
}
EXPORT_SYMBOL(class_manual_cleanup);

#ifdef HAVE_SERVER_SUPPORT
/*
 * nid<->nidstats hash operations
 */
static unsigned
nidstats_hash(struct cfs_hash *hs, const void *key, unsigned int mask)
{
	return cfs_hash_djb2_hash(key, sizeof(lnet_nid_t), mask);
}

static void *
nidstats_key(struct hlist_node *hnode)
{
	struct nid_stat *ns;

	ns = hlist_entry(hnode, struct nid_stat, nid_hash);

	return &ns->nid;
}

static int
nidstats_keycmp(const void *key, struct hlist_node *hnode)
{
	return *(lnet_nid_t *)nidstats_key(hnode) == *(lnet_nid_t *)key;
}

static void *
nidstats_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct nid_stat, nid_hash);
}

static void
nidstats_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nid_stat *ns;

	ns = hlist_entry(hnode, struct nid_stat, nid_hash);
	nidstat_getref(ns);
}

static void
nidstats_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct nid_stat *ns;

	ns = hlist_entry(hnode, struct nid_stat, nid_hash);
	nidstat_putref(ns);
}

static struct cfs_hash_ops nid_stat_hash_ops = {
	.hs_hash        = nidstats_hash,
	.hs_key         = nidstats_key,
	.hs_keycmp      = nidstats_keycmp,
	.hs_object      = nidstats_object,
	.hs_get         = nidstats_get,
	.hs_put_locked  = nidstats_put_locked,
};


/*
 * client_generation<->export hash operations
 */

static unsigned
gen_hash(struct cfs_hash *hs, const void *key, unsigned mask)
{
	return cfs_hash_djb2_hash(key, sizeof(__u32), mask);
}

static void *
gen_key(struct hlist_node *hnode)
{
	struct obd_export *exp;

	exp = hlist_entry(hnode, struct obd_export, exp_gen_hash);

	RETURN(&exp->exp_target_data.ted_lcd->lcd_generation);
}

/*
 * NOTE: It is impossible to find an export that is in failed
 *       state with this function
 */
static int
gen_kepcmp(const void *key, struct hlist_node *hnode)
{
	struct obd_export *exp;

	LASSERT(key);
	exp = hlist_entry(hnode, struct obd_export, exp_gen_hash);

	RETURN(exp->exp_target_data.ted_lcd->lcd_generation == *(__u32 *)key &&
	       !exp->exp_failed);
}

static void *
gen_export_object(struct hlist_node *hnode)
{
	return hlist_entry(hnode, struct obd_export, exp_gen_hash);
}

static void
gen_export_get(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct obd_export *exp;

	exp = hlist_entry(hnode, struct obd_export, exp_gen_hash);
	class_export_get(exp);
}

static void
gen_export_put_locked(struct cfs_hash *hs, struct hlist_node *hnode)
{
	struct obd_export *exp;

	exp = hlist_entry(hnode, struct obd_export, exp_gen_hash);
	class_export_put(exp);
}

static struct cfs_hash_ops gen_hash_ops = {
	.hs_hash        = gen_hash,
	.hs_key         = gen_key,
	.hs_keycmp      = gen_kepcmp,
	.hs_object      = gen_export_object,
	.hs_get         = gen_export_get,
	.hs_put_locked  = gen_export_put_locked,
};

#endif /* HAVE_SERVER_SUPPORT */
