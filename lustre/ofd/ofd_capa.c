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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, 2014 Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/ofd/ofd_capa.c
 *
 * This file provides helper functions for Lustre capability key management and
 * capability authentication. A capability is a token of authority, which is
 * distributed by MDT to client upon open/lookup/getattr/setattr and unlink
 * (this is not needed for new servers because destroying objects on OST is
 * originated from MDT, which doesn't need capability), and will be packed
 * into subsequent requests to MDT and OST. Capability key is shared by MDT and
 * OST, which is used to sign and authenticate capability (HMAC algorithm).
 *
 * Author: Lai Siyao <lai.siyao@intel.com>
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

static inline __u32 ofd_ck_keyid(struct filter_capa_key *key)
{
	return key->k_key.lk_keyid;
}

/**
 * Update capability key
 *
 * A new capability key is received from MDT, because MDT only uses the
 * latest key to sign capability, OFD caches the latest two keys in case client
 * still helds capability signed with old key.
 *
 * \param[in] ofd	OFD device
 * \param[in] new	new capability key
 * \retval		0 on success
 * \retval		negative number on error
 */
int ofd_update_capa_key(struct ofd_device *ofd, struct lustre_capa_key *new)
{
	struct obd_device	*obd = ofd_obd(ofd);
	struct filter_capa_key	*k, *keys[2] = { NULL, NULL };
	int			 i;

	spin_lock(&capa_lock);
	list_for_each_entry(k, &obd->u.filter.fo_capa_keys, k_list) {
		if (k->k_key.lk_seq != new->lk_seq)
			continue;

		if (keys[0]) {
			keys[1] = k;
			if (ofd_ck_keyid(keys[1]) > ofd_ck_keyid(keys[0]))
				keys[1] = keys[0], keys[0] = k;
		} else {
			keys[0] = k;
		}
	}
	spin_unlock(&capa_lock);

	for (i = 0; i < 2; i++) {
		if (!keys[i])
			continue;
		if (ofd_ck_keyid(keys[i]) != new->lk_keyid)
			continue;
		/* maybe because of recovery or other reasons, MDS sent the
		 * the old capability key again.
		 */
		spin_lock(&capa_lock);
		keys[i]->k_key = *new;
		spin_unlock(&capa_lock);

		RETURN(0);
	}

	if (keys[1]) {
		/* if OSS already have two keys, update the old one */
		k = keys[1];
	} else {
		OBD_ALLOC_PTR(k);
		if (!k)
			RETURN(-ENOMEM);
		INIT_LIST_HEAD(&k->k_list);
	}

	spin_lock(&capa_lock);
	k->k_key = *new;
	if (list_empty(&k->k_list))
		list_add(&k->k_list, &obd->u.filter.fo_capa_keys);
	spin_unlock(&capa_lock);

	DEBUG_CAPA_KEY(D_SEC, new, "new");
	RETURN(0);
}

/**
 * Authenticate capability
 *
 * OFD authenticate the capability packed in client request. Firstly, it will
 * lookup from local cache, if found, compare with it, otherwise sign it with
 * capability key to validate it. If the capability is valid, it will be added
 * into local cache for later use.
 *
 * \param[in] exp	export for the client
 * \param[in] fid	master fid (on MDT) of the file
 * \param[in] seq	OST sequence extracted from master fid
 * \param[in] capa	capability extracted from client request
 * \param[in] opc	opcode the caller requested
 * \retval		0 on success
 * \retval		negative number on error
 */
int ofd_auth_capa(struct obd_export *exp, const struct lu_fid *fid,
		  u64 seq, struct lustre_capa *capa, __u64 opc)
{
	struct filter_obd	*filter = &exp->exp_obd->u.filter;
	struct filter_capa_key	*k;
	struct lustre_capa_key	 key;
	struct obd_capa		*oc;
	__u8			*hmac;
	int			 keys_ready = 0, key_found = 0, rc = 0;

	ENTRY;

	/* skip capa check for llog and obdecho */
	if (!fid_seq_is_mdt(seq))
		RETURN(0);

	/* capability is disabled */
	if (!filter->fo_fl_oss_capa)
		RETURN(0);

	if (!(exp_connect_flags(exp) & OBD_CONNECT_OSS_CAPA))
		RETURN(0);

	if (capa == NULL) {
		if (fid)
			CERROR("seq/fid/opc "LPU64"/"DFID"/"LPX64
			       ": no capability has been passed\n",
			       seq, PFID(fid), opc);
		else
			CERROR("seq/opc "LPU64"/"LPX64
			       ": no capability has been passed\n",
			       seq, opc);
		RETURN(-EACCES);
	}

	if (opc == CAPA_OPC_OSS_READ) {
		if (!(capa->lc_opc & CAPA_OPC_OSS_RW))
			rc = -EACCES;
	} else if (!capa_opc_supported(capa, opc)) {
		rc = -EACCES;
	}

	if (rc) {
		DEBUG_CAPA(D_ERROR, capa, "opc "LPX64" not supported by", opc);
		RETURN(rc);
	}

	oc = capa_lookup(filter->fo_capa_hash, capa, 0);
	if (oc) {
		spin_lock(&oc->c_lock);
		if (capa_is_expired(oc)) {
			DEBUG_CAPA(D_ERROR, capa, "expired");
			rc = -ESTALE;
		}
		spin_unlock(&oc->c_lock);

		capa_put(oc);
		RETURN(rc);
	}

	if (capa_is_expired_sec(capa)) {
		DEBUG_CAPA(D_ERROR, capa, "expired");
		RETURN(-ESTALE);
	}

	spin_lock(&capa_lock);
	list_for_each_entry(k, &filter->fo_capa_keys, k_list) {
		if (k->k_key.lk_seq == seq) {
			keys_ready = 1;
			if (k->k_key.lk_keyid == capa_keyid(capa)) {
				key = k->k_key;
				key_found = 1;
				break;
			}
		}
	}
	spin_unlock(&capa_lock);

	if (!keys_ready) {
		CDEBUG(D_SEC, "MDS hasn't propagated capability keys yet, "
		       "ignore check!\n");
		RETURN(0);
	}

	if (!key_found) {
		DEBUG_CAPA(D_ERROR, capa, "no matched capability key for");
		RETURN(-ESTALE);
	}

	OBD_ALLOC(hmac, CAPA_HMAC_MAX_LEN);
	if (hmac == NULL)
		RETURN(-ENOMEM);

	rc = capa_hmac(hmac, capa, key.lk_key);
	if (rc) {
		DEBUG_CAPA(D_ERROR, capa, "HMAC failed: rc %d", rc);
		OBD_FREE(hmac, CAPA_HMAC_MAX_LEN);
		RETURN(rc);
	}

	rc = memcmp(hmac, capa->lc_hmac, CAPA_HMAC_MAX_LEN);
	OBD_FREE(hmac, CAPA_HMAC_MAX_LEN);
	if (rc) {
		DEBUG_CAPA_KEY(D_ERROR, &key, "calculate HMAC with ");
		DEBUG_CAPA(D_ERROR, capa, "HMAC mismatch");
		RETURN(-EACCES);
	}

	/* store in capa hash */
	oc = capa_add(filter->fo_capa_hash, capa);
	capa_put(oc);
	RETURN(0);
}

/**
 * Free capability keys
 *
 * OFD free cached capability keys when OFD device is destroyed.
 *
 *  \param[in] ofd	OFD device
 */
void ofd_free_capa_keys(struct ofd_device *ofd)
{
	struct obd_device	*obd = ofd_obd(ofd);
	struct filter_capa_key	*key, *n;

	spin_lock(&capa_lock);
	list_for_each_entry_safe(key, n, &obd->u.filter.fo_capa_keys, k_list) {
		list_del_init(&key->k_list);
		OBD_FREE_PTR(key);
	}
	spin_unlock(&capa_lock);
}
