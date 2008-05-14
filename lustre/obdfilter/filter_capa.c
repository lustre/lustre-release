/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2005 Cluster File Systems, Inc.
 *
 * Author: Lai Siyao <lsy@clusterfs.com>
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

#define DEBUG_SUBSYSTEM S_FILTER

#include <linux/fs.h>
#include <linux/version.h>
#include <asm/uaccess.h>
#include <linux/file.h>
#include <linux/kmod.h>

#include <lustre_fsfilt.h>
#include <lustre_capa.h>

#include "filter_internal.h"

static inline __u32 filter_ck_keyid(struct filter_capa_key *key)
{
        return key->k_key.lk_keyid;
}

int filter_update_capa_key(struct obd_device *obd, struct lustre_capa_key *new)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_capa_key *k, *keys[2] = { NULL, NULL };
        int i;

        spin_lock(&capa_lock);
        list_for_each_entry(k, &filter->fo_capa_keys, k_list) {
                if (k->k_key.lk_mdsid != new->lk_mdsid)
                        continue;

                if (keys[0]) {
                        keys[1] = k;
                        if (filter_ck_keyid(keys[1]) > filter_ck_keyid(keys[0]))
                                keys[1] = keys[0], keys[0] = k;
                } else {
                        keys[0] = k;
                }
        }
        spin_unlock(&capa_lock);

        for (i = 0; i < 2; i++) {
                if (!keys[i])
                        continue;
                if (filter_ck_keyid(keys[i]) != new->lk_keyid)
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
                CFS_INIT_LIST_HEAD(&k->k_list);
        }

        spin_lock(&capa_lock);
        k->k_key = *new;
        if (list_empty(&k->k_list))
                list_add(&k->k_list, &filter->fo_capa_keys);
        spin_unlock(&capa_lock);

        DEBUG_CAPA_KEY(D_SEC, new, "new");
        RETURN(0);
}

int filter_auth_capa(struct obd_export *exp, struct lu_fid *fid, __u64 mdsid,
                     struct lustre_capa *capa, __u64 opc)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct filter_capa_key *k;
        struct lustre_capa_key key;
        struct obd_capa *oc;
        __u8 *hmac;
        int keys_ready = 0, key_found = 0, rc = 0;
        ENTRY;

        /* capability is disabled */
        if (!filter->fo_fl_oss_capa)
                RETURN(0);

        if (capa == NULL) {
                if (fid)
                        CERROR("mdsno/fid/opc "LPU64"/"DFID"/"LPX64
                               ": no capability has been passed\n",
                               mdsid, PFID(fid), opc);
                else
                        CERROR("mdsno/opc "LPU64"/"LPX64
                               ": no capability has been passed\n",
                               mdsid, opc);
                RETURN(-EACCES);
        }

#warning "enable fid check in filter_auth_capa() when fid stored in OSS object"

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

        spin_lock(&capa_lock);
        list_for_each_entry(k, &filter->fo_capa_keys, k_list)
                if (k->k_key.lk_mdsid == mdsid) {
                        keys_ready = 1;
                        if (k->k_key.lk_keyid == capa_keyid(capa)) {
                                key = k->k_key;
                                key_found = 1;
                                break;
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

void filter_free_capa_keys(struct filter_obd *filter)
{
        struct filter_capa_key *key, *n;

        spin_lock(&capa_lock);
        list_for_each_entry_safe(key, n, &filter->fo_capa_keys, k_list) {
                list_del_init(&key->k_list);
                OBD_FREE(key, sizeof(*key));
        }
        spin_unlock(&capa_lock);
}
