/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Copyright (C) 2004, 2005 Cluster File Systems, Inc.
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

#include <linux/lustre_fsfilt.h>
#include <linux/lustre_sec.h>

#include "filter_internal.h"

void filter_free_capa_keys(struct filter_obd *filter)
{
        struct filter_capa_key *key, *n;

        spin_lock(&filter->fo_capa_lock);
        list_for_each_entry_safe(key, n, &filter->fo_capa_keys, k_list) {
                list_del_init(&key->k_list);
                OBD_FREE(key, sizeof(*key));
        }
        spin_unlock(&filter->fo_capa_lock);
}

int filter_update_capa_key(struct obd_device *obd, struct lustre_capa_key *key)
{
        struct filter_obd *filter = &obd->u.filter;
        struct filter_capa_key *tmp = NULL, *rkey = NULL, *bkey = NULL;
        int rc = 0;
        ENTRY;

        spin_lock(&filter->fo_capa_lock);
        list_for_each_entry(tmp, &filter->fo_capa_keys, k_list) {
                if (tmp->k_key.lk_mdsid != le32_to_cpu(key->lk_mdsid))
                        continue;

                if (rkey == NULL)
                        rkey = tmp;
                else
                        bkey = tmp;
        }
        spin_unlock(&filter->fo_capa_lock);

        if (rkey && bkey && capa_key_cmp(&rkey->k_key, &bkey->k_key) < 0) {
                tmp = rkey;
                rkey = bkey;
                bkey = tmp;
        }

        if (bkey) {
                tmp = bkey;

                DEBUG_CAPA_KEY(D_INFO, &tmp->k_key, "filter update");
        } else {
                OBD_ALLOC(tmp, sizeof(*tmp));
                if (!tmp)
                        GOTO(out, rc = -ENOMEM);

                DEBUG_CAPA_KEY(D_INFO, &tmp->k_key, "filter new");
        }

        /* fields in lustre_capa_key are in cpu order */
        spin_lock(&filter->fo_capa_lock);
        tmp->k_key.lk_mdsid = le32_to_cpu(key->lk_mdsid);
        tmp->k_key.lk_keyid = le32_to_cpu(key->lk_keyid);
        tmp->k_key.lk_expiry = le64_to_cpu(key->lk_expiry);
        memcpy(&tmp->k_key.lk_key, key->lk_key, sizeof(key->lk_key));

        if (!bkey)
                list_add_tail(&tmp->k_list, &filter->fo_capa_keys);
        spin_unlock(&filter->fo_capa_lock);
out:
        RETURN(rc);
}

int filter_verify_fid(struct obd_export *exp, struct inode *inode,
                      struct lustre_capa *capa)
{
        struct lustre_id fid;
        int rc;

        if (!capa)
                return 0;

        ENTRY;
        rc = fsfilt_get_md(exp->exp_obd, inode, &fid, sizeof(fid), EA_SID);
        if (rc < 0) {
                CERROR("get fid from object failed! rc:%d\n", rc);
                RETURN(rc);
        } else if (rc > 0) {
                if (capa->lc_mdsid != id_group(&fid) ||
                    capa->lc_ino != id_ino(&fid))
                        RETURN(-EINVAL);
        }

        RETURN(0);
}

int
filter_verify_capa(int cmd, struct obd_export *exp, struct lustre_capa *capa)
{
        struct obd_device *obd = exp->exp_obd;
        struct filter_obd *filter = &obd->u.filter;
        struct obd_capa *ocapa;
        struct lustre_capa tcapa;
        struct filter_capa_key *rkey = NULL, *bkey = NULL, *tmp;
        __u8 hmac_key[CAPA_KEY_LEN];
        int rc = 0;

        /* capability is disabled */
        if (filter->fo_capa_stat == 0)
                RETURN(0);

        ENTRY;
        if (capa == NULL)
                RETURN(-EACCES);

        if (cmd == OBD_BRW_WRITE && capa->lc_op != MAY_WRITE)
                RETURN(-EACCES);
        if (cmd == OBD_BRW_READ && !(capa->lc_op & (MAY_WRITE | MAY_READ)))
                RETURN(-EACCES);

        if (OBD_FAIL_CHECK(OBD_FAIL_FILTER_VERIFY_CAPA))
                RETURN(-EACCES);

        if (capa_expired(capa))
                RETURN(-ESTALE);

        ocapa = capa_get(capa->lc_uid, capa->lc_op, capa->lc_mdsid,
                         capa->lc_ino, FILTER_CAPA, NULL, NULL, NULL);
verify:
        if (ocapa) {
                /* fo_capa_lock protects capa too */
                spin_lock(&filter->fo_capa_lock);
                if (capa->lc_keyid == ocapa->c_capa.lc_keyid) {
                        rc = memcmp(capa, &ocapa->c_capa, sizeof(*capa));
                } else if (ocapa->c_bvalid &&
                           capa->lc_keyid == ocapa->c_bkeyid) {
                        rc = memcmp(capa->lc_hmac, ocapa->c_bhmac,
                                    sizeof(capa->lc_hmac));
                } else {
                        /* ocapa is obsolete */
                        capa_put(ocapa, FILTER_CAPA);
                        spin_unlock(&filter->fo_capa_lock);
                        goto new_capa;
                }
                spin_unlock(&filter->fo_capa_lock);

                capa_put(ocapa, FILTER_CAPA);
                RETURN(rc ? -EACCES : 0);
        }

new_capa:
        spin_lock(&filter->fo_capa_lock);
        list_for_each_entry(tmp, &filter->fo_capa_keys, k_list) {
                if (tmp->k_key.lk_mdsid == capa->lc_mdsid) {
                        if (rkey == NULL)
                                rkey = tmp;
                        else
                                bkey = tmp;
                }
        }

        if (rkey && bkey && capa_key_cmp(&rkey->k_key, &bkey->k_key) < 0) {
                tmp = rkey;
                rkey = bkey;
                bkey = tmp;
        }

        if ((!rkey || rkey->k_key.lk_keyid != capa->lc_keyid) &&
            (!bkey || bkey->k_key.lk_keyid != capa->lc_keyid)) {
                spin_unlock(&filter->fo_capa_lock);
                GOTO(out, rc = -ESTALE);
        }

        LASSERT(rkey);

        memcpy(&tcapa, capa, sizeof(tcapa));
        tcapa.lc_keyid = rkey->k_key.lk_keyid;
        memcpy(hmac_key, rkey->k_key.lk_key, sizeof(hmac_key));
        spin_unlock(&filter->fo_capa_lock);

        capa_hmac(filter->fo_capa_hmac, hmac_key, &tcapa);

        /* store in capa cache */
        ocapa = capa_get(capa->lc_uid, capa->lc_op, capa->lc_mdsid,
                         capa->lc_ino, FILTER_CAPA, capa, NULL, NULL);
        if (!ocapa)
                GOTO(out, rc = -ENOMEM);

        if (bkey) {
                spin_lock(&filter->fo_capa_lock);
                tcapa.lc_keyid = bkey->k_key.lk_keyid;
                memcpy(hmac_key, bkey->k_key.lk_key, sizeof(hmac_key));
                ocapa->c_bkeyid = bkey->k_key.lk_keyid;
                spin_unlock(&filter->fo_capa_lock);

                capa_hmac(filter->fo_capa_hmac, bkey->k_key.lk_key, &tcapa);

                spin_lock(&filter->fo_capa_lock);
                memcpy(ocapa->c_bhmac, tcapa.lc_hmac, sizeof(ocapa->c_bhmac));
                spin_unlock(&filter->fo_capa_lock);
        }
        goto verify;
out:
        RETURN(rc);
}
