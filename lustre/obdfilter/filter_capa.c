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

/*
 * FIXME
 * keep this as simple as possible. we suppose the blacklist usually
 * be empry or very short (<5), since long term blacklist should be
 * done on MDS side. A more sophisticated blacklist will be implemented
 * later.
 *
 * note blacklist didn't take effect when OSS capability disabled. this
 * looks reasonable to me.
 */
#define BLACKLIST_MAX   (32)
static int nblacklist = 0;
static uid_t blacklist[BLACKLIST_MAX];
static spinlock_t blacklist_lock = SPIN_LOCK_UNLOCKED;

int blacklist_display(char *buf, int bufsize)
{
        char one[16];
        int i;
        LASSERT(buf);

        buf[0] = '\0';
        spin_lock(&blacklist_lock);
        for (i = 0; i < nblacklist; i++) {
                snprintf(one, 16, "%u\n", blacklist[i]);
                strncat(buf, one, bufsize);
        }
        spin_unlock(&blacklist_lock);
        return strnlen(buf, bufsize);
}

void blacklist_add(uid_t uid)
{
        int i;

        spin_lock(&blacklist_lock);
        if (nblacklist == BLACKLIST_MAX) {
                CERROR("can't add more in blacklist\n");
                spin_unlock(&blacklist_lock);
                return;
        }

        for (i = 0; i < nblacklist; i++) {
                if (blacklist[i] == uid) {
                        spin_unlock(&blacklist_lock);
                        return;
                }
        }

        blacklist[nblacklist++] = uid;
        spin_unlock(&blacklist_lock);
}

void blacklist_del(uid_t uid)
{
        int i;

        spin_lock(&blacklist_lock);
        for (i = 0; i < nblacklist; i++) {
                if (blacklist[i] == uid) {
                        nblacklist--;
                        while (i < nblacklist) {
                                blacklist[i] = blacklist[i+1];
                                i++;
                        }
                        spin_unlock(&blacklist_lock);
                        return;
                }
        }
        spin_unlock(&blacklist_lock);
}

int blacklist_check(uid_t uid)
{
        int i, rc = 0;

        spin_lock(&blacklist_lock);
        for (i = 0; i < nblacklist; i++) {
                if (blacklist[i] == uid) {
                        rc = 1;
                        break;
                }
        }
        spin_unlock(&blacklist_lock);
        return rc;
}


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
        struct filter_capa_key *rkey = NULL, *bkey = NULL, *tmp, capa_keys[2];
        int rc = 0;

        /* capability is disabled */
        if (filter->fo_capa_stat == 0)
                RETURN(0);

        ENTRY;
        if (capa == NULL) {
                CDEBUG(D_ERROR, "no capa has been passed\n");
                RETURN(-EACCES);
        }

        if (blacklist_check(capa->lc_uid)) {
                DEBUG_CAPA(D_ERROR, capa, "found in blacklist\n");
                RETURN(-EACCES);
        }

        if (cmd == OBD_BRW_WRITE && !(capa->lc_op & (CAPA_WRITE | CAPA_TRUNC))) {
                DEBUG_CAPA(D_ERROR, capa, "have no write access\n");
                RETURN(-EACCES);
        }
        if (cmd == OBD_BRW_READ && !(capa->lc_op & (CAPA_WRITE | CAPA_READ))) {
                DEBUG_CAPA(D_ERROR, capa, "have no read access\n");
                RETURN(-EACCES);
        }

        if (OBD_FAIL_CHECK(OBD_FAIL_FILTER_VERIFY_CAPA))
                RETURN(-EACCES);

        if (capa_expired(capa)) {
                DEBUG_CAPA(D_INFO | D_ERROR, capa, "expired");
                RETURN(-ESTALE);
        }

        ocapa = filter_capa_get(capa);
verify:
        if (ocapa) {
                struct timeval tv;

                /* fo_capa_lock protects capa too */
                do_gettimeofday(&tv);
                spin_lock(&filter->fo_capa_lock);
                if (capa->lc_keyid == ocapa->c_capa.lc_keyid) {
                        rc = memcmp(capa, &ocapa->c_capa, sizeof(*capa));
                } else if (ocapa->c_bvalid &&
                           capa->lc_keyid == ocapa->c_bkeyid) {
                        rc = memcmp(capa->lc_hmac, ocapa->c_bhmac,
                                    sizeof(capa->lc_hmac));
                } else {
                        /* ocapa is obsolete too */
                        ocapa->c_bvalid = 0;
                        goto new_capa;
                }

                if (rc && __capa_is_to_expire(ocapa, &tv)) {
                        /* client should use new expiry now */
                        ocapa->c_bvalid = 0;
                        goto new_capa;
                }
                spin_unlock(&filter->fo_capa_lock);

                if (rc) {
                        char *key1 = NULL, *key2 = NULL;
                        OBD_ALLOC(key1, CAPA_DIGEST_SIZE * 2 + 1);
                        OBD_ALLOC(key2, CAPA_DIGEST_SIZE * 2 + 1);
                        if (key1 && key2) {
                                dump_capa_hmac(key1, capa->lc_hmac);
                                dump_capa_hmac(key2, ocapa->c_capa.lc_hmac);
                                DEBUG_CAPA(D_ERROR, capa,
                                           "access denied for (%s != %s)",
                                           key1, key2);
                                DEBUG_CAPA(D_ERROR, &ocapa->c_capa, "used capa");
                        }
                        if (key1)
                                OBD_FREE(key1, CAPA_DIGEST_SIZE * 2 + 1);
                        if (key2)
                                OBD_FREE(key2, CAPA_DIGEST_SIZE * 2 + 1);
                }
                capa_put(ocapa);
                RETURN(rc ? -EACCES : 0);
        }

        spin_lock(&filter->fo_capa_lock);
new_capa:
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
        capa_keys[0] = *rkey;
        if (bkey)
                capa_keys[1] = *bkey;
        spin_unlock(&filter->fo_capa_lock);

        tcapa = *capa;
        tcapa.lc_keyid = capa_keys[0].k_key.lk_keyid;
        capa_hmac(capa_keys[0].k_key.lk_key, &tcapa);

        /* store in capa cache */
        ocapa = capa_renew(&tcapa, FILTER_CAPA);
        if (!ocapa)
                GOTO(out, rc = -ENOMEM);

        if (bkey) {
                tcapa.lc_keyid = capa_keys[1].k_key.lk_keyid;
                capa_hmac(capa_keys[1].k_key.lk_key, &tcapa);

                spin_lock(&filter->fo_capa_lock);
                memcpy(ocapa->c_bhmac, tcapa.lc_hmac, sizeof(ocapa->c_bhmac));
                ocapa->c_bkeyid = capa_keys[1].k_key.lk_keyid;
                ocapa->c_bvalid = 1;
                spin_unlock(&filter->fo_capa_lock);
        }
        goto verify;
out:
        RETURN(rc);
}
