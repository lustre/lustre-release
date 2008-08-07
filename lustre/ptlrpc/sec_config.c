/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
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
 * Copyright  2008 Sun Microsystems, Inc. All rights reserved
 * Use is subject to license terms.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#ifndef EXPORT_SYMTAB
#define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_SEC

#include <libcfs/libcfs.h>
#ifndef __KERNEL__
#include <liblustre.h>
#include <libcfs/list.h>
#else
#include <linux/crypto.h>
#include <linux/key.h>
#endif

#include <obd.h>
#include <obd_class.h>
#include <obd_support.h>
#include <lustre_net.h>
#include <lustre_import.h>
#include <lustre_dlm.h>
#include <lustre_sec.h>

#include "ptlrpc_internal.h"

const char *sptlrpc_part2name(enum lustre_sec_part part)
{
        switch (part) {
        case LUSTRE_SP_CLI:
                return "cli";
        case LUSTRE_SP_MDT:
                return "mdt";
        case LUSTRE_SP_OST:
                return "ost";
        case LUSTRE_SP_MGS:
                return "mgs";
        case LUSTRE_SP_ANY:
                return "any";
        default:
                return "err";
        }
}
EXPORT_SYMBOL(sptlrpc_part2name);

enum lustre_sec_part sptlrpc_target_sec_part(struct obd_device *obd)
{
        const char *type = obd->obd_type->typ_name;

        if (!strcmp(type, LUSTRE_MDT_NAME))
                return LUSTRE_SP_MDT;
        if (!strcmp(type, LUSTRE_OST_NAME))
                return LUSTRE_SP_OST;
        if (!strcmp(type, LUSTRE_MGS_NAME))
                return LUSTRE_SP_MGS;

        CERROR("unknown target %p(%s)\n", obd, type);
        return LUSTRE_SP_ANY;
}
EXPORT_SYMBOL(sptlrpc_target_sec_part);

/****************************************
 * user supplied flavor string parsing  *
 ****************************************/

#ifdef HAVE_ADLER
#define BULK_HASH_ALG_DEFAULT   BULK_HASH_ALG_ADLER32
#else
#define BULK_HASH_ALG_DEFAULT   BULK_HASH_ALG_CRC32
#endif

typedef enum {
        BULK_TYPE_N = 0,
        BULK_TYPE_I = 1,
        BULK_TYPE_P = 2
} bulk_type_t;

static void get_default_flavor(struct sptlrpc_flavor *sf)
{
        sf->sf_rpc = SPTLRPC_FLVR_NULL;
        sf->sf_bulk_ciph = BULK_CIPH_ALG_NULL;
        sf->sf_bulk_hash = BULK_HASH_ALG_NULL;
        sf->sf_flags = 0;
}

static void get_flavor_by_rpc(struct sptlrpc_rule *rule, __u16 rpc_flavor)
{
        get_default_flavor(&rule->sr_flvr);

        rule->sr_flvr.sf_rpc = rpc_flavor;

        switch (rpc_flavor) {
        case SPTLRPC_FLVR_NULL:
                break;
        case SPTLRPC_FLVR_PLAIN:
        case SPTLRPC_FLVR_KRB5N:
        case SPTLRPC_FLVR_KRB5A:
                rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_DEFAULT;
                break;
        case SPTLRPC_FLVR_KRB5P:
                rule->sr_flvr.sf_bulk_ciph = BULK_CIPH_ALG_AES128;
                /* fall through */
        case SPTLRPC_FLVR_KRB5I:
                rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_SHA1;
                break;
        default:
                LBUG();
        }
}

static void get_flavor_by_bulk(struct sptlrpc_rule *rule,
                               __u16 rpc_flavor, bulk_type_t bulk_type)
{
        switch (bulk_type) {
        case BULK_TYPE_N:
                rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_NULL;
                rule->sr_flvr.sf_bulk_ciph = BULK_CIPH_ALG_NULL;
                break;
        case BULK_TYPE_I:
                switch (rpc_flavor) {
                case SPTLRPC_FLVR_PLAIN:
                case SPTLRPC_FLVR_KRB5N:
                case SPTLRPC_FLVR_KRB5A:
                        rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_DEFAULT;
                        break;
                case SPTLRPC_FLVR_KRB5I:
                case SPTLRPC_FLVR_KRB5P:
                        rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_SHA1;
                        break;
                default:
                        LBUG();
                }
                rule->sr_flvr.sf_bulk_ciph = BULK_CIPH_ALG_NULL;
                break;
        case BULK_TYPE_P:
                rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_SHA1;
                rule->sr_flvr.sf_bulk_ciph = BULK_CIPH_ALG_AES128;
                break;
        default:
                LBUG();
        }
}

static __u16 __flavors[] = {
        SPTLRPC_FLVR_NULL,
        SPTLRPC_FLVR_PLAIN,
        SPTLRPC_FLVR_KRB5N,
        SPTLRPC_FLVR_KRB5A,
        SPTLRPC_FLVR_KRB5I,
        SPTLRPC_FLVR_KRB5P,
};

#define __nflavors      ARRAY_SIZE(__flavors)

/*
 * flavor string format: rpc[-bulk{n|i|p}[:cksum/enc]]
 * for examples:
 *  null
 *  plain-bulki
 *  krb5p-bulkn
 *  krb5i-bulkp
 *  krb5i-bulkp:sha512/arc4
 */
static int parse_flavor(char *str, struct sptlrpc_rule *rule)
{
        const char     *f;
        char           *bulk, *alg, *enc;
        char            buf[64];
        bulk_type_t     bulk_type;
        __u8            i;
        ENTRY;

        if (str == NULL || str[0] == '\0') {
                rule->sr_flvr.sf_rpc = SPTLRPC_FLVR_INVALID;
                goto out;
        }

        for (i = 0; i < __nflavors; i++) {
                f = sptlrpc_rpcflavor2name(__flavors[i]);
                if (strncmp(str, f, strlen(f)) == 0)
                        break;
        }

        if (i >= __nflavors)
                GOTO(invalid, -EINVAL);

        /* prepare local buffer thus we can modify it as we want */
        strncpy(buf, str, 64);
        buf[64 - 1] = '\0';

        /* find bulk string */
        bulk = strchr(buf, '-');
        if (bulk)
                *bulk++ = '\0';

        /* now the first part must equal to rpc flavor name */
        if (strcmp(buf, f) != 0)
                GOTO(invalid, -EINVAL);

        get_flavor_by_rpc(rule, __flavors[i]);

        if (bulk == NULL)
                goto out;

        /* find bulk algorithm string */
        alg = strchr(bulk, ':');
        if (alg)
                *alg++ = '\0';

        /* verify bulk section */
        if (strcmp(bulk, "bulkn") == 0) {
                rule->sr_flvr.sf_bulk_hash = BULK_HASH_ALG_NULL;
                rule->sr_flvr.sf_bulk_ciph = BULK_CIPH_ALG_NULL;
                bulk_type = BULK_TYPE_N;
        } else if (strcmp(bulk, "bulki") == 0)
                bulk_type = BULK_TYPE_I;
        else if (strcmp(bulk, "bulkp") == 0)
                bulk_type = BULK_TYPE_P;
        else
                GOTO(invalid, -EINVAL);

        /* null flavor don't support bulk i/p */
        if (__flavors[i] == SPTLRPC_FLVR_NULL && bulk_type != BULK_TYPE_N)
                GOTO(invalid, -EINVAL);

        /* plain policy dosen't support bulk p */
        if (__flavors[i] == SPTLRPC_FLVR_PLAIN && bulk_type == BULK_TYPE_P)
                GOTO(invalid, -EINVAL);

        get_flavor_by_bulk(rule, __flavors[i], bulk_type);

        if (alg == NULL)
                goto out;

        /* find encryption algorithm string */
        enc = strchr(alg, '/');
        if (enc)
                *enc++ = '\0';

        /* checksum algorithm */
        for (i = 0; i < BULK_HASH_ALG_MAX; i++) {
                if (strcmp(alg, sptlrpc_get_hash_name(i)) == 0) {
                        rule->sr_flvr.sf_bulk_hash = i;
                        break;
                }
        }
        if (i >= BULK_HASH_ALG_MAX)
                GOTO(invalid, -EINVAL);

        /* privacy algorithm */
        if (enc) {
                for (i = 0; i < BULK_CIPH_ALG_MAX; i++) {
                        if (strcmp(enc, sptlrpc_get_ciph_name(i)) == 0) {
                                rule->sr_flvr.sf_bulk_ciph = i;
                                break;
                        }
                }
                if (i >= BULK_CIPH_ALG_MAX)
                        GOTO(invalid, -EINVAL);
        }

        /*
         * bulk combination sanity checks
         */
        if (bulk_type == BULK_TYPE_P &&
            rule->sr_flvr.sf_bulk_ciph == BULK_CIPH_ALG_NULL)
                GOTO(invalid, -EINVAL);

        if (bulk_type == BULK_TYPE_I &&
            (rule->sr_flvr.sf_bulk_hash == BULK_HASH_ALG_NULL ||
             rule->sr_flvr.sf_bulk_ciph != BULK_CIPH_ALG_NULL))
                GOTO(invalid, -EINVAL);

        if (bulk_type == BULK_TYPE_N &&
            (rule->sr_flvr.sf_bulk_hash != BULK_HASH_ALG_NULL ||
             rule->sr_flvr.sf_bulk_ciph != BULK_CIPH_ALG_NULL))
                GOTO(invalid, -EINVAL);

out:
        return 0;
invalid:
        CERROR("invalid flavor string: %s\n", str);
        return -EINVAL;
}

/****************************************
 * configure rules                      *
 ****************************************/

static void sptlrpc_rule_init(struct sptlrpc_rule *rule)
{
        rule->sr_netid = LNET_NIDNET(LNET_NID_ANY);
        rule->sr_from = LUSTRE_SP_ANY;
        rule->sr_to = LUSTRE_SP_ANY;
        rule->sr_padding = 0;

        get_default_flavor(&rule->sr_flvr);
}

/*
 * format: network[.direction]=flavor
 */
int sptlrpc_parse_rule(char *param, struct sptlrpc_rule *rule)
{
        char           *flavor, *dir;
        int             rc;

        sptlrpc_rule_init(rule);

        flavor = strchr(param, '=');
        if (flavor == NULL) {
                CERROR("invalid param, no '='\n");
                RETURN(-EINVAL);
        }
        *flavor++ = '\0';

        dir = strchr(param, '.');
        if (dir)
                *dir++ = '\0';

        /* 1.1 network */
        if (strcmp(param, "default")) {
                rule->sr_netid = libcfs_str2net(param);
                if (rule->sr_netid == LNET_NIDNET(LNET_NID_ANY)) {
                        CERROR("invalid network name: %s\n", param);
                        RETURN(-EINVAL);
                }
        }

        /* 1.2 direction */
        if (dir) {
                if (!strcmp(dir, "mdt2ost")) {
                        rule->sr_from = LUSTRE_SP_MDT;
                        rule->sr_to = LUSTRE_SP_OST;
                } else if (!strcmp(dir, "mdt2mdt")) {
                        rule->sr_from = LUSTRE_SP_MDT;
                        rule->sr_to = LUSTRE_SP_MDT;
                } else if (!strcmp(dir, "cli2ost")) {
                        rule->sr_from = LUSTRE_SP_CLI;
                        rule->sr_to = LUSTRE_SP_OST;
                } else if (!strcmp(dir, "cli2mdt")) {
                        rule->sr_from = LUSTRE_SP_CLI;
                        rule->sr_to = LUSTRE_SP_MDT;
                } else {
                        CERROR("invalid rule dir segment: %s\n", dir);
                        RETURN(-EINVAL);
                }
        }

        /* 2.1 flavor */
        rc = parse_flavor(flavor, rule);
        if (rc)
                RETURN(-EINVAL);

        RETURN(0);
}
EXPORT_SYMBOL(sptlrpc_parse_rule);

void sptlrpc_rule_set_free(struct sptlrpc_rule_set *rset)
{
        LASSERT(rset->srs_nslot ||
                (rset->srs_nrule == 0 && rset->srs_rules == NULL));

        if (rset->srs_nslot) {
                OBD_FREE(rset->srs_rules,
                         rset->srs_nslot * sizeof(*rset->srs_rules));
                sptlrpc_rule_set_init(rset);
        }
}
EXPORT_SYMBOL(sptlrpc_rule_set_free);

/*
 * return 0 if the rule set could accomodate one more rule.
 * if @expand != 0, the rule set might be expanded.
 */
int sptlrpc_rule_set_expand(struct sptlrpc_rule_set *rset, int expand)
{
        struct sptlrpc_rule *rules;
        int nslot;

        if (rset->srs_nrule < rset->srs_nslot)
                return 0; 

        if (expand == 0)
                return -E2BIG;

        if (rset->srs_nslot == 0)
                nslot = 8;
        else
                nslot = rset->srs_nslot + 8;

        /* better use realloc() if available */
        OBD_ALLOC(rules, nslot * sizeof(*rset->srs_rules));
        if (rules == NULL)
                return -ENOMEM;

        memcpy(rules, rset->srs_rules,
               rset->srs_nrule * sizeof(*rset->srs_rules));

        if (rset->srs_rules)
                OBD_FREE(rset->srs_rules,
                         rset->srs_nslot * sizeof(*rset->srs_rules));

        rset->srs_rules = rules;
        rset->srs_nslot = nslot;
        return 0;
}
EXPORT_SYMBOL(sptlrpc_rule_set_expand);

static inline int rule_spec_dir(struct sptlrpc_rule *rule)
{
        return (rule->sr_from != LUSTRE_SP_ANY ||
                rule->sr_to != LUSTRE_SP_ANY);
}
static inline int rule_spec_net(struct sptlrpc_rule *rule)
{
        return (rule->sr_netid != LNET_NIDNET(LNET_NID_ANY));
}
static inline int rule_match_dir(struct sptlrpc_rule *r1,
                                 struct sptlrpc_rule *r2)
{
        return (r1->sr_from == r2->sr_from && r1->sr_to == r2->sr_to);
}
static inline int rule_match_net(struct sptlrpc_rule *r1,
                                 struct sptlrpc_rule *r2)
{
        return (r1->sr_netid == r2->sr_netid);
}

/*
 * merge @rule into @rset.
 * if @expand != 0 then @rset slots might be expanded.
 */
int sptlrpc_rule_set_merge(struct sptlrpc_rule_set *rset, 
                           struct sptlrpc_rule *rule,
                           int expand)
{
        struct sptlrpc_rule      *p = rset->srs_rules;
        int                       spec_dir, spec_net;
        int                       rc, n, match = 0;

        spec_net = rule_spec_net(rule);
        spec_dir = rule_spec_dir(rule);

        for (n = 0; n < rset->srs_nrule; n++) {
                p = &rset->srs_rules[n]; 

                /* test network match, if failed:
                 * - spec rule: skip rules which is also spec rule match, until
                 *   we hit a wild rule, which means no more chance
                 * - wild rule: skip until reach the one which is also wild
                 *   and matches
                 */
                if (!rule_match_net(p, rule)) {
                        if (spec_net) {
                                if (rule_spec_net(p))
                                        continue;
                                else
                                        break;
                        } else {
                                continue;
                        }
                }

                /* test dir match, same logic as net matching */
                if (!rule_match_dir(p, rule)) {
                        if (spec_dir) {
                                if (rule_spec_dir(p))
                                        continue;
                                else
                                        break;
                        } else {
                                continue;
                        }
                }

                /* find a match */
                match = 1;
                break;
        }

        if (match) {
                LASSERT(n >= 0 && n < rset->srs_nrule);

                if (rule->sr_flvr.sf_rpc == SPTLRPC_FLVR_INVALID) {
                        /* remove this rule */
                        if (n < rset->srs_nrule - 1)
                                memmove(&rset->srs_rules[n],
                                        &rset->srs_rules[n + 1],
                                        (rset->srs_nrule - n - 1) *
                                        sizeof(*rule));
                        rset->srs_nrule--;
                } else {
                        /* override the rule */
                        memcpy(&rset->srs_rules[n], rule, sizeof(*rule));
                }
        } else {
                LASSERT(n >= 0 && n <= rset->srs_nrule);

                if (rule->sr_flvr.sf_rpc != SPTLRPC_FLVR_INVALID) {
                        rc = sptlrpc_rule_set_expand(rset, expand);
                        if (rc)
                                return rc;

                        if (n < rset->srs_nrule)
                                memmove(&rset->srs_rules[n + 1],
                                        &rset->srs_rules[n],
                                        (rset->srs_nrule - n) * sizeof(*rule));
                        memcpy(&rset->srs_rules[n], rule, sizeof(*rule));
                        rset->srs_nrule++;
                } else {
                        CWARN("ignore the unmatched deletion\n");
                }
        }

        return 0;
}
EXPORT_SYMBOL(sptlrpc_rule_set_merge);

int sptlrpc_rule_set_from_log(struct sptlrpc_rule_set *rset,
                              struct sptlrpc_conf_log *log)
{
        LASSERT(rset);
        LASSERT(log);

        sptlrpc_rule_set_free(rset);

        if (log->scl_nrule == 0)
                return 0;

        OBD_ALLOC(rset->srs_rules, log->scl_nrule * sizeof(*log->scl_rules));
        if (!rset->srs_rules)
                return -ENOMEM;

        memcpy(rset->srs_rules, log->scl_rules,
               log->scl_nrule * sizeof(*log->scl_rules));
        rset->srs_nslot = rset->srs_nrule = log->scl_nrule;
        return 0;
}
EXPORT_SYMBOL(sptlrpc_rule_set_from_log);

/*
 * according to NID/from choose a flavor from rule set.
 */
void sptlrpc_rule_set_choose(struct sptlrpc_rule_set *rset,
                             enum lustre_sec_part from,
                             lnet_nid_t nid,
                             struct sptlrpc_flavor *sf)
{
        struct sptlrpc_rule    *r;
        int                     n;

        for (n = 0; n < rset->srs_nrule; n++) {
                r = &rset->srs_rules[n];

                if (LNET_NIDNET(nid) != LNET_NIDNET(LNET_NID_ANY) &&
                    r->sr_netid != LNET_NIDNET(LNET_NID_ANY) &&
                    LNET_NIDNET(nid) != r->sr_netid)
                        continue;

                if (from != LUSTRE_SP_ANY && r->sr_from != LUSTRE_SP_ANY &&
                    from != r->sr_from)
                        continue;

                *sf = r->sr_flvr;
                return;
        }

        /* no match found, set as default flavor */
        get_default_flavor(sf);
}
EXPORT_SYMBOL(sptlrpc_rule_set_choose);

void sptlrpc_rule_set_dump(struct sptlrpc_rule_set *rset)
{
        struct sptlrpc_rule *r;
        int     n;

        for (n = 0; n < rset->srs_nrule; n++) {
                r = &rset->srs_rules[n];
                CWARN("<%02d> from %x to %x, net %x, rpc %x\n", n,
                      r->sr_from, r->sr_to, r->sr_netid, r->sr_flvr.sf_rpc);
        }
}
EXPORT_SYMBOL(sptlrpc_rule_set_dump);

/****************************************
 * sptlrpc config log                   *
 ****************************************/

struct sptlrpc_conf_log *sptlrpc_conf_log_alloc(void)
{
        struct sptlrpc_conf_log *log;

        OBD_ALLOC_PTR(log);
        if (log == NULL)
                return ERR_PTR(-ENOMEM);

        log->scl_max = SPTLRPC_CONF_LOG_MAX;
        return log;
}
EXPORT_SYMBOL(sptlrpc_conf_log_alloc);

void sptlrpc_conf_log_free(struct sptlrpc_conf_log *log)
{
        LASSERT(log->scl_max == SPTLRPC_CONF_LOG_MAX);
        OBD_FREE_PTR(log);
}
EXPORT_SYMBOL(sptlrpc_conf_log_free);

static __u32 get_log_rule_flags(enum lustre_sec_part from,
                                enum lustre_sec_part to,
                                unsigned int fl_udesc)
{
        /* MDT->MDT; MDT->OST */
        if (from == LUSTRE_SP_MDT)
                return PTLRPC_SEC_FL_ROOTONLY;
        /* CLI->OST */
        if (from == LUSTRE_SP_CLI && to == LUSTRE_SP_OST)
                return PTLRPC_SEC_FL_ROOTONLY | PTLRPC_SEC_FL_BULK;
        /* CLI->MDT */
        if (from == LUSTRE_SP_CLI && to == LUSTRE_SP_MDT)
                if (fl_udesc)
                        return PTLRPC_SEC_FL_UDESC;

        return 0;
}

/*
 * generate config log: merge general and target rules, which
 * match @from @to
 */
int sptlrpc_conf_log_populate(struct sptlrpc_rule_set *gen,
                              struct sptlrpc_rule_set *tgt,
                              enum lustre_sec_part from,
                              enum lustre_sec_part to,
                              unsigned int fl_udesc,
                              struct sptlrpc_conf_log *log)
{
        struct sptlrpc_rule_set *src[2] = { gen, tgt };
        struct sptlrpc_rule_set  dst;
        struct sptlrpc_rule     *rule;
        __u32                    flags;
        int                      i, n, rc;

        LASSERT(log);

        dst.srs_nslot = log->scl_max;
        dst.srs_nrule = 0;
        dst.srs_rules = log->scl_rules;

        /* merge general rules firstly, then target-specific rules */
        for (i = 0; i < 2; i++) {
                if (src[i] == NULL)
                        continue;

                for (n = 0; n < src[i]->srs_nrule; n++) {
                        rule = &src[i]->srs_rules[n];

                        if (from != LUSTRE_SP_ANY &&
                            rule->sr_from != LUSTRE_SP_ANY &&
                            rule->sr_from != from)
                                continue;
                        if (to != LUSTRE_SP_ANY &&
                            rule->sr_to != LUSTRE_SP_ANY &&
                            rule->sr_to != to)
                                continue;

                        rc = sptlrpc_rule_set_merge(&dst, rule, 0);
                        if (rc) {
                                CERROR("can't merge: %d\n", rc);
                                return rc;
                        }
                }
        }

        log->scl_nrule = dst.srs_nrule;

        /* set flags for each rule */
        flags = get_log_rule_flags(from, to, fl_udesc);

        for (i = 0; i < log->scl_nrule; i++) {
                log->scl_rules[i].sr_flvr.sf_flags = flags;

                /* also clear the from/to fields which don't need to be known
                 * accordingly. @from == ANY means this log is for target,
                 * otherwise for client. */
                if (from != LUSTRE_SP_ANY)
                        log->scl_rules[i].sr_from = LUSTRE_SP_ANY;
                log->scl_rules[i].sr_to = LUSTRE_SP_ANY;
        }

        return 0;
}
EXPORT_SYMBOL(sptlrpc_conf_log_populate);

/*
 * extract config log from @lcfg
 */
struct sptlrpc_conf_log *sptlrpc_conf_log_extract(struct lustre_cfg *lcfg)
{
        struct sptlrpc_conf_log *log;
        struct sptlrpc_rule     *r;
        int                      i;
        ENTRY;

        log = lustre_cfg_buf(lcfg, 1);
        if (log == NULL) {
                CERROR("no sptlrpc config data\n");
                RETURN(ERR_PTR(-EINVAL));
        }

        if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION)) {
                __swab32s(&log->scl_max);
                __swab32s(&log->scl_nrule);
        }

        if (LUSTRE_CFG_BUFLEN(lcfg, 1) <
            log->scl_max * sizeof(log->scl_rules[0])) {
                CERROR("mal-formed config log\n");
                RETURN(ERR_PTR(-EINVAL));
        }

        if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION)) {
                for (i = 0; i < log->scl_nrule; i++) {
                        r = &log->scl_rules[i];
                        __swab32s(&r->sr_netid);
                        __swab16s(&r->sr_flvr.sf_rpc);
                        __swab32s(&r->sr_flvr.sf_flags);
                }
        }

        RETURN(log);
}
EXPORT_SYMBOL(sptlrpc_conf_log_extract);

void sptlrpc_conf_log_cleanup(struct sptlrpc_conf_log *log)
{
        log->scl_nrule = 0;
        memset(log->scl_rules, 0, sizeof(log->scl_rules));
}
EXPORT_SYMBOL(sptlrpc_conf_log_cleanup);

void sptlrpc_conf_log_dump(struct sptlrpc_conf_log *log)
{
        struct sptlrpc_rule    *r;
        int                     n;

        CWARN("max %u, rule# %u part %u\n",
              log->scl_max, log->scl_nrule, log->scl_part);

        for (n = 0; n < log->scl_nrule; n++) {
                r = &log->scl_rules[n];
                CWARN("<%02d> %x -> %x, net %x, rpc %x\n", n,
                      r->sr_from, r->sr_to, r->sr_netid, r->sr_flvr.sf_rpc);
        }
}
EXPORT_SYMBOL(sptlrpc_conf_log_dump);

/*
 * caller should guarantee that no concurrent calls to this function
 */
#define SEC_ADAPT_DELAY         (10)

int sptlrpc_cliobd_process_config(struct obd_device *obd,
                                  struct lustre_cfg *lcfg)
{
        struct sptlrpc_conf_log *log;
        struct obd_import       *imp;
        int                      rc;

        log = sptlrpc_conf_log_extract(lcfg);
        if (IS_ERR(log)) {
                CERROR("extract log error: %ld\n", PTR_ERR(log));
                return PTR_ERR(log);
        }

        obd->u.cli.cl_sec_part = log->scl_part;

        rc = sptlrpc_rule_set_from_log(&obd->u.cli.cl_sptlrpc_rset, log);
        if (rc) {
                CERROR("failed create rule set: %d\n", rc);
                return rc;
        }

        imp = obd->u.cli.cl_import;
        if (imp == NULL)
                return 0;

        /* even if imp_sec_expire is already set, we'll override it to a
         * newer (later) time */
        spin_lock(&imp->imp_lock);
        if (imp->imp_sec)
                imp->imp_sec_expire = cfs_time_current_sec() + SEC_ADAPT_DELAY;
        spin_unlock(&imp->imp_lock);
        return 0;
}
EXPORT_SYMBOL(sptlrpc_cliobd_process_config);
