/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2006 Cluster File Systems, Inc.
 *
 *   This file is part of the Lustre file system, http://www.lustre.org
 *   Lustre is a trademark of Cluster File Systems, Inc.
 *
 *   You may have signed or agreed to another license before downloading
 *   this software.  If so, you are bound by the terms and conditions
 *   of that agreement, and the following does not apply to you.  See the
 *   LICENSE file included with this distribution for more information.
 *
 *   If you did not agree to a different license, then this copy of Lustre
 *   is open source software; you can redistribute it and/or modify it
 *   under the terms of version 2 of the GNU General Public License as
 *   published by the Free Software Foundation.
 *
 *   In either case, Lustre is distributed in the hope that it will be
 *   useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 *   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   license text for more details.
 *
 * Config API
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <obd_class.h>
#include <linux/string.h>
#else
#include <liblustre.h>
#include <obd_class.h>
#include <obd.h>
#endif
#include <lustre_log.h>
#include <lprocfs_status.h>
#include <libcfs/list.h>
#include <lustre_param.h>
#include <class_hash.h>

extern struct lustre_hash_operations uuid_hash_operations;
extern struct lustre_hash_operations nid_hash_operations;

/*********** string parsing utils *********/

/* returns 0 if we find this key in the buffer, else 1 */
int class_find_param(char *buf, char *key, char **valp)
{
        char *ptr;

        if (!buf) 
                return 1;

        if ((ptr = strstr(buf, key)) == NULL) 
                return 1;

        if (valp) 
                *valp = ptr + strlen(key);
        
        return 0;
}

/* returns 0 if this is the first key in the buffer, else 1.
   valp points to first char after key. */
int class_match_param(char *buf, char *key, char **valp)
{
        if (!buf) 
                return 1;

        if (memcmp(buf, key, strlen(key)) != 0) 
                return 1;

        if (valp) 
                *valp = buf + strlen(key);
        
        return 0;
}

/* 0 is good nid, 
   1 not found
   < 0 error
   endh is set to next separator */
int class_parse_nid(char *buf, lnet_nid_t *nid, char **endh)
{
        char tmp, *endp;

        if (!buf) 
                return 1;
        while (*buf == ',' || *buf == ':') 
                buf++;
        if (*buf == ' ' || *buf == '/' || *buf == '\0') 
                return 1;

        /* nid separators or end of nids */
        endp = strpbrk(buf, ",: /");
        if (endp == NULL) 
                endp = buf + strlen(buf);

        tmp = *endp;
        *endp = '\0';
        *nid = libcfs_str2nid(buf);
        if (*nid == LNET_NID_ANY) {
                LCONSOLE_ERROR_MSG(0x159, "Can't parse NID '%s'\n", buf);
                *endp = tmp;
                return -EINVAL;
        }
        *endp = tmp;

        if (endh) 
                *endh = endp;
        CDEBUG(D_INFO, "Nid %s\n", libcfs_nid2str(*nid));
        return 0;
}

EXPORT_SYMBOL(class_find_param);
EXPORT_SYMBOL(class_match_param);
EXPORT_SYMBOL(class_parse_nid);

/********************** class fns **********************/

/* Create a new device and set the type, name and uuid.  If
 * successful, the new device can be accessed by either name or uuid.
 */
int class_attach(struct lustre_cfg *lcfg)
{
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

        CDEBUG(D_IOCTL, "attach type %s name: %s uuid: %s\n",
               MKSTR(typename), MKSTR(name), MKSTR(uuid));

        /* Mountconf transitional hack, should go away after 1.6.
           1.4.7 uses the old names, so translate back if the
           mountconf flag is set.
           1.6 should set this flag, and translate the other way here
           if not set. */
        if (lcfg->lcfg_flags & LCFG_FLG_MOUNTCONF){
                char *tmp = NULL;
                if (strcmp(typename, "mds") == 0)
                        tmp = "mdt";
                if (strcmp(typename, "mdt") == 0)
                        tmp = "mds";
                if (strcmp(typename, "osd") == 0)
                        tmp = "obdfilter";
                if (tmp) {
                        LCONSOLE_WARN("Using type %s for %s %s\n", tmp,
                                      MKSTR(typename), MKSTR(name));
                        typename = tmp;
                }
        }

        obd = class_newdev(typename, name);
        if (IS_ERR(obd)) {
                /* Already exists or out of obds */
                rc = PTR_ERR(obd);
                obd = NULL;
                CERROR("Cannot create device %s of type %s : %d\n",
                       name, typename, rc);
                GOTO(out, rc);
        }
        LASSERTF(obd != NULL, "Cannot get obd device %s of type %s\n",
                 name, typename);
        LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, 
                 "obd %p obd_magic %08X != %08X\n",
                 obd, obd->obd_magic, OBD_DEVICE_MAGIC);
        LASSERTF(strncmp(obd->obd_name, name, strlen(name)) == 0, "%p obd_name %s != %s\n",
                 obd, obd->obd_name, name);

        CFS_INIT_LIST_HEAD(&obd->obd_exports);
        CFS_INIT_LIST_HEAD(&obd->obd_exports_timed);
        CFS_INIT_LIST_HEAD(&obd->obd_nid_stats);
        spin_lock_init(&obd->nid_lock);
        spin_lock_init(&obd->obd_dev_lock);
        sema_init(&obd->obd_dev_sem, 1);
        spin_lock_init(&obd->obd_osfs_lock);
        /* obd->obd_osfs_age must be set to a value in the distant
         * past to guarantee a fresh statfs is fetched on mount. */
        obd->obd_osfs_age = cfs_time_shift_64(-1000);

        /* XXX belongs in setup not attach  */
        /* recovery data */
        cfs_init_timer(&obd->obd_recovery_timer);
        spin_lock_init(&obd->obd_processing_task_lock);
        cfs_waitq_init(&obd->obd_next_transno_waitq);
        cfs_waitq_init(&obd->obd_evict_inprogress_waitq);
        cfs_waitq_init(&obd->obd_llog_waitq);
        CFS_INIT_LIST_HEAD(&obd->obd_recovery_queue);
        CFS_INIT_LIST_HEAD(&obd->obd_delayed_reply_queue);

        spin_lock_init(&obd->obd_uncommitted_replies_lock);
        CFS_INIT_LIST_HEAD(&obd->obd_uncommitted_replies);

        len = strlen(uuid);
        if (len >= sizeof(obd->obd_uuid)) {
                CERROR("uuid must be < %d bytes long\n",
                       (int)sizeof(obd->obd_uuid));
                GOTO(out, rc = -EINVAL);
        }
        memcpy(obd->obd_uuid.uuid, uuid, len);

        /* do the attach */
        if (OBP(obd, attach)) {
                rc = OBP(obd,attach)(obd, sizeof *lcfg, lcfg);
                if (rc)
                        GOTO(out, rc = -EINVAL);
        }

        /* Detach drops this */
        spin_lock(&obd->obd_dev_lock);
        atomic_set(&obd->obd_refcount, 1);
        spin_unlock(&obd->obd_dev_lock);

        obd->obd_attached = 1;
        CDEBUG(D_IOCTL, "OBD: dev %d attached type %s with refcount %d\n",
               obd->obd_minor, typename, atomic_read(&obd->obd_refcount));
        RETURN(0);
 out:
        if (obd != NULL) {
                class_release_dev(obd);
        }
        return rc;
}

int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int err = 0;
        struct obd_export *exp;
        ENTRY;

        LASSERT(obd != NULL);
        LASSERTF(obd == class_num2obd(obd->obd_minor), "obd %p != obd_devs[%d] %p\n", 
                 obd, obd->obd_minor, class_num2obd(obd->obd_minor));
        LASSERTF(obd->obd_magic == OBD_DEVICE_MAGIC, "obd %p obd_magic %08x != %08x\n", 
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
        /* just leave this on forever.  I can't use obd_set_up here because
           other fns check that status, and we're not actually set up yet. */
        obd->obd_starting = 1;
        spin_unlock(&obd->obd_dev_lock);

        /* create an uuid-export hash body */
        err = lustre_hash_init(&obd->obd_uuid_hash_body, "UUID_HASH",
                               128, &uuid_hash_operations);
        if (err)
                GOTO(err_hash, err);

        /* create a nid-export hash body */
        err = lustre_hash_init(&obd->obd_nid_hash_body, "NID_HASH",
                               128, &nid_hash_operations);
        if (err)
                GOTO(err_hash, err);

        /* create a nid-stats hash body */
        err = lustre_hash_init(&obd->obd_nid_stats_hash_body, "NID_STATS",
                               128, &nid_stat_hash_operations);
        if (err)
                GOTO(err_hash, err);


        exp = class_new_export(obd, &obd->obd_uuid);
        if (IS_ERR(exp))
                RETURN(PTR_ERR(exp));
        obd->obd_self_export = exp;
        list_del_init(&exp->exp_obd_chain_timed);
        class_export_put(exp);

        err = obd_setup(obd, sizeof(*lcfg), lcfg);
        if (err)
                GOTO(err_exp, err);

        obd->obd_set_up = 1;
        spin_lock(&obd->obd_dev_lock);
        /* cleanup drops this */
        class_incref(obd);
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_IOCTL, "finished setup of obd %s (uuid %s)\n",
               obd->obd_name, obd->obd_uuid.uuid);

        RETURN(0);

err_exp:
        class_unlink_export(obd->obd_self_export);
        obd->obd_self_export = NULL;
err_hash:
        lustre_hash_exit(&obd->obd_uuid_hash_body);
        lustre_hash_exit(&obd->obd_nid_hash_body);
        lustre_hash_exit(&obd->obd_nid_stats_hash_body);
        obd->obd_starting = 0;
        CERROR("setup %s failed (%d)\n", obd->obd_name, err);
        RETURN(err);
}

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

        CDEBUG(D_IOCTL, "detach on obd %s (uuid %s)\n",
               obd->obd_name, obd->obd_uuid.uuid);

        class_decref(obd);
        
        /* not strictly necessary, but cleans up eagerly */
        obd_zombie_impexp_cull();
        
        RETURN(0);
}

static void dump_exports(struct obd_device *obd)
{
        struct obd_export *exp, *n;

        list_for_each_entry_safe(exp, n, &obd->obd_exports, exp_obd_chain) {
                struct ptlrpc_reply_state *rs;
                struct ptlrpc_reply_state *first_reply = NULL;
                int                        nreplies = 0;

                list_for_each_entry (rs, &exp->exp_outstanding_replies,
                                     rs_exp_list) {
                        if (nreplies == 0)
                                first_reply = rs;
                        nreplies++;
                }

                CDEBUG(D_IOCTL, "%s: %p %s %s %d %d %d: %p %s\n",
                       obd->obd_name, exp, exp->exp_client_uuid.uuid,
                       obd_export_nid2str(exp),
                       atomic_read(&exp->exp_refcount),
                       exp->exp_failed, nreplies, first_reply,
                       nreplies > 3 ? "..." : "");
        }
}

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

        if (lcfg->lcfg_bufcount >= 2 && LUSTRE_CFG_BUFLEN(lcfg, 1) > 0) {
                for (flag = lustre_cfg_string(lcfg, 1); *flag != 0; flag++)
                        switch (*flag) {
                        case 'F':
                                obd->obd_force = 1;
                                break;
                        case 'A':
                                LCONSOLE_WARN("Failing over %s\n", 
                                              obd->obd_name);
                                obd->obd_fail = 1;
                                obd->obd_no_transno = 1;
                                obd->obd_no_recov = 1;
                                /* Set the obd readonly if we can */
                                if (OBP(obd, iocontrol))
                                        obd_iocontrol(OBD_IOC_SET_READONLY,
                                                      obd->obd_self_export,
                                                      0, NULL, NULL);
                                break;
                        default:
                                CERROR("unrecognised flag '%c'\n",
                                       *flag);
                        }
        }

        /* The three references that should be remaining are the
         * obd_self_export and the attach and setup references. */
        if (atomic_read(&obd->obd_refcount) > 3) {
#if 0           /* We should never fail to cleanup with mountconf */ 
                if (!(obd->obd_fail || obd->obd_force)) {
                        CERROR("OBD %s is still busy with %d references\n"
                               "You should stop active file system users,"
                               " or use the --force option to cleanup.\n",
                               obd->obd_name, atomic_read(&obd->obd_refcount));
                        dump_exports(obd);
                        /* Allow a failed cleanup to try again. */
                        obd->obd_stopping = 0;
                        RETURN(-EBUSY);
                }
#endif
                /* refcounf - 3 might be the number of real exports 
                   (excluding self export). But class_incref is called
                   by other things as well, so don't count on it. */
                CDEBUG(D_IOCTL, "%s: forcing exports to disconnect: %d\n",
                       obd->obd_name, atomic_read(&obd->obd_refcount) - 3);
                dump_exports(obd);
                class_disconnect_exports(obd);
        }

        LASSERT(obd->obd_self_export);

        /* destroy an uuid-export hash body */
        lustre_hash_exit(&obd->obd_uuid_hash_body);

        /* destroy a nid-export hash body */
        lustre_hash_exit(&obd->obd_nid_hash_body);

        /* destroy a nid-stats hash body */
        lustre_hash_exit(&obd->obd_nid_stats_hash_body);

        /* Precleanup stage 1, we must make sure all exports (other than the
           self-export) get destroyed. */
        err = obd_precleanup(obd, OBD_CLEANUP_EXPORTS);
        if (err)
                CERROR("Precleanup %s returned %d\n",
                       obd->obd_name, err);

        class_decref(obd);
        obd->obd_set_up = 0;

        RETURN(0);
}

struct obd_device *class_incref(struct obd_device *obd)
{
        atomic_inc(&obd->obd_refcount);
        CDEBUG(D_INFO, "incref %s (%p) now %d\n", obd->obd_name, obd,
               atomic_read(&obd->obd_refcount));

        return obd;
}

void class_decref(struct obd_device *obd)
{
        int err;
        int refs;

        spin_lock(&obd->obd_dev_lock);
        atomic_dec(&obd->obd_refcount);
        refs = atomic_read(&obd->obd_refcount);
        spin_unlock(&obd->obd_dev_lock);

        CDEBUG(D_INFO, "Decref %s (%p) now %d\n", obd->obd_name, obd, refs);

        if ((refs == 1) && obd->obd_stopping) {
                /* All exports (other than the self-export) have been
                   destroyed; there should be no more in-progress ops
                   by this point.*/
                /* if we're not stopping, we didn't finish setup */
                /* Precleanup stage 2,  do other type-specific
                   cleanup requiring the self-export. */
                err = obd_precleanup(obd, OBD_CLEANUP_SELF_EXP);
                if (err)
                        CERROR("Precleanup %s returned %d\n",
                               obd->obd_name, err);

                spin_lock(&obd->obd_self_export->exp_lock);
                obd->obd_self_export->exp_flags |=
                        (obd->obd_fail ? OBD_OPT_FAILOVER : 0) |
                        (obd->obd_force ? OBD_OPT_FORCE : 0);
                spin_unlock(&obd->obd_self_export->exp_lock);

                /* note that we'll recurse into class_decref again */
                class_unlink_export(obd->obd_self_export);
                return;
        }

        if (refs == 0) {
                CDEBUG(D_CONFIG, "finishing cleanup of obd %s (%s)\n",
                       obd->obd_name, obd->obd_uuid.uuid);
                LASSERT(!obd->obd_attached);
                if (obd->obd_stopping) {
                        /* If we're not stopping, we were never set up */
                        err = obd_cleanup(obd);
                        if (err)
                                CERROR("Cleanup %s returned %d\n",
                                       obd->obd_name, err);
                }
                if (OBP(obd, detach)) {
                        err = OBP(obd,detach)(obd);
                        if (err)
                                CERROR("Detach returned %d\n", err);
                }
                class_release_dev(obd);
        }
}

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

int class_del_conn(struct obd_device *obd, struct lustre_cfg *lcfg)
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

CFS_LIST_HEAD(lustre_profile_list);

struct lustre_profile *class_get_profile(char * prof)
{
        struct lustre_profile *lprof;

        ENTRY;
        list_for_each_entry(lprof, &lustre_profile_list, lp_list) {
                if (!strcmp(lprof->lp_profile, prof)) {
                        RETURN(lprof);
                }
        }
        RETURN(NULL);
}

int class_add_profile(int proflen, char *prof, int osclen, char *osc,
                      int mdclen, char *mdc)
{
        struct lustre_profile *lprof;
        int err = 0;
        ENTRY;

        CDEBUG(D_CONFIG, "Add profile %s\n", prof);

        OBD_ALLOC(lprof, sizeof(*lprof));
        if (lprof == NULL)
                RETURN(-ENOMEM);
        CFS_INIT_LIST_HEAD(&lprof->lp_list);

        LASSERT(proflen == (strlen(prof) + 1));
        OBD_ALLOC(lprof->lp_profile, proflen);
        if (lprof->lp_profile == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_profile, prof, proflen);

        LASSERT(osclen == (strlen(osc) + 1));
        OBD_ALLOC(lprof->lp_osc, osclen);
        if (lprof->lp_osc == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_osc, osc, osclen);

        if (mdclen > 0) {
                LASSERT(mdclen == (strlen(mdc) + 1));
                OBD_ALLOC(lprof->lp_mdc, mdclen);
                if (lprof->lp_mdc == NULL)
                        GOTO(out, err = -ENOMEM);
                memcpy(lprof->lp_mdc, mdc, mdclen);
        }

        list_add(&lprof->lp_list, &lustre_profile_list);
        RETURN(err);

out:
        if (lprof->lp_mdc)
                OBD_FREE(lprof->lp_mdc, mdclen);
        if (lprof->lp_osc)
                OBD_FREE(lprof->lp_osc, osclen);
        if (lprof->lp_profile)
                OBD_FREE(lprof->lp_profile, proflen);
        OBD_FREE(lprof, sizeof(*lprof));        
        RETURN(err);
}

void class_del_profile(char *prof)
{
        struct lustre_profile *lprof;
        ENTRY;

        CDEBUG(D_CONFIG, "Del profile %s\n", prof);

        lprof = class_get_profile(prof);
        if (lprof) {
                list_del(&lprof->lp_list);
                OBD_FREE(lprof->lp_profile, strlen(lprof->lp_profile) + 1);
                OBD_FREE(lprof->lp_osc, strlen(lprof->lp_osc) + 1);
                if (lprof->lp_mdc)
                        OBD_FREE(lprof->lp_mdc, strlen(lprof->lp_mdc) + 1);
                OBD_FREE(lprof, sizeof *lprof);
        }
        EXIT;
}

/* COMPAT_146 */
void class_del_profiles(void)
{
        struct lustre_profile *lprof, *n;
        ENTRY;

        list_for_each_entry_safe(lprof, n, &lustre_profile_list, lp_list) {
                list_del(&lprof->lp_list);
                OBD_FREE(lprof->lp_profile, strlen(lprof->lp_profile) + 1);
                OBD_FREE(lprof->lp_osc, strlen(lprof->lp_osc) + 1);
                if (lprof->lp_mdc)
                        OBD_FREE(lprof->lp_mdc, strlen(lprof->lp_mdc) + 1);
                OBD_FREE(lprof, sizeof *lprof);
        }
        EXIT;
}

/* We can't call ll_process_config directly because it lives in a module that
   must be loaded after this one. */
static int (*client_process_config)(struct lustre_cfg *lcfg) = NULL;

void lustre_register_client_process_config(int (*cpc)(struct lustre_cfg *lcfg))
{
        client_process_config = cpc;
}
EXPORT_SYMBOL(lustre_register_client_process_config);

int class_process_config(struct lustre_cfg *lcfg)
{
        struct obd_device *obd;
        int err;

        LASSERT(lcfg && !IS_ERR(lcfg));
        CDEBUG(D_IOCTL, "processing cmd: %x\n", lcfg->lcfg_command);

        /* Commands that don't need a device */
        switch(lcfg->lcfg_command) {
        case LCFG_ATTACH: {
                err = class_attach(lcfg);
                GOTO(out, err);
        }
        case LCFG_ADD_UUID: {
                CDEBUG(D_IOCTL, "adding mapping from uuid %s to nid "LPX64
                       " (%s)\n", lustre_cfg_string(lcfg, 1),
                       lcfg->lcfg_nid, libcfs_nid2str(lcfg->lcfg_nid));

                err = class_add_uuid(lustre_cfg_string(lcfg, 1), lcfg->lcfg_nid);
                GOTO(out, err);
        }
        case LCFG_DEL_UUID: {
                CDEBUG(D_IOCTL, "removing mappings for uuid %s\n",
                       (lcfg->lcfg_bufcount < 2 || LUSTRE_CFG_BUFLEN(lcfg, 1) == 0)
                       ? "<all uuids>" : lustre_cfg_string(lcfg, 1));

                err = class_del_uuid(lustre_cfg_string(lcfg, 1));
                GOTO(out, err);
        }
        case LCFG_MOUNTOPT: {
                CDEBUG(D_IOCTL, "mountopt: profile %s osc %s mdc %s\n",
                       lustre_cfg_string(lcfg, 1),
                       lustre_cfg_string(lcfg, 2),
                       lustre_cfg_string(lcfg, 3));
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
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
                      marker->cm_flags, marker->cm_tgtname, marker->cm_comment);
                GOTO(out, err = 0);
        }
        case LCFG_PARAM: {
                /* llite has no obd */
                if ((class_match_param(lustre_cfg_string(lcfg, 1), 
                                       PARAM_LLITE, 0) == 0) &&
                    client_process_config) {
                        err = (*client_process_config)(lcfg);
                        GOTO(out, err);
                }
                /* Fall through */
                break;
        }
        }

        /* Commands that require a device */
        obd = class_name2obd(lustre_cfg_string(lcfg, 0));
        if (obd == NULL) {
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
        default: {
                err = obd_process_config(obd, sizeof(*lcfg), lcfg);
                GOTO(out, err);

        }
        }
out:
        if ((err < 0) && !(lcfg->lcfg_command & LCFG_REQUIRED)) {
                CWARN("Ignoring error %d on optional command %#x\n", err, 
                      lcfg->lcfg_command);
                err = 0;
        }
        return err;
}

int class_process_proc_param(char *prefix, struct lprocfs_vars *lvars, 
                             struct lustre_cfg *lcfg, void *data)
{
#ifdef __KERNEL__
        struct lprocfs_vars *var;
        char *key, *sval;
        int i, vallen;
        int matched = 0, j = 0;
        int rc = 0;
        ENTRY;

        if (lcfg->lcfg_command != LCFG_PARAM) {
                CERROR("Unknown command: %d\n", lcfg->lcfg_command);
                RETURN(-EINVAL);
        }

        /* e.g. tunefs.lustre --param mdt.group_upcall=foo /r/tmp/lustre-mdt
           or   lctl conf_param lustre-MDT0000.mdt.group_upcall=bar
           or   lctl conf_param lustre-OST0000.osc.max_dirty_mb=36 */
        for (i = 1; i < lcfg->lcfg_bufcount; i++) {
                key = lustre_cfg_buf(lcfg, i);
                /* Strip off prefix */
                class_match_param(key, prefix, &key);
                sval = strchr(key, '=');
                if (!sval || (*(sval + 1) == 0)) {
                        CERROR("Can't parse param %s\n", key);
                        rc = -EINVAL;
                        /* continue parsing other params */
                        continue;
                }
                sval++;
                vallen = strlen(sval);
                matched = 0;
                j = 0;
                /* Search proc entries */
                while (lvars[j].name) {
                        var = &lvars[j];
                        if (class_match_param(key, (char *)var->name, 0) == 0) {
                                matched++;
                                rc = -EROFS;
                                if (var->write_fptr) {
                                        mm_segment_t oldfs;
                                        oldfs = get_fs();
                                        set_fs(KERNEL_DS);
                                        rc = (var->write_fptr)(NULL, sval,
                                                               vallen, data);
                                        set_fs(oldfs);
                                }
                                if (rc < 0) 
                                        CERROR("writing proc entry %s err %d\n", 
                                               var->name, rc);
                                break;
                        }
                        j++;
                }    
                if (!matched) {
                        CERROR("%s: unknown param %s\n",
                               (char *)lustre_cfg_string(lcfg, 0), key);
                        rc = -EINVAL;
                        /* continue parsing other params */
                } else {
                        LCONSOLE_INFO("%s.%.*s: set parameter %.*s=%s\n", 
                                      (char *)lustre_cfg_string(lcfg, 0),
                                      (int)strlen(prefix) - 1, prefix,
                                      (int)(sval - key - 1), key, sval);
                }
        }
        
        if (rc > 0) 
                rc = 0;
        RETURN(rc);
#else
        CDEBUG(D_CONFIG, "liblustre can't process params.\n");
        /* Don't throw config error */
        RETURN(0);
#endif
}

int class_config_dump_handler(struct llog_handle * handle,
                              struct llog_rec_hdr *rec, void *data);

#ifdef __KERNEL__
extern int lustre_check_exclusion(struct super_block *sb, char *svname);
#else
#define lustre_check_exclusion(a,b)  0
#endif

static int class_config_llog_handler(struct llog_handle * handle,
                                     struct llog_rec_hdr *rec, void *data)
{
        struct config_llog_instance *clli = data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;
        ENTRY;
        
        //class_config_dump_handler(handle, rec, data);

        switch (rec->lrh_type) {
        case OBD_CFG_REC: {
                struct lustre_cfg *lcfg, *lcfg_new;
                struct lustre_cfg_bufs bufs;
                char *inst_name = NULL;
                int inst_len = 0;
                int inst = 0;

                lcfg = (struct lustre_cfg *)cfg_buf;
                if (lcfg->lcfg_version == __swab32(LUSTRE_CFG_VERSION))
                        lustre_swab_lustre_cfg(lcfg);

                rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
                if (rc)
                        GOTO(out, rc);

                /* Figure out config state info */
                if (lcfg->lcfg_command == LCFG_MARKER) {
                        struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);
                        CDEBUG(D_CONFIG, "Marker, inst_flg=%#x mark_flg=%#x\n",
                               clli->cfg_flags, marker->cm_flags);
                        if (marker->cm_flags & CM_START) {
                                /* all previous flags off */
                                clli->cfg_flags = CFG_F_MARKER;
                                if (marker->cm_flags & CM_SKIP) { 
                                        clli->cfg_flags |= CFG_F_SKIP;
                                        CDEBUG(D_CONFIG, "SKIP #%d\n",
                                               marker->cm_step);
                                } else if ((marker->cm_flags & CM_EXCLUDE) ||
                                           lustre_check_exclusion(clli->cfg_sb, 
                                                          marker->cm_tgtname)) {
                                        clli->cfg_flags |= CFG_F_EXCLUDE;
                                        CDEBUG(D_CONFIG, "EXCLUDE %d\n",
                                               marker->cm_step);
                                }
                        } else if (marker->cm_flags & CM_END) {
                                clli->cfg_flags = 0;
                        }
                }
                /* A config command without a start marker before it is 
                   illegal (post 146) */
                if (!(clli->cfg_flags & CFG_F_COMPAT146) &&
                    !(clli->cfg_flags & CFG_F_MARKER) && 
                    (lcfg->lcfg_command != LCFG_MARKER)) {
                        CWARN("Config not inside markers, ignoring! (%#x)\n", 
                              clli->cfg_flags);
                        clli->cfg_flags |= CFG_F_SKIP;
                }

                if (clli->cfg_flags & CFG_F_SKIP) {
                        CDEBUG(D_CONFIG, "skipping %#x\n",
                               clli->cfg_flags);
                        rc = 0;
                        /* No processing! */
                        break;
                }

                if ((clli->cfg_flags & CFG_F_EXCLUDE) && 
                    (lcfg->lcfg_command == LCFG_LOV_ADD_OBD))
                        /* Add inactive instead */
                        lcfg->lcfg_command = LCFG_LOV_ADD_INA;

                lustre_cfg_bufs_init(&bufs, lcfg);

                if (clli && clli->cfg_instance && 
                    LUSTRE_CFG_BUFLEN(lcfg, 0) > 0){
                        inst = 1;
                        inst_len = LUSTRE_CFG_BUFLEN(lcfg, 0) +
                                strlen(clli->cfg_instance) + 1;
                        OBD_ALLOC(inst_name, inst_len);
                        if (inst_name == NULL)
                                GOTO(out, rc = -ENOMEM);
                        sprintf(inst_name, "%s-%s",
                                lustre_cfg_string(lcfg, 0),
                                clli->cfg_instance);
                        lustre_cfg_bufs_set_string(&bufs, 0, inst_name);
                        CDEBUG(D_CONFIG, "cmd %x, instance name: %s\n", 
                               lcfg->lcfg_command, inst_name);
                }

                /* we override the llog's uuid for clients, to insure they
                are unique */
                if (clli && clli->cfg_instance && 
                    lcfg->lcfg_command == LCFG_ATTACH) {
                        lustre_cfg_bufs_set_string(&bufs, 2,
                                                   clli->cfg_uuid.uuid);
                }

                lcfg_new = lustre_cfg_new(lcfg->lcfg_command, &bufs);

                lcfg_new->lcfg_num   = lcfg->lcfg_num;
                lcfg_new->lcfg_flags = lcfg->lcfg_flags;

                /* XXX Hack to try to remain binary compatible with
                 * pre-newconfig logs */
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
                lustre_cfg_free(lcfg_new);

                if (inst)
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
                CERROR("Err %d on cfg command:\n", rc);
                class_config_dump_handler(handle, rec, data);
        }
        RETURN(rc);
}

int class_config_parse_llog(struct llog_ctxt *ctxt, char *name,
                            struct config_llog_instance *cfg)
{
        struct llog_process_cat_data cd = {0, 0};
        struct llog_handle *llh;
        int rc, rc2;
        ENTRY;

        CDEBUG(D_INFO, "looking up llog %s\n", name);
        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc)
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(parse_out, rc);

        /* continue processing from where we last stopped to end-of-log */
        if (cfg)
                cd.first_idx = cfg->cfg_last_idx;
        cd.last_idx = 0;

        rc = llog_process(llh, class_config_llog_handler, cfg, &cd);

        CDEBUG(D_CONFIG, "Processed log %s gen %d-%d (rc=%d)\n", name, 
               cd.first_idx + 1, cd.last_idx, rc);
        if (cfg)
                cfg->cfg_last_idx = cd.last_idx;

parse_out:
        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;

        RETURN(rc);
}

int class_config_dump_handler(struct llog_handle * handle,
                              struct llog_rec_hdr *rec, void *data)
{
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        char *outstr, *ptr, *end;
        int rc = 0;
        ENTRY;

        OBD_ALLOC(outstr, 256);
        end = outstr + 256;
        ptr = outstr;
        if (!outstr) {
                RETURN(-ENOMEM);
        }
        if (rec->lrh_type == OBD_CFG_REC) {
                struct lustre_cfg *lcfg;
                int i;

                rc = lustre_cfg_sanity_check(cfg_buf, cfg_len);
                if (rc)
                        GOTO(out, rc);
                lcfg = (struct lustre_cfg *)cfg_buf;

                ptr += snprintf(ptr, end-ptr, "cmd=%05x ",
                                lcfg->lcfg_command);
                if (lcfg->lcfg_flags) {
                        ptr += snprintf(ptr, end-ptr, "flags=%#08x ",
                                        lcfg->lcfg_flags);
                }
                if (lcfg->lcfg_num) {
                        ptr += snprintf(ptr, end-ptr, "num=%#08x ",
                                        lcfg->lcfg_num);
                }
                if (lcfg->lcfg_nid) {
                        ptr += snprintf(ptr, end-ptr, "nid=%s("LPX64")\n     ",
                                        libcfs_nid2str(lcfg->lcfg_nid),
                                        lcfg->lcfg_nid);
                }
                if (lcfg->lcfg_command == LCFG_MARKER) {
                        struct cfg_marker *marker = lustre_cfg_buf(lcfg, 1);
                        ptr += snprintf(ptr, end-ptr, "marker=%d(%#x)%s '%s'",
                                        marker->cm_step, marker->cm_flags, 
                                        marker->cm_tgtname, marker->cm_comment);
                } else {
                        for (i = 0; i <  lcfg->lcfg_bufcount; i++) {
                                ptr += snprintf(ptr, end-ptr, "%d:%s  ", i,
                                                lustre_cfg_string(lcfg, i));
                        }
                }
                LCONSOLE(D_WARNING, "   %s\n", outstr);
        } else {
                LCONSOLE(D_WARNING, "unhandled lrh_type: %#x\n", rec->lrh_type);
                rc = -EINVAL;
        }
out:
        OBD_FREE(outstr, 256);
        RETURN(rc);
}

int class_config_dump_llog(struct llog_ctxt *ctxt, char *name,
                           struct config_llog_instance *cfg)
{
        struct llog_handle *llh;
        int rc, rc2;
        ENTRY;

        LCONSOLE_INFO("Dumping config log %s\n", name);

        rc = llog_create(ctxt, &llh, NULL, name);
        if (rc)
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc)
                GOTO(parse_out, rc);

        rc = llog_process(llh, class_config_dump_handler, cfg, NULL);
parse_out:
        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;

        LCONSOLE_INFO("End config log %s\n", name);
        RETURN(rc);

}

/* Cleanup and detach */
int class_manual_cleanup(struct obd_device *obd)
{
        struct lustre_cfg *lcfg;
        struct lustre_cfg_bufs bufs;
        int rc;
        char flags[3]="";
        ENTRY;

        if (!obd) {
                CERROR("empty cleanup\n");
                RETURN(-EALREADY);
        }

        if (obd->obd_force)
                strcat(flags, "F");
        if (obd->obd_fail)
                strcat(flags, "A");

        CDEBUG(D_CONFIG, "Manual cleanup of %s (flags='%s')\n",
               obd->obd_name, flags);

        lustre_cfg_bufs_reset(&bufs, obd->obd_name);
        lustre_cfg_bufs_set_string(&bufs, 1, flags);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);

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
        lustre_cfg_free(lcfg);
        RETURN(rc);
}

