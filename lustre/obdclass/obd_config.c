/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001-2003 Cluster File Systems, Inc.
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
 *
 * Config API
 *
 */

#define DEBUG_SUBSYSTEM S_CLASS
#ifdef __KERNEL__
#include <linux/kmod.h>   /* for request_module() */
#include <linux/module.h>
#include <linux/obd_class.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#else 
#include <liblustre.h>
#include <linux/obd_class.h>
#include <linux/obd.h>
#endif
#include <linux/lprocfs_status.h>
#include <portals/list.h>


/* Create a new device and set the type, name and uuid.  If
 * successful, the new device can be accessed by either name or uuid.
 */
int class_attach(struct lustre_cfg *lcfg)
{
        int minor;
        struct obd_type *type;
        int err = 0;
        int len;
	char *typename;
	char *name;
	char *uuid;
	struct obd_device *obd;
	int dev;
                 
	if (!lcfg->lcfg_inllen1 || !lcfg->lcfg_inlbuf1) {
		CERROR("No type passed!\n");
		RETURN(-EINVAL);
	}
	if (lcfg->lcfg_inlbuf1[lcfg->lcfg_inllen1 - 1] != 0) {
		CERROR("Type not nul terminated!\n");
		RETURN(-EINVAL);
	}
	typename = lcfg->lcfg_inlbuf1;

	if (!lcfg->lcfg_dev_namelen || !lcfg->lcfg_dev_name) {
		CERROR("No name passed!\n");
		RETURN(-EINVAL);
	}
	if (lcfg->lcfg_dev_name[lcfg->lcfg_dev_namelen - 1] != 0) {
		CERROR("Name not nul terminated!\n");
		RETURN(-EINVAL);
	}
	name = lcfg->lcfg_dev_name;

	if (!lcfg->lcfg_inllen2 || !lcfg->lcfg_inlbuf2) {
		CERROR("No UUID passed!\n");
		RETURN(-EINVAL);
	}
	if (lcfg->lcfg_inlbuf2[lcfg->lcfg_inllen2 - 1] != 0) {
		CERROR("UUID not nul terminated!\n");
		RETURN(-EINVAL);
	}
	uuid = lcfg->lcfg_inlbuf2;

	CDEBUG(D_IOCTL, "attach type %s name: %s uuid: %s\n",
	       MKSTR(lcfg->lcfg_inlbuf1),
	       MKSTR(lcfg->lcfg_inlbuf2), MKSTR(lcfg->lcfg_inlbuf3));

        /* find the type */
        type = class_get_type(typename);
        if (!type) {
                CERROR("OBD: unknown type: %s\n", typename);
                RETURN(-EINVAL);
        }
        
        obd = class_name2obd(name);
        if (obd != NULL) {
                CERROR("obd %s already attached\n", name);
                RETURN(-EEXIST);
        }

	obd = class_newdev(&dev);
	if (dev == -1)
		RETURN(-EINVAL);

	/* have we attached a type to this device */
	if (obd->obd_attached || obd->obd_type) {
		CERROR("OBD: Device %d already typed as %s.\n",
		       obd->obd_minor, MKSTR(obd->obd_type->typ_name));
		RETURN(-EBUSY);
	}

        minor = obd->obd_minor;
        memset(obd, 0, sizeof(*obd));
        obd->obd_minor = minor;
        obd->obd_type = type;
        INIT_LIST_HEAD(&obd->obd_exports);
        obd->obd_num_exports = 0;
        spin_lock_init(&obd->obd_dev_lock);
        init_waitqueue_head(&obd->obd_refcount_waitq);
        
        /* XXX belongs in setup not attach  */
        /* recovery data */
        spin_lock_init(&obd->obd_processing_task_lock);
        init_waitqueue_head(&obd->obd_next_transno_waitq);
        INIT_LIST_HEAD(&obd->obd_recovery_queue);
        INIT_LIST_HEAD(&obd->obd_delayed_reply_queue);
        
        init_waitqueue_head(&obd->obd_commit_waitq);
        
        len = strlen(name) + 1;
        OBD_ALLOC(obd->obd_name, len);
        if (!obd->obd_name) {
                class_put_type(obd->obd_type);
                obd->obd_type = NULL;
                RETURN(-ENOMEM);
        }
        memcpy(obd->obd_name, name, len);
        
        len = strlen(uuid);
        if (len >= sizeof(obd->obd_uuid)) {
                CERROR("uuid must be < "LPSZ" bytes long\n",
                       sizeof(obd->obd_uuid));
                OBD_FREE(obd->obd_name, strlen(obd->obd_name) + 1);
                class_put_type(obd->obd_type);
                obd->obd_type = NULL;
                RETURN(-EINVAL);
        }
        memcpy(obd->obd_uuid.uuid, uuid, len);
        
        /* do the attach */
        if (OBP(obd, attach))
                err = OBP(obd,attach)(obd, sizeof *lcfg, lcfg);

        if (err) {
                OBD_FREE(obd->obd_name, strlen(obd->obd_name) + 1);
                class_put_type(obd->obd_type);
                obd->obd_type = NULL;
        } else {
                obd->obd_attached = 1;
                type->typ_refcnt++;
                CDEBUG(D_IOCTL, "OBD: dev %d attached type %s\n",
                       obd->obd_minor, typename);
        }
        RETURN(err);
}

int class_setup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int err = 0;
        ENTRY;

        /* have we attached a type to this device? */
        if (!obd->obd_attached) {
                CERROR("Device %d not attached\n", obd->obd_minor);
                RETURN(-ENODEV);
        }

        /* has this been done already? */
        if (obd->obd_set_up) {
                CERROR("Device %d already setup (type %s)\n",
                       obd->obd_minor, obd->obd_type->typ_name);
                RETURN(-EBUSY);
        }

        atomic_set(&obd->obd_refcount, 0);

        err = obd_setup(obd, sizeof(*lcfg), lcfg);
        if (!err) {
                obd->obd_type->typ_refcnt++;
                obd->obd_set_up = 1;
                atomic_inc(&obd->obd_refcount);
        } 
        RETURN(err);
}

int class_detach(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int err = 0;

        ENTRY;
        if (obd->obd_set_up) {
                CERROR("OBD device %d still set up\n", obd->obd_minor);
                RETURN(-EBUSY);
        }
        if (!obd->obd_attached) {
                CERROR("OBD device %d not attached\n", obd->obd_minor);
                RETURN(-ENODEV);
        }
        if (OBP(obd, detach))
                err = OBP(obd,detach)(obd);

        if (obd->obd_name) {
                OBD_FREE(obd->obd_name, strlen(obd->obd_name)+1);
                obd->obd_name = NULL;
        } else 
                CERROR("device %d: no name at detach\n", obd->obd_minor);

        obd->obd_attached = 0;
        obd->obd_type->typ_refcnt--;
        class_put_type(obd->obd_type);
        obd->obd_type = NULL;
        memset(obd, 0, sizeof(*obd));
        RETURN(err);
}

static void dump_exports(struct obd_device *obd)
{
        struct obd_export *exp, *n;

        list_for_each_entry_safe(exp, n, &obd->obd_exports, exp_obd_chain) {
                CERROR("%s: %p %s %d %d %p\n",
                       obd->obd_name, exp, exp->exp_client_uuid.uuid,
                       atomic_read(&exp->exp_refcount),
                       exp->exp_failed, exp->exp_outstanding_reply );
        }
}

int class_cleanup(struct obd_device *obd, struct lustre_cfg *lcfg)
{
        int flags = 0;
	int err = 0;
        char *flag;
        
        ENTRY;
        if (!obd->obd_set_up) {
                CERROR("Device %d not setup\n", obd->obd_minor);
                RETURN(-ENODEV);
        }

        if (lcfg->lcfg_inlbuf1) {
                for (flag = lcfg->lcfg_inlbuf1; *flag != 0; flag++)
                        switch (*flag) {
                        case 'F':
                                flags |= OBD_OPT_FORCE;
                                break;
                        case 'A':
                                flags |= OBD_OPT_FAILOVER;
                                break;
                        default:
                                CERROR("unrecognised flag '%c'\n",
                                       *flag);
                        }
        }

        err = obd_precleanup(obd, flags);
        if (err) 
                RETURN(err);
        
        if (atomic_read(&obd->obd_refcount) == 1 ||
            flags & OBD_OPT_FORCE) {
                /* this will stop new connections, and need to
                   do it before class_disconnect_exports() */
                obd->obd_stopping = 1;
        }

        if (atomic_read(&obd->obd_refcount) > 1) {
                struct l_wait_info lwi = LWI_TIMEOUT_INTR(1 * HZ, NULL,
                                                          NULL, NULL);
                int rc;

                if (!(flags & OBD_OPT_FORCE)) {
                        CERROR("OBD device %d (%p) has refcount %d\n",
                               obd->obd_minor, obd,
                               atomic_read(&obd->obd_refcount));
                        dump_exports(obd);
                        RETURN(-EBUSY);
                }
                class_disconnect_exports(obd, flags);
                CDEBUG(D_IOCTL,
                       "%s: waiting for obd refs to go away: %d\n",
                       obd->obd_name, atomic_read(&obd->obd_refcount));

                rc = l_wait_event(obd->obd_refcount_waitq,
                                  atomic_read(&obd->obd_refcount) < 2, &lwi);
                if (rc == 0) {
                        LASSERT(atomic_read(&obd->obd_refcount) == 1);
                } else {
                        CERROR("wait cancelled cleaning anyway. "
                               "refcount: %d\n",
                               atomic_read(&obd->obd_refcount));
                        dump_exports(obd);
                }
                CDEBUG(D_IOCTL, "%s: awake, now finishing cleanup\n",
                       obd->obd_name);
        }

        err = obd_cleanup(obd, flags);
        if (!err) {
                obd->obd_set_up = obd->obd_stopping = 0;
                obd->obd_type->typ_refcnt--;
                atomic_dec(&obd->obd_refcount);
                /* XXX this should be an LASSERT */
                if (atomic_read(&obd->obd_refcount) > 0) 
                        CERROR("%s still has refcount %d after "
                               "cleanup.\n", obd->obd_name,
                               atomic_read(&obd->obd_refcount));
        }

        RETURN(err);
}

LIST_HEAD(lustre_profile_list);

struct lustre_profile *class_get_profile(char * prof)
{
        struct lustre_profile *lprof;
        
        list_for_each_entry(lprof, &lustre_profile_list, lp_list) {
                if (!strcmp(lprof->lp_profile, prof)) {
                        RETURN(lprof);
                }
        }
        RETURN(NULL);
}

int class_add_profile(int proflen, char *prof, 
                      int osclen, char *osc, 
                      int mdclen, char *mdc)
{
        struct lustre_profile *lprof;
        int err = 0;

        OBD_ALLOC(lprof, sizeof(*lprof));
        if (lprof == NULL)
                GOTO(out, err = -ENOMEM);
        INIT_LIST_HEAD(&lprof->lp_list);

        LASSERT(proflen == (strlen(prof) + 1));
        OBD_ALLOC(lprof->lp_profile, proflen);
        if (lprof->lp_profile == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_profile, prof, proflen);
        
        LASSERT(osclen == (strlen(osc) + 1));
        OBD_ALLOC(lprof->lp_osc, osclen);
        if (lprof->lp_profile == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_osc, osc, osclen);

        LASSERT(mdclen == (strlen(mdc) + 1));
        OBD_ALLOC(lprof->lp_mdc, mdclen);
        if (lprof->lp_mdc == NULL)
                GOTO(out, err = -ENOMEM);
        memcpy(lprof->lp_mdc, mdc, mdclen);

        list_add(&lprof->lp_list, &lustre_profile_list);

out:
        RETURN(err);
}

void class_del_profile(char *prof)
{
        struct lustre_profile *lprof;
        
        lprof = class_get_profile(prof);
        if (lprof) {
                list_del(&lprof->lp_list);
                OBD_FREE(lprof->lp_profile, strlen(lprof->lp_profile) + 1);
                OBD_FREE(lprof->lp_osc, strlen(lprof->lp_osc) + 1);
                OBD_FREE(lprof->lp_mdc, strlen(lprof->lp_mdc) + 1);
                OBD_FREE(lprof, sizeof *lprof);
        }
}

int class_process_config(struct lustre_cfg *lcfg)
{
	struct obd_device *obd;
        char str[PTL_NALFMT_SIZE];
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
                       " (%s), nal %d\n", lcfg->lcfg_inlbuf1, lcfg->lcfg_nid,
                       portals_nid2str(lcfg->lcfg_nal, lcfg->lcfg_nid, str),
                       lcfg->lcfg_nal);

                err = class_add_uuid(lcfg->lcfg_inlbuf1, lcfg->lcfg_nid,
                                     lcfg->lcfg_nal);
                GOTO(out, err);
        }
        case LCFG_DEL_UUID: {
                CDEBUG(D_IOCTL, "removing mappings for uuid %s\n",
                       lcfg->lcfg_inlbuf1 == NULL ? "<all uuids>" :
                       lcfg->lcfg_inlbuf1);

                err = class_del_uuid(lcfg->lcfg_inlbuf1);
                GOTO(out, err);
        }
        case LCFG_MOUNTOPT: {
                CDEBUG(D_IOCTL, "mountopt: profile %s osc %s mdc %s\n", 
                       lcfg->lcfg_inlbuf1, lcfg->lcfg_inlbuf2, lcfg->lcfg_inlbuf3);
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
                err = class_add_profile(lcfg->lcfg_inllen1, lcfg->lcfg_inlbuf1, 
                                        lcfg->lcfg_inllen2, lcfg->lcfg_inlbuf2, 
                                        lcfg->lcfg_inllen3, lcfg->lcfg_inlbuf3);
                GOTO(out, err);
        }
        case LCFG_DEL_MOUNTOPT: {
                CDEBUG(D_IOCTL, "mountopt: profile %s\n", lcfg->lcfg_inlbuf1);
                /* set these mount options somewhere, so ll_fill_super
                 * can find them. */
                class_del_profile(lcfg->lcfg_inlbuf1);
                GOTO(out, err = 0);
        }
	}
	

	/* Commands that require a device */
        obd = class_name2obd(lcfg->lcfg_dev_name);
        if (obd == NULL) {
                CERROR("no device\n");
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
        default: { 
                err = obd_config(obd, lcfg);
                if (err)
                        GOTO(out, err);
        }
	}
out:
        RETURN(err);
}
	    
static int class_config_llog_handler(struct llog_handle * handle,
                                     struct llog_rec_hdr *rec, void *data)
{
        struct config_llog_instance *cfg = data;
        int cfg_len = rec->lrh_len;
        char *cfg_buf = (char*) (rec + 1);
        int rc = 0;

        if (rec->lrh_type == OBD_CFG_REC) {
                char *buf;
                struct lustre_cfg *lcfg;
                char *old_name = NULL;
                int old_len = 0;
                char *old_uuid = NULL;
                int old_uuid_len = 0;
                char *inst_name = NULL;
                int inst_len = 0;

                rc = lustre_cfg_getdata(&buf, cfg_len, cfg_buf, 1);
                if (rc) 
                        GOTO(out, rc);
                lcfg = (struct lustre_cfg* ) buf;

                if (cfg && lcfg->lcfg_dev_name) {
                        inst_len = strlen(lcfg->lcfg_dev_name) + 
                                strlen(cfg->cfg_instance) + 2;
                        OBD_ALLOC(inst_name, inst_len);
                        sprintf(inst_name, "%s-%s", lcfg->lcfg_dev_name, 
                                cfg->cfg_instance);
                        old_name = lcfg->lcfg_dev_name;
                        old_len = lcfg->lcfg_dev_namelen;
                        lcfg->lcfg_dev_name = inst_name;
                        lcfg->lcfg_dev_namelen = strlen(inst_name) + 1;
                }
                
                if (cfg && lcfg->lcfg_command == LCFG_ATTACH) {
                        old_uuid = lcfg->lcfg_inlbuf2;
                        old_uuid_len = lcfg->lcfg_inllen2;

                        lcfg->lcfg_inlbuf2 = (char*)&cfg->cfg_uuid.uuid;
                        lcfg->lcfg_inllen2 = sizeof(cfg->cfg_uuid);
                }

                rc = class_process_config(lcfg);

                if (old_name) {
                        lcfg->lcfg_dev_name = old_name;
                        lcfg->lcfg_dev_namelen = old_len;
                        OBD_FREE(inst_name, inst_len);
                }
              
                if (old_uuid) {
                        lcfg->lcfg_inlbuf2 = old_uuid;
                        lcfg->lcfg_inllen2 = old_uuid_len;
                }
                
                lustre_cfg_freedata(buf, cfg_len);
        } else if (rec->lrh_type == PTL_CFG_REC) {
                rc = kportal_nal_cmd((struct portals_cfg *)cfg_buf);
        }
out:
        RETURN(rc);
}

int class_config_parse_llog(struct obd_export *exp, char *name, 
                          struct config_llog_instance *cfg)
{
        struct llog_handle *llh;
        struct obd_device *obd = exp->exp_obd;
        int rc, rc2;
        ENTRY;

        if (obd->obd_log_exp == NULL) {
                CERROR("No log export on obd:%s\n", obd->obd_name);
                RETURN(-ENOTCONN);
        }

        rc = llog_create(obd, &llh, NULL, name);
        if (rc) 
                RETURN(rc);

        rc = llog_init_handle(llh, LLOG_F_IS_PLAIN, NULL);
        if (rc) 
                GOTO(parse_out, rc);

        rc = llog_process(llh, class_config_llog_handler, cfg);
parse_out:
        rc2 = llog_close(llh);
        if (rc == 0)
                rc = rc2;

        RETURN(rc);

}

