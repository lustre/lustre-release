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
        if (obd != NULL)
                RETURN(-EEXIST);

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
        
        /* XXX belong ins setup not attach  */
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
                if (obd->obd_name)
                        OBD_FREE(obd->obd_name,
                                 strlen(obd->obd_name) + 1);
                class_put_type(obd->obd_type);
                obd->obd_type = NULL;
                RETURN(-EINVAL);
        }
        memcpy(obd->obd_uuid.uuid, uuid, len);
        
        /* do the attach */
        if (OBP(obd, attach))
                err = OBP(obd,attach)(obd, sizeof *lcfg, lcfg);

        if (err) {
                if(name)
                        OBD_FREE(obd->obd_name,
                                 strlen(obd->obd_name) + 1);
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
        
        if (OBT(obd) && OBP(obd, setup))
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
        }

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

        if (OBT(obd) && OBP(obd, cleanup))
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

int class_process_config(int len, char *data)
{
        char *buf;
	struct obd_device *obd;
        struct lustre_cfg *lcfg;
        int err;

        lustre_cfg_getdata(&buf, len, data);
        lcfg = (struct lustre_cfg* ) buf;

        /* Commands that don't need a device */
	switch(lcfg->lcfg_command) {
        case LCFG_ATTACH: {
                err = class_attach(lcfg);
                GOTO(out, err);
        }
        case LCFG_ADD_UUID: {
                CDEBUG(D_IOCTL, "adding mapping from uuid %s to nid "LPX64
                       ", nal %d\n", lcfg->lcfg_inlbuf1, lcfg->lcfg_nid,
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
        lustre_cfg_freedata(buf, len);
        RETURN(err);
}
	    
