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
 * http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
 *
 * Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
 * CA 95054 USA or visit www.sun.com if you need additional information or
 * have any questions.
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2012, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/liblustre/llite_lib.c
 *
 * Lustre Light common routines
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <liblustre.h>
#include <lnet/lnetctl.h>     /* needed for parse_dump */
#include <lustre_log.h>

#include "lutil.h"
#include "llite_lib.h"

int slp_global_init(void);

static int lllib_init(void)
{
        if (liblustre_init_current("liblustre") ||
            init_lib_portals() ||
            init_obdclass() ||
            ptlrpc_init() ||
            mgc_init() ||
            lmv_init() ||
            mdc_init() ||
            lov_init() ||
            osc_init() ||
            slp_global_init())
                return -1;

        return _sysio_fssw_register("lustre", &llu_fssw_ops);
}

int liblustre_process_log(struct config_llog_instance *cfg,
                          char *mgsnid, char *profile,
                          int allow_recov)
{
        struct lustre_cfg_bufs bufs;
        struct lustre_cfg *lcfg;
        char  *peer = "MGS_UUID";
        struct obd_device *obd;
        struct obd_export *exp;
        char  *name = "mgc_dev";
        class_uuid_t uuid;
        struct obd_uuid mgc_uuid;
        struct llog_ctxt *ctxt;
        lnet_nid_t nid = 0;
        char *mdsnid;
        int err, rc = 0;
        struct obd_connect_data *ocd = NULL;
        ENTRY;

        ll_generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &mgc_uuid);

        nid = libcfs_str2nid(mgsnid);
        if (nid == LNET_NID_ANY) {
                CERROR("Can't parse NID %s\n", mgsnid);
                RETURN(-EINVAL);
        }

        lustre_cfg_bufs_reset(&bufs, NULL);
        lustre_cfg_bufs_set_string(&bufs, 1, peer);
        lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
        lcfg->lcfg_nid = nid;
        rc = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0)
                GOTO(out, rc);

        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, LUSTRE_MGC_NAME);
        lustre_cfg_bufs_set_string(&bufs, 2, mgc_uuid.uuid);
        lcfg = lustre_cfg_new(LCFG_ATTACH, &bufs);
        rc = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0)
                GOTO(out_del_uuid, rc);

        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, LUSTRE_MGS_OBDNAME);
        lustre_cfg_bufs_set_string(&bufs, 2, peer);
        lcfg = lustre_cfg_new(LCFG_SETUP, &bufs);
        rc = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (rc < 0)
                GOTO(out_detach, rc);

        while ((mdsnid = strsep(&mgsnid, ","))) {
                nid = libcfs_str2nid(mdsnid);
                lustre_cfg_bufs_reset(&bufs, NULL);
                lustre_cfg_bufs_set_string(&bufs, 1, libcfs_nid2str(nid));
                lcfg = lustre_cfg_new(LCFG_ADD_UUID, &bufs);
                lcfg->lcfg_nid = nid;
                rc = class_process_config(lcfg);
                lustre_cfg_free(lcfg);
                if (rc) {
                        CERROR("Add uuid for %s failed %d\n",
                               libcfs_nid2str(nid), rc);
                        continue;
                }

                lustre_cfg_bufs_reset(&bufs, name);
                lustre_cfg_bufs_set_string(&bufs, 1, libcfs_nid2str(nid));
                lcfg = lustre_cfg_new(LCFG_ADD_CONN, &bufs);
                lcfg->lcfg_nid = nid;
                rc = class_process_config(lcfg);
                lustre_cfg_free(lcfg);
                if (rc) {
                        CERROR("Add conn for %s failed %d\n",
                               libcfs_nid2str(nid), rc);
                        continue;
                }
        }

        obd = class_name2obd(name);
        if (obd == NULL)
                GOTO(out_cleanup, rc = -EINVAL);

        OBD_ALLOC(ocd, sizeof(*ocd));
        if (ocd == NULL)
                GOTO(out_cleanup, rc = -ENOMEM);

	ocd->ocd_connect_flags = OBD_CONNECT_VERSION | OBD_CONNECT_AT |
				 OBD_CONNECT_FULL20;
        ocd->ocd_version = LUSTRE_VERSION_CODE;

        rc = obd_connect(NULL, &exp, obd, &mgc_uuid, ocd, NULL);
        if (rc) {
                CERROR("cannot connect to %s at %s: rc = %d\n",
                       LUSTRE_MGS_OBDNAME, mgsnid, rc);
                GOTO(out_cleanup, rc);
        }

        ctxt = llog_get_context(exp->exp_obd, LLOG_CONFIG_REPL_CTXT);
        cfg->cfg_flags |= CFG_F_COMPAT146;
	rc = class_config_parse_llog(NULL, ctxt, profile, cfg);
        llog_ctxt_put(ctxt);
        if (rc) {
                CERROR("class_config_parse_llog failed: rc = %d\n", rc);
        }

        /* We don't so much care about errors in cleaning up the config llog
         * connection, as we have already read the config by this point. */
        err = obd_disconnect(exp);
        if (err)
                CERROR("obd_disconnect failed: rc = %d\n", err);

out_cleanup:
        if (ocd)
                OBD_FREE(ocd, sizeof(*ocd));

        lustre_cfg_bufs_reset(&bufs, name);
        lcfg = lustre_cfg_new(LCFG_CLEANUP, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err)
                CERROR("md_cleanup failed: rc = %d\n", err);

out_detach:
        lustre_cfg_bufs_reset(&bufs, name);
        lcfg = lustre_cfg_new(LCFG_DETACH, &bufs);
        err = class_process_config(lcfg);
        lustre_cfg_free(lcfg);
        if (err)
                CERROR("md_detach failed: rc = %d\n", err);

out_del_uuid:
        lustre_cfg_bufs_reset(&bufs, name);
        lustre_cfg_bufs_set_string(&bufs, 1, peer);
        lcfg = lustre_cfg_new(LCFG_DEL_UUID, &bufs);
        err = class_process_config(lcfg);
        if (err)
                CERROR("del MDC UUID failed: rc = %d\n", err);
        lustre_cfg_free(lcfg);
out:

        RETURN(rc);
}

/* parse host:/fsname string */
int ll_parse_mount_target(const char *target, char **mgsnid,
                          char **fsname)
{
        static char buf[256];
        char *s;

        buf[255] = 0;
        strncpy(buf, target, 255);

        if ((s = strchr(buf, ':'))) {
                *mgsnid = buf;
                *s = '\0';

                while (*++s == '/')
                        ;
                sprintf(s + strlen(s), "-client");
                *fsname = s;

                return 0;
        }

        return -1;
}

/*
 * early liblustre init
 * called from C startup in catamount apps, before main()
 *
 * The following is a skeleton sysio startup sequence,
 * as implemented in C startup (skipping error handling).
 * In this framework none of these calls need be made here
 * or in the apps themselves.  The NAMESPACE_STRING specifying
 * the initial set of fs ops (creates, mounts, etc.) is passed
 * as an environment variable.
 *
 *      _sysio_init();
 *      _sysio_incore_init();
 *      _sysio_native_init();
 *      _sysio_lustre_init();
 *      _sysio_boot(NAMESPACE_STRING);
 *
 * the name _sysio_lustre_init() follows the naming convention
 * established in other fs drivers from libsysio:
 *  _sysio_incore_init(), _sysio_native_init()
 *
 * _sysio_lustre_init() must be called before _sysio_boot()
 * to enable libsysio's processing of namespace init strings containing
 * lustre filesystem operations
 */
int _sysio_lustre_init(void)
{
        int err;
        char *envstr;
#ifndef INIT_SYSIO
        extern void __liblustre_cleanup_(void);
#endif

        liblustre_init_random();

        err = lllib_init();
        if (err) {
                perror("init llite driver");
                return err;
        }

        envstr = getenv("LIBLUSTRE_TIMEOUT");
        if (envstr != NULL) {
                obd_timeout = (unsigned int)strtol(envstr, NULL, 0);
                printf("LibLustre: obd timeout=%u seconds\n",
                        obd_timeout);
        }

        /* debug peer on timeout? */
        envstr = getenv("LIBLUSTRE_DEBUG_PEER_ON_TIMEOUT");
        if (envstr != NULL) {
                obd_debug_peer_on_timeout = 
                        (unsigned int)strtol(envstr, NULL, 0);
                printf("LibLustre: debug peer on timeout=%d\n",
                        obd_debug_peer_on_timeout ? 0 : 1);
        }

#ifndef INIT_SYSIO
        (void)atexit(__liblustre_cleanup_);
#endif
        return err;
}

extern int _sysio_native_init();

static int mnt_retry = 0;

char *lustre_path = NULL;

void __liblustre_setup_(void)
{
        char *target = NULL;
        char *lustre_driver = "lustre";
        unsigned mntflgs = 0;
        int err, count;

        lustre_path = getenv("LIBLUSTRE_MOUNT_POINT");
        if (!lustre_path) {
                lustre_path = "/mnt/lustre";
        }

        target = getenv("LIBLUSTRE_MOUNT_RETRY");
        if (target) {
                mnt_retry = atoi(target);
                if (mnt_retry < 0)
                        mnt_retry = 0;
        }

        /* mount target */
        target = getenv("LIBLUSTRE_MOUNT_TARGET");
        if (!target) {
                printf("LibLustre: no mount target specified\n");
                exit(1);
        }

        CDEBUG(D_CONFIG, "LibLustre: mount point %s, target %s\n",
               lustre_path, target);

#ifdef INIT_SYSIO
        /* initialize libsysio & mount rootfs */
        if (_sysio_init()) {
                perror("init sysio");
                exit(1);
        }
        _sysio_native_init();

        err = _sysio_mount_root("/", "native", mntflgs, NULL);
        if (err) {
                fprintf(stderr, "sysio mount failed: %s\n", strerror(errno));
                exit(1);
        }

        if (_sysio_lustre_init())
                exit(1);
#endif /* INIT_SYSIO */

        count = mnt_retry;
        do {
                err = mount(target, lustre_path, lustre_driver, mntflgs, NULL);
                if (err && mnt_retry && (-- count)) {
                        fprintf(stderr, "Lustre mount failed: %s. "
                                 "Will retry %d more times\n",
                                strerror(errno), mnt_retry - count );
                        sleep(2);
                }
        } while (err && count > 0);
        if (err) {
                fprintf(stderr, "Lustre mount failed: %s\n", strerror(errno));
                exit(1);
        }
}

void __liblustre_cleanup_(void)
{
#ifndef INIT_SYSIO
        /* guard against being called multiple times */
        static int cleaned = 0;

        if (cleaned)
                return;
        cleaned++;
#endif

        /* user app might chdir to a lustre directory, and leave busy pnode
         * during finaly libsysio cleanup. here we chdir back to "/".
         * but it can't fix the situation that liblustre is mounted
         * at "/".
         */
        if (!chdir("/")) {}
#if 0
        umount(lustre_path);
#endif
        /* we can't call umount here, because libsysio will not cleanup
         * opening files for us. _sysio_shutdown() will cleanup fds at
         * first but which will also close the sockets we need for umount
         * liblutre. this dilema lead to another hack in
         * libsysio/src/file_hack.c FIXME
         */
#ifdef INIT_SYSIO
        _sysio_shutdown();
        cleanup_lib_portals();
        LNetFini();
#endif
}
