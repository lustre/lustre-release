/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2001, 2002 Cluster File Systems, Inc.
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/fs.h>

#define DEBUG_SUBSYSTEM S_ECHO

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obd_echo.h>
#include <linux/lustre_debug.h>
#include <linux/lprocfs_status.h>

static int echo_iocontrol(long cmd, struct lustre_handle *obdconn, int len,
                          void *karg, void *uarg)
{
        struct obd_device *obd = class_conn2obd(obdconn);
        struct echo_client_obd *ec = &obd->u.echo_client;
        struct obd_ioctl_data *data = karg;
        int rw = OBD_BRW_READ, rc = 0;
        ENTRY;

        if (obd == NULL) {
                CERROR("ioctl: No device\n");
                GOTO(out, rc = -EINVAL);
        }

        switch (cmd) {
        case OBD_IOC_CREATE: {
                struct lov_stripe_md *lsm = NULL;
#warning FIXME: save lsm into file handle for other ops, release on close
                rc = obd_create(&ec->conn, &data->ioc_obdo1, &lsm);
                GOTO(out, rc);
        }

        case OBD_IOC_GETATTR:
                rc = obd_getattr(&ec->conn, &data->ioc_obdo1, NULL);
                GOTO(out, rc);

        case OBD_IOC_SETATTR:
                rc = obd_setattr(&ec->conn, &data->ioc_obdo1, NULL);
                GOTO(out, rc);

        case OBD_IOC_DESTROY: {
                //void *ea;
                rc = obd_destroy(&ec->conn, &data->ioc_obdo1, NULL);
                GOTO(out, rc);
        }

        case OBD_IOC_OPEN: {
                struct lov_stripe_md *lsm = NULL; // XXX fill in from create

                rc = obd_open(&ec->conn, &data->ioc_obdo1, lsm);
                GOTO(out, rc);
        }

        case OBD_IOC_CLOSE: {
                struct lov_stripe_md *lsm = NULL; // XXX fill in from create

                rc = obd_close(&ec->conn, &data->ioc_obdo1, lsm);
                GOTO(out, rc);
        }

        case OBD_IOC_BRW_WRITE:
                rw = OBD_BRW_WRITE;
        case OBD_IOC_BRW_READ: {
                struct lov_stripe_md tmp_lsm; // XXX fill in from create
                struct lov_stripe_md *lsm = &tmp_lsm; // XXX fill in from create
                struct obd_brw_set *set;
                obd_count pages = 0;
                struct brw_page *pga, *pgp;
                __u64 id = data->ioc_obdo1.o_id;
                int gfp_mask = (id & 1) ? GFP_HIGHUSER : GFP_KERNEL;
                int verify = (id != 0);
                __u64 off;
                int j;

                set = obd_brw_set_new();
                if (set == NULL)
                        GOTO(out, rc = -ENOMEM);

                pages = data->ioc_count / PAGE_SIZE;
                off = data->ioc_offset;

                CDEBUG(D_INODE, "BRW %s with %d pages @ "LPX64"\n",
                       rw == OBD_BRW_READ ? "read" : "write", pages, off);
                OBD_ALLOC(pga, pages * sizeof(*pga));
                if (!pga) {
                        CERROR("no memory for %d BRW per-page data\n", pages);
                        GOTO(brw_free, rc = -ENOMEM);
                }

                memset(lsm, 0, sizeof(*lsm)); // XXX don't do this later
                lsm->lsm_object_id = id; // ensure id == lsm->lsm_object_id

                for (j = 0, pgp = pga; j < pages; j++, off += PAGE_SIZE, pgp++){
                        pgp->pg = alloc_pages(gfp_mask, 0);
                        if (!pgp->pg) {
                                CERROR("no memory for brw pages\n");
                                GOTO(brw_cleanup, rc = -ENOMEM);
                        }
                        pgp->count = PAGE_SIZE;
                        pgp->off = off;
                        pgp->flag = 0;

                        if (verify) {
                                void *addr = kmap(pgp->pg);

                                if (rw == OBD_BRW_WRITE)
                                        page_debug_setup(addr, pgp->count,
                                                         pgp->off, id);
                                else
                                        page_debug_setup(addr, pgp->count,
                                                         0xdeadbeef00c0ffee,
                                                         0xdeadbeef00c0ffee);
                                kunmap(pgp->pg);
                        }
                }

                set->brw_callback = ll_brw_sync_wait;
                rc = obd_brw(rw, &ec->conn, lsm, j, pga, set);
                if (rc)
                        CERROR("test_brw: error from obd_brw: rc = %d\n", rc);
                else {
                        rc = ll_brw_sync_wait(set, CB_PHASE_START);
                        if (rc)
                                CERROR("test_brw: error from callback: rc = "
                                       "%d\n", rc);
                }
                EXIT;
        brw_cleanup:
                for (j = 0, pgp = pga; j < pages; j++, pgp++) {
                        if (pgp->pg == NULL)
                                continue;

                        if (verify && !rc) {
                                void *addr = kmap(pgp->pg);

                                rc = page_debug_check("test_brw", addr,
                                                       PAGE_SIZE, pgp->off, id);
                                kunmap(pgp->pg);
                        }
                        __free_pages(pgp->pg, 0);
                }
        brw_free:
                obd_brw_set_free(set);
                OBD_FREE(pga, pages * sizeof(*pga));
                GOTO(out, rc);
        }
        default:
                return -ENOTTY;
        }

 out:
        RETURN(rc);
}

static int echo_setup(struct obd_device *obddev, obd_count len, void *buf)
{
        struct obd_ioctl_data* data = buf;
        struct echo_client_obd *ec = &obddev->u.echo_client;
        struct obd_device *tgt;
        int rc;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a TARGET OBD UUID\n");
                RETURN(-EINVAL);
        }
        if (data->ioc_inllen1 > 37) {
                CERROR("OBD UUID must be less than 38 characters\n");
                RETURN(-EINVAL);
        }

        MOD_INC_USE_COUNT;
        tgt = class_uuid2obd(data->ioc_inlbuf1);
        if (!tgt || !(tgt->obd_flags & OBD_ATTACHED) ||
            !(tgt->obd_flags & OBD_SET_UP)) {
                CERROR("device not attached or not set up (%d)\n",
                       data->ioc_dev);
                GOTO(error_dec, rc = -EINVAL);
        }

        rc = obd_connect(&ec->conn, tgt, NULL, NULL, NULL);
        if (rc) {
                CERROR("fail to connect to device %d\n", data->ioc_dev);
                GOTO(error_dec, rc = -EINVAL);
        }
        RETURN(rc);
error_dec:
        MOD_DEC_USE_COUNT;
        RETURN(rc);
}

static int echo_cleanup(struct obd_device * obddev)
{
        struct echo_client_obd *ec = &obddev->u.echo_client;
        int rc;
        ENTRY;

        if (!list_empty(&obddev->obd_exports)) {
                CERROR("still has clients!\n");
                RETURN(-EBUSY);
        }

        rc = obd_disconnect(&ec->conn);
        if (rc) {
                CERROR("fail to disconnect device: %d\n", rc);
                RETURN(-EINVAL);
        }

        MOD_DEC_USE_COUNT;
        RETURN(0);
}

static int echo_connect(struct lustre_handle *conn, struct obd_device *src,
                        obd_uuid_t cluuid, struct recovd_obd *recovd,
                        ptlrpc_recovery_cb_t recover)
{
        return class_connect(conn, src, cluuid);
}

static struct obd_ops echo_obd_ops = {
        o_setup:       echo_setup,
        o_cleanup:     echo_cleanup,
        o_iocontrol:   echo_iocontrol,
        o_connect:     echo_connect,
        o_disconnect:  class_disconnect
};

int echo_client_init(void)
{
        extern struct lprocfs_vars status_class_var[];

        return class_register_type(&echo_obd_ops, status_class_var,
                                   OBD_ECHO_CLIENT_DEVICENAME);
}

void echo_client_cleanup(void)
{
        class_unregister_type(OBD_ECHO_CLIENT_DEVICENAME);
}
