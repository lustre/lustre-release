/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2003 Cluster File Systems, Inc.
 *   Author: Phil Schwan <phil@clusterfs.com>
 *
 *   This file is part of Lustre, http://www.lustre.org/
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
 * A kernel module which tests the llog API from the OBD setup function.
 */

#ifndef EXPORT_SYMTAB
# define EXPORT_SYMTAB
#endif
#define DEBUG_SUBSYSTEM S_CLASS

#include <linux/module.h>
#include <linux/init.h>

#include <linux/obd_class.h>
#include <linux/lustre_log.h>

static int llog_test_rand;

/* Test named-log create/open, close */
static int llog_test_1(struct obd_device *obd)
{
        struct llog_handle *llh;
        char name[10];
        int rc, err;
        ENTRY;

        CERROR("1a: create a log with a name\n");
        sprintf(name, "%x", llog_test_rand);
        rc = llog_create(obd, &llh, name);
        if (rc)
                CERROR("1a: llog_create with name %s failed: %d\n", name, rc);

        CERROR("1b: close newly-created log\n");
        err = llog_close(llh);
        if (err)
                CERROR("1b: close log %s failed: %d\n", name, err);
        if (!rc)
                rc = err;
        RETURN(rc);
}

/* Test named-log reopen; returns opened log on success */
static int llog_test_2(struct obd_device *obd, struct llog_handle **llh)
{
        char name[10];
        int rc;
        ENTRY;

        CERROR("2: re-open a log with a name\n");
        sprintf(name, "%x", llog_test_rand);
        rc = 0;//llog_open(obd, llh, name);
        if (rc)
                CERROR("2: re-open log with name %s failed: %d\n", name, rc);

        RETURN(rc);
}

/* Test record writing, single and in bulk */
static int llog_test_3(struct obd_device *obd, struct llog_handle *llh)
{
        struct llog_rec_hdr rec;
        int rc, i;
        ENTRY;

        rec.lrh_len = LLOG_MIN_REC_SIZE;
        rec.lrh_type = 0xf00f00;

        CERROR("3a: write one log record\n");
        rc = llog_write_rec(llh, &rec, NULL, 0, NULL, -1);
        if (rc) {
                CERROR("3a: write one log record failed: %d\n", rc);
                RETURN(rc);
        }

        CERROR("3b: write 1000 more log records\n");
        for (i = 0; i < 1000; i++) {
                rc = llog_write_rec(llh, &rec, NULL, 0, NULL, -1);
                if (rc) {
                        CERROR("3b: write 1000 records failed at #%d: %d\n",
                               i + 1, rc);
                        RETURN(rc);
                }
        }

        RETURN(rc);
}

/* -------------------------------------------------------------------------
 * Tests above, boring obd functions below
 * ------------------------------------------------------------------------- */
static int llog_run_tests(struct obd_device *obd)
{
        struct llog_handle *llh;
        int rc, err, cleanup_phase = 0;
        ENTRY;

        rc = llog_test_1(obd);
        if (rc)
                GOTO(cleanup, rc);

        rc = llog_test_2(obd, &llh);
        if (rc)
                GOTO(cleanup, rc);
        cleanup_phase = 1; /* close llh */

        rc = llog_test_3(obd, llh);
        if (rc)
                GOTO(cleanup, rc);

        GOTO(cleanup, rc);
 cleanup:
        switch (cleanup_phase) {
        case 1:
                err = llog_close(llh);
                if (err)
                        CERROR("cleanup: llog_close failed: %d\n", err);
                if (!rc)
                        rc = err;
        }

        return rc;
}

static int llog_test_cleanup(struct obd_device *obd, int flags)
{
        int rc = obd_disconnect(obd->obd_log_exp, 0);
        if (rc)
                CERROR("failed to disconnect from log device: %d\n", rc);
        return rc;
}

static int llog_test_setup(struct obd_device *obd, obd_count len, void *buf)
{
        struct obd_ioctl_data *data = buf;
        struct lustre_handle conn = {0, };
        struct obd_device *tgt;
        struct obd_uuid fake_uuid = { "LLOG_TEST_UUID" };
        int rc;
        ENTRY;

        if (data->ioc_inllen1 < 1) {
                CERROR("requires a TARGET OBD name\n");
                RETURN(-EINVAL);
        }

        tgt = class_name2obd(data->ioc_inlbuf1);
        if (!tgt || !tgt->obd_attached || !tgt->obd_set_up) {
                CERROR("target device not attached or not set up (%d/%s)\n",
                       data->ioc_dev, data->ioc_inlbuf1);
                RETURN(-EINVAL);
        }

        rc = obd_connect(&conn, tgt, &fake_uuid);
        if (rc) {
                CERROR("fail to connect to target device %d\n", data->ioc_dev);
                RETURN(rc);
        }
        obd->obd_log_exp = class_conn2export(&conn);

        rc = llog_run_tests(obd);
        if (rc)
                llog_test_cleanup(obd, 0);
        RETURN(rc);
}

static int llog_test_attach(struct obd_device *dev, obd_count len, void *data)
{
        struct lprocfs_static_vars lvars;

        lprocfs_init_vars(ost, &lvars);
        return lprocfs_obd_attach(dev, lvars.obd_vars);
}

static int llog_test_detach(struct obd_device *dev)
{
        return lprocfs_obd_detach(dev);
}

static struct obd_ops llog_obd_ops = {
        o_owner:       THIS_MODULE,
        o_attach:      llog_test_attach,
        o_detach:      llog_test_detach,
        o_setup:       llog_test_setup,
        o_cleanup:     llog_test_cleanup,
};

static int __init llog_test_init(void)
{
        struct lprocfs_static_vars lvars;

        llog_test_rand = ll_insecure_random_int();

        lprocfs_init_multi_vars(0, &lvars);
        return class_register_type(&llog_obd_ops,lvars.module_vars,"llog_test");
}

static void __exit llog_test_exit(void)
{
        class_unregister_type("llog_test");
}

MODULE_AUTHOR("Cluster File Systems, Inc. <info@clusterfs.com>");
MODULE_DESCRIPTION("llog test module");
MODULE_LICENSE("GPL");

module_init(llog_test_init);
module_exit(llog_test_exit);
