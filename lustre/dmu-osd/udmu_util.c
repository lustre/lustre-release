#if 0
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
 *
 * lustre/dmu/udmu.c
 * Module that interacts with the ZFS DMU and provides an abstraction
 * to the rest of Lustre.
 *
 * Author: Manoj Joseph <manoj.joseph@sun.com>
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/debug.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/errno.h>

#include <udmu.h>
#include <udmu_util.h>

static int udmu_util_object_delete(udmu_objset_t *uos, dmu_buf_t **dbp,
                                   void *tag)
{
        dmu_tx_t *tx;
        uint64_t id;
        int rc;

        id = udmu_object_get_id(*dbp);
        tx = udmu_tx_create(uos);

        udmu_tx_hold_free(tx, id, 0, DMU_OBJECT_END);

        rc = udmu_tx_assign(tx, TXG_WAIT);
        if (rc) {
                fprintf(stderr,
                        "udmu_util_object_delete: udmu_tx_assign failed (%d)", rc);
                udmu_tx_abort(tx);
                return (rc);
        }

        rc = udmu_object_delete(uos, dbp, tx, tag);
        if (rc)
                fprintf(stderr, "udmu_object_delete() failed (%d)", rc);

        udmu_tx_commit(tx);
        return rc;
}

int udmu_util_mkdir(udmu_objset_t *uos, dmu_buf_t *parent_db,
                    const char *name, dmu_buf_t **new_dbp, void *tag)
{
        dmu_buf_t *db;
        dmu_tx_t *tx;
        uint64_t id, pid, value;
        int rc;

        /* return EEXIST early to avoid object creation/deletion */
        rc = udmu_zap_lookup(uos, parent_db, name, &id,
                             sizeof(id), sizeof(uint64_t));
        if (rc == 0)
                return EEXIST;

        pid = udmu_object_get_id(parent_db);

        tx = udmu_tx_create(uos);
        udmu_tx_hold_zap(tx, DMU_NEW_OBJECT, 1, NULL); /* for zap create */
        udmu_tx_hold_bonus(tx, pid); /* for zap_add */
        udmu_tx_hold_zap(tx, pid, 1, (char *)name); /* for zap_add */

        rc = udmu_tx_assign(tx, TXG_WAIT);
        if (rc) {
                fprintf(stderr,
                        "udmu_util_mkdir: udmu_tx_assign failed (%d)", rc);
                udmu_tx_abort(tx);
                return (rc);
        }

        udmu_zap_create(uos, &db, tx, tag);
        id = udmu_object_get_id(db);
        value = ZFS_DIRENT_MAKE(0, id);
        rc = udmu_zap_insert(uos, parent_db, tx, name, &value, sizeof(value));
        udmu_tx_commit(tx);

        if (rc) {
                fprintf(stderr, "can't insert (%s) in zap (%d)", name, rc);
                /* error handling, delete just created object */
                udmu_util_object_delete(uos, &db, tag);
        } else if (new_dbp) {
                *new_dbp = db;
        } else {
                udmu_object_put_dmu_buf(db, tag);
        }

        return (rc);
}

int udmu_util_setattr(udmu_objset_t *uos, dmu_buf_t *db, vnattr_t *va)
{
        dmu_tx_t *tx;
        int rc;

        tx = udmu_tx_create(uos);
        udmu_tx_hold_bonus(tx, udmu_object_get_id(db));

        rc = udmu_tx_assign(tx, TXG_WAIT);
        if (rc) {
                udmu_tx_abort(tx);
        } else {
                udmu_object_setattr(db, tx, va);
                udmu_tx_commit(tx);
        }

        return (rc);
}

int udmu_util_create(udmu_objset_t *uos, dmu_buf_t *parent_db,
                     const char *name, dmu_buf_t **new_dbp, void *tag)
{
        dmu_buf_t *db;
        dmu_tx_t *tx;
        uint64_t id, pid, value;
        int rc;

        /* return EEXIST early to avoid object creation/deletion */
        rc = udmu_zap_lookup(uos, parent_db, name, &id,
                             sizeof(id), sizeof(uint64_t));
        if (rc == 0)
                return EEXIST;

        pid = udmu_object_get_id(parent_db);

        tx = udmu_tx_create(uos);

        udmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
        udmu_tx_hold_bonus(tx, pid);
        udmu_tx_hold_zap(tx, pid, 1, (char *) name);

        rc = udmu_tx_assign(tx, TXG_WAIT);
        if (rc) {
                fprintf(stderr,
                        "udmu_util_create: udmu_tx_assign failed (%d)", rc);
                udmu_tx_abort(tx);
                return (rc);
        }

        udmu_object_create(uos, &db, tx, tag);
        id = udmu_object_get_id(db);
        value = ZFS_DIRENT_MAKE(0, id);
        rc = udmu_zap_insert(uos, parent_db, tx, name,
                             &value, sizeof(value));
        udmu_tx_commit(tx);

        if (rc) {
                fprintf(stderr, "can't insert new object in zap (%d)", rc);
                /* error handling, delete just created object */
                udmu_util_object_delete(uos, &db, tag);
        } else if (new_dbp) {
                *new_dbp = db;
        } else {
                udmu_object_put_dmu_buf(db, tag);
        }

        return (rc);
}

int udmu_util_lookup(udmu_objset_t *uos, dmu_buf_t *parent_db,
                     const char *name, dmu_buf_t **new_dbp, void *tag)
{
        uint64_t id;
        int rc;

        rc = udmu_zap_lookup(uos, parent_db, name, &id,
                             sizeof(id), sizeof(uint64_t));
        if (rc == 0) {
                udmu_object_get_dmu_buf(uos, id, new_dbp, tag);
        }

        return (rc);
}

int udmu_util_write(udmu_objset_t *uos, dmu_buf_t *db,
                    uint64_t offset, uint64_t len, void *buf)
{
        dmu_tx_t *tx;
        int set_size = 0;
        uint64_t end = offset + len;
        vnattr_t va;
        int rc;

        udmu_object_getattr(db, &va);

        if (va.va_size < end) {
                /* extending write; set file size */
                set_size = 1;
                va.va_mask = AT_SIZE;
                va.va_size = end;
        }

        tx = udmu_tx_create(uos);
        if (set_size) {
                udmu_tx_hold_bonus(tx, udmu_object_get_id(db));
        }
        udmu_tx_hold_write(tx, udmu_object_get_id(db), offset, len);

        rc = udmu_tx_assign(tx, TXG_WAIT);
        if (rc) {
                fprintf(stderr, "dmu_tx_assign() failed %d", rc);
                udmu_tx_abort(tx);
                return (-rc);
        }

        udmu_object_write(uos, db, tx, offset,
                          len, buf);
        if (set_size) {
                udmu_object_setattr(db, tx, &va);
        }

        udmu_tx_commit(tx);

        return (len);
}
#endif
