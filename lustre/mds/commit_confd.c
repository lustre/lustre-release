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
 * version 2 along with this program; If not, see [sun.com URL with a
 * copy of GPLv2].
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

void commit_add(struct )
{
        struct obd_import *import = commit_uuid2import(rec->  uuid);

        if (!import) {
                CERROR("unaware of OST UUID %s - dorpping\n", rec-> uuid);
                EXIT;
                return;
        }

        spin_lock(&import->llcconf_lock);
        list_add(&rec->  &import);
        spin_unlock(&import->llcconf_lock);
        EXIT;
        return;
}

void commit_confd_conf_import(struct obd_import *import,
                              struct llog_commit_confirm_daemon *lccd)
{
        struct list_head *tmp, *save;


        list_for_each_safe(&import->import_cc_list, tmp, save) {
                struct llog_canceld_ctxt *cd;

                if (atomic_read(import->import_cc_count) <=
                    lccd->llcconf_lowwater)
                        break;

                cd = list_entry(tmp, struct llog_canceld_ctxt *, llcconf_entry);
                atomic_dec(&import->import_cc_count);
                commit_confd_add_and_fire(cd);
        }
        EXIT;
        return;
}


int commit_confd_main(void *data)
{
        struct llog_commit_confirm_daemon *lccd = data;

        while (1) {
                /* something has happened */
                event_wait();

                if (lccd->flags & LCCD_STOP)
                        break;


                /* lock llccd imporlist */
                spin_lock(&lccd->llcconf_lock);
                list_for_each_safe(&lccd->llcconf_list,   ) {
                        struct obd_import *import;
                        import = list_entry(&lccd->llcconf_list,
                                            struct obd_import,
                                            import_entry);
                        get_import(import);
                        spin_unlock(&lccd->llcconf_lock);
                        if (atomic_read(import->import_cc_count) >
                            lccd->llcconf_highwater)
                                commit_confd_conf_import(import);
                        put_import(import);
                        spin_lock(&lccd->llcconf_lock);

                }
                spin_unlock(&lccd->llcconf_lock);

        }

        lccd->flags = LCCD_STOPPED;
        RETURN(0);
}
