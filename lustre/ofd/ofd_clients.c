/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/ofd/ofd_clients.c
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
 *   Author: Peter Braam <braam@clusterfs.com>
 *   Author: Andreas Dilger <adilger@clusterfs.com>
 *   Author: Alex Tomas <alex@clusterfs.com>
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

#include "ofd_internal.h"

/* Add client data to the FILTER.  We use a bitmap to locate a free space
 * in the last_rcvd file if cl_idx is -1 (i.e. a new client).
 * Otherwise, we have just read the data from the last_rcvd file and
 * we know its offset. */
int filter_client_new(const struct lu_env *env, struct filter_device *ofd,
                      struct filter_export_data *fed)
{
        struct obd_device *obd = filter_obd(ofd);
        unsigned long *bitmap = ofd->ofd_last_rcvd_slots;
        struct lsd_client_data *lcd = fed->fed_lcd;
        loff_t off;
        int err, cl_idx = 0;
        struct thandle *th;
        ENTRY;

        LASSERT(bitmap != NULL);

        /* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp((char *)lcd->lcd_uuid, (char *)obd->obd_uuid.uuid))
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        cl_idx = find_first_zero_bit(bitmap, LR_MAX_CLIENTS);
repeat:
        if (cl_idx >= LR_MAX_CLIENTS) {
                CERROR("no client slots - fix LR_MAX_CLIENTS\n");
                RETURN(-EOVERFLOW);
        }
        if (test_and_set_bit(cl_idx, bitmap)) {
                cl_idx = find_next_zero_bit(bitmap, LR_MAX_CLIENTS, cl_idx);
                goto repeat;
        }

        fed->fed_lr_idx = cl_idx;
        fed->fed_lr_off = ofd->ofd_fsd.lsd_client_start +
                          cl_idx * ofd->ofd_fsd.lsd_client_size;
        init_mutex(&fed->fed_lastrcvd_lock);
        LASSERTF(fed->fed_lr_off > 0, "fed_lr_off = %llu\n", fed->fed_lr_off);

        CDEBUG(D_INFO, "client at index %d (%llu) with UUID '%s' added\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_lcd->lcd_uuid);

        CDEBUG(D_INFO, "writing client lcd at idx %u (%llu) (len %u)\n",
               fed->fed_lr_idx, fed->fed_lr_off,
               (unsigned int)sizeof(*fed->fed_lcd));

        th = filter_trans_create(env, ofd);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));
        /* off is changed, use tmp value */
        off = fed->fed_lr_off;
        dt_declare_record_write(env, ofd->ofd_last_rcvd, off,
                                sizeof(*lcd), th, BYPASS_CAPA);
        err = filter_trans_start(env, ofd, th);
        if (err)
                RETURN(err);
        /* XXX: until this operations will be committed the sync is needed for this
         * export */
        /*
        mdt_trans_add_cb(th, mdt_cb_new_client, mti->mti_exp);
        spin_lock(&mti->mti_exp->exp_lock);
        mti->mti_exp->exp_need_sync = 1;
        spin_unlock(&mti->mti_exp->exp_lock);
        */

        err = filter_last_rcvd_write(env, ofd, lcd, &off, th);

        CDEBUG(D_INFO, "wrote client lcd at idx %u off %llu (len %u)\n",
               cl_idx, fed->fed_lr_off, sizeof(*fed->fed_lcd));

        filter_trans_stop(env, ofd, th);

        RETURN(err);
}

int filter_client_add(const struct lu_env *env, struct filter_device *ofd,
                      struct filter_export_data *fed, int cl_idx)
{
        struct obd_device *obd = filter_obd(ofd);
        unsigned long *bitmap = ofd->ofd_last_rcvd_slots;
        ENTRY;

        LASSERT(bitmap != NULL);
        LASSERT(cl_idx >= 0);

        /* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp((char *)fed->fed_lcd->lcd_uuid, (char *)obd->obd_uuid.uuid))
                RETURN(0);

        /* the bitmap operations can handle cl_idx > sizeof(long) * 8, so
         * there's no need for extra complication here
         */
        if (test_and_set_bit(cl_idx, bitmap)) {
                CERROR("FILTER client %d: bit already set in bitmap!\n",
                       cl_idx);
                LBUG();
        }

        fed->fed_lr_idx = cl_idx;
        fed->fed_lr_off = ofd->ofd_fsd.lsd_client_start +
                          cl_idx * ofd->ofd_fsd.lsd_client_size;
        init_mutex(&fed->fed_lastrcvd_lock);
        LASSERTF(fed->fed_lr_off > 0, "fed_lr_off = %llu\n", fed->fed_lr_off);

        CDEBUG(D_INFO, "client at index %d (%llu) with UUID '%s' added\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_lcd->lcd_uuid);

        RETURN(0);
}

int filter_client_free(struct lu_env *env, struct obd_export *exp)
{
        struct filter_export_data *fed = &exp->exp_filter_data;
        struct obd_device *obd = exp->exp_obd;
        struct filter_device *ofd = filter_exp(exp);
        struct lsd_client_data *lcd = fed->fed_lcd;
        struct thandle *th;
        loff_t off;
        int rc;
        ENTRY;

        if (fed->fed_lcd == NULL)
                RETURN(0);

        /* XXX if lcd_uuid were a real obd_uuid, I could use obd_uuid_equals */
        if (!strcmp((char *)fed->fed_lcd->lcd_uuid, (char *)obd->obd_uuid.uuid))
                GOTO(free, 0);

        CDEBUG(D_INFO, "freeing client at idx %u, offset %lld with UUID '%s'\n",
               fed->fed_lr_idx, fed->fed_lr_off, fed->fed_lcd->lcd_uuid);

        LASSERT(ofd->ofd_last_rcvd_slots != NULL);

        /* Clear the bit _after_ zeroing out the client so we don't
           race with filter_client_add and zero out new clients.*/
        if (!test_bit(fed->fed_lr_idx, ofd->ofd_last_rcvd_slots)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       fed->fed_lr_idx);
                LBUG();
        }

        if (!(exp->exp_flags & OBD_OPT_FAILOVER)) {
                th = filter_trans_create(env, ofd);
                if (IS_ERR(th))
                        GOTO(free, rc = PTR_ERR(th));
                /* declare last_rcvd write */
                dt_declare_record_write(env, ofd->ofd_last_rcvd, fed->fed_lr_off,
                                        sizeof(*lcd), th, BYPASS_CAPA);
                /* declare header write */
                dt_declare_record_write(env, ofd->ofd_last_rcvd, 0,
                                        sizeof(ofd->ofd_fsd), th, BYPASS_CAPA);

                rc = filter_trans_start(env, ofd, th);
                if (rc)
                        GOTO(free, rc);
                mutex_down(&fed->fed_lastrcvd_lock);
                memset(lcd, 0, sizeof(*lcd));
                /* off is changed after write, use tmp value */
                off = fed->fed_lr_off;
                rc = filter_last_rcvd_write(env, ofd, lcd, &off, th);
                mutex_up(&fed->fed_lastrcvd_lock);
                LASSERT(rc == 0);

                /* update server's transno */
                filter_last_rcvd_header_write(env, ofd, th);

                filter_trans_stop(env, ofd, th);

                CDEBUG(rc == 0 ? D_INFO : D_ERROR,
                       "zeroing out client %s at idx %u (%llu) in %s rc %d\n",
                       fed->fed_lcd->lcd_uuid, fed->fed_lr_idx, fed->fed_lr_off,
                       LAST_RCVD, rc);
        }

        if (!test_and_clear_bit(fed->fed_lr_idx, ofd->ofd_last_rcvd_slots)) {
                CERROR("FILTER client %u: bit already clear in bitmap!!\n",
                       fed->fed_lr_idx);
                LBUG();
        }

        EXIT;
free:
        OBD_FREE(fed->fed_lcd, sizeof(*fed->fed_lcd));
        fed->fed_lcd = NULL;

        return 0;
}

