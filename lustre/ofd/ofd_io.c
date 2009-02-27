/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  lustre/ofd/ofd_io.c
 *
 *  Copyright (c) 2007 Cluster File Systems, Inc.
 *   Author: Alex Tomas <alex@clusterfs.com>
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
 */

#define DEBUG_SUBSYSTEM S_FILTER

#include <libcfs/libcfs.h>
#include <obd_class.h>

#include "ofd_internal.h"

static int filter_preprw_read(const struct lu_env *env,
                              struct filter_device *ofd, struct lu_fid *fid,
                              struct lu_attr *la, int niocount,
                              struct niobuf_remote *nb, int *nr_local,
                              struct niobuf_local *res)
{
        struct filter_object *fo;
        int i, j, rc = 0;
        LASSERT(env != NULL);

        fo = filter_object_find(env, ofd, fid);
        if (IS_ERR(fo))
                RETURN(PTR_ERR(fo));
        LASSERT(fo != NULL);

        if (filter_object_exists(fo)) {
                /* parse remote buffers to local buffers 
                   and prepare the latter */
                for (i = 0, j = 0; i < niocount; i++) {
                        rc = dt_bufs_get(env, filter_object_child(fo),
                                         nb + i, res + j);
                        LASSERT(rc > 0);
                        LASSERT(rc < PTLRPC_MAX_BRW_PAGES);
                        /* correct index for local buffers to continue with */
                        j += rc;
                        LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
                }
                *nr_local = j;
                LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);
                rc = dt_attr_get(env, filter_object_child(fo), la,
                                 filter_object_capa(env, fo));
                LASSERT(rc == 0);
                rc = dt_read_prep(env, filter_object_child(fo), res,
                                  *nr_local);
        } else {
                /* CROW object. We have to simulate empty buffers */
                for (i = 0, j = 0; i < niocount; i++) {
                        res[j].file_offset = nb[i].offset;
                        res[j].page_offset = 0;
                        res[j].len = 0;
                        res[j].page = NULL;
                        res[j].lnb_grant_used = 0;
                        res[j].bytes = 0;
                        res[j].rc = 0;
                        j++;
                        LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
                }
                *nr_local = j;
                filter_attr_get(env, fo, la);
        }

        filter_object_put(env, fo);
        RETURN(rc);
}

static int filter_preprw_write(const struct lu_env *env, struct obd_export *exp,
                               struct filter_device *ofd, struct lu_fid *fid,
                               struct lu_attr *la, struct obdo *oa,
                               int objcount, struct obd_ioobj *obj,
                               struct niobuf_remote *nb, int *nr_local,
                               struct niobuf_local *res)
{
        unsigned long used = 0, ungranted = 0;
        obd_size left;
        struct filter_object *fo;
        int i, j, rc = 0;

        ENTRY;
        LASSERT(env != NULL);

        fo = filter_object_find_or_create(env, ofd, fid, la);
        if (IS_ERR(fo))
                RETURN(PTR_ERR(fo));
        LASSERT(fo != NULL);
        LASSERT(filter_object_exists(fo));

        /* parse remote buffers to local buffers and prepare the latter */
        for (i = 0, j = 0; i < obj->ioo_bufcnt; i++) {
                rc = dt_bufs_get(env, filter_object_child(fo),
                                 nb + i, res + j);
                LASSERT(rc > 0);
                LASSERT(rc < PTLRPC_MAX_BRW_PAGES);
                /* correct index for local buffers to continue with */
                j += rc;
                LASSERT(j <= PTLRPC_MAX_BRW_PAGES);
        }
        *nr_local = j;
        LASSERT(*nr_local > 0 && *nr_local <= PTLRPC_MAX_BRW_PAGES);

        spin_lock(&exp->exp_obd->obd_osfs_lock);
        filter_grant_incoming(exp, oa);
        left = filter_grant_space_left(env, exp);

        rc = filter_grant_check(env, exp, oa, objcount, obj, nb,
                                res, &left, &used, &ungranted);

        rc = filter_grant_client_calc(exp, &left, &used, &ungranted);

        /* do not zero out oa->o_valid as it is used in
         * * filter_commitrw_write() for setting UID/GID and
         * * fid EA in first write time. */
        if (oa->o_valid & OBD_MD_FLGRANT)
                oa->o_grant = filter_grant(env, exp, oa->o_grant,
                                           oa->o_undirty, left);
        spin_unlock(&exp->exp_obd->obd_osfs_lock);

        rc = dt_write_prep(env, filter_object_child(fo), res, *nr_local, &used);

        filter_object_put(env, fo);
        RETURN(rc);
}

int filter_preprw(int cmd, struct obd_export *exp, struct obdo *oa, int objcount,
                  struct obd_ioobj *obj, struct niobuf_remote *nb,
                  int *nr_local, struct niobuf_local *res,
                  struct obd_trans_info *oti, struct lustre_capa *capa)
{
        struct lu_env env;
        struct filter_device *ofd = filter_exp(exp);
        struct filter_thread_info *info;
        int rc = 0;

        rc = lu_env_init(&env, LCT_DT_THREAD);
        if (rc)
                RETURN(rc);
        info = filter_info_init(&env, exp);

        LASSERT(objcount == 1);
        LASSERT(obj->ioo_bufcnt > 0);

        lu_idif_build(&info->fti_fid, obj->ioo_id, obj->ioo_gr);

        if (cmd == OBD_BRW_WRITE) {
                rc = filter_auth_capa(ofd, &info->fti_fid, obdo_mdsno(oa),
                                      capa, CAPA_OPC_OSS_WRITE);
                if (rc == 0) {
                        LASSERT(oa != NULL);
                        la_from_obdo(&info->fti_attr, oa, OBD_MD_FLGETATTR);
                        /* XXX: shouldn't we get this from odbo? */
                        info->fti_attr.la_valid = LA_TYPE|LA_MODE;
                        info->fti_attr.la_mode = S_IFREG | 0666;

                        rc = filter_preprw_write(&env, exp, ofd, &info->fti_fid,
                                                 &info->fti_attr, oa, objcount,
                                                 obj, nb, nr_local,
                                                 res);
                }
        } else if (cmd == OBD_BRW_READ) {
                rc = filter_auth_capa(ofd, &info->fti_fid, obdo_mdsno(oa),
                                      capa, CAPA_OPC_OSS_READ);
                if (rc == 0) {
                        if (oa && oa->o_valid & OBD_MD_FLGRANT) {
                                struct obd_device *obd = filter_obd(ofd);
                                spin_lock(&obd->obd_osfs_lock);
                                filter_grant_incoming(exp, oa);

                                oa->o_grant = 0;
                                spin_unlock(&obd->obd_osfs_lock);
                        }
                        rc = filter_preprw_read(&env, ofd, &info->fti_fid,
                                                &info->fti_attr, obj->ioo_bufcnt,
                                                nb, nr_local, res);
                        obdo_from_la(oa, &info->fti_attr, LA_ATIME);
                }
        } else {
                LBUG();
                rc = -EPROTO;
        }
        lu_env_fini(&env);
        RETURN(rc);
}

static int
filter_commitrw_read(const struct lu_env *env, struct filter_device *ofd,
                     struct lu_fid *fid, int objcount, int niocount,
                     struct niobuf_local *res)
{
        struct filter_object *fo;
        ENTRY;

        LASSERT(niocount > 0);

        fo = filter_object_find(env, ofd, fid);
        if (IS_ERR(fo))
                RETURN(PTR_ERR(fo));
        LASSERT(fo != NULL);
        if (filter_object_exists(fo)) {
                dt_bufs_put(env, filter_object_child(fo), res, niocount);
        } else {
                /* CROW object, do nothing */
        }

        filter_object_put(env, fo);
        RETURN(0);
}

static int
filter_commitrw_write(const struct lu_env *env, struct filter_device *ofd,
                      struct lu_fid *fid, struct lu_attr *la, int objcount,
                      int niocount, struct niobuf_local *res, int old_rc)
{
        struct filter_thread_info *info = filter_info(env);
        struct filter_object *fo;
        struct thandle *th;
        int rc = 0;
        ENTRY;

        LASSERT(objcount == 1);

        fo = filter_object_find(env, ofd, fid);
        if (IS_ERR(fo))
                RETURN(PTR_ERR(fo));
        LASSERT(fo != NULL);
        LASSERT(filter_object_exists(fo));
        if (old_rc)
                GOTO(out, rc = old_rc);

        /* XXX: need 1 here until support on client for async writes */
#if 0
        info->fti_txn_param.tp_sync = 0;
#endif

        th = filter_trans_create(env, ofd);
        if (IS_ERR(th))
                GOTO(out, rc = PTR_ERR(th));

        rc = dt_declare_write_commit(env, filter_object_child(fo),
                                     res, niocount, th);
        LASSERT(rc == 0);

        if (la->la_valid) {
                rc = dt_declare_attr_set(env, filter_object_child(fo), la,
                                         th, filter_object_capa(env, fo));
                LASSERT(rc == 0);
        }

        rc = filter_trans_start(env, ofd, th);
        if (rc)
                GOTO(out, rc);

        rc = dt_write_commit(env, filter_object_child(fo), res, niocount, th);
        LASSERT(rc == 0);

        if (la->la_valid) {
                rc = dt_attr_set(env, filter_object_child(fo), la, th);
                LASSERT(rc == 0);
        }

        filter_trans_stop(env, ofd, th);

        /* get attr to return */
        dt_attr_get(env, filter_object_child(fo), la,
                         filter_object_capa(env, fo));
out:
        filter_grant_commit(info->fti_exp, niocount, res);
        dt_bufs_put(env, filter_object_child(fo), res, niocount);
        filter_object_put(env, fo);

        RETURN(rc);
}

int filter_commitrw(int cmd, struct obd_export *exp,
                    struct obdo *oa, int objcount, struct obd_ioobj *obj,
                    struct niobuf_remote *nb, int npages, struct niobuf_local *res,
                    struct obd_trans_info *oti, int old_rc)
{
        struct filter_device *ofd = filter_exp(exp);
        struct filter_thread_info *info;
        struct filter_mod_data *fmd;
        struct lu_env env;
        int rc = 0;

        rc = lu_env_init(&env, LCT_DT_THREAD);
        if (rc)
                RETURN(rc);
        info = filter_info_init(&env, exp);

        LASSERT(npages > 0);

        lu_idif_build(&info->fti_fid, obj->ioo_id, obj->ioo_gr);
        if (cmd == OBD_BRW_WRITE) {
                /* Don't update timestamps if this write is older than a
                 * setattr which modifies the timestamps. b=10150 */

                /* XXX when we start having persistent reservations this needs
                 * to be changed to filter_fmd_get() to create the fmd if it
                 * doesn't already exist so we can store the reservation handle
                 * there. */
                fmd = filter_fmd_find(exp, &info->fti_fid);
                if (!fmd || fmd->fmd_mactime_xid < info->fti_xid) {
                        la_from_obdo(&info->fti_attr, oa,
                                     OBD_MD_FLATIME | OBD_MD_FLMTIME |
                                     OBD_MD_FLCTIME);
                } else {
                        info->fti_attr.la_valid = 0;
                }
                filter_fmd_put(exp, fmd);

                rc = filter_commitrw_write(&env, ofd, &info->fti_fid,
                                           &info->fti_attr, objcount,
                                           npages, res, old_rc);
                if (rc == 0)
                        obdo_from_la(oa, &info->fti_attr,
                                     FILTER_VALID_FLAGS | LA_GID | LA_UID);
                else
                        obdo_from_la(oa, &info->fti_attr, LA_GID | LA_UID);
                if (old_rc == 0) {
#if 0
                        /* update per-buffer error codes */
                        if (rcs != NULL) {
                                memset(rcs, 0, npages * sizeof(__u32));
                                /* XXX: update rcs */
                                /* for (i = 0; i < npages; i++)
                                if (res[i].rc < 0)
                                        rcs[res[i].rindex] = res[i].rc;
                                */
                        }
#endif
                }
        } else if (cmd == OBD_BRW_READ) {
                struct ldlm_namespace *ns = ofd->ofd_namespace;

                /* If oa != NULL then filter_preprw_read updated the inode
                 * atime and we should update the lvb so that other glimpses
                 * will also get the updated value. bug 5972 */
                if (oa && ns && ns->ns_lvbo && ns->ns_lvbo->lvbo_update) {
                         struct ldlm_resource *rs = NULL;

                        lu_idif_resid(&info->fti_fid, &info->fti_resid);
                        rs = ldlm_resource_get(ns, NULL, &info->fti_resid,
                                               LDLM_EXTENT, 0);
                        if (rs != NULL) {
                                ns->ns_lvbo->lvbo_update(rs, NULL, 0, 1);
                                ldlm_resource_putref(rs);
                        }
                }
                rc = filter_commitrw_read(&env, ofd, &info->fti_fid, objcount,
                                          npages, res);
        } else {
                LBUG();
                rc = -EPROTO;
        }
        lu_env_fini(&env);
        RETURN(rc);
}
