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
 * lustre/ofd/ofd_objects.c
 *
 * Author: Alex Tomas <alex@clusterfs.com>
 * Author: Mike Pershin <tappro@sun.com>
 */


#define DEBUG_SUBSYSTEM S_FILTER

#include "ofd_internal.h"

struct filter_object *filter_object_find(const struct lu_env *env,
                                         struct filter_device *ofd,
                                         const struct lu_fid *fid)
{
        struct filter_object *fo;
        struct lu_object *o;
        ENTRY;

        o = lu_object_find(env, &ofd->ofd_dt_dev.dd_lu_dev, fid, NULL);
        if (likely(!IS_ERR(o)))
                fo = filter_obj(o);
        else
                fo = (struct filter_object *)o; /* return error */
        RETURN(fo);
}

struct filter_object *filter_object_find_or_create(const struct lu_env *env,
                                                   struct filter_device *ofd,
                                                   const struct lu_fid *fid,
                                                   struct lu_attr *attr)
{
        struct filter_object *fo;
        struct dt_object *next;
        struct thandle *th;
        struct dt_object_format dof;
        int rc;
        ENTRY;

        fo = filter_object_find(env, ofd, fid);
        if (IS_ERR(fo))
                RETURN(fo);

        LASSERT(fo != NULL);
        if (filter_object_exists(fo))
                RETURN(fo);

        dof.dof_type = dt_mode_to_dft(S_IFREG);

        next = filter_object_child(fo);
        LASSERT(next != NULL);

        th = filter_trans_create(env, ofd);
        if (IS_ERR(th))
                GOTO(out, rc = PTR_ERR(th));

        rc = dt_declare_create(env, next, attr, NULL, &dof, th);
        LASSERT(rc == 0);

        rc = filter_trans_start(env, ofd, th);
        if (rc)
                GOTO(trans_stop, rc);

        filter_write_lock(env, fo, 0);
        if (filter_object_exists(fo))
                GOTO(unlock, rc = 0);

        CDEBUG(D_OTHER, "create new object %lu:%llu\n",
               (unsigned long) fid->f_oid, fid->f_seq);

        rc = dt_create(env, next, attr, NULL, &dof, th);
        LASSERT(rc == 0);
        LASSERT(filter_object_exists(fo));

unlock:
        filter_write_unlock(env, fo);

trans_stop:
        filter_trans_stop(env, ofd, th);
out:
        if (rc) {
                filter_object_put(env, fo);
                RETURN(ERR_PTR(rc));
        }
        RETURN(fo);
}

void filter_object_put(const struct lu_env *env, struct filter_object *fo)
{
        lu_object_put(env, &fo->ofo_obj.do_lu);
}

int filter_attr_set(const struct lu_env *env, struct filter_object *fo,
                    const struct lu_attr *la)
{
        struct thandle *th;
        struct filter_device *ofd = filter_obj2dev(fo);
        struct filter_thread_info *info = filter_info(env);
        struct filter_mod_data *fmd;
        int rc;
        ENTRY;

        if (la->la_valid & (LA_ATIME | LA_MTIME | LA_CTIME)) {
                fmd = filter_fmd_get(info->fti_exp, &fo->ofo_header.loh_fid);
                if (fmd && fmd->fmd_mactime_xid < info->fti_xid)
                        fmd->fmd_mactime_xid = info->fti_xid;
                filter_fmd_put(info->fti_exp, fmd);
        }

        th = filter_trans_create(env, ofd);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));

        rc = dt_declare_attr_set(env, filter_object_child(fo), la, th);
        LASSERT(rc == 0);

        rc = filter_trans_start(env, ofd, th);
        if (rc)
                RETURN(rc);

        rc = dt_attr_set(env, filter_object_child(fo), la, th,
                        filter_object_capa(env, fo));

        filter_trans_stop(env, ofd, th);

        RETURN(rc);
}

int filter_object_punch(const struct lu_env *env, struct filter_object *fo,
                        __u64 start, __u64 end, struct obdo *oa)
{
        struct thandle *th;
        struct filter_device *ofd = filter_obj2dev(fo);
        struct filter_thread_info *info = filter_info(env);
        struct filter_mod_data *fmd;
        struct lu_attr attr;
        int rc;
        ENTRY;

        /* we support truncate, not punch yet */
        LASSERT(end == OBD_OBJECT_EOF);

        fmd = filter_fmd_get(info->fti_exp, &fo->ofo_header.loh_fid);
        if (fmd && fmd->fmd_mactime_xid < info->fti_xid)
                fmd->fmd_mactime_xid = info->fti_xid;
        filter_fmd_put(info->fti_exp, fmd);

        la_from_obdo(&attr, oa, OBD_MD_FLMTIME | OBD_MD_FLATIME | OBD_MD_FLCTIME);
        attr.la_size = start;
        attr.la_valid |= LA_SIZE;
        attr.la_valid &= ~LA_TYPE;

        th = filter_trans_create(env, ofd);
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));

        rc = dt_declare_attr_set(env, filter_object_child(fo), &attr, th);
        LASSERT(rc == 0);

        rc = filter_trans_start(env, ofd, th);
        if (rc)
                RETURN(rc);

        rc = dt_attr_set(env, filter_object_child(fo), &attr, th,
                         filter_object_capa(env, fo));

        filter_trans_stop(env, ofd, th);

        RETURN(rc);

}

int filter_object_destroy(const struct lu_env *env, struct filter_object *fo)
{
        struct thandle *th;
        int rc = 0;
        ENTRY;

        th = filter_trans_create(env, filter_obj2dev(fo));
        if (IS_ERR(th))
                RETURN(PTR_ERR(th));
        dt_declare_ref_del(env, filter_object_child(fo), th);
        rc = filter_trans_start(env, filter_obj2dev(fo), th);
        if (rc)
                RETURN(rc);

        filter_fmd_drop(filter_info(env)->fti_exp, &fo->ofo_header.loh_fid);

        filter_write_lock(env, fo, 0);
        dt_ref_del(env, filter_object_child(fo), th);
        filter_write_unlock(env, fo);

        filter_trans_stop(env, filter_obj2dev(fo), th);

        RETURN(rc);
}

int filter_attr_get(const struct lu_env *env, struct filter_object *fo,
                    struct lu_attr *la)
{
        int rc = 0;

        /* CROW allow object to don't exist */
        if (filter_object_exists(fo)) {
                rc = dt_attr_get(env, filter_object_child(fo), la,
                                 filter_object_capa(env, fo));
        } else {
                la->la_size = 0;
                la->la_blocks = 0;
                la->la_atime = 0;
                la->la_ctime = 0;
                la->la_mtime = 0;
                la->la_valid = LA_SIZE | LA_BLOCKS |
                               LA_ATIME | LA_CTIME | LA_MTIME;
        }

        return rc;
}
