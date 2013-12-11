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
 * Copyright (c) 2011, 2013, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/liblustre/rw.c
 *
 * Lustre Light block IO
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <sys/uio.h>

#include "llite_lib.h"

typedef ssize_t llu_file_piov_t(const struct iovec *iovec, int iovlen,
                                _SYSIO_OFF_T pos, ssize_t len,
                                void *private);

size_t llap_cookie_size;

static int llu_lock_to_stripe_offset(struct obd_export *exp,
				     struct lov_stripe_md *lsm,
				     struct ldlm_lock *lock)
{
        struct {
                char name[16];
                struct ldlm_lock *lock;
        } key = { .name = KEY_LOCK_TO_STRIPE, .lock = lock };
        __u32 stripe, vallen = sizeof(stripe);
        int rc;
        ENTRY;

	if (lsm == NULL || lsm->lsm_stripe_count == 1)
		RETURN(0);

        /* get our offset in the lov */
        rc = obd_get_info(NULL, exp, sizeof(key), &key, &vallen, &stripe, lsm);
        if (rc != 0) {
                CERROR("obd_get_info: rc = %d\n", rc);
                LBUG();
        }
        LASSERT(stripe < lsm->lsm_stripe_count);
	RETURN(stripe);
}

int llu_extent_lock_cancel_cb(struct ldlm_lock *lock,
                              struct ldlm_lock_desc *new, void *data,
                              int flag)
{
        struct lustre_handle lockh = { 0 };
        int rc;
        ENTRY;

        if ((unsigned long)data > 0 && (unsigned long)data < 0x1000) {
                LDLM_ERROR(lock, "cancelling lock with bad data %p", data);
                LBUG();
        }

        switch (flag) {
        case LDLM_CB_BLOCKING:
                ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, 0);
                if (rc != ELDLM_OK)
                        CERROR("ldlm_cli_cancel failed: %d\n", rc);
                break;
        case LDLM_CB_CANCELING: {
                struct inode *inode;
                struct llu_inode_info *lli;
                struct lov_stripe_md *lsm;
                __u32 stripe;
                __u64 kms;

                /* This lock wasn't granted, don't try to evict pages */
                if (lock->l_req_mode != lock->l_granted_mode)
                        RETURN(0);

                inode = llu_inode_from_lock(lock);
                if (!inode)
                        RETURN(0);
                lli= llu_i2info(inode);
                if (!lli)
                        goto iput;
		if (!lli->lli_has_smd)
			goto iput;

		lsm = ccc_inode_lsm_get(inode);
		if (lsm == NULL)
			goto iput;

                stripe = llu_lock_to_stripe_offset(llu_i2obdexp(inode),
						   lsm, lock);
                lock_res_and_lock(lock);
                kms = ldlm_extent_shift_kms(lock,
                                            lsm->lsm_oinfo[stripe]->loi_kms);
                unlock_res_and_lock(lock);
                if (lsm->lsm_oinfo[stripe]->loi_kms != kms)
                        LDLM_DEBUG(lock, "updating kms from "LPU64" to "LPU64,
                                   lsm->lsm_oinfo[stripe]->loi_kms, kms);
                loi_kms_set(lsm->lsm_oinfo[stripe], kms);
		ccc_inode_lsm_put(inode, lsm);
iput:
                I_RELE(inode);
                break;
        }
        default:
                LBUG();
        }

        RETURN(0);
}

int llu_merge_lvb(const struct lu_env *env, struct inode *inode)
{
	struct llu_inode_info *lli = llu_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct intnl_stat *st = llu_i2stat(inode);
	struct cl_attr *attr = ccc_env_thread_attr(env);
	struct ost_lvb lvb;
	int rc;
	ENTRY;

	/* merge timestamps the most recently obtained from mds with
	   timestamps obtained from osts */
	LTIME_S(inode->i_atime) = lli->lli_lvb.lvb_atime;
	LTIME_S(inode->i_mtime) = lli->lli_lvb.lvb_mtime;
	LTIME_S(inode->i_ctime) = lli->lli_lvb.lvb_ctime;

	inode_init_lvb(inode, &lvb);

	cl_object_attr_lock(obj);
	rc = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);
	if (rc == 0) {
		if (lvb.lvb_atime < attr->cat_atime)
			lvb.lvb_atime = attr->cat_atime;
		if (lvb.lvb_ctime < attr->cat_ctime)
			lvb.lvb_ctime = attr->cat_ctime;
		if (lvb.lvb_mtime < attr->cat_mtime)
			lvb.lvb_mtime = attr->cat_mtime;

		st->st_size = lvb.lvb_size;
		st->st_blocks = lvb.lvb_blocks;
		st->st_mtime = lvb.lvb_mtime;
		st->st_atime = lvb.lvb_atime;
		st->st_ctime = lvb.lvb_ctime;
	}

	RETURN(rc);
}

static
ssize_t llu_file_prwv(const struct iovec *iovec, int iovlen,
                        _SYSIO_OFF_T pos, ssize_t len,
                        void *private)
{
        struct llu_io_session *session = (struct llu_io_session *) private;
        struct inode *inode = session->lis_inode;
        struct llu_inode_info *lli = llu_i2info(inode);
        int err;
        struct lu_env *env;
        struct cl_io  *io;
        struct slp_io *sio;
        int refcheck;
        ENTRY;

        /* in a large iov read/write we'll be repeatedly called.
         * so give a chance to answer cancel ast here
         */
        liblustre_wait_event(0);

        if (len == 0 || iovlen == 0)
                RETURN(0);

        if (pos + len > lli->lli_maxbytes)
                RETURN(-ERANGE);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        /* Do NOT call "ccc_env_thread_io()" again to prevent reinitializing */
        io = &ccc_env_info(env)->cti_io;
        if (cl_io_rw_init(env, io, session->lis_cmd == OBD_BRW_WRITE?CIT_WRITE:
                                                                      CIT_READ,
                          pos, len) == 0) {
                struct ccc_io *cio;
                sio = slp_env_io(env);
                cio = ccc_env_io(env);
                /* XXX this is not right: cio->cui_iov can be modified. */
                cio->cui_iov = (struct iovec *)iovec;
                cio->cui_nrsegs = iovlen;
                cio->cui_tot_nrsegs = iovlen;
                sio->sio_session = session;
                err = cl_io_loop(env, io);
        } else {
                /* XXX WTF? */
                LBUG();
        }
        cl_io_fini(env, io);
        cl_env_put(env, &refcheck);

        if (err < 0)
                RETURN(err);

        RETURN(len);
}

static
struct llu_io_session *get_io_session(struct inode *ino, int ngroups, int cmd)
{
        struct llu_io_session *session;

        OBD_ALLOC_PTR(session);
        if (!session)
                return NULL;

        I_REF(ino);
        session->lis_inode = ino;
        session->lis_max_groups = ngroups;
        session->lis_cmd = cmd;
        return session;
}

static void put_io_session(struct llu_io_session *session)
{
        I_RELE(session->lis_inode);
        OBD_FREE_PTR(session);
}

static int llu_file_rwx(struct inode *ino,
                        struct ioctx *ioctx,
                        int read)
{
        struct llu_io_session *session;
        ssize_t cc;
        int cmd = read ? OBD_BRW_READ : OBD_BRW_WRITE;
        ENTRY;

        LASSERT(ioctx->ioctx_xtvlen >= 0);
        LASSERT(ioctx->ioctx_iovlen >= 0);

        liblustre_wait_event(0);

        if (!ioctx->ioctx_xtvlen)
                RETURN(0);

        /* XXX consider other types later */
        if (S_ISDIR(llu_i2stat(ino)->st_mode))
                RETURN(-EISDIR);
        if (!S_ISREG(llu_i2stat(ino)->st_mode))
                RETURN(-EOPNOTSUPP);

        session = get_io_session(ino, ioctx->ioctx_xtvlen * 2, cmd);
        if (!session)
                RETURN(-ENOMEM);

        cc = _sysio_enumerate_extents(ioctx->ioctx_xtv, ioctx->ioctx_xtvlen,
                                      ioctx->ioctx_iov, ioctx->ioctx_iovlen,
                                      llu_file_prwv, session);

        if (cc >= 0) {
                LASSERT(!ioctx->ioctx_cc);
                ioctx->ioctx_private = session;
                cc = 0;
        } else {
                put_io_session(session);
        }

        liblustre_wait_event(0);
        RETURN(cc);
}

void llu_io_init(struct cl_io *io, struct inode *inode, int write)
{
        struct llu_inode_info *lli = llu_i2info(inode);

        io->u.ci_rw.crw_nonblock = lli->lli_open_flags & O_NONBLOCK;
        if (write)
                io->u.ci_wr.wr_append = lli->lli_open_flags & O_APPEND;
        io->ci_obj  = llu_i2info(inode)->lli_clob;

        if ((lli->lli_open_flags & O_APPEND) && write)
                io->ci_lockreq = CILR_MANDATORY;
        else
                io->ci_lockreq = CILR_NEVER;
}

int llu_iop_read(struct inode *ino,
                 struct ioctx *ioctx)
{
        struct intnl_stat *st = llu_i2stat(ino);
        struct lu_env *env;
        struct cl_io  *io;
        int refcheck;
        int ret;

        /* BUG: 5972 */
        st->st_atime = CFS_CURRENT_TIME;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        io = ccc_env_thread_io(env);
        llu_io_init(io, ino, 0);

        ret = llu_file_rwx(ino, ioctx, 1);

        cl_env_put(env, &refcheck);
        return ret;
}

int llu_iop_write(struct inode *ino,
                  struct ioctx *ioctx)
{
        struct intnl_stat *st = llu_i2stat(ino);
        struct lu_env *env;
        struct cl_io  *io;
        int refcheck;
        int ret;

        st->st_mtime = st->st_ctime = CFS_CURRENT_TIME;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        io = ccc_env_thread_io(env);
        llu_io_init(io, ino, 1);

        ret = llu_file_rwx(ino, ioctx, 0);
        cl_env_put(env, &refcheck);
        return ret;
}

int llu_iop_iodone(struct ioctx *ioctx)
{
        struct llu_io_session *session;
        struct lu_env *env;
        struct cl_io  *io;
        int refcheck;
        ENTRY;

        liblustre_wait_event(0);

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

        io = &ccc_env_info(env)->cti_io;
        cl_io_fini(env, io);
        cl_env_put(env, &refcheck);
        session = (struct llu_io_session *) ioctx->ioctx_private;
        LASSERT(session);
        LASSERT(!IS_ERR(session));

        if (session->lis_rc == 0) {
                ioctx->ioctx_cc = session->lis_rwcount;
        } else {
                LASSERT(session->lis_rc < 0);
                ioctx->ioctx_cc = -1;
                ioctx->ioctx_errno = -session->lis_rc;
        }

        put_io_session(session);
        ioctx->ioctx_private = NULL;
        liblustre_wait_event(0);

        RETURN(1);
}
