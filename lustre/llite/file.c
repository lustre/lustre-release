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
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/file.c
 *
 * Author: Peter Braam <braam@clusterfs.com>
 * Author: Phil Schwan <phil@clusterfs.com>
 * Author: Andreas Dilger <adilger@clusterfs.com>
 */

#define DEBUG_SUBSYSTEM S_LLITE
#include <lustre_dlm.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/sched.h>
#include <linux/user_namespace.h>
#ifdef HAVE_UIDGID_HEADER
# include <linux/uidgid.h>
#endif
#include <lustre/ll_fiemap.h>

#include <uapi/linux/lustre_ioctl.h>
#include <lustre_swab.h>

#include "cl_object.h"
#include "llite_internal.h"
#include "vvp_internal.h"

static int
ll_put_grouplock(struct inode *inode, struct file *file, unsigned long arg);

static int ll_lease_close(struct obd_client_handle *och, struct inode *inode,
			  bool *lease_broken);

static struct ll_file_data *ll_file_data_get(void)
{
	struct ll_file_data *fd;

	OBD_SLAB_ALLOC_PTR_GFP(fd, ll_file_data_slab, GFP_NOFS);
	if (fd == NULL)
		return NULL;

	fd->fd_write_failed = false;

	return fd;
}

static void ll_file_data_put(struct ll_file_data *fd)
{
        if (fd != NULL)
                OBD_SLAB_FREE_PTR(fd, ll_file_data_slab);
}

/**
 * Packs all the attributes into @op_data for the CLOSE rpc.
 */
static void ll_prepare_close(struct inode *inode, struct md_op_data *op_data,
                             struct obd_client_handle *och)
{
	ENTRY;

	ll_prep_md_op_data(op_data, inode, NULL, NULL,
			   0, 0, LUSTRE_OPC_ANY, NULL);

	op_data->op_attr.ia_mode = inode->i_mode;
	op_data->op_attr.ia_atime = inode->i_atime;
	op_data->op_attr.ia_mtime = inode->i_mtime;
	op_data->op_attr.ia_ctime = inode->i_ctime;
	op_data->op_attr.ia_size = i_size_read(inode);
	op_data->op_attr.ia_valid |= ATTR_MODE | ATTR_ATIME | ATTR_ATIME_SET |
				     ATTR_MTIME | ATTR_MTIME_SET |
				     ATTR_CTIME | ATTR_CTIME_SET;
	op_data->op_attr_blocks = inode->i_blocks;
	op_data->op_attr_flags = ll_inode_to_ext_flags(inode->i_flags);
	op_data->op_handle = och->och_fh;

	if (och->och_flags & FMODE_WRITE &&
	    ll_file_test_and_clear_flag(ll_i2info(inode), LLIF_DATA_MODIFIED))
		/* For HSM: if inode data has been modified, pack it so that
		 * MDT can set data dirty flag in the archive. */
		op_data->op_bias |= MDS_DATA_MODIFIED;

	EXIT;
}

/**
 * Perform a close, possibly with a bias.
 * The meaning of "data" depends on the value of "bias".
 *
 * If \a bias is MDS_HSM_RELEASE then \a data is a pointer to the data version.
 * If \a bias is MDS_CLOSE_LAYOUT_SWAP then \a data is a pointer to the inode to
 * swap layouts with.
 */
static int ll_close_inode_openhandle(struct inode *inode,
				     struct obd_client_handle *och,
				     enum mds_op_bias bias, void *data)
{
	struct obd_export *md_exp = ll_i2mdexp(inode);
	const struct ll_inode_info *lli = ll_i2info(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc;
	ENTRY;

	if (class_exp2obd(md_exp) == NULL) {
		CERROR("%s: invalid MDC connection handle closing "DFID"\n",
		       ll_get_fsname(inode->i_sb, NULL, 0),
		       PFID(&lli->lli_fid));
		GOTO(out, rc = 0);
	}

	OBD_ALLOC_PTR(op_data);
	/* We leak openhandle and request here on error, but not much to be
	 * done in OOM case since app won't retry close on error either. */
	if (op_data == NULL)
		GOTO(out, rc = -ENOMEM);

	ll_prepare_close(inode, op_data, och);
	switch (bias) {
	case MDS_CLOSE_LAYOUT_SWAP:
		LASSERT(data != NULL);
		op_data->op_bias |= MDS_CLOSE_LAYOUT_SWAP;
		op_data->op_data_version = 0;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_fid2 = *ll_inode2fid(data);
		break;

	case MDS_HSM_RELEASE:
		LASSERT(data != NULL);
		op_data->op_bias |= MDS_HSM_RELEASE;
		op_data->op_data_version = *(__u64 *)data;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_attr.ia_valid |= ATTR_SIZE | ATTR_BLOCKS;
		break;

	default:
		LASSERT(data == NULL);
		break;
	}

	rc = md_close(md_exp, op_data, och->och_mod, &req);
	if (rc != 0 && rc != -EINTR)
		CERROR("%s: inode "DFID" mdc close failed: rc = %d\n",
		       md_exp->exp_obd->obd_name, PFID(&lli->lli_fid), rc);

	if (rc == 0 &&
	    op_data->op_bias & (MDS_HSM_RELEASE | MDS_CLOSE_LAYOUT_SWAP)) {
		struct mdt_body *body;

		body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
		if (!(body->mbo_valid & OBD_MD_CLOSE_INTENT_EXECED))
			rc = -EBUSY;
	}

	ll_finish_md_op_data(op_data);
	EXIT;
out:

	md_clear_open_replay_data(md_exp, och);
	och->och_fh.cookie = DEAD_HANDLE_MAGIC;
	OBD_FREE_PTR(och);

	ptlrpc_req_finished(req);	/* This is close request */
	return rc;
}

int ll_md_real_close(struct inode *inode, fmode_t fmode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct obd_client_handle **och_p;
	struct obd_client_handle *och;
	__u64 *och_usecount;
	int rc = 0;
	ENTRY;

	if (fmode & FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else if (fmode & FMODE_EXEC) {
		och_p = &lli->lli_mds_exec_och;
		och_usecount = &lli->lli_open_fd_exec_count;
	} else {
		LASSERT(fmode & FMODE_READ);
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	mutex_lock(&lli->lli_och_mutex);
	if (*och_usecount > 0) {
		/* There are still users of this handle, so skip
		 * freeing it. */
		mutex_unlock(&lli->lli_och_mutex);
		RETURN(0);
	}

	och = *och_p;
	*och_p = NULL;
	mutex_unlock(&lli->lli_och_mutex);

	if (och != NULL) {
		/* There might be a race and this handle may already
		 * be closed. */
		rc = ll_close_inode_openhandle(inode, och, 0, NULL);
	}

	RETURN(rc);
}

static int ll_md_close(struct inode *inode, struct file *file)
{
	union ldlm_policy_data policy = {
		.l_inodebits	= { MDS_INODELOCK_OPEN },
	};
	__u64 flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_TEST_LOCK;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lustre_handle lockh;
	enum ldlm_mode lockmode;
	int rc = 0;
	ENTRY;

	/* clear group lock, if present */
	if (unlikely(fd->fd_flags & LL_FILE_GROUP_LOCKED))
		ll_put_grouplock(inode, file, fd->fd_grouplock.lg_gid);

	if (fd->fd_lease_och != NULL) {
		bool lease_broken;

		/* Usually the lease is not released when the
		 * application crashed, we need to release here. */
		rc = ll_lease_close(fd->fd_lease_och, inode, &lease_broken);
		CDEBUG(rc ? D_ERROR : D_INODE, "Clean up lease "DFID" %d/%d\n",
			PFID(&lli->lli_fid), rc, lease_broken);

		fd->fd_lease_och = NULL;
	}

	if (fd->fd_och != NULL) {
		rc = ll_close_inode_openhandle(inode, fd->fd_och, 0, NULL);
		fd->fd_och = NULL;
		GOTO(out, rc);
	}

        /* Let's see if we have good enough OPEN lock on the file and if
           we can skip talking to MDS */
	mutex_lock(&lli->lli_och_mutex);
	if (fd->fd_omode & FMODE_WRITE) {
		lockmode = LCK_CW;
		LASSERT(lli->lli_open_fd_write_count);
		lli->lli_open_fd_write_count--;
	} else if (fd->fd_omode & FMODE_EXEC) {
		lockmode = LCK_PR;
		LASSERT(lli->lli_open_fd_exec_count);
		lli->lli_open_fd_exec_count--;
	} else {
		lockmode = LCK_CR;
		LASSERT(lli->lli_open_fd_read_count);
		lli->lli_open_fd_read_count--;
	}
	mutex_unlock(&lli->lli_och_mutex);

	if (!md_lock_match(ll_i2mdexp(inode), flags, ll_inode2fid(inode),
			   LDLM_IBITS, &policy, lockmode, &lockh))
		rc = ll_md_real_close(inode, fd->fd_omode);

out:
	LUSTRE_FPRIVATE(file) = NULL;
	ll_file_data_put(fd);

	RETURN(rc);
}

/* While this returns an error code, fput() the caller does not, so we need
 * to make every effort to clean up all of our state here.  Also, applications
 * rarely check close errors and even if an error is returned they will not
 * re-try the close call.
 */
int ll_file_release(struct inode *inode, struct file *file)
{
        struct ll_file_data *fd;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        int rc;
        ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);

	if (inode->i_sb->s_root != file_dentry(file))
                ll_stats_ops_tally(sbi, LPROC_LL_RELEASE, 1);
        fd = LUSTRE_FPRIVATE(file);
        LASSERT(fd != NULL);

	/* The last ref on @file, maybe not the the owner pid of statahead,
	 * because parent and child process can share the same file handle. */
	if (S_ISDIR(inode->i_mode) && lli->lli_opendir_key == fd)
		ll_deauthorize_statahead(inode, fd);

	if (inode->i_sb->s_root == file_dentry(file)) {
		LUSTRE_FPRIVATE(file) = NULL;
		ll_file_data_put(fd);
		RETURN(0);
	}

	if (!S_ISDIR(inode->i_mode)) {
		if (lli->lli_clob != NULL)
			lov_read_and_clear_async_rc(lli->lli_clob);
		lli->lli_async_rc = 0;
	}

	rc = ll_md_close(inode, file);

	if (CFS_FAIL_TIMEOUT_MS(OBD_FAIL_PTLRPC_DUMP_LOG, cfs_fail_val))
		libcfs_debug_dumplog();

	RETURN(rc);
}

static int ll_intent_file_open(struct dentry *de, void *lmm, int lmmsize,
				struct lookup_intent *itp)
{
	struct ll_sb_info *sbi = ll_i2sbi(de->d_inode);
	struct dentry *parent = de->d_parent;
	const char *name = NULL;
	int len = 0;
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc;
	ENTRY;

	LASSERT(parent != NULL);
	LASSERT(itp->it_flags & MDS_OPEN_BY_FID);

	/* if server supports open-by-fid, or file name is invalid, don't pack
	 * name in open request */
	if (!(exp_connect_flags(sbi->ll_md_exp) & OBD_CONNECT_OPEN_BY_FID) &&
	    lu_name_is_valid_2(de->d_name.name, de->d_name.len)) {
		name = de->d_name.name;
		len = de->d_name.len;
	}

	op_data = ll_prep_md_op_data(NULL, parent->d_inode, de->d_inode,
				     name, len, 0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));
	op_data->op_data = lmm;
	op_data->op_data_size = lmmsize;

	rc = md_intent_lock(sbi->ll_md_exp, op_data, itp, &req,
			    &ll_md_blocking_ast, 0);
	ll_finish_md_op_data(op_data);
	if (rc == -ESTALE) {
		/* reason for keep own exit path - don`t flood log
		 * with messages with -ESTALE errors.
		 */
		if (!it_disposition(itp, DISP_OPEN_OPEN) ||
		     it_open_error(DISP_OPEN_OPEN, itp))
			GOTO(out, rc);
		ll_release_openhandle(de, itp);
		GOTO(out, rc);
	}

	if (it_disposition(itp, DISP_LOOKUP_NEG))
		GOTO(out, rc = -ENOENT);

	if (rc != 0 || it_open_error(DISP_OPEN_OPEN, itp)) {
		rc = rc ? rc : it_open_error(DISP_OPEN_OPEN, itp);
		CDEBUG(D_VFSTRACE, "lock enqueue: err: %d\n", rc);
		GOTO(out, rc);
	}

	rc = ll_prep_inode(&de->d_inode, req, NULL, itp);
	if (!rc && itp->it_lock_mode)
		ll_set_lock_data(sbi->ll_md_exp, de->d_inode, itp, NULL);

out:
	ptlrpc_req_finished(req);
	ll_intent_drop_lock(itp);

	/* We did open by fid, but by the time we got to the server,
	 * the object disappeared. If this is a create, we cannot really
	 * tell the userspace that the file it was trying to create
	 * does not exist. Instead let's return -ESTALE, and the VFS will
	 * retry the create with LOOKUP_REVAL that we are going to catch
	 * in ll_revalidate_dentry() and use lookup then.
	 */
	if (rc == -ENOENT && itp->it_op & IT_CREAT)
		rc = -ESTALE;

	RETURN(rc);
}

static int ll_och_fill(struct obd_export *md_exp, struct lookup_intent *it,
		       struct obd_client_handle *och)
{
	struct mdt_body *body;

	body = req_capsule_server_get(&it->it_request->rq_pill, &RMF_MDT_BODY);
	och->och_fh = body->mbo_handle;
	och->och_fid = body->mbo_fid1;
	och->och_lease_handle.cookie = it->it_lock_handle;
	och->och_magic = OBD_CLIENT_HANDLE_MAGIC;
	och->och_flags = it->it_flags;

	return md_set_open_replay_data(md_exp, och, it);
}

static int ll_local_open(struct file *file, struct lookup_intent *it,
			 struct ll_file_data *fd, struct obd_client_handle *och)
{
	struct inode *inode = file_inode(file);
	ENTRY;

	LASSERT(!LUSTRE_FPRIVATE(file));

	LASSERT(fd != NULL);

	if (och) {
		int rc;

		rc = ll_och_fill(ll_i2sbi(inode)->ll_md_exp, it, och);
		if (rc != 0)
			RETURN(rc);
	}

	LUSTRE_FPRIVATE(file) = fd;
	ll_readahead_init(inode, &fd->fd_ras);
	fd->fd_omode = it->it_flags & (FMODE_READ | FMODE_WRITE | FMODE_EXEC);

	/* ll_cl_context initialize */
	rwlock_init(&fd->fd_lock);
	INIT_LIST_HEAD(&fd->fd_lccs);

	RETURN(0);
}

/* Open a file, and (for the very first open) create objects on the OSTs at
 * this time.  If opened with O_LOV_DELAY_CREATE, then we don't do the object
 * creation or open until ll_lov_setstripe() ioctl is called.
 *
 * If we already have the stripe MD locally then we don't request it in
 * md_open(), by passing a lmm_size = 0.
 *
 * It is up to the application to ensure no other processes open this file
 * in the O_LOV_DELAY_CREATE case, or the default striping pattern will be
 * used.  We might be able to avoid races of that sort by getting lli_open_sem
 * before returning in the O_LOV_DELAY_CREATE case and dropping it here
 * or in ll_file_release(), but I'm not sure that is desirable/necessary.
 */
int ll_file_open(struct inode *inode, struct file *file)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct lookup_intent *it, oit = { .it_op = IT_OPEN,
					  .it_flags = file->f_flags };
	struct obd_client_handle **och_p = NULL;
	__u64 *och_usecount = NULL;
	struct ll_file_data *fd;
	int rc = 0;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), flags %o\n",
	       PFID(ll_inode2fid(inode)), inode, file->f_flags);

	it = file->private_data; /* XXX: compat macro */
	file->private_data = NULL; /* prevent ll_local_open assertion */

	fd = ll_file_data_get();
	if (fd == NULL)
		GOTO(out_openerr, rc = -ENOMEM);

	fd->fd_file = file;
	if (S_ISDIR(inode->i_mode))
		ll_authorize_statahead(inode, fd);

	if (inode->i_sb->s_root == file_dentry(file)) {
                LUSTRE_FPRIVATE(file) = fd;
                RETURN(0);
        }

	if (!it || !it->it_disposition) {
                /* Convert f_flags into access mode. We cannot use file->f_mode,
                 * because everything but O_ACCMODE mask was stripped from
                 * there */
                if ((oit.it_flags + 1) & O_ACCMODE)
                        oit.it_flags++;
                if (file->f_flags & O_TRUNC)
                        oit.it_flags |= FMODE_WRITE;

                /* kernel only call f_op->open in dentry_open.  filp_open calls
                 * dentry_open after call to open_namei that checks permissions.
                 * Only nfsd_open call dentry_open directly without checking
                 * permissions and because of that this code below is safe. */
                if (oit.it_flags & (FMODE_WRITE | FMODE_READ))
                        oit.it_flags |= MDS_OPEN_OWNEROVERRIDE;

                /* We do not want O_EXCL here, presumably we opened the file
                 * already? XXX - NFS implications? */
                oit.it_flags &= ~O_EXCL;

                /* bug20584, if "it_flags" contains O_CREAT, the file will be
                 * created if necessary, then "IT_CREAT" should be set to keep
                 * consistent with it */
                if (oit.it_flags & O_CREAT)
                        oit.it_op |= IT_CREAT;

                it = &oit;
        }

restart:
        /* Let's see if we have file open on MDS already. */
        if (it->it_flags & FMODE_WRITE) {
                och_p = &lli->lli_mds_write_och;
                och_usecount = &lli->lli_open_fd_write_count;
        } else if (it->it_flags & FMODE_EXEC) {
                och_p = &lli->lli_mds_exec_och;
                och_usecount = &lli->lli_open_fd_exec_count;
         } else {
                och_p = &lli->lli_mds_read_och;
                och_usecount = &lli->lli_open_fd_read_count;
        }

	mutex_lock(&lli->lli_och_mutex);
        if (*och_p) { /* Open handle is present */
                if (it_disposition(it, DISP_OPEN_OPEN)) {
                        /* Well, there's extra open request that we do not need,
                           let's close it somehow. This will decref request. */
                        rc = it_open_error(DISP_OPEN_OPEN, it);
                        if (rc) {
				mutex_unlock(&lli->lli_och_mutex);
                                GOTO(out_openerr, rc);
                        }

			ll_release_openhandle(file_dentry(file), it);
                }
                (*och_usecount)++;

                rc = ll_local_open(file, it, fd, NULL);
                if (rc) {
                        (*och_usecount)--;
			mutex_unlock(&lli->lli_och_mutex);
                        GOTO(out_openerr, rc);
                }
        } else {
                LASSERT(*och_usecount == 0);
		if (!it->it_disposition) {
			struct ll_dentry_data *ldd = ll_d2d(file->f_path.dentry);
                        /* We cannot just request lock handle now, new ELC code
                           means that one of other OPEN locks for this file
                           could be cancelled, and since blocking ast handler
                           would attempt to grab och_mutex as well, that would
                           result in a deadlock */
			mutex_unlock(&lli->lli_och_mutex);
			/*
			 * Normally called under two situations:
			 * 1. NFS export.
			 * 2. A race/condition on MDS resulting in no open
			 *    handle to be returned from LOOKUP|OPEN request,
			 *    for example if the target entry was a symlink.
			 *
			 *  Only fetch MDS_OPEN_LOCK if this is in NFS path,
			 *  marked by a bit set in ll_iget_for_nfs. Clear the
			 *  bit so that it's not confusing later callers.
			 *
			 *  NB; when ldd is NULL, it must have come via normal
			 *  lookup path only, since ll_iget_for_nfs always calls
			 *  ll_d_init().
			 */
			if (ldd && ldd->lld_nfs_dentry) {
				ldd->lld_nfs_dentry = 0;
				it->it_flags |= MDS_OPEN_LOCK;
			}

			 /*
			 * Always specify MDS_OPEN_BY_FID because we don't want
			 * to get file with different fid.
			 */
			it->it_flags |= MDS_OPEN_BY_FID;
			rc = ll_intent_file_open(file_dentry(file), NULL, 0,
						 it);
                        if (rc)
                                GOTO(out_openerr, rc);

                        goto restart;
                }
                OBD_ALLOC(*och_p, sizeof (struct obd_client_handle));
                if (!*och_p)
                        GOTO(out_och_free, rc = -ENOMEM);

                (*och_usecount)++;

                /* md_intent_lock() didn't get a request ref if there was an
                 * open error, so don't do cleanup on the request here
                 * (bug 3430) */
                /* XXX (green): Should not we bail out on any error here, not
                 * just open error? */
		rc = it_open_error(DISP_OPEN_OPEN, it);
		if (rc != 0)
			GOTO(out_och_free, rc);

		LASSERTF(it_disposition(it, DISP_ENQ_OPEN_REF),
			 "inode %p: disposition %x, status %d\n", inode,
			 it_disposition(it, ~0), it->it_status);

		rc = ll_local_open(file, it, fd, *och_p);
		if (rc)
			GOTO(out_och_free, rc);
	}
	mutex_unlock(&lli->lli_och_mutex);
        fd = NULL;

        /* Must do this outside lli_och_mutex lock to prevent deadlock where
           different kind of OPEN lock for this same inode gets cancelled
           by ldlm_cancel_lru */
        if (!S_ISREG(inode->i_mode))
                GOTO(out_och_free, rc);

	cl_lov_delay_create_clear(&file->f_flags);
	GOTO(out_och_free, rc);

out_och_free:
        if (rc) {
                if (och_p && *och_p) {
                        OBD_FREE(*och_p, sizeof (struct obd_client_handle));
                        *och_p = NULL; /* OBD_FREE writes some magic there */
                        (*och_usecount)--;
                }
		mutex_unlock(&lli->lli_och_mutex);

out_openerr:
		if (lli->lli_opendir_key == fd)
			ll_deauthorize_statahead(inode, fd);
		if (fd != NULL)
			ll_file_data_put(fd);
        } else {
                ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_OPEN, 1);
        }

	if (it && it_disposition(it, DISP_ENQ_OPEN_REF)) {
		ptlrpc_req_finished(it->it_request);
		it_clear_disposition(it, DISP_ENQ_OPEN_REF);
	}

        return rc;
}

static int ll_md_blocking_lease_ast(struct ldlm_lock *lock,
			struct ldlm_lock_desc *desc, void *data, int flag)
{
	int rc;
	struct lustre_handle lockh;
	ENTRY;

	switch (flag) {
	case LDLM_CB_BLOCKING:
		ldlm_lock2handle(lock, &lockh);
		rc = ldlm_cli_cancel(&lockh, LCF_ASYNC);
		if (rc < 0) {
			CDEBUG(D_INODE, "ldlm_cli_cancel: %d\n", rc);
			RETURN(rc);
		}
		break;
	case LDLM_CB_CANCELING:
		/* do nothing */
		break;
	}
	RETURN(0);
}

/**
 * When setting a lease on a file, we take ownership of the lli_mds_*_och
 * and save it as fd->fd_och so as to force client to reopen the file even
 * if it has an open lock in cache already.
 */
static int ll_lease_och_acquire(struct inode *inode, struct file *file,
				struct lustre_handle *old_handle)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct obd_client_handle **och_p;
	__u64 *och_usecount;
	int rc = 0;
	ENTRY;

	/* Get the openhandle of the file */
	mutex_lock(&lli->lli_och_mutex);
	if (fd->fd_lease_och != NULL)
		GOTO(out_unlock, rc = -EBUSY);

	if (fd->fd_och == NULL) {
		if (file->f_mode & FMODE_WRITE) {
			LASSERT(lli->lli_mds_write_och != NULL);
			och_p = &lli->lli_mds_write_och;
			och_usecount = &lli->lli_open_fd_write_count;
		} else {
			LASSERT(lli->lli_mds_read_och != NULL);
			och_p = &lli->lli_mds_read_och;
			och_usecount = &lli->lli_open_fd_read_count;
		}

		if (*och_usecount > 1)
			GOTO(out_unlock, rc = -EBUSY);

		fd->fd_och = *och_p;
		*och_usecount = 0;
		*och_p = NULL;
	}

	*old_handle = fd->fd_och->och_fh;

	EXIT;
out_unlock:
	mutex_unlock(&lli->lli_och_mutex);
	return rc;
}

/**
 * Release ownership on lli_mds_*_och when putting back a file lease.
 */
static int ll_lease_och_release(struct inode *inode, struct file *file)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct obd_client_handle **och_p;
	struct obd_client_handle *old_och = NULL;
	__u64 *och_usecount;
	int rc = 0;
	ENTRY;

	mutex_lock(&lli->lli_och_mutex);
	if (file->f_mode & FMODE_WRITE) {
		och_p = &lli->lli_mds_write_och;
		och_usecount = &lli->lli_open_fd_write_count;
	} else {
		och_p = &lli->lli_mds_read_och;
		och_usecount = &lli->lli_open_fd_read_count;
	}

	/* The file may have been open by another process (broken lease) so
	 * *och_p is not NULL. In this case we should simply increase usecount
	 * and close fd_och.
	 */
	if (*och_p != NULL) {
		old_och = fd->fd_och;
		(*och_usecount)++;
	} else {
		*och_p = fd->fd_och;
		*och_usecount = 1;
	}
	fd->fd_och = NULL;
	mutex_unlock(&lli->lli_och_mutex);

	if (old_och != NULL)
		rc = ll_close_inode_openhandle(inode, old_och, 0, NULL);

	RETURN(rc);
}

/**
 * Acquire a lease and open the file.
 */
static struct obd_client_handle *
ll_lease_open(struct inode *inode, struct file *file, fmode_t fmode,
	      __u64 open_flags)
{
	struct lookup_intent it = { .it_op = IT_OPEN };
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	struct lustre_handle old_handle = { 0 };
	struct obd_client_handle *och = NULL;
	int rc;
	int rc2;
	ENTRY;

	if (fmode != FMODE_WRITE && fmode != FMODE_READ)
		RETURN(ERR_PTR(-EINVAL));

	if (file != NULL) {
		if (!(fmode & file->f_mode) || (file->f_mode & FMODE_EXEC))
			RETURN(ERR_PTR(-EPERM));

		rc = ll_lease_och_acquire(inode, file, &old_handle);
		if (rc)
			RETURN(ERR_PTR(rc));
	}

	OBD_ALLOC_PTR(och);
	if (och == NULL)
		RETURN(ERR_PTR(-ENOMEM));

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL, 0, 0,
					LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		GOTO(out, rc = PTR_ERR(op_data));

	/* To tell the MDT this openhandle is from the same owner */
	op_data->op_handle = old_handle;

	it.it_flags = fmode | open_flags;
	it.it_flags |= MDS_OPEN_LOCK | MDS_OPEN_BY_FID | MDS_OPEN_LEASE;
	rc = md_intent_lock(sbi->ll_md_exp, op_data, &it, &req,
			    &ll_md_blocking_lease_ast,
	/* LDLM_FL_NO_LRU: To not put the lease lock into LRU list, otherwise
	 * it can be cancelled which may mislead applications that the lease is
	 * broken;
	 * LDLM_FL_EXCL: Set this flag so that it won't be matched by normal
	 * open in ll_md_blocking_ast(). Otherwise as ll_md_blocking_lease_ast
	 * doesn't deal with openhandle, so normal openhandle will be leaked. */
			    LDLM_FL_NO_LRU | LDLM_FL_EXCL);
	ll_finish_md_op_data(op_data);
	ptlrpc_req_finished(req);
	if (rc < 0)
		GOTO(out_release_it, rc);

	if (it_disposition(&it, DISP_LOOKUP_NEG))
		GOTO(out_release_it, rc = -ENOENT);

	rc = it_open_error(DISP_OPEN_OPEN, &it);
	if (rc)
		GOTO(out_release_it, rc);

	LASSERT(it_disposition(&it, DISP_ENQ_OPEN_REF));
	ll_och_fill(sbi->ll_md_exp, &it, och);

	if (!it_disposition(&it, DISP_OPEN_LEASE)) /* old server? */
		GOTO(out_close, rc = -EOPNOTSUPP);

	/* already get lease, handle lease lock */
	ll_set_lock_data(sbi->ll_md_exp, inode, &it, NULL);
	if (it.it_lock_mode == 0 ||
	    it.it_lock_bits != MDS_INODELOCK_OPEN) {
		/* open lock must return for lease */
		CERROR(DFID "lease granted but no open lock, %d/%llu.\n",
			PFID(ll_inode2fid(inode)), it.it_lock_mode,
			it.it_lock_bits);
		GOTO(out_close, rc = -EPROTO);
	}

	ll_intent_release(&it);
	RETURN(och);

out_close:
	/* Cancel open lock */
	if (it.it_lock_mode != 0) {
		ldlm_lock_decref_and_cancel(&och->och_lease_handle,
					    it.it_lock_mode);
		it.it_lock_mode = 0;
		och->och_lease_handle.cookie = 0ULL;
	}
	rc2 = ll_close_inode_openhandle(inode, och, 0, NULL);
	if (rc2 < 0)
		CERROR("%s: error closing file "DFID": %d\n",
		       ll_get_fsname(inode->i_sb, NULL, 0),
		       PFID(&ll_i2info(inode)->lli_fid), rc2);
	och = NULL; /* och has been freed in ll_close_inode_openhandle() */
out_release_it:
	ll_intent_release(&it);
out:
	if (och != NULL)
		OBD_FREE_PTR(och);
	RETURN(ERR_PTR(rc));
}

/**
 * Check whether a layout swap can be done between two inodes.
 *
 * \param[in] inode1  First inode to check
 * \param[in] inode2  Second inode to check
 *
 * \retval 0 on success, layout swap can be performed between both inodes
 * \retval negative error code if requirements are not met
 */
static int ll_check_swap_layouts_validity(struct inode *inode1,
					  struct inode *inode2)
{
	if (!S_ISREG(inode1->i_mode) || !S_ISREG(inode2->i_mode))
		return -EINVAL;

	if (inode_permission(inode1, MAY_WRITE) ||
	    inode_permission(inode2, MAY_WRITE))
		return -EPERM;

	if (inode1->i_sb != inode2->i_sb)
		return -EXDEV;

	return 0;
}

static int ll_swap_layouts_close(struct obd_client_handle *och,
				 struct inode *inode, struct inode *inode2)
{
	const struct lu_fid	*fid1 = ll_inode2fid(inode);
	const struct lu_fid	*fid2;
	int			 rc;
	ENTRY;

	CDEBUG(D_INODE, "%s: biased close of file "DFID"\n",
	       ll_get_fsname(inode->i_sb, NULL, 0), PFID(fid1));

	rc = ll_check_swap_layouts_validity(inode, inode2);
	if (rc < 0)
		GOTO(out_free_och, rc);

	/* We now know that inode2 is a lustre inode */
	fid2 = ll_inode2fid(inode2);

	rc = lu_fid_cmp(fid1, fid2);
	if (rc == 0)
		GOTO(out_free_och, rc = -EINVAL);

	/* Close the file and swap layouts between inode & inode2.
	 * NB: lease lock handle is released in mdc_close_layout_swap_pack()
	 * because we still need it to pack l_remote_handle to MDT. */
	rc = ll_close_inode_openhandle(inode, och, MDS_CLOSE_LAYOUT_SWAP,
				       inode2);

	och = NULL; /* freed in ll_close_inode_openhandle() */

out_free_och:
	if (och != NULL)
		OBD_FREE_PTR(och);

	RETURN(rc);
}

/**
 * Release lease and close the file.
 * It will check if the lease has ever broken.
 */
static int ll_lease_close(struct obd_client_handle *och, struct inode *inode,
			  bool *lease_broken)
{
	struct ldlm_lock *lock;
	bool cancelled = true;
	int rc;
	ENTRY;

	lock = ldlm_handle2lock(&och->och_lease_handle);
	if (lock != NULL) {
		lock_res_and_lock(lock);
		cancelled = ldlm_is_cancel(lock);
		unlock_res_and_lock(lock);
		LDLM_LOCK_PUT(lock);
	}

	CDEBUG(D_INODE, "lease for "DFID" broken? %d\n",
	       PFID(&ll_i2info(inode)->lli_fid), cancelled);

	if (!cancelled)
		ldlm_cli_cancel(&och->och_lease_handle, 0);

	if (lease_broken != NULL)
		*lease_broken = cancelled;

	rc = ll_close_inode_openhandle(inode, och, 0, NULL);
	RETURN(rc);
}

int ll_merge_attr(const struct lu_env *env, struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct cl_attr *attr = vvp_env_thread_attr(env);
	s64 atime;
	s64 mtime;
	s64 ctime;
	int rc = 0;

	ENTRY;

	ll_inode_size_lock(inode);

	/* Merge timestamps the most recently obtained from MDS with
	 * timestamps obtained from OSTs.
	 *
	 * Do not overwrite atime of inode because it may be refreshed
	 * by file_accessed() function. If the read was served by cache
	 * data, there is no RPC to be sent so that atime may not be
	 * transferred to OSTs at all. MDT only updates atime at close time
	 * if it's at least 'mdd.*.atime_diff' older.
	 * All in all, the atime in Lustre does not strictly comply with
	 * POSIX. Solving this problem needs to send an RPC to MDT for each
	 * read, this will hurt performance. */
	if (LTIME_S(inode->i_atime) < lli->lli_atime || lli->lli_update_atime) {
		LTIME_S(inode->i_atime) = lli->lli_atime;
		lli->lli_update_atime = 0;
	}
	LTIME_S(inode->i_mtime) = lli->lli_mtime;
	LTIME_S(inode->i_ctime) = lli->lli_ctime;

	atime = LTIME_S(inode->i_atime);
	mtime = LTIME_S(inode->i_mtime);
	ctime = LTIME_S(inode->i_ctime);

	cl_object_attr_lock(obj);
	rc = cl_object_attr_get(env, obj, attr);
	cl_object_attr_unlock(obj);

	if (rc != 0)
		GOTO(out_size_unlock, rc);

	if (atime < attr->cat_atime)
		atime = attr->cat_atime;

	if (ctime < attr->cat_ctime)
		ctime = attr->cat_ctime;

	if (mtime < attr->cat_mtime)
		mtime = attr->cat_mtime;

	CDEBUG(D_VFSTRACE, DFID" updating i_size %llu\n",
	       PFID(&lli->lli_fid), attr->cat_size);

	i_size_write(inode, attr->cat_size);
	inode->i_blocks = attr->cat_blocks;

	LTIME_S(inode->i_atime) = atime;
	LTIME_S(inode->i_mtime) = mtime;
	LTIME_S(inode->i_ctime) = ctime;

out_size_unlock:
	ll_inode_size_unlock(inode);

	RETURN(rc);
}

static bool file_is_noatime(const struct file *file)
{
	const struct vfsmount *mnt = file->f_path.mnt;
	const struct inode *inode = file_inode((struct file *)file);

	/* Adapted from file_accessed() and touch_atime().*/
	if (file->f_flags & O_NOATIME)
		return true;

	if (inode->i_flags & S_NOATIME)
		return true;

	if (IS_NOATIME(inode))
		return true;

	if (mnt->mnt_flags & (MNT_NOATIME | MNT_READONLY))
		return true;

	if ((mnt->mnt_flags & MNT_NODIRATIME) && S_ISDIR(inode->i_mode))
		return true;

	if ((inode->i_sb->s_flags & MS_NODIRATIME) && S_ISDIR(inode->i_mode))
		return true;

	return false;
}

static int ll_file_io_ptask(struct cfs_ptask *ptask);

static void ll_io_init(struct cl_io *io, struct file *file, enum cl_io_type iot)
{
	struct inode *inode = file_inode(file);

	memset(&io->u.ci_rw.rw_iter, 0, sizeof(io->u.ci_rw.rw_iter));
	init_sync_kiocb(&io->u.ci_rw.rw_iocb, file);
	io->u.ci_rw.rw_file = file;
	io->u.ci_rw.rw_ptask = ll_file_io_ptask;
	io->u.ci_rw.rw_nonblock = !!(file->f_flags & O_NONBLOCK);
	if (iot == CIT_WRITE) {
		io->u.ci_rw.rw_append = !!(file->f_flags & O_APPEND);
		io->u.ci_rw.rw_sync   = !!(file->f_flags & O_SYNC ||
					   file->f_flags & O_DIRECT ||
					   IS_SYNC(inode));
	}
	io->ci_obj = ll_i2info(inode)->lli_clob;
	io->ci_lockreq = CILR_MAYBE;
	if (ll_file_nolock(file)) {
		io->ci_lockreq = CILR_NEVER;
		io->ci_no_srvlock = 1;
	} else if (file->f_flags & O_APPEND) {
		io->ci_lockreq = CILR_MANDATORY;
	}
	io->ci_noatime = file_is_noatime(file);
	if (ll_i2sbi(inode)->ll_flags & LL_SBI_PIO)
		io->ci_pio = !io->u.ci_rw.rw_append;
	else
		io->ci_pio = 0;
}

static int ll_file_io_ptask(struct cfs_ptask *ptask)
{
	struct cl_io_pt *pt = ptask->pt_cbdata;
	struct file *file = pt->cip_file;
	struct lu_env *env;
	struct cl_io *io;
	loff_t pos = pt->cip_pos;
	int rc;
	__u16 refcheck;
	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	CDEBUG(D_VFSTRACE, "%s: %s range: [%llu, %llu)\n",
		file_dentry(file)->d_name.name,
		pt->cip_iot == CIT_READ ? "read" : "write",
		pos, pos + pt->cip_count);

restart:
	io = vvp_env_thread_io(env);
	ll_io_init(io, file, pt->cip_iot);
	io->u.ci_rw.rw_iter = pt->cip_iter;
	io->u.ci_rw.rw_iocb = pt->cip_iocb;
	io->ci_pio = 0; /* It's already in parallel task */

	rc = cl_io_rw_init(env, io, pt->cip_iot, pos,
			   pt->cip_count - pt->cip_result);
	if (!rc) {
		struct vvp_io *vio = vvp_env_io(env);

		vio->vui_io_subtype = IO_NORMAL;
		vio->vui_fd = LUSTRE_FPRIVATE(file);

		ll_cl_add(file, env, io, LCC_RW);
		rc = cl_io_loop(env, io);
		ll_cl_remove(file, env);
	} else {
		/* cl_io_rw_init() handled IO */
		rc = io->ci_result;
	}

	if (OBD_FAIL_CHECK_RESET(OBD_FAIL_LLITE_PTASK_IO_FAIL, 0)) {
		if (io->ci_nob > 0)
			io->ci_nob /= 2;
		rc = -EIO;
	}

	if (io->ci_nob > 0) {
		pt->cip_result += io->ci_nob;
		iov_iter_advance(&pt->cip_iter, io->ci_nob);
		pos += io->ci_nob;
		pt->cip_iocb.ki_pos = pos;
#ifdef HAVE_KIOCB_KI_LEFT
		pt->cip_iocb.ki_left = pt->cip_count - pt->cip_result;
#elif defined(HAVE_KI_NBYTES)
		pt->cip_iocb.ki_nbytes = pt->cip_count - pt->cip_result;
#endif
	}

	cl_io_fini(env, io);

	if ((rc == 0 || rc == -ENODATA) &&
	    pt->cip_result < pt->cip_count &&
	    io->ci_need_restart) {
		CDEBUG(D_VFSTRACE,
			"%s: restart %s range: [%llu, %llu) ret: %zd, rc: %d\n",
			file_dentry(file)->d_name.name,
			pt->cip_iot == CIT_READ ? "read" : "write",
			pos, pos + pt->cip_count - pt->cip_result,
			pt->cip_result, rc);
		goto restart;
	}

	CDEBUG(D_VFSTRACE, "%s: %s ret: %zd, rc: %d\n",
		file_dentry(file)->d_name.name,
		pt->cip_iot == CIT_READ ? "read" : "write",
		pt->cip_result, rc);

	cl_env_put(env, &refcheck);
	RETURN(pt->cip_result > 0 ? 0 : rc);
}

static ssize_t
ll_file_io_generic(const struct lu_env *env, struct vvp_io_args *args,
		   struct file *file, enum cl_io_type iot,
		   loff_t *ppos, size_t count)
{
	struct range_lock	range;
	struct vvp_io		*vio = vvp_env_io(env);
	struct inode		*inode = file_inode(file);
	struct ll_inode_info	*lli = ll_i2info(inode);
	struct ll_file_data	*fd  = LUSTRE_FPRIVATE(file);
	struct cl_io		*io;
	loff_t			pos = *ppos;
	ssize_t			result = 0;
	int			rc = 0;

	ENTRY;

	CDEBUG(D_VFSTRACE, "%s: %s range: [%llu, %llu)\n",
		file_dentry(file)->d_name.name,
		iot == CIT_READ ? "read" : "write", pos, pos + count);

restart:
	io = vvp_env_thread_io(env);
	ll_io_init(io, file, iot);
	if (args->via_io_subtype == IO_NORMAL) {
		io->u.ci_rw.rw_iter = *args->u.normal.via_iter;
		io->u.ci_rw.rw_iocb = *args->u.normal.via_iocb;
	} else {
		io->ci_pio = 0;
	}

	if (cl_io_rw_init(env, io, iot, pos, count) == 0) {
		bool range_locked = false;

		if (file->f_flags & O_APPEND)
			range_lock_init(&range, 0, LUSTRE_EOF);
		else
			range_lock_init(&range, pos, pos + count - 1);

		vio->vui_fd  = LUSTRE_FPRIVATE(file);
		vio->vui_io_subtype = args->via_io_subtype;

		switch (vio->vui_io_subtype) {
		case IO_NORMAL:
			/* Direct IO reads must also take range lock,
			 * or multiple reads will try to work on the same pages
			 * See LU-6227 for details. */
			if (((iot == CIT_WRITE) ||
			    (iot == CIT_READ && (file->f_flags & O_DIRECT))) &&
			    !(vio->vui_fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
				CDEBUG(D_VFSTRACE, "Range lock "RL_FMT"\n",
				       RL_PARA(&range));
				rc = range_lock(&lli->lli_write_tree, &range);
				if (rc < 0)
					GOTO(out, rc);

				range_locked = true;
			}
			break;
		case IO_SPLICE:
			vio->u.splice.vui_pipe = args->u.splice.via_pipe;
			vio->u.splice.vui_flags = args->u.splice.via_flags;
			break;
		default:
			CERROR("unknown IO subtype %u\n", vio->vui_io_subtype);
			LBUG();
		}

		ll_cl_add(file, env, io, LCC_RW);
		if (io->ci_pio && iot == CIT_WRITE && !IS_NOSEC(inode) &&
		    !lli->lli_inode_locked) {
			inode_lock(inode);
			lli->lli_inode_locked = 1;
		}
		rc = cl_io_loop(env, io);
		if (lli->lli_inode_locked) {
			lli->lli_inode_locked = 0;
			inode_unlock(inode);
		}
		ll_cl_remove(file, env);

		if (range_locked) {
			CDEBUG(D_VFSTRACE, "Range unlock "RL_FMT"\n",
			       RL_PARA(&range));
			range_unlock(&lli->lli_write_tree, &range);
		}
	} else {
		/* cl_io_rw_init() handled IO */
		rc = io->ci_result;
	}

	if (io->ci_nob > 0) {
		result += io->ci_nob;
		count  -= io->ci_nob;

		if (args->via_io_subtype == IO_NORMAL) {
			iov_iter_advance(args->u.normal.via_iter, io->ci_nob);

			/* CLIO is too complicated. See LU-11069. */
			if (cl_io_is_append(io))
				pos = io->u.ci_rw.rw_iocb.ki_pos;
			else
				pos += io->ci_nob;

			args->u.normal.via_iocb->ki_pos = pos;
#ifdef HAVE_KIOCB_KI_LEFT
			args->u.normal.via_iocb->ki_left = count;
#elif defined(HAVE_KI_NBYTES)
			args->u.normal.via_iocb->ki_nbytes = count;
#endif
		} else {
			/* for splice */
			pos = io->u.ci_rw.rw_range.cir_pos;
		}
	}
out:
	cl_io_fini(env, io);

	if ((rc == 0 || rc == -ENODATA) && count > 0 && io->ci_need_restart) {
		CDEBUG(D_VFSTRACE,
			"%s: restart %s range: [%llu, %llu) ret: %zd, rc: %d\n",
			file_dentry(file)->d_name.name,
			iot == CIT_READ ? "read" : "write",
			pos, pos + count, result, rc);
		goto restart;
	}

	if (iot == CIT_READ) {
		if (result > 0)
			ll_stats_ops_tally(ll_i2sbi(inode),
					   LPROC_LL_READ_BYTES, result);
	} else if (iot == CIT_WRITE) {
		if (result > 0) {
			ll_stats_ops_tally(ll_i2sbi(inode),
					   LPROC_LL_WRITE_BYTES, result);
			fd->fd_write_failed = false;
		} else if (result == 0 && rc == 0) {
			rc = io->ci_result;
			if (rc < 0)
				fd->fd_write_failed = true;
			else
				fd->fd_write_failed = false;
		} else if (rc != -ERESTARTSYS) {
			fd->fd_write_failed = true;
		}
	}

	CDEBUG(D_VFSTRACE, "%s: %s *ppos: %llu, pos: %llu, ret: %zd, rc: %d\n",
		file_dentry(file)->d_name.name,
		iot == CIT_READ ? "read" : "write", *ppos, pos, result, rc);

	*ppos = pos;

	RETURN(result > 0 ? result : rc);
}

/**
 * The purpose of fast read is to overcome per I/O overhead and improve IOPS
 * especially for small I/O.
 *
 * To serve a read request, CLIO has to create and initialize a cl_io and
 * then request DLM lock. This has turned out to have siginificant overhead
 * and affects the performance of small I/O dramatically.
 *
 * It's not necessary to create a cl_io for each I/O. Under the help of read
 * ahead, most of the pages being read are already in memory cache and we can
 * read those pages directly because if the pages exist, the corresponding DLM
 * lock must exist so that page content must be valid.
 *
 * In fast read implementation, the llite speculatively finds and reads pages
 * in memory cache. There are three scenarios for fast read:
 *   - If the page exists and is uptodate, kernel VM will provide the data and
 *     CLIO won't be intervened;
 *   - If the page was brought into memory by read ahead, it will be exported
 *     and read ahead parameters will be updated;
 *   - Otherwise the page is not in memory, we can't do fast read. Therefore,
 *     it will go back and invoke normal read, i.e., a cl_io will be created
 *     and DLM lock will be requested.
 *
 * POSIX compliance: posix standard states that read is intended to be atomic.
 * Lustre read implementation is in line with Linux kernel read implementation
 * and neither of them complies with POSIX standard in this matter. Fast read
 * doesn't make the situation worse on single node but it may interleave write
 * results from multiple nodes due to short read handling in ll_file_aio_read().
 *
 * \param env - lu_env
 * \param iocb - kiocb from kernel
 * \param iter - user space buffers where the data will be copied
 *
 * \retval - number of bytes have been read, or error code if error occurred.
 */
static ssize_t
ll_do_fast_read(const struct lu_env *env, struct kiocb *iocb,
		struct iov_iter *iter)
{
	ssize_t result;

	if (!ll_sbi_has_fast_read(ll_i2sbi(file_inode(iocb->ki_filp))))
		return 0;

	/* NB: we can't do direct IO for fast read because it will need a lock
	 * to make IO engine happy. */
	if (iocb->ki_filp->f_flags & O_DIRECT)
		return 0;

	ll_cl_add(iocb->ki_filp, env, NULL, LCC_RW);
	result = generic_file_read_iter(iocb, iter);
	ll_cl_remove(iocb->ki_filp, env);

	/* If the first page is not in cache, generic_file_aio_read() will be
	 * returned with -ENODATA.
	 * See corresponding code in ll_readpage(). */
	if (result == -ENODATA)
		result = 0;

	if (result > 0)
		ll_stats_ops_tally(ll_i2sbi(file_inode(iocb->ki_filp)),
				LPROC_LL_READ_BYTES, result);

	return result;
}

/*
 * Read from a file (through the page cache).
 */
static ssize_t ll_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct lu_env *env;
	struct vvp_io_args *args;
	ssize_t result;
	ssize_t rc2;
	__u16 refcheck;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	result = ll_do_fast_read(env, iocb, to);
	if (result < 0 || iov_iter_count(to) == 0)
		GOTO(out, result);

	args = ll_env_args(env, IO_NORMAL);
	args->u.normal.via_iter = to;
	args->u.normal.via_iocb = iocb;

	rc2 = ll_file_io_generic(env, args, iocb->ki_filp, CIT_READ,
				 &iocb->ki_pos, iov_iter_count(to));
	if (rc2 > 0)
		result += rc2;
	else if (result == 0)
		result = rc2;

out:
	cl_env_put(env, &refcheck);
	return result;
}

/*
 * Write to a file (through the page cache).
 */
static ssize_t ll_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct vvp_io_args *args;
	struct lu_env *env;
	ssize_t result;
	__u16 refcheck;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		return PTR_ERR(env);

	args = ll_env_args(env, IO_NORMAL);
	args->u.normal.via_iter = from;
	args->u.normal.via_iocb = iocb;

	result = ll_file_io_generic(env, args, iocb->ki_filp, CIT_WRITE,
				    &iocb->ki_pos, iov_iter_count(from));
	cl_env_put(env, &refcheck);
	return result;
}

#ifndef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
/*
 * XXX: exact copy from kernel code (__generic_file_aio_write_nolock)
 */
static int ll_file_get_iov_count(const struct iovec *iov,
				 unsigned long *nr_segs, size_t *count)
{
	size_t cnt = 0;
	unsigned long seg;

	for (seg = 0; seg < *nr_segs; seg++) {
		const struct iovec *iv = &iov[seg];

		/*
		 * If any segment has a negative length, or the cumulative
		 * length ever wraps negative then return -EINVAL.
		 */
		cnt += iv->iov_len;
		if (unlikely((ssize_t)(cnt|iv->iov_len) < 0))
			return -EINVAL;
		if (access_ok(VERIFY_READ, iv->iov_base, iv->iov_len))
			continue;
		if (seg == 0)
			return -EFAULT;
		*nr_segs = seg;
		cnt -= iv->iov_len;	/* This segment is no good */
		break;
	}
	*count = cnt;
	return 0;
}

static ssize_t ll_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
				unsigned long nr_segs, loff_t pos)
{
	struct iov_iter	to;
	size_t iov_count;
	ssize_t result;
	ENTRY;

	result = ll_file_get_iov_count(iov, &nr_segs, &iov_count);
	if (result)
		RETURN(result);

# ifdef HAVE_IOV_ITER_INIT_DIRECTION
	iov_iter_init(&to, READ, iov, nr_segs, iov_count);
# else /* !HAVE_IOV_ITER_INIT_DIRECTION */
	iov_iter_init(&to, iov, nr_segs, iov_count, 0);
# endif /* HAVE_IOV_ITER_INIT_DIRECTION */

	result = ll_file_read_iter(iocb, &to);

	RETURN(result);
}

static ssize_t ll_file_read(struct file *file, char __user *buf, size_t count,
			    loff_t *ppos)
{
	struct lu_env *env;
	struct iovec   iov = { .iov_base = buf, .iov_len = count };
	struct kiocb  *kiocb;
	ssize_t        result;
	__u16          refcheck;
	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	kiocb = &ll_env_info(env)->lti_kiocb;
        init_sync_kiocb(kiocb, file);
        kiocb->ki_pos = *ppos;
#ifdef HAVE_KIOCB_KI_LEFT
	kiocb->ki_left = count;
#elif defined(HAVE_KI_NBYTES)
	kiocb->ki_nbytes = count;
#endif

	result = ll_file_aio_read(kiocb, &iov, 1, kiocb->ki_pos);
	*ppos = kiocb->ki_pos;

	cl_env_put(env, &refcheck);
	RETURN(result);
}

/*
 * Write to a file (through the page cache).
 * AIO stuff
 */
static ssize_t ll_file_aio_write(struct kiocb *iocb, const struct iovec *iov,
				 unsigned long nr_segs, loff_t pos)
{
	struct iov_iter from;
	size_t iov_count;
	ssize_t result;
	ENTRY;

	result = ll_file_get_iov_count(iov, &nr_segs, &iov_count);
	if (result)
		RETURN(result);

# ifdef HAVE_IOV_ITER_INIT_DIRECTION
	iov_iter_init(&from, WRITE, iov, nr_segs, iov_count);
# else /* !HAVE_IOV_ITER_INIT_DIRECTION */
	iov_iter_init(&from, iov, nr_segs, iov_count, 0);
# endif /* HAVE_IOV_ITER_INIT_DIRECTION */

	result = ll_file_write_iter(iocb, &from);

	RETURN(result);
}

static ssize_t ll_file_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct lu_env *env;
	struct iovec   iov = { .iov_base = (void __user *)buf,
			       .iov_len = count };
        struct kiocb  *kiocb;
        ssize_t        result;
	__u16          refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

	kiocb = &ll_env_info(env)->lti_kiocb;
        init_sync_kiocb(kiocb, file);
        kiocb->ki_pos = *ppos;
#ifdef HAVE_KIOCB_KI_LEFT
	kiocb->ki_left = count;
#elif defined(HAVE_KI_NBYTES)
	kiocb->ki_nbytes = count;
#endif

	result = ll_file_aio_write(kiocb, &iov, 1, kiocb->ki_pos);
	*ppos = kiocb->ki_pos;

	cl_env_put(env, &refcheck);
	RETURN(result);
}
#endif /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */

/*
 * Send file content (through pagecache) somewhere with helper
 */
static ssize_t ll_file_splice_read(struct file *in_file, loff_t *ppos,
                                   struct pipe_inode_info *pipe, size_t count,
                                   unsigned int flags)
{
        struct lu_env      *env;
        struct vvp_io_args *args;
        ssize_t             result;
	__u16               refcheck;
        ENTRY;

        env = cl_env_get(&refcheck);
        if (IS_ERR(env))
                RETURN(PTR_ERR(env));

	args = ll_env_args(env, IO_SPLICE);
        args->u.splice.via_pipe = pipe;
        args->u.splice.via_flags = flags;

        result = ll_file_io_generic(env, args, in_file, CIT_READ, ppos, count);
        cl_env_put(env, &refcheck);
        RETURN(result);
}

int ll_lov_setstripe_ea_info(struct inode *inode, struct dentry *dentry,
			     __u64 flags, struct lov_user_md *lum, int lum_size)
{
	struct lookup_intent oit = {
		.it_op = IT_OPEN,
		.it_flags = flags | MDS_OPEN_BY_FID,
	};
	int rc;
	ENTRY;

	ll_inode_size_lock(inode);
	rc = ll_intent_file_open(dentry, lum, lum_size, &oit);
	if (rc < 0)
		GOTO(out_unlock, rc);

	ll_release_openhandle(dentry, &oit);

out_unlock:
	ll_inode_size_unlock(inode);
	ll_intent_release(&oit);

	RETURN(rc);
}

int ll_lov_getstripe_ea_info(struct inode *inode, const char *filename,
                             struct lov_mds_md **lmmp, int *lmm_size,
                             struct ptlrpc_request **request)
{
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct mdt_body  *body;
        struct lov_mds_md *lmm = NULL;
        struct ptlrpc_request *req = NULL;
        struct md_op_data *op_data;
        int rc, lmmsize;

	rc = ll_get_default_mdsize(sbi, &lmmsize);
	if (rc)
		RETURN(rc);

        op_data = ll_prep_md_op_data(NULL, inode, NULL, filename,
                                     strlen(filename), lmmsize,
                                     LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

        op_data->op_valid = OBD_MD_FLEASIZE | OBD_MD_FLDIREA;
        rc = md_getattr_name(sbi->ll_md_exp, op_data, &req);
        ll_finish_md_op_data(op_data);
        if (rc < 0) {
                CDEBUG(D_INFO, "md_getattr_name failed "
                       "on %s: rc %d\n", filename, rc);
                GOTO(out, rc);
        }

        body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
        LASSERT(body != NULL); /* checked by mdc_getattr_name */

	lmmsize = body->mbo_eadatasize;

	if (!(body->mbo_valid & (OBD_MD_FLEASIZE | OBD_MD_FLDIREA)) ||
                        lmmsize == 0) {
                GOTO(out, rc = -ENODATA);
        }

        lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_MDT_MD, lmmsize);
        LASSERT(lmm != NULL);

	if (lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V1) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_V3) &&
	    lmm->lmm_magic != cpu_to_le32(LOV_MAGIC_COMP_V1))
		GOTO(out, rc = -EPROTO);

        /*
         * This is coming from the MDS, so is probably in
         * little endian.  We convert it to host endian before
         * passing it to userspace.
         */
        if (LOV_MAGIC != cpu_to_le32(LOV_MAGIC)) {
		int stripe_count;

		if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1) ||
		    lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
			stripe_count = le16_to_cpu(lmm->lmm_stripe_count);
			if (le32_to_cpu(lmm->lmm_pattern) &
			    LOV_PATTERN_F_RELEASED)
				stripe_count = 0;
		}

                /* if function called for directory - we should
                 * avoid swab not existent lsm objects */
                if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V1)) {
			lustre_swab_lov_user_md_v1(
					(struct lov_user_md_v1 *)lmm);
			if (S_ISREG(body->mbo_mode))
				lustre_swab_lov_user_md_objects(
				    ((struct lov_user_md_v1 *)lmm)->lmm_objects,
				    stripe_count);
		} else if (lmm->lmm_magic == cpu_to_le32(LOV_MAGIC_V3)) {
			lustre_swab_lov_user_md_v3(
					(struct lov_user_md_v3 *)lmm);
			if (S_ISREG(body->mbo_mode))
				lustre_swab_lov_user_md_objects(
				    ((struct lov_user_md_v3 *)lmm)->lmm_objects,
				    stripe_count);
		} else if (lmm->lmm_magic ==
			   cpu_to_le32(LOV_MAGIC_COMP_V1)) {
			lustre_swab_lov_comp_md_v1(
					(struct lov_comp_md_v1 *)lmm);
		}
	}

out:
	*lmmp = lmm;
	*lmm_size = lmmsize;
	*request = req;
	return rc;
}

static int ll_lov_setea(struct inode *inode, struct file *file,
			void __user *arg)
{
	__u64			 flags = MDS_OPEN_HAS_OBJS | FMODE_WRITE;
	struct lov_user_md	*lump;
	int			 lum_size = sizeof(struct lov_user_md) +
					    sizeof(struct lov_user_ost_data);
	int			 rc;
	ENTRY;

	if (!cfs_capable(CFS_CAP_SYS_ADMIN))
		RETURN(-EPERM);

	OBD_ALLOC_LARGE(lump, lum_size);
	if (lump == NULL)
                RETURN(-ENOMEM);

	if (copy_from_user(lump, arg, lum_size))
		GOTO(out_lump, rc = -EFAULT);

	rc = ll_lov_setstripe_ea_info(inode, file_dentry(file), flags, lump,
				      lum_size);
	cl_lov_delay_create_clear(&file->f_flags);

out_lump:
	OBD_FREE_LARGE(lump, lum_size);
	RETURN(rc);
}

static int ll_file_getstripe(struct inode *inode, void __user *lum, size_t size)
{
	struct lu_env	*env;
	__u16		refcheck;
	int		rc;
	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	rc = cl_object_getstripe(env, ll_i2info(inode)->lli_clob, lum, size);
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

static int ll_lov_setstripe(struct inode *inode, struct file *file,
			    void __user *arg)
{
	struct lov_user_md __user *lum = (struct lov_user_md __user *)arg;
	struct lov_user_md	  *klum;
	int			   lum_size, rc;
	__u64			   flags = FMODE_WRITE;
	ENTRY;

	rc = ll_copy_user_md(lum, &klum);
	if (rc < 0)
		RETURN(rc);

	lum_size = rc;
	rc = ll_lov_setstripe_ea_info(inode, file_dentry(file), flags, klum,
				      lum_size);
	if (!rc) {
		__u32 gen;

		rc = put_user(0, &lum->lmm_stripe_count);
		if (rc)
			GOTO(out, rc);

		rc = ll_layout_refresh(inode, &gen);
		if (rc)
			GOTO(out, rc);

		rc = ll_file_getstripe(inode, arg, lum_size);
	}
	cl_lov_delay_create_clear(&file->f_flags);

out:
	OBD_FREE(klum, lum_size);
	RETURN(rc);
}

static int
ll_get_grouplock(struct inode *inode, struct file *file, unsigned long arg)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_grouplock grouplock;
	int rc;
	ENTRY;

	if (arg == 0) {
		CWARN("group id for group lock must not be 0\n");
		RETURN(-EINVAL);
	}

        if (ll_file_nolock(file))
                RETURN(-EOPNOTSUPP);

	spin_lock(&lli->lli_lock);
	if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
		CWARN("group lock already existed with gid %lu\n",
		      fd->fd_grouplock.lg_gid);
		spin_unlock(&lli->lli_lock);
		RETURN(-EINVAL);
	}
	LASSERT(fd->fd_grouplock.lg_lock == NULL);
	spin_unlock(&lli->lli_lock);

	/**
	 * XXX: group lock needs to protect all OST objects while PFL
	 * can add new OST objects during the IO, so we'd instantiate
	 * all OST objects before getting its group lock.
	 */
	if (obj) {
		struct lu_env *env;
		__u16 refcheck;
		struct cl_layout cl = {
			.cl_is_composite = false,
		};

		env = cl_env_get(&refcheck);
		if (IS_ERR(env))
			RETURN(PTR_ERR(env));

		rc = cl_object_layout_get(env, obj, &cl);
		if (!rc && cl.cl_is_composite)
			rc = ll_layout_write_intent(inode, 0, OBD_OBJECT_EOF);

		cl_env_put(env, &refcheck);
		if (rc)
			RETURN(rc);
	}

	rc = cl_get_grouplock(ll_i2info(inode)->lli_clob,
			      arg, (file->f_flags & O_NONBLOCK), &grouplock);
	if (rc)
		RETURN(rc);

	spin_lock(&lli->lli_lock);
	if (fd->fd_flags & LL_FILE_GROUP_LOCKED) {
		spin_unlock(&lli->lli_lock);
		CERROR("another thread just won the race\n");
		cl_put_grouplock(&grouplock);
		RETURN(-EINVAL);
	}

	fd->fd_flags |= LL_FILE_GROUP_LOCKED;
	fd->fd_grouplock = grouplock;
	spin_unlock(&lli->lli_lock);

	CDEBUG(D_INFO, "group lock %lu obtained\n", arg);
	RETURN(0);
}

static int ll_put_grouplock(struct inode *inode, struct file *file,
			    unsigned long arg)
{
	struct ll_inode_info   *lli = ll_i2info(inode);
	struct ll_file_data    *fd = LUSTRE_FPRIVATE(file);
	struct ll_grouplock	grouplock;
	ENTRY;

	spin_lock(&lli->lli_lock);
	if (!(fd->fd_flags & LL_FILE_GROUP_LOCKED)) {
		spin_unlock(&lli->lli_lock);
                CWARN("no group lock held\n");
                RETURN(-EINVAL);
        }

	LASSERT(fd->fd_grouplock.lg_lock != NULL);

	if (fd->fd_grouplock.lg_gid != arg) {
		CWARN("group lock %lu doesn't match current id %lu\n",
		      arg, fd->fd_grouplock.lg_gid);
		spin_unlock(&lli->lli_lock);
		RETURN(-EINVAL);
	}

	grouplock = fd->fd_grouplock;
	memset(&fd->fd_grouplock, 0, sizeof(fd->fd_grouplock));
	fd->fd_flags &= ~LL_FILE_GROUP_LOCKED;
	spin_unlock(&lli->lli_lock);

	cl_put_grouplock(&grouplock);
	CDEBUG(D_INFO, "group lock %lu released\n", arg);
	RETURN(0);
}

/**
 * Close inode open handle
 *
 * \param dentry [in]     dentry which contains the inode
 * \param it     [in,out] intent which contains open info and result
 *
 * \retval 0     success
 * \retval <0    failure
 */
int ll_release_openhandle(struct dentry *dentry, struct lookup_intent *it)
{
        struct inode *inode = dentry->d_inode;
        struct obd_client_handle *och;
        int rc;
        ENTRY;

        LASSERT(inode);

        /* Root ? Do nothing. */
        if (dentry->d_inode->i_sb->s_root == dentry)
                RETURN(0);

        /* No open handle to close? Move away */
        if (!it_disposition(it, DISP_OPEN_OPEN))
                RETURN(0);

        LASSERT(it_open_error(DISP_OPEN_OPEN, it) == 0);

        OBD_ALLOC(och, sizeof(*och));
        if (!och)
                GOTO(out, rc = -ENOMEM);

	ll_och_fill(ll_i2sbi(inode)->ll_md_exp, it, och);

	rc = ll_close_inode_openhandle(inode, och, 0, NULL);
out:
	/* this one is in place of ll_file_open */
	if (it_disposition(it, DISP_ENQ_OPEN_REF)) {
		ptlrpc_req_finished(it->it_request);
		it_clear_disposition(it, DISP_ENQ_OPEN_REF);
	}
	RETURN(rc);
}

/**
 * Get size for inode for which FIEMAP mapping is requested.
 * Make the FIEMAP get_info call and returns the result.
 * \param fiemap	kernel buffer to hold extens
 * \param num_bytes	kernel buffer size
 */
static int ll_do_fiemap(struct inode *inode, struct fiemap *fiemap,
			size_t num_bytes)
{
	struct lu_env			*env;
	__u16				refcheck;
	int				rc = 0;
	struct ll_fiemap_info_key	fmkey = { .lfik_name = KEY_FIEMAP, };
	ENTRY;

	/* Checks for fiemap flags */
	if (fiemap->fm_flags & ~LUSTRE_FIEMAP_FLAGS_COMPAT) {
		fiemap->fm_flags &= ~LUSTRE_FIEMAP_FLAGS_COMPAT;
		return -EBADR;
	}

	/* Check for FIEMAP_FLAG_SYNC */
	if (fiemap->fm_flags & FIEMAP_FLAG_SYNC) {
		rc = filemap_fdatawrite(inode->i_mapping);
		if (rc)
			return rc;
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	if (i_size_read(inode) == 0) {
		rc = ll_glimpse_size(inode);
		if (rc)
			GOTO(out, rc);
	}

	fmkey.lfik_oa.o_valid = OBD_MD_FLID | OBD_MD_FLGROUP;
	obdo_from_inode(&fmkey.lfik_oa, inode, OBD_MD_FLSIZE);
	obdo_set_parent_fid(&fmkey.lfik_oa, &ll_i2info(inode)->lli_fid);

	/* If filesize is 0, then there would be no objects for mapping */
	if (fmkey.lfik_oa.o_size == 0) {
		fiemap->fm_mapped_extents = 0;
		GOTO(out, rc = 0);
	}

	fmkey.lfik_fiemap = *fiemap;

	rc = cl_object_fiemap(env, ll_i2info(inode)->lli_clob,
			      &fmkey, fiemap, &num_bytes);
out:
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

int ll_fid2path(struct inode *inode, void __user *arg)
{
	struct obd_export	*exp = ll_i2mdexp(inode);
	const struct getinfo_fid2path __user *gfin = arg;
	__u32			 pathlen;
	struct getinfo_fid2path	*gfout;
	size_t			 outsize;
	int			 rc;

	ENTRY;

	if (!cfs_capable(CFS_CAP_DAC_READ_SEARCH) &&
	    !(ll_i2sbi(inode)->ll_flags & LL_SBI_USER_FID2PATH))
		RETURN(-EPERM);

	/* Only need to get the buflen */
	if (get_user(pathlen, &gfin->gf_pathlen))
		RETURN(-EFAULT);

	if (pathlen > PATH_MAX)
		RETURN(-EINVAL);

	outsize = sizeof(*gfout) + pathlen;
	OBD_ALLOC(gfout, outsize);
	if (gfout == NULL)
		RETURN(-ENOMEM);

	if (copy_from_user(gfout, arg, sizeof(*gfout)))
		GOTO(gf_free, rc = -EFAULT);
	/* append root FID after gfout to let MDT know the root FID so that it
	 * can lookup the correct path, this is mainly for fileset.
	 * old server without fileset mount support will ignore this. */
	*gfout->gf_u.gf_root_fid = *ll_inode2fid(inode);

	/* Call mdc_iocontrol */
	rc = obd_iocontrol(OBD_IOC_FID2PATH, exp, outsize, gfout, NULL);
	if (rc != 0)
		GOTO(gf_free, rc);

	if (copy_to_user(arg, gfout, outsize))
		rc = -EFAULT;

gf_free:
	OBD_FREE(gfout, outsize);
	RETURN(rc);
}

/*
 * Read the data_version for inode.
 *
 * This value is computed using stripe object version on OST.
 * Version is computed using server side locking.
 *
 * @param flags if do sync on the OST side;
 *		0: no sync
 *		LL_DV_RD_FLUSH: flush dirty pages, LCK_PR on OSTs
 *		LL_DV_WR_FLUSH: drop all caching pages, LCK_PW on OSTs
 */
int ll_data_version(struct inode *inode, __u64 *data_version, int flags)
{
	struct cl_object *obj = ll_i2info(inode)->lli_clob;
	struct lu_env *env;
	struct cl_io *io;
	__u16  refcheck;
	int result;

	ENTRY;

	/* If no file object initialized, we consider its version is 0. */
	if (obj == NULL) {
		*data_version = 0;
		RETURN(0);
	}

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_thread_io(env);
	io->ci_obj = obj;
	io->u.ci_data_version.dv_data_version = 0;
	io->u.ci_data_version.dv_flags = flags;

restart:
	if (cl_io_init(env, io, CIT_DATA_VERSION, io->ci_obj) == 0)
		result = cl_io_loop(env, io);
	else
		result = io->ci_result;

	*data_version = io->u.ci_data_version.dv_data_version;

	cl_io_fini(env, io);

	if (unlikely(io->ci_need_restart))
		goto restart;

	cl_env_put(env, &refcheck);

	RETURN(result);
}

/*
 * Trigger a HSM release request for the provided inode.
 */
int ll_hsm_release(struct inode *inode)
{
	struct lu_env *env;
	struct obd_client_handle *och = NULL;
	__u64 data_version = 0;
	int rc;
	__u16 refcheck;
	ENTRY;

	CDEBUG(D_INODE, "%s: Releasing file "DFID".\n",
	       ll_get_fsname(inode->i_sb, NULL, 0),
	       PFID(&ll_i2info(inode)->lli_fid));

	och = ll_lease_open(inode, NULL, FMODE_WRITE, MDS_OPEN_RELEASE);
	if (IS_ERR(och))
		GOTO(out, rc = PTR_ERR(och));

	/* Grab latest data_version and [am]time values */
	rc = ll_data_version(inode, &data_version, LL_DV_WR_FLUSH);
	if (rc != 0)
		GOTO(out, rc);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		GOTO(out, rc = PTR_ERR(env));

	ll_merge_attr(env, inode);
	cl_env_put(env, &refcheck);

	/* Release the file.
	 * NB: lease lock handle is released in mdc_hsm_release_pack() because
	 * we still need it to pack l_remote_handle to MDT. */
	rc = ll_close_inode_openhandle(inode, och, MDS_HSM_RELEASE,
				       &data_version);
	och = NULL;

	EXIT;
out:
	if (och != NULL && !IS_ERR(och)) /* close the file */
		ll_lease_close(och, inode, NULL);

	return rc;
}

struct ll_swap_stack {
	__u64			 dv1;
	__u64			 dv2;
	struct inode		*inode1;
	struct inode		*inode2;
	bool			 check_dv1;
	bool			 check_dv2;
};

static int ll_swap_layouts(struct file *file1, struct file *file2,
			   struct lustre_swap_layouts *lsl)
{
	struct mdc_swap_layouts	 msl;
	struct md_op_data	*op_data;
	__u32			 gid;
	__u64			 dv;
	struct ll_swap_stack	*llss = NULL;
	int			 rc;

	OBD_ALLOC_PTR(llss);
	if (llss == NULL)
		RETURN(-ENOMEM);

	llss->inode1 = file_inode(file1);
	llss->inode2 = file_inode(file2);

	rc = ll_check_swap_layouts_validity(llss->inode1, llss->inode2);
	if (rc < 0)
		GOTO(free, rc);

	/* we use 2 bool because it is easier to swap than 2 bits */
	if (lsl->sl_flags & SWAP_LAYOUTS_CHECK_DV1)
		llss->check_dv1 = true;

	if (lsl->sl_flags & SWAP_LAYOUTS_CHECK_DV2)
		llss->check_dv2 = true;

	/* we cannot use lsl->sl_dvX directly because we may swap them */
	llss->dv1 = lsl->sl_dv1;
	llss->dv2 = lsl->sl_dv2;

	rc = lu_fid_cmp(ll_inode2fid(llss->inode1), ll_inode2fid(llss->inode2));
	if (rc == 0) /* same file, done! */
		GOTO(free, rc);

	if (rc < 0) { /* sequentialize it */
		swap(llss->inode1, llss->inode2);
		swap(file1, file2);
		swap(llss->dv1, llss->dv2);
		swap(llss->check_dv1, llss->check_dv2);
	}

	gid = lsl->sl_gid;
	if (gid != 0) { /* application asks to flush dirty cache */
		rc = ll_get_grouplock(llss->inode1, file1, gid);
		if (rc < 0)
			GOTO(free, rc);

		rc = ll_get_grouplock(llss->inode2, file2, gid);
		if (rc < 0) {
			ll_put_grouplock(llss->inode1, file1, gid);
			GOTO(free, rc);
		}
	}

	/* ultimate check, before swaping the layouts we check if
	 * dataversion has changed (if requested) */
	if (llss->check_dv1) {
		rc = ll_data_version(llss->inode1, &dv, 0);
		if (rc)
			GOTO(putgl, rc);
		if (dv != llss->dv1)
			GOTO(putgl, rc = -EAGAIN);
	}

	if (llss->check_dv2) {
		rc = ll_data_version(llss->inode2, &dv, 0);
		if (rc)
			GOTO(putgl, rc);
		if (dv != llss->dv2)
			GOTO(putgl, rc = -EAGAIN);
	}

	/* struct md_op_data is used to send the swap args to the mdt
	 * only flags is missing, so we use struct mdc_swap_layouts
	 * through the md_op_data->op_data */
	/* flags from user space have to be converted before they are send to
	 * server, no flag is sent today, they are only used on the client */
	msl.msl_flags = 0;
	rc = -ENOMEM;
	op_data = ll_prep_md_op_data(NULL, llss->inode1, llss->inode2, NULL, 0,
				     0, LUSTRE_OPC_ANY, &msl);
	if (IS_ERR(op_data))
		GOTO(free, rc = PTR_ERR(op_data));

	rc = obd_iocontrol(LL_IOC_LOV_SWAP_LAYOUTS, ll_i2mdexp(llss->inode1),
			   sizeof(*op_data), op_data, NULL);
	ll_finish_md_op_data(op_data);

	if (rc < 0)
		GOTO(putgl, rc);

putgl:
	if (gid != 0) {
		ll_put_grouplock(llss->inode2, file2, gid);
		ll_put_grouplock(llss->inode1, file1, gid);
	}

free:
	if (llss != NULL)
		OBD_FREE_PTR(llss);

	RETURN(rc);
}

int ll_hsm_state_set(struct inode *inode, struct hsm_state_set *hss)
{
	struct md_op_data	*op_data;
	int			 rc;
	ENTRY;

	/* Detect out-of range masks */
	if ((hss->hss_setmask | hss->hss_clearmask) & ~HSM_FLAGS_MASK)
		RETURN(-EINVAL);

	/* Non-root users are forbidden to set or clear flags which are
	 * NOT defined in HSM_USER_MASK. */
	if (((hss->hss_setmask | hss->hss_clearmask) & ~HSM_USER_MASK) &&
	    !cfs_capable(CFS_CAP_SYS_ADMIN))
		RETURN(-EPERM);

	/* Detect out-of range archive id */
	if ((hss->hss_valid & HSS_ARCHIVE_ID) &&
	    (hss->hss_archive_id > LL_HSM_MAX_ARCHIVE))
		RETURN(-EINVAL);

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, hss);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	rc = obd_iocontrol(LL_IOC_HSM_STATE_SET, ll_i2mdexp(inode),
			   sizeof(*op_data), op_data, NULL);

	ll_finish_md_op_data(op_data);

	RETURN(rc);
}

static int ll_hsm_import(struct inode *inode, struct file *file,
			 struct hsm_user_import *hui)
{
	struct hsm_state_set	*hss = NULL;
	struct iattr		*attr = NULL;
	int			 rc;
	ENTRY;

	if (!S_ISREG(inode->i_mode))
		RETURN(-EINVAL);

	/* set HSM flags */
	OBD_ALLOC_PTR(hss);
	if (hss == NULL)
		GOTO(out, rc = -ENOMEM);

	hss->hss_valid = HSS_SETMASK | HSS_ARCHIVE_ID;
	hss->hss_archive_id = hui->hui_archive_id;
	hss->hss_setmask = HS_ARCHIVED | HS_EXISTS | HS_RELEASED;
	rc = ll_hsm_state_set(inode, hss);
	if (rc != 0)
		GOTO(out, rc);

	OBD_ALLOC_PTR(attr);
	if (attr == NULL)
		GOTO(out, rc = -ENOMEM);

	attr->ia_mode = hui->hui_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
	attr->ia_mode |= S_IFREG;
	attr->ia_uid = make_kuid(&init_user_ns, hui->hui_uid);
	attr->ia_gid = make_kgid(&init_user_ns, hui->hui_gid);
	attr->ia_size = hui->hui_size;
	attr->ia_mtime.tv_sec = hui->hui_mtime;
	attr->ia_mtime.tv_nsec = hui->hui_mtime_ns;
	attr->ia_atime.tv_sec = hui->hui_atime;
	attr->ia_atime.tv_nsec = hui->hui_atime_ns;

	attr->ia_valid = ATTR_SIZE | ATTR_MODE | ATTR_FORCE |
			 ATTR_UID | ATTR_GID |
			 ATTR_MTIME | ATTR_MTIME_SET |
			 ATTR_ATIME | ATTR_ATIME_SET;

	inode_lock(inode);

	rc = ll_setattr_raw(file_dentry(file), attr, true);
	if (rc == -ENODATA)
		rc = 0;

	inode_unlock(inode);

out:
	if (hss != NULL)
		OBD_FREE_PTR(hss);

	if (attr != NULL)
		OBD_FREE_PTR(attr);

	RETURN(rc);
}

static inline long ll_lease_type_from_fmode(fmode_t fmode)
{
	return ((fmode & FMODE_READ) ? LL_LEASE_RDLCK : 0) |
	       ((fmode & FMODE_WRITE) ? LL_LEASE_WRLCK : 0);
}

static int ll_file_futimes_3(struct file *file, const struct ll_futimes_3 *lfu)
{
	struct inode *inode = file_inode(file);
	struct iattr ia = {
		.ia_valid = ATTR_ATIME | ATTR_ATIME_SET |
			    ATTR_MTIME | ATTR_MTIME_SET |
			    ATTR_CTIME | ATTR_CTIME_SET,
		.ia_atime = {
			.tv_sec = lfu->lfu_atime_sec,
			.tv_nsec = lfu->lfu_atime_nsec,
		},
		.ia_mtime = {
			.tv_sec = lfu->lfu_mtime_sec,
			.tv_nsec = lfu->lfu_mtime_nsec,
		},
		.ia_ctime = {
			.tv_sec = lfu->lfu_ctime_sec,
			.tv_nsec = lfu->lfu_ctime_nsec,
		},
	};
	int rc;
	ENTRY;

	if (!capable(CAP_SYS_ADMIN))
		RETURN(-EPERM);

	if (!S_ISREG(inode->i_mode))
		RETURN(-EINVAL);

	inode_lock(inode);
	rc = ll_setattr_raw(file_dentry(file), &ia, false);
	inode_unlock(inode);

	RETURN(rc);
}

/*
 * Give file access advices
 *
 * The ladvise interface is similar to Linux fadvise() system call, except it
 * forwards the advices directly from Lustre client to server. The server side
 * codes will apply appropriate read-ahead and caching techniques for the
 * corresponding files.
 *
 * A typical workload for ladvise is e.g. a bunch of different clients are
 * doing small random reads of a file, so prefetching pages into OSS cache
 * with big linear reads before the random IO is a net benefit. Fetching
 * all that data into each client cache with fadvise() may not be, due to
 * much more data being sent to the client.
 */
static int ll_ladvise(struct inode *inode, struct file *file, __u64 flags,
		      struct llapi_lu_ladvise *ladvise)
{
	struct lu_env *env;
	struct cl_io *io;
	struct cl_ladvise_io *lio;
	int rc;
	__u16 refcheck;
	ENTRY;

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;

	/* initialize parameters for ladvise */
	lio = &io->u.ci_ladvise;
	lio->li_start = ladvise->lla_start;
	lio->li_end = ladvise->lla_end;
	lio->li_fid = ll_inode2fid(inode);
	lio->li_advice = ladvise->lla_advice;
	lio->li_flags = flags;

	if (cl_io_init(env, io, CIT_LADVISE, io->ci_obj) == 0)
		rc = cl_io_loop(env, io);
	else
		rc = io->ci_result;

	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);
	RETURN(rc);
}

int ll_ioctl_fsgetxattr(struct inode *inode, unsigned int cmd,
			unsigned long arg)
{
	struct fsxattr fsxattr;

	if (copy_from_user(&fsxattr,
			   (const struct fsxattr __user *)arg,
			   sizeof(fsxattr)))
		RETURN(-EFAULT);

	fsxattr.fsx_xflags = ll_inode_to_ext_flags(inode->i_flags);
	fsxattr.fsx_projid = ll_i2info(inode)->lli_projid;
	if (copy_to_user((struct fsxattr __user *)arg,
			 &fsxattr, sizeof(fsxattr)))
		RETURN(-EFAULT);

	RETURN(0);
}

int ll_ioctl_fssetxattr(struct inode *inode, unsigned int cmd,
			unsigned long arg)
{

	struct md_op_data *op_data;
	struct ptlrpc_request *req = NULL;
	int rc = 0;
	struct fsxattr fsxattr;
	struct cl_object *obj;

	/* only root could change project ID */
	if (!cfs_capable(CFS_CAP_SYS_ADMIN))
		RETURN(-EPERM);

	op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	if (copy_from_user(&fsxattr,
			   (const struct fsxattr __user *)arg,
			   sizeof(fsxattr)))
		GOTO(out_fsxattr1, rc = -EFAULT);

	op_data->op_attr_flags = fsxattr.fsx_xflags;
	op_data->op_projid = fsxattr.fsx_projid;
	op_data->op_attr.ia_valid |= (MDS_ATTR_PROJID | ATTR_ATTR_FLAG);
	rc = md_setattr(ll_i2sbi(inode)->ll_md_exp, op_data, NULL,
			0, &req);
	ptlrpc_req_finished(req);

	obj = ll_i2info(inode)->lli_clob;
	if (obj) {
		struct iattr *attr;

		inode->i_flags = ll_ext_to_inode_flags(fsxattr.fsx_xflags);
		OBD_ALLOC_PTR(attr);
		if (attr == NULL)
			GOTO(out_fsxattr1, rc = -ENOMEM);
		attr->ia_valid = ATTR_ATTR_FLAG;
		rc = cl_setattr_ost(obj, attr, fsxattr.fsx_xflags);

		OBD_FREE_PTR(attr);
	}
out_fsxattr1:
	ll_finish_md_op_data(op_data);
	RETURN(rc);


}

static long
ll_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode		*inode = file_inode(file);
	struct ll_file_data	*fd = LUSTRE_FPRIVATE(file);
	int			 flags, rc;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), cmd=%x\n",
	       PFID(ll_inode2fid(inode)), inode, cmd);
        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_IOCTL, 1);

        /* asm-ppc{,64} declares TCGETS, et. al. as type 't' not 'T' */
        if (_IOC_TYPE(cmd) == 'T' || _IOC_TYPE(cmd) == 't') /* tty ioctls */
                RETURN(-ENOTTY);

        switch(cmd) {
        case LL_IOC_GETFLAGS:
                /* Get the current value of the file flags */
		return put_user(fd->fd_flags, (int __user *)arg);
        case LL_IOC_SETFLAGS:
        case LL_IOC_CLRFLAGS:
                /* Set or clear specific file flags */
                /* XXX This probably needs checks to ensure the flags are
                 *     not abused, and to handle any flag side effects.
                 */
		if (get_user(flags, (int __user *) arg))
                        RETURN(-EFAULT);

                if (cmd == LL_IOC_SETFLAGS) {
                        if ((flags & LL_FILE_IGNORE_LOCK) &&
                            !(file->f_flags & O_DIRECT)) {
                                CERROR("%s: unable to disable locking on "
                                       "non-O_DIRECT file\n", current->comm);
                                RETURN(-EINVAL);
                        }

                        fd->fd_flags |= flags;
                } else {
                        fd->fd_flags &= ~flags;
                }
                RETURN(0);
	case LL_IOC_LOV_SETSTRIPE:
	case LL_IOC_LOV_SETSTRIPE_NEW:
		RETURN(ll_lov_setstripe(inode, file, (void __user *)arg));
	case LL_IOC_LOV_SETEA:
		RETURN(ll_lov_setea(inode, file, (void __user *)arg));
	case LL_IOC_LOV_SWAP_LAYOUTS: {
		struct file *file2;
		struct lustre_swap_layouts lsl;

		if (copy_from_user(&lsl, (char __user *)arg,
				   sizeof(struct lustre_swap_layouts)))
			RETURN(-EFAULT);

		if ((file->f_flags & O_ACCMODE) == O_RDONLY)
			RETURN(-EPERM);

		file2 = fget(lsl.sl_fd);
		if (file2 == NULL)
			RETURN(-EBADF);

		/* O_WRONLY or O_RDWR */
		if ((file2->f_flags & O_ACCMODE) == O_RDONLY)
			GOTO(out, rc = -EPERM);

		if (lsl.sl_flags & SWAP_LAYOUTS_CLOSE) {
			struct inode			*inode2;
			struct ll_inode_info		*lli;
			struct obd_client_handle	*och = NULL;

			if (lsl.sl_flags != SWAP_LAYOUTS_CLOSE)
				GOTO(out, rc = -EINVAL);

			lli = ll_i2info(inode);
			mutex_lock(&lli->lli_och_mutex);
			if (fd->fd_lease_och != NULL) {
				och = fd->fd_lease_och;
				fd->fd_lease_och = NULL;
			}
			mutex_unlock(&lli->lli_och_mutex);
			if (och == NULL)
				GOTO(out, rc = -ENOLCK);
			inode2 = file_inode(file2);
			rc = ll_swap_layouts_close(och, inode, inode2);
		} else {
			rc = ll_swap_layouts(file, file2, &lsl);
		}
out:
		fput(file2);
		RETURN(rc);
	}
	case LL_IOC_LOV_GETSTRIPE:
	case LL_IOC_LOV_GETSTRIPE_NEW:
		RETURN(ll_file_getstripe(inode, (void __user *)arg, 0));
        case FSFILT_IOC_GETFLAGS:
        case FSFILT_IOC_SETFLAGS:
                RETURN(ll_iocontrol(inode, file, cmd, arg));
        case FSFILT_IOC_GETVERSION_OLD:
        case FSFILT_IOC_GETVERSION:
		RETURN(put_user(inode->i_generation, (int __user *)arg));
        case LL_IOC_GROUP_LOCK:
                RETURN(ll_get_grouplock(inode, file, arg));
        case LL_IOC_GROUP_UNLOCK:
                RETURN(ll_put_grouplock(inode, file, arg));
        case IOC_OBD_STATFS:
		RETURN(ll_obd_statfs(inode, (void __user *)arg));

        /* We need to special case any other ioctls we want to handle,
         * to send them to the MDS/OST as appropriate and to properly
         * network encode the arg field.
        case FSFILT_IOC_SETVERSION_OLD:
        case FSFILT_IOC_SETVERSION:
        */
	case LL_IOC_FLUSHCTX:
		RETURN(ll_flush_ctx(inode));
	case LL_IOC_PATH2FID: {
		if (copy_to_user((void __user *)arg, ll_inode2fid(inode),
				 sizeof(struct lu_fid)))
			RETURN(-EFAULT);

		RETURN(0);
	}
	case LL_IOC_GETPARENT:
		RETURN(ll_getparent(file, (struct getparent __user *)arg));

	case OBD_IOC_FID2PATH:
		RETURN(ll_fid2path(inode, (void __user *)arg));
	case LL_IOC_DATA_VERSION: {
		struct ioc_data_version	idv;
		int rc;

		if (copy_from_user(&idv, (char __user *)arg, sizeof(idv)))
			RETURN(-EFAULT);

		idv.idv_flags &= LL_DV_RD_FLUSH | LL_DV_WR_FLUSH;
		rc = ll_data_version(inode, &idv.idv_version, idv.idv_flags);

		if (rc == 0 &&
		    copy_to_user((char __user *)arg, &idv, sizeof(idv)))
			RETURN(-EFAULT);

		RETURN(rc);
	}

        case LL_IOC_GET_MDTIDX: {
                int mdtidx;

                mdtidx = ll_get_mdt_idx(inode);
                if (mdtidx < 0)
                        RETURN(mdtidx);

		if (put_user((int)mdtidx, (int __user *)arg))
                        RETURN(-EFAULT);

                RETURN(0);
        }
	case OBD_IOC_GETDTNAME:
	case OBD_IOC_GETMDNAME:
		RETURN(ll_get_obd_name(inode, cmd, arg));
	case LL_IOC_HSM_STATE_GET: {
		struct md_op_data	*op_data;
		struct hsm_user_state	*hus;
		int			 rc;

		OBD_ALLOC_PTR(hus);
		if (hus == NULL)
			RETURN(-ENOMEM);

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, hus);
		if (IS_ERR(op_data)) {
			OBD_FREE_PTR(hus);
			RETURN(PTR_ERR(op_data));
		}

		rc = obd_iocontrol(cmd, ll_i2mdexp(inode), sizeof(*op_data),
				   op_data, NULL);

		if (copy_to_user((void __user *)arg, hus, sizeof(*hus)))
			rc = -EFAULT;

		ll_finish_md_op_data(op_data);
		OBD_FREE_PTR(hus);
		RETURN(rc);
	}
	case LL_IOC_HSM_STATE_SET: {
		struct hsm_state_set	*hss;
		int			 rc;

		OBD_ALLOC_PTR(hss);
		if (hss == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(hss, (char __user *)arg, sizeof(*hss))) {
			OBD_FREE_PTR(hss);
			RETURN(-EFAULT);
		}

		rc = ll_hsm_state_set(inode, hss);

		OBD_FREE_PTR(hss);
		RETURN(rc);
	}
	case LL_IOC_HSM_ACTION: {
		struct md_op_data		*op_data;
		struct hsm_current_action	*hca;
		int				 rc;

		OBD_ALLOC_PTR(hca);
		if (hca == NULL)
			RETURN(-ENOMEM);

		op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
					     LUSTRE_OPC_ANY, hca);
		if (IS_ERR(op_data)) {
			OBD_FREE_PTR(hca);
			RETURN(PTR_ERR(op_data));
		}

		rc = obd_iocontrol(cmd, ll_i2mdexp(inode), sizeof(*op_data),
				   op_data, NULL);

		if (copy_to_user((char __user *)arg, hca, sizeof(*hca)))
			rc = -EFAULT;

		ll_finish_md_op_data(op_data);
		OBD_FREE_PTR(hca);
		RETURN(rc);
	}
	case LL_IOC_SET_LEASE: {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct obd_client_handle *och = NULL;
		bool lease_broken;
		fmode_t fmode;

		switch (arg) {
		case LL_LEASE_WRLCK:
			if (!(file->f_mode & FMODE_WRITE))
				RETURN(-EPERM);
			fmode = FMODE_WRITE;
			break;
		case LL_LEASE_RDLCK:
			if (!(file->f_mode & FMODE_READ))
				RETURN(-EPERM);
			fmode = FMODE_READ;
			break;
		case LL_LEASE_UNLCK:
			mutex_lock(&lli->lli_och_mutex);
			if (fd->fd_lease_och != NULL) {
				och = fd->fd_lease_och;
				fd->fd_lease_och = NULL;
			}
			mutex_unlock(&lli->lli_och_mutex);

			if (och == NULL)
				RETURN(-ENOLCK);

			fmode = och->och_flags;
			rc = ll_lease_close(och, inode, &lease_broken);
			if (rc < 0)
				RETURN(rc);

			rc = ll_lease_och_release(inode, file);
			if (rc < 0)
				RETURN(rc);

			if (lease_broken)
				fmode = 0;

			RETURN(ll_lease_type_from_fmode(fmode));
		default:
			RETURN(-EINVAL);
		}

		CDEBUG(D_INODE, "Set lease with mode %u\n", fmode);

		/* apply for lease */
		och = ll_lease_open(inode, file, fmode, 0);
		if (IS_ERR(och))
			RETURN(PTR_ERR(och));

		rc = 0;
		mutex_lock(&lli->lli_och_mutex);
		if (fd->fd_lease_och == NULL) {
			fd->fd_lease_och = och;
			och = NULL;
		}
		mutex_unlock(&lli->lli_och_mutex);
		if (och != NULL) {
			/* impossible now that only excl is supported for now */
			ll_lease_close(och, inode, &lease_broken);
			rc = -EBUSY;
		}
		RETURN(rc);
	}
	case LL_IOC_GET_LEASE: {
		struct ll_inode_info *lli = ll_i2info(inode);
		struct ldlm_lock *lock = NULL;
		fmode_t fmode = 0;

		mutex_lock(&lli->lli_och_mutex);
		if (fd->fd_lease_och != NULL) {
			struct obd_client_handle *och = fd->fd_lease_och;

			lock = ldlm_handle2lock(&och->och_lease_handle);
			if (lock != NULL) {
				lock_res_and_lock(lock);
				if (!ldlm_is_cancel(lock))
					fmode = och->och_flags;

				unlock_res_and_lock(lock);
				LDLM_LOCK_PUT(lock);
			}
		}
		mutex_unlock(&lli->lli_och_mutex);

		RETURN(ll_lease_type_from_fmode(fmode));
	}
	case LL_IOC_HSM_IMPORT: {
		struct hsm_user_import *hui;

		OBD_ALLOC_PTR(hui);
		if (hui == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(hui, (void __user *)arg, sizeof(*hui))) {
			OBD_FREE_PTR(hui);
			RETURN(-EFAULT);
		}

		rc = ll_hsm_import(inode, file, hui);

		OBD_FREE_PTR(hui);
		RETURN(rc);
	}
	case LL_IOC_FUTIMES_3: {
		struct ll_futimes_3 lfu;

		if (copy_from_user(&lfu,
				   (const struct ll_futimes_3 __user *)arg,
				   sizeof(lfu)))
			RETURN(-EFAULT);

		RETURN(ll_file_futimes_3(file, &lfu));
	}
	case LL_IOC_LADVISE: {
		struct llapi_ladvise_hdr *ladvise_hdr;
		int i;
		int num_advise;
		int alloc_size = sizeof(*ladvise_hdr);

		rc = 0;
		OBD_ALLOC_PTR(ladvise_hdr);
		if (ladvise_hdr == NULL)
			RETURN(-ENOMEM);

		if (copy_from_user(ladvise_hdr,
				   (const struct llapi_ladvise_hdr __user *)arg,
				   alloc_size))
			GOTO(out_ladvise, rc = -EFAULT);

		if (ladvise_hdr->lah_magic != LADVISE_MAGIC ||
		    ladvise_hdr->lah_count < 1)
			GOTO(out_ladvise, rc = -EINVAL);

		num_advise = ladvise_hdr->lah_count;
		if (num_advise >= LAH_COUNT_MAX)
			GOTO(out_ladvise, rc = -EFBIG);

		OBD_FREE_PTR(ladvise_hdr);
		alloc_size = offsetof(typeof(*ladvise_hdr),
				      lah_advise[num_advise]);
		OBD_ALLOC(ladvise_hdr, alloc_size);
		if (ladvise_hdr == NULL)
			RETURN(-ENOMEM);

		/*
		 * TODO: submit multiple advices to one server in a single RPC
		 */
		if (copy_from_user(ladvise_hdr,
				   (const struct llapi_ladvise_hdr __user *)arg,
				   alloc_size))
			GOTO(out_ladvise, rc = -EFAULT);

		for (i = 0; i < num_advise; i++) {
			rc = ll_ladvise(inode, file, ladvise_hdr->lah_flags,
					&ladvise_hdr->lah_advise[i]);
			if (rc)
				break;
		}

out_ladvise:
		OBD_FREE(ladvise_hdr, alloc_size);
		RETURN(rc);
	}
	case LL_IOC_FSGETXATTR:
		RETURN(ll_ioctl_fsgetxattr(inode, cmd, arg));
	case LL_IOC_FSSETXATTR:
		RETURN(ll_ioctl_fssetxattr(inode, cmd, arg));
	case BLKSSZGET:
		RETURN(put_user(PAGE_SIZE, (int __user *)arg));
	default:
		RETURN(obd_iocontrol(cmd, ll_i2dtexp(inode), 0, NULL,
				     (void __user *)arg));
	}
}

#ifndef HAVE_FILE_LLSEEK_SIZE
static inline loff_t
llseek_execute(struct file *file, loff_t offset, loff_t maxsize)
{
	if (offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET))
		return -EINVAL;
	if (offset > maxsize)
		return -EINVAL;

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}
	return offset;
}

static loff_t
generic_file_llseek_size(struct file *file, loff_t offset, int origin,
                loff_t maxsize, loff_t eof)
{
	struct inode *inode = file_inode(file);

	switch (origin) {
	case SEEK_END:
		offset += eof;
		break;
	case SEEK_CUR:
		/*
		 * Here we special-case the lseek(fd, 0, SEEK_CUR)
		 * position-querying operation.  Avoid rewriting the "same"
		 * f_pos value back to the file because a concurrent read(),
		 * write() or lseek() might have altered it
		 */
		if (offset == 0)
			return file->f_pos;
		/*
		 * f_lock protects against read/modify/write race with other
		 * SEEK_CURs. Note that parallel writes and reads behave
		 * like SEEK_SET.
		 */
		inode_lock(inode);
		offset = llseek_execute(file, file->f_pos + offset, maxsize);
		inode_unlock(inode);
		return offset;
	case SEEK_DATA:
		/*
		 * In the generic case the entire file is data, so as long as
		 * offset isn't at the end of the file then the offset is data.
		 */
		if (offset >= eof)
			return -ENXIO;
		break;
	case SEEK_HOLE:
		/*
		 * There is a virtual hole at the end of the file, so as long as
		 * offset isn't i_size or larger, return i_size.
		 */
		if (offset >= eof)
			return -ENXIO;
		offset = eof;
		break;
	}

	return llseek_execute(file, offset, maxsize);
}
#endif

static loff_t ll_file_seek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file_inode(file);
	loff_t retval, eof = 0;

	ENTRY;
	retval = offset + ((origin == SEEK_END) ? i_size_read(inode) :
			   (origin == SEEK_CUR) ? file->f_pos : 0);
	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), to=%llu=%#llx(%d)\n",
	       PFID(ll_inode2fid(inode)), inode, retval, retval,
	       origin);
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_LLSEEK, 1);

	if (origin == SEEK_END || origin == SEEK_HOLE || origin == SEEK_DATA) {
		retval = ll_glimpse_size(inode);
		if (retval != 0)
			RETURN(retval);
		eof = i_size_read(inode);
	}

	retval = ll_generic_file_llseek_size(file, offset, origin,
					  ll_file_maxbytes(inode), eof);
	RETURN(retval);
}

static int ll_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	int rc, err;

	LASSERT(!S_ISDIR(inode->i_mode));

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping. */
	rc = lli->lli_async_rc;
	lli->lli_async_rc = 0;
	if (lli->lli_clob != NULL) {
		err = lov_read_and_clear_async_rc(lli->lli_clob);
		if (rc == 0)
			rc = err;
	}

	/* The application has been told write failure already.
	 * Do not report failure again. */
	if (fd->fd_write_failed)
		return 0;
	return rc ? -EIO : 0;
}

/**
 * Called to make sure a portion of file has been written out.
 * if @mode is not CL_FSYNC_LOCAL, it will send OST_SYNC RPCs to OST.
 *
 * Return how many pages have been written.
 */
int cl_sync_file_range(struct inode *inode, loff_t start, loff_t end,
		       enum cl_fsync_mode mode, int ignore_layout)
{
	struct lu_env *env;
	struct cl_io *io;
	struct cl_fsync_io *fio;
	int result;
	__u16 refcheck;
	ENTRY;

	if (mode != CL_FSYNC_NONE && mode != CL_FSYNC_LOCAL &&
	    mode != CL_FSYNC_DISCARD && mode != CL_FSYNC_ALL)
		RETURN(-EINVAL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	io = vvp_env_thread_io(env);
	io->ci_obj = ll_i2info(inode)->lli_clob;
	io->ci_ignore_layout = ignore_layout;

	/* initialize parameters for sync */
	fio = &io->u.ci_fsync;
	fio->fi_start = start;
	fio->fi_end = end;
	fio->fi_fid = ll_inode2fid(inode);
	fio->fi_mode = mode;
	fio->fi_nr_written = 0;

	if (cl_io_init(env, io, CIT_FSYNC, io->ci_obj) == 0)
		result = cl_io_loop(env, io);
	else
		result = io->ci_result;
	if (result == 0)
		result = fio->fi_nr_written;
	cl_io_fini(env, io);
	cl_env_put(env, &refcheck);

	RETURN(result);
}

/*
 * When dentry is provided (the 'else' case), file_dentry() may be
 * null and dentry must be used directly rather than pulled from
 * file_dentry() as is done otherwise.
 */

#ifdef HAVE_FILE_FSYNC_4ARGS
int ll_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct dentry *dentry = file_dentry(file);
	bool lock_inode;
#elif defined(HAVE_FILE_FSYNC_2ARGS)
int ll_fsync(struct file *file, int datasync)
{
	struct dentry *dentry = file_dentry(file);
	loff_t start = 0;
	loff_t end = LLONG_MAX;
#else
int ll_fsync(struct file *file, struct dentry *dentry, int datasync)
{
	loff_t start = 0;
	loff_t end = LLONG_MAX;
#endif
	struct inode *inode = dentry->d_inode;
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ptlrpc_request *req;
	int rc, err;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p)\n",
	       PFID(ll_inode2fid(inode)), inode);
	ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FSYNC, 1);

#ifdef HAVE_FILE_FSYNC_4ARGS
	rc = filemap_write_and_wait_range(inode->i_mapping, start, end);
	lock_inode = !lli->lli_inode_locked;
	if (lock_inode)
		inode_lock(inode);
#else
	/* fsync's caller has already called _fdata{sync,write}, we want
	 * that IO to finish before calling the osc and mdc sync methods */
	rc = filemap_fdatawait(inode->i_mapping);
#endif

	/* catch async errors that were recorded back when async writeback
	 * failed for pages in this mapping. */
	if (!S_ISDIR(inode->i_mode)) {
		err = lli->lli_async_rc;
		lli->lli_async_rc = 0;
		if (rc == 0)
			rc = err;
		if (lli->lli_clob != NULL) {
			err = lov_read_and_clear_async_rc(lli->lli_clob);
			if (rc == 0)
				rc = err;
		}
	}

	err = md_fsync(ll_i2sbi(inode)->ll_md_exp, ll_inode2fid(inode), &req);
	if (!rc)
		rc = err;
	if (!err)
		ptlrpc_req_finished(req);

	if (S_ISREG(inode->i_mode)) {
		struct ll_file_data *fd = LUSTRE_FPRIVATE(file);

		err = cl_sync_file_range(inode, start, end, CL_FSYNC_ALL, 0);
		if (rc == 0 && err < 0)
			rc = err;
		if (rc < 0)
			fd->fd_write_failed = true;
		else
			fd->fd_write_failed = false;
	}

#ifdef HAVE_FILE_FSYNC_4ARGS
	if (lock_inode)
		inode_unlock(inode);
#endif
	RETURN(rc);
}

static int
ll_file_flock(struct file *file, int cmd, struct file_lock *file_lock)
{
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ldlm_enqueue_info einfo = {
		.ei_type	= LDLM_FLOCK,
		.ei_cb_cp	= ldlm_flock_completion_ast,
		.ei_cbdata	= file_lock,
	};
	struct md_op_data *op_data;
	struct lustre_handle lockh = { 0 };
	union ldlm_policy_data flock = { { 0 } };
	int fl_type = file_lock->fl_type;
	__u64 flags = 0;
	int rc;
	int rc2 = 0;
	ENTRY;

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID" file_lock=%p\n",
	       PFID(ll_inode2fid(inode)), file_lock);

        ll_stats_ops_tally(ll_i2sbi(inode), LPROC_LL_FLOCK, 1);

        if (file_lock->fl_flags & FL_FLOCK) {
                LASSERT((cmd == F_SETLKW) || (cmd == F_SETLK));
                /* flocks are whole-file locks */
                flock.l_flock.end = OFFSET_MAX;
                /* For flocks owner is determined by the local file desctiptor*/
                flock.l_flock.owner = (unsigned long)file_lock->fl_file;
        } else if (file_lock->fl_flags & FL_POSIX) {
                flock.l_flock.owner = (unsigned long)file_lock->fl_owner;
                flock.l_flock.start = file_lock->fl_start;
                flock.l_flock.end = file_lock->fl_end;
        } else {
                RETURN(-EINVAL);
        }
        flock.l_flock.pid = file_lock->fl_pid;

	/* Somewhat ugly workaround for svc lockd.
	 * lockd installs custom fl_lmops->lm_compare_owner that checks
	 * for the fl_owner to be the same (which it always is on local node
	 * I guess between lockd processes) and then compares pid.
	 * As such we assign pid to the owner field to make it all work,
	 * conflict with normal locks is unlikely since pid space and
	 * pointer space for current->files are not intersecting */
	if (file_lock->fl_lmops && file_lock->fl_lmops->lm_compare_owner)
		flock.l_flock.owner = (unsigned long)file_lock->fl_pid;

	switch (fl_type) {
        case F_RDLCK:
                einfo.ei_mode = LCK_PR;
                break;
        case F_UNLCK:
                /* An unlock request may or may not have any relation to
                 * existing locks so we may not be able to pass a lock handle
                 * via a normal ldlm_lock_cancel() request. The request may even
                 * unlock a byte range in the middle of an existing lock. In
                 * order to process an unlock request we need all of the same
                 * information that is given with a normal read or write record
                 * lock request. To avoid creating another ldlm unlock (cancel)
                 * message we'll treat a LCK_NL flock request as an unlock. */
                einfo.ei_mode = LCK_NL;
                break;
        case F_WRLCK:
                einfo.ei_mode = LCK_PW;
                break;
        default:
		CDEBUG(D_INFO, "Unknown fcntl lock type: %d\n", fl_type);
                RETURN (-ENOTSUPP);
        }

        switch (cmd) {
        case F_SETLKW:
#ifdef F_SETLKW64
        case F_SETLKW64:
#endif
                flags = 0;
                break;
        case F_SETLK:
#ifdef F_SETLK64
        case F_SETLK64:
#endif
                flags = LDLM_FL_BLOCK_NOWAIT;
                break;
        case F_GETLK:
#ifdef F_GETLK64
        case F_GETLK64:
#endif
                flags = LDLM_FL_TEST_LOCK;
                break;
        default:
                CERROR("unknown fcntl lock command: %d\n", cmd);
                RETURN (-EINVAL);
        }

	/* Save the old mode so that if the mode in the lock changes we
	 * can decrement the appropriate reader or writer refcount. */
	file_lock->fl_type = einfo.ei_mode;

        op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL, 0, 0,
                                     LUSTRE_OPC_ANY, NULL);
        if (IS_ERR(op_data))
                RETURN(PTR_ERR(op_data));

	CDEBUG(D_DLMTRACE, "inode="DFID", pid=%u, flags=%#llx, mode=%u, "
	       "start=%llu, end=%llu\n", PFID(ll_inode2fid(inode)),
	       flock.l_flock.pid, flags, einfo.ei_mode,
	       flock.l_flock.start, flock.l_flock.end);

	rc = md_enqueue(sbi->ll_md_exp, &einfo, &flock, op_data, &lockh,
			flags);

	/* Restore the file lock type if not TEST lock. */
	if (!(flags & LDLM_FL_TEST_LOCK))
		file_lock->fl_type = fl_type;

#ifdef HAVE_LOCKS_LOCK_FILE_WAIT
	if ((rc == 0 || file_lock->fl_type == F_UNLCK) &&
	    !(flags & LDLM_FL_TEST_LOCK))
		rc2  = locks_lock_file_wait(file, file_lock);
#else
        if ((file_lock->fl_flags & FL_FLOCK) &&
            (rc == 0 || file_lock->fl_type == F_UNLCK))
		rc2  = flock_lock_file_wait(file, file_lock);
        if ((file_lock->fl_flags & FL_POSIX) &&
            (rc == 0 || file_lock->fl_type == F_UNLCK) &&
            !(flags & LDLM_FL_TEST_LOCK))
		rc2  = posix_lock_file_wait(file, file_lock);
#endif /* HAVE_LOCKS_LOCK_FILE_WAIT */

	if (rc2 && file_lock->fl_type != F_UNLCK) {
		einfo.ei_mode = LCK_NL;
		md_enqueue(sbi->ll_md_exp, &einfo, &flock, op_data,
			   &lockh, flags);
		rc = rc2;
	}

	ll_finish_md_op_data(op_data);

        RETURN(rc);
}

int ll_get_fid_by_name(struct inode *parent, const char *name,
		       int namelen, struct lu_fid *fid,
		       struct inode **inode)
{
	struct md_op_data	*op_data = NULL;
	struct mdt_body		*body;
	struct ptlrpc_request	*req;
	int			rc;
	ENTRY;

	op_data = ll_prep_md_op_data(NULL, parent, NULL, name, namelen, 0,
				     LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_valid = OBD_MD_FLID | OBD_MD_FLTYPE;
	rc = md_getattr_name(ll_i2sbi(parent)->ll_md_exp, op_data, &req);
	ll_finish_md_op_data(op_data);
	if (rc < 0)
		RETURN(rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		GOTO(out_req, rc = -EFAULT);
	if (fid != NULL)
		*fid = body->mbo_fid1;

	if (inode != NULL)
		rc = ll_prep_inode(inode, req, parent->i_sb, NULL);
out_req:
	ptlrpc_req_finished(req);
	RETURN(rc);
}

int ll_migrate(struct inode *parent, struct file *file, int mdtidx,
	       const char *name, int namelen)
{
	struct dentry         *dchild = NULL;
	struct inode          *child_inode = NULL;
	struct md_op_data     *op_data;
	struct ptlrpc_request *request = NULL;
	struct obd_client_handle *och = NULL;
	struct qstr           qstr;
	struct mdt_body		*body;
	int                    rc;
	__u64			data_version = 0;
	ENTRY;

	CDEBUG(D_VFSTRACE, "migrate %s under "DFID" to MDT%04x\n",
	       name, PFID(ll_inode2fid(parent)), mdtidx);

	op_data = ll_prep_md_op_data(NULL, parent, NULL, name, namelen,
				     0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	/* Get child FID first */
	qstr.hash = ll_full_name_hash(file_dentry(file), name, namelen);
	qstr.name = name;
	qstr.len = namelen;
	dchild = d_lookup(file_dentry(file), &qstr);
	if (dchild != NULL) {
		if (dchild->d_inode != NULL)
			child_inode = igrab(dchild->d_inode);
		dput(dchild);
	}

	if (child_inode == NULL) {
		rc = ll_get_fid_by_name(parent, name, namelen,
					&op_data->op_fid3, &child_inode);
		if (rc != 0)
			GOTO(out_free, rc);
	}

	if (child_inode == NULL)
		GOTO(out_free, rc = -EINVAL);

	/*
	 * lfs migrate command needs to be blocked on the client
	 * by checking the migrate FID against the FID of the
	 * filesystem root.
	 */
	if (child_inode == parent->i_sb->s_root->d_inode)
		GOTO(out_iput, rc = -EINVAL);

	inode_lock(child_inode);
	op_data->op_fid3 = *ll_inode2fid(child_inode);
	if (!fid_is_sane(&op_data->op_fid3)) {
		CERROR("%s: migrate %s, but FID "DFID" is insane\n",
		       ll_get_fsname(parent->i_sb, NULL, 0), name,
		       PFID(&op_data->op_fid3));
		GOTO(out_unlock, rc = -EINVAL);
	}

	rc = ll_get_mdt_idx_by_fid(ll_i2sbi(parent), &op_data->op_fid3);
	if (rc < 0)
		GOTO(out_unlock, rc);

	if (rc == mdtidx) {
		CDEBUG(D_INFO, "%s: "DFID" is already on MDT%04x\n", name,
		       PFID(&op_data->op_fid3), mdtidx);
		GOTO(out_unlock, rc = 0);
	}
again:
	if (S_ISREG(child_inode->i_mode)) {
		och = ll_lease_open(child_inode, NULL, FMODE_WRITE, 0);
		if (IS_ERR(och)) {
			rc = PTR_ERR(och);
			och = NULL;
			GOTO(out_unlock, rc);
		}

		rc = ll_data_version(child_inode, &data_version,
				     LL_DV_WR_FLUSH);
		if (rc != 0)
			GOTO(out_close, rc);

		op_data->op_handle = och->och_fh;
		op_data->op_data = och->och_mod;
		op_data->op_data_version = data_version;
		op_data->op_lease_handle = och->och_lease_handle;
		op_data->op_bias |= MDS_RENAME_MIGRATE;
	}

	op_data->op_mds = mdtidx;
	op_data->op_cli_flags = CLI_MIGRATE;
	rc = md_rename(ll_i2sbi(parent)->ll_md_exp, op_data, name,
		       namelen, name, namelen, &request);
	if (rc == 0) {
		LASSERT(request != NULL);
		ll_update_times(request, parent);

		body = req_capsule_server_get(&request->rq_pill, &RMF_MDT_BODY);
		LASSERT(body != NULL);

		/* If the server does release layout lock, then we cleanup
		 * the client och here, otherwise release it in out_close: */
		if (och != NULL &&
		    body->mbo_valid & OBD_MD_CLOSE_INTENT_EXECED) {
			obd_mod_put(och->och_mod);
			md_clear_open_replay_data(ll_i2sbi(parent)->ll_md_exp,
						  och);
			och->och_fh.cookie = DEAD_HANDLE_MAGIC;
			OBD_FREE_PTR(och);
			och = NULL;
		}
	}

	if (request != NULL) {
		ptlrpc_req_finished(request);
		request = NULL;
	}

	/* Try again if the file layout has changed. */
	if (rc == -EAGAIN && S_ISREG(child_inode->i_mode))
		goto again;

out_close:
	if (och != NULL) /* close the file */
		ll_lease_close(och, child_inode, NULL);
	if (rc == 0)
		clear_nlink(child_inode);
out_unlock:
	inode_unlock(child_inode);
out_iput:
	iput(child_inode);
out_free:
	ll_finish_md_op_data(op_data);
	RETURN(rc);
}

static int
ll_file_noflock(struct file *file, int cmd, struct file_lock *file_lock)
{
        ENTRY;

        RETURN(-ENOSYS);
}

/**
 * test if some locks matching bits and l_req_mode are acquired
 * - bits can be in different locks
 * - if found clear the common lock bits in *bits
 * - the bits not found, are kept in *bits
 * \param inode [IN]
 * \param bits [IN] searched lock bits [IN]
 * \param l_req_mode [IN] searched lock mode
 * \retval boolean, true iff all bits are found
 */
int ll_have_md_lock(struct inode *inode, __u64 *bits, enum ldlm_mode l_req_mode)
{
	struct lustre_handle lockh;
	union ldlm_policy_data policy;
	enum ldlm_mode mode = (l_req_mode == LCK_MINMODE) ?
			      (LCK_CR | LCK_CW | LCK_PR | LCK_PW) : l_req_mode;
	struct lu_fid *fid;
	__u64 flags;
	int i;
	ENTRY;

        if (!inode)
               RETURN(0);

        fid = &ll_i2info(inode)->lli_fid;
        CDEBUG(D_INFO, "trying to match res "DFID" mode %s\n", PFID(fid),
               ldlm_lockname[mode]);

	flags = LDLM_FL_BLOCK_GRANTED | LDLM_FL_CBPENDING | LDLM_FL_TEST_LOCK;
	for (i = 0; i <= MDS_INODELOCK_MAXSHIFT && *bits != 0; i++) {
		policy.l_inodebits.bits = *bits & (1 << i);
		if (policy.l_inodebits.bits == 0)
			continue;

                if (md_lock_match(ll_i2mdexp(inode), flags, fid, LDLM_IBITS,
                                  &policy, mode, &lockh)) {
                        struct ldlm_lock *lock;

                        lock = ldlm_handle2lock(&lockh);
                        if (lock) {
                                *bits &=
                                      ~(lock->l_policy_data.l_inodebits.bits);
                                LDLM_LOCK_PUT(lock);
                        } else {
                                *bits &= ~policy.l_inodebits.bits;
                        }
                }
        }
        RETURN(*bits == 0);
}

enum ldlm_mode ll_take_md_lock(struct inode *inode, __u64 bits,
			       struct lustre_handle *lockh, __u64 flags,
			       enum ldlm_mode mode)
{
	union ldlm_policy_data policy = { .l_inodebits = { bits } };
	struct lu_fid *fid;
	enum ldlm_mode rc;
	ENTRY;

	fid = &ll_i2info(inode)->lli_fid;
	CDEBUG(D_INFO, "trying to match res "DFID"\n", PFID(fid));

	rc = md_lock_match(ll_i2mdexp(inode), LDLM_FL_BLOCK_GRANTED|flags,
			   fid, LDLM_IBITS, &policy, mode, lockh);

	RETURN(rc);
}

static int ll_inode_revalidate_fini(struct inode *inode, int rc)
{
	/* Already unlinked. Just update nlink and return success */
	if (rc == -ENOENT) {
		clear_nlink(inode);
		/* If it is striped directory, and there is bad stripe
		 * Let's revalidate the dentry again, instead of returning
		 * error */
		if (S_ISDIR(inode->i_mode) &&
		    ll_i2info(inode)->lli_lsm_md != NULL)
			return 0;

		/* This path cannot be hit for regular files unless in
		 * case of obscure races, so no need to to validate
		 * size. */
		if (!S_ISREG(inode->i_mode) && !S_ISDIR(inode->i_mode))
			return 0;
	} else if (rc != 0) {
		CDEBUG_LIMIT((rc == -EACCES || rc == -EIDRM) ? D_INFO : D_ERROR,
			     "%s: revalidate FID "DFID" error: rc = %d\n",
			     ll_get_fsname(inode->i_sb, NULL, 0),
			     PFID(ll_inode2fid(inode)), rc);
	}

	return rc;
}

static int __ll_inode_revalidate(struct dentry *dentry, __u64 ibits)
{
        struct inode *inode = dentry->d_inode;
        struct ptlrpc_request *req = NULL;
        struct obd_export *exp;
        int rc = 0;
        ENTRY;

        LASSERT(inode != NULL);

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p),name=%s\n",
	       PFID(ll_inode2fid(inode)), inode, dentry->d_name.name);

        exp = ll_i2mdexp(inode);

        /* XXX: Enable OBD_CONNECT_ATTRFID to reduce unnecessary getattr RPC.
         *      But under CMD case, it caused some lock issues, should be fixed
         *      with new CMD ibits lock. See bug 12718 */
	if (exp_connect_flags(exp) & OBD_CONNECT_ATTRFID) {
                struct lookup_intent oit = { .it_op = IT_GETATTR };
                struct md_op_data *op_data;

                if (ibits == MDS_INODELOCK_LOOKUP)
                        oit.it_op = IT_LOOKUP;

                /* Call getattr by fid, so do not provide name at all. */
                op_data = ll_prep_md_op_data(NULL, dentry->d_inode,
                                             dentry->d_inode, NULL, 0, 0,
                                             LUSTRE_OPC_ANY, NULL);
                if (IS_ERR(op_data))
                        RETURN(PTR_ERR(op_data));

		rc = md_intent_lock(exp, op_data, &oit, &req,
				    &ll_md_blocking_ast, 0);
                ll_finish_md_op_data(op_data);
                if (rc < 0) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        GOTO (out, rc);
                }

                rc = ll_revalidate_it_finish(req, &oit, dentry);
                if (rc != 0) {
                        ll_intent_release(&oit);
                        GOTO(out, rc);
                }

                /* Unlinked? Unhash dentry, so it is not picked up later by
                   do_lookup() -> ll_revalidate_it(). We cannot use d_drop
                   here to preserve get_cwd functionality on 2.6.
                   Bug 10503 */
		if (!dentry->d_inode->i_nlink) {
			ll_lock_dcache(inode);
			d_lustre_invalidate(dentry, 0);
			ll_unlock_dcache(inode);
		}

                ll_lookup_finish_locks(&oit, dentry);
        } else if (!ll_have_md_lock(dentry->d_inode, &ibits, LCK_MINMODE)) {
		struct ll_sb_info *sbi = ll_i2sbi(dentry->d_inode);
		u64 valid = OBD_MD_FLGETATTR;
		struct md_op_data *op_data;
		int ealen = 0;

		if (S_ISREG(inode->i_mode)) {
			rc = ll_get_default_mdsize(sbi, &ealen);
			if (rc)
				RETURN(rc);
			valid |= OBD_MD_FLEASIZE | OBD_MD_FLMODEASIZE;
		}

                op_data = ll_prep_md_op_data(NULL, inode, NULL, NULL,
                                             0, ealen, LUSTRE_OPC_ANY,
                                             NULL);
                if (IS_ERR(op_data))
                        RETURN(PTR_ERR(op_data));

                op_data->op_valid = valid;
                rc = md_getattr(sbi->ll_md_exp, op_data, &req);
                ll_finish_md_op_data(op_data);
                if (rc) {
                        rc = ll_inode_revalidate_fini(inode, rc);
                        RETURN(rc);
                }

                rc = ll_prep_inode(&inode, req, NULL, NULL);
        }
out:
        ptlrpc_req_finished(req);
        return rc;
}

static int ll_merge_md_attr(struct inode *inode)
{
	struct cl_attr attr = { 0 };
	int rc;

	LASSERT(ll_i2info(inode)->lli_lsm_md != NULL);
	rc = md_merge_attr(ll_i2mdexp(inode), ll_i2info(inode)->lli_lsm_md,
			   &attr, ll_md_blocking_ast);
	if (rc != 0)
		RETURN(rc);

	set_nlink(inode, attr.cat_nlink);
	inode->i_blocks = attr.cat_blocks;
	i_size_write(inode, attr.cat_size);

	ll_i2info(inode)->lli_atime = attr.cat_atime;
	ll_i2info(inode)->lli_mtime = attr.cat_mtime;
	ll_i2info(inode)->lli_ctime = attr.cat_ctime;

	RETURN(0);
}

static int
ll_inode_revalidate(struct dentry *dentry, __u64 ibits)
{
	struct inode	*inode = dentry->d_inode;
	int		 rc;
	ENTRY;

	rc = __ll_inode_revalidate(dentry, ibits);
	if (rc != 0)
		RETURN(rc);

	/* if object isn't regular file, don't validate size */
	if (!S_ISREG(inode->i_mode)) {
		if (S_ISDIR(inode->i_mode) &&
		    ll_i2info(inode)->lli_lsm_md != NULL) {
			rc = ll_merge_md_attr(inode);
			if (rc != 0)
				RETURN(rc);
		}

		LTIME_S(inode->i_atime) = ll_i2info(inode)->lli_atime;
		LTIME_S(inode->i_mtime) = ll_i2info(inode)->lli_mtime;
		LTIME_S(inode->i_ctime) = ll_i2info(inode)->lli_ctime;
	} else {
		/* In case of restore, the MDT has the right size and has
		 * already send it back without granting the layout lock,
		 * inode is up-to-date so glimpse is useless.
		 * Also to glimpse we need the layout, in case of a running
		 * restore the MDT holds the layout lock so the glimpse will
		 * block up to the end of restore (getattr will block)
		 */
		if (!ll_file_test_flag(ll_i2info(inode), LLIF_FILE_RESTORING))
			rc = ll_glimpse_size(inode);
	}
	RETURN(rc);
}

static inline dev_t ll_compat_encode_dev(dev_t dev)
{
	/* The compat_sys_*stat*() syscalls will fail unless the
	 * device majors and minors are both less than 256. Note that
	 * the value returned here will be passed through
	 * old_encode_dev() in cp_compat_stat(). And so we are not
	 * trying to return a valid compat (u16) device number, just
	 * one that will pass the old_valid_dev() check. */

	return MKDEV(MAJOR(dev) & 0xff, MINOR(dev) & 0xff);
}

#ifdef HAVE_INODEOPS_ENHANCED_GETATTR
int ll_getattr(const struct path *path, struct kstat *stat,
	       u32 request_mask, unsigned int flags)

{
	struct dentry *de = path->dentry;
#else
int ll_getattr(struct vfsmount *mnt, struct dentry *de, struct kstat *stat)
{
#endif
        struct inode *inode = de->d_inode;
        struct ll_sb_info *sbi = ll_i2sbi(inode);
        struct ll_inode_info *lli = ll_i2info(inode);
        int res = 0;

	res = ll_inode_revalidate(de, MDS_INODELOCK_UPDATE |
				      MDS_INODELOCK_LOOKUP);
        ll_stats_ops_tally(sbi, LPROC_LL_GETATTR, 1);

        if (res)
                return res;

	OBD_FAIL_TIMEOUT(OBD_FAIL_GETATTR_DELAY, 30);

	if (ll_need_32bit_api(sbi)) {
		stat->ino = cl_fid_build_ino(&lli->lli_fid, 1);
		stat->dev = ll_compat_encode_dev(inode->i_sb->s_dev);
		stat->rdev = ll_compat_encode_dev(inode->i_rdev);
	} else {
		stat->ino = inode->i_ino;
		stat->dev = inode->i_sb->s_dev;
		stat->rdev = inode->i_rdev;
	}

	stat->mode = inode->i_mode;
	stat->uid = inode->i_uid;
	stat->gid = inode->i_gid;
	stat->atime = inode->i_atime;
	stat->mtime = inode->i_mtime;
	stat->ctime = inode->i_ctime;
	stat->blksize = sbi->ll_stat_blksize ?: 1 << inode->i_blkbits;

	stat->nlink = inode->i_nlink;
	stat->size = i_size_read(inode);
	stat->blocks = inode->i_blocks;

        return 0;
}

static int ll_fiemap(struct inode *inode, struct fiemap_extent_info *fieinfo,
		     __u64 start, __u64 len)
{
	int		rc;
	size_t		num_bytes;
	struct fiemap	*fiemap;
	unsigned int	extent_count = fieinfo->fi_extents_max;

	num_bytes = sizeof(*fiemap) + (extent_count *
				       sizeof(struct fiemap_extent));
	OBD_ALLOC_LARGE(fiemap, num_bytes);

	if (fiemap == NULL)
		RETURN(-ENOMEM);

	fiemap->fm_flags = fieinfo->fi_flags;
	fiemap->fm_extent_count = fieinfo->fi_extents_max;
	fiemap->fm_start = start;
	fiemap->fm_length = len;
	if (extent_count > 0 &&
	    copy_from_user(&fiemap->fm_extents[0], fieinfo->fi_extents_start,
			   sizeof(struct fiemap_extent)) != 0)
		GOTO(out, rc = -EFAULT);

	rc = ll_do_fiemap(inode, fiemap, num_bytes);

	fieinfo->fi_flags = fiemap->fm_flags;
	fieinfo->fi_extents_mapped = fiemap->fm_mapped_extents;
	if (extent_count > 0 &&
	    copy_to_user(fieinfo->fi_extents_start, &fiemap->fm_extents[0],
			 fiemap->fm_mapped_extents *
			 sizeof(struct fiemap_extent)) != 0)
		GOTO(out, rc = -EFAULT);
out:
	OBD_FREE_LARGE(fiemap, num_bytes);
	return rc;
}

struct posix_acl *ll_get_acl(struct inode *inode, int type)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct posix_acl *acl = NULL;
	ENTRY;

	spin_lock(&lli->lli_lock);
	/* VFS' acl_permission_check->check_acl will release the refcount */
	acl = posix_acl_dup(lli->lli_posix_acl);
	spin_unlock(&lli->lli_lock);

	RETURN(acl);
}

#ifdef HAVE_IOP_SET_ACL
#ifdef CONFIG_FS_POSIX_ACL
int ll_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req = NULL;
	const char *name = NULL;
	char *value = NULL;
	size_t value_size = 0;
	int rc;
	ENTRY;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name = XATTR_NAME_POSIX_ACL_ACCESS;
		if (acl) {
			rc = posix_acl_update_mode(inode, &inode->i_mode, &acl);
			if (rc)
				GOTO(out, rc);
		}

		break;
	case ACL_TYPE_DEFAULT:
		name = XATTR_NAME_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			GOTO(out, rc = acl ? -EACCES : 0);

		break;
	default:
		GOTO(out, rc = -EINVAL);
	}

	if (acl) {
		value_size = posix_acl_xattr_size(acl->a_count);
		value = kmalloc(value_size, GFP_NOFS);
		if (value == NULL)
			GOTO(out, rc = -ENOMEM);

		rc = posix_acl_to_xattr(&init_user_ns, acl, value, value_size);
		if (rc < 0)
			GOTO(out_value, rc);
	}

	rc = md_setxattr(sbi->ll_md_exp, ll_inode2fid(inode),
			 value ? OBD_MD_FLXATTR : OBD_MD_FLXATTRRM,
			 name, value, value_size, 0, 0, 0, &req);

	ptlrpc_req_finished(req);
out_value:
	kfree(value);
out:
	if (!rc)
		set_cached_acl(inode, type, acl);
	else
		forget_cached_acl(inode, type);
	RETURN(rc);
}
#endif /* CONFIG_FS_POSIX_ACL */
#endif /* HAVE_IOP_SET_ACL */

#ifndef HAVE_GENERIC_PERMISSION_2ARGS
static int
# ifdef HAVE_GENERIC_PERMISSION_4ARGS
ll_check_acl(struct inode *inode, int mask, unsigned int flags)
# else
ll_check_acl(struct inode *inode, int mask)
# endif
{
# ifdef CONFIG_FS_POSIX_ACL
	struct posix_acl *acl;
	int rc;
	ENTRY;

#  ifdef HAVE_GENERIC_PERMISSION_4ARGS
	if (flags & IPERM_FLAG_RCU)
		return -ECHILD;
#  endif
	acl = ll_get_acl(inode, ACL_TYPE_ACCESS);

	if (!acl)
		RETURN(-EAGAIN);

	rc = posix_acl_permission(inode, acl, mask);
	posix_acl_release(acl);

	RETURN(rc);
# else /* !CONFIG_FS_POSIX_ACL */
	return -EAGAIN;
# endif /* CONFIG_FS_POSIX_ACL */
}
#endif /* HAVE_GENERIC_PERMISSION_2ARGS */

#ifdef HAVE_GENERIC_PERMISSION_4ARGS
int ll_inode_permission(struct inode *inode, int mask, unsigned int flags)
#else
# ifdef HAVE_INODE_PERMISION_2ARGS
int ll_inode_permission(struct inode *inode, int mask)
# else
int ll_inode_permission(struct inode *inode, int mask, struct nameidata *nd)
# endif
#endif
{
	int rc = 0;
	struct ll_sb_info *sbi;
	struct root_squash_info *squash;
	struct cred *cred = NULL;
	const struct cred *old_cred = NULL;
	cfs_cap_t cap;
	bool squash_id = false;
	ENTRY;

#ifdef MAY_NOT_BLOCK
	if (mask & MAY_NOT_BLOCK)
		return -ECHILD;
#elif defined(HAVE_GENERIC_PERMISSION_4ARGS)
	if (flags & IPERM_FLAG_RCU)
		return -ECHILD;
#endif

       /* as root inode are NOT getting validated in lookup operation,
        * need to do it before permission check. */

        if (inode == inode->i_sb->s_root->d_inode) {
		rc = __ll_inode_revalidate(inode->i_sb->s_root,
					   MDS_INODELOCK_LOOKUP);
                if (rc)
                        RETURN(rc);
        }

	CDEBUG(D_VFSTRACE, "VFS Op:inode="DFID"(%p), inode mode %x mask %o\n",
	       PFID(ll_inode2fid(inode)), inode, inode->i_mode, mask);

	/* squash fsuid/fsgid if needed */
	sbi = ll_i2sbi(inode);
	squash = &sbi->ll_squash;
	if (unlikely(squash->rsi_uid != 0 &&
		     uid_eq(current_fsuid(), GLOBAL_ROOT_UID) &&
		     !(sbi->ll_flags & LL_SBI_NOROOTSQUASH))) {
			squash_id = true;
	}
	if (squash_id) {
		CDEBUG(D_OTHER, "squash creds (%d:%d)=>(%d:%d)\n",
		       __kuid_val(current_fsuid()), __kgid_val(current_fsgid()),
		       squash->rsi_uid, squash->rsi_gid);

		/* update current process's credentials
		 * and FS capability */
		cred = prepare_creds();
		if (cred == NULL)
			RETURN(-ENOMEM);

		cred->fsuid = make_kuid(&init_user_ns, squash->rsi_uid);
		cred->fsgid = make_kgid(&init_user_ns, squash->rsi_gid);
		for (cap = 0; cap < sizeof(cfs_cap_t) * 8; cap++) {
			if ((1 << cap) & CFS_CAP_FS_MASK)
				cap_lower(cred->cap_effective, cap);
		}
		old_cred = override_creds(cred);
	}

	ll_stats_ops_tally(sbi, LPROC_LL_INODE_PERM, 1);
	rc = ll_generic_permission(inode, mask, flags, ll_check_acl);
	/* restore current process's credentials and FS capability */
	if (squash_id) {
		revert_creds(old_cred);
		put_cred(cred);
	}

	RETURN(rc);
}

/* -o localflock - only provides locally consistent flock locks */
struct file_operations ll_file_operations = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif
	.read_iter	= ll_file_read_iter,
	.write_iter	= ll_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= ll_file_read,
	.aio_read	= ll_file_aio_read,
	.write		= ll_file_write,
	.aio_write	= ll_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= ll_file_ioctl,
	.open		= ll_file_open,
	.release	= ll_file_release,
	.mmap		= ll_file_mmap,
	.llseek		= ll_file_seek,
	.splice_read	= ll_file_splice_read,
	.fsync		= ll_fsync,
	.flush		= ll_flush
};

struct file_operations ll_file_operations_flock = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif /* HAVE_SYNC_READ_WRITE */
	.read_iter	= ll_file_read_iter,
	.write_iter	= ll_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= ll_file_read,
	.aio_read	= ll_file_aio_read,
	.write		= ll_file_write,
	.aio_write	= ll_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= ll_file_ioctl,
	.open		= ll_file_open,
	.release	= ll_file_release,
	.mmap		= ll_file_mmap,
	.llseek		= ll_file_seek,
	.splice_read	= ll_file_splice_read,
	.fsync		= ll_fsync,
	.flush		= ll_flush,
	.flock		= ll_file_flock,
	.lock		= ll_file_flock
};

/* These are for -o noflock - to return ENOSYS on flock calls */
struct file_operations ll_file_operations_noflock = {
#ifdef HAVE_FILE_OPERATIONS_READ_WRITE_ITER
# ifdef HAVE_SYNC_READ_WRITE
	.read		= new_sync_read,
	.write		= new_sync_write,
# endif /* HAVE_SYNC_READ_WRITE */
	.read_iter	= ll_file_read_iter,
	.write_iter	= ll_file_write_iter,
#else /* !HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.read		= ll_file_read,
	.aio_read	= ll_file_aio_read,
	.write		= ll_file_write,
	.aio_write	= ll_file_aio_write,
#endif /* HAVE_FILE_OPERATIONS_READ_WRITE_ITER */
	.unlocked_ioctl	= ll_file_ioctl,
	.open		= ll_file_open,
	.release	= ll_file_release,
	.mmap		= ll_file_mmap,
	.llseek		= ll_file_seek,
	.splice_read	= ll_file_splice_read,
	.fsync		= ll_fsync,
	.flush		= ll_flush,
	.flock		= ll_file_noflock,
	.lock		= ll_file_noflock
};

struct inode_operations ll_file_inode_operations = {
	.setattr	= ll_setattr,
	.getattr	= ll_getattr,
	.permission	= ll_inode_permission,
#ifdef HAVE_IOP_XATTR
	.setxattr	= ll_setxattr,
	.getxattr	= ll_getxattr,
	.removexattr	= ll_removexattr,
#endif
	.listxattr	= ll_listxattr,
	.fiemap		= ll_fiemap,
#ifdef HAVE_IOP_GET_ACL
	.get_acl	= ll_get_acl,
#endif
#ifdef HAVE_IOP_SET_ACL
	.set_acl	= ll_set_acl,
#endif
};

int ll_layout_conf(struct inode *inode, const struct cl_object_conf *conf)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct cl_object *obj = lli->lli_clob;
	struct lu_env *env;
	int rc;
	__u16 refcheck;
	ENTRY;

	if (obj == NULL)
		RETURN(0);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		RETURN(PTR_ERR(env));

	rc = cl_conf_set(env, lli->lli_clob, conf);
	if (rc < 0)
		GOTO(out, rc);

	if (conf->coc_opc == OBJECT_CONF_SET) {
		struct ldlm_lock *lock = conf->coc_lock;
		struct cl_layout cl = {
			.cl_layout_gen = 0,
		};

		LASSERT(lock != NULL);
		LASSERT(ldlm_has_layout(lock));

		/* it can only be allowed to match after layout is
		 * applied to inode otherwise false layout would be
		 * seen. Applying layout shoud happen before dropping
		 * the intent lock. */
		ldlm_lock_allow_match(lock);

		rc = cl_object_layout_get(env, obj, &cl);
		if (rc < 0)
			GOTO(out, rc);

		CDEBUG(D_VFSTRACE,
		       DFID": layout version change: %u -> %u\n",
		       PFID(&lli->lli_fid), ll_layout_version_get(lli),
		       cl.cl_layout_gen);
		ll_layout_version_set(lli, cl.cl_layout_gen);
	}

out:
	cl_env_put(env, &refcheck);

	RETURN(rc);
}

/* Fetch layout from MDT with getxattr request, if it's not ready yet */
static int ll_layout_fetch(struct inode *inode, struct ldlm_lock *lock)

{
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct ptlrpc_request *req;
	struct mdt_body *body;
	void *lvbdata;
	void *lmm;
	int lmmsize;
	int rc;
	ENTRY;

	CDEBUG(D_INODE, DFID" LVB_READY=%d l_lvb_data=%p l_lvb_len=%d\n",
	       PFID(ll_inode2fid(inode)), ldlm_is_lvb_ready(lock),
	       lock->l_lvb_data, lock->l_lvb_len);

	if (lock->l_lvb_data != NULL)
		RETURN(0);

	/* if layout lock was granted right away, the layout is returned
	 * within DLM_LVB of dlm reply; otherwise if the lock was ever
	 * blocked and then granted via completion ast, we have to fetch
	 * layout here. Please note that we can't use the LVB buffer in
	 * completion AST because it doesn't have a large enough buffer */
	rc = ll_get_default_mdsize(sbi, &lmmsize);
	if (rc == 0)
		rc = md_getxattr(sbi->ll_md_exp, ll_inode2fid(inode),
				OBD_MD_FLXATTR, XATTR_NAME_LOV, NULL, 0,
				lmmsize, 0, &req);
	if (rc < 0)
		RETURN(rc);

	body = req_capsule_server_get(&req->rq_pill, &RMF_MDT_BODY);
	if (body == NULL)
		GOTO(out, rc = -EPROTO);

	lmmsize = body->mbo_eadatasize;
	if (lmmsize == 0) /* empty layout */
		GOTO(out, rc = 0);

	lmm = req_capsule_server_sized_get(&req->rq_pill, &RMF_EADATA, lmmsize);
	if (lmm == NULL)
		GOTO(out, rc = -EFAULT);

	OBD_ALLOC_LARGE(lvbdata, lmmsize);
	if (lvbdata == NULL)
		GOTO(out, rc = -ENOMEM);

	memcpy(lvbdata, lmm, lmmsize);
	lock_res_and_lock(lock);
	if (unlikely(lock->l_lvb_data == NULL)) {
		lock->l_lvb_type = LVB_T_LAYOUT;
		lock->l_lvb_data = lvbdata;
		lock->l_lvb_len = lmmsize;
		lvbdata = NULL;
	}
	unlock_res_and_lock(lock);

	if (lvbdata)
		OBD_FREE_LARGE(lvbdata, lmmsize);

	EXIT;

out:
	ptlrpc_req_finished(req);
	return rc;
}

/**
 * Apply the layout to the inode. Layout lock is held and will be released
 * in this function.
 */
static int ll_layout_lock_set(struct lustre_handle *lockh, enum ldlm_mode mode,
			      struct inode *inode)
{
	struct ll_inode_info *lli = ll_i2info(inode);
	struct ll_sb_info    *sbi = ll_i2sbi(inode);
	struct ldlm_lock *lock;
	struct cl_object_conf conf;
	int rc = 0;
	bool lvb_ready;
	bool wait_layout = false;
	ENTRY;

	LASSERT(lustre_handle_is_used(lockh));

	lock = ldlm_handle2lock(lockh);
	LASSERT(lock != NULL);
	LASSERT(ldlm_has_layout(lock));

	LDLM_DEBUG(lock, "file "DFID"(%p) being reconfigured",
		   PFID(&lli->lli_fid), inode);

	/* in case this is a caching lock and reinstate with new inode */
	md_set_lock_data(sbi->ll_md_exp, lockh, inode, NULL);

	lock_res_and_lock(lock);
	lvb_ready = ldlm_is_lvb_ready(lock);
	unlock_res_and_lock(lock);

	/* checking lvb_ready is racy but this is okay. The worst case is
	 * that multi processes may configure the file on the same time. */
	if (lvb_ready)
		GOTO(out, rc = 0);

	rc = ll_layout_fetch(inode, lock);
	if (rc < 0)
		GOTO(out, rc);

	/* for layout lock, lmm is stored in lock's lvb.
	 * lvb_data is immutable if the lock is held so it's safe to access it
	 * without res lock.
	 *
	 * set layout to file. Unlikely this will fail as old layout was
	 * surely eliminated */
	memset(&conf, 0, sizeof conf);
	conf.coc_opc = OBJECT_CONF_SET;
	conf.coc_inode = inode;
	conf.coc_lock = lock;
	conf.u.coc_layout.lb_buf = lock->l_lvb_data;
	conf.u.coc_layout.lb_len = lock->l_lvb_len;
	rc = ll_layout_conf(inode, &conf);

	/* refresh layout failed, need to wait */
	wait_layout = rc == -EBUSY;
	EXIT;
out:
	LDLM_LOCK_PUT(lock);
	ldlm_lock_decref(lockh, mode);

	/* wait for IO to complete if it's still being used. */
	if (wait_layout) {
		CDEBUG(D_INODE, "%s: "DFID"(%p) wait for layout reconf\n",
		       ll_get_fsname(inode->i_sb, NULL, 0),
		       PFID(&lli->lli_fid), inode);

		memset(&conf, 0, sizeof conf);
		conf.coc_opc = OBJECT_CONF_WAIT;
		conf.coc_inode = inode;
		rc = ll_layout_conf(inode, &conf);
		if (rc == 0)
			rc = -EAGAIN;

		CDEBUG(D_INODE, "%s file="DFID" waiting layout return: %d\n",
		       ll_get_fsname(inode->i_sb, NULL, 0),
		       PFID(&lli->lli_fid), rc);
	}
	RETURN(rc);
}

/**
 * Issue layout intent RPC to MDS.
 * \param inode [in]	file inode
 * \param intent [in]	layout intent
 *
 * \retval 0	on success
 * \retval < 0	error code
 */
static int ll_layout_intent(struct inode *inode, struct layout_intent *intent)
{
	struct ll_inode_info  *lli = ll_i2info(inode);
	struct ll_sb_info     *sbi = ll_i2sbi(inode);
	struct md_op_data     *op_data;
	struct lookup_intent it;
	struct ptlrpc_request *req;
	int rc;
	ENTRY;

	op_data = ll_prep_md_op_data(NULL, inode, inode, NULL,
				     0, 0, LUSTRE_OPC_ANY, NULL);
	if (IS_ERR(op_data))
		RETURN(PTR_ERR(op_data));

	op_data->op_data = intent;
	op_data->op_data_size = sizeof(*intent);

	memset(&it, 0, sizeof(it));
	it.it_op = IT_LAYOUT;
	if (intent->li_opc == LAYOUT_INTENT_WRITE ||
	    intent->li_opc == LAYOUT_INTENT_TRUNC)
		it.it_flags = FMODE_WRITE;

	LDLM_DEBUG_NOLOCK("%s: requeue layout lock for file "DFID"(%p)",
			  ll_get_fsname(inode->i_sb, NULL, 0),
			  PFID(&lli->lli_fid), inode);

	rc = md_intent_lock(sbi->ll_md_exp, op_data, &it, &req,
			    &ll_md_blocking_ast, 0);
	if (it.it_request != NULL)
		ptlrpc_req_finished(it.it_request);
	it.it_request = NULL;

	ll_finish_md_op_data(op_data);

	/* set lock data in case this is a new lock */
	if (!rc)
		ll_set_lock_data(sbi->ll_md_exp, inode, &it, NULL);

	ll_intent_drop_lock(&it);

	RETURN(rc);
}

/**
 * This function checks if there exists a LAYOUT lock on the client side,
 * or enqueues it if it doesn't have one in cache.
 *
 * This function will not hold layout lock so it may be revoked any time after
 * this function returns. Any operations depend on layout should be redone
 * in that case.
 *
 * This function should be called before lov_io_init() to get an uptodate
 * layout version, the caller should save the version number and after IO
 * is finished, this function should be called again to verify that layout
 * is not changed during IO time.
 */
int ll_layout_refresh(struct inode *inode, __u32 *gen)
{
	struct ll_inode_info	*lli = ll_i2info(inode);
	struct ll_sb_info	*sbi = ll_i2sbi(inode);
	struct lustre_handle lockh;
	struct layout_intent intent = {
		.li_opc = LAYOUT_INTENT_ACCESS,
	};
	enum ldlm_mode mode;
	int rc;
	ENTRY;

	*gen = ll_layout_version_get(lli);
	if (!(sbi->ll_flags & LL_SBI_LAYOUT_LOCK) || *gen != CL_LAYOUT_GEN_NONE)
		RETURN(0);

	/* sanity checks */
	LASSERT(fid_is_sane(ll_inode2fid(inode)));
	LASSERT(S_ISREG(inode->i_mode));

	/* take layout lock mutex to enqueue layout lock exclusively. */
	mutex_lock(&lli->lli_layout_mutex);

	while (1) {
		/* mostly layout lock is caching on the local side, so try to
		 * match it before grabbing layout lock mutex. */
		mode = ll_take_md_lock(inode, MDS_INODELOCK_LAYOUT, &lockh, 0,
				       LCK_CR | LCK_CW | LCK_PR | LCK_PW);
		if (mode != 0) { /* hit cached lock */
			rc = ll_layout_lock_set(&lockh, mode, inode);
			if (rc == -EAGAIN)
				continue;
			break;
		}

		rc = ll_layout_intent(inode, &intent);
		if (rc != 0)
			break;
	}

	if (rc == 0)
		*gen = ll_layout_version_get(lli);
	mutex_unlock(&lli->lli_layout_mutex);

	RETURN(rc);
}

/**
 * Issue layout intent RPC indicating where in a file an IO is about to write.
 *
 * \param[in] inode	file inode.
 * \param[in] start	start offset of fille in bytes where an IO is about to
 *			write.
 * \param[in] end	exclusive end offset in bytes of the write range.
 *
 * \retval 0	on success
 * \retval < 0	error code
 */
int ll_layout_write_intent(struct inode *inode, __u64 start, __u64 end)
{
	struct layout_intent intent = {
		.li_opc = LAYOUT_INTENT_WRITE,
		.li_start = start,
		.li_end = end,
	};
	int rc;
	ENTRY;

	rc = ll_layout_intent(inode, &intent);

	RETURN(rc);
}

/**
 *  This function send a restore request to the MDT
 */
int ll_layout_restore(struct inode *inode, loff_t offset, __u64 length)
{
	struct hsm_user_request	*hur;
	int			 len, rc;
	ENTRY;

	len = sizeof(struct hsm_user_request) +
	      sizeof(struct hsm_user_item);
	OBD_ALLOC(hur, len);
	if (hur == NULL)
		RETURN(-ENOMEM);

	hur->hur_request.hr_action = HUA_RESTORE;
	hur->hur_request.hr_archive_id = 0;
	hur->hur_request.hr_flags = 0;
	memcpy(&hur->hur_user_item[0].hui_fid, &ll_i2info(inode)->lli_fid,
	       sizeof(hur->hur_user_item[0].hui_fid));
	hur->hur_user_item[0].hui_extent.offset = offset;
	hur->hur_user_item[0].hui_extent.length = length;
	hur->hur_request.hr_itemcount = 1;
	rc = obd_iocontrol(LL_IOC_HSM_REQUEST, ll_i2sbi(inode)->ll_md_exp,
			   len, hur, NULL);
	OBD_FREE(hur, len);
	RETURN(rc);
}
