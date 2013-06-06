/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * (C) Copyright 2012 Commissariat a l'energie atomique et aux energies
 *     alternatives
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 or (at your discretion) any later version.
 * (LGPL) version 2.1 accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * LGPL HEADER END
 */
/*
 * lustre/utils/liblustreapi_hsm.c
 *
 * lustreapi library for hsm calls
 *
 * Author: Aurelien Degremont <aurelien.degremont@cea.fr>
 * Author: JC Lafoucriere <jacques-charles.lafoucriere@cea.fr>
 * Author: Thomas leibovici <thomas.leibovici@cea.fr>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utime.h>
#include <sys/syscall.h>
#include <fnmatch.h>
#include <glob.h>
#ifdef HAVE_LINUX_UNISTD_H
#include <linux/unistd.h>
#else
#include <unistd.h>
#endif

#include <liblustre.h>
#include <lnet/lnetctl.h>
#include <obd.h>
#include <obd_lov.h>
#include <lustre/lustreapi.h>
#include "lustreapi_internal.h"

/****** HSM Copytool API ********/
#define CT_PRIV_MAGIC 0xC0BE2001
struct hsm_copytool_private {
	int			 magic;
	char			*fsname;
	lustre_kernelcomm	 kuc;
	__u32			 archives;
};

#include <libcfs/libcfs.h>

/** Register a copytool
 * \param[out] priv Opaque private control structure
 * \param fsname Lustre filesystem
 * \param flags Open flags, currently unused (e.g. O_NONBLOCK)
 * \param archive_count
 * \param archives Which archive numbers this copytool is responsible for
 */
int llapi_hsm_copytool_start(struct hsm_copytool_private **priv, char *fsname,
			     int flags, int archive_count, int *archives)
{
	struct hsm_copytool_private	*ct;
	int				 rc;

	if (archive_count > 0 && archives == NULL) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "NULL archive numbers");
		return -EINVAL;
	}

	ct = calloc(1, sizeof(*ct));
	if (ct == NULL)
		return -ENOMEM;

	ct->fsname = malloc(strlen(fsname) + 1);
	if (ct->fsname == NULL) {
		rc = -ENOMEM;
		goto out_err;
	}
	strcpy(ct->fsname, fsname);
	ct->magic = CT_PRIV_MAGIC;

	/* no archives specified means "match all". */
	ct->archives = 0;
	for (rc = 0; rc < archive_count; rc++) {
		if (archives[rc] > 8 * sizeof(ct->archives)) {
			llapi_err_noerrno(LLAPI_MSG_ERROR,
					  "Maximum of %d archives supported",
					  8 * sizeof(ct->archives));
			goto out_err;
		}
		/* in the list we have a all archive wildcard
		 * so move to all archives mode
		 */
		if (archives[rc] == 0) {
			ct->archives = 0;
			archive_count = 0;
			break;
		}
		ct->archives |= (1 << (archives[rc] - 1));
	}

	rc = libcfs_ukuc_start(&ct->kuc, KUC_GRP_HSM);
	if (rc < 0)
		goto out_err;

	/* Storing archive(s) in lk_data; see mdc_ioc_hsm_ct_start */
	ct->kuc.lk_data = ct->archives;
	rc = root_ioctl(ct->fsname, LL_IOC_HSM_CT_START, &(ct->kuc), NULL,
			WANT_ERROR);
	/* ignore if it was already registered on coordinator */
	if (rc == -EEXIST)
		rc = 0;
	/* Only the kernel reference keeps the write side open */
	close(ct->kuc.lk_wfd);
	ct->kuc.lk_wfd = 0;
	if (rc < 0)
		goto out_err;

	*priv = ct;
	return 0;

out_err:
	if (ct->fsname)
		free(ct->fsname);
	free(ct);
	return rc;
}

/** Deregister a copytool
 * Note: under Linux, until llapi_hsm_copytool_fini is called (or the program is
 * killed), the libcfs module will be referenced and unremovable,
 * even after Lustre services stop.
 */
int llapi_hsm_copytool_fini(struct hsm_copytool_private **priv)
{
	struct hsm_copytool_private *ct;

	ct = *priv;
	if (!ct || (ct->magic != CT_PRIV_MAGIC))
		return -EINVAL;

	/* Tell the kernel to stop sending us messages */
	ct->kuc.lk_flags = LK_FLG_STOP;
	root_ioctl(ct->fsname, LL_IOC_HSM_CT_START, &(ct->kuc), NULL, 0);

	/* Shut down the kernelcomms */
	libcfs_ukuc_stop(&ct->kuc);

	free(ct->fsname);
	free(ct);
	*priv = NULL;
	return 0;
}

/** Wait for the next hsm_action_list
 * \param ct Opaque private control structure
 * \param halh Action list handle, will be allocated here
 * \param msgsize Number of bytes in the message, will be set here
 * \return 0 valid message received; halh and msgsize are set
 *	   <0 error code
 */
int llapi_hsm_copytool_recv(struct hsm_copytool_private *ct,
			    struct hsm_action_list **halh, int *msgsize)
{
	struct kuc_hdr			*kuch;
	struct hsm_action_list		*hal;
	int				 rc = 0;

	if (!ct || (ct->magic != CT_PRIV_MAGIC))
		return -EINVAL;
	if (halh == NULL || msgsize == NULL)
		return -EINVAL;

	kuch = malloc(HAL_MAXSIZE + sizeof(*kuch));
	if (kuch == NULL)
		return -ENOMEM;

	rc = libcfs_ukuc_msg_get(&ct->kuc, (char *)kuch,
				 HAL_MAXSIZE + sizeof(*kuch),
				 KUC_TRANSPORT_HSM);
	if (rc < 0)
		goto out_free;

	/* Handle generic messages */
	if (kuch->kuc_transport == KUC_TRANSPORT_GENERIC &&
	    kuch->kuc_msgtype == KUC_MSG_SHUTDOWN) {
		rc = -ESHUTDOWN;
		goto out_free;
	}

	if (kuch->kuc_transport != KUC_TRANSPORT_HSM ||
	    kuch->kuc_msgtype != HMT_ACTION_LIST) {
		llapi_err_noerrno(LLAPI_MSG_ERROR,
				  "Unknown HSM message type %d:%d\n",
				  kuch->kuc_transport, kuch->kuc_msgtype);
		rc = -EPROTO;
		goto out_free;
	}

	if (kuch->kuc_msglen < sizeof(*kuch) + sizeof(*hal)) {
		llapi_err_noerrno(LLAPI_MSG_ERROR, "Short HSM message %d",
				  kuch->kuc_msglen);
		rc = -EPROTO;
		goto out_free;
	}

	/* Our message is a hsm_action_list. Use pointer math to skip
	* kuch_hdr and point directly to the message payload.
	*/
	hal = (struct hsm_action_list *)(kuch + 1);

	/* Check that we have registered for this archive #
	 * if 0 registered, we serve any archive */
	if (ct->archives &&
	    ((1 << (hal->hal_archive_id - 1)) & ct->archives) == 0) {
		llapi_err_noerrno(LLAPI_MSG_INFO,
				  "This copytool does not service archive #%d,"
				  " ignoring this request."
				  " Mask of served archive is 0x%.8X",
				  hal->hal_archive_id, ct->archives);
		rc = -EAGAIN;

		goto out_free;
	}

	*halh = hal;
	*msgsize = kuch->kuc_msglen - sizeof(*kuch);
	return 0;

out_free:
	*halh = NULL;
	*msgsize = 0;
	free(kuch);
	return rc;
}

/** Release the action list when done with it. */
int llapi_hsm_copytool_free(struct hsm_action_list **hal)
{
	/* Reuse the llapi_changelog_free function */
	return llapi_changelog_free((struct changelog_ext_rec **)hal);
}


/**
 * Should be called by copytools just before starting handling a request.
 * It could be skipped if copytool only want to directly report an error,
 * \see llapi_hsm_copy_end().
 *
 * \param mnt   Mount point of the corresponding Lustre filesystem.
 * \param hai   The hsm_action_item describing the request they will handle.
 * \param copy  Updated by this call. Caller will passed it to
 *		llapi_hsm_copy_end()
 *
 * \return 0 on success.
 */
int llapi_hsm_copy_start(char *mnt, struct hsm_copy *copy,
			 const struct hsm_action_item *hai)
{
	int	fd;
	int	rc;

	if (memcpy(&copy->hc_hai, hai, sizeof(*hai)) == NULL)
		RETURN(-EFAULT);

	rc = get_root_path(WANT_FD, NULL, &fd, mnt, -1);
	if (rc)
		return rc;

	rc = ioctl(fd, LL_IOC_HSM_COPY_START, copy);
	/* If error, return errno value */
	rc = rc ? -errno : 0;
	close(fd);

	return rc;
}

/**
 * Should be called by copytools just having finished handling the request.
 *
 * \param mnt   Mount point of the corresponding Lustre filesystem.
 * \param copy  The element used when calling llapi_hsm_copy_start()
 * \param hp    A hsm_progress structure describing the final state of the
 *		request.
 *
 * There is a special case which can be used only when the copytool cannot
 * start the copy at all and want to directly return an error. In this case,
 * simply fill \a hp structure and set \a copy to NULL. It is useless to call
 * llapi_hsm_copy_start() in this case.
 *
 * \return 0 on success.
 */
int llapi_hsm_copy_end(char *mnt, struct hsm_copy *copy,
		       const struct hsm_progress *hp)
{
	int	end_only = 0;
	int	fd;
	int	rc;

	/* llapi_hsm_copy_start() was skipped, so alloc copy. It will
	 * only be used to give the needed progress information. */
	if (copy == NULL) {
		/* This is only ok if there is an error. */
		if (hp->hp_errval == 0)
			return -EINVAL;

		copy = (struct hsm_copy *)malloc(sizeof(*copy));
		if (copy == NULL)
			return -ENOMEM;
		end_only = 1;
		copy->hc_hai.hai_cookie = hp->hp_cookie;
		copy->hc_hai.hai_fid = hp->hp_fid;
		copy->hc_hai.hai_action = HSMA_NONE;
	}

	/* Fill the last missing data that will be needed by kernel
	 * to send a hsm_progress. */
	copy->hc_flags = hp->hp_flags;
	copy->hc_errval = hp->hp_errval;
	/* Update hai if it has changed since start */
	copy->hc_hai.hai_extent = hp->hp_extent;
	/* In some cases, like restore, 2 FIDs are used. hp knows the right FID
	 * to use here. */
	copy->hc_hai.hai_fid = hp->hp_fid;

	rc = get_root_path(WANT_FD, NULL, &fd, mnt, -1);
	if (rc)
		goto out_free;

	rc = ioctl(fd, LL_IOC_HSM_COPY_END, copy);
	/* If error, return errno value */
	rc = rc ? -errno : 0;
	close(fd);

out_free:
	if (end_only)
		free(copy);

	return rc;
}

/**
 * Copytool progress reporting.
 *
 * \a hp->hp_errval should be EAGAIN until action is completely finished.
 *
 * \return 0 on success, an error code otherwise.
 */
int llapi_hsm_progress(char *mnt, struct hsm_progress *hp)
{
	int	fd;
	int	rc;

	rc = get_root_path(WANT_FD, NULL, &fd, mnt, -1);
	if (rc)
		return rc;

	rc = ioctl(fd, LL_IOC_HSM_PROGRESS, hp);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	close(fd);
	return rc;
}

/**
 * Import an existing hsm-archived file into Lustre.
 *
 * Caller must access file by (returned) newfid value from now on.
 *
 * \param dst      path to Lustre destination (e.g. /mnt/lustre/my/file).
 * \param archive  archive number.
 * \param st       struct stat buffer containing file ownership, perm, etc.
 * \param stripe_* Striping options.  Currently ignored, since the restore
 *                 operation will set the striping.  In V2, this striping might
 *                 be used.
 * \param newfid[out] Filled with new Lustre fid.
 */
int llapi_hsm_import(const char *dst, int archive, struct stat *st,
		     unsigned long long stripe_size, int stripe_offset,
		     int stripe_count, int stripe_pattern, char *pool_name,
		     lustre_fid *newfid)
{
	struct utimbuf	time;
	int		fd;
	int		rc = 0;

	/* Create a non-striped file */
	fd = open(dst, O_CREAT | O_EXCL | O_LOV_DELAY_CREATE | O_NONBLOCK,
		  st->st_mode);

	if (fd < 0)
		return -errno;
	close(fd);

	/* set size on MDT */
	if (truncate(dst, st->st_size) != 0) {
		rc = -errno;
		goto out_unlink;
	}
	/* Mark archived */
	rc = llapi_hsm_state_set(dst, HS_EXISTS | HS_RELEASED | HS_ARCHIVED, 0,
				 archive);
	if (rc)
		goto out_unlink;

	/* Get the new fid in the archive. Caller needs to use this fid
	   from now on. */
	rc = llapi_path2fid(dst, newfid);
	if (rc)
		goto out_unlink;

	/* Copy the file attributes */
	time.actime = st->st_atime;
	time.modtime = st->st_mtime;
	if (utime(dst, &time) == -1 ||
		chmod(dst, st->st_mode) == -1 ||
		chown(dst, st->st_uid, st->st_gid) == -1) {
		/* we might fail here because we change perms/owner */
		rc = -errno;
		goto out_unlink;
	}

out_unlink:
	if (rc)
		unlink(dst);
	return rc;
}

/**
 * Return the current HSM states and HSM requests related to file pointed by \a
 * path.
 *
 * \param hus  Should be allocated by caller. Will be filled with current file
 *             states.
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
int llapi_hsm_state_get(const char *path, struct hsm_user_state *hus)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	rc = ioctl(fd, LL_IOC_HSM_STATE_GET, hus);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	close(fd);
	return rc;
}

/**
 * Set HSM states of file pointed by \a path.
 *
 * Using the provided bitmasks, the current HSM states for this file will be
 * changed. \a archive_id could be used to change the archive number also. Set
 * it to 0 if you do not want to change it.
 *
 * \param setmask      Bitmask for flag to be set.
 * \param clearmask    Bitmask for flag to be cleared.
 * \param archive_id  Archive number identifier to use. 0 means no change.
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
int llapi_hsm_state_set(const char *path, __u64 setmask, __u64 clearmask,
			__u32 archive_id)
{
	struct hsm_state_set hss;
	int fd;
	int rc;

	fd = open(path, O_WRONLY | O_LOV_DELAY_CREATE | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	hss.hss_valid = HSS_SETMASK|HSS_CLEARMASK;
	hss.hss_setmask = setmask;
	hss.hss_clearmask = clearmask;
	/* Change archive_id if provided. We can only change
	 * to set something different than 0. */
	if (archive_id > 0) {
		hss.hss_valid |= HSS_ARCHIVE_ID;
		hss.hss_archive_id = archive_id;
	}
	rc = ioctl(fd, LL_IOC_HSM_STATE_SET, &hss);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	close(fd);
	return rc;
}


/**
 * Return the current HSM request related to file pointed by \a path.
 *
 * \param hca  Should be allocated by caller. Will be filled with current file
 *             actions.
 *
 * \retval 0 on success.
 * \retval -errno on error.
 */
int llapi_hsm_current_action(const char *path, struct hsm_current_action *hca)
{
	int fd;
	int rc;

	fd = open(path, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return -errno;

	rc = ioctl(fd, LL_IOC_HSM_ACTION, hca);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	close(fd);
	return rc;
}

/**
 * Allocate a hsm_user_request with the specified carateristics.
 * This structure should be freed with free().
 *
 * \return an allocated structure on success, NULL otherwise.
 */
struct hsm_user_request *llapi_hsm_user_request_alloc(int itemcount,
						      int data_len)
{
	int len = 0;

	len += sizeof(struct hsm_user_request);
	len += sizeof(struct hsm_user_item) * itemcount;
	len += data_len;

	return (struct hsm_user_request *)malloc(len);
}

/**
 * Send a HSM request to Lustre, described in \param request.
 *
 * This request should be allocated with llapi_hsm_user_request_alloc().
 *
 * \param mnt Should be the Lustre moint point.
 * \return 0 on success, an error code otherwise.
 */
int llapi_hsm_request(char *mnt, struct hsm_user_request *request)
{
	int rc;
	int fd;

	rc = get_root_path(WANT_FD, NULL, &fd, mnt, -1);
	if (rc)
		return rc;

	rc = ioctl(fd, LL_IOC_HSM_REQUEST, request);
	/* If error, save errno value */
	rc = rc ? -errno : 0;

	close(fd);
	return rc;
}

