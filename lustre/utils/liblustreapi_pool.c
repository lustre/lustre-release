// SPDX-License-Identifier: LGPL-2.1+
/*
 * This file is part of Lustre, http://www.lustre.org/
 *
 * Pool pinning helpers for liblustreapi.
 */

#include <sys/types.h>
#include <sys/xattr.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <lnetconfig/cyaml.h>
#include <linux/lustre/lustre_user.h>

#include "lustreapi_internal.h"

#define PIN_YAML_POOL_STR	"pool"

static int pool_pin_ensure_entry(struct cYAML *yaml, const char *pool_name,
				 char *buff, size_t bufflen)
{
	struct cYAML *node;

	/* Search for an existing entry. */
	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		if (strcmp(node->cy_string, PIN_YAML_POOL_STR) == 0 &&
		    node->cy_type == CYAML_TYPE_STRING &&
		    node->cy_valuestring != NULL &&
		    strcmp(node->cy_valuestring, pool_name) == 0)
			break;
	}

	/* If not found, create a new entry. */
	if (node == NULL) {
		node = cYAML_create_string(yaml, (char *)PIN_YAML_POOL_STR,
					   (char *)pool_name);
		if (node == NULL)
			return -errno ? -errno : -ENOMEM;
	}

	/* Serialise the (possibly updated) YAML object into buff. */
	errno = -dump_pin_object(yaml, buff, bufflen);
	if (errno)
		return -errno;

	/* buff now contains the new serialised lustre.pin value. */
	return 0;
}

static int pool_unpin_update_entry(struct cYAML *yaml, const char *pool_name,
				   char *buff, size_t bufflen)
{
	struct cYAML *node;

	/* We have a valid pin object, search for the entry to be deleted. */
	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		if (strcmp(node->cy_string, PIN_YAML_POOL_STR) == 0 &&
		    node->cy_type == CYAML_TYPE_STRING &&
		    node->cy_valuestring != NULL &&
		    strcmp(node->cy_valuestring, pool_name) == 0)
			break;
	}
	if (node == NULL) {
		/* No matching pool entry in lustre.pin. */
		errno = ENOENT;
		return -ENOENT;
	}

	/* Remove the node from the YAML tree. */
	if (node == yaml->cy_child) {
		/* the first child */
		if (node->cy_next)
			node->cy_next->cy_prev = NULL;
		yaml->cy_child = node->cy_next;
	} else {
		/* not the first child */
		node->cy_prev->cy_next = node->cy_next;
		if (node->cy_next)
			node->cy_next->cy_prev = node->cy_prev;
	}
	node->cy_prev = node->cy_next = NULL;
	cYAML_free_tree(node);

	errno = -dump_pin_object(yaml, buff, bufflen);
	if (errno)
		return -errno;

	return 0;
}

static int pool_is_pinned_from_yaml(struct cYAML *yaml, const char *pool_name)
{
	struct cYAML *node;
	int pinned = 0;

	for (node = yaml->cy_child; node != NULL; node = node->cy_next) {
		if (strcmp(node->cy_string, PIN_YAML_POOL_STR) == 0 &&
		    node->cy_type == CYAML_TYPE_STRING &&
		    node->cy_valuestring != NULL &&
		    strcmp(node->cy_valuestring, pool_name) == 0) {
			pinned = 1;
			break;
		}
	}

	cYAML_free_tree(yaml);
	return pinned;
}

/**
 * llapi_pool_pin_fd() - Pin a file for a given pool name using an open fd.
 * @fd: Open file descriptor for a Lustre file.
 * @pool_name: Name of the pool to pin for (optionally fsname-qualified).
 *
 * Ensure that a "pool: pool_name" entry exists in the lustre.pin xattr of the
 * file referenced by @fd. If such an entry already exists, this function
 * succeeds without modifying the xattr.
 *
 * Return: 0 on success; on failure, a negative errno value is returned and
 *         errno is set to the corresponding error code.
 */
int llapi_pool_pin_fd(int fd, const char *pool_name)
{
	int rc = 0;
	struct cYAML *yaml = NULL;
	char buff[XATTR_SIZE_MAX];

	if (!llapi_pool_name_is_valid(&pool_name)) {
		errno = EINVAL;
		return -errno;
	}

	yaml = read_pin_xattr_object_fd(fd);

	if (yaml == NULL && errno == ENODATA) {
		snprintf(buff, sizeof(buff), "[%s: %s]", PIN_YAML_POOL_STR,
			 pool_name);
	} else if (yaml == NULL) {
		return -errno;
	} else {
		rc = pool_pin_ensure_entry(yaml, pool_name, buff, sizeof(buff));
		if (rc < 0)
			goto out;
	}

	if (fsetxattr(fd, XATTR_LUSTRE_PIN, buff, strlen(buff), 0) < 0)
		rc = -errno;
	else
		rc = 0;

out:
	if (yaml)
		cYAML_free_tree(yaml);
	return rc;
}

/**
 * llapi_pool_pin_file() - Pin a file for a given pool name using a path.
 * @path: Path to a Lustre file.
 * @pool_name: Name of the pool to pin for (optionally fsname-qualified).
 *
 * Ensure that a "pool: pool_name" entry exists in the lustre.pin xattr of the
 * file at @path. If such an entry already exists, this function succeeds
 * without modifying the xattr.
 *
 * Return: 0 on success; on failure, a negative errno value is returned and
 *         errno is set to the corresponding error code.
 */
int llapi_pool_pin_file(const char *path, const char *pool_name)
{
	int rc = 0;
	struct cYAML *yaml = NULL;
	char buff[XATTR_SIZE_MAX];

	if (!llapi_pool_name_is_valid(&pool_name)) {
		errno = EINVAL;
		return -errno;
	}

	yaml = read_pin_xattr_object(path);

	if (yaml == NULL && errno == ENODATA) {
		snprintf(buff, sizeof(buff), "[%s: %s]", PIN_YAML_POOL_STR,
			 pool_name);
	} else if (yaml == NULL) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "cannot read or parse pin xattr of file '%s'.",
			    path);
		rc = -errno;
		goto out;
	} else {
		rc = pool_pin_ensure_entry(yaml, pool_name, buff, sizeof(buff));
		if (rc < 0)
			goto out;
	}

	if (setxattr(path, XATTR_LUSTRE_PIN, buff, strlen(buff), 0) < 0)
		rc = -errno;
	else
		rc = 0;

out:
	if (yaml)
		cYAML_free_tree(yaml);
	return rc;
}

/**
 * llapi_pool_pin_fid() - Pin a file for a given pool name using its FID.
 * @lustre_dir: Path within the target Lustre filesystem (usually the mount).
 * @fid:        FID of the file to be pinned.
 * @pool_name:  Name of the pool to pin for (optionally fsname-qualified).
 *
 * Open the object referenced by @fid in @lustre_dir, then ensure a
 * corresponding "pool: pool_name" entry exists in its lustre.pin xattr.
 *
 * Return: 0 on success; on failure, a negative errno value is returned and
 *         errno is set to the corresponding error code.
 */
int llapi_pool_pin_fid(const char *lustre_dir, const struct lu_fid *fid,
		       const char *pool_name)
{
	int fd;
	int rc;

	fd = llapi_open_by_fid(lustre_dir, fid, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return fd; /* negative errno, errno set by helper */

	rc = llapi_pool_pin_fd(fd, pool_name);
	if (rc < 0) {
		int saved_errno = errno;

		close(fd);
		errno = saved_errno;
		return rc;
	}

	close(fd);
	return 0;
}

/**
 * llapi_pool_unpin_fd() - Remove a pool pin from a file (by fd).
 * @fd: Open file descriptor for a Lustre file.
 * @pool_name: Name of the pool to unpin (optionally fsname-qualified).
 *
 * Remove the "pool: pool_name" entry from the lustre.pin xattr of the file
 * referenced by @fd. If no matching entry exists (or the attribute is
 * missing), this is treated as an error and ENOENT is reported. When the last
 * entry is removed, the lustre.pin xattr itself is deleted.
 *
 * Return: 0 on success; on failure, a negative errno value is returned and
 *         errno is set to the corresponding error code.
 */
int llapi_pool_unpin_fd(int fd, const char *pool_name)
{
	int rc = 0;
	struct cYAML *yaml = NULL;
	char buff[XATTR_SIZE_MAX];

	if (!llapi_pool_name_is_valid(&pool_name)) {
		errno = EINVAL;
		return -errno;
	}

	yaml = read_pin_xattr_object_fd(fd);

	if (yaml == NULL && errno == ENODATA) {
		errno = ENOENT;
		return -errno;
	}
	if (yaml == NULL)
		return -errno;

	rc = pool_unpin_update_entry(yaml, pool_name, buff, sizeof(buff));
	if (rc < 0)
		goto out;

	if (strlen(buff) == 0) {
		if (fremovexattr(fd, XATTR_LUSTRE_PIN) < 0)
			rc = -errno;
		else
			rc = 0;
	} else {
		if (fsetxattr(fd, XATTR_LUSTRE_PIN, buff, strlen(buff), 0) < 0)
			rc = -errno;
		else
			rc = 0;
	}

out:
	if (yaml)
		cYAML_free_tree(yaml);
	return rc;
}

/**
 * llapi_pool_unpin_file() - Remove a pool pin from a file.
 * @path: Path to a Lustre file.
 * @pool_name: Name of the pool to unpin (optionally fsname-qualified).
 *
 * Remove the "pool: pool_name" entry from the lustre.pin xattr of @path. If
 * no matching entry exists (or the attribute is missing), this is treated as
 * an error and ENOENT is reported. When the last entry is removed, the
 * lustre.pin xattr itself is deleted.
 *
 * Return: 0 on success; on failure, a negative errno value is returned and
 *         errno is set to the corresponding error code.
 */
int llapi_pool_unpin_file(const char *path, const char *pool_name)
{
	int rc = 0;
	struct cYAML *yaml = NULL;
	char buff[XATTR_SIZE_MAX];

	if (!llapi_pool_name_is_valid(&pool_name)) {
		errno = EINVAL;
		return -errno;
	}

	yaml = read_pin_xattr_object(path);

	if (yaml == NULL && errno == ENODATA) {
		errno = ENOENT;
		rc = -errno;
		goto out;
	}
	if (yaml == NULL) {
		llapi_error(LLAPI_MSG_ERROR, errno,
			    "cannot read or parse pin xattr of file '%s'.",
			    path);
		rc = -errno;
		goto out;
	}

	rc = pool_unpin_update_entry(yaml, pool_name, buff, sizeof(buff));
	if (rc < 0)
		goto out;

	if (strlen(buff) == 0) {
		if (removexattr(path, XATTR_LUSTRE_PIN) < 0)
			rc = -errno;
		else
			rc = 0;
	} else {
		if (setxattr(path, XATTR_LUSTRE_PIN, buff, strlen(buff), 0) < 0)
			rc = -errno;
		else
			rc = 0;
	}

out:
	if (yaml)
		cYAML_free_tree(yaml);
	return rc;
}

/**
 * llapi_pool_unpin_fid() - Remove a pool pin from a FID-referenced file.
 * @lustre_dir: Path within the target Lustre filesystem (usually the mount).
 * @fid:        FID of the file to be unpinned.
 * @pool_name:  Name of the pool to unpin (optionally fsname-qualified).
 *
 * Open the object referenced by @fid in @lustre_dir and remove the
 * corresponding "pool: pool_name" entry from its lustre.pin xattr.
 *
 * Return: 0 on success; on failure, a negative errno value is returned and
 *         errno is set to the corresponding error code.
 */
int llapi_pool_unpin_fid(const char *lustre_dir, const struct lu_fid *fid,
			 const char *pool_name)
{
	int fd;
	int rc;

	fd = llapi_open_by_fid(lustre_dir, fid, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return fd;

	rc = llapi_pool_unpin_fd(fd, pool_name);
	if (rc < 0) {
		int saved_errno = errno;

		close(fd);
		errno = saved_errno;
		return rc;
	}

	close(fd);
	return 0;
}

/**
 * llapi_pool_is_pinned_fd() - Test if a file is pinned for a pool name (fd).
 * @fd: Open file descriptor for a Lustre file.
 * @pool_name: Pool name to test (optionally fsname-qualified).
 *
 * Check whether the lustre.pin xattr of the file referenced by @fd contains
 * a "pool: pool_name" entry.
 *
 * Return: 1 if such an entry exists, 0 if not. On error, a negative errno
 *         value is returned.
 */
int llapi_pool_is_pinned_fd(int fd, const char *pool_name)
{
	struct cYAML *yaml;

	if (!llapi_pool_name_is_valid(&pool_name)) {
		errno = EINVAL;
		return -errno;
	}

	yaml = read_pin_xattr_object_fd(fd);
	if (yaml == NULL) {
		/*
		 * No lustre.pin attribute: treat as "not pinned".
		 * Any other error is propagated as -errno.
		 */
		if (errno == ENODATA)
			return 0;
		return -errno;
	}

	return pool_is_pinned_from_yaml(yaml, pool_name);
}

/**
 * llapi_pool_is_pinned_file() - Test if a file is pinned for a pool name.
 * @path: Path to a Lustre file.
 * @pool_name: Pool name to test (optionally fsname-qualified).
 *
 * Check whether the lustre.pin xattr of the file at @path contains a
 * "pool: pool_name" entry.
 *
 * Return: 1 if such an entry exists, 0 if not. On error, a negative errno
 *         value is returned.
 */
int llapi_pool_is_pinned_file(const char *path, const char *pool_name)
{
	struct cYAML *yaml;

	if (!llapi_pool_name_is_valid(&pool_name)) {
		errno = EINVAL;
		return -errno;
	}

	yaml = read_pin_xattr_object(path);
	if (yaml == NULL) {
		if (errno == ENODATA)
			return 0;
		return -errno;
	}

	return pool_is_pinned_from_yaml(yaml, pool_name);
}

/**
 * llapi_pool_is_pinned_fid() - Test if a FID-referenced file is pool-pinned.
 * @lustre_dir: Path within the target Lustre filesystem (usually the mount).
 * @fid:        FID of the file to be checked.
 * @pool_name:  Pool name to test (optionally fsname-qualified).
 *
 * Open the object referenced by @fid in @lustre_dir and check whether its
 * lustre.pin xattr contains a "pool: pool_name" entry.
 *
 * Return: 1 if such an entry exists, 0 if not. On error, a negative errno
 *         value is returned, including failures from llapi_open_by_fid().
 */
int llapi_pool_is_pinned_fid(const char *lustre_dir, const struct lu_fid *fid,
			     const char *pool_name)
{
	int fd;
	int pinned;

	fd = llapi_open_by_fid(lustre_dir, fid, O_RDONLY | O_NONBLOCK);
	if (fd < 0)
		return fd;

	pinned = llapi_pool_is_pinned_fd(fd, pool_name);
	if (pinned < 0) {
		int saved_errno = errno;

		close(fd);
		errno = saved_errno;
		return pinned;
	}

	close(fd);
	return pinned;
}
