/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026, Google
 *
 * GSSIAM structure
 */

#ifndef _LUSTRE_GSSIAM_H
#define _LUSTRE_GSSIAM_H

#include <linux/types.h>
#include <uapi/linux/lustre/lustre_idl.h>

struct lustre_gssiam_desc {
	void *lid_token;
	char *lid_subdir;
	char *lid_principal;
	__u32 lid_token_len;
	__u32 lid_options;
	__u32 lid_projid;
};

struct upcall_cache_entry;
struct lustre_gssiam_info {
	struct lustre_gssiam_desc	lii_desc;
	struct upcall_cache_entry	*lii_gssiam_entry;
	__u32				lii_auth_permission;
};

/**
 * struct gssiam_desc - GSSIAM cached authentication descriptor
 *
 * This structure serves as the payload for an upcall_cache_entry. It caches
 * the results of an Identity and Access Management (IAM) authentication
 * request, binding an opaque token to an authorization state, target UUID,
 * and mapped identity.
 */
struct gssiam_desc {
	/* Back-pointer to the upcall cache entry enclosing this struct */
	struct upcall_cache_entry *gd_uc_entry;

	/* The opaque IAM authentication token provided by the client */
	void                      *gd_token;
	/* The specific subdirectory the client is requesting access to */
	char                      *gd_subdir;
	/* The translated user identity/principal string mapped by IAM */
	char                      *gd_principal;
	/* The mapped project ID associated with this authenticated session */
	__u32			  gd_auth_projid;

	/* Client-requested options (e.g. OBD_CONNECT_RDONLY) */
	__u32			  gd_options;

	/* UUID of the target device (MDT/OST) this authentication applies to */
	struct obd_uuid		  gd_obd_uuid;

	/* Ref count shared by export */
	atomic_t                  gd_export_count;

	/* The authorization status & permissions (e.g. GSSIAM_AUTH_RW |
	 * GSSIAM_AUTH_RO)
	 */
	__u32			  gd_auth_permission;

	/* The login uid of the mount process */
	uid_t                     gd_loginuid;

	/* Length of the gd_token buffer */
	__u32                     gd_token_len;
};

static inline
__u64 lustre_hash_fnv_1a_64_multi(int count, const void *const bufs[],
				  const __kernel_size_t sizes[])
{
	__u64 hash = LUSTRE_FNV_1A_64_OFFSET_BIAS;
	int i;

	for (i = 0; i < count; i++) {
		if (bufs[i] && sizes[i] > 0)
			hash = lustre_hash_fnv_1a_64_continue(hash, bufs[i],
							      sizes[i]);
	}

	return hash;
}

static inline
__u64 lustre_gssiam_hash_key(const void *token, __kernel_size_t token_len,
			     const char *subdir)
{
	const void *bufs[3] = {token, &token_len, subdir};
	__kernel_size_t sizes[3] = {0, 0, 0};

	if (token)
		sizes[0] = token_len;

	sizes[1] = sizeof(token_len);

	if (subdir)
		sizes[2] = strlen(subdir);

	return lustre_hash_fnv_1a_64_multi(3, bufs, sizes);
}

static inline void
gssiam_nodemap_name(char *nm_name, size_t nm_size, const void *token,
		    __kernel_size_t token_len, const char *subdir,
		    __u32 projid, __u32 auth_permission)
{
	__u64 gssiam_hash;

	gssiam_hash = lustre_gssiam_hash_key(token, token_len, subdir);
	gssiam_hash = lustre_hash_fnv_1a_64_continue(gssiam_hash, &projid,
						     sizeof(projid));
	gssiam_hash = lustre_hash_fnv_1a_64_continue(gssiam_hash,
						     &auth_permission,
						     sizeof(auth_permission));
	snprintf(nm_name, nm_size, "%llx", (unsigned long long)gssiam_hash);
}

#endif /* _LUSTRE_GSSIAM_H */
