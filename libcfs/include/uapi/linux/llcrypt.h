/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * llcrypt user API
 *
 * These ioctls can be used on filesystems that support llcrypt.  See the
 * "User API" section of Documentation/filesystems/llcrypt.rst.
 */
/*
 * Linux commit 219d54332a09
 * tags/v5.4
 */
#ifndef _UAPI_LINUX_LLCRYPT_H
#define _UAPI_LINUX_LLCRYPT_H

#include <linux/types.h>

/* Encryption policy flags */
#define LLCRYPT_POLICY_FLAGS_PAD_4		0x00
#define LLCRYPT_POLICY_FLAGS_PAD_8		0x01
#define LLCRYPT_POLICY_FLAGS_PAD_16		0x02
#define LLCRYPT_POLICY_FLAGS_PAD_32		0x03
#define LLCRYPT_POLICY_FLAGS_PAD_MASK		0x03
#define LLCRYPT_POLICY_FLAG_DIRECT_KEY		0x04
#define LLCRYPT_POLICY_FLAGS_VALID		0x07

/* Encryption algorithms */
#define LLCRYPT_MODE_NULL			0
#define LLCRYPT_MODE_AES_256_XTS		1
#define LLCRYPT_MODE_AES_256_CTS		4
#define LLCRYPT_MODE_AES_128_CBC		5
#define LLCRYPT_MODE_AES_128_CTS		6
#define LLCRYPT_MODE_ADIANTUM			9
#define __LLCRYPT_MODE_MAX			9

/*
 * Legacy policy version; ad-hoc KDF and no key verification.
 * For new encrypted directories, use llcrypt_policy_v2 instead.
 *
 * Careful: the .version field for this is actually 0, not 1.
 */
#define LLCRYPT_POLICY_V1		0
#define LLCRYPT_KEY_DESCRIPTOR_SIZE	8
struct llcrypt_policy_v1 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 master_key_descriptor[LLCRYPT_KEY_DESCRIPTOR_SIZE];
};
#define llcrypt_policy	llcrypt_policy_v1

/*
 * Process-subscribed "logon" key description prefix and payload format.
 * Deprecated; prefer LL_IOC_ADD_ENCRYPTION_KEY instead.
 */
#define LLCRYPT_KEY_DESC_PREFIX		"fscrypt:"
#define LLCRYPT_KEY_DESC_PREFIX_SIZE	8
#define LLCRYPT_MAX_KEY_SIZE		64
struct llcrypt_key {
	__u32 mode;
	__u8 raw[LLCRYPT_MAX_KEY_SIZE];
	__u32 size;
};

/*
 * New policy version with HKDF and key verification (recommended).
 */
#define LLCRYPT_POLICY_V2		2
#define LLCRYPT_KEY_IDENTIFIER_SIZE	16
struct llcrypt_policy_v2 {
	__u8 version;
	__u8 contents_encryption_mode;
	__u8 filenames_encryption_mode;
	__u8 flags;
	__u8 __reserved[4];
	__u8 master_key_identifier[LLCRYPT_KEY_IDENTIFIER_SIZE];
};

/* Struct passed to LL_IOC_GET_ENCRYPTION_POLICY_EX */
struct llcrypt_get_policy_ex_arg {
	__u64 policy_size; /* input/output */
	union {
		__u8 version;
		struct llcrypt_policy_v1 v1;
		struct llcrypt_policy_v2 v2;
	} policy; /* output */
};

/*
 * v1 policy keys are specified by an arbitrary 8-byte key "descriptor",
 * matching llcrypt_policy_v1::master_key_descriptor.
 */
#define LLCRYPT_KEY_SPEC_TYPE_DESCRIPTOR	1

/*
 * v2 policy keys are specified by a 16-byte key "identifier" which the kernel
 * calculates as a cryptographic hash of the key itself,
 * matching llcrypt_policy_v2::master_key_identifier.
 */
#define LLCRYPT_KEY_SPEC_TYPE_IDENTIFIER	2

/*
 * Specifies a key, either for v1 or v2 policies.  This doesn't contain the
 * actual key itself; this is just the "name" of the key.
 */
struct llcrypt_key_specifier {
	__u32 type;	/* one of LLCRYPT_KEY_SPEC_TYPE_* */
	__u32 __reserved;
	union {
		__u8 __reserved[32]; /* reserve some extra space */
		__u8 descriptor[LLCRYPT_KEY_DESCRIPTOR_SIZE];
		__u8 identifier[LLCRYPT_KEY_IDENTIFIER_SIZE];
	} u;
};

/* Struct passed to LL_IOC_ADD_ENCRYPTION_KEY */
struct llcrypt_add_key_arg {
	struct llcrypt_key_specifier key_spec;
	__u32 raw_size;
	__u32 __reserved[9];
	__u8 raw[];
};

/* Struct passed to LL_IOC_REMOVE_ENCRYPTION_KEY */
struct llcrypt_remove_key_arg {
	struct llcrypt_key_specifier key_spec;
#define LLCRYPT_KEY_REMOVAL_STATUS_FLAG_FILES_BUSY	0x00000001
#define LLCRYPT_KEY_REMOVAL_STATUS_FLAG_OTHER_USERS	0x00000002
	__u32 removal_status_flags;	/* output */
	__u32 __reserved[5];
};

/* Struct passed to LL_IOC_GET_ENCRYPTION_KEY_STATUS */
struct llcrypt_get_key_status_arg {
	/* input */
	struct llcrypt_key_specifier key_spec;
	__u32 __reserved[6];

	/* output */
#define LLCRYPT_KEY_STATUS_ABSENT		1
#define LLCRYPT_KEY_STATUS_PRESENT		2
#define LLCRYPT_KEY_STATUS_INCOMPLETELY_REMOVED	3
	__u32 status;
#define LLCRYPT_KEY_STATUS_FLAG_ADDED_BY_SELF   0x00000001
	__u32 status_flags;
	__u32 user_count;
	__u32 __out_reserved[13];
};

#define LL_IOC_SET_ENCRYPTION_POLICY		_IOR('f', 19, struct llcrypt_policy)
#define LL_IOC_GET_ENCRYPTION_PWSALT		_IOW('f', 20, __u8[16])
#define LL_IOC_GET_ENCRYPTION_POLICY		_IOW('f', 21, struct llcrypt_policy)
#define LL_IOC_GET_ENCRYPTION_POLICY_EX		_IOWR('f', 22, __u8[9]) /* size + version */
#define LL_IOC_ADD_ENCRYPTION_KEY		_IOWR('f', 23, struct llcrypt_add_key_arg)
#define LL_IOC_REMOVE_ENCRYPTION_KEY		_IOWR('f', 24, struct llcrypt_remove_key_arg)
#define LL_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS	_IOWR('f', 25, struct llcrypt_remove_key_arg)
#define LL_IOC_GET_ENCRYPTION_KEY_STATUS	_IOWR('f', 26, struct llcrypt_get_key_status_arg)

/**********************************************************************/

/* old names; don't add anything new here! */
#ifndef __KERNEL__
#define LL_KEY_DESCRIPTOR_SIZE		LLCRYPT_KEY_DESCRIPTOR_SIZE
#define LL_POLICY_FLAGS_PAD_4		LLCRYPT_POLICY_FLAGS_PAD_4
#define LL_POLICY_FLAGS_PAD_8		LLCRYPT_POLICY_FLAGS_PAD_8
#define LL_POLICY_FLAGS_PAD_16		LLCRYPT_POLICY_FLAGS_PAD_16
#define LL_POLICY_FLAGS_PAD_32		LLCRYPT_POLICY_FLAGS_PAD_32
#define LL_POLICY_FLAGS_PAD_MASK	LLCRYPT_POLICY_FLAGS_PAD_MASK
#define LL_POLICY_FLAG_DIRECT_KEY	LLCRYPT_POLICY_FLAG_DIRECT_KEY
#define LL_POLICY_FLAGS_VALID		LLCRYPT_POLICY_FLAGS_VALID
#define LL_ENCRYPTION_MODE_INVALID	0	/* never used */
#define LL_ENCRYPTION_MODE_AES_256_XTS	LLCRYPT_MODE_AES_256_XTS
#define LL_ENCRYPTION_MODE_AES_256_GCM	2	/* never used */
#define LL_ENCRYPTION_MODE_AES_256_CBC	3	/* never used */
#define LL_ENCRYPTION_MODE_AES_256_CTS	LLCRYPT_MODE_AES_256_CTS
#define LL_ENCRYPTION_MODE_AES_128_CBC	LLCRYPT_MODE_AES_128_CBC
#define LL_ENCRYPTION_MODE_AES_128_CTS	LLCRYPT_MODE_AES_128_CTS
#define LL_ENCRYPTION_MODE_SPECK128_256_XTS	7	/* removed */
#define LL_ENCRYPTION_MODE_SPECK128_256_CTS	8	/* removed */
#define LL_ENCRYPTION_MODE_ADIANTUM	LLCRYPT_MODE_ADIANTUM
#define LL_KEY_DESC_PREFIX		LLCRYPT_KEY_DESC_PREFIX
#define LL_KEY_DESC_PREFIX_SIZE		LLCRYPT_KEY_DESC_PREFIX_SIZE
#define LL_MAX_KEY_SIZE			LLCRYPT_MAX_KEY_SIZE
#endif /* !__KERNEL__ */

#endif /* _UAPI_LINUX_LLCRYPT_H */
