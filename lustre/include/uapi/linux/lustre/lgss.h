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
 * Copyright (c) 2022, Whamcloud.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _LGSS_H
#define _LGSS_H

#ifndef __KERNEL__
# define __USE_ISOC99	1
# include <stdio.h> /* snprintf() */
# include <stdlib.h> /* abs() */
# include <inttypes.h> /* PRIu64 */
# include <ctype.h> /* isascii() */
# define __USE_GNU      1
# define __USE_XOPEN2K8  1
#else
#include <linux/ctype.h>
#define PRIu64 "llu"
#define PRIx64 "llx"
#endif /* !__KERNEL__ */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/unistd.h>

/*
 * sparse kernel source annotations
 */
#ifndef __user
#define __user
#endif

struct lgssd_ioctl_param {
	/* in */
	__u32 version;
	__u32 secid;
	char __user *uuid;
	__u32 lustre_svc;
	__kernel_uid_t uid;
	__kernel_gid_t gid;
	__u64 send_token_size;
	char __user *send_token;
	__u64 reply_buf_size;
	char __user *reply_buf;
	/* out */
	__s64 status;
	__u64 reply_length;
};

#define GSS_SOCKET_PATH	"/tmp/svcgssd.socket"
/*
 * Old RSI_DOWNCALL_MAGIC was:
 * #define RSI_DOWNCALL_MAGIC	0x6d6dd62a
 *
 * This is an uapi and to catch cases like kernel modules
 * being updated separately from user tools new
 * RSI_DOWNCALL_MAGIC(0x6d6dd63a) was introduced
 */
#define RSI_DOWNCALL_MAGIC	0x6d6dd63a
#define RSI_DOWNCALL_PATH	"sptlrpc/gss/rsi_info"
#define RSI_CACHE_NAME		"rsicache"

struct rsi_downcall_data {
	__u32	  sid_magic;
	__u32	  sid_err;
	__u32	  sid_unused;
	__u32	  sid_maj_stat;
	__u32	  sid_min_stat;
	__u32	  sid_len;
	__s64	  sid_offset;
	__u64	  sid_hash;
	/* sid_val contains in_handle, in_token,
	 * out_handle, out_token
	 */
	char	  sid_val[];
};

#define RSC_DOWNCALL_MAGIC	0x6d6dd62b
#define RSC_DOWNCALL_PATH	"sptlrpc/gss/rsc_info"
#define RSC_CACHE_NAME		"rsccache"

/* rsc_downcall_data flags */
enum scd_flag_bits {
	RSC_DATA_FLAG_REMOTE	= 0x0001,
	RSC_DATA_FLAG_ROOT	= 0x0002,
	RSC_DATA_FLAG_MDS	= 0x0004,
	RSC_DATA_FLAG_OSS	= 0x0008,
};

struct rsc_downcall_data {
	__u32		scd_magic;
	__u32		scd_err;
	__u32		scd_flags;
	__u32		scd_mapped_uid;
	__u32		scd_uid;
	__u32		scd_gid;
	char		scd_mechname[8];
	__s64		scd_offset;
	__u32		scd_len;
	__u32		scd_padding;
	/* scd_val contains handle and context token */
	char		scd_val[];
};

/*
 * gss_string_write() - write some string
 *
 * If string is empty, write single digit 0.
 * Pad with a trailing space.
 */
static inline void gss_string_write(char **dst, int *dstlen, const char *src)
{
	char *cp = *dst;
	int ret;

	if (*dstlen < 0)
		return;

	if (!strlen(src))
		ret = snprintf(cp, *dstlen, "0");
	else
		ret = snprintf(cp, *dstlen, "%s", src);
	if (ret >= *dstlen) {
		cp += *dstlen;
		*dstlen = -1;
	} else {
		cp[ret] = ' ';
		cp += ret + 1;
		*dstlen -= ret + 1;
	}
	*dst = cp;
}

/*
 * gss_u64_write() - write some u64
 */
static inline void gss_u64_write_string(char **dst, int *dstlen, uint64_t n)
{
	char *cp = *dst;
	int ret;

	if (*dstlen < 0)
		return;

	ret = snprintf(cp, *dstlen, "%"PRIu64, n);
	if (ret >= *dstlen) {
		cp += *dstlen;
		*dstlen = -1;
	} else {
		cp[ret] = ' ';
		cp += ret + 1;
		*dstlen -= ret + 1;
	}
	*dst = cp;
}

/*
 * gss_u64_write_hex() - write some u64 in hex
 */
static inline void gss_u64_write_hex_string(char **dst, int *dstlen, uint64_t n)
{
	char *cp = *dst;
	int ret;

	if (*dstlen < 0)
		return;

	ret = snprintf(cp, *dstlen, "0x%"PRIx64, n);
	if (ret >= *dstlen) {
		cp += *dstlen;
		*dstlen = -1;
	} else {
		cp[ret] = ' ';
		cp += ret + 1;
		*dstlen -= ret + 1;
	}
	*dst = cp;
}

/*
 * gss_buffer_write() - write some buffer
 */
static inline void gss_buffer_write(char **dst, int *dstlen,
				    const __u8 *src, int srclen)
{
	char *cp = *dst;
	int len = *dstlen;
	__u32 *p;

	if (len < 0)
		return;

	if (len < sizeof(__u32)) {
		len = -1;
		goto out;
	}

	/* write size of data */
	p = (__u32 *)cp;
	*p = srclen;
	cp += sizeof(__u32);
	len -= sizeof(__u32);

	if (!srclen)
		goto out;

	/* write data itself */
	while (srclen && len) {
		*cp++ = *src++;
		len--;
		srclen--;
	}
	if (!len && srclen)
		len = -1;

out:
	*dst = cp;
	*dstlen = len;
}

/*
 * gss_u32_write() - write some u32
 */
static inline void gss_u32_write(char **dst, int *dstlen, __u32 val)
{
	char *cp = *dst;
	int len = *dstlen;
	__u32 *p;

	if (len < 0)
		return;

	if (len < sizeof(__u32)) {
		len = -1;
		goto out;
	}

	p = (__u32 *)cp;
	*p = val;
	cp += sizeof(__u32);
	len -= sizeof(__u32);

out:
	*dst = cp;
	*dstlen = len;
}

static const char base64url_table[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#define BASE64URL_CHARS(nbytes) ((((nbytes) * 4) + 3 - 1) / 3)

/*
 * gss_base64url_encode() - base64url-encode some binary data
 *
 * Encode data using base64url encoding, i.e. the "Base 64 Encoding with URL
 * and Filename Safe Alphabet" specified by RFC 4648.  '='-padding isn't used,
 * as it's unneeded and not required by the RFC.
 * Pad with a trailing space.
 */
static inline void gss_base64url_encode(char **dst, int *dstlen,
					const __u8 *src, int srclen)
{
	char *cp = *dst;
	int len = *dstlen;
	__u32 ac = 0;
	int bits = 0;
	int i;

	if (len < 0)
		return;

	if (!srclen)
		return gss_string_write(dst, dstlen, "");

	for (i = 0; i < srclen; i++) {
		if (!len)
			break;
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64url_table[(ac >> bits) & 0x3f];
			len--;
		} while (bits >= 6 && len > 0);
	}
	if (i < srclen) {
		len = -1;
		goto out;
	}

	if (bits) {
		*cp++ = base64url_table[(ac << (6 - bits)) & 0x3f];
		len--;
	}

	if (!len) {
		len = -1;
		goto out;
	}
	*cp++ = ' ';
	len--;

out:
	*dst = cp;
	*dstlen = len;
}

/*
 * gss_base64url_decode() - base64url-decode a string
 *
 * Decode a string using base64url encoding, i.e. the "Base 64 Encoding with
 * URL and Filename Safe Alphabet" specified by RFC 4648.  '='-padding isn't
 * accepted, nor are non-encoding characters such as whitespace.
 * String end is marked with a trailing space or '\n' or '\0'.
 */
static inline int gss_base64url_decode(char **src, char *dst, int destsize)
{
	int bits = 0, len = 0;
	char *cp = *src, *p;
	char *bp = dst;
	__u32 ac = 0;

	while (*cp == ' ')
		cp++;

	/* the single digit 0 is inserted if field is empty */
	if (*cp == '0' &&
	    (*(cp + 1) == ' ' || *(cp + 1) == '\n' || *(cp + 1) == '\0')) {
		cp++;
		goto fini;
	}

	while (isascii(*cp)) {
		if (*cp == ' ' || *cp == '\n' || *cp == '\0')
			break;

		p = strchr(base64url_table, *cp);
		if (len > destsize || p == NULL || *cp == '\0') {
			len = -1;
			goto out;
		}

		cp++;
		ac = (ac << 6) | (p - base64url_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (__u8)(ac >> bits);
			len++;
		}
	}

	if (!isascii(*cp) || (ac & ((1 << bits) - 1))) {
		len = -1;
		goto out;
	}

fini:
	*src = cp;
out:
	return len;
}

/*
 * gss_string_read() - read some string
 *
 * An empty string is represented with the single digit 0.
 * String end is marked with a trailing space or '\n' or '\0'.
 */
static inline int gss_string_read(char **src, char *dst, int destsize,
				  int allowzero)
{
	char *cp = *src;
	char *bp = dst;
	int len = 0;

	while (*cp == ' ')
		cp++;

	/* the single digit 0 is inserted if field is empty */
	if (!allowzero && *cp == '0' &&
	    (*(cp + 1) == ' ' || *(cp + 1) == '\n')) {
		cp++;
		goto out;
	}

	while (isascii(*cp)) {
		if (*cp == ' ' || *cp == '\n')
			break;

		if (len >= destsize || *cp == '\0') {
			len = -1;
			goto out;
		}

		*(bp++) = *(cp++);
		len++;
	}

	if (!isascii(*cp)) {
		len = -1;
		goto out;
	}

	*src = cp;

out:
	return len;
}

#ifndef __KERNEL__
/*
 * gss_u64_read() - read some u64
 */
static inline int gss_u64_read_string(char **src, __u64 *n)
{
	char buf[24];
	char *ep;
	int ret;

	ret = gss_string_read(src, buf, sizeof(buf), 1);
	if (ret < 0)
		return ret;

	buf[ret] = '\0';
	*n = strtoull(buf, &ep, 0);
	if (*ep)
		return -1;

	return 0;
}
#endif

/*
 * gss_buffer_read() - read some buffer
 */
static inline int gss_buffer_read(char **src, char *dst, int destsize)
{
	char *cp = *src;
	char *bp = dst;
	__u32 *p;
	int len, size;

	/* read data size */
	p = (__u32 *)cp;
	len = *p;
	cp += sizeof(__u32);

	if (len > destsize) {
		len = -1;
		goto out;
	}

	if (!len)
		goto fini;

	/* read data itself */
	size = len;
	while (size && destsize) {
		*(bp++) = *(cp++);
		destsize--;
		size--;
	}
	if (!destsize && size)
		len = -1;

fini:
	*src = cp;
out:
	return len;
}

/*
 * gss_buffer_get() - get reference to gss buffer
 */
static inline int gss_buffer_get(char **src, __u32 *len, __u8 **data)
{
	char *cp = *src;
	__u32 *p;

	/* read data size */
	p = (__u32 *)cp;
	*len = *p;
	cp += sizeof(__u32);

	/* point to data buf */
	if (!*len)
		*data = NULL;
	else
		*data = (__u8 *)cp;

	/* move forward */
	cp += *len;

	*src = cp;
	return *len;
}

/*
 * gss_u32_read() - read some u32
 */
static inline int gss_u32_read(char **src, __u32 *val)
{
	char *cp = *src;
	__u32 *p;

	p = (__u32 *)cp;
	*val = *p;
	cp += sizeof(__u32);

	*src = cp;
	return 0;
}

#endif /* _LGSS_H */
