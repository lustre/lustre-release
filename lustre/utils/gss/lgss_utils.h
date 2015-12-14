/*
 * Modifications for Lustre
 *
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Author: Eric Mei <ericm@clusterfs.com>
 */

/*
  Copyright (c) 2004 The Regents of the University of Michigan.
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of the University nor the names of its
     contributors may be used to endorse or promote products derived
     from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef LGSS_UTILS_H
#define LGSS_UTILS_H

#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <gssapi/gssapi.h>

#include "lsupport.h"

#define LGSS_SVC_MGS_STR        "lustre_mgs"
#define LGSS_SVC_MDS_STR        "lustre_mds"
#define LGSS_SVC_OSS_STR        "lustre_oss"
#define LGSS_USR_ROOT_STR       "lustre_root"

typedef enum {
        LGSS_SVC_MGS    = 0,
        LGSS_SVC_MDS    = 1,
        LGSS_SVC_OSS    = 2,
        LGSS_SVC_MAX
} lgss_svc_t;

extern const char *lgss_svc_str[LGSS_SVC_MAX];

/****************************************
 * inter-process locking                *
 ****************************************/

typedef enum {
	LGSS_MUTEX_KRB5 = 0,
	LGSS_MUTEX_MAX
} lgss_mutex_id_t;

int lgss_mutex_lock(lgss_mutex_id_t mid);
int lgss_mutex_unlock(lgss_mutex_id_t mid);

/****************************************
 * log facilities                       *
 ****************************************/

/*
 * log level:
 * LL_ERR:      critical error messages
 * LL_WARN:     warning (default)
 * LL_INFO:     important infomation
 * LL_DEBUG:    debugging
 * LL_TRACE:    excessive tracing messages
 */
typedef enum {
        LL_ERR          = 0,
        LL_WARN         = 1,
        LL_INFO         = 2,
        LL_DEBUG        = 3,
        LL_TRACE        = 4,
        LL_MAX
} loglevel_t;

extern loglevel_t g_log_level;

void lgss_set_loglevel(loglevel_t level);

void __logmsg(loglevel_t level, const char *func, const char *format, ...)
	__attribute__((format(printf, 3, 4)));

void __logmsg_gss(loglevel_t level, const char *func, const gss_OID mech,
		  uint32_t major, uint32_t minor, const char *format, ...)
	__attribute__((format(printf, 6, 7)));

#define logmsg(loglevel, format, args...)                               \
do {                                                                    \
	if (loglevel <= g_log_level)					\
                __logmsg(loglevel, __FUNCTION__, format, ##args);       \
} while (0)

#define logmsg_gss(loglevel, mech, major, minor, format, args...)       \
do {                                                                    \
	if (loglevel <= g_log_level)					\
                __logmsg_gss(loglevel, __FUNCTION__, mech,              \
                             major, minor, format, ##args);             \
} while (0)

#define lassert(exp)                                                    \
do {                                                                    \
        if (!(exp)) {                                                   \
                logmsg(LL_ERR, "ASSERTION FAILED: %s", #exp);           \
                exit(-1);                                               \
        }                                                               \
} while (0)

/*
 * for compatible reason, we're using files (context_xxx.c) from nfs-utils
 */
#define printerr(priority, format, args...)                             \
        logmsg(priority, format, ##args)

#define pgsserr(msg, maj_stat, min_stat, mech)				\
	logmsg_gss(LL_ERR, mech, maj_stat, min_stat, msg)

/****************************************
 * GSS MECH, OIDs                       *
 ****************************************/

extern gss_OID_desc krb5oid;
extern gss_OID_desc spkm3oid;
extern gss_OID_desc nulloid;
extern gss_OID_desc skoid;

/****************************************
 * client credentials                   *
 ****************************************/

struct lgss_cred;

struct lgss_mech_type {
	char		*lmt_name;
	enum lgss_mech	 lmt_mech_n;

	int		 (*lmt_init)(void);
	void		 (*lmt_fini)(void);
	int		 (*lmt_prepare_cred)(struct lgss_cred *cred);
	void		 (*lmt_release_cred)(struct lgss_cred *cred);
	int		 (*lmt_using_cred)(struct lgss_cred *cred);
	int		 (*lmt_validate_cred)(struct lgss_cred *cred,
					      gss_buffer_desc *token,
					      gss_buffer_desc *ctx_token);
};

struct lgss_cred {
	int			lc_uid;
	unsigned int		lc_root_flags;
	uint64_t		lc_self_nid;
	uint64_t		lc_tgt_nid;
	uint32_t		lc_tgt_svc;
	char			lc_svc_type;
	char			*lc_tgt_uuid;

	struct lgss_mech_type	*lc_mech;
	void			*lc_mech_cred;
	gss_buffer_desc		lc_mech_token;
};

struct lgss_mech_type *lgss_name2mech(const char *mech_name);
int  lgss_mech_initialize(struct lgss_mech_type *mech);
void lgss_mech_finalize(struct lgss_mech_type *mech);

struct lgss_cred * lgss_create_cred(struct lgss_mech_type *mech);
void lgss_destroy_cred(struct lgss_cred *cred);
int lgss_prepare_cred(struct lgss_cred *cred);
void lgss_release_cred(struct lgss_cred *cred);
int lgss_using_cred(struct lgss_cred *cred);
int lgss_validate_cred(struct lgss_cred *cred, gss_buffer_desc *token,
		       gss_buffer_desc *ctx_token);

int lgss_get_service_str(char **string, uint32_t lsvc, uint64_t tgt_nid);

static inline
int gss_OID_equal(gss_OID_desc *oid1, gss_OID_desc *oid2)
{
        return (oid1->length == oid2->length &&
                memcmp(oid1->elements, oid2->elements, oid1->length) == 0);
}

#ifndef g_OID_equal
#define g_OID_equal(o1,o2)      gss_OID_equal((o1), (o2))
#endif

#endif /* LGSS_UTILS_H */
