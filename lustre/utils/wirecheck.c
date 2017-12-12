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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2016, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <lustre/lustre_idl.h>
#include <lustre/lustre_lfsck_user.h>
#include <linux/lustre_disk.h>

#define BLANK_LINE()						\
do {								\
	printf("\n");						\
} while(0)

#define COMMENT(c)						\
do {								\
	printf("	/* "c" */\n");				\
} while(0)

#define STRINGIFY(a) #a

#define CHECK_CDEFINE(a)					\
	printf("	CLASSERT("#a" == "STRINGIFY(a) ");\n")

#define CHECK_CVALUE(a)					 \
	printf("	CLASSERT("#a" == %lld);\n", (long long)a)

#define CHECK_CVALUE_X(a)					\
	printf("	CLASSERT("#a" == 0x%.8x);\n", a)

#define CHECK_DEFINE(a)						\
do {								\
	printf("	LASSERTF("#a" == "STRINGIFY(a)		\
		", \"found %%lld\\n\",\n			"\
		"(long long)"#a");\n");				\
} while(0)

#define CHECK_DEFINE_X(a)					\
do {								\
	printf("	LASSERTF("#a" == "STRINGIFY(a)		\
		", \"found 0x%%.8x\\n\",\n		"#a	\
		");\n");					\
} while(0)

#define CHECK_DEFINE_64X(a)					\
do {								\
	printf("	LASSERTF("#a" == "STRINGIFY(a)		\
		", \"found 0x%%.16llxULL\\n\",\n		"\
		" "#a");\n");					\
} while(0)

#define CHECK_VALUE(a)						\
do {								\
	printf("	LASSERTF("#a				\
		" == %lld, \"found %%lld\\n\",\n		"\
		" (long long)"#a");\n", (long long)a);		\
} while(0)

#define CHECK_VALUE_X(a)					\
do {								\
	printf("	LASSERTF("#a				\
		" == 0x%.8xUL, \"found 0x%%.8xUL\\n\",\n	"\
		"	(unsigned)"#a");\n", (unsigned)a);	\
} while(0)

#define CHECK_VALUE_O(a)					\
do {								\
	printf("	LASSERTF("#a				\
		" == 0%.11oUL, \"found 0%%.11oUL\\n\",\n	"\
		"	"#a");\n", a);				\
} while(0)

#define CHECK_VALUE_64X(a)					\
do {								\
	printf("	LASSERTF("#a" == 0x%.16llxULL, "	\
		"\"found 0x%%.16llxULL\\n\",\n			"\
		"(long long)"#a");\n", (long long)a);		\
} while(0)

#define CHECK_VALUE_64O(a)					\
do {								\
	printf("	LASSERTF("#a" == 0%.22lloULL, "		\
		"\"found 0%%.22lloULL\\n\",\n			"\
		"(long long)"#a");\n", (long long)a);		\
} while(0)

#define CHECK_MEMBER_OFFSET(s, m)				\
do {								\
	CHECK_VALUE((int)offsetof(struct s, m));		\
} while(0)

#define CHECK_MEMBER_OFFSET_TYPEDEF(s, m)			\
do {								\
	CHECK_VALUE((int)offsetof(s, m));			\
} while(0)

#define CHECK_MEMBER_SIZEOF(s, m)				\
do {								\
	CHECK_VALUE((int)sizeof(((struct s *)0)->m));		\
} while(0)

#define CHECK_MEMBER_SIZEOF_TYPEDEF(s, m)			\
do {								\
	CHECK_VALUE((int)sizeof(((s *)0)->m));			\
} while(0)

#define CHECK_MEMBER(s, m)					\
do {								\
	CHECK_MEMBER_OFFSET(s, m);				\
	CHECK_MEMBER_SIZEOF(s, m);				\
} while(0)

#define CHECK_MEMBER_TYPEDEF(s, m)				\
do {								\
	CHECK_MEMBER_OFFSET_TYPEDEF(s, m);			\
	CHECK_MEMBER_SIZEOF_TYPEDEF(s, m);			\
} while(0)

#define CHECK_STRUCT(s)						\
do {								\
	COMMENT("Checks for struct "#s);			\
		CHECK_VALUE((int)sizeof(struct s));		\
} while(0)

#define CHECK_STRUCT_TYPEDEF(s)					\
do {								\
	COMMENT("Checks for type "#s);				\
		CHECK_VALUE((int)sizeof(s));			\
} while(0)

#define CHECK_UNION(s)						\
do {								\
	COMMENT("Checks for union "#s);				\
	CHECK_VALUE((int)sizeof(union s));			\
} while(0)

#define CHECK_VALUE_SAME(v1, v2)				\
do {								\
	printf("\tLASSERTF("#v1" == "#v2", "			\
		"\"%%d != %%d\\n\",\n"				\
		"\t\t "#v1", "#v2");\n");			\
} while (0)

#define CHECK_MEMBER_SAME(s1, s2, m)				\
do {								\
	CHECK_VALUE_SAME((int)offsetof(struct s1, m),		\
			 (int)offsetof(struct s2, m));		\
	CHECK_VALUE_SAME((int)sizeof(((struct s1 *)0)->m),	\
			 (int)sizeof(((struct s2 *)0)->m));	\
} while (0)

static void
check_lu_seq_range(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lu_seq_range);
	CHECK_MEMBER(lu_seq_range, lsr_start);
	CHECK_MEMBER(lu_seq_range, lsr_end);
	CHECK_MEMBER(lu_seq_range, lsr_index);
	CHECK_MEMBER(lu_seq_range, lsr_flags);

	CHECK_VALUE(LU_SEQ_RANGE_MDT);
	CHECK_VALUE(LU_SEQ_RANGE_OST);
}

static void
check_lustre_mdt_attrs(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lustre_mdt_attrs);
	CHECK_MEMBER(lustre_mdt_attrs, lma_compat);
	CHECK_MEMBER(lustre_mdt_attrs, lma_incompat);
	CHECK_MEMBER(lustre_mdt_attrs, lma_self_fid);

	CHECK_VALUE_X(LMAC_HSM);
	CHECK_VALUE_X(LMAC_NOT_IN_OI);
	CHECK_VALUE_X(LMAC_FID_ON_OST);
	CHECK_VALUE_X(LMAC_STRIPE_INFO);
	CHECK_VALUE_X(LMAC_COMP_INFO);

	CHECK_VALUE_X(LMAI_RELEASED);
	CHECK_VALUE_X(LMAI_AGENT);
	CHECK_VALUE_X(LMAI_REMOTE_PARENT);
	CHECK_VALUE_X(LMAI_STRIPED);
	CHECK_VALUE_X(LMAI_ORPHAN);
}

static void
check_lustre_ost_attrs(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lustre_ost_attrs);
	CHECK_MEMBER(lustre_ost_attrs, loa_lma);
	CHECK_MEMBER(lustre_ost_attrs, loa_parent_fid);
	CHECK_MEMBER(lustre_ost_attrs, loa_stripe_size);
	CHECK_MEMBER(lustre_ost_attrs, loa_comp_id);
	CHECK_MEMBER(lustre_ost_attrs, loa_comp_start);
	CHECK_MEMBER(lustre_ost_attrs, loa_comp_end);
}

static void
check_hsm_attrs(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_attrs);
	CHECK_MEMBER(hsm_attrs, hsm_compat);
	CHECK_MEMBER(hsm_attrs, hsm_flags);
	CHECK_MEMBER(hsm_attrs, hsm_arch_id);
	CHECK_MEMBER(hsm_attrs, hsm_arch_ver);
}

static void
check_ost_id(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ost_id);
	CHECK_MEMBER(ost_id, oi);

	CHECK_VALUE(LUSTRE_FID_INIT_OID);

	CHECK_VALUE(FID_SEQ_OST_MDT0);
	CHECK_VALUE(FID_SEQ_LLOG);
	CHECK_VALUE(FID_SEQ_ECHO);
	CHECK_VALUE(FID_SEQ_UNUSED_START);
	CHECK_VALUE(FID_SEQ_UNUSED_END);
	CHECK_VALUE(FID_SEQ_RSVD);
	CHECK_VALUE(FID_SEQ_IGIF);
	CHECK_VALUE_64X(FID_SEQ_IGIF_MAX);
	CHECK_VALUE_64X(FID_SEQ_IDIF);
	CHECK_VALUE_64X(FID_SEQ_IDIF_MAX);
	CHECK_VALUE_64X(FID_SEQ_START);
	CHECK_VALUE_64X(FID_SEQ_LOCAL_FILE);
	CHECK_VALUE_64X(FID_SEQ_DOT_LUSTRE);
	CHECK_VALUE_64X(FID_SEQ_SPECIAL);
	CHECK_VALUE_64X(FID_SEQ_QUOTA);
	CHECK_VALUE_64X(FID_SEQ_QUOTA_GLB);
	CHECK_VALUE_64X(FID_SEQ_ROOT);
	CHECK_VALUE_64X(FID_SEQ_LAYOUT_RBTREE);
	CHECK_VALUE_64X(FID_SEQ_UPDATE_LOG);
	CHECK_VALUE_64X(FID_SEQ_UPDATE_LOG_DIR);
	CHECK_VALUE_64X(FID_SEQ_NORMAL);
	CHECK_VALUE_64X(FID_SEQ_LOV_DEFAULT);

	CHECK_VALUE_X(FID_OID_SPECIAL_BFL);
	CHECK_VALUE_X(FID_OID_DOT_LUSTRE);
	CHECK_VALUE_X(FID_OID_DOT_LUSTRE_OBF);
}

static void
check_lu_dirent(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lu_dirent);
	CHECK_MEMBER(lu_dirent, lde_fid);
	CHECK_MEMBER(lu_dirent, lde_hash);
	CHECK_MEMBER(lu_dirent, lde_reclen);
	CHECK_MEMBER(lu_dirent, lde_namelen);
	CHECK_MEMBER(lu_dirent, lde_attrs);
	CHECK_MEMBER(lu_dirent, lde_name[0]);

	CHECK_VALUE_X(LUDA_FID);
	CHECK_VALUE_X(LUDA_TYPE);
	CHECK_VALUE_X(LUDA_64BITHASH);
}

static void
check_luda_type(void)
{
	BLANK_LINE();
	CHECK_STRUCT(luda_type);
	CHECK_MEMBER(luda_type, lt_type);
}

static void
check_lu_dirpage(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lu_dirpage);
	CHECK_MEMBER(lu_dirpage, ldp_hash_start);
	CHECK_MEMBER(lu_dirpage, ldp_hash_end);
	CHECK_MEMBER(lu_dirpage, ldp_flags);
	CHECK_MEMBER(lu_dirpage, ldp_pad0);
	CHECK_MEMBER(lu_dirpage, ldp_entries[0]);

	CHECK_VALUE(LDF_EMPTY);
	CHECK_VALUE(LDF_COLLIDE);
	CHECK_VALUE(LU_PAGE_SIZE);
	CHECK_UNION(lu_page);
}

static void
check_lu_ladvise(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lu_ladvise);
	CHECK_MEMBER(lu_ladvise, lla_advice);
	CHECK_MEMBER(lu_ladvise, lla_value1);
	CHECK_MEMBER(lu_ladvise, lla_value2);
	CHECK_MEMBER(lu_ladvise, lla_start);
	CHECK_MEMBER(lu_ladvise, lla_end);
	CHECK_MEMBER(lu_ladvise, lla_value3);
	CHECK_MEMBER(lu_ladvise, lla_value4);
	CHECK_VALUE(LU_LADVISE_WILLREAD);
	CHECK_VALUE(LU_LADVISE_DONTNEED);
}

static void
check_ladvise_hdr(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ladvise_hdr);
	CHECK_MEMBER(ladvise_hdr, lah_magic);
	CHECK_MEMBER(ladvise_hdr, lah_count);
	CHECK_MEMBER(ladvise_hdr, lah_flags);
	CHECK_MEMBER(ladvise_hdr, lah_value1);
	CHECK_MEMBER(ladvise_hdr, lah_value2);
	CHECK_MEMBER(ladvise_hdr, lah_value3);
	CHECK_MEMBER(ladvise_hdr, lah_advise);

	CHECK_VALUE(LF_ASYNC);
	CHECK_VALUE(LADVISE_MAGIC);
}

static void
check_lustre_handle(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lustre_handle);
	CHECK_MEMBER(lustre_handle, cookie);
}

static void
check_lustre_msg_v2(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lustre_msg_v2);
	CHECK_MEMBER(lustre_msg_v2, lm_bufcount);
	CHECK_MEMBER(lustre_msg_v2, lm_secflvr);
	CHECK_MEMBER(lustre_msg_v2, lm_magic);
	CHECK_MEMBER(lustre_msg_v2, lm_repsize);
	CHECK_MEMBER(lustre_msg_v2, lm_cksum);
	CHECK_MEMBER(lustre_msg_v2, lm_flags);
	CHECK_MEMBER(lustre_msg_v2, lm_padding_2);
	CHECK_MEMBER(lustre_msg_v2, lm_padding_3);
	CHECK_MEMBER(lustre_msg_v2, lm_buflens[0]);

	CHECK_DEFINE_X(LUSTRE_MSG_MAGIC_V2);
	CHECK_DEFINE_X(LUSTRE_MSG_MAGIC_V2_SWABBED);
}

static void
check_ptlrpc_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ptlrpc_body);
	CHECK_MEMBER(ptlrpc_body, pb_handle);
	CHECK_MEMBER(ptlrpc_body, pb_type);
	CHECK_MEMBER(ptlrpc_body, pb_version);
	CHECK_MEMBER(ptlrpc_body, pb_opc);
	CHECK_MEMBER(ptlrpc_body, pb_status);
	CHECK_MEMBER(ptlrpc_body, pb_last_xid);
	CHECK_MEMBER(ptlrpc_body, pb_tag);
	CHECK_MEMBER(ptlrpc_body, pb_padding0);
	CHECK_MEMBER(ptlrpc_body, pb_padding1);
	CHECK_MEMBER(ptlrpc_body, pb_last_committed);
	CHECK_MEMBER(ptlrpc_body, pb_transno);
	CHECK_MEMBER(ptlrpc_body, pb_flags);
	CHECK_MEMBER(ptlrpc_body, pb_op_flags);
	CHECK_MEMBER(ptlrpc_body, pb_conn_cnt);
	CHECK_MEMBER(ptlrpc_body, pb_timeout);
	CHECK_MEMBER(ptlrpc_body, pb_service_time);
	CHECK_MEMBER(ptlrpc_body, pb_limit);
	CHECK_MEMBER(ptlrpc_body, pb_slv);
	CHECK_CVALUE(PTLRPC_NUM_VERSIONS);
	CHECK_MEMBER(ptlrpc_body, pb_pre_versions);
	CHECK_MEMBER(ptlrpc_body, pb_mbits);
	CHECK_MEMBER(ptlrpc_body, pb_padding64_0);
	CHECK_MEMBER(ptlrpc_body, pb_padding64_1);
	CHECK_MEMBER(ptlrpc_body, pb_padding64_2);
	CHECK_CVALUE(LUSTRE_JOBID_SIZE);
	CHECK_MEMBER(ptlrpc_body, pb_jobid);

	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_handle);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_type);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_version);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_opc);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_status);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_last_xid);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_tag);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_padding0);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_padding1);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_last_committed);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_transno);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_flags);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_op_flags);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_conn_cnt);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_timeout);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_service_time);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_limit);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_slv);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_pre_versions);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_mbits);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_padding64_0);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_padding64_1);
	CHECK_MEMBER_SAME(ptlrpc_body_v3, ptlrpc_body_v2, pb_padding64_2);

	CHECK_VALUE(MSG_PTLRPC_BODY_OFF);
	CHECK_VALUE(REQ_REC_OFF);
	CHECK_VALUE(REPLY_REC_OFF);
	CHECK_VALUE(DLM_LOCKREQ_OFF);
	CHECK_VALUE(DLM_REQ_REC_OFF);
	CHECK_VALUE(DLM_INTENT_IT_OFF);
	CHECK_VALUE(DLM_INTENT_REC_OFF);
	CHECK_VALUE(DLM_LOCKREPLY_OFF);
	CHECK_VALUE(DLM_REPLY_REC_OFF);
	CHECK_VALUE(MSG_PTLRPC_HEADER_OFF);

	CHECK_DEFINE_X(PTLRPC_MSG_VERSION);
	CHECK_DEFINE_X(LUSTRE_VERSION_MASK);
	CHECK_DEFINE_X(LUSTRE_OBD_VERSION);
	CHECK_DEFINE_X(LUSTRE_MDS_VERSION);
	CHECK_DEFINE_X(LUSTRE_OST_VERSION);
	CHECK_DEFINE_X(LUSTRE_DLM_VERSION);
	CHECK_DEFINE_X(LUSTRE_LOG_VERSION);
	CHECK_DEFINE_X(LUSTRE_MGS_VERSION);

	CHECK_VALUE(MSGHDR_AT_SUPPORT);
	CHECK_VALUE(MSGHDR_CKSUM_INCOMPAT18);

	CHECK_VALUE_X(MSG_OP_FLAG_MASK);
	CHECK_VALUE(MSG_OP_FLAG_SHIFT);
	CHECK_VALUE_X(MSG_GEN_FLAG_MASK);

	CHECK_VALUE_X(MSG_LAST_REPLAY);
	CHECK_VALUE_X(MSG_RESENT);
	CHECK_VALUE_X(MSG_REPLAY);
	CHECK_VALUE_X(MSG_DELAY_REPLAY);
	CHECK_VALUE_X(MSG_VERSION_REPLAY);
	CHECK_VALUE_X(MSG_REQ_REPLAY_DONE);
	CHECK_VALUE_X(MSG_LOCK_REPLAY_DONE);

	CHECK_VALUE_X(MSG_CONNECT_RECOVERING);
	CHECK_VALUE_X(MSG_CONNECT_RECONNECT);
	CHECK_VALUE_X(MSG_CONNECT_REPLAYABLE);
	CHECK_VALUE_X(MSG_CONNECT_LIBCLIENT);
	CHECK_VALUE_X(MSG_CONNECT_INITIAL);
	CHECK_VALUE_X(MSG_CONNECT_ASYNC);
	CHECK_VALUE_X(MSG_CONNECT_NEXT_VER);
	CHECK_VALUE_X(MSG_CONNECT_TRANSNO);
}

/* XXX README XXX:
 * Please DO NOT add flag values here before first ensuring that this same
 * flag value is not in use on some other branch.  Please clear any such
 * changes with senior engineers before starting to use a new flag.  Then,
 * submit a small patch against EVERY branch that ONLY adds the new flag,
 * updates obd_connect_names[] for lprocfs_rd_connect_flags(), adds the
 * flag to check_obd_connect_data(), and updates wiretests accordingly, so it
 * can be approved and landed easily to reserve the flag for future use. */
static void
check_obd_connect_data(void)
{
	BLANK_LINE();
	CHECK_STRUCT(obd_connect_data);
	CHECK_MEMBER(obd_connect_data, ocd_connect_flags);
	CHECK_MEMBER(obd_connect_data, ocd_version);
	CHECK_MEMBER(obd_connect_data, ocd_grant);
	CHECK_MEMBER(obd_connect_data, ocd_index);
	CHECK_MEMBER(obd_connect_data, ocd_brw_size);
	CHECK_MEMBER(obd_connect_data, ocd_ibits_known);
	CHECK_MEMBER(obd_connect_data, ocd_grant_blkbits);
	CHECK_MEMBER(obd_connect_data, ocd_grant_inobits);
	CHECK_MEMBER(obd_connect_data, ocd_grant_tax_kb);
	CHECK_MEMBER(obd_connect_data, ocd_grant_max_blks);
	CHECK_MEMBER(obd_connect_data, ocd_transno);
	CHECK_MEMBER(obd_connect_data, ocd_group);
	CHECK_MEMBER(obd_connect_data, ocd_cksum_types);
	CHECK_MEMBER(obd_connect_data, ocd_max_easize);
	CHECK_MEMBER(obd_connect_data, ocd_instance);
	CHECK_MEMBER(obd_connect_data, ocd_maxbytes);
	CHECK_MEMBER(obd_connect_data, ocd_maxmodrpcs);
	CHECK_MEMBER(obd_connect_data, padding0);
	CHECK_MEMBER(obd_connect_data, padding1);
	CHECK_MEMBER(obd_connect_data, ocd_connect_flags2);
	CHECK_MEMBER(obd_connect_data, padding3);
	CHECK_MEMBER(obd_connect_data, padding4);
	CHECK_MEMBER(obd_connect_data, padding5);
	CHECK_MEMBER(obd_connect_data, padding6);
	CHECK_MEMBER(obd_connect_data, padding7);
	CHECK_MEMBER(obd_connect_data, padding8);
	CHECK_MEMBER(obd_connect_data, padding9);
	CHECK_MEMBER(obd_connect_data, paddingA);
	CHECK_MEMBER(obd_connect_data, paddingB);
	CHECK_MEMBER(obd_connect_data, paddingC);
	CHECK_MEMBER(obd_connect_data, paddingD);
	CHECK_MEMBER(obd_connect_data, paddingE);
	CHECK_MEMBER(obd_connect_data, paddingF);

	CHECK_DEFINE_64X(OBD_CONNECT_RDONLY);
	CHECK_DEFINE_64X(OBD_CONNECT_INDEX);
	CHECK_DEFINE_64X(OBD_CONNECT_MDS);
	CHECK_DEFINE_64X(OBD_CONNECT_GRANT);
	CHECK_DEFINE_64X(OBD_CONNECT_SRVLOCK);
	CHECK_DEFINE_64X(OBD_CONNECT_VERSION);
	CHECK_DEFINE_64X(OBD_CONNECT_REQPORTAL);
	CHECK_DEFINE_64X(OBD_CONNECT_ACL);
	CHECK_DEFINE_64X(OBD_CONNECT_XATTR);
	CHECK_DEFINE_64X(OBD_CONNECT_LARGE_ACL);
	CHECK_DEFINE_64X(OBD_CONNECT_TRUNCLOCK);
	CHECK_DEFINE_64X(OBD_CONNECT_TRANSNO);
	CHECK_DEFINE_64X(OBD_CONNECT_IBITS);
	CHECK_DEFINE_64X(OBD_CONNECT_BARRIER);
	CHECK_DEFINE_64X(OBD_CONNECT_ATTRFID);
	CHECK_DEFINE_64X(OBD_CONNECT_NODEVOH);
	CHECK_DEFINE_64X(OBD_CONNECT_RMT_CLIENT);
	CHECK_DEFINE_64X(OBD_CONNECT_RMT_CLIENT_FORCE);
	CHECK_DEFINE_64X(OBD_CONNECT_BRW_SIZE);
	CHECK_DEFINE_64X(OBD_CONNECT_QUOTA64);
	CHECK_DEFINE_64X(OBD_CONNECT_MDS_CAPA);
	CHECK_DEFINE_64X(OBD_CONNECT_OSS_CAPA);
	CHECK_DEFINE_64X(OBD_CONNECT_CANCELSET);
	CHECK_DEFINE_64X(OBD_CONNECT_SOM);
	CHECK_DEFINE_64X(OBD_CONNECT_AT);
	CHECK_DEFINE_64X(OBD_CONNECT_LRU_RESIZE);
	CHECK_DEFINE_64X(OBD_CONNECT_MDS_MDS);
	CHECK_DEFINE_64X(OBD_CONNECT_REAL);
	CHECK_DEFINE_64X(OBD_CONNECT_CHANGE_QS);
	CHECK_DEFINE_64X(OBD_CONNECT_CKSUM);
	CHECK_DEFINE_64X(OBD_CONNECT_FID);
	CHECK_DEFINE_64X(OBD_CONNECT_VBR);
	CHECK_DEFINE_64X(OBD_CONNECT_LOV_V3);
	CHECK_DEFINE_64X(OBD_CONNECT_GRANT_SHRINK);
	CHECK_DEFINE_64X(OBD_CONNECT_SKIP_ORPHAN);
	CHECK_DEFINE_64X(OBD_CONNECT_MAX_EASIZE);
	CHECK_DEFINE_64X(OBD_CONNECT_FULL20);
	CHECK_DEFINE_64X(OBD_CONNECT_LAYOUTLOCK);
	CHECK_DEFINE_64X(OBD_CONNECT_64BITHASH);
	CHECK_DEFINE_64X(OBD_CONNECT_MAXBYTES);
	CHECK_DEFINE_64X(OBD_CONNECT_IMP_RECOV);
	CHECK_DEFINE_64X(OBD_CONNECT_JOBSTATS);
	CHECK_DEFINE_64X(OBD_CONNECT_UMASK);
	CHECK_DEFINE_64X(OBD_CONNECT_EINPROGRESS);
	CHECK_DEFINE_64X(OBD_CONNECT_GRANT_PARAM);
	CHECK_DEFINE_64X(OBD_CONNECT_FLOCK_OWNER);
	CHECK_DEFINE_64X(OBD_CONNECT_LVB_TYPE);
	CHECK_DEFINE_64X(OBD_CONNECT_NANOSEC_TIME);
	CHECK_DEFINE_64X(OBD_CONNECT_LIGHTWEIGHT);
	CHECK_DEFINE_64X(OBD_CONNECT_SHORTIO);
	CHECK_DEFINE_64X(OBD_CONNECT_PINGLESS);
	CHECK_DEFINE_64X(OBD_CONNECT_FLOCK_DEAD);
	CHECK_DEFINE_64X(OBD_CONNECT_OPEN_BY_FID);
	CHECK_DEFINE_64X(OBD_CONNECT_LFSCK);
	CHECK_DEFINE_64X(OBD_CONNECT_UNLINK_CLOSE);
	CHECK_DEFINE_64X(OBD_CONNECT_MULTIMODRPCS);
	CHECK_DEFINE_64X(OBD_CONNECT_DIR_STRIPE);
	CHECK_DEFINE_64X(OBD_CONNECT_SUBTREE);
	CHECK_DEFINE_64X(OBD_CONNECT_LOCK_AHEAD);
	CHECK_DEFINE_64X(OBD_CONNECT_BULK_MBITS);
	CHECK_DEFINE_64X(OBD_CONNECT_OBDOPACK);
	CHECK_DEFINE_64X(OBD_CONNECT_FLAGS2);
	CHECK_DEFINE_64X(OBD_CONNECT2_FILE_SECCTX);

	CHECK_VALUE_X(OBD_CKSUM_CRC32);
	CHECK_VALUE_X(OBD_CKSUM_ADLER);
	CHECK_VALUE_X(OBD_CKSUM_CRC32C);
}

static void
check_ost_layout(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ost_layout);
	CHECK_MEMBER(ost_layout, ol_stripe_size);
	CHECK_MEMBER(ost_layout, ol_stripe_count);
	CHECK_MEMBER(ost_layout, ol_comp_start);
	CHECK_MEMBER(ost_layout, ol_comp_end);
	CHECK_MEMBER(ost_layout, ol_comp_id);
}

static void
check_obdo(void)
{
	BLANK_LINE();
	CHECK_STRUCT(obdo);
	CHECK_MEMBER(obdo, o_valid);
	CHECK_MEMBER(obdo, o_oi);
	CHECK_MEMBER(obdo, o_parent_seq);
	CHECK_MEMBER(obdo, o_size);
	CHECK_MEMBER(obdo, o_mtime);
	CHECK_MEMBER(obdo, o_atime);
	CHECK_MEMBER(obdo, o_ctime);
	CHECK_MEMBER(obdo, o_blocks);
	CHECK_MEMBER(obdo, o_grant);
	CHECK_MEMBER(obdo, o_blksize);
	CHECK_MEMBER(obdo, o_mode);
	CHECK_MEMBER(obdo, o_uid);
	CHECK_MEMBER(obdo, o_gid);
	CHECK_MEMBER(obdo, o_flags);
	CHECK_MEMBER(obdo, o_nlink);
	CHECK_MEMBER(obdo, o_parent_oid);
	CHECK_MEMBER(obdo, o_misc);
	CHECK_MEMBER(obdo, o_ioepoch);
	CHECK_MEMBER(obdo, o_stripe_idx);
	CHECK_MEMBER(obdo, o_parent_ver);
	CHECK_MEMBER(obdo, o_handle);
	CHECK_MEMBER(obdo, o_layout);
	CHECK_MEMBER(obdo, o_padding_3);
	CHECK_MEMBER(obdo, o_uid_h);
	CHECK_MEMBER(obdo, o_gid_h);
	CHECK_MEMBER(obdo, o_data_version);
	CHECK_MEMBER(obdo, o_projid);
	CHECK_MEMBER(obdo, o_padding_4);
	CHECK_MEMBER(obdo, o_padding_5);
	CHECK_MEMBER(obdo, o_padding_6);

	CHECK_DEFINE_64X(OBD_MD_FLID);
	CHECK_DEFINE_64X(OBD_MD_FLATIME);
	CHECK_DEFINE_64X(OBD_MD_FLMTIME);
	CHECK_DEFINE_64X(OBD_MD_FLCTIME);
	CHECK_DEFINE_64X(OBD_MD_FLSIZE);
	CHECK_DEFINE_64X(OBD_MD_FLBLOCKS);
	CHECK_DEFINE_64X(OBD_MD_FLBLKSZ);
	CHECK_DEFINE_64X(OBD_MD_FLMODE);
	CHECK_DEFINE_64X(OBD_MD_FLTYPE);
	CHECK_DEFINE_64X(OBD_MD_FLUID);
	CHECK_DEFINE_64X(OBD_MD_FLGID);
	CHECK_DEFINE_64X(OBD_MD_FLFLAGS);
	CHECK_DEFINE_64X(OBD_MD_FLNLINK);
	CHECK_DEFINE_64X(OBD_MD_FLGENER);
	CHECK_DEFINE_64X(OBD_MD_FLRDEV);
	CHECK_DEFINE_64X(OBD_MD_FLEASIZE);
	CHECK_DEFINE_64X(OBD_MD_LINKNAME);
	CHECK_DEFINE_64X(OBD_MD_FLHANDLE);
	CHECK_DEFINE_64X(OBD_MD_FLCKSUM);
	CHECK_DEFINE_64X(OBD_MD_FLQOS);
	CHECK_DEFINE_64X(OBD_MD_FLGROUP);
	CHECK_DEFINE_64X(OBD_MD_FLFID);
	CHECK_DEFINE_64X(OBD_MD_FLEPOCH);
	CHECK_DEFINE_64X(OBD_MD_FLGRANT);
	CHECK_DEFINE_64X(OBD_MD_FLDIREA);
	CHECK_DEFINE_64X(OBD_MD_FLUSRQUOTA);
	CHECK_DEFINE_64X(OBD_MD_FLGRPQUOTA);
	CHECK_DEFINE_64X(OBD_MD_FLMODEASIZE);
	CHECK_DEFINE_64X(OBD_MD_MDS);
	CHECK_DEFINE_64X(OBD_MD_REINT);
	CHECK_DEFINE_64X(OBD_MD_MEA);
	CHECK_DEFINE_64X(OBD_MD_TSTATE);
	CHECK_DEFINE_64X(OBD_MD_FLXATTR);
	CHECK_DEFINE_64X(OBD_MD_FLXATTRLS);
	CHECK_DEFINE_64X(OBD_MD_FLXATTRRM);
	CHECK_DEFINE_64X(OBD_MD_FLACL);
	CHECK_DEFINE_64X(OBD_MD_FLMDSCAPA);
	CHECK_DEFINE_64X(OBD_MD_FLOSSCAPA);
	CHECK_DEFINE_64X(OBD_MD_FLCKSPLIT);
	CHECK_DEFINE_64X(OBD_MD_FLCROSSREF);
	CHECK_DEFINE_64X(OBD_MD_FLGETATTRLOCK);
	CHECK_DEFINE_64X(OBD_MD_FLDATAVERSION);
	CHECK_DEFINE_64X(OBD_MD_CLOSE_INTENT_EXECED);
	CHECK_DEFINE_64X(OBD_MD_DEFAULT_MEA);
	CHECK_DEFINE_64X(OBD_MD_FLOSTLAYOUT);
	CHECK_DEFINE_64X(OBD_MD_FLPROJID);

	CHECK_CVALUE_X(OBD_FL_INLINEDATA);
	CHECK_CVALUE_X(OBD_FL_OBDMDEXISTS);
	CHECK_CVALUE_X(OBD_FL_DELORPHAN);
	CHECK_CVALUE_X(OBD_FL_NORPC);
	CHECK_CVALUE_X(OBD_FL_IDONLY);
	CHECK_CVALUE_X(OBD_FL_RECREATE_OBJS);
	CHECK_CVALUE_X(OBD_FL_DEBUG_CHECK);
	CHECK_CVALUE_X(OBD_FL_NO_USRQUOTA);
	CHECK_CVALUE_X(OBD_FL_NO_GRPQUOTA);
	CHECK_CVALUE_X(OBD_FL_CREATE_CROW);
	CHECK_CVALUE_X(OBD_FL_SRVLOCK);
	CHECK_CVALUE_X(OBD_FL_CKSUM_CRC32);
	CHECK_CVALUE_X(OBD_FL_CKSUM_ADLER);
	CHECK_CVALUE_X(OBD_FL_CKSUM_CRC32C);
	CHECK_CVALUE_X(OBD_FL_CKSUM_RSVD2);
	CHECK_CVALUE_X(OBD_FL_CKSUM_RSVD3);
	CHECK_CVALUE_X(OBD_FL_SHRINK_GRANT);
	CHECK_CVALUE_X(OBD_FL_MMAP);
	CHECK_CVALUE_X(OBD_FL_RECOV_RESEND);
	CHECK_CVALUE_X(OBD_FL_NOSPC_BLK);
	CHECK_CVALUE_X(OBD_FL_FLUSH);
	CHECK_CVALUE_X(OBD_FL_SHORT_IO);
}

static void
check_lov_ost_data_v1(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lov_ost_data_v1);
	CHECK_MEMBER(lov_ost_data_v1, l_ost_oi);
	CHECK_MEMBER(lov_ost_data_v1, l_ost_gen);
	CHECK_MEMBER(lov_ost_data_v1, l_ost_idx);
}

static void
check_lov_mds_md_v1(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lov_mds_md_v1);
	CHECK_MEMBER(lov_mds_md_v1, lmm_magic);
	CHECK_MEMBER(lov_mds_md_v1, lmm_pattern);
	CHECK_MEMBER(lov_mds_md_v1, lmm_oi);
	CHECK_MEMBER(lov_mds_md_v1, lmm_stripe_size);
	CHECK_MEMBER(lov_mds_md_v1, lmm_stripe_count);
	CHECK_MEMBER(lov_mds_md_v1, lmm_layout_gen);
	CHECK_MEMBER(lov_mds_md_v1, lmm_objects[0]);

	CHECK_CDEFINE(LOV_MAGIC_V1);
}

static void
check_lov_mds_md_v3(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lov_mds_md_v3);
	CHECK_MEMBER(lov_mds_md_v3, lmm_magic);
	CHECK_MEMBER(lov_mds_md_v3, lmm_pattern);
	CHECK_MEMBER(lov_mds_md_v3, lmm_oi);
	CHECK_MEMBER(lov_mds_md_v3, lmm_stripe_size);
	CHECK_MEMBER(lov_mds_md_v3, lmm_stripe_count);
	CHECK_MEMBER(lov_mds_md_v3, lmm_layout_gen);
	CHECK_CVALUE(LOV_MAXPOOLNAME);
	CHECK_MEMBER(lov_mds_md_v3, lmm_pool_name[LOV_MAXPOOLNAME + 1]);
	CHECK_MEMBER(lov_mds_md_v3, lmm_objects[0]);

	CHECK_CDEFINE(LOV_MAGIC_V3);

	CHECK_VALUE_X(LOV_PATTERN_RAID0);
	CHECK_VALUE_X(LOV_PATTERN_RAID1);
	CHECK_VALUE_X(LOV_PATTERN_FIRST);
	CHECK_VALUE_X(LOV_PATTERN_CMOBD);
}

static void
check_lov_comp_md_entry_v1(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lov_comp_md_entry_v1);
	CHECK_MEMBER(lov_comp_md_entry_v1, lcme_id);
	CHECK_MEMBER(lov_comp_md_entry_v1, lcme_flags);
	CHECK_MEMBER(lov_comp_md_entry_v1, lcme_extent);
	CHECK_MEMBER(lov_comp_md_entry_v1, lcme_offset);
	CHECK_MEMBER(lov_comp_md_entry_v1, lcme_size);
	CHECK_MEMBER(lov_comp_md_entry_v1, lcme_padding);

	CHECK_VALUE_X(LCME_FL_INIT);
}

static void
check_lov_comp_md_v1(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lov_comp_md_v1);
	CHECK_MEMBER(lov_comp_md_v1, lcm_magic);
	CHECK_MEMBER(lov_comp_md_v1, lcm_size);
	CHECK_MEMBER(lov_comp_md_v1, lcm_layout_gen);
	CHECK_MEMBER(lov_comp_md_v1, lcm_flags);
	CHECK_MEMBER(lov_comp_md_v1, lcm_entry_count);
	CHECK_MEMBER(lov_comp_md_v1, lcm_padding1);
	CHECK_MEMBER(lov_comp_md_v1, lcm_padding2);
	CHECK_MEMBER(lov_comp_md_v1, lcm_entries[0]);

	CHECK_CDEFINE(LOV_MAGIC_COMP_V1);
}

static void
check_lmv_mds_md_v1(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lmv_mds_md_v1);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_magic);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_stripe_count);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_master_mdt_index);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_hash_type);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_layout_version);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_padding1);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_padding2);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_padding3);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_pool_name[LOV_MAXPOOLNAME]);
	CHECK_MEMBER(lmv_mds_md_v1, lmv_stripe_fids[0]);

	CHECK_CDEFINE(LMV_MAGIC_V1);
	CHECK_CDEFINE(LMV_MAGIC_STRIPE);
	CHECK_CDEFINE(LMV_HASH_TYPE_MASK);
	CHECK_CDEFINE(LMV_HASH_FLAG_MIGRATION);
	CHECK_CDEFINE(LMV_HASH_FLAG_DEAD);
	CHECK_CDEFINE(LMV_HASH_FLAG_BAD_TYPE);
	CHECK_CDEFINE(LMV_HASH_FLAG_LOST_LMV);
}

static void
check_obd_statfs(void)
{
	BLANK_LINE();
	CHECK_STRUCT(obd_statfs);
	CHECK_MEMBER(obd_statfs, os_type);
	CHECK_MEMBER(obd_statfs, os_blocks);
	CHECK_MEMBER(obd_statfs, os_bfree);
	CHECK_MEMBER(obd_statfs, os_bavail);
	CHECK_MEMBER(obd_statfs, os_ffree);
	CHECK_MEMBER(obd_statfs, os_fsid);
	CHECK_MEMBER(obd_statfs, os_bsize);
	CHECK_MEMBER(obd_statfs, os_namelen);
	CHECK_MEMBER(obd_statfs, os_state);
	CHECK_MEMBER(obd_statfs, os_fprecreated);
	CHECK_MEMBER(obd_statfs, os_spare2);
	CHECK_MEMBER(obd_statfs, os_spare3);
	CHECK_MEMBER(obd_statfs, os_spare4);
	CHECK_MEMBER(obd_statfs, os_spare5);
	CHECK_MEMBER(obd_statfs, os_spare6);
	CHECK_MEMBER(obd_statfs, os_spare7);
	CHECK_MEMBER(obd_statfs, os_spare8);
	CHECK_MEMBER(obd_statfs, os_spare9);
}

static void
check_obd_ioobj(void)
{
	BLANK_LINE();
	CHECK_STRUCT(obd_ioobj);
	CHECK_MEMBER(obd_ioobj, ioo_oid);
	CHECK_MEMBER(obd_ioobj, ioo_max_brw);
	CHECK_MEMBER(obd_ioobj, ioo_bufcnt);
	CHECK_VALUE(IOOBJ_MAX_BRW_BITS);
}

static void
check_obd_quotactl(void)
{

	BLANK_LINE();
	CHECK_UNION(lquota_id);

	BLANK_LINE();
	CHECK_VALUE(QUOTABLOCK_BITS);
	CHECK_VALUE(QUOTABLOCK_SIZE);

	BLANK_LINE();
	CHECK_STRUCT(obd_quotactl);
	CHECK_MEMBER(obd_quotactl, qc_cmd);
	CHECK_MEMBER(obd_quotactl, qc_type);
	CHECK_MEMBER(obd_quotactl, qc_id);
	CHECK_MEMBER(obd_quotactl, qc_stat);
	CHECK_MEMBER(obd_quotactl, qc_dqinfo);
	CHECK_MEMBER(obd_quotactl, qc_dqblk);

	BLANK_LINE();
	CHECK_STRUCT(obd_dqinfo);
	CHECK_MEMBER(obd_dqinfo, dqi_bgrace);
	CHECK_MEMBER(obd_dqinfo, dqi_igrace);
	CHECK_MEMBER(obd_dqinfo, dqi_flags);
	CHECK_MEMBER(obd_dqinfo, dqi_valid);

	BLANK_LINE();
	CHECK_STRUCT(obd_dqblk);
	CHECK_MEMBER(obd_dqblk, dqb_bhardlimit);
	CHECK_MEMBER(obd_dqblk, dqb_bsoftlimit);
	CHECK_MEMBER(obd_dqblk, dqb_curspace);
	CHECK_MEMBER(obd_dqblk, dqb_ihardlimit);
	CHECK_MEMBER(obd_dqblk, dqb_isoftlimit);
	CHECK_MEMBER(obd_dqblk, dqb_curinodes);
	CHECK_MEMBER(obd_dqblk, dqb_btime);
	CHECK_MEMBER(obd_dqblk, dqb_itime);
	CHECK_MEMBER(obd_dqblk, dqb_valid);
	CHECK_MEMBER(obd_dqblk, dqb_padding);

	CHECK_DEFINE_X(Q_QUOTACHECK);
	CHECK_DEFINE_X(Q_INITQUOTA);
	CHECK_DEFINE_X(Q_GETOINFO);
	CHECK_DEFINE_X(Q_GETOQUOTA);
	CHECK_DEFINE_X(Q_FINVALIDATE);

	BLANK_LINE();
	CHECK_STRUCT(lquota_acct_rec);
	CHECK_MEMBER(lquota_acct_rec, bspace);
	CHECK_MEMBER(lquota_acct_rec, ispace);

	BLANK_LINE();
	CHECK_STRUCT(lquota_glb_rec);
	CHECK_MEMBER(lquota_glb_rec, qbr_hardlimit);
	CHECK_MEMBER(lquota_glb_rec, qbr_softlimit);
	CHECK_MEMBER(lquota_glb_rec, qbr_time);
	CHECK_MEMBER(lquota_glb_rec, qbr_granted);

	BLANK_LINE();
	CHECK_STRUCT(lquota_slv_rec);
	CHECK_MEMBER(lquota_slv_rec, qsr_granted);

}

static void
check_obd_idx_read(void)
{
	BLANK_LINE();
	CHECK_STRUCT(idx_info);
	CHECK_MEMBER(idx_info, ii_magic);
	CHECK_MEMBER(idx_info, ii_flags);
	CHECK_MEMBER(idx_info, ii_count);
	CHECK_MEMBER(idx_info, ii_pad0);
	CHECK_MEMBER(idx_info, ii_attrs);
	CHECK_MEMBER(idx_info, ii_fid);
	CHECK_MEMBER(idx_info, ii_version);
	CHECK_MEMBER(idx_info, ii_hash_start);
	CHECK_MEMBER(idx_info, ii_hash_end);
	CHECK_MEMBER(idx_info, ii_keysize);
	CHECK_MEMBER(idx_info, ii_recsize);
	CHECK_MEMBER(idx_info, ii_pad1);
	CHECK_MEMBER(idx_info, ii_pad2);
	CHECK_MEMBER(idx_info, ii_pad3);
	CHECK_CDEFINE(IDX_INFO_MAGIC);

	BLANK_LINE();
	CHECK_STRUCT(lu_idxpage);
	CHECK_MEMBER(lu_idxpage, lip_magic);
	CHECK_MEMBER(lu_idxpage, lip_flags);
	CHECK_MEMBER(lu_idxpage, lip_nr);
	CHECK_MEMBER(lu_idxpage, lip_pad0);

	CHECK_CDEFINE(LIP_MAGIC);
	CHECK_VALUE(LIP_HDR_SIZE);

	CHECK_VALUE(II_FL_NOHASH);
	CHECK_VALUE(II_FL_VARKEY);
	CHECK_VALUE(II_FL_VARREC);
	CHECK_VALUE(II_FL_NONUNQ);
}

static void
check_niobuf_remote(void)
{
	BLANK_LINE();
	CHECK_STRUCT(niobuf_remote);
	CHECK_MEMBER(niobuf_remote, rnb_offset);
	CHECK_MEMBER(niobuf_remote, rnb_len);
	CHECK_MEMBER(niobuf_remote, rnb_flags);

	CHECK_DEFINE_X(OBD_BRW_READ);
	CHECK_DEFINE_X(OBD_BRW_WRITE);
	CHECK_DEFINE_X(OBD_BRW_SYNC);
	CHECK_DEFINE_X(OBD_BRW_CHECK);
	CHECK_DEFINE_X(OBD_BRW_FROM_GRANT);
	CHECK_DEFINE_X(OBD_BRW_GRANTED);
	CHECK_DEFINE_X(OBD_BRW_NOCACHE);
	CHECK_DEFINE_X(OBD_BRW_NOQUOTA);
	CHECK_DEFINE_X(OBD_BRW_SRVLOCK);
	CHECK_DEFINE_X(OBD_BRW_ASYNC);
	CHECK_DEFINE_X(OBD_BRW_MEMALLOC);
	CHECK_DEFINE_X(OBD_BRW_OVER_USRQUOTA);
	CHECK_DEFINE_X(OBD_BRW_OVER_GRPQUOTA);
	CHECK_DEFINE_X(OBD_BRW_SOFT_SYNC);
}

static void
check_ost_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ost_body);
	CHECK_MEMBER(ost_body, oa);
}

static void
check_ll_fid(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ll_fid);
	CHECK_MEMBER(ll_fid, id);
	CHECK_MEMBER(ll_fid, generation);
	CHECK_MEMBER(ll_fid, f_type);
}

static void
check_mdt_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_body);
	CHECK_MEMBER(mdt_body, mbo_fid1);
	CHECK_MEMBER(mdt_body, mbo_fid2);
	CHECK_MEMBER(mdt_body, mbo_handle);
	CHECK_MEMBER(mdt_body, mbo_valid);
	CHECK_MEMBER(mdt_body, mbo_size);
	CHECK_MEMBER(mdt_body, mbo_mtime);
	CHECK_MEMBER(mdt_body, mbo_atime);
	CHECK_MEMBER(mdt_body, mbo_ctime);
	CHECK_MEMBER(mdt_body, mbo_blocks);
	CHECK_MEMBER(mdt_body, mbo_t_state);
	CHECK_MEMBER(mdt_body, mbo_fsuid);
	CHECK_MEMBER(mdt_body, mbo_fsgid);
	CHECK_MEMBER(mdt_body, mbo_capability);
	CHECK_MEMBER(mdt_body, mbo_mode);
	CHECK_MEMBER(mdt_body, mbo_uid);
	CHECK_MEMBER(mdt_body, mbo_gid);
	CHECK_MEMBER(mdt_body, mbo_flags);
	CHECK_MEMBER(mdt_body, mbo_rdev);
	CHECK_MEMBER(mdt_body, mbo_nlink);
	CHECK_MEMBER(mdt_body, mbo_unused2);
	CHECK_MEMBER(mdt_body, mbo_suppgid);
	CHECK_MEMBER(mdt_body, mbo_eadatasize);
	CHECK_MEMBER(mdt_body, mbo_aclsize);
	CHECK_MEMBER(mdt_body, mbo_max_mdsize);
	CHECK_MEMBER(mdt_body, mbo_unused3);
	CHECK_MEMBER(mdt_body, mbo_uid_h);
	CHECK_MEMBER(mdt_body, mbo_gid_h);
	CHECK_MEMBER(mdt_body, mbo_projid);
	CHECK_MEMBER(mdt_body, mbo_padding_6);
	CHECK_MEMBER(mdt_body, mbo_padding_7);
	CHECK_MEMBER(mdt_body, mbo_padding_8);
	CHECK_MEMBER(mdt_body, mbo_padding_9);
	CHECK_MEMBER(mdt_body, mbo_padding_10);

	CHECK_VALUE_O(MDS_FMODE_CLOSED);
	CHECK_VALUE_O(MDS_FMODE_EXEC);

	CHECK_VALUE_O(MDS_OPEN_CREATED);
	CHECK_VALUE_O(MDS_OPEN_CROSS);
	CHECK_VALUE_O(MDS_OPEN_CREAT);
	CHECK_VALUE_O(MDS_OPEN_EXCL);
	CHECK_VALUE_O(MDS_OPEN_TRUNC);
	CHECK_VALUE_O(MDS_OPEN_APPEND);
	CHECK_VALUE_O(MDS_OPEN_SYNC);
	CHECK_VALUE_O(MDS_OPEN_DIRECTORY);
	CHECK_VALUE_O(MDS_OPEN_BY_FID);
	CHECK_VALUE_O(MDS_OPEN_DELAY_CREATE);
	CHECK_VALUE_O(MDS_OPEN_OWNEROVERRIDE);
	CHECK_VALUE_O(MDS_OPEN_JOIN_FILE);
	CHECK_VALUE_O(MDS_OPEN_LOCK);
	CHECK_VALUE_O(MDS_OPEN_HAS_EA);
	CHECK_VALUE_O(MDS_OPEN_HAS_OBJS);
	CHECK_VALUE_64O(MDS_OPEN_NORESTORE);
	CHECK_VALUE_64O(MDS_OPEN_NEWSTRIPE);
	CHECK_VALUE_64O(MDS_OPEN_VOLATILE);

	/* these should be identical to their EXT3_*_FL counterparts, and
	 * are redefined only to avoid dragging in ext3_fs.h */
	CHECK_VALUE_X(LUSTRE_SYNC_FL);
	CHECK_VALUE_X(LUSTRE_IMMUTABLE_FL);
	CHECK_VALUE_X(LUSTRE_APPEND_FL);
	CHECK_VALUE_X(LUSTRE_NODUMP_FL);
	CHECK_VALUE_X(LUSTRE_NOATIME_FL);
	CHECK_VALUE_X(LUSTRE_INDEX_FL);
	CHECK_VALUE_X(LUSTRE_ORPHAN_FL);
	CHECK_VALUE_X(LUSTRE_DIRSYNC_FL);
	CHECK_VALUE_X(LUSTRE_TOPDIR_FL);
	CHECK_VALUE_X(LUSTRE_DIRECTIO_FL);
	CHECK_VALUE_X(LUSTRE_INLINE_DATA_FL);

	CHECK_DEFINE_X(MDS_INODELOCK_LOOKUP);
	CHECK_DEFINE_X(MDS_INODELOCK_UPDATE);
	CHECK_DEFINE_X(MDS_INODELOCK_OPEN);
	CHECK_DEFINE_X(MDS_INODELOCK_LAYOUT);
}

static void
check_mdt_ioepoch(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_ioepoch);
	CHECK_MEMBER(mdt_ioepoch, mio_handle);
	CHECK_MEMBER(mdt_ioepoch, mio_unused1);
	CHECK_MEMBER(mdt_ioepoch, mio_unused2);
	CHECK_MEMBER(mdt_ioepoch, mio_padding);
}

static void
check_mdt_rec_setattr(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_setattr);
	CHECK_MEMBER(mdt_rec_setattr, sa_opcode);
	CHECK_MEMBER(mdt_rec_setattr, sa_cap);
	CHECK_MEMBER(mdt_rec_setattr, sa_fsuid);
	CHECK_MEMBER(mdt_rec_setattr, sa_fsuid_h);
	CHECK_MEMBER(mdt_rec_setattr, sa_fsgid);
	CHECK_MEMBER(mdt_rec_setattr, sa_fsgid_h);
	CHECK_MEMBER(mdt_rec_setattr, sa_suppgid);
	CHECK_MEMBER(mdt_rec_setattr, sa_suppgid_h);
	CHECK_MEMBER(mdt_rec_setattr, sa_padding_1);
	CHECK_MEMBER(mdt_rec_setattr, sa_padding_1_h);
	CHECK_MEMBER(mdt_rec_setattr, sa_fid);
	CHECK_MEMBER(mdt_rec_setattr, sa_valid);
	CHECK_MEMBER(mdt_rec_setattr, sa_uid);
	CHECK_MEMBER(mdt_rec_setattr, sa_gid);
	CHECK_MEMBER(mdt_rec_setattr, sa_size);
	CHECK_MEMBER(mdt_rec_setattr, sa_blocks);
	CHECK_MEMBER(mdt_rec_setattr, sa_mtime);
	CHECK_MEMBER(mdt_rec_setattr, sa_atime);
	CHECK_MEMBER(mdt_rec_setattr, sa_ctime);
	CHECK_MEMBER(mdt_rec_setattr, sa_attr_flags);
	CHECK_MEMBER(mdt_rec_setattr, sa_mode);
	CHECK_MEMBER(mdt_rec_setattr, sa_bias);
	CHECK_MEMBER(mdt_rec_setattr, sa_projid);
	CHECK_MEMBER(mdt_rec_setattr, sa_padding_4);
	CHECK_MEMBER(mdt_rec_setattr, sa_padding_5);
}

static void
check_mdt_rec_create(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_create);
	CHECK_MEMBER(mdt_rec_create, cr_opcode);
	CHECK_MEMBER(mdt_rec_create, cr_cap);
	CHECK_MEMBER(mdt_rec_create, cr_fsuid);
	CHECK_MEMBER(mdt_rec_create, cr_fsuid_h);
	CHECK_MEMBER(mdt_rec_create, cr_fsgid);
	CHECK_MEMBER(mdt_rec_create, cr_fsgid_h);
	CHECK_MEMBER(mdt_rec_create, cr_suppgid1);
	CHECK_MEMBER(mdt_rec_create, cr_suppgid1_h);
	CHECK_MEMBER(mdt_rec_create, cr_suppgid2);
	CHECK_MEMBER(mdt_rec_create, cr_suppgid2_h);
	CHECK_MEMBER(mdt_rec_create, cr_fid1);
	CHECK_MEMBER(mdt_rec_create, cr_fid2);
	CHECK_MEMBER(mdt_rec_create, cr_old_handle);
	CHECK_MEMBER(mdt_rec_create, cr_time);
	CHECK_MEMBER(mdt_rec_create, cr_rdev);
	CHECK_MEMBER(mdt_rec_create, cr_ioepoch);
	CHECK_MEMBER(mdt_rec_create, cr_padding_1);
	CHECK_MEMBER(mdt_rec_create, cr_mode);
	CHECK_MEMBER(mdt_rec_create, cr_bias);
	CHECK_MEMBER(mdt_rec_create, cr_flags_l);
	CHECK_MEMBER(mdt_rec_create, cr_flags_h);
	CHECK_MEMBER(mdt_rec_create, cr_umask);
	CHECK_MEMBER(mdt_rec_create, cr_padding_4);
}

static void
check_mdt_rec_link(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_link);
	CHECK_MEMBER(mdt_rec_link, lk_opcode);
	CHECK_MEMBER(mdt_rec_link, lk_cap);
	CHECK_MEMBER(mdt_rec_link, lk_fsuid);
	CHECK_MEMBER(mdt_rec_link, lk_fsuid_h);
	CHECK_MEMBER(mdt_rec_link, lk_fsgid);
	CHECK_MEMBER(mdt_rec_link, lk_fsgid_h);
	CHECK_MEMBER(mdt_rec_link, lk_suppgid1);
	CHECK_MEMBER(mdt_rec_link, lk_suppgid1_h);
	CHECK_MEMBER(mdt_rec_link, lk_suppgid2);
	CHECK_MEMBER(mdt_rec_link, lk_suppgid2_h);
	CHECK_MEMBER(mdt_rec_link, lk_fid1);
	CHECK_MEMBER(mdt_rec_link, lk_fid2);
	CHECK_MEMBER(mdt_rec_link, lk_time);
	CHECK_MEMBER(mdt_rec_link, lk_padding_1);
	CHECK_MEMBER(mdt_rec_link, lk_padding_2);
	CHECK_MEMBER(mdt_rec_link, lk_padding_3);
	CHECK_MEMBER(mdt_rec_link, lk_padding_4);
	CHECK_MEMBER(mdt_rec_link, lk_bias);
	CHECK_MEMBER(mdt_rec_link, lk_padding_5);
	CHECK_MEMBER(mdt_rec_link, lk_padding_6);
	CHECK_MEMBER(mdt_rec_link, lk_padding_7);
	CHECK_MEMBER(mdt_rec_link, lk_padding_8);
	CHECK_MEMBER(mdt_rec_link, lk_padding_9);
}

static void
check_mdt_rec_unlink(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_unlink);
	CHECK_MEMBER(mdt_rec_unlink, ul_opcode);
	CHECK_MEMBER(mdt_rec_unlink, ul_cap);
	CHECK_MEMBER(mdt_rec_unlink, ul_fsuid);
	CHECK_MEMBER(mdt_rec_unlink, ul_fsuid_h);
	CHECK_MEMBER(mdt_rec_unlink, ul_fsgid);
	CHECK_MEMBER(mdt_rec_unlink, ul_fsgid_h);
	CHECK_MEMBER(mdt_rec_unlink, ul_suppgid1);
	CHECK_MEMBER(mdt_rec_unlink, ul_suppgid1_h);
	CHECK_MEMBER(mdt_rec_unlink, ul_suppgid2);
	CHECK_MEMBER(mdt_rec_unlink, ul_suppgid2_h);
	CHECK_MEMBER(mdt_rec_unlink, ul_fid1);
	CHECK_MEMBER(mdt_rec_unlink, ul_fid2);
	CHECK_MEMBER(mdt_rec_unlink, ul_time);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_2);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_3);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_4);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_5);
	CHECK_MEMBER(mdt_rec_unlink, ul_bias);
	CHECK_MEMBER(mdt_rec_unlink, ul_mode);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_6);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_7);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_8);
	CHECK_MEMBER(mdt_rec_unlink, ul_padding_9);
}

static void
check_mdt_rec_rename(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_rename);
	CHECK_MEMBER(mdt_rec_rename, rn_opcode);
	CHECK_MEMBER(mdt_rec_rename, rn_cap);
	CHECK_MEMBER(mdt_rec_rename, rn_fsuid);
	CHECK_MEMBER(mdt_rec_rename, rn_fsuid_h);
	CHECK_MEMBER(mdt_rec_rename, rn_fsgid);
	CHECK_MEMBER(mdt_rec_rename, rn_fsgid_h);
	CHECK_MEMBER(mdt_rec_rename, rn_suppgid1);
	CHECK_MEMBER(mdt_rec_rename, rn_suppgid1_h);
	CHECK_MEMBER(mdt_rec_rename, rn_suppgid2);
	CHECK_MEMBER(mdt_rec_rename, rn_suppgid2_h);
	CHECK_MEMBER(mdt_rec_rename, rn_fid1);
	CHECK_MEMBER(mdt_rec_rename, rn_fid2);
	CHECK_MEMBER(mdt_rec_rename, rn_time);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_1);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_2);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_3);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_4);
	CHECK_MEMBER(mdt_rec_rename, rn_bias);
	CHECK_MEMBER(mdt_rec_rename, rn_mode);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_5);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_6);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_7);
	CHECK_MEMBER(mdt_rec_rename, rn_padding_8);
}

static void
check_mdt_rec_setxattr(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_setxattr);
	CHECK_MEMBER(mdt_rec_setxattr, sx_opcode);
	CHECK_MEMBER(mdt_rec_setxattr, sx_cap);
	CHECK_MEMBER(mdt_rec_setxattr, sx_fsuid);
	CHECK_MEMBER(mdt_rec_setxattr, sx_fsuid_h);
	CHECK_MEMBER(mdt_rec_setxattr, sx_fsgid);
	CHECK_MEMBER(mdt_rec_setxattr, sx_fsgid_h);
	CHECK_MEMBER(mdt_rec_setxattr, sx_suppgid1);
	CHECK_MEMBER(mdt_rec_setxattr, sx_suppgid1_h);
	CHECK_MEMBER(mdt_rec_setxattr, sx_suppgid2);
	CHECK_MEMBER(mdt_rec_setxattr, sx_suppgid2_h);
	CHECK_MEMBER(mdt_rec_setxattr, sx_fid);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_1);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_2);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_3);
	CHECK_MEMBER(mdt_rec_setxattr, sx_valid);
	CHECK_MEMBER(mdt_rec_setxattr, sx_time);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_5);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_6);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_7);
	CHECK_MEMBER(mdt_rec_setxattr, sx_size);
	CHECK_MEMBER(mdt_rec_setxattr, sx_flags);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_8);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_9);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_10);
	CHECK_MEMBER(mdt_rec_setxattr, sx_padding_11);
}

static void
check_mdt_rec_reint(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mdt_rec_reint);
	CHECK_MEMBER(mdt_rec_reint, rr_opcode);
	CHECK_MEMBER(mdt_rec_reint, rr_cap);
	CHECK_MEMBER(mdt_rec_reint, rr_fsuid);
	CHECK_MEMBER(mdt_rec_reint, rr_fsuid_h);
	CHECK_MEMBER(mdt_rec_reint, rr_fsgid);
	CHECK_MEMBER(mdt_rec_reint, rr_fsgid_h);
	CHECK_MEMBER(mdt_rec_reint, rr_suppgid1);
	CHECK_MEMBER(mdt_rec_reint, rr_suppgid1_h);
	CHECK_MEMBER(mdt_rec_reint, rr_suppgid2);
	CHECK_MEMBER(mdt_rec_reint, rr_suppgid2_h);
	CHECK_MEMBER(mdt_rec_reint, rr_fid1);
	CHECK_MEMBER(mdt_rec_reint, rr_fid2);
	CHECK_MEMBER(mdt_rec_reint, rr_mtime);
	CHECK_MEMBER(mdt_rec_reint, rr_atime);
	CHECK_MEMBER(mdt_rec_reint, rr_ctime);
	CHECK_MEMBER(mdt_rec_reint, rr_size);
	CHECK_MEMBER(mdt_rec_reint, rr_blocks);
	CHECK_MEMBER(mdt_rec_reint, rr_bias);
	CHECK_MEMBER(mdt_rec_reint, rr_mode);
	CHECK_MEMBER(mdt_rec_reint, rr_flags);
	CHECK_MEMBER(mdt_rec_reint, rr_flags_h);
	CHECK_MEMBER(mdt_rec_reint, rr_umask);
	CHECK_MEMBER(mdt_rec_reint, rr_padding_4);
}

static void
check_lmv_desc(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lmv_desc);
	CHECK_MEMBER(lmv_desc, ld_tgt_count);
	CHECK_MEMBER(lmv_desc, ld_active_tgt_count);
	CHECK_MEMBER(lmv_desc, ld_default_stripe_count);
	CHECK_MEMBER(lmv_desc, ld_pattern);
	CHECK_MEMBER(lmv_desc, ld_default_hash_size);
	CHECK_MEMBER(lmv_desc, ld_padding_1);
	CHECK_MEMBER(lmv_desc, ld_padding_2);
	CHECK_MEMBER(lmv_desc, ld_qos_maxage);
	CHECK_MEMBER(lmv_desc, ld_padding_3);
	CHECK_MEMBER(lmv_desc, ld_padding_4);
	CHECK_MEMBER(lmv_desc, ld_uuid);
}

static void
check_lov_desc(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lov_desc);
	CHECK_MEMBER(lov_desc, ld_tgt_count);
	CHECK_MEMBER(lov_desc, ld_active_tgt_count);
	CHECK_MEMBER(lov_desc, ld_default_stripe_count);
	CHECK_MEMBER(lov_desc, ld_pattern);
	CHECK_MEMBER(lov_desc, ld_default_stripe_size);
	CHECK_MEMBER(lov_desc, ld_default_stripe_offset);
	CHECK_MEMBER(lov_desc, ld_padding_0);
	CHECK_MEMBER(lov_desc, ld_qos_maxage);
	CHECK_MEMBER(lov_desc, ld_padding_1);
	CHECK_MEMBER(lov_desc, ld_padding_2);
	CHECK_MEMBER(lov_desc, ld_uuid);

	CHECK_CDEFINE(LOV_DESC_MAGIC);
}

static void
check_ldlm_res_id(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_res_id);
	CHECK_CVALUE(RES_NAME_SIZE);
	CHECK_MEMBER(ldlm_res_id, name[RES_NAME_SIZE]);
}

static void
check_ldlm_extent(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_extent);
	CHECK_MEMBER(ldlm_extent, start);
	CHECK_MEMBER(ldlm_extent, end);
	CHECK_MEMBER(ldlm_extent, gid);
}

static void
check_ldlm_inodebits(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_inodebits);
	CHECK_MEMBER(ldlm_inodebits, bits);
}

static void
check_ldlm_flock(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_flock_wire);
	CHECK_MEMBER(ldlm_flock_wire, lfw_start);
	CHECK_MEMBER(ldlm_flock_wire, lfw_end);
	CHECK_MEMBER(ldlm_flock_wire, lfw_owner);
	CHECK_MEMBER(ldlm_flock_wire, lfw_padding);
	CHECK_MEMBER(ldlm_flock_wire, lfw_pid);
}

static void
check_ldlm_intent(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_intent);
	CHECK_MEMBER(ldlm_intent, opc);
	CHECK_VALUE(IT_OPEN);
	CHECK_VALUE(IT_CREAT);
	CHECK_VALUE(IT_READDIR);
	CHECK_VALUE(IT_GETATTR);
	CHECK_VALUE(IT_LOOKUP);
	CHECK_VALUE(IT_UNLINK);
	CHECK_VALUE(IT_TRUNC);
	CHECK_VALUE(IT_GETXATTR);
	CHECK_VALUE(IT_EXEC);
	CHECK_VALUE(IT_PIN);
	CHECK_VALUE(IT_LAYOUT);
	CHECK_VALUE(IT_QUOTA_DQACQ);
	CHECK_VALUE(IT_QUOTA_CONN);
	CHECK_VALUE(IT_SETXATTR);
}

static void
check_ldlm_resource_desc(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_resource_desc);
	CHECK_MEMBER(ldlm_resource_desc, lr_type);
	CHECK_MEMBER(ldlm_resource_desc, lr_pad);
	CHECK_MEMBER(ldlm_resource_desc, lr_name);
}

static void
check_ldlm_lock_desc(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_lock_desc);
	CHECK_MEMBER(ldlm_lock_desc, l_resource);
	CHECK_MEMBER(ldlm_lock_desc, l_req_mode);
	CHECK_MEMBER(ldlm_lock_desc, l_granted_mode);
	CHECK_MEMBER(ldlm_lock_desc, l_policy_data);
}

static void
check_ldlm_request(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_request);
	CHECK_MEMBER(ldlm_request, lock_flags);
	CHECK_MEMBER(ldlm_request, lock_count);
	CHECK_MEMBER(ldlm_request, lock_desc);
	CHECK_MEMBER(ldlm_request, lock_handle);
}

static void
check_ldlm_reply(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_reply);
	CHECK_MEMBER(ldlm_reply, lock_flags);
	CHECK_MEMBER(ldlm_reply, lock_padding);
	CHECK_MEMBER(ldlm_reply, lock_desc);
	CHECK_MEMBER(ldlm_reply, lock_handle);
	CHECK_MEMBER(ldlm_reply, lock_policy_res1);
	CHECK_MEMBER(ldlm_reply, lock_policy_res2);
}

static void
check_ldlm_ost_lvb_v1(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ost_lvb_v1);
	CHECK_MEMBER(ost_lvb_v1, lvb_size);
	CHECK_MEMBER(ost_lvb_v1, lvb_mtime);
	CHECK_MEMBER(ost_lvb_v1, lvb_atime);
	CHECK_MEMBER(ost_lvb_v1, lvb_ctime);
	CHECK_MEMBER(ost_lvb_v1, lvb_blocks);
}

static void
check_ldlm_ost_lvb(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ost_lvb);
	CHECK_MEMBER(ost_lvb, lvb_size);
	CHECK_MEMBER(ost_lvb, lvb_mtime);
	CHECK_MEMBER(ost_lvb, lvb_atime);
	CHECK_MEMBER(ost_lvb, lvb_ctime);
	CHECK_MEMBER(ost_lvb, lvb_blocks);
	CHECK_MEMBER(ost_lvb, lvb_mtime_ns);
	CHECK_MEMBER(ost_lvb, lvb_atime_ns);
	CHECK_MEMBER(ost_lvb, lvb_ctime_ns);
	CHECK_MEMBER(ost_lvb, lvb_padding);
}

static void
check_ldlm_lquota_lvb(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lquota_lvb);
	CHECK_MEMBER(lquota_lvb, lvb_flags);
	CHECK_MEMBER(lquota_lvb, lvb_id_may_rel);
	CHECK_MEMBER(lquota_lvb, lvb_id_rel);
	CHECK_MEMBER(lquota_lvb, lvb_id_qunit);
	CHECK_MEMBER(lquota_lvb, lvb_pad1);
	CHECK_VALUE(LQUOTA_FL_EDQUOT);
}

static void
check_ldlm_gl_lquota_desc(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_gl_lquota_desc);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_id);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_flags);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_ver);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_hardlimit);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_softlimit);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_time);
	CHECK_MEMBER(ldlm_gl_lquota_desc, gl_pad2);
}

static void check_ldlm_gl_barrier_desc(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ldlm_gl_barrier_desc);
	CHECK_MEMBER(ldlm_gl_barrier_desc, lgbd_status);
	CHECK_MEMBER(ldlm_gl_barrier_desc, lgbd_timeout);
	CHECK_MEMBER(ldlm_gl_barrier_desc, lgbd_padding);
}

static void check_ldlm_barrier_lvb(void)
{
	BLANK_LINE();
	CHECK_STRUCT(barrier_lvb);
	CHECK_MEMBER(barrier_lvb, lvb_status);
	CHECK_MEMBER(barrier_lvb, lvb_index);
	CHECK_MEMBER(barrier_lvb, lvb_padding);
}

#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 13, 53, 0)
static void
check_mgs_send_param(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mgs_send_param);
	CHECK_CVALUE(MGS_PARAM_MAXLEN);
	CHECK_MEMBER(mgs_send_param, mgs_param[MGS_PARAM_MAXLEN]);
}
#endif

static void
check_cfg_marker(void)
{
	BLANK_LINE();
	CHECK_STRUCT(cfg_marker);
	CHECK_MEMBER(cfg_marker, cm_step);
	CHECK_MEMBER(cfg_marker, cm_flags);
	CHECK_MEMBER(cfg_marker, cm_vers);
	CHECK_MEMBER(cfg_marker, cm_padding);
	CHECK_MEMBER(cfg_marker, cm_createtime);
	CHECK_MEMBER(cfg_marker, cm_canceltime);
	CHECK_MEMBER(cfg_marker, cm_tgtname);
	CHECK_MEMBER(cfg_marker, cm_comment);
}

static void
check_llog_logid(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_logid);
	CHECK_MEMBER(llog_logid, lgl_oi);
	CHECK_MEMBER(llog_logid, lgl_ogen);

	CHECK_CVALUE(OST_SZ_REC);
	CHECK_CVALUE(MDS_UNLINK_REC);
	CHECK_CVALUE(MDS_UNLINK64_REC);
	CHECK_CVALUE(MDS_SETATTR64_REC);
	CHECK_CVALUE(OBD_CFG_REC);
	CHECK_CVALUE(LLOG_GEN_REC);
	CHECK_CVALUE(CHANGELOG_REC);
	CHECK_CVALUE(CHANGELOG_USER_REC);
	CHECK_CVALUE(LLOG_HDR_MAGIC);
	CHECK_CVALUE(LLOG_LOGID_MAGIC);
}

static void
check_llog_catid(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_catid);
	CHECK_MEMBER(llog_catid, lci_logid);
	CHECK_MEMBER(llog_catid, lci_padding1);
	CHECK_MEMBER(llog_catid, lci_padding2);
	CHECK_MEMBER(llog_catid, lci_padding3);
}

static void
check_llog_rec_hdr(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_rec_hdr);
	CHECK_MEMBER(llog_rec_hdr, lrh_len);
	CHECK_MEMBER(llog_rec_hdr, lrh_index);
	CHECK_MEMBER(llog_rec_hdr, lrh_type);
	CHECK_MEMBER(llog_rec_hdr, lrh_id);
}

static void
check_llog_rec_tail(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_rec_tail);
	CHECK_MEMBER(llog_rec_tail, lrt_len);
	CHECK_MEMBER(llog_rec_tail, lrt_index);
}

static void
check_llog_logid_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_logid_rec);
	CHECK_MEMBER(llog_logid_rec, lid_hdr);
	CHECK_MEMBER(llog_logid_rec, lid_id);
	CHECK_MEMBER(llog_logid_rec, lid_padding1);
	CHECK_MEMBER(llog_logid_rec, lid_padding2);
	CHECK_MEMBER(llog_logid_rec, lid_padding3);
	CHECK_MEMBER(llog_logid_rec, lid_tail);
}

static void
check_llog_unlink_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_unlink_rec);
	CHECK_MEMBER(llog_unlink_rec, lur_hdr);
	CHECK_MEMBER(llog_unlink_rec, lur_oid);
	CHECK_MEMBER(llog_unlink_rec, lur_oseq);
	CHECK_MEMBER(llog_unlink_rec, lur_count);
	CHECK_MEMBER(llog_unlink_rec, lur_tail);
}

static void
check_llog_unlink64_rec(void)
{
	CHECK_STRUCT(llog_unlink64_rec);
	CHECK_MEMBER(llog_unlink64_rec, lur_hdr);
	CHECK_MEMBER(llog_unlink64_rec, lur_fid);
	CHECK_MEMBER(llog_unlink64_rec, lur_count);
	CHECK_MEMBER(llog_unlink64_rec, lur_tail);
	CHECK_MEMBER(llog_unlink64_rec, lur_padding1);
	CHECK_MEMBER(llog_unlink64_rec, lur_padding2);
	CHECK_MEMBER(llog_unlink64_rec, lur_padding3);
}

static void
check_llog_setattr64_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_setattr64_rec);
	CHECK_MEMBER(llog_setattr64_rec, lsr_hdr);
	CHECK_MEMBER(llog_setattr64_rec, lsr_oi);
	CHECK_MEMBER(llog_setattr64_rec, lsr_uid);
	CHECK_MEMBER(llog_setattr64_rec, lsr_uid_h);
	CHECK_MEMBER(llog_setattr64_rec, lsr_gid);
	CHECK_MEMBER(llog_setattr64_rec, lsr_gid_h);
	CHECK_MEMBER(llog_setattr64_rec, lsr_valid);
	CHECK_MEMBER(llog_setattr64_rec, lsr_tail);
	CHECK_MEMBER(llog_setattr64_rec_v2, lsr_projid);
}

static void
check_llog_size_change_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_size_change_rec);
	CHECK_MEMBER(llog_size_change_rec, lsc_hdr);
	CHECK_MEMBER(llog_size_change_rec, lsc_fid);
	CHECK_MEMBER(llog_size_change_rec, lsc_ioepoch);
	CHECK_MEMBER(llog_size_change_rec, lsc_padding1);
	CHECK_MEMBER(llog_size_change_rec, lsc_padding2);
	CHECK_MEMBER(llog_size_change_rec, lsc_padding3);
	CHECK_MEMBER(llog_size_change_rec, lsc_tail);
}

static void
check_changelog_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(changelog_rec);
	CHECK_MEMBER(changelog_rec, cr_namelen);
	CHECK_MEMBER(changelog_rec, cr_flags);
	CHECK_MEMBER(changelog_rec, cr_type);
	CHECK_MEMBER(changelog_rec, cr_index);
	CHECK_MEMBER(changelog_rec, cr_prev);
	CHECK_MEMBER(changelog_rec, cr_time);
	CHECK_MEMBER(changelog_rec, cr_tfid);
	CHECK_MEMBER(changelog_rec, cr_pfid);
}

static void
check_changelog_ext_rename(void)
{
	BLANK_LINE();
	CHECK_STRUCT(changelog_ext_rename);
	CHECK_MEMBER(changelog_ext_rename, cr_sfid);
	CHECK_MEMBER(changelog_ext_rename, cr_spfid);
}

static void
check_changelog_ext_jobid(void)
{
	BLANK_LINE();
	CHECK_STRUCT(changelog_ext_jobid);
	CHECK_MEMBER(changelog_ext_jobid, cr_jobid);
}

static void
check_changelog_setinfo(void)
{
	BLANK_LINE();
	CHECK_STRUCT(changelog_setinfo);
	CHECK_MEMBER(changelog_setinfo, cs_recno);
	CHECK_MEMBER(changelog_setinfo, cs_id);
}

static void
check_llog_changelog_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_changelog_rec);
	CHECK_MEMBER(llog_changelog_rec, cr_hdr);
	CHECK_MEMBER(llog_changelog_rec, cr);
	CHECK_MEMBER(llog_changelog_rec, cr_do_not_use);
}

static void
check_llog_changelog_user_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_changelog_user_rec);
	CHECK_MEMBER(llog_changelog_user_rec, cur_hdr);
	CHECK_MEMBER(llog_changelog_user_rec, cur_id);
	CHECK_MEMBER(llog_changelog_user_rec, cur_time);
	CHECK_MEMBER(llog_changelog_user_rec, cur_endrec);
	CHECK_MEMBER(llog_changelog_user_rec, cur_tail);
}

static void
check_llog_gen(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_gen);
	CHECK_MEMBER(llog_gen, mnt_cnt);
	CHECK_MEMBER(llog_gen, conn_cnt);
}

static void
check_llog_gen_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_gen_rec);
	CHECK_MEMBER(llog_gen_rec, lgr_hdr);
	CHECK_MEMBER(llog_gen_rec, lgr_gen);
	CHECK_MEMBER(llog_gen_rec, lgr_tail);
}

static void
check_llog_log_hdr(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_log_hdr);
	CHECK_MEMBER(llog_log_hdr, llh_hdr);
	CHECK_MEMBER(llog_log_hdr, llh_timestamp);
	CHECK_MEMBER(llog_log_hdr, llh_count);
	CHECK_MEMBER(llog_log_hdr, llh_bitmap_offset);
	CHECK_MEMBER(llog_log_hdr, llh_size);
	CHECK_MEMBER(llog_log_hdr, llh_flags);
	CHECK_MEMBER(llog_log_hdr, llh_cat_idx);
	CHECK_MEMBER(llog_log_hdr, llh_tgtuuid);
}

static void
check_llogd_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llogd_body);
	CHECK_MEMBER(llogd_body, lgd_logid);
	CHECK_MEMBER(llogd_body, lgd_ctxt_idx);
	CHECK_MEMBER(llogd_body, lgd_llh_flags);
	CHECK_MEMBER(llogd_body, lgd_index);
	CHECK_MEMBER(llogd_body, lgd_saved_index);
	CHECK_MEMBER(llogd_body, lgd_len);
	CHECK_MEMBER(llogd_body, lgd_cur_offset);

	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_CREATE);
	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_NEXT_BLOCK);
	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_READ_HEADER);
	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_WRITE_REC);
	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_CLOSE);
	CHECK_CVALUE(LLOG_ORIGIN_CONNECT);
	CHECK_CVALUE(LLOG_CATINFO);
	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_PREV_BLOCK);
	CHECK_CVALUE(LLOG_ORIGIN_HANDLE_DESTROY);
	CHECK_CVALUE(LLOG_FIRST_OPC);
	CHECK_CVALUE(LLOG_LAST_OPC);

	CHECK_CVALUE(LLOG_CONFIG_ORIG_CTXT);
	CHECK_CVALUE(LLOG_CONFIG_REPL_CTXT);
	CHECK_CVALUE(LLOG_MDS_OST_ORIG_CTXT);
	CHECK_CVALUE(LLOG_MDS_OST_REPL_CTXT);
	CHECK_CVALUE(LLOG_SIZE_ORIG_CTXT);
	CHECK_CVALUE(LLOG_SIZE_REPL_CTXT);
	CHECK_CVALUE(LLOG_TEST_ORIG_CTXT);
	CHECK_CVALUE(LLOG_TEST_REPL_CTXT);
	CHECK_CVALUE(LLOG_CHANGELOG_ORIG_CTXT);
	CHECK_CVALUE(LLOG_CHANGELOG_REPL_CTXT);
	CHECK_CVALUE(LLOG_CHANGELOG_USER_ORIG_CTXT);
	CHECK_CVALUE(LLOG_AGENT_ORIG_CTXT);
	CHECK_CVALUE(LLOG_UPDATELOG_ORIG_CTXT);
	CHECK_CVALUE(LLOG_UPDATELOG_REPL_CTXT);
	CHECK_CVALUE(LLOG_MAX_CTXTS);
}

static void
check_llogd_conn_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llogd_conn_body);
	CHECK_MEMBER(llogd_conn_body, lgdc_gen);
	CHECK_MEMBER(llogd_conn_body, lgdc_logid);
	CHECK_MEMBER(llogd_conn_body, lgdc_ctxt_idx);
}

static void
check_ll_fiemap_info_key(void)
{
	BLANK_LINE();
	CHECK_STRUCT(ll_fiemap_info_key);
	CHECK_MEMBER(ll_fiemap_info_key, lfik_name[8]);
	CHECK_MEMBER(ll_fiemap_info_key, lfik_oa);
	CHECK_MEMBER(ll_fiemap_info_key, lfik_fiemap);
}

static void
check_quota_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(quota_body);
	CHECK_MEMBER(quota_body, qb_fid);
	CHECK_MEMBER(quota_body, qb_id);
	CHECK_MEMBER(quota_body, qb_flags);
	CHECK_MEMBER(quota_body, qb_padding);
	CHECK_MEMBER(quota_body, qb_count);
	CHECK_MEMBER(quota_body, qb_usage);
	CHECK_MEMBER(quota_body, qb_slv_ver);
	CHECK_MEMBER(quota_body, qb_lockh);
	CHECK_MEMBER(quota_body, qb_glb_lockh);
	CHECK_MEMBER(quota_body, qb_padding1[4]);
}

static void
check_mgs_target_info(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mgs_target_info);
	CHECK_MEMBER(mgs_target_info, mti_lustre_ver);
	CHECK_MEMBER(mgs_target_info, mti_stripe_index);
	CHECK_MEMBER(mgs_target_info, mti_config_ver);
	CHECK_MEMBER(mgs_target_info, mti_flags);
	CHECK_MEMBER(mgs_target_info, mti_nid_count);
	CHECK_MEMBER(mgs_target_info, mti_instance);
	CHECK_MEMBER(mgs_target_info, mti_fsname);
	CHECK_MEMBER(mgs_target_info, mti_svname);
	CHECK_MEMBER(mgs_target_info, mti_uuid);
	CHECK_MEMBER(mgs_target_info, mti_nids);
	CHECK_MEMBER(mgs_target_info, mti_params);
}

static void
check_mgs_nidtbl_entry(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mgs_nidtbl_entry);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_version);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_instance);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_index);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_length);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_type);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_nid_type);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_nid_size);
	CHECK_MEMBER(mgs_nidtbl_entry, mne_nid_count);
	CHECK_MEMBER(mgs_nidtbl_entry, u.nids[0]);
}

static void
check_mgs_config_body(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mgs_config_body);
	CHECK_MEMBER(mgs_config_body, mcb_name);
	CHECK_MEMBER(mgs_config_body, mcb_offset);
	CHECK_MEMBER(mgs_config_body, mcb_type);
	CHECK_MEMBER(mgs_config_body, mcb_nm_cur_pass);
	CHECK_MEMBER(mgs_config_body, mcb_bits);
	CHECK_MEMBER(mgs_config_body, mcb_units);

	CHECK_CVALUE(CONFIG_T_CONFIG);
	CHECK_CVALUE(CONFIG_T_SPTLRPC);
	CHECK_CVALUE(CONFIG_T_RECOVER);
	CHECK_CVALUE(CONFIG_T_PARAMS);
	CHECK_CVALUE(CONFIG_T_NODEMAP);
	CHECK_CVALUE(CONFIG_T_BARRIER);
}

static void
check_mgs_config_res(void)
{
	BLANK_LINE();
	CHECK_STRUCT(mgs_config_res);
	CHECK_MEMBER(mgs_config_res, mcr_offset);
	CHECK_MEMBER(mgs_config_res, mcr_size);
}

static void
check_lustre_capa(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lustre_capa);
	CHECK_MEMBER(lustre_capa, lc_fid);
	CHECK_MEMBER(lustre_capa, lc_opc);
	CHECK_MEMBER(lustre_capa, lc_uid);
	CHECK_MEMBER(lustre_capa, lc_gid);
	CHECK_MEMBER(lustre_capa, lc_flags);
	CHECK_MEMBER(lustre_capa, lc_keyid);
	CHECK_MEMBER(lustre_capa, lc_timeout);
	CHECK_MEMBER(lustre_capa, lc_expiry);
	CHECK_CVALUE(CAPA_HMAC_MAX_LEN);
	CHECK_MEMBER(lustre_capa, lc_hmac[CAPA_HMAC_MAX_LEN]);
}

static void
check_lustre_capa_key(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lustre_capa_key);
	CHECK_MEMBER(lustre_capa_key, lk_seq);
	CHECK_MEMBER(lustre_capa_key, lk_keyid);
	CHECK_MEMBER(lustre_capa_key, lk_padding);
	CHECK_CVALUE(CAPA_HMAC_KEY_MAX_LEN);
	CHECK_MEMBER(lustre_capa_key, lk_key[CAPA_HMAC_KEY_MAX_LEN]);
}

static void
check_getinfo_fid2path(void)
{
	BLANK_LINE();
	CHECK_STRUCT(getinfo_fid2path);
	CHECK_MEMBER(getinfo_fid2path, gf_fid);
	CHECK_MEMBER(getinfo_fid2path, gf_recno);
	CHECK_MEMBER(getinfo_fid2path, gf_linkno);
	CHECK_MEMBER(getinfo_fid2path, gf_pathlen);
	CHECK_MEMBER(getinfo_fid2path, gf_u.gf_path[0]);
}

/* We don't control the definitions of posix_acl_xattr_{entry,header}
 * and so we shouldn't have used them in our wire protocol. But it's
 * too late now and so we emit checks against the *fixed* definitions
 * below. See LU-5607. */

typedef struct {
	__u16			e_tag;
	__u16			e_perm;
	__u32			e_id;
} posix_acl_xattr_entry;

typedef struct {
	__u32			a_version;
	posix_acl_xattr_entry	a_entries[0];
} posix_acl_xattr_header;

static void
check_posix_acl_xattr_entry(void)
{
	BLANK_LINE();
	printf("#ifdef CONFIG_FS_POSIX_ACL\n");
	CHECK_STRUCT_TYPEDEF(posix_acl_xattr_entry);
	CHECK_MEMBER_TYPEDEF(posix_acl_xattr_entry, e_tag);
	CHECK_MEMBER_TYPEDEF(posix_acl_xattr_entry, e_perm);
	CHECK_MEMBER_TYPEDEF(posix_acl_xattr_entry, e_id);
	printf("#endif /* CONFIG_FS_POSIX_ACL */\n");
}

static void
check_posix_acl_xattr_header(void)
{
	BLANK_LINE();
	printf("#ifdef CONFIG_FS_POSIX_ACL\n");
	CHECK_STRUCT_TYPEDEF(posix_acl_xattr_header);
	CHECK_MEMBER_TYPEDEF(posix_acl_xattr_header, a_version);
	printf("#ifndef HAVE_STRUCT_POSIX_ACL_XATTR\n");
	CHECK_MEMBER_TYPEDEF(posix_acl_xattr_header, a_entries);
	printf("#endif /* HAVE_STRUCT_POSIX_ACL_XATTR */\n");
	printf("#endif /* CONFIG_FS_POSIX_ACL */\n");
}

static void
check_ll_user_fiemap(void)
{
	BLANK_LINE();
	CHECK_STRUCT(fiemap);
	CHECK_MEMBER(fiemap, fm_start);
	CHECK_MEMBER(fiemap, fm_length);
	CHECK_MEMBER(fiemap, fm_flags);
	CHECK_MEMBER(fiemap, fm_mapped_extents);
	CHECK_MEMBER(fiemap, fm_extent_count);
	CHECK_MEMBER(fiemap, fm_reserved);
	CHECK_MEMBER(fiemap, fm_extents);

	CHECK_CDEFINE(FIEMAP_FLAG_SYNC);
	CHECK_CDEFINE(FIEMAP_FLAG_XATTR);
	CHECK_CDEFINE(FIEMAP_FLAG_DEVICE_ORDER);
}

static void
check_ll_fiemap_extent(void)
{
	BLANK_LINE();
	CHECK_STRUCT(fiemap_extent);
	CHECK_MEMBER(fiemap_extent, fe_logical);
	CHECK_MEMBER(fiemap_extent, fe_physical);
	CHECK_MEMBER(fiemap_extent, fe_length);
	CHECK_MEMBER(fiemap_extent, fe_flags);
	CHECK_MEMBER(fiemap_extent, fe_device);

	CHECK_CDEFINE(FIEMAP_EXTENT_LAST);
	CHECK_CDEFINE(FIEMAP_EXTENT_UNKNOWN);
	CHECK_CDEFINE(FIEMAP_EXTENT_DELALLOC);
	CHECK_CDEFINE(FIEMAP_EXTENT_ENCODED);
	CHECK_CDEFINE(FIEMAP_EXTENT_DATA_ENCRYPTED);
	CHECK_CDEFINE(FIEMAP_EXTENT_NOT_ALIGNED);
	CHECK_CDEFINE(FIEMAP_EXTENT_DATA_INLINE);
	CHECK_CDEFINE(FIEMAP_EXTENT_DATA_TAIL);
	CHECK_CDEFINE(FIEMAP_EXTENT_UNWRITTEN);
	CHECK_CDEFINE(FIEMAP_EXTENT_MERGED);
	CHECK_CDEFINE(FIEMAP_EXTENT_NO_DIRECT);
	CHECK_CDEFINE(FIEMAP_EXTENT_NET);
}

static void
check_link_ea_header(void)
{
	BLANK_LINE();
	CHECK_STRUCT(link_ea_header);
	CHECK_MEMBER(link_ea_header, leh_magic);
	CHECK_MEMBER(link_ea_header, leh_reccount);
	CHECK_MEMBER(link_ea_header, leh_len);
	CHECK_MEMBER(link_ea_header, leh_overflow_time);
	CHECK_MEMBER(link_ea_header, leh_padding);

	CHECK_CDEFINE(LINK_EA_MAGIC);
}

static void
check_link_ea_entry(void)
{
	BLANK_LINE();
	CHECK_STRUCT(link_ea_entry);
	CHECK_MEMBER(link_ea_entry, lee_reclen);
	CHECK_MEMBER(link_ea_entry, lee_parent_fid);
	CHECK_MEMBER(link_ea_entry, lee_name);
}

static void
check_hsm_user_item(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_user_item);
	CHECK_MEMBER(hsm_user_item, hui_fid);
	CHECK_MEMBER(hsm_user_item, hui_extent);
}

static void
check_hsm_user_state(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_user_state);
	CHECK_MEMBER(hsm_user_state, hus_states);
	CHECK_MEMBER(hsm_user_state, hus_archive_id);
	CHECK_MEMBER(hsm_user_state, hus_in_progress_state);
	CHECK_MEMBER(hsm_user_state, hus_in_progress_action);
	CHECK_MEMBER(hsm_user_state, hus_in_progress_location);
}

static void
check_hsm_action_item(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_action_item);
	CHECK_MEMBER(hsm_action_item, hai_len);
	CHECK_MEMBER(hsm_action_item, hai_action);
	CHECK_MEMBER(hsm_action_item, hai_fid);
	CHECK_MEMBER(hsm_action_item, hai_dfid);
	CHECK_MEMBER(hsm_action_item, hai_extent);
	CHECK_MEMBER(hsm_action_item, hai_cookie);
	CHECK_MEMBER(hsm_action_item, hai_gid);
	CHECK_MEMBER(hsm_action_item, hai_data);
}

static void
check_hsm_action_list(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_action_list);
	CHECK_MEMBER(hsm_action_list, hal_version);
	CHECK_MEMBER(hsm_action_list, hal_count);
	CHECK_MEMBER(hsm_action_list, hal_compound_id);
	CHECK_MEMBER(hsm_action_list, hal_flags);
	CHECK_MEMBER(hsm_action_list, hal_archive_id);
	CHECK_MEMBER(hsm_action_list, padding1);
	CHECK_MEMBER(hsm_action_list, hal_fsname);
}

static void
check_hsm_progress_kernel(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_progress_kernel);
	CHECK_MEMBER(hsm_progress_kernel, hpk_fid);
	CHECK_MEMBER(hsm_progress_kernel, hpk_cookie);
	CHECK_MEMBER(hsm_progress_kernel, hpk_extent);
	CHECK_MEMBER(hsm_progress_kernel, hpk_flags);
	CHECK_MEMBER(hsm_progress_kernel, hpk_errval);
	CHECK_MEMBER(hsm_progress_kernel, hpk_padding1);
	CHECK_MEMBER(hsm_progress_kernel, hpk_data_version);
	CHECK_MEMBER(hsm_progress_kernel, hpk_padding2);
}

static void
check_hsm_progress(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_progress);
	CHECK_MEMBER(hsm_progress, hp_fid);
	CHECK_MEMBER(hsm_progress, hp_cookie);
	CHECK_MEMBER(hsm_progress, hp_extent);
	CHECK_MEMBER(hsm_progress, hp_flags);
	CHECK_MEMBER(hsm_progress, hp_errval);
	CHECK_MEMBER(hsm_progress, padding);
	CHECK_DEFINE_X(HP_FLAG_COMPLETED);
	CHECK_DEFINE_X(HP_FLAG_RETRY);
}

static void
check_hsm_copy(void)
{
	BLANK_LINE();
	CHECK_MEMBER(hsm_copy, hc_data_version);
	CHECK_MEMBER(hsm_copy, hc_flags);
	CHECK_MEMBER(hsm_copy, hc_errval);
	CHECK_MEMBER(hsm_copy, padding);
	CHECK_MEMBER(hsm_copy, hc_hai);
}

static void check_layout_intent(void)
{
        BLANK_LINE();
        CHECK_STRUCT(layout_intent);
        CHECK_MEMBER(layout_intent, li_opc);
        CHECK_MEMBER(layout_intent, li_flags);
        CHECK_MEMBER(layout_intent, li_start);
        CHECK_MEMBER(layout_intent, li_end);

	CHECK_VALUE(LAYOUT_INTENT_ACCESS);
	CHECK_VALUE(LAYOUT_INTENT_READ);
	CHECK_VALUE(LAYOUT_INTENT_WRITE);
	CHECK_VALUE(LAYOUT_INTENT_GLIMPSE);
	CHECK_VALUE(LAYOUT_INTENT_TRUNC);
	CHECK_VALUE(LAYOUT_INTENT_RELEASE);
	CHECK_VALUE(LAYOUT_INTENT_RESTORE);
}

static void check_hsm_state_set(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_state_set);
	CHECK_MEMBER(hsm_state_set, hss_valid);
	CHECK_MEMBER(hsm_state_set, hss_archive_id);
	CHECK_MEMBER(hsm_state_set, hss_setmask);
	CHECK_MEMBER(hsm_state_set, hss_clearmask);
}

static void check_hsm_current_action(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_current_action);
	CHECK_MEMBER(hsm_current_action, hca_state);
	CHECK_MEMBER(hsm_current_action, hca_action);
	CHECK_MEMBER(hsm_current_action, hca_location);
}

static void check_hsm_request(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_request);
	CHECK_MEMBER(hsm_request, hr_action);
	CHECK_MEMBER(hsm_request, hr_archive_id);
	CHECK_MEMBER(hsm_request, hr_flags);
	CHECK_MEMBER(hsm_request, hr_itemcount);
	CHECK_MEMBER(hsm_request, hr_data_len);
	CHECK_VALUE_X(HSM_FORCE_ACTION);
	CHECK_VALUE_X(HSM_GHOST_COPY);
}

static void check_hsm_user_request(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_user_request);
	CHECK_MEMBER(hsm_user_request, hur_request);
	CHECK_MEMBER(hsm_user_request, hur_user_item);
}

static void check_hsm_user_import(void)
{
	BLANK_LINE();
	CHECK_STRUCT(hsm_user_import);
	CHECK_MEMBER(hsm_user_import, hui_size);
	CHECK_MEMBER(hsm_user_import, hui_uid);
	CHECK_MEMBER(hsm_user_import, hui_gid);
	CHECK_MEMBER(hsm_user_import, hui_mode);
	CHECK_MEMBER(hsm_user_import, hui_atime);
	CHECK_MEMBER(hsm_user_import, hui_atime_ns);
	CHECK_MEMBER(hsm_user_import, hui_mtime);
	CHECK_MEMBER(hsm_user_import, hui_mtime_ns);
	CHECK_MEMBER(hsm_user_import, hui_archive_id);
}

static void check_object_update_param(void)
{
	BLANK_LINE();
	CHECK_STRUCT(object_update_param);
	CHECK_MEMBER(object_update_param, oup_len);
	CHECK_MEMBER(object_update_param, oup_padding);
	CHECK_MEMBER(object_update_param, oup_padding2);
	CHECK_MEMBER(object_update_param, oup_buf);
}

static void check_object_update(void)
{
	BLANK_LINE();
	CHECK_STRUCT(object_update);
	CHECK_MEMBER(object_update, ou_type);
	CHECK_MEMBER(object_update, ou_params_count);
	CHECK_MEMBER(object_update, ou_result_size);
	CHECK_MEMBER(object_update, ou_flags);
	CHECK_MEMBER(object_update, ou_padding1);
	CHECK_MEMBER(object_update, ou_batchid);
	CHECK_MEMBER(object_update, ou_fid);
	CHECK_MEMBER(object_update, ou_params);
}

static void check_object_update_request(void)
{
	BLANK_LINE();
	CHECK_STRUCT(object_update_request);
	CHECK_MEMBER(object_update_request, ourq_magic);
	CHECK_MEMBER(object_update_request, ourq_count);
	CHECK_MEMBER(object_update_request, ourq_padding);
	CHECK_MEMBER(object_update_request, ourq_updates);
}

static void check_object_update_result(void)
{
	BLANK_LINE();
	CHECK_STRUCT(object_update_result);
	CHECK_MEMBER(object_update_result, our_rc);
	CHECK_MEMBER(object_update_result, our_datalen);
	CHECK_MEMBER(object_update_result, our_padding);
	CHECK_MEMBER(object_update_result, our_data);
}

static void check_object_update_reply(void)
{
	BLANK_LINE();
	CHECK_STRUCT(object_update_reply);
	CHECK_MEMBER(object_update_reply, ourp_magic);
	CHECK_MEMBER(object_update_reply, ourp_count);
	CHECK_MEMBER(object_update_reply, ourp_padding);
	CHECK_MEMBER(object_update_reply, ourp_lens);
}

static void check_out_update_header(void)
{
	BLANK_LINE();
	CHECK_STRUCT(out_update_header);
	CHECK_MEMBER(out_update_header, ouh_magic);
	CHECK_MEMBER(out_update_header, ouh_count);
	CHECK_MEMBER(out_update_header, ouh_inline_length);
	CHECK_MEMBER(out_update_header, ouh_reply_size);
	CHECK_MEMBER(out_update_header, ouh_inline_data);
}

static void check_out_update_buffer(void)
{
	BLANK_LINE();
	CHECK_STRUCT(out_update_buffer);
	CHECK_MEMBER(out_update_buffer, oub_size);
	CHECK_MEMBER(out_update_buffer, oub_padding);
}

static void check_nodemap_cluster_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(nodemap_cluster_rec);
	CHECK_MEMBER(nodemap_cluster_rec, ncr_name);
	CHECK_MEMBER(nodemap_cluster_rec, ncr_flags);
	CHECK_MEMBER(nodemap_cluster_rec, ncr_padding1);
	CHECK_MEMBER(nodemap_cluster_rec, ncr_padding2);
	CHECK_MEMBER(nodemap_cluster_rec, ncr_squash_uid);
	CHECK_MEMBER(nodemap_cluster_rec, ncr_squash_gid);
}

static void check_nodemap_range_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(nodemap_range_rec);
	CHECK_MEMBER(nodemap_range_rec, nrr_start_nid);
	CHECK_MEMBER(nodemap_range_rec, nrr_end_nid);
	CHECK_MEMBER(nodemap_range_rec, nrr_padding1);
	CHECK_MEMBER(nodemap_range_rec, nrr_padding2);
}

static void check_nodemap_id_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(nodemap_id_rec);
	CHECK_MEMBER(nodemap_id_rec, nir_id_fs);
	CHECK_MEMBER(nodemap_id_rec, nir_padding1);
	CHECK_MEMBER(nodemap_id_rec, nir_padding2);
	CHECK_MEMBER(nodemap_id_rec, nir_padding3);
	CHECK_MEMBER(nodemap_id_rec, nir_padding4);
}

static void check_nodemap_global_rec(void)
{
	BLANK_LINE();
	CHECK_STRUCT(nodemap_global_rec);
	CHECK_MEMBER(nodemap_global_rec, ngr_is_active);
	CHECK_MEMBER(nodemap_global_rec, ngr_padding1);
	CHECK_MEMBER(nodemap_global_rec, ngr_padding2);
	CHECK_MEMBER(nodemap_global_rec, ngr_padding3);
	CHECK_MEMBER(nodemap_global_rec, ngr_padding4);
	CHECK_MEMBER(nodemap_global_rec, ngr_padding5);
	CHECK_MEMBER(nodemap_global_rec, ngr_padding6);
}

static void check_nodemap_rec(void)
{
	BLANK_LINE();
	CHECK_UNION(nodemap_rec);
}

static void check_lfsck_request(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lfsck_request);
	CHECK_MEMBER(lfsck_request, lr_event);
	CHECK_MEMBER(lfsck_request, lr_index);
	CHECK_MEMBER(lfsck_request, lr_flags);
	CHECK_MEMBER(lfsck_request, lr_valid);
	CHECK_MEMBER(lfsck_request, lr_speed);
	CHECK_MEMBER(lfsck_request, lr_version);
	CHECK_MEMBER(lfsck_request, lr_active);
	CHECK_MEMBER(lfsck_request, lr_param);
	CHECK_MEMBER(lfsck_request, lr_async_windows);
	CHECK_MEMBER(lfsck_request, lr_flags);
	CHECK_MEMBER(lfsck_request, lr_fid);
	CHECK_MEMBER(lfsck_request, lr_fid2);
	CHECK_MEMBER(lfsck_request, lr_comp_id);
	CHECK_MEMBER(lfsck_request, lr_padding_0);
	CHECK_MEMBER(lfsck_request, lr_padding_1);
	CHECK_MEMBER(lfsck_request, lr_padding_2);
	CHECK_MEMBER(lfsck_request, lr_padding_3);

	CHECK_VALUE_X(LFSCK_TYPE_SCRUB);
	CHECK_VALUE_X(LFSCK_TYPE_LAYOUT);
	CHECK_VALUE_X(LFSCK_TYPE_NAMESPACE);

	CHECK_VALUE(LE_LASTID_REBUILDING);
	CHECK_VALUE(LE_LASTID_REBUILT);
	CHECK_VALUE(LE_PHASE1_DONE);
	CHECK_VALUE(LE_PHASE2_DONE);
	CHECK_VALUE(LE_START);
	CHECK_VALUE(LE_STOP);
	CHECK_VALUE(LE_QUERY);
	CHECK_VALUE(LE_PEER_EXIT);
	CHECK_VALUE(LE_CONDITIONAL_DESTROY);
	CHECK_VALUE(LE_PAIRS_VERIFY);
	CHECK_VALUE(LE_SET_LMV_MASTER);
	CHECK_VALUE(LE_SET_LMV_SLAVE);

	CHECK_VALUE_X(LEF_TO_OST);
	CHECK_VALUE_X(LEF_FROM_OST);
	CHECK_VALUE_X(LEF_SET_LMV_HASH);
	CHECK_VALUE_X(LEF_SET_LMV_ALL);
	CHECK_VALUE_X(LEF_RECHECK_NAME_HASH);
	CHECK_VALUE_X(LEF_QUERY_ALL);
}

static void check_lfsck_reply(void)
{
	BLANK_LINE();
	CHECK_STRUCT(lfsck_reply);
	CHECK_MEMBER(lfsck_reply, lr_status);
	CHECK_MEMBER(lfsck_reply, lr_padding_1);
	CHECK_MEMBER(lfsck_reply, lr_repaired);
}

static void check_update_params(void)
{
	BLANK_LINE();
	CHECK_STRUCT(update_params);
	CHECK_MEMBER(update_params, up_params);
}

static void check_update_op(void)
{
	BLANK_LINE();
	CHECK_STRUCT(update_op);
	CHECK_MEMBER(update_op, uop_fid);
	CHECK_MEMBER(update_op, uop_type);
	CHECK_MEMBER(update_op, uop_param_count);
	CHECK_MEMBER(update_op, uop_params_off);
}

static void check_update_ops(void)
{
	BLANK_LINE();
	CHECK_STRUCT(update_ops);
	CHECK_MEMBER(update_ops, uops_op);
}

static void check_update_records(void)
{
	BLANK_LINE();
	CHECK_STRUCT(update_records);
	CHECK_MEMBER(update_records, ur_master_transno);
	CHECK_MEMBER(update_records, ur_batchid);
	CHECK_MEMBER(update_records, ur_flags);
	CHECK_MEMBER(update_records, ur_index);
	CHECK_MEMBER(update_records, ur_update_count);
	CHECK_MEMBER(update_records, ur_param_count);

	CHECK_VALUE_X(UPDATE_RECORD_CONTINUE);
}

static void check_llog_update_record(void)
{
	BLANK_LINE();
	CHECK_STRUCT(llog_update_record);
	CHECK_MEMBER(llog_update_record, lur_hdr);
	CHECK_MEMBER(llog_update_record, lur_update_rec);
}

static void system_string(char *cmdline, char *str, int len)
{
	int   fds[2];
	int   rc;
	pid_t pid;

	rc = pipe(fds);
	if (rc != 0)
		abort();

	pid = fork();
	if (pid == 0) {
		/* child */
		int   fd = fileno(stdout);

		rc = dup2(fds[1], fd);
		if (rc != fd)
			abort();

		exit(system(cmdline));
		/* notreached */
	} else if ((int)pid < 0) {
		abort();
	} else {
		FILE *f = fdopen(fds[0], "r");

		if (f == NULL)
			abort();

		close(fds[1]);

		if (fgets(str, len, f) == NULL)
			abort();

		if (waitpid(pid, &rc, 0) != pid)
			abort();

		if (!WIFEXITED(rc) || WEXITSTATUS(rc) != 0)
			abort();

		if (strnlen(str, len) == len)
			str[len - 1] = 0;

		if (str[strlen(str) - 1] == '\n')
			str[strlen(str) - 1] = 0;

		fclose(f);
	}
}

int
main(int argc, char **argv)
{
	char unameinfo[80];
	char gccinfo[80];

	system_string("uname -a", unameinfo, sizeof(unameinfo));
	system_string(CC " -v 2>&1 | tail -1", gccinfo, sizeof(gccinfo));

	printf ("void lustre_assert_wire_constants(void)\n"
		"{\n"
		"	 /* Wire protocol assertions generated by 'wirecheck'\n"
		"	  * (make -C lustre/utils newwiretest)\n"
		"	  * running on %s\n"
		"	  * with %s */\n"
		"\n", unameinfo, gccinfo);

	BLANK_LINE ();

	COMMENT("Constants...");
	CHECK_VALUE(PTL_RPC_MSG_REQUEST);
	CHECK_VALUE(PTL_RPC_MSG_ERR);
	CHECK_VALUE(PTL_RPC_MSG_REPLY);

	CHECK_DEFINE_64X(MDS_DIR_END_OFF);

	CHECK_DEFINE_64X(DEAD_HANDLE_MAGIC);

	CHECK_CVALUE(MTI_NAME_MAXLEN);

	CHECK_VALUE(OST_REPLY);
	CHECK_VALUE(OST_GETATTR);
	CHECK_VALUE(OST_SETATTR);
	CHECK_VALUE(OST_READ);
	CHECK_VALUE(OST_WRITE);
	CHECK_VALUE(OST_CREATE);
	CHECK_VALUE(OST_DESTROY);
	CHECK_VALUE(OST_GET_INFO);
	CHECK_VALUE(OST_CONNECT);
	CHECK_VALUE(OST_DISCONNECT);
	CHECK_VALUE(OST_PUNCH);
	CHECK_VALUE(OST_OPEN);
	CHECK_VALUE(OST_CLOSE);
	CHECK_VALUE(OST_STATFS);
	CHECK_VALUE(OST_SYNC);
	CHECK_VALUE(OST_SET_INFO);
	CHECK_VALUE(OST_QUOTACHECK);
	CHECK_VALUE(OST_QUOTACTL);
	CHECK_VALUE(OST_QUOTA_ADJUST_QUNIT);
	CHECK_VALUE(OST_LADVISE);
	CHECK_VALUE(OST_LAST_OPC);

	CHECK_DEFINE_64X(OBD_OBJECT_EOF);

	CHECK_VALUE(OST_MIN_PRECREATE);
	CHECK_VALUE(OST_MAX_PRECREATE);

	CHECK_DEFINE_64X(OST_LVB_ERR_INIT);
	CHECK_DEFINE_64X(OST_LVB_ERR_MASK);

	CHECK_VALUE(MDS_FIRST_OPC);
	CHECK_VALUE(MDS_GETATTR);
	CHECK_VALUE(MDS_GETATTR_NAME);
	CHECK_VALUE(MDS_CLOSE);
	CHECK_VALUE(MDS_REINT);
	CHECK_VALUE(MDS_READPAGE);
	CHECK_VALUE(MDS_CONNECT);
	CHECK_VALUE(MDS_DISCONNECT);
	CHECK_VALUE(MDS_GET_ROOT);
	CHECK_VALUE(MDS_STATFS);
	CHECK_VALUE(MDS_PIN);
	CHECK_VALUE(MDS_UNPIN);
	CHECK_VALUE(MDS_SYNC);
	CHECK_VALUE(MDS_DONE_WRITING);
	CHECK_VALUE(MDS_SET_INFO);
	CHECK_VALUE(MDS_QUOTACHECK);
	CHECK_VALUE(MDS_QUOTACTL);
	CHECK_VALUE(MDS_GETXATTR);
	CHECK_VALUE(MDS_SETXATTR);
	CHECK_VALUE(MDS_WRITEPAGE);
	CHECK_VALUE(MDS_IS_SUBDIR);
	CHECK_VALUE(MDS_GET_INFO);
	CHECK_VALUE(MDS_HSM_STATE_GET);
	CHECK_VALUE(MDS_HSM_STATE_SET);
	CHECK_VALUE(MDS_HSM_ACTION);
	CHECK_VALUE(MDS_HSM_PROGRESS);
	CHECK_VALUE(MDS_HSM_REQUEST);
	CHECK_VALUE(MDS_HSM_CT_REGISTER);
	CHECK_VALUE(MDS_HSM_CT_UNREGISTER);
	CHECK_VALUE(MDS_SWAP_LAYOUTS);
	CHECK_VALUE(MDS_LAST_OPC);

	CHECK_VALUE(REINT_SETATTR);
	CHECK_VALUE(REINT_CREATE);
	CHECK_VALUE(REINT_LINK);
	CHECK_VALUE(REINT_UNLINK);
	CHECK_VALUE(REINT_RENAME);
	CHECK_VALUE(REINT_OPEN);
	CHECK_VALUE(REINT_SETXATTR);
	CHECK_VALUE(REINT_RMENTRY);
	CHECK_VALUE(REINT_MIGRATE);
	CHECK_VALUE(REINT_MAX);

	CHECK_VALUE_X(DISP_IT_EXECD);
	CHECK_VALUE_X(DISP_LOOKUP_EXECD);
	CHECK_VALUE_X(DISP_LOOKUP_NEG);
	CHECK_VALUE_X(DISP_LOOKUP_POS);
	CHECK_VALUE_X(DISP_OPEN_CREATE);
	CHECK_VALUE_X(DISP_OPEN_OPEN);
	CHECK_VALUE_X(DISP_ENQ_COMPLETE);
	CHECK_VALUE_X(DISP_ENQ_OPEN_REF);
	CHECK_VALUE_X(DISP_ENQ_CREATE_REF);
	CHECK_VALUE_X(DISP_OPEN_LOCK);

	CHECK_VALUE(MDS_STATUS_CONN);
	CHECK_VALUE(MDS_STATUS_LOV);

	CHECK_VALUE_64X(MDS_ATTR_MODE);
	CHECK_VALUE_64X(MDS_ATTR_UID);
	CHECK_VALUE_64X(MDS_ATTR_GID);
	CHECK_VALUE_64X(MDS_ATTR_SIZE);
	CHECK_VALUE_64X(MDS_ATTR_ATIME);
	CHECK_VALUE_64X(MDS_ATTR_MTIME);
	CHECK_VALUE_64X(MDS_ATTR_CTIME);
	CHECK_VALUE_64X(MDS_ATTR_ATIME_SET);
	CHECK_VALUE_64X(MDS_ATTR_MTIME_SET);
	CHECK_VALUE_64X(MDS_ATTR_FORCE);
	CHECK_VALUE_64X(MDS_ATTR_ATTR_FLAG);
	CHECK_VALUE_64X(MDS_ATTR_KILL_SUID);
	CHECK_VALUE_64X(MDS_ATTR_KILL_SGID);
	CHECK_VALUE_64X(MDS_ATTR_CTIME_SET);
	CHECK_VALUE_64X(MDS_ATTR_FROM_OPEN);
	CHECK_VALUE_64X(MDS_ATTR_BLOCKS);
	CHECK_VALUE_64X(MDS_ATTR_PROJID);

	CHECK_VALUE(FLD_QUERY);
	CHECK_VALUE(FLD_READ);
	CHECK_VALUE(FLD_FIRST_OPC);
	CHECK_VALUE(FLD_LAST_OPC);

	CHECK_VALUE(SEQ_QUERY);
	CHECK_VALUE(SEQ_FIRST_OPC);
	CHECK_VALUE(SEQ_LAST_OPC);

	CHECK_VALUE(LFSCK_NOTIFY);
	CHECK_VALUE(LFSCK_QUERY);
	CHECK_VALUE(LFSCK_FIRST_OPC);
	CHECK_VALUE(LFSCK_LAST_OPC);

	CHECK_VALUE(SEQ_ALLOC_SUPER);
	CHECK_VALUE(SEQ_ALLOC_META);

	CHECK_VALUE(LDLM_ENQUEUE);
	CHECK_VALUE(LDLM_CONVERT);
	CHECK_VALUE(LDLM_CANCEL);
	CHECK_VALUE(LDLM_BL_CALLBACK);
	CHECK_VALUE(LDLM_CP_CALLBACK);
	CHECK_VALUE(LDLM_GL_CALLBACK);
	CHECK_VALUE(LDLM_SET_INFO);
	CHECK_VALUE(LDLM_LAST_OPC);

	CHECK_VALUE(LCK_MINMODE);
	CHECK_VALUE(LCK_EX);
	CHECK_VALUE(LCK_PW);
	CHECK_VALUE(LCK_PR);
	CHECK_VALUE(LCK_CW);
	CHECK_VALUE(LCK_CR);
	CHECK_VALUE(LCK_NL);
	CHECK_VALUE(LCK_GROUP);
	CHECK_VALUE(LCK_COS);
	CHECK_VALUE(LCK_MAXMODE);
	CHECK_VALUE(LCK_MODE_NUM);

	CHECK_CVALUE(LDLM_PLAIN);
	CHECK_CVALUE(LDLM_EXTENT);
	CHECK_CVALUE(LDLM_FLOCK);
	CHECK_CVALUE(LDLM_IBITS);
	CHECK_CVALUE(LDLM_MAX_TYPE);

	CHECK_CVALUE(LUSTRE_RES_ID_SEQ_OFF);
	CHECK_CVALUE(LUSTRE_RES_ID_VER_OID_OFF);
	/* CHECK_CVALUE(LUSTRE_RES_ID_WAS_VER_OFF); packed with OID */

	CHECK_VALUE(OUT_UPDATE);
	CHECK_VALUE(OUT_UPDATE_LAST_OPC);
	CHECK_CVALUE(LUSTRE_RES_ID_QUOTA_SEQ_OFF);
	CHECK_CVALUE(LUSTRE_RES_ID_QUOTA_VER_OID_OFF);
	CHECK_CVALUE(LUSTRE_RES_ID_HSH_OFF);

	CHECK_CVALUE(LQUOTA_TYPE_USR);
	CHECK_CVALUE(LQUOTA_TYPE_GRP);

	CHECK_CVALUE(LQUOTA_RES_MD);
	CHECK_CVALUE(LQUOTA_RES_DT);

	CHECK_VALUE(OBD_PING);
	CHECK_VALUE(OBD_LOG_CANCEL);
	CHECK_VALUE(OBD_QC_CALLBACK);
	CHECK_VALUE(OBD_IDX_READ);
	CHECK_VALUE(OBD_LAST_OPC);

	CHECK_VALUE(QUOTA_DQACQ);
	CHECK_VALUE(QUOTA_DQREL);
	CHECK_VALUE(QUOTA_LAST_OPC);

	CHECK_VALUE(MGS_CONNECT);
	CHECK_VALUE(MGS_DISCONNECT);
	CHECK_VALUE(MGS_EXCEPTION);
	CHECK_VALUE(MGS_TARGET_REG);
	CHECK_VALUE(MGS_TARGET_DEL);
	CHECK_VALUE(MGS_SET_INFO);
	CHECK_VALUE(MGS_LAST_OPC);

	CHECK_VALUE(SEC_CTX_INIT);
	CHECK_VALUE(SEC_CTX_INIT_CONT);
	CHECK_VALUE(SEC_CTX_FINI);
	CHECK_VALUE(SEC_LAST_OPC);

	COMMENT("Sizes and Offsets");
	BLANK_LINE();
	CHECK_STRUCT(obd_uuid);
	check_lu_seq_range();
	check_lustre_mdt_attrs();
	check_lustre_ost_attrs();

	CHECK_VALUE(OUT_CREATE);
	CHECK_VALUE(OUT_DESTROY);
	CHECK_VALUE(OUT_REF_ADD);
	CHECK_VALUE(OUT_REF_DEL);
	CHECK_VALUE(OUT_ATTR_SET);
	CHECK_VALUE(OUT_ATTR_GET);
	CHECK_VALUE(OUT_XATTR_SET);
	CHECK_VALUE(OUT_XATTR_GET);
	CHECK_VALUE(OUT_INDEX_LOOKUP);
	CHECK_VALUE(OUT_INDEX_LOOKUP);
	CHECK_VALUE(OUT_INDEX_INSERT);
	CHECK_VALUE(OUT_INDEX_DELETE);
	CHECK_VALUE(OUT_WRITE);
	CHECK_VALUE(OUT_XATTR_DEL);
	CHECK_VALUE(OUT_PUNCH);
	CHECK_VALUE(OUT_READ);

	check_hsm_attrs();
	check_ost_id();
	check_lu_dirent();
	check_luda_type();
	check_lu_dirpage();
	check_lu_ladvise();
	check_ladvise_hdr();
	check_lustre_handle();
	check_lustre_msg_v2();
	check_ptlrpc_body();
	check_obd_connect_data();
	check_ost_layout();
	check_obdo();
	check_lov_ost_data_v1();
	check_lov_mds_md_v1();
	check_lov_mds_md_v3();
	check_lov_comp_md_entry_v1();
	check_lov_comp_md_v1();
	check_lmv_mds_md_v1();
	check_obd_statfs();
	check_obd_ioobj();
	check_obd_quotactl();
	check_obd_idx_read();
	check_niobuf_remote();
	check_ost_body();
	check_ll_fid();
	check_mdt_body();
	check_mdt_ioepoch();
	check_mdt_rec_setattr();
	check_mdt_rec_create();
	check_mdt_rec_link();
	check_mdt_rec_unlink();
	check_mdt_rec_rename();
	check_mdt_rec_setxattr();
	check_mdt_rec_reint();
	check_lmv_desc();
	check_lov_desc();
	check_ldlm_res_id();
	check_ldlm_extent();
	check_ldlm_inodebits();
	check_ldlm_flock();
	check_ldlm_intent();
	check_ldlm_resource_desc();
	check_ldlm_lock_desc();
	check_ldlm_request();
	check_ldlm_reply();
	check_ldlm_ost_lvb_v1();
	check_ldlm_ost_lvb();
	check_ldlm_lquota_lvb();
	check_ldlm_gl_lquota_desc();
	check_ldlm_gl_barrier_desc();
	check_ldlm_barrier_lvb();
#if LUSTRE_VERSION_CODE < OBD_OCD_VERSION(2, 13, 53, 0)
	check_mgs_send_param();
#endif
	check_cfg_marker();
	check_llog_logid();
	check_llog_catid();
	check_llog_rec_hdr();
	check_llog_rec_tail();
	check_llog_logid_rec();
	check_llog_unlink_rec();
	check_llog_unlink64_rec();
	check_llog_setattr64_rec();
	check_llog_size_change_rec();
	check_changelog_rec();
	check_changelog_ext_rename();
	check_changelog_ext_jobid();
	check_changelog_setinfo();
	check_llog_changelog_rec();
	check_llog_changelog_user_rec();
	check_llog_gen();
	check_llog_gen_rec();
	check_llog_log_hdr();
	check_llogd_body();
	check_llogd_conn_body();
	check_ll_fiemap_info_key();
	check_quota_body();
	check_mgs_target_info();
	check_mgs_nidtbl_entry();
	check_mgs_config_body();
	check_mgs_config_res();
	check_lustre_capa();
	check_lustre_capa_key();
	check_getinfo_fid2path();
	check_ll_user_fiemap();
	check_ll_fiemap_extent();
	check_posix_acl_xattr_entry();
	check_posix_acl_xattr_header();
	check_link_ea_header();
	check_link_ea_entry();
	check_layout_intent();
	check_hsm_action_item();
	check_hsm_action_list();
	check_hsm_progress();
	check_hsm_copy();
	check_hsm_progress_kernel();
	check_hsm_user_item();
	check_hsm_user_state();
	check_hsm_state_set();
	check_hsm_current_action();
	check_hsm_request();
	check_hsm_user_request();
	check_hsm_user_import();

	check_object_update_param();
	check_object_update();
	check_object_update_request();
	check_object_update_result();
	check_object_update_reply();
	check_out_update_header();
	check_out_update_buffer();

	check_nodemap_cluster_rec();
	check_nodemap_range_rec();
	check_nodemap_id_rec();
	check_nodemap_global_rec();
	check_nodemap_rec();

	check_lfsck_request();
	check_lfsck_reply();

	check_update_params();
	check_update_op();
	check_update_ops();
	check_update_records();
	check_llog_update_record();

	printf("}\n\n");

	return 0;
}
