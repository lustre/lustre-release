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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2011 Whamcloud, Inc.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <liblustre.h>
#include <lustre_lib.h>
#include <lustre/lustre_idl.h>
#include <lustre_disk.h>

#define BLANK_LINE()                                            \
do {                                                            \
        printf("\n");                                           \
} while(0)

#define COMMENT(c)                                              \
do {                                                            \
        printf("        /* "c" */\n");                          \
} while(0)

#define STRINGIFY(a) #a


#define CHECK_CDEFINE(a)                                        \
        printf("        CLASSERT("#a" == "STRINGIFY(a) ");\n")

#define CHECK_CVALUE(a)                                         \
        printf("        CLASSERT("#a" == %lld);\n", (long long)a)

#define CHECK_DEFINE(a)                                         \
do {                                                            \
        printf("        LASSERTF("#a" == "STRINGIFY(a)          \
               ",\" found %%lld\\n\",\n                 "       \
               "(long long)"#a");\n");   \
} while(0)

#define CHECK_VALUE(a)                                          \
do {                                                            \
        printf("        LASSERTF("#a                            \
               " == %lld, \" found %%lld\\n\",\n                 "\
               "(long long)"#a");\n", (long long)a);            \
} while(0)

#define CHECK_VALUE_64(a)                                       \
do {                                                            \
        printf("        LASSERTF("#a                            \
               " == %lldULL, \" found %%lld\\n\",\n                 "\
               "(long long)"#a");\n", (long long)a);            \
} while(0)

#define CHECK_MEMBER_OFFSET(s,m)                                \
do {                                                            \
        CHECK_VALUE((int)offsetof(struct s, m));                \
} while(0)

#define CHECK_MEMBER_OFFSET_TYPEDEF(s,m)                        \
do {                                                            \
        CHECK_VALUE((int)offsetof(s, m));                       \
} while(0)

#define CHECK_MEMBER_SIZEOF(s,m)                                \
do {                                                            \
        CHECK_VALUE((int)sizeof(((struct s *)0)->m));           \
} while(0)

#define CHECK_MEMBER_SIZEOF_TYPEDEF(s,m)                        \
do {                                                            \
        CHECK_VALUE((int)sizeof(((s *)0)->m));                  \
} while(0)

#define CHECK_MEMBER(s,m)                                       \
do {                                                            \
        CHECK_MEMBER_OFFSET(s, m);                              \
        CHECK_MEMBER_SIZEOF(s, m);                              \
} while(0)

#define CHECK_MEMBER_TYPEDEF(s,m)                               \
do {                                                            \
        CHECK_MEMBER_OFFSET_TYPEDEF(s, m);                      \
        CHECK_MEMBER_SIZEOF_TYPEDEF(s, m);                      \
} while(0)

#define CHECK_STRUCT(s)                                         \
do {                                                            \
        COMMENT("Checks for struct "#s);                        \
                CHECK_VALUE((int)sizeof(struct s));             \
} while(0)

#define CHECK_STRUCT_TYPEDEF(s)                                 \
do {                                                            \
        COMMENT("Checks for type "#s);                          \
                CHECK_VALUE((int)sizeof(s));                    \
} while(0)

static void
check_lustre_handle(void)
{
        BLANK_LINE();
        CHECK_STRUCT(lustre_handle);
        CHECK_MEMBER(lustre_handle, cookie);
}

void
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
}

void
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
        CHECK_MEMBER(ptlrpc_body, pb_last_seen);
        CHECK_MEMBER(ptlrpc_body, pb_last_committed);
        CHECK_MEMBER(ptlrpc_body, pb_transno);
        CHECK_MEMBER(ptlrpc_body, pb_flags);
        CHECK_MEMBER(ptlrpc_body, pb_op_flags);
        CHECK_MEMBER(ptlrpc_body, pb_conn_cnt);
        CHECK_MEMBER(ptlrpc_body, pb_timeout);
        CHECK_MEMBER(ptlrpc_body, pb_service_time);
        CHECK_MEMBER(ptlrpc_body, pb_slv);
        CHECK_MEMBER(ptlrpc_body, pb_limit);
        CHECK_CVALUE(PTLRPC_NUM_VERSIONS);
        CHECK_MEMBER(ptlrpc_body, pb_pre_versions[PTLRPC_NUM_VERSIONS]);
}

static void check_obd_connect_data(void)
{
        BLANK_LINE();
        CHECK_STRUCT(obd_connect_data);
        CHECK_MEMBER(obd_connect_data, ocd_connect_flags);
        CHECK_MEMBER(obd_connect_data, ocd_version);
        CHECK_MEMBER(obd_connect_data, ocd_grant);
        CHECK_MEMBER(obd_connect_data, ocd_index);
        CHECK_MEMBER(obd_connect_data, ocd_brw_size);
        CHECK_MEMBER(obd_connect_data, ocd_ibits_known);
        CHECK_MEMBER(obd_connect_data, ocd_nllu);
        CHECK_MEMBER(obd_connect_data, ocd_nllg);
        CHECK_MEMBER(obd_connect_data, ocd_transno);
        CHECK_MEMBER(obd_connect_data, ocd_group);
        CHECK_MEMBER(obd_connect_data, ocd_cksum_types);
        CHECK_MEMBER(obd_connect_data, ocd_max_easize);
        CHECK_MEMBER(obd_connect_data, padding);
        CHECK_MEMBER(obd_connect_data, ocd_maxbytes);
        CHECK_MEMBER(obd_connect_data, padding1);
        CHECK_MEMBER(obd_connect_data, padding2);

        CHECK_CDEFINE(OBD_CONNECT_RDONLY);
        CHECK_CDEFINE(OBD_CONNECT_INDEX);
        CHECK_CDEFINE(OBD_CONNECT_MDS);
        CHECK_CDEFINE(OBD_CONNECT_GRANT);
        CHECK_CDEFINE(OBD_CONNECT_SRVLOCK);
        CHECK_CDEFINE(OBD_CONNECT_VERSION);
        CHECK_CDEFINE(OBD_CONNECT_REQPORTAL);
        CHECK_CDEFINE(OBD_CONNECT_ACL);
        CHECK_CDEFINE(OBD_CONNECT_XATTR);
        CHECK_CDEFINE(OBD_CONNECT_CROW);
        CHECK_CDEFINE(OBD_CONNECT_TRUNCLOCK);
        CHECK_CDEFINE(OBD_CONNECT_TRANSNO);
        CHECK_CDEFINE(OBD_CONNECT_IBITS);
        CHECK_CDEFINE(OBD_CONNECT_JOIN);
        CHECK_CDEFINE(OBD_CONNECT_ATTRFID);
        CHECK_CDEFINE(OBD_CONNECT_NODEVOH);
        CHECK_CDEFINE(OBD_CONNECT_RMT_CLIENT);
        CHECK_CDEFINE(OBD_CONNECT_RMT_CLIENT_FORCE);
        CHECK_CDEFINE(OBD_CONNECT_BRW_SIZE);
        CHECK_CDEFINE(OBD_CONNECT_QUOTA64);
        CHECK_CDEFINE(OBD_CONNECT_MDS_CAPA);
        CHECK_CDEFINE(OBD_CONNECT_OSS_CAPA);
        CHECK_CDEFINE(OBD_CONNECT_CANCELSET);
        CHECK_CDEFINE(OBD_CONNECT_SOM);
        CHECK_CDEFINE(OBD_CONNECT_AT);
        CHECK_CDEFINE(OBD_CONNECT_LRU_RESIZE);
        CHECK_CDEFINE(OBD_CONNECT_MDS_MDS);
        CHECK_CDEFINE(OBD_CONNECT_REAL);
        CHECK_CDEFINE(OBD_CONNECT_CHANGE_QS);
        CHECK_CDEFINE(OBD_CONNECT_CKSUM);
        CHECK_CDEFINE(OBD_CONNECT_FID);
        CHECK_CDEFINE(OBD_CONNECT_VBR);
        CHECK_CDEFINE(OBD_CONNECT_LOV_V3);
        CHECK_CDEFINE(OBD_CONNECT_GRANT_SHRINK);
        CHECK_CDEFINE(OBD_CONNECT_SKIP_ORPHAN);
        CHECK_CDEFINE(OBD_CONNECT_MAX_EASIZE);
        CHECK_CDEFINE(OBD_CONNECT_FULL20);
        CHECK_CDEFINE(OBD_CONNECT_LAYOUTLOCK);
        CHECK_CDEFINE(OBD_CONNECT_64BITHASH);
        CHECK_CDEFINE(OBD_CONNECT_MAXBYTES);
}

static void
check_obdo(void)
{
        BLANK_LINE();
        CHECK_STRUCT(obdo);
        CHECK_MEMBER(obdo, o_valid);
        CHECK_MEMBER(obdo, o_id);
        CHECK_MEMBER(obdo, o_seq);
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
        CHECK_MEMBER(obdo, o_lcookie);
        CHECK_MEMBER(obdo, o_uid_h);
        CHECK_MEMBER(obdo, o_gid_h);
        CHECK_MEMBER(obdo, o_padding_3);
        CHECK_MEMBER(obdo, o_padding_4);
        CHECK_MEMBER(obdo, o_padding_5);
        CHECK_MEMBER(obdo, o_padding_6);

        CHECK_CDEFINE(OBD_MD_FLID);
        CHECK_CDEFINE(OBD_MD_FLATIME);
        CHECK_CDEFINE(OBD_MD_FLMTIME);
        CHECK_CDEFINE(OBD_MD_FLCTIME);
        CHECK_CDEFINE(OBD_MD_FLSIZE);
        CHECK_CDEFINE(OBD_MD_FLBLOCKS);
        CHECK_CDEFINE(OBD_MD_FLBLKSZ);
        CHECK_CDEFINE(OBD_MD_FLMODE);
        CHECK_CDEFINE(OBD_MD_FLTYPE);
        CHECK_CDEFINE(OBD_MD_FLUID);
        CHECK_CDEFINE(OBD_MD_FLGID);
        CHECK_CDEFINE(OBD_MD_FLFLAGS);
        CHECK_CDEFINE(OBD_MD_FLNLINK);
        CHECK_CDEFINE(OBD_MD_FLGENER);
        CHECK_CDEFINE(OBD_MD_FLRDEV);
        CHECK_CDEFINE(OBD_MD_FLEASIZE);
        CHECK_CDEFINE(OBD_MD_LINKNAME);
        CHECK_CDEFINE(OBD_MD_FLHANDLE);
        CHECK_CDEFINE(OBD_MD_FLCKSUM);
        CHECK_CDEFINE(OBD_MD_FLQOS);
        CHECK_CDEFINE(OBD_MD_FLCOOKIE);
        CHECK_CDEFINE(OBD_MD_FLGROUP);
        CHECK_CDEFINE(OBD_MD_FLFID);
        CHECK_CDEFINE(OBD_MD_FLEPOCH);
        CHECK_CDEFINE(OBD_MD_FLGRANT);
        CHECK_CDEFINE(OBD_MD_FLDIREA);
        CHECK_CDEFINE(OBD_MD_FLUSRQUOTA);
        CHECK_CDEFINE(OBD_MD_FLGRPQUOTA);
        CHECK_CDEFINE(OBD_MD_FLMODEASIZE);
        CHECK_CDEFINE(OBD_MD_MDS);
        CHECK_CDEFINE(OBD_MD_REINT);
        CHECK_CDEFINE(OBD_MD_FLXATTR);
        CHECK_CDEFINE(OBD_MD_FLXATTRLS);
        CHECK_CDEFINE(OBD_MD_FLXATTRRM);
        CHECK_CDEFINE(OBD_MD_FLACL);

        CHECK_CVALUE(OBD_FL_INLINEDATA);
        CHECK_CVALUE(OBD_FL_OBDMDEXISTS);
        CHECK_CVALUE(OBD_FL_DELORPHAN);
        CHECK_CVALUE(OBD_FL_NORPC);
        CHECK_CVALUE(OBD_FL_IDONLY);
        CHECK_CVALUE(OBD_FL_RECREATE_OBJS);
        CHECK_CVALUE(OBD_FL_DEBUG_CHECK);
        CHECK_CVALUE(OBD_FL_NO_USRQUOTA);
        CHECK_CVALUE(OBD_FL_NO_GRPQUOTA);
        CHECK_CVALUE(OBD_FL_SRVLOCK);
        CHECK_CVALUE(OBD_FL_CKSUM_CRC32);
        CHECK_CVALUE(OBD_FL_CKSUM_ADLER);
        CHECK_CVALUE(OBD_FL_CKSUM_CRC32C);
        CHECK_CVALUE(OBD_FL_SHRINK_GRANT);
        CHECK_CVALUE(OBD_FL_MMAP);
        CHECK_CVALUE(OBD_FL_RECOV_RESEND);
        CHECK_CVALUE(OBD_CKSUM_CRC32);
        CHECK_CVALUE(OBD_CKSUM_ADLER);
        CHECK_CVALUE(OBD_CKSUM_CRC32C);
}

static void
check_lov_mds_md_v1(void)
{
        BLANK_LINE();
        CHECK_STRUCT(lov_mds_md_v1);
        CHECK_MEMBER(lov_mds_md_v1, lmm_magic);
        CHECK_MEMBER(lov_mds_md_v1, lmm_pattern);
        CHECK_MEMBER(lov_mds_md_v1, lmm_object_id);
        CHECK_MEMBER(lov_mds_md_v1, lmm_object_seq);
        CHECK_MEMBER(lov_mds_md_v1, lmm_stripe_size);
        CHECK_MEMBER(lov_mds_md_v1, lmm_stripe_count);
        CHECK_MEMBER(lov_mds_md_v1, lmm_objects);

        BLANK_LINE();
        CHECK_STRUCT(lov_ost_data_v1);
        CHECK_MEMBER(lov_ost_data_v1, l_object_id);
        CHECK_MEMBER(lov_ost_data_v1, l_object_seq);
        CHECK_MEMBER(lov_ost_data_v1, l_ost_gen);
        CHECK_MEMBER(lov_ost_data_v1, l_ost_idx);

        CHECK_CDEFINE(LOV_MAGIC_V1);

        CHECK_VALUE(LOV_PATTERN_RAID0);
        CHECK_VALUE(LOV_PATTERN_RAID1);
}

static void
check_lov_mds_md_v3(void)
{
        BLANK_LINE();
        CHECK_STRUCT(lov_mds_md_v3);
        CHECK_MEMBER(lov_mds_md_v3, lmm_magic);
        CHECK_MEMBER(lov_mds_md_v3, lmm_pattern);
        CHECK_MEMBER(lov_mds_md_v3, lmm_object_id);
        CHECK_MEMBER(lov_mds_md_v3, lmm_object_seq);
        CHECK_MEMBER(lov_mds_md_v3, lmm_stripe_size);
        CHECK_MEMBER(lov_mds_md_v3, lmm_stripe_count);
        CHECK_MEMBER(lov_mds_md_v3, lmm_pool_name);
        CHECK_MEMBER(lov_mds_md_v3, lmm_objects);

        BLANK_LINE();
        CHECK_STRUCT(lov_ost_data_v1);
        CHECK_MEMBER(lov_ost_data_v1, l_object_id);
        CHECK_MEMBER(lov_ost_data_v1, l_object_seq);
        CHECK_MEMBER(lov_ost_data_v1, l_ost_gen);
        CHECK_MEMBER(lov_ost_data_v1, l_ost_idx);

        CHECK_CDEFINE(LOV_MAGIC_V3);

        CHECK_VALUE(LOV_PATTERN_RAID0);
        CHECK_VALUE(LOV_PATTERN_RAID1);
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
        CHECK_MEMBER(obd_statfs, os_spare1);
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
        CHECK_MEMBER(obd_ioobj, ioo_id);
        CHECK_MEMBER(obd_ioobj, ioo_seq);
        CHECK_MEMBER(obd_ioobj, ioo_type);
        CHECK_MEMBER(obd_ioobj, ioo_bufcnt);
}

static void
check_obd_quotactl(void)
{
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
        CHECK_MEMBER(obd_dqblk, padding);

        CHECK_DEFINE(Q_QUOTACHECK);
        CHECK_DEFINE(Q_INITQUOTA);
        CHECK_DEFINE(Q_GETOINFO);
        CHECK_DEFINE(Q_GETOQUOTA);
}

static void
check_niobuf_remote(void)
{
        BLANK_LINE();
        CHECK_STRUCT(niobuf_remote);
        CHECK_MEMBER(niobuf_remote, offset);
        CHECK_MEMBER(niobuf_remote, len);
        CHECK_MEMBER(niobuf_remote, flags);

        CHECK_VALUE(OBD_BRW_READ);
        CHECK_VALUE(OBD_BRW_WRITE);
        CHECK_VALUE(OBD_BRW_SYNC);
        CHECK_VALUE(OBD_BRW_FROM_GRANT);
        CHECK_VALUE(OBD_BRW_NOQUOTA);
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
check_mds_status_req(void)
{
        BLANK_LINE();
        CHECK_STRUCT(mds_status_req);
        CHECK_MEMBER(mds_status_req, flags);
        CHECK_MEMBER(mds_status_req, repbuf);
}

static void
check_mds_body(void)
{
        BLANK_LINE();
        CHECK_STRUCT(mds_body);
        CHECK_MEMBER(mds_body, fid1);
        CHECK_MEMBER(mds_body, fid2);
        CHECK_MEMBER(mds_body, handle);
        CHECK_MEMBER(mds_body, size);
        CHECK_MEMBER(mds_body, blocks);
        CHECK_MEMBER(mds_body, io_epoch);
        CHECK_MEMBER(mds_body, ino);
        CHECK_MEMBER(mds_body, valid);
        CHECK_MEMBER(mds_body, fsuid);
        CHECK_MEMBER(mds_body, fsgid);
        CHECK_MEMBER(mds_body, capability);
        CHECK_MEMBER(mds_body, mode);
        CHECK_MEMBER(mds_body, uid);
        CHECK_MEMBER(mds_body, gid);
        CHECK_MEMBER(mds_body, mtime);
        CHECK_MEMBER(mds_body, ctime);
        CHECK_MEMBER(mds_body, atime);
        CHECK_MEMBER(mds_body, flags);
        CHECK_MEMBER(mds_body, rdev);
        CHECK_MEMBER(mds_body, nlink);
        CHECK_MEMBER(mds_body, generation);
        CHECK_MEMBER(mds_body, suppgid);
        CHECK_MEMBER(mds_body, eadatasize);
        CHECK_MEMBER(mds_body, aclsize);
        CHECK_MEMBER(mds_body, max_mdsize);
        CHECK_MEMBER(mds_body, max_cookiesize);
        CHECK_MEMBER(mds_body, padding_4);

        CHECK_VALUE(FMODE_READ);
        CHECK_VALUE(FMODE_WRITE);
        CHECK_VALUE(MDS_FMODE_EXEC);

        CHECK_CDEFINE(MDS_OPEN_CREAT);
        CHECK_CDEFINE(MDS_OPEN_EXCL);
        CHECK_CDEFINE(MDS_OPEN_TRUNC);
        CHECK_CDEFINE(MDS_OPEN_APPEND);
        CHECK_CDEFINE(MDS_OPEN_SYNC);
        CHECK_CDEFINE(MDS_OPEN_DIRECTORY);
        CHECK_CDEFINE(MDS_OPEN_DELAY_CREATE);
        CHECK_CDEFINE(MDS_OPEN_OWNEROVERRIDE);
        CHECK_CDEFINE(MDS_OPEN_JOIN_FILE);
        CHECK_CDEFINE(MDS_OPEN_HAS_EA);
        CHECK_CDEFINE(MDS_OPEN_HAS_OBJS);

        /* these should be identical to their EXT3_*_FL counterparts, and
         * are redefined only to avoid dragging in ext3_fs.h */
        CHECK_CDEFINE(MDS_SYNC_FL);
        CHECK_CDEFINE(MDS_IMMUTABLE_FL);
        CHECK_CDEFINE(MDS_APPEND_FL);
        CHECK_CDEFINE(MDS_NOATIME_FL);
        CHECK_CDEFINE(MDS_DIRSYNC_FL);

        CHECK_CDEFINE(MDS_INODELOCK_LOOKUP);
        CHECK_CDEFINE(MDS_INODELOCK_UPDATE);
        CHECK_CDEFINE(MDS_INODELOCK_OPEN);
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
        CHECK_MEMBER(mdt_rec_setattr, sa_padding_2);
        CHECK_MEMBER(mdt_rec_setattr, sa_padding_3);
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
        CHECK_MEMBER(mdt_rec_create, cr_padding_3);
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
        CHECK_MEMBER(lov_desc, ld_qos_maxage);
        CHECK_MEMBER(lov_desc, ld_padding_1);
        CHECK_MEMBER(lov_desc, ld_padding_2);
        CHECK_MEMBER(lov_desc, ld_uuid);
}

static void
check_ldlm_res_id(void)
{
        BLANK_LINE();
        CHECK_STRUCT(ldlm_res_id);
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
        CHECK_MEMBER(ldlm_flock_wire, lfw_pid);
}

static void
check_ldlm_intent(void)
{
        BLANK_LINE();
        CHECK_STRUCT(ldlm_intent);
        CHECK_MEMBER(ldlm_intent, opc);
}

static void
check_ldlm_resource_desc(void)
{
        BLANK_LINE();
        CHECK_STRUCT(ldlm_resource_desc);
        CHECK_MEMBER(ldlm_resource_desc, lr_type);
        CHECK_MEMBER(ldlm_resource_desc, lr_padding);
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
check_ldlm_lvb(void)
{
        BLANK_LINE();
        CHECK_STRUCT(ost_lvb);
        CHECK_MEMBER(ost_lvb, lvb_size);
        CHECK_MEMBER(ost_lvb, lvb_mtime);
        CHECK_MEMBER(ost_lvb, lvb_atime);
        CHECK_MEMBER(ost_lvb, lvb_ctime);
        CHECK_MEMBER(ost_lvb, lvb_blocks);
}

static void
check_cfg_marker(void)
{
        BLANK_LINE();
        CHECK_STRUCT(cfg_marker);
        CHECK_MEMBER(cfg_marker, cm_step);
        CHECK_MEMBER(cfg_marker, cm_flags);
        CHECK_MEMBER(cfg_marker, cm_vers);
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
        CHECK_MEMBER(llog_logid, lgl_oid);
        CHECK_MEMBER(llog_logid, lgl_oseq);
        CHECK_MEMBER(llog_logid, lgl_ogen);

        CHECK_CVALUE(OST_SZ_REC);
        CHECK_CVALUE(OST_RAID1_REC);
        CHECK_CVALUE(MDS_UNLINK_REC);
        CHECK_CVALUE(MDS_SETATTR_REC);
        CHECK_CVALUE(OBD_CFG_REC);
        CHECK_CVALUE(PTL_CFG_REC);
        CHECK_CVALUE(LLOG_GEN_REC);
        CHECK_CVALUE(LLOG_JOIN_REC);
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
        CHECK_MEMBER(llog_rec_hdr, padding);
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
        CHECK_MEMBER(llog_logid_rec, padding1);
        CHECK_MEMBER(llog_logid_rec, padding2);
        CHECK_MEMBER(llog_logid_rec, padding3);
        CHECK_MEMBER(llog_logid_rec, padding4);
        CHECK_MEMBER(llog_logid_rec, padding5);
        CHECK_MEMBER(llog_logid_rec, lid_tail);
}

static void
check_llog_create_rec(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_create_rec);
        CHECK_MEMBER(llog_create_rec, lcr_hdr);
        CHECK_MEMBER(llog_create_rec, lcr_fid);
        CHECK_MEMBER(llog_create_rec, lcr_oid);
        CHECK_MEMBER(llog_create_rec, lcr_oseq);
        CHECK_MEMBER(llog_create_rec, padding);
        CHECK_MEMBER(llog_create_rec, lcr_tail);
}

static void
check_llog_orphan_rec(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_orphan_rec);
        CHECK_MEMBER(llog_orphan_rec, lor_hdr);
        CHECK_MEMBER(llog_orphan_rec, lor_oid);
        CHECK_MEMBER(llog_orphan_rec, lor_ogen);
        CHECK_MEMBER(llog_orphan_rec, padding);
        CHECK_MEMBER(llog_orphan_rec, lor_tail);
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
check_llog_setattr_rec(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_setattr_rec);
        CHECK_MEMBER(llog_setattr_rec, lsr_hdr);
        CHECK_MEMBER(llog_setattr_rec, lsr_oid);
        CHECK_MEMBER(llog_setattr_rec, lsr_oseq);
        CHECK_MEMBER(llog_setattr_rec, lsr_uid);
        CHECK_MEMBER(llog_setattr_rec, lsr_gid);
        CHECK_MEMBER(llog_setattr_rec, padding);
        CHECK_MEMBER(llog_setattr_rec, lsr_tail);
}

static void
check_llog_setattr64_rec(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_setattr64_rec);
        CHECK_MEMBER(llog_setattr64_rec, lsr_hdr);
        CHECK_MEMBER(llog_setattr64_rec, lsr_oid);
        CHECK_MEMBER(llog_setattr64_rec, lsr_oseq);
        CHECK_MEMBER(llog_setattr64_rec, padding);
        CHECK_MEMBER(llog_setattr64_rec, lsr_uid);
        CHECK_MEMBER(llog_setattr64_rec, lsr_uid_h);
        CHECK_MEMBER(llog_setattr64_rec, lsr_gid);
        CHECK_MEMBER(llog_setattr64_rec, lsr_gid_h);
        CHECK_MEMBER(llog_setattr64_rec, lsr_tail);
}

static void
check_llog_size_change_rec(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_size_change_rec);
        CHECK_MEMBER(llog_size_change_rec, lsc_hdr);
        CHECK_MEMBER(llog_size_change_rec, lsc_fid);
        CHECK_MEMBER(llog_size_change_rec, lsc_ioepoch);
        CHECK_MEMBER(llog_size_change_rec, padding);
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
check_llog_changelog_rec(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_changelog_rec);
        CHECK_MEMBER(llog_changelog_rec, cr_hdr);
        CHECK_MEMBER(llog_changelog_rec, cr);
        CHECK_MEMBER(llog_changelog_rec, cr_tail);
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
        CHECK_MEMBER(llog_log_hdr, llh_reserved);
        CHECK_MEMBER(llog_log_hdr, llh_bitmap);
        CHECK_MEMBER(llog_log_hdr, llh_tail);
}

static void
check_llog_cookie(void)
{
        BLANK_LINE();
        CHECK_STRUCT(llog_cookie);
        CHECK_MEMBER(llog_cookie, lgc_lgl);
        CHECK_MEMBER(llog_cookie, lgc_subsys);
        CHECK_MEMBER(llog_cookie, lgc_index);
        CHECK_MEMBER(llog_cookie, lgc_padding);
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
check_qunit_data(void)
{
        BLANK_LINE();
        CHECK_STRUCT(qunit_data);
        CHECK_MEMBER(qunit_data, qd_id);
        CHECK_MEMBER(qunit_data, qd_flags);
        CHECK_MEMBER(qunit_data, qd_count);
        CHECK_MEMBER(qunit_data, qd_qunit);
        CHECK_MEMBER(qunit_data, padding);
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
        CHECK_MEMBER(mgs_target_info, mti_fsname);
        CHECK_MEMBER(mgs_target_info, mti_svname);
        CHECK_MEMBER(mgs_target_info, mti_uuid);
        CHECK_MEMBER(mgs_target_info, mti_nids);
        CHECK_MEMBER(mgs_target_info, mti_params);
}

static void
check_lustre_disk_data(void)
{
        BLANK_LINE();
        CHECK_STRUCT(lustre_disk_data);
        CHECK_MEMBER(lustre_disk_data, ldd_magic);
        CHECK_MEMBER(lustre_disk_data, ldd_feature_compat);
        CHECK_MEMBER(lustre_disk_data, ldd_feature_rocompat);
        CHECK_MEMBER(lustre_disk_data, ldd_feature_incompat);
        CHECK_MEMBER(lustre_disk_data, ldd_config_ver);
        CHECK_MEMBER(lustre_disk_data, ldd_flags);
        CHECK_MEMBER(lustre_disk_data, ldd_svindex);
        CHECK_MEMBER(lustre_disk_data, ldd_mount_type);
        CHECK_MEMBER(lustre_disk_data, ldd_fsname);
        CHECK_MEMBER(lustre_disk_data, ldd_svname);
        CHECK_MEMBER(lustre_disk_data, ldd_uuid);
        CHECK_MEMBER(lustre_disk_data, ldd_userdata);
        CHECK_MEMBER(lustre_disk_data, ldd_mount_opts);
        CHECK_MEMBER(lustre_disk_data, ldd_params);
}

static void
check_posix_acl_xattr_entry(void)
{
        BLANK_LINE();
        CHECK_STRUCT_TYPEDEF(posix_acl_xattr_entry);
        CHECK_MEMBER_TYPEDEF(posix_acl_xattr_entry, e_tag);
        CHECK_MEMBER_TYPEDEF(posix_acl_xattr_entry, e_perm);
        CHECK_MEMBER_TYPEDEF(posix_acl_xattr_entry, e_id);
}

static void
check_posix_acl_xattr_header(void)
{
        BLANK_LINE();
        CHECK_STRUCT_TYPEDEF(posix_acl_xattr_header);
        CHECK_MEMBER_TYPEDEF(posix_acl_xattr_header, a_version);
        CHECK_MEMBER_TYPEDEF(posix_acl_xattr_header, a_entries);
}

static void
check_quota_adjust_qunit(void)
{
        BLANK_LINE();
        CHECK_STRUCT(quota_adjust_qunit);
        CHECK_MEMBER(quota_adjust_qunit, qaq_flags);
        CHECK_MEMBER(quota_adjust_qunit, qaq_id);
        CHECK_MEMBER(quota_adjust_qunit, qaq_bunit_sz);
        CHECK_MEMBER(quota_adjust_qunit, qaq_iunit_sz);
        CHECK_MEMBER(quota_adjust_qunit, padding1);
}

static void
check_ll_user_fiemap(void)
{
        BLANK_LINE();
        CHECK_STRUCT(ll_user_fiemap);
        CHECK_MEMBER(ll_user_fiemap, fm_start);
        CHECK_MEMBER(ll_user_fiemap, fm_length);
        CHECK_MEMBER(ll_user_fiemap, fm_flags);
        CHECK_MEMBER(ll_user_fiemap, fm_mapped_extents);
        CHECK_MEMBER(ll_user_fiemap, fm_extent_count);
        CHECK_MEMBER(ll_user_fiemap, fm_reserved);
        CHECK_MEMBER(ll_user_fiemap, fm_extents);

        CHECK_CDEFINE(FIEMAP_FLAG_SYNC);
        CHECK_CDEFINE(FIEMAP_FLAG_XATTR);
        CHECK_CDEFINE(FIEMAP_FLAG_DEVICE_ORDER);
}

static void
check_ll_fiemap_extent(void)
{
        BLANK_LINE();
        CHECK_STRUCT(ll_fiemap_extent);
        CHECK_MEMBER(ll_fiemap_extent, fe_logical);
        CHECK_MEMBER(ll_fiemap_extent, fe_physical);
        CHECK_MEMBER(ll_fiemap_extent, fe_length);
        CHECK_MEMBER(ll_fiemap_extent, fe_flags);
        CHECK_MEMBER(ll_fiemap_extent, fe_device);

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
        CHECK_MEMBER(link_ea_header, padding1);
        CHECK_MEMBER(link_ea_header, padding2);
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
check_hsm_user_request(void)
{
        BLANK_LINE();
        CHECK_STRUCT(hsm_user_request);
        CHECK_MEMBER(hsm_user_request, hur_action);
        CHECK_MEMBER(hsm_user_request, hur_archive_num);
        CHECK_MEMBER(hsm_user_request, hur_itemcount);
        CHECK_MEMBER(hsm_user_request, hur_data_len);
}

static void
check_hsm_user_state(void)
{
        BLANK_LINE();
        CHECK_STRUCT(hsm_user_state);
        CHECK_MEMBER(hsm_user_state, hus_states);
        CHECK_MEMBER(hsm_user_state, hus_archive_num);
        CHECK_MEMBER(hsm_user_state, hus_in_progress_state);
        CHECK_MEMBER(hsm_user_state, hus_in_progress_action);
        CHECK_MEMBER(hsm_user_state, hus_in_progress_location);
}

static void
system_string (char *cmdline, char *str, int len)
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
                "        /* Wire protocol assertions generated by 'wirecheck'\n"
                "         * (make -C lustre/utils newwiretest)\n"
                "         * running on %s\n"
                "         * with %s */\n"
                "\n", unameinfo, gccinfo);

        BLANK_LINE ();

        COMMENT("Constants...");
        CHECK_DEFINE(LUSTRE_MSG_MAGIC_V2);
        CHECK_DEFINE(PTLRPC_MSG_VERSION);
        CHECK_VALUE(MSGHDR_AT_SUPPORT);

        CHECK_VALUE(PTL_RPC_MSG_REQUEST);
        CHECK_VALUE(PTL_RPC_MSG_ERR);
        CHECK_VALUE(PTL_RPC_MSG_REPLY);

        CHECK_VALUE(MSG_LAST_REPLAY);
        CHECK_VALUE(MSG_RESENT);
        CHECK_VALUE(MSG_REPLAY);

        CHECK_VALUE(MSG_CONNECT_RECOVERING);
        CHECK_VALUE(MSG_CONNECT_RECONNECT);
        CHECK_VALUE(MSG_CONNECT_REPLAYABLE);

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
        CHECK_VALUE(OST_QUOTACHECK);
        CHECK_VALUE(OST_QUOTACTL);
        CHECK_VALUE(OST_QUOTA_ADJUST_QUNIT);
        CHECK_VALUE(OST_LAST_OPC);

        CHECK_DEFINE(OBD_OBJECT_EOF);

        CHECK_VALUE(MDS_GETATTR);
        CHECK_VALUE(MDS_GETATTR_NAME);
        CHECK_VALUE(MDS_CLOSE);
        CHECK_VALUE(MDS_REINT);
        CHECK_VALUE(MDS_READPAGE);
        CHECK_VALUE(MDS_CONNECT);
        CHECK_VALUE(MDS_DISCONNECT);
        CHECK_VALUE(MDS_GETSTATUS);
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
        CHECK_VALUE(MDS_LAST_OPC);

        CHECK_VALUE(REINT_SETATTR);
        CHECK_VALUE(REINT_CREATE);
        CHECK_VALUE(REINT_LINK);
        CHECK_VALUE(REINT_UNLINK);
        CHECK_VALUE(REINT_RENAME);
        CHECK_VALUE(REINT_OPEN);
        CHECK_VALUE(REINT_MAX);

        CHECK_VALUE(MGS_CONNECT);
        CHECK_VALUE(MGS_DISCONNECT);
        CHECK_VALUE(MGS_EXCEPTION);
        CHECK_VALUE(MGS_TARGET_REG);
        CHECK_VALUE(MGS_TARGET_DEL);
        CHECK_VALUE(MGS_SET_INFO);

        CHECK_VALUE(DISP_IT_EXECD);
        CHECK_VALUE(DISP_LOOKUP_EXECD);
        CHECK_VALUE(DISP_LOOKUP_NEG);
        CHECK_VALUE(DISP_LOOKUP_POS);
        CHECK_VALUE(DISP_OPEN_CREATE);
        CHECK_VALUE(DISP_OPEN_OPEN);

        CHECK_VALUE(MDS_STATUS_CONN);
        CHECK_VALUE(MDS_STATUS_LOV);

        CHECK_VALUE(LDLM_ENQUEUE);
        CHECK_VALUE(LDLM_CONVERT);
        CHECK_VALUE(LDLM_CANCEL);
        CHECK_VALUE(LDLM_BL_CALLBACK);
        CHECK_VALUE(LDLM_CP_CALLBACK);
        CHECK_VALUE(LDLM_GL_CALLBACK);
        CHECK_VALUE(LDLM_SET_INFO);
        CHECK_VALUE(LDLM_LAST_OPC);

        CHECK_VALUE(LCK_EX);
        CHECK_VALUE(LCK_PW);
        CHECK_VALUE(LCK_PR);
        CHECK_VALUE(LCK_CW);
        CHECK_VALUE(LCK_CR);
        CHECK_VALUE(LCK_NL);
        CHECK_VALUE(LCK_GROUP);
        CHECK_VALUE(LCK_MAXMODE);
        CHECK_VALUE(LCK_MODE_NUM);

        CHECK_CVALUE(LDLM_PLAIN);
        CHECK_CVALUE(LDLM_EXTENT);
        CHECK_CVALUE(LDLM_FLOCK);
        CHECK_CVALUE(LDLM_IBITS);

        CHECK_VALUE(OBD_PING);
        CHECK_VALUE(OBD_LOG_CANCEL);
        CHECK_VALUE(OBD_QC_CALLBACK);
        CHECK_VALUE(OBD_LAST_OPC);

        CHECK_VALUE(QUOTA_DQACQ);
        CHECK_VALUE(QUOTA_DQREL);

        CHECK_VALUE(MGS_CONNECT);
        CHECK_VALUE(MGS_DISCONNECT);
        CHECK_VALUE(MGS_EXCEPTION);
        CHECK_VALUE(MGS_TARGET_REG);
        CHECK_VALUE(MGS_TARGET_DEL);
        CHECK_VALUE(MGS_SET_INFO);

        CHECK_VALUE(LDF_EMPTY);
        CHECK_VALUE(LDF_COLLIDE);
        CHECK_VALUE(LU_PAGE_SIZE);

        COMMENT("Sizes and Offsets");
        BLANK_LINE();
        CHECK_STRUCT(obd_uuid);
        check_lustre_handle();
        check_lustre_msg_v2();
        check_ptlrpc_body();
        check_obd_connect_data();
        check_obdo();
        check_lov_mds_md_v1();
        check_lov_mds_md_v3();
        check_obd_statfs();
        check_obd_ioobj();
        check_obd_quotactl();
        check_niobuf_remote();
        check_ost_body();
        check_ll_fid();
        check_mds_status_req();
        check_mds_body();
        check_mdt_rec_setattr();
        check_mdt_rec_create();
        check_mdt_rec_link();
        check_mdt_rec_unlink();
        check_mdt_rec_rename();
        check_lov_desc();
        check_ldlm_res_id();
        check_ldlm_extent();
        check_ldlm_flock();
        check_ldlm_inodebits();
        check_ldlm_intent();
        check_ldlm_resource_desc();
        check_ldlm_lock_desc();
        check_ldlm_request();
        check_ldlm_reply();
        check_ldlm_lvb();
        check_cfg_marker();
        check_llog_logid();
        check_llog_catid();
        check_llog_rec_hdr();
        check_llog_rec_tail();
        check_llog_logid_rec();
        check_llog_create_rec();
        check_llog_orphan_rec();
        check_llog_unlink_rec();
        check_llog_setattr_rec();
        check_llog_setattr64_rec();
        check_llog_size_change_rec();
        check_changelog_rec();
        check_llog_changelog_rec();
        check_llog_gen();
        check_llog_gen_rec();
        check_llog_log_hdr();
        check_llog_cookie();
        check_llogd_body();
        check_llogd_conn_body();
        check_qunit_data();
        check_quota_adjust_qunit();
        check_mgs_target_info();
        check_lustre_disk_data();
        check_ll_user_fiemap();
        check_ll_fiemap_extent();
        printf("#ifdef LIBLUSTRE_POSIX_ACL\n");
#ifndef LIBLUSTRE_POSIX_ACL
#error build generator without LIBLUSTRE_POSIX_ACL defined - produce wrong check code.
#endif
        check_posix_acl_xattr_entry();
        check_posix_acl_xattr_header();
        printf("#endif\n");
        check_link_ea_header();
        check_link_ea_entry();
        check_hsm_user_item();
        check_hsm_user_request();
        check_hsm_user_state();

        printf("}\n\n");

        return(0);
}
