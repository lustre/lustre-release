#include <stdio.h>
#include <liblustre.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_idl.h>

#define BLANK_LINE()				\
do {						\
	printf ("\n");				\
} while (0)

#define COMMENT(c)				\
do {						\
	printf ("        /* "c" */\n");		\
} while (0)

#define STRINGIFY(a) #a

#define CHECK_DEFINE(a)						\
do {								\
	printf ("        LASSERT ("#a" == "STRINGIFY(a)");\n");	\
} while (0)

#define CHECK_VALUE(a)					\
do {							\
	printf ("        LASSERT ("#a" == %d);\n", a);	\
} while (0)

#define CHECK_MEMBER_OFFSET(s,m)		\
do {						\
	CHECK_VALUE (offsetof (struct s, m));	\
} while (0)

#define CHECK_MEMBER_SIZEOF(s,m)			\
do {							\
	CHECK_VALUE (sizeof (((struct s *)0)->m));	\
} while (0)

#define CHECK_MEMBER(s,m)			\
do {						\
	CHECK_MEMBER_OFFSET (s, m);		\
	CHECK_MEMBER_SIZEOF (s, m);		\
} while (0)

#define CHECK_STRUCT(s)				\
do {						\
        COMMENT ("Checks for struct "#s);	\
	CHECK_VALUE (sizeof (struct s));	\
} while (0)



void check1 (void)
{
#define VALUE 1234567

	CHECK_VALUE (VALUE);
	CHECK_DEFINE (VALUE);
}

void
check_lustre_handle (void) 
{
	BLANK_LINE ();
	CHECK_STRUCT (lustre_handle);
	CHECK_MEMBER (lustre_handle, cookie);
}

void
check_lustre_msg (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (lustre_msg);
	CHECK_MEMBER (lustre_msg, handle);
	CHECK_MEMBER (lustre_msg, magic);
	CHECK_MEMBER (lustre_msg, type);
	CHECK_MEMBER (lustre_msg, version);
	CHECK_MEMBER (lustre_msg, opc);
	CHECK_MEMBER (lustre_msg, last_xid);
	CHECK_MEMBER (lustre_msg, last_committed);
	CHECK_MEMBER (lustre_msg, transno);
	CHECK_MEMBER (lustre_msg, status);
	CHECK_MEMBER (lustre_msg, flags);
	CHECK_MEMBER (lustre_msg, bufcount);
	CHECK_MEMBER (lustre_msg, buflens[7]);
}

void
check_obdo (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (obdo);
	CHECK_MEMBER (obdo, o_id);
	CHECK_MEMBER (obdo, o_gr);
	CHECK_MEMBER (obdo, o_atime);
	CHECK_MEMBER (obdo, o_mtime);
	CHECK_MEMBER (obdo, o_ctime);
	CHECK_MEMBER (obdo, o_size);
	CHECK_MEMBER (obdo, o_blocks);
	CHECK_MEMBER (obdo, o_rdev);
	CHECK_MEMBER (obdo, o_blksize);
	CHECK_MEMBER (obdo, o_mode);
	CHECK_MEMBER (obdo, o_uid);
	CHECK_MEMBER (obdo, o_gid);
	CHECK_MEMBER (obdo, o_flags);
	CHECK_MEMBER (obdo, o_nlink);
	CHECK_MEMBER (obdo, o_generation);
	CHECK_MEMBER (obdo, o_valid);
	CHECK_MEMBER (obdo, o_obdflags);
	CHECK_MEMBER (obdo, o_easize);
	CHECK_MEMBER (obdo, o_inline);
}

void
check_obd_statfs (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (obd_statfs);
	CHECK_MEMBER (obd_statfs, os_type);
	CHECK_MEMBER (obd_statfs, os_blocks);
	CHECK_MEMBER (obd_statfs, os_bfree);
	CHECK_MEMBER (obd_statfs, os_bavail);
	CHECK_MEMBER (obd_statfs, os_ffree);
	CHECK_MEMBER (obd_statfs, os_fsid);
	CHECK_MEMBER (obd_statfs, os_bsize);
	CHECK_MEMBER (obd_statfs, os_namelen);
}

void
check_obd_ioobj (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (obd_ioobj);
	CHECK_MEMBER (obd_ioobj, ioo_id);
	CHECK_MEMBER (obd_ioobj, ioo_gr);
	CHECK_MEMBER (obd_ioobj, ioo_type);
	CHECK_MEMBER (obd_ioobj, ioo_bufcnt);
}

void
check_niobuf_remote (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (niobuf_remote);
	CHECK_MEMBER (niobuf_remote, offset);
	CHECK_MEMBER (niobuf_remote, len);
	CHECK_MEMBER (niobuf_remote, flags);
}

void
check_ost_body (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ost_body);
	CHECK_MEMBER (ost_body, oa);
}

void
check_ll_fid (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ll_fid);
	CHECK_MEMBER (ll_fid, id);
	CHECK_MEMBER (ll_fid, generation);
	CHECK_MEMBER (ll_fid, f_type);
}

void
check_mds_status_req (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_status_req);
	CHECK_MEMBER (mds_status_req, flags);
	CHECK_MEMBER (mds_status_req, repbuf);
}

void
check_mds_fileh_body (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_fileh_body);
	CHECK_MEMBER (mds_fileh_body, f_fid);
}

void
check_mds_body (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_body);
	CHECK_MEMBER (mds_body, fid1);
	CHECK_MEMBER (mds_body, fid2);
	CHECK_MEMBER (mds_body, handle);
	CHECK_MEMBER (mds_body, size);
	CHECK_MEMBER (mds_body, blocks);
	CHECK_MEMBER (mds_body, ino);
	CHECK_MEMBER (mds_body, valid);
	CHECK_MEMBER (mds_body, fsuid);
	CHECK_MEMBER (mds_body, fsgid);
	CHECK_MEMBER (mds_body, capability);
	CHECK_MEMBER (mds_body, mode);
	CHECK_MEMBER (mds_body, uid);
	CHECK_MEMBER (mds_body, gid);
	CHECK_MEMBER (mds_body, mtime);
	CHECK_MEMBER (mds_body, ctime);
	CHECK_MEMBER (mds_body, atime);
	CHECK_MEMBER (mds_body, flags);
	CHECK_MEMBER (mds_body, rdev);
	CHECK_MEMBER (mds_body, nlink);
	CHECK_MEMBER (mds_body, generation);
	CHECK_MEMBER (mds_body, suppgid);
}

void
check_mds_rec_setattr (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_rec_setattr);
	CHECK_MEMBER (mds_rec_setattr, sa_opcode);
	CHECK_MEMBER (mds_rec_setattr, sa_fsuid);
	CHECK_MEMBER (mds_rec_setattr, sa_fsgid);
	CHECK_MEMBER (mds_rec_setattr, sa_cap);
	CHECK_MEMBER (mds_rec_setattr, sa_reserved);
	CHECK_MEMBER (mds_rec_setattr, sa_valid);
	CHECK_MEMBER (mds_rec_setattr, sa_fid);
	CHECK_MEMBER (mds_rec_setattr, sa_mode);
	CHECK_MEMBER (mds_rec_setattr, sa_uid);
	CHECK_MEMBER (mds_rec_setattr, sa_gid);
	CHECK_MEMBER (mds_rec_setattr, sa_attr_flags);
	CHECK_MEMBER (mds_rec_setattr, sa_size);
	CHECK_MEMBER (mds_rec_setattr, sa_atime);
	CHECK_MEMBER (mds_rec_setattr, sa_mtime);
	CHECK_MEMBER (mds_rec_setattr, sa_ctime);
	CHECK_MEMBER (mds_rec_setattr, sa_suppgid);
}

void
check_mds_rec_create (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_rec_create);
	CHECK_MEMBER (mds_rec_create, cr_opcode);
	CHECK_MEMBER (mds_rec_create, cr_fsuid);
	CHECK_MEMBER (mds_rec_create, cr_fsgid);
	CHECK_MEMBER (mds_rec_create, cr_cap);
	CHECK_MEMBER (mds_rec_create, cr_flags);
	CHECK_MEMBER (mds_rec_create, cr_mode);
	CHECK_MEMBER (mds_rec_create, cr_fid);
	CHECK_MEMBER (mds_rec_create, cr_replayfid);
	CHECK_MEMBER (mds_rec_create, cr_uid);
	CHECK_MEMBER (mds_rec_create, cr_gid);
	CHECK_MEMBER (mds_rec_create, cr_time);
	CHECK_MEMBER (mds_rec_create, cr_rdev);
	CHECK_MEMBER (mds_rec_create, cr_suppgid);
}

void
check_mds_rec_link (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_rec_link);
	CHECK_MEMBER (mds_rec_link, lk_opcode);
	CHECK_MEMBER (mds_rec_link, lk_fsuid);
	CHECK_MEMBER (mds_rec_link, lk_fsgid);
	CHECK_MEMBER (mds_rec_link, lk_cap);
	CHECK_MEMBER (mds_rec_link, lk_suppgid1);
	CHECK_MEMBER (mds_rec_link, lk_suppgid2);
	CHECK_MEMBER (mds_rec_link, lk_fid1);
	CHECK_MEMBER (mds_rec_link, lk_fid2);
}

void
check_mds_rec_unlink (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_rec_unlink);
	CHECK_MEMBER (mds_rec_unlink, ul_opcode);
	CHECK_MEMBER (mds_rec_unlink, ul_fsuid);
	CHECK_MEMBER (mds_rec_unlink, ul_fsgid);
	CHECK_MEMBER (mds_rec_unlink, ul_cap);
	CHECK_MEMBER (mds_rec_unlink, ul_reserved);
	CHECK_MEMBER (mds_rec_unlink, ul_mode);
	CHECK_MEMBER (mds_rec_unlink, ul_suppgid);
	CHECK_MEMBER (mds_rec_unlink, ul_fid1);
	CHECK_MEMBER (mds_rec_unlink, ul_fid2);
}

void
check_mds_rec_rename (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (mds_rec_rename);
	CHECK_MEMBER (mds_rec_rename, rn_opcode);
	CHECK_MEMBER (mds_rec_rename, rn_fsuid);
	CHECK_MEMBER (mds_rec_rename, rn_fsgid);
	CHECK_MEMBER (mds_rec_rename, rn_cap);
	CHECK_MEMBER (mds_rec_rename, rn_suppgid1);
	CHECK_MEMBER (mds_rec_rename, rn_suppgid2);
	CHECK_MEMBER (mds_rec_rename, rn_fid1);
	CHECK_MEMBER (mds_rec_rename, rn_fid2);
}

void
check_lov_desc (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (lov_desc);
	CHECK_MEMBER (lov_desc, ld_tgt_count);
	CHECK_MEMBER (lov_desc, ld_active_tgt_count);
	CHECK_MEMBER (lov_desc, ld_default_stripe_count);
	CHECK_MEMBER (lov_desc, ld_default_stripe_size);
	CHECK_MEMBER (lov_desc, ld_default_stripe_offset);
	CHECK_MEMBER (lov_desc, ld_pattern);
	CHECK_MEMBER (lov_desc, ld_uuid);
}

void
check_ldlm_res_id (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_res_id);
	CHECK_MEMBER (ldlm_res_id, name[RES_NAME_SIZE]);
}

void
check_ldlm_extent (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_extent);
	CHECK_MEMBER (ldlm_extent, start);
	CHECK_MEMBER (ldlm_extent, end);
}

void
check_ldlm_intent (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_intent);
	CHECK_MEMBER (ldlm_intent, opc);
}

void
check_ldlm_resource_desc (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_resource_desc);
	CHECK_MEMBER (ldlm_resource_desc, lr_type);
	CHECK_MEMBER (ldlm_resource_desc, lr_name);
	CHECK_MEMBER (ldlm_resource_desc, lr_version[RES_VERSION_SIZE]);
}

void
check_ldlm_lock_desc (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_lock_desc);
	CHECK_MEMBER (ldlm_lock_desc, l_resource);
	CHECK_MEMBER (ldlm_lock_desc, l_req_mode);
	CHECK_MEMBER (ldlm_lock_desc, l_granted_mode);
	CHECK_MEMBER (ldlm_lock_desc, l_extent);
	CHECK_MEMBER (ldlm_lock_desc, l_version[RES_VERSION_SIZE]);
}

void
check_ldlm_request (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_request);
	CHECK_MEMBER (ldlm_request, lock_flags);
	CHECK_MEMBER (ldlm_request, lock_desc);
	CHECK_MEMBER (ldlm_request, lock_handle1);
	CHECK_MEMBER (ldlm_request, lock_handle2);
}

void
check_ldlm_reply (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ldlm_reply);
	CHECK_MEMBER (ldlm_reply, lock_flags);
	CHECK_MEMBER (ldlm_reply, lock_mode);
	CHECK_MEMBER (ldlm_reply, lock_resource_name);
	CHECK_MEMBER (ldlm_reply, lock_handle);
	CHECK_MEMBER (ldlm_reply, lock_extent);
	CHECK_MEMBER (ldlm_reply, lock_policy_res1);
	CHECK_MEMBER (ldlm_reply, lock_policy_res2);
}

void
check_ptlbd_op (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ptlbd_op);
	CHECK_MEMBER (ptlbd_op, op_cmd);
	CHECK_MEMBER (ptlbd_op, op_lun);
	CHECK_MEMBER (ptlbd_op, op_niob_cnt);
	CHECK_MEMBER (ptlbd_op, op__padding);
	CHECK_MEMBER (ptlbd_op, op_block_cnt);
}

void
check_ptlbd_niob (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ptlbd_niob);
	CHECK_MEMBER (ptlbd_niob, n_xid);
	CHECK_MEMBER (ptlbd_niob, n_block_nr);
	CHECK_MEMBER (ptlbd_niob, n_offset);
	CHECK_MEMBER (ptlbd_niob, n_length);
}

void
check_ptlbd_rsp (void)
{
	BLANK_LINE ();
	CHECK_STRUCT (ptlbd_rsp);
	CHECK_MEMBER (ptlbd_rsp, r_status);
	CHECK_MEMBER (ptlbd_rsp, r_error_cnt);
}

int
main (int argc, char **argv)
{
	printf ("void lustre_assert_wire_constants (void)\n"
		"{\n");

	COMMENT ("Wire protocol assertions generated by 'wirecheck'");
	BLANK_LINE ();
	
	COMMENT ("Constants...");
	CHECK_DEFINE (PTLRPC_MSG_MAGIC);
	CHECK_DEFINE (PTLRPC_MSG_VERSION);

	CHECK_VALUE (PTL_RPC_MSG_REQUEST);
	CHECK_VALUE (PTL_RPC_MSG_ERR);
	CHECK_VALUE (PTL_RPC_MSG_REPLY);

	CHECK_VALUE (MSG_LAST_REPLAY);
	CHECK_VALUE (MSG_RESENT);
	
	CHECK_VALUE (MSG_CONNECT_RECOVERING);
	CHECK_VALUE (MSG_CONNECT_RECONNECT);
	CHECK_VALUE (MSG_CONNECT_REPLAYABLE);
	
	CHECK_VALUE (OST_REPLY);
	CHECK_VALUE (OST_GETATTR);
	CHECK_VALUE (OST_SETATTR);
	CHECK_VALUE (OST_READ);
	CHECK_VALUE (OST_WRITE);
	CHECK_VALUE (OST_CREATE);
	CHECK_VALUE (OST_DESTROY);
	CHECK_VALUE (OST_GET_INFO);
	CHECK_VALUE (OST_CONNECT);
	CHECK_VALUE (OST_DISCONNECT);
	CHECK_VALUE (OST_PUNCH);
	CHECK_VALUE (OST_OPEN);
	CHECK_VALUE (OST_CLOSE);
	CHECK_VALUE (OST_STATFS);
	CHECK_VALUE (OST_SAN_READ);
	CHECK_VALUE (OST_SAN_WRITE);
	CHECK_VALUE (OST_SYNCFS);
	CHECK_VALUE (OST_LAST_OPC);
	CHECK_VALUE (OST_FIRST_OPC);

	CHECK_VALUE (OBD_FL_INLINEDATA);
	CHECK_VALUE (OBD_FL_OBDMDEXISTS);

	CHECK_VALUE (LOV_MAGIC);

	CHECK_VALUE (OBD_MD_FLALL);
	CHECK_VALUE (OBD_MD_FLID);
	CHECK_VALUE (OBD_MD_FLATIME);
	CHECK_VALUE (OBD_MD_FLMTIME);
	CHECK_VALUE (OBD_MD_FLCTIME);
	CHECK_VALUE (OBD_MD_FLSIZE);
	CHECK_VALUE (OBD_MD_FLBLOCKS);
	CHECK_VALUE (OBD_MD_FLBLKSZ);
	CHECK_VALUE (OBD_MD_FLMODE);
	CHECK_VALUE (OBD_MD_FLTYPE);
	CHECK_VALUE (OBD_MD_FLUID);
	CHECK_VALUE (OBD_MD_FLGID);
	CHECK_VALUE (OBD_MD_FLFLAGS);
	CHECK_VALUE (OBD_MD_FLOBDFLG);
	CHECK_VALUE (OBD_MD_FLNLINK);
	CHECK_VALUE (OBD_MD_FLGENER);
	CHECK_VALUE (OBD_MD_FLINLINE);
	CHECK_VALUE (OBD_MD_FLRDEV);
	CHECK_VALUE (OBD_MD_FLEASIZE);
	CHECK_VALUE (OBD_MD_LINKNAME);
	CHECK_VALUE (OBD_MD_FLHANDLE);
	CHECK_VALUE (OBD_MD_FLCKSUM);

	CHECK_VALUE (OBD_BRW_READ);
	CHECK_VALUE (OBD_BRW_WRITE);
	CHECK_VALUE (OBD_BRW_CREATE);
	CHECK_VALUE (OBD_BRW_SYNC);

	CHECK_DEFINE (OBD_OBJECT_EOF);

	CHECK_VALUE (OST_REQ_HAS_OA1);

	CHECK_VALUE (MDS_GETATTR);
	CHECK_VALUE (MDS_GETATTR_NAME);
	CHECK_VALUE (MDS_CLOSE);
	CHECK_VALUE (MDS_REINT);
	CHECK_VALUE (MDS_READPAGE);
	CHECK_VALUE (MDS_CONNECT);
	CHECK_VALUE (MDS_DISCONNECT);
	CHECK_VALUE (MDS_GETSTATUS);
	CHECK_VALUE (MDS_STATFS);
	CHECK_VALUE (MDS_GETLOVINFO);
	CHECK_VALUE (MDS_LAST_OPC);
	CHECK_VALUE (MDS_FIRST_OPC);

	CHECK_VALUE (REINT_SETATTR);
	CHECK_VALUE (REINT_CREATE);
	CHECK_VALUE (REINT_LINK);
	CHECK_VALUE (REINT_UNLINK);
	CHECK_VALUE (REINT_RENAME);
	CHECK_VALUE (REINT_OPEN);
	CHECK_VALUE (REINT_MAX);

	CHECK_VALUE (IT_INTENT_EXEC);
	CHECK_VALUE (IT_OPEN_LOOKUP);
	CHECK_VALUE (IT_OPEN_NEG);
	CHECK_VALUE (IT_OPEN_POS);
	CHECK_VALUE (IT_OPEN_CREATE);
	CHECK_VALUE (IT_OPEN_OPEN);

	CHECK_VALUE (MDS_STATUS_CONN);
	CHECK_VALUE (MDS_STATUS_LOV);

	CHECK_VALUE (MDS_OPEN_HAS_EA);

	CHECK_VALUE (LOV_RAID0);
	CHECK_VALUE (LOV_RAIDRR);

	CHECK_VALUE (LDLM_ENQUEUE);
	CHECK_VALUE (LDLM_CONVERT);
	CHECK_VALUE (LDLM_CANCEL);
	CHECK_VALUE (LDLM_BL_CALLBACK);
	CHECK_VALUE (LDLM_CP_CALLBACK);
	CHECK_VALUE (LDLM_LAST_OPC);
	CHECK_VALUE (LDLM_FIRST_OPC);

        CHECK_VALUE (PTLBD_QUERY);
        CHECK_VALUE (PTLBD_READ);
        CHECK_VALUE (PTLBD_WRITE);
        CHECK_VALUE (PTLBD_FLUSH);
        CHECK_VALUE (PTLBD_CONNECT);
        CHECK_VALUE (PTLBD_DISCONNECT);
	CHECK_VALUE (PTLBD_LAST_OPC);
	CHECK_VALUE (PTLBD_FIRST_OPC);

	CHECK_VALUE (OBD_PING);

	COMMENT ("Sizes and Offsets");
	BLANK_LINE ();
	check_lustre_handle ();
	check_lustre_msg ();
	check_obdo ();
	check_obd_statfs ();
	check_obd_ioobj ();
	check_niobuf_remote ();
	check_ost_body ();
	check_ll_fid ();
	check_mds_status_req ();
	check_mds_fileh_body ();
	check_mds_body ();
	check_mds_rec_setattr ();
	check_mds_rec_create ();
	check_mds_rec_link ();
	check_mds_rec_unlink ();
	check_mds_rec_rename ();
	check_lov_desc ();
	check_ldlm_res_id ();
	check_ldlm_extent ();
	check_ldlm_intent ();
	check_ldlm_resource_desc ();
	check_ldlm_lock_desc ();
	check_ldlm_request ();
	check_ldlm_reply ();
	check_ptlbd_op ();
	check_ptlbd_niob ();
	check_ptlbd_rsp ();

	printf ("}\n\n");
	
	return (0);
}
