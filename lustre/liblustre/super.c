/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 * Lustre Light Super operations
 *
 *  Copyright (c) 2002, 2003 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define DEBUG_SUBSYSTEM S_LLITE

#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/queue.h>

#include <sysio.h>
#include <fs.h>
#include <mount.h>
#include <inode.h>
#include <file.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <portals/api-support.h> /* needed for ptpctl.h */
#include <portals/ptlctl.h>	/* needed for parse_dump */

#include "llite_lib.h"


ptl_handle_ni_t         tcpnal_ni;
struct task_struct *current;
struct obd_class_user_state ocus;

/* portals interfaces */
ptl_handle_ni_t *
kportal_get_ni (int nal)
{
        return &tcpnal_ni;
}

inline void
kportal_put_ni (int nal)
{
        return;
}

struct ldlm_namespace;
struct ldlm_res_id;
struct obd_import;

extern int ldlm_cli_cancel_unused(struct ldlm_namespace *ns, struct ldlm_res_id *res_id, int flags);
extern int ldlm_namespace_cleanup(struct ldlm_namespace *ns, int local_only);
extern int ldlm_replay_locks(struct obd_import *imp);

void *inter_module_get(char *arg)
{
        if (!strcmp(arg, "tcpnal_ni"))
                return &tcpnal_ni;
        else if (!strcmp(arg, "ldlm_cli_cancel_unused"))
                return ldlm_cli_cancel_unused;
        else if (!strcmp(arg, "ldlm_namespace_cleanup"))
                return ldlm_namespace_cleanup;
        else if (!strcmp(arg, "ldlm_replay_locks"))
                return ldlm_replay_locks;
        else
                return NULL;
}

void init_current(char *comm)
{ 
        current = malloc(sizeof(*current));
        current->fs = malloc(sizeof(*current->fs));
        strncpy(current->comm, comm, sizeof(current->comm));
        current->pid = getpid();
        current->fsuid = 0;
        current->fsgid = 0;
        current->cap_effective = 0;
        memset(&current->pending, 0, sizeof(current->pending));
}

ptl_nid_t tcpnal_mynid;

int init_lib_portals()
{
        int rc;

        PtlInit();
        rc = PtlNIInit(procbridge_interface, 0, 0, 0, &tcpnal_ni);
        if (rc != 0) {
                CERROR("ksocknal: PtlNIInit failed: error %d\n", rc);
                PtlFini();
                RETURN (rc);
        }
        PtlNIDebug(tcpnal_ni, ~0);
        return rc;
}

static void llu_fsop_gone(struct filesys *fs)
{
        /* FIXME */
}

static struct inode_ops llu_inode_ops;

void llu_update_inode(struct inode *inode, struct mds_body *body,
                     struct lov_mds_md *lmm)
{
        struct llu_inode_info *lli = llu_i2info(inode);

        if (lmm != NULL)
                obd_unpackmd(llu_i2obdconn(inode), &lli->lli_smd, lmm);

        if (body->valid & OBD_MD_FLID)
                lli->lli_st_ino = body->ino;
        if (body->valid & OBD_MD_FLATIME)
                LTIME_S(lli->lli_st_atime) = body->atime;
        if (body->valid & OBD_MD_FLMTIME)
                LTIME_S(lli->lli_st_mtime) = body->mtime;
        if (body->valid & OBD_MD_FLCTIME)
                LTIME_S(lli->lli_st_ctime) = body->ctime;
        if (body->valid & OBD_MD_FLMODE)
                lli->lli_st_mode = (lli->lli_st_mode & S_IFMT)|(body->mode & ~S_IFMT);
        if (body->valid & OBD_MD_FLTYPE)
                lli->lli_st_mode = (lli->lli_st_mode & ~S_IFMT)|(body->mode & S_IFMT);
        if (body->valid & OBD_MD_FLUID)
                lli->lli_st_uid = body->uid;
        if (body->valid & OBD_MD_FLGID)
                lli->lli_st_gid = body->gid;
        if (body->valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = body->flags;
        if (body->valid & OBD_MD_FLNLINK)
                lli->lli_st_nlink = body->nlink;
        if (body->valid & OBD_MD_FLGENER)
                lli->lli_st_generation = body->generation;
        if (body->valid & OBD_MD_FLRDEV)
                lli->lli_st_rdev = body->rdev;
        if (body->valid & OBD_MD_FLSIZE)
                lli->lli_st_size = body->size;
        if (body->valid & OBD_MD_FLBLOCKS)
                lli->lli_st_blocks = body->blocks;
}

static void obdo_to_inode(struct inode *dst, struct obdo *src,
                          obd_flag valid)
{
        struct llu_inode_info *lli = llu_i2info(dst);

        valid &= src->o_valid;

        if (valid & OBD_MD_FLATIME)
                LTIME_S(lli->lli_st_atime) = src->o_atime;
        if (valid & OBD_MD_FLMTIME)
                LTIME_S(lli->lli_st_mtime) = src->o_mtime;
        if (valid & OBD_MD_FLCTIME && src->o_ctime > LTIME_S(lli->lli_st_ctime))
                LTIME_S(lli->lli_st_ctime) = src->o_ctime;
        if (valid & OBD_MD_FLSIZE)
                lli->lli_st_size = src->o_size;
        if (valid & OBD_MD_FLBLOCKS) /* allocation of space */
                lli->lli_st_blocks = src->o_blocks;
        if (valid & OBD_MD_FLBLKSZ)
                lli->lli_st_blksize = src->o_blksize;
        if (valid & OBD_MD_FLTYPE)
                lli->lli_st_mode = (lli->lli_st_mode & ~S_IFMT) | (src->o_mode & S_IFMT);
        if (valid & OBD_MD_FLMODE)
                lli->lli_st_mode = (lli->lli_st_mode & S_IFMT) | (src->o_mode & ~S_IFMT);
        if (valid & OBD_MD_FLUID)
                lli->lli_st_uid = src->o_uid;
        if (valid & OBD_MD_FLGID)
                lli->lli_st_gid = src->o_gid;
        if (valid & OBD_MD_FLFLAGS)
                lli->lli_st_flags = src->o_flags;
        if (valid & OBD_MD_FLNLINK)
                lli->lli_st_nlink = src->o_nlink;
        if (valid & OBD_MD_FLGENER)
                lli->lli_st_generation = src->o_generation;
        if (valid & OBD_MD_FLRDEV)
                lli->lli_st_rdev = src->o_rdev;
}

int llu_inode_getattr(struct inode *inode, struct lov_stripe_md *lsm,
                      char *ostdata)
{
        struct llu_sb_info *sbi = llu_i2sbi(inode);
        struct obdo oa;
        int rc;
        ENTRY;

        LASSERT(lsm);
        LASSERT(sbi);

        memset(&oa, 0, sizeof oa);
        oa.o_id = lsm->lsm_object_id;
        oa.o_mode = S_IFREG;
        oa.o_valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE |
                OBD_MD_FLBLOCKS | OBD_MD_FLMTIME | OBD_MD_FLCTIME;

        if (ostdata != NULL) {
                memcpy(&oa.o_inline, ostdata, FD_OSTDATA_SIZE);
                oa.o_valid |= OBD_MD_FLHANDLE;
        }

        rc = obd_getattr(&sbi->ll_osc_conn, &oa, lsm);
        if (rc)
                RETURN(rc);

        obdo_to_inode(inode, &oa, OBD_MD_FLSIZE | OBD_MD_FLBLOCKS |
                           OBD_MD_FLMTIME | OBD_MD_FLCTIME);

        RETURN(0);
}

struct inode* llu_new_inode(struct filesys *fs, ino_t ino, mode_t mode)
{
	struct inode *inode;
        struct llu_inode_info *lli;

        OBD_ALLOC(lli, sizeof(*lli));
        if (!lli)
                return NULL;

        /* initialize lli here */
        lli->lli_sbi = llu_fs2sbi(fs);
        lli->lli_smd = NULL;
        lli->lli_symlink_name = NULL;
        lli->lli_flags = 0;
        INIT_LIST_HEAD(&lli->lli_read_extents);

        /* could file_identifier be 0 ? FIXME */
	inode = _sysio_i_new(fs, ino, NULL,
#ifndef AUTOMOUNT_FILE_NAME
	 	       	     mode & S_IFMT,
#else
			     mode,	/* all of the bits! */
#endif
			     &llu_inode_ops, lli);

	if (!inode)
		free(lli);

        return inode;
}

static int llu_iop_lookup(struct pnode *pnode,
                          struct inode **inop,
                          struct intent *intnt __IS_UNUSED,
                          const char *path __IS_UNUSED)
{
        struct pnode_base *pb_dir = pnode->p_parent->p_base;
        struct ptlrpc_request *request = NULL;
        struct llu_sb_info *sbi = llu_i2sbi(pb_dir->pb_ino);
        struct ll_fid *fid = &llu_i2info(pb_dir->pb_ino)->lli_fid;
        struct qstr *name = &pnode->p_base->pb_name;
        struct mds_body *body;
        unsigned long valid;
        int rc;
        struct ll_read_inode2_cookie lic = {.lic_body = NULL, .lic_lmm = NULL};

        /* the mount root inode have no name, so don't call
         * remote in this case. but probably we need revalidate
         * it here? FIXME */
        if (pnode->p_mount->mnt_root == pnode) {
                struct inode *i = pnode->p_base->pb_ino;
                I_REF(i);
                *inop = i;
                return 0;
        }

        if (!name->len)
                return -EINVAL;

        valid = OBD_MD_FLID | OBD_MD_FLTYPE | OBD_MD_FLSIZE;
        rc = mdc_getattr_name(&sbi->ll_mdc_conn, fid,
                              (char*)name->name, name->len + 1,
                              valid, 0, &request);
        if (rc < 0) {
                CERROR("mdc_getattr_name: %d\n", rc);
                goto out;
        }
        body = lustre_msg_buf(request->rq_repmsg, 0);

        *inop = llu_new_inode(pnode->p_mount->mnt_fs, body->ino, body->mode);
        if (!inop)
                goto out;

        lic.lic_body = lustre_msg_buf(request->rq_repmsg, 0);
        if (S_ISREG(lic.lic_body->mode) &&
            lic.lic_body->valid & OBD_MD_FLEASIZE) {
                LASSERT(request->rq_repmsg->bufcount > 0);
                lic.lic_lmm = lustre_msg_buf(request->rq_repmsg, 1);
        } else {
                lic.lic_lmm = NULL;
        }

        llu_update_inode(*inop, body, lic.lic_lmm);
                
        rc = llu_inode_getattr(*inop, llu_i2info(*inop)->lli_smd, NULL);
        if (rc)
                _sysio_i_gone(*inop);

out:
        ptlrpc_req_finished(request);

        return rc;
}

static int llu_iop_getattr(struct pnode *pno,
                           struct inode *ino,
                           struct intnl_stat *b)
{
        struct llu_inode_info *lli = llu_i2info(ino);

        b->st_dev = lli->lli_st_dev;
        b->st_ino = lli->lli_st_ino;
        b->st_mode = lli->lli_st_mode;
        b->st_nlink = lli->lli_st_nlink;
        b->st_uid = lli->lli_st_uid;
        b->st_gid = lli->lli_st_gid;
        b->st_rdev = lli->lli_st_rdev;
        b->st_size = lli->lli_st_size;
        b->st_blksize = lli->lli_st_blksize;
        b->st_blocks = lli->lli_st_blocks;
        b->st_atime = lli->lli_st_atime;
        b->st_mtime = lli->lli_st_mtime;
        b->st_ctime = lli->lli_st_ctime;

        return 0;
}

struct filesys_ops llu_filesys_ops =
{
        fsop_gone: llu_fsop_gone,
};

/* FIXME */
void generate_random_uuid(unsigned char uuid_out[16])
{
        int *arr = (int*)uuid_out;
        int i;

        for (i = 0; i < sizeof(uuid_out)/sizeof(int); i++)
                arr[i] = rand();
}

static struct inode_ops llu_inode_ops = {
        inop_lookup:    llu_iop_lookup,
        inop_getattr:   llu_iop_getattr,
};


static int
llu_fsswop_mount(const char *source,
                 unsigned flags,
                 const void *data __IS_UNUSED,
                 struct pnode *tocover,
                 struct mount **mntp)
{
        struct filesys *fs;
        struct inode *root;
        struct pnode_base *rootpb;
        static struct qstr noname = { NULL, 0, 0 };
        struct ll_fid rootfid;

        struct llu_sb_info *sbi;
        struct ptlrpc_connection *mdc_conn;
        struct ptlrpc_request *request = NULL;
        struct mds_body *root_body;
        struct obd_uuid param_uuid;
        class_uuid_t uuid;
        struct obd_device *obd;
        char *osc="lov1_UUID";
//        char *mdc="57f5ded574_MDC_lov1_mds1_a8c55ce8f1"; /* FIXME */
        char *mdc="853fe49c56_MDC_lov1_mds1_704cccf8fd";
        int err = -EINVAL;

        ENTRY;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        fs = _sysio_fs_new(&llu_filesys_ops, flags, sbi);
        if (!fs) {
                err = -ENOMEM;
                goto out_free;
        }

        strncpy(param_uuid.uuid, mdc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("MDC %s: not setup or attached\n", mdc);
                err = -EINVAL;
                goto out_free;
        }

        /* setup mdc */
        /* FIXME need recover stuff */
        err = obd_connect(&sbi->ll_mdc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                goto out_free;
        }

        mdc_conn = sbi2mdc(sbi)->cl_import->imp_connection;

        /* setup osc */
        strncpy(param_uuid.uuid, osc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                err = -EINVAL;
                goto out_mdc;
        }

        err = obd_connect(&sbi->ll_osc_conn, obd, &sbi->ll_sb_uuid);
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", osc, err);
                goto out_mdc;
        }

        err = mdc_getstatus(&sbi->ll_mdc_conn, &rootfid);
        if (err) {
                CERROR("cannot mds_connect: rc = %d\n", err);
                goto out_osc;
        }
        CDEBUG(D_SUPER, "rootfid "LPU64"\n", rootfid.id);
        sbi->ll_rootino = rootfid.id;

/* XXX do we need this??
        memset(&osfs, 0, sizeof(osfs));
        rc = obd_statfs(&sbi->ll_mdc_conn, &osfs);
*/
        /* fetch attr of root inode */
        err = mdc_getattr(&sbi->ll_mdc_conn, &rootfid,
                          OBD_MD_FLNOTOBD|OBD_MD_FLBLOCKS, 0, &request);
        if (err) {
                CERROR("mdc_getattr failed for root: rc = %d\n", err);
                goto out_request;
        }

        root_body = lustre_msg_buf(request->rq_repmsg, 0);
        LASSERT(sbi->ll_rootino != 0);

        root = llu_new_inode(fs, root_body->ino, root_body->mode);
        if (!root) {
		err = -ENOMEM;
                goto out_request;
        }

        llu_update_inode(root, root_body, NULL);

	/*
	 * Generate base path-node for root.
	 */
	rootpb = _sysio_pb_new(&noname, NULL, root);
	if (!rootpb) {
		err = -ENOMEM;
		goto out_inode;
	}

	err = _sysio_do_mount(fs, rootpb, flags, NULL, mntp);
	if (err) {
                _sysio_pb_gone(rootpb);
		goto out_inode;
        }

        ptlrpc_req_finished(request);
        request = NULL;

        printf("************************************************\n");
        printf("*          Mount successfully!!!!!!!           *\n");
        printf("************************************************\n");

        return 0;

out_inode:
        _sysio_i_gone(root);
out_request:
        ptlrpc_req_finished(request);
out_osc:
        obd_disconnect(&sbi->ll_osc_conn);
out_mdc:
        obd_disconnect(&sbi->ll_mdc_conn);
out_free:
        OBD_FREE(sbi, sizeof(*sbi));
        return err;
}

static struct fssw_ops llu_fssw_ops = {
        llu_fsswop_mount
};

extern int class_handle_ioctl(struct obd_class_user_state *ocus, unsigned int cmd, unsigned long arg);


int lib_ioctl(int dev_id, int opc, void * ptr)
{
        int rc;

	if (dev_id == OBD_DEV_ID) {
                struct obd_ioctl_data *ioc = ptr;
		rc = class_handle_ioctl(&ocus, opc, (unsigned long)ptr);

		/* you _may_ need to call obd_ioctl_unpack or some
		   other verification function if you want to use ioc
		   directly here */
		printf ("processing ioctl cmd: %x buf len: %d, rc %d\n", 
			opc,  ioc->ioc_len, rc);

                if (rc)
                        return rc;
	}
	return (0);
}

int lllib_init(char *arg)
{
	tcpnal_mynid = ntohl(inet_addr(arg));
        INIT_LIST_HEAD(&ocus.ocus_conns);

        init_current("dummy");
        if (init_obdclass() ||
            init_lib_portals() ||
            ptlrpc_init() ||
            ldlm_init() ||
            mdc_init() ||
            lov_init() ||
            osc_init())
                return -1;

	if (parse_dump("/tmp/DUMP_FILE", lib_ioctl))
                return -1;

        return _sysio_fssw_register("llite", &llu_fssw_ops);
}

