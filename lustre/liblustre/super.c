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

static void ll_fsop_gone(struct filesys *fs)
{
        /* FIXME */
}

static struct inode_ops ll_inode_ops;

static void fill_inode_fields(struct ll_inode_info *lli,
                              struct mds_body *body)
{
	lli->lli_st_dev = 0; /* FIXME */
        lli->lli_st_ino = body->ino;
	lli->lli_st_mode = body->mode;
	lli->lli_st_nlink = body->nlink;
	lli->lli_st_uid = body->uid;
	lli->lli_st_gid = body->gid;
	lli->lli_st_rdev = body->rdev;
	lli->lli_st_size = 0; /* XXX  */
	lli->lli_st_blksize = 0; /* XXX */
	lli->lli_st_blocks = body->blocks;
	lli->lli_st_atime = body->atime;
	lli->lli_st_mtime = body->mtime;
	lli->lli_st_ctime = body->ctime;
}

struct inode* ll_new_inode(struct filesys *fs, struct mds_body *body)
{
	struct inode *inode;
        struct ll_inode_info *lli;

        OBD_ALLOC(lli, sizeof(*lli));
        if (!lli)
                return NULL;

        /* initialize lli here */
        lli->lli_sbi = ll_fs2sbi(fs);
        lli->lli_smd = NULL; /* FIXME need setup it here */
        lli->lli_symlink_name = NULL; /* FIXME */
        lli->lli_flags = 0;
        INIT_LIST_HEAD(&lli->lli_read_extents);
        ll_ino2fid(&lli->lli_fid,
                   body->ino,
                   body->generation,
                   body->mode & S_IFMT);
        fill_inode_fields(lli, body);


        /* could file_identifier be 0 ? FIXME */
	inode = _sysio_i_new(fs, body->ino, NULL,
#ifndef AUTOMOUNT_FILE_NAME
	 	       	     body->mode & S_IFMT,
#else
			     body->mode,	/* all of the bits! */
#endif
			     &ll_inode_ops, lli);

	if (!inode)
		free(lli);

        return inode;
}

static int ll_iop_lookup(struct pnode *pnode,
                         struct inode **inop,
                         struct intent *intnt __IS_UNUSED,
                         const char *path __IS_UNUSED)
{
        struct pnode_base *pb_dir = pnode->p_parent->p_base;
        struct ptlrpc_request *request = NULL;
        struct ll_sb_info *sbi = ll_i2sbi(pb_dir->pb_ino);
        struct ll_fid *fid = &ll_i2info(pb_dir->pb_ino)->lli_fid;
        struct qstr *name = &pnode->p_base->pb_name;
        struct mds_body *body;
        unsigned long valid;
        int rc;

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
        *inop = ll_new_inode(pnode->p_mount->mnt_fs, body);
out:
        ptlrpc_req_finished(request);
        return rc;
}

static int ll_iop_getattr(struct pnode *pno,
                          struct inode *ino,
                          struct intnl_stat *b)
{
        struct ll_inode_info *lli = ll_i2info(ino);

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

struct filesys_ops ll_filesys_ops =
{
        fsop_gone: ll_fsop_gone,
};

/* FIXME */
void generate_random_uuid(unsigned char uuid_out[16])
{
        int *arr = (int*)uuid_out;
        int i;

        for (i = 0; i < sizeof(uuid_out)/sizeof(int); i++)
                arr[i] = rand();
}

static struct inode_ops ll_inode_ops = {
        inop_lookup:    ll_iop_lookup,
        inop_getattr:   ll_iop_getattr,
};


static int
ll_fsswop_mount(const char *source,
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

        struct ll_sb_info *sbi;
        struct obd_statfs osfs;
        struct ptlrpc_connection *mdc_conn;
        struct ptlrpc_request *request = NULL;
        struct mds_body *root_body;
        struct obd_uuid param_uuid;
        class_uuid_t uuid;
        struct obd_device *obd;
        char *osc="lov1_UUID", *mdc="57f5ded574_MDC_lov1_mds1_a8c55ce8f1"; /* FIXME */
        int err = -EINVAL;

        ENTRY;

        OBD_ALLOC(sbi, sizeof(*sbi));
        if (!sbi)
                RETURN(-ENOMEM);

        INIT_LIST_HEAD(&sbi->ll_conn_chain);
        generate_random_uuid(uuid);
        class_uuid_unparse(uuid, &sbi->ll_sb_uuid);

        fs = _sysio_fs_new(&ll_filesys_ops, flags, sbi);
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
        err = obd_connect(&sbi->ll_mdc_conn, obd, &sbi->ll_sb_uuid,
                          NULL, NULL); /*ptlrpc_recovd, ll_recover);*/
        if (err) {
                CERROR("cannot connect to %s: rc = %d\n", mdc, err);
                goto out_free;
        }

        mdc_conn = sbi2mdc(sbi)->cl_import.imp_connection;
        list_add(&mdc_conn->c_sb_chain, &sbi->ll_conn_chain);

        /* setup osc */
        strncpy(param_uuid.uuid, osc, sizeof(param_uuid.uuid));
        obd = class_uuid2obd(&param_uuid);
        if (!obd) {
                CERROR("OSC %s: not setup or attached\n", osc);
                err = -EINVAL;
                goto out_mdc;
        }

        err = obd_connect(&sbi->ll_osc_conn, obd, &sbi->ll_sb_uuid,
                          NULL, NULL); /*ptlrpc_recovd, ll_recover);*/
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

        root = ll_new_inode(fs, root_body);
        if (!root) {
		err = -ENOMEM;
                goto out_request;
        }

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
        ll_fsswop_mount
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

