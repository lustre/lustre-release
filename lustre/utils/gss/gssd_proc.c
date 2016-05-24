/*
  gssd_proc.c

  Copyright (c) 2000-2004 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2000 Dug Song <dugsong@UMICH.EDU>.
  Copyright (c) 2001 Andy Adamson <andros@UMICH.EDU>.
  Copyright (c) 2002 Marius Aamodt Eriksen <marius@UMICH.EDU>.
  Copyright (c) 2002 Bruce Fields <bfields@UMICH.EDU>
  Copyright (c) 2004 Kevin Coffman <kwc@umich.edu>
  All rights reserved, all wrongs reversed.

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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "config.h"
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/fsuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <dirent.h>
#include <poll.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <gssapi/gssapi.h>
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <libcfs/util/param.h>

#include "gssd.h"
#include "err_util.h"
#include "gss_util.h"
#include "gss_oids.h"
#include "krb5_util.h"
#include "context.h"
#include "lsupport.h"

/*
 * pollarray:
 *      array of struct pollfd suitable to pass to poll. initialized to
 *      zero - a zero struct is ignored by poll() because the events mask is 0.
 *
 * clnt_list:
 *      linked list of struct clnt_info which associates a clntXXX directory
 *	with an index into pollarray[], and other basic data about that client.
 *
 * Directory structure: created by the kernel nfs client
 *      {pipefs_nfsdir}/clntXX             : one per rpc_clnt struct in the kernel
 *      {pipefs_nfsdir}/clntXX/krb5        : read uid for which kernel wants
 *					    a context, write the resulting context
 *      {pipefs_nfsdir}/clntXX/info        : stores info such as server name
 *
 * Algorithm:
 *      Poll all {pipefs_nfsdir}/clntXX/krb5 files.  When ready, data read
 *      is a uid; performs rpcsec_gss context initialization protocol to
 *      get a cred for that user.  Writes result to corresponding krb5 file
 *      in a form the kernel code will understand.
 *      In addition, we make sure we are notified whenever anything is
 *      created or destroyed in {pipefs_nfsdir} or in an of the clntXX directories,
 *      and rescan the whole {pipefs_nfsdir} when this happens.
 */

struct pollfd * pollarray;

int pollsize;  /* the size of pollaray (in pollfd's) */

static void
destroy_client(struct clnt_info *clp)
{
	printerr(3, "clp %p: dirname %s, krb5fd %d\n", clp, clp->dirname, clp->krb5_fd);
	if (clp->krb5_poll_index != -1)
		memset(&pollarray[clp->krb5_poll_index], 0,
					sizeof(struct pollfd));
	if (clp->spkm3_poll_index != -1)
		memset(&pollarray[clp->spkm3_poll_index], 0,
					sizeof(struct pollfd));
	if (clp->dir_fd != -1) close(clp->dir_fd);
	if (clp->krb5_fd != -1) close(clp->krb5_fd);
	if (clp->spkm3_fd != -1) close(clp->spkm3_fd);
	if (clp->dirname) free(clp->dirname);
	if (clp->servicename) free(clp->servicename);
	free(clp);
}

static struct clnt_info *
insert_new_clnt(void)
{
	struct clnt_info	*clp = NULL;

	if (!(clp = (struct clnt_info *)calloc(1,sizeof(struct clnt_info)))) {
		printerr(0, "ERROR: can't malloc clnt_info: %s\n",
			 strerror(errno));
		goto out;
	}
	clp->krb5_poll_index = -1;
	clp->spkm3_poll_index = -1;
	clp->krb5_fd = -1;
	clp->spkm3_fd = -1;
	clp->dir_fd = -1;

	TAILQ_INSERT_HEAD(&clnt_list, clp, list);
out:
	return clp;
}

static int
process_clnt_dir_files(struct clnt_info * clp)
{
	char	kname[32];
	char	sname[32];

	if (clp->krb5_fd == -1) {
		snprintf(kname, sizeof(kname), "%s/krb5", clp->dirname);
		clp->krb5_fd = open(kname, O_RDWR);
	}
	if (clp->spkm3_fd == -1) {
		snprintf(sname, sizeof(sname), "%s/spkm3", clp->dirname);
		clp->spkm3_fd = open(sname, O_RDWR);
	}
	if((clp->krb5_fd == -1) && (clp->spkm3_fd == -1))
		return -1;
	return 0;
}

static int
get_poll_index(int *ind)
{
	int i;

	*ind = -1;
	for (i=0; i<FD_ALLOC_BLOCK; i++) {
		if (pollarray[i].events == 0) {
			*ind = i;
			break;
		}
	}
	if (*ind == -1) {
		printerr(0, "ERROR: No pollarray slots open\n");
		return -1;
	}
	return 0;
}


static int
insert_clnt_poll(struct clnt_info *clp)
{
	if ((clp->krb5_fd != -1) && (clp->krb5_poll_index == -1)) {
		if (get_poll_index(&clp->krb5_poll_index)) {
			printerr(0, "ERROR: Too many krb5 clients\n");
			return -1;
		}
		pollarray[clp->krb5_poll_index].fd = clp->krb5_fd;
		pollarray[clp->krb5_poll_index].events |= POLLIN;
		printerr(2, "monitoring krb5 channel under %s\n",
			 clp->dirname);
	}

	if ((clp->spkm3_fd != -1) && (clp->spkm3_poll_index == -1)) {
		if (get_poll_index(&clp->spkm3_poll_index)) {
			printerr(0, "ERROR: Too many spkm3 clients\n");
			return -1;
		}
		pollarray[clp->spkm3_poll_index].fd = clp->spkm3_fd;
		pollarray[clp->spkm3_poll_index].events |= POLLIN;
	}

	return 0;
}

static void
process_clnt_dir(char *dir)
{
	struct clnt_info *	clp;

	if (!(clp = insert_new_clnt()))
		goto fail_destroy_client;

	if (!(clp->dirname = calloc(strlen(dir) + 1, 1))) {
		goto fail_destroy_client;
	}
	memcpy(clp->dirname, dir, strlen(dir));
	if ((clp->dir_fd = open(clp->dirname, O_RDONLY)) == -1) {
		printerr(0, "ERROR: can't open %s: %s\n",
			 clp->dirname, strerror(errno));
		goto fail_destroy_client;
	}
	fcntl(clp->dir_fd, F_SETSIG, DNOTIFY_SIGNAL);
	fcntl(clp->dir_fd, F_NOTIFY, DN_CREATE | DN_DELETE | DN_MULTISHOT);

	if (process_clnt_dir_files(clp))
		goto fail_keep_client;

	if (insert_clnt_poll(clp))
		goto fail_destroy_client;

	return;

fail_destroy_client:
	if (clp) {
		TAILQ_REMOVE(&clnt_list, clp, list);
		destroy_client(clp);
	}
fail_keep_client:
	/* We couldn't find some subdirectories, but we keep the client
	 * around in case we get a notification on the directory when the
	 * subdirectories are created. */
	return;
}

void
init_client_list(void)
{
	TAILQ_INIT(&clnt_list);
	/* Eventually plan to grow/shrink poll array: */
	pollsize = FD_ALLOC_BLOCK;
	pollarray = calloc(pollsize, sizeof(struct pollfd));
}

/*
 * This is run after a DNOTIFY signal, and should clear up any
 * directories that are no longer around, and re-scan any existing
 * directories, since the DNOTIFY could have been in there.
 */
static void
update_old_clients(struct dirent **namelist, int size)
{
	struct clnt_info *clp;
	void *saveprev;
	int i, stillhere;

	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next) {
		stillhere = 0;
		for (i=0; i < size; i++) {
			if (!strcmp(clp->dirname, namelist[i]->d_name)) {
				stillhere = 1;
				break;
			}
		}
		if (!stillhere) {
			printerr(2, "destroying client %s\n", clp->dirname);
			saveprev = clp->list.tqe_prev;
			TAILQ_REMOVE(&clnt_list, clp, list);
			destroy_client(clp);
			clp = saveprev;
		}
	}
	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next) {
		if (!process_clnt_dir_files(clp))
			insert_clnt_poll(clp);
	}
}

/* Search for a client by directory name, return 1 if found, 0 otherwise */
static int
find_client(char *dirname)
{
	struct clnt_info	*clp;

	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next)
		if (!strcmp(clp->dirname, dirname))
			return 1;
	return 0;
}

/* Used to read (and re-read) list of clients, set up poll array. */
int
update_client_list(void)
{
	char lustre_dir[PATH_MAX];
	struct dirent lustre_dirent = { .d_name = "lustre" };
	struct dirent *namelist[1];
	struct stat statbuf;
	int i, j;

	if (chdir(pipefs_dir) < 0) {
		printerr(0, "ERROR: can't chdir to %s: %s\n",
			 pipefs_dir, strerror(errno));
		return -1;
	}

	snprintf(lustre_dir, sizeof(lustre_dir), "%s/%s", pipefs_dir, "lustre");
	if (stat(lustre_dir, &statbuf) == 0) {
		namelist[0] = &lustre_dirent;
		j = 1;
		printerr(2, "re-processing lustre directory\n");
	} else {
		namelist[0] = NULL;
		j = 0;
		printerr(2, "lustre directory not exist\n");
	}

	update_old_clients(namelist, j);
	for (i=0; i < j; i++) {
		if (i < FD_ALLOC_BLOCK && !find_client(namelist[i]->d_name))
			process_clnt_dir(namelist[i]->d_name);
	}

	chdir("/");
	return 0;
}

/* Context creation response. */
struct lustre_gss_init_res {
	gss_buffer_desc gr_ctx;         /* context handle */
	unsigned int    gr_major;       /* major status */
	unsigned int    gr_minor;       /* minor status */
	unsigned int    gr_win;         /* sequence window */
	gss_buffer_desc gr_token;       /* token */
};

struct lustre_gss_data {
	int             lgd_established;
	int             lgd_lustre_svc; /* mds/oss */
	int             lgd_uid;        /* uid */
	char           *lgd_uuid;       /* client device uuid */
	gss_name_t      lgd_name;       /* service name */

	gss_OID         lgd_mech;       /* mech OID */
	unsigned int    lgd_req_flags;  /* request flags */
	gss_cred_id_t   lgd_cred;       /* credential */
	gss_ctx_id_t    lgd_ctx;        /* session context */
	gss_buffer_desc lgd_rmt_ctx;    /* remote handle of context */
	uint32_t        lgd_seq_win;    /* sequence window */

	int             lgd_rpc_err;
	int             lgd_gss_err;
};

static int
do_downcall(int k5_fd, struct lgssd_upcall_data *updata,
            struct lustre_gss_data *lgd, gss_buffer_desc *context_token)
{
	char    *buf = NULL, *p = NULL, *end = NULL;
	unsigned int timeout = 0; /* XXX decide on a reasonable value */
	unsigned int buf_size = 0;

	printerr(2, "doing downcall\n");
	buf_size = sizeof(updata->seq) + sizeof(timeout) +
		sizeof(lgd->lgd_seq_win) +
		sizeof(lgd->lgd_rmt_ctx.length) + lgd->lgd_rmt_ctx.length +
		sizeof(context_token->length) + context_token->length;
	p = buf = malloc(buf_size);
	end = buf + buf_size;

	if (WRITE_BYTES(&p, end, updata->seq)) goto out_err;
	/* Not setting any timeout for now: */
	if (WRITE_BYTES(&p, end, timeout)) goto out_err;
	if (WRITE_BYTES(&p, end, lgd->lgd_seq_win)) goto out_err;
	if (write_buffer(&p, end, &lgd->lgd_rmt_ctx)) goto out_err;
	if (write_buffer(&p, end, context_token)) goto out_err;

	lgssd_mutex_get(lgssd_mutex_downcall);
	if (write(k5_fd, buf, p - buf) < p - buf) {
		lgssd_mutex_put(lgssd_mutex_downcall);
		goto out_err;
	}
	lgssd_mutex_put(lgssd_mutex_downcall);

	if (buf) free(buf);
	return 0;
out_err:
	if (buf) free(buf);
	printerr(0, "ERROR: Failed to write downcall!\n");
	return -1;
}

static int
do_error_downcall(int k5_fd, uint32_t seq, int rpc_err, int gss_err)
{
	char	buf[1024];
	char	*p = buf, *end = buf + 1024;
	unsigned int timeout = 0;
	int	zero = 0;

	printerr(1, "doing error downcall\n");

	if (WRITE_BYTES(&p, end, seq)) goto out_err;
	if (WRITE_BYTES(&p, end, timeout)) goto out_err;
	/* use seq_win = 0 to indicate an error: */
	if (WRITE_BYTES(&p, end, zero)) goto out_err;
	if (WRITE_BYTES(&p, end, rpc_err)) goto out_err;
	if (WRITE_BYTES(&p, end, gss_err)) goto out_err;

	lgssd_mutex_get(lgssd_mutex_downcall);
	if (write(k5_fd, buf, p - buf) < p - buf) {
		lgssd_mutex_put(lgssd_mutex_downcall);
		goto out_err;
	}
	lgssd_mutex_put(lgssd_mutex_downcall);
	return 0;
out_err:
	printerr(0, "Failed to write error downcall!\n");
	return -1;
}

static
int do_negotiation(struct lustre_gss_data *lgd,
		   gss_buffer_desc *gss_token,
		   struct lustre_gss_init_res *gr,
		   int timeout)
{
	struct lgssd_ioctl_param param;
	struct passwd *pw;
	char outbuf[8192];
	unsigned int *p;
	glob_t path;
	int fd;
	int rc;

	pw = getpwuid(lgd->lgd_uid);
	if (!pw) {
		printerr(0, "no uid %u in local user database\n",
			 lgd->lgd_uid);
		return -1;
	}

	param.version = GSSD_INTERFACE_VERSION_V1;
	param.uuid = lgd->lgd_uuid;
	param.lustre_svc = lgd->lgd_lustre_svc;
	param.uid = lgd->lgd_uid;
	param.gid = pw->pw_gid;
	param.send_token_size = gss_token->length;
	param.send_token = (char *) gss_token->value;
	param.reply_buf_size = sizeof(outbuf);
	param.reply_buf = outbuf;

	if (cfs_get_param_paths(&path, "sptlrpc/gss/init_channel") != 0)
		return -1;

	fd = open(path.gl_pathv[0], O_RDWR);
	if (fd < 0) {
		printerr(0, "can't open file %s\n", path.gl_pathv[0]);
		rc = -1;
		goto out_params;
	}

	rc = write(fd, &param, sizeof(param));
	if (rc != sizeof(param)) {
		printerr(0, "lustre ioctl err: %d\n", strerror(errno));
		rc = -1;
		goto out_fd;
	}
	if (param.status) {
		printerr(0, "status: %d (%s)\n",
			 param.status, strerror((int)param.status));
		if (param.status == -ETIMEDOUT) {
			/* kernel return -ETIMEDOUT means the rpc timedout,
			 * we should notify the caller to reinitiate the
			 * gss negotiation, by return -ERESTART
			 */
			lgd->lgd_rpc_err = -ERESTART;
			lgd->lgd_gss_err = 0;
		} else {
			lgd->lgd_rpc_err = param.status;
			lgd->lgd_gss_err = 0;
		}
		rc = -1;
		goto out_fd;
	}
	p = (unsigned int *)outbuf;
	gr->gr_major = *p++;
	gr->gr_minor = *p++;
	gr->gr_win = *p++;

	gr->gr_ctx.length = *p++;
	gr->gr_ctx.value = malloc(gr->gr_ctx.length);
	memcpy(gr->gr_ctx.value, p, gr->gr_ctx.length);
	p += (((gr->gr_ctx.length + 3) & ~3) / 4);

	gr->gr_token.length = *p++;
	gr->gr_token.value = malloc(gr->gr_token.length);
	memcpy(gr->gr_token.value, p, gr->gr_token.length);
	p += (((gr->gr_token.length + 3) & ~3) / 4);

	printerr(2, "do_negotiation: receive handle len %d, token len %d\n",
		 gr->gr_ctx.length, gr->gr_token.length);
	rc = 0;
out_fd:
	close(fd);
out_params:
	cfs_free_param_data(&path);
	return rc;
}

static
int gssd_refresh_lgd(struct lustre_gss_data *lgd)
{
	struct lustre_gss_init_res gr;
	gss_buffer_desc		*recv_tokenp, send_token;
	OM_uint32		 maj_stat, min_stat, call_stat, ret_flags;

	/* GSS context establishment loop. */
	memset(&gr, 0, sizeof(gr));
	recv_tokenp = GSS_C_NO_BUFFER;

	for (;;) {
		/* print the token we just received */
		if (recv_tokenp != GSS_C_NO_BUFFER) {
			printerr(3, "The received token length %d\n",
				 recv_tokenp->length);
			print_hexl(3, recv_tokenp->value, recv_tokenp->length);
		}

		maj_stat = gss_init_sec_context(&min_stat,
						lgd->lgd_cred,
						&lgd->lgd_ctx,
						lgd->lgd_name,
						lgd->lgd_mech,
						lgd->lgd_req_flags,
						0,		/* time req */
						NULL,		/* channel */
						recv_tokenp,
						NULL,		/* used mech */
						&send_token,
						&ret_flags,
						NULL);		/* time rec */

		if (recv_tokenp != GSS_C_NO_BUFFER) {
			gss_release_buffer(&min_stat, &gr.gr_token);
			recv_tokenp = GSS_C_NO_BUFFER;
		}
		if (maj_stat != GSS_S_COMPLETE &&
		    maj_stat != GSS_S_CONTINUE_NEEDED) {
			pgsserr("gss_init_sec_context", maj_stat, min_stat,
				lgd->lgd_mech);
			break;
		}
		if (send_token.length != 0) {
			memset(&gr, 0, sizeof(gr));

			/* print the token we are about to send */
			printerr(3, "token being sent length %d\n",
				 send_token.length);
			print_hexl(3, send_token.value, send_token.length);

			call_stat = do_negotiation(lgd, &send_token, &gr, 0);
			gss_release_buffer(&min_stat, &send_token);

			if (call_stat != 0 ||
			    (gr.gr_major != GSS_S_COMPLETE &&
			     gr.gr_major != GSS_S_CONTINUE_NEEDED)) {
				printerr(0, "call stat %d, major stat 0x%x\n",
					 (int)call_stat, gr.gr_major);
				return -1;
			}

			if (gr.gr_ctx.length != 0) {
				if (lgd->lgd_rmt_ctx.value)
					gss_release_buffer(&min_stat,
							   &lgd->lgd_rmt_ctx);
				lgd->lgd_rmt_ctx = gr.gr_ctx;
			}
			if (gr.gr_token.length != 0) {
				if (maj_stat != GSS_S_CONTINUE_NEEDED)
					break;
				recv_tokenp = &gr.gr_token;
			}
		}

		/* GSS_S_COMPLETE => check gss header verifier,
		 * usually checked in gss_validate
		 */
		if (maj_stat == GSS_S_COMPLETE) {
			lgd->lgd_established = 1;
			lgd->lgd_seq_win = gr.gr_win;
			break;
		}
	}
	/* End context negotiation loop. */
	if (!lgd->lgd_established) {
		if (gr.gr_token.length != 0)
			gss_release_buffer(&min_stat, &gr.gr_token);

		printerr(0, "context negotiation failed\n");
		return -1;
	}

	printerr(2, "successfully refreshed lgd\n");
	return 0;
}

static
int gssd_create_lgd(struct clnt_info *clp,
		    struct lustre_gss_data *lgd,
		    struct lgssd_upcall_data *updata,
		    int authtype)
{
	gss_buffer_desc		sname;
	OM_uint32		maj_stat, min_stat;
	int 			retval = -1;

	lgd->lgd_established = 0;
	lgd->lgd_lustre_svc = updata->svc;
	lgd->lgd_uid = updata->uid;
	lgd->lgd_uuid = updata->obd;

	switch (authtype) {
	case AUTHTYPE_KRB5:
		lgd->lgd_mech = (gss_OID) &krb5oid;
		lgd->lgd_req_flags = GSS_C_MUTUAL_FLAG;
		break;
	case AUTHTYPE_SPKM3:
		lgd->lgd_mech = (gss_OID) &spkm3oid;
		/* XXX sec.req_flags = GSS_C_ANON_FLAG;
		 * Need a way to switch....
		 */
		lgd->lgd_req_flags = GSS_C_MUTUAL_FLAG;
		break;
	default:
		printerr(0, "Invalid authentication type (%d)\n", authtype);
		return -1;
	}

	lgd->lgd_cred = GSS_C_NO_CREDENTIAL;
	lgd->lgd_ctx = GSS_C_NO_CONTEXT;
	lgd->lgd_rmt_ctx = (gss_buffer_desc) GSS_C_EMPTY_BUFFER;
	lgd->lgd_seq_win = 0;

	sname.value = clp->servicename;
	sname.length = strlen(clp->servicename);

	maj_stat = gss_import_name(&min_stat, &sname,
				   (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				   &lgd->lgd_name);
	if (maj_stat != GSS_S_COMPLETE) {
		pgsserr(0, maj_stat, min_stat, lgd->lgd_mech);
		goto out_fail;
	}

	retval = gssd_refresh_lgd(lgd);

	if (lgd->lgd_name != GSS_C_NO_NAME)
		gss_release_name(&min_stat, &lgd->lgd_name);

	if (lgd->lgd_cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min_stat, &lgd->lgd_cred);

  out_fail:
	return retval;
}

static
void gssd_free_lgd(struct lustre_gss_data *lgd)
{
	gss_buffer_t		token = GSS_C_NO_BUFFER;
	OM_uint32		maj_stat, min_stat;

	if (lgd->lgd_ctx == GSS_C_NO_CONTEXT)
		return;

	maj_stat = gss_delete_sec_context(&min_stat, &lgd->lgd_ctx, token);
}

static
int construct_service_name(struct clnt_info *clp,
                           struct lgssd_upcall_data *ud)
{
        const int buflen = 256;
        char name[buflen];

        if (clp->servicename) {
                free(clp->servicename);
                clp->servicename = NULL;
        }

        if (lnet_nid2hostname(ud->nid, name, buflen))
                return -1;

        clp->servicename = malloc(32 + strlen(name));
        if (!clp->servicename) {
                printerr(0, "can't alloc memory\n");
                return -1;
        }
        sprintf(clp->servicename, "%s@%s",
                ud->svc == LUSTRE_GSS_SVC_MDS ?
		GSSD_SERVICE_MDS : GSSD_SERVICE_OSS,
                name);
        printerr(2, "constructed servicename: %s\n", clp->servicename);
        return 0;
}

/*
 * this code uses the userland rpcsec gss library to create a krb5
 * context on behalf of the kernel
 */
void
handle_krb5_upcall(struct clnt_info *clp)
{
	pid_t			pid;
	gss_buffer_desc		token = { 0, NULL };
	struct lgssd_upcall_data updata;
	struct lustre_gss_data	lgd;
	char			**credlist = NULL;
	char			**ccname;
	int			read_rc;

	printerr(2, "handling krb5 upcall\n");

	memset(&lgd, 0, sizeof(lgd));
	lgd.lgd_rpc_err = -EPERM; /* default error code */

	read_rc = read(clp->krb5_fd, &updata, sizeof(updata));
	if (read_rc < 0) {
		printerr(0, "WARNING: failed reading from krb5 "
			    "upcall pipe: %s\n", strerror(errno));
		return;
	} else if (read_rc != sizeof(updata)) {
		printerr(0, "upcall data mismatch: length %d, expect %d\n",
			 read_rc, sizeof(updata));

		/* the sequence number must be the first field. if read >= 4
		 * bytes then we know at least sequence is fine, try to send
		 * error notification nicely.
		 */
		if (read_rc >= 4)
			do_error_downcall(clp->krb5_fd, updata.seq, -EPERM, 0);
		return;
	}

	/* FIXME temporary fix, do this before fork.
	 * in case of errors could have memory leak!!!
	 */
	if (updata.uid == 0) {
		if (gssd_get_krb5_machine_cred_list(&credlist)) {
			printerr(0, "ERROR: Failed to obtain machine "
				    "credentials\n");
			do_error_downcall(clp->krb5_fd, updata.seq, -EPERM, 0);
			return;
		}
	}

	/* fork child process */
	pid = fork();
	if (pid < 0) {
		printerr(0, "can't fork: %s\n", strerror(errno));
		do_error_downcall(clp->krb5_fd, updata.seq, -EPERM, 0);
		return;
	} else if (pid > 0) {
		printerr(2, "forked child process: %d\n", pid);
		return;
	}

	printerr(1, "krb5 upcall: seq %u, uid %u, svc %u, nid 0x%llx, obd %s\n",
		 updata.seq, updata.uid, updata.svc, updata.nid, updata.obd);

	if (updata.svc != LUSTRE_GSS_SVC_MDS &&
	    updata.svc != LUSTRE_GSS_SVC_OSS) {
		printerr(0, "invalid svc %d\n", updata.svc);
		lgd.lgd_rpc_err = -EPROTO;
		goto out_return_error;
	}
	updata.obd[sizeof(updata.obd)-1] = '\0';

	if (construct_service_name(clp, &updata)) {
		printerr(0, "failed to construct service name\n");
		goto out_return_error;
	}

	if (updata.uid == 0) {
		int success = 0;

		/*
		 * Get a list of credential cache names and try each
		 * of them until one works or we've tried them all
		 */
/*
		if (gssd_get_krb5_machine_cred_list(&credlist)) {
			printerr(0, "ERROR: Failed to obtain machine "
				    "credentials for %s\n", clp->servicename);
			goto out_return_error;
		}
*/
		for (ccname = credlist; ccname && *ccname; ccname++) {
			gssd_setup_krb5_machine_gss_ccache(*ccname);
			if ((gssd_create_lgd(clp, &lgd, &updata,
					     AUTHTYPE_KRB5)) == 0) {
				/* Success! */
				success++;
				break;
			}
			printerr(2, "WARNING: Failed to create krb5 context "
				    "for user with uid %d with credentials "
				    "cache %s for service %s\n",
				 updata.uid, *ccname, clp->servicename);
		}
		gssd_free_krb5_machine_cred_list(credlist);
		if (!success) {
			printerr(0, "ERROR: Failed to create krb5 context "
				    "for user with uid %d with any "
				    "credentials cache for service %s\n",
				 updata.uid, clp->servicename);
			goto out_return_error;
		}
	}
	else {
		/* Tell krb5 gss which credentials cache to use */
		gssd_setup_krb5_user_gss_ccache(updata.uid, clp->servicename);

		if ((gssd_create_lgd(clp, &lgd, &updata, AUTHTYPE_KRB5)) != 0) {
			printerr(0, "WARNING: Failed to create krb5 context "
				    "for user with uid %d for service %s\n",
				 updata.uid, clp->servicename);
			goto out_return_error;
		}
	}

	if (serialize_context_for_kernel(lgd.lgd_ctx, &token, &krb5oid)) {
		printerr(0, "WARNING: Failed to serialize krb5 context for "
			    "user with uid %d for service %s\n",
			 updata.uid, clp->servicename);
		goto out_return_error;
	}

	printerr(1, "refreshed: %u@%s for %s\n",
		 updata.uid, updata.obd, clp->servicename);
	do_downcall(clp->krb5_fd, &updata, &lgd, &token);

out:
	if (token.value)
		free(token.value);

	gssd_free_lgd(&lgd);
	exit(0); /* i'm child process */

out_return_error:
	do_error_downcall(clp->krb5_fd, updata.seq,
			  lgd.lgd_rpc_err, lgd.lgd_gss_err);
	goto out;
}

