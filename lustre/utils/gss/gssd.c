/*
  gssd.c

  Copyright (c) 2000 The Regents of the University of Michigan.
  All rights reserved.

  Copyright (c) 2000 Dug Song <dugsong@UMICH.EDU>.
  Copyright (c) 2002 Andy Adamson <andros@UMICH.EDU>.
  Copyright (c) 2002 Marius Aamodt Eriksen <marius@UMICH.EDU>.
  All rights reserved, all wrongs reversed.

  Copyright (c) 2014, Intel Corporation.

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

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/sem.h>

#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <libcfs/util/string.h>

#include "gssd.h"
#include "err_util.h"
#include "gss_util.h"
#include "krb5_util.h"
#include "lsupport.h"

char pipefs_dir[PATH_MAX] = GSSD_PIPEFS_DIR;
char pipefs_nfsdir[PATH_MAX] = GSSD_PIPEFS_DIR;
char keytabfile[PATH_MAX] = GSSD_DEFAULT_KEYTAB_FILE;
char ccachedir[PATH_MAX] = GSSD_DEFAULT_CRED_DIR;
int  use_memcache = 0;
int  lgssd_mutex_downcall = -1;

static int lgssd_create_mutex(int *semid)
{
	int		id;
	int		arg;

	id = semget(IPC_PRIVATE, 1, IPC_CREAT);
	if (id == -1) {
		printerr(0, "semget: %s\n", strerror(errno));
		return -1;
	}

	arg = 1;
	if (semctl(id, 0, SETVAL, arg) != 0) {
		printerr(0, "semctl: %s\n", strerror(errno));
		semctl(id, 1, IPC_RMID, arg);
		return -1;
	}

	*semid = id;
	return 0;
}

void lgssd_init_mutexs(void)
{
	if (lgssd_create_mutex(&lgssd_mutex_downcall)) {
		printerr(0, "can't create downcall mutex\n");
		exit(1);
	}
}

void lgssd_fini_mutexs(void)
{
	int	arg = 0;

	if (lgssd_mutex_downcall != -1)
		semctl(lgssd_mutex_downcall, 1, IPC_RMID, arg);
}

void lgssd_mutex_get(int semid)
{
	struct sembuf op = {
		.sem_op = -1,
		.sem_flag = SEM_UNDO
	};
	int rc;

	rc = semop(semid, &op, 1);
	if (rc != 0) {
		printerr(0, "exit on mutex_get err %d: %s\n",
			 rc, strerror(errno));
		exit(1);
	}
}

void lgssd_mutex_put(int semid)
{
	struct sembuf op = {
		.sem_op = 1
	};
	int rc;

	rc = semop(semid, &op, 1);
	if (rc != 0) {
		printerr(0, "ignore mutex_put err %d: %s\n",
			 rc, strerror(errno));
	}
}

static void lgssd_cleanup(void)
{
	pid_t	child_pid;

	/* make sure all children finished */
	while (1) {
		child_pid = waitpid(-1, NULL, 0);
		if (child_pid < 0)
			break;

		printerr(3, "cleanup: child %d terminated\n", child_pid);
	}

	lgssd_fini_mutexs();

	/* destroy krb5 machine creds */
	gssd_destroy_krb5_machine_creds();
}

void
sig_die(int signal)
{
	printerr(1, "exiting on signal %d\n", signal);
	lgssd_cleanup();
	exit(1);
}

void
sig_hup(int signal)
{
	/* don't exit on SIGHUP */
	printerr(1, "Received SIGHUP... Ignoring.\n");
	return;
}

static void
usage(char *progname)
{
	fprintf(stderr, "usage: %s [-f] [-v] [-p pipefsdir] [-k keytab] [-d ccachedir]\n",
		progname);
	exit(1);
}

int
main(int argc, char *argv[])
{
	int fg = 0;
	int verbosity = 0;
	int opt;
	extern char *optarg;
	char *progname;

	while ((opt = getopt(argc, argv, "fvrmMp:k:d:")) != -1) {
		switch (opt) {
			case 'f':
				fg = 1;
				break;
			case 'M':
				use_memcache = 1;
				break;
			case 'v':
				verbosity++;
				break;
			case 'p':
				strlcpy(pipefs_dir, optarg, sizeof(pipefs_dir));
				if (pipefs_dir[sizeof(pipefs_dir)-1] != '\0')
					errx(1, "pipefs path name too long");
				break;
			case 'k':
				strlcpy(keytabfile, optarg, sizeof(keytabfile));
				if (keytabfile[sizeof(keytabfile)-1] != '\0')
					errx(1, "keytab path name too long");
				break;
			case 'd':
				strlcpy(ccachedir, optarg, sizeof(ccachedir));
				if (ccachedir[sizeof(ccachedir)-1] != '\0')
					errx(1, "ccachedir path name too long");
				break;
			default:
				usage(argv[0]);
				break;
		}
	}

	if ((progname = strrchr(argv[0], '/')))
		progname++;
	else
		progname = argv[0];

	initerr(progname, verbosity, fg);

	if (gssd_check_mechs() != 0)
		errx(1, "Problem with gssapi library");

	if (gssd_get_local_realm())
		errx(1, "get local realm");

	if (!fg && daemon(0, 0) < 0)
		errx(1, "fork");

	/* This should be checked _after_ daemon(), because we need to own
	 * the undo-able semaphore by this process
	 */
	gssd_init_unique(GSSD_CLI);

	/* Process keytab file and get machine credentials. This will modify
	 * disk status so do it after we are sure we are the only instance
	 */
	if (gssd_refresh_krb5_machine_creds())
		return -1;

	signal(SIGINT, sig_die);
	signal(SIGTERM, sig_die);
	signal(SIGHUP, sig_hup);

	lgssd_init_mutexs();

	printerr(0, "lgssd initialized and ready to serve\n");
	lgssd_run();

	lgssd_cleanup();
	printerr(0, "lgssd exiting\n");
	return 0;
}
