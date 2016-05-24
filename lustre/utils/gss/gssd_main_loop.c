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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
/* For time() */
#include <time.h>
/* For waitpid() */
#include <wait.h>

#include "gssd.h"
#include "err_util.h"

extern struct pollfd *pollarray;
extern int pollsize;

#define POLL_MILLISECS	500

static volatile int dir_changed = 1;

static void dir_notify_handler(int sig, siginfo_t *si, void *data)
{
	dir_changed = 1;
}

static void
scan_poll_results(int ret)
{
	int			i;
	struct clnt_info	*clp;

	for (clp = clnt_list.tqh_first; clp != NULL; clp = clp->list.tqe_next)
	{
		i = clp->krb5_poll_index;
		if (i >= 0 && pollarray[i].revents) {
			if (pollarray[i].revents & POLLHUP)
				dir_changed = 1;
			if (pollarray[i].revents & POLLIN)
				handle_krb5_upcall(clp);
			pollarray[clp->krb5_poll_index].revents = 0;
			ret--;
			if (!ret)
				break;
		}
		i = clp->spkm3_poll_index;
		if (i >= 0 && pollarray[i].revents) {
			if (pollarray[i].revents & POLLHUP)
				dir_changed = 1;
			pollarray[clp->spkm3_poll_index].revents = 0;
			ret--;
			if (!ret)
				break;
		}
	}
};

void
lgssd_run()
{
	int			ret;
	struct sigaction	dn_act;
	int			fd;
	time_t			child_check = 0;
	pid_t			child_pid;

	/* Taken from linux/Documentation/dnotify.txt: */
	dn_act.sa_sigaction = dir_notify_handler;
	sigemptyset(&dn_act.sa_mask);
	dn_act.sa_flags = SA_SIGINFO;
	sigaction(DNOTIFY_SIGNAL, &dn_act, NULL);

	if ((fd = open(pipefs_dir, O_RDONLY)) == -1) {
		printerr(0, "ERROR: failed to open %s: %s\n",
			 pipefs_dir, strerror(errno));
		return;
	}
	fcntl(fd, F_SETSIG, DNOTIFY_SIGNAL);
	fcntl(fd, F_NOTIFY, DN_CREATE|DN_DELETE|DN_MODIFY|DN_MULTISHOT);

	init_client_list();

	while (1) {
		while (dir_changed) {
			dir_changed = 0;
			printerr(2, "pipefs root dir changed\n");
			if (update_client_list()) {
				printerr(0, "ERROR: couldn't update "
					 "client list\n");
				goto out;
			}
		}

		/* every 5s cleanup possible zombies of child processes */
		if (time(NULL) - child_check >= 5) {
			printerr(3, "check zombie children...\n");

			while (1) {
				child_pid = waitpid(-1, NULL, WNOHANG);
				if (child_pid <= 0)
					break;

				printerr(2, "terminate zombie child: %d\n",
					 child_pid);
			}

			child_check = time(NULL);
		}

		/* race condition here: dir_changed could be set before we
		 * enter the poll, and we'd never notice if it weren't for the
		 * timeout. */
		ret = poll(pollarray, pollsize, POLL_MILLISECS);
		if (ret < 0) {
			if (errno != EINTR)
				printerr(0,
					 "WARNING: error return from poll\n");
		} else if (ret == 0) {
			/* timeout */
		} else { /* ret > 0 */
			scan_poll_results(ret);
		}
	}
out:
	close(fd);
	return;
}
