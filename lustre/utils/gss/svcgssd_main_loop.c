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

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
/* For nanosleep() */
#include <time.h>

#include "svcgssd.h"
#include "err_util.h"

#define GSS_RPC_FILE "/proc/net/rpc/auth.sptlrpc.init/channel"

/*
 * nfs4 in-kernel cache implementation make upcall failed directly
 * if there's no listener detected. so here we should keep the init
 * channel file open as possible as we can.
 *
 * unfortunately the proc doesn't support dir change notification.
 * and when an entry get unlinked, we only got POLLIN event once,
 * it's the only oppotunity we can close the file and startover.
 */
void
svcgssd_run()
{
	static const char gss_rpc_channel_path[] =
		"/proc/net/rpc/auth.sptlrpc.init/channel";
	int			ret;
	FILE			*f = NULL;
	struct pollfd		pollfd;
	struct timespec		halfsec = { .tv_sec = 0, .tv_nsec = 500000000 };

	while (1) {
		int save_err;

		while (f == NULL) {
			f = fopen(gss_rpc_channel_path, "rw");
			if (f == NULL) {
				printerr(4, "failed to open %s: %s\n",
					 gss_rpc_channel_path, strerror(errno));
				nanosleep(&halfsec, NULL);
			} else {
				printerr(1, "successfully open %s\n",
					 gss_rpc_channel_path);
				break;
			}
		}
		pollfd.fd = fileno(f);
		pollfd.events = POLLIN;

		pollfd.revents = 0;
		ret = poll(&pollfd, 1, 1000);
		save_err = errno;

		if (ret < 0) {
			printerr(0, "error return from poll: %s\n",
				 strerror(save_err));
			fclose(f);
			f = NULL;
		} else if (ret == 0) {
			printerr(4, "poll timeout\n");
		} else {
			if (ret != 1) {
				printerr(0, "bug: unexpected poll return %d\n",
						ret);
				exit(1);
			}
			if (pollfd.revents & POLLIN) {
				if (handle_channel_request(f) < 0) {
					fclose(f);
					f = NULL;
				}
			}
		}
	}
}
