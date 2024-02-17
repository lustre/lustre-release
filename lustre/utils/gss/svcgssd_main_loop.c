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
#include <sys/un.h>
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
#include <sys/mman.h>

#include "cacheio.h"
#include "svcgssd.h"
#include "lsupport.h"
#include "err_util.h"
#include "sk_utils.h"

/* max allowed time for prime testing: 400 ms */
#define MAX_ALLOWED_TIME_FOR_PRIME 400000
int *sk_dh_checks;

void svcgssd_run(void)
{
	int local_socket = -1, remote_socket;
	struct sockaddr_un addr;
	bool retried = false;
#if !defined(HAVE_OPENSSL_EVP_PKEY) && OPENSSL_VERSION_NUMBER >= 0x1010103fL
	pid_t child = 1;
#endif
	int ret = EXIT_SUCCESS;

	if (sk_enabled) {
		sk_dh_checks = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE,
				    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (sk_dh_checks == MAP_FAILED) {
			printerr(LL_ERR,
			       "cannot mmap memory for sk_dh_checks: %s\n",
			       strerror(errno));
			ret = EXIT_FAILURE;
			goto out_close;
		}

#if !defined(HAVE_OPENSSL_EVP_PKEY) && OPENSSL_VERSION_NUMBER >= 0x1010103fL
		/* child will run asynchronously, parent will not wait for it */
		*sk_dh_checks =
			sk_speedtest_dh_valid(MAX_ALLOWED_TIME_FOR_PRIME,
					      &child);
		if (*sk_dh_checks)
			printerr(LL_WARN,
				 "will use %d rounds for prime testing\n",
				 *sk_dh_checks);
		else
			printerr(LL_WARN,
				 "will use default number of rounds for prime testing\n");
		if (child == 0)
			/* job done for child */
			exit(EXIT_SUCCESS);
#else
		*sk_dh_checks = 0;
		printerr(LL_WARN,
			 "will use default number of rounds for prime testing\n");
#endif
	} else {
		/* For krb, preload mapping table if any */
		load_mapping();
	}

again:
	local_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (local_socket == -1) {
		printerr(LL_ERR, "unable to create socket: %d\n", -errno);
		ret = EXIT_FAILURE;
		goto out_close;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, GSS_SOCKET_PATH, sizeof(addr.sun_path) - 1);

	if (bind(local_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		if (!retried) {
			retried = true;
			unlink(GSS_SOCKET_PATH);
			close(local_socket);
			goto again;
		}
		printerr(LL_ERR, "unable to bind socket: %d\n", -errno);
		ret = EXIT_FAILURE;
		goto out_close;
	}

	if (listen(local_socket, 10) == -1) {
		printerr(LL_ERR, "unable to listen on socket: %d\n", -errno);
		ret = EXIT_FAILURE;
		goto out;
	}

	while (1) {
		remote_socket = accept(local_socket, NULL, NULL);
		if (remote_socket == -1) {
			printerr(LL_TRACE, "accept on socket ret %d\n", -errno);
			continue;
		}

		ret = handle_channel_request(remote_socket);
		printerr(LL_DEBUG, "handle_channel_request ret %d\n", ret);
		close(remote_socket);
	}

out:
	unlink(GSS_SOCKET_PATH);
out_close:
	if (local_socket >= 0)
		close(local_socket);
	if (munmap(sk_dh_checks, sizeof(int)) == -1) {
		printerr(LL_ERR, "cannot munmap memory for sk_dh_checks: %s\n",
			 strerror(errno));
		ret = EXIT_FAILURE;
	}
	exit(ret);
}
