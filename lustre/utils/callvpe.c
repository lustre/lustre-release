/*
 * LGPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 * LGPL HEADER END
 *
 * Copyright (c) 2018, Intel Corporation.
 */

#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "callvpe.h"

/**
 * callvpe() - execute a file with given arguments and environment.
 * \param file[in] name or path of file to be executed.
 * \param args[in] arguments to file.
 * \param envp[in] execution environment.
 * \return -1 on failure (for example if fork() failed).
 * \return process return status on success.
 *
 * callvpe() is intended as a safer replacement for system(). It
 * executes the file specified and returns after it has completed. As
 * with system during execution of the command, SIGCHLD will be
 * blocked, and SIGINT and SIGQUIT will be ignored. The main
 * difference between system(cmd) and callvpe(file, args, envp) is
 * that system() calls exec("/bin/sh" "-c" "cmd") whereas callvpe()
 * bypasses the shell and passes the args given directly to execvpe().
 *
 * Rather than:
 *
 *      snprintf(cmd, sizeof(cmd), "rm -rf %s\n", path);
 *      rc = system(cmd);
 *
 * instead use:
 *
 *      char *args[] = { "rm", "-rf", "--", path, NULL };
 *      extern char **environ;
 *      rc = callvpe("/bin/rm", args, environ);
 *
 * Note that since callvpe() does not use the shell, IO redirection
 * and pipelines (cmd > /dev/null, cmd 2>&1, cmd1 | cmd2, ...) are not
 * supported.
 */
int callvpe(const char *file, char *const args[], char *const envp[])
{
	struct sigaction sa = {
		.sa_handler = SIG_IGN,
	};
	struct sigaction sa_int_saved;
	struct sigaction sa_quit_saved;
	sigset_t sigset_saved;
	pid_t pid;
	pid_t pid2;
	int status;
	int rc;

	sigemptyset(&sa.sa_mask);

	rc = sigaction(SIGINT, &sa, &sa_int_saved);
	if (rc < 0)
		return rc;

	rc = sigaction(SIGQUIT, &sa, &sa_quit_saved);
	if (rc < 0)
		goto out_sa_int;

	sigaddset(&sa.sa_mask, SIGCHLD);
	rc = sigprocmask(SIG_BLOCK, &sa.sa_mask, &sigset_saved);
	if (rc < 0)
		goto out_sa_quit;

	pid = fork();
	if (pid < 0) {
		rc = -1;
		goto out_sigset;
	}

	if (pid == 0) {
		execvpe(file, args, envp);
		_exit(127);
	}

	pid2 = waitpid(pid, &status, 0);
	if (pid2 < 0) {
		rc = -1;
		goto out_sigset;
	}

	rc = status;

out_sigset:
	sigprocmask(SIG_SETMASK, &sigset_saved, NULL);
out_sa_quit:
	sigaction(SIGQUIT, &sa_quit_saved, NULL);
out_sa_int:
	sigaction(SIGINT, &sa_int_saved, NULL);

	return rc;
}
