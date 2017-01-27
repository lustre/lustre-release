// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2014, Intel Corporation.
 */

/*
 * This file is part of Lustre, http://www.lustre.org/
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/lnet/lnet-types.h>

#ifndef HAVE_STRNLEN
#define strnlen(s, i) strlen(s)
#endif

#define BLANK_LINE() printf("\n")

#define COMMENT(c) printf("        /* "c" */\n")

#define STRINGIFY(a) #a

#define CHECK_BUILD_TEST(a) printf("	BUILD_BUG_ON("#a");\n")

#define CHECK_DEFINE(a)							\
	printf("        BUILD_BUG_ON("#a" != "STRINGIFY(a)");\n")

#define CHECK_VALUE(a)							\
	printf("        BUILD_BUG_ON("#a" != %d);\n", a)

#define CHECK_MEMBER_OFFSET(s, m) CHECK_VALUE((int)offsetof(s, m))

#define CHECK_MEMBER_SIZEOF(s, m) CHECK_VALUE((int)sizeof(((s *)0)->m))

#define CHECK_MEMBER_IS_FLEXIBLE(s, m)					\
do {									\
	CHECK_MEMBER_OFFSET(s, m);					\
	CHECK_BUILD_TEST(offsetof(struct s, m) != sizeof(struct s));	\
} while (0)

#define CHECK_MEMBER(s, m)						\
do {									\
	CHECK_MEMBER_OFFSET(s, m);					\
	CHECK_MEMBER_SIZEOF(s, m);					\
} while (0)

#define CHECK_STRUCT(s)							\
do {									\
	BLANK_LINE();							\
	COMMENT("Checks for "#s);					\
	CHECK_VALUE((int)sizeof(s));					\
} while (0)

static void
check_lnet_handle_wire(void)
{
	CHECK_STRUCT(struct lnet_handle_wire);
	CHECK_MEMBER(struct lnet_handle_wire, wh_interface_cookie);
	CHECK_MEMBER(struct lnet_handle_wire, wh_object_cookie);
}

static void
check_lnet_magicversion(void)
{
	CHECK_STRUCT(struct lnet_magicversion);
	CHECK_MEMBER(struct lnet_magicversion, magic);
	CHECK_MEMBER(struct lnet_magicversion, version_major);
	CHECK_MEMBER(struct lnet_magicversion, version_minor);
}

static void
check_lnet_hdr_nid4(void)
{
	CHECK_STRUCT(struct _lnet_hdr_nid4);
	CHECK_MEMBER(struct _lnet_hdr_nid4, dest_nid);
	CHECK_MEMBER(struct _lnet_hdr_nid4, src_nid);
	CHECK_MEMBER(struct _lnet_hdr_nid4, dest_pid);
	CHECK_MEMBER(struct _lnet_hdr_nid4, src_pid);
	CHECK_MEMBER(struct _lnet_hdr_nid4, type);
	CHECK_MEMBER(struct _lnet_hdr_nid4, payload_length);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg);

	BLANK_LINE();
	COMMENT("Ack");
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.ack.dst_wmd);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.ack.match_bits);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.ack.mlength);

	BLANK_LINE();
	COMMENT("Put");
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.put.ack_wmd);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.put.match_bits);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.put.hdr_data);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.put.ptl_index);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.put.offset);

	BLANK_LINE();
	COMMENT("Get");
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.get.return_wmd);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.get.match_bits);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.get.ptl_index);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.get.src_offset);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.get.sink_length);

	BLANK_LINE();
	COMMENT("Reply");
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.reply.dst_wmd);

	BLANK_LINE();
	COMMENT("Hello");
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.hello.incarnation);
	CHECK_MEMBER(struct _lnet_hdr_nid4, msg.hello.type);
}

static void
check_lnet_ni_status(void)
{
	BLANK_LINE();
	COMMENT("Checks for struct lnet_ni_status and related constants");

	CHECK_DEFINE(LNET_NI_STATUS_INVALID);
	CHECK_DEFINE(LNET_NI_STATUS_UP);
	CHECK_DEFINE(LNET_NI_STATUS_DOWN);

	CHECK_STRUCT(struct lnet_ni_status);
	CHECK_MEMBER(struct lnet_ni_status, ns_nid);
	CHECK_MEMBER(struct lnet_ni_status, ns_status);
	CHECK_MEMBER(struct lnet_ni_status, ns_msg_size);

	CHECK_STRUCT(struct lnet_ni_large_status);
	CHECK_MEMBER(struct lnet_ni_large_status, ns_status);
	CHECK_MEMBER(struct lnet_ni_large_status, ns_nid);
}

static void
check_lnet_ping_info(void)
{
	BLANK_LINE();
	COMMENT("Checks for struct lnet_ping_info and related constants");

	CHECK_DEFINE(LNET_PROTO_PING_MAGIC);
	CHECK_VALUE(LNET_PING_FEAT_INVAL);
	CHECK_VALUE(LNET_PING_FEAT_BASE);
	CHECK_VALUE(LNET_PING_FEAT_NI_STATUS);
	CHECK_VALUE(LNET_PING_FEAT_RTE_DISABLED);
	CHECK_VALUE(LNET_PING_FEAT_MULTI_RAIL);
	CHECK_VALUE(LNET_PING_FEAT_DISCOVERY);
	CHECK_VALUE(LNET_PING_FEAT_LARGE_ADDR);
	CHECK_VALUE(LNET_PING_FEAT_PRIMARY_LARGE);
	CHECK_VALUE(LNET_PING_FEAT_BITS);

	CHECK_STRUCT(struct lnet_ping_info);
	CHECK_MEMBER(struct lnet_ping_info, pi_magic);
	CHECK_MEMBER(struct lnet_ping_info, pi_features);
	CHECK_MEMBER(struct lnet_ping_info, pi_pid);
	CHECK_MEMBER(struct lnet_ping_info, pi_nnis);
	CHECK_MEMBER_IS_FLEXIBLE(struct lnet_ping_info, pi_ni);
}

static void
system_string(char *cmdline, char *str, int len)
{
	int fds[2];
	int rc;
	pid_t pid;

	rc = pipe(fds);
	if (rc != 0)
		abort();

	pid = fork();
	if (pid == 0) {
		/* child */
		int fd = fileno(stdout);

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
	char unameinfo[256];
	char gccinfo[256];

	system_string("uname -a", unameinfo, sizeof(unameinfo));
	system_string("gcc -v 2>&1 | tail -1", gccinfo, sizeof(gccinfo));

	printf("void lnet_assert_wire_constants (void)\n"
	       "{\n"
	       "        /* Wire protocol assertions generated by 'wirecheck'\n"
	       "         * running on %s\n"
	       "         * with %s */\n"
	       "\n", unameinfo, gccinfo);

	BLANK_LINE();

	COMMENT("Constants...");

	CHECK_DEFINE(LNET_PROTO_RA_MAGIC);

	CHECK_DEFINE(LNET_PROTO_TCP_MAGIC);
	CHECK_DEFINE(LNET_PROTO_TCP_VERSION_MAJOR);
	CHECK_DEFINE(LNET_PROTO_TCP_VERSION_MINOR);

	CHECK_VALUE(LNET_MSG_ACK);
	CHECK_VALUE(LNET_MSG_PUT);
	CHECK_VALUE(LNET_MSG_GET);
	CHECK_VALUE(LNET_MSG_REPLY);
	CHECK_VALUE(LNET_MSG_HELLO);

	check_lnet_handle_wire();
	check_lnet_magicversion();
	check_lnet_hdr_nid4();
	check_lnet_ni_status();
	check_lnet_ping_info();

	printf("}\n\n");

	return 0;
}
