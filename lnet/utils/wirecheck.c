/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
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

#define BLANK_LINE()                            \
do {                                            \
        printf ("\n");                          \
} while (0)

#define COMMENT(c)                              \
do {                                            \
        printf ("        /* "c" */\n");         \
} while (0)

#define STRINGIFY(a) #a

#define CHECK_DEFINE(a)                                                 \
do {                                                                    \
        printf ("        BUILD_BUG_ON("#a" != "STRINGIFY(a)");\n");     \
} while (0)

#define CHECK_VALUE(a)                                     \
do {                                                       \
        printf ("        BUILD_BUG_ON("#a" != %d);\n", a); \
} while (0)

#define CHECK_MEMBER_OFFSET(s,m)                \
do {                                            \
        CHECK_VALUE((int)offsetof(s, m));       \
} while (0)

#define CHECK_MEMBER_SIZEOF(s,m)                \
do {                                            \
        CHECK_VALUE((int)sizeof(((s *)0)->m));  \
} while (0)

#define CHECK_MEMBER(s,m)                       \
do {                                            \
        CHECK_MEMBER_OFFSET(s, m);              \
        CHECK_MEMBER_SIZEOF(s, m);              \
} while (0)

#define CHECK_STRUCT(s)                         \
do {                                            \
        BLANK_LINE ();                          \
        COMMENT ("Checks for struct "#s);       \
        CHECK_VALUE((int)sizeof(s));            \
} while (0)

void
check_lnet_handle_wire(void)
{
	CHECK_STRUCT(struct lnet_handle_wire);
	CHECK_MEMBER(struct lnet_handle_wire, wh_interface_cookie);
	CHECK_MEMBER(struct lnet_handle_wire, wh_object_cookie);
}

void
check_lnet_magicversion (void)
{
	CHECK_STRUCT(struct lnet_magicversion);
	CHECK_MEMBER(struct lnet_magicversion, magic);
	CHECK_MEMBER(struct lnet_magicversion, version_major);
	CHECK_MEMBER(struct lnet_magicversion, version_minor);
}

void
check_lnet_hdr (void)
{
	CHECK_STRUCT(struct lnet_hdr);
	CHECK_MEMBER(struct lnet_hdr, dest_nid);
	CHECK_MEMBER(struct lnet_hdr, src_nid);
	CHECK_MEMBER(struct lnet_hdr, dest_pid);
	CHECK_MEMBER(struct lnet_hdr, src_pid);
	CHECK_MEMBER(struct lnet_hdr, type);
	CHECK_MEMBER(struct lnet_hdr, payload_length);
	CHECK_MEMBER(struct lnet_hdr, msg);

        BLANK_LINE ();
        COMMENT ("Ack");
	CHECK_MEMBER(struct lnet_hdr, msg.ack.dst_wmd);
	CHECK_MEMBER(struct lnet_hdr, msg.ack.match_bits);
	CHECK_MEMBER(struct lnet_hdr, msg.ack.mlength);

        BLANK_LINE ();
        COMMENT ("Put");
	CHECK_MEMBER(struct lnet_hdr, msg.put.ack_wmd);
	CHECK_MEMBER(struct lnet_hdr, msg.put.match_bits);
	CHECK_MEMBER(struct lnet_hdr, msg.put.hdr_data);
	CHECK_MEMBER(struct lnet_hdr, msg.put.ptl_index);
	CHECK_MEMBER(struct lnet_hdr, msg.put.offset);

        BLANK_LINE ();
        COMMENT ("Get");
	CHECK_MEMBER(struct lnet_hdr, msg.get.return_wmd);
	CHECK_MEMBER(struct lnet_hdr, msg.get.match_bits);
	CHECK_MEMBER(struct lnet_hdr, msg.get.ptl_index);
	CHECK_MEMBER(struct lnet_hdr, msg.get.src_offset);
	CHECK_MEMBER(struct lnet_hdr, msg.get.sink_length);

        BLANK_LINE ();
        COMMENT ("Reply");
	CHECK_MEMBER(struct lnet_hdr, msg.reply.dst_wmd);

        BLANK_LINE ();
        COMMENT ("Hello");
	CHECK_MEMBER(struct lnet_hdr, msg.hello.incarnation);
	CHECK_MEMBER(struct lnet_hdr, msg.hello.type);
}

void
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
	CHECK_MEMBER(struct lnet_ni_status, ns_unused);
}

void
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
	CHECK_VALUE(LNET_PING_FEAT_BITS);

	CHECK_STRUCT(struct lnet_ping_info);
	CHECK_MEMBER(struct lnet_ping_info, pi_magic);
	CHECK_MEMBER(struct lnet_ping_info, pi_features);
	CHECK_MEMBER(struct lnet_ping_info, pi_pid);
	CHECK_MEMBER(struct lnet_ping_info, pi_nnis);
	CHECK_MEMBER(struct lnet_ping_info, pi_ni);
}

void
system_string(char *cmdline, char *str, int len)
{
        int   fds[2];
        int   rc;
        pid_t pid;

        rc = pipe (fds);
        if (rc != 0)
                abort ();

        pid = fork ();
        if (pid == 0) {
                /* child */
                int   fd = fileno(stdout);

                rc = dup2(fds[1], fd);
                if (rc != fd)
                        abort();

                exit(system(cmdline));
                /* notreached */
        } else if ((int)pid < 0) {
                abort();
        } else {
                FILE *f = fdopen (fds[0], "r");

                if (f == NULL)
                        abort();

                close(fds[1]);

                if (fgets(str, len, f) == NULL)
                        abort();

                if (waitpid(pid, &rc, 0) != pid)
                        abort();

                if (!WIFEXITED(rc) ||
                    WEXITSTATUS(rc) != 0)
                        abort();

                if (strnlen(str, len) == len)
                        str[len - 1] = 0;

                if (str[strlen(str) - 1] == '\n')
                        str[strlen(str) - 1] = 0;

                fclose(f);
        }
}

int
main (int argc, char **argv)
{
        char unameinfo[256];
        char gccinfo[256];

        system_string("uname -a", unameinfo, sizeof(unameinfo));
        system_string("gcc -v 2>&1 | tail -1", gccinfo, sizeof(gccinfo));

        printf ("void lnet_assert_wire_constants (void)\n"
                "{\n"
                "        /* Wire protocol assertions generated by 'wirecheck'\n"
                "         * running on %s\n"
                "         * with %s */\n"
                "\n", unameinfo, gccinfo);

        BLANK_LINE ();

        COMMENT ("Constants...");

        CHECK_DEFINE (LNET_PROTO_RA_MAGIC);

        CHECK_DEFINE (LNET_PROTO_TCP_MAGIC);
        CHECK_DEFINE (LNET_PROTO_TCP_VERSION_MAJOR);
        CHECK_DEFINE (LNET_PROTO_TCP_VERSION_MINOR);

        CHECK_VALUE (LNET_MSG_ACK);
        CHECK_VALUE (LNET_MSG_PUT);
        CHECK_VALUE (LNET_MSG_GET);
        CHECK_VALUE (LNET_MSG_REPLY);
        CHECK_VALUE (LNET_MSG_HELLO);

	check_lnet_handle_wire();
	check_lnet_magicversion();
	check_lnet_hdr();
	check_lnet_ni_status();
	check_lnet_ping_info();

        printf ("}\n\n");

        return (0);
}
