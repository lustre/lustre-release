# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution

include ../Rules.linux

LDFLAGS = -m "`$(LD) --help | awk '/supported emulations/ {print $$4}'`" -r
LINK = $(LD) $(LDFLAGS) -o $@
DEFS =
LIBS =
MODULE = $(basename)
EXTRA_DIST = startserver.sh startclient.sh stopserver.sh stopclient.sh

noinst_PROGRAMS = pingsrv.o pingcli.o spingsrv.o spingcli.o 

pingsrv_o_SOURCES = ping_srv.c ping.h

pingcli_o_SOURCES = ping_cli.c ping.h

spingsrv_o_SOURCES = sping_srv.c ping.h

spingcli_o_SOURCES = sping_cli.c ping.h
