#!/bin/sh
# Copyright (C) 2001  Cluster File Systems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
set -vx
rm -f TAGS ; find . -name '*.h' -or -name '*.c' | xargs etags
rm -f ctags; find . -name '*.h' -or -name '*.c' | xargs ctags
