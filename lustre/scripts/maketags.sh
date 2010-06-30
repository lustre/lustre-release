#!/bin/sh
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
set -vx
rm -f TAGS ; find . -name '*.h' -or -name '*.c' | xargs etags
rm -f ctags; find . -name '*.h' -or -name '*.c' | xargs ctags
