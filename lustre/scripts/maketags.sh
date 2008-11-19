#!/bin/sh
# Copyright 2008 Sun Microsystems, Inc.
#
# This code is issued under the GNU General Public License.
# See the file COPYING in this distribution
set -vx
rm -f TAGS ; find . -name '*.h' -or -name '*.c' | xargs etags
rm -f ctags; find . -name '*.h' -or -name '*.c' | xargs ctags
