#!/bin/sh
set -vx
JSIZE=32 ISIZE=256 sh `dirname $0`/local.sh local-large-inode.xml
