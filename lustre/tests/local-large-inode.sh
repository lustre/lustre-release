#!/bin/sh
#set -vx
JSIZE=32 MDSISIZE=256 sh `dirname $0`/local.sh `basename $0 .sh`.xml
