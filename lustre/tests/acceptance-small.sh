#!/bin/sh
# script which _must_ complete successfully (at minimum) before checkins to
# the CVS HEAD are allowed.
set -vxe
sh local.sh
sh runtests --reformat local.xml

sh lov.sh
sh runtests --reformat lov.xml

export NAME=local
sh llmount.sh
sh sanity
sh rundbench 1
sh llmountcleanup.sh

export NAME=lov
llmount.sh
sh sanity
sh rundbench 1
sh llmountcleanup.sh
