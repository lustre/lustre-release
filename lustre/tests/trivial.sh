#!/bin/sh
# Simple test of mount and unmount
sh llsetup.sh obdecho.cfg net-local.cfg client-echo.cfg || exit 1
# FIXME: Scan logs for any unusual things (unbalanced allocations, errors)
sh llcleanup.sh obdecho.cfg net-local.cfg client-echo.cfg
OBD_LEAK=`dmesg | awk '/obd memory leaked/ { print $7 }'`
[ "$OBD_LEAK" != "0" ] && echo "OBD memory leak: $OBD_LEAK bytes" && ERR=1
NAL_LEAK=`dmesg | awk '/NAL unloaded/ { print $7 }'
[ "$NAL_LEAK" != "0)" ] && echo "Portals memory leak: $NAL_LEAK" && ERR=1
/sbin/lsmod | grep -q portals && "Portals module still loaded" && ERR=1
exit $ERR
