#!/bin/sh
# Simple test of mount and unmount
llsetup.sh obd-echo.cfg net-local.cfg client-echo.cfg || exit 1
# FIXME: Scan logs for any unusual things (unbalanced allocations, errors)
llcleanup obd-echo.cfg net-local.cfg client-echo.cfg
