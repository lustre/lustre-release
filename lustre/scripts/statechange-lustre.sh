#!/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License Version 1.0 (CDDL-1.0).
# You can obtain a copy of the license from the top-level file
# "OPENSOLARIS.LICENSE" or at <http://opensource.org/licenses/CDDL-1.0>.
# You may not use this file except in compliance with the license.
#
# CDDL HEADER END
#

#
# Copyright (c) 2018, Intel Corporation.
#

#
# Adjust lustre service degrade state in response to a statechange
#
# ZEVENT_SUBCLASS: 'statechange'
# POOL HEALTH: status from "zpool list health" (either ONLINE or DEGRADED)
#
# depends on lctl(1)
#
# Exit codes:
#   0: normal exit
#   1: lctl missing
#   2: zpool missing
#   3: zfs missing
#   4: Pool status neither "ONLINE" nor "DEGRADED
#
# This script is also symlinked as vdev_attach-lustre.sh, vdev_remove-lustre.sh
# and vdev_clear-lustre.sh, since it needs to take the same action on those
# ZFS events as well.

[ -f "${ZED_ZEDLET_DIR}/zed.rc" ] && . "${ZED_ZEDLET_DIR}/zed.rc"
. "${ZED_ZEDLET_DIR}/zed-functions.sh"

LCTL=${LCTL:-/usr/sbin/lctl}
ZPOOL=${ZPOOL:-/usr/sbin/zpool}
ZFS=${ZFS:-/usr/sbin/zfs}

zed_check_cmd "$LCTL" || exit 1
zed_check_cmd "$ZPOOL" || exit 2
zed_check_cmd "$ZFS" || exit 3

#
# sync_degrade_state (dataset, state)
#
sync_degrade_state()
{
	local dataset="$1"
	local state="$2"
	local service=$($ZFS list -H -o lustre:svname ${dataset})

	zed_log_msg "Lustre:sync_degrade_state pool:${dataset} degraded:${state}"

	if [ -n "${service}" ] && [ "${service}" != "-" ] ; then
		local current=$($LCTL get_param -n obdfilter.${service}.degraded)

		if [ "${current}" != "${state}" ] ; then
			$LCTL set_param obdfilter.${service}.degraded=${state}
		fi
	fi
}

#
# use pool state as deciding factor
#
POOL_STATE=$($ZPOOL list -H -o health ${ZEVENT_POOL})

if [ "${POOL_STATE}" == "ONLINE" ] ; then
	MODE="0"
elif [ "${POOL_STATE}" == "DEGRADED" ] ; then
	MODE="1"
else
	exit 4
fi

#
# visit target pool's datasets and adjust lustre service degrade mode
#
read -r -a DATASETS <<< \
	$($ZFS get -rH -s local -t filesystem -o name lustre:svname ${ZEVENT_POOL})

for dataset in "${DATASETS[@]}" ; do
	sync_degrade_state "${dataset}" "${MODE}"
done

exit 0
