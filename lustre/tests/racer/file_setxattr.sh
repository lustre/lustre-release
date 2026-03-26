#!/usr/bin/bash
trap 'kill $(jobs -p)' EXIT

DIR=$1
MAX=$2

LFS_BIN=${LFS:-lfs}
# 1-in-N chance per iteration of also exercising lfs pool pin/unpin,
# so it fires less often than the plain user.* setxattr racing above.
RACER_PIN_FREQ=${RACER_PIN_FREQ:-10}

# Try to pick a real pool name from this filesystem, so we exercise a
# meaningful lfs pool pin/unpin path. If no pools are defined (or lfs is
# unavailable), fall back to generic user.* xattrs only.
PIN_POOL=""
have_lfs_pin=false
if (( "$UID" == 0 )) && command -v "$LFS_BIN" >/dev/null 2>&1; then
	PIN_POOL=$("$LFS_BIN" pool_list "$DIR" 2>/dev/null |
		grep -v "[Pp]ools from" | head -n1 | cut -d. -f2)
	if [[ -n "$PIN_POOL" ]] &&
		"$LFS_BIN" help pool 2>&1 | grep -q ' pool pin '; then
		have_lfs_pin=true
	fi
fi

while true; do
	file=$DIR/$((RANDOM % MAX))

	# Original behaviour: random user.* xattrs, every iteration.
	attr=user.$((RANDOM % MAX))
	value=$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM$RANDOM
	setfattr -n "$attr" -v "$value" "$file" 2> /dev/null

	if $have_lfs_pin && (( RANDOM % RACER_PIN_FREQ == 0 )); then
		# Randomly pin or unpin (rather than always both) so some
		# files are left pinned, for other racer scripts (e.g.
		# file_create.sh's lfs migrate) to occasionally exercise the
		# pinned code path, and so unpin sometimes hits a file that
		# isn't currently pinned.
		subcmd=pin
		(( RANDOM % 2 == 0 )) || subcmd=unpin
		"$LFS_BIN" pool $subcmd --pool "$PIN_POOL" \
			"$file" 2> /dev/null
	fi
done
