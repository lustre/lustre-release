#!/bin/bash
trap 'kill $(jobs -p)' EXIT
RACER_ENABLE_DOM=${RACER_ENABLE_DOM:-false}
DIR=$1
MAX=$2
MAX_MB=${RACER_MAX_MB:-8}

. $LUSTRE/tests/test-framework.sh

OSTCOUNT=${OSTCOUNT:-$($LFS df $DIR 2> /dev/null | grep -c OST)}

layout=(raid0 raid0)

# check if it supports PFL layout
[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.10.0) ]] &&
	layout+=(pfl pfl pfl)

# check if it supports DoM
if $RACER_ENABLE_DOM ; then
	[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.10.53) ]] &&
		layout+=(dom dom dom)
fi

[[ $(lustre_version_code $SINGLEMDS) -ge $(version_code 2.10.55) ]] &&
	layout+=(flr flr flr)

echo "layout: ${layout[*]}"

while /bin/true; do
	file=$((RANDOM % MAX))
	# $RANDOM is between 0 and 32767, and we want $blockcount in 64kB units
	blockcount=$((RANDOM * MAX_MB / 32 / 64))
	stripecount=$((RANDOM % (OSTCOUNT + 1)))

	[ $stripecount -gt 0 ] && {
		stripesize=$(((RANDOM % 16 + 1) * 64))K
		pattern=${layout[$RANDOM % ${#layout[*]}]}

		case $pattern in
		dom) opt="setstripe -E $stripesize -L mdt -E eof -c $stripecount -S 1M" ;;
		pfl) opt="setstripe -E 1M -S $stripesize -E eof -c $stripecount -S 2M" ;;
		flr) opt="mirror create -N2 -E 1M -S $stripesize -E eof -c $stripecount -S 2M" ;;
		raid0) opt="setstripe -S $stripesize -c $stripecount" ;;
		esac

		$LFS $opt $DIR/$file 2> /dev/null || true
	}

	# offset between 0 and 16MB (256 64k chunks), with 1/2 at offset 0
	seek=$((RANDOM / 64)); [ $seek -gt 256 ] && seek=0
	dd if=/dev/zero of=$DIR/$file bs=64k count=$blockcount \
		seek=$seek 2> /dev/null || true
done

