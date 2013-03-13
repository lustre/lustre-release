#!/bin/sh

# Run this script after a package install and pre uninstall
usage()
{
	echo "Usage: $0 <root_dir> <create|remove>"
	exit 1
}

if [ $# -ne 2 ]; then usage; fi
if [ !  -d $1 ]; then usage; fi

NAME=$(basename "$0" .sh)
ROOT_DIR="$1"
FILELIST="$(dirname $ROOT_DIR)/$NAME.filelist"
case "$2" in
create)
	EXCLUDE="\(share\|include\|src\)"

	# Create filelist for Intel(R) Xeon Phi(TM) infrastructure
	for i in $(rpm -ql $NAME | grep $ROOT_DIR | grep -v $EXCLUDE); do
		find $ROOT_DIR -path $i -type f -printf "file /%P $(basename $ROOT_DIR)/%P %#m 0 0\n"
		dir=$(dirname $i)
		while [ "$dir" != "$ROOT_DIR" ]; do
			echo "dir $dir 0755 0 0" | sed -e "s#$ROOT_DIR##"
			dir=$(dirname $dir)
		done
		# Link scripts for autorun after boot (NOT READY YET)
		#if [ -n "$(echo $i | grep '/init.d/')" ]; then
		#	echo "slink /etc/rc3.d/S31$(basename $i) ../init.d/$(basename $i) 0755 0 0"
		#fi
	done | sort -u > $FILELIST

	mkdir -p /etc/sysconfig/mic/conf.d
	echo "Overlay $(dirname $ROOT_DIR) $FILELIST" > /etc/sysconfig/mic/conf.d/$NAME.conf
	;;
remove)
	rm -f $FILELIST
	rm -f /etc/sysconfig/mic/conf.d/$NAME.conf
	;;
*)
	usage
	;;
esac
exit 0
