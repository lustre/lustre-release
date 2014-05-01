#!/bin/sh

# NOTE: Please avoid bashisms (bash specific syntax) in this script

# die a horrible death.  All output goes to stderr.
#
die()
{
	echo "bootstrap failure:  $*"
	echo Aborting
	exit 1
} 1>&2

run_cmd()
{
	echo -n "Running $*"
	eval "$@" || die "command exited with code $?"
	echo
}

echo "Checking for a complete tree..."
REQUIRED_DIRS="libcfs lnet lustre"
OPTIONAL_DIRS="snmp portals"
CONFIGURE_DIRS="libsysio"

for dir in $REQUIRED_DIRS ; do
	test -d "$dir" || \
		die "Your tree seems to be missing $dir.
Please read README.lustrecvs for details."

	ACLOCAL_FLAGS="$ACLOCAL_FLAGS -I $PWD/$dir/autoconf"
done
# optional directories for Lustre
for dir in $OPTIONAL_DIRS; do
	if [ -d "$dir" ] ; then
		ACLOCAL_FLAGS="$ACLOCAL_FLAGS -I $PWD/$dir/autoconf"
	fi
done

PWD_SAVE=$PWD

run_cmd "libtoolize -q"
run_cmd "aclocal -I $PWD/config $ACLOCAL_FLAGS"
run_cmd "autoheader"
run_cmd "automake -a -c"
run_cmd autoconf

# bootstrap in these directories
for dir in $CONFIGURE_DIRS; do
	if [ -d $dir ] ; then
		cd $dir
		echo "bootstrapping in $dir..."
		run_cmd "sh autogen.sh"
	fi
	cd $PWD_SAVE
done
