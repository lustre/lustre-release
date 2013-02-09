#!/bin/sh

# NOTE: Please avoid bashisms (bash specific syntax) in this script

# install Lustre Git commit hooks by default - LU-2083
for HOOK in commit-msg prepare-commit-msg; do
	if [ -d .git/hooks -a ! -e .git/hooks/$HOOK ]; then
		ln -sf ../../build/$HOOK .git/hooks/
	fi
done

echo "Checking for a complete tree..."
REQUIRED_DIRS="libcfs lnet lustre"
OPTIONAL_DIRS="snmp portals"
CONFIGURE_DIRS="libsysio lustre-iokit ldiskfs"

for dir in $REQUIRED_DIRS ; do
	if [ ! -d "$dir" ] ; then
		cat >&2 <<EOF
Your tree seems to be missing $dir.
Please read README.lustrecvs for details.
EOF
		exit 1
	fi
	ACLOCAL_FLAGS="$ACLOCAL_FLAGS -I $PWD/$dir/autoconf"
done
# optional directories for Lustre
for dir in $OPTIONAL_DIRS; do
	if [ -d "$dir" ] ; then
		ACLOCAL_FLAGS="$ACLOCAL_FLAGS -I $PWD/$dir/autoconf"
	fi
done

run_cmd()
{
	cmd="$@"
	echo -n "Running $cmd"
	eval $cmd
	res=$?
	if [ $res -ne 0 ]; then
		echo " failed: $res"
		echo "Aborting"
		exit 1
	fi
	echo
}

run_cmd "aclocal -I $PWD/config $ACLOCAL_FLAGS"
run_cmd "autoheader"
run_cmd "automake -a -c"
run_cmd autoconf

# Run autogen.sh in these directories
PWD_SAVE=$PWD
for dir in $CONFIGURE_DIRS; do
	if [ -d $dir ] ; then
		cd $dir
		echo "Running autogen for $dir..."
		run_cmd "sh autogen.sh"
	fi
	cd $PWD_SAVE
done
