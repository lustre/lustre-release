#!/bin/bash

# taken from gnome-common/macros2/autogen.sh
compare_versions() {
    ch_min_version=$1
    ch_actual_version=$2
    ch_status=0
    IFS="${IFS=         }"; ch_save_IFS="$IFS"; IFS="."
    set $ch_actual_version
    for ch_min in $ch_min_version; do
        ch_cur=`echo $1 | sed 's/[^0-9].*$//'`; shift # remove letter suffixes
        if [ -z "$ch_min" ]; then break; fi
        if [ -z "$ch_cur" ]; then ch_status=1; break; fi
        if [ $ch_cur -gt $ch_min ]; then break; fi
        if [ $ch_cur -lt $ch_min ]; then ch_status=1; break; fi
    done
    IFS="$ch_save_IFS"
    return $ch_status
}

error_msg() {
	echo "$cmd is $1.  version $required is required to build Lustre."

	if [ -e /usr/lib/autolustre/bin/$cmd ]; then
		cat >&2 <<-EOF
		You apparently already have Lustre-specific autoconf/make RPMs
		installed on your system at /usr/lib/autolustre/share/$cmd.
		Please set your PATH to point to those versions:

		export PATH="/usr/lib/autolustre/bin:\$PATH"
		EOF
	else
		cat >&2 <<-EOF
		CFS provides RPMs which can be installed alongside your
		existing autoconf/make RPMs, if you are nervous about
		upgrading.  See

		http://downloads.lustre.org/public/tools/autolustre/README.autolustre

		You may be able to download newer version from:

		http://ftp.gnu.org/gnu/$tool/$tool-$required.tar.gz
	EOF
	fi
	[ "$cmd" = "autoconf" -a "$required" = "2.57" ] && cat >&2 <<EOF

or for RH9 systems you can use:

ftp://fr2.rpmfind.net/linux/redhat/9/en/os/i386/RedHat/RPMS/autoconf-2.57-3.noarch.rpm
EOF
	[ "$cmd" = "automake-1.7" -a "$required" = "1.7.8" ] && cat >&2 <<EOF

or for RH9 systems you can use:

ftp://fr2.rpmfind.net/linux/fedora/core/1/i386/os/Fedora/RPMS/automake-1.7.8-1.noarch.rpm
EOF
	exit 1
}

check_version() {
    local tool
    local cmd
    local required
    local version

    tool=$1
    cmd=$2
    required=$3
    echo -n "checking for $cmd $required... "
    if ! $cmd --version >/dev/null ; then
	error_msg "missing"
    fi
    version=$($cmd --version | awk "/$tool \(GNU/ { print \$4 }")
    echo "found $version"
    if ! compare_versions "$required" "$version" ; then
	error_msg "too old"
    fi
}

echo "Checking for a complete tree..."
if [ -d kernel_patches ] ; then
    # This is ldiskfs
    REQUIRED_DIRS="build"
    CONFIGURE_DIRS=""
else
    REQUIRED_DIRS="build lnet lustre"
    OPTIONAL_DIRS="snmp portals"
    CONFIGURE_DIRS="libsysio lustre-iokit ldiskfs"
fi

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

check_version automake automake-1.7 "1.7.8"
check_version autoconf autoconf "2.57"

echo "Running aclocal-1.7 $ACLOCAL_FLAGS..."
aclocal-1.7 $ACLOCAL_FLAGS || exit 1
echo "Running autoheader..."
autoheader || exit 1
echo "Running automake-1.7..."
automake-1.7 -a -c || exit 1
echo "Running autoconf..."
autoconf || exit 1

# Run autogen.sh in these directories
for dir in $CONFIGURE_DIRS; do
    if [ -d $dir ] ; then
        pushd $dir >/dev/null
        echo "Running autogen for $dir..."
        sh autogen.sh || exit $?
        popd >/dev/null
    fi
done
