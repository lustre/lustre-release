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
	cat >&2 <<EOF
$cmd is $1.  version $required is required to build Lustre.

You may be able to download a new version from:
http://ftp.gnu.org/gnu/$cmd/$cmd-$required.tar.gz
EOF
	[ "$cmd" = "autoconf" -a "$required" = "2.57" ] && cat >&2 <<EOF

or

ftp://fr2.rpmfind.net/linux/redhat/9/en/os/i386/RedHat/RPMS/autoconf-2.57-3.noarch.rpm
EOF
	[ "$cmd" = "automake" -a "$required" = "1.7.8" ] && cat >&2 <<EOF

or

ftp://fr2.rpmfind.net/linux/fedora/core/1/i386/os/Fedora/RPMS/automake-1.7.8-1.noarch.rpm
EOF
	exit 1
}

check_version() {
    local cmd
    local required
    local version

    cmd=$1
    required=$2
    echo -n "checking for $cmd $required... "
    if ! $cmd --version >/dev/null ; then
	error_msg "missing"
    fi
    version=$($cmd --version | awk "BEGIN { IGNORECASE=1 } /$cmd \(GNU $cmd\)/ { print \$4 }")
    echo "found $version"
    if ! compare_versions "$required" "$version" ; then
	error_msg "too old"
    fi
}

check_version automake "1.7.8"
check_version autoconf "2.57"
echo "Running autoreconf..."
autoreconf -fi
