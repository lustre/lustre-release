# This file contain all configuration information to build
# `lustre-release/lustre/contrib/wireshark'

[[ $1 =~ --.* ]] || {
    ###########################################################################
    #                                                                         #
    #    DOWNLOAD CONFIGURATION
    #                                                                         #
    ###########################################################################

    ##   BEGIN: -can-edit   ##
    # URL of directory containing all source tar balls
    export WS_DOWNLOAD_BASE_URL='http://wiresharkdownloads.riverbed.com'
    WS_DOWNLOAD_BASE_URL+='/wireshark/src/all-versions'

    # wireshark verion to be used
    export WS_VERSION='1.6.8'
    ##   END  : -can-edit   ##

    # URL of the wireshark source code tarball
    # Implicit assumption: Wireshark release names follow the nameing
    # convention coded in the content of the following varialble
    export WS_SOURCE_URL="${WS_DOWNLOAD_BASE_URL}/wireshark-${WS_VERSION}.tar.bz2"


    ###########################################################################
    #                                                                         #
    #                   BUILD ENVIRONMENT                                     #
    #                                                                         #
    ###########################################################################

    ##   BEGIN: -can-edit   ##
    # Space separate list of RPMs needed to be installed for 
    # compilation of wireshark

    # Package name(s) (can) vary between different distributions
    # If distributions 'marked' by same release file, content has to
    # parsed and variable PREREQUISITE_RPMS has to be set accoringly to
    # package name(s) used for each distro.
    if [ -r /etc/redhat-release ] ; then
        export PREREQUISITE_RPMS='gtk2 gtk2-devel glib2 libpcap libpcap-devel perl'
    elif [ -r /etc/SuSE-release ] ; then
        export PREREQUISITE_RPMS='gtk2 gtk2-devel glib2 libpcap0 libpcap-devel perl'
    fi

    # Include and linker flags needed to Lustre/LNet
    # Only version indepent information should be added here
    # (Back ticked expression will be evaluated by make command)
    export PLUGIN_COMPILE_FLAGS='`pkg-config --libs --cflags glib-2.0`'
    ##   END  : -can-edit   ##

    # Top-level directory to be used to unpack/compile/install
    # wireshark/lustre-git-repo
    export BUILD_DIR=`pwd`

    # Directory location of wireshark source code
    export WS_HOME="${BUILD_DIR}/wireshark-${WS_VERSION}"

    # (Relative) path of the wireshark contribution directory
    export LUSTRE_WS_DIR='lustre-release/lustre/contrib/wireshark'

    # RPM internal name for the Lustre/LNet plugins
    export PLUGIN_RPM_NAME='lustre-wireshark-plugins'

    # TAR command + options to be used to create a bzip2 tarball
    export TAR='/bin/tar jcpf '
    # TAR command + options to be used to unpack a bzip2 tarball
    export UNTAR='/bin/tar jxpf '
    exit 0
}

die() {
    echo "wsconfig error:  $*"
    exit 1
} 1>&2

# arg1: complete package name, with version
# arg2: the minimum version
#
chk_ver() {
    act_ver=${1#*-devel-} ; shift
    act_ver=${act_ver%%-*}

    declare low_ver=$(
        printf "${act_ver}\n$1\n" | sort -V | head -n1 )
    test "X$low_ver" = "X$1" || \
        die "wireshark too old: $act_ver is before $1"
}

set_var() {
    case "X$2" in
    Xlibdir )
        txt=$(echo $(rpm -q --list $1 | \
            sed -n '\@/libwire@s@/libwire[^/]*$@@p' | \
            sort -u) )
        ;;
    * )
        die "unknown variable: $2"
        ;;
    esac
}

set_cflags() {
    dlst=$(rpm -q --list $pkg | \
        grep '/usr.*/include.*/wireshark$' | \
        while read f ; do test -d $f && echo "$f" ; done)
    rm -f config.h
    for f in $dlst XX
    do test -f $f/config.h && ln -s ${f}/config.h .
        txt+=" -I$f"
    done
    test -f config.h || die "cannot find config header"
}

parse_wireshark() {
    declare pkg=$(rpm -qa | sed -n '/wireshark-devel/{;p;q;}')
    declare dlst=

    while test $# -gt 1
    do
        txt=
        case "$1" in
        --libs )
            txt=$(rpm -q --list $pkg | \
                sed -n 's@\.so$@@p' | \
                sed 's@.*/lib@-l@')
            ;;

        --cflags )
            set_cflags
            ;;

        --modversion )
            txt=${pkg#wireshark-devel-}
            txt=${txt%%-*}
            ;;

        --atleast-version=* )
            chk_ver ${pkg} ${1#*=}
            ;;

        --atleast-version )
            shift
            chk_ver ${pkg} ${1}
            ;;

        --variable=* )
            set_var ${pkg} ${1#*=}
            ;;

        --variable )
            shift
            set_var ${pkg} ${1}
            ;;

        * )
            die "unknown option: $1"
            ;;
        esac
        test ${#txt} -gt 0 && \
            printf "%s" "$(echo ' '$txt)"
        shift
    done
    echo
}

pkg-config "$@" 2>/dev/null && exit 0

pkg=$#
case ${!pkg} in
glib* )
    fullpkg=$(rpm -qa | grep -E '^glib[2-9].*-devel' | head -n1)
    dirs=$(rpm -q --list $fullpkg | \
        while read f ; do test -d $f && echo $f ; done | \
        grep -F /include)
    for f in $dirs ; do printf "-I$f " ; done
    rpm -q --list $fullpkg | \
        sed -n 's@^.*/libglib@-lglib@p' | \
        sed -n 's/\.so$//p' | \
        head -n 1
    ;;

wireshark )
    parse_wireshark "$@"
    ;;

* )
    echo huh?
    exit 1
    ;;
esac
