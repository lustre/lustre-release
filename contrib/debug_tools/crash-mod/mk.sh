#! /bin/bash

declare -r prog=$(basename $0 .sh)
declare -r progdir=$(cd $(dirname $0) > /dev/null ; pwd -P)
declare -r program=${progdir}/$(basename $0)
declare -r progpid=$$

die() {
    echo "${prog} fatal error:  $*"
    kill -TERM $progpid
    sleep 0.1
    kill -KILL $progpid
    exit 1
} >&2

set_crashdir() {
    test -d "${CRASHDIR}" && return 0
    CRASHDIR=$(command -v crash | sed 's@/bin/crash@@')
    test -d "${CRASHDIR}" && {
        CRASHDIR=${CRASHDIR}/include/crash
        return 0
    }
    for d in /usr/local /usr "$(
        rpm -q --list crash | sed -n 's@/bin/crash$@@')"
    do
        test -d "$d" || continue
        test -x ${d}/bin/crash && {
            CRASHDIR=${d}/include/crash
            return 0
        }
    done
    die "cannot locate crash installation root"
}

set_crashexe() {
    CRASHEXE=${CRASHDIR%/include/crash}/bin/crash
    test -x "$CRASHEXE" || {
        CRASHEXE=${CRASHDIR%/include/crash}/crash
        test -x "$CRASHEXE" || \
            die "crash executable is not ${CRASHEXE}"
    }
}

set_target() {
    # This is derived from the "configure.c" program in the crash sources.
    # It is needed to select the correct code from the defs.h header.
    #
    declare defs=$(gcc -E -dM - < /dev/null | grep -v '('|\
        sed -n $'s/^#define[ \t]*__\([a-z]\)/HAVE_\\1/p' | \
        sed $'s/[ \t].*//;s/^/declare /;s/$/=true/');

    eval "$defs"
    TARGET=unknown
    ${HAVE_alpha__:-false}     && TARGET=ALPHA  && return
    ${HAVE_i386__:-false}      && TARGET=X86    && return
    ${HAVE_powerpc__:-false}   && TARGET=PPC    && return
    ${HAVE_ia64__:-false}      && TARGET=IA64   && return
    ${HAVE_s390__:-false}      && TARGET=S390   && return
    ${HAVE_s390x__:-false}     && TARGET=S390X  && return
    ${HAVE_powerpc64__:-false} && TARGET=PPC64  && return
    ${HAVE_x86_64__:-false}    && TARGET=X86_64 && return
    ${HAVE_arm__:-false}       && TARGET=ARM    && return
}

set_gdb_ver() {
    declare v=$(${CRASHEXE} --version | grep 'GNU gdb ')
    test ${#v} -eq 0 && die "no gdb version found in $CRASHEXE"
    set -- $v
    eval GDB_FLAGS=-DGDB_\${$#}
    GDB_FLAGS=$(echo $GDB_FLAGS | tr . _)
}

set_cflags() {
    declare -A cflags=(
        [ALPHA]=""
        [X86]="-D_FILE_OFFSET_BITS=64"
        [PPC]="-D_FILE_OFFSET_BITS=64"
        [IA64]=""
        [S390]="-D_FILE_OFFSET_BITS=64"
        [S390X]=""
        [PPC64]="-m64"
        [X86_64]=""
        [ARM]="-D_FILE_OFFSET_BITS=64")
    TARGET_CFLAGS=${cflags[$TARGET]}\ -D${TARGET}\ ${GDB_FLAGS}
}

build_so() {
    test ${#CRASHDIR} -eq 0 && set_crashdir
    test -f ${CRASHDIR}/defs.h || \
        die "${CRASHDIR} does not contain 'defs.h'"
    test ${#CRASHEXE} -eq 0 && set_crashexe
    set_target
    set_gdb_ver
    set_cflags
    declare GCC_OPTS='-Wall -Werror -nostartfiles -shared -rdynamic -fPIC'
    GCC_CMD="gcc -I${CRASHDIR} ${GCC_OPTS} ${TARGET_CFLAGS}"

    obj='lustre-ext.so'
    test ! -f $obj -o $obj -ot lustre-ext.c && {
        echo ${GCC_CMD} -o $obj lustre-ext.c
        ${GCC_CMD} -o $obj lustre-ext.c || \
            die could not build lustre-ext.so
    }
}

while test $# -gt 0
do
    arg=$(echo $1 | sed 's/^-*//')

    case X"$arg" in
    Xcl* )
        # check for clean/clobber
        #
        rm -f *.so
        ;;

    Xunin* )
        # check for uninstall
        #
        test -d ~/.crash.d && \
            rm -f ~/.crash.d/lustre-*.so
        ;;

    Xall )
        build_so
        ;;

    Xin* )
        test -f lustre-ext.so || build_so

        # check for install
        #
        test -d ~/.crash.d || mkdir ~/.crash.d || \
            die "could not make installation directory $HOME/.crash.d"
        cp -fp lustre-*.so ~/.crash.d/.
        ;;

    * )
        die "invalid option:  $1"
    esac

    shift
done

exit 0
