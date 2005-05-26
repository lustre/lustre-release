#!/bin/sh

#
# KDC could be on remote hosts, but we suppose lgssd/lsvcgssd only
# runs locally.
#

export KDCHOST=${KDCHOST:-"localhost"}
export KDCDIR=${KDCDIR:-"/usr/kerberos/sbin"}
export KRB5DIR=${KRB5DIR:-"/usr/kerberos"}
export LGSSD=${LGSSD:-"/usr/sbin/lgssd"}
export SVCGSSD=${SVCGSSD:-"/usr/sbin/lsvcgssd"}
export PDSH=${PDSH:-"ssh"}

export CHECK_KDC=${CHECKKDC:-"no"}

using_krb5_sec() {
    if [ "x$1" != "xkrb5i" -a "x$1" != "xkrb5p" ]; then
        echo "n"
    else
        echo "y"
    fi
}

start_krb5_kdc() {
    if [ `using_krb5_sec $SECURITY` == 'n' ] ; then
        return 0
    fi

    if [ "x$CHECK_KDC" == "xno" ]; then
        return 0
    fi

    num=`$PDSH $KDCHOST "PATH=\$PATH:$KDCDIR; ps ax | grep krb5kdc | grep -v "grep" | wc -l"`
    if [ $num -eq 1 ]; then
        return 0
    fi

    $PDSH $KDCHOST "PATH=\$PATH:$KDCDIR; krb5kdc"
    num=`$PDSH $KDCHOST "PATH=\$PATH:$KDCDIR; ps ax | grep krb5kdc | grep -v "grep" | wc -l"`
    if [ $num -ne 1 ]; then
        echo "fail to start krb5 KDC, check env KDCHOST and KDCDIR"
        return 1
    fi
    return 0
}

prepare_krb5_cache() {
    if [ `using_krb5_sec $SECURITY` == 'n' ] ; then
        return 0
    fi

    $KRB5DIR/bin/klist -5 -s
    invalid=$?
    if [ $invalid -eq 0 ]; then
        return 0
    fi

    #
    # check installed service keytab for root
    #
    if [ $UID -eq 0 ]; then
        output=`$KRB5DIR/bin/klist -5 -k`
        if [ $? == 0 ]; then
            item=`echo $output | egrep "lustre_mds/.*@"`
            if [ "x$item" != "x" ]; then
                echo "Using service keytab"
                return 0
            fi
        fi
    fi

    echo "***** refresh Kerberos V5 TGT for uid $UID *****"
    $KRB5DIR/bin/kinit
    ret=$?
    return $ret
}

start_lsvcgssd() {
    if [ `using_krb5_sec $SECURITY` == 'n' ] ; then
        return 0
    fi

    killall -q -9 lsvcgssd || true

    `$SVCGSSD`
    num=`ps -o cmd -C "lsvcgssd" | grep lsvcgssd | wc -l`
    if [ $num -ne 1 ]; then
        echo "failed to start lsvcgssd"
        return 1
    fi
    return 0
}

stop_lsvcgssd() {
    killall -q -9 lsvcgssd || true
    return 0
}

start_lgssd() {
    if [ `using_krb5_sec $SECURITY` == 'n' ] ; then
        return 0
    fi

    prepare_krb5_cache || exit 1

    killall -q -9 lgssd || true

    `$LGSSD`
    num=`ps -o cmd -C "lgssd" | grep lgssd | wc -l`
    if [ $num -ne 1 ]; then
        echo "failed to start lgssd $num"
        return 1
    fi
    return 0
}

stop_lgssd() {
    killall -q -9 lgssd || true
    return 0
}
