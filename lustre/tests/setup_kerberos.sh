#!/bin/bash
# -*- mode: Bash; tab-width: 4; indent-tabs-mode: t; -*-
# vim:shiftwidth=4:softtabstop=4:tabstop=4:

#
# setup_kerberos.sh - setup the Kerberos environment on Lustre cluster
#
# Notes:
#  * Only one KDC involved, no slave KDC.
#  * Only one Kerberos realm involved, no multiple Kerberos realms.
#
###############################################################################

# usage
my_usage() {
    cat <<EOF
Usage: $(basename $0) <KDC_distro> <KDC_node> <MGS_node> <MDS_node>[:MDS_node:...]
                      <OSS_node>[:OSS_node:...] <CLIENT_node>[:CLIENT_node:...]

    This script is used to setup the Kerberos environment on Lustre cluster.

    KDC_distro      distribution on the KDC node (rhel5 or sles10)
    KDC_node        KDC node name
    MGS_node        Lustre MGS node name
    MDS_node        Lustre MDS node name
    OSS_node        Lustre OSS node name
    CLIENT_node     Lustre client node name

    e.g.: $(basename $0) rhel5 scsi2 scsi2 sata2 sata3 client5
    e.g.: $(basename $0) sles10 scsi2 scsi2 scsi2 sata3:sata5 client2:client3
    e.g.: $(basename $0) rhel5 scsi2 scsi2 scsi2 scsi2 scsi2

    Notes:
    1) The script will destroy all the old Kerberos settings by default. If you
    want to reserve the original krb5.conf and KDC configuration, please set
    "RESET_KDC=false".

    2) The script will create principals for some runas users and add them into
    the Kerberos database by default. The UIDs of the runas users specified in
    "LOCAL_UIDS" variable need exist on KDC, MDS and Client nodes. If you do not
    need runas users, please set "CFG_RUNAS=false".

EOF
}

# ************************ Parameters and Variables ************************ #
MY_KDC_DISTRO=$1
MY_KDCNODE=$2
MY_MGSNODE=$3
MY_MDSNODES=$4
MY_OSSNODES=$5
MY_CLIENTNODES=$6

# translate to lower case letters
MY_KDC_DISTRO=$(echo $MY_KDC_DISTRO | tr '[A-Z]' '[a-z]')

if [ -z "$MY_KDC_DISTRO" -o -z "$MY_KDCNODE" -o -z "$MY_MDSNODES" -o \
    -z "$MY_OSSNODES" -o -z "$MY_CLIENTNODES" -o -z "$MY_MGSNODE" ]; then
    my_usage
    exit 1
fi

LUSTRE=${LUSTRE:-$(dirname $0)/..}
. $LUSTRE/tests/test-framework.sh
init_test_env

SCP=${SCP:-"scp -q"}
ACCEPTOR_PORT=${ACCEPTOR_PORT:-988}

# check and configure runas users
CFG_RUNAS=${CFG_RUNAS:-true}
# uids for local users
LOCAL_UIDS=${LOCAL_UIDS:-"500 501"}

# remove the original Kerberos and KDC settings
RESET_KDC=${RESET_KDC:-true}

# generate unique keytab for each client node
SPLIT_KEYTAB=${SPLIT_KEYTAB:-true}

# encryption types for generating keytab
MDS_ENCTYPE=${MDS_ENCTYPE:-"aes128-cts"}
MGS_ENCTYPE=${MGS_ENCTYPE:-"$MDS_ENCTYPE"}
OSS_ENCTYPE=${OSS_ENCTYPE:-"aes128-cts"}
CLIENT_ENCTYPE=${CLIENT_ENCTYPE:-"aes128-cts"}

# configuration file for Kerberos
KRB5_CONF=${KRB5_CONF:-"/etc/krb5.conf"}
KRB5_KEYTAB=${KRB5_KEYTAB:-"/etc/krb5.keytab"}
KRB5_TICKET_LIFETIME=${KRB5_TICKET_LIFETIME:-"24h"}

# configuration files for libgssapi and keyutils
GSSAPI_MECH_CONF=${GSSAPI_MECH_CONF:-"/etc/gssapi_mech.conf"}
REQUEST_KEY_CONF=${REQUEST_KEY_CONF:-"/etc/request-key.conf"}

# krb5 realm & domain
KRB5_REALM=${KRB5_REALM:-"CO.CFS"}
KRB5_DOMAIN=$(echo $KRB5_REALM | tr '[A-Z]' '[a-z]')

MY_MDSNODES=${MY_MDSNODES//:/ }
MY_OSSNODES=${MY_OSSNODES//:/ }
MY_CLIENTNODES=${MY_CLIENTNODES//:/ }

# set vars according to the KDC distribution
KRB5PKG_SVR="krb5-server"
KRB5PKG_DEV="krb5-devel"
case $MY_KDC_DISTRO in
    rhel5)
        KRB5PKG_CLI="krb5-workstation"
        KRB5PKG_LIB="krb5-libs"
        KDC_CONF_DIR="/var/kerberos/krb5kdc"
        ;;
    sles10)
        KRB5PKG_CLI="krb5-client"
        KRB5PKG_LIB="krb5"
        KDC_CONF_DIR="/var/lib/kerberos/krb5kdc"
        ;;
    *)
        echo "Unsupported KDC distro: $MY_KDC_DISTRO!"
        exit 1
esac
KDC_CONF="$KDC_CONF_DIR/kdc.conf"
KDC_ACL="$KDC_CONF_DIR/kadm5.acl"

# ******************************** Functions ******************************** #
is_part_of() {
    local name="$1"
    shift
    local list="$@"

    if [ -z "$name" -o -z "$list" ]; then
        false
        return
    fi

    if [[ " $list " == *" $name "* ]]; then
        true
    else
        false
    fi

    return
}

my_do_node() {
    local node=$1
    shift
    local nodename=${node%.$KRB5_DOMAIN}
    do_node $node "PATH=\$PATH:/usr/kerberos/sbin:/usr/kerberos/bin:\
/usr/lib/mit/sbin:/usr/lib/mit/bin $@" | sed "s/^${nodename}: //"
    return ${PIPESTATUS[0]}
}

do_node_mute() {
    local output
    output=$(my_do_node "$@" 2>&1)
    return ${PIPESTATUS[0]}
}

do_kdc() {
    my_do_node $MY_KDCNODE "$@"
    return ${PIPESTATUS[0]}
}

do_kdc_mute() {
    do_node_mute $MY_KDCNODE "$@"
    return ${PIPESTATUS[0]}
}

#
# convert a space-delimited node name list to a canonical name list
#
get_fqdn() {
    local nodename_list="$@"
    local fqdn_list=""
    local name
    local fqdn
    local rc

    for name in $nodename_list; do
        fqdn=$(do_kdc "gethostip -n $name 2>&1")
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ]; then
            echo "Can not get the FQDN of node $name: $fqdn"
            return $rc
        fi
        [ -z "$fqdn_list" ] && fqdn_list="$fqdn" \
        || fqdn_list="$fqdn_list $fqdn"

    done

    echo "$fqdn_list"
    return 0
}

#
# convert MDS/OSS nodes to their canonical name, it required by
# kerberos. we also convert kdc and client too in order to make
# node name comparison easier
#
normalize_names() {
    local rc

    # KDC
    MY_KDCNODE=$(get_fqdn $MY_KDCNODE)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo $MY_KDCNODE
        return $rc
    fi

    # MGS node
    MY_MGSNODE=$(get_fqdn $MY_MGSNODE)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo $MY_MGSNODE
        return $rc
    fi

    # MDS nodes
    MY_MDSNODES=$(get_fqdn $MY_MDSNODES)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo $MY_MDSNODES
        return $rc
    fi

    # OSS nodes
    MY_OSSNODES=$(get_fqdn $MY_OSSNODES)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo $MY_OSSNODES
        return $rc
    fi

    # client nodes
    MY_CLIENTNODES=$(get_fqdn $MY_CLIENTNODES)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo $MY_CLIENTNODES
        return $rc
    fi

    return 0
}

#
# verify remote shell works on all nodes
#
check_rsh() {
    local checked=""
    local node

    echo "+++ Checking remote shell"

    for node in $MY_KDCNODE $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES
    do
        is_part_of $node $checked && continue

        echo -n "Checking remote shell on $node..."
        do_node_mute $node true || return ${PIPESTATUS[0]}
        echo "OK!"

        checked="$checked $node"
    done
}

#
# verify the entropy (random numbers) on the KDC node, which is
# used by kdb5_util to create Kerberos database
#
check_entropy() {
    local limit=170
    local avail

    echo "+++ Checking the entropy on the KDC"

    echo -n "Checking $MY_KDCNODE..."
    avail=$(do_kdc "sysctl -n kernel.random.entropy_avail")
    local rc=${PIPESTATUS[0]}
    if [ $rc -eq 0 ]; then
        if [ $avail -lt $limit ]; then
            echo -e "\nWarning: The entropy on the KDC node is only $avail, \
which is not enough for kdb5_util to create Kerberos database! \
Let's use /dev/urandom!"
            do_kdc "rm -f /dev/random.bak && mv /dev/random{,.bak} && \
mknod /dev/random c 1 9"
            return ${PIPESTATUS[0]}
        fi
    else
        echo "Can not get the entropy on the KDC node!"
        return $rc
    fi
    echo "OK!"
}

#
# verify runas users and groups
#
check_users() {
    local checked=""
    local node
    local id
    local user

    echo "+++ Checking users and groups"

    for node in $MY_KDCNODE $MY_MGSNODE $MY_MDSNODES $MY_CLIENTNODES; do
        is_part_of $node $checked && continue

        for id in $LOCAL_UIDS; do
            echo -n "Checking uid/gid $id/$id on $node..."
            user=$(my_do_node $node getent passwd | grep :$id:$id: | cut -d: -f1)
            if [ -z "$user" ]; then
				echo -e "\nPlease set LOCAL_UIDS to some users \
which exist on KDC, MDS and client or add user/group $id/$id on these nodes."
                return 1
            fi
            echo "OK!"
        done
        checked="$checked $node"
    done
}

cfg_mount() {
    local node=$1
    local dev=$2
    local dir=$3

    echo -n "Checking $dev mount on $node..."
    if do_node_mute $node "grep -q $dir' ' /proc/mounts"; then
        echo "OK!"
        return 0
    fi

    if ! do_node_mute $node "grep -q ^$dev /etc/fstab"; then
        my_do_node $node "echo '$dev $dir $dev defaults 0 0' >> /etc/fstab" || \
            return ${PIPESTATUS[0]}
    fi
    my_do_node $node "mkdir -p $dir && mount $dir" || true

    if ! do_node_mute $node "grep -q $dir' ' /proc/mounts"; then
        echo "Failed to mount fs $dev at $dir!"
        return 1
    fi
    echo "OK!"
}

#
# configure nfsd mount on MDS and OSS nodes
#
cfg_nfs_mount() {
    local checked=""
    local node

    echo "+++ Configuring nfsd mount"

    for node in $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES; do
        is_part_of $node $checked && continue
        cfg_mount $node nfsd /proc/fs/nfsd || return ${PIPESTATUS[0]}
        checked="$checked $node"
    done
}

get_pkgname() {
    local node=$1
    local pkg=$2

    my_do_node $node "rpm -q $pkg 2>&1" | tail -n1
    return ${PIPESTATUS[0]}
}

get_krb5pkgname() {
    local node=$1
    local flavor=$2

    my_do_node $node cat /etc/SuSE-release 2>/dev/null | \
    grep -q 'Enterprise Server 10'
    if [ ${PIPESTATUS[1]} -eq 0 ]; then
        case $flavor in
            cli) echo "krb5-client";;
            lib) echo "krb5";;
        esac
    else
        case $flavor in
            cli) echo "krb5-workstation";;
            lib) echo "krb5-libs";;
        esac
    fi
}

check_kdc() {
    local pkg
    local rc

    echo "+++ Checking KDC installation"

    echo -n "Checking $MY_KDCNODE..."
    pkg=$(get_pkgname $MY_KDCNODE $KRB5PKG_SVR)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo -e "\nCan not find $KRB5PKG_SVR package on $MY_KDCNODE: $pkg"
        return $rc
    fi
    echo "OK!"
}

check_krb5() {
    local checked=""
    local pkg
    local rc
    local krb5pkg_cli

    echo "+++ Checking Kerberos 5 installation"
    for node in $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES; do
        is_part_of $node $checked && continue

        echo -n "Checking $node..."
        krb5pkg_cli=$(get_krb5pkgname $node cli)

        pkg=$(get_pkgname $node $krb5pkg_cli)
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ]; then
            echo -e "\nCan not find $krb5pkg_cli package on $node: $pkg"
            return $rc
        fi
        echo "OK!"
        checked="$checked $node"
    done
}

check_libgssapi() {
    local checked=""
    local node
    local pkg
    local rc

    echo "+++ Checking libgssapi installation"

    LIBGSSAPI=$(get_pkgname $MY_KDCNODE libgssapi)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo "Can not find libgssapi package on $MY_KDCNODE: $LIBGSSAPI"
        return $rc
    fi

    for node in $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES; do
        is_part_of $node $checked && continue

        echo -n "Checking $node..."
        pkg=$(get_pkgname $node libgssapi)
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ]; then
            echo -e "\nCan not find libgssapi package on $node: $pkg"
            return $rc
        fi
        echo "OK!"
        checked="$checked $node"
    done
}

#
# check and update the /etc/gssapi_mech.conf file on each node
# We only support MIT Kerberos 5 GSS-API mechanism.
#
cfg_libgssapi() {
    local checked=""
    local node
    local pkg
    local rc
    local krb5pkg_lib
    local krb5_lib 

    echo "+++ Updating $GSSAPI_MECH_CONF"

    for node in $MY_KDCNODE $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES
    do
        is_part_of $node $checked && continue

        krb5pkg_lib=$(get_krb5pkgname $node lib)
        pkg=$(get_pkgname $node $krb5pkg_lib)
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ]; then
            echo -e "\nCan not find $krb5pkg_lib package on $node: $pkg"
            return $rc
        fi

        krb5_lib=$(my_do_node $node "rpm -ql $pkg" | \
                    grep libgssapi_krb5.so | head -n1)

        if ! do_node_mute $node \
"egrep -q \\\"^$krb5_lib|^$(basename $krb5_lib)\\\" $GSSAPI_MECH_CONF"; then
            do_node_mute $node \
"echo '$krb5_lib mechglue_internal_krb5_init' >> $GSSAPI_MECH_CONF"
        fi
        checked="$checked $node"
    done
    echo "OK!"
}

#
# check and update the /etc/request-key.conf file on each MDS and client node
#
cfg_keyutils() {
    local checked=""
    local node
    local lgss_keyring

    echo "+++ Updating $REQUEST_KEY_CONF"

    for node in $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES; do
        is_part_of $node $checked && continue
        lgss_keyring=$(my_do_node $node "which lgss_keyring") || \
            return ${PIPESTATUS[0]}

        if ! do_node_mute $node \
"grep -q \\\"^create.*$lgss_keyring\\\" $REQUEST_KEY_CONF"; then
            do_node_mute $node \
"echo 'create lgssc * * $lgss_keyring %o %k %t %d %c %u %g %T %P %S' \
>> $REQUEST_KEY_CONF"
        fi
        checked="$checked $node"
    done
    echo "OK!"
}

add_svc_princ() {
    local fqdn=$1
    local type=$2

    echo -n "Creating service principal lustre_$type/$fqdn@$KRB5_REALM..."
    do_kdc_mute "kadmin.local -r $KRB5_REALM <<EOF
addprinc -randkey lustre_$type/$fqdn@$KRB5_REALM
EOF"
    local rc=${PIPESTATUS[0]}
    [ $rc -ne 0 ] && echo "Failed!" || echo "OK!"

    return $rc
}

add_svc_princ_root() {
    echo -n "Creating service principal lustre_root@$KRB5_REALM..."
    do_kdc_mute "kadmin.local -r $KRB5_REALM <<EOF
addprinc -randkey lustre_root@$KRB5_REALM
EOF"
    local rc=${PIPESTATUS[0]}
    [ $rc -ne 0 ] && echo "Failed!" || echo "OK!"

    return $rc
}

add_user_princ() {
    local user=$1

    echo -n "Creating user principal $user@$KRB5_REALM..."
    do_kdc_mute "kadmin.local -r $KRB5_REALM <<EOF
addprinc -pw $user $user@$KRB5_REALM
EOF"
    local rc=${PIPESTATUS[0]}
    [ $rc -ne 0 ] && echo "Failed!" || echo "OK!"

    return $rc
}

add_test_princ_id() {
    local id=$1
    local user

    user=$(do_kdc getent passwd $id | cut -d: -f1)
    if [ -z "$user" ]; then
        echo "Can not find the user with uid $id on the KDC!"
        return 1
    fi

    add_user_princ $user || return ${PIPESTATUS[0]}
}

#
# create principals for the client, MDS, OSS, runas users and add them to 
# the Kerberos database
#
cfg_kdc_princs() {
    local node

    add_svc_princ $MY_MGSNODE mgs || return ${PIPESTATUS[0]}

    for node in $MY_MDSNODES; do
        add_svc_princ $node mds || return ${PIPESTATUS[0]}
    done

    for node in $MY_OSSNODES; do
        add_svc_princ $node oss || return ${PIPESTATUS[0]}
    done

    for node in $MY_CLIENTNODES; do
        if $SPLIT_KEYTAB; then
            add_svc_princ $node root || return ${PIPESTATUS[0]}
        else
            add_svc_princ_root || return ${PIPESTATUS[0]}
        fi
    done

    if ! $SPLIT_KEYTAB; then 
        add_user_princ lustre_root || return ${PIPESTATUS[0]}
    fi
    add_user_princ bin || return ${PIPESTATUS[0]}
    add_user_princ daemon || return ${PIPESTATUS[0]}
    add_user_princ games || return ${PIPESTATUS[0]}

    if $CFG_RUNAS; then
        for uid in $LOCAL_UIDS; do
            add_test_princ_id $uid || return ${PIPESTATUS[0]}
        done
    fi
}

#
# create and install the KDC configuration file kdc.conf on the KDC, which 
# will destroy the old KDC setting
#
cfg_kdc() {
    local tmpdir="$TMP/krb5_cfg_tmp_$UID"
    local tmpcfg=$tmpdir/kdc.conf
    local tmpacl=$tmpdir/kadm5.acl

    echo "+++ Configuring KDC on $MY_KDCNODE"
    echo "Warning: old KDC setting on $MY_KDCNODE will be destroied!!!"

    echo -n "Checking the existence of KDC config dir..."
    do_kdc_mute "[ -d $KDC_CONF_DIR ]"
    if [ ${PIPESTATUS[0]} -ne 0 ]; then
        echo -e "\nUnrecognized krb5 distribution!"
        return 1
    else
        echo "OK!"
    fi

    # stop KDC daemon
    do_kdc_mute "/etc/init.d/krb5kdc stop < /dev/null" || true

    echo -n "Removing old KDC configurations..."
    do_kdc_mute "rm -f $KDC_CONF_DIR/*"
    echo "OK!"

    # create kdc.conf locally
    rm -rf $tmpdir
    mkdir -p $tmpdir || return ${PIPESTATUS[0]}
    cat <<EOF > $tmpcfg
[kdcdefaults]
 acl_file = $KDC_ACL

[realms]
 $KRB5_REALM = {
  master_key_type = aes128-cts
  supported_enctypes = des3-hmac-sha1:normal aes128-cts:normal aes256-cts:normal des-cbc-md5:normal
 }
EOF

    # install kdc.conf remotely
    echo -n "Installing kdc.conf on $MY_KDCNODE..."
    $SCP $tmpcfg root@$MY_KDCNODE:$KDC_CONF || return ${PIPESTATUS[0]}
    echo "OK!"

    # initialize KDC database
    echo -n "Creating Kerberos database on $MY_KDCNODE..."
    do_kdc_mute "kdb5_util create -r $KRB5_REALM -s -P 111111"
    local rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo "Failed!"
        return $rc
    else
        echo "OK!"
    fi

    # create ACL file locally & install remotely
    cat <<EOF > $tmpacl
*/admin@$KRB5_REALM   *
root@$KRB5_REALM      *
EOF
    echo -n "Installing kadm5.acl on $MY_KDCNODE..."
    $SCP $tmpacl root@$MY_KDCNODE:$KDC_ACL || return ${PIPESTATUS[0]}
    echo "OK!"
    rm -rf $tmpdir || true

    # start KDC daemon
    do_kdc "/etc/init.d/krb5kdc restart < /dev/null" || return ${PIPESTATUS[0]}
}

#
# create and install the Kerberos configuration file krb5.conf on the KDC, 
# client, MDS and OSS
#
cfg_krb5_conf() {
    local tmpdir="$TMP/krb5_cfg_tmp_$UID"
    local tmpcfg="$tmpdir/krb5.conf"
    local checked=""

    echo "+++ Installing krb5.conf on all nodes"

    # create krb5.conf locally
    rm -rf $tmpdir
    mkdir -p $tmpdir || return ${PIPESTATUS[0]}
    cat <<EOF > $tmpcfg
[libdefaults]
 default_realm = $KRB5_REALM
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = $KRB5_TICKET_LIFETIME
 forwardable = yes

[realms]
 $KRB5_REALM = {
  kdc = $MY_KDCNODE:88
  admin_server = $MY_KDCNODE:749
  default_domain = $KRB5_DOMAIN
 }

[domain_realm]
 .$KRB5_DOMAIN = $KRB5_REALM
 $KRB5_DOMAIN = $KRB5_REALM

[kdc]
 profile = $KDC_CONF

[appdefaults]
 pam = {
  debug = false
  forwardable = true
  krb4_convert = false
 }
EOF

    # install krb5.conf remotely
    for node in $MY_KDCNODE $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES
    do
        is_part_of $node $checked && continue

        echo -n "Installing krb5.conf on $node..."
        $SCP $tmpcfg root@$node:$KRB5_CONF || return ${PIPESTATUS[0]}
        echo "OK!"

        checked="$checked $node"
    done
    rm -rf $tmpdir || true
}

add_keytab() {
    local tab=$1
    local princ=$2
    local enctype=$3

    do_kdc_mute "kadmin.local -r $KRB5_REALM <<EOF
ktadd -k $tab -e $enctype:normal $princ@$KRB5_REALM
EOF"
}

add_keytab_svc() {
    local tab=$1
    local fqdn=$2
    local type=$3
    local enctype=$4

    add_keytab $tab lustre_$type/$fqdn $enctype
}

add_keytab_root() {
    local tab=$1
    local enctype=$2

    add_keytab $tab lustre_root $enctype
}

merge_keytab() {
    local tab=$1
    local node=$2

    $SCP $tab root@$node:$tab || return ${PIPESTATUS[0]}
    do_node_mute $node "ktutil <<EOF
rkt $tab
wkt $KRB5_KEYTAB
EOF" || return ${PIPESTATUS[0]}
}

#
# create and install the keytab file krb5.keytab on the client, MDS and OSS
#
cfg_keytab() {
    local tmptab="$TMP/keytab.tmp"
    local node

    echo "+++ Generating keytabs"

    # remove old keytabs
    echo -n "Deleting old keytabs on all nodes..."
    for node in $MY_MGSNODE $MY_OSSNODES $MY_MDSNODES $MY_CLIENTNODES; do
        do_node_mute $node "rm -f $KRB5_KEYTAB $TMP/krb5cc*"
    done
    echo "OK!"

    # install for MDS nodes
    for node in $MY_MDSNODES; do
        echo -n "Preparing for MDS $node..."
        do_kdc_mute "rm -f $tmptab"
        add_keytab_svc $tmptab $node mds $MDS_ENCTYPE || return ${PIPESTATUS[0]}

        if is_part_of $node $MY_MGSNODE; then
            echo -n "also be an MGS..."
            add_keytab_svc $tmptab $node mgs $MGS_ENCTYPE || \
                return ${PIPESTATUS[0]}
        fi

        if is_part_of $node $MY_OSSNODES; then
            echo -n "also be an OSS..."
            add_keytab_svc $tmptab $node oss $OSS_ENCTYPE || \
                return ${PIPESTATUS[0]}
        fi
        echo "OK!"

        echo -n "Installing krb5.keytab on $node..."
        $SCP root@$MY_KDCNODE:$tmptab $tmptab || return ${PIPESTATUS[0]}
        $SCP $tmptab root@$node:$KRB5_KEYTAB || return ${PIPESTATUS[0]}
        echo "OK!"
        rm -f $tmptab
    done

    # install for MGS node
    echo -n "Preparing for MGS $MY_MGSNODE..."
    if ! is_part_of $MY_MGSNODE $MY_MDSNODES; then
        do_kdc_mute "rm -f $tmptab"
        add_keytab_svc $tmptab $MY_MGSNODE mgs $MGS_ENCTYPE || \
            return ${PIPESTATUS[0]}

        if is_part_of $MY_MGSNODE $MY_OSSNODES; then
            echo -n "also be an OSS..."
            add_keytab_svc $tmptab $MY_MGSNODE oss $OSS_ENCTYPE || \
                return ${PIPESTATUS[0]}
        fi
        echo "OK!"

        echo -n "Installing krb5.keytab on $MY_MGSNODE..."
        $SCP root@$MY_KDCNODE:$tmptab $tmptab || return ${PIPESTATUS[0]}
        $SCP $tmptab root@$MY_MGSNODE:$KRB5_KEYTAB || return ${PIPESTATUS[0]}
        echo "OK!"
        rm -f $tmptab
    else
        echo "also be an MDS, already done, skip"
    fi

    # install for OSS nodes
    for node in $MY_OSSNODES; do
        echo -n "Preparing for OSS $node..."
        if is_part_of $node $MY_MDSNODES; then
            echo "also be an MDS, already done, skip"
        elif is_part_of $node $MY_MGSNODE; then
            echo "also be an MGS, already done, skip"
        else
            do_kdc_mute "rm -f $tmptab"
            add_keytab_svc $tmptab $node oss $OSS_ENCTYPE || \
                return ${PIPESTATUS[0]}
            echo "OK!"

            echo -n "Installing krb5.keytab on $node..."
            $SCP root@$MY_KDCNODE:$tmptab $tmptab || return ${PIPESTATUS[0]}
            $SCP $tmptab root@$node:$KRB5_KEYTAB || return ${PIPESTATUS[0]}
            echo "OK!"
            rm -f $tmptab
        fi
    done

    # install for client nodes
    do_kdc_mute "rm -f $tmptab"
    if ! $SPLIT_KEYTAB; then
        echo -n "Preparing for client..."
        add_keytab_root $tmptab $CLIENT_ENCTYPE || return ${PIPESTATUS[0]}
        $SCP root@$MY_KDCNODE:$tmptab $tmptab || return ${PIPESTATUS[0]}
        echo "OK!"
    else
        for node in $MY_CLIENTNODES; do
            echo -n "Preparing for client $node..."
            # don't generate keytabs if it's also an MDS
            if is_part_of $node $MY_MDSNODES; then
                echo "also be an MDS, already done, skip"
                continue
            fi

            add_keytab_svc $tmptab $node root $CLIENT_ENCTYPE || \
                return ${PIPESTATUS[0]}
            $SCP root@$MY_KDCNODE:$tmptab $tmptab || return ${PIPESTATUS[0]}
            echo "OK!"
        done
    fi
    for node in $MY_CLIENTNODES; do
        echo -n "Installing krb5.keytab on client $node..."

        # don't install if it's also an MDS
        if is_part_of $node $MY_MDSNODES; then
            echo "also be an MDS, already done, skip"
            continue
        fi

        # merge keytab if it's also an MGS
        if is_part_of $node $MY_MGSNODE; then
            echo -n "also be an MGS, merging keytab..."
            merge_keytab $tmptab $node || return ${PIPESTATUS[0]}
            echo "OK!"
            continue 
        fi

        # merge keytab if it's also an OSS
        if is_part_of $node $MY_OSSNODES; then
            echo -n "also be an OSS, merging keytab..."
            merge_keytab $tmptab $node || return ${PIPESTATUS[0]}
            echo "OK!"
            continue 
        fi

        # simply install otherwise
        $SCP $tmptab root@$node:$KRB5_KEYTAB || return ${PIPESTATUS[0]}
        echo "OK!"
    done
    rm -f $tmptab || true
}

check_acceptor_port() {
    local node=$1
    local port=$2

    if [ -z "$port" ]; then
        echo "Missing acceptor port!"
        return 1
    fi

    local WAIT=0
    local MAX_WAIT=300
    while [ $WAIT -lt $MAX_WAIT ]; do
        sleep 5
        my_do_node $node "netstat -tpan" | grep -q ":$port .*TIME_WAIT"
        if [ ${PIPESTATUS[1]} -ne 0 ]; then
            return 0
        fi
        WAIT=$((WAIT + 5))
    done

    echo "LNET acceptor port $port is in use on node $node!"
    return 2
}

get_client_nids() {
    local client_nids=""
    local node
    local nid
    local local_fqdn
    local rc

    # get the fqdn of the local host
    local_fqdn=$(get_fqdn $HOSTNAME)
    rc=${PIPESTATUS[0]}
    if [ $rc -ne 0 ]; then
        echo $local_fqdn
        return $rc
    fi

    for node in $MY_CLIENTNODES; do
        my_do_node $node lsmod | grep -q lnet || \
        my_do_node $node "modprobe lnet" || {
            if [ "$node" = "$local_fqdn" ]; then
                lsmod | grep -q lnet || load_modules
            else
                echo "Failed to load lnet module on node $node!"
                return 1
            fi
        }

        check_acceptor_port $node $ACCEPTOR_PORT || return ${PIPESTATUS[0]}

        nid=$(set +x; my_do_node $node \
"$LCTL net up 1>/dev/null && $LCTL list_nids" 2>&1 | head -n1
exit ${PIPESTATUS[0]})
        rc=${PIPESTATUS[0]}
        if [ $rc -ne 0 ]; then
            echo "Failed to get the nid for node $node: $nid"
            return $rc
        fi
        [ -z "$client_nids" ] && client_nids="$nid" \
        || client_nids="$client_nids $nid"

        my_do_node $node "$LCTL net down 1>/dev/null" || true
    done

    echo "$client_nids"
    return 0
}

# ******************************** Main Flow ******************************** #
normalize_names || exit ${PIPESTATUS[0]}
check_rsh || exit ${PIPESTATUS[0]}
check_entropy || exit ${PIPESTATUS[0]}

if $CFG_RUNAS; then
    check_users || exit ${PIPESTATUS[0]}
fi

check_kdc || exit ${PIPESTATUS[0]}
check_krb5 || exit ${PIPESTATUS[0]}
check_libgssapi || exit ${PIPESTATUS[0]}

echo "===================================================================="
echo " Configure Kerberos testing environment for Lustre"
echo " KDC: $MY_KDCNODE"
echo " realm: $KRB5_REALM, domain: $KRB5_DOMAIN"
echo " Using gssapi package: $LIBGSSAPI"
echo " MGS node:"
echo "     $MY_MGSNODE"
echo " OSS nodes:"
for i in $MY_OSSNODES; do echo "     $i"; done
echo " MDS nodes:"
for i in $MY_MDSNODES; do echo "     $i"; done
echo " CLIENT nodes:"
for i in $MY_CLIENTNODES; do echo "     $i"; done
echo "===================================================================="

cfg_nfs_mount || exit ${PIPESTATUS[0]}
cfg_libgssapi || exit ${PIPESTATUS[0]}
cfg_keyutils || exit ${PIPESTATUS[0]}

if $RESET_KDC; then
    cfg_krb5_conf || exit ${PIPESTATUS[0]}
    cfg_kdc || exit ${PIPESTATUS[0]}
fi

cfg_kdc_princs || exit ${PIPESTATUS[0]}
cfg_keytab || exit ${PIPESTATUS[0]}

echo "Complete successfully!"
