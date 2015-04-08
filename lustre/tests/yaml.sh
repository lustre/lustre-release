#!/bin/bash
# vim:shiftwidth=4:softtabstop=4:tabstop=4:

#
# Shell routines for logging results to a yaml file.
#

split_output() {
    while read line; do
        host=${line%%:*};
        echo "$line" | sed "s/^${host}: //" | sed "s/^${host}://" \
            >> $logdir/node.$host.yml;
    done
}

yml_nodes_file() {
    export logdir=$1

    if [ -f $logdir/shared ]; then
        do_rpc_nodes $(comma_list $(all_nodes)) \
            "yml_node >> $logdir/node.\\\$(hostname -s).yml"
    else
        do_rpc_nodes $(comma_list $(all_nodes)) yml_node | split_output
    fi
    yml_entities
}

yml_results_file() {
    export logdir=$1

    #TestGroup
    yml_test_group

    #CodeReview
    yml_code_review

    # Tests
    printf "Tests:\n"
}

# Called on the node for which we the info is needed.
yml_node() {
    logdir=$1

    printf "Build:\n"
    yml_build_info
    printf "\n"

    printf "Node:\n"
    yml_node_info
    printf "\n"

    printf "LustreEntities:\n"
}

yml_test_group() {
    TEST_GROUP=${TEST_GROUP:-"acc-sm-$(hostname -s)"}
    TEST_HOST=${TEST_HOST:-$(hostname -s)}
    TEST_USER=${TEST_USER:-$USER}

    # TestGroup information
    cat <<EOF
TestGroup:
    test_group: $TEST_GROUP
    testhost: $TEST_HOST
    submission: $(date)
    user_name: $TEST_USER
EOF
}

yml_code_review() {
    echo -e $CODE_REVIEW_YAML
}

release() {
	if [ -r /etc/SuSE-release ]; then
		name=$(awk '/SUSE/ { printf("%s %s %s %s", $1, $2, $3, $4) }' \
			/etc/SuSE-release)
		version=$(sed -n -e 's/^VERSION = //p' /etc/SuSE-release)
		level=$(sed -n -e 's/^PATCHLEVEL = //p' /etc/SuSE-release)
		dist="${name} ${version}.${level}"
	elif [ -r /etc/os-release ]; then
		name=$(sed -n -e 's/"//g' -e 's/^NAME=//p' /etc/os-release)
		version=$(sed -n -e 's/"//g' -e 's/^VERSION_ID=//p' \
			/etc/os-release)
		dist="${name} ${version}"
	elif [ -r /etc/system-release ]; then
		dist=$(awk '/release/ \
			{ printf("%s %s %s", $1, $2, $3) }' \
			/etc/system-release)
	elif [ -r /etc/*-release ]; then
		dist=$(find /etc/ -maxdepth 1 -name '*release' 2> /dev/null | \
			sed -e 's/\/etc\///' -e 's/-release//' | head -n1)
	else
		dist="UNKNOWN"
	fi

	echo $dist
}

yml_build_info() {
	local TEST_DISTRO=$(release)
	local LUSTRE_VERSION=$(lustre_build_version)
	local LUSTRE_BUILD=${LUSTRE_BUILD_SOURCE:-$LUSTRE_VERSION}
	local FILE_SYSTEM=$(node_fstypes $(hostname -s))

cat <<EOF
    lbats_build_id: $LBATS_ID
    lbats_build_name: $LBATS_NAME
    architecture: $(uname -m)
    os: $(uname -o)
    os_distribution: $TEST_DISTRO
    lustre_version: $LUSTRE_VERSION
    lustre_build: $LUSTRE_BUILD
    lustre_branch: $LUSTRE_BRANCH
    lustre_revision: $LUSTRE_REVISION
    kernel_version: $(uname -r)
    file_system: ${FILE_SYSTEM:-"NA"}
EOF
}

yml_node_info()
{
    mem=$(awk '/MemTotal:/ {print $2 " " $3}' /proc/meminfo)
cat <<EOF
    node_name: $(hostname -s)
    mem_size: $mem
    architecture: $(uname -m)
    networks:
EOF
    for nw in $(lctl list_nids | grep -v @lo | cut -f 2 -d '@' | uniq); do
        printf "        - $nw\n"
    done
}

yml_entity() {
    cat<<EOF
-
    node_type: $1
    node_name: $2
EOF
}

yml_entities() {
	local host
	local f_host
	local i

	if ! combined_mgs_mds; then
		host=$(short_hostname $(facet_active_host mgs))
		f_host=$(short_hostname $(facet_passive_host mgs))

		yml_entity "MGS" $host >> $logdir/node.$host.yml
		[[ -n $f_host ]] &&
			yml_entity "MGS" $f_host >> $logdir/node.$f_host.yml
	fi

	for i in $(seq $MDSCOUNT); do
		host=$(short_hostname $(facet_active_host mds$i))
		f_host=$(short_hostname $(facet_passive_host mds$i))

		yml_entity "MDS $i" $host >> $logdir/node.$host.yml
		[[ -n $f_host ]] &&
			yml_entity "MDS $i" $f_host >> $logdir/node.$f_host.yml
	done

	for i in $(seq $OSTCOUNT); do
		host=$(short_hostname $(facet_active_host ost$i))
		f_host=$(short_hostname $(facet_passive_host ost$i))

		yml_entity "OST $i" $host >> $logdir/node.$host.yml
		[[ -n $f_host ]] &&
			yml_entity "OST $i" $f_host >> $logdir/node.$f_host.yml
	done

	i=1
	for host in ${CLIENTS//,/ }; do
		host=$(short_hostname $host)
		yml_entity "Client $i" $host >> $logdir/node.$host.yml
		i=$((i+1))
	done
}

yml_log_test() {
    if [ $1 != "FINISHED" ]; then
        cat <<EOF
-
        name: $1
        description: $TESTSUITE $1
        submission: $(date)
        report_version: 2
        SubTests:
EOF
    fi
}

yml_log_test_status() {
    cat <<EOF
        duration: $1
        status: $2
EOF
}

yml_log_sub_test_begin() {
    cat <<EOF
        -
            name: $1
EOF
}

yml_log_sub_test_end() {
    cat <<EOF
            status: $1
            duration: $2
            return_code: $3
EOF
    shift 3
    if [ -z "$*" ]; then
        printf '            error:\n'
    else
        printf '            error: "%q"\n' "$*"
    fi
}

yml_log_sub_test_log() {
    cat <<EOF
        -
            name: $1
            type: $2
            location: $3
EOF
}
