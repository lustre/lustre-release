#!/bin/bash
#set -x
set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@
. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}
init_logging

# QE uses the following parameters:
# size=128 crghi=16 thrhi=32
crghi=${crghi:-2}
thrhi=${thrhi:-16}
size=${size:-1024}

[ "$SLOW" = no ] && { crghi=2; thrhi=2; }

if [ "$SGPDD_YES" != "yes" -o "$REFORMAT" != "yes" ]; then
	skip_env "$0 reformats all devices, set SGPDD_YES=yes REFORMAT=yes"
	exit 0
fi

# Skip these tests
ALWAYS_EXCEPT="$SGPDD_SURVEY_EXCEPT"

build_test_filter

init_facets_vars

cleanupall

run_sgpdd_host () {
    local host=$1
    local devs=$2

    local params="size=$size crghi=$crghi thrhi=$thrhi"
    do_rpc_nodes $host run_sgpdd $devs "$params"
}

run_sgpdd_facets () {
    local facets=$1
    local facet

    local facetshosts
    for facet in ${facets//,/ }; do
        local host=$(facet_host $facet)
        local dev=${facet}_dev
        local var=$(node_var_name ${host}_devs)
        eval ${var}=$(expand_list ${!var} ${!dev})
        facetshosts=$(expand_list $facetshosts $host)
    done

    for host in ${facetshosts//,/ }; do
        var=$(node_var_name ${host}_devs)
        echo "=== $facets === $host === ${!var} ==="
        local scsidevs=${!var}
        run_sgpdd_host $host ${scsidevs}
    done
}

test_1 () {
    local mdss=$(get_facets MDS)

    check_progs_installed $(facets_hosts $mdss) $SGPDDSURVEY sg_map || \
        { skip_env "SGPDDSURVEY=$SGPDDSURVEY or sg_map not found" && return 0; }

    run_sgpdd_facets $mdss
}
run_test 1 "sgpdd-survey, mds, scsidevs"

test_2 () {
    local osts=$(get_facets OST)

    check_progs_installed $(facets_hosts $osts) $SGPDDSURVEY sg_map || \
        { skip_env "SGPDDSURVEY=$SGPDDSURVEY or sg_map not found" && return 0; }

    run_sgpdd_facets $osts
}
run_test 2 "sgpdd-survey, osts, scsidevs"

complete $SECONDS
exit_status
