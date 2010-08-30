#!/bin/bash
#set -x
set -e

LUSTRE=${LUSTRE:-`dirname $0`/..}
. $LUSTRE/tests/test-framework.sh
init_test_env $@

# QE uses the following parameters:
# size=128 crghi=16 thrhi=32
crghi=${crghi:-2}
thrhi=${thrhi:-16} 
size=${size:-1024}

. ${CONFIG:=$LUSTRE/tests/cfg/$NAME.sh}

[ "$SLOW" = no ] && { crghi=2; thrhi=2; }

# Skip these tests
ALWAYS_EXCEPT="$SGPDD_SURVEY_EXCEPT"

SGPDDSURVEY=${SGPDDSURVEY:-$(which sgpdd-survey)}

build_test_filter

init_facets_vars

cleanupall

run_sgpdd_host () {
    local host=$1
    local devs=$2

    local params="size=$size crghi=$crghi thrhi=$thrhi"
    do_rpc_nodes $host run_sgpdd $devs "$params"
}

test_1 () {
    local facet=mds

    local host=$(facet_host $facet)
    local dev=${facet}_dev
    echo "=== $facet === $host === ${!dev} ==="
    run_sgpdd_host $host ${!dev}
}
run_test 1 "sgpdd-survey, mds, scsidevs"

test_2 () {
    local facet

    local osts=$(get_facets OST)
    
    local ostshosts
    for facet in ${osts//,/ }; do
        local host=$(facet_host $facet)
        local dev=${facet}_dev
        local var=${host}_devs
        eval ${var}=$(expand_list ${!var} ${!dev})
	ostshosts=$(expand_list $ostshosts $host)
    done

    for host in ${ostshosts//,/ }; do
	var=${host}_devs
        echo "=== osts === $host === ${!var} ==="
        local scsidevs=${!var}
        run_sgpdd_host $host ${scsidevs}
    done
}
run_test 2 "sgpdd-survey, osts, scsidevs"

equals_msg `basename $0`: test complete, cleaning up
[ -f "$TESTSUITELOG" ] && cat $TESTSUITELOG || true
