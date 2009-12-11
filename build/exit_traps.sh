#!/bin/bash

# a framework for stacking EXIT traps
# this could, should be further enhanced to allow stacks of traps for various
# exits.  but right now it's hard-coded for EXIT traps

exit_actions=()

push_exit_trap() {
    local action="$1"
    local trap_handle="$2"

    local var="exit_trap_handle_$trap_handle"

    if [ -n "${!var}" ]; then
        echo "fail!  trap handle $trap_handle is already in use"
        return 1
    fi

    local num_items=${#exit_actions[@]}
    exit_actions[$num_items]="$action"
    eval $var="$num_items"

    return 0

}

delete_exit_trap() {
    local trap_handle="$1"

    local var="exit_trap_handle_$trap_handle"
    local trap_num=${!var}
    exit_actions[$trap_num]=""
    eval unset $var
}

print_exit_traps() {

    local i num_items=${#exit_actions[@]}
    for i in $(seq 0 $((num_items-1))); do
        if [ -z "${exit_actions[$i]}" ]; then
            continue
        fi
        echo "${exit_actions[$i]}"
    done

}

run_exit_traps() {

    local i num_items=${#exit_actions[@]}
    for i in $(seq $((num_items-1)) -1 0); do
        if [ -z "${exit_actions[$i]}" ]; then
            continue
        fi
        eval ${exit_actions[$i]}
    done

}

trap run_exit_traps EXIT

#if ! push_exit_trap "echo \"this is the first trap\"" "a"; then
#    echo "failed to install trap 1"
#    exit 1
#fi
#if ! push_exit_trap "echo \"this is the second trap\"" "b"; then
#    echo "failed to install trap 2"
#    exit 2
#fi
#delete_exit_trap "b"
#if ! push_exit_trap "echo \"this is the third trap\"" "b"; then
#    echo "failed to install trap 3"
#    exit 3
#fi

# to see the traps
#print_exit_traps
