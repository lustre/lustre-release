#!/bin/sh

fatal() {
    local msg="$1"

    echo "FATAL: $msg"
    exit 1
}

run_cmd() {
    local cmd="$1"

    echo "Running $cmd..."
    $cmd || fatal "$cmd failed!"
}

run_cmd aclocal
run_cmd "automake -a -c"
run_cmd autoconf

echo "Finished.  Ready for ./configure ..."
