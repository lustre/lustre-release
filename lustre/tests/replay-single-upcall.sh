#!/bin/sh

LUSTRE=`dirname $0`/..

failed_import() {
    $LUSTRE/utils/lctl --device %$3 recover ||
        logger -p kern.info recovery failed: $@
}

recovery_over() {
    logger -p kern.info upcall: $@
}


case "$1" in
FAILED_IMPORT) failed_import $@
               ;;
RECOVERY_OVER) recovery_over $@
               ;;
esac
