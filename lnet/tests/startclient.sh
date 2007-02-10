#!/bin/sh

case `uname -r` in
    2.6.*) ext=.ko;;
    2.4.*) ext=.o;;
    *)     echo unknown OS version; return 1;;
esac

insmod pingcli$ext

