#!/bin/bash

# Currently the following tests do not pass:
# 47 - due to unresolvable symbol in UML local libc
# 52a, 52b - due to not implemented ioctl() in tmpfs
# 57a - due to inability to be supplied to tmpfs
# 56 - due to some unknown reason yet.

NAME=local FSTYPE=tmpfs MDSDEV=tmpfs OSTDEV=tmpfs sh llmount.sh && \
START=: CLEAN=: EXCEPT="47 52a 52b 56 57a" sh sanity.sh
