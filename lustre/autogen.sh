#!/bin/sh

find . -type d -name .deps | xargs rm -rf
aclocal &&
automake --add-missing &&
${AUTOCONF:-autoconf}
