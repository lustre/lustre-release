#!/bin/sh

find . -type d -name .deps | xargs rm -rf
aclocal &&
${AUTOMAKE:-automake} --add-missing &&
${AUTOCONF:-autoconf}
