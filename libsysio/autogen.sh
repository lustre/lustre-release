#!/bin/sh

aclocal &&
automake --add-missing --copy &&
${AUTOCONF:-autoconf}
