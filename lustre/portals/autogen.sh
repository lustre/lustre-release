#!/bin/sh

aclocal &&
automake --add-missing &&
${AUTOCONF:-autoconf}
