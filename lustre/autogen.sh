#!/bin/sh

aclocal &&
${AUTOMAKE:-automake} --add-missing &&
${AUTOCONF:-autoconf}
