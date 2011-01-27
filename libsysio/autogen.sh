#!/bin/sh

${ACLOCAL:-aclocal} &&
${AUTOMAKE:-automake} --add-missing --copy &&
${AUTOCONF:-autoconf}
