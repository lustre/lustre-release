#!/bin/sh

find . -type d -name .deps | xargs rm -rf
automake --add-missing &&
aclocal &&
autoconf 
