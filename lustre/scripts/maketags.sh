#!/bin/sh

rm -f TAGS ; find . -name '*.h' -or -name '*.c' | xargs etags
rm -f tags ; ctags -R *
