#!/bin/sh
set -vx
rm -f TAGS ; find . -name '*.h' -or -name '*.c' | xargs etags
rm -f ctags; find . -name '*.h' -or -name '*.c' | xargs ctags
