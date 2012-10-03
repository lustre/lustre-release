#!/bin/sh

# install Lustre Git commit hooks by default - LU-2083
for HOOK in commit-msg prepare-commit-msg; do
	[ -e .git/hooks/$HOOK ] || ln -sf ../build/$HOOK .git/hooks/
done

exec bash build/autogen.sh $@ 

