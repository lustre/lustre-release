#!/bin/sh

# remove the old source tree
rm -rf $BASEDIR/lustre_src

# get lustre sources
echo "*** Checking out lustre tag $LUSTRE_TAG and portals tag $PORTALS_TAG ***"
mkdir $BASEDIR/lustre_src
cd $BASEDIR/lustre_src
CVS_RSH=""
CVSROOT=":pserver:anonymous@cvs.lustre.sf.net:/cvsroot/lustre"
cvs export -r $LUSTRE_TAG lustre || exit 1
CVSROOT=":pserver:anonymous@cvs.sandiaportals.sf.net:/cvsroot/sandiaportals"
cvs export -r $PORTALS_TAG portals || exit 1
cd $BASEDIR

# build lustre
echo "*** Building lustre ***"
cd $BASEDIR/lustre_src/portals
sh autogen.sh
./configure --with-linux=$KERNEL_SRC
make
cd $BASEDIR/lustre_src/lustre
sh autogen.sh
./configure --with-linux=$KERNEL_SRC
make
cd $BASEDIR
