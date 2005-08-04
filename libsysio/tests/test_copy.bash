#!/bin/bash
#############################################################################
#
#     This Cplant(TM) source code is the property of Sandia National
#     Laboratories.
#
#     This Cplant(TM) source code is copyrighted by Sandia National
#     Laboratories.
#
#     The redistribution of this Cplant(TM) source code is subject to the
#     terms of the GNU Lesser General Public License
#     (see cit/LGPL or http://www.gnu.org/licenses/lgpl.html)
#
#     Cplant(TM) Copyright 1998-2003 Sandia Corporation. 
#     Under the terms of Contract DE-AC04-94AL85000, there is a non-exclusive
#     license for use of this work by or on behalf of the US Government.
#     Export of this program may require a license from the United States
#     Government.
#
#############################################################################


# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
# 
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
# 
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# Questions or comments about this library should be sent to:
#
# Lee Ward
# Sandia National Laboratories, New Mexico
# P.O. Box 5800
# Albuquerque, NM 87185-1110
#
# lee@sandia.gov

############################################################################
#
#   File:  test_copy.bash
#
#   Description:  Script to exercise the sysio library.
#
#   Usage:  
#   test_copy.bash 
# 
#   Limitations:
#   1.  Doesn't exercise all of sysio.
#   2.  Uses hardcoded /native prefix for file names which may not be the
#       final solution.
#
############################################################################

# defaults - change as necessary for local system
SCRATCH=test_copy.$$
CWD=`pwd`
SRC=${CWD}/test_copy.src
DEST=${CWD}/test_copy.dest
PREFIX=/native

# main processing logic follows
cp /dev/null $SCRATCH
rm -f $SRC $DEST
if [ -f $SRC ] 
then 
  echo "Could not remove $SRC - test INDETERMINATE" >> $SCRATCH
  exit 5
fi
if [ -f $DEST ] 
then 
  echo "Could not remove $DEST - test INDETERMINATE" >> $SCRATCH
  exit 5
fi

if ( ! cp /usr/include/stdio.h $SRC )  # just picked something handy
then
  echo "Could not create source file - test INDETERMINATE" >> $SCRATCH
  exit 5
fi


#
#  Run the test
#
./test_copy ${PREFIX}/${SRC} ${PREFIX}/${DEST}
SRC_VERF=`cksum $SRC | awk '{ print $1 }'`
DEST_VERF=`cksum $DEST | awk '{ print $1 }'`
if [ "$SRC_VERF" -ne "$DEST_VERF" ]
then
    echo "The source and destination files did not match; test FAILED" >> $SCRATCH 2>&1
else
    echo "The source and destination files matched; test PASSED" >> $SCRATCH 2>&1
fi

#
#  Report test results
#
echo ""
PASSCNT=1
if grep "FAILED" $SCRATCH > /dev/null
then
        echo "TEST $0 FAILED - found failed"
        cat $SCRATCH
        RC=8
elif test `grep -c "PASSED" $SCRATCH` -ne $PASSCNT > /dev/null
then
        echo "TEST $0 FAILED - wrong pass count"
        cat $SCRATCH
        RC=4
else
        echo "TEST $0 PASSED"
        RC=0

fi

if [ -z "$NOCLEANUP" ]
then
  rm -f $SCRATCH $SRC $DEST
fi

exit $RC
