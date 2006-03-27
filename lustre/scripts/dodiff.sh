#!/bin/sh

for f in `cat $1` ; do 
   diff -u $2-pristine/$f $2/$f 
done
