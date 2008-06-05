#!/bin/bash

DIR=$1
MAX=$2

while /bin/true ; do 
    file=$(($RANDOM%$MAX))
    new_file=$((($file + 1)%$MAX))
    ln $file $DIR/$new_file 2> /dev/null
done
