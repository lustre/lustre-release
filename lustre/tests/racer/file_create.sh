#!/bin/bash

DIR=$1
MAX=$2
MAX_MB=256

create() {
    SIZE=$((RANDOM * MAX_MB / 32))
    echo "file_create: SIZE=$SIZE"
    dd if=/dev/zero of=$DIR/$file bs=1k count=$SIZE
}

while /bin/true ; do 
    file=$((RANDOM % MAX))
    create 2> /dev/null
done

