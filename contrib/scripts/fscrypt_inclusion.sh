#!/bin/bash

#
# Purpose of this script is to show the method used to integrate fscrypt
# sources from the Linux kernel, and the transformations required.
#
# All C files from $LINUX/fs/crypto/ are put under libcfs/libcfs/crypto/.
# File $LINUX/include/linux/fscrypt.h is put in libcfs/include/libcfs/crypto/.
# File $LINUX/include/uapi/linux/fscrypt.h is placed under
# libcfs/include/uapi/linux/.
#

mv libcfs/libcfs/crypto/fscrypt_private.h libcfs/libcfs/crypto/llcrypt_private.h
mv libcfs/include/libcfs/crypto/fscrypt.h libcfs/include/libcfs/crypto/llcrypt.h
mv libcfs/include/uapi/linux/fscrypt.h libcfs/include/uapi/linux/llcrypt.h

file_list=$(find libcfs/libcfs/crypto/ -type f)
file_list+=" libcfs/include/libcfs/crypto/Makefile.am"
file_list+=" libcfs/include/libcfs/crypto/llcrypt.h"
file_list+=" libcfs/include/libcfs/crypto/Makefile.in"
file_list+=" libcfs/include/uapi/linux/llcrypt.h"

udef_list=$(grep -n "#define FS_" libcfs/include/uapi/linux/llcrypt.h | awk '{print $2}')

for file in $file_list; do
	cp $file ${file}.bkp
	sed -i s+fscrypt+llcrypt+g $file
	sed -i s+FSCRYPT+LLCRYPT+g $file
	sed -i s+FS_CRYPTO_BLOCK_SIZE+LL_CRYPTO_BLOCK_SIZE+g $file
	sed -i s+FSTR_INIT+LLTR_INIT+g $file
	sed -i s+FSTR_TO_QSTR+LLTR_TO_QSTR+g $file
	sed -i s+CONFIG_FS_ENCRYPTION+CONFIG_LL_ENCRYPTION+g $file
	sed -i s+FS_CFLG_OWN_PAGES+LL_CFLG_OWN_PAGES+g $file
	sed -i s+fname_name+lname_name+g $file
	sed -i s+fname_len+lname_len+g $file
	for def in $udef_list; do
		newdef=$(echo $def | sed s+^FS_+LL_+)
		sed -i s+$def+$newdef+g $file
	done
done

for patch in $(cat contrib/scripts/crypto_patches/series); do
	patch -p1 < $patch
done

exit 0
