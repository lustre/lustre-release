if [ -f /boot/vmlinuz-%ver_str ]; then
    image=vmlinuz
elif [ -f /boot/image-%ver_str ]; then
    image=image
elif [ -f /boot/vmlinux-%ver_str ]; then
    image=vmlinux
else
    # nothing to do (UML kernels for example).
    exit 0
fi

# If we have old symlinks, rename them to *.previous
if [ -L /boot/$image -a -L /boot/initrd -a \
     "$(readlink /boot/$image)" != $image-%ver_str -a \
     "$(readlink /boot/initrd)" != initrd-%ver_str ]; then
    mv /boot/$image /boot/$image.previous
    mv /boot/initrd /boot/initrd.previous
fi

# update /boot/vmlinuz symlink
relink $image-%ver_str /boot/$image

if test "$YAST_IS_RUNNING" != instsys ; then
    if [ -f /etc/fstab ]; then
	echo Setting up /lib/modules/%ver_str
	/sbin/update-modules.dep -v %ver_str
	cd /boot
	/sbin/mkinitrd -k $image-%ver_str -i initrd-%ver_str

	if [ -e /boot/initrd-%ver_str ]; then
	    relink initrd-%ver_str /boot/initrd
	else
	    rm -f /boot/initrd
	fi
    else
	echo "please run mkinitrd as soon as your system is complete"
    fi
fi

if [ "$YAST_IS_RUNNING" != instsys -a -x /sbin/new-kernel-pkg ]; then
    # Notify boot loader that a new kernel image has been installed.
    # (during initial installation the boot loader configuration does not
    #  yet exist when the kernel is installed, but yast kicks the boot
    #  loader itself later.)
    /sbin/new-kernel-pkg %ver_str
fi
