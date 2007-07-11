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

case %ver_str in
    (*xen*|*um*)
	NOBOOTSPLASH="-s off"
	SHORTNM=%ver_str
	SHORTNM=-${SHORTNM##*-}
	;;
    (*)
	unset NOBOOTSPLASH
	unset SHORTNM
	;;
esac	

# If we have old symlinks, rename them to *.previous
if [ -L /boot/$image$SHORTNM -a \
    "$(readlink /boot/$image$SHORTNM)" != $image-%ver_str ]; then
	mv /boot/$image$SHORTNM /boot/$image$SHORTNM.previous
fi
relink $image-%ver_str /boot/$image$SHORTNM

if test "$YAST_IS_RUNNING" != instsys ; then
    if [ -f /etc/fstab ]; then
	echo Setting up /lib/modules/%ver_str
        if [ -x /sbin/update-modules.dep ]; then
	    /sbin/update-modules.dep -v %ver_str
        else
            /sbin/depmod -a -F /boot/System.map-%ver_str %ver_str
        fi
	cd /boot
	/sbin/mkinitrd -k $image-%ver_str -i initrd-%ver_str $NOBOOTSPLASH

	if [ -L /boot/initrd$SHORTNM -a \
	     "$(readlink /boot/initrd)" != initrd-%ver_str ]; then
	    mv /boot/initrd$SHORTNM /boot/initrd$SHORTNM.previous
	fi  
	if [ -e /boot/initrd-%ver_str ]; then
	    relink initrd-%ver_str /boot/initrd$SHORTNM
	else
	    rm -f /boot/initrd$SHORTNM
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
