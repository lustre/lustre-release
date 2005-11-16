if [ -L /boot/vmlinux ]; then
    image=vmlinux
elif [ -L /boot/vmlinuz ]; then
    image=vmlinuz
elif [ -L /boot/image ]; then
    image=image
else
    # nothing to do (UML kernels for example).
    exit 0
fi

case %ver_str in
    (*xen*|*um*)
	SHORTNM=%ver_str
	SHORTNM=-${SHORTNM##*-}
	;;
    (*)
	unset SHORTNM
	;;
esac

if [ "$(readlink /boot/$image$SHORTNM)" = $image-%ver_str ]; then
    # This may be the last kernel RPM on the system, or it may
    # be an update. In both of those cases the symlinks will
    # eventually be correct. Only if this kernel
    # is removed and other kernel rpms remain installed,
    # find the most recent of the remaining kernels, and make
    # the symlinks point to it. This makes sure that the boot
    # manager will always have a kernel to boot in its default
    # configuration.
    shopt -s nullglob
    for img in $(cd /boot ; ls -dt $image-*$SHORTNM); do
	initrd=initrd-${img#*-}
	if [ -f /boot/$img -a -f /boot/$initrd ]; then
	    relink $img /boot/${img%%%%-*}$SHORTNM
	    relink $initrd /boot/${initrd%%%%-*}$SHORTNM

	    # Notify the boot loader that a new kernel image is active.
	    if [ -x /sbin/new-kernel-pkg ]; then
		/sbin/new-kernel-pkg $(/sbin/get_kernel_version /boot/$img)
	    fi
	    break
	fi
    done
    shopt -u nullglob
fi

# Check whether there is a .previous link to the image we're about
# to remove or to the image we point the new symlink to (so .previous
# would be identical to the current symlink)
case "$(readlink /boot/$image$SHORTNM.previous)" in
$image-%ver_str|$(readlink /boot/$image$SHORTNM))
    rm -f /boot/$image$SHORTNM.previous ;;
esac
case "$(readlink /boot/initrd$SHORTNM.previous)" in
initrd-%ver_str|$(readlink /boot/initrd$SHORTNM))
    rm -f /boot/initrd$SHORTNM.previous ;;
esac
# created in %post
rm -f /boot/initrd-%ver_str
