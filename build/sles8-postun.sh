rm -f /boot/initrd-%ver_str  # created in %post -- clean up.

if [ "$(readlink /boot/vmlinuz)" = "vmlinuz-%ver_str" -o \
     "$(readlink /boot/initrd)"  = "initrd-%ver_str" ]; then
    # This may be the last kernel RPM on the system, or it may
    # be an update. In both of those cases the symlinks will
    # eventually be correct. On the other hand, if this kernel
    # is removed and other kernel rpms remain installed,
    # find the most recent of the remaining kernels, and make
    # the symlinks point to it. This makes sure that the boot
    # manager will always have a kernel to boot in its default
    # configuration.
    for vmlinuz in $(cd /boot ; ls -dt vmlinuz-*); do
	version="${vmlinuz#vmlinuz-}"
	initrd="initrd-$version"
	if [ -f "/boot/$vmlinuz" -a -f "/boot/$initrd" ]; then
	    relink "$vmlinuz" /boot/vmlinuz
	    relink "$initrd" /boot/initrd
	    break
	fi
    done
fi
