# Replace fake symlinks with the real ones
relink vmlinuz-%ver_str /boot/vmlinuz
relink initrd-%ver_str /boot/initrd

if [ -e /etc/sysconfig/kernel ]; then
    update_rcfile_setting /etc/sysconfig/kernel INITRD_MODULES 2>&1
elif [ -e /etc/rc.config ]; then
    update_rcfile_setting /etc/rc.config INITRD_MODULES 2>&1
fi

# If any trigger scripts have created additional modules, we need to
# run depmod.
run_depmod=
if [ -x /sbin/depmod ]; then
    for module in $(find /lib/modules/%ver_str \
	    		 /lib/modules/%{version}-override-%{cfg_name} \
			 -type f) ; do
	if [ $module -nt /lib/modules/%ver_str/modules.dep ]; then
	    run_depmod=1
	    break
	fi
    done
fi
if [ -n "$run_depmod" ]; then
    depmod -ae %ver_str
fi

if [ -f /etc/fstab -a -x /sbin/mkinitrd ]; then
    cd /boot && \
    /sbin/mkinitrd -k "vmlinuz-%ver_str" -i "initrd-%ver_str"
elif [ -f /etc/fstab -a -x /sbin/mk_initrd ]; then
    cd /boot && \
    /sbin/mk_initrd -k "vmlinuz-%ver_str" -i "initrd-%ver_str"
else
    echo "please run mkinitrd as soon as your system is complete"
fi

# Only call new-kernel-pkg during package updates: Otherwise we might
# call this during an initial installation, with a half-initialized
# boot loader. ($1 = number of instances of this package currently
# installed.)
if [ "$1" -gt 1 ]; then
    # Notify boot loader that a new kernel image has been installed.
    if [ -x /sbin/new-kernel-pkg ]; then
	/sbin/new-kernel-pkg %ver_str
    elif [ -e /etc/lilo.conf -a -x /sbin/lilo ]; then
    	/sbin/lilo
    fi
fi
