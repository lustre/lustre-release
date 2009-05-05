# Check if $1 is equal to any argument in $1 .. $*.
#
contains() {
    local x=$1
    shift

    case " $@ " in
    *" $x "*)	return 0 ;;
    *)		return 1 ;;
    esac
}

# Check the old value of INITRD_MODULES:
#  - Remove modules that no longer exist.
#  - Add modules that were built into the kernel before.
#
update_INITRD_MODULES() {
    # MD_MODS is the list of modules that require md.o.
    local MD_MODS="linear multipath raid0 raid1 raid5"

    # NON_SCSI is a whitelist of modules that are no scsi drivers. Any
    # module not listed here is assumed to be a scsi driver, and the
    # low-level scsi modules are added to INITRD_MODULES.
    local NON_SCSI="jbd ext3 jfs xfs reiserfs $MD_MODS md"

    local result maybe_scsi need_md have_md have_scsi have_sd m
    for m in "$@" ; do
	m="${m%.o}" ; m="${m%.ko}"
	
	contains "$m" $NON_SCSI || maybe_scsi=1
	contains "$m" $MD_MODS && need_md=1
	[ "$m" == md ] && have_md=1
	if contains "$m" scsi_mod sd_mod ; then
	    eval have_${m%_mod}=1
	    continue
	fi
	if contains "$m" xfs_dmapi xfs_support ; then
	    echo "Module $m no longer exists, and was removed from" \
		 "INITRD_MODULES." >&2
	    continue
	fi
	
	result[${#result[@]}]="$m"
    done
    if [ -n "$maybe_scsi" -o -n "$have_scsi" -o -n "$have_sd" ]; then
	[ -z "$have_scsi" -o -z "$have_sd" ] \
	    && echo "Adding SCSI disk modules to INITRD_MODULES" >&2
	result=(scsi_mod sd_mod ${result[@]})
    fi
    if [ -n "$need_md" -a -z "$have_md" ]; then
        echo "Adding RAID support module to INITRD_MODULES" >&2
    	result=(md ${result[@]})
    fi

    echo ${result[@]}
}
