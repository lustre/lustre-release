#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Embed BTF in Lustre kernel modules, run after kbuild produces the .ko.
# Encode with a distilled base (.BTF.base) so the module BTF is
# relocatable and loads on kernels other than the build host; a
# base-pinned .BTF fails at load with -EINVAL ("failed to validate
# module BTF") when the running vmlinux differs from the build host's.

command -v pahole > /dev/null 2>&1 || exit 0
[ -f /sys/kernel/btf/vmlinux ] || exit 0

# distilled base needs pahole 1.26+; skip rather than ship pinned BTF.
pahole --supported_btf_features 2>/dev/null | grep -qw distilled_base || exit 0

# Fall back to binutils objcopy when llvm-objcopy is missing.
command -v llvm-objcopy > /dev/null 2>&1 || \
	export LLVM_OBJCOPY=${OBJCOPY:-objcopy}

find "${1:-.}" -name '*.ko' -exec \
	pahole -J --btf_features=default,distilled_base \
		--btf_base /sys/kernel/btf/vmlinux {} \;
