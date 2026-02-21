#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# Embed BTF in Lustre kernel modules, run after kbuild produces the
# .ko.  usage: embed-btf.sh <dir> <linux_obj> <linuxrelease>
#
# kbuild's Makefile.modfinal already encodes module BTF when the build
# tree has a vmlinux, so only the kernel-devel case is handled here.
# The base must be the target kernel's BTF: a module encoded against a
# foreign base fails btf_relocate() at load time and, with
# CONFIG_MODULE_ALLOW_BTF_MISMATCH=n, will not load.  So use
# /sys/kernel/btf/vmlinux only when building for the running kernel,
# and only if that kernel's kbuild uses a distilled base itself (its
# module loader reads .BTF.base).

dir=${1:-.}
linux_obj=$2
linuxrelease=$3

[ -n "$linux_obj" ] || exit 0
[ -f "$linux_obj/vmlinux" ] && exit 0
[ "$linuxrelease" = "$(uname -r)" ] || exit 0
[ -f /sys/kernel/btf/vmlinux ] || exit 0
grep -qw distilled_base "$linux_obj/scripts/Makefile.btf" 2>/dev/null ||
	exit 0

command -v pahole > /dev/null 2>&1 || exit 0

# distilled base needs pahole 1.28+; skip rather than ship pinned BTF.
pahole --supported_btf_features 2>/dev/null | grep -qw distilled_base || exit 0

# Fall back to binutils objcopy when llvm-objcopy is missing.
command -v llvm-objcopy > /dev/null 2>&1 || \
	export LLVM_OBJCOPY=${OBJCOPY:-objcopy}

# Best effort: find runs pahole on every .ko regardless, and a module
# that fails to encode just keeps no BTF -- do not fail the build.
find "$dir" -name '*.ko' -exec \
	pahole -J --btf_features=default,distilled_base \
		--btf_base /sys/kernel/btf/vmlinux {} \; || :
