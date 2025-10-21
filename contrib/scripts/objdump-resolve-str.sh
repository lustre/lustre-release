#!/bin/sh

function usage() {
	echo "Usage: $0 .."
	exit 1
}

function error() {
	echo $*
	exit 1
}

TGT=$1
[[ -z $TGT ]] && usage $*

which readelf >&/dev/null || error "install readelf"
which objdump >&/dev/null || error "install objdump"

declare -A section2num
declare -A strings

while read snum sname ooo; do
	snum=${snum//[/}
	snum=${snum//]/}
	sections="$sections $sname"
	section2num[$sname]=$snum
done <<< $(readelf -S $TGT | grep .rodata.str)

for i in $sections; do
	#echo "$i -> ${section2num[$i]}"
	while read br offset str; do
		offset=${offset//]/}
		strings[${i}+0x${offset}]=$str
	done <<< $( readelf -p ${section2num[$i]} $TGT)
done

# 12680: R_X86_64_64 .rodata.str1.8+0x38e0
nr=10
while read -r str; do
	[[ $str == *.rodata.str* ]] && {

		echo -en "\t\t\t\t$str"
		str=${str//*.rodata.str/}
		str=".rodata.str${str}"
		#echo -n "$str --- "
		echo "  # ${strings[$str]}"
		#(( nr-- == 0 )) && break
		continue
	}
	[[ $str == *R_X86_64* ]] && echo -en "\t\t\t\t"
	echo $str
done <<< $(objdump --prefix-addresses -gDr $TGT)

