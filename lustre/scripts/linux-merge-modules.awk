#!/bin/awk -f
{
	# lines in input look like ARCH TYPE path/to/TYPE/ARCH/modules/foo.ver
	ARCH=$1
	ARCHES[ARCH]=1
	TYPE=$2
	TYPES[TYPE]=1
	NTOTAL++
	NARCHES[TYPE]++
	NTYPES[ARCH]++
	FILE=$3

	# read files that look like pairs of repeating
	# #define __ver_foo hexstring
	# #define foo _set_ver(foo)
	while ((getline < FILE) > 0) {
		if ($0 ~ /^[ 	]*$/)
			continue
		if ($1 != "#define" || $2 !~ /^__ver_/)
			exit 1

		# this is a "#define __ver_foo somehex" line
		SYMBOL=gensub(/^__ver_/,"","",$2)
		VALUE=gensub(/^(smp_|2gig_|smp2gig_)/,"","",$3)
		VALUE=gensub(/^(smp|2gig|smp2gig)/,"","",VALUE)
		values[SYMBOL,ARCH,TYPE]=VALUE

		# skip the "#define foo _set_ver(foo)" line
		if ((getline < FILE) <= 0)
			exit 2
		if ($1 != "#define" || $2 != SYMBOL || $3 != "_set_ver(" SYMBOL ")")
			exit 3
	}
	close(FILE)
}
END {
	count=0
	for (key in values)
		if (values[key]) {
			count++
			split(key,x,SUBSEP)
			SYMBOL=x[1]
			ARCH=x[2]
			TYPE=x[3]

			# (re)initialize a few arrays to have no elements
			split("",x)
			split("",ntype)
			split("",total)

			totalsum=0
			for (arch in ARCHES)
			    for (type in TYPES)
				if (values[SYMBOL,arch,type]) {
				    VALUE = values[SYMBOL,arch,type]
				    values[SYMBOL,arch,type] = ""
				    ntype[VALUE,type] += 1
				    total[VALUE] += 1
				    if (x[VALUE])
					x[VALUE] = x[VALUE] " "
				    x[VALUE] = x[VALUE] arch ":" type
				}
			ifstr="#if "
			for (VALUE in x) {
			    if (total[VALUE] == NTOTAL) {
				# there is only one checksum for this symbol
				printf "#define __ver_%s\t_ver_str(%s)\n", SYMBOL, VALUE
				printf "#define %s _set_ver(%s)\n", SYMBOL, SYMBOL
				break
			    }

			    totalsum += total[VALUE]
			    if (totalsum == NTOTAL && ifstr == "#elif") {
				# this is the last unique checksum for this symbol
				printf "#else\n#define __ver_%s\t_ver_str(%s)\n", SYMBOL, VALUE
				printf "#define %s _set_ver(%s)\n", SYMBOL, SYMBOL
				break
			    }

			    # there must be more than one checksum still to
			    # print for this symbol
			    str=""
			    split(x[VALUE],y)
			    for (type in TYPES)
				if (ntype[VALUE,type] == NARCHES[type]) {
				    if (str) str = str " || "
				    str = str "defined(__module__" type ")"
				    for (k in y) {
					split(y[k], z, ":")
					if (z[2] == type)
					    delete y[k]
				    }
				}
			    for (arch in ARCHES) {
				narch=0
				for (k in y) {
				    split(y[k], z, ":")
				    if (z[1] == arch)
					narch++
				}
				if (narch == NTYPES[arch]) {
				    if (str) str = str " || "
				    str = str "defined(__module__" arch ")"
				    for (k in y) {
					split(y[k], z, ":")
					if (z[1] == arch)
					    delete y[k]
				    }
				}
			    }
			    for (k in y) {
				split(y[k], z, ":")
				if (str) str = str " || "
				str = str "defined(__module__" z[1] "_" z[2] ")"
			    }
			    printf "%s %s\n#define __ver_%s\t_ver_str(%s)\n", ifstr, str, SYMBOL, VALUE
			    printf "#define %s _set_ver(%s)\n", SYMBOL, SYMBOL
			    ifstr="#elif "
			}
			if (ifstr == "#elif ")
			    printf "#endif\n"
		}
	if (!count)
		printf "\n"
}
