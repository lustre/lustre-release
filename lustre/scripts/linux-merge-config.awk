#!/bin/awk -f
BEGIN {
	nsects = 0
}
{
	ARCH = $1
	ARCHES[ARCH] = 1
	TYPE = $2
	TYPES[TYPE] = 1
	NTOTAL++
	ARCHTYPES[ARCH ":" TYPE] = 1
	NARCHES[TYPE]++
	if (NARCHES[TYPE] == 1)
	    NTOTALTYPES++
	NTYPES[ARCH]++
	if (NTYPES[ARCH] == 1)
	    NTOTALARCHES++
	FILE = $3
	cursects = nsects
	while ((getline < FILE) > 0) {
		if ($0 ~ /^\/\*/ || $0 ~ /^ \*\// || $0 ~ /^[ 	]*$/)
			continue
		if ($0 ~ /^ * /) {
			SECTION = gensub(/^ \* /,"",$0)
			if (!(SECTION in sectno)) {
				sectno[SECTION] = nsects
				counts[SECTION] = 0
				nsects++
			} else if (cursects && cursects != nsects) {
				no = sectno[SECTION]
				diff = nsects - cursects
				for (s in sectno) {
					if (sectno[s] >= cursects)
						sectno[s] = sectno[s] - cursects + no
					else if (sectno[s] >= no)
						sectno[s] += diff
				}
			}
			cursects = nsect
			cursym[SECTION] = counts[SECTION]
			continue
		}
		if ($1 != "#define" && $1 != "#undef")
			exit 1
		SYMBOL = $2
		n = index($0,SYMBOL)+length(SYMBOL)
		if ($1 == "#define") {
			n = index($0,SYMBOL)+length(SYMBOL)
			VALUE = gensub(/^[ 	]*/,"","",substr($0,n))
			if (VALUE == "") VALUE = "__novalue__"
		} else
			VALUE = "__undefined__"
		if (values[SYMBOL]) {
			if (present[SYMBOL,ARCH,TYPE]) continue
			present[SYMBOL,ARCH,TYPE] = 1
			values[SYMBOL] = values[SYMBOL] SUBSEP ARCH ":" TYPE ":" VALUE
			if (SECTION == sections[SYMBOL] && cursym[SECTION] && cursym[SECTION] != counts[SECTION]) {
				no = pos[SYMBOL]
				diff = counts[SECTION]-cursym[SECTION]
				for (s in pos)
					if (sections[s] == SECTION) {
						if (pos[s] >= cursym[SECTION])
							pos[s] = pos[s] - cursym[SECTION] + no
						else if (pos[s] >= no)
							pos[s] += diff
					}
				cursym[SECTION] = counts[SECTION]
			}
		} else {
			present[SYMBOL,ARCH,TYPE] = 1
			values[SYMBOL] = ARCH ":" TYPE ":" VALUE
			sections[SYMBOL] = SECTION
			pos[SYMBOL] = counts[SECTION]
			counts[SECTION]++
		}
	}
	close(FILE)
}
END {
	for (SECTION in sectno)
		x[sectno[SECTION]] = SECTION
	for (i = 0; i < nsects; i++) {
		SECTION = x[i]
		if (i > 0)
			printf "\n"
		printf "/*\n * %s\n */\n", SECTION
		split("",lines)
		lastelse = ""
		for (SYMBOL in sections)
			if (sections[SYMBOL] == SECTION)
				y[pos[SYMBOL]] = SYMBOL
		for (j = 0; j < counts[SECTION]; j++) {
			SYMBOL = y[j]
			split("",ntype)
			split("",total)
			split(values[SYMBOL],z,SUBSEP)
			split("",val)
			totalsum = 0
			for (k in z) {
				split(z[k],l,":")
				ARCH = l[1]
				TYPE = l[2]
				VALUE = substr(z[k],length(ARCH)+length(TYPE)+3)
				if (val[VALUE])
					val[VALUE] = val[VALUE] " "
				val[VALUE] = val[VALUE] ARCH ":" TYPE
				ntype[VALUE,TYPE] += 1
				total[VALUE] += 1
				totalsum += 1
			}
			split("",curlines)
			append = 1
			for (VALUE in val) {
			    if (total[VALUE] == NTOTAL) {
				if (VALUE == "__undefined__")
				    curlines["1"] = "#undef  " SYMBOL "\n"
				else if (VALUE == "__novalue__")
				    curlines["1"] = "#define " SYMBOL "\n"
				else
				    curlines["1"] = "#define " SYMBOL " " VALUE "\n"
				if (!lines["1"])
				    append = 0
				break
			    }
			    shorteststr = ""
			    curcount = 0
			    for (m = 0; m < 4; m++) {
				str = ""
				split(val[VALUE],yy)
				if (total[VALUE] > 1 && total[VALUE] == NTOTAL - 1) {
				    found = 0
				    for (arch in ARCHES) {
					for (type in TYPES) {
					    archtype = arch ":" type
					    if (ARCHTYPES [archtype] == 1) {
						for (n in yy)
						    if (yy[n] == archtype)
							break
						if (yy[n] != archtype) {
						    found = 1
						    break
						}
					    }
					}
					if (found)
					    break
				    }
				    if (NARCHES[type] > 1 && NTYPES[arch] > 1) {
					str = "!defined(__module__" arch "_" type ")"
					shorteststr = str
					break
				    }
				}
				if (m == 0 || m == 2) {
				    nfull = 0
				    split("",yysave)
				    for (type in TYPES)
					if (ntype[VALUE,type] == NARCHES[type]) {
					    if (str) str = str " || "
					    str = str "defined(__module__" type ")"
					    for (k in yy) {
						split(yy[k], z, ":")
						if (z[2] == type) {
						    yysave[k] = yy[k]
						    delete yy[k]
						}
					    }
					    nfull++
					} else
					    NOTYPE = type
				    if (m < 2 && nfull > 1 && nfull == NTOTALTYPES - 1) {
					str = "!defined(__module__" NOTYPE ")"
					for (k in yysave)
					    yy[k] = yysave[k]
					for (k in yy) {
					    split(yy[k], z, ":")
					    if (z[2] != NOTYPE)
						delete yy[k]
					}
				    }
				}
				savestr = str
				nfull = 0
				split("",yysave)
				for (arch in ARCHES) {
				    narch = 0
				    for (k in yy) {
					split(yy[k], z, ":")
					if (z[1] == arch)
					    narch++
				    }
				    if (narch == NTYPES[arch]) {
					if (str) str = str " || "
					str = str "defined(__module__" arch ")"
					for (k in yy) {
					    split(yy[k], z, ":")
					    if (z[1] == arch) {
						yysave[k] = yy[k]
						delete yy[k]
					    }
					}
					nfull++
				    } else
					NOARCH = arch
				}
				if (m < 2 && nfull > 1 && nfull == NTOTALARCHES - 1) {
				    str = savestr
				    for (k in yysave)
					yy[k] = yysave[k]
				    if (str) str = str " || "
				    str = str "!defined(__module__" NOARCH ")"
				    for (k in yy) {
					split(yy[k], z, ":")
					if (z[1] != NOARCH)
					    delete yy[k]
				    }
				}
				if (m == 1 || m == 3) {
				    savestr = str
				    nfull = 0
				    split("",yysave)
				    for (type in TYPES) {
					ntypex = 0
					for (k in yy) {
					    split(yy[k], z, ":")
					    if (z[2] == type)
						ntypex++
					}
					if (ntypex == NARCHES[type]) {
					    if (str) str = str " || "
					    str = str "defined(__module__" type ")"
					    for (k in yy) {
						split(yy[k], z, ":")
						if (z[2] == type) {
						    yysave[k] = yy[k]
						    delete yy[k]
						}
					    }
					    nfull++
					} else
					    NOTYPE = type
				    }
				    if (m < 2 && nfull > 1 && nfull == NTOTALTYPES - 1) {
					str = savestr
				 	for (k in yysave)
					    yy[k] = yysave[k]
					if (str) str = str " || "
					str = "!defined(__module__" NOTYPE ")"
					for (k in yy) {
					    split(yy[k], z, ":")
					    if (z[2] != NOTYPE)
						delete yy[k]
					}
				    }
				}
				for (k in yy) {
				    split(yy[k], z, ":")
				    if (str) str = str " || "
				    str = str "defined(__module__" z[1] "_" z[2] ")"
				}
				if (m == 0 || length(str) < length(shorteststr))
				    shorteststr = str
			    }
			    str = shorteststr
			    if (VALUE == "__undefined__")
				curlines[str] = "#undef  " SYMBOL "\n"
			    else if (VALUE == "__novalue__")
				curlines[str] = "#define " SYMBOL "\n"
			    else
				curlines[str] = "#define " SYMBOL " " VALUE "\n"
			    if (!lines[str])
				append = 0
			}
			if (append) {
			    for (str in curlines)
				if (curlines[str])
				    lines[str] = lines[str] curlines[str]
			} else {
			    if (lines["1"])
				printf "%s", lines["1"]
			    else if (j > 0) {
				ifstr = "#if "
				for (str in lines)
				    if (lines[str] && str != lastelse) {
					printf "%s %s\n%s", ifstr, str, lines[str]
					ifstr = "#elif "
				    }
				if (lastelse != "")
				    printf "#else\n%s", lines[lastelse]
				printf "#endif\n"
			    }
			    split("",lines)
			    lastelse = ""
			    for (str in curlines)
				if (curlines[str]) {
				    lines[str] = curlines[str]
				    if (totalsum == NTOTAL && length(str) > length(lastelse)) {
					lastelse = str
				    }
				}
			}
		}
		if (lines["1"])
		    printf "%s", lines["1"]
		else if (j > 0) {
		    ifstr = "#if "
		    for (str in lines)
			if (lines[str] && str != lastelse) {
			    printf "%s %s\n%s", ifstr, str, lines[str]
			    ifstr = "#elif "
			}
		    if (lastelse != "")
			printf "#else\n%s", lines[lastelse]
		    printf "#endif\n"
		}
	}
}
