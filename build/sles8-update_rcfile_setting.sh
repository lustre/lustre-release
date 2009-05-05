# Update the variable $var in $rcfile: The function update_$VAR must
# exist. It is called with the old value of $var, and must return the
# new value.
# 
update_rcfile_setting() {
    local rcfile=$1 var=$2

    # The characters $, `, ", and \ have special meaning inside double
    # quoted shell variables. The characters " and \ have special meaning
    # inside awk double-quoted variables.

    local old=$(source "$rcfile" ;
    		eval echo \$$var \
		| sed -e 's/\([$`"\\]\)/\\\1/g')
    local new=$(eval update_$var "$old" \
    		| sed -e 's/\([$`"\\]\)/\\\1/g' \
		      -e 's/\(["\\]\)/\\\1/g')
    local tmp=$(mktemp /tmp/${rcfile##/*}.XXXXXX)
    
    # This script breaks for multi-line varables -- I don't think
    # we need to handle this special case.
    awk '
	function replace() {
	    if (!done)
		print "'"$var"'=\"'"$new"'\""
	    done=1
	}
	
	/^'"$var"'=/	{ replace() ; next }
			{ print }
    ' < $rcfile > $tmp &&
    cat $tmp > $rcfile

    rm -f $tmp
}
