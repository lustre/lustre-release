#!/bin/bash

fail()
{
	echo "ERROR: $@"
	exit 1
}

check_xattr()
{
	name=$1
	value=$2
	file="$3"
	
	if test "x$value" != "x<deleted>"; then
		res=`$getattr -n $name $file 2>/dev/null | grep -v "^#" | sed 's/\"//g'`
	
		if test "x$res" = "x$name=$value"; then
			return 0
		else
			return 1
		fi
	else
		res=`$getattr -d -m ".*" $file 2>/dev/null | grep -v "^#" | sed 's/\"//g'`
		
		if echo $res | grep $name > /dev/null 2>&1; then
			return 1
		else
			return 0
		fi
	fi
}

test_del_xattr()
{
	name=$1
	file=$2
	message=$3

	echo -n "$message..."
	`$setattr -x $name $file 2> /dev/null`
	
	if test "x$?" != "x0"; then
		echo "failed"
		return 1
	else
		check_xattr $name "<deleted>" $file && echo "done" || echo "failed"
		return 0
	fi
}

test_set_xattr()
{
	name=$1
	value=$2
	file=$3
	message=$4

	echo -n "$message..."
	`$setattr -n $name -v $value $file 2>/dev/null`

	if test "x$?" != "x0"; then
		echo "failed"
		return 1
	else
		check_xattr $name $value $file && echo "done" || echo "failed"
		return 0
	fi
}

test_list_xattr()
{
	file=$1
	message=$2

	echo -n "$message..."
	`$setattr -n list_name0 -v list_value0 $file 2>/dev/null`
	`$setattr -n list_name1 -v list_value1 $file 2>/dev/null`
	`$setattr -n list_name2 -v list_value2 $file 2>/dev/null`

	values=`$getattr -d -m ".*" $file 2>/dev/null | grep -v "^#" | \
grep list_name | sed 's/\"//g'`

	i=0
	
	for chunk in $values; do
		if test "x$chunk" != "xlist_name$i=list_value$i"; then
			echo "failed"
			return 1
		fi
		
		let i=$i+1
	done
		
	echo "done"
	return 0
}

# check each function related to xattrs
test_individual()
{
	file="$1"

	test_set_xattr test_name0 test_value0 $file "Create new attribute" &&
	test_set_xattr test_name0 test_value012345 $file "Expanding attribute" &&
	test_set_xattr test_name0 test_value0 $file "Shrinking attribute" &&
	test_del_xattr test_name0 $file "Delete attribute"
	test_list_xattr $file "Getting list of attributes"
}

# checking xattr code as whole working. Not implemented yet.
test_composite()
{
	return 0
}

getattr=$(which getfattr 2>/dev/null)
setattr=$(which setfattr 2>/dev/null)

if test "x$getattr" = "x" -o "x$setattr" = "x"; then
	fail "Can't find getfattr or setfattr utilities in current path."
fi

if ! mount | grep tmpfs > /dev/null 2>&1; then
	fail "tmpfs is not mounted"
fi
	
mntpoint=$(mount | grep tmpfs | awk '{print $3}')

if test "x$mntpoint" = "x"; then
	fail "Can't find tmpfs mount point"
fi

rm -fr $mntpoint/test_file0 2> /dev/null
touch "$mntpoint/test_file0"

test_individual "$mntpoint/test_file0" && 
test_composite "$mntpoint/test_file0" && echo "All tests passed"
