#!/bin/bash

IDL=../../lustre/include/lustre/lustre_idl.h

idl_types=$(mktemp -t idl_types-XXXX)
idl_types2=$(mktemp -t idl_types2-XXXX)
idl_struct_types=$(mktemp -t idl_struct_types-XXXX)
idl_struct_types2=$(mktemp -t idl_struct_types2-XXXX)
status=0

trap 'rm -f "$idl_types" "$idl_types2" "$idl_struct_types" "$idl_struct_types2"' EXIT

# All named types
egrep '^(struct|union|enum|typedef|#define)' $IDL |
    grep -v '} __attribute__((packed));' |
    grep -v '}__attribute__((packed));' > $idl_types
sed -e '/^#define/s/^#define.\([^ 	]*\).*$/\1/' \
    -e '/^typedef/s/typedef.[^ 	]*[ 	]*\<\(.*\);/\1/' \
    -e '/^struct/s/^struct[ 	]*\([^ 	]*\).*$/\1/' \
    -e '/^enum/s/^enum[ 	]*\([^ 	]*\).*$/\1/' \
    -e '/^typedef enum/s/^typedef enum[ 	]*\([^ 	]*\)[ 	].*/\1/' \
    -e '/^typedef union/s/^typedef union[ 	]*\([^ 	]*\)[ 	].*/\1/' \
    "$idl_types" | grep -v '[()]'  > "$idl_types2"
while read sym; do
        # Ignore the #define for the header guard
        [[ "$sym" = _LUSTRE_IDL_H_ ]] && continue
        grep -q "$sym" wirecheck.c || echo "Missing wirecheck for $sym"
done < "$idl_types2"

# Just struct types (the grep -v ';' part ignores incomplete structs; we can't
# check those).
grep '^struct' $IDL | grep -v ';' > "$idl_struct_types"
sed -e '/^struct/s/^struct[ 	]*\([^ 	]*\).*$/\1/' \
    "$idl_struct_types" | grep -v '[()]'  > "$idl_struct_types2"
while read sym; do
        grep -q "$sym" wirecheck.c && continue
        status=1
        echo "Missing wirecheck for struct $sym"
done < "$idl_struct_types2"

# Reflect only missing structs, for now.
exit $status
