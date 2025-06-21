#!/bin/bash

# Generate a man page with section-specific content
# Usage: ./generate_manpage.sh NAME SECTION [OUTPUT_FILE]
# Usage: ./generate_manpage.sh MANUAL_FILE

show_usage() {
	cat >&2 <<EOF
Usage: $0 NAME (1-8) [OUTPUT_FILE]
       $0 [DIR/]NAME.(1-8)
EOF
}

if (( $# < 1 )); then
	echo "Error: Missing arguments" >&2
	show_usage
	exit 1
elif (( $# == 1 )); then
	if [[ "$1" =~ ^([^.]*/)?(.*)\.([1-8])$ ]]; then
		NAME="${BASH_REMATCH[2]}"
		SECTION="${BASH_REMATCH[3]}"
		OUTPUT="$1"
	else
		echo "Error: $1 must be in NAME.SECTION format (SECTION 1-8)" >&2
		show_usage
		exit 1
	fi
elif (( $# == 2 )); then
	NAME="$1"
	SECTION="$2"
	OUTPUT="Documentation/man$SECTION/$NAME.$SECTION"
elif (( $# == 3 )); then
	NAME="$1"
	SECTION="$2"
	OUTPUT="$3"
else
	echo "Error: Too many arguments" >&2
	show_usage
	exit 1
fi

# Validate section number
if ! [[ "$SECTION" =~ ^[1-8]$ ]]; then
	echo "Error: Section must be between 1 and 8" >&2
	show_usage
	exit 1
fi

# Check if Documentation/man$SECTION folder exists when using default output path
if [[ "$OUTPUT" == Documentation/man$SECTION/* ]]; then
	if [[ ! -d "Documentation/man$SECTION" ]]; then
		echo "Error: Documentation/man$SECTION does not exist" >&2
		echo "Please create the directory first or specify a custom output file" >&2
		exit 1
	fi
fi

# Don't overwrite non-empty files
if [[ -s $OUTPUT ]]; then
	echo "Error: $OUTPUT is not empty"
	exit 1
fi

LCTL=$(find ../.. -name lctl -type f -executable 2>/dev/null | head -1)
DATE=$(date +"%Y-%m-%d")

# Section-specific content
case $SECTION in
	1)
	DESC="Lustre User Utilities"
	;;
	2)
	DESC="Lustre System Calls"
	;;
	3)
	DESC="Lustre Library Functions"
	;;
	4)
	DESC="Lustre Kernel Interfaces"
	;;
	5)
	DESC="Lustre File Formats"
	;;
	6)
	DESC="Lustre Games"
	;;
	7)
	DESC="Lustre Miscellaneous Information"
	;;
	8)
	DESC="Lustre Configuration Utilities"
	;;
esac

case $SECTION in
	1|8)
	SYNOPSIS=$(cat <<EOF
.SY "${NAME//_/ }"

.YS
EOF
	)
	printf -v OPTIONS "\n.SH OPTIONS\n"
	printf -v EXAMPLES "\n.SH EXAMPLES\n"
	;;
	2|3)
	SYNOPSIS=$(cat <<EOF
.nf
.B #include
.PP
.BI "RETURN_TYPE $NAME( ... );
.fi
EOF
	)
	printf -v EXIT_STATUS "\n.SH EXIT_STATUS\n"
	printf -v RETURN_VALUE "\n.SH RETURN_VALUE\n"
	printf -v ERRORS "\n.SH ERRORS\n"
	;;
	4)
	if [[ $NAME =~ "lctl-param-" ]]; then
		NAME=${NAME/lctl-param-/}
		[[ -n "$($LCTL get_param -r "$NAME")" ]] || {
			echo "could not read parameter: '$NAME'"
			exit 1
		}
		[[ "$(git grep PARM_DESC 82f2bdb17ae~1 -- | grep "$NAME",)" =~ $NAME,\ \"([^\"]+)\" ]] &&
			NAMEDESC=" ${BASH_REMATCH[1]}"
		printf -v PARAM ".EX\n$($LCTL get_param ${NAME//.-/.*})\n.EE"
		param_path=$($LCTL list_param -p ${NAME//.-/.*})
		printf -v FILES "\n.SH FILES\nThis parameter is located at:\n.P\n.B $param_path"
		# actual path
		param_path=$(readlink -f $param_path)
		code_location=$(git grep -E "LDEBUGFS_SEQ_FOPS|LUSTRE_[RW][OW]_ATTR" 82f2bdb17ae~1 -- | grep ${NAME##*\.})
		printf -v SYNOPSIS ".SY \"lctl set_param\"\n.YS
.SS PROPERTIES
.TP\n.B Perms\n.BR $(stat -c "%a" $param_path) \" | \" $(ls -l $param_path | awk '{print $1}')
[.PP param resets upon write]
.TP\n.B Scope\nPer-Device | Global
.TP\n.B Config\nalways present | present if ...
.B PARAMETER DECLARATION POTENTIAL LOCATIONS
.PP\nlocated at:\n.EX\n$code_location\n.EE"
	fi
	printf -v EXAMPLES "\n.SH EXAMPLES\n$PARAM"
	;;
esac


# Generate the man page
cat > "$OUTPUT" <<EOF
.TH ${NAME^^} $SECTION $DATE Lustre "$DESC"
.SH NAME
$NAME \-$NAMEDESC$LIBRARY
.SH SYNOPSIS
$SYNOPSIS$CONFIGURATION
.SH DESCRIPTION
$OPTIONS$EXIT_STATUS$RETURN_VALUE$ERRORS$ENVIRONMENT$FILES$ATTRIBUTES$VERSIONS$HISTORY$NOTES$CAVEATS$BUGS$EXAMPLES
.SH AVAILABILITY
.B $NAME
is part of the
.BR lustre (7)
filesystem package.
.\" commit #
.SH SEE ALSO
EOF

echo "Generated man page: $OUTPUT"
