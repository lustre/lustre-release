#!/usr/bin/env bash

# Generate a man page with section-specific content

show_usage() {
	cat >&2 <<EOF
Usage: $0 [-o OUTPUT_FILE] COMMAND_NAME {1-8}
       $0 [-o OUTPUT_FILE] --param MODULE.PARAM
EOF
}

PATH=$(dirname $0)/../../lustre/utils:$PWD/lustre/utils:$PATH
PARAM=0
for arg in "$@"; do
	shift
	case "$arg" in
		-o)
			OUTPUT="$1"
			shift
			;;
		-p|--param)
			SECTION=4
			PARAM=1
			;;
		*)
			set -- "$@" "$arg"
			;;
	esac
done
if (( $# < 1 )); then
	echo "Error: Missing parameters" >&2
	show_usage
	exit 1
elif (( $# > 2 )); then
	echo "Error: Too many arguments" >&2
	show_usage
	exit 1
fi
NAME="$1"
[[ -n "$SECTION" ]] || SECTION="$2"
[[ -n "$OUTPUT" ]] || OUTPUT="Documentation/man$SECTION/${NAME//.\*}.$SECTION"

# Validate section number
if ! [[ "$SECTION" =~ ^[1-8]$ ]]; then
	echo "Error: Section must be between 1 and 8" >&2
	show_usage
	exit 1
fi

# Check if Documentation/man$SECTION folder exists when using default output path
if [[ "$OUTPUT" == Documentation/man$SECTION/* ]]; then
	if [[ ! -d "Documentation/man$SECTION" ]]; then
		echo "Error: Documentation/man$SECTION directory missing." >&2
		echo "Please create it first or specify output filename." >&2
		exit 1
	fi
fi

# Don't overwrite non-empty files
if [[ -s $OUTPUT ]]; then
	echo "error: $OUTPUT exists. If you want to recreate it, remove first."
	exit 1
fi

DATE=$(date +"%F")

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
	DESC="Lustre Parameter Files"
	;;
	5)
	DESC="Lustre File Formats"
	;;
	6)
	DESC="Lustre Games???"
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
	if (( PARAM )); then
		opts="--only-name --dshbak --no-links"
		which lctl
		PARAM=($(lctl find_param $opts ${NAME//./[.]?[^.]*[.]}))
		[[ -n "$PARAM" ]] || {
			opts+=" --module"
			PARAM=($(lctl find_param $opts ${NAME//./[.]?[^.]*[.]}))
		}
		[[ -n "$PARAM" ]] || {
			echo "Error: Parameter $NAME not found" >&2
			exit 1
		}
		NAMEDESC=$(git grep "PARM_DESC.${PARAM##*.}," |
			   sed -e 's/.*, \"//' -e 's/\");$//')
		param_modules=$(lctl find_param $opts ${NAME//./[.]?[^.]*[.]} |
				awk '{print ".B "$1}')
		printf -v FILES "\n.SH MODULES
This parameter is in the following modules:
.EX
$param_modules
.EE"
		# actual path
		param_path=($(readlink -f $(lctl find_param ${opts} --path $NAME)))
		PARAM=$(lctl get_param $PARAM 2> /dev/null)
		printf -v SYNOPSIS ".SY \"lctl set_param\"
.YS
.SS PROPERTIES
.TP
.B Perms
.BR $(stat -c "%a | %A" $param_path)
.br
[
.PP
param resets upon write
.br
]
.TP
.B Scope
Per-Device | Global
.TP
.B Config
always present | present if ...
.br
[
.TP
.B Default
.RB param= DEFAULT
.br
]"
	fi

	printf -v EXAMPLES "\n.SH EXAMPLES\n.EX\n$PARAM\n.EE"
	;;
esac

# Generate the man page
cat > "$OUTPUT" <<EOF
.TH ${NAME^^} $SECTION $DATE Lustre "$DESC"
.SH NAME
${NAME//.\*} \-$NAMEDESC
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
