#
# Source this file. It will craft a usable name space for your testing.
#
# Lee; Sun Feb  8 18:02:16 EST 2004
#
# Note: We really should support symlinks someday.
#
unset _root_flags
unset _extras
if [ "x${SYSIO_AUTOMOUNT}" == "xyes" ]; then
	_root_flags="2"
	#
	# Add a /auto directory for automounted file systems. We
	# craft one automount that mounts /usr/home from the native
	# file system. Further automounts in the sub-mounts are not enabled.
	#
	_extras=" \
		{mnt,	dev=\"incore:0755+0+0\",dir=\"/mnt\",fl=2} \
		{creat, ft=dir,nm=\"/mnt/home\",pm=04755,ow=0,gr=0} \
		{creat, ft=file,nm=\"/mnt/home/.mount\",pm=0600, \
			str=\"native:/home\"} \
	"
fi
export SYSIO_NAMESPACE="\
	{mnt,	dev=\"native:/\",dir=/,fl=${_root_flags:-0}} \
	{mnt,	dev=\"incore:0755+0+0\",dir=\"/dev\"} \
	{creat,	ft=chr,nm=\"/dev/stdin\",pm=0400,mm=0+0} \
	{creat,	ft=chr,nm=\"/dev/stdout\",pm=0200,mm=0+1} \
	{creat,	ft=chr,nm=\"/dev/stderr\",pm=0200,mm=0+2} \
	{creat,	ft=dir,nm=\"/dev/fd\",pm=0755,ow=0,gr=0} \
	{creat,	ft=chr,nm=\"/dev/fd/0\",pm=0400,mm=0+0} \
	{creat,	ft=chr,nm=\"/dev/fd/1\",pm=0200,mm=0+1} \
	{creat,	ft=chr,nm=\"/dev/fd/2\",pm=0200,mm=0+2} \
	{cd,	dir=\"$HOME\"} \
	${_extras} \
"
unset _root_flags
unset _extras
