export PATH="$PATH:./../utils:/r/sbin:/r/usr/bin"

LCTL=${LCTL:-"lctl"}
TMP=${TMP:-"/tmp"}
TARBALL=${TARBALL:-doc.tgz}
DEBUGFS=${DEBUGFS:-debugfs}
MNTPATH=${MNTPATH:-"/mnt/lustre"}
TARCMD=${TARCMD:-"tar"}
UNTARCMD=${UNTARCMD:-"tar -zxvf"}
CPCMD=${CPCMD:-"cp -f"}
CACHEMDS=${CACHEMDS:-$TMP/mds1-`hostname`}
REALMDS=${REALMDS:-$TMP/mds3-`hostname`}

CACHEOST=${CACHEOST:-$TMP/ost1-`hostname`}
REALOST=${REALOST:-$TMP/ost3-`hostname`}

MDS_CMOBD_INDEX=${MDS_CMOBD_INDEX:-12}
OST_CMOBD_INDEX=${OST_CMOBD_INDEX:-14}

MDS_COBD_INDEX=${MDS_COBD_INDEX:-22}
OST_COBD_INDEX=${OST_COBD_INDEX:-19}


if ! [ -e "$TARBALL" ]; then
	echo "$TARBALL does not exist"
fi

show_filesystem() {
	local cache_mds=$1
	local cache_ost=$2

	echo "sleep 20 secs sync fs for show the usages of fs"
	sync
	sleep 20 
	sync
	echo cache_mds: $1
	string=`${DEBUGFS} -R stats $cache_mds | tail -n 2`
	echo $string
	echo cache_ost: $2
	string=`${DEBUGFS} -R stats $cache_ost | tail -n 2`
	echo $string
}

flush_cache() {
${LCTL} << EOF
device $OST_CMOBD_INDEX
lsync
device $MDS_CMOBD_INDEX
lsync 
EOF
}

cobd_cache_off() {
${LCTL} << EOF
device $OST_COBD_INDEX
cache_off
device $MDS_COBD_INDEX
cache_off
EOF
}

cobd_cache_on() {
${LCTL} << EOF
device $OST_COBD_INDEX
cache_on
device $MDS_COBD_INDEX
cache_on
EOF
}
cobd_cache_on
echo "before test ...."
show_filesystem $CACHEMDS $CACHEOST  

#first step cp the tar to cache dev and untar it
echo "cp $TARBALL to lustre dir and untar ..."
${CPCMD} ${TARBALL} ${MNTPATH}	|| exit 1
${UNTARCMD} ${MNTPATH}/`basename ${TARBALL}` -C ${MNTPATH} > /dev/null || exit 2 

#show status of the filesystem
echo after cp show the filsystem....
show_filesystem $CACHEMDS $CACHEOST  
echo .... done!

#second step flush and cache off these file to the real dev
cobd_cache_off
flush_cache  || exit 1
echo "flush these tar and files....."
show_filesystem $CACHEMDS $CACHEOST  
echo .... done!

#third step and write files to real dev
mkdir -p $MNTPATH/new
$CPCMD -f $TARBALL $MNTPATH/new	|| exit 1
$UNTARCMD $MNTPATH/new/`basename $TARBALL` -C $MNTPATH/new > /dev/null || exit 2
show_filesystem $CACHEMDS $CACHEOST  
echo .... done!
