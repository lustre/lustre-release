BASEDIR=${BASEDIR:-lustre/kernel_patches}
SERIESPATH=${SERIESPATH:-$BASEDIR/series}
PATCHESPATH=${PATCHESPATH:-$BASEDIR/patches}
for SERIES in `ls $SERIESPATH | egrep -v "CVS|~$|.orig"` ; do
	#echo $SERIES
	for PATCH in `cat $SERIESPATH/$SERIES`; do
		#echo $PATCH
		if [ ! `find $PATCHESPATH -name $PATCH` ]; then
			echo "$SERIESPATH/$SERIES: patch $PATCH was not found !"
		fi
	done
done
