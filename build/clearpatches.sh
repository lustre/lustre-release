BASEDIR=${BASEDIR:-lustre/kernel_patches}
SERIESPATH=${SERIESPATH:-$BASEDIR/series}
PATCHESPATH=${PATCHESPATH:-$BASEDIR/patches}
NOUSEPATH=${NOUSEPATH:-$BASEDIR/unused}

#mkdir -p $NOUSEPATH
for PATCH in `ls $PATCHESPATH | grep -v CVS` ; do
	#echo $PATCH
 	if ! grep -rq $PATCH $SERIESPATH ; then
		echo "$PATCH"
	  	#mv $PATCHESPATH/$PATCH $NOUSEPATH
	fi
done
