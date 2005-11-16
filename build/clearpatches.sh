SERIESPATH=./series
PATCHESPATH=./patches
NOUSEPATH=./nousepatches

#mkdir -p $NOUSEPATH
for PATCH in `ls $PATCHESPATH | grep -v CVS` ; do
	#echo $PATCH
 	if ! grep -rq $PATCH $SERIESPATH ; then
		echo "$PATCH"
	  	#mv $PATCHESPATH/$PATCH $NOUSEPATH
	fi
done
