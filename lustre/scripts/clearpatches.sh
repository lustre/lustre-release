SERIESPATH=./series
PATCHESPATH=./patches
NOUSEPATH=./nousepatches

mkdir -p $NOUSEPATH
for PATCH in `ls $PATCHESPATH` ; do
	echo $PATCH
 	if ! grep -r $PATCH $SERIESPATH ; then
		echo "$PATCH was not in use !"
	  	mv $PATCHESPATH/$PATCH $NOUSEPATH
	fi
done
