#!/bin/sh

set -e

FILENAME=$1

if [ -r ~/.maloorc ] ; then
	source ~/.maloorc
else
	echo "Error: ~/.maloorc not found." \
	     "Please obtain this file from the maloo web interface," \
	     "under 'Upload results'"
	exit 1
fi

if [ -z $FILENAME ] ; then
	echo "Usage: ${0} <tarball or directory>"
	exit 2
fi

if [ ! -r $FILENAME ] ; then
	echo "Input file '$FILENAME' not found"
	exit 3
fi

echo Uploading $FILENAME to $MALOO_URL
if [ -d $FILENAME ] ; then
	pushd $FILENAME
	tar czf upload.tar.gz * |
		curl -F "user_id=${MALOO_USER_ID}" -F "upload=@upload.tar.gz" \
		     -F "user_upload_token=${MALOO_UPLOAD_TOKEN}" ${MALOO_URL} \
		     > /dev/null
	popd
else
	curl -F "user_id=${MALOO_USER_ID}" -F "upload=@${FILENAME}" \
	     -F "user_upload_token=${MALOO_UPLOAD_TOKEN}" ${MALOO_URL} \
	     > /dev/null
fi
echo Complete.
