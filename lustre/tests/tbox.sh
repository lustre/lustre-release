# tbox.sh - Shell functions to manage tinderbox build reporting
# Copyright (C) 2002  Cluster File Systems, Inc.
# Gord Eagle <gord@clusterfs.com>, 2002-08-22

HOSTNAME=`hostname`
PROGNAME=`echo "$0" | sed -e 's%^.*/%%'`
MAILPROG="${MAILPROG-mail}"

TBOX_PHASE=build # or test
TBOX_STARTTIME=`date +%s`
TBOX_LOG="${TBOX_LOG-/tmp/tbox.$$.$TBOX_STARTTIME.log}"
TBOX_BUILDMAIL=tinderbox_builds@lustre.org
TBOX_BUILDNAME="${TBOX_BUILDNAME-$PROGNAME-$HOSTNAME}"

# Send a status message to the list.
tbox_status() {
  [ -n "$TBOX_BUILDNAME" -a -n "$TBOX_BUILDMAIL" ] || return 0
  [ "$#" -ge 4 ] || return 1
  if [ "$#" -gt 4 ]; then
    log="$5"
    echo >> $log
  else
    log=
  fi

  TREE="$1"
  SUBJECT="$2"
  STATUS="$3"
  TIMENOW="$4"

  echo "sending tinderbox mail to $TBOX_BUILDMAIL: $TREE $SUBJECT $STATUS"

  TMPFILE="/tmp/tinderbox.boilerplate.$$.$TIMENOW"

  cat > $TMPFILE <<-EOF
  tinderbox: tree: $TREE
  tinderbox: starttime: $TBOX_STARTTIME
  tinderbox: timenow: $TIMENOW
  tinderbox: builddate: $TBOX_STARTTIME
  tinderbox: status: $STATUS
  tinderbox: buildname: $TBOX_BUILDNAME
  tinderbox: errorparser: unix
  tinderbox: END

EOF

  cat $TMPFILE $log | $MAILPROG -s "build $SUBJECT ($TBOX_BUILDNAME)" $TBOX_BUILDMAIL
  rm -f $TMPFILE
}

# Send out the failure or success message based on exit status.
tbox_exit() {
  TREE="$1"
  TAILPID="$2"
  CODE=${3-$?}
  if [ $CODE -eq 0 ]; then
    SUBJECT=successful
    STATUS=success
  else
    SUBJECT=failed
    STATUS="${TBOX_PHASE}_failed"
  fi

  # Send off the status message.
  trap 0
  tbox_status "$TREE" "$SUBJECT" "$STATUS"
  rm -f $TBOX_LOG

  # Wait for tail to display all output, then finish it.
  sleep 1
  kill $TAILPID
  exit $CODE
}

# Run a subprogram, but stop it from sending its own tinderbox
# messages.
tbox_dont_start_log() {
  eval 'TBOX_LOG= '"$@"
}

# Start the log for a given tree.
tbox_start_log() {
  TREE="$1"

  # Send status messages to stdout, stderr.
  exec 6>&1 7>&2

  [ -n "$TBOX_LOG" ] || return 0

  # Initialize the output log file.
  : > $TBOX_LOG

  # Send all our output to the log.
  exec >>$TBOX_LOG 2>&1

  # Monitor it on the old stdout.
  tail -f $TBOX_LOG 1>&6 &

  # Allow tail to print our last output before exiting.
  trap "tbox_exit \"$TREE\" $! 1" 1 2 10 15
  trap "tbox_exit \"$TREE\" $!" 0
}


# Begin writing to the log and send out the initial status.
# tbox_start TREE
tbox_start() {
  TREE="$1"
  tbox_start_log "$TREE"
  tbox_status "$TREE" starting building "$TBOX_STARTTIME"
}
