. $LUSTRE/tests/cfg/local.sh

CLIENT1=${CLIENT1:-`hostname`}
SINGLECLIENT=$CLIENT1
RCLIENTS=${RCLIENTS:-""}

init_clients_lists

[ -n "$RCLIENTS" -a "$PDSH" = "no_dsh" ] && \
                error "tests for remote clients $RCLIENTS needs pdsh != do_dsh " || true

[ -n "$FUNCTIONS" ] && . $FUNCTIONS || true

# for recovery scale tests
# default boulder cluster iozone location
export PATH=/opt/iozone/bin:$PATH

# This is used by a small number of tests to share state between the client
# running the tests, or in some cases between the servers (e.g. lfsck.sh).
# It needs to be a non-lustre filesystem that is available on all the nodes.
SHARED_DIRECTORY=${SHARED_DIRECTORY:-""}	# bug 17839 comment 65

LOADS=${LOADS:-"dd tar dbench iozone"}
for i in $LOADS; do
    [ -f $LUSTRE/tests/run_${i}.sh ] || \
        error "incorrect load: $i"
done
CLIENT_LOADS=($LOADS)

# This is used when testing on SLURM environment.
# Test will use srun when SRUN_PARTITION is set
SRUN=${SRUN:-$(which srun 2>/dev/null)}
SRUN_PARTITION=${SRUN_PARTITION:-""}
SRUN_OPTIONS=${SRUN_OPTIONS:-"-W 1800 -l -O"}
