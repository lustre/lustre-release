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

LOADS=${LOADS:-"dd tar dbench iozone"}
for i in $LOADS; do
    [ -f $LUSTRE/tests/run_${i}.sh ] || \
        error "incorrect load: $i"
done
CLIENT_LOADS=($LOADS)
