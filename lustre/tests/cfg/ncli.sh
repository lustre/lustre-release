. $LUSTRE/tests/cfg/local.sh

CLIENT1=${CLIENT1:-`hostname`}
SINGLECLIENT=$CLIENT1
RCLIENTS=${RCLIENTS:-""}

init_clients_lists

[ -n "$RCLIENTS" -a "$PDSH" = "no_dsh" ] && \
                error "tests for remote clients $RCLIENTS needs pdsh != do_dsh " || true

[ -n "$FUNCTIONS" ] && . $FUNCTIONS || true

MPIBIN=${MPIBIN:-/testsuite/tests/`arch`/bin}
export PATH=:$PATH:$MPIBIN
MPIRUN=$(which mpirun)

