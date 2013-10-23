. $LUSTRE/tests/cfg/local.sh

# For multiple clients testing, we need use the cfg/ncli.sh config file, and
# only need specify the "RCLIENTS" variable. The "CLIENTS" and "CLIENTCOUNT"
# variables are defined in init_clients_lists(), called from cfg/ncli.sh.
CLIENT1=${CLIENT1:-$(hostname)}
SINGLECLIENT=$CLIENT1
RCLIENTS=${RCLIENTS:-""}

init_clients_lists

[ -n "$RCLIENTS" -a "$PDSH" = "no_dsh" ] &&
	error "tests for remote clients $RCLIENTS needs pdsh != do_dsh " || true

[ -n "$FUNCTIONS" ] && . $FUNCTIONS || true

# for recovery scale tests
# default boulder cluster iozone location
export PATH=/opt/iozone/bin:$PATH

LOADS=${LOADS:-"dd tar dbench iozone"}
for i in $LOADS; do
	[ -f $LUSTRE/tests/run_${i}.sh ] || error "incorrect load: $i"
done
CLIENT_LOADS=($LOADS)

# This is used when testing on SLURM environment.
# Test will use srun when SRUN_PARTITION is set
SRUN=${SRUN:-$(which srun 2>/dev/null || true)}
SRUN_PARTITION=${SRUN_PARTITION:-""}
SRUN_OPTIONS=${SRUN_OPTIONS:-"-W 1800 -l -O"}
