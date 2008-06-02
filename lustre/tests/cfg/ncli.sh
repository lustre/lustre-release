. $LUSTRE/tests/cfg/local.sh

CLIENT1=${CLIENT1:-`hostname`}
SINGLECLIENT=$CLIENT1
RCLIENTS=${RCLIENTS:-""}
CLIENTS=`comma_list $SINGLECLIENT $RCLIENTS`
REMOTECLIENTS=($RCLIENTS)
for ((i=0; $i<${#REMOTECLIENTS[@]}; i++)); do
	varname=CLIENT$((i + 2))
	eval $varname=${REMOTECLIENTS[i]}
done

CLIENTCOUNT=$((${#REMOTECLIENTS[@]} + 1))

[ -n "$RCLIENTS" -a "$PDSH" = "no_dsh" ] && \
                error "tests for remote clients $RCLIENTS needs pdsh != do_dsh " || true

[ -n "$FUNCTIONS" ] && . $FUNCTIONS || true
