#need to get the functions defined in the cluster's .sh configuration
. $LTESTDIR/harness/config/$MACHINENAME/config.sh
# comma_list and friends
. $LTESTDIR/harness/config/common/utility_functions.sh

all_but_one_clients() {
    local n=0
    local clients=""
    for client in ${CLIENTS//,/ }; do
        if [ $n -gt 0 ]; then
            # don't include first client
            clients="$clients $client"
        fi
        let n=n+1
    done
    echo $clients
}

# make sure client list is a comma separated list
CLIENTS=`comma_list $CLIENTS`
# could probably set this to $CLIENT1
#FAIL_CLIENT=${CLIENT1}

mds_HOST=${mds_HOST:-${MDSNODE1}}
mdsfailover_HOST=${mdsfailover_HOST:-${MDSNODE2}}
ost1_HOST=${ost1_HOST:-${OSTNODE1}}
ost2_HOST=${ost2_HOST:-${OSTNODE2}}
EXTRA_OSTS=${EXTRA_OSTS:-""}
client_HOST=${CLIENT1}
LIVE_CLIENT=${LIVE_CLIENT:-${CLIENT1}}
# This should always be a list, not a regexp
FAIL_CLIENTS=${FAIL_CLIENTS:-"`all_but_one_clients`"}
SINGLEMDS=${SINGLEMDS:-"mds"}

NETTYPE=${NETTYPE:-${NETTYPE}}

TIMEOUT=${TIMEOUT:-30}
PTLDEBUG=${PTLDEBUG:-0}
DEBUG_SIZE=${DEBUG_SIZE:-10}
SUBSYSTEM=${SUBSYSTEM:-0}
MOUNT=${MOUNT:-${MOUNTPT}}
#UPCALL=${CLIENT_UPCALL:-"${LUSTRE_TESTS}/replay-single-upcall.sh"}

mdsdev1=${MDSDEV[1]:-$MDSDEVBASE}
MDSDEV=${MDSDEV:-${mdsdev1}}

# need to pull off the --size 
if [ -n "$MDSSIZE" ]; then
    MDSSIZE=`echo $MDSSIZE | awk '{print $2}'`
else
    MDSSIZE=100000
fi
MDSJOURNALSIZE=${MDSJOURNALSIZE:-0}

ostdev1=${OSTDEV[1]:-$OSTDEVBASE}
OSTDEV=${OSTDEV:-${ostdev1}}

# need to pull off the --size 
if [ -n "$OSTSIZE" ]; then
    OSTSIZE=`echo $OSTSIZE | awk '{print $2}'`
else
    OSTSIZE=100000
fi
OSTJOURNALSIZE=${OSTJOURNALSIZE:-0}

FSTYPE=${FSTYPE:-ext3}
STRIPE_BYTES=${STRIPE_BYTES:-1048576} 
STRIPES_PER_OBJ=${STRIPES_PER_OBJ:-0}

FAILURE_MODE=${FAILURE_MODE:-HARD} # or HARD
#POWER_DOWN=${POWER_DOWN:-"powerman --off"}
#POWER_UP=${POWER_UP:-"powerman --on"}
POWER_UP=$POWER_ON
POWER_DOWN=$POWER_OFF

PDSH="${DSH}"
