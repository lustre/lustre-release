# note the cfg/<lutf config>.sh should export all environment variables
# required. EX: export ost4_HOST=lustre01

export PYTHONPATH=$PYTHONPATH:$LUSTRE/tests/lutf/:$LUSTRE/tests/lutf/src/:$LUSTRE/tests/lutf/python:$LUSTRE/tests/lutf/python/tests/:$LUSTRE/tests/lutf/python/config/:$LUSTRE/tests/lutf/python/deploy:$LUSTRE/tests/lutf/python/infra

export LUTFPATH=$LUSTRE/tests/lutf/

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$LUTFPATH:$LUTFPATH/src:$LUSTRE/lnet/utils/lnetconfig/.libs/

export PATH=$PATH:$LUSTRE/tests/lutf/src:$LUSTRE/tests/lutf

if [[ -z "${TELNET_PORT}" ]]; then
	export TELNET_PORT=8181
fi

if [[ -z "${MASTER_PORT}" ]]; then
	export MASTER_PORT=8282
fi

if [[ -z "${LUTF_SHELL}" ]]; then
	export LUTF_SHELL=batch
fi

if [[ -z "${PYTHONBIN}" ]]; then
	export PYTHONBIN=python3
fi

export LUTF_ENV_VARS=$1
$PYTHONBIN $LUSTRE/tests/lutf/python/config/lutf_start.py
