#!/bin/bash

config=${1:-mcr.xml}

LMC=../utils/lmc

# create nodes
${LMC} -o $config --node client --net '*' elan || exit 1
${LMC} -m $config --node mdev2 --net mdev2 tcp || exit 1
${LMC} -m $config --router --node mdev3 --net mdev3  tcp || exit 1
${LMC} -m $config --node mdev3 --net 3  elan || exit 1

${LMC} -m $config --node mdev3 --route elan 3 2 25 || exit 2
${LMC} -m $config --node mdev3 --route tcp mdev3 mdev2 || exit 2


# configure ost
${LMC} -m $config --format --node mdev2 --obdtype=obdecho --ost || exit 3

# create client config
${LMC} -m $config --node client --osc  OSC_mdev2 || exit 4
