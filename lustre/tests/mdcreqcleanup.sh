rmmod llight
rmmod mdc
/usr/src/obd/utils/obdctl <<EOF
device 0
cleanup
detach
quit
EOF
rmmod mds
rmmod osc
rmmod ost
rmmod obdext2
rmmod obdclass
rmmod ptlrpc
/usr/src/portals/linux/utils/ptlctl <<EOF
setup tcp localhost 1234
disconnect self
disconnect mds
EOF
killall acceptor
rmmod ksocknal
rmmod portals
