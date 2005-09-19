#!/usr/bin/expect

spawn lwizard $argv
set timeout 3
expect {
	"overwrite existing" {
		interact
	}
}
expect "HOSTNAME for mds"
send -- "localhost\n"
expect "network INTERFACE"
send -- "192.168.1.29/24 10.0.0.29/24\n"
expect "enter the device or loop file name for mds"
send -- "/tmp/mds\n"
expect "device SIZE"
send -- "10000\n"
expect "configure FAILOVER"
send -- "n\n"
expect "HOSTNAME for ost"
send -- "localhost\n"
expect "network INTERFACE"
send -- "192.168.1.29/24 10.0.0.29/24\n"
expect "device or loop file name for ost"
send -- "/tmp/ost\n"
expect "device SIZE"
send -- "10000\n"
expect "configure FAILOVER"
send -- "n\n"
expect "HOSTNAME for ost"
send -- "\n"
expect "clients' mountpoint"
send -- "\n"
expect "configure another client with multiple network interfaces"
send -- "y\n"
expect "HOSTNAME"
send -- "node\n"
expect "network interface address"
send -- "192.168.1.29/24 10.0.0.29/24\n"
expect "configure another client with multiple network interfaces"
send -- "n\n"
expect "Lustre configuration has been written"
send -- "\n"
close
