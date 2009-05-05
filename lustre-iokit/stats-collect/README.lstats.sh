Overview
--------
These script will be used to collect profile info of lustre client and server.
It will be run on a single(control) node, and collect all the profile info and 
create a tarball on the control node. 

lstat.sh : The stat script for single node, which will be run on each profile 
	   node.
gather_stats_everywhere.sh : collect stats script.
config.sh : the config for gather_stats_everywhere.sh.

Requirements
-------
1) Lustre is installed and setup on your profiling cluster.
2) ssh/scp to these node names works without requiring a password.

Configuration
------
Configuration is very simple for this script, all of the profiling config VARs are
in config.sh

XXXX_INTERVAL: the profiling interval
where value of interval means:
   0 - gather stats at start and stop only
   N - gather stats every N seconds
if some XXX_INTERVAL isn't specified, related stats won't be collected
XXXX can be: VMSTAT, SERVICE, BRW, SDIO, MBALLOC, IO, JBD, CLIENT 

As for ior-collect-stat.sh, you can modify the various IOR and MPI 
parameters inside ior-collect-stat.sh 

Running
--------
1) The gather_stats_everywhere.sh will be run in three mode
   
   a)sh gather_stats_everywhere.sh config.sh start 
     It will start collect stats on each node provided in config.sh
   
   b)sh gather_stats_everywhere.sh config.sh stop <log_name>
     It will stop collect stats on each node. If <log_name> is provided,
     it will create a profile tarball /tmp/<log_name>.tar.gz.
   
   c)sh gather_stats_everywhere.sh config.sh analyse log_tarball.tar.gz csv
     It will analyse the log_tarball and create a csv tarball for this
     profiling tarball. 

2) The ior-collect-stat.sh will be run as
        sh ior-collect-stat.sh start <profile> 
   It will create a ior result csv file. If <profile> is provided, 
   the detail profile info tarball will be created under /tmp.

Example
-------
When you want collect your profile info, you should
   1)sh gather_stats_everywhere.sh config.sh start 
	 #start the collect profile daemon on each node.

   2)run your test.

   3)sh gather_stats_everywhere.sh config.sh stop log_tarball
     #stop the collect profile daemon on each node, cleanup
      the tmp file and create a profiling tarball.

   4)sh gather_stats_everywhere.sh config.sh analyse log_tarball.tar.gz csv
     #create a csv file according to the profile.

TBD
------
Add liblustre profiling support and add more options for analyse.  



   


