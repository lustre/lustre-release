#!/usr/bin/python2
"""
Run the application with "--help" for documentation of how to run 
it as an application.

Copyright (c) 2005 Scali AS. All Rights Reserved.
"""

import logging
import string
import lustre_obdsurveylib
try:
    import optparse
except ImportError:
    # Compability with older python-distributions:
    import optik as optparse



def main():
    parser = optparse.OptionParser(version="%prog 1.0", usage="%prog <--diskio | --network | --networkdiskio> <targetlist>")
    parser.add_option("--pagesize", type="int", default=4, help="Set the pagesize (KB)")
    parser.add_option("--size", type="int", default=100, help="Set the dataset-size (MB)")
    parser.add_option("--minrecordsize", type="int", default=1024, help="Minimum record size (KB)")
    parser.add_option("--maxrecordsize", type="int", default=1024, help="Maximum record size (KB)")
    parser.add_option("--minthreads", type="int", default=1, help="Minimum number of threads")
    parser.add_option("--maxthreads", type="int", default=16, help="Maximum number of threads")
    parser.add_option("--diskio", action="store_const", const="diskio", dest="mode", 
        help="Test local IO-performance on a set of OSTs. List OSTs as a space-seperated list of node:ostname.")
    parser.add_option("--networkio", action="store_const", const="networkio", dest="mode",
        help="Test network-performance. List network-connections as a space-seperated list of server:client pairs.")
    parser.add_option("--networkdiskio", action="store_const", const="networkdiskio", dest="mode",
        help="Test IO-performance over network. Assumes existing OSC-devices. List OSCs as a space-seperated list of"
            "node:oscname pairs.")
    (options, args) = parser.parse_args()
    args = map(lambda arg: tuple(string.split(arg, ":")), args)
    # Set up lustre-devices according to mode:
    clients = []
    if options.mode == "diskio":
        for node, device in args:
            obdfilter = lustre_obdsurveylib.ExistingOBDFilter(node, device)
            echo_client = lustre_obdsurveylib.EchoClient(node, device+"_client", obdfilter)
            clients.append(echo_client)
    elif options.mode == "networkio":
        for servername, clientname in args:
            obdecho = lustre_obdsurveylib.OBDEcho(servername, "test_obdecho")
            osc = lustre_obdsurveylib.OSC(clientname, "test_osc", obdecho)
            echo_client = lustre_obdsurveylib.EchoClient(clientname, "test_client", osc)
            clients.append(echo_client)
    elif options.mode == "networkdiskio":
        for clientname, oscname in args:
            osc = lustre_obdsurveylib.ExistingOSC(clientname, oscname)
            echo_client = lustre_obdsurveylib.EchoClient(clientname, oscname+"_client", osc)
            clients.append(echo_client)
    else:
        parser.error("You need to specify either --diskio, --networkio or --networkdiskio")
    rsz = options.minrecordsize
    while rsz <= options.maxrecordsize:
        threads = options.minthreads
        while threads <= options.maxthreads:
            results = lustre_obdsurveylib.ParallelTestBRW(clients, threads, options.size, ('w', 'r'), rsz, options.pagesize)
            print "ost %2d sz %7dK rsz %4d thr %2d" % (len(clients), results[0].getTotalSize(), rsz, threads),
            for result in results:
                try:
                    result.verifyExitCodes()
                except:
                    print "%30s" % "ERROR",
                else:
                    print "%s %8.2f [%8.2f,%8.2f]" % (result.getTestType(), result.getTotalBandwidth(), result.getMinBandwidth(), result.getMaxBandwidth()), 
            print
            threads *= 2
        rsz *= 2
        
    
if __name__ == '__main__':
    log = logging.getLogger()
    log.addHandler(logging.StreamHandler())
    log.setLevel(logging.INFO)
    main()
