#!/usr/bin/env python

import getopt, re, string, sys

def my_range(match):
    zeropad = 0
    low = int(match.group(1))
    high = int(match.group(2))+1

    if low >= high:
        sys.exit('invalid host range')

    if len(match.group(1)) == len(match.group(2)) and match.group(1)[0] == '0':
        zeropad = 1
        padlen = len(match.group(1))

    range_list = range(low, high)
    if zeropad:
        val = string.zfill(`range_list[0]`, padlen)
    else:
        val = `range_list[0]`
    replacement = '%s' % val
    for val in range_list[1:]:
        val = `val`
        if zeropad:
            val = string.zfill(val, padlen)
        replacement = replacement + ', %s' % (val)

    return replacement

def unglobhosts(hostglob):
    bracket = 0
    start = 0
    hosts = []
    for i in range(len(hostglob)):
        if hostglob[i] == '[':
            bracket = bracket + 1
            continue
        if hostglob[i] == ']':
            bracket = bracket - 1
            continue
        if hostglob[i] == ',' and bracket == 0:
            substring = hostglob[start:i]
            hosts = hosts + [substring]
            start = i + 1
    hosts = hosts + [hostglob[start:i+1]]

    hostlist = []
    for host in hosts:
        host = re.sub('(\d+)-(\d+)', my_range, host)
        m = re.match('(.*)\[(.*)]', host)
        if m:
            prefix = m.group(1)
            for number in string.split(m.group(2),','):
                number = string.strip(number)
                hostlist = hostlist + [prefix + number]
        else:
            hostlist = hostlist + [host]
    return hostlist

def main():
    num_hosts = 0
    try:
        opts, leftover = getopt.getopt(sys.argv[1:], "n:", [])
    except getopt.GetoptError:
        sys.exit(1)

    for opt, val in opts:
        if opt == '-n':
            num_hosts = int(val)

    if leftover == []:
        sys.exit('Usage: unglobhosts.py [-n numhosts] <host glob>')

    hostlist = unglobhosts(leftover[0])

    if num_hosts == 0:
        num_hosts = len(hostlist)

    output = ''
    for i in range(num_hosts):
        output = output + hostlist[i]
        if i != num_hosts-1:
            output = output + ','
    print output

if __name__ == "__main__":
    main()
