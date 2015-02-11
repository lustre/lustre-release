#!/usr/bin/env python

# Copyright (c) 2014, Lawrence Livermore National Security, LLC.
# Produced at the Lawrence Livermore National Laboratory.
# Written by Christopher J. Morrone <morrone2@llnl.gov>
# LLNL-CODE-468512
#
# This file is part of lustre-tools-llnl.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License (as published by the
# Free Software Foundation) version 2, dated June 1991.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the IMPLIED WARRANTY OF
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# terms and conditions of the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

# Given a zfs dataset for a Lustre OST and the object number of a file
# in that dataset, this script will call zdb to retreive the Lustre FID
# and print it out in standard Lustre FID format.

import sys
import subprocess

def from_bytes(b):
    return sum(b[i] << i*8 for i in range(len(b)))

def main():
    if len(sys.argv) != 3:
        print "Usage:", sys.argv[0], "<dataset> <object>"
        return 1

    p = subprocess.Popen(["zdb", "-e", "-vvv", sys.argv[1], sys.argv[2]],
                          stdout=subprocess.PIPE)
    pout, perr = p.communicate()

    b = bytearray()
    found_fid = False
    for line in pout.split('\n'):
        part = line.split()
        if not part or part[0] != 'trusted.fid':
            continue
        fid = part[2]
        found_fid = True
        while len(fid) > 0:
            val = fid[0]
            fid = fid[1:]
            if val == '\\':
                val = fid[0:3]
                fid = fid[3:]
                b.append(int(val, 8))
            else:
                b.append(ord(val))
        break

    if not found_fid:
        print "FID not found on", sys.argv[1], sys.argv[2]
        return 1

    print '[' \
        + hex(from_bytes(b[0:8])) \
        + ':' \
        + hex(from_bytes(b[8:12])) \
        + ':' \
        + hex(from_bytes(b[12:16])) \
        + ']'

    return 0

if __name__ == '__main__':
      sys.exit(main())
