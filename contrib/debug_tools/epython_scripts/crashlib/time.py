"""
Routines for retrieving and manipulating kernel time
Copyright 2017 Cray Inc.  All Rights Reserved
"""

from pykdump.API import readSymbol, symbol_exists
from crashlib.exceptions import *

# --------------------------------------------------------------------------
# get_wallclock_seconds()
#
# There are multiple variants, depending on kernel version.  Attempt to
# discern the proper method for retrieving the current wall clock time.
#

if symbol_exists('xtime'):
    # SLES 11 uses struct timespec xtime to hold the wall time.
    _wallclock_xtime = readSymbol('xtime')
    def get_wallclock_seconds():
        '''Return current time in seconds'''
        return _wallclock_xtime.tv_sec

elif symbol_exists('timekeeper'):
    # SLES 12 has a new timekeeper struct for that purpose
    _wallclock_timekeeper = readSymbol('timekeeper')
    def get_wallclock_seconds():
        '''Return current time in seconds'''
        return _wallclock_timekeeper.xtime_sec

elif symbol_exists('tk_core'):
    # SLES 12 SP2 embeds the timekeeper struct in tk_core
    _wallclock_tk_core = readSymbol('tk_core')
    def get_wallclock_seconds():
        '''Return current time in seconds'''
        return _wallclock_tk_core.timekeeper.xtime_sec

else:
    # Unknown how to read wallclock time in this kernel
    def get_wallclock_seconds():
        raise CompatibilityError('Could not find wallclock time in the kernel')

# --------------------------------------------------------------------------
