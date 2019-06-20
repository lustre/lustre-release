
"""
Provide access to the page flags known by crash.
Copyright 2014 Cray Inc.  All Rights Reserved

The data is gathered from the 'kmem -g' command.
"""

from pykdump.API import *

import crashlib.cid


class PageFlag:
    # Note: This class should probably be abstracted somewhere as a
    # bit or bitmask class, but since we don't have that yet, just
    # create a new class here.
    """Represent a flag as a bit mask and a shift value."""
    def __init__(self, name, shift_val):
        self.name  = name
        self.shift = int(shift_val)
        self.mask  = 1 << self.shift

    def __call__(self):
        return self.mask


class MachPageFlags:
    """Extract the machine-specific page flags from crash.

    When instantiated, this class produces an object with data members
    for each kernel page flag that crash knows about, based on the kernel
    version.  Each page flag is an instance of class PageFlag.  An example
    of usage would be:

        page = readSU('struct page', page_addr)
        kpf = MachPageFlags()
        if page.flags & kpf.PG_slab.mask:
            ...
    """

    def __init__(self):
        """Extract the page flags from the crash 'kmem -g' command."""
        for line in exec_crash_command('kmem -g').splitlines():
            # crash> kmem -g
            # PAGE-FLAG       BIT  VALUE
            # PG_locked         0  0000001
            # PG_waiters        1  0000002
            # ...
            fields = line.split()
            if len(fields) < 3 or fields[0][0:3] != 'PG_': continue

            name  = fields[0]
            shift = int(fields[1])
            self.__dict__[name] = PageFlag(name, shift)

# --------------------------------------------------------------------------

# Create a shared instances of the above classes.

crashlib.cid.pgflags = MachPageFlags()
