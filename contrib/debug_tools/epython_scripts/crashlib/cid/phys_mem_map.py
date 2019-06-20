
"""
Provide access to physical memory information.
Copyright 2014, 2017 Cray Inc.  All Rights Reserved
"""

from pykdump.API import *

import crashlib.cid

class Resource:
    """Generates /proc/iomem by traversing iomem Resource tree."""
    def __init__(self, resource):
        self.resource = resource
        self.lvl = 0

    def resource_start(self):
        return self.resource.start
    start = property(resource_start)

    def resource_end(self):
        return self.resource.end
    end = property(resource_end)

    def resource_name(self):
        return self.resource.name
    name = property(resource_name)

    def addr(self):
        return Addr(self.resource)

    def __str__(self):
        return '{0:08x}-{1:08x} : {2}'.format(self.start, self.end, self.name)

    def get_child(self):
        if self.resource.child:
            return Resource(self.resource.child)
        else:
            return None

    def get_sibling(self):
        if self.resource.sibling:
            return Resource(self.resource.sibling)
        else:
            return None

    def _walk(self, lvl=0):
        self.lvl = lvl
        yield self
        child = self.get_child()
        if child is not None:
            for res in child._walk(lvl+1):
                yield res
        next = self.get_sibling()
        if next is not None:
            for res in next._walk(lvl):
                yield res

    def iomem(self):
        """ returns /proc/iomem tree generator """
        return self.get_child()._walk()

    def is_System_RAM(self):
        return self.name == "System RAM"

def get_iomem():
    """ generator wrapper function for iomem """
    iomem_resource = Resource(readSymbol('iomem_resource'))
    return iomem_resource.iomem()

class MemMapEntry:
    """Define a single entry for a memory map.

    A MemMapEntry consists of three attributes:

        start - first address within the range
        end   - first address past the end of the range
        name  - name of address space type
    """
    start = None
    end   = None
    name  = None

    def __init__(self, start_addr, end_addr, name_str):
        self.start = int(start_addr)
        self.end   = int(end_addr)
        self.name  = name_str


def GetPhysMemMap():
    """Define a physical memory map.

    Returns the physical memory map as a list by extracting system ram
    ranges from iomem Resource class above.
    The list defines the physical address map as provided the iomem
    and will be a list of objects of type MemMapEntry.
    """
    memmap = []

    for ent in get_iomem():
        # get System RAM from iomem resource
        if ent.is_System_RAM():
            memmap.append(MemMapEntry(ent.start, ent.end+1, ent.name))

    return memmap

# --------------------------------------------------------------------------

# Create shared objects.

crashlib.cid.physmap = GetPhysMemMap()
