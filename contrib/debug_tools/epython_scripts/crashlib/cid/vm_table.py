
"""
Provide access to the crash's vm table.
Copyright 2014 Cray Inc.  All Rights Reserved
"""

from pykdump.API import *

import crashlib.cid

class VmInfo:
    """Make data from the crash vmtbl easily available."""

    def __init__(self):
        """Extract VM table data from crash.

        Initialize the table of VM information by parsing
        the output of the 'help -v' command.  This only extracts
        selected data.

        Each item extracted is made available as an instance attribute.
        """

        # crash 'help -v' doesn't use prefixes on numbers, so we must
        # know what number base is in use for each numeric field.
        decFields = ('total_pages', 'max_mapnr', 'totalram_pages',
            'totalhigh_pages', 'num_physpages',
            'page_hash_table_len', 'kmem_max_c_num',
            'kmem_max_limit', 'kmem_max_cpus', 'kmem_cache_count',
            'kmem_cache_namelen', 'kmem_cache_len_nodes', 'PG_slab',
            'paddr_prlen', 'numnodes', 'nr_zones', 'nr_free_areas',
            'cpu_slab_type', 'nr_swapfiles', 'ZONE_HIGHMEM',
            'node_online_map_len', 'nr_vm_stat_items',
            'nr_vm_event_items')

        hexFields = ('flags', 'high_memory', 'vmalloc_start',
            'mem_map', 'page_hash_table', 'PG_reserved',
            'PG_head_tail_mask', 'slab_data', 'last_swap_read',
            'swap_info_struct', 'mem_sec', 'mem_section')

        expected_key_count = len(decFields) + len(hexFields)

        for line in exec_crash_command('help -v').splitlines():
            #               flags: 10dc52
            #  (NODES_ONLINE|ZONES|PERCPU_KMALLOC_V2|KMEM_CACHE_INIT|SPARSEMEM|SPARSEMEM_EX|PERCPU_KMALLOC_V2_NODES|VM_STAT|VM_INIT)
            #      kernel_pgd[NR_CPUS]: ffffffff8163f000 ...
            #         high_memory: ffff880880000000
            #       vmalloc_start: ffffc90000000000
            #             mem_map: 0
            # ...
            #
            # Only use the first value after the field name and
            # only for selected fields.
            parts = line.split()
            if len(parts) < 2: continue
            key = parts[0].rstrip(':')
            if key in decFields:
                self.__dict__[key] = int(parts[1],10)
            elif key in hexFields:
                self.__dict__[key] = int(parts[1],16)

        # If some versions of crash or the kernel don't have all the
        # fields, this check code may need to be removed or modified.
        if len(self.__dict__.keys()) != expected_key_count:
            raise crashlib.ida.ParseError(
                'Expected {:d}, but parsed {:d} entries.'.format(
                    expected_key_count, len(self.__dict__.keys())))

# --------------------------------------------------------------------------

# Declare a shared instance.

crashlib.cid.vmtbl = VmInfo()
