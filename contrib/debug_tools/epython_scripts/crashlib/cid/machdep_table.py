
"""
Provide access to machine-dependent data.
Copyright 2014, 2017 Cray Inc.  All Rights Reserved
"""

from pykdump.API import *

import crashlib.cid

class MachDepInfo:
    """Provide access to the crash machdep_table.

    The data is collected by parsing the output of the 'help -m' command.
    """

    def __init__(self):
        """Extract machine-dependent data from crash.

        Initialize the table of machine dependent information by parsing
        the output of the 'help -m' command.  This only extracts
        selected data.

        Each item extracted is made available as an instance attribute.
        """

        # crash 'help -m' doesn't use prefixes on numbers, so we must
        # know what number base is in use for each numeric field.
        fieldBase = {
            'bits' : 10, 'flags' : 16, 'hz' : 10, 'identity_map_base' : 16,
            'kvbase' : 16, 'last_pgd_read' : 16, 'last_pmd_read' : 16,
            'last_ptbl_read' : 16, 'machspec' : 16, 'max_physmem_bits' : 10,
            'memsize' : 10, 'mhz' : 10, 'modules_vaddr' : 16, 'nr_irqs' : 10,
            'page_offset' : 16, 'pagemask' : 16, 'pageshift' : 10,
            'pagesize' : 10, 'pgd' : 16, 'pmd' : 16, 'ptbl' : 16,
            'ptrs_per_pgd' : 10, 'section_size_bits' : 10,
            'sections_per_root' : 10, 'stacksize' : 10, 'userspace_top' : 16,
            'vmalloc_end' : 16, 'vmalloc_start_addr' : 16, 'vmemmap_end' : 16,
            'vmemmap_vaddr' : 16
        }

        if sys_info.machine in ("x86_64", "k1om", "x86"):
            # additional x86_64 fields:
            # Attic: 'last_pml4_read': 16, 'last_umpl_read': 16,
            #        'umpl': 16, 'pml4': 16
            x86_64_fields = {
                'irq_eframe_link' : 10, 'irqstack' : 16,
                'page_protnone' : 16, 'phys_base' : 16,
                'thread_return' : 16, 'vsyscall_page' : 16,
            }
            fieldBase.update(x86_64_fields)
        elif sys_info.machine == 'aarch64':
            # no additional aarch64 field yet
            pass
        else:
            raise crashlib.cid.ParseError(
                    'Invalid machine type {0}.'.format(sys_info.machine))

        expected_key_count = len(fieldBase)

        for line in exec_crash_command('help -m').splitlines():
            # crash> help -m
            #               flags: 30400209 (KSYMS_START|MACHDEP_BT_TEXT|VM_2_6_11|VMEMMAP|FRAMESIZE_DEBUG|FRAMEPOINTER)
            #              kvbase: ffff880000000000
            #   identity_map_base: ffff880000000000
            #            pagesize: 4096
            #           pageshift: 12
            #            pagemask: fffffffffffff000
            #          pageoffset: fff
            #           stacksize: 8192
            #                  hz: 250
            #                 mhz: 2599
            #             memsize: 68694994944 (0xffe8a7000)
            #  ...
            #
            # Only use the first value after the field name and
            # only for selected fields.
            parts = line.split()
            if len(parts) < 2: continue

            key = parts[0].rstrip(':')
            base = fieldBase.get(key, None)

            if base is not None:
                self.__dict__[key] = int(parts[1], base)

        # If some versions of crash or the kernel don't have all the
        # fields, this check code may need to be removed or modified.
        if len(self.__dict__.keys()) != expected_key_count:
            raise crashlib.cid.ParseError(
                'Expected {:d}, but parsed {:d} entries.'.format(
                    expected_key_count, len(self.__dict__.keys())))

# --------------------------------------------------------------------------

# Create a shared instances.

crashlib.cid.mdtbl = MachDepInfo()
