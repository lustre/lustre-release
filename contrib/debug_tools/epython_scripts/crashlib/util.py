#!/usr/bin/env python

# Copyright (c) 2017-2018 Cray Inc. All Rights Reserved.

from collections import namedtuple
from math import ceil

from crash import addr2sym, PAGESIZE
from pykdump.API import (Addr, exec_crash_command, getSizeOf, member_offset,
                         readmem, readU8, readULong, sys_info)

from crashlib.cl import (cl_err, cl_warn, cl_info, cl_trace)

BYTES_1K = 1024
BYTES_1M = BYTES_1K * 1024
BYTES_1G = BYTES_1M * 1024
BYTES_1T = BYTES_1G * 1024

def bytes2size(bytes):
    '''Return a string representation of bytes, including order,
    ie '15.0M' or '2.1G'.'''
    suffix = ""
    if bytes >= BYTES_1T:
        suffix = "T"
        size = BYTES_1T
    elif bytes >= BYTES_1G:
        suffix = "G"
        size = BYTES_1G
    elif bytes >= BYTES_1M:
        suffix = "M"
        size = BYTES_1M
    elif bytes >= BYTES_1K:
        suffix = "K"
        size = BYTES_1K
    else:
        size = 1
    full = bytes / size
    rem = ((bytes % size) * 10) / size
    return "%d.%d%s" % (full, rem, suffix)

def pages2size(npages):
    '''Return a string representation of the number of bytes contained
    in npages.'''
    return bytes2size(npages * PAGESIZE)

def page_to_virt(page):
    # run kmem -p to get the pys addr for the page
    cmd = "kmem -p %#x" % page
    kmemp = exec_crash_command(cmd)
    paddr = kmemp.splitlines()[1].split()[1]
    cl_trace("*>>> page_to_virt #### phys_addr = %s" % paddr)
    # find vaddr from crash ptov command
    res = exec_crash_command("ptov " + paddr)
    vaddr = res.splitlines()[1].split()[0]
    cl_trace("*>>> page_to_virt #### vaddr = %s" % vaddr)
    return long(vaddr, 16)

def get_config(name):
    cl_trace(">>> get_config: searching system config for %s" % name)
    res = exec_crash_command("sys config")
    for line in res.splitlines():
        if not "=" in line:
            continue
        (key, value) = line.split("=", 1)
        if key == name:
            cl_trace(">>> get_config: %s has a value of '%s'" % (name, value))
            return value
    raise ValueError("Name %s not found in system config" % name)

def atoi(arg):
    # See if the user specified the format.
    try:
        val = int(arg, 0)
    except:
        # Nope, be generous and try again as hex.
        try:
            val = int(arg, 16)
        except:
            # No luck. Return an error.
            print("Invalid number: %s" % arg)
            val = None
    return val

def is_kernel_address(addr):
    # The top 17 bits should all be ones.
    val = (1 << 17) - 1
    if (addr >> 47) != val:
        return False
    return True

def is_kernel_text_address(addr):
    # The top 33 bits should all be ones.
    val = (1 << 33) - 1
    if (addr >> 31) != val:
        return False
    return True

def is_valid_address(addr):
    if addr < 0x10000:
        return False
    if addr & 7:
        return False
    return True

def readString(addr):
    res = readmem(addr, 64)
    return res.split('\0')[0]

def symbol_name(addr):
    if not is_kernel_text_address(addr):
        return ""
    (name, offset) = addr2sym(addr, True)
    if name == None:
        return ""
    if offset != 0:
        name += "+" + hex(offset)
    return name

def read_bool(addr):
    '''pykdump can't read bools on its own.'''
    return bool(readU8(addr))

def read_bool_member(struct, member_name):
    '''struct must be a pykdump object, member name is the string name
    of the bool member in the struct.'''
    struct_type = struct.PYT_symbol
    return read_bool(Addr(struct) + member_offset(struct_type, member_name))

def read_bitmap(addr, num_bits):
    '''Return an integer representation of the 'num_bits' sized bitmap
    at 'addr'. Note Python has arbitrary precision ints so the return
    value may be very large.'''
    bits_per_long = 8 * getSizeOf('long')
    num_longs = int(ceil(float(num_bits) / bits_per_long))
    total = 0
    for i in range(num_longs):
        total |= (readULong(addr + i * getSizeOf('long'))
                 << ((num_longs - i - 1) * bits_per_long))
    # Mask off unused bits when num_bits not a multiple of bits/long.
    mask = 2 ** num_bits - 1
    return total & mask

def read_cpumask(cpumask_addr):
    '''Return an integer representation of the cpumask bitmap.'''
    return read_bitmap(cpumask_addr, sys_info.CPUS)

def read_cpumask_var_t(container_struct, member_name):
    '''Return an integer representation of the cpumask_var_t bitmap.
    'container_struct' is the struct object which has a cpumask_var_t
    as a member. 'member_name' is the name of the cpumask_var_t field
    within the container struct.

    Pykdump crashes when trying to read a cpumask_var_t. This function
    provides a workaround which does not read a cpumask_var_t directly.'''
    container_type = container_struct.PYT_symbol
    offset = member_offset(container_type, member_name)
    cpumask_addr = Addr(container_struct) + offset
    return read_cpumask(cpumask_addr)


# Bit offsets and masks for read_qspinlock
# Copied from linux/include/asm-generic/qspinlock_types.h.
#
# Bitfields in the atomic value:
#
# When NR_CPUS < 16K
# 0- 7: locked byte
#    8: pending
# 9-15: not used
# 16-17: tail index
# 18-31: tail cpu (+1)
#
# When NR_CPUS >= 16K
# 0- 7: locked byte
#    8: pending
# 9-10: tail index
# 11-31: tail cpu (+1)'''

if sys_info.CPUS < 2 ** 14:
    _q_pending_bits = 8
else:
    _q_pending_bits = 1
_q_tail_index_offset = 9
_q_tail_index_bits = 2
_q_tail_index_mask = (2 ** _q_tail_index_bits - 1) << _q_tail_index_offset
_q_tail_cpu_offset = _q_tail_index_offset + _q_tail_index_bits
_q_tail_cpu_bits = 32 - _q_tail_cpu_offset
_q_tail_cpu_mask = (2 ** _q_tail_cpu_bits - 1) << _q_tail_cpu_offset

qspinlock_tuple = namedtuple('qspinlock',
                             ['locked', 'pending', 'tail_index', 'tail_cpu'])

def read_qspinlock(qspinlock):
    '''Given a struct qspinlock, which consists of a single 32 bit atomic
    value, return a namedtuple of ints (locked, pending, tail_index, tail_cpu),
    representing the bit fields of the qspinlock.'''

    val = qspinlock.val.counter
    locked_byte = val & 0xff
    pending = (val & 0x100) >> 8

    tail_index = (val & _q_tail_index_mask) >> _q_tail_index_offset

    _q_tail_cpu_offset = _q_tail_index_offset + _q_tail_index_bits
    _q_tail_cpu_bits = 32 - _q_tail_cpu_offset
    _q_tail_cpu_mask = (2 ** _q_tail_cpu_bits - 1) << _q_tail_cpu_offset
    tail_cpu = ((val & _q_tail_cpu_mask) >> _q_tail_cpu_offset) - 1

    return qspinlock_tuple(locked=locked_byte, pending=pending,
                           tail_index=tail_index, tail_cpu=tail_cpu)
