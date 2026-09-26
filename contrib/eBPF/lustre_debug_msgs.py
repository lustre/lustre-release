#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
lustre_debug_msgs.py - eBPF tool to capture Lustre debug messages in real-time

This tool uses eBPF tracepoints to intercept Lustre debug messages and display them
with filtering capabilities.

The tracepoints only see messages already enabled by "lctl set_param debug=" and
"subsystem_debug=" (D_ERROR, D_EMERG, D_WARNING and D_CONSOLE are always on).
Enable the wanted masks first, e.g. "lctl set_param debug=+net"; -s and -m only
narrow that stream. Message text is truncated to 1535 bytes.

Usage:
    sudo python3 lustre_debug_msgs.py                    # Capture enabled messages
    sudo python3 lustre_debug_msgs.py -s S_RPC          # Capture RPC subsystem
    sudo python3 lustre_debug_msgs.py -m D_WARNING      # Capture warnings
    sudo python3 lustre_debug_msgs.py -f osc_request.c  # Capture from osc_request.c
    sudo python3 lustre_debug_msgs.py -n 100            # Capture 100 messages and exit
    sudo python3 lustre_debug_msgs.py -b 1024           # Use a 4MB ring buffer

Examples of subsystems: S_RPC, S_OSC, S_OST, S_MDS, S_MDC, S_LNET, S_LDLM, etc.
Examples of masks: D_WARNING, D_ERROR, D_NET, D_TRACE, D_INFO, etc.
"""

from __future__ import print_function
import argparse
import os
import signal
import sys
import time
import json
from bcc import BPF
from datetime import datetime

# eBPF program to trace Lustre debug messages
EBPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct debug_event {
    u64 ts;
    u32 subsys;
    u32 mask;
    u32 line;
    char file[256];
    char function[128];
    char message[1536];
};

BPF_RINGBUF_OUTPUT(debug_events, RINGBUF_PAGES);
BPF_ARRAY(dropped, u64, 1);

TRACEPOINT_PROBE(lustre_debug, lustre_debug_msg) {
    struct debug_event *event;

    if (FILTER_SUBSYS && args->msg_subsys != FILTER_SUBSYS)
        return 0;
    if (FILTER_MASK && !(args->msg_mask & FILTER_MASK))
        return 0;

    event = debug_events.ringbuf_reserve(sizeof(*event));
    if (!event) {
        int zero = 0;
        u64 *cnt = dropped.lookup(&zero);

        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return 0;
    }

    event->ts = bpf_ktime_get_ns();
    event->subsys = args->msg_subsys;
    event->mask = args->msg_mask;
    event->line = args->msg_line;

    TP_DATA_LOC_READ_STR(&event->file, msg_file, sizeof(event->file));
    TP_DATA_LOC_READ_STR(&event->function, msg_fn, sizeof(event->function));
    TP_DATA_LOC_READ_STR(&event->message, msg, sizeof(event->message));

    debug_events.ringbuf_submit(event, 0);

    return 0;
}
"""

# Subsystem name mappings
SUBSYS_NAMES = {
    0x00000001: "S_UNDEFINED",
    0x00000002: "S_MDC",
    0x00000004: "S_MDS",
    0x00000008: "S_OSC",
    0x00000010: "S_OST",
    0x00000020: "S_CLASS",
    0x00000040: "S_LOG",
    0x00000080: "S_LLITE",
    0x00000100: "S_RPC",
    0x00000200: "S_MGMT",
    0x00000400: "S_LNET",
    0x00000800: "S_LND",
    0x00001000: "S_PINGER",
    0x00002000: "S_FILTER",
    0x00004000: "S_LIBCFS",
    0x00008000: "S_ECHO",
    0x00010000: "S_LDLM",
    0x00020000: "S_LOV",
    0x00040000: "S_LQUOTA",
    0x00080000: "S_OSD",
    0x00100000: "S_LFSCK",
    0x00200000: "S_SNAPSHOT",
    0x00800000: "S_LMV",
    0x02000000: "S_SEC",
    0x04000000: "S_GSS",
    0x10000000: "S_MGC",
    0x20000000: "S_MGS",
    0x40000000: "S_FID",
    0x80000000: "S_FLD",
}

# Debug mask name mappings
MASK_NAMES = {
    0x00000001: "D_TRACE",
    0x00000002: "D_INODE",
    0x00000004: "D_SUPER",
    0x00000008: "D_IOTRACE",
    0x00000010: "D_MALLOC",
    0x00000020: "D_CACHE",
    0x00000040: "D_INFO",
    0x00000080: "D_IOCTL",
    0x00000100: "D_NETERROR",
    0x00000200: "D_NET",
    0x00000400: "D_WARNING",
    0x00000800: "D_BUFFS",
    0x00001000: "D_OTHER",
    0x00002000: "D_DENTRY",
    0x00004000: "D_NETTRACE",
    0x00008000: "D_PAGE",
    0x00010000: "D_DLMTRACE",
    0x00020000: "D_ERROR",
    0x00040000: "D_EMERG",
    0x00080000: "D_HA",
    0x00100000: "D_RPCTRACE",
    0x00200000: "D_VFSTRACE",
    0x00400000: "D_READA",
    0x00800000: "D_MMAP",
    0x01000000: "D_CONFIG",
    0x02000000: "D_CONSOLE",
    0x04000000: "D_QUOTA",
    0x08000000: "D_SEC",
    0x10000000: "D_LFSCK",
    0x20000000: "D_HSM",
    0x40000000: "D_SNAPSHOT",
    0x80000000: "D_LAYOUT",
}

def resolve_subsys(subsys):
    """Convert subsystem bitmask to name"""
    if subsys in SUBSYS_NAMES:
        return SUBSYS_NAMES[subsys]
    return f"0x{subsys:08x}"

def resolve_mask(mask):
    """Convert debug mask bitmask to comma-separated names"""
    names = []
    for bit, name in MASK_NAMES.items():
        if mask & bit:
            names.append(name)
    return ",".join(names) if names else f"0x{mask:08x}"

def resolve_subsys_num(name):
    """Convert subsystem name to bitmask"""
    for num, sname in SUBSYS_NAMES.items():
        if sname == name:
            return num
    try:
        return int(name, 0)
    except ValueError:
        return None

def resolve_mask_num(name):
    """Convert mask name to bitmask"""
    for num, mname in MASK_NAMES.items():
        if mname == name:
            return num
    try:
        return int(name, 0)
    except ValueError:
        return None

# Number of messages printed, checked against --count
msg_count = [0]

def print_event(ctx, data, size):
    if stop or (args.count and msg_count[0] >= args.count):
        return

    event = b["debug_events"].event(data)

    try:
        file_str = event.file.decode(errors='replace').rstrip('\x00')
        func_str = event.function.decode(errors='replace').rstrip('\x00')
        msg_str = event.message.decode(errors='replace').rstrip('\x00').rstrip('\n')
    except Exception as e:
        print(f"Warning: Failed to decode event: {e}", file=sys.stderr)
        return

    if args.file_filter and args.file_filter not in file_str:
        return

    try:
        ts = datetime.fromtimestamp(time.time() - time.monotonic() + event.ts / 1e9)
        subsys = resolve_subsys(event.subsys)
        mask = resolve_mask(event.mask)

        # Output as JSON (YAML-compatible)
        yaml_output = {
            "timestamp": ts.strftime("%H:%M:%S.%f")[:-3],
            "subsystem": subsys,
            "mask": mask,
            "file": file_str,
            "line": event.line,
            "function": func_str,
            "message": msg_str
        }
        print(json.dumps(yaml_output), flush=True)
        msg_count[0] += 1
    except BrokenPipeError:
        # the reader went away (e.g. head); stop quietly
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        stop.append(signal.SIGPIPE)
    except Exception as e:
        print(f"Warning: Failed to print event: {e}", file=sys.stderr)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Trace Lustre debug messages using eBPF",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("-s", "--subsys",
                        help="Filter by subsystem name or number (e.g., S_RPC); "
                             "must also be enabled in subsystem_debug")
    parser.add_argument("-m", "--mask",
                        help="Filter by debug mask name or number (e.g., D_WARNING); "
                             "must also be enabled in debug")
    parser.add_argument("-f", "--file",
                        dest="file_filter",
                        help="Filter by source file name substring")
    parser.add_argument("-b", "--buffer-pages",
                        type=int, default=256,
                        help="Ring buffer size in pages, a power of 2 (default 256)")
    parser.add_argument("-n", "--count",
                        type=int,
                        help="Stop after N messages")

    args = parser.parse_args()

    # Resolve filter arguments
    if args.subsys:
        subsys_num = resolve_subsys_num(args.subsys)
        if subsys_num is None:
            print("ERROR: Unknown subsystem '{0}'".format(args.subsys), file=sys.stderr)
            sys.exit(1)
        args.subsys = subsys_num

    if args.mask:
        mask_num = resolve_mask_num(args.mask)
        if mask_num is None:
            print("ERROR: Unknown mask '{0}'".format(args.mask), file=sys.stderr)
            sys.exit(1)
        args.mask = mask_num

    pages = args.buffer_pages
    if pages <= 0 or pages & (pages - 1):
        print("ERROR: --buffer-pages must be a power of 2", file=sys.stderr)
        sys.exit(1)

    # Load eBPF program
    try:
        b = BPF(text=EBPF_PROGRAM,
                cflags=["-DFILTER_SUBSYS={0}U".format(args.subsys or 0),
                        "-DFILTER_MASK={0}U".format(args.mask or 0),
                        "-DRINGBUF_PAGES={0}".format(pages)])
    except Exception as e:
        print("ERROR: Failed to load eBPF program:", str(e), file=sys.stderr)
        print("\nMake sure:", file=sys.stderr)
        print("  1. The libcfs module is loaded (lustre_debug tracepoints)", file=sys.stderr)
        print("  2. The kernel has CONFIG_TRACEPOINTS and CONFIG_BPF_EVENTS", file=sys.stderr)
        print("  3. The kernel supports BPF ring buffers (5.8 or later)", file=sys.stderr)
        sys.exit(1)

    print("Tracing Lustre debug messages (press Ctrl-C to exit)...", file=sys.stderr)
    print(f"Filter: subsys={resolve_subsys(args.subsys) if args.subsys else 'ALL'}, "
          f"mask={resolve_mask(args.mask) if args.mask else 'ALL'}, "
          f"file={args.file_filter or 'ALL'}", file=sys.stderr)

    # exceptions raised inside the ring buffer callback are swallowed by
    # ctypes, so stop through a flag the poll loop checks instead
    stop = []

    def on_signal(signum, frame):
        stop.append(signum)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Attach to ring buffer output
    b["debug_events"].open_ring_buffer(print_event)

    while not stop and not (args.count and msg_count[0] >= args.count):
        b.ring_buffer_poll(timeout=100)
    if stop:
        print("\nExiting...", file=sys.stderr)

    lost = b["dropped"][0].value
    if lost:
        print("{0} messages dropped: ring buffer full, try a larger -b".format(lost),
              file=sys.stderr)
