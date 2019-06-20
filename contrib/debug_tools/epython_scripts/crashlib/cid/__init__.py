
"""
Provide access to internal crash data.
Copyright 2014 Cray Inc.  All Rights Reserved

Much of the data this package provides is available by reading the dump file,
but some is information that crash 'knows' about the kernel based on the
kernel version.

The data is generally extracted by executing various crash commands, parsing
the output and storing it within a Python object.
"""


class ParseError:
    """Exception indicating an error while parsing crash information."""

    def __init__(self, msg=None):
        self.message = msg
