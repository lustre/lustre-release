#!/usr/bin/env python
# GPL HEADER START
#
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 only,
# as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License version 2 for more details (a copy is included
# in the LICENSE file that accompanied this code).
#
# You should have received a copy of the GNU General Public License
# version 2 along with this program; If not, see
# http://www.sun.com/software/products/lustre/docs/GPLv2.pdf
# copy of GPLv2].
#
# Please contact Sun Microsystems, Inc., 4150 Network Circle, Santa Clara,
# CA 95054 USA or visit www.sun.com if you need additional information or
# have any questions.
#
# GPL HEADER END
#

#
# Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
# Use is subject to license terms.
#

#
# This file is part of Lustre, http://www.lustre.org/
# Lustre is a trademark of Sun Microsystems, Inc.
#
# Author: Robert Read <rread@clusterfs.com>
#
# Standard the comand line handling for all the python tools.

import sys, getopt, types
import string
import error

class Options:
    FLAG = 1
    PARAM = 2
    INTPARAM = 3
    PARAMLIST = 4
    def __init__(self, cmd, remain_help, options):
        self.options = options
        shorts = ""
        longs = []
        options.append(('help,h', "Print this help")) 
        for opt in options:
            long = self.long(opt)
            short = self.short(opt)
            if self.type(opt) in (Options.PARAM, Options.INTPARAM,
                                  Options.PARAMLIST):
                if short: short = short + ':'
                if long:
                    long = long + '='
            if string.find(long, '_') >= 0:
                longs.append(string.replace(long, '_', '-'))
            shorts = shorts + short
            longs.append(long)
        self.short_opts = shorts
        self.long_opts = longs
        self.cmd = cmd
        self.remain_help = remain_help

    def init_values(self):
        values = {}
        for opt in self.options:
            values[self.key(opt)] = self.default(opt)
        return values

    def long(self, option):
        n = string.find(option[0], ',')
        if n < 0: return option[0]
        else:     return option[0][0:n]

    def key(self, option):
        key = self.long(option)
        return string.replace(key, '-', '_')
        
    def short(self, option):
        n = string.find(option[0], ',')
        if n < 0: return ''
        else:     return option[0][n+1:]

    def help(self, option):
        return option[1]
    
    def type(self, option):
        if len(option) >= 3:
            return option[2]
        return Options.FLAG
    
    def default(self, option):
        if len(option) >= 4:
            return option[3]
        if self.type(option) == Options.PARAMLIST:
            return []
        return None

    def lookup_option(self, key, key_func):
        for opt in self.options:
            if key_func(opt) == key:
                return opt

    def lookup_short(self, key):
        return self.lookup_option(key, self.short)

    def lookup_long(self, key):
        key = string.replace(key, '-', '_')
        return self.lookup_option(key, self.long)

    def handle_opts(self, opts):
        values = self.init_values()
        for o, a in opts:
            if o[0:2] != '--':
                option = self.lookup_short(o[1:])
            else:
                option = self.lookup_long(o[2:])
            if self.type(option) == Options.PARAM:
                val = a
            elif self.type(option) == Options.INTPARAM:
                try: 
                    val = int(a)
                except ValueError, e:
                    raise error.OptionError("option: '%s' expects integer value, got '%s' "  % (o,a))
            elif self.type(option) == Options.PARAMLIST:
                val = values[self.key(option)];
                val.append(a)
            else:
                val = 1
            values[self.key(option)] = val
        return values
                
        
    class option_wrapper:
        def __init__(self, values):
            self.__dict__['values'] = values
        def __getattr__(self, name):
            if self.values.has_key(name):
                return self.values[name]
            else:
                raise error.OptionError("bad option name: " + name)
        def __getitem__(self, name):
            if self.values.has_key(name):
                return self.values[name]
            else:
                raise error.OptionError("bad option name: " + name)
        def __setattr__(self, name, value):
            self.values[name] = value

    def parse(self, argv):
        try:
            opts, args = getopt.getopt(argv, self.short_opts, self.long_opts)
            values = self.handle_opts(opts)
            if values["help"]:
                self.usage()
                sys.exit(0)
            return self.option_wrapper(values), args
        except getopt.error, e:
            raise error.OptionError(str(e))

    def usage(self):
        ret = 'usage: %s [options] %s\n' % (self.cmd, self.remain_help)
        for opt in self.options:
            s = self.short(opt)
            if s: str = "-%s|--%s" % (s,self.long(opt))
            else: str = "--%s" % (self.long(opt),)
            if self.type(opt) in (Options.PARAM, Options.INTPARAM):
                str = "%s <arg>" % (str,)
            help = self.help(opt)
            n = string.find(help, '\n')
            if self.default(opt) != None:
                if n < 0:
                    str = "%-15s  %s (default=%s)" %(str, help,
                                                     self.default(opt))
                else:
                    str = "%-15s  %s (default=%s)%s" %(str, help[0:n],
                                                       self.default(opt),
                                                       help[n:])
            else:
                str = "%-15s  %s" %(str, help)
            ret = ret + str + "\n"
        print ret

# Test driver
if __name__ == "__main__":
    cl = Options("test", "xml_file", [
                  ('verbose,v', "verbose ", Options.FLAG, 0),
                  ('cleanup,d', "shutdown"),
                  ('gdb',     "Display gdb module file ", Options.FLAG, 0),
                  ('device', "device path ", Options.PARAM),
                  ('ldapurl', "LDAP server URL ", Options.PARAM),
                  ('lustre', "Lustre source dir ", Options.PARAM),
                  ('portals', "Portals source dir ", Options.PARAM),
                  ('maxlevel', """Specify the maximum level
                    Levels are aproximatly like:
                            70 - mountpoint, echo_client, osc, mdc, lov""",
                   Options.INTPARAM, 100),

                  ])

    conf, args = cl.parse(sys.argv[1:])

    for key in conf.values.keys():
        print "%-10s = %s" % (key, conf.values[key])
