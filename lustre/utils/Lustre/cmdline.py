#!/usr/bin/env python
#
#  Copyright (C) 2002 Cluster File Systems, Inc.
#   Author: Robert Read <rread@clusterfs.com>
#   This file is part of Lustre, http://www.lustre.org.
#
#   Lustre is free software; you can redistribute it and/or
#   modify it under the terms of version 2 of the GNU General Public
#   License as published by the Free Software Foundation.
#
#   Lustre is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with Lustre; if not, write to the Free Software
#   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

# Standard the comand line handling for all the python tools.

import sys, getopt, types
import string
import error

class Options:
    FLAG = 1
    PARAM = 2
    INTPARAM = 3
    def __init__(self, cmd, remain_help, options):
        self.options = options
        shorts = ""
        longs = []
        options.append(('help,h', "Print this help")) 
        for opt in options:
            long = self.long(opt)
            short = self.short(opt)
            if self.type(opt) in (Options.PARAM, Options.INTPARAM):
                if short:  short = short + ':'
                if long: long = long + '='
            shorts = shorts + short
            longs.append(long)
        self.short_opts = shorts
        self.long_opts = longs
        self.cmd = cmd
        self.remain_help = remain_help

    def init_values(self):
        values = {}
        for opt in self.options:
            values[self.long(opt)] = self.default(opt)
        return values

    def long(self, option):
        n = string.find(option[0], ',')
        if n < 0: return option[0]
        else:     return option[0][0:n]

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
        return None

    def lookup_option(self, key, key_func):
        for opt in self.options:
            if key_func(opt) == key:
                return opt

    def lookup_short(self, key):
        return self.lookup_option(key, self.short)

    def lookup_long(self, key):
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
            else:
                val = 1
            values[self.long(option)] = val
        return values
                
    class option_wrapper:
        def __init__(self, values):
            self.__dict__['values'] = values
        def __getattr__(self, name):
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
