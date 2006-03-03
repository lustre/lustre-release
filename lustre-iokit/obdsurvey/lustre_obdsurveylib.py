#!/usr/bin/python2
"""
This module implements lustre-specific IO- and network-tests.
It is based on the 'obdfilter-survey'-script distributed with lustre-iokit.

To use it as a library, the caller should first create a set of
EchoClient-object. The EchoClient-class will automatically create the
echo_client-device, and set it up to communicate with the device 
given as the target to the EchoClient-constructor. See main() for
an example of how to set up EchoClient-objects and the objects it
depends on. 

Next, run ParallelTestBRW to run benchmarks in parallel over all
the EchoClients with a specific number of threads++.

ParallelTestBRW returns a list of ParallelTestBRWResult-objects
(one for eacy type of test ('w' and 'r') performed).
See the documentation for ParallelTestBRWResult for how to extract
the data from this object.

Some notes about the implementation:
The core-functionality is implemented as python-classes wrapping lustre-devices
such as obdecho-, osc-, and echo_client-devices. The constructors for these 
classes automatically create the lustre-device, and the destructor removes the
devices. High-level devices keep references to low-level devices, ensuring that
the low-level devices are not removed as long as they are in use. The
garbage-collector will clean everything up in the right order. However, there
are two corner-cases that users of the library must be awere of:

1. You can not create to lustre-devices of the same type with the same name on
the same node at the same time. Replacing one object with a conflicting object
like this:

foo = OBDEcho("nodename", "test_obdecho")
foo = OBDEcho("nodename", "test_obdecho")

will fail because the second obdecho-object's constructor will run before the old
object has been removed. To replace an object with a conflicting new object the 
fist one has to explisitly be removed first:

foo = OBDEcho("nodename", "test_obdecho")
del foo
foo = OBDEcho("nodename", "test_obdecho")


2. When python exists it will remove all remaining objects without following 
the dependency-rules between objects. This may cause lustre-devices to not
be removed properly. Make sure to delete all references to the lustre-device 
objects _before_ exiting python to make sure this doesn't happen.



Copyright (c) 2005 Scali AS. All Rights Reserved.
"""

import string
import time
import random
import re
import logging
import os
import popen2



# Classes that implement remote execution using different tools/protocols:
# These should subclass Popen3, and implement the same interface.

class scashPopen3(popen2.Popen3):
    """
    Implement the same functionality as popen2.Popen3, but for a
    remote machine.
    """
    def __init__(self, node, cmd, *args, **kwargs):
        """
        As popen2.Popen3, except:
        @node - hostname where to execute cmd
        @cmd - the command to execute. (Needs to be a string!)
        """
        cmd = ["scash", "-n", node, cmd]
        popen2.Popen3.__init__(self, cmd, *args, **kwargs)

class sshPopen3(popen2.Popen3):
    """
    Implement the same functionality as popen2.Popen3, but for a
    remote machine.
    """
    def __init__(self, node, cmd, *args, **kwargs):
        """
        As popen2.Popen3, except:
        @node - hostname where to execute cmd
        @cmd - the command to execute. (Needs to be a string!)
        """
        cmd = ["ssh", node, cmd]
        popen2.Popen3.__init__(self, cmd, *args, **kwargs)


# Select remote execution tool/protocol based on what is actually available:
if os.path.isfile("/opt/scali/bin/scash"):
    remotePopen3 = scashPopen3
elif os.path.isfile("/usr/bin/ssh"):
    remotePopen3 = sshPopen3
else:
    raise Exception("No remote-execution environment found!")


def remoteCommand(node, command):
    """
    Run an external command, and return the output as a list of strings 
    (one string per line). Raise an exception if the command fails 
    (returns non-zero exit-code).
    @node - nodename where to run the command
    @command - the command to run
    """
    remote = remotePopen3(node, command, True)
    exit_code = remote.wait()
    if exit_code != 0 :
        raise Exception("Remote command %s failed with exit-code: %d" % 
            (repr(command), exit_code))
    return remote.fromchild.readlines()

def genUUID():
    """
    Generate a random UUID
    """
    r = random.Random(time.time())
    return "%04x%04x-%04x-%04x-%04x-%04x%04x%04x" % (r.randint(0,16**4), r.randint(0,16**4), 
        r.randint(0,16**4), r.randint(0,16**4), r.randint(0,16**4), 
        r.randint(0,16**4), r.randint(0,16**4), r.randint(0,16**4))

class KernelModule:
    """
    Object to keep track of the usage of a kernel-module, and unload it when
    it's no longer needed. The constructor will check if the module is already
    loaded. If it is, the use_count will be preset to 1 and the module will never
    be automatically unloaded. (Assuming no object will cal decUse without first 
    having called incUse)
    """
    def __init__(self, node, name):
        """
        KernelModule constructor.
        Does _not_ increase the usage-counter or load the module!
        @name - the name of the kernel-module
        """
        self.node = node
        self.name = name
        self.use_count = self.__isLoaded()
    def __isLoaded(self):
        """
        Check if the module is currently loaded
        """
        for line in remoteCommand(self.node, "/sbin/lsmod"):
            if line.split()[0] == self.name:
                return 1
        return 0
    def __load(self):
        """
        Load the module now
        Don't call this directly - call incUse.
        """
        remoteCommand(self.node, "modprobe %s" % self.name)
    def __unload(self):
        """
        Unload the module now.
        Don't call this directly - call decUse.
        """
        remoteCommand(self.node, "rmmod obdecho")
    def incUse(self):
        """
        Call this method before using the module
        """
        self.use_count += 1
        if self.use_count == 1:
            self.__load()
    def decUse(self):
        """
        Call this method when you're done using the module
        """
        self.use_count -= 1
        if self.use_count == 0:
            self.__unload()


class KernelModules:
    """
    Class to keep track of multiple KernelModule-objects
    for multiple kernel-modules on multiple nodes.
    """
    def __init__(self):
        # The KernelModule-objects are stored in self.data
        # The key in self.data is the nodename. The value is a new 
        # new dictionary with module-names as keys and KernelModule
        # objects as values.
        self.data = {}
    def getKernelModule(self, nodename, modulename):
        """
        Lookup (or create) a KernelModule object
        @nodename - the node where the kernel-module should be loaded
        @modulename - the name of the kernel-module
        """
        # Create the object if it's not already in self.data:
        if not self.data.has_key(nodename):
                self.data[nodename] = {}
        if not self.data[nodename].has_key(modulename):
                self.data[nodename][modulename] = KernelModule(nodename, modulename)
        # And then return it:
        return self.data[nodename][modulename]

# This global object is used to keep track of all the loaded kernel-modules:
modules = KernelModules()

def lctl(node, commands):
    """
    Run a set of lctl-commands
    @node - node where to run the commands
    @commands - list of commands
    Returns the output from lctl as a list of strings (one string per line)
    """
    # Encapsulate in quotes:
    commands = string.join(commands, '\n')
    log = logging.getLogger("lctl")
    log.debug("lctl: %s" % repr(commands))
    return remoteCommand(node, 'echo -e "%s" | lctl' % commands)

def find_device(node, search_type, search_name):
    """
    Find the devicenumber for a device
    @ node - the node where the device lives
    @ search_type - the device-type to search for
    @ search_name - the devine-name to search for
    Returns the device-number (int)
    """
    
    for dev in lctl(node, ['device_list']):
        device_id, device_state, device_type, device_name, uuid, refcnt = dev.split()
        if device_type == search_type and device_name == search_name:
            return int(device_id)
    raise ValueError("device not found: %s:%s" % (search_type, search_name))


class OBDEcho:
    """
    Create a obdecho-device (A device that can simulate a ost)
    """
    def __init__(self, node, name):
        """
        The constructor will create the device
        @node - the node where to run the obdecho-device
        @name - the name of the new device
        """
        self.node = node
        self.name = name
        self.uuid = genUUID()
        self.module = modules.getKernelModule(self.node, "obdecho")
        self.module.incUse()
        lctl(self.node, ['attach obdecho %s %s' % (self.name, self.uuid), 'setup n']) 
    def __del__(self):
        """
        The destructor will remove the device
        """
        lctl(self.node, ['cfg_device %s' % self.name, 'cleanup', 'detach'])
        self.module.decUse()


class ExistingOSC:
    """
    Class to represent an existing osc-device
    The object is device is not manipulated in any way - this class
    is just used to keep refer to the device
    """
    def __init__(self, node, name):
        """
        Create a reference to the device
        @node - the node where the device lives
        @name - the name of the device
        """
        self.node = node
        self.name = name

class OSC:
    """
    Create a osc-device (A device that connects to a remote ost/obdecho-device
    and looks like a local obdfilter.
    """
    def __init__(self, node, name, ost):
        """
        Create the device
        @node - the node where to run the OSC
        @name - the name of the new device
        @ost - the object that the osc should be connected to. This should
            be an OBDEcho-object
        """
        self.node = node
        self.name = name
        self.ost = ost
        self.module = modules.getKernelModule(self.node, "obdecho")
        self.module.incUse()
        self.uuid = genUUID()
        # FIXME: "NID_%s_UUID" should probably not be hardcoded? Retrieve uuid from node-object?
        lctl(self.node, ['attach osc %s %s' % (self.name, self.uuid), 'setup %s "NID_%s_UUID"' % (self.ost.uuid, self.ost.node)])
    def __del__(self):
        """
        The destructor will remove the device
        """
        lctl(self.node, ['cfg_device %s' % self.name, 'cleanup', 'detach'])
        self.module.decUse()

class ExistingOBDFilter:
    """
    Class to represent an existing obdfilter-device
    The object is device is not manipulated in any way - this class
    is just used to keep refer to the device
    """
    def __init__(self, node, name):
        """
        Create a reference to the device
        @node - the node where the device lives
        @name - the name of the device
        """
        self.node = node
        self.name = name

class EchoClient:
    """
    Class wrapping echo_client functionality
    """
    def __init__(self, node, name, target):
        """
        Create a new echo_client
        @node - the node to run the echo_client on
        @name - the name of the new echo_client
        @target - The obdfilter / osc device to connect to. This should 
            be an OSC, ExistingOSC or ExistingOBDFilter-object on the same node.
        """
        self.node = node
        self.name = name
        self.target = target
        self.objects = [] # List of objects that have been created and not yet destroyed.
        self.log = logging.getLogger("EchoClient")
        self.module = modules.getKernelModule(self.node, "obdecho")
        self.module.incUse()
        self.uuid = genUUID()
        lctl(self.node, ['attach echo_client %s %s' % (self.name, self.uuid), 'setup %s' % self.target.name])
        self.devicenum = find_device(self.node, 'echo_client', self.name)
        self.log.debug("EchoClient created: %s" % self.name)

    def __del__(self):
        """
        Remove the echo_client, and unload the obdecho module if it is no longer in use
        Destroy all objects that have been created.
        """
        self.log.debug("EchoClient destructor: destroying objects")
        self.destroyObjects(self.objects[:])
        self.log.debug("EchoClient destructor: detach echo_client:")
        lctl(self.node, ['cfg_device %s' % self.name, 'cleanup', 'detach'])
        self.log.debug("EchoClient destructor: Unload modules:")
        self.module.decUse()
        self.log.debug("EchoClient destructor: Done")

    def createObjects(self, num):
        """
        Create new objects on this device
        @num - the number of devices to create
        Returns a list of object-ids.
        """
        oids = []
        line = lctl(self.node, ['device %d' % self.devicenum, 'create %d' % num])
        if line[0].strip() != 'create: %d objects' % num:
            raise Exception("Invalid output from lctl(2): %s" % repr(line[1]))
        pattern=re.compile('create: #(.*) is object id 0x(.*)')
        for line in line[1:]:
            i, oid = pattern.match(line).groups()
            if int(i) != len(oids)+1:
                raise Exception("Expected to find object nr %d - found object nr %d:" % ( len(oids)+1, int(i)))
            oids.append(long(oid, 16))
        self.objects += oids
        return oids

    def destroyObjects(self, objects):
        """
        Destroy a set of objects
        @objects - list of object ids
        """
        for oid in objects:
            lctl(self.node, ['device %d' % self.devicenum, 'destroy %d' % oid])
            self.objects.remove(oid)

    def startTestBRW(self, oid, threads=1, num=1, test='w', pages=1):
        """
        Start an test_brw, and return a remotePopen3-object to the test-process
        Do <num> bulk read/writes on OST object <objid> (<npages> per I/O).
        @oid - objectid for the first object to use.
            (each thread will use one object)
        @threads - number of threads to use
        @num - number of io-operations to perform
        @test - what test to perform ('w' or 'r', for write or read-tests)
        @pages - number of pages to use in each io-request. (4KB on ia32)
        """
        cmd = 'lctl --threads %d q %d test_brw %d %s q %d %d' % \
            (threads, self.devicenum, num, test, pages, oid)

        self.log.debug("startTestBRW: %s:%s" % (self.node, cmd))
        remote = remotePopen3(self.node, cmd, True)
        return remote

    def testBRW(self, oid, threads=1, num=1, test='w', pages=1):
        """
        Do <num> bulk read/writes on OST object <objid> (<npages> per I/O).
        @oid - objectid for the first object to use.
            (each thread will use one object)
        @threads - number of threads to use
        @num - number of io-operations to perform
        @test - what test to perform ('w' or 'r', for write or read-tests)
        @pages - number of pages to use in each io-request. (4KB on ia32)
        """
        test = self.startTestBRW(oid, threads, num, test, pages)
        exit_code = test.wait()
        if exit_code != 0:
            raise Exception("test_brw failed with exitcode %d." % exit_code)

class ParallelTestBRWResult:
    """
    Class to hold result from ParallelTestBRW
    """
    def __init__(self, threads, num, testtype, pages, pagesize, numclients):
        """
        Prepare the result-object with the constants for the test
        threads -- number of threads (per client)
        num -- number of io-operations for each thread
        testtype -- what kind of test ('w' for write-test or 'r' for read-test)
        pages -- number of pages in each request
        pagesize -- pagesize (Assumes same page-size accross all clients)
        numclients -- number of clients used in the tests
        """
        self.threads = threads
        self.num = num
        self.testtype = testtype
        self.pages = pages
        self.pagesize = pagesize
        self.numclients = numclients
        self.starttimes = {} # clientid to starttime mapping
        self.finishtimes = {} # clientid to finishtime mapping
        self.exitcodes = {} # clientid to exit-code mapping
        self.runtimes = {} # clientid to runtime mapping
        self.stdout = {} # clientid to output mapping
        self.stderr = {} # clientid to errors mapping
    def registerStart(self, clientid):
        """
        Register that this client is about to start
        clientid -- the id of the client
        """
        self.starttimes[clientid] = time.time()
    def registerFinish(self, clientid, exitcode, stdout, stderr):
        """
        Register that this client just finished
        clientid -- the id of the client
        exitcode -- the exitcode of this test
        stdout -- the output from the test
        stderr -- the errors from the test
        """
        self.finishtimes[clientid] = time.time()
        self.exitcodes[clientid] = exitcode
        self.stdout[clientid] = stdout
        self.stderr[clientid] = stderr
        self.runtimes[clientid] = self.finishtimes[clientid] - self.starttimes[clientid]
    def getTestType(self):
        """
        Return the name of the test-type ('w' for write-tests and 'r' for read-tests)
        """
        return self.testtype
    def verifyExitCodes(self):
        """
        Verify that all tests finished successfully. Raise exception if they didn't.
        """
        if self.exitcodes.values().count(0) != self.numclients:
            raise Exception("test_brw failed!")
    def getTotalTime(self):
        """
        Return the number of seconds used for the test
        """
        return max(self.finishtimes.values()) - min(self.starttimes.values())
    def getTotalSize(self):
        """
        Return total amount of data transfered (in KB)
        """
        return self.numclients * self.num * self.pages * self.threads * self.pagesize
    def getTotalBandwidth(self):
        """
        Return the total bandwidth for the test
        """
        return self.getTotalSize() / self.getTotalTime()
    def getMaxBandwidth(self):
        """
        Return the bandwidth of the fastest OST
        """
        time = min(self.runtimes.values())
        return self.num * self.pages * self.threads * self.pagesize / time
    def getMinBandwidth(self):
        """
        Return the bandwidth of the fastest OST
        """
        time = max(self.runtimes.values())
        return self.num * self.pages * self.threads * self.pagesize / time



def ParallelTestBRW(echo_clients, threads=1, size=100, tests=('w', 'r'), rsz=1024, pagesize=4):
    """
    Run a test_brw in parallel on a set of echo_clients
    @echo_client -- list of EchoClient-objects to run tests on
    @threads -- number of threads to use per client
    @size -- amount of data to transfer for each thread (MB)
    @test -- list of tests to perform ('w' or 'r', for write or read-tests)
    @rsz -- Amount of data (in KB) for each request. Default, 1024.
    @pagesize - Size of each page (KB)
    """
    pages = rsz / pagesize
    num = size * 1024 / rsz / threads
    # Create objects:
    objects = {}
    for client in echo_clients:
        objects[client] = client.createObjects(threads)
        # Verify if the objectids are consequative:
        for i in range(len(objects[client])-1):
            if objects[client][i+1] != objects[client][i] + 1:
                raise Exception("Non-consequative objectids on client %s: %s" % (client, objects[client]))
    # Run tests:
    results = []
    for test in tests:
        result = ParallelTestBRWResult(threads, num, test, pages, pagesize, len(echo_clients))
        pids = {} # pid to clientid mapping
        remotes = {} # clientid to RemotePopen3-objects
        # Start tests:
        clientid = 0
        for client in echo_clients:
            first_obj = objects[client][0]
            result.registerStart(clientid)
            remote = client.startTestBRW(first_obj, threads, num, test, pages)
            remotes[clientid] = remote
            pids[remote.pid] = clientid
            clientid += 1
        # Wait for tests to finish:
        while pids:
            pid, status = os.wait()
            clientid = pids[pid]
            remote = remotes[clientid]
            # Workaround for leak in popen2, see patch #816059 at python.sf.net:
            popen2._active.remove(remote)
            result.registerFinish(clientid, status, remote.fromchild.read(), remote.childerr.read())
            del pids[pid]
        results.append(result)
    # Clean up objects:
    for client in echo_clients:
        client.destroyObjects(objects[client])
    return results



def timeit(func, *args, **kwargs):
    """
    Helper-function to easily time the execution of a function.
    @func - the function to run
    @*args - possitional arguments
    @**kwargs - keyword arguments
    Returns the number of seconds used executing the function

    Example:
    timeit(max, 1, 2, 5, 2) - will time how long it takes to run max(1,2,5,2)
    """
    t1 = time.time()
    func(*args, **kwargs)
    t2 = time.time()
    return t2-t1

