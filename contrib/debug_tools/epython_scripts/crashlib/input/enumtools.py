
"""
Routines for handling enums (or other symbolic names)
Copyright 2015 Cray Inc.  All Rights Reserved
"""

import uflookup

class NameSet:
    """Two-way translation between int values (enums, #defines) and strings.
    Also provides access to value by e.g.:
    vms = NameSet()  # vmstat nameset
    vms.AddName("NR_FILE_MAPPED", 8)
    vms.NR_FILE_MAPPED == 8

    The advantages over just using a dict include:

    * Define the values once, and get value->string, string->value,
      and python identifier ns.<name> as above.
    * The auto-incrementing _next_value
      """

    def __init__(self, mapping=None):
        """Create and initialize a NameSet object

        Arguments:
            mapping:    if specified, provides a mapping object, e.g. dict,
                        that supplies the initial key(name)/value pairs.
        """
        self.value_to_name = {}
        self.name_to_value = {}

        self._next_value = 0
#        self._sorted_values = []
#        self._sorted_names = []

        if mapping is not None:
            self.addMap(mapping)

    def addName(self, name, value=None):
        """Add a single name, by default using the next value.

        If two names end up with the same value, the value will map
        only to the first of them.
        """

        if name in self.name_to_value.keys():
            raise ValueError("Name {0} already defined (value {1})".format(
                name, self.name_to_value[name]))
        try:
            getattr(self, name)
        except AttributeError:
            pass
        else:
            raise ValueError("Value {0} already used by NameSet object!".
                             format(value))

        if value is None:
            value = self._next_value
        self._next_value = value + 1

        self.name_to_value[name] = value
        if value not in self.value_to_name:
            self.value_to_name[value] = name
 #       self._sorted_values = []
 #       self._sorted_names = []

        setattr(self, name, value)

    def addNames(self, *namelist):
        """Add a list of names, each using the respective next value"""
        map(self.addName, namelist)

    def addMap(self, mapping):
        """Add the key/value pairs from a mapping type"""
        for k, v in mapping.items():
            self.addName(k, v)

    def UFLookup(self, key, **kwargs):
        return uflookup.UFLookup(self.name_to_value, key, **kwargs)

#    def somethingUsingSortedArrays:
#        if not self._sorted_values:
#            self._sorted_values = sorted(self.value_to_name.keys())
#            self._sorted_names = sorted(self.name_to_value.keys())



if __name__ == '__main__':
    import unittest

    class Test_NameSet(unittest.TestCase):
        """Test the NameSet class"""

        def VerifyName(self, name, value):
            """Verify that self.ns has name <-> value"""
            self.assertEqual(value, self.ns.name_to_value[name])
            self.assertEqual(value, getattr(self.ns, name))
            self.assertEqual(name, self.ns.value_to_name[value])

    class Test_Empty(Test_NameSet):
        """Test an empty NameSet"""
        def setUp(self):
            self.ns = NameSet()

        def test_empty_vtn(self):
            self.assertEqual(0, len(self.ns.value_to_name))
        def test_empty_ntv(self):
            self.assertEqual(0, len(self.ns.name_to_value))


    class Test_addName(Test_NameSet):
        """Test addName"""
        def setUp(self):
            self.ns = NameSet()

        def test_add_one_name(self):
            self.ns.addName("FOO")

            self.VerifyName("FOO", 0)
            self.assertEqual(0, self.ns.FOO)

        def test_add_two_names(self):
            self.ns.addName("BAR")
            self.ns.addName("BAZ")

            self.VerifyName("BAR", 0)
            self.VerifyName("BAZ", 1)
            self.assertEqual(0, self.ns.BAR)
            self.assertEqual(1, self.ns.BAZ)


        def test_add_namevalue(self):
            self.ns.addName("FOO", 87)
            self.VerifyName("FOO", 87)
            self.assertEqual(87, self.ns.FOO)

        def test_reuse_existing_value(self):
            self.ns.addName("FOO", 2)
            self.ns.addName("B0",0)
            self.ns.addName("B1")
            self.ns.addName("B2")
            self.ns.addName("B3")

            self.VerifyName("FOO", 2)
            self.VerifyName("B0", 0)
            self.VerifyName("B1", 1)
            self.assertEqual(2, self.ns.name_to_value["B2"])
            self.VerifyName("B3", 3)

            self.assertEqual(2, self.ns.FOO)
            self.assertEqual(0, self.ns.B0)
            self.assertEqual(1, self.ns.B1)
            self.assertEqual(3, self.ns.B3)

        def test_addNames(self):
            self.ns.addNames("FOO", "BAR", "BAZ")
            self.VerifyName("FOO", 0)
            self.VerifyName("BAR", 1)
            self.VerifyName("BAZ", 2)

            self.assertEqual(0, self.ns.FOO)
            self.assertEqual(1, self.ns.BAR)
            self.assertEqual(2, self.ns.BAZ)

        def test_addDupName(self):
            self.ns.addName("FOO", 1)
            self.assertRaises(ValueError, self.ns.addName, "FOO", 2)

        def test_addDupValue(self):
            self.ns.addName("FOO")
            self.ns.addName("BAR", 0)

            self.VerifyName("FOO", 0)
            self.assertEqual(0, self.ns.name_to_value["BAR"])

        def test_addMoreDupValues(self):
            self.ns.addName("FOO")
            self.ns.addName("BAR", 0)
            self.ns.addName("BAZ", 0)

            self.VerifyName("FOO", 0)
            self.assertEqual(0, self.ns.name_to_value["BAR"])
            self.assertEqual(0, self.ns.name_to_value["BAZ"])


        def test_addConflicting(self):
            self.assertRaises(ValueError, self.ns.addName, "addName")


    class Test_mapping(Test_NameSet):
        """Test map handling"""
        def setUp(self):
            self.ns = NameSet(mapping={"SLEEPY":1, "GRUMPY": 0})

        def test_constructor(self):
            self.VerifyName("SLEEPY", 1)
            self.VerifyName("GRUMPY", 0)

        def test_addMap(self):
            self.ns.addMap({"DOC": 9, "BASHFUL": 3})

            self.VerifyName("SLEEPY", 1)
            self.VerifyName("GRUMPY", 0)
            self.VerifyName("DOC", 9)
            self.VerifyName("BASHFUL", 3)


    # Run all unit tests
    unittest.main()

