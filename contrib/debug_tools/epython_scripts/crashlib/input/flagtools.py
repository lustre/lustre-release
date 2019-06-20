
"""
Flag handling routines
Copyright 2015 Cray Inc.  All Rights Reserved
"""


### TBD: The "Simple" in the addSimple* interfaces refers to a flag
### that's a single bit.  It's meant to distinguish from flags that
### have multibit fields, such as the node/zone indices stuck in the
### high end of struct page.flags; or a field that's mostly a pointer
### but with some flags in the low bits.
#
### To add cases like that will mean redoing most of the
### implementation, but all the current interfaces should be ok, with
### new interfaces added to let users define the non-simple flags.

import uflookup


class FlagSet:
    """A collection of flags and values, with routines for translating

    For decoding a flag int to a string, encoding a flag string to an
    int, and providing python identifiers for testing by name, e.g.,

    jafs = FlagSet() # job_attach flagset
    jafs.addSimpleFlag("disable_affinity_apply")
    if job_attach.flags & jafs.disable_affinity_apply: ...

    The advantages over just using a dict include:
    * Define the values once, and get value->string, string->value,
      and python identifiers ns.<name> and ns.<name>_shift as above.
    * The auto-incrementing _next_bit
    """
    def __init__(self, mapping=None):
        """Create and initialize a FlagSet object

        Arguments:
            mapping:    if specified, provides a mapping object, e.g. dict,
                        that supplies the initial key(name)/value pairs.
        """
        # Public dict of flag names to flag values (not the bit number)
        self.str_to_value = {}
        # Public dict of flag values to flag names
        self.value_to_str = {}

        self._next_bit = 0

        # sorted_values is so that translating a value to a string
        # will report the strings in the same order every time.  That
        # order is by numerically increasing value.
        self._sorted_values = []
        self._sorted_strs = []

        if mapping is not None:
            self.addMap(mapping)

    def addSimpleFlag(self, s, bit=None):
        """Add a single-bit flag.

        If bit is not specified, uses the bit one greater than the
        previously defined bit.  If multiple flags are defined to use
        the same bit, value_to_str will remember only the first."""

        if s in self.str_to_value.keys():
            raise ValueError("Flag {0} already defined (value {1:x})".format(
                s, self.str_to_value[s]))
        if s + "_shift" in self.str_to_value.keys():
            raise ValueError("Flag {0} conflicts with another "
                             "flag ({1})".format(s, s + "_shift"))

        try:
            getattr(self, s)
        except AttributeError:
            pass
        else:
            raise ValueError("Value {0} already used by FlagSet object!".
                             format(s))

        try:
            getattr(self, s + "_shift")
        except AttributeError:
            pass
        else:
            raise valueError("{0}_shift already used by FlagSet object!".
                             format(s))


        if bit is None:
            bit = self._next_bit;
        self._next_bit = bit + 1

        value = 1 << bit
        if value not in self.value_to_str:
            self.value_to_str[value] = s
        self.str_to_value[s] = value

        self._sorted_values = []

        setattr(self, s, value)
        setattr(self, s+"_shift", bit)

    def addSimpleFlags(self, *l):
        """Adds a list of single-bit flags."""
        map(self.addSimpleFlag, l)

    def addMap(self, mapping):
        """Add the key/value pairs from a mapping type"""
        for k, v in mapping.items():
            self.addSimpleFlag(k, v)

    def _EnsureSorted(self):
        if self._sorted_values:
            return
        self._sorted_values = sorted(self.value_to_str.keys())
#        self._sorted_strs = sorted(self.str_to_value.keys())


    def flagsToStringList(self, flagint):
        """Translate a given flag int to a list of flag strings."""
        self._EnsureSorted()
        strs = []
        for v in self._sorted_values:
            if flagint & v != 0:
                strs.append(self.value_to_str[v])
                flagint &= ~v
        if flagint != 0:
            strs.append("{0:#x}".format(flagint))
        return strs

    def UFLookup(self, key, **kwargs):
        return uflookup.UFLookup(self.str_to_value, key, **kwargs)

    # TBD: interface to enable a script --dump-flag-translations argument?



def join_flaglist(fl, sep = "|", empty = "0"):
    """Helper function to join a list of flag strings."""
    if fl:
        return sep.join(fl)
    else:
        return empty


### Tests

# I'm trying to follow the convention of

#   assertEquals(expectedvalue, function_under_test(args))

# I didn't discover that (on some unittest page) until I was halfway
# through, so I may not have gotten them all the right order.

if __name__ == '__main__':
    import unittest

    class Test_join_flaglist(unittest.TestCase):
        """Test the join_flaglist function"""

        def assertJoinFlaglistEqual(self, expectedstring, flaglist):
            self.assertEqual(expectedstring, join_flaglist(flaglist))

        def test_single_value(self):
            """Test join_flaglist() with a single value"""
            self.assertJoinFlaglistEqual("aflag", ["aflag"])

        def test_two_values(self):
            """Test join_flaglist() with two values"""
            self.assertJoinFlaglistEqual("aflag|bflag",["aflag", "bflag"])

        def test_three_values(self):
            """Test join_flaglist() with three values"""
            self.assertJoinFlaglistEqual("af|bf|cf", ["af", "bf", "cf"])

        def test_comma_sep(self):
            """Test join_flaglist() with a non-default sep"""
            self.assertEqual("af,bf,cf",
                             join_flaglist(["af", "bf", "cf"], sep=','))

        def test_join_empty(self):
            """Test join_flaglist() with an empty list"""
            self.assertEqual("0", join_flaglist([]))

        def test_join_empty_nondefault(self):
            """Test join_flaglist() with a non-default value of empty"""
            self.assertEqual(" ", join_flaglist([], empty=" "))


    class Test_FlagSet(unittest.TestCase):
        """Test the FlagSet class"""

        def setUp(self):
            self.fs = FlagSet()

        def VerifyFlag(self, string, value):
            """Test string->value and value->string"""
            self.assertEqual(value, self.fs.str_to_value[string])
            self.assertEqual(string, self.fs.value_to_str[value])
            self.assertEqual(value, getattr(self.fs, string))
            self.assertEqual(value, 1<<getattr(self.fs, string+"_shift"))

    class Test_FlagSet_Constructor(Test_FlagSet):
        def test_constructor(self):
            """Too much?"""
            self.assertEqual(self.fs._next_bit, 0)
            self.assertFalse(self.fs.value_to_str)
            # etc.

    class Test_Add_Simple_Flag(Test_FlagSet):
        def test_add_simple_flag(self):
            """Test that adding a simple flag to an empty FlagSet works"""
            self.fs.addSimpleFlag("FOO")
            self.VerifyFlag("FOO", 1)

        def test_3_add_simple_flag(self):
            """Test multiple addSimpleFlag calls"""
            self.fs.addSimpleFlag("FOO")
            self.fs.addSimpleFlag("BAR")
            self.fs.addSimpleFlag("BAZ")

            self.VerifyFlag("FOO", 1)
            self.VerifyFlag("BAR", 2)
            self.VerifyFlag("BAZ", 4)

            self.assertEqual(1, self.fs.FOO)
            self.assertEqual(2, self.fs.BAR)
            self.assertEqual(4, self.fs.BAZ)

            self.assertEqual(0, self.fs.FOO_shift)
            self.assertEqual(1, self.fs.BAR_shift)
            self.assertEqual(2, self.fs.BAZ_shift)

            self.fs._EnsureSorted()
#            self.assertEqual(self.fs._sorted_strs, ["BAR", "BAZ", "FOO"])
            self.assertEqual(self.fs._sorted_values, [1, 2, 4])

        def test_add_simple_flag_with_value(self):
            """Test addSimpleFlag calls with explicit bit="""
            self.fs.addSimpleFlag("FOO")
            self.fs.addSimpleFlag("BAR", bit=1)
            self.fs.addSimpleFlag("BAZ")
            self.fs.addSimpleFlag("BLAT", bit=17)
            self.fs.addSimpleFlag("FROB")
            self.fs.addSimpleFlag("SNARF", bit=5)

            self.VerifyFlag("FOO", 1)
            self.VerifyFlag("BAR", 2)
            self.VerifyFlag("BAZ", 4)
            self.VerifyFlag("SNARF", 32)
            self.VerifyFlag("BLAT", 1<<17)
            self.VerifyFlag("FROB", 1<<18)

            self.fs._EnsureSorted()
#            self.assertEqual(self.fs._sorted_strs,
#                             ["BAR", "BAZ", "BLAT", "FOO", "FROB"])
            self.assertEqual(self.fs._sorted_values,
                             [1, 2, 4, 32, 1<<17, 1<<18])


        def test_add_simple_flag_dup_name(self):
            """Test exception on duplicate flag name"""
            self.fs.addSimpleFlag("FOO")
            self.assertRaises(ValueError, self.fs.addSimpleFlag, "FOO")

        def test_add_simple_flag_dup_value(self):
            """Test exception on duplicate flag value"""
            self.fs.addSimpleFlag("FOO")
            self.fs.addSimpleFlag("BAR", bit=0)

            self.VerifyFlag("FOO", 1)
            self.assertEqual(1, self.fs.str_to_value["BAR"])

        def test_add_shift_duplicated_name(self):
            """Test that name and name_shift can't both be added"""
            self.fs.addSimpleFlag("FOO_shift")
            self.assertRaises(ValueError, self.fs.addSimpleFlag, "FOO")
            self.assertRaises(ValueError,
                              self.fs.addSimpleFlag, "FOO_shift_shift")

        def test_attr_name_conflict(self):
            """Test that adding a flag won't clobber an object attribute"""
            self.assertRaises(ValueError,
                              self.fs.addSimpleFlag, "addSimpleFlag")

    class Test_Add_Simple_Flags(Test_FlagSet):
        def test_add_simple_flags(self):
            """Test that addSimpleFlags() can add several flags"""

            self.fs.addSimpleFlags("FOO", "BAR", "BAZ")
            self.VerifyFlag("FOO", 1)
            self.VerifyFlag("BAR", 2)
            self.VerifyFlag("BAZ", 4)

    class Test_FlagSet_mapping(Test_FlagSet):
        def setUp(self):
            self.fs = FlagSet(mapping={"FOO": 9, "BAR": 1})

        def test_constructor(self):
            self.VerifyFlag("FOO", 1<<9)
            self.VerifyFlag("BAR", 1<<1)

        def test_addMap(self):
            self.fs.addMap({"BAZ": 3, "ZING": 7})

            self.VerifyFlag("FOO", 1<<9)
            self.VerifyFlag("BAR", 1<<1)
            self.VerifyFlag("BAZ", 1<<3)
            self.VerifyFlag("ZING", 1<<7)

    class Test_FlagSet_FBBZZ(Test_FlagSet):
        """FlagSet with certain set of flags"""
        def setUp(self):
            self.fs = FlagSet()
            self.fs.addSimpleFlags("FOO", "BAR", "BAZ")
            self.fs.addSimpleFlag("ZING", bit=13)
            self.fs.addSimpleFlag("ZOING", bit=42)

        def Verify_F2SL(self, expectedstrlist, flags):
            self.assertEqual(expectedstrlist, self.fs.flagsToStringList(flags))

    class Test_FlagSet_FBBZZ_flagsToStringList(Test_FlagSet_FBBZZ):
        def test_F(self):
            self.Verify_F2SL(["FOO"], 1)
        def test_B(self):
            self.Verify_F2SL(["BAR"], 2)
        def test_B2(self):
            self.Verify_F2SL(["BAZ"], 4)
        def test_Z(self):
            self.Verify_F2SL(["ZING"], 1<<13)
        def test_Z2(self):
            self.Verify_F2SL(["ZOING"], 1<<42)

        def test_FB(self):
            self.Verify_F2SL(["FOO", "BAR"], 3)
        def test_FBB(self):
            self.Verify_F2SL(["FOO", "BAR", "BAZ"], 7)
        def test_FB2(self):
            self.Verify_F2SL(["BAR", "BAZ"], 6)

        def test_FBBZZ(self):
            self.Verify_F2SL(["FOO", "BAR", "BAZ", "ZING", "ZOING"],
                             7|1<<13|1<<42)

        def test_unknownflag(self):
            self.Verify_F2SL(["0x10"], 0x10)
        def test_unknownflags(self):
            self.Verify_F2SL(["0x30"], 0x30)
        def test_knownandunknownflags(self):
            self.Verify_F2SL(["FOO", "0x30"], 0x31)


    # Run all unit tests
    unittest.main()
