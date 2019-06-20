
"""
User Friendly Lookup routine
Copyright 2015 Cray Inc.  All Rights Reserved
"""

# TBD: Maybe it would be more useful to replace prefixok with
# substringok, for cases with lots of common prefix, like
# CAP_SYS_PTRACE and CAP_SYS_TTY_CONFIG
#
# Wait until there's a user for it.

def UFLookup(d, key, casesensitive=False, prefixok=True):
    """User Friendly Lookup

    By default, case-insensitive, unique-prefix-accepting lookups on
    dict d"""

    def _casesensitive_prefixok(d, key):
        """case sensitive, prefixes ok"""
        matches = []
        for s in d.keys():
            if s == key:
                return d[s]
            if s.startswith(key):
                matches.append(s)
        if len(matches) == 1:
            return d[matches[0]]
        raise KeyError("{0} matches multiple keys: {1}".format(
            key, ", ".join(matches)))

    def _caseinsensitive_prefixok(d, key):
        """case insensitive, prefixes ok"""
        matches = []
        lkey = key.lower()
        for s in d.keys():
            if s.lower() == lkey:
                return d[s]
            if s.lower().startswith(lkey):
                matches.append(s)
        if len(matches) == 0:
            raise KeyError("No match for {0}".format(key))
        if len(matches) == 1:
            return d[matches[0]]
        raise KeyError("{0} matches multiple keys: {1}".format(
            key, ", ".join(matches)))

    def _caseinsensitive_noprefix(d, key):
        """case insensitive, prefixes not ok"""
        lkey = key.lower()
        for s in d.keys():
            if s.lower() == lkey:
                return d[s]
        raise KeyError("No match for {0}".format(key))

    def _casesensitive_noprefix(d, key):
        """case sensitive, prefixes not ok"""
        return d[key]

    if casesensitive and not prefixok:
        return _casesensitive_noprefix(d, key)
    if casesensitive:
        return _casesensitive_prefixok(d, key)
    if prefixok:
        return _caseinsensitive_prefixok(d, key)
    return _caseinsensitive_noprefix(d, key)



if __name__ == '__main__':
    import unittest

    class Test_UFLookup_FBBZZ(unittest.TestCase):
        def setUp(self):
            self.d = { "FOO": 1,
                       "BAR": 2,
                       "baz": 3,
                       "zing": 4,
                       "zinGlinG": 5 }

        def checkall(self, expectedlist, key):
            """Test UFLookup(self.d, key) for all four flags combinations.

            expectedlist[] contains the four expected results,
            [0]: casesensitive = False, prefixok = False
            [1]: casesensitive = False, prefixok = True
            [2]: casesensitive = True,  prefixok = False
            [3]: casesensitive = True,  prefixok = True

            If expectedlist[i] is None, then UFLookup should raise
            KeyError for that case.  Otherwise, it's the value that
            should be returned."""

            kdicts = [{"casesensitive": False, "prefixok": False},
                      {"casesensitive": False, "prefixok": True},
                      {"casesensitive": True,  "prefixok": False},
                      {"casesensitive": True,  "prefixok": True}]
            for i in xrange(len(expectedlist)):
                e = expectedlist[i]
                if e is None:
                    self.assertRaises(KeyError,
                                      UFLookup, self.d, key, **kdicts[i])
                else:
                    self.assertEqual(e, UFLookup(self.d, key, **kdicts[i]))

        def test_FOO(self):
            self.checkall([1, 1, 1, 1], "FOO")
        def test_foo(self):
            self.checkall([1, 1, None, None], "foo")
        def test_F(self):
            self.checkall([None, 1, None, 1], "F")
        def test_f(self):
            self.checkall([None, 1, None, None], "f")


        def test_ambig_prefix_zin(self):
            self.checkall([None, None, None, None], "zin")
        def test_semiambig_prefix_ba(self):
            self.checkall([None, None, None, 3], "ba")
        def test_prefix_exactmatch_zing(self):
            self.checkall([4, 4, 4, 4], "zing")
        def test_prefix_semiexact_zinG(self):
            self.checkall([4, 4, None, 5], "zinG")


    # Run all unit tests
    unittest.main()
