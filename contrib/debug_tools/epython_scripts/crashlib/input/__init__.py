
"""
Input handling routines
Copyright 2014 Cray Inc.  All Rights Reserved
"""


import itertools


# Define some common integer multiplier suffixes

# Powers of two
binary_suffixes={
    'k': 2**10, 'K': 2**10,
    'm': 2**20, 'M': 2**20,
    'g': 2**30, 'G': 2**30,
    't': 2**40, 'T': 2**40,
    'p': 2**50, 'P': 2**50
}
memory_suffixes = binary_suffixes

# Powers of ten
decimal_suffixes={
    'k': 10**3,  'K': 10**3,
    'm': 10**6,  'M': 10**6,
    'g': 10**9,  'G': 10**9,
    't': 10**12, 'T': 10**12,
    'p': 10**15, 'P': 10**15
}
disk_suffixes = decimal_suffixes

default_bases = [0, 16]

def toint(string, base=default_bases, suffixes=binary_suffixes):
    """Convert to integer with flexible base and multiplier support.

    Provide a way to handle input that may be in any of several number
    bases but may not use the appropriate prefix, e.g. 'deadbeef' rather
    than the more pedantic '0xdeadbeef'. Also provide support for
    multiplier suffixes, such as 'K' for kilo.

    Arguments:

        string      - string to convert to integer
        base        - a single number, as used in int() or an iterable
                      of base values to try
        suffixes    - dictionary keyed by the string suffix with a value
                      to be used as a multiplier

    The default base of [0, 16] allows the automatic recognition of numbers
    with the standard prefixes and if that fails, tries a base 16 conversion.
    """
    try:
        bases = list(base)
    except TypeError:
        # Object isn't iterable, so create one that is
        bases = [base]

    for b in bases:
        if not (b == 0 or 2 <= b <= 36):
            raise ValueError(
                "toint() base {!s:s} must be >= 2 and <= 36".format(b))

    multiplier = 1
    try:
        # Second iteration is after removing any suffix.  This way, if
        # a suffix happens to contain valid numeric characters, we'll
        # try the numeric interpretation before we try their multiplier
        # meaning, e.g. 'g' is a valid numeric value in base 17).
        for i in xrange(2):
            for b in bases:
                try:
                    return int(string, b) * multiplier
                except ValueError:
                    pass

            if i != 0:
                raise ValueError

            # Find a suffix that matches the end of the string and use it
            for k, v in suffixes.iteritems():
                if string.endswith(k):
                    multiplier = v
                    string = string[0:-len(k)]
                    break
            else:
                raise ValueError

    except ValueError:
        suffix_list = suffixes.keys()
        suffix_list.sort()
        raise ValueError(
            "invalid literal '{:s}' for toint() with base {!s:s} "
            "and suffixes {!s:s}".format(string, list(bases), suffix_list))


def hex2int(string):
    """Wrapper for toint() which prefers base 16 input

    This function is useful in situations where a callable must be passed,
    such as with argparse.add_argument(type=hex2int, ...
    """
    return toint(string, base=[16, 0])


def to_rangelist(args, default=xrange(0), base=[0,16],
                  suffixes=binary_suffixes):
    """Convert a bunch of range list strings into a list of ranges

    The arguments are:

        args     - iterable containing ranglist strings
        default  - iterator to return if args is empty
        base     - number base to use for integer conversion
        suffixes - integer multiplier suffixes

    Each arg is taken to be a range list, where a range list may be:

        rangelist ::= range[,range]...
        range     ::= <first>-<last> | <first>#<count> | <value>

    where the range first-last is inclusive.
    """
    if len(args) == 0:
        return default

    ranges = []
    for range_list_str in args:
        range_strs = range_list_str.split(',')
        for range_str in range_strs:
            if "-" in range_str:
                fields = range_str.split('-', 1)
                start = toint(fields[0], base, suffixes=suffixes)
                end = toint(fields[1], base, suffixes=suffixes) + 1
                ranges.append(xrange(start, end))
            elif "#" in range_str:
                fields = range_str.split('#', 1)
                start = toint(fields[0], base, suffixes=suffixes)
                end = start + toint(fields[1], base, suffixes=suffixes)
                ranges.append(xrange(start, end))
            else:
                start = toint(range_str, base, suffixes=suffixes)
                end = start + 1
                ranges.append(xrange(start, end))

    return ranges


def iter_rangestr(*args, **kwargs):
    """Convert a bunch of range list strings into a single iterator

    The arguments are the same as for to_rangelist().
    """
    return itertools.chain(*to_rangelist(*args, **kwargs))


if __name__ == '__main__':
    import unittest

    # toint()
    class Test_toint(unittest.TestCase):
        def test_base_zero(self):
            self.assertEqual(toint('0b10', 0), 2)
            self.assertEqual(toint('0o10', 0), 8)
            self.assertEqual(toint('10', 0), 10)
            self.assertEqual(toint('0x10', 0), 16)

        def test_base_out_of_range(self):
            self.assertRaises(ValueError, toint, '10', -1)
            self.assertRaises(ValueError, toint, '10',  1)
            self.assertRaises(ValueError, toint, '10', 37)

        def test_base_search(self):
            bases = [0, 16]
            self.assertEqual(toint('10', bases), 10)
            self.assertEqual(toint('f', bases), 15)

            self.assertEqual(toint('0b10', bases), 2)
            self.assertEqual(toint('0o10', bases), 8)
            self.assertEqual(toint('10', bases), 10)
            self.assertEqual(toint('0x10', bases), 16)

        def test_suffixes(self):
            for k, v in binary_suffixes.iteritems():
                self.assertEqual(toint('0b10'+k), 0b10*v)
                self.assertEqual(toint('0o10'+k), 0o10*v)
                self.assertEqual(toint('10'+k), 10*v)
                self.assertEqual(toint('0x10'+k), 0x10*v)

        def test_suffix_number_overlap(self):
            # Verify a valid numeric isn't used as a suffix
            self.assertEqual(toint('1g', 17), 33)
            self.assertEqual(toint('1gk', 17), 33*binary_suffixes['k'])


    # hex2int()
    class Test_hex2int(unittest.TestCase):
        """Verify the hex2int() function"""
        def test_explicit_base(self):
            """Verify that explicit base syntax is honored"""
            self.assertEqual(hex2int('0x10'), 16)
            self.assertEqual(hex2int('0o10'), 8)

        def test_default_base(self):
            """Verify that base 16 is preferred"""
            self.assertEqual(hex2int('10'), 16)
            self.assertEqual(hex2int('0b10'), 2832)


    # iter_rangelist()
    class Test_iter_rangelist(unittest.TestCase):
        """Test both iter_rangelist and the underlying to_rangelist."""
        def test_good_single_ranges(self):
            self.assertEqual(list(iter_rangestr([])), [])
            self.assertEqual(list(iter_rangestr(['1-2'])), list(xrange(1,3)))
            self.assertEqual(list(iter_rangestr(['1#2'])), list(xrange(1,3)))
            self.assertEqual(list(iter_rangestr(['1'])), list(xrange(1,2)))

        def test_good_multiple_ranges(self):
            test_rangestrs = [
                # Test params,        Expected result
                (['1', '3-5', '1#2'], [1, 3, 4, 5, 1, 2]),
                ]

            for ranges, expected in test_rangestrs:
                # Test the ranges as separate list elements
                self.assertEqual(list(iter_rangestr(ranges)), expected)

                # Test the ranges joined by commas
                joined = [','.join(ranges)]
                self.assertEqual(list(iter_rangestr(joined)), expected)

        def test_bad_single_ranges(self):
            self.assertRaises(ValueError, iter_rangestr, ['1#2#3'])
            self.assertRaises(ValueError, iter_rangestr, ['1#2-3'])
            self.assertRaises(ValueError, iter_rangestr, ['1-2#3'])
            self.assertRaises(ValueError, iter_rangestr, ['1-2-3'])

    # Run all unit tests
    unittest.main()
