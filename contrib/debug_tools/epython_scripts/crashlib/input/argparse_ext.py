
"""
Module which provides extensions for the standard Python argparse module.
Copyright 2015 Cray Inc.  All Rights Reserved
"""

import argparse
import copy

from argparse import _ensure_value, Action, ArgumentTypeError


class ExtendAction(Action):
    """Action to extend a list of argument values

    This action is similar to the standard AppendAction, but uses the
    extend() attribute of lists rather than the append() attribute.  As
    such, it also has an additional requirement:

    -   This action must receive an iterable 'values' argument from the
        parser.  There are two ways to make this happen:

        1.  Use type= to produce an iterable, e.g. type=str or type=list
        2.  Use nargs= to cause the parser to produe a list, which it
            does for any nargs= setting that is not None (default) and
            is not '?'
    """

    def __call__(self, parser, namespace, values, option_string):
        items = copy.copy(_ensure_value(namespace, self.dest, []))

        try:
            items.extend(values)
        except TypeError:
            # Assume the TypeError is because values is not iterable
            raise ArgumentTypeError(
                "argument type '{:s}' is not iterable".format(
                    type(values).__name__))

        setattr(namespace, self.dest, items)


def str2list(string, sep=',', totype=None, choices=None):
    """Split a string into a list with conversion and validation

    Split a string into a list, optionally convert each element to a
    given type and optionally validate that all resulting values are
    in a collection of valid values.
    """

    plural = {False: '', True: 's'}

    # Values should be string or an iterable container of strings.
    # Split values on the separator into a list
    try:
        lst = string.split(sep)
    except AttributeError:
        raise ArgumentTypeError(
            "argument type '{:s}' does not have split() attribute".format(
                type(string).__name__))

    # Perform type conversion
    if totype is not None:
        errs = []
        for i, v in enumerate(lst):
            try:
                lst[i] = totype(v)
            except (TypeError, ValueError):
                errs.append(v)
        if errs:
            msg = "invalid {:s} value{:s}: {!r:s}".format(
                totype.__name__, plural[len(errs) > 1], errs)
            raise ArgumentTypeError(msg)

    # Verify each separate value
    if choices is not None:
        errs = filter(lambda x:x not in choices, lst)
        if errs:
            msg = "invalid choice{:s}: {!r:s} (choose from {!s:s})".format(
                plural[len(errs) > 1], errs, choices)
            raise ArgumentTypeError(msg)

    return lst


def tolist(sep=',', totype=None, choices=None):
    """Returns a parameterized callable for argument parser type conversion

    This function returns a function which accepts a single argument at
    call time and which uses the supplied arguments to modify its conversion
    behavior.
    """
    return lambda x:str2list(x, sep=sep, totype=totype, choices=choices)


if __name__ == '__main__':
    import unittest

    class Test_Action_Base(unittest.TestCase):
        """Create a base class for testing argparse Action classes"""

        def setUp(self):
            """Create the ExtendAction object and args Namespace"""
            self.action = ExtendAction([], dest='dest')
            self.args   = argparse.Namespace()

        def actionRun(self, values):
            """Run the Action instance using values"""
            self.action(None, self.args, values, '')

        def actionEqual(self, values, expected):
            """Run the Action and check the expected results"""
            self.actionRun(values)
            self.assertEqual(self.args.dest, expected)

        def actionArgTypeErr(self, values):
            """Run the Action and verify it raises ArgumentTypeError"""
            self.assertRaises(
                ArgumentTypeError, self.action, None, self.args, values, '')


    class Test_ExtendAction(Test_Action_Base):
        """Test the ExtendAction class"""

        def test_non_iterable(self):
            """Test ExtendAction with a non-iterable type

            This is similar to:
                parser.add_argument('-z', nargs=None, type=int ...)

                parser.parse_args(['-z', '0'])
            """
            self.actionArgTypeErr(0)

        def test_single_value(self):
            """Test ExtendAction with a single value

            This is similar to:
                parser.add_argument('-z', nargs=None ...)

                parser.parse_args(['-z', 'a'])
            """
            self.actionEqual('a', ['a'])

        def test_single_string(self):
            """Test ExtendAction with a single value

            This is similar to:
                parser.add_argument('-z', nargs=None ...)

                parser.parse_args(['-z', 'abc'])
            """
            self.actionEqual('abc', ['a', 'b', 'c'])

        def test_single_value_multiple_calls(self):
            """Test ExtendAction with a single value and multiple calls

            This is similar to:
                parser.add_argument('-z', nargs=None, type=int ...)

                parser.parse_args(['-z', 'a', '-z', 'b'])
            """
            self.actionEqual('a', ['a'])
            self.actionEqual('b', ['a', 'b'])

        def test_value_list(self):
            """Test ExtendAction with a value list

            This is similar to:
                parser.add_argument('-z', nargs=1 ...)

                parser.parse_args(['-z', 'abc'])
            """
            self.actionEqual(['abc'], ['abc'])

        def test_value_list_multiple_calls(self):
            """Test ExtendAction with a single value and multiple calls

            This is similar to:
                parser.add_argument('-z', nargs=1 ...)

                parser.parse_args(['-z', 'abc', '-z', 'def'])
            """
            self.actionRun(['abc'])
            self.actionEqual(['def'], ['abc', 'def'])

        def test_value_list_multiple_values(self):
            """Test ExtendAction with a value list of length > 1

            This is similar to:
                parser.add_argument('-z', nargs=2 ...)
                -or-
                parser.add_argument('-z', nargs='+' ...)
                -or-
                parser.add_argument('-z', nargs='*' ...)

                parser.parse_args(['-z', 'abc', 'def'])
            """
            self.actionEqual(['abc', 'def'], ['abc', 'def'])


    class Test_tolist_str2list(unittest.TestCase):
        """Test the str2list and tolist conversion functions"""

        def test_sep(self):
            """Verify default and non-default separators work"""
            f = tolist()
            self.assertEqual(f('a,b,c'), ['a','b','c'])
            f = tolist(sep=':')
            self.assertEqual(f('a:b:c'), ['a','b','c'])

        def test_non_iterable(self):
            """Verify a non-iterable string is caught"""
            f = tolist()
            self.assertRaises(ArgumentTypeError, f, 0)

        def test_type_conversion(self):
            """Verify type conversion works properly"""
            f = tolist(totype=int)
            self.assertEqual(f('0,1,2'), [0, 1, 2])
            self.assertRaises(
                ArgumentTypeError, f, '1,z,2,q')

        def test_choices(self):
            """Verify the choices validation works properly"""
            f = tolist(totype=int, choices=[0, 1, 2, 3])
            self.assertEqual(f('0,1,2'), [0, 1, 2])
            self.assertRaises(ArgumentTypeError, f, '0,5,2')


    unittest.main()
