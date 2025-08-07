#!/usr/bin/env python3

#
# logic snipped from analyze_patch() here:
# https://github.com/verygreen/lustretester/blob/master/gerrit_build-and-test-new.py
#

import json
import os
import re
import sys

if len(sys.argv[1:]) != 1:
    print("script takes 1 argument; path to output of git format-patch for the patch to analyze")
    sys.exit(1)

# script takes 1 argument; the path to the output of git format-patch
file_path = sys.argv[1:][0]

# verify the path exists
if not os.path.exists(file_path):
    print("'%s' does not exist" % file_path)
    sys.exit(1)


def affected_files(patch_content):
    """
    Parse a git patch content and categorize file changes.

    Args:
        patch_content (str): Content of the git patch

    Returns:
        dict: Dictionary with lists of modified, added, and deleted files
    """
    changes = { 'm': [ ], 'a': [ ], 'd': [ ] }
    current_file = None

    for line in patch_content.splitlines():
        if line.startswith('diff --git'):
            # Extract filename from: diff --git a/path/to/file b/path/to/file
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[2][2:]  # Remove 'a/' prefix
                if current_file not in [f for files in changes.values() for f in files]:
                    changes['m'].append(current_file)
        elif line.startswith('new file mode'):
            if changes['m'] and current_file:
                changes['m'].pop()  # Remove from modified if added
            if current_file:
                changes['a'].append(current_file)
        elif line.startswith('deleted file mode'):
            if changes['m'] and current_file:
                changes['m'].pop()  # Remove from modified if deleted
            if current_file:
                changes['d'].append(current_file)

    return changes

# read the file in
with open(file_path, 'r') as file:
    # Read the entire file into a string
    patch = file.read()

change = {}
chfile = None
function = None
newtests = [] # captures newly created tests
for line in patch.splitlines():
    if line.startswith('+++ '):
        if newtests:
            if not change.get('updated_tests'):
                change['updated_tests'] = {}
            if basename.endswith('.sh') or basename == 'runtests':
                change['updated_tests'].update({basename.replace('.sh', ''):newtests})
            newtests = []
        chfile = line.replace('+++ b/', '')
        basename = os.path.basename(chfile)
    if not chfile: # diff did not start yet - skip
        continue
    if line.startswith('--- '): # src file - skip
        continue
    if line.startswith('@@ '):
        tags = line.split(' ', 5)
        if tags[0] != '@@' or tags[3] != '@@':
            print("Malformed patch line: " + line)
            continue
        if len(tags) > 4:
            function = tags[4].replace('()', '')
            if function.endswith("{"):
                function = function[:-1]
        else:
            function = None
    if line.startswith(' '): # context line, not a change - skip
        # context changed to new function, record it.
        if (basename.endswith(".sh") or basename == 'runtests') and line.startswith(' test_'):
            tags = line[1:].split(' ')
            function = tags[0].replace('()', '')
            if function.endswith("{"):
                function = function[:-1]
        continue
    if re.match(r"^[-+][^\-+]", line): # added/removed/changed line
        tmp = line.replace(' ', '').replace('\t', '') # remove spaces
        if not line[1:]: # empty line? skip
            continue
        if tmp[1:].startswith('#'): # comment, skip
            continue
        if line[1:].startswith('test_'):
            function = None # Added or removed function, we'll catch with the +run_test
        if function and function not in newtests:
            if (basename.endswith('.sh') or basename == 'runtests') and function.startswith("test_"):
                newtests.append(function)
            function = None # To ease our work
    if re.match(r"^[+][^+]", line): # Added/changed line
        if basename.endswith('.sh') or basename == 'runtests':
            # Try to detect a new test added.
            # while we can try and detect new function added, instead
            # in our framework there's a very specific pattern:
            # +run_test 65 "Check lfs quota result"
            # So let's match for that instead
            if line.startswith("+run_test "):
                tags = line.split(" ")
                if len(tags) > 1:
                    test = "test_" + tags[1]
                    newtests.append(test)
# Catch remaining stuff
if newtests and (basename.endswith('.sh') or basename == 'runtests'):
    if not change.get('updated_tests'):
        change['updated_tests'] = {}
    change['updated_tests'].update({basename.replace('.sh', ''):newtests})

# Check if parallel-scale-nfs exists in updated_tests and handle it specially
if 'updated_tests' in change and 'parallel-scale-nfs' in change['updated_tests']:
    # Get the tests associated with parallel-scale-nfs
    nfs_tests = change['updated_tests']['parallel-scale-nfs']

    # Define target keys
    target_keys = ['parallel-scale-nfsv3', 'parallel-scale-nfsv4']

    # Process each target key
    for target_key in target_keys:
        # Simply assign the tests to each target key
        # Use list() to create a copy of the list since Python 2 doesn't have list.copy()
        change['updated_tests'][target_key] = list(nfs_tests)

    # Remove the original entry
    del change['updated_tests']['parallel-scale-nfs']

# Add affected files information
change['affected_files']  = affected_files(patch)

# Check if patch only changes paths that don't require testing
# Paths that don't require testing: Documentation/*, LICENSES/*, lustre/ChangeLog, contrib/*
def only_non_testable_paths(affected):
    """
    Check if all affected files match paths that don't require testing.

    Args:
        affected (dict): Dictionary with 'm', 'a', 'd' keys containing file lists

    Returns:
        bool: True if all files are in non-testable paths, False otherwise
    """
    non_testable_prefixes = [ 'Documentation/', 'LICENSES/', 'contrib/' ]
    non_testable_exact = [ 'lustre/ChangeLog' ]

    # Collect all affected files from all categories
    all_files = affected.get('m', [ ]) + affected.get('a', [ ]) + affected.get('d', [ ])

    # If no files were changed, we can't skip testing
    if not all_files:
        return False

    # Check each file against the non-testable patterns
    for filepath in all_files:
        is_non_testable = False

        # Check against exact matches
        if filepath in non_testable_exact:
            is_non_testable = True

        # Check against prefix matches
        for prefix in non_testable_prefixes:
            if filepath.startswith(prefix):
                is_non_testable = True
                break

        # If any file is testable, return False
        if not is_non_testable:
            return False

    # All files matched non-testable patterns
    return True

if only_non_testable_paths(change['affected_files']):
    change['SkipTesting'] = True
    if 'updated_tests' in change:
        del change['updated_tests']

print(json.dumps(change))

