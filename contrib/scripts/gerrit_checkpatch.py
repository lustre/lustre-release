#!/usr/bin/env python
#
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
# http://www.gnu.org/licenses/gpl-2.0.html
#
# GPL HEADER END
#
# Copyright (c) 2014, Intel Corporation.
#
# Author: John L. Hammond <john.hammond@intel.com>
#
"""
Gerrit Checkpatch Reviewer Daemon
~~~~~~ ~~~~~~~~~~ ~~~~~~~~ ~~~~~~

* Watch for new change revisions in a gerrit instance.
* Pass new revisions through checkpatch script.
* POST reviews back to gerrit based on checkpatch output.
"""

import base64
import fnmatch
import logging
import json
import os
import requests
import subprocess
import time
import urllib

def _getenv_list(key, default=None, sep=':'):
    """
    'PATH' => ['/bin', '/usr/bin', ...]
    """
    value = os.getenv(key)
    if value is None:
        return default
    else:
        return value.split(sep)

GERRIT_HOST = os.getenv('GERRIT_HOST', 'review.whamcloud.com')
GERRIT_PROJECT = os.getenv('GERRIT_PROJECT', 'fs/lustre-release')
GERRIT_BRANCH = os.getenv('GERRIT_BRANCH', 'master')
GERRIT_AUTH_PATH = os.getenv('GERRIT_AUTH_PATH', 'GERRIT_AUTH')
GERRIT_CHANGE_NUMBER = os.getenv('GERRIT_CHANGE_NUMBER', None)

# GERRIT_AUTH should contain a single JSON dictionary of the form:
# {
#     "review.example.com": {
#         "gerrit/http": {
#             "username": "example-checkpatch",
#             "password": "1234"
#         }
#     }
#     ...
# }

CHECKPATCH_PATHS = _getenv_list('CHECKPATCH_PATHS', ['checkpatch.pl'])
CHECKPATCH_ARGS = os.getenv('CHECKPATCH_ARGS','--show-types -').split(' ')
CHECKPATCH_IGNORED_FILES = _getenv_list('CHECKPATCH_IGNORED_FILES', [
        'lustre/contrib/wireshark/packet-lustre.c',
        'lustre/ptlrpc/wiretest.c',
        'lustre/utils/wiretest.c',
        '*.patch'])
CHECKPATCH_IGNORED_KINDS = _getenv_list('CHECKPATCH_IGNORED_KINDS', [
        'LASSERT',
        'LCONSOLE',
        'LEADING_SPACE'])
REVIEW_HISTORY_PATH = os.getenv('REVIEW_HISTORY_PATH', 'REVIEW_HISTORY')
STYLE_LINK = os.getenv('STYLE_LINK',
        'http://wiki.lustre.org/Lustre_Coding_Style_Guidelines')

USE_CODE_REVIEW_SCORE = False

def parse_checkpatch_output(out, path_line_comments, warning_count):
    """
    Parse string output out of CHECKPATCH into path_line_comments.
    Increment warning_count[0] for each warning.

    path_line_comments is { PATH: { LINE: [COMMENT, ...] }, ... }.
    """
    def add_comment(path, line, level, kind, message):
        """_"""
        logging.debug("add_comment %s %d %s %s '%s'",
                      path, line, level, kind, message)
        if kind in CHECKPATCH_IGNORED_KINDS:
            return

        for pattern in CHECKPATCH_IGNORED_FILES:
            if fnmatch.fnmatch(path, pattern):
                return

        path_comments = path_line_comments.setdefault(path, {})
        line_comments = path_comments.setdefault(line, [])
        line_comments.append('(style) %s\n' % message)
        warning_count[0] += 1

    level = None # 'ERROR', 'WARNING'
    kind = None # 'CODE_INDENT', 'LEADING_SPACE', ...
    message = None # 'code indent should use tabs where possible'

    for line in out.splitlines():
        # ERROR:CODE_INDENT: code indent should use tabs where possible
        # #404: FILE: lustre/liblustre/dir.c:103:
        # +        op_data.op_hash_offset = hash_x_index(page->index, 0);$
        line = line.strip()
        if not line:
            level, kind, message = None, None, None
        elif line[0] == '#':
            # '#404: FILE: lustre/liblustre/dir.c:103:'
            tokens = line.split(':', 5)
            if len(tokens) != 5 or tokens[1] != ' FILE':
                continue

            path = tokens[2].strip()
            line_number_str = tokens[3].strip()
            if not line_number_str.isdigit():
                continue

            line_number = int(line_number_str)

            if path and level and kind and message:
                add_comment(path, line_number, level, kind, message)
        elif line[0] == '+':
            continue
        else:
            # ERROR:CODE_INDENT: code indent should use tabs where possible
            try:
                level, kind, message = line.split(':', 2)
            except ValueError:
                level, kind, message = None, None, None

            if level != 'ERROR' and level != 'WARNING':
                level, kind, message = None, None, None


def review_input_and_score(path_line_comments, warning_count):
    """
    Convert { PATH: { LINE: [COMMENT, ...] }, ... }, [11] to a gerrit
    ReviewInput() and score
    """
    review_comments = {}

    for path, line_comments in path_line_comments.iteritems():
        path_comments = []
        for line, comment_list in line_comments.iteritems():
            message = '\n'.join(comment_list)
            path_comments.append({'line': line, 'message': message})
        review_comments[path] = path_comments

    if warning_count[0] > 0:
        score = -1
    else:
        score = +1

    if USE_CODE_REVIEW_SCORE:
        code_review_score = score
    else:
        code_review_score = 0

    if score < 0:
        return {
            'message': ('%d style warning(s).\nFor more details please see %s' %
                        (warning_count[0], STYLE_LINK)),
            'labels': {
                'Code-Review': code_review_score
                },
            'comments': review_comments,
            'notify': 'OWNER',
            }, score
    else:
        return {
            'message': 'Looks good to me.',
            'labels': {
                'Code-Review': code_review_score
                },
            'notify': 'NONE',
            }, score


def _now():
    """_"""
    return long(time.time())


class Reviewer(object):
    """
    * Poll gerrit instance for updates to changes matching project and branch.
    * Pipe new patches through checkpatch.
    * Convert checkpatch output to gerrit ReviewInput().
    * Post ReviewInput() to gerrit instance.
    * Track reviewed revisions in history_path.
    """
    def __init__(self, host, project, branch, username, password, history_path):
        self.host = host
        self.project = project
        self.branch = branch
        self.auth = requests.auth.HTTPDigestAuth(username, password)
        self.logger = logging.getLogger(__name__)
        self.history_path = history_path
        self.history_mode = 'rw'
        self.history = {}
        self.timestamp = 0L
        self.post_enabled = True
        self.post_interval = 10
        self.update_interval = 300
        self.request_timeout = 60

    def _debug(self, msg, *args):
        """_"""
        self.logger.debug(msg, *args)

    def _error(self, msg, *args):
        """_"""
        self.logger.error(msg, *args)

    def _url(self, path):
        """_"""
        return 'http://' + self.host + '/a' + path

    def _get(self, path):
        """
        GET path return Response.
        """
        url = self._url(path)
        try:
            res = requests.get(url, auth=self.auth,
                               timeout=self.request_timeout)
        except Exception as exc:
            self._error("cannot GET '%s': exception = %s", url, str(exc))
            return None

        if res.status_code != requests.codes.ok:
            self._error("cannot GET '%s': reason = %s, status_code = %d",
                       url, res.reason, res.status_code)
            return None

        return res

    def _post(self, path, obj):
        """
        POST json(obj) to path, return True on success.
        """
        url = self._url(path)
        data = json.dumps(obj)
        if not self.post_enabled:
            self._debug("_post: disabled: url = '%s', data = '%s'", url, data)
            return False

        try:
            res = requests.post(url, data=data,
                                headers={'Content-Type': 'application/json'},
                                auth=self.auth, timeout=self.request_timeout)
        except Exception as exc:
            self._error("cannot POST '%s': exception = %s", url, str(exc))
            return False

        if res.status_code != requests.codes.ok:
            self._error("cannot POST '%s': reason = %s, status_code = %d",
                       url, res.reason, res.status_code)
            return False

        return True

    def load_history(self):
        """
        Load review history from history_path containing lines of the form:
        EPOCH      FULL_CHANGE_ID                         REVISION    SCORE
        1394536722 fs%2Flustre-release~master~I5cc6c23... 00e2cc75... 1
        1394536721 -                                      -           0
        1394537033 fs%2Flustre-release~master~I10be8e9... 44f7b504... 1
        1394537032 -                                      -           0
        1394537344 -                                      -           0
        ...
        """
        if 'r' in self.history_mode:
            with open(self.history_path) as history_file:
                for line in history_file:
                    epoch, change_id, revision, score = line.split()
                    if change_id == '-':
                        self.timestamp = long(float(epoch))
                    else:
                        self.history[change_id + ' ' + revision] = score

        self._debug("load_history: history size = %d, timestamp = %d",
                    len(self.history), self.timestamp)

    def write_history(self, change_id, revision, score, epoch=-1):
        """
        Add review record to history dict and file.
        """
        if change_id != '-':
            self.history[change_id + ' ' + revision] = score

        if epoch <= 0:
            epoch = self.timestamp

        if 'w' in self.history_mode:
            with open(self.history_path, 'a') as history_file:
                print >> history_file, epoch, change_id, revision, score

    def in_history(self, change_id, revision):
        """
        Return True if change_id/revision was already reviewed.
        """
        return change_id + ' ' + revision in self.history

    def get_change_by_id(self, change_id):
        """
        GET one change by id.
        """
        path = ('/changes/' + urllib.quote(self.project, safe='') + '~' +
                urllib.quote(self.branch, safe='') + '~' + change_id +
                '?o=CURRENT_REVISION')
        res = self._get(path)
        if not res:
            return None

        # Gerrit uses " )]}'" to guard against XSSI.
        return json.loads(res.content[5:])

    def get_changes(self, query):
        """
        GET a list of ChangeInfo()s for all changes matching query.

        {'status':'open', '-age':'60m'} =>
          GET /changes/?q=project:...+status:open+-age:60m&o=CURRENT_REVISION =>
            [ChangeInfo()...]
        """
        query = dict(query)
        project = query.get('project', self.project)
        query['project'] = urllib.quote(project, safe='')
        branch = query.get('branch', self.branch)
        query['branch'] = urllib.quote(branch, safe='')
        path = ('/changes/?q=' +
                '+'.join(k + ':' + v for k, v in query.iteritems()) +
                '&o=CURRENT_REVISION')
        res = self._get(path)
        if not res:
            return []

        # Gerrit uses " )]}'" to guard against XSSI.
        return json.loads(res.content[5:])

    def decode_patch(self, content):
        """
        Decode gerrit's idea of base64.

        The base64 encoded patch returned by gerrit isn't always
        padded correctly according to b64decode. Don't know why. Work
        around this by appending more '=' characters or truncating the
        content until it decodes. But do try the unmodified content
        first.
        """
        for i in (0, 1, 2, 3, -1, -2, -3):
            if i >= 0:
                padded_content = content + (i * '=')
            else:
                padded_content = content[:i]

            try:
                return base64.b64decode(padded_content)
            except TypeError as exc:
                self._debug("decode_patch: len = %d, exception = %s",
                           len(padded_content), str(exc))
        else:
            return ''

    def get_patch(self, change, revision='current'):
        """
        GET and decode the (current) patch for change.
        """
        path = '/changes/' + change['id'] + '/revisions/' + revision + '/patch'
        self._debug("get_patch: path = '%s'", path)
        res = self._get(path)
        if not res:
            return ''

        self._debug("get_patch: len(content) = %d, content = '%s...'",
                   len(res.content), res.content[:20])

        return self.decode_patch(res.content)

    def post_review(self, change, revision, review_input):
        """
        POST review_input for the given revision of change.
        """
        path = '/changes/' + change['id'] + '/revisions/' + revision + '/review'
        self._debug("post_review: path = '%s'", path)
        return self._post(path, review_input)

    def check_patch(self, patch):
        """
        Run each script in CHECKPATCH_PATHS on patch, return a
        ReviewInput() and score.
        """
        path_line_comments = {}
        warning_count = [0]

        for path in CHECKPATCH_PATHS:
            pipe = subprocess.Popen([path] + CHECKPATCH_ARGS,
                                    stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
            out, err = pipe.communicate(patch)
            self._debug("check_patch: path = %s, out = '%s...', err = '%s...'",
                        path, out[:80], err[:80])
            parse_checkpatch_output(out, path_line_comments, warning_count)

        return review_input_and_score(path_line_comments, warning_count)

    def change_needs_review(self, change):
        """
        * Bail if the change isn't open (status is not 'NEW').
        * Bail if we've already reviewed the current revision.
        """
        status = change.get('status')
        if status != 'NEW':
            self._debug("change_needs_review: status = %s", status)
            return False

        current_revision = change.get('current_revision')
        self._debug("change_needs_review: current_revision = '%s'",
                    current_revision)
        if not current_revision:
            return False

        # Have we already checked this revision?
        if self.in_history(change['id'], current_revision):
            self._debug("change_needs_review: already reviewed")
            return False

        return True

    def review_change(self, change):
        """
        Review the current revision of change.
        * Pipe the patch through checkpatch(es).
        * Save results to review history.
        * POST review to gerrit.
        """
        self._debug("review_change: change = %s, subject = '%s'",
                    change['id'], change.get('subject', ''))

        current_revision = change.get('current_revision')
        self._debug("change_needs_review: current_revision = '%s'",
                    current_revision)
        if not current_revision:
            return

        patch = self.get_patch(change, current_revision)
        if not patch:
            self._debug("review_change: no patch")
            return

        review_input, score = self.check_patch(patch)
        self._debug("review_change: score = %d", score)
        self.write_history(change['id'], current_revision, score)
        self.post_review(change, current_revision, review_input)

    def update(self):
        """
        GET recently updated changes and review as needed.
        """
        new_timestamp = _now()
        age = new_timestamp - self.timestamp + 60 * 60 # 1h padding
        self._debug("update: age = %d", age)

        open_changes = self.get_changes({'status':'open',
                                         '-age':str(age) + 's'})
        self._debug("update: got %d open_changes", len(open_changes))

        for change in open_changes:
            if self.change_needs_review(change):
                self.review_change(change)
                # Don't POST more than every post_interval seconds.
                time.sleep(self.post_interval)

        self.timestamp = new_timestamp
        self.write_history('-', '-', 0)

    def update_single_change(self, change):

        self.load_history()

        open_changes = self.get_changes({'status':'open',
                                         'change':change})
        self._debug("update: got %d open_changes", len(open_changes))

        for change in open_changes:
            if self.change_needs_review(change):
                self.review_change(change)

    def run(self):
        """
        * Load review history.
        * Call update() every poll_interval seconds.
        """

        if self.timestamp <= 0:
            self.load_history()

        while True:
            self.update()
            time.sleep(self.update_interval)


def main():
    """_"""
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)

    with open(GERRIT_AUTH_PATH) as auth_file:
        auth = json.load(auth_file)
        username = auth[GERRIT_HOST]['gerrit/http']['username']
        password = auth[GERRIT_HOST]['gerrit/http']['password']

    reviewer = Reviewer(GERRIT_HOST, GERRIT_PROJECT, GERRIT_BRANCH,
                        username, password, REVIEW_HISTORY_PATH)

    if GERRIT_CHANGE_NUMBER:
        reviewer.update_single_change(GERRIT_CHANGE_NUMBER)
    else:
        reviewer.run()


if __name__ == "__main__":
    main()
