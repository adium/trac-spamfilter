# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2012 Edgewall Software
# Copyright (C) 2005-2006 Matthew Good <trac@matt-good.net>
# Copyright (C) 2006 Christopher Lenz <cmlenz@gmx.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.
#
# Author: Matthew Good <trac@matt-good.net>
#         Christopher Lenz <cmlenz@gmx.de>

from difflib import SequenceMatcher
import inspect
from StringIO import StringIO
import textwrap
import time

from pkg_resources import resource_filename

from trac.config import BoolOption, ExtensionOption, IntOption, Option, ConfigSection
from trac.core import *
from trac.db import DatabaseManager
from trac.env import IEnvironmentSetupParticipant
from trac.perm import IPermissionRequestor
from trac.util.text import shorten_line, to_unicode
from trac.web import Request
from tracspamfilter.api import (
    IFilterStrategy, IRejectHandler, RejectContent, 
    add_domain, _, N_, gettext, tag_, get_strategy_name
)
from tracspamfilter.model import LogEntry, schema, schema_version, Statistics
from tracspamfilter.filters.trapfield import TrapFieldFilterStrategy
from genshi.builder import tag

__all__ = ['FilterSystem']

class FilterSystem(Component):
    """The central component for spam filtering. Must be enabled always to allow
    filtering of spam.
    """

    strategies = ExtensionPoint(IFilterStrategy)

    implements(IEnvironmentSetupParticipant, IPermissionRequestor,
               IRejectHandler)

    min_karma = IntOption('spam-filter', 'min_karma', '0',
        """The minimum score required for a submission to be allowed.""",
        doc_domain='tracspamfilter')

    authenticated_karma = IntOption('spam-filter', 'authenticated_karma', '20', 
        """The karma given to authenticated users, in case
        `trust_authenticated` is false.""", doc_domain='tracspamfilter')
                                                                      
    logging_enabled = BoolOption('spam-filter', 'logging_enabled', 'true',
        """Whether all content submissions and spam filtering activity should
        be logged to the database.""", doc_domain='tracspamfilter')

    purge_age = IntOption('spam-filter', 'purge_age', '7',
        """The number of days after which log entries should be purged.""",
        doc_domain='tracspamfilter')

    use_external = BoolOption('spam-filter', 'use_external', 'true',
        """Allow usage of external services.""", doc_domain='tracspamfilter')

    skip_external = IntOption('spam-filter', 'skip_external', '20',
        """Skip external calls when this negative karma is already reached
        by internal tests.""", doc_domain='tracspamfilter')

    skip_externalham = IntOption('spam-filter', 'skip_externalham', '30',
        """Skip external calls when this positive karma is already reached
        by internal tests.""", doc_domain='tracspamfilter')

    stop_external = IntOption('spam-filter', 'stop_external', '50',
        """Stop external calls when this negative karma is reached.""",
        doc_domain='tracspamfilter')

    stop_externalham = IntOption('spam-filter', 'stop_externalham', '50',
        """Stop external calls when this positive karma is reached.""",
        doc_domain='tracspamfilter')

    train_external = BoolOption('spam-filter', 'train_external', 'true',
        """Allow training of external services.""", doc_domain='tracspamfilter')

    trust_authenticated = BoolOption('spam-filter', 'trust_authenticated',
                                     'false',
        """Whether content submissions by authenticated users should be trusted
        without checking for potential spam or other abuse.""",
        doc_domain='tracspamfilter')

    attachment_karma = IntOption('spam-filter', 'attachment_karma', '0', 
        """The karma given to attachments.""", doc_domain='tracspamfilter')

    reject_handler = ExtensionOption('spam-filter', 'reject_handler',
                                     IRejectHandler, 'FilterSystem',
        """The handler used to reject content.""", doc_domain='tracspamfilter')

    isforwarded = BoolOption('spam-filter', 'is_forwarded', 'false',
        """Interpret X-Forwarded-For header for IP checks.""",
        doc_domain='tracspamfilter')

    spam_section = ConfigSection('spam-filter', 
        """This section is used to handle all configurations used by
        spam filter plugin.""", doc_domain='tracspamfilter')

    def __init__(self):
        """Set up translation domain"""
        locale_dir = resource_filename(__name__, 'locale')
        add_domain(self.env.path, locale_dir)

    # IRejectHandler methods

    def reject_content(self, req, message):
        raise RejectContent(message)

    # Public methods

    def test(self, req, author, changes):
        """Test a submission against the registered filter strategies.
        
        @param req: the request object
        @param author: the name of the logged in user, or 'anonymous' if the
            user is not logged in
        @param changes: a list of `(old_content, new_content)` tuples for every
            modified "field", where `old_content` may contain the previous
            version of that field (if available), and `new_content` contains
            the newly submitted content
        """

        start = time.time()
        ip = req.remote_addr
        if self.isforwarded:
            x_forwarded = req.get_header('X-Forwarded-For')
            if x_forwarded and x_forwarded != '':
                ip = x_forwarded.split(',',1)[0]

        if author.find("@") < 1:
            trap = TrapFieldFilterStrategy(self.env).get_trap(req)
            if trap:
                if trap.find("@") > 0:
                    author += " <%s>" % trap
                else:
                    self.log.debug("Append trap field to changes")
                    changes.append((None, trap))

        score = 0
        if self.trust_authenticated:
            # Authenticated users are trusted
            if req.authname and req.authname != 'anonymous':
                return

        reasons = []
        outreasons = []
        results = []
        if req.authname and req.authname != 'anonymous':
            reasons.append(("AuthenticatedUserScore", str(self.authenticated_karma),
                            N_("User is authenticated")))
            score += self.authenticated_karma

        if req.args.get('attachment') != None and self.attachment_karma != 0:
            reasons.append(("AttachmentScore", str(self.attachment_karma),
                            N_("Attachment weighting")))
            score += self.attachment_karma

        if not author:
            author = 'anonymous'
        self.log.debug("Spam testing for %s" % req.path_info)
        content = self._combine_changes(changes)
        abbrev = shorten_line(content)
        self.log.debug('Testing content %r submitted by "%s"', abbrev, author)
        externals = []

        for strategy in self.strategies:
            tim = time.time()
            try:
                if not strategy.is_external():
                    retval = strategy.test(req, author, content, ip)
                    tim = time.time()-tim
                    if tim > 3:
                        self.log.warn('Test %s took %d seconds to complete.' % (strategy, tim))
                    if retval:
                        points = retval[0]
                        if len(retval) > 2:
                            reason = retval[1] % retval[2:]
                        else:
                            reason = retval[1]
                        if points < 0:
                            if len(retval) > 2:
                                outreasons.append(gettext(retval[1]) % retval[2:])
                            else:
                                outreasons.append(gettext(retval[1]))
                                                                                                                
                        self.log.debug('Filter strategy %r gave submission %d '
                                       'karma points (reason: %r)', strategy,
                                       points, reason)
                        score += points
                        if reason:
                            name = get_strategy_name(strategy)
                            reasons.append((name, str(points)) + retval[1:])
                            results.append((strategy, points, tim))
                    else:
                        self._record_action('test','empty', '', strategy, tim)
                elif self.use_external:
                    externals.append(strategy)
            except Exception, e:
                self._record_action('test', 'error', '', strategy, time.time()-tim)
                self.log.exception('Filter strategy %s raised exception: %s', strategy, e)

        extint = "testint"
        if score > -self.skip_external and score < self.skip_externalham:
            externals = Statistics(self.env).sortbyperformance(externals)
            for strategy in externals:
                tim = time.time()
                try:
                    if score > -self.stop_external and score < self.stop_externalham:
                        extint = "testext"
                        retval = strategy.test(req, author, content, ip)
                        tim = time.time()-tim
                        if tim > 3:
                            self.log.warn('Test %s took %d seconds to complete.' % (strategy, tim))
                        if retval:
                            points = retval[0]
                            if len(retval) > 2:
                                reason = retval[1] % retval[2:]
                            else:
                                reason = retval[1]
                            if points < 0:
                                if len(retval) > 2:
                                    outreasons.append(gettext(retval[1]) % retval[2:])
                                else:
                                    outreasons.append(gettext(retval[1]))
                                                                                                                
                            self.log.debug('Filter strategy %r gave submission %d '
                                           'karma points (reason: %r)', strategy,
                                           points, reason)
                            score += points
                            if reason:
                                name = get_strategy_name(strategy)
                                reasons.append((name,str(points)) + retval[1:])
                                results.append((strategy, points, tim))
                        else:
                            self._record_action('test','empty', '', strategy, tim)
                except Exception, e:
                    self._record_action('test','error', '', strategy, time.time()-tim)
                    self.log.exception('Filter strategy %s raised exception: %s', strategy, e)

        reasons = sorted(reasons, key=lambda r: r[0])

        if score < self.min_karma:
            type = "spam"
            self._record_action(extint, 'spam', '', '', time.time()-start)
        else:
            type = "ham"
            self._record_action(extint, 'ham', '', '', time.time()-start)
        for strategy,points,tim in results:
            if (points < 0 and score < self.min_karma) or (points > 0 and score >= self.min_karma):
                status = "ok"
            else:
                status = "error"
            self._record_action("test", type, status, strategy, tim)

        if self.logging_enabled:
            headers = '\n'.join(['%s: %s' % (k[5:].replace('_', '-').title(), v)
                                 for k, v in req.environ.items()
                                 if k.startswith('HTTP_')])
            LogEntry(self.env, time.time(), req.path_info, author,
                     req.authname and req.authname != 'anonymous',
                     ip, headers, content, score < self.min_karma,
                     score, reasons, [req.path_info, req.args]).insert()
            LogEntry.purge(self.env, self.purge_age)

        if score < self.min_karma:
            self.log.debug('Rejecting submission %r by "%s" (%r) because it '
                           'earned only %d karma points (%d are required).',
                           abbrev, author, req.remote_addr, score, self.min_karma)
            rejects = []
            outreasons.sort()
            for r in outreasons:
                rejects.append(tag.li(r))
            msg = tag.ul(rejects)

            self.reject_handler.reject_content(
                req, tag.div(
                    tag_('Submission rejected as potential spam %(message)s',
                         message=msg),
                    class_='message'))

    def train(self, req, ids, spam=True, delete=False):
        environ = {}
        for name, value in req.environ.items():
            if not name.startswith('HTTP_'):
                environ[name] = value

        if not isinstance(ids, list):
            ids = [ids]
        for log_id in ids:
            start = time.time()
            entry = LogEntry.fetch(self.env, log_id)
            if entry:
                extint = "trainint"
                self.log.debug('Marking as %s: %r submitted by "%s"',
                               spam and 'spam' or 'ham',
                               shorten_line(entry.content),
                               entry.author)
                fakeenv = environ.copy()
                for header in entry.headers.splitlines():
                    name, value = header.split(':', 1)
                    if name == 'Cookie': # breaks SimpleCookie somehow
                        continue
                    cgi_name = 'HTTP_%s' % name.strip().replace('-', '_').upper()
                    fakeenv[cgi_name] = value.strip()
                fakeenv['REQUEST_METHOD'] = 'POST'
                fakeenv['PATH_INFO'] = entry.path
                fakeenv['wsgi.input'] = StringIO('')
                fakeenv['REMOTE_ADDR'] = entry.ipnr
                if entry.authenticated:
                    fakeenv['REMOTE_USER'] = entry.author

                type = "spam" if spam else "ham"
                for strategy in self.strategies:
                    status = "trainskip"
                    if (self.use_external and self.train_external) or not strategy.is_external():
                        tim = time.time()
                        extint = "trainext"
                        res = strategy.train(Request(fakeenv, None),
                                   entry.author or 'anonymous',
                                   entry.content, entry.ipnr, spam=spam)
                        tim = time.time()-tim
                        if tim > 3:
                            self.log.warn('Training %s took %d seconds to complete.' % (strategy, tim))
                        if res == -1:
                            status = "trainerror"
                        elif res == -2:
                            status = "traincond"
                        elif res > 0:
                            status = "train"
                    count = entry.findreasonvalue(get_strategy_name(strategy))
                    if count:
                        spamstatus = count < 0
                        self._record_action(status, type, ("ok" if spamstatus == spam else "error"), strategy, tim)
                    else:
                        self._record_action(status, type, '', strategy, tim)
                
                self._record_action(extint, type, ("ok" if entry.rejected == spam else "error"), '', time.time()-start)
                entry.update(rejected=spam)
                if delete:
                    self.delete(req, log_id, True)

    def delete(self, req, ids, stats):
        if not isinstance(ids, list):
            ids = [ids]
        if stats:
            for log_id in ids:
                entry = LogEntry.fetch(self.env, log_id)
                if entry:
                    type = "spam" if entry.rejected else "ham"
                    status = "delete"
                    for strategy in self.strategies:
                        count = entry.findreasonvalue(get_strategy_name(strategy))
                        if count:
                            spamstatus = count < 0
                            self._record_action(status, type, ("ok" if spamstatus == entry.rejected else "error"), strategy, 0)
                        else:
                            self._record_action(status, type, '', strategy, 0)
                    self._record_action(status, type, '', '', 0)
                    LogEntry.delete(self.env, log_id)
        else:
            LogEntry.delete(self.env,ids)

    def deleteobvious(self, req):
        ids = LogEntry.getobvious(self.env)
        if ids:
            self.delete(req, ids, True)

    # IEnvironmentSetupParticipant

    def environment_created(self):
        with self.env.db_transaction as db:
            self.upgrade_environment(db)

    def environment_needs_upgrade(self, db):
        try:
            row = db("SELECT value FROM system "
                     "WHERE name='spamfilter_version'")
            if not row or int(row[0][0]) < schema_version:
                return True
        except:
            return True

    def upgrade_environment(self, db):
        try:
            row = db("SELECT value FROM system "
               "WHERE name='spamfilter_version'")
            current_version = row and int(row[0][0]) or 0
        except:
            current_version = 0

        from tracspamfilter import upgrades
        for version in range(current_version + 1, schema_version + 1):
            for function in upgrades.version_map.get(version):
                self.log.info(textwrap.fill(inspect.getdoc(function)))
                function(self.env, db)
                self.log.info('Done.')

        if current_version == 0:
            db("INSERT INTO system VALUES ('spamfilter_version',%s)",
               (schema_version,))
            self.log.info('Created SpamFilter tables')
        else:
            db("UPDATE system SET value=%s WHERE "
               "name='spamfilter_version'", (schema_version,))
            self.log.info('Upgraded SpamFilter tables from version %d to %d',
                          current_version, schema_version)

    # IPermissionRequestor

    def get_permission_actions(self):
        return ['SPAM_CONFIG', 'SPAM_MONITOR', 'SPAM_TRAIN', 'SPAM_USER', 'SPAM_REPORT',
                'SPAM_CHECKREPORTS',
                ('SPAM_ADMIN', ['SPAM_CONFIG', 'SPAM_MONITOR', 'SPAM_TRAIN',
                'SPAM_USER', 'SPAM_REPORT', 'SPAM_CHECKREPORTS'])]

    # Internal methods

    def _combine_changes(self, changes, sep='\n\n'):
        fields = []
        for old_content, new_content in changes:
            new_content = to_unicode(new_content)
            if old_content:
                old_content = to_unicode(old_content)
                new_content = self._get_added_lines(old_content, new_content)
            fields.append(new_content)
        return sep.join(fields)

    def _get_added_lines(self, old_content, new_content):
        buf = []
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()
        matcher = SequenceMatcher(None, old_lines, new_lines)
        for group in matcher.get_grouped_opcodes(0):
            for tag, i1, i2, j1, j2 in group:
                if tag in ('insert', 'replace'):
                    buf.append('\n'.join(new_lines[j1:j2]))

        return '\n'.join(buf)

    def _record_action(self, action, data, status, strategy, delay):
        stats = Statistics(self.env)
        if strategy:
            name = get_strategy_name(strategy)
            stats.insert_or_update(name, action, data, status, delay, 1 if strategy.is_external() else 0)
        else:
            stats.insert_or_update('', action, data, status, delay, None)
