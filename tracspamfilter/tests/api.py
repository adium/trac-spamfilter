# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

import time
import unittest

from trac.core import *
from trac.db.sqlite_backend import _to_sql
from trac.test import EnvironmentStub, Mock
from tracspamfilter.api import IFilterStrategy, RejectContent
from tracspamfilter.filtersystem import FilterSystem
from tracspamfilter.model import LogEntry, schema


class DummyStrategy(Component):
    implements(IFilterStrategy)

    def __init__(self):
        self.test_called = self.train_called = False
        self.req = self.author = self.content = None
        self.karma = 0
        self.message = None
        self.spam = None

    def configure(self, karma, message="Dummy"):
        self.karma = karma
        self.message = message

    def test(self, req, author, content, ip):
        self.test_called = True
        self.req = req
        self.author = author
        self.content = content
        self.ip = ip
        return self.karma, self.message

    def train(self, req, author, content, ip, spam=True):
        self.train_called = True
        self.req = req
        self.author = author
        self.content = content
        self.ip = ip
        self.spam = spam

    def is_external(self):
        return False

class FilterSystemTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(enable=[FilterSystem, DummyStrategy])

        with self.env.db_transaction as db:
            cursor = db.cursor()
            for table in schema:
                for stmt in _to_sql(table):
                    cursor.execute(stmt)

    def test_trust_authenticated(self):
        req = Mock(environ={}, path_info='/foo', authname='john',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).test(req, '', [], '127.0.0.1')
        self.assertEqual(False, DummyStrategy(self.env).test_called)

    def test_dont_trust_authenticated(self):
        self.env.config['spam-filter'].set('trust_authenticated', 'false')
        req = Mock(environ={}, path_info='/foo', authname='john',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).test(req, '', [], '127.0.0.1')
        self.assertEqual(True, DummyStrategy(self.env).test_called)

    def test_without_oldcontent(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).test(req, 'John Doe', [(None, 'Test')],
                                   '127.0.0.1')
        self.assertEqual('Test', DummyStrategy(self.env).content)

    def test_with_oldcontent(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).test(req, 'John Doe', [('Test', 'Test 1 2 3')],
                                    '127.0.0.1')
        self.assertEqual('Test 1 2 3', DummyStrategy(self.env).content)

    def test_with_oldcontent_multiline(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).test(req, 'John Doe', [('Text\n1 2 3\n7 8 9',
                                                       'Test\n1 2 3\n4 5 6')],
                                                       '127.0.0.1')
        self.assertEqual('Test\n4 5 6', DummyStrategy(self.env).content)

    def test_bad_karma(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1', args={})
        DummyStrategy(self.env).configure(-5, 'Blacklisted')
        try:
            FilterSystem(self.env).test(req, 'John Doe', [(None, 'Test')])
            self.fail('Expected RejectContent exception')
        except RejectContent, e:
            self.assertEqual('<div class="message">'
                             'Submission rejected as potential spam '
                             '<ul><li>Blacklisted</li></ul></div>', str(e))

    def test_good_karma(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        DummyStrategy(self.env).configure(5)
        FilterSystem(self.env).test(req, 'John Doe', [(None, 'Test')])

    def test_log_reject(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        DummyStrategy(self.env).configure(-5, 'Blacklisted')
        try:
            FilterSystem(self.env).test(req, 'John Doe', [(None, 'Test')])
            self.fail('Expected RejectContent exception')
        except RejectContent, e:
            pass

        log = list(LogEntry.select(self.env))
        self.assertEqual(1, len(log))
        entry = log[0]
        self.assertEqual('/foo', entry.path)
        self.assertEqual('John Doe', entry.author)
        self.assertEqual(False, entry.authenticated)
        self.assertEqual('127.0.0.1', entry.ipnr)
        self.assertEqual('Test', entry.content)
        self.assertEqual(True, entry.rejected)
        self.assertEqual(-5, entry.karma)
        self.assertEqual(['DummyStrategy (-5): Blacklisted'], entry.reasons)

    def test_log_accept(self):
        req = Mock(environ={}, path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        DummyStrategy(self.env).configure(5)
        FilterSystem(self.env).test(req, 'John Doe', [(None, 'Test')])

        log = list(LogEntry.select(self.env))
        self.assertEqual(1, len(log))
        entry = log[0]
        self.assertEqual('/foo', entry.path)
        self.assertEqual('John Doe', entry.author)
        self.assertEqual(False, entry.authenticated)
        self.assertEqual('127.0.0.1', entry.ipnr)
        self.assertEqual('Test', entry.content)
        self.assertEqual(False, entry.rejected)
        self.assertEqual(5, entry.karma)
        self.assertEqual([], entry.reasons)

    def test_train_spam(self):
        entry = LogEntry(self.env, time.time(), '/foo', 'john', False,
                         '127.0.0.1', '', 'Test', False, 5, [])
        entry.insert()

        req = Mock(environ={'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
                            'wsgi.url_scheme': 'http'},
                   path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).train(req, entry.id, spam=True)

        strategy = DummyStrategy(self.env)
        self.assertEqual(True, strategy.train_called)
        self.assertEqual('john', strategy.author)
        self.assertEqual('Test', strategy.content)
        self.assertEqual(True, strategy.spam)

        log = list(LogEntry.select(self.env))
        self.assertEqual(1, len(log))
        entry = log[0]
        self.assertEqual(True, entry.rejected)

    def test_train_ham(self):
        entry = LogEntry(self.env, time.time(), '/foo', 'john', False,
                         '127.0.0.1', '', 'Test', True, -5, [])
        entry.insert()

        req = Mock(environ={'SERVER_NAME': 'localhost', 'SERVER_PORT': '80',
                            'wsgi.url_scheme': 'http'},
                   path_info='/foo', authname='anonymous',
                   remote_addr='127.0.0.1')
        FilterSystem(self.env).train(req, entry.id, spam=False)

        strategy = DummyStrategy(self.env)
        self.assertEqual(True, strategy.train_called)
        self.assertEqual('john', strategy.author)
        self.assertEqual('Test', strategy.content)
        self.assertEqual(False, strategy.spam)

        log = list(LogEntry.select(self.env))
        self.assertEqual(1, len(log))
        entry = log[0]
        self.assertEqual(False, entry.rejected)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(FilterSystemTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
