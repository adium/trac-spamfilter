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

from datetime import datetime, timedelta
import time
import unittest

from trac.core import *
from trac.db.sqlite_backend import _to_sql
from trac.test import EnvironmentStub, Mock
from tracspamfilter.model import LogEntry, schema


class LogEntryTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub()

        with self.env.db_transaction as db:
            cursor = db.cursor()
            for table in schema:
                for stmt in _to_sql(table):
                    cursor.execute(stmt)

    def test_purge(self):
        now = datetime.now()
        oneweekago = time.mktime((now - timedelta(weeks=1)).timetuple())
        onedayago = time.mktime((now - timedelta(days=1)).timetuple())
        req = None

        LogEntry(self.env, oneweekago, '/foo', 'john', False, '127.0.0.1',
                 '', 'Test', False, 5, [], req).insert()
        LogEntry(self.env, onedayago, '/foo', 'anonymous', False, '127.0.0.1',
                 '', 'Test', True, -3, [], req).insert()

        LogEntry.purge(self.env, days=4)

        log = list(LogEntry.select(self.env))
        self.assertEqual(1, len(log))
        entry = log[0]
        self.assertEqual('anonymous', entry.author)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(LogEntryTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
