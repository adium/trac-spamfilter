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

from StringIO import StringIO
import unittest

from trac.test import EnvironmentStub, Mock
from tracspamfilter.filters.session import SessionFilterStrategy


class SessionFilterStrategyTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(enable=[SessionFilterStrategy])
        self.strategy = SessionFilterStrategy(self.env)

    def test_new_session(self):
        data = {}
        session = Mock(last_visit=42, get=data.get)
        retval = self.strategy.test(Mock(session=session), None, None, "127.0.0.1")
        self.assertEqual((3, 'Existing session found'), retval)

    def test_session_name_set(self):
        data = {'name': 'joe'}
        session = Mock(last_visit=42, get=data.get)
        retval = self.strategy.test(Mock(session=session), None, None, "127.0.0.1")
        self.assertEqual((6, 'Existing session found'), retval)

    def test_session_email_set(self):
        data = {'email': 'joe@example.org'}
        session = Mock(last_visit=42, get=data.get)
        retval = self.strategy.test(Mock(session=session), None, None, "127.0.0.1")
        self.assertEqual((6, 'Existing session found'), retval)

    def test_session_email_set_but_invalid(self):
        data = {'email': 'joey'}
        session = Mock(last_visit=42, get=data.get)
        retval = self.strategy.test(Mock(session=session), None, None, "127.0.0.1")
        self.assertEqual((3, 'Existing session found'), retval)

    def test_session_name_and_email_set(self):
        data = {'name': 'joe', 'email': 'joe@example.org'}
        session = Mock(last_visit=42, get=data.get)
        retval = self.strategy.test(Mock(session=session), None, None, "127.0.0.1")
        self.assertEqual((9, 'Existing session found'), retval)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SessionFilterStrategyTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
