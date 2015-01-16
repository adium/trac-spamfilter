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

from trac.db.sqlite_backend import _to_sql
from trac.test import EnvironmentStub, Mock
from tracspamfilter.model import schema


class BayesianFilterStrategyTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(enable=[BayesianFilterStrategy])
        self.env.config.set('spam-filter', 'bayes_karma', '10')
        with self.env.db_transaction as db:
            cursor = db.cursor()
            for table in schema:
                for stmt in _to_sql(table):
                    cursor.execute(stmt)

        self.strategy = BayesianFilterStrategy(self.env)

    def test_karma_calculation_unsure(self):
        bayes.Hammie = lambda x: Mock(score=lambda x: .5,
                                      bayes=Mock(nham=1000, nspam=1000))

        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1')
        self.assertEquals(None, self.strategy.test(req, 'John Doe', 'Spam', '127.0.0.1'))

    def test_karma_calculation_negative(self):
        bayes.Hammie = lambda x: Mock(score=lambda x: .75,
                                      bayes=Mock(nham=1000, nspam=1000))

        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1')
        points, reasons = self.strategy.test(req, 'John Doe', 'Spam', '127.0.0.1')
        self.assertEquals(-5, points)

    def test_karma_calculation_positive(self):
        bayes.Hammie = lambda x: Mock(score=lambda x: .25,
                                      bayes=Mock(nham=1000, nspam=1000))

        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1')
        points, reasons = self.strategy.test(req, 'John Doe', 'Spam', '127.0.0.1')
        self.assertEquals(5, points)

    def test_classifier_untrained(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1')
        self.assertEqual(None, self.strategy.test(req, 'John Doe', 'Hammie', '127.0.0.1'))

    def test_classifier_basics(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1')
        self.env.config.set('spam-filter', 'bayes_min_training', '1')
        self.strategy.train(req, 'John Doe', 'Spam spam spammie', '127.0.0.1', True)
        self.strategy.train(req, 'John Doe', 'Ham ham hammie', '127.0.0.1', False)

        points, reasons = self.strategy.test(req, 'John Doe', 'Hammie', '127.0.0.1')
        assert points > 0, 'Expected positive karma'
        points, reasons = self.strategy.test(req, 'John Doe', 'Spam', '127.0.0.1')
        assert points < 0, 'Expected negative karma'


try:
    from tracspamfilter.filters import bayes
    from tracspamfilter.filters.bayes import BayesianFilterStrategy
except ImportError:
    # Skip tests if SpamBayes isn't installed
    class BayesianFilterStrategyTestCase(object): pass

def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(BayesianFilterStrategyTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
