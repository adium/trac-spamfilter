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
from tracspamfilter.filters import regex
from tracspamfilter.filters.regex import RegexFilterStrategy


class DummyWikiPage(object):

    def __init__(self):
        self.text = ''

    def __call__(self, env, name):
        self.env = env
        self.name = name
        self.exists = True
        return self


class RegexFilterStrategyTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(enable=[RegexFilterStrategy])
        self.page = regex.WikiPage = DummyWikiPage()
        self.strategy = RegexFilterStrategy(self.env)

    def test_no_patterns(self):
        retval = self.strategy.test(Mock(), 'anonymous', 'foobar', '127.0.0.1')
        self.assertEqual(None, retval)

    def test_one_matching_pattern(self):
        self.page.text = """{{{
foobar
}}}"""
        self.strategy.wiki_page_changed(self.page)
        retval = self.strategy.test(Mock(), 'anonymous', 'foobar', '127.0.0.1')
        self.assertEqual((-5, 'Content contained these blacklisted patterns: %s', '\'foobar\''), retval)

    def test_multiple_matching_pattern(self):
        self.page.text = """{{{
foobar
^foo
bar$
}}}"""
        self.strategy.wiki_page_changed(self.page)
        retval = self.strategy.test(Mock(), 'anonymous', '\nfoobar', '127.0.0.1')
        self.assertEqual((-10, 'Content contained these blacklisted patterns: %s', '\'foobar\', \'bar$\''),
                         retval)


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(RegexFilterStrategyTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
