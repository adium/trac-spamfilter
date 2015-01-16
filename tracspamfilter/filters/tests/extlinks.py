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

import unittest

from trac.test import EnvironmentStub, Mock
from tracspamfilter.filters.extlinks import ExternalLinksFilterStrategy


class ExternalLinksFilterStrategyTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(enable=[ExternalLinksFilterStrategy])
        self.strategy = ExternalLinksFilterStrategy(self.env)

    def test_no_links(self):
        req = Mock(get_header=lambda x: {'Host': 'example.org'}.get(x))
        retval = self.strategy.test(req, 'John Doe', 'Foo bar', '127.0.0.1')
        self.assertEqual(None, retval)

    def test_few_ext_links(self):
        req = Mock(get_header=lambda x: {'Host': 'example.org'}.get(x))
        retval = self.strategy.test(req, 'John Doe', """
        <a href="http://spammers-site.com/fakehandbags">fakehandbags</a>
        <a href="http://spammers-site.com/fakewatches">fakewatches</a>
        """, '127.0.0.1')
        self.assertEqual(None, retval)

    def test_many_ext_links(self):
        req = Mock(get_header=lambda x: {'Host': 'example.org'}.get(x))
        retval = self.strategy.test(req, 'John Doe', """
        <a href="http://spammers-site.com/fakehandbags">fakehandbags</a>
        <a href="http://spammers-site.com/fakewatches">fakewatches</a>
        <a href="http://spammers-site.com/fakehandbags">fakehandbags</a>
        <a href="http://spammers-site.com/fakewatches">fakewatches</a>
        <a href="http://spammers-site.com/fakehandbags">fakehandbags</a>
        <a href="http://spammers-site.com/fakewatches">fakewatches</a>
        """, '127.0.0.1')
        self.assertEqual(
            (-3, 'Maximum number of external links per post exceeded'),
            retval
        )

    def test_many_ext_links_same_site(self):
        req = Mock(get_header=lambda x: {'Host': 'example.org'}.get(x))
        retval = self.strategy.test(req, 'John Doe', """
        <a href="http://example.org/page1">foo</a>
        <a href="http://example.org/page2">bar</a>
        <a href="http://example.org/page1">foo</a>
        <a href="http://example.org/page2">bar</a>
        <a href="http://example.org/page1">foo</a>
        <a href="http://example.org/page2">bar</a>
        """, '127.0.0.1')
        self.assertEqual(None, retval)

    def test_many_ext_links_raw(self):
        req = Mock(get_header=lambda x: {'Host': 'example.org'}.get(x))
        retval = self.strategy.test(req, 'John Doe', """
        http://spammers-site.com/fakehandbags
        http://spammers-site.com/fakewatches
        http://spammers-site.com/fakehandbags
        http://spammers-site.com/fakewatches
        http://spammers-site.com/fakehandbags
        http://spammers-site.com/fakewatches
        """, '127.0.0.1')
        self.assertEqual(
            (-3, 'Maximum number of external links per post exceeded'),
            retval
        )

    def test_many_ext_links_bbcode(self):
        req = Mock(get_header=lambda x: {'Host': 'example.org'}.get(x))
        retval = self.strategy.test(req, 'John Doe', """
        [url=http://spammers-site.com/fakehandbags]fakehandbags[/url]
        [url=http://spammers-site.com/fakewatches]fakewatches[/url]
        [url=http://spammers-site.com/fakehandbags]fakehandbags[/url]
        [url=http://spammers-site.com/fakewatches]fakewatches[/url]
        [url=http://spammers-site.com/fakehandbags]fakehandbags[/url]
        [url=http://spammers-site.com/fakewatches]fakewatches[/url]
        """, '127.0.0.1')
        self.assertEqual(
            (-3, 'Maximum number of external links per post exceeded'),
            retval
        )

def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ExternalLinksFilterStrategyTestCase,
                                     'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
