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
from tracspamfilter.filters import akismet
from tracspamfilter.filters.akismet import AkismetFilterStrategy


class DummyRequest(object):

    def __init__(self, url, params, headers):
        self.url = url
        self.params = params
        self.headers = headers

akismet.urllib2.Request = DummyRequest


class DummyURLOpener(object):

    def __init__(self):
        self.responses = []
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return StringIO(self.responses.pop(0))


class AkismetFilterStrategyTestCase(unittest.TestCase):

    def setUp(self):
        self.env = EnvironmentStub(enable=[AkismetFilterStrategy])
        self.strategy = AkismetFilterStrategy(self.env)
        self.urlopen = akismet.urllib2.urlopen = DummyURLOpener()

    def test_no_api_key(self):
        req = Mock()
        retval = self.strategy.test(req, 'anonymous', 'foobar', req.remote_addr)
        self.assertEqual(None, retval)

    def test_bad_api_key(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1')
        self.env.config.set('spam-filter', 'akismet_api_key', 'INVALID')

        self.urlopen.responses = ['invalid']
        retval = self.strategy.test(req, 'anonymous', 'foobar', req.remote_addr)
        self.assertEqual(None, retval)
        self.assertEqual(1, len(self.urlopen.requests))

        req = self.urlopen.requests[0]
        self.assertEqual('http://rest.akismet.com/1.1/verify-key', req.url)
        self.assertEqual('blog=http%3A%2F%2Fexample.org%2F&key=INVALID',
                         req.params)
        self.assertEqual(self.strategy.user_agent, req.headers['User-Agent'])

    def test_check_ham(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1', get_header=lambda x: None)
        self.env.config.set('spam-filter', 'akismet_api_key', 'mykey')

        self.urlopen.responses = ['valid', 'false']
        retval = self.strategy.test(req, 'anonymous', 'foobar', req.remote_addr)
        self.assertEqual(None, retval)
        self.assertEqual(2, len(self.urlopen.requests))

        req = self.urlopen.requests[1]
        self.assertEqual('http://mykey.rest.akismet.com/1.1/comment-check',
                         req.url)
        self.assertEqual('user_ip=127.0.0.1&referrer=unknown&'
                         'blog=http%3A%2F%2Fexample.org%2F&user_agent=None&'
                         'comment_content=foobar&comment_author=&'
                         'comment_author_email=anonymous', req.params)
        self.assertEqual(self.strategy.user_agent, req.headers['User-Agent'])

    def test_check_spam(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1', get_header=lambda x: None)
        self.env.config.set('spam-filter', 'akismet_api_key', 'mykey')

        self.urlopen.responses = ['valid', 'true']
        retval = self.strategy.test(req, 'anonymous', 'foobar', req.remote_addr)
        self.assertEqual((-5, 'Akismet says content is spam'), retval)
        self.assertEqual(2, len(self.urlopen.requests))

    def test_submit_ham(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1', get_header=lambda x: None)
        self.env.config.set('spam-filter', 'akismet_api_key', 'mykey')

        self.urlopen.responses = ['valid', '']
        self.strategy.train(req, 'anonymous', 'foobar', req.remote_addr, spam=False)

        req = self.urlopen.requests[1]
        self.assertEqual('http://mykey.rest.akismet.com/1.1/submit-ham',
                         req.url)
        self.assertEqual('user_ip=127.0.0.1&referrer=unknown&'
                         'blog=http%3A%2F%2Fexample.org%2F&user_agent=None&'
                         'comment_content=foobar&comment_author=&'
                         'comment_author_email=anonymous', req.params)
        self.assertEqual(self.strategy.user_agent, req.headers['User-Agent'])

    def test_submit_spam(self):
        req = Mock(authname='anonymous', base_url='http://example.org/',
                   remote_addr='127.0.0.1', get_header=lambda x: None)
        self.env.config.set('spam-filter', 'akismet_api_key', 'mykey')

        self.urlopen.responses = ['valid', '']
        retval = self.strategy.train(req, 'anonymous', 'foobar', req.remote_addr, spam=True)

        req = self.urlopen.requests[1]
        self.assertEqual('http://mykey.rest.akismet.com/1.1/submit-spam',
                         req.url)
        self.assertEqual('user_ip=127.0.0.1&referrer=unknown&'
                         'blog=http%3A%2F%2Fexample.org%2F&user_agent=None&'
                         'comment_content=foobar&comment_author=&'
                         'comment_author_email=anonymous', req.params)
        self.assertEqual(self.strategy.user_agent, req.headers['User-Agent'])


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(AkismetFilterStrategyTestCase, 'test'))
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
