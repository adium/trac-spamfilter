# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2006 Edgewall Software
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

from email.Utils import parseaddr
from urllib import urlencode
import urllib2
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from trac.mimeview.api import is_binary
from tracspamfilter.api import IFilterStrategy, N_


class AkismetFilterStrategy(Component):
    """Spam filter using the Akismet service (http://akismet.com/).
    
    Based on the `akismet` Python module written by Michael Ford:
      http://www.voidspace.org.uk/python/modules.shtml#akismet
    """
    implements(IFilterStrategy)
    
    noheaders = ['HTTP_COOKIE', 'HTTP_HOST', 'HTTP_REFERER','HTTP_USER_AGENT',
                 'HTTP_AUTHORIZATION']

    karma_points = IntOption('spam-filter', 'akismet_karma', '10',
        """By how many points an Akismet reject impacts the overall karma of
        a submission.""", doc_domain = "tracspamfilter")

    api_key = Option('spam-filter', 'akismet_api_key', '',
        """Wordpress key required to use the Akismet API.""",
        doc_domain = "tracspamfilter")

    api_url = Option('spam-filter', 'akismet_api_url', 'rest.akismet.com/1.1/',
        """URL of the Akismet service.""", doc_domain = "tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
        TRAC_VERSION, get_distribution('TracSpamFilter').version
    )

    def __init__(self):
        self.verified_key = None

    # IFilterStrategy implementation

    def is_external(self):
        return True
            
    def test(self, req, author, content, ip):
        if not self._check_preconditions(req, author, content):
            return

        try:
            url = 'http://%s.%scomment-check' % (self.api_key, self.api_url)
            self.log.debug('Checking content with Akismet service at %s', url)
            resp = self._post(url, req, author, content, ip)
            if resp.strip().lower() != 'false':
                self.log.debug('Akismet says content is spam')
                return -abs(self.karma_points), N_('Akismet says content is spam')

        except urllib2.URLError, e:
            self.log.warn('Akismet request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        if not self._check_preconditions(req, author, content):
            return -2

        try:
            which = spam and 'spam' or 'ham'
            url = 'http://%s.%ssubmit-%s' % (self.api_key, self.api_url, which)
            self.log.debug('Submitting %s to Akismet service at %s', which, url)
            self._post(url, req, author, content, ip)
            return 1
        except urllib2.URLError, e:
            self.log.warn('Akismet request failed (%s)', e)
        return -1

    # Internal methods

    def _check_preconditions(self, req, author, content):
        if self.karma_points == 0:
            return False

        if not self.api_key:
            self.log.warning('Akismet API key is missing')
            return False

        if is_binary(content):
            self.log.warning('Content is binary, Akismet content check skipped')
            return False

        try:
            if not self.verify_key(req):
                self.log.warning('Akismet API key is invalid')
                return False
            return True
        except urllib2.URLError, e:
            self.log.warn('Akismet request failed (%s)', e)

    def verify_key(self, req, api_url=None, api_key=None):
        if api_url is None:
            api_url = self.api_url
        if api_key is None:
            api_key = self.api_key

        if api_key != self.verified_key:
            self.log.debug('Verifying Akismet API key')
            params = {'blog': req.base_url, 'key': api_key}
            req = urllib2.Request('http://%sverify-key' % api_url,
                                  urlencode(params),
                                  {'User-Agent' : self.user_agent})
            resp = urllib2.urlopen(req).read()
            if resp.strip().lower() == 'valid':
                self.log.debug('Akismet API key is valid')
                self.verified = True
                self.verified_key = api_key

        return self.verified_key is not None

    def _post(self, url, req, author, content, ip):
        # Split up author into name and email, if possible
        author = author.encode('utf-8')
        author_name, author_email = parseaddr(author)
        if not author_name and not author_email:
            author_name = author
        elif not author_name and author_email.find("@") < 1:
            author_name = author
            author_email = None

        params = {'blog': req.base_url, 'user_ip': ip,
                  'user_agent': req.get_header('User-Agent'),
                  'referrer': req.get_header('Referer') or 'unknown',
                  'comment_author': author_name,
                  'comment_type': 'trac',
                  'comment_content': content.encode('utf-8')}
        if author_email:
            params['comment_author_email'] = author_email
        for k, v in req.environ.items():
            if k.startswith('HTTP_') and not k in self.noheaders:
                params[k] = v.encode('utf-8')
        urlreq = urllib2.Request(url, urlencode(params),
                              {'User-Agent' : self.user_agent})

        #self.log.warn('AkismetPOST2 %s URL %s', urlencode(params), url)
        resp = urllib2.urlopen(urlreq)
        return resp.read()
