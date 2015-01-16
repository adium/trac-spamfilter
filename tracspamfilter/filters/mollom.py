# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Dirk Stöcker <trac@dstoecker.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

from email.Utils import parseaddr
from urllib import urlencode
import httplib2
import urllib2
import oauth2
from pkg_resources import get_distribution
from xml.etree import ElementTree

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from trac.mimeview.api import is_binary
from tracspamfilter.api import IFilterStrategy, N_


class MollomFilterStrategy(Component):
    """Spam filter using the Mollom service (http://mollom.com/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'mollom_karma', '10',
        """By how many points an Mollom reject impacts the overall karma of
        a submission.""", doc_domain = "tracspamfilter")

    public_key = Option('spam-filter', 'mollom_public_key', '',
        """Public key required to use the Mollom API.""",
        doc_domain = "tracspamfilter")

    private_key = Option('spam-filter', 'mollom_private_key', '',
        """Private key required to use the Mollom API.""",
        doc_domain = "tracspamfilter")

    api_url = Option('spam-filter', 'mollom_api_url', 'rest.mollom.com/v1/',
        """URL of the Mollom service.""", doc_domain = "tracspamfilter")

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
            # Split up author into name and email, if possible
            author = author.encode('utf-8')
            author_name, author_email = parseaddr(author)
            if not author_name and not author_email:
                author_name = author
            elif not author_name and author_email.find("@") < 1:
                author_name = author
                author_email = None

            params = {'authorIp': ip,
                      'postBody': content.encode('utf-8'),
                      'checks': 'spam',
                      'authorName': author_name}
            if author_email:
                params['authorMail'] = author_email

            resp, content = self._call("content", params)
            if "<spamClassification>spam</spamClassification>" in content:
                tree = ElementTree.fromstring(content)
                confidence = 1
                se = tree.find('./content/spamScore')
                if se != None:
                    confidence = float(se.text)
                else:
                    self.log.warn('Mollom score not found')
                karma = abs(self.karma_points)*float(confidence);
                self.log.debug('Mollom says content is %s spam', confidence)
                return -int(karma+0.5), N_('Mollom says content is spam')
            elif "<spamClassification>ham</spamClassification>" in content:
                tree = ElementTree.fromstring(content)
                confidence = 1
                se = tree.find('./content/spamScore')
                if se != None:
                    confidence = 1.0-float(se.text)
                else:
                    self.log.warn('Mollom score not found')
                karma = abs(self.karma_points)*float(confidence);
                self.log.debug('Mollom says content is %s ham', confidence)
                return int(karma+0.5), N_('Mollom says content is ham')

        except urllib2.URLError, e:
            self.log.warn('Mollom request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        return 0

    # Internal methods

    def _call(self, url, params = None, public_key = None, private_key = None, api_url = None):
        if not api_url:
          api_url = self.api_url
        if not public_key:
          public_key = self.public_key
        if not private_key:
          private_key = self.private_key
        headers = {'Content-Type': 'text/plain', 'User-Agent': self.user_agent}
        if params:
            body = urlencode(params)
        else:
            body = "\n"

        url = "http://" + api_url + url
        consumer = oauth2.Consumer(public_key, private_key)
        req = oauth2.Request.from_consumer_and_token(consumer, http_method="POST", http_url=url, body=body)
        req.sign_request(oauth2.SignatureMethod_HMAC_SHA1(), consumer, None)
        headers.update(req.to_header())
        return httplib2.Http().request(url, method="POST", body=body, headers=headers)

    def _check_preconditions(self, req, author, content):
        if self.karma_points == 0:
            return False

        if not self.public_key or not self.private_key:
            self.log.warning('Mollom API keys missing')
            return False

        if is_binary(content):
            self.log.warning('Content is binary, Mollom content check skipped')
            return False

        try:
            if not self.verify_key(req):
                self.log.warning('Mollom API keys are invalid')
                return False
            return True
        except urllib2.URLError, e:
            self.log.warn('Mollom request failed (%s)', e)

    def verify_key(self, req, api_url=None, public_key=None, private_key=None):
        if api_url is None:
            api_url = self.api_url
        if private_key is None:
            private_key = self.private_key
        if public_key is None:
            public_key = self.public_key

        if public_key+private_key != self.verified_key:
            self.log.debug('Verifying Mollom API keys')
            resp, content = self._call("site/%s" % public_key, None, public_key, private_key, api_url)
            c = "<privateKey>%s</privateKey>" % private_key
            if c in content:
                self.log.debug('Mollom API keys are valid')
                self.verified = True
                self.verified_key = public_key+private_key

        return self.verified_key is not None
