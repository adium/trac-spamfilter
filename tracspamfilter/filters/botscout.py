# -*- coding: utf-8 -*-
#
# Copyright (C) 2012 Dirk Stöcker <trac@dstoecker.de>
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
import urllib2
import re
import string
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_

class BotScoutFilterStrategy(Component):
    """Spam filter using the BotScount (http://botscout.com/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'botscout_karma', '3',
        """By how many points a BotScout reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'botscout_api_key', '',
        """API key required to use BotScout.""", doc_domain="tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
        TRAC_VERSION, get_distribution('TracSpamFilter').version
    )

    # IFilterStrategy implementation

    def is_external(self):
        return True

    def test(self, req, author, content, ip):
        if not self._check_preconditions(False):
            return
        try:
            resp = self._send(req, author, ip)
            if resp.startswith("Y"):
                count = 0
                res = string.split(resp, '|')
                if res[3] != "0":
                  count += 1
                if res[5] != "0":
                  count += 1
                if res[7] != "0":
                  count += 1
                return -abs(self.karma_points)*count, N_('BotScout says this is spam (%s)'), resp
        except urllib2.URLError, e:
            self.log.warn('BotScout request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        return 0

    # Internal methods

    def _check_preconditions(self, train):
        if self.karma_points == 0:
            return False

        if not self.api_key:
            return False

        return True

    def _send(self, req, author, ip):
        # Split up author into name and email, if possible
        author = author.encode('utf-8')
        author_name, author_email = parseaddr(author)
        if not author_name and not author_email:
            author_name = author
        elif not author_name and author_email.find("@") < 1:
            author_name = author
            author_email = None
        if author_name == "anonymous":
            author_name = None

        params = {'ip': ip , 'key': self.api_key}
        if author_name:
            params['name'] = author_name
        if author_email:
            params['mail'] = author_email

        url = 'http://botscout.com/test/?multi&' + urlencode(params)
        urlreq = urllib2.Request(url, None, {'User-Agent' : self.user_agent})

        resp = urllib2.urlopen(urlreq)
        return resp.read()
