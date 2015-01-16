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
from urllib import quote
import urllib2
import re
from pkg_resources import get_distribution
from xml.etree import ElementTree
import string

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_

class FSpamListFilterStrategy(Component):
    """Spam filter using the FSpamList (http://www.fspamlist.com/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'fspamlist_karma', '3',
        """By how many points a FSpamList reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'fspamlist_api_key', '',
        """API key required to use FSpamList.""", doc_domain="tracspamfilter")

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
            reason = []
            tree = ElementTree.fromstring(resp)
            for el in list(tree):
                if el.findtext('isspammer', 'false') == 'true':
                    r = "%s [%s" % (el.findtext('spammer','-'), \
                        el.findtext('threat','-'))
                    n = string.split(el.findtext('notes', '-'), \
                        "Time taken")[0].rstrip(" ")
                    if n != "":
                      r += ", " + n
                    r += "]"
                    reason.append(r)
            if len(reason):
                return -abs(self.karma_points)*len(reason), \
                    N_('FSpamList says this is spam (%s)'), ("; ".join(reason))
        except urllib2.URLError, e:
            self.log.warn('FSpamList request failed (%s)', e)

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

        request = quote(ip)
        if author_name:
            request += "," + quote(author_name)
        if author_email:
            request += "," + quote(author_email)

        url = 'http://www.fspamlist.com/api.php?spammer=' + request + "&key=" + self.api_key
        urlreq = urllib2.Request(url, None, {'User-Agent' : self.user_agent})

        resp = urllib2.urlopen(urlreq)
        return resp.read()

