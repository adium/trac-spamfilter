# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Dirk Stöcker <trac@dstoecker.de>
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
from pkg_resources import get_distribution
from xml.etree import ElementTree

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from tracspamfilter.api import IFilterStrategy, _, N_

class StopForumSpamFilterStrategy(Component):
    """Spam filter using the StopForumSpam service (http://stopforumspam.com/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'stopforumspam_karma', '4',
        """By how many points a StopForumSpam reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'stopforumspam_api_key', '',
        """API key used to report SPAM.""", doc_domain="tracspamfilter")

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
            resp = self._send(req, author, content, ip, False)
            tree = ElementTree.fromstring(resp)
            karma = 0
            reason = []
            for entry in ('username', 'ip', 'email'):
                e = tree.find('./%s/appears' % entry)
                if e != None and e.text == "1":
                    confidence = tree.find('./%s/confidence' % entry).text
                    karma += abs(self.karma_points)*float(confidence)/100.0;
                    reason.append("%s [%s]" % (entry, confidence))
            reason = ",".join(reason);
            if karma:
                return -int(karma+0.5), N_('StopForumSpam says this is spam (%s)'), reason
        except IOError, e:
            self.log.warn('StopForumSpam request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        if not spam:
            return 0
        elif not self._check_preconditions(True):
            return -2

        try:
            self._send(req, author, content, ip, True)
            return 1
        except urllib2.URLError, e:
            self.log.warn('StopForumSpam request failed (%s)', e)
        return -1

    # Internal methods

    def _check_preconditions(self, train):
        if self.karma_points == 0:
            return False

        if train and not self.api_key:
            return False

        return True

    def _send(self, req, author, content, ip, train):
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

        params = {'ip': ip}
        if author_name:
            params['username'] = author_name
        if author_email:
            params['email'] = author_email

        if train:
            if not author_name or not author_email:
                return
            params['api_key'] = self.api_key
            params['ip_addr'] = ip
            params['evidence'] = "Spam training using Trac SpamFilter (%s)\n%s" % (self.user_agent, content.encode('utf-8'))
            url = 'http://www.stopforumspam.com/add.php'
            urlreq = urllib2.Request(url, urlencode(params), {'User-Agent' : self.user_agent})
        else:
            params['ip'] = ip
            url = 'http://www.stopforumspam.com/api?confidence&f=xmldom&' + urlencode(params)
            urlreq = urllib2.Request(url, None, {'User-Agent' : self.user_agent})

        resp = urllib2.urlopen(urlreq)
        return resp.read()

