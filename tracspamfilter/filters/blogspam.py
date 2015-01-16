# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Edgewall Software
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
#
# Author: Dirk Stöcker <trac@dstoecker.de>

from email.Utils import parseaddr
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option, ListOption
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_
from tracspamfilter.timeoutserverproxy import TimeoutServerProxy
from trac.mimeview.api import is_binary

class BlogSpamFilterStrategy(Component):
    """Spam filter using the BlogSpam service (http://blogspam.net/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'blogspam_karma', '5',
        """By how many points an BlogSpam reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_url = Option('spam-filter', 'blogspam_api_url', 'test.blogspam.net:8888',
        """URL of the BlogSpam service.""", doc_domain="tracspamfilter")

    skip_tests = ListOption('spam-filter', 'blogspam_skip_tests', 'bayesian, linksleeve, sfs', doc=
        """Comma separated list of tests to skip.""", doc_domain="tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
        TRAC_VERSION, get_distribution('TracSpamFilter').version
    )

    # IFilterStrategy implementation

    def is_external(self):
        return True

    def test(self, req, author, content, ip):
        if not self._check_preconditions(req, author, content):
            return

        try:
            server = TimeoutServerProxy("http://"+self.api_url)
            res = server.testComment(self._getparams(req, author, content, ip))
            if res.startswith("SPAM:"):
                return -abs(self.karma_points), N_('BlogSpam says content is spam (%s)'), res[5:]
        except Exception, v:
            self.log.warning('Checking with BlogSpam failed: %s', v)
        except IOError, v:
            self.log.warning("Checking with BlogSpam failed: %s", v)

    def train(self, req, author, content, ip, spam=True):
        if not self._check_preconditions(req, author, content):
            return -2

        try:
            params = self._getparams(req, author, content, ip)
            if spam:
                params['train'] = "spam"
            else:
                params['train'] = "ham"
            server = TimeoutServerProxy("http://"+self.api_url)
            res = server.classifyComment(params)
            self.log.debug('Classifying with BlogSpam succeeded: %s', res)
            return 1
        except Exception, v:
            self.log.warning('Classifying with BlogSpam failed: %s', v)
        except IOError, v:
            self.log.warning("Classifying with BlogSpam failed: %s", v)
        return -1

    def getmethods(self):
        try:
            server=TimeoutServerProxy("http://"+self.api_url)
            return server.getPlugins();
        except Exception:
            return ""

    # Internal methods

    def _check_preconditions(self, req, author, content):
        if self.karma_points == 0:
            return False

        if len(content) == 0:
            return False

        if is_binary(content):
            self.log.warning('Content is binary, BlogSpam content check skipped')
            return False

        return True

    def _getparams(self, req, author, content, ip):
        # Split up author into name and email, if possible
        author = author.encode('utf-8')
        author_name, author_email = parseaddr(author)
        if not author_name and not author_email:
            author_name = author
        elif not author_name and author_email.find("@") < 1:
            author_name = author
            author_email = None
        params = {
            'ip':ip,
            'name':author_name,
            'comment':content.encode('utf-8'),
            'agent':req.get_header('User-Agent'),
            'site':req.base_url,
            'version':self.user_agent
        }
        if len(self.skip_tests):
            params['options'] = "exclude=%s" % ",exclude=".join(self.skip_tests)
        if author_email:
            params['email'] = author_email
        return params
