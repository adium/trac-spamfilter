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

import re
import copy

from trac.config import ListOption, IntOption
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_
from tracspamfilter.model import LogEntry

class ExternalLinksFilterStrategy(Component):
    """Spam filter strategy that reduces the karma of a submission if the
    content contains too many links to external sites.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'extlinks_karma', '2',
        """By how many points too many external links in a submission impact
        the overall score.""", doc_domain="tracspamfilter")

    max_links = IntOption('spam-filter', 'max_external_links', '4',
        """The maximum number of external links allowed in a submission until
        that submission gets negative karma.""", doc_domain="tracspamfilter")

    allowed_domains = ListOption('spam-filter', 'extlinks_allowed_domains',
                                 'example.com, example.org', doc=
        """List of domains that should be allowed in external links""", 
        doc_domain="tracspamfilter")

    _URL_RE = re.compile('https?://([^/]+)/?', re.IGNORECASE)

    # IFilterStrategy methods

    def is_external(self):
        return False

    def test(self, req, author, content, ip):
        num_ext = 0
        allowed = copy.copy(self.allowed_domains)
        allowed.append(req.get_header('Host'))

        for host in self._URL_RE.findall(content):
            if host not in allowed:
                self.env.log.debug('"%s" is not in extlink_allowed_domains' % host)
                num_ext += 1
            else:
                self.env.log.debug('"%s" is whitelisted.' % host)

        if num_ext > self.max_links:
            if(self.max_links > 0):
                return -abs(self.karma_points) * num_ext / self.max_links, \
                       N_('Maximum number of external links per post exceeded')
            else:
                return -abs(self.karma_points) * num_ext, \
                       N_('External links in post found')

    def train(self, req, author, content, ip, spam=True):
        return 0
