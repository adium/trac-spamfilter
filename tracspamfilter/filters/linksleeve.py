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

import urllib2
from urllib import urlencode
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_
from tracspamfilter.timeoutserverproxy import TimeoutServerProxy

class LinkSleeveFilterStrategy(Component):
    """Spam filter using the LinkSleeve service (http://linksleeve.org/).
    """
    implements(IFilterStrategy)
    
    karma_points = IntOption('spam-filter', 'linksleeve_karma', '3',
        """By how many points a LinkSleeve reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

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
            if TimeoutServerProxy('http://www.linksleeve.org/slv.php').slv(content) != 1:
                return -abs(self.karma_points), N_('LinkSleeve says this is spam')
        except urllib2.URLError, e:
            self.log.warn('LinkSleeve request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        return 0

    # Internal methods

    def _check_preconditions(self, train):
        if self.karma_points == 0:
            return False

        return True
