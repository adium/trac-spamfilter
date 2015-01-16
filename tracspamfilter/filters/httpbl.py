# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# Copyright (C) 2006 Matthew Good <trac@matt-good.net>
# Copyright (C) 2009 Vaclav Slavik <vslavik@fastmail.fm>
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
# Author: Vaclav Slavik <vslavik@fastmail.fm>,
#         Matthew Good <trac@matt-good.net>

from dns.resolver import query, Timeout, NXDOMAIN, NoAnswer, NoNameservers

from trac.config import Option, IntOption
from trac.core import *
from trac.util import reversed
from tracspamfilter.api import IFilterStrategy, N_

class HttpBLFilterStrategy(Component):
    """Spam filter based on Project Honey Pot's Http:BL blacklist.

    Requires the dnspython module from http://www.dnspython.org/.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'httpbl_spammer_karma', '6',
        """By how many points listing as "comment spammer" impacts the
        overall karma of a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'httpbl_api_key', '',
        """Http:BL API key required for use.""", doc_domain="tracspamfilter")

    # IFilterStrategy implementation

    def is_external(self):
        return True

    def test(self, req, author, content, ip):
        if not self.api_key:
            self.log.warning('API key not configured.')
            return

        reverse_octal = '.'.join(reversed(ip.split('.')))
        addr = '%s.%s.dnsbl.httpbl.org' % (self.api_key, reverse_octal)
        self.log.debug('Querying Http:BL: %s' % addr)

        try:
            dns_answer = query(addr)
            answer = [int(i) for i in str(dns_answer[0]).split('.')]
            if answer[0] != 127:
                self.log.warning('Invalid Http:BL reply for IP "%s": %s' %
                                 (ip, dns_answer))
                return

            # TODO: answer[1] represents number of days since last activity
            #       and answer[2] is treat score assigned by Project Honey
            #       Pot. We could use both to adjust karma.

            is_suspicious = answer[3] & 1
            is_spammer =    answer[3] & 4

            points = 0
            if is_suspicious:
                points -= abs(self.karma_points) / 3
            if is_spammer:
                points -= abs(self.karma_points)

            if points != 0:
                return points, N_('IP %s blacklisted by Http:BL'), ip

        except NXDOMAIN:
            # not blacklisted on this server
            return
        except (Timeout, NoAnswer, NoNameservers), e:
            self.log.warning('Error checking Http:BL for IP "%s": %s' %
                             (ip, e))

    def train(self, req, author, content, ip, spam=True):
        return 0
