# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# Copyright (C) 2006 Matthew Good <trac@matt-good.net>
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

from dns.name import from_text
from dns.resolver import query, Timeout, NXDOMAIN, NoAnswer, NoNameservers

from trac.config import ListOption, IntOption
from trac.core import *
from trac.util import reversed
from tracspamfilter.api import IFilterStrategy, N_

class IPBlacklistFilterStrategy(Component):
    """Spam filter based on IP blacklistings.
    
    Requires the dnspython module from http://www.dnspython.org/.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'ip_blacklist_karma', '5',
        """By how many points blacklisting by a single server impacts the
        overall karma of a submission.""", doc_domain="tracspamfilter")

    servers = ListOption('spam-filter', 'ip_blacklist_servers',
                         'list.blogspambl.com, all.s5h.net, dnsbl.tornevall.org', doc=
        """Servers used for IP blacklisting.""", doc_domain="tracspamfilter")

    # IFilterStrategy implementation

    def is_external(self):
        return True

    def test(self, req, author, content, ip):
        if not self._check_preconditions(req, author, content, ip):
            return

        if not self.servers:
            self.log.warning('No IP blacklist servers configured')
            return

        self.log.debug('Checking for IP blacklisting on "%s"' % ip)

        points = 0
        servers = []

        prefix = '.'.join(reversed(ip.split('.'))) + '.'
        for server in self.servers:
            self.log.debug("Checking blacklist %s for %s" % (server, ip))
            try:
                res = query(from_text(prefix + server.encode('utf-8')))[0].to_text()
                points -= abs(self.karma_points)
                if res == "127.0.0.1":
                    servers.append(server)
                else:
                    # strip the common part of responses
                    if res.startswith("127.0.0."):
                      res = res[8:]
                    elif res.startswith("127."):
                      res = res[4:]
                    servers.append("%s [%s]" %(server, res))
            except NXDOMAIN: # not blacklisted on this server
                continue
            except (Timeout, NoAnswer, NoNameservers), e:
                self.log.warning('Error checking IP blacklist server "%s" for '
                                 'IP "%s": %s' % (server, ip, e))

        if points != 0:
            return points, N_('IP %s blacklisted by %s'), ip, ', '.join(servers)

    def train(self, req, author, content, ip, spam=True):
        return 0

    # Internal methods

    def _check_preconditions(self, req, author, content,ip):
        if self.karma_points == 0:
            return False
        
        # IPV4 address ?
        if ip.find(".") < 0:
            return False

        return True
