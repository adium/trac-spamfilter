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

from email.Utils import parseaddr

from trac.config import IntOption
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_

class SessionFilterStrategy(Component):
    """This strategy grants positive karma points to users with an existing
    session, and extra points if they've set up their user name and password."""

    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'session_karma', '9',
        """By how many points an existing and configured session improves the
        overall karma of the submission. A third of the points is granted for
        having an existing session at all, the other two thirds are granted
        when the user has his name and/or email address set in the session,
        respectively.""", doc_domain="tracspamfilter")

    # IFilterStrategy implementation

    def is_external(self):
        return False

    def test(self, req, author, content, ip):
        points = 0
        if req.session.last_visit:
            points += abs(self.karma_points) / 3
            if req.session.get('name'):
                points += abs(self.karma_points) / 3
            if req.session.get('email'):
                email = parseaddr(req.session.get('email'))[1]
                if email and '@' in email:
                    points += abs(self.karma_points) / 3
            return points, N_('Existing session found')

    def train(self, req, author, content, ip, spam=True):
        return 0
