# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2012 Edgewall Software
# Copyright (C) 2005-2006 Matthew Good <trac@matt-good.net>
# Copyright (C) 2006 Christopher Lenz <cmlenz@gmx.de>
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
#         Christopher Lenz <cmlenz@gmx.de>

from trac.core import *

from trac.util.translation  import domain_functions

_, tag_, N_, add_domain, gettext, ngettext = domain_functions(
    'tracspamfilter', 
    ('_', 'tag_', 'N_', 'add_domain', 'gettext', 'ngettext'))

__all__ = ['RejectContent', 'IFilterStrategy']

class RejectContent(TracError):
    """Exception raised when content is rejected by a filter."""

class IFilterStrategy(Interface):
    """Mainfilter class, mainly consisting of test() and train() function

       Filters using network access should return True for is_external() call.

       Any variable ending in "karma_points" is presented in the karma admin
       interface.
    """

    def is_external(self):
        """Is this an service sending data to external servers.

        Return True if data is passed to external servers
        """

    def test(req, author, content, ip):
        """Test the given content submission.
        
        Should return a `(points, reason)` tuple to affect the score of the
        submission, where `points` is an integer, and `reason` is a brief
        description of why the score is being affected.
        
        If the filter strategy does not want (or is not able) to effectively
        test the submission, it should return `None`.
        """

    def train(req, author, content, ip, spam=True):
        """Train the filter by reporting a false negative or positive.
        
        The spam keyword argument is `True` if the content should be considered
        spam (a false negative), and `False` if the content was legitimate (a
        false positive).
        
        returns
           0 (no training),
           1 (training ok),
          -1 (training error) or
          -2 (missing preconditions, e.g. keys)
        """

class IRejectHandler(Interface):
    """Handle content rejection."""

    def reject_content(req, reason):
        """Reject content. `reason` is a human readable message describing why
        the content was rejected. """

def get_strategy_name(strategy):
    try:
        name = strategy._name
    except Exception, e:
        name = strategy.__class__.__name__
    if name.endswith("FilterStrategy"):
        name = name[:-14]
    return name
