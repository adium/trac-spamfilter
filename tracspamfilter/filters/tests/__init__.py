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

import unittest

from tracspamfilter.filters.tests import akismet, bayes, extlinks, regex, \
                                         session

def suite():
    suite = unittest.TestSuite()
    suite.addTest(akismet.suite())
    suite.addTest(bayes.suite())
    suite.addTest(extlinks.suite())
    suite.addTest(regex.suite())
    suite.addTest(session.suite())
    return suite

if __name__ == '__main__':
    unittest.main(defaultTest='suite')
