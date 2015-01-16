# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# Copyright (C) 2006 Alec Thomas <alec@swapoff.org>
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
# Author: Alec Thomas <alec@swapoff.org>

import random

from trac.core import *
from trac.config import *
from trac.util.html import html, Markup
from tracspamfilter.captcha import ICaptchaMethod
from tracspamfilter.api import add_domain, gettext, _, N_

class ExpressionCaptcha(Component):
    """captcha in the form of a human readable numeric expression
    
    Initial implementation by sergeych@tancher.com.
    """

    implements(ICaptchaMethod)

    terms = IntOption('spam-filter', 'captcha_expression_terms', 3,
            """Number of terms in numeric CAPTCHA expression.""",
            doc_domain='tracspamfilter')

    ceiling = IntOption('spam-filter', 'captcha_expression_ceiling', 10,
            """Maximum value of individual terms in numeric CAPTCHA
            expression.""", doc_domain='tracspamfilter')

    operations = {'*': N_('multiplied by'), '-': N_('minus'),
                  '+': N_('plus')}

    numerals = (N_('zero'), N_('one'), N_('two'), N_('three'), N_('four'),
                N_('five'), N_('six'), N_('seven'), N_('eight'),
                N_('nine'), N_('ten'), N_('eleven'), N_('twelve'),
                N_('thirteen'), N_('fourteen'), N_('fifteen'),
                N_('sixteen'), N_('seventeen'), N_('eighteen'),
                N_('nineteen') )

    # TRANSLATOR: if compound numbers like in english are not
    # supported, simply add a "plus" command to the following
    # translations!
    tens = (N_('twenty'), N_('thirty'), N_('forty'), N_('fifty'),
            N_('sixty'), N_('seventy'), N_('eighty'), N_('ninety') )

    # ICaptchaMethod methods

    def generate_captcha(self, req):
        if self.ceiling > 100:
            raise TracError(
                _('Numeric captcha can not represent numbers > 100'))
        terms = [unicode(random.randrange(0, self.ceiling)) 
                 for i in xrange(self.terms)]
        operations = [random.choice(self.operations.keys()) 
                      for i in xrange(self.terms)]
        expression = sum(zip(terms, operations), ())[:-1]
        expression = eval(compile(' '.join(expression), 'captcha_eval', 'eval'))
        human = sum(zip([self._humanise(int(t)) for t in terms],
                        [gettext(self.operations[o]) for o in operations]),
                    ())[:-1]
        return (expression, u' '.join(map(unicode, human)))

    def verify_captcha(self, req):
        return False

    def is_usable(self, req):
        return True

    # Internal methods
    
    def _humanise(self, value):
        if value < 20:
            return gettext(self.numerals[value])
        english = gettext(self.tens[value / 10 - 2])
        if value % 10:
            english += u' ' + gettext(self.numerals[value % 10])
        return english
