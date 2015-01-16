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

from __future__ import absolute_import

import os
import urllib2, urllib
from pkg_resources import get_distribution

from genshi.builder import Element, Fragment, tag
from genshi.core import Markup
from trac import __version__ as TRAC_VERSION
from trac.core import *
from trac.config import *
from trac.util.html import html
from tracspamfilter.api import _
from tracspamfilter.captcha import ICaptchaMethod

from recaptcha.client import captcha

class RecaptchaCaptcha(Component):
    """reCAPTCHA implementation"""

    implements(ICaptchaMethod)

    private_key = Option('spam-filter', 'captcha_recaptcha_private_key',
                      '', """Private key for reCaptcha usage.""",
                      doc_domain="tracspamfilter")

    public_key = Option('spam-filter', 'captcha_recaptcha_public_key',
                      '', """Public key for reCaptcha usage.""",
                      doc_domain="tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
            TRAC_VERSION, get_distribution('TracSpamFilter').version)

    def generate_captcha(self, req):

        fragment = tag(Markup(captcha.displayhtml(self.public_key, True, None)))

        fragment.append(Element('input', type="submit", value=_("Submit")))

        return None, fragment

    def encode_if_necessary(self, s):
        if isinstance(s, unicode):
            return s.encode('utf-8')
        return s

    def verify_key(self, private_key, public_key):
        if private_key == None or public_key == None:
            return False;
        # FIXME - Not yet implemented
        return True

    def verify_captcha(self, req):
        try:
            remoteip = req.remote_addr
            result = captcha.submit(req.args.get('g-recaptcha-response'), self.private_key, remoteip)

            if result.is_valid:
                return True
            else:
                self.log.warning('reCAPTCHA returned error: %s', result.return_values)
        except Exception, e:
            self.log.warning('Exception in reCAPTCHA handling (%s)', e)
            return False
        return False

    def is_usable(self, req):
        return (self.public_key and self.private_key)
