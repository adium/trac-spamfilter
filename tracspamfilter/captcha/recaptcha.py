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

import os
import urllib2, urllib
from pkg_resources import get_distribution

from genshi.builder import Element, Fragment, tag
from trac import __version__ as TRAC_VERSION
from trac.core import *
from trac.config import *
from trac.util.html import html
from tracspamfilter.api import _
from tracspamfilter.captcha import ICaptchaMethod


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
        fragment = tag(Element('script', type="text/javascript",
        src="https://www.google.com/recaptcha/api/challenge?k="
        +self.public_key))

        # note - this is not valid XHTML!
        fragment.append(Element('noscript')(Element('iframe',
        src="https://www.google.com/recaptcha/api/noscript?k="+ self.public_key,
        height=300, width=500, frameborder=0))(Element('br'))(Element('textarea',
        name="recaptcha_challenge_field", rows=3, cols=40))(Element('input',
        type="hidden", name="recaptcha_response_field",
        value="manual_challenge"))(Element('br'))(Element('input', type="submit",
        value=_("Submit"))))

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
            recaptcha_challenge_field = req.args.get('recaptcha_challenge_field')
            recaptcha_response_field = req.args.get('recaptcha_response_field')
            remoteip = req.remote_addr
            params = urllib.urlencode({
                'privatekey': self.encode_if_necessary(self.private_key),
                'remoteip' :  self.encode_if_necessary(remoteip),
                'challenge':  self.encode_if_necessary(recaptcha_challenge_field),
                'response' :  self.encode_if_necessary(recaptcha_response_field),
                })
            request = urllib2.Request (
                url = "https://www.google.com/recaptcha/api/verify",
                data = params,
                headers = {
                    "Content-type": "application/x-www-form-urlencoded",
                    "User-agent": self.user_agent
                    }
                )
    
            httpresp = urllib2.urlopen(request)
            return_values = httpresp.read().splitlines();
            httpresp.close();

            if return_values[0] == "true":
                return True
            else:
                self.log.warning('reCAPTCHA returned error: %s', return_values[1])
        except Exception, e:
            self.log.warning('Exception in reCAPTCHA handling (%s)', e)
            return False
        return False

    def is_usable(self, req):
        return (self.public_key and self.private_key)
