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
import urllib
import urllib2
from pkg_resources import get_distribution

from genshi.builder import Element, Fragment, tag
from trac import __version__ as TRAC_VERSION
from trac.core import *
from trac.config import *
from trac.util.html import html
from tracspamfilter.captcha import ICaptchaMethod

class AreYouAHumanCaptcha(Component):
    """AreYouAHuman implementation"""

    implements(ICaptchaMethod)

    publisher_key = Option('spam-filter', 'captcha_areyouahuman_publisher_key',
                      '', """Publisher key for AreYouAHuman usage.""",
                      doc_domain="tracspamfilter")

    scoring_key = Option('spam-filter', 'captcha_areyouahuman_scoring_key',
                      '', """Scoring key for AreYouAHuman usage.""",
                      doc_domain="tracspamfilter")

    host = Option('spam-filter', 'captcha_areyouahuman_host',
           'ws.areyouahuman.com', """Host name for AreYouAHuman usage.""",
           doc_domain="tracspamfilter")

    user_agent = 'Trac/%s | SpamFilter/%s'  % (
            TRAC_VERSION, get_distribution('TracSpamFilter').version)

    def generate_captcha(self, req):
        fragment1 = tag.div(id="AYAH")

        fragment2 = tag(Element('script', type="text/javascript",
        src="https://%s/ws/script/%s" % (self.host, urllib2.quote(self.publisher_key, safe=''))))

        fragment3 = tag(Element('input', type="submit"))

        return None, Fragment()(fragment1, fragment2, fragment3)

    def verify_key(self, publisher_key, scoring_key):
        if publisher_key == None or scoring_key == None:
            return False;
        # FIXME - Not yet implemented
        return True
                                
    def verify_captcha(self, req):
        res = False
        try:
            secret = req.args.get('session_secret')
            self.log.debug('AreYouAHuman check result: %s', secret)
            response = urllib2.urlopen("https://%s/ws/scoreGame" % self.host, \
            urllib.urlencode({ 'scoring_key': self.scoring_key, 'session_secret': secret }))
            self.log.debug('AreYouAHuman server check response: %s', response.code)
            if response.code == 200:
                resp = response.readline()
                self.log.debug('AreYouAHuman server check result: %s', resp)
                if '{"status_code":1}' in resp:
                    res = True
                else:
                    self.log.warning('AreYouAHuman returned invalid check result: %s', resp)
            else:
                self.log.warning('AreYouAHuman returned invalid check result: %s (%s)', response.code, response.read())
            response = urllib2.urlopen("https://%s//ws/recordConversion/%s" % (self.host, secret))
            if response.code != 200:
                self.log.warning('AreYouAHuman returned invalid conversion result: %s (%s)', response.code, response.read())
        except Exception, e:
            self.log.warning('Exception in AreYouAHuman handling (%s)', e)
        return res

    def is_usable(self, req):
        return (self.publisher_key and self.scoring_key)
