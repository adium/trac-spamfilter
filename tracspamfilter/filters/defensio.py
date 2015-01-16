# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2011 Edgewall Software
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
#
# Author: Dirk Stöcker <trac@dstoecker.de>
#         Camilo Lopez <clopez@websense.com>

def is_python3():
    return sys.version_info[0] == 3

from email.Utils import parseaddr
import sys
if is_python3():
    import urllib.parse
else:
    import urllib
import json
from pkg_resources import get_distribution

from trac import __version__ as TRAC_VERSION
from trac.config import IntOption, Option
from trac.core import *
from trac.mimeview.api import is_binary
from tracspamfilter.api import IFilterStrategy, N_
from tracspamfilter.timeoutserverproxy import TimeoutHTTPConnection

class DefensioFilterStrategy(Component):
    """Spam filter using the Defensio service (http://defensio.com/).
    """
    implements(IFilterStrategy)
    
    noheaders = ['HTTP_COOKIE', 'HTTP_HOST', 'HTTP_REFERER', 'HTTP_AUTHORIZATION']

    karma_points = IntOption('spam-filter', 'defensio_karma', '2',
        """By how many points a Defensio reject impacts the overall karma of
        a submission.""", doc_domain="tracspamfilter")

    api_key = Option('spam-filter', 'defensio_api_key', '',
        """Defensio key required to use the API.""", doc_domain="tracspamfilter")

    api_url = Option('spam-filter', 'defensio_api_url', 'api.defensio.com/2.0/users/',
        """URL of the Defensio service.""", doc_domain="tracspamfilter")

    dist = get_distribution('TracSpamFilter')
    user_agent = 'Trac/%s | SpamFilter/%s'  % (
        TRAC_VERSION, dist.version
    )
    client  = "Trac-SpamFilter | %s_%s | %s | %s" % (
        TRAC_VERSION, dist.version,
        "Edgewall Software", "info@edgewall.com"
    )

    def __init__(self):
        self.verified_key = None

    # IFilterStrategy implementation

    def is_external(self):
        return True

    def test(self, req, author, content, ip):
        if not self._check_preconditions(req, author, content):
            return
        try:
            self.log.debug('Checking content with Defensio service')
            resp = self._post(req, author, content, ip)
            val = float(self._getresult(resp, 'spaminess', 1.0))
            message = self._getresult(resp, 'message', 'none')
            if len(message) < 1:
                message = 'none'
            if not self._getresult(resp, 'allow'):
                self.log.debug('Defensio says content is spam')
                return -int(round(abs(self.karma_points*val))), \
                    N_('Defensio says content is not allowed (%s, %s, %s)'), \
                    self._getresult(resp, 'classification', 'unknown'), \
                    str(val), message
            else:
                self.log.debug('Defensio says content is ham')
                return int(round(abs(self.karma_points*(1.0-val)))), \
                    N_('Defensio says content is allowed (%s, %s, %s)'), \
                    self._getresult(resp, 'classification', 'unknown'), \
                    str(val), message
        except Exception, e:
            self.log.warn('Defensio testing request failed (%s)', e)

    def train(self, req, author, content, ip, spam=True):
        if not self._check_preconditions(req, author, content):
            return -2
        try:
            resp = self._post(req, author, content, ip)
            signature = self._getresult(resp, 'signature')
            if signature != None:
                data = {'allow' : not spam}
                resp = self._call('PUT', "%s%s/documents/%s.json" % (self.api_url, self.api_key, signature), data)
                return 1
        except Exception, e:
            self.log.warn('Defensio training request failed (%s)', e)
        return -1

    # Internal methods

    def _check_preconditions(self, req, author, content):
        if self.karma_points == 0:
            return False

        if not self.api_key:
            self.log.debug('Defensio API key is missing')
            return False

        if is_binary(content):
            self.log.debug('Content is binary, Defensio content check skipped')
            return False

        try:
            if not self.verify_key(req):
                self.log.warn('Defensio API key is invalid')
                return False
            return True
        except Exception, e:
            self.log.warn('Defensio request failed (%s)', e)
                   
    def verify_key(self, req, api_url=None, api_key=None):
        if api_url is None:
            api_url = self.api_url
        if api_key is None:
            api_key = self.api_key

        if api_key != self.verified_key:
            self.log.debug('Verifying Defensio API key')
            try:
                resp = self._call('GET', '%s%s.json' % (api_url, api_key))
                if self._getresult(resp, 'owner-url') != None:
                    self.log.debug('Defensio API key is valid')
                    self.verified = True
                    self.verified_key = api_key
            except Exception, e:
                self.log.warn('Defensio key request failed (%s)', e)

        return self.verified_key is not None

    def _post(self, req, author, content, ip):
        # Split up author into name and email, if possible
        author = author.encode('utf-8')
        author_name, author_email = parseaddr(author)
        if not author_name and not author_email:
            author_name = author
        elif not author_name and author_email.find("@") < 1:
            author_name = author
            author_email = None

        params = {'client': self.client,
                  'content': content.encode('utf-8'),
                  'platform': 'trac',
                  'type':'wiki',
                  'async':'false',
                  'author-ip': ip,
                  'author-name': author_name}
        ref = req.get_header('Referer')
        if ref:
            params['referrer'] = ref
        if author_email:
            params['author-email'] = author_email
        headers = ""
        for k, v in req.environ.items():
            if k.startswith('HTTP_') and not k in self.noheaders:
                headers += "%s: %s\n" % (k[5:].replace("_","-").title(), v)
        if len(headers) > 0:
            params['http-headers'] = headers
        return self._call('POST', "%s%s/documents.json" %(self.api_url, self.api_key), params)

    def _call(self, method, url, data=None):
        """ Do the actual HTTP request """
        offs = url.find('/')
        api_host = url[:offs]
        path = url[offs:]
        conn = TimeoutHTTPConnection(api_host)
        headers = {'User-Agent' : self.user_agent}

        if data:
            headers.update( {'Content-type': 'application/x-www-form-urlencoded'} )
            conn.request(method, path, self._urlencode(data), headers)
        else:
            conn.request(method, path, None, headers)

        response = conn.getresponse()
        body = response.read()
        if is_python3():
            body = json.loads(body.decode('UTF-8'))
        else:
            body = json.loads(body)
        result   =  [response.status, body]
        conn.close()
        return result

    def _parse_body(self, body):
        """ For just call a deserializer for FORMAT"""
        if is_python3():
            return json.loads(body.decode('UTF-8'))
        else:
            return json.loads(body)

    def _getresult(self, body, val, defval=None):
        try:
            res = body[1].get('defensio-result').get(val)
        except:
            pass
        if res == None:
            res = defval
        return res

    def _urlencode(self, url):
        if is_python3():
          return urllib.parse.urlencode(url)
        else:
          return urllib.urlencode(url)
