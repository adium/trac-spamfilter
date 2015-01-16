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

import time

from trac.core import *
from trac.config import ExtensionOption, IntOption
from trac.web.api import IRequestFilter, IRequestHandler
from tracspamfilter.api import IFilterStrategy, IRejectHandler, RejectContent, N_, _
from trac.util.html import Markup

class ICaptchaMethod(Interface):
    """ A CAPTCHA implementation. """

    def generate_captcha(req):
        """Return a tuple of `(result, html)`, where `result` is the expected
        response and `html` is a HTML fragment for displaying the CAPTCHA
        challenge."""

    def verify_captcha(req):
        """Checks if captcha is valid (only in case generate_captcha returns
        None for challenge parameter, otherwise check directly."""

    def is_usable(req):
        """Check if captcha can be used for the request."""

class CaptchaSystem(Component):
    """ Main captcha handling system required to allow captcha based score updating
    in case submission was rejected.
    """
    implements(IRequestHandler, IRejectHandler, IFilterStrategy, IRequestFilter)

    handlers = ExtensionPoint(IRequestHandler)

    _name = "Captcha"

    captcha = ExtensionOption('spam-filter', 'captcha', ICaptchaMethod,
                              'ExpressionCaptcha',
        """CAPTCHA method to use for verifying humans.""",
        doc_domain="tracspamfilter")

    karma_points = IntOption('spam-filter', 'captcha_karma', 20,
        """By how many points a successful CAPTCHA response increases the
        overall score.""",
        doc_domain="tracspamfilter")

    repeat_karma_points = IntOption('spam-filter', 'captcha_failed_karma', 1,
        """By how many points a failed CAPTCHA impacts the overall score.""",
        doc_domain="tracspamfilter")

    karma_lifetime = IntOption('spam-filter', 'captcha_karma_lifetime', 86400,
        """Time in seconds that a successful CAPTCHA response increases
        karma.""", doc_domain="tracspamfilter")

    captcha_lifetime = IntOption('spam-filter', 'captcha_lifetime', 120,
        """Time in seconds before CAPTCHA is removed.""",
        doc_domain="tracspamfilter")

    captcha_cleantime = IntOption('spam-filter', 'captcha_lifetime', 3600,
        """Time in seconds before database cleanup is called.""",
        doc_domain="tracspamfilter")

    # IFilterStrategy methods

    def is_external(self):
        return False

    def _getcaptchaname(self, req):
        name = self.captcha.__class__.__name__
        if name.endswith("Captcha"):
            name = name[:-7]
        return req.session.get('captcha_verified_name', name)

    def test(self, req, author, content, ip):
        if not self._expired(req):
            self.log.debug("CAPTCHA: Test %s not expired" % self._getcaptchaname(req))
            return self.karma_points, N_('Human verified via CAPTCHA (%s)'), \
                self._getcaptchaname(req)
        else:
            # simply test to downweight wrong captcha solutions
            val = int(req.session.get('captcha_reject_count', 0))
            self.log.debug("CAPTCHA: Test %s reject %d" % (self._getcaptchaname(req), val))
            if(val > 0):
                return -self.repeat_karma_points*val, \
                    N_('Failed CAPTCHA (%s) attempts'), \
                    self._getcaptchaname(req)

    def train(self, req, author, content, ip, spam=True):
        pass

    # IRejectHandler methods

    def reject_content(self, req, message):
        self._cleanup()
        if self._expired(req):
            req.session['captcha_reject_time'] = int(time.time())
            val = int(req.session.get('captcha_reject_count', 0))
            req.session['captcha_reject_count'] = val+1
            req.session['captcha_reject_reason'] = message
            req.session['captcha_redirect'] = req.path_info
            for key, value in req.args.iteritems():
                req.session['captcha_arg_%s' % (key)] = value
            req.redirect(req.href.captcha())
        else:
            raise RejectContent(message)

    # IRequestHandler methods

    def match_request(self, req):
        return req.path_info == '/captcha'

    def process_request(self, req):
        data = {}
        exp = req.session.get('captcha_expected')
        if req.method == 'POST':
            if req.args.get('captcha_response') == exp:
                data['error'] = _('CAPTCHA failed to handle original request')
            else:
                data['error'] = _('CAPTCHA verification failed')
        else:
            data['error'] = Markup(req.session.get('captcha_reject_reason'))
        # cleanup olf values
        if exp != None:
            del req.session['captcha_expected']
        # generate new captcha
        result, html = self.captcha.generate_captcha(req)
        data['challenge'] = html
        if self.captcha.__class__.__name__ == "RandomCaptcha":
            data['random'] = 1
        if result != None:
            data['defaultform'] = 1
            req.session['captcha_expected'] = result
        req.session.save()
        return 'verify_captcha.html', data, None

    def pre_process_request(self, req, handler):
        if req.path_info == '/captcha' and req.method == 'POST':
            valid = False
            exp = req.session.get('captcha_expected')
            try:
               name = self.captcha.name(req)
            except Exception, e:
               name = self.captcha.__class__.__name__
            if name.endswith("Captcha"):
               name = name[:-7]
            if exp == None:
                valid = self.captcha.verify_captcha(req)
            elif req.args.get('captcha_response', "") == exp:
                valid = True

            if valid:
                req.environ['PATH_INFO'] = req.session.get('captcha_redirect', req.href())
                if ('SCRIPT_NAME' in req.environ and len(req.environ['SCRIPT_NAME']) > 1):
                    req.environ['PATH_INFO'] = req.environ['PATH_INFO'].replace(req.environ['SCRIPT_NAME'], '')
                req.environ['PATH_INFO'] = req.environ['PATH_INFO'].encode('utf-8')
                if 'captcha_redirect' in req.session:
                    del req.session['captcha_redirect']
                if 'captcha_reject_reason' in req.session:
                    del req.session['captcha_reject_reason']
                if 'captcha_reject_time' in req.session:
                    del req.session['captcha_reject_time']
                keys = req.session.keys()
                for key in keys:
                    if key.startswith('captcha_arg_'):
                        arg = key[12:]
                        req.args[arg] = req.session[key]
                        del req.session[key]
                try:
                    for newhandler in self.handlers:
                        try:
                            if newhandler.match_request(req):
                                keys = req.session.keys()
                                for key in keys:
                                    if key.startswith('captcha_'):
                                        self.log.warning('Del %s', key)
                                        del req.session[key]
                                handler = newhandler
                                break
                        except Exception, e:
                            self.log.debug('Exception when parsing handlers: (%s)', e)
                except TracError, e:
                    self.log.debug("CAPTCHA: PreProcess End %s %s" % (name, e))
                    req.session['captcha_verified_name'] = name
                    return (handler)
                req.session['captcha_verified_name'] = name
                req.session['captcha_verified'] = int(time.time())
                self.log.debug("CAPTCHA: PreProcess OK %s" % name)
                req.session.save()
        return (handler)

    def post_process_request(self, req, template, content_type):
        return (template, content_type)

    def post_process_request(self, req, template, data, content_type):
        return (template, data, content_type)

    # Internal methods

    def _expired(self, req):
        return int(req.session.get('captcha_verified', 0)) + \
               self.karma_lifetime < time.time()

    # remove old entries from database
    def _cleanup(self):
        last = 0
        try:
            row = self.env.db_query("SELECT value FROM system "
                                    "WHERE name='spamfilter_lastclean'")
            last = int(row[0][0])
        except:
            pass
        tim = int(time.time())
        if last+self.captcha_cleantime < tim:
            self.log.debug('CAPTCHA: Cleanup captcha %s+%s < %s' % (last,self.captcha_cleantime, tim))
            t = tim - self.captcha_lifetime
            tc = tim - self.karma_lifetime
            with self.env.db_transaction as db:
                if last == 0:
                    db("INSERT INTO system VALUES "
                       "('spamfilter_lastclean',%s)", (tim,))
                else:
                    db("UPDATE system SET value=%s WHERE "
                       "name='spamfilter_lastclean'", (tim,))
                db("""DELETE FROM session_attribute
                WHERE
                  name LIKE 'captcha%%'
                 AND
                  (name != 'captcha_verified' OR %s < %%s)
                 AND
                  (name != 'captcha_verified_name' OR
                    (
                     sid IN
                      (SELECT * FROM
                        (SELECT sid FROM session_attribute
                          WHERE
                            name = 'captcha_verified'
                           AND
                            %s < %%s
                        ) AS tmp1
                      )
                    )
                  )
                 AND
                  (
                   sid IN
                    (SELECT * FROM
                      (SELECT sid FROM session_attribute
                        WHERE
                          name = 'captcha_reject_time'
                         AND
                          %s < %%s
                      ) AS tmp1
                    )
                  OR
                   sid NOT IN
                    (SELECT * FROM
                      (SELECT sid FROM session_attribute
                        WHERE
                          name = 'captcha_reject_time'
                      ) AS tmp2
                    )
                  )""" % (db.cast('value','int'), \
                db.cast('value', 'int'), db.cast('value', 'int')), (tc,tc,t))
