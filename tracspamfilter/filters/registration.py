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

from trac.config import ListOption, IntOption, BoolOption
from trac.core import *
from tracspamfilter.api import IFilterStrategy, N_
from acct_mgr.api import IAccountRegistrationInspector
from acct_mgr.register import RegistrationError
from genshi.builder import tag

class RegistrationFilterStrategy(Component):
    """Spam filter strategy that calls account manager checks for
    account registration.
    """
    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'account_karma', '0',
        """By how many points a failed registration check impacts
        the overall score.""", doc_domain="tracspamfilter")

    replace_checks = BoolOption('spam-filter', 'account_replace_checks', 'false',
        """Replace checks in account manager totally.""", doc_domain="tracspamfilter")

    listeners = ExtensionPoint(IAccountRegistrationInspector)

    def render_registration_fields(self, req, data, fragments):
        self.log.debug('Adding registration check data fields')
        if self.replace_checks:
            for check in self.listeners:
                try:
                    if check.__class__.__name__ != 'RegistrationFilterAdapter':
                        self.log.debug('Add registration check data %s' % check)
                        fragment, f_data = check.render_registration_fields(req, data)
                        try:
                            fragments['optional'] = tag(fragments.get('optional', ''), fragment.get('optional', ''))
                            fragments['required'] = tag(fragments.get('required', ''), fragment.get('required', ''))
                        except AttributeError:
                            if fragment != None and fragment != '':
                                fragments['required'] = tag(fragments.get('required', ''), fragment)
                        data.update(f_data)
                except Exception, e:
                    self.log.exception('Adding registration fields failed: %s' % e)
        return fragments, data

    # IFilterStrategy methods

    def is_external(self):
        return False

    def test(self, req, author, content, ip):
        if req.path_info == "/register":
            karma = 0
            checks = []
            for check in self.listeners:
                try:
                    if check.__class__.__name__ != 'RegistrationFilterAdapter':
                        self.log.debug("Try registration check %s" % check)
                        check.validate_registration(req)
                except RegistrationError, e:
                    karma -= abs(self.karma_points)
                    msg = e.message.replace('\n','')
                    args = e.msg_args
                    if args:
                        msg = msg % args
                        msg.replace("<b>","*").replace("</b>","*")
                    self.log.debug(u"Registration check returned %s" % msg)
                    checks.append(u"%s: %s" % (check.__class__.__name__, msg))
                except Exception, e:
                    self.log.exception(u"Registration check %s failed: %s" % (check, e))
            if karma or checks:
                return karma, N_('Account registration failed (%s)'), ", ".join(checks)

    def train(self, req, author, content, ip, spam=True):
        return 0
