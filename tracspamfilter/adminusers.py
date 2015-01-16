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

from pkg_resources import resource_filename
from time import time

from urllib import quote, unquote
from trac.admin import IAdminPanelProvider
from trac.config import IntOption, ChoiceOption
from trac.core import Component, implements, TracError
from trac.web.chrome import add_stylesheet, add_notice
from tracspamfilter.api import _, ngettext
from tracspamfilter.users import UserInfo

class UserAdminPageProvider(Component):
    """Web administration panel for spam user info."""

    MIN_WIKI =  IntOption('spam-filter', 'spam_user_minwiki', '0',
    "How many wiki edits are still an unused account.",
    doc_domain='tracspamfilter')

    MAX_AGE =  IntOption('spam-filter', 'spam_user_maxage', '200',
    "How many days no login are considered for dead accounts.",
    doc_domain='tracspamfilter')

    modes = ['overview', 'unused', 'authorized', 'all']
    DEFAULT_MODE =  ChoiceOption('spam-filter', 'spam_user_defaultmode',
    modes, "Default mode for spam user admin panel.",
    doc_domain='tracspamfilter')

    implements(IAdminPanelProvider)

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_USER'):
            yield ('spamfilter', _('Spam Filtering'), 'user', _('Users'))

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_USER')

        if req.method == 'POST':
            if 'cleantemp' in req.args:
                UserInfo.deletetemporary(self.env)
            elif 'changeuser' in req.args:
                if not 'userold' in req.args or not 'usernew' in req.args:
                    raise TracError(_('Old or new value cannot be empty'))
                old = req.args['userold']
                new = req.args['usernew']
                # for strange usernames entering names already encoded is helpful
                if req.args.get('encoded', 0):
                    old = unquote(old).decode('utf8')
                    new = unquote(new).decode('utf8')
                if old == new:
                    raise TracError(_('Old and new value cannot be equal'))
                res = UserInfo.changeuser(self.env, old, new, req.args.get('auth', ''))
                if res == -3:
                    raise TracError(_('New name cannot be used in CC fields'))
                elif res < 0:
                    raise TracError(_('Illegal user arguments passed or changing not allowed'))
                elif res:
                    add_notice(req, ngettext('%(num)d entry has been updated', '%(num)d entries have been updated', res))
            elif 'fixemails' in req.args:
                users, stats = UserInfo.getinfo(self.env, 'authorized')
                for name,user in sorted(users.iteritems()):
                    if user[3] and user[3] != name and ((user[4] | user[6]) & 2):
                        res = UserInfo.changeuser(self.env, user[3], name)
                        if res == -3:
                            add_notice(req, _('Username \'%s\' cannot be used in CC fields') % name)
                        elif res < 0:
                            add_notice(req, _('Error for e-mail change for username \'%s\'') % name)
                        elif res:
                            add_notice(req, ngettext('%(num)d entry has been updated for user %(user)s',
                            '%(num)d entries have been updated for user %(user)s', res, user=name))
                        elif res:
                            add_notice(req, _('E-mails for user %s updated') % name)

            req.redirect(req.href.admin(cat, page,
                                        mode=req.args.get('mode')))

        data = {}
        data['_'] = _
        data['ngettext'] = ngettext
        data['curtime'] = int(time())
        data['maxage'] = int(req.args.get('maxage', self.MAX_AGE))*24*60*60
        data['tempcount'] = len(UserInfo.gettemporary(self.env))
        data['accmgr'] = req.perm.has_permission('ACCTMGR_USER_ADMIN')
        mode = req.args.get('mode', self.DEFAULT_MODE)
        data['mode'] = mode
        data['encoded'] = req.args.get('encoded','')
        data['auth'] = req.args.get('auth','')
        minwiki = int(req.args.get('minwiki', self.MIN_WIKI))
        if 'user' in req.args:
          user = req.args['user']
          data['username'] = user
          data['user'] = UserInfo.getuserinfo(self.env, user)
          data['users'] = []
          data['stats'] = None
        else:
          data['username'] = None
          data['user'] = []
          users, stats = UserInfo.getinfo(self.env, mode, minwiki)
          data['users'] = users
          data['stats'] = stats
        data['quote'] = quote
        if mode == 'overview':
            data['usertype'] = _('data overview')
        elif mode == 'unused':
            data['usertype'] = _('unused accounts')
        elif mode == 'authorized':
            data['usertype'] = _('registered accounts')
        elif mode == 'user':
            data['usertype'] = _("detailed user information for '%s'") % data['username']
        else:
            data['usertype'] = _('everything from accounts, wiki, tickets and svn')
        data['entrytext'] = ngettext('%(num)d entry', '%(num)d entries', (stats['numtotal'] if mode=='overview' else len(data['users'])))

        add_stylesheet(req, 'spamfilter/admin.css')
        return 'admin_user.html', data
