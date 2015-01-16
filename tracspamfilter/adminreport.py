# -*- coding: utf-8 -*-
#
# Copyright (C) 2014 Edgewall Software
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

from trac.admin import IAdminPanelProvider
from trac.config import IntOption
from trac.core import Component, implements
from trac.web.chrome import add_link, add_stylesheet, add_script, add_script_data
from tracspamfilter.api import _
from tracspamfilter.model import LogEntry

class ReportAdminPageProvider(Component):
    """Web administration panel for reviewing Spam reports"""

    implements(IAdminPanelProvider)

    MAX_PER_PAGE = 10000
    MIN_PER_PAGE = 5
    DEF_PER_PAGE =  IntOption('spam-filter', 'spam_report_entries', '100',
    "How many report entries are displayed by default (between 5 and 10000).",
    doc_domain='tracspamfilter')

    # IAdminPanelProvider methods

    def get_admin_panels(self, req):
        if req.perm.has_permission('SPAM_CHECKREPORTS'):
            total = self.env.db_query("SELECT COUNT(*) FROM spamfilter_report")
            total = total[0][0]

            yield ('spamfilter', _("Spam Filtering"), 'report', _("Reports") \
                + (" (%s)"%total if total else ""))

    def render_admin_panel(self, req, cat, page, path_info):
        req.perm.assert_permission('SPAM_CHECKREPORTS')
        if req.method == 'POST' and 'delete' in req.args:
            entries = req.args.getlist('sel')
            if entries:
                self.env.db_transaction("""
                    DELETE FROM spamfilter_report WHERE id IN (%s)
                    """ % ",".join("'%s'" % each for each in entries))
            req.redirect(req.href.admin(cat, page,
                                        page=req.args.get('page'),
                                        num=req.args.get('num')))
        if path_info:
            data = self._render_entry(req, cat, page, path_info)
            page = 'entry'
            data['allowselect'] = False
            data['entries'] = LogEntry.selectrelated(self.env, data['path'], data['time'])
        else:
            data = self._render_panel(req, cat, page)
            page = ''

        add_stylesheet(req, 'spamfilter/admin.css')
        data['_'] = _
        return 'admin_report%s.html' % page, data

    # Internal methods

    def _render_panel(self, req, cat, page):
        try:
            pagenum = int(req.args.get('page', 1)) - 1
        except ValueError:
            pagenum = 1

        try:
            pagesize = int(req.args.get('num', self.DEF_PER_PAGE))
        except ValueError:
            pagesize = self.DEF_PER_PAGE
        if pagesize < self.MIN_PER_PAGE:
            pagesize = self.MIN_PER_PAGE
        elif pagesize > self.MAX_PER_PAGE:
            pagesize = self.MAX_PER_PAGE

        total = self.env.db_query("SELECT COUNT(*) FROM spamfilter_report")
        total = total[0][0]

        if total < pagesize:
            pagenum = 0
        elif total <= pagenum * pagesize:
            pagenum = (total-1)/pagesize

        offset = pagenum * pagesize
        entries = []
        idx = 0;
        for e in self.env.db_query("""
            SELECT id,time,entry,author,authenticated,comment
            FROM spamfilter_report
            ORDER BY time DESC LIMIT %s OFFSET %s""", (pagesize, offset)):
            # don't display additional appended values
            p = e[2].split("#")
            entries.append(('odd' if idx %2 else 'even',)+e[0:2]+(p[0],)+e[3:])
            idx += 1;

        if pagenum > 0:
            add_link(req, 'prev', req.href.admin(cat, page, page=pagenum,
                                                 num=pagesize),
                     _('Previous Page'))
        if offset + pagesize < total:
            add_link(req, 'next', req.href.admin(cat, page, page=pagenum+2,
                                                 num=pagesize),
                     _('Next Page'))

        if entries:
            add_script_data(req, {'toggleform': "spamreportform"})
            add_script(req, 'spamfilter/toggle.js')
        return {
            'entries': entries,
            'offset': offset + 1,
            'page': pagenum + 1,
            'num': pagesize,
            'total': total
        }

    def _render_entry(self, req, cat, page, entry_id):
        with self.env.db_query as db:
            entry = db("""
                SELECT time,entry,author,authenticated,headers,comment
                FROM spamfilter_report
                WHERE id = %s""", (entry_id,))
            if not entry:
                raise HTTPNotFound(_('Report entry not found'))
            entry = entry[0]

            for previous, in db("""
                SELECT id
                FROM spamfilter_report
                WHERE id<%s ORDER BY id DESC LIMIT 1""", (entry_id,)):
                add_link(req, 'prev', req.href.admin(cat, page, previous),
                         _('Report Entry %d') % previous)
            add_link(req, 'up', req.href.admin(cat, page), _('Report Entry List'))
            for next, in db("""
                SELECT id
                FROM spamfilter_report
                WHERE id>%s ORDER BY id DESC LIMIT 1""", (entry_id,)):
                add_link(req, 'next', req.href.admin(cat, page, next),
                         _('Report Entry %d') % next)

            # don't display additional appended values
            path = entry[1].split("#")
            return {'time': entry[0],
                    'monitor': req.perm.has_permission('SPAM_MONITOR'),
                    'id': entry_id,
                    'path': path[0],
                    'author': entry[2],
                    'authenticated': entry[3],
                    'headers': entry[4],
                    'comment': entry[5]}
