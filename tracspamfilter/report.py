# -*- coding: utf-8 -*-
#
# Copyright (C) 2024 Edgewall Software
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

from time import time

from genshi.builder import tag

from trac.config import ListOption
from trac.core import Component, implements
from trac.web import IRequestFilter, IRequestHandler
from trac.web.chrome import add_ctxtnav, add_notice, add_script, add_script_data

from tracspamfilter.api import _, ngettext

class SpamReportAdapter(Component):
    """Interface to allow users to report spam."""

    checkreq = ListOption('spam-filter', 'report_pages',
                                 'wiki, attachment, ticket', doc=
        """List of page types to add spam report link""", 
        doc_domain="tracspamfilter")

    implements(IRequestFilter, IRequestHandler)

    def match_request(self, req):
        return req.path_info == '/reportspam'

    def process_request(self, req):
        if not 'SPAM_REPORT' in req.perm:
            raise Exception(_("Missing permissions to report spam"))
        if not 'page' in req.args:
            raise Exception(_("No page supplied to report as spam"))
        page = req.args['page']
        savepage = page
        isauth = 1 if req.authname and req.authname != 'anonymous' else 0
        headers = '\n'.join(['%s: %s' % (k[5:].replace('_', '-').title(), v)
                             for k, v in req.environ.items()
                             if k.startswith('HTTP_')])
        if page.startswith("/ticket/"):
            for tim, in self.env.db_query("SELECT time/1000000 from ticket WHERE id=%s", (page[8:],)):
                # append creation time, so spam log entries can be seen after deleting ticket
                savepage = "%s#%d" % (page, tim)
        self.env.db_transaction("""
            INSERT INTO spamfilter_report
                (entry, headers, author, authenticated, comment, time)
                VALUES (%s,%s,%s,%s,%s,%s)""",
            (savepage, headers, req.authname, isauth, req.args.get('comment', None), int(time())))
        req.redirect(req.href(page))

    def pre_process_request(self, req, handler):
        return handler

    def post_process_request(self, req, template, data, content_type):
        if 'SPAM_REPORT' in req.perm:
            i = req.path_info.find("/", 1)
            if (req.path_info[1:i] if i > 0 else req.path_info[1:]) in self.checkreq:
                isauth = 1 if req.authname and req.authname != 'anonymous' else 0
                if self.env.db_query("""
                    SELECT id FROM spamfilter_report
                       WHERE entry = %s
                          AND author = %s
                          AND authenticated = %s""",
                                     (req.path_info, req.authname, isauth)):
                    add_ctxtnav(req, _('Reported spam'))
                else:
                    add_script_data(req, {'spamreport_comment': _("Comment")})
                    add_script(req, 'spamfilter/reportspam.js')
                    add_ctxtnav(req, tag.a(_('Report spam'), id='reportspam', href=req.href('reportspam', (('page', req.path_info),))))
        if 'SPAM_CHECKREPORTS' in req.perm:
            for total, in self.env.db_query("SELECT COUNT(*) FROM spamfilter_report"):
                if total:
                    add_notice(req, tag.a(ngettext('%(num)d spam report', '%(num)d spam reports', total),
                    href=req.href.admin("spamfilter/report")))
            
        return template, data, content_type
