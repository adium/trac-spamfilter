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

from StringIO import StringIO

from trac.attachment import IAttachmentManipulator
from trac.core import *
from trac.config import IntOption
from trac.mimeview import is_binary
from trac.ticket import ITicketManipulator, TicketSystem
from trac.util.text import to_unicode
from trac.wiki import WikiPage, IWikiPageManipulator
from tracspamfilter.filtersystem import FilterSystem

class TicketFilterAdapter(Component):
    """Interface to check ticket changes for spam.
    """
    implements(ITicketManipulator)

    # ITicketManipulator methods

    def prepare_ticket(self, req, ticket, fields, actions):
        pass

    def validate_ticket(self, req, ticket):
        if req.perm.has_permission('TICKET_ADMIN'):
            # An administrator is allowed to spam
            return []

        if 'preview' in req.args:
            # Only a preview, no need to filter the submission yet
            return []

        changes = []

        # Add the author/reporter name
        if req.authname and req.authname != 'anonymous':
            author = req.authname
        elif not ticket.exists:
            author = ticket['reporter']
        else:
            author = req.args.get('author', req.authname)

        # Add any modified text fields of the ticket
        fields = [f['name'] for f in
                  TicketSystem(self.env).get_ticket_fields()
                  if f['type'] in ('textarea', 'text')]
        for field in fields:
            if field in ticket._old:
                changes.append((ticket._old[field], ticket[field]))

        if 'comment' in req.args:
            changes.append((None, req.args.get('comment')))

        FilterSystem(self.env).test(req, author, changes)
        return []

class WikiFilterAdapter(Component):
    """Interface to check wiki changes for spam.
    """
    implements(IWikiPageManipulator)

    # IWikiPageManipulator methods

    def prepare_wiki_page(self, req, page, fields):
        pass

    def validate_wiki_page(self, req, page):
        if req.perm.has_permission('WIKI_ADMIN'):
            # An administrator is allowed to spam
            return []

        if 'preview' in req.args:
            # Only a preview, no need to filter the submission yet
            return []

        old_text = page.old_text
        text = page.text
        author = req.args.get('author', req.authname)
        comment = req.args.get('comment')

        # Test the actual page changes as well as the comment
        changes = [(old_text, text)]
        if comment:
            changes += [(None, comment)]

        FilterSystem(self.env).test(req, author, changes)
        return []


class AttachmentFilterAdapter(Component):
    """Interface to check attachment uploads for spam.
    """
    implements(IAttachmentManipulator)

    sample_size = IntOption('spam-filter', 'attachment_sample_size', 16384,
        """The maximum number of bytes from an attachment to pass through
        the spam filters.""", doc_domain='tracspamfilter')

    # ITicketManipulator methods

    def prepare_attachment(self, req, attachment, fields):
        pass

    def validate_attachment(self, req, attachment):
        if req.perm.has_permission('WIKI_ADMIN'):
            # An administrator is allowed to spam
            return []

        author = req.args.get('author', req.authname)
        description = req.args.get('description')

        filename = None
        upload = req.args.get('attachment')
        content = ''
        if upload is not None:
            try:
                data = upload.file.read(self.sample_size)
                if not is_binary(data):
                    content = to_unicode(data)
            finally:
                upload.file.seek(0)
            filename = upload.filename

        changes = []
        for field in filter(None, [description, filename, content]):
            changes += [(None, field)]

        FilterSystem(self.env).test(req, author, changes)
        return []
