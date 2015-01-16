# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2011 Edgewall Software
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2006 Christopher Lenz <cmlenz@gmx.de>
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
# Author: Dirk Stöcker <trac@dstoecker.de>,
#         Matthew Good <trac@matt-good.net>

import re

from trac.config import IntOption, Option, BoolOption
from trac.core import *
from trac.wiki.api import IWikiChangeListener
from trac.wiki.model import WikiPage
from tracspamfilter.api import IFilterStrategy, N_

class IPRegexFilterStrategy(Component):
    """Spam filter for submitter's IP based on regular expressions
    defined in BadIP page.
    """
    implements(IFilterStrategy, IWikiChangeListener)

    karma_points = IntOption('spam-filter', 'ipregex_karma', '20',
        """By how many points a match with a pattern on the BadIP page
        impacts the overall karma of a submission.""", doc_domain="tracspamfilter")
    badcontent_file = Option('spam-filter', 'ipbadcontent_file', '',
        """Local file to be loaded to get BadIP. Can be used in
        addition to BadIP wiki page.""", doc_domain="tracspamfilter")
    show_blacklisted = BoolOption('spam-filter', 'show_blacklisted_ip', 'true',
        """Show the matched bad IP patterns in rejection message.""", doc_domain="tracspamfilter")

    def __init__(self):
        self.patterns = []
        page = WikiPage(self.env, 'BadIP')
        if page.exists:
            self._load_patterns(page)
        if self.badcontent_file != '':
            file = open(self.badcontent_file,"r")
            if file == None:
                self.log.warning('BadIP file cannot be opened')
            else:
                lines = file.read().splitlines()
                pat = [re.compile(p.strip()) for p in lines if p.strip()]
                self.log.debug('Loaded %s patterns from BadIP file', len(pat))
                self.patterns += pat

    # IFilterStrategy implementation

    def is_external(self):
        return False

    def test(self, req, author, content, ip):
        gotcha = []
        points = 0
        for pattern in self.patterns:
            match = pattern.search(ip)
            if match:
                gotcha.append("'%s'" % pattern.pattern)
                self.log.debug('Pattern %s found in submission',
                               pattern.pattern)
                points -= abs(self.karma_points)
        if points != 0:
            if self.show_blacklisted:
                matches = ", ".join(gotcha)
                return points, N_('IP catched by these blacklisted patterns: %s'), matches
            else:
                return points, N_('IP catched by %s blacklisted patterns'), str(len(gotcha))

    def train(self, req, author, content, ip, spam=True):
        return 0

    # IWikiChangeListener implementation

    def wiki_page_changed(self, page, *args):
        if page.name == 'BadIP':
            self._load_patterns(page)
    wiki_page_added = wiki_page_changed
    wiki_page_version_deleted = wiki_page_changed

    def wiki_page_deleted(self, page):
        if page.name == 'BadIP':
            self.patterns = []

    # Internal methods

    def _load_patterns(self, page):
        if '{{{' in page.text and '}}}' in page.text:
            lines = page.text.split('{{{', 1)[1].split('}}}', 1)[0].splitlines()
            self.patterns = [re.compile(p.strip()) for p in lines if p.strip()]
            self.log.debug('Loaded %s patterns from BadIP',
                           len(self.patterns))
        else:
            self.log.warning('BadIP page does not contain any patterns')
            self.patterns = []
