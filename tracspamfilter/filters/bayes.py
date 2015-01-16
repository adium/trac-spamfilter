# -*- coding: utf-8 -*-
#
# Copyright (C) 2005-2006 Edgewall Software
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2006 Christopher Lenz <cmlenz@gmx.de>
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
# Author: Matthew Good <trac@matt-good.net>

from math import ceil
import re
from pkg_resources import parse_version

from trac import __version__ as VERSION
from trac.config import IntOption
from trac.core import *
from trac.db import DatabaseManager
from trac.wiki.api import IWikiChangeListener
from trac.wiki.model import WikiPage
from tracspamfilter.api import IFilterStrategy, N_

from spambayes.hammie import Hammie
from spambayes.storage import SQLClassifier


class BayesianFilterStrategy(Component):
    """Bayesian filtering strategy based on SpamBayes."""

    implements(IFilterStrategy)

    karma_points = IntOption('spam-filter', 'bayes_karma', '15',
        """By what factor Bayesian spam probability score affects the overall
        karma of a submission.""", doc_domain = "tracspamfilter")

    min_training = IntOption('spam-filter', 'bayes_min_training', '25',
        """The minimum number of submissions in the training database required
        for the filter to start impacting the karma of submissions.""",
        doc_domain = "tracspamfilter")

    # IFilterStrategy implementation

    def is_external(self):
        return False

    def test(self, req, author, content, ip):
        hammie = self._get_hammie()
        nspam = hammie.bayes.nspam
        nham = hammie.bayes.nham
        if author != None:
            testcontent = author+"\n"+content
        else:
            testcontent = content

        if min(nspam, nham) < self.min_training:
            self.log.info('Bayes filter strategy requires more training. '
                          'It currently has only %d words marked as ham, and '
                          '%d marked as spam, but requires at least %d for '
                          'each.', nham, nspam, self.min_training)
            return

        if nham - nspam > min(nham, nspam) * 2:
            self.log.warn('The difference between the number of ham versus '
                          'spam submissions in the training database is large, '
                          'results may be bad.')

        score = hammie.score(testcontent.encode('utf-8'))
        self.log.debug('SpamBayes reported spam probability of %s', score)
        points = -int(round(self.karma_points * (score * 2 - 1)))
        if points != 0:
            return points, N_('SpamBayes determined spam probability of %s%%'), \
                           ("%3.2f" % (score * 100))

    def train(self, req, author, content, ip, spam=True):
        if author != None:
            testcontent = author+"\n"+content
        else:
            testcontent = content
        self.log.info('Training SpamBayes, marking content as %s',
                      spam and 'spam' or 'ham')

        hammie = self._get_hammie()
        hammie.train(testcontent.encode('utf-8','ignore'), spam)
        hammie.store()
        return 1

    # Internal methods

    def _get_hammie(self):
        try: # 1.0
            return Hammie(TracDbClassifier(self.env, self.log))
        except TypeError, e: # 1.1
            return Hammie(TracDbClassifier(self.env, self.log), 'c')

    def _get_numbers(self):
        hammie = self._get_hammie()
        return hammie.nspam, hammie.nham


class TracDbClassifier(SQLClassifier):
    # FIXME: This thing is incredibly slow

    def __init__(self, env_db, log):
        self.env_db = env_db
        self.log = log
        SQLClassifier.__init__(self, 'Trac')

    def load(self):
        if self._has_key(self.statekey):
            row = self._get_row(self.statekey)
            self.nspam = row['nspam']
            self.nham = row['nham']
        else: # new database
            self.nspam = self.nham = 0

    def _sanitize(self, text):
        if isinstance(text, unicode):
            return text
        """Remove invalid byte sequences from utf-8 encoded text"""
        return text.decode('utf-8', 'ignore')

    def _get_row(self, word):
        word = self._sanitize(word)
        for row in self.env_db.db_query(
            "SELECT nspam,nham FROM spamfilter_bayes WHERE word=%s",
            (word,)):
            break
        else:
            return {}
        # prevent assertion - happens when there are failures in training and
        # the count is not updated due to an exception
        if word != self.statekey:
            if row[0] > self.nspam:
                self.log.warn('Reset SPAM count from %d to %d due to keyword \'%s\'.',
                              self.nspam, row[0], word)
                self.nspam = row[0]
                self.store()
            if row[1] > self.nham:
                self.log.warn('Reset HAM count from %d to %d due to keyword \'%s\'.',
                              self.nham, row[1], word)
                self.nham = row[1]
                self.store()
        return {'nspam': row[0], 'nham': row[1]}

    def _set_row(self, word, nspam, nham):
        word = self._sanitize(word)
        with self.env_db.db_transaction as db:
            if self._has_key(word):
                db("UPDATE spamfilter_bayes SET nspam=%s,nham=%s "
                   "WHERE word=%s", (nspam, nham, word))
            else:
                db("INSERT INTO spamfilter_bayes (word,nspam,nham) "
                   "VALUES (%s,%s,%s)", (word, nspam, nham))

    def _delete_row(self, word):
        word = self._sanitize(word)
        self.env_db.db_transaction(
            "DELETE FROM spamfilter_bayes WHERE word=%s", (word,))

    def _has_key(self, key):
        key = self._sanitize(key)
        for count, in self.env_db.db_query(
            "SELECT COUNT(*) FROM spamfilter_bayes WHERE word=%s",
            (key,)):
            return bool(count)

    def _wordinfoget(self, word):
        row = self._get_row(word)
        if row:
            item = self.WordInfoClass()
            item.__setstate__((row["nspam"], row["nham"]))
            return item

    def _wordinfokeys(self):
        words = []
        for word, in self.env_db.db_query("SELECT word FROM spamfilter_bayes"):
            words.append(word)
        return words
