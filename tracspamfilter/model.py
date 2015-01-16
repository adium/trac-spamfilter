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

import binascii

from datetime import datetime, timedelta
from time import mktime,time

import xml.etree.ElementTree as ElementTree

from trac.db import Column, Index, Table
from trac.util.text import to_unicode

from tracspamfilter.api import gettext, _, get_strategy_name

__all__ = ['LogEntry']


class LogEntry(object):

    table = Table('spamfilter_log', key='id')[
        Column('id', auto_increment=True),
        Column('time', type='int'),
        Column('path'),
        Column('author'),
        Column('authenticated', type='int'),
        Column('ipnr'),
        Column('headers'),
        Column('content'),
        Column('rejected', type='int'),
        Column('karma', type='int'),
        Column('reasons'),
        Column('request')
    ]

    def __init__(self, env, time, path, author, authenticated, ipnr, headers,
                 content, rejected, karma, reasons, request):
        self.id = None
        self.env = env
        self.time = time
        self.path = path
        self.author = to_unicode(author)
        self.authenticated = bool(authenticated)
        self.ipnr = ipnr
        self.headers = to_unicode(headers) or ''
        self.content = content
        self.rejected = bool(rejected)
        self.karma = karma
        self.reasons = reasons
        self.request = request

    def __repr__(self):
        date = datetime.fromtimestamp(self.time).isoformat()
        return '<%s %s from %s by "%s">' % (self.__class__.__name__, self.id,
                                            date, self.author)

    exists = property(fget=lambda self: self.id is not None,
                      doc='Whether this log entry exists in the database')

    def _encode_content(cls, content):
        """Take a `basestring` content and return a plain text encoding."""
        return to_unicode(content).encode('utf-8').encode('base64')

    _encode_content = classmethod(_encode_content)

    def _decode_content(cls, content):
        """Revert the encoding done by `_encode_content` and return an unicode
        string"""
        try:
            return to_unicode(content.decode('base64'))
        except (UnicodeEncodeError, binascii.Error):
            # cope with legacy content (stored before base64 encoding)
            return to_unicode(content)

    _decode_content = classmethod(_decode_content)

    def get_next(self):
        """Return the next log entry in reverse chronological order (i.e. the
        next older entry.)"""
        for row in self.env.db_query("""
            SELECT id,time,path,author,authenticated,ipnr,headers,
                   content,rejected,karma,reasons,request
            FROM spamfilter_log 
            WHERE id<%s ORDER BY id DESC LIMIT 1
            """, (self.id,)):
            return self.__class__._from_db(self.env, row)

    def get_previous(self):
        """Return the previous log entry in reverse chronological order
        (i.e. the next younger entry.)"""
        for row in self.env.db_query("""
            SELECT id,time,path,author,authenticated,ipnr,headers,
                   content,rejected,karma,reasons,request 
            FROM spamfilter_log 
            WHERE id>%s ORDER BY id LIMIT 1
            """, (self.id,)):
            return self.__class__._from_db(self.env, row)

    def insert(self):
        """Insert a new log entry into the database."""
        assert not self.exists, 'Cannot insert existing log entry'

        content = self._encode_content(self.content)
        with self.env.db_transaction as db:
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO spamfilter_log 
                    (time,path,author,authenticated,ipnr,headers,content,rejected,
                     karma,reasons,request)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                """, (int(self.time), self.path, self.author,
                      int(bool(self.authenticated)), self.ipnr, self.headers,
                      content, int(bool(self.rejected)), int(self.karma),
                      self._reasons_to_xml(self.reasons),
                      self._request_to_xml(self.request)))
            self.id = db.get_last_id(cursor, 'spamfilter_log')

    def update(self, **kwargs):
        """Update the log entry in the database."""
        assert self.exists, 'Cannot update a non-existing log entry'

        for name, value in kwargs.items():
            if hasattr(self, name):
                setattr(self, name, value)

        content = self._encode_content(self.content)
        self.env.db_transaction("""
            UPDATE spamfilter_log 
            SET time=%s,path=%s,author=%s,
                authenticated=%s,ipnr=%s,headers=%s,content=%s,
                rejected=%s,karma=%s,reasons=%s, request=%s
            WHERE id=%s
            """, (int(self.time), self.path, self.author,
                  int(bool(self.authenticated)), self.ipnr, self.headers,
                  content, int(bool(self.rejected)), int(self.karma),
                  self._reasons_to_xml(self.reasons),
                  self._request_to_xml(self.request), self.id))

    def delete(cls, env, id):
        """Delete the log entry with the specified ID from the database."""
        if isinstance(id, list):
            env.db_transaction(
                "DELETE FROM spamfilter_log WHERE id IN (%s)"
                % ",".join("'%s'" % each for each in id))
        else:
            env.db_transaction(
                "DELETE FROM spamfilter_log WHERE id=%s", (id,))

    delete = classmethod(delete)

    def getobvious(cls, env):
        """Delete the obvious log entries from the database."""
        ids = []
        for id, reasons in env.db_query("""
            SELECT id,reasons
            FROM spamfilter_log
            WHERE authenticated=0 AND rejected=1
            """):
            for r in cls._xml_to_reasons(reasons):
                if r[0] == "Bayesian" and float(r[3]) > 90:
                    ids.append(id)
        return ids

    getobvious = classmethod(getobvious)

    def fetch(cls, env, id):
        """Retrieve an existing log entry from the database by ID."""
        for row in env.db_query("""
            SELECT id,time,path,author,authenticated,ipnr,headers,
                   content,rejected,karma,reasons,request 
            FROM spamfilter_log 
            WHERE id=%s
            """, (int(id),)):
            return cls._from_db(env, row)

    fetch = classmethod(fetch)

    def count(cls, env):
        """Return the number of log entries in the database."""
        for count, in env.db_query(
            "SELECT COUNT(*) FROM spamfilter_log "):
            return count

    count = classmethod(count)

    def purge(cls, env, days):
        """Delete log entries older than the specified number of days."""
        threshold = datetime.now() - timedelta(days=days)
        env.db_transaction(
            "DELETE FROM spamfilter_log WHERE time < %s",
            (mktime(threshold.timetuple()),))

    purge = classmethod(purge)

    def select(cls, env, ipnr=None, limit=None, offset=0):
        """Retrieve existing log entries from the database that match the
        specified criteria.
        """
        params = []
        where_clauses = []
        if ipnr:
            where_clauses.append("ipnr=%s")
            params.append(ipnr)

        if where_clauses:
            where = "WHERE %s" % " AND ".join(where_clauses)
        else:
            where = ""

        return cls._doselect(env, where, limit, offset, params)

    select = classmethod(select)

    def selectrelated(cls, env, page, limit=None, offset=0):
        """Retrieve page related log entries"""
        # strip additional appended values
        p = page.split("#")
        params = [p[0]]
        where_clauses = ["path = %s"]

        if page.startswith('/ticket/'):
            if len(p) == 2: # if we have time, use it
                time = p[1]
            else: # otherwise hope ticket is not yet deleted
                time = None
                for t, in env.db_query("SELECT time/1000000 from ticket WHERE id=%s", (page[8:],)):
                    time = t
            if time:
                where_clauses.append("(path = '/newticket' AND time BETWEEN %s AND %s)")
                params.append(time-30);
                params.append(time+30);

        where = "WHERE %s" % " OR ".join(where_clauses)
        return cls._doselect(env, where, limit, offset, params)

    selectrelated = classmethod(selectrelated)

    def _doselect(cls, env, where, limit, offset, params):
        extra_clauses = []

        if limit:
            extra_clauses.append("LIMIT %s")
            params.append(limit)
            if offset:
                extra_clauses.append("OFFSET %s")
                params.append(offset)
        if extra_clauses:
            extra = " ".join(extra_clauses)
        else:
            extra = ""

        for row in env.db_query("""
            SELECT id,time,path,author,authenticated,ipnr,headers,
                   content,rejected,karma,reasons,request
            FROM spamfilter_log 
            %s 
            ORDER BY time DESC %s
            """ % (where, extra), params):
            yield cls._from_db(env, row)

    _doselect = classmethod(_doselect)

    def _from_db(cls, env, row):
        """Create a new LogEntry from a row from the `spamfilter_log` table."""
        fields = list(row[1:])
        fields[6] = cls._decode_content(fields[6])
        fields[9] = cls._xml_to_reasons(fields[9])
        fields[10] = cls._xml_to_request(fields[10])
        obj = cls(env, *fields)
        obj.id = row[0]
        return obj

    _from_db = classmethod(_from_db)

    def _reasons_to_xml(self, reasons):
        root = ElementTree.Element("entries")
        for r in reasons:
            e = ElementTree.SubElement(root, "e", name = r[0], points = r[1], text = r[2])
            for a in r[3:]:
                 ElementTree.SubElement(e, "v", value=a)
        return ElementTree.tostring(root)

    def _request_to_xml(self, request):
        if request == None:
            return None
        try:
            root = ElementTree.Element("request", target=request[0])
            for key, value in request[1].iteritems():
	        ElementTree.SubElement(root, "arg", key = key).text = value
            return ElementTree.tostring(root)
        except:
            return None

    def _xml_to_reasons(self, xml):
        reasons = []
        root = ElementTree.fromstring(xml)
        for r in list(root):
            reasons.append([r.attrib.get("name"), r.attrib.get("points"), r.attrib.get("text")] +
                   [a.attrib.get("value") for a in list(r)])
        return reasons

    _xml_to_reasons = classmethod(_xml_to_reasons)

    def _xml_to_request(self, xml):
        if xml == None:
            return None
        try:
            root = ElementTree.fromstring(xml)
            request = [root.attrib.get("target"), {}]
            for r in list(root):
                request[1][r.attrib.get("key")] = r.text or ""
            return request
        except:
            return None

    _xml_to_request = classmethod(_xml_to_request)

    def getreasons(self):
        reasons = []
        for r in self.reasons:
            if len(r) == 3:
                reasons.append("%s (%s): %s" % (r[0], r[1], gettext(r[2])))
            else:
                reasons.append("%s (%s): %s" % (r[0], r[1], gettext(r[2]) % tuple(r[3:])))
        return reasons

    def findreasonvalue(self, name):
        for r in self.reasons:
            if r[0] == name:
                try:
                    return int(r[1])
                except:
                    return 0
        return 0

class Bayes(object):

    table = Table('spamfilter_bayes', key='word')[
        Column('word'),
        Column('nspam', type='int'),
        Column('nham', type='int'),
        Index(['word'])
    ]

class Statistics(object):

    table = Table('spamfilter_statistics', key=['strategy', 'action', 'data', 'status'])[
        Column('strategy'),
        Column('action'),
        Column('data'),
        Column('status'),
        Column('delay', type='double precision'),
        Column('delay_max', type='double precision'),
        Column('delay_min', type='double precision'),
        Column('count', type='int'),
        Column('external', type='int'),
        Column('time', type='int')
    ]

    def __init__(self, env):
       self.env = env

    def insert_or_update(self, strategy, action, data, status, delay, external):
        with self.env.db_transaction as db:
            row = db("SELECT delay,delay_max,delay_min,count FROM "
                "spamfilter_statistics WHERE action=%s "
                "AND data=%s AND status=%s AND strategy=%s",
                (action, data, status, strategy))
            if row:
                count = float(row[0][3])
                delay_val = float(row[0][0])*(count/(count+1.0))+delay/(count+1.0)
                delay_max = float(row[0][1])
                if delay > delay_max:
                    delay_max = delay
                delay_min = float(row[0][2])
                if delay < delay_min:
                    delay_min = delay
                count = int(row[0][3])+1
                db("UPDATE spamfilter_statistics SET delay=%s,delay_max=%s,"
                    "delay_min=%s,count=%s WHERE action=%s AND data=%s AND "
                    "status=%s AND strategy=%s", (delay_val, delay_max,
                    delay_min, count, action, data, status, strategy))
            else:
                db("INSERT INTO spamfilter_statistics VALUES (%s, %s, %s, %s, "
                    "%s, %s, %s, 1, %s, %s)", (strategy, action, data, status, delay,
                    delay, delay, external, int(time())))
        self.env.log.debug("SPAMLOG: %s %s %s %s %.3f %s" % (action, data,
            status, strategy, delay, "external" if external else "local"))

    def clean(self, strategy):
        self.env.db_transaction(
            "DELETE FROM spamfilter_statistics WHERE strategy=%s", (strategy,))

    def cleanall(self):
        self.env.db_transaction("DELETE FROM spamfilter_statistics")

    def getstats(self):
        strategies = {}
        overall = {}
        overall['test'] = 0
        overall['time'] = 0
        overall['testspam'] = 0
        overall['testham'] = 0
        overall['testint'] = 0
        overall['testext'] = 0
        overall['testinttime'] = 0 
        overall['testexttime'] = 0 
        for strategy,action,data,status,delay,delay_max,delay_min,count,external,time in \
                self.env.db_query("SELECT * FROM spamfilter_statistics"):
           if strategy:
               str = strategies.get(strategy, {})
               str['type'] = "external" if external else "internal"
               str['i18type'] = _("external") if external else _("internal")
               if action == 'test':
                   if data == 'empty':
                       str['testempty'] = count
                   elif data == 'ham' or data == 'spam':
                       str['test%s%s' % (data,status)] = count
                   lasttotal = str.get('testtotal', 0)
                   str['testtotal'] = count + lasttotal
                   if lasttotal:
                       l = float(lasttotal)
                       c = float(count)
                       s = l+c
                       str['testtime'] = str['testtime']*(l/s)+float(delay)*(c/s)
                   else:
                       str['testtime'] = float(delay)
               elif action.startswith('train') or action == 'delete':
                   if status:
                       key = 'train%s%s' % (data,status)
                       str[key] = count + str.get(key, 0)
                       key = 'train%stotal' % data
                       str[key] = count + str.get(key, 0)
                       str['traintotal'] = count + str.get('traintotal', 0)
                   if action == 'trainerror' or action == 'traincond':
                       str['trainerror'] = count + str.get('trainerror', 0)
               strategies[strategy] = str
           else:
               if not overall['time'] or time < overall['time']:
                   overall['time'] = time
               if action == 'testint' or action == 'testext':
                   overall[action] += count
                   overall["%stime" % action] = delay
                   overall['test'] += count
                   if data == 'spam':
                       overall['testspam'] += count
                   else:
                       overall['testham'] += count
        return strategies,overall

    def sortbyperformance(self, entries):
        strategies = {}
        for strategy,action,data,status,delay,count in self.env.db_query("""
            SELECT strategy,action,data,status,delay,count 
            FROM spamfilter_statistics
            WHERE external=1 AND strategy != ''
            """):
            str = strategies.get(strategy, {'count': 0, 'delay': 0, 'ham': False,
                'err': 0, 'empty': 0, 'testcount': 0})
            if action == 'delete' or action.startswith('train'):
                if status == 'error':
                    str['err'] += count
                if status:
                    str['count'] += count
            elif action == 'test':
                if delay > str['delay']:
                    str['delay'] = delay
                if data == 'empty':
                    str['empty'] += count
                elif data == 'ham':
                    str['ham'] =  True
                str['testcount'] += count
            strategies[strategy] = str
        for strategy,str in strategies.iteritems():
            # 10% if ham is reported
            c = 10 if str['ham'] else 0
            # 40% if fast
            s = 40-int(str['delay']*20)
            c += s if s > 0 else 0
            # 25% if low error rate
            if str['count']:
                e = 25-int(1000.0*str['err']/str['count'])
            else:
                e = 15
            c += e if e > 0 else 0
            # 25% if high answer rate
            if str['testcount']:
                a = 25-int(25.0*str['empty']/str['testcount'])
            else:
                a = 15
            c += a if a > 0 else 0
            strategies[strategy] = c
        def mysort(val):
            return strategies.get(get_strategy_name(val), 0)
        entries = sorted(entries, key=mysort, reverse=True)
        return entries

class SpamReport(object):
    table = Table('spamfilter_report', key=['id'])[
        Column('id', auto_increment=True),
        Column('entry'),
        Column('headers'),
        Column('author'),
        Column('authenticated', type='int'),
        Column('comment'),
        Column('time', type='int')
    ]

schema = [Bayes.table, LogEntry.table, Statistics.table, SpamReport.table]
schema_version = 4
