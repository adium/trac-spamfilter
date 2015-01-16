# -*- coding: utf-8 -*-
#
# Copyright (C) 2013 Dirk Stöcker
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

import re
from tracspamfilter.api import _
try:
    from acct_mgr.api import AccountManager
except ImportError: # not installed
    AccountManager = None

__all__ = ['UserInfo']

class UserInfo(object):

    @staticmethod
    def gettemporary(env):
        anons = []
        for sid, in env.db_query("SELECT sid FROM session WHERE authenticated = 0"):
            anons.append(sid)
        return anons

    @staticmethod
    def getuserinfo(env, username):
        data = []

        for time,page,version in env.db_query("SELECT time,name,version FROM wiki WHERE author=%s", (username,)):
            data.append((time, "/wiki/%s?version=%s" % (page,version), _("Wiki page '%(page)s' version %(version)s modified", page=page, version=version)))

        for filename,time,page,type in env.db_query("SELECT filename,time,id,type FROM attachment WHERE author=%s", (username,)):
            data.append((time, "/%s/%s#no1" % (type, page), _("Attachment '%s' added") % filename))

        for author,time,field,oldvalue,newvalue,ticket in env.db_query("SELECT author,time,field,oldvalue,newvalue,ticket FROM ticket_change"):
            if author == username:
                data.append((time, "/ticket/%s" % ticket, _("Ticket %(id)s field '%(field)s' changed", id=ticket, field=field)))
            if field == "reporter" or field == "owner":
                if oldvalue == username:
                    data.append((time, "/ticket/%s" % ticket, _("Removed from ticket %(id)s field '%(field)s' ('%(old)s' --> '%(new)s')", id=ticket, field=field, old=oldvalue, new=newvalue)))
                if newvalue == username:
                    data.append((time, "/ticket/%s" % ticket, _("Set in ticket %(id)s field '%(field)s' ('%(old)s' --> '%(new)s')", id=ticket, field=field, old=oldvalue, new=newvalue)))
            elif field == 'cc':
                authors = []
                for val in [oldvalue, newvalue]:
                    authors += UserInfo.splitcc(env, val, ticket)
                if username in authors:
                    data.append((time, "/ticket/%s" % ticket, _("Ticket %(id)s CC field change ('%(old)s' --> '%(new)s')", id=ticket, old=oldvalue, new=newvalue)))
        
        for time, reporter, owner, cc, id in env.db_query("SELECT time,reporter,owner,cc,id FROM ticket"):
            if reporter == username:
                data.append((time, "/ticket/%s" % id, _("Reporter of ticket %s") % id))
            if owner == username:
                data.append((time, "/ticket/%s" % id, _("Owner of ticket %s") % id))
            if username in UserInfo.splitcc(env, cc, id):
                data.append((time, "/ticket/%s" % id, _("In CC of ticket %(id)s ('%(cc)s')", id=id, cc=cc)))

        for rev,time in env.db_query("SELECT rev,time FROM revision WHERE author=%s", (username,)):
            data.append((time, None, _("Author of revision %s") % rev))

        for name, in env.db_query("SELECT name FROM component WHERE owner=%s", (username,)):
            data.append((None, "/admin/ticket/components", _("Component '%s' owner") % name))

        for sid, in env.db_query("SELECT DISTINCT(username) FROM permission WHERE username=%s", (username,)):
            data.append((None, "/admin/general/perm", _("In permissions list")))

        for id, in env.db_query("SELECT id FROM report WHERE author=%s", (username,)):
            data.append((None, "/report/%s" %id, _("Author of report %d") % id))

        # non-standard table
        try:
            for time,realm,resource in env.db_query("SELECT time,realm,resource_id FROM votes WHERE username=%s", (username,)):
                data.append((time, "/%s/%s" % (realm, resource), _("Voted for '%s'") % ("/%s/%s" % (realm, resource))))
        except: # old style
            try:
                for resource, in env.db_query("SELECT resource FROM votes WHERE username=%s", (username,)):
                    data.append((None, "/%s" % resource, _("Voted for '%s'") % resource))
            except:
                pass
        return sorted(data, key=lambda x: x[0])

    @staticmethod
    def splitcc(env, cc, ticket):
        authors = []
        if cc != None and cc != '':
            sepchar = re.compile("[ ;]")
            for ccval in cc.split(", "):
                if ccval != '':
                    authors.append(ccval)
                    if sepchar.search(ccval):
                        env.log.warn("Strange character in CC value for ticket %s: '%s'" % (ticket, ccval))
        return authors

    @staticmethod
    def getinfo(env, mode='unused', minwiki=0):
        users = {}
        emails = {}
        emailscase = {}
        # arguments order:
        # 0: last visit time or initial link
        # 1: registered
        # 2: has settings
        # 3: e-mail
        # 4: wiki edited (1=as user, 2=as email, 3=both)
        # 5: wiki edit count
        # 6: ticket edited (1=as user, 2=as email, 3=both)
        # 7: ticket edit count
        # 8: SVN edited (only 1=as user)
        # 9: SVN edit count
        #10: component, permissions (1=as user, 2=as email, 3=both)
        #11: component, ... count
        #12: name
        #13: mail is double
        #14: is in password store

        mailre = re.compile("(?i)^(?:.*<)?([A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+[A-Z0-9-]{2,63})(?:>.*)?$")

        def addemail(user, mail):
            finalmail = mail.lower()
            # sanitize Google mail
            m = finalmail.split("@")
            if len(m) == 2 and m[1] in ("gmail.com", "googlemail.com"):
                m = m[0].split("+") # ignore anything behind a plus
                m = m[0].replace(".", "") # ignore any dots
                finalmail = m + "@gmail.com"
                
            if not mail in emailscase:
                emailscase[mail] = list((user,))
            elif not user in emailscase[mail]:
                # mail already there, but longer name not, remove mail
                if mail in emailscase[mail]:
                    if users[mail][5]:
                        users[user][5] += users[sid][5]
                        users[user][4] |= 2
                    if users[mail][7]:
                        users[user][7] += users[sid][7]
                        users[user][6] |= 2
                    if users[mail][9]:
                        users[user][9] += users[sid][9]
                        users[user][8] |= 2
                    if users[mail][11]:
                        users[user][11] += users[sid][11]
                        users[user][10] |= 2
                    users.pop(mail)
                    emailscase[mail].remove(mail)
                    emails[finalmail].remove(mail)
                emailscase[mail].append(user)
            if not finalmail in emails or not len(emails[finalmail]):
                emails[finalmail] = list((user,))
            elif not user in emails[finalmail]:
               emails[finalmail].append(user)
               for u in emails[finalmail]:
                   users[u][13] = finalmail

        def getuser(mail):
            if mail in emailscase:
                return emailscase[mail][0]
            return mail

        def adduser(user, link, idx):
            if user != None and user != "anonymous" and user != '':
                val = 1
                res = mailre.search(user)
                mail = 0
                if res:
                    mail = res.group(1)
                    if mail == user:
                        val = 2
                        user = getuser(mail)
                if not user in users:
                    users[user] = [link, 0, 0, mail, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
                    if mail:
                        addemail(user, mail)
                users[user][idx] |= val
                users[user][idx+1] += 1
            
        for sid,last_visit in env.db_query("SELECT sid,last_visit FROM session WHERE authenticated = 1"):
            users[sid] = [int(last_visit), 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        for sid,name,value in env.db_query("SELECT sid,name,value FROM session_attribute WHERE authenticated = 1"):
            if not sid in users:
                users[sid] = [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            else:
                users[sid][2] = 1
            if name == "email":
                users[sid][3] = value
                addemail(sid, value)
            elif name == "name":
                users[sid][12] = value

        if AccountManager:
            for sid in AccountManager(env).get_users():
                if not sid in users:
                    users[sid] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                else:
                    users[sid][14] += 1

        for sid,page,version in env.db_query("SELECT author,name,version FROM wiki"):
            adduser(sid, "/wiki/%s?version=%s" % (page,version), 4)

        for sid,page,type in env.db_query("SELECT author,id,type FROM attachment"):
            adduser(sid, "/%s/%s#no1" % (type, page), 6 if type == 'ticket' else 4)

        for author,field,oldvalue,newvalue,ticket in env.db_query("SELECT author,field,oldvalue,newvalue,ticket FROM ticket_change"):
            authors = [author]
            if field == "reporter" or field == "owner":
                if oldvalue != None and oldvalue != '':
                    authors.append(oldvalue)
                if newvalue != None and newvalue != '':
                    authors.append(newvalue)
            elif field == 'cc':
                for val in [oldvalue, newvalue]:
                    authors += UserInfo.splitcc(env, val, ticket)
            for sid in authors:
                adduser(sid, "/ticket/%s" % ticket, 6)

        for reporter, owner, cc, id in env.db_query("SELECT reporter,owner,cc,id FROM ticket"):
            authors = [reporter, owner] + UserInfo.splitcc(env, cc, id)
            for sid in authors:
                adduser(sid, "/ticket/%s" % id, 6)

        for sid, in env.db_query("SELECT author FROM revision"):
            adduser(sid, 0, 8)

        for sid, in env.db_query("SELECT owner FROM component"):
            adduser(sid, 0, 10)

        for sid, in env.db_query("SELECT username FROM permission"):
            adduser(sid, 0, 10)

        for sid, in env.db_query("SELECT author FROM report"):
            adduser(sid, 0, 10)

        # non-standard table
        try:
            for sid, in env.db_query("SELECT username FROM votes"):
                adduser(sid, 0, 10)
        except:
            pass

        killsids = []
        stats = {'numunused': 0, 'numauthorized': 0, 'numtotal': len(users)}
        for sid in users:
            if not users[sid][1]:
                if mode == 'authorized' or mode == 'unused':
                    killsids.append(sid)
            else:
                stats['numauthorized'] += 1
                wikicount = users[sid][5]
                if wikicount <= minwiki:
                    wikicount = 0
                if wikicount+users[sid][7]+users[sid][9]+users[sid][11]:
                    if mode == 'unused':
                        killsids.append(sid)
                else:
                    stats['numunused'] += 1
        for sid in killsids:        
            del users[sid]
        if mode == 'overview':
            users = ()
                                                                                                
        return users,stats

    @staticmethod
    def deletetemporary(env):
        env.db_transaction("DELETE FROM session WHERE authenticated = 0; DELETE FROM session_attribute WHERE authenticated = 0")

    @staticmethod
    def _fixcc(cc, old, new):
        results = []
        for entry in cc.split(", "):
            if entry == old:
                entry = new
            if not entry in results:
                results.append(entry)
        return ", ".join(results)

    @staticmethod
    def _callupdate(cursor, cmd, arg):
        cursor.execute(cmd, arg)
        try: # tested with postgres only
            return int(cursor.statusmessage[7:]) # strip "UPDATE " text
        except:
            return 0

    @staticmethod
    def changeuser(env, old, new, authorized=False):
        if authorized == "forcecc":
            forcecc = True
            authorized = None
        else:
            forcecc = False
        # prevent changing registered users
        if not authorized:
            res = env.db_query("SELECT sid,authenticated FROM session WHERE sid = %s", (old,))
            if len(res):
                return -1
        elif authorized != 'join': # already existing user
            res = env.db_query("SELECT sid,authenticated FROM session WHERE sid = %s", (new,))
            if len(res):
                return -4
        if old == new or not old or not new:
            return -2
        env.log.warn("Change username '%s' to '%s'" % (old, new))
        count = 0
        with env.db_transaction as db:
            cursor = db.cursor()

            entries = []
            cursor.execute("SELECT cc FROM ticket WHERE cc LIKE %s", ("%%"+old+"%%",))
            for row in cursor:
                if not row[0] in entries:
                    entries.append(row[0])

            cursor.execute("SELECT oldvalue,newvalue FROM ticket_change WHERE field='cc' AND (oldvalue LIKE %s OR newvalue LIKE %s)", ("%%"+old+"%%","%%"+old+"%%"))
            for row in cursor:
                for entry in row:
                    if entry != None and entry != '' and not entry in entries:
                        entries.append(entry)

            sepchar = re.compile("[ ,;]")
            for entry in entries:
                newcc = UserInfo._fixcc(entry, old, new)
                if newcc != entry:
                    if sepchar.search(new) and not forcecc:
                        return -3;
                    count += UserInfo._callupdate(cursor, "UPDATE ticket SET cc = %s WHERE cc = %s", (newcc, entry))
                    count += UserInfo._callupdate(cursor, "UPDATE ticket_change SET oldvalue = %s WHERE oldvalue = %s AND field = 'cc'", (newcc, entry))
                    count += UserInfo._callupdate(cursor, "UPDATE ticket_change SET newvalue = %s WHERE newvalue = %s AND field = 'cc'", (newcc, entry))

            if authorized:
                if authorized == 'join':
                    count += UserInfo._callupdate(cursor, "DELETE FROM session WHERE sid = %s", (old,))
                    count += UserInfo._callupdate(cursor, "DELETE FROM session_attribute WHERE sid = %s", (old, ))
                else:
                    count += UserInfo._callupdate(cursor, "UPDATE session SET sid = %s WHERE sid = %s", (new, old))
                    count += UserInfo._callupdate(cursor, "UPDATE session_attribute SET sid = %s WHERE sid = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE wiki SET author = %s WHERE author = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE ticket_change SET author = %s WHERE author = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE ticket_change SET oldvalue = %s WHERE oldvalue = %s AND (field = 'reporter' OR field = 'owner')", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE ticket_change SET newvalue = %s WHERE newvalue = %s AND (field = 'reporter' OR field = 'owner')", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE ticket SET reporter = %s WHERE reporter = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE ticket SET owner = %s WHERE owner = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE attachment SET author = %s WHERE author = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE report SET author = %s WHERE author = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE component SET owner = %s WHERE owner = %s", (new, old))
            count += UserInfo._callupdate(cursor, "UPDATE permission SET username = %s WHERE username = %s", (new, old))
            db.commit()
            # non-standard table
            try:
                try:
                  cursor.execute("DELETE from votes WHERE username = %s AND (realm, resource_id) IN (SELECT realm, resource_id FROM votes WHERE username = %s)", (old, new))
                except:
                  cursor.execute("DELETE from votes WHERE username = %s AND resource IN (SELECT resource FROM votes WHERE username = %s)", (old, new))
                count += UserInfo._callupdate(cursor, "UPDATE votes SET username = %s WHERE username = %s", (new, old))
                db.commit()
            except:
                pass
                    
        return count
