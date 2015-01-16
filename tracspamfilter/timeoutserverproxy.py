# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Edgewall Software
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
# Author: Dirk Stöcker <trac@dstoecker.de>

from xmlrpclib import ServerProxy, Transport, Error
import httplib

class TimeoutHTTPConnection(httplib.HTTPConnection):
    def __init__(self,host,timeout=3):
        httplib.HTTPConnection.__init__(self,host,timeout=timeout)

    # in python 2.6, xmlrpclib expects to use an httplib.HTTP
    # instance and will call getreply() and getfile()

    def getreply(self):
        response = self.getresponse()
        self.file = response.fp
        return response.status, response.reason, response.msg

    def getfile(self):
        return self.file
                            

class TimeoutTransport(Transport):
    def __init__(self, timeout=3, *l, **kw):
        Transport.__init__(self,*l,**kw)
        self.timeout=timeout

    def make_connection(self, host):
        conn = TimeoutHTTPConnection(host,self.timeout)
        return conn


class TimeoutServerProxy(ServerProxy):
    def __init__(self,uri,timeout=3,*l,**kw):
        kw['transport']=TimeoutTransport(timeout=timeout, use_datetime=kw.get('use_datetime',0))
        ServerProxy.__init__(self,uri,*l,**kw)
