# -*- coding: utf-8 -*-
#
# Copyright (C) 2006 Edgewall Software
# Copyright (C) 2006 Alec Thomas <alec@swapoff.org>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at http://trac.edgewall.com/license.html.
#
# This software consists of voluntary contributions made by many
# individuals. For the exact contribution history, see the revision
# history and logs, available at http://projects.edgewall.com/trac/.

import os
import random

from types import *
from trac.core import *
from tracspamfilter.captcha import ICaptchaMethod

class RandomCaptcha(Component):
    """An random captcha chooser"""

    handlers = ExtensionPoint(ICaptchaMethod)

    implements(ICaptchaMethod)

    # ICaptchaMethod methods

    def generate_captcha(self, req):
        count = 0
        for newhandler in self.handlers:
            if not isinstance(newhandler, RandomCaptcha) \
            and newhandler.is_usable(req):
                count += 1
        selectval = random.randint(1, count)
        count = 0
        for newhandler in self.handlers:
            if not isinstance(newhandler, RandomCaptcha) \
            and newhandler.is_usable(req):
                count += 1
                if count == selectval:
                    req.session['captcha_handler'] = count
                    req.session.save()
                    return newhandler.generate_captcha(req)

    def verify_captcha(self, req):
        selectval = req.session.get('captcha_handler')
        if selectval != None:
            del req.session['captcha_handler']
            selectval = int(selectval)
        else:
            return False
        count = 0
        for newhandler in self.handlers:
            if not isinstance(newhandler, RandomCaptcha) \
            and newhandler.is_usable(req):
                count += 1
                if count == selectval:
                    return newhandler.verify_captcha(req)
        return False

    def is_usable(self, req):
        return True

    def name(self, req):
        name = self.__class__.__name__
        selectval = req.session.get('captcha_handler')
        if selectval != None:
            selectval = int(selectval)
            count = 0
            for newhandler in self.handlers:
                if not isinstance(newhandler, RandomCaptcha) \
                and newhandler.is_usable(req):
                    count += 1
                    if count == selectval:
                        name = newhandler.__class__.__name__
        return name
