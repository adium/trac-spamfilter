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
#
# Author: Alec Thomas <alec@swapoff.org>

import os
import random
from StringIO import StringIO

# PIL
try:
  from PIL import Image
  from PIL import ImageFont
  from PIL import ImageDraw
  from PIL import ImageFilter
except ImportError:
  import Image
  import ImageFont
  import ImageDraw
  import ImageFilter

from trac.core import *
from trac.util.html import html
from trac.config import *
from trac.web.api import IRequestHandler
from tracspamfilter.captcha import ICaptchaMethod


class ImageCaptcha(Component):
    """An image captcha courtesy of
    http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/440588
    """

    implements(ICaptchaMethod, IRequestHandler)

    fonts = ListOption('spam-filter', 'captcha_image_fonts', 'vera.ttf',
        doc="""Set of fonts to choose from when generating image CAPTCHA.""",
        doc_domain="tracspamfilter")

    font_size = IntOption('spam-filter', 'captcha_image_font_size', 25,
        """Font size to use in image CAPTCHA.""",
        doc_domain="tracspamfilter")

    alphabet = Option('spam-filter', 'captcha_image_alphabet',
                      'abcdefghkmnopqrstuvwxyz',
        """Alphabet to choose image CAPTCHA challenge from.""",
        doc_domain="tracspamfilter")

    letters = IntOption('spam-filter', 'captcha_image_letters', 6,
        """Number of letters to use in image CAPTCHA challenge.""",
        doc_domain="tracspamfilter")

    # IRequestHandler methods
    def match_request(self, req):
        return req.path_info == '/captcha/image'

    def process_request(self, req):
        if 'captcha_expected' not in req.session:
            # TODO Probably need to render an error image here
            raise TracError('No CAPTCHA response in session')
        req.send_response(200)
        req.send_header('Content-Type', 'image/jpeg')

        image = StringIO()
        from pkg_resources import resource_filename
        font = os.path.join(resource_filename('tracspamfilter', 'fonts'),
                            random.choice(self.fonts))
        self.gen_captcha(image, req.session['captcha_expected'], font,
                         self.font_size)
        img = image.getvalue()
        req.send_header('Content-Length', len(img))
        req.end_headers()
        req.write(img)

    # ICaptchaMethod methods

    def generate_captcha(self, req):
        challenge = ''.join([random.choice(self.alphabet) 
                             for i in xrange(self.letters)])
        return challenge, html.img(src=req.href('/captcha/image'), \
               width='33%', alt='captcha')

    def verify_captcha(self, req):
        return False

    def is_usable(self, req):
        return True

    # Internal methods
    
    def gen_captcha(self, file, text, fnt, fnt_sz, fmt='JPEG'):
        # randomly select the foreground color
        fgcolor = random.randint(0,0xffff00)
        # make the background color the opposite of fgcolor
        bgcolor = fgcolor ^ 0xffffff
        # create a font object 
        font = ImageFont.truetype(fnt,fnt_sz)
        # determine dimensions of the text
        dim = font.getsize(text)
        # create a new image slightly larger that the text
        im = Image.new('RGB', (dim[0]+5,dim[1]+5), bgcolor)
        d = ImageDraw.Draw(im)
        x, y = im.size
        r = random.randint
        # draw 100 random colored boxes on the background
        for num in xrange(100):
            d.rectangle((r(0,x),r(0,y),r(0,x),r(0,y)),fill=r(0,0xffffff))
        # add the text to the image
        d.text((3,3), text, font=font, fill=fgcolor)
        im = im.filter(ImageFilter.EDGE_ENHANCE_MORE)
        # save the image to a file
        im.save(file, format=fmt)
