#!/usr/bin/env python
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

from setuptools import setup, find_packages

PACKAGE = 'TracSpamFilter'
VERSION = '1.0.0-1'

extra = {}
try:
    from trac.util.dist import get_l10n_cmdclass
    cmdclass = get_l10n_cmdclass()
    if cmdclass:
        extra['cmdclass'] = cmdclass
        extractors = [
            ('**.py',                'trac.dist:extract_python', None),
            ('**/templates/**.html', 'genshi', None)
        ]
        extra['message_extractors'] = {
            'tracspamfilter': extractors,
        }
except ImportError:
    pass

setup(
    name = PACKAGE,
    version = VERSION,
    description = 'Plugin for spam filtering',
    author = "Edgewall Software",
    author_email = "info@edgewall.com",
    url = 'http://trac.edgewall.org/wiki/SpamFilter',
    download_url = 'http://trac.edgewall.org/wiki/SpamFilter',
    license = 'BSD',
    classifiers=[
        'Framework :: Trac',
        'License :: OSI Approved :: BSD License', 
    ],
    keywords='trac plugin',

    packages = find_packages(exclude=['*.tests*']),
    package_data = {'tracspamfilter': ['templates/*', 'htdocs/*', 'fonts/*', 'locale/*/LC_MESSAGES/*.mo']},
    install_requires = ['Trac >= 1.0', 'recaptcha_client>=1.0.6-1'],
    extras_require = {
        'DNS': ['dnspython>=1.3.5'],
        'SpamBayes': ['spambayes'],
        'PIL': ['pil'],
        'json': ['python>=2.6'],
        'account' : ['TracAccountManager >= 0.4'],
        'oauth' : ['oauth2']
    },
    entry_points = """
        [trac.plugins]
        spamfilter = tracspamfilter.api
        spamfilter.filtersystem = tracspamfilter.filtersystem
        spamfilter.admin = tracspamfilter.admin
        spamfilter.adminusers = tracspamfilter.adminusers
        spamfilter.adminreport = tracspamfilter.adminreport
        spamfilter.adapters = tracspamfilter.adapters
        spamfilter.report = tracspamfilter.report
        spamfilter.accountadapter = tracspamfilter.accountadapter[account]
        spamfilter.registration = tracspamfilter.filters.registration[account]
        spamfilter.akismet = tracspamfilter.filters.akismet
        spamfilter.stopforumspam = tracspamfilter.filters.stopforumspam
        spamfilter.botscout = tracspamfilter.filters.botscout
        spamfilter.fspamlist = tracspamfilter.filters.fspamlist
        spamfilter.linksleeve = tracspamfilter.filters.linksleeve
        spamfilter.blogspam = tracspamfilter.filters.blogspam
        spamfilter.mollom = tracspamfilter.filters.mollom[oauth]
        spamfilter.defensio = tracspamfilter.filters.defensio[json]
        spamfilter.bayes = tracspamfilter.filters.bayes[SpamBayes]
        spamfilter.extlinks = tracspamfilter.filters.extlinks
        spamfilter.httpbl = tracspamfilter.filters.httpbl[DNS]
        spamfilter.ip_blacklist = tracspamfilter.filters.ip_blacklist[DNS]
        spamfilter.ip_throttle = tracspamfilter.filters.ip_throttle
        spamfilter.regex = tracspamfilter.filters.regex
        spamfilter.trapfield = tracspamfilter.filters.trapfield
        spamfilter.ip_regex = tracspamfilter.filters.ip_regex
        spamfilter.session = tracspamfilter.filters.session
        spamfilter.captcha = tracspamfilter.captcha.api
        spamfilter.captcha.image = tracspamfilter.captcha.image[PIL]
        spamfilter.captcha.expression = tracspamfilter.captcha.expression
        spamfilter.captcha.rand = tracspamfilter.captcha.rand
        spamfilter.captcha.recaptcha = tracspamfilter.captcha.recaptcha
        spamfilter.captcha.keycaptcha = tracspamfilter.captcha.keycaptcha
        spamfilter.captcha.areyouahuman = tracspamfilter.captcha.areyouahuman
    """,
    test_suite = 'tracspamfilter.tests.suite',
    zip_safe = False,
    **extra
)
