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

from trac.db import Column, DatabaseManager, Table

def _schema_to_sql(env, db, table):
    connector, _ = DatabaseManager(env)._get_connector()
    return connector.to_sql(table)

def add_log_table(env, db):
    """Add a table for storing the spamfilter logs."""
    table = Table('spamfilter_log', key='id')[
        Column('id', auto_increment=True),
        Column('time', type='int'),
        Column('path'),
        Column('author'),
        Column('authenticated', type='int'),
        Column('ipnr'),
        Column('content'),
        Column('rejected', type='int'),
        Column('karma', type='int'),
        Column('reasons')
    ]
    cursor = db.cursor()
    for stmt in _schema_to_sql(env, db, table):
        cursor.execute(stmt)

def add_headers_column_to_log_table(env, db):
    """Add a column to the log table for storing the request headers."""
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
        Column('reasons')
    ]
    cursor = db.cursor()
    cursor.execute("CREATE TEMPORARY TABLE spamfilter_log_old AS "
                   "SELECT * FROM spamfilter_log")
    cursor.execute("DROP TABLE spamfilter_log")
    for stmt in _schema_to_sql(env, db, table):
        cursor.execute(stmt)
    cursor.execute("INSERT INTO spamfilter_log (id,time,path,author,"
                   "authenticated,ipnr,content,rejected,karma,reasons) "
                   "SELECT id,time,path,author,authenticated,ipnr,content,"
                   "rejected,karma,reasons FROM spamfilter_log_old")
    cursor.execute("DROP TABLE spamfilter_log_old")

def add_bayes_table(env, db):
    """Add table required for bayesian filtering."""
    table = Table('spamfilter_bayes', key='word')[
        Column('word'),
        Column('nspam', type='int'),
        Column('nham', type='int')
    ]
    cursor = db.cursor()
    for stmt in _schema_to_sql(env, db, table):
        cursor.execute(stmt)

def add_statistics_table(env, db):
    """Add table required for filtering statistics."""
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
    cursor = db.cursor()
    for stmt in _schema_to_sql(env, db, table):
        cursor.execute(stmt)

def add_request_column_to_log_table(env, db):
    """Add a column to the log table for storing the complete request."""
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
    cursor = db.cursor()
    cursor.execute("CREATE TEMPORARY TABLE spamfilter_log_old AS "
                   "SELECT * FROM spamfilter_log")
    cursor.execute("DROP TABLE spamfilter_log")
    for stmt in _schema_to_sql(env, db, table):
        cursor.execute(stmt)
    # copy old, but strip entries with non-XML reasons
    cursor.execute("INSERT INTO spamfilter_log (id,time,path,author,"
                   "authenticated,ipnr,headers,content,rejected,karma,reasons) "
                   "SELECT id,time,path,author,authenticated,ipnr,headers,content,"
                   "rejected,karma,reasons FROM spamfilter_log_old "
                   "WHERE reasons LIKE '<entries>%</entries>'")
    cursor.execute("DROP TABLE spamfilter_log_old")

def add_report_table(env, db):
    """Add table required for spam reports by users."""
    table = Table('spamfilter_report', key=['id'])[
        Column('id', auto_increment=True),
        Column('entry'),
        Column('headers'),
        Column('author'),
        Column('authenticated', type='int'),
        Column('comment'),
        Column('time', type='int')
    ]
    cursor = db.cursor()
    for stmt in _schema_to_sql(env, db, table):
        cursor.execute(stmt)

version_map = {
    1: [add_log_table],
    2: [add_headers_column_to_log_table],
    3: [add_bayes_table],
    4: [add_statistics_table, add_request_column_to_log_table, add_report_table]
}
