# -*- coding: utf-8 -*-
import logging
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb
from collections import OrderedDict
from bp_includes.lib.basehandler import BaseHandler
from bp_includes.models import LogEmail
from google.appengine.api import taskqueue
from bp_includes import messages
from google.appengine.api import users as g_users #https://cloud.google.com/appengine/docs/python/refdocs/modules/google/appengine/api/users#get_current_user
from google.appengine.ext.webapp.mail_handlers import BounceNotificationHandler


class LogBounceHandler(BounceNotificationHandler):
    def receive(self, bounce_message):
        logging.info('Received bounce post ... [%s]', self.request)
        logging.info('Bounce original: %s', bounce_message.original)
        logging.info('Bounce notification: %s', bounce_message.notification)


class AdminLogsEmailsHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            qry = LogEmail.query(ndb.OR(LogEmail.to == q.lower(),
                                           LogEmail.sender == q.lower(),
                                           LogEmail.subject == q.lower()))
        else:
            qry = LogEmail.query()

        PAGE_SIZE = 50
        if forward:
            emails, next_cursor, more = qry.order(LogEmail.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            if next_cursor and more:
                self.view.next_cursor = next_cursor
            if c:
                self.view.prev_cursor = cursor.reversed()
        else:
            emails, next_cursor, more = qry.order(-LogEmail.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            emails = list(reversed(emails))
            if next_cursor and more:
                self.view.prev_cursor = next_cursor
            self.view.next_cursor = cursor.reversed()

        def pager_url(p, cursor):
            params = OrderedDict()
            if q:
                params['q'] = q
            if p in ['prev']:
                params['p'] = p
            if cursor:
                params['c'] = cursor.urlsafe()
            return self.uri_for('admin-logs-emails', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        params = {
            "list_columns": [('when', 'When'),
                             ('to', 'Recipient'),
                             ('subject', 'Subject'),
                             ('sender', 'Sender'),
            #                 ('body', 'Body')
            ],
            "emails": emails,
            "count": qry.count()
        }
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('emails/admin_logs_emails.html', **params)


class AdminLogsEmailViewHandler(BaseHandler):
    def get(self, email_id):
        try:
            emaildata = LogEmail.get_by_id(long(email_id))
            if emaildata:
                params = {
                    'emailinfo': emaildata
                }
                params['nickname'] = g_users.get_current_user().email().lower()
                return self.render_template('emails/admin_logs_email_view.html', **params)
        except ValueError:
            pass
        self.abort(404)


class AdminSendEmailListHandler(BaseHandler):
    def get(self):
        email_id=self.request.get('email_id')
        params = {
            "recipent": email_id,
        }        
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('emails/admin_send_email.html', **params)
            
    def post(self):
        
        def sendEmail (recipent,subject,body):
            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': recipent,
                'subject': subject,
                'body': body
            })
        
        body = self.request.get('emailbody')
        subject = self.request.get('subject')
        to = self.request.get('recipents')

        try:
            if to == 'ALLUSERS':
                users = self.user_model.query()
                for user in users:
                    sendEmail (user.email,subject,body)
            else:
                for recipents in to.split(','):
                    sendEmail (recipents.strip(),subject,body)
            self.add_message('Emails sent !', 'success')
        
        except Exception as e:
            logging.info('error in form: %s' % e)
            self.add_message('Something went wrong.', 'danger')
            pass
        
        return self.get()