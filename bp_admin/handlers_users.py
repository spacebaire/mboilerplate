# -*- coding: utf-8 -*-
import webapp2, json
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb
from collections import OrderedDict, Counter
from wtforms import fields  
from bp_includes import forms, models, handlers, messages
from bp_includes.models import LogVisit, User
from bp_includes.lib.basehandler import BaseHandler
from datetime import datetime, date, time, timedelta
import logging
from google.appengine.api import users as g_users #https://cloud.google.com/appengine/docs/python/refdocs/modules/google/appengine/api/users#get_current_user

class AdminStatsHandler(BaseHandler):
    def get(self): 
        params = {}       
        users = self.user_model.query()
        params['sum_users'] = users.count()

        blogs = models.BlogPost.query()
        params['sum_blogs'] = blogs.count()
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/essentials/admin_stats.html' % self.app.config.get('app_lang'), **params)

class EditProfileForm(forms.SettingsProfileForm):
    activated = fields.BooleanField('Activated')
    permission = fields.IntegerField('Permission')

class AdminUserListHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            try:
                qry = self.user_model.get_by_id(long(q.lower()))
                count = 1 if qry else 0
            except Exception as e:
                logging.info('Exception at query: %s; trying with email' % e)
                qry = self.user_model.get_by_email(q.lower())
                count = 1 if qry else 0
            users = []
            if qry:
                users.append(qry)
        else:
            qry = self.user_model.query()
            count = qry.count()

            PAGE_SIZE = 50
            if forward:
                users, next_cursor, more = qry.order(-self.user_model.last_login).fetch_page(PAGE_SIZE, start_cursor=cursor)
                if next_cursor and more:
                    self.view.next_cursor = next_cursor
                if c:
                    self.view.prev_cursor = cursor.reversed()
            else:
                users, next_cursor, more = qry.order(self.user_model.last_login).fetch_page(PAGE_SIZE, start_cursor=cursor)
                users = list(reversed(users))
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
            return self.uri_for('admin-users-list', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        if self.app.config.get('app_lang') == 'es':
            list_columns = [('username', 'Correo'),
                             ('name', 'Nombre'),
                             ('last_name', 'Apellido'),
                             ('level', 'Nivel de acceso'),
                             ('get_role', 'Rol'),
                             ('link_referral', u'Link único'),
                             ('amount','Recompensas'),
                             ('created', u'Creación'),
                             ('last_login', u'Último ingreso')
                             ]
        else:
            list_columns = [('username', 'Email'),
                             ('name', 'Name'),
                             ('last_name', 'Lastname'),
                             ('level', 'Access'),
                             ('get_role', 'Role'),
                             ('link_referral', u'Unique link'),
                             ('amount','Rewards'),
                             ('created', 'Created'),
                             ('last_login', u'Last login')
                             ]

        params = {
            "list_columns": list_columns,
            "users": users,
            "count": count
        }
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/users/admin_users_list.html' % self.app.config.get('app_lang'), **params)

class AdminUserEditHandler(BaseHandler):
    def get_or_404(self, user_id):
        try:
            user = self.user_model.get_by_id(long(user_id))
            if user:
                return user
        except ValueError:
            pass
        self.abort(404)

    def edit(self, user_id):
        if self.request.POST:
            user = self.get_or_404(user_id)
            if not self.form.validate():
                self.add_message(messages.saving_error, 'danger')
                return self.get()
            name = self.request.get('name')
            last_name = self.request.get('last_name')
            gender = self.request.get('gender')
            phone = self.request.get('phone')
            birth = self.request.get('birth')
            permission = int(self.request.get('permission'))
            picture = self.request.get('picture') if len(self.request.get('picture'))>1 else None
            activated = True if 'on' in self.request.get('activated') else False

            try:
                user_info = self.user_model.get_by_id(long(user_id))
                user_info.name = name
                user_info.activated = activated
                user_info.last_name = last_name
                user_info.level = permission
                if (len(birth) > 9):
                    user_info.birth = date(int(birth[:4]), int(birth[5:7]), int(birth[8:]))
                if 'male' in gender:
                    user_info.gender = gender
                user_info.phone = phone
                if picture is not None:
                    user_info.picture = images.resize(picture, width=180, height=180, crop_to_fit=True, quality=100)
                user_info.put()
                self.add_message(messages.saving_success, 'success')
                return self.redirect_to("admin-user-edit", user_id=user_id)
                

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating profile: %s ' % e)
                self.add_message(messages.saving_error, 'danger')
                return self.redirect_to("admin-user-edit", user_id=user_id)
        else:
            user = self.get_or_404(user_id)
            self.form.process(obj=user)

        params = {
            'user': user
        }
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/users/admin_user_edit.html' % self.app.config.get('app_lang'), **params)

    @webapp2.cached_property
    def form(self):
        f = EditProfileForm(self)
        return f

class AdminExportUsers(BaseHandler):
    
    def get(self):
        _users= []
        users = self.user_model.query()
        for user in users:
                _users.append({'username': user.username, 'name': user.name, 'email': user.email, 'last_login': user.last_login})
                                    
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(_users))

class AdminLogsVisitsHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            try:
                user_key = ndb.Key(User,long(q.lower()))
                qry = LogVisit.query(ndb.OR(    LogVisit.user == user_key,
                                                LogVisit.timestamp == q.lower(),
                                                LogVisit.uastring == q.lower(),
                                                LogVisit.ip == q.lower()))
            except:
                qry = LogVisit.query(ndb.OR(    LogVisit.timestamp == q.lower(),
                                                LogVisit.uastring == q.lower(),
                                                LogVisit.ip == q.lower()))
        else:
            qry = LogVisit.query()
    
        PAGE_SIZE = 50
        if forward:
            visits, next_cursor, more = qry.order(LogVisit.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            if next_cursor and more:
                self.view.next_cursor = next_cursor
            if c:
                self.view.prev_cursor = cursor.reversed()
        else:
            visits, next_cursor, more = qry.order(-LogVisit.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            visits = list(reversed(visits))
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
            return self.uri_for('admin-logs-visits', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        #fine-tuning output
        _visits = []
        for _visit in visits:
            if(self.user_model.get_by_id(long(_visit.user.id())) != None):
                _visits.append(_visit)

        if self.app.config.get('app_lang') == 'es':
            list_columns = [('timestamp', 'Fecha'), ('ip', 'IP'),('uastring', 'Navegador')]
        else:
            list_columns = [('timestamp', 'Date'), ('ip', 'IP'),('uastring', 'Browser')]
        
        params = {
            "list_columns": list_columns,
            "visits": _visits,
            "count": qry.count()
        }
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/users/admin_logs_visits.html' % self.app.config.get('app_lang'), **params)
