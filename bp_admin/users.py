# -*- coding: utf-8 -*-
import webapp2, json
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb
from collections import OrderedDict, Counter
from wtforms import fields  
from bp_includes import forms, models, handlers
from bp_includes.lib.basehandler import BaseHandler
from datetime import datetime, date, time, timedelta
import logging


class AdminStatsHandler(BaseHandler):
    def get(self):
        params = {}
        #do the Users dance
        users = self.user_model.query()
        users = users.order(self.user_model.created)
        _users = []
        counter = 0
        for user in users:
            counter += 1
            _created = user.created - timedelta(hours = 6)
            _users.append([counter,_created.strftime("%a, %d %b %Y %H:%M:%S %z")])
       
        params['users'] = json.dumps(_users)
        params['sum_users'] = counter
        return self.render_template('admin_stats.html', **params)

class AdminUserGeoChartHandler(BaseHandler):
    def get(self):
        users = self.user_model.query().fetch(projection=['country'])
        users_by_country = Counter()

        users = self.user_model.query()
        latlngs = []
        for user in users:
            if user.address is not None:
                if user.address.latlng is not None:
                    latlngs.append(user.address.latlng)

        params = {
            "data": users_by_country.items(),
            "list_attrs": [('lat', 'lon')],
            "latlngs": latlngs,
        }
        return self.render_template('admin_users_geochart.html', **params)

class EditProfileForm(forms.SettingsProfileForm):
    activated = fields.BooleanField('Activated')

class AdminUserListHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            _users = []
            qry = self.user_model.query(ndb.OR(self.user_model.name >= q.lower(),
                                           self.user_model.email >= q.lower(),
                                           self.user_model.username >= q.lower()))
            for _qry in qry:
                if q.lower() in _qry.name.lower() or q.lower() in _qry.email.lower() or q.lower() in _qry.username.lower():
                    _users.append(_qry)
            users = _users
            count = len(users)
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

        params = {
            "list_columns": [('username', 'Username'),
                             ('name', 'Name'),
                             ('last_name', 'Last Name'),
                             ('email', 'Email'),
                             ('role', 'Role'),
                             ('last_login', 'Last Login'),
                             ('link_referral', 'Referrals Link'),
                             ('key', 'ID'),
                             ('rewards','Rewards')],
            "users": users,
            "count": count
        }
        return self.render_template('admin_users_list.html', **params)

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
            if self.form.validate():
                self.form.populate_obj(user)
                user.put()
                self.add_message("Changes saved!", 'success')
                return self.redirect_to("admin-user-edit", user_id=user_id)
            else:
                self.add_message("Could not save changes!", 'danger')
        else:
            user = self.get_or_404(user_id)
            self.form.process(obj=user)

        params = {
            'user': user
        }
        return self.render_template('admin_user_edit.html', **params)

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
