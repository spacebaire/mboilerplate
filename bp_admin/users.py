# -*- coding: utf-8 -*-
import webapp2, json
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb
from collections import OrderedDict, Counter
from wtforms import fields  
from bp_includes import forms, models, handlers
from bp_includes.lib.basehandler import BaseHandler
from bp_includes.lib import mycfe
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
        
        #do the Homes dance
        homes = models.Home.query()
        homes = homes.order(models.Home.created)
        _homes = []
        counter2 = 0
        sumsaving_bills = 0
        sumsaving_kwhs = 0
        for home in homes:
            counter2 += 1
            _created = home.created
            _homes.append([counter2,_created.strftime("%a, %d %b %Y %H:%M:%S %z")])
            #do the Savings dance
            if home.cfe.connected: 
                dates = []
                kwhs = []
                bills = []
                for _intake in home.intakes:
                    dates.append(_intake.date)
                    kwhs.append(_intake.kwh)
                    bills.append(_intake.bill) 
                m = mycfe.getPeriod(dates)
                savings_bills = mycfe.getSavings(m,bills) 
                savings_kwhs = mycfe.getSavings(m,kwhs) 
                params['savings'] = []
                params['savings_past'] = []
                for date in dates:
                    if date > home.created:
                        if dates.index(date) < len(savings_bills):
                            sumsaving_bills += max([0, savings_bills[dates.index(date)]])
                            sumsaving_kwhs += max([0, savings_kwhs[dates.index(date)]])
                        else:
                            break
        
        #do the Stores dance
        stores = models.Store.query()
        stores = stores.order(models.Store.created)
        _stores = []
        counter3 = 0
        for store in stores:
            counter3 += 1
            _created = store.created - timedelta(hours = 6)
            _stores.append([counter3,_created.strftime("%a, %d %b %Y %H:%M:%S %z")])

        params['users'] = json.dumps(_users)
        params['homes'] = json.dumps(_homes)
        params['stores'] = json.dumps(_stores)
        params['sum_users'] = counter
        params['sum_homes'] = counter2
        params['sum_stores'] = counter3
        params['savings_sum_bills'] = format(sumsaving_bills, ',d')
        params['savings_sum_kwhs'] = format(sumsaving_kwhs, ',d')
        return self.render_template('admin_stats.html', **params)


class AdminUserGeoChartHandler(BaseHandler):
    def get(self):
        users = self.user_model.query().fetch(projection=['country'])
        users_by_country = Counter()
        for user in users:
            if user.country:
                users_by_country[user.country] += 1


        homes = models.Home.query()
        latlngs = []
        for home in homes:
            if home.address is not None:
                if home.address.latlng is not None:
                    latlngs.append(home.address.latlng)
        for store in stores:
            if store.address is not None:
                if store.address.latlng is not None:
                    latlngs.append(store.address.latlng)

        params = {
            "data": users_by_country.items(),
            "list_attrs": [('lat', 'lon')],
            "latlngs": latlngs,
        }
        return self.render_template('admin_users_geochart.html', **params)


class EditProfileForm(forms.EditProfileForm):
    activated = fields.BooleanField('Activated')


class AdminUserListHandler(BaseHandler):
    def get(self):
        home_id = self.request.get('homeid')
        if len(home_id) > 1:
            logging.info("Received a home id")
            users = self.user_model.query(self.user_model.home_id == int(home_id))
            count = users.count()
        else:
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
                             ('country', 'Country'),
                             ('tz', 'TimeZone'),
                             ('last_login', 'Last Login'),
                             ('link_referral', 'Referrals Link'),
                             ('key', 'ID'),
                             ('rewards','Rewards'),
                             #('cfe','CFE'),
                             ('home_id', 'Home ID')],
            "users": users,
            "count": count
        }
        return self.render_template('admin_users_list.html', **params)

class AdminHomeListHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            qry = models.Home.query()
            qry = qry.filter(models.Home._key == ndb.Key('Home', long(q)))
        else:
            qry = models.Home.query()
        
        PAGE_SIZE = 50
        if forward:
            homes, next_cursor, more = qry.order(models.Home.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            if next_cursor and more:
                self.view.next_cursor = next_cursor
            if c:
                self.view.prev_cursor = cursor.reversed()
        else:
            homes, next_cursor, more = qry.order(-models.Home.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            homes = list(reversed(homes))
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
            return self.uri_for('admin-homes-list', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        params = {
            "list_columns": [('key', 'ID'),
                             ('habitant', 'Habitantes'),
                             ('allowed_emails', 'Emails roomie'),
                             ('address','Address'),
                             ('agg_rewards','Qubits'),
                             ('box', 'Box ID'),
                             ('cfe', 'CFE'),
                             ('intakes', 'Consumos'),
                             ('umr', 'UMR'),
                             ('attributes', 'Atributos'),
                             ('intake_profile', 'Perfil de consumo'),
                             ('created', 'Ingreso'),
                             ('tips_email_counter', 'Email Counter'),
                             ('tips_email_lastdate', 'Email Last Date')],
            "homes": homes,
            "count": qry.count()
        }
        return self.render_template('admin_homes_list.html', **params)

class AdminStoreListHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        if q:
            qry = models.Store.query()
            qry = qry.filter(models.Store._key == ndb.Key('Store', long(q)))
        else:
            qry = models.Store.query()
        
        PAGE_SIZE = 50
        if forward:
            stores, next_cursor, more = qry.order(models.Store.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            if next_cursor and more:
                self.view.next_cursor = next_cursor
            if c:
                self.view.prev_cursor = cursor.reversed()
        else:
            stores, next_cursor, more = qry.order(-models.Store.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            stores = list(reversed(homes))
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
            return self.uri_for('admin-stores-list', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        params = {
            "list_columns": [
                                ('key', 'ID'),
                                ('company', 'Company'),
                                ('phone', 'Phone'),
                                ('razs', 'R. Social'),
                                ('rfc', 'RFC'),
                                ('description', 'Description'),
                                ('website', 'Website'),
                                ('facebook', 'Facebook'),
                                ('twitter', 'Twitter'),
                                ('tagline', 'Tagline'),
                                ('address', 'Address'),
                                ('coverage', 'Coverage'),
                                ('terms', 'Accepted Terms'),
                                ('has_products', 'Has Products'),
                                ('is_verified', 'Verified'),
                                ('admin_email', 'Admin'),
                            ],
            "stores": stores,
            "count": qry.count()
        }
        return self.render_template('admin_stores_list.html', **params)

class AdminQubitListHandler(BaseHandler):
    def get(self):
        p = self.request.get('p')
        q = self.request.get('q')
        c = self.request.get('c')
        forward = True if p not in ['prev'] else False
        cursor = Cursor(urlsafe=c)

        qry = models.Qubit.query()

        PAGE_SIZE = 50
        if forward:
            qubits, next_cursor, more = qry.order(models.Qubit.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            if next_cursor and more:
                self.view.next_cursor = next_cursor
            if c:
                self.view.prev_cursor = cursor.reversed()
        else:
            qubits, next_cursor, more = qry.order(-models.Qubit.key).fetch_page(PAGE_SIZE, start_cursor=cursor)
            qubits = list(reversed(qubits))
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
            return self.uri_for('admin-qubits-list', **params)

        self.view.pager_url = pager_url
        self.view.q = q

        params = {
            "list_columns": [('key', 'ID'),
                             ('Value', 'Qubits')],
            "qubits": qubits,
            "count": qry.count()
        }
        return self.render_template('admin_qubits_list.html', **params)

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
        f.country.choices = self.countries_tuple
        f.tz.choices = self.tz
        return f

class AdminIntakesHandler(BaseHandler):
    def get(self):
        params = {}        
        return self.render_template('admin_manual_intakes.html', **params)
    
    def post(self):

        params = {}
        import json
        logging.info(dir(self.form))
        dates = self.form.dates.data.strip()
        kwh = self.form.kwh.data.strip()
        money = self.form.money.data.strip()
        homeID = self.form.homeid.data.strip().replace('"','')
        erase = self.form.erase.data.strip()
        cfe_error = self.form.cfe_error.data.strip().replace('"','')
        intake_count = 0
        if homeID != '':            
            user_home = models.Home.get_by_id(long(homeID))
            if user_home:
                zipped = zip(json.loads(dates),json.loads(kwh),json.loads(money))
                msg = ""
                for row in zipped:
                    f_date = row[0]                    
                    intake = models.Intakes(date = date(int(f_date[:4]), int(f_date[5:7]), int(f_date[8:])), 
                                            kwh = int(row[1]), 
                                            bill = int(row[2]))
                    already_stored = False
                    for _intake in user_home.intakes:
                        if _intake.date == intake.date and _intake.kwh == intake.kwh and _intake.bill == intake.bill:
                            already_stored = True
                            break
                    
                    if not already_stored:
                        logging.info("Trying to allocate intake: %s" % intake)
                        if erase != 'SI':
                            user_home.intakes.insert(0,intake)
                            user_home.put()
                            msg = "(Added intakes)"
                    else:
                        logging.info("Already stored intake: %s" % intake)
                        if 'SI' in erase:
                            logging.info("Trying to delete intake: %s" % intake)
                            user_home.intakes.pop(user_home.intakes.index(intake))
                            user_home.put()
                            msg = "(Erased intakes)"
                
                #case no rows in zipped
                for _intake in user_home.intakes:
                        intake_count += 1

                if intake_count > 11:
                    user_home.cfe.connected = True
                    user_home.cfe.error = cfe_error
                    user_home.put()
                else:
                    user_home.cfe.connected = False
                    user_home.cfe.error = cfe_error
                    user_home.put()

                if 'intakes' in msg:
                    user_home.intakes = sorted(user_home.intakes, key=lambda intakes: intakes.date)
                    user_home.intakes.reverse()
                    user_home.put()

                msg = "Changes saved! " + msg + "[CFE Error Type:"+ cfe_error +"]"
                self.add_message(msg, 'success')

                return self.render_template('admin_manual_intakes.html', **params)
        else:
            self.add_message("No valid home ID !", 'danger')
        
        return self.render_template('admin_manual_intakes.html', **params)
    
    @webapp2.cached_property  
    def form(self):        
        return forms.admin_intakesForm(self)

class AdminHomeIntakesSorter(BaseHandler):
    def get(self):
        homes = models.Home.query()
        for home in homes:
            if len(home.intakes) > 1:
                home.intakes = sorted(home.intakes, key=lambda intakes: intakes.date)
                home.intakes.reverse()
                home.put()
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.write('Woah, intakes have been automagically sorted!')

class AdminBoxHandler(BaseHandler):
    def get(self):
        params = {}        
        return self.render_template('admin_box.html', **params)
    
    def post(self):
        params = {}
        serial = self.form.serial.data.strip()
        vera_user = self.form.vera_user.data.strip()
        vera_pass = self.form.vera_pass.data.strip()
        homeID = self.form.homeid.data.strip().replace('"','')
        if homeID != '':            
            user_home = models.Home.get_by_id(long(homeID))
            if user_home:
                msg = ""
                user_home.box = models.Boxes()
                user_home.box.serial = serial
                user_home.box.vera_user = vera_user
                user_home.box.vera_pass = vera_pass
                user_home.put()
                msg = "Changes saved!"
                self.add_message(msg, 'success')

                return self.render_template('admin_box.html', **params)
            else:
                self.add_message("No home with that ID, please check and retry !", 'danger')
                return self.render_template('admin_box.html', **params)
        else:
            self.add_message("No valid home ID !", 'danger')
            return self.render_template('admin_box.html', **params)
    
    @webapp2.cached_property  
    def form(self):        
        return forms.admin_BoxForm(self)

class AdminExportHomes(BaseHandler):
    
    def get(self):
        homes = models.Home.query()
        homes = homes.order(models.Home.created)
        consumos = []
        
        if self.request.get('q'):
            q = self.request.get('q')
            home = models.Home.get_by_id(long(q))
            for intake in home.intakes:
                    consumos.append({'id': str(home.key.id())+"_", 'fecha': intake.date.strftime("%Y-%m-%d"), 'consumo': intake.kwh, 'pago': intake.bill })
        else:
            for home in homes:
                for intake in home.intakes:
                    consumos.append({'id': str(home.key.id())+"_", 'fecha': intake.date.strftime("%Y-%m-%d"), 'consumo': intake.kwh, 'pago': intake.bill })
                                    
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(consumos))

class AdminExportUsers(BaseHandler):
    
    def get(self):
        usuarios= []
        home_id = self.request.get('homeid')
        if home_id is not None:
            logging.info("Received a home id")
            users = self.user_model.query(self.user_model.home_id == int(home_id))
            for user in users:
                    usuarios.append({'username': user.username, 'name': user.name, 'email': user.email, 'last_login': user.last_login, 'home_id': user.home_id})
        else:
            users = self.user_model.query()
            for user in users:
                    usuarios.append({'username': user.username, 'name': user.name, 'email': user.email, 'last_login': user.last_login, 'home_id': user.home_id})
                                    
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(usuarios))

class AdminExportStores(BaseHandler):
    
    def get(self):
        stores = models.Store.query()
        stores = stores.order(models.Store.created)
        data = []
        
        if self.request.get('q'):
            q = self.request.get('q')
            store = models.Store.get_by_id(long(q))
            data.append({'id': str(store.key.id())+"_", 'fecha': store.created.strftime("%Y-%m-%d") })
        else:
            for store in stores:
                data.append({'id': str(store.key.id())+"_", 'fecha': store.created.strftime("%Y-%m-%d")})
                                    
        self.response.headers.add_header("Access-Control-Allow-Origin", "*")
        self.response.headers['Content-Type'] = 'application/json'
        self.response.write(json.dumps(data))

class AdminEstimatorHandler(BaseHandler):
    def get(self):
        params = {}    
        params['home_id'] = False
        home_id = self.request.get('homeid')
        params['has_umr'] = True
        if home_id:
            user_home = models.Home.get_by_id(long(home_id))
            if user_home != None:
                params['home_id'] = home_id
                if len(user_home.umr) >= 1:
                    params['date'] = user_home.umr[len(user_home.umr)-1].date
                    params['period'] = user_home.umr[len(user_home.umr)-1].period
                    params['reading'] = user_home.umr[len(user_home.umr)-1].reading
                    params['pdf_date'] = user_home.umr[len(user_home.umr)-1].pdf_date
                    params['pdf_reading'] = user_home.umr[len(user_home.umr)-1].pdf_reading
                    for _umr in user_home.umr:
                        if _umr.period == params['period'] and _umr.date < params['date'] and _umr.reading != -1:
                            params['pdf_date'] = _umr.pdf_date
                            params['pdf_reading'] = _umr.pdf_reading
                            break
                else:
                    params['has_umr'] = False
                    msg = "No UMR for that Home ID!"
                    self.add_message(msg, 'danger')

        return self.render_template('admin_est.html', **params)
    
    def post(self):
        from datetime import date

        params = {}
        pdf_date = self.form.pdf_date.data.strip()
        period = self.form.period.data.strip()
        pdf_reading = self.form.pdf_reading.data
        reading = self.form.reading.data
        homeID = self.form.homeid.data.strip().replace('"','')
        if homeID != '':            
            user_home = models.Home.get_by_id(long(homeID))
            if user_home:
                msg = ""
                if len(user_home.umr) >= 1: 
                    _pdf_date = date(int(pdf_date[:4]), int(pdf_date[5:7]), int(pdf_date[8:]))
                    _pdf_reading = pdf_reading
                    _reading = reading
                    _period = user_home.umr[len(user_home.umr)-1].period
                    _date = user_home.umr[len(user_home.umr)-1].date
                    _picture = user_home.umr[len(user_home.umr)-1].picture

                    dates = []
                    kwhs = []
                    for _intake in user_home.intakes:
                        dates.append(_intake.date)
                        kwhs.append(_intake.kwh)
                    m = mycfe.getPeriod(dates)
                    pdArray = mycfe.getPeriodsArray(dates)
                    months = mycfe.getMonths(m,pdArray,pdArray[0].month)
                    months_years = mycfe.getMonthsYears(m,pdArray,pdArray[0].month, pdArray[0].year)
                    year = int(months_years[0][4:])
                    if 'Dec' in months[m-1]:
                        year += 1
                    calculated_period = months[m-1].replace('Jan','Ene').replace('Apr','Abr').replace('Aug','Ago').replace('Dec','Dic') + '. ' + str(year)       
                    today = date.today()
                    diff = today - dates[0]
                    if m == 6:
                        avg_day_kwh = float(kwhs[m-1])/60
                    else:
                        avg_day_kwh = float(kwhs[m-1])/30
                    est_kwh = avg_day_kwh*diff.days
                    real_kwh = _reading - _pdf_reading 
                    _error = real_kwh - est_kwh 
                    
                    np = False
                    if _period != calculated_period:
                        _period = calculated_period
                        np = True

                    #update most recent user request
                    _umr = models.UMR(pdf_date= _pdf_date, 
                                      pdf_reading = int(_pdf_reading),
                                      date = _date, 
                                      period = _period, 
                                      picture = _picture, 
                                      reading = int(_reading), 
                                      error = int(_error))                 
                    user_home.umr[len(user_home.umr)-1] = _umr
                    user_home.put()

                    msg = "Changes saved, updated period !" if np else "Changes saved!"
                    self.add_message(msg, 'success')
                    return self.render_template('admin_est.html', **params)
                else:
                    self.add_message("No UMR for that Home ID, please check and retry !", 'danger')
                    return self.render_template('admin_est.html', **params)
            else:
                self.add_message("No home with that ID, please check and retry !", 'danger')
                return self.render_template('admin_est.html', **params)
        else:
            self.add_message("No valid home ID !", 'danger')
            return self.render_template('admin_est.html', **params)
    
    @webapp2.cached_property  
    def form(self):        
        return forms.admin_EstForm(self)
        
        
        
