# -*- coding: utf-8 -*-
from bp_includes.lib.basehandler import BaseHandler
from google.appengine.api import users
from bp_includes import forms, models, handlers, messages
from google.appengine.api import users as g_users #https://cloud.google.com/appengine/docs/python/refdocs/modules/google/appengine/api/users#get_current_user


class AdminLogoutHandler(BaseHandler):
    def get(self):
        self.redirect(users.create_logout_url(dest_url=self.uri_for('landing')))

class AdminBrandHandler(BaseHandler):
    """
    Handler to show the map page
    """
    def get(self):
        """ Returns a simple HTML form for branding setup """
        params = {}

        brand = models.Brand.query().get()

        if brand is not None:
            params['app_name'] = self.app.config.get('app_name') if brand.app_name == '' else brand.app_name 
            params['brand_layout'] = self.app.config.get('brand_layout') if brand.brand_layout == '' else brand.brand_layout 
            params['brand_video'] = self.app.config.get('brand_video') if brand.brand_video == '' else brand.brand_video 
            params['brand_splash'] = self.app.config.get('brand_splash') if brand.brand_splash == '' else brand.brand_splash 
            params['brand_splash_light'] = self.app.config.get('brand_splash_light') if brand.brand_splash_light == '' else brand.brand_splash_light
            params['brand_logo'] = self.app.config.get('brand_logo') if brand.brand_logo == '' else brand.brand_logo 
            params['brand_email_logo'] = self.app.config.get('brand_email_logo') if brand.brand_email_logo == '' else brand.brand_email_logo 
            params['brand_favicon'] = self.app.config.get('brand_favicon') if brand.brand_favicon == '' else brand.brand_favicon 
            params['brand_color'] = self.app.config.get('brand_color') if brand.brand_color == '' else brand.brand_color 
            params['brand_secondary_color'] = self.app.config.get('brand_secondary_color') if brand.brand_secondary_color == '' else brand.brand_secondary_color 
            params['brand_tertiary_color'] = self.app.config.get('brand_tertiary_color') if brand.brand_tertiary_color == '' else brand.brand_tertiary_color 

        else:
            params['app_name'] = self.app.config.get('app_name')
            params['brand_layout'] = self.app.config.get('brand_layout')
            params['brand_video'] = self.app.config.get('brand_video')
            params['brand_splash'] = self.app.config.get('brand_splash')
            params['brand_splash_light'] = self.app.config.get('brand_splash_light')
            params['brand_logo'] = self.app.config.get('brand_logo')
            params['brand_email_logo'] = self.app.config.get('brand_email_logo')
            params['brand_favicon'] = self.app.config.get('brand_favicon')
            params['brand_color'] = self.app.config.get('brand_color')
            params['brand_secondary_color'] = self.app.config.get('brand_secondary_color')
            params['brand_tertiary_color'] = self.app.config.get('brand_tertiary_color')

        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('essentials/admin_brand.html', **params)


    def post(self):
        """ Saves a simple HTML form for branding setup """
        try:
            brand = models.Brand.query().get()
            if brand is None:
                brand = models.Brand()

            brand.app_name = self.request.get('app_name') if self.request.get('app_name') != '' else self.app.config.get('app_name')
            brand.brand_layout = self.request.get('brand_layout') if self.request.get('brand_layout') != '' else self.app.config.get('brand_layout')
            brand.brand_video = self.request.get('brand_video') if self.request.get('brand_video') != '' else self.app.config.get('brand_video')
            brand.brand_splash = self.request.get('brand_splash') if self.request.get('brand_splash') != '' else self.app.config.get('brand_splash')
            brand.brand_splash_light = self.request.get('brand_splash_light') if self.request.get('brand_splash_light') != '' else self.app.config.get('brand_splash_light')
            brand.brand_logo = self.request.get('brand_logo') if self.request.get('brand_logo') != '' else self.app.config.get('brand_logo')
            brand.brand_email_logo = self.request.get('brand_email_logo') if self.request.get('brand_email_logo') != '' else self.app.config.get('brand_email_logo')
            brand.brand_favicon = self.request.get('brand_fav_logo') if self.request.get('brand_fav_logo') != '' else self.app.config.get('brand_favicon')
            brand.brand_color = self.request.get('brand_color') if self.request.get('brand_color') != '' else self.app.config.get('brand_color')
            brand.brand_secondary_color = self.request.get('brand_secondary_color') if self.request.get('brand_secondary_color') != '' else self.app.config.get('brand_secondary_color')
            brand.brand_tertiary_color = self.request.get('brand_tertiary_color') if self.request.get('brand_tertiary_color') != '' else self.app.config.get('brand_tertiary_color')
            brand.put()
            self.add_message(messages.saving_success, 'success')
            return self.get()
        except Exception as e:
            logging.info('error in branding post: %s' % e)
            self.add_message(messages.saving_error, 'danger')
            return self.get()


