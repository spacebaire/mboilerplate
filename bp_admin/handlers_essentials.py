# -*- coding: utf-8 -*-
import logging
from bp_includes.lib.basehandler import BaseHandler
from google.appengine.api import users
from bp_includes import forms, models, handlers, messages
from google.appengine.api import taskqueue
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
            params['brand_about'] = self.app.config.get('brand_about') if brand.brand_about == '' else brand.brand_about 

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
            params['brand_about'] = self.app.config.get('brand_about')

        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/essentials/admin_brand.html' % self.app.config.get('app_lang'), **params)


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
            brand.brand_about = self.request.get('brand_about') if self.request.get('brand_about') != '' else self.app.config.get('brand_about')
            brand.put()
            self.add_message(messages.saving_success, 'success')
            return self.get()
        except Exception as e:
            logging.info('error in branding post: %s' % e)
            self.add_message(messages.saving_error, 'danger')
            return self.get()

class AdminContentsHandler(BaseHandler):
    """
    Handler to show the map page
    """
    def get(self):
        """ Returns a simple HTML form for branding setup """
        params = {}

        contents = models.Content.query()
        params['videos'] = contents.filter(models.Content.kind == 'video')
        params['v_count'] = params['videos'].count()
        params['audios'] = contents.filter(models.Content.kind == 'audio')
        params['a_count'] = params['audios'].count()
        params['images'] = contents.filter(models.Content.kind == 'image')
        params['i_count'] = params['images'].count()
        params['documents'] = contents.filter(models.Content.kind == 'document')
        params['d_count'] = params['documents'].count()
        params['surveys'] = contents.filter(models.Content.kind == 'survey')
        params['s_count'] = params['surveys'].count()

        params['nickname'] = g_users.get_current_user().email().lower()

        return self.render_template('%s/essentials/admin_contents.html' % self.app.config.get('app_lang'), **params)


    def post(self):
        try:
            if len(self.request.get('content_id')) > 12:
                try:
                    content = models.Content.get_by_id(long(self.request.get('content_id')))
                    logging.info('content to edit: %s' % content)
                except Exception as e:
                    logging.info('error getting content: %s' % e)
                    content = models.Content()
                    logging.info('content to create %s' % content)
                    pass
            else:
                content = models.Content()
                logging.info('content to create %s' % content)

            content.permission = int(self.request.get('permission'))
            content.title = self.request.get('title')
            content.subtitle = self.request.get('subtitle')
            content.description = self.request.get('description')
            content.kind = self.request.get('kind')
            content.link = self.request.get('link')
            content.put()

            self.add_message(messages.saving_success, 'success')
            return self.get()
        
        except Exception as e:
            logging.info('error in contents post: %s' % e)
            self.add_message(messages.saving_error, 'danger')
            return self.get()

class AdminContentDeleteHandler(BaseHandler):
    def get(self, content_id):
        if content_id != 1:
            content = models.Content.get_by_id(long(content_id))
            if content is not None:
                content.key.delete()
            self.add_message(messages.saving_success, 'success')
        return self.redirect_to('admin-contents')

class AdminContentShowHandler(BaseHandler):
    def get(self, content_id):
        if content_id != 1:
            content = models.Content.get_by_id(long(content_id))
            content.hidden = False
            content.put()
            self.add_message(messages.saving_success, 'success')
        return self.redirect_to('admin-contents')

class AdminContentHideHandler(BaseHandler):
    def get(self, content_id):
        if content_id != 1:
            content = models.Content.get_by_id(long(content_id))
            content.hidden = True
            content.put()
            self.add_message(messages.saving_success, 'success')
        return self.redirect_to('admin-contents')

class AdminSpecialsHandler(BaseHandler):
    def get(self):
        params = {}
        params['operators']  = models.SpecialAccess.query()
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/essentials/admin_specials.html' % self.app.config.get('app_lang'), **params)

    def post(self):
        try:
            #SECRETARY ADD
            logging.info("adding a new special access")
            operator = models.SpecialAccess()
            operator.email = self.request.get('adminemail') if self.request.get('adminemail') else ''
            operator.name = self.request.get('adminname') if self.request.get('adminname') else ''
            operator.role = self.request.get('adminrole') if self.request.get('adminrole') else 'Member'
            operator.put()

            user_info = models.User.get_by_email(operator.email)
            if user_info:
                user_info.role = operator.role
                user_info.put()

            #SEND EMAIL NOTIFICATION TO ADMIN_EMAIL
            template_val = {
                "_url": self.uri_for("register", _full=True),
                "brand_logo": self.brand['brand_logo'],
                "brand_email_logo": self.brand['brand_email_logo'],
                "brand_color": self.brand['brand_color'],
                "brand_secondary_color": self.brand['brand_secondary_color'],
                "support_url": self.uri_for("contact", _full=True),
                "twitter_url": self.app.config.get('twitter_url'),
                "facebook_url": self.app.config.get('facebook_url'),
                "faq_url": self.uri_for("faq", _full=True)
            }
            body_path = "%s/emails/special_access_invite.txt" % self.app.config.get('app_lang')
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': str(operator.email),
                'subject': messages.special_access,
                'body': body,
            })

            self.add_message(messages.saving_success, 'success')
            return self.get()
        except Exception as e:
            logging.info("error in saving to datastore: %s" % e)
            self.add_message(messages.saving_error, 'danger')
            return self.get()

class AdminSpecialsEditHandler(BaseHandler):
    def get_or_404(self, operator_id):
        try:
            operator = models.SpecialAccess.get_by_id(long(operator_id))
            if operator:
                return operator
        except ValueError:
            pass
        self.abort(404)

    def edit(self, operator_id):
        if self.request.POST:
            operator = self.get_or_404(operator_id)
            delete = self.request.get('delete')
            
            try:

                if delete == 'confirmed_deletion':
                    #DELETE REQUEST
                    operator_info = models.SpecialAccess.get_by_id(long(operator_id))
                    user_info = models.User.get_by_email(operator_info.email)
                    if user_info:
                        user_info.role = 'NA'
                        user_info.put()
                    operator_info.key.delete()
                    self.add_message(messages.saving_success, 'success')
                    return self.redirect_to("admin-specials")
                elif delete == 'operator_edition':
                    #OPERATOR EDITION
                    operator_info = models.SpecialAccess.get_by_id(long(operator_id))
                    operator_info.name = self.request.get('opsadminname') if self.request.get('opsadminname') else operator_info.name
                    operator_info.role = self.request.get('opsadminrole') if self.request.get('opsadminrole') else operator_info.role
                    if operator_info.email != self.request.get('opsadminemail') and self.request.get('opsadminemail') != '':
                        operator_info.email = self.request.get('opsadminemail')
                        #SEND EMAIL NOTIFICATION TO ADMIN_EMAIL
                        template_val = {
                            "_url": self.uri_for("register", _full=True),
                            "brand_logo": self.app.config.get('brand_logo'),
                            "brand_color": self.app.config.get('brand_color'),
                            "brand_secondary_color": self.app.config.get('brand_secondary_color'),
                            "support_url": self.uri_for("contact", _full=True),
                            "twitter_url": self.app.config.get('twitter_url'),
                            "facebook_url": self.app.config.get('facebook_url'),
                            "faq_url": self.uri_for("faq", _full=True)
                        }
                        body_path = "%s/emails/special_access_invite.txt" % self.app.config.get('app_lang')
                        body = self.jinja2.render_template(body_path, **template_val)

                        email_url = self.uri_for('taskqueue-send-email')
                        taskqueue.add(url=email_url, params={
                            'to': str(operator_info.email),
                            'subject': messages.special_access,
                            'body': body,
                        })
                    user_info = models.User.get_by_email(operator_info.email)
                    if user_info:
                        user_info.role = operator_info.role
                        user_info.put()
                    operator_info.put()

                    self.add_message(messages.saving_success, 'success')
                    return self.redirect_to("admin-specials-edit", operator_id=operator_id)

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating operator: %s ' % e)
                self.add_message(messages.saving_error, 'danger')
                return self.redirect_to("admin-specials-edit", operator_id=operator_id)
        else:
            operator = self.get_or_404(operator_id)

        params = {
            'operator': operator,
            '_user': models.User.get_by_email(operator.email)
        }
        params['nickname'] = g_users.get_current_user().email().lower()
        return self.render_template('%s/essentials/admin_specials_edit.html' % self.app.config.get('app_lang'), **params)
