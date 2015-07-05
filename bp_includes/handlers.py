# -*- coding: utf-8 -*-

"""
    A real simple app for using webapp2 with auth and session.

    It just covers the basics. Creating a user, login, logout
    and a decorator for protecting certain handlers.

    Routes are setup in routes.py and added in main.py
"""
# standard library imports
import logging
import json
import requests
from datetime import date, timedelta
import time

# related third party imports
import webapp2
from webapp2_extras import security
from webapp2_extras.auth import InvalidAuthIdError, InvalidPasswordError
from webapp2_extras.i18n import gettext as _
from webapp2_extras.appengine.auth.models import Unique
from google.appengine.ext import ndb
from google.appengine.api import taskqueue
from google.appengine.api import users
from google.appengine.api import images
from google.appengine.api.datastore_errors import BadValueError
from google.appengine.runtime import apiproxy_errors
from github import github
from linkedin import linkedin

# local application/library specific imports
import models
import forms as forms
import messages
from lib import utils, captcha, twitter, bitly, myhtmlparser
from lib.cartodb import CartoDBAPIKey, CartoDBException
from lib.basehandler import BaseHandler
from lib.decorators import user_required
from lib.decorators import taskqueue_method
from lib import facebook



""" ACCOUNT handlers 

    These handlers include all classes concerning the login and logout interactions with users.

"""
class LoginRequiredHandler(BaseHandler):
    def get(self):
        continue_url = self.request.get_all('continue')
        self.redirect(users.create_login_url(dest_url=continue_url))

# class LoginHandler(BaseHandler):
#     """
#     Handler for authentication
#     """

#     def get(self):
#         """ Returns a simple HTML form for login """

#         if self.user:
#             self.redirect_to('home')
#         chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
#         if self.app.config.get('captcha_public_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
#                         self.app.config.get('captcha_private_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
#             chtml = '<div class="alert alert-danger"><strong>Error</strong>: You have to ' \
#                     '<a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
#                     'for API keys</a> in order to use reCAPTCHA.</div>' \
#                     '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
#                     '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
#         params = {
#             'captchahtml': chtml,
#         }
#         continue_url = self.request.get('continue').encode('ascii', 'ignore')
#         params['continue_url'] = continue_url
#         return self.render_template('login.html', **params)

#     def post(self):
#         """
#         username: Get the username from POST dict
#         password: Get the password from POST dict
#         """

#         if not self.form.validate():
# 			_message = _(messages.post_error)
# 			self.add_message(_message, 'danger')
# 			return self.get()
#         username = self.form.username.data.lower()
#         continue_url = self.request.get('continue').encode('ascii', 'ignore')

#         try:
#             if utils.is_email_valid(username):
#                 user = self.user_model.get_by_email(username)
#                 if user:
#                     auth_id = user.auth_ids[0]
#                 else:
#                     raise InvalidAuthIdError
#             else:
#                 auth_id = "own:%s" % username
#                 user = self.user_model.get_by_auth_id(auth_id)
            
#             password = self.form.password.data.strip()
#             remember_me = True if str(self.request.POST.get('remember_me')) == 'on' else False

#             # Password to SHA512
#             password = utils.hashing(password, self.app.config.get('salt'))

#             # Try to login user with password
#             # Raises InvalidAuthIdError if user is not found
#             # Raises InvalidPasswordError if provided password
#             # doesn't match with specified user
#             self.auth.get_user_by_password(
#                 auth_id, password, remember=remember_me)

#             # if user account is not activated, logout and redirect to home
#             if (user.activated == False):
#                 # logout
#                 self.auth.unset_session()

#                 # redirect to home with error message
#                 resend_email_uri = self.uri_for('resend-account-activation', user_id=user.get_id(),
#                                                 token=self.user_model.create_resend_token(user.get_id()))
#                 message = _(messages.inactive_account) + ' ' + resend_email_uri
#                 self.add_message(message, 'danger')
#                 return self.redirect_to('login')
#             else:
#                 try:
#                     user.last_login = utils.get_date_time()
#                     user.put()
#                 except (apiproxy_errors.OverQuotaError, BadValueError):
#                     logging.error("Error saving Last Login in datastore")

#             # check twitter association in session
#             twitter_helper = twitter.TwitterAuth(self)
#             twitter_association_data = twitter_helper.get_association_data()
#             if twitter_association_data is not None:
#                 if models.SocialUser.check_unique(user.key, 'twitter', str(twitter_association_data['id'])):
#                     social_user = models.SocialUser(
#                         user=user.key,
#                         provider='twitter',
#                         uid=str(twitter_association_data['id']),
#                         extra_data=twitter_association_data
#                     )
#                     social_user.put()

#             # check facebook association
#             fb_data = None
#             try:
#                 fb_data = json.loads(self.session['facebook'])
#             except:
#                 pass

#             if fb_data is not None:
#                 if models.SocialUser.check_unique(user.key, 'facebook', str(fb_data['id'])):
#                     social_user = models.SocialUser(
#                         user=user.key,
#                         provider='facebook',
#                         uid=str(fb_data['id']),
#                         extra_data=fb_data
#                     )
#                     social_user.put()

#             # check linkedin association
#             li_data = None
#             try:
#                 li_data = json.loads(self.session['linkedin'])
#             except:
#                 pass

#             if li_data is not None:
#                 if models.SocialUser.check_unique(user.key, 'linkedin', str(li_data['id'])):
#                     social_user = models.SocialUser(
#                         user=user.key,
#                         provider='linkedin',
#                         uid=str(li_data['id']),
#                         extra_data=li_data
#                     )
#                     social_user.put()

#             # end linkedin

#             if self.app.config['log_visit']:
#                 try:
#                     logVisit = models.LogVisit(
#                         user=user.key,
#                         uastring=self.request.user_agent,
#                         ip=self.request.remote_addr,
#                         timestamp=utils.get_date_time()
#                     )
#                     logVisit.put()
#                 except (apiproxy_errors.OverQuotaError, BadValueError):
#                     logging.error("Error saving Visit Log in datastore")
#             if continue_url:
#                 self.redirect(continue_url)
#             else:
#                 self.redirect_to('home')
#         except (InvalidAuthIdError, InvalidPasswordError), e:
#             # Returns error message to self.response.write in
#             # the BaseHandler.dispatcher
#             message = _(messages.user_pass_mismatch)
#             self.add_message(message, 'danger')
#             self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to('login')

#     @webapp2.cached_property
#     def form(self):
#         return forms.LoginForm(self)

class SocialLoginHandler(BaseHandler):
    """
    Handler for Social authentication
    """

    def get(self, provider_name):
        provider = self.provider_info[provider_name]

        if not self.app.config.get('enable_federated_login'):
            message = _('Federated login is disabled.')
            self.add_message(message, 'warning')
            return self.redirect_to('login')
        callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)

        if provider_name == "twitter":
            twitter_helper = twitter.TwitterAuth(self, redirect_uri=callback_url)
            self.redirect(twitter_helper.auth_url())

        elif provider_name == "facebook":
            self.session['linkedin'] = None
            perms = ['email', 'publish_stream']
            self.redirect(facebook.auth_url(self.app.config.get('fb_api_key'), callback_url, perms))

        elif provider_name == 'linkedin':
            self.session['facebook'] = None
            authentication = linkedin.LinkedInAuthentication(
                self.app.config.get('linkedin_api'),
                self.app.config.get('linkedin_secret'),
                callback_url,
                [linkedin.PERMISSIONS.BASIC_PROFILE, linkedin.PERMISSIONS.EMAIL_ADDRESS])
            self.redirect(authentication.authorization_url)

        elif provider_name == "github":
            scope = 'gist'
            github_helper = github.GithubAuth(self.app.config.get('github_server'),
                                              self.app.config.get('github_client_id'), \
                                              self.app.config.get('github_client_secret'),
                                              self.app.config.get('github_redirect_uri'), scope)
            self.redirect(github_helper.get_authorize_url())

        elif provider_name in models.SocialUser.open_id_providers():
            continue_url = self.request.get('continue_url')
            if continue_url:
                dest_url = self.uri_for('social-login-complete', provider_name=provider_name, continue_url=continue_url)
            else:
                dest_url = self.uri_for('social-login-complete', provider_name=provider_name)
            try:
                login_url = users.create_login_url(federated_identity=provider['uri'], dest_url=dest_url)
                self.redirect(login_url)
            except users.NotAllowedError:
                self.add_message('You must enable Federated Login Before for this application.<br> '
                                 '<a href="http://appengine.google.com" target="_blank">Google App Engine Control Panel</a> -> '
                                 'Administration -> Application Settings -> Authentication Options', 'danger')
                self.redirect_to('login')

        else:
            message = _('%s authentication is not yet implemented.' % provider.get('label'))
            self.add_message(message, 'warning')
            self.redirect_to('login')

class CallbackSocialLoginHandler(BaseHandler):
    """
    Callback (Save Information) for Social Authentication
    """

    def get(self, provider_name):
        if not self.app.config.get('enable_federated_login'):
            message = _('Federated login is disabled.')
            self.add_message(message, 'warning')
            return self.redirect_to('login')
        continue_url = self.request.get('continue_url')
        if provider_name == "twitter":
            oauth_token = self.request.get('oauth_token')
            oauth_verifier = self.request.get('oauth_verifier')
            twitter_helper = twitter.TwitterAuth(self)
            user_data = twitter_helper.auth_complete(oauth_token,
                                                     oauth_verifier)
            logging.info('twitter user_data: ' + str(user_data))
            if self.user:
                # new association with twitter
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'twitter', str(user_data['user_id'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='twitter',
                        uid=str(user_data['user_id']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Twitter association added.')
                    self.add_message(message, 'success')
                else:
                    message = _('This Twitter account is already in use.')
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with twitter
                social_user = models.SocialUser.get_by_provider_and_uid('twitter',
                                                                        str(user_data['user_id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    uid = str(user_data['user_id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)

        # github association
        elif provider_name == "github":
            # get our request code back from the social login handler above
            code = self.request.get('code')

            # create our github auth object
            scope = 'gist'
            github_helper = github.GithubAuth(self.app.config.get('github_server'),
                                              self.app.config.get('github_client_id'), \
                                              self.app.config.get('github_client_secret'),
                                              self.app.config.get('github_redirect_uri'), scope)

            # retrieve the access token using the code and auth object
            access_token = github_helper.get_access_token(code)
            user_data = github_helper.get_user_info(access_token)
            logging.info('github user_data: ' + str(user_data))
            if self.user:
                # user is already logged in so we set a new association with twitter
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'github', str(user_data['login'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='github',
                        uid=str(user_data['login']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Github association added.')
                    self.add_message(message, 'success')
                else:
                    message = _('This Github account is already in use.')
                    self.add_message(message, 'danger')
                self.redirect_to('edit-profile')
            else:
                # user is not logged in, but is trying to log in via github
                social_user = models.SocialUser.get_by_provider_and_uid('github', str(user_data['login']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    self.redirect_to('home')
                else:
                    uid = str(user_data['id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)
        #end github

        # facebook association
        elif provider_name == "facebook":
            code = self.request.get('code')
            callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)
            token = facebook.get_access_token_from_code(code, callback_url, self.app.config.get('fb_api_key'),
                                                        self.app.config.get('fb_secret'))
            access_token = token['access_token']
            fb = facebook.GraphAPI(access_token)
            user_data = fb.get_object('me')
            logging.info('facebook user_data: ' + str(user_data))
            if self.user:
                # new association with facebook
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'facebook', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='facebook',
                        uid=str(user_data['id']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Facebook association added!')
                    self.add_message(message, 'success')
                else:
                    message = _('This Facebook account is already in use!')
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with Facebook
                social_user = models.SocialUser.get_by_provider_and_uid('facebook',
                                                                        str(user_data['id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    uid = str(user_data['id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)

                    # end facebook
        # association with linkedin
        elif provider_name == "linkedin":
            callback_url = "%s/social_login/%s/complete" % (self.request.host_url, provider_name)
            authentication = linkedin.LinkedInAuthentication(
                self.app.config.get('linkedin_api'),
                self.app.config.get('linkedin_secret'),
                callback_url,
                [linkedin.PERMISSIONS.BASIC_PROFILE, linkedin.PERMISSIONS.EMAIL_ADDRESS])
            authentication.authorization_code = self.request.get('code')
            access_token = authentication.get_access_token()
            link = linkedin.LinkedInApplication(authentication)
            u_data = link.get_profile(selectors=['id', 'first-name', 'last-name', 'email-address'])
            user_data = {
                'first_name': u_data.get('firstName'),
                'last_name': u_data.get('lastName'),
                'id': u_data.get('id'),
                'email': u_data.get('emailAddress')}
            self.session['linkedin'] = json.dumps(user_data)
            logging.info('linkedin user_data: ' + str(user_data))

            if self.user:
                # new association with linkedin
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, 'linkedin', str(user_data['id'])):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider='linkedin',
                        uid=str(user_data['id']),
                        extra_data=user_data
                    )
                    social_user.put()

                    message = _('Linkedin association added!')
                    self.add_message(message, 'success')
                else:
                    message = _('This Linkedin account is already in use!')
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with Linkedin
                social_user = models.SocialUser.get_by_provider_and_uid('linkedin',
                                                                        str(user_data['id']))
                if social_user:
                    # Social user exists. Need authenticate related site account
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    uid = str(user_data['id'])
                    email = str(user_data.get('email'))
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url, user_data)

                    #end linkedin

        # google, myopenid, yahoo OpenID Providers
        elif provider_name in models.SocialUser.open_id_providers():
            provider_display_name = models.SocialUser.PROVIDERS_INFO[provider_name]['label']
            # get info passed from OpenID Provider
            from google.appengine.api import users

            current_user = users.get_current_user()
            if current_user:
                if current_user.federated_identity():
                    uid = current_user.federated_identity()
                else:
                    uid = current_user.user_id()
                email = current_user.email()
            else:
                message = _('No user authentication information received from %s. '
                            'Please ensure you are logging in from an authorized OpenID Provider (OP).'
                            % provider_display_name)
                self.add_message(message, 'danger')
                return self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to(
                    'login')
            if self.user:
                # add social account to user
                user_info = self.user_model.get_by_id(long(self.user_id))
                if models.SocialUser.check_unique(user_info.key, provider_name, uid):
                    social_user = models.SocialUser(
                        user=user_info.key,
                        provider=provider_name,
                        uid=uid
                    )
                    social_user.put()

                    message = _('%s association successfully added.' % provider_display_name)
                    self.add_message(message, 'success')
                else:
                    message = _('This %s account is already in use.' % provider_display_name)
                    self.add_message(message, 'danger')
                if continue_url:
                    self.redirect(continue_url)
                else:
                    self.redirect_to('edit-profile')
            else:
                # login with OpenID Provider
                social_user = models.SocialUser.get_by_provider_and_uid(provider_name, uid)
                if social_user:
                    # Social user found. Authenticate the user
                    user = social_user.user.get()
                    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
                    if self.app.config['log_visit']:
                        try:
                            logVisit = models.LogVisit(
                                user=user.key,
                                uastring=self.request.user_agent,
                                ip=self.request.remote_addr,
                                timestamp=utils.get_date_time()
                            )
                            logVisit.put()
                        except (apiproxy_errors.OverQuotaError, BadValueError):
                            logging.error("Error saving Visit Log in datastore")
                    if continue_url:
                        self.redirect(continue_url)
                    else:
                        self.redirect_to('home')
                else:
                    self.create_account_from_social_provider(provider_name, uid, email, continue_url)
        else:
            message = _('This authentication method is not yet implemented.')
            self.add_message(message, 'warning')
            self.redirect_to('login', continue_url=continue_url) if continue_url else self.redirect_to('login')

    def create_account_from_social_provider(self, provider_name, uid, email=None, continue_url=None, user_data=None):
        """Social user does not exist yet so create it with the federated identity provided (uid)
        and create prerequisite user and log the user account in
        """
        provider_display_name = models.SocialUser.PROVIDERS_INFO[provider_name]['label']
        if models.SocialUser.check_unique_uid(provider_name, uid):
            # create user
            # Returns a tuple, where first value is BOOL.
            # If True ok, If False no new user is created
            # Assume provider has already verified email address
            # if email is provided so set activated to True
            auth_id = "%s:%s" % (provider_name, uid)
            if email:
                unique_properties = ['email']
                user_info = self.auth.store.user_model.create_user(
                    auth_id, unique_properties, email=email,
                    activated=True
                )
            else:
                user_info = self.auth.store.user_model.create_user(
                    auth_id, activated=True
                )
            if not user_info[0]: #user is a tuple
                message = _('The account %s is already in use.' % provider_display_name)
                self.add_message(message, 'danger')
                return self.redirect_to('register')

            user = user_info[1]

            # create social user and associate with user
            social_user = models.SocialUser(
                user=user.key,
                provider=provider_name,
                uid=uid,
            )
            if user_data:
                social_user.extra_data = user_data
                self.session[provider_name] = json.dumps(user_data) # TODO is this needed?
            social_user.put()
            # authenticate user
            self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)
            if self.app.config['log_visit']:
                try:
                    logVisit = models.LogVisit(
                        user=user.key,
                        uastring=self.request.user_agent,
                        ip=self.request.remote_addr,
                        timestamp=utils.get_date_time()
                    )
                    logVisit.put()
                except (apiproxy_errors.OverQuotaError, BadValueError):
                    logging.error("Error saving Visit Log in datastore")

            message = _('Welcome!  You have been registered as a new user '
                        'and logged in through {}.').format(provider_display_name)
            self.add_message(message, 'success')
        else:
            message = _('This %s account is already in use.' % provider_display_name)
            self.add_message(message, 'danger')
        if continue_url:
            self.redirect(continue_url)
        else:
            self.redirect_to('edit-profile')

class DeleteSocialProviderHandler(BaseHandler):
    """
    Delete Social association with an account
    """

    @user_required
    def post(self, provider_name):
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if len(user_info.get_social_providers_info()['used']) > 1 and user_info.password is not None:
                social_user = models.SocialUser.get_by_user_and_provider(user_info.key, provider_name)
                if social_user:
                    social_user.key.delete()
                    message = _('%s successfully disassociated.' % provider_name)
                    self.add_message(message, 'success')
                else:
                    message = _('Social account on %s not found for this user.' % provider_name)
                    self.add_message(message, 'danger')
            else:
                message = ('Social account on %s cannot be deleted for user.'
                           '  Please create a username and password to delete social account.' % provider_name)
                self.add_message(message, 'danger')
        self.redirect_to('edit-profile')

class SendEmailHandler(BaseHandler):
    """
    Core Handler for sending Emails
    Use with TaskQueue
    """

    @taskqueue_method
    def post(self):

        from google.appengine.api import mail, app_identity
        from lib import sendgrid
        from lib.sendgrid import SendGridError, SendGridClientError, SendGridServerError 

        to = self.request.get("to")
        subject = self.request.get("subject")
        body = self.request.get("body")
        sender = self.request.get("sender")

        if sender != '' or not utils.is_email_valid(sender):
            if utils.is_email_valid(self.app.config.get('contact_sender')):
                sender = self.app.config.get('contact_sender')
            else:
                app_id = app_identity.get_application_id()
                sender = "MBoilerplate Mail <no-reply@%s.appspotmail.com>" % (app_id)

        if self.app.config['log_email']:
            try:
                logEmail = models.LogEmail(
                    sender=sender,
                    to=to,
                    subject=subject,
                    body=body,
                    when=utils.get_date_time("datetimeProperty")
                )
                logEmail.put()
            except (apiproxy_errors.OverQuotaError, BadValueError):
                logging.error("Error saving Email Log in datastore")




        #using appengine email 
        try:            
            message = mail.EmailMessage()
            message.sender = sender
            message.to = to
            message.subject = subject
            message.html = body
            message.send()
            logging.info("... sending email to: %s ..." % to)
        except Exception, e:
            logging.error("Error sending email: %s" % e)


        # using sendgrid
        # try:
        #     sg = sendgrid.SendGridClient(self.app.config.get('sendgrid_login'), self.app.config.get('sendgrid_passkey'))
        #     logging.info("sending with sendgrid client: %s" % sg)
        #     message = sendgrid.Mail()
        #     message.add_to(to)
        #     message.set_subject(subject)
        #     message.set_html(body)
        #     message.set_text(body)
        #     message.set_from(sender)
        #     status, msg = sg.send(message)
        # except Exception, e:
        #     logging.error("Error sending email: %s" % e)

class PasswordResetHandler(BaseHandler):
    """
    Password Reset Handler with Captcha
    """

    def get(self):
        if self.user:
            self.auth.unset_session()

        chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
        params = {
            'captchahtml': chtml,
        }
        return self.render_template('password_reset.html', **params)

    def post(self):
        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.redirect_to('password-reset')

        #check if we got an email or username
        email_or_username = str(self.request.POST.get('email_or_username')).lower().strip()
        if utils.is_email_valid(email_or_username):
            user = self.user_model.get_by_email(email_or_username)
            _message = _("Si el correo que ingresaste")
        else:
            auth_id = "own:%s" % email_or_username
            user = self.user_model.get_by_auth_id(auth_id)
            _message = _("Revisa tu correo con las instrucciones para cambiar tu password. Tip: Revisa tu spam.")

        if user is not None:
            user_id = user.get_id()
            token = self.user_model.create_auth_token(user_id)
            email_url = self.uri_for('taskqueue-send-email')
            reset_url = self.uri_for('password-reset-check', user_id=user_id, token=token, _full=True)
            subject = _(messages.email_passwordassist_subject)

            # load email's template
            template_val = {
                "username": user.name,
                "email": user.email,
                "reset_password_url": reset_url,
                "support_url": self.uri_for("contact", _full=True),
                "faq_url": self.uri_for("faq", _full=True),
                "app_name": self.app.config.get('app_name'),
            }

            body_path = "emails/reset_password.txt"
            body = self.jinja2.render_template(body_path, **template_val)
            taskqueue.add(url=email_url, params={
                'to': user.email,
                'subject': subject,
                'body': body,
                'sender': self.app.config.get('contact_sender'),
            })
        self.add_message(_message, 'warning')
        return self.redirect_to('materialize-login')

class PasswordResetCompleteHandler(BaseHandler):
    """
    Handler to process the link of reset password that received the user
    """

    def get(self, user_id, token):
        verify = self.user_model.get_by_auth_token(int(user_id), token)
        params = {}
        if verify[0] is None:
            message = _(messages.password_reset_invalid_link)
            self.add_message(message, 'warning')
            return self.redirect_to('password-reset')

        else:
            user = self.user_model.get_by_id(long(user_id))
            params = {
                '_username':user.name
            }
            return self.render_template('password_reset_complete.html', **params)

    def post(self, user_id, token):
        verify = self.user_model.get_by_auth_token(int(user_id), token)
        user = verify[0]
        password = self.form.password.data.strip()
        if user and self.form.validate():
            # Password to SHA512
            password = utils.hashing(password, self.app.config.get('salt'))

            user.password = security.generate_password_hash(password, length=12)
            user.put()
            # Delete token
            self.user_model.delete_auth_token(int(user_id), token)
            # Login User
            self.auth.get_user_by_password(user.auth_ids[0], password)
            self.add_message(_(messages.passwordchange_success), 'success')
            return self.redirect_to('materialize-home')

        else:
            self.add_message(_(messages.passwords_mismatch), 'danger')
            return self.redirect_to('password-reset-check', user_id=user_id, token=token)

    @webapp2.cached_property
    def form(self):
        return forms.PasswordResetCompleteForm(self)




""" REGISTRATION handlers 

    These handlers concern registration in 2 ways: direct, or from referral.

"""
class RegisterBaseHandler(BaseHandler):
    """
    Base class for handlers with registration and login forms.
    """

    @webapp2.cached_property
    def form(self):
        return forms.RegisterForm(self)

class MaterializeRegisterReferralHandler(BaseHandler):
    """
    Handler to process the link of referrals for a given user_id
    """

    def get(self, user_id):
        if self.user:
            self.redirect_to('materialize-home')
        user = self.user_model.get_by_id(long(user_id))
        chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
        if self.app.config.get('captcha_public_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
                        self.app.config.get('captcha_private_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
            chtml = '<div class="alert alert-danger"><strong>Error</strong>: You have to ' \
                    '<a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
                    'for API keys</a> in order to use reCAPTCHA.</div>' \
                    '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                    '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
        if user is not None:
            params = {
                'captchahtml': chtml,
                '_username': user.name,
                'is_referral' : True
            }
            return self.render_template('materialize/users/register.html', **params)
        else:
            return self.redirect_to('materialize-landing')

    def post(self, user_id):
        """ Get fields from POST dict """

        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.get(user_id)

        if not self.form.validate():
			_message = _(messages.saving_error)
			self.add_message(_message, 'danger')
			return self.get(user_id)
        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        email = self.form.email.data.lower()
        password = self.form.password.data.strip()

        # Password to SHA512
        password = utils.hashing(password, self.app.config.get('salt'))

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL.
        # If True ok, If False no new user is created
        unique_properties = ['username', 'email']
        auth_id = "own:%s" % username
        referred_user = self.auth.store.user_model.create_user(
            auth_id, unique_properties, password_raw=password,
            username=username, name=name, last_name=last_name, email=email,
            ip=self.request.remote_addr
        )

        if not referred_user[0]: #user is a tuple
            if "username" in str(referred_user[1]):
                message = _(messages.username_exists).format(username)
            elif "email" in str(referred_user[1]):
                message = _(messages.email_exists).format(email)
            else:
                message = _(messages.user_exists)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-register-referral',user_id=user_id, _full = True)
        else:
            # User registered successfully
            # But if the user registered using the form, the user has to check their email to activate the account ???
            try:
                if not referred_user[1].activated:
                    # send email
                    subject = _(messages.email_activation_subject)
                    confirmation_url = self.uri_for("materialize-account-activation-referral",
                                                    ref_user_id=referred_user[1].get_id(),
                                                    token=self.user_model.create_auth_token(referred_user[1].get_id()),
                                                    user_id =  user_id,
                                                    _full=True)
                    if name != '':
                        _username = str(name)
                    else:
                        _username = str(username)
                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": _username,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True),
						"faq_url": self.uri_for("faq", _full=True)
                    }
                    body_path = "emails/account_activation.txt"
                    body = self.jinja2.render_template(body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                    
                    #unlock rewards status for the user who referred this referred_user
                    already_invited = False;
                    user = self.user_model.get_by_id(long(user_id))
                    for reward in user.rewards:
                        if reward.content == email:
                            already_invited = True;
                            break

                    if not already_invited:
                        reward = models.Rewards(amount = 0,earned = True, category = 'invite',
                            content = email,timestamp = utils.get_date_time(),status = 'invited')                 
                        user.rewards.append(reward)
                        user.put()

                    message = _(messages.register_success)
                    self.add_message(message, 'success')
                    return self.redirect_to('materialize-landing')

                # If the user didn't register using registration form ???
                db_user = self.auth.get_user_by_password(referred_user[1].auth_ids[0], password)

                # Check Twitter association in session
                twitter_helper = twitter.TwitterAuth(self)
                twitter_association_data = twitter_helper.get_association_data()
                if twitter_association_data is not None:
                    if models.SocialUser.check_unique(referred_user[1].key, 'twitter', str(twitter_association_data['id'])):
                        social_user = models.SocialUser(
                            user=referred_user[1].key,
                            provider='twitter',
                            uid=str(twitter_association_data['id']),
                            extra_data=twitter_association_data
                        )
                        social_user.put()

                #check Facebook association
                fb_data = json.loads(self.session['facebook'])
                if fb_data is not None:
                    if models.SocialUser.check_unique(referred_user.key, 'facebook', str(fb_data['id'])):
                        social_user = models.SocialUser(
                            user=referred_user.key,
                            provider='facebook',
                            uid=str(fb_data['id']),
                            extra_data=fb_data
                        )
                        social_user.put()

                #check LinkedIn association
                li_data = json.loads(self.session['linkedin'])
                if li_data is not None:
                    if models.SocialUser.check_unique(referred_user.key, 'linkedin', str(li_data['id'])):
                        social_user = models.SocialUser(
                            user=referred_user.key,
                            provider='linkedin',
                            uid=str(li_data['id']),
                            extra_data=li_data
                        )
                        social_user.put()

                message = _(messages.logged).format(username)
                self.add_message(message, 'success')
                return self.redirect_to('materialize-home')
            except (AttributeError, KeyError), e:
                logging.error('Unexpected error creating the user %s: %s' % (username, e ))
                message = _(messages.user_creation_error).format(username)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-register-referral',user_id=user_id, _full = True)

    @webapp2.cached_property
    def form(self):
        f = forms.RegisterForm(self)
        return f

class MaterializeRegisterRequestHandler(BaseHandler):
    """
    Handler for Sign Up Users
    """

    def get(self):
        """ Returns a simple HTML form for create a new user """

        if self.user:
            self.redirect_to('materialize-home')
        chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
        params = {
            'captchahtml': chtml,
        }
        return self.render_template('materialize/users/register.html', **params)

    def post(self):
        """ Get fields from POST dict """

        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.redirect_to('materialize-register')

        if not self.form.validate():
            logging.info("Form did not passed.")
            _message = _(messages.saving_error)
            self.add_message(_message, 'danger')
            return self.get()
        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        email = self.form.email.data.lower()
        password = self.form.password.data.strip()

        # Password to SHA512
        password = utils.hashing(password, self.app.config.get('salt'))

        # Passing password_raw=password so password will be hashed
        # Returns a tuple, where first value is BOOL.
        # If True ok, If False no new user is created
        unique_properties = ['username', 'email']
        auth_id = "own:%s" % username
        user = self.auth.store.user_model.create_user(
            auth_id, unique_properties, password_raw=password,
            username=username, name=name, last_name=last_name, email=email,
            ip=self.request.remote_addr
        )

        if not user[0]: #user is a tuple
            if "username" in str(user[1]):
                message = _(messages.username_exists).format(username)
            elif "email" in str(user[1]):
                message = _(messages.email_exists).format(email)
            else:
                message = _(messages.user_exists)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-register')
        else:
            # User registered successfully
            # But if the user registered using the form, the user has to check their email to activate the account ???
            try:
                if not user[1].activated:
                    # send email
                    #subject = _("%s Account Verification" % self.app.config.get('app_name'))
                    subject = _(messages.email_activation_subject)
                    confirmation_url = self.uri_for("materialize-account-activation",
                                                    user_id=user[1].get_id(),
                                                    token=self.user_model.create_auth_token(user[1].get_id()),
                                                    _full=True)

                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": name,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True),
                        "faq_url": self.uri_for("faq", _full=True)
                    }
                    body_path = "emails/account_activation.txt"
                    body = self.jinja2.render_template(body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                    message = _(messages.register_success)
                    self.add_message(message, 'success')
                    return self.redirect_to('materialize-landing')

                # If the user didn't register using registration form ???
                db_user = self.auth.get_user_by_password(user[1].auth_ids[0], password)

                message = _(messages.logged).format(username)
                self.add_message(message, 'success')
                return self.redirect_to('materialize-landing')
            except (AttributeError, KeyError), e:
                logging.error('Unexpected error creating the user %s: %s' % (username, e ))
                message = _(messages.user_creation_error).format(username)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-landing')

    @webapp2.cached_property
    def form(self):
        f = forms.RegisterForm(self)
        return f

class MaterializeLoginRequestHandler(BaseHandler):
    """
    Handler for authentication
    """

    def get(self):
        """ Returns a simple HTML form for login """

        if self.user:
            self.redirect_to('materialize-home')
        chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
        params = {
            'captchahtml': chtml,
        }
        continue_url = self.request.get('continue').encode('ascii', 'ignore')
        params['continue_url'] = continue_url
        return self.render_template('materialize/users/login.html', **params)

    def post(self):
        """
        username: Get the username from POST dict
        password: Get the password from POST dict
        """

        if not self.form.validate():
            _message = _(messages.post_error)
            self.add_message(_message, 'danger')
            return self.get()
        username = self.form.username.data.lower()
        continue_url = self.request.get('continue').encode('ascii', 'ignore')

        try:
            if utils.is_email_valid(username):
                user = self.user_model.get_by_email(username)
                if user:
                    auth_id = user.auth_ids[0]
                else:
                    raise InvalidAuthIdError
            else:
                auth_id = "own:%s" % username
                user = self.user_model.get_by_auth_id(auth_id)
            
            password = self.form.password.data.strip()
            remember_me = True if str(self.request.POST.get('remember_me')) == 'on' else False

            # Password to SHA512
            password = utils.hashing(password, self.app.config.get('salt'))

            # Try to login user with password
            # Raises InvalidAuthIdError if user is not found
            # Raises InvalidPasswordError if provided password
            # doesn't match with specified user
            self.auth.get_user_by_password(
                auth_id, password, remember=remember_me)

            # if user account is not activated, logout and redirect to home
            if (user.activated == False):
                # logout
                self.auth.unset_session()

                # redirect to home with error message
                resend_email_uri = self.uri_for('resend-account-activation', user_id=user.get_id(),
                                                token=self.user_model.create_resend_token(user.get_id()))
                message = _(messages.inactive_account) + ' ' + resend_email_uri
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-login')
            else:
                try:
                    user.last_login = utils.get_date_time()
                    user.put()
                except (apiproxy_errors.OverQuotaError, BadValueError):
                    logging.error("Error saving Last Login in datastore")
            

            if self.app.config['log_visit']:
                try:
                    logVisit = models.LogVisit(
                        user=user.key,
                        uastring=self.request.user_agent,
                        ip=self.request.remote_addr,
                        timestamp=utils.get_date_time()
                    )
                    logVisit.put()
                except (apiproxy_errors.OverQuotaError, BadValueError):
                    logging.error("Error saving Visit Log in datastore")
            if continue_url:
                self.redirect(continue_url)
            else:
                self.redirect_to('materialize-home')
        except (InvalidAuthIdError, InvalidPasswordError), e:
            # Returns error message to self.response.write in
            # the BaseHandler.dispatcher
            message = _(messages.user_pass_mismatch)
            self.add_message(message, 'danger')
            self.redirect_to('materialize-login', continue_url=continue_url) if continue_url else self.redirect_to('materialize-login')

    @webapp2.cached_property
    def form(self):
        return forms.LoginForm(self)

class MaterializeLogoutRequestHandler(BaseHandler):
    """
    Destroy user session and redirect to login
    """

    def get(self):
        if self.user:
            message = _(messages.logout)
            self.add_message(message, 'info')

        self.auth.unset_session()
        # User is logged out, let's try redirecting to login page
        try:
            self.redirect_to('materialize-landing')
        except (AttributeError, KeyError), e:
            logging.error("Error logging out: %s" % e)
            message = _(messages.logout_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-landing')



""" ACTIVATION handlers 

    These handlers concern different email activations: direct, referral and roomie

"""

class MaterializeAccountActivationHandler(BaseHandler):
    """
    Handler for account activation
    """

    def get(self, user_id, token):
        try:
            if not self.user_model.validate_auth_token(user_id, token):
                message = _(messages.used_activation_link)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-login')

            user = self.user_model.get_by_id(long(user_id))
            # activate the user's account
            user.activated = True
            user.last_login = utils.get_date_time()
            
            # create unique url for sharing & referrals purposes
            long_url = self.uri_for("materialize-register-referral",user_id=user.get_id(),_full=True)
            logging.info("Long URL: %s" % long_url)
            
            #The goo.gl way:
            # post_url = 'https://www.googleapis.com/urlshortener/v1/url'            
            # payload = {'longUrl': long_url}
            # headers = {'content-type': 'application/json'}
            # r = requests.post(post_url, data=json.dumps(payload), headers=headers)
            # j = json.loads(r.text)
            # logging.info("Google response: %s" % j)
            # short_url = j['id']

            #The bit.ly way:
            api = bitly.Api(login=self.app.config.get('bitly_login'), apikey=self.app.config.get('bitly_apikey'))
            short_url=api.shorten(long_url)
            logging.info("Bitly response: %s" % short_url)

            user.link_referral = short_url
            reward = models.Rewards(amount = 100,earned = True, category = 'configuration',
                content = 'Activation',timestamp = utils.get_date_time(),status = 'completed')                 
            user.rewards.append(reward)

            #Role init
            user.role = 'Admin'

            #Datastore allocation
            user.put()

            # Login User
            self.auth.get_user_by_token(int(user_id), token)

            # Delete token
            self.user_model.delete_auth_token(user_id, token)

            # Slack Incoming WebHooks
            from google.appengine.api import urlfetch            
            urlfetch.fetch(self.app.config.get('slack_webhook_url'), payload='{"channel": "#general", "username": "webhookbot", "text": "just got a new user ! Go surprise him at '+user.email+'", "icon_emoji": ":bowtie:"}', method='POST')

            message = _(messages.activation_success).format(
                user.email)
            self.add_message(message, 'success')
            self.redirect_to('materialize-home')

        except (AttributeError, KeyError, InvalidAuthIdError, NameError), e:
            logging.error("Error activating an account: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-landing')

class MaterializeAccountActivationReferralHandler(BaseHandler):
    """
    Handler for account activation
    """

    def get(self, ref_user_id, token, user_id):
        try:
            if not self.user_model.validate_auth_token(ref_user_id, token):
                message = _(messages.used_activation_link)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-login')


            user = self.user_model.get_by_id(long(user_id))
            referred_user = self.user_model.get_by_id(long(ref_user_id))
            
            # activate the user's account            
            referred_user.activated = True
            referred_user.last_login = utils.get_date_time()
            
            # create unique url for sharing & referrals purposes
            long_url = self.uri_for("materialize-register-referral",user_id=referred_user.get_id(),_full=True)
            logging.info("Long URL: %s" % long_url)
            
            #The goo.gl way:
            # post_url = 'https://www.googleapis.com/urlshortener/v1/url'            
            # payload = {'longUrl': long_url}
            # headers = {'content-type': 'application/json'}
            # r = requests.post(post_url, data=json.dumps(payload), headers=headers)
            # j = json.loads(r.text)
            # logging.info("Google response: %s" % j)
            # short_url = j['id']

            #The bit.ly way:
            api = bitly.Api(login=self.app.config.get('bitly_login'), apikey=self.app.config.get('bitly_apikey'))
            short_url=api.shorten(long_url)
            logging.info("Bitly response: %s" % short_url)


            referred_user.link_referral = short_url
            reward = models.Rewards(amount = 100,earned = True, category = 'configuration',
                content = 'Activation',timestamp = utils.get_date_time(),status = 'completed')                 
            referred_user.rewards.append(reward)
            reward = models.Rewards(amount = 20,earned = True, category = 'invite',
                content = 'Invitee by: ' + user.email,timestamp = utils.get_date_time(),status = 'completed')                 
            referred_user.rewards.append(reward)


            #Role init
            referred_user.role = 'Admin'

            #Datastore allocation
            referred_user.put()
            
            # assign the referral reward
            for reward in user.rewards:
                if reward.content == referred_user.email:
                    reward.amount = 50;
                    reward.status = 'joined';
                    user.put()
                    break

            # Login User
            self.auth.get_user_by_token(int(ref_user_id), token)

            # Delete token
            self.user_model.delete_auth_token(ref_user_id, token)

            # Slack Incoming WebHooks
            from google.appengine.api import urlfetch
            urlfetch.fetch(self.app.config.get('slack_webhook_url'), payload='{"channel": "#general", "username": "webhookbot", "text": "Just got a new referred user ! Go surprise him at '+referred_user.email+' and remember to thank '+ user.email +'", "icon_emoji": ":bowtie:"}', method='POST')


            message = _(messages.activation_success).format(
                referred_user.email)
            self.add_message(message, 'success')
            self.redirect_to('materialize-home')

        except (AttributeError, KeyError, InvalidAuthIdError, NameError), e:
            logging.error("Error activating an account: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-login')

class ResendActivationEmailHandler(BaseHandler):
    """
    Handler to resend activation email
    """

    def get(self, user_id, token):
        try:
            if not self.user_model.validate_resend_token(user_id, token):
                message = _(messages.used_activation_link)
                self.add_message(message, 'danger')
                return self.redirect_to('materialize-login')

            user = self.user_model.get_by_id(long(user_id))
            email = user.email

            if (user.activated == False):
                # send email
                subject = _(messages.email_activation_subject)
                confirmation_url = self.uri_for("materialize-account-activation",
                                                user_id=user.get_id(),
                                                token=self.user_model.create_auth_token(user.get_id()),
                                                _full=True)
                # load email's template
                template_val = {
                    "app_name": self.app.config.get('app_name'),
                    "username": user.name,
                    "confirmation_url": confirmation_url,
                    "support_url": self.uri_for("contact", _full=True),
					"faq_url": self.uri_for("faq", _full=True)
                }
                body_path = "emails/account_activation.txt"
                body = self.jinja2.render_template(body_path, **template_val)

                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url=email_url, params={
                    'to': str(email),
                    'subject': subject,
                    'body': body,
                })

                self.user_model.delete_resend_token(user_id, token)

                message = _(messages.resend_success).format(email)
                self.add_message(message, 'success')
                return self.redirect_to('materialize-login')
            else:
                message = _(messages.activation_success)
                self.add_message(message, 'warning')
                return self.redirect_to('materialize-home')

        except (KeyError, AttributeError), e:
            logging.error("Error resending activation email: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-login')




""" MATERIALIZE handlers 

    These handlers are the core of the Platform, they give life to main user materialized screens

"""
def disclaim(_self, **kwargs):
    """
        This method is used as a validator previous to loading a get handler for most of user's screens.
        It can either redirect user to login, edit cfe data and edit home data, or
        return required params, user_info and user_home values.
    """
    _params = {}
    user_info = _self.user_model.get_by_id(long(_self.user_id))        
    
    #0: FOR PERSONALIZATION MEANS WE TAKE CARE OF BEST DATA TO ADDRESS USER
    _params['email'] = user_info.email
    _params['last_name'] = user_info.last_name
    _params['last_name_i'] = user_info.last_name[0] + "." if len(user_info.last_name) >= 1 else ""
    _params['name'] = user_info.name
    _params['role'] = 'Administrador' if user_info.role == 'Admin' else 'Miembro'
    _params['phone'] = user_info.phone if user_info.phone != None else ""
    _params['gender'] = user_info.gender if user_info.gender != None else ""
    _params['birth'] = user_info.birth.strftime("%Y-%m-%d") if user_info.birth != None else ""
    _params['has_picture'] = True if user_info.picture != None else False
    _params['link_referral'] = user_info.link_referral
    _params['date'] = date.today().strftime("%Y-%m-%d")

    return _params, user_info

# LANDING
class MaterializeLandingRequestHandler(RegisterBaseHandler):
    """
    Handler to show the landing page
    """

    def get(self):
        """ Returns a simple HTML form for landing """
        params = {}
        if not self.user:
            chtml = captcha.displayhtml(public_key=self.app.config.get('captcha_public_key'))
            params['captchahtml'] = chtml
            return self.render_template('materialize/landing.html', **params)
        else:
            user_info = self.user_model.get_by_id(long(self.user_id)) 
            return self.redirect_to('materialize-home')     

class MaterializeLandingFaqRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized frequented asked questions
    """
    def get(self):
        """ returns simple html for a get request """
        params = {}
        return self.render_template('materialize/faq.html', **params)

class MaterializeLandingTouRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized terms of use
    """
    def get(self):
        """ returns simple html for a get request """
        params = {}
        return self.render_template('materialize/tou.html', **params)

class MaterializeLandingPrivacyRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized privacy policy
    """
    def get(self):
        """ returns simple html for a get request """
        params = {}
        return self.render_template('materialize/privacy.html', **params)

class MaterializeLandingLicenseRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized privacy policy
    """
    def get(self):
        """ returns simple html for a get request """
        params = {}
        return self.render_template('materialize/license.html', **params)

class MaterializeLandingContactRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized contact us
    """
    def get(self):
        """ returns simple html for a get request """
        params = {}
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params['exception'] = self.request.get('exception')

        return self.render_template('materialize/contact.html', **params)

    def post(self):
        """ validate contact form """
        if not self.form.validate():
            _message = _(messages.post_error)
            self.add_message(_message, 'danger')
            return self.get()

        import bp_includes.lib.i18n as i18n
        from bp_includes.external import httpagentparser

        remote_ip = self.request.remote_addr
        city = i18n.get_city_code(self.request)
        region = i18n.get_region_code(self.request)
        country = i18n.get_country_code(self.request)
        coordinates = i18n.get_city_lat_long(self.request)
        user_agent = self.request.user_agent
        exception = self.request.POST.get('exception')
        name = self.form.name.data.strip()
        email = self.form.email.data.lower()
        message = self.form.message.data.strip()
        template_val = {
            "name": name,
            "email": email,
            "ip": remote_ip,
            "city": city,
            "region": region,
            "country": country,
            "coordinates": coordinates,
            "message": message
        }
        try:
            # parsing user_agent and getting which os key to use
            # windows uses 'os' while other os use 'flavor'
            ua = httpagentparser.detect(user_agent)
            _os = ua.has_key('flavor') and 'flavor' or 'os'

            operating_system = str(ua[_os]['name']) if "name" in ua[_os] else "-"
            if 'version' in ua[_os]:
                operating_system += ' ' + str(ua[_os]['version'])
            if 'dist' in ua:
                operating_system += ' ' + str(ua['dist'])

            browser = str(ua['browser']['name']) if 'browser' in ua else "-"
            browser_version = str(ua['browser']['version']) if 'browser' in ua else "-"

            template_val = {
                "name": name,
                "email": email,
                "ip": remote_ip,
                "city": city,
                "region": region,
                "country": country,
                "coordinates": coordinates,

                "browser": browser,
                "browser_version": browser_version,
                "operating_system": operating_system,
                "message": message
            }
        except Exception as e:
            logging.error("error getting user agent info: %s" % e)

        try:
            subject = _("Alguien ha enviado un mensaje")
            # exceptions for error pages that redirect to contact
            if exception != "":
                subject = "{} (Exception error: {})".format(subject, exception)

            body_path = "emails/contact.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': self.app.config.get('contact_recipient'),
                'subject': subject,
                'body': body,
                'sender': self.app.config.get('contact_sender'),
            })

            message = _(messages.contact_success)
            self.add_message(message, 'success')
            return self.redirect_to('mat-contact')

        except (AttributeError, KeyError), e:
            logging.error('Error sending contact form: %s' % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('mat-contact')

    @webapp2.cached_property
    def form(self):
        return forms.ContactForm(self)


# USER
class MaterializeHomeRequestHandler(RegisterBaseHandler):
    """
    Handler for materialized home
    """
    @user_required
    def get(self):
        """ Returns a simple HTML form for materialize home """
        ####-------------------- R E D I R E C T I O N S --------------------####
        if not self.user:
            return self.redirect_to('materialize-login')
        else:
            user_info = self.user_model.get_by_id(long(self.user_id)) 
            if self.request.get('no_data') == "override":
                params, user_info, user_home, user_store = disclaim(self)
                params['data_override'] = True
                return self.render_template('materialize/users/home.html', **params)
            else:
                _params = {}
                if user_info.home_id == -1:
                    return self.redirect_to('materialize-setup-cfe', **_params)
                else:            
                    user_home = models.Home.get_by_id(long(user_info.home_id))
                    if user_home.cfe.rpu == -1 or not user_home.cfe.connected:
                        return self.redirect_to('materialize-setup-cfe', **_params)
                    if user_home.cfe.connected and user_home.cfe.dac_limit == -1:
                        return self.redirect_to('materialize-setup-home', **_params)
        ####------------------------------------------------------------------####

        ####-------------------- P R E P A R A T I O N S --------------------####
        params, user_info, user_home, user_store = disclaim(self)
        params, m, dates, bills, kwhs = data_prep(self, user_home, params)
        params['data_override'] = False
        ####------------------------------------------------------------------####
        
        
        _saving = bills[m]-bills[0] if bills[m-1] else 0
        params['period_savings'] = format(_saving,"d") 

        import random
        if _saving > 0:
            params['mood_icon'] = random.randrange(1,4)
            params['mood_color'] = "#3B9C2C"
        elif _saving < 0:
            params['mood_icon'] = random.randrange(7,10)
            params['mood_color'] = "#D31911"
        else:
            params['mood_icon'] = random.randrange(4,7)
            params['mood_color'] = "#EDB011"

        period_days = 60 if m == 6 else 30

        params['last_update'] = dates[0].strftime("%b %-d, %Y").replace('Jan','Ene').replace('Apr','Abr').replace('Aug','Ago').replace('Dec','Dic')
        today = date.today()
        diff = today - dates[0]
        avg_day = float(bills[m-1])/period_days
        avg_day_kwh = float(kwhs[m-1])/period_days
        params['elapsed_days'] = diff.days
        params['avg_day'] = avg_day
        params['avg_day_kwh'] = avg_day_kwh
        params['estimated_kwh'] = avg_day_kwh*diff.days
        params['f_estimated_kwh'] = int(avg_day_kwh*max(period_days,diff.days+1))       #projections of estimate to end of period
        # logging.info(":::::::::: Results with no UMR ::::::::::")
        # logging.info(" elapsed days = %s " % params['elapsed_days'])
        # logging.info(" avg kwh per day = %s " % params['avg_day_kwh'])
        # logging.info(" est kwh = %s " % params['estimated_kwh'])
        # logging.info(" final est kwh = %s " % params['f_estimated_kwh'])

        if len(user_home.umr) >= 1:
            logging.info("umr period %s ---- next period %s" % (user_home.umr[len(user_home.umr)-1].period[0:3], params['next_period'][0:3]))
            if user_home.umr[len(user_home.umr)-1].period[0:3] == params['next_period'][0:3] and user_home.umr[len(user_home.umr)-1].reading != -1:
                params['last_update'] = user_home.umr[len(user_home.umr)-1].date
                diff = params['last_update'] - user_home.umr[len(user_home.umr)-1].pdf_date
                params['elapsed_days'] = diff.days
                params['estimated_kwh'] = user_home.umr[len(user_home.umr)-1].reading - user_home.umr[len(user_home.umr)-1].pdf_reading
                params['avg_day_kwh'] = float(params['estimated_kwh'])/params['elapsed_days']
                params['f_estimated_kwh'] = int(params['avg_day_kwh']*max(period_days,diff.days+1))
                params['last_update'] = user_home.umr[len(user_home.umr)-1].date.strftime("%b %-d, %Y").replace('Jan','Ene').replace('Apr','Abr').replace('Aug','Ago').replace('Dec','Dic')
                if params['estimated_kwh'] > params['f_estimated_kwh']:
                    params['f_estimated_kwh'] = params['estimated_kwh']
                # logging.info(":::::::::: Results with UMR ::::::::::")
                # logging.info("elapsed days = %s " % params['elapsed_days'])
                # logging.info("avg kwh per day = %s " % params['avg_day_kwh'])
                # logging.info(" est kwh = %s " % params['estimated_kwh'])
                # logging.info("final est kwh = %s " % params['f_estimated_kwh'])

        est_kwh = params['estimated_kwh']
        f_est_kwh = params['f_estimated_kwh']
         #: update r and deliver estimated payment
        API_KEY ='58558e09ef47eb95868a57d59c1175d3d078c8f4'
        cartodb_domain = 'mexico'
        cl = CartoDBAPIKey(API_KEY, cartodb_domain)
        try:
           summer = cl.sql('select d_verano from nacional_codigos_postales where d_codigo = %s and d_municipio = \'%s\'' % (user_home.address.zipcode, user_home.address.municipality))
           summer = summer['rows'][0]['d_verano']
           logging.info('CartoDB Query Success.')
        except CartoDBException as e:
           logging.error("CartoDB Query some error ocurred", e)
           summer = 4
           pass
        card3_region = user_home.address.region
        card3_months = int(12/m)
        next_month = dates[m].month
        if next_month < summer or next_month > summer + 5:
            card3_summer = False
        else:
            card3_summer = True
        card3_basefee = user_home.cfe.base_fee
        card3_sum11 = params['kwhs_acum'][0] - kwhs[m-1]
        cfe_recent = mycfe.getCFEPricing()      
        est_payment = 0
        f_est_payment = 0
        #: case for DAC
        if f_est_kwh + card3_sum11 > user_home.cfe.dac_limit:
            logging.info("using DAC modeling")
            logging.info("using %s modeling" % card3_region)
            if not card3_summer:
                est_payment = (est_kwh*float(cfe_recent[card3_region][1])+float(cfe_recent[card3_region][0]))*(1+self.app.config.get('iva'))
                f_est_payment = (f_est_kwh*float(cfe_recent[card3_region][1])+float(cfe_recent[card3_region][0]))*(1+self.app.config.get('iva'))
            else:
                est_payment = (est_kwh*float(cfe_recent[card3_region][2])+float(cfe_recent[card3_region][0]))*(1+self.app.config.get('iva'))
                f_est_payment = (f_est_kwh*float(cfe_recent[card3_region][2])+float(cfe_recent[card3_region][0]))*(1+self.app.config.get('iva'))
        #: case for base fee
        else:
            logging.info("we should use %s modeling" % card3_basefee)
            subs_label = 'subsidios_' + card3_basefee
            pri_label = 'precios_' + card3_basefee
            subsidios = cfe_recent[subs_label]
            precios = cfe_recent[pri_label]
            min_consumption = 25
            if m == 6:
                subsidios = [int(a)*2 for a in subsidios]
                logging.info("subsidios: %s" % subsidios)
                min_consumption = 50
            #: not summer uses values in array from 0 to 3
            if not card3_summer:
                logging.info('using not summer values')
                usage_1 = max([min_consumption,min([int(subsidios[0]),est_kwh])])
                usage_2 = max([0,min([int(subsidios[1]),est_kwh-int(subsidios[0])])])
                usage_3 = max([0,min([int(subsidios[2]),est_kwh-int(subsidios[0])-int(subsidios[1])])])
                usage_4 = max([0,max([int(subsidios[3]),est_kwh-int(subsidios[0])-int(subsidios[1])-int(subsidios[2])])])
                cost_1 = usage_1*float(precios[0])
                cost_2 = usage_2*float(precios[1])
                cost_3 = usage_3*float(precios[2])
                cost_4 = usage_4*float(precios[3])
                f_usage_1 = max([min_consumption,min([int(subsidios[0]),f_est_kwh])])
                f_usage_2 = max([0,min([int(subsidios[1]),f_est_kwh-int(subsidios[0])])])
                f_usage_3 = max([0,min([int(subsidios[2]),f_est_kwh-int(subsidios[0])-int(subsidios[1])])])
                f_usage_4 = max([0,max([int(subsidios[3]),f_est_kwh-int(subsidios[0])-int(subsidios[1])-int(subsidios[2])])])
                f_cost_1 = f_usage_1*float(precios[0])
                f_cost_2 = f_usage_2*float(precios[1])
                f_cost_3 = f_usage_3*float(precios[2])
                f_cost_4 = f_usage_4*float(precios[3])

            #: summer uses values in array from 4 to 7
            else:
                logging.info('using summer values')
                usage_1 = max([min_consumption,min([int(subsidios[4]),est_kwh])])
                usage_2 = max([0,min([int(subsidios[5]),est_kwh-int(subsidios[4])])])
                usage_3 = max([0,min([int(subsidios[6]),est_kwh-int(subsidios[4])-int(subsidios[5])])])
                usage_4 = max([0,max([int(subsidios[7]),est_kwh-int(subsidios[4])-int(subsidios[5])-int(subsidios[6])])])
                cost_1 = usage_1*float(precios[4])
                cost_2 = usage_2*float(precios[5])
                cost_3 = usage_3*float(precios[6])
                cost_4 = usage_4*float(precios[7])
                f_usage_1 = max([min_consumption,min([int(subsidios[4]),f_est_kwh])])
                f_usage_2 = max([0,min([int(subsidios[5]),f_est_kwh-int(subsidios[4])])])
                f_usage_3 = max([0,min([int(subsidios[6]),f_est_kwh-int(subsidios[4])-int(subsidios[5])])])
                f_usage_4 = max([0,max([int(subsidios[7]),f_est_kwh-int(subsidios[4])-int(subsidios[5])-int(subsidios[6])])])
                f_cost_1 = f_usage_1*float(precios[4])
                f_cost_2 = f_usage_2*float(precios[5])
                f_cost_3 = f_usage_3*float(precios[6])
                f_cost_4 = f_usage_4*float(precios[7])

            est_payment = (cost_1+cost_2+cost_3+cost_4)*(1+self.app.config.get('iva'))    
            f_est_payment = (f_cost_1+f_cost_2+f_cost_3+f_cost_4)*(1+self.app.config.get('iva'))    

        params['estimated_bill'] = format(est_payment,".2f")            
        params['f_estimated_bill'] = format(int(f_est_payment),",d")    
        params['est_limit'] = format(int(bills[m-1]),",d")   
        
        est_mood = bills[m-1]/float(f_est_payment) if float(f_est_payment) > 0 else 'na'
        if est_mood > 1.1:
            params['est_mood_color'] = "#3B9C2C"
            params['est_mood_msg'] = unicode("Bien, no rebases $","utf-8") + params['est_limit']
        elif est_mood < 1:
            params['est_mood_color'] = "#D31911"
            params['est_mood_msg'] = unicode("¡Ya no gastes!","utf-8")
        elif est_mood != 'na':
            params['est_mood_color'] = "#EDB011"
            params['est_mood_msg'] = unicode("¡No rebases $","utf-8") + params['est_limit'] + "!"


        API_KEY ='f99a36512f8976d6480f9dd54a5e3d3f1f717dec'
        cartodb_domain = 'invictus'
        cl = CartoDBAPIKey(API_KEY, cartodb_domain)
        params['tips'] = []
        categoria = dict({'cooling': unicode('Clima','utf-8'), 'heating': unicode('Calefacción','utf-8'), 
            'lighting': unicode('Iluminación','utf-8'), 'appliances': unicode('Elecrodomésticos','utf-8'), 
            'entertainment': unicode('Entretenimiento','utf-8'), 'others': unicode('Otros','utf-8')})
        try:
            tips = cl.sql('select * from tips')
            logging.info("tips retrieved: %s" % tips)
            for i in range(0,len(tips['rows'])):
                _status = ''
                params['tips'].append((tips['rows'][i]['cartodb_id'], tips['rows'][i]['title'], tips['rows'][i]['category'], categoria[str(tips['rows'][i]['category'])], _status))
            logging.info('CartoDB Query Success. Retrieved %s tips from a total of %s' % (len(tips['rows']),tips['total_rows']))
            params['total_tips'] = tips['total_rows']

        except CartoDBException as e:
            logging.error("CartoDB Query some error ocurred", e)
            pass

        params['total_products'] = 0


        return self.render_template('materialize/users/sections/home.html', **params)

class MaterializeInboxRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized inbox
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        ####-------------------- R E D I R E C T I O N S --------------------####
        if not self.user:
            return self.redirect_to('materialize-login')
        ####------------------------------------------------------------------####


        ####-------------------- P R E P A R A T I O N S --------------------####
        params, user_info, user_home, user_store = disclaim(self)
        ####------------------------------------------------------------------####
        return self.render_template('materialize/users/sections/inbox.html', **params)

class MaterializeFaqRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized frequented asked questions
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        return self.render_template('materialize/users/customer/faq.html', **params)

class MaterializeTouRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized terms of use
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        return self.render_template('materialize/users/customer/tou.html', **params)

class MaterializePrivacyRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized privacy policy
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        return self.render_template('materialize/users/customer/privacy.html', **params)

class MaterializeContactRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized contact us
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info.name or user_info.last_name:
                self.form.name.data = user_info.name + " " + user_info.last_name
            if user_info.email:
                self.form.email.data = user_info.email
        params['exception'] = self.request.get('exception')

        return self.render_template('materialize/users/customer/contact.html', **params)

    def post(self):
        """ validate contact form """
        if not self.form.validate():
            _message = _(messages.post_error)
            self.add_message(_message, 'danger')
            return self.get()

        import bp_includes.lib.i18n as i18n
        from bp_includes.external import httpagentparser

        remote_ip = self.request.remote_addr
        city = i18n.get_city_code(self.request)
        region = i18n.get_region_code(self.request)
        country = i18n.get_country_code(self.request)
        coordinates = i18n.get_city_lat_long(self.request)
        user_agent = self.request.user_agent
        exception = self.request.POST.get('exception')
        name = self.form.name.data.strip()
        email = self.form.email.data.lower()
        message = self.form.message.data.strip()
        template_val = {
            "name": name,
            "email": email,
            "ip": remote_ip,
            "city": city,
            "region": region,
            "country": country,
            "coordinates": coordinates,
            "message": message
        }
        try:
            # parsing user_agent and getting which os key to use
            # windows uses 'os' while other os use 'flavor'
            ua = httpagentparser.detect(user_agent)
            _os = ua.has_key('flavor') and 'flavor' or 'os'

            operating_system = str(ua[_os]['name']) if "name" in ua[_os] else "-"
            if 'version' in ua[_os]:
                operating_system += ' ' + str(ua[_os]['version'])
            if 'dist' in ua:
                operating_system += ' ' + str(ua['dist'])

            browser = str(ua['browser']['name']) if 'browser' in ua else "-"
            browser_version = str(ua['browser']['version']) if 'browser' in ua else "-"

            template_val = {
                "name": name,
                "email": email,
                "ip": remote_ip,
                "city": city,
                "region": region,
                "country": country,
                "coordinates": coordinates,

                "browser": browser,
                "browser_version": browser_version,
                "operating_system": operating_system,
                "message": message
            }
        except Exception as e:
            logging.error("error getting user agent info: %s" % e)

        try:
            subject = _("Alguien ha enviado un mensaje")
            # exceptions for error pages that redirect to contact
            if exception != "":
                subject = "{} (Exception error: {})".format(subject, exception)

            body_path = "emails/contact.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            taskqueue.add(url=email_url, params={
                'to': self.app.config.get('contact_recipient'),
                'subject': subject,
                'body': body,
                'sender': self.app.config.get('contact_sender'),
            })

            message = _(messages.contact_success)
            self.add_message(message, 'success')
            return self.redirect_to('materialize-contact')

        except (AttributeError, KeyError), e:
            logging.error('Error sending contact form: %s' % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-contact')

    @webapp2.cached_property
    def form(self):
        return forms.ContactForm(self)

class MaterializeReferralsRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized referrals
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        params['link_referral'] = user_info.link_referral
        return self.render_template('materialize/users/sections/referrals.html', **params)

    def post(self):
        """ Get fields from POST dict """
        user_info = self.user_model.get_by_id(long(self.user_id))
        message = ''

        if not self.form.validate():
            message += messages.saving_error
            self.add_message(message, 'danger')
            return self.get()

        _emails = self.form.emails.data.replace('"','').replace('[','').replace(']','')
        logging.info("Referrals' email addresses: %s" % _emails)

        try:
            # send email
            subject = _(messages.email_referral_subject)
            if user_info.name != '':
                _username = user_info.name
            else:
                _username = user_info.username
             # load email's template
            template_val = {
                "app_name": self.app.config.get('app_name'),
                "user_email": user_info.email,
                "user_name": _username,
                "link_referral" : user_info.link_referral,
                "support_url": self.uri_for("contact", _full=True),
                "faq_url": self.uri_for("faq", _full=True)
            }
            body_path = "emails/referrals.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            _email = _emails.split(",")
            _email = list(set(_email)) #removing duplicates

            for _email_ in _email:

                aUser = self.user_model.get_by_email(_email_)
                if aUser is not None:
                    reward = models.Rewards(amount = 0,earned = True, category = 'invite',content = _email_,
                                            timestamp = utils.get_date_time(),status = 'inelegible')                 
                    edited_userinfo = False
                    for rewards in user_info.rewards:
                        if 'invite' in rewards.category and rewards.content == reward.content:
                            user_info.rewards[user_info.rewards.index(rewards)] = reward
                            edited_userinfo = True
                    if not edited_userinfo:
                        user_info.rewards.append(reward)
                else:
                    taskqueue.add(url=email_url, params={
                        'to': str(_email_),
                        'subject': subject,
                        'body': body,
                    })
                    logging.info('Sent referral invitation to %s' % str(_email_))
                    reward = models.Rewards(amount = 0,earned = True, category = 'invite',content = _email_,
                                            timestamp = utils.get_date_time(),status = 'invited')                 
                    edited_userinfo = False
                    for rewards in user_info.rewards:
                        if 'invite' in rewards.category and rewards.content == reward.content:
                            user_info.rewards[user_info.rewards.index(rewards)] = reward
                            edited_userinfo = True
                    if not edited_userinfo:
                        user_info.rewards.append(reward)
                    
            user_info.put()

            message += " " + _(messages.invite_success)
            self.add_message(message, 'success')
            return self.get()
           
        except (KeyError, AttributeError), e:
            logging.error("Error resending invitation email: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('home')

          
    @webapp2.cached_property
    def form(self):
        f = forms.ReferralsForm(self)
        return f

class MaterializeSettingsProfileRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized settings profile
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        return self.render_template('materialize/users/settings/profile.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            return self.get()
        username = self.form.username.data.lower()
        name = self.form.name.data.strip()
        last_name = self.form.last_name.data.strip()
        gender = self.form.gender.data
        phone = self.form.phone.data
        birth = self.form.birth.data
        country = self.form.country.data
        tz = self.form.tz.data

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))

            try:
                message = ''
                # update username if it has changed and it isn't already taken
                if username != user_info.username:
                    user_info.unique_properties = ['username', 'email']
                    uniques = [
                        'User.username:%s' % username,
                        'User.auth_id:own:%s' % username,
                    ]
                    # Create the unique username and auth_id.
                    success, existing = Unique.create_multi(uniques)
                    if success:
                        # free old uniques
                        Unique.delete_multi(
                            ['User.username:%s' % user_info.username, 'User.auth_id:own:%s' % user_info.username])
                        # The unique values were created, so we can save the user.
                        user_info.username = username
                        user_info.auth_ids[0] = 'own:%s' % username
                        message += _(messages.edit_username_success).format(username)

                    else:
                        message += _(messages.username_exists).format(
                            username)
                        # At least one of the values is not unique.
                        self.add_message(message, 'danger')
                        return self.get()
                user_info.name = name
                user_info.last_name = last_name
                if (len(birth) > 9):
                    user_info.birth = date(int(birth[:4]), int(birth[5:7]), int(birth[8:]))
                if 'male' in gender:
                    user_info.gender = gender
                user_info.phone = phone
                user_info.country = country
                user_info.tz = tz
                user_info.put()
                message += " " + _(messages.saving_success)
                self.add_message(message, 'success')
                return self.get()

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating profile: %s ' % e)
                message = _(messages.saving_error)
                self.add_message(message, 'danger')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            logging.error('Error updating profile: %s' % e)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        f = forms.SettingsProfileForm(self)
        f.country.choices = self.countries_tuple
        f.tz.choices = self.tz
        return f

class MaterializeSettingsEmailRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized settings email
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        return self.render_template('materialize/users/settings/email.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            _message = _(messages.saving_error)
            self.add_message(_message, 'danger')
            return self.get()
        new_email = self.form.new_email.data.strip()
        password = self.form.password.data.strip()

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            # Password to SHA512
            password = utils.hashing(password, self.app.config.get('salt'))

            try:
                # authenticate user by its password
                user = self.user_model.get_by_auth_password(auth_id, password)

                # if the user change his/her email address
                if new_email != user.email:

                    # check whether the new email has been used by another user
                    aUser = self.user_model.get_by_email(new_email)
                    if aUser is not None:
                        message = _("Lo sentimos, el email %s ya ha sido registrado." % new_email)
                        self.add_message(message, 'danger')
                        return self.get()

                    # send email
                    subject = _(messages.email_emailchanged_subject)
                    user_token = self.user_model.create_auth_token(self.user_id)
                    confirmation_url = self.uri_for("materialize-email-changed-check",
                                                    user_id=user_info.get_id(),
                                                    encoded_email=utils.encode(new_email),
                                                    token=user_token,
                                                    _full=True)
                    if user.name != '':
                        _username = user.name
                    else:
                        _username = user.email
                    # load email's template
                    template_val = {
                        "app_name": self.app.config.get('app_name'),
                        "username": _username,
                        "new_email": new_email,
                        "confirmation_url": confirmation_url,
                        "support_url": self.uri_for("contact", _full=True),
                        "faq_url": self.uri_for("faq", _full=True)
                    }

                    old_body_path = "emails/email_changed_notification_old.txt"
                    old_body = self.jinja2.render_template(old_body_path, **template_val)

                    new_body_path = "emails/email_changed_notification_new.txt"
                    new_body = self.jinja2.render_template(new_body_path, **template_val)

                    email_url = self.uri_for('taskqueue-send-email')
                    taskqueue.add(url=email_url, params={
                        'to': user.email,
                        'subject': subject,
                        'body': old_body,
                    })
                    taskqueue.add(url=email_url, params={
                        'to': new_email,
                        'subject': subject,
                        'body': new_body,
                    })

                    # display successful message
                    msg = _(messages.emailchanged_success)
                    self.add_message(msg, 'success')
                    return self.get()

                else:
                    self.add_message(_(messages.emailchanged_error), "warning")
                    return self.get()


            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _(messages.password_wrong)
                self.add_message(message, 'danger')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.EditEmailForm(self)

class MaterializeEmailChangedCompleteHandler(BaseHandler):
    """
    Handler for completed email change
    Will be called when the user click confirmation link from email
    """

    @user_required
    def get(self, user_id, encoded_email, token):
        verify = self.user_model.get_by_auth_token(int(user_id), token)
        email = utils.decode(encoded_email)
        if verify[0] is None:
            message = _(messages.used_activation_link)
            self.add_message(message, 'warning')
            self.redirect_to('home')

        else:
            # save new email
            user = verify[0]
            user.email = email
            user.put()
            # delete token
            self.user_model.delete_auth_token(int(user_id), token)
            # add successful message and redirect
            message = _(messages.emailchanged_confirm)
            self.add_message(message, 'success')
            self.redirect_to('materialize-settings-email')

class MaterializeSettingsPasswordRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized settings password
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        return self.render_template('materialize/users/settings/password.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            self.add_message(_(messages.passwords_mismatch), 'danger')
            return self.get()

        current_password = self.form.current_password.data.strip()
        password = self.form.password.data.strip()

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username

            # Password to SHA512
            current_password = utils.hashing(current_password, self.app.config.get('salt'))
            try:
                user = self.user_model.get_by_auth_password(auth_id, current_password)
                # Password to SHA512
                password = utils.hashing(password, self.app.config.get('salt'))
                user.password = security.generate_password_hash(password, length=12)
                user.put()

                # send email
                subject = messages.email_passwordchanged_subject
                if user.name != '':
                    _username = user.name
                else:
                    _username = user.email
                # load email's template
                template_val = {
                    "app_name": self.app.config.get('app_name'),
                    "username": _username,
                    "email": user.email,
                    "reset_password_url": self.uri_for("password-reset", _full=True),
                    "support_url": self.uri_for("contact", _full=True),
                    "faq_url": self.uri_for("faq", _full=True)
                }
                email_body_path = "emails/password_changed.txt"
                email_body = self.jinja2.render_template(email_body_path, **template_val)
                email_url = self.uri_for('taskqueue-send-email')
                taskqueue.add(url=email_url, params={
                    'to': user.email,
                    'subject': subject,
                    'body': email_body,
                    'sender': self.app.config.get('contact_sender'),
                })

                #Login User
                self.auth.get_user_by_password(user.auth_ids[0], password)
                self.add_message(_(messages.passwordchange_success), 'success')
                return self.get()
            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _(messages.password_wrong)
                self.add_message(message, 'danger')
                return self.get()
        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.EditPasswordForm(self)

class MaterializeSettingsDeleteRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized settings delete account
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        chtml = captcha.displayhtml( public_key=self.app.config.get('captcha_public_key'))
        if self.app.config.get('captcha_public_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE" or \
                        self.app.config.get('captcha_private_key') == "PUT_YOUR_RECAPCHA_PUBLIC_KEY_HERE":
            chtml = '<div class="alert alert-danger"><strong>Error</strong>: You have to ' \
                    '<a href="http://www.google.com/recaptcha/whyrecaptcha" target="_blank">sign up ' \
                    'for API keys</a> in order to use reCAPTCHA.</div>' \
                    '<input type="hidden" name="recaptcha_challenge_field" value="manual_challenge" />' \
                    '<input type="hidden" name="recaptcha_response_field" value="manual_challenge" />'
        params['captchahtml'] = chtml
        return self.render_template('materialize/users/settings/delete.html', **params)

    def post(self, **kwargs):
        # check captcha
        response = self.request.POST.get('g-recaptcha-response')
        remote_ip = self.request.remote_addr

        cResponse = captcha.submit(
            response,
            self.app.config.get('captcha_private_key'),
            remote_ip)

        if cResponse.is_valid:
            # captcha was valid... carry on..nothing to see here
            pass
        else:
            _message = _(messages.captcha_error)
            self.add_message(_message, 'danger')
            return self.get()

        if not self.form.validate():
            message = _(messages.password_wrong)
            self.add_message(message, 'danger')
            return self.get()

        password = self.form.password.data.strip()

        try:

            user_info = self.user_model.get_by_id(long(self.user_id))
            auth_id = "own:%s" % user_info.username
            password = utils.hashing(password, self.app.config.get('salt'))

            try:
                # authenticate user by its password
                user = self.user_model.get_by_auth_password(auth_id, password)
                if user:
                    # Delete Social Login
                    # for social in models_boilerplate.SocialUser.get_by_user(user_info.key):
                    #     social.key.delete()

                    user_info.key.delete()

                    ndb.Key("Unique", "User.username:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.auth_id:own:%s" % user.username).delete_async()
                    ndb.Key("Unique", "User.email:%s" % user.email).delete_async()

                    #TODO: Delete UserToken objects, Delete Home if Admin

                    self.auth.unset_session()

                    # display successful message
                    msg = _(messages.account_delete_success)
                    self.add_message(msg, 'success')
                    return self.redirect_to('home')
                else:
                    message = _(messages.password_wrong)
                    self.add_message(message, 'danger')
                    return self.self.get()

            except (InvalidAuthIdError, InvalidPasswordError), e:
                # Returns error message to self.response.write in
                # the BaseHandler.dispatcher
                message = _(messages.password_wrong)
                self.add_message(message, 'danger')
                return self.self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('login')

    @webapp2.cached_property
    def form(self):
        return forms.DeleteAccountForm(self)

class MaterializeSettingsHomeRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized settings home
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        if user_info.home_id == -1:
            params['kind'] = 'house'
            params['num_hab'] = 'one'
            params['size'] = 'small'
            params['zipcode'] = ''
            params['neighborhood'] = False
            params['latlng'] = 'null'
            params['cfe_connected'] = False
            params['cfe_error'] = 'none'
            params['dac_limit'] = -1
            params['cfe_rpu'] = -1
            params['has_box'] = False
            params['panels'] = 0
            params['capacity'] = 250
        else:
            user_home = models.Home.get_by_id(long(user_info.home_id))
            params['cfe_connected'] = user_home.cfe.connected
            params['cfe_error'] = user_home.cfe.error
            params['dac_limit'] = user_home.cfe.dac_limit
            params['cfe_rpu'] = mycfe.fixedRPU(user_home.cfe.rpu)
            params['has_box'] = False
            if user_home.box != None:
                if user_home.box.serial != '':
                    params['has_box'] = True
            if user_home.attributes == None:
                params['kind'] = 'house'
                params['num_hab'] = 'one'
                params['size'] = 'small'
                params['zipcode'] = ''
                params['neighborhood'] = False
                params['latlng'] = 'null'
            elif user_home.attributes.essentials != None:
                params['kind'] = user_home.attributes.essentials.kind
                params['num_hab'] = user_home.attributes.essentials.num_hab
                params['size'] = user_home.attributes.essentials.size
                params['zipcode'] = str(user_home.address.zipcode)
                while len(params['zipcode']) < 5:
                    params['zipcode'] = '0' + params['zipcode']
                params['neighborhood'] = user_home.address.neighborhood
                params['latlng'] = user_home.address.latlng
            else:
                params['kind'] = 'house'
                params['num_hab'] = 'one'
                params['size'] = 'small'
                params['zipcode'] = ''
                params['neighborhood'] = False
                params['latlng'] = 'null'
            if user_home.solar != None:
                params['panels'] = user_home.solar.panels
                params['capacity'] = user_home.solar.capacity
                if (user_home.solar.since):
                    params['since'] = user_home.solar.since.strftime("%Y-%m-%d")
            else:
                params['panels'] = 0
                params['capacity'] = 250
        return self.render_template('materialize/users/settings/home.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            message = _(messages.saving_error)
            message += "Tip: Asegura que el marcador en el mapa se encuentre en tu zona."
            self.add_message(message, 'danger')
            return self.get()
        kind = self.form.kind.data
        num_hab = self.form.num_hab.data
        size = self.form.size.data
        zipcode = int(self.form.zipcode.data)
        ageb = self.form.ageb.data
        dacl = self.form.dacl.data
        latlng = self.form.latlng.data
        neighborhood = self.form.neighborhood.data
        municipality = self.form.municipality.data
        state = self.form.state.data
        region = self.form.region.data
        fee = self.form.fee.data
        flag = self.form.flag.data
        panels = self.form.panels.data
        capacity = self.form.capacity.data
        since = self.form.since.data

        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            user_home = None
            try:
                
                if user_info.home_id == -1:
                    #create home
                    logging.info("Creating a new home...")
                    home = models.Home()
                    logging.info("User key to create home: %s" % user_info.key.id())
                    home.habitant.append(user_info.key.id())
                    home.cfe = models.CFE()
                    
                    #init
                    home.attributes = models.HomeAttributes()
                    home.attributes.essentials = models.Essentials()
                    home.address = models.Address()
                    home.solar = models.FV()

                    #assign home essentials                    
                    home.attributes.essentials.kind = kind
                    home.attributes.essentials.num_hab = num_hab
                    home.attributes.essentials.size = size

                    #assign home address                    
                    home.address.zipcode = int(zipcode)
                    home.address.ageb = ageb
                    home.address.neighborhood = neighborhood
                    home.address.municipality = municipality
                    home.address.state = state
                    home.address.region = region
                    home.address.latlng = ndb.GeoPt(latlng)
                    
                    #assign dac limit
                    home.cfe.dac_limit = int(dacl)
                    home.cfe.base_fee = fee  

                    #assign solar installation
                    home.solar.panels = panels
                    home.solar.capacity = capacity
                    if (len(since) > 9):
                        home.solar.since = date(int(since[:4]), int(since[5:7]), int(since[8:]))  

                    #allocate in datastore
                    home.put()
                    user_info.home_id = home.key.id()
                    user_info.put()
                    logging.info("Home created with ID: %s" % user_info.home_id)
                else:
                    #update user home
                    user_home = models.Home.get_by_id(long(user_info.home_id))
                    logging.info("Updating home: %s" % user_home.key.id())

                    #init
                    if user_home.attributes == None:
                        user_home.attributes = models.HomeAttributes()
                    user_home.attributes.essentials = models.Essentials()
                    user_home.address = models.Address()
                    
                    #assign home essentials
                    user_home.attributes.essentials.kind = kind
                    user_home.attributes.essentials.num_hab = num_hab
                    user_home.attributes.essentials.size = size
                    logging.info("...essentials assigned...")

                    #assign home address
                    user_home.address.zipcode = int(zipcode)
                    user_home.address.ageb = ageb
                    user_home.address.neighborhood = neighborhood
                    user_home.address.municipality = municipality
                    user_home.address.state = state
                    user_home.address.region = region
                    user_home.address.latlng = ndb.GeoPt(latlng)
                    logging.info("...address assigned...")

                    #assign dac limit
                    user_home.cfe.dac_limit = int(dacl)
                    user_home.cfe.base_fee = fee  
                    logging.info("...dac limit & base fee assigned...") 

                    #assign solar installation
                    if user_home.solar != None:
                        user_home.solar.panels = panels
                        user_home.solar.capacity = capacity
                        if (len(since) > 9):
                            user_home.solar.since = date(int(since[:4]), int(since[5:7]), int(since[8:]))
                    else:
                        user_home.solar = models.FV()
                        user_home.solar.panels = panels
                        user_home.solar.capacity = capacity
                        if (len(since) > 9):
                            user_home.solar.since = date(int(since[:4]), int(since[5:7]), int(since[8:]))
                    
                    #allocate in datastore
                    user_home.put()
                    logging.info("Home updated with ID: %s" % user_home.key.id())

                user_home = models.Home.get_by_id(long(user_info.home_id))
                #: Email rodrigo if user from out of region or base_fee is different from fee while not being DAC
                if flag == 1 or (user_home.cfe.fee != user_home.cfe.base_fee and '1' in user_home.cfe.fee):
                    subject = "Usuario fuera de regiones tarifarias."
                    template_val = {
                        "username": user_info.username,
                        "email": user_info.email,
                        "support_url": self.uri_for("contact", _full=True),
                    }
                    body_path = "emails/user_out_of_region.txt"
                    body = self.jinja2.render_template(body_path, **template_val)
                    email = "rodrigo.dibildox@invictus.mx"
                    email_url = self.uri_for('taskqueue-send-email')                    
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                message = ''                
                message += " " + _(messages.saving_success)
                self.add_message(message, 'success')
                return self.get()

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating home profile: ' + e)
                message = _(messages.saving_error)
                self.add_message(message, 'danger')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('materialize-login')

    @webapp2.cached_property
    def form(self):
        f = forms.EditHomeForm(self)
        return f

class MaterializeSettingsReferralsRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized settings referrals
    """
    @user_required
    def get(self):
        """ returns simple html for a get request """
        params, user_info, user_home, user_store = disclaim(self)
        params['referrals'] = []
        rewards = user_info.rewards
        rewards.reverse
        unique_emails = []
        page = 1
        if self.request.get('p') != '':
            page = 1 + int(self.request.get('p'))
        offset = (page - 1)*51
        last = page*51
        if last > len(rewards):
            last = len(rewards)
        for i in range(offset, last):
            if 'invite' in rewards[i].category and rewards[i].content != '' and 'Invitado Invictus' not in rewards[i].content and rewards[i].content not in unique_emails:
                params['referrals'].append(rewards[i])
                unique_emails.append(rewards[i].content)
                if rewards[i].status == 'invited':
                    aUser = self.user_model.get_by_email(rewards[i].content)
                    if aUser is not None:
                        params['referrals'][params['referrals'].index(rewards[i])].status = 'inelegible'

        params['page'] = page
        params['last_page'] = int(len(rewards)/50)
        params['total'] = len(params['referrals'])
        params['grand_total'] = int(len(rewards))
        params['properties'] = ['timestamp','content','status']

        return self.render_template('materialize/users/settings/referrals.html', **params)

    def post(self):
        """ Get fields from POST dict """
        user_info = self.user_model.get_by_id(long(self.user_id))
        message = ''

        if not self.form.validate():
            message += messages.saving_error
            self.add_message(message, 'error')
            return self.get()

        _emails = self.form.emails.data.replace('"','').replace('[','').replace(']','')
        logging.info("Referrals' email addresses: %s" % _emails)

        try:
            # send email
            subject = _(messages.email_referral_subject)
            if user_info.name != '':
                _username = user_info.name
            else:
                _username = user_info.username
             # load email's template
            template_val = {
                "app_name": self.app.config.get('app_name'),
                "user_email": user_info.email,
                "user_name": _username,
                "link_referral" : user_info.link_referral,
                "support_url": self.uri_for("contact", _full=True),
                "faq_url": self.uri_for("faq", _full=True)
            }
            body_path = "emails/referrals.txt"
            body = self.jinja2.render_template(body_path, **template_val)

            email_url = self.uri_for('taskqueue-send-email')
            _email = _emails.split(",")

            for _email_ in _email:
                taskqueue.add(url=email_url, params={
                    'to': str(_email_),
                    'subject': subject,
                    'body': body,
                })
                reward = models.Rewards(amount = 0,earned = True, category = 'invite',content = _email_,
                                        timestamp = utils.get_date_time(),status = 'invited')    
                
                edited_userinfo = False
                for rewards in user_info.rewards:
                    if 'invite' in rewards.category and rewards.content == reward.content:
                        user_info.rewards[user_info.rewards.index(rewards)] = reward
                        edited_userinfo = True
                if not edited_userinfo:
                    user_info.rewards.append(reward)

                user_info.put()

            message += " " + _(messages.invite_success)
            self.add_message(message, 'success')
            return self.get()
           
        except (KeyError, AttributeError), e:
            logging.error("Error resending invitation email: %s" % e)
            message = _(messages.post_error)
            self.add_message(message, 'danger')
            return self.redirect_to('home')

          
    @webapp2.cached_property
    def form(self):
        f = forms.ReferralsForm(self)
        return f

class MaterializeSetupHomeRequestHandler(RegisterBaseHandler):
    """
        Handler for materialized setup home
    """

    @user_required
    def get(self):
        """ Returns a simple HTML form for edit profile """

        params = {}
        params['setup'] = True
        if self.user:
            user_info = self.user_model.get_by_id(long(self.user_id))
            params['role'] = 'Administrador' if user_info.role == 'Admin' else 'Miembro'
            params['has_picture'] = False
            if user_info.picture != None:
                params['has_picture'] = True            
            
            if self.request.get('comes_from_rpu'):
                params['comes_from_rpu'] = True
            else:
                params['comes_from_rpu'] = False
            
            if self.request.get('comes_from_home'):
                params['comes_from_home'] = True
            else:
                params['comes_from_home'] = False
            
            if user_info.home_id == -1:
                params['kind'] = 'house'
                params['num_hab'] = 'one'
                params['size'] = 'small'
                params['zipcode'] = ''
                params['neighborhood'] = ''
                params['latlng'] = 'null'
                params['cfe_connected'] = False
                params['cfe_error'] = 'none'
                params['dac_limit'] = -1
                params['cfe_rpu'] = -1
                params['has_box'] = False
                params['panels'] = 0
                params['capacity'] = 250
            else:
                user_home = models.Home.get_by_id(long(user_info.home_id))
                params['cfe_connected'] = user_home.cfe.connected
                params['cfe_error'] = user_home.cfe.error
                params['dac_limit'] = user_home.cfe.dac_limit
                params['cfe_rpu'] = mycfe.fixedRPU(user_home.cfe.rpu)
                params['has_box'] = False
                if user_home.box != None:
                    if user_home.box.serial != '':
                        params['has_box'] = True
                if user_home.attributes == None:
                    params['kind'] = 'house'
                    params['num_hab'] = 'one'
                    params['size'] = 'small'
                    params['zipcode'] = ''
                    params['neighborhood'] = ''
                    params['latlng'] = 'null'
                elif user_home.attributes.essentials != None:
                    params['kind'] = user_home.attributes.essentials.kind
                    params['num_hab'] = user_home.attributes.essentials.num_hab
                    params['size'] = user_home.attributes.essentials.size
                    params['zipcode'] = str(user_home.address.zipcode)
                    while len(params['zipcode']) < 5:
                        params['zipcode'] = '0' + params['zipcode']
                    params['neighborhood'] = user_home.address.neighborhood
                    params['latlng'] = user_home.address.latlng
                else:
                    params['kind'] = 'house'
                    params['num_hab'] = 'one'
                    params['size'] = 'small'
                    params['zipcode'] = ''
                    params['neighborhood'] = ''
                    params['latlng'] = 'null'
                if user_home.solar != None:
                    params['panels'] = user_home.solar.panels
                    params['capacity'] = user_home.solar.capacity
                    if (user_home.solar.since):
                        params['since'] = user_home.solar.since.strftime("%Y-%m-%d")
                else:
                    params['panels'] = 0
                    params['capacity'] = 250

        return self.render_template('materialize/users/settings/home.html', **params)

    def post(self):
        """ Get fields from POST dict """

        if not self.form.validate():
            message = _(messages.saving_error)
            message += "Tip: Asegura que el marcador en el mapa se encuentre en tu zona."
            self.add_message(message, 'danger')
            return self.get()
        kind = self.form.kind.data
        if 'undefined' in kind:
            kind = 'house'
        num_hab = self.form.num_hab.data
        if 'undefined' in num_hab:
            num_hab = 'one'
        size = self.form.size.data        
        if 'undefined' in size:
            size = 'medium'
        zipcode = int(self.form.zipcode.data)
        ageb = self.form.ageb.data
        dacl = self.form.dacl.data
        latlng = self.form.latlng.data
        neighborhood = self.form.neighborhood.data
        municipality = self.form.municipality.data
        state = self.form.state.data
        region = self.form.region.data
        fee = self.form.fee.data
        flag = self.form.flag.data
        panels = self.form.panels.data
        capacity = self.form.capacity.data
        since = self.form.since.data
        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            user_home = None
            try:
                
                if user_info.home_id == -1:
                    #create home
                    logging.info("Creating a new home...")
                    home = models.Home()
                    logging.info("User key to create home: %s" % user_info.key.id())
                    home.habitant.append(user_info.key.id())
                    home.cfe = models.CFE()
                    
                    #init
                    home.attributes = models.HomeAttributes()
                    home.attributes.essentials = models.Essentials()
                    home.address = models.Address()
                    home.solar = models.FV()

                    #assign home essentials                    
                    home.attributes.essentials.kind = kind
                    home.attributes.essentials.num_hab = num_hab
                    home.attributes.essentials.size = size

                    #assign home address                    
                    home.address.zipcode = int(zipcode)
                    home.address.ageb = ageb
                    home.address.neighborhood = neighborhood
                    home.address.municipality = municipality
                    home.address.state = state
                    home.address.region = region
                    home.address.latlng = ndb.GeoPt(latlng)
                    
                    #assign dac limit
                    home.cfe.dac_limit = int(dacl)
                    home.cfe.base_fee = fee  

                    #assign solar installation
                    home.solar.panels = panels
                    home.solar.capacity = capacity
                    if (len(since) > 9):
                        home.solar.since = date(int(since[:4]), int(since[5:7]), int(since[8:]))

                    #allocate in datastore
                    home.put()
                    user_info.home_id = home.key.id()
                    user_info.put()
                    logging.info("Home created with ID: %s" % user_info.home_id)
                else:
                    #update user home
                    user_home = models.Home.get_by_id(long(user_info.home_id))
                    logging.info("Updating home: %s" % user_home.key.id())

                    #init
                    if user_home.attributes == None:
                        user_home.attributes = models.HomeAttributes()
                    user_home.attributes.essentials = models.Essentials()
                    user_home.address = models.Address()
                    
                    #assign home essentials
                    user_home.attributes.essentials.kind = kind
                    user_home.attributes.essentials.num_hab = num_hab
                    user_home.attributes.essentials.size = size
                    logging.info("...essentials assigned...")

                    #assign home address
                    user_home.address.zipcode = int(zipcode)
                    user_home.address.ageb = ageb
                    user_home.address.neighborhood = neighborhood
                    user_home.address.municipality = municipality
                    user_home.address.state = state
                    user_home.address.region = region
                    user_home.address.latlng = ndb.GeoPt(latlng)
                    logging.info("...address assigned...")

                    #assign dac limit
                    user_home.cfe.dac_limit = int(dacl)
                    user_home.cfe.base_fee = fee  
                    logging.info("...dac limit & base fee assigned...")  

                    #assign solar installation
                    if user_home.solar != None:
                        user_home.solar.panels = panels
                        user_home.solar.capacity = capacity
                        if (len(since) > 9):
                            user_home.solar.since = date(int(since[:4]), int(since[5:7]), int(since[8:]))
                    else:
                        user_home.solar = models.FV()
                        user_home.solar.panels = panels
                        user_home.solar.capacity = capacity
                        if (len(since) > 9):
                            user_home.solar.since = date(int(since[:4]), int(since[5:7]), int(since[8:]))

                    
                    #allocate in datastore
                    user_home.put()
                    logging.info("Home updated with ID: %s" % user_home.key.id())

                user_home = models.Home.get_by_id(long(user_info.home_id))
                #: Email rodrigo if user from out of region or base_fee is different from fee while not being DAC
                if flag == 1 or (user_home.cfe.fee != user_home.cfe.base_fee and '1' in user_home.cfe.fee):
                    subject = "Usuario fuera de regiones tarifarias."
                    template_val = {
                        "username": user_info.username,
                        "email": user_info.email,
                        "support_url": self.uri_for("contact", _full=True),
                    }
                    body_path = "emails/user_out_of_region.txt"
                    body = self.jinja2.render_template(body_path, **template_val)
                    email = "rodrigo.dibildox@invictus.mx"
                    email_url = self.uri_for('taskqueue-send-email')                    
                    taskqueue.add(url=email_url, params={
                        'to': str(email),
                        'subject': subject,
                        'body': body,
                    })

                message = ''                
                message += " " + _(messages.saving_success)
                self.add_message(message, 'success')
                if (user_home.cfe.connected):
                    return self.redirect_to('materialize-home')
                else:
                    return self.redirect_to('materialize-settings-profile')

            except (AttributeError, KeyError, ValueError), e:
                logging.error('Error updating home profile: ' + e)
                message = _(messages.saving_error)
                self.add_message(message, 'danger')
                return self.get()

        except (AttributeError, TypeError), e:
            login_error_message = _(messages.expired_session)
            self.add_message(login_error_message, 'danger')
            self.redirect_to('materialize-login')

    @webapp2.cached_property
    def form(self):
        f = forms.EditHomeForm(self)
        return f



""" MEDIA handlers

    These handlers are used to upload and serve media as picture and pdf files.

"""
class AvatarUploadHandler(BaseHandler):
    """
    Handler for Edit User's Avatar
    """
    @user_required
    def post(self):
        """ Handles upload"""

        params = {}
        if not self.user:
            return self.render_template('home.html', **params)
        if not self.form.validate():
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            return self.redirect_to('edit-profile')
        picture = self.request.get('picture')
        user_info = self.user_model.get_by_id(long(self.user_id))
        if user_info != None:
            # Transform the image
            avatar = images.resize(picture, width=200, height=200, crop_to_fit=True, quality=100)
            user_info.picture = avatar
            user_info.put()
            message = _(messages.saving_success)
            self.add_message(message, 'success')
            self.redirect_to('edit-profile')

        message = _(messages.saving_error)
        self.add_message(message, 'danger')
        return self.redirect_to('edit-profile')
        

    @webapp2.cached_property
    def form(self):
        f = forms.AvatarForm(self)
        return f

class AvatarDownloadHandler(BaseHandler):
    """
    Handler for Serve User's Avatar
    """
    @user_required
    def get(self):
        """ Handles download"""

        params = {}
        if not self.user:
            return self.render_template('home.html', **params)

        if self.request.get('id') != '':
            logging.info('loading image from id: %s' % self.request.get('id'))
            user_info = self.user_model.get_by_id(long(self.request.get('id')))
            if user_info != None:
                if user_info.picture:
                    self.response.headers['Content-Type'] = 'image/png'
                    self.response.out.write(user_info.picture)
                else:
                    self.response.headers['Content-Type'] = 'text/plain'
                    self.response.out.write('No image')
        else: 
            logging.info('loading user\'s image')
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info != None:
                if user_info.picture:
                    self.response.headers['Content-Type'] = 'image/png'
                    self.response.out.write(user_info.picture)
                else:
                    self.response.headers['Content-Type'] = 'text/plain'
                    self.response.out.write('No image')

class CoverUploadHandler(BaseHandler):
    """
    Handler for Edit Users' Cover
    """
    @user_required
    def post(self):
        """ Handles upload"""

        at_profile = False if not self.request.get('at_profile') else True
        params = {}
        if not self.user:
             return self.redirect_to('materialize-login')
        if not self.form.validate():
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-vendor-setup-store') if not at_profile else self.redirect_to('materialize-vendor-settings-profile')
        picture = self.request.get('picture')
        try:
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info != None:
                if user_info.store_id != -1:
                    user_store = models.Store.get_by_id(long(user_info.store_id))
                else:
                    user_store = models.Store()
                    user_store.admin_email = user_info.email

                # Transform the image
                user_store.cover = images.resize(picture, width=1180, height=420, crop_to_fit=True, quality=100)
                user_store.put()
                user_info.store_id = user_store.key.id()
                user_info.put()

                message = _(messages.saving_success)
                self.add_message(message, 'success')
                return self.redirect_to('materialize-vendor-setup-store') if not at_profile else self.redirect_to('materialize-vendor-settings-profile')
        except:
            pass

        message = _(messages.saving_error)
        self.add_message(message, 'danger')
        return self.redirect_to('materialize-vendor-setup-store') if not at_profile else self.redirect_to('materialize-vendor-settings-profile')
        

    @webapp2.cached_property
    def form(self):
        f = forms.AvatarForm(self)
        return f

class CoverDownloadHandler(BaseHandler):
    """
    Handler for Serve Users' Cover
    """
    @user_required
    def get(self):
        """ Handles download"""

        params = {}
        if not self.user:
             return self.redirect_to('materialize-login')

        if self.request.get('id') != '':
            logging.info('loading image from id: %s' % self.request.get('id'))
            user_store = models.Store.get_by_id(long(self.request.get('id')))
            if user_store != None:
                if user_store.cover != None:
                    self.response.headers['Content-Type'] = 'image/png'
                    self.response.out.write(user_store.cover)

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.out.write('No image')
        else: 
            logging.info('loading user\'s image')
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info != None:
                if user_info.store_id != -1:
                    user_store = models.Store.get_by_id(long(user_info.store_id))
                    if user_store.cover != None:
                        self.response.headers['Content-Type'] = 'image/png'
                        self.response.out.write(user_store.cover)

            self.response.headers['Content-Type'] = 'text/plain'
            self.response.out.write('No image')

class ImgUploadHandler(BaseHandler):
    """
    Handler for Edit Vendor's Logo
    """
    @user_required
    def post(self, panel_id):
        """ Handles upload"""

        if not self.user:
             return self.redirect_to('materialize-login')
        if not self.form.validate():
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            return self.redirect_to('materialize-vendor-setup-panels', step=1)
        picture = self.request.get('picture')
        panel_id= panel_id if panel_id != 'new' else 'new'
        logging.info("panel_id : %s" % panel_id)
        user_panel = None
        try:
            logging.info("got into try")
            user_info = self.user_model.get_by_id(long(self.user_id))
            if user_info != None:
                if user_info.store_id != -1:
                    if panel_id != 'new':
                        user_panel = models.Panels.get_by_id(long(panel_id))
                    if user_panel is None:
                        user_panel = models.Panels()
                        user_panel.store_id = user_info.store_id

                    # Transform the image
                    user_panel.picture = images.resize(picture, width=400, height=380, crop_to_fit=True, quality=100)
                    user_panel.put()
                    _panel_id = user_panel.key.id()

                    message = _(messages.saving_success)
                    self.add_message(message, 'success')
                    return self.redirect_to('materialize-vendor-setup-panels', step=1, id=_panel_id)
        except Exception as e:
            message = _(messages.saving_error)
            self.add_message(message, 'danger')
            logging.info("error in form: %s" % e)
            return self.redirect_to('materialize-vendor-setup-panels', step=1)
         

    @webapp2.cached_property
    def form(self):
        f = forms.AvatarForm(self)
        return f

class ImgDownloadHandler(BaseHandler):
    """
    Handler for Serve Vendor's Logo
    """
    @user_required
    def get(self):
        """ Handles download"""

        params = {}
        if not self.user:
             return self.redirect_to('materialize-login')

        if self.request.get('id') != '':
            logging.info('loading image from id: %s' % self.request.get('id'))
            user_panel = models.Panels.get_by_id(long(self.request.get('id')))
            if user_panel != None:
                if user_panel.picture != None:
                    self.response.headers['Content-Type'] = 'image/png'
                    self.response.out.write(user_panel.picture)
        
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('No image')



""" CRONJOB + TASKQUEUE handlers

    These handlers obey to cron.yaml in order to produce recurrent, autonomous tasks

"""
class WelcomeCronjobHandler(BaseHandler):
    def get(self):
        welcome_url = self.uri_for('taskqueue-welcome')
        taskqueue.add(url=welcome_url, params={
            'offset': 0
        })
        
class WelcomeHandler(BaseHandler):
    """
    Core Handler for sending users welcome message
    Use with TaskQueue
    """

    @taskqueue_method
    def post(self):
        count = 0
        offset = int(self.request.get("offset"))
        attempt = 1
        if (self.request.get("attempt")):
            attempt = int(self.request.get("attempt")) + 1

        #Case "One taskqueue, many homes"
        homes = models.Home.query()
        for home in homes:
            if home.cfe.rpu != -1 and home.cfe.connected and home.tips_email_counter == 0:
                logging.info("Welcoming Home ID: %s" % home.key.id())
                count += 1
                if count > offset:
                    try:
                        for habitant in home.habitant:
                            user_info = self.user_model.get_by_id(long(habitant))
                            if user_info != None:
                                _username = user_info.name
                                logging.info("Welcome message being sent to: %s" % user_info.email)
                                subject = messages.email_welcome_subject
                                template_val = {
                                    "username": _username,
                                    "_url": self.uri_for("history", _full=True),
                                    "support_url": self.uri_for("contact", _full=True),
                                    "faq_url": self.uri_for("faq", _full=True)
                                }
                                body_path = "emails/welcome.txt"
                                body = self.jinja2.render_template(body_path, **template_val)
                                email = user_info.email
                                email_url = self.uri_for('taskqueue-send-email')
                                
                                taskqueue.add(url=email_url, params={
                                    'to': str(user_info.email),
                                    'subject': subject,
                                    'body': body,
                                })

                        home.tips_email_counter = 1
                        home.tips_email_lastdate = date.today()
                        home.put()

                    except Exception, e:
                        logging.error("Error welcoming home: %s. Retrying taskqueue in 5 seconds." % e)
                        logging.info("Attempt number: %s" % attempt)
                        time.sleep(5)
                        if attempt < 10:
                            welcome_url = self.uri_for('taskqueue-welcome')
                            taskqueue.add(url=welcome_url, params={
                                'offset': count - 1,
                                'attempt': attempt,
                            })
                        else:
                            welcome_url = self.uri_for('taskqueue-welcome')
                            taskqueue.add(url=welcome_url, params={
                                'offset': count,
                            })
                        break



""" API handlers

    These handlers obey to interactions with key-holder developers

"""
class APIIncomingHandler(BaseHandler):
    """
    Core Handler for incoming interactions
    """

    def post(self):
        KEY = "mwkMqTWFnK0LzJHyfkeBGoS2hr2KG7WhHqSGX0SbDJ4"
        SECRET = "152731fe2b14da111a72127d642e73c779e530b3"
        
        api_key = ""
        api_secret = ""
        args = self.request.arguments()
        for arg in args:
            logging.info("argument: %s" % arg)
            for key,value in json.loads(arg).iteritems():
                if key == "api_key":
                    api_key = value
                if key == "api_secret":
                    api_secret = value
                if key == "method":
                    if value == "101":
                        logging.info("parsing method 101")
                    elif value == "201":
                        logging.info("parsing method 201")

                        

        if api_key == KEY and api_secret == SECRET:
            logging.info("Attempt to receive incoming message from Simpplo with key: %s." % api_key)

            # DO SOMETHING WITH RECEIVED PAYLOAD

        else:
            logging.info("Attempt to receive incoming message from Simpplo without appropriate key: %s." % api_key)
            self.abort(403)

class APIOutgoingHandler(BaseHandler):
    """
    Core Handler for outgoing interactions with simpplo
    """

    def post(self):
        from google.appengine.api import urlfetch
        
        KEY = "mwkMqTWFnK0LzJHyfkeBGoS2hr2KG7WhHqSGX0SbDJ4"
        _URL = ""


        api_key = ""
        api_secret = ""
        args = self.request.arguments()
        for arg in args:
            logging.info("argument: %s" % arg)
            for key,value in json.loads(arg).iteritems():
                if key == "api_key":
                    api_key = value
                if key == "api_secret":
                    api_secret = value
                if key == "method":
                    if value == "101":
                        logging.info("parsing method 101")
                    elif value == "201":
                        logging.info("parsing method 201")
                        

        if api_key == KEY:
            logging.info("Attempt to send outgoing message to Simpplo with appropriate key: %s." % api_key)
            
            # DO SOMETHING WITH RECEIVED PAYLOAD
            #urlfetch.fetch(_URL, payload='', method='POST') 

        else:
            logging.info("Attempt to send outgoing message to Simpplo without appropriate key: %s." % api_key)
            self.abort(403)
       
class APITestingHandler(BaseHandler):
    """
    Core Handler for testing interactions with simpplo
    """

    def get(self):
        from google.appengine.api import urlfetch
        import urllib

        try:
            _url = self.uri_for('invictusapi-simpplo-out', _full=True)
            urlfetch.fetch(_url, payload='{"api_key": "mwkMqTWFnK0LzJHyfkeBGoS2hr2KG7WhHqSGX0SbDJ4","channel": "CHANNELHERE","container": "CONTENTSHERE"}', method="POST")
        except:
            pass
        self.response.headers['Content-Type'] = 'text/plain'
        self.response.out.write('Tests went good... =)')



""" WEB  static handlers

    These handlers are just to be a full website in the web background.

"""
class RobotsHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'text/plain'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/robots.txt" % self.get_theme).read()))

class HumansHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'text/plain'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/humans.txt" % self.get_theme).read()))

class SitemapHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'application/xml'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/sitemap.xml" % self.get_theme).read()))

class CrossDomainHandler(BaseHandler):
    def get(self):
        params = {
            'scheme': self.request.scheme,
            'host': self.request.host,
        }
        self.response.headers['Content-Type'] = 'application/xml'

        def set_variables(text, key):
            return text.replace("{{ %s }}" % key, params[key])

        self.response.write(reduce(set_variables, params, open("bp_content/themes/%s/templates/seo/crossdomain.xml" % self.get_theme).read()))
