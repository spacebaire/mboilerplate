# -*- coding: utf-8 -*-
"""
Using redirect route instead of simple routes since it supports strict_slash
Simple route: http://webapp-improved.appspot.com/guide/routing.html#simple-routes
RedirectRoute: http://webapp-improved.appspot.com/api/webapp2_extras/routes.html#webapp2_extras.routes.RedirectRoute
"""
from webapp2_extras.routes import RedirectRoute
from bp_includes import handlers
from bp_includes.config import config

secure_scheme = 'https'
appid = config['app_id']

_routes = [
    RedirectRoute('/_ah/login_required', handlers.LoginRequiredHandler),
    
    # Landing
    RedirectRoute('/', handlers.MaterializeLandingRequestHandler, name='landing', strict_slash=True), 
    RedirectRoute('/blog/', handlers.MaterializeLandingBlogRequestHandler, name='blog', strict_slash=True),
    RedirectRoute('/blog/<post_id>/', handlers.MaterializeLandingBlogPostRequestHandler, name='blog-post', strict_slash=True),
    RedirectRoute('/contact/', handlers.MaterializeLandingContactRequestHandler, name='contact', strict_slash=True),
    RedirectRoute('/faq/', handlers.MaterializeLandingFaqRequestHandler, name='faq', strict_slash=True),
    RedirectRoute('/tou/', handlers.MaterializeLandingTouRequestHandler, name='tou', strict_slash=True),
    RedirectRoute('/privacy/', handlers.MaterializeLandingPrivacyRequestHandler, name='privacy', strict_slash=True),
    RedirectRoute('/license/', handlers.MaterializeLandingLicenseRequestHandler, name='license', strict_slash=True),
    RedirectRoute('/register/', handlers.MaterializeRegisterRequestHandler, name='register', strict_slash=True),
    RedirectRoute('/activation/<user_id>/<token>', handlers.MaterializeAccountActivationHandler, name='account-activation', strict_slash=True),
    RedirectRoute('/resend/<user_id>/<token>', handlers.ResendActivationEmailHandler, name='resend-account-activation', strict_slash=True),
    RedirectRoute('/register/referral/<user_id>/', handlers.MaterializeRegisterReferralHandler, name='register-referral', strict_slash=True),
    RedirectRoute('/activation/<ref_user_id>/<token>/<user_id>', handlers.MaterializeAccountActivationReferralHandler, name='account-activation-referral', strict_slash=True),
    RedirectRoute('/login/', handlers.MaterializeLoginRequestHandler, name='login', strict_slash=True),
    RedirectRoute('/logout/', handlers.MaterializeLogoutRequestHandler, name='logout', strict_slash=True),
    RedirectRoute('/password-reset/', handlers.PasswordResetHandler, name='password-reset', strict_slash=True),
    RedirectRoute('/password-reset/<user_id>/<token>', handlers.PasswordResetCompleteHandler, name='password-reset-check', strict_slash=True),
    
    # User
    RedirectRoute('/user/home/', handlers.MaterializeHomeRequestHandler, name='materialize-home', strict_slash=True),
    RedirectRoute('/user/demos/', handlers.MaterializeDemosRequestHandler, name='materialize-demos', strict_slash=True),
    RedirectRoute('/user/referrals/', handlers.MaterializeReferralsRequestHandler, name='materialize-referrals', strict_slash=True),
    RedirectRoute('/user/settings/profile/', handlers.MaterializeSettingsProfileRequestHandler, name='materialize-settings-profile', strict_slash=True),
    RedirectRoute('/user/settings/email/', handlers.MaterializeSettingsEmailRequestHandler, name='materialize-settings-email', strict_slash=True),
    RedirectRoute('/user/settings/password/', handlers.MaterializeSettingsPasswordRequestHandler, name='materialize-settings-password', strict_slash=True),
    RedirectRoute('/user/settings/delete/', handlers.MaterializeSettingsDeleteRequestHandler, name='materialize-settings-delete', strict_slash=True),
    RedirectRoute('/user/settings/referrals/', handlers.MaterializeSettingsReferralsRequestHandler, name='materialize-settings-referrals', strict_slash=True),
    RedirectRoute('/user/settings/social/', handlers.MaterializeSettingsSocialRequestHandler, name='materialize-settings-social', strict_slash=True),
    RedirectRoute('/user/change-email/<user_id>/<encoded_email>/<token>', handlers.MaterializeEmailChangedCompleteHandler, name='materialize-email-changed-check', strict_slash=True),
    
    # SEO
    RedirectRoute(r'/robots.txt', handlers.RobotsHandler, name='robots', strict_slash=True),
    RedirectRoute(r'/humans.txt', handlers.HumansHandler, name='humans', strict_slash=True),
    RedirectRoute(r'/sitemap.xml', handlers.SitemapHandler, name='sitemap', strict_slash=True),
    RedirectRoute(r'/crossdomain.xml', handlers.CrossDomainHandler, name='crossdomain', strict_slash=True),
    
    #Taskqueues
    RedirectRoute('/taskqueue-send-email/', handlers.SendEmailHandler, name='taskqueue-send-email', strict_slash=True),

    #Rest helpers: to-do implement Cloud Endpoints
    RedirectRoute('/user/helper/basic/', handlers.RestBasicHelper, name='helper-basic', strict_slash=True),
    RedirectRoute('/user/helper/mysql/', handlers.RestMySQLHelper, name='helper-mysql', strict_slash=True),

    #Inbound services
    RedirectRoute('/_ah/bounce/', handlers.LogBounceHandler),
    RedirectRoute('/_ah/mail/no-reply@%s.appspotmail.com' % appid, handlers.LogReceivedEmailHandler),
    RedirectRoute('/_in/channel/notify_token/', handlers.GetChannelToken, name='inbound-channel-token', strict_slash=True),
    RedirectRoute('/_ah/channel/connected/', handlers.ClientConnectedHandler),
    RedirectRoute('/_ah/channel/disconnected/', handlers.ClientDisconnectedHandler),
   
    # Blob handlers for media
    RedirectRoute('/media/serve/<kind>/<media_id>/', handlers.MediaDownloadHandler, name='media-serve', strict_slash=True),
    RedirectRoute('/blobstore/form/', handlers.BlobFormHandler, name='blob-form', strict_slash=True),
    RedirectRoute('/blobstore/upload/', handlers.BlobUploadHandler, name='blob-upload', strict_slash=True),
    RedirectRoute('/blobstore/serve/<photo_key>', handlers.BlobDownloadHandler, name='blob-serve', strict_slash=True),
    
]

def get_routes():
    return _routes

def add_routes(app):
    if app.debug:
        secure_scheme = 'http'
    for r in _routes:
        app.router.add(r)
