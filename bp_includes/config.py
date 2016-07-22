# -*- coding: utf-8 -*-
"""
============= DON'T MODIFY THIS FILE ============
This is the boilerplate default configuration file.
Changes and additions to settings should be done in
/bp_content/themes/<YOUR_THEME>/config/ rather than this config.
"""

import os

config = {

    # webapp2 sessions
    'webapp2_extras.sessions': {'secret_key': '_PUT_KEY_HERE_YOUR_SECRET_KEY_'},

    # webapp2 authentication
    'webapp2_extras.auth': {'user_model': 'bp_includes.models.User',
                            'cookie_name': 'session_name'},

    # jinja2 templates
    'webapp2_extras.jinja2': {'template_path': ['bp_admin/templates', 'bp_content/themes/%s/templates' % os.environ['theme']],
                              'environment_args': {'extensions': ['jinja2.ext.i18n']}},

    # application name
    'app_name':  unicode('M Boilerplate','utf-8'),
    'app_id': 'mboilerplate',
    'app_domain':  'http://mboilerplate.appspot.com',
    # application branding 
    'brand_logo': 'http://mboilerplate.appspot.com/default/materialize/images/favicon/fav-white.png',
    'brand_email_logo': 'http://mboilerplate.appspot.com/default/materialize/images/favicon/fav-blue.png',
    'brand_favicon': 'http://mboilerplate.appspot.com/default/materialize/images/favicon/fav.png',
    'brand_color' : '#16ADED',
    'brand_secondary_color' : '#0D3290',
    'brand_tertiary_color' : '#EAEAEA',
    'brand_layout': 'splash',  #splash or video choices
    'brand_video': 'http://mboilerplate.appspot.com/default/materialize/video/space.mp4',
    'brand_splash': 'http://mboilerplate.appspot.com/default/materialize/images/landing/black_mac.png',
    'brand_splash_light':  '45',
    # application on the web
    'meta_tags_code': """
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
            <meta name="description" content="This an amazing, magical materialized boilerplate for the Google AppEngine." />
            <meta name="keywords" content="mboilerplate, appengine, materialize, boilerplate, webcomponents, google cloud, gae"/>
            <meta property="og:site_name" content="MBoilerplate.appspot.com"/>
            <meta property="og:title" content="MBoilerplate"/>
            <meta property="og:type" content="website"/>
            <meta property="og:description" content="This an amazing, magical materialized boilerplate for the Google AppEngine."/>
            <meta property="og:url" content="http://mboilerplate.appspot.com"/>
            <meta property="og:image" content="http://mboilerplate.appspot.com{{brand_splash}}"/>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:site" content="This an amazing, magical materialized boilerplate for the Google AppEngine.">
            <meta name="twitter:creator" content="@chuycepeda">
            <meta name="twitter:title" content="MBoilerplate">
            <meta name="twitter:description" content="This an amazing, magical materialized boilerplate for the Google AppEngine.">
            <meta name="twitter:image" content="http://mboilerplate.appspot.com{{brand_splash}}">
            <meta property="twitter:url" content="http://mboilerplate.appspot.com"/>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="viewport" content="width=device-width, minimum-scale=1.0, initial-scale=1.0, user-scalable=yes">""",

    # the default language code for the application.
    # should match whatever language the site uses when i18n is disabled
    'app_lang': 'en',

    # jinja2 base layout template
    'base_layout': '/materialize/users/base.html',
    'landing_layout': '/materialize/landing/base.html',

    # Locale code = <language>_<territory> (ie 'en_US')
    # to pick locale codes see http://cldr.unicode.org/index/cldr-spec/picking-the-right-language-code
    # also see http://www.sil.org/iso639-3/codes.asp
    # Language codes defined under iso 639-1 http://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
    # Territory codes defined under iso 3166-1 alpha-2 http://en.wikipedia.org/wiki/ISO_3166-1
    # disable i18n if locales array is empty or None
    'locales': ['en_US', 'es_ES', 'it_IT', 'zh_CN', 'id_ID', 'fr_FR', 'de_DE', 'ru_RU', 'pt_BR', 'cs_CZ','vi_VN','nl_NL'],

    # contact page email settings
    'contact_sender': '',
    'contact_recipient': "chuycepeda@gmail.com",

    # application on social media
    'twitter_url': '',
    'twitter_appID': '', #GET IT FROM: https://apps.twitter.com/
    'twitter_handle': '',
    'facebook_url': '',
    'facebook_handle':'',
    'facebook_appID': '523620084480399', #GET IT FROM: https://developers.facebook.com/apps/
    'google_clientID': '143126415076-6sm0gdcglfnv1t3bp7ffbp7eok9sklm6.apps.googleusercontent.com', #GET IT FROM: https://elements.polymer-project.org/elements/google-signin

    # get your own recaptcha keys by registering at http://www.google.com/recaptcha/
    'captcha_public_key': "6LcMfv0SAAAAAGMJ9i-g5aJhXFvSHpPsqDLOHTUD",
    'captcha_private_key': "6LcMfv0SAAAAALMUmCmFt5NOAw_ZTHabWRHAFJI6",

    # Password AES Encryption Parameters
    # aes_key must be only 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes (characters) long.
    'aes_key': "A1BED038702434F8358F799990208234",
    'salt': "634907BCD5EC4F29BE5DE8ED97637366B2C18E42E14EEEBA3925E9E0485FCCC9480BFC6CB2D8E4E8A9464F3C10ADFA0DB97451C8DB1033A6C2D6C4231D0645EF",

    # Use a complete Google Analytics code, no just the Tracking ID
    # In config/boilerplate.py there is an example to fill out this value
    'google_analytics_code': """
        <script>
          (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
          (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
          m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
          })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

          ga('create', 'UA-73362805-1', 'auto');
          ga('send', 'pageview');

        </script>""",

    
    # add status codes and templates used to catch and display errors
    # if a status code is not listed here it will use the default app engine
    # stacktrace error page or browser error page
    'error_templates': {
        403: 'errors/default_error.html',
        404: 'errors/404.html',
        500: 'errors/500.html',
    },

    # Enable Federated login (OpenID and OAuth)
    # Google App Engine Settings must be set to Authentication Options: Federated Login
    'enable_federated_login': True,

    # send error emails to developers
    'send_mail_developer': False,

    # fellas' list
    'developers': (
        ('Santa Klauss', 'snowypal@northpole.com'),
        ('chuycepeda', 'chuycepeda@gmail.com'),
    ),

    # If true, it will write in datastore a log of every email sent
    'log_email': True,

    # If true, it will write in datastore a log of every visit
    'log_visit': True,

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----

    #sendgrid integration if you wish to get more than 20,100 free emails from google email service.
    'sendgrid_login' : '',
    'sendgrid_passkey' : '',

      #bitly Login & API KEY, get them from your bitly account under settings/advanced. this is used to generate a short referrals link.
    'bitly_login' : "mboilerplate",
    'bitly_apikey' : "R_c7794de8fef148c6b950578064492e95",

    #slack webhook url to bring notifications to your dev slack channel
    'slack_webhook_url' : "https://hooks.slack.com/services/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",
    'slack_notify_user' : '',
    'slack_notify_home_visit' : '',
    'slack_notify_landing_visit' : '',

    #cartodb integration
    'cartodb_user': '',
    'cartodb_apikey': '',

    #google apis
    'google_maps_key': 'AIzaSyBaSx2JjNt0VSrilJVRcsEwX3W-zft_FQM',
    'google_nlp_key': 'AIzaSyCXbP34cg9cLJEAJXi501DxrR34L_tsxqk',

    #zendesk integration
    'zendesk_imports': '',
    #EXAMPLE OF ZENDESK IMPORTS
    # """<style type="text/css" media="screen, projection">
    #               @import url(//assets.zendesk.com/external/zenbox/v2.6/zenbox.css);
    #             </style>"""
    'zendesk_code': '',
    #EXAMPLE OF ZENDESK CODE
    # """<script type="text/javascript" src="//assets.zendesk.com/external/zenbox/v2.6/zenbox.js"></script>
    #             <script>
    #                 if (typeof(Zenbox) !== "undefined") {
    #                     Zenbox.init({
    #                       dropboxID:   "20172435",
    #                       url:         "https://invictusmx.zendesk.com",
    #                       tabTooltip:  "Feedback",
    #                       tabImageURL: "https://p4.zdassets.com/external/zenbox/images/tab_es_feedback_right.png",
    #                       tabColor:    "#ff0000",
    #                       tabPosition: "Right",
    #                       hide_tab: true,
    #                     });

    #                 }
    #                 if (document.querySelector('#zen_alias'))
    #                     document.querySelector('#zen_alias').addEventListener('click', function() { window.Zenbox.show();});
    #                 if (document.querySelector('#chat_alias'))
    #                     document.querySelector('#chat_alias').addEventListener('click', function() { window.Zenbox.show();});
    #             </script>"""

    #mailchimp integration
    'mailchimp_code': '',



} # end config
