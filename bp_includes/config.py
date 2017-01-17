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
    'app_name':  unicode('M-Boilerplate','utf-8'),
    'app_id': 'mboilerplate',
    'app_domain':  'http://mboilerplate.appspot.com',
    'app_lang': 'en', # currently: 'en', 'es', this conditional calls which emails/ and templates/ are loaded in jinja's render_template
    'base_layout': '/en/materialize/users/base.html', #remember to take into account the app_lang element
    'landing_layout': '/en/materialize/landing/base.html', #remember to take into account the app_lang element
    # add status codes and templates used to catch and display errors
    # if a status code is not listed here it will use the default app engine
    # stacktrace error page or browser error page, remember app.yaml has routes that should be fixed to app language
    'error_templates': {
        403: '/en/errors/forbidden_access.html',
        404: '/en/errors/404.html',
        500: '/en/errors/500.html',
    },
    'simplify': False, # means web app has no landing, just login directly
    'has_contents': False, # means web app includes contents to share from administrator tu users
    'has_specials': False, # means web app includes special user roles
    'has_blog': False, # means web app includes Blog
    'has_referrals': False, # if this is set to true, remember we should fix referrals and settings/referrals htmls
    'has_translation': False, # this is a simple conditional to use i.e. if user wants to implement jquery translator
    'has_basics': True, # means web app includes FAQ Terms Privacy Contact
    'has_notifications': False, # means web app pushes chrome-like notifications

    # application branding 
    'brand_logo': 'http://mboilerplate.appspot.com/default/materialize/images/brand/logo.png',
    'brand_email_logo': 'http://mboilerplate.appspot.com/default/materialize/images/brand/logo.png',
    'brand_favicon': 'http://mboilerplate.appspot.com/default/materialize/images/brand/fav.png',
    'brand_color' : '#151A7B', # if sublime package color picker, select color and press 'cmd+shift+C' to easily see and select color
    'brand_secondary_color' : '#74C0F6', # if sublime package color picker, select color and press 'cmd+shift+C' to easily see and select color
    'brand_tertiary_color' : '#EBEBEB', # if sublime package color picker, select color and press 'cmd+shift+C' to easily see and select color
    'brand_layout': 'splash',  #splash or video choices
    'brand_video': 'http://mboilerplate.appspot.com/default/materialize/video/space.mp4',
    'brand_splash': 'http://mboilerplate.appspot.com/default/materialize/images/landing/splash.png',
    'brand_splash_light':  '95',
    'brand_about': unicode("""
            MBoilerplate by OneSmart.Tech: Quick prototyping, astonishingly beautiful in the cheapest and most powerful cloud.
            """,'utf-8'),
    ## remember to edit bp_content/themes/default/seo/ files: manifest.json, humans.txt, crossdomain.xml

    # application on the web
    'meta_tags_code': unicode("""
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
            <meta name="apple-mobile-web-app-capable" content="yes">
            <meta name="mobile-web-app-capable" content="yes">
            <link rel="manifest" href="/manifest.json">
            <meta name="description" content="MBoilerplate by OneSmart.Tech: Quick prototyping, astonishingly beautiful in the cheapest and most powerful cloud." />
            <meta name="keywords" content="mlight, mboilerplate, appengine, materialize, boilerplate, google cloud, gae"/>
            <meta property="og:site_name" content="mboilerplate.appspot.com"/>
            <meta property="og:title" content="mboilerplate.appspot.com"/>
            <meta property="og:type" content="website"/>
            <meta property="og:description" content="MBoilerplate by OneSmart.Tech: Quick prototyping, astonishingly beautiful in the cheapest and most powerful cloud."/>
            <meta property="og:url" content="mboilerplate.appspot.com"/>
            <meta property="og:image" content="http://mboilerplate.appspot.com/default/materialize/images/landing/splash.png"/>
            <meta name="twitter:card" content="summary_large_image">
            <meta name="twitter:site" content="MBoilerplate by OneSmart.Tech: Quick prototyping, astonishingly beautiful in the cheapest and most powerful cloud.">
            <meta name="twitter:creator" content="@chuycepeda">
            <meta name="twitter:title" content="mboilerplate.appspot.com">
            <meta name="twitter:description" content="MBoilerplate by OneSmart.Tech: Quick prototyping, astonishingly beautiful in the cheapest and most powerful cloud.">
            <meta name="twitter:image" content="http://mboilerplate.appspot.com/default/materialize/images/landing/splash.png">
            <meta property="twitter:url" content="mboilerplate.appspot.com"/>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="viewport" content="width=device-width, minimum-scale=1.0, initial-scale=1.0, user-scalable=yes">
            """,'utf-8'),

    # Locale code = <language>_<territory> (ie 'en_US')
    # to pick locale codes see http://cldr.unicode.org/index/cldr-spec/picking-the-right-language-code
    # also see http://www.sil.org/iso639-3/codes.asp
    # Language codes defined under iso 639-1 http://en.wikipedia.org/wiki/List_of_ISO_639-1_codes
    # Territory codes defined under iso 3166-1 alpha-2 http://en.wikipedia.org/wiki/ISO_3166-1
    # disable i18n if locales array is empty or None
    # the default language code for the application.
    # should match whatever language the site uses when i18n is disabled
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
    'facebook_appID': '', #GET IT FROM: https://developers.facebook.com/apps/
    'google_clientID': '', #GET IT FROM: https://console.cloud.google.com/apis/credentials?project=<PROJECT_ID>

    # get your own recaptcha keys by registering at http://www.google.com/recaptcha/
    'captcha_public_key': "6LcMfv0SAAAAAGMJ9i-g5aJhXFvSHpPsqDLOHTUD",
    'captcha_private_key': "6LcMfv0SAAAAALMUmCmFt5NOAw_ZTHabWRHAFJI6",

    # Password AES Encryption Parameters
    # aes_key must be only 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes (characters) long.
    'aes_key': "99020A1BED058F799823438702434F83",
    'salt': "8ECCC9480BFC6CB2D842E14EEEBA3925E9E0485FE4E634907BCD5EC4F29BE5DE8ED97637366B2C18A9464F3C10ADFA0DB97451C8DB1033A6C2D6C4231D0645EF",

    # Use a complete Google Analytics code, no just the Tracking ID
    'google_analytics_code': """
        <script>
          (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
          (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
          m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
          })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

          ga('create', 'UA-89963636-1', 'auto');
          ga('send', 'pageview');

        </script>""",

    # Enable Federated login (OpenID and OAuth)
    # Google App Engine Settings must be set to Authentication Options: Federated Login
    'enable_federated_login': False,

    # send error emails to developers
    'send_mail_developer': False,

    # fellas' list
    'developers': (
        ('chuycepeda', 'chuycepeda@gmail.com'),
    ),

    # If true, it will write in datastore a log of every email sent
    'log_email': True,

    # If true, it will write in datastore a log of every visit
    'log_visit': True,

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----

    #sendgrid integration if you wish to get more than 100 free emails from google email service.
    'sendgrid_login' : '',
    'sendgrid_passkey' : '',
    'sendgrid_priority': False,

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

    #google apis, 
    #grab each of them after enabling the api at https://console.cloud.google.com/apis/library?project=<YOUR PROJECT ID>
    #after, create an appropriately named credential as API Key at https://console.cloud.google.com/apis/credentials?project=YOUR PROJECT ID>
    'google_maps_key': 'AIzaSyBaSx2JjNt0VSrilJVRcsEwX3W-zft_FQM', #remember to enable Geocode API at GCP console
    'google_nlp_key': 'AIzaSyCXbP34cg9cLJEAJXi501DxrR34L_tsxqk',
    'google_vision_key': 'AIzaSyA1lWQlYlEaPATMaElEe6iTVl_cjkvonVQ',

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
    #                       dropboxID:   "XXXXXXXXX",
    #                       url:         "https://youraccount.zendesk.com",
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
