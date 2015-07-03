config = {

    # This config file will be detected in production environment and values defined here will overwrite those in config.py
    'environment': "production",

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----
   'app_name': "Materialize Boilerplate",
    
  #  'google_analytics_code': """
  #  		<!-- KISSmetrics tracking snippet -->
		# <script type="text/javascript">var _kmq = _kmq || [];
		# var _kmk = _kmk || '5ca08bc394e27023f21a198f118695b2ae8d8666';
		# function _kms(u){
		#   setTimeout(function(){
		# 	var d = document, f = d.getElementsByTagName('script')[0],
		# 	s = d.createElement('script');
		# 	s.type = 'text/javascript'; s.async = true; s.src = u;
		# 	f.parentNode.insertBefore(s, f);
		#   }, 1);
		# }
		# _kms('//i.kissmetrics.com/i.js');
		# _kms('//doug1izaerwt3.cloudfront.net/' + _kmk + '.1.js');
		# </script>
   
 
  #  		<!-- GoogleAnalytics tracking snippet -->
  #       <script>
		#   (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
		#   (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
		#   m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
		#   })(window,document,'script','//www.google-analytics.com/analytics.js','ga');

		#   ga('create', 'UA-55706622-1', 'auto');
		#   ga('send', 'pageview');

		# </script>
  #   """,
    
    'error_templates': {
        403: 'errors/default_error.html',
        404: 'materialize/errors/404.html',
        500: 'materialize/errors/500.html',
    },
    
     # contact page email settings
    'contact_sender': "SENDER_EMAIL_HERE",
    'contact_recipient': "chuycepeda@gmail.com",
	
	
    # get your own recaptcha keys by registering at http://www.google.com/recaptcha/
    'captcha_public_key': "6LcMfv0SAAAAAGMJ9i-g5aJhXFvSHpPsqDLOHTUD",
    'captcha_private_key': "6LcMfv0SAAAAALMUmCmFt5NOAw_ZTHabWRHAFJI6",

    # Password AES Encryption Parameters
    # aes_key must be only 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes (characters) long.
    'aes_key': "A1BED038702434F8358F799990208234",
    'salt': "634907BCD5EC4F29BE5DE8ED97637366B2C18E42E14EEEBA3925E9E0485FCCC9480BFC6CB2D8E4E8A9464F3C10ADFA0DB97451C8DB1033A6C2D6C4231D0645EF",

    # get your own consumer key and consumer secret by registering at https://dev.twitter.com/apps
    # callback url must be: http://[YOUR DOMAIN]/login/twitter/complete
    'twitter_consumer_key': 'TWITTER_CONSUMER_KEY',
    'twitter_consumer_secret': 'TWITTER_CONSUMER_SECRET',

    #Facebook Login
    # get your own consumer key and consumer secret by registering at https://developers.facebook.com/apps
    #Very Important: set the site_url= your domain in the application settings in the facebook app settings page
    # callback url must be: http://[YOUR DOMAIN]/login/facebook/complete
    'fb_api_key': 'FACEBOOK_API_KEY',
    'fb_secret': 'FACEBOOK_SECRET',
    
    # jinja2 base layout template
    #'base_layout': 'master.html',

    # send error emails to developers
    'send_mail_developer': False,

    # fellas' list
    'developers': (
        ('chuycepeda', 'chuycepeda@gmail.com'),
    )
}