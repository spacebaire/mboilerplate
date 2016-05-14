config = {

    # This config file will be detected in localhost environment and values defined here will overwrite those in config.py
    'environment': "localhost",

    # ----> ADD MORE CONFIGURATION OPTIONS HERE <----
    
    'app_name': "mboilerplate @localhost",
    
    
    'error_templates': {
        403: 'errors/default_error.html',
        404: 'errors/404.html',
        500: 'errors/500.html',
    },
    
     # contact page email settings
    'contact_sender': "SENDER_EMAIL_HERE",
    'contact_recipient': "RECIPIENT_EMAIL_HERE",
	
	
    # get your own recaptcha keys by registering at http://www.google.com/recaptcha/
    'captcha_public_key': "CAPTCHA_PUBLIC_KEY",
    'captcha_private_key': "CAPTCHA_PRIVATE_KEY",

    # Password AES Encryption Parameters
    # aes_key must be only 16 (*AES-128*), 24 (*AES-192*), or 32 (*AES-256*) bytes (characters) long.
    'aes_key': "12_24_32_BYTES_KEY_FOR_PASSWORDS",
    'salt': "_PUT_SALT_HERE_TO_SHA512_PASSWORDS_",   
    
    # jinja2 base layout template
    #'base_layout': 'master.html',

    # send error emails to developers
    'send_mail_developer': False,

    # fellas' list
    'developers': (
        ('chuycepeda', 'chuycepeda@gmail.com'),
    ),

    
}