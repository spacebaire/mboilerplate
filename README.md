#Hello, this is magic ! #

*The materialize boilerplate project is an amazing fusion from material design, polymer web components, and boilerplate framework for easy and quick deployments of web applications on the Google Cloud Platform.*


###Get started in just a few easy steps*

1. Download the last version of the [App Engine SDK](http://code.google.com/appengine/downloads.html#Google_App_Engine_SDK_for_Python) for Linux, Mac OS or Windows.
2. Download or clone the code of this Boilerplate ([here](https://github.com/chuycepeda/mboilerplate/zipball/master))
3. Run locally ([instructions](https://developers.google.com/appengine/docs/python/tools/devserver)).
4. Set your 'application' name in [app.yaml](https://github.com/chuycepeda/mboilerplate/blob/master/app.yaml)
1. Set custom config parameters in bp_content/themes [config/localhost.py](https://github.com/chuycepeda/mboilerplate/blob/master/bp_content/themes/default/config/localhost.py), [config/testing.py](https://github.com/chuycepeda/mboilerplate/blob/master/bp_content/themes/default/config/testing.py) and [config/production.py](https://github.com/chuycepeda/mboilerplate/blob/master/bp_content/themes/default/config/production.py) like secret key, [recaptcha code](http://www.google.com/recaptcha), salt and other.
 * Boilerplate will identify which config file to use in local, unit testing and production.
 * To get started, look the default settings in [bp_includes/config.py](https://github.com/chuycepeda/mboilerplate/blob/master/bp_includes/config.py). Those settings will be overwrite for your config files.
 * Most of the default settings will need to be changed to yield a secure and working application.
1. Deploy it online ([instructions](https://developers.google.com/appengine/docs/python/gettingstarted/uploading) - recommended setup: python 2.7, high replication datastore)

Please note that your custom application code **should be located in the bp_content folder within your own theme**.
The intention is that separating the boilerplate code from your application code will avoid merge conflicts as you keep up with future boilerplate changes.

*As is from [GAEBoilerplate Repo](https://github.com/coto/gae-boilerplate/)

Also, you can see a simple and quick setup in this video:

[![Getting your app in 7 minutes](https://i.ytimg.com/vi/l7fc8rLUOjM/default.jpg)](https://www.youtube.com/watch?v=l7fc8rLUOjM)



###What's Materialize?
Materialize simplifies life for developers and the users they serve. It speeds up development, heavy lifting has been done for you to provide a smoother experience for visitors. ([showcase](http://materializecss.com/showcase.html))

###What's Polymer?
Polymer lets you build encapsulated, re-usable elements that work just like HTML elements, to use in building web applications. It makes it easier than ever to make fast, beautiful, and interoperable web components. ([polymer-project](https://www.polymer-project.org/1.0/))


###What's Boilerplate?
A Boilerplate is used to describe sections of code that can be reused over and over in new contexts or applications which provides good default values, reducing the need to specify program details in every project. ([wikipedia](http://en.wikipedia.org/wiki/Boilerplate_code))

---

#####Functions and features

+ Authentication (Sign In, Sign Out, Sign Up)
+ Federated Login - login via your favorite social network (Google, Twitter, etc...) powered by OpenID and OAuth
+ Reset Password
+ Update User Profile
+ Contact Form
+ Client side and server side form validation
+ Automatic detection of user language
+ Support for many Languages (English, Spanish, Italian, French, Chinese, Indonesian, German, Russian, etc)
+ Visitors Log
+ Notifications and Confirmation for users when they change their email or password
+ Responsive Design for viewing on PCs, tablets, and mobile phones (synchronized with Twitter-Bootstrap project)
+ Mobile identification
+ Unit Testing
+ Error handling
+ Basic user management features available under /admin/users/ for Google Application Administrators

#####Technologies used
+ [Python 2.7.5](https://www.python.org/download/releases/2.7.5/)
+ [NDB 1.0.10](http://developers.google.com/appengine/docs/python/ndb/) (The best datastore API for the Google App Engine Python runtime).
+ [Jinja2 2.6](http://jinja.pocoo.org/docs/) (A fully featured template engine for Python).
+ [WTForms-1.0.2](http://wtforms.simplecodes.com/) (Forms validation framework keeping user interaction secure and flexible with or without javascript).
+ [Babel-0.9.6](http://babel.edgewall.org/) and [gaepytz-2011h](http://code.google.com/p/gae-pytz/) (Industy standard internationalization renders the site in multiple languages).
+ [webapp2 2.5.2](http://webapp-improved.appspot.com/) (A lightweight Python web framework, the most compatible with Google App Engine).
    + webapp2_extras.sessions
    + webapp2_extras.routes
    + webapp2_extras.auth
    + webapp2_extras.i18n
+ Code written following the [Google Python Style Guide](http://google-styleguide.googlecode.com/svn/trunk/pyguide.html)
+ Unit testing with [unittest](http://docs.python.org/library/unittest.html), [webtest](http://webtest.pythonpaste.org/en/latest/index.html), [pyquery](http://packages.python.org/pyquery/)
+ OpenID library provided by Google App Engine
+ OAuth2 for federated login providers that do not support OpenID

#####Front-end Technologies
+ [HTML5Boilerplate](http://html5boilerplate.com/)
+ [Modernizr 2.6.1](http://modernizr.com)
+ [jQuery 2.1.1](http://jquery.com)
+ [MaterializeCSS](http://materializecss.com/)
+ [Polymer](https://www.polymer-project.org/1.0/)

#####Interesting integrations
+ [Bit.ly](https://bitly.com)
+ [Goo.gl](http://goo.gl/)
+ [Slack](http://slack.com)
+ [Sendgrid](http://sendgrid.com)
+ [CartoDB](http://cartodb.com)


#####Security
**SSL**

+ SSL is enabled site wide by adding <tt>secure: always</tt> to the section: <tt>- url: /.*</tt> in app.yaml (remove this line to disable)
+ SSL either requires a free google app engine *.appspot.com domain or a [custom domain and certificate](https://developers.google.com/appengine/docs/ssl)
+ Alternatively SSL can be enabled at a controller level via webapp2 schemes. Use the secure_scheme provided in routes.py
+ It is recommended to enable ssl site wide to help prevent [session hijacking](http://en.wikipedia.org/wiki/Session_hijacking)

**Passwords**

+ Passwords are hashed and encrypted with SHA512 and PyCrypto.

**CSRF**

+ [Cross-site request forgery](http://en.wikipedia.org/wiki/Cross-site_request_forgery) protection