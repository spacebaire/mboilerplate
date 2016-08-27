"""
Using redirect route instead of simple routes since it supports strict_slash
Simple route: http://webapp-improved.appspot.com/guide/routing.html#simple-routes
RedirectRoute: http://webapp-improved.appspot.com/api/webapp2_extras/routes.html#webapp2_extras.routes.RedirectRoute
"""
from webapp2_extras.routes import RedirectRoute
from bp_content.themes.default.handlers import handlers

secure_scheme = 'https'

# Here go your routes, you can overwrite boilerplate routes (bp_includes/routes)

_routes = [
	
	#THIS IS JUST AN EASY CALL FOR TEMPORARY HTML TO EASILY SEE EMAIL DESIGN.
    RedirectRoute('/emails/', handlers.EmailsRequestHandler, name='emails', strict_slash=True)
]

def get_routes():
    return _routes

def add_routes(app):
    if app.debug:
        secure_scheme = 'http'
    for r in _routes:
        app.router.add(r)
