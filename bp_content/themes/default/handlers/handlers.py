# -*- coding: utf-8 -*-
from bp_includes.lib.basehandler import BaseHandler

# Put here your handlers to extend the ones from bp_includes/handlers.py

class EmailsRequestHandler(BaseHandler):

    def get(self):
        params = {}
        return self.render_template('emails/emails.html', **params)
