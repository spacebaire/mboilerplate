# -*- coding: utf-8 -*-
import webapp2, json
from google.appengine.datastore.datastore_query import Cursor
from google.appengine.ext import ndb, blobstore
from google.appengine.ext.webapp import blobstore_handlers
from collections import OrderedDict, Counter
from wtforms import fields  
from bp_includes import forms, models, handlers
from bp_includes.lib.basehandler import BaseHandler
from datetime import datetime, date, time, timedelta
import logging


class AdminBlogHandler(BaseHandler):
    def get(self):
        params = {}
        posts = models.BlogPost.query()
        params['total'] = posts.count()
        params['posts'] = []
        for post in posts:
            params['posts'].append((post.key.id(), post.updated, post.title, post.subtitle, post.blob_key, post.author, post.brief, post.category))

        return self.render_template('admin_blog.html', **params)

class AdminBlogEditHandler(BaseHandler, blobstore_handlers.BlobstoreUploadHandler):
    def get(self, post_id):
        params = {}
        params['blob_key'] = ''
        params['title'] = ''
        params['subtitle'] = ''
        params['author'] = ''
        params['brief'] = ''
        params['content'] = ''
        params['category'] = ''
        params['post_id'] = post_id if len(post_id) > 0 else 1
        if post_id != 1:
            blog = models.BlogPost.get_by_id(long(post_id))
            if blog is not None:
                params['blob_key'] = blog.blob_key
                params['title'] = blog.title
                params['subtitle'] = blog.subtitle
                params['author'] = blog.author
                params['brief'] = blog.brief
                params['content'] = blog.content
                params['category'] = blog.category
        params['upload_url'] = blobstore.create_upload_url('/admin/blog/upload/%s/' % post_id)        
        return self.render_template('admin_blog_edit.html', **params)

class AdminBlogUploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    def post(self, post_id):
        try:
            upload = self.get_uploads()[0]
            logging.info("New blog post because id: %s" % post_id)
            if post_id == '1':
                logging.info("New blog post")
                logging.info("Uploaded blob")
                new_blog = models.BlogPost()
                new_blog.blob_key = upload.key()                                              
                new_blog.title = self.request.get('title')
                new_blog.subtitle = self.request.get('subtitle')
                new_blog.author = self.request.get('author')
                new_blog.brief = self.request.get('brief')
                new_blog.content = self.request.get('content')
                new_blog.category = self.request.get('category').split(',')
                logging.info("Values ready to put")
                new_blog.put()
            else:
                blog = models.BlogPost.get_by_id(long(post_id))
                if blog is not None:
                    if upload is not None:
                        blog.blob_key = upload.key()                                               
                        blog.title = self.request.get('title')
                        blog.subtitle = self.request.get('subtitle')
                        blog.author = self.request.get('author')
                        blog.brief = self.request.get('brief')
                        blog.content = self.request.get('content')
                        blog.category = self.request.get('category').split(',')
                        blog.put()

            self.redirect_to('admin-blog')
        except Exception as e:
            logging.error('something went wrong: %s' % e)
            self.error(404)
