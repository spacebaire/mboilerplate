# -*- coding: utf-8 -*-
from webapp2_extras.appengine.auth.models import User
from google.appengine.ext import ndb, blobstore

class Brand(ndb.Model):
    app_name = ndb.StringProperty(default = '')
    brand_layout = ndb.StringProperty(default = 'splash', choices = ['splash', 'video'])
    brand_video = ndb.StringProperty(default = '')
    brand_splash = ndb.StringProperty(default = '')
    brand_splash_light = ndb.StringProperty(default = '')
    brand_logo = ndb.StringProperty(default = '')
    brand_email_logo = ndb.StringProperty(default = '')
    brand_favicon = ndb.StringProperty(default = '')
    brand_color = ndb.StringProperty(default = '')
    brand_secondary_color = ndb.StringProperty(default = '')
    brand_tertiary_color = ndb.StringProperty(default = '')
    brand_about = ndb.StringProperty(default = '')

class Rewards(ndb.Model):
    amount = ndb.IntegerProperty()                                                                  #: number of points acquired 
    earned = ndb.BooleanProperty()                                                                  #: to identify if earned or spent
    category = ndb.StringProperty(choices = ['invite','donation','purchase','configuration'])       #: to identify main reason of rewards attribution
    content = ndb.StringProperty()                                                                  #: used to track referred emails
    timestamp = ndb.StringProperty()                                                                #: when was it assigned
    status = ndb.StringProperty(choices = ['invited','joined','completed','inelegible'])            #: current status of reward

class Notifications(ndb.Model):  
    sms = ndb.BooleanProperty()
    email = ndb.BooleanProperty()
    endpoint = ndb.BooleanProperty()
    twitter = ndb.StringProperty()

class Address(ndb.Model):
    address_from_coord = ndb.GeoPtProperty()                                                        #: lat/long address
    address_from = ndb.StringProperty()  
    
class Media(ndb.Model):
    blob_key = ndb.BlobKeyProperty()                                                                #: Refer to https://cloud.google.com/appengine/docs/python/blobstore/

class BlogPost(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)                                               #: Creation date.
    updated = ndb.DateTimeProperty(auto_now=True)                                                   #: Modification date.    
    blob_key = ndb.BlobKeyProperty()                                                                #: Refer to https://cloud.google.com/appengine/docs/python/blobstore/
    title = ndb.StringProperty(required = True)
    subtitle = ndb.StringProperty(indexed = False)
    author = ndb.StringProperty()
    brief = ndb.TextProperty(required = True, indexed = False)
    content = ndb.TextProperty(required = True, indexed = False)
    category = ndb.StringProperty(repeated = True)

    def get_id(self):
        return self._key.id()

class User(User):
    """
    Universal user model. Can be used with App Engine's default users API,
    own auth or third party authentication methods (OpenID, OAuth etc).
    """
    created = ndb.DateTimeProperty(auto_now_add=True)                                              #: Creation date.
    updated = ndb.DateTimeProperty(auto_now=True)                                                  #: Modification date.    
    last_login = ndb.StringProperty()                                                              #: Last user login.    
    username = ndb.StringProperty()                                                                #: User defined unique name, also used as key_name. >>Replaced as an email duplicate to avoid same emails several accounts
    name = ndb.StringProperty()                                                                    #: User Name    
    last_name = ndb.StringProperty()                                                               #: User Last Name    
    email = ndb.StringProperty()                                                                   #: User email
    phone = ndb.StringProperty()                                                                   #: User phone
    twitter_handle = ndb.StringProperty()                                                          #: User twitter handle for notification purposes
    address = ndb.StructuredProperty(Address)                                                      #: User georeference
    password = ndb.StringProperty()                                                                #: Hashed password. Only set for own authentication.    
    birth = ndb.DateProperty()                                                                     #: User birthday.
    gender = ndb.StringProperty(choices = ['male','female'])                                       #: User sex    
    activated = ndb.BooleanProperty(default=False)                                                 #: Account activation verifies email    
    link_referral = ndb.StringProperty()                                                           #: Once verified, this link is used for referral sign ups (uses bit.ly)    
    rewards = ndb.StructuredProperty(Rewards, repeated = True)                                     #: Rewards allocation property, includes referral email tracking.    
    amount = ndb.ComputedProperty(lambda self: self.get_rewards())                                 
    role = ndb.StringProperty(choices = ['NA','Member','Coord','Admin'], default = 'Admin')        #: Role in account
    get_role = ndb.ComputedProperty(lambda self: self.has_role())                                 
    level = ndb.IntegerProperty(choices = [0,1,2,3,4,5], default = 0)
    notifications = ndb.StructuredProperty(Notifications)                                          #: Setup of notifications
    picture = ndb.BlobProperty()                                                                   #: User profile picture as an element in datastore of type blob
    facebook_ID = ndb.StringProperty()                                                             #: User facebook ID for profile purposes
    google_ID = ndb.StringProperty()                                                               #: User google ID for profile purposes
    image_url = ndb.ComputedProperty(lambda self: self.get_image_url())                                 

    @classmethod
    def get_by_email(cls, email):
        return cls.query(cls.email == email).get()

    @classmethod
    def create_resend_token(cls, user_id):
        entity = cls.token_model.create(user_id, 'resend-activation-mail')
        return entity.token

    @classmethod
    def validate_resend_token(cls, user_id, token):
        return cls.validate_token(user_id, 'resend-activation-mail', token)

    @classmethod
    def delete_resend_token(cls, user_id, token):
        cls.token_model.get_key(user_id, 'resend-activation-mail', token).delete()

    def get_rewards(self):
        amount = 0
        for reward in self.rewards:
            amount += reward.amount

        return amount

    def get_image_url(self):
        if self.picture:
            return "/media/serve/profile/%s/" % self._key.id()
        elif self.facebook_ID is not None or self.google_ID is not None:
            if self.facebook_ID is not None:
                social = UserFB.query(UserFB.user_id == int(self._key.id())).get()
            elif self.google_ID is not None:
                social = UserGOOG.query(UserGOOG.user_id == int(self._key.id())).get()
            if social is not None:
                return social.picture if social.picture is not None else -1
        else:
            return -1

    def has_role(self):
        if self.role == 'Member':
            return "Operador"
        elif self.role == 'Coord':
            return "Coordinador"     
        elif self.role == 'Admin':
            return "Administrador"     
        else:
            return "NA"

class UserFB(ndb.Model):
    user_id = ndb.IntegerProperty(required = True)
    age_range = ndb.IntegerProperty()
    first_name = ndb.StringProperty()
    last_name = ndb.StringProperty()
    gender = ndb.StringProperty()
    picture = ndb.StringProperty()
    cover = ndb.StringProperty()

class UserGOOG(ndb.Model):
    user_id = ndb.IntegerProperty(required = True)
    first_name = ndb.StringProperty()
    last_name = ndb.StringProperty()
    gender = ndb.StringProperty()
    picture = ndb.StringProperty()
    cover = ndb.StringProperty()

class Content(ndb.Model):
    created = ndb.DateTimeProperty(auto_now_add=True)                                              #: Creation date.
    permission = ndb.IntegerProperty(required = True, default = 0)
    title = ndb.StringProperty(required = True)
    subtitle = ndb.StringProperty(required = True)
    description = ndb.StringProperty(required = True)
    kind = ndb.StringProperty(required = True, choices = ['video','audio','image','document','survey'])
    link = ndb.StringProperty(required = True)
    hidden = ndb.BooleanProperty(required = True, default = False)
    
    def get_id(self):
        return self._key.id()

class SpecialAccess(ndb.Model):
    email= ndb.StringProperty(required = True)
    name= ndb.StringProperty()
    role = ndb.StringProperty(required = True, choices = ['NA','Member', 'Coord', 'Admin'], default = 'Member')

    @classmethod
    def get_by_email(cls, email):
        """Returns an operator object based on an email.

        :param email:
            String representing the user email. Examples:

        :returns:
            A operator object.
        """
        return cls.query(cls.email == email).get()

    def get_id(self):
        return self._key.id()    

    def is_active(self):
        _user = User.get_by_email(self.email)
        if _user:
            return "*"
        else:
            return ""

    def has_role(self):
        if self.role == 'Member':
            return "Operador"
        elif self.role == 'Coord':
            return "Coordinador"     
        elif self.role == 'Admin':
            return "Administrador"     
        else:
            return "NA"

class LogVisit(ndb.Model):
    user = ndb.KeyProperty(kind=User)
    uastring = ndb.StringProperty()
    ip = ndb.StringProperty()
    timestamp = ndb.StringProperty()

    def get_user_count(self, user_id):
        logs = LogVisit.query(LogVisit.user == ndb.Key('User',user_id))
        return logs.count()

class OptionsSite(ndb.Model):
    name = ndb.KeyProperty
    value = ndb.StringProperty()
    @classmethod
    def get_option(cls,option_name):
        return cls.query(name=option_name)

class LogEmail(ndb.Model):
    sender = ndb.StringProperty(required=True)
    to = ndb.StringProperty(required=True)
    subject = ndb.StringProperty(required=True)
    body = ndb.TextProperty()
    when = ndb.DateTimeProperty()

    def get_id(self):
        return self._key.id()