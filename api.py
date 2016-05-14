from google.appengine.datastore.datastore_query import Cursor
from collections import OrderedDict, Counter
from bp_includes import models
from datetime import datetime, date, time, timedelta
import logging
#endpoints related libraries
import endpoints
from google.appengine.ext import ndb
from protorpc import messages
from protorpc import message_types
from protorpc import remote


# TODO: Replace the following lines with client IDs obtained from the APIs
# Console or Cloud Console.
# WEB_CLIENT_ID = 'replace this with your web client application ID'
# ANDROID_CLIENT_ID = 'replace this with your Android client ID'
# IOS_CLIENT_ID = 'replace this with your iOS client ID'
# ANDROID_AUDIENCE = WEB_CLIENT_ID

# Endpoints API is accessible at: <app_id>.appspot.com/_ah/api/explorer


package = 'Hello'


class Greeting(messages.Message):
    """Greeting that stores a message."""
    message = messages.StringField(1)


class GreetingCollection(messages.Message):
    """Collection of Greetings."""
    items = messages.MessageField(Greeting, 1, repeated=True)


STORED_GREETINGS = GreetingCollection(items=[
    Greeting(message='hello world!'),
    Greeting(message='goodbye world!'),
])


mb_api = endpoints.api(name='mbapi', version='v1')

@mb_api.api_class(resource_name='helloworld')
class HelloWorldApi(remote.Service):
    """Helloworld API v1."""

    MULTIPLY_METHOD_RESOURCE = endpoints.ResourceContainer(
            Greeting,
            times=messages.IntegerField(2, variant=messages.Variant.INT32,
                                        required=True))

    @endpoints.method(MULTIPLY_METHOD_RESOURCE, Greeting,
                      path='hellogreeting/{times}', http_method='POST',
                      name='greetings.multiply')
    def greetings_multiply(self, request):
        return Greeting(message=request.message * request.times)

    @endpoints.method(message_types.VoidMessage, GreetingCollection,
                      path='hellogreeting', http_method='GET',
                      name='greetings.listGreeting')
    def greetings_list(self, unused_request):
        return STORED_GREETINGS

    ID_RESOURCE = endpoints.ResourceContainer(
            message_types.VoidMessage,
            id=messages.IntegerField(1, variant=messages.Variant.INT32))

    @endpoints.method(ID_RESOURCE, Greeting,
                      path='hellogreeting/{id}', http_method='GET',
                      name='greetings.getGreeting')
    def greeting_get(self, request):
        try:
            return STORED_GREETINGS.items[request.id]
        except (IndexError, TypeError):
            raise endpoints.NotFoundException('Greeting %s not found.' %
                                              (request.id,))




class Users(messages.Message):
    """Users that stores a message."""
    identifier = messages.StringField(1)
    created_at = messages.StringField(2)
    last_login = messages.StringField(3)
    


class UsersCollection(messages.Message):
    """Collection of Users."""
    total_rows = messages.IntegerField(1)
    items = messages.MessageField(Users, 2, repeated=True)


def getUsers():
  users = models.User.query()
  users = users.order(models.User.created)
  users_array = []
  for user in users:
    _identifier = str(user.key.id())
    _created_at = str(user.created)
    _last_login= str(user.last_login)

    users_array.append(Users(identifier=_identifier, created_at=_created_at, last_login=_last_login))
  return UsersCollection(total_rows = len(users_array), items=users_array)

@mb_api.api_class(resource_name='main')
class MainApi(remote.Service):
    """Main API v1."""

    @endpoints.method(message_types.VoidMessage, UsersCollection,
                      path='users', http_method='GET',
                      name='users.list')
    def users_list(self, unused_request):
        return getUsers()


   


APPLICATION = endpoints.api_server([mb_api])