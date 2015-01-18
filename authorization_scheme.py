# -*- coding: utf-8 -*-
# Clean this list
from sqlite3 import dbapi2 as sqlite3
from flask import Flask, abort, request, session, g, redirect, url_for, abort, \
    render_template, flash
from uuid import uuid4
import urlparse
import requests
import urllib
import oauth2 as oauth

consumer_key = None
consumer_secret = None
providerName = None
REDIRECT_URI = None

app = Flask(__name__)
@app.route('/')
#This code is here for testing purposes.
#ToDo: User interface
#ToDo: Database implementation
def homepage():
    return str(consumeIdentityProvider("Username","TargetService_X"))


#Let's create association between user and identity and consume one identity provider
#ToDo: We need to pick the one with suitable set of data attched to to the user
def consumeIdentityProvider(loginName,targetServiceName):
    userEntity = whoAmI(loginName)
    if userEntity['user'] is loginName:
        if checkIdentityProvider(userEntity['serviceProvider']):
            consumer = oauth.Consumer(getProviderSecrets(providerName)[0], getProviderSecrets(providerName)[1])
            client = oauth.Client(consumer)
        if userEntity['validity'] == 'valid':
            return  "We have a valid identity! " + str(userEntity['user'])
        else:
            renewAuth(consumer,loginName)
            return "We have a new or re-authenticated user!"
    else:
        return  "No user, thou shall not pass."
        

#Step 1: Let's deal with the user
#ToDo: get data from database
#ToDo: decrypt data on retirieval from database
#ToDo: Let's add public key as user identifier. If new user, let's generate the key pair
def whoAmI(user):
    user = user
    userID = "client01"
    access_token = 'user_access_token'
    access_token_secret = 'user_access_secret'
    serviceProvider = "app_name_in_identity_provider" #E.g. Twitter app
    validity = 'valid'
    identity =  {'user':user, 'userID':userID, 'access_token':access_token, 'access_token_secret':access_token_secret, 'serviceProvider':serviceProvider, 'validity':validity}
    return identity

#Let's renew authorization and refresh identity
def renewAuth(consumer, user):
    setMyAuthorizationToClient(getAuthInputs(consumer.key))
    identity = whoAmI(user)
    return identity

#Let's join user and authorization
#ToDo:signing, fixing the parameters etc.
def setMyAuthorizationToClient(key):
    url = requests.get(createAuthorizeUrl(createAuthorizeUrl(params['client_id'])) + urllib.urlencode(getAuthInputs(key)))
    return url

# Let's form dictionary of parameters needed to insert in the authentication URL of a identity provider
# ToDo: a lot to test with
def getAuthInputs(key):
    redirectstate = str(uuid4())
    params = {"client_id": key, "response_type": "code","state": redirectstate,"redirect_uri": createRedirect_uri(key),"duration": "temporary","scope": "identity"} #change duration to permanent?
    return params

#Step 2: Let's find if we have the service user is aiming to access
#ToDo: Let's find what information targetService needs about the user and if any of the identities can be used
def whereAmIGoingTo(targetServiceName):
    targetService = ['Twitter']
    if targetService[0] is targetServiceName:
        target = targetService[0]
    return target

# Step3: Let's check that the identity provider things are ok at our base
def checkIdentityProvider(providerName):
    urlsAndSecrets = [createRequestTokenUrl(getProviderSecrets(providerName)[0]),createAccessTokenUrl(getProviderSecrets(providerName)[0]),createAuthorizeUrl(getProviderSecrets(providerName)[0]),createRedirect_uri(getProviderSecrets(providerName)[0]), getProviderSecrets(providerName)]
    if urlsAndSecrets[3] and urlsAndSecrets[4][0] and urlsAndSecrets[4][1]:
        return urlsAndSecrets
    else:
        return "CheckIdentityProvider: Unknown identity provider: rebuild or remove association to this provider from the provider service"
        pass #This point requires moving user to UI that enables user to tell admin to do something about this.

#Step 3: Check if we know this identity provider, do not fall back to previous versions of APIs
#ToDo: put the URLs in database
def createRequestTokenUrl(key):
    if key is not None:
        request_token_url = 'http://twitter.com/oauth/request_token'
    else:
        print "Unknown identity provider: Request token URL is missing, reauthenticate or remove association to this provider"
        request_token_url = None
    return request_token_url

def createAccessTokenUrl(key):
    if key is not None:
        access_token_url = 'http://twitter.com/oauth/access_token'
    else:
        print "Unknown identity provider: Access token URL is missing, reauthenticate or remove association to this provider"
        access_token_url = None
    return access_token_url

def createAuthorizeUrl(key):
    if key is not None:
        authorize_url = 'https://twitter.com/oauth/authorize'
    else:
        print "Unknown identity provider: Authorization token URL is missing, reauthenticate or remove association to this provider"
        authorize_url = None
    return authorize_url

def createRedirect_uri(key):
    if key is not None:
        redirect_uri = 'http://127.0.0.1:65010/authorize_callback'
    else:
        print "Unknown identity provider: Authorization token URL is missing, reauthenticate or remove association to this provider"
        redirect_uri = None
    return redirect_uri

# Step3: Let's find the provider identity details
#ToDo: Put these in database
def getProviderSecrets(providerName):
    providerSecrets = [consumer_key,consumer_secret]
    providerSecrets[0] = 'API key'
    providerSecrets[1] = 'API secret'
    return providerSecrets

#The callback function
#ToDo: To be implemented

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=65010)
