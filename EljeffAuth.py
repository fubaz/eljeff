#Authorization Flow

#In this authorization flow, the peculiarity is that the credentials sent to the Authorization Server are assertions provided by an SP. So far, this library supports SAML2 and PAPI assertions.

#The steps taken in order to obtain the protected resource are:

#The user goes to a Client Application.
#In the Client App, the user authenticates in an external SP that generates a SAML or PAPI assertion.
#The Client App sends the assertion obtained to an Authorization Server. There, a token for a certain user, client, scope and lifetime is generated.
#The Authorization Server sends the generated token to the Client App.
#The Client App acts on behalf of the user and requests the resource to the Server. This token can be used more times until it expires.
#The Server returns the resource if the token sent is a valid token.


#from django import django.contrib.auth
#from django import django.contrib.auth.views
#from django import django.core.abort
from flask import Flask, abort, request
from uuid import uuid4
import requests
import requests.auth
import urllib

# ToDo: Signing of the clientID


CLIENT_ID = "eRES2NGOiTgniw" # Fill this in with your client ID
CLIENT_SECRET = None # This is mobile device usage, no client_secret for Reddit
#REDIRECT_URI = "127.0.0.1:65010/authorize_callback"
REDIRECT_URI = "https://powerful-eyrie-3894.herokuapp.com:65011/authorize_callback"
#REDIRECT_URI = "localhost:65011/reddit_callback"
STATE = None


#To identify type of client
def user_agent():
    #'''reddit API clients should each have their own, unique user-agent
    #    Ideally, with contact info included.
        
    #    e.g.,
    #    return "oauth2-sample-app by /u/%s" % your_reddit_username
        
    #    '''
    raise NotImplementedError()


def base_headers():
    return {"User-Agent": user_agent()}

app = Flask(__name__)
@app.route('/')

#This code is here for testing purposes.
def homepage():
    text = '<a href="%s">Authenticate with reddit</a>'
    return text % make_authorization_url()
    #return text % AuthenticateLikeBoss()

# This code is here for testing purposes
# Generate a random string for the state parameter
# Save it for use later to prevent xsrf attacks
def make_authorization_url():
    state = str(uuid4())
    save_created_state(state)
    url = getAuthorizationurls() + urllib.urlencode(getAuthinputs())
    return url


# Case new user: Let's create links to identity providers
def AuthenticateLikeBoss():
    if (getAuthorizationurls() == null):
        #state = None
        save_created_state(state)
        print "Error: authorization URL or application parameters are missing"
        return "Error: authorization URL or application parameters are missing"
    # Add here authorization flow to enable user linking new authorization and identity provider
    else:
        # For now, to help testing this looks like this
        return text % getAuthorizationurls() + urllib.urlencode(getAuthinputs())

# Let's form array full of parameters needed to insert in the authentication URL
def getAuthinputs():
    # 3 different clients can be defined, authentication inputs depend on client type
    #if (base_headers() == "mobile"):
    #   CLIENT_SECRET = None
   # Configuration database call to get service specific authentication URL parameters
   #Auch, there are no authorizations that would give the additional info needed
   # Take the one that offers additional info needed by the application, e.g. email address
    state = str(uuid4())
    params = {"client_id": CLIENT_ID, "response_type": "code","state": state,"redirect_uri": REDIRECT_URI,"duration": "temporary","scope": "identity"}
    return params

def getAuthorizationurls():
    #For testing purposes:
    URL = "https://ssl.reddit.com/api/v1/authorize?" #This is service specific authorization URL to initialize authorization of application level calls
    authurl = URL
    # Configuration database call to get service specific authentication URLs
    #authurl = {URL,apiVersion,provider}
    return authurl

# We may want to store valid states in a database (or memcache or something).
def save_created_state(state):
    pass

# Trust: Check validity of session
def is_valid_state(state):
    return True

@app.route('/authorize_callback')
def authorize_callback():
    #def reddit_callback():
    error = request.args.get('error', '')
    if error:
        return "Error: " + error
    state = request.args.get('state', '')
    if not is_valid_state(state):
        # Uh-oh, this request wasn't started by us!
        # Trust: Revoke authorization
        abort(403)
    code = request.args.get('code')
    access_token = get_token(code)
    return "Your username is: %s" % get_username(access_token)

# Get aceess token and store the access token in the database or memcache or something
def get_token(code):
    client_auth = requests.auth.HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
    post_data = {"grant_type": "authorization_code",
        "code": code,
            "redirect_uri": REDIRECT_URI}
    headers = base_headers()
    response = requests.post("https://ssl.reddit.com/api/v1/access_token",
                             auth=client_auth,
                             headers=headers,
                             data=post_data)
    token_json = response.json()
    return token_json["access_token"]


# Trust: Get access token:

def get_username(access_token):
    headers = base_headers()
    headers.update({"Authorization": "bearer " + access_token})
    response = requests.get("https://oauth.reddit.com/api/v1/me", headers=headers)
    me_json = response.json()
    return me_json['name']


if __name__ == '__main__':
    app.run(debug=True, port=65011)


# Trust: Update authorization from identity provider
# This is done outside of the login process

#def checkAuthorizationValidity:
#
#    if (getAuthorizationurls() == null or getAuthinputs() == null):
#        state = None
#        save_created_state(state)
#        return "Error: authorization URL or application parameters are missing"
#    else:
        
        #State has to be set here.Call_back is only initiated if application to application state is ok
#        state = str(uuid4())
#        save_created_state(state)
#
#       return text % getAuthorizationurls() + urllib.urlencode(getAuthinputs())

# Trust: Check validity of session from token, impement Invalid Token Error

# Trust: Revoke authorization from identity provider

# Trust: Revoke token


















