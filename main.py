# Author: Steven Bertolucci
# Course: CS493 - Cloud Application Development
# Project: Assignment 6 - Tarpaulin Course Management Tool
# Due Date: December 6, 2024

from flask import Flask, render_template, request, jsonify
from google.cloud import datastore

import requests
import json

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS_LOGIN = "users/login"

# Update the values of the following 3 variables
CLIENT_ID = '3sZ0EYeu3CIq98xgY8WbetVlnUL4iAfk'
CLIENT_SECRET = 'cq3KOI7tYkm25C3s6p3gLfobv6syXYoQqU7ZaeNLVETwjBjpO9HruLOrEDm02lCh'
DOMAIN = 'dev-x1ennj17g3yv8mg0.us.auth0.com'

ALGORITHMS = ["RS256"]

# Error Codes
ERROR_INVALID_REQUEST_BODY = {"Error" : "The request body is invalid"}
ERROR_UNAUTHORIZED = {"Error" : "Unauthorized"}
ERROR_PERMISSION = {"Error": "You don't have permission on this resource"}
ERROR_NOT_FOUND = {"Error" : "Not found"}

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
        print("Token from verify_jwt: ", token)
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return render_template('index.html')

# Create a lodging if the Authorization header contains a valid JWT
@app.route('/lodgings', methods=['POST'])
def lodgings_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        content = request.get_json()
        new_lodging = datastore.entity.Entity(key=client.key(LODGINGS))
        new_lodging.update({"name": content["name"], "description": content["description"],
          "price": content["price"]})
        client.put(new_lodging)
        return jsonify(id=new_lodging.key.id)
    else:
        return jsonify(error='Method not recogonized')

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload          
        

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/' + USERS_LOGIN, methods=['POST'])
def login_user():
    content = request.get_json()

    for i in ['username', 'password']:
        if i not in content:
            return ERROR_INVALID_REQUEST_BODY, 400

    username = content["username"]
    for i in ['admin1@osu.com', 'instructor1@osu.com', 'instructor2@osu.com', 'student1@osu.com', 
              'student2@osu.com', 'student3@osu.com', 'student4@osu.com', 'student5@osu.com', 
              'student6@osu.com' ]:
        if i not in username:
            return ERROR_UNAUTHORIZED, 401
        
    password = content["password"]
    if password != 'Cheese1234!':
        return ERROR_UNAUTHORIZED, 401
    
    body = {'grant_type':'password','username':username,
            'password':password,
            'client_id':CLIENT_ID,
            'client_secret':CLIENT_SECRET
           }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    # print("Response: ", r.text)

    response = r.json()

    token = response['id_token']

    return jsonify({"token": token})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

