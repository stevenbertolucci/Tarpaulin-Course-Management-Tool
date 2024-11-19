# Author: Steven Bertolucci
# Course: CS493 - Cloud Application Development
# Project: Assignment 6 - Tarpaulin Course Management Tool
# Due Date: December 6, 2024

from flask import Flask, render_template, request, jsonify, send_file
from google.cloud import datastore, storage
from google.cloud.datastore.query import PropertyFilter

import requests
import json
import io

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

AVATAR_BUCKET='project6-tarpaulin-avatars'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

USERS_LOGIN = "users/login"
USERS = "users"
AVATAR = "avatar"

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
        # print("Token from verify_jwt: ", token)
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

# Get all users if the Authorization header contains a valid JWT
@app.route('/' + USERS, methods=['GET'])
def get_users():
    if request.method == 'GET':
        try:
            payload = verify_jwt(request)

            user_id = payload.get('sub')

            query = client.query(kind=USERS)
            query.order = ['role']
            results = list(query.fetch())

            # Verify that the admin only gets to view the users
            if results[0]['sub'] != user_id:
                return ERROR_PERMISSION, 403

            users = []

            for content in results:
                user = {
                    'id': content.key.id,
                    'role': content['role'],
                    'sub': content['sub']
                } 

                users.append(user)

            return jsonify(users)
        
        except:
            return ERROR_UNAUTHORIZED, 401

# Get a user
@app.route('/' + USERS + '/<int:id>', methods=['GET'])
def get_a_user(id):
    if request.method == 'GET':
        try:
            payload = verify_jwt(request)
            # print("PAYLOAD: ", payload)
            user_id = payload.get('sub')

            # print("USER_ID: ", user_id)
            # print("\n\n")

            query = client.query(kind=USERS)
            query.order = ['role']
            results = list(query.fetch())
            
            # print("RESULTS: ", results)
            # print("\n\n")

            if results.get('avatar'):
                avatar_url = f"{request.host_url}{USERS}/{id}/{AVATAR}"
            else:
                avatar_url = None

            ########################################
            #                                      #
            #          DISPLAYING AN ADMIN         #
            #                                      #
            ########################################
            if results[0]['sub'] == user_id:

                # print("ID: ", id)

                query = client.query(kind=USERS)
                query = query.add_filter(filter=PropertyFilter('sub', '=', user_id))
                results = list(query.fetch())

                if avatar_url:
                    for content in results:
                        user = {
                            'id': content.key.id,
                            'role': content['role'],
                            'sub': content['sub'],
                            'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"
                        } 

                    return jsonify(user)
                else:
                    for content in results:
                        user = {
                            'id': content.key.id,
                            'role': content['role'],
                            'sub': content['sub']
                        } 

                    return jsonify(user)

            ########################################
            #                                      #
            #       DISPLAYING AN INSTRUCTOR       #
            #                                      #
            ########################################
            elif results[1]['sub'] == user_id or results[2]['sub'] == user_id:

                #print("ID: ", id)

                #print("I'm searching for instructor.")
                
                # Checking for valid JWTs
                key = client.key(USERS, id)
                instructor = client.get(key)

                # If not valid, return 403
                if instructor['sub'] != user_id:
                    return ERROR_PERMISSION, 403

                query = client.query(kind=USERS)
                query = query.add_filter(filter=PropertyFilter('sub', '=', user_id))
                results = list(query.fetch())

                if avatar_url:
                    for content in results:
                        user = {
                            'id': content.key.id,
                            'role': content['role'],
                            'sub': content['sub'],
                            'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}",
                            'courses': []
                        }

                    return jsonify(user)
                else:
                    for content in results:
                        user = {
                            'id': content.key.id,
                            'role': content['role'],
                            'sub': content['sub'],
                            'courses': []
                        } 

                    return jsonify(user)

            ########################################
            #                                      #
            #         DISPLAYING A STUDENT         #
            #                                      #
            ########################################
            elif results[3]['sub'] == user_id or results[4]['sub'] == user_id or results[5]['sub'] == user_id \
                or results[6]['sub'] == user_id or results[7]['sub'] == user_id or results[8]['sub'] == user_id:

                #print("ID: ", id)

                #print("Searching for student.")

                # Checking for valid JWTs
                key = client.key(USERS, id)
                student = client.get(key)

                # If not valid, return 403
                if student['sub'] != user_id:
                    return ERROR_PERMISSION, 403

                query = client.query(kind=USERS)
                query = query.add_filter(filter=PropertyFilter('sub', '=', user_id))
                results = list(query.fetch())

                #print("RESULTS: ", results)

                if avatar_url:
                    for content in results:
                        user = {
                            'courses': [],
                            'id': content.key.id,
                            'role': content['role'],
                            'sub': content['sub'],
                            'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"
                        } 

                    return jsonify(user)
                else:
                    for content in results:
                        user = {
                            'courses': [],
                            'id': content.key.id,
                            'role': content['role'],
                            'sub': content['sub'],
                        } 

                    return jsonify(user)

            else:
                return ERROR_PERMISSION, 403

        except:
            #print("Uh-oh")
            return ERROR_UNAUTHORIZED, 401
        
# Create/update a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/' + AVATAR, methods=['POST'])
def post_avatar(id):

    # Check if there is an entry in request.files with the key 'file'
    if 'file' not in request.files:
        return ERROR_INVALID_REQUEST_BODY, 400

    try:
         # Verify JWT
        payload = verify_jwt(request)
        user_id = payload.get('sub')

        # Checking for valid JWTs
        key = client.key(USERS, id)
        user = client.get(key)

        # If not valid, return 403
        if user['sub'] != user_id:
            return ERROR_PERMISSION, 403
        
        # Set file_obj to the file sent in the request
        file_obj = request.files['file']
        
        if 'tag' in request.form:
            tag = request.form['tag']

        # Create a storage client
        storage_client = storage.Client()

        # Get a handle on the bucket
        bucket = storage_client.get_bucket(AVATAR_BUCKET)

        # Create a blob object for the bucket with the name of the file
        blob = bucket.blob(file_obj.filename)

        # Position the file_obj to its beginning
        file_obj.seek(0)

        # Upload the file into Cloud Storage
        blob.upload_from_file(file_obj)

        # Update 'avatar_url' entity for the user
        user['avatar_url'] = f"{request.host_url}{USERS}/{id}/{AVATAR}"
        client.put(user) 

        return jsonify({'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"}), 200
    
    # Invalid JWT or missing JWT
    except:
        return ERROR_UNAUTHORIZED, 401
    
# Get a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/' + AVATAR, methods=['GET'])
def get_avatar(id):

    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_id = payload.get('sub')

        # Checking for valid JWTs
        key = client.key(USERS, id)
        user = client.get(key)

        # If not valid, return 403
        if user['sub'] != user_id:
            return ERROR_PERMISSION, 403
        
        # If user has no avatar, return 404
        if user['avatar_url'] is None:
            return ERROR_NOT_FOUND, 404
        
        # Set file_obj to the file sent in the request
        file_obj = request.files['file']
        
        storage_client = storage.Client()
        bucket = storage_client.get_bucket(AVATAR_BUCKET)

        # Create a blob with the given file name
        blob = bucket.blob(file_obj.filename)

        # Create a file object in memory using Python io package
        file_obj = io.BytesIO()

        # Download the file from Cloud Storage to the file_obj variable
        blob.download_to_file(file_obj)

        # Position the file_obj to its beginning
        file_obj.seek(0)

        return send_file(file_obj, mimetype='image/x-png', download_name=file_obj.filename)
    except:
        return ERROR_UNAUTHORIZED, 401
    
# Delete a user's avatar
@app.route('/' + {USERS} + '/<int:id>' + '/' + {AVATAR}, methods=['DELETE'])
def delete_avatar(id):
    
    try:
        # Verify JWT
        payload = verify_jwt(request)
        user_id = payload.get('sub')

        # Checking for valid JWTs
        key = client.key(USERS, id)
        user = client.get(key)

        # If not valid, return 403
        if user['sub'] != user_id:
            return ERROR_PERMISSION, 403
        
        # If user has no avatar, return 404
        if user['avatar_url'] is None:
            return ERROR_NOT_FOUND, 404
        
        # Set file_obj to the file sent in the request
        file_obj = request.files['file']
        
        storage_client = storage.Client()

        bucket = storage_client.get_bucket(AVATAR_BUCKET)

        blob = bucket.blob(file_obj.filename)

        # Delete the file from Cloud Storage
        blob.delete()

        return '', 204
        
    except:
        return ERROR_UNAUTHORIZED, 401

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

