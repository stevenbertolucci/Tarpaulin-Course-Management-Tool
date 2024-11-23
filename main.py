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

# Endpoints/kinds
USERS_LOGIN = "users/login"
USERS = "users"
AVATAR = "avatar"
COURSES = "courses"

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

# Constants
username_list = [
    'admin1@osu.com', 'instructor1@osu.com', 'instructor2@osu.com',
    'student1@osu.com', 'student2@osu.com', 'student3@osu.com',
    'student4@osu.com', 'student5@osu.com', 'student6@osu.com'
]

course_properties = ["instructor_id", "number", "subject", "term", "title"]

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

# Home page (aka Index)
@app.route('/')
def index():
    return render_template('index.html')

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

    username = content['username']

    if username not in username_list:
        return ERROR_UNAUTHORIZED, 401
        
    password = content['password']
    
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

# Get all users if the Authorization header contains a valid JWT
@app.route('/' + USERS, methods=['GET'])
def get_users():
    try:
        payload = verify_jwt(request)
        user_role = payload.get('role')

        # Verify that the admin only gets to view the users
        if user_role != 'admin':
            return ERROR_PERMISSION, 403

        query = client.query(kind=USERS)
        results = list(query.fetch())

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
    try:
        payload = verify_jwt(request)
        # print("PAYLOAD: ", payload)
        user_id = payload.get('sub')

        # print("USER_ID: ", user_id)
        # print("\n\n")

        key = client.key(USERS, id)
        user = client.get(key)

        if 'avatar_url' in user and user['avatar_url'] is not None:
            avatar_url = f"{request.host_url}{USERS}/{id}/{AVATAR}"
        else:
            avatar_url = None

        ########################################
        #                                      #
        #          DISPLAYING AN ADMIN         #
        #                                      #
        ########################################
        if user['role'] == 'admin':

            if avatar_url:
                user = {
                        'id': id,
                        'role': user['role'],
                        'sub': user['sub'],
                        'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"
                    } 

                return jsonify(user)
            else:
                
                user = {
                        'id': id,
                        'role': user['role'],
                        'sub': user['sub']
                    } 

                return jsonify(user)

        ########################################
        #                                      #
        #       DISPLAYING AN INSTRUCTOR       #
        #                                      #
        ########################################
        elif user['role'] == 'instructor':

            #print("ID: ", id)

            #print("I'm searching for instructor.")
            
            # Checking for valid JWTs
            # If not valid, return 403
            if user['sub'] != user_id:
                return ERROR_PERMISSION, 403

            # Get all courses that the instructor teaches
            query = client.query(kind=COURSES)
            query.add_filter(filter=PropertyFilter('instructor_id', '=', user_id))
            courses = list(query.fetch())

            # If instructor is teaching a course
            if courses is not None:
                list_of_courses = []
                for course in courses:
                    list_of_courses.append({
                        'courses': f"{request.host_url}{COURSES}/{course.key.id}"
                    })

                # If instructor has an avatar
                if avatar_url:
                    user = {
                            'id': id,
                            'role': user['role'],
                            'sub': user['sub'],
                            'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}",
                            'courses': list_of_courses
                        }

                    return jsonify(user)

                else:
                    
                    user = {
                            'id': id,
                            'role': user['role'],
                            'sub': user['sub'],
                            'courses': []
                        } 

                    return jsonify(user)
            else:
                # If instructor has an avatar
                if avatar_url:
                    user = {
                            'id': id,
                            'role': user['role'],
                            'sub': user['sub'],
                            'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}",
                            'courses': []
                        }

                    return jsonify(user)

                else:
                    
                    user = {
                            'id': id,
                            'role': user['role'],
                            'sub': user['sub'],
                            'courses': []
                        } 

                    return jsonify(user)

        ########################################
        #                                      #
        #         DISPLAYING A STUDENT         #
        #                                      #
        ########################################
        elif user['role'] == 'student':

            #print("ID: ", id)

            #print("Searching for student.")

            # Checking for valid JWTs
            # If not valid, return 403
            if user['sub'] != user_id:
                return ERROR_PERMISSION, 403

            if avatar_url:
                user = {
                        'courses': [],
                        'id': id,
                        'role': user['role'],
                        'sub': user['sub'],
                        'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"
                    } 

                return jsonify(user)
            else:
                
                user = {
                        'courses': [],
                        'id': id,
                        'role': user['role'],
                        'sub': user['sub'],
                    } 

                return jsonify(user)

        else:
            return ERROR_PERMISSION, 403

    except:
        #print("Uh-oh")
        return ERROR_UNAUTHORIZED, 401
        
# Create/update a user's avatar OR
# GET a user's avatar OR
# DELETE a user's avatar
@app.route('/' + USERS + '/<int:id>' + '/' + AVATAR, methods=['POST', 'GET', 'DELETE'])
def post_avatar(id):
    if request.method == 'POST':
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

            # Check if there is an entry in request.files with the key 'file'
            if 'file' not in request.files:
                print('Uh-oh')
                return ERROR_INVALID_REQUEST_BODY, 400
            
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
            # Save the avatar_url in datastore
            client.put(user) 

            return jsonify({'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"}), 200
        
        # Invalid JWT or missing JWT
        except:
            return ERROR_UNAUTHORIZED, 401

    if request.method == 'GET':
        try:
            # Verify JWT
            payload = verify_jwt(request)
            user_id = payload.get('sub')
            # print("Request: ", request)
            # print("Payload: ", payload)

            # Checking for valid JWTs
            key = client.key(USERS, id)
            user = client.get(key)

            # If not valid, return 403
            if user['sub'] != user_id:
                return ERROR_PERMISSION, 403
            
            # If user has no avatar, return 404
            # Not all users have avatar_url in their property
            # Hence the user.get() call
            if user.get('avatar_url') is None:
                return ERROR_NOT_FOUND, 404
            
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(AVATAR_BUCKET)

            # Create a blob with the given file name
            blob = bucket.blob('student1.jpg')

            # Create a file object in memory using Python io package
            file_obj = io.BytesIO()

            # Download the file from Cloud Storage to the file_obj variable
            blob.download_to_file(file_obj)

            # Position the file_obj to its beginning
            file_obj.seek(0)

            return send_file(file_obj, mimetype='image/x-png', download_name='student1.jpg')
        except:
            return ERROR_UNAUTHORIZED, 401

    if request.method == 'DELETE':
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
            if user.get('avatar_url') is None:
                return ERROR_NOT_FOUND, 404
            
            storage_client = storage.Client()

            bucket = storage_client.get_bucket(AVATAR_BUCKET)

            blob = bucket.blob('student1.jpg')

            # Delete the file from Cloud Storage
            blob.delete()

            # Update the avatar_url for user
            user['avatar_url'] = None
            client.put(user)

            return '', 204
            
        except:
            return ERROR_UNAUTHORIZED, 401    

# Create courses OR
# Get all courses
@app.route('/' + COURSES, methods=['POST', 'GET'])
def post_courses():
    content = request.get_json()
    print("Content: ", content)

    if request.method == "POST":

        try:
            payload = verify_jwt(request)
            print("Payload: ", payload)
            user_id = payload.get('sub')

            # If the request body do not contain any one of the required field, return 400
            for i in ['subject', 'number', 'title', 'term', 'instructor_id']:
                if i not in content:
                    return ERROR_INVALID_REQUEST_BODY, 400

            # Check if it is admin adding the course
            query = client.query(kind=USERS)
            query.add_filter(filter=PropertyFilter('sub', '=', user_id))
            results = list(query.fetch())
            #print("RESULTS: ", results)

            # Check if role is admin because only admin can create courses
            if not results or results[0]['role'] != 'admin':
                return ERROR_PERMISSION, 403
            
            # print("uh-oh")

            # Check to see if the content of the request contains a valid instructor_id and that id matches the instructor
            user = client.key(USERS, content['instructor_id'])
            instructor = client.get(user)

            # If no instructor is found, return 400
            if instructor is not None and instructor['role'] != 'instructor':
                return ERROR_INVALID_REQUEST_BODY, 400
            
            # print('Uh-oh')

            # Create courses entity in datastore
            new_course = datastore.Entity(key=client.key(COURSES))

            new_course.update({
                'subject': content['subject'],
                'number': content['number'],
                'title': content['title'],
                'term': content['term'],
                'instructor_id': content['instructor_id']
            })

            client.put(new_course)
            id = new_course.key.id

            self_link = f"{request.host_url}{COURSES}/{id}"

            response = {
                'id': id,
                'subject': new_course['subject'],
                'number': new_course['number'],
                'title': new_course['title'],
                'term': new_course['term'],
                'instructor_id': new_course['instructor_id'],
                'self': self_link,
            }
            return (response, 201)
        except:
            return ERROR_UNAUTHORIZED, 401

    if request.method == 'GET':
        # Set offset and limit parameters for first page
        offset = int(request.args.get('offset', 0))
        limit = 3

        query = client.query(kind=COURSES)
        query.order = ['subject']
        results = list(query.fetch(offset=offset, limit=limit))

        courses = []

        for course in results:
            courses.append({
                "id": course.key.id,
                'instructor_id': course['instructor_id'],
                'number': course['number'],
                'self': f"{request.host_url}{COURSES}/{course.key.id}",
                'subject': course['subject'],
                'term': course['term'],
                'title': course['title']
            })

        next_offset = offset + limit
        next_url = f"{request.host_url}{COURSES}?offset={next_offset}&limit={limit}" if courses else None

        return {
            "courses": courses,
            "next": next_url
        }

# Get a course
@app.route('/' + COURSES + '/<int:id>', methods=['GET', 'PATCH', 'DELETE'])
def get_a_course(id):
    content = request.get_json()

    if request.method == 'GET':
        course_key = client.key(COURSES, id)
        course = client.get(key=course_key)

        if course is None:
            return ERROR_NOT_FOUND, 404
        else:
            course['id'] = course.key.id
            course['self'] = f"{request.host_url}{COURSES}/{id}"

        return course

    if request.method == 'PATCH':
        try:
            # Verify JWT
            payload = verify_jwt(request)
            user_id = payload.get('sub')

            print("PAYLOAD", payload)

            print("USER ID: ", user_id)

            # Get course
            course_key = client.key(COURSES, id)
            course = client.get(key=course_key)

            # If course doesn't exist, return 403 error code
            if course is None:
                return ERROR_PERMISSION, 403

            # Check if it is admin adding the course
            query = client.query(kind=USERS)
            query.add_filter(filter=PropertyFilter('sub', '=', user_id))
            results = list(query.fetch())
            print("RESULTS: ", results)

            # Check if role is admin because only admin can create courses
            if not results or results[0]['role'] != 'admin':
                return ERROR_PERMISSION, 403
            
            print('Uh-oh')

            for property, value in content.items():
                #print("PROPERTY", property)
                #print('CONTENT: ', content)
                
                # Validating if the instructor id exists
                if property == 'instructor_id':
                    query = client.query(kind=COURSES)
                    query.add_filter(filter=PropertyFilter('instructor_id', '=', content.get('instructor_id')))
                    results = list(query.fetch())

                    if not results:
                        return ERROR_INVALID_REQUEST_BODY, 400
                
                course[property] = value

            client.put(course)

            course['id'] = course.key.id
            course['self'] = f"{request.host_url}{COURSES}/{id}"

            return course, 200

        except:
            return ERROR_UNAUTHORIZED, 401

    if request.method == 'DELETE':
        try:
            # Verify JWT
            payload = verify_jwt(request)
            user_role = payload.get('role')

            # Get course
            course_key = client.key(COURSES, id)
            course = client.get(key=course_key)

            # If course doesn't exist, return 403 error code
            if course is None:
                return ERROR_PERMISSION, 403

            # Is the user updating the course an admin?
            if user_role != 'admin':
                return ERROR_PERMISSION, 403

            client.delete(course_key)
            return '', 204
        except:
            return ERROR_UNAUTHORIZED, 401       

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
