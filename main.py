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

AVATAR_BUCKET='<bucket_name_goes_here>'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# Endpoints/kinds
USERS_LOGIN = "users/login"
USERS = "users"
AVATAR = "avatar"
COURSES = "courses"
STUDENTS = "students"

# Update the values of the following 3 variables
CLIENT_ID = '<client_id_goes_here>'
CLIENT_SECRET = '<client_secret_goes_here>'
DOMAIN = '<domain_goes_here>'

ALGORITHMS = ["RS256"]

# Error Codes
ERROR_INVALID_REQUEST_BODY = {"Error" : "The request body is invalid"}
ERROR_UNAUTHORIZED = {"Error" : "Unauthorized"}
ERROR_PERMISSION = {"Error": "You don't have permission on this resource"}
ERROR_NOT_FOUND = {"Error" : "Not found"}
ERROR_INVALID_ENROLLMENT = {"Error": "Enrollment data is invalid"}

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

    response = r.json()
    token = response['id_token']

    return jsonify({"token": token})

# Get all users if the Authorization header contains a valid JWT
@app.route('/' + USERS, methods=['GET'])
def get_users():
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
    try:
        payload = verify_jwt(request)
        user_id = payload.get('sub')
        key = client.key(USERS, id)
        user = client.get(key)

        # Check if user has a avatar by comparing the value of 'Y' or 'N'. 'Y' = Yes, 'N' = No
        if user['avatar'] == 'Y':
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

            # Checking for valid JWTs
            # If not valid, return 403
            if user['sub'] != user_id:
                return ERROR_PERMISSION, 403

            # Get all courses that the instructor teaches
            query = client.query(kind=COURSES)
            query.add_filter(filter=PropertyFilter('instructor_id', '=', id))
            courses = list(query.fetch())

            # If instructor is teaching a course
            if courses is not None:
                list_of_courses = []
                for course in courses:
                    list_of_courses.append(f"{request.host_url}{COURSES}/{course.key.id}")

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
                            'courses': list_of_courses
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

            # Checking for valid JWTs
            # If not valid, return 403
            if user['sub'] != user_id:
                return ERROR_PERMISSION, 403

            # Get all courses that the instructor teaches
            query = client.query(kind=COURSES)
            courses = list(query.fetch())
            student_courses = []

            # Iterating through courses to see if it contains any students
            for course in courses:
                if course.get('enrollment'):
                    enrollment = course.get('enrollment')
                else:
                    enrollment = []
                
                # Checking to see if that course has enrollment
                if id in enrollment:
                    student_courses.append(f"{request.host_url}{COURSES}/{course.key.id}")

            if student_courses is not None:
                if avatar_url:
                    user = {
                            'courses': student_courses,
                            'id': id,
                            'role': user['role'],
                            'sub': user['sub'],
                            'avatar_url': f"{request.host_url}{USERS}/{id}/{AVATAR}"
                        } 

                    return jsonify(user)
                else:
                    
                    user = {
                            'courses': student_courses,
                            'id': id,
                            'role': user['role'],
                            'sub': user['sub'],
                        } 

                    return jsonify(user)
            else: 
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

            # Update 'avatar' entity for the user to 'Y' for Yes
            user['avatar'] = 'Y'
            # Save the avatar status in datastore
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

            # Checking for valid JWTs
            key = client.key(USERS, id)
            user = client.get(key)

            # If not valid, return 403
            if user['sub'] != user_id:
                return ERROR_PERMISSION, 403
            
            # If user has no avatar, return 404
            if user['avatar'] == 'N':
                return ERROR_NOT_FOUND, 404
            
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(AVATAR_BUCKET)

            # Create a blob with the given file name
            blob = bucket.blob('student1.png')

            # Create a file object in memory using Python io package
            file_obj = io.BytesIO()

            # Download the file from Cloud Storage to the file_obj variable
            blob.download_to_file(file_obj)

            # Position the file_obj to its beginning
            file_obj.seek(0)

            return send_file(file_obj, mimetype='image/png', as_attachment=False, download_name='student1.png')
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
            if user.get('avatar') == 'N':
                return ERROR_NOT_FOUND, 404
            
            storage_client = storage.Client()

            bucket = storage_client.get_bucket(AVATAR_BUCKET)

            blob = bucket.blob('student1.png')

            # Delete the file from Cloud Storage
            blob.delete()

            # Update the avatar for user
            user['avatar'] = 'N'
            client.put(user)

            return '', 204
            
        except:
            return ERROR_UNAUTHORIZED, 401    

# Create courses OR
# Get all courses
@app.route('/' + COURSES, methods=['POST', 'GET'])
def post_courses():
    if request.method == "POST":
        content = request.get_json()

        try:
            payload = verify_jwt(request)
            user_id = payload.get('sub')

            # If the request body do not contain any one of the required field, return 400
            for i in ['subject', 'number', 'title', 'term', 'instructor_id']:
                if i not in content:
                    return ERROR_INVALID_REQUEST_BODY, 400

            # Check if it is admin adding the course
            query = client.query(kind=USERS)
            query.add_filter(filter=PropertyFilter('sub', '=', user_id))
            results = list(query.fetch())

            # Check if role is admin because only admin can create courses
            if not results or results[0]['role'] != 'admin':
                return ERROR_PERMISSION, 403

            # Check to see if the content of the request contains a valid instructor_id and that id matches the instructor
            user = client.key(USERS, content['instructor_id'])
            instructor = client.get(user)

            # If no instructor is found, return 400
            if instructor is not None and instructor['role'] != 'instructor':
                return ERROR_INVALID_REQUEST_BODY, 400

            # Create courses entity in datastore
            course = datastore.Entity(key=client.key(COURSES))

            course.update({
                'subject': content['subject'],
                'number': content['number'],
                'title': content['title'],
                'term': content['term'],
                'instructor_id': content['instructor_id']
            })

            client.put(course)
            id = course.key.id

            self_link = f"{request.host_url}{COURSES}/{id}"

            response = {
                'id': id,
                'subject': course['subject'],
                'number': course['number'],
                'title': course['title'],
                'term': course['term'],
                'instructor_id': course['instructor_id'],
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
        content = request.get_json()
        try:
            # Verify JWT
            payload = verify_jwt(request)
            user_id = payload.get('sub')

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

            # Check if role is admin because only admin can create courses
            if not results or results[0]['role'] != 'admin':
                return ERROR_PERMISSION, 403

            for property, value in content.items():
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
            user_id = payload.get('sub')

            # Get course
            course_key = client.key(COURSES, id)
            course = client.get(key=course_key)

            # If course doesn't exist, return 403 error code
            if course is None:
                return ERROR_PERMISSION, 403

            # Check if it is admin/instructor adding enrollment to the course
            query = client.query(kind=USERS)
            query.add_filter(filter=PropertyFilter('sub', '=', user_id))
            results = list(query.fetch())

            # Check if role is admin or instructor because only admin/instructor can update enrollment
            if not results or results[0]['role'] != 'admin':
                return ERROR_PERMISSION, 403

            client.delete(course_key)
            return '', 204
        except:
            return ERROR_UNAUTHORIZED, 401    

# Update enrollment in a course
@app.route('/' + COURSES + '/<int:id>/' + STUDENTS, methods=['PATCH', 'GET'])
def update_enrollment(id):
    if request.method == 'PATCH':
        try:
            payload = verify_jwt(request)
            user_id = payload.get('sub')

            # Get course
            course_key = client.key(COURSES, id)
            course = client.get(key=course_key)

            # If course doesn't exist, return 403 error code
            if course is None:
                return ERROR_PERMISSION, 403

            # Create a property if it does not exist in the datastore
            if 'enrollment' not in course:
                course['enrollment'] = []

            # Check if it is admin/instructor adding enrollment to the course
            query = client.query(kind=USERS)
            query.add_filter(filter=PropertyFilter('sub', '=', user_id))
            results = list(query.fetch())

            # Check if role is admin or instructor because only admin/instructor can update enrollment
            if not results or results[0]['role'] not in ['admin', 'instructor']:
                return ERROR_PERMISSION, 403

            # Get request content
            content = request.get_json()
            students_to_add = content.get('add', [])
            students_to_remove = content.get('remove', [])

            # Check if students exist in both add and remove JSON attribute using intersection
            error = set(students_to_add) & set(students_to_remove)

            if error:
                return ERROR_INVALID_ENROLLMENT, 409

            # If there are students in 'add' array
            if students_to_add:
                add_students = []

                # Validate if the student IDs exists
                for student in students_to_add:
                    student_key = client.key(USERS, student)
                    result = client.get(student_key)

                    # If student exists
                    if result:
                        add_students.append(student)
                    # Return invalid data code 409
                    else: 
                        return ERROR_INVALID_ENROLLMENT, 409

                 # Add students
                for student in add_students:
                    # Skip students that are already in the course
                    if student not in course['enrollment']:
                        course['enrollment'].append(student)
            
            # If there are students in 'drop' array
            if students_to_remove:
                remove_students = []

                # Validate if the student IDs exists
                for student in students_to_remove:
                    student_key = client.key(USERS, student)
                    result = client.get(student_key)

                    if results:
                        remove_students.append(student)
                    else:
                        return ERROR_INVALID_ENROLLMENT, 409

                 # Drop students
                for student in remove_students:
                    # Skip students not enrolled in the course
                    if student in course['enrollment']:
                        course['enrollment'].remove(student)

            client.put(course)

            return '', 200 
        except:
            return ERROR_UNAUTHORIZED, 401

    if request.method == 'GET':
        try:
            payload = verify_jwt(request)
            user_id = payload.get('sub')

            # Get course
            course_key = client.key(COURSES, id)
            course = client.get(key=course_key)

            # If course doesn't exist, return 403 error code
            if course is None:
                return ERROR_PERMISSION, 403

            # Check if it is admin/instructor adding enrollment to the course
            query = client.query(kind=USERS)
            query.add_filter(filter=PropertyFilter('sub', '=', user_id))
            results = list(query.fetch())

            # Check if role is admin or instructor because only admin/instructor can update enrollment
            if not results or results[0]['role'] not in ['admin', 'instructor']:
                return ERROR_PERMISSION, 403

            if course.get('enrollment'):
                students = course['enrollment']
            else:
                students = []

            return students, 200 
        except:
            return ERROR_UNAUTHORIZED, 401

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
