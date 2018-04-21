"""Description of the module."""
import atexit
from flask import Flask
from flask import jsonify
from flask import request
from flask import Response
from flask_apscheduler import APScheduler
from flask_mail import Mail
from flask_mail import Message
from functools import wraps
import hashlib
import hmac
import os
from pymongo import MongoClient
from smtplib import SMTPException
from time import time

app = Flask(__name__)

# Load app configuration
app.config.from_object('config.default')

# Load the file specified by the APP_CONFIG_FILE environment variable
# Variables defined here will override those in the default configuration
app.config.from_envvar('APP_CONFIG_FILE')

# Put in a easy to type variable
conf = app.config

# Load Flask E-mail Module
mail = Mail(app)

db_name = 'laura'

# Set application start time
start_time = int(time())

# Check if the environment variable is set
if 'APP_CONFIG_FILE' not in os.environ:
    print('ERROR: Missing APP_CONFIG_FILE environment variable. '
          'Set it to run.')
    exit(1)

# Load Flask E-mail Module
mail = Mail(app)

# Make the connection and get the mongo instance
client = MongoClient(conf['DB_URI'])
db = client[conf['DB_NAME']]
if not db:
    print('ERROR: Couldn\'t connect to database')
    exit(2)
print('Connected to db {} with uri {}'.format(conf['DB_NAME'],
                                              conf['DB_URI']))

# On Bluemix, get the port number from the environment variable PORT
# When running this app on the local machine, default the port to 8080
port = int(os.getenv('PORT', 5454))


def send_mail(info):
    """E-mail sending template."""
    subject = info['subject']  # Mail Subject
    message = info['body']  # Mail Body
    msg = Message(recipients=[info['email']],
                  subject=subject,
                  body=message)
    try:
        mail.send(msg)
    except SMTPException as e:
        app.logger.error("Error sending message: {}".format(e))
        return -1
    return 0


# ------------- PASSWORD AUTHENTICATION DECORATOR EXAMPLE ------------------- #
def check_auth(username, password):
    """Check if a username / password combination is valid."""
    return (username == conf['AUTH_USERNAME'] and
            password == conf['AUTH_PASSWORD'])


def authenticate():
    """Send a 401 response that enables basic auth."""
    return Response('Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials', 401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    """Create this view function to be wraped in a decorator."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated
# ------------- PASSWORD AUTHENTICATION DECORATOR EXAMPLE ------------------- #


# --------------- TOKEN AUTHENTICATION DECORATOR EXAMPLE -------------------- #
def generate_signature(data, key):
    """Generate HMAC signature from data and SECRET_KEY."""
    mac = hmac.new(key.encode("utf-8"), msg=data, digestmod=hashlib.sha1)
    return mac.hexdigest()


def verify_signature(key, data, signature):
    """Verify Signature to Accept POST requests."""
    mac = hmac.new(key.encode("utf-8"), msg=data, digestmod=hashlib.sha1)
    return hmac.compare_digest(mac.hexdigest(), signature)


def require_token(f):
    """A decorator that checks and validates the request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            signature = request.headers['X-LAURABOT-SIGNATURE']
            data = request.data
        except Exception as e:
            app.logger.error("An error ocurred: {}".format(e))
            message = {'status': '403', 'message': 'forbbiden: no secret key'}
            response = jsonify(message)
            response.status_code = 403
            return response

        if not verify_signature(conf['SECRET_KEY'], data, signature):
            message = {'status': '403',
                       'message': 'forbbiden: wrong secret key'}
            response = jsonify(message)
            response.status_code = 403
            return response

        return f(*args, **kwargs)
    return decorated
# --------------- TOKEN AUTHENTICATION DECORATOR EXAMPLE -------------------- #


@app.route('/status/', methods=['GET'])
def health_check():
    """Health Check Page to Status Monitoring Application."""
    uptime = int(time()) - start_time
    message = {'uptime': uptime,
               'version': 0.1,
               'status': 0
               }
    response = jsonify(message)
    response.status_code = 200
    return response


@app.route('/user/<int:entidade>/<int:atendimento>/<string:documento>', methods=['GET'])
def user_profile(entidade,atendimento,documento):
    print("aquiii")
    print(username)
    atendimeto = 2713399
    entidade = 1
    documento = 'vital_signs'
    message = {'entidade_id': entidade,
               'atendimento_id': atendimento,
               'document_type': documento}
    print(messege)
    resultSet = db.history_people.find(message)
    print(resultSet)
    empList = []
    for doc in resultSet:
     empList.append(empDict)

    return empList


@app.route('/posto/<int:entidade>', methods=['GET'])
def posto_test(entidade):
    resultSet = db.history_people.find({"entidade_id": entidade})
    print(resultSet)
    empList = []
    for doc in resultSet:
     empList.append(doc)
    response.status_code = 200
    return response

@app.route('/teste/<int:entidade>', methods=['GET'])
def posto(entidade):
    atendimento = 2713399
    entidade = 1
    documento = 'vital_signs'
    message = {'entidade_id': entidade,
               'atendimento_id': atendimento,
               'document_type': documento}
    print(message)
    resultSet = db.history_people.find(message)
    print(resultSet)
    empList = []
    for doc in resultSet:
     empList.append(doc)
    return empList




@atexit.register
def shutdown():
    """Close connection to the database on exit."""
    if client:
        client.close()


def job_function():
    """Cron job will be executed for intervals."""
    print('Print from cron job.')


if __name__ == '__main__':
    # Set and Start Cron jobs.
    conf['JOBS'] = [{
        'id': 'Job_id',
        'func': job_function,
        'trigger': 'interval',
        'seconds': 60  # interval to run again
    }]
    scheduler = APScheduler()
    scheduler.init_app(app)
    scheduler.start()

    app.run(host='0.0.0.0', port=port, debug=conf['DEBUG'],
            use_reloader=False)
