from flask import Flask
from flask_pymongo import PyMongo

app = Flask(__name__)
mongo = PyMongo(app)

# connect to another MongoDB server altogether
app.config['MONGO3_HOST'] = 'bdtest.lan'
app.config['MONGO3_PORT'] = 27017
app.config['MONGO3_DBNAME'] = 'laura'
app.config['MONGO_USERNAME'] = 'allan'
app.config['MONGO_PASSWORD'] = 'allan'
mongo = PyMongo(app, config_prefix='MONGO3')


@app.route("/init")
def hello():
    return "Hello World!"


@app.route('/user/<username>')
def user_profile(username):
    user = mongo.db.history_people.find_one_or_404({'_id': username})
    return 



