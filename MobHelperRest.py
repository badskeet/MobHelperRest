import json
import flask
from os import environ as env
from datetime import datetime, date, timedelta
from sqlalchemy.engine.url import URL
from flask_sqlalchemy import SQLAlchemy, inspect
from flask_jwt_simple import (JWTManager, jwt_required, create_jwt, get_jwt_identity)
from flask.json import JSONEncoder

from flask_cors import CORS

class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        try:
            if isinstance(obj, date):
                return obj.isoformat() #datetime.strftime(obj, '%Y-%m-%d %H:%M:S')
            iterable = iter(obj)
        except TypeError:
            pass
        else:
            return list(iterable)
        return JSONEncoder.default(self, obj)


# Initialization
app = flask.Flask(__name__)

# Add to headers param: Access-Control-Allow-Origin': '*'
#cors = CORS(app, resources={r"/api/*": {"origins": "*"}})
CORS(app)


# declare new custom json encoder
app.json_encoder = CustomJSONEncoder

# Setup the Flask-JWT-Simple extension
app.config['JWT_EXPIRES'] = timedelta(days=2, hours=1, seconds=30) # datetime.timedelta timedelta(days=1, hours=2, seconds=15)
app.config['JWT_SECRET_KEY'] = 'my super secret key for encripting token'
#app.config['CORS_ENABLED'] = True

# Setup the SQLAlchemy extension
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = URL('mssql+pymssql',
                 username='u0361128_user',
                 password="""Qwerty123""",
                 host='mssql.u0361128.plsk.regruhosting.ru',
                 database='u0361128_proj_advice')

# extensions
db = SQLAlchemy(app)
db.create_engine(app.config['SQLALCHEMY_DATABASE_URI'], pool_timeout=60, pool_size=10, max_overflow=20)
jwt = JWTManager(app)

# describe model tables of db
class User(db.Model):
    __tablename__ = '_users' #db.Model.metadata.tables['BUILDING']
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), index=True)
    password_hash = db.Column(db.String(255))

class UserList(db.Model):
    __tablename__ = '_userslist' #db.Model.metadata.tables['BUILDING']
    tb = db.Column(db.String(32), nullable=False)
    name_gosb_in_templ = db.Column(db.String(64), primary_key=True) # id for join to tasks
    role = db.Column(db.String(32), nullable=False)
    fio = db.Column(db.String(64), nullable=False)
    int_email = db.Column(db.String(32), nullable=True)
    ext_email = db.Column(db.String(32), index=True)
    omega = db.Column(db.String(64),nullable=True)
    speech = db.Column(db.String(32),nullable=False)
    comment = db.Column(db.String(255), nullable=True)
    hash_sha1_password = db.Column(db.String(250), nullable=False)
    text_password = db.Column(db.String(250), nullable=False)
    children = db.relationship("Tasks", back_populates="parent",lazy='dynamic') # ralation to tasks
    def find_by_username(self, username):
       return self.query.filter_by(username = username).first()

class Tasks(db.Model):
    __tablename__ = 'v_tasks'
    id_task = db.Column(db.Integer, primary_key=True, index=True)
    report_dt = db.Column(db.Date, nullable=False)
    report_dt_to = db.Column(db.Date, nullable=False)
    dt_beg = db.Column(db.Date, nullable=False)
    dt_end = db.Column(db.Date, nullable=False)
    violation_type_top = db.Column(db.String(16), nullable=False)
    violation_type_id = db.Column(db.Integer, nullable=False)
    vt = db.Column(db.String(128), nullable=False)
    n_priority = db.Column(db.Integer, nullable=False)
    plan_value = db.Column(db.String(30), nullable=False)
    fact_value = db.Column(db.String(30), nullable=False)
    tsk = db.Column(db.String(2048), nullable=False)
    u_com = db.Column(db.String(4000), nullable=False)
    urf_code = db.Column(db.String(16), nullable=False)
    gosb_name = db.Column(db.String(64), db.ForeignKey('_userslist.name_gosb_in_templ')) #id for join to users
    task_checked_cnt = db.Column(db.Integer, nullable=False)
    is_unable_to_workout = db.Column(db.Integer, nullable=False)
    #user_comments = db.Column(db.String(250), nullable=True)
    flg_new = db.Column(db.Integer, nullable=False)
    id_status = db.Column(db.Integer, nullable=False)
    id_priority = db.Column(db.Integer, nullable=False)
    nk_reason = db.Column(db.String(1024), nullable=False)
    dt_dml = db.Column(db.DateTime, default=datetime.now())
    dt_update = db.Column(db.DateTime, onupdate=datetime.now()) # add reverse ralation
    parent = db.relationship("UserList", back_populates="children")
    # function for transfer object to dictionary
    def to_dict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}
    def to_dict2(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class TasksExt(db.Model):
    __tablename__ = 'task_ext'
    task_id = db.Column(db.Integer, primary_key=True, index=True)
    id_status = db.Column(db.Integer, nullable=False)
    id_priority = db.Column(db.Integer, nullable=False)
    flg_new = db.Column(db.Integer, nullable=False)
    nk_reason= db.Column(db.String(1024), nullable=False)

class News(db.Model):
    __tablename__ = '_news'
    id = db.Column(db.Integer, primary_key=True, index=True)
    date = db.Column(db.DateTime, nullable=False)
    title = db.Column(db.String(250), nullable=False)
    description = db.Column(db.String(2000), nullable=False)
    # function for transfer object to dictionary
    def to_dict(self):
        return {c.key: getattr(self, c.key) for c in inspect(self).mapper.column_attrs}

#Check if token expired
@jwt.expired_token_loader
def my_expired_token_callback():
    err_json = {
        "status": 401,
        "title": "Expired JWT",
        "detail": "The JWT has expired"
    }
    return flask.jsonify(err_json), 401

def to_json(data): # return compact json without formatting unlike flask.jsonify
    return json.dumps(data) + "\n"

def json_data_validate():
    errors = []
    json = flask.request.get_json()
    if json is None:
        errors.append(
            "No JSON sent. Did you forget to set Content-Type header to application/json?")
        return (None, errors)

    for field_name in ['id_task','flg_new','id_status','id_priority','nk_reason']:
        if type(json.get(field_name)) is not str:
            errors.append("Field '{}' is missing or is not a string".format(field_name))
    return (json, errors)

def check_auth(username, password):
    #find username
    user = UserList.query.filter_by(ext_email=username).first()
    #compare password hash internal algoritm
    #if user and pwd_context.verify(password, user.password_hash): ## for encript pwd_context.encrypt(password)
    #compare password in plain text
    if (user and password == user.text_password):
        return True
    else:
        return False

@app.route('/')
def index():
    return 'RESTful API for mobile helper of manager Retail Bussines! V.0.1'

@app.route('/api/login', methods=['POST'])
def login():
    print(flask.request)
    if not flask.request.is_json:
        return flask.jsonify({"msg": "Missing JSON in request"}), 400
    params = flask.request.get_json()
    username = params.get('username', None)
    password = params.get('password', None)
    auth_res = check_auth(username, password)
    if not auth_res:
        return flask.jsonify({"msg": "Bad Auth"}), 401
    else:
        # Identity can be any data that is json serializable
        # ret = {'jwt': create_jwt(identity=username)} ##My Custom answer don't work
        ret = {'access_token': create_jwt(identity=username) }
        return flask.jsonify(ret), 200

#Get all tasks
@app.route('/api/tasks', methods=['GET'])
@jwt_required
def get_tasks():
    auth_username = get_jwt_identity()
    user = UserList.query.filter_by(ext_email=auth_username).first()
    tasks = []
    for row in user.children:
        tasks.append(row.to_dict())
    return flask.jsonify(tasks),200 #{"tasks": tasks}

#Get one task
@app.route('/api/tasks/<int:id_task>', methods=['GET'])
@jwt_required
def get_task(id_task):
    auth_username = get_jwt_identity()
    user = UserList.query.filter_by(ext_email = auth_username).first()
    task = user.children.filter_by(id_task = id_task).first()
    if task:
        tasks = []
        tasks.append(task.to_dict())
        return flask.jsonify(tasks),200
    else:
        return flask.jsonify({}),400

#Update properties by id
@app.route('/api/task', methods=['POST'])
@jwt_required
def update_task():
    (json, errors) = json_data_validate()
    if errors:  # list is not empty
        return flask.jsonify({"errors": errors}),400 #resp(400, {"errors": errors})
    auth_username = get_jwt_identity()
    user = UserList.query.filter_by(ext_email = auth_username).first()
    task = user.children.filter_by(id_task = json['id_task']).first()
    if task:
        #task.is_unable_to_workout = json['is_unable_to_workout']
        #task.user_comments = json['user_comments']pip install -r requirements.txt
        #task.action = json['action']
        task.flg_new = json['flg_new']
        task.id_status = json['id_status']
        task.id_priority = json['id_priority']
        task.nk_reason = json['nk_reason']
    return flask.jsonify({"msg": "OK"}),200

#Get all news
@app.route('/api/news', methods=['GET'])
def get_news():
    allnews = News.query.all()
    news = []
    for row in allnews:
        news.append(row.to_dict())
    return flask.jsonify(news),200

if __name__ == '__main__':
    db.create_all()
    app.debug = True  # Enables auto reload during development
    app.port = env.get("PORT", 5000) # Define port binding
    #app.host = "127.0.0.1"  # Define listening ip
    app.run()
