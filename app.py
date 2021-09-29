from flask import Flask, redirect, render_template, request, flash, session
from flask_pymongo import PyMongo
import os
from datetime import datetime
from passlib.hash import pbkdf2_sha256
from flask_moment import Moment
app = Flask(__name__)

moment = Moment(app)

connection_string = os.environ.get("MONGO_URI")
if connection_string == None:
    file = open("connection_string.txt")
    connection_string = file.read().strip()
    file.close()
app.config["MONGO_URI"] = connection_string
mongo = PyMongo(app)

secret_key = os.environ.get("SECRET_KEY")
if secret_key == None:
    file = open("secret_key.txt")
    secret_key = file.read().strip()
    file.close()
app.config["SECRET_KEY"] = secret_key


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        password = request.form["password"]
        encrypted_password = pbkdf2_sha256.hash(password)
        email = request.form["email"].strip()
        name = request.form["name"].strip()
        if email == "" or password == "" or name == "":
            flash(
                "1 or more requires fields are blank, don't try to change the front end.", "danger")
            return redirect("/register")

        user_check = mongo.db.users.find_one({"Email Adress": email})
        if user_check == None:
            record = {"Password": encrypted_password,
                      "Email Adress": email, "Name": name}
            mongo.db.users.insert_one(record)
            flash("Succsessfuly signed up!", "success")
            flash("Welcome!", "primary")
            return redirect("/")
        else:
            flash("email adress already exists", "danger")
            return redirect("/signin")


@app.route("/home", methods=["GET", "POST"])
def home():
    if "Email" not in session:
        flash("Your session has expired, please log in to continue", "warning")
        return redirect("/signin")
    else:
        name_dict = mongo.db.users.find_one({"Email Adress": session["Email"]})
        name = name_dict["Name"]
        return render_template("home.html", name=name)


@app.route("/post", methods=["GET", "POST"])
def post():
    if "Email" not in session:
        flash("Your session has expired, please log in to continue", "warning")
        return redirect("/signin")
    elif request.method == "GET":
        email = session["Email"]
        user = mongo.db.users.find_one({"Email Adress": email})
        name = user["Name"]
        return render_template("post.html", name=name)
    else:
        post = request.form["post"]
        email = session["Email"]
        user = mongo.db.users.find_one({"Email Adress": email})
        name = user["Name"]
        record = {"Post": post, "Name": name, "Email": email,
                  "Time Of Post": datetime.utcnow()}
        mongo.db.posts.insert_one(record)
        return redirect("/post")


@app.route("/logout")
def logout():
    session.pop("Email")
    return redirect("/")


@app.route("/allposts")
def allposts():
    post_data = mongo.db.posts.find()
    posts = list()
    for i in post_data:
        posts.append(i)
    return render_template("allposts.html", posts = posts)

@app.route("/myposts")
def myposts():
    email = session["Email"]
    post_data = mongo.db.posts.find({"Email": email})
    posts = list()
    for i in post_data:
        posts.append(i)
    return render_template("myposts.html", posts = posts)


@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "GET":
        return render_template("signin.html")
    else:
        email = request.form["email"]
        password = request.form["password"]
        user = mongo.db.users.find_one({"Email Adress": email})
        if user != None:
            if pbkdf2_sha256.verify(password, user["Password"]):
                name = user["Name"]
                session["Email"] = email
                flash("Logged in Successfully! welcome "+name, "success")
                return redirect("/home")
            else:
                flash("Password incorrect!", "danger")
                return redirect("/signin")
        else:
            flash("Username incorrect!", "danger")
            return redirect("/signin")


if __name__ == "__main__":
    app.run()
