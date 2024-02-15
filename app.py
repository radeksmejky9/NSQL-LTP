import hashlib
from flask import Flask, redirect, render_template, request, session, url_for
import pymongo
import redis
from bson import ObjectId
import json
import jinja2

app = Flask(__name__)
app.secret_key = "12345"


mongo_client = pymongo.MongoClient("mongodb://admin:admin@mongo:27017/")
db = mongo_client["TaskList"]
tasks_collection = db["tasks"]
users_collection = db["users"]
redis_client = redis.StrictRedis(host="redis", port=6379, db=0)


def hash_password(password):
    password_bytes = password.encode("utf-8")
    hash_object = hashlib.sha256(password_bytes)
    return hash_object.hexdigest()


def handle_task():
    if "delete_task" in request.form:
        task_id = request.form["delete_task"]
        tasks_collection.delete_one({"_id": ObjectId(task_id)})
    elif "complete_task" in request.form:
        task_id = request.form["complete_task"]
        tasks_collection.update_one(
            {"_id": ObjectId(task_id)}, {"$set": {"completed": True}}
        )
    elif "undo_task" in request.form:
        task_id = request.form["undo_task"]
        tasks_collection.update_one(
            {"_id": ObjectId(task_id)}, {"$set": {"completed": False}}
        )
    elif "add_task" in request.form:
        new_task = {
            "email": session["email"],
            "date": request.form["task_date"],
            "description": request.form["task_description"],
            "completed": False,
        }
        tasks_collection.insert_one(new_task)
    redis_client.delete(f"tasks:{session['email']}")


def handle_auth():
    if "sign_in" in request.form:
        email = request.form["email"]
        password = request.form["password"]
        user = users_collection.find_one(
            {"email": email, "password": hash_password(password)}
        )
        if user:
            session["email"] = user["email"]
            return None
        else:
            return "Uživatelské jméno nebo heslo jsou nesprávné"

    elif "sign_up" in request.form:
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        password_check = request.form["password-check"]
        if password == password_check:
            existing_user = users_collection.find_one(
                {"$or": [{"email": email}, {"username": username}]}
            )
            if existing_user:
                return "Uživatel s tímto jménem nebo emailovou adresou již existuje"
            else:
                new_user = {
                    "email": email,
                    "username": username,
                    "password": hash_password(password),
                }
                users_collection.insert_one(new_user)
                return "Registrace byla už úspěšná"
        else:
            return "Hesla nejsou shodná"


@app.route("/", methods=["GET", "POST"])
def index():
    if "email" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        handle_task()

    tasks_cached = redis_client.get(f"tasks:{session['email']}")
    if tasks_cached:
        tasks = json.loads(tasks_cached)
    else:
        tasks_from_db = list(tasks_collection.find({"email": session["email"]}))
        tasks = []
        for task in tasks_from_db:
            task["_id"] = str(task["_id"])
            tasks.append(task)
        redis_client.set(f"tasks:{session['email']}", json.dumps(tasks))
    sorted_tasks = sorted(tasks, key=lambda x: x["date"])
    return render_template("index.html", tasks=sorted_tasks)


@app.route("/login", methods=["GET", "POST"])
def login():
    if "email" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        response = handle_auth()
        if None is response:
            return redirect(url_for("index"))
        return render_template("login.html", response=response)
    return render_template("login.html", response="")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/registration", methods=["GET", "POST"])
def registration():
    if "email" in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        response = handle_auth()
        return render_template("registration.html", response=response)
    return render_template("", response="")


if __name__ == "__main__":
    app.run(debug=True)
