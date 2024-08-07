from flask import Flask, jsonify, request, abort, send_from_directory, url_for, redirect, session
from bson.objectid import ObjectId
from bson.json_util import dumps, default
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_cors import CORS
from dotenv import load_dotenv
from flask_session import Session
import os
import pymongo
import logging

logging.basicConfig(level=logging.DEBUG)

load_dotenv()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

app = Flask(__name__)
app.config["SECRET_KEY"] = "code100"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
CORS(app)

client = pymongo.MongoClient("mongodb://localhost:27017")
db = client["Shlokdb"]
users_collection = db["users"]
tasks_collection = db["tasks"]
attendance_collection = db["attendance"]
chats_collection = db["chats"]

# attendance_data = [
#     {"username": "john_doe", "check_in": "2023-08-03T09:00:00", "check_out": "2023-08-03T17:00:00"},
#     {"username": "jane_doe", "check_in": "2023-08-03T08:45:00", "check_out": "2023-08-03T16:45:00"},
# ]


def default(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError("Type not serializable")

@app.route('/')
def redirect_to_login():
    return redirect(url_for('serve_login'))

@app.route('/login')
def serve_login():
    return send_from_directory('static', 'login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
    
    user = users_collection.find_one({"username": username})
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"msg": "Bad username or password"}), 401
    
    check_in(username)
    session['username'] = username
    return jsonify({"msg": "Logged in successfully", "username": username}), 200

@app.route('/logout', methods=['GET','POST'])
def logout():
    username = session.pop('username', None)
    if not username:
        return jsonify({"msg": "Missing username"}), 400
    check_out(username)
    return jsonify({"msg": "Logged out successfully"})

@app.route('/create-user', methods=['POST'])
def create_user():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    
    if not username or not password:
        return jsonify({"msg": "Missing username or password"}), 400
    
    if users_collection.find_one({"username": username}):
        return jsonify({"msg": "Username already exists"}), 400
    
    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "password": hashed_password,
        "is_admin": False
    })
    return jsonify({"msg": "User created successfully"}), 201

@app.route('/complete-task', methods=['POST'])
def complete_task():
    username = session.get('username')
    task_description = request.json.get('task_description', None)
    if not task_description:
        return jsonify({"msg": "Task description is required"}), 400
    
    tasks_collection.insert_one({
        "username": username,
        "description": task_description,
        "completed_at": datetime.now().isoformat()
    })
    return jsonify({"msg": "Task completed successfully"}), 200

# @app.route('/attendance', methods=['GET'])
# def get_attendance():
#     username = session.get('username')
#     if not is_admin(username):
#         return jsonify({"msg": "Admin access required"}), 403
#     attendance = list(attendance_collection.find())
#     for record in attendance:
#         record['check_in'] = record['check_in'].isoformat()
#         if 'check_out' in record and record['check_out'] is not None:
#             record['check_out'] = record['check_out'].isoformat()
#     logging.debug(f"Attendance Data: {attendance}")
#     return dumps(attendance, default=default), 200

@app.route('/attendance', methods=['GET'])
def get_attendance():
    username = session.get('username')
    if not is_admin(username):
        return jsonify({"msg": "Admin access required"}), 403

    attendance_records = list(attendance_collection.find())
    for record in attendance_records:
        record['_id'] = str(record['_id'])
        if isinstance(record['check_in'], str):
            try:
                record['check_in'] = datetime.fromisoformat(record['check_in']).isoformat()
            except ValueError:
                pass
        if 'check_out' in record and isinstance(record['check_out'], str):
            try:
                record['check_out'] = datetime.fromisoformat(record['check_out']).isoformat()
            except ValueError:
                pass

    logging.debug(f"Attendance Data: {attendance_records}")
    return jsonify(attendance_records)


# @app.route('/tasks', methods=['GET'])
# def get_tasks():
#     username = session.get('username')
#     if not is_admin(username):
#         return jsonify({"msg": "Admin access required"}), 403
#     tasks = list(tasks_collection.find())
#     for task in tasks:
#         task['completed_at'] = task['completed_at'].isoformat()
#     logging.debug(f"Task Data: {tasks}")
#     return dumps(tasks, default=default), 200

@app.route('/tasks', methods=['GET'])
def get_tasks():
    username = session.get('username')
    if not is_admin(username):
        return jsonify({"msg": "Admin access required"}), 403
    
    tasks = list(tasks_collection.find())
    for task in tasks:
        if 'completed_at' in task and isinstance(task['completed_at'], str):
            try:
                task['completed_at'] = datetime.fromisoformat(task['completed_at'])
            except ValueError:
                task['completed_at'] = None

        if 'completed_at' in task and isinstance(task['completed_at'], datetime):
            task['completed_at'] = task['completed_at'].isoformat()
    
    logging.debug(f"Task Data: {tasks}")
    return dumps(tasks, default=default), 200

@app.route('/chat', methods=['POST'])
def post_message():
    username = session.get('username')
    if not username:
        return jsonify({"msg": "User not logged in"}), 401

    message = request.json.get('message')
    if not message:
        return jsonify({"msg": "Message is required"}), 400
    
    chats_collection.insert_one({
        "username": username,
        "message": message,
        "timestamp": datetime.now()
    })
    return jsonify({"msg": "Message posted successfully"}), 201

@app.route('/chat', methods=['GET'])
def get_messages():
    chats = list(chats_collection.find().sort("timestamp", -1).limit(100))
    
    for chat in chats:
        if isinstance(chat['timestamp'], datetime):
            chat['timestamp'] = chat['timestamp'].isoformat()
        chat['_id'] = str(chat['_id'])
    
    return jsonify(chats), 200


@app.route('/delete-user', methods=['DELETE'])
def delete_user():
    username = request.json.get('username')
    admin_username = session.get('username')
    
    if not is_admin(admin_username):
        return jsonify({"msg": "Admin access required"}), 403
    
    result = users_collection.delete_one({"username": username})
    if result.deleted_count == 0:
        return jsonify({"msg": "User not found"}), 404
    return jsonify({"msg": "User deleted successfully"}), 200

@app.route('/delete-chat', methods=['DELETE'])
def delete_chat():
    chat_id = request.json.get('chat_id', None)
    admin_username = session.get('username')
    
    if not is_admin(admin_username):
        return jsonify({"msg": "Admin access required"}), 403
    
    if not chat_id:
        return jsonify({"msg": "Invalid chat ID"}), 400
    
    result = chats_collection.delete_one({"_id": ObjectId(chat_id)})
    if result.deleted_count == 0:
        return jsonify({"msg": "Chat message not found"}), 404
    return jsonify({"msg": "Chat message deleted successfully"}), 200

@app.route('/dashboard', methods=['GET'])
def dashboard():
    username = session.get('username')
    
    if not username:
        return jsonify({"msg": "Username is required"}), 400
    
    user = users_collection.find_one({"username": username})
    
    if user and user.get('is_admin', False):
        return send_from_directory('static', 'admin_dashboard.html')
    elif user:
        return send_from_directory('static', 'user_dashboard.html')
    else:
        return jsonify({"msg": "User not found"}), 404

def check_in(username):
    attendance_collection.update_one(
        {"username": username, "check_out": None},
        {"$set": {"check_in": datetime.now().isoformat(), "username": username}},
        upsert=True
    )

def check_out(username):
    attendance_collection.update_one(
        {"username": username, "check_out": None},
        {"$set": {"check_out": datetime.now().isoformat()}}
    )

def is_admin(username):
    user = users_collection.find_one({"username": username})
    return user and user.get('is_admin', False)

if __name__ == '__main__':
    admin = users_collection.find_one({"username": "ADMIN_USERNAME"})
    if not admin:
        users_collection.insert_one({
            "username": "ADMIN_USERNAME",
            "password": generate_password_hash("ADMIN_PASSWORD"),
            "is_admin": True
        })
    app.run(debug=True)
