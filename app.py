import sqlite3
import logging
import os
import threading
import time
import uuid
import secrets
import hashlib

from flask import Flask, render_template, request, redirect, session
from flask_socketio import join_room, leave_room, send, SocketIO
from flask_session import Session
from markupsafe import escape

from helpers import login_required, hash_password, verify_password, get_db_connection, close_db, generate_token, create_db, rooms, online_users

logging.basicConfig(
    filemode = 'a',
    filename = "room.log",
    level = logging.INFO,
    format = "[%(levelname)s]-%(name)s:%(message)s",
    encoding = 'utf-8'
)
logger = logging.getLogger(__name__)

loacl_time = time.localtime()

private_rooms = {}
private_room_lock = threading.Lock()
PRIVATE_TOKENHEAD = "private_"

# 配置应用程序
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(108)
logger.info(f"SECRET_KEY: {app.config['SECRET_KEY']}")
# 将websocket与Flask应用程序集成
socketio = SocketIO(app)

# 配置会话，将会话数据存储在服务器端
# 会话在浏览器关闭后不会永久保存
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# 建立数据库连接并创建表（如果尚未创建）
# 确保只初始化一次
_initialized = False
# 建立锁
_init_lock = threading.Lock()
create_db_lock = threading.Lock()

@app.before_request
def init_db_once():
    global _initialized
    # 第一次检查
    if not _initialized:
        # 获取锁
        with _init_lock:
            #第二次检查
            if not _initialized:     
                db = get_db_connection() 
                create_db(db)
                _initialized = True

    # user_id = session.get("user_id")
    # if user_id:
    #     if online_users.get(user_id) != session.get("session_id"):
    #         session.clear()
    #         return redirect("/login")
        

# 自动关闭数据库连接
app.teardown_appcontext(close_db)

# 禁止浏览器缓存
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # 获取用户已加入的房间列表
    db = get_db_connection()
    user_rooms = db.execute("""
            SELECT * 
            FROM room
            WHERE token IN (
                SELECT room_token
                FROM bind 
                WHERE user_id = ?
            )""", (session["user_id"],)).fetchall()
    # 如果创造后或加入了房间直接渲染对应聊天页面
    if session.get("room"):
        if db.execute("SELECT 1 FROM room WHERE token = ?", (session["room"],)).fetchone() is None:
            return render_template("error.html", error = "不要改变html的属性!")
        # 正常初始化在线状态
        if session["room"] not in rooms:
            rooms[session["room"]] = set()
        history = db.execute("""SELECT users.name, message.content, message.create_time
                                FROM message JOIN users ON message.user_id = users.id
                                WHERE message.room_token = ?""", (session["room"],)).fetchall()
        history = [dict(row) for row in history]
        room = db.execute("SELECT * FROM room WHERE token = ?", (session["room"],)).fetchone()
        return render_template("index.html", user_rooms = user_rooms, room = room, history = 
        [{"name": escape(row["name"]) ,"content": escape(row["content"]), "create_time": row["create_time"]} for row in history] )
    return render_template("index.html", user_rooms = user_rooms)


@app.route("/select")
def select():
    try:
        session.pop("room")
    except Exception:
        pass
    return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return render_template("login.html", error="账号或密码为空。")
        
        username = username.strip()
        password = password.strip()

        if len(username) < 4:
            return render_template("login.html", error="账号至少为4位。")
        if len(password) < 8:
            return render_template("login.html", error="密码至少为8位。")
        
        db = get_db_connection()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is None or not verify_password(password, user["hash"]):
            return render_template("login.html", error="账号或密码错误。")
       
        session["user_id"] = user["id"]
        session["session_id"] = str(uuid.uuid4())
        session["name"] = user["name"]
        online_users[user['id']] = session["session_id"]
       
        return redirect("/")
    
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":

        name = request.form.get("name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation or not name:
            return render_template("register.html", error="请填写所有字段。")
        
        name = name.strip()
        username = username.strip()
        password = password.strip()
        confirmation = confirmation.strip()

        if len(username) < 4:
            return render_template("register.html", error="账号至少要4位。")
        if len(password) < 8:
            return render_template("register.html", error="密码至少要8位。") 
        if password != confirmation:
            return render_template("register.html", error="两次输入的密码不匹配。") 

        hashed_password = hash_password(password)

        try:
            db = get_db_connection()
            db.execute("INSERT INTO users (username, hash, name) VALUES (?, ?, ?)", (username, hashed_password, name))
            db.commit()
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在。")

        return redirect("/login")
    
    return render_template("register.html")

@app.route("/create", methods=["POST","GET"])
@login_required
def create():
    session["create"] = True
    if request.method == "POST":
        create_room = request.form.get("create")
        join_room = request.form.get("join")
        chat_join = request.form.get("chat_join")
        db = get_db_connection()

        try:
           # 如果点击创造房间
            with create_db_lock:
                if create_room:
                    room_name = request.form.get("room_name")
                    if not room_name:
                        return render_template("create.html", error="房间名不能为空。")
                    # 防止并发导致创造失败
                    token = generate_token(6)
                    try:
                        db.execute("INSERT INTO room (token, name, member) VALUES (?, ?, ?)", (token, room_name.strip(), 0))
                    except sqlite3.IntegrityError:
                        return render_template("create.html", error = "房间名已存在")
                # 如果加入房间
                elif join_room or chat_join:
                    if chat_join:
                        token = chat_join
                    else:
                        token = request.form.get("token")
                    if not token:
                        return render_template("create.html", error="房间令牌不能为空。")
                    # 如果令牌是带有隐私房间标识
                    if token.strip() in private_rooms:
                            session["room"] = token.strip()
                            return redirect("/private_room")
                    #检查房间是否存在
                    room = db.execute("SELECT * FROM room WHERE token = ?", (token.strip(),)).fetchone()
                    if room is None:
                        return render_template("create.html", error="房间令牌不存在。")
                # 绑定用户与房间
                count = db.execute("INSERT OR IGNORE INTO bind (user_id, room_token) VALUES (?, ?)", (session["user_id"], token))
                # 增加房间成员数
                if count.rowcount > 0:
                    db.execute("UPDATE room SET member = member + 1 WHERE token = ?", (token,))
        except Exception as e:
            logger.error(f"Failed to create or join room: {e}")
            return render_template("create.html", error="服务器错误,请稍后再试。")
        db.commit()
        session["room"] = token
        return redirect("/")
    return render_template("create.html")

@app.route("/private",methods = ["GET", "POST"])
@login_required
def private():
    if request.method == "POST":
        with private_room_lock:
            secret = request.form.get("secret")
            if not secret:
                return render_template("create.html",error="无效请求")
            # 拼接生成token函数与private标识
            # 确保唯一性和首次生成
            while True:
                private_token = f"{PRIVATE_TOKENHEAD}{generate_token(8)}" 
                if private_token not in private_rooms:
                    break
            
            private_rooms[private_token] = {
            "member": set(),
            "name": "隐私房间",
            "token": private_token,
            }

            session["room"] = private_token
            return redirect("/private_room")
        
    return render_template("create.html", error = "非法访问路径")

@app.route("/private_room")
@login_required
def private_room():
    return render_template("private.html",room = private_rooms[session["room"]])

@app.route("/introduce")
@login_required
def introduce():
    return render_template("introduce.html")
# 客户端发送连接请求时触发
@socketio.on("connect")
def connect(auth):
    with app.app_context():
        #处理隐私房间连接
        if session.get("room") in private_rooms:
            room_s = private_rooms[session["room"]]
            name = session.get("name")
            room_name = room_s.get("name")
            room = session["room"]
            if not name or not room_name:
                return False
            join_room(room)
            room_s["member"].add(session["user_id"])
            send({"name": name, "message": "加入房间","create_time":  time.strftime("%Y,%m,%d,%H,%M,%S"), "member": len(room_s["member"])}, to = room) # type: ignore
        else:
            db = get_db_connection()
            name = session.get("name")
            room = session.get("room")
            room_name = db.execute("SELECT name FROM room WHERE token = ?", (room,)).fetchone()
            if not room or room not in rooms or not name or not room_name:
                return False
            room_name = room_name["name"]
            join_room(room)
            rooms[room].add(session["user_id"])
            send({"name": name, "message": "加入房间", "create_time": time.strftime("%Y,%m,%d,%H,%M,%S"), "member": len(rooms[room])}, to = room) # type: ignore
            logger.info(f"{name} joined room[{room_name}]-token[{room}]")
           

# 客户端断开连接时触发
@socketio.on("disconnect")
def disconnect():
    with app.app_context():
        if session.get("room") in private_rooms:
            room_s = private_rooms[session["room"]]
            name = session.get("name")
            room_name = room_s.get("name")
            room = session["room"]
            if not name or not room_name:
                return
            leave_room(room)
            room_s["member"].discard(session["user_id"])
            send({"name": name, "message": "离开房间","create_time":  time.strftime("%Y,%m,%d,%H,%M,%S"), "member": len(room_s["member"])}, to = room) # type: ignore
        else:
            db = get_db_connection()
            room = session.get("room")
            name = session.get("name")
            room_name = db.execute("SELECT name FROM room WHERE token = ?", (room,)).fetchone()
            if not room or room not in rooms or not name or not room_name:
                return
            room_name = room_name["name"]
            leave_room(room)
            rooms[room].discard(session["user_id"])
            send({"name": name, "message": "离开房间", "create_time": time.strftime("%Y,%m,%d,%H,%M,%S"),"member": len(rooms[room])}, to = room) # type: ignore
            logger.info(f"{name} left room[{room_name}]-token[{room}]")
        

# 客户端发送事件类型为message时触发
@socketio.on("message")
def message(data):
    with app.app_context():
        if not isinstance(data, dict):
                return 
        msg = data.get("message")

        if not msg or len(msg) > 1000:
                return
        msg = msg.strip()
        
        if session.get("room") in private_rooms:
            room_s = private_rooms[session["room"]]
            name = session.get("name")
            room_name = room_s.get("name")
            room = session["room"]
            if not name or not room_name:
                return 
            content = {
                "name": escape(name),
                "message": escape(msg),
                "create_time": time.strftime("%Y,%m,%d,%H,%M,%S")
            }
            send(content, to = room) # type: ignore
        else:
            db = get_db_connection()
            room = session.get("room")
            name = session.get("name")
            room_name = db.execute("SELECT name FROM room WHERE token = ?", (room,)).fetchone()
            if not room or room not in rooms or not name or not room_name:
                return
            room_name = room_name["name"]
            content = {
                "name": escape(name),
                "message": escape(msg),
                "create_time": time.strftime("%Y,%m,%d,%H,%M,%S")
            }
            send(content, to = room) # type: ignore
            # 将消息存入数据库
            try:
                db.execute("INSERT INTO message (room_token, user_id, content) VALUES (?, ? ,?)", (room, session["user_id"], msg))
            except Exception as e:
                logger.error(f"插入信息出错{e}")
                return
            db.commit()
            # 将消息存入在线房间消息列表
            # rooms[room]["message"].append(content)
            logger.info(f"{name}在{room_name}说: {msg}")

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
        